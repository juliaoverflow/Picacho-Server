//! MIME structure with byte offsets, and the IMAP ENVELOPE / BODY /
//! BODYSTRUCTURE representations computed from it.
//!
//! Offsets point into the original message so FETCH BODY[section] returns
//! exact bytes. Parsing is iterative over lines and never allocates copies of
//! bodies. Nesting depth and part counts are bounded against hostile input.
use std::fmt::Write;

const MAX_DEPTH: usize = 32;
const MAX_PARTS: usize = 2000;

#[derive(Debug, Clone)]
pub struct HeaderField {
    pub name: String,
    /// Start of the field line.
    pub start: usize,
    /// Start of the value (after the colon).
    pub value_start: usize,
    /// End of the field including its final CRLF.
    pub end: usize,
}

#[derive(Debug, Clone, Default)]
pub struct Part {
    pub start: usize,
    pub body_start: usize,
    pub end: usize,
    pub fields: Vec<HeaderField>,
    pub ctype: String,
    pub csub: String,
    pub params: Vec<(String, String)>,
    /// True when the part had a Content-Type header.
    pub explicit_type: bool,
    pub children: Vec<Part>,
    pub message: Option<Box<Part>>,
}

impl Part {
    pub fn is_multipart(&self) -> bool {
        self.ctype.eq_ignore_ascii_case("multipart") && !self.children.is_empty()
            || self.ctype.eq_ignore_ascii_case("multipart") && self.param("boundary").is_some()
    }
    pub fn is_message(&self) -> bool {
        self.message.is_some()
    }
    pub fn param(&self, name: &str) -> Option<&str> {
        self.params.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
    pub fn header(&self, data: &[u8], name: &str) -> Option<Vec<u8>> {
        self.fields
            .iter()
            .find(|f| f.name.eq_ignore_ascii_case(name))
            .map(|f| unfold(&data[f.value_start..f.end]))
    }
    pub fn header_bytes<'a>(&self, data: &'a [u8]) -> &'a [u8] {
        &data[self.start..self.body_start]
    }
    pub fn body_bytes<'a>(&self, data: &'a [u8]) -> &'a [u8] {
        &data[self.body_start..self.end]
    }
}

/// Lenient base64 decoding (whitespace and junk ignored).
pub fn decode_base64(b: &[u8]) -> Vec<u8> {
    let mut val = [255u8; 256];
    for (i, c) in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".iter().enumerate() {
        val[*c as usize] = i as u8;
    }
    let mut out = Vec::with_capacity(b.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0);
    for &c in b {
        if c == b'=' {
            break;
        }
        let v = val[c as usize];
        if v == 255 {
            continue;
        }
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    out
}

/// Quoted-printable decoding: soft line breaks removed and trailing
/// whitespace (transport padding) dropped, per RFC 2045.
pub fn decode_qp(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(b.len());
    let hex = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    let mut lines = b.split(|&c| c == b'\n').peekable();
    while let Some(line) = lines.next() {
        let has_nl = lines.peek().is_some();
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let trimmed_end = line.iter().rposition(|c| *c != b' ' && *c != b'\t').map(|p| p + 1).unwrap_or(0);
        let content = &line[..trimmed_end];
        let soft = content.ends_with(b"=");
        let content = if soft { &content[..content.len() - 1] } else { content };
        let mut i = 0;
        while i < content.len() {
            if content[i] == b'=' {
                if let (Some(h), Some(l)) = (content.get(i + 1).and_then(|c| hex(*c)), content.get(i + 2).and_then(|c| hex(*c))) {
                    out.push(h * 16 + l);
                    i += 3;
                    continue;
                }
            }
            out.push(content[i]);
            i += 1;
        }
        if has_nl && !soft {
            out.extend_from_slice(b"\r\n");
        }
    }
    out
}

/// Re-encode leaf parts that hold binary data (NULs or CTE binary) as
/// base64, so BODY[] stays 7-bit clean (BINARY appends, RFC 3516).
pub fn encode_binary_parts(data: &[u8]) -> Vec<u8> {
    use base64::Engine;
    let root = parse(data);
    let mut leaves: Vec<&Part> = vec![];
    fn walk<'a>(p: &'a Part, out: &mut Vec<&'a Part>) {
        if p.is_multipart() {
            for c in &p.children {
                walk(c, out);
            }
        } else if p.message.is_none() {
            out.push(p);
        }
    }
    walk(&root, &mut leaves);
    let mut edits: Vec<(usize, usize, Vec<u8>)> = vec![];
    for p in leaves {
        let body = p.body_bytes(data);
        let cte = p.header(data, "content-transfer-encoding").map(|v| String::from_utf8_lossy(&v).to_ascii_lowercase());
        if !(body.contains(&0) || cte.as_deref() == Some("binary")) {
            continue;
        }
        let enc = base64::engine::general_purpose::STANDARD.encode(body);
        let mut b64 = Vec::with_capacity(enc.len() + enc.len() / 76 * 2 + 2);
        for chunk in enc.as_bytes().chunks(76) {
            b64.extend_from_slice(chunk);
            b64.extend_from_slice(b"\r\n");
        }
        edits.push((p.body_start, p.end, b64));
        let field = p.fields.iter().find(|f| f.name.eq_ignore_ascii_case("content-transfer-encoding"));
        let new_field = b"Content-Transfer-Encoding: base64\r\n".to_vec();
        match field {
            Some(f) => edits.push((f.start, f.end, new_field)),
            None => {
                let at = p.fields.last().map(|f| f.end).unwrap_or(p.start);
                edits.push((at, at, new_field));
            }
        }
    }
    if edits.is_empty() {
        return data.to_vec();
    }
    edits.sort_by(|a, b| b.0.cmp(&a.0).then(b.1.cmp(&a.1)));
    let mut out = data.to_vec();
    for (s, e, rep) in edits {
        out.splice(s..e, rep);
    }
    out
}

/// Unfold a header value: drop CRLFs, trim surrounding whitespace.
pub fn unfold(v: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(v.len());
    for &c in v {
        if c != b'\r' && c != b'\n' {
            out.push(c);
        }
    }
    let s = out.iter().position(|c| !c.is_ascii_whitespace()).unwrap_or(out.len());
    let e = out.iter().rposition(|c| !c.is_ascii_whitespace()).map(|i| i + 1).unwrap_or(s);
    out[s..e].to_vec()
}

fn line_end(data: &[u8], from: usize, end: usize) -> (usize, usize) {
    // Returns (end of line content, start of next line).
    match memchr(b'\n', &data[from..end]) {
        Some(i) => {
            let nl = from + i;
            let content_end = if nl > from && data[nl - 1] == b'\r' { nl - 1 } else { nl };
            (content_end, nl + 1)
        }
        None => (end, end),
    }
}

fn memchr(c: u8, s: &[u8]) -> Option<usize> {
    s.iter().position(|&x| x == c)
}

/// Parse the header block at `start`; returns fields and body start.
fn parse_header(data: &[u8], start: usize, end: usize) -> (Vec<HeaderField>, usize) {
    let mut fields: Vec<HeaderField> = vec![];
    let mut p = start;
    while p < end {
        let (ce, next) = line_end(data, p, end);
        if ce == p {
            // Empty line ends the header.
            return (fields, next);
        }
        let first = data[p];
        if (first == b' ' || first == b'\t') && !fields.is_empty() {
            fields.last_mut().unwrap().end = next;
        } else if let Some(colon) = memchr(b':', &data[p..ce]) {
            let name = String::from_utf8_lossy(&data[p..p + colon]).trim().to_string();
            fields.push(HeaderField { name, start: p, value_start: p + colon + 1, end: next });
        } else if !fields.is_empty() {
            // Garbage line: attach to the previous field so offsets stay contiguous.
            fields.last_mut().unwrap().end = next;
        } else {
            fields.push(HeaderField { name: String::new(), start: p, value_start: p, end: next });
        }
        p = next;
    }
    (fields, end)
}

/// Parse `type/subtype; k=v; ...`.
pub fn parse_content_type(v: &[u8]) -> Option<(String, String, Vec<(String, String)>)> {
    let s = String::from_utf8_lossy(v);
    let mut t = Tokens::new(&s);
    let ty = t.token()?;
    t.skip_cfws();
    if !t.eat('/') {
        return None;
    }
    let sub = t.token()?;
    Some((ty, sub, t.params()))
}

/// Parse `value; k=v` (Content-Disposition).
pub fn parse_disposition(v: &[u8]) -> Option<(String, Vec<(String, String)>)> {
    let s = String::from_utf8_lossy(v);
    let mut t = Tokens::new(&s);
    let d = t.token()?;
    Some((d, t.params()))
}

struct Tokens<'a> {
    s: &'a [u8],
    p: usize,
}

impl<'a> Tokens<'a> {
    fn new(s: &'a str) -> Self {
        Self { s: s.as_bytes(), p: 0 }
    }
    fn skip_cfws(&mut self) {
        loop {
            while self.p < self.s.len() && self.s[self.p].is_ascii_whitespace() {
                self.p += 1;
            }
            if self.p < self.s.len() && self.s[self.p] == b'(' {
                let mut depth = 0;
                while self.p < self.s.len() {
                    match self.s[self.p] {
                        b'\\' => self.p += 1,
                        b'(' => depth += 1,
                        b')' => {
                            depth -= 1;
                            if depth == 0 {
                                self.p += 1;
                                break;
                            }
                        }
                        _ => {}
                    }
                    self.p += 1;
                }
            } else {
                break;
            }
        }
    }
    fn eat(&mut self, c: char) -> bool {
        self.skip_cfws();
        if self.p < self.s.len() && self.s[self.p] == c as u8 {
            self.p += 1;
            true
        } else {
            false
        }
    }
    fn token(&mut self) -> Option<String> {
        self.skip_cfws();
        let st = self.p;
        while self.p < self.s.len() {
            let c = self.s[self.p];
            if c <= b' ' || b"()<>@,;:\\\"/[]?=".contains(&c) {
                break;
            }
            self.p += 1;
        }
        if self.p == st {
            None
        } else {
            Some(String::from_utf8_lossy(&self.s[st..self.p]).into_owned())
        }
    }
    fn quoted(&mut self) -> Option<String> {
        self.skip_cfws();
        if self.p >= self.s.len() || self.s[self.p] != b'"' {
            return None;
        }
        self.p += 1;
        let mut out = Vec::new();
        while self.p < self.s.len() {
            let c = self.s[self.p];
            self.p += 1;
            match c {
                b'\\' if self.p < self.s.len() => {
                    out.push(self.s[self.p]);
                    self.p += 1;
                }
                b'"' => return Some(String::from_utf8_lossy(&out).into_owned()),
                _ => out.push(c),
            }
        }
        Some(String::from_utf8_lossy(&out).into_owned())
    }
    fn params(&mut self) -> Vec<(String, String)> {
        let mut out = vec![];
        loop {
            self.skip_cfws();
            if self.p >= self.s.len() {
                break;
            }
            if self.s[self.p] != b';' {
                // Skip junk up to the next separator.
                while self.p < self.s.len() && self.s[self.p] != b';' {
                    self.p += 1;
                }
                continue;
            }
            self.p += 1;
            let Some(k) = self.token() else { continue };
            if !self.eat('=') {
                continue;
            }
            self.skip_cfws();
            let v = if self.p < self.s.len() && self.s[self.p] == b'"' { self.quoted() } else { self.token() };
            if let Some(v) = v {
                out.push((k, v));
            }
            if out.len() > 64 {
                break;
            }
        }
        out
    }
}

/// Parse a whole message.
pub fn parse(data: &[u8]) -> Part {
    let mut count = 0;
    parse_part(data, 0, data.len(), false, 0, &mut count)
}

fn parse_part(data: &[u8], start: usize, end: usize, digest: bool, depth: usize, count: &mut usize) -> Part {
    *count += 1;
    let (fields, body_start) = parse_header(data, start, end);
    let mut part = Part { start, body_start, end, fields, ..Default::default() };
    let ct = part.header(data, "content-type").and_then(|v| parse_content_type(&v));
    match ct {
        Some((t, s, p)) => {
            part.ctype = t;
            part.csub = s;
            part.params = p;
            part.explicit_type = true;
        }
        None if digest => {
            part.ctype = "message".into();
            part.csub = "rfc822".into();
        }
        None => {
            part.ctype = "text".into();
            part.csub = "plain".into();
            part.params = vec![("charset".into(), "us-ascii".into())];
        }
    }
    if depth >= MAX_DEPTH || *count >= MAX_PARTS {
        return part;
    }
    if part.ctype.eq_ignore_ascii_case("multipart") {
        if let Some(boundary) = part.param("boundary").map(|b| b.to_string()) {
            let is_digest = part.csub.eq_ignore_ascii_case("digest");
            for (s, e) in split_multipart(data, body_start, end, boundary.as_bytes()) {
                if *count >= MAX_PARTS {
                    break;
                }
                part.children.push(parse_part(data, s, e, is_digest, depth + 1, count));
            }
        } else {
            // Multipart without a boundary is treated as plain text.
            part.ctype = "text".into();
            part.csub = "plain".into();
            part.params = vec![("charset".into(), "us-ascii".into())];
        }
    } else if part.ctype.eq_ignore_ascii_case("message")
        && (part.csub.eq_ignore_ascii_case("rfc822") || part.csub.eq_ignore_ascii_case("global"))
    {
        part.message = Some(Box::new(parse_part(data, body_start, end, false, depth + 1, count)));
    }
    part
}

/// Ranges of the body parts of a multipart body.
fn split_multipart(data: &[u8], start: usize, end: usize, boundary: &[u8]) -> Vec<(usize, usize)> {
    let mut parts = vec![];
    let mut p = start;
    let mut current: Option<usize> = None;
    while p < end {
        let (ce, next) = line_end(data, p, end);
        let line = &data[p..ce];
        if line.len() >= 2 + boundary.len() && line.starts_with(b"--") && &line[2..2 + boundary.len()] == boundary {
            let rest = &line[2 + boundary.len()..];
            let is_close = rest.starts_with(b"--");
            let tail = if is_close { &rest[2..] } else { rest };
            if tail.iter().all(|c| c.is_ascii_whitespace()) {
                if let Some(s) = current.take() {
                    // The CRLF before the delimiter belongs to the delimiter.
                    let mut e = p;
                    if e > s && data[e - 1] == b'\n' {
                        e -= 1;
                        if e > s && data[e - 1] == b'\r' {
                            e -= 1;
                        }
                    }
                    parts.push((s, e.max(s)));
                }
                if is_close {
                    return parts;
                }
                current = Some(next);
            }
        }
        p = next;
    }
    if let Some(s) = current {
        parts.push((s, end));
    }
    parts
}

fn count_lines(b: &[u8]) -> usize {
    b.iter().filter(|&&c| c == b'\n').count()
}

// ---------------------------------------------------------------------------
// IMAP string output
// ---------------------------------------------------------------------------

/// Append an IMAP string: quoted when safe, a literal otherwise.
pub fn imap_string(out: &mut String, s: &[u8]) {
    let needs_literal = s.len() > 1024 || s.iter().any(|&c| c == b'\r' || c == b'\n' || c == 0 || c >= 0x80);
    if needs_literal {
        // Structures are kept as text; invalid UTF-8 is replaced and the
        // literal length counts the bytes actually written.
        let text = String::from_utf8_lossy(s);
        let _ = write!(out, "{{{}}}\r\n", text.len());
        out.push_str(&text);
    } else {
        out.push('"');
        for &c in s {
            if c == b'"' || c == b'\\' {
                out.push('\\');
            }
            out.push(c as char);
        }
        out.push('"');
    }
}

pub fn nstring(out: &mut String, s: Option<&[u8]>) {
    match s {
        Some(s) => imap_string(out, s),
        None => out.push_str("NIL"),
    }
}

fn nstring_nonempty(out: &mut String, s: Option<Vec<u8>>) {
    match s {
        Some(s) if !s.is_empty() => imap_string(out, &s),
        _ => out.push_str("NIL"),
    }
}

// ---------------------------------------------------------------------------
// Addresses and ENVELOPE
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct Address {
    pub name: Option<Vec<u8>>,
    pub route: Option<Vec<u8>>,
    pub mailbox: Option<Vec<u8>>,
    pub host: Option<Vec<u8>>,
}

struct AddrParser<'a> {
    s: &'a [u8],
    p: usize,
    /// Text of the most recently skipped comment (used as a display name
    /// for `user@host (Real Name)`).
    last_comment: Option<Vec<u8>>,
}

impl<'a> AddrParser<'a> {
    fn skip_cfws(&mut self) {
        loop {
            while self.p < self.s.len() && self.s[self.p].is_ascii_whitespace() {
                self.p += 1;
            }
            if self.p < self.s.len() && self.s[self.p] == b'(' {
                let mut depth = 0;
                let start = self.p + 1;
                while self.p < self.s.len() {
                    match self.s[self.p] {
                        b'\\' => self.p += 1,
                        b'(' => depth += 1,
                        b')' => {
                            depth -= 1;
                            if depth == 0 {
                                self.last_comment = Some(self.s[start..self.p].to_vec());
                                self.p += 1;
                                break;
                            }
                        }
                        _ => {}
                    }
                    self.p += 1;
                }
            } else {
                return;
            }
        }
    }
    fn peek(&self) -> Option<u8> {
        self.s.get(self.p).copied()
    }
    /// A word: atom (dots allowed) or quoted string, unquoted.
    fn word(&mut self) -> Option<Vec<u8>> {
        self.skip_cfws();
        let c = self.peek()?;
        if c == b'"' {
            self.p += 1;
            let mut out = vec![];
            while let Some(c) = self.peek() {
                self.p += 1;
                match c {
                    b'\\' => {
                        if let Some(n) = self.peek() {
                            out.push(n);
                            self.p += 1;
                        }
                    }
                    b'"' => break,
                    b'\r' | b'\n' => {}
                    _ => out.push(c),
                }
            }
            return Some(out);
        }
        let st = self.p;
        while let Some(c) = self.peek() {
            if c.is_ascii_whitespace() || b"()<>@,;:\\\"[]".contains(&c) {
                break;
            }
            self.p += 1;
        }
        if st == self.p {
            None
        } else {
            Some(self.s[st..self.p].to_vec())
        }
    }
    /// Phrase: words separated by single spaces, plus the raw form when the
    /// words should be joined without spaces (local parts).
    fn phrase(&mut self) -> (Vec<u8>, Vec<u8>) {
        let mut spaced = vec![];
        let mut joined = vec![];
        loop {
            let save = self.p;
            self.skip_cfws();
            match self.peek() {
                Some(c) if c == b'"' || !(c.is_ascii_whitespace() || b"()<>@,;:\\[]".contains(&c)) => {
                    let had_space = self.p > save && !spaced.is_empty();
                    if let Some(w) = self.word() {
                        if (had_space || (!spaced.is_empty() && !spaced.ends_with(b".") && !w.starts_with(b".")))
                            && had_space {
                                spaced.push(b' ');
                            }
                        spaced.extend_from_slice(&w);
                        joined.extend_from_slice(&w);
                    } else {
                        break;
                    }
                }
                _ => {
                    self.p = save;
                    break;
                }
            }
        }
        (spaced, joined)
    }
    fn domain(&mut self) -> Vec<u8> {
        self.skip_cfws();
        if self.peek() == Some(b'[') {
            let st = self.p;
            while let Some(c) = self.peek() {
                self.p += 1;
                if c == b']' {
                    break;
                }
            }
            return self.s[st..self.p].to_vec();
        }
        let mut out = vec![];
        loop {
            self.skip_cfws();
            let st = self.p;
            while let Some(c) = self.peek() {
                if c.is_ascii_whitespace() || b"()<>@,;:\\\"[]".contains(&c) {
                    break;
                }
                self.p += 1;
            }
            out.extend_from_slice(&self.s[st..self.p]);
            if st == self.p {
                break;
            }
            let save = self.p;
            self.skip_cfws();
            if self.peek() != Some(b'.') && !out.ends_with(b".") {
                self.p = save;
                break;
            }
        }
        out
    }
    fn angle_addr(&mut self, name: Option<Vec<u8>>) -> Address {
        // At '<'.
        self.p += 1;
        self.skip_cfws();
        let mut route = None;
        if self.peek() == Some(b'@') {
            let st = self.p;
            while let Some(c) = self.peek() {
                if c == b':' {
                    break;
                }
                if c == b'>' {
                    break;
                }
                self.p += 1;
            }
            if self.peek() == Some(b':') {
                route = Some(self.s[st..self.p].iter().copied().filter(|c| !c.is_ascii_whitespace()).collect());
                self.p += 1;
            } else {
                self.p = st;
            }
        }
        let (_, local) = self.phrase();
        self.skip_cfws();
        let mut host = None;
        if self.peek() == Some(b'@') {
            self.p += 1;
            host = Some(self.domain());
        }
        self.skip_cfws();
        while let Some(c) = self.peek() {
            self.p += 1;
            if c == b'>' {
                break;
            }
        }
        if local.is_empty() && host.is_none() {
            // `<>` null address.
            return Address { name, route, mailbox: Some(vec![]), host: Some(vec![]) };
        }
        Address {
            name,
            route,
            mailbox: Some(if local.is_empty() { b"MISSING_MAILBOX".to_vec() } else { local }),
            host: Some(host.unwrap_or_else(|| b"MISSING_DOMAIN".to_vec())),
        }
    }
    fn mailbox_or_group(&mut self, out: &mut Vec<Address>, in_group: bool) {
        self.skip_cfws();
        if self.peek() == Some(b'<') {
            let a = self.angle_addr(None);
            out.push(a);
            return;
        }
        let save = self.p;
        let (spaced, joined) = self.phrase();
        self.skip_cfws();
        match self.peek() {
            Some(b'<') => {
                let name = if spaced.is_empty() { None } else { Some(spaced) };
                let a = self.angle_addr(name);
                out.push(a);
            }
            Some(b':') if !in_group => {
                self.p += 1;
                out.push(Address { name: None, route: None, mailbox: Some(spaced), host: None });
                loop {
                    self.skip_cfws();
                    match self.peek() {
                        None => break,
                        Some(b';') => {
                            self.p += 1;
                            break;
                        }
                        Some(b',') => {
                            self.p += 1;
                        }
                        _ => {
                            let before = self.p;
                            self.mailbox_or_group(out, true);
                            if self.p == before {
                                self.p += 1;
                            }
                        }
                    }
                }
                out.push(Address { name: None, route: None, mailbox: None, host: None });
            }
            Some(b'@') => {
                self.p += 1;
                let host = self.domain();
                self.last_comment = None;
                self.skip_cfws();
                let name = self.last_comment.take().filter(|c| !c.is_empty());
                out.push(Address {
                    name,
                    route: None,
                    mailbox: Some(if joined.is_empty() { b"MISSING_MAILBOX".to_vec() } else { joined }),
                    host: Some(if host.is_empty() { b"MISSING_DOMAIN".to_vec() } else { host }),
                });
            }
            _ => {
                if !joined.is_empty() {
                    out.push(Address {
                        name: None,
                        route: None,
                        mailbox: Some(joined),
                        host: Some(b"MISSING_DOMAIN".to_vec()),
                    });
                } else if self.p == save {
                    // Skip an unexpected character.
                    self.p += 1;
                }
            }
        }
    }
}

pub fn parse_addresses(v: &[u8]) -> Vec<Address> {
    let mut p = AddrParser { s: v, p: 0, last_comment: None };
    let mut out = vec![];
    while p.p < v.len() && out.len() < 1000 {
        p.skip_cfws();
        match p.peek() {
            None => break,
            Some(b',') => p.p += 1,
            _ => {
                let before = p.p;
                p.mailbox_or_group(&mut out, false);
                if p.p == before {
                    p.p += 1;
                }
            }
        }
    }
    out
}

fn address_list(out: &mut String, v: Option<Vec<u8>>) {
    let Some(v) = v else {
        out.push_str("NIL");
        return;
    };
    let addrs = parse_addresses(&v);
    if addrs.is_empty() {
        out.push_str("NIL");
        return;
    }
    out.push('(');
    for a in addrs {
        out.push('(');
        nstring(out, a.name.as_deref());
        out.push(' ');
        nstring(out, a.route.as_deref());
        out.push(' ');
        nstring(out, a.mailbox.as_deref());
        out.push(' ');
        nstring(out, a.host.as_deref());
        out.push(')');
    }
    out.push(')');
}

pub fn envelope(data: &[u8], part: &Part) -> String {
    let mut out = String::with_capacity(256);
    let h = |n: &str| part.header(data, n);
    out.push('(');
    nstring_nonempty(&mut out, h("date"));
    out.push(' ');
    nstring(&mut out, h("subject").as_deref());
    out.push(' ');
    let from = h("from");
    address_list(&mut out, from.clone());
    out.push(' ');
    address_list(&mut out, h("sender").filter(|v| !v.is_empty()).or_else(|| from.clone()));
    out.push(' ');
    address_list(&mut out, h("reply-to").filter(|v| !v.is_empty()).or_else(|| from.clone()));
    out.push(' ');
    address_list(&mut out, h("to"));
    out.push(' ');
    address_list(&mut out, h("cc"));
    out.push(' ');
    address_list(&mut out, h("bcc"));
    out.push(' ');
    nstring_nonempty(&mut out, h("in-reply-to"));
    out.push(' ');
    nstring_nonempty(&mut out, h("message-id"));
    out.push(')');
    out
}

// ---------------------------------------------------------------------------
// BODY / BODYSTRUCTURE
// ---------------------------------------------------------------------------

fn params_list(out: &mut String, params: &[(String, String)]) {
    if params.is_empty() {
        out.push_str("NIL");
        return;
    }
    out.push('(');
    for (i, (k, v)) in params.iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        imap_string(out, k.as_bytes());
        out.push(' ');
        imap_string(out, v.as_bytes());
    }
    out.push(')');
}

fn disposition(out: &mut String, data: &[u8], part: &Part) {
    match part.header(data, "content-disposition").and_then(|v| parse_disposition(&v)) {
        Some((d, p)) => {
            out.push('(');
            imap_string(out, d.as_bytes());
            out.push(' ');
            params_list(out, &p);
            out.push(')');
        }
        None => out.push_str("NIL"),
    }
}

fn language(out: &mut String, data: &[u8], part: &Part) {
    match part.header(data, "content-language") {
        Some(v) if !v.is_empty() => {
            let s = String::from_utf8_lossy(&v).into_owned();
            let langs: Vec<&str> = s.split(',').map(|l| l.trim()).filter(|l| !l.is_empty()).collect();
            if langs.len() == 1 {
                imap_string(out, langs[0].as_bytes());
            } else if langs.is_empty() {
                out.push_str("NIL");
            } else {
                out.push('(');
                for (i, l) in langs.iter().enumerate() {
                    if i > 0 {
                        out.push(' ');
                    }
                    imap_string(out, l.as_bytes());
                }
                out.push(')');
            }
        }
        _ => out.push_str("NIL"),
    }
}

pub fn bodystructure(data: &[u8], part: &Part, extended: bool) -> String {
    let mut out = String::with_capacity(256);
    write_structure(&mut out, data, part, extended);
    out
}

fn write_structure(out: &mut String, data: &[u8], part: &Part, ext: bool) {
    out.push('(');
    if part.ctype.eq_ignore_ascii_case("multipart") && part.param("boundary").is_some() {
        if part.children.is_empty() {
            // Multipart with no parts: describe an empty text part (as Dovecot does).
            out.push_str("(\"text\" \"plain\" (\"charset\" \"us-ascii\") NIL NIL \"7bit\" 0 0");
            if ext {
                out.push_str(" NIL NIL NIL NIL");
            }
            out.push(')');
        }
        for c in &part.children {
            write_structure(out, data, c, ext);
        }
        out.push(' ');
        imap_string(out, part.csub.as_bytes());
        if ext {
            out.push(' ');
            params_list(out, &part.params);
            out.push(' ');
            disposition(out, data, part);
            out.push(' ');
            language(out, data, part);
            out.push(' ');
            nstring_nonempty(out, part.header(data, "content-location"));
        }
        out.push(')');
        return;
    }
    imap_string(out, part.ctype.as_bytes());
    out.push(' ');
    imap_string(out, part.csub.as_bytes());
    out.push(' ');
    params_list(out, &part.params);
    out.push(' ');
    nstring_nonempty(out, part.header(data, "content-id"));
    out.push(' ');
    nstring_nonempty(out, part.header(data, "content-description"));
    out.push(' ');
    let enc = part
        .header(data, "content-transfer-encoding")
        .filter(|v| !v.is_empty())
        .map(|v| String::from_utf8_lossy(&v).trim().to_string())
        .unwrap_or_else(|| "7bit".into());
    imap_string(out, enc.as_bytes());
    let body = part.body_bytes(data);
    let _ = write!(out, " {}", body.len());
    if let Some(m) = &part.message {
        out.push(' ');
        out.push_str(&envelope(data, m));
        out.push(' ');
        write_structure(out, data, m, ext);
        let _ = write!(out, " {}", count_lines(body));
    } else if part.ctype.eq_ignore_ascii_case("text") {
        let _ = write!(out, " {}", count_lines(body));
    }
    if ext {
        out.push(' ');
        nstring_nonempty(out, part.header(data, "content-md5"));
        out.push(' ');
        disposition(out, data, part);
        out.push(' ');
        language(out, data, part);
        out.push(' ');
        nstring_nonempty(out, part.header(data, "content-location"));
    }
    out.push(')');
}

// ---------------------------------------------------------------------------
// Section lookup
// ---------------------------------------------------------------------------

/// Find a part by IMAP section path (e.g. [1, 2]). Part 1 of a non-multipart
/// message is its body. Numbers inside a message/rfc822 part address the
/// encapsulated message's parts.
pub fn find_part<'a>(root: &'a Part, path: &[usize]) -> Option<&'a Part> {
    let mut cur = root;
    for (i, &n) in path.iter().enumerate() {
        if n == 0 {
            return None;
        }
        // Step into an encapsulated message, except at the root.
        if i > 0 {
            if let Some(m) = &cur.message {
                cur = m;
            }
        }
        if cur.is_multipart() {
            cur = cur.children.get(n - 1)?;
        } else if n == 1 {
            // The body of a single-part entity is part 1.
        } else {
            return None;
        }
    }
    Some(cur)
}

/// Body ranges of large non-text leaf parts (attachments) for splitting.
pub fn attachment_spans(data: &[u8], threshold: usize) -> Vec<(usize, usize)> {
    let root = parse(data);
    let mut out = vec![];
    fn walk(p: &Part, threshold: usize, out: &mut Vec<(usize, usize)>, root: bool) {
        if p.is_multipart() {
            for c in &p.children {
                walk(c, threshold, out, false);
            }
        } else if !root && !p.ctype.eq_ignore_ascii_case("text") && p.end - p.body_start >= threshold {
            out.push((p.body_start, p.end));
        }
    }
    walk(&root, threshold, &mut out, true);
    out.sort_unstable();
    out
}

/// Summary used at ingest: precomputed IMAP strings plus display fields.
pub struct Summary {
    pub envelope: String,
    pub bodystructure: String,
    pub body: String,
    pub subject: String,
    pub from: String,
    /// JSON of [`Meta`].
    pub meta: String,
    pub msgid: String,
    /// Message-IDs referenced (References, then In-Reply-To).
    pub refs: Vec<String>,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct EmailAddr {
    pub name: Option<String>,
    pub email: String,
}

/// Decoded header facts used by SORT/THREAD, JMAP and the console.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct Meta {
    pub sent: Option<i64>,
    pub subject: String,
    pub base_subject: String,
    pub from: Vec<EmailAddr>,
    pub sender: Vec<EmailAddr>,
    pub reply_to: Vec<EmailAddr>,
    pub to: Vec<EmailAddr>,
    pub cc: Vec<EmailAddr>,
    pub bcc: Vec<EmailAddr>,
    pub msgid: Option<String>,
    pub in_reply_to: Vec<String>,
    pub references: Vec<String>,
    pub preview: String,
    pub has_attachment: bool,
    /// RFC 5256 sort keys: mailbox of the first address (group name for groups).
    pub sort_from: String,
    pub sort_to: String,
    pub sort_cc: String,
    /// RFC 5957 display keys: display name, else addr-spec (group name for groups).
    pub display_from: String,
    pub display_to: String,
}

/// (sort key, display key) of the first address in a header.
fn first_address_keys(v: Option<Vec<u8>>) -> (String, String) {
    let Some(v) = v else { return (String::new(), String::new()) };
    let Some(a) = parse_addresses(&v).into_iter().next() else { return (String::new(), String::new()) };
    let mailbox = a.mailbox.as_deref().map(|m| String::from_utf8_lossy(m).into_owned()).unwrap_or_default();
    if a.host.is_none() {
        return (mailbox.clone(), mailbox);
    }
    let host = a.host.as_deref().map(|h| String::from_utf8_lossy(h).into_owned()).unwrap_or_default();
    let display = match a.name.as_deref().map(decode_rfc2047).filter(|n| !n.trim().is_empty()) {
        Some(n) => n,
        None if host == "MISSING_DOMAIN" || host.is_empty() => mailbox.clone(),
        None => format!("{mailbox}@{host}"),
    };
    (mailbox, display)
}

/// Message-IDs (`<a@b>` tokens, brackets removed).
pub fn msg_ids(v: &[u8]) -> Vec<String> {
    let s = String::from_utf8_lossy(v);
    let mut out = vec![];
    let mut rest: &str = &s;
    while let Some(a) = rest.find('<') {
        match rest[a..].find('>') {
            Some(b) => {
                let id = rest[a + 1..a + b].trim();
                if !id.is_empty() && !id.contains(char::is_whitespace) {
                    out.push(id.to_string());
                }
                rest = &rest[a + b + 1..];
            }
            None => break,
        }
    }
    out
}

pub fn email_addrs(v: Option<Vec<u8>>) -> Vec<EmailAddr> {
    let Some(v) = v else { return vec![] };
    parse_addresses(&v)
        .into_iter()
        .filter_map(|a| {
            let (m, h) = (a.mailbox?, a.host?);
            if m.is_empty() && h.is_empty() {
                return None;
            }
            Some(EmailAddr {
                name: a.name.map(|n| decode_rfc2047(&n)).filter(|n| !n.trim().is_empty()),
                email: format!("{}@{}", String::from_utf8_lossy(&m), String::from_utf8_lossy(&h)),
            })
        })
        .collect()
}

pub fn meta_of(data: &[u8], root: &Part) -> Meta {
    let h = |n: &str| root.header(data, n);
    let subject = h("subject").map(|v| decode_rfc2047(&v)).unwrap_or_default();
    let mut m = Meta {
        sent: h("date").and_then(|d| parse_rfc2822_date(&String::from_utf8_lossy(&d))),
        base_subject: base_subject(&subject),
        subject,
        from: email_addrs(h("from")),
        sender: email_addrs(h("sender")),
        reply_to: email_addrs(h("reply-to")),
        to: email_addrs(h("to")),
        cc: email_addrs(h("cc")),
        bcc: email_addrs(h("bcc")),
        msgid: h("message-id").and_then(|v| msg_ids(&v).into_iter().next()),
        in_reply_to: h("in-reply-to").map(|v| msg_ids(&v)).unwrap_or_default(),
        references: h("references").map(|v| msg_ids(&v)).unwrap_or_default(),
        ..Default::default()
    };
    let (sf, df) = first_address_keys(h("from"));
    let (st, dt) = first_address_keys(h("to"));
    let (sc, _) = first_address_keys(h("cc"));
    (m.sort_from, m.display_from, m.sort_to, m.display_to, m.sort_cc) = (sf, df, st, dt, sc);
    if let Some(p) = mail_parser::MessageParser::default().parse(data) {
        let text: String = p
            .text_bodies()
            .next()
            .map(|t| t.to_string())
            .or_else(|| p.html_bodies().next().map(|h| strip_html(&h)))
            .unwrap_or_default();
        m.preview = text.split_whitespace().collect::<Vec<_>>().join(" ").chars().take(256).collect();
        m.has_attachment = p.attachments().len() > 0;
    }
    m
}

fn strip_html(h: &str) -> String {
    let mut out = String::with_capacity(h.len() / 2);
    let mut in_tag = false;
    let lower = h.to_ascii_lowercase();
    let mut skip_until: Option<&str> = None;
    let mut i = 0;
    let b = h.as_bytes();
    while i < b.len() {
        if let Some(end) = skip_until {
            if lower[i..].starts_with(end) {
                skip_until = None;
                i += end.len();
            } else {
                i += 1;
            }
            continue;
        }
        let c = b[i];
        if c == b'<' {
            if lower[i..].starts_with("<style") {
                skip_until = Some("</style>");
            } else if lower[i..].starts_with("<script") {
                skip_until = Some("</script>");
            }
            in_tag = true;
        } else if c == b'>' {
            in_tag = false;
            out.push(' ');
        } else if !in_tag {
            let ch_len = h[i..].chars().next().map(|c| c.len_utf8()).unwrap_or(1);
            out.push_str(&h[i..i + ch_len]);
            i += ch_len;
            continue;
        }
        i += 1;
    }
    out.replace("&nbsp;", " ").replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"")
}

/// RFC 5256 base subject: strip Re:/Fwd:/[blob] prefixes and (fwd) trailers.
pub fn base_subject(subject: &str) -> String {
    let mut s: String = subject.split_whitespace().collect::<Vec<_>>().join(" ");
    loop {
        // (2) trailing "(fwd)"
        loop {
            let t = s.trim_end();
            if t.len() >= 5 && t.get(t.len() - 5..).is_some_and(|x| x.eq_ignore_ascii_case("(fwd)")) {
                s = t[..t.len() - 5].to_string();
            } else {
                s = t.to_string();
                break;
            }
        }
        // (3)/(4) leaders and blobs
        loop {
            let before = s.clone();
            s = s.trim_start().to_string();
            if let Some(rest) = strip_refwd(&s) {
                s = rest;
                continue;
            }
            if let Some(rest) = strip_blob(&s) {
                if !rest.trim().is_empty() {
                    s = rest;
                    continue;
                }
            }
            if s == before {
                break;
            }
        }
        // (5) [fwd: ... ]
        if s.len() >= 6 && s.get(..5).is_some_and(|x| x.eq_ignore_ascii_case("[fwd:")) && s.ends_with(']') {
            s = s[5..s.len() - 1].to_string();
            continue;
        }
        break;
    }
    s.trim().to_string()
}

fn strip_blob(s: &str) -> Option<String> {
    let s2 = s.strip_prefix('[')?;
    let end = s2.find(']')?;
    if s2[..end].contains('[') {
        return None;
    }
    Some(s2[end + 1..].trim_start().to_string())
}

/// `*blob ("re" / "fw" / "fwd") *WSP [blob] ":"`
fn strip_refwd(s: &str) -> Option<String> {
    let mut rest = s.to_string();
    while let Some(r) = strip_blob(&rest) {
        rest = r;
    }
    let lower = rest.to_ascii_lowercase();
    let after = if lower.starts_with("re") {
        &rest[2..]
    } else if lower.starts_with("fwd") {
        &rest[3..]
    } else if lower.starts_with("fw") {
        &rest[2..]
    } else {
        return None;
    };
    let mut after = after.trim_start().to_string();
    if let Some(r) = strip_blob(&after) {
        after = r;
    }
    after.strip_prefix(':').map(|x| x.to_string())
}

pub fn summarize(data: &[u8]) -> Summary {
    let root = parse(data);
    let meta = meta_of(data, &root);
    let subject: String = meta.subject.chars().take(300).collect();
    let from: String = match meta.from.first() {
        Some(EmailAddr { name: Some(n), email }) => format!("{n} <{email}>"),
        Some(a) => a.email.clone(),
        None => String::new(),
    }
    .chars()
    .take(300)
    .collect();
    let mut refs = meta.references.clone();
    refs.extend(meta.in_reply_to.iter().cloned());
    Summary {
        envelope: envelope(data, &root),
        bodystructure: bodystructure(data, &root, true),
        body: bodystructure(data, &root, false),
        subject,
        from,
        msgid: meta.msgid.clone().unwrap_or_default(),
        refs,
        meta: serde_json::to_string(&meta).unwrap_or_default(),
    }
}

/// The calendar date of an RFC 2822 date in its own time zone.
pub fn parse_rfc2822_local_date(s: &str) -> Option<chrono::NaiveDate> {
    let clean = strip_comments(s);
    chrono::DateTime::parse_from_rfc2822(&clean).ok().map(|d| d.date_naive())
}

fn strip_comments(s: &str) -> String {
    let mut clean = String::new();
    let mut depth = 0;
    for c in s.chars() {
        match c {
            '(' => depth += 1,
            ')' if depth > 0 => depth -= 1,
            _ if depth == 0 => clean.push(c),
            _ => {}
        }
    }
    clean.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Parse an RFC 2822 date leniently (comments and missing day names allowed).
pub fn parse_rfc2822_date(s: &str) -> Option<i64> {
    let mut clean = String::new();
    let mut depth = 0;
    for c in s.chars() {
        match c {
            '(' => depth += 1,
            ')' if depth > 0 => depth -= 1,
            _ if depth == 0 => clean.push(c),
            _ => {}
        }
    }
    let clean = clean.split_whitespace().collect::<Vec<_>>().join(" ");
    chrono::DateTime::parse_from_rfc2822(&clean).ok().map(|d| d.timestamp())
}

fn decode_charset(charset: &str, bytes: &[u8]) -> String {
    let cs = charset.to_ascii_lowercase();
    let cs = cs.split('*').next().unwrap_or("");
    match cs {
        "iso-8859-1" | "latin1" | "iso8859-1" | "windows-1252" | "cp1252" | "us-ascii" | "ascii"
            if std::str::from_utf8(bytes).is_err() =>
        {
            bytes.iter().map(|&b| b as char).collect()
        }
        _ => String::from_utf8_lossy(bytes).into_owned(),
    }
}

/// Decode RFC 2047 encoded words (`=?charset?B|Q?text?=`).
pub fn decode_rfc2047(v: &[u8]) -> String {
    use base64::Engine;
    let s = String::from_utf8_lossy(v);
    let mut out = String::new();
    let mut rest: &str = &s;
    let mut last_was_word = false;
    while let Some(start) = rest.find("=?") {
        let before = &rest[..start];
        let after = &rest[start + 2..];
        let parsed = (|| {
            let q1 = after.find('?')?;
            let charset = &after[..q1];
            let enc = after.get(q1 + 1..q1 + 2)?;
            if after.get(q1 + 2..q1 + 3)? != "?" {
                return None;
            }
            let text_start = q1 + 3;
            let end = after[text_start..].find("?=")? + text_start;
            let text = &after[text_start..end];
            let bytes = match enc {
                "B" | "b" => base64::engine::general_purpose::STANDARD
                    .decode(text.trim_end_matches('='))
                    .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(text.trim_end_matches('=')))
                    .ok()?,
                "Q" | "q" => {
                    let mut b = vec![];
                    let tb = text.as_bytes();
                    let mut i = 0;
                    while i < tb.len() {
                        match tb[i] {
                            b'_' => b.push(b' '),
                            b'=' => {
                                let h = std::str::from_utf8(tb.get(i + 1..i + 3)?).ok()?;
                                b.push(u8::from_str_radix(h, 16).ok()?);
                                i += 2;
                            }
                            c => b.push(c),
                        }
                        i += 1;
                    }
                    b
                }
                _ => return None,
            };
            Some((decode_charset(charset, &bytes), end + 2))
        })();
        match parsed {
            Some((text, consumed)) => {
                // Whitespace between adjacent encoded words is dropped.
                if !(last_was_word && before.trim().is_empty()) {
                    out.push_str(before);
                }
                out.push_str(&text);
                rest = &after[consumed..];
                last_was_word = true;
            }
            None => {
                out.push_str(before);
                out.push_str("=?");
                rest = after;
                last_was_word = false;
            }
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_structure() {
        let m = b"From: a@b.c\r\nSubject: hi\r\n\r\nhello\r\n";
        let p = parse(m);
        assert_eq!(
            bodystructure(m, &p, true),
            "(\"text\" \"plain\" (\"charset\" \"us-ascii\") NIL NIL \"7bit\" 7 1 NIL NIL NIL NIL)"
        );
        assert_eq!(p.body_bytes(m), b"hello\r\n");
    }

    #[test]
    fn multipart_structure() {
        let m = b"Content-Type: multipart/mixed; boundary=\"xx\"\r\n\r\npre\r\n--xx\r\nContent-Type: text/plain\r\n\r\none\r\n--xx\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"a.bin\"\r\n\r\nAAAA\r\n--xx--\r\n";
        let p = parse(m);
        assert_eq!(p.children.len(), 2);
        assert_eq!(p.children[0].body_bytes(m), b"one");
        assert_eq!(p.children[1].body_bytes(m), b"AAAA");
        let bs = bodystructure(m, &p, true);
        assert!(bs.contains("\"mixed\" (\"boundary\" \"xx\")"), "{bs}");
        assert!(bs.contains("(\"attachment\" (\"filename\" \"a.bin\"))"), "{bs}");
        let one = find_part(&p, &[1]).unwrap();
        assert_eq!(one.body_bytes(m), b"one");
        assert!(find_part(&p, &[3]).is_none());
    }

    #[test]
    fn nested_message() {
        let m = b"Content-Type: message/rfc822\r\n\r\nSubject: inner\r\n\r\nbody\r\n";
        let p = parse(m);
        assert!(p.message.is_some());
        let inner = find_part(&p, &[1]).unwrap();
        assert!(inner.message.is_some());
        let bs = bodystructure(m, &p, false);
        assert!(bs.starts_with("(\"message\" \"rfc822\" NIL NIL NIL \"7bit\" 24 (NIL \"inner\""), "{bs}");
    }

    #[test]
    fn addresses() {
        let a = parse_addresses(b"\"Doe, John\" <john@example.com>, jane@example.org (Jane)");
        assert_eq!(a.len(), 2);
        assert_eq!(a[0].name.as_deref(), Some(&b"Doe, John"[..]));
        assert_eq!(a[0].mailbox.as_deref(), Some(&b"john"[..]));
        assert_eq!(a[1].host.as_deref(), Some(&b"example.org"[..]));
        let g = parse_addresses(b"undisclosed-recipients:;");
        assert_eq!(g.len(), 2);
        assert_eq!(g[0].host, None);
        let g = parse_addresses(b"Friends: a@b.c, d@e.f;");
        assert_eq!(g.len(), 4);
        let n = parse_addresses(b"First Last <x@y.z>");
        assert_eq!(n[0].name.as_deref(), Some(&b"First Last"[..]));
    }

    #[test]
    fn base_subjects() {
        assert_eq!(base_subject("Re: [list] Fwd: hello (fwd)"), "hello");
        assert_eq!(base_subject("[fwd: Re: test]"), "test");
        assert_eq!(base_subject("RE:  re: x"), "x");
        assert_eq!(base_subject("[only]"), "[only]");
        assert_eq!(base_subject("Re: Lunch? ☀️ (fwd)"), "Lunch? ☀️");
        assert_eq!(base_subject("☀️☀️"), "☀️☀️");
    }

    #[test]
    fn rfc2047() {
        assert_eq!(decode_rfc2047(b"=?UTF-8?B?SGVsbG8=?= =?utf-8?q?_W=C3=B6rld?="), "Hello Wörld");
        assert_eq!(decode_rfc2047(b"plain"), "plain");
        assert_eq!(decode_rfc2047(b"=?iso-8859-1?q?caf=E9?="), "café");
    }

    #[test]
    fn envelope_basic() {
        let m = b"Date: Mon, 1 Jan 2024 00:00:00 +0000\r\nFrom: A <a@b.c>\r\nSubject: S\r\nMessage-ID: <x@y>\r\n\r\n";
        let p = parse(m);
        assert_eq!(
            envelope(m, &p),
            "(\"Mon, 1 Jan 2024 00:00:00 +0000\" \"S\" ((\"A\" NIL \"a\" \"b.c\")) ((\"A\" NIL \"a\" \"b.c\")) ((\"A\" NIL \"a\" \"b.c\")) NIL NIL NIL NIL \"<x@y>\")"
        );
    }
}
