//! IMAP command reading (with literals) and argument tokenizing.
use crate::net::Stream;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

#[derive(Debug, Clone, PartialEq)]
pub enum Arg {
    Atom(String),
    /// Quoted string.
    Str(Vec<u8>),
    /// Literal (`{n}`).
    Lit(Vec<u8>),
    /// Literal8 (`~{n}`, may hold binary data).
    Lit8(Vec<u8>),
    List(Vec<Arg>),
}

impl Arg {
    pub fn as_atom(&self) -> Option<&str> {
        match self {
            Arg::Atom(a) => Some(a),
            _ => None,
        }
    }
    /// astring / nstring value as bytes (atoms included).
    pub fn bytes(&self) -> Option<Vec<u8>> {
        match self {
            Arg::Atom(a) => Some(a.as_bytes().to_vec()),
            Arg::Str(s) | Arg::Lit(s) | Arg::Lit8(s) => Some(s.clone()),
            Arg::List(_) => None,
        }
    }
    pub fn string(&self) -> Option<String> {
        self.bytes().and_then(|b| String::from_utf8(b).ok())
    }
    pub fn is_nil(&self) -> bool {
        matches!(self, Arg::Atom(a) if a.eq_ignore_ascii_case("NIL"))
    }
}

#[derive(Debug)]
pub enum ReadError {
    Eof,
    Io(std::io::Error),
    LineTooLong,
    LiteralTooBig(String),
    Timeout,
}

impl From<std::io::Error> for ReadError {
    fn from(e: std::io::Error) -> Self {
        ReadError::Io(e)
    }
}

pub struct Conn {
    pub reader: BufReader<Stream>,
    pub out: Vec<u8>,
}

impl Conn {
    pub fn new(stream: Stream) -> Self {
        Self { reader: BufReader::with_capacity(16 * 1024, stream), out: Vec::with_capacity(8192) }
    }

    pub fn stream(&mut self) -> &mut Stream {
        self.reader.get_mut()
    }

    pub fn push(&mut self, s: &str) {
        self.out.extend_from_slice(s.as_bytes());
    }

    pub fn push_bytes(&mut self, b: &[u8]) {
        self.out.extend_from_slice(b);
    }

    pub async fn flush(&mut self) -> std::io::Result<()> {
        if !self.out.is_empty() {
            let out = std::mem::take(&mut self.out);
            let w = self.reader.get_mut();
            w.write_all(&out).await?;
            w.flush().await?;
            self.out = out;
            self.out.clear();
            if self.out.capacity() > 1 << 20 {
                self.out.shrink_to(8192);
            }
        }
        Ok(())
    }

    /// Read one line (without CRLF), bounded by `max`.
    pub async fn read_line(&mut self, max: usize) -> Result<Vec<u8>, ReadError> {
        let mut line = Vec::new();
        loop {
            let buf = self.reader.fill_buf().await?;
            if buf.is_empty() {
                return Err(ReadError::Eof);
            }
            if let Some(i) = buf.iter().position(|&c| c == b'\n') {
                line.extend_from_slice(&buf[..i]);
                self.reader.consume(i + 1);
                break;
            }
            let n = buf.len();
            line.extend_from_slice(buf);
            self.reader.consume(n);
            if line.len() > max {
                // Drain the rest of the line so the connection stays in sync.
                loop {
                    let buf = self.reader.fill_buf().await?;
                    if buf.is_empty() {
                        return Err(ReadError::Eof);
                    }
                    if let Some(i) = buf.iter().position(|&c| c == b'\n') {
                        self.reader.consume(i + 1);
                        return Err(ReadError::LineTooLong);
                    }
                    let n = buf.len();
                    self.reader.consume(n);
                }
            }
        }
        if line.ends_with(b"\r") {
            line.pop();
        }
        if line.len() > max {
            return Err(ReadError::LineTooLong);
        }
        Ok(line)
    }

    /// Bytes buffered but not yet consumed (must be empty before STARTTLS).
    pub fn buffered(&self) -> usize {
        self.reader.buffer().len()
    }

    /// Read a full command, sending continuation requests for synchronizing
    /// literals. Literals are kept inline as `{n}\r\n<bytes>`.
    pub async fn read_command(&mut self, max_line: usize, max_literal: usize, big_literal: usize) -> Result<Vec<u8>, ReadError> {
        let mut cmd = Vec::new();
        let mut first = true;
        let mut append = false;
        let mut total_literals = 0usize;
        loop {
            let line = self.read_line(max_line).await?;
            if first {
                append = is_append(&line);
            }
            let limit = if append { big_literal } else { max_literal };
            first = false;
            cmd.extend_from_slice(&line);
            match literal_suffix(&line) {
                Some((n, nonsync)) => {
                    if n > limit || total_literals + n > big_literal {
                        if nonsync {
                            // The client is already sending; we can't resync.
                            return Err(ReadError::LiteralTooBig(String::new()));
                        }
                        let tag = line.split(|c| *c == b' ').next().unwrap_or(b"*");
                        return Err(ReadError::LiteralTooBig(String::from_utf8_lossy(tag).into_owned()));
                    }
                    total_literals += n;
                    if !nonsync {
                        self.push("+ Ready for literal data\r\n");
                        self.flush().await?;
                    }
                    cmd.extend_from_slice(b"\r\n");
                    let start = cmd.len();
                    cmd.resize(start + n, 0);
                    self.reader.read_exact(&mut cmd[start..]).await?;
                }
                None => return Ok(cmd),
            }
        }
    }
}

fn is_append(line: &[u8]) -> bool {
    let up: Vec<u8> = line.iter().take(64).map(|c| c.to_ascii_uppercase()).collect();
    let mut parts = up.split(|c| *c == b' ');
    parts.next();
    match parts.next() {
        Some(b"APPEND") => true,
        Some(b"UID") => false,
        _ => false,
    }
}

/// `{123}` or `{123+}` at the end of a line.
pub fn literal_suffix(line: &[u8]) -> Option<(usize, bool)> {
    if !line.ends_with(b"}") {
        return None;
    }
    let open = line.iter().rposition(|&c| c == b'{')?;
    let inner = &line[open + 1..line.len() - 1];
    let (digits, nonsync) = match inner.strip_suffix(b"+") {
        Some(d) => (d, true),
        None => (inner, false),
    };
    if digits.is_empty() || digits.len() > 12 || !digits.iter().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let n: usize = std::str::from_utf8(digits).ok()?.parse().ok()?;
    Some((n, nonsync))
}

pub struct Parser<'a> {
    s: &'a [u8],
    pub p: usize,
}

#[derive(Debug)]
pub struct ParseError(pub String);

type PResult<T> = Result<T, ParseError>;

fn perr<T>(m: &str) -> PResult<T> {
    Err(ParseError(m.to_string()))
}

impl<'a> Parser<'a> {
    pub fn new(s: &'a [u8]) -> Self {
        Self { s, p: 0 }
    }

    pub fn at_end(&self) -> bool {
        self.p >= self.s.len()
    }

    pub fn rest(&self) -> &'a [u8] {
        &self.s[self.p..]
    }

    fn peek(&self) -> Option<u8> {
        self.s.get(self.p).copied()
    }

    pub fn sp(&mut self) -> PResult<()> {
        if self.peek() == Some(b' ') {
            self.p += 1;
            Ok(())
        } else {
            perr("Missing space")
        }
    }

    /// Skip a single space if present.
    pub fn opt_sp(&mut self) -> bool {
        if self.peek() == Some(b' ') {
            self.p += 1;
            true
        } else {
            false
        }
    }

    fn is_atom_char(c: u8) -> bool {
        c > b' ' && c < 0x7f && !b"(){\"".contains(&c)
    }

    /// An atom, allowing bracketed sections (`BODY[HEADER.FIELDS (A B)]<0.10>`).
    pub fn atom(&mut self) -> PResult<String> {
        let st = self.p;
        while let Some(c) = self.peek() {
            if c == b'[' {
                let mut depth = 0;
                while let Some(c) = self.peek() {
                    self.p += 1;
                    match c {
                        b'[' => depth += 1,
                        b']' => {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                        }
                        b'\r' | b'\n' => return perr("Bad section"),
                        _ => {}
                    }
                }
                continue;
            }
            if !Self::is_atom_char(c) || c == b')' {
                break;
            }
            self.p += 1;
        }
        if st == self.p {
            return perr("Expected atom");
        }
        Ok(String::from_utf8_lossy(&self.s[st..self.p]).into_owned())
    }

    fn quoted(&mut self) -> PResult<Vec<u8>> {
        self.p += 1;
        let mut out = Vec::new();
        loop {
            match self.peek() {
                None => return perr("Unterminated quoted string"),
                Some(b'"') => {
                    self.p += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.p += 1;
                    match self.peek() {
                        Some(c @ (b'"' | b'\\')) => {
                            out.push(c);
                            self.p += 1;
                        }
                        _ => return perr("Invalid escape in quoted string"),
                    }
                }
                Some(b'\r' | b'\n') => return perr("Newline in quoted string"),
                Some(c) => {
                    out.push(c);
                    self.p += 1;
                }
            }
        }
    }

    fn literal(&mut self) -> PResult<Vec<u8>> {
        // {n}\r\n or {n+}\r\n
        let close = self.s[self.p..].iter().position(|&c| c == b'}').ok_or(ParseError("Bad literal".into()))?;
        let inner = &self.s[self.p + 1..self.p + close];
        let digits = inner.strip_suffix(b"+").unwrap_or(inner);
        let n: usize = std::str::from_utf8(digits)
            .ok()
            .and_then(|d| d.parse().ok())
            .ok_or(ParseError("Bad literal size".into()))?;
        self.p += close + 1;
        if self.s.get(self.p..self.p + 2) != Some(b"\r\n") {
            return perr("Bad literal");
        }
        self.p += 2;
        let data = self.s.get(self.p..self.p + n).ok_or(ParseError("Short literal".into()))?.to_vec();
        self.p += n;
        Ok(data)
    }

    pub fn arg(&mut self) -> PResult<Arg> {
        match self.peek() {
            None => perr("Missing argument"),
            Some(b'"') => Ok(Arg::Str(self.quoted()?)),
            Some(b'{') => Ok(Arg::Lit(self.literal()?)),
            Some(b'~') if self.s.get(self.p + 1) == Some(&b'{') => {
                self.p += 1;
                Ok(Arg::Lit8(self.literal()?))
            }
            Some(b'(') => {
                self.p += 1;
                let mut items = vec![];
                loop {
                    match self.peek() {
                        Some(b')') => {
                            self.p += 1;
                            return Ok(Arg::List(items));
                        }
                        Some(b' ') if !items.is_empty() => {
                            self.p += 1;
                        }
                        None => return perr("Unterminated list"),
                        _ => items.push(self.arg()?),
                    }
                    if items.len() > 10_000 {
                        return perr("List too long");
                    }
                }
            }
            Some(_) => Ok(Arg::Atom(self.atom()?)),
        }
    }

    /// All remaining space-separated arguments.
    pub fn args(&mut self) -> PResult<Vec<Arg>> {
        let mut out = vec![];
        while !self.at_end() {
            self.sp()?;
            if self.at_end() {
                // Trailing space.
                return perr("Unexpected trailing space");
            }
            out.push(self.arg()?);
            if out.len() > 10_000 {
                return perr("Too many arguments");
            }
        }
        Ok(out)
    }
}

/// Split a command into tag, name and the rest.
pub fn split_command(cmd: &[u8]) -> Option<(String, String, usize)> {
    let sp = cmd.iter().position(|&c| c == b' ')?;
    let tag = &cmd[..sp];
    if tag.is_empty() || !tag.iter().all(|&c| c > b' ' && c < 0x7f && !b"(){%*\"\\+".contains(&c)) {
        return None;
    }
    let rest = &cmd[sp + 1..];
    let end = rest.iter().position(|&c| c == b' ').unwrap_or(rest.len());
    let name = &rest[..end];
    if name.is_empty() || !name.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'-' || *c == b'.') {
        return None;
    }
    Some((
        String::from_utf8_lossy(tag).into_owned(),
        String::from_utf8_lossy(name).to_ascii_uppercase(),
        sp + 1 + end,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parse_args() {
        let s = b" 1:* (FLAGS BODY.PEEK[HEADER.FIELDS (From To)]<0.10>) \"q\\\"x\" {3}\r\nabc NIL";
        let mut p = Parser::new(s);
        let a = p.args().unwrap();
        assert_eq!(a[0], Arg::Atom("1:*".into()));
        match &a[1] {
            Arg::List(l) => {
                assert_eq!(l[1], Arg::Atom("BODY.PEEK[HEADER.FIELDS (From To)]<0.10>".into()));
            }
            _ => panic!(),
        }
        assert_eq!(a[2], Arg::Str(b"q\"x".to_vec()));
        assert_eq!(a[3], Arg::Lit(b"abc".to_vec()));
        assert!(a[4].is_nil());
    }
    #[test]
    fn literal_detect() {
        assert_eq!(literal_suffix(b"a APPEND x {10}"), Some((10, false)));
        assert_eq!(literal_suffix(b"a APPEND x {10+}"), Some((10, true)));
        assert_eq!(literal_suffix(b"a NOOP"), None);
    }
    #[test]
    fn split() {
        assert_eq!(split_command(b"a1 uid fetch 1"), Some(("a1".into(), "UID".into(), 6)));
        assert!(split_command(b"a+ NOOP").is_none());
    }
}
