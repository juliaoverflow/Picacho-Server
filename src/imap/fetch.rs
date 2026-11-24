//! FETCH attribute parsing and body section extraction.
use super::proto::Arg;
use crate::mime::{self, Part};

#[derive(Debug, Clone, PartialEq)]
pub enum Spec {
    Full,
    Header,
    HeaderFields(Vec<String>),
    HeaderFieldsNot(Vec<String>),
    Text,
    Mime,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Att {
    Uid,
    Flags,
    InternalDate,
    Size,
    Envelope,
    Body,
    BodyStructure,
    Rfc822,
    Rfc822Header,
    Rfc822Text,
    ModSeq,
    Section {
        peek: bool,
        path: Vec<usize>,
        spec: Spec,
        partial: Option<(usize, usize)>,
        /// Section text echoed back in the response (`HEADER.FIELDS (A B)`).
        label: String,
    },
    /// RFC 3516 BINARY[part]: the part with its transfer encoding removed.
    Binary {
        peek: bool,
        path: Vec<usize>,
        partial: Option<(usize, usize)>,
        label: String,
    },
    BinarySize {
        path: Vec<usize>,
        label: String,
    },
    /// RFC 8474 OBJECTID.
    EmailId,
    ThreadId,
    /// RFC 8514: when the message was saved in this mailbox.
    SaveDate,
    /// RFC 8970: a short plain-text preview.
    Preview,
}

impl Att {
    pub fn needs_content(&self) -> bool {
        matches!(
            self,
            Att::Rfc822 | Att::Rfc822Header | Att::Rfc822Text | Att::Section { .. } | Att::Binary { .. } | Att::BinarySize { .. }
        )
    }
    pub fn needs_parse(&self) -> bool {
        matches!(self, Att::Section { .. } | Att::Binary { .. } | Att::BinarySize { .. })
    }
    pub fn sets_seen(&self) -> bool {
        matches!(self, Att::Rfc822 | Att::Rfc822Text | Att::Section { peek: false, .. } | Att::Binary { peek: false, .. })
    }
}

pub fn parse_atts(arg: &Arg) -> Result<Vec<Att>, String> {
    match arg {
        Arg::Atom(a) => match a.to_ascii_uppercase().as_str() {
            "ALL" => Ok(vec![Att::Flags, Att::InternalDate, Att::Size, Att::Envelope]),
            "FAST" => Ok(vec![Att::Flags, Att::InternalDate, Att::Size]),
            "FULL" => Ok(vec![Att::Flags, Att::InternalDate, Att::Size, Att::Envelope, Att::Body]),
            _ => Ok(vec![parse_att(a)?]),
        },
        Arg::List(items) => {
            let mut out = vec![];
            for i in items {
                match i {
                    Arg::Atom(a) => out.push(parse_att(a)?),
                    // RFC 8970 preview modifiers: `PREVIEW (LAZY)`. Previews are
                    // always available here, so LAZY changes nothing.
                    Arg::List(m) if matches!(out.last(), Some(Att::Preview)) => {
                        if !m.iter().all(|x| x.as_atom().is_some_and(|a| a.eq_ignore_ascii_case("LAZY"))) {
                            return Err("Unknown PREVIEW modifier".into());
                        }
                    }
                    _ => return Err("Invalid fetch attribute".into()),
                }
            }
            if out.is_empty() {
                return Err("Empty fetch attribute list".into());
            }
            Ok(out)
        }
        _ => Err("Invalid fetch attributes".into()),
    }
}

fn parse_att(a: &str) -> Result<Att, String> {
    let up = a.to_ascii_uppercase();
    Ok(match up.as_str() {
        "UID" => Att::Uid,
        "FLAGS" => Att::Flags,
        "INTERNALDATE" => Att::InternalDate,
        "RFC822.SIZE" => Att::Size,
        "ENVELOPE" => Att::Envelope,
        "BODY" => Att::Body,
        "BODYSTRUCTURE" => Att::BodyStructure,
        "RFC822" => Att::Rfc822,
        "RFC822.HEADER" => Att::Rfc822Header,
        "RFC822.TEXT" => Att::Rfc822Text,
        "MODSEQ" => Att::ModSeq,
        "EMAILID" => Att::EmailId,
        "THREADID" => Att::ThreadId,
        "SAVEDATE" => Att::SaveDate,
        "PREVIEW" => Att::Preview,
        _ if up.starts_with("BINARY") => {
            let (kind, rest) = if let Some(r) = up.strip_prefix("BINARY.PEEK[") {
                (1, &a[a.len() - r.len()..])
            } else if let Some(r) = up.strip_prefix("BINARY.SIZE[") {
                (2, &a[a.len() - r.len()..])
            } else if let Some(r) = up.strip_prefix("BINARY[") {
                (0, &a[a.len() - r.len()..])
            } else {
                return Err(format!("Unknown fetch attribute {a}"));
            };
            let close = rest.find(']').ok_or("Missing ]")?;
            let section = &rest[..close];
            let after = &rest[close + 1..];
            let mut path = vec![];
            if !section.is_empty() {
                for n in section.split('.') {
                    let n: usize = n.parse().map_err(|_| "BINARY takes part numbers only")?;
                    if n == 0 {
                        return Err("Invalid part number".into());
                    }
                    path.push(n);
                }
            }
            let partial = parse_partial(after)?;
            if kind == 2 {
                if partial.is_some() {
                    return Err("BINARY.SIZE takes no partial".into());
                }
                Att::BinarySize { path, label: section.to_string() }
            } else {
                Att::Binary { peek: kind == 1, path, partial, label: section.to_string() }
            }
        }
        _ => {
            let (peek, rest) = if let Some(r) = up.strip_prefix("BODY.PEEK[") {
                (true, &a[a.len() - r.len()..])
            } else if let Some(r) = up.strip_prefix("BODY[") {
                (false, &a[a.len() - r.len()..])
            } else {
                return Err(format!("Unknown fetch attribute {a}"));
            };
            let close = rest.rfind(']').ok_or("Missing ]")?;
            let section = &rest[..close];
            let after = &rest[close + 1..];
            let partial = parse_partial(after)?;
            let (path, spec) = parse_section(section)?;
            Att::Section { peek, path, spec, partial, label: section.to_string() }
        }
    })
}

fn parse_partial(after: &str) -> Result<Option<(usize, usize)>, String> {
    if after.is_empty() {
        return Ok(None);
    }
    let inner = after.strip_prefix('<').and_then(|x| x.strip_suffix('>')).ok_or("Invalid partial")?;
    let (o, c) = inner.split_once('.').ok_or("Invalid partial")?;
    let o: usize = o.parse().map_err(|_| "Invalid partial")?;
    let c: usize = c.parse().map_err(|_| "Invalid partial")?;
    if c == 0 {
        return Err("Invalid partial".into());
    }
    Ok(Some((o, c)))
}

/// Decoded content of a part for BINARY. Err(()) = unknown transfer encoding.
pub fn binary_bytes(data: &[u8], root: &Part, path: &[usize]) -> Option<Result<Vec<u8>, ()>> {
    if path.is_empty() {
        return Some(Ok(data.to_vec()));
    }
    let part = mime::find_part(root, path)?;
    let body = part.body_bytes(data);
    if part.is_multipart() || part.message.is_some() {
        return Some(Ok(body.to_vec()));
    }
    let enc = part
        .header(data, "content-transfer-encoding")
        .map(|v| String::from_utf8_lossy(&v).trim().to_ascii_lowercase())
        .unwrap_or_default();
    Some(match enc.as_str() {
        "" | "7bit" | "8bit" | "binary" => Ok(body.to_vec()),
        "base64" => Ok(mime::decode_base64(body)),
        "quoted-printable" => Ok(mime::decode_qp(body)),
        _ => Err(()),
    })
}

pub fn parse_section_spec(s: &str) -> Result<(Vec<usize>, Spec), String> {
    parse_section(s)
}

fn parse_section(s: &str) -> Result<(Vec<usize>, Spec), String> {
    let mut path = vec![];
    let mut rest = s;
    loop {
        let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
        if end == 0 {
            break;
        }
        let n: usize = rest[..end].parse().map_err(|_| "Invalid section")?;
        if n == 0 {
            return Err("Invalid section number".into());
        }
        path.push(n);
        rest = &rest[end..];
        if let Some(r) = rest.strip_prefix('.') {
            rest = r;
        } else {
            break;
        }
        if path.len() > 64 {
            return Err("Section too deep".into());
        }
    }
    let up = rest.to_ascii_uppercase();
    let spec = if up.is_empty() {
        Spec::Full
    } else if up == "HEADER" {
        Spec::Header
    } else if up == "TEXT" {
        Spec::Text
    } else if up == "MIME" {
        if path.is_empty() {
            return Err("MIME requires a part number".into());
        }
        Spec::Mime
    } else if let Some(list) = up.strip_prefix("HEADER.FIELDS.NOT") {
        Spec::HeaderFieldsNot(field_list(list)?)
    } else if let Some(list) = up.strip_prefix("HEADER.FIELDS") {
        Spec::HeaderFields(field_list(list)?)
    } else {
        return Err(format!("Invalid section {rest}"));
    };
    Ok((path, spec))
}

fn field_list(s: &str) -> Result<Vec<String>, String> {
    let s = s.trim();
    let inner = s.strip_prefix('(').and_then(|x| x.strip_suffix(')')).ok_or("Invalid header field list")?;
    let mut out = vec![];
    let mut p = super::proto::Parser::new(inner.as_bytes());
    while !p.at_end() {
        p.opt_sp();
        if p.at_end() {
            break;
        }
        let a = p.arg().map_err(|e| e.0)?;
        out.push(a.string().ok_or("Invalid header field name")?.to_ascii_lowercase());
    }
    if out.is_empty() {
        return Err("Empty header field list".into());
    }
    Ok(out)
}

fn header_subset(data: &[u8], part: &Part, names: &[String], negate: bool) -> Vec<u8> {
    let mut out = Vec::new();
    for f in &part.fields {
        let m = names.iter().any(|n| n.eq_ignore_ascii_case(&f.name));
        if m != negate && !f.name.is_empty() {
            out.extend_from_slice(&data[f.start..f.end]);
        }
    }
    out.extend_from_slice(b"\r\n");
    out
}

/// Bytes of a body section; None when the section doesn't exist.
pub fn section_bytes(data: &[u8], root: &Part, path: &[usize], spec: &Spec) -> Option<Vec<u8>> {
    let part = if path.is_empty() { root } else { mime::find_part(root, path)? };
    // HEADER/TEXT on a part number address the encapsulated message.
    fn msg_part<'a>(root: &'a Part, p: &'a Part, top: bool) -> Option<&'a Part> {
        if top {
            Some(root)
        } else {
            p.message.as_deref()
        }
    }
    let top = path.is_empty();
    Some(match spec {
        Spec::Full => {
            if path.is_empty() {
                data.to_vec()
            } else {
                part.body_bytes(data).to_vec()
            }
        }
        Spec::Mime => part.header_bytes(data).to_vec(),
        Spec::Header => msg_part(root, part, top)?.header_bytes(data).to_vec(),
        Spec::Text => msg_part(root, part, top)?.body_bytes(data).to_vec(),
        Spec::HeaderFields(n) => header_subset(data, msg_part(root, part, top)?, n, false),
        Spec::HeaderFieldsNot(n) => header_subset(data, msg_part(root, part, top)?, n, true),
    })
}

pub fn format_internal_date(ts: i64) -> String {
    use chrono::TimeZone;
    let d = chrono::Utc.timestamp_opt(ts, 0).single().unwrap_or_default();
    d.format("%d-%b-%Y %H:%M:%S +0000").to_string()
}

pub fn parse_internal_date(s: &str) -> Option<i64> {
    let s = s.trim();
    chrono::DateTime::parse_from_str(s, "%d-%b-%Y %H:%M:%S %z")
        .or_else(|_| chrono::DateTime::parse_from_str(&format!("0{s}"), "%d-%b-%Y %H:%M:%S %z"))
        .ok()
        .map(|d| d.timestamp())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn atts() {
        let a = parse_att("BODY.PEEK[HEADER.FIELDS (From Subject)]<0.100>").unwrap();
        match a {
            Att::Section { peek, path, spec, partial, label } => {
                assert!(peek);
                assert!(path.is_empty());
                assert_eq!(spec, Spec::HeaderFields(vec!["from".into(), "subject".into()]));
                assert_eq!(partial, Some((0, 100)));
                assert_eq!(label, "HEADER.FIELDS (From Subject)");
            }
            _ => panic!(),
        }
        assert!(matches!(parse_att("BODY[1.2.MIME]").unwrap(), Att::Section { spec: Spec::Mime, .. }));
        assert!(parse_att("BODY[MIME]").is_err());
    }
    #[test]
    fn dates() {
        let t = parse_internal_date(" 1-Jan-2024 10:00:00 +0100").unwrap();
        assert_eq!(format_internal_date(t), "01-Jan-2024 09:00:00 +0000");
    }
    #[test]
    fn sections() {
        let m = b"From: a@b\r\nTo: c@d\r\nSubject: x\r\n\r\nbody\r\n";
        let root = mime::parse(m);
        assert_eq!(
            section_bytes(m, &root, &[], &Spec::HeaderFields(vec!["subject".into()])).unwrap(),
            b"Subject: x\r\n\r\n"
        );
        assert_eq!(section_bytes(m, &root, &[], &Spec::Text).unwrap(), b"body\r\n");
        assert_eq!(section_bytes(m, &root, &[1], &Spec::Full).unwrap(), b"body\r\n");
    }
}
