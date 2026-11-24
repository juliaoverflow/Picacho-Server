//! Modified UTF-7 (RFC 3501 5.1.3), the form mailbox names are stored in.
//! Sessions with UTF8=ACCEPT (RFC 6855) or IMAP4rev2 (RFC 9051) see them as
//! UTF-8; the rest see them as stored.
use base64::alphabet::Alphabet;
use base64::engine::{general_purpose::NO_PAD, GeneralPurpose};
use base64::Engine;

fn engine() -> GeneralPurpose {
    let a = Alphabet::new("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+,").unwrap();
    GeneralPurpose::new(&a, NO_PAD)
}

/// UTF-8 to modified UTF-7.
pub fn encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut pending: Vec<u16> = vec![];
    let flush = |pending: &mut Vec<u16>, out: &mut String| {
        if pending.is_empty() {
            return;
        }
        let bytes: Vec<u8> = pending.iter().flat_map(|u| u.to_be_bytes()).collect();
        out.push('&');
        out.push_str(&engine().encode(bytes));
        out.push('-');
        pending.clear();
    };
    for c in s.chars() {
        if (' '..='~').contains(&c) {
            flush(&mut pending, &mut out);
            if c == '&' {
                out.push_str("&-");
            } else {
                out.push(c);
            }
        } else {
            let mut buf = [0u16; 2];
            pending.extend_from_slice(c.encode_utf16(&mut buf));
        }
    }
    flush(&mut pending, &mut out);
    out
}

/// Modified UTF-7 to UTF-8; `None` when it isn't valid modified UTF-7.
pub fn decode(s: &str) -> Option<String> {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        let after = &rest[i + 1..];
        let end = after.find('-')?;
        let b64 = &after[..end];
        if b64.is_empty() {
            out.push('&');
        } else {
            let bytes = engine().decode(b64).ok()?;
            if bytes.len() % 2 != 0 {
                return None;
            }
            let units: Vec<u16> = bytes.chunks(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
            out.push_str(&String::from_utf16(&units).ok()?);
        }
        rest = &after[end + 1..];
    }
    if !rest.is_ascii() {
        return None;
    }
    out.push_str(rest);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roundtrip() {
        for (u, m) in [("Entwürfe", "Entw&APw-rfe"), ("A&B", "A&-B"), ("日本語", "&ZeVnLIqe-"), ("Sent/🎉", "Sent/&2DzfiQ-"), ("plain", "plain")] {
            assert_eq!(encode(u), m, "{u}");
            assert_eq!(decode(m).as_deref(), Some(u), "{m}");
        }
        assert_eq!(decode("&Jjo"), None);
        assert_eq!(decode("caf\u{e9}"), None);
    }
}
