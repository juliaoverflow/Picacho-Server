//! URLAUTH (RFC 4467): IMAP URLs another party may fetch, for SMTP BURL
//! (RFC 4468) "send this message from my mailbox without uploading it".
//!
//! `GENURLAUTH <url>;urlauth=<access> INTERNAL` returns the URL with
//! `:internal:<token>` appended. The token is HMAC-SHA256 (hex, 32 bytes) of
//! the URL under a key kept per account (in the database's settings), and
//! RESETKEY replaces the key, invalidating every URL issued before.
//! Accesses: `submit+<user>` (the submission server, for that user only),
//! `user+<user>` and `authuser` (any signed-in user of this server).
use crate::db::Account;
use crate::state::State;
use hmac::{Hmac, Mac};
use sha2::Sha256;

pub const MECH: &str = "INTERNAL";

/// The pieces of an IMAP URL with URLAUTH.
#[derive(Debug, Clone, PartialEq)]
pub struct Url {
    /// Everything up to (not including) `:internal:<token>`.
    pub rump: String,
    pub owner: String,
    pub mailbox: String,
    pub uidvalidity: Option<i64>,
    pub uid: i64,
    pub section: String,
    pub partial: Option<(usize, Option<usize>)>,
    pub expire: Option<i64>,
    pub access: String,
    pub token: Option<String>,
}

fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parse `imap://user@host/mailbox;UIDVALIDITY=n/;UID=n[/;SECTION=x][/;PARTIAL=o.l][;EXPIRE=t];URLAUTH=access[:internal:token]`.
pub fn parse(url: &str) -> Option<Url> {
    let rest = url.strip_prefix("imap://").or_else(|| url.strip_prefix("IMAP://"))?;
    let (auth, path) = rest.split_once('/')?;
    let owner = pct_decode(auth.split_once('@')?.0.split(';').next()?);
    // The token, if any, ends the URL.
    let (rump, token) = match path.to_ascii_lowercase().rfind(":internal:") {
        Some(i) => (&url[..url.len() - path.len() + i], Some(path[i + ":internal:".len()..].to_string())),
        None => (url, None),
    };
    let p = &path[..path.len() - token.as_ref().map(|t| t.len() + ":internal:".len()).unwrap_or(0)];
    let mut segs = p.split("/;");
    let mb = segs.next()?;
    let (mbname, validity) = match mb.to_ascii_lowercase().find(";uidvalidity=") {
        Some(i) => (&mb[..i], mb[i + ";uidvalidity=".len()..].parse::<i64>().ok()),
        None => (mb, None),
    };
    let mut u = Url {
        rump: rump.to_string(),
        owner,
        mailbox: pct_decode(mbname),
        uidvalidity: validity,
        uid: 0,
        section: String::new(),
        partial: None,
        expire: None,
        access: String::new(),
        token,
    };
    for seg in segs {
        for (n, part) in seg.split(';').enumerate() {
            let (k, v) = part.split_once('=').unwrap_or((part, ""));
            match (n, k.to_ascii_lowercase().as_str()) {
                (0, "uid") => u.uid = v.parse().ok()?,
                (0, "section") => u.section = pct_decode(v),
                (0, "partial") => {
                    let (o, l) = v.split_once('.').unwrap_or((v, ""));
                    u.partial = Some((o.parse().ok()?, l.parse().ok()));
                }
                (_, "expire") => u.expire = chrono::DateTime::parse_from_rfc3339(v).ok().map(|d| d.timestamp()),
                (_, "urlauth") => u.access = v.to_string(),
                _ => return None,
            }
        }
    }
    (u.uid > 0 && !u.access.is_empty()).then_some(u)
}

async fn key(state: &State, account_id: i64) -> anyhow::Result<Vec<u8>> {
    let name = format!("urlauth_key:{account_id}");
    if let Some(k) = state.db.get_setting(&name).await? {
        if let Ok(b) = hex::decode(k) {
            return Ok(b);
        }
    }
    let k: [u8; 32] = crate::util::random_bytes();
    state.db.set_setting(&name, &hex::encode(k)).await?;
    Ok(k.to_vec())
}

fn mac(key: &[u8], rump: &str) -> String {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).unwrap();
    m.update(rump.as_bytes());
    hex::encode(m.finalize().into_bytes())
}

/// RESETKEY: a new key for the account; every earlier URL stops working.
pub async fn reset(state: &State, account_id: i64) -> anyhow::Result<()> {
    let k: [u8; 32] = crate::util::random_bytes();
    state.db.set_setting(&format!("urlauth_key:{account_id}"), &hex::encode(k)).await
}

/// GENURLAUTH for `account`: the URL with its token, or why not.
pub async fn generate(state: &State, account: &Account, url: &str) -> anyhow::Result<Result<String, &'static str>> {
    let Some(u) = parse(url) else { return Ok(Err("Not an IMAP URL with ;URLAUTH=")) };
    if u.token.is_some() {
        return Ok(Err("The URL is already authorized"));
    }
    if !u.owner.eq_ignore_ascii_case(&account.email) {
        return Ok(Err("Only the mailbox owner can authorize URLs"));
    }
    let access = u.access.to_ascii_lowercase();
    if !(access == "authuser" || access == "anonymous" || access.starts_with("submit+") || access.starts_with("user+")) {
        return Ok(Err("Unknown access identifier"));
    }
    if access == "anonymous" {
        return Ok(Err("Anonymous access isn't allowed"));
    }
    let k = key(state, account.id).await?;
    Ok(Ok(format!("{}:internal:{}", u.rump, mac(&k, &u.rump))))
}

/// Resolve an authorized URL for `reader` (the signed-in user fetching,
/// or `None` for the submission server). Returns the bytes, or None when
/// the URL isn't valid, expired, or not for this reader.
pub async fn fetch(state: &State, url: &str, reader: Option<&Account>, submission: bool) -> anyhow::Result<Option<Vec<u8>>> {
    let Some(u) = parse(url) else { return Ok(None) };
    let Some(token) = &u.token else { return Ok(None) };
    if u.expire.is_some_and(|t| t < crate::util::now()) {
        return Ok(None);
    }
    let Some(owner) = state.db.account_by_email(&u.owner).await?.filter(|a| a.active) else { return Ok(None) };
    let k = key(state, owner.id).await?;
    let expected = mac(&k, &u.rump);
    if !bool::from(subtle::ConstantTimeEq::ct_eq(expected.as_bytes(), token.to_ascii_lowercase().as_bytes())) {
        return Ok(None);
    }
    let access = u.access.to_ascii_lowercase();
    let allowed = match (access.split_once('+'), reader) {
        (Some(("submit", who)), Some(r)) => submission && r.email.eq_ignore_ascii_case(&pct_decode(who)),
        (Some(("user", who)), Some(r)) => r.email.eq_ignore_ascii_case(&pct_decode(who)),
        (None, Some(_)) if access == "authuser" => true,
        _ => false,
    };
    if !allowed {
        return Ok(None);
    }
    let name = crate::imap::normalize_mailbox(&u.mailbox);
    let Some(mb) = state.db.mailbox(owner.id, &name).await? else { return Ok(None) };
    if u.uidvalidity.is_some_and(|v| v != mb.uidvalidity) {
        return Ok(None);
    }
    let rows = state.db.messages_by_uids(mb.id, u.uid, u.uid).await?;
    let Some(row) = rows.first() else { return Ok(None) };
    let raw = state.blobs.get(&row.blob).await?;
    let data = if u.section.is_empty() {
        raw.to_vec()
    } else {
        let Ok((p, spec)) = crate::imap::fetch::parse_section_spec(&u.section.to_ascii_uppercase()) else { return Ok(None) };
        let root = crate::mime::parse(&raw);
        match crate::imap::fetch::section_bytes(&raw, &root, &p, &spec) {
            Some(d) => d,
            None => return Ok(None),
        }
    };
    Ok(Some(match u.partial {
        Some((o, l)) => {
            let s = o.min(data.len());
            let e = l.map(|l| o.saturating_add(l).min(data.len())).unwrap_or(data.len());
            data[s..e].to_vec()
        }
        None => data,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn urls() {
        let u = parse("imap://bob%40example.test@mx.test/Sent;UIDVALIDITY=7/;UID=42;urlauth=submit+bob%40example.test").unwrap();
        assert_eq!(u.owner, "bob@example.test");
        assert_eq!((u.mailbox.as_str(), u.uidvalidity, u.uid), ("Sent", Some(7), 42));
        assert_eq!(u.access, "submit+bob%40example.test");
        assert!(u.token.is_none());
        let t = parse("imap://bob@mx.test/INBOX/;UID=3/;SECTION=1.2;urlauth=authuser:internal:abcd").unwrap();
        assert_eq!((u.rump.ends_with("example.test"), t.section.as_str(), t.token.as_deref()), (true, "1.2", Some("abcd")));
        assert_eq!(t.rump, "imap://bob@mx.test/INBOX/;UID=3/;SECTION=1.2;urlauth=authuser");
        assert!(parse("imap://bob@mx.test/INBOX").is_none());
    }
}
