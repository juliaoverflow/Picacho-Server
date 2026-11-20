use rand::RngCore;
use std::path::Path;
use std::sync::atomic::{AtomicI64, Ordering};

/// Replace this process with a fresh copy of itself (same arguments).
pub fn reexec() {
    reexec_with(&[]);
}

/// Restart in place with extra environment variables.
pub fn reexec_with(env: &[(&str, &str)]) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        if let Ok(exe) = std::env::current_exe() {
            let mut cmd = std::process::Command::new(exe);
            cmd.args(std::env::args_os().skip(1));
            for (k, v) in env {
                cmd.env(k, v);
            }
            let err = cmd.exec();
            tracing::error!("restart failed: {err}");
        }
    }
    #[cfg(not(unix))]
    {
        let _ = env;
        tracing::error!("in-place restart is only supported on Unix; restart the service manually");
    }
}

pub fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    rand::rng().fill_bytes(&mut b);
    b
}

pub fn random_token() -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random_bytes::<32>())
}

pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(data))
}

static UIDVALIDITY: AtomicI64 = AtomicI64::new(0);

/// Strictly increasing UIDVALIDITY values that fit in 32 bits.
pub fn next_uidvalidity() -> i64 {
    let base = (now() - 1_577_836_800).max(1); // seconds since 2020-01-01
    loop {
        let cur = UIDVALIDITY.load(Ordering::SeqCst);
        let next = if base > cur { base } else { cur + 1 };
        if UIDVALIDITY.compare_exchange(cur, next, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
            return next & 0x7fff_ffff;
        }
    }
}

/// Owner-only permissions for secrets on Unix.
pub fn restrict_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// Lower-case and validate an email address (`local@domain`).
pub fn normalize_address(addr: &str) -> Option<String> {
    let a = addr.trim().trim_start_matches('<').trim_end_matches('>').trim();
    let (local, domain) = a.rsplit_once('@')?;
    if local.is_empty() || domain.is_empty() || a.len() > 254 || local.len() > 64 {
        return None;
    }
    if a.chars().any(|c| c.is_control() || c.is_whitespace() || c == '<' || c == '>' || c == ',') {
        return None;
    }
    if !valid_domain(domain) {
        return None;
    }
    Some(format!("{}@{}", local, domain.to_ascii_lowercase()).to_lowercase())
}

pub fn valid_domain(d: &str) -> bool {
    let d = d.trim_end_matches('.');
    if d.is_empty() || d.len() > 253 {
        return false;
    }
    if d.starts_with('[') && d.ends_with(']') {
        return d[1..d.len() - 1].parse::<std::net::IpAddr>().is_ok();
    }
    d.split('.').all(|l| {
        !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || !c.is_ascii())
    })
}

pub fn domain_of(addr: &str) -> &str {
    addr.rsplit_once('@').map(|(_, d)| d).unwrap_or("")
}

/// Convert bare LF (and lone CR) line endings to CRLF.
pub fn normalize_crlf(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + data.len() / 40);
    let mut i = 0;
    while i < data.len() {
        let c = data[i];
        if c == b'\r' {
            out.extend_from_slice(b"\r\n");
            if i + 1 < data.len() && data[i + 1] == b'\n' {
                i += 1;
            }
        } else if c == b'\n' {
            out.extend_from_slice(b"\r\n");
        } else {
            out.push(c);
        }
        i += 1;
    }
    out
}

pub fn ip_in_list(ip: std::net::IpAddr, list: &[String]) -> bool {
    list.iter().any(|entry| ip_matches(ip, entry))
}

pub fn ip_matches(ip: std::net::IpAddr, entry: &str) -> bool {
    let entry = entry.trim();
    if let Some((net, bits)) = entry.split_once('/') {
        let Ok(net) = net.parse::<std::net::IpAddr>() else { return false };
        let Ok(bits) = bits.parse::<u32>() else { return false };
        match (ip, net) {
            (std::net::IpAddr::V4(a), std::net::IpAddr::V4(n)) if bits <= 32 => {
                let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
                (u32::from(a) & mask) == (u32::from(n) & mask)
            }
            (std::net::IpAddr::V6(a), std::net::IpAddr::V6(n)) if bits <= 128 => {
                let mask = if bits == 0 { 0 } else { u128::MAX << (128 - bits) };
                (u128::from(a) & mask) == (u128::from(n) & mask)
            }
            _ => false,
        }
    } else {
        entry.parse::<std::net::IpAddr>().map(|e| e == ip).unwrap_or(false)
    }
}

pub fn is_loopback(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v) => v.is_loopback(),
        std::net::IpAddr::V6(v) => v.is_loopback() || v.to_ipv4_mapped().is_some_and(|m| m.is_loopback()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn crlf() {
        assert_eq!(normalize_crlf(b"a\nb\r\nc\rd"), b"a\r\nb\r\nc\r\nd");
    }
    #[test]
    fn addr() {
        assert_eq!(normalize_address("<Bob@Example.COM>").as_deref(), Some("bob@example.com"));
        assert!(normalize_address("bad").is_none());
        assert!(normalize_address("a b@x.com").is_none());
    }
    #[test]
    fn cidr() {
        let ip = "10.1.2.3".parse().unwrap();
        assert!(ip_matches(ip, "10.0.0.0/8"));
        assert!(!ip_matches(ip, "11.0.0.0/8"));
        assert!(ip_matches(ip, "10.1.2.3"));
    }
}
