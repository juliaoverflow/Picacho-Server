//! Recipient resolution and delivery of accepted messages: local mailboxes,
//! forwarding (with SRS), per-domain transports and the outbound queue.
use crate::db::Domain;
use crate::state::State;
use crate::util::{domain_of, normalize_address};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Target {
    /// Store in this account (folder decided at delivery).
    Local(i64),
    /// Send out via the queue (direct MX or a routed transport).
    Remote(String),
    /// A domain handled by a transport (relay/webhook domain).
    Transport(String, String),
    /// Held for a downstream Picacho server (relay link).
    Peer(String, String),
}

#[derive(Debug, PartialEq)]
pub enum RcptError {
    NoSuchUser,
    RelayDenied,
    Disabled,
    Temporary,
}

/// Resolve one recipient. `relay_ok` permits remote recipients (the sender
/// authenticated). Forwarding targets from aliases are always allowed.
pub async fn resolve(state: &State, addr: &str, relay_ok: bool) -> Result<Vec<Target>, RcptError> {
    let addr = normalize_address(addr).ok_or(RcptError::NoSuchUser)?;
    // Postmaster must always be accepted (RFC 5321 4.5.1).
    let mut out = BTreeSet::new();
    let domain = state.db.domain_by_name(domain_of(&addr)).await.map_err(|_| RcptError::Temporary)?;
    match domain {
        None => {
            if let Some(orig) = srs_reverse(state, &addr).await {
                // Bounces to forwarded mail go back to the original sender.
                out.insert(Target::Remote(orig));
                return Ok(out.into_iter().collect());
            }
            if relay_ok {
                out.insert(Target::Remote(addr));
                return Ok(out.into_iter().collect());
            }
            return Err(RcptError::RelayDenied);
        }
        Some(d) if !d.active => return Err(RcptError::Disabled),
        Some(d) => expand(state, &addr, &d, &mut out, 0).await?,
    }
    if out.is_empty() {
        return Err(RcptError::NoSuchUser);
    }
    Ok(out.into_iter().collect())
}

fn expand<'a>(
    state: &'a State,
    addr: &'a str,
    domain: &'a Domain,
    out: &'a mut BTreeSet<Target>,
    depth: usize,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), RcptError>> + Send + 'a>> {
    Box::pin(async move {
        if depth > 6 {
            return Ok(());
        }
        if domain.mode == "relay" || domain.mode == "webhook" {
            out.insert(Target::Transport(addr.to_string(), domain.transport.clone()));
            return Ok(());
        }
        if domain.mode == "peer" {
            out.insert(Target::Peer(addr.to_string(), domain.transport.clone()));
            return Ok(());
        }
        if let Some(orig) = srs_reverse(state, addr).await {
            out.insert(Target::Remote(orig));
            return Ok(());
        }
        let db = &state.db;
        let tmp = |_| RcptError::Temporary;
        let (local, dom) = addr.rsplit_once('@').unwrap_or((addr, ""));
        let base = local.split_once('+').map(|(b, _)| format!("{b}@{dom}"));
        let candidates: Vec<String> = std::iter::once(addr.to_string()).chain(base).collect();
        for cand in &candidates {
            if let Some(a) = db.alias_by_source(cand).await.map_err(tmp)? {
                if a.active {
                    return add_destinations(state, &a.destination, out, depth).await;
                }
            }
            if let Some(acc) = db.account_by_email(cand).await.map_err(tmp)? {
                if !acc.active {
                    return Err(RcptError::Disabled);
                }
                let fwd: Vec<String> = acc.forward_to.split(',').filter_map(normalize_address).collect();
                if fwd.is_empty() || acc.keep_copy {
                    out.insert(Target::Local(acc.id));
                }
                for f in fwd {
                    out.insert(Target::Remote(f));
                }
                return Ok(());
            }
        }
        if (local.eq_ignore_ascii_case("postmaster") || local.eq_ignore_ascii_case("abuse")) && depth == 0 {
            // Route postmaster/abuse to the first admin when no alias exists.
            if let Ok(accs) = db.list_accounts().await {
                if let Some(admin) = accs.iter().find(|a| a.is_admin() && a.active) {
                    out.insert(Target::Local(admin.id));
                    return Ok(());
                }
            }
        }
        // Catch-all: alias for @domain, then the domain's catch-all field.
        if let Some(a) = db.alias_by_source(&format!("@{dom}")).await.map_err(tmp)? {
            if a.active {
                return add_destinations(state, &a.destination, out, depth).await;
            }
        }
        if !domain.catch_all.trim().is_empty() {
            return add_destinations(state, &domain.catch_all, out, depth).await;
        }
        Err(RcptError::NoSuchUser)
    })
}

async fn add_destinations(state: &State, dests: &str, out: &mut BTreeSet<Target>, depth: usize) -> Result<(), RcptError> {
    for d in dests.split([',', ' ', '\n']).filter_map(normalize_address) {
        match state.db.domain_by_name(domain_of(&d)).await.map_err(|_| RcptError::Temporary)? {
            Some(dom) if dom.active => {
                // Unknown local targets in an alias are skipped, not fatal.
                let _ = expand(state, &d, &dom, out, depth + 1).await;
            }
            _ => {
                out.insert(Target::Remote(d));
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------- SRS

async fn srs_secret(state: &State) -> Vec<u8> {
    if let Ok(Some(s)) = state.db.get_setting("srs_secret").await {
        if let Ok(b) = hex::decode(s) {
            return b;
        }
    }
    let s = crate::util::random_bytes::<32>();
    let _ = state.db.set_setting("srs_secret", &hex::encode(s)).await;
    s.to_vec()
}

fn srs_hash(secret: &[u8], ts: &str, domain: &str, local: &str) -> String {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(secret).unwrap();
    m.update(ts.as_bytes());
    m.update(domain.to_ascii_lowercase().as_bytes());
    m.update(local.as_bytes());
    hex::encode(&m.finalize().into_bytes()[..4])
}

/// Rewrite an envelope sender for forwarding (SRS0) so SPF passes downstream.
pub async fn srs_forward(state: &State, sender: &str) -> String {
    let Some(primary) = state.settings().server.primary_domain.clone() else {
        return sender.to_string();
    };
    let Some((local, domain)) = sender.rsplit_once('@') else { return sender.to_string() };
    if domain.eq_ignore_ascii_case(&primary) || sender.is_empty() {
        return sender.to_string();
    }
    let secret = srs_secret(state).await;
    let ts = format!("{:x}", (crate::util::now() / 86400) % 1024);
    let h = srs_hash(&secret, &ts, domain, local);
    format!("SRS0={h}={ts}={domain}={local}@{primary}")
}

async fn srs_reverse(state: &State, addr: &str) -> Option<String> {
    let (local, _) = addr.rsplit_once('@')?;
    let rest = local.strip_prefix("srs0=").or_else(|| local.strip_prefix("SRS0="))?;
    let mut it = rest.splitn(4, '=');
    let (h, ts, domain, orig_local) = (it.next()?, it.next()?, it.next()?, it.next()?);
    let secret = srs_secret(state).await;
    if srs_hash(&secret, ts, domain, orig_local) != h.to_ascii_lowercase() {
        return None;
    }
    let day = (crate::util::now() / 86400) % 1024;
    let then = i64::from_str_radix(ts, 16).ok()?;
    if (day - then).rem_euclid(1024) > 21 {
        return None;
    }
    Some(format!("{orig_local}@{domain}"))
}

// ---------------------------------------------------------------- DKIM

/// Generate an RSA-2048 DKIM key: (private PKCS#1 DER base64, public base64).
pub fn generate_dkim() -> anyhow::Result<(String, String)> {
    use base64::Engine;
    let pair = mail_auth::dkim::generate::DkimKeyPair::generate_rsa(2048).map_err(|e| anyhow::anyhow!("{e}"))?;
    let b = base64::engine::general_purpose::STANDARD;
    Ok((b.encode(pair.private_key()), b.encode(pair.public_key())))
}

/// The DKIM key for a domain (or the primary domain): (key, domain, selector).
pub async fn signing_key(
    state: &State,
    domain: Option<&str>,
) -> Option<(mail_auth::crypto::RsaKey<mail_auth::crypto::Sha256>, String, String)> {
    use base64::Engine;
    let name = match domain {
        Some(d) => d.to_string(),
        None => state.settings().server.primary_domain.clone()?,
    };
    let d = state.db.domain_by_name(&name).await.ok()??;
    if d.dkim_private.is_empty() || d.dkim_selector.is_empty() {
        return None;
    }
    let der = base64::engine::general_purpose::STANDARD.decode(&d.dkim_private).ok()?;
    let key = mail_auth::crypto::RsaKey::<mail_auth::crypto::Sha256>::from_key_der(rustls::pki_types::PrivateKeyDer::Pkcs1(der.into())).ok()?;
    Some((key, d.name, d.dkim_selector))
}

/// Prepend a DKIM-Signature when the sender's domain has a key.
pub async fn dkim_sign(state: &State, sender_domain: &str, raw: Vec<u8>) -> Vec<u8> {
    use base64::Engine;
    if !state.settings().delivery.dkim_sign {
        return raw;
    }
    let Ok(Some(d)) = state.db.domain_by_name(sender_domain).await else { return raw };
    if d.dkim_private.is_empty() || d.dkim_selector.is_empty() {
        return raw;
    }
    let Ok(der) = base64::engine::general_purpose::STANDARD.decode(&d.dkim_private) else { return raw };
    let key = match mail_auth::crypto::RsaKey::<mail_auth::crypto::Sha256>::from_key_der(
        rustls::pki_types::PrivateKeyDer::Pkcs1(der.into()),
    ) {
        Ok(k) => k,
        Err(e) => {
            tracing::warn!("dkim key for {sender_domain}: {e}");
            return raw;
        }
    };
    let sig = mail_auth::dkim::DkimSigner::from_key(key)
        .domain(&d.name)
        .selector(&d.dkim_selector)
        .headers(["From", "To", "Cc", "Subject", "Date", "Message-ID", "Reply-To", "In-Reply-To", "References", "MIME-Version", "Content-Type"])
        .sign(&raw);
    match sig {
        Ok(s) => {
            let mut out = mail_auth::headers::HeaderWriter::to_header(&s).into_bytes();
            out.extend_from_slice(&raw);
            out
        }
        Err(e) => {
            tracing::warn!("dkim signing for {sender_domain} failed: {e}");
            raw
        }
    }
}
