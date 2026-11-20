//! OAuth 2.0 resource server.
//!
//! This server issues no tokens of its own. Apps get access tokens from the
//! identity provider configured under `auth.oidc` (for example Pinal
//! Accounts) by asking for this server's resource identifier (RFC 8707);
//! the provider signs them as JWTs (RFC 9068), and we verify them here
//! against its JWKS: signature, issuer, audience and expiry. The token's
//! `sub` picks the account through the same `issuer|sub` link single
//! sign-on uses, and its scopes decide what each protocol may do.
//!
//! Provider scopes are capability-based (`mail.read`, `mail.send`, …); they
//! are translated into this server's per-protocol scopes by [`map_scopes`].
use crate::auth::Principal;
use crate::settings::OidcSettings;
use crate::state::State;
use crate::util::now;
use base64::Engine;
use dashmap::DashMap;
use serde_json::Value;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// Marks a scope set as coming from an outside authorization server, so
/// local-only privileges (app passwords, export, Sieve via `imap`) aren't
/// implied by it.
pub const EXTERNAL: &str = "@external";

/// Capability scopes this server understands, as advertised in the
/// protected-resource metadata.
pub const SCOPES: [&str; 10] = [
    "mail.metadata",
    "mail.read",
    "mail.compose",
    "mail.send",
    "mail.labels",
    "mail.settings",
    "contacts.read",
    "contacts.write",
    "calendar.read",
    "calendar.write",
];

const MAX_TOKEN: usize = 8192;

/// A compact JWS: three base64url segments, a JSON header first.
pub fn looks_like_jwt(t: &str) -> bool {
    t.len() <= MAX_TOKEN
        && t.starts_with("eyJ")
        && t.split('.').count() == 3
        && t.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}

/// Translate provider scopes into this server's scopes. The provider's own
/// scopes are kept too, for the REST API, which checks them directly.
///
/// - `mail.read` → read-only IMAP and JMAP
/// - `mail.read` + `mail.labels` + `mail.compose` → full IMAP and JMAP (a mail app)
/// - `mail.send` → SMTP submission
/// - `mail.settings` → Sieve filters and account settings (forwarding, vacation)
/// - `calendar.*` → CalDAV, `contacts.*` → CardDAV
pub fn map_scopes(raw: &str) -> String {
    let have: Vec<&str> = raw.split_whitespace().collect();
    let has = |s: &str| have.contains(&s);
    let mut out: Vec<&str> = vec![EXTERNAL];
    out.extend(have.iter().filter(|s| SCOPES.contains(s)).copied());
    if has("mail.read") {
        if has("mail.labels") && has("mail.compose") {
            out.extend(["imap", "jmap"]);
        } else {
            out.extend(["imap:read", "jmap:read"]);
        }
    }
    if has("mail.send") {
        out.push("smtp");
    }
    if has("mail.settings") {
        out.extend(["sieve", "account"]);
    }
    if has("calendar.write") {
        out.push("caldav");
    } else if has("calendar.read") {
        out.push("caldav:read");
    }
    if has("contacts.write") {
        out.push("carddav");
    } else if has("contacts.read") {
        out.push("carddav:read");
    }
    out.join(" ")
}

#[derive(Clone)]
struct Jwk {
    kid: Option<String>,
    kty: String,
    alg: Option<String>,
    crv: Option<String>,
    n: Vec<u8>,
    e: Vec<u8>,
    x: Vec<u8>,
    y: Vec<u8>,
}

struct KeySet {
    keys: Vec<Jwk>,
    fetched: Instant,
}

fn jwks_cache() -> &'static DashMap<String, KeySet> {
    static C: OnceLock<DashMap<String, KeySet>> = OnceLock::new();
    C.get_or_init(DashMap::new)
}

/// Verified tokens, keyed by SHA-256 of the token: (account id, scopes, exp).
fn token_cache() -> &'static DashMap<String, (i64, String, i64)> {
    static C: OnceLock<DashMap<String, (i64, String, i64)>> = OnceLock::new();
    C.get_or_init(DashMap::new)
}

fn b64(s: &str) -> Result<Vec<u8>, String> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s.trim_end_matches('='))
        .map_err(|_| "Malformed token.".to_string())
}

async fn fetch_jwks(issuer: &str) -> Result<Vec<Jwk>, String> {
    let d = crate::oidc::discover(issuer).await?;
    let uri = d.jwks_uri.ok_or("The provider publishes no jwks_uri.")?;
    let r = crate::oidc::http()
        .get(&uri)
        .send()
        .await
        .map_err(|e| format!("Couldn't reach {uri}: {e}"))?;
    if !r.status().is_success() {
        return Err(format!("{uri} answered HTTP {}", r.status()));
    }
    let v: Value = r.json().await.map_err(|e| format!("Invalid JWKS: {e}"))?;
    let s = |k: &Value, f: &str| k.get(f).and_then(|x| x.as_str()).map(String::from);
    let bin = |k: &Value, f: &str| s(k, f).and_then(|x| b64(&x).ok()).unwrap_or_default();
    let keys = v
        .get("keys")
        .and_then(|k| k.as_array())
        .ok_or("JWKS has no keys")?
        .iter()
        .filter(|k| s(k, "use").map(|u| u == "sig").unwrap_or(true))
        .map(|k| Jwk {
            kid: s(k, "kid"),
            kty: s(k, "kty").unwrap_or_default(),
            alg: s(k, "alg"),
            crv: s(k, "crv"),
            n: bin(k, "n"),
            e: bin(k, "e"),
            x: bin(k, "x"),
            y: bin(k, "y"),
        })
        .collect();
    Ok(keys)
}

/// The provider's keys, refetched hourly, or sooner (at most every 30 s)
/// when a token names a key we haven't seen, so key rotation just works.
async fn keys_for(issuer: &str, kid: Option<&str>) -> Result<Vec<Jwk>, String> {
    let fresh = |ks: &KeySet| ks.fetched.elapsed() < Duration::from_secs(3600);
    let known =
        |ks: &KeySet| kid.is_none_or(|k| ks.keys.iter().any(|j| j.kid.as_deref() == Some(k)));
    if let Some(ks) = jwks_cache().get(issuer) {
        if fresh(&ks) && (known(&ks) || ks.fetched.elapsed() < Duration::from_secs(30)) {
            return Ok(ks.keys.clone());
        }
    }
    let keys = fetch_jwks(issuer).await?;
    jwks_cache().insert(
        issuer.to_string(),
        KeySet {
            keys: keys.clone(),
            fetched: Instant::now(),
        },
    );
    Ok(keys)
}

fn verify_sig(alg: &str, k: &Jwk, msg: &[u8], sig: &[u8]) -> bool {
    use ring::signature as sg;
    if k.alg.as_deref().is_some_and(|a| a != alg) {
        return false;
    }
    match (alg, k.kty.as_str()) {
        ("RS256" | "RS384" | "RS512" | "PS256" | "PS384" | "PS512", "RSA") => {
            let params: &sg::RsaParameters = match alg {
                "RS256" => &sg::RSA_PKCS1_2048_8192_SHA256,
                "RS384" => &sg::RSA_PKCS1_2048_8192_SHA384,
                "RS512" => &sg::RSA_PKCS1_2048_8192_SHA512,
                "PS256" => &sg::RSA_PSS_2048_8192_SHA256,
                "PS384" => &sg::RSA_PSS_2048_8192_SHA384,
                _ => &sg::RSA_PSS_2048_8192_SHA512,
            };
            sg::RsaPublicKeyComponents { n: &k.n, e: &k.e }
                .verify(params, msg, sig)
                .is_ok()
        }
        ("ES256" | "ES384", "EC") => {
            let (params, crv): (&sg::EcdsaVerificationAlgorithm, &str) = if alg == "ES256" {
                (&sg::ECDSA_P256_SHA256_FIXED, "P-256")
            } else {
                (&sg::ECDSA_P384_SHA384_FIXED, "P-384")
            };
            if k.crv.as_deref() != Some(crv) {
                return false;
            }
            let mut point = vec![4u8];
            point.extend_from_slice(&k.x);
            point.extend_from_slice(&k.y);
            sg::UnparsedPublicKey::new(params, point)
                .verify(msg, sig)
                .is_ok()
        }
        ("EdDSA" | "Ed25519", "OKP") if k.crv.as_deref() == Some("Ed25519") => {
            sg::UnparsedPublicKey::new(&sg::ED25519, &k.x)
                .verify(msg, sig)
                .is_ok()
        }
        _ => false,
    }
}

/// Claims of a verified access token.
#[derive(Debug, Clone)]
pub struct Claims {
    pub sub: String,
    pub scope: String,
    pub exp: i64,
    pub client_id: Option<String>,
}

/// Verify a JWT access token for this resource.
pub async fn verify(cfg: &OidcSettings, token: &str) -> Result<Claims, String> {
    let issuer = cfg.issuer.trim().trim_end_matches('/');
    let resource = cfg.resource.trim();
    if issuer.is_empty() || resource.is_empty() {
        return Err("Access tokens aren't configured.".into());
    }
    let mut parts = token.split('.');
    let (Some(h), Some(p), Some(sig)) = (parts.next(), parts.next(), parts.next()) else {
        return Err("Malformed token.".into());
    };
    let header: Value = serde_json::from_slice(&b64(h)?).map_err(|_| "Malformed token.")?;
    let alg = header.get("alg").and_then(|v| v.as_str()).unwrap_or("");
    if alg.is_empty() || alg == "none" || alg.starts_with("HS") {
        return Err("Unsupported token algorithm.".into());
    }
    if let Some(typ) = header.get("typ").and_then(|v| v.as_str()) {
        // RFC 9068 access tokens; plain JWT is fine, ID tokens are not.
        if !matches!(
            typ.to_ascii_lowercase().as_str(),
            "at+jwt" | "application/at+jwt" | "jwt"
        ) {
            return Err("Not an access token.".into());
        }
    }
    let kid = header.get("kid").and_then(|v| v.as_str());
    let sig = b64(sig)?;
    let signed = &token[..h.len() + 1 + p.len()];
    let keys = keys_for(issuer, kid).await?;
    let ok = keys
        .iter()
        .filter(|k| kid.is_none() || k.kid.as_deref() == kid)
        .any(|k| verify_sig(alg, k, signed.as_bytes(), &sig));
    if !ok {
        return Err("Bad token signature.".into());
    }
    let c: Value = serde_json::from_slice(&b64(p)?).map_err(|_| "Malformed token.")?;
    let s = |k: &str| c.get(k).and_then(|v| v.as_str());
    if s("iss").map(|i| i.trim_end_matches('/')) != Some(issuer) {
        return Err("Token from another issuer.".into());
    }
    let aud_ok = match c.get("aud") {
        Some(Value::String(a)) => a.trim_end_matches('/') == resource.trim_end_matches('/'),
        Some(Value::Array(a)) => a
            .iter()
            .filter_map(|x| x.as_str())
            .any(|a| a.trim_end_matches('/') == resource.trim_end_matches('/')),
        _ => false,
    };
    if !aud_ok {
        return Err("Token is for another resource.".into());
    }
    let t = now();
    let exp = c
        .get("exp")
        .and_then(|v| v.as_i64())
        .ok_or("Token has no expiry.")?;
    if exp + 30 < t {
        return Err("Token expired.".into());
    }
    if c.get("nbf")
        .and_then(|v| v.as_i64())
        .is_some_and(|n| n > t + 30)
    {
        return Err("Token not valid yet.".into());
    }
    let sub = s("sub")
        .filter(|x| !x.is_empty())
        .ok_or("Token has no subject.")?
        .to_string();
    let scope = match c.get("scope").or(c.get("scp")) {
        Some(Value::String(x)) => x.clone(),
        Some(Value::Array(a)) => a
            .iter()
            .filter_map(|x| x.as_str())
            .collect::<Vec<_>>()
            .join(" "),
        _ => String::new(),
    };
    let client_id = s("client_id").or(s("azp")).map(String::from);
    Ok(Claims {
        sub,
        scope,
        exp,
        client_id,
    })
}

/// The account and scopes for a provider access token, if valid.
pub async fn principal(state: &State, token: &str) -> Option<Principal> {
    let cfg = state.settings().auth.oidc.clone();
    if !cfg.access_tokens || !looks_like_jwt(token) {
        return None;
    }
    let key = crate::util::sha256_hex(token.as_bytes());
    let t = now();
    let cached = token_cache().get(&key).map(|c| c.clone());
    let (account_id, scopes) = match cached {
        Some((id, scopes, exp)) if exp + 30 >= t => (id, scopes),
        _ => {
            let claims = match verify(&cfg, token).await {
                Ok(c) => c,
                Err(e) => {
                    tracing::debug!("access token refused: {e}");
                    return None;
                }
            };
            let link = format!("{}|{}", cfg.issuer.trim().trim_end_matches('/'), claims.sub);
            let account = state.db.account_by_oidc(&link).await.ok()??;
            let scopes = map_scopes(&claims.scope);
            if token_cache().len() > 50_000 {
                token_cache().retain(|_, v| v.2 + 30 >= t);
            }
            token_cache().insert(key, (account.id, scopes.clone(), claims.exp));
            (account.id, scopes)
        }
    };
    // The account is re-read every time, so disabling it takes effect at once.
    let account = state.db.get_account(account_id).await.ok()??;
    account.active.then_some(Principal {
        account,
        scopes,
        external: true,
    })
}

/// RFC 9728 protected-resource metadata, when access tokens are on.
pub fn metadata(state: &State) -> Option<Value> {
    let o = state.settings().auth.oidc.clone();
    if !o.access_tokens {
        return None;
    }
    Some(serde_json::json!({
        "resource": o.resource.trim(),
        "authorization_servers": [o.issuer.trim().trim_end_matches('/')],
        "scopes_supported": SCOPES,
        "bearer_methods_supported": ["header"],
        "resource_name": state.settings().branding.name.clone().unwrap_or_else(|| "Picacho Server".into()),
    }))
}

/// `WWW-Authenticate` for a 401 on a bearer-capable endpoint.
pub fn challenge(state: &State, base: &str, error: Option<&str>) -> String {
    let mut v = String::from("Bearer");
    if state.settings().auth.oidc.access_tokens {
        v.push_str(&format!(
            " resource_metadata=\"{base}/.well-known/oauth-protected-resource\""
        ));
    }
    if let Some(e) = error {
        v.push_str(&format!(
            "{}error=\"{e}\"",
            if v.len() > 6 { ", " } else { " " }
        ));
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scopes() {
        let m = map_scopes("openid mail.read");
        assert!(m.contains("imap:read") && m.contains("jmap:read") && !m.contains("smtp"));
        let m = map_scopes("mail.read mail.labels mail.compose mail.send");
        let has = |s: &str| m.split(' ').any(|x| x == s);
        assert!(has("imap") && has("jmap") && has("smtp") && has(EXTERNAL) && has("mail.send"));
        assert!(!has("sieve") && !has("account"));
        let m = map_scopes("calendar.read contacts.write mail.settings");
        let has = |s: &str| m.split(' ').any(|x| x == s);
        assert!(has("caldav:read") && has("carddav") && has("sieve") && has("account"));
        assert!(!looks_like_jwt("pmk_abc"));
        assert!(looks_like_jwt("eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln"));
    }
}
