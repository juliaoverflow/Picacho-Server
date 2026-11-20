//! OpenID Connect sign-in to the web console (relying party).
//!
//! Authorization-code flow with PKCE (S256), `state` and `nonce`. The ID
//! token comes straight from the token endpoint over verified TLS, which
//! OIDC Core 3.1.3.7 accepts in place of a signature check; its issuer,
//! audience, expiry and nonce are still verified. Identities are linked to
//! accounts by `issuer|sub`, so a later email change at the provider doesn't
//! move the person to another mailbox.
use crate::db::Account;
use crate::settings::OidcSettings;
use crate::state::State;
use crate::util::{now, random_token};
use base64::Engine;
use dashmap::DashMap;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct Discovery {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: Option<String>,
    pub end_session_endpoint: Option<String>,
    pub jwks_uri: Option<String>,
    pub basic_auth: bool,
}

/// A sign-in in progress (between redirect and callback).
pub struct Pending {
    pub nonce: String,
    pub verifier: String,
    pub redirect_uri: String,
    pub next: String,
    pub created: Instant,
    /// Setup data when this sign-in completes first-run setup.
    pub setup: Option<Value>,
    /// The OIDC settings used (setup supplies them before they're saved).
    pub cfg: OidcSettings,
}

#[derive(Debug, Clone)]
pub struct Identity {
    /// "issuer|sub"
    pub key: String,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub name: Option<String>,
    pub groups: Vec<String>,
}

fn pending() -> &'static DashMap<String, Pending> {
    static P: OnceLock<DashMap<String, Pending>> = OnceLock::new();
    P.get_or_init(DashMap::new)
}

fn cache() -> &'static DashMap<String, (Discovery, Instant)> {
    static C: OnceLock<DashMap<String, (Discovery, Instant)>> = OnceLock::new();
    C.get_or_init(DashMap::new)
}

pub(crate) fn http() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("Picacho-Mail")
        .build()
        .expect("http client")
}

fn allowed_url(u: &str) -> bool {
    u.starts_with("https://") || crate::settings::is_local_http(u)
}

pub async fn discover(issuer: &str) -> Result<Discovery, String> {
    let issuer = issuer.trim().trim_end_matches('/').to_string();
    if !allowed_url(&issuer) {
        return Err("The issuer must be an https:// URL.".into());
    }
    if let Some(c) = cache().get(&issuer) {
        if c.1.elapsed() < Duration::from_secs(3600) {
            return Ok(c.0.clone());
        }
    }
    let url = format!("{issuer}/.well-known/openid-configuration");
    let r = http().get(&url).send().await.map_err(|e| format!("Couldn't reach {url}: {e}"))?;
    if !r.status().is_success() {
        return Err(format!("{url} answered HTTP {}", r.status()));
    }
    let d: Value = r.json().await.map_err(|e| format!("Invalid discovery document: {e}"))?;
    let s = |k: &str| d.get(k).and_then(|v| v.as_str()).map(String::from);
    let found_issuer = s("issuer").ok_or("Discovery document has no issuer")?;
    if found_issuer.trim_end_matches('/') != issuer {
        return Err(format!("Issuer mismatch: the provider says {found_issuer}"));
    }
    let auth = s("authorization_endpoint").ok_or("No authorization_endpoint")?;
    let token = s("token_endpoint").ok_or("No token_endpoint")?;
    if !allowed_url(&auth) || !allowed_url(&token) {
        return Err("Provider endpoints must use https.".into());
    }
    let methods: Vec<String> = d
        .get("token_endpoint_auth_methods_supported")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_else(|| vec!["client_secret_basic".into()]);
    let disc = Discovery {
        issuer: found_issuer,
        authorization_endpoint: auth,
        token_endpoint: token,
        userinfo_endpoint: s("userinfo_endpoint").filter(|u| allowed_url(u)),
        end_session_endpoint: s("end_session_endpoint"),
        jwks_uri: s("jwks_uri").filter(|u| allowed_url(u)),
        basic_auth: methods.iter().any(|m| m == "client_secret_basic"),
    };
    cache().insert(issuer, (disc.clone(), Instant::now()));
    Ok(disc)
}

/// Only same-site relative paths are followed after sign-in.
pub fn safe_next(next: &str) -> String {
    if next.starts_with('/') && !next.starts_with("//") && !next.contains('\\') && next.len() < 2048 {
        next.to_string()
    } else {
        "/".into()
    }
}

/// Start a sign-in; returns the provider URL to redirect to.
pub async fn begin(cfg: &OidcSettings, redirect_uri: &str, next: &str, setup: Option<Value>) -> Result<String, String> {
    let d = discover(&cfg.issuer).await?;
    let p = pending();
    p.retain(|_, v| v.created.elapsed() < Duration::from_secs(600));
    if p.len() > 10_000 {
        return Err("Too many sign-ins in progress; try again shortly.".into());
    }
    let state = random_token();
    let nonce = random_token();
    let verifier = random_token();
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let mut url = url::Url::parse(&d.authorization_endpoint).map_err(|e| e.to_string())?;
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &cfg.client_id)
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("scope", if cfg.scopes.contains("openid") { &cfg.scopes } else { "openid email profile" })
        .append_pair("state", &state)
        .append_pair("nonce", &nonce)
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256");
    p.insert(
        state,
        Pending {
            nonce,
            verifier,
            redirect_uri: redirect_uri.to_string(),
            next: safe_next(next),
            created: Instant::now(),
            setup,
            cfg: cfg.clone(),
        },
    );
    Ok(url.into())
}

fn claim_str(c: &Value, key: &str) -> Option<String> {
    c.get(key).and_then(|v| v.as_str()).map(String::from)
}

fn claim_groups(c: &Value, key: &str) -> Vec<String> {
    match c.get(key) {
        Some(Value::Array(a)) => a.iter().filter_map(|x| x.as_str().map(String::from)).collect(),
        Some(Value::String(s)) => s.split([',', ' ']).filter(|x| !x.is_empty()).map(String::from).collect(),
        _ => vec![],
    }
}

/// Complete a sign-in from the callback's `code` and `state`.
pub async fn finish(code: &str, state_param: &str) -> Result<(Identity, Pending), String> {
    let (_, p) = pending().remove(state_param).ok_or("This sign-in link expired or was already used. Try again.")?;
    if p.created.elapsed() > Duration::from_secs(600) {
        return Err("The sign-in took too long. Try again.".into());
    }
    let cfg = &p.cfg;
    let d = discover(&cfg.issuer).await?;
    let mut form = vec![
        ("grant_type", "authorization_code".to_string()),
        ("code", code.to_string()),
        ("redirect_uri", p.redirect_uri.clone()),
        ("code_verifier", p.verifier.clone()),
        ("client_id", cfg.client_id.clone()),
    ];
    let mut req = http().post(&d.token_endpoint).header("Accept", "application/json");
    match cfg.client_secret.as_deref().filter(|s| !s.is_empty()) {
        Some(secret) if d.basic_auth => req = req.basic_auth(&cfg.client_id, Some(secret)),
        Some(secret) => form.push(("client_secret", secret.to_string())),
        None => {}
    }
    let r = req.form(&form).send().await.map_err(|e| format!("Token request failed: {e}"))?;
    let status = r.status();
    let body: Value = r.json().await.map_err(|e| format!("Invalid token response: {e}"))?;
    if !status.is_success() {
        let err = body.get("error_description").or(body.get("error")).and_then(|v| v.as_str()).unwrap_or("unknown error");
        return Err(format!("The provider refused the sign-in: {err}"));
    }
    let id_token = body.get("id_token").and_then(|v| v.as_str()).ok_or("The provider returned no ID token.")?;
    let payload = id_token.split('.').nth(1).ok_or("Malformed ID token.")?;
    let claims: Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload.trim_end_matches('=')).map_err(|_| "Malformed ID token.")?,
    )
    .map_err(|_| "Malformed ID token.")?;
    if claim_str(&claims, "iss").as_deref().map(|i| i.trim_end_matches('/')) != Some(d.issuer.trim_end_matches('/')) {
        return Err("ID token issuer doesn't match.".into());
    }
    let aud_ok = match claims.get("aud") {
        Some(Value::String(a)) => a == &cfg.client_id,
        Some(Value::Array(a)) => {
            a.iter().any(|x| x.as_str() == Some(&cfg.client_id))
                && (a.len() == 1 || claim_str(&claims, "azp").as_deref() == Some(&cfg.client_id))
        }
        _ => false,
    };
    if !aud_ok {
        return Err("ID token was issued to another client.".into());
    }
    let exp = claims.get("exp").and_then(|v| v.as_i64()).unwrap_or(0);
    if exp + 60 < now() {
        return Err("ID token expired.".into());
    }
    if claim_str(&claims, "nonce").as_deref() != Some(p.nonce.as_str()) {
        return Err("ID token nonce doesn't match.".into());
    }
    let sub = claim_str(&claims, "sub").ok_or("ID token has no subject.")?;
    let mut all = claims.clone();
    // Fill missing claims from userinfo.
    if claim_str(&all, &cfg.email_claim).is_none() || (!cfg.groups_claim.is_empty() && all.get(&cfg.groups_claim).is_none()) {
        if let (Some(ui), Some(at)) = (&d.userinfo_endpoint, body.get("access_token").and_then(|v| v.as_str())) {
            if let Ok(r) = http().get(ui).bearer_auth(at).send().await {
                if let Ok(info) = r.json::<Value>().await {
                    if claim_str(&info, "sub").as_deref() == Some(sub.as_str()) {
                        if let (Some(o), Some(i)) = (all.as_object_mut(), info.as_object()) {
                            for (k, v) in i {
                                o.entry(k.clone()).or_insert(v.clone());
                            }
                        }
                    }
                }
            }
        }
    }
    let id = Identity {
        key: format!("{}|{sub}", d.issuer.trim_end_matches('/')),
        email: claim_str(&all, &cfg.email_claim).map(|e| e.trim().to_ascii_lowercase()),
        email_verified: all.get("email_verified").and_then(|v| v.as_bool().or_else(|| v.as_str().map(|s| s == "true"))),
        name: claim_str(&all, "name").or_else(|| claim_str(&all, "preferred_username")),
        groups: claim_groups(&all, &cfg.groups_claim),
    };
    Ok((id, p))
}

/// Find (or create) the account for an identity and sync its role.
pub async fn resolve_account(state: &State, cfg: &OidcSettings, id: &Identity) -> Result<Account, String> {
    let db = &state.db;
    let internal = |e: anyhow::Error| {
        tracing::error!("oidc: {e:#}");
        "Internal error.".to_string()
    };
    if cfg.require_verified_email && id.email_verified == Some(false) {
        return Err("Your email address isn't verified with the identity provider.".into());
    }
    if let Some(email) = &id.email {
        let dom = crate::util::domain_of(email);
        if !cfg.allowed_domains.is_empty() && !cfg.allowed_domains.iter().any(|d| d.eq_ignore_ascii_case(dom)) {
            return Err(format!("Accounts from {dom} can't sign in here."));
        }
    }
    let mut account = db.account_by_oidc(&id.key).await.map_err(internal)?;
    if account.is_none() {
        if let Some(email) = &id.email {
            if let Some(a) = db.account_by_email(email).await.map_err(internal)? {
                if !a.oidc_sub.is_empty() && a.oidc_sub != id.key {
                    return Err("This mailbox is linked to a different single sign-on identity.".into());
                }
                db.set_oidc_sub(a.id, &id.key).await.map_err(internal)?;
                account = Some(a);
            } else if cfg.auto_create_accounts {
                let domain = db.domain_by_name(crate::util::domain_of(email)).await.map_err(internal)?;
                match domain {
                    Some(d) if d.mode == "local" && d.active => {
                        let quota = state.settings().limits.default_quota_mb as i64 * 1024 * 1024;
                        let want_admin = !cfg.admin_groups.is_empty() && id.groups.iter().any(|g| cfg.admin_groups.contains(g));
                        let role = if want_admin { "admin" } else { "user" };
                        let new_id = db
                            .create_account(email, d.id, "!", id.name.as_deref().unwrap_or(""), role, quota)
                            .await
                            .map_err(internal)?;
                        db.set_oidc_sub(new_id, &id.key).await.map_err(internal)?;
                        state.event("info", "auth", &format!("created {email} on first single sign-on"));
                        account = db.get_account(new_id).await.map_err(internal)?;
                    }
                    _ => return Err(format!("{email} isn't on a mail domain hosted here.")),
                }
            }
        }
    }
    let Some(mut a) = account else {
        return Err(match &id.email {
            Some(e) => format!("There's no account for {e}. Ask an administrator to create one."),
            None => "The identity provider didn't share an email address.".into(),
        });
    };
    if !a.active {
        return Err("This account is disabled.".into());
    }
    if !cfg.admin_groups.is_empty() {
        let want_admin = id.groups.iter().any(|g| cfg.admin_groups.contains(g));
        let want = if want_admin { "admin" } else { "user" };
        let last_admin = a.is_admin() && db.count_admins().await.map_err(internal)? <= 1;
        if a.role != want && !(last_admin && want == "user") {
            db.set_role(a.id, want).await.map_err(internal)?;
            a.role = want.into();
        }
    }
    Ok(a)
}
