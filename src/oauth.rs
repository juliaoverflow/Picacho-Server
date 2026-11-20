//! OAuth 2.0 authorization server for mail clients (RFC 6749, PKCE RFC 7636,
//! metadata RFC 8414, revocation RFC 7009, dynamic registration RFC 7591).
//!
//! Scopes: `imap` / `imap:read`, `smtp`, `jmap` / `jmap:read`. The consent
//! screen lets the person lower each to "read" or "none". Access tokens
//! (`pmo_…`) work as JMAP Bearer tokens and with IMAP/SMTP XOAUTH2 and
//! OAUTHBEARER; refresh tokens (`pmr_…`) rotate on every use.
use crate::auth::{Access, OAUTH_ACCESS_PREFIX, OAUTH_CODE_PREFIX, OAUTH_REFRESH_PREFIX};
use crate::db::{OAuthClient, OAuthToken};
use crate::state::State;
use crate::util::{now, random_token, sha256_hex};
use axum::extract::State as AxState;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use base64::Engine;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use subtle::ConstantTimeEq;

pub const SCOPES: [&str; 10] = ["imap", "imap:read", "smtp", "jmap", "jmap:read", "dav", "dav:read", "sieve", "account", "account:read"];

/// Services a grant covers; `smtp` and `sieve` have no read-only level.
pub const SERVICES: [&str; 6] = ["imap", "smtp", "jmap", "dav", "sieve", "account"];

fn write_only(svc: &str) -> bool {
    svc == "smtp" || svc == "sieve"
}

pub fn routes(state: State) -> Router {
    Router::new()
        .route("/.well-known/oauth-authorization-server", get(metadata))
        .route("/oauth/token", post(token))
        .route("/oauth/revoke", post(revoke))
        .route("/oauth/register", post(register))
        .with_state(state)
}

fn err(status: StatusCode, code: &str, desc: &str) -> Response {
    (status, [(header::CACHE_CONTROL, "no-store")], Json(json!({"error": code, "error_description": desc}))).into_response()
}

async fn metadata(AxState(state): AxState<State>, headers: HeaderMap) -> Response {
    if !state.settings().oauth.enabled {
        return err(StatusCode::NOT_FOUND, "not_found", "OAuth is turned off.");
    }
    let base = crate::jmap::base_url(&state, &headers);
    let mut m = json!({
        "issuer": base,
        "authorization_endpoint": format!("{base}/oauth/authorize"),
        "token_endpoint": format!("{base}/oauth/token"),
        "revocation_endpoint": format!("{base}/oauth/revoke"),
        "scopes_supported": SCOPES,
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
        "revocation_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
    });
    if state.settings().oauth.dynamic_registration {
        m["registration_endpoint"] = json!(format!("{base}/oauth/register"));
    }
    Json(m).into_response()
}

/// Highest level requested for each service.
pub fn requested_levels(scope: &str) -> HashMap<&'static str, Access> {
    let mut m = HashMap::new();
    for svc in SERVICES {
        let lvl = if scope.split(' ').any(|s| s == svc) {
            Access::Write
        } else if scope.split(' ').any(|s| s == format!("{svc}:read")) && !write_only(svc) {
            Access::Read
        } else {
            Access::None
        };
        m.insert(svc, lvl);
    }
    m
}

/// Scope string for granted levels.
pub fn scope_string(levels: &HashMap<&str, Access>) -> String {
    let mut out = vec![];
    for svc in SERVICES {
        match levels.get(svc).copied().unwrap_or(Access::None) {
            Access::Write => out.push(svc.to_string()),
            Access::Read if !write_only(svc) => out.push(format!("{svc}:read")),
            _ => {}
        }
    }
    out.join(" ")
}

fn is_loopback_http(u: &url::Url) -> bool {
    u.scheme() == "http" && matches!(u.host_str(), Some("127.0.0.1") | Some("[::1]") | Some("localhost"))
}

/// Allowed redirect URIs: https, loopback http (any port, RFC 8252) or a
/// private-use scheme for native apps. Never javascript:/data:/file:.
pub fn valid_redirect(uri: &str) -> bool {
    let Ok(u) = url::Url::parse(uri) else { return false };
    if u.fragment().is_some() {
        return false;
    }
    match u.scheme() {
        "https" => true,
        "http" => is_loopback_http(&u),
        "javascript" | "data" | "file" | "about" | "blob" | "vbscript" | "ftp" | "ws" | "wss" => false,
        s => s.contains('.'),
    }
}

/// Does `given` match a registered redirect URI (loopback ports may vary)?
pub fn redirect_matches(registered: &[String], given: &str) -> bool {
    if registered.iter().any(|r| r == given) {
        return true;
    }
    let Ok(g) = url::Url::parse(given) else { return false };
    is_loopback_http(&g)
        && registered.iter().any(|r| {
            url::Url::parse(r).is_ok_and(|r| is_loopback_http(&r) && r.host_str() == g.host_str() && r.path() == g.path())
        })
}

/// A validated authorization request.
pub struct AuthRequest {
    pub client: OAuthClient,
    pub redirect_uri: String,
    pub state: Option<String>,
    pub challenge: String,
    pub requested: HashMap<&'static str, Access>,
}

/// Errors that must be shown to the person (never redirected), or sent back
/// to the client's redirect URI.
pub enum RequestError {
    Fatal(String),
    Redirect(String),
}

pub fn error_redirect(redirect_uri: &str, code: &str, desc: &str, st: Option<&str>) -> String {
    let mut u = url::Url::parse(redirect_uri).expect("validated");
    {
        let mut q = u.query_pairs_mut();
        q.append_pair("error", code).append_pair("error_description", desc);
        if let Some(s) = st {
            q.append_pair("state", s);
        }
    }
    u.into()
}

pub async fn validate_request(state: &State, q: &HashMap<String, String>) -> Result<AuthRequest, RequestError> {
    if !state.settings().oauth.enabled {
        return Err(RequestError::Fatal("OAuth sign-in is turned off on this server.".into()));
    }
    let g = |k: &str| q.get(k).map(String::as_str).filter(|v| !v.is_empty());
    let client_id = g("client_id").ok_or(RequestError::Fatal("The app didn't identify itself (client_id).".into()))?;
    let (client, secret) = state
        .db
        .oauth_client(client_id)
        .await
        .map_err(|_| RequestError::Fatal("Internal error.".into()))?
        .ok_or(RequestError::Fatal("This app isn't registered with this server.".into()))?;
    let redirect_uri = match g("redirect_uri") {
        Some(r) if redirect_matches(&client.redirect_uris, r) => r.to_string(),
        Some(_) => return Err(RequestError::Fatal("The app's redirect address isn't registered.".into())),
        None if client.redirect_uris.len() == 1 => client.redirect_uris[0].clone(),
        None => return Err(RequestError::Fatal("The app didn't say where to return (redirect_uri).".into())),
    };
    let st = g("state").map(String::from);
    let back = |code: &str, desc: &str| RequestError::Redirect(error_redirect(&redirect_uri, code, desc, st.as_deref()));
    if g("response_type") != Some("code") {
        return Err(back("unsupported_response_type", "Only the authorization code flow is supported."));
    }
    let challenge = g("code_challenge").unwrap_or("").to_string();
    if !challenge.is_empty() && g("code_challenge_method").unwrap_or("plain") != "S256" {
        return Err(back("invalid_request", "PKCE must use S256."));
    }
    if challenge.is_empty() && secret.is_none() {
        return Err(back("invalid_request", "Public clients must use PKCE."));
    }
    let scope = g("scope").unwrap_or("");
    let mut requested = requested_levels(scope);
    let allowed = requested_levels(&client.scopes);
    for (svc, lvl) in requested.iter_mut() {
        if *lvl > allowed[svc] {
            *lvl = allowed[svc];
        }
    }
    if requested.values().all(|l| *l == Access::None) {
        return Err(back("invalid_scope", "Request at least one of: imap, imap:read, smtp, jmap, jmap:read, dav, dav:read, sieve, account, account:read."));
    }
    Ok(AuthRequest { client, redirect_uri, state: st, challenge, requested })
}

/// Issue an authorization code; returns the redirect URL for the client.
pub async fn issue_code(state: &State, req: &AuthRequest, account_id: i64, scopes: &str) -> anyhow::Result<String> {
    let code = format!("{OAUTH_CODE_PREFIX}{}", random_token());
    let t = OAuthToken {
        kind: "code".into(),
        client_id: req.client.client_id.clone(),
        account_id,
        scopes: scopes.to_string(),
        redirect_uri: req.redirect_uri.clone(),
        challenge: req.challenge.clone(),
        family: random_token(),
        expires_at: now() + 120,
        created_at: now(),
        last_used: None,
    };
    state.db.insert_oauth_token(&t, &sha256_hex(code.as_bytes())).await?;
    let mut u = url::Url::parse(&req.redirect_uri)?;
    {
        let mut q = u.query_pairs_mut();
        q.append_pair("code", &code);
        if let Some(s) = &req.state {
            q.append_pair("state", s);
        }
    }
    Ok(u.into())
}

pub async fn issue_tokens(state: &State, client_id: &str, account_id: i64, scopes: &str, family: &str) -> anyhow::Result<Value> {
    let o = state.settings().oauth.clone();
    let access = format!("{OAUTH_ACCESS_PREFIX}{}", random_token());
    let refresh = format!("{OAUTH_REFRESH_PREFIX}{}", random_token());
    let base = OAuthToken {
        kind: "access".into(),
        client_id: client_id.into(),
        account_id,
        scopes: scopes.into(),
        redirect_uri: String::new(),
        challenge: String::new(),
        family: family.into(),
        expires_at: now() + o.access_token_minutes as i64 * 60,
        created_at: now(),
        last_used: None,
    };
    state.db.insert_oauth_token(&base, &sha256_hex(access.as_bytes())).await?;
    let r = OAuthToken { kind: "refresh".into(), expires_at: now() + o.refresh_token_days as i64 * 86400, ..base };
    state.db.insert_oauth_token(&r, &sha256_hex(refresh.as_bytes())).await?;
    Ok(json!({
        "access_token": access,
        "token_type": "Bearer",
        "expires_in": o.access_token_minutes * 60,
        "refresh_token": refresh,
        "scope": scopes,
    }))
}

/// Client authentication: Basic header or form fields. Returns the client.
async fn client_auth(state: &State, headers: &HeaderMap, form: &HashMap<String, String>) -> Result<OAuthClient, Response> {
    let mut id = form.get("client_id").cloned();
    let mut secret = form.get("client_secret").cloned();
    if let Some(b) = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("Basic ")) {
        if let Ok(dec) = base64::engine::general_purpose::STANDARD.decode(b.trim()) {
            if let Some((i, s)) = String::from_utf8_lossy(&dec).split_once(':') {
                let dec = |x: &str| url::form_urlencoded::parse(format!("x={x}").as_bytes()).next().map(|p| p.1.into_owned()).unwrap_or_default();
                id = Some(dec(i));
                secret = Some(dec(s));
            }
        }
    }
    let bad = || err(StatusCode::UNAUTHORIZED, "invalid_client", "Client authentication failed.");
    let id = id.ok_or_else(bad)?;
    let (client, hash) = state.db.oauth_client(&id).await.map_err(|_| bad())?.ok_or_else(bad)?;
    if let Some(h) = hash {
        let given = sha256_hex(secret.unwrap_or_default().as_bytes());
        if !bool::from(given.as_bytes().ct_eq(h.as_bytes())) {
            return Err(bad());
        }
    }
    Ok(client)
}

async fn token(AxState(state): AxState<State>, headers: HeaderMap, Form(form): Form<HashMap<String, String>>) -> Response {
    if !state.settings().oauth.enabled {
        return err(StatusCode::BAD_REQUEST, "invalid_request", "OAuth is turned off.");
    }
    let client = match client_auth(&state, &headers, &form).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let g = |k: &str| form.get(k).map(String::as_str).unwrap_or("");
    let grant = |desc: &str| err(StatusCode::BAD_REQUEST, "invalid_grant", desc);
    let result = match g("grant_type") {
        "authorization_code" => {
            let Ok(Some(t)) = state.db.take_oauth_token(&sha256_hex(g("code").as_bytes()), "code", true).await else {
                return grant("The authorization code is invalid, expired or already used.");
            };
            if t.client_id != client.client_id {
                return grant("The code was issued to another client.");
            }
            if !g("redirect_uri").is_empty() && g("redirect_uri") != t.redirect_uri {
                return grant("redirect_uri doesn't match.");
            }
            if !t.challenge.is_empty() {
                let computed = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(g("code_verifier").as_bytes()));
                if !bool::from(computed.as_bytes().ct_eq(t.challenge.as_bytes())) {
                    return grant("PKCE verification failed.");
                }
            }
            issue_tokens(&state, &client.client_id, t.account_id, &t.scopes, &t.family).await
        }
        "refresh_token" => {
            let Ok(Some(t)) = state.db.take_oauth_token(&sha256_hex(g("refresh_token").as_bytes()), "refresh", true).await else {
                return grant("The refresh token is invalid, expired or already used.");
            };
            if t.client_id != client.client_id {
                // A stolen token being replayed by another client: revoke the grant.
                let _ = state.db.revoke_oauth_family(&t.family, None).await;
                return grant("The refresh token was issued to another client.");
            }
            match state.db.get_account(t.account_id).await {
                Ok(Some(a)) if a.active => {}
                _ => return grant("The account is disabled."),
            }
            let mut scopes = t.scopes.clone();
            if !g("scope").is_empty() {
                let want = requested_levels(g("scope"));
                let had = requested_levels(&t.scopes);
                let narrowed: HashMap<&str, Access> = want.iter().map(|(k, v)| (*k, (*v).min(had[k]))).collect();
                scopes = scope_string(&narrowed);
            }
            issue_tokens(&state, &client.client_id, t.account_id, &scopes, &t.family).await
        }
        _ => return err(StatusCode::BAD_REQUEST, "unsupported_grant_type", "Use authorization_code or refresh_token."),
    };
    match result {
        Ok(v) => (StatusCode::OK, [(header::CACHE_CONTROL, "no-store"), (header::PRAGMA, "no-cache")], Json(v)).into_response(),
        Err(e) => {
            tracing::error!("oauth token: {e:#}");
            err(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "Internal error.")
        }
    }
}

async fn revoke(AxState(state): AxState<State>, headers: HeaderMap, Form(form): Form<HashMap<String, String>>) -> Response {
    let client = match client_auth(&state, &headers, &form).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let tok = form.get("token").map(String::as_str).unwrap_or("");
    let hash = sha256_hex(tok.as_bytes());
    for kind in ["refresh", "access"] {
        if let Ok(Some(t)) = state.db.take_oauth_token(&hash, kind, false).await {
            if t.client_id == client.client_id {
                let _ = state.db.revoke_oauth_family(&t.family, None).await;
            }
        }
    }
    StatusCode::OK.into_response()
}

#[derive(Deserialize)]
struct Registration {
    #[serde(default)]
    client_name: Option<String>,
    redirect_uris: Vec<String>,
    #[serde(default)]
    token_endpoint_auth_method: Option<String>,
    #[serde(default)]
    scope: Option<String>,
}

async fn register(AxState(state): AxState<State>, Json(r): Json<Registration>) -> Response {
    let o = state.settings().oauth.clone();
    if !o.enabled || !o.dynamic_registration {
        return err(StatusCode::FORBIDDEN, "access_denied", "Dynamic client registration is turned off.");
    }
    if r.redirect_uris.is_empty() || r.redirect_uris.len() > 10 || !r.redirect_uris.iter().all(|u| valid_redirect(u)) {
        return err(StatusCode::BAD_REQUEST, "invalid_redirect_uri", "Redirect URIs must be https, loopback http or an app scheme.");
    }
    let confidential = r.token_endpoint_auth_method.as_deref().is_some_and(|m| m != "none");
    match create_client(&state, r.client_name.as_deref().unwrap_or("Unnamed app"), r.redirect_uris.clone(), r.scope.as_deref().unwrap_or("imap smtp jmap"), confidential, true).await {
        Ok((client, secret)) => {
            state.event("info", "auth", &format!("OAuth client '{}' registered itself", client.name));
            let mut v = json!({
                "client_id": client.client_id, "client_name": client.name, "redirect_uris": client.redirect_uris,
                "scope": client.scopes, "token_endpoint_auth_method": if confidential { "client_secret_basic" } else { "none" },
                "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"], "client_id_issued_at": now(),
            });
            if let Some(s) = secret {
                v["client_secret"] = json!(s);
                v["client_secret_expires_at"] = json!(0);
            }
            (StatusCode::CREATED, Json(v)).into_response()
        }
        Err(e) => err(StatusCode::BAD_REQUEST, "invalid_client_metadata", &e),
    }
}

/// Register a client; returns it and its secret (confidential clients).
pub async fn create_client(
    state: &State,
    name: &str,
    redirect_uris: Vec<String>,
    scope: &str,
    confidential: bool,
    dynamic: bool,
) -> Result<(OAuthClient, Option<String>), String> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 80 {
        return Err("Give the app a name (up to 80 characters).".into());
    }
    if redirect_uris.is_empty() || !redirect_uris.iter().all(|u| valid_redirect(u)) {
        return Err("Redirect URIs must be https, loopback http (http://127.0.0.1/…) or an app scheme like com.example.app:/callback.".into());
    }
    let scopes = scope_string(&requested_levels(scope));
    if scopes.is_empty() {
        return Err("Allow at least one of imap, smtp or jmap.".into());
    }
    let client = OAuthClient {
        client_id: format!("pmc-{}", &random_token()[..22]),
        name: name.into(),
        redirect_uris,
        scopes,
        dynamic,
        confidential,
        created_at: now(),
    };
    let secret = confidential.then(|| format!("pms_{}", random_token()));
    state
        .db
        .create_oauth_client(&client, secret.as_ref().map(|s| sha256_hex(s.as_bytes())).as_deref())
        .await
        .map_err(|e| e.to_string())?;
    Ok((client, secret))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn redirects() {
        assert!(valid_redirect("https://app.example/cb"));
        assert!(valid_redirect("http://127.0.0.1:8123/cb"));
        assert!(valid_redirect("com.example.mail:/oauth"));
        assert!(!valid_redirect("http://evil.example/cb"));
        assert!(!valid_redirect("javascript:alert(1)"));
        assert!(redirect_matches(&["http://127.0.0.1/cb".into()], "http://127.0.0.1:5555/cb"));
        assert!(!redirect_matches(&["http://127.0.0.1/cb".into()], "http://127.0.0.1:5555/other"));
    }
    #[test]
    fn scopes() {
        let l = requested_levels("imap:read smtp jmap");
        assert_eq!(l["imap"], Access::Read);
        assert_eq!(scope_string(&l), "imap:read smtp jmap");
    }
}

/// The client used for authorizations an administrator issues directly
/// (provider integrations). Public, so refresh works with just its id.
pub async fn admin_client(state: &State) -> anyhow::Result<String> {
    if let Some(id) = state.db.get_setting("admin_oauth_client").await? {
        if state.db.oauth_client(&id).await?.is_some() {
            return Ok(id);
        }
    }
    let (client, _) = create_client(state, "Issued by an administrator", vec!["http://127.0.0.1/".into()], &SCOPES.join(" "), false, false)
        .await
        .map_err(|e| anyhow::anyhow!(e))?;
    state.db.set_setting("admin_oauth_client", &client.client_id).await?;
    Ok(client.client_id)
}

/// Issue access + refresh tokens for an account without a consent screen
/// (admin API). Scopes are limited to what the client may request.
pub async fn admin_authorize(state: &State, account_id: i64, client_id: Option<&str>, scope: &str) -> Result<Value, String> {
    let cid = match client_id {
        Some(c) => c.to_string(),
        None => admin_client(state).await.map_err(|e| e.to_string())?,
    };
    let (client, _) = state.db.oauth_client(&cid).await.map_err(|e| e.to_string())?.ok_or("No such OAuth client.")?;
    let mut want = requested_levels(scope);
    let allowed = requested_levels(&client.scopes);
    for (svc, lvl) in want.iter_mut() {
        if *lvl > allowed[svc] {
            *lvl = allowed[svc];
        }
    }
    let scopes = scope_string(&want);
    if scopes.is_empty() {
        return Err(format!("Request at least one of: {}.", SCOPES.join(", ")));
    }
    let mut v = issue_tokens(state, &cid, account_id, &scopes, &random_token()).await.map_err(|e| e.to_string())?;
    v["client_id"] = json!(cid);
    Ok(v)
}
