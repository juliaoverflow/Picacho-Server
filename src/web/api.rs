use crate::auth::{check_password_strength, hash_password};
use crate::db::{Account, Domain};
use crate::settings::{LiveSettings, Transport};
use crate::state::State;
use crate::util::{normalize_address, now, sha256_hex, valid_domain};
use axum::extract::{ConnectInfo, Path, Query, State as AxState};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use std::net::{IpAddr, SocketAddr};

pub struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        tracing::error!("api error: {e:#}");
        ApiError(StatusCode::INTERNAL_SERVER_ERROR, "Internal error. See the server log.".into())
    }
}

type R<T = Value> = Result<Json<T>, ApiError>;

fn bad(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, msg.into())
}
fn not_found() -> ApiError {
    ApiError(StatusCode::NOT_FOUND, "Not found.".into())
}
fn unauthorized() -> ApiError {
    ApiError(StatusCode::UNAUTHORIZED, "Please sign in.".into())
}
fn forbidden() -> ApiError {
    ApiError(StatusCode::FORBIDDEN, "Administrator access required.".into())
}

pub fn routes(state: State) -> Router {
    let admin_api = Router::new()
        .route("/overview", get(overview))
        .route("/domains", get(list_domains).post(create_domain))
        .route("/domains/{id}", get(get_domain).patch(update_domain).delete(delete_domain))
        .route("/domains/{id}/dkim", post(rotate_dkim))
        .route("/domains/{id}/dns", get(domain_dns))
        .route("/accounts", get(list_accounts).post(create_account))
        .route("/accounts/{id}", get(get_account).patch(update_account).delete(delete_account))
        .route("/accounts/{id}/password", post(set_account_password))
        .route("/aliases", get(list_aliases).post(create_alias))
        .route("/aliases/{id}", axum::routing::patch(update_alias).delete(delete_alias))
        .route("/queue", get(list_queue))
        .route("/queue/{id}/retry", post(retry_queue))
        .route("/queue/{id}", delete(delete_queue))
        .route("/settings", get(get_settings).put(put_settings))
        .route("/events", get(events));
    Router::new()
        // Versioned REST API for automation (Bearer token with the admin scope).
        .nest("/api/v1", admin_api.clone().route("/openapi.json", get(openapi)))
        .route("/api/tokens", get(list_tokens).post(create_token))
        .route("/api/tokens/{id}", delete(delete_token))
        .route("/api/admin/config", get(get_config).put(put_config))
        .route("/api/admin/config/raw", axum::routing::put(put_config_raw))
        .route("/api/admin/restart", post(restart))
        .route("/api/status", get(status))
        .route("/api/branding", get(branding))
        .route("/api/setup/oidc/begin", post(setup_oidc_begin))
        .route("/api/setup/storage", post(setup_storage))
        .route("/api/setup/storage/test", post(setup_storage_test))
        .route("/api/oidc/test", post(oidc_test))
        .route("/api/auth/oidc/start", get(oidc_start))
        .route("/api/auth/oidc/callback", get(oidc_callback))
        .route("/api/oauth/request", get(oauth_request))
        .route("/api/oauth/approve", post(oauth_approve))
        .route("/api/oauth/grants", get(oauth_grants))
        .route("/api/oauth/grants/{family}", delete(oauth_revoke_grant))
        .route("/api/admin/oauth/clients", get(oauth_clients).post(create_oauth_client))
        .route("/api/admin/oauth/clients/{id}", delete(delete_oauth_client))
        .route("/api/setup/verify", post(setup_verify))
        .route("/api/setup/complete", post(setup_complete))
        .route("/api/auth/login", post(login))
        .route("/api/auth/logout", post(logout))
        .route("/api/auth/me", get(me))
        .route("/api/me/password", post(change_own_password))
        .route("/api/me/client", get(client_settings))
        .route("/api/admin/overview", get(overview))
        .route("/api/admin/domains", get(list_domains).post(create_domain))
        .route("/api/admin/domains/{id}", get(get_domain).patch(update_domain).delete(delete_domain))
        .route("/api/admin/domains/{id}/dkim", post(rotate_dkim))
        .route("/api/admin/domains/{id}/dns", get(domain_dns))
        .route("/api/admin/accounts", get(list_accounts).post(create_account))
        .route("/api/admin/accounts/{id}", get(get_account).patch(update_account).delete(delete_account))
        .route("/api/admin/accounts/{id}/password", post(set_account_password))
        .route("/api/admin/aliases", get(list_aliases).post(create_alias))
        .route("/api/admin/aliases/{id}", axum::routing::patch(update_alias).delete(delete_alias))
        .route("/api/admin/queue", get(list_queue))
        .route("/api/admin/queue/{id}/retry", post(retry_queue))
        .route("/api/admin/queue/{id}", delete(delete_queue))
        .route("/api/admin/settings", get(get_settings).put(put_settings))
        .route("/api/admin/transports/test", post(test_transport))
        .route("/api/admin/events", get(events))
        .route("/api/admin/security", get(security))
        .route("/api/admin/security/bans", post(add_ban))
        .route("/api/admin/security/bans/{ip}", delete(remove_ban))
        .route("/api/admin/storage", get(storage))
        .route("/api/admin/test-message", post(test_message))
        .nest("/api/v1", ext_admin_routes())
        .nest("/api/admin", ext_admin_routes())
        .nest("/api/v1/me", me_routes())
        .nest("/api/me", me_routes())
        .layer(axum::middleware::from_fn_with_state(state.clone(), audit_mw))
        .with_state(state)
}

// ------------------------------------------------------------- sessions

const COOKIE: &str = "pm_session";

fn client_ip(state: &State, peer: SocketAddr, headers: &HeaderMap) -> IpAddr {
    let ip = peer.ip();
    if crate::util::ip_in_list(ip, &state.config.web.trusted_proxies) {
        if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            if let Some(last) = xff.split(',').next_back().and_then(|s| s.trim().parse().ok()) {
                return last;
            }
        }
    }
    ip
}

fn session_token(headers: &HeaderMap) -> Option<String> {
    let cookies = headers.get(header::COOKIE)?.to_str().ok()?;
    cookies.split(';').find_map(|c| {
        let (k, v) = c.trim().split_once('=')?;
        (k == COOKIE).then(|| v.to_string())
    })
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    let v = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    v.strip_prefix("Bearer ").or_else(|| v.strip_prefix("bearer ")).map(str::trim)
}

/// The signed-in account: an API token (Authorization: Bearer, scope
/// "admin") or a console session cookie. A bearer request never falls
/// back to cookies.
async fn current(state: &State, headers: &HeaderMap) -> Result<Account, ApiError> {
    if let Some(t) = bearer(headers) {
        let (acc, tok) = crate::auth::token_auth(state, t).await.ok_or_else(|| ApiError(StatusCode::UNAUTHORIZED, "Invalid or expired API token.".into()))?;
        if !tok.has_scope("admin") {
            return Err(ApiError(StatusCode::FORBIDDEN, "This token lacks the admin scope.".into()));
        }
        return Ok(acc);
    }
    let token = session_token(headers).ok_or_else(unauthorized)?;
    let id = state.db.session_account(&sha256_hex(token.as_bytes())).await?.ok_or_else(unauthorized)?;
    let acc = state.db.get_account(id).await?.ok_or_else(unauthorized)?;
    if !acc.active {
        return Err(unauthorized());
    }
    Ok(acc)
}

async fn admin(state: &State, headers: &HeaderMap) -> Result<Account, ApiError> {
    let a = current(state, headers).await?;
    if !a.is_admin() {
        return Err(forbidden());
    }
    Ok(a)
}

fn secure_request(state: &State, headers: &HeaderMap) -> bool {
    state.config.web.tls || headers.get("x-forwarded-proto").and_then(|v| v.to_str().ok()) == Some("https")
}

/// Create a console session; returns the Set-Cookie value.
async fn session_cookie(state: &State, headers: &HeaderMap, account: &Account, ip: IpAddr) -> Result<String, ApiError> {
    let token = crate::util::random_token();
    let ttl = state.config.web.session_hours.max(1) as i64 * 3600;
    state.db.create_session(&sha256_hex(token.as_bytes()), account.id, ttl, &ip.to_string()).await?;
    let secure = if secure_request(state, headers) { "; Secure" } else { "" };
    // Lax (not Strict) so the cookie survives the redirect back from the identity
    // provider; every state-changing request still needs the X-Picacho header.
    Ok(format!("{COOKIE}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={ttl}{secure}"))
}

async fn start_session(state: &State, headers: &HeaderMap, account: &Account, ip: IpAddr) -> Result<Response, ApiError> {
    let cookie = session_cookie(state, headers, account, ip).await?;
    Ok(([(header::SET_COOKIE, cookie)], Json(account_json(account))).into_response())
}

/// Accounts are addressed by numeric id or email address.
async fn resolve_account(state: &State, key: &str) -> Result<Account, ApiError> {
    let a = match key.parse::<i64>() {
        Ok(id) => state.db.get_account(id).await?,
        Err(_) => state.db.account_by_email(key).await?,
    };
    a.ok_or_else(not_found)
}

/// Domains are addressed by numeric id or name.
async fn resolve_domain(state: &State, key: &str) -> Result<Domain, ApiError> {
    let d = match key.parse::<i64>() {
        Ok(id) => state.db.get_domain(id).await?,
        Err(_) => state.db.domain_by_name(key).await?,
    };
    d.ok_or_else(not_found)
}

fn account_json(a: &Account) -> Value {
    let mut v = serde_json::to_value(a).unwrap_or(Value::Null);
    v["sso_linked"] = json!(!a.oidc_sub.is_empty());
    v["has_password"] = json!(a.password_hash.starts_with('$'));
    if let Some(o) = v.as_object_mut() {
        o.remove("oidc_sub");
    }
    v
}

fn redirect_uri(state: &State, headers: &HeaderMap) -> String {
    format!("{}/api/auth/oidc/callback", crate::jmap::base_url(state, headers))
}

fn redirect(to: &str) -> Response {
    (StatusCode::SEE_OTHER, [(header::LOCATION, to.to_string()), (header::CACHE_CONTROL, "no-store".to_string())]).into_response()
}

// ------------------------------------------------------------- public

async fn status(AxState(state): AxState<State>, headers: HeaderMap) -> R {
    let s = state.settings();
    Ok(Json(json!({
        "setup_required": state.setup_required(),
        "hostname": state.hostname(),
        "version": env!("CARGO_PKG_VERSION"),
        "auth": {
            "password": crate::auth::web_password_allowed(&state),
            "oidc": if s.auth.oidc.enabled { json!({"name": s.auth.oidc.display_name}) } else { Value::Null },
            "redirect_uri": redirect_uri(&state, &headers),
        },
        "branding": s.branding,
    })))
}

async fn branding(AxState(state): AxState<State>) -> R {
    Ok(Json(json!(state.settings().branding)))
}

#[derive(Deserialize)]
struct KeyBody {
    key: String,
}

fn check_key(state: &State, key: &str) -> Result<(), ApiError> {
    if !state.setup_required() {
        return Err(bad("This server is already set up."));
    }
    state.setup_key.check(key).map_err(bad)
}

async fn setup_verify(AxState(state): AxState<State>, headers: HeaderMap, Json(b): Json<KeyBody>) -> R {
    check_key(&state, &b.key)?;
    let suggested = state.config.default_hostname();
    let domain = suggested.split_once('.').map(|(_, d)| d.to_string()).filter(|d| d.contains('.')).unwrap_or_default();
    Ok(Json(json!({
        "ok": true,
        "hostname": state.settings().server.hostname.clone().unwrap_or(suggested),
        "domain": domain,
        "storage": storage_summary(&state),
        "storage_config": state.config.storage,
        "config_path": state.config_path.display().to_string(),
        "password_min_length": state.settings().security.password_min_length,
        "redirect_uri": redirect_uri(&state, &headers),
    })))
}

#[derive(Deserialize, serde::Serialize, Clone)]
struct SetupAuth {
    #[serde(default = "yes")]
    web_password_login: bool,
    #[serde(default = "yes")]
    mail_password_login: bool,
    #[serde(default)]
    oidc: Option<crate::settings::OidcSettings>,
}

fn yes() -> bool {
    true
}

#[derive(Deserialize, serde::Serialize, Clone)]
struct SetupBody {
    key: String,
    hostname: String,
    domain: String,
    admin_local: String,
    #[serde(default)]
    admin_name: String,
    /// Absent when the administrator signs in with OIDC only.
    #[serde(default)]
    admin_password: Option<String>,
    #[serde(default)]
    relay: Option<Transport>,
    #[serde(default)]
    auth: Option<SetupAuth>,
}

/// Validate setup input and build the settings it would save.
fn setup_settings(state: &State, b: &SetupBody) -> Result<(LiveSettings, String, String, String), ApiError> {
    let hostname = b.hostname.trim().trim_end_matches('.').to_ascii_lowercase();
    let domain = b.domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if !valid_domain(&hostname) {
        return Err(bad("Enter a valid server host name, like mail.example.com."));
    }
    if !valid_domain(&domain) || !domain.contains('.') && domain != "localhost" {
        return Err(bad("Enter a valid mail domain, like example.com."));
    }
    let email = normalize_address(&format!("{}@{}", b.admin_local.trim(), domain)).ok_or_else(|| bad("Enter a valid admin address."))?;
    let mut settings = (*state.settings()).clone();
    if let Some(mut relay) = b.relay.clone() {
        if relay.id.is_empty() {
            relay.id = "relay".into();
        }
        if relay.name.is_empty() {
            relay.name = "Outbound relay".into();
        }
        settings.delivery.transports.retain(|t| t.id != relay.id);
        settings.delivery.routes.retain(|r| r.pattern != "*");
        settings.delivery.routes.push(crate::settings::Route { pattern: "*".into(), transport: relay.id.clone() });
        settings.delivery.transports.push(relay);
    }
    if let Some(a) = &b.auth {
        settings.auth.web_password_login = a.web_password_login;
        settings.auth.mail_password_login = a.mail_password_login;
        if let Some(o) = &a.oidc {
            settings.auth.oidc = o.clone();
            settings.auth.oidc.enabled = true;
            settings.auth.oidc.issuer = o.issuer.trim().trim_end_matches('/').to_string();
        }
    }
    settings.server.hostname = Some(hostname.clone());
    settings.server.primary_domain = Some(domain.clone());
    settings.server.setup_complete = true;
    settings.validate().map_err(bad)?;
    Ok((settings, hostname, domain, email))
}

/// Create the domain, admin account and settings. With `oidc_key` the admin
/// is linked to that identity (and may have no password).
async fn perform_setup(state: &State, b: &SetupBody, oidc_key: Option<&str>) -> Result<Account, ApiError> {
    let (settings, hostname, domain, email) = setup_settings(state, b)?;
    let hash = match (&b.admin_password, oidc_key) {
        (Some(pw), _) if !pw.is_empty() => {
            check_password_strength(pw, settings.security.password_min_length).map_err(bad)?;
            let pw = pw.clone();
            tokio::task::spawn_blocking(move || hash_password(&pw)).await.map_err(|e| anyhow::anyhow!(e))??
        }
        (_, Some(_)) => "!".to_string(),
        _ => return Err(bad("Choose a password, or sign in with single sign-on.")),
    };
    let domain_id = match state.db.domain_by_name(&domain).await? {
        Some(d) => d.id,
        None => state.db.create_domain(&domain, "local", "").await?,
    };
    if let Some(mut d) = state.db.get_domain(domain_id).await? {
        if d.dkim_private.is_empty() {
            let (private, public) = tokio::task::spawn_blocking(crate::smtp::delivery::generate_dkim)
                .await
                .map_err(|e| anyhow::anyhow!(e))??;
            d.dkim_private = private;
            d.dkim_public = public;
            d.dkim_selector = format!("picacho{}", chrono::Utc::now().format("%Y%m"));
            state.db.update_domain(&d).await?;
        }
    }
    let quota = settings.limits.default_quota_mb as i64 * 1024 * 1024;
    let account = match state.db.account_by_email(&email).await? {
        Some(a) => a,
        None => {
            let id = state.db.create_account(&email, domain_id, &hash, b.admin_name.trim(), "admin", quota).await?;
            state.db.get_account(id).await?.unwrap()
        }
    };
    if let Some(k) = oidc_key {
        state.db.set_oidc_sub(account.id, k).await?;
    }
    for local in ["postmaster", "abuse"] {
        let src = format!("{local}@{domain}");
        if src != email && state.db.alias_by_source(&src).await?.is_none() {
            state.db.create_alias(&src, &email).await?;
        }
    }
    state.save_settings(settings).await?;
    state.setup_key.clear();
    let how = if oidc_key.is_some() { "single sign-on" } else { "password" };
    state.event("info", "setup", &format!("server set up by {email} ({how}); host {hostname}, domain {domain}"));
    Ok(state.db.get_account(account.id).await?.unwrap_or(account))
}

async fn setup_complete(
    AxState(state): AxState<State>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(b): Json<SetupBody>,
) -> Result<Response, ApiError> {
    check_key(&state, &b.key)?;
    let account = perform_setup(&state, &b, None).await?;
    let ip = client_ip(&state, peer, &headers);
    start_session(&state, &headers, &account, ip).await
}

/// Setup with an OIDC administrator: validate everything, then send the
/// browser to the identity provider. The callback finishes setup.
async fn setup_oidc_begin(AxState(state): AxState<State>, headers: HeaderMap, Json(b): Json<SetupBody>) -> R {
    check_key(&state, &b.key)?;
    let (settings, ..) = setup_settings(&state, &b)?;
    if !settings.auth.oidc.enabled {
        return Err(bad("Configure single sign-on first."));
    }
    let url = crate::oidc::begin(&settings.auth.oidc, &redirect_uri(&state, &headers), "/", Some(serde_json::to_value(&b).unwrap()))
        .await
        .map_err(bad)?;
    Ok(Json(json!({"redirect": url})))
}

#[derive(Deserialize)]
struct OidcTest {
    #[serde(default)]
    key: Option<String>,
    issuer: String,
}

/// Check an issuer's discovery document (setup or admin).
async fn oidc_test(AxState(state): AxState<State>, headers: HeaderMap, Json(b): Json<OidcTest>) -> R {
    match &b.key {
        Some(k) => check_key(&state, k)?,
        None => {
            admin(&state, &headers).await?;
        }
    }
    let d = crate::oidc::discover(&b.issuer).await.map_err(bad)?;
    Ok(Json(json!({"ok": true, "issuer": d.issuer, "authorization_endpoint": d.authorization_endpoint,
        "token_endpoint": d.token_endpoint, "userinfo_endpoint": d.userinfo_endpoint,
        "redirect_uri": redirect_uri(&state, &headers)})))
}

#[derive(Deserialize)]
struct StorageBody {
    key: String,
    storage: crate::config::Storage,
}

/// Try the storage a setup would use, without changing anything.
async fn setup_storage_test(AxState(state): AxState<State>, Json(b): Json<StorageBody>) -> R {
    check_key(&state, &b.key)?;
    let results = crate::blob::test_storage(&b.storage).await;
    let ok = results.iter().all(|r| r.1.is_ok());
    Ok(Json(json!({
        "ok": ok,
        "results": results.into_iter().map(|(n, r)| json!({"name": n, "ok": r.is_ok(), "message": r.unwrap_or_else(|e| e)})).collect::<Vec<_>>(),
    })))
}

/// Save storage choices to config.toml and restart into them, keeping the
/// same access key so setup can continue.
async fn setup_storage(AxState(state): AxState<State>, Json(b): Json<StorageBody>) -> R {
    check_key(&state, &b.key)?;
    let mut cfg = if state.config_path.exists() {
        crate::config::Config::load(&state.config_path).map_err(|e| bad(format!("config.toml has errors: {e}")))?
    } else {
        state.config.clone()
    };
    let before = serde_json::to_value(&cfg.storage).unwrap();
    cfg.storage = b.storage;
    if serde_json::to_value(&cfg.storage).unwrap() == before && serde_json::to_value(&state.config.storage).unwrap() == before {
        return Ok(Json(json!({"restarting": false})));
    }
    let results = crate::blob::test_storage(&cfg.storage).await;
    if let Some((n, Err(e))) = results.into_iter().find(|r| r.1.is_err()) {
        return Err(bad(format!("{n}: {e}")));
    }
    let text = cfg.to_minimal_toml().map_err(|e| bad(format!("{e}")))?;
    write_config(&state, &format!("# Picacho Server configuration (written during setup).\n{text}")).await?;
    state.event("info", "setup", "storage configured during setup; restarting");
    let key = b.key.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        crate::util::reexec_with(&[("PICACHO_SETUP_KEY", key.as_str())]);
    });
    Ok(Json(json!({"restarting": true})))
}

// ------------------------------------------------------------- OIDC sign-in

#[derive(Deserialize)]
struct StartQuery {
    next: Option<String>,
}

async fn oidc_start(AxState(state): AxState<State>, headers: HeaderMap, Query(q): Query<StartQuery>) -> Response {
    let cfg = state.settings().auth.oidc.clone();
    if !cfg.enabled || state.setup_required() {
        return redirect("/login?error=Single+sign-on+isn%27t+set+up.");
    }
    match crate::oidc::begin(&cfg, &redirect_uri(&state, &headers), q.next.as_deref().unwrap_or("/"), None).await {
        Ok(url) => redirect(&url),
        Err(e) => {
            tracing::warn!("oidc start: {e}");
            redirect(&format!("/login?error={}", url::form_urlencoded::byte_serialize(e.as_bytes()).collect::<String>()))
        }
    }
}

#[derive(Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

async fn oidc_callback(
    AxState(state): AxState<State>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(q): Query<CallbackQuery>,
) -> Response {
    let fail = |msg: &str, setup: bool| {
        let enc: String = url::form_urlencoded::byte_serialize(msg.as_bytes()).collect();
        redirect(&format!("{}?error={enc}", if setup { "/setup" } else { "/login" }))
    };
    if let Some(e) = q.error {
        return fail(&q.error_description.unwrap_or(e), state.setup_required());
    }
    let (Some(code), Some(st)) = (q.code, q.state) else {
        return fail("The identity provider sent an incomplete response.", state.setup_required());
    };
    let ip = client_ip(&state, peer, &headers);
    let (id, pending) = match crate::oidc::finish(&code, &st).await {
        Ok(x) => x,
        Err(e) => return fail(&e, state.setup_required()),
    };
    let account = if let Some(setup) = pending.setup {
        // First-run setup: link the administrator to this identity.
        let Ok(b) = serde_json::from_value::<SetupBody>(setup) else { return fail("Setup data was lost.", true) };
        if let Err(e) = check_key(&state, &b.key) {
            return fail(&e.1, true);
        }
        match perform_setup(&state, &b, Some(&id.key)).await {
            Ok(a) => a,
            Err(e) => return fail(&e.1, true),
        }
    } else {
        match crate::oidc::resolve_account(&state, &pending.cfg, &id).await {
            Ok(a) => a,
            Err(e) => {
                state.event("warn", "auth", &format!("single sign-on refused for {} from {ip}: {e}", id.email.as_deref().unwrap_or("?")));
                return fail(&e, false);
            }
        }
    };
    let _ = state.db.touch_login(account.id).await;
    state.event("info", "auth", &format!("console sign-in {} via single sign-on from {ip}", account.email));
    match session_cookie(&state, &headers, &account, ip).await {
        Ok(cookie) => {
            let mut r = redirect(&pending.next);
            r.headers_mut().insert(header::SET_COOKIE, cookie.parse().unwrap());
            r
        }
        Err(_) => fail("Couldn't start a session.", false),
    }
}

#[derive(Deserialize)]
struct LoginBody {
    email: String,
    password: String,
}

async fn login(
    AxState(state): AxState<State>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(b): Json<LoginBody>,
) -> Result<Response, ApiError> {
    let ip = client_ip(&state, peer, &headers);
    if !crate::auth::web_password_allowed(&state) {
        return Err(ApiError(StatusCode::FORBIDDEN, "Password sign-in is turned off. Use single sign-on.".into()));
    }
    match crate::auth::login(&state, &b.email, &b.password, ip).await {
        Ok(a) => {
            let _ = state.db.touch_login(a.id).await;
            state.event("info", "auth", &format!("console login {} from {ip}", a.email));
            start_session(&state, &headers, &a, ip).await
        }
        Err(crate::auth::AuthError::Banned) => {
            Err(ApiError(StatusCode::TOO_MANY_REQUESTS, "Too many failed sign-ins. Try again later.".into()))
        }
        Err(crate::auth::AuthError::Disabled) => Err(ApiError(StatusCode::FORBIDDEN, "This account is disabled.".into())),
        Err(_) => {
            tokio::time::sleep(std::time::Duration::from_millis(400)).await;
            Err(ApiError(StatusCode::UNAUTHORIZED, "Email or password is incorrect.".into()))
        }
    }
}

async fn logout(AxState(state): AxState<State>, headers: HeaderMap) -> Result<Response, ApiError> {
    if let Some(t) = session_token(&headers) {
        state.db.delete_session(&sha256_hex(t.as_bytes())).await?;
    }
    let cookie = format!("{COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0");
    Ok(([(header::SET_COOKIE, cookie)], Json(json!({"ok": true}))).into_response())
}

async fn me(AxState(state): AxState<State>, headers: HeaderMap) -> R {
    let a = current(&state, &headers).await?;
    Ok(Json(account_json(&a)))
}

#[derive(Deserialize)]
struct PasswordChange {
    current: String,
    new: String,
}

async fn change_own_password(AxState(state): AxState<State>, headers: HeaderMap, Json(b): Json<PasswordChange>) -> R {
    let a = current(&state, &headers).await?;
    let (cur, h) = (b.current.clone(), a.password_hash.clone());
    let ok = tokio::task::spawn_blocking(move || crate::auth::verify_password(&cur, &h)).await.unwrap_or(false);
    if !ok {
        return Err(bad("Current password is incorrect."));
    }
    check_password_strength(&b.new, state.settings().security.password_min_length).map_err(bad)?;
    let pw = b.new.clone();
    let hash = tokio::task::spawn_blocking(move || hash_password(&pw)).await.map_err(|e| anyhow::anyhow!(e))??;
    state.db.set_password(a.id, &hash).await?;
    state.event("info", "auth", &format!("{} changed their password", a.email));
    Ok(Json(json!({"ok": true})))
}

async fn client_settings(AxState(state): AxState<State>, headers: HeaderMap) -> R {
    let a = current(&state, &headers).await?;
    Ok(Json(client_info(&state, &a.email)))
}

fn client_info(state: &State, email: &str) -> Value {
    let host = state.hostname();
    let port = |v: &Vec<SocketAddr>, d: u16| v.first().map(|a| a.port()).unwrap_or(d);
    let l = &state.config.listen;
    json!({
        "username": email,
        "imap": {"host": host, "port": port(&l.imaps, 993), "security": "SSL/TLS"},
        "imap_starttls": {"host": host, "port": port(&l.imap, 143), "security": "STARTTLS"},
        "smtp": {"host": host, "port": port(&l.submissions, 465), "security": "SSL/TLS"},
        "smtp_starttls": {"host": host, "port": port(&l.submission, 587), "security": "STARTTLS"},
    })
}

// ------------------------------------------------------------- admin

fn storage_summary(state: &State) -> Value {
    json!({
        "database": format!("{:?}", state.db.kind).to_lowercase(),
        "messages": state.blobs.messages.describe(),
        "attachments": state.blobs.attachments.as_ref().map(|(b, t)| json!({"backend": b.describe(), "threshold_bytes": t})),
        "settings": state.settings_backend.describe(),
        "encrypted": state.blobs.encrypted(),
        "data_dir": state.config.storage.data_dir.display().to_string(),
    })
}

async fn overview(AxState(state): AxState<State>, headers: HeaderMap) -> R {
    admin(&state, &headers).await?;
    let stats = state.db.stats().await?;
    let (queued, deferred, failed) = state.db.queue_stats().await?;
    let events = state.db.list_events(12, None).await?;
    let conns = json!({
        "total": state.conns.total(),
        "imap": state.conns.imap.load(std::sync::atomic::Ordering::Relaxed),
        "smtp": state.conns.smtp.load(std::sync::atomic::Ordering::Relaxed),
    });
    Ok(Json(json!({
        "hostname": state.hostname(),
        "primary_domain": state.settings().server.primary_domain,
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_secs": now() - state.started,
        "stats": stats,
        "queue": {"queued": queued, "deferred": deferred, "failed": failed},
        "connections": conns,
        "listeners": state.listeners.lock().clone(),
        "storage": storage_summary(&state),
        "tls": {"self_signed": state.tls.self_signed, "certificate": state.tls.cert_path.display().to_string()},
        "bans": state.limiter.list_bans().len(),
        "restart_required": state.restart_required.load(std::sync::atomic::Ordering::Relaxed),
        "events": events,
    })))
}

// --- domains

async fn list_domains(AxState(state): AxState<State>, headers: HeaderMap) -> R {
    admin(&state, &headers).await?;
    let domains = state.db.list_domains().await?;
    let accounts = state.db.list_accounts().await?;
    let out: Vec<Value> = domains
        .iter()
        .map(|d| {
            let mut v = serde_json::to_value(d).unwrap();
            v["accounts"] = json!(accounts.iter().filter(|a| a.domain_id == d.id).count());
            v["has_dkim"] = json!(!d.dkim_private.is_empty());
            v
        })
        .collect();
    Ok(Json(json!(out)))
}

#[derive(Deserialize)]
struct NewDomain {
    name: String,
    #[serde(default)]
    mode: Option<String>,
    #[serde(default)]
    transport: Option<String>,
    #[serde(default)]
    dkim: Option<bool>,
}

fn check_mode(state: &State, mode: &str, transport: &str) -> Result<(), ApiError> {
    match mode {
        "local" => Ok(()),
        "relay" | "webhook" => {
            if state.settings().transport(transport).is_none() {
                return Err(bad("Choose a transport for relay/webhook domains (create one in Delivery)."));
            }
            Ok(())
        }
        _ => Err(bad("Mode must be local, relay or webhook.")),
    }
}

async fn create_domain(AxState(state): AxState<State>, headers: HeaderMap, Json(b): Json<NewDomain>) -> R {
    let who = admin(&state, &headers).await?;
    let name = b.name.trim().trim_end_matches('.').to_ascii_lowercase();
    if !valid_domain(&name) {
        return Err(bad("That isn't a valid domain name."));
    }
    if state.db.domain_by_name(&name).await?.is_some() {
        return Err(bad("That domain already exists."));
    }
    let mode = b.mode.unwrap_or_else(|| "local".into());
    let transport = b.transport.unwrap_or_default();
    check_mode(&state, &mode, &transport)?;
    let id = state.db.create_domain(&name, &mode, &transport).await?;
    if b.dkim.unwrap_or(true) {
        set_dkim(&state, id).await?;
    }
    state.event("info", "admin", &format!("{} added domain {name}", who.email));
    let d = state.db.get_domain(id).await?.ok_or_else(not_found)?;
    Ok(Json(serde_json::to_value(d).unwrap()))
}

async fn set_dkim(state: &State, id: i64) -> Result<Domain, ApiError> {
    let mut d = state.db.get_domain(id).await?.ok_or_else(not_found)?;
    let (private, public) =
        tokio::task::spawn_blocking(crate::smtp::delivery::generate_dkim).await.map_err(|e| anyhow::anyhow!(e))??;
    d.dkim_private = private;
    d.dkim_public = public;
    d.dkim_selector = format!("picacho{}", chrono::Utc::now().format("%Y%m%d"));
    state.db.update_domain(&d).await?;
    Ok(d)
}

async fn get_domain(AxState(state): AxState<State>, headers: HeaderMap, Path(key): Path<String>) -> R {
    admin(&state, &headers).await?;
    let id = resolve_domain(&state, &key).await?.id;
    let d = state.db.get_domain(id).await?.ok_or_else(not_found)?;
    let mut v = serde_json::to_value(&d).unwrap();
    v["dns"] = dns_records(&state, &d);
    Ok(Json(v))
}

#[derive(Deserialize)]
struct DomainPatch {
    mode: Option<String>,
    transport: Option<String>,
    catch_all: Option<String>,
    active: Option<bool>,
}

async fn update_domain(AxState(state): AxState<State>, headers: HeaderMap, Path(key): Path<String>, Json(b): Json<DomainPatch>) -> R {
    let who = admin(&state, &headers).await?;
    let id = resolve_domain(&state, &key).await?.id;
    let mut d = state.db.get_domain(id).await?.ok_or_else(not_found)?;
    if let Some(m) = b.mode {
        d.mode = m;
    }
    if let Some(t) = b.transport {
        d.transport = t;
    }
    check_mode(&state, &d.mode, &d.transport)?;
    if let Some(c) = b.catch_all {
        let c = c.trim().to_string();
        if !c.is_empty() && c.split(',').any(|x| normalize_address(x).is_none()) {
            return Err(bad("Catch-all must be a list of email addresses."));
        }
        d.catch_all = c;
    }
    if let Some(a) = b.active {
        d.active = a;
    }
    state.db.update_domain(&d).await?;
    state.event("info", "admin", &format!("{} updated domain {}", who.email, d.name));
    Ok(Json(serde_json::to_value(d).unwrap()))
}

async fn delete_domain(AxState(state): AxState<State>, headers: HeaderMap, Path(key): Path<String>) -> R {
    let who = admin(&state, &headers).await?;
    let id = resolve_domain(&state, &key).await?.id;
    let d = state.db.get_domain(id).await?.ok_or_else(not_found)?;
    let accounts = state.db.list_accounts().await?;
    if accounts.iter().any(|a| a.domain_id == id) {
        return Err(bad("Delete or move this domain's accounts first."));
    }
    if state.settings().server.primary_domain.as_deref() == Some(&d.name) {
        return Err(bad("The primary domain can't be deleted."));
    }
    state.db.delete_domain(id).await?;
    state.event("warn", "admin", &format!("{} deleted domain {}", who.email, d.name));
    Ok(Json(json!({"ok": true})))
}

async fn rotate_dkim(AxState(state): AxState<State>, headers: HeaderMap, Path(key): Path<String>) -> R {
    let who = admin(&state, &headers).await?;
    let id = resolve_domain(&state, &key).await?.id;
    let d = set_dkim(&state, id).await?;
    state.event("info", "admin", &format!("{} generated a new DKIM key for {}", who.email, d.name));
    let mut v = serde_json::to_value(&d).unwrap();
    v["dns"] = dns_records(&state, &d);
    Ok(Json(v))
}

fn chunk_txt(s: &str) -> String {
    s.as_bytes().chunks(250).map(|c| format!("\"{}\"", String::from_utf8_lossy(c))).collect::<Vec<_>>().join(" ")
}

fn dns_records(state: &State, d: &Domain) -> Value {
    let host = state.hostname();
    let mut recs = vec![];
    if d.mode == "local" || d.mode == "relay" || d.mode == "webhook" {
        recs.push(json!({"type": "MX", "name": d.name, "value": format!("10 {host}."), "purpose": "Receive mail for this domain"}));
    }
    recs.push(json!({"type": "TXT", "name": d.name, "value": "v=spf1 mx -all", "purpose": "SPF: only your MX may send"}));
    if !d.dkim_public.is_empty() {
        let v = format!("v=DKIM1; k=rsa; p={}", d.dkim_public);
        recs.push(json!({
            "type": "TXT",
            "name": format!("{}._domainkey.{}", d.dkim_selector, d.name),
            "value": v,
            "zone_value": chunk_txt(&v),
            "purpose": "DKIM: signs outgoing mail",
        }));
    }
    recs.push(json!({
        "type": "TXT",
        "name": format!("_dmarc.{}", d.name),
        "value": format!("v=DMARC1; p=quarantine; rua=mailto:postmaster@{}", d.name),
        "purpose": "DMARC: tell receivers how to treat spoofed mail",
    }));
    recs.push(json!({"type": "SRV", "name": format!("_imaps._tcp.{}", d.name), "value": format!("0 1 993 {host}."), "purpose": "Client autodiscovery (IMAP)"}));
    recs.push(json!({"type": "SRV", "name": format!("_submissions._tcp.{}", d.name), "value": format!("0 1 465 {host}."), "purpose": "Client autodiscovery (SMTP)"}));
    let web_port = state.config.web.public_url.as_deref().and_then(|u| url::Url::parse(u).ok()).and_then(|u| u.port_or_known_default()).or(state.config.web.listen.first().map(|a| a.port())).unwrap_or(443);
    recs.push(json!({"type": "SRV", "name": format!("_caldavs._tcp.{}", d.name), "value": format!("0 1 {web_port} {host}."), "purpose": "Calendar app autodiscovery (CalDAV)"}));
    recs.push(json!({"type": "SRV", "name": format!("_carddavs._tcp.{}", d.name), "value": format!("0 1 {web_port} {host}."), "purpose": "Contacts app autodiscovery (CardDAV)"}));
    recs.push(json!({"type": "TXT", "name": format!("_caldavs._tcp.{}", d.name), "value": "path=/dav/", "purpose": "CalDAV context path"}));
    if let Some(p) = state.config.listen.managesieve.first() {
        recs.push(json!({"type": "SRV", "name": format!("_sieve._tcp.{}", d.name), "value": format!("0 1 {} {host}.", p.port()), "purpose": "Filter editing (ManageSieve)"}));
    }
    recs.push(json!({"type": "CNAME", "name": format!("autoconfig.{}", d.name), "value": format!("{host}."), "purpose": "Thunderbird/K-9 automatic setup"}));
    // MTA-STS and TLS reporting for mail sent *to* this domain.
    let mode = state.settings().server.mta_sts_mode.clone().unwrap_or_else(|| "testing".into());
    if mode != "off" {
        let id = crate::util::sha256_hex(format!("{mode}{host}{:?}", state.settings().server.mta_sts_mx).as_bytes())[..16].to_string();
        recs.push(json!({"type": "CNAME", "name": format!("mta-sts.{}", d.name), "value": format!("{host}."), "purpose": format!("MTA-STS policy host (serves mode: {mode}; needs a certificate for this name)")}));
        recs.push(json!({"type": "TXT", "name": format!("_mta-sts.{}", d.name), "value": format!("v=STSv1; id={id}"), "purpose": "MTA-STS: senders must use verified TLS"}));
    }
    recs.push(json!({"type": "TXT", "name": format!("_smtp._tls.{}", d.name), "value": format!("v=TLSRPTv1; rua=mailto:tls-reports@{}", d.name), "purpose": "TLS-RPT: receive reports about TLS failures (add the address to reports.ingest_addresses)"}));
    // DANE for inbound mail: pins the served certificate's key.
    if let Some(der) = state.tls.leaf() {
        if !state.tls.self_signed || state.config.tls.acme.is_some() {
            if let Ok((_, c)) = x509_parser::parse_x509_certificate(&der) {
                use sha2::Digest;
                let h = hex::encode(sha2::Sha256::digest(c.tbs_certificate.subject_pki.raw));
                recs.push(json!({"type": "TLSA", "name": format!("_25._tcp.{host}"), "value": format!("3 1 1 {h}"), "purpose": "DANE: authenticates this MX (needs DNSSEC; update when the key changes)"}));
            }
        }
    }
    json!(recs)
}

/// Live DNS check: compare what's published with what's recommended.
async fn domain_dns(AxState(state): AxState<State>, headers: HeaderMap, Path(key): Path<String>) -> R {
    admin(&state, &headers).await?;
    let id = resolve_domain(&state, &key).await?.id;
    let d = state.db.get_domain(id).await?.ok_or_else(not_found)?;
    let host = state.hostname();
    let Some(auth) = &state.resolver else { return Ok(Json(json!({"available": false}))) };
    let r = auth.resolver();
    let txt = |name: String| {
        let r = r.clone();
        async move {
            match tokio::time::timeout(std::time::Duration::from_secs(8), r.txt_lookup(format!("{name}."))).await {
                Ok(Ok(l)) => l
                    .answers()
                    .iter()
                    .filter_map(|rec| match &rec.data {
                        mail_auth::hickory_resolver::proto::rr::RData::TXT(t) => {
                            Some(t.txt_data.iter().map(|d| String::from_utf8_lossy(d).to_string()).collect::<String>())
                        }
                        _ => None,
                    })
                    .collect::<Vec<_>>(),
                _ => vec![],
            }
        }
    };
    let mx = crate::queue::mx_hosts(&state, &d.name).await.unwrap_or_default();
    let spf = txt(d.name.clone()).await.into_iter().find(|t| t.starts_with("v=spf1"));
    let dkim = if d.dkim_selector.is_empty() {
        None
    } else {
        txt(format!("{}._domainkey.{}", d.dkim_selector, d.name)).await.into_iter().find(|t| t.contains("p="))
    };
    let dmarc = txt(format!("_dmarc.{}", d.name)).await.into_iter().find(|t| t.starts_with("v=DMARC1"));
    let dkim_ok = dkim.as_ref().map(|t| t.replace(' ', "").contains(&format!("p={}", d.dkim_public))).unwrap_or(false);
    Ok(Json(json!({
        "available": true,
        "mx": {"found": mx, "ok": mx.iter().any(|m| m.eq_ignore_ascii_case(&host))},
        "spf": {"found": spf, "ok": spf.is_some()},
        "dkim": {"found": dkim, "ok": dkim_ok},
        "dmarc": {"found": dmarc, "ok": dmarc.is_some()},
    })))
}

// --- accounts

async fn list_accounts(AxState(state): AxState<State>, headers: HeaderMap) -> R {
    admin(&state, &headers).await?;
    let accounts = state.db.list_accounts().await?;
    Ok(Json(json!(accounts)))
}

#[derive(Deserialize)]
struct NewAccount {
    email: String,
    password: String,
    #[serde(default)]
    display_name: String,
    #[serde(default)]
    role: Option<String>,
    #[serde(default)]
    quota_mb: Option<i64>,
}

async fn create_account(AxState(state): AxState<State>, headers: HeaderMap, Json(b): Json<NewAccount>) -> R {
    let who = admin(&state, &headers).await?;
    let email = normalize_address(&b.email).ok_or_else(|| bad("That isn't a valid email address."))?;
    let dom = state
        .db
        .domain_by_name(crate::util::domain_of(&email))
        .await?
        .ok_or_else(|| bad("Add the domain first."))?;
    if dom.mode != "local" {
        return Err(bad("Accounts can only be created on local domains."));
    }
    if state.db.account_by_email(&email).await?.is_some() || state.db.alias_by_source(&email).await?.is_some() {
        return Err(bad("That address is already in use."));
    }
    check_password_strength(&b.password, state.settings().security.password_min_length).map_err(bad)?;
    let role = b.role.unwrap_or_else(|| "user".into());
    if role != "user" && role != "admin" {
        return Err(bad("Role must be user or admin."));
    }
    let quota = b.quota_mb.unwrap_or(state.settings().limits.default_quota_mb as i64).max(0) * 1024 * 1024;
    let pw = b.password.clone();
    let hash = tokio::task::spawn_blocking(move || hash_password(&pw)).await.map_err(|e| anyhow::anyhow!(e))??;
    let id = state.db.create_account(&email, dom.id, &hash, b.display_name.trim(), &role, quota).await?;
    state.event("info", "admin", &format!("{} created account {email}", who.email));
    let a = state.db.get_account(id).await?.ok_or_else(not_found)?;
    Ok(Json(account_json(&a)))
}

async fn get_account(AxState(state): AxState<State>, headers: HeaderMap, Path(key): Path<String>) -> R {
    admin(&state, &headers).await?;
    let id = resolve_account(&state, &key).await?.id;
    let a = state.db.get_account(id).await?.ok_or_else(not_found)?;
    let mut mailboxes = vec![];
    for m in state.db.list_mailboxes(id).await? {
        let (count, unseen, size) = state.db.mailbox_counts(m.id).await?;
        mailboxes.push(json!({"name": m.name, "special_use": m.special_use, "messages": count, "unseen": unseen, "size": size}));
    }
    let aliases: Vec<_> = state
        .db
        .list_aliases()
        .await?
        .into_iter()
        .filter(|al| al.destination.split([',', ' ']).any(|d| d.trim().eq_ignore_ascii_case(&a.email)))
        .collect();
    let recent = state.db.recent_messages(id, 25).await?;
    let mut v = account_json(&a);
    v["mailboxes"] = json!(mailboxes);
    v["aliases"] = json!(aliases);
    v["recent"] = json!(recent);
    v["client"] = client_info(&state, &a.email);
    v["sessions"] = json!(state.imap_sessions.get(&id).map(|c| *c).unwrap_or(0));
    Ok(Json(v))
}

#[derive(Deserialize)]
struct AccountPatch {
    display_name: Option<String>,
    role: Option<String>,
    quota_mb: Option<i64>,
    active: Option<bool>,
    can_send_external: Option<bool>,
    forward_to: Option<String>,
    keep_copy: Option<bool>,
}

async fn update_account(AxState(state): AxState<State>, headers: HeaderMap, Path(key): Path<String>, Json(b): Json<AccountPatch>) -> R {
    let who = admin(&state, &headers).await?;
    let id = resolve_account(&state, &key).await?.id;
    let mut a = state.db.get_account(id).await?.ok_or_else(not_found)?;
    if let Some(n) = b.display_name {
        a.display_name = n.trim().chars().take(200).collect();
    }
    if let Some(r) = b.role {
        if r != "user" && r != "admin" {
            return Err(bad("Role must be user or admin."));
        }
        if a.is_admin() && r != "admin" && state.db.count_admins().await? <= 1 {
            return Err(bad("Keep at least one administrator."));
        }
        a.role = r;
    }
    if let Some(q) = b.quota_mb {
        a.quota_bytes = q.max(0) * 1024 * 1024;
    }
    if let Some(act) = b.active {
        if !act && a.id == who.id {
            return Err(bad("You can't disable your own account."));
        }
        a.active = act;
    }
    if let Some(c) = b.can_send_external {
        a.can_send_external = c;
    }
    if let Some(f) = b.forward_to {
        let f = f.trim().to_string();
        if !f.is_empty() && f.split(',').any(|x| normalize_address(x).is_none()) {
            return Err(bad("Forwarding must be a comma-separated list of addresses."));
        }
        a.forward_to = f;
    }
    if let Some(k) = b.keep_copy {
        a.keep_copy = k;
    }
    state.db.update_account(&a).await?;
    state.event("info", "admin", &format!("{} updated account {}", who.email, a.email));
    Ok(Json(account_json(&a)))
}

async fn delete_account(AxState(state): AxState<State>, headers: HeaderMap, Path(key): Path<String>) -> R {
    let who = admin(&state, &headers).await?;
    let id = resolve_account(&state, &key).await?.id;
    let a = state.db.get_account(id).await?.ok_or_else(not_found)?;
    if a.id == who.id {
        return Err(bad("You can't delete your own account."));
    }
    if a.is_admin() && state.db.count_admins().await? <= 1 {
        return Err(bad("Keep at least one administrator."));
    }
    let blobs = state.db.delete_account(id).await?;
    state.blobs.delete_all(&blobs).await;
    state.event("warn", "admin", &format!("{} deleted account {} and its mail", who.email, a.email));
    Ok(Json(json!({"ok": true})))
}

#[derive(Deserialize)]
struct SetPassword {
    password: String,
}

async fn set_account_password(AxState(state): AxState<State>, headers: HeaderMap, Path(key): Path<String>, Json(b): Json<SetPassword>) -> R {
    let who = admin(&state, &headers).await?;
    let id = resolve_account(&state, &key).await?.id;
    let a = state.db.get_account(id).await?.ok_or_else(not_found)?;
    check_password_strength(&b.password, state.settings().security.password_min_length).map_err(bad)?;
    let pw = b.password.clone();
    let hash = tokio::task::spawn_blocking(move || hash_password(&pw)).await.map_err(|e| anyhow::anyhow!(e))??;
    state.db.set_password(id, &hash).await?;
    state.event("info", "admin", &format!("{} reset the password for {}", who.email, a.email));
    Ok(Json(json!({"ok": true})))
}

// --- aliases

async fn list_aliases(AxState(state): AxState<State>, headers: HeaderMap) -> R {
    admin(&state, &headers).await?;
    Ok(Json(json!(state.db.list_aliases().await?)))
}

#[derive(Deserialize)]
struct NewAlias {
    source: String,
    destination: String,
}

fn clean_destinations(d: &str) -> Result<String, ApiError> {
    let list: Vec<String> = d.split([',', ' ', '\n']).filter(|x| !x.trim().is_empty()).map(|x| x.trim().to_string()).collect();
    if list.is_empty() {
        return Err(bad("Add at least one destination address."));
    }
    let mut out = vec![];
    for x in list {
        out.push(normalize_address(&x).ok_or_else(|| bad(format!("{x} isn't a valid address.")))?);
    }
    Ok(out.join(", "))
}

async fn create_alias(AxState(state): AxState<State>, headers: HeaderMap, Json(b): Json<NewAlias>) -> R {
    let who = admin(&state, &headers).await?;
    let src = b.source.trim().to_ascii_lowercase();
    let src_domain = if let Some(d) = src.strip_prefix('@') {
        d.to_string()
    } else {
        normalize_address(&src).ok_or_else(|| bad("Source must be an address or @domain for a catch-all."))?;
        crate::util::domain_of(&src).to_string()
    };
    if state.db.domain_by_name(&src_domain).await?.is_none() {
        return Err(bad("The source address must be on one of your domains."));
    }
    if state.db.alias_by_source(&src).await?.is_some() || state.db.account_by_email(&src).await?.is_some() {
        return Err(bad("That address is already in use."));
    }
    let dest = clean_destinations(&b.destination)?;
    let id = state.db.create_alias(&src, &dest).await?;
    state.event("info", "admin", &format!("{} created alias {src} → {dest}", who.email));
    Ok(Json(json!({"id": id})))
}

#[derive(Deserialize)]
struct AliasPatch {
    destination: Option<String>,
    active: Option<bool>,
}

async fn update_alias(AxState(state): AxState<State>, headers: HeaderMap, Path(id): Path<i64>, Json(b): Json<AliasPatch>) -> R {
    let who = admin(&state, &headers).await?;
    let a = state.db.list_aliases().await?.into_iter().find(|a| a.id == id).ok_or_else(not_found)?;
    let dest = match b.destination {
        Some(d) => clean_destinations(&d)?,
        None => a.destination.clone(),
    };
    state.db.update_alias(id, &dest, b.active.unwrap_or(a.active)).await?;
    state.event("info", "admin", &format!("{} updated alias {}", who.email, a.source));
    Ok(Json(json!({"ok": true})))
}

async fn delete_alias(AxState(state): AxState<State>, headers: HeaderMap, Path(id): Path<i64>) -> R {
    let who = admin(&state, &headers).await?;
    state.db.delete_alias(id).await?;
    state.event("info", "admin", &format!("{} deleted alias #{id}", who.email));
    Ok(Json(json!({"ok": true})))
}

// --- queue

async fn list_queue(AxState(state): AxState<State>, headers: HeaderMap) -> R {
    admin(&state, &headers).await?;
    Ok(Json(json!(state.db.list_queue().await?)))
}

async fn retry_queue(AxState(state): AxState<State>, headers: HeaderMap, Path(id): Path<i64>) -> R {
    admin(&state, &headers).await?;
    let q = state.db.get_queue(id).await?.ok_or_else(not_found)?;
    state.db.update_queue(id, &q.recipients, q.attempts, now(), &q.last_error, "queued").await?;
    state.queue_wake.notify_one();
    Ok(Json(json!({"ok": true})))
}

async fn delete_queue(AxState(state): AxState<State>, headers: HeaderMap, Path(id): Path<i64>) -> R {
    let who = admin(&state, &headers).await?;
    if let Some(blob) = state.db.delete_queue(id).await? {
        state.blobs.delete(&blob).await?;
    }
    state.event("info", "admin", &format!("{} removed queue item {id}", who.email));
    Ok(Json(json!({"ok": true})))
}

// --- settings

async fn get_settings(AxState(state): AxState<State>, headers: HeaderMap) -> R {
    admin(&state, &headers).await?;
    let s = state.settings().redacted();
    Ok(Json(json!({
        "settings": s,
        "defaults": LiveSettings::default(),
        "storage": storage_summary(&state),
        "static": {
            "listen": {
                "smtp": state.config.listen.smtp, "submission": state.config.listen.submission,
                "submissions": state.config.listen.submissions, "imap": state.config.listen.imap, "imaps": state.config.listen.imaps,
            },
            "web": state.config.web.listen,
            "web_tls": state.config.web.tls,
            "limits": {
                "max_connections": state.config.limits.max_connections,
                "max_connections_per_ip": state.config.limits.max_connections_per_ip,
            },
        },
    })))
}

async fn put_settings(AxState(state): AxState<State>, headers: HeaderMap, Json(mut s): Json<LiveSettings>) -> R {
    let who = admin(&state, &headers).await?;
    let old = state.settings();
    s.merge_secrets_from(&old);
    s.server.setup_complete = old.server.setup_complete;
    if let Some(h) = &s.server.hostname {
        if !valid_domain(h) {
            return Err(bad("Host name is not valid."));
        }
    }
    s.validate().map_err(bad)?;
    state.save_settings(s).await?;
    state.event("info", "admin", &format!("{} saved settings", who.email));
    Ok(Json(json!({"settings": state.settings().redacted()})))
}

#[derive(Deserialize)]
struct TestTransport {
    transport: Transport,
}

async fn test_transport(AxState(state): AxState<State>, headers: HeaderMap, Json(mut b): Json<TestTransport>) -> R {
    admin(&state, &headers).await?;
    // Use the stored secret when the console only has the redacted marker.
    if let Some(old) = state.settings().transport(&b.transport.id) {
        if b.transport.password.as_deref() == Some(crate::settings::REDACTED) {
            b.transport.password = old.password.clone();
        }
        if b.transport.secret.as_deref() == Some(crate::settings::REDACTED) {
            b.transport.secret = old.secret.clone();
        }
    }
    match crate::queue::test_transport(&state, &b.transport).await {
        Ok(m) => Ok(Json(json!({"ok": true, "message": m}))),
        Err(m) => Ok(Json(json!({"ok": false, "message": m}))),
    }
}

#[derive(Deserialize)]
struct EventQuery {
    kind: Option<String>,
    limit: Option<i64>,
}

async fn events(AxState(state): AxState<State>, headers: HeaderMap, Query(q): Query<EventQuery>) -> R {
    admin(&state, &headers).await?;
    let limit = q.limit.unwrap_or(200).clamp(1, 1000);
    Ok(Json(json!(state.db.list_events(limit, q.kind.as_deref().filter(|k| !k.is_empty())).await?)))
}

async fn security(AxState(state): AxState<State>, headers: HeaderMap) -> R {
    admin(&state, &headers).await?;
    let bans: Vec<Value> = state
        .limiter
        .list_bans()
        .into_iter()
        .map(|(ip, secs, reason)| json!({"ip": ip, "remaining_secs": secs, "reason": reason}))
        .collect();
    Ok(Json(json!({
        "bans": bans,
        "tls": {"self_signed": state.tls.self_signed, "certificate": state.tls.cert_path.display().to_string(),
                "min_version": state.config.tls.min_version.clone().unwrap_or_else(|| "1.2".into())},
        "encrypted_storage": state.blobs.encrypted(),
        "web_tls": state.config.web.tls,
    })))
}

#[derive(Deserialize)]
struct BanBody {
    ip: String,
    minutes: Option<u64>,
}

async fn add_ban(AxState(state): AxState<State>, headers: HeaderMap, Json(b): Json<BanBody>) -> R {
    let who = admin(&state, &headers).await?;
    let ip: IpAddr = b.ip.trim().parse().map_err(|_| bad("Enter a valid IP address."))?;
    state.limiter.ban(ip, b.minutes.unwrap_or(60 * 24) * 60, &format!("banned by {}", who.email));
    state.event("warn", "security", &format!("{} banned {ip}", who.email));
    Ok(Json(json!({"ok": true})))
}

async fn remove_ban(AxState(state): AxState<State>, headers: HeaderMap, Path(ip): Path<String>) -> R {
    let who = admin(&state, &headers).await?;
    let ip: IpAddr = ip.parse().map_err(|_| bad("Invalid IP."))?;
    state.limiter.unban(ip);
    state.event("info", "security", &format!("{} lifted the ban on {ip}", who.email));
    Ok(Json(json!({"ok": true})))
}

async fn storage(AxState(state): AxState<State>, headers: HeaderMap) -> R {
    admin(&state, &headers).await?;
    Ok(Json(json!({"storage": storage_summary(&state), "stats": state.db.stats().await?})))
}

#[derive(Deserialize)]
struct TestMessage {
    to: String,
}

async fn test_message(AxState(state): AxState<State>, headers: HeaderMap, Json(b): Json<TestMessage>) -> R {
    let who = admin(&state, &headers).await?;
    let to = normalize_address(&b.to).ok_or_else(|| bad("Enter a valid address."))?;
    let host = state.hostname();
    let date = chrono::Utc::now().to_rfc2822();
    let body = format!(
        "From: Picacho Server <{from}>\r\nTo: <{to}>\r\nSubject: Picacho Server test message\r\nDate: {date}\r\nMessage-ID: <{id}@{host}>\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nThis is a test message from {host}.\r\nIf you can read it, delivery works.\r\n",
        from = who.email,
        id = uuid::Uuid::new_v4().simple(),
    );
    let targets = crate::smtp::delivery::resolve(&state, &to, true).await.map_err(|e| bad(format!("Can't deliver: {e:?}")))?;
    let signed = crate::smtp::delivery::dkim_sign(&state, crate::util::domain_of(&who.email), body.into_bytes()).await;
    for t in targets {
        crate::smtp::deliver_target(&state, &who.email, &signed, t, false).await?;
    }
    state.event("info", "admin", &format!("{} sent a test message to {to}", who.email));
    Ok(Json(json!({"ok": true})))
}


// ------------------------------------------------------------- tokens

async fn openapi() -> Response {
    ([(header::CONTENT_TYPE, "application/json")], include_str!("openapi.json")).into_response()
}

#[derive(Deserialize)]
struct TokenQuery {
    all: Option<bool>,
}

async fn list_tokens(AxState(state): AxState<State>, headers: HeaderMap, Query(q): Query<TokenQuery>) -> R {
    let me = current(&state, &headers).await?;
    let all = q.all.unwrap_or(false) && me.is_admin();
    let tokens = state.db.list_tokens(if all { None } else { Some(me.id) }).await?;
    let accounts = if all { state.db.list_accounts().await? } else { vec![me.clone()] };
    let out: Vec<Value> = tokens
        .into_iter()
        .map(|t| {
            let mut v = serde_json::to_value(&t).unwrap();
            v["account"] = json!(accounts.iter().find(|a| a.id == t.account_id).map(|a| a.email.clone()));
            v
        })
        .collect();
    Ok(Json(json!(out)))
}

#[derive(Deserialize)]
struct NewToken {
    name: String,
    scopes: Vec<String>,
    expires_days: Option<i64>,
    /// Admins may create a token for another account (by id or email).
    account: Option<String>,
}

async fn create_token(AxState(state): AxState<State>, headers: HeaderMap, Json(b): Json<NewToken>) -> R {
    let me = current(&state, &headers).await?;
    let owner = match &b.account {
        Some(k) if me.is_admin() => resolve_account(&state, k).await?,
        Some(_) => return Err(forbidden()),
        None => me.clone(),
    };
    let name = b.name.trim();
    if name.is_empty() || name.len() > 80 {
        return Err(bad("Give the token a name (up to 80 characters)."));
    }
    let mut scopes: Vec<String> = vec![];
    for sc in &b.scopes {
        match sc.as_str() {
            "admin" if !owner.is_admin() => return Err(bad("Only administrators can hold admin tokens.")),
            s if crate::auth::VALID_SCOPES.contains(&s) => {
                if !scopes.contains(sc) {
                    scopes.push(sc.clone())
                }
            }
            _ => return Err(bad(format!("Unknown scope {sc}. Use admin, imap, imap:read, smtp, jmap or jmap:read."))),
        }
    }
    if scopes.is_empty() {
        return Err(bad("Choose at least one scope."));
    }
    let expires = b.expires_days.filter(|d| *d > 0).map(|d| now() + d.min(3650) * 86400);
    let (secret, hash, prefix) = crate::auth::generate_token();
    let id = state.db.create_token(owner.id, name, &hash, &prefix, &scopes.join(","), expires).await?;
    state.event("info", "auth", &format!("{} created API token '{name}' ({}) for {}", me.email, scopes.join(","), owner.email));
    Ok(Json(json!({"id": id, "token": secret, "prefix": prefix, "scopes": scopes, "expires_at": expires})))
}

async fn delete_token(AxState(state): AxState<State>, headers: HeaderMap, Path(id): Path<i64>) -> R {
    let me = current(&state, &headers).await?;
    let scope = if me.is_admin() { None } else { Some(me.id) };
    if !state.db.delete_token(id, scope).await? {
        return Err(not_found());
    }
    state.event("info", "auth", &format!("{} revoked API token #{id}", me.email));
    Ok(Json(json!({"ok": true})))
}

// ------------------------------------------------------------- config.toml

async fn get_config(AxState(state): AxState<State>, headers: HeaderMap) -> R {
    admin(&state, &headers).await?;
    let path = &state.config_path;
    let exists = path.exists();
    let text = if exists { tokio::fs::read_to_string(path).await.unwrap_or_default() } else { String::new() };
    // What the file would be after a reload (it may have been edited since start).
    let on_disk = if exists { crate::config::Config::load(path).ok() } else { Some(crate::config::Config::default()) };
    let writable = if exists {
        std::fs::OpenOptions::new().append(true).open(path).is_ok()
    } else {
        path.parent().map(|p| p.as_os_str().is_empty() || p.exists()).unwrap_or(true)
    };
    Ok(Json(json!({
        "path": std::fs::canonicalize(path).unwrap_or(path.clone()).display().to_string(),
        "exists": exists,
        "writable": writable,
        "toml": text,
        "running": state.config,
        "saved": on_disk,
        "defaults": crate::config::Config::default(),
        "restart_required": state.restart_required.load(std::sync::atomic::Ordering::Relaxed),
    })))
}

async fn write_config(state: &State, text: &str) -> Result<(), ApiError> {
    let path = &state.config_path;
    if path.exists() {
        let bak = path.with_extension("toml.bak");
        tokio::fs::copy(path, &bak).await.map_err(|e| bad(format!("Couldn't back up {}: {e}", path.display())))?;
    } else if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        tokio::fs::create_dir_all(dir).await.map_err(|e| bad(format!("{e}")))?;
    }
    let tmp = path.with_extension("toml.tmp");
    tokio::fs::write(&tmp, text).await.map_err(|e| bad(format!("Couldn't write {}: {e}", tmp.display())))?;
    crate::util::restrict_permissions(&tmp);
    tokio::fs::rename(&tmp, path).await.map_err(|e| bad(format!("Couldn't replace {}: {e}", path.display())))?;
    state.restart_required.store(true, std::sync::atomic::Ordering::Relaxed);
    Ok(())
}

#[derive(Deserialize)]
struct ConfigBody {
    config: Value,
}

async fn put_config(AxState(state): AxState<State>, headers: HeaderMap, Json(b): Json<ConfigBody>) -> R {
    let who = admin(&state, &headers).await?;
    let cfg: crate::config::Config = serde_json::from_value(b.config).map_err(|e| bad(format!("Invalid configuration: {e}")))?;
    let text = cfg.to_minimal_toml().map_err(|e| bad(format!("{e}")))?;
    let header = "# Picacho Server configuration (written by the web console; see config.example.toml).\n";
    write_config(&state, &format!("{header}{text}")).await?;
    state.event("warn", "admin", &format!("{} saved config.toml; restart to apply", who.email));
    Ok(Json(json!({"ok": true, "toml": format!("{header}{text}"), "restart_required": true})))
}

#[derive(Deserialize)]
struct RawConfig {
    toml: String,
}

async fn put_config_raw(AxState(state): AxState<State>, headers: HeaderMap, Json(b): Json<RawConfig>) -> R {
    let who = admin(&state, &headers).await?;
    if b.toml.len() > 256 * 1024 {
        return Err(bad("Configuration is too large."));
    }
    let _: crate::config::Config = toml::from_str(&b.toml).map_err(|e| bad(format!("{e}")))?;
    write_config(&state, &b.toml).await?;
    state.event("warn", "admin", &format!("{} edited config.toml; restart to apply", who.email));
    Ok(Json(json!({"ok": true, "restart_required": true})))
}

async fn restart(AxState(state): AxState<State>, headers: HeaderMap) -> R {
    let who = admin(&state, &headers).await?;
    // Refuse to restart into a configuration that doesn't load.
    if state.config_path.exists() {
        crate::config::Config::load(&state.config_path).map_err(|e| bad(format!("config.toml has errors: {e}")))?;
    }
    state.event("warn", "admin", &format!("{} restarted the server", who.email));
    tokio::spawn(async {
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        crate::util::reexec();
    });
    Ok(Json(json!({"ok": true})))
}

// ------------------------------------------------------------- OAuth consent

fn level_name(a: crate::auth::Access) -> &'static str {
    match a {
        crate::auth::Access::Write => "write",
        crate::auth::Access::Read => "read",
        crate::auth::Access::None => "none",
    }
}

fn level_from(s: &str) -> crate::auth::Access {
    match s {
        "write" => crate::auth::Access::Write,
        "read" => crate::auth::Access::Read,
        _ => crate::auth::Access::None,
    }
}

/// Validate an authorization request for the consent screen.
async fn oauth_request(AxState(state): AxState<State>, headers: HeaderMap, Query(q): Query<std::collections::HashMap<String, String>>) -> R {
    let signed_in = current(&state, &headers).await.ok();
    match crate::oauth::validate_request(&state, &q).await {
        Ok(req) => {
            let host = url::Url::parse(&req.redirect_uri).ok().and_then(|u| u.host_str().map(String::from)).unwrap_or_else(|| req.redirect_uri.clone());
            Ok(Json(json!({
                "client": {"name": req.client.name, "client_id": req.client.client_id, "dynamic": req.client.dynamic},
                "redirect_host": host,
                "requested": req.requested.iter().map(|(k, v)| (k.to_string(), level_name(*v))).collect::<std::collections::HashMap<_, _>>(),
                "account": signed_in.map(|a| json!({"email": a.email, "display_name": a.display_name})),
            })))
        }
        Err(crate::oauth::RequestError::Fatal(m)) => Ok(Json(json!({"fatal": m}))),
        Err(crate::oauth::RequestError::Redirect(u)) => Ok(Json(json!({"redirect": u}))),
    }
}

#[derive(Deserialize)]
struct Approve {
    params: std::collections::HashMap<String, String>,
    #[serde(default)]
    grant: std::collections::HashMap<String, String>,
    #[serde(default)]
    deny: bool,
}

async fn oauth_approve(AxState(state): AxState<State>, headers: HeaderMap, Json(b): Json<Approve>) -> R {
    if bearer(&headers).is_some() {
        return Err(forbidden());
    }
    let me = current(&state, &headers).await?;
    let req = match crate::oauth::validate_request(&state, &b.params).await {
        Ok(r) => r,
        Err(crate::oauth::RequestError::Fatal(m)) => return Err(bad(m)),
        Err(crate::oauth::RequestError::Redirect(u)) => return Ok(Json(json!({"redirect": u}))),
    };
    if b.deny {
        let u = crate::oauth::error_redirect(&req.redirect_uri, "access_denied", "The person declined.", req.state.as_deref());
        return Ok(Json(json!({"redirect": u})));
    }
    let mut levels = std::collections::HashMap::new();
    for svc in crate::oauth::SERVICES {
        let want = level_from(b.grant.get(svc).map(String::as_str).unwrap_or("none"));
        levels.insert(svc, want.min(req.requested[svc]));
    }
    let scopes = crate::oauth::scope_string(&levels);
    if scopes.is_empty() {
        return Err(bad("Allow at least one kind of access, or choose Deny."));
    }
    let url = crate::oauth::issue_code(&state, &req, me.id, &scopes).await?;
    state.event("info", "auth", &format!("{} authorized '{}' ({scopes})", me.email, req.client.name));
    Ok(Json(json!({"redirect": url})))
}

async fn oauth_grants(AxState(state): AxState<State>, headers: HeaderMap, Query(q): Query<TokenQuery>) -> R {
    let me = current(&state, &headers).await?;
    let all = q.all.unwrap_or(false) && me.is_admin();
    Ok(Json(json!(state.db.oauth_grants(if all { None } else { Some(me.id) }).await?)))
}

async fn oauth_revoke_grant(AxState(state): AxState<State>, headers: HeaderMap, Path(family): Path<String>) -> R {
    let me = current(&state, &headers).await?;
    let scope = if me.is_admin() { None } else { Some(me.id) };
    if !state.db.revoke_oauth_family(&family, scope).await? {
        return Err(not_found());
    }
    state.event("info", "auth", &format!("{} revoked an app's access", me.email));
    Ok(Json(json!({"ok": true})))
}

async fn oauth_clients(AxState(state): AxState<State>, headers: HeaderMap) -> R {
    admin(&state, &headers).await?;
    Ok(Json(json!(state.db.list_oauth_clients().await?)))
}

#[derive(Deserialize)]
struct NewClient {
    name: String,
    redirect_uris: Vec<String>,
    #[serde(default)]
    confidential: bool,
    #[serde(default)]
    scopes: Vec<String>,
}

async fn create_oauth_client(AxState(state): AxState<State>, headers: HeaderMap, Json(b): Json<NewClient>) -> R {
    let who = admin(&state, &headers).await?;
    let uris: Vec<String> = b.redirect_uris.iter().map(|u| u.trim().to_string()).filter(|u| !u.is_empty()).collect();
    let (client, secret) = crate::oauth::create_client(&state, &b.name, uris, &b.scopes.join(" "), b.confidential, false).await.map_err(bad)?;
    state.event("info", "admin", &format!("{} registered OAuth client '{}'", who.email, client.name));
    Ok(Json(json!({"client": client, "client_secret": secret})))
}

async fn delete_oauth_client(AxState(state): AxState<State>, headers: HeaderMap, Path(id): Path<String>) -> R {
    let who = admin(&state, &headers).await?;
    if !state.db.delete_oauth_client(&id).await? {
        return Err(not_found());
    }
    state.event("warn", "admin", &format!("{} removed OAuth client {id} and its tokens", who.email));
    Ok(Json(json!({"ok": true})))
}


// ============================================================= audit

/// Record every successful state-changing admin or account API call.
async fn audit_mw(
    AxState(state): AxState<State>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let headers = req.headers().clone();
    let tracked = method != axum::http::Method::GET
        && method != axum::http::Method::HEAD
        && (path.starts_with("/api/admin") || path.starts_with("/api/v1") || path.starts_with("/api/me") || path.starts_with("/api/tokens"));
    let resp = next.run(req).await;
    if tracked && resp.status().is_success() {
        let actor = match current(&state, &headers).await {
            Ok(a) => a.email,
            Err(_) => match bearer(&headers) {
                Some(t) => crate::auth::bearer_principal(&state, t).await.map(|p| format!("{} (oauth)", p.account.email)).unwrap_or_else(|| "token".into()),
                None => "anonymous".into(),
            },
        };
        let ip = client_ip(&state, peer, &headers).to_string();
        let action = format!("{method} {path}");
        crate::ops::audit(&state, &actor, &ip, &action, &path, &Value::Null);
    }
    resp
}

// ============================================================= admin: extensions

fn ext_admin_routes() -> Router<State> {
    Router::new()
        .route("/server", get(server_info))
        .route("/audit", get(audit_log))
        .route("/reports", get(list_reports))
        .route("/filter/bayes", get(bayes_stats))
        .route("/tls", get(tls_status))
        .route("/tls/renew", post(tls_renew))
        .route("/maintenance/{task}", post(run_maintenance))
        .route("/relay/peers", get(list_peers).post(create_peer))
        .route("/relay/peers/{name}", axum::routing::patch(update_peer).delete(delete_peer))
        .route("/dav/principals", get(list_principals).post(create_principal))
        .route("/dav/principals/{name}", get(get_principal).patch(update_principal).delete(delete_principal))
        .route("/accounts/{id}/authorizations", get(list_authorizations).post(create_authorization))
        .route("/accounts/{id}/authorizations/{family}", delete(revoke_authorization))
        .route("/accounts/{id}/sieve", get(admin_list_sieve))
        .route("/accounts/{id}/sieve/{name}", get(admin_get_sieve).put(admin_put_sieve).delete(admin_delete_sieve))
        .route("/accounts/{id}/sieve/{name}/activate", post(admin_activate_sieve))
        .route("/accounts/{id}/vacation", get(admin_get_vacation).put(admin_put_vacation))
        .route("/accounts/{id}/export", get(admin_export))
        .route("/accounts/{id}/import", post(admin_import).layer(axum::extract::DefaultBodyLimit::max(2 * 1024 * 1024 * 1024)))
        .route("/accounts/{id}/migrate", post(admin_migrate))
        .route("/migrations/{id}", get(migration_status))
        .route("/accounts/{id}/dav", get(admin_account_dav))
}

/// Endpoints of this server, for identity providers and provisioning tools.
async fn server_info(AxState(state): AxState<State>, headers: HeaderMap) -> R {
    admin(&state, &headers).await?;
    let base = crate::jmap::base_url(&state, &headers);
    let l = &state.config.listen;
    let addrs = |v: &Vec<SocketAddr>| v.iter().map(|a| a.to_string()).collect::<Vec<_>>();
    Ok(Json(json!({
        "hostname": state.hostname(),
        "version": env!("CARGO_PKG_VERSION"),
        "imap": {"implicit_tls": addrs(&l.imaps), "starttls": addrs(&l.imap)},
        "smtp": {"mx": addrs(&l.smtp), "submission": addrs(&l.submission), "submissions": addrs(&l.submissions)},
        "managesieve": addrs(&l.managesieve),
        "jmap": {"session": format!("{base}/.well-known/jmap"), "api": format!("{base}/jmap/api")},
        "dav": {"root": format!("{base}/dav/"), "caldav": format!("{base}/.well-known/caldav"), "carddav": format!("{base}/.well-known/carddav")},
        "oauth": {
            "metadata": format!("{base}/.well-known/oauth-authorization-server"),
            "token": format!("{base}/oauth/token"),
            "scopes": crate::oauth::SCOPES,
        },
        "account_api": format!("{base}/api/v1/me"),
        "admin_api": format!("{base}/api/v1"),
        "discovery": format!("{base}/.well-known/picacho"),
        "storage": {"dav": state.dav.describe()},
    })))
}

#[derive(Deserialize)]
struct AuditQuery {
    limit: Option<i64>,
    before: Option<i64>,
    actor: Option<String>,
}

async fn audit_log(AxState(state): AxState<State>, headers: HeaderMap, Query(q): Query<AuditQuery>) -> R {
    admin(&state, &headers).await?;
    Ok(Json(json!(crate::ops::list_audit(&state, q.limit.unwrap_or(200), q.before, q.actor.as_deref()).await?)))
}

#[derive(Deserialize)]
struct ReportQuery {
    kind: Option<String>,
    limit: Option<i64>,
}

async fn list_reports(AxState(state): AxState<State>, headers: HeaderMap, Query(q): Query<ReportQuery>) -> R {
    admin(&state, &headers).await?;
    Ok(Json(json!(crate::reports::list(&state, q.kind.as_deref(), q.limit.unwrap_or(100).clamp(1, 1000)).await?)))
}

async fn bayes_stats(AxState(state): AxState<State>, headers: HeaderMap) -> R {
    admin(&state, &headers).await?;
    Ok(Json(state.db.bayes_stats().await?))
}

async fn tls_status(AxState(state): AxState<State>, headers: HeaderMap) -> R {
    admin(&state, &headers).await?;
    Ok(Json(json!({
        "source": *state.tls.source.read(),
        "names": state.tls.names(),
        "expires_in_secs": state.tls.expires_in(),
        "acme": state.config.tls.acme.is_some(),
        "wanted_names": crate::acme::wanted_names(&state).await,
    })))
}

async fn tls_renew(AxState(state): AxState<State>, headers: HeaderMap) -> R {
    admin(&state, &headers).await?;
    match crate::acme::issue(&state).await {
        Ok(m) => Ok(Json(json!({"ok": true, "message": m}))),
        Err(e) => Err(bad(format!("{e:#}"))),
    }
}

async fn run_maintenance(AxState(state): AxState<State>, headers: HeaderMap, Path(task): Path<String>) -> R {
    admin(&state, &headers).await?;
    match task.as_str() {
        "retention" => Ok(Json(json!({"removed": crate::ops::apply_retention(&state).await?}))),
        "sweep" => {
            let (mail, dav) = crate::ops::sweep_orphans(&state).await?;
            Ok(Json(json!({"removed": mail, "removed_dav": dav, "note": "objects are removed on the first sweep after the grace period"})))
        }
        "reports" => {
            crate::reports::run(&state).await;
            Ok(Json(json!({"ok": true})))
        }
        _ => Err(not_found()),
    }
}

// ---------------------------------------------------------------- relay peers

#[derive(Deserialize)]
struct NewPeer {
    name: String,
    #[serde(default)]
    domains: Vec<String>,
}

fn clean_domains(d: &[String]) -> Result<Vec<String>, ApiError> {
    let mut out = vec![];
    for x in d {
        let x = x.trim().trim_end_matches('.').to_ascii_lowercase();
        if !valid_domain(&x) || !x.contains('.') {
            return Err(bad(format!("{x} is not a valid domain.")));
        }
        out.push(x);
    }
    Ok(out)
}

async fn list_peers(AxState(state): AxState<State>, headers: HeaderMap) -> R {
    admin(&state, &headers).await?;
    let mut out = vec![];
    for p in state.db.list_peers().await? {
        let held = state.db.held_count(&p.name).await.unwrap_or(0);
        let mut v = json!(p);
        v["held"] = json!(held);
        out.push(v);
    }
    Ok(Json(json!(out)))
}

async fn create_peer(AxState(state): AxState<State>, headers: HeaderMap, Json(b): Json<NewPeer>) -> R {
    admin(&state, &headers).await?;
    let name = b.name.trim().to_string();
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return Err(bad("Peer names are letters, digits, - and _."));
    }
    if state.db.peer_by_name(&name).await?.is_some() {
        return Err(bad("A peer with that name exists."));
    }
    let domains = clean_domains(&b.domains)?;
    let (peer, token) = state.db.create_peer(&name, &domains).await?;
    // Receive mail for the peer's domains and hold it for pickup.
    for d in &domains {
        match state.db.domain_by_name(d).await? {
            Some(mut dom) => {
                dom.mode = "peer".into();
                dom.transport = name.clone();
                state.db.update_domain(&dom).await?;
            }
            None => {
                state.db.create_domain(d, "peer", &name).await?;
            }
        }
    }
    let mut s = (*state.settings()).clone();
    if !s.relay.accept_downstream {
        s.relay.accept_downstream = true;
        state.save_settings(s).await?;
    }
    Ok(Json(json!({"peer": peer, "token": token, "note": "Give this token to the downstream server; it is shown only once."})))
}

#[derive(Deserialize)]
struct PeerPatch {
    domains: Option<Vec<String>>,
    active: Option<bool>,
}

async fn update_peer(AxState(state): AxState<State>, headers: HeaderMap, Path(name): Path<String>, Json(b): Json<PeerPatch>) -> R {
    admin(&state, &headers).await?;
    let p = state.db.peer_by_name(&name).await?.ok_or_else(not_found)?;
    let domains = match &b.domains {
        Some(d) => clean_domains(d)?,
        None => p.domains.clone(),
    };
    state.db.update_peer(&name, &domains, b.active.unwrap_or(p.active)).await?;
    for d in &domains {
        if state.db.domain_by_name(d).await?.is_none() {
            state.db.create_domain(d, "peer", &name).await?;
        }
    }
    Ok(Json(json!(state.db.peer_by_name(&name).await?)))
}

async fn delete_peer(AxState(state): AxState<State>, headers: HeaderMap, Path(name): Path<String>) -> R {
    admin(&state, &headers).await?;
    if !state.db.delete_peer(&name).await? {
        return Err(not_found());
    }
    Ok(Json(json!({"ok": true, "note": "Domains that pointed at this peer still exist; change or delete them."})))
}

// ---------------------------------------------------------------- DAV principals

#[derive(Deserialize)]
struct NewPrincipal {
    /// Standalone user name (not an email), or the address of a mail account to link.
    username: Option<String>,
    /// Link to this mail account (same sign-in).
    account: Option<String>,
    password: Option<String>,
    #[serde(default)]
    display_name: String,
    #[serde(default)]
    email: String,
    quota_mb: Option<i64>,
}

fn valid_username(u: &str) -> bool {
    !u.is_empty() && u.len() <= 128 && u.chars().all(|c| c.is_ascii_alphanumeric() || "._-@+".contains(c))
}

async fn hash_pw(state: &State, pw: &str) -> Result<String, ApiError> {
    check_password_strength(pw, state.settings().security.password_min_length).map_err(bad)?;
    let p = pw.to_string();
    Ok(tokio::task::spawn_blocking(move || hash_password(&p)).await.map_err(|e| anyhow::anyhow!(e))??)
}

async fn list_principals(AxState(state): AxState<State>, headers: HeaderMap) -> R {
    admin(&state, &headers).await?;
    let mut out = vec![];
    for p in state.db.dav_principals().await? {
        let mut v = json!(p);
        v["has_password"] = json!(!p.password_hash.is_empty());
        v["linked_account"] = match p.account_id {
            Some(id) => json!(state.db.get_account(id).await?.map(|a| a.email)),
            None => Value::Null,
        };
        out.push(v);
    }
    Ok(Json(json!(out)))
}

async fn create_principal(AxState(state): AxState<State>, headers: HeaderMap, Json(b): Json<NewPrincipal>) -> R {
    admin(&state, &headers).await?;
    let quota = b.quota_mb.unwrap_or(state.settings().dav.default_quota_mb as i64).max(0) * 1024 * 1024;
    let id = match &b.account {
        Some(email) => {
            let acc = resolve_account(&state, email).await?;
            if state.db.dav_principal_for_account(acc.id).await?.is_some() {
                return Err(bad("That account already has a DAV principal."));
            }
            let hash = match &b.password {
                Some(p) => hash_pw(&state, p).await?,
                None => String::new(),
            };
            let name = b.username.clone().unwrap_or_else(|| acc.email.clone()).to_ascii_lowercase();
            if !valid_username(&name) || state.db.dav_principal(&name).await?.is_some() {
                return Err(bad("That user name is invalid or taken."));
            }
            let display = if b.display_name.is_empty() { acc.display_name.clone() } else { b.display_name.clone() };
            state.db.create_dav_principal(&name, Some(acc.id), &hash, &display, &acc.email, quota).await?
        }
        None => {
            let Some(name) = b.username.clone().map(|u| u.to_ascii_lowercase()) else { return Err(bad("username or account is required.")) };
            if !valid_username(&name) {
                return Err(bad("User names are letters, digits and . _ - @ +"));
            }
            if state.db.dav_principal(&name).await?.is_some() || state.db.account_by_email(&name).await?.is_some() {
                return Err(bad("That user name is taken."));
            }
            let Some(pw) = &b.password else { return Err(bad("A standalone DAV account needs a password.")) };
            let hash = hash_pw(&state, pw).await?;
            state.db.create_dav_principal(&name, None, &hash, &b.display_name, &b.email, quota).await?
        }
    };
    let p = state.db.dav_principal_by_id(id).await?.ok_or_else(not_found)?;
    crate::dav::ensure_homes(&state, &p).await?;
    Ok(Json(json!(p)))
}

async fn get_principal(AxState(state): AxState<State>, headers: HeaderMap, Path(name): Path<String>) -> R {
    admin(&state, &headers).await?;
    Ok(Json(json!(state.db.dav_principal(&name).await?.ok_or_else(not_found)?)))
}

#[derive(Deserialize)]
struct PrincipalPatch {
    password: Option<String>,
    /// "" removes the DAV-only password.
    #[serde(default)]
    clear_password: bool,
    display_name: Option<String>,
    email: Option<String>,
    quota_mb: Option<i64>,
    active: Option<bool>,
    /// Link to a mail account (email), or "" to unlink (the principal then
    /// needs its own password).
    account: Option<String>,
}

async fn update_principal(AxState(state): AxState<State>, headers: HeaderMap, Path(name): Path<String>, Json(b): Json<PrincipalPatch>) -> R {
    admin(&state, &headers).await?;
    let mut p = state.db.dav_principal(&name).await?.ok_or_else(not_found)?;
    if let Some(pw) = &b.password {
        p.password_hash = hash_pw(&state, pw).await?;
    }
    if b.clear_password {
        p.password_hash.clear();
    }
    if let Some(d) = b.display_name {
        p.display_name = d;
    }
    if let Some(e) = b.email {
        p.email = e;
    }
    if let Some(q) = b.quota_mb {
        p.quota_bytes = q.max(0) * 1024 * 1024;
    }
    if let Some(a) = b.active {
        p.active = a;
    }
    if let Some(acc) = &b.account {
        if acc.is_empty() {
            p.account_id = None;
        } else {
            let a = resolve_account(&state, acc).await?;
            if state.db.dav_principal_for_account(a.id).await?.is_some_and(|x| x.id != p.id) {
                return Err(bad("That account already has a DAV principal."));
            }
            p.account_id = Some(a.id);
        }
    }
    if p.account_id.is_none() && p.password_hash.is_empty() {
        return Err(bad("A DAV account that isn't linked to a mail account needs a password."));
    }
    state.db.update_dav_principal(&p).await?;
    Ok(Json(json!(p)))
}

async fn delete_principal(AxState(state): AxState<State>, headers: HeaderMap, Path(name): Path<String>) -> R {
    admin(&state, &headers).await?;
    let p = state.db.dav_principal(&name).await?.ok_or_else(not_found)?;
    let n = state.db.delete_dav_principal(p.id).await?.len();
    // Objects are removed by the next orphan sweep.
    Ok(Json(json!({"ok": true, "objects": n})))
}

async fn admin_account_dav(AxState(state): AxState<State>, headers: HeaderMap, Path(key): Path<String>) -> R {
    admin(&state, &headers).await?;
    let acc = resolve_account(&state, &key).await?;
    Ok(Json(json!(state.db.dav_principal_for_account(acc.id).await?)))
}

// ---------------------------------------------------------------- authorizations

#[derive(Deserialize)]
struct NewAuthorization {
    /// Space-separated scopes, e.g. "imap jmap smtp account".
    scope: String,
    /// Registered OAuth client the tokens belong to (default: a built-in public client).
    client_id: Option<String>,
}

/// Issue OAuth tokens for an account without a consent screen: how an
/// identity provider or control panel gets mail, DAV and account access
/// on someone's behalf.
async fn create_authorization(AxState(state): AxState<State>, headers: HeaderMap, Path(key): Path<String>, Json(b): Json<NewAuthorization>) -> R {
    let who = admin(&state, &headers).await?;
    let acc = resolve_account(&state, &key).await?;
    if !acc.active {
        return Err(bad("The account is disabled."));
    }
    let v = crate::oauth::admin_authorize(&state, acc.id, b.client_id.as_deref(), &b.scope).await.map_err(bad)?;
    state.event("info", "auth", &format!("{} issued an authorization for {} ({})", who.email, acc.email, v["scope"].as_str().unwrap_or("")));
    Ok(Json(v))
}

async fn list_authorizations(AxState(state): AxState<State>, headers: HeaderMap, Path(key): Path<String>) -> R {
    admin(&state, &headers).await?;
    let acc = resolve_account(&state, &key).await?;
    Ok(Json(json!(state.db.oauth_grants(Some(acc.id)).await?)))
}

async fn revoke_authorization(AxState(state): AxState<State>, headers: HeaderMap, Path((key, family)): Path<(String, String)>) -> R {
    admin(&state, &headers).await?;
    let acc = resolve_account(&state, &key).await?;
    if !state.db.revoke_oauth_family(&family, Some(acc.id)).await? {
        return Err(not_found());
    }
    Ok(Json(json!({"ok": true})))
}

// ---------------------------------------------------------------- sieve & vacation (shared by admin and /me)

async fn sieve_list(state: &State, acc: i64) -> R {
    Ok(Json(json!(state.db.sieve_scripts(acc).await?)))
}

async fn sieve_get(state: &State, acc: i64, name: &str) -> R {
    Ok(Json(json!(state.db.sieve_script(acc, name).await?.ok_or_else(not_found)?)))
}

#[derive(Deserialize)]
struct SievePut {
    content: String,
    #[serde(default)]
    activate: bool,
}

async fn sieve_put(state: &State, acc: i64, name: &str, b: &SievePut) -> R {
    if !crate::sieve::valid_name(name) {
        return Err(bad("Invalid script name."));
    }
    crate::sieve::check(&b.content).map_err(bad)?;
    if state.db.sieve_script(acc, name).await?.is_none() && state.db.sieve_count(acc).await? >= crate::sieve::MAX_SCRIPTS {
        return Err(bad("Too many scripts."));
    }
    state.db.sieve_put(acc, name, &b.content).await?;
    if b.activate {
        state.db.sieve_activate(acc, Some(name)).await?;
    }
    sieve_get(state, acc, name).await
}

async fn sieve_delete(state: &State, acc: i64, name: &str) -> R {
    if !state.db.sieve_delete(acc, name).await? {
        return Err(not_found());
    }
    Ok(Json(json!({"ok": true})))
}

#[derive(Deserialize, Default)]
struct Activate {
    #[serde(default = "yes")]
    active: bool,
}

async fn sieve_activate(state: &State, acc: i64, name: &str, active: bool) -> R {
    let ok = state.db.sieve_activate(acc, if active { Some(name) } else { None }).await?;
    if !ok {
        return Err(not_found());
    }
    Ok(Json(json!({"ok": true})))
}

#[derive(Deserialize)]
struct VacationBody {
    enabled: bool,
    subject: Option<String>,
    text_body: Option<String>,
    html_body: Option<String>,
    from_date: Option<i64>,
    to_date: Option<i64>,
    days: Option<i64>,
}

async fn vacation_put(state: &State, acc: i64, b: VacationBody) -> R {
    let v = crate::sieve::VacationSettings {
        enabled: b.enabled,
        subject: b.subject.filter(|s| !s.is_empty()),
        text_body: b.text_body,
        html_body: b.html_body,
        from_date: b.from_date,
        to_date: b.to_date,
        days: b.days.unwrap_or(7).clamp(1, 365),
    };
    state.db.set_vacation(acc, &v).await?;
    Ok(Json(json!(state.db.vacation(acc).await?)))
}

async fn admin_list_sieve(AxState(state): AxState<State>, headers: HeaderMap, Path(key): Path<String>) -> R {
    admin(&state, &headers).await?;
    let a = resolve_account(&state, &key).await?;
    sieve_list(&state, a.id).await
}
async fn admin_get_sieve(AxState(state): AxState<State>, headers: HeaderMap, Path((key, name)): Path<(String, String)>) -> R {
    admin(&state, &headers).await?;
    let a = resolve_account(&state, &key).await?;
    sieve_get(&state, a.id, &name).await
}
async fn admin_put_sieve(AxState(state): AxState<State>, headers: HeaderMap, Path((key, name)): Path<(String, String)>, Json(b): Json<SievePut>) -> R {
    admin(&state, &headers).await?;
    let a = resolve_account(&state, &key).await?;
    sieve_put(&state, a.id, &name, &b).await
}
async fn admin_delete_sieve(AxState(state): AxState<State>, headers: HeaderMap, Path((key, name)): Path<(String, String)>) -> R {
    admin(&state, &headers).await?;
    let a = resolve_account(&state, &key).await?;
    sieve_delete(&state, a.id, &name).await
}
async fn admin_activate_sieve(AxState(state): AxState<State>, headers: HeaderMap, Path((key, name)): Path<(String, String)>, body: Option<Json<Activate>>) -> R {
    admin(&state, &headers).await?;
    let a = resolve_account(&state, &key).await?;
    sieve_activate(&state, a.id, &name, body.map(|b| b.active).unwrap_or(true)).await
}
async fn admin_get_vacation(AxState(state): AxState<State>, headers: HeaderMap, Path(key): Path<String>) -> R {
    admin(&state, &headers).await?;
    let a = resolve_account(&state, &key).await?;
    Ok(Json(json!(state.db.vacation(a.id).await?)))
}
async fn admin_put_vacation(AxState(state): AxState<State>, headers: HeaderMap, Path(key): Path<String>, Json(b): Json<VacationBody>) -> R {
    admin(&state, &headers).await?;
    let a = resolve_account(&state, &key).await?;
    vacation_put(&state, a.id, b).await
}

// ---------------------------------------------------------------- export / import / migrate

async fn export_response(state: &State, acc: &Account) -> Result<Response, ApiError> {
    let dir = state.config.data_path("tmp");
    std::fs::create_dir_all(&dir).map_err(|e| anyhow::anyhow!(e))?;
    let path = dir.join(format!("export-{}.zip", uuid::Uuid::new_v4().simple()));
    crate::ops::export_account(state, acc.id, &path).await?;
    let data = tokio::fs::read(&path).await.map_err(|e| anyhow::anyhow!(e))?;
    let _ = tokio::fs::remove_file(&path).await;
    Ok((
        [
            (header::CONTENT_TYPE, "application/zip".to_string()),
            (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{}.zip\"", acc.email.replace(['"', '/'], "_"))),
        ],
        data,
    )
        .into_response())
}

async fn admin_export(AxState(state): AxState<State>, headers: HeaderMap, Path(key): Path<String>) -> Result<Response, ApiError> {
    admin(&state, &headers).await?;
    let a = resolve_account(&state, &key).await?;
    export_response(&state, &a).await
}

#[derive(Deserialize)]
struct ImportQuery {
    folder: Option<String>,
}

async fn admin_import(AxState(state): AxState<State>, headers: HeaderMap, Path(key): Path<String>, Query(q): Query<ImportQuery>, body: axum::body::Bytes) -> R {
    admin(&state, &headers).await?;
    let a = resolve_account(&state, &key).await?;
    let stats = crate::ops::import_account(&state, a.id, body.to_vec(), q.folder.as_deref().unwrap_or("Imported")).await?;
    Ok(Json(json!(stats)))
}

async fn admin_migrate(AxState(state): AxState<State>, headers: HeaderMap, Path(key): Path<String>, Json(b): Json<crate::ops::MigrateRequest>) -> R {
    admin(&state, &headers).await?;
    let a = resolve_account(&state, &key).await?;
    let id = crate::ops::start_migration(&state, a.id, b);
    Ok(Json(json!({"id": id})))
}

async fn migration_status(AxState(state): AxState<State>, headers: HeaderMap, Path(id): Path<String>) -> R {
    let me = current(&state, &headers).await?;
    let m = crate::ops::MIGRATIONS.get(&id).map(|m| m.clone()).ok_or_else(not_found)?;
    if !me.is_admin() && m.account_id != me.id {
        return Err(not_found());
    }
    Ok(Json(json!(m)))
}

// ============================================================= account self-service (/api/v1/me)

/// The signed-in account for self-service: console session, an API token
/// with the `account` scope, or an OAuth token with `account` /
/// `account:read`. Writes need write access.
async fn me_account(state: &State, headers: &HeaderMap, write: bool) -> Result<Account, ApiError> {
    if let Some(t) = bearer(headers) {
        let p = crate::auth::bearer_principal(state, t).await.ok_or_else(|| ApiError(StatusCode::UNAUTHORIZED, "Invalid or expired token.".into()))?;
        let lvl = crate::auth::access(&p.scopes, crate::auth::Service::Account);
        let admin_token = !p.oauth && p.scopes.split([',', ' ']).any(|s| s == "admin");
        let need = if write { crate::auth::Access::Write } else { crate::auth::Access::Read };
        if lvl < need && !admin_token {
            return Err(ApiError(StatusCode::FORBIDDEN, "This token lacks the account scope.".into()));
        }
        return Ok(p.account);
    }
    current(state, headers).await
}

fn me_routes() -> Router<State> {
    Router::new()
        .route("/", get(me_get).patch(me_patch))
        .route("/addresses", get(me_addresses))
        .route("/sieve", get(me_list_sieve))
        .route("/sieve/{name}", get(me_get_sieve).put(me_put_sieve).delete(me_delete_sieve))
        .route("/sieve/{name}/activate", post(me_activate_sieve))
        .route("/vacation", get(me_get_vacation).put(me_put_vacation))
        .route("/app-passwords", get(me_list_tokens).post(me_create_token))
        .route("/app-passwords/{id}", delete(me_delete_token))
        .route("/dav", get(me_dav).put(me_dav_password))
        .route("/export", get(me_export))
        .route("/migrate", post(me_migrate))
        .route("/servers", get(me_servers))
}

async fn me_get(AxState(state): AxState<State>, headers: HeaderMap) -> R {
    let a = me_account(&state, &headers, false).await?;
    let mut v = account_json(&a);
    v["vacation"] = json!(state.db.vacation(a.id).await?);
    v["active_sieve"] = json!(state.db.sieve_active(a.id).await?.map(|s| s.name));
    Ok(Json(v))
}

#[derive(Deserialize)]
struct MePatch {
    display_name: Option<String>,
    forward_to: Option<String>,
    keep_copy: Option<bool>,
}

async fn me_patch(AxState(state): AxState<State>, headers: HeaderMap, Json(b): Json<MePatch>) -> R {
    let mut a = me_account(&state, &headers, true).await?;
    if let Some(d) = b.display_name {
        if d.chars().count() > 200 || d.chars().any(|c| c.is_control()) {
            return Err(bad("Display name is too long or has control characters."));
        }
        a.display_name = d;
    }
    if let Some(f) = b.forward_to {
        a.forward_to = if f.trim().is_empty() { String::new() } else { clean_destinations(&f)? };
    }
    if let Some(k) = b.keep_copy {
        a.keep_copy = k;
    }
    state.db.update_account(&a).await?;
    Ok(Json(account_json(&a)))
}

async fn me_addresses(AxState(state): AxState<State>, headers: HeaderMap) -> R {
    let a = me_account(&state, &headers, false).await?;
    let aliases: Vec<String> = state
        .db
        .list_aliases()
        .await?
        .into_iter()
        .filter(|x| x.active && x.destination.split([',', ' ']).any(|d| d.trim().eq_ignore_ascii_case(&a.email)))
        .map(|x| x.source)
        .collect();
    Ok(Json(json!({"primary": a.email, "aliases": aliases, "plus_addressing": true})))
}

async fn me_list_sieve(AxState(state): AxState<State>, headers: HeaderMap) -> R {
    let a = me_account(&state, &headers, false).await?;
    sieve_list(&state, a.id).await
}
async fn me_get_sieve(AxState(state): AxState<State>, headers: HeaderMap, Path(name): Path<String>) -> R {
    let a = me_account(&state, &headers, false).await?;
    sieve_get(&state, a.id, &name).await
}
async fn me_put_sieve(AxState(state): AxState<State>, headers: HeaderMap, Path(name): Path<String>, Json(b): Json<SievePut>) -> R {
    let a = me_account(&state, &headers, true).await?;
    sieve_put(&state, a.id, &name, &b).await
}
async fn me_delete_sieve(AxState(state): AxState<State>, headers: HeaderMap, Path(name): Path<String>) -> R {
    let a = me_account(&state, &headers, true).await?;
    sieve_delete(&state, a.id, &name).await
}
async fn me_activate_sieve(AxState(state): AxState<State>, headers: HeaderMap, Path(name): Path<String>, body: Option<Json<Activate>>) -> R {
    let a = me_account(&state, &headers, true).await?;
    sieve_activate(&state, a.id, &name, body.map(|b| b.active).unwrap_or(true)).await
}
async fn me_get_vacation(AxState(state): AxState<State>, headers: HeaderMap) -> R {
    let a = me_account(&state, &headers, false).await?;
    Ok(Json(json!(state.db.vacation(a.id).await?)))
}
async fn me_put_vacation(AxState(state): AxState<State>, headers: HeaderMap, Json(b): Json<VacationBody>) -> R {
    let a = me_account(&state, &headers, true).await?;
    vacation_put(&state, a.id, b).await
}

async fn me_list_tokens(AxState(state): AxState<State>, headers: HeaderMap) -> R {
    let a = me_account(&state, &headers, false).await?;
    Ok(Json(json!(state.db.list_tokens(Some(a.id)).await?)))
}

#[derive(Deserialize)]
struct MeToken {
    name: String,
    /// Default: "mail jmap dav sieve" (an app password for every protocol).
    #[serde(default)]
    scopes: Vec<String>,
    expires_days: Option<i64>,
}

async fn me_create_token(AxState(state): AxState<State>, headers: HeaderMap, Json(b): Json<MeToken>) -> R {
    let a = me_account(&state, &headers, true).await?;
    let scopes: Vec<String> = if b.scopes.is_empty() { vec!["mail".into(), "jmap".into(), "dav".into(), "sieve".into()] } else { b.scopes.clone() };
    for s in &scopes {
        if !crate::auth::VALID_SCOPES.contains(&s.as_str()) || s == "admin" {
            return Err(bad(format!("Scope {s} isn't allowed here.")));
        }
    }
    if b.name.trim().is_empty() || b.name.len() > 100 {
        return Err(bad("Give the app password a name."));
    }
    let (secret, hash, prefix) = crate::auth::generate_token();
    let exp = b.expires_days.filter(|d| *d > 0).map(|d| now() + d * 86400);
    let id = state.db.create_token(a.id, b.name.trim(), &hash, &prefix, &scopes.join(" "), exp).await?;
    Ok(Json(json!({"id": id, "token": secret, "scopes": scopes, "note": "Shown only once."})))
}

async fn me_delete_token(AxState(state): AxState<State>, headers: HeaderMap, Path(id): Path<i64>) -> R {
    let a = me_account(&state, &headers, true).await?;
    if !state.db.delete_token(id, Some(a.id)).await? {
        return Err(not_found());
    }
    Ok(Json(json!({"ok": true})))
}

async fn me_dav(AxState(state): AxState<State>, headers: HeaderMap) -> R {
    let a = me_account(&state, &headers, false).await?;
    let p = crate::dav::principal_for_account(&state, &a).await?;
    let base = crate::jmap::base_url(&state, &headers);
    Ok(Json(json!({
        "principal": p.as_ref().map(|p| json!({"username": p.username, "quota_bytes": p.quota_bytes, "used_bytes": p.used_bytes, "has_dav_password": !p.password_hash.is_empty()})),
        "urls": {"caldav": format!("{base}/dav/calendars/{}/", p.as_ref().map(|p| p.username.clone()).unwrap_or_default()), "carddav": format!("{base}/dav/addressbooks/{}/", p.as_ref().map(|p| p.username.clone()).unwrap_or_default()), "webdav": format!("{base}/dav/files/{}/", p.as_ref().map(|p| p.username.clone()).unwrap_or_default())},
    })))
}

#[derive(Deserialize)]
struct DavPassword {
    /// A separate password for calendar/contacts/files apps; null removes it.
    password: Option<String>,
}

async fn me_dav_password(AxState(state): AxState<State>, headers: HeaderMap, Json(b): Json<DavPassword>) -> R {
    let a = me_account(&state, &headers, true).await?;
    let mut p = crate::dav::principal_for_account(&state, &a).await?.ok_or_else(|| bad("Calendars and contacts aren't enabled for this account."))?;
    p.password_hash = match &b.password {
        Some(pw) => hash_pw(&state, pw).await?,
        None => String::new(),
    };
    state.db.update_dav_principal(&p).await?;
    Ok(Json(json!({"ok": true})))
}

async fn me_export(AxState(state): AxState<State>, headers: HeaderMap) -> Result<Response, ApiError> {
    let a = me_account(&state, &headers, false).await?;
    export_response(&state, &a).await
}

async fn me_migrate(AxState(state): AxState<State>, headers: HeaderMap, Json(b): Json<crate::ops::MigrateRequest>) -> R {
    let a = me_account(&state, &headers, true).await?;
    Ok(Json(json!({"id": crate::ops::start_migration(&state, a.id, b)})))
}

async fn me_servers(AxState(state): AxState<State>, headers: HeaderMap) -> R {
    let a = me_account(&state, &headers, false).await?;
    let mut v = client_info(&state, &a.email);
    let base = crate::jmap::base_url(&state, &headers);
    v["jmap"] = json!(format!("{base}/.well-known/jmap"));
    v["dav"] = json!(format!("{base}/dav/"));
    v["managesieve"] = json!({"host": state.hostname(), "port": state.config.listen.managesieve.first().map(|x| x.port()).unwrap_or(4190)});
    v["autoconfig"] = json!(format!("{base}/.well-known/autoconfig/mail/config-v1.1.xml?emailaddress={}", a.email));
    v["apple_profile"] = json!(format!("{base}/.well-known/picacho/mobileconfig?email={}", a.email));
    Ok(Json(v))
}
