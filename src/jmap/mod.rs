//! JMAP (RFC 8620 core, RFC 8621 mail, RFC 9425 quota).
//!
//! Endpoints: `/.well-known/jmap` (session), `/jmap/api`, `/jmap/upload/{account}`,
//! `/jmap/download/{account}/{blob}/{name}`, `/jmap/eventsource`.
//! Authentication: HTTP Basic (account password or app token) or
//! `Authorization: Bearer` with a token holding the `jmap` scope. GETs also
//! accept a console session cookie (EventSource can't send headers); POSTs
//! never do, so cookies can't be used for cross-site requests.
mod blob;
mod dav;
mod extra;
mod mail;
mod submission;
mod ws;
mod rest;

use crate::db::Account;
use crate::state::State;
use axum::body::{Body, Bytes};
use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, Query, State as AxState};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::net::SocketAddr;

pub const CORE: &str = "urn:ietf:params:jmap:core";
pub const MAIL: &str = "urn:ietf:params:jmap:mail";
pub const SUBMISSION: &str = "urn:ietf:params:jmap:submission";
pub const QUOTA: &str = "urn:ietf:params:jmap:quota";
pub const VACATION: &str = "urn:ietf:params:jmap:vacationresponse";
pub const SIEVE: &str = "urn:ietf:params:jmap:sieve";
pub const BLOB: &str = "urn:ietf:params:jmap:blob";
pub const MDN: &str = "urn:ietf:params:jmap:mdn";
pub const WEBSOCKET: &str = "urn:ietf:params:jmap:websocket";
pub const CALENDARS: &str = "urn:ietf:params:jmap:calendars";
pub const CONTACTS: &str = "urn:ietf:params:jmap:contacts";
pub const PRINCIPALS: &str = "urn:ietf:params:jmap:principals";
/// RFC 9670 section 2.2: Principal/getAvailability.
pub const PRINCIPALS_AVAILABILITY: &str = "urn:ietf:params:jmap:principals:availability";
/// Capabilities a request may name in `using`.
const KNOWN: [&str; 13] =
    [CORE, MAIL, SUBMISSION, QUOTA, VACATION, SIEVE, BLOB, MDN, WEBSOCKET, CALENDARS, CONTACTS, PRINCIPALS, PRINCIPALS_AVAILABILITY];
const MAX_CALLS: usize = 64;
const MAX_REQUEST: usize = 10 * 1024 * 1024;
pub const MAX_OBJECTS: usize = 1000;

pub fn routes(state: State) -> Router {
    let upload_limit = state.settings().limits.max_message_bytes as usize + 1024;
    let jmap = Router::new()
        .route("/.well-known/jmap", get(session))
        .route("/jmap/session", get(session))
        .route("/jmap/api", post(api).layer(DefaultBodyLimit::max(MAX_REQUEST)))
        .route("/jmap/upload/{account}", post(upload).layer(DefaultBodyLimit::max(upload_limit)))
        .route("/jmap/upload/{account}/", post(upload).layer(DefaultBodyLimit::max(upload_limit)))
        .route("/jmap/download/{account}/{blob}/{name}", get(download))
        .route("/jmap/eventsource", get(eventsource))
        .route("/jmap/ws", get(ws::upgrade))
        .with_state(state.clone());
    // The Pinal Mail REST API sits on the same engine.
    jmap.merge(rest::routes(state))
}

fn problem(status: StatusCode, kind: &str, detail: &str) -> Response {
    let body = json!({"type": kind, "status": status.as_u16(), "detail": detail});
    (status, [(header::CONTENT_TYPE, "application/problem+json")], body.to_string()).into_response()
}

fn unauthorized() -> Response {
    let mut r = problem(StatusCode::UNAUTHORIZED, "about:blank", "Authentication required.");
    r.headers_mut().insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Basic realm=\"Picacho Server\", charset=\"UTF-8\""));
    r
}

fn secure(state: &State, headers: &HeaderMap, peer: SocketAddr) -> bool {
    let sec = state.settings().security.clone();
    state.config.web.tls
        || headers.get("x-forwarded-proto").and_then(|v| v.to_str().ok()) == Some("https")
            && crate::util::ip_in_list(peer.ip(), &state.config.web.trusted_proxies)
        || !sec.require_tls_for_auth
        || (sec.allow_plaintext_localhost && crate::util::is_loopback(peer.ip()))
}

/// Authenticate a JMAP request. `allow_cookie` for GET endpoints only.
async fn authenticate(state: &State, headers: &HeaderMap, peer: SocketAddr, allow_cookie: bool) -> Result<Account, Response> {
    authenticate_access(state, headers, peer, allow_cookie).await.map(|x| x.0)
}

/// Like `authenticate`, also returning the access level (read-only tokens).
async fn authenticate_access(
    state: &State,
    headers: &HeaderMap,
    peer: SocketAddr,
    allow_cookie: bool,
) -> Result<(Account, crate::auth::Access), Response> {
    use crate::auth::{access, Access, Service};
    let auth = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).unwrap_or("");
    if let Some(t) = auth.strip_prefix("Bearer ").map(str::trim) {
        return match crate::auth::bearer_principal(state, t).await {
            Some(p) => match access(&p.scopes, Service::Jmap) {
                Access::None => Err(problem(StatusCode::FORBIDDEN, "about:blank", "This token doesn't grant JMAP access.")),
                lvl => Ok((p.account, lvl)),
            },
            None => {
                let mut r = unauthorized();
                let c = crate::resource::challenge(state, &base_url(state, headers), Some("invalid_token"));
                if let Ok(v) = HeaderValue::from_str(&c) {
                    r.headers_mut().insert(header::WWW_AUTHENTICATE, v);
                }
                Err(r)
            }
        };
    }
    if let Some(b) = auth.strip_prefix("Basic ") {
        if !secure(state, headers, peer) {
            return Err(problem(StatusCode::FORBIDDEN, "about:blank", "Basic authentication requires HTTPS."));
        }
        let decoded = base64::engine::general_purpose::STANDARD.decode(b.trim()).map_err(|_| unauthorized())?;
        let s = String::from_utf8_lossy(&decoded).to_string();
        let (user, pass) = s.split_once(':').ok_or_else(unauthorized)?;
        return match crate::auth::login_service(state, user, pass, peer.ip(), Service::Jmap).await {
            Ok(x) => Ok(x),
            Err(crate::auth::AuthError::PasswordDisabled) => {
                Err(problem(StatusCode::FORBIDDEN, "about:blank", "Account passwords are turned off; use an app password or OAuth."))
            }
            Err(crate::auth::AuthError::Banned) => Err(problem(StatusCode::TOO_MANY_REQUESTS, "about:blank", "Too many failed logins.")),
            Err(_) => Err(unauthorized()),
        };
    }
    if allow_cookie {
        if let Some(c) = headers.get(header::COOKIE).and_then(|v| v.to_str().ok()) {
            if let Some(tok) = c.split(';').find_map(|x| x.trim().strip_prefix("pm_session=")) {
                if let Ok(Some(id)) = state.db.session_account(&crate::util::sha256_hex(tok.as_bytes())).await {
                    if let Ok(Some(a)) = state.db.get_account(id).await {
                        if a.active {
                            return Ok((a, Access::Write));
                        }
                    }
                }
            }
        }
    }
    Err(unauthorized())
}

pub fn account_id(a: &Account) -> String {
    format!("a{}", a.id)
}

pub fn base_url(state: &State, headers: &HeaderMap) -> String {
    if let Some(u) = &state.config.web.public_url {
        return u.trim_end_matches('/').to_string();
    }
    let host = headers.get(header::HOST).and_then(|v| v.to_str().ok()).unwrap_or("localhost");
    let scheme = if state.config.web.tls || headers.get("x-forwarded-proto").and_then(|v| v.to_str().ok()) == Some("https") {
        "https"
    } else {
        "http"
    };
    format!("{scheme}://{host}")
}

async fn session(AxState(state): AxState<State>, ConnectInfo(peer): ConnectInfo<SocketAddr>, headers: HeaderMap) -> Response {
    let a = match authenticate(&state, &headers, peer, true).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    let base = base_url(&state, &headers);
    let id = account_id(&a);
    let max_upload = state.settings().limits.max_message_bytes;
    let jstate = state.db.jmap_state(a.id).await.unwrap_or(0);
    Json(json!({
        "capabilities": {
            CORE: {
                "maxSizeUpload": max_upload,
                "maxConcurrentUpload": 4,
                "maxSizeRequest": MAX_REQUEST,
                "maxConcurrentRequests": 8,
                "maxCallsInRequest": MAX_CALLS,
                "maxObjectsInGet": MAX_OBJECTS,
                "maxObjectsInSet": MAX_OBJECTS,
                "collationAlgorithms": ["i;ascii-casemap", "i;unicode-casemap"],
            },
            MAIL: {},
            SUBMISSION: {},
            QUOTA: {},
            VACATION: {},
            SIEVE: {"implementation": "Picacho Server"},
            BLOB: {},
            MDN: {},
            WEBSOCKET: {"url": ws_url(&base), "supportsPush": true},
            CALENDARS: {},
            CONTACTS: {},
            PRINCIPALS: {},
            PRINCIPALS_AVAILABILITY: {},
        },
        "accounts": {
            id.clone(): {
                "name": a.email,
                "isPersonal": true,
                "isReadOnly": false,
                "accountCapabilities": {
                    MAIL: {
                        "maxMailboxesPerEmail": 1,
                        "maxMailboxDepth": 32,
                        "maxSizeMailboxName": 255,
                        "maxSizeAttachmentsPerEmail": max_upload,
                        "emailQuerySortOptions": ["receivedAt", "sentAt", "size", "from", "to", "subject", "hasKeyword"],
                        "mayCreateTopLevelMailbox": true,
                    },
                    SUBMISSION: submission_caps(&state),
                    QUOTA: {},
                    VACATION: {},
                    BLOB: {
                        "maxSizeBlobSet": max_upload,
                        "maxDataSources": blob::MAX_DATA_SOURCES,
                        "supportedTypeNames": ["Email", "Thread", "Mailbox"],
                        "supportedDigestAlgorithms": ["sha", "sha-256"],
                    },
                    MDN: {},
                    CALENDARS: {"maxCalendarsPerEvent": 1, "minDateTime": "1970-01-01T00:00:00", "maxDateTime": "2200-01-01T00:00:00",
                        "maxExpandedQueryDuration": "P400D", "maxParticipantsPerEvent": 1000, "mayCreateCalendar": true},
                    CONTACTS: {"maxAddressBooksPerCard": 1, "mayCreateAddressBook": true},
                    PRINCIPALS: {"currentUserPrincipalId": format!("P{}", a.id)},
                    // Principal/getAvailability takes at most 370 days.
                    PRINCIPALS_AVAILABILITY: {"maxAvailabilityDuration": "P370D"},
                    SIEVE: {
                        "maxSizeScriptName": 128,
                        "maxSizeScript": crate::sieve::MAX_SCRIPT_BYTES,
                        "maxNumberScripts": crate::sieve::MAX_SCRIPTS,
                        "maxNumberRedirects": 8,
                        "sieveExtensions": crate::sieve::parse::EXTENSIONS,
                        "notificationMethods": null,
                        "externalLists": null,
                    },
                },
            },
        },
        "primaryAccounts": {MAIL: id, SUBMISSION: id, QUOTA: id, CORE: id, VACATION: id, SIEVE: id, BLOB: id, MDN: id, CALENDARS: id, CONTACTS: id, PRINCIPALS: id, PRINCIPALS_AVAILABILITY: id},
        "username": a.email,
        "apiUrl": format!("{base}/jmap/api"),
        "downloadUrl": format!("{base}/jmap/download/{{accountId}}/{{blobId}}/{{name}}?type={{type}}"),
        "uploadUrl": format!("{base}/jmap/upload/{{accountId}}/"),
        "eventSourceUrl": format!("{base}/jmap/eventsource?types={{types}}&closeafter={{closeafter}}&ping={{ping}}"),
        "state": jstate.to_string(),
    }))
    .into_response()
}

/// `wss://` (or `ws://` for local http) for the WebSocket endpoint.
fn ws_url(base: &str) -> String {
    let rest = base.strip_prefix("https://").map(|r| format!("wss://{r}")).or_else(|| base.strip_prefix("http://").map(|r| format!("ws://{r}")));
    format!("{}/jmap/ws", rest.unwrap_or_else(|| base.to_string()))
}

/// The submission capability: holding for later (FUTURERELEASE) and the
/// envelope parameters EmailSubmission accepts.
fn submission_caps(state: &State) -> Value {
    let hold = crate::submit::max_hold_secs(state);
    let mut ext = serde_json::Map::new();
    ext.insert("DSN".into(), json!([]));
    ext.insert("REQUIRETLS".into(), json!([]));
    ext.insert("DELIVERBY".into(), json!(["60"]));
    ext.insert("MT-PRIORITY".into(), json!(["MIXER"]));
    ext.insert("SIZE".into(), json!([state.settings().limits.max_message_bytes.to_string()]));
    if hold > 0 {
        let until = chrono::Utc::now() + chrono::Duration::seconds(hold);
        ext.insert("FUTURERELEASE".into(), json!([hold.to_string(), until.format("%Y-%m-%dT%H:%M:%SZ").to_string()]));
    }
    json!({"maxDelayedSend": hold, "submissionExtensions": ext})
}

/// A method error (`["error", {...}, callId]`).
#[derive(Debug)]
pub struct MethodError(pub &'static str, pub String);

impl MethodError {
    pub fn invalid(d: impl Into<String>) -> Self {
        MethodError("invalidArguments", d.into())
    }
}

impl From<anyhow::Error> for MethodError {
    fn from(e: anyhow::Error) -> Self {
        tracing::error!("jmap: {e:#}");
        MethodError("serverFail", "Internal error.".into())
    }
}

pub struct Ctx {
    pub state: State,
    pub account: Account,
    /// Creation id -> server id, shared by every method in the request.
    pub created: HashMap<String, String>,
    pub using: Vec<String>,
    /// `jmap:read` tokens may not change anything.
    pub read_only: bool,
}

impl Ctx {
    /// Resolve `#creationId` references.
    pub fn id(&self, s: &str) -> String {
        match s.strip_prefix('#') {
            Some(c) => self.created.get(c).cloned().unwrap_or_else(|| s.to_string()),
            None => s.to_string(),
        }
    }

    pub fn check_account(&self, args: &Value) -> Result<(), MethodError> {
        match args.get("accountId").and_then(|v| v.as_str()) {
            Some(a) if a == account_id(&self.account) => Ok(()),
            Some(_) => Err(MethodError("accountNotFound", "No such account.".into())),
            None => Err(MethodError::invalid("accountId is required")),
        }
    }
}

/// Evaluate a JSON Pointer with JMAP's `*` (map over arrays, flattening).
fn pointer(v: &Value, path: &str) -> Option<Value> {
    if path.is_empty() || path == "/" {
        return Some(v.clone());
    }
    let mut parts = path.trim_start_matches('/').splitn(2, '/');
    let head = parts.next()?.replace("~1", "/").replace("~0", "~");
    let rest = parts.next().map(|r| format!("/{r}")).unwrap_or_default();
    match v {
        Value::Array(arr) if head == "*" => {
            let mut out = vec![];
            for x in arr {
                match pointer(x, &rest)? {
                    Value::Array(inner) if !rest.is_empty() => out.extend(inner),
                    other => out.push(other),
                }
            }
            Some(Value::Array(out))
        }
        Value::Array(arr) => pointer(arr.get(head.parse::<usize>().ok()?)?, &rest),
        Value::Object(o) => pointer(o.get(&head)?, &rest),
        _ => None,
    }
}

/// Replace `#arg: {resultOf, name, path}` with the referenced values.
fn resolve_refs(args: &mut Map<String, Value>, responses: &[Value]) -> Result<(), MethodError> {
    let keys: Vec<String> = args.keys().filter(|k| k.starts_with('#')).cloned().collect();
    for k in keys {
        let r = args.remove(&k).unwrap();
        let (Some(of), Some(name), Some(path)) =
            (r.get("resultOf").and_then(|v| v.as_str()), r.get("name").and_then(|v| v.as_str()), r.get("path").and_then(|v| v.as_str()))
        else {
            return Err(MethodError("invalidResultReference", "Malformed result reference.".into()));
        };
        let src = responses
            .iter()
            .find(|resp| resp[2].as_str() == Some(of) && resp[0].as_str() == Some(name))
            .ok_or_else(|| MethodError("invalidResultReference", format!("No {name} result for {of}.")))?;
        let v = pointer(&src[1], path).ok_or_else(|| MethodError("invalidResultReference", format!("Path {path} not found.")))?;
        let plain = k.trim_start_matches('#').to_string();
        if args.contains_key(&plain) {
            return Err(MethodError::invalid(format!("{plain} given twice")));
        }
        args.insert(plain, v);
    }
    Ok(())
}

async fn api(
    AxState(state): AxState<State>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let (account, level) = match authenticate_access(&state, &headers, peer, false).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    let req: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return problem(StatusCode::BAD_REQUEST, "urn:ietf:params:jmap:error:notJSON", &e.to_string()),
    };
    match process(&state, account, level, &req).await {
        Ok(out) => Json(out).into_response(),
        Err((kind, detail)) => problem(StatusCode::BAD_REQUEST, kind, &detail),
    }
}

/// Run a JMAP request object (HTTP POST or a WebSocket Request). An error
/// is a request-level problem: (type, detail).
pub async fn process(state: &State, account: Account, level: crate::auth::Access, req: &Value) -> Result<Value, (&'static str, String)> {
    let (Some(using), Some(calls)) = (req.get("using").and_then(|v| v.as_array()), req.get("methodCalls").and_then(|v| v.as_array())) else {
        return Err(("urn:ietf:params:jmap:error:notRequest", "using and methodCalls are required".into()));
    };
    let using: Vec<String> = using.iter().filter_map(|u| u.as_str().map(String::from)).collect();
    for u in &using {
        if !KNOWN.contains(&u.as_str()) {
            return Err(("urn:ietf:params:jmap:error:unknownCapability", format!("Unknown capability {u}")));
        }
    }
    if calls.len() > MAX_CALLS {
        return Err(("urn:ietf:params:jmap:error:limit", "Too many method calls".into()));
    }
    let mut ctx = Ctx { state: state.clone(), account, created: HashMap::new(), using, read_only: level == crate::auth::Access::Read };
    if let Some(c) = req.get("createdIds").and_then(|v| v.as_object()) {
        for (k, v) in c {
            if let Some(v) = v.as_str() {
                ctx.created.insert(k.clone(), v.to_string());
            }
        }
    }
    let mut responses: Vec<Value> = vec![];
    for call in calls {
        let (Some(name), Some(args), Some(call_id)) = (call.get(0).and_then(|v| v.as_str()), call.get(1), call.get(2).and_then(|v| v.as_str())) else {
            return Err(("urn:ietf:params:jmap:error:notRequest", "Malformed method call".into()));
        };
        let mut args = match args.as_object() {
            Some(o) => o.clone(),
            None => {
                responses.push(json!(["error", {"type": "invalidArguments"}, call_id]));
                continue;
            }
        };
        if let Err(e) = resolve_refs(&mut args, &responses) {
            responses.push(json!(["error", {"type": e.0, "description": e.1}, call_id]));
            continue;
        }
        let args = Value::Object(args);
        match mail::call(&mut ctx, name, &args).await {
            Ok(outs) => {
                for (n, v) in outs {
                    responses.push(json!([n, v, call_id]));
                }
            }
            Err(e) => responses.push(json!(["error", {"type": e.0, "description": e.1}, call_id])),
        }
    }
    let session_state = state.db.jmap_state(ctx.account.id).await.unwrap_or(0).to_string();
    let mut out = json!({"methodResponses": responses, "sessionState": session_state});
    if req.get("createdIds").is_some() {
        out["createdIds"] = json!(ctx.created);
    }
    Ok(out)
}

async fn upload(
    AxState(state): AxState<State>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(account): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let a = match authenticate(&state, &headers, peer, false).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    if account != account_id(&a) {
        return problem(StatusCode::NOT_FOUND, "about:blank", "No such account.");
    }
    let ctype = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .chars()
        .take(200)
        .collect::<String>();
    let key = match state.blobs.put_message(&body).await {
        Ok(k) => k,
        Err(e) => {
            tracing::error!("upload: {e:#}");
            return problem(StatusCode::INTERNAL_SERVER_ERROR, "about:blank", "Storage error.");
        }
    };
    let id = match state.db.add_upload(a.id, &key, body.len() as i64, &ctype).await {
        Ok(id) => id,
        Err(e) => {
            tracing::error!("upload: {e:#}");
            return problem(StatusCode::INTERNAL_SERVER_ERROR, "about:blank", "Storage error.");
        }
    };
    (StatusCode::CREATED, Json(json!({"accountId": account, "blobId": format!("u{id}"), "type": ctype, "size": body.len()}))).into_response()
}

#[derive(serde::Deserialize)]
struct DownloadQuery {
    #[serde(rename = "type")]
    ctype: Option<String>,
}

async fn download(
    AxState(state): AxState<State>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path((account, blob, name)): Path<(String, String, String)>,
    Query(q): Query<DownloadQuery>,
    headers: HeaderMap,
) -> Response {
    let a = match authenticate(&state, &headers, peer, true).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    if account != account_id(&a) {
        return problem(StatusCode::NOT_FOUND, "about:blank", "No such account.");
    }
    let data = match mail::blob_bytes(&state, &a, &blob).await {
        Ok(Some(d)) => d,
        Ok(None) => return problem(StatusCode::NOT_FOUND, "about:blank", "Blob not found."),
        Err(e) => {
            tracing::error!("download: {e:#}");
            return problem(StatusCode::INTERNAL_SERVER_ERROR, "about:blank", "Storage error.");
        }
    };
    let ctype = q
        .ctype
        .filter(|t| t.len() < 128 && t.chars().all(|c| c.is_ascii_graphic() && c != ';' && c != '"'))
        .unwrap_or_else(|| "application/octet-stream".into());
    let safe_name: String = name.chars().filter(|c| !c.is_control() && *c != '"' && *c != '\\').take(200).collect();
    Response::builder()
        .header(header::CONTENT_TYPE, ctype)
        // Always a download, never rendered in the console's origin.
        .header(header::CONTENT_DISPOSITION, format!("attachment; filename=\"{safe_name}\""))
        .header("content-security-policy", "sandbox; default-src 'none'")
        .header(header::CACHE_CONTROL, "private, immutable, max-age=31536000")
        .body(Body::from(data))
        .unwrap()
}

#[derive(serde::Deserialize)]
struct EventQuery {
    ping: Option<u64>,
    closeafter: Option<String>,
    /// Comma-separated type names, or "*" (RFC 8620 7.3).
    types: Option<String>,
}

/// Every type a StateChange can name.
const PUSH_TYPES: &[&str] = &["Email", "Mailbox", "Thread", "EmailDelivery", "EmailSubmission", "Identity", "Calendar", "CalendarEvent", "AddressBook", "ContactCard"];

/// The StateChange `changed` map for one account. Contacts states carry the
/// directory's (see jmap/dav.rs); `wanted` limits the types (None: all).
pub(crate) fn push_types(st: i64, dir: Option<i64>, wanted: Option<&[String]>) -> serde_json::Map<String, Value> {
    let mut m = serde_json::Map::new();
    for t in PUSH_TYPES {
        if wanted.is_some_and(|w| !w.iter().any(|x| x == t)) {
            continue;
        }
        let v = match (dir, *t) {
            (Some(d), "AddressBook" | "ContactCard") => format!("{st}.{d}"),
            _ => st.to_string(),
        };
        m.insert(t.to_string(), json!(v));
    }
    m
}

async fn eventsource(
    AxState(state): AxState<State>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Query(q): Query<EventQuery>,
    headers: HeaderMap,
) -> Response {
    let a = match authenticate(&state, &headers, peer, true).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    let ping = q.ping.filter(|p| *p > 0).map(|p| p.clamp(5, 300));
    let close_after_state = q.closeafter.as_deref() == Some("state");
    let wanted: Option<Vec<String>> = q.types.as_deref().map(str::trim).filter(|t| !t.is_empty() && *t != "*").map(|t| t.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect());
    let start = state.db.jmap_state(a.id).await.unwrap_or(0);
    let wants_contacts = wanted.as_ref().is_none_or(|w| w.iter().any(|t| t == "AddressBook" || t == "ContactCard"));
    let dir_start = if wants_contacts && state.settings().directory.enabled && crate::directory::refresh(&state, &a).await.is_ok() { state.db.directory_state(a.id).await.ok() } else { None };
    struct S {
        state: State,
        account: crate::db::Account,
        last: i64,
        dir: Option<i64>,
        wanted: Option<Vec<String>>,
        wants_contacts: bool,
        ticks: u64,
        ping: Option<u64>,
        done: bool,
        close_after_state: bool,
        first: bool,
    }
    let init = S { state, account: a, last: start, dir: dir_start, wanted, wants_contacts, ticks: 0, ping, done: false, close_after_state, first: true };
    let stream = futures::stream::unfold(init, |mut s| async move {
        if s.done {
            return None;
        }
        if s.first {
            s.first = false;
            return Some((Ok::<_, std::convert::Infallible>(Bytes::from_static(b": picacho\n\n")), s));
        }
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            s.ticks += 1;
            let now = s.state.db.jmap_state(s.account.id).await.unwrap_or(s.last);
            // The directory changes when other people do; look every few seconds.
            let mut dir = s.dir;
            if s.wants_contacts && s.state.settings().directory.enabled && s.ticks.is_multiple_of(5) && crate::directory::refresh(&s.state, &s.account).await.is_ok() {
                dir = s.state.db.directory_state(s.account.id).await.ok();
            }
            if !s.state.settings().directory.enabled {
                dir = None;
            }
            if now != s.last || dir != s.dir {
                s.last = now;
                s.dir = dir;
                let acc = account_id(&s.account);
                let changed = push_types(now, dir, s.wanted.as_deref());
                if changed.is_empty() {
                    continue;
                }
                let ev = json!({"@type": "StateChange", "changed": {acc: changed}});
                if s.close_after_state {
                    s.done = true;
                }
                return Some((Ok(Bytes::from(format!("event: state\ndata: {ev}\n\n"))), s));
            }
            if let Some(p) = s.ping {
                if s.ticks % p == 0 {
                    return Some((Ok(Bytes::from(format!("event: ping\ndata: {{\"interval\":{p}}}\n\n"))), s));
                }
            }
        }
    });
    Response::builder()
        .header(header::CONTENT_TYPE, "text/event-stream")
        .header(header::CACHE_CONTROL, "no-cache")
        .body(Body::from_stream(stream))
        .unwrap()
}
