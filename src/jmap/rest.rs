//! The Pinal Mail REST API (`/v1/mail/*`), as documented in the Pinal
//! Developers portal: a small JSON layer over the JMAP engine, so both see
//! the same mailboxes, flags and changes.
//!
//! Authentication is `Authorization: Bearer` only: an access token from the
//! identity provider (its capability scopes are checked per operation) or a
//! local API token (`jmap` covers every operation, `jmap:read` reading, and
//! `smtp`/`mail` sending). No cookies, so it is safe to call cross-origin.
//!
//! Labels are folders: a message has exactly one folder label (`inbox`,
//! `sent`, `drafts`, `trash`, `junk`, `archive`, or a custom folder's id),
//! plus `starred` when it is flagged.
use super::{account_id, mail, Ctx, CORE, MAIL, SUBMISSION};
use crate::state::State;
use axum::body::Body;
use axum::extract::{Path, Query, State as AxState};
use axum::http::{header, HeaderMap, HeaderValue, Method, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use base64::Engine;
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::collections::HashMap;

const ROLES: [&str; 6] = ["inbox", "sent", "drafts", "trash", "junk", "archive"];

pub fn routes(state: State) -> Router {
    Router::new()
        .route("/v1/mail/labels", get(labels))
        .route("/v1/mail/messages", get(list).post(send))
        .route("/v1/mail/messages/{id}", get(get_one).patch(patch))
        .route("/v1/mail/drafts", axum::routing::post(draft))
        .layer(middleware::from_fn(cors))
        .with_state(state)
}

/// Bearer-only, so any origin may call it.
async fn cors(req: Request<Body>, next: Next) -> Response {
    let preflight = req.method() == Method::OPTIONS;
    let mut r = if preflight {
        StatusCode::NO_CONTENT.into_response()
    } else {
        next.run(req).await
    };
    let h = r.headers_mut();
    h.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    h.insert(
        header::ACCESS_CONTROL_EXPOSE_HEADERS,
        HeaderValue::from_static("WWW-Authenticate"),
    );
    if preflight {
        h.insert(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static("GET, POST, PATCH, OPTIONS"),
        );
        h.insert(
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_static("Authorization, Content-Type"),
        );
        h.insert(
            header::ACCESS_CONTROL_MAX_AGE,
            HeaderValue::from_static("600"),
        );
    }
    r
}

fn err(status: StatusCode, code: &str, desc: impl Into<String>) -> Response {
    (
        status,
        Json(json!({"error": code, "error_description": desc.into()})),
    )
        .into_response()
}

fn bad(desc: impl Into<String>) -> Response {
    err(StatusCode::BAD_REQUEST, "invalid_request", desc)
}

type Res = Result<Response, Response>;

/// The caller: a JMAP context for their account and what they may do.
struct Caller {
    ctx: Ctx,
    scopes: String,
    external: bool,
}

impl Caller {
    /// Whether the credential carries a Pinal capability scope.
    fn grants(&self, scope: &str) -> bool {
        let has = |x: &str| self.scopes.split([',', ' ']).any(|s| s == x);
        if self.external {
            return has(scope);
        }
        match scope {
            "mail.read" | "mail.metadata" => has("jmap") || has("jmap:read"),
            "mail.send" => has("jmap") || has("smtp") || has("mail"),
            _ => has("jmap"),
        }
    }
}

async fn caller(state: &State, headers: &HeaderMap, any_of: &[&str]) -> Result<Caller, Response> {
    let base = super::base_url(state, headers);
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            v.strip_prefix("Bearer ")
                .or_else(|| v.strip_prefix("bearer "))
        })
        .map(str::trim);
    let unauthorized = |e: Option<&str>, desc: &str| {
        let mut r = err(
            StatusCode::UNAUTHORIZED,
            e.unwrap_or("invalid_request"),
            desc,
        );
        if let Ok(v) = HeaderValue::from_str(&crate::resource::challenge(state, &base, e)) {
            r.headers_mut().insert(header::WWW_AUTHENTICATE, v);
        }
        r
    };
    let Some(token) = token else {
        return Err(unauthorized(
            None,
            "Send an access token in the Authorization header.",
        ));
    };
    let Some(p) = crate::auth::bearer_principal(state, token).await else {
        return Err(unauthorized(
            Some("invalid_token"),
            "The access token is invalid, expired or revoked.",
        ));
    };
    let c = Caller {
        ctx: Ctx {
            state: state.clone(),
            account: p.account,
            created: HashMap::new(),
            using: vec![CORE.into(), MAIL.into(), SUBMISSION.into()],
            read_only: false,
        },
        scopes: p.scopes,
        external: p.external,
    };
    if !any_of.iter().any(|s| c.grants(s)) {
        return Err(err(
            StatusCode::FORBIDDEN,
            "insufficient_scope",
            format!("Requires {}", any_of.join(" or ")),
        ));
    }
    Ok(c)
}

/// Run one JMAP method and return its response arguments.
async fn jmap(ctx: &mut Ctx, name: &str, mut args: Value) -> Result<Value, Response> {
    args["accountId"] = json!(account_id(&ctx.account));
    match mail::call(ctx, name, &args).await {
        Ok(mut out) if !out.is_empty() => Ok(out.remove(0).1),
        Ok(_) => Err(err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "No response.",
        )),
        Err(e) if e.0 == "serverFail" => {
            Err(err(StatusCode::INTERNAL_SERVER_ERROR, "server_error", e.1))
        }
        Err(e) => Err(bad(e.1)),
    }
}

/// The first error in a `/set` response's notCreated / notUpdated map.
fn set_failure(v: &Value, key: &str) -> Option<Response> {
    let m = v.get(key)?.as_object()?;
    let (_, e) = m.iter().next()?;
    let desc = e
        .get("description")
        .and_then(|d| d.as_str())
        .unwrap_or("The change was refused.");
    let status = match e.get("type").and_then(|t| t.as_str()) {
        Some("notFound") => StatusCode::NOT_FOUND,
        Some("forbiddenFrom" | "forbiddenMailFrom" | "forbidden") => StatusCode::FORBIDDEN,
        Some("overQuota") => StatusCode::INSUFFICIENT_STORAGE,
        _ => StatusCode::BAD_REQUEST,
    };
    Some(err(status, "invalid_request", desc))
}

// ------------------------------------------------------------------ labels

struct Folders {
    /// (jmap id, label id, name, role, unread)
    list: Vec<(String, String, String, Option<String>, i64)>,
}

impl Folders {
    async fn load(ctx: &mut Ctx) -> Result<Self, Response> {
        let v = jmap(
            ctx,
            "Mailbox/get",
            json!({"ids": null, "properties": ["id", "name", "role", "unreadEmails"]}),
        )
        .await?;
        let list = v["list"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(|m| {
                let id = m["id"].as_str().unwrap_or("").to_string();
                let role = m["role"].as_str().map(String::from);
                let label = match &role {
                    Some(r) if ROLES.contains(&r.as_str()) => r.clone(),
                    _ => id.clone(),
                };
                (
                    id,
                    label,
                    m["name"].as_str().unwrap_or("").to_string(),
                    role,
                    m["unreadEmails"].as_i64().unwrap_or(0),
                )
            })
            .collect();
        Ok(Folders { list })
    }

    fn mailbox(&self, label: &str) -> Option<&str> {
        self.list
            .iter()
            .find(|f| f.1.eq_ignore_ascii_case(label) || f.0 == label)
            .map(|f| f.0.as_str())
    }

    fn label_of(&self, mailbox: &str) -> Option<&str> {
        self.list
            .iter()
            .find(|f| f.0 == mailbox)
            .map(|f| f.1.as_str())
    }
}

async fn labels(AxState(state): AxState<State>, headers: HeaderMap) -> Res {
    let mut c = caller(
        &state,
        &headers,
        &["mail.labels", "mail.metadata", "mail.read"],
    )
    .await?;
    let f = Folders::load(&mut c.ctx).await?;
    let mut out: Vec<Value> = f
        .list
        .iter()
        .map(|(_, label, name, role, unread)| {
            json!({"id": label, "name": name, "system": role.as_deref().is_some_and(|r| ROLES.contains(&r)), "unread": unread, "color": null})
        })
        .collect();
    let starred = jmap(
        &mut c.ctx,
        "Email/query",
        json!({"filter": {"hasKeyword": "$flagged"}, "calculateTotal": true, "limit": 0}),
    )
    .await?;
    out.push(json!({"id": "starred", "name": "Starred", "system": true, "unread": starred["total"].as_i64().unwrap_or(0), "color": null}));
    Ok(Json(json!({"labels": out})).into_response())
}

// ------------------------------------------------------------------ messages

fn addr(v: &Value) -> Value {
    json!({"name": v.get("name").cloned().unwrap_or(Value::Null), "email": v.get("email").cloned().unwrap_or(json!(""))})
}

fn addrs(v: &Value) -> Value {
    Value::Array(
        v.as_array()
            .map(|a| a.iter().map(addr).collect())
            .unwrap_or_default(),
    )
}

/// A JMAP Email as a REST Message. `full` adds bodies and attachments.
fn message(e: &Value, folders: &Folders, with_snippet: bool, full: bool) -> Value {
    let kw = |k: &str| {
        e["keywords"]
            .get(k)
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    };
    let mut labels: Vec<Value> = e["mailboxIds"]
        .as_object()
        .map(|m| {
            m.keys()
                .filter_map(|id| folders.label_of(id))
                .map(|l| json!(l))
                .collect()
        })
        .unwrap_or_default();
    if kw("$flagged") {
        labels.push(json!("starred"));
    }
    let mut m = json!({
        "id": e["id"],
        "thread_id": e["threadId"],
        "from": e["from"].as_array().and_then(|a| a.first()).map(addr).unwrap_or(Value::Null),
        "to": addrs(&e["to"]),
        "cc": addrs(&e["cc"]),
        "subject": e["subject"].as_str().unwrap_or(""),
        "labels": labels,
        "read": kw("$seen"),
        "date": e["receivedAt"],
    });
    if with_snippet {
        m["snippet"] = json!(e["preview"].as_str().unwrap_or(""));
    }
    if full {
        let body = |key: &str, ctype: &str| -> String {
            e[key]
                .as_array()
                .map(|parts| {
                    parts
                        .iter()
                        .filter(|p| p["type"].as_str() == Some(ctype))
                        .filter_map(|p| p["partId"].as_str())
                        .filter_map(|id| e["bodyValues"][id]["value"].as_str())
                        .collect::<Vec<_>>()
                        .join("\n")
                })
                .unwrap_or_default()
        };
        m["text"] = json!(body("textBody", "text/plain"));
        m["html"] = json!(body("htmlBody", "text/html"));
        m["attachments"] = Value::Array(
            e["attachments"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .map(|p| json!({"id": p["blobId"], "filename": p["name"], "size": p["size"], "content_type": p["type"]}))
                        .collect()
                })
                .unwrap_or_default(),
        );
    } else {
        m["has_attachments"] = json!(e["hasAttachment"].as_bool().unwrap_or(false));
    }
    m
}

const LIST_PROPS: [&str; 10] = [
    "id",
    "threadId",
    "mailboxIds",
    "keywords",
    "from",
    "to",
    "cc",
    "subject",
    "receivedAt",
    "hasAttachment",
];

async fn fetch(c: &mut Caller, ids: &[String], full: bool) -> Result<Vec<Value>, Response> {
    let with_body = c.grants("mail.read");
    let mut props: Vec<&str> = LIST_PROPS.to_vec();
    if with_body {
        props.push("preview");
    }
    if full {
        props.extend(["textBody", "htmlBody", "attachments", "bodyValues"]);
    }
    let v = jmap(
        &mut c.ctx,
        "Email/get",
        json!({"ids": ids, "properties": props, "fetchTextBodyValues": full, "fetchHTMLBodyValues": full, "maxBodyValueBytes": 4 * 1024 * 1024}),
    )
    .await?;
    let mut by_id: HashMap<String, Value> = v["list"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|e| (e["id"].as_str().unwrap_or("").to_string(), e))
        .collect();
    Ok(ids.iter().filter_map(|id| by_id.remove(id)).collect())
}

/// Split a search like `from:sam "trail map" has:attachment` into terms.
fn terms(q: &str) -> Vec<String> {
    let mut out = vec![];
    let mut cur = String::new();
    let mut quoted = false;
    for ch in q.chars() {
        match ch {
            '"' => quoted = !quoted,
            c if c.is_whitespace() && !quoted => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Search syntax (as in Picacho's search bar): `from:`, `to:`, `subject:`,
/// `label:`/`in:`, `has:attachment`, `is:unread|read|starred`,
/// `before:`/`after:` (YYYY-MM-DD) and free text. Without `mail.read`, free
/// text matches senders, recipients and subjects only, never bodies.
fn search_filter(q: &str, folders: &Folders, bodies: bool) -> Result<Vec<Value>, Response> {
    let day = |s: &str| {
        chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d")
            .map(|d| format!("{d}T00:00:00Z"))
            .map_err(|_| bad(format!("Use YYYY-MM-DD dates, not {s}")))
    };
    let mut conds = vec![];
    for t in terms(q) {
        let (k, v) = t
            .split_once(':')
            .map(|(k, v)| (k.to_ascii_lowercase(), v.to_string()))
            .unwrap_or((String::new(), t.clone()));
        let c = match (k.as_str(), v.to_ascii_lowercase().as_str()) {
            ("from", _) => json!({"from": v}),
            ("to", _) => json!({"to": v}),
            ("cc", _) => json!({"cc": v}),
            ("subject", _) => json!({"subject": v}),
            ("has", "attachment") => json!({"hasAttachment": true}),
            ("is", "unread") => json!({"notKeyword": "$seen"}),
            ("is", "read") => json!({"hasKeyword": "$seen"}),
            ("is", "starred") => json!({"hasKeyword": "$flagged"}),
            ("label" | "in", "starred") => json!({"hasKeyword": "$flagged"}),
            ("label" | "in", _) => {
                json!({"inMailbox": folders.mailbox(&v).ok_or_else(|| bad(format!("No label {v}")))?})
            }
            ("before", _) => json!({"before": day(&v)?}),
            ("after", _) => json!({"after": day(&v)?}),
            _ if bodies => json!({"text": t}),
            _ => {
                json!({"operator": "OR", "conditions": [{"from": t}, {"to": t}, {"cc": t}, {"subject": t}]})
            }
        };
        conds.push(c);
    }
    Ok(conds)
}

#[derive(Deserialize)]
struct ListQuery {
    label: Option<String>,
    q: Option<String>,
    limit: Option<i64>,
    cursor: Option<String>,
}

fn encode_cursor(pos: i64) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(format!("p{pos}"))
}

fn decode_cursor(c: &str) -> Option<i64> {
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(c)
        .ok()?;
    String::from_utf8(raw)
        .ok()?
        .strip_prefix('p')?
        .parse()
        .ok()
        .filter(|n: &i64| *n >= 0)
}

async fn list(
    AxState(state): AxState<State>,
    headers: HeaderMap,
    Query(q): Query<ListQuery>,
) -> Res {
    let mut c = caller(&state, &headers, &["mail.metadata", "mail.read"]).await?;
    let folders = Folders::load(&mut c.ctx).await?;
    let limit = q.limit.unwrap_or(25);
    if !(1..=100).contains(&limit) {
        return Err(bad("limit must be between 1 and 100"));
    }
    let position = match q.cursor.as_deref() {
        Some(cur) => decode_cursor(cur).ok_or_else(|| bad("Unknown cursor"))?,
        None => 0,
    };
    let mut conds = search_filter(
        q.q.as_deref().unwrap_or(""),
        &folders,
        c.grants("mail.read"),
    )?;
    match q.label.as_deref() {
        Some("starred") => conds.push(json!({"hasKeyword": "$flagged"})),
        Some(l) => conds.push(json!({"inMailbox": folders.mailbox(l).ok_or_else(|| err(StatusCode::NOT_FOUND, "not_found", format!("No label {l}")))?})),
        // Everything but Trash and Junk.
        None => {
            let hidden: Vec<&str> =
                folders.list.iter().filter(|f| matches!(f.3.as_deref(), Some("trash" | "junk"))).map(|f| f.0.as_str()).collect();
            if !hidden.is_empty() {
                conds.push(json!({"inMailboxOtherThan": hidden}));
            }
        }
    }
    let filter = json!({"operator": "AND", "conditions": conds});
    let v = jmap(
        &mut c.ctx,
        "Email/query",
        json!({"filter": filter, "sort": [{"property": "receivedAt", "isAscending": false}], "position": position, "limit": limit + 1}),
    )
    .await?;
    let mut ids: Vec<String> = v["ids"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|x| x.as_str().map(String::from))
        .collect();
    let more = ids.len() as i64 > limit;
    ids.truncate(limit as usize);
    let snip = c.grants("mail.read");
    let msgs: Vec<Value> = fetch(&mut c, &ids, false)
        .await?
        .iter()
        .map(|e| message(e, &folders, snip, false))
        .collect();
    Ok(Json(
        json!({"messages": msgs, "next_cursor": more.then(|| encode_cursor(position + limit))}),
    )
    .into_response())
}

async fn get_one(
    AxState(state): AxState<State>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Res {
    let mut c = caller(&state, &headers, &["mail.read"]).await?;
    let folders = Folders::load(&mut c.ctx).await?;
    let e = fetch(&mut c, std::slice::from_ref(&id), true).await?;
    let e = e
        .first()
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "not_found", "No such message."))?;
    Ok(Json(message(e, &folders, true, true)).into_response())
}

#[derive(Deserialize)]
struct Patch {
    #[serde(default)]
    add_labels: Vec<String>,
    #[serde(default)]
    remove_labels: Vec<String>,
    read: Option<bool>,
}

async fn patch(
    AxState(state): AxState<State>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(b): Json<Patch>,
) -> Res {
    let mut c = caller(&state, &headers, &["mail.labels"]).await?;
    let folders = Folders::load(&mut c.ctx).await?;
    let cur = fetch(&mut c, std::slice::from_ref(&id), false).await?;
    let cur = cur
        .first()
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "not_found", "No such message."))?;
    let current: Vec<String> = cur["mailboxIds"]
        .as_object()
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();
    let mut upd = Map::new();
    let star = |l: &str| l.eq_ignore_ascii_case("starred");
    let mut targets = vec![];
    for l in b.add_labels.iter().filter(|l| !star(l)) {
        targets.push(
            folders
                .mailbox(l)
                .ok_or_else(|| bad(format!("No label {l}")))?
                .to_string(),
        );
    }
    if targets.len() > 1 {
        return Err(bad("A message has one folder label at a time."));
    }
    for l in b.remove_labels.iter().filter(|l| !star(l)) {
        let mb = folders
            .mailbox(l)
            .ok_or_else(|| bad(format!("No label {l}")))?;
        // Taking a message out of its folder archives it, as mail apps do.
        if current.iter().any(|m| m == mb) && targets.is_empty() {
            let archive = folders
                .list
                .iter()
                .find(|f| f.3.as_deref() == Some("archive"))
                .map(|f| f.0.clone());
            match archive {
                Some(a) if a != mb => targets.push(a),
                _ => {
                    return Err(bad(format!(
                        "Move the message to another label instead of removing {l}."
                    )))
                }
            }
        }
    }
    if let Some(t) = targets.first() {
        upd.insert("mailboxIds".into(), json!({t.clone(): true}));
    }
    if b.add_labels.iter().any(|l| star(l)) {
        upd.insert("keywords/$flagged".into(), json!(true));
    }
    if b.remove_labels.iter().any(|l| star(l)) {
        upd.insert("keywords/$flagged".into(), Value::Null);
    }
    if let Some(r) = b.read {
        upd.insert(
            "keywords/$seen".into(),
            if r { json!(true) } else { Value::Null },
        );
    }
    if !upd.is_empty() {
        let v = jmap(
            &mut c.ctx,
            "Email/set",
            json!({"update": {id.clone(): upd}}),
        )
        .await?;
        if let Some(r) = set_failure(&v, "notUpdated") {
            return Err(r);
        }
    }
    let e = fetch(&mut c, std::slice::from_ref(&id), false).await?;
    let snip = c.grants("mail.read");
    Ok(Json(message(&e[0], &folders, snip, false)).into_response())
}

#[derive(Deserialize)]
struct Outgoing {
    to: Vec<Value>,
    #[serde(default)]
    cc: Vec<Value>,
    #[serde(default)]
    bcc: Vec<Value>,
    subject: String,
    text: Option<String>,
    html: Option<String>,
    in_reply_to: Option<String>,
}

/// A JMAP Email creation object for an outgoing message in `mailbox`.
async fn compose(
    c: &mut Caller,
    b: &Outgoing,
    mailbox: &str,
    keywords: Value,
) -> Result<Value, Response> {
    let clean = |v: &[Value]| -> Result<Vec<Value>, Response> {
        v.iter()
            .map(|a| {
                let email = a
                    .get("email")
                    .and_then(|e| e.as_str())
                    .and_then(crate::util::normalize_address)
                    .ok_or_else(|| bad("Every recipient needs a valid email"))?;
                Ok(json!({"name": a.get("name").and_then(|n| n.as_str()), "email": email}))
            })
            .collect()
    };
    let (to, cc, bcc) = (clean(&b.to)?, clean(&b.cc)?, clean(&b.bcc)?);
    if to.len() + cc.len() + bcc.len() > 100 {
        return Err(bad("At most 100 recipients."));
    }
    let a = &c.ctx.account;
    let from = json!([{"name": (!a.display_name.is_empty()).then(|| a.display_name.clone()), "email": a.email}]);
    let mut e = json!({
        "mailboxIds": {mailbox: true},
        "keywords": keywords,
        "from": from,
        "to": to,
        "subject": b.subject,
        "bodyValues": {},
    });
    if !cc.is_empty() {
        e["cc"] = json!(cc);
    }
    if !bcc.is_empty() {
        e["bcc"] = json!(bcc);
    }
    if let Some(t) = &b.text {
        e["bodyValues"]["t"] = json!({"value": t});
        e["textBody"] = json!([{"partId": "t", "type": "text/plain"}]);
    }
    if let Some(h) = &b.html {
        e["bodyValues"]["h"] = json!({"value": h});
        e["htmlBody"] = json!([{"partId": "h", "type": "text/html"}]);
    }
    if b.text.is_none() && b.html.is_none() {
        e["bodyValues"]["t"] = json!({"value": ""});
        e["textBody"] = json!([{"partId": "t", "type": "text/plain"}]);
    }
    if let Some(r) = &b.in_reply_to {
        let v = jmap(
            &mut c.ctx,
            "Email/get",
            json!({"ids": [r], "properties": ["messageId", "references", "subject"]}),
        )
        .await?;
        let orig = v["list"].get(0).ok_or_else(|| {
            err(
                StatusCode::NOT_FOUND,
                "not_found",
                "in_reply_to: no such message.",
            )
        })?;
        if let Some(mid) = orig["messageId"].as_array().filter(|a| !a.is_empty()) {
            let mut refs: Vec<Value> = orig["references"].as_array().cloned().unwrap_or_default();
            refs.extend(mid.iter().cloned());
            e["inReplyTo"] = json!(mid);
            e["references"] = json!(refs);
        }
    }
    Ok(e)
}

fn folder(folders: &Folders, role: &str) -> Result<String, Response> {
    folders
        .list
        .iter()
        .find(|f| f.3.as_deref() == Some(role))
        .map(|f| f.0.clone())
        .ok_or_else(|| {
            err(
                StatusCode::CONFLICT,
                "invalid_request",
                format!("This mailbox has no {role} folder."),
            )
        })
}

async fn create_email(c: &mut Caller, e: Value) -> Result<String, Response> {
    let v = jmap(&mut c.ctx, "Email/set", json!({"create": {"m": e}})).await?;
    if let Some(r) = set_failure(&v, "notCreated") {
        return Err(r);
    }
    v["created"]["m"]["id"]
        .as_str()
        .map(String::from)
        .ok_or_else(|| {
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Not created.",
            )
        })
}

async fn send(AxState(state): AxState<State>, headers: HeaderMap, Json(b): Json<Outgoing>) -> Res {
    let mut c = caller(&state, &headers, &["mail.send"]).await?;
    if b.to.is_empty() {
        return Err(bad("Add at least one recipient in to."));
    }
    let folders = Folders::load(&mut c.ctx).await?;
    let sent = folder(&folders, "sent")?;
    let e = compose(&mut c, &b, &sent, json!({"$seen": true})).await?;
    let id = create_email(&mut c, e).await?;
    let identity = format!("i{}", c.ctx.account.id);
    let v = jmap(
        &mut c.ctx,
        "EmailSubmission/set",
        json!({"create": {"s": {"identityId": identity, "emailId": id}}}),
    )
    .await?;
    if let Some(r) = set_failure(&v, "notCreated") {
        let _ = jmap(&mut c.ctx, "Email/set", json!({"destroy": [id]})).await;
        return Err(r);
    }
    let e = fetch(&mut c, std::slice::from_ref(&id), true).await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(message(&e[0], &folders, true, true)),
    )
        .into_response())
}

async fn draft(AxState(state): AxState<State>, headers: HeaderMap, Json(b): Json<Outgoing>) -> Res {
    let mut c = caller(&state, &headers, &["mail.compose"]).await?;
    let folders = Folders::load(&mut c.ctx).await?;
    let drafts = folder(&folders, "drafts")?;
    let e = compose(&mut c, &b, &drafts, json!({"$draft": true, "$seen": true})).await?;
    let id = create_email(&mut c, e).await?;
    let e = fetch(&mut c, std::slice::from_ref(&id), true).await?;
    Ok((
        StatusCode::CREATED,
        Json(message(&e[0], &folders, true, true)),
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_terms_and_cursors() {
        assert_eq!(
            terms(r#"from:sam "trail map" has:attachment"#),
            vec!["from:sam", "trail map", "has:attachment"]
        );
        assert_eq!(decode_cursor(&encode_cursor(50)), Some(50));
        assert_eq!(decode_cursor("nope"), None);
        let f = Folders {
            list: vec![(
                "m1".into(),
                "inbox".into(),
                "INBOX".into(),
                Some("inbox".into()),
                0,
            )],
        };
        let c = search_filter("hello label:inbox", &f, false).unwrap();
        assert_eq!(c[0]["operator"], "OR");
        assert_eq!(c[1]["inMailbox"], "m1");
        assert_eq!(
            search_filter("hello", &f, true).unwrap()[0]["text"],
            "hello"
        );
    }
}
