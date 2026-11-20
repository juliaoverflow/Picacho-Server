//! Picacho-to-Picacho relay link, for servers that can't use port 25.
//!
//! A *downstream* server (at home, in an office, behind a provider that
//! blocks port 25) pairs with a public *upstream* Picacho server. Only
//! outbound HTTPS from the downstream is needed:
//!
//! - Outbound: the downstream POSTs each message to the upstream
//!   (`/api/relay/v1/send`), which delivers it by MX. The downstream signs
//!   DKIM itself; the upstream only accepts senders in the peer's domains.
//! - Inbound: the upstream is the MX for the peer's domains (domain mode
//!   `peer`). It verifies SPF/DKIM/DMARC, holds the message, and the
//!   downstream long-polls `/api/relay/v1/pull`, delivers locally and acks.
//!
//! Peers authenticate with a `pmrl_` token created on the upstream.
use crate::db::{Db, QueueItem};
use crate::outbound::{Dsn, RcptOutcome};
use crate::settings::Transport;
use crate::state::State;
use crate::util::{now, sha256_hex};
use anyhow::Result;
use axum::extract::{Query, State as AxState};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::Row;
use std::time::Duration;

pub const TOKEN_PREFIX: &str = "pmrl_";
const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

#[derive(Debug, Clone, Serialize)]
pub struct Peer {
    pub id: i64,
    pub name: String,
    pub prefix: String,
    pub domains: Vec<String>,
    pub active: bool,
    pub created_at: i64,
    pub last_seen: Option<i64>,
}

fn peer_from(r: &sqlx::any::AnyRow) -> Result<Peer> {
    let d: String = r.try_get("domains")?;
    Ok(Peer {
        id: r.try_get("id")?,
        name: r.try_get("name")?,
        prefix: r.try_get("prefix")?,
        domains: d.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect(),
        active: r.try_get::<i64, _>("active")? != 0,
        created_at: r.try_get("created_at")?,
        last_seen: r.try_get("last_seen")?,
    })
}

const PEER_COLS: &str = "id, name, prefix, domains, active, created_at, last_seen";

impl Db {
    pub async fn list_peers(&self) -> Result<Vec<Peer>> {
        let rows = sqlx::query(&format!("SELECT {PEER_COLS} FROM relay_peers ORDER BY name")).fetch_all(&self.pool).await?;
        rows.iter().map(peer_from).collect()
    }

    pub async fn peer_by_name(&self, name: &str) -> Result<Option<Peer>> {
        let r = sqlx::query(&format!("SELECT {PEER_COLS} FROM relay_peers WHERE name = $1")).bind(name).fetch_optional(&self.pool).await?;
        r.as_ref().map(peer_from).transpose()
    }

    async fn peer_by_token(&self, hash: &str) -> Result<Option<Peer>> {
        let r = sqlx::query(&format!("SELECT {PEER_COLS} FROM relay_peers WHERE token_hash = $1 AND active = 1"))
            .bind(hash)
            .fetch_optional(&self.pool)
            .await?;
        r.as_ref().map(peer_from).transpose()
    }

    /// Create a peer; returns (peer, token shown once).
    pub async fn create_peer(&self, name: &str, domains: &[String]) -> Result<(Peer, String)> {
        let token = format!("{TOKEN_PREFIX}{}", crate::util::random_token());
        let prefix: String = token.chars().take(13).collect();
        {
            let _g = self.wl().await;
            sqlx::query("INSERT INTO relay_peers (name, token_hash, prefix, domains, created_at) VALUES ($1, $2, $3, $4, $5)")
                .bind(name)
                .bind(sha256_hex(token.as_bytes()))
                .bind(&prefix)
                .bind(domains.join(","))
                .bind(now())
                .execute(&self.pool)
                .await?;
        }
        let p = self.peer_by_name(name).await?.ok_or_else(|| anyhow::anyhow!("peer vanished"))?;
        Ok((p, token))
    }

    pub async fn update_peer(&self, name: &str, domains: &[String], active: bool) -> Result<bool> {
        let _g = self.wl().await;
        let r = sqlx::query("UPDATE relay_peers SET domains = $1, active = $2 WHERE name = $3")
            .bind(domains.join(","))
            .bind(active as i64)
            .bind(name)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected() == 1)
    }

    pub async fn delete_peer(&self, name: &str) -> Result<bool> {
        let _g = self.wl().await;
        let r = sqlx::query("DELETE FROM relay_peers WHERE name = $1").bind(name).execute(&self.pool).await?;
        Ok(r.rows_affected() == 1)
    }

    async fn touch_peer(&self, id: i64) {
        let _g = self.wl().await;
        let _ = sqlx::query("UPDATE relay_peers SET last_seen = $1 WHERE id = $2").bind(now()).bind(id).execute(&self.pool).await;
    }

    async fn held_for_peer(&self, peer: &str, limit: i64) -> Result<Vec<QueueItem>> {
        let ids: Vec<i64> = sqlx::query("SELECT id FROM queue WHERE peer = $1 AND status = 'held' ORDER BY id LIMIT $2")
            .bind(peer)
            .bind(limit)
            .fetch_all(&self.pool)
            .await?
            .iter()
            .map(|r| r.get::<i64, _>(0))
            .collect();
        let mut out = vec![];
        for id in ids {
            if let Some(q) = self.get_queue(id).await? {
                out.push(q);
            }
        }
        Ok(out)
    }

    pub async fn held_count(&self, peer: &str) -> Result<i64> {
        let r = sqlx::query("SELECT COUNT(*) FROM queue WHERE peer = $1 AND status = 'held'").bind(peer).fetch_one(&self.pool).await?;
        Ok(r.get(0))
    }
}

// ------------------------------------------------------------------ upstream side

pub fn routes(state: State) -> Router {
    Router::new()
        .route("/api/relay/v1/info", get(info))
        .route("/api/relay/v1/send", post(send).layer(axum::extract::DefaultBodyLimit::max(80 * 1024 * 1024)))
        .route("/api/relay/v1/pull", get(pull))
        .route("/api/relay/v1/ack", post(ack))
        .with_state(state)
}

fn err(code: StatusCode, msg: &str) -> Response {
    (code, Json(json!({"error": msg}))).into_response()
}

async fn peer_auth(state: &State, headers: &HeaderMap) -> Result<Peer, Response> {
    if !state.settings().relay.accept_downstream {
        return Err(err(StatusCode::NOT_FOUND, "This server does not accept relay peers."));
    }
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|t| t.starts_with(TOKEN_PREFIX) && t.len() < 200)
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "Relay token required."))?;
    match state.db.peer_by_token(&sha256_hex(token.as_bytes())).await {
        Ok(Some(p)) => {
            state.db.touch_peer(p.id).await;
            Ok(p)
        }
        Ok(None) => Err(err(StatusCode::UNAUTHORIZED, "Invalid relay token.")),
        Err(_) => Err(err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error.")),
    }
}

async fn info(AxState(state): AxState<State>, headers: HeaderMap) -> Response {
    match peer_auth(&state, &headers).await {
        Ok(p) => Json(json!({
            "hostname": state.hostname(),
            "version": env!("CARGO_PKG_VERSION"),
            "peer": p.name,
            "domains": p.domains,
            "held": state.db.held_count(&p.name).await.unwrap_or(0),
        }))
        .into_response(),
        Err(r) => r,
    }
}

#[derive(Deserialize, Serialize)]
pub struct WireMessage {
    #[serde(default)]
    pub id: i64,
    pub from: String,
    pub to: Vec<String>,
    /// Base64 of the raw RFC 5322 message.
    pub raw: String,
    #[serde(default)]
    pub dsn: Option<Dsn>,
    #[serde(default)]
    pub requiretls: bool,
}

fn peer_owns(p: &Peer, addr: &str) -> bool {
    let d = crate::util::domain_of(addr).to_ascii_lowercase();
    p.domains.iter().any(|x| x.eq_ignore_ascii_case(&d) || d.ends_with(&format!(".{}", x.to_ascii_lowercase())))
}

async fn send(AxState(state): AxState<State>, headers: HeaderMap, Json(m): Json<WireMessage>) -> Response {
    let p = match peer_auth(&state, &headers).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    // Null sender (bounces) is fine; otherwise the sender must be the peer's.
    if !m.from.is_empty() && !peer_owns(&p, &m.from) {
        return err(StatusCode::FORBIDDEN, "Sender domain is not assigned to this relay peer.");
    }
    if m.to.is_empty() || m.to.len() > 1000 {
        return err(StatusCode::BAD_REQUEST, "Between 1 and 1000 recipients are required.");
    }
    let mut rcpts = vec![];
    for r in &m.to {
        match crate::util::normalize_address(r) {
            Some(a) => rcpts.push(a),
            None => return err(StatusCode::BAD_REQUEST, &format!("Invalid recipient {r}.")),
        }
    }
    let Ok(raw) = B64.decode(m.raw.as_bytes()) else { return err(StatusCode::BAD_REQUEST, "raw must be base64.") };
    if raw.len() as u64 > state.settings().limits.max_message_bytes {
        return err(StatusCode::PAYLOAD_TOO_LARGE, "Message too large.");
    }
    let raw = crate::util::normalize_crlf(&raw);
    // Recipients on this server are delivered here; others go out.
    let mut remote = vec![];
    for r in rcpts {
        match crate::smtp::delivery::resolve(&state, &r, true).await {
            Ok(targets) => {
                for t in targets {
                    if let Err(e) = crate::smtp::deliver_target(&state, &m.from, &raw, t, false).await {
                        tracing::warn!("relay peer {}: {e:#}", p.name);
                        return err(StatusCode::SERVICE_UNAVAILABLE, "Temporary failure, try again.");
                    }
                }
            }
            Err(crate::smtp::delivery::RcptError::Temporary) => return err(StatusCode::SERVICE_UNAVAILABLE, "Temporary lookup failure."),
            Err(_) => remote.push(r),
        }
    }
    let mut id = 0;
    if !remote.is_empty() {
        match crate::queue::enqueue_ext(&state, &m.from, &remote, &raw, "", &m.dsn.unwrap_or_default(), m.requiretls).await {
            Ok(i) => id = i,
            Err(e) => {
                tracing::error!("relay enqueue: {e:#}");
                return err(StatusCode::SERVICE_UNAVAILABLE, "Temporary failure, try again.");
            }
        }
    }
    state.event("info", "relay", &format!("peer {} relayed <{}> to {} recipient(s)", p.name, m.from, m.to.len()));
    Json(json!({"queued": id})).into_response()
}

#[derive(Deserialize)]
struct PullQuery {
    #[serde(default)]
    wait: Option<u64>,
    #[serde(default)]
    max: Option<i64>,
}

async fn pull(AxState(state): AxState<State>, headers: HeaderMap, Query(q): Query<PullQuery>) -> Response {
    let p = match peer_auth(&state, &headers).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    let max = q.max.unwrap_or(20).clamp(1, 100);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(q.wait.unwrap_or(0).min(55));
    loop {
        let waker = state.peer_wake.entry(p.name.clone()).or_default().clone();
        let notified = waker.notified();
        let items = match state.db.held_for_peer(&p.name, max).await {
            Ok(i) => i,
            Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error."),
        };
        if !items.is_empty() || tokio::time::Instant::now() >= deadline {
            let mut out = vec![];
            let mut bytes = 0usize;
            for it in items {
                let Ok(raw) = state.blobs.get(&it.blob).await else { continue };
                bytes += raw.len();
                out.push(WireMessage {
                    id: it.id,
                    from: it.sender.clone(),
                    to: it.recipients.clone(),
                    raw: B64.encode(raw.as_slice()),
                    dsn: Some(Dsn::from_json(&it.dsn)),
                    requiretls: it.requiretls,
                });
                if bytes > 40 * 1024 * 1024 {
                    break;
                }
            }
            return Json(json!({"messages": out})).into_response();
        }
        tokio::select! {
            _ = notified => {}
            _ = tokio::time::sleep_until(deadline) => {}
            _ = state.shutdown.cancelled() => return Json(json!({"messages": []})).into_response(),
        }
    }
}

#[derive(Deserialize)]
struct AckBody {
    ids: Vec<i64>,
}

async fn ack(AxState(state): AxState<State>, headers: HeaderMap, Json(b): Json<AckBody>) -> Response {
    let p = match peer_auth(&state, &headers).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    let mut done = 0;
    for id in b.ids.iter().take(1000) {
        let Ok(Some(q)) = state.db.get_queue(*id).await else { continue };
        if q.peer != p.name {
            continue;
        }
        if let Ok(Some(blob)) = state.db.delete_queue(*id).await {
            let _ = state.blobs.delete(&blob).await;
        }
        done += 1;
    }
    Json(json!({"acknowledged": done})).into_response()
}

/// Hold a message for a peer and wake its long-poll.
pub async fn hold_for_peer(state: &State, peer: &str, sender: &str, rcpts: &[String], raw: &[u8]) -> Result<()> {
    let key = state.blobs.put_message(raw).await?;
    state.db.enqueue_ext(sender, rcpts, &key, raw.len() as i64, "", "", false, peer).await?;
    if let Some(w) = state.peer_wake.get(peer) {
        w.notify_waiters();
    }
    Ok(())
}

// ------------------------------------------------------------------ downstream side

fn client(insecure: bool, timeout: Duration) -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(timeout)
        .danger_accept_invalid_certs(insecure)
        .user_agent(concat!("PicachoServer/", env!("CARGO_PKG_VERSION")))
        .build()
        .expect("http client")
}

fn upstream_of(t: &Transport) -> (String, String, bool) {
    let url = t.url.clone().unwrap_or_default().trim_end_matches('/').to_string();
    let token = t.password.clone().unwrap_or_default();
    (url, token, t.tls == crate::settings::TlsMode::None)
}

/// Outbound: hand a queued message to the upstream.
pub async fn push(state: &State, t: &Transport, item: &QueueItem, rcpts: &[String], raw: &[u8]) -> Vec<(String, RcptOutcome)> {
    let (url, token, insecure) = upstream_of(t);
    let all = |o: RcptOutcome| rcpts.iter().map(|r| (r.clone(), o.clone())).collect::<Vec<_>>();
    if url.is_empty() || token.is_empty() {
        return all(RcptOutcome::Temporary("relay link is not configured (URL and token)".into()));
    }
    let _ = state;
    let body = WireMessage {
        id: 0,
        from: item.sender.clone(),
        to: rcpts.to_vec(),
        raw: B64.encode(raw),
        dsn: Some(Dsn::from_json(&item.dsn)),
        requiretls: item.requiretls,
    };
    let r = client(insecure, Duration::from_secs(120)).post(format!("{url}/api/relay/v1/send")).bearer_auth(&token).json(&body).send().await;
    match r {
        Ok(r) if r.status().is_success() => all(RcptOutcome::Sent { relayed: true }),
        Ok(r) => {
            let s = r.status();
            let msg: String = r.text().await.unwrap_or_default().chars().take(300).collect();
            let msg = format!("upstream relay answered HTTP {s}: {msg}");
            if s.is_client_error() && !matches!(s.as_u16(), 401 | 408 | 429) {
                all(RcptOutcome::Permanent(msg))
            } else {
                all(RcptOutcome::Temporary(msg))
            }
        }
        Err(e) => all(RcptOutcome::Temporary(format!("upstream relay: {e}"))),
    }
}

pub async fn test_upstream(_state: &State, t: &Transport) -> Result<String, String> {
    let (url, token, insecure) = upstream_of(t);
    let r = client(insecure, Duration::from_secs(20))
        .get(format!("{url}/api/relay/v1/info"))
        .bearer_auth(token)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !r.status().is_success() {
        return Err(format!("{url} answered HTTP {}.", r.status()));
    }
    let v: serde_json::Value = r.json().await.map_err(|e| e.to_string())?;
    Ok(format!(
        "Connected to {} as peer '{}' (domains: {}). {} message(s) waiting.",
        v["hostname"].as_str().unwrap_or("?"),
        v["peer"].as_str().unwrap_or("?"),
        v["domains"].as_array().map(|a| a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(", ")).unwrap_or_default(),
        v["held"].as_i64().unwrap_or(0)
    ))
}

/// Inbound: long-poll the upstream for mail addressed to our domains.
pub fn spawn_puller(state: State) {
    tokio::spawn(async move {
        let mut backoff = 1u64;
        loop {
            if state.shutdown.is_cancelled() {
                return;
            }
            let Some(up) = state.settings().relay.upstream.clone().filter(|u| u.enabled && u.inbound) else {
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(30)) => continue,
                    _ = state.shutdown.cancelled() => return,
                }
            };
            let url = up.url.trim_end_matches('/').to_string();
            let token = up.token.clone().unwrap_or_default();
            let http = client(up.insecure, Duration::from_secs(90));
            let res = tokio::select! {
                r = http.get(format!("{url}/api/relay/v1/pull?wait=50&max=20")).bearer_auth(&token).send() => r,
                _ = state.shutdown.cancelled() => return,
            };
            let batch: Vec<WireMessage> = match res {
                Ok(r) if r.status().is_success() => match r.json::<serde_json::Value>().await {
                    Ok(v) => serde_json::from_value(v["messages"].clone()).unwrap_or_default(),
                    Err(e) => {
                        tracing::warn!("relay pull: {e}");
                        vec![]
                    }
                },
                Ok(r) => {
                    tracing::warn!("relay pull: upstream answered HTTP {}", r.status());
                    tokio::time::sleep(Duration::from_secs(backoff)).await;
                    backoff = (backoff * 2).min(300);
                    continue;
                }
                Err(e) => {
                    tracing::warn!("relay pull: {e}");
                    tokio::time::sleep(Duration::from_secs(backoff)).await;
                    backoff = (backoff * 2).min(300);
                    continue;
                }
            };
            backoff = 1;
            let mut acked = vec![];
            for m in batch {
                let Ok(raw) = B64.decode(m.raw.as_bytes()) else {
                    acked.push(m.id);
                    continue;
                };
                match ingest(&state, &m.from, &m.to, &raw).await {
                    Ok(()) => acked.push(m.id),
                    Err(e) => tracing::warn!("relay ingest of upstream message {} failed, will retry: {e:#}", m.id),
                }
            }
            if !acked.is_empty() {
                let r = http.post(format!("{url}/api/relay/v1/ack")).bearer_auth(&token).json(&json!({"ids": acked})).send().await;
                if let Err(e) = r {
                    tracing::warn!("relay ack: {e}");
                }
            }
        }
    });
}

/// Deliver a message pulled from the upstream: content filter, Sieve and
/// local delivery; unknown recipients bounce back through the relay.
async fn ingest(state: &State, sender: &str, rcpts: &[String], raw: &[u8]) -> Result<()> {
    let raw = crate::util::normalize_crlf(raw);
    let mut unknown = vec![];
    let verdict = crate::filter::scan(state, &crate::filter::Context::relayed(sender, rcpts), &raw).await;
    let raw = crate::filter::apply_headers(&verdict, raw);
    for r in rcpts {
        match crate::smtp::delivery::resolve(state, r, false).await {
            Ok(targets) => {
                for t in targets {
                    crate::smtp::deliver_target(state, sender, &raw, t, verdict.junk).await?;
                }
            }
            Err(crate::smtp::delivery::RcptError::Temporary) => anyhow::bail!("temporary lookup failure"),
            Err(_) => unknown.push(r.clone()),
        }
    }
    if !unknown.is_empty() && !sender.is_empty() {
        let notes: Vec<crate::queue::Notice> = unknown
            .iter()
            .map(|r| crate::queue::Notice { rcpt: r.clone(), action: "failed", status: "5.1.1".into(), diag: "550 5.1.1 user unknown".into() })
            .collect();
        let dsn = crate::queue::build_dsn(state, sender, &raw, &Dsn::default(), &notes);
        crate::queue::send_report(state, sender, &dsn).await?;
    }
    state.event("info", "relay", &format!("received <{sender}> for {} recipient(s) via upstream", rcpts.len()));
    Ok(())
}
