//! Outbound queue: direct MX delivery, SMTP relays (smarthosts) and HTTP
//! webhooks, with retries, routing rules and bounces.
use crate::db::QueueItem;
use crate::outbound::{Dsn, RcptOutcome};
use crate::settings::{TlsMode, Transport, TransportKind};
use crate::state::State;
use crate::util::{domain_of, now};
use hmac::{Hmac, Mac};
use lettre::address::Envelope;
use lettre::transport::smtp::authentication::{Credentials, Mechanism};
use lettre::transport::smtp::client::{Tls, TlsParameters};
use lettre::transport::smtp::extension::ClientId;
use lettre::{AsyncSmtpTransport, AsyncTransport, Tokio1Executor};
use sha2::Sha256;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

pub async fn enqueue(state: &State, sender: &str, rcpts: &[String], message: &[u8], route: &str) -> anyhow::Result<i64> {
    enqueue_ext(state, sender, rcpts, message, route, &Dsn::default(), false).await
}

/// Queue with DSN parameters and/or REQUIRETLS.
pub async fn enqueue_ext(state: &State, sender: &str, rcpts: &[String], message: &[u8], route: &str, dsn: &Dsn, requiretls: bool) -> anyhow::Result<i64> {
    let key = state.blobs.put_message(message).await?;
    let id = state.db.enqueue_ext(sender, rcpts, &key, message.len() as i64, route, &dsn.to_json(), requiretls, "").await?;
    state.queue_wake.notify_one();
    crate::metrics::QUEUED.inc();
    Ok(id)
}

#[derive(Debug, Clone)]
enum Outcome {
    Sent,
    Temporary(String),
    Permanent(String),
}

impl From<RcptOutcome> for Outcome {
    fn from(o: RcptOutcome) -> Self {
        match o {
            RcptOutcome::Sent { .. } => Outcome::Sent,
            RcptOutcome::Temporary(e) => Outcome::Temporary(e),
            RcptOutcome::Permanent(e) => Outcome::Permanent(e),
        }
    }
}

pub fn spawn_worker(state: State) {
    tokio::spawn(async move {
        let sem = Arc::new(Semaphore::new(state.settings().delivery.concurrency.max(1)));
        loop {
            if state.shutdown.is_cancelled() {
                break;
            }
            let due = match state.db.due_queue(200).await {
                Ok(d) => d,
                Err(e) => {
                    tracing::error!("queue scan failed: {e:#}");
                    tokio::time::sleep(Duration::from_secs(10)).await;
                    continue;
                }
            };
            for item in due {
                if state.shutdown.is_cancelled() {
                    break;
                }
                if !state.db.claim_queue(item.id, 900).await.unwrap_or(false) {
                    continue;
                }
                let permit = sem.clone().acquire_owned().await.unwrap();
                let st = state.clone();
                let task = st.tasks.clone();
                task.spawn(async move {
                    let _p = permit;
                    if let Err(e) = process(&st, item).await {
                        tracing::error!("queue item failed: {e:#}");
                    }
                });
            }
            tokio::select! {
                _ = state.queue_wake.notified() => {}
                _ = state.shutdown.cancelled() => break,
                _ = tokio::time::sleep(Duration::from_secs(15)) => {}
            }
        }
    });
}

/// The implicit transport for an upstream Picacho relay link.
fn upstream_transport(state: &State) -> Option<Transport> {
    let s = state.settings();
    let u = s.relay.upstream.as_ref().filter(|u| u.enabled && u.outbound)?;
    Some(Transport {
        id: "upstream".into(),
        name: "Upstream Picacho relay".into(),
        kind: TransportKind::Picacho,
        url: Some(u.url.clone()),
        password: u.token.clone(),
        tls: if u.insecure { TlsMode::None } else { TlsMode::Tls },
        ..Default::default()
    })
}

/// Which transport handles a recipient domain (None = direct MX).
fn route_for(state: &State, item_route: &str, domain: &str) -> Option<Transport> {
    let s = state.settings();
    if let Some(id) = item_route.strip_prefix("transport:") {
        if id == "upstream" {
            return upstream_transport(state);
        }
        return s.transport(id).cloned();
    }
    for r in &s.delivery.routes {
        if r.matches(domain) {
            return s.transport(&r.transport).cloned();
        }
    }
    upstream_transport(state)
}

async fn process(state: &State, item: QueueItem) -> anyhow::Result<()> {
    let raw = state.blobs.get(&item.blob).await?;
    let settings = state.settings();
    let dsn = Dsn::from_json(&item.dsn);
    // Group recipients by (transport id or domain).
    let mut groups: BTreeMap<String, (Option<Transport>, Vec<String>)> = BTreeMap::new();
    for r in &item.recipients {
        let d = domain_of(r).to_ascii_lowercase();
        let t = route_for(state, &item.route, &d);
        let key = match &t {
            Some(t) if t.kind != TransportKind::Direct => format!("t:{}", t.id),
            _ => format!("d:{d}"),
        };
        groups.entry(key).or_insert_with(|| (t, vec![])).1.push(r.clone());
    }
    if item.route.starts_with("transport:") && groups.values().any(|(t, _)| t.is_none()) {
        tracing::warn!("queue {}: transport for route {} is missing", item.id, item.route);
    }
    let mut remaining = vec![];
    let mut failed: Vec<(String, String)> = vec![];
    let mut delivered: Vec<(String, bool)> = vec![];
    let mut last_error = String::new();
    for (key, (transport, rcpts)) in groups {
        let results: Vec<(String, RcptOutcome)> = match &transport {
            Some(t) if t.kind == TransportKind::Smtp => {
                if item.requiretls && !matches!(t.tls, TlsMode::Tls | TlsMode::Starttls) {
                    each(&rcpts, RcptOutcome::Permanent("5.7.10 REQUIRETLS: the configured relay does not require TLS".into()))
                } else {
                    each(&rcpts, send_smtp(state, t, &item.sender, &rcpts, &raw).await.into_rcpt())
                }
            }
            Some(t) if t.kind == TransportKind::Webhook => each(&rcpts, send_webhook(t, &item, &rcpts, &raw).await.into_rcpt()),
            Some(t) if t.kind == TransportKind::Cloudflare => send_cloudflare(state, t, &item.sender, &rcpts, &raw).await,
            Some(t) if t.kind == TransportKind::Picacho => crate::relay::push(state, t, &item, &rcpts, &raw).await,
            _ => {
                if item.route.starts_with("transport:") && transport.is_none() {
                    each(&rcpts, RcptOutcome::Temporary(format!("transport {} not configured", item.route)))
                } else {
                    let m = crate::outbound::Message { sender: &item.sender, rcpts: &rcpts, raw: &raw, dsn: &dsn, requiretls: item.requiretls };
                    crate::outbound::deliver_direct(state, key.trim_start_matches("d:"), &m).await
                }
            }
        };
        for (r, o) in results {
            match o {
                RcptOutcome::Sent { relayed } => {
                    crate::metrics::DELIVERED.inc();
                    state.event("info", "delivery", &format!("queue {}: delivered to {r}", item.id));
                    crate::submit::queue_outcome(state, item.submission_id, &r, true, if relayed { "250 2.0.0 Relayed" } else { "" }).await;
                    delivered.push((r, relayed));
                }
                RcptOutcome::Temporary(e) => {
                    last_error = e.clone();
                    remaining.push(r);
                }
                RcptOutcome::Permanent(e) => {
                    crate::metrics::BOUNCED.inc();
                    crate::submit::queue_outcome(state, item.submission_id, &r, false, &e).await;
                    last_error = e.clone();
                    failed.push((r, e));
                }
            }
        }
    }
    let age_hours = (now() - item.created_at) / 3600;
    // DELIVERBY with R: not delivered in time is returned (RFC 2852 4.1).
    if !remaining.is_empty() && dsn.by.is_some_and(|by| now() >= by) && dsn.by_mode != "N" {
        for r in remaining.drain(..) {
            crate::submit::queue_outcome(state, item.submission_id, &r, false, "5.4.7 Delivery time expired").await;
            failed.push((r, "5.4.7 Delivery time expired (DELIVERBY)".into()));
        }
    }
    if !remaining.is_empty() && age_hours >= settings.delivery.max_queue_hours as i64 {
        for r in remaining.drain(..) {
            failed.push((r, format!("gave up after {age_hours} hours: {last_error}")));
        }
    }
    if !failed.is_empty() {
        state.event(
            "warn",
            "delivery",
            &format!("queue {}: permanent failure for {}: {last_error}", item.id, failed.iter().map(|f| f.0.as_str()).collect::<Vec<_>>().join(", ")),
        );
    }
    // Delivery status notifications (RFC 3461/3464).
    if !item.sender.is_empty() {
        let mut notes: Vec<Notice> = vec![];
        if settings.delivery.send_bounces {
            for (r, e) in &failed {
                if dsn.rcpt(r).wants("FAILURE") {
                    notes.push(Notice { rcpt: r.clone(), action: "failed", status: status_code(e, "5.0.0"), diag: e.clone() });
                }
            }
        }
        for (r, relayed) in &delivered {
            if dsn.rcpt(r).notify.split(',').any(|n| n.trim().eq_ignore_ascii_case("SUCCESS")) {
                notes.push(Notice { rcpt: r.clone(), action: if *relayed { "relayed" } else { "delivered" }, status: "2.0.0".into(), diag: String::new() });
            }
        }
        if !remaining.is_empty() && !item.delay_notified && age_hours >= 4 && settings.delivery.send_bounces {
            let delayed: Vec<Notice> = remaining
                .iter()
                .filter(|r| dsn.rcpt(r).wants("DELAY"))
                .map(|r| Notice { rcpt: r.clone(), action: "delayed", status: status_code(&last_error, "4.0.0"), diag: last_error.clone() })
                .collect();
            if !delayed.is_empty() {
                notes.extend(delayed);
                let _ = state.db.set_delay_notified(item.id).await;
            }
        }
        if !notes.is_empty() {
            if let Err(e) = notify(state, &item, &raw, &dsn, &notes).await {
                tracing::warn!("delivery notification failed: {e:#}");
            }
        }
    }
    if remaining.is_empty() {
        if failed.is_empty() {
            if let Some(blob) = state.db.delete_queue(item.id).await? {
                state.blobs.delete(&blob).await?;
            }
        } else {
            let failed_rcpts: Vec<String> = failed.iter().map(|f| f.0.clone()).collect();
            state.db.update_queue(item.id, &failed_rcpts, item.attempts + 1, now(), &last_error, "failed").await?;
        }
    } else {
        let sched = &settings.delivery.retry_minutes;
        let mins = sched.get(item.attempts as usize).or(sched.last()).copied().unwrap_or(30);
        state
            .db
            .update_queue(item.id, &remaining, item.attempts + 1, now() + mins as i64 * 60, &last_error, "deferred")
            .await?;
    }
    Ok(())
}

fn each(rcpts: &[String], o: RcptOutcome) -> Vec<(String, RcptOutcome)> {
    rcpts.iter().map(|r| (r.clone(), o.clone())).collect()
}

impl Outcome {
    fn into_rcpt(self) -> RcptOutcome {
        match self {
            Outcome::Sent => RcptOutcome::Sent { relayed: true },
            Outcome::Temporary(e) => RcptOutcome::Temporary(e),
            Outcome::Permanent(e) => RcptOutcome::Permanent(e),
        }
    }
}

/// Pull an enhanced status code ("5.1.1") out of an SMTP reply, if present.
fn status_code(text: &str, default: &str) -> String {
    text.split_whitespace()
        .find(|w| {
            let p: Vec<&str> = w.split('.').collect();
            p.len() == 3 && matches!(p[0], "2" | "4" | "5") && p[1..].iter().all(|x| !x.is_empty() && x.len() <= 3 && x.chars().all(|c| c.is_ascii_digit()))
        })
        .map(|s| s.to_string())
        .unwrap_or_else(|| default.to_string())
}

fn envelope(sender: &str, rcpts: &[String]) -> Result<Envelope, String> {
    let from = if sender.is_empty() { None } else { Some(sender.parse().map_err(|e| format!("bad sender: {e}"))?) };
    let to = rcpts.iter().map(|r| r.parse()).collect::<Result<Vec<lettre::Address>, _>>().map_err(|e| format!("bad recipient: {e}"))?;
    Envelope::new(from, to).map_err(|e| e.to_string())
}

fn classify(e: lettre::transport::smtp::Error) -> Outcome {
    if e.is_permanent() {
        Outcome::Permanent(e.to_string())
    } else {
        Outcome::Temporary(e.to_string())
    }
}

/// MX hosts in preference order; the domain itself when it has no MX.
pub async fn mx_hosts(state: &State, domain: &str) -> Result<Vec<String>, String> {
    let Some(auth) = &state.resolver else { return Ok(vec![domain.to_string()]) };
    let r = auth.resolver();
    match tokio::time::timeout(Duration::from_secs(20), r.mx_lookup(format!("{}.", domain.trim_end_matches('.')))).await {
        Err(_) => Err(format!("MX lookup for {domain} timed out")),
        Ok(Ok(mx)) => {
            let mut v: Vec<(u16, String)> =
                mx.answers().iter().filter_map(|rec| match &rec.data {
                    mail_auth::hickory_resolver::proto::rr::RData::MX(mx) => {
                        Some((mx.preference, mx.exchange.to_string().trim_end_matches('.').to_string()))
                    }
                    _ => None,
                }).collect();
            v.sort();
            if v.len() == 1 && (v[0].1.is_empty() || v[0].1 == ".") {
                return Ok(vec![]);
            }
            if v.is_empty() {
                return Ok(vec![domain.to_string()]);
            }
            Ok(v.into_iter().map(|x| x.1).collect())
        }
        Ok(Err(e)) => {
            if e.is_no_records_found() || e.is_nx_domain() {
                if e.is_nx_domain() {
                    return Err(format!("domain {domain} does not exist"));
                }
                Ok(vec![domain.to_string()])
            } else {
                Err(format!("MX lookup for {domain}: {e}"))
            }
        }
    }
}

fn smtp_transport(state: &State, t: &Transport) -> Result<AsyncSmtpTransport<Tokio1Executor>, String> {
    let port = if t.port == 0 {
        match t.tls {
            TlsMode::Tls => 465,
            _ => 587,
        }
    } else {
        t.port
    };
    let params = TlsParameters::new(t.host.clone()).map_err(|e| e.to_string())?;
    let tls = match t.tls {
        TlsMode::Tls => Tls::Wrapper(params),
        TlsMode::Starttls => Tls::Required(params),
        TlsMode::Opportunistic => Tls::Opportunistic(params),
        TlsMode::None => Tls::None,
    };
    let mut b = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(t.host.as_str())
        .port(port)
        .tls(tls)
        .hello_name(ClientId::Domain(state.hostname()))
        .timeout(Some(Duration::from_secs(60)));
    if let (Some(u), Some(p)) = (&t.username, &t.password) {
        if !u.is_empty() {
            b = b.credentials(Credentials::new(u.clone(), p.clone())).authentication(vec![Mechanism::Plain, Mechanism::Login]);
        }
    }
    Ok(b.build())
}

async fn send_smtp(state: &State, t: &Transport, sender: &str, rcpts: &[String], raw: &[u8]) -> Outcome {
    let env = match envelope(sender, rcpts) {
        Ok(e) => e,
        Err(e) => return Outcome::Permanent(e),
    };
    let tr = match smtp_transport(state, t) {
        Ok(t) => t,
        Err(e) => return Outcome::Temporary(e),
    };
    match tr.send_raw(&env, raw).await {
        Ok(_) => Outcome::Sent,
        Err(e) => classify(e),
    }
}

/// The SMTP settings Cloudflare's endpoint needs, whatever was stored.
fn cloudflare_smtp(t: &Transport) -> Transport {
    Transport {
        kind: TransportKind::Smtp,
        host: crate::cloudflare::SMTP_HOST.into(),
        port: crate::cloudflare::SMTP_PORT,
        tls: TlsMode::Tls,
        username: Some(crate::cloudflare::SMTP_USER.into()),
        password: t.password.clone(),
        ..t.clone()
    }
}

/// Cloudflare Email Service: trimmed to the headers it takes, at most 50
/// recipients per session.
async fn send_cloudflare(state: &State, t: &Transport, sender: &str, rcpts: &[String], raw: &[u8]) -> Vec<(String, RcptOutcome)> {
    let msg = crate::cloudflare::for_sending(raw);
    if msg.len() > crate::cloudflare::MAX_SIZE {
        return each(rcpts, RcptOutcome::Permanent("552 5.3.4 Larger than Cloudflare Email Service takes (25 MiB)".into()));
    }
    let smtp = cloudflare_smtp(t);
    let mut out = vec![];
    for chunk in rcpts.chunks(crate::cloudflare::MAX_RCPTS) {
        out.extend(each(chunk, send_smtp(state, &smtp, sender, chunk, &msg).await.into_rcpt()));
    }
    out
}

fn sign(secret: &str, ts: &str, body: &[u8]) -> String {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(secret.as_bytes()).unwrap();
    m.update(ts.as_bytes());
    m.update(b".");
    m.update(body);
    format!("sha256={}", hex::encode(m.finalize().into_bytes()))
}

async fn send_webhook(t: &Transport, item: &QueueItem, rcpts: &[String], raw: &[u8]) -> Outcome {
    use base64::Engine;
    let Some(url) = &t.url else { return Outcome::Permanent("webhook URL missing".into()) };
    let client = match reqwest::Client::builder().timeout(Duration::from_secs(60)).build() {
        Ok(c) => c,
        Err(e) => return Outcome::Temporary(e.to_string()),
    };
    let ts = now().to_string();
    let (body, ctype) = if t.format.as_deref() == Some("raw") {
        (raw.to_vec(), "message/rfc822")
    } else {
        let j = serde_json::json!({
            "id": item.id,
            "from": item.sender,
            "to": rcpts,
            "size": raw.len(),
            "received_at": item.created_at,
            "raw": base64::engine::general_purpose::STANDARD.encode(raw),
        });
        (serde_json::to_vec(&j).unwrap(), "application/json")
    };
    let mut req = client
        .post(url)
        .header("Content-Type", ctype)
        .header("X-Picacho-Timestamp", &ts)
        .header("X-Picacho-From", &item.sender)
        .header("X-Picacho-To", rcpts.join(","));
    if let Some(s) = t.secret.as_deref().filter(|s| !s.is_empty()) {
        req = req.header("X-Picacho-Signature", sign(s, &ts, &body));
    }
    match req.body(body).send().await {
        Ok(r) if r.status().is_success() => Outcome::Sent,
        Ok(r) => {
            let s = r.status();
            let msg = format!("webhook returned HTTP {s}");
            if s.is_client_error() && s.as_u16() != 408 && s.as_u16() != 429 {
                Outcome::Permanent(msg)
            } else {
                Outcome::Temporary(msg)
            }
        }
        Err(e) => Outcome::Temporary(format!("webhook: {e}")),
    }
}

pub struct Notice {
    pub rcpt: String,
    /// failed | delayed | delivered | relayed | expanded
    pub action: &'static str,
    pub status: String,
    pub diag: String,
}

/// Build and send a delivery status notification (RFC 3464) to the sender.
pub async fn notify(state: &State, item: &QueueItem, raw: &[u8], dsn: &Dsn, notes: &[Notice]) -> anyhow::Result<()> {
    let bytes = build_dsn(state, &item.sender, raw, dsn, notes);
    send_report(state, &item.sender, &bytes).await
}

pub fn build_dsn(state: &State, to: &str, raw: &[u8], dsn: &Dsn, notes: &[Notice]) -> Vec<u8> {
    let host = state.hostname();
    let boundary = format!("dsn-{}", uuid::Uuid::new_v4().simple());
    let headers_end = raw.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 2).unwrap_or(raw.len().min(64 * 1024));
    let failed = notes.iter().any(|n| n.action == "failed");
    let delayed = notes.iter().any(|n| n.action == "delayed");
    let subject = if failed {
        "Undelivered Mail Returned to Sender"
    } else if delayed {
        "Delayed Mail (still being retried)"
    } else {
        "Successful Mail Delivery Report"
    };
    let mut text = format!("This is the mail system at host {host}.\r\n\r\n");
    if failed {
        text.push_str("Your message could not be delivered to one or more recipients.\r\n\r\n");
    } else if delayed {
        text.push_str("Your message has not been delivered yet. The mail system will keep trying; no action is needed.\r\n\r\n");
    } else {
        text.push_str("Your message was successfully delivered to the destination(s) listed below.\r\n\r\n");
    }
    let mut status = format!("Reporting-MTA: dns; {host}\r\n");
    if !dsn.envid.is_empty() {
        status.push_str(&format!("Original-Envelope-Id: {}\r\n", crate::outbound::xtext(&dsn.envid)));
    }
    status.push_str(&format!("Arrival-Date: {}\r\n", chrono::Utc::now().to_rfc2822()));
    for n in notes {
        let d: String = n.diag.chars().filter(|c| !c.is_control()).take(500).collect();
        text.push_str(&format!("<{}>: {}\r\n", n.rcpt, if d.is_empty() { n.action.to_string() } else { d.clone() }));
        status.push_str("\r\n");
        let o = dsn.rcpt(&n.rcpt).orcpt;
        if !o.is_empty() {
            status.push_str(&format!("Original-Recipient: {o}\r\n"));
        }
        status.push_str(&format!("Final-Recipient: rfc822; {}\r\nAction: {}\r\nStatus: {}\r\n", n.rcpt, n.action, n.status));
        if !d.is_empty() {
            status.push_str(&format!("Diagnostic-Code: smtp; {d}\r\n"));
        }
    }
    let full = dsn.ret.eq_ignore_ascii_case("FULL") && raw.len() < 10 * 1024 * 1024;
    let (ctype, original) = if full {
        ("message/rfc822", String::from_utf8_lossy(raw).to_string())
    } else {
        ("text/rfc822-headers", String::from_utf8_lossy(&raw[..headers_end]).to_string())
    };
    let msg = format!(
        "From: Mail Delivery System <MAILER-DAEMON@{host}>\r\nTo: <{to}>\r\nSubject: {subject}\r\nDate: {date}\r\nMessage-ID: <{id}@{host}>\r\nAuto-Submitted: auto-replied\r\nMIME-Version: 1.0\r\nContent-Type: multipart/report; report-type=delivery-status; boundary=\"{boundary}\"\r\n\r\n--{boundary}\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{text}\r\n--{boundary}\r\nContent-Type: message/delivery-status\r\n\r\n{status}\r\n--{boundary}\r\nContent-Type: {ctype}\r\n\r\n{original}\r\n--{boundary}--\r\n",
        date = chrono::Utc::now().to_rfc2822(),
        id = uuid::Uuid::new_v4().simple(),
    );
    msg.into_bytes()
}

/// Deliver a server-generated message (null sender) to `to`, wherever it lives.
pub async fn send_report(state: &State, to: &str, bytes: &[u8]) -> anyhow::Result<()> {
    match crate::smtp::delivery::resolve(state, to, true).await {
        Ok(targets) => {
            for t in targets {
                match t {
                    crate::smtp::delivery::Target::Local(acc) => {
                        // Server-generated mail skips Sieve (no reply loops).
                        crate::smtp::store_in(state, acc, "INBOX", bytes, "").await?;
                    }
                    crate::smtp::delivery::Target::Remote(r) => {
                        enqueue(state, "", &[r], bytes, "").await?;
                    }
                    crate::smtp::delivery::Target::Transport(r, tr) => {
                        enqueue(state, "", &[r], bytes, &format!("transport:{tr}")).await?;
                    }
                    crate::smtp::delivery::Target::Peer(r, p) => {
                        crate::relay::hold_for_peer(state, &p, "", &[r], bytes).await?;
                    }
                }
            }
            Ok(())
        }
        Err(_) => Ok(()),
    }
}

/// Connectivity test for the console's "Test" button.
pub async fn test_transport(state: &State, t: &Transport) -> Result<String, String> {
    match t.kind {
        TransportKind::Smtp | TransportKind::Cloudflare => {
            let t = &if t.kind == TransportKind::Cloudflare { cloudflare_smtp(t) } else { t.clone() };
            let tr = smtp_transport(state, t)?;
            match tokio::time::timeout(Duration::from_secs(30), tr.test_connection()).await {
                Ok(Ok(true)) => Ok(format!("Connected to {}:{} and authenticated.", t.host, t.port)),
                Ok(Ok(false)) => Err("The server did not accept the connection.".into()),
                Ok(Err(e)) => Err(e.to_string()),
                Err(_) => Err("Timed out.".into()),
            }
        }
        TransportKind::Webhook => {
            let url = t.url.clone().unwrap_or_default();
            let client = reqwest::Client::builder().timeout(Duration::from_secs(20)).build().map_err(|e| e.to_string())?;
            let ts = now().to_string();
            let body = serde_json::to_vec(&serde_json::json!({"test": true})).unwrap();
            let mut req = client.post(&url).header("Content-Type", "application/json").header("X-Picacho-Timestamp", &ts);
            if let Some(s) = t.secret.as_deref().filter(|s| !s.is_empty()) {
                req = req.header("X-Picacho-Signature", sign(s, &ts, &body));
            }
            let r = req.body(body).send().await.map_err(|e| e.to_string())?;
            if r.status().is_success() {
                Ok(format!("{url} answered HTTP {}.", r.status()))
            } else {
                Err(format!("{url} answered HTTP {}.", r.status()))
            }
        }
        TransportKind::Picacho => crate::relay::test_upstream(state, t).await,
        TransportKind::Direct => {
            let hosts = mx_hosts(state, "gmail.com").await?;
            let host = hosts.first().cloned().ok_or("no MX found")?;
            match tokio::time::timeout(Duration::from_secs(10), tokio::net::TcpStream::connect((host.as_str(), 25))).await {
                Ok(Ok(_)) => Ok(format!("DNS works and outbound port 25 is open ({host}).")),
                Ok(Err(e)) => Err(format!("DNS works, but port 25 to {host} failed: {e}. Many providers block port 25; use an SMTP relay.")),
                Err(_) => Err(format!("DNS works, but port 25 to {host} timed out. Many providers block port 25; use an SMTP relay.")),
            }
        }
    }
}
