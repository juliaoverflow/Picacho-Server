//! Cloudflare Email Service, both ways.
//!
//! **Sending** (transport kind `cloudflare`): authenticated SMTP to
//! `smtp.mx.cloudflare.net:465` with the user name `api_token` and a
//! Cloudflare API token (Email Sending: Edit) as the password. Cloudflare
//! DKIM-signs and sets `Message-ID`, `Date` and the like itself, and
//! refuses a whole message that carries a header outside its allowlist, so
//! the message is trimmed to the headers it takes first (see
//! [`for_sending`]). At most 50 recipients go per session.
//!
//! **Receiving** (an Email Worker): Cloudflare Email Routing holds the
//! domain's MX and runs a Worker, which POSTs each message here
//! (`/api/inbound/v1/cloudflare`, signed with the shared secret in
//! `relay.cloudflare_inbound`). The message is delivered as mail from the
//! Internet would be, except that SPF and DMARC are taken from the
//! `Authentication-Results` Cloudflare added (the connection is
//! Cloudflare's, not the sender's). [`WORKER`] is the Worker to deploy.
use crate::state::State;
use axum::body::Bytes;
use axum::extract::State as AxState;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use hmac::{Hmac, Mac};
use serde_json::json;
use sha2::Sha256;

pub const SMTP_HOST: &str = "smtp.mx.cloudflare.net";
pub const SMTP_PORT: u16 = 465;
pub const SMTP_USER: &str = "api_token";
/// Recipients per SMTP session (Cloudflare's limit).
pub const MAX_RCPTS: usize = 50;
/// Largest message Cloudflare takes (25 MiB).
pub const MAX_SIZE: usize = 25 * 1024 * 1024;

/// Headers Cloudflare sets itself (sending them gets the message refused
/// or overridden) or that only matter to this server.
const DROPPED: &[&str] = &[
    "dkim-signature", "message-id", "date", "return-path", "received", "feedback-id", "tls-required", "tls-report-domain",
    "tls-report-submitter", "cfbl-address", "cfbl-feedback-id", "bcc", "x-original-to", "delivered-to",
];

/// Headers Cloudflare allows besides the address and content headers.
const ALLOWED: &[&str] = &[
    "from", "to", "cc", "subject", "reply-to", "sender", "mime-version", "content-type", "content-transfer-encoding",
    "content-disposition", "content-id", "content-description", "in-reply-to", "references", "thread-index",
    "thread-topic", "list-unsubscribe", "list-unsubscribe-post", "list-id", "list-archive", "list-help", "list-owner",
    "list-post", "list-subscribe", "precedence", "auto-submitted", "content-language", "keywords", "comments",
    "importance", "priority", "sensitivity", "organization", "require-recipient-valid-since", "expires", "reply-by",
    "archived-at", "otp-token",
];

/// Whether Cloudflare takes a header (lowercase name) as given.
fn allowed(name: &str) -> bool {
    if DROPPED.contains(&name) || name.starts_with("arc-") {
        return false;
    }
    ALLOWED.contains(&name) || (name.starts_with("x-") && name.len() <= 100 && name[2..].bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'))
}

/// The message as Cloudflare takes it: top-level headers outside its
/// allowlist removed (with their folded lines); MIME parts untouched.
/// Headers removed this way are kept, renamed `X-Original-<Name>`, when
/// Cloudflare would otherwise drop information people may want (none of
/// the authentication or trace headers).
pub fn for_sending(raw: &[u8]) -> Vec<u8> {
    let end = raw.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 2).unwrap_or(raw.len());
    let (head, body) = raw.split_at(end);
    let mut out = Vec::with_capacity(raw.len());
    let mut keep = false;
    for line in head.split_inclusive(|&b| b == b'\n') {
        if line.first().is_some_and(|b| *b == b' ' || *b == b'\t') {
            if keep {
                out.extend_from_slice(line);
            }
            continue;
        }
        let name = line.iter().position(|&b| b == b':').map(|i| String::from_utf8_lossy(&line[..i]).trim().to_ascii_lowercase()).unwrap_or_default();
        keep = !name.is_empty() && allowed(&name);
        if keep {
            out.extend_from_slice(line);
        } else if matches!(name.as_str(), "user-agent" | "x-mailer" | "autocrypt" | "openpgp" | "disposition-notification-to" | "return-receipt-to" | "importance") {
            // Kept as an X- header so it isn't lost.
            let rest = &line[name.len()..];
            let mut renamed = format!("X-Original-{}", title(&name)).into_bytes();
            renamed.extend_from_slice(rest);
            out.extend_from_slice(&renamed);
            keep = true;
        }
    }
    out.extend_from_slice(body);
    out
}

fn title(name: &str) -> String {
    name.split('-')
        .map(|p| {
            let mut c = p.chars();
            c.next().map(|f| f.to_ascii_uppercase().to_string() + c.as_str()).unwrap_or_default()
        })
        .collect::<Vec<_>>()
        .join("-")
}

// ------------------------------------------------------------------ receiving

pub fn routes(state: State) -> Router {
    Router::new()
        .route("/api/inbound/v1/cloudflare", post(receive).layer(axum::extract::DefaultBodyLimit::max(MAX_SIZE + 64 * 1024)))
        .with_state(state)
}

fn reply(code: StatusCode, action: &str, msg: &str) -> Response {
    (code, Json(json!({"action": action, "message": msg}))).into_response()
}

/// `sha256=<hex>` of `<timestamp>.<body>` with the shared secret (the same
/// scheme outbound webhooks use).
pub fn signature(secret: &str, ts: &str, body: &[u8]) -> String {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(secret.as_bytes()).expect("hmac key");
    m.update(ts.as_bytes());
    m.update(b".");
    m.update(body);
    format!("sha256={}", hex::encode(m.finalize().into_bytes()))
}

fn verify(secret: &str, headers: &HeaderMap, body: &[u8]) -> Result<(), &'static str> {
    use subtle::ConstantTimeEq;
    let h = |k: &str| headers.get(k).and_then(|v| v.to_str().ok()).unwrap_or("");
    let ts = h("x-picacho-timestamp");
    let t: i64 = ts.parse().map_err(|_| "missing timestamp")?;
    if (crate::util::now() - t).abs() > 300 {
        return Err("stale timestamp");
    }
    let want = signature(secret, ts, body);
    if want.as_bytes().ct_eq(h("x-picacho-signature").as_bytes()).into() {
        Ok(())
    } else {
        Err("bad signature")
    }
}

/// SPF, DKIM and DMARC as Cloudflare found them: only from the topmost
/// `Authentication-Results` naming `mx.cloudflare.net` (any lower one
/// could come from the sender).
pub fn cloudflare_results(raw: &[u8]) -> Option<crate::filter::AuthSummary> {
    let end = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap_or(raw.len());
    let head = String::from_utf8_lossy(&raw[..end]).replace("\r\n ", " ").replace("\r\n\t", " ");
    let first = head.lines().find(|l| l.len() > 23 && l[..23].eq_ignore_ascii_case("authentication-results:"))?;
    let value = first[23..].trim();
    let (authserv, rest) = value.split_once(';').unwrap_or((value, ""));
    if !authserv.split_whitespace().next().is_some_and(|a| a.eq_ignore_ascii_case("mx.cloudflare.net")) {
        return None;
    }
    let get = |m: &str| {
        rest.split(';')
            .map(str::trim)
            .find_map(|part| {
                let (k, v) = part.split_once('=')?;
                k.trim().eq_ignore_ascii_case(m).then(|| v.split_whitespace().next().unwrap_or("").to_ascii_lowercase())
            })
            .unwrap_or_else(|| "none".into())
    };
    Some(crate::filter::AuthSummary { spf: get("spf"), dkim: get("dkim"), dmarc: get("dmarc"), arc: get("arc") })
}

async fn receive(AxState(state): AxState<State>, headers: HeaderMap, body: Bytes) -> Response {
    let cfg = state.settings().relay.cloudflare_inbound.clone();
    let Some(secret) = cfg.secret.clone().filter(|s| cfg.enabled && s.len() >= 16) else {
        return reply(StatusCode::NOT_FOUND, "reject", "Not enabled.");
    };
    if let Err(why) = verify(&secret, &headers, &body) {
        crate::metrics::AUTH_FAILURES.inc();
        return reply(StatusCode::UNAUTHORIZED, "retry", why);
    }
    let h = |k: &str| headers.get(k).and_then(|v| v.to_str().ok()).unwrap_or("").trim().to_string();
    let sender = h("x-picacho-from");
    let rcpt = h("x-picacho-to").to_ascii_lowercase();
    if crate::util::normalize_address(&rcpt).is_none() || (!sender.is_empty() && crate::util::normalize_address(&sender).is_none()) {
        return reply(StatusCode::BAD_REQUEST, "reject", "Bad envelope.");
    }
    match ingest(&state, &sender, &rcpt, &body).await {
        Ok(Ingested::Accepted) => reply(StatusCode::OK, "accept", "Delivered."),
        Ok(Ingested::Rejected(msg)) => reply(StatusCode::OK, "reject", &msg),
        Err(e) => {
            tracing::warn!("cloudflare inbound for {rcpt}: {e:#}");
            reply(StatusCode::SERVICE_UNAVAILABLE, "retry", "Try again later.")
        }
    }
}

pub enum Ingested {
    Accepted,
    /// Refused for good: the Worker rejects it at Cloudflare (the sender
    /// gets a bounce from there).
    Rejected(String),
}

/// Deliver a message Cloudflare received for `rcpt`.
pub async fn ingest(state: &State, sender: &str, rcpt: &str, raw: &[u8]) -> anyhow::Result<Ingested> {
    use crate::smtp::delivery::{resolve, RcptError, Target};
    let raw = crate::util::normalize_crlf(raw);
    if raw.len() > state.settings().limits.max_message_bytes as usize {
        return Ok(Ingested::Rejected("Message too large".into()));
    }
    // Only our own domains: this isn't an open relay.
    let targets = match resolve(state, rcpt, false).await {
        Ok(t) => t,
        Err(RcptError::Temporary) => anyhow::bail!("temporary lookup failure"),
        Err(RcptError::Disabled) => return Ok(Ingested::Rejected("Mailbox disabled".into())),
        Err(_) => return Ok(Ingested::Rejected("No such user here".into())),
    };
    let auth = cloudflare_results(&raw);
    let sec = state.settings().security.clone();
    let accounts: Vec<i64> = targets.iter().filter_map(|t| if let Target::Local(a) = t { Some(*a) } else { None }).collect();
    let ctx = crate::filter::Context {
        sender: sender.to_string(),
        rcpts: vec![rcpt.to_string()],
        accounts,
        auth: auth.clone(),
        relayed: true,
        ..Default::default()
    };
    let verdict = crate::filter::scan(state, &ctx, &raw).await;
    if let Some(msg) = &verdict.tempfail {
        anyhow::bail!("{msg}");
    }
    if let Some(msg) = &verdict.reject {
        state.event("info", "filter", &format!("rejected mail from <{sender}> via Cloudflare: {msg} [{:.1}]", verdict.score));
        return Ok(Ingested::Rejected(msg.clone()));
    }
    let junk = verdict.junk || (sec.quarantine_to_junk && auth.as_ref().is_some_and(|a| a.dmarc == "fail"));
    let host = state.hostname();
    let id = uuid::Uuid::new_v4().simple().to_string();
    let mut message = format!("Return-Path: <{sender}>\r\n").into_bytes();
    message.extend_from_slice(&crate::filter::apply_headers(&verdict, Vec::new()));
    message.extend_from_slice(format!("Received: from mx.cloudflare.net (Cloudflare Email Routing)\r\n\tby {host} (Picacho Server) with HTTPS id {id}\r\n\tfor <{rcpt}>; {}\r\n", chrono::Utc::now().to_rfc2822()).as_bytes());
    message.extend_from_slice(&raw);
    for t in targets {
        match t {
            Target::Local(acc) => crate::smtp::deliver_local_from(state, acc, sender, rcpt, &message, junk).await?,
            other => crate::smtp::deliver_target(state, sender, &message, other, junk).await?,
        }
    }
    crate::reports::maybe_ingest(state, &[rcpt.to_string()], &raw).await;
    state.event("info", "smtp", &format!("accepted {id} from <{sender}> via Cloudflare for <{rcpt}>, {} bytes", message.len()));
    Ok(Ingested::Accepted)
}

/// The Email Worker to deploy (Cloudflare dashboard → Email Routing →
/// Email Workers). `PICACHO_URL` and `PICACHO_SECRET` are its variables.
pub const WORKER: &str = r#"// Picacho Server: hands mail Cloudflare Email Routing receives to your server.
// Variables: PICACHO_URL (e.g. https://mail.example.com) and the secret
// PICACHO_SECRET (from Relay link -> Cloudflare Email Workers).
export default {
  async email(message, env, ctx) {
    const raw = new Uint8Array(await new Response(message.raw).arrayBuffer());
    const ts = Math.floor(Date.now() / 1000).toString();
    const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(env.PICACHO_SECRET),
      { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const data = new Uint8Array([...new TextEncoder().encode(ts + "."), ...raw]);
    const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, data));
    const sig = "sha256=" + [...mac].map((b) => b.toString(16).padStart(2, "0")).join("");
    let res;
    try {
      res = await fetch(env.PICACHO_URL.replace(/\/$/, "") + "/api/inbound/v1/cloudflare", {
        method: "POST",
        headers: {
          "Content-Type": "message/rfc822",
          "X-Picacho-Timestamp": ts,
          "X-Picacho-Signature": sig,
          "X-Picacho-From": message.from,
          "X-Picacho-To": message.to,
        },
        body: raw,
      });
    } catch (e) {
      // Unreachable: the delivery fails at Cloudflare (see its Email
      // Routing logs); nothing is accepted that wasn't delivered.
      throw new Error("Picacho Server unreachable: " + e);
    }
    const answer = await res.json().catch(() => ({}));
    if (res.ok && answer.action === "accept") return;
    if (res.ok && answer.action === "reject") {
      message.setReject(answer.message || "Rejected");
      return;
    }
    throw new Error("Picacho Server answered HTTP " + res.status);
  },
};
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trims_to_what_cloudflare_takes() {
        let raw = b"DKIM-Signature: v=1; a=rsa-sha256;\r\n\tb=abc\r\nFrom: Bob <bob@example.test>\r\nTo: amy@elsewhere.test\r\nBcc: secret@x.test\r\nMessage-ID: <1@x>\r\nDate: Mon, 1 Dec 2026 10:00:00 +0000\r\nSubject: Hi\r\nUser-Agent: Picacho\r\nX-Custom: yes\r\nReceived: from x\r\nMIME-Version: 1.0\r\nContent-Type: text/plain\r\n\r\nBody\r\nDate: in the body stays\r\n";
        let out = String::from_utf8(for_sending(raw)).unwrap();
        assert!(!out.contains("DKIM-Signature") && !out.contains("b=abc") && !out.contains("Bcc") && !out.contains("Message-ID") && !out.contains("Received"));
        assert!(out.starts_with("From: Bob <bob@example.test>\r\nTo: amy@elsewhere.test\r\n"), "{out}");
        assert!(out.contains("Subject: Hi\r\n") && out.contains("X-Custom: yes\r\n") && out.contains("X-Original-User-Agent: Picacho\r\n"));
        assert!(out.ends_with("\r\n\r\nBody\r\nDate: in the body stays\r\n"), "{out}");
    }

    #[test]
    fn reads_only_cloudflares_results() {
        let raw = b"Authentication-Results: mx.cloudflare.net;\r\n dkim=pass header.d=a.test; spf=pass smtp.mailfrom=a.test;\r\n dmarc=fail\r\nAuthentication-Results: forged.example; dmarc=pass\r\nSubject: x\r\n\r\nb";
        let a = cloudflare_results(raw).unwrap();
        assert_eq!((a.spf.as_str(), a.dkim.as_str(), a.dmarc.as_str()), ("pass", "pass", "fail"));
        let forged = b"Authentication-Results: evil.example; dmarc=pass\r\nAuthentication-Results: mx.cloudflare.net; dmarc=fail\r\n\r\nb";
        assert!(cloudflare_results(forged).is_none(), "only the topmost header counts");
        let sig = signature("0123456789abcdef", "1700000000", b"hello");
        assert!(sig.starts_with("sha256=") && sig.len() == 71);
    }
}
