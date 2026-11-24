//! Mail an account sends: now, or held at the server and sent later (SMTP
//! FUTURERELEASE, RFC 4865; JMAP HOLDUNTIL/HOLDFOR, RFC 8621 7.5).
//!
//! Every message sent through JMAP, and every message held by either
//! protocol, is recorded as a submission (JMAP `EmailSubmission`): held ones
//! are `pending` and can be canceled until they're released; sent ones are
//! `final`, with each recipient's delivery status, which the queue updates
//! as remote deliveries succeed or fail.
use crate::db::{Account, Submission};
use crate::outbound::Dsn;
use crate::smtp::delivery::{RcptError, Target};
use crate::state::State;
use crate::util::now;
use serde_json::{json, Map, Value};
use std::time::Duration;

/// What to send.
pub struct Outgoing {
    pub identity: String,
    pub email_id: i64,
    pub thread_id: i64,
    /// Envelope sender.
    pub sender: String,
    pub rcpts: Vec<String>,
    /// The message as sent (Bcc removed), not yet DKIM-signed.
    pub message: Vec<u8>,
    pub dsn: Dsn,
    pub requiretls: bool,
    /// Hold until then (unix seconds); `None` sends now.
    pub hold_until: Option<i64>,
}

/// How far ahead a message may be held, in seconds (0: never).
pub fn max_hold_secs(state: &State) -> i64 {
    state.settings().limits.max_hold_days as i64 * 86_400
}

/// When a FUTURERELEASE / HOLDUNTIL parameter asks to send.
/// `HOLDFOR=<seconds>` or `HOLDUNTIL=<RFC 3339 date-time>`.
pub fn hold_time(state: &State, key: &str, value: &str) -> Result<i64, String> {
    let at = match key.to_ascii_uppercase().as_str() {
        "HOLDFOR" => {
            let s: i64 = value.trim().parse().map_err(|_| "HOLDFOR needs a number of seconds".to_string())?;
            if s < 0 {
                return Err("HOLDFOR can't be negative".into());
            }
            now() + s
        }
        "HOLDUNTIL" => chrono::DateTime::parse_from_rfc3339(value.trim())
            .map_err(|_| "HOLDUNTIL needs an RFC 3339 date-time".to_string())?
            .timestamp(),
        _ => return Err(format!("unknown hold parameter {key}")),
    };
    if at - now() > max_hold_secs(state) {
        return Err("That's further ahead than this server holds messages".into());
    }
    Ok(at)
}

/// Whether an account may send as `addr`: its own address, a +tag of it,
/// or an alias that delivers to it.
pub async fn owns_address(state: &State, acc: &Account, addr: &str) -> bool {
    if addr.is_empty() || addr.eq_ignore_ascii_case(&acc.email) {
        return true;
    }
    if let Some((l, d)) = addr.rsplit_once('@') {
        if let Some((base, _)) = l.split_once('+') {
            if format!("{base}@{d}").eq_ignore_ascii_case(&acc.email) {
                return true;
            }
        }
    }
    match state.db.alias_by_source(addr).await {
        Ok(Some(a)) => a.destination.split([',', ' ']).any(|d| d.trim().eq_ignore_ascii_case(&acc.email)),
        _ => false,
    }
}

/// Check every recipient before anything is sent, so a bad address sends
/// nothing rather than some of it.
pub async fn check_recipients(state: &State, account: &Account, rcpts: &[String]) -> Result<(), String> {
    for r in rcpts {
        match crate::smtp::delivery::resolve(state, r, account.can_send_external).await {
            Ok(_) => {}
            Err(RcptError::NoSuchUser) => return Err(format!("{r}: no such mailbox")),
            Err(RcptError::Disabled) => return Err(format!("{r}: mailbox disabled")),
            Err(RcptError::RelayDenied) => return Err(format!("{r}: this account may not send to external recipients")),
            Err(RcptError::Temporary) => return Err(format!("{r}: temporary lookup failure, try again")),
        }
    }
    Ok(())
}

/// Record a submission and send it now, or hold it. The recipients must
/// have passed [`check_recipients`].
pub async fn submit(state: &State, account: &Account, o: Outgoing) -> anyhow::Result<Submission> {
    let held = o.hold_until.is_some_and(|t| t > now());
    let mut s = Submission {
        id: 0,
        account_id: account.id,
        identity: o.identity,
        email_id: o.email_id,
        thread_id: o.thread_id,
        sender: o.sender,
        recipients: o.rcpts,
        blob: String::new(),
        size: o.message.len() as i64,
        send_at: o.hold_until.unwrap_or_else(now).max(now()),
        undo_status: if held { "pending" } else { "final" }.into(),
        delivery: initial_delivery(&[]),
        dsn: o.dsn.to_json(),
        requiretls: o.requiretls,
        created_at: now(),
    };
    if held {
        s.blob = state.blobs.put_message(&o.message).await?;
        s.delivery = initial_delivery(&s.recipients);
        s.id = state.db.create_submission(&s).await?;
        state.event("info", "smtp", &format!("{} holds a message for {} recipient(s) until {}", account.email, s.recipients.len(), s.send_at));
        return Ok(s);
    }
    s.id = state.db.create_submission(&s).await?;
    deliver(state, account, &s, o.message).await;
    Ok(state.db.submission(s.id).await?.unwrap_or(s))
}

fn initial_delivery(rcpts: &[String]) -> String {
    let mut m = Map::new();
    for r in rcpts {
        m.insert(r.clone(), json!({"smtpReply": "250 2.0.0 Held for later", "delivered": "unknown", "displayed": "unknown"}));
    }
    Value::Object(m).to_string()
}

/// Send to every recipient, recording what happened to each.
async fn deliver(state: &State, account: &Account, s: &Submission, message: Vec<u8>) {
    let signed = crate::smtp::delivery::dkim_sign(state, crate::util::domain_of(&s.sender), message).await;
    let dsn = Dsn::from_json(&s.dsn);
    for r in &s.recipients {
        let (delivered, reply) = match crate::smtp::delivery::resolve(state, r, account.can_send_external).await {
            Err(e) => ("no", format!("550 5.1.1 Not sent: {e:?}")),
            Ok(targets) => {
                let mut outcome = ("yes", "250 2.0.0 Delivered".to_string());
                for t in targets {
                    let res = match t {
                        Target::Local(acc) => crate::smtp::deliver_local_from(state, acc, &s.sender, r, &signed, false).await.map(|_| None),
                        Target::Remote(to) => {
                            crate::queue::enqueue_ext(state, &s.sender, &[to], &signed, "", &dsn, s.requiretls).await.map(Some)
                        }
                        Target::Transport(to, tr) => {
                            crate::queue::enqueue_ext(state, &s.sender, &[to], &signed, &format!("transport:{tr}"), &dsn, s.requiretls)
                                .await
                                .map(Some)
                        }
                        // Picked up by a relay peer: queued, without a queue entry to follow.
                        Target::Peer(to, p) => crate::relay::hold_for_peer(state, &p, &s.sender, &[to], &signed).await.map(|_| Some(0)),
                    };
                    match res {
                        Ok(None) => {}
                        Ok(Some(qid)) => {
                            if qid > 0 {
                                let _ = state.db.set_queue_submission(qid, s.id).await;
                            }
                            outcome = ("queued", "250 2.0.0 Queued for delivery".into());
                        }
                        Err(e) => {
                            tracing::warn!("submission {}: {r}: {e:#}", s.id);
                            outcome = ("no", "451 4.3.0 Couldn't be delivered".into());
                        }
                    }
                }
                outcome
            }
        };
        let _ = state.db.set_submission_delivery(s.id, r, delivered, &reply).await;
    }
    state.event("info", "smtp", &format!("{} sent a message to {} recipient(s)", account.email, s.recipients.len()));
}

/// Take back a held submission. False when it was already sent or canceled.
pub async fn cancel(state: &State, id: i64) -> anyhow::Result<bool> {
    match state.db.finish_submission(id, "canceled", None).await? {
        Some(dropped) => {
            state.blobs.delete_all(&dropped).await;
            Ok(true)
        }
        None => Ok(false),
    }
}

/// Send every held submission that's due. Returns how many were sent.
pub async fn release_due(state: &State) -> anyhow::Result<usize> {
    let mut sent = 0;
    for s in state.db.due_submissions(now()).await? {
        // Read the message, then claim the submission; a cancel that got
        // there first wins and nothing is sent.
        let message = match state.blobs.get(&s.blob).await {
            Ok(m) => m.to_vec(),
            Err(e) => {
                tracing::error!("held submission {}: message unreadable: {e:#}", s.id);
                continue;
            }
        };
        let Some(dropped) = state.db.finish_submission(s.id, "final", None).await? else { continue };
        let account = state.db.get_account(s.account_id).await?;
        match account.filter(|a| a.active) {
            Some(a) => {
                deliver(state, &a, &s, message).await;
                sent += 1;
            }
            None => {
                for r in &s.recipients {
                    let _ = state.db.set_submission_delivery(s.id, r, "no", "550 5.7.1 The sending account is disabled").await;
                }
            }
        }
        state.blobs.delete_all(&dropped).await;
    }
    Ok(sent)
}

/// Release held submissions as they come due.
pub fn spawn_worker(state: State) {
    tokio::spawn(async move {
        loop {
            if let Err(e) = release_due(&state).await {
                tracing::error!("held submissions: {e:#}");
            }
            tokio::select! {
                _ = state.shutdown.cancelled() => break,
                _ = tokio::time::sleep(Duration::from_secs(10)) => {}
            }
        }
    });
}

/// The queue reports a remote recipient's outcome.
pub async fn queue_outcome(state: &State, submission_id: i64, rcpt: &str, delivered: bool, reply: &str) {
    if submission_id <= 0 {
        return;
    }
    let reply = if reply.is_empty() { if delivered { "250 2.0.0 Delivered" } else { "550 5.0.0 Failed" } } else { reply };
    let _ = state.db.set_submission_delivery(submission_id, rcpt, if delivered { "yes" } else { "no" }, reply).await;
}
