//! Local delivery through Sieve: decide where a message goes (plan), then
//! do it (execute): store, redirect, reject, discard and vacation replies.
use super::interp::{self, Action, Env, Vacation};
use crate::state::State;
use std::collections::HashMap;

#[derive(Debug, Default)]
pub struct Plan {
    /// (folder, flags) to store the message in.
    pub stores: Vec<(String, Vec<String>)>,
    pub redirects: Vec<String>,
    pub reject: Option<String>,
    pub vacation: Option<Vacation>,
    /// Account address the message arrived for (vacation From).
    pub rcpt: String,
}

fn default_folder(junk: bool) -> String {
    if junk { "Junk" } else { "INBOX" }.to_string()
}

/// Header fields, unfolded and RFC 2047-decoded, lower-case names.
fn headers(raw: &[u8]) -> Vec<(String, String)> {
    let end = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap_or(raw.len());
    let head = &raw[..end];
    let mut out: Vec<(String, String)> = vec![];
    for line in head.split(|b| *b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.first().is_some_and(|c| *c == b' ' || *c == b'\t') {
            if let Some(last) = out.last_mut() {
                last.1.push(' ');
                last.1.push_str(String::from_utf8_lossy(line).trim());
            }
            continue;
        }
        if let Some(p) = line.iter().position(|c| *c == b':') {
            out.push((String::from_utf8_lossy(&line[..p]).trim().to_ascii_lowercase(), String::from_utf8_lossy(&line[p + 1..]).trim().to_string()));
        }
    }
    for (_, v) in out.iter_mut() {
        if v.contains("=?") {
            *v = crate::mime::decode_rfc2047(v.as_bytes());
        }
    }
    out
}

fn body_text(raw: &[u8]) -> String {
    let Some(msg) = mail_parser::MessageParser::default().parse(raw) else { return String::new() };
    let mut t: String = msg.text_bodies().collect::<Vec<_>>().join("\n");
    if t.is_empty() {
        t = msg.html_bodies().map(|h| crate::filter::bayes::strip_html(&h)).collect::<Vec<_>>().join("\n");
    }
    t.chars().take(1024 * 1024).collect()
}

/// RFC 5235 spamtest value from our own X-Spam-Status header.
fn spamtest(state: &State, hdrs: &[(String, String)]) -> u8 {
    let Some((_, v)) = hdrs.iter().find(|(n, _)| n == "x-spam-status") else { return 0 };
    let score: f64 = v.split("score=").nth(1).and_then(|s| s.split(|c: char| c == ',' || c.is_whitespace()).next()).and_then(|s| s.parse().ok()).unwrap_or(0.0);
    let reject = state.settings().filter.reject_score.max(1.0);
    (1.0 + (score.max(0.0) / reject * 9.0).round().min(9.0)) as u8
}

pub async fn plan(state: &State, account_id: i64, sender: &str, rcpt: &str, raw: &[u8], junk: bool) -> Plan {
    let mut plan = Plan { rcpt: rcpt.to_string(), ..Default::default() };
    let active = state.db.sieve_active(account_id).await.ok().flatten();
    let vac = state.db.vacation(account_id).await.unwrap_or_default();
    let Some(active) = active else {
        plan.stores.push((default_folder(junk), vec![]));
        if vac.active_at(crate::util::now()) {
            plan.vacation = Some(jmap_vacation(&vac));
        }
        return plan;
    };
    let script = match super::parse::parse(&active.content) {
        Ok(s) => s,
        Err(e) => {
            state.event("warn", "sieve", &format!("account {account_id}: script \"{}\" has an error ({e}); keeping message", active.name));
            plan.stores.push((default_folder(junk), vec![]));
            return plan;
        }
    };
    // Other scripts are available to `include`.
    let mut scripts = HashMap::new();
    if script.requires.iter().any(|r| r == "include") {
        for s in state.db.sieve_scripts(account_id).await.unwrap_or_default() {
            if let Ok(p) = super::parse::parse(&s.content) {
                scripts.insert(s.name, p);
            }
        }
    }
    let folders: Vec<String> = state.db.list_mailboxes(account_id).await.unwrap_or_default().into_iter().map(|m| m.name).collect();
    let raw_owned = raw.to_vec();
    let hdrs = headers(raw);
    let spam = spamtest(state, &hdrs);
    let virus = if hdrs.iter().any(|(n, _)| n == "x-spam-status") { 1 } else { 0 };
    let envelope_from = sender.to_string();
    let envelope_to = rcpt.to_string();
    let outcome = tokio::task::spawn_blocking(move || {
        let text = body_text(&raw_owned);
        let env = Env {
            headers: hdrs,
            body_text: &text,
            raw: &raw_owned,
            size: raw_owned.len() as u64,
            envelope_from,
            envelope_to,
            folders,
            scripts,
            spamtest: spam,
            virustest: virus,
            now: chrono::Utc::now(),
        };
        interp::run(&script, &env)
    })
    .await;
    let Ok(outcome) = outcome else {
        plan.stores.push((default_folder(junk), vec![]));
        return plan;
    };
    for e in &outcome.errors {
        state.event("warn", "sieve", &format!("account {account_id}: {e}; keeping message"));
    }
    for a in outcome.actions {
        crate::metrics::SIEVE_ACTIONS.inc();
        match a {
            Action::FileInto { folder, flags, .. } => plan.stores.push((folder, flags)),
            Action::Keep { flags } => plan.stores.push((default_folder(junk), flags)),
            Action::Redirect { addr } => plan.redirects.push(addr),
            Action::Reject { reason } => plan.reject = Some(reason),
            Action::Discard => {}
            Action::Vacation(v) => plan.vacation = Some(v),
        }
    }
    if outcome.keep {
        plan.stores.push((default_folder(junk), outcome.flags));
    }
    // A JMAP/console vacation reply applies when the script has none.
    if plan.vacation.is_none() && vac.active_at(crate::util::now()) && plan.reject.is_none() {
        plan.vacation = Some(jmap_vacation(&vac));
    }
    plan
}

fn jmap_vacation(v: &super::VacationSettings) -> Vacation {
    Vacation {
        seconds: v.days.max(1) * 86400,
        subject: v.subject.clone(),
        from: None,
        addresses: vec![],
        mime: false,
        handle: "jmap".into(),
        reason: v.text_body.clone().unwrap_or_else(|| v.html_body.as_deref().map(crate::filter::bayes::strip_html).unwrap_or_default()),
    }
}

pub async fn execute(state: &State, account_id: i64, sender: &str, raw: &[u8], plan: Plan) -> anyhow::Result<()> {
    let mut seen = std::collections::BTreeSet::new();
    for (folder, flags) in &plan.stores {
        if !seen.insert(folder.to_ascii_lowercase()) {
            continue;
        }
        crate::smtp::store_in(state, account_id, folder, raw, &flags.join(" ")).await?;
    }
    for addr in &plan.redirects {
        let env_from = if sender.is_empty() { String::new() } else { crate::smtp::delivery::srs_forward(state, sender).await };
        crate::queue::enqueue(state, &env_from, std::slice::from_ref(addr), raw, "").await?;
    }
    if let Some(reason) = &plan.reject {
        if !sender.is_empty() {
            let notes = vec![crate::queue::Notice { rcpt: plan.rcpt.clone(), action: "failed", status: "5.7.1".into(), diag: format!("550 5.7.1 {reason}") }];
            let dsn = crate::queue::build_dsn(state, sender, raw, &Default::default(), &notes);
            let _ = crate::queue::send_report(state, sender, &dsn).await;
        }
    }
    if let Some(v) = &plan.vacation {
        if let Err(e) = vacation_reply(state, account_id, sender, &plan.rcpt, raw, v).await {
            tracing::debug!("vacation reply: {e:#}");
        }
    }
    Ok(())
}

/// RFC 5230 4.5-4.6: when not to answer.
fn should_reply(hdrs: &[(String, String)], sender: &str, own: &[String]) -> bool {
    if sender.is_empty() {
        return false;
    }
    let local = sender.split('@').next().unwrap_or("").to_ascii_lowercase();
    if ["mailer-daemon", "listserv", "majordomo", "postmaster", "noreply", "no-reply"].contains(&local.as_str())
        || local.starts_with("owner-")
        || local.ends_with("-request")
        || local.ends_with("-bounces")
    {
        return false;
    }
    if own.iter().any(|o| o.eq_ignore_ascii_case(sender)) {
        return false;
    }
    for (n, v) in hdrs {
        let lv = v.to_ascii_lowercase();
        match n.as_str() {
            "auto-submitted" if lv.trim() != "no" => return false,
            "precedence" if ["bulk", "list", "junk"].contains(&lv.trim()) => return false,
            "list-id" | "list-unsubscribe" | "list-post" | "x-auto-response-suppress" => return false,
            "x-spam-flag" if lv.trim() == "yes" => return false,
            _ => {}
        }
    }
    // Only when we're a visible recipient.
    hdrs.iter()
        .filter(|(n, _)| matches!(n.as_str(), "to" | "cc" | "bcc" | "resent-to" | "resent-cc"))
        .flat_map(|(_, v)| interp::addresses(v))
        .any(|a| own.iter().any(|o| o.eq_ignore_ascii_case(&a)))
}

async fn vacation_reply(state: &State, account_id: i64, sender: &str, rcpt: &str, raw: &[u8], v: &Vacation) -> anyhow::Result<()> {
    let Some(acc) = state.db.get_account(account_id).await? else { return Ok(()) };
    let hdrs = headers(raw);
    let mut own = vec![acc.email.clone()];
    if !rcpt.is_empty() {
        own.push(rcpt.to_string());
    }
    own.extend(v.addresses.iter().cloned());
    for a in state.db.list_aliases().await.unwrap_or_default() {
        if a.destination.split([',', ' ']).any(|d| d.trim().eq_ignore_ascii_case(&acc.email)) {
            own.push(a.source.clone());
        }
    }
    if !should_reply(&hdrs, sender, &own) {
        return Ok(());
    }
    if !state.db.vacation_should_send(account_id, &v.handle, sender, v.seconds.max(1)).await? {
        return Ok(());
    }
    let orig_subject = hdrs.iter().find(|(n, _)| n == "subject").map(|(_, v)| v.clone()).unwrap_or_default();
    let subject = v.subject.clone().unwrap_or_else(|| format!("Auto: {orig_subject}"));
    let msgid = hdrs.iter().find(|(n, _)| n == "message-id").map(|(_, v)| v.clone());
    let refs = hdrs.iter().find(|(n, _)| n == "references").map(|(_, v)| v.clone());
    let from = v.from.clone().unwrap_or_else(|| {
        if acc.display_name.is_empty() {
            format!("<{}>", acc.email)
        } else {
            format!("\"{}\" <{}>", acc.display_name.replace('"', ""), acc.email)
        }
    });
    let host = state.hostname();
    let mut m = format!(
        "From: {from}\r\nTo: <{sender}>\r\nSubject: {}\r\nDate: {}\r\nMessage-ID: <{}@{host}>\r\nAuto-Submitted: auto-replied (vacation)\r\nPrecedence: bulk\r\nMIME-Version: 1.0\r\n",
        encode_header(&subject),
        chrono::Utc::now().to_rfc2822(),
        uuid::Uuid::new_v4().simple()
    );
    if let Some(id) = &msgid {
        m.push_str(&format!("In-Reply-To: {id}\r\nReferences: {}{id}\r\n", refs.map(|r| format!("{r} ")).unwrap_or_default()));
    }
    if v.mime {
        // The reason is a MIME entity (headers + body).
        m.push_str(&v.reason.replace("\r\n", "\n").replace('\n', "\r\n"));
    } else {
        m.push_str("Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n");
        m.push_str(&v.reason.replace("\r\n", "\n").replace('\n', "\r\n"));
    }
    if !m.ends_with("\r\n") {
        m.push_str("\r\n");
    }
    let signed = crate::smtp::delivery::dkim_sign(state, crate::util::domain_of(&acc.email), m.into_bytes()).await;
    crate::queue::send_report(state, sender, &signed).await?;
    state.event("info", "sieve", &format!("vacation reply from {} to {sender}", acc.email));
    Ok(())
}

fn encode_header(s: &str) -> String {
    use base64::Engine;
    if s.is_ascii() {
        s.to_string()
    } else {
        format!("=?utf-8?B?{}?=", base64::engine::general_purpose::STANDARD.encode(s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reply_rules() {
        let own = vec!["bob@example.org".to_string()];
        let h = |extra: (&str, &str)| vec![("to".to_string(), "Bob <bob@example.org>".to_string()), (extra.0.to_string(), extra.1.to_string())];
        assert!(should_reply(&h(("subject", "hi")), "alice@example.com", &own));
        assert!(!should_reply(&h(("precedence", "bulk")), "alice@example.com", &own));
        assert!(!should_reply(&h(("list-id", "<x>")), "alice@example.com", &own));
        assert!(!should_reply(&h(("subject", "hi")), "owner-list@example.com", &own));
        assert!(!should_reply(&h(("subject", "hi")), "", &own));
        assert!(!should_reply(&[("to".into(), "other@example.org".into())], "alice@example.com", &own));
    }
    #[test]
    fn header_parse() {
        let h = headers(b"Subject: =?utf-8?B?SMOpbGxv?=\r\nTo: a@b.c,\r\n d@e.f\r\n\r\nbody");
        assert_eq!(h[0], ("subject".into(), "Héllo".into()));
        assert_eq!(h[1].1, "a@b.c, d@e.f");
    }
}
