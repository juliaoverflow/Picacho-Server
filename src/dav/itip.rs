//! Implicit scheduling (RFC 6638), when `dav.server_scheduling` is on.
//!
//! Saving or deleting an event that names attendees makes the server tell
//! them: an organizer's change sends REQUEST (or CANCEL, for attendees
//! taken off and for a deleted event), an attendee's changed answer sends
//! a REPLY to the organizer, and an attendee deleting the event declines
//! it. People with a mailbox here get the message in their scheduling
//! inbox (`calendars/inbox`), and invitations and updates go straight into
//! their default calendar (their answer kept); everyone else gets an iMIP
//! email (RFC 6047) from the organizer's address. Each attendee's
//! SCHEDULE-STATUS says what happened. SCHEDULE-AGENT=CLIENT or NONE and
//! `Schedule-Reply: F` leave the sending to the client.
use super::ical::{self, Comp, Prop};
use super::*;
use std::collections::HashMap;

/// The scheduling inbox, under the calendar home.
pub const INBOX: &str = "calendars/inbox";

/// Whether the server schedules (the admin turned it on).
pub fn on(state: &State) -> bool {
    let s = state.settings();
    s.dav.enabled && s.dav.server_scheduling
}

/// The schedule inbox collection, made on first use.
pub async fn ensure_inbox(state: &State, principal: i64) -> Result<()> {
    if state.db.dav_node(principal, INBOX).await?.is_none() {
        let mut props = Map::new();
        props.insert("displayname".into(), json!("Scheduling inbox"));
        state.db.dav_put(principal, &NewNode { path: INBOX, collection: true, kind: "schedule-inbox", blob: "", size: 0, etag: "", ctype: "", props: &props, uid: "", comp: "", dtstart: None, dtend: None }).await?;
    }
    Ok(())
}

/// The calendar invitations go into: `schedule-default-calendar` if set
/// and still there, else the first calendar taking events.
pub async fn default_calendar(state: &State, principal: i64) -> Result<Option<Node>> {
    let cals: Vec<Node> = state.db.dav_children(principal, "calendars").await?.into_iter().filter(|c| c.collection && c.is_calendar()).collect();
    let inbox = state.db.dav_node(principal, INBOX).await?;
    if let Some(p) = inbox.and_then(|i| i.prop_str("default-calendar")) {
        if let Some(c) = cals.iter().find(|c| c.path == p) {
            return Ok(Some(c.clone()));
        }
    }
    let takes_events = |c: &&Node| c.prop_str("components").map(|x| x.to_ascii_uppercase().contains("VEVENT")).unwrap_or(true);
    Ok(cals.iter().find(takes_events).cloned())
}

pub fn address(v: &str) -> String {
    let v = v.trim();
    let v = if v.len() >= 7 && v[..7].eq_ignore_ascii_case("mailto:") { &v[7..] } else { v };
    v.trim().to_ascii_lowercase()
}

/// The addresses a principal schedules as: its own, and the aliases that
/// deliver to its account.
pub async fn own_addresses(state: &State, p: &Principal) -> Result<Vec<String>> {
    let mut out = vec![address(if p.email.is_empty() { &p.username } else { &p.email })];
    if let Some(id) = p.account_id {
        if let Some(acc) = state.db.get_account(id).await? {
            out.push(acc.email.to_ascii_lowercase());
            for a in state.db.list_aliases().await? {
                if a.active && !a.source.starts_with('@') && a.destination.split([',', ' ']).any(|d| d.trim().eq_ignore_ascii_case(&acc.email)) {
                    out.push(a.source.to_ascii_lowercase());
                }
            }
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}

/// The event components (masters and overrides), not VTIMEZONEs.
fn events(cal: &Comp) -> impl Iterator<Item = &Comp> {
    cal.comps.iter().filter(|c| matches!(c.name.as_str(), "VEVENT" | "VTODO"))
}

fn organizer_of(cal: &Comp) -> Option<&Prop> {
    events(cal).find_map(|c| c.prop("ORGANIZER"))
}

/// Who the server schedules for: SCHEDULE-AGENT absent or SERVER.
fn server_agent(p: &Prop) -> bool {
    p.param("SCHEDULE-AGENT").map(|a| a.eq_ignore_ascii_case("SERVER")).unwrap_or(true)
}

fn mk(name: &str, value: impl Into<String>) -> Prop {
    Prop { name: name.into(), params: vec![], value: value.into() }
}

fn set_param(prop: &mut Prop, k: &str, v: &str) {
    prop.params.retain(|(n, _)| !n.eq_ignore_ascii_case(k));
    prop.params.push((k.into(), v.into()));
}

fn drop_param(prop: &mut Prop, k: &str) {
    prop.params.retain(|(n, _)| !n.eq_ignore_ascii_case(k));
}

/// What changed from the organizer's view, for deciding whether to send.
fn significant(c: &Comp) -> String {
    let keep = ["DTSTART", "DTEND", "DURATION", "DUE", "RRULE", "RDATE", "EXDATE", "SUMMARY", "LOCATION", "DESCRIPTION", "STATUS", "RECURRENCE-ID", "SEQUENCE", "ORGANIZER"];
    let mut v: Vec<String> = c.props.iter().filter(|x| keep.contains(&x.name.as_str())).map(|x| format!("{}={}", x.name, x.value)).collect();
    v.extend(c.props_named("ATTENDEE").map(|a| format!("A={}", address(&a.value))));
    v.sort();
    v.join("\n")
}

/// A component's RECURRENCE-ID, normalized (None for the master).
fn rid(c: &Comp) -> Option<i64> {
    c.prop("RECURRENCE-ID").and_then(ical::prop_when).map(|w| w.utc().timestamp())
}

fn partstat_of(c: &Comp, who: &str) -> String {
    c.props_named("ATTENDEE").find(|a| address(&a.value) == who).and_then(|a| a.param("PARTSTAT")).unwrap_or("NEEDS-ACTION").to_ascii_uppercase()
}

/// An iTIP message: VCALENDAR with METHOD and the given components, plus
/// the VTIMEZONEs they need.
fn itip(method: &str, source: &Comp, comps: Vec<Comp>) -> Comp {
    let mut cal = Comp { name: "VCALENDAR".into(), props: vec![mk("VERSION", "2.0"), mk("PRODID", "-//Picacho Server//CalDAV//EN"), mk("METHOD", method)], comps: vec![] };
    cal.comps.extend(source.sub("VTIMEZONE").cloned());
    cal.comps.extend(comps);
    cal
}

/// The components as attendees should see them: no SCHEDULE-* params, no
/// alarms (those are the organizer's own).
fn for_attendees(c: &Comp) -> Comp {
    let mut c = c.clone();
    c.comps.retain(|x| x.name != "VALARM");
    for prop in c.props.iter_mut().filter(|x| x.name == "ATTENDEE" || x.name == "ORGANIZER") {
        for k in ["SCHEDULE-STATUS", "SCHEDULE-AGENT", "SCHEDULE-FORCE-SEND"] {
            drop_param(prop, k);
        }
    }
    c
}

fn bump_sequence(c: &mut Comp) {
    let n = c.prop("SEQUENCE").and_then(|s| s.value.trim().parse::<i64>().ok()).unwrap_or(0);
    c.props.retain(|x| x.name != "SEQUENCE");
    c.props.push(mk("SEQUENCE", (n + 1).to_string()));
}

fn stamp(c: &mut Comp) {
    c.props.retain(|x| x.name != "DTSTAMP");
    c.props.push(mk("DTSTAMP", ical::fmt_utc(chrono::Utc::now())));
}

/// What happened to one recipient (SCHEDULE-STATUS, RFC 6638 3.2.9).
#[derive(Debug, Clone, Copy, PartialEq)]
enum Sent {
    /// 1.2: delivered to a mailbox here.
    Delivered,
    /// 1.1: sent by email.
    Mailed,
    /// 3.7: not an address that can be sent to.
    Invalid,
    /// 5.1: couldn't be sent.
    Failed,
}

impl Sent {
    fn code(self) -> &'static str {
        match self {
            Sent::Delivered => "1.2",
            Sent::Mailed => "1.1",
            Sent::Invalid => "3.7",
            Sent::Failed => "5.1",
        }
    }
}

/// Deliver one iTIP message from `from` (the sender's own principal) to `to`.
async fn send(state: &State, from: &Principal, from_addr: &str, to: &str, msg: &Comp) -> Sent {
    if to.is_empty() || !to.contains('@') || to.contains(|c: char| c.is_whitespace() || c.is_control() || c == '<' || c == '>') {
        return Sent::Invalid;
    }
    match local_principal(state, to).await {
        Ok(Some(p)) if p.id != from.id => match deliver_local(state, &p, to, msg).await {
            Ok(()) => Sent::Delivered,
            Err(e) => {
                tracing::warn!("scheduling: delivering to {to}: {e:#}");
                Sent::Failed
            }
        },
        // Oneself (another of one's addresses): nothing to send.
        Ok(Some(_)) => Sent::Delivered,
        Ok(None) => match mail(state, from, from_addr, to, msg).await {
            Ok(true) => Sent::Mailed,
            Ok(false) => Sent::Invalid,
            Err(e) => {
                tracing::warn!("scheduling: mailing {to}: {e:#}");
                Sent::Failed
            }
        },
        Err(_) => Sent::Failed,
    }
}

/// The principal an address delivers to here, if any.
async fn local_principal(state: &State, addr: &str) -> Result<Option<Principal>> {
    let db = &state.db;
    let acc = match db.account_by_email(addr).await? {
        Some(a) => Some(a),
        None => match db.alias_by_source(addr).await?.filter(|a| a.active) {
            Some(alias) => {
                let mut found = None;
                for d in alias.destination.split([',', ' ']).map(str::trim).filter(|d| !d.is_empty()) {
                    if let Some(a) = db.account_by_email(d).await? {
                        found = Some(a);
                        break;
                    }
                }
                found
            }
            None => None,
        },
    };
    match acc.filter(|a| a.active) {
        Some(a) => Ok(principal_for_account(state, &a).await?.filter(|p| p.active)),
        None => Ok(None),
    }
}

/// Into the recipient's inbox; a REQUEST or CANCEL also updates their copy
/// of the event (keeping their answer and alarms), a REPLY the organizer's.
async fn deliver_local(state: &State, p: &Principal, to: &str, msg: &Comp) -> Result<()> {
    ensure_homes(state, p).await?;
    ensure_inbox(state, p.id).await?;
    let text = ical::serialize(msg);
    let name = format!("{INBOX}/{}.ics", uuid::Uuid::new_v4().simple());
    let key = write_blob(state, "calendars", text.as_bytes()).await?;
    let uid = events(msg).find_map(|c| c.prop("UID")).map(|u| u.value.clone()).unwrap_or_default();
    let comp = events(msg).next().map(|c| c.name.clone()).unwrap_or_default();
    let (ds, de) = ical::bounds(msg);
    state
        .db
        .dav_put(p.id, &NewNode { path: &name, collection: false, kind: "", blob: &key, size: text.len() as i64, etag: &etag_of(text.as_bytes()), ctype: "text/calendar; charset=utf-8", props: &Map::new(), uid: &uid, comp: &comp, dtstart: ds, dtend: de })
        .await?;
    record_change(state, p.id, &name, false).await;
    let method = msg.prop("METHOD").map(|m| m.value.to_ascii_uppercase()).unwrap_or_default();
    match method.as_str() {
        "REQUEST" | "CANCEL" => apply_to_attendee(state, p, to, &uid, msg, method == "CANCEL").await,
        "REPLY" => apply_reply(state, p, &uid, msg).await,
        _ => Ok(()),
    }
}

/// Where a principal keeps the event with this UID, if anywhere.
async fn find_event(state: &State, pid: i64, uid: &str) -> Result<Option<Node>> {
    for cal in state.db.dav_children(pid, "calendars").await?.into_iter().filter(|c| c.collection && c.is_calendar()) {
        if let Some(n) = state.db.dav_by_uid(pid, &cal.path, uid).await? {
            return Ok(Some(n));
        }
    }
    Ok(None)
}

async fn write_event(state: &State, p: &Principal, path: &str, cal: &Comp) -> Result<()> {
    if let Err(e) = store::put(state, p, path, ical::serialize(cal).as_bytes()).await? {
        anyhow::bail!("couldn't store the event: {e}");
    }
    Ok(())
}

/// An invitation (or its cancellation) in the attendee's own calendar.
async fn apply_to_attendee(state: &State, p: &Principal, me: &str, uid: &str, msg: &Comp, cancel: bool) -> Result<()> {
    let existing = find_event(state, p.id, uid).await?;
    let old = match &existing {
        Some(n) => ical::parse(&store::read(state, n).await?).ok(),
        None => None,
    };
    let incoming: Vec<Comp> = events(msg).cloned().collect();
    let whole = incoming.iter().any(|c| rid(c).is_none());
    let mut cal = match (&old, whole) {
        // A new version of the whole event: replace what's there.
        (_, true) => Comp { name: "VCALENDAR".into(), props: vec![mk("VERSION", "2.0"), mk("PRODID", "-//Picacho Server//CalDAV//EN")], comps: vec![] },
        (Some(o), false) => o.clone(),
        // Just some occurrences of an event not here: take them as they are.
        (None, false) => Comp { name: "VCALENDAR".into(), props: vec![mk("VERSION", "2.0"), mk("PRODID", "-//Picacho Server//CalDAV//EN")], comps: vec![] },
    };
    if cancel {
        let Some(n) = existing else { return Ok(()) };
        if whole {
            // The organizer called it off: it stays, marked cancelled, until
            // the attendee removes it, so they see what happened.
            let mut c = old.unwrap_or(cal);
            for e in c.comps.iter_mut().filter(|c| matches!(c.name.as_str(), "VEVENT" | "VTODO")) {
                e.props.retain(|x| x.name != "STATUS");
                e.props.push(mk("STATUS", "CANCELLED"));
            }
            return write_event(state, p, &n.path, &c).await;
        }
        // Single occurrences: excluded from the series.
        for c in &incoming {
            if let Some(r) = c.prop("RECURRENCE-ID").cloned() {
                cal.comps.retain(|x| !(matches!(x.name.as_str(), "VEVENT" | "VTODO") && rid(x) == rid(c)));
                if let Some(m) = cal.comps.iter_mut().find(|x| matches!(x.name.as_str(), "VEVENT" | "VTODO") && rid(x).is_none()) {
                    m.props.push(Prop { name: "EXDATE".into(), params: r.params.clone(), value: r.value.clone() });
                }
            }
        }
        return write_event(state, p, &n.path, &cal).await;
    }
    // Keep the attendee's own answer and alarms for each occurrence.
    let mine = |c: Option<&Comp>| -> (Option<String>, Vec<Comp>) {
        let Some(c) = c else { return (None, vec![]) };
        let ps = c.props_named("ATTENDEE").find(|a| address(&a.value) == me).and_then(|a| a.param("PARTSTAT")).map(String::from);
        (ps, c.sub("VALARM").cloned().collect())
    };
    for mut c in incoming {
        let before = old.as_ref().and_then(|o| events(o).find(|x| rid(x) == rid(&c)).cloned());
        let (ps, alarms) = mine(before.as_ref());
        // The attendee's answer stays unless the organizer asks again
        // (NEEDS-ACTION after a change of time, RFC 6638 3.2.8).
        let asked_again = partstat_of(&c, me) == "NEEDS-ACTION" && before.as_ref().is_some_and(|b| b.prop("DTSTART").map(|x| &x.value) != c.prop("DTSTART").map(|x| &x.value));
        if let Some(ps) = ps.filter(|_| !asked_again) {
            for a in c.props.iter_mut().filter(|a| a.name == "ATTENDEE" && address(&a.value) == me) {
                set_param(a, "PARTSTAT", &ps);
            }
        }
        c.comps.extend(alarms);
        cal.comps.retain(|x| !(matches!(x.name.as_str(), "VEVENT" | "VTODO") && rid(x) == rid(&c)));
        cal.comps.push(c);
    }
    let tzids: Vec<String> = cal.sub("VTIMEZONE").filter_map(|t| t.prop("TZID")).map(|t| t.value.clone()).collect();
    for tz in msg.sub("VTIMEZONE") {
        if !tz.prop("TZID").is_some_and(|t| tzids.contains(&t.value)) {
            cal.comps.insert(0, tz.clone());
        }
    }
    let path = match existing {
        Some(n) => n.path,
        None => {
            let Some(target) = default_calendar(state, p.id).await? else { return Ok(()) };
            format!("{}/{}.ics", target.path, safe_name(uid))
        }
    };
    write_event(state, p, &path, &cal).await
}

fn safe_name(uid: &str) -> String {
    let s: String = uid.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@')).take(100).collect();
    if s.is_empty() { uuid::Uuid::new_v4().simple().to_string() } else { s }
}

/// An attendee's answer, written into the organizer's copy.
async fn apply_reply(state: &State, p: &Principal, uid: &str, msg: &Comp) -> Result<()> {
    let Some(n) = find_event(state, p.id, uid).await? else { return Ok(()) };
    let Ok(mut cal) = ical::parse(&store::read(state, &n).await?) else { return Ok(()) };
    let mut changed = false;
    for answer in events(msg) {
        for a in answer.props_named("ATTENDEE") {
            let who = address(&a.value);
            let Some(ps) = a.param("PARTSTAT") else { continue };
            let r = rid(answer);
            let targets: Vec<&mut Comp> = cal.comps.iter_mut().filter(|c| matches!(c.name.as_str(), "VEVENT" | "VTODO") && (r.is_none() || rid(c) == r)).collect();
            for c in targets {
                for x in c.props.iter_mut().filter(|x| x.name == "ATTENDEE" && address(&x.value) == who) {
                    set_param(x, "PARTSTAT", ps);
                    set_param(x, "SCHEDULE-STATUS", "2.0");
                    changed = true;
                }
            }
        }
    }
    if changed {
        write_event(state, p, &n.path, &cal).await?;
    }
    Ok(())
}

/// An iMIP email (RFC 6047) to someone without a mailbox here.
async fn mail(state: &State, from: &Principal, from_addr: &str, to: &str, msg: &Comp) -> Result<bool> {
    use base64::Engine;
    let Some(acc_id) = from.account_id else { return Ok(false) };
    let Some(acc) = state.db.get_account(acc_id).await?.filter(|a| a.active) else { return Ok(false) };
    if !acc.can_send_external {
        return Ok(false);
    }
    let limit = state.settings().limits.send_rate_per_hour;
    if limit > 0 && state.db.record_send(acc.id).await? > limit as i64 {
        anyhow::bail!("hourly sending limit reached");
    }
    let method = msg.prop("METHOD").map(|m| m.value.to_ascii_uppercase()).unwrap_or_default();
    let ev = events(msg).next();
    let summary = ev.and_then(|e| e.prop("SUMMARY")).map(|s| s.value.replace("\\,", ",").replace("\\;", ";").replace("\\n", " ")).unwrap_or_else(|| "Event".into());
    let name = if from.display_name.is_empty() { acc.display_name.clone() } else { from.display_name.clone() };
    let (subject, text) = match method.as_str() {
        "REQUEST" => (format!("Invitation: {summary}"), format!("{} invites you to {summary}.", if name.is_empty() { from_addr } else { &name })),
        "CANCEL" => (format!("Cancelled: {summary}"), format!("{summary} was cancelled.")),
        _ => {
            let ps = ev.map(|e| partstat_of(e, from_addr)).unwrap_or_default();
            let verb = match ps.as_str() {
                "ACCEPTED" => "Accepted",
                "DECLINED" => "Declined",
                "TENTATIVE" => "Tentative",
                _ => "Answer",
            };
            (format!("{verb}: {summary}"), format!("{} answered: {}.", if name.is_empty() { from_addr } else { &name }, verb.to_ascii_lowercase()))
        }
    };
    let host = state.hostname();
    let boundary = format!("itip-{}", uuid::Uuid::new_v4().simple());
    let from_hdr = if name.is_empty() { format!("<{from_addr}>") } else { format!("\"{}\" <{from_addr}>", name.replace(['"', '\r', '\n'], "")) };
    let b64 = |s: &str| {
        let e = base64::engine::general_purpose::STANDARD.encode(s.as_bytes());
        e.as_bytes().chunks(76).map(|c| String::from_utf8_lossy(c).into_owned()).collect::<Vec<_>>().join("\r\n")
    };
    let ics = ical::serialize(msg);
    let m = format!(
        "From: {from_hdr}\r\nTo: <{to}>\r\nSubject: =?UTF-8?B?{}?=\r\nDate: {}\r\nMessage-ID: <{}@{host}>\r\nMIME-Version: 1.0\r\n\
         Content-Type: multipart/alternative; boundary=\"{boundary}\"\r\n\r\n\
         --{boundary}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n{}\r\n\
         --{boundary}\r\nContent-Type: text/calendar; charset=utf-8; method={method}\r\nContent-Transfer-Encoding: base64\r\n\r\n{}\r\n\
         --{boundary}--\r\n",
        base64::engine::general_purpose::STANDARD.encode(subject.as_bytes()),
        chrono::Utc::now().to_rfc2822(),
        uuid::Uuid::new_v4().simple(),
        b64(&text),
        b64(&ics),
    );
    let signed = crate::smtp::delivery::dkim_sign(state, crate::util::domain_of(from_addr), m.into_bytes()).await;
    match crate::smtp::delivery::resolve(state, to, true).await {
        Ok(targets) => {
            for t in targets {
                crate::smtp::deliver_target(state, from_addr, &signed, t, false).await?;
            }
            Ok(true)
        }
        Err(crate::smtp::delivery::RcptError::Temporary) => anyhow::bail!("temporary lookup failure"),
        Err(_) => Ok(false),
    }
}

/// A change to one of a principal's calendar objects, as saved.
pub struct Change<'a> {
    pub old: Option<&'a Comp>,
    /// None: the event was deleted.
    pub new: Option<&'a Comp>,
    /// `Schedule-Reply: F`: the attendee's change isn't sent.
    pub no_reply: bool,
}

/// Send what a change calls for. Returns the object to store instead (with
/// SCHEDULE-STATUS, SEQUENCE), or None to store it as given.
pub async fn on_change(state: &State, p: &Principal, ch: Change<'_>) -> Result<Option<Comp>> {
    if !on(state) {
        return Ok(None);
    }
    let Some(any) = ch.new.or(ch.old) else { return Ok(None) };
    let Some(org) = organizer_of(any) else { return Ok(None) };
    let organizer = address(&org.value);
    let mine = own_addresses(state, p).await?;
    if mine.contains(&organizer) {
        if !server_agent(org) {
            return Ok(None);
        }
        return as_organizer(state, p, &organizer, ch).await;
    }
    // An attendee here: an answer that changed goes to the organizer.
    let me = events(any).flat_map(|c| c.props_named("ATTENDEE")).map(|a| address(&a.value)).find(|a| mine.contains(a));
    let Some(me) = me else { return Ok(None) };
    let agent_ok = events(any).flat_map(|c| c.props_named("ATTENDEE")).find(|a| address(&a.value) == me).is_some_and(server_agent);
    // Removing an event its organizer cancelled says nothing more.
    let cancelled = ch.new.is_none() && ch.old.is_some_and(|o| events(o).all(|c| c.prop("STATUS").is_some_and(|s| s.value.eq_ignore_ascii_case("CANCELLED"))));
    if !agent_ok || ch.no_reply || cancelled {
        return Ok(None);
    }
    as_attendee(state, p, &me, org, ch).await?;
    Ok(None)
}

async fn as_organizer(state: &State, p: &Principal, me: &str, ch: Change<'_>) -> Result<Option<Comp>> {
    let Some(new) = ch.new else {
        // Deleted: everyone is told it's cancelled.
        let Some(old) = ch.old else { return Ok(None) };
        let mut cancels = vec![];
        for c in events(old) {
            let mut x = for_attendees(c);
            x.props.retain(|q| q.name != "STATUS");
            x.props.push(mk("STATUS", "CANCELLED"));
            bump_sequence(&mut x);
            stamp(&mut x);
            cancels.push(x);
        }
        let msg = itip("CANCEL", old, cancels);
        for who in attendees(old, me) {
            send(state, p, me, &who, &msg).await;
        }
        return Ok(None);
    };
    let mut out = new.clone();
    let old_people: Vec<String> = ch.old.map(|o| attendees(o, me)).unwrap_or_default();
    let new_people = attendees(new, me);
    // Taken off the event: told it's cancelled for them.
    if let Some(old) = ch.old {
        let gone: Vec<String> = old_people.iter().filter(|a| !new_people.contains(a)).cloned().collect();
        if !gone.is_empty() {
            let cancels = events(old).map(|c| {
                let mut x = for_attendees(c);
                x.props.push(mk("STATUS", "CANCELLED"));
                bump_sequence(&mut x);
                stamp(&mut x);
                x
            });
            let msg = itip("CANCEL", old, cancels.collect());
            for who in gone {
                send(state, p, me, &who, &msg).await;
            }
        }
    }
    // A REQUEST when something that matters changed (or forced, or new people).
    let changed = match ch.old {
        None => true,
        Some(old) => {
            let a: Vec<String> = events(old).map(significant).collect();
            let b: Vec<String> = events(new).map(significant).collect();
            a != b
        }
    };
    let forced: Vec<String> = events(new)
        .flat_map(|c| c.props_named("ATTENDEE"))
        .filter(|a| a.param("SCHEDULE-FORCE-SEND").is_some_and(|v| v.eq_ignore_ascii_case("REQUEST")))
        .map(|a| address(&a.value))
        .collect();
    let to: Vec<String> = new_people.iter().filter(|a| changed || forced.contains(a) || !old_people.contains(a)).cloned().collect();
    if !to.is_empty() {
        if changed && ch.old.is_some() {
            for c in out.comps.iter_mut().filter(|c| matches!(c.name.as_str(), "VEVENT" | "VTODO")) {
                bump_sequence(c);
                // A new time asks everyone again (RFC 6638 3.2.8).
                let before = ch.old.and_then(|o| events(o).find(|x| rid(x) == rid(c)).cloned());
                let moved = before.is_some_and(|b| ["DTSTART", "DTEND", "DURATION", "DUE", "RRULE", "RDATE", "EXDATE"].iter().any(|k| b.prop(k).map(|x| &x.value) != c.prop(k).map(|x| &x.value)));
                if moved {
                    for a in c.props.iter_mut().filter(|a| a.name == "ATTENDEE" && address(&a.value) != me && server_agent(a)) {
                        set_param(a, "PARTSTAT", "NEEDS-ACTION");
                    }
                }
            }
        }
        let comps: Vec<Comp> = events(&out).map(|c| {
            let mut x = for_attendees(c);
            stamp(&mut x);
            x
        }).collect();
        let msg = itip("REQUEST", &out, comps);
        let mut status = HashMap::new();
        for who in &to {
            status.insert(who.clone(), send(state, p, me, who, &msg).await);
        }
        for c in out.comps.iter_mut().filter(|c| matches!(c.name.as_str(), "VEVENT" | "VTODO")) {
            for a in c.props.iter_mut().filter(|a| a.name == "ATTENDEE") {
                drop_param(a, "SCHEDULE-FORCE-SEND");
                if let Some(s) = status.get(&address(&a.value)) {
                    set_param(a, "SCHEDULE-STATUS", s.code());
                }
            }
        }
    }
    Ok(Some(out))
}

/// Everyone the server sends to for this event, not the organizer.
fn attendees(cal: &Comp, organizer: &str) -> Vec<String> {
    let mut v: Vec<String> = events(cal)
        .flat_map(|c| c.props_named("ATTENDEE"))
        .filter(|a| server_agent(a))
        .filter(|a| !a.param("CUTYPE").is_some_and(|t| t.eq_ignore_ascii_case("GROUP")))
        .map(|a| address(&a.value))
        .filter(|a| a != organizer && !a.is_empty())
        .collect();
    v.sort();
    v.dedup();
    v
}

async fn as_attendee(state: &State, p: &Principal, me: &str, org: &Prop, ch: Change<'_>) -> Result<()> {
    let organizer = address(&org.value);
    let Some(any) = ch.new.or(ch.old) else { return Ok(()) };
    let mut answers = vec![];
    for c in events(any) {
        let before = ch.old.and_then(|o| events(o).find(|x| rid(x) == rid(c))).map(|x| partstat_of(x, me));
        let after = match ch.new {
            // Deleting an invitation declines it.
            None => "DECLINED".to_string(),
            Some(n) => match events(n).find(|x| rid(x) == rid(c)) {
                Some(x) => partstat_of(x, me),
                None => "DECLINED".into(),
            },
        };
        if before.as_deref() == Some(after.as_str()) || (ch.new.is_none() && before.as_deref() == Some("DECLINED")) {
            continue;
        }
        let mut r = Comp { name: c.name.clone(), ..Default::default() };
        for k in ["UID", "RECURRENCE-ID", "SEQUENCE", "DTSTART", "SUMMARY"] {
            if let Some(x) = c.prop(k) {
                r.props.push(x.clone());
            }
        }
        let mut o = org.clone();
        drop_param(&mut o, "SCHEDULE-STATUS");
        drop_param(&mut o, "SCHEDULE-AGENT");
        r.props.push(o);
        let mut a = c.props_named("ATTENDEE").find(|a| address(&a.value) == me).cloned().unwrap_or_else(|| mk("ATTENDEE", format!("mailto:{me}")));
        for k in ["SCHEDULE-STATUS", "SCHEDULE-AGENT", "RSVP"] {
            drop_param(&mut a, k);
        }
        set_param(&mut a, "PARTSTAT", &after);
        r.props.push(a);
        stamp(&mut r);
        answers.push(r);
    }
    if answers.is_empty() {
        return Ok(());
    }
    let msg = itip("REPLY", any, answers);
    send(state, p, me, &organizer, &msg).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn what_counts_as_a_change() {
        let cal = ical::parse("BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:x\r\nDTSTART:20261201T100000Z\r\nSUMMARY:A\r\nATTENDEE;PARTSTAT=ACCEPTED;SCHEDULE-STATUS=1.2:mailto:Amy@example.test\r\nORGANIZER:mailto:bob@example.test\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n").unwrap();
        let e = events(&cal).next().unwrap();
        let mut answered = e.clone();
        for a in answered.props.iter_mut().filter(|a| a.name == "ATTENDEE") {
            set_param(a, "PARTSTAT", "DECLINED");
        }
        assert_eq!(significant(e), significant(&answered), "an answer isn't the organizer's change");
        assert_eq!(attendees(&cal, "bob@example.test"), ["amy@example.test"]);
        let out = for_attendees(e);
        assert!(out.props_named("ATTENDEE").all(|a| a.param("SCHEDULE-STATUS").is_none()));
        assert_eq!(address("MAILTO:Amy@Example.test"), "amy@example.test");
    }
}
