//! The scheduling outbox (RFC 6638 section 5): free/busy lookups.
//!
//! A calendar app POSTs a VFREEBUSY request (METHOD:REQUEST) naming the
//! organizer, the attendees and a time range to the principal's
//! `schedule-outbox-URL`; the answer is a `schedule-response` with each
//! attendee's busy time (METHOD:REPLY). Attendees with a mailbox on this
//! server are answered from their calendars; others get "3.7 Invalid
//! calendar user". Only busy times are shared, never what the events are.
//!
//! Invitations themselves are sent when events are saved (implicit
//! scheduling, `itip.rs`), not through the outbox.
use super::ical::{self, Comp, Prop};
use super::{empty, Ctx, CALDAV, DAV};
use crate::xml::Writer;
use anyhow::Result;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};

/// The outbox's path under a user's calendar home.
pub const OUTBOX: &str = "calendars/outbox";

/// Busy periods in [rs, re) across a principal's calendars that count for
/// free/busy (not marked transparent), merged.
async fn busy_of(ctx: &Ctx, principal: i64, rs: DateTime<Utc>, re: DateTime<Utc>) -> Result<Vec<(DateTime<Utc>, DateTime<Utc>, String)>> {
    let db = &ctx.state.db;
    let mut periods = vec![];
    for cal in db.dav_children(principal, "calendars").await?.into_iter().filter(|c| c.collection && c.is_calendar()) {
        if cal.prop_str("transp").is_some_and(|t| t.to_ascii_lowercase().contains("transparent")) {
            continue;
        }
        let tz = cal.prop_str("timezone").and_then(|t| ical::timezone_of(&t));
        for n in db.dav_children(principal, &cal.path).await?.into_iter().filter(|x| !x.collection) {
            let Ok(data) = super::read_blob(&ctx.state, &n).await else { continue };
            let Ok(mut obj) = ical::parse(&String::from_utf8_lossy(&data)) else { continue };
            if let Some(tz) = &tz {
                ical::apply_floating(&mut obj, tz);
            }
            periods.extend(ical::busy(&obj, rs, re));
        }
    }
    // Merge across resources, as free-busy-query does.
    let all = Comp {
        name: "VCALENDAR".into(),
        props: vec![],
        comps: vec![Comp {
            name: "VFREEBUSY".into(),
            props: periods
                .iter()
                .map(|(a, b, k)| Prop { name: "FREEBUSY".into(), params: vec![("FBTYPE".into(), k.clone())], value: format!("{}/{}", ical::fmt_utc(*a), ical::fmt_utc(*b)) })
                .collect(),
            comps: vec![],
        }],
    };
    Ok(ical::busy(&all, rs, re))
}

fn address(p: &Prop) -> String {
    let v = p.value.trim();
    v.strip_prefix("mailto:").or_else(|| v.strip_prefix("MAILTO:")).unwrap_or(v).trim().to_ascii_lowercase()
}

/// The account an address delivers to on this server, if any.
async fn account_for(ctx: &Ctx, addr: &str) -> Result<Option<crate::db::Account>> {
    let db = &ctx.state.db;
    if let Some(a) = db.account_by_email(addr).await? {
        return Ok(a.active.then_some(a));
    }
    if let Some(alias) = db.alias_by_source(addr).await?.filter(|a| a.active) {
        for d in alias.destination.split([',', ' ']).map(str::trim).filter(|d| !d.is_empty()) {
            if let Some(a) = db.account_by_email(d).await?.filter(|a| a.active) {
                return Ok(Some(a));
            }
        }
    }
    Ok(None)
}

fn reply(request: &Comp, organizer: &Prop, attendee: &str, rs: DateTime<Utc>, re: DateTime<Utc>, busy: &[(DateTime<Utc>, DateTime<Utc>, String)]) -> String {
    let p = |n: &str, v: String| Prop { name: n.into(), params: vec![], value: v };
    let mut fb = Comp { name: "VFREEBUSY".into(), ..Default::default() };
    if let Some(uid) = request.prop("UID") {
        fb.props.push(uid.clone());
    }
    fb.props.push(p("DTSTAMP", ical::fmt_utc(Utc::now())));
    fb.props.push(p("DTSTART", ical::fmt_utc(rs)));
    fb.props.push(p("DTEND", ical::fmt_utc(re)));
    fb.props.push(organizer.clone());
    fb.props.push(p("ATTENDEE", format!("mailto:{attendee}")));
    for (a, b, kind) in busy {
        let params = if kind == "BUSY" { vec![] } else { vec![("FBTYPE".to_string(), kind.clone())] };
        fb.props.push(Prop { name: "FREEBUSY".into(), params, value: format!("{}/{}", ical::fmt_utc(*a), ical::fmt_utc(*b)) });
    }
    let cal = Comp {
        name: "VCALENDAR".into(),
        props: vec![p("VERSION", "2.0".into()), p("PRODID", "-//Picacho Server//DAV//EN".into()), p("METHOD", "REPLY".into())],
        comps: vec![fb],
    };
    ical::serialize(&cal)
}

/// POST to the scheduling outbox.
pub async fn outbox_post(ctx: &Ctx, headers: &HeaderMap, body: &[u8]) -> Result<Response> {
    let ctype = headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("").to_ascii_lowercase();
    if !ctype.starts_with("text/calendar") {
        return Ok(empty(StatusCode::UNSUPPORTED_MEDIA_TYPE));
    }
    let Ok(cal) = ical::parse(&String::from_utf8_lossy(body)) else {
        return Ok(super::precondition(StatusCode::BAD_REQUEST, CALDAV, "valid-calendar-data"));
    };
    let method = cal.prop("METHOD").map(|m| m.value.to_ascii_uppercase()).unwrap_or_default();
    let Some(req) = cal.sub("VFREEBUSY").next().filter(|_| method == "REQUEST") else {
        // Only free/busy requests: invitations go by email (iMIP) from the app.
        return Ok(super::precondition(StatusCode::FORBIDDEN, CALDAV, "valid-scheduling-message"));
    };
    let (Some(rs), Some(re)) = (req.prop("DTSTART").and_then(|p| ical::parse_utc(&p.value)), req.prop("DTEND").and_then(|p| ical::parse_utc(&p.value))) else {
        return Ok(super::precondition(StatusCode::BAD_REQUEST, CALDAV, "valid-scheduling-message"));
    };
    if re <= rs || re - rs > chrono::Duration::days(370) {
        return Ok(super::precondition(StatusCode::BAD_REQUEST, CALDAV, "valid-scheduling-message"));
    }
    // The organizer is the person asking (RFC 6638 6.1.1: originator).
    let Some(organizer) = req.prop("ORGANIZER") else {
        return Ok(super::precondition(StatusCode::BAD_REQUEST, CALDAV, "organizer-allowed"));
    };
    let me = if ctx.principal.email.is_empty() { ctx.principal.username.clone() } else { ctx.principal.email.clone() };
    let own = address(organizer) == me.to_ascii_lowercase()
        || match ctx.principal.account_id {
            Some(id) => match ctx.state.db.get_account(id).await? {
                Some(a) => crate::submit::owns_address(&ctx.state, &a, &address(organizer)).await,
                None => false,
            },
            None => false,
        };
    if !own {
        return Ok(super::precondition(StatusCode::FORBIDDEN, CALDAV, "organizer-allowed"));
    }
    let attendees: Vec<String> = req.props_named("ATTENDEE").map(address).filter(|a| !a.is_empty()).take(100).collect();
    if attendees.is_empty() {
        return Ok(super::precondition(StatusCode::BAD_REQUEST, CALDAV, "recipient-specified"));
    }
    let lookups = ctx.state.settings().dav.free_busy_lookup;
    let mut w = Writer::new().prefix("D", DAV).prefix("C", CALDAV);
    w.open(CALDAV, "schedule-response");
    for a in &attendees {
        w.open(CALDAV, "response");
        w.open(CALDAV, "recipient");
        w.text_el(DAV, "href", &format!("mailto:{a}"));
        w.close(CALDAV, "recipient");
        let principal = match account_for(ctx, a).await? {
            Some(acc) if lookups || ctx.principal.account_id == Some(acc.id) => super::principal_for_account(&ctx.state, &acc).await?,
            _ => None,
        };
        match principal.filter(|p| p.active) {
            Some(p) => {
                let busy = busy_of(ctx, p.id, rs, re).await?;
                w.text_el(CALDAV, "request-status", "2.0;Success");
                w.text_el(CALDAV, "calendar-data", &reply(req, organizer, a, rs, re, &busy));
            }
            None => w.text_el(CALDAV, "request-status", "3.7;Invalid calendar user"),
        }
        w.close(CALDAV, "response");
    }
    w.close(CALDAV, "schedule-response");
    Ok((StatusCode::OK, [(header::CONTENT_TYPE, "application/xml; charset=utf-8")], w.finish()).into_response())
}
