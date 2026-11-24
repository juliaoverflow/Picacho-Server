//! iCalendar <-> JSCalendar (RFC 8984) and vCard <-> JSContact (RFC 9553),
//! for JMAP for Calendars and Contacts over the same resources CalDAV and
//! CardDAV serve.
//!
//! Converted both ways: title, description, start/duration/time zone,
//! all-day, status, sequence, free/busy, location, recurrence rules,
//! exclusions and changed occurrences, participants and alerts; for cards,
//! name, emails, phones, addresses, organization, note, birthday, photo and
//! group members. A JMAP change updates the stored iCalendar/vCard property
//! by property, so what JSCalendar/JSContact doesn't describe is kept.
use super::ical::{self, Comp, Prop, When};
use chrono::{DateTime, Datelike, NaiveDateTime, TimeZone, Utc};
use serde_json::{json, Map, Value};

fn p(name: &str, value: impl Into<String>) -> Prop {
    Prop { name: name.into(), params: vec![], value: value.into() }
}

fn unescape(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    let mut it = v.chars();
    while let Some(c) = it.next() {
        if c == '\\' {
            match it.next() {
                Some('n' | 'N') => out.push('\n'),
                Some(x) => out.push(x),
                None => {}
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn escape(v: &str) -> String {
    v.replace('\\', "\\\\").replace(';', "\\;").replace(',', "\\,").replace("\r\n", "\\n").replace('\n', "\\n")
}

// ------------------------------------------------------------------ time

/// A JSCalendar LocalDateTime for an iCalendar date/time, its zone, and
/// whether it is a date.
fn local_of(w: When) -> (String, Option<String>, bool) {
    match w {
        When::Date(d) => (format!("{}T00:00:00", d.format("%Y-%m-%d")), None, true),
        When::Utc(t) => (t.format("%Y-%m-%dT%H:%M:%S").to_string(), Some("Etc/UTC".into()), false),
        When::Local(n, Some(tz)) => (n.format("%Y-%m-%dT%H:%M:%S").to_string(), Some(tz.name().to_string()), false),
        When::Local(n, None) => (n.format("%Y-%m-%dT%H:%M:%S").to_string(), None, false),
    }
}

pub fn duration_text(secs: i64) -> String {
    let neg = secs < 0;
    let secs = secs.abs();
    let (d, r) = (secs / 86_400, secs % 86_400);
    let mut out = String::from(if neg { "-P" } else { "P" });
    if d > 0 {
        out.push_str(&format!("{d}D"));
    }
    if r > 0 || d == 0 {
        out.push('T');
        let (h, m, s) = (r / 3600, r % 3600 / 60, r % 60);
        if h > 0 {
            out.push_str(&format!("{h}H"));
        }
        if m > 0 {
            out.push_str(&format!("{m}M"));
        }
        if s > 0 || (h == 0 && m == 0) {
            out.push_str(&format!("{s}S"));
        }
    }
    out
}

/// An iCalendar date-time property for a JSCalendar LocalDateTime in `zone`.
fn when_prop(name: &str, local: &str, zone: Option<&str>, all_day: bool) -> Option<Prop> {
    let n = NaiveDateTime::parse_from_str(local, "%Y-%m-%dT%H:%M:%S").ok()?;
    if all_day {
        return Some(Prop { name: name.into(), params: vec![("VALUE".into(), "DATE".into())], value: n.format("%Y%m%d").to_string() });
    }
    Some(match zone {
        Some("Etc/UTC" | "UTC") => p(name, format!("{}Z", n.format("%Y%m%dT%H%M%S"))),
        Some(z) => Prop { name: name.into(), params: vec![("TZID".into(), z.into())], value: n.format("%Y%m%dT%H%M%S").to_string() },
        None => p(name, n.format("%Y%m%dT%H%M%S").to_string()),
    })
}

/// A LocalDateTime in `zone` as UTC.
pub fn to_utc(local: &str, zone: Option<&str>) -> Option<DateTime<Utc>> {
    let n = NaiveDateTime::parse_from_str(local, "%Y-%m-%dT%H:%M:%S").ok()?;
    match zone.and_then(ical::zone) {
        Some(tz) => tz.from_local_datetime(&n).earliest().map(|t| t.with_timezone(&Utc)),
        None => Some(Utc.from_utc_datetime(&n)),
    }
}

/// A RECURRENCE-ID/EXDATE value as a recurrenceOverrides key, in the
/// series' zone.
fn override_key(w: When, zone: Option<&str>) -> String {
    match (w, zone.and_then(ical::zone)) {
        (When::Date(d), _) => format!("{}T00:00:00", d.format("%Y-%m-%d")),
        (When::Local(n, None), None) => n.format("%Y-%m-%dT%H:%M:%S").to_string(),
        (w, Some(tz)) => w.utc().with_timezone(&tz).format("%Y-%m-%dT%H:%M:%S").to_string(),
        (w, None) => w.utc().format("%Y-%m-%dT%H:%M:%S").to_string(),
    }
}

// ------------------------------------------------------------------ recurrence

const DAYS: [&str; 7] = ["mo", "tu", "we", "th", "fr", "sa", "su"];
const NUMERIC: [(&str, &str); 7] = [
    ("byMonthDay", "BYMONTHDAY"),
    ("byYearDay", "BYYEARDAY"),
    ("byWeekNo", "BYWEEKNO"),
    ("byHour", "BYHOUR"),
    ("byMinute", "BYMINUTE"),
    ("bySecond", "BYSECOND"),
    ("bySetPosition", "BYSETPOS"),
];

fn rule_of(rrule: &str, zone: Option<&str>) -> Option<Value> {
    let mut r = Map::new();
    r.insert("@type".into(), json!("RecurrenceRule"));
    for part in rrule.split(';') {
        let (k, v) = part.split_once('=')?;
        let k = k.to_ascii_uppercase();
        match k.as_str() {
            "FREQ" => {
                r.insert("frequency".into(), json!(v.to_ascii_lowercase()));
            }
            "INTERVAL" => {
                r.insert("interval".into(), json!(v.parse::<u64>().ok()?));
            }
            "COUNT" => {
                r.insert("count".into(), json!(v.parse::<u64>().ok()?));
            }
            "UNTIL" => {
                let w = ical::parse_when(v, None)?;
                let local = match (w, zone.and_then(ical::zone)) {
                    (When::Utc(t), Some(tz)) => t.with_timezone(&tz).format("%Y-%m-%dT%H:%M:%S").to_string(),
                    _ => local_of(w).0,
                };
                r.insert("until".into(), json!(local));
            }
            "WKST" => {
                r.insert("firstDayOfWeek".into(), json!(v.to_ascii_lowercase()));
            }
            "BYDAY" => {
                let days: Vec<Value> = v
                    .split(',')
                    .filter_map(|d| {
                        let d = d.trim();
                        let (n, day) = d.split_at(d.len().checked_sub(2)?);
                        let day = day.to_ascii_lowercase();
                        if !DAYS.contains(&day.as_str()) {
                            return None;
                        }
                        let mut o = json!({"@type": "NDay", "day": day});
                        if let Ok(n) = n.parse::<i64>() {
                            o["nthOfPeriod"] = json!(n);
                        }
                        Some(o)
                    })
                    .collect();
                r.insert("byDay".into(), Value::Array(days));
            }
            "BYMONTH" => {
                r.insert("byMonth".into(), json!(v.split(',').collect::<Vec<_>>()));
            }
            other => {
                if let Some((key, _)) = NUMERIC.iter().find(|(_, n)| *n == other) {
                    let n: Vec<i64> = v.split(',').filter_map(|x| x.parse().ok()).collect();
                    r.insert((*key).into(), json!(n));
                }
            }
        }
    }
    r.contains_key("frequency").then_some(Value::Object(r))
}

fn rrule_of(rule: &Value, zone: Option<&str>) -> Option<String> {
    let mut parts = vec![format!("FREQ={}", rule["frequency"].as_str()?.to_ascii_uppercase())];
    if let Some(n) = rule["interval"].as_u64().filter(|n| *n > 1) {
        parts.push(format!("INTERVAL={n}"));
    }
    if let Some(n) = rule["count"].as_u64() {
        parts.push(format!("COUNT={n}"));
    }
    if let Some(u) = rule["until"].as_str() {
        parts.push(format!("UNTIL={}", ical::fmt_utc(to_utc(u, zone)?)));
    }
    if let Some(d) = rule["firstDayOfWeek"].as_str() {
        parts.push(format!("WKST={}", d.to_ascii_uppercase()));
    }
    if let Some(days) = rule["byDay"].as_array() {
        let list: Vec<String> = days
            .iter()
            .filter_map(|d| {
                let day = d["day"].as_str()?.to_ascii_uppercase();
                Some(match d["nthOfPeriod"].as_i64() {
                    Some(n) => format!("{n}{day}"),
                    None => day,
                })
            })
            .collect();
        if !list.is_empty() {
            parts.push(format!("BYDAY={}", list.join(",")));
        }
    }
    if let Some(m) = rule["byMonth"].as_array() {
        let list: Vec<String> = m.iter().filter_map(|x| x.as_str().map(String::from).or_else(|| x.as_i64().map(|n| n.to_string()))).collect();
        if !list.is_empty() {
            parts.push(format!("BYMONTH={}", list.join(",")));
        }
    }
    for (key, name) in NUMERIC {
        if let Some(a) = rule[key].as_array() {
            let list: Vec<String> = a.iter().filter_map(|x| x.as_i64().map(|n| n.to_string())).collect();
            if !list.is_empty() {
                parts.push(format!("{name}={}", list.join(",")));
            }
        }
    }
    Some(parts.join(";"))
}

// ------------------------------------------------------------------ events

fn mailto(v: &str) -> String {
    let v = v.trim();
    v.strip_prefix("mailto:").or_else(|| v.strip_prefix("MAILTO:")).unwrap_or(v).to_string()
}

fn partstat(json: &str) -> &'static str {
    match json {
        "accepted" => "ACCEPTED",
        "declined" => "DECLINED",
        "tentative" => "TENTATIVE",
        "delegated" => "DELEGATED",
        _ => "NEEDS-ACTION",
    }
}

fn alert_of(a: &Comp) -> Option<Value> {
    let t = a.prop("TRIGGER")?;
    let action = a.prop("ACTION").map(|x| x.value.to_ascii_lowercase()).unwrap_or_else(|| "display".into());
    let trigger = if t.param("VALUE").is_some_and(|v| v.eq_ignore_ascii_case("DATE-TIME")) {
        json!({"@type": "AbsoluteTrigger", "when": ical::parse_utc(&t.value)?.format("%Y-%m-%dT%H:%M:%SZ").to_string()})
    } else {
        let neg = t.value.starts_with('-');
        let d = ical::parse_duration(t.value.trim_start_matches(['-', '+']))?.num_seconds();
        let mut o = json!({"@type": "OffsetTrigger", "offset": duration_text(if neg { -d } else { d })});
        if t.param("RELATED").is_some_and(|r| r.eq_ignore_ascii_case("END")) {
            o["relativeTo"] = json!("end");
        }
        o
    };
    Some(json!({"@type": "Alert", "trigger": trigger, "action": if action == "email" { "email" } else { "display" }}))
}

fn alarm_of(a: &Value) -> Option<Comp> {
    let t = &a["trigger"];
    let trigger = match t["@type"].as_str().unwrap_or("OffsetTrigger") {
        "AbsoluteTrigger" => {
            let w = DateTime::parse_from_rfc3339(t["when"].as_str()?).ok()?.with_timezone(&Utc);
            Prop { name: "TRIGGER".into(), params: vec![("VALUE".into(), "DATE-TIME".into())], value: ical::fmt_utc(w) }
        }
        _ => {
            let off = t["offset"].as_str()?;
            ical::parse_duration(off.trim_start_matches(['-', '+']))?;
            let mut pr = p("TRIGGER", off);
            if t["relativeTo"].as_str() == Some("end") {
                pr.params.push(("RELATED".into(), "END".into()));
            }
            pr
        }
    };
    let action = if a["action"].as_str() == Some("email") { "EMAIL" } else { "DISPLAY" };
    Some(Comp { name: "VALARM".into(), props: vec![p("ACTION", action), trigger, p("DESCRIPTION", "Reminder")], comps: vec![] })
}

/// The JSCalendar properties of one VEVENT/VTODO (overrides aside).
fn event_props(c: &Comp) -> Map<String, Value> {
    let mut o = Map::new();
    o.insert("@type".into(), json!(if c.name == "VTODO" { "Task" } else { "Event" }));
    if let Some(u) = c.prop("UID") {
        o.insert("uid".into(), json!(u.value));
    }
    o.insert("title".into(), json!(c.prop("SUMMARY").map(|x| unescape(&x.value)).unwrap_or_default()));
    o.insert("description".into(), json!(c.prop("DESCRIPTION").map(|x| unescape(&x.value)).unwrap_or_default()));
    let start = c.prop("DTSTART").and_then(ical::prop_when).or_else(|| c.prop("DUE").and_then(ical::prop_when));
    if let Some(s) = start {
        let (local, zone, all_day) = local_of(s);
        o.insert(if c.name == "VTODO" && c.prop("DTSTART").is_none() { "due" } else { "start" }.into(), json!(local));
        o.insert("timeZone".into(), zone.map(Value::from).unwrap_or(Value::Null));
        o.insert("showWithoutTime".into(), json!(all_day));
        if c.name == "VEVENT" {
            let (a, b) = ical::span(c, s);
            o.insert("duration".into(), json!(duration_text((b - a).num_seconds())));
        }
    }
    if let Some(s) = c.prop("STATUS") {
        o.insert("status".into(), json!(s.value.to_ascii_lowercase()));
    }
    if let Some(s) = c.prop("SEQUENCE").and_then(|x| x.value.parse::<u64>().ok()) {
        o.insert("sequence".into(), json!(s));
    }
    if let Some(l) = c.prop("LOCATION").filter(|l| !l.value.is_empty()) {
        o.insert("locations".into(), json!({"l1": {"@type": "Location", "name": unescape(&l.value)}}));
    }
    if let Some(t) = c.prop("TRANSP") {
        o.insert("freeBusyStatus".into(), json!(if t.value.eq_ignore_ascii_case("TRANSPARENT") { "free" } else { "busy" }));
    }
    if let Some(pc) = c.prop("PERCENT-COMPLETE").and_then(|x| x.value.parse::<u64>().ok()) {
        o.insert("percentComplete".into(), json!(pc));
    }
    let zone = o.get("timeZone").and_then(|z| z.as_str()).map(String::from);
    let rules: Vec<Value> = c.props_named("RRULE").filter_map(|r| rule_of(&r.value, zone.as_deref())).collect();
    if !rules.is_empty() {
        o.insert("recurrenceRules".into(), Value::Array(rules));
    }
    let mut people = Map::new();
    let org = c.prop("ORGANIZER").map(|x| mailto(&x.value).to_ascii_lowercase());
    if let Some(op) = c.prop("ORGANIZER") {
        let mut x = json!({"@type": "Participant", "sendTo": {"imip": format!("mailto:{}", mailto(&op.value))}, "roles": {"owner": true}});
        if let Some(n) = op.param("CN") {
            x["name"] = json!(n);
        }
        if let Some(a) = op.param("SCHEDULE-AGENT") {
            x["scheduleAgent"] = json!(a.to_ascii_lowercase());
        }
        people.insert("organizer".into(), x);
    }
    for (i, a) in c.props_named("ATTENDEE").enumerate() {
        let email = mailto(&a.value);
        let mut x = json!({"@type": "Participant", "sendTo": {"imip": format!("mailto:{email}")}, "roles": {"attendee": true},
            "participationStatus": a.param("PARTSTAT").unwrap_or("NEEDS-ACTION").to_ascii_lowercase()});
        if let Some(n) = a.param("CN") {
            x["name"] = json!(n);
        }
        if let Some(s) = a.param("SCHEDULE-AGENT") {
            x["scheduleAgent"] = json!(s.to_ascii_lowercase());
        }
        if a.param("RSVP").is_some_and(|r| r.eq_ignore_ascii_case("TRUE")) {
            x["expectReply"] = json!(true);
        }
        if org.as_deref() == Some(email.to_ascii_lowercase().as_str()) {
            if let Some(o) = people.get_mut("organizer") {
                o["roles"]["attendee"] = json!(true);
                o["participationStatus"] = x["participationStatus"].clone();
                continue;
            }
        }
        people.insert(format!("p{}", i + 1), x);
    }
    if !people.is_empty() {
        o.insert("participants".into(), Value::Object(people));
    }
    let alerts: Map<String, Value> = c.sub("VALARM").filter_map(alert_of).enumerate().map(|(i, a)| (format!("a{}", i + 1), a)).collect();
    if !alerts.is_empty() {
        o.insert("alerts".into(), Value::Object(alerts));
    }
    o
}

/// A calendar object resource as a JSCalendar object: the master, with its
/// changed and excluded occurrences as recurrenceOverrides.
pub fn to_jscalendar(cal: &Comp) -> Option<Map<String, Value>> {
    let objs: Vec<&Comp> = cal.comps.iter().filter(|c| c.name == "VEVENT" || c.name == "VTODO").collect();
    let master = *objs.iter().find(|c| c.prop("RECURRENCE-ID").is_none()).or(objs.first())?;
    let mut o = event_props(master);
    let zone = o.get("timeZone").and_then(|z| z.as_str()).map(String::from);
    let mut overrides = Map::new();
    for ex in master.props_named("EXDATE") {
        for v in ex.value.split(',') {
            if let Some(w) = ical::parse_when(v, ex.param("TZID")) {
                overrides.insert(override_key(w, zone.as_deref()), json!({"excluded": true}));
            }
        }
    }
    for c in objs.iter().filter(|c| c.prop("RECURRENCE-ID").is_some()) {
        let Some(rid) = c.prop("RECURRENCE-ID").and_then(ical::prop_when) else { continue };
        let mut patch = Map::new();
        for (k, v) in event_props(c) {
            if !matches!(k.as_str(), "@type" | "uid" | "recurrenceRules") && o.get(&k) != Some(&v) {
                patch.insert(k, v);
            }
        }
        overrides.insert(override_key(rid, zone.as_deref()), Value::Object(patch));
    }
    if !overrides.is_empty() {
        o.insert("recurrenceOverrides".into(), Value::Object(overrides));
    }
    Some(o)
}

fn set_prop(c: &mut Comp, name: &str, value: Option<Prop>) {
    c.props.retain(|x| !x.name.eq_ignore_ascii_case(name));
    if let Some(v) = value {
        c.props.push(v);
    }
}

/// Write JSCalendar properties onto a VEVENT/VTODO, keeping the rest.
fn apply_props(c: &mut Comp, o: &Map<String, Value>) -> Result<(), String> {
    if let Some(t) = o.get("title") {
        let t = t.as_str().unwrap_or("");
        set_prop(c, "SUMMARY", (!t.is_empty()).then(|| p("SUMMARY", escape(t))));
    }
    if let Some(t) = o.get("description") {
        let t = t.as_str().unwrap_or("");
        set_prop(c, "DESCRIPTION", (!t.is_empty()).then(|| p("DESCRIPTION", escape(t))));
    }
    if ["start", "due", "timeZone", "showWithoutTime", "duration"].iter().any(|k| o.contains_key(*k)) {
        let current = event_props(c);
        let get = |k: &str| o.get(k).or(current.get(k)).cloned().unwrap_or(Value::Null);
        let all_day = get("showWithoutTime").as_bool().unwrap_or(false);
        let zone = get("timeZone").as_str().map(String::from);
        if let Some(z) = zone.as_deref().filter(|z| !matches!(*z, "Etc/UTC" | "UTC")) {
            if ical::zone(z).is_none() {
                return Err(format!("Unknown time zone {z}"));
            }
        }
        let (field, key) = if c.name == "VTODO" && (o.contains_key("due") || c.prop("DTSTART").is_none() && !o.contains_key("start")) { ("DUE", "due") } else { ("DTSTART", "start") };
        if let Some(start) = get(key).as_str() {
            let sp = when_prop(field, start, zone.as_deref(), all_day).ok_or("start must be a LocalDateTime")?;
            set_prop(c, field, Some(sp));
        } else if c.name == "VEVENT" {
            return Err("start is required".into());
        }
        if c.name == "VEVENT" {
            c.props.retain(|x| !x.name.eq_ignore_ascii_case("DTEND"));
            let dur = get("duration").as_str().map(|d| ical::parse_duration(d).ok_or("Invalid duration")).transpose()?;
            set_prop(c, "DURATION", dur.map(|d| p("DURATION", duration_text(d.num_seconds()))));
        }
    }
    if let Some(s) = o.get("status") {
        set_prop(c, "STATUS", s.as_str().filter(|s| !s.is_empty()).map(|s| p("STATUS", s.to_ascii_uppercase())));
    }
    if let Some(s) = o.get("sequence") {
        set_prop(c, "SEQUENCE", s.as_u64().map(|n| p("SEQUENCE", n.to_string())));
    }
    if let Some(f) = o.get("freeBusyStatus") {
        set_prop(c, "TRANSP", f.as_str().map(|f| p("TRANSP", if f == "free" { "TRANSPARENT" } else { "OPAQUE" })));
    }
    if let Some(pc) = o.get("percentComplete") {
        set_prop(c, "PERCENT-COMPLETE", pc.as_u64().map(|n| p("PERCENT-COMPLETE", n.min(100).to_string())));
    }
    if let Some(l) = o.get("locations") {
        let name = l.as_object().and_then(|m| m.values().find_map(|x| x["name"].as_str().map(String::from)));
        set_prop(c, "LOCATION", name.filter(|n| !n.is_empty()).map(|n| p("LOCATION", escape(&n))));
    }
    if let Some(r) = o.get("recurrenceRules") {
        let zone = o.get("timeZone").and_then(|z| z.as_str()).map(String::from).or_else(|| event_props(c).get("timeZone").and_then(|z| z.as_str()).map(String::from));
        c.props.retain(|x| !x.name.eq_ignore_ascii_case("RRULE"));
        for rule in r.as_array().into_iter().flatten() {
            c.props.push(p("RRULE", rrule_of(rule, zone.as_deref()).ok_or("Invalid recurrence rule")?));
        }
    }
    if let Some(people) = o.get("participants") {
        c.props.retain(|x| !x.name.eq_ignore_ascii_case("ORGANIZER") && !x.name.eq_ignore_ascii_case("ATTENDEE"));
        for (_, x) in people.as_object().into_iter().flatten() {
            let email = x["sendTo"]["imip"].as_str().or(x["email"].as_str()).map(mailto).unwrap_or_default();
            if email.is_empty() || email.contains(['\r', '\n']) {
                continue;
            }
            let roles = &x["roles"];
            let mut params: Vec<(String, String)> = vec![];
            if let Some(n) = x["name"].as_str().filter(|n| !n.is_empty()) {
                params.push(("CN".into(), n.replace(['\r', '\n', '"'], "")));
            }
            if let Some(a) = x["scheduleAgent"].as_str() {
                params.push(("SCHEDULE-AGENT".into(), a.to_ascii_uppercase()));
            }
            let owner = roles["owner"].as_bool().unwrap_or(false);
            if owner {
                c.props.push(Prop { name: "ORGANIZER".into(), params: params.clone(), value: format!("mailto:{email}") });
            }
            if roles["attendee"].as_bool().unwrap_or(false) || !owner {
                let mut ap = params;
                ap.push(("PARTSTAT".into(), partstat(x["participationStatus"].as_str().unwrap_or("needs-action")).into()));
                if x["expectReply"].as_bool().unwrap_or(false) {
                    ap.push(("RSVP".into(), "TRUE".into()));
                }
                c.props.push(Prop { name: "ATTENDEE".into(), params: ap, value: format!("mailto:{email}") });
            }
        }
    }
    if let Some(a) = o.get("alerts") {
        c.comps.retain(|x| x.name != "VALARM");
        for al in a.as_object().into_iter().flatten().map(|(_, v)| v) {
            c.comps.push(alarm_of(al).ok_or("Invalid alert")?);
        }
    }
    Ok(())
}

/// A VTIMEZONE for an IANA zone: its offsets in `year`, and the dates it
/// changes between them (found from chrono-tz, the zone database).
pub fn vtimezone(zone: &str, year: i32) -> Option<Comp> {
    use chrono::Offset;
    let tz = ical::zone(zone)?;
    let off = |t: DateTime<Utc>| t.with_timezone(&tz).offset().fix().local_minus_utc();
    let fmt = |secs: i32| format!("{}{:02}{:02}", if secs < 0 { '-' } else { '+' }, secs.abs() / 3600, secs.abs() % 3600 / 60);
    let start = Utc.with_ymd_and_hms(year, 1, 1, 0, 0, 0).single()?;
    // Offset changes during the year, to the minute.
    let mut changes: Vec<(DateTime<Utc>, i32, i32)> = vec![];
    let mut prev = off(start);
    let mut t = start;
    while t.year_ce().1 as i32 == year {
        let next = t + chrono::Duration::days(1);
        let o = off(next);
        if o != prev {
            let (mut lo, mut hi) = (t, next);
            while hi - lo > chrono::Duration::minutes(1) {
                let mid = lo + (hi - lo) / 2;
                if off(mid) == prev { lo = mid } else { hi = mid }
            }
            changes.push((hi, prev, o));
            prev = o;
        }
        t = next;
    }
    let name = tz.name().to_string();
    let mut c = Comp { name: "VTIMEZONE".into(), props: vec![p("TZID", name)], comps: vec![] };
    if changes.is_empty() {
        let o = off(start);
        c.comps.push(Comp { name: "STANDARD".into(), props: vec![p("DTSTART", "19700101T000000"), p("TZOFFSETFROM", fmt(o)), p("TZOFFSETTO", fmt(o))], comps: vec![] });
        return Some(c);
    }
    for (at, from, to) in changes {
        let local = (at + chrono::Duration::seconds(from as i64)).naive_utc();
        let kind = if to > from { "DAYLIGHT" } else { "STANDARD" };
        c.comps.push(Comp {
            name: kind.into(),
            props: vec![p("DTSTART", local.format("%Y%m%dT%H%M%S").to_string()), p("TZOFFSETFROM", fmt(from)), p("TZOFFSETTO", fmt(to))],
            comps: vec![],
        });
    }
    Some(c)
}

/// Add a VTIMEZONE for each TZID used and not yet defined.
fn add_timezones(cal: &mut Comp) {
    use chrono::Datelike;
    let defined: Vec<String> = cal.sub("VTIMEZONE").filter_map(|t| t.prop("TZID").map(|x| x.value.clone())).collect();
    let mut used: Vec<(String, i32)> = vec![];
    for c in cal.comps.iter().filter(|c| c.name != "VTIMEZONE") {
        for pr in &c.props {
            if let Some(t) = pr.param("TZID") {
                let year = ical::prop_when(pr).map(|w| w.utc().year()).unwrap_or(2026);
                if !defined.iter().any(|d| d == t) && !used.iter().any(|u| u.0 == t) {
                    used.push((t.to_string(), year));
                }
            }
        }
    }
    for (t, y) in used {
        if let Some(z) = vtimezone(&t, y) {
            cal.comps.insert(0, z);
        }
    }
}

/// Apply a JSCalendar object (new, or the current JSON with a patch
/// merged in) to `cal`, or to a new VCALENDAR. Returns the object to store.
pub fn apply_jscalendar(cal: Option<&Comp>, o: &Map<String, Value>) -> Result<Comp, String> {
    let kind = if o.get("@type").and_then(|t| t.as_str()) == Some("Task") { "VTODO" } else { "VEVENT" };
    let mut cal = cal.cloned().unwrap_or_else(|| Comp {
        name: "VCALENDAR".into(),
        props: vec![p("VERSION", "2.0"), p("PRODID", "-//Picacho Server//JMAP//EN")],
        comps: vec![],
    });
    let uid = o
        .get("uid")
        .and_then(|u| u.as_str())
        .map(String::from)
        .or_else(|| cal.comps.iter().find_map(|c| c.prop("UID").map(|u| u.value.clone())))
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let find_master = |cal: &Comp| cal.comps.iter().position(|c| (c.name == "VEVENT" || c.name == "VTODO") && c.prop("RECURRENCE-ID").is_none());
    let idx = match find_master(&cal) {
        Some(i) => i,
        None => {
            cal.comps.push(Comp { name: kind.into(), props: vec![p("UID", uid.clone())], comps: vec![] });
            cal.comps.len() - 1
        }
    };
    apply_props(&mut cal.comps[idx], o)?;
    let stamp = ical::fmt_utc(Utc::now());
    set_prop(&mut cal.comps[idx], "DTSTAMP", Some(p("DTSTAMP", stamp.clone())));
    set_prop(&mut cal.comps[idx], "LAST-MODIFIED", Some(p("LAST-MODIFIED", stamp)));
    if let Some(ov) = o.get("recurrenceOverrides") {
        let master = cal.comps[idx].clone();
        let zone = event_props(&master).get("timeZone").and_then(|z| z.as_str()).map(String::from);
        let all_day = master.prop("DTSTART").and_then(ical::prop_when).is_some_and(|w| w.is_date());
        cal.comps.retain(|c| c.prop("RECURRENCE-ID").is_none());
        let idx = find_master(&cal).unwrap_or(0);
        cal.comps[idx].props.retain(|x| !x.name.eq_ignore_ascii_case("EXDATE"));
        for (at, patch) in ov.as_object().into_iter().flatten() {
            let rid = when_prop("RECURRENCE-ID", at, zone.as_deref(), all_day).ok_or("Invalid recurrenceOverrides key")?;
            if patch["excluded"].as_bool().unwrap_or(false) {
                cal.comps[idx].props.push(Prop { name: "EXDATE".into(), ..rid });
                continue;
            }
            let mut occ = master.clone();
            occ.props.retain(|x| !matches!(x.name.to_ascii_uppercase().as_str(), "RRULE" | "RDATE" | "EXDATE"));
            occ.props.push(rid);
            let mut po: Map<String, Value> = patch.as_object().cloned().unwrap_or_default().into_iter().filter(|(k, _)| !k.contains('/')).collect();
            if !po.contains_key("start") {
                po.insert("start".into(), json!(at));
            }
            apply_props(&mut occ, &po)?;
            cal.comps.push(occ);
        }
    }
    add_timezones(&mut cal);
    Ok(cal)
}

// ------------------------------------------------------------------ cards

fn vcard_values(c: &Comp, name: &str) -> Vec<(String, Option<i64>)> {
    c.props_named(name)
        .map(|x| (unescape(&x.value).trim().trim_start_matches("tel:").to_string(), x.param("PREF").and_then(|p| p.parse().ok())))
        .filter(|(v, _)| !v.is_empty())
        .collect()
}

/// A vCard as a JSContact Card.
pub fn to_jscontact(c: &Comp) -> Map<String, Value> {
    let mut o = Map::new();
    o.insert("@type".into(), json!("Card"));
    o.insert("version".into(), json!("1.0"));
    if let Some(u) = c.prop("UID") {
        o.insert("uid".into(), json!(u.value.trim_start_matches("urn:uuid:")));
    }
    if let Some(k) = c.prop("KIND").or(c.prop("X-ADDRESSBOOKSERVER-KIND")) {
        o.insert("kind".into(), json!(k.value.to_ascii_lowercase()));
    }
    let full = c.prop("FN").map(|f| unescape(&f.value)).unwrap_or_default();
    let mut components = vec![];
    if let Some(n) = c.prop("N") {
        let parts: Vec<String> = n.value.split(';').map(unescape).collect();
        for (i, kind) in [(3, "title"), (1, "given"), (2, "given2"), (0, "surname"), (4, "credential")] {
            if let Some(v) = parts.get(i).filter(|v| !v.is_empty()) {
                components.push(json!({"kind": kind, "value": v}));
            }
        }
    }
    o.insert("name".into(), json!({"@type": "Name", "full": full, "components": components}));
    for (name, key, ty, field, prefix) in [("EMAIL", "emails", "EmailAddress", "address", "e"), ("TEL", "phones", "Phone", "number", "t")] {
        let m: Map<String, Value> = vcard_values(c, name)
            .into_iter()
            .enumerate()
            .map(|(i, (v, pref))| {
                let mut e = json!({"@type": ty, field: v});
                if let Some(pr) = pref {
                    e["pref"] = json!(pr);
                }
                (format!("{prefix}{}", i + 1), e)
            })
            .collect();
        if !m.is_empty() {
            o.insert(key.into(), Value::Object(m));
        }
    }
    let adrs: Map<String, Value> = c
        .props_named("ADR")
        .enumerate()
        .filter_map(|(i, a)| {
            let parts: Vec<String> = a.value.split(';').map(unescape).filter(|s| !s.trim().is_empty()).collect();
            (!parts.is_empty()).then(|| (format!("a{}", i + 1), json!({"@type": "Address", "full": parts.join(", ")})))
        })
        .collect();
    if !adrs.is_empty() {
        o.insert("addresses".into(), Value::Object(adrs));
    }
    if let Some(org) = c.prop("ORG") {
        let parts: Vec<String> = org.value.split(';').map(unescape).collect();
        let mut x = json!({"@type": "Organization", "name": parts.first().cloned().unwrap_or_default()});
        let units: Vec<Value> = parts.iter().skip(1).filter(|u| !u.is_empty()).map(|u| json!({"@type": "OrgUnit", "name": u})).collect();
        if !units.is_empty() {
            x["units"] = Value::Array(units);
        }
        o.insert("organizations".into(), json!({"o1": x}));
    }
    if let Some(n) = c.prop("NOTE") {
        o.insert("notes".into(), json!({"n1": {"@type": "Note", "note": unescape(&n.value)}}));
    }
    if let Some(b) = c.prop("BDAY") {
        let date = match b.value.strip_prefix("--") {
            Some(md) => {
                let md = md.replace('-', "");
                json!({"@type": "PartialDate", "month": md.get(0..2).and_then(|m| m.parse::<u64>().ok()), "day": md.get(2..4).and_then(|d| d.parse::<u64>().ok())})
            }
            None => {
                let v = b.value.replace('-', "");
                json!({"@type": "PartialDate", "year": v.get(0..4).and_then(|y| y.parse::<u64>().ok()), "month": v.get(4..6).and_then(|m| m.parse::<u64>().ok()), "day": v.get(6..8).and_then(|d| d.parse::<u64>().ok())})
            }
        };
        o.insert("anniversaries".into(), json!({"b": {"@type": "Anniversary", "kind": "birth", "date": date}}));
    }
    if let Some(ph) = c.prop("PHOTO") {
        let uri = if ph.value.starts_with("data:") || ph.value.contains("://") {
            ph.value.clone()
        } else {
            let ty = ph.param("TYPE").unwrap_or("jpeg").to_ascii_lowercase();
            format!("data:image/{ty};base64,{}", ph.value)
        };
        o.insert("media".into(), json!({"p": {"@type": "Media", "kind": "photo", "uri": uri}}));
    }
    let members: Map<String, Value> = c.props_named("MEMBER").chain(c.props_named("X-ADDRESSBOOKSERVER-MEMBER")).map(|m| (m.value.trim().to_string(), json!(true))).collect();
    if !members.is_empty() {
        o.insert("members".into(), Value::Object(members));
    }
    if let Some(t) = c.prop("REV").and_then(|r| ical::parse_utc(&r.value.replace(['-', ':'], ""))) {
        o.insert("updated".into(), json!(t.format("%Y-%m-%dT%H:%M:%SZ").to_string()));
    }
    o
}

/// Write JSContact properties onto a vCard (or a new one), keeping the
/// lines JSContact doesn't describe.
pub fn apply_jscontact(card: Option<&Comp>, o: &Map<String, Value>) -> Result<Comp, String> {
    let mut c = card.cloned().unwrap_or_else(|| Comp { name: "VCARD".into(), props: vec![p("VERSION", "3.0")], comps: vec![] });
    if c.prop("UID").is_none() {
        let uid = o.get("uid").and_then(|u| u.as_str()).map(String::from).unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        c.props.push(p("UID", uid));
    }
    let set_all = |c: &mut Comp, name: &str, values: Vec<Prop>| {
        c.props.retain(|x| !x.name.eq_ignore_ascii_case(name));
        c.props.extend(values);
    };
    if let Some(n) = o.get("name") {
        let comps = n["components"].as_array().cloned().unwrap_or_default();
        let part = |k: &str| comps.iter().filter(|x| x["kind"].as_str() == Some(k)).filter_map(|x| x["value"].as_str()).collect::<Vec<_>>().join(" ");
        let full = n["full"]
            .as_str()
            .map(String::from)
            .filter(|f| !f.is_empty())
            .unwrap_or_else(|| [part("given"), part("given2"), part("surname")].into_iter().filter(|s| !s.is_empty()).collect::<Vec<_>>().join(" "));
        let (mut given, mut surname) = (part("given"), part("surname"));
        if given.is_empty() && surname.is_empty() {
            match full.trim().rsplit_once(' ') {
                Some((g, s)) => (given, surname) = (g.into(), s.into()),
                None => given = full.trim().into(),
            }
        }
        set_all(&mut c, "FN", vec![p("FN", escape(&full))]);
        let n = format!("{};{};{};{};{}", escape(&surname), escape(&given), escape(&part("given2")), escape(&part("title")), escape(&part("credential")));
        set_all(&mut c, "N", vec![p("N", n)]);
    }
    for (key, field, name) in [("emails", "address", "EMAIL"), ("phones", "number", "TEL")] {
        let Some(m) = o.get(key) else { continue };
        let mut v: Vec<(i64, String, Option<i64>)> = m
            .as_object()
            .into_iter()
            .flatten()
            .filter_map(|(_, e)| Some((e["pref"].as_i64().unwrap_or(100), e[field].as_str()?.to_string(), e["pref"].as_i64())))
            .collect();
        v.sort_by_key(|x| x.0);
        let props = v
            .into_iter()
            .map(|(_, val, pref)| Prop { name: name.into(), params: pref.map(|n| vec![("PREF".into(), n.to_string())]).unwrap_or_default(), value: escape(&val) })
            .collect();
        set_all(&mut c, name, props);
    }
    if let Some(a) = o.get("addresses") {
        let props = a
            .as_object()
            .into_iter()
            .flatten()
            .filter_map(|(_, x)| {
                let full = x["full"].as_str().map(String::from).or_else(|| {
                    let parts: Vec<&str> = x["components"].as_array()?.iter().filter(|c| c["kind"].as_str() != Some("separator")).filter_map(|c| c["value"].as_str()).collect();
                    (!parts.is_empty()).then(|| parts.join(", "))
                })?;
                Some(p("ADR", format!(";;{};;;;", escape(&full))))
            })
            .collect();
        set_all(&mut c, "ADR", props);
    }
    if let Some(org) = o.get("organizations") {
        let props = org
            .as_object()
            .into_iter()
            .flatten()
            .take(1)
            .map(|(_, x)| {
                let mut parts = vec![escape(x["name"].as_str().unwrap_or(""))];
                parts.extend(x["units"].as_array().into_iter().flatten().filter_map(|u| u["name"].as_str()).map(escape));
                p("ORG", parts.join(";"))
            })
            .collect();
        set_all(&mut c, "ORG", props);
    }
    if let Some(n) = o.get("notes") {
        let note = n.as_object().and_then(|m| m.values().find_map(|x| x["note"].as_str().map(String::from)));
        set_all(&mut c, "NOTE", note.map(|t| vec![p("NOTE", escape(&t))]).unwrap_or_default());
    }
    if let Some(a) = o.get("anniversaries") {
        let birth = a.as_object().and_then(|m| m.values().find(|x| x["kind"].as_str() == Some("birth"))).cloned();
        let props = birth
            .and_then(|b| {
                let d = &b["date"];
                if let Some(s) = d.as_str() {
                    return Some(p("BDAY", s.split('T').next().unwrap_or(s).replace('-', "")));
                }
                let (m, day) = (d["month"].as_u64()?, d["day"].as_u64()?);
                Some(p("BDAY", match d["year"].as_u64() {
                    Some(y) => format!("{y:04}{m:02}{day:02}"),
                    None => format!("--{m:02}{day:02}"),
                }))
            })
            .map(|x| vec![x])
            .unwrap_or_default();
        set_all(&mut c, "BDAY", props);
    }
    if let Some(m) = o.get("media") {
        let photo = m.as_object().and_then(|m| m.values().find(|x| x["kind"].as_str() == Some("photo")).and_then(|x| x["uri"].as_str().map(String::from)));
        let props = photo
            .map(|uri| match uri.strip_prefix("data:").and_then(|r| r.split_once(";base64,")) {
                Some((mime, data)) => {
                    let ty = mime.rsplit('/').next().unwrap_or("jpeg").to_ascii_uppercase();
                    vec![Prop { name: "PHOTO".into(), params: vec![("ENCODING".into(), "b".into()), ("TYPE".into(), ty)], value: data.into() }]
                }
                None => vec![Prop { name: "PHOTO".into(), params: vec![("VALUE".into(), "uri".into())], value: uri }],
            })
            .unwrap_or_default();
        set_all(&mut c, "PHOTO", props);
    }
    if o.get("kind").and_then(|k| k.as_str()) == Some("group") || o.contains_key("members") {
        set_all(&mut c, "X-ADDRESSBOOKSERVER-KIND", vec![p("X-ADDRESSBOOKSERVER-KIND", "group")]);
        let members = o
            .get("members")
            .and_then(|m| m.as_object())
            .into_iter()
            .flatten()
            .filter(|(_, on)| on.as_bool().unwrap_or(false))
            .map(|(m, _)| p("X-ADDRESSBOOKSERVER-MEMBER", if m.starts_with("urn:uuid:") { m.clone() } else { format!("urn:uuid:{m}") }))
            .collect();
        set_all(&mut c, "X-ADDRESSBOOKSERVER-MEMBER", members);
    }
    if c.prop("FN").is_none() {
        c.props.push(p("FN", ""));
    }
    set_all(&mut c, "REV", vec![p("REV", ical::fmt_utc(Utc::now()))]);
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_roundtrip() {
        let text = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:x\r\nBEGIN:VEVENT\r\nUID:e1\r\nDTSTAMP:20260101T000000Z\r\nDTSTART;TZID=Europe/Berlin:20261201T090000\r\nDURATION:PT1H30M\r\nSUMMARY:Stand-up\\, daily\r\nRRULE:FREQ=WEEKLY;BYDAY=MO,WE;COUNT=10\r\nEXDATE;TZID=Europe/Berlin:20261202T090000\r\nX-KEEP:yes\r\nORGANIZER;CN=Bob:mailto:bob@x.test\r\nATTENDEE;PARTSTAT=ACCEPTED:mailto:amy@x.test\r\nBEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER:-PT15M\r\nEND:VALARM\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        let cal = ical::parse(text).unwrap();
        let o = to_jscalendar(&cal).unwrap();
        assert_eq!(o["title"], "Stand-up, daily");
        assert_eq!(o["start"], "2026-12-01T09:00:00");
        assert_eq!(o["timeZone"], "Europe/Berlin");
        assert_eq!(o["duration"], "PT1H30M");
        assert_eq!(o["recurrenceRules"][0]["byDay"][1]["day"], "we");
        assert_eq!(o["recurrenceOverrides"]["2026-12-02T09:00:00"]["excluded"], true);
        assert_eq!(o["participants"]["p1"]["participationStatus"], "accepted");
        assert_eq!(o["alerts"]["a1"]["trigger"]["offset"], "-PT15M");
        let mut patch = o.clone();
        patch.insert("title".into(), json!("Sync"));
        let new = apply_jscalendar(Some(&cal), &patch).unwrap();
        let out = ical::serialize(&new);
        assert!(out.contains("SUMMARY:Sync") && out.contains("X-KEEP:yes") && out.contains("RRULE:FREQ=WEEKLY") && out.contains("EXDATE;TZID=Europe/Berlin:20261202T090000"), "{out}");
        assert!(ical::validate_calendar(&new, &[]).is_ok());
        assert_eq!(to_jscalendar(&new).unwrap()["recurrenceOverrides"], o["recurrenceOverrides"]);
        let o2 = json!({"@type": "Event", "title": "Lunch", "start": "2026-12-03T12:00:00", "timeZone": "Etc/UTC", "duration": "PT1H",
            "recurrenceOverrides": {"2026-12-10T12:00:00": {"excluded": true}, "2026-12-17T12:00:00": {"title": "Late lunch", "start": "2026-12-17T13:00:00"}},
            "recurrenceRules": [{"frequency": "weekly"}]});
        let made = apply_jscalendar(None, o2.as_object().unwrap()).unwrap();
        let s = ical::serialize(&made);
        assert!(s.contains("DTSTART:20261203T120000Z") && s.contains("EXDATE:20261210T120000Z") && s.contains("RECURRENCE-ID:20261217T120000Z"), "{s}");
        assert!(ical::validate_calendar(&made, &[]).is_ok(), "{s}");
    }

    #[test]
    fn card_roundtrip() {
        let c = ical::parse("BEGIN:VCARD\r\nVERSION:3.0\r\nUID:c1\r\nFN:Amy Lee\r\nN:Lee;Amy;;;\r\nEMAIL;TYPE=work:amy@x.test\r\nTEL:+1 555\r\nORG:Acme;Labs\r\nBDAY:1990-04-05\r\nX-SOCIAL:keep\r\nEND:VCARD\r\n").unwrap();
        let o = to_jscontact(&c);
        assert_eq!(o["name"]["full"], "Amy Lee");
        assert_eq!(o["emails"]["e1"]["address"], "amy@x.test");
        assert_eq!(o["organizations"]["o1"]["units"][0]["name"], "Labs");
        assert_eq!(o["anniversaries"]["b"]["date"]["month"], 4);
        let mut patch = Map::new();
        patch.insert("phones".into(), json!({"t1": {"@type": "Phone", "number": "+1 999"}}));
        let n = ical::serialize(&apply_jscontact(Some(&c), &patch).unwrap());
        assert!(n.contains("TEL:+1 999") && n.contains("EMAIL;TYPE=work:amy@x.test") && n.contains("X-SOCIAL:keep"), "{n}");
    }
}
