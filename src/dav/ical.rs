//! iCalendar (RFC 5545) and vCard (RFC 6350) content: parsing, time ranges
//! with recurrence expansion, and the CalDAV/CardDAV filter languages.
use crate::xml::Element;
use chrono::{DateTime, Duration, NaiveDate, NaiveDateTime, TimeZone, Utc};

pub const CALDAV: &str = "urn:ietf:params:xml:ns:caldav";
pub const CARDDAV: &str = "urn:ietf:params:xml:ns:carddav";

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Prop {
    pub name: String,
    pub params: Vec<(String, String)>,
    pub value: String,
}

impl Prop {
    pub fn param(&self, n: &str) -> Option<&str> {
        self.params.iter().find(|(k, _)| k.eq_ignore_ascii_case(n)).map(|(_, v)| v.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Comp {
    pub name: String,
    pub props: Vec<Prop>,
    pub comps: Vec<Comp>,
}

impl Comp {
    pub fn prop(&self, n: &str) -> Option<&Prop> {
        self.props.iter().find(|p| p.name.eq_ignore_ascii_case(n))
    }
    pub fn props_named<'a>(&'a self, n: &'a str) -> impl Iterator<Item = &'a Prop> + 'a {
        self.props.iter().filter(move |p| p.name.eq_ignore_ascii_case(n))
    }
    pub fn sub<'a>(&'a self, n: &'a str) -> impl Iterator<Item = &'a Comp> + 'a {
        self.comps.iter().filter(move |c| c.name.eq_ignore_ascii_case(n))
    }
}

fn unfold(text: &str) -> Vec<String> {
    let mut out: Vec<String> = vec![];
    for raw in text.split('\n') {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        if (line.starts_with(' ') || line.starts_with('\t')) && !out.is_empty() {
            out.last_mut().unwrap().push_str(&line[1..]);
        } else if !line.is_empty() {
            out.push(line.to_string());
        }
    }
    out
}

fn parse_line(line: &str) -> Option<Prop> {
    // name *(";" param) ":" value, with quoted param values.
    let mut name_end = None;
    let mut in_q = false;
    let mut colon = None;
    for (i, c) in line.char_indices() {
        match c {
            '"' => in_q = !in_q,
            ';' if !in_q && name_end.is_none() => name_end = Some(i),
            ':' if !in_q => {
                colon = Some(i);
                break;
            }
            _ => {}
        }
    }
    let colon = colon?;
    let name_end = name_end.unwrap_or(colon).min(colon);
    let name = line[..name_end].trim().to_ascii_uppercase();
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.') {
        return None;
    }
    let mut params = vec![];
    if name_end < colon {
        let mut cur = String::new();
        let mut q = false;
        for c in line[name_end + 1..colon].chars() {
            match c {
                '"' => q = !q,
                ';' if !q => {
                    params.push(std::mem::take(&mut cur));
                }
                _ => cur.push(c),
            }
        }
        params.push(cur);
    }
    let params = params
        .into_iter()
        .filter_map(|p| {
            let (k, v) = p.split_once('=')?;
            Some((k.trim().to_ascii_uppercase(), v.to_string()))
        })
        .collect();
    Some(Prop { name, params, value: line[colon + 1..].to_string() })
}

/// Parse a calendar or vCard object into its component tree.
pub fn parse(text: &str) -> Result<Comp, String> {
    let lines = unfold(text);
    let mut stack: Vec<Comp> = vec![];
    let mut root = None;
    for l in lines {
        let Some(p) = parse_line(&l) else { return Err(format!("invalid line: {}", l.chars().take(60).collect::<String>())) };
        match p.name.as_str() {
            "BEGIN" => {
                if stack.len() > 16 {
                    return Err("components nested too deeply".into());
                }
                stack.push(Comp { name: p.value.trim().to_ascii_uppercase(), ..Default::default() });
            }
            "END" => {
                let c = stack.pop().ok_or("END without BEGIN")?;
                if !c.name.eq_ignore_ascii_case(p.value.trim()) {
                    return Err(format!("END:{} does not match BEGIN:{}", p.value.trim(), c.name));
                }
                match stack.last_mut() {
                    Some(parent) => parent.comps.push(c),
                    None => {
                        if root.is_some() {
                            return Err("more than one object".into());
                        }
                        root = Some(c);
                    }
                }
            }
            _ => match stack.last_mut() {
                Some(c) => c.props.push(p),
                None => return Err("property outside a component".into()),
            },
        }
    }
    if !stack.is_empty() {
        return Err("unterminated component".into());
    }
    root.ok_or_else(|| "no object found".into())
}

fn escape_param(v: &str) -> String {
    if v.contains([':', ';', ',']) && !v.starts_with('"') {
        format!("\"{v}\"")
    } else {
        v.to_string()
    }
}

/// Serialize with 75-octet line folding.
pub fn serialize(c: &Comp) -> String {
    let mut out = String::new();
    fn fold(out: &mut String, line: &str) {
        let mut cur = 0;
        let bytes = line.as_bytes();
        let mut first = true;
        while cur < bytes.len() {
            let max = if first { 75 } else { 74 };
            let mut end = (cur + max).min(bytes.len());
            while end < bytes.len() && !line.is_char_boundary(end) {
                end -= 1;
            }
            if !first {
                out.push(' ');
            }
            out.push_str(&line[cur..end]);
            out.push_str("\r\n");
            cur = end;
            first = false;
        }
    }
    fn go(c: &Comp, out: &mut String) {
        fold(out, &format!("BEGIN:{}", c.name));
        for p in &c.props {
            let mut l = p.name.clone();
            for (k, v) in &p.params {
                l.push_str(&format!(";{k}={}", escape_param(v)));
            }
            l.push(':');
            l.push_str(&p.value);
            fold(out, &l);
        }
        for s in &c.comps {
            go(s, out);
        }
        fold(out, &format!("END:{}", c.name));
    }
    go(c, &mut out);
    out
}

// ------------------------------------------------------------------ dates

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum When {
    Date(NaiveDate),
    /// UTC instant.
    Utc(DateTime<Utc>),
    /// Floating local time, or a time in a zone we resolved to `tz`.
    Local(NaiveDateTime, Option<chrono_tz::Tz>),
}

impl When {
    /// UTC instant; floating times and dates are taken as UTC.
    pub fn utc(&self) -> DateTime<Utc> {
        match self {
            When::Date(d) => Utc.from_utc_datetime(&d.and_hms_opt(0, 0, 0).unwrap()),
            When::Utc(t) => *t,
            When::Local(n, Some(tz)) => tz.from_local_datetime(n).earliest().map(|t| t.with_timezone(&Utc)).unwrap_or_else(|| Utc.from_utc_datetime(n)),
            When::Local(n, None) => Utc.from_utc_datetime(n),
        }
    }
    pub fn is_date(&self) -> bool {
        matches!(self, When::Date(_))
    }
}

/// Map a TZID to an IANA zone ("/mozilla.org/.../America/New_York" works too).
pub fn zone(tzid: &str) -> Option<chrono_tz::Tz> {
    let t = tzid.trim().trim_matches('"');
    if let Ok(z) = t.parse::<chrono_tz::Tz>() {
        return Some(z);
    }
    let parts: Vec<&str> = t.split('/').filter(|p| !p.is_empty()).collect();
    for n in [2, 3, 1] {
        if parts.len() >= n {
            if let Ok(z) = parts[parts.len() - n..].join("/").parse::<chrono_tz::Tz>() {
                return Some(z);
            }
        }
    }
    match t {
        "Eastern Standard Time" | "US/Eastern" => Some(chrono_tz::America::New_York),
        "Central Standard Time" | "US/Central" => Some(chrono_tz::America::Chicago),
        "Mountain Standard Time" | "US/Mountain" => Some(chrono_tz::America::Denver),
        "Pacific Standard Time" | "US/Pacific" => Some(chrono_tz::America::Los_Angeles),
        "GMT Standard Time" => Some(chrono_tz::Europe::London),
        "W. Europe Standard Time" => Some(chrono_tz::Europe::Berlin),
        _ => None,
    }
}

pub fn parse_when(value: &str, tzid: Option<&str>) -> Option<When> {
    let v = value.trim();
    if v.len() == 8 {
        return NaiveDate::parse_from_str(v, "%Y%m%d").ok().map(When::Date);
    }
    if let Some(u) = v.strip_suffix('Z') {
        return NaiveDateTime::parse_from_str(u, "%Y%m%dT%H%M%S").ok().map(|n| When::Utc(Utc.from_utc_datetime(&n)));
    }
    let n = NaiveDateTime::parse_from_str(v, "%Y%m%dT%H%M%S").ok()?;
    Some(When::Local(n, tzid.and_then(zone)))
}

pub fn prop_when(p: &Prop) -> Option<When> {
    parse_when(&p.value, p.param("TZID"))
}

pub fn parse_duration(s: &str) -> Option<Duration> {
    let s = s.trim();
    let (neg, s) = match s.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, s.strip_prefix('+').unwrap_or(s)),
    };
    let s = s.strip_prefix('P')?;
    let mut total = Duration::zero();
    let mut num = String::new();
    let mut in_time = false;
    for c in s.chars() {
        match c {
            'T' => in_time = true,
            '0'..='9' => num.push(c),
            u => {
                let n: i64 = num.parse().ok()?;
                num.clear();
                total += match (u, in_time) {
                    ('W', _) => Duration::weeks(n),
                    ('D', _) => Duration::days(n),
                    ('H', true) => Duration::hours(n),
                    ('M', true) => Duration::minutes(n),
                    ('S', true) => Duration::seconds(n),
                    _ => return None,
                };
            }
        }
    }
    if !num.is_empty() {
        return None;
    }
    Some(if neg { -total } else { total })
}

/// Parse a CalDAV time-range attribute (UTC, "20060104T000000Z").
pub fn parse_utc(s: &str) -> Option<DateTime<Utc>> {
    match parse_when(s, None)? {
        When::Utc(t) => Some(t),
        w => Some(w.utc()),
    }
}

pub fn fmt_utc(t: DateTime<Utc>) -> String {
    t.format("%Y%m%dT%H%M%SZ").to_string()
}

/// [start, end) of one component instance per RFC 4791 9.9.
pub fn span(c: &Comp, start: When) -> (DateTime<Utc>, DateTime<Utc>) {
    let s = start.utc();
    match c.name.as_str() {
        "VEVENT" => {
            if let Some(e) = c.prop("DTEND").and_then(prop_when) {
                return (s, e.utc());
            }
            if let Some(d) = c.prop("DURATION").and_then(|p| parse_duration(&p.value)) {
                return (s, s + d);
            }
            if start.is_date() {
                (s, s + Duration::days(1))
            } else {
                (s, s)
            }
        }
        "VTODO" => {
            if let Some(d) = c.prop("DURATION").and_then(|p| parse_duration(&p.value)) {
                return (s, s + d);
            }
            if let Some(due) = c.prop("DUE").and_then(prop_when) {
                return (s, due.utc());
            }
            (s, s)
        }
        "VJOURNAL" => {
            if start.is_date() {
                (s, s + Duration::days(1))
            } else {
                (s, s)
            }
        }
        _ => (s, s),
    }
}

fn overlaps(s: DateTime<Utc>, e: DateTime<Utc>, rs: DateTime<Utc>, re: DateTime<Utc>) -> bool {
    if s == e {
        // Zero-length: inside [rs, re) or exactly at rs.
        (rs <= s && s < re) || s == rs
    } else {
        s < re && e > rs
    }
}

fn rrule_set(c: &Comp, start: When) -> Option<rrule::RRuleSet> {
    let rrules: Vec<&Prop> = c.props_named("RRULE").collect();
    let rdates: Vec<&Prop> = c.props_named("RDATE").collect();
    if rrules.is_empty() && rdates.is_empty() {
        return None;
    }
    let dtstart = match start {
        // The rrule crate wants a DATE-TIME; all-day events recur at midnight UTC.
        When::Date(d) => format!("DTSTART:{}T000000Z", d.format("%Y%m%d")),
        When::Utc(t) => format!("DTSTART:{}", fmt_utc(t)),
        When::Local(n, Some(tz)) => format!("DTSTART;TZID={}:{}", tz.name(), n.format("%Y%m%dT%H%M%S")),
        When::Local(n, None) => format!("DTSTART:{}Z", n.format("%Y%m%dT%H%M%S")),
    };
    let mut text = dtstart;
    for r in &rrules {
        // UNTIL must agree with DTSTART's form; normalize floating UNTIL to UTC.
        let mut v = r.value.clone();
        if let When::Date(_) = start {
            // rrule wants a DATE-TIME UNTIL; extend to the end of that day.
            if let Some(pos) = v.find("UNTIL=") {
                let rest = &v[pos + 6..];
                let end = rest.find(';').unwrap_or(rest.len());
                if end == 8 {
                    let d = rest[..end].to_string();
                    v = v.replace(&format!("UNTIL={d}"), &format!("UNTIL={d}T235959Z"));
                }
            }
        }
        text.push_str(&format!("\nRRULE:{v}"));
    }
    let mut set: rrule::RRuleSet = text.parse().ok()?;
    let tz = |w: When| -> Option<DateTime<rrule::Tz>> { Some(w.utc().with_timezone(&rrule::Tz::Tz(chrono_tz::UTC))) };
    for p in rdates {
        for v in p.value.split(',') {
            if let Some(w) = parse_when(v, p.param("TZID")) {
                if let Some(t) = tz(w) {
                    set = set.rdate(t);
                }
            }
        }
    }
    for p in c.props_named("EXDATE") {
        for v in p.value.split(',') {
            if let Some(w) = parse_when(v, p.param("TZID")) {
                if let Some(t) = tz(w) {
                    set = set.exdate(t);
                }
            }
        }
    }
    Some(set)
}

/// Instance start times of a component that may overlap [rs, re).
pub fn instances(c: &Comp, rs: DateTime<Utc>, re: DateTime<Utc>, max: u16) -> Vec<When> {
    let Some(start) = c.prop("DTSTART").and_then(prop_when).or_else(|| {
        // VTODO without DTSTART: DUE (or nothing).
        c.prop("DUE").and_then(prop_when)
    }) else {
        return vec![];
    };
    let Some(set) = rrule_set(c, start) else { return vec![start] };
    let (s0, e0) = span(c, start);
    let len = e0 - s0;
    let after = (rs - len - Duration::seconds(1)).with_timezone(&rrule::Tz::Tz(chrono_tz::UTC));
    let before = re.with_timezone(&rrule::Tz::Tz(chrono_tz::UTC));
    let r = set.after(after).before(before).all(max);
    r.dates
        .into_iter()
        .map(|d| match start {
            When::Date(_) => When::Date(d.date_naive()),
            When::Utc(_) => When::Utc(d.with_timezone(&Utc)),
            When::Local(_, tz) => match tz {
                Some(z) => When::Local(d.with_timezone(&z).naive_local(), Some(z)),
                None => When::Utc(d.with_timezone(&Utc)),
            },
        })
        .collect()
}

/// Does any instance of the component overlap [rs, re)?
pub fn in_range(cal: &Comp, c: &Comp, rs: DateTime<Utc>, re: DateTime<Utc>) -> bool {
    // VTODO special cases (RFC 4791 9.9 table).
    if c.name == "VTODO" && c.prop("DTSTART").is_none() {
        let due = c.prop("DUE").and_then(prop_when).map(|w| w.utc());
        let completed = c.prop("COMPLETED").and_then(prop_when).map(|w| w.utc());
        let created = c.prop("CREATED").and_then(prop_when).map(|w| w.utc());
        return match (due, completed, created) {
            (Some(d), _, _) => rs < d && d <= re || rs <= d && d < re,
            (None, Some(cp), Some(cr)) => (rs <= cr || rs <= cp) && (re > cr || re > cp),
            (None, Some(cp), None) => rs <= cp && re >= cp,
            (None, None, Some(cr)) => re > cr,
            (None, None, None) => true,
        };
    }
    let Some(start) = c.prop("DTSTART").and_then(prop_when) else { return false };
    let overridden: Vec<DateTime<Utc>> = cal
        .sub(&c.name)
        .filter(|o| o.prop("RECURRENCE-ID").is_some() && o.prop("UID").map(|u| &u.value) == c.prop("UID").map(|u| &u.value))
        .filter_map(|o| o.prop("RECURRENCE-ID").and_then(prop_when).map(|w| w.utc()))
        .collect();
    let starts = if c.prop("RECURRENCE-ID").is_some() { vec![start] } else { instances(c, rs, re, 2000) };
    let (s0, e0) = span(c, start);
    let len = e0 - s0;
    for st in starts {
        if c.prop("RECURRENCE-ID").is_none() && overridden.contains(&st.utc()) && st.utc() != start.utc() {
            continue;
        }
        let s = st.utc();
        let e = if c.prop("DTEND").is_some() || c.prop("DURATION").is_some() || st.is_date() { s + len } else { s };
        if overlaps(s, e, rs, re) {
            return true;
        }
    }
    false
}

/// Bounds stored with a resource for quick prefiltering: (start, end) in
/// UTC seconds over all instances; end is i64::MAX for endless rules.
pub fn bounds(cal: &Comp) -> (Option<i64>, Option<i64>) {
    let mut lo: Option<i64> = None;
    let mut hi: Option<i64> = None;
    for c in cal.comps.iter().filter(|c| matches!(c.name.as_str(), "VEVENT" | "VTODO" | "VJOURNAL")) {
        let Some(start) = c.prop("DTSTART").and_then(prop_when).or_else(|| c.prop("DUE").and_then(prop_when)) else {
            return (None, None);
        };
        let (s, e) = span(c, start);
        lo = Some(lo.map_or(s.timestamp(), |x| x.min(s.timestamp())));
        let endless = c.props_named("RRULE").any(|r| !r.value.contains("UNTIL") && !r.value.contains("COUNT"));
        let end = if endless {
            i64::MAX
        } else if c.prop("RRULE").is_some() || c.prop("RDATE").is_some() {
            instances(c, s, Utc::now() + Duration::days(366 * 200), 5000).last().map(|w| span(c, *w).1.timestamp()).unwrap_or(e.timestamp())
        } else {
            e.timestamp()
        };
        hi = Some(hi.map_or(end, |x| x.max(end)));
    }
    (lo, hi)
}

// ------------------------------------------------------------------ validation

/// What's in a calendar object resource: (UID, main component name).
pub fn validate_calendar(c: &Comp, allowed: &[String]) -> Result<(String, String), (&'static str, String)> {
    if c.name != "VCALENDAR" {
        return Err(("valid-calendar-data", "not a VCALENDAR".into()));
    }
    let objs: Vec<&Comp> = c.comps.iter().filter(|x| x.name != "VTIMEZONE").collect();
    if objs.is_empty() {
        return Err(("valid-calendar-object-resource", "no calendar component".into()));
    }
    let kind = objs[0].name.clone();
    if objs.iter().any(|o| o.name != kind) {
        return Err(("valid-calendar-object-resource", "mixed component types".into()));
    }
    if !allowed.is_empty() && !allowed.iter().any(|a| a.eq_ignore_ascii_case(&kind)) {
        return Err(("supported-calendar-component", format!("{kind} is not supported by this calendar")));
    }
    let uid = objs[0].prop("UID").map(|u| u.value.clone()).ok_or(("valid-calendar-object-resource", "missing UID".to_string()))?;
    if objs.iter().any(|o| o.prop("UID").map(|u| &u.value) != Some(&uid)) {
        return Err(("valid-calendar-object-resource", "components have different UIDs".into()));
    }
    if c.prop("METHOD").is_some() {
        return Err(("valid-calendar-object-resource", "calendar object resources must not have METHOD".into()));
    }
    let tzids: std::collections::HashSet<String> = c.sub("VTIMEZONE").filter_map(|t| t.prop("TZID").map(|p| p.value.clone())).collect();
    let master = objs.iter().find(|o| o.prop("RECURRENCE-ID").is_none());
    for o in &objs {
        if matches!(o.name.as_str(), "VEVENT") && o.prop("DTSTART").is_none() {
            return Err(("valid-calendar-data", "VEVENT without DTSTART".into()));
        }
        if o.prop("DTEND").is_some() && o.prop("DURATION").is_some() {
            return Err(("valid-calendar-data", "both DTEND and DURATION".into()));
        }
        if o.props_named("ATTENDEE").count() > MAX_ATTENDEES {
            return Err(("max-attendees-per-instance", format!("more than {MAX_ATTENDEES} attendees")));
        }
        for p in &o.props {
            if let Some(t) = p.param("TZID") {
                if !tzids.contains(t) {
                    return Err(("valid-calendar-object-resource", format!("TZID {t} has no VTIMEZONE")));
                }
            }
            if matches!(p.name.as_str(), "DTSTART" | "DTEND" | "DUE" | "RECURRENCE-ID") && prop_when(p).is_none() {
                return Err(("valid-calendar-data", format!("invalid {} value", p.name)));
            }
            if matches!(p.name.as_str(), "SUMMARY" | "DESCRIPTION" | "LOCATION" | "COMMENT" | "CONTACT" | "RESOURCES" | "CATEGORIES") && !valid_text(&p.value) {
                return Err(("valid-calendar-data", format!("bad escaping in {}", p.name)));
            }
            if p.name == "DURATION" && parse_duration(&p.value).is_none() {
                return Err(("valid-calendar-data", "invalid DURATION".into()));
            }
        }
        if o.prop("RRULE").is_some() {
            if let Some(start) = o.prop("DTSTART").and_then(prop_when) {
                if rrule_set(o, start).is_none() {
                    return Err(("valid-calendar-data", "invalid RRULE".into()));
                }
            }
        }
    }
    // Overridden instances must be instances of the recurrence set.
    if let Some(m) = master.filter(|m| m.prop("RRULE").is_some() || m.prop("RDATE").is_some()) {
        for o in objs.iter().filter(|o| o.prop("RECURRENCE-ID").is_some()) {
            let Some(rid) = o.prop("RECURRENCE-ID").and_then(prop_when).map(|w| w.utc()) else { continue };
            let hit = instances(m, rid - Duration::seconds(1), rid + Duration::seconds(1), 10).iter().any(|w| w.utc() == rid);
            let rdate = m.props_named("RDATE").any(|p| p.value.split(',').filter_map(|v| parse_when(v, p.param("TZID"))).any(|w| w.utc() == rid));
            if !hit && !rdate {
                return Err(("valid-calendar-data", "RECURRENCE-ID is not an instance of the event".into()));
            }
        }
    }
    Ok((uid, kind))
}

pub const MAX_ATTENDEES: usize = 100;

/// RFC 5545 3.3.11: only \\ \; \, \n \N escapes.
fn valid_text(v: &str) -> bool {
    let mut it = v.chars();
    while let Some(c) = it.next() {
        if c == '\\' && !matches!(it.next(), Some('\\' | ';' | ',' | 'n' | 'N')) {
            return false;
        }
    }
    true
}

/// Control characters other than TAB are not allowed in content lines.
pub fn has_controls(text: &str) -> bool {
    text.chars().any(|c| (c as u32) < 0x20 && !matches!(c, '\t' | '\r' | '\n') || c == '\u{7f}')
}

pub fn validate_vcard(c: &Comp) -> Result<String, (&'static str, String)> {
    if c.name != "VCARD" {
        return Err(("valid-address-data", "not a VCARD".into()));
    }
    if c.prop("VERSION").is_none() {
        return Err(("valid-address-data", "missing VERSION".into()));
    }
    if c.prop("FN").is_none() && c.prop("N").is_none() {
        return Err(("valid-address-data", "missing FN".into()));
    }
    Ok(c.prop("UID").map(|u| u.value.clone()).unwrap_or_default())
}

// ------------------------------------------------------------------ filters

fn collation_eq(collation: &str, a: &str, b: &str) -> bool {
    match collation {
        "i;octet" => a == b,
        _ => a.to_lowercase() == b.to_lowercase(),
    }
}

/// CalDAV/CardDAV text-match.
pub fn text_match(e: &Element, value: &str) -> bool {
    let needle = e.text();
    let collation = e.attr("collation").unwrap_or("i;ascii-casemap");
    let mt = e.attr("match-type").unwrap_or("contains");
    let negate = e.attr("negate-condition") == Some("yes");
    let (v, n) = if collation == "i;octet" { (value.to_string(), needle.clone()) } else { (value.to_lowercase(), needle.to_lowercase()) };
    let hit = match mt {
        "equals" => collation_eq(collation, value, &needle),
        "starts-with" => v.starts_with(&n),
        "ends-with" => v.ends_with(&n),
        _ => v.contains(&n),
    };
    hit != negate
}

fn time_range(e: &Element) -> (DateTime<Utc>, DateTime<Utc>) {
    let s = e.attr("start").and_then(parse_utc).unwrap_or(DateTime::<Utc>::MIN_UTC);
    let en = e.attr("end").and_then(parse_utc).unwrap_or(DateTime::<Utc>::MAX_UTC);
    (s, en)
}

/// Valid time-range attributes? (UTC with a Z, start < end.)
pub fn valid_time_range(e: &Element) -> bool {
    let ok = |a: Option<&str>| a.is_none_or(|v| v.ends_with('Z') && v.contains('T') && parse_utc(v).is_some());
    if !ok(e.attr("start")) || !ok(e.attr("end")) || (e.attr("start").is_none() && e.attr("end").is_none()) {
        return false;
    }
    let (s, en) = time_range(e);
    s < en
}

fn prop_filter(f: &Element, props: &[&Prop]) -> bool {
    let name_props = props;
    if f.child(CALDAV, "is-not-defined").is_some() || f.child(CARDDAV, "is-not-defined").is_some() {
        return name_props.is_empty();
    }
    if name_props.is_empty() {
        return false;
    }
    let test_any = f.attr("test") == Some("anyof");
    let checks: Vec<&Element> = f.elements().collect();
    if checks.is_empty() {
        return true;
    }
    name_props.iter().any(|p| {
        let mut results = checks.iter().map(|c| match c.name.as_str() {
            "text-match" => text_match(c, &p.value),
            "time-range" => {
                let (rs, re) = time_range(c);
                prop_when(p).is_some_and(|w| {
                    let t = w.utc();
                    rs <= t && t < re
                })
            }
            "param-filter" => {
                let pname = c.attr("name").unwrap_or("");
                let vals: Vec<&str> = p.params.iter().filter(|(k, _)| k.eq_ignore_ascii_case(pname)).map(|(_, v)| v.as_str()).collect();
                if c.child(CALDAV, "is-not-defined").is_some() || c.child(CARDDAV, "is-not-defined").is_some() {
                    vals.is_empty()
                } else if let Some(tm) = c.elements().find(|x| x.name == "text-match") {
                    vals.iter().any(|v| v.split(',').any(|x| text_match(tm, x.trim_matches('"'))))
                } else {
                    !vals.is_empty()
                }
            }
            _ => true,
        });
        if test_any {
            results.any(|x| x)
        } else {
            results.all(|x| x)
        }
    })
}

/// CalDAV comp-filter against a component (`cal` is the VCALENDAR root).
pub fn comp_filter(f: &Element, cal: &Comp, c: &Comp) -> bool {
    if f.child(CALDAV, "is-not-defined").is_some() {
        return false;
    }
    for child in f.elements() {
        let ok = match child.name.as_str() {
            "time-range" => {
                let (rs, re) = time_range(child);
                if c.name == "VCALENDAR" {
                    c.comps.iter().any(|x| in_range(c, x, rs, re))
                } else if c.name == "VALARM" {
                    true
                } else {
                    in_range(cal, c, rs, re)
                }
            }
            "comp-filter" => {
                let name = child.attr("name").unwrap_or("");
                let subs: Vec<&Comp> = c.sub(name).collect();
                if child.child(CALDAV, "is-not-defined").is_some() {
                    subs.is_empty()
                } else {
                    subs.iter().any(|s| comp_filter(child, cal, s))
                }
            }
            "prop-filter" => {
                let name = child.attr("name").unwrap_or("");
                let ps: Vec<&Prop> = c.props_named(name).collect();
                prop_filter(child, &ps)
            }
            _ => true,
        };
        if !ok {
            return false;
        }
    }
    true
}

/// CalDAV <filter> against a calendar object.
pub fn calendar_filter(filter: &Element, cal: &Comp) -> bool {
    match filter.child(CALDAV, "comp-filter") {
        Some(cf) => {
            if cf.attr("name").is_some_and(|n| !n.eq_ignore_ascii_case(&cal.name)) {
                return false;
            }
            comp_filter(cf, cal, cal)
        }
        None => true,
    }
}

/// CardDAV <filter> against a vCard.
pub fn card_filter(filter: &Element, card: &Comp) -> bool {
    let any = filter.attr("test") == Some("anyof") || filter.attr("test").is_none();
    let mut tests = filter.children_named(CARDDAV, "prop-filter").map(|pf| {
        let name = pf.attr("name").unwrap_or("");
        let ps: Vec<&Prop> = card.props.iter().filter(|p| p.name.eq_ignore_ascii_case(name) || p.name.rsplit('.').next().is_some_and(|n| n.eq_ignore_ascii_case(name))).collect();
        prop_filter(pf, &ps)
    });
    let mut tests = tests.by_ref().peekable();
    if tests.peek().is_none() {
        return true;
    }
    if any {
        tests.any(|x| x)
    } else {
        tests.all(|x| x)
    }
}

// ------------------------------------------------------------------ partial data

/// Apply a CALDAV:calendar-data / CARDDAV:address-data request element:
/// comp/prop selection, and `expand` (recurrences as UTC instances).
pub fn select(e: &Element, root: &Comp) -> Comp {
    let mut c = root.clone();
    if let Some(exp) = e.child(CALDAV, "expand") {
        let (rs, re) = time_range(exp);
        c = expand(&c, rs, re);
    }
    if let Some(lim) = e.child(CALDAV, "limit-recurrence-set") {
        let (rs, re) = time_range(lim);
        c.comps.retain(|x| x.prop("RECURRENCE-ID").is_none() || x.prop("RECURRENCE-ID").and_then(prop_when).is_some_and(|w| { let t = w.utc(); t >= rs && t < re }));
    }
    let sel = e.child(CALDAV, "comp").or_else(|| e.child(CARDDAV, "comp"));
    match sel {
        Some(s) => prune(s, &c),
        None => {
            let props: Vec<&Element> = e.elements().filter(|x| x.name == "prop").collect();
            if props.is_empty() || e.elements().any(|x| x.name == "allprop") {
                return c;
            }
            // CardDAV: <C:prop name="EMAIL"/> list.
            let keep: Vec<String> = props.iter().filter_map(|p| p.attr("name").map(|n| n.to_ascii_uppercase())).collect();
            let mut out = c.clone();
            out.props.retain(|p| keep.contains(&p.name) || matches!(p.name.as_str(), "VERSION" | "UID"));
            out
        }
    }
}

fn prune(sel: &Element, c: &Comp) -> Comp {
    let mut out = Comp { name: c.name.clone(), ..Default::default() };
    if sel.child(CALDAV, "allprop").is_some() {
        out.props = c.props.clone();
    } else {
        let names: Vec<String> = sel.children_named(CALDAV, "prop").filter_map(|p| p.attr("name").map(|n| n.to_ascii_uppercase())).collect();
        out.props = c.props.iter().filter(|p| names.contains(&p.name)).cloned().collect();
    }
    if sel.child(CALDAV, "allcomp").is_some() {
        out.comps = c.comps.clone();
    } else {
        for sub in sel.children_named(CALDAV, "comp") {
            let name = sub.attr("name").unwrap_or("");
            for x in c.sub(name) {
                out.comps.push(prune(sub, x));
            }
        }
    }
    out
}

/// Replace recurring components by their instances in [rs, re), in UTC.
pub fn expand(cal: &Comp, rs: DateTime<Utc>, re: DateTime<Utc>) -> Comp {
    let mut out = Comp { name: cal.name.clone(), props: cal.props.clone(), comps: vec![] };
    for c in &cal.comps {
        if c.name == "VTIMEZONE" {
            continue;
        }
        if c.prop("RECURRENCE-ID").is_some() {
            continue;
        }
        let Some(start) = c.prop("DTSTART").and_then(prop_when) else {
            out.comps.push(c.clone());
            continue;
        };
        let recurring = c.prop("RRULE").is_some() || c.prop("RDATE").is_some();
        let overrides: Vec<&Comp> = cal.sub(&c.name).filter(|o| o.prop("RECURRENCE-ID").is_some()).collect();
        let (s0, e0) = span(c, start);
        let len = e0 - s0;
        let starts = if recurring { instances(c, rs, re, 2000) } else { vec![start] };
        for st in starts {
            let su = st.utc();
            if let Some(ov) = overrides.iter().find(|o| o.prop("RECURRENCE-ID").and_then(prop_when).map(|w| w.utc()) == Some(su)) {
                let os = ov.prop("DTSTART").and_then(prop_when).unwrap_or(st);
                let (a, b) = span(ov, os);
                if overlaps(a, b, rs, re) {
                    out.comps.push(to_utc(ov, None));
                }
                continue;
            }
            let (a, b) = (su, if len.is_zero() && !st.is_date() { su } else { su + len });
            if !overlaps(a, b, rs, re) {
                continue;
            }
            let mut inst = to_utc(c, Some(st));
            inst.props.retain(|p| !matches!(p.name.as_str(), "RRULE" | "RDATE" | "EXDATE" | "EXRULE"));
            if recurring {
                let rid = if st.is_date() {
                    Prop { name: "RECURRENCE-ID".into(), params: vec![("VALUE".into(), "DATE".into())], value: st.utc().format("%Y%m%d").to_string() }
                } else {
                    Prop { name: "RECURRENCE-ID".into(), params: vec![], value: fmt_utc(su) }
                };
                inst.props.push(rid);
            }
            out.comps.push(inst);
        }
        // Overrides whose instance wasn't produced (moved into range).
        for ov in overrides {
            let os = ov.prop("DTSTART").and_then(prop_when);
            if let Some(os) = os {
                let (a, b) = span(ov, os);
                let rid = ov.prop("RECURRENCE-ID").and_then(prop_when).map(|w| w.utc());
                let already = out.comps.iter().any(|x| x.prop("RECURRENCE-ID").map(|p| p.value.clone()) == rid.map(fmt_utc));
                if overlaps(a, b, rs, re) && !already {
                    out.comps.push(to_utc(ov, None));
                }
            }
        }
    }
    out
}

/// Copy with date-times converted to UTC (DTSTART replaced by `start`).
fn to_utc(c: &Comp, start: Option<When>) -> Comp {
    let mut out = c.clone();
    let orig_start = c.prop("DTSTART").and_then(prop_when);
    for p in out.props.iter_mut() {
        if matches!(p.name.as_str(), "DTSTART" | "DTEND" | "DUE" | "RECURRENCE-ID" | "EXDATE" | "RDATE") {
            let w = if p.name == "DTSTART" { start.or_else(|| prop_when(p)) } else { prop_when(p) };
            let w = match (p.name.as_str(), start, orig_start, w) {
                ("DTEND" | "DUE", Some(ns), Some(os), Some(w)) => {
                    let shift = ns.utc() - os.utc();
                    Some(When::Utc(w.utc() + shift))
                }
                (_, _, _, w) => w,
            };
            if let Some(w) = w {
                if !w.is_date() {
                    p.value = fmt_utc(w.utc());
                    p.params.retain(|(k, _)| k != "TZID");
                } else if let (When::Date(d), "DTSTART") = (w, p.name.as_str()) {
                    p.value = d.format("%Y%m%d").to_string();
                }
            }
        }
    }
    out.comps.retain(|x| x.name != "VTIMEZONE");
    out
}

/// Busy periods (start, end, FBTYPE) in [rs, re) for free-busy-query.
pub fn busy(cal: &Comp, rs: DateTime<Utc>, re: DateTime<Utc>) -> Vec<(DateTime<Utc>, DateTime<Utc>, String)> {
    let mut out = vec![];
    let exp = expand(cal, rs, re);
    for c in exp.sub("VEVENT") {
        if c.prop("TRANSP").is_some_and(|t| t.value.eq_ignore_ascii_case("TRANSPARENT")) {
            continue;
        }
        let status = c.prop("STATUS").map(|s| s.value.to_ascii_uppercase()).unwrap_or_default();
        if status == "CANCELLED" {
            continue;
        }
        let Some(st) = c.prop("DTSTART").and_then(prop_when) else { continue };
        let (a, b) = span(c, st);
        if a == b {
            continue;
        }
        let kind = if status == "TENTATIVE" { "BUSY-TENTATIVE" } else { "BUSY" };
        out.push((a.max(rs), b.min(re), kind.to_string()));
    }
    for fb in cal.sub("VFREEBUSY") {
        for p in fb.props_named("FREEBUSY") {
            let kind = p.param("FBTYPE").unwrap_or("BUSY").to_ascii_uppercase();
            if kind == "FREE" {
                continue;
            }
            for period in p.value.split(',') {
                let Some((a, b)) = period.split_once('/') else { continue };
                let Some(s) = parse_utc(a) else { continue };
                let e = parse_utc(b).or_else(|| parse_duration(b).map(|d| s + d));
                if let Some(e) = e {
                    if s < re && e > rs {
                        out.push((s.max(rs), e.min(re), kind.clone()));
                    }
                }
            }
        }
    }
    // Merge overlapping periods of the same type (RFC 5545 FREEBUSY is a set).
    out.sort_by(|a, b| a.2.cmp(&b.2).then(a.0.cmp(&b.0)));
    let mut merged: Vec<(DateTime<Utc>, DateTime<Utc>, String)> = vec![];
    for p in out {
        if let Some(last) = merged.last_mut() {
            if last.2 == p.2 && p.0 <= last.1 {
                if p.1 > last.1 {
                    last.1 = p.1;
                }
                continue;
            }
        }
        merged.push(p);
    }
    merged.sort_by(|a, b| a.0.cmp(&b.0).then(a.2.cmp(&b.2)));
    merged
}

/// Interpret floating date-times in `tz` (the calendar's time zone,
/// RFC 4791 7.3): adds TZID to DTSTART/DTEND/DUE/RECURRENCE-ID/EXDATE/RDATE
/// values that have no zone and aren't dates.
pub fn apply_floating(c: &mut Comp, tz: &str) {
    for p in c.props.iter_mut() {
        if matches!(p.name.as_str(), "DTSTART" | "DTEND" | "DUE" | "RECURRENCE-ID" | "EXDATE" | "RDATE")
            && p.param("TZID").is_none()
            && p.value.contains('T')
            && !p.value.ends_with('Z')
            && !p.value.contains(['/', 'Z'])
        {
            p.params.push(("TZID".into(), tz.into()));
        }
    }
    for x in c.comps.iter_mut() {
        apply_floating(x, tz);
    }
}

/// IANA zone of a CALDAV:calendar-timezone value (a VCALENDAR with one VTIMEZONE).
pub fn timezone_of(cal_tz: &str) -> Option<String> {
    let c = parse(cal_tz).ok()?;
    let t = c.sub("VTIMEZONE").next()?;
    let id = t.prop("TZID")?.value.clone();
    let named = t.prop("X-LIC-LOCATION").map(|p| p.value.clone());
    named.as_deref().and_then(zone).or_else(|| zone(&id)).map(|z| z.name().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const EV: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//t//t//EN\r\nBEGIN:VTIMEZONE\r\nTZID:America/New_York\r\nBEGIN:STANDARD\r\nDTSTART:19701101T020000\r\nTZOFFSETFROM:-0400\r\nTZOFFSETTO:-0500\r\nEND:STANDARD\r\nEND:VTIMEZONE\r\nBEGIN:VEVENT\r\nUID:abc\r\nDTSTART;TZID=America/New_York:20250106T090000\r\nDURATION:PT1H\r\nRRULE:FREQ=WEEKLY;COUNT=10\r\nEXDATE;TZID=America/New_York:20250113T090000\r\nSUMMARY:Standup with a very long summary line that will need to be folded because it is longer than seventy five octets\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

    #[test]
    fn parse_roundtrip() {
        let c = parse(EV).unwrap();
        assert_eq!(c.name, "VCALENDAR");
        let ev = c.sub("VEVENT").next().unwrap();
        assert_eq!(ev.prop("UID").unwrap().value, "abc");
        let s = serialize(&c);
        assert!(s.lines().all(|l| l.len() <= 75));
        assert_eq!(parse(&s).unwrap(), c);
        assert!(validate_calendar(&c, &[]).is_ok());
    }

    #[test]
    fn recurrence() {
        let c = parse(EV).unwrap();
        let ev = c.sub("VEVENT").next().unwrap();
        let rs = parse_utc("20250113T000000Z").unwrap();
        let re = parse_utc("20250114T000000Z").unwrap();
        assert!(!in_range(&c, ev, rs, re), "excluded date");
        let rs = parse_utc("20250120T140000Z").unwrap();
        let re = parse_utc("20250120T143000Z").unwrap();
        assert!(in_range(&c, ev, rs, re), "9am EST = 14Z");
        let x = expand(&c, parse_utc("20250101T000000Z").unwrap(), parse_utc("20250201T000000Z").unwrap());
        assert_eq!(x.sub("VEVENT").count(), 3); // Jan 6, 20, 27 (13 excluded)
        let (lo, hi) = bounds(&c);
        assert!(lo.is_some() && hi.unwrap() < i64::MAX);
    }

    #[test]
    fn durations() {
        assert_eq!(parse_duration("P1W"), Some(Duration::weeks(1)));
        assert_eq!(parse_duration("-PT15M"), Some(Duration::minutes(-15)));
        assert_eq!(parse_duration("P1DT2H"), Some(Duration::hours(26)));
        assert_eq!(parse_duration("PT"), Some(Duration::zero()));
    }

    #[test]
    fn filters() {
        let c = parse(EV).unwrap();
        let f = crate::xml::parse(format!(r#"<C:filter xmlns:C="{CALDAV}"><C:comp-filter name="VCALENDAR"><C:comp-filter name="VEVENT"><C:prop-filter name="SUMMARY"><C:text-match>standup</C:text-match></C:prop-filter><C:time-range start="20250120T000000Z" end="20250121T000000Z"/></C:comp-filter></C:comp-filter></C:filter>"#).as_bytes()).unwrap();
        assert!(calendar_filter(&f, &c));
        let card = parse("BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Jane Doe\r\nEMAIL;TYPE=work:jane@example.com\r\nUID:j1\r\nEND:VCARD\r\n").unwrap();
        let f = crate::xml::parse(format!(r#"<C:filter xmlns:C="{CARDDAV}"><C:prop-filter name="EMAIL"><C:text-match match-type="ends-with">@example.com</C:text-match></C:prop-filter></C:filter>"#).as_bytes()).unwrap();
        assert!(card_filter(&f, &card));
        assert_eq!(validate_vcard(&card).unwrap(), "j1");
    }
}

/// RFC 4791 9.7: structural rules for calendar-query filters.
pub fn valid_calendar_filter(filter: &Element) -> bool {
    fn comps_allowed(parent: &str) -> &'static [&'static str] {
        match parent {
            "" => &["VCALENDAR"],
            "VCALENDAR" => &["VEVENT", "VTODO", "VJOURNAL", "VFREEBUSY", "VTIMEZONE", "VAVAILABILITY"],
            "VEVENT" | "VTODO" => &["VALARM"],
            "VTIMEZONE" => &["STANDARD", "DAYLIGHT"],
            "VAVAILABILITY" => &["AVAILABLE"],
            _ => &[],
        }
    }
    fn comp(e: &Element, parent: &str) -> bool {
        let name = e.attr("name").unwrap_or("").to_ascii_uppercase();
        if !comps_allowed(parent).contains(&name.as_str()) {
            return false;
        }
        for c in e.elements() {
            let ok = match c.name.as_str() {
                "comp-filter" => comp(c, &name),
                "time-range" => matches!(name.as_str(), "VEVENT" | "VTODO" | "VJOURNAL" | "VFREEBUSY" | "VALARM" | "VAVAILABILITY" | "AVAILABLE") && valid_time_range(c),
                "prop-filter" => prop(c),
                "is-not-defined" => true,
                _ => false,
            };
            if !ok {
                return false;
            }
        }
        true
    }
    fn prop(e: &Element) -> bool {
        let name = e.attr("name").unwrap_or("").to_ascii_uppercase();
        for c in e.elements() {
            let ok = match c.name.as_str() {
                "time-range" => matches!(name.as_str(), "DTSTART" | "DTEND" | "DUE" | "COMPLETED" | "CREATED" | "LAST-MODIFIED" | "DTSTAMP" | "RECURRENCE-ID" | "EXDATE" | "RDATE") && valid_time_range(c),
                "text-match" => c.attr("collation").is_none_or(|col| matches!(col, "i;ascii-casemap" | "i;octet" | "i;unicode-casemap")),
                "param-filter" | "is-not-defined" => true,
                _ => false,
            };
            if !ok {
                return false;
            }
        }
        true
    }
    let comps: Vec<&Element> = filter.elements().collect();
    comps.len() == 1 && comps[0].name == "comp-filter" && comp(comps[0], "")
}
