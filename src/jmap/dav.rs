//! JMAP for Calendars and JMAP for Contacts (RFC 9610) over the CalDAV and
//! CardDAV store, and JMAP Sharing's Principal (RFC 9670) for free/busy.
//!
//! Ids: calendars `c<node>`, events `v<node>`, address books `b<node>`,
//! cards `k<node>`; the principal is `P<account>`. Each event lives in one
//! calendar and each card in one address book. Writes go through the same
//! validation, quota and sync-token bookkeeping as CalDAV/CardDAV, so both
//! protocols always see the same data.
use super::mail::{ids_arg, num_id, pick, set_error, state_str};
use super::{account_id, Ctx, MethodError};
use crate::dav::jscal;
use crate::dav::{ical, store, Node, Principal};
use serde_json::{json, Map, Value};
use std::collections::HashMap;

type R = Result<Vec<(String, Value)>, MethodError>;

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Calendar,
    Event,
    Book,
    Card,
}

impl Kind {
    fn of(name: &str) -> Option<Kind> {
        Some(match name.split('/').next()? {
            "Calendar" => Kind::Calendar,
            "CalendarEvent" => Kind::Event,
            "AddressBook" => Kind::Book,
            "ContactCard" => Kind::Card,
            _ => return None,
        })
    }
    fn prefix(self) -> char {
        match self {
            Kind::Calendar => 'c',
            Kind::Event => 'v',
            Kind::Book => 'b',
            Kind::Card => 'k',
        }
    }
    fn type_name(self) -> &'static str {
        match self {
            Kind::Calendar => "Calendar",
            Kind::Event => "CalendarEvent",
            Kind::Book => "AddressBook",
            Kind::Card => "ContactCard",
        }
    }
    fn home(self) -> &'static str {
        match self {
            Kind::Calendar | Kind::Event => "calendars",
            Kind::Book | Kind::Card => "addressbooks",
        }
    }
    fn collection(self) -> bool {
        matches!(self, Kind::Calendar | Kind::Book)
    }
}

async fn principal(ctx: &Ctx) -> Result<Principal, MethodError> {
    store::principal(&ctx.state, &ctx.account).await?.ok_or_else(|| MethodError("accountNotSupportedByMethod", "Calendars and contacts aren't on for this account.".into()))
}

async fn collections(ctx: &Ctx, p: &Principal, kind: Kind) -> Result<Vec<Node>, MethodError> {
    let want = if matches!(kind, Kind::Calendar | Kind::Event) { "calendar" } else { "addressbook" };
    Ok(ctx.state.db.dav_children(p.id, kind.home()).await?.into_iter().filter(|n| n.collection && n.kind == want).collect())
}

/// All objects of a kind: (collection id, node).
async fn objects(ctx: &Ctx, p: &Principal, kind: Kind) -> Result<Vec<(i64, Node)>, MethodError> {
    let mut out = vec![];
    for c in collections(ctx, p, kind).await? {
        for n in ctx.state.db.dav_children(p.id, &c.path).await?.into_iter().filter(|n| !n.collection) {
            out.push((c.id, n));
        }
    }
    Ok(out)
}

fn rights_calendar() -> Value {
    json!({"mayReadFreeBusy": true, "mayReadItems": true, "mayWriteAll": true, "mayWriteOwn": true, "mayUpdatePrivate": true,
        "mayRSVP": true, "mayShare": false, "mayDelete": true})
}

fn collection_json(kind: Kind, n: &Node, default: bool) -> Map<String, Value> {
    let mut o = Map::new();
    o.insert("id".into(), json!(format!("{}{}", kind.prefix(), n.id)));
    o.insert("name".into(), json!(n.prop_str("displayname").unwrap_or_else(|| n.name().to_string())));
    o.insert("description".into(), n.prop_str("description").map(Value::from).unwrap_or(Value::Null));
    o.insert("sortOrder".into(), json!(n.prop_str("order").and_then(|s| s.parse::<i64>().ok()).unwrap_or(0)));
    o.insert("isSubscribed".into(), json!(true));
    o.insert("isDefault".into(), json!(default));
    o.insert("shareWith".into(), Value::Null);
    if kind == Kind::Calendar {
        o.insert("color".into(), n.prop_str("color").map(Value::from).unwrap_or(Value::Null));
        o.insert("isVisible".into(), json!(true));
        o.insert("includeInAvailability".into(), json!(if n.prop_str("transp").is_some_and(|t| t.contains("transparent")) { "none" } else { "all" }));
        o.insert("timeZone".into(), n.prop_str("timezone").and_then(|t| ical::timezone_of(&t)).map(Value::from).unwrap_or(Value::Null));
        o.insert("myRights".into(), rights_calendar());
    } else {
        o.insert("myRights".into(), json!({"mayRead": true, "mayWrite": true, "mayShare": false, "mayDelete": true}));
    }
    o
}

async fn object_json(ctx: &Ctx, kind: Kind, coll: i64, n: &Node) -> Option<Map<String, Value>> {
    let text = store::read(&ctx.state, n).await.ok()?;
    let comp = ical::parse(&text).ok()?;
    let mut o = if kind == Kind::Event { jscal::to_jscalendar(&comp)? } else { jscal::to_jscontact(&comp) };
    o.insert("id".into(), json!(format!("{}{}", kind.prefix(), n.id)));
    if kind == Kind::Event {
        o.insert("calendarIds".into(), json!({format!("c{coll}"): true}));
        o.insert("created".into(), json!(utc(n.created_at)));
        o.insert("updated".into(), json!(utc(n.updated_at)));
    } else {
        o.insert("addressBookIds".into(), json!({format!("b{coll}"): true}));
        o.insert("updated".into(), json!(utc(n.updated_at)));
    }
    o.insert("blobId".into(), json!(format!("D{}", n.id)));
    Some(o)
}

fn utc(t: i64) -> String {
    chrono::DateTime::from_timestamp(t, 0).unwrap_or_default().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

pub async fn call(ctx: &mut Ctx, name: &str, args: &Value) -> R {
    let one = |v: Value| Ok(vec![(name.to_string(), v)]);
    match name {
        "Principal/get" => one(principal_get(ctx, args).await?),
        "Principal/query" => one(principal_query(ctx, args).await?),
        "Principal/set" => one(principal_set(ctx, args).await?),
        "Principal/changes" | "ShareNotification/changes" | "CalendarEventNotification/changes" => one(no_changes(ctx, args).await?),
        "Principal/getAvailability" => one(availability(ctx, args).await?),
        "ParticipantIdentity/get" => {
            let st = state_str(ctx).await?;
            let mut list = vec![json!({"id": "pi1", "name": ctx.account.display_name, "sendTo": {"imip": format!("mailto:{}", ctx.account.email)}})];
            for a in ctx.state.db.list_aliases().await? {
                if a.active && !a.source.starts_with('@') && a.destination.split([',', ' ']).any(|d| d.trim().eq_ignore_ascii_case(&ctx.account.email)) {
                    list.push(json!({"id": format!("pi{}", a.id + 1), "name": ctx.account.display_name, "sendTo": {"imip": format!("mailto:{}", a.source)}}));
                }
            }
            one(json!({"accountId": account_id(&ctx.account), "state": st, "list": list, "notFound": []}))
        }
        "ShareNotification/get" | "CalendarEventNotification/get" => {
            let st = state_str(ctx).await?;
            let nf: Vec<Value> = args.get("ids").and_then(|v| v.as_array()).cloned().unwrap_or_default();
            one(json!({"accountId": account_id(&ctx.account), "state": st, "list": [], "notFound": nf}))
        }
        "ShareNotification/set" | "CalendarEventNotification/set" => {
            let st = state_str(ctx).await?;
            let mut nd = Map::new();
            for id in args.get("destroy").and_then(|v| v.as_array()).into_iter().flatten().filter_map(|v| v.as_str()) {
                nd.insert(id.into(), set_error("notFound", "No such notification"));
            }
            one(json!({"accountId": account_id(&ctx.account), "oldState": st, "newState": st, "destroyed": [], "notDestroyed": nd}))
        }
        "CalendarEvent/parse" => one(event_parse(ctx, args).await?),
        _ => {
            let kind = Kind::of(name).ok_or_else(|| MethodError("unknownMethod", format!("Unknown method {name}")))?;
            let method = name.rsplit('/').next().unwrap_or("");
            match method {
                "get" => one(get(ctx, kind, args).await?),
                "changes" => one(changes(ctx, kind, args).await?),
                "query" if !kind.collection() => one(query(ctx, kind, args).await?),
                "queryChanges" if !kind.collection() => one(query_changes(ctx, kind, args).await?),
                "set" => set(ctx, kind, args).await,
                "copy" if !kind.collection() => one(copy(ctx, kind, args).await?),
                _ => Err(MethodError("unknownMethod", format!("Unknown method {name}"))),
            }
        }
    }
}

async fn no_changes(ctx: &Ctx, args: &Value) -> Result<Value, MethodError> {
    let st = state_str(ctx).await?;
    let since = args.get("sinceState").and_then(|v| v.as_str()).unwrap_or("");
    Ok(json!({"accountId": account_id(&ctx.account), "oldState": since, "newState": st, "hasMoreChanges": false, "created": [], "updated": [], "destroyed": []}))
}

async fn get(ctx: &mut Ctx, kind: Kind, args: &Value) -> Result<Value, MethodError> {
    let p = principal(ctx).await?;
    let st = state_str(ctx).await?;
    let ids = ids_arg(ctx, args)?;
    let props: Option<Vec<String>> = args.get("properties").and_then(|v| v.as_array()).map(|a| {
        let mut v: Vec<String> = a.iter().filter_map(|x| x.as_str().map(String::from)).collect();
        v.push("id".into());
        v
    });
    let filter = |o: Map<String, Value>| match &props {
        Some(pr) => pick(o, pr),
        None => Value::Object(o),
    };
    let (mut list, mut not_found) = (vec![], vec![]);
    if kind.collection() {
        let colls = collections(ctx, &p, kind).await?;
        let first = colls.first().map(|c| c.id);
        let all: Vec<Value> = colls.iter().map(|c| filter(collection_json(kind, c, Some(c.id) == first))).collect();
        match ids {
            None => list = all,
            Some(ids) => {
                for id in ids {
                    match all.iter().find(|v| v["id"] == json!(id)) {
                        Some(v) => list.push(v.clone()),
                        None => not_found.push(id),
                    }
                }
            }
        }
    } else {
        let objs = objects(ctx, &p, kind).await?;
        let by_id: HashMap<i64, &(i64, Node)> = objs.iter().map(|o| (o.1.id, o)).collect();
        let wanted: Vec<String> = ids.unwrap_or_else(|| objs.iter().map(|(_, n)| format!("{}{}", kind.prefix(), n.id)).collect());
        if wanted.len() > super::MAX_OBJECTS {
            return Err(MethodError("requestTooLarge", "Too many ids.".into()));
        }
        for id in wanted {
            match num_id(&id, kind.prefix()).and_then(|n| by_id.get(&n)) {
                Some((c, n)) => match object_json(ctx, kind, *c, n).await {
                    Some(o) => list.push(filter(o)),
                    None => not_found.push(id),
                },
                None => not_found.push(id),
            }
        }
    }
    Ok(json!({"accountId": account_id(&ctx.account), "state": st, "list": list, "notFound": not_found}))
}

async fn changes(ctx: &mut Ctx, kind: Kind, args: &Value) -> Result<Value, MethodError> {
    let since_s = args.get("sinceState").and_then(|v| v.as_str()).ok_or_else(|| MethodError::invalid("sinceState is required"))?;
    let since: i64 = since_s.parse().map_err(|_| MethodError("cannotCalculateChanges", "Unknown state.".into()))?;
    let max = args.get("maxChanges").and_then(|v| v.as_i64()).unwrap_or(5000).clamp(1, 50_000);
    let Some((rows, new_state, more)) = ctx.state.db.changes_since(ctx.account.id, kind.type_name(), since, max).await? else {
        return Err(MethodError("cannotCalculateChanges", "State too old; fetch everything again.".into()));
    };
    let (mut first, mut last, mut order): (HashMap<i64, String>, HashMap<i64, String>, Vec<i64>) = Default::default();
    for (id, op) in rows {
        first.entry(id).or_insert_with(|| {
            order.push(id);
            op.clone()
        });
        last.insert(id, op);
    }
    let (mut created, mut updated, mut destroyed) = (vec![], vec![], vec![]);
    for id in order {
        let sid = format!("{}{id}", kind.prefix());
        match (first[&id].as_str(), last[&id].as_str()) {
            ("c", "d") => {}
            ("c", _) => created.push(sid),
            (_, "d") => destroyed.push(sid),
            _ => updated.push(sid),
        }
    }
    let mut out = json!({"accountId": account_id(&ctx.account), "oldState": since_s, "newState": new_state.to_string(),
        "hasMoreChanges": more, "created": created, "updated": updated, "destroyed": destroyed});
    if kind.collection() {
        out["updatedProperties"] = Value::Null;
    }
    Ok(out)
}

fn text_has(hay: &Value, needle: &str) -> bool {
    hay.to_string().to_lowercase().contains(&needle.to_lowercase())
}

/// Whether an object matches a filter (FilterCondition or FilterOperator).
fn matches(o: &Map<String, Value>, f: &Value, ctx: &Ctx) -> Result<bool, MethodError> {
    if let Some(op) = f.get("operator").and_then(|v| v.as_str()) {
        let conds = f.get("conditions").and_then(|v| v.as_array()).cloned().unwrap_or_default();
        let mut r = vec![];
        for c in &conds {
            r.push(matches(o, c, ctx)?);
        }
        return Ok(match op {
            "AND" => r.iter().all(|x| *x),
            "OR" => r.iter().any(|x| *x),
            "NOT" => !r.iter().any(|x| *x),
            _ => return Err(MethodError("unsupportedFilter", format!("Unknown operator {op}"))),
        });
    }
    let Some(f) = f.as_object() else { return Ok(true) };
    let v = Value::Object(o.clone());
    for (k, want) in f {
        let s = want.as_str().unwrap_or("");
        let ok = match k.as_str() {
            "inCalendar" => o.get("calendarIds").and_then(|c| c.get(ctx.id(s))).is_some(),
            "inCalendars" => want.as_array().into_iter().flatten().filter_map(|x| x.as_str()).any(|c| o.get("calendarIds").and_then(|ids| ids.get(ctx.id(c))).is_some()),
            "inAddressBook" => o.get("addressBookIds").and_then(|c| c.get(ctx.id(s))).is_some(),
            "uid" => o.get("uid").and_then(|u| u.as_str()) == Some(s),
            "text" => text_has(&v, s),
            "title" => o.get("title").is_some_and(|t| text_has(t, s)),
            "description" => o.get("description").is_some_and(|t| text_has(t, s)),
            "location" => o.get("locations").is_some_and(|t| text_has(t, s)),
            "owner" | "attendee" | "participant" => o.get("participants").is_some_and(|t| text_has(t, s)),
            "name" => o.get("name").is_some_and(|t| text_has(t, s)),
            "email" => o.get("emails").is_some_and(|t| text_has(t, s)),
            "phone" => o.get("phones").is_some_and(|t| text_has(t, s)),
            "organization" => o.get("organizations").is_some_and(|t| text_has(t, s)),
            "kind" => o.get("kind").and_then(|x| x.as_str()).unwrap_or("individual") == s,
            "hasMember" => o.get("members").and_then(|m| m.get(s)).is_some(),
            "before" | "after" => true, // checked with the event's occurrences below
            other => return Err(MethodError("unsupportedFilter", format!("Unsupported filter {other}"))),
        };
        if !ok {
            return Ok(false);
        }
    }
    Ok(true)
}

/// The UTC range a time filter asks about.
fn time_range(f: &Value) -> (Option<chrono::DateTime<chrono::Utc>>, Option<chrono::DateTime<chrono::Utc>>) {
    let parse = |k: &str| {
        let s = f.get(k)?.as_str()?;
        chrono::DateTime::parse_from_rfc3339(s).ok().map(|d| d.with_timezone(&chrono::Utc)).or_else(|| jscal::to_utc(s.trim_end_matches('Z'), None))
    };
    (parse("after"), parse("before"))
}

/// Objects matching a query, sorted, as (id, sort key) pairs.
async fn run_query(ctx: &mut Ctx, kind: Kind, args: &Value) -> Result<Vec<String>, MethodError> {
    let p = principal(ctx).await?;
    let filter = args.get("filter").cloned().unwrap_or(Value::Null);
    let (after, before) = time_range(&filter);
    let mut hits: Vec<(String, String, i64)> = vec![];
    for (c, n) in objects(ctx, &p, kind).await? {
        if kind == Kind::Event && (after.is_some() || before.is_some()) {
            let rs = after.unwrap_or(chrono::DateTime::<chrono::Utc>::MIN_UTC);
            let re = before.unwrap_or(chrono::DateTime::<chrono::Utc>::MAX_UTC);
            // Prefilter on stored bounds, then check occurrences.
            if n.dtstart.is_some_and(|s| s >= re.timestamp()) || n.dtend.is_some_and(|e| e <= rs.timestamp()) {
                continue;
            }
            let Ok(text) = store::read(&ctx.state, &n).await else { continue };
            let Ok(cal) = ical::parse(&text) else { continue };
            let hit = cal.comps.iter().filter(|x| x.name == "VEVENT" || x.name == "VTODO").any(|x| ical::in_range(&cal, x, rs, re));
            if !hit {
                continue;
            }
        }
        let Some(o) = object_json(ctx, kind, c, &n).await else { continue };
        if !filter.is_null() && !matches(&o, &filter, ctx)? {
            continue;
        }
        let key = if kind == Kind::Event {
            o.get("start").and_then(|s| s.as_str()).unwrap_or("").to_string()
        } else {
            o.get("name").and_then(|x| x["full"].as_str()).unwrap_or("").to_lowercase()
        };
        hits.push((format!("{}{}", kind.prefix(), n.id), key, n.updated_at));
    }
    let sort = args.get("sort").and_then(|v| v.as_array()).and_then(|a| a.first()).cloned();
    let asc = sort.as_ref().and_then(|s| s.get("isAscending")).and_then(|v| v.as_bool()).unwrap_or(true);
    match sort.as_ref().and_then(|s| s.get("property")).and_then(|v| v.as_str()) {
        None | Some("start" | "name" | "uid") => hits.sort_by(|a, b| a.1.cmp(&b.1).then(a.0.cmp(&b.0))),
        Some("updated" | "created") => hits.sort_by_key(|h| h.2),
        Some(other) => return Err(MethodError("unsupportedSort", format!("Can't sort by {other}"))),
    }
    if !asc {
        hits.reverse();
    }
    Ok(hits.into_iter().map(|h| h.0).collect())
}

async fn query(ctx: &mut Ctx, kind: Kind, args: &Value) -> Result<Value, MethodError> {
    let ids = run_query(ctx, kind, args).await?;
    let total = ids.len();
    let mut position = args.get("position").and_then(|v| v.as_i64()).unwrap_or(0);
    if position < 0 {
        position = (total as i64 + position).max(0);
    }
    if let Some(anchor) = args.get("anchor").and_then(|v| v.as_str()) {
        let a = ctx.id(anchor);
        let i = ids.iter().position(|x| *x == a).ok_or(MethodError("anchorNotFound", "Anchor not in results.".into()))? as i64;
        position = (i + args.get("anchorOffset").and_then(|v| v.as_i64()).unwrap_or(0)).max(0);
    }
    let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(10_000).min(10_000) as usize;
    let page: Vec<String> = ids.into_iter().skip(position as usize).take(limit).collect();
    let mut out = json!({"accountId": account_id(&ctx.account), "queryState": state_str(ctx).await?, "canCalculateChanges": true, "position": position, "ids": page});
    if args.get("calculateTotal").and_then(|v| v.as_bool()).unwrap_or(false) {
        out["total"] = json!(total);
    }
    Ok(out)
}

/// Like Email/queryChanges: what changed since then is removed and, if it
/// still matches, added at its current index (RFC 8620 5.6 allows it).
async fn query_changes(ctx: &mut Ctx, kind: Kind, args: &Value) -> Result<Value, MethodError> {
    let since_s = args.get("sinceQueryState").and_then(|v| v.as_str()).ok_or_else(|| MethodError::invalid("sinceQueryState is required"))?;
    let since: i64 = since_s.parse().map_err(|_| MethodError("cannotCalculateChanges", "Unknown state.".into()))?;
    let Some((rows, _, more)) = ctx.state.db.changes_since(ctx.account.id, kind.type_name(), since, 50_000).await? else {
        return Err(MethodError("cannotCalculateChanges", "State too old; run the query again.".into()));
    };
    if more {
        return Err(MethodError("cannotCalculateChanges", "Too many changes; run the query again.".into()));
    }
    let mut removed: Vec<String> = vec![];
    for (id, _) in rows {
        let s = format!("{}{id}", kind.prefix());
        if !removed.contains(&s) {
            removed.push(s);
        }
    }
    let ids = run_query(ctx, kind, args).await?;
    let up_to = args.get("upToId").and_then(|v| v.as_str()).map(|s| ctx.id(s));
    let cutoff = up_to.and_then(|u| ids.iter().position(|i| *i == u)).unwrap_or(usize::MAX);
    let added: Vec<Value> = ids.iter().enumerate().filter(|(i, id)| *i <= cutoff && removed.contains(id)).map(|(i, id)| json!({"id": id, "index": i})).collect();
    let max = args.get("maxChanges").and_then(|v| v.as_u64()).unwrap_or(u64::MAX) as usize;
    if removed.len() + added.len() > max {
        return Err(MethodError("tooManyChanges", "More changes than maxChanges.".into()));
    }
    let mut out = json!({"accountId": account_id(&ctx.account), "oldQueryState": since_s, "newQueryState": state_str(ctx).await?, "removed": removed, "added": added});
    if args.get("calculateTotal").and_then(|v| v.as_bool()).unwrap_or(false) {
        out["total"] = json!(ids.len());
    }
    Ok(out)
}

/// Apply an RFC 8620 PatchObject ("a/b/c": value) to a JSON object.
fn apply_patch(base: &mut Map<String, Value>, patch: &Map<String, Value>) -> Result<(), String> {
    for (path, v) in patch {
        let parts: Vec<String> = path.split('/').map(|s| s.replace("~1", "/").replace("~0", "~")).collect();
        let mut cur = &mut *base;
        for (i, key) in parts.iter().enumerate() {
            if i + 1 == parts.len() {
                if v.is_null() {
                    cur.remove(key);
                } else {
                    cur.insert(key.clone(), v.clone());
                }
            } else {
                let next = cur.entry(key.clone()).or_insert_with(|| json!({}));
                if !next.is_object() {
                    *next = json!({});
                }
                cur = next.as_object_mut().ok_or("invalid patch path")?;
            }
        }
    }
    Ok(())
}

/// The collection named by calendarIds/addressBookIds (exactly one).
fn target_collection(kind: Kind, o: &Map<String, Value>, colls: &[Node], ctx: &Ctx) -> Option<Node> {
    let key = if kind == Kind::Event { "calendarIds" } else { "addressBookIds" };
    let prefix = if kind == Kind::Event { 'c' } else { 'b' };
    match o.get(key).and_then(|v| v.as_object()) {
        Some(m) => {
            let on: Vec<&String> = m.iter().filter(|(_, v)| v.as_bool().unwrap_or(false)).map(|(k, _)| k).collect();
            if on.len() != 1 {
                return None;
            }
            let id = num_id(&ctx.id(on[0]), prefix)?;
            colls.iter().find(|c| c.id == id).cloned()
        }
        None => colls.first().cloned(),
    }
}

async fn write_object(ctx: &Ctx, p: &Principal, kind: Kind, coll: &Node, existing: Option<&Node>, o: &Map<String, Value>) -> Result<Result<Node, Value>, MethodError> {
    let current = match existing {
        Some(n) => ical::parse(&store::read(&ctx.state, n).await?).ok(),
        None => None,
    };
    let comp = if kind == Kind::Event { jscal::apply_jscalendar(current.as_ref(), o) } else { jscal::apply_jscontact(current.as_ref(), o) };
    let comp = match comp {
        Ok(c) => c,
        Err(e) => return Ok(Err(set_error("invalidProperties", e))),
    };
    let text = ical::serialize(&comp);
    // A move to another collection: store there, then remove the old one.
    let name = existing.filter(|e| e.parent == coll.path).map(|e| e.name().to_string()).unwrap_or_else(|| {
        let uid = comp.comps.iter().find_map(|c| c.prop("UID")).or(comp.prop("UID")).map(|u| u.value.clone()).unwrap_or_default();
        let safe: String = uid.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@')).take(100).collect();
        format!("{}.{}", if safe.is_empty() { uuid::Uuid::new_v4().to_string() } else { safe }, if kind == Kind::Event { "ics" } else { "vcf" })
    });
    let path = format!("{}/{name}", coll.path);
    match store::put(&ctx.state, p, &path, text.as_bytes()).await? {
        Ok(n) => {
            if let Some(e) = existing.filter(|e| e.parent != coll.path) {
                store::delete(&ctx.state, p, &e.path).await?;
            }
            Ok(Ok(n))
        }
        Err(e) if e == "overQuota" => Ok(Err(set_error("overQuota", "Not enough storage"))),
        Err(e) => Ok(Err(set_error("invalidProperties", e))),
    }
}

async fn set(ctx: &mut Ctx, kind: Kind, args: &Value) -> R {
    let name = format!("{}/set", kind.type_name());
    let p = principal(ctx).await?;
    let old_state = state_str(ctx).await?;
    if let Some(s) = args.get("ifInState").and_then(|v| v.as_str()) {
        if s != old_state {
            return Err(MethodError("stateMismatch", "The state has changed.".into()));
        }
    }
    let (mut created, mut not_created) = (Map::new(), Map::new());
    let (mut updated, mut not_updated) = (Map::new(), Map::new());
    let (mut destroyed, mut not_destroyed) = (vec![], Map::new());
    let colls = collections(ctx, &p, kind).await?;
    if let Some(c) = args.get("create").and_then(|v| v.as_object()) {
        for (cid, obj) in c {
            let Some(o) = obj.as_object() else {
                not_created.insert(cid.clone(), set_error("invalidProperties", "not an object"));
                continue;
            };
            if kind.collection() {
                let label = o.get("name").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
                if label.is_empty() {
                    not_created.insert(cid.clone(), set_error("invalidProperties", "name is required"));
                    continue;
                }
                let mut props = Map::new();
                props.insert("displayname".into(), json!(label));
                if let Some(d) = o.get("description").and_then(|v| v.as_str()) {
                    props.insert("description".into(), json!(d));
                }
                if let Some(col) = o.get("color").and_then(|v| v.as_str()) {
                    props.insert("color".into(), json!(col));
                }
                if kind == Kind::Calendar {
                    props.insert("components".into(), json!("VEVENT,VTODO"));
                }
                let path = format!("{}/{}", kind.home(), uuid::Uuid::new_v4().simple());
                store::make_collection(&ctx.state, &p, &path, if kind == Kind::Calendar { "calendar" } else { "addressbook" }, &props).await?;
                let n = ctx.state.db.dav_node(p.id, &path).await?.ok_or_else(|| anyhow::anyhow!("collection vanished"))?;
                crate::dav::jmap_change(&ctx.state, p.id, &n, "c").await;
                let id = format!("{}{}", kind.prefix(), n.id);
                ctx.created.insert(cid.clone(), id.clone());
                created.insert(cid.clone(), json!({"id": id, "myRights": if kind == Kind::Calendar { rights_calendar() } else { json!({"mayRead": true, "mayWrite": true, "mayShare": false, "mayDelete": true}) }}));
                continue;
            }
            // Resolve "#creationId" references to collections made above.
            let mut o = o.clone();
            for key in ["calendarIds", "addressBookIds"] {
                if let Some(m) = o.get(key).and_then(|v| v.as_object()).cloned() {
                    o.insert(key.into(), Value::Object(m.into_iter().map(|(k, v)| (ctx.id(&k), v)).collect()));
                }
            }
            let colls = collections(ctx, &p, kind).await?;
            let Some(coll) = target_collection(kind, &o, &colls, ctx) else {
                not_created.insert(cid.clone(), set_error("invalidProperties", "Name exactly one calendar or address book"));
                continue;
            };
            match write_object(ctx, &p, kind, &coll, None, &o).await? {
                Ok(n) => {
                    let id = format!("{}{}", kind.prefix(), n.id);
                    ctx.created.insert(cid.clone(), id.clone());
                    let uid = object_json(ctx, kind, coll.id, &n).await.and_then(|j| j.get("uid").cloned()).unwrap_or(Value::Null);
                    created.insert(cid.clone(), json!({"id": id, "uid": uid, "blobId": format!("D{}", n.id)}));
                }
                Err(e) => {
                    not_created.insert(cid.clone(), e);
                }
            }
        }
    }
    if let Some(u) = args.get("update").and_then(|v| v.as_object()) {
        for (id, patch) in u {
            let id = ctx.id(id);
            let Some(patch) = patch.as_object() else {
                not_updated.insert(id, set_error("invalidPatch", "not an object"));
                continue;
            };
            let Some(n) = num_id(&id, kind.prefix()) else {
                not_updated.insert(id, set_error("notFound", "No such object"));
                continue;
            };
            if kind.collection() {
                let Some(c) = colls.iter().find(|c| c.id == n) else {
                    not_updated.insert(id, set_error("notFound", "No such collection"));
                    continue;
                };
                let mut props = c.props.clone();
                for (k, v) in patch {
                    let key = match k.as_str() {
                        "name" => "displayname",
                        "description" => "description",
                        "color" => "color",
                        "sortOrder" => "order",
                        _ => continue,
                    };
                    match v {
                        Value::Null => {
                            props.remove(key);
                        }
                        Value::Number(x) => {
                            props.insert(key.into(), json!(x.to_string()));
                        }
                        other => {
                            props.insert(key.into(), other.clone());
                        }
                    }
                }
                ctx.state.db.dav_set_props(c.id, &props).await?;
                crate::dav::jmap_change(&ctx.state, p.id, c, "u").await;
                updated.insert(id, Value::Null);
                continue;
            }
            let objs = objects(ctx, &p, kind).await?;
            let Some((c, node)) = objs.into_iter().find(|(_, x)| x.id == n) else {
                not_updated.insert(id, set_error("notFound", "No such object"));
                continue;
            };
            let Some(mut current) = object_json(ctx, kind, c, &node).await else {
                not_updated.insert(id, set_error("notFound", "Unreadable"));
                continue;
            };
            let mut patch = patch.clone();
            for key in ["calendarIds", "addressBookIds"] {
                if let Some(m) = patch.get(key).and_then(|v| v.as_object()).cloned() {
                    patch.insert(key.into(), Value::Object(m.into_iter().map(|(k, v)| (ctx.id(&k), v)).collect()));
                }
            }
            if let Err(e) = apply_patch(&mut current, &patch) {
                not_updated.insert(id, set_error("invalidPatch", e));
                continue;
            }
            let colls = collections(ctx, &p, kind).await?;
            let Some(coll) = target_collection(kind, &current, &colls, ctx) else {
                not_updated.insert(id, set_error("invalidProperties", "Name exactly one calendar or address book"));
                continue;
            };
            match write_object(ctx, &p, kind, &coll, Some(&node), &current).await? {
                Ok(n) if n.id != node.id => {
                    // Moved to another collection: a new resource there.
                    updated.insert(id, json!({"id": format!("{}{}", kind.prefix(), n.id)}));
                }
                Ok(_) => {
                    updated.insert(id, Value::Null);
                }
                Err(e) => {
                    not_updated.insert(id, e);
                }
            }
        }
    }
    if let Some(d) = args.get("destroy").and_then(|v| v.as_array()) {
        let remove_contents = args.get("onDestroyRemoveEvents").or(args.get("onDestroyRemoveContents")).and_then(|v| v.as_bool()).unwrap_or(false);
        for id in d.iter().filter_map(|v| v.as_str()).map(|s| ctx.id(s)) {
            let n = num_id(&id, kind.prefix()).unwrap_or(-1);
            let node = if kind.collection() {
                colls.iter().find(|c| c.id == n).cloned()
            } else {
                objects(ctx, &p, kind).await?.into_iter().find(|(_, x)| x.id == n).map(|x| x.1)
            };
            let Some(node) = node else {
                not_destroyed.insert(id, set_error("notFound", "No such object"));
                continue;
            };
            if kind.collection() && !remove_contents && !ctx.state.db.dav_children(p.id, &node.path).await?.is_empty() {
                not_destroyed.insert(id, set_error(if kind == Kind::Calendar { "calendarHasEvent" } else { "addressBookHasContents" }, "It isn't empty"));
                continue;
            }
            if store::delete(&ctx.state, &p, &node.path).await? {
                destroyed.push(id);
            } else {
                not_destroyed.insert(id, set_error("forbidden", "Can't be removed"));
            }
        }
    }
    Ok(vec![(
        name,
        json!({"accountId": account_id(&ctx.account), "oldState": old_state, "newState": state_str(ctx).await?,
            "created": created, "notCreated": not_created, "updated": updated, "notUpdated": not_updated,
            "destroyed": destroyed, "notDestroyed": not_destroyed}),
    )])
}

/// CalendarEvent/copy and ContactCard/copy: copies within this account
/// (the only account a sign-in reaches here).
async fn copy(ctx: &mut Ctx, kind: Kind, args: &Value) -> Result<Value, MethodError> {
    let from = args.get("fromAccountId").and_then(|v| v.as_str()).unwrap_or("");
    if from != account_id(&ctx.account) {
        return Err(MethodError("fromAccountNotFound", "Only this account can be copied from.".into()));
    }
    let p = principal(ctx).await?;
    let (mut created, mut not_created) = (Map::new(), Map::new());
    let objs = objects(ctx, &p, kind).await?;
    let colls = collections(ctx, &p, kind).await?;
    for (cid, obj) in args.get("create").and_then(|v| v.as_object()).into_iter().flatten() {
        let src = obj.get("id").and_then(|v| v.as_str()).map(|s| ctx.id(s)).unwrap_or_default();
        let Some((c, n)) = num_id(&src, kind.prefix()).and_then(|x| objs.iter().find(|(_, o)| o.id == x)) else {
            not_created.insert(cid.clone(), set_error("notFound", "No such object"));
            continue;
        };
        let Some(mut o) = object_json(ctx, kind, *c, n).await else { continue };
        if let Some(extra) = obj.as_object() {
            for (k, v) in extra.iter().filter(|(k, _)| *k != "id") {
                o.insert(k.clone(), v.clone());
            }
        }
        // A copy is a new object: a new UID.
        o.insert("uid".into(), json!(uuid::Uuid::new_v4().to_string()));
        let Some(coll) = target_collection(kind, &o, &colls, ctx) else {
            not_created.insert(cid.clone(), set_error("invalidProperties", "Name exactly one calendar or address book"));
            continue;
        };
        match write_object(ctx, &p, kind, &coll, None, &o).await? {
            Ok(n) => {
                let id = format!("{}{}", kind.prefix(), n.id);
                ctx.created.insert(cid.clone(), id.clone());
                created.insert(cid.clone(), json!({"id": id}));
            }
            Err(e) => {
                not_created.insert(cid.clone(), e);
            }
        }
    }
    let st = state_str(ctx).await?;
    Ok(json!({"fromAccountId": from, "accountId": account_id(&ctx.account), "oldState": st, "newState": st, "created": created, "notCreated": not_created}))
}

/// CalendarEvent/parse: iCalendar blobs (an invitation's attachment) as events.
async fn event_parse(ctx: &mut Ctx, args: &Value) -> Result<Value, MethodError> {
    let ids: Vec<String> = args.get("blobIds").and_then(|v| v.as_array()).into_iter().flatten().filter_map(|x| x.as_str().map(|s| ctx.id(s))).collect();
    let (mut parsed, mut not_parsable, mut not_found) = (Map::new(), vec![], vec![]);
    for id in ids {
        let Some(raw) = super::mail::blob_bytes(&ctx.state, &ctx.account, &id).await? else {
            not_found.push(id);
            continue;
        };
        let Ok(cal) = ical::parse(&String::from_utf8_lossy(&raw)) else {
            not_parsable.push(id);
            continue;
        };
        // One event per UID.
        let mut uids: Vec<String> = vec![];
        for c in cal.comps.iter().filter(|c| c.name == "VEVENT" || c.name == "VTODO") {
            if let Some(u) = c.prop("UID").map(|u| u.value.clone()) {
                if !uids.contains(&u) {
                    uids.push(u);
                }
            }
        }
        let events: Vec<Value> = uids
            .iter()
            .filter_map(|u| {
                let one = ical::Comp { comps: cal.comps.iter().filter(|c| c.prop("UID").map(|x| &x.value) == Some(u) || c.name == "VTIMEZONE").cloned().collect(), ..cal.clone() };
                jscal::to_jscalendar(&one).map(Value::Object)
            })
            .collect();
        if events.is_empty() {
            not_parsable.push(id);
        } else {
            parsed.insert(id, if events.len() == 1 { events.into_iter().next().unwrap() } else { Value::Array(events) });
        }
    }
    Ok(json!({"accountId": account_id(&ctx.account), "parsed": parsed, "notParsable": not_parsable, "notFound": not_found}))
}

// ------------------------------------------------------------------ principals

fn principal_json(a: &crate::db::Account) -> Value {
    json!({"id": format!("P{}", a.id), "type": "individual", "name": if a.display_name.is_empty() { a.email.clone() } else { a.display_name.clone() },
        "description": Value::Null, "email": a.email, "timeZone": Value::Null, "capabilities": {}, "accounts": {account_id(a): {}}})
}

async fn principal_get(ctx: &mut Ctx, args: &Value) -> Result<Value, MethodError> {
    let ids = ids_arg(ctx, args)?;
    let lookups = ctx.state.settings().dav.free_busy_lookup;
    let all: Vec<crate::db::Account> = if lookups {
        ctx.state.db.list_accounts().await?.into_iter().filter(|a| a.active).collect()
    } else {
        vec![ctx.account.clone()]
    };
    let (mut list, mut nf) = (vec![], vec![]);
    match ids {
        None => list = all.iter().map(principal_json).collect(),
        Some(ids) => {
            for id in ids {
                match num_id(&id, 'P').and_then(|n| all.iter().find(|a| a.id == n)) {
                    Some(a) => list.push(principal_json(a)),
                    None => nf.push(id),
                }
            }
        }
    }
    Ok(json!({"accountId": account_id(&ctx.account), "state": state_str(ctx).await?, "list": list, "notFound": nf}))
}

async fn principal_query(ctx: &mut Ctx, args: &Value) -> Result<Value, MethodError> {
    let f = args.get("filter").cloned().unwrap_or(Value::Null);
    let lookups = ctx.state.settings().dav.free_busy_lookup;
    let mut ids = vec![];
    for a in ctx.state.db.list_accounts().await?.into_iter().filter(|a| a.active) {
        if !lookups && a.id != ctx.account.id {
            continue;
        }
        if let Some(e) = f.get("email").and_then(|v| v.as_str()) {
            let owns = a.email.eq_ignore_ascii_case(e) || crate::submit::owns_address(&ctx.state, &a, &e.to_ascii_lowercase()).await;
            if !owns {
                continue;
            }
        }
        if let Some(t) = f.get("text").or(f.get("name")).and_then(|v| v.as_str()) {
            let t = t.to_lowercase();
            if !a.email.to_lowercase().contains(&t) && !a.display_name.to_lowercase().contains(&t) {
                continue;
            }
        }
        ids.push(format!("P{}", a.id));
    }
    let total = ids.len();
    let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(1000) as usize;
    let ids: Vec<String> = ids.into_iter().take(limit).collect();
    let mut out = json!({"accountId": account_id(&ctx.account), "queryState": state_str(ctx).await?, "canCalculateChanges": false, "position": 0, "ids": ids});
    if args.get("calculateTotal").and_then(|v| v.as_bool()).unwrap_or(false) {
        out["total"] = json!(total);
    }
    Ok(out)
}

/// Principal/set: only one's own name and description.
async fn principal_set(ctx: &mut Ctx, args: &Value) -> Result<Value, MethodError> {
    let st = state_str(ctx).await?;
    let (mut updated, mut not_updated) = (Map::new(), Map::new());
    for (id, patch) in args.get("update").and_then(|v| v.as_object()).into_iter().flatten() {
        if num_id(id, 'P') != Some(ctx.account.id) {
            not_updated.insert(id.clone(), set_error("forbidden", "Only your own entry can change"));
            continue;
        }
        let mut a = ctx.account.clone();
        if let Some(n) = patch.get("name").and_then(|v| v.as_str()) {
            a.display_name = n.chars().filter(|c| !c.is_control()).take(200).collect();
        }
        ctx.state.db.update_account(&a).await?;
        ctx.account = a;
        updated.insert(id.clone(), Value::Null);
    }
    let mut nc = Map::new();
    for (cid, _) in args.get("create").and_then(|v| v.as_object()).into_iter().flatten() {
        nc.insert(cid.clone(), set_error("forbidden", "Principals are made by the administrator"));
    }
    Ok(json!({"accountId": account_id(&ctx.account), "oldState": st, "newState": state_str(ctx).await?, "created": {}, "notCreated": nc,
        "updated": updated, "notUpdated": not_updated, "destroyed": [], "notDestroyed": {}}))
}

/// Principal/getAvailability: busy periods, as the scheduling outbox gives.
async fn availability(ctx: &mut Ctx, args: &Value) -> Result<Value, MethodError> {
    let id = args.get("id").and_then(|v| v.as_str()).unwrap_or("");
    let n = num_id(id, 'P').ok_or(MethodError("notFound", "No such principal".into()))?;
    if n != ctx.account.id && !ctx.state.settings().dav.free_busy_lookup {
        return Err(MethodError("forbidden", "Availability isn't shared here".into()));
    }
    let Some(a) = ctx.state.db.get_account(n).await?.filter(|a| a.active) else { return Err(MethodError("notFound", "No such principal".into())) };
    let parse = |k: &str| args.get(k).and_then(|v| v.as_str()).and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok()).map(|d| d.with_timezone(&chrono::Utc));
    let (Some(rs), Some(re)) = (parse("utcStart"), parse("utcEnd")) else { return Err(MethodError::invalid("utcStart and utcEnd are required")) };
    if re <= rs || re - rs > chrono::Duration::days(370) {
        return Err(MethodError::invalid("The range must be positive and at most a year"));
    }
    let Some(p) = store::principal(&ctx.state, &a).await? else { return Err(MethodError("notFound", "No calendars".into())) };
    let mut list = vec![];
    for cal in ctx.state.db.dav_children(p.id, "calendars").await?.into_iter().filter(|c| c.collection && c.is_calendar()) {
        if cal.prop_str("transp").is_some_and(|t| t.contains("transparent")) {
            continue;
        }
        for node in ctx.state.db.dav_children(p.id, &cal.path).await?.into_iter().filter(|x| !x.collection) {
            let Ok(text) = store::read(&ctx.state, &node).await else { continue };
            let Ok(obj) = ical::parse(&text) else { continue };
            for (s, e, kind) in ical::busy(&obj, rs, re) {
                let busy = match kind.as_str() {
                    "BUSY-TENTATIVE" => "tentative",
                    "BUSY-UNAVAILABLE" => "unavailable",
                    _ => "confirmed",
                };
                list.push(json!({"utcStart": s.format("%Y-%m-%dT%H:%M:%SZ").to_string(), "utcEnd": e.format("%Y-%m-%dT%H:%M:%SZ").to_string(), "busyStatus": busy, "event": Value::Null}));
            }
        }
    }
    list.sort_by(|a, b| a["utcStart"].as_str().cmp(&b["utcStart"].as_str()));
    Ok(json!({"accountId": account_id(&ctx.account), "list": list}))
}
