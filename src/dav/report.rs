//! REPORT: calendar-query, calendar-multiget, free-busy-query (RFC 4791),
//! addressbook-query, addressbook-multiget (RFC 6352), sync-collection
//! (RFC 6578), expand-property and the principal search reports (RFC 3744).
use super::props::{multistatus, response, Res, Want};
use super::*;
use crate::xml::Element;

pub async fn report(ctx: &Ctx, t: &Target, h: &HeaderMap, body: &[u8]) -> Result<Response> {
    let doc = match crate::xml::parse(body) {
        Ok(d) => d,
        Err(_) => return Ok(empty(StatusCode::BAD_REQUEST)),
    };
    // Most clients omit Depth on query reports and expect the members.
    let depth = header_str(h, "depth").unwrap_or("1").trim().to_ascii_lowercase();
    if let Some(r) = check_data_types(&doc) {
        return Ok(r);
    }
    match (doc.ns.as_str(), doc.name.as_str()) {
        (CALDAV, "calendar-query") => query(ctx, t, &doc, &depth, true).await,
        (CARDDAV, "addressbook-query") => query(ctx, t, &doc, &depth, false).await,
        (CALDAV, "calendar-multiget") | (CARDDAV, "addressbook-multiget") => multiget(ctx, &doc).await,
        (CALDAV, "free-busy-query") => free_busy(ctx, t, &doc).await,
        (DAV, "sync-collection") => sync(ctx, t, &doc).await,
        (DAV, "expand-property") => expand_property(ctx, t, &doc).await,
        (DAV, "principal-property-search") => principal_search(ctx, &doc).await,
        (DAV, "principal-search-property-set") => Ok(search_property_set()),
        (DAV, "principal-match") => principal_search(ctx, &doc).await,
        _ => Ok(precondition(StatusCode::FORBIDDEN, DAV, "supported-report")),
    }
}

fn want_of(doc: &Element) -> Want {
    if doc.child(DAV, "allprop").is_some() {
        return Want::All(vec![]);
    }
    if doc.child(DAV, "propname").is_some() {
        return Want::Names;
    }
    match doc.child(DAV, "prop") {
        Some(p) => Want::Props(p.elements().cloned().collect()),
        None => Want::All(vec![]),
    }
}

/// Resources a query runs over: the target resource itself (Depth 0 on a
/// resource) or the members of the target collection.
async fn members(ctx: &Ctx, t: &Target, depth: &str) -> Result<Option<(Node, Vec<Node>)>> {
    let Target::Node(_, path) = t else { return Ok(None) };
    let Some(n) = ctx.state.db.dav_node(ctx.principal.id, path).await? else { return Ok(None) };
    if !n.collection {
        return Ok(Some((n.clone(), vec![n])));
    }
    let kids = if depth == "0" {
        vec![]
    } else if n.is_home() {
        // A query on a home covers the objects in all its collections.
        let mut v = vec![];
        for c in ctx.state.db.dav_children(ctx.principal.id, &n.path).await?.into_iter().filter(|c| c.collection) {
            v.extend(ctx.state.db.dav_children(ctx.principal.id, &c.path).await?.into_iter().filter(|x| !x.collection));
        }
        v
    } else {
        ctx.state.db.dav_children(ctx.principal.id, &n.path).await?.into_iter().filter(|c| !c.collection).collect()
    };
    Ok(Some((n, kids)))
}

/// Parse a calendar object, applying the collection's time zone to floating times.
async fn load_object(ctx: &Ctx, n: &Node, query_tz: Option<&str>) -> Option<ical::Comp> {
    let data = read_blob(&ctx.state, n).await.ok()?;
    let mut obj = ical::parse(&String::from_utf8_lossy(&data)).ok()?;
    if obj.name == "VCALENDAR" {
        let tz = match query_tz {
            Some(t) => Some(t.to_string()),
            None => ctx.state.db.dav_node(ctx.principal.id, &n.parent).await.ok().flatten().and_then(|p| p.prop_str("timezone")).and_then(|t| ical::timezone_of(&t)),
        };
        if let Some(tz) = tz {
            ical::apply_floating(&mut obj, &tz);
        }
    }
    Some(obj)
}

fn valid_filter(f: &Element) -> bool {
    fn walk(e: &Element) -> bool {
        for c in e.elements() {
            if c.name == "time-range" && !ical::valid_time_range(c) {
                return false;
            }
            if c.name == "text-match" {
                if let Some(col) = c.attr("collation") {
                    if !matches!(col, "i;ascii-casemap" | "i;octet" | "i;unicode-casemap") {
                        return false;
                    }
                }
            }
            if !walk(c) {
                return false;
            }
        }
        true
    }
    walk(f)
}

async fn query(ctx: &Ctx, t: &Target, doc: &Element, depth: &str, calendar: bool) -> Result<Response> {
    let ns = if calendar { CALDAV } else { CARDDAV };
    let Some((coll, items)) = members(ctx, t, depth).await? else { return Ok(empty(StatusCode::NOT_FOUND)) };
    let home_ok = coll.kind == if calendar { "calendar-home" } else { "addressbook-home" };
    if coll.collection && !home_ok && ((calendar && !coll.is_calendar()) || (!calendar && !coll.is_addressbook())) {
        return Ok(precondition(StatusCode::FORBIDDEN, DAV, "supported-report"));
    }
    let filter = doc.child(ns, "filter");
    if calendar && filter.is_none() {
        return Ok(precondition(StatusCode::FORBIDDEN, CALDAV, "valid-filter"));
    }
    if let Some(f) = filter {
        if !valid_filter(f) || (calendar && !ical::valid_calendar_filter(f)) {
            return Ok(precondition(StatusCode::FORBIDDEN, ns, if calendar { "valid-filter" } else { "supported-filter" }));
        }
    }
    if let Some(tz) = doc.child(CALDAV, "timezone") {
        let ok = ical::parse(&tz.text()).is_ok_and(|c| c.name == "VCALENDAR" && c.comps.len() == 1 && c.comps[0].name == "VTIMEZONE");
        if !ok {
            return Ok(precondition(StatusCode::FORBIDDEN, CALDAV, "valid-calendar-data"));
        }
    }
    let limit: Option<usize> = doc.child(CARDDAV, "limit").and_then(|l| l.child(CARDDAV, "nresults")).and_then(|n| n.text().trim().parse().ok());
    let want = want_of(doc);
    let mut w = multistatus();
    let mut count = 0;
    let mut truncated = false;
    let query_tz = doc.child(CALDAV, "timezone").and_then(|t| ical::timezone_of(&t.text()));
    for n in items {
        let Some(obj) = load_object(ctx, &n, query_tz.as_deref()).await else { continue };
        let ok = match filter {
            None => true,
            Some(f) if calendar => ical::calendar_filter(f, &obj),
            Some(f) => ical::card_filter(f, &obj),
        };
        if !ok {
            continue;
        }
        if limit.is_some_and(|l| count >= l) {
            truncated = true;
            break;
        }
        count += 1;
        response(ctx, &Res::Node(n), &want, &mut w).await;
    }
    if truncated {
        w.open(DAV, "response");
        w.text_el(DAV, "href", &href_node(&ctx.principal.username, &coll.path, true));
        w.text_el(DAV, "status", &status_line(StatusCode::INSUFFICIENT_STORAGE));
        w.open(DAV, "error");
        w.empty(DAV, "number-of-matches-within-limits");
        w.close(DAV, "error");
        w.close(DAV, "response");
    }
    w.close(DAV, "multistatus");
    Ok(xml_response(StatusCode::MULTI_STATUS, w.finish()))
}

async fn multiget(ctx: &Ctx, doc: &Element) -> Result<Response> {
    let want = want_of(doc);
    let mut w = multistatus();
    for href in doc.children_named(DAV, "href") {
        let h = href.text();
        let found = match target(h.trim()) {
            Some(Target::Node(u, p)) if u == ctx.principal.username => ctx.state.db.dav_node(ctx.principal.id, &p).await?,
            _ => None,
        };
        match found {
            Some(n) if !n.collection => response(ctx, &Res::Node(n), &want, &mut w).await,
            _ => {
                w.open(DAV, "response");
                w.text_el(DAV, "href", h.trim());
                w.text_el(DAV, "status", &status_line(StatusCode::NOT_FOUND));
                w.close(DAV, "response");
            }
        }
    }
    w.close(DAV, "multistatus");
    Ok(xml_response(StatusCode::MULTI_STATUS, w.finish()))
}

async fn free_busy(ctx: &Ctx, t: &Target, doc: &Element) -> Result<Response> {
    let Some(tr) = doc.child(CALDAV, "time-range").filter(|t| ical::valid_time_range(t)) else {
        return Ok(empty(StatusCode::BAD_REQUEST));
    };
    let rs = tr.attr("start").and_then(ical::parse_utc).unwrap_or(chrono::DateTime::<chrono::Utc>::MIN_UTC);
    let re = tr.attr("end").and_then(ical::parse_utc).unwrap_or(chrono::DateTime::<chrono::Utc>::MAX_UTC);
    let Some((coll, items)) = members(ctx, t, "1").await? else { return Ok(empty(StatusCode::NOT_FOUND)) };
    if coll.collection && !coll.is_calendar() && coll.kind != "calendar-home" {
        return Ok(empty(StatusCode::FORBIDDEN));
    }
    let mut periods = vec![];
    for n in items {
        if let Some(c) = load_object(ctx, &n, None).await {
            periods.extend(ical::busy(&c, rs, re));
        }
    }
    // Merge across resources too.
    let all = ical::Comp { name: "VCALENDAR".into(), comps: vec![ical::Comp {
        name: "VFREEBUSY".into(),
        props: periods.iter().map(|(a, b, k)| ical::Prop { name: "FREEBUSY".into(), params: vec![("FBTYPE".into(), k.clone())], value: format!("{}/{}", ical::fmt_utc(*a), ical::fmt_utc(*b)) }).collect(),
        comps: vec![],
    }], props: vec![] };
    let periods = ical::busy(&all, rs, re);
    let mut fb = ical::Comp { name: "VFREEBUSY".into(), ..Default::default() };
    fb.props.push(ical::Prop { name: "DTSTAMP".into(), params: vec![], value: ical::fmt_utc(chrono::Utc::now()) });
    fb.props.push(ical::Prop { name: "DTSTART".into(), params: vec![], value: ical::fmt_utc(rs) });
    fb.props.push(ical::Prop { name: "DTEND".into(), params: vec![], value: ical::fmt_utc(re) });
    for (a, b, kind) in periods {
        let params = if kind == "BUSY" { vec![] } else { vec![("FBTYPE".to_string(), kind)] };
        fb.props.push(ical::Prop { name: "FREEBUSY".into(), params, value: format!("{}/{}", ical::fmt_utc(a), ical::fmt_utc(b)) });
    }
    let cal = ical::Comp {
        name: "VCALENDAR".into(),
        props: vec![ical::Prop { name: "VERSION".into(), params: vec![], value: "2.0".into() }, ical::Prop { name: "PRODID".into(), params: vec![], value: "-//Picacho Server//DAV//EN".into() }],
        comps: vec![fb],
    };
    Ok(([(header::CONTENT_TYPE, "text/calendar; charset=utf-8")], ical::serialize(&cal)).into_response())
}

fn token_number(tok: &str, coll: i64) -> Option<i64> {
    let rest = tok.trim().strip_prefix("http://picacho.mail/ns/sync/")?;
    let (c, n) = rest.split_once('-')?;
    if c.parse::<i64>().ok()? != coll {
        return None;
    }
    n.parse().ok()
}

async fn sync(ctx: &Ctx, t: &Target, doc: &Element) -> Result<Response> {
    let Target::Node(user, path) = t else { return Ok(precondition(StatusCode::FORBIDDEN, DAV, "supported-report")) };
    let Some(coll) = ctx.state.db.dav_node(ctx.principal.id, path).await? else { return Ok(empty(StatusCode::NOT_FOUND)) };
    if !coll.collection {
        return Ok(precondition(StatusCode::FORBIDDEN, DAV, "supported-report"));
    }
    let level = doc.child(DAV, "sync-level").map(|l| l.text().trim().to_string()).unwrap_or_else(|| "1".into());
    if level != "1" {
        return Ok(precondition(StatusCode::FORBIDDEN, DAV, "supported-report"));
    }
    let tok = doc.child(DAV, "sync-token").map(|t| t.text()).unwrap_or_default();
    let since = if tok.trim().is_empty() {
        None
    } else {
        match token_number(&tok, coll.id) {
            Some(n) => Some(n),
            None => return Ok(precondition(StatusCode::FORBIDDEN, DAV, "valid-sync-token")),
        }
    };
    let current = ctx.state.db.dav_sync_token(coll.id).await?;
    if since.is_some_and(|s| s > current) {
        return Ok(precondition(StatusCode::FORBIDDEN, DAV, "valid-sync-token"));
    }
    let want = want_of(doc);
    let limit: Option<usize> = doc.child(DAV, "limit").and_then(|l| l.child(DAV, "nresults")).and_then(|n| n.text().trim().parse().ok());
    let mut w = multistatus();
    let mut n = 0usize;
    match since {
        None => {
            for c in ctx.state.db.dav_children(ctx.principal.id, &coll.path).await? {
                if limit.is_some_and(|l| n >= l) {
                    break;
                }
                n += 1;
                response(ctx, &Res::Node(c), &want, &mut w).await;
            }
        }
        Some(s) => {
            for (name, deleted) in ctx.state.db.dav_changes_since(coll.id, s).await? {
                if name.is_empty() {
                    continue; // property change on the collection itself
                }
                let child_path = format!("{}/{name}", coll.path);
                let node = if deleted { None } else { ctx.state.db.dav_node(ctx.principal.id, &child_path).await? };
                if limit.is_some_and(|l| n >= l) {
                    break;
                }
                n += 1;
                match node {
                    Some(c) => response(ctx, &Res::Node(c), &want, &mut w).await,
                    None => {
                        w.open(DAV, "response");
                        w.text_el(DAV, "href", &href_node(user, &child_path, false));
                        w.text_el(DAV, "status", &status_line(StatusCode::NOT_FOUND));
                        w.close(DAV, "response");
                    }
                }
            }
        }
    }
    w.text_el(DAV, "sync-token", &format!("http://picacho.mail/ns/sync/{}-{current}", coll.id));
    w.close(DAV, "multistatus");
    Ok(xml_response(StatusCode::MULTI_STATUS, w.finish()))
}

async fn expand_property(ctx: &Ctx, t: &Target, doc: &Element) -> Result<Response> {
    let Some(res) = props::resolve(ctx, t).await? else { return Ok(empty(StatusCode::NOT_FOUND)) };
    let wanted: Vec<Element> = doc
        .children_named(DAV, "property")
        .map(|p| Element { ns: p.attr("namespace").unwrap_or(DAV).to_string(), name: p.attr("name").unwrap_or("").to_string(), ..Default::default() })
        .collect();
    let mut w = multistatus();
    response(ctx, &res, &Want::Props(wanted), &mut w).await;
    w.close(DAV, "multistatus");
    Ok(xml_response(StatusCode::MULTI_STATUS, w.finish()))
}

async fn principal_search(ctx: &Ctx, doc: &Element) -> Result<Response> {
    let me = ctx.principal.clone();
    let needles: Vec<String> = doc.children_named(DAV, "property-search").map(|s| s.child(DAV, "match").map(|m| m.text().to_lowercase()).unwrap_or_default()).collect();
    let hay = format!("{} {} {}", me.username, me.display_name, me.email).to_lowercase();
    let hit = needles.is_empty() || needles.iter().any(|n| hay.contains(n.trim_start_matches("mailto:")));
    let mut w = multistatus();
    if hit {
        response(ctx, &Res::Principal(me), &want_of(doc), &mut w).await;
    }
    w.close(DAV, "multistatus");
    Ok(xml_response(StatusCode::MULTI_STATUS, w.finish()))
}

fn search_property_set() -> Response {
    let mut w = crate::xml::Writer::new().prefix("D", DAV).prefix("C", CALDAV).prefix("CS", CS);
    w.open(DAV, "principal-search-property-set");
    for (ns, n, d) in [(DAV, "displayname", "Display name"), (CALDAV, "calendar-user-address-set", "Calendar address"), (CS, "email-address-set", "Email address")] {
        w.open(DAV, "principal-search-property");
        w.open(DAV, "prop");
        w.empty(ns, n);
        w.close(DAV, "prop");
        w.text_el(DAV, "description", d);
        w.close(DAV, "principal-search-property");
    }
    w.close(DAV, "principal-search-property-set");
    xml_response(StatusCode::OK, w.finish())
}

/// calendar-data / address-data must ask for a type we produce.
fn check_data_types(doc: &Element) -> Option<Response> {
    let prop = doc.child(DAV, "prop")?;
    if let Some(cd) = prop.child(CALDAV, "calendar-data") {
        let ct = cd.attr("content-type").unwrap_or("text/calendar");
        let v = cd.attr("version").unwrap_or("2.0");
        if ct != "text/calendar" || v != "2.0" {
            return Some(precondition(StatusCode::FORBIDDEN, CALDAV, "supported-calendar-data"));
        }
    }
    if let Some(ad) = prop.child(CARDDAV, "address-data") {
        let ct = ad.attr("content-type").unwrap_or("text/vcard");
        let v = ad.attr("version").unwrap_or("3.0");
        if ct != "text/vcard" || !(v == "3.0" || v == "4.0") {
            return Some(precondition(StatusCode::FORBIDDEN, CARDDAV, "supported-address-data"));
        }
    }
    None
}
