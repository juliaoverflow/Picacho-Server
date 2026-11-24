//! PROPFIND and PROPPATCH: live properties for principals, collections,
//! calendars, address books and resources, plus dead properties stored
//! verbatim.
use super::*;
use crate::xml::{Element, Writer};

/// A resource as PROPFIND sees it.
pub enum Res {
    Root,
    Principals,
    Principal(Principal),
    SectionRoot(String),
    Node(Node),
}

impl Res {
    pub fn href(&self, user: &str) -> String {
        match self {
            Res::Root => "/dav/".into(),
            Res::Principals => "/dav/principals/".into(),
            Res::Principal(p) => href_principal(&p.username),
            Res::SectionRoot(s) => format!("/dav/{s}/"),
            Res::Node(n) => href_node(user, &n.path, n.collection),
        }
    }
    fn is_collection(&self) -> bool {
        !matches!(self, Res::Node(n) if !n.collection)
    }
}

/// Live properties returned for <allprop/> (RFC 4918 says computed and
/// expensive ones are only returned on request).
const ALLPROP: &[(&str, &str)] = &[
    (DAV, "resourcetype"),
    (DAV, "displayname"),
    (DAV, "getetag"),
    (DAV, "getcontentlength"),
    (DAV, "getcontenttype"),
    (DAV, "getlastmodified"),
    (DAV, "creationdate"),
    (DAV, "supportedlock"),
    (DAV, "lockdiscovery"),
];

/// Live properties we can name in <propname/> responses.
const LIVE: &[(&str, &str)] = &[
    (DAV, "resourcetype"),
    (DAV, "displayname"),
    (DAV, "getetag"),
    (DAV, "getcontentlength"),
    (DAV, "getcontenttype"),
    (DAV, "getlastmodified"),
    (DAV, "creationdate"),
    (DAV, "supportedlock"),
    (DAV, "lockdiscovery"),
    (DAV, "current-user-principal"),
    (DAV, "current-user-privilege-set"),
    (DAV, "owner"),
    (DAV, "supported-report-set"),
    (DAV, "sync-token"),
    (DAV, "quota-available-bytes"),
    (DAV, "quota-used-bytes"),
    (CS, "getctag"),
];

fn writable(ns: &str, name: &str) -> Option<&'static str> {
    match (ns, name) {
        (DAV, "displayname") => Some("displayname"),
        (CALDAV, "calendar-description") => Some("description"),
        (CARDDAV, "addressbook-description") => Some("description"),
        (CALDAV, "calendar-timezone") => Some("timezone"),
        (APPLE, "calendar-color") => Some("color"),
        (APPLE, "calendar-order") => Some("order"),
        (CALDAV, "schedule-calendar-transp") => Some("transp"),
        _ => None,
    }
}

fn protected(ns: &str, name: &str) -> bool {
    LIVE.iter().any(|(n, x)| *n == ns && *x == name && name != "displayname")
        || matches!((ns, name), (CALDAV, "supported-calendar-component-set") | (CALDAV, "supported-calendar-data") | (CALDAV, "max-resource-size") | (CARDDAV, "supported-address-data") | (CARDDAV, "max-resource-size") | (CALDAV, "calendar-home-set") | (CARDDAV, "addressbook-home-set") | (DAV, "principal-URL") | (CALDAV, "schedule-outbox-URL") | (CALDAV, "schedule-inbox-URL") | (CALDAV, "max-attachment-size") | (CALDAV, "max-attachments-per-resource"))
}

fn dead_key(ns: &str, name: &str) -> String {
    format!("{{{ns}}}{name}")
}

/// Apply <set> properties (MKCOL/MKCALENDAR/PROPPATCH). Returns the names
/// that can't be set; when non-empty nothing should be stored.
pub fn apply_set(kind: &str, props: &mut Map<String, Value>, set: &[Element]) -> Vec<(String, String)> {
    let mut failed = vec![];
    for e in set {
        if e.is(CALDAV, "supported-calendar-component-set") && kind == "calendar" {
            let comps: Vec<String> = e.children_named(CALDAV, "comp").filter_map(|c| c.attr("name").map(|n| n.to_ascii_uppercase())).collect();
            if comps.is_empty() {
                failed.push((e.ns.clone(), e.name.clone()));
            } else {
                props.insert("components".into(), json!(comps.join(",")));
            }
            continue;
        }
        if e.is(CALDAV, "calendar-timezone") {
            let t = e.text();
            if !t.trim().is_empty() && ical::parse(&t).map(|c| !(c.name == "VCALENDAR" && c.comps.len() == 1 && c.comps[0].name == "VTIMEZONE")).unwrap_or(true) {
                failed.push((e.ns.clone(), e.name.clone()));
                continue;
            }
        }
        if let Some(k) = writable(&e.ns, &e.name) {
            props.insert(k.into(), json!(e.text()));
        } else if protected(&e.ns, &e.name) {
            failed.push((e.ns.clone(), e.name.clone()));
        } else {
            props.insert(dead_key(&e.ns, &e.name), json!(e.to_fragment()));
        }
    }
    failed
}

fn http_date(t: i64) -> String {
    chrono::DateTime::from_timestamp(t, 0).map(|d| d.format("%a, %d %b %Y %H:%M:%S GMT").to_string()).unwrap_or_default()
}

fn iso_date(t: i64) -> String {
    chrono::DateTime::from_timestamp(t, 0).map(|d| d.format("%Y-%m-%dT%H:%M:%SZ").to_string()).unwrap_or_default()
}

/// Write one property's value into `w`. Returns false when the resource
/// doesn't have it.
pub async fn write_prop(ctx: &Ctx, res: &Res, ns: &str, name: &str, w: &mut Writer, req: Option<&Element>) -> bool {
    let user = ctx.principal.username.clone();
    let st = &ctx.state;
    let node = match res {
        Res::Node(n) => Some(n),
        _ => None,
    };
    match (ns, name) {
        (DAV, "resourcetype") => {
            w.open(DAV, "resourcetype");
            if res.is_collection() {
                w.empty(DAV, "collection");
            }
            match res {
                Res::Principal(_) => w.empty(DAV, "principal"),
                Res::Node(n) if n.is_calendar() => w.empty(CALDAV, "calendar"),
                Res::Node(n) if n.kind == "schedule-inbox" => w.empty(CALDAV, "schedule-inbox"),
                Res::Node(n) if n.is_addressbook() => w.empty(CARDDAV, "addressbook"),
                _ => {}
            }
            w.close(DAV, "resourcetype");
        }
        (DAV, "displayname") => {
            let v = match res {
                Res::Principal(p) => if p.display_name.is_empty() { p.username.clone() } else { p.display_name.clone() },
                Res::Node(n) => match n.prop_str("displayname") {
                    Some(d) => d,
                    None if n.collection && !n.is_home() => n.name().to_string(),
                    None => return false,
                },
                _ => return false,
            };
            w.text_el(DAV, "displayname", &v);
        }
        (DAV, "getetag") => match node {
            Some(n) if !n.collection => w.text_el(DAV, "getetag", &n.etag),
            _ => return false,
        },
        (DAV, "getcontentlength") => match node {
            Some(n) => w.text_el(DAV, "getcontentlength", &if n.collection { 0 } else { n.size }.to_string()),
            _ => return false,
        },
        (DAV, "getcontenttype") => match node {
            Some(n) if !n.collection => w.text_el(DAV, "getcontenttype", if n.ctype.is_empty() { "application/octet-stream" } else { &n.ctype }),
            Some(n) if n.collection => w.text_el(DAV, "getcontenttype", "httpd/unix-directory"),
            _ => return false,
        },
        (DAV, "getlastmodified") => match node {
            Some(n) => w.text_el(DAV, "getlastmodified", &http_date(n.updated_at)),
            None => return false,
        },
        (DAV, "creationdate") => match node {
            Some(n) => w.text_el(DAV, "creationdate", &iso_date(n.created_at)),
            None => return false,
        },
        (DAV, "supportedlock") if node.is_some_and(directory::is_virtual) => w.empty(DAV, "supportedlock"),
        (DAV, "supportedlock") => {
            w.open(DAV, "supportedlock");
            for scope in ["exclusive", "shared"] {
                w.open(DAV, "lockentry");
                w.open(DAV, "lockscope");
                w.empty(DAV, scope);
                w.close(DAV, "lockscope");
                w.open(DAV, "locktype");
                w.empty(DAV, "write");
                w.close(DAV, "locktype");
                w.close(DAV, "lockentry");
            }
            w.close(DAV, "supportedlock");
        }
        (DAV, "lockdiscovery") => {
            let path = match node {
                Some(n) => n.path.clone(),
                None => String::new(),
            };
            w.open(DAV, "lockdiscovery");
            if !path.is_empty() {
                for l in locks::active_for(st, ctx.principal.id, &path).await {
                    locks::write_activelock(w, &l, &user);
                }
            }
            w.close(DAV, "lockdiscovery");
        }
        (DAV, "current-user-principal") => {
            w.open(DAV, "current-user-principal");
            w.text_el(DAV, "href", &href_principal(&user));
            w.close(DAV, "current-user-principal");
        }
        (DAV, "principal-URL") => match res {
            Res::Principal(p) => {
                w.open(DAV, "principal-URL");
                w.text_el(DAV, "href", &href_principal(&p.username));
                w.close(DAV, "principal-URL");
            }
            _ => return false,
        },
        (DAV, "owner") => {
            w.open(DAV, "owner");
            w.text_el(DAV, "href", &href_principal(&user));
            w.close(DAV, "owner");
        }
        (DAV, "principal-collection-set") => {
            w.open(DAV, "principal-collection-set");
            w.text_el(DAV, "href", "/dav/principals/");
            w.close(DAV, "principal-collection-set");
        }
        (DAV, "current-user-privilege-set") => {
            w.open(DAV, "current-user-privilege-set");
            let privs: &[&str] = if ctx.read_only || node.is_some_and(directory::is_virtual) {
                &["read", "read-current-user-privilege-set"]
            } else {
                &["all", "read", "write", "write-properties", "write-content", "bind", "unbind", "unlock", "read-acl", "read-current-user-privilege-set"]
            };
            for p in privs {
                w.open(DAV, "privilege");
                w.empty(DAV, p);
                w.close(DAV, "privilege");
            }
            if !ctx.read_only && node.is_some_and(|n| n.is_calendar()) {
                w.open(DAV, "privilege");
                w.empty(CALDAV, "read-free-busy");
                w.close(DAV, "privilege");
            }
            w.close(DAV, "current-user-privilege-set");
        }
        (DAV, "acl") => {
            w.open(DAV, "acl");
            w.open(DAV, "ace");
            w.open(DAV, "principal");
            w.text_el(DAV, "href", &href_principal(&user));
            w.close(DAV, "principal");
            w.open(DAV, "grant");
            w.open(DAV, "privilege");
            w.empty(DAV, "all");
            w.close(DAV, "privilege");
            w.close(DAV, "grant");
            w.empty(DAV, "protected");
            w.close(DAV, "ace");
            w.close(DAV, "acl");
        }
        (DAV, "supported-report-set") => {
            let reports: Vec<(&str, &str)> = match res {
                Res::Node(n) if n.kind == "schedule-inbox" => vec![(CALDAV, "calendar-query"), (CALDAV, "calendar-multiget"), (DAV, "sync-collection")],
                Res::Node(n) if n.is_calendar() => vec![(CALDAV, "calendar-query"), (CALDAV, "calendar-multiget"), (CALDAV, "free-busy-query"), (DAV, "sync-collection"), (DAV, "expand-property")],
                Res::Node(n) if n.is_addressbook() => vec![(CARDDAV, "addressbook-query"), (CARDDAV, "addressbook-multiget"), (DAV, "sync-collection"), (DAV, "expand-property")],
                Res::Node(n) if n.collection => vec![(DAV, "sync-collection"), (DAV, "expand-property")],
                Res::Principal(_) | Res::Principals => vec![(DAV, "principal-property-search"), (DAV, "principal-search-property-set"), (DAV, "expand-property")],
                _ => vec![(DAV, "expand-property")],
            };
            w.open(DAV, "supported-report-set");
            for (rns, r) in reports {
                w.open(DAV, "supported-report");
                w.open(DAV, "report");
                w.empty(rns, r);
                w.close(DAV, "report");
                w.close(DAV, "supported-report");
            }
            w.close(DAV, "supported-report-set");
        }
        (DAV, "sync-token") | (CS, "getctag") => match node {
            Some(n) if n.collection && directory::is_virtual(n) => {
                let t = directory::token(n);
                w.text_el(ns, name, &if name == "sync-token" { t } else { format!("\"{}\"", t.rsplit('/').next().unwrap_or("")) });
            }
            Some(n) if n.collection => {
                let t = st.db.dav_sync_token(n.id).await.unwrap_or(0);
                let v = if name == "sync-token" { format!("http://picacho.mail/ns/sync/{}-{t}", n.id) } else { format!("\"{}-{t}\"", n.id) };
                w.text_el(ns, name, &v);
            }
            _ => return false,
        },
        (DAV, "quota-available-bytes") | (DAV, "quota-used-bytes") => match node {
            Some(n) if n.collection && !directory::is_virtual(n) => {
                let p = st.db.dav_principal_by_id(ctx.principal.id).await.ok().flatten().unwrap_or_else(|| ctx.principal.clone());
                if name == "quota-used-bytes" {
                    w.text_el(DAV, name, &p.used_bytes.to_string());
                } else if p.quota_bytes > 0 {
                    w.text_el(DAV, name, &(p.quota_bytes - p.used_bytes).max(0).to_string());
                } else {
                    return false;
                }
            }
            _ => return false,
        },
        (DAV, "group-membership") | (DAV, "group-member-set") | (DAV, "alternate-URI-set") => match res {
            Res::Principal(p) => {
                w.open(DAV, name);
                if name == "alternate-URI-set" && !p.email.is_empty() {
                    w.text_el(DAV, "href", &format!("mailto:{}", p.email));
                }
                w.close(DAV, name);
            }
            _ => return false,
        },
        (CALDAV, "calendar-home-set") | (CARDDAV, "addressbook-home-set") => match res {
            Res::Principal(p) => {
                w.open(ns, name);
                let sec = if ns == CALDAV { "calendars" } else { "addressbooks" };
                w.text_el(DAV, "href", &format!("/dav/{sec}/{}/", pct_encode(&p.username)));
                w.close(ns, name);
            }
            _ => return false,
        },
        (CALDAV, "calendar-user-address-set") | (CS, "email-address-set") => match res {
            Res::Principal(p) => {
                w.open(ns, name);
                let email = if p.email.is_empty() { p.username.clone() } else { p.email.clone() };
                if ns == CS {
                    w.text_el(CS, "email-address", &email);
                } else {
                    w.text_el(DAV, "href", &format!("mailto:{email}"));
                    w.text_el(DAV, "href", &href_principal(&p.username));
                }
                w.close(ns, name);
            }
            _ => return false,
        },
        // RFC 6638: where free/busy requests are POSTed (see schedule.rs).
        (CALDAV, "schedule-outbox-URL") => match res {
            Res::Principal(p) => {
                w.open(ns, name);
                w.text_el(DAV, "href", &format!("/dav/calendars/{}/outbox/", pct_encode(&p.username)));
                w.close(ns, name);
            }
            _ => return false,
        },
        // RFC 6638 2.2: where the server delivers scheduling messages.
        (CALDAV, "schedule-inbox-URL") => match res {
            Res::Principal(p) if itip::on(st) => {
                w.open(ns, name);
                w.text_el(DAV, "href", &format!("/dav/calendars/{}/inbox/", pct_encode(&p.username)));
                w.close(ns, name);
            }
            _ => return false,
        },
        // RFC 6638 9.2: the calendar invitations go into.
        (CALDAV, "schedule-default-calendar-URL") => match node {
            Some(n) if n.kind == "schedule-inbox" => {
                let Ok(Some(c)) = itip::default_calendar(st, ctx.principal.id).await else { return false };
                w.open(ns, name);
                w.text_el(DAV, "href", &href_node(&user, &c.path, true));
                w.close(ns, name);
            }
            _ => return false,
        },
        (CALDAV, "calendar-user-type") => match res {
            Res::Principal(_) => w.text_el(CALDAV, name, "INDIVIDUAL"),
            _ => return false,
        },
        (CARDDAV, "principal-address") => return false,
        (CALDAV, "calendar-description") | (CARDDAV, "addressbook-description") => match node {
            Some(n) if (n.is_calendar() && ns == CALDAV) || (n.is_addressbook() && ns == CARDDAV) => match n.prop_str("description") {
                Some(d) => w.text_el(ns, name, &d),
                None => return false,
            },
            _ => return false,
        },
        (CALDAV, "calendar-timezone") => match node.and_then(|n| n.prop_str("timezone")) {
            Some(t) if !t.is_empty() => w.text_el(CALDAV, name, &t),
            _ => return false,
        },
        (APPLE, "calendar-color") | (APPLE, "calendar-order") => match node.and_then(|n| n.prop_str(if name == "calendar-color" { "color" } else { "order" })) {
            Some(v) => w.text_el(APPLE, name, &v),
            None => return false,
        },
        (CALDAV, "schedule-calendar-transp") => match node {
            Some(n) if n.is_calendar() => {
                w.open(CALDAV, name);
                w.empty(CALDAV, if n.prop_str("transp").is_some_and(|t| t.contains("transparent")) { "transparent" } else { "opaque" });
                w.close(CALDAV, name);
            }
            _ => return false,
        },
        (CALDAV, "supported-calendar-component-set") => match node {
            Some(n) if n.is_calendar() => {
                w.open(CALDAV, name);
                for c in n.prop_str("components").unwrap_or_else(|| "VEVENT,VTODO,VJOURNAL".into()).split(',').filter(|s| !s.is_empty()) {
                    w.open_attrs(CALDAV, "comp", &[("name", c)]);
                    w.close(CALDAV, "comp");
                }
                w.close(CALDAV, name);
            }
            _ => return false,
        },
        (CALDAV, "supported-calendar-data") => match node {
            Some(n) if n.is_calendar() => {
                w.open(CALDAV, name);
                w.open_attrs(CALDAV, "calendar-data", &[("content-type", "text/calendar"), ("version", "2.0")]);
                w.close(CALDAV, "calendar-data");
                w.close(CALDAV, name);
            }
            _ => return false,
        },
        (CARDDAV, "supported-address-data") => match node {
            Some(n) if n.is_addressbook() => {
                w.open(CARDDAV, name);
                for v in ["3.0", "4.0"] {
                    w.open_attrs(CARDDAV, "address-data-type", &[("content-type", "text/vcard"), ("version", v)]);
                    w.close(CARDDAV, "address-data-type");
                }
                w.close(CARDDAV, name);
            }
            _ => return false,
        },
        // RFC 8607 6: managed attachment limits, on calendars and the home.
        (CALDAV, "max-attachment-size") | (CALDAV, "max-attachments-per-resource") => match node {
            Some(n) if n.is_calendar() || n.kind == "calendar-home" => {
                let v = if name == "max-attachment-size" { attach::max_size(st) } else { attach::MAX_PER_RESOURCE as u64 };
                w.text_el(CALDAV, name, &v.to_string());
            }
            _ => return false,
        },
        (CALDAV, "max-attendees-per-instance") => match node {
            Some(n) if n.is_calendar() => w.text_el(CALDAV, name, &ical::MAX_ATTENDEES.to_string()),
            _ => return false,
        },
        (CALDAV, "max-resource-size") | (CARDDAV, "max-resource-size") => match node {
            Some(n) if n.is_calendar() || n.is_addressbook() => w.text_el(ns, name, &st.settings().dav.max_resource_bytes.to_string()),
            _ => return false,
        },
        (CALDAV, "calendar-data") | (CARDDAV, "address-data") => match node {
            Some(n) if !n.collection && (n.comp == "VCARD") == (ns == CARDDAV) && !n.comp.is_empty() => {
                let Ok(data) = read_blob(st, n).await else { return false };
                let text = String::from_utf8_lossy(&data).to_string();
                let out = match req.filter(|r| r.elements().next().is_some()) {
                    Some(r) => match ical::parse(&text) {
                        Ok(c) => ical::serialize(&ical::select(r, &c)),
                        Err(_) => text,
                    },
                    None => text,
                };
                w.text_el(ns, name, &out);
            }
            _ => return false,
        },
        _ => {
            // Dead property?
            let Some(n) = node else { return false };
            let Some(x) = n.props.get(&dead_key(ns, name)).and_then(|v| v.as_str()) else { return false };
            match crate::xml::parse(x.as_bytes()) {
                Ok(e) => w.element(&e),
                Err(_) => return false,
            }
        }
    }
    true
}

/// Which properties a PROPFIND asked for.
pub enum Want {
    All(Vec<(String, String)>),
    Names,
    Props(Vec<Element>),
}

fn dead_names(res: &Res) -> Vec<(String, String)> {
    match res {
        Res::Node(n) => n
            .props
            .keys()
            .filter_map(|k| {
                let k = k.strip_prefix('{')?;
                let (ns, name) = k.split_once('}')?;
                Some((ns.to_string(), name.to_string()))
            })
            .collect(),
        _ => vec![],
    }
}

/// One <D:response> for a resource.
pub async fn response(ctx: &Ctx, res: &Res, want: &Want, w: &mut Writer) {
    let user = ctx.principal.username.clone();
    w.open(DAV, "response");
    w.text_el(DAV, "href", &res.href(&user));
    let mut found = Writer::new();
    let mut missing: Vec<(String, String)> = vec![];
    // Write found props into a scratch writer sharing our prefixes.
    found = found.prefix("D", DAV).prefix("C", CALDAV).prefix("CR", CARDDAV).prefix("CS", CS).prefix("A", APPLE);
    found.open(DAV, "x");
    let mut any = false;
    match want {
        Want::Names => {
            for (ns, n) in LIVE.iter().map(|(a, b)| (a.to_string(), b.to_string())).chain(dead_names(res)) {
                found.empty(&ns, &n);
                any = true;
            }
        }
        Want::All(include) => {
            for (ns, n) in ALLPROP.iter().map(|(a, b)| (a.to_string(), b.to_string())).chain(include.iter().cloned()) {
                if write_prop(ctx, res, &ns, &n, &mut found, None).await {
                    any = true;
                }
            }
            for (ns, n) in dead_names(res) {
                if write_prop(ctx, res, &ns, &n, &mut found, None).await {
                    any = true;
                }
            }
        }
        Want::Props(list) => {
            for e in list {
                if write_prop(ctx, res, &e.ns, &e.name, &mut found, Some(e)).await {
                    any = true;
                } else {
                    missing.push((e.ns.clone(), e.name.clone()));
                }
            }
        }
    }
    found.close(DAV, "x");
    if any {
        // Re-parse to move the props under our document (namespaces resolve).
        if let Ok(doc) = crate::xml::parse(found.finish().as_bytes()) {
            w.open(DAV, "propstat");
            w.open(DAV, "prop");
            for c in doc.elements() {
                w.element(c);
            }
            w.close(DAV, "prop");
            w.text_el(DAV, "status", &status_line(StatusCode::OK));
            w.close(DAV, "propstat");
        }
    }
    if !missing.is_empty() {
        w.open(DAV, "propstat");
        w.open(DAV, "prop");
        for (ns, n) in &missing {
            w.empty(ns, n);
        }
        w.close(DAV, "prop");
        w.text_el(DAV, "status", &status_line(StatusCode::NOT_FOUND));
        w.close(DAV, "propstat");
    }
    if !any && missing.is_empty() {
        w.open(DAV, "propstat");
        w.empty(DAV, "prop");
        w.text_el(DAV, "status", &status_line(StatusCode::OK));
        w.close(DAV, "propstat");
    }
    w.close(DAV, "response");
}

pub fn multistatus() -> Writer {
    let mut w = Writer::new().prefix("D", DAV).prefix("C", CALDAV).prefix("CR", CARDDAV).prefix("CS", CS).prefix("A", APPLE);
    w.open(DAV, "multistatus");
    w
}

pub fn parse_want(body: &[u8]) -> Result<Want, Response> {
    if body.iter().all(|b| b.is_ascii_whitespace()) {
        return Ok(Want::All(vec![]));
    }
    let doc = crate::xml::parse(body).map_err(|_| empty(StatusCode::BAD_REQUEST))?;
    if !doc.is(DAV, "propfind") {
        return Err(empty(StatusCode::BAD_REQUEST));
    }
    let kinds = ["propname", "allprop", "prop"].iter().filter(|k| doc.child(DAV, k).is_some()).count();
    if kinds > 1 {
        return Err(empty(StatusCode::BAD_REQUEST));
    }
    if doc.child(DAV, "propname").is_some() {
        return Ok(Want::Names);
    }
    if doc.child(DAV, "allprop").is_some() {
        let inc = doc.child(DAV, "include").map(|i| i.elements().map(|e| (e.ns.clone(), e.name.clone())).collect()).unwrap_or_default();
        return Ok(Want::All(inc));
    }
    match doc.child(DAV, "prop") {
        Some(p) => Ok(Want::Props(p.elements().cloned().collect())),
        None => Err(empty(StatusCode::BAD_REQUEST)),
    }
}

/// Resolve a target to a resource.
pub async fn resolve(ctx: &Ctx, t: &Target) -> Result<Option<Res>> {
    Ok(match t {
        Target::Root => Some(Res::Root),
        Target::Principals => Some(Res::Principals),
        Target::Principal(u) => ctx.state.db.dav_principal(u).await?.map(Res::Principal),
        Target::SectionRoot(s) => Some(Res::SectionRoot(s.clone())),
        Target::Node(_, p) => directory::lookup(ctx, p).await?.map(Res::Node),
    })
}

async fn children(ctx: &Ctx, res: &Res, infinite: bool) -> Result<Vec<Res>> {
    let st = &ctx.state;
    let me = ctx.principal.clone();
    Ok(match res {
        Res::Root => {
            let mut v = vec![Res::Principals];
            for s in ["calendars", "addressbooks", "files"] {
                if let Some(n) = st.db.dav_node(me.id, s).await? {
                    v.push(Res::Node(n));
                }
            }
            v
        }
        Res::Principals => vec![Res::Principal(me)],
        Res::SectionRoot(s) => st.db.dav_node(me.id, s).await?.map(Res::Node).into_iter().collect(),
        Res::Node(n) if directory::is_virtual(n) => directory::book(ctx).await?.map(|b| b.1).unwrap_or_default().into_iter().map(Res::Node).collect(),
        Res::Node(n) if n.collection => {
            if infinite {
                st.db.dav_subtree(me.id, &n.path).await?.into_iter().filter(|x| x.path != n.path).take(20_000).map(Res::Node).collect()
            } else {
                let mut v: Vec<Res> = st.db.dav_children(me.id, &n.path).await?.into_iter().map(Res::Node).collect();
                if n.kind == "addressbook-home" {
                    if let Some((b, _)) = directory::book(ctx).await? {
                        v.push(Res::Node(b));
                    }
                }
                v
            }
        }
        _ => vec![],
    })
}

pub async fn propfind(ctx: &Ctx, t: &Target, h: &HeaderMap, body: &[u8]) -> Result<Response> {
    let want = match parse_want(body) {
        Ok(w) => w,
        Err(r) => return Ok(r),
    };
    let depth = header_str(h, "depth").unwrap_or("infinity").trim().to_ascii_lowercase();
    if !matches!(depth.as_str(), "0" | "1" | "infinity") {
        return Ok(empty(StatusCode::BAD_REQUEST));
    }
    // Depth: infinity is only allowed inside file storage (RFC 4918 9.1).
    let in_files = matches!(t, Target::Node(_, p) if p == "files" || p.starts_with("files/"));
    if depth == "infinity" && !in_files {
        return Ok(precondition(StatusCode::FORBIDDEN, DAV, "propfind-finite-depth"));
    }
    let Some(res) = resolve(ctx, t).await? else { return Ok(empty(StatusCode::NOT_FOUND)) };
    let mut w = multistatus();
    response(ctx, &res, &want, &mut w).await;
    if depth != "0" {
        for c in children(ctx, &res, depth == "infinity").await? {
            response(ctx, &c, &want, &mut w).await;
        }
    }
    w.close(DAV, "multistatus");
    Ok(xml_response(StatusCode::MULTI_STATUS, w.finish()))
}

pub async fn proppatch(ctx: &Ctx, t: &Target, h: &HeaderMap, body: &[u8]) -> Result<Response> {
    let Target::Node(user, path) = t else { return Ok(empty(StatusCode::FORBIDDEN)) };
    let Some(n) = ctx.state.db.dav_node(ctx.principal.id, path).await? else { return Ok(empty(StatusCode::NOT_FOUND)) };
    if let Some(r) = locks::check_write(ctx, user, path, h, false).await? {
        return Ok(r);
    }
    let doc = match crate::xml::parse(body) {
        Ok(d) if d.is(DAV, "propertyupdate") => d,
        _ => return Ok(empty(StatusCode::BAD_REQUEST)),
    };
    let mut props = n.props.clone();
    let mut results: Vec<(String, String, StatusCode)> = vec![];
    for op in doc.elements() {
        let set = op.is(DAV, "set");
        if !set && !op.is(DAV, "remove") {
            continue;
        }
        let Some(p) = op.child(DAV, "prop") else { continue };
        for e in p.elements() {
            if e.is(CALDAV, "schedule-default-calendar-URL") && n.kind == "schedule-inbox" {
                // Set to one of one's calendars (RFC 6638 9.2.1), or removed.
                let to = e.child(DAV, "href").map(|h| h.text()).and_then(|h| target(h.trim()));
                match (set, to) {
                    (false, _) => {
                        props.remove("default-calendar");
                        results.push((e.ns.clone(), e.name.clone(), StatusCode::OK));
                    }
                    (true, Some(Target::Node(u, cp))) if u == ctx.principal.username && ctx.state.db.dav_node(ctx.principal.id, &cp).await?.is_some_and(|c| c.is_calendar()) => {
                        props.insert("default-calendar".into(), json!(cp));
                        results.push((e.ns.clone(), e.name.clone(), StatusCode::OK));
                    }
                    _ => results.push((e.ns.clone(), e.name.clone(), StatusCode::CONFLICT)),
                }
                continue;
            }
            if set {
                if e.is(CALDAV, "supported-calendar-component-set") || protected(&e.ns, &e.name) {
                    results.push((e.ns.clone(), e.name.clone(), StatusCode::FORBIDDEN));
                    continue;
                }
                let failed = apply_set(&n.kind, &mut props, std::slice::from_ref(e));
                results.push((e.ns.clone(), e.name.clone(), if failed.is_empty() { StatusCode::OK } else { StatusCode::FORBIDDEN }));
            } else {
                if protected(&e.ns, &e.name) {
                    results.push((e.ns.clone(), e.name.clone(), StatusCode::FORBIDDEN));
                    continue;
                }
                if let Some(k) = writable(&e.ns, &e.name) {
                    props.remove(k);
                } else {
                    props.remove(&dead_key(&e.ns, &e.name));
                }
                results.push((e.ns.clone(), e.name.clone(), StatusCode::OK));
            }
        }
    }
    let failed = results.iter().any(|r| r.2 != StatusCode::OK);
    if !failed {
        ctx.state.db.dav_set_props(n.id, &props).await?;
        if n.collection {
            let _ = ctx.state.db.dav_change(n.id, "", false).await;
        } else {
            record_change(&ctx.state, ctx.principal.id, path, false).await;
        }
    }
    let mut w = multistatus();
    w.open(DAV, "response");
    w.text_el(DAV, "href", &href_node(user, &n.path, n.collection));
    for (ns, name, code) in results {
        // RFC 4918 9.2: all or nothing; the rest fail with 424.
        let code = if failed && code == StatusCode::OK { StatusCode::FAILED_DEPENDENCY } else { code };
        w.open(DAV, "propstat");
        w.open(DAV, "prop");
        w.empty(&ns, &name);
        w.close(DAV, "prop");
        w.text_el(DAV, "status", &status_line(code));
        if code == StatusCode::FORBIDDEN {
            w.open(DAV, "error");
            w.empty(DAV, "cannot-modify-protected-property");
            w.close(DAV, "error");
        }
        w.close(DAV, "propstat");
    }
    w.close(DAV, "response");
    w.close(DAV, "multistatus");
    Ok(xml_response(StatusCode::MULTI_STATUS, w.finish()))
}
