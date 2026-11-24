//! Managed attachments (RFC 8607): files kept by the server and linked
//! from calendar events.
//!
//! A client POSTs a file to an event with `?action=attachment-add`
//! (`attachment-update` or `attachment-remove` with `managed-id=`; `rid=`
//! for some occurrences only). The file is stored under the owner's
//! `calendars/attachments/` collection, and the event gets an
//! `ATTACH;MANAGED-ID=..;FILENAME=..;SIZE=..;FMTTYPE=..:<url>` pointing at
//! it, which any signed-in client (or anyone who has the URL: the name is
//! random) can GET. A file goes once no event of its owner links to it.
use super::ical::{self, Comp, Prop};
use super::*;

/// Where an owner's attachment files live.
pub const COLLECTION: &str = "calendars/attachments";

/// At most this many managed attachments on one event (RFC 8607 6.2).
pub const MAX_PER_RESOURCE: usize = 20;

/// Largest attachment (RFC 8607 6.1): the DAV upload limit, at most 100 MB.
pub fn max_size(state: &State) -> u64 {
    state.settings().dav.max_resource_bytes.min(100 * 1024 * 1024)
}

fn is_attachment_path(path: &str) -> bool {
    path == COLLECTION || path.starts_with(&format!("{COLLECTION}/"))
}

/// Whether a path is the attachments collection or inside it (clients may
/// read it, not write it themselves).
pub fn touches(path: &str) -> bool {
    is_attachment_path(path)
}

fn query_param(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        (k == key).then(|| pct_decode(&v.replace('+', " ")))
    })
}

/// The file name from Content-Disposition (`filename*=UTF-8''..` first).
fn file_name(h: &HeaderMap) -> String {
    let cd = header_str(h, "content-disposition").unwrap_or("");
    let mut plain = None;
    for part in cd.split(';').map(str::trim) {
        let Some((k, v)) = part.split_once('=') else { continue };
        match k.trim().to_ascii_lowercase().as_str() {
            "filename*" => {
                let v = v.trim().trim_matches('"');
                let enc = v.split_once("''").map(|(_, rest)| rest).unwrap_or(v);
                return clean_name(&pct_decode(enc));
            }
            "filename" => plain = Some(v.trim().trim_matches('"').to_string()),
            _ => {}
        }
    }
    clean_name(&plain.unwrap_or_default())
}

fn clean_name(n: &str) -> String {
    let n: String = n.rsplit(['/', '\\']).next().unwrap_or("").chars().filter(|c| !c.is_control() && *c != '"').take(200).collect();
    if n.trim().is_empty() { "attachment".into() } else { n.trim().to_string() }
}

/// RECURRENCE-IDs in `rid=` (comma separated; `M` is the series itself).
fn wanted(c: &Comp, rids: &Option<Vec<String>>) -> bool {
    let Some(rids) = rids else { return true };
    match c.prop("RECURRENCE-ID") {
        None => rids.iter().any(|r| r == "M"),
        Some(p) => {
            let at = ical::prop_when(p).map(|w| w.utc());
            rids.iter().any(|r| r != "M" && ical::parse_when(r, None).map(|w| w.utc()) == at)
        }
    }
}

/// The event's components to change (not VTIMEZONE).
fn targets<'a>(cal: &'a mut Comp, rids: &Option<Vec<String>>) -> Vec<&'a mut Comp> {
    cal.comps.iter_mut().filter(|c| c.name != "VTIMEZONE").filter(|c| wanted(c, rids)).collect()
}

/// Every MANAGED-ID an event links to.
pub fn managed_ids(cal: &Comp) -> Vec<String> {
    cal.comps.iter().flat_map(|c| c.props_named("ATTACH")).filter_map(|p| p.param("MANAGED-ID").map(String::from)).collect()
}

fn attach_prop(url: &str, id: &str, name: &str, size: usize, ctype: &str) -> Prop {
    Prop {
        name: "ATTACH".into(),
        params: vec![
            ("MANAGED-ID".into(), id.into()),
            ("FILENAME".into(), name.into()),
            ("SIZE".into(), size.to_string()),
            ("FMTTYPE".into(), ctype.into()),
        ],
        value: url.into(),
    }
}

fn refuse(name: &str) -> Response {
    precondition(StatusCode::FORBIDDEN, CALDAV, name)
}

/// POST `?action=attachment-*` on a calendar object resource.
pub async fn post(ctx: &Ctx, user: &str, path: &str, query: &str, h: &HeaderMap, body: &[u8]) -> Result<Response> {
    let st = &ctx.state;
    let pid = ctx.principal.id;
    let action = query_param(query, "action").unwrap_or_default();
    let Some(node) = st.db.dav_node(pid, path).await?.filter(|n| !n.collection && n.section() == "calendars" && !is_attachment_path(&n.path)) else {
        return Ok(empty(StatusCode::NOT_FOUND));
    };
    if let Some(code) = check_conditional(h, Some(&node.etag)) {
        return Ok(empty(code));
    }
    if let Some(r) = locks::check_write(ctx, user, path, h, false).await? {
        return Ok(r);
    }
    let Ok(mut cal) = ical::parse(&String::from_utf8_lossy(&read_blob(st, &node).await?)) else {
        return Ok(refuse("valid-calendar-data"));
    };
    let rids = query_param(query, "rid").map(|r| r.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect::<Vec<_>>());
    if let Some(rs) = &rids {
        // Each rid must name the series (M) or an occurrence on record.
        for r in rs {
            let known = r == "M" || cal.comps.iter().filter_map(|c| c.prop("RECURRENCE-ID")).any(|p| ical::prop_when(p).map(|w| w.utc()) == ical::parse_when(r, None).map(|w| w.utc()));
            if !known {
                return Ok(refuse("valid-rid"));
            }
        }
    }
    let managed = query_param(query, "managed-id");
    let mut new_id = String::new();
    let mut freed_ids: Vec<String> = vec![];
    match action.as_str() {
        "attachment-add" | "attachment-update" => {
            if body.is_empty() {
                return Ok(empty(StatusCode::BAD_REQUEST));
            }
            if body.len() as u64 > max_size(st) {
                return Ok(refuse("max-attachment-size"));
            }
            if action == "attachment-update" {
                let Some(id) = managed.as_deref().filter(|id| managed_ids(&cal).iter().any(|m| m == id)) else { return Ok(refuse("valid-managed-id")) };
                freed_ids.push(id.to_string());
            } else {
                let count = targets(&mut cal, &rids).iter().map(|c| c.props_named("ATTACH").filter(|p| p.param("MANAGED-ID").is_some()).count()).max().unwrap_or(0);
                if count >= MAX_PER_RESOURCE {
                    return Ok(refuse("max-attachments-per-resource"));
                }
            }
            let quota = ctx.principal.quota_bytes;
            let used = st.db.dav_principal_by_id(pid).await?.map(|p| p.used_bytes).unwrap_or(0);
            if quota > 0 && used + body.len() as i64 > quota {
                return Ok(precondition(StatusCode::INSUFFICIENT_STORAGE, DAV, "quota-not-exceeded"));
            }
            let ctype = header_str(h, "content-type").unwrap_or("application/octet-stream").split(';').next().unwrap_or("").trim().to_string();
            let ctype = if ctype.is_empty() || ctype.contains(['"', '\r', '\n']) { "application/octet-stream".to_string() } else { ctype };
            let name = file_name(h);
            new_id = uuid::Uuid::new_v4().simple().to_string();
            store_file(ctx, &new_id, &name, &ctype, body).await?;
            let url = format!("{}{}", ctx.base, href_node(user, &format!("{COLLECTION}/{new_id}"), false));
            let prop = attach_prop(&url, &new_id, &name, body.len(), &ctype);
            for c in targets(&mut cal, &rids) {
                match &managed {
                    Some(old) if action == "attachment-update" => {
                        for p in c.props.iter_mut().filter(|p| p.name == "ATTACH" && p.param("MANAGED-ID") == Some(old.as_str())) {
                            *p = prop.clone();
                        }
                    }
                    _ => c.props.push(prop.clone()),
                }
            }
        }
        "attachment-remove" => {
            let Some(id) = managed.filter(|id| managed_ids(&cal).iter().any(|m| m == id)) else { return Ok(refuse("valid-managed-id")) };
            for c in targets(&mut cal, &rids) {
                c.props.retain(|p| !(p.name == "ATTACH" && p.param("MANAGED-ID") == Some(id.as_str())));
            }
            freed_ids.push(id);
        }
        _ => return Ok(empty(StatusCode::BAD_REQUEST)),
    }
    let text = ical::serialize(&cal);
    let written = match store::put(st, &ctx.principal, path, text.as_bytes()).await? {
        Ok(n) => n,
        Err(e) => {
            if !new_id.is_empty() {
                drop_file(ctx, &new_id).await?;
            }
            return Ok(if e == "overQuota" { precondition(StatusCode::INSUFFICIENT_STORAGE, DAV, "quota-not-exceeded") } else { refuse("valid-calendar-data") });
        }
    };
    // Files no event of the owner links to any more.
    let still = linked(ctx).await?;
    for id in freed_ids.into_iter().filter(|id| !still.contains(id)) {
        drop_file(ctx, &id).await?;
    }
    let mut r = empty(if action == "attachment-remove" { StatusCode::NO_CONTENT } else { StatusCode::CREATED });
    r.headers_mut().insert(header::ETAG, HeaderValue::from_str(&written.etag)?);
    if !new_id.is_empty() {
        r.headers_mut().insert("Cal-Managed-ID", HeaderValue::from_str(&new_id)?);
        r.headers_mut().insert(header::LOCATION, HeaderValue::from_str(&format!("{}{}", ctx.base, href_node(user, &format!("{COLLECTION}/{new_id}"), false)))?);
    }
    Ok(r)
}

async fn store_file(ctx: &Ctx, id: &str, name: &str, ctype: &str, data: &[u8]) -> Result<()> {
    let st = &ctx.state;
    let pid = ctx.principal.id;
    if st.db.dav_node(pid, COLLECTION).await?.is_none() {
        let mut props = Map::new();
        props.insert("displayname".into(), json!("Attachments"));
        st.db.dav_put(pid, &NewNode { path: COLLECTION, collection: true, kind: "attachments", blob: "", size: 0, etag: "", ctype: "", props: &props, uid: "", comp: "", dtstart: None, dtend: None }).await?;
    }
    let key = write_blob(st, "calendars", data).await?;
    let mut props = Map::new();
    props.insert("filename".into(), json!(name));
    let path = format!("{COLLECTION}/{id}");
    st.db.dav_put(pid, &NewNode { path: &path, collection: false, kind: "", blob: &key, size: data.len() as i64, etag: &etag_of(data), ctype, props: &props, uid: "", comp: "", dtstart: None, dtend: None }).await?;
    st.db.dav_usage(pid, data.len() as i64).await?;
    Ok(())
}

async fn drop_file(ctx: &Ctx, id: &str) -> Result<()> {
    let path = format!("{COLLECTION}/{id}");
    if ctx.state.db.dav_node(ctx.principal.id, &path).await?.is_some() {
        remove_tree(ctx, &path).await?;
    }
    Ok(())
}

/// MANAGED-IDs any of the owner's events link to.
async fn linked(ctx: &Ctx) -> Result<std::collections::HashSet<String>> {
    let st = &ctx.state;
    let mut out = std::collections::HashSet::new();
    for cal in st.db.dav_children(ctx.principal.id, "calendars").await?.into_iter().filter(|c| c.collection && c.is_calendar()) {
        for n in st.db.dav_children(ctx.principal.id, &cal.path).await?.into_iter().filter(|n| !n.collection) {
            let Ok(data) = read_blob(st, &n).await else { continue };
            if !data.windows(10).any(|w| w.eq_ignore_ascii_case(b"MANAGED-ID")) {
                continue;
            }
            if let Ok(c) = ical::parse(&String::from_utf8_lossy(&data)) {
                out.extend(managed_ids(&c));
            }
        }
    }
    Ok(out)
}

/// After an event is deleted or replaced: drop files nothing links to.
pub async fn sweep(ctx: &Ctx) -> Result<()> {
    let files = ctx.state.db.dav_children(ctx.principal.id, COLLECTION).await?;
    if files.is_empty() {
        return Ok(());
    }
    let still = linked(ctx).await?;
    for f in files.into_iter().filter(|f| !f.collection && !still.contains(f.name())) {
        remove_tree(ctx, &f.path).await?;
    }
    Ok(())
}

/// GET of an attachment: served with its name as a download.
pub fn decorate(n: &Node, r: &mut Response) {
    if !is_attachment_path(&n.path) {
        return;
    }
    if let Some(name) = n.prop_str("filename") {
        let ascii: String = name.chars().map(|c| if c.is_ascii() && !c.is_ascii_control() && c != '"' && c != '\\' { c } else { '_' }).collect();
        let v = format!("attachment; filename=\"{ascii}\"; filename*=UTF-8''{}", pct_encode(&name));
        if let Ok(v) = HeaderValue::from_str(&v) {
            r.headers_mut().insert(header::CONTENT_DISPOSITION, v);
        }
    }
    r.headers_mut().insert("X-Content-Type-Options", HeaderValue::from_static("nosniff"));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_params() {
        let mut h = HeaderMap::new();
        h.insert("content-disposition", HeaderValue::from_static("attachment;filename=\"plan.pdf\";filename*=UTF-8''pl%C3%A4n.pdf"));
        assert_eq!(file_name(&h), "plän.pdf");
        h.insert("content-disposition", HeaderValue::from_static("attachment; filename=\"../../etc/passwd\""));
        assert_eq!(file_name(&h), "passwd");
        assert_eq!(query_param("action=attachment-add&rid=M,20261201T100000Z", "rid").as_deref(), Some("M,20261201T100000Z"));
        assert_eq!(query_param("action=attachment-remove&managed-id=abc", "managed-id").as_deref(), Some("abc"));
    }
}
