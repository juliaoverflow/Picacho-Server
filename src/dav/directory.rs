//! The contact directory as a read-only address book,
//! `addressbooks/<me>/directory/`, built per request from the rules in
//! `settings.directory` (see `crate::directory`). Cards aren't stored as
//! DAV resources: nodes have negative ids and carry their text in
//! `props["_content"]` (read by `read_blob`). What each viewer last saw is
//! kept, so sync tokens count real changes and sync-collection returns only
//! what changed. A real collection with the same name hides the virtual one.
use super::*;

pub const PATH: &str = "addressbooks/directory";
const CONTENT: &str = "_content";
const TOKEN_PREFIX: &str = "http://picacho.mail/ns/directory/";

pub fn is_dir_path(p: &str) -> bool {
    p == PATH || p.strip_prefix(PATH).is_some_and(|r| r.starts_with('/'))
}

pub fn is_virtual(n: &Node) -> bool {
    n.id < 0
}

/// The virtual book's text content (cards only).
pub fn content(n: &Node) -> Option<Vec<u8>> {
    is_virtual(n).then(|| n.prop_str(CONTENT).unwrap_or_default().into_bytes())
}

/// The sync token / ctag of the virtual book.
pub fn token(n: &Node) -> String {
    n.prop_str("_token").unwrap_or_default()
}

/// Whether this principal gets the virtual book.
pub async fn active(ctx: &Ctx) -> Result<bool> {
    if !ctx.state.settings().directory.enabled || ctx.principal.account_id.is_none() {
        return Ok(false);
    }
    Ok(ctx.state.db.dav_node(ctx.principal.id, PATH).await?.is_none())
}

fn node(path: String, id: i64, collection: bool, etag: String, props: Map<String, Value>, size: i64, uid: String) -> Node {
    let t = now();
    Node {
        id,
        principal_id: 0,
        parent: parent_of(&path),
        path,
        collection,
        kind: if collection { "addressbook".into() } else { String::new() },
        blob: String::new(),
        size,
        etag,
        ctype: if collection { String::new() } else { "text/vcard; charset=utf-8".into() },
        props,
        uid,
        comp: if collection { String::new() } else { "VCARD".into() },
        dtstart: None,
        dtend: None,
        created_at: t,
        updated_at: t,
    }
}

/// The book and its cards, or None when this principal doesn't get one.
pub async fn book(ctx: &Ctx) -> Result<Option<(Node, Vec<Node>)>> {
    if !active(ctx).await? {
        return Ok(None);
    }
    let Some(acc) = ctx.state.db.get_account(ctx.principal.account_id.unwrap_or(0)).await? else { return Ok(None) };
    let b = crate::directory::refresh(&ctx.state, &acc).await?;
    let mut nodes = vec![];
    for (id, etag, text) in b.cards {
        let mut props = Map::new();
        let size = text.len() as i64;
        props.insert(CONTENT.into(), json!(text));
        nodes.push(node(format!("{PATH}/{id}.vcf"), -(id + 1), false, etag, props, size, format!("urn:picacho:account:{id}")));
    }
    let tok = format!("{TOKEN_PREFIX}{}-{}", acc.id, b.state);
    let mut props = Map::new();
    props.insert("displayname".into(), json!("Directory"));
    props.insert("description".into(), json!("People you can see on this server (read-only)"));
    props.insert("_token".into(), json!(tok));
    Ok(Some((node(PATH.into(), -1, true, String::new(), props, 0, String::new()), nodes)))
}

/// A node by path: the virtual book for directory paths, else the store.
pub async fn lookup(ctx: &Ctx, path: &str) -> Result<Option<Node>> {
    if is_dir_path(path) {
        if let Some((coll, cards)) = book(ctx).await? {
            return Ok(if path == PATH { Some(coll) } else { cards.into_iter().find(|c| c.path == path) });
        }
    }
    ctx.state.db.dav_node(ctx.principal.id, path).await
}

/// Whether a request touches the virtual book (target or Destination).
pub async fn touches(ctx: &Ctx, t: &Target, headers: &HeaderMap) -> bool {
    let hit = |t: &Target| matches!(t, Target::Node(_, p) if is_dir_path(p));
    let dest = header_str(headers, "destination").and_then(target);
    (hit(t) || dest.as_ref().is_some_and(hit)) && active(ctx).await.unwrap_or(false)
}

/// GET/HEAD on the book (all cards) or one card.
pub async fn get(ctx: &Ctx, path: &str, h: &HeaderMap, head: bool) -> Result<Response> {
    let Some((coll, cards)) = book(ctx).await? else { return Ok(empty(StatusCode::NOT_FOUND)) };
    let (body, etag) = if path == PATH {
        (cards.iter().filter_map(content).flatten().collect::<Vec<u8>>(), format!("\"{}\"", token(&coll).trim_start_matches(TOKEN_PREFIX)))
    } else {
        match cards.iter().find(|c| c.path == path) {
            Some(c) => (content(c).unwrap_or_default(), c.etag.clone()),
            None => return Ok(empty(StatusCode::NOT_FOUND)),
        }
    };
    if header_str(h, "if-none-match").is_some_and(|m| m.split(',').any(|x| x.trim() == etag || x.trim() == "*")) {
        let mut r = empty(StatusCode::NOT_MODIFIED);
        r.headers_mut().insert(header::ETAG, HeaderValue::from_str(&etag)?);
        return Ok(r);
    }
    let len = body.len();
    let mut r = Response::new(Body::from(if head { vec![] } else { body }));
    let hd = r.headers_mut();
    hd.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/vcard; charset=utf-8"));
    hd.insert(header::ETAG, HeaderValue::from_str(&etag)?);
    hd.insert(header::CONTENT_LENGTH, HeaderValue::from(len as u64));
    hd.insert(header::CACHE_CONTROL, HeaderValue::from_static("private, no-cache"));
    Ok(r)
}

/// The change number in one of our tokens for this viewer.
fn token_number(tok: &str, viewer: i64) -> Option<i64> {
    let (v, n) = tok.trim().strip_prefix(TOKEN_PREFIX)?.split_once('-')?;
    (v.parse::<i64>().ok()? == viewer).then(|| n.parse().ok()).flatten()
}

/// sync-collection on the book: everything for a new sync, otherwise only
/// the people added, changed or no longer visible since the token.
pub async fn sync(ctx: &Ctx, doc: &crate::xml::Element, want: &props::Want) -> Result<Response> {
    let Some((coll, cards)) = book(ctx).await? else { return Ok(empty(StatusCode::NOT_FOUND)) };
    let viewer = ctx.principal.account_id.unwrap_or(0);
    let current = token(&coll);
    let tok = doc.child(DAV, "sync-token").map(|t| t.text()).unwrap_or_default();
    let since = if tok.trim().is_empty() {
        None
    } else {
        let now = token_number(&current, viewer).unwrap_or(0);
        match token_number(&tok, viewer) {
            Some(n) if n <= now => Some(n),
            _ => return Ok(precondition(StatusCode::FORBIDDEN, DAV, "valid-sync-token")),
        }
    };
    let mut w = props::multistatus();
    match since {
        None => {
            for c in cards {
                props::response(ctx, &props::Res::Node(c), want, &mut w).await;
            }
        }
        Some(n) => {
            for (person, _) in ctx.state.db.directory_changes_since(viewer, n).await? {
                let path = format!("{PATH}/{person}.vcf");
                match cards.iter().find(|c| c.path == path) {
                    Some(c) => props::response(ctx, &props::Res::Node(c.clone()), want, &mut w).await,
                    None => {
                        w.open(DAV, "response");
                        w.text_el(DAV, "href", &href_node(&ctx.principal.username, &path, false));
                        w.text_el(DAV, "status", &status_line(StatusCode::NOT_FOUND));
                        w.close(DAV, "response");
                    }
                }
            }
        }
    }
    w.text_el(DAV, "sync-token", &current);
    w.close(DAV, "multistatus");
    Ok(xml_response(StatusCode::MULTI_STATUS, w.finish()))
}

/// principal-property-search over the people this principal may see. A
/// principal's URL contains its user name (the address), so people only
/// appear when their email is visible; the display name only when the
/// name is.
pub async fn search(ctx: &Ctx, needles: &[String]) -> Result<Vec<Principal>> {
    let s = ctx.state.settings().directory.clone();
    let Some(acc_id) = ctx.principal.account_id else { return Ok(vec![]) };
    if !s.enabled || needles.iter().all(|n| n.trim().is_empty()) {
        return Ok(vec![]);
    }
    let entries = crate::directory::load_entries(&ctx.state).await?;
    let Some(me) = entries.iter().find(|e| e.id == acc_id) else { return Ok(vec![]) };
    let mut out = vec![];
    for (e, f) in crate::directory::visible(me, &entries, &s) {
        if e.id == acc_id || !f.contains("email") {
            continue;
        }
        let name = if f.contains("name") { e.name.clone() } else { String::new() };
        let hay = format!("{name} {}", e.email).to_lowercase();
        if !needles.iter().any(|n| !n.trim().is_empty() && hay.contains(n.trim().trim_start_matches("mailto:"))) {
            continue;
        }
        // People who never used calendars or contacts get their principal now,
        // as their first DAV sign-in would (when mail accounts get DAV).
        let principal = match ctx.state.db.dav_principal_for_account(e.id).await? {
            Some(p) => Some(p),
            None => match ctx.state.db.get_account(e.id).await? {
                Some(a) => principal_for_account(&ctx.state, &a).await?,
                None => None,
            },
        };
        let Some(mut p) = principal else { continue };
        if !p.active {
            continue;
        }
        p.display_name = name;
        p.email = e.email.clone();
        out.push(p);
        if out.len() >= 50 {
            break;
        }
    }
    Ok(out)
}
