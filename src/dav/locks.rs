//! WebDAV locking (RFC 4918 sections 6-7, 9.10-9.11, 10.4): exclusive and
//! shared write locks, depth 0/infinity, lock-null (unmapped URL) locks,
//! refresh, and evaluation of the If header.
use super::*;
use crate::xml::Writer;

#[derive(Debug, Clone)]
pub struct Lock {
    pub token: String,
    pub path: String,
    pub depth_infinite: bool,
    pub exclusive: bool,
    pub owner: String,
    pub expires_at: i64,
}

fn lock_from(r: &sqlx::any::AnyRow) -> Lock {
    Lock {
        token: r.get(0),
        path: r.get(1),
        depth_infinite: r.get::<String, _>(2) == "infinity",
        exclusive: r.get::<i64, _>(3) != 0,
        owner: r.get(4),
        expires_at: r.get(5),
    }
}

async fn all_locks(st: &State, principal: i64) -> Vec<Lock> {
    sqlx::query("SELECT token, path, depth, exclusive, owner, expires_at FROM dav_locks WHERE principal_id = $1 AND expires_at > $2")
        .bind(principal)
        .bind(now())
        .fetch_all(&st.db.pool)
        .await
        .map(|rows| rows.iter().map(lock_from).collect())
        .unwrap_or_default()
}

fn covers(l: &Lock, path: &str) -> bool {
    l.path == path || (l.depth_infinite && path.starts_with(&format!("{}/", l.path)))
}

/// Locks that apply to `path` (its own and inherited ones).
pub async fn active_for(st: &State, principal: i64, path: &str) -> Vec<Lock> {
    all_locks(st, principal).await.into_iter().filter(|l| covers(l, path)).collect()
}

pub async fn drop_locks(st: &State, principal: i64, path: &str) {
    let _g = st.db.wl().await;
    let _ = sqlx::query("DELETE FROM dav_locks WHERE principal_id = $1 AND (path = $2 OR path LIKE $3 ESCAPE '\\')")
        .bind(principal)
        .bind(path)
        .bind(format!("{}/%", path.replace('%', "\\%").replace('_', "\\_")))
        .execute(&st.db.pool)
        .await;
}

pub fn write_activelock(w: &mut Writer, l: &Lock, user: &str) {
    w.open(DAV, "activelock");
    w.open(DAV, "locktype");
    w.empty(DAV, "write");
    w.close(DAV, "locktype");
    w.open(DAV, "lockscope");
    w.empty(DAV, if l.exclusive { "exclusive" } else { "shared" });
    w.close(DAV, "lockscope");
    w.text_el(DAV, "depth", if l.depth_infinite { "infinity" } else { "0" });
    if !l.owner.is_empty() {
        if let Ok(o) = crate::xml::parse(l.owner.as_bytes()) {
            w.element(&o);
        }
    }
    w.text_el(DAV, "timeout", &format!("Second-{}", (l.expires_at - now()).max(0)));
    w.open(DAV, "locktoken");
    w.text_el(DAV, "href", &l.token);
    w.close(DAV, "locktoken");
    w.open(DAV, "lockroot");
    w.text_el(DAV, "href", &href_node(user, &l.path, true).trim_end_matches('/').to_string());
    w.close(DAV, "lockroot");
    w.close(DAV, "activelock");
}

// ------------------------------------------------------------------ If header

#[derive(Debug, Clone, PartialEq)]
enum Cond {
    Token(String),
    Etag(String),
}

#[derive(Debug, Clone)]
struct List {
    resource: Option<String>,
    conds: Vec<(bool, Cond)>,
}

fn parse_if(h: &str) -> Option<Vec<List>> {
    let mut out = vec![];
    let mut tag: Option<String> = None;
    let b = h.trim();
    let mut i = 0;
    let c: Vec<char> = b.chars().collect();
    while i < c.len() {
        match c[i] {
            ' ' | '\t' => i += 1,
            '<' => {
                let end = c[i..].iter().position(|x| *x == '>')? + i;
                tag = Some(c[i + 1..end].iter().collect());
                i = end + 1;
            }
            '(' => {
                let end = c[i..].iter().position(|x| *x == ')')? + i;
                let inner: String = c[i + 1..end].iter().collect();
                let mut conds = vec![];
                let mut j = 0;
                let ic: Vec<char> = inner.chars().collect();
                let mut not = false;
                while j < ic.len() {
                    match ic[j] {
                        ' ' | '\t' => j += 1,
                        'N' | 'n' if ic[j..].iter().take(3).collect::<String>().eq_ignore_ascii_case("not") => {
                            not = true;
                            j += 3;
                        }
                        '<' => {
                            let e = ic[j..].iter().position(|x| *x == '>')? + j;
                            conds.push((not, Cond::Token(ic[j + 1..e].iter().collect())));
                            not = false;
                            j = e + 1;
                        }
                        '[' => {
                            let e = ic[j..].iter().position(|x| *x == ']')? + j;
                            conds.push((not, Cond::Etag(ic[j + 1..e].iter().collect::<String>().trim_start_matches("W/").to_string())));
                            not = false;
                            j = e + 1;
                        }
                        _ => return None,
                    }
                }
                if conds.is_empty() {
                    return None;
                }
                out.push(List { resource: tag.clone(), conds });
                i = end + 1;
            }
            _ => return None,
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// Tokens mentioned anywhere in the If header.
fn submitted(lists: &[List]) -> Vec<String> {
    lists.iter().flat_map(|l| l.conds.iter().filter_map(|(_, c)| if let Cond::Token(t) = c { Some(t.clone()) } else { None })).collect()
}

/// Evaluate the If header (RFC 4918 10.4). Untagged lists apply to the
/// request URI; tagged lists to the resource they name.
async fn eval_if(ctx: &Ctx, user: &str, path: &str, lists: &[List]) -> bool {
    let st = &ctx.state;
    let locks = all_locks(st, ctx.principal.id).await;
    // Group lists by resource; the header is true if, for each tagged
    // resource, some list is true (no-tag lists: the request resource).
    let mut groups: std::collections::BTreeMap<String, Vec<&List>> = Default::default();
    for l in lists {
        let p = match &l.resource {
            None => path.to_string(),
            Some(r) => match target(r) {
                Some(Target::Node(u, p)) if u == user => p,
                _ => String::from("\0foreign"),
            },
        };
        groups.entry(p).or_default().push(l);
    }
    for (p, ls) in groups {
        let node = if p == "\0foreign" { None } else { st.db.dav_node(ctx.principal.id, &p).await.ok().flatten() };
        let etag = node.as_ref().map(|n| n.etag.clone()).unwrap_or_default();
        let mut any = false;
        for l in ls {
            let ok = l.conds.iter().all(|(not, c)| {
                let v = match c {
                    Cond::Token(t) => locks.iter().any(|lk| &lk.token == t && covers(lk, &p)),
                    Cond::Etag(e) => node.is_some() && !etag.is_empty() && *e == etag,
                };
                v != *not
            });
            if ok {
                any = true;
                break;
            }
        }
        if !any {
            return false;
        }
    }
    true
}

/// Lock and If-header checks for a write to `path`. `subtree`: the write
/// affects descendants too (DELETE/MOVE of a collection).
pub async fn check_write(ctx: &Ctx, user: &str, path: &str, h: &HeaderMap, subtree: bool) -> Result<Option<Response>> {
    let st = &ctx.state;
    let ifh = h.get("if").and_then(|v| v.to_str().ok());
    let lists = match ifh {
        Some(v) => match parse_if(v) {
            Some(l) => Some(l),
            None => return Ok(Some(empty(StatusCode::BAD_REQUEST))),
        },
        None => None,
    };
    if let Some(l) = &lists {
        if !eval_if(ctx, user, path, l).await {
            return Ok(Some(empty(StatusCode::PRECONDITION_FAILED)));
        }
    }
    let tokens = lists.as_ref().map(|l| submitted(l)).unwrap_or_default();
    let parent = parent_of(path);
    let locks = all_locks(st, ctx.principal.id).await;
    let mut blocking = vec![];
    for l in &locks {
        // The resource itself (or an ancestor with depth infinity), its parent
        // collection's membership, or — for subtree writes — locked descendants.
        let applies = covers(l, path) || l.path == parent || (subtree && l.path.starts_with(&format!("{path}/")));
        if applies && !tokens.contains(&l.token) {
            blocking.push(l.clone());
        }
    }
    if blocking.is_empty() {
        return Ok(None);
    }
    let mut w = Writer::new().prefix("D", DAV);
    w.open(DAV, "error");
    w.open(DAV, "lock-token-submitted");
    for l in blocking {
        w.text_el(DAV, "href", &href_node(user, &l.path, false));
    }
    w.close(DAV, "lock-token-submitted");
    w.close(DAV, "error");
    Ok(Some(xml_response(StatusCode::LOCKED, w.finish())))
}

fn timeout(h: &HeaderMap) -> i64 {
    let v = h.get("timeout").and_then(|v| v.to_str().ok()).unwrap_or("");
    for part in v.split(',') {
        let p = part.trim();
        if let Some(n) = p.strip_prefix("Second-").and_then(|n| n.parse::<i64>().ok()) {
            return n.clamp(1, 7 * 86400);
        }
        if p.eq_ignore_ascii_case("Infinite") {
            return 7 * 86400;
        }
    }
    3600
}

fn lock_response(code: StatusCode, l: &Lock, user: &str) -> Response {
    let mut w = Writer::new().prefix("D", DAV);
    w.open(DAV, "prop");
    w.open(DAV, "lockdiscovery");
    write_activelock(&mut w, l, user);
    w.close(DAV, "lockdiscovery");
    w.close(DAV, "prop");
    let mut r = xml_response(code, w.finish());
    if let Ok(v) = HeaderValue::from_str(&format!("<{}>", l.token)) {
        r.headers_mut().insert("Lock-Token", v);
    }
    r
}

pub async fn lock(ctx: &Ctx, t: &Target, h: &HeaderMap, body: &[u8]) -> Result<Response> {
    let Target::Node(user, path) = t else { return Ok(empty(StatusCode::METHOD_NOT_ALLOWED)) };
    let st = &ctx.state;
    let pid = ctx.principal.id;
    if path.split('/').count() < 2 {
        return Ok(empty(StatusCode::FORBIDDEN));
    }
    let ttl = timeout(h);
    // Refresh: empty body plus an If header naming the lock.
    if body.iter().all(|b| b.is_ascii_whitespace()) {
        let Some(lists) = h.get("if").and_then(|v| v.to_str().ok()).and_then(parse_if) else { return Ok(empty(StatusCode::BAD_REQUEST)) };
        let tokens = submitted(&lists);
        let locks = active_for(st, pid, path).await;
        let Some(l) = locks.into_iter().find(|l| tokens.contains(&l.token)) else { return Ok(empty(StatusCode::PRECONDITION_FAILED)) };
        let _g = st.db.wl().await;
        sqlx::query("UPDATE dav_locks SET expires_at = $1 WHERE token = $2").bind(now() + ttl).bind(&l.token).execute(&st.db.pool).await?;
        drop(_g);
        let mut l2 = l.clone();
        l2.expires_at = now() + ttl;
        return Ok(lock_response(StatusCode::OK, &l2, user));
    }
    let doc = match crate::xml::parse(body) {
        Ok(d) if d.is(DAV, "lockinfo") => d,
        _ => return Ok(empty(StatusCode::BAD_REQUEST)),
    };
    let exclusive = doc.child(DAV, "lockscope").map(|s| s.child(DAV, "exclusive").is_some()).unwrap_or(true);
    if doc.child(DAV, "locktype").is_some_and(|t| t.child(DAV, "write").is_none()) {
        return Ok(empty(StatusCode::UNPROCESSABLE_ENTITY));
    }
    let owner = doc.child(DAV, "owner").map(|o| o.to_fragment()).unwrap_or_default();
    let depth = h.get("depth").and_then(|v| v.to_str().ok()).unwrap_or("infinity").trim().to_ascii_lowercase();
    if depth != "0" && depth != "infinity" {
        return Ok(empty(StatusCode::BAD_REQUEST));
    }
    let infinite = depth == "infinity";
    // Conflicts with existing locks.
    for l in all_locks(st, pid).await {
        let overlap = covers(&l, path) || (infinite && l.path.starts_with(&format!("{path}/")));
        if overlap && (l.exclusive || exclusive) {
            let mut w = Writer::new().prefix("D", DAV);
            w.open(DAV, "error");
            w.open(DAV, "no-conflicting-lock");
            w.text_el(DAV, "href", &href_node(user, &l.path, false));
            w.close(DAV, "no-conflicting-lock");
            w.close(DAV, "error");
            return Ok(xml_response(StatusCode::LOCKED, w.finish()));
        }
    }
    let mut created = false;
    if st.db.dav_node(pid, path).await?.is_none() {
        // Lock on an unmapped URL creates an empty resource (RFC 4918 7.3).
        let parent = parent_of(path);
        match st.db.dav_node(pid, &parent).await? {
            Some(p) if p.collection => {}
            _ => return Ok(empty(StatusCode::CONFLICT)),
        }
        if !path.starts_with("files/") {
            return Ok(empty(StatusCode::FORBIDDEN));
        }
        if let Some(r) = check_write(ctx, user, path, h, false).await? {
            return Ok(r);
        }
        let e = Map::new();
        st.db.dav_put(pid, &NewNode { path, collection: false, kind: "", blob: "", size: 0, etag: &format!("\"{}\"", &crate::util::sha256_hex(b"")[..32]), ctype: "application/octet-stream", props: &e, uid: "", comp: "", dtstart: None, dtend: None }).await?;
        record_change(st, pid, path, false).await;
        created = true;
    }
    let l = Lock { token: format!("opaquelocktoken:{}", uuid::Uuid::new_v4()), path: path.clone(), depth_infinite: infinite, exclusive, owner, expires_at: now() + ttl };
    {
        let _g = st.db.wl().await;
        sqlx::query("INSERT INTO dav_locks (token, principal_id, path, depth, exclusive, owner, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7)")
            .bind(&l.token)
            .bind(pid)
            .bind(&l.path)
            .bind(if infinite { "infinity" } else { "0" })
            .bind(exclusive as i64)
            .bind(&l.owner)
            .bind(l.expires_at)
            .execute(&st.db.pool)
            .await?;
    }
    Ok(lock_response(if created { StatusCode::CREATED } else { StatusCode::OK }, &l, user))
}

pub async fn unlock(ctx: &Ctx, t: &Target, h: &HeaderMap) -> Result<Response> {
    let Target::Node(_, path) = t else { return Ok(empty(StatusCode::METHOD_NOT_ALLOWED)) };
    let st = &ctx.state;
    let Some(token) = h.get("lock-token").and_then(|v| v.to_str().ok()).map(|t| t.trim().trim_start_matches('<').trim_end_matches('>').to_string()) else {
        return Ok(empty(StatusCode::BAD_REQUEST));
    };
    let locks = active_for(st, ctx.principal.id, path).await;
    if !locks.iter().any(|l| l.token == token) {
        return Ok(precondition(StatusCode::CONFLICT, DAV, "lock-token-matches-request-uri"));
    }
    let _g = st.db.wl().await;
    sqlx::query("DELETE FROM dav_locks WHERE token = $1 AND principal_id = $2").bind(&token).bind(ctx.principal.id).execute(&st.db.pool).await?;
    Ok(empty(StatusCode::NO_CONTENT))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn if_header() {
        let l = parse_if(r#"(<opaquelocktoken:a> ["etag1"]) (Not <DAV:no-lock>)"#).unwrap();
        assert_eq!(l.len(), 2);
        assert_eq!(l[0].conds[1], (false, Cond::Etag("\"etag1\"".into())));
        assert!(l[1].conds[0].0);
        let l = parse_if(r#"<http://h/dav/files/u/a> (<opaquelocktoken:b>)"#).unwrap();
        assert_eq!(l[0].resource.as_deref(), Some("http://h/dav/files/u/a"));
        assert!(parse_if("garbage").is_none());
    }
}
