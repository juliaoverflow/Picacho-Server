//! WebDAV (RFC 4918, class 1/2/3), CalDAV (RFC 4791) and CardDAV
//! (RFC 6352), with sync-collection (RFC 6578), current-user-principal
//! (RFC 5397), quotas (RFC 4331) and extended MKCOL (RFC 5689).
//!
//! Layout under `/dav/`:
//!   principals/<user>/                 principal
//!   calendars/<user>/<calendar>/<x>.ics
//!   addressbooks/<user>/<book>/<x>.vcf
//!   files/<user>/<any path>            plain WebDAV storage
//!
//! A DAV principal is either linked to a mail account (same sign-in; the
//! user name is the address) or standalone (its own user name and
//! password). Files, calendars and contacts each have their own store
//! (`[storage.dav]`), defaulting to the message store's backend.
pub mod attach;
pub mod ical;
pub mod itip;
pub mod jscal;
mod directory;
mod locks;
mod props;
mod report;
mod schedule;

use crate::blob::Backend;
use crate::config::Config;
use crate::state::State;
use crate::util::now;
use anyhow::Result;
use axum::body::{Body, Bytes};
use axum::extract::{ConnectInfo, State as AxState};
use axum::http::{header, HeaderMap, HeaderValue, Method, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Router;
use serde_json::{json, Map, Value};
use sqlx::Row;
use std::net::SocketAddr;

pub const DAV: &str = "DAV:";
pub const CS: &str = "http://calendarserver.org/ns/";
pub const APPLE: &str = "http://apple.com/ns/ical/";
pub use ical::{CALDAV, CARDDAV};

// ------------------------------------------------------------------ stores

pub struct Stores {
    pub files: Backend,
    pub calendars: Backend,
    pub contacts: Backend,
}

impl Stores {
    pub fn new(cfg: &Config, db: &crate::db::Db) -> Result<Self> {
        let build = |part: &Option<crate::config::BlobConfig>, name: &str| -> Result<Backend> {
            let c = match part {
                Some(c) => c.clone(),
                None => {
                    // Same kind of store as messages, in its own place.
                    let m = &cfg.storage.messages;
                    let mut c = m.clone();
                    c.path = None;
                    if let Some(s3) = &mut c.s3 {
                        let p = s3.prefix.clone().unwrap_or_default();
                        s3.prefix = Some(format!("{}dav/{name}", if p.is_empty() { String::new() } else { format!("{}/", p.trim_matches('/')) }));
                    }
                    c
                }
            };
            Backend::build(&c.kind, &c.path, &c.s3, cfg.data_path(&format!("dav/{name}")), Some(db))
        };
        Ok(Self { files: build(&cfg.storage.dav.files, "files")?, calendars: build(&cfg.storage.dav.calendars, "calendars")?, contacts: build(&cfg.storage.dav.contacts, "contacts")? })
    }

    pub fn for_section(&self, section: &str) -> &Backend {
        match section {
            "calendars" => &self.calendars,
            "addressbooks" => &self.contacts,
            _ => &self.files,
        }
    }

    pub fn describe(&self) -> Value {
        json!({"files": self.files.describe(), "calendars": self.calendars.describe(), "contacts": self.contacts.describe()})
    }
}

pub fn backends(state: &State) -> Vec<(String, Backend)> {
    vec![
        ("dav-files".into(), state.dav.files.clone()),
        ("dav-calendars".into(), state.dav.calendars.clone()),
        ("dav-contacts".into(), state.dav.contacts.clone()),
    ]
}

fn is_db(b: &Backend) -> bool {
    matches!(b, Backend::Database(_))
}

// ------------------------------------------------------------------ principals

#[derive(Debug, Clone, serde::Serialize)]
pub struct Principal {
    pub id: i64,
    pub username: String,
    pub account_id: Option<i64>,
    #[serde(skip)]
    pub password_hash: String,
    pub display_name: String,
    pub email: String,
    pub quota_bytes: i64,
    pub used_bytes: i64,
    pub active: bool,
    pub created_at: i64,
}

const P_COLS: &str = "id, username, account_id, password_hash, display_name, email, quota_bytes, used_bytes, active, created_at";

fn principal_from(r: &sqlx::any::AnyRow) -> Result<Principal> {
    Ok(Principal {
        id: r.try_get("id")?,
        username: r.try_get("username")?,
        account_id: r.try_get("account_id")?,
        password_hash: r.try_get("password_hash")?,
        display_name: r.try_get("display_name")?,
        email: r.try_get("email")?,
        quota_bytes: r.try_get("quota_bytes")?,
        used_bytes: r.try_get("used_bytes")?,
        active: r.try_get::<i64, _>("active")? != 0,
        created_at: r.try_get("created_at")?,
    })
}

impl crate::db::Db {
    pub async fn dav_principals(&self) -> Result<Vec<Principal>> {
        let rows = sqlx::query(&format!("SELECT {P_COLS} FROM dav_principals ORDER BY username")).fetch_all(&self.pool).await?;
        rows.iter().map(principal_from).collect()
    }
    pub async fn dav_principal(&self, username: &str) -> Result<Option<Principal>> {
        let r = sqlx::query(&format!("SELECT {P_COLS} FROM dav_principals WHERE username = $1")).bind(username.to_ascii_lowercase()).fetch_optional(&self.pool).await?;
        r.as_ref().map(principal_from).transpose()
    }
    pub async fn dav_principal_by_id(&self, id: i64) -> Result<Option<Principal>> {
        let r = sqlx::query(&format!("SELECT {P_COLS} FROM dav_principals WHERE id = $1")).bind(id).fetch_optional(&self.pool).await?;
        r.as_ref().map(principal_from).transpose()
    }
    pub async fn dav_principal_for_account(&self, account_id: i64) -> Result<Option<Principal>> {
        let r = sqlx::query(&format!("SELECT {P_COLS} FROM dav_principals WHERE account_id = $1")).bind(account_id).fetch_optional(&self.pool).await?;
        r.as_ref().map(principal_from).transpose()
    }
    pub async fn create_dav_principal(&self, username: &str, account_id: Option<i64>, password_hash: &str, display: &str, email: &str, quota: i64) -> Result<i64> {
        let _g = self.wl().await;
        let r = sqlx::query(
            "INSERT INTO dav_principals (username, account_id, password_hash, display_name, email, quota_bytes, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id",
        )
        .bind(username.to_ascii_lowercase())
        .bind(account_id)
        .bind(password_hash)
        .bind(display)
        .bind(email)
        .bind(quota)
        .bind(now())
        .fetch_one(&self.pool)
        .await?;
        Ok(r.get(0))
    }
    pub async fn update_dav_principal(&self, p: &Principal) -> Result<()> {
        let _g = self.wl().await;
        sqlx::query("UPDATE dav_principals SET account_id=$1, password_hash=$2, display_name=$3, email=$4, quota_bytes=$5, active=$6 WHERE id=$7")
            .bind(p.account_id)
            .bind(&p.password_hash)
            .bind(&p.display_name)
            .bind(&p.email)
            .bind(p.quota_bytes)
            .bind(p.active as i64)
            .bind(p.id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
    pub async fn delete_dav_principal(&self, id: i64) -> Result<Vec<(String, String)>> {
        let blobs: Vec<(String, String)> = sqlx::query("SELECT path, blob FROM dav_nodes WHERE principal_id = $1 AND blob <> ''")
            .bind(id)
            .fetch_all(&self.pool)
            .await?
            .iter()
            .map(|r| (r.get::<String, _>(0), r.get::<String, _>(1)))
            .collect();
        let mut tx = self.begin().await?;
        sqlx::query("DELETE FROM dav_changes WHERE collection_id IN (SELECT id FROM dav_nodes WHERE principal_id = $1)").bind(id).execute(&mut *tx.tx).await?;
        sqlx::query("DELETE FROM dav_nodes WHERE principal_id = $1").bind(id).execute(&mut *tx.tx).await?;
        sqlx::query("DELETE FROM dav_locks WHERE principal_id = $1").bind(id).execute(&mut *tx.tx).await?;
        sqlx::query("DELETE FROM dav_principals WHERE id = $1").bind(id).execute(&mut *tx.tx).await?;
        tx.commit().await?;
        Ok(blobs)
    }
    async fn dav_usage(&self, id: i64, delta: i64) -> Result<()> {
        let _g = self.wl().await;
        sqlx::query("UPDATE dav_principals SET used_bytes = CASE WHEN used_bytes + $1 < 0 THEN 0 ELSE used_bytes + $1 END WHERE id = $2")
            .bind(delta)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

/// The principal of a mail account, created on first use when enabled.
pub async fn principal_for_account(state: &State, acc: &crate::db::Account) -> Result<Option<Principal>> {
    if let Some(p) = state.db.dav_principal_for_account(acc.id).await? {
        return Ok(Some(p));
    }
    let s = state.settings().dav.clone();
    if !s.mail_accounts {
        return Ok(None);
    }
    let quota = (s.default_quota_mb as i64) * 1024 * 1024;
    if state.db.dav_principal(&acc.email).await?.is_some() {
        // A standalone principal already uses this name.
        return Ok(None);
    }
    state.db.create_dav_principal(&acc.email, Some(acc.id), "", &acc.display_name, &acc.email, quota).await?;
    let p = state.db.dav_principal_for_account(acc.id).await?;
    if let Some(p) = &p {
        ensure_homes(state, p).await?;
    }
    Ok(p)
}

// ------------------------------------------------------------------ nodes

#[derive(Debug, Clone)]
pub struct Node {
    pub id: i64,
    pub principal_id: i64,
    pub path: String,
    pub parent: String,
    pub collection: bool,
    pub kind: String,
    pub blob: String,
    pub size: i64,
    pub etag: String,
    pub ctype: String,
    pub props: Map<String, Value>,
    pub uid: String,
    pub comp: String,
    pub dtstart: Option<i64>,
    pub dtend: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
}

impl Node {
    pub fn name(&self) -> &str {
        self.path.rsplit('/').next().unwrap_or("")
    }
    pub fn section(&self) -> &str {
        self.path.split('/').next().unwrap_or("")
    }
    pub fn is_calendar(&self) -> bool {
        self.kind == "calendar"
    }
    pub fn is_addressbook(&self) -> bool {
        self.kind == "addressbook"
    }
    pub fn is_home(&self) -> bool {
        self.kind.ends_with("-home")
    }
    pub fn prop_str(&self, k: &str) -> Option<String> {
        self.props.get(k).and_then(|v| v.as_str()).map(|s| s.to_string())
    }
}

const N_COLS: &str = "id, principal_id, path, parent, collection, kind, blob, size, etag, ctype, props, uid, comp, dtstart, dtend, created_at, updated_at";

fn node_from(r: &sqlx::any::AnyRow) -> Result<Node> {
    let props: String = r.try_get("props")?;
    Ok(Node {
        id: r.try_get("id")?,
        principal_id: r.try_get("principal_id")?,
        path: r.try_get("path")?,
        parent: r.try_get("parent")?,
        collection: r.try_get::<i64, _>("collection")? != 0,
        kind: r.try_get("kind")?,
        blob: r.try_get("blob")?,
        size: r.try_get("size")?,
        etag: r.try_get("etag")?,
        ctype: r.try_get("ctype")?,
        props: serde_json::from_str(&props).unwrap_or_default(),
        uid: r.try_get("uid")?,
        comp: r.try_get("comp")?,
        dtstart: r.try_get("dtstart")?,
        dtend: r.try_get("dtend")?,
        created_at: r.try_get("created_at")?,
        updated_at: r.try_get("updated_at")?,
    })
}

fn parent_of(path: &str) -> String {
    path.rsplit_once('/').map(|(p, _)| p.to_string()).unwrap_or_default()
}

pub struct NewNode<'a> {
    pub path: &'a str,
    pub collection: bool,
    pub kind: &'a str,
    pub blob: &'a str,
    pub size: i64,
    pub etag: &'a str,
    pub ctype: &'a str,
    pub props: &'a Map<String, Value>,
    pub uid: &'a str,
    pub comp: &'a str,
    pub dtstart: Option<i64>,
    pub dtend: Option<i64>,
}

impl crate::db::Db {
    pub async fn dav_node(&self, principal: i64, path: &str) -> Result<Option<Node>> {
        let r = sqlx::query(&format!("SELECT {N_COLS} FROM dav_nodes WHERE principal_id = $1 AND path = $2")).bind(principal).bind(path).fetch_optional(&self.pool).await?;
        r.as_ref().map(node_from).transpose()
    }
    pub async fn dav_node_by_id(&self, principal: i64, id: i64) -> Result<Option<Node>> {
        let r = sqlx::query(&format!("SELECT {N_COLS} FROM dav_nodes WHERE principal_id = $1 AND id = $2")).bind(principal).bind(id).fetch_optional(&self.pool).await?;
        r.as_ref().map(node_from).transpose()
    }
    pub async fn dav_children(&self, principal: i64, parent: &str) -> Result<Vec<Node>> {
        let rows = sqlx::query(&format!("SELECT {N_COLS} FROM dav_nodes WHERE principal_id = $1 AND parent = $2 ORDER BY path")).bind(principal).bind(parent).fetch_all(&self.pool).await?;
        rows.iter().map(node_from).collect()
    }
    /// The node and everything below it.
    pub async fn dav_subtree(&self, principal: i64, path: &str) -> Result<Vec<Node>> {
        let rows = sqlx::query(&format!("SELECT {N_COLS} FROM dav_nodes WHERE principal_id = $1 AND (path = $2 OR path LIKE $3 ESCAPE '\\') ORDER BY path"))
            .bind(principal)
            .bind(path)
            .bind(format!("{}/%", like_escape(path)))
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(node_from).filter(|n| n.as_ref().map(|n| n.path == path || n.path.starts_with(&format!("{path}/"))).unwrap_or(true)).collect()
    }
    pub async fn dav_by_uid(&self, principal: i64, parent: &str, uid: &str) -> Result<Option<Node>> {
        let r = sqlx::query(&format!("SELECT {N_COLS} FROM dav_nodes WHERE principal_id = $1 AND parent = $2 AND uid = $3")).bind(principal).bind(parent).bind(uid).fetch_optional(&self.pool).await?;
        r.as_ref().map(node_from).transpose()
    }
    /// Insert or replace a node; returns its id.
    pub async fn dav_put(&self, principal: i64, n: &NewNode<'_>) -> Result<i64> {
        let _g = self.wl().await;
        let t = now();
        sqlx::query(
            "INSERT INTO dav_nodes (principal_id, path, parent, collection, kind, blob, size, etag, ctype, props, uid, comp, dtstart, dtend, created_at, updated_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$15)
             ON CONFLICT (principal_id, path) DO UPDATE SET collection = excluded.collection, kind = excluded.kind, blob = excluded.blob,
             size = excluded.size, etag = excluded.etag, ctype = excluded.ctype, props = excluded.props, uid = excluded.uid, comp = excluded.comp,
             dtstart = excluded.dtstart, dtend = excluded.dtend, updated_at = excluded.updated_at",
        )
        .bind(principal)
        .bind(n.path)
        .bind(parent_of(n.path))
        .bind(n.collection as i64)
        .bind(n.kind)
        .bind(n.blob)
        .bind(n.size)
        .bind(n.etag)
        .bind(n.ctype)
        .bind(Value::Object(n.props.clone()).to_string())
        .bind(n.uid)
        .bind(n.comp)
        .bind(n.dtstart)
        .bind(n.dtend)
        .bind(t)
        .execute(&self.pool)
        .await?;
        let r = sqlx::query("SELECT id FROM dav_nodes WHERE principal_id = $1 AND path = $2").bind(principal).bind(n.path).fetch_one(&self.pool).await?;
        Ok(r.get(0))
    }
    pub async fn dav_set_props(&self, id: i64, props: &Map<String, Value>) -> Result<()> {
        let _g = self.wl().await;
        sqlx::query("UPDATE dav_nodes SET props = $1, updated_at = $2 WHERE id = $3").bind(Value::Object(props.clone()).to_string()).bind(now()).bind(id).execute(&self.pool).await?;
        Ok(())
    }
    pub async fn dav_delete(&self, principal: i64, path: &str) -> Result<Vec<Node>> {
        let nodes = self.dav_subtree(principal, path).await?;
        let mut tx = self.begin().await?;
        for n in &nodes {
            sqlx::query("DELETE FROM dav_nodes WHERE id = $1").bind(n.id).execute(&mut *tx.tx).await?;
            if n.collection {
                sqlx::query("DELETE FROM dav_changes WHERE collection_id = $1").bind(n.id).execute(&mut *tx.tx).await?;
            }
        }
        tx.commit().await?;
        Ok(nodes)
    }
    /// Record a change in a collection; returns the new sync token number.
    pub async fn dav_change(&self, collection_id: i64, name: &str, deleted: bool) -> Result<i64> {
        let _g = self.wl().await;
        let r = sqlx::query("INSERT INTO dav_changes (collection_id, name, deleted, ts) VALUES ($1, $2, $3, $4) RETURNING id")
            .bind(collection_id)
            .bind(name)
            .bind(deleted as i64)
            .bind(now())
            .fetch_one(&self.pool)
            .await?;
        Ok(r.get(0))
    }
    pub async fn dav_sync_token(&self, collection_id: i64) -> Result<i64> {
        let r = sqlx::query("SELECT COALESCE(MAX(id), 0) FROM dav_changes WHERE collection_id = $1").bind(collection_id).fetch_one(&self.pool).await?;
        Ok(r.try_get::<i64, _>(0).unwrap_or(0))
    }
    /// Changes after `since`: (name, deleted) with the latest state per name.
    pub async fn dav_changes_since(&self, collection_id: i64, since: i64) -> Result<Vec<(String, bool)>> {
        let rows = sqlx::query("SELECT name, deleted FROM dav_changes WHERE collection_id = $1 AND id > $2 ORDER BY id").bind(collection_id).bind(since).fetch_all(&self.pool).await?;
        let mut latest: indexmap_lite::Map = Default::default();
        for r in rows {
            latest.insert(r.get::<String, _>(0), r.get::<i64, _>(1) != 0);
        }
        Ok(latest.into_vec())
    }
    pub async fn dav_oldest_change(&self, collection_id: i64) -> Result<i64> {
        let r = sqlx::query("SELECT COALESCE(MIN(id), 0) FROM dav_changes WHERE collection_id = $1").bind(collection_id).fetch_one(&self.pool).await?;
        Ok(r.try_get::<i64, _>(0).unwrap_or(0))
    }
}

/// Insertion-ordered map without an extra dependency.
mod indexmap_lite {
    #[derive(Default)]
    pub struct Map {
        keys: Vec<String>,
        vals: std::collections::HashMap<String, bool>,
    }
    impl Map {
        pub fn insert(&mut self, k: String, v: bool) {
            if self.vals.insert(k.clone(), v).is_none() {
                self.keys.push(k);
            }
        }
        pub fn into_vec(mut self) -> Vec<(String, bool)> {
            self.keys.into_iter().map(|k| {
                let v = self.vals.remove(&k).unwrap_or(false);
                (k, v)
            }).collect()
        }
    }
}

fn like_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_")
}

/// Home collections (and default calendar/address book) for a principal.
pub async fn ensure_homes(state: &State, p: &Principal) -> Result<()> {
    let empty = Map::new();
    for (path, kind) in [("calendars", "calendar-home"), ("addressbooks", "addressbook-home"), ("files", "files-home")] {
        if state.db.dav_node(p.id, path).await?.is_none() {
            state.db.dav_put(p.id, &NewNode { path, collection: true, kind, blob: "", size: 0, etag: "", ctype: "", props: &empty, uid: "", comp: "", dtstart: None, dtend: None }).await?;
        }
    }
    if itip::on(state) {
        itip::ensure_inbox(state, p.id).await?;
    }
    if state.settings().dav.create_defaults {
        let mut cal = Map::new();
        cal.insert("displayname".into(), json!("Calendar"));
        cal.insert("components".into(), json!("VEVENT,VTODO"));
        // The inbox and attachments collections don't count as calendars.
        if !state.db.dav_children(p.id, "calendars").await?.iter().any(|c| c.is_calendar()) {
            state.db.dav_put(p.id, &NewNode { path: "calendars/default", collection: true, kind: "calendar", blob: "", size: 0, etag: "", ctype: "", props: &cal, uid: "", comp: "", dtstart: None, dtend: None }).await?;
        }
        let mut ab = Map::new();
        ab.insert("displayname".into(), json!("Contacts"));
        if state.db.dav_children(p.id, "addressbooks").await?.is_empty() {
            state.db.dav_put(p.id, &NewNode { path: "addressbooks/contacts", collection: true, kind: "addressbook", blob: "", size: 0, etag: "", ctype: "", props: &ab, uid: "", comp: "", dtstart: None, dtend: None }).await?;
        }
    }
    Ok(())
}

// ------------------------------------------------------------------ URLs

/// What a request path refers to.
#[derive(Debug, Clone, PartialEq)]
pub enum Target {
    Root,
    Principals,
    Principal(String),
    /// A user's section root listing (e.g. /dav/calendars/) without a user.
    SectionRoot(String),
    /// (user, node path like "calendars/default/x.ics")
    Node(String, String),
}

pub fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or("zz"), 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

pub fn pct_encode(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~@+!$&'()*,;=:".contains(&b) {
            o.push(b as char);
        } else {
            o.push_str(&format!("%{b:02X}"));
        }
    }
    o
}

/// Parse a request path (or Destination URL) into a target.
pub fn target(path: &str) -> Option<Target> {
    let path = match path.find("://") {
        Some(i) => {
            let rest = &path[i + 3..];
            rest.find('/').map(|j| &rest[j..]).unwrap_or("/")
        }
        None => path,
    };
    let path = path.split('?').next().unwrap_or(path);
    if path.contains('#') {
        return None;
    }
    let rest = path.strip_prefix("/dav")?;
    let rest = rest.trim_start_matches('/');
    let segs: Vec<String> = rest.split('/').filter(|s| !s.is_empty()).map(pct_decode).collect();
    if segs.iter().any(|s| s == "." || s == ".." || s.contains('\0')) {
        return None;
    }
    match segs.first().map(|s| s.as_str()) {
        None => Some(Target::Root),
        Some("principals") => match segs.get(1) {
            None => Some(Target::Principals),
            Some(u) if segs.len() == 2 => Some(Target::Principal(u.to_ascii_lowercase())),
            _ => None,
        },
        Some(sec @ ("calendars" | "addressbooks" | "files")) => match segs.get(1) {
            None => Some(Target::SectionRoot(sec.to_string())),
            Some(u) => {
                let mut p = sec.to_string();
                for s in &segs[2..] {
                    p.push('/');
                    p.push_str(s);
                }
                Some(Target::Node(u.to_ascii_lowercase(), p))
            }
        },
        _ => None,
    }
}

pub fn href_node(user: &str, path: &str, collection: bool) -> String {
    let mut parts = path.split('/');
    let section = parts.next().unwrap_or("files");
    let mut h = format!("/dav/{section}/{}/", pct_encode(user));
    let rest: Vec<String> = parts.map(pct_encode).collect();
    if !rest.is_empty() {
        h.push_str(&rest.join("/"));
        if collection {
            h.push('/');
        }
    }
    h
}

pub fn href_principal(user: &str) -> String {
    format!("/dav/principals/{}/", pct_encode(user))
}

// ------------------------------------------------------------------ responses

pub fn status_line(code: StatusCode) -> String {
    format!("HTTP/1.1 {} {}", code.as_u16(), code.canonical_reason().unwrap_or(""))
}

pub fn xml_response(code: StatusCode, body: String) -> Response {
    let mut r = (code, body).into_response();
    r.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/xml; charset=utf-8"));
    r
}

pub fn empty(code: StatusCode) -> Response {
    let mut r = code.into_response();
    if code != StatusCode::NO_CONTENT && code != StatusCode::NOT_MODIFIED {
        r.headers_mut().insert(header::CONTENT_LENGTH, HeaderValue::from_static("0"));
    }
    r
}

/// An error response with a precondition element (RFC 4918 16).
pub fn precondition(code: StatusCode, ns: &str, name: &str) -> Response {
    let mut w = crate::xml::Writer::new().prefix("D", DAV).prefix("C", CALDAV).prefix("CR", CARDDAV);
    w.open(DAV, "error");
    w.empty(ns, name);
    w.close(DAV, "error");
    xml_response(code, w.finish())
}

fn unauthorized(state: &State) -> Response {
    let realm = state.settings().branding.name.clone().unwrap_or_else(|| "Picacho Server".into()).replace('"', "");
    let mut r = empty(StatusCode::UNAUTHORIZED);
    r.headers_mut().insert(header::WWW_AUTHENTICATE, HeaderValue::from_str(&format!("Basic realm=\"{realm}\", charset=\"UTF-8\"")).unwrap_or(HeaderValue::from_static("Basic")));
    r
}

// ------------------------------------------------------------------ auth

pub struct Ctx {
    pub state: State,
    pub principal: Principal,
    pub read_only: bool,
    pub base: String,
}

fn secure(state: &State, headers: &HeaderMap, peer: SocketAddr) -> bool {
    let sec = state.settings().security.clone();
    state.config.web.tls
        || headers.get("x-forwarded-proto").and_then(|v| v.to_str().ok()) == Some("https") && crate::util::ip_in_list(peer.ip(), &state.config.web.trusted_proxies)
        || !sec.require_tls_for_auth
        || (sec.allow_plaintext_localhost && crate::util::is_loopback(peer.ip()))
}

/// What a credential may do: everything (`None`, a password) or what its
/// token scopes allow, per section.
type Grant = Option<String>;

async fn authenticate(state: &State, headers: &HeaderMap, peer: SocketAddr) -> Result<(Principal, bool, Grant), Response> {
    use crate::auth::{access, Access, Service};
    let auth = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).unwrap_or("");
    if let Some(t) = auth.strip_prefix("Bearer ").map(str::trim) {
        let Some(p) = crate::auth::bearer_principal(state, t).await else { return Err(unauthorized(state)) };
        let lvl = access(&p.scopes, Service::Dav);
        if lvl == Access::None {
            return Err(empty(StatusCode::FORBIDDEN));
        }
        let Ok(Some(pr)) = principal_for_account(state, &p.account).await else { return Err(empty(StatusCode::FORBIDDEN)) };
        return Ok((pr, lvl == Access::Read, Some(p.scopes)));
    }
    let Some(b) = auth.strip_prefix("Basic ") else { return Err(unauthorized(state)) };
    if !secure(state, headers, peer) {
        return Err((StatusCode::FORBIDDEN, "Basic authentication requires HTTPS.").into_response());
    }
    use base64::Engine;
    let decoded = base64::engine::general_purpose::STANDARD.decode(b.trim()).map_err(|_| unauthorized(state))?;
    let s = String::from_utf8_lossy(&decoded).to_string();
    let (user, pass) = s.split_once(':').ok_or_else(|| unauthorized(state))?;
    let ip = peer.ip();
    let sec = state.settings().security.clone();
    let allow = crate::util::ip_in_list(ip, &sec.allowlist);
    if !allow && state.limiter.is_banned(ip) {
        return Err(empty(StatusCode::TOO_MANY_REQUESTS));
    }
    // A principal's own DAV password (standalone or linked).
    if let Ok(Some(p)) = state.db.dav_principal(user).await {
        if !p.password_hash.is_empty() && p.active {
            let (h, pw) = (p.password_hash.clone(), pass.to_string());
            let ok = tokio::task::spawn_blocking(move || crate::auth::verify_password(&pw, &h)).await.unwrap_or(false);
            if ok {
                state.limiter.success(ip);
                return Ok((p, false, None));
            }
            if p.account_id.is_none() {
                crate::metrics::AUTH_FAILURES.inc();
                if !allow {
                    state.limiter.fail(ip, sec.max_auth_failures, sec.auth_failure_window_secs, sec.ban_secs);
                }
                return Err(unauthorized(state));
            }
        }
    }
    let token = crate::auth::is_token(pass);
    match crate::auth::login_service(state, user, pass, ip, Service::Dav).await {
        Ok((acc, lvl)) => match principal_for_account(state, &acc).await {
            // A token used as the password keeps its per-section limits.
            Ok(Some(p)) if p.active && token => match crate::auth::bearer_principal(state, pass).await {
                Some(b) => Ok((p, lvl == Access::Read, Some(b.scopes))),
                None => Err(unauthorized(state)),
            },
            Ok(Some(p)) if p.active => Ok((p, lvl == Access::Read, None)),
            _ => Err(empty(StatusCode::FORBIDDEN)),
        },
        Err(crate::auth::AuthError::Banned) => Err(empty(StatusCode::TOO_MANY_REQUESTS)),
        Err(_) => Err(unauthorized(state)),
    }
}

// ------------------------------------------------------------------ routing

pub fn routes(state: State) -> Router {
    let max = state.settings().dav.max_resource_bytes.min(4 * 1024 * 1024 * 1024) as usize;
    Router::new()
        .route("/.well-known/caldav", axum::routing::any(well_known))
        .route("/.well-known/caldav/", axum::routing::any(well_known))
        .route("/.well-known/carddav", axum::routing::any(well_known))
        .route("/.well-known/carddav/", axum::routing::any(well_known))
        .route("/dav", axum::routing::any(handle))
        .route("/dav/", axum::routing::any(handle))
        .route("/dav/{*rest}", axum::routing::any(handle))
        .layer(axum::extract::DefaultBodyLimit::max(max))
        .with_state(state)
}

async fn well_known() -> Response {
    (StatusCode::MOVED_PERMANENTLY, [(header::LOCATION, "/dav/")]).into_response()
}

pub const ALLOW: &str = "OPTIONS, GET, HEAD, PUT, DELETE, PROPFIND, PROPPATCH, MKCOL, MKCALENDAR, COPY, MOVE, LOCK, UNLOCK, REPORT, POST";

fn options(state: &State) -> Response {
    let mut r = empty(StatusCode::OK);
    let h = r.headers_mut();
    // calendar-auto-schedule only when the server sends invitations itself:
    // clients then stop emailing them.
    let classes = if itip::on(state) {
        "1, 2, 3, access-control, calendar-access, calendar-auto-schedule, addressbook, extended-mkcol, calendar-managed-attachments"
    } else {
        "1, 2, 3, access-control, calendar-access, addressbook, extended-mkcol, calendar-managed-attachments"
    };
    h.insert("DAV", HeaderValue::from_static(classes));
    h.insert(header::ALLOW, HeaderValue::from_static(ALLOW));
    h.insert("MS-Author-Via", HeaderValue::from_static("DAV"));
    r
}

async fn handle(AxState(state): AxState<State>, ConnectInfo(peer): ConnectInfo<SocketAddr>, req: Request<Body>) -> Response {
    crate::metrics::DAV_REQUESTS.inc();
    if !state.settings().dav.enabled {
        return empty(StatusCode::NOT_FOUND);
    }
    let method = req.method().clone();
    if method == Method::OPTIONS {
        return options(&state);
    }
    let headers = req.headers().clone();
    let path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or("").to_string();
    let (principal, mut read_only, grant) = match authenticate(&state, &headers, peer).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    let base = crate::jmap::base_url(&state, &headers);
    let max = state.settings().dav.max_resource_bytes as usize;
    let body = match axum::body::to_bytes(req.into_body(), max).await {
        Ok(b) => b,
        Err(_) => return empty(StatusCode::PAYLOAD_TOO_LARGE),
    };
    let Some(t) = target(&path) else { return empty(StatusCode::NOT_FOUND) };
    // Scoped tokens reach only the sections they were granted (an app with
    // calendar access can't read contacts or files).
    if let Some(scopes) = &grant {
        use crate::auth::{dav_access, Access};
        let sections = |t: &Target| -> Vec<String> {
            match t {
                Target::SectionRoot(s) => vec![s.clone()],
                Target::Node(_, p) => vec![p.split('/').next().unwrap_or("").to_string()],
                _ => vec![],
            }
        };
        let mut secs = sections(&t);
        if matches!(method.as_str(), "COPY" | "MOVE") {
            if let Some(d) = headers.get("destination").and_then(|v| v.to_str().ok()).and_then(target) {
                secs.extend(sections(&d));
            }
        }
        let lvl = if secs.is_empty() {
            // Root and principals: readable with any DAV access, never writable.
            Access::Read
        } else {
            secs.iter().map(|s| dav_access(scopes, s)).min().unwrap_or(Access::None)
        };
        if lvl == Access::None {
            return precondition(StatusCode::FORBIDDEN, DAV, "need-privileges");
        }
        read_only = read_only || lvl == Access::Read;
    }
    let ctx = Ctx { state, principal, read_only, base };
    let writes = !matches!(method.as_str(), "GET" | "HEAD" | "PROPFIND" | "REPORT" | "OPTIONS");
    if writes && ctx.read_only {
        return precondition(StatusCode::FORBIDDEN, DAV, "need-privileges");
    }
    if let Err(e) = ensure_homes(&ctx.state, &ctx.principal).await {
        tracing::warn!("dav homes: {e:#}");
    }
    // A managed attachment can be read by anyone signed in here (its name
    // is random): the event's other attendees follow its link.
    if let Target::Node(u, p) = &t {
        if u != &ctx.principal.username && matches!(method.as_str(), "GET" | "HEAD") && attach::touches(p) && p != attach::COLLECTION {
            let Ok(Some(owner)) = ctx.state.db.dav_principal(u).await else { return empty(StatusCode::NOT_FOUND) };
            let octx = Ctx { state: ctx.state.clone(), principal: owner, read_only: true, base: ctx.base.clone() };
            return match get(&octx, &t, &headers, method == Method::HEAD).await {
                Ok(r) => r,
                Err(_) => empty(StatusCode::INTERNAL_SERVER_ERROR),
            };
        }
    }
    // Attachment files change only through their events (RFC 8607).
    if writes && !matches!(method.as_str(), "POST" | "LOCK" | "UNLOCK") {
        let dest = headers.get("destination").and_then(|v| v.to_str().ok()).and_then(target);
        if [Some(&t), dest.as_ref()].into_iter().flatten().any(|x| matches!(x, Target::Node(_, p) if attach::touches(p))) {
            return precondition(StatusCode::FORBIDDEN, DAV, "need-privileges");
        }
        // The scheduling inbox is filled by the server; clients only delete from it.
        let inbox = |x: &Target| {
            matches!(x, Target::Node(_, p) if (p == itip::INBOX && method.as_str() != "PROPPATCH") || (p.starts_with(&format!("{}/", itip::INBOX)) && method != Method::DELETE))
        };
        if [Some(&t), dest.as_ref()].into_iter().flatten().any(inbox) {
            return precondition(StatusCode::FORBIDDEN, DAV, "need-privileges");
        }
    }
    // Only one's own data is reachable.
    if let Target::Node(u, _) | Target::Principal(u) = &t {
        if u != &ctx.principal.username {
            return empty(if ctx.state.db.dav_principal(u).await.ok().flatten().is_some() { StatusCode::FORBIDDEN } else { StatusCode::NOT_FOUND });
        }
    }
    // The contact directory is read-only, whatever the grant.
    if writes && directory::touches(&ctx, &t, &headers).await {
        return precondition(StatusCode::FORBIDDEN, DAV, "need-privileges");
    }
    let r = match method.as_str() {
        "PROPFIND" => props::propfind(&ctx, &t, &headers, &body).await,
        "PROPPATCH" => props::proppatch(&ctx, &t, &headers, &body).await,
        "REPORT" => report::report(&ctx, &t, &headers, &body).await,
        "LOCK" => locks::lock(&ctx, &t, &headers, &body).await,
        "UNLOCK" => locks::unlock(&ctx, &t, &headers).await,
        "GET" | "HEAD" => get(&ctx, &t, &headers, method == Method::HEAD).await,
        "PUT" => put(&ctx, &t, &headers, body).await,
        "DELETE" => delete(&ctx, &t, &headers).await,
        "MKCOL" => mkcol(&ctx, &t, &headers, &body, false).await,
        "MKCALENDAR" => mkcol(&ctx, &t, &headers, &body, true).await,
        "COPY" | "MOVE" => copy_move(&ctx, &t, &headers, method.as_str() == "MOVE").await,
        "POST" if matches!(&t, Target::Node(_, p) if p == schedule::OUTBOX) => schedule::outbox_post(&ctx, &headers, &body).await,
        "POST" if query.contains("action=attachment-") => match &t {
            Target::Node(u, p) => attach::post(&ctx, u, p, &query, &headers, &body).await,
            _ => Ok(empty(StatusCode::NOT_FOUND)),
        },
        "POST" => Ok(empty(StatusCode::METHOD_NOT_ALLOWED)),
        _ => Ok(empty(StatusCode::METHOD_NOT_ALLOWED)),
    };
    match r {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("dav {method} {path}: {e:#}");
            empty(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

// ------------------------------------------------------------------ store API (JMAP)

/// Calendars and address books as JMAP for Calendars/Contacts sees them:
/// the same collections and resources CalDAV and CardDAV serve.
pub mod store {
    use super::*;

    /// The account's DAV principal, with its homes (None: DAV is off for it).
    pub async fn principal(state: &State, acc: &crate::db::Account) -> Result<Option<Principal>> {
        if !state.settings().dav.enabled {
            return Ok(None);
        }
        let Some(p) = principal_for_account(state, acc).await?.filter(|p| p.active) else { return Ok(None) };
        ensure_homes(state, &p).await?;
        Ok(Some(p))
    }

    /// Store (create or replace) a calendar or vCard resource. Err(reason)
    /// when it isn't valid there, or doesn't fit the quota.
    pub async fn put(state: &State, p: &Principal, path: &str, body: &[u8]) -> Result<std::result::Result<Node, String>> {
        let ctx = Ctx { state: state.clone(), principal: p.clone(), read_only: false, base: String::new() };
        let parent_path = parent_of(path);
        let Some(parent) = state.db.dav_node(p.id, &parent_path).await? else { return Ok(Err("No such collection".into())) };
        if !(parent.is_calendar() || parent.is_addressbook()) {
            return Ok(Err("Not a calendar or address book".into()));
        }
        let existing = state.db.dav_node(p.id, path).await?;
        let ctype = if parent.is_calendar() { "text/calendar" } else { "text/vcard" };
        let meta = match validate_content(&ctx, &p.username, &parent, path, ctype, body, existing.as_ref()).await? {
            Ok(m) => m,
            Err(r) => return Ok(Err(format!("Refused by the calendar rules ({})", r.status()))),
        };
        let old_size = existing.as_ref().map(|n| n.size).unwrap_or(0);
        let used = state.db.dav_principal_by_id(p.id).await?.map(|x| x.used_bytes).unwrap_or(0);
        if p.quota_bytes > 0 && used - old_size + body.len() as i64 > p.quota_bytes {
            return Ok(Err("overQuota".into()));
        }
        let section = path.split('/').next().unwrap_or("calendars").to_string();
        let key = write_blob(state, &section, body).await?;
        let etag = etag_of(body);
        let props = existing.as_ref().map(|n| n.props.clone()).unwrap_or_default();
        let ContentMeta { uid, comp, dtstart, dtend, ctype } = meta;
        state.db.dav_put(p.id, &NewNode { path, collection: false, kind: "", blob: &key, size: body.len() as i64, etag: &etag, ctype: &ctype, props: &props, uid: &uid, comp: &comp, dtstart, dtend }).await?;
        if let Some(old) = &existing {
            delete_blob(state, &section, &old.blob).await;
        }
        state.db.dav_usage(p.id, body.len() as i64 - old_size).await?;
        record_change(state, p.id, path, false).await;
        Ok(Ok(state.db.dav_node(p.id, path).await?.ok_or_else(|| anyhow::anyhow!("stored node vanished"))?))
    }

    /// Remove a resource or a whole collection.
    pub async fn delete(state: &State, p: &Principal, path: &str) -> Result<bool> {
        let Some(n) = state.db.dav_node(p.id, path).await? else { return Ok(false) };
        if n.is_home() {
            return Ok(false);
        }
        let ctx = Ctx { state: state.clone(), principal: p.clone(), read_only: false, base: String::new() };
        remove_tree(&ctx, path).await?;
        if n.section() == "calendars" {
            attach::sweep(&ctx).await?;
        }
        Ok(true)
    }

    /// Make a calendar ("calendar") or address book ("addressbook").
    pub async fn make_collection(state: &State, p: &Principal, path: &str, kind: &str, props: &Map<String, Value>) -> Result<()> {
        state.db.dav_put(p.id, &NewNode { path, collection: true, kind, blob: "", size: 0, etag: "", ctype: "", props, uid: "", comp: "", dtstart: None, dtend: None }).await?;
        record_change(state, p.id, path, false).await;
        Ok(())
    }

    pub async fn read(state: &State, n: &Node) -> Result<String> {
        Ok(String::from_utf8_lossy(&read_blob(state, n).await?).into_owned())
    }
}

// ------------------------------------------------------------------ helpers

fn etag_of(data: &[u8]) -> String {
    format!("\"{}\"", &crate::util::sha256_hex(data)[..32])
}

pub async fn read_blob(state: &State, n: &Node) -> Result<Vec<u8>> {
    if let Some(c) = directory::content(n) {
        return Ok(c);
    }
    if n.blob.is_empty() {
        return Ok(vec![]);
    }
    let raw = state.dav.for_section(n.section()).get_raw(&n.blob).await?;
    state.blobs.open_bytes(raw)
}

async fn write_blob(state: &State, section: &str, data: &[u8]) -> Result<String> {
    let key = format!("dav-{}", uuid::Uuid::new_v4().simple());
    state.dav.for_section(section).put_raw(&key, state.blobs.seal_bytes(data)).await?;
    Ok(key)
}

async fn delete_blob(state: &State, section: &str, key: &str) {
    if key.is_empty() {
        return;
    }
    let b = state.dav.for_section(section);
    let r = if is_db(b) {
        state.db.blob_delete(key).await
    } else {
        b.delete_raw(key).await
    };
    if let Err(e) = r {
        tracing::debug!("dav blob delete {key}: {e}");
    }
}

/// The nearest collection that tracks changes for a resource.
async fn change_collection(state: &State, principal: i64, parent: &str) -> Option<Node> {
    state.db.dav_node(principal, parent).await.ok().flatten().filter(|n| n.collection)
}

pub async fn record_change(state: &State, principal: i64, path: &str, deleted: bool) {
    let parent = parent_of(path);
    if let Some(c) = change_collection(state, principal, &parent).await {
        let name = path.rsplit('/').next().unwrap_or("");
        let _ = state.db.dav_change(c.id, name, deleted).await;
    }
    if !deleted {
        if let Ok(Some(n)) = state.db.dav_node(principal, path).await {
            jmap_change(state, principal, &n, "u").await;
        }
    }
}

/// The JMAP kind and id prefix for a DAV node (JMAP Calendars/Contacts).
pub fn jmap_kind(n: &Node) -> Option<&'static str> {
    match (n.collection, n.kind.as_str(), n.section()) {
        (true, "calendar", _) => Some("Calendar"),
        (true, "addressbook", _) => Some("AddressBook"),
        (false, _, "calendars") => Some("CalendarEvent"),
        (false, _, "addressbooks") => Some("ContactCard"),
        _ => None,
    }
}

/// Note a DAV change in the linked account's JMAP change log.
pub async fn jmap_change(state: &State, principal: i64, n: &Node, op: &str) {
    let Some(kind) = jmap_kind(n) else { return };
    let Ok(Some(p)) = state.db.dav_principal_by_id(principal).await else { return };
    let Some(acc) = p.account_id else { return };
    let op = if op == "u" && n.created_at == n.updated_at { "c" } else { op };
    let _ = state.db.log_jmap_change(acc, kind, n.id, op).await;
}

fn header_str<'a>(h: &'a HeaderMap, k: &str) -> Option<&'a str> {
    h.get(k).and_then(|v| v.to_str().ok())
}

/// If-Match / If-None-Match against the current etag (None: no resource).
fn check_conditional(h: &HeaderMap, etag: Option<&str>) -> Option<StatusCode> {
    if let Some(m) = header_str(h, "if-match") {
        let ok = match etag {
            Some(e) => m.trim() == "*" || m.split(',').any(|x| x.trim().trim_start_matches("W/") == e),
            None => false,
        };
        if !ok {
            return Some(StatusCode::PRECONDITION_FAILED);
        }
    }
    if let Some(m) = header_str(h, "if-none-match") {
        let hit = match etag {
            Some(e) => m.trim() == "*" || m.split(',').any(|x| x.trim().trim_start_matches("W/") == e),
            None => false,
        };
        if hit {
            return Some(StatusCode::PRECONDITION_FAILED);
        }
    }
    None
}

// ------------------------------------------------------------------ methods

async fn get(ctx: &Ctx, t: &Target, h: &HeaderMap, head: bool) -> Result<Response> {
    let Target::Node(user, path) = t else {
        let body = format!("<!doctype html><title>DAV</title><p>Signed in as {}. Use a CalDAV, CardDAV or WebDAV client with <code>{}/dav/</code>.</p>", crate::xml::escape(&ctx.principal.username), crate::xml::escape(&ctx.base));
        return Ok(([(header::CONTENT_TYPE, "text/html; charset=utf-8")], if head { String::new() } else { body }).into_response());
    };
    if directory::is_dir_path(path) && directory::active(ctx).await? {
        return directory::get(ctx, path, h, head).await;
    }
    let Some(n) = ctx.state.db.dav_node(ctx.principal.id, path).await? else { return Ok(empty(StatusCode::NOT_FOUND)) };
    if n.collection {
        return get_collection(ctx, user, &n, h, head).await;
    }
    if header_str(h, "if-none-match").is_none() && not_modified_since(h, n.updated_at) {
        let mut r = empty(StatusCode::NOT_MODIFIED);
        r.headers_mut().insert(header::ETAG, HeaderValue::from_str(&n.etag)?);
        return Ok(r);
    }
    if let Some(m) = header_str(h, "if-none-match") {
        if m.split(',').any(|x| x.trim() == n.etag || x.trim() == "*") {
            let mut r = empty(StatusCode::NOT_MODIFIED);
            r.headers_mut().insert(header::ETAG, HeaderValue::from_str(&n.etag)?);
            return Ok(r);
        }
    }
    let data = if head { vec![] } else { read_blob(&ctx.state, &n).await? };
    let mut r = Response::new(Body::from(data));
    let hd = r.headers_mut();
    hd.insert(header::CONTENT_TYPE, HeaderValue::from_str(if n.ctype.is_empty() { "application/octet-stream" } else { &n.ctype }).unwrap_or(HeaderValue::from_static("application/octet-stream")));
    hd.insert(header::ETAG, HeaderValue::from_str(&n.etag)?);
    hd.insert(header::CONTENT_LENGTH, HeaderValue::from(n.size as u64));
    if let Some(d) = chrono::DateTime::from_timestamp(n.updated_at, 0) {
        hd.insert(header::LAST_MODIFIED, HeaderValue::from_str(&d.format("%a, %d %b %Y %H:%M:%S GMT").to_string())?);
    }
    attach::decorate(&n, &mut r);
    Ok(r)
}

/// If-Modified-Since: true when the resource hasn't changed since.
fn not_modified_since(h: &HeaderMap, modified: i64) -> bool {
    header_str(h, "if-modified-since")
        .and_then(|v| chrono::DateTime::parse_from_rfc2822(v.trim().replace("GMT", "+0000").as_str()).ok())
        .is_some_and(|d| modified <= d.timestamp())
}

fn base_type(ct: &str) -> &str {
    ct.split(';').next().unwrap_or(ct).trim()
}

/// GET on a collection: a calendar as one iCalendar object, an address
/// book as concatenated vCards, anything else as an HTML listing.
async fn get_collection(ctx: &Ctx, user: &str, n: &Node, h: &HeaderMap, head: bool) -> Result<Response> {
    let st = &ctx.state;
    let kids = st.db.dav_children(ctx.principal.id, &n.path).await?;
    let token = st.db.dav_sync_token(n.id).await.unwrap_or(0);
    let etag = format!("\"c{}-{token}\"", n.id);
    let modified = kids.iter().map(|k| k.updated_at).chain(std::iter::once(n.updated_at)).max().unwrap_or(n.updated_at);
    let inm = header_str(h, "if-none-match");
    if inm.is_none() && not_modified_since(h, modified) {
        let mut r = empty(StatusCode::NOT_MODIFIED);
        r.headers_mut().insert(header::ETAG, HeaderValue::from_str(&etag)?);
        return Ok(r);
    }
    if let Some(m) = inm {
        if m.split(',').any(|x| x.trim() == etag || x.trim() == "*") {
            let mut r = empty(StatusCode::NOT_MODIFIED);
            r.headers_mut().insert(header::ETAG, HeaderValue::from_str(&etag)?);
            return Ok(r);
        }
    }
    let (ctype, body) = if n.is_calendar() {
        let mut cal = ical::Comp { name: "VCALENDAR".into(), ..Default::default() };
        cal.props.push(ical::Prop { name: "VERSION".into(), params: vec![], value: "2.0".into() });
        cal.props.push(ical::Prop { name: "PRODID".into(), params: vec![], value: "-//Picacho Server//DAV//EN".into() });
        let name = n.prop_str("displayname").unwrap_or_else(|| n.name().to_string());
        cal.props.push(ical::Prop { name: "X-WR-CALNAME".into(), params: vec![], value: name });
        let mut tzids = std::collections::HashSet::new();
        for k in kids.iter().filter(|k| !k.collection) {
            let Ok(data) = read_blob(st, k).await else { continue };
            let Ok(c) = ical::parse(&String::from_utf8_lossy(&data)) else { continue };
            for comp in c.comps {
                if comp.name == "VTIMEZONE" {
                    let id = comp.prop("TZID").map(|p| p.value.clone()).unwrap_or_default();
                    if !tzids.insert(id) {
                        continue;
                    }
                }
                cal.comps.push(comp);
            }
        }
        // VTIMEZONEs first.
        cal.comps.sort_by_key(|c| c.name != "VTIMEZONE");
        ("text/calendar; charset=utf-8", ical::serialize(&cal))
    } else if n.is_addressbook() {
        let mut out = String::new();
        for k in kids.iter().filter(|k| !k.collection) {
            if let Ok(d) = read_blob(st, k).await {
                out.push_str(&String::from_utf8_lossy(&d));
                if !out.ends_with("\r\n") {
                    out.push_str("\r\n");
                }
            }
        }
        ("text/vcard; charset=utf-8", out)
    } else {
        let title = crate::xml::escape(&href_node(user, &n.path, true));
        let mut html = format!("<!doctype html><meta charset=utf-8><title>{title}</title><h1>{title}</h1><table><tr><th>Name</th><th>Type</th><th>Size</th><th>Last modified</th></tr>");
        for c in &kids {
            let href = href_node(user, &c.path, c.collection);
            let ty = if c.is_calendar() {
                "text/calendar"
            } else if c.is_addressbook() {
                "text/vcard"
            } else if c.collection {
                "httpd/unix-directory"
            } else {
                base_type(&c.ctype)
            };
            html.push_str(&format!(
                "<tr><td><a href=\"{}\">{}{}</a></td><td>{}</td><td>{}</td><td>{}</td></tr>",
                crate::xml::escape(&href),
                crate::xml::escape(c.name()),
                if c.collection { "/" } else { "" },
                ty,
                if c.collection { "-".to_string() } else { c.size.to_string() },
                chrono::DateTime::from_timestamp(c.updated_at, 0).map(|d| d.to_rfc2822()).unwrap_or_default()
            ));
        }
        html.push_str("</table>");
        ("text/html; charset=utf-8", html)
    };
    let len = body.len();
    let mut r = Response::new(Body::from(if head { String::new() } else { body }));
    let hd = r.headers_mut();
    hd.insert(header::CONTENT_TYPE, HeaderValue::from_static(ctype));
    hd.insert(header::ETAG, HeaderValue::from_str(&etag)?);
    hd.insert(header::CONTENT_LENGTH, HeaderValue::from(len as u64));
    if let Some(d) = chrono::DateTime::from_timestamp(modified, 0) {
        hd.insert(header::LAST_MODIFIED, HeaderValue::from_str(&d.format("%a, %d %b %Y %H:%M:%S GMT").to_string())?);
    }
    Ok(r)
}

async fn put(ctx: &Ctx, t: &Target, h: &HeaderMap, body: Bytes) -> Result<Response> {
    let Target::Node(user, path) = t else { return Ok(empty(StatusCode::METHOD_NOT_ALLOWED)) };
    let st = &ctx.state;
    let pid = ctx.principal.id;
    if path.split('/').count() < 2 {
        return Ok(empty(StatusCode::FORBIDDEN));
    }
    let existing = st.db.dav_node(pid, path).await?;
    if existing.as_ref().is_some_and(|n| n.collection) {
        return Ok(empty(StatusCode::FORBIDDEN));
    }
    if let Some(r) = locks::check_write(ctx, user, path, h, false).await? {
        return Ok(r);
    }
    if let Some(code) = check_conditional(h, existing.as_ref().map(|n| n.etag.as_str())) {
        return Ok(empty(code));
    }
    let parent_path = parent_of(path);
    let Some(parent) = st.db.dav_node(pid, &parent_path).await? else { return Ok(empty(StatusCode::CONFLICT)) };
    if !parent.collection {
        return Ok(empty(StatusCode::CONFLICT));
    }
    let max = st.settings().dav.max_resource_bytes;
    if body.len() as u64 > max {
        return Ok(precondition(StatusCode::FORBIDDEN, if parent.is_calendar() { CALDAV } else { CARDDAV }, "max-resource-size"));
    }
    let ctype_in = header_str(h, "content-type").unwrap_or("application/octet-stream").to_string();
    let meta = match validate_content(ctx, user, &parent, path, &ctype_in, &body, existing.as_ref()).await? {
        Ok(m) => m,
        Err(r) => return Ok(r),
    };
    let ContentMeta { uid, comp, dtstart, dtend, ctype } = meta;
    // Implicit scheduling (RFC 6638): may add SCHEDULE-STATUS and SEQUENCE.
    let body: Bytes = if parent.is_calendar() && itip::on(st) {
        let old = match &existing {
            Some(n) => ical::parse(&String::from_utf8_lossy(&read_blob(st, n).await?)).ok(),
            None => None,
        };
        let new = ical::parse(&String::from_utf8_lossy(&body)).ok();
        let no_reply = header_str(h, "schedule-reply").is_some_and(|v| v.trim().eq_ignore_ascii_case("F"));
        match itip::on_change(st, &ctx.principal, itip::Change { old: old.as_ref(), new: new.as_ref(), no_reply }).await {
            Ok(Some(c)) => Bytes::from(ical::serialize(&c)),
            Ok(None) => body,
            Err(e) => {
                tracing::warn!("scheduling {path}: {e:#}");
                body
            }
        }
    } else {
        body
    };
    let old_size = existing.as_ref().map(|n| n.size).unwrap_or(0);
    let quota = ctx.principal.quota_bytes;
    let used = st.db.dav_principal_by_id(pid).await?.map(|p| p.used_bytes).unwrap_or(0);
    if quota > 0 && used - old_size + body.len() as i64 > quota {
        return Ok(precondition(StatusCode::INSUFFICIENT_STORAGE, DAV, "quota-not-exceeded"));
    }
    let section = path.split('/').next().unwrap_or("files").to_string();
    let key = write_blob(st, &section, &body).await?;
    let etag = etag_of(&body);
    let props = existing.as_ref().map(|n| n.props.clone()).unwrap_or_default();
    st.db.dav_put(pid, &NewNode { path, collection: false, kind: "", blob: &key, size: body.len() as i64, etag: &etag, ctype: &ctype, props: &props, uid: &uid, comp: &comp, dtstart, dtend }).await?;
    if let Some(old) = &existing {
        delete_blob(st, &section, &old.blob).await;
    }
    st.db.dav_usage(pid, body.len() as i64 - old_size).await?;
    record_change(st, pid, path, false).await;
    if existing.is_some() && parent.is_calendar() {
        attach::sweep(ctx).await?;
    }
    let mut r = empty(if existing.is_some() { StatusCode::NO_CONTENT } else { StatusCode::CREATED });
    r.headers_mut().insert(header::ETAG, HeaderValue::from_str(&etag)?);
    Ok(r)
}

pub struct ContentMeta {
    pub uid: String,
    pub comp: String,
    pub dtstart: Option<i64>,
    pub dtend: Option<i64>,
    pub ctype: String,
}

/// Check content stored at `path` under `parent` (calendar object and
/// address object rules, UID uniqueness). Err(response) when refused.
pub async fn validate_content(ctx: &Ctx, user: &str, parent: &Node, path: &str, ctype_in: &str, body: &[u8], existing: Option<&Node>) -> Result<Result<ContentMeta, Response>> {
    let st = &ctx.state;
    let pid = ctx.principal.id;
    let parent_path = parent.path.clone();
    let mut ctype = ctype_in.to_string();
    let (mut uid, mut comp, mut dtstart, mut dtend) = (String::new(), String::new(), None, None);
    if parent.is_calendar() || parent.is_addressbook() {
        let text = match std::str::from_utf8(body) {
            Ok(t) => t,
            Err(_) => return Ok(Err(precondition(StatusCode::FORBIDDEN, if parent.is_calendar() { CALDAV } else { CARDDAV }, if parent.is_calendar() { "valid-calendar-data" } else { "valid-address-data" }))),
        };
        if parent.is_calendar() {
            if !ctype.to_ascii_lowercase().starts_with("text/calendar") && !ctype.starts_with("application/octet-stream") {
                return Ok(Err(precondition(StatusCode::FORBIDDEN, CALDAV, "supported-calendar-data")));
            }
            if ical::has_controls(text) {
                return Ok(Err(precondition(StatusCode::FORBIDDEN, CALDAV, "valid-calendar-data")));
            }
            let cal = match ical::parse(text) {
                Ok(c) => c,
                Err(_) => return Ok(Err(precondition(StatusCode::FORBIDDEN, CALDAV, "valid-calendar-data"))),
            };
            let allowed: Vec<String> = parent.prop_str("components").unwrap_or_default().split(',').filter(|s| !s.is_empty()).map(|s| s.to_string()).collect();
            match ical::validate_calendar(&cal, &allowed) {
                Ok((u, c)) => {
                    uid = u;
                    comp = c;
                }
                Err((cond, _)) => return Ok(Err(precondition(StatusCode::FORBIDDEN, CALDAV, cond))),
            }
            let (s, e) = ical::bounds(&cal);
            dtstart = s;
            dtend = e;
            ctype = "text/calendar; charset=utf-8".into();
        } else {
            if !ctype.to_ascii_lowercase().starts_with("text/vcard") && !ctype.to_ascii_lowercase().starts_with("text/x-vcard") && !ctype.starts_with("application/octet-stream") {
                return Ok(Err(precondition(StatusCode::FORBIDDEN, CARDDAV, "supported-address-data")));
            }
            let card = match ical::parse(text) {
                Ok(c) => c,
                Err(_) => return Ok(Err(precondition(StatusCode::FORBIDDEN, CARDDAV, "valid-address-data"))),
            };
            match ical::validate_vcard(&card) {
                Ok(u) => uid = u,
                Err((cond, _)) => return Ok(Err(precondition(StatusCode::FORBIDDEN, CARDDAV, cond))),
            }
            comp = "VCARD".into();
            ctype = "text/vcard; charset=utf-8".into();
        }
        // Changing the UID of an existing resource isn't allowed.
        if let Some(e) = existing {
            if !e.uid.is_empty() && e.uid != uid {
                let ns = if parent.is_calendar() { CALDAV } else { CARDDAV };
                return Ok(Err(precondition(StatusCode::FORBIDDEN, ns, "no-uid-conflict")));
            }
        }
        if !uid.is_empty() {
            if let Some(other) = st.db.dav_by_uid(pid, &parent_path, &uid).await? {
                if other.path != *path {
                    let ns = if parent.is_calendar() { CALDAV } else { CARDDAV };
                    let mut w = crate::xml::Writer::new().prefix("D", DAV).prefix("C", ns);
                    w.open(DAV, "error");
                    w.open(ns, "no-uid-conflict");
                    w.text_el(DAV, "href", &href_node(user, &other.path, false));
                    w.close(ns, "no-uid-conflict");
                    w.close(DAV, "error");
                    return Ok(Err(xml_response(StatusCode::FORBIDDEN, w.finish())));
                }
            }
        }
    } else if parent.path.starts_with("calendars") || parent.path.starts_with("addressbooks") {
        // Plain files only belong under files/.
        return Ok(Err(empty(StatusCode::FORBIDDEN)));
    }
    Ok(Ok(ContentMeta { uid, comp, dtstart, dtend, ctype }))
}

async fn delete(ctx: &Ctx, t: &Target, h: &HeaderMap) -> Result<Response> {
    let Target::Node(user, path) = t else { return Ok(empty(StatusCode::FORBIDDEN)) };
    let st = &ctx.state;
    let Some(n) = st.db.dav_node(ctx.principal.id, path).await? else { return Ok(empty(StatusCode::NOT_FOUND)) };
    if n.is_home() {
        return Ok(empty(StatusCode::FORBIDDEN));
    }
    if let Some(code) = check_conditional(h, Some(&n.etag)) {
        return Ok(empty(code));
    }
    if let Some(r) = locks::check_write(ctx, user, path, h, n.collection).await? {
        return Ok(r);
    }
    let old = if !n.collection && n.section() == "calendars" && itip::on(st) && !path.starts_with(itip::INBOX) {
        ical::parse(&String::from_utf8_lossy(&read_blob(st, &n).await?)).ok()
    } else {
        None
    };
    remove_tree(ctx, path).await?;
    if let Some(old) = &old {
        let no_reply = header_str(h, "schedule-reply").is_some_and(|v| v.trim().eq_ignore_ascii_case("F"));
        if let Err(e) = itip::on_change(st, &ctx.principal, itip::Change { old: Some(old), new: None, no_reply }).await {
            tracing::warn!("scheduling {path}: {e:#}");
        }
    }
    if n.section() == "calendars" && !attach::touches(path) {
        attach::sweep(ctx).await?;
    }
    Ok(empty(StatusCode::NO_CONTENT))
}

async fn remove_tree(ctx: &Ctx, path: &str) -> Result<()> {
    let st = &ctx.state;
    let nodes = st.db.dav_delete(ctx.principal.id, path).await?;
    let mut freed = 0;
    for n in &nodes {
        delete_blob(st, n.section(), &n.blob).await;
        freed += n.size;
        jmap_change(st, ctx.principal.id, n, "d").await;
    }
    st.db.dav_usage(ctx.principal.id, -freed).await?;
    record_change(st, ctx.principal.id, path, true).await;
    locks::drop_locks(st, ctx.principal.id, path).await;
    Ok(())
}

async fn mkcol(ctx: &Ctx, t: &Target, h: &HeaderMap, body: &[u8], calendar: bool) -> Result<Response> {
    let Target::Node(user, path) = t else { return Ok(empty(StatusCode::METHOD_NOT_ALLOWED)) };
    let st = &ctx.state;
    let pid = ctx.principal.id;
    if path.split('/').count() < 2 {
        return Ok(empty(StatusCode::METHOD_NOT_ALLOWED));
    }
    if st.db.dav_node(pid, path).await?.is_some() {
        // MKCOL: 405 (RFC 4918); MKCALENDAR: 403 resource-must-be-null (RFC 4791 5.3.1).
        return Ok(if calendar { precondition(StatusCode::FORBIDDEN, DAV, "resource-must-be-null") } else { empty(StatusCode::METHOD_NOT_ALLOWED) });
    }
    let parent_path = parent_of(path);
    let Some(parent) = st.db.dav_node(pid, &parent_path).await? else { return Ok(empty(StatusCode::CONFLICT)) };
    if !parent.collection {
        return Ok(empty(StatusCode::CONFLICT));
    }
    if let Some(r) = locks::check_write(ctx, user, path, h, false).await? {
        return Ok(r);
    }
    let section = path.split('/').next().unwrap_or("");
    let mut kind = String::new();
    let mut props = Map::new();
    let mut set_props: Vec<crate::xml::Element> = vec![];
    if !body.is_empty() {
        let doc = match crate::xml::parse(body) {
            Ok(d) => d,
            Err(_) => return Ok(empty(StatusCode::UNSUPPORTED_MEDIA_TYPE)),
        };
        let ok_root = if calendar { doc.is(CALDAV, "mkcalendar") } else { doc.is(DAV, "mkcol") };
        if !ok_root {
            return Ok(empty(StatusCode::UNSUPPORTED_MEDIA_TYPE));
        }
        for set in doc.children_named(DAV, "set") {
            if let Some(p) = set.child(DAV, "prop") {
                for e in p.elements() {
                    if e.is(DAV, "resourcetype") {
                        if e.child(CALDAV, "calendar").is_some() {
                            kind = "calendar".into();
                        } else if e.child(CARDDAV, "addressbook").is_some() {
                            kind = "addressbook".into();
                        } else if e.elements().any(|x| !x.is(DAV, "collection")) {
                            return Ok(precondition(StatusCode::FORBIDDEN, DAV, "valid-resourcetype"));
                        }
                    } else {
                        set_props.push(e.clone());
                    }
                }
            }
        }
    }
    if calendar {
        kind = "calendar".into();
    }
    // Calendars live under calendars/<user>/, address books under addressbooks/<user>/.
    match kind.as_str() {
        "calendar" if !(section == "calendars" && parent.kind == "calendar-home") => {
            return Ok(precondition(StatusCode::FORBIDDEN, CALDAV, "calendar-collection-location-ok"))
        }
        "addressbook" if !(section == "addressbooks" && parent.kind == "addressbook-home") => {
            return Ok(precondition(StatusCode::FORBIDDEN, CARDDAV, "addressbook-collection-location-ok"))
        }
        "" if section != "files" => return Ok(empty(StatusCode::FORBIDDEN)),
        _ => {}
    }
    if kind == "calendar" {
        props.insert("components".into(), json!("VEVENT,VTODO,VJOURNAL"));
    }
    // Apply the requested properties (atomically: reject all on any failure).
    let failures = props::apply_set(&kind, &mut props, &set_props);
    if !failures.is_empty() {
        let mut w = crate::xml::Writer::new().prefix("D", DAV);
        w.open(DAV, "mkcol-response");
        w.open(DAV, "propstat");
        w.open(DAV, "prop");
        for e in &set_props {
            w.empty(&e.ns, &e.name);
        }
        w.close(DAV, "prop");
        w.text_el(DAV, "status", &status_line(StatusCode::FORBIDDEN));
        w.close(DAV, "propstat");
        w.close(DAV, "mkcol-response");
        return Ok(xml_response(StatusCode::FORBIDDEN, w.finish()));
    }
    st.db.dav_put(pid, &NewNode { path, collection: true, kind: &kind, blob: "", size: 0, etag: "", ctype: "", props: &props, uid: "", comp: "", dtstart: None, dtend: None }).await?;
    record_change(st, pid, path, false).await;
    let mut r = empty(StatusCode::CREATED);
    r.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    Ok(r)
}

async fn copy_move(ctx: &Ctx, t: &Target, h: &HeaderMap, mv: bool) -> Result<Response> {
    let Target::Node(user, src) = t else { return Ok(empty(StatusCode::FORBIDDEN)) };
    let st = &ctx.state;
    let pid = ctx.principal.id;
    let Some(dest_h) = header_str(h, "destination") else { return Ok(empty(StatusCode::BAD_REQUEST)) };
    let Some(Target::Node(du, dst)) = target(dest_h) else { return Ok(empty(StatusCode::BAD_GATEWAY)) };
    if du != *user {
        return Ok(empty(StatusCode::BAD_GATEWAY));
    }
    if dst.split('/').next() != src.split('/').next() || dst.split('/').count() < 2 {
        return Ok(empty(StatusCode::FORBIDDEN));
    }
    let Some(node) = st.db.dav_node(pid, src).await? else { return Ok(empty(StatusCode::NOT_FOUND)) };
    if node.is_home() {
        return Ok(empty(StatusCode::FORBIDDEN));
    }
    if dst == *src || dst.starts_with(&format!("{src}/")) {
        return Ok(empty(StatusCode::FORBIDDEN));
    }
    let depth_inf = !matches!(header_str(h, "depth"), Some("0"));
    if mv && !depth_inf && node.collection {
        return Ok(empty(StatusCode::BAD_REQUEST));
    }
    let overwrite = header_str(h, "overwrite").map(|o| !o.trim().eq_ignore_ascii_case("F")).unwrap_or(true);
    let dest_parent = parent_of(&dst);
    let Some(dp) = st.db.dav_node(pid, &dest_parent).await? else { return Ok(empty(StatusCode::CONFLICT)) };
    if !dp.collection {
        return Ok(empty(StatusCode::CONFLICT));
    }
    if (dp.is_calendar() || dp.is_addressbook()) && node.collection {
        return Ok(empty(StatusCode::FORBIDDEN));
    }
    let existing = st.db.dav_node(pid, &dst).await?;
    if existing.is_some() && !overwrite {
        return Ok(empty(StatusCode::PRECONDITION_FAILED));
    }
    if mv {
        if let Some(r) = locks::check_write(ctx, user, src, h, node.collection).await? {
            return Ok(r);
        }
    }
    if let Some(r) = locks::check_write(ctx, user, &dst, h, existing.as_ref().is_some_and(|e| e.collection)).await? {
        return Ok(r);
    }
    // Calendar/address object rules and UID uniqueness at the destination
    // (a rename within the same collection keeps its UID).
    if !node.collection && (dp.is_calendar() || dp.is_addressbook()) && !(mv && dest_parent == node.parent) {
        let data = read_blob(st, &node).await?;
        if let Err(r) = validate_content(ctx, user, &dp, &dst, &node.ctype, &data, existing.as_ref()).await? {
            return Ok(r);
        }
    }
    if existing.is_some() {
        remove_tree(ctx, &dst).await?;
    }
    let nodes = if node.collection && depth_inf { st.db.dav_subtree(pid, src).await? } else { vec![node.clone()] };
    let mut added = 0i64;
    for n in &nodes {
        let new_path = format!("{dst}{}", &n.path[src.len()..]);
        let blob = if mv || n.blob.is_empty() {
            n.blob.clone()
        } else {
            let data = read_blob(st, n).await?;
            added += n.size;
            write_blob(st, n.section(), &data).await?
        };
        let props = n.props.clone();
        st.db
            .dav_put(pid, &NewNode { path: &new_path, collection: n.collection, kind: &n.kind, blob: &blob, size: n.size, etag: &n.etag, ctype: &n.ctype, props: &props, uid: &n.uid, comp: &n.comp, dtstart: n.dtstart, dtend: n.dtend })
            .await?;
        record_change(st, pid, &new_path, false).await;
    }
    if mv {
        // Remove the source rows without deleting blobs now owned by the destination.
        st.db.dav_delete(pid, src).await?;
        record_change(st, pid, src, true).await;
        locks::drop_locks(st, pid, src).await;
    } else if added > 0 {
        st.db.dav_usage(pid, added).await?;
    }
    Ok(empty(if existing.is_some() { StatusCode::NO_CONTENT } else { StatusCode::CREATED }))
}

// ------------------------------------------------------------------ export / import / sweep

/// Add the account's DAV data to an export zip: dav/<path>.
pub async fn export_into<W: std::io::Write + std::io::Seek>(state: &State, account_id: i64, z: &mut zip::ZipWriter<W>, opt: zip::write::SimpleFileOptions) -> Result<()> {
    use std::io::Write;
    let Some(p) = state.db.dav_principal_for_account(account_id).await? else { return Ok(()) };
    let rows = sqlx::query(&format!("SELECT {N_COLS} FROM dav_nodes WHERE principal_id = $1 ORDER BY path")).bind(p.id).fetch_all(&state.db.pool).await?;
    let mut collections = serde_json::Map::new();
    for r in rows {
        let n = node_from(&r)?;
        if n.collection {
            collections.insert(n.path.clone(), json!({"kind": n.kind, "props": n.props}));
            continue;
        }
        let data = read_blob(state, &n).await?;
        z.start_file(format!("dav/{}", n.path), opt)?;
        z.write_all(&data)?;
    }
    z.start_file("dav/.collections.json", opt)?;
    z.write_all(serde_json::to_vec(&collections)?.as_slice())?;
    Ok(())
}

/// Import one `dav/<path>` zip entry for an account's principal.
pub async fn import_entry(state: &State, account_id: i64, name: &str, data: &[u8]) -> Result<bool> {
    let Some(acc) = state.db.get_account(account_id).await? else { return Ok(false) };
    let Some(p) = principal_for_account(state, &acc).await? else { return Ok(false) };
    ensure_homes(state, &p).await?;
    let rel = name.trim_start_matches("dav/");
    if rel == ".collections.json" {
        let cols: Map<String, Value> = serde_json::from_slice(data).unwrap_or_default();
        for (path, v) in cols {
            if state.db.dav_node(p.id, &path).await?.is_none() && target(&format!("/dav/{}/x/", path.split('/').next().unwrap_or(""))).is_some() {
                let props = v["props"].as_object().cloned().unwrap_or_default();
                let kind = v["kind"].as_str().unwrap_or("").to_string();
                state.db.dav_put(p.id, &NewNode { path: &path, collection: true, kind: &kind, blob: "", size: 0, etag: "", ctype: "", props: &props, uid: "", comp: "", dtstart: None, dtend: None }).await?;
            }
        }
        return Ok(false);
    }
    if rel.split('/').any(|s| s.is_empty() || s == ".." || s == ".") || rel.split('/').count() < 2 {
        return Ok(false);
    }
    // Parents first (plain collections under files/).
    let mut cur = String::new();
    let segs: Vec<&str> = rel.split('/').collect();
    for s in &segs[..segs.len() - 1] {
        if !cur.is_empty() {
            cur.push('/');
        }
        cur.push_str(s);
        if state.db.dav_node(p.id, &cur).await?.is_none() {
            let kind = if cur.starts_with("calendars/") && cur.matches('/').count() == 1 {
                "calendar"
            } else if cur.starts_with("addressbooks/") && cur.matches('/').count() == 1 {
                "addressbook"
            } else {
                ""
            };
            let e = Map::new();
            state.db.dav_put(p.id, &NewNode { path: &cur, collection: true, kind, blob: "", size: 0, etag: "", ctype: "", props: &e, uid: "", comp: "", dtstart: None, dtend: None }).await?;
        }
    }
    let section = segs[0];
    let (mut uid, mut comp, mut ds, mut de, mut ctype) = (String::new(), String::new(), None, None, "application/octet-stream".to_string());
    if section == "calendars" || section == "addressbooks" {
        let Ok(c) = ical::parse(&String::from_utf8_lossy(data)) else { return Ok(false) };
        uid = c.comps.iter().find(|x| x.name != "VTIMEZONE").and_then(|x| x.prop("UID")).or(c.prop("UID")).map(|u| u.value.clone()).unwrap_or_default();
        if section == "calendars" {
            comp = c.comps.iter().find(|x| x.name != "VTIMEZONE").map(|x| x.name.clone()).unwrap_or_default();
            let b = ical::bounds(&c);
            ds = b.0;
            de = b.1;
            ctype = "text/calendar; charset=utf-8".into();
        } else {
            comp = "VCARD".into();
            ctype = "text/vcard; charset=utf-8".into();
        }
    } else if let Some(g) = mime_guess::from_path(rel).first() {
        ctype = g.to_string();
    }
    let key = write_blob(state, section, data).await?;
    let e = Map::new();
    let old = state.db.dav_node(p.id, rel).await?;
    state.db.dav_put(p.id, &NewNode { path: rel, collection: false, kind: "", blob: &key, size: data.len() as i64, etag: &etag_of(data), ctype: &ctype, props: &e, uid: &uid, comp: &comp, dtstart: ds, dtend: de }).await?;
    if let Some(o) = old {
        delete_blob(state, section, &o.blob).await;
    }
    state.db.dav_usage(p.id, data.len() as i64).await?;
    record_change(state, p.id, rel, false).await;
    Ok(true)
}

/// Delete DAV objects no node refers to (after `grace` seconds).
pub async fn sweep_orphans(state: &State, grace: i64) -> Result<usize> {
    let used: std::collections::HashSet<String> = sqlx::query("SELECT blob FROM dav_nodes WHERE blob <> ''").fetch_all(&state.db.pool).await?.iter().map(|r| r.get(0)).collect();
    let mut removed = 0;
    let t = now();
    for (section, b) in [("files", &state.dav.files), ("calendars", &state.dav.calendars), ("addressbooks", &state.dav.contacts)] {
        for k in b.list().await?.into_iter().filter(|k| k.starts_with("dav-") && !used.contains(k)) {
            let seen: Option<i64> = sqlx::query("SELECT first_seen FROM gc_seen WHERE key = $1").bind(&k).fetch_optional(&state.db.pool).await?.map(|r| r.get(0));
            match seen {
                Some(first) if t - first >= grace => {
                    delete_blob(state, section, &k).await;
                    let _g = state.db.wl().await;
                    let _ = sqlx::query("DELETE FROM gc_seen WHERE key = $1").bind(&k).execute(&state.db.pool).await;
                    removed += 1;
                }
                Some(_) => {}
                None => {
                    let _g = state.db.wl().await;
                    let _ = sqlx::query("INSERT INTO gc_seen (key, first_seen) VALUES ($1, $2) ON CONFLICT DO NOTHING").bind(&k).bind(t).execute(&state.db.pool).await;
                }
            }
        }
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn targets() {
        assert_eq!(target("/dav/"), Some(Target::Root));
        assert_eq!(target("/dav/principals/bob%40x.com/"), Some(Target::Principal("bob@x.com".into())));
        assert_eq!(target("/dav/calendars/bob@x.com/work/ev%201.ics"), Some(Target::Node("bob@x.com".into(), "calendars/work/ev 1.ics".into())));
        assert_eq!(target("http://h:8080/dav/files/bob/a/b/"), Some(Target::Node("bob".into(), "files/a/b".into())));
        assert_eq!(target("/dav/files/bob/../x"), None);
        assert_eq!(href_node("bob@x.com", "calendars/work/ev 1.ics", false), "/dav/calendars/bob@x.com/work/ev%201.ics");
        assert_eq!(href_node("bob", "files", true), "/dav/files/bob/");
    }
}
