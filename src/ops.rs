//! Operations: audit log, retention, the orphaned-object sweep, scheduled
//! maintenance, account export/import (zip, mbox, Maildir), IMAP
//! migration from another server, and whole-server backup/restore.
use crate::state::State;
use crate::util::now;
use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use sqlx::{Column, Row, TypeInfo};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{Read, Write};
use std::path::Path;
use std::time::Duration;

// ------------------------------------------------------------------ audit log

/// Record an administrative action (who, from where, what, on what).
pub fn audit(state: &State, actor: &str, ip: &str, action: &str, target: &str, detail: &Value) {
    let db = state.db.clone();
    let (a, i, ac, t) = (actor.to_string(), ip.to_string(), action.to_string(), target.to_string());
    let d = if detail.is_null() { String::new() } else { detail.to_string().chars().take(4000).collect() };
    tracing::info!(target: "audit", actor = %a, ip = %i, action = %ac, target = %t, "{d}");
    tokio::spawn(async move {
        let _g = db.wl().await;
        let _ = sqlx::query("INSERT INTO audit (ts, actor, ip, action, target, detail) VALUES ($1, $2, $3, $4, $5, $6)")
            .bind(now())
            .bind(a)
            .bind(i)
            .bind(ac)
            .bind(t)
            .bind(d)
            .execute(&db.pool)
            .await;
    });
}

pub async fn list_audit(state: &State, limit: i64, before: Option<i64>, actor: Option<&str>) -> Result<Vec<Value>> {
    let mut q = String::from("SELECT id, ts, actor, ip, action, target, detail FROM audit WHERE 1 = 1");
    if before.is_some() {
        q.push_str(" AND id < $2");
    }
    if actor.is_some() {
        q.push_str(if before.is_some() { " AND actor = $3" } else { " AND actor = $2" });
    }
    q.push_str(" ORDER BY id DESC LIMIT $1");
    let mut query = sqlx::query(&q).bind(limit.clamp(1, 1000));
    if let Some(b) = before {
        query = query.bind(b);
    }
    if let Some(a) = actor {
        query = query.bind(a);
    }
    let rows = query.fetch_all(&state.db.pool).await?;
    Ok(rows
        .iter()
        .map(|r| {
            let d: String = r.get(6);
            json!({
                "id": r.get::<i64, _>(0), "ts": r.get::<i64, _>(1), "actor": r.get::<String, _>(2), "ip": r.get::<String, _>(3),
                "action": r.get::<String, _>(4), "target": r.get::<String, _>(5),
                "detail": serde_json::from_str::<Value>(&d).unwrap_or(if d.is_empty() { Value::Null } else { Value::String(d) }),
            })
        })
        .collect())
}

// ------------------------------------------------------------------ retention

/// Expunge messages older than the retention rules allow. Returns how many.
pub async fn apply_retention(state: &State) -> Result<usize> {
    let s = state.settings().retention.clone();
    let mut total = 0;
    for acc in state.db.list_accounts().await? {
        for mb in state.db.list_mailboxes(acc.id).await? {
            let mut days = 0u32;
            if mb.special_use.contains("\\Trash") || mb.name.eq_ignore_ascii_case("Trash") {
                days = s.trash_days;
            }
            if mb.special_use.contains("\\Junk") || mb.name.eq_ignore_ascii_case("Junk") {
                days = s.junk_days;
            }
            for r in &s.rules {
                if r.folder.eq_ignore_ascii_case(&mb.name) || (!r.folder.is_empty() && mb.special_use.split_whitespace().any(|u| u.eq_ignore_ascii_case(&r.folder))) {
                    days = r.days;
                }
            }
            let own: i64 = sqlx::query("SELECT retention_days FROM mailboxes WHERE id = $1").bind(mb.id).fetch_one(&state.db.pool).await?.get(0);
            if own > 0 {
                days = own as u32;
            }
            if days == 0 {
                continue;
            }
            let cutoff = now() - days as i64 * 86400;
            let uids: Vec<i64> = sqlx::query("SELECT uid FROM messages WHERE mailbox_id = $1 AND internal_date < $2 ORDER BY uid LIMIT 5000")
                .bind(mb.id)
                .bind(cutoff)
                .fetch_all(&state.db.pool)
                .await?
                .iter()
                .map(|r| r.get::<i64, _>(0))
                .collect();
            if uids.is_empty() {
                continue;
            }
            let (_, blobs, freed) = state.db.expunge(mb.id, &uids).await?;
            state.db.add_usage(acc.id, -freed).await?;
            state.hub.notify(mb.id);
            state.blobs.delete_all(&blobs).await;
            total += uids.len();
        }
    }
    if total > 0 {
        state.event("info", "retention", &format!("removed {total} expired message(s)"));
    }
    let _g = state.db.wl().await;
    if s.audit_days > 0 {
        let _ = sqlx::query("DELETE FROM audit WHERE ts < $1").bind(now() - s.audit_days as i64 * 86400).execute(&state.db.pool).await;
    }
    Ok(total)
}

// ------------------------------------------------------------------ orphan sweep

/// Delete stored objects nothing refers to. An object must be seen as
/// unreferenced on two sweeps at least `orphan_grace_hours` apart, so
/// writes in flight are never touched.
pub async fn sweep_orphans(state: &State) -> Result<(usize, usize)> {
    let grace = state.settings().retention.orphan_grace_hours.max(1) as i64 * 3600;
    // 1) Reference rows that dropped to zero (crash between release and delete).
    let zero: Vec<String> = sqlx::query("SELECT key FROM blob_refs WHERE refs <= 0").fetch_all(&state.db.pool).await?.iter().map(|r| r.get(0)).collect();
    for k in &zero {
        state.blobs.delete(k).await.ok();
        let _g = state.db.wl().await;
        let _ = sqlx::query("DELETE FROM blob_refs WHERE key = $1 AND refs <= 0").bind(k).execute(&state.db.pool).await;
    }
    // 2) Objects in the stores with no reference row at all.
    let known: HashSet<String> = sqlx::query("SELECT key FROM blob_refs").fetch_all(&state.db.pool).await?.iter().map(|r| r.get(0)).collect();
    let mut stored = state.blobs.messages.list().await?;
    if let Some((att, _)) = &state.blobs.attachments {
        stored.extend(att.list().await?.into_iter().map(|k| if k.starts_with("a/") { k } else { format!("a/{k}") }));
    }
    // DAV objects (dav-…) share stores but are tracked by the DAV module.
    let candidates: Vec<String> = stored.into_iter().filter(|k| !known.contains(k) && !k.starts_with("dav-")).collect();
    let mut removed = 0;
    let t = now();
    for k in &candidates {
        let seen: Option<i64> = sqlx::query("SELECT first_seen FROM gc_seen WHERE key = $1").bind(k).fetch_optional(&state.db.pool).await?.map(|r| r.get(0));
        match seen {
            Some(first) if t - first >= grace => {
                // Re-check under the blob lock (BlobStore::delete re-reads the count).
                state.blobs.delete(k).await.ok();
                let _g = state.db.wl().await;
                let _ = sqlx::query("DELETE FROM gc_seen WHERE key = $1").bind(k).execute(&state.db.pool).await;
                removed += 1;
            }
            Some(_) => {}
            None => {
                let _g = state.db.wl().await;
                let _ = sqlx::query("INSERT INTO gc_seen (key, first_seen) VALUES ($1, $2) ON CONFLICT DO NOTHING").bind(k).bind(t).execute(&state.db.pool).await;
            }
        }
    }
    // Forget bookmarks for objects that came back into use.
    let cand: HashSet<&String> = candidates.iter().collect();
    let marks: Vec<String> = sqlx::query("SELECT key FROM gc_seen").fetch_all(&state.db.pool).await?.iter().map(|r| r.get(0)).collect();
    for m in marks {
        if !cand.contains(&m) {
            let _g = state.db.wl().await;
            let _ = sqlx::query("DELETE FROM gc_seen WHERE key = $1").bind(&m).execute(&state.db.pool).await;
        }
    }
    let dav = crate::dav::sweep_orphans(state, grace).await.unwrap_or(0);
    if removed + zero.len() + dav > 0 {
        state.event("info", "storage", &format!("removed {} orphaned object(s)", removed + zero.len() + dav));
    }
    Ok((removed + zero.len(), dav))
}

// ------------------------------------------------------------------ scheduler

/// Background maintenance: reports hourly, retention and sweeps daily,
/// greylist and cache pruning.
pub fn spawn_maintenance(state: State) {
    tokio::spawn(async move {
        let mut tick = 0u64;
        // Let startup settle first.
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(60)) => {}
            _ = state.shutdown.cancelled() => return,
        }
        loop {
            crate::filter::prune_greylist(&state).await;
            crate::reports::run(&state).await;
            if tick % 24 == 0 {
                if let Err(e) = apply_retention(&state).await {
                    tracing::warn!("retention: {e:#}");
                }
                if let Err(e) = sweep_orphans(&state).await {
                    tracing::warn!("orphan sweep: {e:#}");
                }
                let _g = state.db.wl().await;
                let _ = sqlx::query("DELETE FROM mta_sts_cache WHERE expires_at < $1").bind(now() - 86400).execute(&state.db.pool).await;
                let _ = sqlx::query("DELETE FROM dav_locks WHERE expires_at < $1").bind(now()).execute(&state.db.pool).await;
                let _ = sqlx::query("DELETE FROM vacation_sent WHERE sent_at < $1").bind(now() - 366 * 86400).execute(&state.db.pool).await;
            }
            tick += 1;
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(3600)) => {}
                _ = state.shutdown.cancelled() => return,
            }
        }
    });
}

// ------------------------------------------------------------------ export

fn flags_from_maildir(info: &str) -> String {
    let mut f = vec![];
    for c in info.chars() {
        match c {
            'S' => f.push("\\Seen"),
            'R' => f.push("\\Answered"),
            'F' => f.push("\\Flagged"),
            'T' => f.push("\\Deleted"),
            'D' => f.push("\\Draft"),
            _ => {}
        }
    }
    f.join(" ")
}

fn safe_folder(name: &str) -> Option<String> {
    let n = name.trim_matches('/').replace('\\', "/");
    if n.is_empty() || n.split('/').any(|p| p.is_empty() || p == "." || p == "..") {
        return None;
    }
    Some(n)
}

/// Export an account as a zip: mail (one .eml per message with a flags
/// index per folder), Sieve scripts, vacation and DAV data.
pub async fn export_account(state: &State, account_id: i64, out: &Path) -> Result<()> {
    let acc = state.db.get_account(account_id).await?.ok_or_else(|| anyhow!("no such account"))?;
    let file = std::fs::File::create(out).with_context(|| format!("create {}", out.display()))?;
    let mut z = zip::ZipWriter::new(std::io::BufWriter::new(file));
    let opt = zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated).large_file(true);
    z.start_file("manifest.json", opt)?;
    z.write_all(serde_json::to_vec_pretty(&json!({"format": "picacho-export-1", "account": acc.email, "display_name": acc.display_name, "exported_at": now()}))?.as_slice())?;
    for mb in state.db.list_mailboxes(account_id).await? {
        let Some(folder) = safe_folder(&mb.name) else { continue };
        let rows = state.db.messages_by_uids(mb.id, 1, i64::MAX).await?;
        let mut index = BTreeMap::new();
        for m in rows {
            let raw = match state.blobs.get(&m.blob).await {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!("export: message {} unreadable: {e}", m.id);
                    continue;
                }
            };
            z.start_file(format!("mail/{folder}/{}.eml", m.uid), opt)?;
            z.write_all(&raw)?;
            index.insert(m.uid.to_string(), json!({"flags": m.flags, "internal_date": m.internal_date}));
        }
        z.start_file(format!("mail/{folder}/.index.json"), opt)?;
        z.write_all(serde_json::to_vec(&json!({"special_use": mb.special_use, "messages": index}))?.as_slice())?;
    }
    for s in state.db.sieve_scripts(account_id).await? {
        z.start_file(format!("sieve/{}.sieve", s.name.replace('/', "_")), opt)?;
        z.write_all(s.content.as_bytes())?;
        if s.active {
            z.start_file("sieve/.active", opt)?;
            z.write_all(s.name.as_bytes())?;
        }
    }
    let v = state.db.vacation(account_id).await?;
    z.start_file("vacation.json", opt)?;
    z.write_all(serde_json::to_vec_pretty(&v)?.as_slice())?;
    crate::dav::export_into(state, account_id, &mut z, opt).await?;
    z.finish()?;
    Ok(())
}

async fn message_exists(state: &State, mailbox_id: i64, raw: &[u8]) -> bool {
    let s = crate::mime::summarize(raw);
    if s.msgid.is_empty() {
        return false;
    }
    sqlx::query("SELECT 1 FROM messages WHERE mailbox_id = $1 AND msgid = $2")
        .bind(mailbox_id)
        .bind(&s.msgid)
        .fetch_optional(&state.db.pool)
        .await
        .ok()
        .flatten()
        .is_some()
}

async fn folder(state: &State, account_id: i64, name: &str, special: &str) -> Result<crate::db::Mailbox> {
    if let Some(m) = state.db.mailbox(account_id, name).await? {
        return Ok(m);
    }
    let id = state.db.create_mailbox(account_id, name, special).await?;
    state.db.mailbox_by_id(id).await?.ok_or_else(|| anyhow!("mailbox vanished"))
}

#[derive(Default, serde::Serialize, Clone, Debug)]
pub struct ImportStats {
    pub messages: usize,
    pub skipped: usize,
    pub folders: usize,
    pub scripts: usize,
    pub dav: usize,
    pub errors: Vec<String>,
}

async fn import_one(state: &State, account_id: i64, mb: &crate::db::Mailbox, raw: &[u8], flags: &str, date: Option<i64>, stats: &mut ImportStats) {
    let raw = crate::util::normalize_crlf(raw);
    if message_exists(state, mb.id, &raw).await {
        stats.skipped += 1;
        return;
    }
    match crate::server::store_message(state, account_id, mb, &raw, flags, date).await {
        Ok(_) => stats.messages += 1,
        Err(e) => {
            if stats.errors.len() < 50 {
                stats.errors.push(format!("{}: {e}", mb.name));
            }
        }
    }
}

/// Import a Picacho export zip, a zipped Maildir tree, or an mbox file.
pub async fn import_account(state: &State, account_id: i64, data: Vec<u8>, default_folder: &str) -> Result<ImportStats> {
    let mut stats = ImportStats::default();
    if data.starts_with(b"PK") {
        let entries: Vec<(String, Vec<u8>)> = tokio::task::spawn_blocking(move || -> Result<Vec<(String, Vec<u8>)>> {
            let mut z = zip::ZipArchive::new(std::io::Cursor::new(data))?;
            let mut out = vec![];
            for i in 0..z.len() {
                let mut f = z.by_index(i)?;
                if f.is_dir() {
                    continue;
                }
                let name = f.name().to_string();
                let mut buf = Vec::new();
                (&mut f).take(200 * 1024 * 1024).read_to_end(&mut buf)?;
                out.push((name, buf));
            }
            Ok(out)
        })
        .await??;
        let mut indexes: HashMap<String, Value> = HashMap::new();
        for (n, d) in &entries {
            if let Some(folder) = n.strip_prefix("mail/").and_then(|r| r.strip_suffix("/.index.json")) {
                indexes.insert(folder.to_string(), serde_json::from_slice(d).unwrap_or(Value::Null));
            }
        }
        let mut seen_folders = HashSet::new();
        let mut active_script = None;
        for (name, body) in &entries {
            if let Some(rest) = name.strip_prefix("mail/") {
                // Picacho export: mail/<folder>/<uid>.eml
                let Some((folder_name, file)) = rest.rsplit_once('/') else { continue };
                if file.starts_with('.') {
                    continue;
                }
                let Some(folder_name) = safe_folder(folder_name) else { continue };
                let idx = indexes.get(&folder_name);
                let special = idx.and_then(|i| i["special_use"].as_str()).unwrap_or("");
                let mb = folder(state, account_id, &folder_name, special).await?;
                if seen_folders.insert(folder_name.clone()) {
                    stats.folders += 1;
                }
                let uid = file.trim_end_matches(".eml");
                let meta = idx.map(|i| &i["messages"][uid]);
                let flags = meta.and_then(|m| m["flags"].as_str()).unwrap_or("");
                let date = meta.and_then(|m| m["internal_date"].as_i64());
                import_one(state, account_id, &mb, body, flags, date, &mut stats).await;
            } else if let Some(s) = name.strip_prefix("sieve/") {
                if s == ".active" {
                    active_script = Some(String::from_utf8_lossy(body).trim().to_string());
                    continue;
                }
                let n = s.trim_end_matches(".sieve");
                let text = String::from_utf8_lossy(body).to_string();
                if crate::sieve::valid_name(n) && crate::sieve::check(&text).is_ok() {
                    state.db.sieve_put(account_id, n, &text).await?;
                    stats.scripts += 1;
                }
            } else if name == "vacation.json" {
                if let Ok(v) = serde_json::from_slice::<Value>(body) {
                    let vs = crate::sieve::VacationSettings {
                        enabled: v["enabled"].as_bool().unwrap_or(false),
                        subject: v["subject"].as_str().map(|s| s.to_string()),
                        text_body: v["text_body"].as_str().map(|s| s.to_string()),
                        html_body: v["html_body"].as_str().map(|s| s.to_string()),
                        from_date: v["from_date"].as_i64(),
                        to_date: v["to_date"].as_i64(),
                        days: v["days"].as_i64().unwrap_or(7),
                    };
                    state.db.set_vacation(account_id, &vs).await?;
                }
            } else if name.starts_with("dav/") {
                if crate::dav::import_entry(state, account_id, name, body).await.unwrap_or(false) {
                    stats.dav += 1;
                }
            } else if let Some((path, file)) = name.rsplit_once('/') {
                // Maildir: <folder>/{cur,new}/<file>
                let (folder_path, sub) = path.rsplit_once('/').unwrap_or(("", path));
                if sub != "cur" && sub != "new" {
                    continue;
                }
                let mut fname = folder_path.trim_start_matches('.').replace('.', "/");
                if fname.is_empty() || fname.eq_ignore_ascii_case("inbox") {
                    fname = "INBOX".into();
                }
                let Some(fname) = safe_folder(&fname) else { continue };
                let mb = folder(state, account_id, &fname, "").await?;
                if seen_folders.insert(fname) {
                    stats.folders += 1;
                }
                let flags = file.split_once(":2,").map(|(_, f)| flags_from_maildir(f)).unwrap_or_default();
                import_one(state, account_id, &mb, body, &flags, None, &mut stats).await;
            }
        }
        if let Some(a) = active_script {
            let _ = state.db.sieve_activate(account_id, Some(&a)).await;
        }
    } else {
        // mbox
        let target = safe_folder(default_folder).unwrap_or_else(|| "Imported".into());
        let mb = folder(state, account_id, &target, "").await?;
        stats.folders = 1;
        let msgs: Vec<(Vec<u8>, i64)> = tokio::task::spawn_blocking(move || {
            mail_parser::mailbox::mbox::MessageIterator::new(std::io::Cursor::new(data))
                .filter_map(|m| m.ok())
                .map(|m| {
                    let d = m.internal_date() as i64;
                    (m.unwrap_contents(), d)
                })
                .collect()
        })
        .await?;
        for (raw, date) in msgs {
            import_one(state, account_id, &mb, &raw, "\\Seen", if date > 0 { Some(date) } else { None }, &mut stats).await;
        }
    }
    state.event("info", "import", &format!("account {account_id}: imported {} message(s), skipped {} duplicate(s)", stats.messages, stats.skipped));
    Ok(stats)
}

// ------------------------------------------------------------------ IMAP migration

#[derive(serde::Deserialize, Clone)]
pub struct MigrateRequest {
    pub host: String,
    #[serde(default)]
    pub port: Option<u16>,
    /// "tls" (993, default), "starttls" (143) or "none".
    #[serde(default)]
    pub security: Option<String>,
    pub username: String,
    pub password: String,
    /// Only these folders (default: all).
    #[serde(default)]
    pub folders: Vec<String>,
    /// Prefix for imported folders ("" keeps the names).
    #[serde(default)]
    pub prefix: String,
}

#[derive(Default, serde::Serialize, Clone)]
pub struct MigrationStatus {
    pub id: String,
    pub account_id: i64,
    pub state: String,
    pub folder: String,
    pub done: usize,
    pub total: usize,
    pub stats: ImportStats,
    pub error: Option<String>,
    pub started: i64,
    pub finished: Option<i64>,
}

pub static MIGRATIONS: std::sync::LazyLock<dashmap::DashMap<String, MigrationStatus>> = std::sync::LazyLock::new(dashmap::DashMap::new);

enum ImapStream {
    Plain(tokio::net::TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>),
}

impl tokio::io::AsyncRead for ImapStream {
    fn poll_read(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &mut tokio::io::ReadBuf<'_>) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            ImapStream::Plain(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            ImapStream::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for ImapStream {
    fn poll_write(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &[u8]) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            ImapStream::Plain(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            ImapStream::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            ImapStream::Plain(s) => std::pin::Pin::new(s).poll_flush(cx),
            ImapStream::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            ImapStream::Plain(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            ImapStream::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

/// A response line plus the literals it carried.
struct ImapLine {
    text: String,
    literals: Vec<Vec<u8>>,
}

struct ImapClient {
    r: tokio::io::BufReader<ImapStream>,
    tag: u32,
}

fn imap_quote(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

impl ImapClient {
    async fn connect(req: &MigrateRequest) -> Result<Self> {
        let sec = req.security.clone().unwrap_or_else(|| "tls".into());
        let port = req.port.unwrap_or(if sec == "tls" { 993 } else { 143 });
        let tcp = tokio::time::timeout(Duration::from_secs(30), tokio::net::TcpStream::connect((req.host.as_str(), port))).await??;
        let tls = |tcp| async {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let cfg = rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
            let name = rustls::pki_types::ServerName::try_from(req.host.clone())?;
            let s = tokio_rustls::TlsConnector::from(std::sync::Arc::new(cfg)).connect(name, tcp).await?;
            Ok::<_, anyhow::Error>(ImapStream::Tls(Box::new(s)))
        };
        let stream = if sec == "tls" { tls(tcp).await? } else { ImapStream::Plain(tcp) };
        let mut c = Self { r: tokio::io::BufReader::new(stream), tag: 0 };
        c.read_line().await?; // greeting
        if sec == "starttls" {
            c.command("STARTTLS").await?;
            let ImapStream::Plain(tcp) = c.r.into_inner() else { bail!("unexpected stream") };
            c = Self { r: tokio::io::BufReader::new(tls(tcp).await?), tag: c.tag };
        }
        Ok(c)
    }

    async fn read_line(&mut self) -> Result<ImapLine> {
        use tokio::io::{AsyncBufReadExt, AsyncReadExt};
        let mut text = String::new();
        let mut literals = vec![];
        loop {
            let mut buf = Vec::new();
            let n = tokio::time::timeout(Duration::from_secs(300), self.r.read_until(b'\n', &mut buf)).await??;
            if n == 0 {
                bail!("connection closed");
            }
            let line = String::from_utf8_lossy(&buf).trim_end_matches(['\r', '\n']).to_string();
            if let Some((n, _)) = crate::imap::proto::literal_suffix(line.as_bytes()) {
                if n > 200 * 1024 * 1024 {
                    bail!("literal too large");
                }
                let mut lit = vec![0u8; n];
                self.r.read_exact(&mut lit).await?;
                text.push_str(&line);
                text.push(' ');
                literals.push(lit);
                continue;
            }
            text.push_str(&line);
            return Ok(ImapLine { text, literals });
        }
    }

    /// Run a command; returns untagged responses, fails on NO/BAD.
    async fn command(&mut self, cmd: &str) -> Result<Vec<ImapLine>> {
        use tokio::io::AsyncWriteExt;
        self.tag += 1;
        let tag = format!("m{}", self.tag);
        let w = self.r.get_mut();
        w.write_all(format!("{tag} {cmd}\r\n").as_bytes()).await?;
        w.flush().await?;
        let mut out = vec![];
        loop {
            let l = self.read_line().await?;
            if let Some(rest) = l.text.strip_prefix(&format!("{tag} ")) {
                if rest.starts_with("OK") {
                    return Ok(out);
                }
                bail!("{}", rest.chars().take(300).collect::<String>());
            }
            out.push(l);
        }
    }
}

fn parse_list(line: &str) -> Option<(String, String, char)> {
    // * LIST (\HasNoChildren \Sent) "/" "Sent Items"
    let rest = line.strip_prefix("* LIST ")?;
    let close = rest.find(')')?;
    let attrs = rest[1..close].to_string();
    let rest = rest[close + 1..].trim_start();
    let (delim, rest) = if let Some(r) = rest.strip_prefix("NIL") {
        ('/', r)
    } else {
        let d = rest.chars().nth(1).unwrap_or('/');
        let d = if d == '\\' { rest.chars().nth(2).unwrap_or('/') } else { d };
        (d, rest.splitn(2, ' ').nth(1).map(|r| &rest[rest.len() - r.len() - 1..]).unwrap_or(""))
    };
    let name = rest.trim();
    let name = if name.starts_with('"') { name.trim_matches('"').replace("\\\"", "\"").replace("\\\\", "\\") } else { name.to_string() };
    Some((name, attrs, delim))
}

/// Copy all mail from another IMAP server into an account (background job).
pub fn start_migration(state: &State, account_id: i64, req: MigrateRequest) -> String {
    let id = uuid::Uuid::new_v4().simple().to_string()[..12].to_string();
    MIGRATIONS.insert(id.clone(), MigrationStatus { id: id.clone(), account_id, state: "running".into(), started: now(), ..Default::default() });
    let st = state.clone();
    let jid = id.clone();
    tokio::spawn(async move {
        let r = migrate(&st, account_id, &req, &jid).await;
        if let Some(mut m) = MIGRATIONS.get_mut(&jid) {
            m.finished = Some(now());
            match r {
                Ok(()) => m.state = "done".into(),
                Err(e) => {
                    m.state = "failed".into();
                    m.error = Some(format!("{e:#}"));
                }
            }
        }
    });
    id
}

async fn migrate(state: &State, account_id: i64, req: &MigrateRequest, job: &str) -> Result<()> {
    let mut c = ImapClient::connect(req).await?;
    c.command(&format!("LOGIN {} {}", imap_quote(&req.username), imap_quote(&req.password))).await.context("login")?;
    let lists = c.command("LIST \"\" \"*\"").await?;
    let mut folders: Vec<(String, String, char)> = lists.iter().filter_map(|l| parse_list(&l.text)).filter(|(_, a, _)| !a.contains("\\Noselect") && !a.contains("\\NonExistent")).collect();
    if !req.folders.is_empty() {
        folders.retain(|(n, _, _)| req.folders.iter().any(|f| f.eq_ignore_ascii_case(n)));
    }
    let re_uid = regex::Regex::new(r"UID (\d+)").unwrap();
    let re_flags = regex::Regex::new(r"FLAGS \(([^)]*)\)").unwrap();
    let re_date = regex::Regex::new(r#"INTERNALDATE "([^"]+)""#).unwrap();
    for (name, attrs, delim) in folders {
        let local_name = if name.eq_ignore_ascii_case("INBOX") { "INBOX".to_string() } else { format!("{}{}", req.prefix, name.replace(delim, "/")) };
        let Some(local_name) = safe_folder(&local_name) else { continue };
        let special = ["\\Sent", "\\Drafts", "\\Trash", "\\Junk", "\\Archive"].iter().find(|s| attrs.contains(*s)).copied().unwrap_or("");
        let mb = folder(state, account_id, &local_name, special).await?;
        c.command(&format!("EXAMINE {}", imap_quote(&name))).await?;
        let found = c.command("UID SEARCH ALL").await?;
        let uids: Vec<u64> = found.iter().filter(|l| l.text.starts_with("* SEARCH")).flat_map(|l| l.text.split_whitespace().skip(2).filter_map(|x| x.parse().ok()).collect::<Vec<_>>()).collect();
        if let Some(mut m) = MIGRATIONS.get_mut(job) {
            m.folder = local_name.clone();
            m.total += uids.len();
            m.stats.folders += 1;
        }
        for chunk in uids.chunks(50) {
            let set = chunk.iter().map(|u| u.to_string()).collect::<Vec<_>>().join(",");
            let resp = c.command(&format!("UID FETCH {set} (UID FLAGS INTERNALDATE BODY.PEEK[])")).await?;
            let mut stats = ImportStats::default();
            for l in resp {
                if !l.text.contains("FETCH") || l.literals.is_empty() {
                    continue;
                }
                let _uid = re_uid.captures(&l.text).map(|c| c[1].to_string());
                let flags: String = re_flags
                    .captures(&l.text)
                    .map(|c| c[1].split_whitespace().filter(|f| *f != "\\Recent").collect::<Vec<_>>().join(" "))
                    .unwrap_or_default();
                let date = re_date.captures(&l.text).and_then(|c| chrono::DateTime::parse_from_str(&c[1], "%d-%b-%Y %H:%M:%S %z").ok()).map(|d| d.timestamp());
                import_one(state, account_id, &mb, &l.literals[0], &flags, date, &mut stats).await;
            }
            if let Some(mut m) = MIGRATIONS.get_mut(job) {
                m.done += chunk.len();
                m.stats.messages += stats.messages;
                m.stats.skipped += stats.skipped;
                m.stats.errors.extend(stats.errors);
            }
            if state.shutdown.is_cancelled() {
                bail!("server shutting down");
            }
        }
    }
    let _ = c.command("LOGOUT").await;
    state.event("info", "import", &format!("IMAP migration {job} into account {account_id} finished"));
    Ok(())
}

// ------------------------------------------------------------------ backup / restore

const TABLES: &[&str] = &[
    "settings", "domains", "accounts", "aliases", "mailboxes", "subscriptions", "messages", "blob_refs", "blob_data", "queue", "expunged", "changes",
    "api_tokens", "oauth_clients", "oauth_tokens", "uploads", "sieve_scripts", "vacation", "acl", "metadata", "relay_peers", "audit",
    "dav_principals", "dav_nodes", "dav_changes", "bayes_tokens", "bayes_totals", "bayes_learned", "reports_in",
];

fn cell(r: &sqlx::any::AnyRow, i: usize) -> Value {
    use base64::Engine;
    let ty = r.columns()[i].type_info().name().to_ascii_uppercase();
    if ty.contains("INT") {
        return r.try_get::<Option<i64>, _>(i).ok().flatten().map(Value::from).unwrap_or(Value::Null);
    }
    if ty.contains("BLOB") || ty.contains("BYTEA") {
        return r
            .try_get::<Option<Vec<u8>>, _>(i)
            .ok()
            .flatten()
            .map(|b| json!({"$b64": base64::engine::general_purpose::STANDARD.encode(b)}))
            .unwrap_or(Value::Null);
    }
    if let Ok(v) = r.try_get::<Option<String>, _>(i) {
        return v.map(Value::from).unwrap_or(Value::Null);
    }
    if let Ok(v) = r.try_get::<Option<i64>, _>(i) {
        return v.map(Value::from).unwrap_or(Value::Null);
    }
    if let Ok(v) = r.try_get::<Option<f64>, _>(i) {
        return v.map(Value::from).unwrap_or(Value::Null);
    }
    Value::Null
}

/// Write every table (as JSON lines) and every stored object into `dir`.
/// Objects are copied as stored (encrypted when encryption is on), so a
/// restore needs the same encryption key.
pub async fn backup(state: &State, dir: &Path) -> Result<Value> {
    std::fs::create_dir_all(dir.join("objects"))?;
    let mut counts = serde_json::Map::new();
    for t in TABLES {
        let rows = match sqlx::query(&format!("SELECT * FROM {t}")).fetch_all(&state.db.pool).await {
            Ok(r) => r,
            Err(_) => continue,
        };
        let mut f = std::io::BufWriter::new(std::fs::File::create(dir.join(format!("{t}.jsonl")))?);
        for r in &rows {
            let mut o = serde_json::Map::new();
            for (i, c) in r.columns().iter().enumerate() {
                o.insert(c.name().to_string(), cell(r, i));
            }
            serde_json::to_writer(&mut f, &Value::Object(o))?;
            f.write_all(b"\n")?;
        }
        f.flush()?;
        counts.insert(t.to_string(), json!(rows.len()));
    }
    let mut objects = 0usize;
    for (prefix, store) in state.blobs.all_backends().into_iter().chain(crate::dav::backends(state)) {
        for k in store.list().await? {
            let data = store.get_raw(&k).await?;
            let p = dir.join("objects").join(&prefix).join(k.replace('/', "_"));
            if let Some(par) = p.parent() {
                std::fs::create_dir_all(par)?;
            }
            std::fs::write(&p, data)?;
            objects += 1;
        }
    }
    let manifest = json!({"format": "picacho-backup-1", "created_at": now(), "version": env!("CARGO_PKG_VERSION"), "tables": counts, "objects": objects, "encrypted": state.blobs.encrypted()});
    std::fs::write(dir.join("manifest.json"), serde_json::to_vec_pretty(&manifest)?)?;
    Ok(manifest)
}

/// Restore a backup into an empty database (and empty stores).
pub async fn restore(state: &State, dir: &Path) -> Result<Value> {
    use base64::Engine;
    let manifest: Value = serde_json::from_slice(&std::fs::read(dir.join("manifest.json")).context("manifest.json")?)?;
    if manifest["format"] != "picacho-backup-1" {
        bail!("not a Picacho backup");
    }
    let accounts: i64 = sqlx::query("SELECT COUNT(*) FROM accounts").fetch_one(&state.db.pool).await?.get(0);
    if accounts > 0 {
        bail!("the database already has accounts; restore into a fresh data directory or database");
    }
    let mut tx = state.db.begin().await?;
    for t in TABLES {
        let path = dir.join(format!("{t}.jsonl"));
        if !path.exists() {
            continue;
        }
        sqlx::query(&format!("DELETE FROM {t}")).execute(&mut *tx.tx).await?;
        let text = std::fs::read_to_string(&path)?;
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            let Value::Object(o) = serde_json::from_str::<Value>(line)? else { continue };
            let cols: Vec<&String> = o.keys().collect();
            let ph: Vec<String> = (1..=cols.len()).map(|i| format!("${i}")).collect();
            let sql = format!("INSERT INTO {t} ({}) VALUES ({})", cols.iter().map(|c| c.as_str()).collect::<Vec<_>>().join(", "), ph.join(", "));
            let mut q = sqlx::query(&sql);
            for c in &cols {
                q = match &o[*c] {
                    Value::Null => q.bind(None::<String>),
                    Value::Number(n) if n.is_i64() => q.bind(n.as_i64()),
                    Value::Number(n) => q.bind(n.as_f64()),
                    Value::Bool(b) => q.bind(*b as i64),
                    Value::String(s) => q.bind(s.clone()),
                    Value::Object(b) if b.contains_key("$b64") => q.bind(base64::engine::general_purpose::STANDARD.decode(b["$b64"].as_str().unwrap_or("")).unwrap_or_default()),
                    other => q.bind(other.to_string()),
                };
            }
            q.execute(&mut *tx.tx).await.with_context(|| format!("restore {t}"))?;
        }
    }
    tx.commit().await?;
    if state.db.kind == crate::config::DatabaseKind::Postgres {
        // Move sequences past restored ids.
        for t in TABLES {
            let _ = sqlx::query(&format!("SELECT setval(pg_get_serial_sequence('{t}', 'id'), COALESCE((SELECT MAX(id) FROM {t}), 1))")).execute(&state.db.pool).await;
        }
    }
    let mut objects = 0;
    for (prefix, store) in state.blobs.all_backends().into_iter().chain(crate::dav::backends(state)) {
        let d = dir.join("objects").join(&prefix);
        if !d.exists() {
            continue;
        }
        for e in std::fs::read_dir(&d)? {
            let e = e?;
            let name = e.file_name().to_string_lossy().to_string();
            let key = if prefix == "attachments" { name.replacen("a_", "a/", 1) } else { name };
            store.put_raw(&key, std::fs::read(e.path())?).await?;
            objects += 1;
        }
    }
    Ok(json!({"restored_objects": objects, "tables": manifest["tables"]}))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn helpers() {
        assert_eq!(flags_from_maildir("FRS"), "\\Flagged \\Answered \\Seen");
        assert_eq!(safe_folder("a/../b"), None);
        assert_eq!(safe_folder("/Archive/2020/").as_deref(), Some("Archive/2020"));
        let (n, a, d) = parse_list(r#"* LIST (\HasNoChildren \Sent) "/" "Sent Items""#).unwrap();
        assert_eq!((n.as_str(), d), ("Sent Items", '/'));
        assert!(a.contains("\\Sent"));
        let (n, _, d) = parse_list(r#"* LIST (\HasChildren) "." INBOX"#).unwrap();
        assert_eq!((n.as_str(), d), ("INBOX", '.'));
    }
}
