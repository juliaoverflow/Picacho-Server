//! The contact directory: who may see whom, and which fields.
//!
//! Groups come from the identity provider (`oidc`), the LDAP directory
//! (`ldap`) or the console (`manual`) and are stored per account and source.
//! Contact details (phone, title, ...) come from claims or directory
//! attributes. Rules in `settings.directory` decide, per viewer, which
//! accounts appear in the read-only `addressbooks/<me>/directory/` book and
//! which fields each card carries. Administrators and `full_access_groups`
//! see everyone with every field; anyone not covered by a rule sees nobody.
use crate::db::{Account, Db};
use crate::settings::{DirectorySettings, ProfileClaim};
use crate::state::State;
use crate::util::now;
use anyhow::Result;
use serde_json::{Map, Value};
use sqlx::Row;
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// Contact details filled from claims or attributes.
pub const PROFILE_FIELDS: &[&str] = &["phone", "given_name", "family_name", "nickname", "photo", "address", "website", "birthday", "organization", "title", "department"];
/// Fields every account has.
pub const BASE_FIELDS: &[&str] = &["name", "email", "aliases", "groups"];
/// Collection name of the virtual book under `addressbooks/<me>/`.
pub const BOOK: &str = "directory";

pub fn is_field(f: &str) -> bool {
    BASE_FIELDS.contains(&f) || PROFILE_FIELDS.contains(&f)
}

pub fn all_fields() -> BTreeSet<String> {
    BASE_FIELDS.iter().chain(PROFILE_FIELDS).map(|s| s.to_string()).collect()
}

/// field -> values
pub type Profile = BTreeMap<String, Vec<String>>;

// ------------------------------------------------------------------ claims

/// Follow a dotted path ("attributes.title"). An exact key wins over a path,
/// so claims whose names contain dots still work.
fn lookup<'a>(claims: &'a Value, path: &str) -> Option<&'a Value> {
    if let Some(v) = claims.get(path) {
        return Some(v);
    }
    let mut cur = claims;
    for part in path.split('.') {
        cur = cur.get(part)?;
    }
    Some(cur)
}

fn values_of(field: &str, v: &Value) -> Vec<String> {
    let one = |x: &Value| -> Option<String> {
        let s = match x {
            Value::String(s) => s.trim().to_string(),
            Value::Number(n) => n.to_string(),
            Value::Bool(b) => b.to_string(),
            Value::Object(o) if field == "address" => match o.get("formatted").and_then(|f| f.as_str()).filter(|f| !f.trim().is_empty()) {
                Some(f) => f.trim().to_string(),
                None => ["street_address", "locality", "region", "postal_code", "country"]
                    .iter()
                    .filter_map(|k| o.get(*k).and_then(|x| x.as_str()).map(str::trim).filter(|x| !x.is_empty()))
                    .collect::<Vec<_>>()
                    .join(", "),
            },
            _ => return None,
        };
        (!s.is_empty()).then(|| s.chars().take(1000).collect())
    };
    let mut out: Vec<String> = match v {
        Value::Array(a) => a.iter().filter_map(one).collect(),
        other => one(other).into_iter().collect(),
    };
    out.dedup();
    out.truncate(20);
    out
}

/// What a claim set says about each mapped field. `None`: the claim is
/// absent (keep the stored value); `Some([])`: present but empty (clear it).
pub fn extract(claims: &Value, map: &[ProfileClaim]) -> BTreeMap<String, Option<Vec<String>>> {
    let mut out: BTreeMap<String, Option<Vec<String>>> = BTreeMap::new();
    for m in map {
        let (field, claim) = (m.field.trim(), m.claim.trim());
        if !PROFILE_FIELDS.contains(&field) || claim.is_empty() {
            continue;
        }
        let got = lookup(claims, claim).map(|v| values_of(field, v));
        // Two mappings for one field: the first present one wins.
        match out.get(field) {
            Some(Some(_)) => {}
            _ => {
                out.insert(field.to_string(), got);
            }
        }
    }
    out
}

/// Whether every mapped claim is in `claims` (else userinfo is worth asking).
pub fn claims_missing(claims: &Value, map: &[ProfileClaim]) -> bool {
    map.iter().any(|m| !m.claim.trim().is_empty() && lookup(claims, m.claim.trim()).is_none())
}

/// Apply extracted values to a stored profile.
pub fn merge(profile: &mut Profile, update: &BTreeMap<String, Option<Vec<String>>>) -> bool {
    let mut changed = false;
    for (k, v) in update {
        match v {
            None => {}
            Some(vals) if vals.is_empty() => changed |= profile.remove(k).is_some(),
            Some(vals) if profile.get(k) != Some(vals) => {
                profile.insert(k.clone(), vals.clone());
                changed = true;
            }
            Some(_) => {}
        }
    }
    changed
}

/// Groups from a claim (array, or a comma/space separated string).
pub fn claim_groups(v: Option<&Value>) -> Option<Vec<String>> {
    match v? {
        Value::Array(a) => Some(a.iter().filter_map(|x| x.as_str().map(|s| s.trim().to_string())).filter(|s| !s.is_empty()).collect()),
        Value::String(s) => Some(s.split([',', ' ']).filter(|x| !x.is_empty()).map(String::from).collect()),
        _ => None,
    }
}

// ------------------------------------------------------------------ storage

impl Db {
    /// Replace the groups an account has from one source.
    pub async fn set_account_groups(&self, account_id: i64, source: &str, groups: &[String]) -> Result<()> {
        let mut clean: Vec<String> = groups.iter().map(|g| g.trim().chars().take(512).collect::<String>()).filter(|g| !g.is_empty()).collect();
        clean.sort();
        clean.dedup();
        clean.truncate(500);
        let mut tx = self.begin().await?;
        sqlx::query("DELETE FROM account_groups WHERE account_id = $1 AND source = $2").bind(account_id).bind(source).execute(&mut *tx.tx).await?;
        for g in &clean {
            sqlx::query("INSERT INTO account_groups (account_id, name, source) VALUES ($1, $2, $3)").bind(account_id).bind(g).bind(source).execute(&mut *tx.tx).await?;
        }
        tx.commit().await
    }

    /// Add groups from one source without removing any.
    pub async fn add_account_groups(&self, account_id: i64, source: &str, groups: &[String]) -> Result<()> {
        let mut have: Vec<String> = self.account_group_sources(account_id).await?.into_iter().filter(|(_, s)| s == source).map(|(n, _)| n).collect();
        let before = have.len();
        for g in groups {
            let g = g.trim();
            if !g.is_empty() && !have.iter().any(|h| h == g) {
                have.push(g.to_string());
            }
        }
        if have.len() != before {
            self.set_account_groups(account_id, source, &have).await?;
        }
        Ok(())
    }

    /// (name, source) pairs for one account.
    pub async fn account_group_sources(&self, account_id: i64) -> Result<Vec<(String, String)>> {
        let rows = sqlx::query("SELECT name, source FROM account_groups WHERE account_id = $1 ORDER BY name, source").bind(account_id).fetch_all(&self.pool).await?;
        Ok(rows.iter().map(|r| (r.get::<String, _>(0), r.get::<String, _>(1))).collect())
    }

    /// Every account's groups (all sources, deduplicated).
    pub async fn all_account_groups(&self) -> Result<HashMap<i64, Vec<String>>> {
        let rows = sqlx::query("SELECT account_id, name FROM account_groups ORDER BY account_id, name").fetch_all(&self.pool).await?;
        let mut m: HashMap<i64, Vec<String>> = HashMap::new();
        for r in rows {
            let v = m.entry(r.get::<i64, _>(0)).or_default();
            let g: String = r.get(1);
            if !v.iter().any(|x| x.eq_ignore_ascii_case(&g)) {
                v.push(g);
            }
        }
        Ok(m)
    }

    pub async fn account_groups(&self, account_id: i64) -> Result<Vec<String>> {
        let mut v: Vec<String> = vec![];
        for (g, _) in self.account_group_sources(account_id).await? {
            if !v.iter().any(|x| x.eq_ignore_ascii_case(&g)) {
                v.push(g);
            }
        }
        Ok(v)
    }

    pub async fn account_profile(&self, account_id: i64) -> Result<Profile> {
        let r = sqlx::query("SELECT data FROM account_profiles WHERE account_id = $1").bind(account_id).fetch_optional(&self.pool).await?;
        Ok(r.and_then(|r| serde_json::from_str(&r.get::<String, _>(0)).ok()).unwrap_or_default())
    }

    pub async fn all_account_profiles(&self) -> Result<HashMap<i64, Profile>> {
        let rows = sqlx::query("SELECT account_id, data FROM account_profiles").fetch_all(&self.pool).await?;
        Ok(rows.iter().filter_map(|r| Some((r.get::<i64, _>(0), serde_json::from_str(&r.get::<String, _>(1)).ok()?))).collect())
    }

    pub async fn set_account_profile(&self, account_id: i64, p: &Profile) -> Result<()> {
        let _g = self.wl().await;
        sqlx::query(
            "INSERT INTO account_profiles (account_id, data, updated_at) VALUES ($1, $2, $3)
             ON CONFLICT (account_id) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at",
        )
        .bind(account_id)
        .bind(serde_json::to_string(p)?)
        .bind(now())
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

/// Store what a sign-in said: groups (when the claim/attribute was there) and
/// mapped contact details. Failures are logged, never block the sign-in.
pub async fn sync(state: &State, account_id: i64, source: &str, groups: Option<&[String]>, details: &BTreeMap<String, Option<Vec<String>>>) {
    let r: Result<()> = async {
        if let Some(g) = groups {
            state.db.set_account_groups(account_id, source, g).await?;
        }
        if details.values().any(|v| v.is_some()) {
            let mut p = state.db.account_profile(account_id).await?;
            if merge(&mut p, details) {
                state.db.set_account_profile(account_id, &p).await?;
            }
        }
        Ok(())
    }
    .await;
    if let Err(e) = r {
        tracing::warn!("directory sync for account {account_id}: {e:#}");
    }
}

// ------------------------------------------------------------------ policy

/// One person as the directory knows them.
#[derive(Debug, Clone)]
pub struct Entry {
    pub id: i64,
    pub email: String,
    pub name: String,
    pub active: bool,
    pub admin: bool,
    pub aliases: Vec<String>,
    pub groups: Vec<String>,
    pub profile: Profile,
}

/// Group names match case-insensitively; a DN also matches its first RDN value.
fn has_group(groups: &[String], wanted: &str) -> bool {
    let w = wanted.trim();
    !w.is_empty() && groups.iter().any(|g| g.eq_ignore_ascii_case(w) || crate::ldap::rdn_value(g).eq_ignore_ascii_case(w))
}

fn any_group(groups: &[String], wanted: &[String]) -> bool {
    wanted.iter().any(|w| has_group(groups, w))
}

/// Whether the viewer sees everyone with every field.
pub fn full_access(viewer: &Entry, s: &DirectorySettings) -> bool {
    viewer.admin || any_group(&viewer.groups, &s.full_access_groups)
}

/// The people `viewer` may see, each with the fields they may see.
pub fn visible<'a>(viewer: &Entry, entries: &'a [Entry], s: &DirectorySettings) -> Vec<(&'a Entry, BTreeSet<String>)> {
    if !s.enabled || !viewer.active {
        return vec![];
    }
    if full_access(viewer, s) {
        return entries.iter().filter(|e| e.active).map(|e| (e, all_fields())).collect();
    }
    let rules: Vec<_> = s.rules.iter().filter(|r| r.viewers.iter().any(|v| v.trim() == "*" || has_group(&viewer.groups, v))).collect();
    let mut out = vec![];
    for e in entries.iter().filter(|e| e.active) {
        let mut fields = BTreeSet::new();
        let mut seen = false;
        for r in &rules {
            if r.members.iter().any(|m| m.trim() == "*" || has_group(&e.groups, m)) {
                seen = true;
                fields.extend(r.fields.iter().filter(|f| is_field(f)).cloned());
            }
        }
        if seen {
            out.push((e, fields));
        }
    }
    out
}

/// Everyone, as `visible` needs them.
pub async fn load_entries(state: &State) -> Result<Vec<Entry>> {
    let accounts = state.db.list_accounts().await?;
    let mut groups = state.db.all_account_groups().await?;
    let mut profiles = state.db.all_account_profiles().await?;
    let aliases = state.db.list_aliases().await?;
    Ok(accounts
        .into_iter()
        .map(|a| {
            let al = aliases
                .iter()
                .filter(|x| x.active && x.destination.split([',', ' ']).filter(|d| !d.trim().is_empty()).all(|d| d.trim().eq_ignore_ascii_case(&a.email)))
                .map(|x| x.source.clone())
                .filter(|s| !s.starts_with('@'))
                .collect();
            Entry { id: a.id, email: a.email.clone(), name: a.display_name.clone(), active: a.active, admin: a.is_admin(), aliases: al, groups: groups.remove(&a.id).unwrap_or_default(), profile: profiles.remove(&a.id).unwrap_or_default() }
        })
        .collect())
}

/// The cards an account sees: (account id, vCard), ordered by id.
pub async fn cards_for(state: &State, viewer: &Account) -> Result<Vec<(i64, String)>> {
    let s = state.settings().directory.clone();
    if !s.enabled {
        return Ok(vec![]);
    }
    let entries = load_entries(state).await?;
    let Some(me) = entries.iter().find(|e| e.id == viewer.id) else { return Ok(vec![]) };
    let mut v: Vec<(i64, String)> = visible(me, &entries, &s).into_iter().map(|(e, f)| (e.id, vcard(e, &f))).collect();
    v.sort_by_key(|x| x.0);
    Ok(v)
}

/// One logged change: `added` is the change that made the person visible
/// (0 when unknown, from before it was tracked).
#[derive(Debug, Clone)]
pub struct DirChange {
    pub person: i64,
    pub deleted: bool,
    pub added: i64,
}

/// A viewer's directory as of now, with change tracking.
pub struct Book {
    /// (account id, etag, vCard), ordered by id.
    pub cards: Vec<(i64, String, String)>,
    /// Latest change counter for this viewer (0: never changed).
    pub state: i64,
}

fn card_etag(text: &str) -> String {
    format!("\"{}\"", &crate::util::sha256_hex(text.as_bytes())[..32])
}

impl Db {
    async fn directory_seen(&self, viewer: i64) -> Result<HashMap<i64, String>> {
        let rows = sqlx::query("SELECT person_id, etag FROM directory_seen WHERE viewer_id = $1").bind(viewer).fetch_all(&self.pool).await?;
        Ok(rows.iter().map(|r| (r.get::<i64, _>(0), r.get::<String, _>(1))).collect())
    }

    pub async fn directory_state(&self, viewer: i64) -> Result<i64> {
        let r = sqlx::query("SELECT CAST(COALESCE(MAX(id), 0) AS BIGINT) FROM directory_changes WHERE viewer_id = $1").bind(viewer).fetch_one(&self.pool).await?;
        Ok(r.get(0))
    }

    /// (person, deleted) changed after `since`, latest state per person, in change order.
    pub async fn directory_changes_since(&self, viewer: i64, since: i64) -> Result<Vec<(i64, bool)>> {
        Ok(self.directory_changes_detail(viewer, since).await?.into_iter().map(|c| (c.person, c.deleted)).collect())
    }

    /// Like `directory_changes_since`, with the change that made each person visible.
    pub async fn directory_changes_detail(&self, viewer: i64, since: i64) -> Result<Vec<DirChange>> {
        let rows = sqlx::query("SELECT person_id, deleted, added FROM directory_changes WHERE viewer_id = $1 AND id > $2 ORDER BY id").bind(viewer).bind(since).fetch_all(&self.pool).await?;
        Ok(rows.iter().map(|r| DirChange { person: r.get(0), deleted: r.get::<i64, _>(1) != 0, added: r.get(2) }).collect())
    }

    /// Replace the snapshot and log what changed, in one transaction. Only
    /// the latest change per person is kept, so the log never outgrows the
    /// number of accounts and any earlier state can still be synced from.
    async fn directory_record(&self, viewer: i64, seen: &HashMap<i64, String>, now_cards: &[(i64, String, String)]) -> Result<()> {
        let mut tx = self.begin().await?;
        let t = now();
        let current: HashMap<i64, &String> = now_cards.iter().map(|c| (c.0, &c.1)).collect();
        // When each still-visible person became visible (kept across updates).
        let prior: HashMap<i64, i64> = sqlx::query("SELECT person_id, added FROM directory_changes WHERE viewer_id = $1 AND deleted = 0")
            .bind(viewer)
            .fetch_all(&mut *tx.tx)
            .await?
            .iter()
            .map(|r| (r.get::<i64, _>(0), r.get::<i64, _>(1)))
            .collect();
        for (pid, etag) in &current {
            if seen.get(pid) != Some(*etag) {
                sqlx::query("DELETE FROM directory_seen WHERE viewer_id = $1 AND person_id = $2").bind(viewer).bind(pid).execute(&mut *tx.tx).await?;
                sqlx::query("INSERT INTO directory_seen (viewer_id, person_id, etag) VALUES ($1, $2, $3)").bind(viewer).bind(pid).bind(*etag).execute(&mut *tx.tx).await?;
                sqlx::query("DELETE FROM directory_changes WHERE viewer_id = $1 AND person_id = $2").bind(viewer).bind(pid).execute(&mut *tx.tx).await?;
                let id: i64 = sqlx::query("INSERT INTO directory_changes (viewer_id, person_id, deleted, ts) VALUES ($1, $2, 0, $3) RETURNING id")
                    .bind(viewer)
                    .bind(pid)
                    .bind(t)
                    .fetch_one(&mut *tx.tx)
                    .await?
                    .get(0);
                // Newly visible: this change; already visible: keep when that was.
                let added = if seen.contains_key(pid) { prior.get(pid).copied().filter(|a| *a > 0).unwrap_or(0) } else { id };
                sqlx::query("UPDATE directory_changes SET added = $1 WHERE id = $2").bind(added).bind(id).execute(&mut *tx.tx).await?;
            }
        }
        for pid in seen.keys().filter(|p| !current.contains_key(p)) {
            sqlx::query("DELETE FROM directory_seen WHERE viewer_id = $1 AND person_id = $2").bind(viewer).bind(pid).execute(&mut *tx.tx).await?;
            sqlx::query("DELETE FROM directory_changes WHERE viewer_id = $1 AND person_id = $2").bind(viewer).bind(pid).execute(&mut *tx.tx).await?;
            // Keep when they became visible, so clients that never saw them aren't told they're gone.
            sqlx::query("INSERT INTO directory_changes (viewer_id, person_id, deleted, ts, added) VALUES ($1, $2, 1, $3, $4)")
                .bind(viewer)
                .bind(pid)
                .bind(t)
                .bind(prior.get(pid).copied().unwrap_or(0))
                .execute(&mut *tx.tx)
                .await?;
        }
        tx.commit().await
    }
}

/// The viewer's cards now; differences from the last look are logged so
/// sync tokens and JMAP states move forward instead of forcing a resync.
pub async fn refresh(state: &State, viewer: &Account) -> Result<Book> {
    let cards: Vec<(i64, String, String)> = cards_for(state, viewer).await?.into_iter().map(|(id, text)| (id, card_etag(&text), text)).collect();
    let seen = state.db.directory_seen(viewer.id).await?;
    let changed = cards.len() != seen.len() || cards.iter().any(|c| seen.get(&c.0) != Some(&c.1));
    if changed {
        // Concurrent refreshes may both log the same change; that only repeats
        // an entry in a later sync, which clients accept.
        state.db.directory_record(viewer.id, &seen, &cards).await?;
    }
    Ok(Book { cards, state: state.db.directory_state(viewer.id).await? })
}

/// What a viewer sees, as JSON (console preview).
pub fn preview(viewer: &Entry, entries: &[Entry], s: &DirectorySettings) -> Value {
    let people: Vec<Value> = visible(viewer, entries, s)
        .into_iter()
        .map(|(e, f)| {
            let mut o = Map::new();
            o.insert("id".into(), e.id.into());
            for k in &f {
                let v: Value = match k.as_str() {
                    "name" => e.name.clone().into(),
                    "email" => e.email.clone().into(),
                    "aliases" => e.aliases.clone().into(),
                    "groups" => e.groups.clone().into(),
                    other => match e.profile.get(other) {
                        Some(v) => v.clone().into(),
                        None => continue,
                    },
                };
                o.insert(k.clone(), v);
            }
            serde_json::json!({"person": o, "fields": f})
        })
        .collect();
    serde_json::json!({"enabled": s.enabled, "full_access": s.enabled && viewer.active && full_access(viewer, s), "people": people})
}

// ------------------------------------------------------------------ vCard

/// Escape a vCard text value (RFC 6350 3.4).
fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => o.push_str("\\\\"),
            ',' => o.push_str("\\,"),
            ';' => o.push_str("\\;"),
            '\n' => o.push_str("\\n"),
            '\r' => {}
            c if c.is_control() => {}
            c => o.push(c),
        }
    }
    o
}

/// A quoted parameter value (RFC 6868 caret encoding).
fn param(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '^' => o.push_str("^^"),
            '\n' => o.push_str("^n"),
            '"' => o.push_str("^'"),
            c if c.is_control() => {}
            c => o.push(c),
        }
    }
    o
}

/// Fold a content line at 75 octets without splitting characters.
fn fold(line: &str, out: &mut String) {
    let mut n = 0;
    for c in line.chars() {
        let l = c.len_utf8();
        if n + l > 75 {
            out.push_str("\r\n ");
            n = 1;
        }
        out.push(c);
        n += l;
    }
    out.push_str("\r\n");
}

/// OIDC birthdate (YYYY-MM-DD, YYYY, or 0000-MM-DD when the year is withheld) as a vCard date.
fn bday(b: &str) -> Option<String> {
    let parts: Vec<&str> = b.trim().split('-').collect();
    if !parts.iter().all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit())) {
        return None;
    }
    match parts.as_slice() {
        [y] if y.len() == 4 => Some(y.to_string()),
        ["0000", m, d] if m.len() == 2 && d.len() == 2 => Some(format!("--{m}{d}")),
        [y, m, d] if y.len() == 4 && m.len() == 2 && d.len() == 2 => Some(format!("{y}{m}{d}")),
        _ => None,
    }
}

fn safe_uri(u: &str) -> Option<String> {
    let p = url::Url::parse(u.trim()).ok()?;
    matches!(p.scheme(), "http" | "https").then(|| p.to_string()).filter(|s| !s.chars().any(|c| c.is_control()))
}

/// A vCard 4.0 for one person with only the allowed fields.
pub fn vcard(e: &Entry, fields: &BTreeSet<String>) -> String {
    let has = |f: &str| fields.contains(f);
    let p = |f: &str| -> Vec<String> { if has(f) { e.profile.get(f).cloned().unwrap_or_default() } else { vec![] } };
    let first = |f: &str| p(f).into_iter().next().unwrap_or_default();
    let mut lines = vec!["BEGIN:VCARD".to_string(), "VERSION:4.0".to_string(), "PRODID:-//Picacho Server//Directory//EN".to_string(), format!("UID:urn:picacho:account:{}", e.id), "KIND:individual".to_string()];
    let (given, family) = (first("given_name"), first("family_name"));
    let fn_ = [
        if has("name") { e.name.trim().to_string() } else { String::new() },
        [given.as_str(), family.as_str()].iter().filter(|x| !x.is_empty()).cloned().collect::<Vec<_>>().join(" "),
        first("nickname"),
        if has("email") { e.email.clone() } else { String::new() },
    ]
    .into_iter()
    .find(|x| !x.trim().is_empty())
    .unwrap_or_else(|| "Unknown".into());
    lines.push(format!("FN:{}", esc(&fn_)));
    if !given.is_empty() || !family.is_empty() {
        lines.push(format!("N:{};{};;;", esc(&family), esc(&given)));
    }
    if has("email") {
        lines.push(format!("EMAIL;PREF=1:{}", esc(&e.email)));
    }
    if has("aliases") {
        for a in &e.aliases {
            lines.push(format!("EMAIL:{}", esc(a)));
        }
    }
    for t in p("phone") {
        lines.push(format!("TEL;VALUE=text;TYPE=voice:{}", esc(&t)));
    }
    if let Some(n) = p("nickname").first() {
        lines.push(format!("NICKNAME:{}", esc(n)));
    }
    if let Some(u) = p("photo").iter().find_map(|u| safe_uri(u)) {
        lines.push(format!("PHOTO:{u}"));
    }
    for a in p("address") {
        lines.push(format!("ADR;LABEL=\"{}\":;;{};;;;", param(&a), esc(&a)));
    }
    for u in p("website").iter().filter_map(|u| safe_uri(u)) {
        lines.push(format!("URL:{u}"));
    }
    if let Some(b) = p("birthday").first().and_then(|b| bday(b)) {
        lines.push(format!("BDAY:{b}"));
    }
    let (org, dept) = (first("organization"), first("department"));
    if !org.is_empty() || !dept.is_empty() {
        lines.push(if dept.is_empty() { format!("ORG:{}", esc(&org)) } else { format!("ORG:{};{}", esc(&org), esc(&dept)) });
    }
    if let Some(t) = p("title").first() {
        lines.push(format!("TITLE:{}", esc(t)));
    }
    if has("groups") && !e.groups.is_empty() {
        lines.push(format!("CATEGORIES:{}", e.groups.iter().map(|g| esc(crate::ldap::rdn_value(g))).collect::<Vec<_>>().join(",")));
    }
    lines.push("END:VCARD".into());
    let mut out = String::new();
    for l in lines {
        fold(&l, &mut out);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::DirectoryRule;
    use serde_json::json;

    fn entry(id: i64, groups: &[&str]) -> Entry {
        Entry {
            id,
            email: format!("u{id}@x.test"),
            name: format!("User {id}"),
            active: true,
            admin: false,
            aliases: vec![],
            groups: groups.iter().map(|s| s.to_string()).collect(),
            profile: [("phone".to_string(), vec![format!("+1 555 000{id}")])].into_iter().collect(),
        }
    }

    fn rule(v: &[&str], m: &[&str], f: &[&str]) -> DirectoryRule {
        let s = |x: &[&str]| x.iter().map(|s| s.to_string()).collect();
        DirectoryRule { viewers: s(v), members: s(m), fields: s(f) }
    }

    fn settings(rules: Vec<DirectoryRule>) -> DirectorySettings {
        DirectorySettings { enabled: true, full_access_groups: vec!["Staff".into()], rules }
    }

    fn ids(v: &[(&Entry, BTreeSet<String>)]) -> Vec<i64> {
        v.iter().map(|x| x.0.id).collect()
    }

    #[test]
    fn family_sees_family_only() {
        let all = vec![entry(1, &["family"]), entry(2, &["Family"]), entry(3, &["work"]), entry(4, &[])];
        let s = settings(vec![rule(&["family"], &["family"], &["name", "email"])]);
        let v = visible(&all[0], &all, &s);
        assert_eq!(ids(&v), vec![1, 2]);
        assert!(v[1].1.contains("email") && !v[1].1.contains("phone"));
        assert!(visible(&all[2], &all, &s).is_empty());
        assert!(visible(&all[3], &all, &s).is_empty());
    }

    #[test]
    fn admins_and_full_access_see_everything() {
        let mut all = vec![entry(1, &[]), entry(2, &["x"]), entry(3, &["cn=staff,ou=groups,dc=x"])];
        all[0].admin = true;
        all[1].active = false;
        let s = settings(vec![]);
        let v = visible(&all[0], &all, &s);
        assert_eq!(ids(&v), vec![1, 3]);
        assert_eq!(v[0].1, all_fields());
        // DN membership matches the group's name.
        assert_eq!(ids(&visible(&all[2], &all, &s)), vec![1, 3]);
    }

    #[test]
    fn disabled_or_inactive_viewer_sees_nothing() {
        let mut all = vec![entry(1, &["a"]), entry(2, &["a"])];
        all[0].admin = true;
        let mut s = settings(vec![rule(&["a"], &["a"], &["name"])]);
        s.enabled = false;
        assert!(visible(&all[0], &all, &s).is_empty());
        s.enabled = true;
        all[1].active = false;
        assert!(visible(&all[1], &all, &s).is_empty());
    }

    #[test]
    fn fields_union_and_wildcard() {
        let all = vec![entry(1, &["a", "b"]), entry(2, &["a"]), entry(3, &["c"])];
        let s = settings(vec![rule(&["a"], &["a"], &["name"]), rule(&["b"], &["a"], &["phone", "bogus"]), rule(&["*"], &["*"], &["email"])]);
        let v = visible(&all[0], &all, &s);
        assert_eq!(ids(&v), vec![1, 2, 3]);
        let f2: Vec<_> = v[1].1.iter().cloned().collect();
        assert_eq!(f2, vec!["email", "name", "phone"]);
        let f3: Vec<_> = v[2].1.iter().cloned().collect();
        assert_eq!(f3, vec!["email"]);
        // Someone outside a and b still gets the wildcard rule.
        assert_eq!(ids(&visible(&all[2], &all, &s)), vec![1, 2, 3]);
    }

    #[test]
    fn claim_extraction() {
        let c = json!({
            "phone_number": "+1 555 1234",
            "attributes": {"title": "Chef", "phones": ["1", "2", ""]},
            "a.b": "dotted key",
            "nickname": null,
            "address": {"street_address": "1 Main St", "locality": "Tucson", "country": "US"},
            "website": "",
        });
        let map: Vec<ProfileClaim> = [("phone", "phone_number"), ("title", "attributes.title"), ("organization", "a.b"), ("nickname", "nickname"), ("address", "address"), ("website", "website"), ("birthday", "birthdate"), ("department", "attributes.phones"), ("bogus", "x")]
            .iter()
            .map(|(f, c)| ProfileClaim { field: f.to_string(), claim: c.to_string() })
            .collect();
        let x = extract(&c, &map);
        assert_eq!(x["phone"], Some(vec!["+1 555 1234".to_string()]));
        assert_eq!(x["title"], Some(vec!["Chef".to_string()]));
        assert_eq!(x["organization"], Some(vec!["dotted key".to_string()]));
        assert_eq!(x["nickname"], Some(vec![]));
        assert_eq!(x["address"], Some(vec!["1 Main St, Tucson, US".to_string()]));
        assert_eq!(x["website"], Some(vec![]));
        assert_eq!(x["birthday"], None);
        assert_eq!(x["department"], Some(vec!["1".to_string(), "2".to_string()]));
        assert!(!x.contains_key("bogus"));
        assert!(claims_missing(&c, &map));
        // Absent keeps, empty clears.
        let mut p: Profile = [("birthday".to_string(), vec!["2000-01-01".to_string()]), ("nickname".to_string(), vec!["old".to_string()])].into_iter().collect();
        assert!(merge(&mut p, &x));
        assert!(p.contains_key("birthday") && !p.contains_key("nickname"));
        assert_eq!(p["phone"], vec!["+1 555 1234".to_string()]);
        assert!(!merge(&mut p, &x));
    }

    #[test]
    fn vcard_filters_and_escapes() {
        let mut e = entry(7, &["cn=family,ou=g,dc=x"]);
        e.name = "Ann, \"A\"; B\nC".into();
        e.aliases = vec!["ann@x.test".into()];
        e.profile.insert("photo".into(), vec!["javascript:alert(1)".into()]);
        e.profile.insert("website".into(), vec!["https://ann.example/".into()]);
        e.profile.insert("title".into(), vec!["x".repeat(200)]);
        let f: BTreeSet<String> = ["name", "phone", "photo", "website", "title", "groups"].iter().map(|s| s.to_string()).collect();
        let v = vcard(&e, &f);
        assert!(v.contains("UID:urn:picacho:account:7\r\n"));
        assert!(v.contains("FN:Ann\\, \"A\"\\; B\\nC\r\n"));
        assert!(v.contains("TEL;VALUE=text;TYPE=voice:+1 555 0007"));
        assert!(!v.contains("EMAIL") && !v.contains("PHOTO") && !v.contains("javascript"));
        assert!(v.contains("URL:https://ann.example/"));
        assert!(v.contains("CATEGORIES:family\r\n"));
        assert!(v.split("\r\n").all(|l| l.len() <= 75));
        assert!(v.contains("\r\n x"));
        assert_eq!(bday("1990-04-02").as_deref(), Some("19900402"));
        assert_eq!(bday("0000-04-02").as_deref(), Some("--0402"));
        assert_eq!(bday("1990").as_deref(), Some("1990"));
        assert_eq!(bday("next tuesday"), None);
        let mut a = entry(8, &[]);
        a.profile.insert("address".into(), vec!["1 \"Main\" St\nTucson; AZ".into()]);
        let v = vcard(&a, &["address".to_string()].into_iter().collect());
        assert!(v.replace("\r\n ", "").contains("ADR;LABEL=\"1 ^'Main^' St^nTucson; AZ\":;;1 \"Main\" St\\nTucson\\; AZ;;;;"), "{v}");
        let none = vcard(&e, &BTreeSet::new());
        assert!(none.contains("FN:Unknown") && !none.contains("TEL") && !none.contains("CATEGORIES"));
    }
}
