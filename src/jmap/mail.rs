//! JMAP Mail (RFC 8621), Submission and Quota methods.
//!
//! Ids: accounts `a<n>`, mailboxes `m<n>`, emails `e<n>`, threads `t<n>`,
//! identities `i<n>`; blobs `b<hex>` (whole message), `p<email>_<part>`
//! (decoded body part) and `u<n>` (upload). Each Email lives in exactly one
//! mailbox (`maxMailboxesPerEmail` = 1).
use super::{account_id, Ctx, MethodError, MAX_OBJECTS};
use crate::db::{Account, Mailbox, MessageRow};
use crate::mime::{self, EmailAddr, Meta, Part};
use crate::state::State;
use base64::Engine;
use serde_json::{json, Map, Value};
use std::collections::{HashMap, HashSet};

type R = Result<Vec<(String, Value)>, MethodError>;

pub async fn call(ctx: &mut Ctx, name: &str, args: &Value) -> R {
    let need = |cap: &str| -> Result<(), MethodError> {
        if ctx.using.iter().any(|u| u == cap) {
            Ok(())
        } else {
            Err(MethodError("unknownMethod", format!("{cap} not in 'using'")))
        }
    };
    if name == "Core/echo" {
        return Ok(vec![(name.into(), args.clone())]);
    }
    if name.starts_with("VacationResponse/") || name.starts_with("SieveScript/") {
        return super::extra::call(ctx, name, args).await;
    }
    // JMAP for Calendars and Contacts, and Principals (RFC 9670).
    let dav_cap = match name.split('/').next().unwrap_or("") {
        "Calendar" | "CalendarEvent" | "ParticipantIdentity" | "CalendarEventNotification" => Some(super::CALENDARS),
        "AddressBook" | "ContactCard" => Some(super::CONTACTS),
        "Principal" | "ShareNotification" => Some(super::PRINCIPALS),
        _ => None,
    };
    if let Some(cap) = dav_cap {
        need(cap)?;
        ctx.check_account(args)?;
        if ctx.read_only && (name.ends_with("/set") || name.ends_with("/copy")) {
            return Err(MethodError("forbidden", "This token has read-only access.".into()));
        }
        return super::dav::call(ctx, name, args).await;
    }
    match name {
        "Mailbox/get" | "Mailbox/changes" | "Mailbox/query" | "Mailbox/queryChanges" | "Mailbox/set" | "Email/get"
        | "Email/changes" | "Email/query" | "Email/queryChanges" | "Email/set" | "Email/import" | "Thread/get"
        | "Thread/changes" | "SearchSnippet/get" => need(super::MAIL)?,
        "Identity/get" | "Identity/set" | "Identity/changes" | "EmailSubmission/get" | "EmailSubmission/set" | "EmailSubmission/query"
        | "EmailSubmission/changes" => need(super::SUBMISSION)?,
        "Quota/get" | "Quota/changes" => need(super::QUOTA)?,
        "Blob/upload" | "Blob/get" | "Blob/lookup" => need(super::BLOB)?,
        "Email/parse" | "Email/copy" | "Blob/copy" => need(super::MAIL)?,
        "MDN/send" | "MDN/parse" => need(super::MDN)?,
        "Quota/query" => need(super::QUOTA)?,
        "EmailSubmission/queryChanges" => need(super::SUBMISSION)?,
        _ => return Err(MethodError("unknownMethod", format!("Unknown method {name}"))),
    }
    ctx.check_account(args)?;
    if ctx.read_only && matches!(name, "Mailbox/set" | "Email/set" | "Email/import" | "EmailSubmission/set" | "Identity/set" | "Blob/upload" | "MDN/send") {
        return Err(MethodError("forbidden", "This token has read-only access.".into()));
    }
    let one = |v: Value| Ok(vec![(name.to_string(), v)]);
    match name {
        "Mailbox/get" => one(mailbox_get(ctx, args).await?),
        "Mailbox/changes" => one(changes(ctx, args, "Mailbox").await?),
        "Mailbox/query" => one(mailbox_query(ctx, args).await?),
        "Mailbox/set" => one(mailbox_set(ctx, args).await?),
        "Email/get" => one(email_get(ctx, args).await?),
        "Email/changes" => one(changes(ctx, args, "Email").await?),
        "Email/query" => one(email_query(ctx, args).await?),
        "Email/set" => one(email_set(ctx, args).await?),
        "Email/import" => one(email_import(ctx, args).await?),
        "Thread/get" => one(thread_get(ctx, args).await?),
        "Thread/changes" => one(changes(ctx, args, "Thread").await?),
        "SearchSnippet/get" => one(snippets(ctx, args).await?),
        "Identity/get" => one(super::submission::identity_get(ctx, args).await?),
        "Identity/set" => one(super::submission::identity_set(ctx, args).await?),
        "Identity/changes" => one(changes(ctx, args, "Identity").await?),
        "EmailSubmission/changes" => one(changes(ctx, args, "EmailSubmission").await?),
        "Quota/changes" => {
            let st = state_str(ctx).await?;
            let since = args.get("sinceState").and_then(|v| v.as_str()).unwrap_or("");
            one(json!({"accountId": account_id(&ctx.account), "oldState": since, "newState": st,
                "hasMoreChanges": false, "created": [], "updated": [], "destroyed": []}))
        }
        "EmailSubmission/get" => one(super::submission::submission_get(ctx, args).await?),
        "EmailSubmission/query" => one(super::submission::submission_query(ctx, args).await?),
        "EmailSubmission/set" => super::submission::submission_set(ctx, args).await,
        "Blob/upload" => one(super::blob::blob_upload(ctx, args).await?),
        "Blob/get" => one(super::blob::blob_get(ctx, args).await?),
        "Blob/lookup" => one(super::blob::blob_lookup(ctx, args).await?),
        "MDN/parse" => one(super::blob::mdn_parse(ctx, args).await?),
        "Quota/query" => {
            let types: Vec<String> = args.get("filter").and_then(|f| f.get("types")).and_then(|t| t.as_array()).into_iter().flatten().filter_map(|x| x.as_str().map(String::from)).collect();
            let ids: Vec<&str> = if types.is_empty() || types.iter().any(|t| t == "Email" || t == "Mail") { vec!["q0"] } else { vec![] };
            one(json!({"accountId": account_id(&ctx.account), "queryState": state_str(ctx).await?, "canCalculateChanges": false, "position": 0, "ids": ids, "total": ids.len()}))
        }
        // One account per sign-in: there's nowhere else to copy from.
        "Email/copy" | "Blob/copy" => Err(MethodError("fromAccountNotFound", "This sign-in reaches only its own account.".into())),
        "Mailbox/queryChanges" | "EmailSubmission/queryChanges" => Err(MethodError("cannotCalculateChanges", "Run the query again.".into())),
        "Email/parse" => one(super::blob::email_parse(ctx, args).await?),
        "MDN/send" => super::blob::mdn_send(ctx, args).await,
        "Quota/get" => one(quota_get(ctx, args).await?),
        "Email/queryChanges" => one(email_query_changes(ctx, args).await?),
        _ => unreachable!(),
    }
}

pub(super) async fn state_str(ctx: &Ctx) -> Result<String, MethodError> {
    Ok(ctx.state.db.jmap_state(ctx.account.id).await?.to_string())
}

pub(super) fn num_id(s: &str, prefix: char) -> Option<i64> {
    s.strip_prefix(prefix)?.parse().ok()
}

pub(super) fn utc(ts: i64) -> String {
    use chrono::TimeZone;
    chrono::Utc.timestamp_opt(ts, 0).single().unwrap_or_default().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

fn parse_utc(s: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(s).ok().map(|d| d.timestamp())
}

/// Requested ids (`null` means all) and the properties to return.
pub(super) fn ids_arg(ctx: &Ctx, args: &Value) -> Result<Option<Vec<String>>, MethodError> {
    match args.get("ids") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(a)) => {
            if a.len() > MAX_OBJECTS {
                return Err(MethodError("requestTooLarge", "Too many ids.".into()));
            }
            Ok(Some(a.iter().filter_map(|v| v.as_str().map(|s| ctx.id(s))).collect()))
        }
        _ => Err(MethodError::invalid("ids must be an array or null")),
    }
}

pub(super) fn props_arg(args: &Value, default: &[&str]) -> Vec<String> {
    match args.get("properties").and_then(|v| v.as_array()) {
        Some(p) => {
            let mut v: Vec<String> = p.iter().filter_map(|x| x.as_str().map(String::from)).collect();
            if !v.iter().any(|x| x == "id") {
                v.push("id".into());
            }
            v
        }
        None => default.iter().map(|s| s.to_string()).collect(),
    }
}

pub(super) fn pick(obj: Map<String, Value>, props: &[String]) -> Value {
    Value::Object(obj.into_iter().filter(|(k, _)| props.iter().any(|p| p == k)).collect())
}

// ---------------------------------------------------------------- keywords

pub fn flag_to_keyword(f: &str) -> Option<String> {
    Some(match f.to_ascii_lowercase().as_str() {
        "\\seen" => "$seen".into(),
        "\\flagged" => "$flagged".into(),
        "\\answered" => "$answered".into(),
        "\\draft" => "$draft".into(),
        "\\deleted" | "\\recent" => return None,
        other if other.starts_with('\\') => return None,
        other => other.to_string(),
    })
}

pub fn keyword_to_flag(k: &str) -> Option<String> {
    let k = k.to_ascii_lowercase();
    Some(match k.as_str() {
        "$seen" => "\\Seen".into(),
        "$flagged" => "\\Flagged".into(),
        "$answered" => "\\Answered".into(),
        "$draft" => "\\Draft".into(),
        _ => {
            if k.is_empty() || k.len() > 128 || !k.bytes().all(|c| c > b' ' && c < 0x7f && !b"(){%*\"\\]".contains(&c)) {
                return None;
            }
            k
        }
    })
}

fn keywords_of(flags: &str) -> Map<String, Value> {
    flags.split_whitespace().filter_map(flag_to_keyword).map(|k| (k, Value::Bool(true))).collect()
}

fn has_keyword(flags: &str, kw: &str) -> bool {
    keywords_of(flags).contains_key(&kw.to_ascii_lowercase())
}

// ---------------------------------------------------------------- mailboxes

fn role_of(m: &Mailbox) -> Option<&'static str> {
    if m.name == "INBOX" {
        return Some("inbox");
    }
    Some(match m.special_use.as_str() {
        "\\Sent" => "sent",
        "\\Drafts" => "drafts",
        "\\Trash" => "trash",
        "\\Junk" => "junk",
        "\\Archive" => "archive",
        "\\All" => "all",
        "\\Flagged" => "flagged",
        _ => return None,
    })
}

fn special_of(role: &str) -> Option<&'static str> {
    Some(match role {
        "sent" => "\\Sent",
        "drafts" => "\\Drafts",
        "trash" => "\\Trash",
        "junk" => "\\Junk",
        "archive" => "\\Archive",
        "all" => "\\All",
        "flagged" => "\\Flagged",
        _ => return None,
    })
}

fn sort_order(m: &Mailbox) -> i64 {
    match role_of(m) {
        Some("inbox") => 1,
        Some("drafts") => 2,
        Some("sent") => 3,
        Some("archive") => 4,
        Some("junk") => 5,
        Some("trash") => 6,
        Some(_) => 7,
        None => 10,
    }
}

fn parent_name(name: &str) -> Option<&str> {
    name.rsplit_once('/').map(|(p, _)| p)
}

async fn mailbox_json(ctx: &Ctx, m: &Mailbox, all: &[Mailbox], subs: &HashSet<String>) -> Result<Map<String, Value>, MethodError> {
    let (total, unread, _) = ctx.state.db.mailbox_counts(m.id).await?;
    let (threads, unread_threads) = ctx.state.db.thread_counts(m.id).await?;
    let parent = parent_name(&m.name).and_then(|p| all.iter().find(|x| x.name == p)).map(|p| format!("m{}", p.id));
    let leaf = m.name.rsplit('/').next().unwrap_or(&m.name).to_string();
    let inbox = m.name == "INBOX";
    let mut o = Map::new();
    o.insert("id".into(), json!(format!("m{}", m.id)));
    o.insert("name".into(), json!(if inbox { "Inbox".to_string() } else { leaf }));
    o.insert("parentId".into(), json!(parent));
    o.insert("role".into(), json!(role_of(m)));
    o.insert("sortOrder".into(), json!(sort_order(m)));
    o.insert("totalEmails".into(), json!(total));
    o.insert("unreadEmails".into(), json!(unread));
    o.insert("totalThreads".into(), json!(threads));
    o.insert("unreadThreads".into(), json!(unread_threads));
    o.insert(
        "myRights".into(),
        json!({"mayReadItems": true, "mayAddItems": true, "mayRemoveItems": true, "maySetSeen": true,
               "maySetKeywords": true, "mayCreateChild": true, "mayRename": !inbox, "mayDelete": !inbox, "maySubmit": true}),
    );
    o.insert("isSubscribed".into(), json!(subs.contains(&m.name)));
    Ok(o)
}

async fn mailbox_get(ctx: &mut Ctx, args: &Value) -> Result<Value, MethodError> {
    let all = ctx.state.db.list_mailboxes(ctx.account.id).await?;
    let subs: HashSet<String> = ctx.state.db.subscriptions(ctx.account.id).await?.into_iter().collect();
    let props = props_arg(
        args,
        &["id", "name", "parentId", "role", "sortOrder", "totalEmails", "unreadEmails", "totalThreads", "unreadThreads", "myRights", "isSubscribed"],
    );
    let mut list = vec![];
    let mut not_found = vec![];
    match ids_arg(ctx, args)? {
        None => {
            for m in &all {
                list.push(pick(mailbox_json(ctx, m, &all, &subs).await?, &props));
            }
        }
        Some(ids) => {
            for id in ids {
                match num_id(&id, 'm').and_then(|n| all.iter().find(|m| m.id == n)) {
                    Some(m) => list.push(pick(mailbox_json(ctx, m, &all, &subs).await?, &props)),
                    None => not_found.push(id),
                }
            }
        }
    }
    Ok(json!({"accountId": account_id(&ctx.account), "state": state_str(ctx).await?, "list": list, "notFound": not_found}))
}

async fn changes(ctx: &mut Ctx, args: &Value, kind: &str) -> Result<Value, MethodError> {
    let since_s = args.get("sinceState").and_then(|v| v.as_str()).ok_or_else(|| MethodError::invalid("sinceState is required"))?;
    let since: i64 = since_s.parse().map_err(|_| MethodError("cannotCalculateChanges", "Unknown state.".into()))?;
    let max = args.get("maxChanges").and_then(|v| v.as_i64()).unwrap_or(5000).clamp(1, 50_000);
    let Some((rows, new_state, more)) = ctx.state.db.changes_since(ctx.account.id, kind, since, max).await? else {
        return Err(MethodError("cannotCalculateChanges", "State too old; fetch everything again.".into()));
    };
    let prefix = match kind {
        "Mailbox" => "m",
        "Thread" => "t",
        "EmailSubmission" => "s",
        "Identity" => "j",
        _ => "e",
    };
    // Built-in identities' settings are rows too, but keep their own ids.
    let builtin: HashMap<i64, String> = if kind == "Identity" {
        ctx.state.db.identities(ctx.account.id).await?.into_iter().filter(|r| !r.builtin.is_empty()).map(|r| (r.id, r.builtin)).collect()
    } else {
        HashMap::new()
    };
    let mut first_op: HashMap<i64, String> = HashMap::new();
    let mut last_op: HashMap<i64, String> = HashMap::new();
    let mut order = vec![];
    for (id, op) in rows {
        if !first_op.contains_key(&id) {
            first_op.insert(id, op.clone());
            order.push(id);
        }
        last_op.insert(id, op);
    }
    let (mut created, mut updated, mut destroyed) = (vec![], vec![], vec![]);
    for id in order {
        let (f, l) = (first_op[&id].as_str(), last_op[&id].as_str());
        let sid = builtin.get(&id).cloned().unwrap_or_else(|| format!("{prefix}{id}"));
        // A built-in identity existed before its settings row did.
        let f = if f == "c" && builtin.contains_key(&id) { "u" } else { f };
        match (f, l) {
            ("c", "d") => {}
            ("c", _) => created.push(sid),
            (_, "d") => destroyed.push(sid),
            _ => updated.push(sid),
        }
    }
    let mut out = json!({
        "accountId": account_id(&ctx.account), "oldState": since_s, "newState": new_state.to_string(),
        "hasMoreChanges": more, "created": created, "updated": updated, "destroyed": destroyed,
    });
    if kind == "Mailbox" {
        out["updatedProperties"] = Value::Null;
    }
    Ok(out)
}

async fn mailbox_query(ctx: &mut Ctx, args: &Value) -> Result<Value, MethodError> {
    let all = ctx.state.db.list_mailboxes(ctx.account.id).await?;
    let subs: HashSet<String> = ctx.state.db.subscriptions(ctx.account.id).await?.into_iter().collect();
    let filter = args.get("filter").cloned().unwrap_or(Value::Null);
    let parent_of = |m: &Mailbox| parent_name(&m.name).and_then(|p| all.iter().find(|x| x.name == p)).map(|p| format!("m{}", p.id));
    let matches = |m: &Mailbox| -> bool {
        let f = &filter;
        if let Some(p) = f.get("parentId") {
            let want = p.as_str().map(|s| ctx.id(s));
            if parent_of(m) != want {
                return false;
            }
        }
        if let Some(r) = f.get("role") {
            if role_of(m) != r.as_str() {
                return false;
            }
        }
        if let Some(h) = f.get("hasAnyRole").and_then(|v| v.as_bool()) {
            if role_of(m).is_some() != h {
                return false;
            }
        }
        if let Some(s) = f.get("isSubscribed").and_then(|v| v.as_bool()) {
            if subs.contains(&m.name) != s {
                return false;
            }
        }
        if let Some(n) = f.get("name").and_then(|v| v.as_str()) {
            if !m.name.to_lowercase().contains(&n.to_lowercase()) {
                return false;
            }
        }
        true
    };
    let mut list: Vec<&Mailbox> = all.iter().filter(|m| matches(m)).collect();
    let by_name = args
        .get("sort")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .and_then(|c| c.get("property"))
        .and_then(|p| p.as_str())
        == Some("name");
    if by_name {
        list.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    } else {
        list.sort_by_key(|m| (sort_order(m), m.name.to_lowercase()));
    }
    let ids: Vec<String> = list.iter().map(|m| format!("m{}", m.id)).collect();
    Ok(json!({"accountId": account_id(&ctx.account), "queryState": state_str(ctx).await?, "canCalculateChanges": false,
        "position": 0, "ids": ids, "total": list.len()}))
}

pub(super) fn set_error(kind: &str, desc: impl Into<String>) -> Value {
    json!({"type": kind, "description": desc.into()})
}

async fn mailbox_set(ctx: &mut Ctx, args: &Value) -> Result<Value, MethodError> {
    let old_state = state_str(ctx).await?;
    if let Some(s) = args.get("ifInState").and_then(|v| v.as_str()) {
        if s != old_state {
            return Err(MethodError("stateMismatch", "State changed.".into()));
        }
    }
    let acc = ctx.account.id;
    let db = ctx.state.db.clone();
    let (mut created, mut not_created) = (Map::new(), Map::new());
    let (mut updated, mut not_updated) = (Map::new(), Map::new());
    let (mut destroyed, mut not_destroyed) = (vec![], Map::new());

    if let Some(c) = args.get("create").and_then(|v| v.as_object()) {
        for (cid, obj) in c {
            let all = db.list_mailboxes(acc).await?;
            let name = obj.get("name").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
            if name.is_empty() || name.contains('/') || name.len() > 255 {
                not_created.insert(cid.clone(), set_error("invalidProperties", "name must be non-empty and not contain '/'"));
                continue;
            }
            let parent = match obj.get("parentId").and_then(|v| v.as_str()) {
                Some(p) => match num_id(&ctx.id(p), 'm').and_then(|n| all.iter().find(|m| m.id == n)) {
                    Some(m) => Some(m.name.clone()),
                    None => {
                        not_created.insert(cid.clone(), set_error("invalidProperties", "parentId not found"));
                        continue;
                    }
                },
                None => None,
            };
            let full = match parent {
                Some(p) => format!("{p}/{name}"),
                None => name,
            };
            if all.iter().any(|m| m.name.eq_ignore_ascii_case(&full)) {
                not_created.insert(cid.clone(), set_error("alreadyExists", "A mailbox with that name exists"));
                continue;
            }
            let special = obj.get("role").and_then(|v| v.as_str()).and_then(special_of).unwrap_or("");
            let id = db.create_mailbox(acc, &full, special).await?;
            if obj.get("isSubscribed").and_then(|v| v.as_bool()).unwrap_or(true) {
                db.subscribe(acc, &full).await?;
            }
            let sid = format!("m{id}");
            ctx.created.insert(cid.clone(), sid.clone());
            created.insert(cid.clone(), json!({"id": sid, "totalEmails": 0, "unreadEmails": 0, "totalThreads": 0, "unreadThreads": 0,
                "sortOrder": 10, "myRights": {"mayReadItems": true, "mayAddItems": true, "mayRemoveItems": true, "maySetSeen": true,
                "maySetKeywords": true, "mayCreateChild": true, "mayRename": true, "mayDelete": true, "maySubmit": true}}));
        }
    }
    if let Some(u) = args.get("update").and_then(|v| v.as_object()) {
        for (id, patch) in u {
            let all = db.list_mailboxes(acc).await?;
            let Some(m) = num_id(&ctx.id(id), 'm').and_then(|n| all.iter().find(|m| m.id == n)).cloned() else {
                not_updated.insert(id.clone(), set_error("notFound", "No such mailbox"));
                continue;
            };
            let mut new_name = m.name.clone();
            let mut err = None;
            if let Some(n) = patch.get("name").and_then(|v| v.as_str()) {
                if n.is_empty() || n.contains('/') {
                    err = Some("invalid name");
                } else {
                    new_name = match parent_name(&m.name) {
                        Some(p) => format!("{p}/{n}"),
                        None => n.to_string(),
                    };
                }
            }
            if let Some(p) = patch.get("parentId") {
                let leaf = new_name.rsplit('/').next().unwrap_or(&new_name).to_string();
                new_name = match p.as_str() {
                    Some(p) => match num_id(&ctx.id(p), 'm').and_then(|n| all.iter().find(|x| x.id == n)) {
                        Some(pm) if !pm.name.starts_with(&format!("{}/", m.name)) && pm.id != m.id => format!("{}/{leaf}", pm.name),
                        _ => {
                            err = Some("invalid parentId");
                            new_name.clone()
                        }
                    },
                    None => leaf,
                };
            }
            if err.is_none() && new_name != m.name {
                if m.name == "INBOX" {
                    err = Some("Inbox can't be renamed");
                } else if all.iter().any(|x| x.name.eq_ignore_ascii_case(&new_name)) {
                    err = Some("a mailbox with that name exists");
                } else {
                    db.rename_mailbox(acc, &m.name, &new_name, '/').await?;
                    db.unsubscribe(acc, &m.name).await?;
                    db.subscribe(acc, &new_name).await?;
                    ctx.state.hub.notify(m.id);
                }
            }
            if let Some(e) = err {
                not_updated.insert(id.clone(), set_error("invalidProperties", e));
                continue;
            }
            if let Some(s) = patch.get("isSubscribed").and_then(|v| v.as_bool()) {
                if s {
                    db.subscribe(acc, &new_name).await?;
                } else {
                    db.unsubscribe(acc, &new_name).await?;
                }
            }
            if let Some(r) = patch.get("role") {
                let special = r.as_str().and_then(special_of).unwrap_or("");
                let _g = ();
                sqlx::query("UPDATE mailboxes SET special_use = $1 WHERE id = $2")
                    .bind(special)
                    .bind(m.id)
                    .execute(&db.pool)
                    .await
                    .map_err(anyhow::Error::from)?;
            }
            updated.insert(id.clone(), Value::Null);
        }
    }
    if let Some(d) = args.get("destroy").and_then(|v| v.as_array()) {
        let remove_emails = args.get("onDestroyRemoveEmails").and_then(|v| v.as_bool()).unwrap_or(false);
        for id in d.iter().filter_map(|v| v.as_str()) {
            let all = db.list_mailboxes(acc).await?;
            let Some(m) = num_id(&ctx.id(id), 'm').and_then(|n| all.iter().find(|m| m.id == n)).cloned() else {
                not_destroyed.insert(id.to_string(), set_error("notFound", "No such mailbox"));
                continue;
            };
            if m.name == "INBOX" {
                not_destroyed.insert(id.to_string(), set_error("forbidden", "Inbox can't be deleted"));
                continue;
            }
            if all.iter().any(|x| x.name.starts_with(&format!("{}/", m.name))) {
                not_destroyed.insert(id.to_string(), set_error("mailboxHasChild", "Delete child mailboxes first"));
                continue;
            }
            let (count, _, _) = db.mailbox_counts(m.id).await?;
            if count > 0 && !remove_emails {
                not_destroyed.insert(id.to_string(), set_error("mailboxHasEmail", "Mailbox is not empty"));
                continue;
            }
            let (blobs, freed) = db.delete_mailbox(m.id).await?;
            db.add_usage(acc, -freed).await?;
            db.unsubscribe(acc, &m.name).await?;
            ctx.state.hub.notify(m.id);
            ctx.state.blobs.delete_all(&blobs).await;
            destroyed.push(id.to_string());
        }
    }
    Ok(json!({"accountId": account_id(&ctx.account), "oldState": old_state, "newState": state_str(ctx).await?,
        "created": created, "updated": updated, "destroyed": destroyed,
        "notCreated": not_created, "notUpdated": not_updated, "notDestroyed": not_destroyed}))
}

// ---------------------------------------------------------------- emails

pub(super) fn meta_of_row(row: &MessageRow) -> Meta {
    meta_of(row)
}

fn meta_of(row: &MessageRow) -> Meta {
    serde_json::from_str(&row.meta).unwrap_or_default()
}

pub(super) fn addrs_json(a: &[EmailAddr]) -> Value {
    if a.is_empty() {
        return Value::Null;
    }
    json!(a.iter().map(|x| json!({"name": x.name, "email": x.email})).collect::<Vec<_>>())
}

pub(super) fn ids_json(v: &[String]) -> Value {
    if v.is_empty() {
        Value::Null
    } else {
        json!(v)
    }
}

const EMAIL_DEFAULT: &[&str] = &[
    "id", "blobId", "threadId", "mailboxIds", "keywords", "size", "receivedAt", "messageId", "inReplyTo", "references",
    "sender", "from", "to", "cc", "bcc", "replyTo", "subject", "sentAt", "hasAttachment", "preview", "bodyValues",
    "textBody", "htmlBody", "attachments",
];
const BODY_PROPS: &[&str] = &["bodyStructure", "bodyValues", "textBody", "htmlBody", "attachments", "headers"];

fn part_blob_id(email: i64, path: &[usize]) -> String {
    format!("p{email}_{}", path.iter().map(|n| n.to_string()).collect::<Vec<_>>().join("-"))
}

fn part_name(data: &[u8], p: &Part) -> Option<String> {
    let disp = p.header(data, "content-disposition").and_then(|v| mime::parse_disposition(&v));
    disp.and_then(|(_, params)| params.into_iter().find(|(k, _)| k.eq_ignore_ascii_case("filename") || k.eq_ignore_ascii_case("filename*")).map(|x| x.1))
        .or_else(|| p.param("name").map(String::from))
        .map(|n| mime::decode_rfc2047(n.as_bytes()))
}

pub(super) fn decoded(data: &[u8], p: &Part) -> Vec<u8> {
    let body = p.body_bytes(data);
    let enc = p.header(data, "content-transfer-encoding").map(|v| String::from_utf8_lossy(&v).trim().to_ascii_lowercase()).unwrap_or_default();
    match enc.as_str() {
        "base64" => mime::decode_base64(body),
        "quoted-printable" => mime::decode_qp(body),
        _ => body.to_vec(),
    }
}

fn text_of(data: &[u8], p: &Part) -> String {
    let bytes = decoded(data, p);
    let cs = p.param("charset").unwrap_or("utf-8").to_ascii_lowercase();
    if std::str::from_utf8(&bytes).is_ok() || cs.contains("utf") {
        String::from_utf8_lossy(&bytes).into_owned()
    } else {
        bytes.iter().map(|&b| b as char).collect()
    }
}

struct BodyPart<'a> {
    path: Vec<usize>,
    part: &'a Part,
}

fn part_json(blob_of: &dyn Fn(&[usize]) -> String, data: &[u8], bp: &BodyPart, with_sub: bool) -> Value {
    let p = bp.part;
    let ctype = format!("{}/{}", p.ctype, p.csub).to_ascii_lowercase();
    let disposition = p.header(data, "content-disposition").and_then(|v| mime::parse_disposition(&v)).map(|(d, _)| d.to_ascii_lowercase());
    let multipart = p.is_multipart();
    let mut o = json!({
        "partId": if multipart { Value::Null } else { json!(bp.path.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(".")) },
        "blobId": if multipart { Value::Null } else { json!(blob_of(&bp.path)) },
        "size": if multipart { 0 } else { decoded(data, p).len() },
        "name": part_name(data, p),
        "type": ctype,
        "charset": if p.ctype.eq_ignore_ascii_case("text") { json!(p.param("charset").unwrap_or("us-ascii")) } else { Value::Null },
        "disposition": disposition,
        "cid": p.header(data, "content-id").map(|v| String::from_utf8_lossy(&v).trim_matches(|c| c == '<' || c == '>').to_string()),
        "language": Value::Null,
        "location": p.header(data, "content-location").map(|v| String::from_utf8_lossy(&v).to_string()),
    });
    if multipart && with_sub {
        let subs: Vec<Value> = p
            .children
            .iter()
            .enumerate()
            .map(|(i, c)| {
                let mut path = bp.path.clone();
                path.push(i + 1);
                part_json(blob_of, data, &BodyPart { path, part: c }, true)
            })
            .collect();
        o["subParts"] = json!(subs);
    }
    o
}

/// RFC 8621 section 4.1.4 body classification.
fn classify<'a>(
    parts: Vec<BodyPart<'a>>,
    multipart_type: &str,
    in_alternative: bool,
    data: &[u8],
    html: &mut Option<Vec<BodyPart<'a>>>,
    text: &mut Option<Vec<BodyPart<'a>>>,
    attachments: &mut Vec<BodyPart<'a>>,
) {
    let text_len = text.as_ref().map(|t| t.len());
    let html_len = html.as_ref().map(|h| h.len());
    let inline_media = |t: &str| t.starts_with("image/") || t.starts_with("audio/") || t.starts_with("video/");
    for (i, bp) in parts.into_iter().enumerate() {
        let p = bp.part;
        let ctype = format!("{}/{}", p.ctype, p.csub).to_ascii_lowercase();
        let disp = p.header(data, "content-disposition").and_then(|v| mime::parse_disposition(&v)).map(|(d, _)| d.to_ascii_lowercase());
        let is_inline = disp.as_deref() != Some("attachment")
            && (ctype == "text/plain" || ctype == "text/html" || inline_media(&ctype))
            && (i == 0 || (multipart_type != "related" && (inline_media(&ctype) || part_name(data, p).is_none())));
        if p.is_multipart() {
            let sub = p.csub.to_ascii_lowercase();
            let children: Vec<BodyPart> = p
                .children
                .iter()
                .enumerate()
                .map(|(k, c)| {
                    let mut path = bp.path.clone();
                    path.push(k + 1);
                    BodyPart { path, part: c }
                })
                .collect();
            let alt = in_alternative || sub == "alternative";
            classify(children, &sub, alt, data, html, text, attachments);
        } else if is_inline {
            if multipart_type == "alternative" {
                match ctype.as_str() {
                    "text/plain" => {
                        if let Some(t) = text {
                            t.push(bp)
                        }
                    }
                    "text/html" => {
                        if let Some(h) = html {
                            h.push(bp)
                        }
                    }
                    _ => attachments.push(bp),
                }
                continue;
            } else if in_alternative {
                if ctype == "text/plain" {
                    *html = None;
                }
                if ctype == "text/html" {
                    *text = None;
                }
            }
            let both = text.is_some() && html.is_some();
            if let Some(t) = text {
                t.push(BodyPart { path: bp.path.clone(), part: bp.part });
            }
            if let Some(h) = html {
                h.push(BodyPart { path: bp.path.clone(), part: bp.part });
            }
            if !both && inline_media(&ctype) {
                attachments.push(bp);
            }
        } else {
            attachments.push(bp);
        }
    }
    if multipart_type == "alternative" {
        if let (Some(t), Some(h)) = (text.as_mut(), html.as_mut()) {
            if Some(t.len()) == text_len && Some(h.len()) != html_len {
                for x in &h[html_len.unwrap_or(0)..] {
                    t.push(BodyPart { path: x.path.clone(), part: x.part });
                }
            }
            if Some(h.len()) == html_len && Some(t.len()) != text_len {
                for x in &t[text_len.unwrap_or(0)..] {
                    h.push(BodyPart { path: x.path.clone(), part: x.part });
                }
            }
        }
    }
}

fn header_value(data: &[u8], root: &Part, spec: &str) -> Option<Value> {
    // header:Name[:asForm][:all]
    let mut it = spec.strip_prefix("header:")?.split(':');
    let name = it.next()?;
    let mut form = "asRaw";
    let mut all = false;
    for x in it {
        if x == "all" {
            all = true;
        } else {
            form = match x {
                "asRaw" | "asText" | "asAddresses" | "asMessageIds" | "asDate" | "asURLs" | "asGroupedAddresses" => x,
                _ => return None,
            };
        }
    }
    let convert = |raw: &[u8]| -> Value {
        match form {
            "asText" => json!(mime::decode_rfc2047(&mime::unfold(raw))),
            "asAddresses" | "asGroupedAddresses" => addrs_json(&mime::email_addrs(Some(mime::unfold(raw)))),
            "asMessageIds" => ids_json(&mime::msg_ids(raw)),
            "asDate" => mime::parse_rfc2822_date(&String::from_utf8_lossy(&mime::unfold(raw))).map(|t| json!(utc(t))).unwrap_or(Value::Null),
            "asURLs" => json!(String::from_utf8_lossy(raw).split(',').filter_map(|u| {
                let u = u.trim();
                u.strip_prefix('<').and_then(|x| x.strip_suffix('>')).map(String::from)
            }).collect::<Vec<_>>()),
            _ => json!(String::from_utf8_lossy(raw)),
        }
    };
    let values: Vec<Value> = root
        .fields
        .iter()
        .filter(|f| f.name.eq_ignore_ascii_case(name))
        .map(|f| convert(&data[f.value_start..f.end].strip_suffix(b"\r\n").unwrap_or(&data[f.value_start..f.end])))
        .collect();
    Some(if all { json!(values) } else { values.last().cloned().unwrap_or(Value::Null) })
}

async fn email_get(ctx: &mut Ctx, args: &Value) -> Result<Value, MethodError> {
    let props = props_arg(args, EMAIL_DEFAULT);
    let opts = BodyOpts::from_args(args);
    let ids = match ids_arg(ctx, args)? {
        Some(i) => i,
        None => {
            let rows = ctx.state.db.account_messages(ctx.account.id).await?;
            if rows.len() > MAX_OBJECTS {
                return Err(MethodError("requestTooLarge", "Use Email/query to select emails.".into()));
            }
            rows.iter().map(|r| format!("e{}", r.id)).collect()
        }
    };
    let nums: Vec<i64> = ids.iter().filter_map(|s| num_id(s, 'e')).collect();
    let rows: HashMap<i64, MessageRow> = ctx.state.db.messages_by_ids(ctx.account.id, &nums).await?.into_iter().map(|r| (r.id, r)).collect();
    let needs_body = props.iter().any(|p| BODY_PROPS.contains(&p.as_str()) || p.starts_with("header:"));
    let mut list = vec![];
    let mut not_found = vec![];
    for id in ids {
        let Some(row) = num_id(&id, 'e').and_then(|n| rows.get(&n)) else {
            not_found.push(id);
            continue;
        };
        let m = meta_of(row);
        let mut o = Map::new();
        o.insert("id".into(), json!(id));
        o.insert("blobId".into(), json!(format!("b{}", row.blob.replace('/', "_"))));
        o.insert("threadId".into(), json!(format!("t{}", row.thread_id)));
        o.insert("mailboxIds".into(), json!({format!("m{}", row.mailbox_id): true}));
        o.insert("keywords".into(), Value::Object(keywords_of(&row.flags)));
        o.insert("size".into(), json!(row.size));
        o.insert("receivedAt".into(), json!(utc(row.internal_date)));
        o.insert("messageId".into(), m.msgid.as_ref().map(|x| json!([x])).unwrap_or(Value::Null));
        o.insert("inReplyTo".into(), ids_json(&m.in_reply_to));
        o.insert("references".into(), ids_json(&m.references));
        o.insert("sender".into(), addrs_json(&m.sender));
        o.insert("from".into(), addrs_json(&m.from));
        o.insert("to".into(), addrs_json(&m.to));
        o.insert("cc".into(), addrs_json(&m.cc));
        o.insert("bcc".into(), addrs_json(&m.bcc));
        o.insert("replyTo".into(), addrs_json(&m.reply_to));
        o.insert("subject".into(), if m.subject.is_empty() { Value::Null } else { json!(m.subject) });
        o.insert("sentAt".into(), m.sent.map(|t| json!(utc(t))).unwrap_or(Value::Null));
        o.insert("hasAttachment".into(), json!(m.has_attachment));
        o.insert("preview".into(), json!(m.preview));
        if needs_body {
            let raw = ctx.state.blobs.get(&row.blob).await?;
            let email = row.id;
            body_into(&mut o, &raw, &props, &opts, &|path: &[usize]| part_blob_id(email, path));
        }
        list.push(pick(o, &props));
    }
    Ok(json!({"accountId": account_id(&ctx.account), "state": state_str(ctx).await?, "list": list, "notFound": not_found}))
}

/// What Email/get and Email/parse return of bodies.
pub(super) struct BodyOpts {
    pub body_props: Vec<String>,
    pub fetch_text: bool,
    pub fetch_html: bool,
    pub fetch_all: bool,
    pub max_bytes: usize,
}

impl BodyOpts {
    pub(super) fn from_args(args: &Value) -> Self {
        BodyOpts {
            body_props: match args.get("bodyProperties").and_then(|v| v.as_array()) {
                Some(b) => b.iter().filter_map(|x| x.as_str().map(String::from)).collect(),
                None => ["partId", "blobId", "size", "name", "type", "charset", "disposition", "cid", "language", "location"].iter().map(|s| s.to_string()).collect(),
            },
            fetch_text: args.get("fetchTextBodyValues").and_then(|v| v.as_bool()).unwrap_or(false),
            fetch_html: args.get("fetchHTMLBodyValues").and_then(|v| v.as_bool()).unwrap_or(false),
            fetch_all: args.get("fetchAllBodyValues").and_then(|v| v.as_bool()).unwrap_or(false),
            max_bytes: args.get("maxBodyValueBytes").and_then(|v| v.as_u64()).unwrap_or(0) as usize,
        }
    }
}

/// Body properties (textBody, htmlBody, attachments, bodyStructure,
/// bodyValues, headers, header:*) of a message, with part blob ids from `blob_of`.
pub(super) fn body_into(o: &mut Map<String, Value>, data: &[u8], props: &[String], opts: &BodyOpts, blob_of: &dyn Fn(&[usize]) -> String) {
    let root = mime::parse(data);
    let top = BodyPart { path: if root.is_multipart() { vec![] } else { vec![1] }, part: &root };
    let filter = |v: Value| -> Value {
        match v {
            Value::Object(m) => Value::Object(
                m.into_iter()
                    .filter(|(k, _)| k == "subParts" || opts.body_props.iter().any(|p| p == k))
                    .collect(),
            ),
            o => o,
        }
    };
    let (mut html, mut text, mut atts) = (Some(vec![]), Some(vec![]), vec![]);
    let start: Vec<BodyPart> = if root.is_multipart() {
        root.children
            .iter()
            .enumerate()
            .map(|(i, c)| BodyPart { path: vec![i + 1], part: c })
            .collect()
    } else {
        vec![BodyPart { path: vec![1], part: &root }]
    };
    let mtype = if root.is_multipart() { root.csub.to_ascii_lowercase() } else { "mixed".into() };
    let alt = mtype == "alternative";
    classify(start, &mtype, alt, data, &mut html, &mut text, &mut atts);
    let text = text.unwrap_or_default();
    let html = html.unwrap_or_default();
    let parts_json = |v: &[BodyPart]| json!(v.iter().map(|b| filter(part_json(blob_of, data, b, false))).collect::<Vec<_>>());
    o.insert("textBody".into(), parts_json(&text));
    o.insert("htmlBody".into(), parts_json(&html));
    o.insert("attachments".into(), parts_json(&atts));
    if props.iter().any(|p| p == "bodyStructure") {
        fn strip(v: Value, keep: &[String]) -> Value {
            match v {
                Value::Object(m) => Value::Object(
                    m.into_iter()
                        .filter(|(k, _)| k == "subParts" || keep.iter().any(|p| p == k))
                        .map(|(k, v)| if k == "subParts" { (k, Value::Array(v.as_array().cloned().unwrap_or_default().into_iter().map(|x| strip(x, keep)).collect())) } else { (k, v) })
                        .collect(),
                ),
                o => o,
            }
        }
        o.insert("bodyStructure".into(), strip(part_json(blob_of, data, &top, true), &opts.body_props));
    }
    let mut values = Map::new();
    let mut want: Vec<&BodyPart> = vec![];
    if opts.fetch_text || opts.fetch_all {
        want.extend(text.iter());
    }
    if opts.fetch_html || opts.fetch_all {
        want.extend(html.iter());
    }
    if opts.fetch_all {
        want.extend(atts.iter().filter(|b| b.part.ctype.eq_ignore_ascii_case("text")));
    }
    for b in want {
        let pid = b.path.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(".");
        if values.contains_key(&pid) || !b.part.ctype.eq_ignore_ascii_case("text") {
            continue;
        }
        let mut t = text_of(data, b.part);
        let mut truncated = false;
        if opts.max_bytes > 0 && t.len() > opts.max_bytes {
            t.truncate(t.floor_char_boundary(opts.max_bytes));
            truncated = true;
        }
        values.insert(pid, json!({"value": t, "isEncodingProblem": false, "isTruncated": truncated}));
    }
    o.insert("bodyValues".into(), Value::Object(values));
    if props.iter().any(|p| p == "headers") {
        let h: Vec<Value> = root
            .fields
            .iter()
            .filter(|f| !f.name.is_empty())
            .map(|f| json!({"name": f.name, "value": String::from_utf8_lossy(&data[f.value_start..f.end]).trim_end_matches("\r\n")}))
            .collect();
        o.insert("headers".into(), json!(h));
    }
    for p in props.iter().filter(|p| p.starts_with("header:")) {
        if let Some(v) = header_value(data, &root, p) {
            o.insert(p.clone(), v);
        }
    }
    }

/// Evaluate an Email/query filter against a message.
fn email_matches(ctx: &Ctx, f: &Value, row: &MessageRow, m: &Meta, thread_flags: &HashMap<i64, Vec<String>>) -> Result<bool, MethodError> {
    if let Some(op) = f.get("operator").and_then(|v| v.as_str()) {
    let conds = f.get("conditions").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    let mut results = vec![];
    for c in &conds {
        results.push(email_matches(ctx, c, row, m, thread_flags)?);
    }
    return match op {
        "AND" => Ok(results.iter().all(|x| *x)),
        "OR" => Ok(results.iter().any(|x| *x)),
        "NOT" => Ok(!results.iter().any(|x| *x)),
        _ => Err(MethodError("unsupportedFilter", format!("Unknown operator {op}"))),
    };
    }
    let Some(obj) = f.as_object() else { return Ok(true) };
    let text_in = |hay: &str, needle: &str| hay.to_lowercase().contains(&needle.to_lowercase());
    let addr_text = |a: &[EmailAddr]| a.iter().map(|x| format!("{} {}", x.name.clone().unwrap_or_default(), x.email)).collect::<Vec<_>>().join(" ");
    for (k, v) in obj {
    let ok = match k.as_str() {
        "inMailbox" => v.as_str().map(|s| num_id(&ctx.id(s), 'm') == Some(row.mailbox_id)).unwrap_or(false),
        "inMailboxOtherThan" => !v.as_array().map(|a| a.iter().filter_map(|x| x.as_str()).any(|s| num_id(&ctx.id(s), 'm') == Some(row.mailbox_id))).unwrap_or(false),
        "before" => v.as_str().and_then(parse_utc).map(|t| row.internal_date < t).unwrap_or(false),
        "after" => v.as_str().and_then(parse_utc).map(|t| row.internal_date >= t).unwrap_or(false),
        "minSize" => v.as_i64().map(|n| row.size >= n).unwrap_or(false),
        "maxSize" => v.as_i64().map(|n| row.size < n).unwrap_or(false),
        "hasKeyword" => v.as_str().map(|k| has_keyword(&row.flags, k)).unwrap_or(false),
        "notKeyword" => v.as_str().map(|k| !has_keyword(&row.flags, k)).unwrap_or(false),
        "allInThreadHaveKeyword" | "someInThreadHaveKeyword" | "noneInThreadHaveKeyword" => {
            let kw = v.as_str().unwrap_or("");
            let flags = thread_flags.get(&row.thread_id).cloned().unwrap_or_default();
            let n = flags.iter().filter(|f| has_keyword(f, kw)).count();
            match k.as_str() {
                "allInThreadHaveKeyword" => n == flags.len() && n > 0,
                "someInThreadHaveKeyword" => n > 0,
                _ => n == 0,
            }
        }
        "hasAttachment" => v.as_bool().map(|b| m.has_attachment == b).unwrap_or(false),
        "from" => v.as_str().map(|s| text_in(&addr_text(&m.from), s)).unwrap_or(false),
        "to" => v.as_str().map(|s| text_in(&addr_text(&m.to), s)).unwrap_or(false),
        "cc" => v.as_str().map(|s| text_in(&addr_text(&m.cc), s)).unwrap_or(false),
        "bcc" => v.as_str().map(|s| text_in(&addr_text(&m.bcc), s)).unwrap_or(false),
        "subject" => v.as_str().map(|s| text_in(&m.subject, s)).unwrap_or(false),
        "body" => v.as_str().map(|s| text_in(&m.preview, s)).unwrap_or(false),
        "text" => v
            .as_str()
            .map(|s| {
                text_in(&m.subject, s)
                    || text_in(&m.preview, s)
                    || text_in(&addr_text(&m.from), s)
                    || text_in(&addr_text(&m.to), s)
                    || text_in(&addr_text(&m.cc), s)
            })
            .unwrap_or(false),
        "header" => {
            let arr = v.as_array().cloned().unwrap_or_default();
            let name = arr.first().and_then(|x| x.as_str()).unwrap_or("").to_ascii_lowercase();
            let val = arr.get(1).and_then(|x| x.as_str());
            let hv = match name.as_str() {
                "subject" => Some(m.subject.clone()),
                "from" => Some(addr_text(&m.from)),
                "to" => Some(addr_text(&m.to)),
                "cc" => Some(addr_text(&m.cc)),
                "message-id" => m.msgid.clone(),
                _ => None,
            };
            match (hv, val) {
                (Some(h), Some(v)) => text_in(&h, v),
                (Some(_), None) => true,
                (None, _) => false,
            }
        }
        _ => return Err(MethodError("unsupportedFilter", format!("Unsupported filter {k}"))),
    };
    if !ok {
        return Ok(false);
    }
    }
    Ok(true)
}

async fn email_query(ctx: &mut Ctx, args: &Value) -> Result<Value, MethodError> {
    let rows = ctx.state.db.account_messages(ctx.account.id).await?;
    let metas: HashMap<i64, Meta> = rows.iter().map(|r| (r.id, meta_of(r))).collect();
    let mut thread_flags: HashMap<i64, Vec<String>> = HashMap::new();
    for r in &rows {
        thread_flags.entry(r.thread_id).or_default().push(r.flags.clone());
    }
    let filter = args.get("filter").cloned().unwrap_or(Value::Null);
    let mut hits: Vec<&MessageRow> = vec![];
    for r in &rows {
        if filter.is_null() || email_matches(ctx, &filter, r, &metas[&r.id], &thread_flags)? {
            hits.push(r);
        }
    }
    let sort: Vec<Value> = args.get("sort").and_then(|v| v.as_array()).cloned().unwrap_or_else(|| vec![json!({"property": "receivedAt", "isAscending": false})]);
    for c in &sort {
        let p = c.get("property").and_then(|v| v.as_str()).unwrap_or("");
        if !["receivedAt", "sentAt", "size", "from", "to", "subject", "hasKeyword"].contains(&p) {
            return Err(MethodError("unsupportedSort", format!("Can't sort by {p}")));
        }
    }
    let first = |a: &[EmailAddr]| a.first().map(|x| x.name.clone().unwrap_or_else(|| x.email.clone()).to_lowercase()).unwrap_or_default();
    hits.sort_by(|a, b| {
        let (ma, mb) = (&metas[&a.id], &metas[&b.id]);
        for c in &sort {
            let asc = c.get("isAscending").and_then(|v| v.as_bool()).unwrap_or(true);
            let o = match c.get("property").and_then(|v| v.as_str()).unwrap_or("") {
                "receivedAt" => a.internal_date.cmp(&b.internal_date),
                "sentAt" => ma.sent.unwrap_or(a.internal_date).cmp(&mb.sent.unwrap_or(b.internal_date)),
                "size" => a.size.cmp(&b.size),
                "from" => first(&ma.from).cmp(&first(&mb.from)),
                "to" => first(&ma.to).cmp(&first(&mb.to)),
                "subject" => ma.base_subject.to_lowercase().cmp(&mb.base_subject.to_lowercase()),
                "hasKeyword" => {
                    let kw = c.get("keyword").and_then(|v| v.as_str()).unwrap_or("");
                    has_keyword(&a.flags, kw).cmp(&has_keyword(&b.flags, kw))
                }
                _ => std::cmp::Ordering::Equal,
            };
            let o = if asc { o } else { o.reverse() };
            if o != std::cmp::Ordering::Equal {
                return o;
            }
        }
        b.id.cmp(&a.id)
    });
    if args.get("collapseThreads").and_then(|v| v.as_bool()).unwrap_or(false) {
        let mut seen = HashSet::new();
        hits.retain(|r| seen.insert(r.thread_id));
    }
    let total = hits.len() as i64;
    let mut position = args.get("position").and_then(|v| v.as_i64()).unwrap_or(0);
    if let Some(anchor) = args.get("anchor").and_then(|v| v.as_str()) {
        let a = num_id(&ctx.id(anchor), 'e');
        let idx = hits.iter().position(|r| Some(r.id) == a).ok_or(MethodError("anchorNotFound", "Anchor not in results.".into()))? as i64;
        position = (idx + args.get("anchorOffset").and_then(|v| v.as_i64()).unwrap_or(0)).max(0);
    } else if position < 0 {
        position = (total + position).max(0);
    }
    let limit = args.get("limit").and_then(|v| v.as_i64()).unwrap_or(1000).clamp(0, 10_000);
    let ids: Vec<String> = hits.iter().skip(position as usize).take(limit as usize).map(|r| format!("e{}", r.id)).collect();
    let mut out = json!({"accountId": account_id(&ctx.account), "queryState": state_str(ctx).await?,
        "canCalculateChanges": !args.get("collapseThreads").and_then(|v| v.as_bool()).unwrap_or(false),
        "position": position, "ids": ids});
    if args.get("calculateTotal").and_then(|v| v.as_bool()).unwrap_or(false) {
        out["total"] = json!(total);
    }
    if args.get("limit").is_some() {
        out["limit"] = json!(limit);
    }
    Ok(out)
}

/// Email/queryChanges (RFC 8620 5.6). Every message changed since the old
/// state is reported removed, and re-added at its current index if it still
/// matches; the spec allows this, and it needs no stored results.
async fn email_query_changes(ctx: &mut Ctx, args: &Value) -> Result<Value, MethodError> {
    if args.get("collapseThreads").and_then(|v| v.as_bool()).unwrap_or(false) {
        return Err(MethodError("cannotCalculateChanges", "Collapsed queries can't be followed; run the query again.".into()));
    }
    let since_s = args.get("sinceQueryState").and_then(|v| v.as_str()).ok_or_else(|| MethodError::invalid("sinceQueryState is required"))?;
    let since: i64 = since_s.parse().map_err(|_| MethodError("cannotCalculateChanges", "Unknown state.".into()))?;
    let max = args.get("maxChanges").and_then(|v| v.as_i64()).unwrap_or(5000).clamp(1, 50_000);
    let Some((rows, _, more)) = ctx.state.db.changes_since(ctx.account.id, "Email", since, 50_000).await? else {
        return Err(MethodError("cannotCalculateChanges", "State too old; run the query again.".into()));
    };
    if more {
        return Err(MethodError("cannotCalculateChanges", "Too many changes; run the query again.".into()));
    }
    let mut changed: Vec<String> = vec![];
    for (id, _) in rows {
        let sid = format!("e{id}");
        if !changed.contains(&sid) {
            changed.push(sid);
        }
    }
    // The query as it is now, in full.
    let mut q = args.clone();
    if let Some(o) = q.as_object_mut() {
        for k in ["position", "anchor", "anchorOffset", "sinceQueryState", "maxChanges", "upToId"] {
            o.remove(k);
        }
        o.insert("limit".into(), json!(10_000));
        o.insert("calculateTotal".into(), json!(true));
    }
    let now = email_query(ctx, &q).await?;
    let ids: Vec<String> = now["ids"].as_array().cloned().unwrap_or_default().iter().filter_map(|v| v.as_str().map(String::from)).collect();
    // upToId: changes after that id in the results needn't be reported.
    let up_to = args.get("upToId").and_then(|v| v.as_str()).map(|s| ctx.id(s));
    let cutoff = up_to.as_ref().and_then(|u| ids.iter().position(|i| i == u)).unwrap_or(usize::MAX);
    let mut added = vec![];
    for (index, id) in ids.iter().enumerate() {
        if index <= cutoff && changed.contains(id) {
            added.push(json!({"id": id, "index": index}));
        }
    }
    if (changed.len() + added.len()) as i64 > max {
        return Err(MethodError("tooManyChanges", "More changes than maxChanges.".into()));
    }
    let mut out = json!({"accountId": account_id(&ctx.account), "oldQueryState": since_s, "newQueryState": now["queryState"],
        "removed": changed, "added": added});
    if args.get("calculateTotal").and_then(|v| v.as_bool()).unwrap_or(false) {
        out["total"] = now["total"].clone();
    }
    Ok(out)
}

async fn thread_get(ctx: &mut Ctx, args: &Value) -> Result<Value, MethodError> {
    let rows = ctx.state.db.account_messages(ctx.account.id).await?;
    let mut threads: HashMap<i64, Vec<&MessageRow>> = HashMap::new();
    for r in &rows {
        threads.entry(r.thread_id).or_default().push(r);
    }
    let ids = ids_arg(ctx, args)?.unwrap_or_else(|| threads.keys().map(|t| format!("t{t}")).collect());
    let mut list = vec![];
    let mut not_found = vec![];
    for id in ids {
        match num_id(&id, 't').and_then(|t| threads.get_mut(&t)) {
            Some(v) => {
                v.sort_by_key(|r| (r.internal_date, r.id));
                list.push(json!({"id": id, "emailIds": v.iter().map(|r| format!("e{}", r.id)).collect::<Vec<_>>()}));
            }
            None => not_found.push(id),
        }
    }
    Ok(json!({"accountId": account_id(&ctx.account), "state": state_str(ctx).await?, "list": list, "notFound": not_found}))
}

async fn snippets(ctx: &mut Ctx, args: &Value) -> Result<Value, MethodError> {
    let ids: Vec<String> = args.get("emailIds").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(|s| ctx.id(s))).collect()).unwrap_or_default();
    let nums: Vec<i64> = ids.iter().filter_map(|s| num_id(s, 'e')).collect();
    let rows: HashMap<i64, MessageRow> = ctx.state.db.messages_by_ids(ctx.account.id, &nums).await?.into_iter().map(|r| (r.id, r)).collect();
    let mut list = vec![];
    let mut not_found = vec![];
    for id in ids {
        match num_id(&id, 'e').and_then(|n| rows.get(&n)) {
            Some(_) => list.push(json!({"emailId": id, "subject": Value::Null, "preview": Value::Null})),
            None => not_found.push(id),
        }
    }
    Ok(json!({"accountId": account_id(&ctx.account), "list": list, "notFound": not_found}))
}

/// Bytes for a JMAP blob id, if the account may read it.
pub async fn blob_bytes(state: &State, a: &Account, blob: &str) -> anyhow::Result<Option<Vec<u8>>> {
    if let Some(id) = num_id(blob, 'S') {
        return Ok(state.db.sieve_script_by_id(a.id, id).await?.map(|s| s.content.into_bytes()));
    }
    if let Some(id) = num_id(blob, 'u') {
        return match state.db.upload(a.id, id).await? {
            Some((key, _, _)) => Ok(Some(state.blobs.get(&key).await?.to_vec())),
            None => Ok(None),
        };
    }
    if let Some(key) = blob.strip_prefix('b') {
        let key = key.replacen("a_", "a/", 1);
        if !state.db.account_owns_blob(a.id, &key).await? {
            return Ok(None);
        }
        return Ok(Some(state.blobs.get(&key).await?.to_vec()));
    }
    // A calendar or contact resource: D<node>.
    if let Some(id) = num_id(blob, 'D') {
        let Some(p) = crate::dav::store::principal(state, a).await? else { return Ok(None) };
        let Some(n) = state.db.dav_node_by_id(p.id, id).await? else { return Ok(None) };
        return Ok(Some(crate::dav::read_blob(state, &n).await?));
    }
    // A part of another blob (Email/parse): P<blob>~<1-2-3>.
    if let Some(rest) = blob.strip_prefix('P') {
        let Some((src, path)) = rest.rsplit_once('~') else { return Ok(None) };
        let path: Vec<usize> = path.split('-').filter_map(|x| x.parse().ok()).collect();
        let Some(raw) = Box::pin(blob_bytes(state, a, src)).await? else { return Ok(None) };
        let root = mime::parse(&raw);
        let Some(p) = mime::find_part(&root, &path) else { return Ok(None) };
        return Ok(Some(if p.message.is_some() { p.body_bytes(&raw).to_vec() } else { decoded(&raw, p) }));
    }
    if let Some(rest) = blob.strip_prefix('p') {
        let Some((eid, path)) = rest.split_once('_') else { return Ok(None) };
        let Ok(eid) = eid.parse::<i64>() else { return Ok(None) };
        let path: Vec<usize> = path.split('-').filter_map(|x| x.parse().ok()).collect();
        let rows = state.db.messages_by_ids(a.id, &[eid]).await?;
        let Some(row) = rows.first() else { return Ok(None) };
        let raw = state.blobs.get(&row.blob).await?;
        let root = mime::parse(&raw);
        let Some(p) = mime::find_part(&root, &path) else { return Ok(None) };
        return Ok(Some(if p.message.is_some() { p.body_bytes(&raw).to_vec() } else { decoded(&raw, p) }));
    }
    Ok(None)
}

/// Apply an Email update (keywords, mailboxIds). Returns an error object on failure.
async fn update_email(ctx: &mut Ctx, row: &MessageRow, patch: &Map<String, Value>) -> Result<Option<Value>, MethodError> {
    let db = ctx.state.db.clone();
    // Keywords: whole replacement or "keywords/x" patches.
    let mut kws: Map<String, Value> = keywords_of(&row.flags);
    let mut kw_changed = false;
    let mut target_mailboxes: Option<HashSet<i64>> = None;
    let mut mb_patches: Vec<(i64, bool)> = vec![];
    for (k, v) in patch {
        if k == "keywords" {
            let Some(o) = v.as_object() else { return Ok(Some(set_error("invalidProperties", "keywords must be an object"))) };
            kws = o.iter().filter(|(_, b)| b.as_bool() == Some(true)).map(|(k, _)| (k.to_ascii_lowercase(), Value::Bool(true))).collect();
            kw_changed = true;
        } else if let Some(kw) = k.strip_prefix("keywords/") {
            let kw = kw.replace("~1", "/").replace("~0", "~").to_ascii_lowercase();
            if v.as_bool() == Some(true) {
                kws.insert(kw, Value::Bool(true));
            } else {
                kws.remove(&kw);
            }
            kw_changed = true;
        } else if k == "mailboxIds" {
            let Some(o) = v.as_object() else { return Ok(Some(set_error("invalidProperties", "mailboxIds must be an object"))) };
            let mut set = HashSet::new();
            for (m, b) in o {
                if b.as_bool() == Some(true) {
                    match num_id(&ctx.id(m), 'm') {
                        Some(n) => {
                            set.insert(n);
                        }
                        None => return Ok(Some(set_error("invalidProperties", "unknown mailbox"))),
                    }
                }
            }
            target_mailboxes = Some(set);
        } else if let Some(m) = k.strip_prefix("mailboxIds/") {
            match num_id(&ctx.id(m), 'm') {
                Some(n) => mb_patches.push((n, v.as_bool() == Some(true))),
                None => return Ok(Some(set_error("invalidProperties", "unknown mailbox"))),
            }
        } else {
            return Ok(Some(set_error("invalidProperties", format!("{k} can't be changed"))));
        }
    }
    if !mb_patches.is_empty() {
        let mut set: HashSet<i64> = target_mailboxes.take().unwrap_or_else(|| [row.mailbox_id].into_iter().collect());
        for (m, add) in mb_patches {
            if add {
                set.insert(m);
            } else {
                set.remove(&m);
            }
        }
        target_mailboxes = Some(set);
    }
    let mut mailbox_id = row.mailbox_id;
    let mut uid = row.uid;
    if let Some(set) = target_mailboxes {
        if set.is_empty() {
            return Ok(Some(set_error("invalidProperties", "An email must be in a mailbox")));
        }
        if set.len() > 1 {
            // Moving to a new mailbox via add-then-remove patches: prefer the one that isn't the current.
            let others: Vec<i64> = set.iter().copied().filter(|m| *m != row.mailbox_id).collect();
            if others.len() != 1 {
                return Ok(Some(set_error("tooManyMailboxes", "An email can be in only one mailbox")));
            }
            mailbox_id = others[0];
        } else {
            mailbox_id = *set.iter().next().unwrap();
        }
        let owner = db.mailbox_by_id(mailbox_id).await?;
        if owner.as_ref().is_none_or(|m| m.account_id != ctx.account.id) {
            return Ok(Some(set_error("invalidProperties", "unknown mailbox")));
        }
        if mailbox_id != row.mailbox_id {
            // Train the spam filter from moves into and out of Junk.
            let src = db.mailbox_by_id(row.mailbox_id).await?;
            let src_junk = src.as_ref().is_some_and(|m| m.special_use.contains("\\Junk"));
            let dst = owner.as_ref().unwrap();
            let dst_junk = dst.special_use.contains("\\Junk");
            if src_junk != dst_junk && !(src_junk && dst.special_use.contains("\\Trash")) {
                crate::filter::bayes::learn_blob(&ctx.state, ctx.account.id, row.blob.clone(), dst_junk);
            }
            uid = db.move_message(row.id, mailbox_id).await?.unwrap_or(uid);
            ctx.state.hub.notify(row.mailbox_id);
            ctx.state.hub.notify(mailbox_id);
        }
    }
    if kw_changed {
        let had = |k: &str| row.flags.split_whitespace().any(|f| f.eq_ignore_ascii_case(k));
        if kws.contains_key("$junk") && !had("$junk") {
            crate::filter::bayes::learn_blob(&ctx.state, ctx.account.id, row.blob.clone(), true);
        } else if kws.contains_key("$notjunk") && !had("$notjunk") {
            crate::filter::bayes::learn_blob(&ctx.state, ctx.account.id, row.blob.clone(), false);
        }
        let mut flags: Vec<String> = vec![];
        for k in kws.keys() {
            match keyword_to_flag(k) {
                Some(f) => flags.push(f),
                None => return Ok(Some(set_error("invalidProperties", format!("invalid keyword {k}")))),
            }
        }
        // Keep IMAP-only flags (\Deleted) that JMAP doesn't model.
        if row.flags.split_whitespace().any(|f| f.eq_ignore_ascii_case("\\Deleted")) {
            flags.push("\\Deleted".into());
        }
        db.modify_flags(mailbox_id, &[uid], '=', &flags, None).await?;
        let new_kws: Vec<String> = flags.iter().filter(|f| !f.starts_with('\\')).cloned().collect();
        if !new_kws.is_empty() {
            if let Some(mb) = db.mailbox_by_id(mailbox_id).await? {
                let mut existing: Vec<String> = mb.keywords.split_whitespace().map(String::from).collect();
                let before = existing.len();
                for k in new_kws {
                    if !existing.iter().any(|x| x.eq_ignore_ascii_case(&k)) {
                        existing.push(k);
                    }
                }
                if existing.len() != before {
                    db.add_keywords(mailbox_id, &existing.join(" ")).await?;
                }
            }
        }
        ctx.state.hub.notify(mailbox_id);
    }
    Ok(None)
}

async fn destroy_email(ctx: &Ctx, row: &MessageRow) -> anyhow::Result<()> {
    let (_, blobs, freed) = ctx.state.db.expunge(row.mailbox_id, &[row.uid]).await?;
    ctx.state.db.add_usage(ctx.account.id, -freed).await?;
    ctx.state.hub.notify(row.mailbox_id);
    ctx.state.blobs.delete_all(&blobs).await;
    Ok(())
}

pub(super) fn encode_header_text(s: &str) -> String {
    if s.is_ascii() && !s.contains(['\r', '\n']) {
        return s.to_string();
    }
    let clean: String = s.chars().filter(|c| !c.is_control()).collect();
    format!("=?UTF-8?B?{}?=", base64::engine::general_purpose::STANDARD.encode(clean.as_bytes()))
}

fn format_addrs(v: Option<&Value>) -> Result<Option<String>, String> {
    let Some(Value::Array(a)) = v else { return Ok(None) };
    let mut out = vec![];
    for x in a {
        let email = x.get("email").and_then(|e| e.as_str()).ok_or("address needs an email")?;
        let email = crate::util::normalize_address(email).ok_or_else(|| format!("invalid address {email}"))?;
        match x.get("name").and_then(|n| n.as_str()).filter(|n| !n.trim().is_empty()) {
            Some(n) if n.is_ascii() => out.push(format!("\"{}\" <{email}>", n.replace(['"', '\\', '\r', '\n'], ""))),
            Some(n) => out.push(format!("{} <{email}>", encode_header_text(n))),
            None => out.push(email),
        }
    }
    Ok(if out.is_empty() { None } else { Some(out.join(", ")) })
}

fn qp_encode(s: &str) -> String {
    let mut out = String::new();
    for line in s.replace("\r\n", "\n").split('\n') {
        let mut cur = String::new();
        let bytes = line.as_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            let last = i + 1 == bytes.len();
            let enc = if (b == b' ' || b == b'\t') && last {
                format!("={b:02X}")
            } else if b == b'=' || b >= 0x7f || (b < 0x20 && b != b'\t') {
                format!("={b:02X}")
            } else {
                (b as char).to_string()
            };
            if cur.len() + enc.len() > 75 {
                out.push_str(&cur);
                out.push_str("=\r\n");
                cur.clear();
            }
            cur.push_str(&enc);
        }
        out.push_str(&cur);
        out.push_str("\r\n");
    }
    out
}

/// Build a MIME message from an Email/set create object.
async fn build_email(ctx: &Ctx, obj: &Map<String, Value>) -> Result<Vec<u8>, String> {
    let host = ctx.state.hostname();
    let mut h = String::new();
    let from = format_addrs(obj.get("from"))?.unwrap_or_else(|| ctx.account.email.clone());
    h.push_str(&format!("From: {from}\r\n"));
    for (k, name) in [("to", "To"), ("cc", "Cc"), ("bcc", "Bcc"), ("replyTo", "Reply-To"), ("sender", "Sender")] {
        if let Some(v) = format_addrs(obj.get(k))? {
            h.push_str(&format!("{name}: {v}\r\n"));
        }
    }
    if let Some(s) = obj.get("subject").and_then(|v| v.as_str()) {
        h.push_str(&format!("Subject: {}\r\n", encode_header_text(s)));
    }
    let date = obj.get("sentAt").and_then(|v| v.as_str()).and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok()).map(|d| d.to_rfc2822()).unwrap_or_else(|| chrono::Utc::now().to_rfc2822());
    h.push_str(&format!("Date: {date}\r\n"));
    let mid = obj.get("messageId").and_then(|v| v.as_array()).and_then(|a| a.first()).and_then(|v| v.as_str()).map(String::from).unwrap_or_else(|| format!("{}@{host}", uuid::Uuid::new_v4().simple()));
    h.push_str(&format!("Message-ID: <{}>\r\n", mid.replace(['<', '>', '\r', '\n'], "")));
    for (k, name) in [("inReplyTo", "In-Reply-To"), ("references", "References")] {
        if let Some(a) = obj.get(k).and_then(|v| v.as_array()) {
            let ids: Vec<String> = a.iter().filter_map(|x| x.as_str()).map(|x| format!("<{}>", x.replace(['<', '>', '\r', '\n', ' '], ""))).collect();
            if !ids.is_empty() {
                h.push_str(&format!("{name}: {}\r\n", ids.join(" ")));
            }
        }
    }
    if let Some(hs) = obj.get("headers").and_then(|v| v.as_array()) {
        for x in hs {
            if let (Some(n), Some(v)) = (x.get("name").and_then(|v| v.as_str()), x.get("value").and_then(|v| v.as_str())) {
                let n: String = n.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-').collect();
                if !n.is_empty() && !["from", "to", "cc", "bcc", "subject", "date", "message-id", "mime-version", "content-type"].contains(&n.to_ascii_lowercase().as_str()) {
                    h.push_str(&format!("{n}: {}\r\n", v.replace(['\r', '\n'], " ")));
                }
            }
        }
    }
    h.push_str("MIME-Version: 1.0\r\n");
    let values = obj.get("bodyValues").and_then(|v| v.as_object()).cloned().unwrap_or_default();
    let body_text = |key: &str| -> Option<String> {
        let parts = obj.get(key)?.as_array()?;
        let pid = parts.first()?.get("partId")?.as_str()?;
        values.get(pid)?.get("value")?.as_str().map(String::from)
    };
    let text = body_text("textBody");
    let html = body_text("htmlBody");
    let text_part = |t: &str, sub: &str| format!("Content-Type: text/{sub}; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n{}", qp_encode(t));
    let boundary = |n: &str| format!("=_picacho_{n}_{}", uuid::Uuid::new_v4().simple());
    let main = match (&text, &html) {
        (Some(t), Some(hh)) => {
            let b = boundary("alt");
            format!("Content-Type: multipart/alternative; boundary=\"{b}\"\r\n\r\n--{b}\r\n{}\r\n--{b}\r\n{}\r\n--{b}--\r\n", text_part(t, "plain"), text_part(hh, "html"))
        }
        (None, Some(hh)) => text_part(hh, "html"),
        (Some(t), None) => text_part(t, "plain"),
        (None, None) => text_part("", "plain"),
    };
    let mut atts = vec![];
    if let Some(a) = obj.get("attachments").and_then(|v| v.as_array()) {
        for x in a {
            let blob = x.get("blobId").and_then(|v| v.as_str()).map(|s| ctx.id(s)).ok_or("attachment needs a blobId")?;
            let data = blob_bytes(&ctx.state, &ctx.account, &blob).await.map_err(|e| e.to_string())?.ok_or("attachment blob not found")?;
            let ctype = x.get("type").and_then(|v| v.as_str()).filter(|t| t.contains('/') && t.is_ascii() && !t.contains(['\r', '\n', ';'])).unwrap_or("application/octet-stream");
            let name = x.get("name").and_then(|v| v.as_str()).map(|n| n.replace(['"', '\r', '\n', '\\'], "")).unwrap_or_else(|| "attachment".into());
            let disp = if x.get("disposition").and_then(|v| v.as_str()) == Some("inline") { "inline" } else { "attachment" };
            let enc = base64::engine::general_purpose::STANDARD.encode(&data);
            let lines: Vec<&str> = enc.as_bytes().chunks(76).map(|c| std::str::from_utf8(c).unwrap()).collect();
            let fname = encode_header_text(&name);
            let cid = x.get("cid").and_then(|v| v.as_str()).map(|c| format!("Content-ID: <{}>\r\n", c.replace(['<', '>', '\r', '\n'], ""))).unwrap_or_default();
            atts.push(format!("Content-Type: {ctype}; name=\"{fname}\"\r\nContent-Disposition: {disp}; filename=\"{fname}\"\r\n{cid}Content-Transfer-Encoding: base64\r\n\r\n{}\r\n", lines.join("\r\n")));
        }
    }
    let body = if atts.is_empty() {
        main
    } else {
        let b = boundary("mix");
        let mut s = format!("Content-Type: multipart/mixed; boundary=\"{b}\"\r\n\r\n--{b}\r\n{main}");
        for a in atts {
            s.push_str(&format!("\r\n--{b}\r\n{a}"));
        }
        s.push_str(&format!("\r\n--{b}--\r\n"));
        s
    };
    Ok(format!("{h}{body}").into_bytes())
}

pub(super) async fn email_set(ctx: &mut Ctx, args: &Value) -> Result<Value, MethodError> {
    let old_state = state_str(ctx).await?;
    if let Some(s) = args.get("ifInState").and_then(|v| v.as_str()) {
        if s != old_state {
            return Err(MethodError("stateMismatch", "State changed.".into()));
        }
    }
    let (mut created, mut not_created) = (Map::new(), Map::new());
    let (mut updated, mut not_updated) = (Map::new(), Map::new());
    let (mut destroyed, mut not_destroyed) = (vec![], Map::new());
    if let Some(c) = args.get("create").and_then(|v| v.as_object()) {
        for (cid, obj) in c {
            let Some(obj) = obj.as_object() else { continue };
            let mailbox = obj
                .get("mailboxIds")
                .and_then(|v| v.as_object())
                .and_then(|m| m.iter().find(|(_, b)| b.as_bool() == Some(true)).map(|(k, _)| ctx.id(k)))
                .and_then(|k| num_id(&k, 'm'));
            let Some(mb) = (match mailbox {
                Some(id) => ctx.state.db.mailbox_by_id(id).await?.filter(|m| m.account_id == ctx.account.id),
                None => None,
            }) else {
                not_created.insert(cid.clone(), set_error("invalidProperties", "mailboxIds must name one of your mailboxes"));
                continue;
            };
            let raw = match build_email(ctx, obj).await {
                Ok(r) => r,
                Err(e) => {
                    not_created.insert(cid.clone(), set_error("invalidProperties", e));
                    continue;
                }
            };
            let flags: Vec<String> = obj
                .get("keywords")
                .and_then(|v| v.as_object())
                .map(|k| k.iter().filter(|(_, b)| b.as_bool() == Some(true)).filter_map(|(k, _)| keyword_to_flag(k)).collect())
                .unwrap_or_default();
            let date = obj.get("receivedAt").and_then(|v| v.as_str()).and_then(parse_utc);
            match crate::server::store_message(&ctx.state, ctx.account.id, &mb, &raw, &flags.join(" "), date).await {
                Ok(uid) => {
                    let row = ctx.state.db.messages_by_uids(mb.id, uid, uid).await?.into_iter().next();
                    if let Some(r) = row {
                        let id = format!("e{}", r.id);
                        ctx.created.insert(cid.clone(), id.clone());
                        created.insert(cid.clone(), json!({"id": id, "blobId": format!("b{}", r.blob.replace('/', "_")), "threadId": format!("t{}", r.thread_id), "size": r.size}));
                    }
                }
                Err(crate::server::StoreError::OverQuota) => {
                    not_created.insert(cid.clone(), set_error("overQuota", "Quota exceeded"));
                }
                Err(crate::server::StoreError::Other(e)) => return Err(e.into()),
            }
        }
    }
    if let Some(u) = args.get("update").and_then(|v| v.as_object()) {
        for (id, patch) in u {
            let rid = ctx.id(id);
            let rows = match num_id(&rid, 'e') {
                Some(n) => ctx.state.db.messages_by_ids(ctx.account.id, &[n]).await?,
                None => vec![],
            };
            let Some(row) = rows.into_iter().next() else {
                not_updated.insert(id.clone(), set_error("notFound", "No such email"));
                continue;
            };
            let Some(patch) = patch.as_object() else {
                not_updated.insert(id.clone(), set_error("invalidPatch", "Patch must be an object"));
                continue;
            };
            match update_email(ctx, &row, patch).await? {
                Some(e) => {
                    not_updated.insert(id.clone(), e);
                }
                None => {
                    updated.insert(id.clone(), Value::Null);
                }
            }
        }
    }
    if let Some(d) = args.get("destroy").and_then(|v| v.as_array()) {
        for id in d.iter().filter_map(|v| v.as_str()) {
            let rows = match num_id(&ctx.id(id), 'e') {
                Some(n) => ctx.state.db.messages_by_ids(ctx.account.id, &[n]).await?,
                None => vec![],
            };
            match rows.first() {
                Some(r) => {
                    destroy_email(ctx, r).await?;
                    destroyed.push(id.to_string());
                }
                None => {
                    not_destroyed.insert(id.to_string(), set_error("notFound", "No such email"));
                }
            }
        }
    }
    Ok(json!({"accountId": account_id(&ctx.account), "oldState": old_state, "newState": state_str(ctx).await?,
        "created": created, "updated": updated, "destroyed": destroyed,
        "notCreated": not_created, "notUpdated": not_updated, "notDestroyed": not_destroyed}))
}

async fn email_import(ctx: &mut Ctx, args: &Value) -> Result<Value, MethodError> {
    let old_state = state_str(ctx).await?;
    let (mut created, mut not_created) = (Map::new(), Map::new());
    if let Some(e) = args.get("emails").and_then(|v| v.as_object()) {
        for (cid, obj) in e {
            let blob = obj.get("blobId").and_then(|v| v.as_str()).map(|s| ctx.id(s)).unwrap_or_default();
            let Some(data) = blob_bytes(&ctx.state, &ctx.account, &blob).await? else {
                not_created.insert(cid.clone(), set_error("blobNotFound", "Blob not found"));
                continue;
            };
            let mb_id = obj.get("mailboxIds").and_then(|v| v.as_object()).and_then(|m| m.keys().next().map(|k| ctx.id(k))).and_then(|k| num_id(&k, 'm'));
            let Some(mb) = (match mb_id {
                Some(id) => ctx.state.db.mailbox_by_id(id).await?.filter(|m| m.account_id == ctx.account.id),
                None => None,
            }) else {
                not_created.insert(cid.clone(), set_error("invalidProperties", "mailboxIds must name one of your mailboxes"));
                continue;
            };
            let flags: Vec<String> = obj
                .get("keywords")
                .and_then(|v| v.as_object())
                .map(|k| k.iter().filter(|(_, b)| b.as_bool() == Some(true)).filter_map(|(k, _)| keyword_to_flag(k)).collect())
                .unwrap_or_default();
            let date = obj.get("receivedAt").and_then(|v| v.as_str()).and_then(parse_utc);
            let raw = crate::util::normalize_crlf(&data);
            match crate::server::store_message(&ctx.state, ctx.account.id, &mb, &raw, &flags.join(" "), date).await {
                Ok(uid) => {
                    if let Some(r) = ctx.state.db.messages_by_uids(mb.id, uid, uid).await?.into_iter().next() {
                        let id = format!("e{}", r.id);
                        ctx.created.insert(cid.clone(), id.clone());
                        created.insert(cid.clone(), json!({"id": id, "blobId": format!("b{}", r.blob.replace('/', "_")), "threadId": format!("t{}", r.thread_id), "size": r.size}));
                    }
                }
                Err(crate::server::StoreError::OverQuota) => {
                    not_created.insert(cid.clone(), set_error("overQuota", "Quota exceeded"));
                }
                Err(crate::server::StoreError::Other(e)) => return Err(e.into()),
            }
        }
    }
    Ok(json!({"accountId": account_id(&ctx.account), "oldState": old_state, "newState": state_str(ctx).await?,
        "created": created, "notCreated": not_created}))
}

// ---------------------------------------------------------------- submission

/// Remove Bcc header fields before sending.
pub(super) fn strip_bcc(raw: &[u8]) -> Vec<u8> {
    let root = mime::parse(raw);
    let mut out = Vec::with_capacity(raw.len());
    let mut pos = 0;
    for f in root.fields.iter().filter(|f| f.name.eq_ignore_ascii_case("bcc")) {
        out.extend_from_slice(&raw[pos..f.start]);
        pos = f.end;
    }
    out.extend_from_slice(&raw[pos..]);
    out
}

async fn quota_get(ctx: &mut Ctx, args: &Value) -> Result<Value, MethodError> {
    let a = ctx.state.db.get_account(ctx.account.id).await?.unwrap_or(ctx.account.clone());
    let q = json!({"id": "q0", "resourceType": "octets", "used": a.used_bytes, "hardLimit": if a.quota_bytes > 0 { json!(a.quota_bytes) } else { Value::Null },
        "scope": "account", "name": "Mail storage", "types": ["Email"], "warnLimit": Value::Null, "softLimit": Value::Null});
    let ids = ids_arg(ctx, args)?;
    let (list, not_found): (Vec<Value>, Vec<String>) = match ids {
        None => (vec![q], vec![]),
        Some(ids) => {
            let mut l = vec![];
            let mut nf = vec![];
            for i in ids {
                if i == "q0" {
                    l.push(q.clone());
                } else {
                    nf.push(i);
                }
            }
            (l, nf)
        }
    };
    Ok(json!({"accountId": account_id(&ctx.account), "state": state_str(ctx).await?, "list": list, "notFound": not_found}))
}
