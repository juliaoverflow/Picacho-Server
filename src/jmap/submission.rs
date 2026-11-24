//! JMAP EmailSubmission (RFC 8621 section 7) and Identity (section 6).
//!
//! Submissions are kept (see `crate::submit`): `pending` while held for
//! later (HOLDUNTIL/HOLDFOR, or SMTP FUTURERELEASE) and cancelable with
//! `undoStatus: canceled`; `final` once sent, with each recipient's
//! `deliveryStatus`. Ids: submissions `s<n>`; identities `i<account>` (the
//! account's own address), `i<account>x<alias>` (an alias delivering to it)
//! and `j<n>` (created with Identity/set).
use super::mail::{email_set, ids_arg, meta_of_row, num_id, pick, props_arg, set_error, state_str, strip_bcc, utc};
use super::{account_id, Ctx, MethodError};
use crate::db::{IdentityRow, Submission};
use serde_json::{json, Map, Value};

type R = Result<Vec<(String, Value)>, MethodError>;

/// One identity as JMAP shows it.
pub struct Identity {
    pub id: String,
    pub email: String,
    pub builtin: bool,
    pub row: Option<IdentityRow>,
}

/// Built-in identities (the account's address and aliases to it), with any
/// stored settings, then the ones the account created.
pub async fn identities(ctx: &Ctx) -> anyhow::Result<Vec<Identity>> {
    let rows = ctx.state.db.identities(ctx.account.id).await?;
    let mut out = vec![Identity { id: format!("i{}", ctx.account.id), email: ctx.account.email.clone(), builtin: true, row: None }];
    for a in ctx.state.db.list_aliases().await? {
        if a.active && !a.source.starts_with('@') && a.destination.split([',', ' ']).any(|d| d.trim().eq_ignore_ascii_case(&ctx.account.email)) {
            out.push(Identity { id: format!("i{}x{}", ctx.account.id, a.id), email: a.source.clone(), builtin: true, row: None });
        }
    }
    for i in out.iter_mut() {
        i.row = rows.iter().find(|r| r.builtin == i.id).cloned();
    }
    for r in rows.into_iter().filter(|r| r.builtin.is_empty()) {
        out.push(Identity { id: format!("j{}", r.id), email: r.email.clone(), builtin: false, row: Some(r) });
    }
    Ok(out)
}

fn addresses(s: &str) -> Value {
    serde_json::from_str::<Value>(s).ok().filter(|v| v.is_array()).unwrap_or(Value::Null)
}

fn identity_json(ctx: &Ctx, i: &Identity) -> Map<String, Value> {
    let r = i.row.clone().unwrap_or_default();
    let mut o = Map::new();
    o.insert("id".into(), json!(i.id));
    o.insert("name".into(), json!(if i.row.is_some() { r.name.clone() } else { ctx.account.display_name.clone() }));
    o.insert("email".into(), json!(i.email));
    o.insert("replyTo".into(), addresses(&r.reply_to));
    o.insert("bcc".into(), addresses(&r.bcc));
    o.insert("textSignature".into(), json!(r.text_signature));
    o.insert("htmlSignature".into(), json!(r.html_signature));
    o.insert("mayDelete".into(), json!(!i.builtin));
    o
}

pub async fn identity_get(ctx: &mut Ctx, args: &Value) -> Result<Value, MethodError> {
    let all = identities(ctx).await?;
    let props = props_arg(args, &["id", "name", "email", "replyTo", "bcc", "textSignature", "htmlSignature", "mayDelete"]);
    let ids = ids_arg(ctx, args)?;
    let wanted: Vec<String> = ids.unwrap_or_else(|| all.iter().map(|x| x.id.clone()).collect());
    let (mut list, mut not_found) = (vec![], vec![]);
    for id in wanted {
        match all.iter().find(|x| x.id == id) {
            Some(i) => list.push(pick(identity_json(ctx, i), &props)),
            None => not_found.push(id),
        }
    }
    Ok(json!({"accountId": account_id(&ctx.account), "state": state_str(ctx).await?, "list": list, "notFound": not_found}))
}

/// `[{name, email}]` or null, as stored.
fn address_list(v: Option<&Value>) -> Result<Option<String>, &'static str> {
    match v {
        None => Ok(None),
        Some(Value::Null) => Ok(Some(String::new())),
        Some(Value::Array(a)) => {
            let mut out = vec![];
            for x in a {
                let email = x.get("email").and_then(|e| e.as_str()).and_then(crate::util::normalize_address).ok_or("invalid address")?;
                let name = x.get("name").and_then(|n| n.as_str()).map(|n| n.chars().take(200).collect::<String>());
                out.push(json!({"name": name, "email": email}));
            }
            Ok(Some(Value::Array(out).to_string()))
        }
        _ => Err("must be a list of addresses or null"),
    }
}

/// Apply the settable properties of an Identity object.
fn apply_identity(r: &mut IdentityRow, obj: &Map<String, Value>) -> Result<(), String> {
    for (k, v) in obj {
        match k.as_str() {
            "name" => r.name = v.as_str().ok_or("name must be a string")?.chars().take(200).collect(),
            "replyTo" => r.reply_to = address_list(Some(v)).map_err(|e| format!("replyTo {e}"))?.unwrap_or_default(),
            "bcc" => r.bcc = address_list(Some(v)).map_err(|e| format!("bcc {e}"))?.unwrap_or_default(),
            "textSignature" => r.text_signature = v.as_str().ok_or("textSignature must be a string")?.chars().take(10_000).collect(),
            "htmlSignature" => r.html_signature = v.as_str().ok_or("htmlSignature must be a string")?.chars().take(50_000).collect(),
            "id" | "mayDelete" | "email" => {}
            other => return Err(format!("unknown property {other}")),
        }
    }
    Ok(())
}

pub async fn identity_set(ctx: &mut Ctx, args: &Value) -> Result<Value, MethodError> {
    let old_state = state_str(ctx).await?;
    let (mut created, mut not_created) = (Map::new(), Map::new());
    let (mut updated, mut not_updated) = (Map::new(), Map::new());
    let (mut destroyed, mut not_destroyed) = (vec![], Map::new());
    if let Some(c) = args.get("create").and_then(|v| v.as_object()) {
        for (cid, obj) in c {
            let Some(o) = obj.as_object() else {
                not_created.insert(cid.clone(), set_error("invalidProperties", "not an object"));
                continue;
            };
            let Some(email) = o.get("email").and_then(|v| v.as_str()).and_then(crate::util::normalize_address) else {
                not_created.insert(cid.clone(), set_error("invalidProperties", "email is required"));
                continue;
            };
            if !crate::submit::owns_address(&ctx.state, &ctx.account, &email).await {
                not_created.insert(cid.clone(), set_error("forbiddenFrom", "You may only add your own addresses"));
                continue;
            }
            let mut r = IdentityRow { email: email.clone(), name: ctx.account.display_name.clone(), ..Default::default() };
            if let Err(e) = apply_identity(&mut r, o) {
                not_created.insert(cid.clone(), set_error("invalidProperties", e));
                continue;
            }
            let id = format!("j{}", ctx.state.db.save_identity(ctx.account.id, &r).await?);
            ctx.created.insert(cid.clone(), id.clone());
            created.insert(cid.clone(), json!({"id": id, "mayDelete": true}));
        }
    }
    if let Some(u) = args.get("update").and_then(|v| v.as_object()) {
        let all = identities(ctx).await?;
        for (id, patch) in u {
            let id = ctx.id(id);
            let (Some(i), Some(p)) = (all.iter().find(|x| x.id == id), patch.as_object()) else {
                not_updated.insert(id, set_error("notFound", "No such identity"));
                continue;
            };
            if p.get("email").and_then(|v| v.as_str()).is_some_and(|e| !e.eq_ignore_ascii_case(&i.email)) {
                not_updated.insert(id, set_error("invalidProperties", "email can't be changed"));
                continue;
            }
            let mut r = i.row.clone().unwrap_or(IdentityRow {
                builtin: if i.builtin { i.id.clone() } else { String::new() },
                email: i.email.clone(),
                name: ctx.account.display_name.clone(),
                ..Default::default()
            });
            if let Err(e) = apply_identity(&mut r, p) {
                not_updated.insert(id, set_error("invalidProperties", e));
                continue;
            }
            ctx.state.db.save_identity(ctx.account.id, &r).await?;
            updated.insert(id, Value::Null);
        }
    }
    if let Some(d) = args.get("destroy").and_then(|v| v.as_array()) {
        for id in d.iter().filter_map(|v| v.as_str()).map(|s| ctx.id(s)) {
            match num_id(&id, 'j') {
                Some(n) if ctx.state.db.delete_identity(ctx.account.id, n).await? => destroyed.push(id),
                _ if id.starts_with('i') => {
                    not_destroyed.insert(id, set_error("forbidden", "This address comes from your account and can't be removed"));
                }
                _ => {
                    not_destroyed.insert(id, set_error("notFound", "No such identity"));
                }
            }
        }
    }
    Ok(json!({"accountId": account_id(&ctx.account), "oldState": old_state, "newState": state_str(ctx).await?,
        "created": created, "notCreated": not_created, "updated": updated, "notUpdated": not_updated,
        "destroyed": destroyed, "notDestroyed": not_destroyed}))
}

// ------------------------------------------------------------ submissions

fn submission_json(ctx: &Ctx, s: &Submission) -> Map<String, Value> {
    let dsn = crate::outbound::Dsn::from_json(&s.dsn);
    let mut from_params = Map::new();
    if !dsn.ret.is_empty() {
        from_params.insert("RET".into(), json!(dsn.ret));
    }
    if !dsn.envid.is_empty() {
        from_params.insert("ENVID".into(), json!(dsn.envid));
    }
    if s.requiretls {
        from_params.insert("REQUIRETLS".into(), Value::Null);
    }
    let rcpt_to: Vec<Value> = s.recipients.iter().map(|r| json!({"email": r, "parameters": Value::Null})).collect();
    let delivery: Value = serde_json::from_str(&s.delivery).unwrap_or(Value::Null);
    let mut o = Map::new();
    o.insert("id".into(), json!(format!("s{}", s.id)));
    o.insert("identityId".into(), json!(if s.identity.is_empty() { format!("i{}", ctx.account.id) } else { s.identity.clone() }));
    o.insert("emailId".into(), if s.email_id > 0 { json!(format!("e{}", s.email_id)) } else { Value::Null });
    o.insert("threadId".into(), if s.thread_id > 0 { json!(format!("t{}", s.thread_id)) } else { Value::Null });
    o.insert(
        "envelope".into(),
        json!({"mailFrom": {"email": s.sender, "parameters": if from_params.is_empty() { Value::Null } else { Value::Object(from_params) }}, "rcptTo": rcpt_to}),
    );
    o.insert("sendAt".into(), json!(utc(s.send_at)));
    o.insert("undoStatus".into(), json!(s.undo_status));
    o.insert("deliveryStatus".into(), if delivery.as_object().is_some_and(|d| !d.is_empty()) { delivery } else { Value::Null });
    o.insert("dsnBlobIds".into(), json!([]));
    o.insert("mdnBlobIds".into(), json!([]));
    o
}

const SUBMISSION_PROPS: [&str; 11] =
    ["id", "identityId", "emailId", "threadId", "envelope", "sendAt", "undoStatus", "deliveryStatus", "dsnBlobIds", "mdnBlobIds", "sentAt"];

pub async fn submission_get(ctx: &mut Ctx, args: &Value) -> Result<Value, MethodError> {
    let all = ctx.state.db.submissions(ctx.account.id).await?;
    let props = props_arg(args, &SUBMISSION_PROPS[..10]);
    let ids = ids_arg(ctx, args)?;
    let (mut list, mut not_found) = (vec![], vec![]);
    match ids {
        None => list.extend(all.iter().map(|s| pick(submission_json(ctx, s), &props))),
        Some(ids) => {
            for id in ids {
                match num_id(&id, 's').and_then(|n| all.iter().find(|s| s.id == n)) {
                    Some(s) => list.push(pick(submission_json(ctx, s), &props)),
                    None => not_found.push(id),
                }
            }
        }
    }
    Ok(json!({"accountId": account_id(&ctx.account), "state": state_str(ctx).await?, "list": list, "notFound": not_found}))
}

pub async fn submission_query(ctx: &mut Ctx, args: &Value) -> Result<Value, MethodError> {
    let mut all = ctx.state.db.submissions(ctx.account.id).await?;
    let f = args.get("filter").cloned().unwrap_or(Value::Null);
    if f.get("operator").is_some() {
        return Err(MethodError("unsupportedFilter", "Filter operators aren't supported here.".into()));
    }
    let id_list = |k: &str, prefix: char| -> Option<Vec<i64>> {
        f.get(k).and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(|s| ctx.id(s))).filter_map(|s| num_id(&s, prefix)).collect())
    };
    if let Some(ids) = f.get("identityIds").and_then(|v| v.as_array()) {
        let ids: Vec<String> = ids.iter().filter_map(|x| x.as_str().map(|s| ctx.id(s))).collect();
        let own = format!("i{}", ctx.account.id);
        all.retain(|s| ids.iter().any(|i| *i == s.identity || (s.identity.is_empty() && *i == own)));
    }
    if let Some(ids) = id_list("emailIds", 'e') {
        all.retain(|s| ids.contains(&s.email_id));
    }
    if let Some(ids) = id_list("threadIds", 't') {
        all.retain(|s| ids.contains(&s.thread_id));
    }
    if let Some(u) = f.get("undoStatus").and_then(|v| v.as_str()) {
        all.retain(|s| s.undo_status == u);
    }
    let date = |k: &str| f.get(k).and_then(|v| v.as_str()).and_then(|d| chrono::DateTime::parse_from_rfc3339(d).ok()).map(|d| d.timestamp());
    if let Some(t) = date("before") {
        all.retain(|s| s.send_at < t);
    }
    if let Some(t) = date("after") {
        all.retain(|s| s.send_at >= t);
    }
    if let Some(c) = args.get("sort").and_then(|v| v.as_array()).and_then(|a| a.first()) {
        let asc = c.get("isAscending").and_then(|v| v.as_bool()).unwrap_or(true);
        match c.get("property").and_then(|v| v.as_str()).unwrap_or("") {
            "emailId" => all.sort_by_key(|s| s.email_id),
            "threadId" => all.sort_by_key(|s| s.thread_id),
            // RFC 8621 names it sentAt; sendAt is what the property is called.
            "sentAt" | "sendAt" => all.sort_by_key(|s| (s.send_at, s.id)),
            p => return Err(MethodError("unsupportedSort", format!("Can't sort by {p}."))),
        }
        if !asc {
            all.reverse();
        }
    }
    let total = all.len();
    let position = args.get("position").and_then(|v| v.as_i64()).unwrap_or(0).max(0) as usize;
    let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(super::MAX_OBJECTS as u64) as usize;
    let ids: Vec<String> = all.iter().skip(position).take(limit).map(|s| format!("s{}", s.id)).collect();
    let mut out = json!({"accountId": account_id(&ctx.account), "queryState": state_str(ctx).await?, "canCalculateChanges": false,
        "position": position, "ids": ids});
    if args.get("calculateTotal").and_then(|v| v.as_bool()).unwrap_or(false) {
        out["total"] = json!(total);
    }
    Ok(out)
}

/// What a create may ask for in the envelope.
struct Envelope {
    mail_from: String,
    rcpts: Vec<String>,
    dsn: crate::outbound::Dsn,
    requiretls: bool,
    hold: Option<i64>,
}

fn envelope(ctx: &Ctx, env: &Value, default_from: &str) -> Result<Envelope, Value> {
    let mut e = Envelope { mail_from: default_from.into(), rcpts: vec![], dsn: Default::default(), requiretls: false, hold: None };
    if let Some(mf) = env.get("mailFrom") {
        if let Some(m) = mf.get("email").and_then(|v| v.as_str()) {
            e.mail_from = m.to_string();
        }
        if let Some(p) = mf.get("parameters").and_then(|v| v.as_object()) {
            for (k, v) in p {
                let val = v.as_str().unwrap_or("");
                match k.to_ascii_uppercase().as_str() {
                    "HOLDUNTIL" | "HOLDFOR" => {
                        let t = crate::submit::hold_time(&ctx.state, k, &match v {
                            Value::Number(n) => n.to_string(),
                            _ => val.to_string(),
                        })
                        .map_err(|m| set_error("invalidProperties", m))?;
                        e.hold = Some(t);
                    }
                    "RET" => e.dsn.ret = val.to_ascii_uppercase(),
                    "ENVID" => e.dsn.envid = val.chars().take(100).collect(),
                    "REQUIRETLS" => e.requiretls = true,
                    "BY" => {
                        let (n, mode) = val.split_once(';').unwrap_or((val, "R"));
                        let secs: i64 = n.parse().map_err(|_| set_error("invalidProperties", "BY needs <seconds>;R|N"))?;
                        e.dsn.by = Some(crate::util::now() + secs);
                        e.dsn.by_mode = if mode.to_ascii_uppercase().starts_with('N') { "N".into() } else { "R".into() };
                    }
                    "MT-PRIORITY" => {
                        let p: i8 = val.parse().ok().filter(|p: &i8| (-9..=9).contains(p)).ok_or_else(|| set_error("invalidProperties", "MT-PRIORITY must be -9 to 9"))?;
                        e.dsn.priority = Some(p);
                    }
                    "SIZE" | "BODY" | "SMTPUTF8" => {}
                    other => return Err(set_error("invalidProperties", format!("Unsupported mailFrom parameter {other}"))),
                }
            }
        }
    }
    if let Some(r) = env.get("rcptTo").and_then(|v| v.as_array()) {
        for x in r {
            let Some(addr) = x.get("email").and_then(|v| v.as_str()).and_then(crate::util::normalize_address) else {
                return Err(set_error("invalidRecipients", "Invalid recipient address"));
            };
            if let Some(p) = x.get("parameters").and_then(|v| v.as_object()) {
                let mut d = crate::outbound::RcptDsn::default();
                for (k, v) in p {
                    let val = v.as_str().unwrap_or("");
                    match k.to_ascii_uppercase().as_str() {
                        "NOTIFY" => d.notify = val.to_ascii_uppercase(),
                        "ORCPT" => d.orcpt = val.to_string(),
                        other => return Err(set_error("invalidProperties", format!("Unsupported rcptTo parameter {other}"))),
                    }
                }
                if d != Default::default() {
                    e.dsn.rcpts.insert(addr.clone(), d);
                }
            }
            e.rcpts.push(addr);
        }
    }
    Ok(e)
}

pub async fn submission_set(ctx: &mut Ctx, args: &Value) -> R {
    let old_state = state_str(ctx).await?;
    let (mut created, mut not_created) = (Map::new(), Map::new());
    let (mut updated, mut not_updated) = (Map::new(), Map::new());
    let (mut destroyed, mut not_destroyed) = (vec![], Map::new());
    // Submissions that succeeded, by the keys onSuccess* may use.
    let mut succeeded: Vec<(Vec<String>, String)> = vec![];
    let ids = identities(ctx).await?;
    if let Some(c) = args.get("create").and_then(|v| v.as_object()) {
        for (cid, obj) in c {
            let identity = obj.get("identityId").and_then(|v| v.as_str()).map(|s| ctx.id(s)).unwrap_or_default();
            let Some(ident) = ids.iter().find(|x| x.id == identity) else {
                not_created.insert(cid.clone(), set_error("invalidProperties", "identityId not found"));
                continue;
            };
            let email_id = obj.get("emailId").and_then(|v| v.as_str()).map(|s| ctx.id(s)).unwrap_or_default();
            let rows = match num_id(&email_id, 'e') {
                Some(n) => ctx.state.db.messages_by_ids(ctx.account.id, &[n]).await?,
                None => vec![],
            };
            let Some(row) = rows.into_iter().next() else {
                not_created.insert(cid.clone(), set_error("invalidProperties", "emailId not found"));
                continue;
            };
            let mut env = match envelope(ctx, obj.get("envelope").unwrap_or(&Value::Null), &ident.email) {
                Ok(e) => e,
                Err(e) => {
                    not_created.insert(cid.clone(), e);
                    continue;
                }
            };
            if !env.mail_from.eq_ignore_ascii_case(&ident.email) && !ctx.account.is_admin() {
                not_created.insert(cid.clone(), set_error("forbiddenMailFrom", "You may only send from your own addresses"));
                continue;
            }
            if env.rcpts.is_empty() {
                let meta = meta_of_row(&row);
                env.rcpts = meta.to.iter().chain(meta.cc.iter()).chain(meta.bcc.iter()).filter_map(|a| crate::util::normalize_address(&a.email)).collect();
                env.rcpts.dedup();
            }
            if env.rcpts.is_empty() {
                not_created.insert(cid.clone(), set_error("noRecipients", "No recipients"));
                continue;
            }
            let limits = ctx.state.settings().limits.clone();
            if env.rcpts.len() > limits.max_recipients {
                not_created.insert(cid.clone(), json!({"type": "tooManyRecipients", "maxRecipients": limits.max_recipients}));
                continue;
            }
            if let Err(e) = crate::submit::check_recipients(&ctx.state, &ctx.account, &env.rcpts).await {
                let bad: Vec<&String> = env.rcpts.iter().filter(|r| e.starts_with(r.as_str())).collect();
                not_created.insert(cid.clone(), json!({"type": "invalidRecipients", "description": e, "invalidRecipients": bad}));
                continue;
            }
            if limits.send_rate_per_hour > 0 && ctx.state.db.record_send(ctx.account.id).await? > limits.send_rate_per_hour as i64 {
                not_created.insert(cid.clone(), set_error("rateLimit", "Hourly sending limit reached"));
                continue;
            }
            let raw = ctx.state.blobs.get(&row.blob).await?;
            let o = crate::submit::Outgoing {
                identity: ident.id.clone(),
                email_id: row.id,
                thread_id: row.thread_id,
                sender: env.mail_from.clone(),
                rcpts: env.rcpts,
                message: strip_bcc(&raw),
                dsn: env.dsn,
                requiretls: env.requiretls,
                hold_until: env.hold,
            };
            let s = crate::submit::submit(&ctx.state, &ctx.account, o).await?;
            let sid = format!("s{}", s.id);
            ctx.created.insert(cid.clone(), sid.clone());
            created.insert(
                cid.clone(),
                json!({"id": sid, "threadId": format!("t{}", s.thread_id), "sendAt": utc(s.send_at), "undoStatus": s.undo_status}),
            );
            succeeded.push((vec![format!("#{cid}"), sid], email_id));
        }
    }
    if let Some(u) = args.get("update").and_then(|v| v.as_object()) {
        for (id, patch) in u {
            let id = ctx.id(id);
            let sub = match num_id(&id, 's') {
                Some(n) => ctx.state.db.submission(n).await?.filter(|s| s.account_id == ctx.account.id),
                None => None,
            };
            let Some(sub) = sub else {
                not_updated.insert(id, set_error("notFound", "No such submission"));
                continue;
            };
            let Some(p) = patch.as_object() else {
                not_updated.insert(id, set_error("invalidPatch", "not an object"));
                continue;
            };
            if p.keys().any(|k| k != "undoStatus") || p.get("undoStatus").and_then(|v| v.as_str()) != Some("canceled") {
                not_updated.insert(id, set_error("invalidProperties", "Only undoStatus can change, to canceled"));
                continue;
            }
            if !crate::submit::cancel(&ctx.state, sub.id).await? {
                not_updated.insert(id, set_error("cannotUnsend", "The message has already been sent"));
                continue;
            }
            ctx.state.event("info", "smtp", &format!("{} canceled a held message", ctx.account.email));
            updated.insert(id.clone(), Value::Null);
            if sub.email_id > 0 {
                succeeded.push((vec![id], format!("e{}", sub.email_id)));
            }
        }
    }
    if let Some(d) = args.get("destroy").and_then(|v| v.as_array()) {
        for id in d.iter().filter_map(|v| v.as_str()).map(|s| ctx.id(s)) {
            let n = num_id(&id, 's').unwrap_or(-1);
            // Forgetting a held message also cancels it.
            let _ = crate::submit::cancel(&ctx.state, n).await;
            match ctx.state.db.delete_submission(ctx.account.id, n).await? {
                Some(dropped) => {
                    ctx.state.blobs.delete_all(&dropped).await;
                    destroyed.push(id);
                }
                None => {
                    not_destroyed.insert(id, set_error("notFound", "No such submission"));
                }
            }
        }
    }
    let mut out = vec![(
        "EmailSubmission/set".to_string(),
        json!({"accountId": account_id(&ctx.account), "oldState": old_state, "newState": state_str(ctx).await?,
            "created": created, "notCreated": not_created, "updated": updated, "notUpdated": not_updated,
            "destroyed": destroyed, "notDestroyed": not_destroyed}),
    )];
    // onSuccessUpdateEmail / onSuccessDestroyEmail, keyed by "#creationId" or id.
    let (mut email_updates, mut email_destroys) = (Map::new(), vec![]);
    for (keys, email_id) in &succeeded {
        let matches = |k: &str| keys.iter().any(|x| x == k);
        if let Some(u) = args.get("onSuccessUpdateEmail").and_then(|v| v.as_object()) {
            for (k, patch) in u.iter().filter(|(k, _)| matches(k)) {
                let _ = k;
                email_updates.insert(email_id.clone(), patch.clone());
            }
        }
        if let Some(d) = args.get("onSuccessDestroyEmail").and_then(|v| v.as_array()) {
            if d.iter().filter_map(|v| v.as_str()).any(matches) {
                email_destroys.push(json!(email_id));
            }
        }
    }
    if !email_updates.is_empty() || !email_destroys.is_empty() {
        let set_args = json!({"accountId": account_id(&ctx.account), "update": email_updates, "destroy": email_destroys});
        out.push(("Email/set".to_string(), email_set(ctx, &set_args).await?));
    }
    Ok(out)
}
