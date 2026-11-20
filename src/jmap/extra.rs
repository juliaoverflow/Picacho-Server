//! JMAP VacationResponse (RFC 8621 section 8) and SieveScript (RFC 9661).
use super::{account_id, Ctx, MethodError};
use serde_json::{json, Map, Value};

type R = Result<Vec<(String, Value)>, MethodError>;

fn need(ctx: &Ctx, cap: &str) -> Result<(), MethodError> {
    if ctx.using.iter().any(|u| u == cap) {
        Ok(())
    } else {
        Err(MethodError("unknownMethod", format!("{cap} not in 'using'")))
    }
}

fn utc(t: Option<i64>) -> Value {
    t.and_then(|t| chrono::DateTime::from_timestamp(t, 0)).map(|d| json!(d.format("%Y-%m-%dT%H:%M:%SZ").to_string())).unwrap_or(Value::Null)
}

fn parse_utc(v: &Value) -> Result<Option<i64>, String> {
    match v {
        Value::Null => Ok(None),
        Value::String(s) => chrono::DateTime::parse_from_rfc3339(s).map(|d| Some(d.timestamp())).map_err(|_| "invalid UTCDate".into()),
        _ => Err("invalid UTCDate".into()),
    }
}

async fn state(ctx: &Ctx) -> Result<String, MethodError> {
    Ok(ctx.state.db.jmap_state(ctx.account.id).await?.to_string())
}

pub async fn call(ctx: &mut Ctx, name: &str, args: &Value) -> R {
    let cap = if name.starts_with("Vacation") { super::VACATION } else { super::SIEVE };
    need(ctx, cap)?;
    ctx.check_account(args)?;
    let writes = name.ends_with("/set");
    if writes && ctx.read_only {
        return Err(MethodError("forbidden", "This token has read-only access.".into()));
    }
    let out = match name {
        "VacationResponse/get" => vacation_get(ctx, args).await?,
        "VacationResponse/set" => vacation_set(ctx, args).await?,
        "SieveScript/get" => sieve_get(ctx, args).await?,
        "SieveScript/query" => sieve_query(ctx, args).await?,
        "SieveScript/set" => sieve_set(ctx, args).await?,
        "SieveScript/validate" => sieve_validate(ctx, args).await?,
        "SieveScript/changes" | "VacationResponse/changes" => {
            let st = state(ctx).await?;
            json!({"accountId": account_id(&ctx.account), "oldState": args.get("sinceState"), "newState": st, "hasMoreChanges": false, "created": [], "updated": [], "destroyed": []})
        }
        _ => return Err(MethodError("unknownMethod", format!("Unknown method {name}"))),
    };
    Ok(vec![(name.to_string(), out)])
}

async fn vacation_get(ctx: &Ctx, args: &Value) -> Result<Value, MethodError> {
    let v = ctx.state.db.vacation(ctx.account.id).await?;
    let obj = json!({
        "id": "singleton",
        "isEnabled": v.enabled,
        "fromDate": utc(v.from_date),
        "toDate": utc(v.to_date),
        "subject": v.subject,
        "textBody": v.text_body,
        "htmlBody": v.html_body,
    });
    let ids = args.get("ids").and_then(|v| v.as_array()).cloned();
    let (list, not_found) = match ids {
        None => (vec![obj], vec![]),
        Some(ids) => {
            let mut nf = vec![];
            let mut l = vec![];
            for i in ids {
                if i == "singleton" {
                    l.push(obj.clone());
                } else {
                    nf.push(i);
                }
            }
            (l, nf)
        }
    };
    Ok(json!({"accountId": account_id(&ctx.account), "state": state(ctx).await?, "list": list, "notFound": not_found}))
}

async fn vacation_set(ctx: &Ctx, args: &Value) -> Result<Value, MethodError> {
    let old = state(ctx).await?;
    let mut updated = Map::new();
    let mut not_updated = Map::new();
    let mut not_created = Map::new();
    let mut not_destroyed = Map::new();
    for (k, _) in args.get("create").and_then(|v| v.as_object()).cloned().unwrap_or_default() {
        not_created.insert(k, json!({"type": "singleton", "description": "VacationResponse can't be created"}));
    }
    for d in args.get("destroy").and_then(|v| v.as_array()).cloned().unwrap_or_default() {
        not_destroyed.insert(d.as_str().unwrap_or("").to_string(), json!({"type": "singleton"}));
    }
    for (id, patch) in args.get("update").and_then(|v| v.as_object()).cloned().unwrap_or_default() {
        if id != "singleton" {
            not_updated.insert(id, json!({"type": "notFound"}));
            continue;
        }
        let mut v = ctx.state.db.vacation(ctx.account.id).await?;
        let Some(p) = patch.as_object() else {
            not_updated.insert(id, json!({"type": "invalidPatch"}));
            continue;
        };
        let mut err = None;
        for (k, val) in p {
            match k.as_str() {
                "isEnabled" => v.enabled = val.as_bool().unwrap_or(false),
                "subject" => v.subject = val.as_str().map(String::from),
                "textBody" => v.text_body = val.as_str().map(String::from),
                "htmlBody" => v.html_body = val.as_str().map(String::from),
                "fromDate" => match parse_utc(val) {
                    Ok(t) => v.from_date = t,
                    Err(e) => err = Some(e),
                },
                "toDate" => match parse_utc(val) {
                    Ok(t) => v.to_date = t,
                    Err(e) => err = Some(e),
                },
                "id" => {}
                other => err = Some(format!("unknown property {other}")),
            }
        }
        if let Some(e) = err {
            not_updated.insert(id, json!({"type": "invalidProperties", "description": e}));
            continue;
        }
        ctx.state.db.set_vacation(ctx.account.id, &v).await?;
        updated.insert(id, Value::Null);
    }
    Ok(json!({"accountId": account_id(&ctx.account), "oldState": old, "newState": state(ctx).await?,
        "updated": updated, "notUpdated": not_updated, "notCreated": not_created, "notDestroyed": not_destroyed}))
}

fn script_json(s: &crate::sieve::SieveScript) -> Value {
    json!({"id": format!("S{}", s.id), "name": s.name, "blobId": format!("S{}", s.id), "isActive": s.active})
}

fn sid(v: &str) -> Option<i64> {
    v.strip_prefix('S')?.parse().ok()
}

async fn sieve_get(ctx: &Ctx, args: &Value) -> Result<Value, MethodError> {
    let all = ctx.state.db.sieve_scripts(ctx.account.id).await?;
    let (list, nf): (Vec<Value>, Vec<Value>) = match args.get("ids").and_then(|v| v.as_array()) {
        None => (all.iter().map(script_json).collect(), vec![]),
        Some(ids) => {
            let mut l = vec![];
            let mut nf = vec![];
            for i in ids {
                match i.as_str().and_then(sid).and_then(|id| all.iter().find(|s| s.id == id)) {
                    Some(s) => l.push(script_json(s)),
                    None => nf.push(i.clone()),
                }
            }
            (l, nf)
        }
    };
    Ok(json!({"accountId": account_id(&ctx.account), "state": state(ctx).await?, "list": list, "notFound": nf}))
}

async fn sieve_query(ctx: &Ctx, args: &Value) -> Result<Value, MethodError> {
    let mut all = ctx.state.db.sieve_scripts(ctx.account.id).await?;
    if let Some(f) = args.get("filter") {
        if let Some(n) = f.get("name").and_then(|v| v.as_str()) {
            all.retain(|s| s.name.to_lowercase().contains(&n.to_lowercase()));
        }
        if let Some(a) = f.get("isActive").and_then(|v| v.as_bool()) {
            all.retain(|s| s.active == a);
        }
    }
    let ids: Vec<String> = all.iter().map(|s| format!("S{}", s.id)).collect();
    Ok(json!({"accountId": account_id(&ctx.account), "queryState": state(ctx).await?, "canCalculateChanges": false, "position": 0, "total": ids.len(), "ids": ids}))
}

/// Script text from a blob id (an upload, or another script).
async fn blob_text(ctx: &Ctx, blob: &str) -> Result<Option<String>, MethodError> {
    let b = super::mail::blob_bytes(&ctx.state, &ctx.account, blob).await?;
    Ok(b.map(|v| String::from_utf8_lossy(&v).to_string()))
}

async fn sieve_validate(ctx: &Ctx, args: &Value) -> Result<Value, MethodError> {
    let blob = args.get("blobId").and_then(|v| v.as_str()).ok_or_else(|| MethodError::invalid("blobId is required"))?;
    let Some(text) = blob_text(ctx, blob).await? else { return Err(MethodError("invalidArguments", "blob not found".into())) };
    let error = match crate::sieve::check(&text) {
        Ok(()) => Value::Null,
        Err(e) => json!({"type": "invalidSieve", "description": e}),
    };
    Ok(json!({"accountId": account_id(&ctx.account), "error": error}))
}

async fn sieve_set(ctx: &mut Ctx, args: &Value) -> Result<Value, MethodError> {
    let acc = ctx.account.id;
    let db = ctx.state.db.clone();
    let old = state(ctx).await?;
    let mut created = Map::new();
    let mut not_created = Map::new();
    let mut updated = Map::new();
    let mut not_updated = Map::new();
    let mut destroyed = vec![];
    let mut not_destroyed = Map::new();
    let bad = |d: String| json!({"type": "invalidSieve", "description": d});
    for (cid, obj) in args.get("create").and_then(|v| v.as_object()).cloned().unwrap_or_default() {
        let name = obj.get("name").and_then(|v| v.as_str()).map(String::from).unwrap_or_else(|| format!("script-{}", crate::util::now()));
        let Some(blob) = obj.get("blobId").and_then(|v| v.as_str()) else {
            not_created.insert(cid, json!({"type": "invalidProperties", "properties": ["blobId"]}));
            continue;
        };
        let blob = ctx.id(blob);
        let Some(text) = blob_text(ctx, &blob).await? else {
            not_created.insert(cid, json!({"type": "invalidProperties", "properties": ["blobId"]}));
            continue;
        };
        if !crate::sieve::valid_name(&name) {
            not_created.insert(cid, json!({"type": "invalidProperties", "properties": ["name"]}));
            continue;
        }
        if db.sieve_script(acc, &name).await?.is_some() {
            not_created.insert(cid, json!({"type": "alreadyExists"}));
            continue;
        }
        if db.sieve_count(acc).await? >= crate::sieve::MAX_SCRIPTS {
            not_created.insert(cid, json!({"type": "overQuota"}));
            continue;
        }
        if let Err(e) = crate::sieve::check(&text) {
            not_created.insert(cid, bad(e));
            continue;
        }
        let id = db.sieve_put(acc, &name, &text).await?;
        ctx.created.insert(cid.clone(), format!("S{id}"));
        created.insert(cid, json!({"id": format!("S{id}"), "blobId": format!("S{id}"), "isActive": false}));
    }
    for (id, patch) in args.get("update").and_then(|v| v.as_object()).cloned().unwrap_or_default() {
        let rid = ctx.id(&id);
        let Some(s) = sid(&rid) else {
            not_updated.insert(id, json!({"type": "notFound"}));
            continue;
        };
        let Some(script) = db.sieve_script_by_id(acc, s).await? else {
            not_updated.insert(id, json!({"type": "notFound"}));
            continue;
        };
        let mut name = script.name.clone();
        let mut content = script.content.clone();
        if let Some(n) = patch.get("name").and_then(|v| v.as_str()) {
            if !crate::sieve::valid_name(n) {
                not_updated.insert(id, json!({"type": "invalidProperties", "properties": ["name"]}));
                continue;
            }
            name = n.to_string();
        }
        if let Some(b) = patch.get("blobId").and_then(|v| v.as_str()) {
            let b = ctx.id(b);
            match blob_text(ctx, &b).await? {
                Some(t) => content = t,
                None => {
                    not_updated.insert(id, json!({"type": "invalidProperties", "properties": ["blobId"]}));
                    continue;
                }
            }
            if let Err(e) = crate::sieve::check(&content) {
                not_updated.insert(id, bad(e));
                continue;
            }
        }
        if name != script.name {
            if db.sieve_script(acc, &name).await?.is_some() {
                not_updated.insert(id, json!({"type": "alreadyExists"}));
                continue;
            }
            db.sieve_rename(acc, &script.name, &name).await?;
        }
        db.sieve_put(acc, &name, &content).await?;
        updated.insert(id, Value::Null);
    }
    for d in args.get("destroy").and_then(|v| v.as_array()).cloned().unwrap_or_default() {
        let did = d.as_str().map(|x| ctx.id(x)).unwrap_or_default();
        match sid(&did) {
            Some(s) => match db.sieve_script_by_id(acc, s).await? {
                Some(sc) if sc.active => {
                    not_destroyed.insert(did, json!({"type": "scriptIsActive"}));
                }
                Some(sc) => {
                    db.sieve_delete(acc, &sc.name).await?;
                    destroyed.push(json!(did));
                }
                None => {
                    not_destroyed.insert(did, json!({"type": "notFound"}));
                }
            },
            None => {
                not_destroyed.insert(did, json!({"type": "notFound"}));
            }
        }
    }
    // onSuccessActivateScript / onSuccessDeactivateScript.
    if let Some(a) = args.get("onSuccessActivateScript").and_then(|v| v.as_str()) {
        let a = ctx.id(a.trim_start_matches('#'));
        if let Some(id) = sid(&a) {
            if let Some(sc) = db.sieve_script_by_id(acc, id).await? {
                db.sieve_activate(acc, Some(&sc.name)).await?;
            }
        }
    } else if args.get("onSuccessDeactivateScript").and_then(|v| v.as_bool()) == Some(true) {
        db.sieve_activate(acc, None).await?;
    }
    Ok(json!({"accountId": account_id(&ctx.account), "oldState": old, "newState": state(ctx).await?,
        "created": created, "notCreated": not_created, "updated": updated, "notUpdated": not_updated,
        "destroyed": destroyed, "notDestroyed": not_destroyed}))
}
