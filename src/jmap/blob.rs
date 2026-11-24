//! JMAP Blob management (RFC 9404: Blob/upload, ranged Blob/get), Email/parse
//! (RFC 8621 4.9) and MDN/send (RFC 9007, read receipts).
use super::mail::{addrs_json, blob_bytes, body_into, email_set, ids_json, set_error, utc, BodyOpts};
use super::{account_id, Ctx, MethodError};
use base64::Engine;
use serde_json::{json, Map, Value};

type R = Result<Vec<(String, Value)>, MethodError>;

/// Largest blob Blob/upload builds, and most data sources in one.
pub const MAX_DATA_SOURCES: usize = 64;

pub async fn blob_upload(ctx: &mut Ctx, args: &Value) -> Result<Value, MethodError> {
    let max = ctx.state.settings().limits.max_message_bytes as usize;
    let (mut created, mut not_created) = (Map::new(), Map::new());
    let Some(create) = args.get("create").and_then(|v| v.as_object()) else {
        return Err(MethodError::invalid("create is required"));
    };
    'each: for (cid, obj) in create {
        let Some(sources) = obj.get("data").and_then(|v| v.as_array()) else {
            not_created.insert(cid.clone(), set_error("invalidProperties", "data must be a list"));
            continue;
        };
        if sources.len() > MAX_DATA_SOURCES {
            not_created.insert(cid.clone(), set_error("tooManyDataSources", format!("At most {MAX_DATA_SOURCES} data sources")));
            continue;
        }
        let mut data: Vec<u8> = vec![];
        for src in sources {
            if let Some(t) = src.get("data:asText").and_then(|v| v.as_str()) {
                data.extend_from_slice(t.as_bytes());
            } else if let Some(b) = src.get("data:asBase64").and_then(|v| v.as_str()) {
                match base64::engine::general_purpose::STANDARD.decode(b.trim()) {
                    Ok(d) => data.extend_from_slice(&d),
                    Err(_) => {
                        not_created.insert(cid.clone(), set_error("invalidProperties", "data:asBase64 isn't base64"));
                        continue 'each;
                    }
                }
            } else if let Some(id) = src.get("blobId").and_then(|v| v.as_str()) {
                let id = ctx.id(id);
                let Some(bytes) = blob_bytes(&ctx.state, &ctx.account, &id).await? else {
                    not_created.insert(cid.clone(), set_error("blobNotFound", format!("No blob {id}")));
                    continue 'each;
                };
                let off = src.get("offset").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
                let len = src.get("length").and_then(|v| v.as_u64()).map(|l| l as usize);
                let end = len.map(|l| off.saturating_add(l)).unwrap_or(bytes.len());
                if off > bytes.len() || end > bytes.len() {
                    not_created.insert(cid.clone(), set_error("invalidProperties", "offset or length is past the end of the blob"));
                    continue 'each;
                }
                data.extend_from_slice(&bytes[off..end]);
            } else {
                not_created.insert(cid.clone(), set_error("invalidProperties", "Unknown data source"));
                continue 'each;
            }
            if data.len() > max {
                not_created.insert(cid.clone(), set_error("tooLarge", format!("Blobs may be at most {max} bytes")));
                continue 'each;
            }
        }
        let ctype = obj.get("type").and_then(|v| v.as_str()).unwrap_or("application/octet-stream").chars().take(200).collect::<String>();
        let key = ctx.state.blobs.put_message(&data).await?;
        let id = format!("u{}", ctx.state.db.add_upload(ctx.account.id, &key, data.len() as i64, &ctype).await?);
        ctx.created.insert(cid.clone(), id.clone());
        created.insert(cid.clone(), json!({"id": id, "type": ctype, "size": data.len()}));
    }
    Ok(json!({"accountId": account_id(&ctx.account), "created": created, "notCreated": not_created}))
}

pub async fn blob_get(ctx: &mut Ctx, args: &Value) -> Result<Value, MethodError> {
    let ids: Vec<String> = match args.get("ids").and_then(|v| v.as_array()) {
        Some(a) if a.len() <= super::MAX_OBJECTS => a.iter().filter_map(|x| x.as_str().map(|s| ctx.id(s))).collect(),
        Some(_) => return Err(MethodError("requestTooLarge", "Too many ids.".into())),
        None => return Err(MethodError::invalid("ids is required")),
    };
    let props: Vec<String> = match args.get("properties").and_then(|v| v.as_array()) {
        Some(p) => p.iter().filter_map(|x| x.as_str().map(String::from)).collect(),
        None => vec!["data".into(), "size".into()],
    };
    for p in &props {
        if !matches!(p.as_str(), "data" | "data:asText" | "data:asBase64" | "size" | "digest:sha" | "digest:sha-256") {
            return Err(MethodError::invalid(format!("Unknown property {p}")));
        }
    }
    let offset = args.get("offset").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
    let length = args.get("length").and_then(|v| v.as_u64()).map(|l| l as usize);
    let (mut list, mut not_found) = (vec![], vec![]);
    for id in ids {
        let Some(bytes) = blob_bytes(&ctx.state, &ctx.account, &id).await? else {
            not_found.push(id);
            continue;
        };
        let start = offset.min(bytes.len());
        let end = length.map(|l| start.saturating_add(l)).unwrap_or(bytes.len()).min(bytes.len());
        let slice = &bytes[start..end];
        let truncated = offset > bytes.len() || length.is_some_and(|l| offset.saturating_add(l) > bytes.len());
        let mut o = Map::new();
        o.insert("id".into(), json!(id));
        let text = std::str::from_utf8(slice).ok();
        for p in &props {
            match p.as_str() {
                "size" => {
                    o.insert("size".into(), json!(bytes.len()));
                }
                "data:asText" | "data" if text.is_some() || p == "data:asText" => {
                    o.insert("data:asText".into(), text.map(|t| json!(t)).unwrap_or(Value::Null));
                    o.insert("isEncodingProblem".into(), json!(text.is_none()));
                    o.insert("isTruncated".into(), json!(truncated));
                }
                "data:asBase64" | "data" => {
                    o.insert("data:asBase64".into(), json!(base64::engine::general_purpose::STANDARD.encode(slice)));
                    o.insert("isTruncated".into(), json!(truncated));
                }
                "digest:sha" => {
                    let d = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, slice);
                    o.insert("digest:sha".into(), json!(base64::engine::general_purpose::STANDARD.encode(d.as_ref())));
                }
                "digest:sha-256" => {
                    let d = ring::digest::digest(&ring::digest::SHA256, slice);
                    o.insert("digest:sha-256".into(), json!(base64::engine::general_purpose::STANDARD.encode(d.as_ref())));
                }
                _ => {}
            }
        }
        list.push(Value::Object(o));
    }
    Ok(json!({"accountId": account_id(&ctx.account), "list": list, "notFound": not_found}))
}

const PARSE_DEFAULT: &[&str] = &[
    "messageId", "inReplyTo", "references", "sender", "from", "to", "cc", "bcc", "replyTo", "subject", "sentAt",
    "hasAttachment", "preview", "bodyValues", "textBody", "htmlBody", "attachments",
];

/// Email/parse: Email objects for message blobs (an upload, or a message
/// attached to another), without storing them.
pub async fn email_parse(ctx: &mut Ctx, args: &Value) -> Result<Value, MethodError> {
    let ids: Vec<String> = match args.get("blobIds").and_then(|v| v.as_array()) {
        Some(a) if a.len() <= super::MAX_OBJECTS => a.iter().filter_map(|x| x.as_str().map(|s| ctx.id(s))).collect(),
        Some(_) => return Err(MethodError("requestTooLarge", "Too many blobIds.".into())),
        None => return Err(MethodError::invalid("blobIds is required")),
    };
    let props: Vec<String> = match args.get("properties").and_then(|v| v.as_array()) {
        Some(p) => p.iter().filter_map(|x| x.as_str().map(String::from)).collect(),
        None => PARSE_DEFAULT.iter().map(|s| s.to_string()).collect(),
    };
    let opts = BodyOpts::from_args(args);
    let (mut parsed, mut not_parsable, mut not_found) = (Map::new(), vec![], vec![]);
    for id in ids {
        let Some(raw) = blob_bytes(&ctx.state, &ctx.account, &id).await? else {
            not_found.push(id);
            continue;
        };
        let root = crate::mime::parse(&raw);
        if root.fields.iter().all(|f| f.name.is_empty()) {
            not_parsable.push(id);
            continue;
        }
        let m = crate::mime::meta_of(&raw, &root);
        let mut o = Map::new();
        for null in ["id", "threadId", "mailboxIds", "keywords", "receivedAt"] {
            o.insert(null.into(), Value::Null);
        }
        o.insert("blobId".into(), json!(id));
        o.insert("size".into(), json!(raw.len()));
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
        let src = id.clone();
        body_into(&mut o, &raw, &props, &opts, &|path: &[usize]| {
            format!("P{src}~{}", path.iter().map(|n| n.to_string()).collect::<Vec<_>>().join("-"))
        });
        let o: Map<String, Value> = o.into_iter().filter(|(k, _)| props.iter().any(|p| p == k)).collect();
        parsed.insert(id, Value::Object(o));
    }
    Ok(json!({"accountId": account_id(&ctx.account), "parsed": parsed, "notParsable": not_parsable, "notFound": not_found}))
}

/// The address a read receipt goes to: Disposition-Notification-To.
fn receipt_address(raw: &[u8]) -> Option<String> {
    let root = crate::mime::parse(raw);
    let v = root.header(raw, "disposition-notification-to")?;
    let a = crate::mime::parse_addresses(&v).into_iter().next()?;
    let (m, h) = (a.mailbox?, a.host?);
    crate::util::normalize_address(&format!("{}@{}", String::from_utf8_lossy(&m), String::from_utf8_lossy(&h)))
}

fn header_text(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(500).collect()
}

/// MDN/send: send read receipts (RFC 8098 message/disposition-notification).
pub async fn mdn_send(ctx: &mut Ctx, args: &Value) -> R {
    let ids = super::submission::identities(ctx).await?;
    let identity = args.get("identityId").and_then(|v| v.as_str()).map(|s| ctx.id(s)).unwrap_or_default();
    let Some(ident) = ids.iter().find(|i| i.id == identity) else {
        return Err(MethodError::invalid("identityId not found"));
    };
    let from_name = ident.row.as_ref().map(|r| r.name.clone()).unwrap_or_else(|| ctx.account.display_name.clone());
    let (mut sent, mut not_sent) = (Map::new(), Map::new());
    let mut email_updates = Map::new();
    let Some(send) = args.get("send").and_then(|v| v.as_object()) else {
        return Err(MethodError::invalid("send is required"));
    };
    for (cid, mdn) in send {
        let email_id = mdn.get("forEmailId").and_then(|v| v.as_str()).map(|s| ctx.id(s)).unwrap_or_default();
        let rows = match super::mail::num_id(&email_id, 'e') {
            Some(n) => ctx.state.db.messages_by_ids(ctx.account.id, &[n]).await?,
            None => vec![],
        };
        let Some(row) = rows.into_iter().next() else {
            not_sent.insert(cid.clone(), set_error("notFound", "forEmailId not found"));
            continue;
        };
        if row.flags.split_whitespace().any(|f| f.eq_ignore_ascii_case("$mdnsent")) {
            not_sent.insert(cid.clone(), set_error("mdnAlreadySent", "A receipt was already sent for this message"));
            continue;
        }
        let raw = ctx.state.blobs.get(&row.blob).await?;
        let Some(to) = receipt_address(&raw) else {
            not_sent.insert(cid.clone(), set_error("invalidProperties", "The message doesn't ask for a receipt"));
            continue;
        };
        let d = mdn.get("disposition").cloned().unwrap_or(Value::Null);
        let action = d.get("actionMode").and_then(|v| v.as_str()).unwrap_or("manual-action");
        let sending = d.get("sendingMode").and_then(|v| v.as_str()).unwrap_or("mdn-sent-manually");
        let kind = d.get("type").and_then(|v| v.as_str()).unwrap_or("displayed");
        if !matches!(action, "manual-action" | "automatic-action")
            || !matches!(sending.to_ascii_lowercase().as_str(), "mdn-sent-manually" | "mdn-sent-automatically")
            || !matches!(kind, "deleted" | "dispatched" | "displayed" | "processed")
        {
            not_sent.insert(cid.clone(), set_error("invalidProperties", "Invalid disposition"));
            continue;
        }
        let meta = super::mail::meta_of_row(&row);
        let subject = mdn.get("subject").and_then(|v| v.as_str()).map(header_text).unwrap_or_else(|| format!("Read: {}", header_text(&meta.subject)));
        let text = mdn
            .get("textBody")
            .and_then(|v| v.as_str())
            .map(String::from)
            .unwrap_or_else(|| format!("This is a receipt for the mail you sent to {}.\r\n\r\nIt was {kind}.", ident.email));
        let ua = mdn.get("reportingUA").and_then(|v| v.as_str()).map(header_text).unwrap_or_else(|| "Picacho Server".into());
        let boundary = format!("mdn-{}", crate::util::random_token());
        let msgid = format!("{}@{}", crate::util::random_token(), crate::util::domain_of(&ident.email));
        let mut m = String::new();
        m.push_str(&format!("From: {} <{}>\r\n", super::mail::encode_header_text(&header_text(&from_name)), ident.email));
        m.push_str(&format!("To: <{to}>\r\n"));
        m.push_str(&format!("Subject: {}\r\n", super::mail::encode_header_text(&subject)));
        m.push_str(&format!("Date: {}\r\n", chrono::Utc::now().to_rfc2822()));
        m.push_str(&format!("Message-ID: <{msgid}>\r\n"));
        if let Some(orig) = &meta.msgid {
            m.push_str(&format!("In-Reply-To: <{orig}>\r\nReferences: <{orig}>\r\n"));
        }
        m.push_str("MIME-Version: 1.0\r\n");
        m.push_str(&format!("Content-Type: multipart/report; report-type=disposition-notification; boundary=\"{boundary}\"\r\n\r\n"));
        m.push_str(&format!("--{boundary}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n{}\r\n", String::from_utf8_lossy(&crate::util::normalize_crlf(text.as_bytes()))));
        m.push_str(&format!("--{boundary}\r\nContent-Type: message/disposition-notification\r\n\r\n"));
        m.push_str(&format!("Reporting-UA: {ua}\r\n"));
        m.push_str(&format!("Final-Recipient: rfc822; {}\r\n", ident.email));
        if let Some(orig) = &meta.msgid {
            m.push_str(&format!("Original-Message-ID: <{orig}>\r\n"));
        }
        m.push_str(&format!("Disposition: {action}/{sending}; {kind}\r\n"));
        if let Some(ext) = mdn.get("extensionFields").and_then(|v| v.as_object()) {
            for (k, v) in ext {
                if k.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                    m.push_str(&format!("{k}: {}\r\n", header_text(v.as_str().unwrap_or(""))));
                }
            }
        }
        m.push_str("\r\n");
        if mdn.get("includeOriginalMessage").and_then(|v| v.as_bool()).unwrap_or(false) {
            m.push_str(&format!("--{boundary}\r\nContent-Type: message/rfc822\r\n\r\n"));
            let mut bytes = m.into_bytes();
            bytes.extend_from_slice(&raw);
            bytes.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
            m = String::from_utf8_lossy(&bytes).into_owned();
        } else {
            m.push_str(&format!("--{boundary}--\r\n"));
        }
        if let Err(e) = crate::submit::check_recipients(&ctx.state, &ctx.account, std::slice::from_ref(&to)).await {
            not_sent.insert(cid.clone(), set_error("forbiddenToSend", e));
            continue;
        }
        let o = crate::submit::Outgoing {
            identity: ident.id.clone(),
            email_id: 0,
            thread_id: 0,
            sender: ident.email.clone(),
            rcpts: vec![to],
            message: m.into_bytes(),
            dsn: Default::default(),
            requiretls: false,
            hold_until: None,
        };
        crate::submit::submit(&ctx.state, &ctx.account, o).await?;
        sent.insert(cid.clone(), json!({"finalRecipient": format!("rfc822; {}", ident.email), "originalMessageId": meta.msgid}));
        // The receipt is recorded on the message, plus any update asked for.
        let mut patch = Map::new();
        patch.insert("keywords/$mdnsent".into(), json!(true));
        if let Some(u) = args.get("onSuccessUpdateEmail").and_then(|v| v.as_object()) {
            if let Some(p) = u.get(&format!("#{cid}")).and_then(|v| v.as_object()) {
                patch.extend(p.clone());
            }
        }
        email_updates.insert(email_id.clone(), Value::Object(patch));
    }
    let mut out = vec![("MDN/send".to_string(), json!({"accountId": account_id(&ctx.account), "sent": sent, "notSent": not_sent}))];
    if !email_updates.is_empty() {
        let set_args = json!({"accountId": account_id(&ctx.account), "update": email_updates});
        out.push(("Email/set".to_string(), email_set(ctx, &set_args).await?));
    }
    Ok(out)
}

/// Blob/lookup (RFC 9404 4.3): which Emails (and Threads, Mailboxes) use each blob.
pub async fn blob_lookup(ctx: &mut Ctx, args: &Value) -> Result<Value, MethodError> {
    let types: Vec<String> = args.get("typeNames").and_then(|v| v.as_array()).into_iter().flatten().filter_map(|t| t.as_str().map(String::from)).collect();
    for t in &types {
        if !matches!(t.as_str(), "Email" | "Thread" | "Mailbox") {
            return Err(MethodError("unknownDataType", format!("Can't look up {t}")));
        }
    }
    let ids: Vec<String> = args.get("ids").and_then(|v| v.as_array()).into_iter().flatten().filter_map(|x| x.as_str().map(|s| ctx.id(s))).collect();
    let rows = ctx.state.db.account_messages(ctx.account.id).await?;
    let (mut list, mut nf) = (vec![], vec![]);
    for id in ids {
        // Whole messages (b<key>) and their parts (p<email>_<path>).
        let hits: Vec<&crate::db::MessageRow> = if let Some(key) = id.strip_prefix('b') {
            let key = key.replacen("a_", "a/", 1);
            rows.iter().filter(|r| r.blob == key || r.blob.replace('/', "_") == id[1..]).collect()
        } else if let Some(rest) = id.strip_prefix('p') {
            let eid = rest.split('_').next().and_then(|n| n.parse::<i64>().ok());
            rows.iter().filter(|r| Some(r.id) == eid).collect()
        } else {
            vec![]
        };
        if hits.is_empty() {
            nf.push(id);
            continue;
        }
        let mut matched = Map::new();
        for t in &types {
            let mut v: Vec<String> = hits
                .iter()
                .map(|r| match t.as_str() {
                    "Email" => format!("e{}", r.id),
                    "Thread" => format!("t{}", r.thread_id),
                    _ => format!("m{}", r.mailbox_id),
                })
                .collect();
            v.sort();
            v.dedup();
            matched.insert(t.clone(), json!(v));
        }
        list.push(json!({"id": id, "matchedIds": matched}));
    }
    Ok(json!({"accountId": account_id(&ctx.account), "list": list, "notFound": nf}))
}

/// MDN/parse (RFC 9007 2.2): read receipts kept as blobs.
pub async fn mdn_parse(ctx: &mut Ctx, args: &Value) -> Result<Value, MethodError> {
    let ids: Vec<String> = args.get("blobIds").and_then(|v| v.as_array()).into_iter().flatten().filter_map(|x| x.as_str().map(|s| ctx.id(s))).collect();
    let (mut parsed, mut not_parsable, mut not_found) = (Map::new(), vec![], vec![]);
    for id in ids {
        let Some(raw) = blob_bytes(&ctx.state, &ctx.account, &id).await? else {
            not_found.push(id);
            continue;
        };
        let root = crate::mime::parse(&raw);
        // The message/disposition-notification part, anywhere in the report.
        fn find(p: &crate::mime::Part) -> Option<&crate::mime::Part> {
            if p.ctype.eq_ignore_ascii_case("message") && p.csub.eq_ignore_ascii_case("disposition-notification") {
                return Some(p);
            }
            p.children.iter().find_map(find)
        }
        let Some(part) = find(&root) else {
            not_parsable.push(id);
            continue;
        };
        let text = String::from_utf8_lossy(part.body_bytes(&raw)).replace("\r\n ", " ").replace("\r\n\t", " ");
        let field = |name: &str| text.lines().find_map(|l| l.split_once(':').filter(|(k, _)| k.trim().eq_ignore_ascii_case(name)).map(|(_, v)| v.trim().to_string()));
        let Some(disposition) = field("Disposition") else {
            not_parsable.push(id);
            continue;
        };
        // "manual-action/MDN-sent-manually; displayed"
        let (modes, kind) = disposition.split_once(';').unwrap_or((disposition.as_str(), ""));
        let (action, sending) = modes.split_once('/').unwrap_or((modes, ""));
        let original = field("Original-Message-ID");
        let for_email = match original.as_deref().map(|m| m.trim_matches(['<', '>'])) {
            Some(mid) => ctx.state.db.account_messages(ctx.account.id).await?.into_iter().find(|r| r.msgid == mid).map(|r| format!("e{}", r.id)),
            None => None,
        };
        let subject = crate::mime::meta_of(&raw, &root).subject;
        parsed.insert(
            id,
            json!({"forEmailId": for_email, "subject": subject, "textBody": Value::Null, "reportingUA": field("Reporting-UA"),
                "disposition": {"actionMode": action.trim().to_ascii_lowercase(), "sendingMode": sending.trim().to_ascii_lowercase(), "type": kind.trim().to_ascii_lowercase()},
                "mdnGateway": field("MDN-Gateway"), "originalRecipient": field("Original-Recipient"), "finalRecipient": field("Final-Recipient"),
                "originalMessageId": original, "error": field("Error").map(|e| vec![e]), "extensionFields": Value::Null}),
        );
    }
    Ok(json!({"accountId": account_id(&ctx.account), "parsed": parsed, "notParsable": not_parsable, "notFound": not_found}))
}
