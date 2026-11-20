//! DMARC aggregate reports (RFC 7489 section 7) and SMTP TLS reports
//! (RFC 8460): what we send to other domains once a day, and the reports
//! other providers send us (kept for the console).
use crate::state::State;
use crate::util::now;
use serde_json::{json, Value};
use sqlx::Row;
use std::io::{Read, Write};
use std::net::IpAddr;
use std::time::Duration;

fn today() -> String {
    chrono::Utc::now().format("%Y-%m-%d").to_string()
}

/// Count one DMARC evaluation for tomorrow's aggregate report.
#[allow(clippy::too_many_arguments)]
pub async fn record_dmarc(
    state: &State,
    domain: &str,
    ip: IpAddr,
    header_from: &str,
    disposition: &str,
    dkim: &[mail_auth::DkimOutput<'_>],
    spf: &mail_auth::SpfOutput,
    spf_domain: &str,
) {
    if !state.settings().reports.send_dmarc || domain.is_empty() {
        return;
    }
    let pass = dkim.iter().find(|d| d.result() == &mail_auth::DkimResult::Pass);
    let dkim_res = if pass.is_some() { "pass" } else if dkim.is_empty() { "none" } else { "fail" };
    let dkim_domain = pass.or(dkim.first()).and_then(|d| d.signature()).map(|s| s.d.clone()).unwrap_or_default();
    let spf_res = match spf.result() {
        mail_auth::SpfResult::Pass => "pass",
        mail_auth::SpfResult::Fail => "fail",
        mail_auth::SpfResult::SoftFail => "softfail",
        mail_auth::SpfResult::Neutral => "neutral",
        mail_auth::SpfResult::None => "none",
        mail_auth::SpfResult::TempError => "temperror",
        _ => "permerror",
    };
    let hf = crate::util::domain_of(header_from).to_ascii_lowercase();
    let _g = state.db.wl().await;
    let _ = sqlx::query(
        "INSERT INTO dmarc_records (day, domain, source_ip, header_from, disposition, dkim, spf, dkim_domain, spf_domain, count)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 1)
         ON CONFLICT (day, domain, source_ip, header_from, disposition, dkim, spf, dkim_domain, spf_domain)
         DO UPDATE SET count = dmarc_records.count + 1",
    )
    .bind(today())
    .bind(domain.to_ascii_lowercase())
    .bind(ip.to_string())
    .bind(if hf.is_empty() { domain.to_ascii_lowercase() } else { hf })
    .bind(disposition)
    .bind(dkim_res)
    .bind(spf_res)
    .bind(dkim_domain)
    .bind(spf_domain.to_ascii_lowercase())
    .execute(&state.db.pool)
    .await;
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let _ = e.write_all(data);
    e.finish().unwrap_or_default()
}

fn org(state: &State) -> (String, String) {
    let s = state.settings();
    let org = s.reports.org_name.clone().unwrap_or_else(|| state.hostname());
    let contact = s.reports.contact.clone().unwrap_or_else(|| {
        format!("postmaster@{}", s.server.primary_domain.clone().unwrap_or_else(|| state.hostname()))
    });
    (org, contact)
}

async fn already_sent(state: &State, kind: &str, domain: &str, day: &str) -> bool {
    sqlx::query("SELECT 1 FROM reports_sent WHERE kind = $1 AND domain = $2 AND day = $3")
        .bind(kind)
        .bind(domain)
        .bind(day)
        .fetch_optional(&state.db.pool)
        .await
        .ok()
        .flatten()
        .is_some()
}

async fn mark_sent(state: &State, kind: &str, domain: &str, day: &str) {
    let _g = state.db.wl().await;
    let _ = sqlx::query("INSERT INTO reports_sent (kind, domain, day, sent_at) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING")
        .bind(kind)
        .bind(domain)
        .bind(day)
        .bind(now())
        .execute(&state.db.pool)
        .await;
}

fn day_bounds(day: &str) -> (i64, i64) {
    let d = chrono::NaiveDate::parse_from_str(day, "%Y-%m-%d").unwrap_or_default();
    let start = d.and_hms_opt(0, 0, 0).unwrap_or_default().and_utc().timestamp();
    (start, start + 86399)
}

/// RFC 7489 7.1: a report address outside the policy domain must agree to
/// receive reports with `<domain>._report._dmarc.<dest>`.
async fn external_ok(state: &State, policy_domain: &str, dest: &str) -> bool {
    let dd = crate::util::domain_of(dest).to_ascii_lowercase();
    if dd == policy_domain || dd.ends_with(&format!(".{policy_domain}")) || policy_domain.ends_with(&format!(".{dd}")) {
        return true;
    }
    let Some(r) = &state.resolver else { return false };
    let q = format!("{policy_domain}._report._dmarc.{dd}.");
    match tokio::time::timeout(Duration::from_secs(10), r.resolver().txt_lookup(q)).await {
        Ok(Ok(txt)) => txt.answers().iter().any(|rec| match &rec.data {
            mail_auth::hickory_resolver::proto::rr::RData::TXT(t) => {
                t.txt_data.iter().map(|d| String::from_utf8_lossy(d).to_string()).collect::<String>().starts_with("v=DMARC1")
            }
            _ => false,
        }),
        _ => false,
    }
}

async fn dmarc_rua(state: &State, domain: &str) -> Vec<String> {
    let Some(r) = &state.resolver else { return vec![] };
    match r.txt_lookup::<mail_auth::dmarc::DmarcRecord>(format!("_dmarc.{domain}."), None::<&mail_auth::dns::NoCache>).await {
        Ok(rec) => rec
            .rua()
            .iter()
            .filter_map(|u| {
                let u = u.uri();
                u.strip_prefix("mailto:").map(|s| s.split('!').next().unwrap_or(s).to_string()).or_else(|| (!u.contains(':')).then(|| u.to_string()))
            })
            .collect(),
        Err(_) => vec![],
    }
}

fn report_mail(state: &State, to: &str, subject: &str, report_type: &str, text: &str, ctype: &str, filename: &str, data: &[u8]) -> Vec<u8> {
    use base64::Engine;
    let (_, contact) = org(state);
    let host = state.hostname();
    let boundary = format!("rpt-{}", uuid::Uuid::new_v4().simple());
    let b64 = base64::engine::general_purpose::STANDARD.encode(data);
    let wrapped: Vec<String> = b64.as_bytes().chunks(76).map(|c| String::from_utf8_lossy(c).to_string()).collect();
    let body = format!(
        "From: <{contact}>\r\nTo: <{to}>\r\nSubject: {subject}\r\nDate: {}\r\nMessage-ID: <{}@{host}>\r\nAuto-Submitted: auto-generated\r\nMIME-Version: 1.0\r\nContent-Type: multipart/{}; boundary=\"{boundary}\"\r\n\r\n--{boundary}\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{text}\r\n--{boundary}\r\nContent-Type: {ctype}\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=\"{filename}\"\r\n\r\n{}\r\n--{boundary}--\r\n",
        chrono::Utc::now().to_rfc2822(),
        uuid::Uuid::new_v4().simple(),
        if report_type.is_empty() { "mixed".to_string() } else { format!("report; report-type={report_type}") },
        wrapped.join("\r\n"),
    );
    body.into_bytes()
}

async fn send_mail_report(state: &State, from_domain: &str, to: &str, mail: Vec<u8>) {
    let (_, contact) = org(state);
    let signed = crate::smtp::delivery::dkim_sign(state, crate::util::domain_of(&contact), mail).await;
    let _ = from_domain;
    if let Err(e) = crate::queue::enqueue(state, &contact, &[to.to_string()], &signed, "").await {
        tracing::warn!("report to {to}: {e:#}");
    }
}

async fn send_dmarc_reports(state: &State) {
    let rows = match sqlx::query("SELECT DISTINCT day, domain FROM dmarc_records WHERE day < $1").bind(today()).fetch_all(&state.db.pool).await {
        Ok(r) => r,
        Err(_) => return,
    };
    let (org_name, contact) = org(state);
    for r in rows {
        let day: String = r.get(0);
        let domain: String = r.get(1);
        if already_sent(state, "dmarc", &domain, &day).await {
            continue;
        }
        let rua = dmarc_rua(state, &domain).await;
        let mut dests = vec![];
        for d in rua {
            if external_ok(state, &domain, &d).await {
                dests.push(d);
            }
        }
        if dests.is_empty() {
            mark_sent(state, "dmarc", &domain, &day).await;
            continue;
        }
        let recs = sqlx::query("SELECT source_ip, header_from, disposition, dkim, spf, dkim_domain, spf_domain, count FROM dmarc_records WHERE day = $1 AND domain = $2")
            .bind(&day)
            .bind(&domain)
            .fetch_all(&state.db.pool)
            .await
            .unwrap_or_default();
        let (begin, end) = day_bounds(&day);
        let report_id = format!("{}.{}.{}", day.replace('-', ""), domain, uuid::Uuid::new_v4().simple().to_string().get(..8).unwrap_or(""));
        let mut w = crate::xml::Writer::new();
        w.open("", "feedback");
        w.text_el("", "version", "1.0");
        w.open("", "report_metadata");
        w.text_el("", "org_name", &org_name);
        w.text_el("", "email", &contact);
        w.text_el("", "report_id", &report_id);
        w.open("", "date_range");
        w.text_el("", "begin", &begin.to_string());
        w.text_el("", "end", &end.to_string());
        w.close("", "date_range");
        w.close("", "report_metadata");
        w.open("", "policy_published");
        w.text_el("", "domain", &domain);
        w.close("", "policy_published");
        for rec in &recs {
            let g = |i: usize| rec.get::<String, _>(i);
            let dkim_aligned = if g(3) == "pass" { "pass" } else { "fail" };
            let spf_aligned = if g(4) == "pass" { "pass" } else { "fail" };
            w.open("", "record");
            w.open("", "row");
            w.text_el("", "source_ip", &g(0));
            w.text_el("", "count", &rec.get::<i64, _>(7).to_string());
            w.open("", "policy_evaluated");
            w.text_el("", "disposition", &g(2));
            w.text_el("", "dkim", dkim_aligned);
            w.text_el("", "spf", spf_aligned);
            w.close("", "policy_evaluated");
            w.close("", "row");
            w.open("", "identifiers");
            w.text_el("", "header_from", &g(1));
            w.close("", "identifiers");
            w.open("", "auth_results");
            if !g(5).is_empty() {
                w.open("", "dkim");
                w.text_el("", "domain", &g(5));
                w.text_el("", "result", &g(3));
                w.close("", "dkim");
            }
            w.open("", "spf");
            w.text_el("", "domain", &g(6));
            w.text_el("", "result", &g(4));
            w.close("", "spf");
            w.close("", "auth_results");
            w.close("", "record");
        }
        w.close("", "feedback");
        let xml = w.finish();
        let host = state.hostname();
        let filename = format!("{host}!{domain}!{begin}!{end}.xml.gz");
        let gz = gzip(xml.as_bytes());
        for d in &dests {
            let mail = report_mail(
                state,
                d,
                &format!("Report Domain: {domain} Submitter: {org_name} Report-ID: <{report_id}>"),
                "",
                &format!("DMARC aggregate report for {domain} ({day}) from {org_name}."),
                "application/gzip",
                &filename,
                &gz,
            );
            send_mail_report(state, &domain, d, mail).await;
        }
        state.event("info", "reports", &format!("sent DMARC report for {domain} ({day}) to {}", dests.join(", ")));
        mark_sent(state, "dmarc", &domain, &day).await;
    }
    let _g = state.db.wl().await;
    let cutoff = (chrono::Utc::now() - chrono::Duration::days(7)).format("%Y-%m-%d").to_string();
    let _ = sqlx::query("DELETE FROM dmarc_records WHERE day < $1").bind(&cutoff).execute(&state.db.pool).await;
    let _ = sqlx::query("DELETE FROM reports_sent WHERE day < $1").bind(&cutoff).execute(&state.db.pool).await;
}

async fn tlsrpt_rua(state: &State, domain: &str) -> Vec<mail_auth::mta_sts::ReportUri> {
    let Some(r) = &state.resolver else { return vec![] };
    match r.txt_lookup::<mail_auth::mta_sts::TlsRptRecord>(format!("_smtp._tls.{domain}."), None::<&mail_auth::dns::NoCache>).await {
        Ok(rec) => rec.rua.clone(),
        Err(_) => vec![],
    }
}

async fn send_tls_reports(state: &State) {
    let rows = match sqlx::query("SELECT DISTINCT day, domain FROM tls_results WHERE day < $1").bind(today()).fetch_all(&state.db.pool).await {
        Ok(r) => r,
        Err(_) => return,
    };
    let (org_name, contact) = org(state);
    for r in rows {
        let day: String = r.get(0);
        let domain: String = r.get(1);
        if already_sent(state, "tls", &domain, &day).await {
            continue;
        }
        let rua = tlsrpt_rua(state, &domain).await;
        if rua.is_empty() {
            mark_sent(state, "tls", &domain, &day).await;
            continue;
        }
        let recs = sqlx::query("SELECT policy_type, policy, mx, result, detail, count FROM tls_results WHERE day = $1 AND domain = $2")
            .bind(&day)
            .bind(&domain)
            .fetch_all(&state.db.pool)
            .await
            .unwrap_or_default();
        // One policy entry per policy type.
        let mut policies: std::collections::BTreeMap<String, (String, i64, i64, Vec<Value>, std::collections::BTreeSet<String>)> = Default::default();
        for rec in &recs {
            let ptype: String = rec.get(0);
            let e = policies.entry(ptype.clone()).or_default();
            let policy: String = rec.get(1);
            if !policy.is_empty() {
                e.0 = policy;
            }
            let mx: String = rec.get(2);
            let result: String = rec.get(3);
            let count: i64 = rec.get(5);
            if !mx.is_empty() {
                e.4.insert(mx.clone());
            }
            if result == "success" {
                e.1 += count;
            } else {
                e.2 += count;
                e.3.push(json!({"result-type": result, "receiving-mx-hostname": mx, "failed-session-count": count, "failure-reason-code": rec.get::<String, _>(4)}));
            }
        }
        let (begin, end) = day_bounds(&day);
        let iso = |t: i64| chrono::DateTime::from_timestamp(t, 0).map(|d| d.format("%Y-%m-%dT%H:%M:%SZ").to_string()).unwrap_or_default();
        let report_id = format!("{day}_{domain}_{}", uuid::Uuid::new_v4().simple().to_string().get(..8).unwrap_or(""));
        let report = json!({
            "organization-name": org_name,
            "date-range": {"start-datetime": iso(begin), "end-datetime": iso(end + 1)},
            "contact-info": contact,
            "report-id": report_id,
            "policies": policies.iter().map(|(ptype, (text, ok, bad, details, mxs))| {
                let ptype = if ptype == "sts" || ptype == "tlsa" { ptype.as_str() } else { "no-policy-found" };
                json!({
                    "policy": {
                        "policy-type": ptype,
                        "policy-string": text.lines().map(|l| l.to_string()).collect::<Vec<_>>(),
                        "policy-domain": domain,
                        "mx-host": mxs.iter().collect::<Vec<_>>(),
                    },
                    "summary": {"total-successful-session-count": ok, "total-failure-session-count": bad},
                    "failure-details": details,
                })
            }).collect::<Vec<_>>(),
        });
        let body = serde_json::to_vec_pretty(&report).unwrap_or_default();
        let gz = gzip(&body);
        let filename = format!("{}!{domain}!{begin}!{end}!{report_id}.json.gz", state.hostname());
        for dest in &rua {
            match dest {
                mail_auth::mta_sts::ReportUri::Mail(to) => {
                    let mail = report_mail(
                        state,
                        to,
                        &format!("Report Domain: {domain} Submitter: {org_name} Report-ID: <{report_id}>"),
                        "tlsrpt",
                        &format!("SMTP TLS report for {domain} ({day}) from {org_name}."),
                        "application/tlsrpt+gzip",
                        &filename,
                        &gz,
                    );
                    send_mail_report(state, &domain, to, mail).await;
                }
                mail_auth::mta_sts::ReportUri::Http(url) => {
                    let c = reqwest::Client::builder().timeout(Duration::from_secs(60)).build();
                    if let Ok(c) = c {
                        if let Err(e) = c.post(url).header("Content-Type", "application/tlsrpt+gzip").body(gz.clone()).send().await {
                            tracing::warn!("TLS report to {url}: {e}");
                        }
                    }
                }
            }
        }
        state.event("info", "reports", &format!("sent TLS report for {domain} ({day})"));
        mark_sent(state, "tls", &domain, &day).await;
    }
    let _g = state.db.wl().await;
    let cutoff = (chrono::Utc::now() - chrono::Duration::days(7)).format("%Y-%m-%d").to_string();
    let _ = sqlx::query("DELETE FROM tls_results WHERE day < $1").bind(&cutoff).execute(&state.db.pool).await;
}

/// Send yesterday's reports (called hourly; each day/domain goes out once).
pub async fn run(state: &State) {
    let s = state.settings();
    if s.reports.send_dmarc {
        send_dmarc_reports(state).await;
    }
    if s.reports.send_tls {
        send_tls_reports(state).await;
    }
}

// ------------------------------------------------------------------ ingest

fn decompress(name: &str, ctype: &str, data: &[u8]) -> Option<Vec<u8>> {
    let lname = name.to_ascii_lowercase();
    if data.starts_with(&[0x1f, 0x8b]) || lname.ends_with(".gz") || ctype.contains("gzip") {
        let mut out = Vec::new();
        flate2::read::GzDecoder::new(data).take(64 * 1024 * 1024).read_to_end(&mut out).ok()?;
        return Some(out);
    }
    if data.starts_with(b"PK") || lname.ends_with(".zip") || ctype.contains("zip") {
        let mut z = zip::ZipArchive::new(std::io::Cursor::new(data)).ok()?;
        let mut f = z.by_index(0).ok()?;
        let mut out = Vec::new();
        (&mut f).take(64 * 1024 * 1024).read_to_end(&mut out).ok()?;
        return Some(out);
    }
    Some(data.to_vec())
}

fn summarize_dmarc(doc: &crate::xml::Element) -> Option<(String, String, String, i64, i64, Value)> {
    if doc.name != "feedback" {
        return None;
    }
    let org = doc.find_text("report_metadata/org_name");
    let id = doc.find_text("report_metadata/report_id");
    let domain = doc.find_text("policy_published/domain");
    let begin = doc.find_text("report_metadata/date_range/begin").parse().unwrap_or(0);
    let end = doc.find_text("report_metadata/date_range/end").parse().unwrap_or(0);
    let mut total = 0i64;
    let mut pass = 0i64;
    let mut rows = vec![];
    for rec in doc.elements().filter(|e| e.name == "record") {
        let count: i64 = rec.find_text("row/count").parse().unwrap_or(0);
        let ok = rec.find_text("row/policy_evaluated/dkim") == "pass" || rec.find_text("row/policy_evaluated/spf") == "pass";
        total += count;
        if ok {
            pass += count;
        }
        rows.push(json!({
            "source_ip": rec.find_text("row/source_ip"),
            "count": count,
            "disposition": rec.find_text("row/policy_evaluated/disposition"),
            "dkim": rec.find_text("row/policy_evaluated/dkim"),
            "spf": rec.find_text("row/policy_evaluated/spf"),
            "header_from": rec.find_text("identifiers/header_from"),
        }));
    }
    Some((org, id, domain, begin, end, json!({"messages": total, "passed": pass, "failed": total - pass, "records": rows})))
}

async fn store_report(state: &State, kind: &str, org: &str, id: &str, domain: &str, begin: i64, end: i64, summary: &Value, data: &str) {
    let _g = state.db.wl().await;
    let r = sqlx::query(
        "INSERT INTO reports_in (kind, org, report_id, domain, begin_ts, end_ts, summary, data, received_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
         ON CONFLICT (kind, org, report_id) DO NOTHING",
    )
    .bind(kind)
    .bind(org)
    .bind(id)
    .bind(domain)
    .bind(begin)
    .bind(end)
    .bind(summary.to_string())
    .bind(data.chars().take(4 * 1024 * 1024).collect::<String>())
    .bind(now())
    .execute(&state.db.pool)
    .await;
    if r.is_ok() {
        state.event("info", "reports", &format!("received {kind} report from {org} for {domain}"));
    }
}

/// Keep DMARC/TLS reports that arrive at a configured address.
pub async fn maybe_ingest(state: &State, rcpts: &[String], raw: &[u8]) {
    let s = state.settings();
    if !rcpts.iter().any(|r| s.reports.ingest_addresses.iter().any(|a| a.eq_ignore_ascii_case(r))) {
        return;
    }
    let raw = raw.to_vec();
    let parts: Vec<(String, String, Vec<u8>)> = tokio::task::spawn_blocking(move || {
        let Some(msg) = mail_parser::MessageParser::default().parse(&raw) else { return vec![] };
        let mut out = vec![];
        for p in msg.attachments() {
            let ct = p.content_type().map(|c| format!("{}/{}", c.ctype(), c.subtype().unwrap_or(""))).unwrap_or_default().to_ascii_lowercase();
            out.push((p.attachment_name().unwrap_or("").to_string(), ct, p.decoded().into_owned()));
        }
        if out.is_empty() {
            // Some reporters send the XML as the body itself.
            for p in msg.text_body() {
                out.push((String::new(), "text/xml".into(), p.decoded().into_owned()));
            }
        }
        out
    })
    .await
    .unwrap_or_default();
    for (name, ctype, data) in parts {
        let Some(doc) = decompress(&name, &ctype, &data) else { continue };
        let text = String::from_utf8_lossy(&doc).to_string();
        if text.trim_start().starts_with('{') {
            let Ok(v) = serde_json::from_str::<Value>(&text) else { continue };
            let org = v["organization-name"].as_str().unwrap_or("").to_string();
            let id = v["report-id"].as_str().unwrap_or("").to_string();
            let domain = v["policies"][0]["policy"]["policy-domain"].as_str().unwrap_or("").to_string();
            let parse_t = |s: &str| chrono::DateTime::parse_from_rfc3339(s).map(|d| d.timestamp()).unwrap_or(0);
            let begin = parse_t(v["date-range"]["start-datetime"].as_str().unwrap_or(""));
            let end = parse_t(v["date-range"]["end-datetime"].as_str().unwrap_or(""));
            let (mut ok, mut bad) = (0, 0);
            for p in v["policies"].as_array().into_iter().flatten() {
                ok += p["summary"]["total-successful-session-count"].as_i64().unwrap_or(0);
                bad += p["summary"]["total-failure-session-count"].as_i64().unwrap_or(0);
            }
            store_report(state, "tls", &org, &id, &domain, begin, end, &json!({"successful": ok, "failed": bad}), &text).await;
        } else if let Ok(doc) = crate::xml::parse(text.as_bytes()) {
            if let Some((org, id, domain, begin, end, summary)) = summarize_dmarc(&doc) {
                store_report(state, "dmarc", &org, &id, &domain, begin, end, &summary, &text).await;
            }
        }
    }
}

pub async fn list(state: &State, kind: Option<&str>, limit: i64) -> anyhow::Result<Vec<Value>> {
    let rows = match kind {
        Some(k) => sqlx::query("SELECT id, kind, org, report_id, domain, begin_ts, end_ts, summary, received_at FROM reports_in WHERE kind = $1 ORDER BY id DESC LIMIT $2")
            .bind(k)
            .bind(limit)
            .fetch_all(&state.db.pool)
            .await?,
        None => sqlx::query("SELECT id, kind, org, report_id, domain, begin_ts, end_ts, summary, received_at FROM reports_in ORDER BY id DESC LIMIT $1")
            .bind(limit)
            .fetch_all(&state.db.pool)
            .await?,
    };
    Ok(rows
        .iter()
        .map(|r| {
            json!({
                "id": r.get::<i64, _>(0), "kind": r.get::<String, _>(1), "org": r.get::<String, _>(2),
                "report_id": r.get::<String, _>(3), "domain": r.get::<String, _>(4), "begin": r.get::<i64, _>(5),
                "end": r.get::<i64, _>(6), "summary": serde_json::from_str::<Value>(&r.get::<String, _>(7)).unwrap_or(Value::Null),
                "received_at": r.get::<i64, _>(8),
            })
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dmarc_summary() {
        let xml = br#"<?xml version="1.0"?><feedback><report_metadata><org_name>google.com</org_name><report_id>123</report_id><date_range><begin>1</begin><end>2</end></date_range></report_metadata><policy_published><domain>example.com</domain></policy_published><record><row><source_ip>192.0.2.1</source_ip><count>3</count><policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>fail</spf></policy_evaluated></row><identifiers><header_from>example.com</header_from></identifiers></record><record><row><source_ip>192.0.2.9</source_ip><count>2</count><policy_evaluated><disposition>reject</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated></row></record></feedback>"#;
        let doc = crate::xml::parse(xml).unwrap();
        let (org, id, domain, _, _, s) = summarize_dmarc(&doc).unwrap();
        assert_eq!((org.as_str(), id.as_str(), domain.as_str()), ("google.com", "123", "example.com"));
        assert_eq!(s["messages"], 5);
        assert_eq!(s["failed"], 2);
        let gz = gzip(xml);
        assert_eq!(decompress("r.xml.gz", "", &gz).unwrap(), xml.to_vec());
    }
}
