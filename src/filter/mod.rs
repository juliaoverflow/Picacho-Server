//! Inbound content filtering.
//!
//! Every test adds to a score: authentication results, reverse DNS, DNS
//! block lists, URI block lists, header and body heuristics, custom rules,
//! the Bayesian classifier and (optionally) rspamd. ClamAV and blocked
//! attachment types reject outright; greylisting defers first contact.
//! At `junk_score` the message is filed in Junk; at `reject_score` it is
//! refused during the SMTP transaction.
pub mod bayes;
pub mod external;

use crate::state::State;
use std::collections::BTreeSet;
use std::net::IpAddr;
use std::time::Duration;

/// Authentication results from the SMTP layer.
#[derive(Debug, Clone, Default)]
pub struct AuthSummary {
    pub spf: String,
    pub dkim: String,
    pub dmarc: String,
    pub arc: String,
}

#[derive(Debug, Clone, Default)]
pub struct Context {
    pub ip: Option<IpAddr>,
    pub helo: String,
    pub rdns: Option<String>,
    pub sender: String,
    pub rcpts: Vec<String>,
    /// Local accounts among the recipients (for per-user Bayes).
    pub accounts: Vec<i64>,
    pub authenticated: bool,
    pub auth: Option<AuthSummary>,
    /// The client IP is on this DNSBL (when DNSBLs score instead of reject).
    pub dnsbl: Option<String>,
    /// Arrived through the relay link (IP checks were done upstream).
    pub relayed: bool,
}

impl Context {
    pub fn relayed(sender: &str, rcpts: &[String]) -> Self {
        Self { sender: sender.to_string(), rcpts: rcpts.to_vec(), relayed: true, ..Default::default() }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Verdict {
    pub score: f64,
    pub tests: Vec<(String, f64)>,
    pub junk: bool,
    /// Refuse permanently with this message.
    pub reject: Option<String>,
    /// Refuse temporarily (greylisting, scanner down).
    pub tempfail: Option<String>,
    pub virus: Option<String>,
    pub scanned: bool,
    pub bayes: Option<f64>,
}

impl Verdict {
    fn add(&mut self, name: &str, score: f64) {
        if score != 0.0 {
            self.score += score;
            self.tests.push((name.to_string(), score));
        }
    }
}

fn listed(list: &[String], addr: &str) -> bool {
    let addr = addr.to_ascii_lowercase();
    let dom = crate::util::domain_of(&addr).to_string();
    list.iter().any(|e| {
        let e = e.trim().to_ascii_lowercase();
        !e.is_empty() && (e == addr || e == dom || e.strip_prefix('@') == Some(dom.as_str()) || (e.starts_with("*.") && dom.ends_with(&e[1..])))
    })
}

/// Domains of http(s) links in the message's text and HTML parts.
pub fn link_domains(raw: &[u8]) -> BTreeSet<String> {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| regex::Regex::new(r#"(?i)https?://([a-z0-9][a-z0-9.\-]{0,252}[a-z0-9])"#).unwrap());
    let mut out = BTreeSet::new();
    let Some(msg) = mail_parser::MessageParser::default().parse(raw) else { return out };
    let mut scan = |t: &str| {
        for c in re.captures_iter(t) {
            out.insert(c[1].to_ascii_lowercase());
            if out.len() > 200 {
                return;
            }
        }
    };
    for i in 0..msg.text_body().len() {
        if let Some(t) = msg.body_text(i) {
            scan(&t);
        }
    }
    for i in 0..msg.html_body().len() {
        if let Some(h) = msg.body_html(i) {
            scan(&h);
        }
    }
    out
}

/// Registrable-ish domain: the last two labels (three for common 2nd-level ccTLDs).
fn base_domain(d: &str) -> String {
    let labels: Vec<&str> = d.trim_end_matches('.').split('.').collect();
    if labels.len() <= 2 {
        return d.to_string();
    }
    let sld = labels[labels.len() - 2];
    let n = if labels[labels.len() - 1].len() == 2 && matches!(sld, "co" | "com" | "org" | "net" | "ac" | "gov" | "edu" | "ne" | "or") { 3 } else { 2 };
    labels[labels.len().saturating_sub(n)..].join(".")
}

async fn uribl(state: &State, domains: &BTreeSet<String>, lists: &[String]) -> Vec<(String, String)> {
    let Some(r) = &state.resolver else { return vec![] };
    let mut hits = vec![];
    let bases: BTreeSet<String> = domains.iter().map(|d| base_domain(d)).collect();
    for d in bases.iter().take(20) {
        for zone in lists {
            let q = format!("{d}.{}.", zone.trim_end_matches('.'));
            if let Ok(Ok(a)) = tokio::time::timeout(Duration::from_secs(3), r.resolver().ipv4_lookup(q)).await {
                // 127.255.255.x are error codes from public resolvers, not listings.
                let real = a.answers().iter().any(|rec| match &rec.data {
                    mail_auth::hickory_resolver::proto::rr::RData::A(ip) => ip.0.octets()[0] == 127 && ip.0.octets()[1] != 255,
                    _ => false,
                });
                if real {
                    hits.push((d.clone(), zone.clone()));
                }
            }
        }
    }
    hits
}

fn header_tests(v: &mut Verdict, msg: &mail_parser::Message<'_>, ctx: &Context) {
    if msg.date().is_none() {
        v.add("MISSING_DATE", 1.0);
    } else if let Some(d) = msg.date() {
        let skew = d.to_timestamp() - crate::util::now();
        if skew > 2 * 86400 {
            v.add("DATE_IN_FUTURE", 1.5);
        } else if skew < -30 * 86400 {
            v.add("DATE_IN_PAST", 0.5);
        }
    }
    if msg.message_id().is_none() {
        v.add("MISSING_MID", 1.0);
    }
    if msg.subject().is_none() {
        v.add("MISSING_SUBJECT", 0.5);
    }
    let from_list = msg.from();
    let from = from_list.as_ref().and_then(|f| f.first());
    let from_addr = from.as_ref().and_then(|a| a.address()).unwrap_or("").to_ascii_lowercase();
    if from_addr.is_empty() {
        v.add("MISSING_FROM", 2.0);
    }
    if let Some(name) = from.as_ref().and_then(|a| a.name()) {
        // "PayPal <x@evil.example>" style spoofs: an address in the name that differs.
        if let Some(at) = name.find('@') {
            let around: String = name[..at].chars().rev().take_while(|c| !c.is_whitespace() && *c != '<' && *c != '"').collect::<String>().chars().rev().collect::<String>()
                + &name[at..].chars().take_while(|c| !c.is_whitespace() && *c != '>' && *c != '"').collect::<String>();
            if !around.eq_ignore_ascii_case(&from_addr) && around.contains('.') {
                v.add("FROM_NAME_HAS_OTHER_ADDR", 2.5);
            }
        }
    }
    if let (Some(rt), false) = (msg.reply_to().and_then(|r| r.first()).and_then(|a| a.address()), from_addr.is_empty()) {
        let rd = crate::util::domain_of(&rt.to_ascii_lowercase()).to_string();
        let fd = crate::util::domain_of(&from_addr).to_string();
        if base_domain(&rd) != base_domain(&fd) {
            let freemail = ["gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "aol.com", "proton.me", "protonmail.com", "gmx.com", "mail.ru", "yandex.ru", "icloud.com"];
            v.add("REPLYTO_OTHER_DOMAIN", if freemail.contains(&rd.as_str()) { 1.5 } else { 0.3 });
        }
    }
    if let Some(s) = msg.subject() {
        let letters: Vec<char> = s.chars().filter(|c| c.is_alphabetic()).collect();
        if letters.len() >= 10 && letters.iter().filter(|c| c.is_uppercase()).count() * 10 >= letters.len() * 8 {
            v.add("SUBJ_ALL_CAPS", 1.5);
        }
        if s.matches('!').count() >= 3 || s.contains("$$$") {
            v.add("SUBJ_EXCLAIM", 1.0);
        }
    }
    if (msg.text_body().len() == 0) && !(msg.html_body().len() == 0) {
        v.add("HTML_ONLY", 0.5);
    }
    let to_count: usize = msg.to().map(|l| l.mailboxes().count()).unwrap_or(0);
    if to_count == 0 && !msg.headers().contains("Cc") && !ctx.relayed {
        v.add("NO_TO_HEADER", 0.5);
    }
    if to_count > 50 {
        v.add("MANY_RECIPIENTS", 1.0);
    }
}

fn blocked_attachment(msg: &mail_parser::Message<'_>, exts: &[String]) -> Option<String> {
    for part in msg.attachments() {
        let Some(name) = part.attachment_name() else { continue };
        let lower = name.to_ascii_lowercase();
        let ext = lower.rsplit_once('.').map(|(_, e)| e).unwrap_or("");
        if exts.iter().any(|e| e.trim_start_matches('.').eq_ignore_ascii_case(ext)) {
            return Some(name.to_string());
        }
        // Archives can hide executables; look one level into zip files.
        if ext == "zip" {
            if let Ok(mut z) = zip::ZipArchive::new(std::io::Cursor::new(part.decoded().into_owned())) {
                for i in 0..z.len().min(500) {
                    if let Ok(f) = z.by_index_raw(i) {
                        let n = f.name().to_ascii_lowercase();
                        let e = n.rsplit_once('.').map(|(_, e)| e).unwrap_or("");
                        if exts.iter().any(|x| x.trim_start_matches('.').eq_ignore_ascii_case(e)) {
                            return Some(format!("{name}/{}", f.name()));
                        }
                    }
                }
            }
        }
    }
    None
}

fn link_mismatch(msg: &mail_parser::Message<'_>) -> bool {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| {
        regex::Regex::new(r#"(?is)<a\s[^>]*href\s*=\s*["']?https?://([a-z0-9.\-]+)[^>]*>\s*(?:https?://)?([a-z0-9\-]+\.[a-z0-9.\-]+)"#).unwrap()
    });
    for i in 0..msg.html_body().len() {
        if let Some(h) = msg.body_html(i) {
            for c in re.captures_iter(&h).take(100) {
                let href = c[1].to_ascii_lowercase();
                let shown = c[2].to_ascii_lowercase();
                if shown.contains('.') && base_domain(&href) != base_domain(&shown) && !shown.ends_with(".png") && !shown.ends_with(".jpg") {
                    return true;
                }
            }
        }
    }
    false
}

fn custom_rules(v: &mut Verdict, raw: &[u8], msg: &mail_parser::Message<'_>, rules: &[crate::settings::FilterRule]) {
    for r in rules.iter().filter(|r| r.enabled) {
        let Ok(re) = regex::RegexBuilder::new(&r.pattern).case_insensitive(true).size_limit(1 << 20).build() else { continue };
        let field = r.field.to_ascii_lowercase();
        let hit = match field.as_str() {
            "raw" => re.is_match(&String::from_utf8_lossy(&raw[..raw.len().min(512 * 1024)])),
            "body" => (0..msg.text_body().len()).filter_map(|i| msg.body_text(i)).any(|t| re.is_match(&t))
                || (0..msg.html_body().len()).filter_map(|i| msg.body_html(i)).any(|t| re.is_match(&t)),
            "subject" => msg.subject().is_some_and(|s| re.is_match(s)),
            "from" => msg.from().and_then(|f| f.first()).is_some_and(|a| {
                re.is_match(a.address().unwrap_or("")) || a.name().is_some_and(|n| re.is_match(n))
            }),
            "to" => msg.to().is_some_and(|t| t.mailboxes().any(|a| re.is_match(a.address().unwrap_or("")))),
            h => msg.headers().iter().any(|hd| hd.raw_name().eq_ignore_ascii_case(h) && re.is_match(&String::from_utf8_lossy(hd.raw_value()))),
        };
        if hit {
            let name = if r.name.is_empty() { format!("RULE_{}", r.field.to_ascii_uppercase()) } else { r.name.to_ascii_uppercase().replace(' ', "_") };
            v.add(&name, r.score);
        }
    }
}

/// Greylisting key: client /24 (IPv4) or /64 (IPv6), sender, first recipient.
fn triplet(ip: IpAddr, sender: &str, rcpt: &str) -> String {
    let net = match ip {
        IpAddr::V4(v) => {
            let o = v.octets();
            format!("{}.{}.{}", o[0], o[1], o[2])
        }
        IpAddr::V6(v) => {
            let s = v.segments();
            format!("{:x}:{:x}:{:x}:{:x}", s[0], s[1], s[2], s[3])
        }
    };
    crate::util::sha256_hex(format!("{net}|{}|{}", sender.to_ascii_lowercase(), rcpt.to_ascii_lowercase()).as_bytes())
}

async fn greylist(state: &State, ctx: &Context) -> Option<String> {
    use sqlx::Row;
    let g = state.settings().filter.greylist.clone();
    let ip = ctx.ip?;
    let rcpt = ctx.rcpts.first()?;
    let key = triplet(ip, &ctx.sender, rcpt);
    let now = crate::util::now();
    let row = sqlx::query("SELECT first_seen, passed FROM greylist WHERE triplet = $1").bind(&key).fetch_optional(&state.db.pool).await.ok()?;
    let _g = state.db.wl().await;
    match row {
        Some(r) if r.get::<i64, _>(1) != 0 => {
            let _ = sqlx::query("UPDATE greylist SET last_seen = $1 WHERE triplet = $2").bind(now).bind(&key).execute(&state.db.pool).await;
            None
        }
        Some(r) => {
            let first: i64 = r.get(0);
            if now - first >= g.delay_secs {
                let _ = sqlx::query("UPDATE greylist SET passed = 1, last_seen = $1 WHERE triplet = $2").bind(now).bind(&key).execute(&state.db.pool).await;
                None
            } else {
                Some(format!("4.7.1 Greylisted, please try again in {} seconds", g.delay_secs - (now - first)))
            }
        }
        None => {
            let _ = sqlx::query("INSERT INTO greylist (triplet, first_seen, last_seen, passed) VALUES ($1, $2, $2, 0) ON CONFLICT (triplet) DO NOTHING")
                .bind(&key)
                .bind(now)
                .execute(&state.db.pool)
                .await;
            Some(format!("4.7.1 Greylisted, please try again in {} seconds", g.delay_secs))
        }
    }
}

/// Forget stale greylist entries.
pub async fn prune_greylist(state: &State) {
    let g = state.settings().filter.greylist.clone();
    let now = crate::util::now();
    let _w = state.db.wl().await;
    let _ = sqlx::query("DELETE FROM greylist WHERE (passed = 0 AND first_seen < $1) OR (passed = 1 AND last_seen < $2)")
        .bind(now - g.retry_window_hours * 3600)
        .bind(now - g.pass_days * 86400)
        .execute(&state.db.pool)
        .await;
}

/// Scan a message. Never fails: problems are logged and skipped.
pub async fn scan(state: &State, ctx: &Context, raw: &[u8]) -> Verdict {
    let s = state.settings();
    let f = &s.filter;
    let mut v = Verdict::default();
    if !f.enabled || (ctx.authenticated && !f.scan_outbound) {
        return v;
    }
    v.scanned = true;
    if !ctx.sender.is_empty() && listed(&f.allow_senders, &ctx.sender) {
        v.add("SENDER_ALLOWED", -100.0);
        return v;
    }
    // Viruses and dangerous attachments first: they are rejected regardless of score.
    if let Some(c) = &f.clamav {
        match external::clamav(c, raw).await {
            Ok(Some(name)) => {
                crate::metrics::VIRUS_FOUND.inc();
                v.virus = Some(name.clone());
                v.reject = Some(format!("5.7.1 Message rejected: virus found ({name})"));
                return v;
            }
            Ok(None) => {}
            Err(e) => {
                tracing::warn!("clamav: {e}");
                if c.on_error == "tempfail" {
                    v.tempfail = Some("4.7.0 Virus scanner unavailable, try again later".into());
                    return v;
                }
            }
        }
    }
    let raw_owned = raw.to_vec();
    let exts = f.blocked_extensions.clone();
    let rules = f.rules.clone();
    let ctx2 = ctx.clone();
    let (tests, blocked) = tokio::task::spawn_blocking(move || {
        let mut tv = Verdict::default();
        let Some(msg) = mail_parser::MessageParser::default().parse(&raw_owned) else {
            tv.add("UNPARSEABLE", 2.0);
            return (tv, None);
        };
        header_tests(&mut tv, &msg, &ctx2);
        if link_mismatch(&msg) {
            tv.add("HTML_LINK_MISMATCH", 1.5);
        }
        custom_rules(&mut tv, &raw_owned, &msg, &rules);
        (tv, blocked_attachment(&msg, &exts))
    })
    .await
    .unwrap_or_default();
    if let Some(name) = blocked {
        v.reject = Some(format!("5.7.1 Attachments of this type are not accepted ({name})"));
        return v;
    }
    v.score += tests.score;
    v.tests.extend(tests.tests);
    if !ctx.sender.is_empty() && listed(&f.block_senders, &ctx.sender) {
        v.add("SENDER_BLOCKED", 100.0);
    }
    if let Some(a) = &ctx.auth {
        match a.spf.as_str() {
            "fail" => v.add("SPF_FAIL", 2.0),
            "softfail" => v.add("SPF_SOFTFAIL", 1.0),
            "pass" => v.add("SPF_PASS", -0.1),
            _ => {}
        }
        match a.dkim.as_str() {
            "pass" => v.add("DKIM_VALID", -0.5),
            "fail" => v.add("DKIM_INVALID", 1.0),
            "none" => v.add("DKIM_NONE", 0.3),
            _ => {}
        }
        match a.dmarc.as_str() {
            "fail" => v.add("DMARC_FAIL", 3.0),
            "pass" => v.add("DMARC_PASS", -0.5),
            _ => {}
        }
        if a.arc == "pass" {
            v.add("ARC_VALID", -0.2);
        }
    }
    if !ctx.relayed {
        if ctx.ip.is_some() && ctx.rdns.is_none() && !ctx.authenticated {
            v.add("RDNS_NONE", 1.0);
        }
        if ctx.helo.parse::<IpAddr>().is_ok() || ctx.helo.trim_start_matches('[').trim_end_matches(']').parse::<IpAddr>().is_ok() {
            v.add("HELO_IS_IP", 0.5);
        } else if !ctx.helo.contains('.') && !ctx.helo.is_empty() {
            v.add("HELO_NOT_FQDN", 1.0);
        }
        if let Some(list) = &ctx.dnsbl {
            v.add(&format!("DNSBL_{}", list.split('.').next().unwrap_or("LISTED").to_ascii_uppercase()), f.dnsbl_score);
        }
    }
    if !f.uribl.is_empty() {
        let doms = link_domains(raw);
        for (d, zone) in uribl(state, &doms, &f.uribl).await.into_iter().take(3) {
            v.add(&format!("URIBL_{}", zone.split('.').next().unwrap_or("HIT").to_ascii_uppercase()), 4.0);
            tracing::debug!("uribl hit {d} on {zone}");
        }
    }
    if f.bayes {
        if let Some(p) = bayes::classify(state, &ctx.accounts, raw).await {
            v.bayes = Some(p);
            let w = f.bayes_weight;
            let s = if p >= 0.5 { (p - 0.5) * 2.0 * w } else { -(0.5 - p) * 2.0 * w * 0.5 };
            v.add(&format!("BAYES_{:02}", (p * 100.0).round() as i64), (s * 100.0).round() / 100.0);
        }
    }
    if let Some(r) = &f.rspamd {
        match external::rspamd(r, ctx, raw).await {
            Ok(res) => {
                v.add("RSPAMD", res.score);
                if r.use_action {
                    match res.action.as_str() {
                        "reject" => v.reject = Some("5.7.1 Message rejected as spam".into()),
                        "soft reject" | "greylist" => v.tempfail = Some("4.7.1 Try again later".into()),
                        "add header" | "rewrite subject" => v.junk = true,
                        _ => {}
                    }
                }
            }
            Err(e) => tracing::warn!("rspamd: {e}"),
        }
    }
    v.score = (v.score * 100.0).round() / 100.0;
    if v.score >= f.reject_score && v.reject.is_none() {
        v.reject = Some(format!("5.7.1 Message rejected as spam (score {:.1})", v.score));
    }
    if v.score >= f.junk_score {
        v.junk = true;
    }
    // Greylist only unauthenticated first contacts that aren't clearly legitimate.
    let dmarc_pass = ctx.auth.as_ref().is_some_and(|a| a.dmarc == "pass");
    if f.greylist.enabled && !ctx.authenticated && !ctx.relayed && v.reject.is_none() && v.tempfail.is_none() && !dmarc_pass && v.score >= f.greylist.min_score {
        if let Some(msg) = greylist(state, ctx).await {
            crate::metrics::GREYLISTED.inc();
            v.tempfail = Some(msg);
        }
    }
    if v.junk {
        crate::metrics::SPAM_JUNKED.inc();
    }
    v
}

/// Prepend X-Spam-* headers describing the verdict.
pub fn apply_headers(v: &Verdict, raw: Vec<u8>) -> Vec<u8> {
    if !v.scanned {
        return raw;
    }
    let mut h = String::new();
    h.push_str(&format!("X-Spam-Status: {}, score={:.2}\r\n", if v.junk { "Yes" } else { "No" }, v.score));
    if v.junk {
        h.push_str("X-Spam-Flag: YES\r\n");
    }
    if !v.tests.is_empty() {
        let tests: Vec<String> = v.tests.iter().map(|(n, s)| format!("{n}={s:.1}")).collect();
        let mut line = String::from("X-Spam-Report:");
        let mut len = line.len();
        for t in tests {
            if len + t.len() + 1 > 76 {
                line.push_str("\r\n\t");
                len = 1;
            } else {
                line.push(' ');
                len += 1;
            }
            line.push_str(&t);
            len += t.len();
        }
        h.push_str(&line);
        h.push_str("\r\n");
    }
    let mut out = h.into_bytes();
    out.extend_from_slice(&raw);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn domains() {
        assert_eq!(base_domain("a.b.example.com"), "example.com");
        assert_eq!(base_domain("x.example.co.uk"), "example.co.uk");
        assert!(listed(&["@spam.example".into()], "bob@spam.example"));
        assert!(listed(&["*.spam.example".into()], "bob@mx.spam.example"));
        assert!(!listed(&["spam.example".into()], "bob@ok.example"));
    }
    #[test]
    fn heuristics() {
        let raw = b"From: \"service@paypal.com\" <x@evil.example>\r\nSubject: URGENT ACCOUNT NOTICE!!!\r\n\r\n<a href=\"http://evil.example/login\">www.paypal.com</a>\r\n";
        let msg = mail_parser::MessageParser::default().parse(&raw[..]).unwrap();
        let mut v = Verdict::default();
        header_tests(&mut v, &msg, &Context::default());
        let names: Vec<&str> = v.tests.iter().map(|t| t.0.as_str()).collect();
        assert!(names.contains(&"FROM_NAME_HAS_OTHER_ADDR"), "{names:?}");
        assert!(names.contains(&"SUBJ_ALL_CAPS"));
        assert!(names.contains(&"MISSING_DATE"));
    }
    #[test]
    fn blocked() {
        let raw = b"From: a@b.c\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\nContent-Type: text/plain\r\n\r\nhi\r\n--x\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"invoice.pdf.exe\"\r\n\r\nMZ\r\n--x--\r\n";
        let msg = mail_parser::MessageParser::default().parse(&raw[..]).unwrap();
        assert_eq!(blocked_attachment(&msg, &["exe".into()]).as_deref(), Some("invoice.pdf.exe"));
    }
}
