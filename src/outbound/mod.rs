//! Direct-to-MX delivery with authenticated TLS.
//!
//! For every MX host the strongest available policy applies:
//! 1. DANE (RFC 7672) when the domain's MX records and the host's TLSA
//!    records are DNSSEC-signed: STARTTLS is required and the certificate
//!    must match a TLSA record.
//! 2. MTA-STS (RFC 8461) in `enforce` mode: the host must be listed in the
//!    policy and present a publicly trusted certificate for its name.
//! 3. `require_tls` (settings) or REQUIRETLS (RFC 8689) on the message.
//! 4. Otherwise opportunistic STARTTLS, falling back to plaintext.
//!
//! Every session under a policy is counted for SMTP TLS reports (RFC 8460).
//! The client speaks PIPELINING, CHUNKING (BDAT), 8BITMIME, SMTPUTF8, DSN
//! (RFC 3461) and REQUIRETLS.
pub mod dane;
pub mod mtasts;
pub mod tlsrpt;

use crate::state::State;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf};
use tokio::net::TcpStream;

/// DSN parameters for one recipient (RFC 3461).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct RcptDsn {
    /// "NEVER" or a comma list of SUCCESS, FAILURE, DELAY. Empty: default.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub notify: String,
    /// Original recipient, "rfc822;addr".
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub orcpt: String,
}

impl RcptDsn {
    pub fn wants(&self, what: &str) -> bool {
        if self.notify.is_empty() {
            // Default: failures (and delays at our discretion).
            return what == "FAILURE" || what == "DELAY";
        }
        self.notify.split(',').any(|n| n.trim().eq_ignore_ascii_case(what))
    }
}

/// Envelope-level DSN parameters, stored with queued messages.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Dsn {
    /// "FULL" or "HDRS".
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ret: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub envid: String,
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub rcpts: std::collections::BTreeMap<String, RcptDsn>,
    /// DELIVERBY (RFC 2852): deliver by this time (unix seconds)...
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by: Option<i64>,
    /// ...or return it ("R") / just report it late ("N").
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub by_mode: String,
    /// MT-PRIORITY (RFC 6710), -9 to 9.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<i8>,
}

impl Dsn {
    pub fn rcpt(&self, addr: &str) -> RcptDsn {
        self.rcpts.get(addr).cloned().unwrap_or_default()
    }
    pub fn is_empty(&self) -> bool {
        self.ret.is_empty() && self.envid.is_empty() && self.rcpts.is_empty() && self.by.is_none() && self.priority.is_none()
    }
    pub fn to_json(&self) -> String {
        if self.is_empty() {
            String::new()
        } else {
            serde_json::to_string(self).unwrap_or_default()
        }
    }
    pub fn from_json(s: &str) -> Self {
        if s.is_empty() {
            Self::default()
        } else {
            serde_json::from_str(s).unwrap_or_default()
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum RcptOutcome {
    /// Accepted. `relayed`: the next hop doesn't do DSN, so a SUCCESS
    /// notification must say "relayed" instead of "delivered".
    Sent { relayed: bool },
    Temporary(String),
    Permanent(String),
}

pub struct Message<'a> {
    pub sender: &'a str,
    pub rcpts: &'a [String],
    pub raw: &'a [u8],
    pub dsn: &'a Dsn,
    pub requiretls: bool,
}

// ------------------------------------------------------------------ TLS policy

#[derive(Clone)]
enum HostTls {
    Dane { records: Vec<dane::Tlsa>, names: Vec<String> },
    /// Publicly trusted certificate required (MTA-STS enforce, require_tls, REQUIRETLS).
    Pkix,
    /// STARTTLS when offered; any certificate.
    Opportunistic,
}

/// What the domain-level lookups found.
struct DomainPolicy {
    sts: Option<mtasts::Policy>,
    sts_error: Option<String>,
    mx_secure: bool,
}

fn webpki_roots() -> Arc<rustls::RootCertStore> {
    static R: std::sync::OnceLock<Arc<rustls::RootCertStore>> = std::sync::OnceLock::new();
    R.get_or_init(|| {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Arc::new(roots)
    })
    .clone()
}

fn client_config(tls: &HostTls) -> Arc<rustls::ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let b = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("tls versions");
    let cfg = match tls {
        HostTls::Pkix => b.with_root_certificates(webpki_roots()).with_no_client_auth(),
        HostTls::Dane { records, names } => b
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(dane::DaneVerifier::new(records.clone(), names.clone())))
            .with_no_client_auth(),
        HostTls::Opportunistic => {
            b.dangerous().with_custom_certificate_verifier(Arc::new(dane::AnyCert::default())).with_no_client_auth()
        }
    };
    Arc::new(cfg)
}

/// RFC 8460 result type for a failed TLS handshake.
fn tls_failure_type(e: &std::io::Error) -> &'static str {
    let Some(inner) = e.get_ref().and_then(|i| i.downcast_ref::<rustls::Error>()) else { return "validation-failure" };
    use rustls::CertificateError as C;
    match inner {
        rustls::Error::InvalidCertificate(C::Expired | C::ExpiredContext { .. } | C::NotValidYet | C::NotValidYetContext { .. }) => {
            "certificate-expired"
        }
        rustls::Error::InvalidCertificate(C::NotValidForName | C::NotValidForNameContext { .. }) => "certificate-host-mismatch",
        rustls::Error::InvalidCertificate(_) => "certificate-not-trusted",
        rustls::Error::General(m) if m.starts_with("DANE") => "validation-failure",
        _ => "validation-failure",
    }
}

// ------------------------------------------------------------------ stream

enum CStream {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
    Gone,
}

impl AsyncRead for CStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            CStream::Plain(s) => Pin::new(s).poll_read(cx, buf),
            CStream::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
            CStream::Gone => Poll::Ready(Ok(())),
        }
    }
}

impl AsyncWrite for CStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            CStream::Plain(s) => Pin::new(s).poll_write(cx, buf),
            CStream::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
            CStream::Gone => Poll::Ready(Err(std::io::ErrorKind::NotConnected.into())),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            CStream::Plain(s) => Pin::new(s).poll_flush(cx),
            CStream::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
            CStream::Gone => Poll::Ready(Ok(())),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            CStream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            CStream::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
            CStream::Gone => Poll::Ready(Ok(())),
        }
    }
}

// ------------------------------------------------------------------ client

#[derive(Debug)]
pub struct Reply {
    pub code: u16,
    pub text: String,
}

impl Reply {
    fn ok(&self) -> bool {
        (200..400).contains(&self.code)
    }
    fn permanent(&self) -> bool {
        self.code >= 500
    }
    fn describe(&self) -> String {
        format!("{} {}", self.code, self.text.replace('\n', " "))
    }
}

pub struct Client {
    r: BufReader<CStream>,
    ext: HashSet<String>,
    size_limit: Option<u64>,
    pub tls: bool,
}

const CMD_TIMEOUT: Duration = Duration::from_secs(300);

impl Client {
    pub async fn connect(host: &str, port: u16) -> std::io::Result<Self> {
        let addrs: Vec<std::net::SocketAddr> =
            tokio::time::timeout(Duration::from_secs(30), tokio::net::lookup_host((host, port))).await.map_err(to_io)??.collect();
        let mut last = std::io::Error::new(std::io::ErrorKind::NotFound, format!("{host} has no address"));
        for a in addrs.iter().take(4) {
            match tokio::time::timeout(Duration::from_secs(30), TcpStream::connect(a)).await {
                Ok(Ok(s)) => {
                    let _ = s.set_nodelay(true);
                    return Ok(Self { r: BufReader::new(CStream::Plain(s)), ext: HashSet::new(), size_limit: None, tls: false });
                }
                Ok(Err(e)) => last = e,
                Err(_) => last = std::io::Error::new(std::io::ErrorKind::TimedOut, format!("connect to {a} timed out")),
            }
        }
        Err(last)
    }

    pub async fn read_reply(&mut self) -> std::io::Result<Reply> {
        let mut text = String::new();
        loop {
            let mut line = String::new();
            let n = tokio::time::timeout(CMD_TIMEOUT, self.r.read_line(&mut line)).await.map_err(to_io)??;
            if n == 0 {
                return Err(std::io::ErrorKind::UnexpectedEof.into());
            }
            if line.len() < 3 || line.len() > 4096 {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "malformed SMTP reply"));
            }
            let code: u16 = line[..3].parse().map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "malformed SMTP reply"))?;
            let more = line.as_bytes().get(3) == Some(&b'-');
            if !text.is_empty() {
                text.push('\n');
            }
            text.push_str(line.get(4..).unwrap_or("").trim_end());
            if !more {
                return Ok(Reply { code, text });
            }
        }
    }

    async fn send(&mut self, data: &[u8]) -> std::io::Result<()> {
        let w = self.r.get_mut();
        tokio::time::timeout(CMD_TIMEOUT, async {
            w.write_all(data).await?;
            w.flush().await
        })
        .await
        .map_err(to_io)?
    }

    pub async fn cmd(&mut self, line: &str) -> std::io::Result<Reply> {
        self.send(format!("{line}\r\n").as_bytes()).await?;
        self.read_reply().await
    }

    pub async fn ehlo(&mut self, hello: &str) -> std::io::Result<Reply> {
        let r = self.cmd(&format!("EHLO {hello}")).await?;
        if r.ok() {
            self.ext.clear();
            for l in r.text.lines().skip(1) {
                let mut it = l.split_whitespace();
                let Some(k) = it.next() else { continue };
                let k = k.to_ascii_uppercase();
                if k == "SIZE" {
                    self.size_limit = it.next().and_then(|v| v.parse().ok()).filter(|v| *v > 0);
                }
                self.ext.insert(k);
            }
            return Ok(r);
        }
        let r2 = self.cmd(&format!("HELO {hello}")).await?;
        self.ext.clear();
        Ok(r2)
    }

    pub fn has(&self, ext: &str) -> bool {
        self.ext.contains(ext)
    }

    pub async fn starttls(&mut self, host: &str, cfg: Arc<rustls::ClientConfig>) -> std::io::Result<()> {
        let r = self.cmd("STARTTLS").await?;
        if r.code != 220 {
            return Err(std::io::Error::other(format!("STARTTLS refused: {}", r.describe())));
        }
        if !self.r.buffer().is_empty() {
            return Err(std::io::Error::other("server sent data before the TLS handshake"));
        }
        let plain = match std::mem::replace(self.r.get_mut(), CStream::Gone) {
            CStream::Plain(s) => s,
            _ => return Err(std::io::Error::other("already using TLS")),
        };
        let name = rustls::pki_types::ServerName::try_from(host.trim_end_matches('.').to_string())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        let tls = tokio::time::timeout(Duration::from_secs(60), tokio_rustls::TlsConnector::from(cfg).connect(name, plain))
            .await
            .map_err(to_io)??;
        self.r = BufReader::new(CStream::Tls(Box::new(tls)));
        self.tls = true;
        Ok(())
    }

    pub async fn quit(mut self) {
        let _ = tokio::time::timeout(Duration::from_secs(5), self.cmd("QUIT")).await;
    }

    /// MAIL, RCPT (pipelined when possible) and the message.
    async fn transaction(&mut self, m: &Message<'_>) -> std::io::Result<Vec<(String, RcptOutcome)>> {
        let dsn_ok = self.has("DSN");
        let eight = m.raw.iter().any(|b| *b >= 0x80);
        let utf8_addr = !m.sender.is_ascii() || m.rcpts.iter().any(|r| !r.is_ascii());
        if utf8_addr && !self.has("SMTPUTF8") {
            return Ok(all(m.rcpts, RcptOutcome::Permanent("5.6.7 the receiving server does not support SMTPUTF8 addresses".into())));
        }
        if m.requiretls && !self.has("REQUIRETLS") {
            return Ok(all(m.rcpts, RcptOutcome::Permanent("5.7.30 REQUIRETLS: the receiving server does not support REQUIRETLS".into())));
        }
        if let Some(limit) = self.size_limit {
            if m.raw.len() as u64 > limit {
                return Ok(all(m.rcpts, RcptOutcome::Permanent(format!("5.3.4 message is larger than the receiving server's limit ({limit} bytes)"))));
            }
        }
        let mut mail = format!("MAIL FROM:<{}>", m.sender);
        if self.has("SIZE") {
            mail.push_str(&format!(" SIZE={}", m.raw.len()));
        }
        if eight && self.has("8BITMIME") {
            mail.push_str(" BODY=8BITMIME");
        }
        if utf8_addr {
            mail.push_str(" SMTPUTF8");
        }
        if m.requiretls {
            mail.push_str(" REQUIRETLS");
        }
        // DELIVERBY: the time left, where the next server takes it.
        if let (Some(by), true) = (m.dsn.by, self.has("DELIVERBY")) {
            let left = (by - crate::util::now()).max(1);
            mail.push_str(&format!(" BY={left};{}", if m.dsn.by_mode.is_empty() { "R" } else { &m.dsn.by_mode }));
        }
        if let (Some(p), true) = (m.dsn.priority, self.has("MT-PRIORITY")) {
            mail.push_str(&format!(" MT-PRIORITY={p}"));
        }
        if dsn_ok {
            if !m.dsn.ret.is_empty() {
                mail.push_str(&format!(" RET={}", m.dsn.ret));
            }
            if !m.dsn.envid.is_empty() {
                mail.push_str(&format!(" ENVID={}", xtext(&m.dsn.envid)));
            }
        }
        let rcpt_lines: Vec<String> = m
            .rcpts
            .iter()
            .map(|r| {
                let mut l = format!("RCPT TO:<{r}>");
                if dsn_ok {
                    let d = m.dsn.rcpt(r);
                    if !d.notify.is_empty() {
                        l.push_str(&format!(" NOTIFY={}", d.notify));
                    }
                    if !d.orcpt.is_empty() {
                        let (t, a) = d.orcpt.split_once(';').unwrap_or(("rfc822", &d.orcpt));
                        l.push_str(&format!(" ORCPT={t};{}", xtext(a)));
                    }
                }
                l
            })
            .collect();
        let (mail_reply, rcpt_replies) = if self.has("PIPELINING") {
            let mut batch = format!("{mail}\r\n");
            for l in &rcpt_lines {
                batch.push_str(l);
                batch.push_str("\r\n");
            }
            self.send(batch.as_bytes()).await?;
            let mr = self.read_reply().await?;
            let mut rr = vec![];
            for _ in &rcpt_lines {
                rr.push(self.read_reply().await?);
            }
            (mr, rr)
        } else {
            let mr = self.cmd(&mail).await?;
            let mut rr = vec![];
            if mr.ok() {
                for l in &rcpt_lines {
                    rr.push(self.cmd(l).await?);
                }
            }
            (mr, rr)
        };
        if !mail_reply.ok() {
            let o = if mail_reply.permanent() {
                RcptOutcome::Permanent(mail_reply.describe())
            } else {
                RcptOutcome::Temporary(mail_reply.describe())
            };
            let _ = self.cmd("RSET").await;
            return Ok(all(m.rcpts, o));
        }
        let mut out = vec![];
        let mut accepted = vec![];
        for (r, reply) in m.rcpts.iter().zip(rcpt_replies.iter()) {
            if reply.ok() {
                accepted.push(r.clone());
            } else if reply.permanent() {
                out.push((r.clone(), RcptOutcome::Permanent(reply.describe())));
            } else {
                out.push((r.clone(), RcptOutcome::Temporary(reply.describe())));
            }
        }
        if accepted.is_empty() {
            let _ = self.cmd("RSET").await;
            return Ok(out);
        }
        let final_reply = if self.has("CHUNKING") {
            self.send(format!("BDAT {} LAST\r\n", m.raw.len()).as_bytes()).await?;
            self.send(m.raw).await?;
            tokio::time::timeout(Duration::from_secs(600), self.read_reply()).await.map_err(to_io)??
        } else {
            let r = self.cmd("DATA").await?;
            if r.code != 354 {
                let o = if r.permanent() { RcptOutcome::Permanent(r.describe()) } else { RcptOutcome::Temporary(r.describe()) };
                for a in accepted {
                    out.push((a, o.clone()));
                }
                return Ok(out);
            }
            self.send(&dot_stuff(m.raw)).await?;
            tokio::time::timeout(Duration::from_secs(600), self.read_reply()).await.map_err(to_io)??
        };
        let o = if final_reply.ok() {
            RcptOutcome::Sent { relayed: !dsn_ok }
        } else if final_reply.permanent() {
            RcptOutcome::Permanent(final_reply.describe())
        } else {
            RcptOutcome::Temporary(final_reply.describe())
        };
        for a in accepted {
            out.push((a, o.clone()));
        }
        Ok(out)
    }
}

fn all(rcpts: &[String], o: RcptOutcome) -> Vec<(String, RcptOutcome)> {
    rcpts.iter().map(|r| (r.clone(), o.clone())).collect()
}

fn to_io(_: tokio::time::error::Elapsed) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::TimedOut, "timed out")
}

/// RFC 3461 xtext encoding.
pub fn xtext(s: &str) -> String {
    s.bytes()
        .map(|b| if (33..=126).contains(&b) && b != b'+' && b != b'=' { (b as char).to_string() } else { format!("+{b:02X}") })
        .collect()
}

pub fn xtext_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'+' && i + 2 < b.len() {
            if let Some(v) = std::str::from_utf8(&b[i + 1..i + 3]).ok().and_then(|h| u8::from_str_radix(h, 16).ok()) {
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

/// CRLF-terminate, dot-stuff and append the terminating dot.
fn dot_stuff(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len() + raw.len() / 50 + 5);
    let mut bol = true;
    for &b in raw {
        if bol && b == b'.' {
            out.push(b'.');
        }
        out.push(b);
        bol = b == b'\n';
    }
    if !out.ends_with(b"\r\n") {
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b".\r\n");
    out
}

// ------------------------------------------------------------------ delivery

enum Attempt {
    Done(Vec<(String, RcptOutcome)>),
    /// Try the next MX. `permanent` marks errors that would be final on every host.
    Failed { msg: String },
}

async fn domain_policy(state: &State, domain: &str) -> DomainPolicy {
    let s = state.settings();
    let (sts, sts_error) = if s.delivery.mta_sts {
        match mtasts::lookup(state, domain).await {
            mtasts::Lookup::Found(p) if p.mode != mtasts::Mode::None => (Some(p), None),
            mtasts::Lookup::Found(_) | mtasts::Lookup::NoPolicy => (None, None),
            mtasts::Lookup::FetchError(e) => (None, Some(e)),
        }
    } else {
        (None, None)
    };
    let mx_secure = s.delivery.dane && dane::mx_secure(domain).await;
    DomainPolicy { sts, sts_error, mx_secure }
}

/// Deliver to one recipient domain by MX. Returns an outcome per recipient.
pub async fn deliver_direct(state: &State, domain: &str, m: &Message<'_>) -> Vec<(String, RcptOutcome)> {
    let hosts = match crate::queue::mx_hosts(state, domain).await {
        Ok(h) if !h.is_empty() => h,
        Ok(_) => return all(m.rcpts, RcptOutcome::Permanent(format!("5.1.10 domain {domain} does not accept mail (null MX)"))),
        Err(e) => return all(m.rcpts, RcptOutcome::Temporary(e)),
    };
    let settings = state.settings();
    let pol = domain_policy(state, domain).await;
    if let Some(e) = &pol.sts_error {
        tlsrpt::record(state, domain, "sts", "", "", "sts-policy-fetch-error", e).await;
    }
    let hello = state.hostname();
    let mut last = format!("no usable MX host for {domain}");
    let mut any_tried = false;
    for host in hosts.iter().take(5) {
        // Decide how TLS must look on this host.
        let mut tls = HostTls::Opportunistic;
        let mut report: Option<(&str, String)> = None; // (policy type, policy text)
        if pol.mx_secure {
            match dane::tlsa(host).await {
                dane::DnsSecure::Secure(records) if !records.is_empty() => {
                    let names = vec![host.trim_end_matches('.').to_string(), domain.to_string()];
                    tls = HostTls::Dane { records: records.clone(), names };
                    let text = records.iter().map(|t| format!("{} {} {} {}", t.usage, t.selector, t.matching, hex::encode(&t.data))).collect::<Vec<_>>().join("\n");
                    report = Some(("tlsa", text));
                }
                dane::DnsSecure::Error(e) => {
                    // RFC 7672 2.2: a failed TLSA lookup makes the host unusable.
                    last = format!("{host}: {e}");
                    tlsrpt::record(state, domain, "tlsa", "", host, "dnssec-invalid", &e).await;
                    continue;
                }
                _ => {}
            }
        }
        if matches!(tls, HostTls::Opportunistic) {
            if let Some(p) = &pol.sts {
                let enforce = p.mode == mtasts::Mode::Enforce || m.requiretls;
                if !p.allows(host) {
                    tlsrpt::record(state, domain, "sts", &p.text, host, "validation-failure", "MX host not listed in the MTA-STS policy").await;
                    if enforce {
                        last = format!("{host} is not allowed by {domain}'s MTA-STS policy");
                        continue;
                    }
                } else if enforce {
                    tls = HostTls::Pkix;
                }
                report = Some(("sts", p.text.clone()));
            }
        }
        if matches!(tls, HostTls::Opportunistic) && m.requiretls {
            return all(
                m.rcpts,
                RcptOutcome::Permanent(format!("5.7.10 REQUIRETLS: {domain} publishes neither MTA-STS nor DANE, so TLS can't be authenticated")),
            );
        }
        if matches!(tls, HostTls::Opportunistic) && settings.delivery.require_tls {
            tls = HostTls::Pkix;
        }
        any_tried = true;
        let testing = matches!(&pol.sts, Some(p) if p.mode == mtasts::Mode::Testing) && !m.requiretls && matches!(tls, HostTls::Opportunistic);
        match attempt(state, host, &tls, m, &hello, report.as_ref(), domain, testing).await {
            Attempt::Done(res) => return res,
            Attempt::Failed { msg } => last = format!("{host}: {msg}"),
        }
    }
    if !any_tried {
        // Only policy failures: keep retrying, the policy may be fixed.
        return all(m.rcpts, RcptOutcome::Temporary(last));
    }
    all(m.rcpts, RcptOutcome::Temporary(last))
}

#[allow(clippy::too_many_arguments)]
async fn attempt(
    state: &State,
    host: &str,
    tls: &HostTls,
    m: &Message<'_>,
    hello: &str,
    report: Option<&(&str, String)>,
    domain: &str,
    sts_testing: bool,
) -> Attempt {
    let required = !matches!(tls, HostTls::Opportunistic);
    let rec = |result: &'static str, detail: String| async move {
        if let Some((kind, text)) = report {
            tlsrpt::record(state, domain, kind, text, host, result, &detail).await;
        }
    };
    let mut c = match Client::connect(host, 25).await {
        Ok(c) => c,
        Err(e) => return Attempt::Failed { msg: format!("connect: {e}") },
    };
    let greet = match c.read_reply().await {
        Ok(r) => r,
        Err(e) => return Attempt::Failed { msg: format!("greeting: {e}") },
    };
    if greet.code != 220 {
        c.quit().await;
        return Attempt::Failed { msg: format!("greeting: {}", greet.describe()) };
    }
    if let Err(e) = c.ehlo(hello).await {
        return Attempt::Failed { msg: format!("EHLO: {e}") };
    }
    if c.has("STARTTLS") {
        if let Err(e) = c.starttls(host, client_config(tls)).await {
            let kind = tls_failure_type(&e);
            rec(kind, e.to_string()).await;
            if required {
                return Attempt::Failed { msg: format!("TLS: {e}") };
            }
            // Opportunistic: retry this host in plaintext (or with any certificate
            // for MTA-STS testing mode, which already used the lenient verifier).
            let _ = sts_testing;
            return plaintext_retry(host, hello, m).await;
        }
        if let Err(e) = c.ehlo(hello).await {
            return Attempt::Failed { msg: format!("EHLO after STARTTLS: {e}") };
        }
        rec("success", String::new()).await;
    } else {
        rec("starttls-not-supported", "STARTTLS not offered".into()).await;
        if required || m.requiretls {
            c.quit().await;
            return Attempt::Failed { msg: "STARTTLS not offered but TLS is required".into() };
        }
    }
    match c.transaction(m).await {
        Ok(res) => {
            c.quit().await;
            Attempt::Done(res)
        }
        Err(e) => Attempt::Failed { msg: format!("{e}") },
    }
}

async fn plaintext_retry(host: &str, hello: &str, m: &Message<'_>) -> Attempt {
    if m.requiretls {
        return Attempt::Failed { msg: "TLS handshake failed and REQUIRETLS is set".into() };
    }
    let mut c = match Client::connect(host, 25).await {
        Ok(c) => c,
        Err(e) => return Attempt::Failed { msg: format!("connect: {e}") },
    };
    match c.read_reply().await {
        Ok(r) if r.code == 220 => {}
        Ok(r) => return Attempt::Failed { msg: format!("greeting: {}", r.describe()) },
        Err(e) => return Attempt::Failed { msg: format!("greeting: {e}") },
    }
    if let Err(e) = c.ehlo(hello).await {
        return Attempt::Failed { msg: format!("EHLO: {e}") };
    }
    match c.transaction(m).await {
        Ok(res) => {
            c.quit().await;
            Attempt::Done(res)
        }
        Err(e) => Attempt::Failed { msg: format!("{e}") },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stuffing() {
        assert_eq!(dot_stuff(b"a\r\n.b\r\n"), b"a\r\n..b\r\n.\r\n");
        assert_eq!(dot_stuff(b".x"), b"..x\r\n.\r\n");
    }
    #[test]
    fn xtext_roundtrip() {
        assert_eq!(xtext("a+b=c d"), "a+2Bb+3Dc+20d");
        assert_eq!(xtext_decode("a+2Bb+3Dc+20d"), "a+b=c d");
    }
    #[test]
    fn notify() {
        let d = RcptDsn { notify: "SUCCESS,DELAY".into(), orcpt: String::new() };
        assert!(d.wants("SUCCESS") && d.wants("DELAY") && !d.wants("FAILURE"));
        assert!(RcptDsn::default().wants("FAILURE"));
        assert!(!RcptDsn { notify: "NEVER".into(), orcpt: String::new() }.wants("FAILURE"));
    }
}
