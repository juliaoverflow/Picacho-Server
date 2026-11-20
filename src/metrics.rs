//! Prometheus metrics (`/metrics`, text exposition format 0.0.4).
//!
//! Counters are process-wide atomics; gauges are read from the database and
//! the connection tracker when scraped.
use crate::state::State;
use std::fmt::Write;
use std::sync::atomic::{AtomicU64, Ordering};

pub struct Counter {
    name: &'static str,
    help: &'static str,
    v: AtomicU64,
}

impl Counter {
    const fn new(name: &'static str, help: &'static str) -> Self {
        Self { name, help, v: AtomicU64::new(0) }
    }
    pub fn inc(&self) {
        self.v.fetch_add(1, Ordering::Relaxed);
    }
    pub fn add(&self, n: u64) {
        self.v.fetch_add(n, Ordering::Relaxed);
    }
    pub fn get(&self) -> u64 {
        self.v.load(Ordering::Relaxed)
    }
}

pub static SMTP_ACCEPTED: Counter = Counter::new("picacho_smtp_messages_accepted_total", "Messages accepted over SMTP");
pub static SMTP_REJECTED: Counter = Counter::new("picacho_smtp_messages_rejected_total", "Messages rejected during SMTP (policy, spam, virus)");
pub static SPAM_JUNKED: Counter = Counter::new("picacho_filter_junked_total", "Messages filed in Junk by the content filter");
pub static VIRUS_FOUND: Counter = Counter::new("picacho_filter_virus_total", "Messages rejected because a virus was found");
pub static GREYLISTED: Counter = Counter::new("picacho_filter_greylisted_total", "Deliveries deferred by greylisting");
pub static QUEUED: Counter = Counter::new("picacho_queue_enqueued_total", "Messages added to the outbound queue");
pub static DELIVERED: Counter = Counter::new("picacho_queue_delivered_total", "Recipients delivered by the outbound queue");
pub static BOUNCED: Counter = Counter::new("picacho_queue_failed_total", "Recipients that failed permanently");
pub static AUTH_FAILURES: Counter = Counter::new("picacho_auth_failures_total", "Failed sign-ins (all protocols)");
pub static LOCAL_DELIVERIES: Counter = Counter::new("picacho_local_deliveries_total", "Messages stored in local mailboxes");
pub static SIEVE_ACTIONS: Counter = Counter::new("picacho_sieve_actions_total", "Sieve actions executed at delivery");
pub static HTTP_REQUESTS: Counter = Counter::new("picacho_http_requests_total", "HTTP requests served");
pub static DAV_REQUESTS: Counter = Counter::new("picacho_dav_requests_total", "WebDAV/CalDAV/CardDAV requests served");

const COUNTERS: &[&Counter] = &[
    &SMTP_ACCEPTED,
    &SMTP_REJECTED,
    &SPAM_JUNKED,
    &VIRUS_FOUND,
    &GREYLISTED,
    &QUEUED,
    &DELIVERED,
    &BOUNCED,
    &AUTH_FAILURES,
    &LOCAL_DELIVERIES,
    &SIEVE_ACTIONS,
    &HTTP_REQUESTS,
    &DAV_REQUESTS,
];

pub async fn render(state: &State) -> String {
    let mut out = String::with_capacity(4096);
    for c in COUNTERS {
        let _ = writeln!(out, "# HELP {} {}\n# TYPE {} counter\n{} {}", c.name, c.help, c.name, c.name, c.get());
    }
    let gauge = |out: &mut String, name: &str, help: &str, v: f64| {
        let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} gauge\n{name} {v}");
    };
    gauge(&mut out, "picacho_up", "1 while the server is running", 1.0);
    gauge(&mut out, "picacho_start_time_seconds", "Process start time", state.started as f64);
    gauge(&mut out, "picacho_connections", "Open IMAP/SMTP/ManageSieve connections", state.conns.total() as f64);
    gauge(&mut out, "picacho_imap_connections", "Open IMAP connections", state.conns.imap.load(Ordering::Relaxed) as f64);
    gauge(&mut out, "picacho_smtp_connections", "Open SMTP connections", state.conns.smtp.load(Ordering::Relaxed) as f64);
    gauge(&mut out, "picacho_banned_ips", "Addresses currently banned", state.limiter.list_bans().len() as f64);
    if let Ok((q, d, f)) = state.db.queue_stats().await {
        let _ = writeln!(out, "# HELP picacho_queue_messages Messages in the outbound queue\n# TYPE picacho_queue_messages gauge");
        let _ = writeln!(out, "picacho_queue_messages{{status=\"queued\"}} {q}\npicacho_queue_messages{{status=\"deferred\"}} {d}\npicacho_queue_messages{{status=\"failed\"}} {f}");
    }
    if let Ok(v) = state.db.stats().await {
        for (k, name) in [("accounts", "picacho_accounts"), ("domains", "picacho_domains"), ("messages", "picacho_messages"), ("stored_bytes", "picacho_stored_bytes")] {
            if let Some(n) = v.get(k).and_then(|x| x.as_f64()) {
                gauge(&mut out, name, k, n);
            }
        }
    }
    out
}
