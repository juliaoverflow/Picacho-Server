//! INPROGRESS (RFC 9585): progress reports on long-running commands.
//!
//! While a command runs past `limits.imap_progress_ms`, the session sends
//! `* OK [INPROGRESS ("tag" done total)] Still working.` at most that
//! often, so clients keep waiting rather than time out. Loops over
//! messages (SEARCH, SORT, THREAD) report how far they are; single
//! database steps (COPY, MOVE, EXPUNGE) report with NIL counts.
use super::proto::Conn;
use std::future::Future;
use std::time::{Duration, Instant};

/// The untagged response; `None` counts are sent as NIL.
pub fn line(tag: &str, done: Option<usize>, total: Option<usize>) -> String {
    let n = |v: Option<usize>| v.map_or_else(|| "NIL".to_string(), |v| v.to_string());
    format!("* OK [INPROGRESS (\"{tag}\" {} {})] Still working.\r\n", n(done), n(total))
}

/// Says when a loop should report again: first after `every`, then no
/// more often than that.
pub struct Ticker {
    every: Duration,
    next: Instant,
}

impl Ticker {
    pub fn new(every: Duration) -> Self {
        Self { every, next: Instant::now() + every }
    }

    pub fn due(&mut self) -> bool {
        let now = Instant::now();
        if now < self.next {
            return false;
        }
        self.next = now + self.every;
        true
    }
}

/// Runs `fut`, reporting progress (without counts) on `conn` while it takes
/// longer than `every`.
pub async fn during<F: Future>(conn: &mut Conn, tag: &str, every: Duration, fut: F) -> F::Output {
    let every = every.max(Duration::from_millis(1));
    tokio::pin!(fut);
    let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + every, every);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            r = &mut fut => return r,
            _ = tick.tick() => {
                conn.push(&line(tag, None, None));
                // A client that stopped reading mustn't hold up the command.
                let _ = tokio::time::timeout(every, conn.flush()).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_as_rfc_9585() {
        assert_eq!(line("a7", Some(3), Some(10)), "* OK [INPROGRESS (\"a7\" 3 10)] Still working.\r\n");
        assert_eq!(line("a7", None, None), "* OK [INPROGRESS (\"a7\" NIL NIL)] Still working.\r\n");
    }

    #[test]
    fn ticker_waits_then_limits_the_rate() {
        let mut t = Ticker::new(Duration::from_secs(3600));
        assert!(!t.due(), "not before the first interval");
        let mut t = Ticker::new(Duration::ZERO);
        assert!(t.due() && t.due(), "zero reports every time");
    }
}
