//! In-process change notifications. A session watching a mailbox is woken
//! when anything changes it; the database's per-mailbox modseq remains the
//! source of truth, so missed or coalesced wakeups are harmless.
//!
//! Every change is also announced on a global channel with its mailbox id,
//! for IMAP NOTIFY sessions that follow many mailboxes at once.
use dashmap::DashMap;
use std::sync::{Arc, OnceLock};
use tokio::sync::broadcast;

#[derive(Clone, Default)]
pub struct Hub {
    mailboxes: Arc<DashMap<i64, broadcast::Sender<()>>>,
    any: Arc<OnceLock<broadcast::Sender<i64>>>,
}

impl Hub {
    pub fn subscribe(&self, mailbox_id: i64) -> broadcast::Receiver<()> {
        self.mailboxes
            .entry(mailbox_id)
            .or_insert_with(|| broadcast::channel(16).0)
            .subscribe()
    }

    fn any_tx(&self) -> &broadcast::Sender<i64> {
        self.any.get_or_init(|| broadcast::channel(1024).0)
    }

    /// Every mailbox change, by mailbox id. A lagging receiver should
    /// treat the lag as "anything may have changed".
    pub fn subscribe_all(&self) -> broadcast::Receiver<i64> {
        self.any_tx().subscribe()
    }

    pub fn notify(&self, mailbox_id: i64) {
        let drop_it = match self.mailboxes.get(&mailbox_id) {
            Some(tx) => tx.send(()).is_err(),
            None => false,
        };
        if drop_it {
            self.mailboxes.remove_if(&mailbox_id, |_, tx| tx.receiver_count() == 0);
        }
        if let Some(tx) = self.any.get() {
            let _ = tx.send(mailbox_id);
        }
    }
}
