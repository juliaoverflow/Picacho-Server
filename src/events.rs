//! In-process change notifications. A session watching a mailbox is woken
//! when anything changes it; the database's per-mailbox modseq remains the
//! source of truth, so missed or coalesced wakeups are harmless.
use dashmap::DashMap;
use std::sync::Arc;
use tokio::sync::broadcast;

#[derive(Clone, Default)]
pub struct Hub {
    mailboxes: Arc<DashMap<i64, broadcast::Sender<()>>>,
}

impl Hub {
    pub fn subscribe(&self, mailbox_id: i64) -> broadcast::Receiver<()> {
        self.mailboxes
            .entry(mailbox_id)
            .or_insert_with(|| broadcast::channel(16).0)
            .subscribe()
    }

    pub fn notify(&self, mailbox_id: i64) {
        let drop_it = match self.mailboxes.get(&mailbox_id) {
            Some(tx) => tx.send(()).is_err(),
            None => false,
        };
        if drop_it {
            self.mailboxes.remove_if(&mailbox_id, |_, tx| tx.receiver_count() == 0);
        }
    }
}
