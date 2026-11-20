//! IMAP ACL (RFC 4314) and METADATA (RFC 5464) storage.
//!
//! Owners have every right on their own mailboxes. Other accounts get
//! rights through ACL entries for their address, `authenticated` (any
//! signed-in user) or `anyone`, and see shared folders as
//! `Shared/<owner>/<folder>` (the "other users" namespace).
use crate::db::{Db, Mailbox};
use anyhow::Result;
use sqlx::Row;

pub const ALL_RIGHTS: &str = "lrswipkxtea";
pub const SHARED: &str = "Shared";

/// Normalize a rights string: known letters, unique, canonical order.
/// The obsolete `c` maps to `k`+`x` and `d` to `e`+`t` (RFC 4314 2.1.1).
pub fn normalize(r: &str) -> Option<String> {
    let mut set = std::collections::BTreeSet::new();
    for ch in r.chars() {
        match ch {
            'c' => {
                set.insert('k');
                set.insert('x');
            }
            'd' => {
                set.insert('e');
                set.insert('t');
            }
            c if ALL_RIGHTS.contains(c) => {
                set.insert(c);
            }
            '0'..='9' => {}
            _ => return None,
        }
    }
    Some(ALL_RIGHTS.chars().filter(|c| set.contains(c)).collect())
}

impl Db {
    pub async fn acl(&self, mailbox_id: i64) -> Result<Vec<(String, String)>> {
        let rows = sqlx::query("SELECT identifier, rights FROM acl WHERE mailbox_id = $1 ORDER BY identifier").bind(mailbox_id).fetch_all(&self.pool).await?;
        Ok(rows.iter().map(|r| (r.get(0), r.get(1))).collect())
    }

    pub async fn set_acl(&self, mailbox_id: i64, ident: &str, rights: &str) -> Result<()> {
        let _g = self.wl().await;
        if rights.is_empty() {
            sqlx::query("DELETE FROM acl WHERE mailbox_id = $1 AND identifier = $2").bind(mailbox_id).bind(ident).execute(&self.pool).await?;
        } else {
            sqlx::query("INSERT INTO acl (mailbox_id, identifier, rights) VALUES ($1, $2, $3) ON CONFLICT (mailbox_id, identifier) DO UPDATE SET rights = excluded.rights")
                .bind(mailbox_id)
                .bind(ident)
                .bind(rights)
                .execute(&self.pool)
                .await?;
        }
        Ok(())
    }

    /// Rights `email` has on a mailbox it doesn't own.
    pub async fn rights_for(&self, mailbox_id: i64, email: &str) -> Result<String> {
        let rows = sqlx::query("SELECT rights FROM acl WHERE mailbox_id = $1 AND identifier IN ($2, 'anyone', 'authenticated')")
            .bind(mailbox_id)
            .bind(email.to_ascii_lowercase())
            .fetch_all(&self.pool)
            .await?;
        let all: String = rows.iter().map(|r| r.get::<String, _>(0)).collect();
        Ok(normalize(&all).unwrap_or_default())
    }

    /// Mailboxes shared with `email`: (owner address, mailbox, rights).
    pub async fn shared_with(&self, email: &str, own_id: i64) -> Result<Vec<(String, Mailbox, String)>> {
        let rows = sqlx::query(
            "SELECT DISTINCT acl.mailbox_id, a.email FROM acl JOIN mailboxes m ON m.id = acl.mailbox_id JOIN accounts a ON a.id = m.account_id
             WHERE acl.identifier IN ($1, 'anyone', 'authenticated') AND m.account_id <> $2",
        )
        .bind(email.to_ascii_lowercase())
        .bind(own_id)
        .fetch_all(&self.pool)
        .await?;
        let mut out = vec![];
        for r in rows {
            let id: i64 = r.get(0);
            let owner: String = r.get(1);
            let rights = self.rights_for(id, email).await?;
            if !rights.contains('l') {
                continue;
            }
            if let Some(mb) = self.mailbox_by_id(id).await? {
                out.push((owner, mb, rights));
            }
        }
        Ok(out)
    }

    // ---------------------------------------------------------------- METADATA

    /// Entries under a mailbox (0 = server) visible to `owner` (0 = shared).
    pub async fn metadata(&self, mailbox_id: i64, owners: &[i64]) -> Result<Vec<(i64, String, Vec<u8>)>> {
        let mut out = vec![];
        for o in owners {
            let rows = sqlx::query("SELECT name, value FROM metadata WHERE owner_id = $1 AND mailbox_id = $2 ORDER BY name")
                .bind(o)
                .bind(mailbox_id)
                .fetch_all(&self.pool)
                .await?;
            for r in rows {
                out.push((*o, r.get::<String, _>(0), r.get::<Vec<u8>, _>(1)));
            }
        }
        Ok(out)
    }

    pub async fn metadata_count(&self, mailbox_id: i64, owner: i64) -> Result<i64> {
        Ok(sqlx::query("SELECT COUNT(*) FROM metadata WHERE owner_id = $1 AND mailbox_id = $2").bind(owner).bind(mailbox_id).fetch_one(&self.pool).await?.get(0))
    }

    pub async fn set_metadata(&self, owner: i64, mailbox_id: i64, name: &str, value: Option<&[u8]>) -> Result<()> {
        let _g = self.wl().await;
        match value {
            Some(v) => {
                sqlx::query("INSERT INTO metadata (owner_id, mailbox_id, name, value) VALUES ($1, $2, $3, $4) ON CONFLICT (owner_id, mailbox_id, name) DO UPDATE SET value = excluded.value")
                    .bind(owner)
                    .bind(mailbox_id)
                    .bind(name)
                    .bind(v.to_vec())
                    .execute(&self.pool)
                    .await?;
            }
            None => {
                sqlx::query("DELETE FROM metadata WHERE owner_id = $1 AND mailbox_id = $2 AND name = $3").bind(owner).bind(mailbox_id).bind(name).execute(&self.pool).await?;
            }
        }
        Ok(())
    }
}

/// Entry names are /private/... or /shared/..., no wildcards or "//".
pub fn valid_entry(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    (lower.starts_with("/private/") || lower.starts_with("/shared/") || lower == "/private" || lower == "/shared")
        && !name.contains("//")
        && !name.ends_with('/')
        && !name.contains(['*', '%'])
        && name.chars().all(|c| !c.is_control())
        && name.len() <= 512
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rights() {
        assert_eq!(normalize("rl").as_deref(), Some("lr"));
        assert_eq!(normalize("c").as_deref(), Some("kx"));
        assert_eq!(normalize("lrd").as_deref(), Some("lrte"));
        assert!(normalize("lrQ").is_none());
        assert!(valid_entry("/private/comment"));
        assert!(!valid_entry("/other/x"));
        assert!(!valid_entry("/shared/a//b"));
    }
}
