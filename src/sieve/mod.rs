//! Sieve mail filtering (RFC 5228) with fileinto, reject, envelope,
//! imap4flags, body, variables, vacation (+seconds), relational,
//! subaddress, copy, regex, date, index, mailbox, spamtest/virustest,
//! include and encoded-character. Scripts are managed with ManageSieve
//! (RFC 5804), JMAP (RFC 9661 SieveScript) or the account API.
pub mod deliver;
pub mod interp;
pub mod managesieve;
pub mod parse;

use crate::db::Db;
use anyhow::Result;
use serde::Serialize;
use sqlx::Row;

pub const MAX_SCRIPTS: i64 = 32;
pub const MAX_SCRIPT_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, Serialize)]
pub struct SieveScript {
    pub id: i64,
    pub name: String,
    pub content: String,
    pub active: bool,
    pub updated_at: i64,
}

fn script_from(r: &sqlx::any::AnyRow) -> Result<SieveScript> {
    Ok(SieveScript {
        id: r.try_get("id")?,
        name: r.try_get("name")?,
        content: r.try_get("content")?,
        active: r.try_get::<i64, _>("active")? != 0,
        updated_at: r.try_get("updated_at")?,
    })
}

/// Script names: 1-128 characters, no control characters or slashes.
pub fn valid_name(n: &str) -> bool {
    !n.is_empty() && n.chars().count() <= 128 && !n.chars().any(|c| c.is_control() || c == '/' || c == '\\')
}

/// Check a script without storing it.
pub fn check(content: &str) -> Result<(), String> {
    if content.len() > MAX_SCRIPT_BYTES {
        return Err(format!("Script is larger than {MAX_SCRIPT_BYTES} bytes."));
    }
    parse::parse(content).map(|_| ()).map_err(|e| e.to_string())
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct VacationSettings {
    pub enabled: bool,
    pub subject: Option<String>,
    pub text_body: Option<String>,
    pub html_body: Option<String>,
    pub from_date: Option<i64>,
    pub to_date: Option<i64>,
    pub days: i64,
}

impl VacationSettings {
    pub fn active_at(&self, t: i64) -> bool {
        self.enabled && self.from_date.is_none_or(|f| t >= f) && self.to_date.is_none_or(|e| t < e)
    }
}

impl Db {
    pub async fn sieve_scripts(&self, account_id: i64) -> Result<Vec<SieveScript>> {
        let rows = sqlx::query("SELECT id, name, content, active, updated_at FROM sieve_scripts WHERE account_id = $1 ORDER BY name")
            .bind(account_id)
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(script_from).collect()
    }

    pub async fn sieve_script(&self, account_id: i64, name: &str) -> Result<Option<SieveScript>> {
        let r = sqlx::query("SELECT id, name, content, active, updated_at FROM sieve_scripts WHERE account_id = $1 AND name = $2")
            .bind(account_id)
            .bind(name)
            .fetch_optional(&self.pool)
            .await?;
        r.as_ref().map(script_from).transpose()
    }

    pub async fn sieve_script_by_id(&self, account_id: i64, id: i64) -> Result<Option<SieveScript>> {
        let r = sqlx::query("SELECT id, name, content, active, updated_at FROM sieve_scripts WHERE account_id = $1 AND id = $2")
            .bind(account_id)
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        r.as_ref().map(script_from).transpose()
    }

    pub async fn sieve_active(&self, account_id: i64) -> Result<Option<SieveScript>> {
        let r = sqlx::query("SELECT id, name, content, active, updated_at FROM sieve_scripts WHERE account_id = $1 AND active = 1")
            .bind(account_id)
            .fetch_optional(&self.pool)
            .await?;
        r.as_ref().map(script_from).transpose()
    }

    /// Create or replace a script; returns its id.
    pub async fn sieve_put(&self, account_id: i64, name: &str, content: &str) -> Result<i64> {
        let _g = self.wl().await;
        let now = crate::util::now();
        sqlx::query(
            "INSERT INTO sieve_scripts (account_id, name, content, active, created_at, updated_at) VALUES ($1, $2, $3, 0, $4, $4)
             ON CONFLICT (account_id, name) DO UPDATE SET content = excluded.content, updated_at = excluded.updated_at",
        )
        .bind(account_id)
        .bind(name)
        .bind(content)
        .bind(now)
        .execute(&self.pool)
        .await?;
        let r = sqlx::query("SELECT id FROM sieve_scripts WHERE account_id = $1 AND name = $2").bind(account_id).bind(name).fetch_one(&self.pool).await?;
        Ok(r.get(0))
    }

    pub async fn sieve_count(&self, account_id: i64) -> Result<i64> {
        Ok(sqlx::query("SELECT COUNT(*) FROM sieve_scripts WHERE account_id = $1").bind(account_id).fetch_one(&self.pool).await?.get(0))
    }

    pub async fn sieve_delete(&self, account_id: i64, name: &str) -> Result<bool> {
        let _g = self.wl().await;
        let r = sqlx::query("DELETE FROM sieve_scripts WHERE account_id = $1 AND name = $2").bind(account_id).bind(name).execute(&self.pool).await?;
        Ok(r.rows_affected() == 1)
    }

    pub async fn sieve_rename(&self, account_id: i64, from: &str, to: &str) -> Result<bool> {
        let _g = self.wl().await;
        let r = sqlx::query("UPDATE sieve_scripts SET name = $1, updated_at = $2 WHERE account_id = $3 AND name = $4")
            .bind(to)
            .bind(crate::util::now())
            .bind(account_id)
            .bind(from)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected() == 1)
    }

    /// Activate one script (or none).
    pub async fn sieve_activate(&self, account_id: i64, name: Option<&str>) -> Result<bool> {
        let mut tx = self.begin().await?;
        sqlx::query("UPDATE sieve_scripts SET active = 0 WHERE account_id = $1").bind(account_id).execute(&mut *tx.tx).await?;
        let mut ok = true;
        if let Some(n) = name {
            let r = sqlx::query("UPDATE sieve_scripts SET active = 1 WHERE account_id = $1 AND name = $2").bind(account_id).bind(n).execute(&mut *tx.tx).await?;
            ok = r.rows_affected() == 1;
        }
        if ok {
            tx.commit().await?;
        }
        Ok(ok)
    }

    pub async fn vacation(&self, account_id: i64) -> Result<VacationSettings> {
        let r = sqlx::query("SELECT enabled, subject, text_body, html_body, from_date, to_date, days FROM vacation WHERE account_id = $1")
            .bind(account_id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(match r {
            Some(r) => VacationSettings {
                enabled: r.get::<i64, _>(0) != 0,
                subject: r.get(1),
                text_body: r.get(2),
                html_body: r.get(3),
                from_date: r.get(4),
                to_date: r.get(5),
                days: r.get(6),
            },
            None => VacationSettings { days: 7, ..Default::default() },
        })
    }

    pub async fn set_vacation(&self, account_id: i64, v: &VacationSettings) -> Result<()> {
        let _g = self.wl().await;
        sqlx::query(
            "INSERT INTO vacation (account_id, enabled, subject, text_body, html_body, from_date, to_date, days) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
             ON CONFLICT (account_id) DO UPDATE SET enabled = excluded.enabled, subject = excluded.subject, text_body = excluded.text_body,
             html_body = excluded.html_body, from_date = excluded.from_date, to_date = excluded.to_date, days = excluded.days",
        )
        .bind(account_id)
        .bind(v.enabled as i64)
        .bind(&v.subject)
        .bind(&v.text_body)
        .bind(&v.html_body)
        .bind(v.from_date)
        .bind(v.to_date)
        .bind(v.days.max(0))
        .execute(&self.pool)
        .await?;
        if !v.enabled {
            sqlx::query("DELETE FROM vacation_sent WHERE account_id = $1 AND handle = 'jmap'").bind(account_id).execute(&self.pool).await?;
        }
        Ok(())
    }

    /// Record a vacation reply unless one went to `sender` within `seconds`.
    /// Returns true when a reply should be sent now.
    pub async fn vacation_should_send(&self, account_id: i64, handle: &str, sender: &str, seconds: i64) -> Result<bool> {
        let now = crate::util::now();
        let sender = sender.to_ascii_lowercase();
        let _g = self.wl().await;
        let r = sqlx::query("SELECT sent_at FROM vacation_sent WHERE account_id = $1 AND handle = $2 AND sender = $3")
            .bind(account_id)
            .bind(handle)
            .bind(&sender)
            .fetch_optional(&self.pool)
            .await?;
        if let Some(r) = r {
            if now - r.get::<i64, _>(0) < seconds {
                return Ok(false);
            }
        }
        sqlx::query(
            "INSERT INTO vacation_sent (account_id, handle, sender, sent_at) VALUES ($1, $2, $3, $4)
             ON CONFLICT (account_id, handle, sender) DO UPDATE SET sent_at = excluded.sent_at",
        )
        .bind(account_id)
        .bind(handle)
        .bind(&sender)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(true)
    }
}
