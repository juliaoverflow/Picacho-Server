//! MTA-STS (RFC 8461): discover and cache recipient domains' TLS policies.
use crate::db::Db;
use crate::state::State;
use crate::util::now;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Mode {
    Enforce,
    Testing,
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub id: String,
    pub mode: Mode,
    pub mx: Vec<String>,
    pub max_age: i64,
    /// The policy text as fetched (for TLS reports).
    pub text: String,
}

impl Policy {
    /// Does an MX host name match one of the policy's `mx` patterns?
    pub fn allows(&self, host: &str) -> bool {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        self.mx.iter().any(|p| mx_matches(p, &host))
    }
}

pub fn mx_matches(pattern: &str, host: &str) -> bool {
    let p = pattern.trim().trim_end_matches('.').to_ascii_lowercase();
    if let Some(suffix) = p.strip_prefix("*.") {
        // A wildcard covers exactly one leftmost label.
        return host.split_once('.').is_some_and(|(first, rest)| !first.is_empty() && rest == suffix);
    }
    p == host
}

/// Parse a policy file (`version`, `mode`, `mx`, `max_age` lines).
pub fn parse(text: &str, id: &str) -> Option<Policy> {
    let mut version = None;
    let mut mode = None;
    let mut mx = vec![];
    let mut max_age = None;
    for line in text.lines() {
        let Some((k, v)) = line.split_once(':') else { continue };
        let v = v.trim();
        match k.trim() {
            "version" => version = Some(v.to_string()),
            "mode" => {
                mode = Some(match v {
                    "enforce" => Mode::Enforce,
                    "testing" => Mode::Testing,
                    "none" => Mode::None,
                    _ => return None,
                })
            }
            "mx" => mx.push(v.to_string()),
            "max_age" => max_age = v.parse::<i64>().ok(),
            _ => {}
        }
    }
    if version.as_deref() != Some("STSv1") {
        return None;
    }
    let mode = mode?;
    if mode != Mode::None && mx.is_empty() {
        return None;
    }
    Some(Policy { id: id.to_string(), mode, mx, max_age: max_age?.clamp(0, 31_557_600), text: text.to_string() })
}

/// Outcome of a policy lookup.
pub enum Lookup {
    /// No MTA-STS for this domain.
    NoPolicy,
    Found(Policy),
    /// Advertised, but the policy couldn't be fetched (and nothing is cached).
    FetchError(String),
}

impl Db {
    async fn sts_cached(&self, domain: &str) -> Result<Option<(Policy, i64)>> {
        let r = sqlx::query("SELECT policy, expires_at FROM mta_sts_cache WHERE domain = $1")
            .bind(domain)
            .fetch_optional(&self.pool)
            .await?;
        Ok(r.and_then(|r| {
            let p: String = r.get(0);
            serde_json::from_str::<Policy>(&p).ok().map(|p| (p, r.get::<i64, _>(1)))
        }))
    }

    async fn sts_store(&self, domain: &str, p: &Policy) -> Result<()> {
        let _g = self.wl().await;
        sqlx::query(
            "INSERT INTO mta_sts_cache (domain, policy_id, policy, fetched_at, expires_at) VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (domain) DO UPDATE SET policy_id = excluded.policy_id, policy = excluded.policy,
             fetched_at = excluded.fetched_at, expires_at = excluded.expires_at",
        )
        .bind(domain)
        .bind(&p.id)
        .bind(serde_json::to_string(p)?)
        .bind(now())
        .bind(now() + p.max_age)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

/// The `id` from `_mta-sts.<domain>` (None: no record).
async fn txt_id(state: &State, domain: &str) -> Result<Option<String>, String> {
    let Some(auth) = &state.resolver else { return Ok(None) };
    let name = format!("_mta-sts.{}.", domain.trim_end_matches('.'));
    match tokio::time::timeout(Duration::from_secs(10), auth.resolver().txt_lookup(name)).await {
        Err(_) => Err("MTA-STS TXT lookup timed out".into()),
        Ok(Err(e)) if e.is_no_records_found() || e.is_nx_domain() => Ok(None),
        Ok(Err(e)) => Err(format!("MTA-STS TXT lookup: {e}")),
        Ok(Ok(txt)) => {
            let records: Vec<String> = txt
                .answers()
                .iter()
                .filter_map(|r| match &r.data {
                    mail_auth::hickory_resolver::proto::rr::RData::TXT(t) => {
                        Some(t.txt_data.iter().map(|d| String::from_utf8_lossy(d).to_string()).collect::<String>())
                    }
                    _ => None,
                })
                .filter(|t| t.starts_with("v=STSv1"))
                .collect();
            if records.len() != 1 {
                return Ok(None);
            }
            let id = records[0]
                .split(';')
                .filter_map(|kv| kv.trim().split_once('='))
                .find(|(k, _)| k.trim() == "id")
                .map(|(_, v)| v.trim().to_string());
            Ok(id.filter(|i| !i.is_empty() && i.len() <= 32 && i.chars().all(|c| c.is_ascii_alphanumeric())))
        }
    }
}

async fn fetch(domain: &str, id: &str) -> Result<Policy, String> {
    let url = format!("https://mta-sts.{domain}/.well-known/mta-sts.txt");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| e.to_string())?;
    let r = client.get(&url).send().await.map_err(|e| format!("fetch {url}: {e}"))?;
    if !r.status().is_success() {
        return Err(format!("fetch {url}: HTTP {}", r.status()));
    }
    let ctype = r.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("").to_ascii_lowercase();
    if !ctype.starts_with("text/plain") {
        return Err(format!("{url} is not text/plain"));
    }
    let body = r.bytes().await.map_err(|e| e.to_string())?;
    if body.len() > 64 * 1024 {
        return Err(format!("{url} is too large"));
    }
    parse(&String::from_utf8_lossy(&body), id).ok_or_else(|| format!("{url} is not a valid MTA-STS policy"))
}

/// Current policy for a recipient domain, refreshing the cache when the
/// advertised id changed or the cached copy expired.
pub async fn lookup(state: &State, domain: &str) -> Lookup {
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    let cached = state.db.sts_cached(&domain).await.ok().flatten();
    let fresh_cache = cached.as_ref().filter(|(_, exp)| *exp > now()).map(|(p, _)| p.clone());
    let id = match txt_id(state, &domain).await {
        Ok(Some(id)) => id,
        // No record (or DNS trouble): a cached, unexpired policy still applies.
        Ok(None) | Err(_) => {
            return match fresh_cache {
                Some(p) => Lookup::Found(p),
                None => Lookup::NoPolicy,
            }
        }
    };
    if let Some(p) = &fresh_cache {
        if p.id == id {
            return Lookup::Found(p.clone());
        }
    }
    match fetch(&domain, &id).await {
        Ok(p) => {
            let _ = state.db.sts_store(&domain, &p).await;
            Lookup::Found(p)
        }
        Err(e) => match fresh_cache {
            Some(p) => Lookup::Found(p),
            None => Lookup::FetchError(e),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn policy() {
        let p = parse("version: STSv1\nmode: enforce\nmx: mail.example.com\nmx: *.example.net\nmax_age: 86400\n", "1").unwrap();
        assert_eq!(p.mode, Mode::Enforce);
        assert!(p.allows("mail.example.com"));
        assert!(p.allows("mx1.example.net"));
        assert!(!p.allows("a.b.example.net"));
        assert!(!p.allows("example.net"));
        assert!(parse("version: STSv1\nmode: enforce\nmax_age: 5", "1").is_none());
    }
}
