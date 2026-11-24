//! LDAP directory authentication.
//!
//! Two ways to check a password:
//! - search, then bind (default): bind as the service account (or
//!   anonymously), find exactly one entry with `user_filter`, read its mail,
//!   name and groups, then bind as that entry's DN with the password;
//! - direct bind: bind as `user_dn_template` filled in with the user name,
//!   then read the user's own entry with those credentials.
//!
//! The entry's mail attribute picks the mailbox. Accounts are matched by
//! address, so the same mailbox can also be linked to a single sign-on
//! identity (`oidc_sub`) and use access tokens; nothing here touches that link.
use crate::auth::AuthError;
use crate::db::Account;
use crate::settings::LdapSettings;
use crate::state::State;
use ldap3::{dn_escape, ldap_escape, Ldap, LdapConnAsync, LdapConnSettings, LdapError, Scope, SearchEntry};
use serde::Serialize;
use std::sync::Arc;
use std::time::Duration;

/// LDAP result code for a wrong password (or unknown DN).
const INVALID_CREDENTIALS: u32 = 49;
const MAX_USER: usize = 256;

/// A user found in the directory.
#[derive(Debug, Clone, Serialize)]
pub struct DirUser {
    pub dn: String,
    pub emails: Vec<String>,
    pub name: Option<String>,
    pub groups: Vec<String>,
    /// Contact details from `profile_attributes` (field -> values; empty: the attribute is unset).
    #[serde(skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub details: std::collections::BTreeMap<String, Vec<String>>,
}

#[derive(Debug)]
pub enum Outcome {
    /// The password is right.
    Valid(DirUser),
    /// The directory doesn't know this user (a local password may still apply).
    NotFound,
    /// The user exists and the password is wrong.
    BadPassword,
}

/// Fill a filter or DN template. `escape` is `ldap_escape` for filters,
/// `dn_escape` for DNs.
fn fill(template: &str, user: &str, dn: &str, escape: fn(&str) -> String) -> String {
    let (local, domain) = user.rsplit_once('@').unwrap_or((user, ""));
    template
        .replace("{user}", &escape(user))
        .replace("{local}", &escape(local))
        .replace("{domain}", &escape(domain))
        .replace("{dn}", &escape(dn))
}

fn filter_escape(s: &str) -> String {
    ldap_escape(s).into_owned()
}

fn dn_value_escape(s: &str) -> String {
    dn_escape(s).into_owned()
}

/// Values of an attribute; attribute names are case-insensitive.
fn attr(e: &SearchEntry, name: &str) -> Vec<String> {
    e.attrs
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case(name))
        .flat_map(|(_, v)| v.iter().cloned())
        .collect()
}

/// "cn=Mail Admins,ou=groups,dc=x" -> "Mail Admins".
pub fn rdn_value(dn: &str) -> &str {
    let first = dn.split(',').next().unwrap_or(dn);
    first.split_once('=').map(|(_, v)| v.trim()).unwrap_or(first.trim())
}

/// Whether any group (DN or name) matches any wanted name or DN.
pub fn in_groups(groups: &[String], wanted: &[String]) -> bool {
    groups.iter().any(|g| {
        wanted.iter().any(|w| {
            let w = w.trim();
            !w.is_empty() && (g.eq_ignore_ascii_case(w) || rdn_value(g).eq_ignore_ascii_case(w))
        })
    })
}

fn tls_config(cfg: &LdapSettings) -> Result<Arc<rustls::ClientConfig>, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let b = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?;
    if cfg.tls_skip_verify {
        return Ok(Arc::new(
            b.dangerous()
                .with_custom_certificate_verifier(Arc::new(crate::outbound::dane::AnyCert::default()))
                .with_no_client_auth(),
        ));
    }
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    for c in rustls_pemfile::certs(&mut cfg.ca_cert.as_bytes()) {
        let c = c.map_err(|e| format!("CA certificate: {e}"))?;
        roots.add(c).map_err(|e| format!("CA certificate: {e}"))?;
    }
    Ok(Arc::new(b.with_root_certificates(roots).with_no_client_auth()))
}

fn describe(e: LdapError) -> String {
    match e {
        LdapError::LdapResult { result } => {
            let t = result.text.trim();
            if t.is_empty() {
                format!("the directory answered with result code {}", result.rc)
            } else {
                format!("the directory answered with result code {}: {t}", result.rc)
            }
        }
        e => e.to_string(),
    }
}

async fn connect(cfg: &LdapSettings) -> Result<Ldap, String> {
    let settings = LdapConnSettings::new()
        .set_conn_timeout(Duration::from_secs(5))
        .set_starttls(cfg.starttls)
        .set_no_tls_verify(cfg.tls_skip_verify)
        .set_config(tls_config(cfg)?);
    let (conn, ldap) = LdapConnAsync::with_settings(settings, cfg.url.trim())
        .await
        .map_err(|e| format!("Couldn't connect to {}: {}", cfg.url.trim(), describe(e)))?;
    tokio::spawn(async move {
        if let Err(e) = conn.drive().await {
            tracing::debug!("ldap connection: {e}");
        }
    });
    Ok(ldap)
}

/// Bind; `Ok(false)` for wrong credentials.
async fn bind(ldap: &mut Ldap, dn: &str, password: &str) -> Result<bool, String> {
    let r = ldap.simple_bind(dn, password).await.map_err(describe)?;
    match r.rc {
        0 => Ok(true),
        INVALID_CREDENTIALS => Ok(false),
        _ => Err(describe(LdapError::LdapResult { result: r })),
    }
}

async fn service_bind(ldap: &mut Ldap, cfg: &LdapSettings) -> Result<(), String> {
    let dn = cfg.bind_dn.trim();
    if dn.is_empty() {
        return Ok(());
    }
    match bind(ldap, dn, cfg.bind_password.as_deref().unwrap_or("")).await {
        Ok(true) => Ok(()),
        Ok(false) => Err("The directory refused the service account's credentials.".into()),
        Err(e) => Err(format!("Service account bind failed: {e}")),
    }
}

fn user_attrs(cfg: &LdapSettings) -> Vec<String> {
    let mut a = vec![cfg.email_attr.trim().to_string(), cfg.name_attr.trim().to_string(), "cn".to_string()];
    if !cfg.group_attr.trim().is_empty() {
        a.push(cfg.group_attr.trim().to_string());
    }
    for m in &cfg.profile_attributes {
        a.push(m.claim.trim().to_string());
    }
    a.retain(|x| !x.is_empty());
    a.sort();
    a.dedup();
    a
}

/// Find the one entry for a user name.
async fn find(ldap: &mut Ldap, cfg: &LdapSettings, user: &str) -> Result<Option<SearchEntry>, String> {
    let filter = fill(cfg.user_filter.trim(), user, "", filter_escape);
    let (rs, _) = ldap
        .search(cfg.base_dn.trim(), Scope::Subtree, &filter, user_attrs(cfg))
        .await
        .map_err(describe)?
        .success()
        .map_err(|e| format!("User search failed: {}", describe(e)))?;
    let mut entries: Vec<SearchEntry> = rs.into_iter().map(SearchEntry::construct).collect();
    match entries.len() {
        0 => Ok(None),
        1 => Ok(entries.pop()),
        n => Err(format!("{n} directory entries match {user:?}; make the user filter more specific.")),
    }
}

async fn groups(ldap: &mut Ldap, cfg: &LdapSettings, user: &str, e: &SearchEntry) -> Result<Vec<String>, String> {
    let mut out = if cfg.group_attr.trim().is_empty() { vec![] } else { attr(e, cfg.group_attr.trim()) };
    if !cfg.group_base_dn.trim().is_empty() {
        let filter = fill(cfg.group_filter.trim(), user, &e.dn, filter_escape);
        let name = cfg.group_name_attr.trim();
        let (rs, _) = ldap
            .search(cfg.group_base_dn.trim(), Scope::Subtree, &filter, vec![name])
            .await
            .map_err(describe)?
            .success()
            .map_err(|e| format!("Group search failed: {}", describe(e)))?;
        for g in rs.into_iter().map(SearchEntry::construct) {
            out.push(attr(&g, name).into_iter().next().unwrap_or(g.dn));
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}

fn dir_user(cfg: &LdapSettings, e: &SearchEntry, groups: Vec<String>) -> DirUser {
    let name = attr(e, cfg.name_attr.trim()).into_iter().chain(attr(e, "cn")).find(|n| !n.trim().is_empty());
    DirUser {
        dn: e.dn.clone(),
        emails: attr(e, cfg.email_attr.trim()).into_iter().map(|m| m.trim().to_ascii_lowercase()).filter(|m| m.contains('@')).collect(),
        name,
        groups,
        details: cfg
            .profile_attributes
            .iter()
            .filter(|m| crate::directory::PROFILE_FIELDS.contains(&m.field.trim()) && !m.claim.trim().is_empty())
            .map(|m| {
                let mut v: Vec<String> = attr(e, m.claim.trim()).into_iter().map(|x| x.trim().chars().take(1000).collect::<String>()).filter(|x| !x.is_empty()).collect();
                v.dedup();
                v.truncate(20);
                (m.field.trim().to_string(), v)
            })
            .fold(std::collections::BTreeMap::new(), |mut m, (k, v)| {
                // Several attributes for one field (telephoneNumber, mobile) add up.
                let e: &mut Vec<String> = m.entry(k).or_default();
                for x in v {
                    if !e.contains(&x) {
                        e.push(x);
                    }
                }
                m
            }),
    }
}

fn valid_user(user: &str) -> bool {
    !user.is_empty() && user.len() <= MAX_USER && !user.chars().any(|c| c.is_control())
}

async fn run(cfg: &LdapSettings, user: &str, password: &str) -> Result<Outcome, String> {
    let mut ldap = connect(cfg).await?;
    let template = cfg.user_dn_template.trim();
    let out = if !template.is_empty() {
        // Direct bind: a refusal can't tell "no such user" from "wrong
        // password", so it's reported as NotFound and local passwords still apply.
        let dn = fill(template, user, "", dn_value_escape);
        if !bind(&mut ldap, &dn, password).await? {
            let _ = ldap.unbind().await;
            return Ok(Outcome::NotFound);
        }
        let entry = match find(&mut ldap, cfg, user).await? {
            Some(e) => e,
            None => {
                // Read the bound entry itself (works when the DN template is a real DN).
                let (rs, _) = ldap
                    .search(&dn, Scope::Base, "(objectClass=*)", user_attrs(cfg))
                    .await
                    .map_err(describe)?
                    .non_error()
                    .map_err(|_| format!("Signed in as {dn}, but the user filter doesn't find that entry under the base DN."))?;
                rs.into_iter().map(SearchEntry::construct).next().ok_or_else(|| format!("Signed in as {dn}, but couldn't read the entry."))?
            }
        };
        let g = groups(&mut ldap, cfg, user, &entry).await?;
        Outcome::Valid(dir_user(cfg, &entry, g))
    } else {
        service_bind(&mut ldap, cfg).await?;
        match find(&mut ldap, cfg, user).await? {
            None => Outcome::NotFound,
            Some(entry) => {
                // Groups are read with the service account, before rebinding as the user.
                let g = groups(&mut ldap, cfg, user, &entry).await?;
                if bind(&mut ldap, &entry.dn, password).await? {
                    Outcome::Valid(dir_user(cfg, &entry, g))
                } else {
                    Outcome::BadPassword
                }
            }
        }
    };
    let _ = ldap.unbind().await;
    Ok(out)
}

/// Check a user name and password against the directory. `Err` means the
/// directory couldn't answer (unreachable, misconfigured).
pub async fn authenticate(cfg: &LdapSettings, user: &str, password: &str) -> Result<Outcome, String> {
    let user = user.trim();
    // An empty password is an "unauthenticated bind", which servers accept
    // as success (RFC 4513 5.1.2); never let it through.
    if password.is_empty() || !valid_user(user) {
        return Ok(Outcome::BadPassword);
    }
    tokio::time::timeout(Duration::from_secs(15), run(cfg, user, password))
        .await
        .unwrap_or_else(|_| Err("The directory didn't answer in time.".into()))
}

/// For the console's "Test" button: connect, bind the service account,
/// and optionally look up a user and check their password.
pub async fn test(cfg: &LdapSettings, user: Option<&str>, password: Option<&str>) -> Result<serde_json::Value, String> {
    use serde_json::json;
    cfg.validate()?;
    let user = user.map(str::trim).filter(|u| !u.is_empty());
    let password = password.filter(|p| !p.is_empty());
    let fut = async {
        match (user, password) {
            (Some(u), Some(p)) => match run(cfg, u, p).await? {
                Outcome::Valid(d) => Ok(json!({"ok": true, "found": true, "password_ok": true, "user": d,
                    "admin": in_groups(&d.groups, &cfg.admin_groups), "allowed": cfg.required_groups.is_empty() || in_groups(&d.groups, &cfg.required_groups)})),
                Outcome::BadPassword => Ok(json!({"ok": true, "found": true, "password_ok": false})),
                Outcome::NotFound => Ok(json!({"ok": true, "found": false, "password_ok": false})),
            },
            (Some(u), None) if cfg.user_dn_template.trim().is_empty() => {
                let mut ldap = connect(cfg).await?;
                service_bind(&mut ldap, cfg).await?;
                let r = match find(&mut ldap, cfg, u).await? {
                    Some(e) => {
                        let g = groups(&mut ldap, cfg, u, &e).await?;
                        let d = dir_user(cfg, &e, g);
                        json!({"ok": true, "found": true, "user": d, "admin": in_groups(&d.groups, &cfg.admin_groups),
                            "allowed": cfg.required_groups.is_empty() || in_groups(&d.groups, &cfg.required_groups)})
                    }
                    None => json!({"ok": true, "found": false}),
                };
                let _ = ldap.unbind().await;
                Ok(r)
            }
            (Some(_), None) => Err("With a user DN template, enter the user's password to test.".to_string()),
            (None, _) => {
                let mut ldap = connect(cfg).await?;
                if cfg.user_dn_template.trim().is_empty() {
                    service_bind(&mut ldap, cfg).await?;
                }
                let _ = ldap.unbind().await;
                Ok(json!({"ok": true}))
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(20), fut).await.unwrap_or_else(|_| Err("The directory didn't answer in time.".into()))
}

/// Pick the mailbox address for a directory user. When an address was
/// typed it must be one of the entry's addresses.
pub fn mailbox_address(typed: &str, u: &DirUser) -> Option<String> {
    let typed = typed.trim().to_ascii_lowercase();
    if typed.contains('@') {
        u.emails.iter().find(|e| **e == typed).cloned()
    } else {
        u.emails.first().cloned()
    }
}

/// Find (or create) the mailbox for a verified directory user, enforce
/// required groups and sync the role.
pub async fn resolve_account(state: &State, cfg: &LdapSettings, typed: &str, u: &DirUser) -> Result<Account, AuthError> {
    let db = &state.db;
    let internal = |e: anyhow::Error| {
        tracing::error!("ldap: {e:#}");
        AuthError::Internal
    };
    let Some(email) = mailbox_address(typed, u) else {
        state.event("warn", "auth", &format!("directory sign-in as {typed:?}: entry {} has no matching {} address", u.dn, cfg.email_attr));
        return Err(AuthError::Invalid);
    };
    if !cfg.required_groups.is_empty() && !in_groups(&u.groups, &cfg.required_groups) {
        state.event("warn", "auth", &format!("directory sign-in refused for {email}: not in a required group"));
        return Err(AuthError::NotPermitted);
    }
    let want_admin = in_groups(&u.groups, &cfg.admin_groups);
    let mut a = match db.account_by_email(&email).await.map_err(internal)? {
        Some(a) => a,
        None if cfg.auto_create_accounts => {
            let domain = db.domain_by_name(crate::util::domain_of(&email)).await.map_err(internal)?;
            let Some(d) = domain.filter(|d| d.mode == "local" && d.active) else {
                state.event("warn", "auth", &format!("directory sign-in for {email}: not on a local mail domain"));
                return Err(AuthError::NotPermitted);
            };
            let quota = state.settings().limits.default_quota_mb as i64 * 1024 * 1024;
            let role = if !cfg.admin_groups.is_empty() && want_admin { "admin" } else { "user" };
            let id = db.create_account(&email, d.id, "!", u.name.as_deref().unwrap_or(""), role, quota).await.map_err(internal)?;
            state.event("info", "auth", &format!("created {email} on first directory sign-in"));
            db.get_account(id).await.map_err(internal)?.ok_or(AuthError::Internal)?
        }
        None => {
            state.event("warn", "auth", &format!("directory sign-in for {email}: no mailbox (create it, or turn on automatic creation)"));
            return Err(AuthError::Invalid);
        }
    };
    if !a.active {
        return Err(AuthError::Disabled);
    }
    if !cfg.admin_groups.is_empty() {
        let want = if want_admin { "admin" } else { "user" };
        let last_admin = a.is_admin() && db.count_admins().await.map_err(internal)? <= 1;
        if a.role != want && !(last_admin && want == "user") {
            db.set_role(a.id, want).await.map_err(internal)?;
            a.role = want.into();
        }
    }
    if a.display_name.is_empty() {
        if let Some(n) = &u.name {
            a.display_name = n.chars().take(200).collect();
            db.update_account(&a).await.map_err(internal)?;
        }
    }
    // Groups are only known when the directory is set up to report them;
    // LDAP returns no attribute when it's unset, so an empty value clears.
    let has_groups = !cfg.group_attr.trim().is_empty() || !cfg.group_base_dn.trim().is_empty();
    let details = u.details.iter().map(|(k, v)| (k.clone(), Some(v.clone()))).collect();
    crate::directory::sync(state, a.id, "ldap", has_groups.then_some(u.groups.as_slice()), &details).await;
    Ok(a)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn templates_escape() {
        let f = fill("(|(uid={user})(mail={user})(cn={local}))", "a*)(uid=*", "", filter_escape);
        assert_eq!(f, "(|(uid=a\\2a\\29\\28uid=\\2a)(mail=a\\2a\\29\\28uid=\\2a)(cn=a\\2a\\29\\28uid=\\2a))");
        let f = fill("(&(uid={local})(o={domain}))", "sam@example.com", "", filter_escape);
        assert_eq!(f, "(&(uid=sam)(o=example.com))");
        let d = fill("uid={user},ou=people,dc=x", "a,b=c", "", dn_value_escape);
        assert_eq!(d, "uid=a\\2cb\\3dc,ou=people,dc=x");
        let g = fill("(member={dn})", "x", "cn=a(b),dc=x", filter_escape);
        assert_eq!(g, "(member=cn=a\\28b\\29,dc=x)");
    }

    #[test]
    fn groups_match() {
        let g = vec!["cn=Mail Admins,ou=groups,dc=x".to_string(), "staff".to_string()];
        assert!(in_groups(&g, &["mail admins".into()]));
        assert!(in_groups(&g, &["CN=Mail Admins,ou=groups,dc=x".into()]));
        assert!(in_groups(&g, &["staff".into()]));
        assert!(!in_groups(&g, &["admins".into()]));
        assert!(!in_groups(&g, &["".into()]));
    }

    #[test]
    fn preset_filters_parse() {
        // Presets offered by the console (Access.svelte).
        for f in [
            "(&(objectClass=inetOrgPerson)(|(uid={user})(mail={user})))",
            "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(|(sAMAccountName={local})(userPrincipalName={user})(mail={user})))",
            "(&(objectClass=person)(|(uid={user})(mail={user})))",
            "(|(member={dn})(uniqueMember={dn}))",
        ] {
            let f = fill(f, "sam@example.com", "uid=sam,dc=x", filter_escape);
            assert!(ldap3::parse_filter(&f).is_ok(), "{f}");
        }
    }

    #[test]
    fn address_choice() {
        let u = DirUser { dn: "x".into(), emails: vec!["sam@a.test".into(), "s@b.test".into()], name: None, groups: vec![], details: Default::default() };
        assert_eq!(mailbox_address("sam", &u).as_deref(), Some("sam@a.test"));
        assert_eq!(mailbox_address("S@B.test", &u).as_deref(), Some("s@b.test"));
        assert_eq!(mailbox_address("other@a.test", &u), None);
    }
}
