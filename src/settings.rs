//! Live settings: everything a postmaster can change from the web console
//! without a restart. Stored as JSON in the database (default) or as a TOML
//! file, according to `storage.settings` in config.toml.
use crate::config::{Config, SettingsKind};
use crate::db::Db;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(default)]
pub struct LiveSettings {
    pub server: ServerSettings,
    pub security: SecuritySettings,
    pub limits: LimitSettings,
    pub delivery: DeliverySettings,
    pub auth: AuthSettings,
    pub branding: Branding,
    pub filter: FilterSettings,
    pub reports: ReportSettings,
    pub retention: RetentionSettings,
    pub relay: RelaySettings,
    pub dav: DavSettings,
    pub directory: DirectorySettings,
}

/// The contact directory: a read-only address book (`addressbooks/<me>/directory/`)
/// listing the people each user may see, decided by group rules.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(default)]
pub struct DirectorySettings {
    pub enabled: bool,
    /// Members of these groups see everyone with every field (administrators always do).
    pub full_access_groups: Vec<String>,
    pub rules: Vec<DirectoryRule>,
}

/// Members of `viewers` see the members of `members` ("*" = everyone), with `fields`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(default)]
pub struct DirectoryRule {
    pub viewers: Vec<String>,
    pub members: Vec<String>,
    pub fields: Vec<String>,
}

/// A contact field filled from an identity-provider claim (or LDAP attribute).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(default)]
pub struct ProfileClaim {
    /// One of `crate::directory::PROFILE_FIELDS`.
    pub field: String,
    /// Claim name; dotted paths reach into objects ("attributes.title").
    pub claim: String,
}

fn default_profile_claims() -> Vec<ProfileClaim> {
    [("phone", "phone_number"), ("given_name", "given_name"), ("family_name", "family_name"), ("nickname", "nickname"), ("photo", "picture"), ("address", "address"), ("website", "website"), ("birthday", "birthdate")]
        .iter()
        .map(|(f, c)| ProfileClaim { field: f.to_string(), claim: c.to_string() })
        .collect()
}

/// Inbound content filtering: built-in scoring, Bayes, rspamd, ClamAV and
/// greylisting. Scores add up; thresholds decide what happens.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct FilterSettings {
    pub enabled: bool,
    /// At or above: add X-Spam-Flag and file in Junk.
    pub junk_score: f64,
    /// At or above: reject during SMTP (550).
    pub reject_score: f64,
    /// Add X-Spam-Score/X-Spam-Report headers to every scanned message.
    pub add_headers: bool,
    /// Also scan mail from authenticated users (outbound abuse protection).
    pub scan_outbound: bool,
    /// Built-in Bayesian classifier, trained when people move mail to and from Junk.
    pub bayes: bool,
    /// Messages of each class seen before Bayes starts scoring.
    pub bayes_min_learns: i64,
    /// Bayes contribution at probability 1.0 (scaled down linearly from 0.5).
    pub bayes_weight: f64,
    /// URI block lists (domain-based, e.g. dbl.spamhaus.org, multi.surbl.org).
    pub uribl: Vec<String>,
    /// DNS block lists that add `dnsbl_score` instead of rejecting.
    pub dnsbl: Vec<String>,
    /// Score added when the client IP is on one of `dnsbl`.
    pub dnsbl_score: f64,
    /// Custom header/body rules.
    pub rules: Vec<FilterRule>,
    /// Sender addresses or domains never treated as spam.
    pub allow_senders: Vec<String>,
    /// Sender addresses or domains always treated as spam.
    pub block_senders: Vec<String>,
    pub rspamd: Option<RspamdSettings>,
    pub clamav: Option<ClamavSettings>,
    pub greylist: GreylistSettings,
    /// Reject attachments with these extensions (exe, scr, js, ...).
    pub blocked_extensions: Vec<String>,
}

impl Default for FilterSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            junk_score: 5.0,
            reject_score: 15.0,
            add_headers: true,
            scan_outbound: false,
            bayes: true,
            bayes_min_learns: 50,
            bayes_weight: 4.0,
            uribl: vec![],
            dnsbl: vec![],
            dnsbl_score: 4.0,
            rules: vec![],
            allow_senders: vec![],
            block_senders: vec![],
            rspamd: None,
            clamav: None,
            greylist: GreylistSettings::default(),
            blocked_extensions: ["exe", "scr", "pif", "bat", "cmd", "com", "cpl", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "msi", "jar", "lnk", "iso", "img"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        }
    }
}

/// A scoring rule. `field` is a header name, or "body", "subject", "from",
/// "to", "raw". `pattern` is a case-insensitive regular expression.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(default)]
pub struct FilterRule {
    pub name: String,
    pub field: String,
    pub pattern: String,
    pub score: f64,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct RspamdSettings {
    /// Controller/normal worker URL, e.g. http://127.0.0.1:11333
    pub url: String,
    pub password: Option<String>,
    /// Use rspamd's action (reject/add header/greylist) instead of only adding its score.
    pub use_action: bool,
    pub timeout_secs: u64,
}

impl Default for RspamdSettings {
    fn default() -> Self {
        Self { url: "http://127.0.0.1:11333".into(), password: None, use_action: true, timeout_secs: 15 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct ClamavSettings {
    /// "127.0.0.1:3310" or "unix:/run/clamav/clamd.ctl"
    pub address: String,
    /// When clamd is unreachable: "accept" or "tempfail".
    pub on_error: String,
    pub timeout_secs: u64,
}

impl Default for ClamavSettings {
    fn default() -> Self {
        Self { address: "127.0.0.1:3310".into(), on_error: "accept".into(), timeout_secs: 30 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct GreylistSettings {
    pub enabled: bool,
    /// Seconds a new (ip/24, sender, recipient) triplet must wait.
    pub delay_secs: i64,
    /// Forget unconfirmed triplets after this long.
    pub retry_window_hours: i64,
    /// Keep passed triplets this long.
    pub pass_days: i64,
    /// Only greylist mail scoring at least this much (0 = everything).
    pub min_score: f64,
}

impl Default for GreylistSettings {
    fn default() -> Self {
        Self { enabled: false, delay_secs: 300, retry_window_hours: 24, pass_days: 36, min_score: 0.0 }
    }
}

/// DMARC aggregate and SMTP TLS reports.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct ReportSettings {
    /// Send DMARC aggregate reports to domains that ask for them (rua).
    pub send_dmarc: bool,
    /// Send SMTP TLS reports (RFC 8460) to domains that ask for them.
    pub send_tls: bool,
    /// Parse DMARC/TLS reports arriving at these local addresses and keep
    /// them for the console (they are still delivered).
    pub ingest_addresses: Vec<String>,
    /// Organization name in outgoing reports (defaults to the host name).
    pub org_name: Option<String>,
    /// Contact address in outgoing reports (defaults to postmaster@primary).
    pub contact: Option<String>,
}

impl Default for ReportSettings {
    fn default() -> Self {
        Self { send_dmarc: false, send_tls: false, ingest_addresses: vec![], org_name: None, contact: None }
    }
}

/// Automatic clean-up.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct RetentionSettings {
    /// Expunge Trash messages older than this many days (0 = keep).
    pub trash_days: u32,
    /// Expunge Junk messages older than this many days (0 = keep).
    pub junk_days: u32,
    /// Per-folder rules applied to every account, by folder name or special-use.
    pub rules: Vec<RetentionRule>,
    /// Keep the audit log this many days.
    pub audit_days: u32,
    /// Delete stored objects nothing refers to (after this many hours).
    pub orphan_grace_hours: u32,
}

impl Default for RetentionSettings {
    fn default() -> Self {
        Self { trash_days: 30, junk_days: 30, rules: vec![], audit_days: 365, orphan_grace_hours: 24 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(default)]
pub struct RetentionRule {
    /// Folder name ("Archive/2019") or special use ("\\Sent").
    pub folder: String,
    pub days: u32,
}

/// Picacho-to-Picacho relaying over HTTPS, for servers that cannot use port 25.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct RelaySettings {
    /// Downstream side: connect to an upstream Picacho server.
    pub upstream: Option<UpstreamRelay>,
    /// Upstream side: accept downstream Picacho servers.
    pub accept_downstream: bool,
}

impl Default for RelaySettings {
    fn default() -> Self {
        Self { upstream: None, accept_downstream: false }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(default)]
pub struct UpstreamRelay {
    pub enabled: bool,
    /// Base URL of the upstream console/API, e.g. https://mx.example.net:8080
    pub url: String,
    /// Relay token issued by the upstream (pmk_… with the `relay` scope).
    pub token: Option<String>,
    /// Send outbound mail through the upstream.
    pub outbound: bool,
    /// Pull mail the upstream received for our domains.
    pub inbound: bool,
    /// Accept invalid upstream certificates (testing only).
    pub insecure: bool,
}

/// WebDAV, CalDAV and CardDAV.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct DavSettings {
    pub enabled: bool,
    /// Give every mail account a DAV principal automatically.
    pub mail_accounts: bool,
    /// Default WebDAV file quota for new DAV principals in MiB (0 = unlimited).
    pub default_quota_mb: u64,
    /// Largest single uploaded file.
    pub max_resource_bytes: u64,
    /// Create a default calendar and address book for new principals.
    pub create_defaults: bool,
    /// Let calendar apps look up when other people on this server are busy
    /// (RFC 6638 free/busy; times only, never what the events are).
    pub free_busy_lookup: bool,
    /// Send invitations, updates, cancellations and answers when people
    /// save events (RFC 6638 implicit scheduling): to mailboxes here
    /// directly, to everyone else by email from the organizer's address.
    pub server_scheduling: bool,
}

impl Default for DavSettings {
    fn default() -> Self {
        Self { enabled: true, mail_accounts: true, default_quota_mb: 10 * 1024, max_resource_bytes: 1024 * 1024 * 1024, create_defaults: true, free_busy_lookup: true, server_scheduling: false }
    }
}

/// How people sign in.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct AuthSettings {
    /// Email + password sign-in to the web console. Can be forced back on
    /// with PICACHO_ALLOW_PASSWORD_LOGIN=1 (break-glass).
    pub web_password_login: bool,
    /// Account passwords for IMAP, SMTP and JMAP Basic. When off, mail apps
    /// need an app password or an OAuth token.
    pub mail_password_login: bool,
    pub oidc: OidcSettings,
    pub ldap: LdapSettings,
}

impl Default for AuthSettings {
    fn default() -> Self {
        Self { web_password_login: true, mail_password_login: true, oidc: OidcSettings::default(), ldap: LdapSettings::default() }
    }
}

impl AuthSettings {
    /// Directory passwords for the web console.
    pub fn ldap_web(&self) -> bool {
        self.ldap.enabled && self.ldap.web_login
    }

    /// Directory passwords for IMAP, SMTP, JMAP, DAV and ManageSieve.
    pub fn ldap_mail(&self) -> bool {
        self.ldap.enabled && self.ldap.mail_login
    }
}

/// Passwords checked against an LDAP directory (OpenLDAP, Active Directory,
/// FreeIPA, LLDAP, …). Works next to local passwords, single sign-on and
/// access tokens: a mailbox that signs in to the console with SSO can use
/// its directory password in mail apps.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct LdapSettings {
    pub enabled: bool,
    /// Shown on the sign-in page: "Use your {display_name} account".
    pub display_name: String,
    /// ldaps://host:636, ldap://host:389 or ldapi://%2Frun%2Fslapd%2Fldapi
    pub url: String,
    /// Upgrade ldap:// with StartTLS.
    pub starttls: bool,
    /// Allow ldap:// without StartTLS to a non-local host (passwords travel in clear).
    pub allow_plaintext: bool,
    /// Don't verify the directory's certificate (testing only).
    pub tls_skip_verify: bool,
    /// Extra trusted CA certificates (PEM) for a private directory CA.
    pub ca_cert: String,
    /// Service account used to find users. Empty: anonymous search.
    pub bind_dn: String,
    pub bind_password: Option<String>,
    /// Bind directly as the user instead of searching first, e.g.
    /// "uid={user},ou=people,dc=example,dc=com" or "{user}@corp.example.com".
    pub user_dn_template: String,
    /// Where users live.
    pub base_dn: String,
    /// Finds the user. Placeholders: {user} (as typed), {local} and {domain}
    /// (parts of an email address); values are escaped.
    pub user_filter: String,
    /// Attribute with the user's mailbox address(es).
    pub email_attr: String,
    /// Attribute with the display name (falls back to cn).
    pub name_attr: String,
    /// Attribute on the user listing group DNs (memberOf). Empty: none.
    pub group_attr: String,
    /// Also search for groups here (empty: only `group_attr`).
    pub group_base_dn: String,
    /// Placeholders: {dn} (the user's DN), {user}, {local}.
    pub group_filter: String,
    pub group_name_attr: String,
    /// Members of these groups (name or DN) are administrators, others
    /// users. Empty: roles are managed here.
    pub admin_groups: Vec<String>,
    /// Only members of these groups may sign in (empty: anyone found).
    pub required_groups: Vec<String>,
    /// Contact details read from directory attributes (claim = attribute name).
    pub profile_attributes: Vec<ProfileClaim>,
    /// Create the mailbox on first sign-in when its address is on a local domain.
    pub auto_create_accounts: bool,
    /// Accept directory passwords in the web console.
    pub web_login: bool,
    /// Accept directory passwords in mail, calendar and contacts apps.
    pub mail_login: bool,
}

impl Default for LdapSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            display_name: "Directory".into(),
            url: String::new(),
            starttls: false,
            allow_plaintext: false,
            tls_skip_verify: false,
            ca_cert: String::new(),
            bind_dn: String::new(),
            bind_password: None,
            user_dn_template: String::new(),
            base_dn: String::new(),
            user_filter: "(&(objectClass=person)(|(uid={user})(mail={user})))".into(),
            email_attr: "mail".into(),
            name_attr: "displayName".into(),
            group_attr: "memberOf".into(),
            group_base_dn: String::new(),
            group_filter: "(|(member={dn})(uniqueMember={dn}))".into(),
            group_name_attr: "cn".into(),
            admin_groups: vec![],
            required_groups: vec![],
            profile_attributes: vec![],
            auto_create_accounts: false,
            web_login: true,
            mail_login: true,
        }
    }
}

impl LdapSettings {
    pub fn validate(&self) -> Result<(), String> {
        let u = url::Url::parse(self.url.trim()).map_err(|_| "Enter the directory URL, like ldaps://ldap.example.com.".to_string())?;
        match u.scheme() {
            "ldaps" | "ldapi" => {}
            "ldap" => {
                let local = matches!(u.host_str(), Some("localhost" | "127.0.0.1" | "[::1]" | "::1"));
                if !self.starttls && !self.allow_plaintext && !local {
                    return Err("Use ldaps:// or StartTLS, or explicitly allow unencrypted LDAP; passwords would travel in clear.".into());
                }
            }
            _ => return Err("The directory URL must start with ldap://, ldaps:// or ldapi://.".into()),
        }
        if self.starttls && u.scheme() != "ldap" {
            return Err("StartTLS is only for ldap:// URLs.".into());
        }
        let direct = !self.user_dn_template.trim().is_empty();
        if direct && !self.user_dn_template.contains("{user}") && !self.user_dn_template.contains("{local}") {
            return Err("The user DN template needs {user} or {local}.".into());
        }
        if self.base_dn.trim().is_empty() {
            return Err("Enter the base DN where users live.".into());
        }
        if !direct && !self.bind_dn.trim().is_empty() && self.bind_password.as_deref().unwrap_or("").is_empty() {
            return Err("Enter the service account's password.".into());
        }
        if !["{user}", "{local}", "{domain}"].iter().any(|p| self.user_filter.contains(p)) {
            return Err("The user filter needs {user} (or {local}).".into());
        }
        let probe = |f: &str| f.replace("{user}", "x").replace("{local}", "x").replace("{domain}", "x").replace("{dn}", "x");
        if ldap3::parse_filter(probe(self.user_filter.trim())).is_err() {
            return Err("The user filter isn't a valid LDAP filter.".into());
        }
        if !self.group_base_dn.trim().is_empty() && ldap3::parse_filter(probe(self.group_filter.trim())).is_err() {
            return Err("The group filter isn't a valid LDAP filter.".into());
        }
        if self.email_attr.trim().is_empty() {
            return Err("Enter the attribute holding email addresses (usually mail).".into());
        }
        if !self.ca_cert.trim().is_empty() && rustls_pemfile::certs(&mut self.ca_cert.as_bytes()).filter_map(Result::ok).next().is_none() {
            return Err("The CA certificate must be PEM (-----BEGIN CERTIFICATE-----).".into());
        }
        if !self.web_login && !self.mail_login {
            return Err("Use the directory for the console, for apps, or both.".into());
        }
        Ok(())
    }

    /// Changes whenever any setting does, so cached logins don't outlive a reconfiguration.
    pub fn fingerprint(&self) -> String {
        format!("ldap:{}", crate::util::sha256_hex(serde_json::to_string(self).unwrap_or_default().as_bytes()))
    }
}

/// OpenID Connect single sign-on for the web console.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct OidcSettings {
    pub enabled: bool,
    /// Button label: "Sign in with {display_name}".
    pub display_name: String,
    /// Issuer URL; discovery is at {issuer}/.well-known/openid-configuration.
    pub issuer: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub scopes: String,
    /// Claim holding the user's email address.
    pub email_claim: String,
    /// Claim with group names (for admin mapping).
    pub groups_claim: String,
    /// Members of these groups are administrators (empty: roles aren't synced).
    pub admin_groups: Vec<String>,
    /// Contact details (phone, title, ...) read from claims at every sign-in.
    pub profile_claims: Vec<ProfileClaim>,
    /// Access tokens issued to these client IDs (`client_id`/`azp`) carry the
    /// full groups claim, so an empty one there clears groups. Tokens for other
    /// apps only ever add groups and details.
    pub token_groups_clients: Vec<String>,
    /// Only these email domains may sign in (empty: any).
    pub allowed_domains: Vec<String>,
    /// Create an account on first sign-in when the email is on a local domain.
    pub auto_create_accounts: bool,
    /// Refuse identities whose email_verified claim is false.
    pub require_verified_email: bool,
    /// Accept the provider's OAuth access tokens (JWTs signed with its JWKS)
    /// for IMAP, SMTP, JMAP, DAV, ManageSieve and the REST APIs. The provider
    /// is the only authorization server; this server never issues tokens.
    pub access_tokens: bool,
    /// This server's resource identifier (RFC 8707): tokens must carry it in
    /// `aud`. Apps request it with `resource=`.
    pub resource: String,
}

impl Default for OidcSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            display_name: "SSO".into(),
            issuer: String::new(),
            client_id: String::new(),
            client_secret: None,
            scopes: "openid email profile".into(),
            email_claim: "email".into(),
            groups_claim: "groups".into(),
            admin_groups: vec![],
            profile_claims: default_profile_claims(),
            token_groups_clients: vec![],
            allowed_domains: vec![],
            auto_create_accounts: false,
            require_verified_email: true,
            access_tokens: false,
            resource: String::new(),
        }
    }
}

/// Look and feel of the console, sign-in and consent pages.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(default)]
pub struct Branding {
    /// Product name shown instead of "Picacho Server".
    pub name: Option<String>,
    /// Logo as a data: URL (PNG, JPEG, WebP, GIF or SVG; at most 256 KiB).
    pub logo: Option<String>,
    /// Accent color, #rrggbb.
    pub accent: Option<String>,
    /// Shown on the sign-in page.
    pub login_message: Option<String>,
    pub support_url: Option<String>,
    pub support_email: Option<String>,
    pub hide_powered_by: bool,
}

impl Branding {
    pub fn validate(&self) -> Result<(), String> {
        if let Some(n) = &self.name {
            if n.chars().count() > 60 || n.chars().any(|c| c.is_control()) {
                return Err("Brand name must be at most 60 characters.".into());
            }
        }
        if let Some(l) = &self.logo {
            const OK: [&str; 5] = ["data:image/png;base64,", "data:image/jpeg;base64,", "data:image/webp;base64,", "data:image/gif;base64,", "data:image/svg+xml;base64,"];
            if !OK.iter().any(|p| l.starts_with(p)) {
                return Err("Logo must be a PNG, JPEG, WebP, GIF or SVG image.".into());
            }
            if l.len() > 350_000 {
                return Err("Logo must be 256 KB or smaller.".into());
            }
        }
        if let Some(a) = &self.accent {
            if !(a.len() == 7 && a.starts_with('#') && a[1..].chars().all(|c| c.is_ascii_hexdigit())) {
                return Err("Accent color must look like #2a7650.".into());
            }
        }
        if let Some(u) = &self.support_url {
            if !u.is_empty() && !u.starts_with("https://") && !u.starts_with("http://") {
                return Err("Support link must be an http(s) URL.".into());
            }
        }
        if let Some(m) = &self.login_message {
            if m.len() > 1000 {
                return Err("Sign-in message is too long.".into());
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(default)]
pub struct ServerSettings {
    /// Overrides config.toml / system host name when set.
    pub hostname: Option<String>,
    /// Primary mail domain, used for postmaster@ and bounces.
    pub primary_domain: Option<String>,
    /// Text after the host name in SMTP/IMAP greetings.
    pub greeting: Option<String>,
    pub setup_complete: bool,
    /// MTA-STS policy served at mta-sts.<domain>: "testing" (default),
    /// "enforce", "none" or "off" (don't serve).
    pub mta_sts_mode: Option<String>,
    /// Extra MX names for the MTA-STS policy (backup MX, relay upstream).
    pub mta_sts_mx: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct SecuritySettings {
    /// Refuse AUTH/LOGIN on connections without TLS (localhost excepted).
    pub require_tls_for_auth: bool,
    /// Allow plaintext auth from 127.0.0.1/::1 (useful for tests and local tools).
    pub allow_plaintext_localhost: bool,
    /// Failed logins from one address before it is banned.
    pub max_auth_failures: u32,
    pub auth_failure_window_secs: u64,
    pub ban_secs: u64,
    /// Authenticated users may only send from their own addresses/aliases.
    pub enforce_sender_ownership: bool,
    pub password_min_length: usize,
    /// Check SPF, DKIM and DMARC on inbound mail and record the results.
    pub verify_inbound: bool,
    /// Reject inbound mail whose DMARC result is fail with p=reject.
    pub honor_dmarc_reject: bool,
    /// File messages failing DMARC (p=quarantine) in Junk.
    pub quarantine_to_junk: bool,
    /// DNS block lists checked for inbound connections (e.g. zen.spamhaus.org).
    pub dnsbl: Vec<String>,
    /// Require reverse DNS on connecting MX clients.
    pub require_rdns: bool,
    /// Addresses never banned (CIDR or exact IP).
    pub allowlist: Vec<String>,
}

impl Default for SecuritySettings {
    fn default() -> Self {
        Self {
            require_tls_for_auth: true,
            allow_plaintext_localhost: true,
            max_auth_failures: 10,
            auth_failure_window_secs: 600,
            ban_secs: 3600,
            enforce_sender_ownership: true,
            password_min_length: 10,
            verify_inbound: true,
            honor_dmarc_reject: true,
            quarantine_to_junk: true,
            dnsbl: vec![],
            require_rdns: false,
            allowlist: vec![],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct LimitSettings {
    pub max_message_bytes: u64,
    pub max_recipients: usize,
    /// Default mailbox quota for new accounts in MiB (0 = unlimited).
    pub default_quota_mb: u64,
    /// Messages a user may submit per hour (0 = unlimited).
    pub send_rate_per_hour: u32,
    pub max_imap_sessions_per_user: usize,
    /// How far ahead a submission may be held for sending later (SMTP
    /// FUTURERELEASE, JMAP HOLDUNTIL), in days (0 = never held).
    pub max_hold_days: u32,
}

impl Default for LimitSettings {
    fn default() -> Self {
        Self {
            max_message_bytes: 50 * 1024 * 1024,
            max_recipients: 100,
            default_quota_mb: 5 * 1024,
            send_rate_per_hour: 500,
            max_imap_sessions_per_user: 50,
            max_hold_days: 31,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct DeliverySettings {
    /// Named outbound transports (smarthosts, webhooks, direct MX).
    pub transports: Vec<Transport>,
    /// Domain patterns to transport ids; first match wins. With no match,
    /// mail goes out by direct MX delivery.
    pub routes: Vec<Route>,
    /// Minutes between attempts; the last value repeats.
    pub retry_minutes: Vec<u64>,
    /// Give up and bounce after this many hours.
    pub max_queue_hours: u64,
    pub send_bounces: bool,
    /// Refuse to deliver over unencrypted connections (direct MX).
    pub require_tls: bool,
    /// Parallel outbound deliveries.
    pub concurrency: usize,
    /// DKIM-sign outbound mail for domains with keys.
    pub dkim_sign: bool,
    /// Honor recipient domains' MTA-STS policies (RFC 8461).
    pub mta_sts: bool,
    /// Authenticate MX hosts with DNSSEC-signed TLSA records (RFC 7672).
    pub dane: bool,
    /// ARC-seal messages forwarded to other servers (RFC 8617).
    pub arc_seal: bool,
}

impl Default for DeliverySettings {
    fn default() -> Self {
        Self {
            transports: vec![],
            routes: vec![],
            retry_minutes: vec![1, 5, 15, 30, 60, 120, 240, 480],
            max_queue_hours: 120,
            send_bounces: true,
            require_tls: false,
            concurrency: 16,
            dkim_sign: true,
            mta_sts: true,
            dane: true,
            arc_seal: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum TransportKind {
    /// Look up MX records and deliver directly.
    #[default]
    Direct,
    /// Hand off to an SMTP relay (SES, SendGrid, Mailgun, Postmark, an ISP, another MTA).
    Smtp,
    /// POST the message to an HTTP endpoint.
    Webhook,
    /// Hand off to an upstream Picacho Server server over HTTPS (relay link).
    Picacho,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum TlsMode {
    /// Use STARTTLS when offered.
    #[default]
    Opportunistic,
    /// Require STARTTLS.
    Starttls,
    /// Implicit TLS (port 465).
    Tls,
    /// No TLS at all (trusted networks only).
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(default)]
pub struct Transport {
    pub id: String,
    pub name: String,
    pub kind: TransportKind,
    pub host: String,
    pub port: u16,
    pub tls: TlsMode,
    pub username: Option<String>,
    pub password: Option<String>,
    /// Webhook URL.
    pub url: Option<String>,
    /// Webhook HMAC-SHA256 signing secret (sent as X-Picacho-Signature).
    pub secret: Option<String>,
    /// Webhook body format: "json" (default) or "raw" (message/rfc822).
    pub format: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(default)]
pub struct Route {
    /// "*", "example.com" or "*.example.com".
    pub pattern: String,
    pub transport: String,
}

impl Route {
    pub fn matches(&self, domain: &str) -> bool {
        let p = self.pattern.trim().to_ascii_lowercase();
        let d = domain.to_ascii_lowercase();
        if p == "*" {
            return true;
        }
        if let Some(suffix) = p.strip_prefix("*.") {
            return d.ends_with(&format!(".{suffix}")) || d == suffix;
        }
        p == d
    }
}

impl LiveSettings {
    pub fn transport(&self, id: &str) -> Option<&Transport> {
        self.delivery.transports.iter().find(|t| t.id == id)
    }

    /// Copy with secrets replaced by a marker for display.
    pub fn redacted(&self) -> Self {
        let mut s = self.clone();
        if s.auth.oidc.client_secret.as_deref().is_some_and(|p| !p.is_empty()) {
            s.auth.oidc.client_secret = Some(REDACTED.into());
        }
        if s.auth.ldap.bind_password.as_deref().is_some_and(|p| !p.is_empty()) {
            s.auth.ldap.bind_password = Some(REDACTED.into());
        }
        if let Some(r) = &mut s.filter.rspamd {
            if r.password.as_deref().is_some_and(|p| !p.is_empty()) {
                r.password = Some(REDACTED.into());
            }
        }
        if let Some(u) = &mut s.relay.upstream {
            if u.token.as_deref().is_some_and(|p| !p.is_empty()) {
                u.token = Some(REDACTED.into());
            }
        }
        for t in &mut s.delivery.transports {
            if t.password.as_deref().is_some_and(|p| !p.is_empty()) {
                t.password = Some(REDACTED.into());
            }
            if t.secret.as_deref().is_some_and(|p| !p.is_empty()) {
                t.secret = Some(REDACTED.into());
            }
        }
        s
    }

    /// Accept an update from the console, keeping secrets the console only
    /// saw redacted.
    pub fn merge_secrets_from(&mut self, old: &LiveSettings) {
        if self.auth.oidc.client_secret.as_deref() == Some(REDACTED) {
            self.auth.oidc.client_secret = old.auth.oidc.client_secret.clone();
        }
        if self.auth.ldap.bind_password.as_deref() == Some(REDACTED) {
            self.auth.ldap.bind_password = old.auth.ldap.bind_password.clone();
        }
        if let Some(r) = &mut self.filter.rspamd {
            if r.password.as_deref() == Some(REDACTED) {
                r.password = old.filter.rspamd.as_ref().and_then(|o| o.password.clone());
            }
        }
        if let Some(u) = &mut self.relay.upstream {
            if u.token.as_deref() == Some(REDACTED) {
                u.token = old.relay.upstream.as_ref().and_then(|o| o.token.clone());
            }
        }
        for t in &mut self.delivery.transports {
            let prev = old.delivery.transports.iter().find(|o| o.id == t.id);
            if t.password.as_deref() == Some(REDACTED) {
                t.password = prev.and_then(|p| p.password.clone());
            }
            if t.secret.as_deref() == Some(REDACTED) {
                t.secret = prev.and_then(|p| p.secret.clone());
            }
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        let mut ids = std::collections::HashSet::new();
        for t in &self.delivery.transports {
            if t.id.is_empty() || !t.id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
                return Err(format!("transport id '{}' must be letters, digits, - or _", t.id));
            }
            if !ids.insert(&t.id) {
                return Err(format!("duplicate transport id '{}'", t.id));
            }
            match t.kind {
                TransportKind::Smtp if t.host.trim().is_empty() => {
                    return Err(format!("transport '{}' needs a host", t.id))
                }
                TransportKind::Webhook => {
                    let url = t.url.as_deref().unwrap_or("");
                    if !(url.starts_with("https://") || url.starts_with("http://")) {
                        return Err(format!("transport '{}' needs an http(s) URL", t.id));
                    }
                }
                _ => {}
            }
        }
        for r in &self.delivery.routes {
            if !ids.contains(&r.transport) {
                return Err(format!("route '{}' uses unknown transport '{}'", r.pattern, r.transport));
            }
        }
        if self.limits.max_message_bytes < 1024 {
            return Err("max message size is too small".into());
        }
        if self.security.password_min_length < 8 {
            return Err("minimum password length must be at least 8".into());
        }
        self.branding.validate()?;
        let o = &self.auth.oidc;
        if o.enabled {
            if !(o.issuer.starts_with("https://") || is_local_http(&o.issuer)) {
                return Err("The OIDC issuer must be an https:// URL.".into());
            }
            if o.client_id.trim().is_empty() {
                return Err("The OIDC client ID is required.".into());
            }
        }
        if self.auth.ldap.enabled {
            self.auth.ldap.validate()?;
        }
        for m in o.profile_claims.iter().chain(&self.auth.ldap.profile_attributes) {
            if !crate::directory::PROFILE_FIELDS.contains(&m.field.as_str()) {
                return Err(format!("'{}' isn't a contact field.", m.field));
            }
            if m.claim.trim().is_empty() {
                return Err(format!("Enter the claim or attribute for {}.", m.field));
            }
        }
        for r in &self.directory.rules {
            if r.viewers.iter().all(|g| g.trim().is_empty()) || r.members.iter().all(|g| g.trim().is_empty()) {
                return Err("Each directory rule needs viewer and member groups.".into());
            }
            if let Some(f) = r.fields.iter().find(|f| !crate::directory::is_field(f)) {
                return Err(format!("'{f}' isn't a directory field."));
            }
        }
        if !self.auth.web_password_login && !o.enabled && !self.auth.ldap_web() {
            return Err("Turn on single sign-on or directory sign-in before turning off password sign-in.".into());
        }
        if o.access_tokens {
            if !(o.issuer.starts_with("https://") || is_local_http(&o.issuer)) {
                return Err("Accepting access tokens needs the identity provider's issuer URL.".into());
            }
            if url::Url::parse(o.resource.trim()).is_err() {
                return Err("Set this server's resource identifier (an absolute URL) to accept access tokens.".into());
            }
        }
        if self.delivery.retry_minutes.is_empty() {
            return Err("retry schedule needs at least one value".into());
        }
        let f = &self.filter;
        if f.junk_score <= 0.0 || f.reject_score <= f.junk_score {
            return Err("The reject score must be higher than the junk score, and both above zero.".into());
        }
        for r in &f.rules {
            if r.field.trim().is_empty() {
                return Err(format!("filter rule '{}' needs a field", r.name));
            }
            if let Err(e) = regex::RegexBuilder::new(&r.pattern).case_insensitive(true).size_limit(1 << 20).build() {
                return Err(format!("filter rule '{}': {e}", r.name));
            }
        }
        if let Some(r) = &f.rspamd {
            if !(r.url.starts_with("http://") || r.url.starts_with("https://")) {
                return Err("The rspamd URL must be http(s).".into());
            }
        }
        if let Some(u) = &self.relay.upstream {
            if u.enabled && !(u.url.starts_with("https://") || is_local_http(&u.url) || u.insecure) {
                return Err("The upstream relay URL must be https://.".into());
            }
        }
        for t in &self.delivery.transports {
            if t.kind == TransportKind::Picacho {
                let url = t.url.as_deref().unwrap_or("");
                if !(url.starts_with("https://") || is_local_http(url)) {
                    return Err(format!("transport '{}' needs the upstream's https:// URL", t.id));
                }
            }
        }
        Ok(())
    }
}

pub const REDACTED: &str = "••••••••";

/// Where live settings are persisted.
#[derive(Clone)]
pub enum SettingsBackend {
    Database(Db),
    File(PathBuf),
}

impl SettingsBackend {
    pub fn from_config(cfg: &Config, db: &Db) -> Self {
        match cfg.storage.settings.kind {
            SettingsKind::Database => SettingsBackend::Database(db.clone()),
            SettingsKind::File => SettingsBackend::File(
                cfg.storage.settings.path.clone().unwrap_or_else(|| cfg.data_path("live.toml")),
            ),
        }
    }

    pub fn describe(&self) -> String {
        match self {
            SettingsBackend::Database(_) => "database".into(),
            SettingsBackend::File(p) => format!("file: {}", p.display()),
        }
    }

    pub async fn load(&self) -> anyhow::Result<LiveSettings> {
        match self {
            SettingsBackend::Database(db) => match db.get_setting("live").await? {
                Some(json) => Ok(serde_json::from_str(&json)?),
                None => Ok(LiveSettings::default()),
            },
            SettingsBackend::File(p) => {
                if !p.exists() {
                    return Ok(LiveSettings::default());
                }
                let text = tokio::fs::read_to_string(p).await?;
                Ok(toml::from_str(&text)?)
            }
        }
    }

    pub async fn save(&self, s: &LiveSettings) -> anyhow::Result<()> {
        match self {
            SettingsBackend::Database(db) => db.set_setting("live", &serde_json::to_string(s)?).await,
            SettingsBackend::File(p) => {
                if let Some(dir) = p.parent() {
                    tokio::fs::create_dir_all(dir).await?;
                }
                let text = toml::to_string_pretty(s)?;
                let tmp = p.with_extension("tmp");
                tokio::fs::write(&tmp, text).await?;
                crate::util::restrict_permissions(&tmp);
                tokio::fs::rename(&tmp, p).await?;
                Ok(())
            }
        }
    }
}

/// http:// is accepted only for local test identity providers.
pub fn is_local_http(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("http://") else { return false };
    let host = rest.split(['/', ':']).next().unwrap_or("");
    host == "localhost" || host == "127.0.0.1" || host == "[::1]" || host.ends_with(".localhost")
}
