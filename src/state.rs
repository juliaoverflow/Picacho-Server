use crate::auth::{CredCache, Limiter, SetupKey};
use crate::blob::BlobStore;
use crate::config::Config;
use crate::db::Db;
use crate::events::Hub;
use crate::net::Connections;
use crate::settings::{LiveSettings, SettingsBackend};
use crate::tls::Tls;
use parking_lot::RwLock;
use std::sync::Arc;
use tokio::sync::Notify;

pub struct AppState {
    pub config: Config,
    /// Where config.toml lives (it may not exist yet).
    pub config_path: std::path::PathBuf,
    /// Set when config.toml changed and a restart is needed to apply it.
    pub restart_required: std::sync::atomic::AtomicBool,
    pub db: Db,
    pub blobs: BlobStore,
    pub settings_backend: SettingsBackend,
    settings: RwLock<Arc<LiveSettings>>,
    pub limiter: Limiter,
    pub creds: CredCache,
    pub hub: Hub,
    pub conns: Arc<Connections>,
    pub tls: Tls,
    pub setup_key: Arc<SetupKey>,
    pub resolver: Option<mail_auth::MessageAuthenticator>,
    pub queue_wake: Notify,
    pub started: i64,
    /// Per-account IMAP session counts.
    pub imap_sessions: dashmap::DashMap<i64, usize>,
    /// Bound listeners, for the console.
    pub listeners: parking_lot::Mutex<Vec<serde_json::Value>>,
    /// Cancelled on SIGTERM/ctrl-c: listeners stop accepting, sessions wind down.
    pub shutdown: tokio_util::sync::CancellationToken,
    /// Sessions and deliveries in flight, awaited during shutdown.
    pub tasks: tokio_util::task::TaskTracker,
    /// Wakes relay peers' long-polls when mail is held for them.
    pub peer_wake: dashmap::DashMap<String, Arc<Notify>>,
    /// Pending ACME HTTP-01 challenges: token -> key authorization.
    pub acme_tokens: dashmap::DashMap<String, String>,
    /// WebDAV / CalDAV / CardDAV object stores.
    pub dav: crate::dav::Stores,
}

pub type State = Arc<AppState>;

impl AppState {
    pub async fn new(config: Config) -> anyhow::Result<State> {
        Self::with_path(config, "config.toml".into()).await
    }

    pub async fn with_path(config: Config, config_path: std::path::PathBuf) -> anyhow::Result<State> {
        let db = Db::connect(&config).await?;
        let blobs = BlobStore::new(&config, &db)?;
        let dav = crate::dav::Stores::new(&config, &db)?;
        let settings_backend = SettingsBackend::from_config(&config, &db);
        let live = settings_backend.load().await?;
        let hostname = live.server.hostname.clone().unwrap_or_else(|| config.default_hostname());
        let tls = crate::tls::load(&config, &hostname)?;
        if let Some(k) = config.kerberos.as_ref().filter(|k| k.enabled) {
            if let Err(e) = crate::gssapi::init(&k.keytab) {
                tracing::warn!("kerberos: {e:#}; GSSAPI won't be offered");
            }
        }
        let resolver = match config.dns.resolver.as_deref() {
            Some("cloudflare") => mail_auth::MessageAuthenticator::new_cloudflare().ok(),
            Some("google") => mail_auth::MessageAuthenticator::new_google().ok(),
            Some("quad9") => mail_auth::MessageAuthenticator::new_quad9().ok(),
            _ => mail_auth::MessageAuthenticator::new_system_conf()
                .ok()
                .or_else(|| mail_auth::MessageAuthenticator::new_cloudflare().ok()),
        };
        Ok(Arc::new(AppState {
            config,
            config_path,
            restart_required: Default::default(),
            db,
            blobs,
            settings_backend,
            settings: RwLock::new(Arc::new(live)),
            limiter: Limiter::default(),
            creds: CredCache::default(),
            hub: Hub::default(),
            conns: Arc::new(Connections::default()),
            tls,
            setup_key: SetupKey::new(),
            resolver,
            queue_wake: Notify::new(),
            started: crate::util::now(),
            imap_sessions: Default::default(),
            listeners: Default::default(),
            shutdown: Default::default(),
            tasks: Default::default(),
            peer_wake: Default::default(),
            acme_tokens: Default::default(),
            dav,
        }))
    }

    pub fn settings(&self) -> Arc<LiveSettings> {
        self.settings.read().clone()
    }

    pub async fn save_settings(&self, s: LiveSettings) -> anyhow::Result<()> {
        self.settings_backend.save(&s).await?;
        *self.settings.write() = Arc::new(s);
        Ok(())
    }

    pub fn hostname(&self) -> String {
        self.settings().server.hostname.clone().unwrap_or_else(|| self.config.default_hostname())
    }

    pub fn setup_required(&self) -> bool {
        !self.settings().server.setup_complete
    }

    /// Record an event for the console's activity log (and the tracing log).
    pub fn event(&self, level: &str, kind: &str, message: &str) {
        match level {
            "error" => tracing::error!(kind, "{message}"),
            "warn" => tracing::warn!(kind, "{message}"),
            _ => tracing::info!(kind, "{message}"),
        }
        let db = self.db.clone();
        let (l, k, m) = (level.to_string(), kind.to_string(), message.chars().take(2000).collect::<String>());
        tokio::spawn(async move {
            let _ = db.log_event(&l, &k, &m).await;
        });
    }
}
