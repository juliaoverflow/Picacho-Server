//! TLS for IMAP, SMTP, ManageSieve and the console. The certificate can be
//! replaced while running (ACME renewals, `watch_files`): every listener
//! shares one resolver whose key is swapped atomically.
//!
//! Precedence: an ACME certificate in `<data_dir>/tls/acme-*.pem`, then the
//! configured `[tls] cert/key`, then a generated self-signed certificate.
use crate::config::Config;
use anyhow::{Context, Result};
use parking_lot::RwLock;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;

#[derive(Debug)]
pub struct Resolver {
    current: RwLock<Arc<CertifiedKey>>,
}

impl ResolvesServerCert for Resolver {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.current.read().clone())
    }
}

pub struct Tls {
    pub acceptor: TlsAcceptor,
    pub self_signed: bool,
    pub cert_path: PathBuf,
    resolver: Arc<Resolver>,
    /// (cert, key) files being served, for change detection.
    files: RwLock<(PathBuf, PathBuf, Option<std::time::SystemTime>)>,
    pub source: RwLock<String>,
}

fn load_pair(cert: &Path, key: &Path) -> Result<CertifiedKey> {
    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut std::io::BufReader::new(std::fs::File::open(cert).with_context(|| format!("open {}", cert.display()))?))
            .collect::<Result<_, _>>()?;
    let key: PrivateKeyDer<'static> =
        rustls_pemfile::private_key(&mut std::io::BufReader::new(std::fs::File::open(key).with_context(|| format!("open {}", key.display()))?))?
            .context("no private key found")?;
    certified(certs, key)
}

fn certified(certs: Vec<CertificateDer<'static>>, key: PrivateKeyDer<'static>) -> Result<CertifiedKey> {
    if certs.is_empty() {
        anyhow::bail!("no certificates found");
    }
    let signing = rustls::crypto::ring::sign::any_supported_type(&key).map_err(|e| anyhow::anyhow!("unsupported private key: {e}"))?;
    Ok(CertifiedKey::new(certs, signing))
}

fn mtime(p: &Path) -> Option<std::time::SystemTime> {
    std::fs::metadata(p).and_then(|m| m.modified()).ok()
}

pub fn acme_paths(cfg: &Config) -> (PathBuf, PathBuf) {
    (cfg.data_path("tls/acme-cert.pem"), cfg.data_path("tls/acme-key.pem"))
}

pub fn load(cfg: &Config, hostname: &str) -> Result<Tls> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (acme_cert, acme_key) = acme_paths(cfg);
    let (cert_path, key_path, self_signed, source) = if cfg.tls.acme.is_some() && acme_cert.exists() && acme_key.exists() {
        (acme_cert, acme_key, false, "acme".to_string())
    } else {
        match (&cfg.tls.cert, &cfg.tls.key) {
            (Some(c), Some(k)) => (c.clone(), k.clone(), false, "files".to_string()),
            _ => {
                let dir = cfg.data_path("tls");
                std::fs::create_dir_all(&dir)?;
                let c = dir.join("cert.pem");
                let k = dir.join("key.pem");
                if !c.exists() || !k.exists() {
                    let mut names = vec![hostname.to_string(), "localhost".to_string()];
                    names.dedup();
                    let ck = rcgen::generate_simple_self_signed(names)?;
                    std::fs::write(&c, ck.cert.pem())?;
                    std::fs::write(&k, ck.signing_key.serialize_pem())?;
                    crate::util::restrict_permissions(&k);
                    tracing::warn!("generated a self-signed certificate at {}; configure [tls] cert/key or [tls.acme] for production", c.display());
                }
                (c, k, true, "self-signed".to_string())
            }
        }
    };
    let ck = load_pair(&cert_path, &key_path)?;
    let resolver = Arc::new(Resolver { current: RwLock::new(Arc::new(ck)) });
    let versions: &[&rustls::SupportedProtocolVersion] = match cfg.tls.min_version.as_deref() {
        Some("1.3") => &[&rustls::version::TLS13],
        _ => &[&rustls::version::TLS13, &rustls::version::TLS12],
    };
    let mut sc = rustls::ServerConfig::builder_with_protocol_versions(versions).with_no_client_auth().with_cert_resolver(resolver.clone());
    sc.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"imap".to_vec(), b"smtp".to_vec(), b"managesieve".to_vec()];
    let m = mtime(&cert_path);
    Ok(Tls {
        acceptor: TlsAcceptor::from(Arc::new(sc)),
        self_signed,
        cert_path: cert_path.clone(),
        resolver,
        files: RwLock::new((cert_path, key_path, m)),
        source: RwLock::new(source),
    })
}

impl Tls {
    /// Serve a new certificate from PEM text (ACME).
    pub fn install_pem(&self, chain_pem: &str, key_pem: &str) -> Result<()> {
        let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut chain_pem.as_bytes()).collect::<Result<_, _>>()?;
        let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())?.context("no private key")?;
        let ck = certified(certs, key)?;
        *self.resolver.current.write() = Arc::new(ck);
        *self.source.write() = "acme".into();
        Ok(())
    }

    /// Re-read the certificate files if they changed. Returns true on reload.
    pub fn reload_if_changed(&self) -> Result<bool> {
        let (c, k, old) = self.files.read().clone();
        let now = mtime(&c);
        if now.is_none() || now == old {
            return Ok(false);
        }
        let ck = load_pair(&c, &k)?;
        *self.resolver.current.write() = Arc::new(ck);
        self.files.write().2 = now;
        Ok(true)
    }

    /// Leaf certificate of what's being served.
    pub fn leaf(&self) -> Option<Vec<u8>> {
        self.resolver.current.read().cert.first().map(|c| c.to_vec())
    }

    /// Seconds until the served certificate expires (negative when expired).
    pub fn expires_in(&self) -> Option<i64> {
        let der = self.leaf()?;
        let (_, c) = x509_parser::parse_x509_certificate(&der).ok()?;
        Some(c.validity().not_after.timestamp() - crate::util::now())
    }

    pub fn names(&self) -> Vec<String> {
        let Some(der) = self.leaf() else { return vec![] };
        let Ok((_, c)) = x509_parser::parse_x509_certificate(&der) else { return vec![] };
        let mut out = vec![];
        if let Ok(Some(san)) = c.subject_alternative_name() {
            for n in &san.value.general_names {
                if let x509_parser::extensions::GeneralName::DNSName(d) = n {
                    out.push(d.to_string());
                }
            }
        }
        out
    }
}
