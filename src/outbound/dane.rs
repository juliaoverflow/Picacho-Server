//! DANE for SMTP (RFC 7672): DNSSEC-validated TLSA records authenticate MX
//! hosts without relying on public certificate authorities.
use hickory_resolver::proto::dnssec::Proof;
use hickory_resolver::proto::rr::{RData, RecordType};
use hickory_resolver::TokioResolver;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256, Sha512};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

/// A usable TLSA record (usage 2 = DANE-TA or 3 = DANE-EE).
#[derive(Debug, Clone, PartialEq)]
pub struct Tlsa {
    pub usage: u8,
    pub selector: u8,
    pub matching: u8,
    pub data: Vec<u8>,
}

pub enum DnsSecure<T> {
    /// Validated by DNSSEC.
    Secure(T),
    /// Answered, but not provably secure (unsigned zone).
    Insecure,
    /// Lookup failed or the answer was bogus.
    Error(String),
}

fn resolver() -> Option<&'static TokioResolver> {
    static R: OnceLock<Option<TokioResolver>> = OnceLock::new();
    R.get_or_init(|| {
        let mut b = TokioResolver::builder_tokio().ok()?;
        b.options_mut().validate = true;
        b.options_mut().timeout = Duration::from_secs(10);
        b.build().ok()
    })
    .as_ref()
}

fn all_secure(records: &[hickory_resolver::proto::rr::Record]) -> bool {
    !records.is_empty() && records.iter().all(|r| r.proof == Proof::Secure)
}

/// Are the domain's MX records DNSSEC-signed? (DANE applies only then.)
pub async fn mx_secure(domain: &str) -> bool {
    let Some(r) = resolver() else { return false };
    let name = format!("{}.", domain.trim_end_matches('.'));
    match tokio::time::timeout(Duration::from_secs(15), r.lookup(name, RecordType::MX)).await {
        Ok(Ok(l)) => all_secure(l.answers()),
        _ => false,
    }
}

/// TLSA records for `_25._tcp.<host>`, keeping only usages 2 and 3.
pub async fn tlsa(host: &str) -> DnsSecure<Vec<Tlsa>> {
    let Some(r) = resolver() else { return DnsSecure::Insecure };
    let name = format!("_25._tcp.{}.", host.trim_end_matches('.'));
    let l = match tokio::time::timeout(Duration::from_secs(15), r.lookup(name, RecordType::TLSA)).await {
        Err(_) => return DnsSecure::Error("TLSA lookup timed out".into()),
        Ok(Err(e)) if e.is_no_records_found() || e.is_nx_domain() => return DnsSecure::Insecure,
        Ok(Err(e)) => return DnsSecure::Error(format!("TLSA lookup: {e}")),
        Ok(Ok(l)) => l,
    };
    let answers: Vec<_> = l.answers().iter().filter(|r| r.record_type() == RecordType::TLSA).cloned().collect();
    if answers.is_empty() {
        return DnsSecure::Insecure;
    }
    if !all_secure(&answers) {
        return DnsSecure::Insecure;
    }
    let usable = answers
        .iter()
        .filter_map(|rec| match &rec.data {
            RData::TLSA(t) => Some(Tlsa {
                usage: u8::from(t.cert_usage),
                selector: u8::from(t.selector),
                matching: u8::from(t.matching),
                data: t.cert_data.clone(),
            }),
            _ => None,
        })
        .filter(|t| (t.usage == 2 || t.usage == 3) && t.selector <= 1 && t.matching <= 2)
        .collect();
    DnsSecure::Secure(usable)
}

fn selected(cert: &[u8], selector: u8) -> Option<Vec<u8>> {
    match selector {
        0 => Some(cert.to_vec()),
        1 => {
            let (_, c) = x509_parser::parse_x509_certificate(cert).ok()?;
            Some(c.tbs_certificate.subject_pki.raw.to_vec())
        }
        _ => None,
    }
}

pub fn matches(t: &Tlsa, cert: &[u8]) -> bool {
    let Some(content) = selected(cert, t.selector) else { return false };
    let digest = match t.matching {
        0 => content,
        1 => Sha256::digest(&content).to_vec(),
        2 => Sha512::digest(&content).to_vec(),
        _ => return false,
    };
    subtle::ConstantTimeEq::ct_eq(digest.as_slice(), t.data.as_slice()).into()
}

/// Verifies the server certificate against TLSA records. DANE-EE (3)
/// matches the leaf and ignores names and dates (RFC 7672 3.1.1); DANE-TA
/// (2) needs a chain from the presented anchor to a leaf valid for one of
/// the reference names.
#[derive(Debug)]
pub struct DaneVerifier {
    pub records: Vec<Tlsa>,
    /// Names the certificate may carry for DANE-TA: the MX host (and the
    /// recipient domain when the MX lookup was secure).
    pub names: Vec<String>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl DaneVerifier {
    pub fn new(records: Vec<Tlsa>, names: Vec<String>) -> Self {
        Self { records, names, provider: Arc::new(rustls::crypto::ring::default_provider()) }
    }
}

impl ServerCertVerifier for DaneVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        for t in self.records.iter().filter(|t| t.usage == 3) {
            if matches(t, end_entity) {
                return Ok(ServerCertVerified::assertion());
            }
        }
        for t in self.records.iter().filter(|t| t.usage == 2) {
            // The anchor may be any certificate the server sent.
            for anchor in intermediates.iter() {
                if !matches(t, anchor) {
                    continue;
                }
                let mut roots = rustls::RootCertStore::empty();
                if roots.add(anchor.clone()).is_err() {
                    continue;
                }
                let Ok(v) = rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(roots), self.provider.clone()).build()
                else {
                    continue;
                };
                for n in &self.names {
                    let Ok(name) = ServerName::try_from(n.clone()) else { continue };
                    if v.verify_server_cert(end_entity, intermediates, &name, &[], now).is_ok() {
                        return Ok(ServerCertVerified::assertion());
                    }
                }
            }
        }
        Err(rustls::Error::General("DANE: no TLSA record matches the server certificate".into()))
    }

    fn verify_tls12_signature(&self, m: &[u8], c: &CertificateDer<'_>, d: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(&self, m: &[u8], c: &CertificateDer<'_>, d: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// Accepts any certificate (opportunistic TLS), still checking handshake signatures.
#[derive(Debug)]
pub struct AnyCert(Arc<rustls::crypto::CryptoProvider>);

impl Default for AnyCert {
    fn default() -> Self {
        Self(Arc::new(rustls::crypto::ring::default_provider()))
    }
}

impl ServerCertVerifier for AnyCert {
    fn verify_server_cert(&self, _: &CertificateDer<'_>, _: &[CertificateDer<'_>], _: &ServerName<'_>, _: &[u8], _: UnixTime) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(&self, m: &[u8], c: &CertificateDer<'_>, d: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn verify_tls13_signature(&self, m: &[u8], c: &CertificateDer<'_>, d: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tlsa_match() {
        let ck = rcgen::generate_simple_self_signed(vec!["mx.example.com".into()]).unwrap();
        let der = ck.cert.der().to_vec();
        let spki = selected(&der, 1).unwrap();
        let t = Tlsa { usage: 3, selector: 1, matching: 1, data: Sha256::digest(&spki).to_vec() };
        assert!(matches(&t, &der));
        let t2 = Tlsa { usage: 3, selector: 0, matching: 2, data: Sha512::digest(&der).to_vec() };
        assert!(matches(&t2, &der));
        let bad = Tlsa { usage: 3, selector: 1, matching: 1, data: vec![0; 32] };
        assert!(!matches(&bad, &der));
    }
}
