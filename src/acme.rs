//! Automatic certificates (ACME, RFC 8555) with HTTP-01 challenges.
//!
//! Challenges are answered at `/.well-known/acme-challenge/<token>` on the
//! console listeners and on `[tls.acme] http_listen` (port 80). The
//! certificate and key go to `<data_dir>/tls/acme-*.pem` and are swapped
//! into every TLS listener without a restart.
use crate::state::State;
use anyhow::{anyhow, Context, Result};
use instant_acme::{Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, NewAccount, NewOrder, OrderStatus, RetryPolicy};
use std::time::Duration;

/// Names the certificate should cover.
pub async fn wanted_names(state: &State) -> Vec<String> {
    let cfg = state.config.tls.acme.clone().unwrap_or_default();
    let mut names: Vec<String> = if cfg.domains.is_empty() { vec![state.hostname()] } else { cfg.domains.clone() };
    names.iter_mut().for_each(|n| *n = n.trim().trim_end_matches('.').to_ascii_lowercase());
    names.retain(|n| crate::util::valid_domain(n) && n.contains('.') && n != "localhost");
    names.sort();
    names.dedup();
    names
}

async fn account(state: &State) -> Result<Account> {
    let cfg = state.config.tls.acme.clone().unwrap_or_default();
    if let Some(saved) = state.db.get_setting("acme_account").await? {
        if let Ok(creds) = serde_json::from_str::<AccountCredentials>(&saved) {
            if let Ok(a) = Account::builder()?.from_credentials(creds).await {
                return Ok(a);
            }
        }
    }
    let contacts: Vec<String> = cfg.contact.iter().map(|c| if c.starts_with("mailto:") { c.clone() } else { format!("mailto:{c}") }).collect();
    let refs: Vec<&str> = contacts.iter().map(|s| s.as_str()).collect();
    let (acc, creds) = Account::builder()?
        .create(&NewAccount { contact: &refs, terms_of_service_agreed: cfg.accept_terms, only_return_existing: false }, cfg.directory.clone(), None)
        .await
        .context("ACME account registration")?;
    state.db.set_setting("acme_account", &serde_json::to_string(&creds)?).await?;
    Ok(acc)
}

/// Obtain a certificate now.
pub async fn issue(state: &State) -> Result<String> {
    let cfg = state.config.tls.acme.clone().ok_or_else(|| anyhow!("ACME is not configured"))?;
    if !cfg.accept_terms {
        anyhow::bail!("set [tls.acme] accept_terms = true to agree to the CA's terms of service");
    }
    let names = wanted_names(state).await;
    if names.is_empty() {
        anyhow::bail!("no public host names to request a certificate for (set the server host name)");
    }
    let acc = account(state).await?;
    let ids: Vec<Identifier> = names.iter().map(|n| Identifier::Dns(n.clone())).collect();
    let mut order = acc.new_order(&NewOrder::new(&ids)).await.context("ACME new order")?;
    let mut tokens = vec![];
    {
        let mut auths = order.authorizations();
        while let Some(a) = auths.next().await {
            let mut a = a?;
            match a.status {
                AuthorizationStatus::Valid => continue,
                AuthorizationStatus::Pending => {}
                s => anyhow::bail!("authorization is {s:?}"),
            }
            let mut ch = a.challenge(ChallengeType::Http01).ok_or_else(|| anyhow!("the CA offered no HTTP-01 challenge"))?;
            state.acme_tokens.insert(ch.token.clone(), ch.key_authorization().as_str().to_string());
            tokens.push(ch.token.clone());
            ch.set_ready().await?;
        }
    }
    let status = order.poll_ready(&RetryPolicy::default()).await;
    let cleanup = |state: &State| {
        for t in &tokens {
            state.acme_tokens.remove(t);
        }
    };
    let status = match status {
        Ok(s) => s,
        Err(e) => {
            cleanup(state);
            return Err(e.into());
        }
    };
    if status != OrderStatus::Ready {
        cleanup(state);
        anyhow::bail!("order is {status:?}; check that {} resolve here and port 80 reaches this server", names.join(", "));
    }
    // Keep the same key across renewals so DANE TLSA (3 1 1) records stay valid.
    let (_, kp) = crate::tls::acme_paths(&state.config);
    let key = match std::fs::read_to_string(&kp).ok().and_then(|p| rcgen::KeyPair::from_pem(&p).ok()) {
        Some(k) => k,
        None => rcgen::KeyPair::generate()?,
    };
    let mut params = rcgen::CertificateParams::new(names.clone())?;
    // rcgen's default subject ("rcgen self signed cert") isn't a host name,
    // and CAs refuse a CSR whose common name isn't one of its names.
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.distinguished_name.push(rcgen::DnType::CommonName, names[0].clone());
    let csr = params.serialize_request(&key)?;
    order.finalize_csr(csr.der()).await?;
    let chain = order.poll_certificate(&RetryPolicy::default()).await?;
    cleanup(state);
    let key_pem = key.serialize_pem();
    let (cp, kp) = crate::tls::acme_paths(&state.config);
    if let Some(d) = cp.parent() {
        std::fs::create_dir_all(d)?;
    }
    std::fs::write(&kp, &key_pem)?;
    crate::util::restrict_permissions(&kp);
    std::fs::write(&cp, &chain)?;
    state.tls.install_pem(&chain, &key_pem)?;
    let msg = format!("installed a new certificate for {}", names.join(", "));
    state.event("info", "tls", &msg);
    Ok(msg)
}

/// Renew when due (or when names changed); checks twice a day. Also
/// reloads `[tls] cert/key` from disk when `watch_files` is set.
pub fn spawn(state: State) {
    tokio::spawn(async move {
        let mut failures = 0u32;
        loop {
            if let Some(cfg) = state.config.tls.acme.clone() {
                let left = state.tls.expires_in().unwrap_or(-1);
                let wanted = wanted_names(&state).await;
                let have = state.tls.names();
                let names_changed = !wanted.iter().all(|n| have.iter().any(|h| h.eq_ignore_ascii_case(n)));
                let due = *state.tls.source.read() != "acme" || left < cfg.renew_days * 86400 || names_changed;
                if due {
                    match issue(&state).await {
                        Ok(_) => failures = 0,
                        Err(e) => {
                            failures += 1;
                            state.event("warn", "tls", &format!("certificate renewal failed: {e:#}"));
                        }
                    }
                }
            } else if state.config.tls.watch_files {
                match state.tls.reload_if_changed() {
                    Ok(true) => state.event("info", "tls", "reloaded the certificate from disk"),
                    Ok(false) => {}
                    Err(e) => state.event("warn", "tls", &format!("certificate reload failed: {e:#}")),
                }
            }
            let wait = if state.config.tls.acme.is_some() {
                // Back off after failures (CA rate limits), else twice a day.
                if failures > 0 { Duration::from_secs((300u64 << failures.min(6)).min(43_200)) } else { Duration::from_secs(43_200) }
            } else {
                Duration::from_secs(60)
            };
            tokio::select! {
                _ = tokio::time::sleep(wait) => {}
                _ = state.shutdown.cancelled() => return,
            }
        }
    });
}
