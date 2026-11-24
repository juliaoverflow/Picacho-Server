//! Unauthenticated discovery and operations endpoints:
//!
//! - `/.well-known/acme-challenge/<token>`: ACME HTTP-01.
//! - `/.well-known/mta-sts.txt`: our MTA-STS policy (served on mta-sts.<domain>).
//! - Thunderbird autoconfig, Outlook Autodiscover, Apple configuration
//!   profiles (.mobileconfig) with IMAP, SMTP, CalDAV and CardDAV.
//! - `/healthz` (liveness), `/readyz` (database reachable, not shutting down).
//! - `/metrics` (Prometheus), for allowed addresses or a bearer token.
use crate::state::State;
use axum::body::Body;
use axum::extract::{ConnectInfo, Path, Query, State as AxState};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use std::collections::HashMap;
use std::net::SocketAddr;

pub fn routes(state: State) -> Router {
    Router::new()
        .route("/.well-known/acme-challenge/{token}", get(acme_challenge))
        .route("/.well-known/mta-sts.txt", get(mta_sts))
        .route("/.well-known/autoconfig/mail/config-v1.1.xml", get(autoconfig))
        .route("/mail/config-v1.1.xml", get(autoconfig))
        .route("/autodiscover/autodiscover.xml", get(autodiscover).post(autodiscover))
        .route("/Autodiscover/Autodiscover.xml", get(autodiscover).post(autodiscover))
        .route("/.well-known/picacho/mobileconfig", get(mobileconfig))
        .route("/.well-known/picacho", get(discovery))
        .route("/.well-known/oauth-protected-resource", get(protected_resource))
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics))
        .with_state(state)
}

/// Port-80 listener for ACME (and MTA-STS / autoconfig when proxied there).
pub async fn serve_http(state: State, addr: SocketAddr) -> Result<SocketAddr, String> {
    let listener = tokio::net::TcpListener::bind(addr).await.map_err(|e| format!("ACME HTTP on {addr}: {e}"))?;
    let bound = listener.local_addr().unwrap_or(addr);
    state.listeners.lock().push(serde_json::json!({"protocol": "HTTP (ACME)", "address": bound.to_string()}));
    let app = routes(state.clone()).fallback(redirect_https);
    let shutdown = state.shutdown.clone();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
            .with_graceful_shutdown(async move { shutdown.cancelled().await })
            .await;
    });
    Ok(bound)
}

async fn redirect_https(headers: HeaderMap, req: axum::http::Request<Body>) -> Response {
    let host = headers.get(header::HOST).and_then(|v| v.to_str().ok()).unwrap_or("").split(':').next().unwrap_or("").to_string();
    if host.is_empty() || !crate::util::valid_domain(&host) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let path = req.uri().path_and_query().map(|p| p.as_str()).unwrap_or("/");
    (StatusCode::MOVED_PERMANENTLY, [(header::LOCATION, format!("https://{host}{path}"))]).into_response()
}

fn text(ctype: &'static str, body: String) -> Response {
    ([(header::CONTENT_TYPE, ctype), (header::CACHE_CONTROL, "no-cache")], body).into_response()
}

async fn acme_challenge(AxState(state): AxState<State>, Path(token): Path<String>) -> Response {
    match state.acme_tokens.get(&token) {
        Some(k) => text("application/octet-stream", k.clone()),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

fn host_of(headers: &HeaderMap) -> String {
    headers.get(header::HOST).and_then(|v| v.to_str().ok()).unwrap_or("").split(':').next().unwrap_or("").to_ascii_lowercase()
}

async fn mta_sts(AxState(state): AxState<State>, headers: HeaderMap) -> Response {
    let mode = state.settings().server.mta_sts_mode.clone().unwrap_or_else(|| "testing".into());
    if mode == "off" {
        return StatusCode::NOT_FOUND.into_response();
    }
    // Served for mta-sts.<local domain> (or the bare host when testing locally).
    let host = host_of(&headers);
    let domain = host.strip_prefix("mta-sts.").unwrap_or(&host).to_string();
    let known = state.db.domain_by_name(&domain).await.ok().flatten().is_some() || domain == state.hostname();
    if !known {
        return StatusCode::NOT_FOUND.into_response();
    }
    let mut body = format!("version: STSv1\nmode: {mode}\nmx: {}\n", state.hostname());
    for extra in &state.settings().server.mta_sts_mx {
        body.push_str(&format!("mx: {extra}\n"));
    }
    body.push_str("max_age: 604800\n");
    text("text/plain", body)
}

/// Mail and DAV endpoints for an address (`None` when not a local account).
async fn endpoints(state: &State, headers: &HeaderMap, email: &str) -> serde_json::Value {
    let host = state.hostname();
    let l = &state.config.listen;
    let port = |v: &Vec<SocketAddr>, d: u16| v.first().map(|a| a.port()).unwrap_or(d);
    let base = crate::jmap::base_url(state, headers);
    serde_json::json!({
        "email": email,
        "imap": {"host": host, "port": port(&l.imaps, 993), "socket": "SSL", "starttls_port": port(&l.imap, 143), "enabled": !l.imaps.is_empty() || !l.imap.is_empty()},
        "smtp": {"host": host, "port": port(&l.submissions, 465), "socket": "SSL", "starttls_port": port(&l.submission, 587), "enabled": !l.submissions.is_empty() || !l.submission.is_empty()},
        "managesieve": {"host": host, "port": port(&l.managesieve, 4190), "enabled": !l.managesieve.is_empty()},
        "pop3": {"host": host, "port": port(&l.pop3s, 995), "socket": if l.pop3s.is_empty() { "STARTTLS" } else { "SSL" }, "starttls_port": port(&l.pop3, 110), "enabled": !l.pop3s.is_empty() || !l.pop3.is_empty()},
        "jmap": format!("{base}/.well-known/jmap"),
        "caldav": format!("{base}/dav/"),
        "carddav": format!("{base}/dav/"),
        "webdav": format!("{base}/dav/files/"),
        "oauth_resource": crate::resource::metadata(state).map(|_| format!("{base}/.well-known/oauth-protected-resource")),
        "rest": format!("{base}/v1"),
    })
}

/// RFC 9728: where apps get tokens for this server (the identity provider).
async fn protected_resource(AxState(state): AxState<State>) -> Response {
    match crate::resource::metadata(&state) {
        Some(m) => ([(axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")], axum::Json(m)).into_response(),
        None => (axum::http::StatusCode::NOT_FOUND, "").into_response(),
    }
}

/// The provider's authorize and token endpoints, for mail-app autoconfig.
async fn oauth_endpoints(state: &State) -> Option<(String, String, String)> {
    let o = state.settings().auth.oidc.clone();
    if !o.access_tokens {
        return None;
    }
    let d = crate::oidc::discover(&o.issuer).await.ok()?;
    let host = url::Url::parse(&d.issuer).ok()?.host_str()?.to_string();
    Some((host, d.authorization_endpoint, d.token_endpoint))
}

/// Machine-readable discovery for apps and the identity provider.
async fn discovery(AxState(state): AxState<State>, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> Response {
    let email = q.get("email").cloned().unwrap_or_default();
    let mut v = endpoints(&state, &headers, &email).await;
    v["hostname"] = serde_json::json!(state.hostname());
    v["version"] = serde_json::json!(env!("CARGO_PKG_VERSION"));
    axum::Json(v).into_response()
}

async fn autoconfig(AxState(state): AxState<State>, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> Response {
    let email = q.get("emailaddress").cloned().unwrap_or_default();
    let domain = if email.contains('@') { crate::util::domain_of(&email).to_string() } else { host_of(&headers).trim_start_matches("autoconfig.").to_string() };
    let e = endpoints(&state, &headers, &email).await;
    let x = crate::xml::escape;
    let brand = state.settings().branding.name.clone().unwrap_or_else(|| "Picacho Server".into());
    let mut body = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<clientConfig version=\"1.1\">\n  <emailProvider id=\"{d}\">\n    <domain>{d}</domain>\n    <displayName>{b}</displayName>\n    <displayShortName>{b}</displayShortName>\n",
        d = x(&domain),
        b = x(&brand)
    );
    let host = x(e["imap"]["host"].as_str().unwrap_or(""));
    let oauth = oauth_endpoints(&state).await;
    let oauth_auth = if oauth.is_some() { "      <authentication>OAuth2</authentication>\n" } else { "" };
    body.push_str(&format!(
        "    <incomingServer type=\"imap\">\n      <hostname>{host}</hostname>\n      <port>{}</port>\n      <socketType>SSL</socketType>\n      <authentication>password-cleartext</authentication>\n{oauth_auth}      <username>%EMAILADDRESS%</username>\n    </incomingServer>\n",
        e["imap"]["port"]
    ));
    body.push_str(&format!(
        "    <incomingServer type=\"imap\">\n      <hostname>{host}</hostname>\n      <port>{}</port>\n      <socketType>STARTTLS</socketType>\n      <authentication>password-cleartext</authentication>\n      <username>%EMAILADDRESS%</username>\n    </incomingServer>\n",
        e["imap"]["starttls_port"]
    ));
    // POP3 after IMAP, so apps that pick the first entry still choose IMAP.
    if e["pop3"]["enabled"] == true {
        let (port, socket) = if state.config.listen.pop3s.is_empty() { (&e["pop3"]["starttls_port"], "STARTTLS") } else { (&e["pop3"]["port"], "SSL") };
        body.push_str(&format!(
            "    <incomingServer type=\"pop3\">\n      <hostname>{host}</hostname>\n      <port>{port}</port>\n      <socketType>{socket}</socketType>\n      <authentication>password-cleartext</authentication>\n{oauth_auth}      <username>%EMAILADDRESS%</username>\n      <pop3>\n        <leaveMessagesOnServer>true</leaveMessagesOnServer>\n      </pop3>\n    </incomingServer>\n"
        ));
    }
    body.push_str(&format!(
        "    <outgoingServer type=\"smtp\">\n      <hostname>{host}</hostname>\n      <port>{}</port>\n      <socketType>SSL</socketType>\n      <authentication>password-cleartext</authentication>\n{oauth_auth}      <username>%EMAILADDRESS%</username>\n    </outgoingServer>\n",
        e["smtp"]["port"]
    ));
    body.push_str(&format!(
        "    <outgoingServer type=\"smtp\">\n      <hostname>{host}</hostname>\n      <port>{}</port>\n      <socketType>STARTTLS</socketType>\n      <authentication>password-cleartext</authentication>\n      <username>%EMAILADDRESS%</username>\n    </outgoingServer>\n  </emailProvider>\n",
        e["smtp"]["starttls_port"]
    ));
    body.push_str(&format!(
        "  <addressBook type=\"carddav\">\n    <username>%EMAILADDRESS%</username>\n    <authentication>http-basic</authentication>\n    <serverURL>{}</serverURL>\n  </addressBook>\n  <calendar type=\"caldav\">\n    <username>%EMAILADDRESS%</username>\n    <authentication>http-basic</authentication>\n    <serverURL>{}</serverURL>\n  </calendar>\n",
        x(e["carddav"].as_str().unwrap_or("")),
        x(e["caldav"].as_str().unwrap_or(""))
    ));
    if let Some((issuer, auth, token)) = oauth {
        body.push_str(&format!(
            "  <oAuth2>\n    <issuer>{}</issuer>\n    <scope>openid email offline_access mail.read mail.labels mail.compose mail.send calendar.write contacts.write</scope>\n    <authURL>{}</authURL>\n    <tokenURL>{}</tokenURL>\n  </oAuth2>\n",
            x(&issuer),
            x(&auth),
            x(&token)
        ));
    }
    body.push_str("</clientConfig>\n");
    text("application/xml", body)
}

async fn autodiscover(AxState(state): AxState<State>, headers: HeaderMap, body: axum::body::Bytes) -> Response {
    // Outlook POSTs <Request><EMailAddress>…</EMailAddress></Request>.
    let email = crate::xml::parse(&body).ok().map(|d| d.find_text("Request/EMailAddress")).filter(|s| !s.is_empty()).unwrap_or_default();
    let e = endpoints(&state, &headers, &email).await;
    let x = crate::xml::escape;
    let host = x(e["imap"]["host"].as_str().unwrap_or(""));
    let out = format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<Autodiscover xmlns=\"http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006\">\n  <Response xmlns=\"http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a\">\n    <Account>\n      <AccountType>email</AccountType>\n      <Action>settings</Action>\n      <Protocol>\n        <Type>IMAP</Type>\n        <Server>{host}</Server>\n        <Port>{}</Port>\n        <LoginName>{em}</LoginName>\n        <SPA>off</SPA>\n        <SSL>on</SSL>\n        <AuthRequired>on</AuthRequired>\n      </Protocol>\n      <Protocol>\n        <Type>SMTP</Type>\n        <Server>{host}</Server>\n        <Port>{}</Port>\n        <LoginName>{em}</LoginName>\n        <SPA>off</SPA>\n        <SSL>on</SSL>\n        <AuthRequired>on</AuthRequired>\n        <UsePOPAuth>off</UsePOPAuth>\n        <SMTPLast>off</SMTPLast>\n      </Protocol>\n    </Account>\n  </Response>\n</Autodiscover>\n",
        e["imap"]["port"],
        e["smtp"]["port"],
        em = x(&email)
    );
    text("application/xml", out)
}

async fn mobileconfig(AxState(state): AxState<State>, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> Response {
    let Some(email) = q.get("email").and_then(|e| crate::util::normalize_address(e)) else {
        return (StatusCode::BAD_REQUEST, "email is required").into_response();
    };
    let e = endpoints(&state, &headers, &email).await;
    let x = crate::xml::escape;
    let brand = state.settings().branding.name.clone().unwrap_or_else(|| "Picacho Server".into());
    let host = state.hostname();
    let id = |s: &str| format!("{}.{}", host.split('.').rev().collect::<Vec<_>>().join("."), s);
    let uuid = || uuid::Uuid::new_v4().to_string().to_uppercase();
    let dav_host = crate::jmap::base_url(&state, &headers);
    let dav_host = dav_host.trim_start_matches("https://").trim_start_matches("http://").split('/').next().unwrap_or(&host).to_string();
    let (dh, dp) = match dav_host.split_once(':') {
        Some((h, p)) => (h.to_string(), p.parse::<u16>().unwrap_or(443)),
        None => (dav_host.clone(), 443),
    };
    let body = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>PayloadContent</key><array>
<dict>
<key>EmailAccountDescription</key><string>{brand}</string>
<key>EmailAccountName</key><string>{em}</string>
<key>EmailAccountType</key><string>EmailTypeIMAP</string>
<key>EmailAddress</key><string>{em}</string>
<key>IncomingMailServerAuthentication</key><string>EmailAuthPassword</string>
<key>IncomingMailServerHostName</key><string>{h}</string>
<key>IncomingMailServerPortNumber</key><integer>{ip}</integer>
<key>IncomingMailServerUseSSL</key><true/>
<key>IncomingMailServerUsername</key><string>{em}</string>
<key>OutgoingMailServerAuthentication</key><string>EmailAuthPassword</string>
<key>OutgoingMailServerHostName</key><string>{h}</string>
<key>OutgoingMailServerPortNumber</key><integer>{sp}</integer>
<key>OutgoingMailServerUseSSL</key><true/>
<key>OutgoingMailServerUsername</key><string>{em}</string>
<key>OutgoingPasswordSameAsIncomingPassword</key><true/>
<key>PayloadDisplayName</key><string>{brand} Mail</string>
<key>PayloadIdentifier</key><string>{i1}</string>
<key>PayloadType</key><string>com.apple.mail.managed</string>
<key>PayloadUUID</key><string>{u1}</string>
<key>PayloadVersion</key><integer>1</integer>
</dict>
<dict>
<key>CalDAVAccountDescription</key><string>{brand} Calendar</string>
<key>CalDAVHostName</key><string>{dh}</string>
<key>CalDAVPort</key><integer>{dp}</integer>
<key>CalDAVPrincipalURL</key><string>/dav/principals/{em}/</string>
<key>CalDAVUseSSL</key><true/>
<key>CalDAVUsername</key><string>{em}</string>
<key>PayloadDisplayName</key><string>{brand} Calendar</string>
<key>PayloadIdentifier</key><string>{i2}</string>
<key>PayloadType</key><string>com.apple.caldav.account</string>
<key>PayloadUUID</key><string>{u2}</string>
<key>PayloadVersion</key><integer>1</integer>
</dict>
<dict>
<key>CardDAVAccountDescription</key><string>{brand} Contacts</string>
<key>CardDAVHostName</key><string>{dh}</string>
<key>CardDAVPort</key><integer>{dp}</integer>
<key>CardDAVPrincipalURL</key><string>/dav/principals/{em}/</string>
<key>CardDAVUseSSL</key><true/>
<key>CardDAVUsername</key><string>{em}</string>
<key>PayloadDisplayName</key><string>{brand} Contacts</string>
<key>PayloadIdentifier</key><string>{i3}</string>
<key>PayloadType</key><string>com.apple.carddav.account</string>
<key>PayloadUUID</key><string>{u3}</string>
<key>PayloadVersion</key><integer>1</integer>
</dict>
</array>
<key>PayloadDisplayName</key><string>{brand} ({em})</string>
<key>PayloadIdentifier</key><string>{i0}</string>
<key>PayloadRemovalDisallowed</key><false/>
<key>PayloadType</key><string>Configuration</string>
<key>PayloadUUID</key><string>{u0}</string>
<key>PayloadVersion</key><integer>1</integer>
</dict></plist>
"#,
        brand = x(&brand),
        em = x(&email),
        h = x(e["imap"]["host"].as_str().unwrap_or("")),
        ip = e["imap"]["port"],
        sp = e["smtp"]["port"],
        dh = x(&dh),
        i0 = id("profile"),
        i1 = id("mail"),
        i2 = id("caldav"),
        i3 = id("carddav"),
        u0 = uuid(),
        u1 = uuid(),
        u2 = uuid(),
        u3 = uuid(),
    );
    (
        [
            (header::CONTENT_TYPE, "application/x-apple-aspen-config".to_string()),
            (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{}.mobileconfig\"", email.replace('@', "_at_"))),
        ],
        body,
    )
        .into_response()
}

async fn healthz() -> Response {
    text("text/plain", "ok\n".into())
}

async fn readyz(AxState(state): AxState<State>) -> Response {
    if state.shutdown.is_cancelled() {
        return (StatusCode::SERVICE_UNAVAILABLE, "shutting down\n").into_response();
    }
    match sqlx::query("SELECT 1").execute(&state.db.pool).await {
        Ok(_) => text("text/plain", "ready\n".into()),
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, "database unavailable\n").into_response(),
    }
}

async fn metrics(AxState(state): AxState<State>, ConnectInfo(peer): ConnectInfo<SocketAddr>, headers: HeaderMap) -> Response {
    let w = &state.config.web;
    if !w.metrics {
        return StatusCode::NOT_FOUND.into_response();
    }
    let allowed_ip = crate::util::ip_in_list(peer.ip(), &w.metrics_allow);
    let token_ok = match &w.metrics_token_file {
        Some(f) => {
            let want = std::fs::read_to_string(f).unwrap_or_default();
            let want = want.trim();
            let got = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("Bearer ")).unwrap_or("");
            !want.is_empty() && subtle::ConstantTimeEq::ct_eq(want.as_bytes(), got.trim().as_bytes()).into()
        }
        None => false,
    };
    if !allowed_ip && !token_ok {
        return StatusCode::FORBIDDEN.into_response();
    }
    text("text/plain; version=0.0.4", crate::metrics::render(&state).await)
}

