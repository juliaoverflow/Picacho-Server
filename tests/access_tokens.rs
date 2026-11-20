//! Access tokens from the identity provider (Pinal Accounts): provisioning
//! a linked mailbox, JWT verification against the provider's JWKS, scope
//! mapping for IMAP, SMTP, JMAP, DAV and the account API, and the Pinal
//! Mail REST API.
use axum::routing::get;
use axum::{Json, Router};
use base64::Engine;
use picacho_server::config::Config;
use picacho_server::server::{spawn_listener, Proto};
use picacho_server::state::{AppState, State};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

const RESOURCE: &str = "https://mail.sonoran.exchange";

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

struct Idp {
    issuer: String,
    key: Arc<EcdsaKeyPair>,
}

impl Idp {
    async fn start() -> Idp {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let key = Arc::new(
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
                .unwrap(),
        );
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!("http://{}", l.local_addr().unwrap());
        let pt = key.public_key().as_ref().to_vec();
        let jwks = json!({"keys": [{"kty": "EC", "crv": "P-256", "kid": "k1", "alg": "ES256", "use": "sig", "x": b64(&pt[1..33]), "y": b64(&pt[33..])}]});
        let disc = json!({"issuer": issuer, "authorization_endpoint": format!("{issuer}/authorize"),
            "token_endpoint": format!("{issuer}/token"), "jwks_uri": format!("{issuer}/jwks")});
        let app = Router::new()
            .route(
                "/.well-known/openid-configuration",
                get(move || async move { Json(disc) }),
            )
            .route("/jwks", get(move || async move { Json(jwks) }));
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        Idp { issuer, key }
    }

    fn sign(&self, header: Value, claims: Value) -> String {
        let msg = format!(
            "{}.{}",
            b64(header.to_string().as_bytes()),
            b64(claims.to_string().as_bytes())
        );
        let sig = self.key.sign(&SystemRandom::new(), msg.as_bytes()).unwrap();
        format!("{msg}.{}", b64(sig.as_ref()))
    }

    /// An RFC 9068 access token for `sub` with `scope`.
    fn token(&self, sub: &str, scope: &str) -> String {
        let now = chrono::Utc::now().timestamp();
        self.sign(
            json!({"alg": "ES256", "typ": "at+jwt", "kid": "k1"}),
            json!({"iss": self.issuer, "aud": [RESOURCE, format!("{}/api/auth/oauth2/userinfo", self.issuer)], "sub": sub,
                "scope": scope, "client_id": "app", "iat": now, "exp": now + 600}),
        )
    }
}

struct Srv {
    state: State,
    base: String,
    imap: SocketAddr,
    smtp: SocketAddr,
    admin: String,
    _dir: tempfile::TempDir,
}

async fn start(idp: &Idp) -> Srv {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    cfg.hostname = Some("mx.sonoran.exchange".into());
    cfg.storage.data_dir = dir.path().to_path_buf();
    let state = AppState::new(cfg).await.unwrap();
    let mut s = (*state.settings()).clone();
    s.server.setup_complete = true;
    s.server.primary_domain = Some("sonoran.exchange".into());
    s.security.verify_inbound = false;
    s.security.require_tls_for_auth = false;
    s.filter.bayes = false;
    s.auth.oidc.issuer = idp.issuer.clone();
    s.auth.oidc.client_id = "picacho".into();
    s.auth.oidc.access_tokens = true;
    s.auth.oidc.resource = RESOURCE.into();
    s.validate().unwrap();
    state.save_settings(s).await.unwrap();
    let d = state
        .db
        .create_domain("sonoran.exchange", "local", "")
        .await
        .unwrap();
    let hash = picacho_server::auth::hash_password("Correct-Horse-9").unwrap();
    let root = state
        .db
        .create_account(
            "postmaster@sonoran.exchange",
            d,
            &hash,
            "Postmaster",
            "admin",
            0,
        )
        .await
        .unwrap();
    let (admin, h, p) = picacho_server::auth::generate_token();
    state
        .db
        .create_token(root, "pinal-accounts", &h, &p, "admin", None)
        .await
        .unwrap();
    let any: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let web = picacho_server::web::serve(state.clone(), any)
        .await
        .unwrap();
    let imap = spawn_listener(state.clone(), any, Proto::Imap)
        .await
        .unwrap();
    let smtp = spawn_listener(state.clone(), any, Proto::Submission)
        .await
        .unwrap();
    Srv {
        state,
        base: format!("http://{web}"),
        imap,
        smtp,
        admin,
        _dir: dir,
    }
}

async fn imap_cmd(
    r: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
    w: &mut tokio::net::tcp::OwnedWriteHalf,
    tag: &str,
    cmd: &str,
) -> String {
    w.write_all(format!("{tag} {cmd}\r\n").as_bytes())
        .await
        .unwrap();
    let mut out = String::new();
    loop {
        let mut l = String::new();
        r.read_line(&mut l).await.unwrap();
        assert!(!l.is_empty(), "connection closed after: {out}");
        out.push_str(&l);
        if l.starts_with(&format!("{tag} ")) {
            return out;
        }
    }
}

async fn imap_xoauth(
    s: &Srv,
    user: &str,
    token: &str,
) -> (
    String,
    BufReader<tokio::net::tcp::OwnedReadHalf>,
    tokio::net::tcp::OwnedWriteHalf,
) {
    let (rd, mut w) = tokio::net::TcpStream::connect(s.imap)
        .await
        .unwrap()
        .into_split();
    let mut rd = BufReader::new(rd);
    let mut greet = String::new();
    rd.read_line(&mut greet).await.unwrap();
    let sasl = base64::engine::general_purpose::STANDARD
        .encode(format!("user={user}\x01auth=Bearer {token}\x01\x01"));
    let r = imap_cmd(
        &mut rd,
        &mut w,
        "a",
        &format!("AUTHENTICATE XOAUTH2 {sasl}"),
    )
    .await;
    (r, rd, w)
}

#[tokio::test]
async fn provisioning_and_protocol_access() {
    let idp = Idp::start().await;
    let s = start(&idp).await;
    let http = reqwest::Client::new();

    // Pinal Accounts checks the address, then creates a linked mailbox with no password.
    let chk: Value = http
        .get(format!("{}/api/v1/addresses/sam@sonoran.exchange", s.base))
        .bearer_auth(&s.admin)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(chk["available"], true, "{chk}");
    let chk: Value = http
        .get(format!("{}/api/v1/addresses/sam@elsewhere.test", s.base))
        .bearer_auth(&s.admin)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(chk["reason"], "domain");
    let r = http
        .post(format!("{}/api/v1/accounts", s.base))
        .bearer_auth(&s.admin)
        .json(&json!({"email": "sam@sonoran.exchange", "display_name": "Sam", "oidc_subject": "user-sam"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "{}", r.text().await.unwrap());
    let acc: Value = r.json().await.unwrap();
    assert_eq!(acc["sso_linked"], true);
    assert_eq!(acc["has_password"], false);
    let chk: Value = http
        .get(format!("{}/api/v1/addresses/Sam@sonoran.exchange", s.base))
        .bearer_auth(&s.admin)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(chk["reason"], "taken");
    // The same identity can't get a second mailbox.
    let r = http
        .post(format!("{}/api/v1/accounts", s.base))
        .bearer_auth(&s.admin)
        .json(&json!({"email": "sam2@sonoran.exchange", "oidc_subject": "user-sam"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 409);

    // Protected-resource metadata points apps at the provider.
    let m: Value = http
        .get(format!("{}/.well-known/oauth-protected-resource", s.base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(m["resource"], RESOURCE);
    assert_eq!(m["authorization_servers"][0], idp.issuer.as_str());
    // Picacho's own authorization server is gone.
    // (Unknown paths fall through to the console page, never to token metadata.)
    let r = http
        .get(format!("{}/.well-known/oauth-authorization-server", s.base))
        .send()
        .await
        .unwrap();
    assert!(!r.text().await.unwrap().contains("token_endpoint"));
    let r = http
        .post(format!("{}/oauth/token", s.base))
        .form(&[("grant_type", "client_credentials")])
        .send()
        .await
        .unwrap();
    assert!(!r.text().await.unwrap().contains("access_token"));

    // Read-only mail access: IMAP reads, can't write; SMTP refused.
    let read = idp.token("user-sam", "openid mail.read");
    let (r, mut rd, mut w) = imap_xoauth(&s, "sam@sonoran.exchange", &read).await;
    assert!(r.contains("a OK"), "{r}");
    assert!(imap_cmd(&mut rd, &mut w, "b", "SELECT INBOX")
        .await
        .contains("[READ-ONLY]"));
    assert!(imap_cmd(&mut rd, &mut w, "c", "CREATE Nope")
        .await
        .contains("c NO"));
    let ip = "127.0.0.1".parse().unwrap();
    use picacho_server::auth::{login_service, Service};
    assert!(
        login_service(&s.state, "sam@sonoran.exchange", &read, ip, Service::Smtp)
            .await
            .is_err()
    );
    // A token only works for its own mailbox.
    assert!(login_service(
        &s.state,
        "postmaster@sonoran.exchange",
        &read,
        ip,
        Service::Imap
    )
    .await
    .is_err());

    // A mail app (read + labels + compose + send) gets full IMAP and SMTP, but not Sieve.
    let app = idp.token(
        "user-sam",
        "openid mail.read mail.labels mail.compose mail.send",
    );
    let (r, mut rd, mut w) = imap_xoauth(&s, "sam@sonoran.exchange", &app).await;
    assert!(r.contains("a OK"), "{r}");
    assert!(imap_cmd(&mut rd, &mut w, "b", "CREATE Projects")
        .await
        .contains("b OK"));
    assert!(
        login_service(&s.state, "sam@sonoran.exchange", &app, ip, Service::Smtp)
            .await
            .is_ok()
    );
    assert!(
        login_service(&s.state, "sam@sonoran.exchange", &app, ip, Service::Sieve)
            .await
            .is_err()
    );
    // SMTP AUTH XOAUTH2 with a real JWT (long lines) on the submission port.
    let (srd, mut sw) = tokio::net::TcpStream::connect(s.smtp)
        .await
        .unwrap()
        .into_split();
    let mut srd = BufReader::new(srd);
    let mut line = String::new();
    srd.read_line(&mut line).await.unwrap();
    sw.write_all(b"EHLO t\r\n").await.unwrap();
    loop {
        line.clear();
        srd.read_line(&mut line).await.unwrap();
        if line.as_bytes().get(3) == Some(&b' ') {
            break;
        }
    }
    let sasl = base64::engine::general_purpose::STANDARD.encode(format!(
        "user=sam@sonoran.exchange\x01auth=Bearer {app}\x01\x01"
    ));
    sw.write_all(format!("AUTH XOAUTH2 {sasl}\r\n").as_bytes())
        .await
        .unwrap();
    line.clear();
    srd.read_line(&mut line).await.unwrap();
    assert!(line.starts_with("235"), "SMTP XOAUTH2: {line}");

    // Tokens that must be refused.
    let now = chrono::Utc::now().timestamp();
    let refused = [
        // Another resource.
        idp.sign(json!({"alg": "ES256", "typ": "at+jwt", "kid": "k1"}), json!({"iss": idp.issuer, "aud": "https://other.example", "sub": "user-sam", "scope": "mail.read", "exp": now + 600})),
        // Another issuer.
        idp.sign(json!({"alg": "ES256", "typ": "at+jwt", "kid": "k1"}), json!({"iss": "https://evil.example", "aud": RESOURCE, "sub": "user-sam", "scope": "mail.read", "exp": now + 600})),
        // Expired.
        idp.sign(json!({"alg": "ES256", "typ": "at+jwt", "kid": "k1"}), json!({"iss": idp.issuer, "aud": RESOURCE, "sub": "user-sam", "scope": "mail.read", "exp": now - 600})),
        // Unknown person.
        idp.token("nobody", "mail.read"),
        // alg=none.
        format!("{}.{}.", b64(br#"{"alg":"none"}"#), b64(json!({"iss": idp.issuer, "aud": RESOURCE, "sub": "user-sam", "scope": "mail.read", "exp": now + 600}).to_string().as_bytes())),
        // Tampered payload.
        {
            let t = idp.token("user-sam", "mail.read");
            let p: Vec<&str> = t.split('.').collect();
            let forged = b64(json!({"iss": idp.issuer, "aud": RESOURCE, "sub": "user-sam", "scope": "mail.read mail.send", "exp": now + 600}).to_string().as_bytes());
            format!("{}.{forged}.{}", p[0], p[2])
        },
    ];
    for (i, t) in refused.iter().enumerate() {
        assert!(
            login_service(&s.state, "sam@sonoran.exchange", t, ip, Service::Imap)
                .await
                .is_err(),
            "token {i} was accepted"
        );
    }

    // JMAP Bearer: read-only token can read, not write; 401s point at the resource metadata.
    let using = json!(["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"]);
    let aid = format!("a{}", acc["id"]);
    let r: Value = http
        .post(format!("{}/jmap/api", s.base))
        .bearer_auth(&read)
        .json(&json!({"using": using, "methodCalls": [["Mailbox/get", {"accountId": aid, "ids": null}, "0"],
            ["Mailbox/set", {"accountId": aid, "create": {"x": {"name": "New"}}}, "1"]]}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["methodResponses"][0][0], "Mailbox/get", "{r}");
    assert_eq!(r["methodResponses"][1][1]["type"], "forbidden", "{r}");
    let r = http
        .post(format!("{}/jmap/api", s.base))
        .bearer_auth(&refused[0])
        .json(&json!({"using": using, "methodCalls": []}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
    assert!(r.headers()["www-authenticate"]
        .to_str()
        .unwrap()
        .contains("oauth-protected-resource"));

    // DAV: calendar scope reaches calendars only.
    let cal = idp.token("user-sam", "calendar.write contacts.read");
    let ics = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//t//t//EN\r\nBEGIN:VEVENT\r\nUID:ev1\r\nDTSTAMP:20270101T000000Z\r\nDTSTART:20270105T100000Z\r\nDURATION:PT1H\r\nSUMMARY:Planning\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
    let put = http
        .put(format!(
            "{}/dav/calendars/sam@sonoran.exchange/default/ev1.ics",
            s.base
        ))
        .bearer_auth(&cal)
        .header("Content-Type", "text/calendar")
        .body(ics)
        .send()
        .await
        .unwrap();
    assert_eq!(put.status().as_u16(), 201);
    let vcf = "BEGIN:VCARD\r\nVERSION:3.0\r\nUID:c1\r\nFN:Ana\r\nEND:VCARD\r\n";
    let put = http
        .put(format!(
            "{}/dav/addressbooks/sam@sonoran.exchange/default/c1.vcf",
            s.base
        ))
        .bearer_auth(&cal)
        .header("Content-Type", "text/vcard")
        .body(vcf)
        .send()
        .await
        .unwrap();
    assert_eq!(
        put.status().as_u16(),
        403,
        "contacts.read must not write contacts"
    );
    let files = http
        .request(
            reqwest::Method::from_bytes(b"PROPFIND").unwrap(),
            format!("{}/dav/files/sam@sonoran.exchange/", s.base),
        )
        .bearer_auth(&cal)
        .header("Depth", "1")
        .send()
        .await
        .unwrap();
    assert_eq!(files.status().as_u16(), 403, "no files access");
    let mail_only = http
        .get(format!(
            "{}/dav/calendars/sam@sonoran.exchange/default/ev1.ics",
            s.base
        ))
        .bearer_auth(&read)
        .send()
        .await
        .unwrap();
    assert_eq!(mail_only.status().as_u16(), 403);

    // Account API: mail.settings can set a vacation reply, but never mint app passwords.
    let settings = idp.token("user-sam", "mail.settings");
    let v = http
        .put(format!("{}/api/v1/me/vacation", s.base))
        .bearer_auth(&settings)
        .json(&json!({"enabled": true, "subject": "Out", "text_body": "Back Monday"}))
        .send()
        .await
        .unwrap();
    assert!(v.status().is_success(), "{}", v.text().await.unwrap());
    let r = http
        .post(format!("{}/api/v1/me/app-passwords", s.base))
        .bearer_auth(&settings)
        .json(&json!({"name": "x"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
    let r = http
        .get(format!("{}/api/v1/me", s.base))
        .bearer_auth(&read)
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        403,
        "mail.read alone doesn't reach account settings"
    );

    // Disabling the mailbox stops its tokens at once.
    let r = http
        .patch(format!("{}/api/v1/accounts/sam@sonoran.exchange", s.base))
        .bearer_auth(&s.admin)
        .json(&json!({"active": false}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert!(
        login_service(&s.state, "sam@sonoran.exchange", &app, ip, Service::Imap)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn rest_api() {
    let idp = Idp::start().await;
    let s = start(&idp).await;
    let http = reqwest::Client::new();
    let r = http
        .post(format!("{}/api/v1/accounts", s.base))
        .bearer_auth(&s.admin)
        .json(&json!({"email": "sam@sonoran.exchange", "display_name": "Sam", "oidc_subject": "user-sam"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let sam = s
        .state
        .db
        .account_by_email("sam@sonoran.exchange")
        .await
        .unwrap()
        .unwrap();
    // Two messages arrive.
    for (i, subj) in ["Trail map", "Invoice"].iter().enumerate() {
        if i > 0 {
            // Received times have one-second resolution; keep the order certain.
            tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
        }
        let raw = format!("From: Ana <ana@elsewhere.test>\r\nTo: sam@sonoran.exchange\r\nSubject: {subj}\r\nMessage-ID: <m{i}@x>\r\nDate: Mon, 2 Nov 2026 10:0{i}:00 +0000\r\n\r\nSecret body {i}\r\n");
        picacho_server::smtp::deliver_local(&s.state, sam.id, raw.as_bytes(), false)
            .await
            .unwrap();
    }
    let api = |path: &str| format!("{}/v1/mail{path}", s.base);

    // No token, then a token without the scope.
    let r = http.get(api("/messages")).send().await.unwrap();
    assert_eq!(r.status(), 401);
    let cal = idp.token("user-sam", "calendar.read");
    let r = http
        .get(api("/messages"))
        .bearer_auth(&cal)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
    assert_eq!(
        r.json::<Value>().await.unwrap()["error"],
        "insufficient_scope"
    );

    // Metadata only: no snippets, and free text doesn't search bodies.
    let meta = idp.token("user-sam", "mail.metadata");
    let page: Value = http
        .get(api("/messages?label=inbox&limit=1"))
        .bearer_auth(&meta)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(page["messages"].as_array().unwrap().len(), 1, "{page}");
    assert_eq!(page["messages"][0]["subject"], "Invoice");
    assert!(page["messages"][0].get("snippet").is_none());
    let cursor = page["next_cursor"].as_str().unwrap().to_string();
    let page2: Value = http
        .get(api(&format!(
            "/messages?label=inbox&limit=1&cursor={cursor}"
        )))
        .bearer_auth(&meta)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(page2["messages"][0]["subject"], "Trail map");
    assert!(page2["next_cursor"].is_null());
    let none: Value = http
        .get(api("/messages?q=Secret"))
        .bearer_auth(&meta)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        none["messages"].as_array().unwrap().len(),
        0,
        "metadata search must not match bodies"
    );
    let id = page2["messages"][0]["id"].as_str().unwrap().to_string();
    assert_eq!(
        http.get(api(&format!("/messages/{id}")))
            .bearer_auth(&meta)
            .send()
            .await
            .unwrap()
            .status(),
        403
    );

    // mail.read: bodies, search.
    let read = idp.token("user-sam", "mail.read");
    let m: Value = http
        .get(api(&format!("/messages/{id}")))
        .bearer_auth(&read)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(m["text"].as_str().unwrap().contains("Secret body 0"), "{m}");
    assert_eq!(m["from"]["email"], "ana@elsewhere.test");
    assert_eq!(m["labels"], json!(["inbox"]));
    let hits: Value = http
        .get(api("/messages?q=from:ana%20Secret"))
        .bearer_auth(&read)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(hits["messages"].as_array().unwrap().len(), 2);

    // Labels: read, star and archive.
    let labels = idp.token("user-sam", "mail.labels");
    let l: Value = http
        .get(api("/labels"))
        .bearer_auth(&labels)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let inbox = l["labels"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["id"] == "inbox")
        .unwrap()
        .clone();
    assert_eq!(inbox["unread"], 2, "{l}");
    let r: Value = http
        .patch(api(&format!("/messages/{id}")))
        .bearer_auth(&labels)
        .json(&json!({"read": true, "add_labels": ["starred"], "remove_labels": ["inbox"]}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["read"], true, "{r}");
    assert_eq!(r["labels"], json!(["archive", "starred"]), "{r}");
    let r = http
        .patch(api(&format!("/messages/{id}")))
        .bearer_auth(&read)
        .json(&json!({"read": false}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403, "mail.read can't change labels");

    // Drafts need mail.compose; sending needs mail.send.
    let msg = json!({"to": [{"email": "postmaster@sonoran.exchange", "name": "PM"}], "subject": "Hello", "text": "Hi there"});
    assert_eq!(
        http.post(api("/drafts"))
            .bearer_auth(&read)
            .json(&msg)
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    let compose = idp.token("user-sam", "mail.compose");
    let r = http
        .post(api("/drafts"))
        .bearer_auth(&compose)
        .json(&msg)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 201);
    let d: Value = r.json().await.unwrap();
    assert_eq!(d["labels"], json!(["drafts"]));
    assert_eq!(d["text"].as_str().unwrap().trim(), "Hi there");
    assert_eq!(
        http.post(api("/messages"))
            .bearer_auth(&compose)
            .json(&msg)
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    let send = idp.token("user-sam", "mail.send");
    let r = http.post(api("/messages")).bearer_auth(&send).json(&json!({"to": [{"email": "ana@elsewhere.test"}], "subject": "Re: Trail map", "text": "Thanks!", "in_reply_to": id})).send().await.unwrap();
    assert_eq!(r.status(), 202, "{}", r.text().await.unwrap());
    let q = s.state.db.list_queue().await.unwrap();
    let item = q
        .iter()
        .find(|i| i.sender == "sam@sonoran.exchange")
        .expect("queued");
    assert_eq!(item.recipients, vec!["ana@elsewhere.test".to_string()]);
    let raw = String::from_utf8_lossy(&s.state.blobs.get(&item.blob).await.unwrap()).to_string();
    assert!(raw.contains("In-Reply-To: <m0@x>"), "{raw}");
    let sent: Value = http
        .get(api("/messages?label=sent"))
        .bearer_auth(&meta)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(sent["messages"][0]["subject"], "Re: Trail map");

    // CORS preflight for browser apps.
    let r = http
        .request(reqwest::Method::OPTIONS, api("/messages"))
        .header("Origin", "https://app.example")
        .send()
        .await
        .unwrap();
    assert_eq!(r.headers()["access-control-allow-origin"], "*");
}
