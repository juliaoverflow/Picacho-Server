//! OIDC sign-in to the console (against a mock identity provider).
use axum::extract::{Form, Query, State as AxState};
use axum::response::{IntoResponse, Redirect};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use parking_lot::Mutex;
use picacho_server::config::Config;
use picacho_server::state::{AppState, State};
use serde_json::{json, Value};
use sha2::Digest;
use std::collections::HashMap;
use std::sync::Arc;

// ------------------------------------------------------------ mock IdP

#[derive(Default)]
struct Idp {
    base: String,
    /// Identity the next sign-in returns: (sub, email, groups).
    user: (String, String, Vec<String>),
    codes: HashMap<String, (String, String, String)>, // code -> (nonce, client_id, challenge)
}

type IdpState = Arc<Mutex<Idp>>;

async fn idp_discovery(AxState(s): AxState<IdpState>) -> Json<Value> {
    let b = s.lock().base.clone();
    Json(json!({"issuer": b, "authorization_endpoint": format!("{b}/authorize"), "token_endpoint": format!("{b}/token"),
        "token_endpoint_auth_methods_supported": ["client_secret_post"]}))
}

async fn idp_authorize(AxState(s): AxState<IdpState>, Query(q): Query<HashMap<String, String>>) -> impl IntoResponse {
    assert_eq!(q["code_challenge_method"], "S256");
    let code = format!("code{}", s.lock().codes.len());
    s.lock().codes.insert(code.clone(), (q["nonce"].clone(), q["client_id"].clone(), q["code_challenge"].clone()));
    Redirect::to(&format!("{}?code={code}&state={}", q["redirect_uri"], q["state"]))
}

async fn idp_token(AxState(s): AxState<IdpState>, Form(f): Form<HashMap<String, String>>) -> Json<Value> {
    let g = s.lock();
    let (nonce, client, challenge) = g.codes.get(&f["code"]).cloned().expect("known code");
    assert_eq!(f["client_secret"], "idp-secret");
    let computed = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(f["code_verifier"].as_bytes()));
    assert_eq!(computed, challenge, "PKCE");
    let b64 = |v: &Value| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v.to_string());
    let claims = json!({"iss": g.base, "aud": client, "sub": g.user.0, "email": g.user.1, "email_verified": true,
        "exp": chrono::Utc::now().timestamp() + 300, "nonce": nonce, "groups": g.user.2, "name": "From IdP"});
    let id_token = format!("{}.{}.sig", b64(&json!({"alg": "RS256"})), b64(&claims));
    Json(json!({"access_token": "idp-at", "token_type": "Bearer", "id_token": id_token}))
}

async fn start_idp() -> IdpState {
    let st: IdpState = Default::default();
    let app = Router::new()
        .route("/.well-known/openid-configuration", get(idp_discovery))
        .route("/authorize", get(idp_authorize))
        .route("/token", post(idp_token))
        .with_state(st.clone());
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    st.lock().base = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    st
}

// ------------------------------------------------------------ server

struct Srv {
    state: State,
    base: String,
    _dir: tempfile::TempDir,
}

async fn start(setup_done: bool) -> Srv {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    cfg.hostname = Some("mx.test".into());
    cfg.storage.data_dir = dir.path().to_path_buf();
    let state = AppState::new(cfg).await.unwrap();
    if setup_done {
        let mut s = (*state.settings()).clone();
        s.server.setup_complete = true;
        s.server.primary_domain = Some("example.test".into());
        state.save_settings(s).await.unwrap();
        let d = state.db.create_domain("example.test", "local", "").await.unwrap();
        let hash = picacho_server::auth::hash_password("Correct-Horse-9").unwrap();
        state.db.create_account("root@example.test", d, &hash, "Root", "admin", 0).await.unwrap();
        state.db.create_account("bob@example.test", d, &hash, "Bob", "user", 0).await.unwrap();
    }
    let web = picacho_server::web::serve(state.clone(), "127.0.0.1:0".parse().unwrap()).await.unwrap();
    Srv { state, base: format!("http://{web}"), _dir: dir }
}

fn oidc_cfg(issuer: &str) -> picacho_server::settings::OidcSettings {
    picacho_server::settings::OidcSettings {
        enabled: true,
        display_name: "Mock".into(),
        issuer: issuer.into(),
        client_id: "picacho".into(),
        client_secret: Some("idp-secret".into()),
        ..Default::default()
    }
}

fn client() -> reqwest::Client {
    reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap()
}

fn location(r: &reqwest::Response) -> String {
    r.headers().get("location").unwrap().to_str().unwrap().to_string()
}

/// Walk the redirect chain: start -> IdP -> callback. Returns (final location, cookie).
async fn sso(c: &reqwest::Client, first: &str) -> (String, Option<String>) {
    let r = c.get(first).send().await.unwrap();
    let to_idp = location(&r);
    let r = c.get(&to_idp).send().await.unwrap();
    let cb = location(&r);
    let r = c.get(&cb).send().await.unwrap();
    let cookie = r.headers().get("set-cookie").map(|v| v.to_str().unwrap().split(';').next().unwrap().to_string());
    (location(&r), cookie)
}

async fn me(c: &reqwest::Client, base: &str, cookie: &str) -> Value {
    c.get(format!("{base}/api/auth/me")).header("cookie", cookie).send().await.unwrap().json().await.unwrap()
}

#[tokio::test]
async fn oidc_sign_in_links_and_provisions() {
    let idp = start_idp().await;
    let s = start(true).await;
    let mut set = (*s.state.settings()).clone();
    set.auth.oidc = oidc_cfg(&idp.lock().base.clone());
    set.auth.oidc.admin_groups = vec!["mail-admins".into()];
    s.state.save_settings(set.clone()).await.unwrap();
    let c = client();

    // Existing mailbox user, matched by email and then linked by subject.
    idp.lock().user = ("sub-bob".into(), "bob@example.test".into(), vec![]);
    let (loc, cookie) = sso(&c, &format!("{}/api/auth/oidc/start?next=/me", s.base)).await;
    assert_eq!(loc, "/me");
    let m = me(&c, &s.base, &cookie.unwrap()).await;
    assert_eq!(m["email"], "bob@example.test");
    assert_eq!(m["sso_linked"], true);
    assert_eq!(m["role"], "user");

    // Same subject, new email at the IdP: still Bob's mailbox.
    idp.lock().user = ("sub-bob".into(), "robert@elsewhere.test".into(), vec![]);
    let (_, cookie) = sso(&c, &format!("{}/api/auth/oidc/start", s.base)).await;
    assert_eq!(me(&c, &s.base, &cookie.unwrap()).await["email"], "bob@example.test");

    // Unknown person without auto-provisioning: refused.
    idp.lock().user = ("sub-carol".into(), "carol@example.test".into(), vec![]);
    let (loc, cookie) = sso(&c, &format!("{}/api/auth/oidc/start", s.base)).await;
    assert!(loc.starts_with("/login?error="), "{loc}");
    assert!(cookie.is_none());

    // With auto-provisioning and the admin group: created as an admin.
    set.auth.oidc.auto_create_accounts = true;
    s.state.save_settings(set.clone()).await.unwrap();
    idp.lock().user = ("sub-carol".into(), "carol@example.test".into(), vec!["mail-admins".into()]);
    let (_, cookie) = sso(&c, &format!("{}/api/auth/oidc/start", s.base)).await;
    let m = me(&c, &s.base, &cookie.unwrap()).await;
    assert_eq!(m["email"], "carol@example.test");
    assert_eq!(m["role"], "admin");
    assert_eq!(m["has_password"], false);

    // Open redirects are refused.
    idp.lock().user = ("sub-bob".into(), "bob@example.test".into(), vec![]);
    let (loc, _) = sso(&c, &format!("{}/api/auth/oidc/start?next=//evil.example", s.base)).await;
    assert_eq!(loc, "/");

    // Password sign-in can be turned off.
    set.auth.web_password_login = false;
    s.state.save_settings(set).await.unwrap();
    let r = c
        .post(format!("{}/api/auth/login", s.base))
        .header("x-picacho", "1")
        .json(&json!({"email": "root@example.test", "password": "Correct-Horse-9"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
    let st: Value = c.get(format!("{}/api/status", s.base)).send().await.unwrap().json().await.unwrap();
    assert_eq!(st["auth"]["password"], false);
    assert_eq!(st["auth"]["oidc"]["name"], "Mock");
}

#[tokio::test]
async fn first_run_setup_with_oidc() {
    let idp = start_idp().await;
    let s = start(false).await;
    let key = s.state.setup_key.generate();
    let issuer = idp.lock().base.clone();
    idp.lock().user = ("sub-alex".into(), "alex@corp.test".into(), vec![]);
    let c = client();
    let r = c
        .post(format!("{}/api/setup/oidc/begin", s.base))
        .header("x-picacho", "1")
        .json(&json!({"key": key, "hostname": "mail.example.test", "domain": "example.test", "admin_local": "postmaster",
            "admin_name": "Alex", "auth": {"web_password_login": false, "mail_password_login": true,
            "oidc": {"issuer": issuer, "client_id": "picacho", "client_secret": "idp-secret", "display_name": "Corp"}}}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "{}", r.text().await.unwrap());
    let v: Value = r.json().await.unwrap();
    let r = c.get(v["redirect"].as_str().unwrap()).send().await.unwrap();
    let r = c.get(location(&r)).send().await.unwrap();
    assert_eq!(location(&r), "/");
    let cookie = r.headers().get("set-cookie").unwrap().to_str().unwrap().split(';').next().unwrap().to_string();
    let m = me(&c, &s.base, &cookie).await;
    assert_eq!(m["email"], "postmaster@example.test");
    assert_eq!(m["role"], "admin");
    assert_eq!(m["sso_linked"], true);
    assert!(!s.state.setup_required());
    assert!(!s.state.settings().auth.web_password_login);
    // The key is spent.
    assert!(s.state.setup_key.check(&key).is_err());
}
