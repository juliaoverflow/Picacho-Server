//! Contact directory: groups and contact details from single sign-on, and
//! the read-only `addressbooks/<me>/directory/` book filtered by rules.
use axum::extract::{Form, Query, State as AxState};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use parking_lot::Mutex;
use picacho_server::config::Config;
use picacho_server::settings::{DirectoryRule, ProfileClaim};
use picacho_server::state::{AppState, State};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;

// ------------------------------------------------------------ mock IdP

#[derive(Default)]
struct Idp {
    base: String,
    /// The next sign-in: ID-token claims and userinfo claims (sub/iss added).
    id_claims: Value,
    userinfo: Value,
    codes: HashMap<String, (String, String)>, // code -> (nonce, client_id)
}

type IdpState = Arc<Mutex<Idp>>;

async fn idp_discovery(AxState(s): AxState<IdpState>) -> Json<Value> {
    let b = s.lock().base.clone();
    Json(json!({"issuer": b, "authorization_endpoint": format!("{b}/authorize"), "token_endpoint": format!("{b}/token"),
        "userinfo_endpoint": format!("{b}/userinfo"), "token_endpoint_auth_methods_supported": ["client_secret_post"]}))
}

async fn idp_authorize(AxState(s): AxState<IdpState>, Query(q): Query<HashMap<String, String>>) -> impl IntoResponse {
    let code = format!("code{}", s.lock().codes.len());
    s.lock().codes.insert(code.clone(), (q["nonce"].clone(), q["client_id"].clone()));
    Redirect::to(&format!("{}?code={code}&state={}", q["redirect_uri"], q["state"]))
}

async fn idp_token(AxState(s): AxState<IdpState>, Form(f): Form<HashMap<String, String>>) -> Json<Value> {
    let g = s.lock();
    let (nonce, client) = g.codes.get(&f["code"]).cloned().expect("known code");
    let mut claims = g.id_claims.clone();
    let o = claims.as_object_mut().unwrap();
    o.insert("iss".into(), json!(g.base));
    o.insert("aud".into(), json!(client));
    o.insert("nonce".into(), json!(nonce));
    o.insert("email_verified".into(), json!(true));
    o.insert("exp".into(), json!(chrono::Utc::now().timestamp() + 300));
    let b64 = |v: &Value| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v.to_string());
    let id_token = format!("{}.{}.sig", b64(&json!({"alg": "RS256"})), b64(&claims));
    Json(json!({"access_token": "idp-at", "token_type": "Bearer", "id_token": id_token}))
}

async fn idp_userinfo(AxState(s): AxState<IdpState>, h: HeaderMap) -> Json<Value> {
    assert_eq!(h.get("authorization").unwrap().to_str().unwrap(), "Bearer idp-at");
    let g = s.lock();
    let mut u = g.userinfo.clone();
    u["sub"] = g.id_claims["sub"].clone();
    Json(u)
}

async fn start_idp() -> IdpState {
    let st: IdpState = Default::default();
    let app = Router::new()
        .route("/.well-known/openid-configuration", get(idp_discovery))
        .route("/authorize", get(idp_authorize))
        .route("/token", post(idp_token))
        .route("/userinfo", get(idp_userinfo))
        .with_state(st.clone());
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    st.lock().base = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    st
}

// ------------------------------------------------------------ server

const PW: &str = "Correct-Horse-9";

struct Srv {
    state: State,
    base: String,
    _dir: tempfile::TempDir,
}

async fn start() -> Srv {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config { hostname: Some("mx.test".into()), ..Default::default() };
    cfg.storage.data_dir = dir.path().to_path_buf();
    let state = AppState::new(cfg).await.unwrap();
    let mut s = (*state.settings()).clone();
    s.server.setup_complete = true;
    s.server.primary_domain = Some("example.test".into());
    s.security.require_tls_for_auth = false;
    state.save_settings(s).await.unwrap();
    let d = state.db.create_domain("example.test", "local", "").await.unwrap();
    let hash = picacho_server::auth::hash_password(PW).unwrap();
    for (e, n, r) in [("root@example.test", "Root", "admin"), ("mom@example.test", "Mom", "user"), ("kid@example.test", "Kid", "user"), ("boss@example.test", "Boss", "user")] {
        state.db.create_account(e, d, &hash, n, r, 0).await.unwrap();
    }
    let web = picacho_server::web::serve(state.clone(), "127.0.0.1:0".parse().unwrap()).await.unwrap();
    Srv { state, base: format!("http://{web}"), _dir: dir }
}

fn client() -> reqwest::Client {
    reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap()
}

/// Sign in through the mock IdP as whoever `id_claims` says.
async fn sso(c: &reqwest::Client, base: &str) -> Option<String> {
    let loc = |r: &reqwest::Response| r.headers().get("location").unwrap().to_str().unwrap().to_string();
    let r = c.get(format!("{base}/api/auth/oidc/start")).send().await.unwrap();
    let r = c.get(loc(&r)).send().await.unwrap();
    let r = c.get(loc(&r)).send().await.unwrap();
    r.headers().get("set-cookie").map(|v| v.to_str().unwrap().split(';').next().unwrap().to_string())
}

async fn dav(s: &Srv, user: &str, method: &str, path: &str, depth: &str, body: &str) -> (u16, String) {
    let mut r = client()
        .request(method.parse().unwrap(), format!("{}{path}", s.base))
        .basic_auth(user, Some(PW))
        .header("content-type", if method == "PUT" { "text/vcard" } else { "application/xml" })
        .body(body.to_string());
    if !depth.is_empty() {
        r = r.header("depth", depth);
    }
    let r = r.send().await.unwrap();
    (r.status().as_u16(), r.text().await.unwrap())
}

fn book(user: &str) -> String {
    format!("/dav/addressbooks/{user}/directory/")
}

#[tokio::test]
async fn directory_from_sso_groups_and_claims() {
    let idp = start_idp().await;
    let s = start().await;
    let mut set = (*s.state.settings()).clone();
    set.auth.oidc.enabled = true;
    set.auth.oidc.issuer = idp.lock().base.clone();
    set.auth.oidc.client_id = "picacho".into();
    set.auth.oidc.client_secret = Some("idp-secret".into());
    set.auth.oidc.profile_claims.push(ProfileClaim { field: "title".into(), claim: "attributes.title".into() });
    s.state.save_settings(set.clone()).await.unwrap();
    let c = client();

    // Groups in the ID token; phone and a nested custom claim only in userinfo.
    let sign_in = |sub: &str, email: &str, groups: Value, info: Value| {
        let mut g = idp.lock();
        g.id_claims = json!({"sub": sub, "email": email, "name": email, "groups": groups});
        g.userinfo = info;
    };
    sign_in("s-mom", "mom@example.test", json!(["family"]), json!({"phone_number": "+1 520 555 0101", "attributes": {"title": "Chef"}}));
    assert!(sso(&c, &s.base).await.is_some());
    sign_in("s-kid", "kid@example.test", json!(["Family"]), json!({"phone_number": ["+1 520 555 0102", "+1 520 555 0103"]}));
    assert!(sso(&c, &s.base).await.is_some());
    sign_in("s-boss", "boss@example.test", json!(["work"]), json!({"phone_number": "+1 520 555 0199"}));
    assert!(sso(&c, &s.base).await.is_some());

    let mom = s.state.db.account_by_email("mom@example.test").await.unwrap().unwrap();
    let kid = s.state.db.account_by_email("kid@example.test").await.unwrap().unwrap();
    assert_eq!(s.state.db.account_groups(mom.id).await.unwrap(), vec!["family".to_string()]);
    let p = s.state.db.account_profile(mom.id).await.unwrap();
    assert_eq!(p["phone"], vec!["+1 520 555 0101".to_string()]);
    assert_eq!(p["title"], vec!["Chef".to_string()]);
    assert_eq!(s.state.db.account_profile(kid.id).await.unwrap()["phone"].len(), 2);

    // Off by default: no directory book.
    let (st, body) = dav(&s, "mom@example.test", "PROPFIND", "/dav/addressbooks/mom@example.test/", "1", "").await;
    assert_eq!(st, 207);
    assert!(!body.contains("/directory/"), "{body}");
    let (st, _) = dav(&s, "mom@example.test", "GET", &format!("{}{}.vcf", book("mom@example.test"), kid.id), "", "").await;
    assert_eq!(st, 404);

    // Family sees family with name and email; phone only through a second rule.
    set.directory.enabled = true;
    set.directory.rules = vec![DirectoryRule { viewers: vec!["family".into()], members: vec!["family".into()], fields: vec!["name".into(), "email".into()] }];
    s.state.save_settings(set.clone()).await.unwrap();
    let (st, body) = dav(&s, "mom@example.test", "PROPFIND", "/dav/addressbooks/mom@example.test/", "1", "").await;
    assert_eq!(st, 207);
    assert!(body.contains(&book("mom@example.test")), "{body}");
    let (st, body) = dav(&s, "mom@example.test", "PROPFIND", &book("mom@example.test"), "1", "").await;
    assert_eq!(st, 207);
    assert!(body.contains(&format!("{}.vcf", kid.id)) && body.contains(&format!("{}.vcf", mom.id)), "{body}");
    let boss = s.state.db.account_by_email("boss@example.test").await.unwrap().unwrap();
    assert!(!body.contains(&format!("/{}.vcf", boss.id)), "{body}");
    let privs = "<D:propfind xmlns:D=\"DAV:\"><D:prop><D:current-user-privilege-set/><D:supportedlock/></D:prop></D:propfind>";
    let (_, body) = dav(&s, "mom@example.test", "PROPFIND", &book("mom@example.test"), "0", privs).await;
    assert!(body.contains("<D:read/>") && !body.contains("<D:write/>") && !body.contains("<D:all/>"), "{body}");
    let (st, card) = dav(&s, "mom@example.test", "GET", &format!("{}{}.vcf", book("mom@example.test"), kid.id), "", "").await;
    assert_eq!(st, 200);
    assert!(card.contains("EMAIL;PREF=1:kid@example.test") && !card.contains("TEL"), "{card}");
    // Not visible: 404 even with the right id.
    let (st, _) = dav(&s, "mom@example.test", "GET", &format!("{}{}.vcf", book("mom@example.test"), boss.id), "", "").await;
    assert_eq!(st, 404);
    // Boss is in no rule: an empty book.
    let (_, body) = dav(&s, "boss@example.test", "PROPFIND", &book("boss@example.test"), "1", "").await;
    assert!(!body.contains(".vcf"), "{body}");

    set.directory.rules.push(DirectoryRule { viewers: vec!["family".into()], members: vec!["family".into()], fields: vec!["phone".into()] });
    s.state.save_settings(set.clone()).await.unwrap();
    let (_, card) = dav(&s, "mom@example.test", "GET", &format!("{}{}.vcf", book("mom@example.test"), kid.id), "", "").await;
    assert!(card.contains("TEL;VALUE=text;TYPE=voice:+1 520 555 0102") && card.contains("0103"), "{card}");
    assert!(!card.contains("TITLE"), "{card}");

    // Queries and multiget go through the same filter.
    let q = "<C:addressbook-query xmlns:D=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:carddav\"><D:prop><D:getetag/><C:address-data/></D:prop></C:addressbook-query>";
    let (st, body) = dav(&s, "mom@example.test", "REPORT", &book("mom@example.test"), "1", q).await;
    assert_eq!(st, 207);
    assert!(body.contains("kid@example.test") && !body.contains("boss@example.test"), "{body}");
    let mg = format!("<C:addressbook-multiget xmlns:D=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:carddav\"><D:prop><C:address-data/></D:prop><D:href>{0}{1}.vcf</D:href><D:href>{0}{2}.vcf</D:href></C:addressbook-multiget>", book("mom@example.test"), kid.id, boss.id);
    let (_, body) = dav(&s, "mom@example.test", "REPORT", &book("mom@example.test"), "", &mg).await;
    assert!(body.contains("kid@example.test") && !body.contains("boss@example.test") && body.contains("404"), "{body}");

    // sync-collection: full list, then nothing while unchanged, then a resync.
    let sc = |tok: &str| format!("<D:sync-collection xmlns:D=\"DAV:\"><D:sync-token>{tok}</D:sync-token><D:sync-level>1</D:sync-level><D:prop><D:getetag/></D:prop></D:sync-collection>");
    let (st, body) = dav(&s, "mom@example.test", "REPORT", &book("mom@example.test"), "", &sc("")).await;
    assert_eq!(st, 207);
    let tok = body.split("<D:sync-token>").nth(1).unwrap().split('<').next().unwrap().to_string();
    assert!(body.contains(&format!("{}.vcf", kid.id)));
    let (_, body) = dav(&s, "mom@example.test", "REPORT", &book("mom@example.test"), "", &sc(&tok)).await;
    assert!(!body.contains(".vcf"), "{body}");
    // Dropping the phone rule changes both cards: only they come back, with a new token.
    set.directory.rules.pop();
    s.state.save_settings(set.clone()).await.unwrap();
    let (st, body) = dav(&s, "mom@example.test", "REPORT", &book("mom@example.test"), "", &sc(&tok)).await;
    assert_eq!(st, 207, "{body}");
    assert!(body.contains(&format!("{}.vcf", kid.id)) && body.contains("getetag"), "{body}");
    let tok2 = body.split("<D:sync-token>").nth(1).unwrap().split('<').next().unwrap().to_string();
    assert_ne!(tok, tok2);
    // Someone leaving the group shows up as removed (404) in the next sync.
    s.state.db.set_account_groups(kid.id, "oidc", &[]).await.unwrap();
    let (_, body) = dav(&s, "mom@example.test", "REPORT", &book("mom@example.test"), "", &sc(&tok2)).await;
    assert!(body.contains(&format!("{}.vcf</D:href><D:status>HTTP/1.1 404", kid.id)), "{body}");
    let tok3 = body.split("<D:sync-token>").nth(1).unwrap().split('<').next().unwrap().to_string();
    // An old token still works and reports the removal too.
    let (_, body) = dav(&s, "mom@example.test", "REPORT", &book("mom@example.test"), "", &sc(&tok)).await;
    assert!(body.contains("404"), "{body}");
    // Forged or someone else's tokens are refused.
    let forged = tok3.replace(&format!("/{}-", mom.id), &format!("/{}-", kid.id));
    let (st, _) = dav(&s, "mom@example.test", "REPORT", &book("mom@example.test"), "", &sc(&forged)).await;
    assert_eq!(st, 403);
    let (st, _) = dav(&s, "mom@example.test", "REPORT", &book("mom@example.test"), "", &sc(&format!("{tok3}9"))).await;
    assert_eq!(st, 403);
    s.state.db.set_account_groups(kid.id, "oidc", &["Family".into()]).await.unwrap();

    // Read-only, whatever the method.
    let card = "BEGIN:VCARD\r\nVERSION:3.0\r\nUID:x\r\nFN:X\r\nEND:VCARD\r\n";
    for (m, p, b) in [
        ("PUT", format!("{}new.vcf", book("mom@example.test")), card.to_string()),
        ("DELETE", format!("{}{}.vcf", book("mom@example.test"), kid.id), String::new()),
        ("DELETE", book("mom@example.test"), String::new()),
        ("MKCOL", format!("{}sub/", book("mom@example.test")), String::new()),
        ("PROPPATCH", book("mom@example.test"), "<D:propertyupdate xmlns:D=\"DAV:\"><D:set><D:prop><D:displayname>X</D:displayname></D:prop></D:set></D:propertyupdate>".into()),
    ] {
        let (st, _) = dav(&s, "mom@example.test", m, &p, "", &b).await;
        assert_eq!(st, 403, "{m} {p}");
    }
    let r = client()
        .request("COPY".parse().unwrap(), format!("{}/dav/addressbooks/mom@example.test/contacts/", s.base))
        .basic_auth("mom@example.test", Some(PW))
        .header("destination", format!("{}{}", s.base, book("mom@example.test")))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 403);

    // Someone else's directory isn't reachable.
    let (st, _) = dav(&s, "boss@example.test", "PROPFIND", &book("mom@example.test"), "1", "").await;
    assert_eq!(st, 403);

    // Principal search finds visible people only, including people who never
    // used calendars or contacts (kid hasn't signed in to DAV yet).
    assert!(s.state.db.dav_principal_for_account(kid.id).await.unwrap().is_none());
    let ps = |m: &str| format!("<D:principal-property-search xmlns:D=\"DAV:\"><D:property-search><D:prop><D:displayname/></D:prop><D:match>{m}</D:match></D:property-search><D:prop><D:displayname/></D:prop></D:principal-property-search>");
    let (_, body) = dav(&s, "mom@example.test", "REPORT", "/dav/principals/", "0", &ps("kid")).await;
    assert!(body.contains("/dav/principals/kid@example.test/"), "{body}");
    let (_, body) = dav(&s, "mom@example.test", "REPORT", "/dav/principals/", "0", &ps("boss")).await;
    assert!(!body.contains("boss@"), "{body}");
    // principal-match is about oneself only.
    let pm = "<D:principal-match xmlns:D=\"DAV:\"><D:self/><D:prop><D:displayname/></D:prop></D:principal-match>";
    let (_, body) = dav(&s, "mom@example.test", "REPORT", "/dav/principals/", "0", pm).await;
    assert!(!body.contains("kid@"), "{body}");
    // A query on the address-book home covers the directory, filtered the same way.
    let (_, body) = dav(&s, "mom@example.test", "REPORT", "/dav/addressbooks/mom@example.test/", "1", q).await;
    assert!(body.contains("kid@example.test") && !body.contains("boss@example.test"), "{body}");
    let (_, body) = dav(&s, "boss@example.test", "REPORT", "/dav/addressbooks/boss@example.test/", "1", q).await;
    assert!(!body.contains("mom@example.test") && !body.contains("kid@example.test"), "{body}");

    // JMAP for Contacts: the same directory as a read-only address book.
    let jmap = |user: &'static str, calls: Value| {
        let base = s.base.clone();
        async move {
            let c = client();
            let sess: Value = c.get(format!("{base}/.well-known/jmap")).basic_auth(user, Some(PW)).send().await.unwrap().json().await.unwrap();
            let acc = sess["primaryAccounts"]["urn:ietf:params:jmap:contacts"].as_str().unwrap().to_string();
            let calls: Vec<Value> = calls.as_array().unwrap().iter().map(|c| {
                let mut c = c.clone();
                c[1]["accountId"] = json!(acc);
                c
            }).collect();
            let r: Value = c.post(format!("{base}/jmap/api")).basic_auth(user, Some(PW))
                .json(&json!({"using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:contacts"], "methodCalls": calls}))
                .send().await.unwrap().json().await.unwrap();
            r["methodResponses"].as_array().cloned().unwrap_or_else(|| panic!("{r}"))
        }
    };
    let r = jmap("mom@example.test", json!([["AddressBook/get", {"ids": null}, "0"], ["ContactCard/get", {"ids": null}, "1"]])).await;
    let books = r[0][1]["list"].as_array().unwrap();
    let dir = books.iter().find(|b| b["id"] == "bdir").unwrap_or_else(|| panic!("{books:?}"));
    assert_eq!(dir["myRights"]["mayWrite"], false);
    let cards = r[1][1]["list"].as_array().unwrap();
    let kid_card = cards.iter().find(|c| c["id"] == format!("kd{}", kid.id)).unwrap_or_else(|| panic!("{cards:?}"));
    assert_eq!(kid_card["addressBookIds"]["bdir"], true);
    assert!(kid_card.to_string().contains("kid@example.test") && !kid_card.to_string().contains("+1 520"), "{kid_card}");
    assert!(!cards.iter().any(|c| c["id"] == format!("kd{}", boss.id)), "{cards:?}");
    let state = r[1][1]["state"].as_str().unwrap().to_string();
    assert!(state.contains('.'), "{state}");
    // Writes are refused; copying a directory card into one's own book works.
    let own = books.iter().find(|b| b["id"] != "bdir").unwrap()["id"].as_str().unwrap().to_string();
    let r = jmap("mom@example.test", json!([
        ["ContactCard/set", {"create": {"x": {"addressBookIds": {"bdir": true}, "name": {"full": "X"}}},
            "update": {format!("kd{}", kid.id): {"name/full": "Y"}}, "destroy": [format!("kd{}", kid.id)]}, "0"],
        ["AddressBook/set", {"destroy": ["bdir"], "update": {"bdir": {"name": "Mine"}}}, "1"],
        ["ContactCard/query", {"filter": {"email": "kid@"}}, "2"],
    ])).await;
    assert_eq!(r[0][1]["notCreated"]["x"]["type"], "forbidden", "{}", r[0][1]);
    assert_eq!(r[0][1]["notUpdated"][format!("kd{}", kid.id)]["type"], "forbidden");
    assert_eq!(r[0][1]["notDestroyed"][format!("kd{}", kid.id)]["type"], "forbidden");
    assert_eq!(r[1][1]["notDestroyed"]["bdir"]["type"], "forbidden", "{}", r[1][1]);
    assert_eq!(r[1][1]["notUpdated"]["bdir"]["type"], "forbidden", "{}", r[1][1]);
    assert!(r[2][1]["ids"].as_array().unwrap().iter().any(|i| *i == format!("kd{}", kid.id)), "{}", r[2][1]);
    // Boss can't reach mom's directory cards by id.
    let r = jmap("boss@example.test", json!([["ContactCard/get", {"ids": [format!("kd{}", kid.id)]}, "0"]])).await;
    assert_eq!(r[0][1]["notFound"][0], format!("kd{}", kid.id), "{}", r[0][1]);
    // Changes: kid leaving the family is reported as destroyed.
    s.state.db.set_account_groups(kid.id, "oidc", &[]).await.unwrap();
    let r = jmap("mom@example.test", json!([["ContactCard/changes", {"sinceState": state}, "0"]])).await;
    assert!(r[0][1]["destroyed"].as_array().unwrap().iter().any(|i| *i == format!("kd{}", kid.id)), "{}", r[0][1]);
    let st2 = r[0][1]["newState"].as_str().unwrap().to_string();
    assert_ne!(st2, state);
    let r = jmap("mom@example.test", json!([["ContactCard/changes", {"sinceState": st2}, "0"]])).await;
    assert!(r[0][1]["destroyed"].as_array().unwrap().is_empty() && r[0][1]["updated"].as_array().unwrap().is_empty(), "{}", r[0][1]);
    s.state.db.set_account_groups(kid.id, "oidc", &["Family".into()]).await.unwrap();
    // Back in the family: created (newly visible), not updated.
    let r = jmap("mom@example.test", json!([["ContactCard/changes", {"sinceState": st2}, "0"]])).await;
    assert!(r[0][1]["created"].as_array().unwrap().iter().any(|i| *i == format!("kd{}", kid.id)), "{}", r[0][1]);
    assert!(r[0][1]["updated"].as_array().unwrap().is_empty(), "{}", r[0][1]);
    let st3 = r[0][1]["newState"].as_str().unwrap().to_string();
    // A change to someone already visible is an update.
    let mut with_phone = set.clone();
    with_phone.directory.rules.push(DirectoryRule { viewers: vec!["family".into()], members: vec!["family".into()], fields: vec!["phone".into()] });
    s.state.save_settings(with_phone).await.unwrap();
    let r = jmap("mom@example.test", json!([["ContactCard/changes", {"sinceState": st3}, "0"]])).await;
    assert!(r[0][1]["updated"].as_array().unwrap().iter().any(|i| *i == format!("kd{}", kid.id)), "{}", r[0][1]);
    assert!(r[0][1]["created"].as_array().unwrap().is_empty(), "{}", r[0][1]);
    s.state.save_settings(set.clone()).await.unwrap();
    // Someone who appeared and left since the client's state isn't reported at all.
    let st4 = jmap("mom@example.test", json!([["ContactCard/get", {"ids": []}, "0"]])).await[0][1]["state"].as_str().unwrap().to_string();
    s.state.db.set_account_groups(boss.id, "manual", &["family".into()]).await.unwrap();
    jmap("mom@example.test", json!([["ContactCard/get", {"ids": []}, "0"]])).await;
    s.state.db.set_account_groups(boss.id, "manual", &[]).await.unwrap();
    let r = jmap("mom@example.test", json!([["ContactCard/changes", {"sinceState": st4}, "0"]])).await;
    assert!(!r[0][1].to_string().contains(&format!("kd{}", boss.id)), "{}", r[0][1]);
    // EventSource push: only the asked types, and directory changes announce ContactCard.
    let es = client().get(format!("{}/jmap/eventsource?types=ContactCard&closeafter=state&ping=0", s.base)).basic_auth("mom@example.test", Some(PW)).send().await.unwrap();
    assert_eq!(es.status(), 200);
    let reader = tokio::spawn(async move { es.text().await.unwrap() });
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    s.state.db.set_account_groups(boss.id, "manual", &["family".into()]).await.unwrap();
    let text = tokio::time::timeout(std::time::Duration::from_secs(15), reader).await.expect("push within 15s").unwrap();
    s.state.db.set_account_groups(boss.id, "manual", &[]).await.unwrap();
    let data = text.lines().find_map(|l| l.strip_prefix("data: ")).unwrap_or_else(|| panic!("{text}"));
    let ev: Value = serde_json::from_str(data).unwrap();
    let changed = ev["changed"].as_object().unwrap().values().next().unwrap().as_object().unwrap();
    assert_eq!(changed.keys().collect::<Vec<_>>(), vec!["ContactCard"], "{ev}");
    assert!(changed["ContactCard"].as_str().unwrap().contains('.'), "{ev}");
    // A state from before the directory was on: the book appears as created.
    let r = jmap("mom@example.test", json!([["AddressBook/changes", {"sinceState": st2.split('.').next().unwrap()}, "0"]])).await;
    assert!(r[0][1]["created"].as_array().unwrap().iter().any(|i| *i == "bdir"), "{}", r[0][1]);
    let r = jmap("mom@example.test", json!([["ContactCard/copy", {"fromAccountId": r[0][1]["accountId"], "create": {"c": {"id": format!("kd{}", kid.id), "addressBookIds": {own.clone(): true}}}}, "0"]])).await;
    assert!(r[0][1]["created"]["c"]["id"].as_str().unwrap().starts_with('k'), "{}", r[0][1]);

    // Absent claims keep stored values; present-but-empty clears them.
    sign_in("s-mom", "mom@example.test", json!(["family"]), json!({}));
    sso(&c, &s.base).await.unwrap();
    assert_eq!(s.state.db.account_profile(mom.id).await.unwrap()["phone"].len(), 1);
    sign_in("s-mom", "mom@example.test", json!(["family"]), json!({"phone_number": "", "attributes": {}}));
    sso(&c, &s.base).await.unwrap();
    let p = s.state.db.account_profile(mom.id).await.unwrap();
    assert!(!p.contains_key("phone") && p.contains_key("title"), "{p:?}");

    // Admin API: preview, groups, profile.
    let r = client().post(format!("{}/api/auth/login", s.base)).header("x-picacho", "1").json(&json!({"email": "root@example.test", "password": PW})).send().await.unwrap();
    let cookie = r.headers().get("set-cookie").unwrap().to_str().unwrap().split(';').next().unwrap().to_string();
    let api = |m: reqwest::Method, p: &str| client().request(m, format!("{}{p}", s.base)).header("cookie", &cookie).header("x-picacho", "1");
    let v: Value = api(reqwest::Method::GET, "/api/admin/directory/preview?account=boss@example.test").send().await.unwrap().json().await.unwrap();
    assert_eq!(v["people"].as_array().unwrap().len(), 0, "{v}");
    let r = api(reqwest::Method::PUT, "/api/admin/accounts/boss@example.test/groups").json(&json!({"groups": ["family"]})).send().await.unwrap();
    assert_eq!(r.status(), 200);
    let v: Value = r.json().await.unwrap();
    assert!(v["groups"].as_array().unwrap().iter().any(|g| g["name"] == "family" && g["source"] == "manual"), "{v}");
    assert!(v["groups"].as_array().unwrap().iter().any(|g| g["name"] == "work" && g["source"] == "oidc"), "{v}");
    let v: Value = api(reqwest::Method::GET, "/api/admin/directory/preview?account=boss@example.test").send().await.unwrap().json().await.unwrap();
    assert_eq!(v["people"].as_array().unwrap().len(), 3, "{v}");
    assert!(v["people"][0]["person"].get("phone").is_none(), "{v}");
    let v: Value = api(reqwest::Method::GET, "/api/admin/directory/preview?account=root@example.test").send().await.unwrap().json().await.unwrap();
    assert_eq!(v["full_access"], true);
    assert_eq!(v["people"].as_array().unwrap().len(), 4, "{v}");
    let v: Value = api(reqwest::Method::GET, &format!("/api/admin/accounts/{}/profile", kid.id)).send().await.unwrap().json().await.unwrap();
    assert_eq!(v["profile"]["phone"].as_array().unwrap().len(), 2, "{v}");
    // Not for non-admins.
    let r = client().post(format!("{}/api/auth/login", s.base)).header("x-picacho", "1").json(&json!({"email": "kid@example.test", "password": PW})).send().await.unwrap();
    let kc = r.headers().get("set-cookie").unwrap().to_str().unwrap().split(';').next().unwrap().to_string();
    let r = client().get(format!("{}/api/admin/directory/preview?account=root@example.test", s.base)).header("cookie", kc).send().await.unwrap();
    assert_eq!(r.status(), 403);

    // An admin sees everyone with every field over CardDAV too.
    let (_, card) = dav(&s, "root@example.test", "GET", &format!("{}{}.vcf", book("root@example.test"), mom.id), "", "").await;
    assert!(card.contains("TITLE:Chef") && card.contains("CATEGORIES:family"), "{card}");
}
