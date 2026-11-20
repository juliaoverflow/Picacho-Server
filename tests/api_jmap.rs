//! Admin REST API (bearer tokens) and JMAP, against a real server.
use picacho_server::config::Config;
use picacho_server::state::AppState;
use serde_json::{json, Value};

struct Srv {
    base: String,
    _dir: tempfile::TempDir,
    admin_token: String,
}

async fn start() -> Srv {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    cfg.hostname = Some("mx.test".into());
    cfg.storage.data_dir = dir.path().to_path_buf();
    let state = AppState::new(cfg).await.unwrap();
    let mut s = (*state.settings()).clone();
    s.server.setup_complete = true;
    s.server.primary_domain = Some("example.test".into());
    s.security.verify_inbound = false;
    state.save_settings(s).await.unwrap();
    let d = state.db.create_domain("example.test", "local", "").await.unwrap();
    let hash = picacho_server::auth::hash_password("Correct-Horse-9").unwrap();
    let admin = state.db.create_account("root@example.test", d, &hash, "Root", "admin", 0).await.unwrap();
    state.db.create_account("bob@example.test", d, &hash, "Bob", "user", 0).await.unwrap();
    state.db.create_account("alice@example.test", d, &hash, "Alice", "user", 0).await.unwrap();
    let (secret, h, prefix) = picacho_server::auth::generate_token();
    state.db.create_token(admin, "ci", &h, &prefix, "admin", None).await.unwrap();
    let addr = picacho_server::web::serve(state.clone(), "127.0.0.1:0".parse().unwrap()).await.unwrap();
    Srv { base: format!("http://{addr}"), _dir: dir, admin_token: secret }
}

#[tokio::test]
async fn rest_api_with_tokens() {
    let s = start().await;
    let c = reqwest::Client::new();
    // No credentials, bad token.
    assert_eq!(c.get(format!("{}/api/v1/accounts", s.base)).send().await.unwrap().status(), 401);
    let r = c.get(format!("{}/api/v1/accounts", s.base)).bearer_auth("pmk_nope").send().await.unwrap();
    assert_eq!(r.status(), 401);
    // List, create, read by email, update, password, delete.
    let list: Value = c.get(format!("{}/api/v1/accounts", s.base)).bearer_auth(&s.admin_token).send().await.unwrap().json().await.unwrap();
    assert_eq!(list.as_array().unwrap().len(), 3);
    let r = c
        .post(format!("{}/api/v1/accounts", s.base))
        .bearer_auth(&s.admin_token)
        .json(&json!({"email": "carol@example.test", "password": "Another-Passw0rd", "display_name": "Carol", "quota_mb": 100}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "{}", r.text().await.unwrap());
    let a: Value = c.get(format!("{}/api/v1/accounts/carol@example.test", s.base)).bearer_auth(&s.admin_token).send().await.unwrap().json().await.unwrap();
    assert_eq!(a["quota_bytes"], 100 * 1024 * 1024);
    let r = c
        .patch(format!("{}/api/v1/accounts/carol@example.test", s.base))
        .bearer_auth(&s.admin_token)
        .json(&json!({"active": false, "forward_to": "x@elsewhere.test"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let r = c
        .post(format!("{}/api/v1/accounts/carol@example.test/password", s.base))
        .bearer_auth(&s.admin_token)
        .json(&json!({"password": "short"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);
    let r = c.delete(format!("{}/api/v1/accounts/carol@example.test", s.base)).bearer_auth(&s.admin_token).send().await.unwrap();
    assert_eq!(r.status(), 200);
    let d: Value = c.get(format!("{}/api/v1/domains/example.test", s.base)).bearer_auth(&s.admin_token).send().await.unwrap().json().await.unwrap();
    assert_eq!(d["name"], "example.test");
    let spec: Value = c.get(format!("{}/api/v1/openapi.json", s.base)).bearer_auth(&s.admin_token).send().await.unwrap().json().await.unwrap();
    assert_eq!(spec["openapi"], "3.1.0");
    // Cookie-less POST without the CSRF header but with a token is fine; with neither it's refused.
    let r = c.post(format!("{}/api/v1/aliases", s.base)).json(&json!({})).send().await.unwrap();
    assert_eq!(r.status(), 403);
}

async fn jmap(c: &reqwest::Client, base: &str, user: &str, calls: Value) -> Value {
    let using = json!(["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail", "urn:ietf:params:jmap:submission", "urn:ietf:params:jmap:quota"]);
    let r = c
        .post(format!("{base}/jmap/api"))
        .basic_auth(user, Some("Correct-Horse-9"))
        .json(&json!({"using": using, "methodCalls": calls}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    r.json().await.unwrap()
}

#[tokio::test]
async fn jmap_compose_send_and_receive() {
    let s = start().await;
    let c = reqwest::Client::new();
    let r = c.get(format!("{}/.well-known/jmap", s.base)).basic_auth("bob@example.test", Some("wrong")).send().await.unwrap();
    assert_eq!(r.status(), 401);
    let session: Value = c
        .get(format!("{}/.well-known/jmap", s.base))
        .basic_auth("bob@example.test", Some("Correct-Horse-9"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let acc = session["primaryAccounts"]["urn:ietf:params:jmap:mail"].as_str().unwrap().to_string();

    // Mailboxes, with a result reference feeding Mailbox/get.
    let r = jmap(&c, &s.base, "bob@example.test", json!([
        ["Mailbox/query", {"accountId": acc, "filter": {"role": "drafts"}}, "q"],
        ["Mailbox/get", {"accountId": acc, "#ids": {"resultOf": "q", "name": "Mailbox/query", "path": "/ids"}}, "g"],
        ["Mailbox/get", {"accountId": acc, "ids": null, "properties": ["name", "role"]}, "all"],
        ["Identity/get", {"accountId": acc}, "i"],
    ])).await;
    let drafts = r["methodResponses"][1][1]["list"][0]["id"].as_str().unwrap().to_string();
    assert_eq!(r["methodResponses"][1][1]["list"][0]["role"], "drafts");
    let mailboxes = r["methodResponses"][2][1]["list"].as_array().unwrap().clone();
    let sent = mailboxes.iter().find(|m| m["role"] == "sent").unwrap()["id"].as_str().unwrap().to_string();
    let identity = r["methodResponses"][3][1]["list"][0]["id"].as_str().unwrap().to_string();
    let state0 = r["sessionState"].as_str().unwrap().to_string();

    // Create a draft and send it, moving it to Sent on success.
    let r = jmap(&c, &s.base, "bob@example.test", json!([
        ["Email/set", {"accountId": acc, "create": {"d1": {
            "mailboxIds": {drafts.clone(): true}, "keywords": {"$draft": true, "$seen": true},
            "from": [{"name": "Bob", "email": "bob@example.test"}],
            "to": [{"name": "Alice Ünïcode", "email": "alice@example.test"}],
            "subject": "Lunch on Friday? ☀️",
            "textBody": [{"partId": "t", "type": "text/plain"}],
            "bodyValues": {"t": {"value": "Shall we try the new place = near the trailhead?"}}
        }}}, "c"],
        ["EmailSubmission/set", {"accountId": acc, "create": {"s1": {"identityId": identity, "emailId": "#d1"}},
            "onSuccessUpdateEmail": {"#s1": {"mailboxIds": {sent.clone(): true}, "keywords/$draft": null}}}, "s"],
    ])).await;
    let resp = &r["methodResponses"];
    assert!(resp[0][1]["created"]["d1"]["id"].is_string(), "{r}");
    assert!(resp[1][1]["created"]["s1"]["id"].is_string(), "{r}");
    assert_eq!(resp[2][0], "Email/set", "{r}");
    let email_id = resp[0][1]["created"]["d1"]["id"].as_str().unwrap().to_string();

    // Bob's copy moved to Sent without $draft; changes since the first state include it.
    let r = jmap(&c, &s.base, "bob@example.test", json!([
        ["Email/get", {"accountId": acc, "ids": [email_id], "properties": ["mailboxIds", "keywords", "subject"]}, "g"],
        ["Email/changes", {"accountId": acc, "sinceState": state0}, "ch"],
    ])).await;
    let e = &r["methodResponses"][0][1]["list"][0];
    assert_eq!(e["mailboxIds"][&sent], true, "{r}");
    assert!(e["keywords"].get("$draft").is_none(), "{r}");
    assert_eq!(e["subject"], "Lunch on Friday? ☀️");
    assert!(r["methodResponses"][1][1]["created"].as_array().unwrap().iter().any(|x| x == &json!(email_id)));

    // Alice received it; read body values, mark seen.
    let session: Value = c.get(format!("{}/.well-known/jmap", s.base)).basic_auth("alice@example.test", Some("Correct-Horse-9")).send().await.unwrap().json().await.unwrap();
    let alice = session["primaryAccounts"]["urn:ietf:params:jmap:mail"].as_str().unwrap().to_string();
    let r = jmap(&c, &s.base, "alice@example.test", json!([
        ["Email/query", {"accountId": alice, "filter": {"subject": "Lunch"}, "calculateTotal": true}, "q"],
        ["Email/get", {"accountId": alice, "#ids": {"resultOf": "q", "name": "Email/query", "path": "/ids"},
            "properties": ["from", "to", "subject", "textBody", "bodyValues", "preview", "keywords"], "fetchTextBodyValues": true}, "g"],
    ])).await;
    assert_eq!(r["methodResponses"][0][1]["total"], 1, "{r}");
    let e = &r["methodResponses"][1][1]["list"][0];
    assert_eq!(e["to"][0]["name"], "Alice Ünïcode", "{r}");
    let part = e["textBody"][0]["partId"].as_str().unwrap();
    assert!(e["bodyValues"][part]["value"].as_str().unwrap().contains("new place = near"), "{r}");
    assert!(e["keywords"].as_object().unwrap().is_empty());
    let id = e["id"].as_str().unwrap().to_string();
    let r = jmap(&c, &s.base, "alice@example.test", json!([
        ["Email/set", {"accountId": alice, "update": {id.clone(): {"keywords/$seen": true}}}, "u"],
        ["Email/get", {"accountId": alice, "ids": [id], "properties": ["keywords"]}, "g"],
        ["Quota/get", {"accountId": alice, "ids": null}, "qq"],
    ])).await;
    assert_eq!(r["methodResponses"][1][1]["list"][0]["keywords"]["$seen"], true, "{r}");
    assert!(r["methodResponses"][2][1]["list"][0]["used"].as_i64().unwrap() > 0);

    // Accounts are isolated: Bob can't read Alice's email.
    let r = jmap(&c, &s.base, "bob@example.test", json!([["Email/get", {"accountId": alice, "ids": ["e1"]}, "x"]])).await;
    assert_eq!(r["methodResponses"][0][0], "error");
}
