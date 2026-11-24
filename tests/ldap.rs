//! LDAP directory sign-in, against a small in-process LDAP server.
use bytes::BytesMut;
use ldap3::asn1::{parse_tag, write, ASNTag, Enumerated, Integer, OctetString, Sequence, Set, StructureTag, Tag, TagClass, PL};
use picacho_server::auth::{login_service, AuthError, Service};
use picacho_server::config::Config;
use picacho_server::settings::LdapSettings;
use picacho_server::state::{AppState, State};
use serde_json::{json, Value};
use std::net::IpAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// ------------------------------------------------------------ mock directory

struct Entry {
    dn: &'static str,
    password: &'static str,
    attrs: Vec<(&'static str, Vec<&'static str>)>,
}

fn directory() -> Arc<Vec<Entry>> {
    Arc::new(vec![
        Entry { dn: "cn=svc,dc=test", password: "svc-pw", attrs: vec![] },
        Entry {
            dn: "uid=sam,ou=people,dc=test",
            password: "sam-pw",
            attrs: vec![
                ("uid", vec!["sam"]),
                ("mail", vec!["sam@example.test"]),
                ("cn", vec!["Sam Doe"]),
                ("memberOf", vec!["cn=mail-admins,ou=groups,dc=test"]),
                ("telephoneNumber", vec!["+1 520 555 0150"]),
                ("mobile", vec!["+1 520 555 0151"]),
                ("title", vec!["Postmaster"]),
            ],
        },
        Entry { dn: "uid=bob,ou=people,dc=test", password: "bob-dir-pw", attrs: vec![("uid", vec!["bob"]), ("mail", vec!["bob@example.test"])] },
        Entry { dn: "uid=carol,ou=people,dc=test", password: "carol-pw", attrs: vec![("uid", vec!["carol"]), ("mail", vec!["carol@example.test"])] },
        Entry { dn: "uid=other,ou=people,dc=test", password: "other-pw", attrs: vec![("uid", vec!["other"]), ("mail", vec!["other@elsewhere.test"])] },
        Entry { dn: "cn=staff,ou=groups,dc=test", password: "", attrs: vec![("cn", vec!["staff"]), ("member", vec!["uid=sam,ou=people,dc=test"])] },
    ])
}

fn os(s: &str) -> Tag {
    Tag::OctetString(OctetString { inner: s.as_bytes().to_vec(), ..Default::default() })
}

fn ldap_result(app: u64, rc: i64) -> Tag {
    Tag::Sequence(Sequence {
        id: app,
        class: TagClass::Application,
        inner: vec![Tag::Enumerated(Enumerated { inner: rc, ..Default::default() }), os(""), os("")],
    })
}

fn frame(id: i64, op: Tag) -> Vec<u8> {
    let t = Tag::Sequence(Sequence { inner: vec![Tag::Integer(Integer { inner: id, ..Default::default() }), op], ..Default::default() });
    let mut b = BytesMut::new();
    write::encode_into(&mut b, t.into_structure()).unwrap();
    b.to_vec()
}

fn prim(t: &StructureTag) -> String {
    match &t.payload {
        PL::P(v) => String::from_utf8_lossy(v).into_owned(),
        PL::C(_) => String::new(),
    }
}

/// Equality assertions (attr, value) anywhere in a filter.
fn equalities(t: &StructureTag, out: &mut Vec<(String, String)>) {
    if let PL::C(kids) = &t.payload {
        if t.class == TagClass::Context && t.id == 3 && kids.len() == 2 {
            out.push((prim(&kids[0]).to_ascii_lowercase(), prim(&kids[1])));
        } else {
            for k in kids {
                equalities(k, out);
            }
        }
    }
}

async fn serve_conn(mut sock: tokio::net::TcpStream, dir: Arc<Vec<Entry>>) {
    let mut buf: Vec<u8> = vec![];
    let mut bound = false;
    loop {
        let (msg, used) = match parse_tag(&buf) {
            Ok((rest, t)) => (t, buf.len() - rest.len()),
            Err(_) => {
                let mut chunk = [0u8; 4096];
                match sock.read(&mut chunk).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => {
                        buf.extend_from_slice(&chunk[..n]);
                        continue;
                    }
                }
            }
        };
        buf.drain(..used);
        let PL::C(parts) = msg.payload else { return };
        let id = match &parts[0].payload {
            PL::P(v) => v.iter().fold(0i64, |a, b| (a << 8) | *b as i64),
            _ => return,
        };
        let op = &parts[1];
        let PL::C(f) = &op.payload else { return };
        let mut out = vec![];
        match op.id {
            0 => {
                let (dn, pw) = (prim(&f[1]), prim(&f[2]));
                let rc = if dn.is_empty() {
                    0
                } else {
                    match dir.iter().find(|e| e.dn.eq_ignore_ascii_case(&dn)) {
                        // Like real servers: an empty password is an "unauthenticated bind" and succeeds.
                        Some(e) if pw.is_empty() || e.password == pw => 0,
                        _ => 49,
                    }
                };
                bound = rc == 0 && !dn.is_empty();
                out.extend(frame(id, ldap_result(1, rc)));
            }
            3 => {
                let base = prim(&f[0]).to_ascii_lowercase();
                let scope = prim(&f[1]).bytes().next().unwrap_or(2);
                let mut eq = vec![];
                equalities(&f[6], &mut eq);
                eq.retain(|(a, _)| a != "objectclass");
                if !bound {
                    out.extend(frame(id, ldap_result(5, 50)));
                } else {
                    for e in dir.iter() {
                        let dn = e.dn.to_ascii_lowercase();
                        let hit = if scope == 0 {
                            dn == base
                        } else {
                            dn.ends_with(&base)
                                && eq.iter().any(|(a, v)| e.attrs.iter().any(|(k, vs)| k.eq_ignore_ascii_case(a) && vs.iter().any(|x| x.eq_ignore_ascii_case(v))))
                        };
                        if hit {
                            let attrs = e
                                .attrs
                                .iter()
                                .map(|(k, vs)| {
                                    Tag::Sequence(Sequence { inner: vec![os(k), Tag::Set(Set { inner: vs.iter().map(|v| os(v)).collect(), ..Default::default() })], ..Default::default() })
                                })
                                .collect();
                            let entry = Tag::Sequence(Sequence { id: 4, class: TagClass::Application, inner: vec![os(e.dn), Tag::Sequence(Sequence { inner: attrs, ..Default::default() })] });
                            out.extend(frame(id, entry));
                        }
                    }
                    out.extend(frame(id, ldap_result(5, 0)));
                }
            }
            _ => return, // unbind
        }
        if sock.write_all(&out).await.is_err() {
            return;
        }
    }
}

async fn start_directory() -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ldap://{}", l.local_addr().unwrap());
    let dir = directory();
    tokio::spawn(async move {
        loop {
            let Ok((s, _)) = l.accept().await else { return };
            tokio::spawn(serve_conn(s, dir.clone()));
        }
    });
    url
}

// ------------------------------------------------------------ server

struct Srv {
    state: State,
    base: String,
    _dir: tempfile::TempDir,
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
    s.security.max_auth_failures = 1000;
    state.save_settings(s).await.unwrap();
    let d = state.db.create_domain("example.test", "local", "").await.unwrap();
    let hash = picacho_server::auth::hash_password("Correct-Horse-9").unwrap();
    state.db.create_account("root@example.test", d, &hash, "Root", "admin", 0).await.unwrap();
    state.db.create_account("bob@example.test", d, &hash, "", "user", 0).await.unwrap();
    let web = picacho_server::web::serve(state.clone(), "127.0.0.1:0".parse().unwrap()).await.unwrap();
    Srv { state, base: format!("http://{web}"), _dir: dir }
}

fn ldap_cfg(url: &str) -> LdapSettings {
    LdapSettings {
        enabled: true,
        url: url.into(),
        bind_dn: "cn=svc,dc=test".into(),
        bind_password: Some("svc-pw".into()),
        base_dn: "ou=people,dc=test".into(),
        admin_groups: vec!["mail-admins".into()],
        ..Default::default()
    }
}

async fn set_ldap(s: &Srv, f: impl FnOnce(&mut picacho_server::settings::LiveSettings)) {
    let mut set = (*s.state.settings()).clone();
    f(&mut set);
    set.validate().unwrap();
    s.state.save_settings(set).await.unwrap();
}

async fn web_login(s: &Srv, user: &str, pw: &str) -> (u16, Value, Option<String>) {
    let r = reqwest::Client::new()
        .post(format!("{}/api/auth/login", s.base))
        .header("x-picacho", "1")
        .json(&json!({"email": user, "password": pw}))
        .send()
        .await
        .unwrap();
    let st = r.status().as_u16();
    let cookie = r.headers().get("set-cookie").map(|v| v.to_str().unwrap().split(';').next().unwrap().to_string());
    (st, r.json().await.unwrap_or(Value::Null), cookie)
}

fn ip() -> IpAddr {
    "127.0.0.1".parse().unwrap()
}

#[tokio::test]
async fn console_sign_in_with_directory() {
    let url = start_directory().await;
    let s = start().await;
    set_ldap(&s, |x| x.auth.ldap = ldap_cfg(&url)).await;

    let status: Value = reqwest::get(format!("{}/api/status", s.base)).await.unwrap().json().await.unwrap();
    assert_eq!(status["auth"]["ldap"]["name"], "Directory");
    assert_eq!(status["auth"]["password"], true);

    // In the directory, but no mailbox and automatic creation is off.
    assert_eq!(web_login(&s, "sam", "sam-pw").await.0, 401);
    set_ldap(&s, |x| x.auth.ldap.auto_create_accounts = true).await;
    let (st, me, cookie) = web_login(&s, "sam", "sam-pw").await;
    assert_eq!(st, 200, "{me}");
    assert_eq!(me["email"], "sam@example.test");
    assert_eq!(me["role"], "admin", "admin group maps to the admin role");
    assert_eq!(me["display_name"], "Sam Doe");
    assert_eq!(me["has_password"], false);
    assert!(cookie.is_some());
    // By address too, and wrong / empty passwords are refused (the mock, like
    // real servers, accepts an empty password as an unauthenticated bind).
    assert_eq!(web_login(&s, "SAM@example.test", "sam-pw").await.0, 200);
    assert_eq!(web_login(&s, "sam", "nope").await.0, 401);
    assert_eq!(web_login(&s, "sam", "").await.0, 401);
    // Filter injection doesn't match anyone.
    assert_eq!(web_login(&s, "*)(uid=*", "sam-pw").await.0, 401);

    // Found in the directory: its password decides, the old local one no longer works.
    assert_eq!(web_login(&s, "bob@example.test", "bob-dir-pw").await.0, 200);
    assert_eq!(web_login(&s, "bob@example.test", "Correct-Horse-9").await.0, 401);
    let bob = s.state.db.account_by_email("bob@example.test").await.unwrap().unwrap();
    assert_eq!(bob.role, "user");

    // Not in the directory: local password still works (break-glass admin).
    assert_eq!(web_login(&s, "root@example.test", "Correct-Horse-9").await.0, 200);

    // The directory's address must be on a local domain to create a mailbox.
    assert_eq!(web_login(&s, "other", "other-pw").await.0, 403);
    // An address that isn't the entry's own is refused.
    assert_eq!(web_login(&s, "sam@elsewhere.test", "sam-pw").await.0, 401);

    // Required groups, found through a group search.
    set_ldap(&s, |x| {
        x.auth.ldap.required_groups = vec!["staff".into()];
        x.auth.ldap.group_base_dn = "ou=groups,dc=test".into();
    })
    .await;
    assert_eq!(web_login(&s, "sam", "sam-pw").await.0, 200);
    assert_eq!(web_login(&s, "bob", "bob-dir-pw").await.0, 403);

    // Directory-only console: local passwords off.
    set_ldap(&s, |x| {
        x.auth.ldap.required_groups = vec![];
        x.auth.web_password_login = false;
    })
    .await;
    assert_eq!(web_login(&s, "root@example.test", "Correct-Horse-9").await.0, 401);
    assert_eq!(web_login(&s, "bob", "bob-dir-pw").await.0, 200);
}

#[tokio::test]
async fn directory_groups_and_details_sync() {
    use picacho_server::settings::{DirectoryRule, ProfileClaim};
    let url = start_directory().await;
    let s = start().await;
    set_ldap(&s, |x| {
        x.auth.ldap = ldap_cfg(&url);
        x.auth.ldap.auto_create_accounts = true;
        x.auth.ldap.group_base_dn = "ou=groups,dc=test".into();
        x.auth.ldap.profile_attributes = [("phone", "telephoneNumber"), ("phone", "mobile"), ("title", "title")]
            .iter()
            .map(|(f, a)| ProfileClaim { field: f.to_string(), claim: a.to_string() })
            .collect();
    })
    .await;
    assert_eq!(web_login(&s, "sam", "sam-pw").await.0, 200);
    let sam = s.state.db.account_by_email("sam@example.test").await.unwrap().unwrap();
    let groups = s.state.db.account_group_sources(sam.id).await.unwrap();
    assert!(groups.contains(&("cn=mail-admins,ou=groups,dc=test".to_string(), "ldap".to_string())), "{groups:?}");
    assert!(groups.contains(&("staff".to_string(), "ldap".to_string())), "{groups:?}");
    let p = s.state.db.account_profile(sam.id).await.unwrap();
    assert_eq!(p["phone"], vec!["+1 520 555 0150".to_string(), "+1 520 555 0151".to_string()]);
    assert_eq!(p["title"], vec!["Postmaster".to_string()]);

    // Bob has no groups in the directory; a rule naming the DN's group by name matches Sam.
    assert_eq!(web_login(&s, "bob", "bob-dir-pw").await.0, 200);
    let bob = s.state.db.account_by_email("bob@example.test").await.unwrap().unwrap();
    assert!(s.state.db.account_groups(bob.id).await.unwrap().is_empty());
    s.state.db.set_account_groups(bob.id, "manual", &["Staff".into()]).await.unwrap();
    set_ldap(&s, |x| {
        x.directory.enabled = true;
        x.directory.rules = vec![DirectoryRule { viewers: vec!["staff".into()], members: vec!["mail-admins".into()], fields: vec!["name".into(), "phone".into()] }];
    })
    .await;
    let entries = picacho_server::directory::load_entries(&s.state).await.unwrap();
    let me = entries.iter().find(|e| e.id == bob.id).unwrap();
    let seen = picacho_server::directory::visible(me, &entries, &s.state.settings().directory);
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].0.id, sam.id);
    assert!(seen[0].1.contains("phone") && !seen[0].1.contains("title"));
    // A later sign-in that no longer reports the manual group keeps it.
    assert_eq!(web_login(&s, "bob", "bob-dir-pw").await.0, 200);
    assert_eq!(s.state.db.account_groups(bob.id).await.unwrap(), vec!["Staff".to_string()]);
}

#[tokio::test]
async fn mail_apps_and_sso_accounts() {
    let url = start_directory().await;
    let s = start().await;
    set_ldap(&s, |x| x.auth.ldap = ldap_cfg(&url)).await;

    // IMAP/SMTP/DAV etc. go through login_service.
    let (a, _) = login_service(&s.state, "bob", "bob-dir-pw", ip(), Service::Imap).await.unwrap();
    assert_eq!(a.email, "bob@example.test");
    assert!(login_service(&s.state, "bob@example.test", "bob-dir-pw", ip(), Service::Smtp).await.is_ok());
    assert!(login_service(&s.state, "bob@example.test", "Correct-Horse-9", ip(), Service::Imap).await.is_err());
    assert!(login_service(&s.state, "root@example.test", "Correct-Horse-9", ip(), Service::Dav).await.is_ok());

    // A passwordless mailbox that signs in with single sign-on (linked to the
    // identity provider) uses its directory password in mail apps.
    let d = s.state.db.domain_by_name("example.test").await.unwrap().unwrap();
    let id = s.state.db.create_account("carol@example.test", d.id, "!", "Carol", "user", 0).await.unwrap();
    s.state.db.set_oidc_sub(id, "https://idp.test|carol-sub").await.unwrap();
    set_ldap(&s, |x| {
        x.auth.oidc = picacho_server::settings::OidcSettings {
            enabled: true,
            issuer: "https://idp.test".into(),
            client_id: "picacho".into(),
            ..Default::default()
        };
        x.auth.mail_password_login = false;
    })
    .await;
    let (a, _) = login_service(&s.state, "carol@example.test", "carol-pw", ip(), Service::Jmap).await.unwrap();
    assert_eq!(a.id, id);
    assert_eq!(a.oidc_sub, "https://idp.test|carol-sub", "the SSO link is untouched");
    // Local passwords are off for apps now, directory passwords aren't.
    assert_eq!(login_service(&s.state, "root@example.test", "Correct-Horse-9", ip(), Service::Imap).await.unwrap_err(), AuthError::Invalid);
    // Directory for the console only: apps can't use passwords at all.
    set_ldap(&s, |x| x.auth.ldap.mail_login = false).await;
    assert_eq!(login_service(&s.state, "bob", "bob-dir-pw", ip(), Service::Imap).await.unwrap_err(), AuthError::PasswordDisabled);
}

#[tokio::test]
async fn direct_bind_unreachable_and_test_endpoint() {
    let url = start_directory().await;
    let s = start().await;
    // Direct bind, no service account.
    set_ldap(&s, |x| {
        x.auth.ldap = LdapSettings { user_dn_template: "uid={user},ou=people,dc=test".into(), bind_dn: String::new(), bind_password: None, ..ldap_cfg(&url) };
    })
    .await;
    assert_eq!(web_login(&s, "bob", "bob-dir-pw").await.0, 200);
    assert_eq!(web_login(&s, "bob", "wrong").await.0, 401);
    // A refused direct bind can't tell users apart, so local passwords apply.
    assert_eq!(web_login(&s, "bob@example.test", "Correct-Horse-9").await.0, 200);

    // Directory down: local accounts still sign in; directory-only gives 503.
    set_ldap(&s, |x| x.auth.ldap = ldap_cfg("ldap://127.0.0.1:1")).await;
    assert_eq!(web_login(&s, "root@example.test", "Correct-Horse-9").await.0, 200);
    set_ldap(&s, |x| x.auth.mail_password_login = false).await;
    assert_eq!(login_service(&s.state, "bob", "bob-dir-pw", ip(), Service::Imap).await.unwrap_err(), AuthError::Internal);

    // The console's test button, with the stored (redacted) service password.
    set_ldap(&s, |x| x.auth.ldap = ldap_cfg(&url)).await;
    let (_, _, cookie) = web_login(&s, "root@example.test", "Correct-Horse-9").await;
    let cookie = cookie.unwrap();
    let c = reqwest::Client::new();
    let got: Value = c.get(format!("{}/api/admin/settings", s.base)).header("cookie", &cookie).send().await.unwrap().json().await.unwrap();
    let settings = got["settings"].clone();
    assert_eq!(settings["auth"]["ldap"]["bind_password"], picacho_server::settings::REDACTED);
    let ldap = settings["auth"]["ldap"].clone();
    let test = |body: Value| {
        let (c, cookie, base) = (c.clone(), cookie.clone(), s.base.clone());
        async move {
            let r = c.post(format!("{base}/api/admin/ldap/test")).header("cookie", cookie).header("x-picacho", "1").json(&body).send().await.unwrap();
            (r.status().as_u16(), r.json::<Value>().await.unwrap())
        }
    };
    let (st, r) = test(json!({"ldap": ldap})).await;
    assert_eq!((st, r["ok"].clone()), (200, json!(true)), "{r}");
    let (_, r) = test(json!({"ldap": ldap, "user": "sam"})).await;
    assert_eq!(r["user"]["emails"], json!(["sam@example.test"]));
    assert_eq!(r["admin"], true);
    let (_, r) = test(json!({"ldap": ldap, "user": "sam", "password": "nope"})).await;
    assert_eq!((r["found"].clone(), r["password_ok"].clone()), (json!(true), json!(false)));
    let (_, r) = test(json!({"ldap": ldap, "user": "nobody"})).await;
    assert_eq!(r["found"], false);
    let mut bad = ldap.clone();
    bad["bind_password"] = json!("wrong");
    let (st, r) = test(json!({"ldap": bad})).await;
    assert_eq!(st, 400, "{r}");

    // Saving keeps the stored secret when the console sends it back redacted.
    let mut all = settings.clone();
    all["auth"]["ldap"]["display_name"] = json!("Corp");
    let r = c.put(format!("{}/api/admin/settings", s.base)).header("cookie", &cookie).header("x-picacho", "1").json(&all).send().await.unwrap();
    assert!(r.status().is_success(), "{}", r.text().await.unwrap());
    assert_eq!(s.state.settings().auth.ldap.bind_password.as_deref(), Some("svc-pw"));
    assert_eq!(s.state.settings().auth.ldap.display_name, "Corp");
}

#[test]
fn validation() {
    let ok = ldap_cfg("ldaps://ldap.example.com");
    assert!(ok.validate().is_ok());
    let plain = ldap_cfg("ldap://ldap.example.com");
    assert!(plain.validate().unwrap_err().contains("StartTLS"));
    assert!(LdapSettings { starttls: true, ..plain.clone() }.validate().is_ok());
    assert!(LdapSettings { allow_plaintext: true, ..plain }.validate().is_ok());
    assert!(LdapSettings { user_filter: "(uid=sam".into(), ..ok.clone() }.validate().is_err());
    assert!(LdapSettings { user_filter: "(uid=sam)".into(), ..ok.clone() }.validate().is_err());
    assert!(LdapSettings { base_dn: "".into(), ..ok.clone() }.validate().is_err());
    assert!(LdapSettings { url: "http://x".into(), ..ok.clone() }.validate().is_err());
    assert!(LdapSettings { bind_password: None, ..ok }.validate().is_err());
}
