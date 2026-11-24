//! End-to-end tests for Sieve, vacation, filtering, BDAT/DSN and the relay link.
use picacho_server::config::Config;
use picacho_server::server::{spawn_listener, Proto};
use picacho_server::state::{AppState, State};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

struct Smtp {
    r: BufReader<tokio::net::tcp::OwnedReadHalf>,
    w: tokio::net::tcp::OwnedWriteHalf,
}

impl Smtp {
    async fn connect(addr: SocketAddr) -> Self {
        let (r, w) = TcpStream::connect(addr).await.unwrap().into_split();
        let mut s = Smtp { r: BufReader::new(r), w };
        assert!(s.reply().await.starts_with("220"));
        s
    }
    async fn reply(&mut self) -> String {
        let mut all = String::new();
        loop {
            let mut l = String::new();
            self.r.read_line(&mut l).await.unwrap();
            all.push_str(&l);
            if l.len() < 4 || l.as_bytes()[3] == b' ' {
                return all;
            }
        }
    }
    async fn cmd(&mut self, c: &str) -> String {
        self.w.write_all(format!("{c}\r\n").as_bytes()).await.unwrap();
        self.reply().await
    }
    async fn send(&mut self, from: &str, to: &str, msg: &str) -> String {
        assert!(self.cmd(&format!("MAIL FROM:<{from}>")).await.starts_with("250"));
        assert!(self.cmd(&format!("RCPT TO:<{to}>")).await.starts_with("250"));
        assert!(self.cmd("DATA").await.starts_with("354"));
        self.w.write_all(format!("{msg}\r\n.\r\n").as_bytes()).await.unwrap();
        self.reply().await
    }
}

struct Srv {
    state: State,
    smtp: SocketAddr,
    web: SocketAddr,
    _dir: tempfile::TempDir,
}

async fn server(domain: &str) -> Srv {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    cfg.hostname = Some(format!("mx.{domain}"));
    cfg.storage.data_dir = dir.path().to_path_buf();
    let state = AppState::new(cfg).await.unwrap();
    let mut s = (*state.settings()).clone();
    s.server.setup_complete = true;
    s.server.primary_domain = Some(domain.into());
    s.security.verify_inbound = false;
    s.security.require_tls_for_auth = false;
    s.filter.bayes = false;
    state.save_settings(s).await.unwrap();
    let d = state.db.create_domain(domain, "local", "").await.unwrap();
    let hash = picacho_server::auth::hash_password("Correct-Horse-9").unwrap();
    state.db.create_account(&format!("bob@{domain}"), d, &hash, "Bob", "user", 0).await.unwrap();
    state.db.create_account(&format!("admin@{domain}"), d, &hash, "Admin", "admin", 0).await.unwrap();
    let any: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let smtp = spawn_listener(state.clone(), any, Proto::Smtp).await.unwrap();
    let web = picacho_server::web::serve(state.clone(), any).await.unwrap();
    Srv { state, smtp, web, _dir: dir }
}

async fn admin_token(s: &Srv, domain: &str) -> String {
    let a = s.state.db.account_by_email(&format!("admin@{domain}")).await.unwrap().unwrap();
    let (t, h, p) = picacho_server::auth::generate_token();
    s.state.db.create_token(a.id, "test", &h, &p, "admin", None).await.unwrap();
    t
}

async fn folder_count(state: &State, email: &str, folder: &str) -> usize {
    let a = state.db.account_by_email(email).await.unwrap().unwrap();
    match state.db.mailbox(a.id, folder).await.unwrap() {
        Some(m) => state.db.view(m.id).await.unwrap().len(),
        None => 0,
    }
}

#[tokio::test]
async fn sieve_fileinto_and_vacation() {
    let s = server("example.test").await;
    let bob = s.state.db.account_by_email("bob@example.test").await.unwrap().unwrap();
    let script = "require [\"fileinto\", \"vacation\"];\nif header :contains \"subject\" \"[list]\" { fileinto \"Lists\"; stop; }\nvacation :days 1 :subject \"Away\" \"I'm away.\";\n";
    s.state.db.sieve_put(bob.id, "main", script).await.unwrap();
    s.state.db.sieve_activate(bob.id, Some("main")).await.unwrap();

    let mut c = Smtp::connect(s.smtp).await;
    c.cmd("EHLO client.test").await;
    let r = c.send("alice@elsewhere.test", "bob@example.test", "From: alice@elsewhere.test\r\nTo: bob@example.test\r\nSubject: [list] weekly\r\nMessage-ID: <1@x>\r\n\r\nhi").await;
    assert!(r.starts_with("250"), "{r}");
    let r = c.send("alice@elsewhere.test", "bob@example.test", "From: alice@elsewhere.test\r\nTo: bob@example.test\r\nSubject: personal\r\nMessage-ID: <2@x>\r\n\r\nhello").await;
    assert!(r.starts_with("250"), "{r}");
    assert_eq!(folder_count(&s.state, "bob@example.test", "Lists").await, 1);
    assert_eq!(folder_count(&s.state, "bob@example.test", "INBOX").await, 1);
    // One vacation reply (null sender) for the personal message only.
    let q = s.state.db.list_queue().await.unwrap();
    let replies: Vec<_> = q.iter().filter(|i| i.sender.is_empty() && i.recipients == vec!["alice@elsewhere.test".to_string()]).collect();
    assert_eq!(replies.len(), 1, "{q:?}");
    let raw = s.state.blobs.get(&replies[0].blob).await.unwrap();
    let text = String::from_utf8_lossy(&raw);
    assert!(text.contains("Subject: Away") && text.contains("Auto-Submitted: auto-replied"), "{text}");
}

#[tokio::test]
async fn sieve_special_use_and_vacation_fcc() {
    let s = server("example.test").await;
    let bob = s.state.db.account_by_email("bob@example.test").await.unwrap().unwrap();
    s.state.db.create_mailbox(bob.id, "Starred", "\\Flagged").await.unwrap();
    // RFC 8579: the folder with the attribute wins over the named one; a
    // missing attribute falls back to the name. RFC 8580: the reply's copy
    // goes to Sent.
    let script = "require [\"fileinto\", \"special-use\", \"vacation\", \"fcc\", \"imap4flags\"];\r\n\
        if header :contains \"subject\" \"[star]\" { fileinto :specialuse \"\\\\Flagged\" \"Elsewhere\"; stop; }\r\n\
        if specialuse_exists \"\\\\All\" { discard; stop; }\r\n\
        if header :contains \"subject\" \"[later]\" { fileinto :specialuse \"\\\\All\" \"Later\"; stop; }\r\n\
        vacation :days 1 :handle \"picacho-vacation\" :fcc \"Sent\" :flags \"\\\\Seen\" \"I'm away.\";\r\n";
    picacho_server::sieve::check(script).unwrap();
    s.state.db.sieve_put(bob.id, "main", script).await.unwrap();
    s.state.db.sieve_activate(bob.id, Some("main")).await.unwrap();

    let mut c = Smtp::connect(s.smtp).await;
    c.cmd("EHLO client.test").await;
    for (n, subject) in [(1, "[star] look"), (2, "[later] read"), (3, "personal")] {
        let msg = format!("From: alice@elsewhere.test\r\nTo: bob@example.test\r\nSubject: {subject}\r\nMessage-ID: <{n}@x>\r\n\r\nhi");
        let r = c.send("alice@elsewhere.test", "bob@example.test", &msg).await;
        assert!(r.starts_with("250"), "{r}");
    }
    assert_eq!(folder_count(&s.state, "bob@example.test", "Starred").await, 1);
    assert_eq!(folder_count(&s.state, "bob@example.test", "Elsewhere").await, 0);
    assert_eq!(folder_count(&s.state, "bob@example.test", "Later").await, 1);
    assert_eq!(folder_count(&s.state, "bob@example.test", "INBOX").await, 1);
    let sent = s.state.db.mailbox(bob.id, "Sent").await.unwrap().unwrap();
    let copies = s.state.db.view(sent.id).await.unwrap();
    assert_eq!(copies.len(), 1);
    assert!(copies[0].flags.contains("\\Seen"), "{}", copies[0].flags);
    let copy = s.state.db.messages_by_uids(sent.id, copies[0].uid, copies[0].uid).await.unwrap();
    let text = String::from_utf8_lossy(&s.state.blobs.get(&copy[0].blob).await.unwrap()).to_string();
    assert!(text.contains("Auto-Submitted: auto-replied") && text.contains("I'm away."), "{text}");
    let q = s.state.db.list_queue().await.unwrap();
    let replies: Vec<_> = q.iter().filter(|i| i.sender.is_empty() && i.recipients == vec!["alice@elsewhere.test".to_string()]).collect();
    assert_eq!(replies.len(), 1, "{q:?}");
}

#[tokio::test]
async fn filter_blocks_executables_and_bdat_dsn_work() {
    let s = server("example.test").await;
    let mut c = Smtp::connect(s.smtp).await;
    let ehlo = c.cmd("EHLO client.test").await;
    assert!(ehlo.contains("CHUNKING") && ehlo.contains("DSN"), "{ehlo}");
    let r = c
        .send(
            "alice@elsewhere.test",
            "bob@example.test",
            "From: alice@elsewhere.test\r\nSubject: invoice\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nsee attached\r\n--b\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"invoice.pdf.exe\"\r\n\r\nMZ\r\n--b--",
        )
        .await;
    assert!(r.starts_with("550"), "{r}");
    // BDAT with DSN parameters.
    assert!(c.cmd("MAIL FROM:<alice@elsewhere.test> RET=HDRS ENVID=abc").await.starts_with("250"));
    assert!(c.cmd("RCPT TO:<bob@example.test> NOTIFY=FAILURE ORCPT=rfc822;bob@example.test").await.starts_with("250"));
    let body = "From: alice@elsewhere.test\r\nSubject: chunked\r\n\r\nin two chunks\r\n";
    let (a, b) = body.split_at(20);
    c.w.write_all(format!("BDAT {}\r\n{a}", a.len()).as_bytes()).await.unwrap();
    assert!(c.reply().await.starts_with("250"));
    c.w.write_all(format!("BDAT {} LAST\r\n{b}", b.len()).as_bytes()).await.unwrap();
    let r = c.reply().await;
    assert!(r.starts_with("250"), "{r}");
    assert_eq!(folder_count(&s.state, "bob@example.test", "INBOX").await, 1);
}

#[tokio::test]
async fn relay_link_carries_mail_both_ways() {
    let up = server("upstream.test").await;
    let down = server("home.test").await;
    let tok = admin_token(&up, "upstream.test").await;
    let http = reqwest::Client::new();
    let r: Value = http
        .post(format!("http://{}/api/v1/relay/peers", up.web))
        .bearer_auth(&tok)
        .json(&json!({"name": "home", "domains": ["home.test"]}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let peer_token = r["token"].as_str().unwrap_or_else(|| panic!("{r}")).to_string();
    let mut s = (*down.state.settings()).clone();
    s.relay.upstream = Some(picacho_server::settings::UpstreamRelay {
        enabled: true,
        url: format!("http://{}", up.web).replace("127.0.0.1", "localhost"),
        token: Some(peer_token),
        outbound: true,
        inbound: true,
        insecure: false,
    });
    down.state.save_settings(s).await.unwrap();
    picacho_server::relay::spawn_puller(down.state.clone());
    picacho_server::queue::spawn_worker(down.state.clone());

    // Inbound: the upstream is MX for home.test and holds the message.
    let mut c = Smtp::connect(up.smtp).await;
    c.cmd("EHLO sender.test").await;
    let r = c.send("alice@elsewhere.test", "bob@home.test", "From: alice@elsewhere.test\r\nTo: bob@home.test\r\nSubject: via relay\r\n\r\nhello home").await;
    assert!(r.starts_with("250"), "{r}");
    let mut got = false;
    for _ in 0..100 {
        if folder_count(&down.state, "bob@home.test", "INBOX").await == 1 {
            got = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(got, "downstream never received the message");
    assert_eq!(up.state.db.held_count("home").await.unwrap(), 0, "upstream should forget acknowledged mail");

    // Outbound: downstream mail to the internet goes out through the upstream.
    picacho_server::queue::enqueue(&down.state, "bob@home.test", &["carol@far.example".to_string()], b"From: bob@home.test\r\nSubject: out\r\n\r\nbye\r\n", "")
        .await
        .unwrap();
    let mut relayed = false;
    for _ in 0..100 {
        let q = up.state.db.list_queue().await.unwrap();
        if q.iter().any(|i| i.sender == "bob@home.test" && i.recipients == vec!["carol@far.example".to_string()]) {
            relayed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(relayed, "upstream never queued the downstream's outbound mail");
}
