//! End-to-end test without Docker: a real server on ephemeral ports, mail
//! submitted over SMTP and read back over IMAP. Run with `cargo test`.
use picacho_server::config::Config;
use picacho_server::server::{spawn_listener, Proto};
use picacho_server::state::AppState;
use std::net::SocketAddr;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

struct Client {
    r: BufReader<tokio::net::tcp::OwnedReadHalf>,
    w: tokio::net::tcp::OwnedWriteHalf,
}

impl Client {
    async fn connect(addr: SocketAddr) -> Self {
        let (r, w) = TcpStream::connect(addr).await.unwrap().into_split();
        Client { r: BufReader::new(r), w }
    }
    async fn line(&mut self) -> String {
        let mut s = String::new();
        self.r.read_line(&mut s).await.unwrap();
        s
    }
    async fn send(&mut self, s: &str) {
        self.w.write_all(s.as_bytes()).await.unwrap();
    }
    /// Read SMTP reply lines until the final one; returns it.
    async fn smtp(&mut self) -> String {
        loop {
            let l = self.line().await;
            if l.len() < 4 || l.as_bytes()[3] == b' ' {
                return l;
            }
        }
    }
    /// Read IMAP lines until the tagged response; returns all lines.
    async fn imap(&mut self, tag: &str) -> String {
        let mut all = String::new();
        loop {
            let l = self.line().await;
            assert!(!l.is_empty(), "connection closed");
            all.push_str(&l);
            if l.starts_with(&format!("{tag} ")) {
                return all;
            }
        }
    }
}

async fn server() -> (picacho_server::state::State, SocketAddr, SocketAddr, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    cfg.hostname = Some("mx.test".into());
    cfg.storage.data_dir = dir.path().to_path_buf();
    cfg.storage.encrypt = true;
    cfg.storage.attachments = Some(Default::default());
    let state = AppState::new(cfg).await.unwrap();
    let mut s = (*state.settings()).clone();
    s.server.setup_complete = true;
    s.server.primary_domain = Some("example.test".into());
    s.security.verify_inbound = false;
    state.save_settings(s).await.unwrap();
    let d = state.db.create_domain("example.test", "local", "").await.unwrap();
    let hash = picacho_server::auth::hash_password("Correct-Horse-9").unwrap();
    state.db.create_account("bob@example.test", d, &hash, "Bob", "user", 0).await.unwrap();
    state.db.create_alias("team@example.test", "bob@example.test").await.unwrap();
    let any: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let smtp = spawn_listener(state.clone(), any, Proto::Smtp).await.unwrap();
    let imap = spawn_listener(state.clone(), any, Proto::Imap).await.unwrap();
    (state, smtp, imap, dir)
}

#[tokio::test]
async fn smtp_to_imap_roundtrip() {
    let (_state, smtp, imap, _dir) = server().await;

    let mut c = Client::connect(smtp).await;
    assert!(c.smtp().await.starts_with("220"));
    c.send("EHLO client.test\r\n").await;
    assert!(c.smtp().await.starts_with("250"));
    c.send("MAIL FROM:<alice@elsewhere.test>\r\n").await;
    assert!(c.smtp().await.starts_with("250"));
    // Open relay protection.
    c.send("RCPT TO:<victim@elsewhere.test>\r\n").await;
    assert!(c.smtp().await.starts_with("554"));
    c.send("RCPT TO:<nobody@example.test>\r\n").await;
    assert!(c.smtp().await.starts_with("550"));
    // Alias delivers to bob.
    c.send("RCPT TO:<team@example.test>\r\n").await;
    assert!(c.smtp().await.starts_with("250"));
    c.send("DATA\r\n").await;
    assert!(c.smtp().await.starts_with("354"));
    let attachment = "QUFB".repeat(30_000);
    c.send(&format!(
        "From: Alice <alice@elsewhere.test>\r\nTo: team@example.test\r\nSubject: Hello there\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\n..dot-stuffed line\r\n--b\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n\r\n{attachment}\r\n--b--\r\n.\r\n"
    ))
    .await;
    assert!(c.smtp().await.starts_with("250"));
    c.send("QUIT\r\n").await;

    let mut i = Client::connect(imap).await;
    assert!(i.line().await.starts_with("* OK"));
    i.send("a LOGIN bob@example.test wrong-password\r\n").await;
    assert!(i.imap("a").await.contains("a NO"));
    i.send("b LOGIN bob@example.test Correct-Horse-9\r\n").await;
    assert!(i.imap("b").await.contains("b OK"));
    i.send("c SELECT INBOX\r\n").await;
    let r = i.imap("c").await;
    assert!(r.contains("* 1 EXISTS"), "{r}");
    i.send("d FETCH 1 (FLAGS ENVELOPE BODY[1])\r\n").await;
    let r = i.imap("d").await;
    assert!(r.contains("\"Hello there\""), "{r}");
    assert!(r.contains(".dot-stuffed line"), "{r}");
    assert!(r.contains("\\Seen"), "{r}");
    // Attachment split out, encrypted, and reassembled byte for byte.
    i.send("e FETCH 1 BODY.PEEK[2]\r\n").await;
    let r = i.imap("e").await;
    assert!(r.contains(&attachment), "attachment not reassembled");
    i.send("f STORE 1 +FLAGS (\\Deleted)\r\nf2 EXPUNGE\r\n").await;
    i.imap("f").await;
    let r = i.imap("f2").await;
    assert!(r.contains("* 1 EXPUNGE"), "{r}");
    i.send("g LOGOUT\r\n").await;
    assert!(i.imap("g").await.contains("BYE"));
}

#[tokio::test]
async fn brute_force_is_banned() {
    let (state, _smtp, imap, _dir) = server().await;
    let mut s = (*state.settings()).clone();
    s.security.max_auth_failures = 3;
    s.security.allow_plaintext_localhost = true;
    state.save_settings(s).await.unwrap();
    for n in 0..3 {
        let mut i = Client::connect(imap).await;
        i.line().await;
        i.send(&format!("t{n} LOGIN bob@example.test nope\r\n")).await;
        i.imap(&format!("t{n}")).await;
    }
    let mut i = Client::connect(imap).await;
    assert!(i.line().await.starts_with("* BYE"), "banned client should be refused");
}
