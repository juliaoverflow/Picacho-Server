//! Protocol extensions the Picacho mail app uses (see ../Picacho's
//! docs/SYNCHRONIZATION.md): IMAP OBJECTID, SAVEDATE, PREVIEW, APPENDLIMIT,
//! SEARCHRES and REPLACE; SMTP FUTURERELEASE and LIMITS; JMAP submissions,
//! identities, blobs, Email/parse and MDN/send; Pinal Mail's encryption at
//! rest; and the Web Key Directory the app looks keys up in.
use picacho_server::config::Config;
use picacho_server::server::{spawn_listener, Proto};
use picacho_server::state::{AppState, State};
use std::net::SocketAddr;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

pub struct Srv {
    pub state: State,
    pub imap: SocketAddr,
    pub smtp: SocketAddr,
    pub submission: SocketAddr,
    pub web: SocketAddr,
    pub pop3: SocketAddr,
    _dir: tempfile::TempDir,
}

pub async fn server() -> Srv {
    server_with(|_| {}).await
}

/// A server whose configuration `tweak` adjusts first.
pub async fn server_with(tweak: impl FnOnce(&mut Config)) -> Srv {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    cfg.hostname = Some("mx.example.test".into());
    cfg.storage.data_dir = dir.path().to_path_buf();
    tweak(&mut cfg);
    let state = AppState::new(cfg).await.unwrap();
    let mut s = (*state.settings()).clone();
    s.server.setup_complete = true;
    s.server.primary_domain = Some("example.test".into());
    s.security.verify_inbound = false;
    s.security.require_tls_for_auth = false;
    s.filter.bayes = false;
    s.filter.enabled = false;
    state.save_settings(s).await.unwrap();
    let d = state.db.create_domain("example.test", "local", "").await.unwrap();
    let hash = picacho_server::auth::hash_password("Correct-Horse-9").unwrap();
    state.db.create_account("bob@example.test", d, &hash, "Bob", "user", 0).await.unwrap();
    state.db.create_account("amy@example.test", d, &hash, "Amy", "user", 0).await.unwrap();
    let any: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let imap = spawn_listener(state.clone(), any, Proto::Imap).await.unwrap();
    let smtp = spawn_listener(state.clone(), any, Proto::Smtp).await.unwrap();
    let submission = spawn_listener(state.clone(), any, Proto::Submission).await.unwrap();
    let web = picacho_server::web::serve(state.clone(), any).await.unwrap();
    let pop3 = spawn_listener(state.clone(), any, Proto::Pop3).await.unwrap();
    Srv { state, imap, smtp, submission, web, pop3, _dir: dir }
}

// ------------------------------------------------------------ IMAP

pub struct Imap {
    pub r: BufReader<tokio::net::tcp::OwnedReadHalf>,
    pub w: tokio::net::tcp::OwnedWriteHalf,
    n: u32,
}

impl Imap {
    pub async fn login(addr: SocketAddr, user: &str) -> Self {
        let (r, w) = TcpStream::connect(addr).await.unwrap().into_split();
        let mut s = Imap { r: BufReader::new(r), w, n: 0 };
        let mut greeting = String::new();
        s.r.read_line(&mut greeting).await.unwrap();
        assert!(greeting.starts_with("* OK"), "{greeting}");
        let r = s.cmd(&format!("LOGIN {user} Correct-Horse-9")).await;
        assert!(r.contains(" OK "), "{r}");
        s
    }

    /// Send a command (literals as `{n+}`) and read up to its tagged reply.
    pub async fn cmd(&mut self, c: &str) -> String {
        self.n += 1;
        let tag = format!("a{}", self.n);
        self.w.write_all(format!("{tag} {c}\r\n").as_bytes()).await.unwrap();
        let mut all = String::new();
        loop {
            let mut l = String::new();
            if self.r.read_line(&mut l).await.unwrap() == 0 {
                panic!("connection closed after: {all}");
            }
            // Literals in responses: read their bytes too.
            if let Some(n) = l.trim_end().strip_suffix('}').and_then(|x| x.rsplit_once('{')).and_then(|(_, n)| n.parse::<usize>().ok()) {
                all.push_str(&l);
                let mut buf = vec![0u8; n];
                tokio::io::AsyncReadExt::read_exact(&mut self.r, &mut buf).await.unwrap();
                all.push_str(&String::from_utf8_lossy(&buf));
                continue;
            }
            all.push_str(&l);
            if l.starts_with(&format!("{tag} ")) {
                return all;
            }
        }
    }

    pub async fn append(&mut self, cmd_prefix: &str, msg: &str) -> String {
        self.cmd(&format!("{cmd_prefix} {{{}+}}\r\n{msg}", msg.len())).await
    }
}

fn msg(subject: &str, body: &str) -> String {
    format!("From: Amy <amy@example.test>\r\nTo: bob@example.test\r\nSubject: {subject}\r\nMessage-ID: <{subject}@example.test>\r\n\r\n{body}\r\n")
}

fn tagged_ok(r: &str) -> bool {
    r.lines().last().is_some_and(|l| l.split(' ').nth(1) == Some("OK"))
}

#[tokio::test]
async fn imap_object_ids_preview_savedate_appendlimit() {
    let s = server().await;
    let mut c = Imap::login(s.imap, "bob@example.test").await;
    let caps = c.cmd("CAPABILITY").await;
    for cap in ["OBJECTID", "SAVEDATE", "PREVIEW", "REPLACE", "SEARCHRES", "APPENDLIMIT="] {
        assert!(caps.contains(cap), "{cap} missing: {caps}");
    }
    let r = c.cmd("CREATE Projects").await;
    assert!(r.contains("[MAILBOXID (m"), "{r}");
    let r = c.cmd("STATUS Projects (MAILBOXID APPENDLIMIT MESSAGES)").await;
    assert!(r.contains("MAILBOXID (m") && r.contains("APPENDLIMIT "), "{r}");

    let r = c.append("APPEND INBOX", &msg("hello", "First line of the body\r\nsecond line")).await;
    assert!(tagged_ok(&r), "{r}");
    let r = c.cmd("SELECT INBOX").await;
    assert!(r.contains("[MAILBOXID (m"), "{r}");
    let r = c.cmd("UID FETCH 1 (EMAILID THREADID SAVEDATE PREVIEW)").await;
    assert!(r.contains("EMAILID (e") && r.contains("THREADID (t"), "{r}");
    assert!(r.contains("SAVEDATE \""), "{r}");
    assert!(r.contains("PREVIEW \"First line of the body second line\""), "{r}");
    let r = c.cmd("UID FETCH 1 (PREVIEW (LAZY))").await;
    assert!(r.contains("PREVIEW \"First line"), "{r}");
    let email_id = r.split("EMAILID (").nth(1).map(|x| x.split(')').next().unwrap().to_string());
    let r = c.cmd("UID FETCH 1 EMAILID").await;
    let eid = r.split("EMAILID (").nth(1).unwrap().split(')').next().unwrap().to_string();
    assert!(email_id.is_none() || email_id.as_deref() == Some(eid.as_str()));
    let r = c.cmd(&format!("UID SEARCH EMAILID {eid}")).await;
    assert!(r.contains("* SEARCH 1"), "{r}");
    let r = c.cmd("UID SEARCH SAVEDSINCE 1-Jan-2020 SAVEDATESUPPORTED").await;
    assert!(r.contains("* SEARCH 1"), "{r}");

    // MOVE keeps the message's EMAILID (RFC 8474).
    let r = c.cmd("UID MOVE 1 Projects").await;
    assert!(r.contains("COPYUID") && tagged_ok(&r), "{r}");
    c.cmd("SELECT Projects").await;
    let r = c.cmd("UID FETCH 1:* EMAILID").await;
    assert!(r.contains(&format!("EMAILID ({eid})")), "EMAILID changed on MOVE: {r}");

    // APPENDLIMIT is the server's message size limit.
    let limit: usize = caps.split("APPENDLIMIT=").nth(1).unwrap().split_whitespace().next().unwrap().parse().unwrap();
    assert_eq!(limit as u64, s.state.settings().limits.max_message_bytes as u64);
}

#[tokio::test]
async fn imap_inprogress_reports_on_long_commands() {
    // Reports start at once with no interval, so a short mailbox shows them.
    let s = server_with(|c| c.limits.imap_progress_ms = 0).await;
    let mut c = Imap::login(s.imap, "bob@example.test").await;
    assert!(c.cmd("CAPABILITY").await.contains(" INPROGRESS"));
    c.cmd("CREATE Archive").await;
    for i in 1..=3 {
        assert!(tagged_ok(&c.append("APPEND INBOX", &msg(&format!("p{i}"), "x")).await));
    }
    c.cmd("SELECT INBOX").await;
    let r = c.cmd("UID SEARCH ALL").await;
    // The command's tag, from its tagged reply.
    let tag = r.lines().last().unwrap().split(' ').next().unwrap().to_string();
    assert!(r.contains(&format!("* OK [INPROGRESS (\"{tag}\" 0 3)]")), "{r}");
    assert!(r.contains(&format!("* OK [INPROGRESS (\"{tag}\" 2 3)]")), "{r}");
    let tagged = r.find(&format!("{tag} OK")).unwrap();
    assert!(r.rfind("INPROGRESS").unwrap() < tagged, "nothing after the tagged reply: {r}");
    let r = c.cmd("SORT (SUBJECT) UTF-8 ALL").await;
    assert!(r.contains("[INPROGRESS (") && r.contains("* SORT 1 2 3"), "{r}");
    let r = c.cmd("UID COPY 1:* Archive").await;
    assert!(tagged_ok(&r) && r.contains("COPYUID"), "{r}");

    // With the default interval, quick commands say nothing extra.
    let s = server().await;
    let mut c = Imap::login(s.imap, "bob@example.test").await;
    c.append("APPEND INBOX", &msg("q", "x")).await;
    c.cmd("SELECT INBOX").await;
    let r = c.cmd("UID SEARCH ALL").await;
    assert!(!r.contains("INPROGRESS"), "{r}");
}

#[tokio::test]
async fn imap_searchres_and_replace() {
    let s = server().await;
    let mut c = Imap::login(s.imap, "bob@example.test").await;
    c.cmd("CREATE Archive").await;
    for i in 1..=4 {
        let r = c.append(if i % 2 == 0 { "APPEND INBOX (\\Flagged)" } else { "APPEND INBOX" }, &msg(&format!("m{i}"), "x")).await;
        assert!(tagged_ok(&r), "{r}");
    }
    c.cmd("SELECT INBOX").await;
    // What the app does when a snoozed message wakes: search, save, act on `$`.
    let r = c.cmd("UID SEARCH RETURN (SAVE ALL) FLAGGED").await;
    assert!(r.contains("ESEARCH") && r.contains("ALL 2,4"), "{r}");
    let r = c.cmd("UID STORE $ +FLAGS.SILENT (\\Seen)").await;
    assert!(tagged_ok(&r), "{r}");
    let r = c.cmd("UID SEARCH SEEN").await;
    assert!(r.contains("* SEARCH 2 4"), "{r}");
    // SAVE alone returns nothing but keeps the result.
    let r = c.cmd("UID SEARCH RETURN (SAVE) UNFLAGGED").await;
    assert!(!r.contains("ESEARCH") && tagged_ok(&r), "{r}");
    let r = c.cmd("UID SEARCH $").await;
    assert!(r.contains("* SEARCH 1 3"), "{r}");
    let r = c.cmd("UID MOVE $ Archive").await;
    assert!(tagged_ok(&r), "{r}");
    let r = c.cmd("UID SEARCH ALL").await;
    assert!(r.contains("* SEARCH 2 4"), "{r}");

    // REPLACE: a draft's new version replaces its copy in one step.
    c.cmd("CREATE Drafts").await;
    let r = c.append("APPEND Drafts (\\Draft)", &msg("draft", "v1")).await;
    assert!(tagged_ok(&r), "{r}");
    c.cmd("SELECT Drafts").await;
    let v2 = msg("draft", "version two");
    let r = c.append("UID REPLACE 1 Drafts (\\Draft \\Seen)", &v2).await;
    assert!(r.contains("[APPENDUID ") && tagged_ok(&r), "{r}");
    assert!(r.contains("* 1 EXPUNGE") || r.contains("VANISHED"), "old copy reported gone: {r}");
    let r = c.cmd("UID FETCH 1:* (FLAGS BODY.PEEK[TEXT])").await;
    assert!(r.contains("version two") && !r.contains("v1\r\n"), "{r}");
    assert!(r.contains("\\Draft") && r.contains("\\Seen"), "{r}");
    // A failed REPLACE removes nothing.
    let r = c.append("UID REPLACE 2 Nowhere", &v2).await;
    assert!(r.contains("TRYCREATE"), "{r}");
    let r = c.cmd("UID SEARCH ALL").await;
    assert!(r.contains("* SEARCH 2"), "{r}");
}

// ------------------------------------------------------------ SMTP

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
    async fn login(&mut self, user: &str) {
        use base64::Engine;
        let t = base64::engine::general_purpose::STANDARD.encode(format!("\0{user}\0Correct-Horse-9"));
        let r = self.cmd(&format!("AUTH PLAIN {t}")).await;
        assert!(r.starts_with("235"), "{r}");
    }
    async fn data(&mut self, msg: &str) -> String {
        assert!(self.cmd("DATA").await.starts_with("354"));
        self.w.write_all(format!("{msg}\r\n.\r\n").as_bytes()).await.unwrap();
        self.reply().await
    }
}

async fn inbox_count(s: &Srv, email: &str) -> usize {
    let a = s.state.db.account_by_email(email).await.unwrap().unwrap();
    let mb = s.state.db.mailbox(a.id, "INBOX").await.unwrap().unwrap();
    s.state.db.view(mb.id).await.unwrap().len()
}

#[tokio::test]
async fn smtp_futurerelease_and_limits() {
    let s = server().await;
    let mut c = Smtp::connect(s.submission).await;
    let ehlo = c.cmd("EHLO client.test").await;
    assert!(ehlo.contains("FUTURERELEASE 2678400 "), "{ehlo}");
    assert!(ehlo.contains("LIMITS RCPTMAX=100"), "{ehlo}");
    // Not before signing in.
    assert!(c.cmd("MAIL FROM:<bob@example.test> HOLDFOR=60").await.starts_with("530"));
    c.login("bob@example.test").await;
    let r = c.cmd("MAIL FROM:<bob@example.test> HOLDFOR=99999999").await;
    assert!(r.starts_with("501"), "too far ahead: {r}");
    assert!(c.cmd("MAIL FROM:<bob@example.test> HOLDFOR=2").await.starts_with("250"));
    assert!(c.cmd("RCPT TO:<amy@example.test>").await.starts_with("250"));
    let r = c.data(&msg("later", "Sent later")).await;
    assert!(r.starts_with("250") && r.contains("held until"), "{r}");
    // Held: not delivered yet, even to a local mailbox.
    assert_eq!(inbox_count(&s, "amy@example.test").await, 0);
    let bob = s.state.db.account_by_email("bob@example.test").await.unwrap().unwrap();
    let subs = s.state.db.submissions(bob.id).await.unwrap();
    assert_eq!(subs.len(), 1);
    assert_eq!(subs[0].undo_status, "pending");
    assert_eq!(picacho_server::submit::release_due(&s.state).await.unwrap(), 0, "not due yet");
    tokio::time::sleep(std::time::Duration::from_millis(2500)).await;
    assert_eq!(picacho_server::submit::release_due(&s.state).await.unwrap(), 1);
    assert_eq!(inbox_count(&s, "amy@example.test").await, 1);
    let sub = s.state.db.submission(subs[0].id).await.unwrap().unwrap();
    assert_eq!(sub.undo_status, "final");
    assert!(sub.blob.is_empty(), "held copy released");
    assert!(sub.delivery.contains("\"delivered\":\"yes\""), "{}", sub.delivery);

    // A held message canceled before its time is never sent.
    assert!(c.cmd("MAIL FROM:<bob@example.test> HOLDUNTIL=2099-01-01T00:00:00Z").await.starts_with("501"));
    let until = (chrono::Utc::now() + chrono::Duration::hours(1)).format("%Y-%m-%dT%H:%M:%SZ").to_string();
    assert!(c.cmd(&format!("MAIL FROM:<bob@example.test> HOLDUNTIL={until}")).await.starts_with("250"));
    assert!(c.cmd("RCPT TO:<amy@example.test>").await.starts_with("250"));
    assert!(c.data(&msg("never", "Canceled")).await.starts_with("250"));
    let held = s.state.db.submissions(bob.id).await.unwrap().into_iter().find(|x| x.undo_status == "pending").unwrap();
    assert!(picacho_server::submit::cancel(&s.state, held.id).await.unwrap());
    assert!(!picacho_server::submit::cancel(&s.state, held.id).await.unwrap(), "only once");

    // The MX port doesn't hold mail for anyone.
    let mut mx = Smtp::connect(s.smtp).await;
    let ehlo = mx.cmd("EHLO peer.test").await;
    assert!(!ehlo.contains("FUTURERELEASE"), "{ehlo}");
    assert!(mx.cmd("MAIL FROM:<x@peer.test> HOLDFOR=60").await.starts_with("554"));
}

// ------------------------------------------------------------ JMAP

struct Jmap {
    base: String,
    user: String,
    c: reqwest::Client,
    account: String,
}

impl Jmap {
    async fn new(s: &Srv, user: &str) -> (Self, serde_json::Value) {
        let base = format!("http://{}", s.web);
        let c = reqwest::Client::new();
        let session: serde_json::Value =
            c.get(format!("{base}/.well-known/jmap")).basic_auth(user, Some("Correct-Horse-9")).send().await.unwrap().json().await.unwrap();
        let account = session["primaryAccounts"]["urn:ietf:params:jmap:mail"].as_str().unwrap().to_string();
        (Jmap { base, user: user.into(), c, account }, session)
    }

    /// One request; returns the method responses.
    async fn call(&self, calls: serde_json::Value) -> Vec<serde_json::Value> {
        let using = [
            "urn:ietf:params:jmap:core",
            "urn:ietf:params:jmap:mail",
            "urn:ietf:params:jmap:submission",
            "urn:ietf:params:jmap:blob",
            "urn:ietf:params:jmap:mdn",
            "urn:ietf:params:jmap:calendars",
            "urn:ietf:params:jmap:contacts",
            "urn:ietf:params:jmap:principals",
            // The app names this whenever it asks for free/busy (sync/jmap.rs).
            "urn:ietf:params:jmap:principals:availability",
        ];
        let r: serde_json::Value = self
            .c
            .post(format!("{}/jmap/api", self.base))
            .basic_auth(&self.user, Some("Correct-Horse-9"))
            .json(&serde_json::json!({"using": using, "methodCalls": calls}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        r["methodResponses"].as_array().cloned().unwrap_or_else(|| panic!("{r}"))
    }

    async fn one(&self, method: &str, mut args: serde_json::Value) -> serde_json::Value {
        args["accountId"] = serde_json::json!(self.account);
        let r = self.call(serde_json::json!([[method, args, "0"]])).await;
        assert_eq!(r[0][0], method, "{}", r[0]);
        r[0][1].clone()
    }

    async fn mailbox(&self, role: &str) -> String {
        let r = self.one("Mailbox/get", serde_json::json!({})).await;
        r["list"].as_array().unwrap().iter().find(|m| m["role"] == role).unwrap()["id"].as_str().unwrap().to_string()
    }

    /// Upload a message and import it into the mailbox with that role.
    async fn import(&self, role: &str, raw: &str, keywords: serde_json::Value) -> (String, String) {
        let mb = self.mailbox(role).await;
        let up = self.one("Blob/upload", serde_json::json!({"create": {"m": {"data": [{"data:asText": raw}], "type": "message/rfc822"}}})).await;
        let blob = up["created"]["m"]["id"].as_str().unwrap_or_else(|| panic!("{up}")).to_string();
        let r = self.one("Email/import", serde_json::json!({"emails": {"e": {"blobId": blob, "mailboxIds": {mb: true}, "keywords": keywords}}})).await;
        (r["created"]["e"]["id"].as_str().unwrap_or_else(|| panic!("{r}")).to_string(), blob)
    }
}

#[tokio::test]
async fn jmap_held_submissions_undo_and_delivery_status() {
    use serde_json::json;
    let s = server().await;
    let (bob, session) = Jmap::new(&s, "bob@example.test").await;
    let sub = &session["accounts"][&bob.account]["accountCapabilities"]["urn:ietf:params:jmap:submission"];
    assert_eq!(sub["maxDelayedSend"], 31 * 86400);
    assert!(sub["submissionExtensions"]["FUTURERELEASE"].is_array(), "{sub}");
    assert!(session["capabilities"]["urn:ietf:params:jmap:blob"].is_object());
    assert!(session["capabilities"]["urn:ietf:params:jmap:mdn"].is_object());
    let ident = bob.one("Identity/get", json!({})).await["list"][0]["id"].as_str().unwrap().to_string();
    let draft_raw = "From: Bob <bob@example.test>\r\nTo: amy@example.test\r\nBcc: friend@elsewhere.test\r\nSubject: held\r\nMessage-ID: <held@example.test>\r\n\r\nWait for it\r\n";
    let (draft, _) = bob.import("drafts", draft_raw, json!({"$draft": true})).await;

    // Held for an hour, then taken back.
    let until = (chrono::Utc::now() + chrono::Duration::hours(1)).format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let r = bob
        .one(
            "EmailSubmission/set",
            json!({"create": {"s1": {"identityId": ident, "emailId": draft,
                "envelope": {"mailFrom": {"email": "bob@example.test", "parameters": {"HOLDUNTIL": until}}, "rcptTo": [{"email": "amy@example.test"}]}}}}),
        )
        .await;
    let sid = r["created"]["s1"]["id"].as_str().unwrap_or_else(|| panic!("{r}")).to_string();
    assert_eq!(r["created"]["s1"]["undoStatus"], "pending");
    let q = bob.one("EmailSubmission/query", json!({"filter": {"undoStatus": "pending"}, "sort": [{"property": "sendAt", "isAscending": false}]})).await;
    assert_eq!(q["ids"], json!([sid]));
    let state = bob.one("EmailSubmission/get", json!({"ids": [sid]})).await["state"].clone();
    let r = bob.one("EmailSubmission/set", json!({"update": {&sid: {"undoStatus": "canceled"}}})).await;
    assert!(r["updated"].get(&sid).is_some(), "{r}");
    let r = bob.one("EmailSubmission/set", json!({"update": {&sid: {"undoStatus": "canceled"}}})).await;
    assert_eq!(r["notUpdated"][&sid]["type"], "cannotUnsend");
    let g = bob.one("EmailSubmission/get", json!({"ids": [sid], "properties": ["undoStatus", "emailId"]})).await;
    assert_eq!(g["list"][0]["undoStatus"], "canceled");
    assert_eq!(g["list"][0]["emailId"], draft);
    let ch = bob.one("EmailSubmission/changes", json!({"sinceState": state})).await;
    assert!(ch["updated"].as_array().unwrap().iter().any(|x| x == &json!(sid)), "{ch}");
    picacho_server::submit::release_due(&s.state).await.unwrap();
    assert_eq!(inbox_count(&s, "amy@example.test").await, 0, "canceled mail isn't sent");

    // Sent now: final, with each recipient's delivery status.
    let r = bob
        .one(
            "EmailSubmission/set",
            json!({"create": {"s2": {"identityId": ident, "emailId": draft}},
                "onSuccessUpdateEmail": {"#s2": {"keywords/$draft": null}}}),
        )
        .await;
    let sid = r["created"]["s2"]["id"].as_str().unwrap_or_else(|| panic!("{r}")).to_string();
    assert_eq!(r["created"]["s2"]["undoStatus"], "final");
    let g = bob.one("EmailSubmission/get", json!({"ids": [sid]})).await;
    assert_eq!(g["list"][0]["deliveryStatus"]["amy@example.test"]["delivered"], "yes", "{g}");
    // Remote recipients wait in the queue (no worker runs in this test).
    assert_eq!(g["list"][0]["deliveryStatus"]["friend@elsewhere.test"]["delivered"], "queued", "{g}");
    let q = s.state.db.due_queue(10).await.unwrap();
    assert_eq!(q.len(), 1);
    assert!(q[0].submission_id > 0, "the queue entry reports back to the submission");
    let queued = s.state.blobs.get(&q[0].blob).await.unwrap();
    assert!(!String::from_utf8_lossy(&queued).contains("Bcc:"), "Bcc is removed before sending");
    assert_eq!(inbox_count(&s, "amy@example.test").await, 1);
    // Unknown recipients send nothing at all.
    let r = bob
        .one(
            "EmailSubmission/set",
            json!({"create": {"s3": {"identityId": ident, "emailId": draft,
                "envelope": {"mailFrom": {"email": "bob@example.test"}, "rcptTo": [{"email": "amy@example.test"}, {"email": "nobody@example.test"}]}}}}),
        )
        .await;
    assert_eq!(r["notCreated"]["s3"]["type"], "invalidRecipients", "{r}");
    assert_eq!(inbox_count(&s, "amy@example.test").await, 1);
}

#[tokio::test]
async fn jmap_identities_blobs_parse_and_receipts() {
    use serde_json::json;
    let s = server().await;
    let (bob, _) = Jmap::new(&s, "bob@example.test").await;
    let (amy, _) = Jmap::new(&s, "amy@example.test").await;

    // Identity/set: own addresses only; built-ins can be renamed, not removed.
    let g = bob.one("Identity/get", json!({})).await;
    let (builtin, state) = (g["list"][0]["id"].as_str().unwrap().to_string(), g["state"].clone());
    let r = bob
        .one(
            "Identity/set",
            json!({"create": {"n": {"email": "bob+news@example.test", "name": "Bob's News", "textSignature": "-- \nBob"},
                "x": {"email": "amy@example.test"}},
                "update": {&builtin: {"name": "Robert", "replyTo": [{"name": null, "email": "bob@example.test"}]}},
                "destroy": [&builtin]}),
        )
        .await;
    let news = r["created"]["n"]["id"].as_str().unwrap_or_else(|| panic!("{r}")).to_string();
    assert_eq!(r["notCreated"]["x"]["type"], "forbiddenFrom");
    assert!(r["updated"].get(&builtin).is_some(), "{r}");
    assert_eq!(r["notDestroyed"][&builtin]["type"], "forbidden");
    let g = bob.one("Identity/get", json!({})).await;
    let list = g["list"].as_array().unwrap();
    let b = list.iter().find(|i| i["id"] == json!(builtin)).unwrap();
    assert_eq!(b["name"], "Robert");
    assert_eq!(b["replyTo"][0]["email"], "bob@example.test");
    let n = list.iter().find(|i| i["id"] == json!(news)).unwrap();
    assert_eq!((n["email"].clone(), n["mayDelete"].clone()), (json!("bob+news@example.test"), json!(true)));
    let ch = bob.one("Identity/changes", json!({"sinceState": state})).await;
    assert!(ch["created"].as_array().unwrap().contains(&json!(news)), "{ch}");
    assert!(ch["updated"].as_array().unwrap().contains(&json!(builtin)), "{ch}");
    let r = bob.one("Identity/set", json!({"destroy": [&news]})).await;
    assert_eq!(r["destroyed"], json!([news]));

    // Blob/upload from several sources, then ranged Blob/get with digests.
    let up = bob
        .one("Blob/upload", json!({"create": {"a": {"data": [{"data:asText": "Hello, "}, {"data:asBase64": "d29ybGQh"}], "type": "text/plain"}}}))
        .await;
    let a = up["created"]["a"]["id"].as_str().unwrap().to_string();
    assert_eq!(up["created"]["a"]["size"], 13);
    let g = bob.one("Blob/get", json!({"ids": [&a], "properties": ["data:asText", "digest:sha-256", "size"], "offset": 7, "length": 5})).await;
    assert_eq!(g["list"][0]["data:asText"], "world");
    assert_eq!(g["list"][0]["size"], 13);
    assert_eq!(g["list"][0]["isTruncated"], false);
    assert!(g["list"][0]["digest:sha-256"].as_str().is_some_and(|d| d.len() == 44));
    let g = bob.one("Blob/get", json!({"ids": [&a, "u999999"], "offset": 10, "length": 50})).await;
    assert_eq!(g["list"][0]["data:asText"], "ld!");
    assert_eq!(g["list"][0]["isTruncated"], true);
    assert_eq!(g["notFound"], json!(["u999999"]));
    // A blob built from a range of another one.
    let up = bob.one("Blob/upload", json!({"create": {"b": {"data": [{"blobId": &a, "offset": 0, "length": 5}]}}})).await;
    let b = up["created"]["b"]["id"].as_str().unwrap().to_string();
    assert_eq!(bob.one("Blob/get", json!({"ids": [b]})).await["list"][0]["data:asText"], "Hello");

    // Email/parse: a message too large to keep, read without storing it.
    let raw = "From: Ann <ann@example.org>\r\nTo: bob@example.test\r\nSubject: Parsed\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nInside text\r\n--b\r\nContent-Type: application/pdf; name=x.pdf\r\nContent-Disposition: attachment; filename=x.pdf\r\n\r\n%PDF\r\n--b--\r\n";
    let up = bob.one("Blob/upload", json!({"create": {"m": {"data": [{"data:asText": raw}], "type": "message/rfc822"}}})).await;
    let m = up["created"]["m"]["id"].as_str().unwrap().to_string();
    let p = bob.one("Email/parse", json!({"blobIds": [&m, "u424242"], "fetchTextBodyValues": true})).await;
    let e = &p["parsed"][&m];
    assert_eq!(e["subject"], "Parsed");
    assert_eq!(e["from"][0]["email"], "ann@example.org");
    let part = e["textBody"][0]["partId"].as_str().unwrap();
    assert_eq!(e["bodyValues"][part]["value"].as_str().unwrap().trim(), "Inside text");
    assert_eq!(e["attachments"][0]["name"], "x.pdf");
    assert_eq!(p["notFound"], json!(["u424242"]));
    let att_blob = e["attachments"][0]["blobId"].as_str().unwrap().to_string();
    assert!(att_blob.starts_with('P'), "{att_blob}");
    let g = bob.one("Blob/get", json!({"ids": [att_blob]})).await;
    assert_eq!(g["list"][0]["data:asText"].as_str().unwrap().trim(), "%PDF");

    // MDN/send: Amy reads Bob's message and sends the receipt he asked for.
    let asking = "From: Bob <bob@example.test>\r\nTo: amy@example.test\r\nSubject: Please confirm\r\nMessage-ID: <ask@example.test>\r\nDisposition-Notification-To: bob@example.test\r\n\r\nDid you get it?\r\n";
    let (eid, _) = amy.import("inbox", asking, json!({})).await;
    let aid = amy.one("Identity/get", json!({})).await["list"][0]["id"].as_str().unwrap().to_string();
    let before = inbox_count(&s, "bob@example.test").await;
    let send = json!({"identityId": aid, "send": {"r": {"forEmailId": eid, "disposition": {"actionMode": "manual-action", "sendingMode": "mdn-sent-manually", "type": "displayed"}}}});
    let mut args = send.clone();
    args["accountId"] = json!(amy.account);
    let r = amy.call(json!([["MDN/send", args, "0"]])).await;
    assert!(r[0][1]["sent"].get("r").is_some(), "{r:?}");
    assert_eq!(r[1][0], "Email/set", "the receipt is recorded on the message");
    assert_eq!(inbox_count(&s, "bob@example.test").await, before + 1);
    let kw = amy.one("Email/get", json!({"ids": [&eid], "properties": ["keywords"]})).await;
    assert_eq!(kw["list"][0]["keywords"]["$mdnsent"], true);
    // The receipt Bob got is a disposition notification for his message.
    let bob_acc = s.state.db.account_by_email("bob@example.test").await.unwrap().unwrap();
    let mb = s.state.db.mailbox(bob_acc.id, "INBOX").await.unwrap().unwrap();
    let rows = s.state.db.messages_by_uids(mb.id, 1, 1_000_000).await.unwrap();
    let raw = s.state.blobs.get(&rows.last().unwrap().blob).await.unwrap();
    let text = String::from_utf8_lossy(&raw);
    assert!(text.contains("report-type=disposition-notification") && text.contains("Original-Message-ID: <ask@example.test>"), "{text}");
    assert!(text.contains("Disposition: manual-action/mdn-sent-manually; displayed"), "{text}");
    let mut args = send;
    args["accountId"] = json!(amy.account);
    let r = amy.call(json!([["MDN/send", args, "0"]])).await;
    assert_eq!(r[0][1]["notSent"]["r"]["type"], "mdnAlreadySent");
}

// ------------------------------------------------------------ Pinal encryption at rest

fn test_key() -> pgp::composed::SignedSecretKey {
    use pgp::composed::{EncryptionCaps, KeyType, SecretKeyParamsBuilder, SubkeyParamsBuilder};
    use pgp::crypto::ecc_curve::ECCCurve;
    let mut encrypt = SubkeyParamsBuilder::default();
    encrypt.key_type(KeyType::ECDH(ECCCurve::Curve25519Legacy)).can_sign(false).can_encrypt(EncryptionCaps::All);
    let mut params = SecretKeyParamsBuilder::default();
    params
        .key_type(KeyType::Ed25519Legacy)
        .can_certify(true)
        .can_sign(true)
        .can_encrypt(EncryptionCaps::None)
        .primary_user_id("Amy <amy@example.test>".into())
        .subkeys(vec![encrypt.build().unwrap()]);
    params.build().unwrap().generate(rand08::thread_rng()).unwrap()
}

/// Open a stored message as the Picacho app does (manage/crypto.rs
/// `open_message`): the outer headers without Content-Type, then the
/// decrypted part. Panics if it isn't the expected PGP/MIME shape.
fn open_like_the_app(stored: &[u8], key: &pgp::composed::SignedSecretKey) -> String {
    use pgp::composed::Message;
    use pgp::types::Password;
    let text = String::from_utf8_lossy(stored).to_string();
    let (head, body) = text.split_once("\r\n\r\n").unwrap();
    assert!(head.contains("Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\""), "{head}");
    let boundary = head.split("boundary=\"").nth(1).unwrap().split('"').next().unwrap();
    let parts: Vec<&str> = body.split(&format!("--{boundary}")).skip(1).filter(|p| !p.starts_with("--")).collect();
    assert_eq!(parts.len(), 2, "two parts: version and payload");
    assert!(parts[0].contains("Content-Type: application/pgp-encrypted") && parts[0].contains("Version: 1"));
    assert!(parts[1].contains("Content-Type: application/octet-stream"));
    let armored = parts[1].split_once("\r\n\r\n").unwrap().1.trim();
    assert!(armored.starts_with("-----BEGIN PGP MESSAGE-----"));
    let (message, _) = Message::from_string(armored).unwrap();
    let passwords = [Password::empty()];
    let mut opened = message.decrypt_with_keys(passwords.iter().collect(), vec![key]).unwrap();
    assert!(!opened.is_compressed(), "the app refuses compressed data");
    let inner = String::from_utf8(opened.as_data_vec().unwrap()).unwrap();
    let outer: String = head
        .split("\r\n")
        .filter(|l| !l.to_ascii_lowercase().starts_with("content-type:"))
        .map(|l| format!("{l}\r\n"))
        .collect();
    format!("{outer}{inner}")
}

#[tokio::test]
async fn pinal_encryption_at_rest() {
    let s = server().await;
    let key = test_key();
    let public = pgp::composed::SignedPublicKey::from(key.clone()).to_armored_string(Default::default()).unwrap();
    let amy = s.state.db.account_by_email("amy@example.test").await.unwrap().unwrap();
    let (token, h, p) = picacho_server::auth::generate_token();
    s.state.db.create_token(amy.id, "settings", &h, &p, "account", None).await.unwrap();
    let c = reqwest::Client::new();
    let url = format!("http://{}/api/v1/me/encryption", s.web);
    let r: serde_json::Value = c.get(&url).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(r["encrypted"], false);
    let r = c.put(&url).bearer_auth(&token).header("x-picacho", "1").json(&serde_json::json!({"public_key": "not a key"})).send().await.unwrap();
    assert_eq!(r.status(), 400);
    let r = c.put(&url).bearer_auth(&token).header("x-picacho", "1").json(&serde_json::json!({"public_key": public})).send().await.unwrap();
    assert_eq!(r.status(), 200, "{}", r.text().await.unwrap());
    let r: serde_json::Value = c.get(&url).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(r["encrypted"], true);
    assert_eq!(r["fingerprint"].as_str().unwrap().len(), 40);

    // Delivered mail is stored encrypted; listing headers stay readable.
    let mut mx = Smtp::connect(s.smtp).await;
    mx.cmd("EHLO peer.test").await;
    assert!(mx.cmd("MAIL FROM:<ann@peer.test>").await.starts_with("250"));
    assert!(mx.cmd("RCPT TO:<amy@example.test>").await.starts_with("250"));
    let original = "From: Ann <ann@peer.test>\r\nTo: amy@example.test\r\nSubject: Secret plans\r\nMessage-ID: <plans@peer.test>\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\nMeet at the old mill at nine. \u{2615}\r\n";
    assert!(mx.data(original).await.starts_with("250"));
    let mb = s.state.db.mailbox(amy.id, "INBOX").await.unwrap().unwrap();
    let rows = s.state.db.messages_by_uids(mb.id, 1, 1_000_000).await.unwrap();
    assert_eq!(rows.len(), 1);
    let stored = s.state.blobs.get(&rows[0].blob).await.unwrap();
    let stored_text = String::from_utf8_lossy(&stored);
    assert!(!stored_text.contains("old mill"), "the body isn't readable on the server");
    assert!(stored_text.contains("Subject: Secret plans"), "headers stay outside");
    assert!(rows[0].envelope.contains("Secret plans"), "ENVELOPE still works");
    let opened = open_like_the_app(&stored, &key);
    assert!(opened.contains("Subject: Secret plans\r\n"), "{opened}");
    assert!(opened.contains("Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\nMeet at the old mill at nine. \u{2615}"), "{opened}");
    assert_eq!(opened.matches("Content-Type:").count(), 1, "{opened}");

    // Mail its sender encrypted is kept as it came.
    assert!(mx.cmd("MAIL FROM:<ann@peer.test>").await.starts_with("250"));
    assert!(mx.cmd("RCPT TO:<amy@example.test>").await.starts_with("250"));
    let pgp_mail = "From: ann@peer.test\r\nTo: amy@example.test\r\nSubject: Already\r\nMIME-Version: 1.0\r\nContent-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=x\r\n\r\n--x\r\nContent-Type: application/pgp-encrypted\r\n\r\nVersion: 1\r\n--x\r\nContent-Type: application/octet-stream\r\n\r\n-----BEGIN PGP MESSAGE-----\r\nabc\r\n-----END PGP MESSAGE-----\r\n--x--\r\n";
    assert!(mx.data(pgp_mail).await.starts_with("250"));
    let rows = s.state.db.messages_by_uids(mb.id, 1, 1_000_000).await.unwrap();
    let stored = s.state.blobs.get(&rows[1].blob).await.unwrap();
    assert_eq!(String::from_utf8_lossy(&stored).matches("multipart/encrypted").count(), 1, "not wrapped twice");
    assert!(String::from_utf8_lossy(&stored).contains("boundary=x"));

    // Turned off: mail is stored as it arrives again.
    let r = c.delete(&url).bearer_auth(&token).header("x-picacho", "1").send().await.unwrap();
    assert_eq!(r.status(), 200);
    assert!(mx.cmd("MAIL FROM:<ann@peer.test>").await.starts_with("250"));
    assert!(mx.cmd("RCPT TO:<amy@example.test>").await.starts_with("250"));
    assert!(mx.data(&msg("plain", "Readable again")).await.starts_with("250"));
    let rows = s.state.db.messages_by_uids(mb.id, 1, 1_000_000).await.unwrap();
    let stored = s.state.blobs.get(&rows[2].blob).await.unwrap();
    assert!(String::from_utf8_lossy(&stored).contains("Readable again"));
}

// ------------------------------------------------------------ Web Key Directory

/// The WKD hash of a local part, as the Picacho app computes it
/// (sync/keys.rs `wkd_urls`).
fn wkd_hash(local: &str) -> String {
    const ALPHABET: &[u8; 32] = b"ybndrfg8ejkmcpqxot1uwisza345h769";
    let digest = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, local.to_ascii_lowercase().as_bytes());
    let (mut out, mut buffer, mut bits) = (String::new(), 0u32, 0);
    for &b in digest.as_ref() {
        buffer = (buffer << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            out.push(ALPHABET[((buffer >> (bits - 5)) & 31) as usize] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    out
}

#[tokio::test]
async fn web_key_directory_publishes_account_keys() {
    use pgp::composed::{Deserializable, EncryptionCaps, KeyType, SecretKeyParamsBuilder, SignedPublicKey, SubkeyParamsBuilder};
    use pgp::crypto::ecc_curve::ECCCurve;
    use pgp::types::KeyDetails as _;
    let s = server().await;
    let mut encrypt = SubkeyParamsBuilder::default();
    encrypt.key_type(KeyType::ECDH(ECCCurve::Curve25519Legacy)).can_sign(false).can_encrypt(EncryptionCaps::All);
    let mut params = SecretKeyParamsBuilder::default();
    params
        .key_type(KeyType::Ed25519Legacy)
        .can_certify(true)
        .can_sign(true)
        .can_encrypt(EncryptionCaps::None)
        .primary_user_id("Amy <amy@example.test>".into())
        .user_ids(vec!["Amy Sales <sales@example.test>".into(), "amy@home.test".into()])
        .subkeys(vec![encrypt.build().unwrap()]);
    let public = SignedPublicKey::from(params.build().unwrap().generate(rand08::thread_rng()).unwrap());
    let amy = s.state.db.account_by_email("amy@example.test").await.unwrap().unwrap();
    let (token, h, p) = picacho_server::auth::generate_token();
    s.state.db.create_token(amy.id, "settings", &h, &p, "account", None).await.unwrap();
    let c = reqwest::Client::new();
    let r = c
        .put(format!("http://{}/api/v1/me/encryption", s.web))
        .bearer_auth(&token)
        .header("x-picacho", "1")
        .json(&serde_json::json!({"public_key": public.to_armored_string(Default::default()).unwrap()}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    s.state.db.create_alias("sales@example.test", "amy@example.test").await.unwrap();
    s.state.db.create_alias("team@example.test", "amy@example.test").await.unwrap();

    let get = |host: &str, path: String| {
        let req = c.get(format!("http://{}{path}", s.web)).header("host", host);
        async move {
            let r = req.send().await.unwrap();
            let ctype = r.headers().get("content-type").map(|v| v.to_str().unwrap().to_string()).unwrap_or_default();
            (r.status().as_u16(), ctype, r.bytes().await.unwrap().to_vec())
        }
    };
    let user_ids = |bytes: &[u8]| -> Vec<String> {
        let key = SignedPublicKey::from_bytes(bytes).unwrap();
        key.verify_bindings().unwrap();
        assert_eq!(key.fingerprint(), public.fingerprint());
        key.details.users.iter().map(|u| String::from_utf8_lossy(u.id.id()).into_owned()).collect()
    };

    // The direct method, as the app asks: binary key, its User ID only.
    let (status, ctype, body) = get("example.test", format!("/.well-known/openpgpkey/hu/{}?l=Amy", wkd_hash("amy"))).await;
    assert_eq!((status, ctype.as_str()), (200, "application/octet-stream"));
    assert_eq!(user_ids(&body), ["Amy <amy@example.test>"]);
    // `l=` is optional.
    let (status, _, body) = get("example.test", format!("/.well-known/openpgpkey/hu/{}", wkd_hash("amy"))).await;
    assert_eq!(status, 200);
    assert_eq!(user_ids(&body), ["Amy <amy@example.test>"]);
    assert_eq!(get("example.test", "/.well-known/openpgpkey/policy".into()).await.0, 200);

    // The advanced method, on openpgpkey.<domain>; an alias gets its owner's key.
    let (status, ctype, body) = get("openpgpkey.example.test", format!("/.well-known/openpgpkey/example.test/hu/{}?l=sales", wkd_hash("sales"))).await;
    assert_eq!((status, ctype.as_str()), (200, "application/octet-stream"));
    assert_eq!(user_ids(&body), ["Amy Sales <sales@example.test>"]);
    assert_eq!(get("openpgpkey.example.test", "/.well-known/openpgpkey/example.test/policy".into()).await.0, 200);
    // The path's domain must be the host's.
    assert_eq!(get("example.test", "/.well-known/openpgpkey/example.test/policy".into()).await.0, 404);
    assert_eq!(get("openpgpkey.other.test", format!("/.well-known/openpgpkey/other.test/hu/{}?l=amy", wkd_hash("amy"))).await.0, 404);

    // Nothing for addresses the key doesn't name, accounts without a key,
    // unknown users, or domains not hosted here.
    assert_eq!(get("example.test", format!("/.well-known/openpgpkey/hu/{}?l=team", wkd_hash("team"))).await.0, 404);
    assert_eq!(get("example.test", format!("/.well-known/openpgpkey/hu/{}?l=bob", wkd_hash("bob"))).await.0, 404);
    assert_eq!(get("example.test", format!("/.well-known/openpgpkey/hu/{}?l=nobody", wkd_hash("nobody"))).await.0, 404);
    assert_eq!(get("home.test", format!("/.well-known/openpgpkey/hu/{}?l=amy", wkd_hash("amy"))).await.0, 404);
    assert_eq!(get("home.test", "/.well-known/openpgpkey/policy".into()).await.0, 404);

    // Turned off in the configuration ([web] wkd = false): nothing is published.
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    cfg.storage.data_dir = dir.path().to_path_buf();
    cfg.web.wkd = false;
    let off = AppState::new(cfg).await.unwrap();
    let d = off.db.create_domain("example.test", "local", "").await.unwrap();
    let id = off.db.create_account("amy@example.test", d, "!", "Amy", "user", 0).await.unwrap();
    let armored = public.to_armored_string(Default::default()).unwrap();
    off.db.set_encryption_key(id, Some((&armored, "fp"))).await.unwrap();
    let web = picacho_server::web::serve(off, "127.0.0.1:0".parse().unwrap()).await.unwrap();
    let r = c.get(format!("http://{web}/.well-known/openpgpkey/hu/{}?l=amy", wkd_hash("amy"))).header("host", "example.test").send().await.unwrap();
    assert_eq!(r.status(), 404);
}

// ------------------------------------------------------------ CalDAV free/busy

async fn dav(s: &Srv, user: &str, method: &str, path: &str, ctype: &str, body: &str) -> (u16, String) {
    // PROPFIND on a collection lists its members (Depth: 1).
    let depth = if matches!(method, "PROPFIND" | "REPORT") && path.ends_with('/') && !path.contains("/principals/") && path != "/dav/" { "1" } else { "0" };
    let r = reqwest::Client::new()
        .request(reqwest::Method::from_bytes(method.as_bytes()).unwrap(), format!("http://{}{path}", s.web))
        .basic_auth(user, Some("Correct-Horse-9"))
        .header("content-type", ctype)
        .header("depth", depth)
        .body(body.to_string())
        .send()
        .await
        .unwrap();
    (r.status().as_u16(), r.text().await.unwrap())
}

#[tokio::test]
async fn caldav_free_busy_through_the_scheduling_outbox() {
    let s = server().await;
    // Amy has two events: one busy, one marked free (transparent).
    let event = |uid: &str, start: &str, end: &str, transp: &str| {
        format!("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//test//EN\r\nBEGIN:VEVENT\r\nUID:{uid}\r\nDTSTAMP:20261101T000000Z\r\nDTSTART:{start}\r\nDTEND:{end}\r\nSUMMARY:Private dentist\r\nTRANSP:{transp}\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n")
    };
    let (st, _) = dav(&s, "amy@example.test", "PROPFIND", "/dav/", "application/xml", "<propfind xmlns=\"DAV:\"><prop><resourcetype/></prop></propfind>").await;
    assert_eq!(st, 207);
    for (n, e) in [("a", event("a", "20261201T100000Z", "20261201T110000Z", "OPAQUE")), ("b", event("b", "20261201T140000Z", "20261201T150000Z", "TRANSPARENT"))] {
        let (st, body) = dav(&s, "amy@example.test", "PUT", &format!("/dav/calendars/amy@example.test/default/{n}.ics"), "text/calendar", &e).await;
        assert!(st == 201 || st == 204, "{st} {body}");
    }

    // Bob finds his outbox, then asks when Amy (and a stranger) are busy.
    let (st, body) = dav(&s, "bob@example.test", "PROPFIND", "/dav/principals/bob@example.test/", "application/xml",
        "<propfind xmlns=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:caldav\"><prop><C:schedule-outbox-URL/></prop></propfind>").await;
    assert_eq!(st, 207);
    assert!(body.contains("/dav/calendars/bob@example.test/outbox/"), "{body}");
    let request = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//test//EN\r\nMETHOD:REQUEST\r\nBEGIN:VFREEBUSY\r\nUID:fb-1\r\nDTSTAMP:20261122T000000Z\r\nDTSTART:20261201T000000Z\r\nDTEND:20261202T000000Z\r\nORGANIZER:mailto:bob@example.test\r\nATTENDEE:mailto:amy@example.test\r\nATTENDEE:mailto:someone@elsewhere.test\r\nEND:VFREEBUSY\r\nEND:VCALENDAR\r\n";
    let (st, body) = dav(&s, "bob@example.test", "POST", "/dav/calendars/bob@example.test/outbox/", "text/calendar; charset=utf-8", request).await;
    assert_eq!(st, 200, "{body}");
    assert!(body.contains("schedule-response"), "{body}");
    assert!(body.contains("mailto:amy@example.test") && body.contains("2.0;Success"), "{body}");
    assert!(body.contains("FREEBUSY:20261201T100000Z/20261201T110000Z"), "the busy hour: {body}");
    assert!(!body.contains("20261201T140000Z"), "transparent events don't count: {body}");
    assert!(!body.contains("dentist"), "only times are shared: {body}");
    assert!(body.contains("METHOD:REPLY") && body.contains("UID:fb-1"), "{body}");
    assert!(body.contains("3.7;Invalid calendar user"), "unknown attendee: {body}");

    // Nobody can ask in someone else's name, or post elsewhere.
    let forged = request.replace("ORGANIZER:mailto:bob@", "ORGANIZER:mailto:amy@");
    let (st, _) = dav(&s, "bob@example.test", "POST", "/dav/calendars/bob@example.test/outbox/", "text/calendar", &forged).await;
    assert_eq!(st, 403);
    let (st, _) = dav(&s, "bob@example.test", "POST", "/dav/calendars/amy@example.test/outbox/", "text/calendar", request).await;
    assert_eq!(st, 403);
    let (st, _) = dav(&s, "bob@example.test", "POST", "/dav/calendars/bob@example.test/default/", "text/calendar", request).await;
    assert_eq!(st, 405);
    // The scheduling server never claims to send invitations itself.
    let r = reqwest::Client::new().request(reqwest::Method::OPTIONS, format!("http://{}/dav/", s.web)).send().await.unwrap();
    assert!(!r.headers()["dav"].to_str().unwrap().contains("calendar-auto-schedule"));

    // Turned off: only one's own busy time.
    let mut set = (*s.state.settings()).clone();
    set.dav.free_busy_lookup = false;
    s.state.save_settings(set).await.unwrap();
    let (_, body) = dav(&s, "bob@example.test", "POST", "/dav/calendars/bob@example.test/outbox/", "text/calendar", request).await;
    assert!(!body.contains("2.0;Success"), "{body}");
}

#[tokio::test]
async fn caldav_managed_attachments() {
    let s = server().await;
    let c = reqwest::Client::new();
    let base = format!("http://{}", s.web);
    let ev = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//test//EN\r\nBEGIN:VEVENT\r\nUID:att-1\r\nDTSTAMP:20261101T000000Z\r\nDTSTART:20261201T100000Z\r\nDTEND:20261201T110000Z\r\nSUMMARY:Review\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
    let href = "/dav/calendars/bob@example.test/default/att-1.ics";
    let (st, _) = dav(&s, "bob@example.test", "PUT", href, "text/calendar", ev).await;
    assert_eq!(st, 201);
    // What the app checks first (sync/dav.rs `manages_attachments`, `attachment_limits`).
    let r = c.request(reqwest::Method::OPTIONS, format!("{base}/dav/calendars/bob@example.test/default/")).send().await.unwrap();
    assert!(r.headers()["dav"].to_str().unwrap().contains("calendar-managed-attachments"));
    let (_, body) = dav(&s, "bob@example.test", "PROPFIND", "/dav/calendars/bob@example.test/default/", "application/xml",
        "<propfind xmlns=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:caldav\"><prop><C:max-attachment-size/><C:max-attachments-per-resource/></prop></propfind>").await;
    assert!(body.contains("max-attachment-size>") && body.contains("max-attachments-per-resource>20<"), "{body}");

    let etag = |r: &reqwest::Response| r.headers().get("etag").map(|v| v.to_str().unwrap().to_string()).unwrap_or_default();
    let (_, before) = dav(&s, "bob@example.test", "GET", href, "", "").await;
    let current = c.get(format!("{base}{href}")).basic_auth("bob@example.test", Some("Correct-Horse-9")).send().await.unwrap();
    let tag = etag(&current);
    assert!(!before.contains("ATTACH"));
    // Add, as the app sends it.
    let r = c
        .post(format!("{base}{href}?action=attachment-add"))
        .basic_auth("bob@example.test", Some("Correct-Horse-9"))
        .header("content-type", "application/pdf")
        .header("content-disposition", "attachment;filename=\"plan.pdf\";filename*=UTF-8''pl%C3%A4n.pdf")
        .header("if-match", &tag)
        .body("%PDF-1.4 hello")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 201);
    let id = r.headers()["cal-managed-id"].to_str().unwrap().to_string();
    let tag = etag(&r);
    let (_, ics) = dav(&s, "bob@example.test", "GET", href, "", "").await;
    let unfolded = ics.replace("\r\n ", "");
    assert!(unfolded.contains(&format!("MANAGED-ID={id}")) && unfolded.contains("FILENAME=plän.pdf") && unfolded.contains("SIZE=14") && unfolded.contains("FMTTYPE=application/pdf"), "{ics}");
    let url = unfolded.lines().find(|l| l.starts_with("ATTACH")).unwrap().rsplit_once(':').map(|x| x.1).unwrap();
    let url = format!("{base}{}", &url[url.find("/dav/").unwrap()..]);
    // The file, for the owner and for a guest signed in here; nobody else.
    for user in ["bob@example.test", "amy@example.test"] {
        let r = c.get(&url).basic_auth(user, Some("Correct-Horse-9")).send().await.unwrap();
        assert_eq!(r.status(), 200, "{user}");
        assert!(r.headers()["content-disposition"].to_str().unwrap().contains("pl%C3%A4n.pdf"));
        assert_eq!(r.text().await.unwrap(), "%PDF-1.4 hello");
    }
    assert_eq!(c.get(&url).send().await.unwrap().status(), 401);
    // Clients can't write the files directly.
    let (st, _) = dav(&s, "bob@example.test", "PUT", &url[url.find("/dav/").unwrap()..], "application/pdf", "x").await;
    assert_eq!(st, 403);
    // A stale ETag is refused; an unknown id too.
    let r = c.post(format!("{base}{href}?action=attachment-remove&managed-id={id}")).basic_auth("bob@example.test", Some("Correct-Horse-9")).header("if-match", "\"old\"").send().await.unwrap();
    assert_eq!(r.status(), 412);
    let r = c.post(format!("{base}{href}?action=attachment-remove&managed-id=nope")).basic_auth("bob@example.test", Some("Correct-Horse-9")).send().await.unwrap();
    assert_eq!(r.status(), 403);
    assert!(r.text().await.unwrap().contains("valid-managed-id"));
    // Update replaces the file and its id; then remove takes it off and away.
    let r = c
        .post(format!("{base}{href}?action=attachment-update&managed-id={id}"))
        .basic_auth("bob@example.test", Some("Correct-Horse-9"))
        .header("content-type", "text/plain")
        .header("content-disposition", "attachment;filename=\"notes.txt\"")
        .header("if-match", &tag)
        .body("v2")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 201);
    let id2 = r.headers()["cal-managed-id"].to_str().unwrap().to_string();
    assert_ne!(id, id2);
    assert_eq!(c.get(&url).basic_auth("bob@example.test", Some("Correct-Horse-9")).send().await.unwrap().status(), 404, "the old file is gone");
    let r = c.post(format!("{base}{href}?action=attachment-remove&managed-id={id2}")).basic_auth("bob@example.test", Some("Correct-Horse-9")).send().await.unwrap();
    assert_eq!(r.status(), 204);
    let (_, ics) = dav(&s, "bob@example.test", "GET", href, "", "").await;
    assert!(!ics.contains("ATTACH"), "{ics}");
    let (_, list) = dav(&s, "bob@example.test", "PROPFIND", "/dav/calendars/bob@example.test/attachments/", "application/xml", "<propfind xmlns=\"DAV:\"><prop><getetag/></prop></propfind>").await;
    assert!(!list.contains(&id2), "{list}");

    // Deleting the event takes its files along; an unknown occurrence is refused.
    let r = c.post(format!("{base}{href}?action=attachment-add")).basic_auth("bob@example.test", Some("Correct-Horse-9")).body("x").send().await.unwrap();
    let id3 = r.headers()["cal-managed-id"].to_str().unwrap().to_string();
    let r = c.post(format!("{base}{href}?action=attachment-add&rid=20261202T100000Z")).basic_auth("bob@example.test", Some("Correct-Horse-9")).body("x").send().await.unwrap();
    assert_eq!(r.status(), 403);
    assert!(r.text().await.unwrap().contains("valid-rid"));
    let (st, _) = dav(&s, "bob@example.test", "DELETE", href, "", "").await;
    assert_eq!(st, 204);
    let r = c.get(format!("{base}/dav/calendars/bob@example.test/attachments/{id3}")).basic_auth("bob@example.test", Some("Correct-Horse-9")).send().await.unwrap();
    assert_eq!(r.status(), 404);
}

#[tokio::test]
async fn caldav_server_scheduling() {
    let s = server().await;
    let c = reqwest::Client::new();
    let base = format!("http://{}", s.web);
    let opts = |c: &reqwest::Client| c.request(reqwest::Method::OPTIONS, format!("{base}/dav/calendars/bob@example.test/"));
    assert!(!opts(&c).send().await.unwrap().headers()["dav"].to_str().unwrap().contains("calendar-auto-schedule"), "off by default");
    let mut set = (*s.state.settings()).clone();
    set.dav.server_scheduling = true;
    s.state.save_settings(set).await.unwrap();
    s.state.db.domain_by_name("example.test").await.unwrap().unwrap();
    // As the app finds out (sync/caldav.rs `schedules`, `scheduling_identity`).
    assert!(opts(&c).send().await.unwrap().headers()["dav"].to_str().unwrap().contains("calendar-auto-schedule"));
    for who in ["bob@example.test", "amy@example.test"] {
        let (st, body) = dav(&s, who, "PROPFIND", &format!("/dav/principals/{who}/"), "application/xml",
            "<propfind xmlns=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:caldav\"><prop><C:schedule-inbox-URL/></prop></propfind>").await;
        assert_eq!(st, 207);
        assert!(body.contains(&format!("/dav/calendars/{who}/inbox/")), "{body}");
    }
    let (_, body) = dav(&s, "amy@example.test", "PROPFIND", "/dav/calendars/amy@example.test/inbox/", "application/xml",
        "<propfind xmlns=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:caldav\"><prop><resourcetype/><C:schedule-default-calendar-URL/></prop></propfind>").await;
    assert!(body.contains("<C:schedule-inbox/>") && body.contains("schedule-default-calendar-URL><D:href>/dav/calendars/amy@example.test/default/"), "{body}");

    // Bob invites Amy (here) and Cy (elsewhere).
    let ev = |seq: &str, start: &str, extra: &str| format!(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//test//EN\r\nBEGIN:VEVENT\r\nUID:meet-1\r\nDTSTAMP:20261101T000000Z\r\nDTSTART:{start}\r\nDURATION:PT1H\r\nSUMMARY:Planning\r\n{seq}\
         ORGANIZER;CN=Bob:mailto:bob@example.test\r\nATTENDEE;PARTSTAT=ACCEPTED:mailto:bob@example.test\r\nATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:mailto:amy@example.test\r\n{extra}END:VEVENT\r\nEND:VCALENDAR\r\n");
    let bob_href = "/dav/calendars/bob@example.test/default/meet-1.ics";
    let (st, _) = dav(&s, "bob@example.test", "PUT", bob_href, "text/calendar", &ev("", "20261201T100000Z", "ATTENDEE:mailto:cy@elsewhere.test\r\n")).await;
    assert_eq!(st, 201);
    let (_, ics) = dav(&s, "bob@example.test", "GET", bob_href, "", "").await;
    let ics = ics.replace("\r\n ", "");
    assert!(ics.contains("SCHEDULE-STATUS=1.2:mailto:amy@example.test"), "{ics}");
    assert!(ics.contains("SCHEDULE-STATUS=1.1:mailto:cy@elsewhere.test"), "{ics}");
    // Cy gets an iMIP email from Bob's address.
    let q = s.state.db.due_queue(10).await.unwrap();
    assert_eq!(q.len(), 1);
    assert_eq!(q[0].recipients, ["cy@elsewhere.test"]);
    let mail = String::from_utf8_lossy(&s.state.blobs.get(&q[0].blob).await.unwrap()).to_string();
    assert!(mail.contains("From: \"Bob\" <bob@example.test>") && mail.contains("text/calendar; charset=utf-8; method=REQUEST"), "{mail}");
    // Amy: the request in her inbox, the event in her calendar.
    let inbox = "<C:calendar-query xmlns:D=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:caldav\"><D:prop><D:getetag/><C:calendar-data/></D:prop><C:filter><C:comp-filter name=\"VCALENDAR\"/></C:filter></C:calendar-query>";
    let (st, body) = dav(&s, "amy@example.test", "REPORT", "/dav/calendars/amy@example.test/inbox/", "application/xml", inbox).await;
    assert_eq!(st, 207);
    assert!(body.contains("METHOD:REQUEST") && body.contains("UID:meet-1") && !body.contains("SCHEDULE-STATUS"), "{body}");
    let amy_href = "/dav/calendars/amy@example.test/default/meet-1.ics";
    let (st, amy_ics) = dav(&s, "amy@example.test", "GET", amy_href, "", "").await;
    assert_eq!(st, 200, "the invitation is in Amy's calendar");
    assert!(amy_ics.contains("SUMMARY:Planning") && !amy_ics.contains("METHOD"), "{amy_ics}");
    // She clears her inbox, as the app does after reading it.
    let item = body.split("<D:href>").nth(1).unwrap().split("</D:href>").next().unwrap().to_string();
    let (st, _) = dav(&s, "amy@example.test", "DELETE", &item, "", "").await;
    assert_eq!(st, 204);
    let (st, _) = dav(&s, "amy@example.test", "PUT", "/dav/calendars/amy@example.test/inbox/x.ics", "text/calendar", &ev("", "20261201T100000Z", "")).await;
    assert_eq!(st, 403, "clients don't put things in the inbox");

    // Amy accepts: Bob gets a REPLY and his copy says so.
    let accepted = amy_ics.replace("PARTSTAT=NEEDS-ACTION", "PARTSTAT=ACCEPTED");
    let (st, _) = dav(&s, "amy@example.test", "PUT", amy_href, "text/calendar", &accepted).await;
    assert_eq!(st, 204);
    let (_, body) = dav(&s, "bob@example.test", "REPORT", "/dav/calendars/bob@example.test/inbox/", "application/xml", inbox).await;
    assert!(body.contains("METHOD:REPLY") && body.contains("PARTSTAT=ACCEPTED"), "{body}");
    let (_, ics) = dav(&s, "bob@example.test", "GET", bob_href, "", "").await;
    assert!(ics.replace("\r\n ", "").contains("PARTSTAT=ACCEPTED;SCHEDULE-STATUS=2.0:mailto:amy@example.test"), "{ics}");

    // Bob changes only the summary: Amy's answer stays. Moving it asks again.
    let (_, ics) = dav(&s, "bob@example.test", "GET", bob_href, "", "").await;
    let (st, _) = dav(&s, "bob@example.test", "PUT", bob_href, "text/calendar", &ics.replace("SUMMARY:Planning", "SUMMARY:Planning v2")).await;
    assert_eq!(st, 204);
    let (_, a) = dav(&s, "amy@example.test", "GET", amy_href, "", "").await;
    assert!(a.contains("SUMMARY:Planning v2") && a.contains("PARTSTAT=ACCEPTED:mailto:amy@example.test"), "{a}");
    assert!(a.contains("SEQUENCE:1"), "{a}");
    let (_, ics) = dav(&s, "bob@example.test", "GET", bob_href, "", "").await;
    dav(&s, "bob@example.test", "PUT", bob_href, "text/calendar", &ics.replace("DTSTART:20261201T100000Z", "DTSTART:20261202T100000Z")).await;
    let (_, a) = dav(&s, "amy@example.test", "GET", amy_href, "", "").await;
    assert!(a.contains("DTSTART:20261202T100000Z") && a.contains("NEEDS-ACTION"), "{a}");

    // Schedule-Reply: F keeps an answer to oneself.
    let (_, before) = dav(&s, "bob@example.test", "REPORT", "/dav/calendars/bob@example.test/inbox/", "application/xml", inbox).await;
    let r = c.put(format!("{base}{amy_href}")).basic_auth("amy@example.test", Some("Correct-Horse-9")).header("content-type", "text/calendar").header("schedule-reply", "F")
        .body(a.replace("PARTSTAT=NEEDS-ACTION", "PARTSTAT=TENTATIVE")).send().await.unwrap();
    assert_eq!(r.status(), 204);
    let (_, after) = dav(&s, "bob@example.test", "REPORT", "/dav/calendars/bob@example.test/inbox/", "application/xml", inbox).await;
    assert_eq!(before.matches("<D:response>").count(), after.matches("<D:response>").count());

    // Bob cancels: Amy's copy is marked cancelled, Cy is mailed again.
    let (st, _) = dav(&s, "bob@example.test", "DELETE", bob_href, "", "").await;
    assert_eq!(st, 204);
    let (_, a) = dav(&s, "amy@example.test", "GET", amy_href, "", "").await;
    assert!(a.contains("STATUS:CANCELLED"), "{a}");
    let mut cancelled = false;
    for x in s.state.db.due_queue(20).await.unwrap() {
        cancelled |= String::from_utf8_lossy(&s.state.blobs.get(&x.blob).await.unwrap()).contains("method=CANCEL");
    }
    assert!(cancelled, "Cy is told it's off");
    // Amy removing the cancelled event sends Bob nothing.
    let (_, before) = dav(&s, "bob@example.test", "REPORT", "/dav/calendars/bob@example.test/inbox/", "application/xml", inbox).await;
    let (st, _) = dav(&s, "amy@example.test", "DELETE", amy_href, "", "").await;
    assert_eq!(st, 204);
    let (_, after) = dav(&s, "bob@example.test", "REPORT", "/dav/calendars/bob@example.test/inbox/", "application/xml", inbox).await;
    assert_eq!(before.matches("<D:response>").count(), after.matches("<D:response>").count());

    // A client that schedules itself (SCHEDULE-AGENT=CLIENT) sends nothing.
    let quiet = ev("", "20261205T100000Z", "").replace("ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:", "ATTENDEE;SCHEDULE-AGENT=CLIENT;PARTSTAT=NEEDS-ACTION:").replace("ORGANIZER;CN=Bob:", "ORGANIZER;SCHEDULE-AGENT=CLIENT;CN=Bob:").replace("meet-1", "meet-2");
    dav(&s, "bob@example.test", "PUT", "/dav/calendars/bob@example.test/default/meet-2.ics", "text/calendar", &quiet).await;
    let (st, _) = dav(&s, "amy@example.test", "GET", "/dav/calendars/amy@example.test/default/meet-2.ics", "", "").await;
    assert_eq!(st, 404);

    // JMAP: sendSchedulingMessages has the server invite (sync/jscal.rs `save_event_scheduled`).
    let (bob, _) = Jmap::new(&s, "bob@example.test").await;
    let cal = bob.one("Calendar/get", serde_json::json!({"ids": null})).await["list"][0]["id"].as_str().unwrap().to_string();
    let e = serde_json::json!({"@type": "Event", "uid": "jmap-meet", "title": "Sync", "start": "2026-12-09T10:00:00", "timeZone": "Etc/UTC", "duration": "PT30M",
        "calendarIds": {&cal: true},
        "participants": {"o": {"@type": "Participant", "sendTo": {"imip": "mailto:bob@example.test"}, "roles": {"owner": true, "attendee": true}, "scheduleAgent": "server"},
                         "a": {"@type": "Participant", "sendTo": {"imip": "mailto:amy@example.test"}, "roles": {"attendee": true}, "participationStatus": "needs-action", "scheduleAgent": "server"}}});
    let r = bob.one("CalendarEvent/set", serde_json::json!({"create": {"e": e}, "sendSchedulingMessages": true})).await;
    assert!(r["created"]["e"]["id"].is_string(), "{r}");
    let (_, body) = dav(&s, "amy@example.test", "REPORT", "/dav/calendars/amy@example.test/default/", "application/xml", inbox).await;
    assert!(body.contains("UID:jmap-meet"), "{body}");
}

// ------------------------------------------------------------ POP3

struct Pop {
    r: BufReader<tokio::net::tcp::OwnedReadHalf>,
    w: tokio::net::tcp::OwnedWriteHalf,
}

impl Pop {
    async fn connect(addr: SocketAddr) -> Self {
        let (r, w) = TcpStream::connect(addr).await.unwrap().into_split();
        let mut p = Pop { r: BufReader::new(r), w };
        assert!(p.line().await.starts_with("+OK"));
        p
    }
    async fn line(&mut self) -> String {
        let mut l = String::new();
        self.r.read_line(&mut l).await.unwrap();
        l
    }
    async fn cmd(&mut self, c: &str) -> String {
        self.w.write_all(format!("{c}\r\n").as_bytes()).await.unwrap();
        self.line().await
    }
    /// A multi-line reply's body, un-stuffed.
    async fn multi(&mut self, c: &str) -> (String, String) {
        let status = self.cmd(c).await;
        assert!(status.starts_with("+OK"), "{c}: {status}");
        let mut body = String::new();
        loop {
            let l = self.line().await;
            if l == ".\r\n" {
                return (status, body);
            }
            body.push_str(l.strip_prefix('.').filter(|_| l.starts_with("..")).unwrap_or(&l));
        }
    }
}

#[tokio::test]
async fn pop3_download_and_delete() {
    let s = server().await;
    let mut c = Imap::login(s.imap, "bob@example.test").await;
    for (i, body) in ["First", ".dotted line\r\nend"].iter().enumerate() {
        assert!(tagged_ok(&c.append("APPEND INBOX", &msg(&format!("p{i}"), body)).await));
    }
    let mut p = Pop::connect(s.pop3).await;
    let (_, capa) = p.multi("CAPA").await;
    for cap in ["UIDL", "TOP", "USER", "SASL PLAIN XOAUTH2 OAUTHBEARER", "RESP-CODES"] {
        assert!(capa.contains(cap), "{capa}");
    }
    assert!(p.cmd("STAT").await.starts_with("-ERR"), "not before signing in");
    assert!(p.cmd("USER bob@example.test").await.starts_with("+OK"));
    assert!(p.cmd("PASS wrong").await.starts_with("-ERR [AUTH]"));
    assert!(p.cmd("USER bob@example.test").await.starts_with("+OK"));
    assert!(p.cmd("PASS Correct-Horse-9").await.starts_with("+OK 2 messages"));
    let stat = p.cmd("STAT").await;
    assert!(stat.starts_with("+OK 2 "), "{stat}");
    let (_, uidl) = p.multi("UIDL").await;
    let ids: Vec<&str> = uidl.lines().map(|l| l.split(' ').nth(1).unwrap()).collect();
    assert_eq!(ids.len(), 2);
    assert!(ids.iter().all(|i| (1..=70).contains(&i.len()) && i.bytes().all(|b| (0x21..=0x7e).contains(&b))), "{uidl}");
    assert_ne!(ids[0], ids[1]);
    let (_, list) = p.multi("LIST").await;
    assert_eq!(list.lines().count(), 2);
    let (st, m) = p.multi("RETR 2").await;
    assert!(st.contains("octets"));
    assert!(m.contains("\r\n.dotted line\r\nend"), "dot-stuffing undone: {m:?}");
    let (_, top) = p.multi("TOP 2 0").await;
    assert!(top.contains("Subject: p1") && !top.contains("dotted"), "{top}");
    assert!(p.cmd("RETR 9").await.starts_with("-ERR"));
    // DELE then a dropped connection: nothing removed.
    assert!(p.cmd("DELE 1").await.starts_with("+OK"));
    assert!(p.cmd("RETR 1").await.starts_with("-ERR"), "deleted in this session");
    drop(p);
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert_eq!(inbox_count(&s, "bob@example.test").await, 2);

    // AUTH PLAIN, DELE, RSET, DELE again, QUIT: removed once QUIT confirms.
    use base64::Engine;
    let mut p = Pop::connect(s.pop3).await;
    let t = base64::engine::general_purpose::STANDARD.encode("\0bob@example.test\0Correct-Horse-9");
    assert!(p.cmd(&format!("AUTH PLAIN {t}")).await.starts_with("+OK"));
    let (_, again) = p.multi("UIDL").await;
    assert_eq!(again, uidl, "identities stay the same across sessions");
    assert!(p.cmd("DELE 1").await.starts_with("+OK"));
    assert!(p.cmd("RSET").await.starts_with("+OK"));
    assert!(p.cmd("STAT").await.starts_with("+OK 2 "));
    assert!(p.cmd("DELE 1").await.starts_with("+OK"));
    assert!(p.cmd("QUIT").await.starts_with("+OK"));
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert_eq!(inbox_count(&s, "bob@example.test").await, 1);

    // Account passwords off for apps: refused with the AUTH response code.
    let mut set = (*s.state.settings()).clone();
    set.auth.mail_password_login = false;
    s.state.save_settings(set).await.unwrap();
    let mut p = Pop::connect(s.pop3).await;
    p.cmd("USER bob@example.test").await;
    assert!(p.cmd("PASS Correct-Horse-9").await.starts_with("-ERR [AUTH]"));
}

// ------------------------------------------------------------ IMAP4rev2, UTF-8, UIDONLY, PARTIAL, NOTIFY

#[tokio::test]
async fn imap4rev2_utf8_and_uidonly() {
    let s = server().await;
    let mut c = Imap::login(s.imap, "bob@example.test").await;
    let caps = c.cmd("CAPABILITY").await;
    for cap in ["IMAP4rev2", "UTF8=ACCEPT", "UIDONLY", "PARTIAL", "NOTIFY", "URLAUTH"] {
        assert!(caps.contains(cap), "{cap}: {caps}");
    }
    for i in 1..=3 {
        assert!(tagged_ok(&c.append("APPEND INBOX", &msg(&format!("r{i}"), "x")).await));
    }
    // rev1 sessions are unchanged: RECENT, plain SEARCH.
    let r = c.cmd("SELECT INBOX").await;
    assert!(r.contains(" RECENT"), "{r}");
    assert!(c.cmd("UID SEARCH ALL").await.contains("* SEARCH 1 2 3"));

    let mut c = Imap::login(s.imap, "bob@example.test").await;
    let r = c.cmd("ENABLE IMAP4rev2 UIDONLY").await;
    assert!(r.contains("* ENABLED IMAP4rev2 UIDONLY"), "{r}");
    // UTF-8 mailbox names, stored as modified UTF-7 for older clients.
    assert!(tagged_ok(&c.cmd("CREATE \"Entwürfe\"").await));
    let r = c.cmd("LIST \"\" \"*\"").await;
    assert!(r.contains("\"Entwürfe\""), "{r}");
    let r = c.cmd("SELECT INBOX").await;
    assert!(!r.contains("RECENT") && r.contains("* LIST () \"/\" \"INBOX\""), "rev2 SELECT: {r}");
    // SEARCH answers as ESEARCH.
    let r = c.cmd("UID SEARCH ALL").await;
    assert!(r.contains("* ESEARCH (TAG") && r.contains("ALL 1:3"), "{r}");
    // UIDONLY: sequence numbers refused, replies as UIDFETCH.
    assert!(c.cmd("FETCH 1 FLAGS").await.contains("UIDREQUIRED"));
    let r = c.cmd("UID FETCH 2 (FLAGS)").await;
    assert!(r.contains("* 2 UIDFETCH (FLAGS ())") && !r.contains("UID 2"), "{r}");
    let r = c.cmd("UID STORE 3 +FLAGS (\\Seen)").await;
    assert!(r.contains("* 3 UIDFETCH (FLAGS (\\Seen))"), "{r}");
    // Expunges are reported as VANISHED.
    c.cmd("UID STORE 1 +FLAGS.SILENT (\\Deleted)").await;
    let r = c.cmd("UID EXPUNGE 1").await;
    assert!(r.contains("* VANISHED 1") && !r.contains("EXPUNGE\r"), "{r}");

    // An older client sees the same folder in modified UTF-7.
    let mut old = Imap::login(s.imap, "bob@example.test").await;
    let r = old.cmd("LIST \"\" \"*\"").await;
    assert!(r.contains("Entw&APw-rfe"), "{r}");
    assert!(tagged_ok(&old.cmd("SELECT \"Entw&APw-rfe\"").await));
}

#[tokio::test]
async fn imap_partial_and_notify() {
    let s = server().await;
    let mut c = Imap::login(s.imap, "bob@example.test").await;
    c.cmd("CREATE Lists").await;
    for i in 1..=10 {
        c.append("APPEND INBOX", &msg(&format!("n{i}"), "x")).await;
    }
    c.cmd("SELECT INBOX").await;
    // PARTIAL: the newest three of ten, with the count.
    let r = c.cmd("UID SEARCH RETURN (COUNT PARTIAL -1:-3) ALL").await;
    assert!(r.contains("PARTIAL (-1:-3 8:10)") && r.contains("COUNT 10"), "{r}");
    let r = c.cmd("UID SEARCH RETURN (PARTIAL 1:2) ALL").await;
    assert!(r.contains("PARTIAL (1:2 1:2)"), "{r}");
    assert!(c.cmd("UID SEARCH RETURN (PARTIAL 0:2) ALL").await.contains("BAD"));

    // NOTIFY: other mailboxes' changes arrive as STATUS, here during IDLE.
    let r = c.cmd("NOTIFY SET STATUS (SELECTED (MessageNew MessageExpunge FlagChange)) (PERSONAL (MessageNew MessageExpunge FlagChange))").await;
    assert!(tagged_ok(&r) && r.contains("* STATUS \"Lists\""), "initial STATUS: {r}");
    assert!(c.cmd("NOTIFY SET (PERSONAL (Bogus))").await.contains("BADEVENT"));
    c.cmd("NOTIFY SET (SELECTED (MessageNew)) (PERSONAL (MessageNew MessageExpunge FlagChange))").await;
    let mut other = Imap::login(s.imap, "bob@example.test").await;
    c.w.write_all(b"i1 IDLE\r\n").await.unwrap();
    let mut l = String::new();
    c.r.read_line(&mut l).await.unwrap();
    assert!(l.starts_with('+'), "{l}");
    other.append("APPEND Lists", &msg("list-mail", "x")).await;
    let mut heard = String::new();
    loop {
        let mut l = String::new();
        tokio::time::timeout(std::time::Duration::from_secs(5), c.r.read_line(&mut l)).await.expect("STATUS during IDLE").unwrap();
        heard.push_str(&l);
        if l.starts_with("* STATUS") {
            break;
        }
    }
    assert!(heard.contains("* STATUS \"Lists\" (MESSAGES 1"), "{heard}");
    c.w.write_all(b"DONE\r\n").await.unwrap();
    let mut l = String::new();
    c.r.read_line(&mut l).await.unwrap();
    assert!(l.starts_with("i1 OK"), "{l}");
    assert!(tagged_ok(&c.cmd("NOTIFY NONE").await));
}

// ------------------------------------------------------------ URLAUTH and BURL

#[tokio::test]
async fn urlauth_and_burl_send_from_the_mailbox() {
    let s = server().await;
    let mut c = Imap::login(s.imap, "bob@example.test").await;
    let body = msg("by-reference", "A large attachment, sent once");
    assert!(tagged_ok(&c.append("APPEND Sent", &body).await));
    let r = c.cmd("SELECT Sent").await;
    let validity: String = r.split("UIDVALIDITY ").nth(1).unwrap().split(']').next().unwrap().to_string();
    // What the Picacho app asks for (manage/connection.rs `submit_url`).
    let url = format!("imap://bob%40example.test@mx.example.test/Sent;UIDVALIDITY={validity}/;UID=1;urlauth=submit+bob%40example.test");
    let r = c.cmd(&format!("GENURLAUTH \"{url}\" INTERNAL")).await;
    assert!(tagged_ok(&r), "{r}");
    let authorized = r.lines().find(|l| l.starts_with("* GENURLAUTH")).unwrap().split('"').nth(1).unwrap().to_string();
    assert!(authorized.starts_with(&url) && authorized.contains(":internal:"), "{authorized}");
    // Only the submission server may fetch a submit+ URL, not even its owner.
    let r = c.cmd(&format!("URLFETCH \"{authorized}\"")).await;
    assert!(r.contains(" NIL"), "{r}");
    let user_url = format!("imap://bob%40example.test@mx.example.test/Sent;UIDVALIDITY={validity}/;UID=1;urlauth=user+bob%40example.test");
    let r = c.cmd(&format!("GENURLAUTH \"{user_url}\" INTERNAL")).await;
    let user_auth = r.lines().find(|l| l.starts_with("* GENURLAUTH")).unwrap().split('"').nth(1).unwrap().to_string();
    let r = c.cmd(&format!("URLFETCH \"{user_auth}\"")).await;
    assert!(r.contains("A large attachment, sent once"), "{r}");
    // Someone else can't authorize Bob's URLs.
    let mut amy = Imap::login(s.imap, "amy@example.test").await;
    assert!(amy.cmd(&format!("GENURLAUTH \"{url}\" INTERNAL")).await.contains("NO [BADURL]"));

    // BURL on submission: the message comes from the mailbox.
    let mut sm = Smtp::connect(s.submission).await;
    sm.cmd("EHLO client.test").await;
    sm.login("bob@example.test").await;
    let ehlo = sm.cmd("EHLO client.test").await;
    assert!(ehlo.contains("BURL imap") && ehlo.contains("BINARYMIME"), "{ehlo}");
    assert!(sm.cmd("MAIL FROM:<bob@example.test>").await.starts_with("250"));
    assert!(sm.cmd("RCPT TO:<amy@example.test>").await.starts_with("250"));
    let tampered = format!("{}0", &authorized[..authorized.len() - 1]);
    assert!(sm.cmd(&format!("BURL {tampered} LAST")).await.starts_with("554"), "a changed token is refused");
    let r = sm.cmd(&format!("BURL {authorized} LAST")).await;
    assert!(r.starts_with("250"), "{r}");
    assert_eq!(inbox_count(&s, "amy@example.test").await, 1);
    // RESETKEY: every URL issued before stops working.
    assert!(tagged_ok(&c.cmd("RESETKEY").await));
    assert!(sm.cmd("MAIL FROM:<bob@example.test>").await.starts_with("250"));
    assert!(sm.cmd("RCPT TO:<amy@example.test>").await.starts_with("250"));
    assert!(sm.cmd(&format!("BURL {authorized} LAST")).await.starts_with("554"));
}

// ------------------------------------------------------------ JMAP queryChanges and WebSocket

#[tokio::test]
async fn jmap_query_changes_and_websocket_push() {
    use serde_json::json;
    let s = server().await;
    let (bob, session) = Jmap::new(&s, "bob@example.test").await;
    assert_eq!(session["capabilities"]["urn:ietf:params:jmap:websocket"]["supportsPush"], true);
    let inbox = bob.mailbox("inbox").await;
    for i in 1..=3 {
        bob.import("inbox", &msg(&format!("q{i}"), "x"), json!({})).await;
    }
    let filter = json!({"inMailbox": inbox});
    let sort = json!([{"property": "receivedAt", "isAscending": false}]);
    let q = bob.one("Email/query", json!({"filter": filter, "sort": sort})).await;
    assert_eq!(q["canCalculateChanges"], true);
    let state = q["queryState"].as_str().unwrap().to_string();
    let first = q["ids"][2].as_str().unwrap().to_string();
    // One message leaves the mailbox, another arrives.
    let archive = bob.mailbox("archive").await;
    bob.one("Email/set", json!({"update": {&first: {"mailboxIds": {archive: true}}}})).await;
    let (new_id, _) = bob.import("inbox", &msg("q4", "x"), json!({})).await;
    let ch = bob.one("Email/queryChanges", json!({"filter": filter, "sort": sort, "sinceQueryState": state, "calculateTotal": true})).await;
    assert!(ch["removed"].as_array().unwrap().contains(&json!(first)), "{ch}");
    assert!(ch["added"].as_array().unwrap().iter().any(|a| a["id"] == json!(new_id)), "{ch}");
    assert_eq!(ch["total"], 3);

    // WebSocket: a Request over the socket, then pushed StateChanges.
    let url = session["capabilities"]["urn:ietf:params:jmap:websocket"]["url"].as_str().unwrap().replace("ws://", "");
    let (host, path) = url.split_once('/').unwrap();
    let tcp = TcpStream::connect(host).await.unwrap();
    use base64::Engine;
    let auth = base64::engine::general_purpose::STANDARD.encode("bob@example.test:Correct-Horse-9");
    let req = format!("GET /{path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: jmap\r\nAuthorization: Basic {auth}\r\n\r\n");
    let (r, mut w) = tcp.into_split();
    let mut r = BufReader::new(r);
    w.write_all(req.as_bytes()).await.unwrap();
    let mut head = String::new();
    loop {
        let mut l = String::new();
        r.read_line(&mut l).await.unwrap();
        head.push_str(&l);
        if l == "\r\n" {
            break;
        }
    }
    assert!(head.starts_with("HTTP/1.1 101") && head.to_ascii_lowercase().contains("sec-websocket-protocol: jmap"), "{head}");
    // Minimal client frames (masked text) and server frames (unmasked).
    async fn send(w: &mut tokio::net::tcp::OwnedWriteHalf, text: &str) {
        let b = text.as_bytes();
        let mut f = vec![0x81u8];
        if b.len() < 126 {
            f.push(0x80 | b.len() as u8);
        } else {
            f.push(0x80 | 126);
            f.extend_from_slice(&(b.len() as u16).to_be_bytes());
        }
        let mask = [1u8, 2, 3, 4];
        f.extend_from_slice(&mask);
        f.extend(b.iter().enumerate().map(|(i, c)| c ^ mask[i % 4]));
        w.write_all(&f).await.unwrap();
    }
    async fn recv(r: &mut BufReader<tokio::net::tcp::OwnedReadHalf>) -> serde_json::Value {
        use tokio::io::AsyncReadExt;
        loop {
            let mut h = [0u8; 2];
            tokio::time::timeout(std::time::Duration::from_secs(5), r.read_exact(&mut h)).await.expect("frame").unwrap();
            let mut len = (h[1] & 0x7f) as usize;
            if len == 126 {
                let mut l = [0u8; 2];
                r.read_exact(&mut l).await.unwrap();
                len = u16::from_be_bytes(l) as usize;
            } else if len == 127 {
                let mut l = [0u8; 8];
                r.read_exact(&mut l).await.unwrap();
                len = u64::from_be_bytes(l) as usize;
            }
            let mut body = vec![0u8; len];
            r.read_exact(&mut body).await.unwrap();
            if h[0] & 0x0f == 1 {
                return serde_json::from_slice(&body).unwrap();
            }
        }
    }
    send(&mut w, &json!({"@type": "Request", "id": "r1", "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
        "methodCalls": [["Mailbox/get", {"accountId": bob.account, "properties": ["role"]}, "0"]]}).to_string()).await;
    let resp = recv(&mut r).await;
    assert_eq!((resp["@type"].clone(), resp["requestId"].clone()), (json!("Response"), json!("r1")), "{resp}");
    assert!(resp["methodResponses"][0][1]["list"].as_array().unwrap().len() >= 5);
    send(&mut w, &json!({"@type": "WebSocketPushEnable", "dataTypes": ["Email", "Mailbox"]}).to_string()).await;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    bob.import("inbox", &msg("pushed", "x"), json!({})).await;
    let push = recv(&mut r).await;
    assert_eq!(push["@type"], "StateChange", "{push}");
    assert!(push["changed"][&bob.account]["Email"].is_string(), "{push}");
}

// ------------------------------------------------------------ JMAP Calendars and Contacts

#[tokio::test]
async fn jmap_calendars_and_contacts_share_the_dav_store() {
    use serde_json::json;
    let s = server().await;
    let (bob, session) = Jmap::new(&s, "bob@example.test").await;
    for cap in ["calendars", "contacts", "principals", "principals:availability"] {
        assert!(session["capabilities"][format!("urn:ietf:params:jmap:{cap}")].is_object(), "{cap}");
    }
    let caps = &session["accounts"][&bob.account]["accountCapabilities"];
    assert_eq!(caps["urn:ietf:params:jmap:principals:availability"]["maxAvailabilityDuration"], "P370D");
    assert_eq!(caps["urn:ietf:params:jmap:blob"]["supportedTypeNames"], json!(["Email", "Thread", "Mailbox"]));
    // The default calendar, as the app lists it.
    let cals = bob.one("Calendar/get", json!({"ids": null})).await;
    let cal = cals["list"][0]["id"].as_str().unwrap().to_string();
    assert_eq!(cals["list"][0]["myRights"]["mayWriteAll"], true);
    let state = cals["state"].as_str().unwrap().to_string();

    // Create an event the way the app does (sync/jscal.rs `save_event_scheduled`).
    let ev = json!({"@type": "Event", "uid": "jmap-1", "title": "Planning", "start": "2026-12-07T10:00:00", "timeZone": "Europe/Berlin",
        "duration": "PT1H", "showWithoutTime": false, "calendarIds": {&cal: true},
        "recurrenceRules": [{"@type": "RecurrenceRule", "frequency": "weekly", "count": 4}],
        "recurrenceOverrides": {"2026-12-14T10:00:00": {"excluded": true}},
        "participants": {"organizer": {"@type": "Participant", "sendTo": {"imip": "mailto:bob@example.test"}, "roles": {"owner": true}, "scheduleAgent": "client"},
                         "p1": {"@type": "Participant", "sendTo": {"imip": "mailto:amy@example.test"}, "roles": {"attendee": true}, "participationStatus": "needs-action", "scheduleAgent": "client"}},
        "alerts": {"a1": {"@type": "Alert", "trigger": {"@type": "OffsetTrigger", "offset": "-PT10M"}, "action": "display"}}});
    let r = bob.one("CalendarEvent/set", json!({"create": {"e": ev}, "sendSchedulingMessages": false})).await;
    let id = r["created"]["e"]["id"].as_str().unwrap_or_else(|| panic!("{r}")).to_string();

    // CalDAV sees the same event, with a VTIMEZONE and SCHEDULE-AGENT=CLIENT.
    let (st, body) = dav(&s, "bob@example.test", "PROPFIND", "/dav/calendars/bob@example.test/default/", "application/xml",
        "<propfind xmlns=\"DAV:\"><prop><getetag/></prop></propfind>").await;
    assert_eq!(st, 207);
    let href = body.split("<D:href>").filter_map(|x| x.split("</D:href>").next()).find(|h| h.ends_with(".ics")).unwrap().to_string();
    let (_, ics) = dav(&s, "bob@example.test", "GET", &href, "", "").await;
    assert!(ics.contains("SUMMARY:Planning") && ics.contains("BEGIN:VTIMEZONE") && ics.contains("TZID=Europe/Berlin"), "{ics}");
    assert!(ics.contains("RRULE:FREQ=WEEKLY;COUNT=4") && ics.contains("EXDATE;TZID=Europe/Berlin:20261214T100000"), "{ics}");
    assert!(ics.contains("SCHEDULE-AGENT=CLIENT") && ics.contains("TRIGGER:-PT10M"), "{ics}");

    // Query by time range, then read it back as the app does.
    let q = bob.one("CalendarEvent/query", json!({"filter": {"inCalendar": cal, "after": "2026-12-20T00:00:00Z", "before": "2026-12-22T00:00:00Z"}})).await;
    assert_eq!(q["ids"], json!([id]), "the third occurrence is in range");
    let q = bob.one("CalendarEvent/query", json!({"filter": {"inCalendar": cal, "after": "2026-12-14T00:00:00Z", "before": "2026-12-15T00:00:00Z"}})).await;
    assert_eq!(q["ids"], json!([]), "the excluded one isn't");
    let g = bob.one("CalendarEvent/get", json!({"ids": [&id]})).await;
    let e = &g["list"][0];
    assert_eq!((e["title"].clone(), e["start"].clone(), e["timeZone"].clone()), (json!("Planning"), json!("2026-12-07T10:00:00"), json!("Europe/Berlin")));
    assert_eq!(e["participants"]["p1"]["sendTo"]["imip"], "mailto:amy@example.test");

    // A CalDAV edit shows up in CalendarEvent/changes; a JMAP patch keeps unknown properties.
    let edited = ics.replace("SUMMARY:Planning", "SUMMARY:Planning (moved)\r\nX-OTHER-APP:keep");
    let (st, _) = dav(&s, "bob@example.test", "PUT", &href, "text/calendar", &edited).await;
    assert!(st == 204 || st == 201, "{st}");
    let ch = bob.one("CalendarEvent/changes", json!({"sinceState": state})).await;
    assert!(ch["created"].as_array().unwrap().contains(&json!(id)) || ch["updated"].as_array().unwrap().contains(&json!(id)), "{ch}");
    let r = bob.one("CalendarEvent/set", json!({"update": {&id: {"title": "Planning v2", "participants/p1/participationStatus": "accepted"}}})).await;
    assert!(r["updated"].get(&id).is_some(), "{r}");
    let (_, ics) = dav(&s, "bob@example.test", "GET", &href, "", "").await;
    assert!(ics.contains("SUMMARY:Planning v2") && ics.contains("X-OTHER-APP:keep") && ics.contains("PARTSTAT=ACCEPTED"), "{ics}");

    // Free/busy for another person (sync/jscal.rs `availability`).
    let (amy, _) = Jmap::new(&s, "amy@example.test").await;
    let pq = amy.one("Principal/query", json!({"filter": {"email": "bob@example.test"}, "limit": 1})).await;
    let pid = pq["ids"][0].as_str().unwrap().to_string();
    let av = amy.one("Principal/getAvailability", json!({"id": pid, "utcStart": "2026-12-07T00:00:00Z", "utcEnd": "2026-12-08T00:00:00Z"})).await;
    assert_eq!(av["list"][0]["utcStart"], "2026-12-07T09:00:00Z", "{av}");

    // Calendars: create, rename, delete (only when empty unless asked).
    let r = bob.one("Calendar/set", json!({"create": {"c": {"name": "Work", "color": "#3a7"}}})).await;
    let work = r["created"]["c"]["id"].as_str().unwrap().to_string();
    let r = bob.one("Calendar/set", json!({"update": {&work: {"name": "Office"}}})).await;
    assert!(r["updated"].get(&work).is_some());
    let r = bob.one("CalendarEvent/set", json!({"update": {&id: {"calendarIds": {&work: true}}}})).await;
    assert!(r["updated"].get(&id).is_some(), "move between calendars: {r}");
    let r = bob.one("Calendar/set", json!({"destroy": [&work]})).await;
    assert_eq!(r["notDestroyed"][&work]["type"], "calendarHasEvent");
    let r = bob.one("Calendar/set", json!({"destroy": [&work], "onDestroyRemoveEvents": true})).await;
    assert_eq!(r["destroyed"], json!([work]));

    // Contacts: the app's card, then CardDAV sees it.
    let books = bob.one("AddressBook/get", json!({"ids": null})).await;
    let book = books["list"][0]["id"].as_str().unwrap().to_string();
    let card = json!({"@type": "Card", "version": "1.0", "uid": "card-1", "addressBookIds": {&book: true},
        "name": {"@type": "Name", "full": "Amy Lee", "components": [{"kind": "given", "value": "Amy"}, {"kind": "surname", "value": "Lee"}]},
        "emails": {"emails1": {"@type": "EmailAddress", "address": "amy@example.test"}},
        "phones": {"phones1": {"@type": "Phone", "number": "+1 555 0100"}},
        "anniversaries": {"b": {"@type": "Anniversary", "kind": "birth", "date": {"@type": "PartialDate", "month": 4, "day": 5}}}});
    let r = bob.one("ContactCard/set", json!({"create": {"k": card}})).await;
    let kid = r["created"]["k"]["id"].as_str().unwrap_or_else(|| panic!("{r}")).to_string();
    let q = bob.one("ContactCard/query", json!({"filter": {"email": "amy@"}})).await;
    assert_eq!(q["ids"], json!([kid]));
    let (st, body) = dav(&s, "bob@example.test", "PROPFIND", "/dav/addressbooks/bob@example.test/contacts/", "application/xml",
        "<propfind xmlns=\"DAV:\"><prop><getetag/></prop></propfind>").await;
    assert_eq!(st, 207);
    let vhref = body.split("<D:href>").filter_map(|x| x.split("</D:href>").next()).find(|h| h.ends_with(".vcf")).unwrap().to_string();
    let (_, vcf) = dav(&s, "bob@example.test", "GET", &vhref, "", "").await;
    assert!(vcf.contains("FN:Amy Lee") && vcf.contains("EMAIL:amy@example.test") && vcf.contains("BDAY:--0405"), "{vcf}");
    let r = bob.one("ContactCard/set", json!({"destroy": [&kid]})).await;
    assert_eq!(r["destroyed"], json!([kid]));
}
