//! POP3 (RFC 1939) with CAPA (RFC 2449), STLS (RFC 2595), SASL AUTH
//! (RFC 5034: PLAIN, XOAUTH2, OAUTHBEARER), UIDL and TOP.
//!
//! A session sees the INBOX as it was when it signed in. Messages marked
//! with DELE are removed only when the session ends with QUIT (the UPDATE
//! state); a dropped connection removes nothing. UIDL identities are
//! `<uidvalidity>.<uid>`, so they never repeat for different messages.
//! Signing in works as for IMAP (passwords, app passwords, directory
//! passwords and access tokens); read-only access can't delete.
use crate::auth::{Access, Service};
use crate::db::Account;
use crate::imap::proto::{Conn, ReadError};
use crate::net::Stream;
use crate::state::State;
use base64::Engine;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

struct Msg {
    uid: i64,
    size: i64,
    blob: String,
    deleted: bool,
}

struct Session {
    state: State,
    conn: Conn,
    peer: IpAddr,
    user: Option<String>,
    account: Option<Account>,
    access: Access,
    mailbox: i64,
    uidvalidity: i64,
    msgs: Vec<Msg>,
    pending_tls: bool,
    quit: bool,
    failures: u32,
}

pub async fn handle(state: State, stream: Stream, peer: SocketAddr) {
    let mut s = Session {
        state,
        conn: Conn::new(stream),
        peer: peer.ip(),
        user: None,
        account: None,
        access: Access::None,
        mailbox: 0,
        uidvalidity: 0,
        msgs: vec![],
        pending_tls: false,
        quit: false,
        failures: 0,
    };
    if s.state.limiter.is_banned(s.peer) && !crate::util::ip_in_list(s.peer, &s.state.settings().security.allowlist) {
        s.conn.push("-ERR [SYS/TEMP] Too many failed logins. Try again later.\r\n");
        let _ = s.conn.flush().await;
        return;
    }
    s.conn.push("+OK Picacho Server POP3 ready.\r\n");
    if let Err(e) = s.run().await {
        tracing::debug!("pop3 {}: {e:#}", s.peer);
    }
    let _ = s.conn.flush().await;
}

impl Session {
    fn tls(&mut self) -> bool {
        self.conn.stream().is_tls()
    }

    fn auth_ok(&mut self) -> bool {
        let sec = self.state.settings().security.clone();
        self.tls() || !sec.require_tls_for_auth || (sec.allow_plaintext_localhost && crate::util::is_loopback(self.peer))
    }

    fn ok(&mut self, t: &str) {
        self.conn.push(&format!("+OK {t}\r\n"));
    }

    fn err(&mut self, t: &str) {
        self.conn.push(&format!("-ERR {t}\r\n"));
    }

    async fn run(&mut self) -> anyhow::Result<()> {
        loop {
            self.conn.flush().await?;
            if self.quit {
                return Ok(());
            }
            if self.pending_tls {
                self.pending_tls = false;
                let old = std::mem::replace(&mut self.conn, Conn::new(Stream::Duplex(tokio::io::duplex(1).0)));
                let tls = tokio::time::timeout(Duration::from_secs(30), old.reader.into_inner().upgrade(&self.state.tls.acceptor)).await??;
                self.conn = Conn::new(tls);
                continue;
            }
            // RFC 1939: at least ten minutes of inactivity before closing.
            let timeout = if self.account.is_some() { 600 } else { self.state.config.limits.auth_timeout_secs.max(30) };
            let shutdown = self.state.shutdown.clone();
            let line = tokio::select! {
                r = tokio::time::timeout(Duration::from_secs(timeout), self.conn.read_line(512)) => r,
                _ = shutdown.cancelled() => {
                    self.err("[SYS/TEMP] Server shutting down.");
                    return Ok(());
                }
            };
            let line = match line {
                Err(_) => {
                    self.err("Disconnected for inactivity.");
                    return Ok(());
                }
                Ok(Err(ReadError::LineTooLong)) => {
                    self.err("Line too long.");
                    continue;
                }
                Ok(Err(_)) => return Ok(()),
                Ok(Ok(l)) => String::from_utf8_lossy(&l).trim_end_matches(['\r', '\n']).to_string(),
            };
            let (cmd, arg) = line.split_once(' ').unwrap_or((line.as_str(), ""));
            let cmd = cmd.to_ascii_uppercase();
            if let Err(e) = self.dispatch(&cmd, arg.trim()).await {
                tracing::warn!("pop3 {cmd}: {e:#}");
                self.err("[SYS/TEMP] Internal error.");
            }
        }
    }

    fn capa(&mut self) {
        let mut c = String::from("+OK Capability list follows\r\nTOP\r\nUIDL\r\nRESP-CODES\r\nAUTH-RESP-CODE\r\nPIPELINING\r\nEXPIRE NEVER\r\nUTF8\r\nLANG\r\n");
        if self.account.is_none() {
            if self.auth_ok() {
                c.push_str(if crate::gssapi::available(&self.state) { "USER\r\nSASL PLAIN XOAUTH2 OAUTHBEARER GSSAPI\r\n" } else { "USER\r\nSASL PLAIN XOAUTH2 OAUTHBEARER\r\n" });
            }
            if !self.tls() {
                c.push_str("STLS\r\n");
            }
        }
        c.push_str("IMPLEMENTATION Picacho-Server\r\n.\r\n");
        self.conn.push(&c);
    }

    /// A message number argument: (index, message) when it exists and isn't deleted.
    fn number(&self, arg: &str) -> Result<usize, &'static str> {
        let n: usize = arg.split_whitespace().next().and_then(|x| x.parse().ok()).ok_or("Invalid message number.")?;
        match self.msgs.get(n.wrapping_sub(1)) {
            None => Err("No such message."),
            Some(m) if m.deleted => Err("Message is deleted."),
            Some(_) => Ok(n - 1),
        }
    }

    async fn dispatch(&mut self, cmd: &str, arg: &str) -> anyhow::Result<()> {
        // Allowed in either state.
        match cmd {
            "CAPA" => {
                self.capa();
                return Ok(());
            }
            // RFC 6856: UTF-8 user names and passwords; mail is sent as stored.
            "UTF8" => {
                self.ok("UTF8 enabled");
                return Ok(());
            }
            // RFC 6856 4: only English replies; LANG lists or accepts "en".
            "LANG" => {
                match arg {
                    "" => self.conn.push("+OK Language listing follows\r\nen English\r\n.\r\n"),
                    "*" | "en" | "en-US" | "en-GB" => self.ok("en Language set"),
                    _ => self.err("Unsupported language"),
                }
                return Ok(());
            }
            "NOOP" if self.account.is_some() => {
                self.ok("");
                return Ok(());
            }
            "QUIT" => {
                self.quit = true;
                if self.account.is_none() {
                    self.ok("Bye.");
                    return Ok(());
                }
                // UPDATE state: remove what was marked, then confirm.
                let uids: Vec<i64> = self.msgs.iter().filter(|m| m.deleted).map(|m| m.uid).collect();
                if !uids.is_empty() {
                    let (_, blobs, freed) = self.state.db.expunge(self.mailbox, &uids).await?;
                    if let Some(a) = &self.account {
                        self.state.db.add_usage(a.id, -freed).await?;
                    }
                    self.state.hub.notify(self.mailbox);
                    self.state.blobs.delete_all(&blobs).await;
                }
                self.ok(&format!("Bye ({} removed).", uids.len()));
                return Ok(());
            }
            _ => {}
        }
        if self.account.is_none() {
            return self.authorization(cmd, arg).await;
        }
        match cmd {
            "STAT" => {
                let live: Vec<&Msg> = self.msgs.iter().filter(|m| !m.deleted).collect();
                let total: i64 = live.iter().map(|m| m.size).sum();
                self.ok(&format!("{} {total}", live.len()));
            }
            "LIST" | "UIDL" => {
                let row = |i: usize, m: &Msg, v: i64| if cmd == "LIST" { format!("{} {}", i + 1, m.size) } else { format!("{} {v}.{}", i + 1, m.uid) };
                if arg.is_empty() {
                    let mut out = String::from("+OK\r\n");
                    for (i, m) in self.msgs.iter().enumerate().filter(|(_, m)| !m.deleted) {
                        out.push_str(&row(i, m, self.uidvalidity));
                        out.push_str("\r\n");
                    }
                    out.push_str(".\r\n");
                    self.conn.push(&out);
                } else {
                    match self.number(arg) {
                        Ok(i) => {
                            let r = row(i, &self.msgs[i], self.uidvalidity);
                            self.ok(&r);
                        }
                        Err(e) => self.err(e),
                    }
                }
            }
            "RETR" | "TOP" => {
                let i = match self.number(arg) {
                    Ok(i) => i,
                    Err(e) => {
                        self.err(e);
                        return Ok(());
                    }
                };
                let lines: Option<usize> = if cmd == "TOP" {
                    match arg.split_whitespace().nth(1).and_then(|n| n.parse().ok()) {
                        Some(n) => Some(n),
                        None => {
                            self.err("TOP needs a message number and a line count.");
                            return Ok(());
                        }
                    }
                } else {
                    None
                };
                let raw = match self.state.blobs.get(&self.msgs[i].blob).await {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::error!("pop3: message {} unreadable: {e:#}", self.msgs[i].blob);
                        self.err("[SYS/TEMP] Message unreadable.");
                        return Ok(());
                    }
                };
                let data: &[u8] = match lines {
                    None => &raw,
                    Some(n) => {
                        let root = crate::mime::parse(&raw);
                        let body = root.body_bytes(&raw);
                        let head_len = raw.len() - body.len();
                        let mut end = head_len;
                        for _ in 0..n {
                            match raw[end..].iter().position(|b| *b == b'\n') {
                                Some(p) => end += p + 1,
                                None => {
                                    end = raw.len();
                                    break;
                                }
                            }
                        }
                        &raw[..end]
                    }
                };
                self.conn.push(&format!("+OK {} octets\r\n", self.msgs[i].size));
                self.conn.push_bytes(&dot_stuff(data));
                self.conn.push(".\r\n");
            }
            "DELE" => {
                if self.access != Access::Write {
                    self.err("[SYS/PERM] This sign-in can't delete mail.");
                    return Ok(());
                }
                match self.number(arg) {
                    Ok(i) => {
                        self.msgs[i].deleted = true;
                        self.ok("Marked for deletion.");
                    }
                    Err(e) => self.err(e),
                }
            }
            "RSET" => {
                for m in &mut self.msgs {
                    m.deleted = false;
                }
                let n = self.msgs.len();
                self.ok(&format!("{n} messages"));
            }
            "USER" | "PASS" | "AUTH" | "STLS" | "APOP" => self.err("Already signed in."),
            _ => self.err("Unknown command."),
        }
        Ok(())
    }

    async fn authorization(&mut self, cmd: &str, arg: &str) -> anyhow::Result<()> {
        match cmd {
            "STLS" => {
                if self.tls() {
                    self.err("TLS is already active.");
                } else if self.conn.buffered() > 0 {
                    self.err("Commands may not be pipelined before STLS.");
                    self.quit = true;
                } else {
                    self.ok("Begin TLS negotiation.");
                    self.pending_tls = true;
                }
            }
            "USER" => {
                if !self.auth_ok() {
                    self.err("[AUTH] Use STLS first.");
                } else if arg.is_empty() || arg.len() > 256 {
                    self.err("USER needs a name.");
                } else {
                    self.user = Some(arg.to_string());
                    self.ok("Send your password.");
                }
            }
            "PASS" => {
                let Some(user) = self.user.take() else {
                    self.err("USER first.");
                    return Ok(());
                };
                self.login(&user, arg).await?;
            }
            "AUTH" => {
                if arg.is_empty() {
                    // Some clients list the mechanisms this way.
                    self.conn.push("+OK\r\nPLAIN\r\nXOAUTH2\r\nOAUTHBEARER\r\n.\r\n");
                    return Ok(());
                }
                if !self.auth_ok() {
                    self.err("[AUTH] Use STLS first.");
                    return Ok(());
                }
                let mut it = arg.split_whitespace();
                let mech = it.next().unwrap_or("").to_ascii_uppercase();
                if mech == "GSSAPI" && crate::gssapi::available(&self.state) {
                    return self.auth_gssapi(it.next().map(String::from)).await;
                }
                if !matches!(mech.as_str(), "PLAIN" | "XOAUTH2" | "OAUTHBEARER") {
                    self.err("Unsupported mechanism.");
                    return Ok(());
                }
                let initial = match it.next() {
                    Some("=") => String::new(),
                    Some(d) => d.to_string(),
                    None => {
                        self.conn.push("+ \r\n");
                        self.conn.flush().await?;
                        let l = match self.conn.read_line(16 * 1024).await {
                            Ok(l) => String::from_utf8_lossy(&l).trim().to_string(),
                            Err(_) => return Ok(()),
                        };
                        if l == "*" {
                            self.err("Authentication canceled.");
                            return Ok(());
                        }
                        l
                    }
                };
                let Ok(raw) = base64::engine::general_purpose::STANDARD.decode(initial.trim()) else {
                    self.err("Invalid base64.");
                    return Ok(());
                };
                let creds = if mech == "PLAIN" {
                    let parts: Vec<&[u8]> = raw.split(|c| *c == 0).collect();
                    if parts.len() != 3 {
                        None
                    } else {
                        let (authz, user) = (String::from_utf8_lossy(parts[0]).to_string(), String::from_utf8_lossy(parts[1]).to_string());
                        if !authz.is_empty() && !authz.eq_ignore_ascii_case(&user) {
                            self.err("[AUTH] Authorization identity not permitted.");
                            return Ok(());
                        }
                        Some((user, String::from_utf8_lossy(parts[2]).to_string()))
                    }
                } else {
                    crate::auth::parse_oauth_sasl(&mech, &raw)
                };
                match creds {
                    Some((u, p)) => self.login(&u, &p).await?,
                    None => self.err("Invalid authentication data."),
                }
            }
            "APOP" => self.err("APOP isn't supported; use USER/PASS or AUTH over TLS."),
            _ => self.err("Sign in first."),
        }
        Ok(())
    }

    /// One SASL continuation: `+ <data>`, the client's line back (None: cancelled).
    async fn sasl_step(&mut self, data: &str) -> anyhow::Result<Option<String>> {
        self.conn.push(&format!("+ {data}\r\n"));
        self.conn.flush().await?;
        let l = match self.conn.read_line(16 * 1024).await {
            Ok(l) => String::from_utf8_lossy(&l).trim().to_string(),
            Err(_) => return Ok(None),
        };
        Ok((l != "*").then_some(l))
    }

    /// SASL GSSAPI (RFC 4752): Kerberos sign-in.
    async fn auth_gssapi(&mut self, initial: Option<String>) -> anyhow::Result<()> {
        let b64 = base64::engine::general_purpose::STANDARD;
        let Ok(mut ex) = crate::gssapi::Exchange::new() else {
            self.err("[SYS/TEMP] Kerberos isn't available.");
            return Ok(());
        };
        let mut input = match initial {
            Some(d) if d == "=" => String::new(),
            Some(d) => d,
            None => match self.sasl_step("").await? {
                Some(d) => d,
                None => {
                    self.err("Authentication cancelled.");
                    return Ok(());
                }
            },
        };
        loop {
            let Ok(raw) = b64.decode(input.trim()) else {
                self.err("Invalid base64.");
                return Ok(());
            };
            match ex.step(&raw) {
                Ok(crate::gssapi::Step::Continue(out)) => match self.sasl_step(&b64.encode(out)).await? {
                    Some(d) => input = d,
                    None => {
                        self.err("Authentication cancelled.");
                        return Ok(());
                    }
                },
                Ok(crate::gssapi::Step::Done { principal, authzid }) => {
                    match crate::gssapi::account_for(&self.state, &principal, &authzid).await {
                        Some(a) => self.open_mailbox(a, Access::Write).await?,
                        None => self.err("[AUTH] This Kerberos principal has no mailbox here."),
                    }
                    return Ok(());
                }
                Err(e) => {
                    tracing::debug!("gssapi: {e:#}");
                    self.err("[AUTH] Kerberos authentication failed.");
                    return Ok(());
                }
            }
        }
    }

    async fn login(&mut self, user: &str, pass: &str) -> anyhow::Result<()> {
        if !self.auth_ok() {
            self.err("[AUTH] Use STLS first.");
            return Ok(());
        }
        match crate::auth::login_service(&self.state, user, pass, self.peer, Service::Imap).await {
            Ok((a, access)) => self.open_mailbox(a, access).await?,
            Err(crate::auth::AuthError::Banned) => {
                self.err("[SYS/TEMP] Too many failed logins.");
                self.quit = true;
            }
            Err(crate::auth::AuthError::PasswordDisabled) => self.err("[AUTH] Account passwords are turned off; use an app password or OAuth."),
            Err(crate::auth::AuthError::Internal) => self.err("[SYS/TEMP] Sign-in is temporarily unavailable."),
            Err(_) => {
                self.failures += 1;
                tokio::time::sleep(Duration::from_millis(400)).await;
                self.err("[AUTH] Authentication failed.");
                if self.failures >= 3 {
                    self.quit = true;
                }
            }
        }
        Ok(())
    }

    /// Signed in: take the inbox as it is now.
    async fn open_mailbox(&mut self, a: Account, access: Access) -> anyhow::Result<()> {
        let Some(mb) = self.state.db.mailbox(a.id, "INBOX").await? else {
            self.err("[SYS/PERM] This account has no inbox.");
            return Ok(());
        };
        let rows = self.state.db.messages_by_uids(mb.id, 1, i64::MAX).await?;
        self.msgs = rows
            .into_iter()
            .filter(|r| !crate::imap::seq::has_flag(&r.flags, "\\Deleted"))
            .map(|r| Msg { uid: r.uid, size: r.size, blob: r.blob, deleted: false })
            .collect();
        self.mailbox = mb.id;
        self.uidvalidity = mb.uidvalidity;
        self.access = access;
        let _ = self.state.db.touch_login(a.id).await;
        self.state.event("info", "auth", &format!("pop3 login {} from {}", a.email, self.peer));
        self.account = Some(a);
        let n = self.msgs.len();
        self.ok(&format!("{n} messages"));
        Ok(())
    }

}

/// Byte-stuff a message for a multi-line response (RFC 1939 3), ending
/// with a line break so the terminating "." stands on its own line.
fn dot_stuff(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 64);
    let mut at_line_start = true;
    for &b in data {
        if at_line_start && b == b'.' {
            out.push(b'.');
        }
        out.push(b);
        at_line_start = b == b'\n';
    }
    if !out.ends_with(b"\r\n") {
        if out.ends_with(b"\n") {
            out.pop();
        }
        out.extend_from_slice(b"\r\n");
    }
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn stuffing() {
        assert_eq!(super::dot_stuff(b"a\r\n.b\r\n..c"), b"a\r\n..b\r\n...c\r\n");
        assert_eq!(super::dot_stuff(b".\r\n"), b"..\r\n");
    }
}
