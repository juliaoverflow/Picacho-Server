//! ManageSieve (RFC 5804) on port 4190: mail apps (Thunderbird, Roundcube,
//! K-9/FairEmail add-ons, sieve-connect) upload and activate scripts.
use crate::db::Account;
use crate::imap::proto::{literal_suffix, Conn, ReadError};
use crate::net::Stream;
use crate::state::State;
use base64::Engine;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::AsyncReadExt;

struct Session {
    state: State,
    conn: Conn,
    peer: IpAddr,
    account: Option<Account>,
    pending_tls: bool,
    quit: bool,
}

enum Tok {
    Atom(String),
    Str(String),
}

impl Tok {
    fn text(&self) -> &str {
        match self {
            Tok::Atom(s) | Tok::Str(s) => s,
        }
    }
}

fn quote(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

/// A string for a response: quoted when short and simple, else a literal.
fn string(s: &str) -> String {
    if s.len() < 1024 && !s.contains(['\r', '\n', '"', '\\']) {
        quote(s)
    } else {
        format!("{{{}}}\r\n{s}", s.len())
    }
}

fn tokenize(cmd: &[u8]) -> Result<Vec<Tok>, String> {
    let mut out = vec![];
    let mut i = 0;
    while i < cmd.len() {
        match cmd[i] {
            b' ' | b'\r' | b'\n' | b'\t' => i += 1,
            b'"' => {
                i += 1;
                let mut s = Vec::new();
                loop {
                    match cmd.get(i) {
                        None => return Err("unterminated string".into()),
                        Some(b'"') => {
                            i += 1;
                            break;
                        }
                        Some(b'\\') => {
                            if let Some(c) = cmd.get(i + 1) {
                                s.push(*c);
                            }
                            i += 2;
                        }
                        Some(c) => {
                            s.push(*c);
                            i += 1;
                        }
                    }
                }
                out.push(Tok::Str(String::from_utf8(s).map_err(|_| "string is not UTF-8")?));
            }
            b'{' => {
                let close = cmd[i..].iter().position(|c| *c == b'}').ok_or("bad literal")? + i;
                let n: usize = std::str::from_utf8(&cmd[i + 1..close]).unwrap_or("").trim_end_matches('+').parse().map_err(|_| "bad literal")?;
                let start = close + 3; // "}\r\n"
                let end = start + n;
                if end > cmd.len() {
                    return Err("short literal".into());
                }
                out.push(Tok::Str(String::from_utf8(cmd[start..end].to_vec()).map_err(|_| "script is not UTF-8")?));
                i = end;
            }
            _ => {
                let start = i;
                while i < cmd.len() && !matches!(cmd[i], b' ' | b'\r' | b'\n') {
                    i += 1;
                }
                out.push(Tok::Atom(String::from_utf8_lossy(&cmd[start..i]).to_string()));
            }
        }
    }
    Ok(out)
}

pub async fn handle(state: State, stream: Stream, peer: SocketAddr) {
    let mut s = Session { state, conn: Conn::new(stream), peer: peer.ip(), account: None, pending_tls: false, quit: false };
    if s.state.limiter.is_banned(s.peer) && !crate::util::ip_in_list(s.peer, &s.state.settings().security.allowlist) {
        s.conn.push("BYE \"Too many failed logins. Try again later.\"\r\n");
        let _ = s.conn.flush().await;
        return;
    }
    s.capabilities();
    s.conn.push("OK \"Picacho Server ManageSieve ready.\"\r\n");
    if let Err(e) = s.run().await {
        tracing::debug!("managesieve {}: {e:#}", s.peer);
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

    fn capabilities(&mut self) {
        let host = self.state.hostname();
        self.conn.push("\"IMPLEMENTATION\" \"Picacho Server\"\r\n");
        if self.account.is_none() && self.auth_ok() {
            self.conn.push("\"SASL\" \"PLAIN OAUTHBEARER XOAUTH2\"\r\n");
        } else if self.account.is_none() {
            self.conn.push("\"SASL\" \"\"\r\n");
        }
        self.conn.push(&format!("\"SIEVE\" {}\r\n", quote(&super::parse::EXTENSIONS.iter().filter(|e| !e.starts_with("comparator-i;octet") && !e.starts_with("comparator-i;ascii-casemap")).copied().collect::<Vec<_>>().join(" "))));
        if !self.tls() {
            self.conn.push("\"STARTTLS\"\r\n");
        }
        self.conn.push(&format!("\"MAXREDIRECTS\" \"8\"\r\n\"NOTIFY\" \"\"\r\n\"VERSION\" \"1.0\"\r\n\"OWNER\" {}\r\n", quote(self.account.as_ref().map(|a| a.email.as_str()).unwrap_or(&host))));
    }

    async fn read_cmd(&mut self) -> Result<Vec<u8>, ReadError> {
        let mut cmd = Vec::new();
        loop {
            let line = self.conn.read_line(8192).await?;
            cmd.extend_from_slice(&line);
            match literal_suffix(&line) {
                Some((n, _)) => {
                    if n > super::MAX_SCRIPT_BYTES + 1024 {
                        return Err(ReadError::LiteralTooBig(String::new()));
                    }
                    cmd.extend_from_slice(b"\r\n");
                    let start = cmd.len();
                    cmd.resize(start + n, 0);
                    self.conn.reader.read_exact(&mut cmd[start..]).await?;
                }
                None => return Ok(cmd),
            }
        }
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
                self.capabilities();
                self.conn.push("OK\r\n");
                continue;
            }
            let timeout = if self.account.is_some() { 1800 } else { 120 };
            let shutdown = self.state.shutdown.clone();
            let read = tokio::select! {
                r = tokio::time::timeout(Duration::from_secs(timeout), self.read_cmd()) => r,
                _ = shutdown.cancelled() => {
                    self.conn.push("BYE (TRYLATER) \"Server shutting down.\"\r\n");
                    return Ok(());
                }
            };
            let cmd = match read {
                Err(_) => {
                    self.conn.push("BYE \"Disconnected for inactivity.\"\r\n");
                    return Ok(());
                }
                Ok(Err(ReadError::LiteralTooBig(_))) => {
                    self.conn.push("BYE (QUOTA/MAXSIZE) \"Script too large.\"\r\n");
                    return Ok(());
                }
                Ok(Err(ReadError::LineTooLong)) => {
                    self.conn.push("NO \"Line too long.\"\r\n");
                    continue;
                }
                Ok(Err(_)) => return Ok(()),
                Ok(Ok(c)) => c,
            };
            let toks = match tokenize(&cmd) {
                Ok(t) if !t.is_empty() => t,
                Ok(_) => continue,
                Err(e) => {
                    self.conn.push(&format!("NO {}\r\n", quote(&e)));
                    continue;
                }
            };
            let name = toks[0].text().to_ascii_uppercase();
            let args: Vec<String> = toks[1..].iter().map(|t| t.text().to_string()).collect();
            let r = self.dispatch(&name, &args).await;
            match r {
                Ok(()) => {}
                Err(e) => {
                    tracing::warn!("managesieve {name}: {e:#}");
                    self.conn.push("NO \"Internal error.\"\r\n");
                }
            }
        }
    }

    fn ok(&mut self, text: &str) {
        self.conn.push(&format!("OK {}\r\n", quote(text)));
    }

    fn no(&mut self, text: &str) {
        self.conn.push(&format!("NO {}\r\n", quote(text)));
    }

    async fn dispatch(&mut self, name: &str, args: &[String]) -> anyhow::Result<()> {
        match name {
            "CAPABILITY" => {
                self.capabilities();
                self.ok("Capability completed.");
            }
            "NOOP" => {
                match args.first() {
                    Some(tag) => self.conn.push(&format!("OK (TAG {}) \"Done.\"\r\n", quote(tag))),
                    None => self.ok("Done."),
                }
            }
            "LOGOUT" => {
                self.ok("Bye.");
                self.quit = true;
            }
            "STARTTLS" => {
                if self.tls() {
                    self.no("TLS is already active.");
                } else if self.conn.buffered() > 0 {
                    self.conn.push("BYE \"Pipelining not allowed before STARTTLS.\"\r\n");
                    self.quit = true;
                } else {
                    self.ok("Begin TLS negotiation now.");
                    self.conn.flush().await?;
                    self.pending_tls = true;
                }
            }
            "AUTHENTICATE" => self.authenticate(args).await?,
            "UNAUTHENTICATE" => {
                self.account = None;
                self.ok("Signed out.");
            }
            _ if self.account.is_none() => self.no("Authenticate first."),
            "HAVESPACE" => {
                let size: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
                if size > super::MAX_SCRIPT_BYTES {
                    self.conn.push(&format!("NO (QUOTA/MAXSIZE) {}\r\n", quote(&format!("Scripts may be at most {} bytes.", super::MAX_SCRIPT_BYTES))));
                } else {
                    self.ok("Putscript would succeed.");
                }
            }
            "LISTSCRIPTS" => {
                let acc = self.account.as_ref().unwrap().id;
                for s in self.state.db.sieve_scripts(acc).await? {
                    self.conn.push(&format!("{}{}\r\n", string(&s.name), if s.active { " ACTIVE" } else { "" }));
                }
                self.ok("Listscripts completed.");
            }
            "GETSCRIPT" => {
                let acc = self.account.as_ref().unwrap().id;
                match self.state.db.sieve_script(acc, args.first().map(|s| s.as_str()).unwrap_or("")).await? {
                    Some(s) => {
                        self.conn.push(&format!("{{{}}}\r\n{}\r\n", s.content.len(), s.content));
                        self.ok("Getscript completed.");
                    }
                    None => self.conn.push("NO (NONEXISTENT) \"There is no script by that name.\"\r\n"),
                }
            }
            "PUTSCRIPT" | "CHECKSCRIPT" => {
                let (script_name, content) = if name == "PUTSCRIPT" { (args.first().cloned(), args.get(1).cloned()) } else { (None, args.first().cloned()) };
                let Some(content) = content else {
                    self.no("Missing script.");
                    return Ok(());
                };
                if let Err(e) = super::check(&content) {
                    self.no(&e);
                    return Ok(());
                }
                if let Some(n) = script_name {
                    if !super::valid_name(&n) {
                        self.no("Invalid script name.");
                        return Ok(());
                    }
                    let acc = self.account.as_ref().unwrap().id;
                    if self.state.db.sieve_script(acc, &n).await?.is_none() && self.state.db.sieve_count(acc).await? >= super::MAX_SCRIPTS {
                        self.conn.push("NO (QUOTA/MAXSCRIPTS) \"Too many scripts.\"\r\n");
                        return Ok(());
                    }
                    self.state.db.sieve_put(acc, &n, &content).await?;
                    self.ok("Putscript completed.");
                } else {
                    self.ok("Script is valid.");
                }
            }
            "SETACTIVE" => {
                let acc = self.account.as_ref().unwrap().id;
                let n = args.first().cloned().unwrap_or_default();
                let ok = self.state.db.sieve_activate(acc, if n.is_empty() { None } else { Some(&n) }).await?;
                if ok {
                    self.ok("Setactive completed.");
                } else {
                    self.conn.push("NO (NONEXISTENT) \"There is no script by that name.\"\r\n");
                }
            }
            "DELETESCRIPT" => {
                let acc = self.account.as_ref().unwrap().id;
                let n = args.first().cloned().unwrap_or_default();
                match self.state.db.sieve_script(acc, &n).await? {
                    Some(s) if s.active => self.conn.push("NO (ACTIVE) \"You may not delete the active script.\"\r\n"),
                    Some(_) => {
                        self.state.db.sieve_delete(acc, &n).await?;
                        self.ok("Deletescript completed.");
                    }
                    None => self.conn.push("NO (NONEXISTENT) \"There is no script by that name.\"\r\n"),
                }
            }
            "RENAMESCRIPT" => {
                let acc = self.account.as_ref().unwrap().id;
                let (from, to) = (args.first().cloned().unwrap_or_default(), args.get(1).cloned().unwrap_or_default());
                if !super::valid_name(&to) {
                    self.no("Invalid script name.");
                } else if self.state.db.sieve_script(acc, &to).await?.is_some() {
                    self.conn.push("NO (ALREADYEXISTS) \"A script with that name already exists.\"\r\n");
                } else if self.state.db.sieve_rename(acc, &from, &to).await? {
                    self.ok("Renamescript completed.");
                } else {
                    self.conn.push("NO (NONEXISTENT) \"There is no script by that name.\"\r\n");
                }
            }
            _ => self.no("Unknown command."),
        }
        Ok(())
    }

    async fn authenticate(&mut self, args: &[String]) -> anyhow::Result<()> {
        if self.account.is_some() {
            self.no("Already authenticated.");
            return Ok(());
        }
        if !self.auth_ok() {
            self.conn.push("NO (ENCRYPT-NEEDED) \"Use STARTTLS first.\"\r\n");
            return Ok(());
        }
        let mech = args.first().map(|m| m.to_ascii_uppercase()).unwrap_or_default();
        let initial = match args.get(1) {
            Some(i) => i.clone(),
            None => {
                self.conn.push("\"\"\r\n");
                self.conn.flush().await?;
                let line = match self.read_cmd().await {
                    Ok(l) => l,
                    Err(_) => return Ok(()),
                };
                let toks = tokenize(&line).unwrap_or_default();
                match toks.first() {
                    Some(t) if t.text() == "*" => {
                        self.no("Authentication cancelled.");
                        return Ok(());
                    }
                    Some(t) => t.text().to_string(),
                    None => String::new(),
                }
            }
        };
        let Ok(raw) = base64::engine::general_purpose::STANDARD.decode(initial.trim()) else {
            self.no("Invalid base64.");
            return Ok(());
        };
        let creds = match mech.as_str() {
            "PLAIN" => {
                let parts: Vec<&[u8]> = raw.split(|c| *c == 0).collect();
                if parts.len() != 3 {
                    None
                } else {
                    let authz = String::from_utf8_lossy(parts[0]).to_string();
                    let user = String::from_utf8_lossy(parts[1]).to_string();
                    if !authz.is_empty() && !authz.eq_ignore_ascii_case(&user) {
                        self.no("Authorization identity not permitted.");
                        return Ok(());
                    }
                    Some((user, String::from_utf8_lossy(parts[2]).to_string()))
                }
            }
            "XOAUTH2" | "OAUTHBEARER" => crate::auth::parse_oauth_sasl(&mech, &raw),
            _ => {
                self.no("Unsupported mechanism.");
                return Ok(());
            }
        };
        let Some((user, pass)) = creds else {
            self.no("Invalid authentication data.");
            return Ok(());
        };
        match crate::auth::login_service(&self.state, &user, &pass, self.peer, crate::auth::Service::Sieve).await {
            Ok((a, access)) if access == crate::auth::Access::Write => {
                self.state.event("info", "auth", &format!("managesieve login {} from {}", a.email, self.peer));
                self.account = Some(a);
                self.ok("Logged in.");
            }
            Ok(_) => self.no("This sign-in can't change filters."),
            Err(crate::auth::AuthError::Banned) => {
                self.conn.push("BYE \"Too many failed attempts.\"\r\n");
                self.quit = true;
            }
            Err(crate::auth::AuthError::PasswordDisabled) => self.no("Account passwords are turned off; use an app password or OAuth."),
            Err(_) => {
                crate::metrics::AUTH_FAILURES.inc();
                tokio::time::sleep(Duration::from_millis(500)).await;
                self.no("Authentication failed.");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tokens() {
        let t = tokenize(b"PUTSCRIPT \"my \\\"x\\\"\" {13+}\r\nkeep; stop;\r\n").unwrap();
        assert_eq!(t[1].text(), "my \"x\"");
        assert_eq!(t[2].text(), "keep; stop;\r\n");
    }
}
