//! External scanners: rspamd (HTTP `/checkv2`) and ClamAV (clamd INSTREAM).
use super::Context;
use crate::settings::{ClamavSettings, RspamdSettings};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub struct RspamdResult {
    pub score: f64,
    pub action: String,
}

pub async fn rspamd(cfg: &RspamdSettings, ctx: &Context, raw: &[u8]) -> Result<RspamdResult, String> {
    let client = reqwest::Client::builder().timeout(Duration::from_secs(cfg.timeout_secs.max(1))).build().map_err(|e| e.to_string())?;
    let mut req = client.post(format!("{}/checkv2", cfg.url.trim_end_matches('/'))).body(raw.to_vec());
    if let Some(ip) = ctx.ip {
        req = req.header("IP", ip.to_string());
    }
    if !ctx.helo.is_empty() {
        req = req.header("Helo", &ctx.helo);
    }
    if let Some(h) = &ctx.rdns {
        req = req.header("Hostname", h);
    }
    if !ctx.sender.is_empty() {
        req = req.header("From", &ctx.sender);
    }
    for r in &ctx.rcpts {
        req = req.header("Rcpt", r);
    }
    if let Some(p) = cfg.password.as_deref().filter(|p| !p.is_empty()) {
        req = req.header("Password", p);
    }
    let r = req.send().await.map_err(|e| e.to_string())?;
    if !r.status().is_success() {
        return Err(format!("HTTP {}", r.status()));
    }
    let v: serde_json::Value = r.json().await.map_err(|e| e.to_string())?;
    Ok(RspamdResult { score: v["score"].as_f64().unwrap_or(0.0), action: v["action"].as_str().unwrap_or("no action").to_string() })
}

/// Scan with clamd. Ok(Some(name)) when infected.
pub async fn clamav(cfg: &ClamavSettings, raw: &[u8]) -> Result<Option<String>, String> {
    let t = Duration::from_secs(cfg.timeout_secs.max(1));
    let reply = tokio::time::timeout(t, async {
        if let Some(path) = cfg.address.strip_prefix("unix:") {
            #[cfg(unix)]
            {
                let s = tokio::net::UnixStream::connect(path).await.map_err(|e| e.to_string())?;
                return instream(s, raw).await;
            }
            #[cfg(not(unix))]
            {
                let _ = path;
                return Err("unix sockets are not supported here".to_string());
            }
        }
        let s = tokio::net::TcpStream::connect(&cfg.address).await.map_err(|e| e.to_string())?;
        instream(s, raw).await
    })
    .await
    .map_err(|_| "timed out".to_string())??;
    let reply = reply.trim_end_matches('\0').trim();
    if let Some(rest) = reply.strip_suffix(" FOUND") {
        return Ok(Some(rest.rsplit_once(": ").map(|(_, n)| n).unwrap_or(rest).to_string()));
    }
    if reply.ends_with("OK") {
        return Ok(None);
    }
    Err(format!("unexpected clamd reply: {reply}"))
}

async fn instream<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(mut s: S, raw: &[u8]) -> Result<String, String> {
    let io = |e: std::io::Error| e.to_string();
    s.write_all(b"zINSTREAM\0").await.map_err(io)?;
    for chunk in raw.chunks(64 * 1024) {
        s.write_all(&(chunk.len() as u32).to_be_bytes()).await.map_err(io)?;
        s.write_all(chunk).await.map_err(io)?;
    }
    s.write_all(&0u32.to_be_bytes()).await.map_err(io)?;
    s.flush().await.map_err(io)?;
    let mut out = Vec::new();
    s.read_to_end(&mut out).await.map_err(io)?;
    Ok(String::from_utf8_lossy(&out).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn clamd_protocol() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut c, _) = l.accept().await.unwrap();
            let mut buf = vec![0u8; 10];
            c.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"zINSTREAM\0");
            let mut data = vec![];
            loop {
                let mut len = [0u8; 4];
                c.read_exact(&mut len).await.unwrap();
                let n = u32::from_be_bytes(len) as usize;
                if n == 0 {
                    break;
                }
                let mut chunk = vec![0u8; n];
                c.read_exact(&mut chunk).await.unwrap();
                data.extend(chunk);
            }
            let reply = if data.windows(5).any(|w| w == b"EICAR") { "stream: Eicar-Test-Signature FOUND\0" } else { "stream: OK\0" };
            c.write_all(reply.as_bytes()).await.unwrap();
        });
        let cfg = ClamavSettings { address: addr.to_string(), ..Default::default() };
        assert_eq!(clamav(&cfg, b"hello EICAR test").await.unwrap().as_deref(), Some("Eicar-Test-Signature"));
    }
}
