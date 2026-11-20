//! Connection plumbing shared by IMAP and SMTP: a boxed stream that can be
//! upgraded with STARTTLS, and per-IP connection accounting.
use dashmap::DashMap;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;

pub enum Stream {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
    /// In-memory stream for tests.
    Duplex(tokio::io::DuplexStream),
    /// IMAP COMPRESS=DEFLATE (RFC 4978) over another stream.
    Deflate(Box<Deflate>),
}

impl Stream {
    pub fn is_tls(&self) -> bool {
        match self {
            Stream::Tls(_) => true,
            Stream::Deflate(d) => d.inner.is_tls(),
            _ => false,
        }
    }

    /// Wrap in raw DEFLATE compression (both directions).
    pub fn compress(self) -> Stream {
        Stream::Deflate(Box::new(Deflate {
            inner: self,
            dec: flate2::Decompress::new(false),
            enc: flate2::Compress::new(flate2::Compression::new(6), false),
            rbuf: Vec::new(),
            rpos: 0,
            wbuf: Vec::new(),
            eof: false,
        }))
    }

    pub async fn upgrade(self, acceptor: &tokio_rustls::TlsAcceptor) -> std::io::Result<Stream> {
        match self {
            Stream::Deflate(_) => Err(std::io::Error::other("STARTTLS after COMPRESS")),
            Stream::Plain(tcp) => Ok(Stream::Tls(Box::new(acceptor.accept(tcp).await?))),
            other => Ok(other),
        }
    }

    pub fn tls_info(&self) -> Option<String> {
        if let Stream::Deflate(d) = self {
            return d.inner.tls_info();
        }
        if let Stream::Tls(t) = self {
            let (_, c) = t.get_ref();
            let v = c.protocol_version().map(|v| format!("{v:?}")).unwrap_or_default();
            let s = c.negotiated_cipher_suite().map(|s| format!("{:?}", s.suite())).unwrap_or_default();
            return Some(format!("{v} {s}").replace('_', "_"));
        }
        None
    }
}

impl AsyncRead for Stream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(s) => Pin::new(s).poll_read(cx, buf),
            Stream::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
            Stream::Duplex(s) => Pin::new(s).poll_read(cx, buf),
            Stream::Deflate(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Stream::Plain(s) => Pin::new(s).poll_write(cx, buf),
            Stream::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
            Stream::Duplex(s) => Pin::new(s).poll_write(cx, buf),
            Stream::Deflate(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(s) => Pin::new(s).poll_flush(cx),
            Stream::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
            Stream::Duplex(s) => Pin::new(s).poll_flush(cx),
            Stream::Deflate(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            Stream::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
            Stream::Duplex(s) => Pin::new(s).poll_shutdown(cx),
            Stream::Deflate(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Stream::Plain(s) => Pin::new(s).poll_write_vectored(cx, bufs),
            Stream::Tls(s) => Pin::new(s.as_mut()).poll_write_vectored(cx, bufs),
            Stream::Duplex(s) => Pin::new(s).poll_write_vectored(cx, bufs),
            Stream::Deflate(s) => {
                let first = bufs.iter().find(|b| !b.is_empty()).map(|b| &**b).unwrap_or(&[]);
                Pin::new(s.as_mut()).poll_write(cx, first)
            }
        }
    }
    fn is_write_vectored(&self) -> bool {
        match self {
            Stream::Plain(s) => s.is_write_vectored(),
            Stream::Tls(s) => s.is_write_vectored(),
            Stream::Duplex(s) => s.is_write_vectored(),
            Stream::Deflate(_) => false,
        }
    }
}

/// Raw DEFLATE in both directions; every flush is a sync flush so the
/// peer can decode each response as soon as it arrives.
pub struct Deflate {
    inner: Stream,
    dec: flate2::Decompress,
    enc: flate2::Compress,
    rbuf: Vec<u8>,
    rpos: usize,
    wbuf: Vec<u8>,
    eof: bool,
}

impl Deflate {
    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        while !self.wbuf.is_empty() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.wbuf) {
                Poll::Ready(Ok(0)) => return Poll::Ready(Err(std::io::ErrorKind::WriteZero.into())),
                Poll::Ready(Ok(n)) => {
                    self.wbuf.drain(..n);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }

    fn compress_into(&mut self, mut input: &[u8], flush: flate2::FlushCompress) -> std::io::Result<()> {
        loop {
            let mut out = [0u8; 16 * 1024];
            let (bi, bo) = (self.enc.total_in(), self.enc.total_out());
            self.enc.compress(input, &mut out, flush).map_err(std::io::Error::other)?;
            let consumed = (self.enc.total_in() - bi) as usize;
            let produced = (self.enc.total_out() - bo) as usize;
            self.wbuf.extend_from_slice(&out[..produced]);
            input = &input[consumed..];
            if input.is_empty() && produced < out.len() {
                return Ok(());
            }
        }
    }
}

impl AsyncRead for Deflate {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        loop {
            // Always try the decoder first: it may hold output from input it
            // already consumed.
            let out = buf.initialize_unfilled();
            let (bi, bo) = (this.dec.total_in(), this.dec.total_out());
            this.dec.decompress(&this.rbuf[this.rpos..], out, flate2::FlushDecompress::Sync).map_err(std::io::Error::other)?;
            let consumed = (this.dec.total_in() - bi) as usize;
            let produced = (this.dec.total_out() - bo) as usize;
            this.rpos += consumed;
            if produced > 0 {
                buf.advance(produced);
                return Poll::Ready(Ok(()));
            }
            if consumed > 0 {
                continue;
            }
            // Stuck: need more input.
            this.rbuf.drain(..this.rpos);
            this.rpos = 0;
            if this.eof {
                return Poll::Ready(Ok(()));
            }
            let mut tmp = [0u8; 16 * 1024];
            let mut rb = ReadBuf::new(&mut tmp);
            match Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
                Poll::Ready(Ok(())) => {
                    if rb.filled().is_empty() {
                        this.eof = true;
                        return Poll::Ready(Ok(()));
                    }
                    this.rbuf.extend_from_slice(rb.filled());
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for Deflate {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if this.wbuf.len() > 256 * 1024 {
            match this.drain(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        this.compress_into(data, flate2::FlushCompress::None)?;
        Poll::Ready(Ok(data.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        this.compress_into(&[], flate2::FlushCompress::Sync)?;
        match this.drain(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_flush(cx),
            other => other,
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut *this).poll_flush(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_shutdown(cx),
            other => other,
        }
    }
}

/// Global and per-IP connection counters.
#[derive(Default)]
pub struct Connections {
    total: AtomicUsize,
    per_ip: DashMap<IpAddr, usize>,
    pub imap: AtomicUsize,
    pub smtp: AtomicUsize,
}

pub struct ConnGuard {
    conns: Arc<Connections>,
    ip: IpAddr,
    kind: &'static str,
}

impl Connections {
    pub fn acquire(self: &Arc<Self>, ip: IpAddr, max: usize, max_ip: usize, kind: &'static str) -> Option<ConnGuard> {
        if self.total.fetch_add(1, Ordering::SeqCst) >= max {
            self.total.fetch_sub(1, Ordering::SeqCst);
            return None;
        }
        {
            let mut e = self.per_ip.entry(ip).or_insert(0);
            if *e >= max_ip && !crate::util::is_loopback(ip) {
                drop(e);
                self.total.fetch_sub(1, Ordering::SeqCst);
                return None;
            }
            *e += 1;
        }
        match kind {
            "imap" => self.imap.fetch_add(1, Ordering::SeqCst),
            _ => self.smtp.fetch_add(1, Ordering::SeqCst),
        };
        Some(ConnGuard { conns: self.clone(), ip, kind })
    }

    pub fn total(&self) -> usize {
        self.total.load(Ordering::SeqCst)
    }
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.conns.total.fetch_sub(1, Ordering::SeqCst);
        match self.kind {
            "imap" => self.conns.imap.fetch_sub(1, Ordering::SeqCst),
            _ => self.conns.smtp.fetch_sub(1, Ordering::SeqCst),
        };
        let remove = {
            let mut e = self.conns.per_ip.entry(self.ip).or_insert(1);
            *e = e.saturating_sub(1);
            *e == 0
        };
        if remove {
            self.conns.per_ip.remove_if(&self.ip, |_, v| *v == 0);
        }
    }
}

#[cfg(test)]
mod deflate_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    #[tokio::test]
    async fn roundtrip() {
        let (a, b) = tokio::io::duplex(1 << 16);
        let mut a = Stream::Duplex(a).compress();
        let mut b = Stream::Duplex(b).compress();
        a.write_all(b"* OK hello\r\n").await.unwrap();
        a.flush().await.unwrap();
        let mut buf = [0u8; 64];
        let n = b.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"* OK hello\r\n");
        b.write_all(&vec![b'x'; 100_000]).await.unwrap();
        b.flush().await.unwrap();
        let mut got = vec![];
        while got.len() < 100_000 {
            let n = a.read(&mut buf).await.unwrap();
            got.extend_from_slice(&buf[..n]);
        }
        assert!(got.iter().all(|c| *c == b'x'));
    }
}
