// Server-side TLS stream: rustls's sync state machine over monoio's
// owned-buffer IO.
//
// Replaces the `monoio-rustls` crate, whose upstream has had no release
// since 0.4.0 (May 2024). Owning the adapter lets us read the negotiated
// session directly (the `$ssl_*` snapshot in `tls.rs`) and keeps the
// buffered-ciphertext state visible to ruxen, which the TLS keepalive idle
// wait needs.
//
// Data flow:
//
// - read: socket → `rbuf` (ciphertext) → `ServerConnection::read_tls` +
//   `process_new_packets` → plaintext copied out of rustls into the
//   caller's buffer.
// - write: caller's buffer → `ServerConnection::writer` (encrypts into
//   rustls's outgoing queue) → `write_tls` drains the whole queue into
//   `wbuf` → one `write_all` to the socket.
//
// Server side only: ruxen talks plain HTTP to upstreams.

use std::io::{self, BufRead, IoSlice, Write};
use std::mem;
use std::sync::Arc;

use monoio::BufResult;
use monoio::buf::{IoBuf, IoBufMut, IoVecBuf, IoVecBufMut, RawBuf};
use monoio::io::{AsyncReadRent, AsyncWriteRent, AsyncWriteRentExt};
use rustls::{ServerConfig, ServerConnection};

/// Socket read size: one maximum-size TLS record (16 KiB of plaintext plus
/// record overhead) fits in a single read.
const READ_BUF_SIZE: usize = 17 * 1024;

/// `wbuf` keeps its allocation between writes only up to this size, so a
/// connection that once streamed a large body doesn't pin ~64 KiB (rustls's
/// outgoing limit) for the rest of its keepalive life.
const WRITE_BUF_KEEP: usize = 32 * 1024;

/// Per-listen handshake entry point, built once from the listen's
/// `ServerConfig`.
#[derive(Clone)]
pub struct TlsAcceptor {
    config: Arc<ServerConfig>,
    session_ids: bool,
}

impl From<Arc<ServerConfig>> for TlsAcceptor {
    fn from(config: Arc<ServerConfig>) -> Self {
        Self {
            config,
            session_ids: false,
        }
    }
}

impl TlsAcceptor {
    /// Give each session an id for `$ssl_session_id`, when the config
    /// resumes sessions at all. rustls exposes neither the TLS 1.2 session
    /// ID nor the TLS 1.3 ticket, so a full handshake draws 32 random bytes
    /// and stores them in the session as its resumption data (see
    /// `TlsStream::session_id`).
    pub fn with_session_ids(mut self) -> Self {
        self.session_ids =
            self.config.session_storage.can_cache() || self.config.ticketer.enabled();
        self
    }

    /// Run the server handshake over `io`. rustls errors surface as
    /// `InvalidData`, a peer that hangs up mid-handshake as `UnexpectedEof`.
    pub async fn accept<IO>(&self, io: IO) -> io::Result<TlsStream<IO>>
    where
        IO: AsyncReadRent + AsyncWriteRent,
    {
        let mut conn = ServerConnection::new(self.config.clone()).map_err(io::Error::other)?;
        let session_id = if self.session_ids {
            let mut id = [0; 32];
            self.config
                .crypto_provider()
                .secure_random
                .fill(&mut id)
                .map_err(|_| io::Error::other("no random bytes for a session id"))?;
            conn.set_resumption_data(&id);
            Some(id)
        } else {
            None
        };
        let mut stream = TlsStream {
            io,
            conn,
            rbuf: Vec::new(),
            rpos: 0,
            wbuf: Vec::new(),
            session_id,
        };
        stream.handshake().await?;
        Ok(stream)
    }
}

#[derive(Debug)]
pub struct TlsStream<IO> {
    io: IO,
    conn: ServerConnection,
    /// Ciphertext read from `io`; `rbuf[rpos..]` hasn't been handed to
    /// rustls yet. Allocated on the first read.
    rbuf: Vec<u8>,
    rpos: usize,
    /// Outgoing ciphertext staging, reused across writes (see
    /// `WRITE_BUF_KEEP`).
    wbuf: Vec<u8>,
    /// The session's `$ssl_session_id` bytes, with `with_session_ids`.
    session_id: Option<[u8; 32]>,
}

impl<IO> TlsStream<IO> {
    /// The rustls session, for reading negotiated parameters.
    pub fn connection(&self) -> &ServerConnection {
        &self.conn
    }

    /// The id `with_session_ids` gave this session: drawn on a full
    /// handshake, carried over on a TLS 1.3 resumption. rustls doesn't
    /// return the resumption data of a resumed TLS 1.2 session, so that
    /// one has none, like a listen without resumption.
    pub fn session_id(&self) -> Option<&[u8; 32]> {
        let resumed = self.conn.handshake_kind() == Some(rustls::HandshakeKind::Resumed);
        if resumed && self.conn.received_resumption_data().map(<[u8]>::len) != Some(32) {
            return None;
        }
        self.session_id.as_ref()
    }

    /// The underlying transport, for waiting on the socket directly.
    pub fn io(&self) -> &IO {
        &self.io
    }

    /// Whether the next `read` can make progress without new bytes from
    /// the socket: ciphertext already read but not yet handed to rustls, or
    /// plaintext (or a close_notify) rustls hasn't returned yet. TLS 1.3
    /// clients often send the first request in the same flight as their
    /// Finished, so it is already here when the handshake completes.
    pub fn has_buffered_input(&self) -> bool {
        // After the handshake `wants_read` is false exactly when rustls
        // holds unread plaintext or has seen close_notify.
        self.rpos < self.rbuf.len() || !self.conn.wants_read()
    }
}

impl<IO: AsyncReadRent + AsyncWriteRent> TlsStream<IO> {
    async fn handshake(&mut self) -> io::Result<()> {
        loop {
            // The final pass also flushes what rustls queues right after the
            // handshake (TLS 1.3 session tickets).
            self.write_tls().await?;
            if !self.conn.is_handshaking() {
                return Ok(());
            }
            if self.read_tls().await? == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "tls handshake eof",
                ));
            }
            // A resumed TLS 1.3 session keeps its id, also in the tickets
            // issued now (after the client's Finished, a later flight).
            if let Some(id) = &mut self.session_id
                && let Some(Ok(received)) = self
                    .conn
                    .received_resumption_data()
                    .map(<[u8; 32]>::try_from)
                && received != *id
            {
                *id = received;
                self.conn.set_resumption_data(&received);
            }
        }
    }

    /// Hand rustls the next chunk of ciphertext, reading from the socket
    /// first when nothing is buffered, and process it. Returns 0 at EOF:
    /// TCP FIN, or a close_notify already received.
    async fn read_tls(&mut self) -> io::Result<usize> {
        if self.rpos == self.rbuf.len() {
            let mut buf = mem::take(&mut self.rbuf);
            self.rpos = 0;
            buf.clear();
            buf.reserve(READ_BUF_SIZE);
            let (res, buf) = self.io.read(buf).await;
            self.rbuf = buf;
            res?;
        }
        // At EOF the slice is empty: rustls records the TCP EOF, so its
        // plaintext reader reports `UnexpectedEof` instead of `WouldBlock`.
        let mut pending = &self.rbuf[self.rpos..];
        let n = self.conn.read_tls(&mut pending)?;
        self.rpos += n;
        if let Err(e) = self.conn.process_new_packets() {
            // Best effort: get the alert rustls queued out to the peer.
            let _ = self.write_tls().await;
            return Err(io::Error::new(io::ErrorKind::InvalidData, e));
        }
        Ok(n)
    }

    /// Move everything rustls has queued for the peer onto the socket.
    async fn write_tls(&mut self) -> io::Result<()> {
        if !self.conn.wants_write() {
            return Ok(());
        }
        let mut buf = mem::take(&mut self.wbuf);
        buf.clear();
        // A `Vec` sink never pushes back, so this drains the whole queue.
        while self.conn.wants_write() {
            self.conn.write_tls(&mut buf)?;
        }
        let (res, buf) = self.io.write_all(buf).await;
        if buf.capacity() <= WRITE_BUF_KEEP {
            self.wbuf = buf;
        }
        res.map(drop)
    }

    /// Encrypt as much of `bufs` as rustls accepts (its outgoing limit is
    /// 64 KiB) as one run of records and write it out.
    async fn write_plaintext(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        // Normally a no-op; clears anything left by an earlier failed write
        // or queued by the read side (alerts, key updates) so the limit
        // applies to this write alone.
        self.write_tls().await?;
        let n = self.conn.writer().write_vectored(bufs)?;
        self.write_tls().await?;
        Ok(n)
    }

    /// Copy decrypted bytes out of rustls into `dst`. `Ok(0)` for an empty
    /// `dst` or after the peer's close_notify; `WouldBlock` when rustls
    /// needs more ciphertext; `UnexpectedEof` after a TCP FIN without
    /// close_notify.
    fn read_plaintext(&mut self, dst: *mut u8, cap: usize) -> io::Result<usize> {
        let mut reader = self.conn.reader();
        let mut n = 0;
        while n < cap {
            let chunk = match reader.fill_buf() {
                Ok(chunk) => chunk,
                // Return what we have; the condition resurfaces next call.
                Err(_) if n > 0 => break,
                Err(e) => return Err(e),
            };
            if chunk.is_empty() {
                break;
            }
            let k = chunk.len().min(cap - n);
            // SAFETY: `dst` is valid for `cap` bytes (the caller's
            // `IoBufMut`) and `n + k <= cap`.
            unsafe { std::ptr::copy_nonoverlapping(chunk.as_ptr(), dst.add(n), k) };
            reader.consume(k);
            n += k;
        }
        Ok(n)
    }
}

impl<IO: AsyncReadRent + AsyncWriteRent> AsyncReadRent for TlsStream<IO> {
    async fn read<T: IoBufMut>(&mut self, mut buf: T) -> BufResult<usize, T> {
        let (dst, cap) = (buf.write_ptr(), buf.bytes_total());
        loop {
            match self.read_plaintext(dst, cap) {
                Ok(n) => {
                    // SAFETY: `read_plaintext` initialized the first `n` bytes.
                    unsafe { buf.set_init(n) };
                    return (Ok(n), buf);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return (Err(e), buf),
            }
            if let Err(e) = self.read_tls().await {
                return (Err(e), buf);
            }
        }
    }

    async fn readv<T: IoVecBufMut>(&mut self, mut buf: T) -> BufResult<usize, T> {
        // Fill the first iovec only: a short read, which callers handle.
        // SAFETY: `buf` is owned here and outlives `raw`.
        let res = match unsafe { RawBuf::new_from_iovec_mut(&mut buf) } {
            Some(raw) => self.read(raw).await.0,
            None => Ok(0),
        };
        if let Ok(n) = res {
            // SAFETY: `n` bytes of the first iovec were just written.
            unsafe { buf.set_init(n) };
        }
        (res, buf)
    }
}

impl<IO: AsyncReadRent + AsyncWriteRent> AsyncWriteRent for TlsStream<IO> {
    async fn write<T: IoBuf>(&mut self, buf: T) -> BufResult<usize, T> {
        // SAFETY: `IoBuf` guarantees `bytes_init` initialized bytes at
        // `read_ptr`, and `buf` is owned here until we return it.
        let src = unsafe { std::slice::from_raw_parts(buf.read_ptr(), buf.bytes_init()) };
        let res = self.write_plaintext(&[IoSlice::new(src)]).await;
        (res, buf)
    }

    async fn writev<T: IoVecBuf>(&mut self, buf: T) -> BufResult<usize, T> {
        // SAFETY: `IoVecBuf` guarantees `read_iovec_len` valid iovecs at
        // `read_iovec_ptr`, each pointing at initialized bytes, and `buf`
        // is owned here until we return it.
        let iovecs =
            unsafe { std::slice::from_raw_parts(buf.read_iovec_ptr(), buf.read_iovec_len()) };
        let slices: Vec<IoSlice<'_>> = iovecs
            .iter()
            .map(|v| {
                IoSlice::new(unsafe {
                    std::slice::from_raw_parts(v.iov_base as *const u8, v.iov_len)
                })
            })
            .collect();
        let res = self.write_plaintext(&slices).await;
        (res, buf)
    }

    async fn flush(&mut self) -> io::Result<()> {
        self.write_tls().await?;
        self.io.flush().await
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        self.conn.send_close_notify();
        self.write_tls().await?;
        self.io.shutdown().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Read;
    use std::net::TcpStream as StdTcpStream;

    use monoio::RuntimeBuilder;
    use monoio::net::TcpListener;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};

    fn configs() -> (Arc<ServerConfig>, Arc<rustls::ClientConfig>) {
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert = CertificateDer::from(ck.cert.der().to_vec());
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der()));
        let server = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert.clone()], key)
            .unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert).unwrap();
        let client = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        (Arc::new(server), Arc::new(client))
    }

    /// Accept one connection on a monoio runtime and run `server` on it,
    /// while `client` drives a blocking rustls client on a plain thread.
    fn run<S, F, C>(server: S, client: C)
    where
        S: FnOnce(TlsAcceptor, monoio::net::TcpStream) -> F,
        F: Future<Output = ()>,
        C: FnOnce(rustls::StreamOwned<rustls::ClientConnection, StdTcpStream>) + Send + 'static,
    {
        let (server_cfg, client_cfg) = configs();
        let mut rt = RuntimeBuilder::<monoio::IoUringDriver>::new()
            .build()
            .unwrap();
        rt.block_on(async move {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let client = std::thread::spawn(move || {
                let sock = StdTcpStream::connect(addr).unwrap();
                let name = ServerName::try_from("localhost").unwrap();
                let conn = rustls::ClientConnection::new(client_cfg, name).unwrap();
                client(rustls::StreamOwned::new(conn, sock));
            });
            let (sock, _) = listener.accept().await.unwrap();
            server(TlsAcceptor::from(server_cfg), sock).await;
            client.join().unwrap();
        });
    }

    #[test]
    fn roundtrip_writev_and_close_notify() {
        run(
            |acceptor, sock| async move {
                let mut s = acceptor.accept(sock).await.unwrap();
                assert_eq!(s.connection().server_name(), Some("localhost"));
                let (res, buf) = s.read(Vec::with_capacity(64)).await;
                assert_eq!(res.unwrap(), 4);
                assert_eq!(buf, b"ping");
                let (res, _) = s
                    .writev(monoio::buf::VecBuf::from(vec![
                        b"po".to_vec(),
                        b"ng".to_vec(),
                    ]))
                    .await;
                assert_eq!(res.unwrap(), 4);
                s.shutdown().await.unwrap();
            },
            |mut c| {
                c.write_all(b"ping").unwrap();
                let mut out = Vec::new();
                // `read_to_end` only succeeds on a clean close_notify.
                c.read_to_end(&mut out).unwrap();
                assert_eq!(out, b"pong");
            },
        );
    }

    #[test]
    fn large_write_and_unclean_eof() {
        const LEN: usize = 300 * 1024;
        let body: Vec<u8> = (0..LEN).map(|i| (i % 251) as u8).collect();
        let expect = body.clone();
        run(
            |acceptor, sock| async move {
                let mut s = acceptor.accept(sock).await.unwrap();
                // Longer than rustls's 64 KiB outgoing limit: `write_all`
                // has to loop over partial writes.
                let (res, _) = s.write_all(body).await;
                assert_eq!(res.unwrap(), LEN);
                // The client echoes everything back, then drops TCP without
                // close_notify.
                let mut got = Vec::new();
                loop {
                    let (res, buf) = s.read(Vec::with_capacity(8192)).await;
                    match res {
                        Ok(0) => panic!("clean EOF without close_notify"),
                        Ok(_) => got.extend_from_slice(&buf),
                        Err(e) => {
                            assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof);
                            break;
                        }
                    }
                }
                assert_eq!(got, expect);
            },
            |mut c| {
                let mut buf = vec![0; LEN];
                c.read_exact(&mut buf).unwrap();
                c.write_all(&buf).unwrap();
                c.flush().unwrap();
                c.sock.shutdown(std::net::Shutdown::Both).unwrap();
            },
        );
    }

    #[test]
    fn handshake_eof() {
        run(
            |acceptor, sock| async move {
                let err = acceptor.accept(sock).await.unwrap_err();
                assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
            },
            |c| c.sock.shutdown(std::net::Shutdown::Both).unwrap(),
        );
    }
}
