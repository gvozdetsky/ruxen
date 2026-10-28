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
// The same stream carries an upstream connection (`proxy_pass https://`,
// #116): `TlsStream<IO, ClientConnection>`, made by `connect`. What is
// server-only (the session id, `connection()`) is on `TlsStream<IO>`.

use std::io::{self, BufRead, IoSlice, Write};
use std::mem;
use std::ptr::NonNull;
use std::sync::Arc;

use monoio::BufResult;
use monoio::buf::{IoBuf, IoBufMut, IoVecBuf, IoVecBufMut, RawBuf};
use monoio::io::{AsyncReadRent, AsyncWriteRent, AsyncWriteRentExt};
use rustls::{
    ClientConfig, ClientConnection, ConnectionCommon, ServerConfig, ServerConnection, SideData,
};

use crate::duplex::Duplex;

/// Socket read size: one maximum-size TLS record (16 KiB of plaintext plus
/// record overhead) fits in a single read.
const READ_BUF_SIZE: usize = 17 * 1024;

/// A write of at least this much (plaintext, or ciphertext in
/// `take_ciphertext`) is tried on the socket at once; smaller ones, most
/// responses, stay batched in io_uring.
const DIRECT_SEND_MIN: usize = 16 * 1024;

/// rustls's queued records straight to a socket: `sendmsg` without waiting,
/// `WouldBlock` when it is full.
struct SendNow(std::os::unix::io::RawFd);

impl io::Write for SendNow {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_vectored(&[IoSlice::new(buf)])
    }

    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        // SAFETY: a msghdr over `bufs`, which `IoSlice` lays out as iovecs
        // and which live through the call.
        let r = unsafe {
            let mut msg: libc::msghdr = mem::zeroed();
            msg.msg_iov = bufs.as_ptr() as *mut libc::iovec;
            msg.msg_iovlen = bufs.len().min(1024) as _;
            libc::sendmsg(self.0, &msg, libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL)
        };
        if r < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(r as usize)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// `wbuf` keeps its allocation between writes only up to this size, so a
/// connection that once streamed a large body doesn't pin ~64 KiB (rustls's
/// outgoing limit) for the rest of its keepalive life.
const WRITE_BUF_KEEP: usize = 32 * 1024;

/// What a client opened on a TLS port with.
#[allow(clippy::large_enum_variant)] // once per connection; its size is part of #467
pub enum Accepted<IO> {
    /// A completed handshake, and the client-certificate context of the
    /// config it ran with (`ssl_verify_client`, #113).
    Tls(TlsStream<IO>, Option<Arc<crate::client_verify::ClientAuth>>),
    /// The first bytes aren't a TLS record: plain HTTP sent to an `ssl`
    /// port (#384). The transport comes back with the bytes already read,
    /// for the caller to answer as nginx does (`NGX_HTTP_TO_HTTPS`).
    Plain(IO, Vec<u8>),
}

/// nginx's test in `ngx_http_ssl_handshake`: an SSLv2 ClientHello has the
/// top bit set, a TLS record starts with the handshake type (22). Anything
/// else is taken for plain HTTP.
fn starts_tls(first: u8) -> bool {
    first & 0x80 != 0 || first == 0x16
}

/// The first read on a TLS port: `None` at EOF.
async fn first_read<IO: AsyncReadRent>(io: &mut IO) -> io::Result<Option<Vec<u8>>> {
    let (res, buf) = io.read(Vec::with_capacity(READ_BUF_SIZE)).await;
    Ok((res? > 0).then_some(buf))
}

fn handshake_eof() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "tls handshake eof")
}

/// Per-listen handshake entry point, built once from the listen's
/// `ServerConfig`.
#[derive(Clone)]
pub struct TlsAcceptor {
    config: Arc<ServerConfig>,
    /// `config` without `h2` in ALPN, for the servers of an address that
    /// have HTTP/2 off when others have it on (#144).
    without_h2: Option<Arc<ServerConfig>>,
    session_ids: bool,
    /// The client-certificate context of `config` (#113).
    verify: Option<Arc<crate::client_verify::ClientAuth>>,
    /// The other servers' contexts, for `Choice::Accept { context: Some(i) }`.
    contexts: Vec<Context>,
}

/// A server's own context: `config` with its client-certificate verifier
/// (#113) and protocol versions (#586), the rest as the address's.
#[derive(Clone)]
struct Context {
    config: Arc<ServerConfig>,
    without_h2: Option<Arc<ServerConfig>>,
    verify: Option<Arc<crate::client_verify::ClientAuth>>,
}

/// What `accept_choosing` does after the ClientHello.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Choice {
    /// `ssl_reject_handshake`: an `unrecognized_name` alert.
    Reject,
    /// Accept, offering HTTP/2 through ALPN if `h2`, with the config of
    /// client-certificate context `context` (`with_contexts`), else the
    /// address's.
    Accept { h2: bool, context: Option<u16> },
}

impl From<Arc<ServerConfig>> for TlsAcceptor {
    fn from(config: Arc<ServerConfig>) -> Self {
        Self {
            config,
            without_h2: None,
            session_ids: false,
            verify: None,
            contexts: Vec::new(),
        }
    }
}

impl TlsAcceptor {
    /// Give each session an id for `$ssl_session_id`, when the config
    /// resumes sessions at all. rustls exposes neither the TLS 1.2 session
    /// ID nor the TLS 1.3 ticket, so a full handshake draws 32 random bytes
    /// and stores them in the session as its resumption data (see
    /// `TlsStream::session_id`).
    /// Keep `config` without `h2` in its ALPN list too, for
    /// `Choice::AcceptWithoutH2`.
    pub fn with_choice_of_h2(mut self) -> Self {
        let without = |config: &Arc<ServerConfig>| {
            let mut config = (**config).clone();
            config.alpn_protocols.retain(|p| p != b"h2");
            Some(Arc::new(config))
        };
        self.without_h2 = without(&self.config);
        for c in &mut self.contexts {
            c.without_h2 = without(&c.config);
        }
        self
    }

    /// Server contexts (#113, #586): `verify` is the client-certificate
    /// context of the address's config, `contexts` the configs of servers
    /// with another verifier or other protocols (each built from the
    /// address's), chosen by index in `Choice::Accept`. Before
    /// `with_choice_of_h2`.
    pub fn with_contexts(
        mut self,
        verify: Option<Arc<crate::client_verify::ClientAuth>>,
        contexts: Vec<(
            Arc<ServerConfig>,
            Option<Arc<crate::client_verify::ClientAuth>>,
        )>,
    ) -> Self {
        self.verify = verify;
        self.contexts = contexts
            .into_iter()
            .map(|(config, verify)| Context {
                config,
                without_h2: None,
                verify,
            })
            .collect();
        self
    }

    pub fn with_session_ids(mut self) -> Self {
        self.session_ids =
            self.config.session_storage.can_cache() || self.config.ticketer.enabled();
        self
    }

    /// Run the server handshake over `io`. rustls errors surface as
    /// `InvalidData`, a peer that hangs up mid-handshake as `UnexpectedEof`.
    /// A first byte that can't start TLS gives `Accepted::Plain`.
    pub async fn accept<IO>(&self, mut io: IO) -> io::Result<Accepted<IO>>
    where
        IO: AsyncReadRent + AsyncWriteRent + 'static,
    {
        let Some(first) = first_read(&mut io).await? else {
            return Err(handshake_eof());
        };
        if !starts_tls(first[0]) {
            return Ok(Accepted::Plain(io, first));
        }
        let conn = ServerConnection::new(self.config.clone()).map_err(io::Error::other)?;
        self.handshake_with(io, conn, first)
            .await
            .map(|s| Accepted::Tls(s, self.verify.clone()))
    }

    /// `accept`, but the ClientHello is read first and `choose` sees its
    /// SNI name (nginx's servername callback). `Choice::Reject` ends the
    /// handshake with a fatal `unrecognized_name` alert before any
    /// certificate is chosen (`ssl_reject_handshake`, #112), and the error
    /// is `ConnectionRefused`; `Choice::AcceptWithoutH2` doesn't offer
    /// `h2` (the server the name selects has HTTP/2 off, #144). Plain HTTP
    /// is `Accepted::Plain`, as in `accept`.
    pub async fn accept_choosing<IO>(
        &self,
        mut io: IO,
        choose: impl FnOnce(Option<&str>) -> Choice,
    ) -> io::Result<Accepted<IO>>
    where
        IO: AsyncReadRent + AsyncWriteRent + 'static,
    {
        let mut acceptor = rustls::server::Acceptor::default();
        let Some(mut buf) = first_read(&mut io).await? else {
            return Err(handshake_eof());
        };
        if !starts_tls(buf[0]) {
            return Ok(Accepted::Plain(io, buf));
        }
        let mut first = true;
        let accepted = loop {
            if !mem::take(&mut first) {
                buf.clear();
                let (res, returned) = io.read(buf).await;
                buf = returned;
                if res? == 0 {
                    return Err(handshake_eof());
                }
            }
            let mut pending = &buf[..];
            // rustls documents `Ok(0)` as EOF (or a close_notify already
            // received); without this check the loop, which never awaits,
            // would spin past the handshake timeout and stall the worker.
            while !pending.is_empty() {
                if acceptor.read_tls(&mut pending)? == 0 {
                    return Err(handshake_eof());
                }
            }
            match acceptor.accept() {
                Ok(Some(accepted)) => break accepted,
                Ok(None) => {}
                Err((e, mut alert)) => {
                    let mut out = Vec::new();
                    let _ = alert.write_all(&mut out);
                    let _ = io.write_all(out).await;
                    return Err(io::Error::new(io::ErrorKind::InvalidData, e));
                }
            }
        };
        let choice = choose(accepted.client_hello().server_name());
        if choice == Choice::Reject {
            // A plaintext fatal alert record, unrecognized_name (112): no
            // keys exist yet, for TLS 1.2 and 1.3 alike.
            let _ = io
                .write_all(vec![0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x70])
                .await;
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "handshake rejected (ssl_reject_handshake)",
            ));
        }
        let (h2, context) = match choice {
            Choice::Accept { h2, context } => (h2, context),
            Choice::Reject => (true, None),
        };
        let (config, without_h2, verify) = match context.and_then(|i| self.contexts.get(i as usize))
        {
            Some(c) => (&c.config, &c.without_h2, &c.verify),
            None => (&self.config, &self.without_h2, &self.verify),
        };
        let config = match (h2, without_h2) {
            (false, Some(config)) => config.clone(),
            _ => config.clone(),
        };
        let verify = verify.clone();
        let conn = match accepted.into_connection(config) {
            Ok(conn) => conn,
            Err((e, mut alert)) => {
                let mut out = Vec::new();
                let _ = alert.write_all(&mut out);
                let _ = io.write_all(out).await;
                return Err(io::Error::new(io::ErrorKind::InvalidData, e));
            }
        };
        self.handshake_with(io, conn, Vec::new())
            .await
            .map(|s| Accepted::Tls(s, verify))
    }

    /// The handshake, with `rbuf` holding ciphertext already read.
    async fn handshake_with<IO>(
        &self,
        io: IO,
        mut conn: ServerConnection,
        rbuf: Vec<u8>,
    ) -> io::Result<TlsStream<IO>>
    where
        IO: AsyncReadRent + AsyncWriteRent + 'static,
    {
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
            rbuf,
            rpos: 0,
            wbuf: Vec::new(),
            session_id,
        };
        stream.handshake().await?;
        Ok(stream)
    }
}

#[derive(Debug)]
pub struct TlsStream<IO, C = ServerConnection> {
    io: IO,
    conn: C,
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
}

/// A TLS client connection to `name` over `io`, handshaken: an HTTPS
/// upstream (#116). `name` is what the certificate is checked against
/// and, with SNI on in `config`, what the ClientHello names.
pub async fn connect<IO: AsyncReadRent + AsyncWriteRent + 'static>(
    config: Arc<ClientConfig>,
    name: rustls::pki_types::ServerName<'static>,
    io: IO,
) -> io::Result<TlsStream<IO, ClientConnection>> {
    let conn = ClientConnection::new(config, name)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let mut stream = TlsStream {
        io,
        conn,
        rbuf: Vec::new(),
        rpos: 0,
        wbuf: Vec::new(),
        session_id: None,
    };
    loop {
        stream.write_tls().await?;
        if !stream.conn.is_handshaking() {
            return Ok(stream);
        }
        if stream.read_tls().await? == 0 {
            return Err(handshake_eof());
        }
    }
}

impl<IO, C, D> TlsStream<IO, C>
where
    C: std::ops::DerefMut<Target = ConnectionCommon<D>>,
    D: SideData,
{
    /// The underlying transport, for waiting on the socket directly.
    pub fn io(&self) -> &IO {
        &self.io
    }

    /// The transport, for a read of ciphertext into `take_read_buf`'s
    /// buffer (the keep-alive wait, #145).
    pub(crate) fn io_mut(&mut self) -> &mut IO {
        &mut self.io
    }

    /// The ciphertext buffer, empty and with room for a record, when
    /// everything read so far went to rustls (`!has_buffered_input`).
    pub(crate) fn take_read_buf(&mut self) -> Vec<u8> {
        let mut buf = mem::take(&mut self.rbuf);
        self.rpos = 0;
        buf.clear();
        buf.reserve(READ_BUF_SIZE);
        buf
    }

    /// Back from `take_read_buf` with what the socket gave: the next
    /// `read` hands it to rustls before it reads the socket again.
    pub(crate) fn put_read_buf(&mut self, buf: Vec<u8>) {
        self.rbuf = buf;
        self.rpos = 0;
    }

    /// `take_read_buf`, when the socket is to be read: everything read so
    /// far went to rustls.
    #[inline]
    fn read_buf_if_drained(&mut self) -> Option<Vec<u8>> {
        (self.rpos == self.rbuf.len()).then(|| self.take_read_buf())
    }

    /// Hand rustls the ciphertext read and not yet handed, and process it.
    /// At EOF the slice is empty: rustls records the TCP EOF, so its
    /// plaintext reader reports `UnexpectedEof` instead of `WouldBlock`.
    #[inline]
    fn process_read(&mut self) -> io::Result<usize> {
        let mut pending = &self.rbuf[self.rpos..];
        let n = self.conn.read_tls(&mut pending)?;
        self.rpos += n;
        self.conn
            .process_new_packets()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        Ok(n)
    }

    /// What rustls has queued for the peer, as ciphertext for the socket;
    /// `None` when nothing is queued. `direct`: try a large run on the
    /// socket at once.
    // Inline, as it was in `write_tls`: out of line it cost ~90
    // instructions per TLS response (callgrind).
    #[inline(always)]
    fn take_ciphertext(&mut self, direct: bool) -> io::Result<Option<Vec<u8>>>
    where
        IO: 'static,
    {
        if !self.conn.wants_write() {
            return Ok(None);
        }
        let mut buf = mem::take(&mut self.wbuf);
        buf.clear();
        // A `Vec` sink never pushes back, so this drains the whole queue.
        while self.conn.wants_write() {
            self.conn.write_tls(&mut buf)?;
        }
        // A large run of records over plain TCP goes out at once, while
        // it is still in the cache from being encrypted (#247); what
        // the socket doesn't take goes through io_uring.
        if direct
            && buf.len() >= DIRECT_SEND_MIN
            && let Some(tcp) =
                (&self.io as &dyn std::any::Any).downcast_ref::<monoio::net::TcpStream>()
        {
            use std::os::unix::io::AsRawFd;
            let fd = tcp.as_raw_fd();
            let mut sent = 0usize;
            while sent < buf.len() {
                // SAFETY: the pointer/len pair stays within `buf`.
                let r = unsafe {
                    libc::send(
                        fd,
                        buf[sent..].as_ptr().cast(),
                        buf.len() - sent,
                        libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                    )
                };
                if r > 0 {
                    sent += r as usize;
                    continue;
                }
                if r < 0 && std::io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                break;
            }
            buf.drain(..sent);
        }
        Ok(Some(buf))
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

    /// Back from the socket write of `take_ciphertext`'s buffer.
    #[inline]
    fn put_write_buf(&mut self, buf: Vec<u8>) {
        if buf.capacity() <= WRITE_BUF_KEEP {
            self.wbuf = buf;
        }
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

impl<IO: AsyncReadRent + AsyncWriteRent + 'static> TlsStream<IO> {
    async fn handshake(&mut self) -> io::Result<()> {
        loop {
            // The final pass also flushes what rustls queues right after the
            // handshake (TLS 1.3 session tickets).
            self.write_tls().await?;
            if !self.conn.is_handshaking() {
                return Ok(());
            }
            if self.read_tls().await? == 0 {
                return Err(handshake_eof());
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
}

impl<IO, C, D> TlsStream<IO, C>
where
    IO: AsyncReadRent + AsyncWriteRent + 'static,
    C: std::ops::DerefMut<Target = ConnectionCommon<D>>,
    D: SideData,
{
    /// Hand rustls the next chunk of ciphertext, reading from the socket
    /// first when nothing is buffered, and process it. Returns 0 at EOF:
    /// TCP FIN, or a close_notify already received.
    async fn read_tls(&mut self) -> io::Result<usize> {
        if let Some(buf) = self.read_buf_if_drained() {
            let (res, buf) = self.io.read(buf).await;
            self.rbuf = buf;
            res?;
        }
        let res = self.process_read();
        // What rustls queued in answer goes out now: the alert for an
        // error (best effort), the `no_renegotiation` alert for a TLS 1.2
        // ClientHello after the handshake, the KeyUpdate a TLS 1.3
        // `update_requested` asks for. The server may be waiting for
        // request bytes and not write anything else. OpenSSL writes these
        // from inside SSL_read. The handshake loop flushes on its own.
        if res.is_err() {
            let _ = self.write_tls().await;
        } else if self.conn.wants_write() && !self.conn.is_handshaking() {
            self.write_tls().await?;
        }
        res
    }

    /// Move everything rustls has queued for the peer onto the socket.
    async fn write_tls(&mut self) -> io::Result<()> {
        self.write_tls_from(false).await
    }

    /// `write_tls`; `large`: a large run of records, which over plain TCP
    /// goes out at once from rustls's queue, while it is still in the cache
    /// from being encrypted (#247), without a copy into `wbuf` (#545).
    /// What the socket doesn't take goes through io_uring.
    async fn write_tls_from(&mut self, large: bool) -> io::Result<()> {
        if large
            && let Some(tcp) =
                (&self.io as &dyn std::any::Any).downcast_ref::<monoio::net::TcpStream>()
        {
            use std::os::unix::io::AsRawFd;
            let mut sock = SendNow(tcp.as_raw_fd());
            while self.conn.wants_write() {
                match self.conn.write_tls(&mut sock) {
                    Ok(_) => {}
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => return Err(e),
                }
            }
        }
        // After `SendNow`, the socket is full: no second try at once.
        while let Some(buf) = self.take_ciphertext(!large)? {
            let (res, buf) = if buf.is_empty() {
                (Ok(()), buf)
            } else {
                let (res, buf) = self.io.write_all(buf).await;
                (res.map(|_| ()), buf)
            };
            self.put_write_buf(buf);
            res?;
        }
        Ok(())
    }

    /// Encrypt as much of `bufs` as rustls accepts (its outgoing limit is
    /// 64 KiB) as one run of records and write it out.
    async fn write_plaintext(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        // Normally a no-op; clears anything left by an earlier failed write
        // or queued by the read side (alerts, key updates) so the limit
        // applies to this write alone.
        self.write_tls().await?;
        let n = self.conn.writer().write_vectored(bufs)?;
        self.write_tls_from(n >= DIRECT_SEND_MIN).await?;
        Ok(n)
    }
}

/// For the `Duplex` side, as `write_tls` and its socket.
impl<IO, C, D> TlsStream<IO, C>
where
    IO: Duplex,
    C: std::ops::DerefMut<Target = ConnectionCommon<D>> + 'static,
    D: SideData + 'static,
{
    /// The transport, projected without a reference to the stream.
    fn io_ptr(this: NonNull<Self>) -> NonNull<IO> {
        // SAFETY: a field of a valid pointer.
        unsafe { NonNull::new_unchecked(&raw mut (*this.as_ptr()).io) }
    }

    /// # Safety
    ///
    /// As `Duplex::write_raw`.
    async unsafe fn duplex_write_tls(this: NonNull<Self>) -> io::Result<()> {
        // Again after each write: the read side may queue records (an
        // alert, a KeyUpdate) while one is in flight.
        // SAFETY: as in `read_raw`, here and below.
        while let Some(buf) = unsafe { &mut *this.as_ptr() }.take_ciphertext(true)? {
            let (res, buf) = if buf.is_empty() {
                (Ok(0), buf)
            } else {
                unsafe { crate::duplex::write_all_raw(Self::io_ptr(this), buf) }.await
            };
            unsafe { &mut *this.as_ptr() }.put_write_buf(buf);
            res?;
        }
        Ok(())
    }
}

/// An HTTP/2 connection, a tunnel (#501): a read and a write in flight at
/// once, each with a reference to the stream only between awaits. A read
/// doesn't write to the socket: what rustls queues in answer goes with the
/// next write.
// SAFETY: as just said; `io` is reached through `io_ptr`.
unsafe impl<IO, C, D> Duplex for TlsStream<IO, C>
where
    IO: Duplex,
    C: std::ops::DerefMut<Target = ConnectionCommon<D>> + 'static,
    D: SideData + 'static,
{
    async unsafe fn read_raw<T: IoBufMut>(this: NonNull<Self>, mut buf: T) -> BufResult<usize, T> {
        let (dst, cap) = (buf.write_ptr(), buf.bytes_total());
        loop {
            let socket_read = {
                // SAFETY: valid, and no other reference to it is live (the
                // caller's); this one ends before the await.
                let s = unsafe { &mut *this.as_ptr() };
                match s.read_plaintext(dst, cap) {
                    Ok(n) => {
                        // SAFETY: `read_plaintext` initialized the first `n` bytes.
                        unsafe { buf.set_init(n) };
                        return (Ok(n), buf);
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e) => return (Err(e), buf),
                }
                s.read_buf_if_drained()
            };
            if let Some(rbuf) = socket_read {
                // SAFETY: valid; the other operation on `io` is at most the
                // write side's.
                let (res, rbuf) = unsafe { IO::read_raw(Self::io_ptr(this), rbuf) }.await;
                // SAFETY: as above, here and below.
                unsafe { (*this.as_ptr()).rbuf = rbuf };
                if let Err(e) = res {
                    return (Err(e), buf);
                }
            }
            if let Err(e) = unsafe { &mut *this.as_ptr() }.process_read() {
                return (Err(e), buf);
            }
        }
    }

    /// As `write_plaintext`.
    async unsafe fn write_raw<T: IoBuf>(this: NonNull<Self>, buf: T) -> BufResult<usize, T> {
        // SAFETY: `IoBuf` guarantees `bytes_init` initialized bytes at
        // `read_ptr`, and `buf` is owned here until we return it.
        let src = unsafe { std::slice::from_raw_parts(buf.read_ptr(), buf.bytes_init()) };
        // SAFETY: as in `read_raw`, here and below.
        if let Err(e) = unsafe { Self::duplex_write_tls(this) }.await {
            return (Err(e), buf);
        }
        let n = match unsafe { &mut *this.as_ptr() }.conn.writer().write(src) {
            Ok(n) => n,
            Err(e) => return (Err(e), buf),
        };
        let res = unsafe { Self::duplex_write_tls(this) }.await;
        (res.map(|()| n), buf)
    }

    async unsafe fn shutdown_raw(this: NonNull<Self>) -> io::Result<()> {
        // SAFETY: as in `read_raw`, here and below.
        unsafe { (*this.as_ptr()).conn.send_close_notify() };
        unsafe { Self::duplex_write_tls(this) }.await?;
        unsafe { IO::shutdown_raw(Self::io_ptr(this)) }.await
    }
}

impl<IO, C, D> AsyncReadRent for TlsStream<IO, C>
where
    IO: AsyncReadRent + AsyncWriteRent + 'static,
    C: std::ops::DerefMut<Target = ConnectionCommon<D>>,
    D: SideData,
{
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

impl<IO, C, D> AsyncWriteRent for TlsStream<IO, C>
where
    IO: AsyncReadRent + AsyncWriteRent + 'static,
    C: std::ops::DerefMut<Target = ConnectionCommon<D>>,
    D: SideData,
{
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

    fn tls<IO>(accepted: Accepted<IO>) -> TlsStream<IO> {
        match accepted {
            Accepted::Tls(s, _) => s,
            Accepted::Plain(..) => panic!("plain bytes on the TLS port"),
        }
    }

    #[test]
    fn roundtrip_writev_and_close_notify() {
        run(
            |acceptor, sock| async move {
                let mut s = tls(acceptor.accept(sock).await.unwrap());
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
                let mut s = tls(acceptor.accept(sock).await.unwrap());
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

    /// #545: records sent from rustls's queue at once until the socket is
    /// full, the rest through the ring, in order.
    #[test]
    fn large_write_to_a_slow_reader() {
        const LEN: usize = 4 * 1024 * 1024;
        let body: Vec<u8> = (0..LEN).map(|i| (i % 253) as u8).collect();
        let expect = body.clone();
        run(
            |acceptor, sock| async move {
                // A small send buffer: the socket fills long before the end.
                {
                    use std::os::unix::io::AsRawFd;
                    let size: libc::c_int = 16 * 1024;
                    // SAFETY: a c_int option value on the accepted socket.
                    let r = unsafe {
                        libc::setsockopt(
                            sock.as_raw_fd(),
                            libc::SOL_SOCKET,
                            libc::SO_SNDBUF,
                            (&size as *const libc::c_int).cast(),
                            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                        )
                    };
                    assert_eq!(r, 0);
                }
                let mut s = tls(acceptor.accept(sock).await.unwrap());
                let (res, _) = s.write_all(body).await;
                assert_eq!(res.unwrap(), LEN);
                s.shutdown().await.unwrap();
            },
            move |mut c| {
                std::thread::sleep(std::time::Duration::from_millis(300));
                let mut out = Vec::new();
                c.read_to_end(&mut out).unwrap();
                assert!(out == expect, "{} bytes, not the body", out.len());
            },
        );
    }

    /// A read in flight while a large write goes out, on the `Duplex`
    /// halves (an HTTP/2 connection, a tunnel, #501).
    #[test]
    fn halves_read_while_writing() {
        const LEN: usize = 200 * 1024;
        run(
            |acceptor, sock| async move {
                let s = tls(acceptor.accept(sock).await.unwrap());
                let (mut r, mut w, _) = crate::duplex::into_split(s);
                let read = async {
                    let (res, buf) = r.read(Vec::with_capacity(64)).await;
                    assert_eq!(res.unwrap(), 4);
                    assert_eq!(buf, b"done");
                };
                let write = async {
                    let (res, _) = w.write_all(vec![7u8; LEN]).await;
                    assert_eq!(res.unwrap(), LEN);
                };
                monoio::join!(read, write);
                w.shutdown().await.unwrap();
            },
            |mut c| {
                let mut buf = vec![0; LEN];
                c.read_exact(&mut buf).unwrap();
                assert!(buf.iter().all(|&b| b == 7));
                c.write_all(b"done").unwrap();
                let mut rest = Vec::new();
                // `read_to_end` only succeeds on a clean close_notify.
                c.read_to_end(&mut rest).unwrap();
                assert!(rest.is_empty());
            },
        );
    }

    #[test]
    fn handshake_eof() {
        run(
            |acceptor, sock| async move {
                let Err(err) = acceptor.accept(sock).await else {
                    panic!("accepted a closed connection");
                };
                assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
            },
            |c| c.sock.shutdown(std::net::Shutdown::Both).unwrap(),
        );
    }
}
