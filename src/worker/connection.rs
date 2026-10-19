//! Wire I/O: the `ConnIo` trait that abstracts plain TCP vs TLS, the
//! chunked-body decoder, and the `stream_file` send path.

#![allow(unused_imports)]

use std::cell::{Cell, RefCell};
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::SocketAddr;
use std::os::unix::net::UnixDatagram;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use monoio::RuntimeBuilder;
use monoio::buf::{IoBuf, IoBufMut};
use monoio::fs::File as AsyncFile;
use monoio::io::{AsyncReadRent, AsyncWriteRent, AsyncWriteRentExt};
use monoio::net::{ListenerOpts, TcpListener, TcpStream};

use crate::config::{
    AccessLog, AddHeader, AuthBasic, AutoindexFormat, ErrorLog, ErrorLogLevel,
    ErrorLogSyslogServer, ErrorLogTarget, ErrorPage, ErrorPageAction, FileTestKind, Handler,
    HttpConfig, IfGuard, IndexEntry, KeepaliveDisable, KeepaliveTimeout, Location, LogFormatDef,
    MapBlock, MapExactEntry, MapRegexEntry, MatchMode, PathMapping, ProxyPass, ProxySetHeader,
    RewriteFlag as ConfigRewriteFlag, RewriteOp, RewriteRule, Server, SplitClients, TryFiles,
    TryFilesFallback, TryFilesProbe, ValuePart, Variable,
};
use crate::http::{self, Method, Parse, ParseState, READ_BUF};
use crate::phase::{self, Response};
use crate::{autoindex, file, fs_resolve, uri};

use super::*;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum RequestTransferEncoding {
    ChunkedOnly,
    Unsupported,
    Invalid,
}

/// Request-body transfer-coding support for inbound client requests.
///
/// ruxen supports exactly one transfer-coding today: `chunked`.
/// Anything else is syntactically valid but unsupported (501), while
/// malformed token lists are rejected as bad requests (400).
pub(crate) fn classify_request_transfer_encoding(value: &[u8]) -> RequestTransferEncoding {
    let n = value.len();
    let mut i = 0usize;
    let mut tokens = 0usize;
    let mut saw_chunked = false;
    while i < n {
        while i < n && matches!(value[i], b' ' | b'\t') {
            i += 1;
        }
        if i >= n {
            break;
        }
        let token_start = i;
        while i < n && value[i] != b',' {
            i += 1;
        }
        let mut token_end = i;
        while token_end > token_start && matches!(value[token_end - 1], b' ' | b'\t') {
            token_end -= 1;
        }
        if token_end == token_start {
            return RequestTransferEncoding::Invalid;
        }
        tokens += 1;
        let token = &value[token_start..token_end];
        if !token.eq_ignore_ascii_case(b"chunked") {
            return RequestTransferEncoding::Unsupported;
        }
        saw_chunked = true;
        if i < n {
            i += 1; // skip comma
        }
    }
    if tokens == 0 {
        return RequestTransferEncoding::Invalid;
    }
    if tokens == 1 && saw_chunked {
        RequestTransferEncoding::ChunkedOnly
    } else {
        RequestTransferEncoding::Unsupported
    }
}

/// Connection I/O abstraction: anything the request loop runs against,
/// be it a raw `TcpStream` or a `ServerTlsStream<TcpStream>`. Plain HTTP
/// uses the per-byte `read`/`write` path; the trait factors out the
/// keep-alive idle wait, which differs by IO type.
pub trait ConnIo: AsyncReadRent + monoio::io::AsyncWriteRent {
    /// Wait until the next request *may* be available, or shutdown / idle
    /// timeout fires. Returns `true` to proceed to the read step, `false`
    /// to drop the connection.
    ///
    /// Plain TCP polls the kernel socket for readability without
    /// allocating a buffer (mirrors nginx's
    /// `keepalive_handler` / `wait_request_handler` split).
    ///
    /// TLS does the same poll, except when the stream already holds input
    /// the socket won't signal again: ciphertext or decrypted bytes left
    /// over from the handshake (TLS 1.3 clients send the first request in
    /// the same flight as Finished) or from a previous read. Then it
    /// proceeds straight to the read.
    async fn idle_wait(
        &self,
        state: &RuntimeState,
        idle: Option<Duration>,
        fresh: bool,
        timers: &mut ConnTimers<'_>,
    ) -> bool;

    /// Raw socket fd for the zero-copy `sendfile` path, or `None` when the
    /// transport has to see the bytes (TLS).
    fn sendfile_fd(&self) -> Option<std::os::unix::io::RawFd>;

    /// Wait until the socket accepts more data. Only used by the zero-copy
    /// path, which writes to the fd directly.
    async fn wait_writable(&self) -> std::io::Result<()>;

    /// The connection is about to carry a tunnel (#87), where one read and
    /// one write are in flight at once; after this, `read` must not write
    /// to the socket itself.
    fn begin_tunnel(&mut self) {}

    /// Whether `send_file_body` may take a file body: a plain check, so
    /// that HTTP/1 connections don't pay for the call.
    fn sends_file_bodies(&self) -> bool {
        false
    }

    /// Send a file body itself, when the transport can do better than
    /// `stream_file`'s read-and-write loop: an HTTP/2 stream hands the
    /// bytes to its DATA frames without copying them (#348). `None`: not
    /// done, use the loop. Called only when `sends_file_bodies`.
    async fn send_file_body(&mut self, _body: &phase::FileBody) -> Option<bool> {
        None
    }

    /// An HTTP/2 stream (`h2::StreamIo`): its request line says `HTTP/2.0`.
    fn h2(&self) -> bool {
        false
    }

    /// For an HTTP/2 stream, the size of its header block as the client
    /// sent it, where nginx's `$request_length` starts there instead of
    /// the HTTP/1.1 head `handle` reads (#409).
    fn h2_header_block(&self) -> Option<u64> {
        None
    }

    /// For an HTTP/2 stream, its connection's start and the requests it
    /// carried before this one (`$connection_time`, `$connection_requests`).
    fn conn_counters(&self) -> Option<(Instant, u64)> {
        None
    }

    /// Completes once the client has closed the connection (a read would
    /// see EOF), for a response that waits between writes: nginx's
    /// `ngx_http_test_reading` ends the request then (#383). Pending
    /// otherwise, also once bytes arrive (a pipelined request, left for
    /// the next read). Plain TCP watches; other transports never complete.
    async fn peer_closed(&self) {
        std::future::pending::<()>().await
    }

    /// The keep-alive wait for the next request, which may also read its
    /// first bytes into `buf` (from offset 0). By default the readiness
    /// wait of `idle_wait`, after which the caller reads.
    async fn idle_read(
        &mut self,
        buf: Vec<u8>,
        state: &RuntimeState,
        idle: Option<Duration>,
        fresh: bool,
        timers: &mut ConnTimers<'_>,
    ) -> (IdleRead, Vec<u8>) {
        let next = if self.idle_wait(state, idle, fresh, timers).await {
            IdleRead::Ready
        } else {
            IdleRead::Close
        };
        (next, buf)
    }
}

/// How a keep-alive wait ended.
pub enum IdleRead {
    /// Drop the connection (timeout, shutdown, reload, a slot needed, EOF).
    Close,
    /// A request may be there: read it.
    Ready,
    /// This many bytes of the next request are already in the buffer.
    Read(usize),
}

impl ConnIo for TcpStream {
    /// The read itself instead of a readiness poll and then a read: one
    /// io_uring operation per keep-alive request instead of two (#145),
    /// like nginx's `c->recv` on a read event.
    async fn idle_read(
        &mut self,
        buf: Vec<u8>,
        state: &RuntimeState,
        idle: Option<Duration>,
        fresh: bool,
        timers: &mut ConnTimers<'_>,
    ) -> (IdleRead, Vec<u8>) {
        use monoio::buf::IoBufMut;
        let len = buf.len();
        let (next, buf) =
            read_first_or_shutdown(self, buf.slice_mut(0..len), state, idle, fresh, timers).await;
        (next, buf.map_or_else(Vec::new, |b| b.into_inner()))
    }

    async fn idle_wait(
        &self,
        state: &RuntimeState,
        idle: Option<Duration>,
        fresh: bool,
        timers: &mut ConnTimers<'_>,
    ) -> bool {
        wait_readable_or_shutdown(self, state, idle, fresh, timers).await
    }

    fn sendfile_fd(&self) -> Option<std::os::unix::io::RawFd> {
        use std::os::unix::io::AsRawFd;
        Some(self.as_raw_fd())
    }

    async fn wait_writable(&self) -> std::io::Result<()> {
        self.writable(false).await
    }

    async fn peer_closed(&self) {
        use std::os::unix::io::AsRawFd;
        loop {
            if self.readable(false).await.is_err() {
                return;
            }
            let mut byte = 0u8;
            // SAFETY: a one-byte peek into our own buffer; MSG_DONTWAIT
            // keeps it from blocking whatever the socket's mode.
            let n = unsafe {
                libc::recv(
                    self.as_raw_fd(),
                    (&raw mut byte).cast(),
                    1,
                    libc::MSG_PEEK | libc::MSG_DONTWAIT,
                )
            };
            match n {
                0 => return,
                // Bytes of a next request: no EOF to see behind them.
                1.. => std::future::pending::<()>().await,
                _ if std::io::Error::last_os_error().kind() == std::io::ErrorKind::WouldBlock => {}
                // A reset or another error: the client is gone too.
                _ => return,
            }
        }
    }
}

impl ConnIo for crate::tls::ServerTlsStream<TcpStream> {
    /// The socket read itself, of ciphertext into the stream's own buffer,
    /// instead of a readiness poll and then the read (#145), as plain TCP
    /// does; `Ready` then, and the request read decrypts what came.
    async fn idle_read(
        &mut self,
        buf: Vec<u8>,
        state: &RuntimeState,
        idle: Option<Duration>,
        fresh: bool,
        timers: &mut ConnTimers<'_>,
    ) -> (IdleRead, Vec<u8>) {
        if self.has_buffered_input() {
            let next = if fresh || !state.is_shutting_down() {
                IdleRead::Ready
            } else {
                IdleRead::Close
            };
            return (next, buf);
        }
        let ciphertext = self.take_read_buf();
        let (next, ciphertext) =
            read_first_or_shutdown(self.io_mut(), ciphertext, state, idle, fresh, timers).await;
        // A dropped read took the buffer: the next read allocates one.
        self.put_read_buf(ciphertext.unwrap_or_default());
        let next = match next {
            IdleRead::Read(_) => IdleRead::Ready,
            other => other,
        };
        (next, buf)
    }

    async fn idle_wait(
        &self,
        state: &RuntimeState,
        idle: Option<Duration>,
        fresh: bool,
        timers: &mut ConnTimers<'_>,
    ) -> bool {
        if self.has_buffered_input() {
            return fresh || !state.is_shutting_down();
        }
        wait_readable_or_shutdown(self.io(), state, idle, fresh, timers).await
    }

    fn sendfile_fd(&self) -> Option<std::os::unix::io::RawFd> {
        None
    }

    async fn wait_writable(&self) -> std::io::Result<()> {
        Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
    }

    fn begin_tunnel(&mut self) {
        crate::tls_stream::TlsStream::begin_tunnel(self);
    }
}

/// A plain TCP connection whose first bytes are already read: plain HTTP
/// sent to an `ssl` port, read by the TLS acceptor (#384). Those bytes
/// come first, then the socket's.
pub(crate) struct Preread {
    io: TcpStream,
    read: Vec<u8>,
    pos: usize,
}

impl Preread {
    pub(crate) fn new(io: TcpStream, read: Vec<u8>) -> Self {
        Preread { io, read, pos: 0 }
    }

    fn has_pending(&self) -> bool {
        self.pos < self.read.len()
    }

    /// Copy what is left of the read bytes to `dst`, as far as it fits.
    ///
    /// # Safety
    /// `dst` is valid for writes of `len` bytes.
    unsafe fn take_into(&mut self, dst: *mut u8, len: usize) -> usize {
        let n = (self.read.len() - self.pos).min(len);
        // SAFETY: `n` bytes from our own buffer into `dst`, which the
        // caller vouches for; the two can't overlap.
        unsafe { std::ptr::copy_nonoverlapping(self.read.as_ptr().add(self.pos), dst, n) };
        self.pos += n;
        n
    }
}

impl AsyncReadRent for Preread {
    async fn read<T: IoBufMut>(&mut self, mut buf: T) -> monoio::BufResult<usize, T> {
        if !self.has_pending() {
            return self.io.read(buf).await;
        }
        // SAFETY: `write_ptr` is valid for `bytes_total` bytes, and the
        // first `n` are initialized once copied.
        unsafe {
            let n = self.take_into(buf.write_ptr(), buf.bytes_total());
            buf.set_init(n);
            (Ok(n), buf)
        }
    }

    async fn readv<T: monoio::buf::IoVecBufMut>(
        &mut self,
        mut buf: T,
    ) -> monoio::BufResult<usize, T> {
        if !self.has_pending() {
            return self.io.readv(buf).await;
        }
        // The first iovec only: a short read, which callers handle.
        // SAFETY: `buf` is owned here and outlives `raw`.
        let res = match unsafe { monoio::buf::RawBuf::new_from_iovec_mut(&mut buf) } {
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

impl AsyncWriteRent for Preread {
    async fn write<T: IoBuf>(&mut self, buf: T) -> monoio::BufResult<usize, T> {
        self.io.write(buf).await
    }

    async fn writev<T: monoio::buf::IoVecBuf>(&mut self, buf: T) -> monoio::BufResult<usize, T> {
        self.io.writev(buf).await
    }

    async fn flush(&mut self) -> std::io::Result<()> {
        self.io.flush().await
    }

    async fn shutdown(&mut self) -> std::io::Result<()> {
        self.io.shutdown().await
    }
}

impl ConnIo for Preread {
    async fn idle_read(
        &mut self,
        mut buf: Vec<u8>,
        state: &RuntimeState,
        idle: Option<Duration>,
        fresh: bool,
        timers: &mut ConnTimers<'_>,
    ) -> (IdleRead, Vec<u8>) {
        if !self.has_pending() {
            use monoio::buf::IoBufMut;
            let len = buf.len();
            let (next, buf) = read_first_or_shutdown(
                &mut self.io,
                buf.slice_mut(0..len),
                state,
                idle,
                fresh,
                timers,
            )
            .await;
            return (next, buf.map_or_else(Vec::new, |b| b.into_inner()));
        }
        // As `read_first_or_shutdown`: into `buf[..buf.len()]`.
        // SAFETY: `buf` holds `len` initialized bytes to overwrite.
        let n = unsafe { self.take_into(buf.as_mut_ptr(), buf.len()) };
        (IdleRead::Read(n), buf)
    }

    async fn idle_wait(
        &self,
        state: &RuntimeState,
        idle: Option<Duration>,
        fresh: bool,
        timers: &mut ConnTimers<'_>,
    ) -> bool {
        if self.has_pending() {
            return fresh || !state.is_shutting_down();
        }
        wait_readable_or_shutdown(&self.io, state, idle, fresh, timers).await
    }

    fn sendfile_fd(&self) -> Option<std::os::unix::io::RawFd> {
        use std::os::unix::io::AsRawFd;
        Some(self.io.as_raw_fd())
    }

    async fn wait_writable(&self) -> std::io::Result<()> {
        self.io.writable(false).await
    }
}

/// Upper bound for one `sendfile(2)` call, matching nginx's
/// `sendfile_max_chunk` default (2m since 1.21.4).
const SENDFILE_MAX_CHUNK: usize = 2 * 1024 * 1024;

/// `sendfile on` path for plain TCP: write the response header block, then
/// the file range with `sendfile(2)`, so the body never passes through user
/// space (nginx's `ngx_linux_sendfile_chain`).
///
/// The socket is switched to `O_NONBLOCK` on first use (`nonblocking`
/// remembers that per connection). io_uring ops on the same socket behave
/// the same either way — the kernel arms an internal poll on EAGAIN — so
/// only the direct `send` / `sendfile` calls here see the flag, and they
/// wait for writability instead of blocking the worker.
///
/// Fails on any write error or if the file is shorter than the
/// `Content-Length` already promised, with the bytes that went out (head
/// and file); the caller logs the request and drops the connection.
pub(crate) async fn send_head_and_file<S: ConnIo>(
    stream: &S,
    nonblocking: &mut bool,
    head: &[u8],
    body: phase::FileBody,
    mut timer: std::pin::Pin<&mut monoio::time::Sleep>,
    send_timeout: Duration,
) -> Result<(), u64> {
    use std::os::unix::io::AsRawFd;
    let Some(sock) = stream.sendfile_fd() else {
        return Err(0);
    };
    if !*nonblocking {
        // SAFETY: fcntl on an fd we own for the connection's lifetime.
        let flags = unsafe { libc::fcntl(sock, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(sock, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(0);
        }
        *nonblocking = true;
    }

    // MSG_MORE holds the header back so the kernel coalesces it with the
    // first file pages instead of pushing a short segment on its own (nginx
    // gets the same effect from `tcp_nopush` + sendfile).
    let mut sent = 0usize;
    while sent < head.len() {
        // SAFETY: the pointer/len pair stays within `head`.
        let n = unsafe {
            libc::send(
                sock,
                head[sent..].as_ptr().cast(),
                head.len() - sent,
                libc::MSG_MORE | libc::MSG_NOSIGNAL,
            )
        };
        if n >= 0 {
            sent += n as usize;
            continue;
        }
        match std::io::Error::last_os_error().kind() {
            std::io::ErrorKind::WouldBlock => {
                // `send_timeout` bounds each wait for the socket to drain,
                // like nginx's timer between two successive sends.
                let ready = with_timeout(timer.as_mut(), send_timeout, stream.wait_writable());
                if !matches!(ready.await, Some(Ok(_))) {
                    return Err(sent as u64);
                }
            }
            std::io::ErrorKind::Interrupted => {}
            _ => return Err(sent as u64),
        }
    }

    let file = body.fd.as_raw_fd();
    let mut offset = body.offset as libc::off_t;
    let end = offset + body.len as libc::off_t;
    while offset < end {
        let chunk = ((end - offset) as usize).min(SENDFILE_MAX_CHUNK);
        // SAFETY: both fds are open; the kernel advances `offset`.
        let n = unsafe { libc::sendfile(sock, file, &mut offset, chunk) };
        if n > 0 {
            continue;
        }
        if n == 0 {
            // File shrank below the Content-Length we already sent.
            return Err(sent as u64 + (offset as u64 - body.offset));
        }
        match std::io::Error::last_os_error().kind() {
            std::io::ErrorKind::WouldBlock => {
                // `send_timeout` bounds each wait for the socket to drain,
                // like nginx's timer between two successive sends.
                let ready = with_timeout(timer.as_mut(), send_timeout, stream.wait_writable());
                if !matches!(ready.await, Some(Ok(_))) {
                    return Err(sent as u64 + (offset as u64 - body.offset));
                }
            }
            std::io::ErrorKind::Interrupted => {}
            _ => return Err(sent as u64 + (offset as u64 - body.offset)),
        }
    }
    Ok(())
}

/// A connection's long-lived timers. monoio extends a registered timer
/// lazily when it is moved to a later deadline, so re-arming one of these
/// costs a clock read, where a fresh `sleep`/`timeout` per operation costs
/// a timer-wheel insert and remove. `io` is only ever moved forward on the
/// hot path, by the same client timeouts; `idle` is moved only when it
/// fires before the keep-alive deadline (`arm_idle`). Shutdown, reload and
/// drains wake idle connections directly (#127), so there is no tick.
pub(crate) struct ConnTimers<'a> {
    /// client_header_timeout / client_body_timeout / send_timeout.
    pub io: std::pin::Pin<&'a mut monoio::time::Sleep>,
    /// The keep-alive (or first-request) deadline while idle.
    pub idle: std::pin::Pin<&'a mut monoio::time::Sleep>,
}

/// Run `fut` unless `deadline` passes first, using `timer` (see
/// `ConnTimers`). The operation is polled first, and the timer is armed
/// only once it has to wait: most reads and writes complete on the first
/// poll, and they then cost neither a clock read nor a timer update.
pub(crate) fn with_deadline<F: std::future::Future>(
    timer: std::pin::Pin<&mut monoio::time::Sleep>,
    deadline: monoio::time::Instant,
    fut: F,
) -> Timed<'_, F, impl FnOnce() -> monoio::time::Instant> {
    Timed {
        timer,
        deadline: Some(move || deadline),
        due: None,
        fut,
    }
}

/// `monoio::time::timeout` for an upstream operation, that reads the clock
/// and touches the timer wheel only once `fut` has to wait: a write that
/// the socket takes at once (the request to an upstream, most of the
/// time) costs neither. The timeout runs from that first wait, as nginx
/// arms its timer when a send or read would block.
pub(crate) fn lazy_timeout<F: std::future::Future>(dur: Duration, fut: F) -> LazyTimeout<F> {
    LazyTimeout {
        fut,
        dur,
        sleep: None,
    }
}

/// The future of `lazy_timeout`.
pub(crate) struct LazyTimeout<F> {
    fut: F,
    dur: Duration,
    /// Armed on the first `Pending`.
    sleep: Option<monoio::time::Sleep>,
}

/// `lazy_timeout`'s operation took longer than its duration.
#[derive(Debug)]
pub(crate) struct Elapsed;

impl<F: std::future::Future> std::future::Future for LazyTimeout<F> {
    type Output = Result<F::Output, Elapsed>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        use std::task::Poll;
        // SAFETY: neither field is moved out of the pinned struct; `sleep`
        // is only ever set once, in place.
        let this = unsafe { self.get_unchecked_mut() };
        let fut = unsafe { std::pin::Pin::new_unchecked(&mut this.fut) };
        if let Poll::Ready(out) = fut.poll(cx) {
            return Poll::Ready(Ok(out));
        }
        let dur = this.dur;
        let sleep = this.sleep.get_or_insert_with(|| monoio::time::sleep(dur));
        // SAFETY: as above.
        match unsafe { std::pin::Pin::new_unchecked(sleep) }.poll(cx) {
            Poll::Ready(()) => Poll::Ready(Err(Elapsed)),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// `with_deadline` for a timeout that starts when the operation first
/// waits, as nginx arms its timer when a read or send would block.
pub(crate) fn with_timeout<F: std::future::Future>(
    timer: std::pin::Pin<&mut monoio::time::Sleep>,
    timeout: Duration,
    fut: F,
) -> Timed<'_, F, impl FnOnce() -> monoio::time::Instant> {
    Timed {
        timer,
        deadline: Some(move || monoio::time::Instant::now() + timeout),
        due: None,
        fut,
    }
}

/// The future of `with_deadline` / `with_timeout`: `None` when the timer
/// fires first.
pub(crate) struct Timed<'t, F, D> {
    timer: std::pin::Pin<&'t mut monoio::time::Sleep>,
    /// Taken when the timer is armed, on the first `Pending`.
    deadline: Option<D>,
    /// The operation's own deadline, once armed: the timer may be due a
    /// little earlier (kept from the previous operation).
    due: Option<monoio::time::Instant>,
    fut: F,
}

/// How much earlier than an operation's deadline the connection's timer
/// may stay set, rather than being moved for every read and write.
const TIMER_SLACK: Duration = Duration::from_secs(1);

impl<F, D> std::future::Future for Timed<'_, F, D>
where
    F: std::future::Future,
    D: FnOnce() -> monoio::time::Instant,
{
    type Output = Option<F::Output>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        use std::task::Poll;
        // SAFETY: `fut` is structurally pinned: it is never moved out of
        // `self`, and `Timed` has no `Drop` impl or `Unpin` impl of its own.
        let this = unsafe { self.get_unchecked_mut() };
        let fut = unsafe { std::pin::Pin::new_unchecked(&mut this.fut) };
        if let Poll::Ready(out) = fut.poll(cx) {
            return Poll::Ready(Some(out));
        }
        if let Some(deadline) = this.deadline.take() {
            let due = deadline();
            this.due = Some(due);
            let set = this.timer.deadline();
            if !this.timer.is_elapsed() && set <= due && set + TIMER_SLACK >= due {
                // Still set (and polled by this connection) for a moment
                // before `due`: an early fire is re-armed below.
                return Poll::Pending;
            }
            this.timer.as_mut().reset(due);
        }
        if this.timer.as_mut().poll(cx).is_ready() {
            match this.due {
                Some(due) if monoio::time::Instant::now() < due => {
                    this.timer.as_mut().reset(due);
                    if this.timer.as_mut().poll(cx).is_ready() {
                        return Poll::Ready(None);
                    }
                }
                _ => return Poll::Ready(None),
            }
        }
        Poll::Pending
    }
}

/// `write_all_timed`, but on plain TCP the bytes go out at once with
/// `send(MSG_DONTWAIT)`, while they are still in the cache from being
/// read; it waits for writability only when the socket is full (#247).
/// An io_uring write would run at the next submit, after other
/// connections' reads have pushed them out. TLS and HTTP/2 use the
/// io_uring write.
pub(crate) async fn write_all_now<S: ConnIo>(
    stream: &mut S,
    buf: Vec<u8>,
    len: usize,
    mut timer: std::pin::Pin<&mut monoio::time::Sleep>,
    timeout: Duration,
) -> (Result<(), usize>, Vec<u8>) {
    let Some(sock) = stream.sendfile_fd() else {
        return write_all_timed(stream, buf, len, timer, timeout).await;
    };
    let mut sent = 0usize;
    while sent < len {
        // SAFETY: the pointer/len pair stays within `buf[..len]`.
        let r = unsafe {
            libc::send(
                sock,
                buf[sent..len].as_ptr().cast(),
                len - sent,
                libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
            )
        };
        if r > 0 {
            sent += r as usize;
            continue;
        }
        if r == 0 {
            return (Err(sent), buf);
        }
        match std::io::Error::last_os_error().kind() {
            std::io::ErrorKind::WouldBlock => {
                let ready = with_timeout(timer.as_mut(), timeout, stream.wait_writable());
                if !matches!(ready.await, Some(Ok(_))) {
                    return (Err(sent), buf);
                }
            }
            std::io::ErrorKind::Interrupted => {}
            _ => return (Err(sent), buf),
        }
    }
    (Ok(()), buf)
}

/// `write_all` with nginx's `send_timeout`: the connection is given up
/// when one write makes no progress for `timeout`. nginx re-arms the timer
/// after every partial send, so a slow but steady client may take longer
/// than `timeout` in total. Writes `buf[..len]`; on a timeout the buffer
/// is dropped with the write and an empty one comes back. A write that
/// fails says how many bytes went out (nginx's `c->sent`, for the log).
pub(crate) async fn write_all_timed<S: monoio::io::AsyncWriteRent>(
    stream: &mut S,
    mut buf: Vec<u8>,
    len: usize,
    mut timer: std::pin::Pin<&mut monoio::time::Sleep>,
    timeout: Duration,
) -> (Result<(), usize>, Vec<u8>) {
    let mut written = 0;
    while written < len {
        let slice = buf.slice(written..len);
        let Some((res, slice)) = with_timeout(timer.as_mut(), timeout, stream.write(slice)).await
        else {
            return (Err(written), Vec::new());
        };
        buf = slice.into_inner();
        match res {
            Ok(n) if n > 0 => written += n,
            _ => return (Err(written), buf),
        }
    }
    (Ok(()), buf)
}

/// nginx's lingering close (`ngx_http_set_lingering_close`): after an
/// early answer the client may still be sending the request body, and
/// closing a socket with unread input makes the kernel reset the
/// connection — the client can then lose the response. Stop writing, read
/// and discard until the client is done (EOF), at most `lingering_timeout`
/// (5 s) per read and `lingering_time` (30 s) in total, then close.
pub(crate) async fn lingering_close<S: ConnIo>(stream: &mut S, buf: &mut Vec<u8>) {
    const LINGERING_TIME: Duration = Duration::from_secs(30);
    const LINGERING_TIMEOUT: Duration = Duration::from_secs(5);
    let _ = monoio::io::AsyncWriteRent::shutdown(stream).await;
    let deadline = Instant::now() + LINGERING_TIME;
    let mut scratch = std::mem::take(buf);
    scratch.clear();
    scratch.reserve(16 * 1024);
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        match monoio::time::timeout(left.min(LINGERING_TIMEOUT), stream.read(scratch)).await {
            Ok((Ok(n), returned)) if n > 0 => {
                scratch = returned;
                scratch.clear();
            }
            Ok((_, returned)) => {
                scratch = returned;
                break;
            }
            // Timed out: the buffer went with the read.
            Err(_) => {
                scratch = Vec::new();
                break;
            }
        }
    }
    scratch.clear();
    *buf = scratch;
}

/// nginx's `limit_rate` pacing (`ngx_http_write_filter`): past
/// `limit_rate_after` bytes the response may have sent at most
/// `rate * (elapsed + 1 s)` more, so writes wait for that.
pub(crate) struct Pacer {
    rate: u64,
    after: u64,
    start: Instant,
    sent: u64,
}

impl Pacer {
    /// `None` for an unlimited response (rate 0), the common case.
    pub(crate) fn new(rate: u64, after: u64, start: Instant) -> Option<Pacer> {
        (rate > 0).then_some(Pacer {
            rate,
            after,
            start,
            sent: 0,
        })
    }

    /// How many of `want` bytes may go now, or how long to wait first.
    fn next(&self, want: usize) -> Result<usize, Duration> {
        let elapsed_ms = self.start.elapsed().as_millis() as u64;
        let allowed = self
            .after
            .saturating_add(self.rate.saturating_mul(elapsed_ms + 1000) / 1000);
        if self.sent < allowed {
            // Small writes keep the pace even, as nginx's `limit`.
            let step = self.rate.clamp(1, 64 * 1024);
            return Ok(((allowed - self.sent).min(step) as usize).min(want));
        }
        let over = self.sent - allowed + 1;
        let wait_ms = (over.saturating_mul(1000)).div_ceil(self.rate).max(1);
        Err(Duration::from_millis(wait_ms))
    }
}

/// `write_all_timed` under `limit_rate`. A client that closes while the
/// response waits for its next write ends it then, not at that write
/// (`ConnIo::peer_closed`).
pub(crate) async fn write_all_paced<S: ConnIo>(
    stream: &mut S,
    mut buf: Vec<u8>,
    len: usize,
    pacer: &mut Pacer,
    mut timer: std::pin::Pin<&mut monoio::time::Sleep>,
    timeout: Duration,
) -> (Result<(), usize>, Vec<u8>) {
    let mut written = 0;
    while written < len {
        let n = match pacer.next(len - written) {
            Ok(n) => n,
            Err(wait) => {
                let closed = monoio::select! {
                    _ = monoio::time::sleep(wait) => false,
                    _ = stream.peer_closed() => true,
                };
                if closed {
                    return (Err(written), buf);
                }
                continue;
            }
        };
        let slice = buf.slice(written..written + n);
        let Some((res, slice)) = with_timeout(timer.as_mut(), timeout, stream.write(slice)).await
        else {
            return (Err(written), Vec::new());
        };
        buf = slice.into_inner();
        match res {
            Ok(n) if n > 0 => {
                written += n;
                pacer.sent += n as u64;
            }
            _ => return (Err(written), buf),
        }
    }
    (Ok(()), buf)
}

/// Fails with the body bytes that went out.
pub(crate) async fn stream_file<S: ConnIo>(
    stream: &mut S,
    body: phase::FileBody,
    mut timer: std::pin::Pin<&mut monoio::time::Sleep>,
    send_timeout: Duration,
    mut pacer: Option<&mut Pacer>,
) -> Result<(), u64> {
    // The fd is owned by `body` and was already opened + contained by the
    // resolver; wrap it into `std::fs::File` so we get Seek/Read without
    // duplicating the fd. Dropping `file` at the end closes the fd.
    // Positional reads: the fd may be a `dup` of an `alias` file's anchor,
    // whose file offset is shared with every other dup of it.
    use std::os::unix::fs::FileExt;
    let file = std::fs::File::from(body.fd);
    let mut offset = body.offset;
    let mut remaining = body.len;
    let chunk = body.len.clamp(1, 65_536) as usize;
    let mut buf: Vec<u8> = vec![0u8; chunk];
    while remaining > 0 {
        let want = remaining.min(buf.len() as u64) as usize;
        let n = match file.read_at(&mut buf[..want], offset) {
            Ok(0) | Err(_) => return Err(body.len - remaining),
            Ok(n) => n,
        };
        offset += n as u64;
        let (res, returned) = match pacer.as_deref_mut() {
            Some(pacer) => {
                write_all_paced(
                    stream,
                    std::mem::take(&mut buf),
                    n,
                    pacer,
                    timer.as_mut(),
                    send_timeout,
                )
                .await
            }
            // Plain TCP: at once, while the chunk is still in the cache
            // (`write_all_now`, #247).
            None => {
                write_all_now(
                    stream,
                    std::mem::take(&mut buf),
                    n,
                    timer.as_mut(),
                    send_timeout,
                )
                .await
            }
        };
        buf = returned;
        if let Err(n) = res {
            return Err(body.len - remaining + n as u64);
        }
        remaining -= n as u64;
    }
    Ok(())
}

/// `stream_file` through the gzip filter: the file is read in 64 KiB
/// blocks, compressed, and sent as HTTP/1.1 chunks (or raw for HTTP/1.0,
/// where the connection closes after). Returns the bytes written, or
/// those that went out before an error or a file shorter than its stat
/// said.
pub(crate) async fn stream_file_gzip<S: monoio::io::AsyncWriteRent>(
    stream: &mut S,
    body: phase::FileBody,
    gzip: super::gzip::GzipStream,
    mut timer: std::pin::Pin<&mut monoio::time::Sleep>,
    send_timeout: Duration,
) -> Result<u64, u64> {
    use std::os::unix::fs::FileExt;
    let file = std::fs::File::from(body.fd);
    let mut deflater = super::gzip::Deflater::new(gzip);
    let mut offset = body.offset;
    let mut remaining = body.len;
    let block = body.len.clamp(1, 65_536) as usize;
    // Pooled buffers (see `gzip::BUFFER_POOL`): grown once, kept.
    let mut input = std::mem::take(&mut deflater.input);
    if input.len() < block {
        input.resize(block, 0);
    }
    // Room for the chunk-size line in front of the compressed bytes.
    const PREFIX: usize = 10;
    let mut out = std::mem::take(&mut deflater.out);
    out.reserve(PREFIX + block.min(16_384));
    let mut sent = 0u64;
    let result = loop {
        let n = if remaining == 0 {
            0
        } else {
            let want = remaining.min(block as u64) as usize;
            match file.read_at(&mut input[..want], offset) {
                Ok(0) | Err(_) => break Err(sent),
                Ok(n) => n,
            }
        };
        offset += n as u64;
        remaining -= n as u64;
        out.clear();
        out.resize(PREFIX, 0);
        deflater.push(&input[..n], &mut out, remaining == 0);
        let data_len = out.len() - PREFIX;
        let start = if gzip.chunked && data_len > 0 {
            // "<hex>\r\n" right before the data, "\r\n" after it.
            let digits = (usize::BITS - data_len.leading_zeros()).div_ceil(4).max(1) as usize;
            let start = PREFIX - (digits + 2);
            for i in 0..digits {
                let nibble = (data_len >> (4 * (digits - 1 - i))) & 0xf;
                out[start + i] = b"0123456789abcdef"[nibble];
            }
            out[PREFIX - 2..PREFIX].copy_from_slice(b"\r\n");
            out.extend_from_slice(b"\r\n");
            start
        } else {
            PREFIX
        };
        if remaining == 0 && gzip.chunked {
            out.extend_from_slice(b"0\r\n\r\n");
        }
        if out.len() > start {
            // Shift so the write starts at the chunk line (a few KiB).
            out.drain(..start);
            let len = out.len();
            let (res, returned) = write_all_timed(
                stream,
                std::mem::take(&mut out),
                len,
                timer.as_mut(),
                send_timeout,
            )
            .await;
            out = returned;
            if let Err(n) = res {
                break Err(sent + n as u64);
            }
            sent += len as u64;
        }
        if remaining == 0 {
            break Ok(sent);
        }
    };
    deflater.input = input;
    deflater.out = out;
    result
}

/// Outcome of decoding a chunked request body.
pub(crate) struct ChunkedBody {
    /// Bytes consumed from the caller's `initial` buffer (the slice we
    /// were handed at body-start). Used to advance `read_start` for the
    /// keep-alive resumption path.
    pub(crate) consumed_initial: usize,
    /// Total raw chunked bytes — chunk sizes, data, CRLFs, trailers — for
    /// `$request_length` accounting.
    pub(crate) raw_consumed: u64,
    /// Bytes that were read from the socket past the chunked terminator.
    /// These belong to the next pipelined request and are spliced back
    /// into the worker's read buffer by the caller.
    pub(crate) pipelined_tail: Vec<u8>,
}

/// Why a chunked body was refused.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ChunkedBodyError {
    /// Over the size limit: 413, as nginx.
    TooLarge,
    /// Malformed framing, a line or trailer block too long, EOF, a read
    /// error or timeout, or a failed temp-file write: 400.
    Invalid,
}

/// Maximum length of any single chunk-size or trailer line, including the
/// terminating CRLF. nginx caps the chunk size line at
/// `NGX_HTTP_PARSE_LARGE_CLIENT_HEADER` (8 KiB by default); we use the
/// same. Without this cap a peer can withhold the CRLF and force `raw`
/// to grow unboundedly.
pub(crate) const MAX_CHUNK_LINE_BYTES: usize = 8192;

/// Maximum trailer block size in bytes. Bounds total trailer-line growth.
pub(crate) const MAX_TRAILER_BLOCK_BYTES: usize = 16 * 1024;

/// Read `len` more bytes of a body nothing will read and drop them, through
/// one small pooled buffer (nginx's ngx_http_read_discarded_request_body):
/// no body-sized buffer is held per request (#289). `false` on EOF, an
/// error or `client_body_timeout`.
pub(crate) async fn discard_request_body<S: ConnIo>(
    stream: &mut S,
    mut len: u64,
    mut timer: std::pin::Pin<&mut monoio::time::Sleep>,
    read_timeout: Duration,
) -> bool {
    use monoio::buf::IoBufMut;
    const DISCARD_CHUNK: usize = 16 * 1024;
    if len == 0 {
        return true;
    }
    let mut buf = super::take_body_buffer(DISCARD_CHUNK);
    let ok = loop {
        // Never past the body, so a pipelined request isn't consumed.
        let want = len.min(DISCARD_CHUNK as u64) as usize;
        let slice = std::mem::take(&mut buf).slice_mut(0..want);
        let Some((res, returned)) =
            with_timeout(timer.as_mut(), read_timeout, stream.read(slice)).await
        else {
            break false;
        };
        buf = returned.into_inner();
        match res {
            Ok(0) | Err(_) => break false,
            Ok(n) => {
                len -= n as u64;
                if len == 0 {
                    break true;
                }
            }
        }
    };
    drop(super::PooledBody(buf));
    ok
}

/// Read and decode a chunked request body from the connection into `sink`
/// (memory, then a temp file for large bodies). Chunk data is passed on as
/// it arrives and consumed input is dropped, so memory stays bounded
/// whatever the chunk sizes.
pub(crate) async fn read_chunked_request_body<S: AsyncReadRent>(
    stream: &mut S,
    initial: &[u8],
    max_body: u64,
    sink: &mut BodySink<'_>,
    mut timer: std::pin::Pin<&mut monoio::time::Sleep>,
    read_timeout: Duration,
) -> Result<ChunkedBody, ChunkedBodyError> {
    use ChunkedBodyError::{Invalid, TooLarge};

    // `raw[cursor..]` is unread input; `raw_base` is how many stream bytes
    // (counted from `initial[0]`) were dropped from the front of `raw`.
    let mut raw = Vec::with_capacity(initial.len().saturating_add(128));
    raw.extend_from_slice(initial);
    let mut raw_base: u64 = 0;
    let mut cursor: usize = 0;
    let mut trailer_bytes: usize = 0;

    // Drop consumed input, then read more after what's left.
    macro_rules! read_more {
        ($cap:expr) => {{
            if cursor > 0 {
                raw.drain(..cursor);
                raw_base += cursor as u64;
                cursor = 0;
            }
            let chunk: Vec<u8> = vec![0u8; $cap];
            let (res, returned) = with_timeout(timer.as_mut(), read_timeout, stream.read(chunk))
                .await
                .ok_or(Invalid)?;
            match res {
                Ok(0) | Err(_) => return Err(Invalid),
                Ok(n) => raw.extend_from_slice(&returned[..n]),
            }
        }};
    }

    // The next CRLF-terminated line (chunk size or trailer), excluding the
    // CRLF, as an index past `cursor`.
    macro_rules! line_end {
        ($cap:expr) => {{
            loop {
                if let Some(pos) = raw[cursor..].windows(2).position(|w| w == b"\r\n") {
                    break cursor + pos;
                }
                if raw.len() - cursor > MAX_CHUNK_LINE_BYTES {
                    return Err(Invalid);
                }
                read_more!($cap);
            }
        }};
    }

    loop {
        let end = line_end!(4096);
        if end - cursor > MAX_CHUNK_LINE_BYTES {
            return Err(Invalid);
        }
        let chunk_len = http::parse_chunk_size(&raw[cursor..end]).ok_or(Invalid)?;
        cursor = end + 2;

        if chunk_len == 0 {
            // Trailers: zero or more header-style lines, then an empty line.
            loop {
                let end = line_end!(1024);
                let trailer_len = end - cursor;
                trailer_bytes = trailer_bytes.saturating_add(trailer_len + 2);
                if trailer_bytes > MAX_TRAILER_BLOCK_BYTES {
                    return Err(Invalid);
                }
                cursor = end + 2;
                if trailer_len == 0 {
                    let consumed = raw_base + cursor as u64;
                    let consumed_initial = consumed.min(initial.len() as u64) as usize;
                    // Bytes past the chunked terminator belong to the next
                    // pipelined request. If the terminator landed within
                    // `initial`, those bytes are still in the worker's read
                    // buffer at their original position — leave them there.
                    // If we read past `initial` from the socket, hand the
                    // over-read back to the caller so it can splice them
                    // into the next-request slot.
                    let pipelined_tail = if consumed > initial.len() as u64 {
                        raw[cursor..].to_vec()
                    } else {
                        Vec::new()
                    };
                    return Ok(ChunkedBody {
                        consumed_initial,
                        raw_consumed: consumed,
                        pipelined_tail,
                    });
                }
            }
        }

        if chunk_len > max_body.saturating_sub(sink.len()) {
            return Err(TooLarge);
        }
        // Pass the chunk on as it arrives instead of buffering all of it.
        let mut left = chunk_len;
        while left > 0 {
            if cursor == raw.len() {
                read_more!((left.min(64 * 1024)) as usize);
            }
            let take = (left.min((raw.len() - cursor) as u64)) as usize;
            if !sink.extend(&raw[cursor..cursor + take]) {
                return Err(Invalid);
            }
            cursor += take;
            left -= take as u64;
        }
        while raw.len() - cursor < 2 {
            read_more!(64);
        }
        if raw[cursor..cursor + 2] != *b"\r\n" {
            return Err(Invalid);
        }
        cursor += 2;
    }
}
