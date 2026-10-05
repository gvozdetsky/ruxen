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
        start_reload_gen: u64,
        timers: &mut ConnTimers<'_>,
    ) -> bool;

    /// Raw socket fd for the zero-copy `sendfile` path, or `None` when the
    /// transport has to see the bytes (TLS).
    fn sendfile_fd(&self) -> Option<std::os::unix::io::RawFd>;

    /// Wait until the socket accepts more data. Only used by the zero-copy
    /// path, which writes to the fd directly.
    async fn wait_writable(&self) -> std::io::Result<()>;
}

impl ConnIo for TcpStream {
    async fn idle_wait(
        &self,
        state: &RuntimeState,
        idle: Option<Duration>,
        start_reload_gen: u64,
        timers: &mut ConnTimers<'_>,
    ) -> bool {
        wait_readable_or_shutdown(self, state, idle, start_reload_gen, timers).await
    }

    fn sendfile_fd(&self) -> Option<std::os::unix::io::RawFd> {
        use std::os::unix::io::AsRawFd;
        Some(self.as_raw_fd())
    }

    async fn wait_writable(&self) -> std::io::Result<()> {
        self.writable(false).await
    }
}

impl ConnIo for crate::tls::ServerTlsStream<TcpStream> {
    async fn idle_wait(
        &self,
        state: &RuntimeState,
        idle: Option<Duration>,
        start_reload_gen: u64,
        timers: &mut ConnTimers<'_>,
    ) -> bool {
        if self.has_buffered_input() {
            return !state.is_shutting_down() && state.reload_gen() == start_reload_gen;
        }
        wait_readable_or_shutdown(self.io(), state, idle, start_reload_gen, timers).await
    }

    fn sendfile_fd(&self) -> Option<std::os::unix::io::RawFd> {
        None
    }

    async fn wait_writable(&self) -> std::io::Result<()> {
        Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
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
/// Returns `false` on any write error or if the file is shorter than the
/// `Content-Length` already promised; the caller drops the connection.
pub(crate) async fn send_head_and_file<S: ConnIo>(
    stream: &S,
    nonblocking: &mut bool,
    head: &[u8],
    body: phase::FileBody,
    mut timer: std::pin::Pin<&mut monoio::time::Sleep>,
    send_timeout: Duration,
) -> bool {
    use std::os::unix::io::AsRawFd;
    let Some(sock) = stream.sendfile_fd() else {
        return false;
    };
    if !*nonblocking {
        // SAFETY: fcntl on an fd we own for the connection's lifetime.
        let flags = unsafe { libc::fcntl(sock, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(sock, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return false;
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
                    return false;
                }
            }
            std::io::ErrorKind::Interrupted => {}
            _ => return false,
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
            return false;
        }
        match std::io::Error::last_os_error().kind() {
            std::io::ErrorKind::WouldBlock => {
                // `send_timeout` bounds each wait for the socket to drain,
                // like nginx's timer between two successive sends.
                let ready = with_timeout(timer.as_mut(), send_timeout, stream.wait_writable());
                if !matches!(ready.await, Some(Ok(_))) {
                    return false;
                }
            }
            std::io::ErrorKind::Interrupted => {}
            _ => return false,
        }
    }
    true
}

/// A connection's long-lived timers. monoio extends a registered timer
/// lazily when it is moved to a later deadline, so re-arming one of these
/// costs a clock read, where a fresh `sleep`/`timeout` per operation costs
/// a timer-wheel insert and remove. Each is only ever moved forward on the
/// hot path: `io` by the same client timeouts, `idle` by keepalive_timeout,
/// `tick` by 50 ms.
pub(crate) struct ConnTimers<'a> {
    /// client_header_timeout / client_body_timeout / send_timeout.
    pub io: std::pin::Pin<&'a mut monoio::time::Sleep>,
    /// The keep-alive (or first-request) deadline while idle.
    pub idle: std::pin::Pin<&'a mut monoio::time::Sleep>,
    /// The 50 ms poll for shutdown / reload while idle.
    pub tick: std::pin::Pin<&'a mut monoio::time::Sleep>,
}

/// Run `fut` unless `deadline` passes first, using `timer` (see
/// `ConnTimers`). The operation is polled first, so one that is ready
/// never waits on the timer.
pub(crate) async fn with_deadline<F: std::future::Future>(
    mut timer: std::pin::Pin<&mut monoio::time::Sleep>,
    deadline: monoio::time::Instant,
    fut: F,
) -> Option<F::Output> {
    use std::task::Poll;
    timer.as_mut().reset(deadline);
    let mut fut = std::pin::pin!(fut);
    std::future::poll_fn(|cx| {
        if let Poll::Ready(out) = fut.as_mut().poll(cx) {
            return Poll::Ready(Some(out));
        }
        if timer.as_mut().poll(cx).is_ready() {
            return Poll::Ready(None);
        }
        Poll::Pending
    })
    .await
}

/// `with_deadline` for a timeout that starts now.
pub(crate) async fn with_timeout<F: std::future::Future>(
    timer: std::pin::Pin<&mut monoio::time::Sleep>,
    timeout: Duration,
    fut: F,
) -> Option<F::Output> {
    with_deadline(timer, monoio::time::Instant::now() + timeout, fut).await
}

/// `write_all` with nginx's `send_timeout`: the connection is given up
/// when one write makes no progress for `timeout`. nginx re-arms the timer
/// after every partial send, so a slow but steady client may take longer
/// than `timeout` in total. Writes `buf[..len]`; on a timeout the buffer
/// is dropped with the write and an empty one comes back.
pub(crate) async fn write_all_timed<S: monoio::io::AsyncWriteRent>(
    stream: &mut S,
    mut buf: Vec<u8>,
    len: usize,
    mut timer: std::pin::Pin<&mut monoio::time::Sleep>,
    timeout: Duration,
) -> (std::io::Result<()>, Vec<u8>) {
    let mut written = 0;
    while written < len {
        let slice = buf.slice(written..len);
        let Some((res, slice)) = with_timeout(timer.as_mut(), timeout, stream.write(slice)).await
        else {
            return (Err(std::io::ErrorKind::TimedOut.into()), Vec::new());
        };
        buf = slice.into_inner();
        match res {
            Ok(0) => return (Err(std::io::ErrorKind::WriteZero.into()), buf),
            Ok(n) => written += n,
            Err(e) => return (Err(e), buf),
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

    /// Wait until some of `want` bytes may go; returns how many.
    async fn allowance(&mut self, want: usize) -> usize {
        loop {
            let elapsed_ms = self.start.elapsed().as_millis() as u64;
            let allowed = self
                .after
                .saturating_add(self.rate.saturating_mul(elapsed_ms + 1000) / 1000);
            if self.sent < allowed {
                // Small writes keep the pace even, as nginx's `limit`.
                let step = self.rate.clamp(1, 64 * 1024);
                return ((allowed - self.sent).min(step) as usize).min(want);
            }
            let over = self.sent - allowed + 1;
            let wait_ms = (over.saturating_mul(1000)).div_ceil(self.rate).max(1);
            monoio::time::sleep(Duration::from_millis(wait_ms)).await;
        }
    }
}

/// `write_all_timed` under `limit_rate`.
pub(crate) async fn write_all_paced<S: monoio::io::AsyncWriteRent>(
    stream: &mut S,
    mut buf: Vec<u8>,
    len: usize,
    pacer: &mut Pacer,
    mut timer: std::pin::Pin<&mut monoio::time::Sleep>,
    timeout: Duration,
) -> (std::io::Result<()>, Vec<u8>) {
    let mut written = 0;
    while written < len {
        let n = pacer.allowance(len - written).await;
        let slice = buf.slice(written..written + n);
        let Some((res, slice)) = with_timeout(timer.as_mut(), timeout, stream.write(slice)).await
        else {
            return (Err(std::io::ErrorKind::TimedOut.into()), Vec::new());
        };
        buf = slice.into_inner();
        match res {
            Ok(0) => return (Err(std::io::ErrorKind::WriteZero.into()), buf),
            Ok(n) => {
                written += n;
                pacer.sent += n as u64;
            }
            Err(e) => return (Err(e), buf),
        }
    }
    (Ok(()), buf)
}

pub(crate) async fn stream_file<S: monoio::io::AsyncWriteRent>(
    stream: &mut S,
    body: phase::FileBody,
    mut timer: std::pin::Pin<&mut monoio::time::Sleep>,
    send_timeout: Duration,
    mut pacer: Option<&mut Pacer>,
) -> bool {
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
            Ok(0) => return false,
            Ok(n) => n,
            Err(_) => return false,
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
            None => {
                write_all_timed(
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
        if res.is_err() {
            return false;
        }
        remaining -= n as u64;
    }
    true
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

/// Read and decode a chunked request body from the connection into `sink`
/// (memory, then a temp file for large bodies). Chunk data is passed on as
/// it arrives and consumed input is dropped, so memory stays bounded
/// whatever the chunk sizes.
pub(crate) async fn read_chunked_request_body<S: ConnIo>(
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
        let line = &raw[cursor..end];
        let size_field = line.split(|&b| b == b';').next().unwrap_or(line);
        let size_text = std::str::from_utf8(size_field).map_err(|_| Invalid)?.trim();
        if size_text.is_empty() {
            return Err(Invalid);
        }
        let chunk_len = u64::from_str_radix(size_text, 16).map_err(|_| Invalid)?;
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
