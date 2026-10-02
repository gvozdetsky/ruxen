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
    ) -> bool {
        wait_readable_or_shutdown(self, state, idle, start_reload_gen).await
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
    ) -> bool {
        if self.has_buffered_input() {
            return !state.is_shutting_down() && state.reload_gen() == start_reload_gen;
        }
        wait_readable_or_shutdown(self.io(), state, idle, start_reload_gen).await
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
                if stream.wait_writable().await.is_err() {
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
                if stream.wait_writable().await.is_err() {
                    return false;
                }
            }
            std::io::ErrorKind::Interrupted => {}
            _ => return false,
        }
    }
    true
}

pub(crate) async fn stream_file<S: monoio::io::AsyncWriteRent>(
    stream: &mut S,
    body: phase::FileBody,
) -> bool {
    // The fd is owned by `body` and was already opened + contained by the
    // resolver; wrap it into `std::fs::File` so we get Seek/Read without
    // duplicating the fd. Dropping `file` at the end closes the fd.
    let mut file = std::fs::File::from(body.fd);
    if body.offset != 0 && file.seek(SeekFrom::Start(body.offset)).is_err() {
        return false;
    }

    let mut remaining = body.len;
    let chunk = body.len.clamp(1, 65_536) as usize;
    let mut buf: Vec<u8> = vec![0u8; chunk];
    while remaining > 0 {
        let want = remaining.min(buf.len() as u64) as usize;
        let n = match file.read(&mut buf[..want]) {
            Ok(0) => return false,
            Ok(n) => n,
            Err(_) => return false,
        };
        let slice = std::mem::take(&mut buf).slice(..n);
        let (res, returned) = stream.write_all(slice).await;
        buf = returned.into_inner();
        if res.is_err() {
            return false;
        }
        remaining -= n as u64;
    }
    true
}

/// Outcome of decoding a chunked request body.
pub(crate) struct ChunkedBody {
    /// Decoded body bytes.
    pub(crate) body: Vec<u8>,
    /// Bytes consumed from the caller's `initial` buffer (the slice we
    /// were handed at body-start). Used to advance `read_start` for the
    /// keep-alive resumption path.
    pub(crate) consumed_initial: usize,
    /// Total raw chunked bytes — request_line+headers framing plus chunk
    /// sizes, data, CRLFs, trailers — for `$request_length` accounting.
    pub(crate) raw_consumed: usize,
    /// Bytes that were read from the socket past the chunked terminator.
    /// These belong to the next pipelined request and are spliced back
    /// into the worker's read buffer by the caller.
    pub(crate) pipelined_tail: Vec<u8>,
}

/// Maximum length of any single chunk-size or trailer line, including the
/// terminating CRLF. nginx caps the chunk size line at
/// `NGX_HTTP_PARSE_LARGE_CLIENT_HEADER` (8 KiB by default); we use the
/// same. Without this cap a peer can withhold the CRLF and force `raw`
/// to grow unboundedly.
pub(crate) const MAX_CHUNK_LINE_BYTES: usize = 8192;

/// Maximum trailer block size in bytes. Bounds total trailer-line growth.
pub(crate) const MAX_TRAILER_BLOCK_BYTES: usize = 16 * 1024;

/// Read and decode a chunked request body from the connection.
///
/// `None` means malformed framing, body too large, line/trailer too long,
/// or socket EOF/error. The caller responds with 400 in that case.
pub(crate) async fn read_chunked_request_body<S: ConnIo>(
    stream: &mut S,
    initial: &[u8],
    max_body: usize,
) -> Option<ChunkedBody> {
    let mut raw = Vec::with_capacity(initial.len().saturating_add(128));
    raw.extend_from_slice(initial);
    let mut cursor: usize = 0;
    let mut body = Vec::new();
    let mut trailer_bytes: usize = 0;

    loop {
        // Find the next CRLF for the chunk-size line, capped to bound growth.
        let line_end = loop {
            if let Some(pos) = raw[cursor..].windows(2).position(|w| w == b"\r\n") {
                break cursor + pos;
            }
            if raw.len() - cursor > MAX_CHUNK_LINE_BYTES {
                return None;
            }
            let chunk: Vec<u8> = vec![0u8; 4096];
            let (res, returned) = stream.read(chunk).await;
            match res {
                Ok(0) | Err(_) => return None,
                Ok(n) => raw.extend_from_slice(&returned[..n]),
            }
        };
        if line_end - cursor > MAX_CHUNK_LINE_BYTES {
            return None;
        }
        let line = &raw[cursor..line_end];
        let size_field = line.split(|&b| b == b';').next().unwrap_or(line);
        let size_text = std::str::from_utf8(size_field).ok()?.trim();
        if size_text.is_empty() {
            return None;
        }
        let chunk_len = usize::from_str_radix(size_text, 16).ok()?;
        // Reject oversize chunks before allocating; also guards arithmetic
        // below against `cursor + chunk_len + 2` overflow.
        if chunk_len > max_body {
            return None;
        }
        cursor = line_end + 2;

        if chunk_len == 0 {
            // Trailers: zero or more header-style lines, then an empty line.
            loop {
                let trailer_end = loop {
                    if let Some(pos) = raw[cursor..].windows(2).position(|w| w == b"\r\n") {
                        break cursor + pos;
                    }
                    if raw.len() - cursor > MAX_CHUNK_LINE_BYTES {
                        return None;
                    }
                    let chunk: Vec<u8> = vec![0u8; 1024];
                    let (res, returned) = stream.read(chunk).await;
                    match res {
                        Ok(0) | Err(_) => return None,
                        Ok(n) => raw.extend_from_slice(&returned[..n]),
                    }
                };
                let trailer = &raw[cursor..trailer_end];
                trailer_bytes = trailer_bytes.saturating_add(trailer.len() + 2);
                if trailer_bytes > MAX_TRAILER_BLOCK_BYTES {
                    return None;
                }
                cursor = trailer_end + 2;
                if trailer.is_empty() {
                    let consumed_initial = cursor.min(initial.len());
                    // Bytes past the chunked terminator belong to the next
                    // pipelined request. If the terminator landed within
                    // `initial`, those bytes are still in the worker's
                    // read buffer at their original position — leave them
                    // there. If we read past `initial` from the socket,
                    // hand the over-read back to the caller so it can
                    // splice them into the next-request slot.
                    let pipelined_tail = if cursor > initial.len() {
                        raw[cursor..].to_vec()
                    } else {
                        Vec::new()
                    };
                    return Some(ChunkedBody {
                        body,
                        consumed_initial,
                        raw_consumed: cursor,
                        pipelined_tail,
                    });
                }
            }
        }

        // Body cap check before extending; chunk_len <= max_body was
        // already enforced, so the add can't wrap.
        if body.len() + chunk_len > max_body {
            return None;
        }

        while raw.len() < cursor + chunk_len + 2 {
            let need = (cursor + chunk_len + 2) - raw.len();
            let cap = need.min(8192);
            let chunk: Vec<u8> = vec![0u8; cap];
            let (res, returned) = stream.read(chunk).await;
            match res {
                Ok(0) | Err(_) => return None,
                Ok(n) => raw.extend_from_slice(&returned[..n]),
            }
        }
        body.extend_from_slice(&raw[cursor..cursor + chunk_len]);
        cursor += chunk_len;
        if raw[cursor..cursor + 2] != *b"\r\n" {
            return None;
        }
        cursor += 2;
    }
}
