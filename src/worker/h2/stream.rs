//! One HTTP/2 stream as an HTTP/1.1 connection that carries one request,
//! so `handle` serves it like any other: everything a request goes through
//! (rewrites, static files, the proxy, logging) works on HTTP/2 as is.
//!
//! Reading gives `handle` the stream's request as an HTTP/1.1 head (with
//! the version `HTTP/2.0`, which the parser takes only from here) and then
//! its DATA frames as the body, chunked when the client sent no
//! Content-Length. Writing parses the HTTP/1.1 response `handle` writes:
//! the head becomes a HEADERS frame without the connection-specific
//! fields, and the body (by Content-Length, chunked, or up to the end)
//! becomes DATA frames, sent as the stream's flow-control window allows,
//! as nginx's ngx_http_v2_send_chain does.

use std::cell::RefCell;
use std::future::poll_fn;
use std::io;

use bytes::Bytes;
use h2::server::SendResponse;
use h2::{RecvStream, SendStream};
use monoio::buf::{IoBuf, IoBufMut, IoVecBuf, IoVecBufMut, RawBuf};
use monoio::io::{AsyncReadRent, AsyncWriteRent};

use super::super::{ConnTimers, IdleRead, RuntimeState};

/// Connection-specific fields, which HTTP/2 doesn't carry (RFC 9113,
/// 8.2.2); nginx's header filter skips the same.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "upgrade",
];

pub(crate) struct StreamIo {
    /// The request head, then the body bytes as `handle` reads them:
    /// `pending[pos..]` is still to be read.
    pending: Vec<u8>,
    pos: usize,
    /// The request body's DATA frames, until the stream's end.
    body: Option<RecvStream>,
    /// The body goes to `handle` chunked (no Content-Length).
    chunked_in: bool,
    /// `idle_read` handed out the request.
    started: bool,
    /// A HEAD request: the response has no body, whatever it says.
    head_request: bool,
    /// In cells for `peer_closed`, which watches them for the client's
    /// RST_STREAM through `&self`; everything else has `&mut self` and
    /// goes through `get_mut`.
    respond: RefCell<Option<SendResponse<Bytes>>>,
    send: RefCell<Option<SendStream<Bytes>>>,
    out: Out,
    /// The response head, until it is complete.
    head: Vec<u8>,
    /// The connection's start and the streams it carried before this one.
    counters: (std::time::Instant, u64),
    /// `http2_chunk_size`: the largest DATA frame sent.
    chunk: usize,
    /// The request's header block as sent (`compat::HeaderBlocks`), for
    /// `$request_length` (#409).
    header_block: u64,
    /// The request has an `:authority` and a `Host` that differs from it
    /// (`request_head`): refused with 400.
    authority_mismatch: bool,
    /// The head's lines that aren't the client's fields (`request_head`).
    synthetic_lines: usize,
}

enum Out {
    Head,
    Length(u64),
    Chunked(Chunked),
    /// Up to the end of the stream: `handle` closes it.
    Close,
    Done,
}

/// The decoder of the chunked body `handle` writes.
enum Chunked {
    /// In the size line; the size so far.
    Size(u64),
    /// Skipping a chunk extension up to the line's end.
    Ext(u64),
    /// After the size line's CR.
    SizeLf(u64),
    Data(u64),
    /// The CRLF after a chunk's data.
    DataCr,
    DataLf,
    /// After the last chunk: trailer lines up to an empty one; `true`
    /// while the current line is empty so far.
    Trailer(bool),
}

impl StreamIo {
    pub(crate) fn new(
        parts: &http::request::Parts,
        body: RecvStream,
        respond: SendResponse<Bytes>,
        counters: (std::time::Instant, u64),
        chunk: usize,
        header_block: u64,
    ) -> Self {
        let has_body = !body.is_end_stream();
        let length = parts.headers.contains_key(http::header::CONTENT_LENGTH);
        let chunked_in = has_body && !length;
        let mut pending = Vec::with_capacity(512);
        let (authority_mismatch, synthetic_lines) = request_head(parts, chunked_in, &mut pending);
        StreamIo {
            pending,
            pos: 0,
            body: has_body.then_some(body),
            chunked_in,
            started: false,
            head_request: parts.method == http::Method::HEAD,
            respond: RefCell::new(Some(respond)),
            send: RefCell::new(None),
            out: Out::Head,
            head: Vec::new(),
            counters,
            chunk: chunk.max(1),
            header_block,
            authority_mismatch,
            synthetic_lines,
        }
    }

    /// Copy what is pending into `dst`, fetching the next DATA frame first
    /// when nothing is. `Ok(0)`: the request is all read.
    async fn read_into(&mut self, dst: *mut u8, cap: usize) -> io::Result<usize> {
        while self.pos == self.pending.len() {
            self.pending.clear();
            self.pos = 0;
            let Some(body) = self.body.as_mut() else {
                return Ok(0);
            };
            match body.data().await {
                Some(Ok(data)) => {
                    let _ = body.flow_control().release_capacity(data.len());
                    if data.is_empty() {
                        continue;
                    }
                    if self.chunked_in {
                        self.pending
                            .extend_from_slice(format!("{:x}\r\n", data.len()).as_bytes());
                        self.pending.extend_from_slice(&data);
                        self.pending.extend_from_slice(b"\r\n");
                    } else {
                        self.pending.extend_from_slice(&data);
                    }
                }
                Some(Err(e)) => return Err(io::Error::new(io::ErrorKind::ConnectionReset, e)),
                None => {
                    self.body = None;
                    if self.chunked_in {
                        self.pending.extend_from_slice(b"0\r\n\r\n");
                    }
                }
            }
        }
        let n = (self.pending.len() - self.pos).min(cap);
        // SAFETY: `dst` is valid for `cap` bytes (the caller's buffer).
        unsafe {
            std::ptr::copy_nonoverlapping(self.pending.as_ptr().add(self.pos), dst, n);
        }
        self.pos += n;
        Ok(n)
    }

    /// Take `data` from `handle`'s response.
    async fn write_bytes(&mut self, mut data: &[u8]) -> io::Result<()> {
        while !data.is_empty() {
            match &mut self.out {
                Out::Head => {
                    let from = self.head.len().saturating_sub(3);
                    self.head.extend_from_slice(data);
                    let Some(end) = find(&self.head[from..], b"\r\n\r\n").map(|i| from + i + 4)
                    else {
                        return Ok(());
                    };
                    let rest_start = data.len() - (self.head.len() - end);
                    data = &data[rest_start..];
                    let head = std::mem::take(&mut self.head);
                    self.send_head(&head[..end])?;
                }
                Out::Length(left) => {
                    let k = (*left).min(data.len() as u64) as usize;
                    *left -= k as u64;
                    let end = *left == 0;
                    self.send_data(&data[..k], end).await?;
                    if end {
                        self.out = Out::Done;
                    }
                    data = &data[k..];
                }
                Out::Close => {
                    self.send_data(data, false).await?;
                    return Ok(());
                }
                Out::Chunked(state) => {
                    let (used, piece, end) = decode_chunked(state, data, &mut self.head);
                    if let Some((from, to)) = piece {
                        self.send_data(&data[from..to], false).await?;
                    }
                    if end {
                        // `add_trailer`: the fields after the last chunk
                        // (gathered in `head`) go as a trailing HEADERS frame.
                        let trailers = std::mem::take(&mut self.head);
                        self.finish_with(&trailers).await?;
                        self.out = Out::Done;
                    }
                    data = &data[used..];
                }
                // More than the response said: dropped.
                Out::Done => return Ok(()),
            }
        }
        Ok(())
    }
}

/// One step of the decoder of the chunked body `handle` writes, over
/// `data`: bytes used, the range of chunk data among them (at most one
/// run), and whether the body ended. The trailer section goes to
/// `trailers`.
fn decode_chunked(
    state: &mut Chunked,
    data: &[u8],
    trailers: &mut Vec<u8>,
) -> (usize, Option<(usize, usize)>, bool) {
    let mut i = 0;
    while i < data.len() {
        let b = data[i];
        match state {
            Chunked::Size(n) => match b {
                b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F' => {
                    let digit = (b as char).to_digit(16).unwrap_or(0) as u64;
                    *n = n.saturating_mul(16).saturating_add(digit);
                }
                b'\r' => *state = Chunked::SizeLf(*n),
                b'\n' => *state = next_after_size(*n),
                _ => *state = Chunked::Ext(*n),
            },
            Chunked::Ext(n) => match b {
                b'\r' => *state = Chunked::SizeLf(*n),
                b'\n' => *state = next_after_size(*n),
                _ => {}
            },
            Chunked::SizeLf(n) => *state = next_after_size(*n),
            Chunked::Data(left) => {
                let k = (*left).min((data.len() - i) as u64) as usize;
                *left -= k as u64;
                if *left == 0 {
                    *state = Chunked::DataCr;
                }
                return (i + k, Some((i, i + k)), false);
            }
            Chunked::DataCr => *state = Chunked::DataLf,
            Chunked::DataLf => *state = Chunked::Size(0),
            Chunked::Trailer(empty) => match b {
                b'\r' => {}
                b'\n' if *empty => return (i + 1, None, true),
                b'\n' => {
                    trailers.push(b'\n');
                    *empty = true;
                }
                _ => {
                    trailers.push(b);
                    *empty = false;
                }
            },
        }
        i += 1;
    }
    (i, None, false)
}

impl StreamIo {
    /// The response head `handle` wrote, as a HEADERS frame. Out of line:
    /// whether LLVM inlined it into `write` flipped with unrelated changes
    /// elsewhere, and inlined it cost h2c_hello ~1% (callgrind and ABBA,
    /// 2026-10-22).
    #[inline(never)]
    fn send_head(&mut self, head: &[u8]) -> io::Result<()> {
        let (status, fields) = parse_head(head)?;
        // An interim response (100 Continue): HTTP/2 has its own; the
        // final one follows.
        if (100..200).contains(&status) {
            return Ok(());
        }
        let mut response = http::Response::new(());
        *response.status_mut() =
            http::StatusCode::from_u16(status).map_err(|_| invalid("response status"))?;
        let mut length = None;
        let mut chunked = false;
        for (name, value) in fields {
            if name.eq_ignore_ascii_case(b"transfer-encoding") {
                chunked = value
                    .split(|&b| b == b',')
                    .any(|t| t.trim_ascii().eq_ignore_ascii_case(b"chunked"));
                continue;
            }
            if name.eq_ignore_ascii_case(b"content-length") {
                length = std::str::from_utf8(value).ok().and_then(|s| s.parse().ok());
            }
            let name = http::HeaderName::from_bytes(name).map_err(|_| invalid("header name"))?;
            if HOP_BY_HOP.contains(&name.as_str()) {
                continue;
            }
            let value =
                http::HeaderValue::from_bytes(value).map_err(|_| invalid("header value"))?;
            response.headers_mut().append(name, value);
        }
        let bodiless = self.head_request || status == 204 || status == 304;
        let out = if bodiless {
            Out::Done
        } else if chunked {
            Out::Chunked(Chunked::Size(0))
        } else {
            match length {
                Some(0) => Out::Done,
                Some(n) => Out::Length(n),
                None => Out::Close,
            }
        };
        let end = matches!(out, Out::Done);
        let respond = self
            .respond
            .get_mut()
            .as_mut()
            .ok_or_else(|| invalid("a second response"))?;
        let send = respond
            .send_response(response, end)
            .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e))?;
        *self.respond.get_mut() = None;
        if !end {
            *self.send.get_mut() = Some(send);
        }
        self.out = out;
        Ok(())
    }

    /// End the body: with a trailing HEADERS frame when `trailers` (lines
    /// of `name: value`) has fields, else an empty DATA frame.
    async fn finish_with(&mut self, trailers: &[u8]) -> io::Result<()> {
        let mut fields = http::HeaderMap::new();
        for line in trailers.split(|&b| b == b'\n').filter(|l| !l.is_empty()) {
            let Some(colon) = line.iter().position(|&b| b == b':') else {
                continue;
            };
            if let (Ok(name), Ok(value)) = (
                http::HeaderName::from_bytes(&line[..colon]),
                http::HeaderValue::from_bytes(line[colon + 1..].trim_ascii()),
            ) {
                fields.append(name, value);
            }
        }
        if fields.is_empty() {
            return self.send_data(&[], true).await;
        }
        match self.send.get_mut().as_mut() {
            Some(send) => send
                .send_trailers(fields)
                .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e)),
            None => Ok(()),
        }
    }

    /// Send `data` as DATA frames as the flow-control windows open.
    /// The whole body, owned, as the stream's last DATA frames: split,
    /// not copied.
    async fn send_data_owned(&mut self, mut data: Bytes) -> io::Result<()> {
        let Some(send) = self.send.get_mut().as_mut() else {
            return Ok(());
        };
        let broken = |e: h2::Error| io::Error::new(io::ErrorKind::BrokenPipe, e);
        if data.is_empty() {
            return send.send_data(Bytes::new(), true).map_err(broken);
        }
        while !data.is_empty() {
            send.reserve_capacity(data.len());
            let granted = match send.capacity() {
                0 => match poll_fn(|cx| send.poll_capacity(cx)).await {
                    Some(Ok(n)) => n,
                    Some(Err(e)) => return Err(broken(e)),
                    None => return Err(io::ErrorKind::BrokenPipe.into()),
                },
                n => n,
            };
            if granted == 0 {
                continue;
            }
            let k = granted.min(data.len()).min(self.chunk);
            let piece = data.split_to(k);
            send.send_data(piece, data.is_empty()).map_err(broken)?;
        }
        Ok(())
    }

    async fn send_data(&mut self, mut data: &[u8], end: bool) -> io::Result<()> {
        let Some(send) = self.send.get_mut().as_mut() else {
            return Ok(());
        };
        let broken = |e: h2::Error| io::Error::new(io::ErrorKind::BrokenPipe, e);
        while !data.is_empty() {
            send.reserve_capacity(data.len());
            // What is left of the window first: `poll_capacity` reports
            // only increases, and a chunk may use part of one.
            let granted = match send.capacity() {
                0 => match poll_fn(|cx| send.poll_capacity(cx)).await {
                    Some(Ok(n)) => n,
                    Some(Err(e)) => return Err(broken(e)),
                    None => return Err(io::ErrorKind::BrokenPipe.into()),
                },
                n => n,
            };
            if granted == 0 {
                continue;
            }
            let k = granted.min(data.len()).min(self.chunk);
            let last = end && k == data.len();
            send.send_data(Bytes::copy_from_slice(&data[..k]), last)
                .map_err(broken)?;
            data = &data[k..];
            if last {
                return Ok(());
            }
        }
        if end {
            send.send_data(Bytes::new(), true).map_err(broken)?;
        }
        Ok(())
    }
}

fn next_after_size(n: u64) -> Chunked {
    if n == 0 {
        Chunked::Trailer(true)
    } else {
        Chunked::Data(n)
    }
}

impl Drop for StreamIo {
    /// `handle` is done with the stream. A body that ends with the stream
    /// ends now; a response cut short (or none at all, `return 444`) resets
    /// the stream, as nginx does.
    fn drop(&mut self) {
        if let Some(respond) = self.respond.get_mut().as_mut() {
            respond.send_reset(h2::Reason::INTERNAL_ERROR);
            return;
        }
        let Some(send) = self.send.get_mut().as_mut() else {
            return;
        };
        match self.out {
            Out::Close => {
                let _ = send.send_data(Bytes::new(), true);
            }
            Out::Done => {}
            _ => send.send_reset(h2::Reason::INTERNAL_ERROR),
        }
    }
}

/// The request head: the request line with `HTTP/2.0`, `Host` from
/// `:authority`, the fields with every `cookie` joined into one (RFC 9113,
/// 8.2.3, as nginx does for `$http_cookie`), and `Transfer-Encoding:
/// chunked` for a body without a length.
///
/// `true` when there is an `:authority` and a `Host` field that isn't the
/// same bytes: nginx (since 1.29.1, ngx_http_v2_run_request) answers 400,
/// comparing the two as sent, not normalised (case, a port, a trailing
/// dot all count). The head carries
/// the `:authority` alone, by which the request was routed, as nginx's
/// `ngx_http_v2_parse_authority` chose the server.
///
/// And how many of the head's lines aren't fields nginx counts for
/// `max_headers` (#584): it counts each field but `cookie`, and no
/// pseudo-header.
fn request_head(parts: &http::request::Parts, chunked: bool, out: &mut Vec<u8>) -> (bool, usize) {
    let mut synthetic = usize::from(chunked);
    out.extend_from_slice(parts.method.as_str().as_bytes());
    out.push(b' ');
    let target = parts.uri.path_and_query().map_or("/", |p| p.as_str());
    out.extend_from_slice(target.as_bytes());
    out.extend_from_slice(b" HTTP/2.0\r\n");
    let authority = parts.uri.authority();
    if let Some(authority) = authority {
        out.extend_from_slice(b"Host: ");
        out.extend_from_slice(authority.as_str().as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    let mut cookies = parts
        .headers
        .get_all(http::header::COOKIE)
        .iter()
        .peekable();
    if cookies.peek().is_some() {
        synthetic += 1;
        out.extend_from_slice(b"Cookie: ");
        for (i, c) in cookies.enumerate() {
            if i > 0 {
                out.extend_from_slice(b"; ");
            }
            out.extend_from_slice(c.as_bytes());
        }
        out.extend_from_slice(b"\r\n");
    }
    let mut authority_mismatch = false;
    let mut host_seen = false;
    for (name, value) in &parts.headers {
        if name == http::header::COOKIE {
            continue;
        }
        // The first `host` stands with the `:authority`; a second one goes
        // into the head, where the parser refuses a duplicate Host as
        // nginx does, `:authority` being its Host (#609).
        if name == http::header::HOST
            && let Some(authority) = authority
            && !std::mem::replace(&mut host_seen, true)
        {
            authority_mismatch |= value.as_bytes() != authority.as_str().as_bytes();
            continue;
        }
        out.extend_from_slice(name.as_str().as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    if chunked {
        out.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
    }
    out.extend_from_slice(b"\r\n");
    // The `Host` line stands for the client's `host` field if there was
    // one, else for `:authority`, which isn't counted.
    if authority.is_some() && !parts.headers.contains_key(http::header::HOST) {
        synthetic += 1;
    }
    (authority_mismatch, synthetic)
}

/// The status and fields of a response head `handle` wrote.
/// A response head's fields: (name, value) slices of it.
type Fields<'a> = Vec<(&'a [u8], &'a [u8])>;

fn parse_head(head: &[u8]) -> io::Result<(u16, Fields<'_>)> {
    let mut lines = head
        .split(|&b| b == b'\n')
        .map(|l| l.strip_suffix(b"\r").unwrap_or(l));
    let status_line = lines.next().ok_or_else(|| invalid("response head"))?;
    let status = status_line
        .get(9..12)
        .and_then(|s| std::str::from_utf8(s).ok())
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| invalid("response status"))?;
    let mut fields = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let colon = line
            .iter()
            .position(|&b| b == b':')
            .ok_or_else(|| invalid("response field"))?;
        fields.push((&line[..colon], line[colon + 1..].trim_ascii()));
    }
    Ok((status, fields))
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn invalid(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("HTTP/2: bad {what}"))
}

impl AsyncReadRent for StreamIo {
    async fn read<T: IoBufMut>(&mut self, mut buf: T) -> monoio::BufResult<usize, T> {
        let res = self.read_into(buf.write_ptr(), buf.bytes_total()).await;
        if let Ok(n) = res {
            // SAFETY: `read_into` initialized the first `n` bytes.
            unsafe { buf.set_init(n) };
        }
        (res, buf)
    }

    async fn readv<T: IoVecBufMut>(&mut self, mut buf: T) -> monoio::BufResult<usize, T> {
        // The first iovec only: a short read, which callers handle.
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

impl AsyncWriteRent for StreamIo {
    async fn write<T: IoBuf>(&mut self, buf: T) -> monoio::BufResult<usize, T> {
        // SAFETY: `IoBuf` guarantees `bytes_init` initialized bytes at
        // `read_ptr`, and `buf` is owned here until we return it.
        let src = unsafe { std::slice::from_raw_parts(buf.read_ptr(), buf.bytes_init()) };
        let res = self.write_bytes(src).await.map(|()| src.len());
        (res, buf)
    }

    async fn writev<T: IoVecBuf>(&mut self, buf: T) -> monoio::BufResult<usize, T> {
        // SAFETY: as in `TlsStream::writev`: valid iovecs over initialized
        // bytes, owned here until returned.
        let iovecs =
            unsafe { std::slice::from_raw_parts(buf.read_iovec_ptr(), buf.read_iovec_len()) };
        let mut total = 0;
        for v in iovecs {
            let src = unsafe { std::slice::from_raw_parts(v.iov_base as *const u8, v.iov_len) };
            if let Err(e) = self.write_bytes(src).await {
                return (Err(e), buf);
            }
            total += src.len();
        }
        (Ok(total), buf)
    }

    async fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// SAFETY: never touches the stream. An HTTP/2 stream carries no tunnel:
// the `h2` crate refuses a request with an `Upgrade` field (RFC 9113,
// 8.2.2), so no upstream 101 is relayed on one.
unsafe impl crate::duplex::Duplex for StreamIo {
    unsafe fn read_raw<T: IoBufMut>(
        _: std::ptr::NonNull<Self>,
        buf: T,
    ) -> impl std::future::Future<Output = monoio::BufResult<usize, T>> + 'static {
        std::future::ready((Err(io::ErrorKind::Unsupported.into()), buf))
    }

    unsafe fn write_raw<T: IoBuf>(
        _: std::ptr::NonNull<Self>,
        buf: T,
    ) -> impl std::future::Future<Output = monoio::BufResult<usize, T>> + 'static {
        std::future::ready((Err(io::ErrorKind::Unsupported.into()), buf))
    }

    unsafe fn shutdown_raw(
        _: std::ptr::NonNull<Self>,
    ) -> impl std::future::Future<Output = io::Result<()>> + 'static {
        std::future::ready(Ok(()))
    }
}

impl super::super::ConnIo for StreamIo {
    async fn idle_wait(
        &self,
        _state: &RuntimeState,
        _idle: super::super::IdleLimits,
        _fresh: bool,
        _timers: &mut ConnTimers<'_>,
    ) -> bool {
        !self.started
    }

    /// The request, once: a stream carries one.
    async fn idle_read(
        &mut self,
        mut buf: Vec<u8>,
        _state: &RuntimeState,
        _idle: super::super::IdleLimits,
        _fresh: bool,
        _timers: &mut ConnTimers<'_>,
    ) -> (IdleRead, Vec<u8>) {
        if std::mem::replace(&mut self.started, true) {
            return (IdleRead::Close, buf);
        }
        let n = (self.pending.len() - self.pos).min(buf.len());
        buf[..n].copy_from_slice(&self.pending[self.pos..self.pos + n]);
        self.pos += n;
        (IdleRead::Read(n), buf)
    }

    fn sendfile_fd(&self) -> Option<std::os::unix::io::RawFd> {
        None
    }

    async fn wait_writable(&self) -> io::Result<()> {
        Err(io::ErrorKind::Unsupported.into())
    }

    /// The client reset the stream (RST_STREAM), or the connection failed:
    /// nginx's ngx_http_v2_state_rst_stream sets `fc->error` and runs the
    /// request's handler, so an upstream exchange ends with 499
    /// (ngx_http_upstream_check_broken_connection). Without this, the work
    /// behind a reset stream would go on until the upstream answered
    /// (CVE-2023-44487). Pending once the response is all sent.
    async fn peer_closed(&self) {
        poll_fn(|cx| {
            // No borrow can be out: the other users have `&mut self`.
            if let Some(send) = self.send.borrow_mut().as_mut() {
                return send.poll_reset(cx).map(drop);
            }
            match self.respond.borrow_mut().as_mut() {
                Some(respond) => respond.poll_reset(cx).map(drop),
                None => std::task::Poll::Pending,
            }
        })
        .await
    }

    fn h2(&self) -> bool {
        true
    }

    fn sends_file_bodies(&self) -> bool {
        true
    }

    /// The file read straight into the `Bytes` its DATA frames carry: no
    /// zeroed buffer per request and no copy into the frames (#348). Only
    /// for a body the head announced with its length, up to 1 MiB.
    async fn send_file_body(
        &mut self,
        body: crate::phase::FileBody,
        aio: Option<&'static crate::aio::ThreadPool>,
    ) -> Result<bool, crate::phase::FileBody> {
        use std::os::fd::AsRawFd;
        const MAX: u64 = 1 << 20;
        if self.head_request
            || body.len > MAX
            || !matches!(self.out, Out::Length(n) if n == body.len)
        {
            return Err(body);
        }
        if let Some(pool) = aio {
            let read = Box::pin(crate::aio::run(pool, move || {
                let mut buf = bytes::BytesMut::zeroed(body.len as usize);
                crate::aio::pread_exact(body.fd.as_raw_fd(), &mut buf, body.offset).map(|()| buf)
            }))
            .await;
            let Ok(Ok(buf)) = read else {
                return Ok(false);
            };
            self.out = Out::Done;
            return Ok(self.send_data_owned(buf.freeze()).await.is_ok());
        }
        let len = body.len as usize;
        let mut buf = bytes::BytesMut::with_capacity(len);
        let mut filled = 0;
        while filled < len {
            // SAFETY: `pread` writes at most `len - filled` bytes into the
            // spare capacity, which `with_capacity(len)` reserved.
            let n = unsafe {
                libc::pread(
                    body.fd.as_raw_fd(),
                    buf.as_mut_ptr().add(filled).cast(),
                    len - filled,
                    (body.offset + filled as u64) as libc::off_t,
                )
            };
            if n <= 0 {
                // An error, or a file shorter than its stat said.
                return Ok(false);
            }
            filled += n as usize;
        }
        // SAFETY: `filled == len` bytes were written above.
        unsafe { buf.set_len(len) };
        self.out = Out::Done;
        Ok(self.send_data_owned(buf.freeze()).await.is_ok())
    }

    fn h2_header_block(&self) -> Option<u64> {
        Some(self.header_block)
    }

    fn set_h2_chunk(&mut self, chunk: usize) {
        self.chunk = chunk.max(1);
    }

    fn h2_authority_mismatch(&self) -> bool {
        self.authority_mismatch
    }

    fn h2_synthetic_lines(&self) -> usize {
        self.synthetic_lines
    }

    fn conn_counters(&self) -> Option<(std::time::Instant, u64)> {
        Some(self.counters)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decode `body` fed in pieces of `step` bytes.
    fn dechunk(body: &[u8], step: usize) -> (Vec<u8>, bool) {
        let mut state = Chunked::Size(0);
        let mut out = Vec::new();
        let mut trailers = Vec::new();
        for piece in body.chunks(step) {
            let mut piece = piece;
            while !piece.is_empty() {
                let (used, data, end) = decode_chunked(&mut state, piece, &mut trailers);
                if let Some((from, to)) = data {
                    out.extend_from_slice(&piece[from..to]);
                }
                if end {
                    return (out, true);
                }
                piece = &piece[used..];
            }
        }
        (out, false)
    }

    #[test]
    fn chunked_bodies_decode_whatever_the_pieces() {
        let body = b"5\r\nhello\r\n7;ext=1\r\n, world\r\n0\r\nX-T: 1\r\n\r\n";
        for step in 1..body.len() {
            assert_eq!(
                dechunk(body, step),
                (b"hello, world".to_vec(), true),
                "{step}"
            );
        }
        assert_eq!(dechunk(b"0\r\n\r\n", 3), (Vec::new(), true));
        assert_eq!(dechunk(b"3\r\nabc\r\n", 4), (b"abc".to_vec(), false));
    }

    #[test]
    fn response_heads_parse() {
        let head = b"HTTP/1.1 404 Not Found\r\nServer: ruxen\r\nContent-Length:  10 \r\n\r\n";
        let (status, fields) = parse_head(head).unwrap();
        assert_eq!(status, 404);
        assert_eq!(
            fields,
            vec![
                (&b"Server"[..], &b"ruxen"[..]),
                (&b"Content-Length"[..], &b"10"[..])
            ]
        );
        assert!(parse_head(b"HTTP/1.1 2x0 OK\r\n\r\n").is_err());
        assert!(parse_head(b"HTTP/1.1 200 OK\r\nno colon\r\n\r\n").is_err());
    }

    #[test]
    fn request_heads_carry_authority_and_cookies() {
        let request = http::Request::builder()
            .method("POST")
            .uri("http://example.com:8080/p?q=1")
            .header("cookie", "a=1")
            .header("x-y", "z")
            .header("cookie", "b=2")
            .body(())
            .unwrap();
        let (parts, ()) = request.into_parts();
        let mut out = Vec::new();
        // Of 5 lines: one field nginx counts (`x-y`).
        assert_eq!(request_head(&parts, true, &mut out), (false, 3));
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "POST /p?q=1 HTTP/2.0\r\nHost: example.com:8080\r\nCookie: a=1; b=2\r\n\
             x-y: z\r\nTransfer-Encoding: chunked\r\n\r\n"
        );
    }

    #[test]
    fn a_host_other_than_the_authority_is_a_mismatch() {
        let head = |uri: &str, host: Option<&str>| {
            let mut request = http::Request::builder().uri(uri);
            if let Some(host) = host {
                request = request.header("host", host);
            }
            let (parts, ()) = request.body(()).unwrap().into_parts();
            let mut out = Vec::new();
            let (mismatch, _) = request_head(&parts, false, &mut out);
            (mismatch, String::from_utf8(out).unwrap())
        };
        // The client's Host isn't passed on: the head has the authority's.
        assert_eq!(
            head("http://a.test/", Some("b.test")),
            (true, "GET / HTTP/2.0\r\nHost: a.test\r\n\r\n".to_string())
        );
        assert!(head("http://a.test/", Some("A.test")).0);
        assert!(head("http://a.test/", Some("a.test:80")).0);
        assert!(head("http://a.test/", Some("a.test.")).0);
        assert_eq!(
            head("http://a.test/", Some("a.test")),
            (false, "GET / HTTP/2.0\r\nHost: a.test\r\n\r\n".to_string())
        );
        assert!(!head("http://a.test/", None).0);
        assert_eq!(
            head("/", Some("b.test")),
            (false, "GET / HTTP/2.0\r\nhost: b.test\r\n\r\n".to_string())
        );
    }

    /// A second `host` next to the `:authority` goes into the head, which
    /// the parser then refuses for a duplicate Host, as nginx does (#609).
    #[test]
    fn a_second_host_goes_into_the_head() {
        let (parts, ()) = http::Request::builder()
            .uri("http://a.test/")
            .header("host", "a.test")
            .header("host", "a.test")
            .body(())
            .unwrap()
            .into_parts();
        let mut out = Vec::new();
        let (mismatch, _) = request_head(&parts, false, &mut out);
        assert!(!mismatch);
        assert_eq!(
            String::from_utf8(out.clone()).unwrap(),
            "GET / HTTP/2.0\r\nHost: a.test\r\nhost: a.test\r\n\r\n"
        );
        let mut state = crate::http::ParseState {
            h2: true,
            ..Default::default()
        };
        assert!(matches!(
            crate::http::parse_request(&out, &mut state),
            crate::http::Parse::Invalid
        ));
    }
}
