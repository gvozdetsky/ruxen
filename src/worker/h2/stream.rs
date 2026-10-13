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
    respond: Option<SendResponse<Bytes>>,
    send: Option<SendStream<Bytes>>,
    out: Out,
    /// The response head, until it is complete.
    head: Vec<u8>,
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
    ) -> Self {
        let has_body = !body.is_end_stream();
        let length = parts.headers.contains_key(http::header::CONTENT_LENGTH);
        let chunked_in = has_body && !length;
        let mut pending = Vec::with_capacity(512);
        request_head(parts, chunked_in, &mut pending);
        StreamIo {
            pending,
            pos: 0,
            body: has_body.then_some(body),
            chunked_in,
            started: false,
            head_request: parts.method == http::Method::HEAD,
            respond: Some(respond),
            send: None,
            out: Out::Head,
            head: Vec::new(),
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
                Out::Chunked(_) => {
                    let (used, piece, end) = self.decode_chunked(data);
                    if let Some((from, to)) = piece {
                        self.send_data(&data[from..to], false).await?;
                    }
                    if end {
                        self.send_data(&[], true).await?;
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

    /// One step of the chunked decoder over `data`: bytes used, the data
    /// range among them, and whether the body ended.
    fn decode_chunked(&mut self, data: &[u8]) -> (usize, Option<(usize, usize)>, bool) {
        let Out::Chunked(state) = &mut self.out else {
            unreachable!("chunked output")
        };
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
                    b'\n' => *empty = true,
                    _ => *empty = false,
                },
            }
            i += 1;
        }
        (i, None, false)
    }

    /// The response head `handle` wrote, as a HEADERS frame.
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
            .as_mut()
            .ok_or_else(|| invalid("a second response"))?;
        let send = respond
            .send_response(response, end)
            .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e))?;
        self.respond = None;
        if !end {
            self.send = Some(send);
        }
        self.out = out;
        Ok(())
    }

    /// Send `data` as DATA frames as the flow-control windows open.
    async fn send_data(&mut self, mut data: &[u8], end: bool) -> io::Result<()> {
        let Some(send) = self.send.as_mut() else {
            return Ok(());
        };
        let broken = |e: h2::Error| io::Error::new(io::ErrorKind::BrokenPipe, e);
        while !data.is_empty() {
            send.reserve_capacity(data.len());
            let granted = match poll_fn(|cx| send.poll_capacity(cx)).await {
                Some(Ok(n)) => n,
                Some(Err(e)) => return Err(broken(e)),
                None => return Err(io::ErrorKind::BrokenPipe.into()),
            };
            if granted == 0 {
                continue;
            }
            let k = granted.min(data.len());
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
        if let Some(respond) = self.respond.as_mut() {
            respond.send_reset(h2::Reason::INTERNAL_ERROR);
            return;
        }
        let Some(send) = self.send.as_mut() else {
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
fn request_head(parts: &http::request::Parts, chunked: bool, out: &mut Vec<u8>) {
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
        out.extend_from_slice(b"Cookie: ");
        for (i, c) in cookies.enumerate() {
            if i > 0 {
                out.extend_from_slice(b"; ");
            }
            out.extend_from_slice(c.as_bytes());
        }
        out.extend_from_slice(b"\r\n");
    }
    for (name, value) in &parts.headers {
        if name == http::header::COOKIE || (name == http::header::HOST && authority.is_some()) {
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
}

/// The status and fields of a response head `handle` wrote.
fn parse_head(head: &[u8]) -> io::Result<(u16, Vec<(&[u8], &[u8])>)> {
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

impl super::super::ConnIo for StreamIo {
    async fn idle_wait(
        &self,
        _state: &RuntimeState,
        _idle: Option<std::time::Duration>,
        _start_reload_gen: u64,
        _timers: &mut ConnTimers<'_>,
    ) -> bool {
        !self.started
    }

    /// The request, once: a stream carries one.
    async fn idle_read(
        &mut self,
        mut buf: Vec<u8>,
        _state: &RuntimeState,
        _idle: Option<std::time::Duration>,
        _start_reload_gen: u64,
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

    fn h2(&self) -> bool {
        true
    }
}
