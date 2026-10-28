//! `proxy_http_version 2` (#599): HTTP/2 to the upstream, through the `h2`
//! crate as a client, as the server side uses it (#144).
//!
//! An `H2Conn` is an upstream connection the proxy writes an HTTP/1.1
//! request to and reads an HTTP/1.1 response from, as from any other: the
//! request head it is given becomes a stream's HEADERS and the
//! Content-Length bytes after it DATA; the response comes back as an
//! HTTP/1.1 head, its body chunked when it has no Content-Length. So the
//! proxy's framing, header rules, buffering, relay and keep-alive pool work
//! unchanged, and HTTP/1.1 upstreams pay one more enum arm.
//!
//! As nginx's ngx_http_proxy_v2_module: one stream at a time on a
//! connection, which the keep-alive pool hands to the next request; h2c by
//! prior knowledge for `http://`, ALPN `h2` offered for `https://` (and
//! HTTP/2 spoken whatever the server picks).

use std::cell::Cell;
use std::future::{Future, poll_fn};
use std::io;
use std::pin::Pin;
use std::rc::Rc;
use std::task::Poll;

use bytes::Bytes;
use h2::client::{ResponseFuture, SendRequest};
use h2::{RecvStream, SendStream};
use monoio::BufResult;
use monoio::buf::{IoBuf, IoBufMut, IoVecBuf, IoVecBufMut};

use crate::upstream_io::UpstreamIo;
use crate::upstream_tls::TlsIdentity;

/// The flow-control window for a response, stream and connection alike:
/// one stream at a time, and the relay reads it at the client's pace.
const WINDOW: u32 = 1024 * 1024;

/// The response header block bound: the proxy takes 64 KiB of head.
const MAX_HEADER_LIST: u32 = 64 * 1024;

/// Where the exchange on the connection is.
enum Phase {
    /// No exchange, or the last one is over: a write starts a request head.
    Idle,
    /// The request body: what is left of its Content-Length.
    Body(SendStream<Bytes>, u64),
    /// The upstream stopped taking the body (a response, a reset): what is
    /// left of it is taken and dropped, and the response read.
    Discard(u64),
    /// The request is sent; the response head is awaited.
    Sent,
    /// The response body; for a Content-Length one, what is left of it.
    Recv(RecvStream, Option<u64>),
}

pub struct H2Conn {
    send: SendRequest<Bytes>,
    /// Set when the connection's task ends: closed, or done after a GOAWAY.
    closed: Rc<Cell<bool>>,
    https: bool,
    identity: Option<TlsIdentity>,
    phase: Phase,
    response: Option<ResponseFuture>,
    /// The response, when it came while the body was being sent.
    early: Option<Result<http::Response<RecvStream>, h2::Error>>,
    /// The request head, until its end is written.
    head: Vec<u8>,
    /// The request is a HEAD: its response has no body.
    head_request: bool,
    /// The response as HTTP/1.1, not yet read: `out[out_pos..]`.
    out: Vec<u8>,
    out_pos: usize,
}

/// Start HTTP/2 on a connection: the preface is sent, and a task drives the
/// connection from then on.
pub async fn handshake(
    io: UpstreamIo,
    https: bool,
    identity: Option<TlsIdentity>,
) -> io::Result<H2Conn> {
    // nginx's preface: no dynamic table, no push (ngx_http_proxy_v2_module.c,
    // ngx_http_proxy_v2_connection_start).
    let (send, conn) = h2::client::Builder::new()
        .enable_push(false)
        .header_table_size(0)
        .initial_window_size(WINDOW)
        .initial_connection_window_size(WINDOW)
        .max_header_list_size(MAX_HEADER_LIST)
        .handshake::<_, Bytes>(crate::worker::h2::compat::PollIo::client(io))
        .await
        .map_err(h2_io)?;
    let closed = Rc::new(Cell::new(false));
    let done = closed.clone();
    crate::worker::spawn_contained("an upstream HTTP/2 connection", || {}, async move {
        let _ = conn.await;
        done.set(true);
    });
    Ok(H2Conn {
        send,
        closed,
        https,
        identity,
        phase: Phase::Idle,
        response: None,
        early: None,
        head: Vec::new(),
        head_request: false,
        out: Vec::new(),
        out_pos: 0,
    })
}

fn h2_io(e: h2::Error) -> io::Error {
    if e.is_io() {
        e.into_io()
            .unwrap_or_else(|| io::Error::other("http2 i/o error"))
    } else {
        io::Error::other(e)
    }
}

impl H2Conn {
    pub fn tls_identity(&self) -> Option<&TlsIdentity> {
        self.identity.as_ref()
    }

    /// For the keep-alive pool: the connection may carry another request.
    pub fn is_open(&self) -> bool {
        !self.closed.get()
    }

    /// Take request bytes: the head, then the body. Returns how many were
    /// taken, short when the stream's window is.
    async fn take(&mut self, data: &[u8]) -> io::Result<usize> {
        if matches!(self.phase, Phase::Sent | Phase::Recv(..)) {
            // A request on a connection whose last response wasn't read to
            // its end: that stream is reset (CANCEL) as its handles go.
            self.phase = Phase::Idle;
            self.response = None;
            self.early = None;
            self.out.clear();
            self.out_pos = 0;
        }
        if let Phase::Discard(left) = &mut self.phase {
            *left = left.saturating_sub(data.len() as u64);
            if *left == 0 {
                self.phase = Phase::Sent;
            }
            return Ok(data.len());
        }
        let mut taken = 0;
        if matches!(self.phase, Phase::Idle) {
            let from = self.head.len().saturating_sub(3);
            self.head.extend_from_slice(data);
            let Some(end) = memchr::memmem::find(&self.head[from..], b"\r\n\r\n") else {
                return Ok(data.len());
            };
            let head_len = from + end + 4;
            taken = data.len() - (self.head.len() - head_len);
            self.head.truncate(head_len);
            let parsed = request_from_head(&self.head, self.https);
            self.head.clear();
            let (request, body_len) = parsed?;
            self.head_request = request.method() == http::Method::HEAD;
            poll_fn(|cx| self.send.poll_ready(cx))
                .await
                .map_err(h2_io)?;
            let (response, stream) = self
                .send
                .send_request(request, body_len == 0)
                .map_err(h2_io)?;
            self.response = Some(response);
            self.out.clear();
            self.out_pos = 0;
            if body_len == 0 {
                self.phase = Phase::Sent;
                // Nothing follows a request without a length.
                return Ok(data.len());
            }
            self.phase = Phase::Body(stream, body_len);
        }
        let Phase::Body(stream, left) = &mut self.phase else {
            unreachable!("set above");
        };
        let body = &data[taken..];
        let n = body.len().min(usize::try_from(*left).unwrap_or(usize::MAX));
        if n == 0 {
            return Ok(data.len());
        }
        // As hyper does: wait for some window, then hand the crate the
        // chunk, which it sends as the window opens. An upstream that
        // answers (or resets the stream) without taking the whole body
        // gets no more of it, and its response is read, as nginx does.
        stream.reserve_capacity(n);
        let mut taking = true;
        while taking && stream.capacity() == 0 {
            let response = &mut self.response;
            let early = &mut self.early;
            taking = poll_fn(|cx| {
                if let Poll::Ready(capacity) = stream.poll_capacity(cx) {
                    return Poll::Ready(matches!(capacity, Some(Ok(_))));
                }
                if let Some(future) = response.as_mut()
                    && let Poll::Ready(r) = Pin::new(future).poll(cx)
                {
                    *response = None;
                    *early = Some(r);
                    return Poll::Ready(false);
                }
                Poll::Pending
            })
            .await;
        }
        let left_after = *left - n as u64;
        if taking {
            let end = left_after == 0;
            stream
                .send_data(Bytes::copy_from_slice(&body[..n]), end)
                .map_err(h2_io)?;
            *left = left_after;
            if end {
                self.phase = Phase::Sent;
            }
        } else {
            self.phase = Phase::Discard(left_after);
            if left_after == 0 {
                self.phase = Phase::Sent;
            }
        }
        Ok(taken + n)
    }

    /// Make response bytes ready in `out`; none left means the response
    /// is over.
    async fn fill(&mut self) -> io::Result<()> {
        if self.out_pos < self.out.len() {
            return Ok(());
        }
        self.out.clear();
        self.out_pos = 0;
        let early = self.early.take();
        if early.is_some() || self.response.is_some() {
            let response = match early {
                Some(r) => r,
                None => {
                    let future = self.response.as_mut().expect("checked");
                    match poll_fn(|cx| poll_head(future, cx)).await {
                        Head::Final(r) => r,
                        // The proxy reads it as an HTTP/1.1 upstream's (#848).
                        Head::Hints(fields) => {
                            self.out.extend_from_slice(b"HTTP/1.1 103 Early Hints\r\n");
                            write_fields(&fields, &mut self.out);
                            self.out.extend_from_slice(b"\r\n");
                            return Ok(());
                        }
                    }
                }
            }
            .map_err(h2_io)?;
            self.response = None;
            let (parts, mut recv) = response.into_parts();
            let status = parts.status.as_u16();
            let bodiless = self.head_request || status == 204 || status == 304;
            let length = parts
                .headers
                .get(http::header::CONTENT_LENGTH)
                .and_then(|v| crate::proxy::parse_content_length(v.as_bytes()));
            let chunked = !bodiless && length.is_none();
            write_response_head(&parts, chunked, &mut self.out);
            if chunked {
                self.phase = Phase::Recv(recv, None);
                if self.recv_end() {
                    self.out.extend_from_slice(b"0\r\n\r\n");
                }
            } else if bodiless || length == Some(0) {
                // The proxy reads no body: wait for the stream's end here,
                // so the connection goes back to the pool done with it.
                drain(&mut recv).await?;
                self.phase = Phase::Idle;
            } else {
                self.phase = Phase::Recv(recv, length);
            }
            return Ok(());
        }
        let Phase::Recv(recv, left) = &mut self.phase else {
            return Ok(());
        };
        let chunked = left.is_none();
        let mut ended = false;
        loop {
            match poll_fn(|cx| recv.poll_data(cx)).await {
                Some(Ok(data)) => {
                    let _ = recv.flow_control().release_capacity(data.len());
                    if data.is_empty() {
                        continue;
                    }
                    if chunked {
                        self.out
                            .extend_from_slice(format!("{:x}\r\n", data.len()).as_bytes());
                        self.out.extend_from_slice(&data);
                        self.out.extend_from_slice(b"\r\n");
                    } else {
                        self.out.extend_from_slice(&data);
                    }
                    if let Some(left) = left {
                        *left = left.saturating_sub(data.len() as u64);
                        if *left == 0 {
                            // The last bytes go once the stream has ended,
                            // so the connection is reusable when they're read.
                            drain(recv).await?;
                            ended = true;
                        }
                    }
                    break;
                }
                Some(Err(e)) => return Err(h2_io(e)),
                None => {
                    ended = true;
                    break;
                }
            }
        }
        if ended || recv.is_end_stream() {
            // Trailers keep the stream open until polled.
            let trailers = poll_fn(|cx| recv.poll_trailers(cx)).await.map_err(h2_io)?;
            if chunked {
                self.out.extend_from_slice(b"0\r\n");
                if let Some(fields) = trailers {
                    write_fields(&fields, &mut self.out);
                }
                self.out.extend_from_slice(b"\r\n");
            }
            self.phase = Phase::Idle;
        }
        Ok(())
    }

    fn recv_end(&mut self) -> bool {
        match &self.phase {
            Phase::Recv(recv, _) if recv.is_end_stream() => {
                self.phase = Phase::Idle;
                true
            }
            _ => false,
        }
    }

    pub async fn read<T: IoBufMut>(&mut self, mut buf: T) -> BufResult<usize, T> {
        if let Err(e) = self.fill().await {
            self.phase = Phase::Idle;
            self.closed.set(true);
            return (Err(e), buf);
        }
        let n = (self.out.len() - self.out_pos).min(buf.bytes_total());
        // SAFETY: `buf` has room for `bytes_total()` bytes at `write_ptr()`.
        unsafe {
            std::ptr::copy_nonoverlapping(self.out.as_ptr().add(self.out_pos), buf.write_ptr(), n);
            buf.set_init(n);
        }
        self.out_pos += n;
        (Ok(n), buf)
    }

    pub async fn readv<T: IoVecBufMut>(&mut self, mut buf: T) -> BufResult<usize, T> {
        if let Err(e) = self.fill().await {
            self.phase = Phase::Idle;
            self.closed.set(true);
            return (Err(e), buf);
        }
        let mut n = 0;
        let iovs = buf.write_iovec_ptr();
        for i in 0..buf.write_iovec_len() {
            if self.out_pos == self.out.len() {
                break;
            }
            // SAFETY: `write_iovec_len()` iovecs at `write_iovec_ptr()`.
            let iov = unsafe { &*iovs.add(i) };
            let k = (self.out.len() - self.out_pos).min(iov.iov_len);
            // SAFETY: the iovec has room for `iov_len` bytes.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    self.out.as_ptr().add(self.out_pos),
                    iov.iov_base.cast::<u8>(),
                    k,
                );
            }
            self.out_pos += k;
            n += k;
        }
        // SAFETY: `n` bytes were written from the start of the iovecs.
        unsafe { buf.set_init(n) };
        (Ok(n), buf)
    }

    pub async fn write<T: IoBuf>(&mut self, buf: T) -> BufResult<usize, T> {
        // SAFETY: `buf` holds `bytes_init()` bytes at `read_ptr()`; it is
        // owned here until returned.
        let data = unsafe { std::slice::from_raw_parts(buf.read_ptr(), buf.bytes_init()) };
        let res = self.take(data).await;
        if res.is_err() {
            self.closed.set(true);
        }
        (res, buf)
    }

    pub async fn writev<T: IoVecBuf>(&mut self, buf: T) -> BufResult<usize, T> {
        let iovs = buf.read_iovec_ptr();
        let mut n = 0;
        for i in 0..buf.read_iovec_len() {
            // SAFETY: `read_iovec_len()` iovecs at `read_iovec_ptr()`, each
            // over bytes `buf` owns until returned.
            let data = unsafe {
                let iov = &*iovs.add(i);
                std::slice::from_raw_parts(iov.iov_base.cast::<u8>(), iov.iov_len)
            };
            if data.is_empty() {
                continue;
            }
            match self.take(data).await {
                Ok(k) => {
                    n += k;
                    if k < data.len() {
                        break;
                    }
                }
                Err(e) if n == 0 => {
                    self.closed.set(true);
                    return (Err(e), buf);
                }
                Err(_) => {
                    self.closed.set(true);
                    break;
                }
            }
        }
        (Ok(n), buf)
    }
}

/// Wait for the end of a response stream, dropping what still comes.
enum Head {
    /// A 103's fields.
    Hints(http::HeaderMap),
    Final(Result<http::Response<RecvStream>, h2::Error>),
}

/// The next head: a 103, or the final one. Other 1xx are dropped.
fn poll_head(future: &mut ResponseFuture, cx: &mut std::task::Context<'_>) -> Poll<Head> {
    loop {
        match future.poll_informational(cx) {
            Poll::Ready(Some(Ok(r))) if r.status() == http::StatusCode::EARLY_HINTS => {
                return Poll::Ready(Head::Hints(r.into_parts().0.headers));
            }
            Poll::Ready(Some(Ok(_))) => {}
            Poll::Ready(Some(Err(e))) => return Poll::Ready(Head::Final(Err(e))),
            Poll::Ready(None) | Poll::Pending => break,
        }
    }
    Pin::new(future).poll(cx).map(Head::Final)
}

async fn drain(recv: &mut RecvStream) -> io::Result<()> {
    while let Some(data) = poll_fn(|cx| recv.poll_data(cx)).await {
        let data = data.map_err(h2_io)?;
        let _ = recv.flow_control().release_capacity(data.len());
    }
    Ok(())
}

/// The request the proxy wrote as an HTTP/1.1 head (`write_request`), and
/// its body length. `:authority` comes as a field of its own unless
/// `proxy_set_header Host` gave a `Host`, which then goes as a header
/// (ngx_http_proxy_v2_create_request, `host_set`). Connection-specific
/// fields don't exist in HTTP/2 and are dropped.
fn request_from_head(head: &[u8], https: bool) -> io::Result<(http::Request<()>, u64)> {
    let bad = |what: &str| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("http2 upstream: {what}"),
        )
    };
    let mut lines = head
        .split(|&b| b == b'\n')
        .map(|l| l.strip_suffix(b"\r").unwrap_or(l));
    let line = lines.next().unwrap_or_default();
    let (Some(sp1), Some(sp2)) = (
        line.iter().position(|&b| b == b' '),
        line.iter().rposition(|&b| b == b' '),
    ) else {
        return Err(bad("request line"));
    };
    if sp2 <= sp1 {
        return Err(bad("request line"));
    }
    let method = http::Method::from_bytes(&line[..sp1]).map_err(|_| bad("method"))?;
    let target = &line[sp1 + 1..sp2];
    let mut authority: Option<&[u8]> = None;
    let mut host: Option<&[u8]> = None;
    let mut body_len = 0u64;
    let mut headers = http::HeaderMap::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some(value) = line.strip_prefix(b":authority:") {
            authority = Some(value.trim_ascii());
            continue;
        }
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            continue;
        };
        let name = line[..colon].trim_ascii();
        let value = line[colon + 1..].trim_ascii();
        let is = |n: &[u8]| name.eq_ignore_ascii_case(n);
        if is(b"connection")
            || is(b"keep-alive")
            || is(b"proxy-connection")
            || is(b"transfer-encoding")
            || is(b"upgrade")
            || (is(b"te") && !value.eq_ignore_ascii_case(b"trailers"))
        {
            continue;
        }
        if is(b"host") {
            host = Some(value);
            continue;
        }
        if is(b"content-length") {
            body_len = crate::proxy::parse_content_length(value).ok_or_else(|| bad("length"))?;
        }
        let (Ok(name), Ok(value)) = (
            http::HeaderName::from_bytes(name),
            http::HeaderValue::from_bytes(value),
        ) else {
            continue;
        };
        headers.append(name, value);
    }
    // `https://` needs an authority: the Host given, if that is all.
    if https && authority.is_none() {
        authority = host.take();
    }
    let path = http::uri::PathAndQuery::try_from(target).map_err(|_| bad("uri"))?;
    let uri = match authority {
        Some(authority) => http::Uri::builder()
            .scheme(if https { "https" } else { "http" })
            .authority(authority)
            .path_and_query(path)
            .build()
            .map_err(|_| bad("authority"))?,
        // No `:authority`; the `h2` crate sends `:scheme: http`.
        None => http::Uri::from(path),
    };
    if let Some(host) = host
        && let Ok(value) = http::HeaderValue::from_bytes(host)
    {
        headers.append(http::header::HOST, value);
    }
    let mut request = http::Request::new(());
    *request.method_mut() = method;
    *request.uri_mut() = uri;
    *request.headers_mut() = headers;
    Ok((request, body_len))
}

/// The response head as HTTP/1.1, chunked when the body has no length.
/// Header or trailer lines, CRLF each.
fn write_fields(fields: &http::HeaderMap, out: &mut Vec<u8>) {
    for (name, value) in fields {
        out.extend_from_slice(name.as_str().as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
}

fn write_response_head(parts: &http::response::Parts, chunked: bool, out: &mut Vec<u8>) {
    out.extend_from_slice(b"HTTP/1.1 ");
    out.extend_from_slice(parts.status.as_str().as_bytes());
    out.push(b' ');
    out.extend_from_slice(parts.status.canonical_reason().unwrap_or("").as_bytes());
    out.extend_from_slice(b"\r\n");
    write_fields(&parts.headers, out);
    if chunked {
        out.extend_from_slice(b"transfer-encoding: chunked\r\n");
    }
    out.extend_from_slice(b"\r\n");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_head_maps_to_http2() {
        let head = b"POST /a?b=1 HTTP/1.1\r\n:authority: up:8080\r\nX-A: 1\r\n\
                     Connection: close\r\nTE: deflate\r\nContent-Length: 3\r\nx-a: 2\r\n\r\n";
        let (req, len) = request_from_head(head, false).unwrap();
        assert_eq!(req.method(), http::Method::POST);
        assert_eq!(req.uri().to_string(), "http://up:8080/a?b=1");
        assert_eq!(len, 3);
        let a: Vec<_> = req.headers().get_all("x-a").iter().collect();
        assert_eq!(a, ["1", "2"]);
        assert!(req.headers().get("connection").is_none());
        assert!(req.headers().get("te").is_none());
        assert_eq!(req.headers()["content-length"], "3");
    }

    #[test]
    fn a_host_set_goes_as_a_header() {
        let head = b"GET / HTTP/1.1\r\nHost: example.com\r\nTE: trailers\r\n\r\n";
        let (req, len) = request_from_head(head, false).unwrap();
        assert_eq!(req.uri().authority(), None);
        assert_eq!(req.headers()["host"], "example.com");
        assert_eq!(req.headers()["te"], "trailers");
        assert_eq!(len, 0);
        // Over TLS the URI needs it.
        let (req, _) = request_from_head(head, true).unwrap();
        assert_eq!(req.uri().to_string(), "https://example.com/");
        assert!(req.headers().get("host").is_none());
    }

    #[test]
    fn a_response_head_is_http11() {
        let resp = http::Response::builder()
            .status(404)
            .header("x-a", "1")
            .header("set-cookie", "a")
            .header("set-cookie", "b")
            .body(())
            .unwrap();
        let (parts, ()) = resp.into_parts();
        let mut out = Vec::new();
        write_response_head(&parts, true, &mut out);
        assert_eq!(
            out,
            b"HTTP/1.1 404 Not Found\r\nx-a: 1\r\nset-cookie: a\r\nset-cookie: b\r\n\
              transfer-encoding: chunked\r\n\r\n"
        );
    }
}
