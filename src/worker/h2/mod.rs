//! HTTP/2 connections (#144), served by the `h2` crate (DESIGN.md,
//! "Runtime choice"): `compat` lets it drive a monoio stream, and each
//! request stream runs through `handle` as a one-request HTTP/1.1
//! connection (`stream`). nginx's counterpart is ngx_http_v2.c.
//!
//! A connection is HTTP/2 when its address has `http2` on and it starts
//! with the client preface (cleartext, "prior knowledge"), or when TLS
//! negotiated `h2` through ALPN.

mod compat;
mod stream;

use std::cell::Cell;
use std::net::SocketAddr;
use std::rc::Rc;
use std::time::Duration;

use bytes::Bytes;
use monoio::io::{AsyncReadRent, AsyncWriteRent};
use monoio::net::TcpStream;

use super::{Contained, PreparedHttp, RuntimeState};
use crate::phase;

/// The client connection preface (RFC 9113, 3.4).
const PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// How long a connection without streams stays: nginx's default
/// keepalive_timeout, which it applies to HTTP/2 connections (the default
/// server's own setting comes with the connection lifecycle, #144 phase 3).
const IDLE: Duration = Duration::from_secs(75);

/// What every stream of a connection shares.
pub(crate) struct ConnCtx {
    pub peer_addr: SocketAddr,
    pub listen_index: usize,
    pub sni: Option<Vec<u8>>,
    pub tls: Option<crate::tls::HandshakeInfo>,
    pub conn: phase::ConnInfo,
    pub http: &'static PreparedHttp,
    pub state: &'static RuntimeState,
    pub connection_id: u64,
}

/// Whether a plain connection starts with the HTTP/2 preface, looked at
/// without reading it (`MSG_PEEK`), as nginx's ngx_http_wait_request_handler
/// compares the first bytes. `false` as soon as a byte differs, at EOF, or
/// when nothing arrives within `wait`: the HTTP/1.1 path takes over.
pub(crate) async fn starts_with_preface(stream: &TcpStream, wait: Duration) -> bool {
    use std::os::fd::AsRawFd;
    let deadline = monoio::time::Instant::now() + wait;
    loop {
        match monoio::time::timeout_at(deadline, stream.readable(false)).await {
            Ok(Ok(())) => {}
            _ => return false,
        }
        let mut buf = [0u8; PREFACE.len()];
        // SAFETY: recv into a stack buffer of the length given.
        let n = unsafe {
            libc::recv(
                stream.as_raw_fd(),
                buf.as_mut_ptr().cast(),
                buf.len(),
                libc::MSG_PEEK | libc::MSG_DONTWAIT,
            )
        };
        if n <= 0 {
            // EAGAIN after a spurious wakeup: look again.
            if n < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::WouldBlock {
                continue;
            }
            return false;
        }
        let n = n as usize;
        if buf[..n] != PREFACE[..n] {
            return false;
        }
        if n == PREFACE.len() {
            return true;
        }
        // Part of the preface so far: the socket stays readable, so wait a
        // little for the rest instead of spinning.
        monoio::time::sleep(Duration::from_millis(1)).await;
    }
}

/// Serve an HTTP/2 connection until the client or a shutdown ends it.
pub(crate) async fn serve<S>(stream: S, ctx: ConnCtx)
where
    S: super::ConnIo + 'static,
{
    let ctx = Rc::new(ctx);
    let listen = &ctx.http.listens[ctx.listen_index];
    let timeouts = listen.servers[listen.default_server].timeouts;
    let io = compat::PollIo::new(stream);
    let writing_since = io.writing_since();
    let header_blocks = io.header_blocks();
    let stream = io.stream_handle();
    // What nginx announces (ngx_http_v2_send_settings), from the default
    // server's settings: http2_max_concurrent_streams (128), a stream
    // window of http2_body_preread_size (64k); then it opens the
    // connection window to the maximum with a WINDOW_UPDATE
    // (ngx_http_v2_init). Clients such as Test::Nginx wait for both.
    // nginx also announces the largest frame size, 2^24-1, which it can
    // afford: it parses frames as they arrive. The `h2` crate reads each
    // frame whole first, so a client could make every connection hold a
    // 16 MiB frame (#506). The default, 16384, is left: request bodies
    // come in a 64k window anyway, and a head is held whole regardless.
    let h2conf = listen.servers[listen.default_server].h2;
    let max_streams = h2conf.max_concurrent_streams.unwrap_or(128);
    let handshake = h2::server::Builder::new()
        .max_concurrent_streams(max_streams)
        .initial_window_size(h2conf.body_preread_size.unwrap_or(64 * 1024))
        .initial_connection_window_size((1 << 31) - 1)
        // The decoded request head is held whole before `handle` sees it:
        // bounded, with room above large_client_header_buffers' total,
        // which `fields_over_limit` checks, as the crate counts 32 bytes
        // per field on top and would answer 431 first.
        .max_header_list_size(max_header_list(timeouts.large_header))
        .handshake::<_, Bytes>(io);
    // The preface and SETTINGS come under client_header_timeout, as the
    // first request line would.
    let conn = match monoio::time::timeout(timeouts.header, handshake).await {
        Ok(Ok(conn)) => conn,
        _ => return,
    };
    drive(
        conn,
        &ctx,
        timeouts,
        max_streams as usize,
        writing_since,
        header_blocks,
    )
    .await;
    // The `h2` connection, and with it every operation on the stream, is
    // gone. Close as nginx does (ngx_http_v2_finalize_connection →
    // lingering close): what the client still sends (a WINDOW_UPDATE, a
    // PING) would otherwise make the kernel reset the connection, and the
    // client could lose the end of a response.
    // SAFETY: nothing else borrows the stream any more (see above).
    let stream = unsafe { &mut *stream.get() };
    super::lingering_close(stream, &mut Vec::new()).await;
}

/// Accept streams and keep the connection going until the client or a
/// GOAWAY ends it.
///
/// At most `max_streams` streams are served at once. The crate counts a
/// stream as open until it is closed, and a client's RST_STREAM closes it
/// at once while the work behind it may go on: without a count of its own,
/// a client could open and reset streams (CVE-2023-44487, "rapid reset")
/// and run as many requests as it liked, keepalive_requests of them per
/// connection. nginx counts its streams until their requests end
/// (`h2c->processing`, ngx_http_v2_state_headers). With all of them busy,
/// new streams wait in the crate, whose own limits then apply: no more than
/// `max_streams` open, and a GOAWAY ENHANCE_YOUR_CALM once 20 of those
/// waiting are reset (`max_pending_accept_reset_streams`).
async fn drive<IO>(
    mut conn: h2::server::Connection<IO, Bytes>,
    ctx: &Rc<ConnCtx>,
    timeouts: super::PreparedClientTimeouts,
    max_streams: usize,
    writing_since: Rc<Cell<Option<std::time::Instant>>>,
    header_blocks: Rc<compat::HeaderBlocks>,
) where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let listen = &ctx.http.listens[ctx.listen_index];
    // The default server's keep-alive settings, as nginx applies its
    // default server's to the connection (ngx_http_v2_state_headers,
    // ngx_http_v2_handle_connection).
    let keepalive = listen.servers[listen.default_server].keepalive;
    let idle = keepalive
        .idle_timeout_ms
        .map_or(IDLE, Duration::from_millis);
    let max_time = Duration::from_millis(keepalive.max_time_ms);
    let started = std::time::Instant::now();
    let mut requests: u64 = 0;
    // Streams in progress; the last to end wakes the loop, for the idle
    // timer, and so does one that makes room under `max_streams`.
    let streams = Rc::new(Streams {
        limit: max_streams,
        ..Streams::default()
    });
    let mut idle_since = monoio::time::Instant::now();
    let mut going_away = false;
    // Gone away with nothing left to send: closed shortly after, also for a
    // client that doesn't answer the GOAWAY's PING.
    let mut drained_at: Option<monoio::time::Instant> = None;
    // Shutdown and reload wake the loop, as they wake idle HTTP/1.1
    // connections: no per-connection tick (#127).
    let watch = super::EventWatch::new();
    loop {
        let now = monoio::time::Instant::now();
        // What the loop waits for besides the connection: the idle
        // deadline, or, while going away, the next look at the drain.
        let wake_at = if going_away {
            Some(now + Duration::from_millis(50))
        } else if streams.active.get() == 0 {
            Some(if !keepalive.allow && requests > 0 {
                now
            } else {
                idle_since + idle
            })
        } else {
            None
        };
        let timer = async {
            match wake_at {
                Some(at) => monoio::time::sleep_until(at).await,
                None => std::future::pending().await,
            }
        };
        // Every stream busy: the connection is driven (frames in and out,
        // new streams queued in the crate) but nothing is accepted.
        let full = streams.active.get() >= max_streams;
        let event = std::future::poll_fn(|cx| {
            if !going_away && ctx.state.is_shutting_down() {
                return std::task::Poll::Ready(());
            }
            if streams.ended_at.get().is_some() {
                return std::task::Poll::Ready(());
            }
            if full && streams.active.get() < max_streams {
                return std::task::Poll::Ready(());
            }
            watch.register(cx.waker());
            streams.waker.set(Some(cx.waker().clone()));
            std::task::Poll::Pending
        });
        let next = std::future::poll_fn(|cx| {
            if !full {
                return conn.poll_accept(cx);
            }
            conn.poll_closed(cx).map(|closed| closed.err().map(Err))
        });
        let accepted = monoio::select! {
            accepted = next => Some(accepted),
            _ = timer => None,
            _ = event => None,
        };
        let now = monoio::time::Instant::now();
        // The connection is idle from when its last stream ended.
        if let Some(at) = streams.ended_at.take() {
            idle_since = at;
        }
        match accepted {
            Some(Some(Ok((request, respond)))) => {
                if let Some(what) =
                    fields_over_limit(&request, timeouts.large_header_line, timeouts.large_header)
                {
                    // A connection error in nginx: GOAWAY, and the crate
                    // ends the connection once it is sent.
                    super::write_worker_log(
                        listen.servers[listen.default_server].error_logs,
                        super::ErrorLogLevel::Info,
                        &format!(
                            "*{} client sent {what} while processing HTTP/2 connection, \
                             client: {}, server: {}",
                            ctx.connection_id,
                            ctx.peer_addr.ip(),
                            listen.addr
                        ),
                    );
                    conn.abrupt_shutdown(h2::Reason::ENHANCE_YOUR_CALM);
                    continue;
                }
                streams.active.set(streams.active.get() + 1);
                let counters = (started, requests);
                let header_block = header_blocks.take(u32::from(respond.stream_id()));
                requests += 1;
                let (http, connection_id, peer_addr) = (ctx.http, ctx.connection_id, ctx.peer_addr);
                let ctx = ctx.clone();
                let streams = streams.clone();
                // Boxed: the stream's future is about 11 KB, and moved by
                // value it was copied four more times per request on its
                // way into the task (callgrind: 99k -> 52k instructions
                // per h2c request).
                monoio::spawn(Contained::new(
                    Box::pin(async move {
                        serve_stream(request, respond, &ctx, counters, header_block).await;
                        streams.end();
                    }),
                    http,
                    connection_id,
                    peer_addr,
                ));
                // nginx: GOAWAY once the connection carried
                // keepalive_requests streams or outlived keepalive_time;
                // the open streams finish.
                if !going_away
                    && (requests >= keepalive.max_requests || started.elapsed() > max_time)
                {
                    conn.graceful_shutdown();
                    going_away = true;
                }
            }
            // The client went away, or the connection failed.
            Some(Some(Err(_))) | Some(None) => break,
            None => {}
        }
        if going_away {
            // Done once the streams are and what they sent is written, or
            // when a write has made no progress for send_timeout.
            let stuck = writing_since
                .get()
                .is_some_and(|since| since.elapsed() >= timeouts.send);
            if streams.active.get() == 0 && !conn.has_streams() && writing_since.get().is_none() {
                let at = *drained_at.get_or_insert(now);
                if now.duration_since(at) >= Duration::from_millis(200) {
                    break;
                }
            } else {
                drained_at = None;
            }
            if stuck {
                break;
            }
            continue;
        }
        // keepalive_timeout bounds a connection without streams (0: closed
        // after its streams), as nginx (http2_idle_timeout is obsolete); a
        // shutdown or reload sends GOAWAY and lets the open streams finish.
        let idle_expired = streams.active.get() == 0
            && ((!keepalive.allow && requests > 0) || now.duration_since(idle_since) >= idle);
        if ctx.state.is_shutting_down() || idle_expired {
            conn.graceful_shutdown();
            going_away = true;
        }
    }
}

/// The crate's bound on a decoded request head (`max_header_list_size`):
/// twice `large_client_header_buffers`' total, and at least 64 KiB.
pub(crate) fn max_header_list(large_header: usize) -> u32 {
    large_header
        .saturating_mul(2)
        .max(64 * 1024)
        .try_into()
        .unwrap_or(u32::MAX)
}

/// What nginx says when a request's fields are over
/// `large_client_header_buffers` (ngx_http_v2_state_field_len,
/// ngx_http_v2_state_process_header): a name or value longer than `field`
/// (the buffer size), or the names and values together, pseudo-headers
/// included, longer than `total` (size × number). nginx compares a
/// Huffman-coded string's length as sent; the crate gives the decoded one.
fn fields_over_limit(
    request: &http::Request<h2::RecvStream>,
    field: usize,
    total: usize,
) -> Option<&'static str> {
    let uri = request.uri();
    let pseudo = [
        (":method", Some(request.method().as_str())),
        (":scheme", uri.scheme_str()),
        (":authority", uri.authority().map(|a| a.as_str())),
        (":path", uri.path_and_query().map(|p| p.as_str())),
    ];
    let fields = pseudo
        .into_iter()
        .filter_map(|(name, value)| Some((name.len(), value?.len())))
        .chain(
            request
                .headers()
                .iter()
                .map(|(name, value)| (name.as_str().len(), value.len())),
        );
    let mut sum = 0usize;
    for (name, value) in fields {
        if name > field || value > field {
            return Some("too large header field");
        }
        sum += name + value;
        if sum > total {
            return Some("too large header");
        }
    }
    None
}

/// A connection's streams in progress, shared with their tasks.
#[derive(Default)]
struct Streams {
    active: Cell<usize>,
    /// `max_streams`: at this many, the loop waits for one to end.
    limit: usize,
    /// When the last one ended, until the loop looks.
    ended_at: Cell<Option<monoio::time::Instant>>,
    waker: Cell<Option<std::task::Waker>>,
}

impl Streams {
    fn end(&self) {
        let active = self.active.get() - 1;
        self.active.set(active);
        if active == 0 {
            self.ended_at.set(Some(monoio::time::Instant::now()));
        }
        if (active == 0 || active + 1 == self.limit)
            && let Some(waker) = self.waker.take()
        {
            waker.wake();
        }
    }
}

/// Whether the server the request goes to has HTTP/2 on. A request for
/// one that doesn't is answered 421, as nginx does when the `Host` names a
/// server other than the one ALPN was negotiated for
/// (ngx_http_set_virtual_server: "client attempted to request the server
/// name different from the one that was negotiated").
fn h2_server(
    listen: &'static super::PreparedListen,
    parts: &http::request::Parts,
    sni: Option<&[u8]>,
) -> bool {
    let host = parts
        .uri
        .authority()
        .map(|a| a.host().as_bytes())
        .or_else(|| {
            parts
                .headers
                .get(http::header::HOST)
                .map(|v| strip_port(v.as_bytes()))
        });
    phase::server_for(listen, host, sni).http2
}

/// `host[:port]` → `host`, brackets of an IPv6 literal kept.
fn strip_port(host: &[u8]) -> &[u8] {
    match host.iter().rposition(|&b| b == b':') {
        Some(i) if !host[i..].contains(&b']') && host[i + 1..].iter().all(u8::is_ascii_digit) => {
            &host[..i]
        }
        _ => host,
    }
}

fn misdirected(mut respond: h2::server::SendResponse<Bytes>) {
    let mut response = http::Response::new(());
    *response.status_mut() = http::StatusCode::MISDIRECTED_REQUEST;
    response.headers_mut().insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("text/plain"),
    );
    if let Ok(mut send) = respond.send_response(response, false) {
        let _ = send.send_data(Bytes::from_static(b"Misdirected Request\n"), true);
    }
}

async fn serve_stream(
    request: http::Request<h2::RecvStream>,
    respond: h2::server::SendResponse<Bytes>,
    ctx: &ConnCtx,
    counters: (std::time::Instant, u64),
    header_block: u64,
) {
    let (parts, body) = request.into_parts();
    let listen = &ctx.http.listens[ctx.listen_index];
    if !listen.http2_listen && !h2_server(listen, &parts, ctx.sni.as_deref()) {
        return misdirected(respond);
    }
    let listen = &ctx.http.listens[ctx.listen_index];
    // The default server's http2_chunk_size, until the request has a
    // location: `handle` then sets the location's (#594).
    let chunk = listen.servers[listen.default_server].timeouts.h2_chunk;
    let mut io = stream::StreamIo::new(&parts, body, respond, counters, chunk, header_block);
    super::handle(
        &mut io,
        ctx.peer_addr,
        ctx.listen_index,
        ctx.sni.as_deref(),
        ctx.tls.as_ref(),
        &ctx.conn,
        ctx.http,
        ctx.state,
        ctx.connection_id,
    )
    .await;
}
