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
    S: AsyncReadRent + AsyncWriteRent + 'static,
{
    let ctx = Rc::new(ctx);
    let listen = &ctx.http.listens[ctx.listen_index];
    let timeouts = listen.servers[listen.default_server].timeouts;
    let io = compat::PollIo::new(stream);
    // What nginx announces (ngx_http_v2_send_settings): 128 concurrent
    // streams (http2_max_concurrent_streams), a 64 KiB stream window
    // (http2_body_preread_size) and the largest frame size; then it opens
    // the connection window to the maximum with a WINDOW_UPDATE
    // (ngx_http_v2_init). Clients such as Test::Nginx wait for both.
    let handshake = h2::server::Builder::new()
        .max_concurrent_streams(128)
        .initial_window_size(64 * 1024)
        .max_frame_size((1 << 24) - 1)
        .initial_connection_window_size((1 << 31) - 1)
        .handshake::<_, Bytes>(io);
    // The preface and SETTINGS come under client_header_timeout, as the
    // first request line would.
    let mut conn = match monoio::time::timeout(timeouts.header, handshake).await {
        Ok(Ok(conn)) => conn,
        _ => return,
    };
    let active = Rc::new(Cell::new(0usize));
    let mut idle_since = Some(monoio::time::Instant::now());
    let mut going_away = false;
    loop {
        let accepted = monoio::time::timeout(Duration::from_millis(50), conn.accept()).await;
        match accepted {
            Ok(Some(Ok((request, respond)))) => {
                idle_since = None;
                active.set(active.get() + 1);
                let (http, connection_id, peer_addr) = (ctx.http, ctx.connection_id, ctx.peer_addr);
                let ctx = ctx.clone();
                let active = active.clone();
                monoio::spawn(Contained::new(
                    async move {
                        serve_stream(request, respond, &ctx).await;
                        active.set(active.get() - 1);
                    },
                    http,
                    connection_id,
                    peer_addr,
                ));
            }
            // The client went away, or the connection failed.
            Ok(Some(Err(_))) | Ok(None) => break,
            Err(_) => {}
        }
        if going_away {
            continue;
        }
        // keepalive_timeout bounds an HTTP/2 connection without streams, as
        // nginx (http2_idle_timeout is obsolete); a shutdown or reload
        // sends GOAWAY and lets the open streams finish.
        let now = monoio::time::Instant::now();
        if active.get() > 0 {
            idle_since = None;
        } else if idle_since.is_none() {
            idle_since = Some(now);
        }
        let idle_expired = idle_since.is_some_and(|since| now.duration_since(since) >= IDLE);
        if ctx.state.is_shutting_down() || idle_expired {
            conn.graceful_shutdown();
            going_away = true;
        }
    }
}

async fn serve_stream(
    request: http::Request<h2::RecvStream>,
    respond: h2::server::SendResponse<Bytes>,
    ctx: &ConnCtx,
) {
    let (parts, body) = request.into_parts();
    let mut io = stream::StreamIo::new(&parts, body, respond);
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
