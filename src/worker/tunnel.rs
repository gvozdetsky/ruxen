//! The tunnel after a proxied 101 (#87), as nginx's
//! ngx_http_upstream_upgrade / _process_upgraded: once the upstream has
//! switched protocols, bytes go both ways until either side closes. Bytes
//! already read past the request head (the client's) or the 101's head
//! (the upstream's) go first.
//!
//! The two directions run at once, so a peer that writes without reading
//! can't stall the other way. The upstream connection is split as monoio
//! splits a `TcpStream`; the client connection is borrowed by both
//! directions, which `ConnIo::begin_tunnel` makes safe for TLS (see
//! `TlsStream::begin_tunnel`).
//!
//! Timeouts are nginx's: the tunnel ends after `proxy_read_timeout` with
//! nothing read from either side (nginx re-arms the upstream read timer on
//! every event), a write to the upstream gets `proxy_send_timeout`, a
//! write to the client `send_timeout`. After a reload, an upgraded
//! connection lives on until `worker_shutdown_timeout`, as on an old
//! nginx worker.

use std::cell::{Cell, UnsafeCell};
use std::time::Duration;

use monoio::io::{AsyncReadRent, AsyncWriteRentExt, Splitable};
use monoio::net::TcpStream;
use monoio::time::{Instant, timeout};

use super::{ConnIo, EventWatch, PreparedHttp, RuntimeState};

/// Read size for each direction: one maximum-size TLS record.
const BUF: usize = 16 * 1024;

/// Why a tunnel ended.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum TunnelEnd {
    /// Either side closed, or a read or write failed.
    Closed,
    /// Nothing was read from either side for `proxy_read_timeout`, or a
    /// write to the upstream took longer than `proxy_send_timeout`.
    UpstreamTimedOut,
    /// A write to the client took longer than `send_timeout`.
    ClientTimedOut,
    /// `worker_shutdown_timeout` passed after a reload.
    Shutdown,
}

/// What went through a tunnel.
pub(crate) struct Tunnelled {
    pub to_client: u64,
    pub to_upstream: u64,
    pub from_upstream: u64,
    pub end: TunnelEnd,
}

/// Timeouts and context for `run_tunnel`.
pub(crate) struct TunnelConf<'a> {
    pub read_timeout: Duration,
    pub upstream_send_timeout: Duration,
    pub client_send_timeout: Duration,
    pub http: &'static PreparedHttp,
    pub state: &'a RuntimeState,
    pub start_reload_gen: u64,
}

pub(crate) async fn run_tunnel<S: ConnIo>(
    client: &mut S,
    upstream: TcpStream,
    client_early: &[u8],
    upstream_early: Vec<u8>,
    conf: TunnelConf<'_>,
) -> Tunnelled {
    client.begin_tunnel();
    let (mut up_read, mut up_write) = upstream.into_split();
    let client = UnsafeCell::from_mut(client);
    let activity = Cell::new(Instant::now());
    let to_client = Cell::new(0u64);
    let to_upstream = Cell::new(0u64);
    let from_upstream = Cell::new(0u64);

    let downstream = async {
        let mut buf = upstream_early;
        buf.reserve(BUF.saturating_sub(buf.len()));
        loop {
            if !buf.is_empty() {
                // SAFETY: the other direction only reads from the client
                // (see `begin_tunnel`); this is the only writer.
                let c = unsafe { &mut *client.get() };
                let (res, returned) =
                    match timeout(conf.client_send_timeout, c.write_all(buf)).await {
                        Ok(pair) => pair,
                        Err(_) => return TunnelEnd::ClientTimedOut,
                    };
                buf = returned;
                match res {
                    Ok(n) => to_client.set(to_client.get() + n as u64),
                    Err(_) => return TunnelEnd::Closed,
                }
                activity.set(Instant::now());
            }
            buf.clear();
            let (res, returned) = up_read.read(buf).await;
            buf = returned;
            match res {
                Ok(0) | Err(_) => return TunnelEnd::Closed,
                Ok(n) => from_upstream.set(from_upstream.get() + n as u64),
            }
            activity.set(Instant::now());
        }
    };

    let upstream_dir = async {
        let mut buf = Vec::with_capacity(BUF);
        buf.extend_from_slice(client_early);
        loop {
            if !buf.is_empty() {
                let (res, returned) =
                    match timeout(conf.upstream_send_timeout, up_write.write_all(buf)).await {
                        Ok(pair) => pair,
                        Err(_) => return TunnelEnd::UpstreamTimedOut,
                    };
                buf = returned;
                match res {
                    Ok(n) => to_upstream.set(to_upstream.get() + n as u64),
                    Err(_) => return TunnelEnd::Closed,
                }
                activity.set(Instant::now());
            }
            buf.clear();
            // SAFETY: the other direction only writes to the client; this
            // is the only reader.
            let c = unsafe { &mut *client.get() };
            let (res, returned) = c.read(buf).await;
            buf = returned;
            match res {
                Ok(0) | Err(_) => return TunnelEnd::Closed,
                Ok(_) => {}
            }
            activity.set(Instant::now());
        }
    };

    let idle = async {
        loop {
            let due = activity.get() + conf.read_timeout;
            if Instant::now() >= due {
                return TunnelEnd::UpstreamTimedOut;
            }
            monoio::time::sleep_until(due).await;
        }
    };

    let reload = async {
        let watch = EventWatch::new();
        std::future::poll_fn(|cx| {
            if conf.state.reload_gen() != conf.start_reload_gen {
                return std::task::Poll::Ready(());
            }
            watch.register(cx.waker());
            std::task::Poll::Pending
        })
        .await;
        match conf.http.shutdown_timeout {
            Some(limit) => monoio::time::sleep(limit).await,
            None => std::future::pending().await,
        }
        TunnelEnd::Shutdown
    };

    let end = monoio::select! {
        end = downstream => end,
        end = upstream_dir => end,
        end = idle => end,
        end = reload => end,
    };
    Tunnelled {
        to_client: to_client.get(),
        to_upstream: to_upstream.get(),
        from_upstream: from_upstream.get(),
        end,
    }
}
