// Reverse proxy / upstream forwarder.
//
// The path negotiates response framing (Content-Length /
// Transfer-Encoding: chunked / Connection: close), supports
// `proxy_http_version 1.1`, applies proxy_next_upstream failover, and
// returns reusable upstream sockets to the per-worker keepalive pool.
//
// The plan is built synchronously by `worker::run_location_handler` (in
// the `PreparedHandler::Proxy` arm) and packaged into
// `Response::Proxy(plan)`. The worker connection task awaits
// `run_proxy(plan)` after `process_with_meta` returns, then feeds the
// resulting bytes back into the existing write path (Connection-header
// injection, access logging, etc.). This keeps phase.rs itself sync and
// isolates monoio I/O to one site.
//
// Notes from `ngx_http_upstream.c` and `ngx_http_upstream_keepalive_module.c`
// are distilled in DESIGN.md.

use std::cell::RefCell;
use std::time::Duration;
use std::time::Instant;

use crate::worker::lazy_timeout as timeout;
use monoio::io::AsyncReadRent;
use monoio::io::AsyncWriteRentExt;
use monoio::net::TcpStream;

use crate::upstream_io::UpstreamIo;

use crate::config::ProxyNextUpstream;
use crate::http::Method;
use crate::phase::Response;
use crate::upstream;
use crate::upstream::LeasedPeer;
use crate::worker::PeerAddr;
use crate::worker::PreparedUpstream;
use crate::worker::range::RangeAllow;

// Per-worker reusable scratch buffers for proxy::attempt. The proxy hot path
// otherwise allocates `accum` (~4 KiB) and `read_buf` (4 KiB zero-filled) on
// every upstream request — at >500 k req/s that's ~10M alloc/s plus 4 GB/s of
// memset. The pool returns the same buffer on subsequent requests; the
// kernel-write read side never reads from uninit bytes, so we avoid the
// zero-fill by tracking capacity rather than length.
const PROXY_SCRATCH_CAP: usize = 4096;
const PROXY_POOL_LIMIT: usize = 32;

thread_local! {
    static PROXY_BUF_POOL: RefCell<Vec<Vec<u8>>> = const { RefCell::new(Vec::new()) };
}

fn take_proxy_buf() -> Vec<u8> {
    PROXY_BUF_POOL.with(|p| {
        if let Some(mut v) = p.borrow_mut().pop() {
            v.clear();
            return v;
        }
        Vec::with_capacity(PROXY_SCRATCH_CAP)
    })
}

pub(crate) fn return_proxy_buf(mut v: Vec<u8>) {
    // Cap individual buffer growth so a giant chunked body doesn't keep an
    // oversized Vec alive in the pool forever.
    // And a smaller one would come back as a read buffer: a read into no
    // room returns 0, which looks like the upstream closing.
    if v.capacity() > PROXY_SCRATCH_CAP * 16 || v.capacity() < PROXY_SCRATCH_CAP {
        return;
    }
    v.clear();
    PROXY_BUF_POOL.with(|p| {
        let mut pool = p.borrow_mut();
        if pool.len() < PROXY_POOL_LIMIT {
            pool.push(v);
        }
    });
}

/// Per-request upstream attempt plan. Built synchronously inside the
/// location handler; consumed by `run_proxy` on the worker async task.
pub struct ProxyPlan {
    /// Pointer to the prepared upstream (owns peers + keepalive config).
    pub upstream: &'static PreparedUpstream,
    /// `proxy_pass` with variables naming an address (#100): the one peer
    /// to use instead of `upstream`'s, which is then a placeholder.
    /// Boxed: only a `proxy_pass` with variables has one, and the plan
    /// moves with every proxied response.
    pub adhoc_peer: Option<Box<PeerAddr>>,
    /// `proxy_pass https://` (#116): TLS over the connection to the peer.
    pub tls: Option<Box<crate::upstream_tls::TlsPlan>>,
    /// First peer to try, leased at plan-build time. Subsequent
    /// `proxy_next_upstream` retries lease their own peers inside
    /// `run_proxy`. Wrapped in `Option` so the run loop can `.take()`
    /// without fighting partial moves out of the plan struct.
    pub initial_peer: Option<LeasedPeer>,
    /// Pre-rendered upstream request bytes — request line + headers +
    /// `\r\n\r\n` + body. The location handler folds proxy_set_header
    /// overrides + the forwarded client header set into this buffer
    /// before handing the plan off. Stored as `Bytes` (refcounted slice)
    /// so per-attempt cloning is an Arc bump, not an alloc + memcpy —
    /// matters because retries hold the original while the in-flight
    /// `write_all` consumes a clone.
    pub request: bytes::Bytes,
    /// A large client body, sent after `request` from the request's own
    /// buffer (shared, not copied); empty when the body is in `request`.
    pub body: bytes::Bytes,
    /// Method of the *client* request — needed to strip the body for
    /// HEAD responses on the way back when the upstream sends one
    /// anyway.
    pub method: Method,
    /// The method sent upstream is HEAD (compared case-insensitively, as
    /// nginx sets `ctx->head`), so its response has no body.
    pub upstream_head: bool,
    /// `Server:` header bytes for synthesized 502/504 errors.
    #[allow(dead_code)]
    pub server_bytes: &'static [u8],
    pub connect_timeout: Duration,
    pub read_timeout: Duration,
    pub send_timeout: Duration,
    /// `proxy_limit_rate` in bytes/sec; `0` means unlimited. When non-zero,
    /// the response-body read loop sleeps after each chunk so that the total
    /// bytes received from the upstream don't outpace this rate.
    pub limit_rate: u64,
    /// Cached `Bad Gateway` prebuilt for connect/upstream-protocol errors.
    pub bad_gateway: &'static crate::worker::Prebuilt,
    /// Cached `Gateway Timeout` prebuilt for any timeout in the attempt.
    pub gateway_timeout: &'static crate::worker::Prebuilt,
    /// True when the upstream attempt is HTTP/1.1 + the upstream block
    /// has `keepalive N;` configured. Drives whether `run_proxy` returns
    /// the socket to the pool or drops it.
    pub keepalive_eligible: bool,
    /// `proxy_next_upstream` mask — gates failover triggers across the
    /// retry loop.
    pub next_upstream: ProxyNextUpstream,
    /// `proxy_next_upstream_tries` cap. `0` = "as many as we have peers".
    pub next_upstream_tries: u32,
    /// `proxy_next_upstream_timeout` overall budget. `Duration::ZERO`
    /// means no overall cap (per-attempt timeouts still apply).
    pub next_upstream_timeout: Duration,
    /// False for POST, LOCK and PATCH, the methods nginx won't send to
    /// another peer once the request went out, unless
    /// `proxy_next_upstream non_idempotent` is set (with or without a
    /// body). Every other method counts as idempotent there.
    pub method_idempotent: bool,
    /// The proxied location was reached as an error page, so its own
    /// `error_page` doesn't apply again (no `recursive_error_pages`).
    pub in_error_page: bool,
    /// `proxy_intercept_errors on;` (M43): when `Some`, an upstream
    /// status that matches one of these rules is reflected back as a
    /// `Response::Reroute` instead of being forwarded to the client. The
    /// rules are pre-rendered (against the request's `RenderCtx`) at
    /// plan-build time, so `run_proxy` doesn't need to re-render
    /// `$variables`.
    pub intercept: Option<Vec<InterceptRule>>,
    /// A request body too large to keep in memory: sent from this file
    /// after `request` (which then holds only the header block).
    pub body_file: Option<RequestBodyFile>,
    /// Keep the upstream's header lines in `ProxyReport` because the
    /// location's add_header / add_trailer may read `$upstream_http_*`.
    pub keep_upstream_headers: bool,
    /// Header rules for the response: `proxy_redirect` (applied by the
    /// worker when `ProxyReport::redirect_header` is set), and the hide /
    /// pass lists.
    pub response: &'static crate::worker::ProxyResponseRules,
    /// The client asked for a protocol switch (an `Upgrade` header): an
    /// upstream 101 then turns the connection into a tunnel
    /// (ngx_http_proxy_process_header, `u->upgrade`).
    pub upgrade: bool,
    /// `proxy_cache` (#233): `None` unless the location has one and the
    /// request may use it.
    pub cache: Option<Box<CachePlan>>,
    /// A hash balancer's state for this request (`hash`, `ip_hash`), which
    /// `proxy_next_upstream` picks continue from.
    pub hash: Option<Box<upstream::HashPick>>,
    /// `proxy_bind` for this request: the local address new upstream
    /// connections are bound to. Pooled ones are reused as they are.
    pub bind: Option<LocalBind>,
    /// A body that doesn't arrive with the header may be relayed as it
    /// comes (#88): nothing on this location needs it whole (no cache or
    /// `add_trailer`), and this is the request's first pass.
    pub stream: bool,
    /// `proxy_force_ranges`: the range filter may cut the response whatever
    /// the upstream says (#370).
    pub force_ranges: bool,
    /// `proxy_ignore_client_abort`: when off, a client that closes while
    /// the upstream is awaited ends the exchange with 499 (#136).
    pub ignore_client_abort: bool,
}

/// An upstream that answered 101 to a client asking to upgrade: the
/// response head for the client and the connection to tunnel to.
pub struct Upgraded {
    pub head: Vec<u8>,
    pub upstream: UpstreamIo,
    /// Bytes the upstream sent past its head, already read.
    pub leftover: Vec<u8>,
    /// The worker_connections slot the upstream connection holds.
    pub slot: crate::worker::UpstreamSlot,
    /// `proxy_read_timeout` / `proxy_send_timeout`.
    pub read_timeout: Duration,
    pub send_timeout: Duration,
    /// `upstream: "…"` for the error log.
    pub upstream_url: String,
    /// The peer stays leased while the tunnel is open, so `least_conn`
    /// counts it, as nginx frees the peer only when the request ends.
    pub lease: Option<LeasedPeer>,
}

/// A request's view of its `proxy_cache`: what the lookup found, and what
/// storing the response needs.
pub struct CachePlan {
    pub conf: &'static crate::worker::PreparedProxyCache,
    pub zone: &'static crate::proxy_cache::CacheZone,
    pub key: Vec<u8>,
    pub hash: crate::proxy_cache::CacheHash,
    pub status: crate::proxy_cache::CacheStatus,
    /// The response may be stored (`proxy_cache_min_uses` reached, no
    /// `proxy_no_cache` condition holds).
    pub store: bool,
    /// nginx's `u->cacheable` before `proxy_no_cache` is tested:
    /// `proxy_cache_min_uses` is reached. The upstream then gets no
    /// conditional or range headers, and an `Accept-Ranges` from it lets
    /// the range filter cut the response (#370).
    pub cacheable: bool,
    /// The answer the cache already has.
    pub hit: Option<CacheHit>,
    /// The stale response, kept with `proxy_cache_revalidate` to answer
    /// with if the upstream says 304.
    pub stale: Option<crate::proxy_cache::Entry>,
    /// The client's request header block, for the variant of a response
    /// with `Vary`.
    pub request_headers: Vec<u8>,
    /// A HEAD request went upstream as a GET, so the body can be stored
    /// (`proxy_cache_convert_head`).
    pub head_as_get: bool,
    /// This request fetches the response for everyone (nginx's
    /// `updating`: a stale entry's update, or `proxy_cache_lock`); the
    /// zone forgets it when the plan is dropped.
    pub token: Option<u64>,
    /// Another request holds `proxy_cache_lock`: wait for it until then.
    pub wait_until: Option<Instant>,
    /// `hit` is a stale response: send it, then update it in the
    /// background (`proxy_cache_background_update`).
    pub background: bool,
    /// The stale response's `stale-if-error` still covers it.
    pub stale_error: bool,
}

impl Drop for CachePlan {
    fn drop(&mut self) {
        if let Some(token) = self.token {
            self.zone.release(&self.hash, token);
        }
    }
}

pub enum CacheHit {
    Entry(crate::proxy_cache::Entry),
    /// A cached intercepted error.
    Error(u16),
}

/// A response `attempt` found cacheable: its upstream header block (the
/// file keeps it, and a hit filters it again) and freshness. The body is
/// the client response's, after `client_head_len` bytes.
struct Storable {
    head: Vec<u8>,
    valid_sec: i64,
    updating_sec: i64,
    error_sec: i64,
    vary: Vec<u8>,
    client_head_len: usize,
}

/// Bodies up to this size are copied into the upstream request buffer
/// (one buffer, one write); larger ones are sent from their own buffer with
/// one writev, which keeps a body-sized copy per request out of the cache.
pub const SEPARATE_BODY_MIN: usize = 16 * 1024;

/// The upstream request header block and a body, owned by the writev
/// operation (monoio keeps it until the kernel is done, also when the
/// attempt is cancelled by a timeout, so the pooled buffers can't be
/// reused while they are being sent).
struct RequestParts {
    head: bytes::Bytes,
    body: bytes::Bytes,
    /// Boxed so its address stays put while the value moves around.
    iov: Box<[libc::iovec; 2]>,
}

impl RequestParts {
    fn new(head: bytes::Bytes, body: bytes::Bytes) -> Self {
        let empty = libc::iovec {
            iov_base: std::ptr::null_mut(),
            iov_len: 0,
        };
        let mut parts = RequestParts {
            head,
            body,
            iov: Box::new([empty, empty]),
        };
        parts.set_iov();
        parts
    }

    fn set_iov(&mut self) {
        for (iov, part) in self.iov.iter_mut().zip([&self.head, &self.body]) {
            iov.iov_base = part.as_ptr() as *mut libc::c_void;
            iov.iov_len = part.len();
        }
    }

    fn len(&self) -> usize {
        self.head.len() + self.body.len()
    }

    /// Drop the first `n` bytes, which were written.
    fn advance(&mut self, n: usize) {
        let from_head = n.min(self.head.len());
        bytes::Buf::advance(&mut self.head, from_head);
        bytes::Buf::advance(&mut self.body, n - from_head);
        self.set_iov();
    }
}

// SAFETY: the iovecs point into `head` and `body`, which the value owns
// and doesn't change while the runtime holds it; the boxed array keeps its
// address when the value moves.
unsafe impl monoio::buf::IoVecBuf for RequestParts {
    fn read_iovec_ptr(&self) -> *const libc::iovec {
        self.iov.as_ptr()
    }
    fn read_iovec_len(&self) -> usize {
        2
    }
}

/// Write the header block and the body with writev until both are sent.
async fn write_request_parts(
    stream: &mut UpstreamIo,
    head: bytes::Bytes,
    body: bytes::Bytes,
) -> std::io::Result<()> {
    let mut parts = RequestParts::new(head, body);
    while parts.len() > 0 {
        let (res, returned) = monoio::io::AsyncWriteRent::writev(stream, parts).await;
        parts = returned;
        match res {
            Ok(0) => return Err(std::io::ErrorKind::WriteZero.into()),
            Ok(n) => parts.advance(n),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// The temp file holding a large request body (an open descriptor: the
/// name may already be gone), and its length.
pub struct RequestBodyFile {
    pub file: std::fs::File,
    pub len: u64,
}

/// One pre-rendered `error_page` rule for the intercept path. Mirrors
/// `PreparedErrorPage` but with the `target` bytes already rendered for
/// this specific request.
pub struct InterceptRule {
    pub status: u16,
    pub action: crate::worker::PreparedErrorPageAction,
    pub target: Vec<u8>,
}

#[allow(dead_code)] // direct callers without a plan still want hardcoded fallback constants
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(60);
#[allow(dead_code)]
pub const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(60);
#[allow(dead_code)]
pub const DEFAULT_SEND_TIMEOUT: Duration = Duration::from_secs(60);

/// One header to write into the upstream request line block. Names are
/// fixed bytes; values are owned (already-rendered).
pub struct ProxyHeader<'a> {
    pub name: &'a [u8],
    pub value: &'a [u8],
}

/// `write_request` into a fresh buffer.
#[cfg(test)]
pub fn build_request_bytes_with_headers(
    method_bytes: &[u8],
    uri: &[u8],
    http_version_minor: u8,
    headers: &[ProxyHeader<'_>],
    body: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::new();
    write_request(
        &mut buf,
        method_bytes,
        uri,
        http_version_minor,
        headers,
        body,
    );
    buf
}

/// Append the upstream request bytes to `buf` (the caller brings a pooled
/// buffer). `http_version_minor` selects HTTP/1.0 vs HTTP/1.1. The headers
/// slice is the final ordered set: caller is
/// responsible for any `Connection:` header (no auto-injection here —
/// nginx + the keepalive module manage Connection via `proxy_set_header`
/// instead, and ruxen mirrors that). A `Host:` header MUST be present.
pub fn write_request(
    buf: &mut Vec<u8>,
    method_bytes: &[u8],
    uri: &[u8],
    http_version_minor: u8,
    headers: &[ProxyHeader<'_>],
    body: &[u8],
) {
    let mut size = method_bytes.len() + uri.len() + body.len() + 64;
    for h in headers {
        size += h.name.len() + h.value.len() + 4;
    }
    buf.reserve(size);
    buf.extend_from_slice(method_bytes);
    buf.push(b' ');
    buf.extend_from_slice(uri);
    buf.extend_from_slice(if http_version_minor == 1 {
        b" HTTP/1.1\r\n"
    } else {
        b" HTTP/1.0\r\n"
    });
    for h in headers {
        // Skip empty-value headers — nginx semantics for
        // `proxy_set_header NAME ""` is "do not forward this header".
        if h.value.is_empty() {
            continue;
        }
        buf.extend_from_slice(h.name);
        buf.extend_from_slice(b": ");
        buf.extend_from_slice(h.value);
        buf.extend_from_slice(b"\r\n");
    }
    buf.extend_from_slice(b"\r\n");
    buf.extend_from_slice(body);
}

#[cfg(test)]
pub fn build_request_bytes(method_bytes: &[u8], uri: &[u8], host_header: &[u8]) -> Vec<u8> {
    build_request_bytes_with_headers(
        method_bytes,
        uri,
        0,
        &[
            ProxyHeader {
                name: b"Host",
                value: host_header,
            },
            ProxyHeader {
                name: b"Connection",
                value: b"close",
            },
        ],
        &[],
    )
}

/// True when the named request header isn't forwarded upstream as the
/// client sent it (`is_hop_by_hop`).
pub fn is_hop_by_hop_name(name: &[u8]) -> bool {
    is_hop_by_hop(name)
}

/// Run an upstream attempt with `proxy_next_upstream` failover. Returns a
/// `Response` ready to flow into the existing write path. The high-level
/// shape mirrors nginx's `ngx_http_upstream_next` (line 4573):
///
///   - Attempt with the leased peer (or a pooled conn for it).
///   - On a stale-pool first-write failure with an idempotent method
///     (or `proxy_next_upstream non_idempotent` set), retry once on a
///     fresh socket against the same peer.
///   - On a "real" failure (connect/timeout/protocol/upstream-status):
///     report the failure to the LB; if `next_upstream` allows AND we
///     haven't exhausted `next_upstream_tries` AND idempotency permits,
///     pick the next peer (with the tried mask blocking the failed one)
///     and retry.
///   - Pool the upstream socket on success when the upstream and request
///     framing both permit it.
/// Record a failed attempt for the error log. Out of line and cold so the
/// formatting stays out of the retry loop's code.
#[cold]
#[inline(never)]
fn record_failure(
    failures: &mut Vec<AttemptFailure>,
    plan: &ProxyPlan,
    peer_idx: usize,
    error: Box<UpstreamError>,
) {
    failures.push(AttemptFailure {
        error: *error,
        upstream: upstream_url(plan, peer_idx),
    });
}

/// `http://<peer><URI>` for `upstream: "…"` in error-log lines; the URI is
/// taken from the request line already built for the upstream.
fn upstream_url(plan: &ProxyPlan, peer_idx: usize) -> String {
    let uri = upstream_uri(plan);
    let addr = plan.peer_addr(peer_idx);
    // nginx puts a `:` between a socket path and the URI
    // (ngx_http_log_error_handler).
    let separator = match addr {
        PeerAddr::Unix(_) => ":",
        PeerAddr::Inet(_) => "",
    };
    let scheme = if plan.tls.is_some() { "https" } else { "http" };
    format!(
        "{scheme}://{addr}{separator}{}",
        String::from_utf8_lossy(uri)
    )
}

fn upstream_uri(plan: &ProxyPlan) -> &[u8] {
    let request_line = plan.request.split(|&b| b == b'\n').next().unwrap_or(&[]);
    request_line.split(|&b| b == b' ').nth(1).unwrap_or(b"/")
}

impl ProxyPlan {
    /// The address of `upstream.peers[peer_idx]`, or the request's own peer.
    fn peer_addr(&self, peer_idx: usize) -> PeerAddr {
        match &self.adhoc_peer {
            Some(addr) => **addr,
            None => self.upstream.peers[peer_idx].addr,
        }
    }
}

/// Run the upstream exchange, with `proxy_next_upstream` failover. Each
/// failed attempt is appended to `failures` so the worker can log it with
/// the request's context; on the happy path nothing is pushed and the
/// caller's empty `Vec` never allocates.
pub async fn run_proxy(mut plan: Box<ProxyPlan>, report: &mut ProxyReport) -> Response {
    report.passes_date = plan.response.passes_date;
    if let Some(cache) = plan.cache.as_deref_mut() {
        if cache.wait_until.is_some() {
            Box::pin(wait_for_lock(cache)).await;
        }
        report.cache_status = Some(cache.status);
        if let Some(hit) = cache.hit.take() {
            let response = cached_response(&plan, hit, report);
            if plan.cache.as_ref().is_some_and(|c| c.background) {
                monoio::spawn(background_update(plan));
            }
            return response;
        }
    }
    let mut storable: Option<Storable> = None;
    let failures = &mut report.failures;
    let upstream_headers = &mut report.upstream_headers;
    let redirect_header = &mut report.redirect_header;
    let range_allow = &mut report.range_allow;
    let accel = &mut report.accel;
    let states = &mut report.states;
    let attempt_started = &mut report.attempt_started;
    let upstream = plan.upstream;
    // nginx's `peer.tries`: the servers not marked `down`
    // (ngx_http_upstream_tries).
    let live = upstream.peers.iter().filter(|p| !p.down).count();
    let max_tries = compute_max_tries(plan.next_upstream_tries, live);
    let overall_deadline = if plan.next_upstream_timeout.is_zero() {
        None
    } else {
        Some(Instant::now() + plan.next_upstream_timeout)
    };
    // Take ownership of the initial leased peer. `current` always names
    // the peer we're about to try; `tried` records peers already
    // attempted (and reported FAILED) so the next pick skips them.
    // No initial peer: every peer is `down` or cooling off after
    // `max_fails`.
    let Some(mut current) = plan.initial_peer.take() else {
        // No peer left: nginx's FT_NOLIVE, which `proxy_cache_use_stale error`
        // covers (ngx_http_proxy_merge_loc_conf).
        let resp = no_live_upstreams(&plan, states, failures);
        if let Some(stale) = stale_answer(&mut plan, report, StaleCase::Failed(FailKind::Error)) {
            return stale;
        }
        return resp;
    };
    let mut tried = upstream::Tried::default();
    tried.insert(current.peer_idx);
    let mut attempts: u32 = 0;
    // nginx's NGX_HTTP_UPSTREAM_FT_NON_IDEMPOTENT: once the request went
    // out, POST/LOCK/PATCH move to the next peer only with
    // `proxy_next_upstream non_idempotent`. Before that (connect failed)
    // any request may.
    let sent_may_retry = plan.method_idempotent || plan.next_upstream.non_idempotent;
    // Tracks the last response we'd return if the next failover branch
    // doesn't fire. The first iteration always overwrites it before any
    // read — `unused_assignments` complains about the initializer, but
    // returning a generic 502 if every peer is unreachable mid-loop is
    // safer than juggling MaybeUninit.
    #[allow(unused_assignments)]
    let mut last_failure: Option<Response> = None;

    loop {
        attempts += 1;
        let started = Instant::now();
        // In place from the start: if the exchange is dropped mid-attempt
        // (the client went away, #136), the attempt still reaches the log.
        *attempt_started = Some(started);
        states.push(UpstreamState::new(UpstreamPeerName::Addr(
            plan.peer_addr(current.peer_idx),
        )));
        let state = states.last_mut().expect("just pushed");
        // 1. Try the pool first for this peer. On any failure before the
        //    response headers parse, drop the socket and retry once with
        //    a fresh connect — the pooled conn was likely stale. The
        //    stale-retry counts as part of the same `attempt` budget.
        let pooled = upstream::pool_take(upstream, current.peer_idx, plan.tls.as_deref());
        let outcome = if let Some(c) = pooled {
            match attempt(
                &plan,
                current.peer_idx,
                Some(c),
                upstream_headers,
                redirect_header,
                range_allow,
                accel,
                &mut *state,
                started,
                &mut storable,
            )
            .await
            {
                AttemptOutcome::PooledStale => {
                    // M43: only retry the same peer with a fresh socket
                    // if the body can be safely re-sent. The stale socket
                    // isn't an attempt of its own in nginx's terms.
                    *state = UpstreamState::new(state.peer);
                    if sent_may_retry {
                        attempt(
                            &plan,
                            current.peer_idx,
                            None,
                            upstream_headers,
                            redirect_header,
                            range_allow,
                            accel,
                            &mut *state,
                            started,
                            &mut storable,
                        )
                        .await
                    } else {
                        AttemptOutcome::Failed(
                            Response::Prebuilt(plan.bad_gateway.pick(plan.method)),
                            FailKind::Error,
                            Box::new(UpstreamError::PrematurelyClosed(Stage::ReadingHeader)),
                        )
                    }
                }
                other => other,
            }
        } else {
            attempt(
                &plan,
                current.peer_idx,
                None,
                upstream_headers,
                redirect_header,
                range_allow,
                accel,
                &mut *state,
                started,
                &mut storable,
            )
            .await
        };
        state.response_ms = Some(elapsed_ms(started));
        if let AttemptOutcome::Failed(_, kind, _) = &outcome {
            state.status = if matches!(kind, FailKind::Timeout) {
                504
            } else {
                502
            };
        }

        match outcome {
            AttemptOutcome::Ok(resp) => {
                // Inspect status against next_upstream's http_* mask. A
                // status that triggers failover is treated like a soft
                // failure (the upstream answered, but we want to retry
                // elsewhere).
                let status = response_status(&resp).unwrap_or(0);
                // nginx moves on only while a try is left
                // (ngx_http_upstream_test_next: `u->peer.tries > 1`, the
                // request may be re-sent, the timeout hasn't passed).
                // Otherwise the response is the answer, like any other:
                // the peer isn't blamed and proxy_intercept_errors applies.
                if plan.next_upstream.matches_status(status)
                    && attempts < max_tries
                    && sent_may_retry
                    && !deadline_exceeded(overall_deadline)
                {
                    // http_403 / http_404 move on without counting against
                    // max_fails (NGX_PEER_NEXT, ngx_http_upstream_next);
                    // 5xx and 429 are failures.
                    if matches!(status, 403 | 404) {
                        upstream::report_success(upstream, current.peer_idx);
                    } else {
                        upstream::report_failure(upstream, current.peer_idx);
                    }
                    let Some(next) =
                        upstream::pick_peer(upstream, &tried, plan.hash.as_deref_mut())
                    else {
                        // No peer left: nginx's FT_NOLIVE, which `proxy_cache_use_stale error`
                        // covers (ngx_http_proxy_merge_loc_conf).
                        let resp = no_live_upstreams(&plan, states, failures);
                        if let Some(stale) =
                            stale_answer(&mut plan, report, StaleCase::Failed(FailKind::Error))
                        {
                            return stale;
                        }
                        return resp;
                    };
                    tried.insert(next.peer_idx);
                    drop(current);
                    current = next;
                    continue;
                }
                // Healthy response — record the success on the LB. Then
                // check `proxy_intercept_errors`: an upstream status that
                // matches a configured `error_page` rule turns into a
                // Reroute instead of being forwarded.
                upstream::report_success(upstream, current.peer_idx);
                // ngx_http_upstream_test_next: a status
                // proxy_cache_use_stale lists is answered from the cache.
                if let Some(stale) = stale_answer(&mut plan, report, StaleCase::Status(status)) {
                    return stale;
                }
                if status == 304
                    && let Some(cache) = plan.cache.as_deref_mut()
                    && cache.conf.revalidate
                    && let Some(stale) = cache.stale.take()
                {
                    revalidate(cache, &stale, storable.take());
                    report.cache_status = Some(crate::proxy_cache::CacheStatus::Revalidated);
                    return cached_response(&plan, CacheHit::Entry(stale), report);
                }
                let intercepted = plan
                    .intercept
                    .as_ref()
                    .and_then(|rules| rules.iter().find(|r| r.status == status));
                let mut resp = resp;
                if let Some(cache) = plan.cache.as_deref() {
                    if let Some(storable) = storable.take() {
                        store_response(cache, storable, status, intercepted.is_some(), &resp);
                        // The client may already have it (#349): the
                        // not-modified filter of a cacheable response.
                        if status == 200 && intercepted.is_none() {
                            conditional_fresh(&plan, cache, &mut resp);
                        }
                    }
                    if cache.head_as_get {
                        strip_body(&mut resp);
                    }
                }
                if let Some(rule) = intercepted {
                    return build_intercept_reroute(
                        rule,
                        status,
                        resp,
                        plan.response.recursive_error_pages,
                        plan.method,
                        plan.server_bytes,
                    );
                }
                // This try is still in flight while the response header is
                // filtered: nginx's response_time is -1 (`-`) until the
                // upstream request is finalized.
                if let Some(state) = report.states.last_mut() {
                    state.in_flight = true;
                }
                if let Response::Upgrade(upgraded) = &mut resp {
                    upgraded.lease = Some(current);
                } else if let Response::ProxyStream(body) = &mut resp {
                    body.lease = Some(current);
                }
                return resp;
            }
            AttemptOutcome::NoConnection => {
                return crate::worker::internal_error_response(plan.method);
            }
            AttemptOutcome::LocalError(error) => {
                record_failure(failures, &plan, current.peer_idx, error);
                return crate::worker::internal_error_response(plan.method);
            }
            AttemptOutcome::PooledStale => {
                // The pre-match collapses PooledStale into either a fresh
                // retry or a Failed; reaching here is a logic bug.
                unreachable!("ruxen: pooled-stale outcome leaked past stale-retry collapse");
            }
            AttemptOutcome::Failed(resp, kind, error) => {
                upstream::report_failure(upstream, current.peer_idx);
                let sent = !matches!(
                    *error,
                    UpstreamError::ConnectFailed(_)
                        | UpstreamError::UnixConnectFailed(..)
                        | UpstreamError::TimedOut(Stage::Connecting)
                );
                record_failure(failures, &plan, current.peer_idx, error);
                let triggers = match kind {
                    FailKind::Error => plan.next_upstream.error,
                    FailKind::Timeout => plan.next_upstream.timeout,
                    FailKind::InvalidHeader => plan.next_upstream.invalid_header,
                };
                last_failure = Some(resp);
                if !triggers
                    || attempts >= max_tries
                    || (sent && !sent_may_retry)
                    || deadline_exceeded(overall_deadline)
                {
                    if let Some(stale) = stale_answer(&mut plan, report, StaleCase::Failed(kind)) {
                        return stale;
                    }
                    return last_failure
                        .unwrap_or_else(|| Response::Prebuilt(plan.bad_gateway.pick(plan.method)));
                }
                let Some(next) = upstream::pick_peer(upstream, &tried, plan.hash.as_deref_mut())
                else {
                    // No peer left: nginx's FT_NOLIVE, which `proxy_cache_use_stale error`
                    // covers (ngx_http_proxy_merge_loc_conf).
                    let resp = no_live_upstreams(&plan, states, failures);
                    if let Some(stale) =
                        stale_answer(&mut plan, report, StaleCase::Failed(FailKind::Error))
                    {
                        return stale;
                    }
                    return resp;
                };
                tried.insert(next.peer_idx);
                drop(current);
                current = next;
                continue;
            }
        }
    }
}

/// No peer to try (every one down, cooling off after `max_fails`, or
/// tried): nginx's NGX_BUSY from the balancer. The try shows as the
/// upstream's name in `$upstream_addr`, `no live upstreams` is logged and
/// the answer is a 502, whatever earlier tries got
/// (ngx_http_upstream_connect, NGX_HTTP_UPSTREAM_FT_NOLIVE).
#[cold]
fn no_live_upstreams(
    plan: &ProxyPlan,
    states: &mut Vec<UpstreamState>,
    failures: &mut Vec<AttemptFailure>,
) -> Response {
    states.push(UpstreamState {
        status: 502,
        response_ms: Some(0),
        ..UpstreamState::new(UpstreamPeerName::Group(plan.upstream.name))
    });
    // `upstream:` names the group, as the balancer's `pc->name`.
    failures.push(AttemptFailure {
        error: UpstreamError::NoLiveUpstreams,
        upstream: format!(
            "{}://{}{}",
            if plan.tls.is_some() { "https" } else { "http" },
            String::from_utf8_lossy(plan.upstream.name),
            String::from_utf8_lossy(upstream_uri(plan))
        ),
    });
    Response::Prebuilt(plan.bad_gateway.pick(plan.method))
}

/// `proxy_next_upstream_tries 0;` is "no cap"; everything else caps the
/// retry loop at the configured value. The peers not marked `down` are
/// the natural upper bound when no cap is set (we never re-try the same
/// peer).
fn compute_max_tries(configured: u32, peers: usize) -> u32 {
    let peer_cap = (peers as u32).max(1);
    if configured == 0 {
        peer_cap
    } else {
        configured.min(peer_cap)
    }
}

fn deadline_exceeded(deadline: Option<Instant>) -> bool {
    deadline.is_some_and(|d| Instant::now() >= d)
}

fn response_status(resp: &Response) -> Option<u16> {
    match resp {
        Response::Prebuilt(b) => parse_response_status(b),
        Response::Owned(b) => parse_response_status(b),
        Response::File { headers, .. } => parse_response_status(headers),
        _ => None,
    }
}

/// Build a `Response::Reroute` from a matched `proxy_intercept_errors`
/// rule. `target[0] == b'/'` → URI internal redirect; `target[0] == b'@'`
/// → named-location jump; anything else (absolute URL) is *not* supported
/// for intercept in v0.1 (nginx itself produces a 302 redirect there;
/// surface a 502 since intercepting to an external target through the
/// proxy makes little sense).
fn build_intercept_reroute(
    rule: &InterceptRule,
    upstream_status: u16,
    upstream_resp: Response,
    recursive: bool,
    method: Method,
    server: &[u8],
) -> Response {
    use crate::phase::{ErrorPageStatus, Reroute, RerouteTarget};
    use crate::worker::PreparedErrorPageAction;
    // A target that renders empty: no error page, the upstream response
    // goes through, as for a local error_page.
    if rule.target.is_empty() {
        return upstream_resp;
    }
    let error_page_status = match rule.action {
        PreparedErrorPageAction::PreserveOriginal => {
            Some(ErrorPageStatus::Preserve(upstream_status))
        }
        PreparedErrorPageAction::UseTargetStatus => None,
        PreparedErrorPageAction::Override(code) => Some(ErrorPageStatus::Override(code)),
    };
    // Preserve the upstream's `WWW-Authenticate:` challenge(s) when
    // intercepting a 401 — nginx keeps every challenge value (ticket
    // #485). Empty for non-401 statuses.
    let preserved_www_authenticate = if upstream_status == 401 {
        let bytes: &[u8] = match &upstream_resp {
            Response::Prebuilt(b) => b,
            Response::Owned(b) => b,
            Response::File { headers, .. } => headers,
            _ => &[],
        };
        crate::worker::response_header_values_all(bytes, b"www-authenticate")
    } else {
        Vec::new()
    };
    if rule.target[0] == b'/' {
        let (uri, args) = match rule.target.iter().position(|&b| b == b'?') {
            Some(i) => (
                rule.target[..i].to_vec(),
                Some(rule.target[i + 1..].to_vec()),
            ),
            None => (rule.target.clone(), None),
        };
        return Response::Reroute(Reroute {
            target: RerouteTarget::Uri(uri),
            args,
            error_page_status,
            enters_error_page: !recursive,
            preserved_location: None,
            preserved_www_authenticate,
        });
    }
    if rule.target[0] == b'@' {
        return Response::Reroute(Reroute {
            target: RerouteTarget::Named(rule.target.clone()),
            args: None,
            error_page_status,
            enters_error_page: !recursive,
            preserved_location: None,
            preserved_www_authenticate,
        });
    }
    // An absolute URL: a redirect to it, 302 unless `=301` etc. says
    // otherwise (ngx_http_send_error_page), as for a local error_page.
    Response::Owned(crate::http::build_redirect_response(
        crate::worker::external_error_page_status(rule.action),
        &rule.target,
        method,
        server,
    ))
}

fn parse_response_status(bytes: &[u8]) -> Option<u16> {
    // Status lives at offset 9 in `HTTP/1.1 NNN ...`. Be defensive — the
    // builder always emits this shape, but if anything regresses we'd
    // rather return None than panic.
    if bytes.len() < 12 {
        return None;
    }
    let d = &bytes[9..12];
    if !d.iter().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(((d[0] - b'0') as u16) * 100 + ((d[1] - b'0') as u16) * 10 + (d[2] - b'0') as u16)
}

#[derive(Debug, Copy, Clone)]
enum FailKind {
    Error,
    Timeout,
    InvalidHeader,
}

/// What the proxy was doing when an attempt failed — the `while …` part
/// of nginx's upstream error lines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Connecting,
    SendingRequest,
    ReadingHeader,
    ReadingBody,
    Upgraded,
    /// The TLS handshake with an HTTPS upstream (#116).
    SslHandshaking,
}

impl Stage {
    fn as_str(self) -> &'static str {
        match self {
            Stage::Connecting => "connecting to upstream",
            Stage::SendingRequest => "sending request to upstream",
            Stage::ReadingHeader => "reading response header from upstream",
            Stage::ReadingBody => "reading upstream",
            Stage::Upgraded => "proxying upgraded connection",
            Stage::SslHandshaking => "SSL handshaking to upstream",
        }
    }
}

/// Why one upstream attempt failed. `Display` is nginx's wording
/// (ngx_http_upstream.c, ngx_event_connect.c), so error-log lines read the
/// same as nginx's.
#[derive(Debug)]
pub enum UpstreamError {
    ConnectFailed(std::io::Error),
    /// The TLS handshake with an HTTPS upstream failed (#116): nginx's
    /// `SSL_do_handshake() failed`.
    SslHandshakeFailed(std::io::Error),
    /// `proxy_ssl_verify on` refused the certificate (#117): nginx's
    /// `upstream SSL certificate verify error: (..)` or `does not match`.
    SslVerifyFailed(String),
    /// A UNIX-domain socket refuses at once, so nginx reports it from
    /// connect() itself, with the path (ngx_event_connect_peer).
    UnixConnectFailed(std::io::Error, &'static std::path::Path),
    /// `proxy_bind`: socket(), setsockopt(IP_TRANSPARENT) or bind() failed.
    SocketFailed(std::io::Error),
    TransparentFailed(std::io::Error, &'static str),
    BindFailed(std::io::Error, std::net::SocketAddr),
    SendFailed(std::io::Error),
    RecvFailed(std::io::Error, Stage),
    TimedOut(Stage),
    PrematurelyClosed(Stage),
    TooBigHeader,
    InvalidStatusLine,
    Status444,
    InvalidChunked,
    TooBigBody,
    NoLiveUpstreams,
    DuplicateHeader {
        line: String,
        previous: String,
    },
    LengthAndTransferEncoding,
    InvalidContentLength(String),
    UnknownTransferEncoding(String),
}

impl UpstreamError {
    /// The error-log level nginx uses: `crit` for a UNIX-domain connect()
    /// failing with anything but a refusal or a full backlog (a missing
    /// socket file, say), `error` otherwise (ngx_event_connect_peer).
    pub fn log_level(&self) -> crate::config::ErrorLogLevel {
        use crate::config::ErrorLogLevel;
        match self {
            UpstreamError::UnixConnectFailed(e, _) => match e.raw_os_error() {
                Some(
                    libc::ECONNREFUSED
                    | libc::EAGAIN
                    | libc::ECONNRESET
                    | libc::ENETDOWN
                    | libc::ENETUNREACH
                    | libc::EHOSTDOWN
                    | libc::EHOSTUNREACH,
                ) => ErrorLogLevel::Error,
                _ => ErrorLogLevel::Crit,
            },
            UpstreamError::SocketFailed(_) | UpstreamError::TransparentFailed(..) => {
                ErrorLogLevel::Alert
            }
            UpstreamError::BindFailed(..) => ErrorLogLevel::Crit,
            _ => ErrorLogLevel::Error,
        }
    }
}

impl std::fmt::Display for UpstreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use crate::worker::errno_text;
        use UpstreamError::*;
        match self {
            ConnectFailed(e) => write!(
                f,
                "connect() failed ({}) while {}",
                errno_text(e),
                Stage::Connecting.as_str()
            ),
            SslHandshakeFailed(e) => write!(
                f,
                "SSL_do_handshake() failed ({e}) while {}",
                Stage::SslHandshaking.as_str()
            ),
            SslVerifyFailed(why) => write!(f, "{why} while {}", Stage::SslHandshaking.as_str()),
            UnixConnectFailed(e, path) => write!(
                f,
                "connect() to unix:{} failed ({}) while {}",
                path.display(),
                errno_text(e),
                Stage::Connecting.as_str()
            ),
            SocketFailed(e) => write!(
                f,
                "socket() failed ({}) while {}",
                errno_text(e),
                Stage::Connecting.as_str()
            ),
            TransparentFailed(e, option) => write!(
                f,
                "setsockopt({option}_TRANSPARENT) failed ({}) while {}",
                errno_text(e),
                Stage::Connecting.as_str()
            ),
            // nginx names the address as given: no port when none was.
            BindFailed(e, addr) if addr.port() == 0 => write!(
                f,
                "bind({}) failed ({}) while {}",
                addr.ip(),
                errno_text(e),
                Stage::Connecting.as_str()
            ),
            BindFailed(e, addr) => write!(
                f,
                "bind({addr}) failed ({}) while {}",
                errno_text(e),
                Stage::Connecting.as_str()
            ),
            SendFailed(e) => write!(
                f,
                "send() failed ({}) while {}",
                errno_text(e),
                Stage::SendingRequest.as_str()
            ),
            RecvFailed(e, stage) => {
                write!(
                    f,
                    "recv() failed ({}) while {}",
                    errno_text(e),
                    stage.as_str()
                )
            }
            TimedOut(stage) => write!(
                f,
                "upstream timed out (110: Connection timed out) while {}",
                stage.as_str()
            ),
            PrematurelyClosed(stage) => {
                write!(
                    f,
                    "upstream prematurely closed connection while {}",
                    stage.as_str()
                )
            }
            TooBigHeader => write!(
                f,
                "upstream sent too big header while {}",
                Stage::ReadingHeader.as_str()
            ),
            InvalidStatusLine => write!(
                f,
                "upstream sent no valid HTTP/1.0 header while {}",
                Stage::ReadingHeader.as_str()
            ),
            Status444 => write!(
                f,
                "upstream sent status 444 while {}",
                Stage::ReadingHeader.as_str()
            ),
            InvalidChunked => write!(
                f,
                "upstream sent invalid chunked response while {}",
                Stage::ReadingBody.as_str()
            ),
            TooBigBody => write!(
                f,
                "upstream response is too big to buffer while {}",
                Stage::ReadingBody.as_str()
            ),
            NoLiveUpstreams => write!(f, "no live upstreams while {}", Stage::Connecting.as_str()),
            DuplicateHeader { line, previous } => write!(
                f,
                "upstream sent duplicate header line: \"{line}\", previous value: \"{previous}\" \
                 while {}",
                Stage::ReadingHeader.as_str()
            ),
            LengthAndTransferEncoding => write!(
                f,
                "upstream sent \"Content-Length\" and \"Transfer-Encoding\" headers at the same \
                 time while {}",
                Stage::ReadingHeader.as_str()
            ),
            InvalidContentLength(line) => write!(
                f,
                "upstream sent invalid \"Content-Length\" header: \"{line}\" while {}",
                Stage::ReadingHeader.as_str()
            ),
            UnknownTransferEncoding(value) => write!(
                f,
                "upstream sent unknown \"Transfer-Encoding\": \"{value}\" while {}",
                Stage::ReadingHeader.as_str()
            ),
        }
    }
}

/// What the upstream passes before an internal redirect leave for
/// `$upstream_*`: every attempt, and the answering upstream's header lines
/// (as `ProxyReport::upstream_headers`).
#[derive(Default)]
pub struct UpstreamTrail {
    pub states: Vec<UpstreamState>,
    pub headers: Vec<u8>,
    /// `$upstream_cache_status` of the last pass that looked at a cache.
    pub cache_status: Option<crate::proxy_cache::CacheStatus>,
}

impl UpstreamTrail {
    pub fn cache_status_bytes(&self) -> &'static [u8] {
        self.cache_status.map_or(&[], |s| s.as_bytes())
    }
}

/// What `run_proxy` reports besides the response.
#[derive(Default)]
pub struct ProxyReport {
    /// Every failed attempt, for the error log (empty on the happy path,
    /// so no allocation then).
    pub failures: Vec<AttemptFailure>,
    /// The upstream's own header lines (each ending in CRLF), including
    /// the ones hidden from the client, for `$upstream_http_*`. Filled
    /// only when `ProxyPlan::keep_upstream_headers` is set, or for an
    /// X-Accel-Redirect.
    pub upstream_headers: Vec<u8>,
    /// The response has a `Location` or `Refresh` header and there are
    /// `proxy_redirect` rules to apply to it.
    pub redirect_header: bool,
    /// The upstream's `X-Accel-Redirect` / `X-Accel-Limit-Rate`, unless
    /// `proxy_ignore_headers` lists them.
    pub accel: Option<Box<AccelHeaders>>,
    /// One entry per attempt, for `$upstream_addr`, `$upstream_status` and
    /// the other per-attempt variables.
    pub states: Vec<UpstreamState>,
    /// `$upstream_cache_status`, when the location has a `proxy_cache`.
    pub cache_status: Option<crate::proxy_cache::CacheStatus>,
    /// `proxy_pass_header Date`: the response's `Date` is the upstream's,
    /// or there is none, and the worker doesn't stamp one (#360).
    pub passes_date: bool,
    /// Whether the range filter may cut the response (#370).
    pub range_allow: RangeAllow,
    /// When the last attempt started: an attempt cut short by a client
    /// that went away (#136) gets its `$upstream_response_time` from it.
    pub attempt_started: Option<Instant>,
}

/// The answer's upstream request is over (its header filtered, or the
/// request redirected internally): its `$upstream_response_time` shows,
/// as after ngx_http_upstream_finalize_request.
pub fn finish_answer(states: &mut [UpstreamState]) {
    if let Some(state) = states.last_mut() {
        state.in_flight = false;
    }
}

/// Record an upstream `X-Accel-Redirect` / `X-Accel-Limit-Rate` unless
/// `proxy_ignore_headers` lists it. Cold: kept out of the attempt's code.
#[cold]
#[inline(never)]
fn note_accel_header(
    accel: &mut Option<Box<AccelHeaders>>,
    rules: &crate::worker::ProxyResponseRules,
    name: &[u8],
    value: &[u8],
) {
    if name.eq_ignore_ascii_case(b"x-accel-redirect") && !rules.ignore_accel_redirect {
        accel.get_or_insert_default().redirect = Some(value.to_vec());
    } else if name.eq_ignore_ascii_case(b"x-accel-limit-rate") && !rules.ignore_accel_limit_rate {
        // ngx_http_upstream_process_limit_rate: a number, or `off`.
        let rate = if value.eq_ignore_ascii_case(b"off") {
            Some(0)
        } else {
            std::str::from_utf8(value).ok().and_then(|v| v.parse().ok())
        };
        if rate.is_some() {
            accel.get_or_insert_default().limit_rate = rate;
        }
    }
}

/// The upstream's X-Accel headers that change what ruxen does next.
#[derive(Default)]
pub struct AccelHeaders {
    /// `X-Accel-Redirect`: redirect there instead of sending the response.
    pub redirect: Option<Vec<u8>>,
    /// `X-Accel-Limit-Rate`: the response's `limit_rate` (0 for `off`).
    pub limit_rate: Option<u64>,
}

/// One upstream attempt, as nginx's `ngx_http_upstream_state_t`: what the
/// `$upstream_*` list variables print, one entry per attempt.
#[derive(Debug, Clone, Copy)]
pub struct UpstreamState {
    pub peer: UpstreamPeerName,
    /// Status from the upstream, or 502/504 when the attempt failed.
    pub status: u16,
    /// The try whose response is being sent, while its header is filtered:
    /// `$upstream_response_time` is `-` then, as nginx's response_time is
    /// -1 until the upstream request is finalized. `response_ms` already
    /// holds the time (the body is read whole before the header filter).
    pub in_flight: bool,
    /// Milliseconds from the start of the attempt; `None` until reached.
    pub connect_ms: Option<u64>,
    pub header_ms: Option<u64>,
    pub response_ms: Option<u64>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    /// Body bytes as received.
    pub response_length: u64,
}

#[derive(Debug, Clone, Copy)]
pub enum UpstreamPeerName {
    Addr(PeerAddr),
    /// No peer could be tried (`no live upstreams`): the upstream's name.
    Group(&'static [u8]),
}

impl UpstreamState {
    fn new(peer: UpstreamPeerName) -> Self {
        UpstreamState {
            peer,
            status: 0,
            in_flight: false,
            connect_ms: None,
            header_ms: None,
            response_ms: None,
            bytes_sent: 0,
            bytes_received: 0,
            response_length: 0,
        }
    }
}

fn elapsed_ms(start: Instant) -> u64 {
    start.elapsed().as_millis() as u64
}

/// One failed attempt, for the error log: what went wrong and where. The
/// worker adds the request context (client, server, request, host).
#[derive(Debug)]
pub struct AttemptFailure {
    pub error: UpstreamError,
    /// `http://<peer><upstream URI>`, as nginx prints `upstream: "…"`.
    /// Empty when no peer was tried (`no live upstreams`).
    pub upstream: String,
}

enum AttemptOutcome {
    Ok(Response),
    /// The pooled connection failed before we received any response data
    /// — caller should retry the same peer with a fresh socket (gated by
    /// idempotency in the outer loop).
    PooledStale,
    /// Hard failure. Carries the response we'd return if no failover
    /// fires, a classification for the next_upstream check, and the
    /// reason for the error log (boxed: allocated only on failure, and it
    /// keeps this enum the size of a `Response`, which every attempt
    /// returns).
    Failed(Response, FailKind, Box<UpstreamError>),
    /// No `worker_connections` slot for a new connection: the request ends
    /// with a 500, without trying another peer or blaming this one
    /// (ngx_http_upstream_connect on NGX_ERROR).
    NoConnection,
    /// Setting up the connection failed before connect(), on our side
    /// (`proxy_bind`): the request ends with a 500, the peer not blamed
    /// (ngx_http_upstream_connect on NGX_ERROR).
    LocalError(Box<UpstreamError>),
}

/// A `proxy_bind` address, resolved for one request.
#[derive(Debug, Clone, Copy)]
pub struct LocalBind {
    pub addr: std::net::SocketAddr,
    pub transparent: bool,
}

/// Connect to `addr` from `bind`, as ngx_event_connect_peer does with a
/// local address: IP_TRANSPARENT first if asked, IP_BIND_ADDRESS_NO_PORT
/// when no port is given (the port is then picked at connect time, so
/// many connections can share the address), then bind(). A failure
/// before connect() is the request's (500), not the peer's.
#[cold]
#[inline(never)]
async fn connect_bound(
    addr: std::net::SocketAddr,
    bind: LocalBind,
) -> Result<std::io::Result<TcpStream>, UpstreamError> {
    use socket2::{Domain, SockAddr, Socket, Type};
    use std::os::fd::AsRawFd;
    let socket = Socket::new(
        Domain::for_address(addr),
        Type::STREAM.nonblocking().cloexec(),
        None,
    )
    .map_err(UpstreamError::SocketFailed)?;
    let fd = socket.as_raw_fd();
    let set = |level: libc::c_int, name: libc::c_int| -> std::io::Result<()> {
        let one: libc::c_int = 1;
        // SAFETY: an int option on a socket this function owns.
        let rc = unsafe {
            libc::setsockopt(
                fd,
                level,
                name,
                (&one as *const libc::c_int).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if rc == -1 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    };
    if bind.transparent {
        let (level, name, option) = match bind.addr {
            std::net::SocketAddr::V4(_) => (libc::IPPROTO_IP, libc::IP_TRANSPARENT, "IP"),
            std::net::SocketAddr::V6(_) => (libc::IPPROTO_IPV6, libc::IPV6_TRANSPARENT, "IPV6"),
        };
        set(level, name).map_err(|e| UpstreamError::TransparentFailed(e, option))?;
    }
    if bind.addr.port() == 0 {
        // nginx goes on without it when the kernel lacks it.
        let _ = set(libc::IPPROTO_IP, libc::IP_BIND_ADDRESS_NO_PORT);
    }
    socket
        .bind(&SockAddr::from(bind.addr))
        .map_err(|e| UpstreamError::BindFailed(e, bind.addr))?;
    Ok(async {
        match socket.connect(&SockAddr::from(addr)) {
            Ok(()) => {}
            Err(e) if e.raw_os_error() == Some(libc::EINPROGRESS) => {}
            Err(e) => return Err(e),
        }
        let stream = TcpStream::from_std(socket.into())?;
        stream.writable(false).await?;
        let fd = stream.as_raw_fd();
        // SAFETY: borrowed for getsockopt only; `stream` keeps the fd.
        let sock = std::mem::ManuallyDrop::new(unsafe {
            <Socket as std::os::fd::FromRawFd>::from_raw_fd(fd)
        });
        match sock.take_error()? {
            Some(e) => Err(e),
            None => Ok(stream),
        }
    }
    .await)
}

/// Connect to a UNIX-domain socket, returned as a `TcpStream`: monoio's
/// stream I/O is plain recv/send/readv/writev on the descriptor, which
/// works the same on any stream socket, so the pool, `attempt` and the
/// TCP path keep their one stream type. Only `set_nodelay` fails on it,
/// and that result is ignored.
async fn connect_unix(path: &'static std::path::Path) -> std::io::Result<TcpStream> {
    use std::os::fd::{FromRawFd, IntoRawFd};
    let fd = monoio::net::UnixStream::connect(path).await?.into_raw_fd();
    // SAFETY: `fd` is a connected stream socket that nothing else owns.
    TcpStream::from_std(unsafe { std::net::TcpStream::from_raw_fd(fd) })
}

async fn attempt(
    plan: &ProxyPlan,
    peer_idx: usize,
    pooled: Option<upstream::PooledConn>,
    upstream_headers: &mut Vec<u8>,
    redirect_header: &mut bool,
    range_allow: &mut RangeAllow,
    accel: &mut Option<Box<AccelHeaders>>,
    state: &mut UpstreamState,
    started: Instant,
    storable: &mut Option<Storable>,
) -> AttemptOutcome {
    let from_pool = pooled.is_some();
    // Only the answering attempt's X-Accel headers count.
    *accel = None;
    *storable = None;
    let peer_addr = plan.peer_addr(peer_idx);
    let (mut stream, opened_at, requests_served, slot) = if let Some(c) = pooled {
        (c.stream, c.opened_at, c.requests_served, c.slot)
    } else {
        let Some(slot) = crate::worker::take_upstream_slot() else {
            return AttemptOutcome::NoConnection;
        };
        let stream = match peer_addr {
            PeerAddr::Inet(addr) => match plan.bind {
                None => timeout(plan.connect_timeout, TcpStream::connect(addr)).await,
                Some(bind) => {
                    match timeout(plan.connect_timeout, Box::pin(connect_bound(addr, bind))).await {
                        Ok(Ok(connected)) => Ok(connected),
                        Ok(Err(error)) => return AttemptOutcome::LocalError(Box::new(error)),
                        Err(elapsed) => Err(elapsed),
                    }
                }
            },
            // An inet local address can't be bound on a UNIX-domain
            // socket: nginx's bind() fails there with EINVAL.
            PeerAddr::Unix(path) => match plan.bind {
                None => timeout(plan.connect_timeout, Box::pin(connect_unix(path))).await,
                Some(bind) => {
                    return AttemptOutcome::LocalError(Box::new(UpstreamError::BindFailed(
                        std::io::Error::from_raw_os_error(libc::EINVAL),
                        bind.addr,
                    )));
                }
            },
        };
        let stream = match stream {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                let error = match peer_addr {
                    PeerAddr::Unix(path) => UpstreamError::UnixConnectFailed(e, path),
                    PeerAddr::Inet(_) => UpstreamError::ConnectFailed(e),
                };
                return AttemptOutcome::Failed(
                    Response::Prebuilt(plan.bad_gateway.pick(plan.method)),
                    FailKind::Error,
                    Box::new(error),
                );
            }
            Err(_) => {
                return AttemptOutcome::Failed(
                    Response::Prebuilt(plan.gateway_timeout.pick(plan.method)),
                    FailKind::Timeout,
                    Box::new(UpstreamError::TimedOut(Stage::Connecting)),
                );
            }
        };
        let _ = stream.set_nodelay(true);
        let stream = match plan.tls.as_deref() {
            None => UpstreamIo::Plain(stream),
            // proxy_pass https:// (#116): the handshake under its own
            // proxy_connect_timeout, as nginx arms it again for the SSL
            // handshake (ngx_http_upstream_ssl_init_connection). Boxed:
            // only TLS upstreams need its state in the attempt.
            Some(tls) => {
                let handshake =
                    crate::tls_stream::connect(tls.config.clone(), tls.name.clone(), stream);
                match timeout(plan.connect_timeout, Box::pin(handshake)).await {
                    Ok(Ok(tls)) => UpstreamIo::Tls(Box::new(tls)),
                    Ok(Err(e)) => {
                        let error = match crate::upstream_tls::verify_failure(&e) {
                            Some(why) => UpstreamError::SslVerifyFailed(why.to_string()),
                            None => UpstreamError::SslHandshakeFailed(e),
                        };
                        return AttemptOutcome::Failed(
                            Response::Prebuilt(plan.bad_gateway.pick(plan.method)),
                            FailKind::Error,
                            Box::new(error),
                        );
                    }
                    Err(_) => {
                        return AttemptOutcome::Failed(
                            Response::Prebuilt(plan.gateway_timeout.pick(plan.method)),
                            FailKind::Timeout,
                            Box::new(UpstreamError::TimedOut(Stage::SslHandshaking)),
                        );
                    }
                }
            }
        };
        (stream, Instant::now(), 0, slot)
    };
    state.connect_ms = Some(elapsed_ms(started));

    // 2. Send the request. Cloning here keeps the original bytes available
    // for `proxy_next_upstream` retries when this attempt fails — monoio's
    // write_all consumes the buffer, and on `timeout()` cancellation the
    // future drops the buffer with the kernel-completion still pending, so
    // the original on `plan.request` is the only way to recover. With
    // `Bytes` the clone is just an Arc bump; the underlying request bytes
    // are never copied per attempt.
    let res = if plan.body.is_empty() {
        timeout(plan.send_timeout, stream.write_all(plan.request.clone()))
            .await
            .map(|(res, _)| res.map(drop))
    } else {
        let parts = write_request_parts(&mut stream, plan.request.clone(), plan.body.clone());
        timeout(plan.send_timeout, Box::pin(parts)).await
    };
    let res = match res {
        Ok(res) => res,
        Err(_) => {
            return AttemptOutcome::Failed(
                Response::Prebuilt(plan.gateway_timeout.pick(plan.method)),
                FailKind::Timeout,
                Box::new(UpstreamError::TimedOut(Stage::SendingRequest)),
            );
        }
    };
    if let Err(e) = res {
        if from_pool {
            return AttemptOutcome::PooledStale;
        }
        return AttemptOutcome::Failed(
            Response::Prebuilt(plan.bad_gateway.pick(plan.method)),
            FailKind::Error,
            Box::new(UpstreamError::SendFailed(e)),
        );
    }
    state.bytes_sent = (plan.request.len() + plan.body.len()) as u64;
    if let Some(file) = &plan.body_file
        && let Err(error) = send_body_file(&mut stream, file, plan.send_timeout).await
    {
        let kind = match error {
            UpstreamError::TimedOut(_) => FailKind::Timeout,
            _ => FailKind::Error,
        };
        let response = match kind {
            FailKind::Timeout => plan.gateway_timeout,
            _ => plan.bad_gateway,
        };
        return AttemptOutcome::Failed(
            Response::Prebuilt(response.pick(plan.method)),
            kind,
            Box::new(error),
        );
    }
    if let Some(file) = &plan.body_file {
        state.bytes_sent += file.len;
    }

    // 3. Receive the header block. We need at least the head/body
    // separator before we can decide framing. `read_buf` is a single
    // 4 KiB scratch that gets handed to monoio for each `read()` and
    // returned via the `(res, returned)` pair — we reuse it across
    // every read in this attempt (header pull, body pull, chunked
    // decoder) so the hot path does one alloc instead of one per read.
    //
    // Both `accum` and `read_buf` come from a per-worker pool so the
    // common case is zero allocation per request. The buffers are
    // capacity-tracked Vecs (no zero-fill); monoio's IoBufMut writes
    // through `write_ptr() = as_mut_ptr()` over `bytes_total() =
    // capacity()` and updates len via `set_init`, so uninit capacity is
    // safe — the kernel writes before we read.
    let mut accum: Vec<u8> = take_proxy_buf();
    let mut read_buf: Vec<u8> = take_proxy_buf();
    let head_end_terminator: (usize, usize); // (head_end, terminator_len)
    let mut scanned = 0;
    loop {
        let (res, returned) = match timeout(plan.read_timeout, stream.read(read_buf)).await {
            Ok(pair) => pair,
            Err(_) => {
                return AttemptOutcome::Failed(
                    Response::Prebuilt(plan.gateway_timeout.pick(plan.method)),
                    FailKind::Timeout,
                    Box::new(UpstreamError::TimedOut(Stage::ReadingHeader)),
                );
            }
        };
        read_buf = returned;
        match res {
            Ok(0) => {
                if accum.is_empty() && from_pool {
                    return AttemptOutcome::PooledStale;
                }
                return AttemptOutcome::Failed(
                    Response::Prebuilt(plan.bad_gateway.pick(plan.method)),
                    FailKind::Error,
                    Box::new(UpstreamError::PrematurelyClosed(Stage::ReadingHeader)),
                );
            }
            Ok(n) => {
                state.bytes_received += n as u64;
                accum.extend_from_slice(&read_buf[..n]);
            }
            Err(e) => {
                if accum.is_empty() && from_pool {
                    return AttemptOutcome::PooledStale;
                }
                return AttemptOutcome::Failed(
                    Response::Prebuilt(plan.bad_gateway.pick(plan.method)),
                    FailKind::Error,
                    Box::new(UpstreamError::RecvFailed(e, Stage::ReadingHeader)),
                );
            }
        }
        if let Some(p) = find_head_end(&accum, scanned) {
            head_end_terminator = p;
            break;
        }
        // A terminator can start in the last 3 bytes and end in the next read.
        scanned = accum.len().saturating_sub(3);
        // Sanity bound on header block size — refuse 64 KiB+ headers.
        if accum.len() > 64 * 1024 {
            return AttemptOutcome::Failed(
                Response::Prebuilt(plan.bad_gateway.pick(plan.method)),
                FailKind::InvalidHeader,
                Box::new(UpstreamError::TooBigHeader),
            );
        }
    }

    let head_end = head_end_terminator.0;
    let term_len = head_end_terminator.1;
    let body_start = head_end + term_len;

    // 4. Parse the status line. Without header fields, its CRLF is part
    // of the terminator and the whole head is the status line (#323).
    let first_line_end = find_line_end(&accum[..head_end]).map_or(head_end, |p| p.0);
    // `status_line` is `accum[..first_line_end]`, but binding it as a
    // slice would hold an immutable borrow across the body-pull loop
    // (which mutates accum). Re-borrow on each use instead.
    let upstream_is_11 = if accum[..first_line_end].starts_with(b"HTTP/1.1 ") {
        true
    } else if accum[..first_line_end].starts_with(b"HTTP/1.0 ") {
        false
    } else {
        return AttemptOutcome::Failed(
            Response::Prebuilt(plan.bad_gateway.pick(plan.method)),
            FailKind::InvalidHeader,
            Box::new(UpstreamError::InvalidStatusLine),
        );
    };
    let status_code = parse_status_code(&accum[..first_line_end]);
    state.status = status_code;
    state.header_ms = Some(elapsed_ms(started));
    if status_code == 444 {
        // nginx's internal "close connection with no response" status.
        // Treat as an upstream error so `proxy_next_upstream error` can
        // fail over to the next peer. nginx's own `proxy_next_upstream`
        // semantics distinguish `error`, `timeout`, `invalid_header`,
        // `non_idempotent`, and several `http_*` masks; we map 444 to
        // `Error` here because the upstream never produced a response,
        // which matches the spirit of nginx's `non_response` bucket
        // (covered by `error` in default `proxy_next_upstream` mode).
        return AttemptOutcome::Failed(
            Response::Prebuilt(plan.bad_gateway.pick(plan.method)),
            FailKind::Error,
            Box::new(UpstreamError::Status444),
        );
    }

    if status_code == 101 && plan.upgrade {
        state.response_length = 0;
        return upgraded(
            plan,
            peer_idx,
            stream,
            accum,
            first_line_end,
            head_end,
            body_start,
            slot,
        );
    }

    // 5. Parse framing-relevant headers.
    let head_after_status = &accum[headers_start(&accum, first_line_end, head_end)..head_end];
    let mut content_length: Option<u64> = None;
    let mut chunked = false;
    let mut upstream_close = !upstream_is_11; // HTTP/1.0 closes by default

    // Framing is validated as strictly as nginx does
    // (ngx_http_upstream_process_content_length / _transfer_encoding): a
    // second Content-Length or Transfer-Encoding, both together, a
    // non-numeric length, or any coding but `chunked` is a 502. Forwarding
    // them would let the upstream split the client's response stream or
    // desync a pooled connection.
    // The first Content-Length / Transfer-Encoding line, and whether it was
    // the length.
    let mut framing_line: Option<(&[u8], bool)> = None;
    {
        let mut cursor = 0;
        while cursor < head_after_status.len() {
            let (line_len, t) = match find_line_end(&head_after_status[cursor..]) {
                Some(v) => v,
                None => (head_after_status.len() - cursor, 0),
            };
            let line = &head_after_status[cursor..cursor + line_len];
            cursor += line_len + t;
            let Some(colon) = line.iter().position(|&b| b == b':') else {
                continue;
            };
            let name = trim_ascii(&line[..colon]);
            let value = trim_ascii(&line[colon + 1..]);
            let is_length = name.eq_ignore_ascii_case(b"content-length");
            if is_length || name.eq_ignore_ascii_case(b"transfer-encoding") {
                let header_line = trim_ascii(line);
                let invalid = if let Some((previous, previous_is_length)) = framing_line {
                    Some(if previous_is_length == is_length {
                        UpstreamError::DuplicateHeader {
                            line: String::from_utf8_lossy(header_line).into_owned(),
                            previous: String::from_utf8_lossy(previous).into_owned(),
                        }
                    } else {
                        UpstreamError::LengthAndTransferEncoding
                    })
                } else if is_length {
                    match parse_content_length(value) {
                        Some(n) => {
                            content_length = Some(n);
                            None
                        }
                        None => Some(UpstreamError::InvalidContentLength(
                            String::from_utf8_lossy(header_line).into_owned(),
                        )),
                    }
                } else if value.eq_ignore_ascii_case(b"chunked") {
                    chunked = true;
                    None
                } else {
                    Some(UpstreamError::UnknownTransferEncoding(
                        String::from_utf8_lossy(value).into_owned(),
                    ))
                };
                if let Some(error) = invalid {
                    return AttemptOutcome::Failed(
                        Response::Prebuilt(plan.bad_gateway.pick(plan.method)),
                        FailKind::InvalidHeader,
                        Box::new(error),
                    );
                }
                framing_line = Some((header_line, is_length));
            } else if name.len() >= 16 && name[..8].eq_ignore_ascii_case(b"x-accel-") {
                note_accel_header(accel, plan.response, name, value);
            } else if name.eq_ignore_ascii_case(b"connection") {
                if value
                    .split(|&b| b == b',')
                    .any(|t| trim_ascii(t).eq_ignore_ascii_case(b"close"))
                {
                    upstream_close = true;
                }
                if value
                    .split(|&b| b == b',')
                    .any(|t| trim_ascii(t).eq_ignore_ascii_case(b"keep-alive"))
                    && upstream_is_11
                {
                    upstream_close = false;
                }
            }
        }
    }

    // 6. Pull the rest of the body. HEAD / 204 / 304 have no body even if
    //    a Content-Length header is present.
    //
    // For non-chunked framings the body is grown directly inside `accum`
    // so the response bytes — header block + body — live in one buffer.
    // The stitch step (step 7) slices the body out of `accum` instead of
    // copying through an intermediate `body_owned`. For chunked, we still
    // need a separate decoded buffer because the wire bytes carry chunk
    // sizes that would otherwise leak into the forwarded body.
    // `X-Accel-Redirect` (unless ignored): nginx redirects as soon as it
    // has the header and never reads the body, so a response that may have
    // one leaves the connection unusable for the pool. A bodiless one (204,
    // 304, HEAD, or not chunked with Content-Length 0) keeps it, as nginx
    // does (ngx_http_proxy_module.c:1999), provided nothing was read past
    // the header.
    let skip_body = accel.as_ref().is_some_and(|a| a.redirect.is_some());
    // No body follows when the method sent upstream was a HEAD: the
    // client's, unless the cache sent it as a GET, or `proxy_method HEAD`.
    let upstream_head = plan.upstream_head;
    let bodiless = upstream_head
        || status_code == 204
        || status_code == 304
        || (!chunked && content_length == Some(0));
    if skip_body && !(bodiless && accum.len() == body_start) {
        upstream_close = true;
    }
    let body_has_content = !skip_body
        && !upstream_head
        && status_code != 204
        && status_code != 304
        && !(status_code >= 100 && status_code < 200);
    // Neither a length nor chunked: the body ends with the connection,
    // whatever `Connection` says, and the connection isn't reused. nginx
    // takes such a body as of unknown length too (length -1 in
    // ngx_http_proxy_input_filter_init, `u->keepalive` left off).
    if !chunked && content_length.is_none() && body_has_content {
        upstream_close = true;
    }
    let mut body_len_in_accum: usize = accum.len() - body_start;
    let mut decoded_chunked_body: Option<Vec<u8>> = None;
    // proxy_limit_rate pacer state — anchors at the moment body collection
    // begins. `paced_bytes` counts body bytes received from the upstream so
    // far; we sleep when bytes/elapsed would exceed `plan.limit_rate`. Bytes
    // already pulled in with the header read are counted as received.
    let body_pacer_start = Instant::now();
    let mut paced_body_bytes: u64 = body_len_in_accum as u64;
    // A body that hasn't all arrived goes to the client as it comes (#88),
    // unless something needs it whole: a status that may fail over or be
    // intercepted (decided after the body today), or the plan says so.
    if plan.stream
        && body_has_content
        && !plan.next_upstream.matches_status(status_code)
        && !plan
            .intercept
            .as_ref()
            .is_some_and(|rules| rules.iter().any(|r| r.status == status_code))
        && let Some(framing) = stream_framing(
            &accum[body_start..],
            chunked,
            content_length,
            upstream_close,
        )
    {
        state.response_length = body_len_in_accum as u64;
        let head = client_head(
            plan,
            &accum[..head_end],
            first_line_end,
            None,
            body_has_content,
            skip_body,
            false,
            upstream_headers,
            redirect_header,
            range_allow,
        );
        let pool =
            (plan.keepalive_eligible && status_code != 101 && !upstream_close && upstream_is_11)
                .then_some(crate::proxy_stream::StreamPool {
                    upstream: plan.upstream,
                    peer_idx,
                    opened_at,
                    requests_served,
                    tls: plan.tls.as_ref().map(|t| t.identity()),
                });
        let pending = accum[body_start..].to_vec();
        return_proxy_buf(accum);
        return AttemptOutcome::Ok(Response::ProxyStream(Box::new(
            crate::proxy_stream::ProxyStream {
                head,
                framing,
                pending,
                upstream: stream,
                read_buf,
                read_timeout: plan.read_timeout,
                limit_rate: plan.limit_rate,
                pacer_start: body_pacer_start,
                paced: paced_body_bytes,
                started,
                pool,
                slot,
                upstream_url: upstream_url(plan, peer_idx),
                lease: None,
                gzip: None,
            },
        )));
    }
    if !body_has_content {
        // No body to forward, whatever came in with the header (nginx
        // sends a 1xx not upgraded, a 204 or a 304 without one). Bytes
        // past the head leave the connection unusable for the pool.
        if body_len_in_accum > 0 && !skip_body {
            upstream_close = true;
        }
        body_len_in_accum = 0;
    } else if chunked {
        let mut body = Vec::with_capacity(body_len_in_accum + 4096);
        body.extend_from_slice(&accum[body_start..]);
        // Truncate accum to just the header block — the chunked-encoded
        // bytes after `body_start` are not what we'll forward.
        accum.truncate(body_start);
        body_len_in_accum = 0;
        match read_chunked_body_with_buf(&mut stream, &mut body, &mut read_buf, plan.read_timeout)
            .await
        {
            Ok(read) => state.bytes_received += read,
            Err((stale, error)) => {
                if stale && from_pool && body.is_empty() {
                    return AttemptOutcome::PooledStale;
                }
                return AttemptOutcome::Failed(
                    Response::Prebuilt(plan.bad_gateway.pick(plan.method)),
                    FailKind::Error,
                    Box::new(error),
                );
            }
        }
        decoded_chunked_body = Some(body);
    } else if let Some(cl) = content_length {
        // Refused before reading, like the chunked and close-delimited
        // bodies once they pass the cap.
        if cl > MAX_BUFFERED_BODY as u64 {
            return AttemptOutcome::Failed(
                Response::Prebuilt(plan.bad_gateway.pick(plan.method)),
                FailKind::Error,
                Box::new(UpstreamError::TooBigBody),
            );
        }
        let cl_usize = cl as usize;
        // We may have already read more than cl_usize bytes in the header
        // pull (the upstream pipelined another response or sent stray
        // bytes). Trim the over-read so we forward exactly cl_usize body
        // bytes and don't pollute the keepalive socket — but only if the
        // socket isn't going back to the pool. For simplicity we always
        // trim; pool-release happens after this and the socket has no
        // pending bytes to recover from in either case.
        if body_len_in_accum > cl_usize {
            accum.truncate(body_start + cl_usize);
            body_len_in_accum = cl_usize;
        }
        // Reserve for what is likely to arrive, not for what the upstream
        // claims: a bogus `Content-Length: 1000000000000` must not abort
        // the process on allocation. Bigger bodies grow as bytes come in.
        accum.reserve((cl_usize - body_len_in_accum).min(MAX_UPFRONT_RESERVE));
        while body_len_in_accum < cl_usize {
            let (res, returned) = match timeout(plan.read_timeout, stream.read(read_buf)).await {
                Ok(pair) => pair,
                Err(_) => {
                    return AttemptOutcome::Failed(
                        Response::Prebuilt(plan.gateway_timeout.pick(plan.method)),
                        FailKind::Timeout,
                        Box::new(UpstreamError::TimedOut(Stage::ReadingBody)),
                    );
                }
            };
            read_buf = returned;
            match res {
                Ok(0) => {
                    return AttemptOutcome::Failed(
                        Response::Prebuilt(plan.bad_gateway.pick(plan.method)),
                        FailKind::Error,
                        Box::new(UpstreamError::PrematurelyClosed(Stage::ReadingBody)),
                    );
                }
                Ok(n) => {
                    state.bytes_received += n as u64;
                    let need = cl_usize - body_len_in_accum;
                    let take = n.min(need);
                    accum.extend_from_slice(&read_buf[..take]);
                    body_len_in_accum += take;
                    paced_body_bytes += take as u64;
                    pace_body_read(plan.limit_rate, paced_body_bytes, body_pacer_start).await;
                }
                Err(e) => {
                    return AttemptOutcome::Failed(
                        Response::Prebuilt(plan.bad_gateway.pick(plan.method)),
                        FailKind::Error,
                        Box::new(UpstreamError::RecvFailed(e, Stage::ReadingBody)),
                    );
                }
            }
        }
    } else {
        // No length, no chunked, "close" semantics — read until EOF
        // straight into `accum`.
        loop {
            let (res, returned) = match timeout(plan.read_timeout, stream.read(read_buf)).await {
                Ok(pair) => pair,
                Err(_) => {
                    return AttemptOutcome::Failed(
                        Response::Prebuilt(plan.gateway_timeout.pick(plan.method)),
                        FailKind::Timeout,
                        Box::new(UpstreamError::TimedOut(Stage::ReadingBody)),
                    );
                }
            };
            read_buf = returned;
            match res {
                Ok(0) => break,
                Ok(n) => {
                    state.bytes_received += n as u64;
                    accum.extend_from_slice(&read_buf[..n]);
                    body_len_in_accum += n;
                    paced_body_bytes += n as u64;
                    pace_body_read(plan.limit_rate, paced_body_bytes, body_pacer_start).await;
                }
                Err(e) => {
                    return AttemptOutcome::Failed(
                        Response::Prebuilt(plan.bad_gateway.pick(plan.method)),
                        FailKind::Error,
                        Box::new(UpstreamError::RecvFailed(e, Stage::ReadingBody)),
                    );
                }
            }
            if body_len_in_accum > MAX_BUFFERED_BODY {
                return AttemptOutcome::Failed(
                    Response::Prebuilt(plan.bad_gateway.pick(plan.method)),
                    FailKind::Error,
                    Box::new(UpstreamError::TooBigBody),
                );
            }
        }
    }

    // 7. Stitch the rewritten response: status line forced to HTTP/1.1,
    //    drop hop-by-hop + Transfer-Encoding (we've decoded chunked for
    //    the client; the client framing is done by the worker write
    //    path), append a synthesized Content-Length when we re-framed.
    state.response_length = state.bytes_received.saturating_sub(body_start as u64);
    let body_len = decoded_chunked_body
        .as_ref()
        .map(Vec::len)
        .unwrap_or(body_len_in_accum);
    let mut out = client_head(
        plan,
        &accum[..head_end],
        first_line_end,
        Some(body_len),
        body_has_content,
        skip_body,
        false,
        upstream_headers,
        redirect_header,
        range_allow,
    );
    let client_head_len = out.len();
    if let Some(decoded) = decoded_chunked_body.as_ref() {
        out.extend_from_slice(decoded);
    } else {
        out.extend_from_slice(&accum[body_start..body_start + body_len_in_accum]);
    }
    if !skip_body && let Some(cache) = plan.cache.as_deref() {
        *storable = if status_code == 304 && cache.conf.revalidate && cache.stale.is_some() {
            // A revalidation: the 304's own header is what renews the entry.
            Some(Storable {
                head: accum[..head_end].to_vec(),
                valid_sec: 0,
                updating_sec: 0,
                error_sec: 0,
                vary: Vec::new(),
                client_head_len,
            })
        } else if cache.store && !upstream_head {
            // A HEAD's answer has no body to store (proxy_cache_convert_head
            // off): a GET hitting it would get none.
            storable_response(plan, &accum[..head_end], status_code, client_head_len)
        } else {
            None
        };
    }

    // 8. Pool eligibility — return the socket only if all of these hold:
    //    - upstream block opted into keepalive (plan.keepalive_eligible)
    //    - the response isn't a 101: the connection now speaks another
    //      protocol, and a later request from another client would be
    //      written into that tunnel (nginx sets u->keepalive = 0 for it)
    //    - upstream did not signal close
    //    - the upstream announced HTTP/1.1
    //    - we framed the body (chunked or content-length) so we know we
    //      consumed exactly the right number of bytes
    let response_framed = chunked || content_length.is_some() || !body_has_content;
    if plan.keepalive_eligible
        && status_code != 101
        && !upstream_close
        && upstream_is_11
        && response_framed
    {
        upstream::pool_release(
            plan.upstream,
            peer_idx,
            upstream::PooledConn {
                stream,
                last_used: Instant::now(),
                opened_at,
                requests_served: requests_served + 1,
                slot,
                tls: plan.tls.as_ref().map(|t| t.identity()),
            },
        );
    }

    // Return scratch to the per-worker pool only on the success path. Error
    // returns (timeout, bad upstream framing, etc.) are rare in steady state
    // and just drop the buffers; the pool refills naturally on subsequent
    // requests.
    return_proxy_buf(accum);
    return_proxy_buf(read_buf);
    AttemptOutcome::Ok(Response::Owned(out))
}

/// How a body that hasn't all arrived with the header (`initial`) is
/// relayed, or `None` when it is complete (or malformed): it is then
/// buffered as before, which keeps small responses on one write.
fn stream_framing(
    initial: &[u8],
    chunked: bool,
    content_length: Option<u64>,
    upstream_close: bool,
) -> Option<crate::proxy_stream::StreamFraming> {
    use crate::proxy_stream::{ChunkedDecoder, StreamFraming};
    if chunked {
        let mut probe = ChunkedDecoder::default();
        return match probe.feed(initial, &mut Vec::new()) {
            Ok((false, _)) => Some(StreamFraming::Chunked(ChunkedDecoder::default())),
            _ => None,
        };
    }
    match content_length {
        Some(cl) => (cl > initial.len() as u64).then_some(StreamFraming::Length(cl)),
        None => upstream_close.then_some(StreamFraming::Close),
    }
}

/// How a response's ranges are decided (`ngx_http_upstream_process_headers`
/// with `proxy_force_ranges`, `ngx_http_upstream_copy_allow_ranges`).
#[derive(Clone, Copy)]
struct RangePolicy {
    /// Without an `Accept-Ranges` from the upstream.
    allow: RangeAllow,
    /// With one: what it allows, and it is dropped (the range filter
    /// writes its own). `None`: it goes to the client as it is.
    on_accept_ranges: Option<RangeAllow>,
}

impl RangePolicy {
    #[inline]
    fn new(plan: &ProxyPlan, cached: bool) -> Self {
        if !plan.force_ranges && plan.cache.is_none() {
            return Self {
                allow: RangeAllow::No,
                on_accept_ranges: None,
            };
        }
        Self::cold(plan, cached)
    }

    #[cold]
    #[inline(never)]
    fn cold(plan: &ProxyPlan, cached: bool) -> Self {
        if plan.force_ranges {
            let allow = if cached {
                RangeAllow::Multi
            } else {
                RangeAllow::Single
            };
            return Self {
                allow,
                on_accept_ranges: Some(allow),
            };
        }
        let on_accept_ranges = if cached {
            Some(RangeAllow::Multi)
        } else if plan.cache.as_deref().is_some_and(|c| c.cacheable) {
            Some(RangeAllow::Single)
        } else {
            None
        };
        Self {
            allow: RangeAllow::No,
            on_accept_ranges,
        }
    }
}

/// Step 7 of `attempt`, also run on a cached response: the client's
/// header block from the upstream's `head` (status line and header lines,
/// without the empty line), ready for a body of `body_len` bytes.
#[allow(clippy::too_many_arguments)]
fn client_head(
    plan: &ProxyPlan,
    head: &[u8],
    first_line_end: usize,
    body_len: Option<usize>,
    body_has_content: bool,
    skip_body: bool,
    cached: bool,
    upstream_headers: &mut Vec<u8>,
    redirect_header: &mut bool,
    range_allow: &mut RangeAllow,
) -> Vec<u8> {
    let ranges = RangePolicy::new(plan, cached);
    *range_allow = ranges.allow;
    let mut out = Vec::with_capacity(head.len() + 64 + body_len.unwrap_or(0));
    out.extend_from_slice(b"HTTP/1.1");
    out.extend_from_slice(&head[8..first_line_end]);
    // nginx hides the upstream's `Server` and `Date`
    // (`ngx_http_proxy_hide_headers`) and its header filter writes its own;
    // the worker write path stamps the date.
    let rules = plan.response;
    if rules.pass_mask & (HIDDEN_DATE | HIDDEN_SERVER) == 0 {
        crate::http::write_server_and_date(&mut out, plan.server_bytes);
    } else {
        // `proxy_pass_header Server` / `Date`: the upstream's line stays,
        // and ruxen doesn't write its own.
        if rules.pass_mask & HIDDEN_SERVER == 0 {
            out.extend_from_slice(b"\r\nServer: ");
            out.extend_from_slice(plan.server_bytes);
        }
        if rules.pass_mask & HIDDEN_DATE == 0 {
            out.extend_from_slice(b"\r\nDate: ");
            out.extend_from_slice(&crate::http_date::now());
        }
    }
    out.extend_from_slice(b"\r\n");
    // An X-Accel-Redirect target reads them too: its `$upstream_http_*`,
    // and the headers nginx carries over to its response.
    let keep_upstream_headers = plan.keep_upstream_headers || skip_body;
    if keep_upstream_headers {
        upstream_headers.clear();
    }
    let mut cursor = headers_start(head, first_line_end, head.len());
    let mut have_content_length = false;
    let mut seen_single: u16 = 0;
    while cursor < head.len() {
        let (line_len, t) = match find_line_end(&head[cursor..]) {
            Some(v) => v,
            None => (head.len() - cursor, 0),
        };
        let line = &head[cursor..cursor + line_len];
        cursor += line_len + t;
        if line.is_empty() {
            break;
        }
        let colon = match line.iter().position(|&b| b == b':') {
            Some(p) => p,
            None => continue,
        };
        let name = trim_ascii(&line[..colon]);
        if keep_upstream_headers {
            upstream_headers.extend_from_slice(line);
            upstream_headers.extend_from_slice(b"\r\n");
        }
        let class = classify_upstream_header(name);
        match class {
            UpstreamHeader::HopByHop => continue,
            UpstreamHeader::Hidden(bit) if rules.pass_mask & bit == 0 => continue,
            _ if !rules.hide.is_empty()
                && rules.hide.iter().any(|h| h.eq_ignore_ascii_case(name)) =>
            {
                continue;
            }
            _ => {}
        }
        match class {
            UpstreamHeader::HopByHop | UpstreamHeader::Hidden(_) => {}
            // nginx keeps the first of a repeated single-valued header and
            // drops the rest (ngx_http_upstream_process_header_line).
            UpstreamHeader::Single(bit) => {
                if seen_single & bit != 0 {
                    continue;
                }
                seen_single |= bit;
            }
            UpstreamHeader::Redirect(bit) => {
                if seen_single & bit != 0 {
                    continue;
                }
                seen_single |= bit;
                *redirect_header |= !rules.redirects.is_empty();
            }
            // Step 5 rejected Content-Length together with chunked, so a
            // Content-Length here is the upstream's own framing: keep it.
            UpstreamHeader::ContentLength => have_content_length = true,
            UpstreamHeader::AcceptRanges => {
                if let Some(allow) = ranges.on_accept_ranges {
                    *range_allow = allow;
                    continue;
                }
            }
            UpstreamHeader::Other => {}
        }
        out.extend_from_slice(line);
        out.extend_from_slice(b"\r\n");
        if t == 0 {
            break;
        }
    }
    // nginx's range filter needs the upstream's length
    // (`content_length_n`), cached or not; a chunked body has none.
    if !have_content_length {
        *range_allow = RangeAllow::No;
    }
    if body_has_content
        && !have_content_length
        && let Some(body_len) = body_len
    {
        // The body is fully buffered, so frame it for the client with its
        // length: chunked was decoded to identity, and a close-delimited
        // body (HTTP/1.0 or `Connection: close` without a length) would
        // otherwise go out unframed on a keep-alive client connection.
        // A relayed body (`None`) is framed by the worker.
        out.extend_from_slice(b"Content-Length: ");
        let mut buf = itoa_buf();
        let s = u64_to_decimal(body_len as u64, &mut buf);
        out.extend_from_slice(s);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out
}

/// The response may be cached: its headers allow it, and they or
/// `proxy_cache_valid` give it a lifetime (ngx_http_upstream_send_response).
#[cold]
fn storable_response(
    plan: &ProxyPlan,
    head: &[u8],
    status: u16,
    client_head_len: usize,
) -> Option<Storable> {
    let cache = plan.cache.as_deref()?;
    // A 1xx (a 101 included) answers nothing to keep.
    if status < 200 {
        return None;
    }
    let now = crate::proxy_cache::now_secs();
    let fresh = crate::proxy_cache::freshness(
        crate::proxy_cache::header_lines(head),
        cache.conf.ignore,
        now,
    )?;
    let valid_sec = match fresh.valid_sec {
        0 => match cache.conf.valid_for(status) {
            0 => return None,
            secs => now.saturating_add(secs as i64),
        },
        until => until,
    };
    Some(Storable {
        head: head.to_vec(),
        valid_sec,
        updating_sec: fresh.updating_sec,
        error_sec: fresh.error_sec,
        vary: fresh.vary.to_vec(),
        client_head_len,
    })
}

/// Keep the response in the cache: on disk, or as its status alone when
/// `proxy_intercept_errors` takes it (nginx's cached `error`).
#[cold]
fn store_response(
    cache: &CachePlan,
    storable: Storable,
    status: u16,
    intercepted: bool,
    resp: &Response,
) {
    if intercepted {
        cache
            .zone
            .store_error(&cache.hash, status, storable.valid_sec);
        return;
    }
    let Response::Owned(out) = resp else {
        return;
    };
    let variant = if storable.vary.is_empty() {
        [0; 16]
    } else {
        crate::proxy_cache::vary_digest(&storable.vary, &cache.request_headers)
    };
    let entry = crate::proxy_cache::EntryParts {
        valid_sec: storable.valid_sec,
        updating_sec: storable.updating_sec,
        error_sec: storable.error_sec,
        key: &cache.key,
        vary: &storable.vary,
        variant,
        head: &storable.head,
        body: &out[storable.client_head_len..],
    };
    // A file that can't be written leaves the entry uncached; the
    // response itself still goes out.
    let _ = cache.zone.store(&cache.hash, &entry);
}

/// The upstream said 304 to a revalidation (ngx_http_upstream_test_next):
/// the stale entry is fresh again for the 304's lifetime, else for the one
/// its own headers give from now, else `proxy_cache_valid`'s for its
/// status.
#[cold]
fn revalidate(cache: &CachePlan, stale: &crate::proxy_cache::Entry, reply: Option<Storable>) {
    use crate::proxy_cache::{header_lines, header_valid_sec, now_secs};
    let now = now_secs();
    let ignore = cache.conf.ignore;
    let mut valid = reply.map_or(0, |r| header_valid_sec(header_lines(&r.head), ignore, now));
    if valid == 0 {
        valid = header_valid_sec(header_lines(stale.head()), ignore, now);
    }
    if valid == 0 {
        valid = match cache.conf.valid_for(stale.status()) {
            0 => return,
            secs => now.saturating_add(secs as i64),
        };
    }
    cache.zone.refresh(&cache.hash, valid);
}

/// What a stale response may stand in for (proxy_cache_use_stale).
enum StaleCase {
    Failed(FailKind),
    Status(u16),
}

/// The stale response instead of the upstream's failure, when
/// `proxy_cache_use_stale` lists it, or (for errors) the response's own
/// `stale-if-error` still covers it: ngx_http_upstream_next and
/// ngx_http_upstream_test_next.
#[cold]
fn stale_answer(
    plan: &mut ProxyPlan,
    report: &mut ProxyReport,
    case: StaleCase,
) -> Option<Response> {
    let stale = {
        let cache = plan.cache.as_deref_mut()?;
        if cache.status != crate::proxy_cache::CacheStatus::Expired {
            return None;
        }
        let use_stale = cache.conf.use_stale;
        let wanted = match case {
            StaleCase::Status(status) => use_stale.status(status),
            StaleCase::Failed(kind) => {
                cache.stale_error
                    || match kind {
                        FailKind::Error => use_stale.error,
                        FailKind::Timeout => use_stale.timeout,
                        FailKind::InvalidHeader => use_stale.invalid_header,
                    }
            }
        };
        if !wanted {
            return None;
        }
        cache.stale.take()?
    };
    report.cache_status = Some(crate::proxy_cache::CacheStatus::Stale);
    Some(cached_response(plan, CacheHit::Entry(stale), report))
}

/// Another request holds `proxy_cache_lock`: look again every half
/// second at most (ngx_http_file_cache_lock_wait) until the response is
/// cached, the lock is free or aged, or `proxy_cache_lock_timeout` ends;
/// then the response isn't stored.
async fn wait_for_lock(cache: &mut CachePlan) {
    use crate::proxy_cache::{CacheStatus, Entry, now_ms, now_secs};
    let Some(deadline) = cache.wait_until.take() else {
        return;
    };
    loop {
        let now = Instant::now();
        if now >= deadline {
            cache.store = false;
            return;
        }
        let mut pause = (deadline - now).min(Duration::from_millis(500));
        if let Some(until) = cache.zone.locked_until(&cache.hash) {
            pause = pause.min(Duration::from_millis(until.saturating_sub(now_ms()).max(1)));
        }
        monoio::time::sleep(pause).await;
        if cache.zone.is_fresh(&cache.hash, now_secs())
            && let Some(entry) = Entry::read(&cache.zone.file_path(&cache.hash), &cache.key)
            && entry.matches_variant(&cache.request_headers)
        {
            cache.status = CacheStatus::Hit;
            cache.hit = Some(CacheHit::Entry(entry));
            return;
        }
        if let Some(token) = cache.zone.try_lock(&cache.hash, cache.conf.lock_age_ms) {
            cache.token = Some(token);
            return;
        }
    }
}

/// `proxy_cache_background_update`: the stale response went to the
/// client; this fetches the new one and stores it, as nginx's background
/// subrequest does. Boxed: `run_proxy` spawns it.
fn background_update(
    mut plan: Box<ProxyPlan>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()>>> {
    if let Some(cache) = plan.cache.as_deref_mut() {
        cache.background = false;
        cache.status = crate::proxy_cache::CacheStatus::Expired;
    }
    Box::pin(async move {
        let mut report = ProxyReport::default();
        let _ = run_proxy(plan, &mut report).await;
    })
}

/// The client asked with HEAD and the upstream got a GET: keep the header
/// block, with the body's length, and drop the body.
fn strip_body(resp: &mut Response) {
    if let Response::Owned(out) = resp
        && let Some((end, terminator)) = find_head_end(out, 0)
    {
        out.truncate(end + terminator);
    }
}

/// The answer from the cache (ngx_http_upstream_cache_send): the stored
/// upstream header goes through the same filtering as a fresh one.
#[cold]
fn cached_response(plan: &ProxyPlan, hit: CacheHit, report: &mut ProxyReport) -> Response {
    let entry = match hit {
        // nginx finalizes the request with the status, so the location's
        // error_page answers it.
        CacheHit::Error(status) => {
            let body = format!("{}\n", crate::http::reason_phrase(status));
            let resp = Response::Owned(crate::http::error_response_for_method(
                status,
                &body,
                plan.method,
                plan.server_bytes,
            ));
            let rule = plan
                .intercept
                .as_ref()
                .and_then(|rules| rules.iter().find(|r| r.status == status));
            return match rule {
                Some(rule) => build_intercept_reroute(
                    rule,
                    status,
                    resp,
                    plan.response.recursive_error_pages,
                    plan.method,
                    plan.server_bytes,
                ),
                None => resp,
            };
        }
        CacheHit::Entry(entry) => entry,
    };
    let head = entry.head();
    let first_line_end = find_line_end(head).map_or(head.len(), |(end, _)| end);
    let status = parse_status_code(&head[..first_line_end]);
    // nginx's not-modified filter runs for a cacheable upstream response
    // (#349): a conditional request gets 304 or 412 instead of the body.
    if status == 200
        && let Some(cache) = plan.cache.as_deref()
        && let Some(answer) = not_modified(head, &cache.request_headers)
    {
        // A failed precondition is an error response
        // (ngx_http_filter_finalize_request), with the server's own head.
        if answer == 412 {
            let body = format!("{}\n", crate::http::reason_phrase(412));
            return Response::Owned(crate::http::error_response_for_method(
                412,
                &body,
                plan.method,
                plan.server_bytes,
            ));
        }
        let head = conditional_head(head, answer);
        let first_line_end = find_line_end(&head).map_or(head.len(), |(end, _)| end);
        return Response::Owned(client_head(
            plan,
            &head,
            first_line_end,
            None,
            false,
            false,
            true,
            &mut report.upstream_headers,
            &mut report.redirect_header,
            &mut report.range_allow,
        ));
    }
    for (name, value) in crate::proxy_cache::header_lines(head) {
        if name.len() >= 16 && name[..8].eq_ignore_ascii_case(b"x-accel-") {
            note_accel_header(&mut report.accel, plan.response, name, value);
        }
    }
    let skip_body = report.accel.as_ref().is_some_and(|a| a.redirect.is_some());
    let body_has_content = !skip_body && status >= 200 && status != 204 && status != 304;
    let body = entry.body();
    let mut out = client_head(
        plan,
        head,
        first_line_end,
        Some(body.len()),
        body_has_content,
        skip_body,
        true,
        &mut report.upstream_headers,
        &mut report.redirect_header,
        &mut report.range_allow,
    );
    if body_has_content && !matches!(plan.method, Method::Head) {
        out.extend_from_slice(body);
    }
    Response::Owned(out)
}

/// nginx's `ngx_http_not_modified_header_filter` (1.24) for a 200 the
/// cache answers, against the request's conditional headers:
/// `If-Unmodified-Since` / `If-Match` that fail give 412; `If-Modified-Since`
/// (`if_modified_since exact`, the default: unmodified only on the same
/// date) and `If-None-Match` that all say "unchanged" give 304.
fn not_modified(head: &[u8], request_headers: &[u8]) -> Option<u16> {
    let response = |name: &[u8]| {
        crate::proxy_cache::header_lines(head)
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v)
    };
    let request = |name: &[u8]| {
        crate::proxy_cache::header_lines(request_headers)
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v)
    };
    let last_modified = response(b"last-modified").and_then(crate::file::parse_http_date);
    let etag = response(b"etag");
    if let Some(since) = request(b"if-unmodified-since") {
        // ngx_http_test_if_unmodified: no date to compare is a failure.
        let unmodified = match (crate::file::parse_http_date(since), last_modified) {
            (Some(since), Some(lm)) => lm <= since,
            _ => false,
        };
        if !unmodified {
            return Some(412);
        }
    }
    if let Some(if_match) = request(b"if-match")
        && !etag.is_some_and(|e| crate::file::etag_list_matches_strong(if_match, e))
    {
        return Some(412);
    }
    let ims = request(b"if-modified-since");
    let inm = request(b"if-none-match");
    if ims.is_none() && inm.is_none() {
        return None;
    }
    if let Some(ims) = ims {
        let same = matches!(
            (crate::file::parse_http_date(ims), last_modified),
            (Some(a), Some(b)) if a == b
        );
        if !same {
            return None;
        }
    }
    if let Some(inm) = inm
        && !etag.is_some_and(|e| crate::file::etag_list_matches(inm, e))
    {
        return None;
    }
    Some(304)
}

/// `not_modified` for a response just fetched and stored: `resp` (the
/// client's response, buffered with a cache) becomes the 304 or 412.
#[cold]
#[inline(never)]
fn conditional_fresh(plan: &ProxyPlan, cache: &CachePlan, resp: &mut Response) {
    let Response::Owned(out) = resp else {
        return;
    };
    let Some((end, terminator)) = find_head_end(out, 0) else {
        return;
    };
    match not_modified(&out[..end + terminator], &cache.request_headers) {
        Some(412) => {
            let body = format!("{}\n", crate::http::reason_phrase(412));
            *out =
                crate::http::error_response_for_method(412, &body, plan.method, plan.server_bytes);
        }
        Some(status) => *out = conditional_head(&out[..end], status),
        None => {}
    }
}

/// The cached head as the not-modified filter sends a 304: without
/// `Content-Type`, `Content-Length` and `Accept-Ranges`
/// (ngx_http_not_modified_header_filter clears them).
fn conditional_head(head: &[u8], status: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(head.len());
    out.extend_from_slice(
        format!("HTTP/1.1 {status} {}", crate::http::reason_phrase(status)).as_bytes(),
    );
    for line in head.split(|&b| b == b'\n').skip(1) {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        let name = line
            .split(|&b| b == b':')
            .next()
            .unwrap_or(line)
            .trim_ascii();
        let cleared = [&b"content-length"[..], b"content-type", b"accept-ranges"]
            .iter()
            .any(|h| name.eq_ignore_ascii_case(h));
        if status != 304 || !cleared {
            out.extend_from_slice(b"\r\n");
            out.extend_from_slice(line);
        }
    }
    out.extend_from_slice(b"\r\n\r\n");
    out
}

/// The 101 to a client that asked to upgrade (ngx_http_upstream_upgrade):
/// the head goes out as nginx's header filter writes it, with the
/// upstream's `Upgrade` kept and `Connection: upgrade`, and the connection
/// is handed over for the tunnel instead of reading a body.
#[cold]
#[inline(never)]
#[allow(clippy::too_many_arguments)]
fn upgraded(
    plan: &ProxyPlan,
    peer_idx: usize,
    stream: UpstreamIo,
    accum: Vec<u8>,
    first_line_end: usize,
    head_end: usize,
    body_start: usize,
    slot: crate::worker::UpstreamSlot,
) -> AttemptOutcome {
    let mut head = Vec::with_capacity(head_end + 64);
    head.extend_from_slice(b"HTTP/1.1");
    head.extend_from_slice(&accum[8..first_line_end]);
    crate::http::write_server_and_date(&mut head, plan.server_bytes);
    head.extend_from_slice(b"\r\nConnection: upgrade\r\n");
    let rules = plan.response;
    let mut cursor = first_line_end + first_line_terminator_len(&accum, first_line_end);
    while cursor < head_end {
        let (line_len, t) = match find_line_end(&accum[cursor..head_end]) {
            Some(v) => v,
            None => (head_end - cursor, 0),
        };
        let line = &accum[cursor..cursor + line_len];
        cursor += line_len + t;
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            if line.is_empty() {
                break;
            }
            continue;
        };
        let name = trim_ascii(&line[..colon]);
        let keep = name.eq_ignore_ascii_case(b"upgrade")
            || match classify_upstream_header(name) {
                UpstreamHeader::HopByHop => false,
                UpstreamHeader::Hidden(bit) => rules.pass_mask & bit != 0,
                _ => !rules.hide.iter().any(|h| h.eq_ignore_ascii_case(name)),
            };
        if keep {
            head.extend_from_slice(line);
            head.extend_from_slice(b"\r\n");
        }
        if t == 0 {
            break;
        }
    }
    head.extend_from_slice(b"\r\n");
    let leftover = accum[body_start.min(accum.len())..].to_vec();
    return_proxy_buf(accum);
    AttemptOutcome::Ok(Response::Upgrade(Box::new(Upgraded {
        head,
        upstream: stream,
        leftover,
        slot,
        read_timeout: plan.read_timeout,
        send_timeout: plan.send_timeout,
        upstream_url: upstream_url(plan, peer_idx),
        lease: None,
    })))
}

/// Stream a request body that was too large to keep in memory from its
/// temp file. Opened per attempt, so a retry on the next peer re-sends it
/// from the start; `proxy_send_timeout` bounds each write.
async fn send_body_file(
    stream: &mut UpstreamIo,
    file: &RequestBodyFile,
    send_timeout: Duration,
) -> Result<(), UpstreamError> {
    use monoio::buf::IoBuf;
    use std::os::unix::fs::FileExt;
    // Positional reads from the start: each attempt re-sends the whole
    // body through the same descriptor.
    let mut offset = 0u64;
    let mut left = file.len;
    let mut buf = vec![0u8; 64 * 1024];
    while left > 0 {
        let want = left.min(buf.len() as u64) as usize;
        let n = file
            .file
            .read_at(&mut buf[..want], offset)
            .map_err(UpstreamError::SendFailed)?;
        if n == 0 {
            return Err(UpstreamError::SendFailed(
                std::io::ErrorKind::UnexpectedEof.into(),
            ));
        }
        let (res, returned) = timeout(send_timeout, stream.write_all(buf.slice(..n)))
            .await
            .map_err(|_| UpstreamError::TimedOut(Stage::SendingRequest))?;
        buf = returned.into_inner();
        res.map_err(UpstreamError::SendFailed)?;
        left -= n as u64;
        offset += n as u64;
    }
    Ok(())
}

/// `proxy_limit_rate` pacer. Sleeps just enough that the cumulative body
/// bytes received so far don't exceed `limit_rate` bytes/second since
/// `started`. `limit_rate == 0` is a no-op (unlimited). Mirrors nginx's
/// `ngx_http_proxy_module.c`: pacing is computed from the start of the body
/// transfer, not per-chunk, so a slow first read isn't "credited" against
/// later reads.
pub(crate) async fn pace_body_read(limit_rate: u64, paced_bytes: u64, started: Instant) {
    if limit_rate == 0 {
        return;
    }
    let allowed_micros = paced_bytes.saturating_mul(1_000_000) / limit_rate;
    let allowed = Duration::from_micros(allowed_micros);
    let elapsed = started.elapsed();
    if allowed > elapsed {
        monoio::time::sleep(allowed - elapsed).await;
    }
}

/// Read a chunked transfer-encoding body, decoding it into `body`. Strips
/// chunk-size and trailing CRLF lines so the resulting `body` is the
/// dechunked payload only. Stops at the terminating zero-length chunk.
///
/// `read_buf` is a caller-owned scratch passed through from `attempt`'s
/// header-pull loop and reused for every read here too — `attempt` does
/// one allocation for it per request and threads it through both phases.
///
/// On failure returns the reason, paired with `true` if no bytes were read
/// at all (a stale pooled connection) and `false` otherwise.
async fn read_chunked_body_with_buf(
    stream: &mut UpstreamIo,
    body: &mut Vec<u8>,
    read_buf: &mut Vec<u8>,
    read_timeout: Duration,
) -> Result<u64, (bool, UpstreamError)> {
    // Buffered reader over the stream — chunked decoding is line-oriented
    // and we already may have leftover bytes from the header read in
    // `body`. Returns the bytes read from the stream.
    let mut buf = std::mem::take(body);
    let leftover = buf.len();
    let mut decoded: Vec<u8> = Vec::with_capacity(buf.len() + 4096);
    let mut pos = 0usize;
    let mut nothing_read = buf.is_empty();

    loop {
        // Find chunk-size line.
        let line_end = loop {
            if let Some(rel) = buf[pos..].iter().position(|&b| b == b'\n') {
                break pos + rel;
            }
            // Need more bytes — borrow the shared read scratch.
            let scratch = std::mem::take(read_buf);
            let (res, returned) = match timeout(read_timeout, stream.read(scratch)).await {
                Ok(pair) => pair,
                Err(_) => {
                    *read_buf = vec![0u8; 4096];
                    return Err((false, UpstreamError::TimedOut(Stage::ReadingBody)));
                }
            };
            *read_buf = returned;
            match res {
                Ok(0) => {
                    return Err((
                        nothing_read,
                        UpstreamError::PrematurelyClosed(Stage::ReadingBody),
                    ));
                }
                Ok(n) => {
                    buf.extend_from_slice(&read_buf[..n]);
                    nothing_read = false;
                }
                Err(e) => {
                    return Err((
                        nothing_read,
                        UpstreamError::RecvFailed(e, Stage::ReadingBody),
                    ));
                }
            }
        };
        let line = trim_crlf(&buf[pos..line_end]);
        // Chunk extension after `;` is allowed; ignore.
        let size_part = match line.iter().position(|&b| b == b';') {
            Some(i) => &line[..i],
            None => line,
        };
        let size_str = match std::str::from_utf8(size_part) {
            Ok(s) => s.trim(),
            Err(_) => return Err((false, UpstreamError::InvalidChunked)),
        };
        let chunk_size = match u64::from_str_radix(size_str, 16) {
            Ok(n) => n,
            Err(_) => return Err((false, UpstreamError::InvalidChunked)),
        };
        pos = line_end + 1;
        // Bound the size before any arithmetic on it: `FFFFFFFFFFFFFFFF`
        // would overflow `chunk_size + 2` below and panic the worker.
        if chunk_size > (MAX_BUFFERED_BODY - decoded.len()) as u64 {
            return Err((false, UpstreamError::TooBigBody));
        }
        if chunk_size == 0 {
            // Read the trailing CRLF (or any trailers, but we don't
            // forward them — drain until the empty line).
            loop {
                let line_end = loop {
                    if let Some(rel) = buf[pos..].iter().position(|&b| b == b'\n') {
                        break pos + rel;
                    }
                    let scratch = std::mem::take(read_buf);
                    let (res, returned) = match timeout(read_timeout, stream.read(scratch)).await {
                        Ok(pair) => pair,
                        Err(_) => {
                            *read_buf = vec![0u8; 4096];
                            return Err((false, UpstreamError::TimedOut(Stage::ReadingBody)));
                        }
                    };
                    *read_buf = returned;
                    match res {
                        Ok(0) => {
                            return Err((
                                false,
                                UpstreamError::PrematurelyClosed(Stage::ReadingBody),
                            ));
                        }
                        Ok(n) => buf.extend_from_slice(&read_buf[..n]),
                        Err(e) => {
                            return Err((false, UpstreamError::RecvFailed(e, Stage::ReadingBody)));
                        }
                    }
                };
                let line = trim_crlf(&buf[pos..line_end]);
                pos = line_end + 1;
                if line.is_empty() {
                    break;
                }
                // Trailer line — ignore.
            }
            *body = decoded;
            return Ok((buf.len() - leftover) as u64);
        }
        // Pull `chunk_size` bytes plus trailing CRLF.
        let need_total = chunk_size as usize + 2;
        while buf.len() - pos < need_total {
            let scratch = std::mem::take(read_buf);
            let (res, returned) = match timeout(read_timeout, stream.read(scratch)).await {
                Ok(pair) => pair,
                Err(_) => {
                    *read_buf = vec![0u8; 4096];
                    return Err((false, UpstreamError::TimedOut(Stage::ReadingBody)));
                }
            };
            *read_buf = returned;
            match res {
                Ok(0) => return Err((false, UpstreamError::PrematurelyClosed(Stage::ReadingBody))),
                Ok(n) => buf.extend_from_slice(&read_buf[..n]),
                Err(e) => return Err((false, UpstreamError::RecvFailed(e, Stage::ReadingBody))),
            }
        }
        decoded.extend_from_slice(&buf[pos..pos + chunk_size as usize]);
        pos += chunk_size as usize + 2;
    }
}

/// Largest upstream body we buffer, however it is framed: past it the
/// answer is a 502. Responses are buffered whole until they stream (#88),
/// so without this one response could take a worker's memory.
const MAX_BUFFERED_BODY: usize = 64 * 1024 * 1024;

/// Upper bound on the up-front reservation for a `Content-Length` body.
const MAX_UPFRONT_RESERVE: usize = 1024 * 1024;

/// How the response stitch treats one upstream header.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum UpstreamHeader {
    /// `Connection`, `Keep-Alive`, `Transfer-Encoding`: never forwarded,
    /// the ones nginx's `ngx_http_upstream_headers_in` doesn't copy. The
    /// rest of RFC 9110's hop-by-hop set (`Upgrade`, `TE`, `Trailers`,
    /// `Proxy-Authenticate`) reaches an HTTP/1 client as with nginx;
    /// HTTP/2 drops the connection-specific ones (`h2::stream`).
    HopByHop,
    /// Hidden by default like nginx's `ngx_http_proxy_hide_headers` (Date,
    /// Server, X-Pad, X-Accel-*): it writes its own Date and Server, and
    /// X-Accel-* are instructions for the proxy, not for clients.
    /// `proxy_pass_header` lets one through; the bit identifies it.
    Hidden(u16),
    /// Single-valued in nginx (`ngx_http_upstream_process_header_line` and
    /// friends): later copies are ignored. The bit tracks "seen".
    Single(u16),
    /// `Location` / `Refresh`: single-valued, and subject to
    /// `proxy_redirect`.
    Redirect(u16),
    ContentLength,
    /// `Accept-Ranges`: dropped where ruxen's range filter decides
    /// (`RangePolicy`).
    AcceptRanges,
    Other,
}

const HIDDEN_DATE: u16 = 1 << 0;
const HIDDEN_SERVER: u16 = 1 << 1;
const HIDDEN_X_ACCEL_REDIRECT: u16 = 1 << 5;
const HIDDEN_X_ACCEL_LIMIT_RATE: u16 = 1 << 7;

/// One dispatch on the name's length, then at most a few compares: this
/// runs for every upstream header line on the proxy hot path.
pub(crate) fn classify_upstream_header(name: &[u8]) -> UpstreamHeader {
    use UpstreamHeader::*;
    let is = |h: &[u8]| name.eq_ignore_ascii_case(h);
    match name.len() {
        4 if is(b"date") => Hidden(HIDDEN_DATE),
        4 if is(b"etag") => Single(1 << 0),
        5 if is(b"x-pad") => Hidden(1 << 2),
        6 if is(b"server") => Hidden(HIDDEN_SERVER),
        7 if is(b"expires") => Single(1 << 1),
        7 if is(b"refresh") => Redirect(1 << 2),
        8 if is(b"location") => Redirect(1 << 3),
        10 if is(b"connection") || is(b"keep-alive") => HopByHop,
        12 if is(b"content-type") => Single(1 << 4),
        13 if is(b"last-modified") => Single(1 << 5),
        13 if is(b"accept-ranges") => AcceptRanges,
        14 if is(b"content-length") => ContentLength,
        15 if is(b"x-accel-expires") => Hidden(1 << 3),
        15 if is(b"x-accel-charset") => Hidden(1 << 4),
        16 if is(b"x-accel-redirect") => Hidden(HIDDEN_X_ACCEL_REDIRECT),
        17 if is(b"transfer-encoding") => HopByHop,
        17 if is(b"x-accel-buffering") => Hidden(1 << 6),
        18 if is(b"x-accel-limit-rate") => Hidden(HIDDEN_X_ACCEL_LIMIT_RATE),
        _ => Other,
    }
}

/// The bit of a header nginx hides by default, for `proxy_pass_header`.
pub fn default_hidden_bit(name: &[u8]) -> Option<u16> {
    match classify_upstream_header(name) {
        UpstreamHeader::Hidden(bit) => Some(bit),
        _ => None,
    }
}

/// `Content-Length` value as nginx's `ngx_atoof` accepts it: decimal
/// digits only, no sign, no overflow.
pub(crate) fn parse_content_length(value: &[u8]) -> Option<u64> {
    if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
        return None;
    }
    value.iter().try_fold(0u64, |n, &d| {
        n.checked_mul(10)?.checked_add(u64::from(d - b'0'))
    })
}

fn trim_crlf(s: &[u8]) -> &[u8] {
    let mut end = s.len();
    while end > 0 && (s[end - 1] == b'\n' || s[end - 1] == b'\r') {
        end -= 1;
    }
    &s[..end]
}

pub(crate) fn parse_status_code(status_line: &[u8]) -> u16 {
    if status_line.len() < 12 {
        return 0;
    }
    let d = &status_line[9..12];
    if !d.iter().all(|b| b.is_ascii_digit()) {
        return 0;
    }
    ((d[0] - b'0') as u16) * 100 + ((d[1] - b'0') as u16) * 10 + (d[2] - b'0') as u16
}

fn itoa_buf() -> [u8; 20] {
    [0u8; 20]
}

fn u64_to_decimal(mut n: u64, buf: &mut [u8; 20]) -> &[u8] {
    if n == 0 {
        buf[0] = b'0';
        return &buf[..1];
    }
    let mut i = buf.len();
    while n > 0 {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    let len = buf.len() - i;
    buf.copy_within(i.., 0);
    &buf[..len]
}

/// Find the head/body boundary (`\r\n\r\n` or `\n\n`, whichever comes
/// first). Returns `(position, terminator_len)`. nginx tolerates the
/// LF-only form. One pass over the line feeds from `from`, which both
/// terminators contain, stopping at the first that ends the head: the body
/// bytes read along with the head aren't scanned, nor the bytes an earlier
/// read already looked at.
pub(crate) fn find_head_end(buf: &[u8], from: usize) -> Option<(usize, usize)> {
    let mut i = from;
    while let Some(p) = buf[i..].iter().position(|&b| b == b'\n') {
        let lf = i + p;
        match buf.get(lf + 1) {
            Some(b'\n') => return Some((lf, 2)),
            Some(b'\r') if lf > 0 && buf[lf - 1] == b'\r' && buf.get(lf + 2) == Some(&b'\n') => {
                return Some((lf - 1, 4));
            }
            _ => {}
        }
        i = lf + 1;
    }
    None
}

/// Find the next line terminator (`\r\n` or `\n`). Returns
/// `(line_len, terminator_len)`.
pub(crate) fn find_line_end(buf: &[u8]) -> Option<(usize, usize)> {
    for (i, &b) in buf.iter().enumerate() {
        if b == b'\n' {
            if i > 0 && buf[i - 1] == b'\r' {
                return Some((i - 1, 2));
            }
            return Some((i, 1));
        }
    }
    None
}

/// Where the header fields start: past the status line's terminator, or
/// at `head_end` when there are none.
pub(crate) fn headers_start(buf: &[u8], first_line_end: usize, head_end: usize) -> usize {
    (first_line_end + first_line_terminator_len(buf, first_line_end)).min(head_end)
}

fn first_line_terminator_len(buf: &[u8], line_end: usize) -> usize {
    if line_end + 1 < buf.len() && buf[line_end] == b'\r' && buf[line_end + 1] == b'\n' {
        2
    } else {
        1
    }
}

/// The client's request headers that don't go upstream: nginx's proxy
/// module sets these itself or sends them empty (`ngx_http_proxy_headers`,
/// ngx_http_proxy_module.c:820: `Connection: close` or the configured
/// value, `Transfer-Encoding` of its own framing, and `TE`, `Keep-Alive`,
/// `Expect`, `Upgrade` empty). Everything else, `Proxy-Authorization`
/// included, is forwarded as nginx does. Compared case-insensitively
/// against the header name (everything before the `:`).
fn is_hop_by_hop(name: &[u8]) -> bool {
    const HOP_BY_HOP: &[&[u8]] = &[
        b"connection",
        b"expect",
        b"keep-alive",
        b"te",
        b"transfer-encoding",
        b"upgrade",
    ];
    let trimmed = trim_ascii(name);
    for &h in HOP_BY_HOP {
        if trimmed.eq_ignore_ascii_case(h) {
            return true;
        }
    }
    false
}

fn trim_ascii(s: &[u8]) -> &[u8] {
    let mut start = 0;
    let mut end = s.len();
    while start < end && (s[start] == b' ' || s[start] == b'\t') {
        start += 1;
    }
    while end > start && (s[end - 1] == b' ' || s[end - 1] == b'\t') {
        end -= 1;
    }
    &s[start..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The single pass finds what the two whole-buffer searches it replaced
    /// found, on every string of `\r`, `\n` and `a` up to 9 bytes, and also
    /// when the bytes arrive split in two reads.
    #[test]
    fn find_head_end_matches_two_scans() {
        fn two_scans(buf: &[u8]) -> Option<(usize, usize)> {
            let crlf = buf.windows(4).position(|w| w == b"\r\n\r\n");
            let lflf = buf.windows(2).position(|w| w == b"\n\n");
            match (crlf, lflf) {
                (Some(a), Some(b)) if a < b => Some((a, 4)),
                (Some(_), Some(b)) => Some((b, 2)),
                (Some(a), None) => Some((a, 4)),
                (None, Some(b)) => Some((b, 2)),
                (None, None) => None,
            }
        }
        for len in 0..=9u32 {
            for mut n in 0..3usize.pow(len) {
                let buf: Vec<u8> = (0..len)
                    .map(|_| {
                        let b = [b'\r', b'\n', b'a'][n % 3];
                        n /= 3;
                        b
                    })
                    .collect();
                let want = two_scans(&buf);
                assert_eq!(find_head_end(&buf, 0), want, "{buf:?}");
                for split in 0..=buf.len() {
                    let first = two_scans(&buf[..split]);
                    let got = first.or_else(|| find_head_end(&buf, split.saturating_sub(3)));
                    assert_eq!(got, want, "{buf:?} split at {split}");
                }
            }
        }
    }

    #[test]
    fn the_buffer_pool_keeps_only_read_sized_buffers() {
        PROXY_BUF_POOL.with(|p| p.borrow_mut().clear());
        return_proxy_buf(Vec::new());
        return_proxy_buf(Vec::with_capacity(3));
        return_proxy_buf(Vec::with_capacity(PROXY_SCRATCH_CAP * 32));
        assert_eq!(PROXY_BUF_POOL.with(|p| p.borrow().len()), 0);
        return_proxy_buf(Vec::with_capacity(PROXY_SCRATCH_CAP));
        assert!(take_proxy_buf().capacity() >= PROXY_SCRATCH_CAP);
    }

    #[test]
    fn request_parts_advance_across_head_and_body() {
        fn sent(parts: &RequestParts) -> Vec<u8> {
            use monoio::buf::IoVecBuf;
            let iov = parts.read_iovec_ptr();
            let mut out = Vec::new();
            for i in 0..parts.read_iovec_len() {
                // SAFETY: the iovecs point into `parts`' own buffers.
                let v = unsafe { *iov.add(i) };
                if v.iov_len > 0 {
                    out.extend_from_slice(unsafe {
                        std::slice::from_raw_parts(v.iov_base as *const u8, v.iov_len)
                    });
                }
            }
            out
        }
        let mut parts = RequestParts::new(
            bytes::Bytes::from_static(b"HEAD\r\n"),
            bytes::Bytes::from_static(b"body"),
        );
        assert_eq!(sent(&parts), b"HEAD\r\nbody");
        parts.advance(3);
        assert_eq!(sent(&parts), b"D\r\nbody");
        parts.advance(4);
        assert_eq!(sent(&parts), b"ody");
        assert_eq!(parts.len(), 3);
        parts.advance(3);
        assert_eq!(parts.len(), 0);
        assert_eq!(sent(&parts), b"");
    }

    #[test]
    fn build_request_minimal() {
        let bytes = build_request_bytes(b"GET", b"/foo?bar=1", b"backend.example");
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(s.starts_with("GET /foo?bar=1 HTTP/1.0\r\n"));
        assert!(s.contains("Host: backend.example\r\n"));
        assert!(s.contains("Connection: close\r\n"));
        assert!(s.ends_with("\r\n\r\n"));
    }

    #[test]
    fn build_request_http11_no_auto_connection() {
        let bytes = build_request_bytes_with_headers(
            b"GET",
            b"/",
            1,
            &[ProxyHeader {
                name: b"Host",
                value: b"x",
            }],
            &[],
        );
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(s.starts_with("GET / HTTP/1.1\r\n"));
        // No Connection: header injected — caller decides.
        assert!(!s.to_ascii_lowercase().contains("connection:"));
    }

    #[test]
    fn hop_by_hop_classification() {
        assert!(is_hop_by_hop(b"Connection"));
        assert!(is_hop_by_hop(b"connection"));
        assert!(is_hop_by_hop(b"  Transfer-Encoding "));
        assert!(is_hop_by_hop(b"Keep-Alive"));
        assert!(is_hop_by_hop(b"TE"));
        assert!(is_hop_by_hop(b"Expect"));
        // nginx forwards these.
        assert!(!is_hop_by_hop(b"Proxy-Authorization"));
        assert!(!is_hop_by_hop(b"Trailers"));
        assert!(!is_hop_by_hop(b"Content-Length"));
        assert!(!is_hop_by_hop(b"Server"));
        assert!(!is_hop_by_hop(b"Date"));
    }

    #[test]
    fn content_length_parses_like_ngx_atoof() {
        assert_eq!(parse_content_length(b"0"), Some(0));
        assert_eq!(parse_content_length(b"1234"), Some(1234));
        assert_eq!(
            parse_content_length(b"18446744073709551615"),
            Some(u64::MAX)
        );
        for bad in [
            &b""[..],
            b"foo",
            b"+5",
            b"-5",
            b"5 5",
            b"0x10",
            b"18446744073709551616",
        ] {
            assert_eq!(parse_content_length(bad), None, "{:?}", bad);
        }
    }

    #[test]
    fn upstream_headers_classify_like_nginx() {
        use UpstreamHeader::*;
        for name in [
            &b"Date"[..],
            b"Server",
            b"X-Pad",
            b"X-Accel-Expires",
            b"x-accel-redirect",
            b"X-Accel-Limit-Rate",
            b"X-Accel-Buffering",
            b"X-Accel-Charset",
        ] {
            assert!(
                matches!(classify_upstream_header(name), Hidden(_)),
                "{:?}",
                name
            );
        }
        for name in [&b"Connection"[..], b"Keep-Alive", b"Transfer-Encoding"] {
            assert_eq!(classify_upstream_header(name), HopByHop, "{:?}", name);
        }
        // nginx copies the rest of the RFC's hop-by-hop set to the client
        // (ngx_http_upstream_headers_in ignores only the three above).
        for name in [
            &b"TE"[..],
            b"Trailers",
            b"Upgrade",
            b"Proxy-Authenticate",
            b"Proxy-Authorization",
        ] {
            assert_eq!(classify_upstream_header(name), Other, "{:?}", name);
        }
        for name in [&b"Expires"[..], b"content-type", b"ETag", b"Last-Modified"] {
            assert!(
                matches!(classify_upstream_header(name), Single(_)),
                "{:?}",
                name
            );
        }
        for name in [&b"Location"[..], b"refresh"] {
            assert!(
                matches!(classify_upstream_header(name), Redirect(_)),
                "{:?}",
                name
            );
        }
        assert_eq!(classify_upstream_header(b"Content-Length"), ContentLength);
        for name in [
            &b"Set-Cookie"[..],
            b"Cache-Control",
            b"Vary",
            b"X-Custom",
            b"X-Accel-Other",
        ] {
            assert_eq!(classify_upstream_header(name), Other, "{:?}", name);
        }
        // Every hidden header has its own bit for proxy_pass_header.
        let mut bits = 0u16;
        for name in [
            &b"date"[..],
            b"server",
            b"x-pad",
            b"x-accel-expires",
            b"x-accel-charset",
            b"x-accel-redirect",
            b"x-accel-buffering",
            b"x-accel-limit-rate",
        ] {
            let bit = default_hidden_bit(name).unwrap();
            assert_eq!(bits & bit, 0, "{:?}", name);
            bits |= bit;
        }
    }
}
