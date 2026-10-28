// Request processing pipeline.
//
// Nginx structures request handling as a fixed ordered list of phases, each
// composed of registered checker/handler pairs; `ngx_http_core_run_phases`
// walks that list per request. This module currently runs the request flow
// directly in `process_with_meta` (explicit steps + reroute loop), not via
// a generic phase-engine dispatcher. The `Phase` enum below is kept as the
// nginx-compatible planned phase list and as a reference for future
// refactoring toward a real phase runner.
//
// Host-missing-on-HTTP/1.1 → 400 is modelled as a pre-FindConfig guard, not
// a separate phase: nginx does the same (process_host is a per-header
// handler that runs before the phase machinery).

use crate::auth;
use crate::config::{AccessAddr, AccessRule, ValuePart, Variable, limit_except_method_bit};
use crate::http::Method;
use crate::uri;
use crate::worker::{
    MatchedLocation, PreparedAccess, PreparedAuthBasic, PreparedErrorLog, PreparedHttp,
    PreparedListen, PreparedLocation, PreparedServer, RewriteOutcome, RewriteState,
    normalize_request_uri_into, run_location_handler, run_rewrite_program,
};
use std::borrow::Cow;
use std::net::IpAddr;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

/// Maximum location searches for a request before we declare a loop: the
/// first and nginx's `NGX_HTTP_MAX_URI_CHANGES` (10) more, as its
/// `r->uri_changes` starts at 11. A flagless `rewrite` spends one too
/// (#682), so a chain of them reaches the limit as in nginx.
pub(crate) const MAX_REROUTES: u32 = 11;

/// Planned nginx-compatible phase list.
///
/// Currently used for documentation and future extension; `process_with_meta`
/// still executes the flow directly.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub enum Phase {
    PostRead,
    ServerRewrite,
    FindConfig,
    Rewrite,
    PostRewrite,
    PreAccess,
    Access,
    PostAccess,
    PreContent,
    Content,
    Log,
}

/// What a connection carries for every request on it: the PROXY protocol
/// header, when the listen has `proxy_protocol`, and `$server_addr`.
/// Requests point at it, so it costs them one word however much it holds.
#[derive(Debug, Clone)]
pub struct ConnInfo {
    pub proxy_protocol: Option<crate::proxy_protocol::ProxyHeader>,
    /// The connection's local address as `$server_addr` shows it.
    pub server_addr: std::borrow::Cow<'static, [u8]>,
    /// The client's address, which `allow` / `deny` match.
    pub peer_ip: IpAddr,
    /// The client came over a `listen unix:` socket (#263): `peer_ip` is a
    /// placeholder, and only `all` / `unix:` rules match it.
    pub peer_unix: bool,
    /// The connection's own peer, once the realip module replaced
    /// `peer_ip` for a request (`$realip_remote_addr`, `$realip_remote_port`).
    pub realip: Option<Box<RealIpPeer>>,
    /// Plain HTTP on an `ssl` port (#384): the request is refused with
    /// nginx's 497, sent as 400 unless `error_page 497` says otherwise.
    pub plain_http: bool,
    /// When the connection was accepted: its first request head is due
    /// `client_header_timeout` after it, as nginx's one accept timer
    /// (#484). `None` where there is no such connection (tests).
    pub accepted_at: Option<std::time::Instant>,
}

#[derive(Debug, Clone)]
pub struct RealIpPeer {
    pub addr: Vec<u8>,
    pub port: u16,
}

impl ConnInfo {
    /// For request contexts built by tests.
    #[cfg(test)]
    pub const NONE: ConnInfo = ConnInfo {
        proxy_protocol: None,
        server_addr: std::borrow::Cow::Borrowed(b""),
        peer_ip: IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        peer_unix: false,
        realip: None,
        plain_http: false,
        accepted_at: None,
    };
}

/// An `auth_request` subrequest to run before the request goes on (#358).
#[derive(Debug, Clone)]
pub struct AuthPending {
    pub uri: &'static [u8],
    pub sets: &'static [(&'static [u8], &'static [crate::worker::PreparedValuePart])],
    /// What limit_req and limit_conn noted on this pass: the pass after
    /// the subrequest doesn't count the request again.
    pub limit_req_status: u8,
    pub limit_conn_status: u8,
}

/// A subrequest's outcome, for the passes that follow it.
#[derive(Debug, Default, Clone)]
pub struct AuthResume {
    pub status: u16,
    pub www_authenticate: Vec<Vec<u8>>,
    /// `auth_request_set` values, rendered in the subrequest's context.
    pub vars: Vec<(&'static [u8], Vec<u8>)>,
    pub limit_req_status: u8,
    pub limit_conn_status: u8,
}

thread_local! {
    /// The outcomes so far, by auth_request URI: processing starts over
    /// after each subrequest, and a location after an internal redirect
    /// may need another one (`auth_request_set.t`, "set on second auth").
    static AUTH_RESUME: std::cell::RefCell<Vec<(&'static [u8], AuthResume)>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// The worker hands the next `process` call the subrequests' outcomes,
/// and takes them back after (an empty list), so no other request sees
/// them.
pub(crate) fn resume_auth_request(resume: Vec<(&'static [u8], AuthResume)>) {
    AUTH_RESUME.with(|r| *r.borrow_mut() = resume);
}

/// The body of a request that has none.
pub static NO_BODY: bytes::Bytes = bytes::Bytes::new();

/// Per-request inputs the pipeline needs from the parser + connection.
/// Narrow on purpose — each field added here is a new dependency between
/// the worker's parse loop and the phase machinery.
#[derive(Copy, Clone)]
pub struct RequestCtx<'a> {
    pub method: Method,
    /// Raw method bytes from the request line. Carries the original
    /// spelling of methods that classify to `Method::Other`
    /// (POST/PUT/DELETE/PATCH/etc.) so the proxy can build a faithful
    /// upstream request line. Always uppercase ASCII per RFC 7230 §3.1.1.
    pub method_bytes: &'a [u8],
    pub path: &'a [u8],
    /// The request line without its CRLF (`$request`).
    pub request_line: &'a [u8],
    /// What upstream passes left before an internal redirect, for
    /// `$upstream_*` in an error page reached through
    /// `proxy_intercept_errors` or in an X-Accel-Redirect target (nginx's
    /// `r->upstream` survives the redirect). `None` otherwise.
    pub upstream: Option<&'a crate::proxy::UpstreamTrail>,
    pub http_11: bool,
    pub host: Option<&'a [u8]>,
    /// SNI hostname captured at TLS handshake time, lowercased. `None` for
    /// plain-HTTP connections and for TLS connections where the client
    /// didn't send a `server_name` extension. Used by `find_config` as a
    /// routing fallback when the HTTP `Host` header is missing or doesn't
    /// match any server block on this listen.
    pub sni: Option<&'a [u8]>,
    /// Index into `PreparedHttp::listens` for the socket that accepted
    /// this connection.
    pub listen_index: usize,
    /// Client IP rendered by `$remote_addr`.
    pub remote_addr: &'a [u8],
    /// Client source port rendered by `$remote_port`.
    pub remote_port: u16,
    pub if_modified_since: Option<&'a [u8]>,
    pub if_unmodified_since: Option<&'a [u8]>,
    pub if_none_match: Option<&'a [u8]>,
    pub if_match: Option<&'a [u8]>,
    pub range: Option<&'a [u8]>,
    pub if_range: Option<&'a [u8]>,
    /// Raw header block bytes — used by `$http_NAME` expansion to scan for
    /// arbitrary request headers at render time. Already lowercased in the
    /// worker's read buffer because `parse_header_line` writes the lowercased
    /// name back in place; values are left byte-for-byte.
    pub headers_raw: &'a [u8],
    /// Process-global monotonic connection id (nginx's `$connection`).
    pub connection_id: u64,
    /// `$request_id` (#487), drawn when the request starts if the config
    /// uses it, else 0.
    pub request_id: u128,
    /// Requests already served on this connection before the current one
    /// (nginx's `$connection_requests`). Zero on the first request.
    pub connection_requests: u64,
    /// Time since connection accept, in microseconds. Rendered as
    /// `seconds.milliseconds` for `$connection_time`.
    pub connection_time_us: u64,
    /// Time spent processing this request, in microseconds. Rendered as
    /// `seconds.milliseconds` for `$request_time`.
    pub request_time_us: u64,
    /// Port substring of the request authority (`Host: host:port` or
    /// absolute-form). Empty if no explicit port was sent. Rendered by
    /// `$request_port`; `$is_request_port` reads its emptiness.
    pub request_port: &'a [u8],
    /// `p` if pipelined, `.` otherwise. Driven by the worker loop:
    /// `read_start > 0` at parse time means a previous request already
    /// consumed bytes from this read buffer.
    pub pipe: u8,
    /// Bytes consumed by the parser for this request (request line +
    /// headers + body). Surface for `$request_length`.
    pub request_length: u64,
    /// Wall-clock seconds since UNIX epoch — captured at request start so
    /// `$time_iso8601` / `$time_local` / `$msec` agree on the same instant
    /// across access-log entries.
    pub epoch_secs: u64,
    /// Millisecond fraction component for `$msec`.
    pub epoch_ms: u16,
    /// Request body bytes the worker already buffered. Empty when the
    /// request had no body or when `proxy_pass_request_body off;` is set.
    /// Both Content-Length and chunked client bodies arrive here decoded
    /// as plain bytes; proxy forwarding recomputes `Content-Length`.
    /// Shared (`Bytes`) so the proxy can send it without a copy (#289).
    pub body: &'a bytes::Bytes,
    /// Length of the request body: `body.len()`, unless the body was too
    /// large to keep in memory and is only in `body_file` (then `body` is
    /// empty, and `$request_body` too, as in nginx).
    pub body_len: u64,
    /// Path to a temp file containing the request body when the worker
    /// spilled it. Empty when no spill file exists.
    pub body_file: Option<&'a crate::worker::SpilledBody>,
    /// Negotiated TLS handshake info, taken once at handshake completion.
    /// `None` for plain-HTTP connections. Drives `$scheme` and `$ssl_*`
    /// variable rendering; otherwise untouched on the hot path.
    pub tls: Option<&'a crate::tls::HandshakeInfo>,
    /// The connection's PROXY protocol header, if its listen has
    /// `proxy_protocol`.
    /// What the connection carries for every request on it.
    pub conn: &'a ConnInfo,
    /// The worker already refused the request with this status (400 for an
    /// invalid Host, 400/501 for Transfer-Encoding) and didn't read its
    /// body. `process` answers it at the server level, where the server's
    /// `error_page` applies, as in nginx.
    pub refuse: Option<u16>,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct KeepaliveMeta {
    pub allow: bool,
    pub idle_timeout_ms: Option<u64>,
    pub header_timeout_secs: Option<u64>,
    pub max_requests: u64,
    pub max_time_ms: u64,
    pub disable_msie6: bool,
    pub disable_safari: bool,
}

impl KeepaliveMeta {
    /// A server's settings, for a response before any location (a
    /// server-level `return`, a refused URI).
    fn of_server(server: &PreparedServer) -> Self {
        let k = &server.keepalive;
        KeepaliveMeta {
            allow: k.allow,
            idle_timeout_ms: k.idle_timeout_ms,
            header_timeout_secs: k.header_timeout_secs,
            max_requests: k.max_requests,
            max_time_ms: k.max_time_ms,
            disable_msie6: k.disable_msie6,
            disable_safari: k.disable_safari,
        }
    }
}

impl Default for KeepaliveMeta {
    fn default() -> Self {
        KeepaliveMeta {
            allow: true,
            idle_timeout_ms: Some(crate::worker::DEFAULT_KEEPALIVE_TIMEOUT_MS),
            header_timeout_secs: None,
            max_requests: 1_000,
            max_time_ms: 3_600_000,
            disable_msie6: true,
            disable_safari: false,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct LogMeta {
    pub error_logs: &'static [PreparedErrorLog],
    pub log_not_found: bool,
}

impl Default for LogMeta {
    fn default() -> Self {
        LogMeta {
            error_logs: &[],
            log_not_found: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProcessMeta {
    pub keepalive: KeepaliveMeta,
    pub log: LogMeta,
    /// `$server_port` for access-log rendering on this request.
    pub server_port: u16,
    /// `access_log` sinks for the matched location (or server scope if no
    /// location matched). The worker uses this list — not `PreparedHttp::
    /// access_logs` — so location-scope `access_log` directives fire
    /// against the right format/path for the request that landed.
    pub access_logs: &'static [crate::worker::PreparedAccessLog],
    /// `limit_req` holds the request this long before its content handler
    /// (#94).
    pub limit_req_delay_ms: u64,
    /// The counts `limit_conn` took for this request, given back when the
    /// last copy of the meta goes, after the response is written (#95).
    pub limit_conn_held: Option<std::rc::Rc<crate::worker::limit_conn::Held>>,
    /// `auth_request` needs its subrequest (#358): the worker runs it and
    /// processes the request again with the result (`AuthResume`).
    pub auth_request: Option<Box<AuthPending>>,
    /// The location's root, which an access_log path with variables
    /// checks before it writes (#303).
    pub doc_root: Option<&'static crate::worker::DocRoot>,
    /// The location's `send_timeout` (and `client_body_timeout`) for this
    /// request; `None` before routing (#147).
    pub timeouts: Option<&'static crate::worker::PreparedClientTimeouts>,
    /// Authenticated user from HTTP Basic auth, for `$remote_user`.
    pub remote_user: Option<Vec<u8>>,
    /// The client address the realip module set, for the log lines the
    /// worker writes after processing.
    pub realip: Option<Box<RealIpState>>,
    /// Location-scope `add_header` list to apply to a `proxy_pass`-served
    /// response. The worker awaits the upstream future, then reuses these
    /// to inject headers (with `$upstream_http_*` populated). Empty when
    /// the request didn't land on a proxied location.
    pub proxy_add_headers: &'static [crate::worker::PreparedAddHeader],
    /// Location-scope `add_trailer` list to apply to a `proxy_pass`-served
    /// response. Same lifecycle as `proxy_add_headers` — applied after the
    /// upstream future resolves so `$upstream_response_length` and
    /// `$upstream_http_*` are populated.
    pub proxy_add_trailers: &'static [crate::worker::PreparedAddHeader],
    /// `chunked_transfer_encoding` knob carried through to the post-await
    /// trailer filter. False suppresses the trailer block (matching nginx's
    /// chunked filter, which skips chunked encoding entirely when off).
    pub proxy_chunked_transfer_encoding: bool,
    /// The location's `absolute_redirect` and friends, for a `Location`
    /// that `proxy_redirect` rewrote to a path (#15).
    pub redirect: crate::config::RedirectPolicy,
    /// `$server_name` value for the matched server, for the post-await
    /// proxy add_header render and the `server: …` part of error-log lines.
    pub server_name: &'static [u8],
    /// `$proxy_host` value (upstream URL authority) for the proxy plan.
    pub proxy_host: &'static [u8],
    /// `proxy_pass https://` (#116): `$proxy_port` defaults to 443.
    pub proxy_tls: bool,
    /// Pre-write delay in milliseconds, applied by the worker via
    /// `monoio::time::sleep` before sending the response. Set by the
    /// access-control phase to defer 401 replies (`auth_delay`) without
    /// blocking the runtime thread.
    pub response_delay_ms: u64,
    /// Effective `underscores_in_headers` for the matched server, used by
    /// post-await render paths to filter `$http_*` lookups.
    pub underscores_in_headers: bool,
    /// Effective `client_body_in_file_only` for the matched location.
    /// `On` keeps the spilled request body file after the response;
    /// `Off`/`Clean` unlink it.
    pub client_body_in_file_only: crate::config::ClientBodyInFileOnly,
    /// Effective `sendfile` for the matched location. The worker sends a
    /// `Response::File` body zero-copy when this is on and the transport
    /// allows it (plain TCP).
    pub sendfile: bool,
    /// A proxied response under `proxy_pass_header Date`: its `Date` is
    /// the upstream's, or there is none, and the worker doesn't stamp one
    /// (#360).
    pub keep_upstream_date: bool,
    /// The matched location's gzip settings; `None` when gzip is off.
    pub gzip: Option<&'static crate::worker::PreparedGzip>,
    /// The location's `max_ranges` (`None`: no limit; 0 turns ranges off),
    /// for the range filter on a proxied or cached response (#370).
    pub max_ranges: Option<u32>,
    /// Whether the range filter may cut the response (#370): set for a
    /// proxied or cached response by the proxy.
    pub range_allow: crate::worker::range::RangeAllow,
    /// `limit_rate` / `limit_rate_after` for this response. Boxed: `None`
    /// (one word) in the common case.
    pub limit_rate: Option<Box<ResponseLimit>>,
    /// Effective `post_action` target for the matched location/server.
    /// The worker runs this after the client response is written and
    /// suppresses its output.
    pub post_action: Option<&'static [u8]>,
    /// `$upstream_cache_status` (#233).
    pub upstream_cache_status: Option<crate::proxy_cache::CacheStatus>,
    /// One entry per upstream attempt (`$upstream_addr` and friends), set
    /// by `settle_proxy_response`. Empty when the request wasn't proxied.
    pub upstream_states: Vec<crate::proxy::UpstreamState>,
    /// The upstream's header lines, for `$upstream_http_*` in access_log
    /// (kept only when a format reads them).
    pub upstream_headers: Vec<u8>,
    /// Effective `expires` directive for the matched location, applied to
    /// proxied responses after the upstream future resolves (so the
    /// upstream's `Last-Modified` is visible for `expires modified ...`).
    pub proxy_expires: crate::worker::PreparedExpires,
    /// The URI was refused before routing (`/../x`): logged with
    /// the server's access_log and an empty `$uri`, as nginx.
    pub invalid_uri: bool,
    /// The request's `set` variables, for what renders after the handler:
    /// a proxied response's `add_header` / `proxy_redirect` and the access
    /// log (nginx's `r->variables` live as long as the request). `None`
    /// when nothing was `set`, the common case.
    pub rewrite_state: Option<Box<RewriteState>>,
}

impl Default for ProcessMeta {
    fn default() -> Self {
        Self {
            keepalive: KeepaliveMeta::default(),
            log: LogMeta::default(),
            server_port: 0,
            access_logs: &[],
            limit_req_delay_ms: 0,
            limit_conn_held: None,
            auth_request: None,
            doc_root: None,
            timeouts: None,
            remote_user: None,
            realip: None,
            proxy_add_headers: &[],
            proxy_add_trailers: &[],
            proxy_chunked_transfer_encoding: true,
            redirect: crate::config::RedirectPolicy::default(),
            server_name: &[],
            proxy_host: &[],
            proxy_tls: false,
            response_delay_ms: 0,
            underscores_in_headers: false,
            client_body_in_file_only: crate::config::ClientBodyInFileOnly::Off,
            sendfile: false,
            keep_upstream_date: false,
            gzip: None,
            max_ranges: None,
            range_allow: crate::worker::range::RangeAllow::No,
            limit_rate: None,
            post_action: None,
            upstream_states: Vec::new(),
            upstream_cache_status: None,
            upstream_headers: Vec::new(),
            proxy_expires: crate::worker::PreparedExpires::Off,
            invalid_uri: false,
            rewrite_state: None,
        }
    }
}

/// Keep the request's variables past the handler (see
/// `ProcessMeta::rewrite_state`). Cold: most requests have none.
#[cold]
#[inline(never)]
fn keep_rewrite_state(meta: &mut ProcessMeta, state: RewriteState) {
    meta.rewrite_state = Some(Box::new(state));
}

/// Logging context for a request refused at the server level, before any
/// location: the server's access_log and error_log.
fn refused_meta(server: &'static PreparedServer, invalid_uri: bool) -> ProcessMeta {
    ProcessMeta {
        log: LogMeta {
            error_logs: server.error_logs,
            log_not_found: server.log_not_found,
        },
        server_port: server.listen_port,
        server_name: server.primary_server_name,
        access_logs: server.access_logs,
        invalid_uri,
        keepalive: KeepaliveMeta::of_server(server),
        ..ProcessMeta::default()
    }
}

/// Answer a request refused at the server level: the server's
/// `error_page` for the status if it has one (nginx's special response
/// handler runs with the server's configuration here), else `response`.
/// `close` ends the connection afterwards, as nginx does for 400 and 501.
/// `code` is the status `error_page` is looked up by, when it isn't the
/// response's own (497).
#[allow(clippy::too_many_arguments)]
fn refuse(
    http: &'static PreparedHttp,
    req: &RequestCtx<'_>,
    url_scratch: &mut Vec<u8>,
    server: &'static PreparedServer,
    response: Response,
    close: bool,
    in_error_page: bool,
    code: Option<u16>,
) -> (Response, ProcessMeta) {
    let (response, mut meta) = match crate::worker::finish_server_response(
        http,
        req,
        server,
        response,
        in_error_page,
        code,
    ) {
        Response::Reroute(reroute) => {
            process_with_meta_inner(http, req, url_scratch, Some(reroute))
        }
        mut response => {
            server_charset(server, &mut response);
            (response, refused_meta(server, false))
        }
    };
    if close {
        meta.keepalive.allow = false;
    }
    (response, meta)
}

/// The server's charset on what it answers before a location (#464);
/// a location's answers get theirs from its DocRoot in the worker.
#[cold]
#[inline(never)]
fn server_charset(server: &PreparedServer, response: &mut Response) {
    if let Some(charset) = server.charset {
        crate::worker::add_charset(charset, response);
    }
}

/// A response's `limit_rate` (bytes per second, 0 = unlimited) and
/// `limit_rate_after` (bytes sent before pacing starts).
#[derive(Debug, Clone, Copy)]
pub struct ResponseLimit {
    pub rate: u64,
    pub after: u64,
}

impl ResponseLimit {
    /// `None` unless something is set.
    pub fn new(rate: u64, after: u64) -> Option<Box<ResponseLimit>> {
        (rate > 0 || after > 0).then(|| Box::new(ResponseLimit { rate, after }))
    }

    /// The rate from X-Accel-Limit-Rate, keeping the location's `after`.
    pub fn with_rate(current: Option<Box<ResponseLimit>>, rate: u64) -> Option<Box<ResponseLimit>> {
        ResponseLimit::new(rate, current.map_or(0, |l| l.after))
    }
}

/// What to write back on the socket. `Prebuilt` is a `&'static` slice baked
/// at startup (return directive, error responses). `Owned` is a per-request
/// buffered response — on the hot path this `Vec<u8>` is the worker's
/// per-connection scratch buffer, taken by `std::mem::take` and returned
/// after `write_all`, so no fresh allocation happens per request. `File`
/// splits small headers from a streamed file-body descriptor so large
/// static-file responses avoid full-body allocation. `Reroute` is an internal
/// signal from the content handler that the request URL should be rewritten
/// and matching re-run — callers outside this module should never observe it
/// because `process` consumes `Reroute` variants in its hop loop. Keep-alive
/// lives on `Request`, not here — a phase outcome doesn't decide connection
/// persistence.
pub enum Response {
    Prebuilt(&'static [u8]),
    Owned(Vec<u8>),
    File {
        headers: Vec<u8>,
        body: FileBody,
    },
    Reroute(Reroute),
    /// Deferred reverse-proxy attempt. The location handler builds a
    /// `ProxyPlan` synchronously; the worker task awaits
    /// `proxy::run_proxy(plan)` to perform the upstream connect/send/recv,
    /// then re-enters the existing write path with `Owned` / `Prebuilt`
    /// bytes. Mirrors how `File` carries an fd that the worker streams.
    Proxy(Box<crate::proxy::ProxyPlan>),
    /// An upstream 101 to a client that asked to upgrade: the head to
    /// send, then the connection becomes a tunnel (#87).
    Upgrade(Box<crate::proxy::Upgraded>),
    /// An upstream response whose body is relayed as it arrives (#88): the
    /// head is filtered like `Owned`, then the worker writes it and relays
    /// the body.
    ProxyStream(Box<crate::proxy_stream::ProxyStream>),
}

pub struct FileBody {
    /// Already-opened, root-contained fd produced by the resolver. The
    /// streaming path consumes this by value — no second `open(2)`.
    pub fd: OwnedFd,
    pub offset: u64,
    pub len: u64,
}

/// Status handling requested by `error_page` after an internal redirect.
/// We only apply these overrides when the target handler completes with a
/// successful/non-redirect status; if the target itself returns a redirect
/// or another error, that terminal status wins.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ErrorPageStatus {
    Preserve(u16),
    Override(u16),
}

/// Internal redirect target. URI redirects rematch the normal location tree
/// after normalization; named redirects jump straight to an internal-only
/// `location @name` without changing the current URI.
pub enum RerouteTarget {
    Uri(Vec<u8>),
    Named(Vec<u8>),
}

/// Internal-use redirect signal. `args: None` means "preserve current
/// args", while `Some(vec![])` means "replace with an explicitly empty
/// query string".
pub struct Reroute {
    pub target: RerouteTarget,
    pub args: Option<Vec<u8>>,
    pub error_page_status: Option<ErrorPageStatus>,
    pub enters_error_page: bool,
    /// `Location:` header bytes preserved across an `error_page` intercept
    /// of a 3xx response. nginx's `r->headers_out.location` survives the
    /// internal redirect because `ngx_http_send_header` later overrides
    /// the new handler's status with `r->err_status`. We mirror that by
    /// re-injecting this header into the final response at finalize time
    /// when the preserved status is in the 3xx range.
    pub preserved_location: Option<Vec<u8>>,
    /// `WWW-Authenticate:` header values preserved across an `error_page`
    /// intercept of a 401. nginx preserves `r->headers_out.www_authenticate`
    /// (a list — `ticket #485`) so multi-value challenges survive. Re-
    /// injected at finalize time when the preserved status is 401.
    pub preserved_www_authenticate: Vec<Vec<u8>>,
    /// The error page answers a status after which nginx's special
    /// response handler ends the connection (`http::closes_connection`).
    pub closes: bool,
}

/// Test-only helper: run the pipeline and return only the response,
/// dropping keepalive metadata. Allocates its own URL scratch; production
/// callers pass a reusable per-connection buffer into `process_with_meta`.
#[cfg(test)]
pub fn process(http: &'static PreparedHttp, req: &RequestCtx<'_>) -> Response {
    let mut url_scratch = Vec::new();
    process_with_meta(http, req, &mut url_scratch).0
}

/// Same as `process`, but also returns keepalive policy resolved from the
/// terminal matched location. `url_scratch` holds the normalized request
/// URI across the reroute loop — production callers reuse the same `Vec`
/// across requests on a connection to keep the hot path allocation-free.
/// The control flow here is intentionally explicit for now (no generic
/// phase dispatcher yet).
pub fn process_with_meta(
    http: &'static PreparedHttp,
    req: &RequestCtx<'_>,
    url_scratch: &mut Vec<u8>,
) -> (Response, ProcessMeta) {
    let out = process_with_meta_inner(http, req, url_scratch, None);
    log_failed_lookup(req, &out.1);
    out
}

/// Re-enter the pipeline starting from an already-resolved reroute target.
/// Used by the worker for proxy-side `proxy_intercept_errors` outcomes so
/// the same reroute machinery handles URI/named jumps, args replacement,
/// and `error_page` status overrides.
pub fn process_with_meta_from_reroute(
    http: &'static PreparedHttp,
    req: &RequestCtx<'_>,
    url_scratch: &mut Vec<u8>,
    reroute: Reroute,
) -> (Response, ProcessMeta) {
    let out = process_with_meta_inner(http, req, url_scratch, Some(reroute));
    log_failed_lookup(req, &out.1);
    out
}

/// nginx's `rewrite or internal redirection cycle` line, noted for the
/// request's error log (#682).
#[cold]
#[inline(never)]
fn rewrite_cycle_log(uri: &[u8]) {
    crate::fs_resolve::note_failed_lookup_at(
        format!(
            "rewrite or internal redirection cycle while processing \"{}\"",
            String::from_utf8_lossy(uri)
        ),
        false,
        crate::config::ErrorLogLevel::Error,
    );
}

/// nginx's `[info]` line for an HTTP/1.1 request without `Host` (#663).
#[cold]
#[inline(never)]
fn missing_host_log(server: &PreparedServer, req: &RequestCtx<'_>) {
    crate::worker::write_error_log(
        server.error_logs,
        crate::config::ErrorLogLevel::Info,
        &crate::worker::ErrorLogRequest::new(req, server.primary_server_name),
        b"client sent HTTP/1.1 request without \"Host\" header while reading client request headers",
        None,
    );
}

/// A file lookup that failed while processing (`open() "…" failed`) is
/// logged now, with this request's context, as nginx logs it where the
/// open fails. The note is per worker thread, so it has to be taken
/// before anything awaits: another connection would overwrite it.
fn log_failed_lookup(req: &RequestCtx<'_>, meta: &ProcessMeta) {
    if let Some(failed) = crate::fs_resolve::take_failed_lookup() {
        crate::worker::write_lookup_error_log(
            meta.log,
            &crate::worker::ErrorLogRequest::new(req, meta.server_name).with_realip(meta),
            failed,
        );
    }
}

fn process_with_meta_inner(
    http: &'static PreparedHttp,
    req: &RequestCtx<'_>,
    url_scratch: &mut Vec<u8>,
    initial_reroute: Option<Reroute>,
) -> (Response, ProcessMeta) {
    let Some(listen) = select_listen(http, req.listen_index) else {
        let server_bytes = default_server_header(http);
        return (
            Response::Owned(crate::http::error_response_for_method(
                500,
                "Internal Server Error\n",
                req.method,
                server_bytes,
            )),
            ProcessMeta::default(),
        );
    };

    // The checks of nginx's ngx_http_process_request_header, in its order.
    // An error page reached from one of them doesn't run them again.
    let refusing = initial_reroute.is_none();
    if refusing {
        // Refused below before normalising: don't leave the previous
        // request's URI behind for the access log's `$uri`, nor its
        // failed file lookup for the error log.
        url_scratch.clear();
        let _ = crate::fs_resolve::take_failed_lookup();
    }

    // RFC 7230 §5.4: a missing Host header on HTTP/1.1 is a client error.
    // Nginx enforces this in ngx_http_process_request_header
    // (request.c:2034–2039) after all headers parse. HTTP/1.0 falls through
    // — empty Host is treated as "default server".
    if refusing && req.http_11 && req.host.is_none_or(|h| h.is_empty()) {
        let server = &listen.servers[listen.default_server];
        // Not past an invalid one, logged already.
        if req.refuse.is_none() {
            missing_host_log(server, req);
        }
        let response = Response::Prebuilt(http.bad_request.pick(req.method));
        return refuse(http, req, url_scratch, server, response, true, false, None);
    }

    let (server, regex_captures) = find_config(listen, req.host, req.sni);

    if refusing {
        if let Some(status) = req.refuse {
            let canned = match status {
                501 => &http.not_implemented,
                // nginx's 497: plain HTTP on an `ssl` port, sent as 400
                // unless `error_page 497` takes it (#384).
                497 => &http.plain_http,
                _ => &http.bad_request,
            };
            let response = Response::Prebuilt(canned.pick(req.method));
            return refuse(
                http,
                req,
                url_scratch,
                server,
                response,
                true,
                false,
                Some(status),
            );
        }
        // `ssl_verify_client` (#113): a Host naming another server than
        // the SNI name, when that server checks certificates, is 421
        // (ngx_http_set_virtual_server); a certificate the server refuses
        // is 495, a missing one 496, both sent as 400 unless `error_page`
        // takes them (ngx_http_process_request).
        if listen.client_verify
            && let Some(tls) = req.tls
            && let Some((status, close)) = client_certificate_refusal(listen, server, req, tls)
        {
            let canned = match status {
                421 => &http.misdirected,
                495 => &http.cert_error,
                _ => &http.no_cert,
            };
            let response = Response::Prebuilt(canned.pick(req.method));
            let code = (status != 421).then_some(status);
            return refuse(http, req, url_scratch, server, response, close, false, code);
        }
        if matches!(req.method, Method::Trace | Method::Connect) {
            if req.method == Method::Trace
                && crate::worker::test_panic() == crate::worker::TestPanic::Trace
            {
                panic!("{}=trace", crate::worker::TEST_PANIC_ENV);
            }
            let response = Response::Owned(crate::file::method_not_allowed(
                req.method,
                server.server_header,
            ));
            return refuse(http, req, url_scratch, server, response, false, false, None);
        }
    }
    let mut named_target: Option<Vec<u8>> = None;
    let mut current_args: Option<Vec<u8>> = None;
    let mut error_page_status: Option<ErrorPageStatus> = None;
    let mut in_error_page = false;
    let mut preserved_location: Option<Vec<u8>> = None;
    let mut preserved_www_authenticate: Vec<Vec<u8>> = Vec::new();
    // The client address the realip module set, if it did. nginx keeps it
    // for the rest of the request, internal redirects included.
    let realip: std::cell::OnceCell<Box<RealIpState>> = std::cell::OnceCell::new();
    // The request as the phases see it once it changed: GET after an
    // error_page sent it to a URI, the realip address.
    let mut req_now: Option<RequestCtx<'_>> = None;
    let req_in = req;
    // An error page for a status that ends the connection (`Reroute::closes`).
    let mut closes = false;
    match initial_reroute {
        None => {
            // Normalize the URI once at FindConfig entry; Rewrite / internal
            // redirects (our try_files reroute loop) reuse the already-normalized
            // form. The original request-target stays on `RequestCtx` so later
            // rendering can still expose `$request_uri`, `$args`, `$is_args`, and
            // `$arg_*` from the client-facing URI even after internal reroutes.
            // `url_scratch` is reused across hops and (for production callers)
            // across requests on the same connection.
            url_scratch.clear();
            if let Err(resp) =
                normalize_request_uri_into(http, req, server.merge_slashes, url_scratch)
            {
                // A 400 ends the connection, as nginx's does.
                let mut meta = refused_meta(server, true);
                meta.keepalive.allow = false;
                return (resp, meta);
            }
        }
        Some(reroute) => {
            closes = reroute.closes;
            if turns_into_get(req, &reroute) {
                req_now = Some(error_page_request(req));
            }
            if let Some(args) = reroute.args {
                current_args = Some(args);
            }
            if let Some(status) = reroute.error_page_status {
                error_page_status = Some(status);
            }
            if reroute.enters_error_page {
                in_error_page = true;
            }
            if let Some(loc) = reroute.preserved_location {
                preserved_location = Some(loc);
            }
            if !reroute.preserved_www_authenticate.is_empty() {
                preserved_www_authenticate = reroute.preserved_www_authenticate;
            }
            match reroute.target {
                RerouteTarget::Uri(uri) => {
                    url_scratch.clear();
                    match uri::normalize_with(&uri, server.merge_slashes, url_scratch) {
                        Ok(_) => {}
                        Err(uri::UriError::EscapesRoot) => {
                            return (
                                Response::Prebuilt(http.forbidden.pick(req.method)),
                                ProcessMeta::default(),
                            );
                        }
                        Err(_) => {
                            return (
                                Response::Prebuilt(http.bad_request.pick(req.method)),
                                ProcessMeta::default(),
                            );
                        }
                    }
                }
                RerouteTarget::Named(name) => {
                    // Named-location jumps preserve the current URI. Seed the
                    // normalized request URI and start the loop with a named target.
                    url_scratch.clear();
                    if let Err(resp) =
                        normalize_request_uri_into(http, req, server.merge_slashes, url_scratch)
                    {
                        return (resp, refused_meta(server, true));
                    }
                    named_target = Some(name);
                }
            }
        }
    }
    let mut rewrite_state = RewriteState::default();
    rewrite_state.doc_root = Some(server.doc_root);
    // A regex server_name's captures are `$1`…`$9` until another regex
    // matches (nginx's r->captures from ngx_http_find_virtual_server).
    if let Some(captures) = regex_captures.as_ref() {
        for (n, value) in captures.numbered.iter().enumerate() {
            rewrite_state.set_numbered_capture(n + 1, value);
        }
    }
    let mut meta = ProcessMeta {
        server_port: server.listen_port,
        server_name: server.primary_server_name,
        // `allow` is the client's until a location's applies: its
        // keepalive_timeout decides, not the server's (nginx's
        // ngx_http_update_location_config).
        keepalive: KeepaliveMeta {
            allow: !closes,
            ..KeepaliveMeta::of_server(server)
        },
        ..ProcessMeta::default()
    };
    // The realip module's post-read handler, with the server's settings.
    if !server.access.realip.from.is_empty() {
        let req = req_now.as_ref().unwrap_or(req_in);
        if let Some(state) = real_ip(req, &server.access.realip) {
            let state: &RealIpState = realip.get_or_init(|| Box::new(state));
            meta.realip = Some(Box::new(state.clone()));
            req_now = Some(with_real_ip(req, state));
        }
    }

    // Reroute loop — nginx calls this `r->internal` handling inside
    // `ngx_http_internal_redirect`; the counter is `r->uri_changes`. We
    // bound at MAX_REROUTES to guarantee termination on cyclic configs
    // (`try_files / =404` pointing at a URI that re-triggers try_files).
    // nginx runs the server rewrite phase first, and again after an
    // internal redirect, but not after a location's `rewrite … last`.
    let mut run_server_rewrite = true;
    for hop in 0..MAX_REROUTES {
        let req = req_now.as_ref().unwrap_or(req_in);
        // nginx's `r->internal`: set by any internal redirect (an entry
        // reroute, or a later hop: rewrite, error_page, try_files, index).
        let internal_request = !refusing || hop > 0;
        if internal_request {
            rewrite_state.unparsed_uri = false;
        }
        let mut loc = if let Some(name) = named_target.take() {
            match match_named_location(server, &name) {
                Some(loc) => loc,
                None => {
                    return (
                        Response::Owned(crate::http::error_response_for_method(
                            500,
                            "Internal Server Error\n",
                            req.method,
                            server.server_header,
                        )),
                        meta,
                    );
                }
            }
        } else {
            if std::mem::take(&mut run_server_rewrite)
                && !server.rewrite_program.is_empty()
                && let Some(response) = crate::worker::run_server_rewrite(
                    http,
                    server,
                    req,
                    url_scratch,
                    &mut current_args,
                    &mut rewrite_state,
                    regex_captures.as_ref(),
                )
            {
                // Answered before any location: the server's error_page,
                // add_header and logs, and the realip address.
                let (response, mut refused) = refuse(
                    http,
                    req,
                    url_scratch,
                    server,
                    response,
                    false,
                    in_error_page,
                    None,
                );
                if refused.realip.is_none() {
                    refused.realip = meta.realip.take();
                }
                return (response, refused);
            }
            match match_location(server, url_scratch, &mut rewrite_state) {
                Some(loc) => loc,
                None => match server.server_default.as_ref() {
                    // Server-scope `root` with no `/` location: nginx's
                    // implicit catch-all.
                    Some(default) => MatchedLocation::from_prefix(default),
                    None => {
                        meta.server_port = server.listen_port;
                        meta.log = LogMeta {
                            error_logs: server.error_logs,
                            log_not_found: server.log_not_found,
                        };
                        // No location matched; fall back to the server-scope
                        // access_log list so the request still gets logged.
                        meta.access_logs = server.access_logs;
                        meta.post_action = server.post_action;
                        meta.remote_user = None;
                        let auth_resume = take_auth_resume(&server.access, &mut rewrite_state);
                        match run_access_control(
                            http,
                            req,
                            &server.access,
                            server.server_header,
                            &meta,
                            auth_resume.as_ref(),
                        ) {
                            AccessControl::Allow { remote_user } => {
                                meta.remote_user = remote_user;
                            }
                            AccessControl::Subrequest => {
                                meta.auth_request = auth_pending(&server.access, &rewrite_state);
                                return (Response::Prebuilt(http.not_found.pick(req.method)), meta);
                            }
                            AccessControl::Deny { response, delay_ms } => {
                                // The server's error_page applies.
                                meta.response_delay_ms = delay_ms;
                                return match crate::worker::finish_server_response(
                                    http,
                                    req,
                                    server,
                                    response,
                                    in_error_page,
                                    None,
                                ) {
                                    Response::Reroute(reroute) => process_with_meta_inner(
                                        http,
                                        req,
                                        url_scratch,
                                        Some(reroute),
                                    ),
                                    mut response => {
                                        server_charset(server, &mut response);
                                        (response, meta)
                                    }
                                };
                            }
                        }
                        let mut response = Response::Prebuilt(http.not_found.pick(req.method));
                        server_charset(server, &mut response);
                        return (response, meta);
                    }
                },
            }
        };
        apply_location_meta(&loc, &mut meta, &mut rewrite_state);
        // ngx_http_core_find_config_phase: an `internal` location is not
        // found for an external request. The 404 is finalized there, before
        // the rewrite and access phases, with the location's `error_page`.
        let refused = loc.internal && !internal_request;
        if !refused && let Some(target) = loc.auto_redirect_to {
            let args = current_args
                .as_deref()
                .unwrap_or_else(|| request_args(req.path));
            return (
                build_auto_redirect_response(
                    server,
                    loc.server_header,
                    loc.redirect,
                    req,
                    target,
                    args,
                ),
                meta,
            );
        }
        if !refused
            && let Some(le) = loc.limit_except
            && limit_except_method_bit(req.method_bytes) & le.methods == 0
        {
            loc = loc.limited(le);
        }
        rewrite_state.if_location = None;
        rewrite_state.if_proxy = false;
        // A response from the rewrite program (`return` in an `if`, a
        // `rewrite … redirect`) goes on to the location's response
        // filters, `error_page` and `add_header`, as nginx finalizes it
        // like a handler's (#362).
        let mut rewrite_response = None;
        // A `return` with text is sent as it is: no `error_page` for it.
        let mut takes_error_page = true;
        let rewrite_broke = if refused {
            rewrite_response = Some(Response::Prebuilt(http.not_found.pick(req.method)));
            false
        } else {
            match run_rewrite_program(
                http,
                server,
                loc,
                req,
                url_scratch,
                &mut current_args,
                &mut rewrite_state,
                regex_captures.as_ref(),
            ) {
                RewriteOutcome::Continue => false,
                RewriteOutcome::Break => true,
                RewriteOutcome::Reroute => continue,
                RewriteOutcome::Respond(response, finalized) => {
                    rewrite_response = Some(response);
                    takes_error_page = finalized;
                    false
                }
            }
        };
        // An `if` block with settings of its own held: the request goes on
        // with its anonymous location (#137), as nginx's
        // `ngx_http_script_if_code` switches `r->loc_conf`; a response
        // from inside the block too (its `access_log`, `error_page`, …).
        if let Some(n) = rewrite_state.if_location {
            loc = switch_to_if_location(server, n, &mut meta, &mut rewrite_state);
        }
        // Access-control phase (allow/deny, auth_basic): runs after
        // rewrite and before content dispatch. A top-level `return` is a
        // rewrite-module directive in nginx, so it answers in the rewrite
        // phase and access control never runs for it — unless a `break`
        // ended the rewrite program first, in which case nginx never reaches
        // the `return` and does run access control.
        meta.remote_user = None;
        let answered_in_rewrite_phase = rewrite_response.is_some()
            || (!rewrite_broke
                && matches!(loc.handler, crate::worker::PreparedHandler::Return(..)));
        // The realip module's pre-access handler, with the location's
        // settings, unless the post-read one already set the address.
        if !answered_in_rewrite_phase
            && !loc.access.realip.from.is_empty()
            && realip.get().is_none()
            && let Some(state) = real_ip(req, &loc.access.realip)
        {
            let state: &RealIpState = realip.get_or_init(|| Box::new(state));
            meta.realip = Some(Box::new(state.clone()));
            req_now = Some(with_real_ip(req, state));
        }
        let req = req_now.as_ref().unwrap_or(req_in);
        // The access phase doesn't run for it: it is finished like a
        // denial, with the location's filters.
        let mut denied = rewrite_response;
        // After an auth_request subrequest (#358): its outcome, and what
        // the first pass noted, so limit_req and limit_conn don't count
        // the request again.
        let auth_resume = take_auth_resume(loc.access, &mut rewrite_state);
        // `auth_request_set $args …`: the variable's setter replaces the
        // request's arguments (auth_request_set.t, "variable with
        // set_handler").
        if let Some(args) = auth_resume
            .as_ref()
            .and_then(|r| r.vars.iter().find(|(name, _)| *name == b"args"))
        {
            current_args = Some(args.1.clone());
        }
        // The limit_req module's pre-access handler (#94), once per
        // request (nginx's `r->main->limit_req_status`); not again on the
        // way to an error page.
        if !answered_in_rewrite_phase
            && let Some(lr) = loc.limit_req
            && rewrite_state.limit_req_status == 0
            && !in_error_page
        {
            let (rejected, delay_ms) = crate::worker::limit_req::run(
                http,
                server,
                req,
                url_scratch,
                current_args.as_deref(),
                &mut rewrite_state,
                regex_captures.as_ref(),
                lr,
                &meta.log,
                meta.server_name,
                loc.server_header,
            );
            denied = rejected;
            if delay_ms > 0 {
                // The worker waits, then processes the request again
                // (`limit_req::resume_after_delay`): nothing past this
                // point runs now.
                meta.limit_req_delay_ms = delay_ms;
                return (Response::Prebuilt(http.not_found.pick(req.method)), meta);
            }
        }
        // limit_conn's handler, after limit_req's as nginx runs them (#95),
        // once per request.
        if !answered_in_rewrite_phase
            && denied.is_none()
            && let Some(lc) = loc.limit_conn
            && rewrite_state.limit_conn_status == 0
            && !in_error_page
        {
            let (rejected, held) = crate::worker::limit_conn::run(
                http,
                server,
                req,
                url_scratch,
                current_args.as_deref(),
                &mut rewrite_state,
                regex_captures.as_ref(),
                lc,
                &meta.log,
                meta.server_name,
                loc.server_header,
            );
            meta.limit_conn_held = Some(std::rc::Rc::new(held));
            denied = rejected;
        }
        if !answered_in_rewrite_phase && denied.is_none() {
            match run_access_control(
                http,
                req,
                loc.access,
                loc.server_header,
                &meta,
                auth_resume.as_ref(),
            ) {
                AccessControl::Allow { remote_user } => {
                    meta.remote_user = remote_user;
                }
                AccessControl::Deny { response, delay_ms } => {
                    meta.response_delay_ms = delay_ms;
                    denied = Some(response);
                }
                AccessControl::Subrequest => {
                    // The worker runs the subrequest, then processes the
                    // request again (`resume_auth_request`).
                    meta.auth_request = auth_pending(loc.access, &rewrite_state);
                    return (Response::Prebuilt(http.not_found.pick(req.method)), meta);
                }
            }
        }
        // Surface the location's `add_header` list onto `meta` ahead of
        // the handler call. The proxy path consumes the plan async on the
        // worker, by which point the caller has lost direct access to
        // `loc`; threading the slice through `meta` lets the worker apply
        // these headers (with `$upstream_http_*` available) once the
        // upstream future resolves. For non-proxy outcomes the field is
        // simply unused.
        let loc_add_headers = loc.add_headers;
        let loc_add_trailers = loc.add_trailers;
        let loc_chunked_te = loc.chunked_transfer_encoding;
        let loc_expires = loc.expires;
        meta.client_body_in_file_only = loc.client_body_in_file_only;
        meta.sendfile = loc.sendfile;
        meta.gzip = loc.gzip;
        meta.max_ranges = loc.max_ranges;
        // `set $limit_rate` wins over the directive, as nginx's
        // r->limit_rate_set. Rendered only when something is set.
        meta.limit_rate = if loc.limit_rate.is_none() && !rewrite_state.has_user_vars() {
            None
        } else {
            let (rate, after) = crate::worker::evaluate_limit_rate(
                http,
                server,
                req,
                url_scratch,
                current_args.as_deref(),
                &rewrite_state,
                regex_captures.as_ref(),
                loc.limit_rate.copied().unwrap_or_default(),
            );
            ResponseLimit::new(rate, after)
        };
        // `$proxy_host` exists once the proxy handler runs: not for a
        // response from the rewrite or access phase.
        if denied.is_none()
            && let crate::worker::PreparedHandler::Proxy(proxy) = loc.handler
        {
            meta.proxy_host = proxy.host_header;
            meta.proxy_tls = proxy.tls.is_some() && proxy.url.is_none();
        }
        let response = match denied {
            None => run_location_handler(
                http,
                server,
                loc,
                req,
                url_scratch,
                current_args.as_deref(),
                meta.remote_user.as_deref(),
                &rewrite_state,
                error_page_status,
                in_error_page,
                preserved_location.as_deref(),
                &preserved_www_authenticate,
                regex_captures.as_ref(),
            ),
            Some(response) => crate::worker::finish_access_denial(
                http,
                server,
                loc,
                req,
                url_scratch,
                current_args.as_deref(),
                &rewrite_state,
                error_page_status,
                in_error_page,
                preserved_location.as_deref(),
                &preserved_www_authenticate,
                regex_captures.as_ref(),
                response,
                takes_error_page,
            ),
        };
        match response {
            Response::Reroute(next) => {
                run_server_rewrite = true;
                // An internal redirect (error_page, try_files, index): the
                // location is found anew, so no rewrite of the old one
                // counts (ngx_http_handler sets `valid_location` again,
                // find_config clears `uri_changed`, #682). A named location
                // keeps `valid_location`, as ngx_http_named_location does.
                rewrite_state.uri_changed = false;
                if matches!(next.target, RerouteTarget::Uri(_)) {
                    rewrite_state.valid_location = true;
                }
                let to_get = turns_into_get(req, &next);
                if let Some(args) = next.args {
                    current_args = Some(args);
                }
                if let Some(status) = next.error_page_status {
                    error_page_status = Some(status);
                }
                if next.enters_error_page {
                    in_error_page = true;
                }
                if next.closes {
                    meta.keepalive.allow = false;
                }
                if let Some(loc_header) = next.preserved_location {
                    preserved_location = Some(loc_header);
                }
                if !next.preserved_www_authenticate.is_empty() {
                    preserved_www_authenticate = next.preserved_www_authenticate;
                }
                match next.target {
                    RerouteTarget::Uri(uri) => {
                        url_scratch.clear();
                        match uri::normalize_with(&uri, server.merge_slashes, url_scratch) {
                            Ok(_) => {}
                            Err(uri::UriError::EscapesRoot) => {
                                return (Response::Prebuilt(http.forbidden.pick(req.method)), meta);
                            }
                            Err(_) => {
                                return (
                                    Response::Prebuilt(http.bad_request.pick(req.method)),
                                    meta,
                                );
                            }
                        }
                    }
                    RerouteTarget::Named(name) => {
                        named_target = Some(name);
                    }
                }
                if to_get {
                    req_now = Some(error_page_request(req));
                }
            }
            Response::Proxy(plan) => {
                meta.proxy_add_headers = loc_add_headers;
                meta.proxy_add_trailers = loc_add_trailers;
                meta.proxy_chunked_transfer_encoding = loc_chunked_te;
                meta.redirect = loc.redirect;
                meta.proxy_expires = loc_expires;
                meta.underscores_in_headers = server.underscores_in_headers;
                // The proxied response's add_header / proxy_redirect read
                // `set` values, cached maps and `$1`…`$9` after the handler.
                if rewrite_state.worth_keeping() || rewrite_state.has_numbered_captures() {
                    keep_rewrite_state(&mut meta, rewrite_state);
                }
                return (Response::Proxy(plan), meta);
            }
            other => {
                if rewrite_state.worth_keeping() {
                    keep_rewrite_state(&mut meta, rewrite_state);
                }
                return (other, meta);
            }
        }
    }
    // Budget exhausted: nginx returns 500; we match.
    rewrite_cycle_log(url_scratch);
    (
        Response::Owned(crate::http::error_response_for_method(
            500,
            "Internal Server Error\n",
            req.method,
            server.server_header,
        )),
        meta,
    )
}

/// What the realip module changed: the client address it set, and the
/// connection info as the request sees it from then on (`peer_ip`, and
/// the original peer for `$realip_remote_addr`).
#[derive(Debug, Clone)]
pub struct RealIpState {
    pub addr: Vec<u8>,
    /// 0 when the header gave no port: `$remote_port` is empty then.
    pub port: u16,
    pub conn: ConnInfo,
}

/// The client address the realip module finds for `req`, if the peer is
/// trusted and the header gives one (`ngx_http_realip_handler`).
#[cold]
#[inline(never)]
fn real_ip(req: &RequestCtx<'_>, conf: &crate::worker::PreparedRealIp) -> Option<RealIpState> {
    use crate::worker::PreparedRealIpHeader as H;
    let mut joined = Vec::new();
    let (ip, port) = match conf.header {
        H::ProxyProtocol => {
            let source = req.conn.proxy_protocol.as_ref()?.source?;
            if !peer_trusted(conf.from, req.conn) {
                return None;
            }
            (source.ip(), source.port())
        }
        header => {
            let value = match header {
                H::XRealIp => crate::worker::lookup_request_header(req.headers_raw, b"x-real-ip")?,
                H::Other(name) => crate::worker::lookup_request_header(req.headers_raw, name)?,
                // Every X-Forwarded-For line, in order, as one list.
                _ => {
                    crate::worker::write_all_request_header_values(
                        &mut joined,
                        req.headers_raw,
                        b"x-forwarded-for",
                    );
                    &joined
                }
            };
            forwarded_addr(req.conn, value, conf.from, conf.recursive)?
        }
    };
    let mut conn = req.conn.clone();
    conn.peer_ip = ip;
    conn.peer_unix = false;
    conn.realip = Some(Box::new(RealIpPeer {
        addr: req.remote_addr.to_vec(),
        port: req.remote_port,
    }));
    Some(RealIpState {
        addr: ip.to_string().into_bytes(),
        port,
        conn,
    })
}

#[cold]
#[inline(never)]
fn with_real_ip<'a>(req: &RequestCtx<'a>, state: &'a RealIpState) -> RequestCtx<'a> {
    RequestCtx {
        remote_addr: &state.addr,
        remote_port: state.port,
        conn: &state.conn,
        ..*req
    }
}

/// `ngx_http_get_forwarded_addr_internal`: walk `list` (`addr, addr, …`)
/// from the right while the address in hand is trusted. Without
/// `recursive`, only the last entry is taken. `None` when the peer isn't
/// trusted or the last entry doesn't parse.
fn forwarded_addr(
    peer: &ConnInfo,
    list: &[u8],
    from: &[AccessAddr],
    recursive: bool,
) -> Option<(IpAddr, u16)> {
    let is_sep = |b: u8| b == b' ' || b == b',';
    let mut current = peer.peer_ip;
    // The connection's own peer may be a unix-domain one.
    let mut first = true;
    let mut found = None;
    let mut len = list.len();
    loop {
        let trusted = if std::mem::take(&mut first) {
            peer_trusted(from, peer)
        } else {
            real_ip_trusted(from, current)
        };
        if !trusted || len == 0 {
            return found;
        }
        let mut p = len - 1;
        while p > 0 && is_sep(list[p]) {
            p -= 1;
            len -= 1;
        }
        while p > 0 {
            if is_sep(list[p]) {
                p += 1;
                break;
            }
            p -= 1;
        }
        let Some((ip, port)) = parse_addr_port(&list[p..len]) else {
            return found;
        };
        current = ip;
        found = Some((ip, port));
        if !recursive || p == 0 {
            return found;
        }
        len = p - 1;
    }
}

/// `ngx_parse_addr_port`: an address, `[addr]`, or `addr:port` /
/// `[addr]:port`. The port is 0 when there is none.
fn parse_addr_port(text: &[u8]) -> Option<(IpAddr, u16)> {
    let text = std::str::from_utf8(text).ok()?;
    let addr = |s: &str| {
        crate::config::parse_inet_addr(s)
            .map(|v4| IpAddr::V4(v4.into()))
            .or_else(|| s.parse::<std::net::Ipv6Addr>().ok().map(IpAddr::V6))
    };
    if let Some(ip) = addr(text) {
        return Some((ip, 0));
    }
    let (host, port) = match text.strip_prefix('[') {
        Some(rest) => {
            let (host, after) = rest.split_once(']')?;
            // 1.27.3+: `]` last, no port (ngx_inet.c, `p == last - 1`).
            if after.is_empty() {
                return Some((addr(host)?, 0));
            }
            (host, after.strip_prefix(':')?)
        }
        None => text.split_once(':')?,
    };
    if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let port: u16 = port.parse().ok().filter(|&p| p > 0)?;
    Some((addr(host)?, port))
}

/// The connection's peer against `set_real_ip_from`: `unix:` for a
/// unix-domain client, the address otherwise.
fn peer_trusted(from: &[AccessAddr], conn: &ConnInfo) -> bool {
    if conn.peer_unix {
        from.iter().any(|a| matches!(a, AccessAddr::Unix))
    } else {
        real_ip_trusted(from, conn.peer_ip)
    }
}

/// `ngx_cidr_match` against `set_real_ip_from`; IPv4-mapped addresses
/// match the IPv4 entries.
fn real_ip_trusted(from: &[AccessAddr], ip: IpAddr) -> bool {
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        v4 => v4,
    };
    from.iter().any(|entry| match (*entry, ip) {
        (AccessAddr::V4 { addr, mask }, IpAddr::V4(ip)) => u32::from(ip) & mask == addr,
        (AccessAddr::V6 { addr, mask }, IpAddr::V6(ip)) => u128::from(ip) & mask == addr,
        _ => false,
    })
}

/// `ngx_http_send_error_page`: an error_page that sends the request to a
/// URI turns it into a GET, unless it is a HEAD. A named location keeps
/// the method.
fn turns_into_get(req: &RequestCtx<'_>, reroute: &Reroute) -> bool {
    reroute.enters_error_page
        && matches!(reroute.target, RerouteTarget::Uri(_))
        && !matches!(req.method, Method::Get | Method::Head)
}

#[cold]
#[inline(never)]
fn error_page_request<'a>(req: &RequestCtx<'a>) -> RequestCtx<'a> {
    RequestCtx {
        method: Method::Get,
        method_bytes: b"GET",
        ..*req
    }
}

enum AccessControl {
    Allow {
        remote_user: Option<Vec<u8>>,
    },
    /// `delay_ms` is non-zero only for credential failures (missing,
    /// malformed, or wrong) — the worker awaits an async sleep before
    /// writing the 401. Configuration errors (no user file, unreadable)
    /// fail-fast with no delay, matching nginx.
    Deny {
        response: Response,
        delay_ms: u64,
    },
    /// `auth_request` needs its subrequest first (#358).
    Subrequest,
}

/// The access phase: `allow` / `deny`, then auth_basic, then
/// auth_request, combined as `satisfy` says (`ngx_http_core_access_phase`).
/// The common case, no checks at all, stays inline. `auth`: the
/// subrequest's outcome, on the pass after it.
#[inline]
fn run_access_control(
    http: &PreparedHttp,
    req: &RequestCtx<'_>,
    access: &PreparedAccess,
    server_header: &'static [u8],
    meta: &ProcessMeta,
    auth: Option<&AuthResume>,
) -> AccessControl {
    if access.rules.is_empty()
        && matches!(access.auth_basic, PreparedAuthBasic::Off)
        && access.auth_request.is_none()
    {
        return AccessControl::Allow { remote_user: None };
    }
    check_access(http, req, access, server_header, meta, auth)
}

/// The pass after an `auth_request` subrequest: its outcome, with its
/// variables set and the first pass's limit_req / limit_conn statuses
/// restored. `None` on any other pass, or where auth_request is off.
#[inline]
fn take_auth_resume(access: &PreparedAccess, state: &mut RewriteState) -> Option<AuthResume> {
    access.auth_request?;
    let uri = access.auth_request?;
    let resume = AUTH_RESUME.with(|r| {
        r.borrow()
            .iter()
            .find(|(u, _)| *u == uri)
            .map(|(_, resume)| resume.clone())
    })?;
    state.limit_req_status = resume.limit_req_status;
    state.limit_conn_status = resume.limit_conn_status;
    for (name, value) in &resume.vars {
        state.set_user_var(name, value.clone());
    }
    Some(resume)
}

fn auth_pending(access: &PreparedAccess, state: &RewriteState) -> Option<Box<AuthPending>> {
    Some(Box::new(AuthPending {
        uri: access.auth_request?,
        sets: access.auth_request_set,
        limit_req_status: state.limit_req_status,
        limit_conn_status: state.limit_conn_status,
    }))
}

/// The handlers in nginx's order: the access module's, auth_basic's, then
/// auth_request's (the reverse of the module list). With `satisfy all` the
/// first that refuses answers; with `any` the first that allows does, and
/// otherwise a 401 wins over a 403 (`r->access_code`).
#[inline(never)]
fn check_access(
    http: &PreparedHttp,
    req: &RequestCtx<'_>,
    access: &PreparedAccess,
    server_header: &'static [u8],
    meta: &ProcessMeta,
    auth: Option<&AuthResume>,
) -> AccessControl {
    let any = access.satisfy_any;
    // `satisfy any`'s pending refusal: 403, or a 401 with its response.
    let mut unauthorized: Option<(Response, u64)> = None;
    let mut forbidden = match match_access_rules(access.rules, req.conn.peer_ip, req.conn.peer_unix)
    {
        Some(false) if any => return AccessControl::Allow { remote_user: None },
        Some(true) if !any => return access_forbidden(http, req, meta),
        found => found == Some(true),
    };
    let mut remote_user = None;
    match run_auth_basic(http, req, access, server_header) {
        None => {}
        Some(AccessControl::Allow { remote_user: user }) => {
            if any {
                return AccessControl::Allow { remote_user: user };
            }
            remote_user = user;
        }
        Some(AccessControl::Deny { response, delay_ms }) if is_unauthorized(&response) && any => {
            unauthorized = Some((response, delay_ms));
        }
        // A refusal under `satisfy all`, or an error.
        Some(outcome) => return outcome,
    }
    if access.auth_request.is_some() {
        let Some(auth) = auth else {
            return AccessControl::Subrequest;
        };
        match auth.status {
            200..=299 => {
                if any {
                    return AccessControl::Allow { remote_user };
                }
            }
            401 => {
                let response = Response::Owned(crate::auth::build_unauthorized_with(
                    req.method,
                    server_header,
                    &auth.www_authenticate,
                ));
                if !any {
                    return AccessControl::Deny {
                        response,
                        delay_ms: access.auth_delay_ms,
                    };
                }
                // Both handlers' challenges, as nginx keeps the list.
                unauthorized = Some(match unauthorized.take() {
                    Some((basic, delay_ms)) => (merge_challenges(basic, response), delay_ms),
                    None => (response, access.auth_delay_ms),
                });
            }
            403 => {
                if !any {
                    return AccessControl::Deny {
                        response: Response::Prebuilt(http.forbidden.pick(req.method)),
                        delay_ms: 0,
                    };
                }
                forbidden = true;
            }
            status => {
                crate::worker::write_error_log(
                    meta.log.error_logs,
                    crate::config::ErrorLogLevel::Error,
                    &crate::worker::ErrorLogRequest::new(req, meta.server_name),
                    format!("auth request unexpected status: {status}").as_bytes(),
                    None,
                );
                return AccessControl::Deny {
                    response: Response::Prebuilt(http.internal_error.pick(req.method)),
                    delay_ms: 0,
                };
            }
        }
    }
    // The post-access phase: what `satisfy any` kept, a 401 first.
    match unauthorized {
        Some((response, delay_ms)) => AccessControl::Deny { response, delay_ms },
        None if forbidden => access_forbidden(http, req, meta),
        None => AccessControl::Allow { remote_user },
    }
}

fn is_unauthorized(response: &Response) -> bool {
    match response {
        Response::Owned(b) => crate::worker::response_status(b) == 401,
        Response::Prebuilt(b) => crate::worker::response_status(b) == 401,
        _ => false,
    }
}

/// auth_basic's 401 with auth_request's `WWW-Authenticate` lines added.
fn merge_challenges(basic: Response, other: Response) -> Response {
    let (Response::Owned(mut basic), Response::Owned(other)) = (basic, other) else {
        unreachable!("both 401s are built owned");
    };
    let lines: Vec<u8> = other
        .split(|&b| b == b'\n')
        .filter(|l| l.len() > 18 && l[..18].eq_ignore_ascii_case(b"www-authenticate: "))
        .flat_map(|l| {
            b"\r\n"
                .iter()
                .chain(l.strip_suffix(b"\r").unwrap_or(l))
                .copied()
        })
        .collect();
    if let Some(head_end) = basic.windows(4).position(|w| w == b"\r\n\r\n") {
        basic.splice(head_end..head_end, lines);
    }
    Response::Owned(basic)
}

/// The first `allow` / `deny` rule matching `peer`: `Some(deny)`, or
/// `None` when none does (`ngx_http_access_handler`). An IPv4-mapped IPv6
/// peer is matched as IPv4.
fn match_access_rules(rules: &[AccessRule], peer: IpAddr, unix: bool) -> Option<bool> {
    // A unix-domain client matches only `all` and `unix:`
    // (ngx_http_access_handler by address family).
    if unix {
        return rules.iter().find_map(|rule| {
            matches!(rule.addr, AccessAddr::All | AccessAddr::Unix).then_some(rule.deny)
        });
    }
    let peer = match peer {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        v4 => v4,
    };
    rules.iter().find_map(|rule| {
        let hit = match (rule.addr, peer) {
            (AccessAddr::All, _) => true,
            (AccessAddr::V4 { addr, mask }, IpAddr::V4(ip)) => u32::from(ip) & mask == addr,
            (AccessAddr::V6 { addr, mask }, IpAddr::V6(ip)) => u128::from(ip) & mask == addr,
            _ => false,
        };
        hit.then_some(rule.deny)
    })
}

/// A 403 from the rules, logged as nginx does.
#[cold]
#[inline(never)]
fn access_forbidden(
    http: &PreparedHttp,
    req: &RequestCtx<'_>,
    meta: &ProcessMeta,
) -> AccessControl {
    crate::worker::write_error_log(
        meta.log.error_logs,
        crate::config::ErrorLogLevel::Error,
        &crate::worker::ErrorLogRequest::new(req, meta.server_name),
        b"access forbidden by rule",
        None,
    );
    AccessControl::Deny {
        response: Response::Prebuilt(http.forbidden.pick(req.method)),
        delay_ms: 0,
    }
}

/// auth_basic: `None` when it is off, else whether the credentials pass.
fn run_auth_basic(
    http: &PreparedHttp,
    req: &RequestCtx<'_>,
    access: &PreparedAccess,
    server_header: &'static [u8],
) -> Option<AccessControl> {
    let PreparedAuthBasic::Realm(realm) = access.auth_basic else {
        return None;
    };
    let auth_delay_ms = access.auth_delay_ms;
    let internal_error = || AccessControl::Deny {
        response: Response::Owned(crate::http::error_response_for_method(
            500,
            "Internal Server Error\n",
            req.method,
            server_header,
        )),
        delay_ms: 0,
    };
    let Some(user_file) = access.auth_basic_user_file else {
        return Some(internal_error());
    };
    let Some(user_file) = resolve_auth_basic_user_file(req, user_file, http.conf_prefix) else {
        return Some(internal_error());
    };
    let creds = match auth::decode_basic_authorization(req.headers_raw) {
        Ok(creds) => creds,
        Err(auth::BasicHeaderError::Missing | auth::BasicHeaderError::Malformed) => {
            let response = auth::build_unauthorized_response(req.method, server_header, realm);
            return Some(AccessControl::Deny {
                response: Response::Owned(response),
                delay_ms: auth_delay_ms,
            });
        }
    };
    Some(match auth::verify_credentials(user_file.as_ref(), &creds) {
        Ok(true) => AccessControl::Allow {
            remote_user: Some(creds.username),
        },
        Ok(false) => {
            let response = auth::build_unauthorized_response(req.method, server_header, realm);
            AccessControl::Deny {
                response: Response::Owned(response),
                delay_ms: auth_delay_ms,
            }
        }
        // Hash compare or htpasswd I/O failed. Don't apply `auth_delay`
        // here: the delay's purpose is to throttle credential-probing
        // attackers; an internal verification fault isn't a probe and
        // shouldn't have the request held open.
        Err(_) => internal_error(),
    })
}

/// Literal paths were already resolved against the config directory at
/// parse time. Paths with variables are rendered per request; a relative
/// result is then resolved against the config directory too, matching
/// nginx's `ccv.conf_prefix = 1` for this directive.
fn resolve_auth_basic_user_file<'a>(
    req: &RequestCtx<'_>,
    user_file: &'a Path,
    conf_prefix: Option<&Path>,
) -> Option<Cow<'a, Path>> {
    let raw = user_file.to_string_lossy();
    if !raw.as_bytes().contains(&b'$') {
        return Some(Cow::Borrowed(user_file));
    }
    let parts = crate::config::parse_value_with_vars(&raw).ok()?;
    let mut rendered = Vec::with_capacity(raw.len());
    let args = request_args(req.path);
    let uri = request_uri_path(req.path);
    for part in parts {
        match part {
            ValuePart::Literal(s) => rendered.extend_from_slice(s.as_bytes()),
            ValuePart::Var(var) => write_auth_path_var(&var, req, args, uri, &mut rendered),
        }
    }
    let rendered = PathBuf::from(String::from_utf8_lossy(&rendered).as_ref());
    Some(Cow::Owned(crate::config::resolve_conf_path(
        conf_prefix,
        rendered,
    )))
}

fn write_auth_path_var(
    var: &Variable,
    req: &RequestCtx<'_>,
    args: &[u8],
    uri_path: &[u8],
    out: &mut Vec<u8>,
) {
    match var {
        Variable::Uri => out.extend_from_slice(uri_path),
        Variable::RequestUri => out.extend_from_slice(req.path),
        Variable::Host => out.extend_from_slice(req.host.unwrap_or(b"")),
        Variable::Args => out.extend_from_slice(args),
        Variable::IsArgs => {
            if !args.is_empty() {
                out.push(b'?');
            }
        }
        Variable::Arg(name) => {
            if let Some(value) = request_arg_value(args, name.as_bytes()) {
                out.extend_from_slice(value);
            }
        }
        _ => {}
    }
}

fn request_uri_path(request_uri: &[u8]) -> &[u8] {
    match request_uri.iter().position(|&b| b == b'?') {
        Some(i) => &request_uri[..i],
        None => request_uri,
    }
}

fn request_args(request_uri: &[u8]) -> &[u8] {
    match request_uri.iter().position(|&b| b == b'?') {
        Some(i) if i + 1 < request_uri.len() => &request_uri[i + 1..],
        Some(_) | None => &[],
    }
}

fn request_arg_value<'a>(args: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    if args.is_empty() {
        return None;
    }
    for pair in args.split(|&b| b == b'&') {
        let (key, value) = match pair.iter().position(|&b| b == b'=') {
            Some(eq) => (&pair[..eq], &pair[eq + 1..]),
            None => (pair, &[][..]),
        };
        // ngx_http_arg: the name matches whatever its case.
        if key.eq_ignore_ascii_case(name) {
            return Some(value);
        }
    }
    None
}

/// One server-name regex hit, with the named-capture values surfaced for
/// `$name` rendering. Owns the captured bytes so the type carries no
/// borrow lifetime — the captures live as long as the `ProcessMeta` /
/// render path needs them, regardless of when the request `Host` slice
/// is dropped.
pub struct ServerNameCaptures {
    pub names: Vec<(&'static str, Vec<u8>)>,
    /// `$1`…`$9` (index 0 is `$1`; empty when the group didn't take
    /// part), until a regex location, `rewrite` or `if` replaces them.
    pub numbered: Vec<Vec<u8>>,
}

/// `client_max_body_size` of the location a request is routed to first,
/// with what an error-log line about it needs.
pub(crate) struct FirstBodyLimit {
    /// In bytes; `0` turns the check off.
    pub max: u64,
    /// `client_body_buffer_size`: a body above it goes to a temp file;
    /// with `client_body_in_file_only on|clean`, 0: every body does.
    pub buffer: u64,
    pub error_logs: &'static [PreparedErrorLog],
    pub server_name: &'static [u8],
    /// `client_body_in_file_only on`: a temp file holding the body
    /// outlives the request (nginx's `request_body_in_persistent_file`).
    pub persistent: bool,
    /// The location's `client_body_temp_path` directory, if it (or its
    /// server) has its own.
    pub body_temp: Option<&'static crate::worker::BodyTempDir>,
    /// Nothing can read the body (`discards_body`): the response goes
    /// first and the body is dropped, as nginx's
    /// ngx_http_discard_request_body does, instead of being kept.
    pub discard: bool,
    /// With `discard`, which response a `100 Continue` goes out before
    /// (`discard_continue`); only looked at, and set, with an `Expect`.
    pub continue_status: Option<u16>,
    /// The location's `client_body_timeout` (#147).
    pub body_timeout: std::time::Duration,
}

/// The limit nginx holds a request's Content-Length to before reading the
/// body: that of the location `ngx_http_core_find_config_phase` finds
/// first, after the server's rewrite phase. The worker reads bodies before
/// routing, so it asks this first and refuses an oversized body unread.
/// `None` when the request doesn't get to a location that way (refused,
/// answered by the server's rewrite phase, an `internal` location): then
/// the body is read and the pipeline answers as before. Pure: runs the
/// server's rewrite program on a throwaway state, and leaves `url_scratch`
/// to be reset by `process_with_meta`.
pub(crate) fn first_body_limit(
    http: &'static PreparedHttp,
    req: &RequestCtx<'_>,
    url_scratch: &mut Vec<u8>,
    // An `Expect` header came: `continue_status` is wanted.
    expect: bool,
) -> Option<FirstBodyLimit> {
    let listen = select_listen(http, req.listen_index)?;
    if req.refuse.is_some()
        || (req.http_11 && req.host.is_none_or(|h| h.is_empty()))
        || matches!(req.method, Method::Trace | Method::Connect)
    {
        return None;
    }
    let (server, regex_captures) = find_config(listen, req.host, req.sni);
    url_scratch.clear();
    normalize_request_uri_into(http, req, server.merge_slashes, url_scratch).ok()?;
    let mut rewrite_state = RewriteState::default();
    if !server.rewrite_program.is_empty() {
        let mut current_args = None;
        if crate::worker::run_server_rewrite(
            http,
            server,
            req,
            url_scratch,
            &mut current_args,
            &mut rewrite_state,
            regex_captures.as_ref(),
        )
        .is_some()
        {
            return None;
        }
    }
    let loc = match match_location(server, url_scratch, &mut rewrite_state) {
        Some(loc) => loc,
        None => MatchedLocation::from_prefix(server.server_default.as_ref()?),
    };
    if loc.internal {
        return None;
    }
    Some(FirstBodyLimit {
        max: loc
            .client_max_body_size
            .unwrap_or(crate::worker::DEFAULT_CLIENT_MAX_BODY_SIZE),
        // nginx writes the body to a file whatever its size when
        // `request_body_in_file_only` is set (ngx_http_read_client_request_body).
        buffer: match loc.client_body_in_file_only {
            crate::config::ClientBodyInFileOnly::Off => loc
                .client_body_buffer_size
                .unwrap_or(crate::worker::DEFAULT_CLIENT_BODY_BUFFER_SIZE),
            _ => 0,
        },
        error_logs: loc.error_logs,
        server_name: server.primary_server_name,
        persistent: matches!(
            loc.client_body_in_file_only,
            crate::config::ClientBodyInFileOnly::On
        ),
        body_temp: loc.body_temp,
        discard: discards_body(http, server, &loc, url_scratch, true, 0),
        continue_status: if expect { discard_continue(&loc) } else { None },
        body_timeout: loc.timeouts.body,
    })
}

/// Where the body is discarded, which response nginx sends a `100
/// Continue` before, the discard sending it (ngx_http_test_expect) unless
/// the special response handler set `expect_tested` first. A `return`
/// discards in ngx_http_send_response for a status under 400 or with a
/// text (ngx_http_script_return_code), so `Some` of that status, `Some(0)`
/// for none; an error it or the access phase answers goes without. `None`
/// for a static file: its handler discards once the file is open
/// (ngx_http_static_module.c), so its 200, 206, 304, 412 and 416 follow
/// a 100, and a 404, a 403 or a 301 to the directory don't.
fn discard_continue(loc: &MatchedLocation<'_>) -> Option<u16> {
    use crate::worker::{PreparedHandler, PreparedReturn};
    let PreparedHandler::Return(ret, finalized) = loc.handler else {
        return None;
    };
    let status = match ret {
        PreparedReturn::Static(prebuilt, _) => crate::worker::response_status(prebuilt.head),
        PreparedReturn::Template { status, .. } => *status,
    };
    // `finalized`: no text, or a redirect.
    Some(if status < 400 || !finalized {
        status
    } else {
        0
    })
}

/// Whether nothing a request in `loc` (at `uri`) can get to reads its
/// body, so it is discarded and the response goes first (#627). A
/// `return` with no rewrite, `if`, `error_page`, `post_action` or
/// `limit_except` that could take the request elsewhere, while neither
/// `$request_body` nor `$request_body_file` appears anywhere (#289). A
/// static file, as nginx's static module discards the body
/// (ngx_http_static_module.c:221), so `$request_body` is empty there as in
/// nginx; but `index` and `error_page` redirect before that discard
/// (ngx_http_special_response.c:470-481), so where they lead must discard
/// too. `try_files`, rewrites, `auth_request` and the rest aren't
/// followed: the body is read. `errors_redirect`: the location's
/// `error_page` applies (not past an error page without
/// `recursive_error_pages`). Cold: only for requests with a body.
#[cold]
#[inline(never)]
fn discards_body(
    http: &PreparedHttp,
    server: &PreparedServer,
    loc: &MatchedLocation<'_>,
    uri: &[u8],
    errors_redirect: bool,
    hops: u8,
) -> bool {
    use crate::worker::PreparedHandler;
    if hops > 2
        || !loc.rewrite_program.is_empty()
        || loc.post_action.is_some()
        || loc.limit_except.is_some()
    {
        return false;
    }
    let root = match loc.handler {
        PreparedHandler::Return(..) => {
            return !http.uses_request_body
                && !http.uses_request_body_file
                && (loc.error_pages.is_empty() || !errors_redirect);
        }
        PreparedHandler::Root(root) => root,
        _ => return false,
    };
    if root.try_files.is_some()
        || loc.access.auth_request.is_some()
        || loc.auto_redirect_to.is_some()
    {
        return false;
    }
    // Where an internal redirect goes, as `process` routes it.
    let follow = |target: &[u8], errors_redirect: bool| {
        let mut state = RewriteState::default();
        let next = if target.first() == Some(&b'@') {
            match_named_location(server, target)
        } else {
            match_location(server, target, &mut state).or_else(|| {
                server
                    .server_default
                    .as_ref()
                    .map(MatchedLocation::from_prefix)
            })
        };
        next.is_some_and(|next| {
            discards_body(http, server, &next, target, errors_redirect, hops + 1)
        })
    };
    if uri.ends_with(b"/") {
        for entry in root.index {
            let Some(name) = literal_value(entry.parts) else {
                return false;
            };
            let target = if name.first() == Some(&b'/') {
                name
            } else {
                [uri, &name[..]].concat()
            };
            if !follow(&target, errors_redirect) {
                return false;
            }
        }
    }
    if !errors_redirect {
        return true;
    }
    loc.error_pages.iter().all(|page| {
        // What a static location answers before its handler drops the
        // body: the access phase, the file lookup, the method check, and
        // the conditional and range checks.
        let arises = matches!(page.status, 301 | 401 | 403 | 404 | 405 | 412 | 416 | 500)
            || loc.limit_req.is_some_and(|l| l.status == page.status)
            || loc.limit_conn.is_some_and(|l| l.status == page.status);
        if !arises {
            return true;
        }
        let Some(target) = literal_value(page.target) else {
            return false;
        };
        match target.first() {
            Some(b'/') => {
                let path = target.split(|&b| b == b'?').next().unwrap_or_default();
                follow(path, loc.recursive_error_pages)
            }
            Some(b'@') => follow(&target, loc.recursive_error_pages),
            // An external redirect, or nothing.
            _ => true,
        }
    })
}

/// A value with no variables, as its bytes.
fn literal_value(parts: &[crate::worker::PreparedValuePart]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    for part in parts {
        match part {
            crate::worker::PreparedValuePart::Literal(bytes) => out.extend_from_slice(bytes),
            crate::worker::PreparedValuePart::Var(_) => return None,
        }
    }
    Some(out)
}

fn select_listen(http: &PreparedHttp, listen_index: usize) -> Option<&PreparedListen> {
    http.listens.get(listen_index)
}

pub(crate) fn default_server_header(http: &PreparedHttp) -> &'static [u8] {
    http.listens
        .first()
        .and_then(|listen| listen.servers.get(listen.default_server))
        .map(|server| server.server_header)
        .unwrap_or(b"ruxen")
}

/// FIND_CONFIG phase — pick a server block by Host, then a location
/// within it. Selection priority follows nginx's
/// `ngx_http_find_virtual_server` (`ngx_http_request.c`), with an SNI
/// fallback for TLS connections (mirrors nginx's
/// `ngx_http_ssl_servername` initial-server-from-SNI behavior):
///
/// 1. Run the exact / leading-wildcard / trailing-wildcard / regex ladder
///    against the HTTP `Host` header.
/// 2. If `Host` is absent, claim the request for any `server_name "";`
///    block before falling through.
/// 3. Run the same ladder against the SNI hostname for TLS connections —
///    a `Host` header that contradicts SNI keeps step 1, but a missing or
///    unmatched `Host` lets SNI pick the server.
/// 4. Default server for the listen address.
fn find_config<'h, 'r>(
    listen: &'h PreparedListen,
    host: Option<&'r [u8]>,
    sni: Option<&'r [u8]>,
) -> (&'h PreparedServer, Option<ServerNameCaptures>) {
    if let Some(host_raw) = host {
        if let Some(hit) = match_server_name(listen, host_raw) {
            return hit;
        }
    } else {
        // No Host header — `server_name "";` claims the request before
        // SNI fallback. Matches nginx's pre-SNI behavior on plain HTTP.
        for server in &listen.servers {
            if server.matches_empty {
                return (server, None);
            }
        }
    }

    if let Some(sni_raw) = sni
        && let Some(hit) = match_server_name(listen, sni_raw)
    {
        return hit;
    }

    (&listen.servers[listen.default_server], None)
}

/// The anonymous location of an `if` block (#137) as the request's
/// location from here on: its handler, headers, limits and logs. Cold.
#[cold]
#[inline(never)]
fn switch_to_if_location(
    server: &'static PreparedServer,
    n: u32,
    meta: &mut ProcessMeta,
    rewrite_state: &mut RewriteState,
) -> MatchedLocation<'static> {
    let loc = MatchedLocation::from_prefix(&server.if_locations[n as usize]);
    // What the location sets in the request's meta before its rewrite
    // program, again for the new one.
    apply_location_meta(&loc, meta, rewrite_state);
    loc
}

/// The request's meta from the location it is in: what the location sets
/// before its rewrite program, and an `if` location again (#137).
#[inline(always)]
fn apply_location_meta(
    loc: &MatchedLocation<'static>,
    meta: &mut ProcessMeta,
    rewrite_state: &mut RewriteState,
) {
    rewrite_state.doc_root = Some(loc.doc_root);
    meta.keepalive = KeepaliveMeta {
        // Once off, it stays off across internal redirects: nginx's
        // ngx_http_update_location_config only ever clears r->keepalive.
        allow: meta.keepalive.allow && loc.keepalive.allow,
        idle_timeout_ms: loc.keepalive.idle_timeout_ms,
        header_timeout_secs: loc.keepalive.header_timeout_secs,
        max_requests: loc.keepalive.max_requests,
        max_time_ms: loc.keepalive.max_time_ms,
        disable_msie6: loc.keepalive.disable_msie6,
        disable_safari: loc.keepalive.disable_safari,
    };
    meta.access_logs = loc.access_logs;
    meta.doc_root = Some(loc.doc_root);
    meta.timeouts = Some(loc.timeouts);
    meta.post_action = loc.post_action;
    meta.log = LogMeta {
        error_logs: loc.error_logs,
        log_not_found: loc.log_not_found,
    };
}

/// Whether a ClientHello with this SNI name is to be refused
/// (`ssl_reject_handshake`): the server the name selects, as nginx's
/// servername callback finds it, else the address's TLS default server.
pub(crate) fn rejects_handshake(listen: &PreparedListen, sni: Option<&str>) -> bool {
    let Some((rejecting, default)) = &listen.reject_handshake else {
        return false;
    };
    let index = sni
        .and_then(|name| match_server_name(listen, name.as_bytes()))
        .and_then(|(server, _)| listen.servers.iter().position(|s| std::ptr::eq(s, server)))
        .unwrap_or(*default);
    rejecting.get(index).copied().unwrap_or(false)
}

/// The handshake for a ClientHello with this SNI name: refused
/// (`rejects_handshake`), or accepted with `h2` offered only when the
/// server the name selects (else the TLS default server) has HTTP/2 on,
/// as ngx_http_ssl_alpn_select asks the server the servername callback
/// chose (#144).
/// Why `ssl_verify_client` refuses this request, if it does: the status
/// (421, 495 or 496) and whether the connection closes after it, as nginx
/// closes it after 495 and 496.
#[cold]
#[inline(never)]
fn client_certificate_refusal(
    listen: &PreparedListen,
    server: &'static PreparedServer,
    req: &RequestCtx<'_>,
    tls: &crate::tls::HandshakeInfo,
) -> Option<(u16, bool)> {
    use crate::client_verify::ClientVerify;
    use crate::config::{ErrorLogLevel, VerifyClient};
    let log = |message: &[u8]| {
        crate::worker::write_error_log(
            server.error_logs,
            ErrorLogLevel::Info,
            &crate::worker::ErrorLogRequest::new(req, server.primary_server_name),
            message,
            None,
        )
    };
    // The server the Host names, else the default one, as nginx looks it
    // up when the Host isn't the SNI name.
    if let (Some(sni), Some(host)) = (req.sni, req.host)
        && !host.eq_ignore_ascii_case(sni)
    {
        let named = match_server_name(listen, host)
            .map(|(s, _)| s)
            .unwrap_or(&listen.servers[listen.default_server]);
        if named.client_verify != VerifyClient::Off {
            log(b"client attempted to request the server name different from the one that was negotiated");
            return Some((421, false));
        }
    }
    match (server.client_verify, &tls.client_verify) {
        (VerifyClient::Off, _) => None,
        (mode, ClientVerify::Failed(code, text))
            if mode != VerifyClient::OptionalNoCa
                || !crate::x509_verify::error_is_optional(*code as std::ffi::c_long) =>
        {
            log(format!("client SSL certificate verify error: ({code}:{text})").as_bytes());
            Some((495, true))
        }
        (VerifyClient::On, ClientVerify::None) => {
            log(b"client sent no required SSL certificate");
            Some((496, true))
        }
        _ => None,
    }
}

pub(crate) fn tls_choice(listen: &PreparedListen, sni: Option<&str>) -> crate::tls_stream::Choice {
    use crate::tls_stream::Choice;
    if rejects_handshake(listen, sni) {
        return Choice::Reject;
    }
    if !listen.h2_by_sni && !listen.tls_contexts_by_sni {
        return Choice::Accept {
            h2: true,
            context: None,
        };
    }
    let server = sni
        .and_then(|name| match_server_name(listen, name.as_bytes()))
        .map(|(server, _)| server)
        .unwrap_or(&listen.servers[listen.tls_default_server]);
    Choice::Accept {
        h2: !listen.h2_by_sni || server.http2,
        context: server.tls_context,
    }
}

/// The server a request with this `Host` (else SNI name) goes to, as
/// `process` chooses it.
pub(crate) fn server_for(
    listen: &'static PreparedListen,
    host: Option<&[u8]>,
    sni: Option<&[u8]>,
) -> &'static PreparedServer {
    find_config(listen, host, sni).0
}

/// Run the exact / leading-wildcard / trailing-wildcard / regex ladder
/// for one candidate hostname. Used both for the HTTP `Host` header pass
/// and the TLS SNI fallback pass — the matching logic is identical, only
/// the input bytes differ. Returns `None` when nothing matches so the
/// caller can chain candidates and only fall back to the default server
/// once all of them have failed.
fn match_server_name<'h>(
    listen: &'h PreparedListen,
    host_raw: &[u8],
) -> Option<(&'h PreparedServer, Option<ServerNameCaptures>)> {
    // Lowercase host once for case-insensitive matching against
    // already-lowercased prepared names. Hot path is the all-lowercase
    // input; falls back to a 256-byte stack buffer, then a heap Vec for
    // the rare oversized hostnames seen in pathological clients.
    // Initialized only when used: zeroing it on every request showed in
    // the profile.
    let mut host_lc_buf: [u8; 256];
    let owned_lc: Vec<u8>;
    let host_lc: &[u8] = if host_raw.iter().all(|b| !b.is_ascii_uppercase()) {
        host_raw
    } else if host_raw.len() <= 256 {
        host_lc_buf = [0; 256];
        for (i, &b) in host_raw.iter().enumerate() {
            host_lc_buf[i] = b.to_ascii_lowercase();
        }
        &host_lc_buf[..host_raw.len()]
    } else {
        owned_lc = host_raw.iter().map(|b| b.to_ascii_lowercase()).collect();
        &owned_lc[..]
    };

    // 1. Exact match: one hash lookup (nginx's server-name hash).
    if let Some(&si) = listen.exact_names.get(host_lc) {
        return Some((&listen.servers[si as usize], None));
    }

    // 2. Longest leading-wildcard. Each list is sorted by descending
    // length; we still scan all servers to find the global longest.
    let mut best_lead: Option<(usize, &PreparedServer)> = None;
    for server in &listen.servers {
        for suffix in &server.wildcard_leading {
            if host_matches_leading_wildcard(host_lc, suffix) {
                let len = suffix.len();
                if best_lead.is_none_or(|(blen, _)| len > blen) {
                    best_lead = Some((len, server));
                }
            }
        }
    }
    if let Some((_, server)) = best_lead {
        return Some((server, None));
    }

    // 3. Longest trailing-wildcard.
    let mut best_trail: Option<(usize, &PreparedServer)> = None;
    for server in &listen.servers {
        for head in &server.wildcard_trailing {
            if host_matches_trailing_wildcard(host_lc, head) {
                let len = head.len();
                if best_trail.is_none_or(|(blen, _)| len > blen) {
                    best_trail = Some((len, server));
                }
            }
        }
    }
    if let Some((_, server)) = best_trail {
        return Some((server, None));
    }

    // 4. First regex match in declaration order. Captures are surfaced
    // for `$name` rendering on the request that landed.
    // One pass over every regex name of the listen (#248); without a set,
    // each in turn.
    let first = match &listen.regex_name_set {
        Some((set, index)) => {
            let i = set.matches(host_raw).iter().next()?;
            Some(index[i])
        }
        None => None,
    };
    for (si, server) in listen.servers.iter().enumerate() {
        for (ni, rn) in server.regex_names.iter().enumerate() {
            if first.is_some_and(|(s, n)| (s as usize, n as usize) != (si, ni)) {
                continue;
            }
            if let Some(caps) = rn.regex.captures(host_raw) {
                let mut names: Vec<(&'static str, Vec<u8>)> = Vec::new();
                for &cn in &rn.capture_names {
                    if let Some(m) = caps.name(cn) {
                        names.push((cn, m.as_bytes().to_vec()));
                    }
                }
                let numbered: Vec<Vec<u8>> = (1..caps.len().min(10))
                    .map(|n| caps.get(n).map_or_else(Vec::new, |m| m.as_bytes().to_vec()))
                    .collect();
                let caps_out = if names.is_empty() && numbered.is_empty() {
                    None
                } else {
                    Some(ServerNameCaptures { names, numbered })
                };
                return Some((server, caps_out));
            }
        }
    }

    None
}

/// Match `host` against a `*.suffix` wildcard. Matches when the host
/// equals the suffix or ends with `.suffix` — the dot has to be present
/// or the wildcard would also match `xexample.com` against
/// `*.example.com`.
fn host_matches_leading_wildcard(host: &[u8], suffix: &[u8]) -> bool {
    // `*.example.com` doesn't take `example.com` (ngx_hash_find_wc_head);
    // `.example.com` does, as an exact name the parser adds beside it.
    if host.len() <= suffix.len() {
        return false;
    }
    let split = host.len() - suffix.len();
    host[split - 1] == b'.' && &host[split..] == suffix
}

/// Match `host` against a `head.*` wildcard: it starts with `head.`
/// (`www.example.*` doesn't take `www.example`, ngx_hash_find_wc_tail).
fn host_matches_trailing_wildcard(host: &[u8], head: &[u8]) -> bool {
    if host.len() <= head.len() {
        return false;
    }
    &host[..head.len()] == head && host[head.len()] == b'.'
}

/// Location match — five-step ladder mirroring nginx's
/// `ngx_http_core_find_static_location` + the regex loop in
/// `ngx_http_core_find_location` (core_module.c:1454):
///
/// 1. Scan exact (`=`) candidates → on hit, return immediately.
/// 2. Scan prefix candidates, pre-sorted by descending pattern length, and
///    record the first hit as `best` — which by construction is also the
///    longest prefix match, because the list is sorted.
/// 3. If `best` is set and carries the `^~` flag → return it without
///    consulting regex (`clcf->noregex`).
/// 4. Walk regex_locations in declaration order → first match wins.
/// 5. Fall back to `best` (or `None` → 404).
///
/// All lists are tiny in practice (<20 in any realistic config) so linear
/// scans beat tree lookups for both cache and code-size reasons. Cost when
/// no regex locations are configured: one `Vec::is_empty()` check. Named
/// locations are looked up separately on internal redirects and are never
/// part of this external URI ladder.
pub(crate) fn match_location<'a>(
    server: &'a PreparedServer,
    path: &[u8],
    rewrite_state: &mut RewriteState,
) -> Option<MatchedLocation<'a>> {
    // `$1`…`$9` stay as they are unless a regex location matches: nginx's
    // location search leaves r->captures alone on no match, so a regex
    // server_name's (or an earlier rewrite's) captures carry on.
    for loc in &server.exact_locations {
        if loc.pattern == path {
            return Some(MatchedLocation::from_prefix(loc));
        }
    }

    if let Some(loc) = auto_redirect_match(&server.exact_locations, path)
        .or_else(|| auto_redirect_match(&server.prefix_locations, path))
    {
        return Some(loc);
    }

    // Locations nested in others: nginx's search, level by level.
    if let Some(tree) = &server.location_tree {
        return match_nested(server, tree, path, rewrite_state);
    }

    let best = server
        .prefix_locations
        .iter()
        .find(|loc| path.starts_with(loc.pattern));

    if let Some(loc) = best
        && loc.noregex
    {
        return Some(MatchedLocation::from_prefix(loc));
    }

    if !server.regex_locations.is_empty() {
        // Bytes mode: percent-decoding in `uri::normalize` can leave the
        // path as arbitrary octets (e.g. `/img%FF.gif` decodes to `…0xFF…`).
        // Going through `from_utf8` would silently skip the regex pass for
        // any non-UTF-8 sequence — nginx matches PCRE against
        // `r->uri.data` as raw bytes, and so do we.
        // One pass over all of them finds the first match in declaration
        // order (#248); only that one's captures are taken.
        let first = match &server.regex_location_set {
            Some(set) => set.matches(path).iter().next(),
            None => None,
        };
        let candidates: &[crate::worker::PreparedRegexLocation] = match first {
            Some(i) => &server.regex_locations[i..=i],
            None if server.regex_location_set.is_some() => &[],
            None => &server.regex_locations,
        };
        for rloc in candidates {
            if let Some(captures) = rloc.regex.captures(path) {
                rewrite_state.set_numbered_from_regex_captures(&captures, path);
                return Some(MatchedLocation::from_regex(rloc));
            }
        }
    }

    best.map(MatchedLocation::from_prefix)
}

/// `match_location` for a server with nested locations, as nginx's
/// ngx_http_core_find_location: on each level, an exact match ends the
/// search; else the longest prefix, and the locations nested in it are
/// searched before this level's regex locations (unless the prefix has
/// `^~`); a regex match ends it, after a search of its own nested ones.
/// A regex location nested in a prefix one is tried only for URIs that
/// prefix matches, and before the server's own (#730).
#[cold]
#[inline(never)]
fn match_nested<'a>(
    server: &'a PreparedServer,
    tree: &crate::worker::LocationTree,
    path: &[u8],
    rewrite_state: &mut RewriteState,
) -> Option<MatchedLocation<'a>> {
    // Which regex locations match at all, in one pass (#248).
    let hits = server
        .regex_location_set
        .as_ref()
        .map(|set| set.matches(path));
    let hit = |r: usize| hits.as_ref().is_none_or(|h| h.matched(r));
    #[derive(PartialEq)]
    enum Found {
        /// An exact or a regex location: the search is over.
        Final,
        /// A prefix location: a regex one further up may still win.
        Prefix,
        Nothing,
    }
    fn level<'a>(
        server: &'a PreparedServer,
        tree: &crate::worker::LocationTree,
        at: usize,
        path: &[u8],
        rewrite_state: &mut RewriteState,
        hit: &dyn Fn(usize) -> bool,
    ) -> (Found, Option<MatchedLocation<'a>>) {
        let lvl = &tree.levels[at];
        for &e in &lvl.exact {
            let loc = &server.exact_locations[e as usize];
            if loc.pattern == path {
                return (Found::Final, Some(MatchedLocation::from_prefix(loc)));
            }
        }
        let mut found = (Found::Nothing, None);
        let mut noregex = false;
        if let Some(&p) = lvl
            .prefix
            .iter()
            .find(|&&p| path.starts_with(server.prefix_locations[p as usize].pattern))
        {
            let loc = &server.prefix_locations[p as usize];
            found = (Found::Prefix, Some(MatchedLocation::from_prefix(loc)));
            noregex = loc.noregex;
            if let Some(child) = tree.prefix_children[p as usize] {
                let (deeper, m) = level(server, tree, child as usize, path, rewrite_state, hit);
                if m.is_some() {
                    found.1 = m;
                }
                if deeper == Found::Final {
                    return (Found::Final, found.1);
                }
            }
        }
        if !noregex {
            for &r in &lvl.regex {
                let rloc = &server.regex_locations[r as usize];
                if !hit(r as usize) {
                    continue;
                }
                if let Some(captures) = rloc.regex.captures(path) {
                    rewrite_state.set_numbered_from_regex_captures(&captures, path);
                    let mut m = MatchedLocation::from_regex(rloc);
                    if let Some(child) = tree.regex_children[r as usize]
                        && let (_, Some(deeper)) =
                            level(server, tree, child as usize, path, rewrite_state, hit)
                    {
                        m = deeper;
                    }
                    return (Found::Final, Some(m));
                }
            }
        }
        found
    }
    level(server, tree, 0, path, rewrite_state, &hit).1
}

/// What a `Location` that starts with `/` becomes (#15), as nginx's header
/// filter writes it: with `absolute_redirect` on, `scheme://host[:port]`
/// before it. The host is the server's name with `server_name_in_redirect`,
/// else the request's host, else the connection's local address; the port
/// the listen's, unless `port_in_redirect` is off or it is the scheme's.
#[derive(Clone, Copy)]
pub(crate) struct RedirectCtx<'a> {
    pub policy: crate::config::RedirectPolicy,
    pub host: Option<&'a [u8]>,
    pub server_name: &'a [u8],
    pub port: u16,
    pub tls: bool,
    pub local_addr: &'a [u8],
}

impl<'a> RedirectCtx<'a> {
    pub(crate) fn new(
        policy: crate::config::RedirectPolicy,
        req: &'a RequestCtx<'_>,
        server: &'a PreparedServer,
    ) -> Self {
        Self {
            policy,
            host: req.host,
            server_name: server.primary_server_name,
            port: server.listen_port,
            tls: req.tls.is_some(),
            local_addr: &req.conn.server_addr,
        }
    }

    pub(crate) fn apply<'l>(&self, location: &'l [u8]) -> std::borrow::Cow<'l, [u8]> {
        if !self.policy.absolute() || location.first() != Some(&b'/') {
            return std::borrow::Cow::Borrowed(location);
        }
        let host = if self.policy.server_name() {
            self.server_name
        } else {
            match self.host {
                Some(h) if !h.is_empty() => h,
                _ => self.local_addr,
            }
        };
        let (scheme, default_port): (&[u8], u16) = if self.tls {
            (b"https://", 443)
        } else {
            (b"http://", 80)
        };
        let mut out = Vec::with_capacity(scheme.len() + host.len() + 6 + location.len());
        out.extend_from_slice(scheme);
        out.extend_from_slice(host);
        if self.policy.port() && self.port != default_port {
            out.push(b':');
            out.extend_from_slice(self.port.to_string().as_bytes());
        }
        out.extend_from_slice(location);
        std::borrow::Cow::Owned(out)
    }
}

fn build_auto_redirect_response(
    server: &PreparedServer,
    server_header: &[u8],
    redirect: crate::config::RedirectPolicy,
    req: &RequestCtx<'_>,
    target: &[u8],
    args: &[u8],
) -> Response {
    let escaped = escape_redirect_uri(target);
    let mut path = Vec::with_capacity(escaped.len() + usize::from(!args.is_empty()) + args.len());
    path.extend_from_slice(&escaped);
    if !args.is_empty() {
        path.push(b'?');
        path.extend_from_slice(args);
    }
    let location = RedirectCtx::new(redirect, req, server)
        .apply(&path)
        .into_owned();
    Response::Owned(crate::http::build_redirect_response(
        301,
        &location,
        req.method,
        server_header,
    ))
}

pub(crate) fn escape_redirect_uri(raw: &[u8]) -> Vec<u8> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = Vec::with_capacity(raw.len());
    for &b in raw {
        if redirect_uri_byte_needs_escape(b) {
            out.push(b'%');
            out.push(HEX[(b >> 4) as usize]);
            out.push(HEX[(b & 0x0f) as usize]);
        } else {
            out.push(b);
        }
    }
    out
}

fn redirect_uri_byte_needs_escape(b: u8) -> bool {
    matches!(
        b,
        0x00..=0x20
            | 0x7f..=0xff
            | b'"'
            | b'#'
            | b'%'
            | b'<'
            | b'>'
            | b'?'
            | b'\\'
            | b'^'
            | b'`'
            | b'{'
            | b'|'
            | b'}'
    )
}

fn auto_redirect_match<'a>(
    locations: &'a [PreparedLocation],
    path: &[u8],
) -> Option<MatchedLocation<'a>> {
    locations
        .iter()
        .find(|loc| {
            loc.auto_redirect
                && loc.pattern.len() == path.len() + 1
                && loc.pattern.starts_with(path)
                && loc.pattern.ends_with(b"/")
        })
        .map(MatchedLocation::from_auto_redirect)
}

fn match_named_location<'a>(
    server: &'a PreparedServer,
    name: &[u8],
) -> Option<MatchedLocation<'a>> {
    server
        .named_locations
        .iter()
        .find(|loc| loc.pattern == name)
        .map(MatchedLocation::from_prefix)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcards_take_only_names_below_them() {
        // ngx_hash_find_wc_head / _tail: `*.example.com` and `www.example.*`
        // need a label more; `.example.com` covers the bare name as an exact
        // one.
        assert!(host_matches_leading_wildcard(
            b"x.example.com",
            b"example.com"
        ));
        assert!(host_matches_leading_wildcard(
            b"a.b.example.com",
            b"example.com"
        ));
        assert!(!host_matches_leading_wildcard(
            b"example.com",
            b"example.com"
        ));
        assert!(!host_matches_leading_wildcard(
            b"xexample.com",
            b"example.com"
        ));
        assert!(host_matches_trailing_wildcard(
            b"www.example.org",
            b"www.example"
        ));
        assert!(!host_matches_trailing_wildcard(
            b"www.example",
            b"www.example"
        ));
        assert!(!host_matches_trailing_wildcard(
            b"www.exampleorg",
            b"www.example"
        ));
    }
    use crate::config;
    use crate::worker::prepare;
    use std::path::Path;
    use std::path::PathBuf;

    fn build(src: &str) -> &'static PreparedHttp {
        prepare(config::parse(src).unwrap()).expect("prepare")
    }

    fn unique_dir() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let d = std::env::temp_dir().join(format!(
            "ruxen-phase-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir(&d).unwrap();
        d
    }

    fn response_bytes(r: Response) -> Vec<u8> {
        match r {
            Response::Prebuilt(b) => b.to_vec(),
            Response::Owned(b) => b,
            Response::File { .. } => {
                panic!("phase::process test helper expected buffered response")
            }
            Response::Reroute(_) => panic!("phase::process must consume Reroute"),
            Response::Proxy(_) | Response::Upgrade(_) | Response::ProxyStream(_) => {
                panic!("phase::process test helper expected buffered response")
            }
        }
    }

    fn method_bytes_for(method: Method) -> &'static [u8] {
        match method {
            Method::Get => b"GET",
            Method::Head => b"HEAD",
            Method::Trace => b"TRACE",
            Method::Connect => b"CONNECT",
            Method::Other => b"GET",
        }
    }

    fn response_body(bytes: &[u8]) -> &[u8] {
        bytes
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map(|i| &bytes[i + 4..])
            .unwrap_or(&[])
    }

    fn ctx_with_method<'a>(
        method: Method,
        path: &'a [u8],
        host: Option<&'a [u8]>,
        http_11: bool,
    ) -> RequestCtx<'a> {
        RequestCtx {
            method,
            method_bytes: method_bytes_for(method),
            path,
            request_line: b"",
            upstream: None,
            http_11,
            host,
            sni: None,
            listen_index: 0,
            remote_addr: b"127.0.0.1",
            remote_port: 12345,
            if_modified_since: None,
            if_unmodified_since: None,
            if_none_match: None,
            if_match: None,
            range: None,
            if_range: None,
            headers_raw: &[],
            connection_id: 0,
            request_id: 0,
            connection_requests: 0,
            connection_time_us: 0,
            request_time_us: 0,
            request_port: &[],
            pipe: b'.',
            request_length: 0,
            epoch_secs: 0,
            epoch_ms: 0,
            body: &NO_BODY,
            body_len: 0,
            body_file: None,
            tls: None,
            conn: &ConnInfo::NONE,
            refuse: None,
        }
    }

    fn ctx<'a>(path: &'a [u8], host: Option<&'a [u8]>, http_11: bool) -> RequestCtx<'a> {
        ctx_with_method(Method::Get, path, host, http_11)
    }

    #[test]
    fn forwarded_addr_walks_the_list_like_nginx() {
        use crate::config::AccessAddr::V4;
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        // 127.0.0.0/8 and 192.0.2.0/24 trusted.
        let from = [
            V4 {
                addr: 0x7f00_0000,
                mask: 0xff00_0000,
            },
            V4 {
                addr: 0xc000_0200,
                mask: 0xffff_ff00,
            },
        ];
        let conn = |peer| ConnInfo {
            peer_ip: peer,
            ..ConnInfo::NONE
        };
        let peer = conn(ip("127.0.0.1"));
        let get = |list: &str, recursive| forwarded_addr(&peer, list.as_bytes(), &from, recursive);
        // Off: the last entry, trusted or not.
        assert_eq!(
            get("10.0.0.1, 192.0.2.7", false),
            Some((ip("192.0.2.7"), 0))
        );
        // On: right to left while trusted.
        assert_eq!(get("10.0.0.1, 192.0.2.7", true), Some((ip("10.0.0.1"), 0)));
        assert_eq!(get("192.0.2.8,192.0.2.7", true), Some((ip("192.0.2.8"), 0)));
        // Separators at the end are skipped; ports and brackets parse.
        assert_eq!(get("10.0.0.1:81 , ", false), Some((ip("10.0.0.1"), 81)));
        assert_eq!(
            get("[2001:db8::1]:99", false),
            Some((ip("2001:db8::1"), 99))
        );
        assert_eq!(get("2001:db8::1", false), Some((ip("2001:db8::1"), 0)));
        // Brackets without a port (nginx 1.27.3+), as ngx_parse_addr
        // reads what is inside: IPv6 or IPv4.
        assert_eq!(
            get("10.0.0.1, [2001:db8::2]", false),
            Some((ip("2001:db8::2"), 0))
        );
        assert_eq!(get("[192.0.2.9]", true), Some((ip("192.0.2.9"), 0)));
        assert_eq!(get("[2001:db8::1]]", false), None);
        assert_eq!(get("[2001:db8::1", false), None);
        assert_eq!(get("[]", false), None);
        assert_eq!(get("[bogus]", false), None);
        // A bad last entry: nothing; a bad entry further left: the last
        // good one.
        assert_eq!(get("10.0.0.1, bogus", true), None);
        assert_eq!(get("bogus, 192.0.2.7", true), Some((ip("192.0.2.7"), 0)));
        assert_eq!(get("10.0.0.1:0", false), None);
        assert_eq!(get("", false), None);
        // An untrusted peer: the header is ignored.
        assert_eq!(
            forwarded_addr(&conn(ip("10.9.9.9")), b"1.2.3.4", &from, false),
            None
        );
        // An IPv4-mapped peer matches the IPv4 entries.
        assert_eq!(
            forwarded_addr(&conn(ip("::ffff:127.0.0.1")), b"1.2.3.4", &from, false),
            Some((ip("1.2.3.4"), 0))
        );
        // A unix-domain peer is trusted only by `unix:`.
        let unix_peer = ConnInfo {
            peer_unix: true,
            ..ConnInfo::NONE
        };
        assert_eq!(forwarded_addr(&unix_peer, b"1.2.3.4", &from, false), None);
        let with_unix = [crate::config::AccessAddr::Unix];
        assert_eq!(
            forwarded_addr(&unix_peer, b"1.2.3.4", &with_unix, false),
            Some((ip("1.2.3.4"), 0))
        );
    }

    #[test]
    fn access_rules_match_in_order_and_by_family() {
        use crate::config::AccessAddr::{All, Unix, V4, V6};
        let rule = |deny, addr| AccessRule { deny, addr };
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let rules = [
            rule(true, Unix),
            rule(
                false,
                V4 {
                    addr: 0x7f00_0000,
                    mask: 0xff00_0000,
                },
            ),
            rule(
                true,
                V6 {
                    addr: 1,
                    mask: u128::MAX,
                },
            ),
            rule(true, V4 { addr: 0, mask: 0 }),
        ];
        // `unix:` never matches a TCP peer; the first matching rule wins.
        assert_eq!(
            match_access_rules(&rules, ip("127.0.0.2"), false),
            Some(false)
        );
        assert_eq!(
            match_access_rules(&rules, ip("10.0.0.1"), false),
            Some(true)
        );
        assert_eq!(match_access_rules(&rules, ip("::1"), false), Some(true));
        // IPv4 rules don't match IPv6 peers…
        assert_eq!(match_access_rules(&rules, ip("::2"), false), None);
        // …but IPv4-mapped peers are matched as IPv4.
        assert_eq!(
            match_access_rules(&rules, ip("::ffff:127.0.0.1"), false),
            Some(false)
        );
        assert_eq!(
            match_access_rules(&[rule(true, All)], ip("::2"), false),
            Some(true)
        );
        assert_eq!(match_access_rules(&[], ip("127.0.0.1"), false), None);
        // A unix-domain client: only `all` and `unix:` rules apply.
        let rules = [rule(false, V4 { addr: 0, mask: 0 }), rule(true, Unix)];
        assert_eq!(
            match_access_rules(&rules, ip("127.0.0.1"), true),
            Some(true)
        );
        assert_eq!(
            match_access_rules(&[rule(false, All)], ip("127.0.0.1"), true),
            Some(false)
        );
    }

    #[test]
    fn auth_basic_user_file_expands_arg_variable() {
        let req = ctx(b"/var/?f=htpasswd", Some(b"localhost"), true);
        let resolved = resolve_auth_basic_user_file(&req, Path::new("$arg_f"), None).unwrap();
        assert_eq!(resolved.as_ref(), Path::new("htpasswd"));
    }

    #[test]
    fn auth_basic_user_file_keeps_percent_encoded_arg_value() {
        // nginx's $arg_f is the query string's bytes, undecoded.
        let req = ctx(b"/var/?f=sub%2Fhtpasswd", Some(b"localhost"), true);
        let resolved = resolve_auth_basic_user_file(&req, Path::new("$arg_f"), None).unwrap();
        assert_eq!(resolved.as_ref(), Path::new("sub%2Fhtpasswd"));
    }

    #[test]
    fn host_selects_server() {
        let http = build(
            r#"
                http {
                    server { listen 80; server_name a.example; location / { return 200 "A"; } }
                    server { listen 80; server_name b.example; location / { return 200 "B"; } }
                }
            "#,
        );
        let ra = response_bytes(process(http, &ctx(b"/", Some(b"a.example"), true)));
        let rb = response_bytes(process(http, &ctx(b"/", Some(b"b.example"), true)));
        assert!(std::str::from_utf8(&ra).unwrap().ends_with("A"));
        assert!(std::str::from_utf8(&rb).unwrap().ends_with("B"));
    }

    #[test]
    fn unknown_host_falls_to_default_server() {
        let http = build(
            r#"
                http {
                    server { listen 80; server_name a.example; location / { return 200 "A"; } }
                    server { listen 80; server_name b.example; location / { return 200 "B"; } }
                }
            "#,
        );
        let r = response_bytes(process(http, &ctx(b"/", Some(b"unknown.host"), true)));
        // Default is the first server block (A).
        assert!(std::str::from_utf8(&r).unwrap().ends_with("A"));
    }

    #[test]
    fn m36_server_match_is_scoped_to_accept_listen() {
        let http = build(
            r#"
                http {
                    server { listen 80; server_name same.example; location / { return 200 "L80"; } }
                    server { listen 81; server_name same.example; location / { return 200 "L81"; } }
                }
            "#,
        );
        let r80 = response_bytes(process(http, &ctx(b"/", Some(b"same.example"), true)));
        assert!(std::str::from_utf8(&r80).unwrap().ends_with("L80"));

        let mut req81 = ctx(b"/", Some(b"same.example"), true);
        req81.listen_index = 1;
        let r81 = response_bytes(process(http, &req81));
        assert!(std::str::from_utf8(&r81).unwrap().ends_with("L81"));
    }

    #[test]
    fn m36_unknown_host_uses_default_server_per_listen() {
        let http = build(
            r#"
                http {
                    server { listen 80; server_name a.example; location / { return 200 "A80"; } }
                    server { listen 80; server_name b.example; location / { return 200 "B80"; } }
                    server { listen 81; server_name c.example; location / { return 200 "C81"; } }
                    server { listen 81; server_name d.example; location / { return 200 "D81"; } }
                }
            "#,
        );
        let r80 = response_bytes(process(http, &ctx(b"/", Some(b"unknown.host"), true)));
        assert!(std::str::from_utf8(&r80).unwrap().ends_with("A80"));

        let mut req81 = ctx(b"/", Some(b"unknown.host"), true);
        req81.listen_index = 1;
        let r81 = response_bytes(process(http, &req81));
        assert!(std::str::from_utf8(&r81).unwrap().ends_with("C81"));
    }

    #[test]
    fn invalid_listen_index_returns_500() {
        let http = build(r#"http { server { listen 80; location / { return 200 "ok"; } } }"#);
        let mut req = ctx(b"/", Some(b"h"), true);
        req.listen_index = 999;
        let r = response_bytes(process(http, &req));
        assert!(
            std::str::from_utf8(&r)
                .unwrap()
                .starts_with("HTTP/1.1 500 Internal Server Error")
        );
    }

    #[test]
    fn missing_host_on_http_11_is_400() {
        let http = build(r#"http { server { listen 80; location / { return 200 "ok"; } } }"#);
        let r = response_bytes(process(http, &ctx(b"/", None, true)));
        assert!(std::str::from_utf8(&r).unwrap().starts_with("HTTP/1.1 400"));
    }

    #[test]
    fn empty_host_on_http_11_is_400() {
        let http = build(r#"http { server { listen 80; location / { return 200 "ok"; } } }"#);
        let r = response_bytes(process(http, &ctx(b"/", Some(b""), true)));
        assert!(std::str::from_utf8(&r).unwrap().starts_with("HTTP/1.1 400"));
    }

    #[test]
    fn missing_host_on_http_10_is_allowed() {
        let http = build(r#"http { server { listen 80; location / { return 200 "ok"; } } }"#);
        let r = response_bytes(process(http, &ctx(b"/", None, false)));
        assert!(std::str::from_utf8(&r).unwrap().starts_with("HTTP/1.1 200"));
    }

    #[test]
    fn head_reroute_loop_500_has_no_body() {
        let root = unique_dir();
        let http = build(&format!(
            "http {{ server {{ listen 80; location / {{ root {}; try_files $uri /missing; }} }} }}",
            root.display()
        ));
        let req = ctx_with_method(Method::Head, b"/loop", Some(b"h"), true);

        let r = response_bytes(process(http, &req));
        assert!(
            std::str::from_utf8(&r)
                .unwrap()
                .starts_with("HTTP/1.1 500 Internal Server Error")
        );
        assert_eq!(response_body(&r), b"");

        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn exact_location_beats_prefix() {
        let http = build(
            r#"
                http {
                    server {
                        listen 80;
                        location = / { return 200 "root"; }
                        location / { return 200 "prefix"; }
                    }
                }
            "#,
        );
        let r = response_bytes(process(http, &ctx(b"/", Some(b"h"), true)));
        assert!(std::str::from_utf8(&r).unwrap().ends_with("root"));
        // A non-exact path falls through to prefix.
        let r = response_bytes(process(http, &ctx(b"/other", Some(b"h"), true)));
        assert!(std::str::from_utf8(&r).unwrap().ends_with("prefix"));
    }

    #[test]
    fn longest_prefix_wins() {
        let http = build(
            r#"
                http {
                    server {
                        listen 80;
                        location /a { return 200 "a"; }
                        location /a/b { return 200 "ab"; }
                        location / { return 200 "root"; }
                    }
                }
            "#,
        );
        let r = response_bytes(process(http, &ctx(b"/a/b/c", Some(b"h"), true)));
        assert!(std::str::from_utf8(&r).unwrap().ends_with("ab"));
        let r = response_bytes(process(http, &ctx(b"/a/xxx", Some(b"h"), true)));
        assert!(std::str::from_utf8(&r).unwrap().ends_with("a"));
        let r = response_bytes(process(http, &ctx(b"/z", Some(b"h"), true)));
        assert!(std::str::from_utf8(&r).unwrap().ends_with("root"));
    }

    #[test]
    fn proxy_slash_location_auto_redirects_bare_uri_before_regex() {
        let http = build(
            r#"
                http {
                    server {
                        listen 80;
                        server_name h;
                        location / { return 200 "root"; }
                        location /a/ { proxy_pass http://127.0.0.1:8080/a-a; }
                        location ~ ^/a$ { return 200 "regex"; }
                    }
                }
            "#,
        );
        let r = response_bytes(process(http, &ctx(b"/a?x=1", Some(b"h"), true)));
        let s = std::str::from_utf8(&r).unwrap();
        assert!(s.starts_with("HTTP/1.1 301 Moved Permanently"), "{s}");
        assert!(s.contains("Location: http://h/a/?x=1\r\n"), "{s}");
    }

    #[test]
    fn non_proxy_slash_location_does_not_auto_redirect() {
        let http = build(
            r#"
                http {
                    server {
                        listen 80;
                        location / { return 200 "root"; }
                        location /a/ { return 200 "slash"; }
                    }
                }
            "#,
        );
        let r = response_bytes(process(http, &ctx(b"/a", Some(b"h"), true)));
        assert!(std::str::from_utf8(&r).unwrap().ends_with("root"));
    }

    #[test]
    fn no_location_match_is_404() {
        let http = build(
            r#"
                http {
                    server {
                        listen 80;
                        location /a { return 200 "a"; }
                    }
                }
            "#,
        );
        let r = response_bytes(process(http, &ctx(b"/b", Some(b"h"), true)));
        assert!(std::str::from_utf8(&r).unwrap().starts_with("HTTP/1.1 404"));
    }

    #[test]
    fn external_requests_do_not_match_named_locations() {
        let http = build(
            r#"
                http {
                    server {
                        listen 80;
                        location @hidden { return 200 "hidden"; }
                    }
                }
            "#,
        );
        let r = response_bytes(process(http, &ctx(b"/@hidden", Some(b"h"), true)));
        assert!(std::str::from_utf8(&r).unwrap().starts_with("HTTP/1.1 404"));
    }

    #[test]
    fn server_name_match_is_case_insensitive() {
        let http = build(
            r#"
                http {
                    server {
                        listen 80;
                        server_name Example.COM;
                        location / { return 200 "ex"; }
                    }
                    server {
                        listen 80;
                        location / { return 200 "default"; }
                    }
                }
            "#,
        );
        // Parser lowercases incoming Host; server_name is lowercased at
        // prepare time. Both mixed-case inputs here simulate what the
        // worker would pass in without relying on the parser.
        let r = response_bytes(process(http, &ctx(b"/", Some(b"example.com"), true)));
        assert!(std::str::from_utf8(&r).unwrap().ends_with("ex"));
    }

    // M9: regex + ^~ location modifiers.
    //
    // Precedence ladder validated end-to-end via `process` so the test
    // exercises the actual `match_location` call path the worker hits.

    #[test]
    fn m9_regex_runs_after_prefix_when_no_caret_tilde() {
        // A normal prefix is recorded as `best`, but the regex pass still
        // runs and wins because `noregex` is false.
        let http = build(
            r#"
                http {
                    server {
                        listen 80;
                        location / { return 200 "prefix"; }
                        location ~ \.gif$ { return 200 "regex"; }
                    }
                }
            "#,
        );
        let r = response_bytes(process(http, &ctx(b"/foo.gif", Some(b"h"), true)));
        assert!(std::str::from_utf8(&r).unwrap().ends_with("regex"));
        // Non-matching path falls back to the prefix.
        let r = response_bytes(process(http, &ctx(b"/foo.txt", Some(b"h"), true)));
        assert!(std::str::from_utf8(&r).unwrap().ends_with("prefix"));
    }

    #[test]
    fn m9_caret_tilde_prefix_suppresses_regex() {
        // `^~ /images/` matches /images/x.gif as the longest prefix and
        // sets noregex, so the regex is not consulted even though it would
        // match too. Without `^~` the regex would win.
        let http = build(
            r#"
                http {
                    server {
                        listen 80;
                        location / { return 200 "root"; }
                        location ^~ /images/ { return 200 "images"; }
                        location ~* \.(gif|jpg)$ { return 200 "regex"; }
                    }
                }
            "#,
        );
        let r = response_bytes(process(http, &ctx(b"/images/foo.gif", Some(b"h"), true)));
        assert!(std::str::from_utf8(&r).unwrap().ends_with("images"));
        // Regex still wins outside the `^~` prefix.
        let r = response_bytes(process(http, &ctx(b"/foo.gif", Some(b"h"), true)));
        assert!(std::str::from_utf8(&r).unwrap().ends_with("regex"));
    }

    #[test]
    fn m9_regex_first_declared_wins() {
        // Two regexes both match /casefull/x.gif; declaration order
        // decides — the first regex (`\.gif$`) wins.
        let http = build(
            r#"
                http {
                    server {
                        listen 80;
                        location / { return 200 "root"; }
                        location ~* \.gif$ { return 200 "first"; }
                        location ~ casefull { return 200 "second"; }
                    }
                }
            "#,
        );
        let r = response_bytes(process(http, &ctx(b"/casefull/x.gif", Some(b"h"), true)));
        assert!(std::str::from_utf8(&r).unwrap().ends_with("first"));
    }

    #[test]
    fn m9_tilde_is_case_sensitive_and_tilde_star_is_not() {
        let http = build(
            r#"
                http {
                    server {
                        listen 80;
                        location / { return 200 "root"; }
                        location ~ casefull { return 200 "cs"; }
                        location ~* \.png$  { return 200 "ci"; }
                    }
                }
            "#,
        );
        // ~ casefull matches lowercase, not uppercase
        let r = response_bytes(process(http, &ctx(b"/casefull/x", Some(b"h"), true)));
        assert!(std::str::from_utf8(&r).unwrap().ends_with("cs"));
        let r = response_bytes(process(http, &ctx(b"/CASEFULL/x", Some(b"h"), true)));
        assert!(std::str::from_utf8(&r).unwrap().ends_with("root"));
        // ~* matches both cases
        let r = response_bytes(process(http, &ctx(b"/foo.PNG", Some(b"h"), true)));
        assert!(std::str::from_utf8(&r).unwrap().ends_with("ci"));
    }

    #[test]
    fn m9_regex_matches_percent_encoded_non_ascii_path() {
        // `/img%FF.gif` decodes to bytes `…0xFF.gif`, which is not valid
        // UTF-8. An earlier implementation routed match_location through
        // `from_utf8(path)` and silently skipped the regex pass on Err,
        // so this request would land on the prefix `/` instead of the
        // regex location. The bytes-mode regex makes it match correctly,
        // mirroring nginx's byte-oriented PCRE behavior.
        let http = build(
            r#"
                http {
                    server {
                        listen 80;
                        location / { return 200 "prefix"; }
                        location ~ \.gif$ { return 200 "regex"; }
                    }
                }
            "#,
        );
        let r = response_bytes(process(http, &ctx(b"/img%FF.gif", Some(b"h"), true)));
        assert!(
            std::str::from_utf8(&r).unwrap().ends_with("regex"),
            "non-UTF-8 path must still hit the regex location: {}",
            String::from_utf8_lossy(&r)
        );
    }

    #[test]
    fn m9_exact_beats_regex() {
        let http = build(
            r#"
                http {
                    server {
                        listen 80;
                        location = /foo { return 200 "exact"; }
                        location ~ /foo { return 200 "regex"; }
                        location / { return 200 "root"; }
                    }
                }
            "#,
        );
        let r = response_bytes(process(http, &ctx(b"/foo", Some(b"h"), true)));
        assert!(std::str::from_utf8(&r).unwrap().ends_with("exact"));
    }
}
