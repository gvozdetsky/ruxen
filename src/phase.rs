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
use crate::config::{ValuePart, Variable};
use crate::http::Method;
use crate::uri;
use crate::worker::{
    MatchedLocation, PreparedAuthBasic, PreparedErrorLog, PreparedHttp, PreparedListen,
    PreparedLocation, PreparedServer, RewriteOutcome, RewriteState, normalize_request_uri_into,
    run_location_handler, run_rewrite_program,
};
use std::borrow::Cow;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

/// Maximum internal reroute hops before we declare a loop. nginx uses
/// `NGX_HTTP_MAX_URI_CHANGES` (default 10) for the same purpose; we pick
/// 8 as a slightly tighter budget since our reroute surface is narrower
/// (no rewrite engine, only try_files fallback).
pub(crate) const MAX_REROUTES: u32 = 8;

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
    /// Upstream attempts made so far, for `$upstream_*` in an error page
    /// reached through `proxy_intercept_errors` (nginx keeps them across
    /// the internal redirect). Empty otherwise.
    pub upstream_states: &'a [crate::proxy::UpstreamState],
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
    pub body: &'a [u8],
    /// Length of the request body: `body.len()`, unless the body was too
    /// large to keep in memory and is only in `body_file` (then `body` is
    /// empty, and `$request_body` too, as in nginx).
    pub body_len: u64,
    /// Path to a temp file containing the request body when the worker
    /// spilled it. Empty when no spill file exists.
    pub body_file: &'a [u8],
    /// Negotiated TLS handshake info, taken once at handshake completion.
    /// `None` for plain-HTTP connections. Drives `$scheme` and `$ssl_*`
    /// variable rendering; otherwise untouched on the hot path.
    pub tls: Option<&'a crate::tls::HandshakeInfo>,
    /// The connection's PROXY protocol header, if its listen has
    /// `proxy_protocol`.
    pub proxy_protocol: Option<&'a crate::proxy_protocol::ProxyHeader>,
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

impl Default for KeepaliveMeta {
    fn default() -> Self {
        KeepaliveMeta {
            allow: true,
            idle_timeout_ms: None,
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
    /// Authenticated user from HTTP Basic auth, for `$remote_user`.
    pub remote_user: Option<Vec<u8>>,
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
    /// `$server_name` value for the matched server, for the post-await
    /// proxy add_header render and the `server: …` part of error-log lines.
    pub server_name: &'static [u8],
    /// `$proxy_host` value (upstream URL authority) for the proxy plan.
    pub proxy_host: &'static [u8],
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
    /// `limit_rate` / `limit_rate_after` for this response. Boxed: `None`
    /// (one word) in the common case.
    pub limit_rate: Option<Box<ResponseLimit>>,
    /// Effective `post_action` target for the matched location/server.
    /// The worker runs this after the client response is written and
    /// suppresses its output.
    pub post_action: Option<&'static [u8]>,
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
            remote_user: None,
            proxy_add_headers: &[],
            proxy_add_trailers: &[],
            proxy_chunked_transfer_encoding: true,
            server_name: &[],
            proxy_host: &[],
            response_delay_ms: 0,
            underscores_in_headers: false,
            client_body_in_file_only: crate::config::ClientBodyInFileOnly::Off,
            sendfile: false,
            limit_rate: None,
            post_action: None,
            upstream_states: Vec::new(),
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
        ..ProcessMeta::default()
    }
}

/// Answer a request refused at the server level: the server's
/// `error_page` for the status if it has one (nginx's special response
/// handler runs with the server's configuration here), else `response`.
/// `close` ends the connection afterwards, as nginx does for 400 and 501.
fn refuse(
    http: &'static PreparedHttp,
    req: &RequestCtx<'_>,
    url_scratch: &mut Vec<u8>,
    server: &'static PreparedServer,
    response: Response,
    close: bool,
    in_error_page: bool,
) -> (Response, ProcessMeta) {
    let (response, mut meta) =
        match crate::worker::finish_server_response(http, req, server, response, in_error_page) {
            Response::Reroute(reroute) => {
                process_with_meta_inner(http, req, url_scratch, Some(reroute))
            }
            response => (response, refused_meta(server, false)),
        };
    if close {
        meta.keepalive.allow = false;
    }
    (response, meta)
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
    Proxy(crate::proxy::ProxyPlan),
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

/// A file lookup that failed while processing (`open() "…" failed`) is
/// logged now, with this request's context, as nginx logs it where the
/// open fails. The note is per worker thread, so it has to be taken
/// before anything awaits: another connection would overwrite it.
fn log_failed_lookup(req: &RequestCtx<'_>, meta: &ProcessMeta) {
    if let Some(failed) = crate::fs_resolve::take_failed_lookup() {
        crate::worker::write_lookup_error_log(
            meta.log,
            &crate::worker::ErrorLogRequest::new(req, meta.server_name),
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
            Response::Owned(crate::http::build_response_for_method(
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
        let response = Response::Prebuilt(http.bad_request.pick(req.method));
        return refuse(http, req, url_scratch, server, response, true, false);
    }

    let (server, regex_captures) = find_config(listen, req.host, req.sni);

    if refusing {
        if let Some(status) = req.refuse {
            let canned = if status == 501 {
                &http.not_implemented
            } else {
                &http.bad_request
            };
            let response = Response::Prebuilt(canned.pick(req.method));
            return refuse(http, req, url_scratch, server, response, true, false);
        }
        if matches!(req.method, Method::Trace | Method::Connect) {
            let response = Response::Owned(crate::file::method_not_allowed(
                req.method,
                server.server_header,
            ));
            return refuse(http, req, url_scratch, server, response, false, false);
        }
    }
    let mut named_target: Option<Vec<u8>> = None;
    let mut current_args: Option<Vec<u8>> = None;
    let mut error_page_status: Option<ErrorPageStatus> = None;
    let mut in_error_page = false;
    let mut preserved_location: Option<Vec<u8>> = None;
    let mut preserved_www_authenticate: Vec<Vec<u8>> = Vec::new();
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
                return (resp, refused_meta(server, true));
            }
        }
        Some(reroute) => {
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
    let mut meta = ProcessMeta::default();
    meta.server_port = server.listen_port;
    meta.server_name = server.primary_server_name;

    // Reroute loop — nginx calls this `r->internal` handling inside
    // `ngx_http_internal_redirect`; the counter is `r->uri_changes`. We
    // bound at MAX_REROUTES to guarantee termination on cyclic configs
    // (`try_files / =404` pointing at a URI that re-triggers try_files).
    // nginx runs the server rewrite phase first, and again after an
    // internal redirect, but not after a location's `rewrite … last`.
    let mut run_server_rewrite = true;
    for hop in 0..MAX_REROUTES {
        // nginx's `r->internal`: set by any internal redirect (an entry
        // reroute, or a later hop: rewrite, error_page, try_files, index).
        let internal_request = !refusing || hop > 0;
        let loc = if let Some(name) = named_target.take() {
            match match_named_location(server, &name) {
                Some(loc) => loc,
                None => {
                    return (
                        Response::Owned(crate::http::build_response_for_method(
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
                // add_header and logs.
                return refuse(
                    http,
                    req,
                    url_scratch,
                    server,
                    response,
                    false,
                    in_error_page,
                );
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
                        match run_access_control(
                            http,
                            req,
                            server.auth_basic,
                            server.auth_basic_user_file,
                            server.auth_delay_ms,
                            server.server_header,
                        ) {
                            AccessControl::Allow { remote_user } => {
                                meta.remote_user = remote_user;
                            }
                            AccessControl::Deny { response, delay_ms } => {
                                meta.response_delay_ms = delay_ms;
                                return (response, meta);
                            }
                        }
                        return (Response::Prebuilt(http.not_found.pick(req.method)), meta);
                    }
                },
            }
        };
        meta.keepalive = KeepaliveMeta {
            allow: loc.keepalive.allow,
            idle_timeout_ms: loc.keepalive.idle_timeout_ms,
            header_timeout_secs: loc.keepalive.header_timeout_secs,
            max_requests: loc.keepalive.max_requests,
            max_time_ms: loc.keepalive.max_time_ms,
            disable_msie6: loc.keepalive.disable_msie6,
            disable_safari: loc.keepalive.disable_safari,
        };
        meta.access_logs = loc.access_logs;
        meta.post_action = loc.post_action;
        meta.log = LogMeta {
            error_logs: loc.error_logs,
            log_not_found: loc.log_not_found,
        };
        if loc.internal && !internal_request {
            // ngx_http_core_find_config_phase: an `internal` location is
            // not found for an external request.
            return (Response::Prebuilt(http.not_found.pick(req.method)), meta);
        }
        if let Some(target) = loc.auto_redirect_to {
            let args = current_args
                .as_deref()
                .unwrap_or_else(|| request_args(req.path));
            return (
                build_auto_redirect_response(server, loc.server_header, req, target, args),
                meta,
            );
        }
        let rewrite_broke = match run_rewrite_program(
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
            RewriteOutcome::Respond(response) => return (response, meta),
        };
        // Access-control phase (auth_basic/auth_basic_user_file): runs after
        // rewrite and before content dispatch. A top-level `return` is a
        // rewrite-module directive in nginx, so it answers in the rewrite
        // phase and access control never runs for it — unless a `break`
        // ended the rewrite program first, in which case nginx never reaches
        // the `return` and does run access control.
        meta.remote_user = None;
        let answered_in_rewrite_phase =
            !rewrite_broke && matches!(loc.handler, crate::worker::PreparedHandler::Return(_));
        if !answered_in_rewrite_phase {
            match run_access_control(
                http,
                req,
                loc.auth_basic,
                loc.auth_basic_user_file,
                loc.auth_delay_ms,
                loc.server_header,
            ) {
                AccessControl::Allow { remote_user } => {
                    meta.remote_user = remote_user;
                }
                AccessControl::Deny { response, delay_ms } => {
                    meta.response_delay_ms = delay_ms;
                    return (response, meta);
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
        if let crate::worker::PreparedHandler::Proxy(proxy) = loc.handler {
            meta.proxy_host = proxy.host_header;
        }
        match run_location_handler(
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
        ) {
            Response::Reroute(next) => {
                run_server_rewrite = true;
                if let Some(args) = next.args {
                    current_args = Some(args);
                }
                if let Some(status) = next.error_page_status {
                    error_page_status = Some(status);
                }
                if next.enters_error_page {
                    in_error_page = true;
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
            }
            Response::Proxy(plan) => {
                meta.proxy_add_headers = loc_add_headers;
                meta.proxy_add_trailers = loc_add_trailers;
                meta.proxy_chunked_transfer_encoding = loc_chunked_te;
                meta.proxy_expires = loc_expires;
                meta.underscores_in_headers = server.underscores_in_headers;
                if rewrite_state.has_user_vars() {
                    keep_rewrite_state(&mut meta, rewrite_state);
                }
                return (Response::Proxy(plan), meta);
            }
            other => {
                if rewrite_state.has_user_vars() {
                    keep_rewrite_state(&mut meta, rewrite_state);
                }
                return (other, meta);
            }
        }
    }
    // Budget exhausted: nginx returns 500; we match.
    (
        Response::Owned(crate::http::build_response_for_method(
            500,
            "Internal Server Error\n",
            req.method,
            server.server_header,
        )),
        meta,
    )
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
}

fn run_access_control(
    http: &PreparedHttp,
    req: &RequestCtx<'_>,
    auth_basic: PreparedAuthBasic,
    auth_basic_user_file: Option<&Path>,
    auth_delay_ms: u64,
    server_header: &'static [u8],
) -> AccessControl {
    let PreparedAuthBasic::Realm(realm) = auth_basic else {
        return AccessControl::Allow { remote_user: None };
    };
    let Some(user_file) = auth_basic_user_file else {
        return AccessControl::Deny {
            response: Response::Owned(crate::http::build_response_for_method(
                500,
                "Internal Server Error\n",
                req.method,
                server_header,
            )),
            delay_ms: 0,
        };
    };
    let user_file = match resolve_auth_basic_user_file(req, user_file, http.conf_prefix) {
        Some(path) => path,
        None => {
            return AccessControl::Deny {
                response: Response::Owned(crate::http::build_response_for_method(
                    500,
                    "Internal Server Error\n",
                    req.method,
                    server_header,
                )),
                delay_ms: 0,
            };
        }
    };
    let creds = match auth::decode_basic_authorization(req.headers_raw) {
        Ok(creds) => creds,
        Err(auth::BasicHeaderError::Missing | auth::BasicHeaderError::Malformed) => {
            let response = auth::build_unauthorized_response(req.method, server_header, realm);
            return AccessControl::Deny {
                response: Response::Owned(response),
                delay_ms: auth_delay_ms,
            };
        }
    };
    match auth::verify_credentials(user_file.as_ref(), &creds) {
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
        Err(_) => AccessControl::Deny {
            response: Response::Owned(crate::http::build_response_for_method(
                500,
                "Internal Server Error\n",
                req.method,
                server_header,
            )),
            delay_ms: 0,
        },
    }
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
                write_unescaped_arg_value(out, value);
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
        if key == name {
            return Some(value);
        }
    }
    None
}

fn write_unescaped_arg_value(out: &mut Vec<u8>, raw: &[u8]) {
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == b'%'
            && i + 2 < raw.len()
            && let (Some(hi), Some(lo)) = (hex_nibble(raw[i + 1]), hex_nibble(raw[i + 2]))
        {
            out.push((hi << 4) | lo);
            i += 3;
            continue;
        }
        out.push(raw[i]);
        i += 1;
    }
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// One server-name regex hit, with the named-capture values surfaced for
/// `$name` rendering. Owns the captured bytes so the type carries no
/// borrow lifetime — the captures live as long as the `ProcessMeta` /
/// render path needs them, regardless of when the request `Host` slice
/// is dropped.
pub struct ServerNameCaptures {
    pub names: Vec<(&'static str, Vec<u8>)>,
}

/// `client_max_body_size` of the location a request is routed to first,
/// with what an error-log line about it needs.
pub(crate) struct FirstBodyLimit {
    /// In bytes; `0` turns the check off.
    pub max: u64,
    pub error_logs: &'static [PreparedErrorLog],
    pub server_name: &'static [u8],
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
        error_logs: loc.error_logs,
        server_name: server.primary_server_name,
    })
}

fn select_listen<'h>(http: &'h PreparedHttp, listen_index: usize) -> Option<&'h PreparedListen> {
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

/// Run the exact / leading-wildcard / trailing-wildcard / regex ladder
/// for one candidate hostname. Used both for the HTTP `Host` header pass
/// and the TLS SNI fallback pass — the matching logic is identical, only
/// the input bytes differ. Returns `None` when nothing matches so the
/// caller can chain candidates and only fall back to the default server
/// once all of them have failed.
fn match_server_name<'h, 'r>(
    listen: &'h PreparedListen,
    host_raw: &'r [u8],
) -> Option<(&'h PreparedServer, Option<ServerNameCaptures>)> {
    // Lowercase host once for case-insensitive matching against
    // already-lowercased prepared names. Hot path is the all-lowercase
    // input; falls back to a 256-byte stack buffer, then a heap Vec for
    // the rare oversized hostnames seen in pathological clients.
    let mut host_lc_buf: [u8; 256] = [0; 256];
    let owned_lc: Vec<u8>;
    let host_lc: &[u8] = if host_raw.iter().all(|b| !b.is_ascii_uppercase()) {
        host_raw
    } else if host_raw.len() <= host_lc_buf.len() {
        for (i, &b) in host_raw.iter().enumerate() {
            host_lc_buf[i] = b.to_ascii_lowercase();
        }
        &host_lc_buf[..host_raw.len()]
    } else {
        owned_lc = host_raw.iter().map(|b| b.to_ascii_lowercase()).collect();
        &owned_lc[..]
    };

    // 1. Exact match.
    for server in &listen.servers {
        for name in &server.exact_names {
            if *name == host_lc {
                return Some((server, None));
            }
        }
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
    for server in &listen.servers {
        for rn in &server.regex_names {
            if let Some(caps) = rn.regex.captures(host_raw) {
                let mut names: Vec<(&'static str, Vec<u8>)> = Vec::new();
                for &cn in &rn.capture_names {
                    if let Some(m) = caps.name(cn) {
                        names.push((cn, m.as_bytes().to_vec()));
                    }
                }
                let caps_out = if names.is_empty() {
                    None
                } else {
                    Some(ServerNameCaptures { names })
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
    if host == suffix {
        return true;
    }
    if host.len() <= suffix.len() {
        return false;
    }
    let split = host.len() - suffix.len();
    host[split - 1] == b'.' && &host[split..] == suffix
}

/// Match `host` against a `head.*` wildcard. Matches when the host
/// equals the head or starts with `head.`.
fn host_matches_trailing_wildcard(host: &[u8], head: &[u8]) -> bool {
    if host == head {
        return true;
    }
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
    rewrite_state.clear_numbered_captures();
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

    let best = server
        .prefix_locations
        .iter()
        .find(|loc| path.starts_with(loc.pattern));

    if let Some(loc) = best {
        if loc.noregex {
            return Some(MatchedLocation::from_prefix(loc));
        }
    }

    if !server.regex_locations.is_empty() {
        // Bytes mode: percent-decoding in `uri::normalize` can leave the
        // path as arbitrary octets (e.g. `/img%FF.gif` decodes to `…0xFF…`).
        // Going through `from_utf8` would silently skip the regex pass for
        // any non-UTF-8 sequence — nginx matches PCRE against
        // `r->uri.data` as raw bytes, and so do we.
        for rloc in &server.regex_locations {
            if let Some(captures) = rloc.regex.captures(path) {
                rewrite_state.set_numbered_from_regex_captures(&captures, path);
                return Some(MatchedLocation::from_regex(rloc));
            }
        }
    }

    best.map(MatchedLocation::from_prefix)
}

fn build_auto_redirect_response(
    server: &PreparedServer,
    server_header: &[u8],
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
    let location = build_absolute_redirect_location(
        &path,
        req.host.unwrap_or(server.primary_server_name),
        server.listen_port,
        req.tls.is_some(),
    );
    Response::Owned(crate::http::build_redirect_response(
        301,
        &location,
        req.method,
        server_header,
    ))
}

fn build_absolute_redirect_location(path: &[u8], host: &[u8], port: u16, tls: bool) -> Vec<u8> {
    let scheme: &[u8] = if tls { b"https" } else { b"http" };
    let default_port = if tls { 443 } else { 80 };
    let mut out = Vec::with_capacity(scheme.len() + 3 + host.len() + 6 + path.len());
    out.extend_from_slice(scheme);
    out.extend_from_slice(b"://");
    out.extend_from_slice(host);
    if port != default_port {
        out.push(b':');
        out.extend_from_slice(port.to_string().as_bytes());
    }
    out.extend_from_slice(path);
    out
}

fn escape_redirect_uri(raw: &[u8]) -> Vec<u8> {
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
            Response::Proxy(_) => panic!("phase::process test helper expected buffered response"),
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
            upstream_states: &[],
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
            connection_requests: 0,
            connection_time_us: 0,
            request_time_us: 0,
            request_port: &[],
            pipe: b'.',
            request_length: 0,
            epoch_secs: 0,
            epoch_ms: 0,
            body: &[],
            body_len: 0,
            body_file: &[],
            tls: None,
            proxy_protocol: None,
            refuse: None,
        }
    }

    fn ctx<'a>(path: &'a [u8], host: Option<&'a [u8]>, http_11: bool) -> RequestCtx<'a> {
        ctx_with_method(Method::Get, path, host, http_11)
    }

    #[test]
    fn auth_basic_user_file_expands_arg_variable() {
        let req = ctx(b"/var/?f=htpasswd", Some(b"localhost"), true);
        let resolved = resolve_auth_basic_user_file(&req, Path::new("$arg_f"), None).unwrap();
        assert_eq!(resolved.as_ref(), Path::new("htpasswd"));
    }

    #[test]
    fn auth_basic_user_file_decodes_percent_encoded_arg_value() {
        let req = ctx(b"/var/?f=sub%2Fhtpasswd", Some(b"localhost"), true);
        let resolved = resolve_auth_basic_user_file(&req, Path::new("$arg_f"), None).unwrap();
        assert_eq!(resolved.as_ref(), Path::new("sub/htpasswd"));
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
