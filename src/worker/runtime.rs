//! Per-worker monoio runtime: `run` builds the runtime + listeners,
//! `spawn_connection` enters the keep-alive request loop, and `handle`
//! drives one request through the phase pipeline.

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

#[allow(clippy::too_many_arguments)]
pub(crate) async fn write_access_logs(
    logs: &'static [PreparedAccessLog],
    request_uri: &[u8],
    request_method: &[u8],
    request_line: &[u8],
    host: Option<&[u8]>,
    remote_addr: &[u8],
    remote_port: u16,
    remote_user: Option<&[u8]>,
    headers_raw: &[u8],
    response: &[u8],
    connection_id: u64,
    connection_requests: u64,
    connection_time_us: u64,
    request_time_us: u64,
    server_port: u16,
    request_port: &[u8],
    pipe: u8,
    request_length: u64,
    bytes_sent: u64,
    body_bytes_sent: u64,
    epoch_secs: u64,
    epoch_ms: u16,
    tls: Option<&crate::tls::HandshakeInfo>,
    proxy_protocol: Option<&crate::proxy_protocol::ProxyHeader>,
    http: &'static PreparedHttp,
    // The request's processing result, for `$proxy_host` and the
    // upstream variables; `None` for a request refused before routing.
    meta: Option<&phase::ProcessMeta>,
    // `$uri`: the URI the request ended up with (after normalisation,
    // rewrites and internal redirects), or `None` to take the path of
    // `request_uri`.
    uri: Option<&[u8]>,
) {
    if logs.is_empty() {
        return;
    }
    // The worker opens its access_log fds once at startup (see
    // `init_access_logs_for_worker`); if that hasn't run we have nothing to
    // write to, so bail quietly.
    let Some(files) = access_log_files(http.access_logs) else {
        return;
    };

    let status = response_status(response);
    let args = request_args(request_uri);
    let uri: &[u8] = uri.unwrap_or_else(|| {
        request_uri
            .iter()
            .position(|&b| b == b'?')
            .map(|i| &request_uri[..i])
            .unwrap_or(request_uri)
    });
    let ctx = RenderCtx {
        uri,
        request_uri,
        request_method,
        request_line,
        host: host.unwrap_or(b""),
        remote_addr,
        remote_port,
        remote_user: remote_user.unwrap_or(b""),
        server_name: b"",
        status,
        args,
        is_args: if args.is_empty() { b"" } else { b"?" },
        scheme: if tls.is_some() { b"https" } else { b"http" },
        hostname: hostname(),
        headers_raw,
        underscores_in_headers: false,
        sent_headers: response,
        connection_id,
        connection_requests,
        connection_time_us,
        request_time_us,
        server_port,
        request_port,
        pipe,
        request_length,
        request_body: &[],
        request_body_file: &[],
        bytes_sent,
        body_bytes_sent,
        epoch_secs,
        epoch_ms,
        // Access-log render runs after the response is on the wire; the
        // server-name regex captures from `find_config` no longer live by
        // this point. `$name` references in `log_format` therefore render
        // empty here, which mirrors nginx (where regex captures are
        // discarded after request termination).
        server_name_captures: &[],
        rewrite_state: meta.and_then(|m| m.rewrite_state.as_deref()),
        split_clients: Some(&http.split_clients),
        maps: Some(&http.maps),
        proxy_host: meta.map_or(&[][..], |m| m.proxy_host),
        upstream_headers: meta.map_or(&[][..], |m| &m.upstream_headers),
        upstream_states: meta.map_or(&[][..], |m| &m.upstream_states),
        sent_trailers: &[],
        tls,
        proxy_protocol,
    };

    for log in logs.iter() {
        if let Some(cond) = log.condition {
            let mut rendered = Vec::with_capacity(32);
            render_parts(cond, &ctx, &mut rendered);
            if !condition_is_truthy(&rendered) {
                continue;
            }
        }

        if let Some(peer) = log.syslog {
            send_syslog_access_line(peer, &files, log, &ctx);
            continue;
        }
        let mut line = Vec::with_capacity(64);
        render_log_parts(log.format, log.escape, &ctx, &mut line);
        if line.is_empty() {
            line.push(b'-');
        }
        line.push(b'\n');

        // `write_at(_, 0)` is safe because the fd was opened with
        // `O_APPEND`: on Linux, pwrite ignores the offset for O_APPEND fds
        // and performs an atomic append under the inode lock (see
        // pwrite(2)). That gives us safe concurrent writes without any
        // per-file mutex.
        // `file_index` is the slot in `PreparedHttp::access_logs` (the
        // canonical list); the per-worker fd table is opened from that
        // same list so this lookup is always in range.
        let Some(AccessLogSink::File(file)) = files.get(log.file_index) else {
            continue;
        };
        let (res, _buf) = file.write_all_at(line, 0).await;
        if let Err(e) = res {
            eprintln!(
                "ruxen: access_log write to {} failed: {e}",
                log.path.display()
            );
        }
    }
}

/// `access_log syslog:…`: one datagram, the syslog header and the line
/// without a newline (nginx's ngx_http_log_handler). Cold: syslog access
/// logs are rare, and the send doesn't block.
#[cold]
#[inline(never)]
fn send_syslog_access_line(
    peer: &PreparedSyslogPeer,
    files: &[AccessLogSink],
    log: &PreparedAccessLog,
    ctx: &RenderCtx<'_>,
) {
    let Some(AccessLogSink::Syslog(sock)) = files.get(log.file_index) else {
        return;
    };
    let mut msg = Vec::with_capacity(128);
    crate::syslog::write_header(&mut msg, peer, peer.severity, crate::syslog::now_secs());
    let start = msg.len();
    render_log_parts(log.format, log.escape, ctx, &mut msg);
    if msg.len() == start {
        msg.push(b'-');
    }
    if let Err(e) = sock.send(&msg) {
        eprintln!(
            "ruxen: access_log send to {} failed: {e}",
            log.path.display()
        );
    }
}

/// `$uri` for the access log: nginx's `r->uri` at the end of the request,
/// which `phase::process` leaves in `url_scratch` (normalised, rewritten,
/// after internal redirects). Empty for a refused URI, as in nginx;
/// `None` (the request's own path) when processing never got that far.
fn final_uri<'a>(meta: &phase::ProcessMeta, url_scratch: &'a [u8]) -> Option<&'a [u8]> {
    if meta.invalid_uri {
        Some(b"")
    } else if url_scratch.is_empty() {
        None
    } else {
        Some(url_scratch)
    }
}

/// `line` without its trailing CRLF (or bare LF).
fn trim_crlf(line: &[u8]) -> &[u8] {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    line.strip_suffix(b"\r").unwrap_or(line)
}

/// What an early rejection needs for its access-log line.
pub(crate) struct ConnLogCtx<'a> {
    pub listen_index: usize,
    pub remote_addr: &'a [u8],
    pub remote_port: u16,
    pub connection_id: u64,
    pub connection_requests: u64,
    pub connection_start: Instant,
    pub tls: Option<&'a crate::tls::HandshakeInfo>,
    pub proxy_protocol: Option<&'a crate::proxy_protocol::ProxyHeader>,
}

/// Send a canned error for a request refused before a server is chosen (a
/// bad request line or header, an unsupported transfer coding, a body
/// over the limit), and log it as nginx does: to the access_log of the
/// address's default server. The connection is closed by the caller.
async fn reject_request<S: ConnIo>(
    stream: &mut S,
    scratch: &mut Vec<u8>,
    http: &'static PreparedHttp,
    response: &[u8],
    request_head: &[u8],
    conn: &ConnLogCtx<'_>,
) {
    scratch.clear();
    scratch.extend_from_slice(response);
    inject_connection_header(scratch, true);
    refresh_date_header(scratch);
    let sent = scratch.len() as u64;
    let taken = std::mem::take(scratch);
    let _ = stream.write_all(taken).await;

    let listen = &http.listens[conn.listen_index];
    let server = &listen.servers[listen.default_server];
    if server.access_logs.is_empty() {
        return;
    }
    // Whatever of the request line arrived (nginx's `$request` then is up
    // to the first CR or LF): method, then URI.
    let line_end = request_head
        .iter()
        .position(|&b| b == b'\r' || b == b'\n')
        .unwrap_or(request_head.len());
    let request_line = &request_head[..line_end];
    let mut words = request_line.split(|&b| b == b' ').filter(|w| !w.is_empty());
    let method = words.next().unwrap_or(b"");
    let uri = words.next().unwrap_or(b"");
    let header_len = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map_or(response.len(), |p| p + 4) as u64;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    write_access_logs(
        server.access_logs,
        uri,
        method,
        request_line,
        None,
        conn.remote_addr,
        conn.remote_port,
        None,
        b"",
        response,
        conn.connection_id,
        conn.connection_requests,
        conn.connection_start.elapsed().as_micros() as u64,
        0,
        server.listen_port,
        b"",
        b'.',
        request_head.len() as u64,
        sent,
        (response.len() as u64).saturating_sub(header_len),
        now.as_secs(),
        now.subsec_millis() as u16,
        conn.tls,
        conn.proxy_protocol,
        http,
        None,
        None,
    )
    .await;
}

/// A response under `limit_rate`: the head, then the file body if any,
/// paced as nginx's write filter does. `false` if the connection failed.
#[allow(clippy::too_many_arguments)]
async fn write_response_paced<S: monoio::io::AsyncWriteRent>(
    stream: &mut S,
    scratch: &mut Vec<u8>,
    file_body: Option<phase::FileBody>,
    rate: u64,
    after: u64,
    request_start: Instant,
    mut timer: std::pin::Pin<&mut monoio::time::Sleep>,
    send_timeout: Duration,
) -> bool {
    let Some(mut pacer) = Pacer::new(rate, after, request_start) else {
        return false;
    };
    let taken = std::mem::take(scratch);
    let len = taken.len();
    let (res, returned) =
        write_all_paced(stream, taken, len, &mut pacer, timer.as_mut(), send_timeout).await;
    *scratch = returned;
    if res.is_err() {
        return false;
    }
    match file_body {
        Some(body) => stream_file(stream, body, timer, send_timeout, Some(&mut pacer)).await,
        None => true,
    }
}

async fn settle_proxy_response(
    http: &'static PreparedHttp,
    ctx: &phase::RequestCtx<'_>,
    url_scratch: &mut Vec<u8>,
    response: Response,
    process_meta: phase::ProcessMeta,
) -> (Response, phase::ProcessMeta) {
    let Response::Proxy(plan) = response else {
        return (response, process_meta);
    };

    // The first pass is inline (an `async fn` layer here costs on the
    // proxy hot path); later passes, after an internal redirect, are in
    // `settle_redirected`.
    let redirects = plan.response.redirects;
    let server_bytes = plan.server_bytes;
    let recursive_error_pages = plan.response.recursive_error_pages;
    let error_pages: &'static [PreparedErrorPage] = if plan.in_error_page {
        &[]
    } else {
        plan.response.error_pages
    };
    let mut report = crate::proxy::ProxyReport::default();
    let upstream_resp = crate::proxy::run_proxy(plan, &mut report).await;
    if !report.failures.is_empty() {
        write_upstream_error_log(
            &process_meta.log,
            &ErrorLogRequest::new(ctx, process_meta.server_name),
            &report.failures,
        );
    }
    let upstream_resp = if error_pages.is_empty() {
        upstream_resp
    } else {
        let pass_ctx = phase::RequestCtx {
            upstream_states: &report.states,
            ..*ctx
        };
        intercept_proxy_error(
            upstream_resp,
            error_pages,
            recursive_error_pages,
            http,
            &pass_ctx,
            &process_meta,
            server_bytes,
        )
    };
    let (reroute, as_get) = match upstream_resp {
        // `proxy_intercept_errors` or an `error_page` for the proxy's own
        // 502/504.
        Response::Reroute(reroute) => (reroute, false),
        // nginx's ngx_http_upstream_process_headers: the response is dropped
        // and the request redirected internally, as a GET.
        _ if report.accel.as_ref().is_some_and(|a| a.redirect.is_some()) => (
            accel_redirect(&mut report),
            !matches!(ctx.method, Method::Head),
        ),
        upstream_resp => {
            return finish_proxy_response(
                upstream_resp,
                report,
                redirects,
                http,
                ctx,
                process_meta,
            );
        }
    };
    // Cold. Boxed so its state doesn't grow every connection's future.
    Box::pin(settle_redirected(
        http,
        ctx,
        url_scratch,
        reroute,
        report.states,
        as_get,
        report.accel.as_ref().and_then(|a| a.limit_rate),
    ))
    .await
}

/// The upstream response goes to the client: apply `proxy_redirect` and
/// the location's `add_header` / `add_trailer` / `expires`, with the
/// upstream headers visible to `$upstream_http_*` / `$upstream_cookie_*`.
fn finish_proxy_response(
    upstream_resp: Response,
    mut report: crate::proxy::ProxyReport,
    redirects: &'static [PreparedRedirect],
    http: &'static PreparedHttp,
    ctx: &phase::RequestCtx<'_>,
    mut process_meta: phase::ProcessMeta,
) -> (Response, phase::ProcessMeta) {
    process_meta.upstream_states = std::mem::take(&mut report.states);
    // `X-Accel-Limit-Rate` is the response's `limit_rate`.
    if let Some(rate) = report.accel.as_ref().and_then(|a| a.limit_rate) {
        process_meta.limit_rate =
            phase::ResponseLimit::with_rate(process_meta.limit_rate.take(), rate);
    }
    // nginx rewrites Location / Refresh while processing the upstream
    // header, before the add_header filter sees the response.
    let upstream_resp = if report.redirect_header {
        rewrite_proxy_redirects(
            upstream_resp,
            redirects,
            http,
            ctx,
            &process_meta,
            &report.upstream_headers,
        )
    } else {
        upstream_resp
    };
    let response = apply_proxy_add_headers(
        upstream_resp,
        http,
        ctx,
        &process_meta,
        &report.upstream_headers,
    );
    // The header is filtered; the body is already read (responses are
    // buffered whole), so the upstream request is over.
    crate::proxy::finish_answer(&mut process_meta.upstream_states);
    process_meta.upstream_headers = report.upstream_headers;
    (response, process_meta)
}

enum PassOutcome {
    /// The response to send, with its metadata.
    Done(Response, phase::ProcessMeta),
    /// The request is redirected internally: an error page (intercept or
    /// the proxy's own 502/504) or an upstream X-Accel-Redirect.
    Redirect {
        reroute: phase::Reroute,
        states: Vec<crate::proxy::UpstreamState>,
        as_get: bool,
        /// The upstream's `X-Accel-Limit-Rate`: it outlives the redirect
        /// (nginx's `r->limit_rate_set`).
        limit_rate: Option<u64>,
    },
}

/// One upstream pass: run the plan, then either finish the response
/// (proxy_redirect, add_header) or say where the request is redirected.
/// `as_get`: the request already went through an X-Accel-Redirect.
async fn run_proxy_pass(
    http: &'static PreparedHttp,
    ctx: &phase::RequestCtx<'_>,
    plan: crate::proxy::ProxyPlan,
    process_meta: phase::ProcessMeta,
    as_get: bool,
) -> PassOutcome {
    let redirects = plan.response.redirects;
    let server_bytes = plan.server_bytes;
    let recursive_error_pages = plan.response.recursive_error_pages;
    let error_pages: &'static [PreparedErrorPage] = if plan.in_error_page {
        &[]
    } else {
        plan.response.error_pages
    };
    let mut report = crate::proxy::ProxyReport::default();
    let upstream_resp = crate::proxy::run_proxy(plan, &mut report).await;
    if !report.failures.is_empty() {
        write_upstream_error_log(
            &process_meta.log,
            &ErrorLogRequest::new(&pass_request(ctx, as_get), process_meta.server_name),
            &report.failures,
        );
    }
    let upstream_resp = if error_pages.is_empty() {
        upstream_resp
    } else {
        let pass_ctx = phase::RequestCtx {
            upstream_states: &report.states,
            ..pass_request(ctx, as_get)
        };
        intercept_proxy_error(
            upstream_resp,
            error_pages,
            recursive_error_pages,
            http,
            &pass_ctx,
            &process_meta,
            server_bytes,
        )
    };
    match upstream_resp {
        // `proxy_intercept_errors` or an `error_page` for the proxy's own
        // 502/504.
        Response::Reroute(reroute) => PassOutcome::Redirect {
            reroute,
            states: report.states,
            as_get,
            limit_rate: report.accel.as_ref().and_then(|a| a.limit_rate),
        },
        // nginx's ngx_http_upstream_process_headers: the response is dropped
        // and the request redirected internally, as a GET.
        _ if report.accel.as_ref().is_some_and(|a| a.redirect.is_some()) => PassOutcome::Redirect {
            reroute: accel_redirect(&mut report),
            states: report.states,
            as_get: !matches!(ctx.method, Method::Head),
            limit_rate: report.accel.as_ref().and_then(|a| a.limit_rate),
        },
        upstream_resp => {
            let (response, process_meta) =
                finish_proxy_response(upstream_resp, report, redirects, http, ctx, process_meta);
            PassOutcome::Done(response, process_meta)
        }
    }
}

/// A proxied request redirected internally: process the target, and if it
/// proxies again, run that pass too. The attempts of every pass stay in
/// `$upstream_*`, as nginx keeps them across internal redirects. Bounded
/// like the reroute loop in `phase` (nginx's `uri_changes`).
async fn settle_redirected(
    http: &'static PreparedHttp,
    ctx: &phase::RequestCtx<'_>,
    url_scratch: &mut Vec<u8>,
    mut reroute: phase::Reroute,
    mut states: Vec<crate::proxy::UpstreamState>,
    mut as_get: bool,
    mut accel_limit_rate: Option<u64>,
) -> (Response, phase::ProcessMeta) {
    for _ in 0..phase::MAX_REROUTES {
        let pass_ctx = phase::RequestCtx {
            upstream_states: &states,
            ..pass_request(ctx, as_get)
        };
        let (response, mut process_meta) =
            phase::process_with_meta_from_reroute(http, &pass_ctx, url_scratch, reroute);
        if let Some(rate) = accel_limit_rate {
            process_meta.limit_rate =
                phase::ResponseLimit::with_rate(process_meta.limit_rate.take(), rate);
        }
        let Response::Proxy(plan) = response else {
            process_meta.upstream_states = states;
            return (response, process_meta);
        };
        match run_proxy_pass(http, ctx, plan, process_meta, as_get).await {
            PassOutcome::Done(response, mut meta) => {
                states.append(&mut meta.upstream_states);
                meta.upstream_states = states;
                return (response, meta);
            }
            PassOutcome::Redirect {
                reroute: next,
                states: mut more,
                as_get: next_as_get,
                limit_rate,
            } => {
                states.append(&mut more);
                reroute = next;
                as_get = next_as_get;
                accel_limit_rate = limit_rate.or(accel_limit_rate);
            }
        }
    }
    // nginx: "rewrite or internal redirection cycle" → 500.
    let response = Response::Owned(http::build_response_for_method(
        500,
        "Internal Server Error\n",
        ctx.method,
        phase::default_server_header(http),
    ));
    (response, phase::ProcessMeta::default())
}

/// The request as a later upstream pass sees it: a GET after an
/// X-Accel-Redirect (HEAD stays HEAD).
fn pass_request<'a>(ctx: &phase::RequestCtx<'a>, as_get: bool) -> phase::RequestCtx<'a> {
    if as_get {
        phase::RequestCtx {
            method: Method::Get,
            method_bytes: b"GET",
            ..*ctx
        }
    } else {
        *ctx
    }
}

/// An `X-Accel-Redirect` value as an internal redirect: `@name` jumps to a
/// named location, anything else is a URI with optional `?args`.
/// The upstream's X-Accel-Redirect: its request is over (nginx finalizes
/// it before redirecting), and the request goes to the target.
fn accel_redirect(report: &mut crate::proxy::ProxyReport) -> phase::Reroute {
    crate::proxy::finish_answer(&mut report.states);
    accel_redirect_reroute(
        report
            .accel
            .as_mut()
            .and_then(|a| a.redirect.take())
            .unwrap_or_default(),
    )
}

fn accel_redirect_reroute(target: Vec<u8>) -> phase::Reroute {
    let (target, args) = if target.first() == Some(&b'@') {
        (phase::RerouteTarget::Named(target), None)
    } else {
        match target.iter().position(|&b| b == b'?') {
            Some(i) => (
                phase::RerouteTarget::Uri(target[..i].to_vec()),
                Some(target[i + 1..].to_vec()),
            ),
            None => (phase::RerouteTarget::Uri(target), None),
        }
    };
    phase::Reroute {
        target,
        args,
        error_page_status: None,
        enters_error_page: false,
        preserved_location: None,
        preserved_www_authenticate: Vec::new(),
    }
}

async fn run_post_action(
    http: &'static PreparedHttp,
    base_ctx: &phase::RequestCtx<'_>,
    target: &'static [u8],
    request_start: Instant,
    url_scratch: &mut Vec<u8>,
) {
    if target.is_empty() {
        return;
    }

    // No recursion: nginx gates re-entry with `r->post_action == 1`. Here
    // the equivalent is structural — `run_post_action` is only invoked
    // from the main request handler, never from itself, and the inner
    // `post_meta.post_action` is intentionally discarded below.
    let empty: &[u8] = &[];
    let post_path = if target.first() == Some(&b'/') {
        target
    } else {
        base_ctx.path
    };
    let post_ctx = phase::RequestCtx {
        path: post_path,
        body: empty,
        body_len: 0,
        body_file: empty,
        refuse: None,
        ..*base_ctx
    };

    let initial = if target.first() == Some(&b'/') {
        phase::process_with_meta(http, &post_ctx, url_scratch)
    } else {
        phase::process_with_meta_from_reroute(
            http,
            &post_ctx,
            url_scratch,
            phase::Reroute {
                target: phase::RerouteTarget::Named(target.to_vec()),
                args: None,
                error_page_status: None,
                enters_error_page: false,
                preserved_location: None,
                preserved_www_authenticate: Vec::new(),
            },
        )
    };
    let (response, post_meta) =
        settle_proxy_response(http, &post_ctx, url_scratch, initial.0, initial.1).await;

    let mut owned_response = Vec::new();
    let mut static_response: Option<&'static [u8]> = None;
    match response {
        Response::Prebuilt(bytes) => static_response = Some(bytes),
        Response::Owned(bytes) => owned_response = bytes,
        Response::File { headers, body: _ } => owned_response = headers,
        Response::Reroute(_) | Response::Proxy(_) => return,
    }
    let response_for_logs = static_response.unwrap_or(owned_response.as_slice());
    let log_request_uri = post_path;

    if !post_meta.access_logs.is_empty() {
        write_access_logs(
            post_meta.access_logs,
            log_request_uri,
            base_ctx.method_bytes,
            base_ctx.request_line,
            base_ctx.host,
            base_ctx.remote_addr,
            base_ctx.remote_port,
            post_meta.remote_user.as_deref(),
            base_ctx.headers_raw,
            response_for_logs,
            base_ctx.connection_id,
            base_ctx.connection_requests,
            base_ctx.connection_time_us,
            // Nginx's post_action runs as an internal redirect on the
            // same `r`, so its access log sees `$request_time` measured
            // from the original request start. Match that semantic by
            // measuring from `request_start`, not the post-action's
            // own dispatch start.
            request_start.elapsed().as_micros() as u64,
            post_meta.server_port,
            base_ctx.request_port,
            base_ctx.pipe,
            base_ctx.request_length,
            0,
            0,
            base_ctx.epoch_secs,
            base_ctx.epoch_ms,
            base_ctx.tls,
            base_ctx.proxy_protocol,
            http,
            Some(&post_meta),
            final_uri(&post_meta, url_scratch),
        )
        .await;
    }
}

/// Give this worker thread its own copy of the fd table.
///
/// Threads share one fd table, and every `open(2)` / `close(2)` takes its
/// spinlock (`alloc_fd`, `file_close_fd`). With one open + close per static
/// request and 32 workers, that lock was ~5–8% of CPU on the 304 bench.
/// nginx doesn't pay this: its workers are processes. After
/// `unshare(CLONE_FILES)` each worker has a private table, like an nginx
/// worker.
///
/// Safe because no fd crosses threads after startup: fds opened before the
/// workers spawn (root dirs, stdio) are copied into each private table, and
/// everything else — listeners, the io_uring ring, accepted sockets,
/// per-request files, access-log handles — is opened by the worker that
/// uses it. `RUXEN_UNSHARE_FILES=0` keeps the shared table (for A/B runs).
fn unshare_fd_table() {
    if matches!(std::env::var("RUXEN_UNSHARE_FILES").as_deref(), Ok("0")) {
        return;
    }
    // SAFETY: plain syscall; affects only the calling thread's fd table.
    if unsafe { libc::unshare(libc::CLONE_FILES) } != 0 {
        eprintln!(
            "ruxen: unshare(CLONE_FILES) failed: {}; worker keeps the shared fd table",
            std::io::Error::last_os_error()
        );
    }
}

/// Worker thread body. `ready` gets exactly one message once startup is
/// done — `Ok` when every listener is bound, or the `[emerg]` text of the
/// first failure, after which the worker exits. `main` waits for all of
/// them before writing the pid file.
pub fn run(
    http: &'static PreparedHttp,
    cpu: Option<usize>,
    state: Arc<RuntimeState>,
    ready: std::sync::mpsc::Sender<Result<(), String>>,
) {
    unshare_fd_table();
    if let Some(c) = cpu {
        // Pin before building the runtime so io_uring setup + the submission
        // queue end up on the target CPU's kernel workers too.
        if let Err(e) = monoio::utils::bind_to_cpu_set([c]) {
            eprintln!("ruxen: worker pin to cpu {c} failed: {e}");
        }
    }

    let mut rt = match RuntimeBuilder::<monoio::IoUringDriver>::new()
        .enable_timer()
        .with_entries(4096)
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            let _ = ready.send(Err(format!("io_uring_setup() failed ({})", errno_text(&e))));
            return;
        }
    };

    rt.block_on(async move {
        // Open one fd per configured access_log for this worker. Kept in a
        // thread-local so `write_access_logs` can do io_uring writes without
        // re-opening the file per request.
        if let Err(e) = init_access_logs_for_worker(http.access_logs) {
            let _ = ready.send(Err(e));
            return;
        }

        let mut listeners = Vec::with_capacity(http.listens.len());
        for prepared in &http.listens {
            let bound = listen_socket(http, prepared)
                .and_then(|socket| TcpListener::from_std(socket.into()));
            match bound {
                Ok(listener) => listeners.push(listener),
                Err(e) => {
                    let _ = ready.send(Err(format!(
                        "bind() to {} failed ({})",
                        prepared.addr,
                        errno_text(&e)
                    )));
                    return;
                }
            }
        }
        let _ = ready.send(Ok(()));
        // Drop the sender so `main` sees a closed channel, not a hang, if
        // another worker dies before reporting.
        drop(ready);

        if listeners.len() == 1 {
            // Single-listen fast path: keep the accept loop in this top-level
            // task (the pre-m36 shape) to avoid an extra scheduler hop on
            // every accepted connection.
            let prepared = &http.listens[0];
            let listener = listeners.pop().expect("one listener");
            loop {
                if state.is_shutting_down() {
                    while state.active_connections() != 0 {
                        monoio::time::sleep(Duration::from_millis(10)).await;
                    }
                    return;
                }
                match accept_or_tick(&listener).await {
                    Ok(Some((stream, addr))) => {
                        if !admit_connection(http) {
                            continue;
                        }
                        let _ = stream.set_nodelay(true);
                        state.connection_started();
                        let connection_id = state.next_connection_id();
                        spawn_connection(
                            prepared,
                            stream,
                            addr,
                            0,
                            http,
                            state.clone(),
                            connection_id,
                        );
                    }
                    Ok(None) => {}
                    Err(e) => accept_failed(http, &e).await,
                }
            }
        } else {
            for (listen_index, listener) in listeners.into_iter().enumerate() {
                monoio::spawn(run_listener(listener, listen_index, http, state.clone()));
            }

            loop {
                if state.is_shutting_down() && state.active_connections() == 0 {
                    return;
                }
                monoio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    });
}

pub(crate) async fn run_listener(
    listener: TcpListener,
    listen_index: usize,
    http: &'static PreparedHttp,
    state: Arc<RuntimeState>,
) {
    let prepared = &http.listens[listen_index];
    loop {
        if state.is_shutting_down() {
            return;
        }
        match accept_or_tick(&listener).await {
            Ok(Some((stream, addr))) => {
                if !admit_connection(http) {
                    continue;
                }
                let _ = stream.set_nodelay(true);
                state.connection_started();
                let connection_id = state.next_connection_id();
                spawn_connection(
                    prepared,
                    stream,
                    addr,
                    listen_index,
                    http,
                    state.clone(),
                    connection_id,
                );
            }
            Ok(None) => {}
            Err(e) => accept_failed(http, &e).await,
        }
    }
}

/// Branch on whether this listen address is TLS and spawn the matching
/// trampoline. Plain HTTP costs one `Option::is_some` check on the accept
/// path; the TLS branch clones an `Arc<TlsAcceptor>` (two atomics) before
/// the spawn.
#[inline]
pub(crate) fn spawn_connection(
    prepared: &'static PreparedListen,
    stream: TcpStream,
    peer_addr: SocketAddr,
    listen_index: usize,
    http: &'static PreparedHttp,
    state: Arc<RuntimeState>,
    connection_id: u64,
) {
    // The connection was counted on accept; whatever path it takes from
    // here, dropping the guard un-counts it.
    let guard = ConnectionGuard(state.clone());
    if prepared.proxy_protocol {
        // Cold: `listen … proxy_protocol`.
        monoio::spawn(handle_proxy_protocol(
            prepared,
            stream,
            peer_addr,
            listen_index,
            http,
            state,
            connection_id,
            guard,
        ));
        return;
    }
    match &prepared.tls {
        None => {
            monoio::spawn(handle_plain(
                stream,
                peer_addr,
                listen_index,
                http,
                state,
                connection_id,
                None,
                guard,
            ));
        }
        Some(acceptor) => {
            let acceptor = acceptor.clone();
            monoio::spawn(handle_tls(
                stream,
                acceptor,
                peer_addr,
                listen_index,
                http,
                state,
                connection_id,
                None,
                Instant::now(),
                guard,
            ));
        }
    }
}

/// `listen … proxy_protocol`: read the PROXY header (within the default
/// server's `client_header_timeout`), then serve the connection as usual.
/// A connection without a valid header is closed with an error-log line,
/// as nginx does ("broken header: …").
async fn handle_proxy_protocol(
    prepared: &'static PreparedListen,
    stream: TcpStream,
    peer_addr: SocketAddr,
    listen_index: usize,
    http: &'static PreparedHttp,
    state: Arc<RuntimeState>,
    connection_id: u64,
    guard: ConnectionGuard,
) {
    let accepted_at = Instant::now();
    let server = &prepared.servers[prepared.default_server];
    let header = match crate::proxy_protocol::read(&stream, server.timeouts.header).await {
        Ok(header) => header,
        Err((level, reason)) => {
            // There's no request yet, so nginx's context is the client and
            // the listening address.
            write_worker_log(
                server.error_logs,
                level,
                &format!(
                    "*{connection_id} {reason} while reading PROXY protocol, \
                     client: {}, server: {}",
                    peer_addr.ip(),
                    prepared.addr
                ),
            );
            return;
        }
    };
    match &prepared.tls {
        None => {
            handle_plain(
                stream,
                peer_addr,
                listen_index,
                http,
                state,
                connection_id,
                Some(header),
                guard,
            )
            .await
        }
        Some(acceptor) => {
            handle_tls(
                stream,
                acceptor.clone(),
                peer_addr,
                listen_index,
                http,
                state,
                connection_id,
                Some(header),
                accepted_at,
                guard,
            )
            .await
        }
    }
}

/// The listening socket for `prepared`, with its `listen` options, as
/// nginx's ngx_open_listening_sockets and ngx_configure_listening_sockets:
/// `IPV6_V6ONLY` before bind, the rest before listen. A failed option is an
/// `[alert] … ignored`, as in nginx; a failed bind or listen fails.
pub(crate) fn listen_socket(
    http: &PreparedHttp,
    prepared: &PreparedListen,
) -> std::io::Result<socket2::Socket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let addr = prepared.addr;
    let o = &prepared.socket;
    let domain = if addr.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_nonblocking(true)?;
    socket.set_reuse_port(true)?;
    socket.set_reuse_address(true)?;
    let alert = |what: String, e: std::io::Error| {
        write_worker_log(
            http.error_logs,
            ErrorLogLevel::Alert,
            &format!(
                "setsockopt({what}) {addr} failed ({}), ignored",
                errno_text(&e)
            ),
        );
    };
    if addr.is_ipv6()
        && let Err(e) = socket.set_only_v6(o.ipv6only)
    {
        alert(format!("IPV6_V6ONLY, {}", o.ipv6only as i32), e);
    }
    socket.bind(&addr.into())?;
    if let Some(n) = o.rcvbuf
        && let Err(e) = socket.set_recv_buffer_size(n)
    {
        alert(format!("SO_RCVBUF, {n}"), e);
    }
    if let Some(n) = o.sndbuf
        && let Err(e) = socket.set_send_buffer_size(n)
    {
        alert(format!("SO_SNDBUF, {n}"), e);
    }
    if let Some(keepalive) = o.keepalive {
        let on = !matches!(keepalive, crate::config::SoKeepalive::Off);
        if let Err(e) = socket.set_keepalive(on) {
            alert(format!("SO_KEEPALIVE, {}", on as i32), e);
        }
        if let crate::config::SoKeepalive::On { idle, intvl, cnt } = keepalive {
            for (opt, name, value) in [
                (libc::TCP_KEEPIDLE, "TCP_KEEPIDLE", idle),
                (libc::TCP_KEEPINTVL, "TCP_KEEPINTVL", intvl),
                (libc::TCP_KEEPCNT, "TCP_KEEPCNT", cnt),
            ] {
                if let Some(v) = value
                    && let Err(e) = setsockopt_int(&socket, libc::IPPROTO_TCP, opt, v as i32)
                {
                    alert(format!("{name}, {v}"), e);
                }
            }
        }
    }
    if let Some(n) = o.fastopen
        && let Err(e) = setsockopt_int(&socket, libc::IPPROTO_TCP, libc::TCP_FASTOPEN, n as i32)
    {
        alert(format!("TCP_FASTOPEN, {n}"), e);
    }
    socket.listen(o.backlog)?;
    // nginx: a 1 s defer, since how long a connection queued can't be known.
    if o.deferred
        && let Err(e) = setsockopt_int(&socket, libc::IPPROTO_TCP, libc::TCP_DEFER_ACCEPT, 1)
    {
        alert("TCP_DEFER_ACCEPT, 1".to_string(), e);
    }
    Ok(socket)
}

fn setsockopt_int(
    socket: &socket2::Socket,
    level: libc::c_int,
    name: libc::c_int,
    value: libc::c_int,
) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    // SAFETY: an int option on a socket we own.
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            name,
            (&value as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Out of file descriptors, `accept` fails at once while the connection
/// stays queued, so retrying immediately spins a core until fds free up.
/// nginx logs it and stops accepting for `accept_mutex_delay` (500 ms,
/// `ngx_event_accept.c`); do the same. Other errors (a client that reset
/// before we accepted) are per-connection: just carry on.
pub(crate) async fn accept_failed(http: &PreparedHttp, err: &std::io::Error) {
    if matches!(
        err.raw_os_error(),
        Some(libc::EMFILE | libc::ENFILE | libc::ENOBUFS | libc::ENOMEM)
    ) {
        write_worker_log(
            http.error_logs,
            ErrorLogLevel::Crit,
            &format!("accept() failed ({})", errno_text(err)),
        );
        monoio::time::sleep(Duration::from_millis(500)).await;
    }
}

pub(crate) async fn accept_or_tick(
    listener: &TcpListener,
) -> std::io::Result<Option<(TcpStream, SocketAddr)>> {
    use std::pin::pin;

    let canceler = monoio::io::Canceller::new();
    let mut accept = pin!(listener.cancelable_accept(canceler.handle()));
    let mut tick = pin!(monoio::time::sleep(Duration::from_millis(50)));
    monoio::select! {
        res = &mut accept => res.map(Some),
        _ = &mut tick => {
            // If the accept SQE completed in the same poll batch as the
            // timer, dropping it here closes the accepted fd and the client
            // sees EOF. Cancel the op, then keep whatever the kernel already
            // handed back: a real success (race with cancel) hands us the
            // connection; a genuine cancel returns the canceled-op error.
            canceler.cancel();
            match accept.await {
                Ok(pair) => Ok(Some(pair)),
                Err(_) => Ok(None),
            }
        }
    }
}

pub(crate) async fn wait_readable_or_shutdown(
    stream: &TcpStream,
    state: &RuntimeState,
    idle_timeout: Option<Duration>,
    start_reload_gen: u64,
    timers: &mut ConnTimers<'_>,
) -> bool {
    use std::task::Poll;

    if let Some(timeout) = idle_timeout {
        timers
            .idle
            .as_mut()
            .reset(monoio::time::Instant::now() + timeout);
    }

    let idle = IdleMark::new();
    loop {
        if state.is_shutting_down() || idle.asked_to_close() {
            return false;
        }
        // SIGHUP-driven reload while this connection was idle: bail out so
        // the worker can close it. New connections accepted after the
        // reload start with the bumped generation, so they keep waiting.
        if state.reload_gen() != start_reload_gen {
            return false;
        }

        // Wake every 50 ms to re-check shutdown / reload / room-making; the
        // idle deadline
        // ends the wait. Both are the connection's long-lived timers.
        timers
            .tick
            .as_mut()
            .reset(monoio::time::Instant::now() + Duration::from_millis(50));
        let mut readable = std::pin::pin!(stream.readable(false));
        let woke = std::future::poll_fn(|cx| {
            if let Poll::Ready(res) = readable.as_mut().poll(cx) {
                return Poll::Ready(Some(res.is_ok()));
            }
            if idle_timeout.is_some() && timers.idle.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Some(false));
            }
            if timers.tick.as_mut().poll(cx).is_ready() {
                return Poll::Ready(None);
            }
            Poll::Pending
        })
        .await;
        if let Some(proceed) = woke {
            return proceed;
        }
    }
}

pub(crate) struct ConnectionGuard(Arc<RuntimeState>);

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.0.connection_finished();
        WORKER_CONNS.with(|w| w.active.set(w.active.get().saturating_sub(1)));
    }
}

/// This worker's share of `worker_connections`, and nginx's reuse of idle
/// connections when it runs low (`ngx_drain_connections`). A worker is a
/// thread that owns its connections, so thread-local cells are enough.
struct WorkerConns {
    /// Accepted connections that haven't finished.
    active: Cell<usize>,
    /// Connections waiting for a request — nginx's "reusable" ones.
    idle: Cell<usize>,
    /// How many idle connections are asked to close to make room.
    drain: Cell<usize>,
    /// UNIX second of the last "not enough" line: log once a second.
    logged_at: Cell<u64>,
}

thread_local! {
    static WORKER_CONNS: WorkerConns = const {
        WorkerConns {
            active: Cell::new(0),
            idle: Cell::new(0),
            drain: Cell::new(0),
            logged_at: Cell::new(0),
        }
    };
}

/// Count a newly accepted connection against the worker's slots. When few
/// are left, ask up to 32 idle connections (an eighth of them) to close,
/// as nginx does below a sixteenth free; with none left, `false`: the new
/// connection is closed, as when nginx's ngx_get_connection fails.
pub(crate) fn admit_connection(http: &PreparedHttp) -> bool {
    let slots = http.client_slots();
    WORKER_CONNS.with(|w| {
        let active = w.active.get();
        let idle = w.idle.get();
        let full = active >= slots;
        if slots - active.min(slots) <= slots / 16 && idle > 0 {
            w.drain.set(w.drain.get().max((idle / 8).clamp(1, 32)));
            if !full {
                log_connections_not_enough(w, http, ErrorLogLevel::Warn, ", reusing connections");
            }
        }
        if full {
            log_connections_not_enough(w, http, ErrorLogLevel::Alert, "");
            return false;
        }
        w.active.set(active + 1);
        true
    })
}

fn log_connections_not_enough(
    w: &WorkerConns,
    http: &PreparedHttp,
    level: ErrorLogLevel,
    tail: &str,
) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if w.logged_at.replace(now) != now {
        write_worker_log(
            http.error_logs,
            level,
            &format!(
                "{} worker_connections are not enough{tail}",
                http.worker_connections
            ),
        );
    }
}

/// Marks a connection idle (waiting for a request) while alive, so
/// `admit_connection` can ask it to make room.
struct IdleMark;

impl IdleMark {
    fn new() -> Self {
        WORKER_CONNS.with(|w| w.idle.set(w.idle.get() + 1));
        IdleMark
    }

    /// Whether this idle connection should close to free a slot.
    fn asked_to_close(&self) -> bool {
        WORKER_CONNS.with(|w| {
            let drain = w.drain.get();
            if drain == 0 {
                return false;
            }
            w.drain.set(drain - 1);
            true
        })
    }
}

impl Drop for IdleMark {
    fn drop(&mut self) {
        WORKER_CONNS.with(|w| w.idle.set(w.idle.get().saturating_sub(1)));
    }
}

pub(crate) async fn handle_plain(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    listen_index: usize,
    http: &'static PreparedHttp,
    state: Arc<RuntimeState>,
    connection_id: u64,
    proxy_protocol: Option<crate::proxy_protocol::ProxyHeader>,
    _guard: ConnectionGuard,
) {
    handle(
        &mut stream,
        peer_addr,
        listen_index,
        None,
        None,
        proxy_protocol.as_ref(),
        http,
        state,
        connection_id,
    )
    .await;
}

pub(crate) async fn handle_tls(
    stream: TcpStream,
    acceptor: Arc<crate::tls::TlsAcceptor>,
    peer_addr: SocketAddr,
    listen_index: usize,
    http: &'static PreparedHttp,
    state: Arc<RuntimeState>,
    connection_id: u64,
    proxy_protocol: Option<crate::proxy_protocol::ProxyHeader>,
    accepted_at: Instant,
    _guard: ConnectionGuard,
) {
    // nginx 1.24 has no separate handshake timeout: the handshake runs
    // under the default server's client_header_timeout, armed at accept
    // (ngx_http_init_connection), so a PROXY header read shares it.
    let listen = &http.listens[listen_index];
    let budget = listen.servers[listen.default_server].timeouts.header;
    let (mut tls_stream, info) = match crate::tls::accept_with_timeout(
        &acceptor,
        stream,
        budget.saturating_sub(accepted_at.elapsed()),
    )
    .await
    {
        Ok(p) => p,
        Err(e) => {
            // nginx logs SSL handshake failures at info level. We don't have
            // a structured logging sink yet (m33's error_log only fires from
            // request scope); stderr is an acceptable v0.1 placeholder.
            eprintln!("ruxen: tls handshake from {peer_addr} failed: {e}");
            return;
        }
    };
    // Lowercase SNI once at handshake time so the per-request find_config
    // fallback can do byte-equal comparisons against prepared (already-
    // lowercased) server_name tables. rustls validates the SNI as a DNS
    // name but doesn't case-fold; we do it here once so the request hot
    // path stays a slice compare.
    let sni: Option<Vec<u8>> = info.server_name.as_deref().map(|s| {
        s.as_bytes()
            .iter()
            .map(|b| b.to_ascii_lowercase())
            .collect()
    });
    handle(
        &mut tls_stream,
        peer_addr,
        listen_index,
        sni.as_deref(),
        Some(&info),
        proxy_protocol.as_ref(),
        http,
        state,
        connection_id,
    )
    .await;
    // close_notify before TCP FIN. Best-effort: peer may already have gone
    // away; we don't have anything useful to do with the error.
    let _ = monoio::io::AsyncWriteRent::shutdown(&mut tls_stream).await;
}

pub(crate) async fn handle<S: ConnIo>(
    stream: &mut S,
    peer_addr: SocketAddr,
    listen_index: usize,
    sni: Option<&[u8]>,
    tls: Option<&crate::tls::HandshakeInfo>,
    proxy_protocol: Option<&crate::proxy_protocol::ProxyHeader>,
    http: &'static PreparedHttp,
    state: Arc<RuntimeState>,
    connection_id: u64,
) {
    // Mirrors nginx's keepalive_handler ↔ wait_request_handler dance: no
    // read buffer is held while the connection is idle. On idle-to-active
    // transition we PollAdd for readability (one io_uring SQE, no buffer),
    // then allocate the 8 KiB read buffer when data is actually arriving.
    //
    // Outer loop = idle ↔ active cycle; inner loop = within an active
    // session, read more / parse / write until the session drains back to
    // empty (→ idle) or the request-line overflows the buffer (→ close).
    let mut parse_state = ParseState::default();

    // Per-connection counters surfaced via `$connection*` variables.
    // `connection_id` is assigned once in the accept loop. `request_count` tracks
    // requests on this connection *including* the one being processed —
    // nginx increments `r->connection->requests` at request init, so
    // `$connection_requests` reads 1 on the first request, 2 on the
    // second, etc. Incrementing before rendering matches that contract.
    let connection_start = Instant::now();
    let remote_addr = peer_addr.ip().to_string().into_bytes();
    let remote_port = peer_addr.port();
    let mut request_count: u64 = 0;
    // Client timeouts come from the address's default server for the whole
    // connection: the header is read before a virtual server is chosen (as
    // in nginx), and the body here too. nginx switches client_body_timeout
    // and send_timeout to the chosen server / location afterwards.
    let timeouts = {
        let listen = &http.listens[listen_index];
        listen.servers[listen.default_server].timeouts
    };
    // A new connection gets client_header_timeout to send its first request
    // (nginx's post-accept timeout); later waits use keepalive_timeout.
    let mut keepalive_idle_timeout: Option<Duration> = Some(timeouts.header);
    // When the current request's header must be complete; set on the first
    // read for it, cleared once the request is handled.
    let mut header_deadline: Option<monoio::time::Instant>;
    // Long-lived timers for this connection (see `ConnTimers`).
    let far = Duration::from_secs(3600);
    let mut timers = ConnTimers {
        io: std::pin::pin!(monoio::time::sleep(far)),
        idle: std::pin::pin!(monoio::time::sleep(far)),
        tick: std::pin::pin!(monoio::time::sleep(far)),
    };
    // Snapshot the reload generation at accept time. SIGHUP bumps the
    // counter; idle keepalive waits and post-request keepalive checks both
    // bail when the live value drifts above this snapshot, which makes
    // existing connections close on reload while new ones (accepted after
    // the bump) keep their fresh snapshot and stay open.
    let start_reload_gen = state.reload_gen();

    // Per-connection scratch buffers — allocated once and reused across
    // every request on this connection. `mem::take` during `write_all`
    // briefly leaves these empty, monoio returns the Vec after the I/O
    // completes, and we restore it. `buf` lives outside `'idle: loop`
    // because non-pipelining clients (wrk, curl) drain `buf` after each
    // response and `continue 'idle`, so a per-iteration alloc here was
    // showing up as ~3% memset / ~1% calloc in the proxy bench profile.
    let mut scratch_owned: Vec<u8> = Vec::with_capacity(READ_BUF);
    let mut url_scratch_owned: Vec<u8> = Vec::with_capacity(256);
    // Set once the zero-copy `sendfile` path has put the socket in
    // O_NONBLOCK mode; see `send_head_and_file`.
    let mut sock_nonblocking = false;
    let mut buf_owned: Vec<u8> = vec![0u8; READ_BUF];
    let scratch = &mut scratch_owned;
    let url_scratch = &mut url_scratch_owned;
    let buf = &mut buf_owned;

    // Context for `reject_request`'s access-log line.
    macro_rules! conn_log {
        () => {
            &ConnLogCtx {
                listen_index,
                remote_addr: &remote_addr,
                remote_port,
                connection_id,
                connection_requests: request_count,
                connection_start,
                tls,
                proxy_protocol,
            }
        };
    }

    'idle: loop {
        if !stream
            .idle_wait(
                &state,
                keepalive_idle_timeout,
                start_reload_gen,
                &mut timers,
            )
            .await
        {
            return;
        }
        keepalive_idle_timeout = None;
        header_deadline = None;

        let mut read_start: usize = 0; // first unread byte of the current request
        let mut filled: usize = 0; // one past the last received byte

        loop {
            let taken = std::mem::take(&mut *buf);
            let slice = taken.slice_mut(filled..READ_BUF);
            let deadline = *header_deadline
                .get_or_insert_with(|| monoio::time::Instant::now() + timeouts.header);
            let read = with_deadline(timers.io.as_mut(), deadline, stream.read(slice));
            // client_header_timeout: nginx closes without a response.
            let Some((res, returned)) = read.await else {
                return;
            };
            *buf = returned.into_inner();
            match res {
                Ok(0) => return,
                Ok(n) => filled += n,
                Err(_) => return,
            }

            loop {
                let view = &buf[read_start..filled];
                match http::parse_request(view, &mut parse_state) {
                    Parse::Complete(req) => {
                        let request_start = Instant::now();
                        // Counted up front so a request refused below logs
                        // `$connection_requests` as nginx does.
                        request_count = request_count.saturating_add(1);
                        // All offsets in `req` are relative to `view`; shift
                        // to absolute buffer offsets before indexing.
                        let base = read_start;
                        // Copy the method into a small stack buffer up
                        // front. The read buffer below is borrowed mutably
                        // by `normalize_host_in_place`, which would
                        // otherwise overlap with a long-lived method-bytes
                        // slice into `buf`. Methods are short ASCII tokens
                        // (longest standardized: `OPTIONS` / `CONNECT` =
                        // 7 bytes); 16 covers any future additions before
                        // we'd need to revisit. Requests with a longer
                        // method tag get clipped — they'll classify as
                        // `Method::Other` either way and the proxy path
                        // would forward a truncated method, which we'd
                        // rather reject. Bound it.
                        let method_len = req.method_end - req.method_start;
                        if method_len > 16 {
                            reject_request(
                                stream,
                                &mut *scratch,
                                http,
                                http.bad_request.pick(Method::Other),
                                &buf[read_start..filled],
                                conn_log!(),
                            )
                            .await;
                            return;
                        }
                        let mut method_buf: [u8; 16] = [0; 16];
                        method_buf[..method_len]
                            .copy_from_slice(&buf[base + req.method_start..base + req.method_end]);
                        let method_bytes: &[u8] = &method_buf[..method_len];
                        let method = http::classify_method(method_bytes);
                        let method_is_post = method_bytes.eq_ignore_ascii_case(b"POST");
                        // Refused below at the server level, where its
                        // `error_page` applies (`phase::process`). The body
                        // is not read and the connection closes.
                        let mut refuse: Option<u16> = None;
                        if let Some(te) = lookup_request_header(
                            &buf[base + req.headers_start..base + req.headers_end],
                            b"transfer-encoding",
                        ) {
                            // nginx request-body gate:
                            // - Transfer-Encoding is HTTP/1.1-only.
                            // - Transfer-Encoding + Content-Length is rejected.
                            refuse = if !req.http_11 || req.content_length.is_some() {
                                Some(400)
                            } else {
                                match classify_request_transfer_encoding(te) {
                                    RequestTransferEncoding::ChunkedOnly => None,
                                    RequestTransferEncoding::Unsupported => Some(501),
                                    RequestTransferEncoding::Invalid => Some(400),
                                }
                            };
                        }
                        let mut bad_host = false;
                        let request_line_host =
                            req.request_line_host.map(|(s, e)| (base + s, base + e));
                        let header_host = req.host.map(|(s, e)| (base + s, base + e));
                        let request_line_host = match request_line_host {
                            Some((s, e)) => match http::normalize_host_in_place(&mut *buf, s, e) {
                                Some(nh) => Some(nh),
                                None => {
                                    // An invalid Host is refused by the
                                    // default server, before the checks
                                    // above (nginx validates it while
                                    // reading the headers).
                                    refuse = Some(400);
                                    bad_host = true;
                                    None
                                }
                            },
                            None => None,
                        };
                        let header_host = match header_host {
                            Some((s, e)) => match http::normalize_host_in_place(&mut *buf, s, e) {
                                Some(nh) => Some(nh),
                                None => {
                                    // An invalid Host is refused by the
                                    // default server, before the checks
                                    // above (nginx validates it while
                                    // reading the headers).
                                    refuse = Some(400);
                                    bad_host = true;
                                    None
                                }
                            },
                            None => None,
                        };
                        // Pick request-line authority over Host header when both
                        // present (mirrors nginx's `r->headers_in.server`
                        // priority for absolute-form requests). Both `host`
                        // and `request_port` come from the same chosen
                        // authority so they stay consistent.
                        let chosen_authority = if bad_host {
                            None
                        } else {
                            request_line_host.as_ref().or(header_host.as_ref())
                        };
                        let host = chosen_authority.map(|nh| &buf[nh.host.0..nh.host.1]);
                        let request_port: &[u8] = chosen_authority
                            .and_then(|nh| nh.port.map(|(s, e)| &buf[s..e]))
                            .unwrap_or(&[]);
                        // Absolute-form `GET http://host?args HTTP/1.1`
                        // has no path byte but a query. We splice `/` in
                        // front of the raw `?args…` so the rest of the
                        // pipeline (URI normalization, `$args`,
                        // `$request_uri`) sees a conventional origin-form.
                        let synthesized_path: Option<Vec<u8>> = req.absolute_query.map(|(s, e)| {
                            let mut v = Vec::with_capacity(1 + (e - s));
                            v.push(b'/');
                            v.extend_from_slice(&buf[base + s..base + e]);
                            v
                        });
                        let path: &[u8] = if let Some(ref p) = synthesized_path {
                            p.as_slice()
                        } else if req.implicit_path {
                            &b"/"[..]
                        } else {
                            &buf[base + req.path_start..base + req.path_end]
                        };
                        let if_modified_since =
                            req.if_modified_since.map(|(s, e)| &buf[base + s..base + e]);
                        let if_unmodified_since = req
                            .if_unmodified_since
                            .map(|(s, e)| &buf[base + s..base + e]);
                        let if_none_match =
                            req.if_none_match.map(|(s, e)| &buf[base + s..base + e]);
                        let if_match = req.if_match.map(|(s, e)| &buf[base + s..base + e]);
                        let range = req.range.map(|(s, e)| &buf[base + s..base + e]);
                        let if_range = req.if_range.map(|(s, e)| &buf[base + s..base + e]);
                        let headers_raw = &buf[base + req.headers_start..base + req.headers_end];
                        let keep_alive = req.keep_alive && refuse.is_none();
                        // `as u64` saturates only at ~584k years of uptime;
                        // the explicit clamp would be unreachable.
                        let connection_time_us = connection_start.elapsed().as_micros() as u64;
                        let request_time_us = request_start.elapsed().as_micros() as u64;
                        // `read_start > 0` ⇒ a previous request on this
                        // connection already consumed bytes from this read
                        // buffer ⇒ pipelined. Matches nginx's `r->pipeline`
                        // semantic.
                        let pipe_byte: u8 = if read_start > 0 { b'p' } else { b'.' };
                        let request_line =
                            trim_crlf(&buf[base + req.method_start..base + req.headers_start]);
                        macro_rules! request_ctx {
                            ($body:expr, $body_len:expr, $body_file:expr, $request_length:expr,
                             $epoch_secs:expr, $epoch_ms:expr) => {
                                phase::RequestCtx {
                                    method,
                                    method_bytes,
                                    path,
                                    request_line,
                                    upstream_states: &[],
                                    http_11: req.http_11,
                                    host,
                                    sni,
                                    listen_index,
                                    remote_addr: &remote_addr,
                                    remote_port,
                                    if_modified_since,
                                    if_unmodified_since,
                                    if_none_match,
                                    if_match,
                                    range,
                                    if_range,
                                    headers_raw,
                                    connection_id,
                                    connection_requests: request_count,
                                    connection_time_us,
                                    request_time_us,
                                    request_port,
                                    pipe: pipe_byte,
                                    request_length: $request_length,
                                    epoch_secs: $epoch_secs,
                                    epoch_ms: $epoch_ms,
                                    body: $body,
                                    body_len: $body_len,
                                    body_file: $body_file,
                                    tls,
                                    proxy_protocol,
                                    refuse,
                                }
                            };
                        }
                        // The read is bounded by the client_max_body_size
                        // of the location the request is routed to first,
                        // and a Content-Length over it is refused unread,
                        // as nginx's find_config phase does. Without a
                        // location (refused, answered by the server's
                        // rewrite phase) the bound is the largest of any
                        // location; the matched location checks its own
                        // limit after the read either way.
                        let mut max_body = http.max_request_body;
                        let has_body = req.content_length.is_some_and(|cl| cl > 0)
                            || req.transfer_encoding_chunked;
                        if refuse.is_none() && has_body {
                            let cl = req.content_length.unwrap_or(0);
                            let probe = request_ctx!(&[], cl, &[], req.consumed as u64 + cl, 0, 0);
                            if let Some(first) =
                                phase::first_body_limit(http, &probe, &mut *url_scratch)
                            {
                                max_body = match first.max {
                                    0 => u64::MAX,
                                    n => n,
                                };
                                if cl > max_body {
                                    write_error_log(
                                        first.error_logs,
                                        ErrorLogLevel::Error,
                                        &ErrorLogRequest::new(&probe, first.server_name),
                                        format!(
                                            "client intended to send too large body: {cl} bytes"
                                        )
                                        .as_bytes(),
                                        None,
                                    );
                                }
                            }
                        }
                        // Expect: 100-continue (nginx ngx_http_test_expect):
                        // when the client sent the exact value "100-continue"
                        // on HTTP/1.1, send the interim `HTTP/1.1 100 Continue`
                        // response before reading the body. nginx fires this
                        // from both read_client_request_body and
                        // discard_request_body, so it applies regardless of
                        // whether the eventual handler consumes the body and
                        // regardless of Content-Length (CL: 0 with the header
                        // still gets a 100). Other Expect tokens (extensions
                        // / unknown) are silently ignored — RFC says 417, but
                        // nginx never implemented that branch and the upstream
                        // test marks it TODO.
                        // Not when the body is refused from its
                        // Content-Length below: nginx sets expect_tested
                        // before discarding it, so no 100 goes out.
                        let refused_unread = req.content_length.is_some_and(|cl| cl > max_body);
                        if req.http_11 && refuse.is_none() && !refused_unread {
                            if let Some(expect) = lookup_request_header(
                                &buf[base + req.headers_start..base + req.headers_end],
                                b"expect",
                            ) {
                                if expect.eq_ignore_ascii_case(b"100-continue") {
                                    let resp: Vec<u8> = b"HTTP/1.1 100 Continue\r\n\r\n".to_vec();
                                    let (res, _) = stream.write_all(resp).await;
                                    if res.is_err() {
                                        return;
                                    }
                                }
                            }
                        }
                        // Request bodies stay in memory up to
                        // REQUEST_BODY_IN_MEMORY and go to a temp file past
                        // that (`BodySink`), within `max_body` above.
                        let mut pipelined_tail: Vec<u8> = Vec::new();
                        let mut sink = BodySink::with_capacity(
                            req.content_length.unwrap_or(0),
                            &http.body_temp,
                        );
                        let (body_in_buf, request_body_len): (usize, u64) = if refuse.is_some() {
                            (0, 0)
                        } else if let Some(cl) = req.content_length {
                            if cl > max_body {
                                // nginx answers 413 from the Content-Length
                                // alone, without reading the body.
                                reject_request(
                                    stream,
                                    &mut *scratch,
                                    http,
                                    http.entity_too_large.pick(method),
                                    &buf[read_start..filled],
                                    conn_log!(),
                                )
                                .await;
                                // The client is likely still sending the
                                // body: let it, so it gets the 413 (nginx's
                                // lingering close; not for 400s, as nginx).
                                Box::pin(lingering_close(stream, &mut *scratch)).await;
                                return;
                            }
                            let body_start = base + req.consumed;
                            let already = filled.saturating_sub(body_start);
                            let take = (already as u64).min(cl) as usize;
                            if !sink.extend(&buf[body_start..body_start + take]) {
                                return;
                            }
                            // One read buffer for the whole body; each read
                            // stops at the body's end so a pipelined next
                            // request isn't consumed.
                            let mut chunk: Vec<u8> = Vec::with_capacity(64 * 1024);
                            while sink.len() < cl {
                                let want = (cl - sink.len()).min(chunk.capacity() as u64) as usize;
                                chunk.clear();
                                let slice = std::mem::take(&mut chunk).slice_mut(0..want);
                                // client_body_timeout between reads.
                                let Some((res, returned)) = with_timeout(
                                    timers.io.as_mut(),
                                    timeouts.body,
                                    stream.read(slice),
                                )
                                .await
                                else {
                                    return;
                                };
                                chunk = returned.into_inner();
                                match res {
                                    Ok(0) | Err(_) => return,
                                    Ok(n) => {
                                        if !sink.extend(&chunk[..n]) {
                                            return;
                                        }
                                    }
                                }
                            }
                            (take, cl)
                        } else if req.transfer_encoding_chunked {
                            let body_start = base + req.consumed;
                            let initial = &buf[body_start..filled];
                            match read_chunked_request_body(
                                stream,
                                initial,
                                max_body,
                                &mut sink,
                                timers.io.as_mut(),
                                timeouts.body,
                            )
                            .await
                            {
                                Ok(decoded) => {
                                    pipelined_tail = decoded.pipelined_tail;
                                    (decoded.consumed_initial, decoded.raw_consumed)
                                }
                                Err(error) => {
                                    let too_large = matches!(error, ChunkedBodyError::TooLarge);
                                    let response = if too_large {
                                        &http.entity_too_large
                                    } else {
                                        &http.bad_request
                                    };
                                    reject_request(
                                        stream,
                                        &mut *scratch,
                                        http,
                                        response.pick(method),
                                        &buf[read_start..filled],
                                        conn_log!(),
                                    )
                                    .await;
                                    if too_large {
                                        Box::pin(lingering_close(stream, &mut *scratch)).await;
                                    }
                                    return;
                                }
                            }
                        } else {
                            (0, 0)
                        };
                        let body_len = sink.len();
                        let (body_vec, spooled) = sink.finish();
                        // Bound to this request iteration; holds the
                        // temp-file path bytes for `$request_body_file`.
                        let request_body_file = match spooled {
                            Some(file) => Some(file),
                            None => maybe_spill_request_body_to_file(&body_vec, &http.body_temp),
                        };
                        let body_file = request_body_file
                            .as_ref()
                            .map(SpilledBody::path_bytes)
                            .unwrap_or(&[]);
                        let request_total_consumed = req.consumed + body_in_buf;
                        let request_length = req.consumed as u64 + request_body_len as u64;
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default();
                        let epoch_secs = now.as_secs();
                        let epoch_ms = (now.subsec_millis() as u16) % 1000;

                        let ctx = request_ctx!(
                            body_vec.as_slice(),
                            body_len,
                            body_file,
                            request_length,
                            epoch_secs,
                            epoch_ms
                        );
                        let (response, mut process_meta) =
                            phase::process_with_meta(http, &ctx, &mut *url_scratch);
                        if let Some(spilled) = request_body_file.as_ref() {
                            if matches!(
                                process_meta.client_body_in_file_only,
                                crate::config::ClientBodyInFileOnly::On
                            ) {
                                spilled.set_keep(true);
                            }
                        }

                        let (response, settled_meta) = settle_proxy_response(
                            http,
                            &ctx,
                            &mut *url_scratch,
                            response,
                            process_meta,
                        )
                        .await;
                        process_meta = settled_meta;

                        // Defer the response write per `auth_delay`. We
                        // sleep on the runtime, not the OS thread, so other
                        // connections on this worker keep progressing.
                        if process_meta.response_delay_ms > 0 {
                            monoio::time::sleep(Duration::from_millis(
                                process_meta.response_delay_ms,
                            ))
                            .await;
                        }

                        // Funnel the response bytes into `scratch`. Owned and
                        // File variants hand us a Vec the handler allocated
                        // this request — prefer whichever of the two buffers
                        // has the larger capacity so scratch converges to the
                        // high-water mark and stops allocating after a few
                        // iterations. Prebuilt responses stay as static slices:
                        // we can synthesize and cache finalized header variants
                        // once per worker and avoid per-request Vec copies.
                        scratch.clear();
                        let mut prebuilt_base: Option<&'static [u8]> = None;
                        let mut file_body: Option<phase::FileBody> = match response {
                            Response::Prebuilt(bytes) => {
                                prebuilt_base = Some(bytes);
                                None
                            }
                            Response::Owned(bytes) => {
                                if bytes.capacity() > scratch.capacity() {
                                    *scratch = bytes;
                                } else {
                                    scratch.extend_from_slice(&bytes);
                                }
                                None
                            }
                            Response::File { headers, body } => {
                                if headers.capacity() > scratch.capacity() {
                                    *scratch = headers;
                                } else {
                                    scratch.extend_from_slice(&headers);
                                }
                                Some(body)
                            }
                            // phase::process consumes Reroute internally
                            // via its hop loop; a Reroute reaching the
                            // worker means the loop terminated without a
                            // terminal outcome, which `process` already
                            // guards against with a 500. Defensive only.
                            Response::Reroute(_) => return,
                            // The Proxy variant is consumed above by
                            // `run_proxy` before this match runs; reaching
                            // here is a logic bug.
                            Response::Proxy(_) => return,
                        };
                        // Single walk over the response header block replaces
                        // what used to be three separate scans. For static
                        // prebuilts, cache the result by pointer so repeat
                        // requests stay allocation-free.
                        let mut scan = match prebuilt_base {
                            Some(bytes) => cached_scan_response_headers(bytes),
                            None => {
                                let mut scan = scan_response_headers(&scratch).unwrap_or_default();
                                stamp_date(&mut *scratch, &mut scan);
                                scan
                            }
                        };
                        let mut close_after = !keep_alive
                            || !process_meta.keepalive.allow
                            || request_count >= process_meta.keepalive.max_requests
                            || connection_time_us / 1_000 > process_meta.keepalive.max_time_ms
                            || matches!(method, Method::Trace | Method::Connect)
                            || state.is_shutting_down()
                            || state.reload_gen() != start_reload_gen
                            || (scan.has_connection && scan.connection_is_close);
                        // Only scan the raw headers for User-Agent when a
                        // policy could actually trigger. disable_safari fires
                        // on any method; disable_msie6 only on POST. Skipping
                        // the scan in the common case (both flags off, or
                        // msie6-only + non-POST) removes a full header-block
                        // walk from the hot path.
                        let ua_scan_needed = process_meta.keepalive.disable_safari
                            || (process_meta.keepalive.disable_msie6 && method_is_post);
                        if ua_scan_needed
                            && should_disable_keepalive_for_user_agent(
                                method_is_post,
                                process_meta.keepalive,
                                lookup_request_header(headers_raw, b"user-agent"),
                            )
                        {
                            close_after = true;
                        }
                        // Capture file body length before `stream_file`
                        // consumes the value — `$bytes_sent` and
                        // `$body_bytes_sent` need it after the write
                        // completes.
                        let streamed_body_len = file_body.as_ref().map(|b| b.len).unwrap_or(0);
                        let response_for_logs: &[u8];
                        if let Some(base) = prebuilt_base {
                            let variant = cached_prebuilt_variant(
                                base,
                                close_after,
                                if close_after {
                                    None
                                } else {
                                    process_meta.keepalive.header_timeout_secs
                                },
                            );
                            // The cached variant is shared and its `Date` is
                            // from when it was built: send a stamped copy.
                            scratch.extend_from_slice(variant.bytes);
                            scan = variant.scan;
                            stamp_date(&mut *scratch, &mut scan);
                            let taken = std::mem::take(&mut *scratch);
                            let len = taken.len();
                            let (res, returned) = write_all_timed(
                                stream,
                                taken,
                                len,
                                timers.io.as_mut(),
                                timeouts.send,
                            )
                            .await;
                            *scratch = returned;
                            if res.is_err() {
                                return;
                            }
                            response_for_logs = &*scratch;
                        } else {
                            if !close_after && !scan.has_keep_alive {
                                if let Some(timeout_secs) =
                                    process_meta.keepalive.header_timeout_secs
                                {
                                    let mut buf: [u8; 48] = [0; 48];
                                    let n = format_keep_alive_header(timeout_secs, &mut buf);
                                    insert_header_at(&mut *scratch, &mut scan.head_end, &buf[..n]);
                                }
                            }
                            if !scan.has_connection {
                                let header: &[u8] = if close_after {
                                    b"Connection: close\r\n"
                                } else {
                                    b"Connection: keep-alive\r\n"
                                };
                                insert_header_at(&mut *scratch, &mut scan.head_end, header);
                            }
                            if let Some(limit) = process_meta.limit_rate.as_deref()
                                && limit.rate > 0
                            {
                                // Cold: `limit_rate`. Boxed so the pacer
                                // doesn't grow every connection's future.
                                let body = file_body.take();
                                if !Box::pin(write_response_paced(
                                    stream,
                                    &mut *scratch,
                                    body,
                                    limit.rate,
                                    limit.after,
                                    request_start,
                                    timers.io.as_mut(),
                                    timeouts.send,
                                ))
                                .await
                                {
                                    return;
                                }
                            } else if process_meta.sendfile
                                && file_body.is_some()
                                && stream.sendfile_fd().is_some()
                            {
                                let body = file_body.take().expect("checked is_some");
                                if !send_head_and_file(
                                    &*stream,
                                    &mut sock_nonblocking,
                                    scratch,
                                    body,
                                    timers.io.as_mut(),
                                    timeouts.send,
                                )
                                .await
                                {
                                    return;
                                }
                            } else {
                                // Hand scratch to monoio for the io_uring
                                // write; it returns the Vec after the write
                                // completes so we reuse the same allocation
                                // next request.
                                let taken = std::mem::take(&mut *scratch);
                                let len = taken.len();
                                let (res, returned) = write_all_timed(
                                    stream,
                                    taken,
                                    len,
                                    timers.io.as_mut(),
                                    timeouts.send,
                                )
                                .await;
                                *scratch = returned;
                                if res.is_err() {
                                    return;
                                }
                            }
                            response_for_logs = &*scratch;
                            if let Some(body) = file_body.take()
                                && !stream_file(
                                    stream,
                                    body,
                                    timers.io.as_mut(),
                                    timeouts.send,
                                    None,
                                )
                                .await
                            {
                                return;
                            }
                        }

                        if !process_meta.access_logs.is_empty() {
                            let request_time_us = request_start.elapsed().as_micros() as u64;
                            // Body bytes = total minus header block. The header
                            // block is everything up to and including the
                            // `\r\n\r\n` separator; `scan.head_end` points at
                            // the terminator's first `\r` and was kept in sync
                            // through the Connection / Keep-Alive injections
                            // above, so we don't need a second `windows(4)`
                            // scan here.
                            let header_size = scan.head_end + 4;
                            let bytes_sent = response_for_logs.len() as u64 + streamed_body_len;
                            let body_bytes_sent = bytes_sent.saturating_sub(header_size as u64);
                            write_access_logs(
                                process_meta.access_logs,
                                path,
                                method_bytes,
                                request_line,
                                host,
                                &remote_addr,
                                remote_port,
                                process_meta.remote_user.as_deref(),
                                headers_raw,
                                response_for_logs,
                                connection_id,
                                request_count,
                                connection_time_us,
                                request_time_us,
                                process_meta.server_port,
                                request_port,
                                pipe_byte,
                                request_length,
                                bytes_sent,
                                body_bytes_sent,
                                epoch_secs,
                                epoch_ms,
                                tls,
                                proxy_protocol,
                                http,
                                Some(&process_meta),
                                final_uri(&process_meta, url_scratch),
                            )
                            .await;
                        }

                        if let Some(target) = process_meta.post_action {
                            run_post_action(http, &ctx, target, request_start, &mut *url_scratch)
                                .await;
                        }

                        read_start += request_total_consumed;
                        parse_state.reset();
                        header_deadline = None;

                        // Chunked decode may have read post-terminator
                        // bytes from the socket — those belong to the next
                        // pipelined request. The chunked path consumes all
                        // of `initial`, so `read_start == filled` here;
                        // compact the buffer and lay the tail down at
                        // offset 0 so the next parse iteration sees it.
                        if !pipelined_tail.is_empty() {
                            if pipelined_tail.len() > buf.len() {
                                // Larger than READ_BUF: can't resume keep-alive.
                                return;
                            }
                            buf[..pipelined_tail.len()].copy_from_slice(&pipelined_tail);
                            read_start = 0;
                            filled = pipelined_tail.len();
                        }

                        if close_after {
                            return;
                        }

                        keepalive_idle_timeout = process_meta
                            .keepalive
                            .idle_timeout_ms
                            .map(Duration::from_millis);
                    }
                    Parse::Incomplete => break,
                    Parse::Invalid => {
                        request_count = request_count.saturating_add(1);
                        // Honor HEAD if the request line parsed before the
                        // header block went sideways; otherwise default to
                        // full — we don't know the method and a body on a
                        // 400 is fine for non-HEAD clients.
                        let method = if parse_state.rline_done {
                            http::classify_method(
                                &buf[read_start + parse_state.method_start
                                    ..read_start + parse_state.method_end],
                            )
                        } else {
                            Method::Other
                        };
                        reject_request(
                            stream,
                            &mut *scratch,
                            http,
                            http.bad_request.pick(method),
                            &buf[read_start..filled],
                            conn_log!(),
                        )
                        .await;
                        return;
                    }
                }
            }

            if read_start == filled {
                // Drained everything — release the buffer and wait idle.
                continue 'idle;
            }

            if filled == READ_BUF {
                // No tail room left. If we have a prefix of consumed bytes,
                // compact the remaining partial request down to offset 0 and
                // keep reading. Otherwise the request itself is larger than
                // the buffer — close.
                if read_start == 0 {
                    return;
                }
                buf.copy_within(read_start..filled, 0);
                filled -= read_start;
                read_start = 0;
            }
        }
    }
}
