//! Per-request location handler: dispatches the matched location's
//! `PreparedHandler`, runs `add_header` / error-page interception, and
//! finalizes the response into the wire form.

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

pub(crate) fn finalize_location_response(
    response: Response,
    add_headers: &'static [PreparedAddHeader],
    add_trailers: &[PreparedAddHeader],
    trailers_allowed: bool,
    render_ctx_base: &RenderCtx<'_>,
    forced_status: Option<phase::ErrorPageStatus>,
    preserved_location: Option<&[u8]>,
    preserved_www_authenticate: &[Vec<u8>],
    expires: PreparedExpires,
) -> Response {
    let add_trailers: &[PreparedAddHeader] = if trailers_allowed { add_trailers } else { &[] };
    // A 3xx forced status with a preserved Location (e.g. `return 302
    // "text"` intercepted by `error_page 302 /...`) re-injects that
    // Location into the new handler's response, replacing any existing
    // Location it set itself. Mirrors nginx, where `r->headers_out.location`
    // survives internal redirect and `ngx_http_send_header` rewrites the
    // status line back to `r->err_status` on the way out.
    let inject_location: Option<&[u8]> = match (forced_status, preserved_location) {
        (Some(phase::ErrorPageStatus::Preserve(s)), Some(loc)) if is_redirect_status(s) => {
            Some(loc)
        }
        _ => None,
    };
    // 401 mirror: when the original was a 401 carrying `WWW-Authenticate:`
    // (e.g. proxied upstream auth challenge intercepted by `error_page 401
    // /login`), preserve every challenge so the client sees the original
    // auth request. nginx's `ngx_http_special_response_handler` always
    // copies `r->headers_out.www_authenticate` for 401 responses.
    let inject_www_authenticate: &[Vec<u8>] = match forced_status {
        Some(phase::ErrorPageStatus::Preserve(401)) => preserved_www_authenticate,
        _ => &[],
    };
    match response {
        Response::Reroute(r) => Response::Reroute(r),
        // Proxy responses bypass `finalize_location_response` — the M40
        // dispatch returns `Response::Proxy(plan)` directly from
        // `run_location_handler` without flowing through here. This arm
        // is defensive: passing the plan through unchanged keeps the
        // type system happy.
        Response::Proxy(plan) => Response::Proxy(plan),
        Response::Prebuilt(bytes) => {
            let base_status = response_status(bytes);
            let status = effective_error_page_status(base_status, forced_status);
            let needs_expires =
                !matches!(expires, PreparedExpires::Off) && is_safe_status_for_expires_pub(status);
            if add_headers.is_empty()
                && add_trailers.is_empty()
                && status == base_status
                && inject_location.is_none()
                && !needs_expires
            {
                return Response::Prebuilt(bytes);
            }
            if add_trailers.is_empty()
                && status == base_status
                && inject_location.is_none()
                && inject_www_authenticate.is_empty()
                && !needs_expires
            {
                if let Some(cached) =
                    prebuilt_with_literal_add_headers(bytes, add_headers, status, render_ctx_base)
                {
                    return Response::Prebuilt(cached);
                }
            }
            let mut out = if status == base_status {
                bytes.to_vec()
            } else {
                rewrite_response_status(bytes.to_vec(), status)
            };
            if let Some(loc_bytes) = inject_location {
                out = replace_location_header(out, loc_bytes);
            }
            if !inject_www_authenticate.is_empty() {
                out = inject_www_authenticate_headers(out, inject_www_authenticate);
            }
            if needs_expires {
                let ctx = RenderCtx {
                    status,
                    ..*render_ctx_base
                };
                out = apply_expires(out, expires, &ctx);
            }
            if !add_headers.is_empty() {
                let ctx = RenderCtx {
                    status,
                    ..*render_ctx_base
                };
                out = inject_add_headers(out, add_headers, &ctx);
            }
            if !add_trailers.is_empty() {
                let ctx = RenderCtx {
                    status,
                    ..*render_ctx_base
                };
                out = inject_add_trailers(out, add_trailers, &ctx);
            }
            Response::Owned(out)
        }
        Response::Owned(bytes) => {
            let base_status = response_status(&bytes);
            let status = effective_error_page_status(base_status, forced_status);
            let mut out = if status == base_status {
                bytes
            } else {
                rewrite_response_status(bytes, status)
            };
            if let Some(loc_bytes) = inject_location {
                out = replace_location_header(out, loc_bytes);
            }
            if !inject_www_authenticate.is_empty() {
                out = inject_www_authenticate_headers(out, inject_www_authenticate);
            }
            if !matches!(expires, PreparedExpires::Off) && is_safe_status_for_expires_pub(status) {
                let ctx = RenderCtx {
                    status,
                    ..*render_ctx_base
                };
                out = apply_expires(out, expires, &ctx);
            }
            if !add_headers.is_empty() {
                let ctx = RenderCtx {
                    status,
                    ..*render_ctx_base
                };
                out = inject_add_headers(out, add_headers, &ctx);
            }
            if !add_trailers.is_empty() {
                let ctx = RenderCtx {
                    status,
                    ..*render_ctx_base
                };
                out = inject_add_trailers(out, add_trailers, &ctx);
            }
            Response::Owned(out)
        }
        Response::File { headers, body } => {
            let base_status = response_status(&headers);
            let status = effective_error_page_status(base_status, forced_status);
            let mut out = if status == base_status {
                headers
            } else {
                rewrite_response_status(headers, status)
            };
            if let Some(loc_bytes) = inject_location {
                out = replace_location_header(out, loc_bytes);
            }
            if !inject_www_authenticate.is_empty() {
                out = inject_www_authenticate_headers(out, inject_www_authenticate);
            }
            if !matches!(expires, PreparedExpires::Off) && is_safe_status_for_expires_pub(status) {
                let ctx = RenderCtx {
                    status,
                    ..*render_ctx_base
                };
                out = apply_expires(out, expires, &ctx);
            }
            if !add_headers.is_empty() {
                let ctx = RenderCtx {
                    status,
                    ..*render_ctx_base
                };
                out = inject_add_headers(out, add_headers, &ctx);
            }
            // `add_trailer` against a streamed file body would require the
            // worker to wrap the body in chunked encoding on the way out;
            // the static-file path doesn't support that today. Quietly skip
            // — the directive is rare on static content anyway.
            Response::File { headers: out, body }
        }
    }
}

/// Walk the raw client header block and append each non-hop-by-hop header
/// that isn't already in `overrides` (matched case-insensitively by name)
/// to `out`. Names already lowercased by the parser, but we still
/// case-fold the override-name compare since `overrides_buf` carries
/// the user-written casing.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum HeaderNamePolicy {
    Valid,
    InvalidButIgnorable,
    InvalidFatal,
}

pub(crate) fn classify_header_name_policy(
    name: &[u8],
    underscores_in_headers: bool,
) -> HeaderNamePolicy {
    if name.is_empty() {
        return HeaderNamePolicy::InvalidFatal;
    }
    let mut invalid = false;
    for &b in name {
        // Space/control bytes and DEL are always invalid in field-name.
        if b <= 0x20 || b == 0x7f || b == b':' {
            return HeaderNamePolicy::InvalidFatal;
        }
        if b.is_ascii_alphanumeric() || b == b'-' {
            continue;
        }
        if b == b'_' {
            if underscores_in_headers {
                continue;
            }
            invalid = true;
            continue;
        }
        invalid = true;
    }
    if invalid {
        HeaderNamePolicy::InvalidButIgnorable
    } else {
        HeaderNamePolicy::Valid
    }
}

pub(crate) fn forward_client_headers<'a>(
    headers_raw: &'a [u8],
    overrides: &[(&[u8], Vec<u8>)],
    out: &mut Vec<crate::proxy::ProxyHeader<'a>>,
    ignore_invalid_headers: bool,
    underscores_in_headers: bool,
) {
    let mut block = headers_raw;
    while !block.is_empty() {
        let line_end = match block.iter().position(|&b| b == b'\n') {
            Some(i) => i,
            None => block.len(),
        };
        let line = &block[..line_end];
        block = &block[(line_end + 1).min(block.len())..];
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        let colon = match line.iter().position(|&b| b == b':') {
            Some(i) => i,
            None => continue,
        };
        let name = &line[..colon];
        match classify_header_name_policy(name, underscores_in_headers) {
            HeaderNamePolicy::InvalidFatal => continue,
            HeaderNamePolicy::InvalidButIgnorable if ignore_invalid_headers => continue,
            HeaderNamePolicy::Valid | HeaderNamePolicy::InvalidButIgnorable => {}
        }
        if crate::proxy::is_hop_by_hop_name(name) {
            continue;
        }
        // Skip headers that we recompute or that an override already
        // emitted (Host, Content-Length, etc.).
        let overridden = overrides.iter().any(|(n, _)| n.eq_ignore_ascii_case(name));
        if overridden {
            continue;
        }
        // Trim OWS on the value side, matching parse_header_line.
        let mut v = &line[colon + 1..];
        while let Some((&c, rest)) = v.split_first() {
            if c == b' ' || c == b'\t' {
                v = rest;
            } else {
                break;
            }
        }
        while let Some((&c, rest)) = v.split_last() {
            if c == b' ' || c == b'\t' {
                v = rest;
            } else {
                break;
            }
        }
        out.push(crate::proxy::ProxyHeader { name, value: v });
    }
}

/// Dispatch a location's matched handler for a given URL path. Called from
/// `phase::process` inside the reroute loop — the URL may differ from
/// `req.path` on subsequent hops after an internal redirect.
///
/// Return semantics: on `Response::Reroute`, `phase::process` re-runs
/// location matching with the new URL. All other variants are terminal.
pub(crate) fn run_location_handler(
    http: &'static PreparedHttp,
    server: &'static PreparedServer,
    loc: MatchedLocation<'static>,
    req: &phase::RequestCtx<'_>,
    url_path: &[u8],
    current_args: Option<&[u8]>,
    remote_user: Option<&[u8]>,
    rewrite_state: &RewriteState,
    error_page_status: Option<phase::ErrorPageStatus>,
    in_error_page: bool,
    preserved_location: Option<&[u8]>,
    preserved_www_authenticate: &[Vec<u8>],
    server_name_captures: Option<&phase::ServerNameCaptures>,
) -> Response {
    // nginx's default client_max_body_size is 1m; `0` turns the check off.
    let body_limit = loc
        .client_max_body_size
        .unwrap_or(DEFAULT_CLIENT_MAX_BODY_SIZE);
    if body_limit > 0 && req.body_len > body_limit {
        let body = "413 Request Entity Too Large\n";
        let response = if matches!(req.method, Method::Head) {
            http::build_head_response(413, body.len(), loc.server_header)
        } else {
            http::build_response(413, body, loc.server_header)
        };
        return Response::Owned(response);
    }

    // Build the per-request variable-render context once; both the `return`
    // body and any `add_header` values share it.
    //
    // nginx's `$host` falls back to the matched server's primary name when
    // the request didn't carry a `Host` header (HTTP/1.0 with no Host, or a
    // raw URI request). Mirroring that here keeps `add_header X-Host $host`
    // working for HTTP/1.0 clients.
    let host = req.host.unwrap_or(server.primary_server_name);
    let request_uri = req.path;
    let args = current_args.unwrap_or_else(|| request_args(request_uri));
    let captures_slice: &[(&'static str, Vec<u8>)] = match server_name_captures {
        Some(caps) => caps.names.as_slice(),
        None => &[],
    };
    let render_ctx_base = RenderCtx {
        uri: url_path,
        request_uri,
        request_method: req.method_bytes,
        request_line: req.request_line,
        host,
        remote_addr: req.remote_addr,
        remote_port: req.remote_port,
        remote_user: remote_user.unwrap_or(b""),
        server_name: server.primary_server_name,
        status: 0, // filled in below once the response status is known
        args,
        is_args: if args.is_empty() { b"" } else { b"?" },
        scheme: if req.tls.is_some() { b"https" } else { b"http" },
        hostname: hostname(),
        headers_raw: req.headers_raw,
        underscores_in_headers: server.underscores_in_headers,
        sent_headers: &[],
        connection_id: req.connection_id,
        connection_requests: req.connection_requests,
        connection_time_us: req.connection_time_us,
        request_time_us: req.request_time_us,
        server_port: server.listen_port,
        request_port: req.request_port,
        pipe: req.pipe,
        request_length: req.request_length,
        request_body: req.body,
        request_body_file: req.body_file.map_or(&[][..], |f| f.path_bytes()),
        // Filled in by access-log render after the response is on the wire;
        // handler-time templates that touch these read 0.
        bytes_sent: 0,
        body_bytes_sent: 0,
        epoch_secs: req.epoch_secs,
        epoch_ms: req.epoch_ms,
        server_name_captures: captures_slice,
        rewrite_state: Some(rewrite_state),
        split_clients: Some(&http.split_clients),
        maps: Some(&http.maps),
        proxy_host: &[],
        upstream_headers: &[],
        upstream_states: req.upstream_states,
        sent_trailers: &[],
        tls: req.tls,
        proxy_protocol: req.proxy_protocol,
    };

    let server_bytes = loc.server_header;
    // The plan carries everything `proxy::run_proxy` needs for async work.
    // The worker awaits it after `process_with_meta`, then applies the
    // location's proxy add_header/add_trailer state with `$upstream_*`
    // variables populated.
    if let PreparedHandler::Proxy(proxy) = loc.handler {
        // Path rewriting: nginx forwards the *post-rewrite* URI (`r->uri`
        // after any internal redirects), not the client's original
        // request line. When `proxy_pass http://up/PATH` had a URI part,
        // strip the matched location prefix from the current URL path
        // and prepend `request_path`. Empty `request_path` means "forward
        // post-rewrite URI verbatim" — also r->uri, plus current args.
        //
        // valid_location reset: when a `rewrite` directive in this
        // location modified the URI in-place, nginx clears
        // `r->valid_location` and proxy_pass forwards `r->uri` verbatim
        // (its own URI prefix is ignored). Treat `request_path` as empty
        // in that case.
        let request_path: &[u8] = if rewrite_state.valid_location {
            proxy.request_path
        } else {
            b""
        };
        let rewritten_uri: Vec<u8>;
        let request_uri: &[u8] = if request_path.is_empty() {
            if args.is_empty() {
                let mut buf = Vec::with_capacity(url_path.len());
                buf.extend_from_slice(url_path);
                rewritten_uri = buf;
            } else {
                let mut buf = Vec::with_capacity(url_path.len() + 1 + args.len());
                buf.extend_from_slice(url_path);
                buf.push(b'?');
                buf.extend_from_slice(args);
                rewritten_uri = buf;
            }
            rewritten_uri.as_slice()
        } else {
            // Strip the location prefix. nginx normalizes both sides
            // before matching, but our match_location did the work
            // already; when url_path doesn't start with the prefix
            // (regex location, etc.) we fall back to "no strip".
            let suffix = url_path
                .strip_prefix(proxy.location_prefix)
                .unwrap_or(url_path);
            let qlen = if args.is_empty() { 0 } else { args.len() + 1 };
            let mut buf = Vec::with_capacity(request_path.len() + suffix.len() + qlen);
            buf.extend_from_slice(request_path);
            buf.extend_from_slice(suffix);
            if !args.is_empty() {
                buf.push(b'?');
                buf.extend_from_slice(args);
            }
            rewritten_uri = buf;
            rewritten_uri.as_slice()
        };
        // Pick the first peer via the per-worker LB. None means every
        // peer is `down` or in a `max_fails` cooldown: `run_proxy` answers
        // 502 and reports `no live upstreams` for the error log.
        let initial_peer = crate::upstream::pick_peer(proxy.upstream, &Default::default());
        // Render proxy_set_header values with $proxy_host populated for
        // this location's upstream URL authority. The other RenderCtx
        // fields are inherited from the base built above.
        let mut proxy_render_ctx = render_ctx_base;
        proxy_render_ctx.proxy_host = proxy.host_header;

        // Build the final header set: proxy_set_header overrides first
        // (nginx wins ties on declaration order) plus a synthesized
        // default Host when the user didn't override it; then forwarded
        // client headers (filtered for hop-by-hop and override conflicts).
        // Names are always `&'static [u8]` (either prepared at parse time or
        // hardcoded byte strings here), so we hold them by reference and
        // only allocate Vec<u8> for values that need rendering.
        let mut overrides_buf: Vec<(&[u8], Vec<u8>)> =
            Vec::with_capacity(proxy.set_headers.len() + 2);
        let mut have_host_override = false;
        let mut have_content_length_override = false;
        let mut have_connection_override = false;
        for sh in proxy.set_headers {
            let mut value = Vec::with_capacity(32);
            render_parts(sh.value, &proxy_render_ctx, &mut value);
            if sh.name.eq_ignore_ascii_case(b"host") {
                have_host_override = true;
            }
            if sh.name.eq_ignore_ascii_case(b"content-length") {
                have_content_length_override = true;
            }
            if sh.name.eq_ignore_ascii_case(b"connection") {
                have_connection_override = true;
            }
            overrides_buf.push((sh.name, value));
        }
        if !have_host_override {
            overrides_buf.insert(0, (b"Host", proxy.host_header.to_vec()));
        }

        // Pool eligibility: HTTP/1.1 + the upstream block opted into
        // `keepalive N;`. Drives both the Connection-header default
        // synthesized below and `run_proxy`'s pool-release decision.
        let pool_eligible = proxy.http_version == 1 && proxy.upstream.keepalive_max_idle.is_some();

        if !have_connection_override {
            // Default Connection on the upstream side: keep-alive when
            // pooling is on, close otherwise. Matches nginx's behavior:
            // without `proxy_set_header Connection ""` the keepalive
            // module silently overrides Connection itself; without the
            // keepalive module the proxy emits Connection: close.
            let value: &[u8] = if pool_eligible {
                b"keep-alive"
            } else {
                b"close"
            };
            overrides_buf.push((b"Connection", value.to_vec()));
        }

        // Decide on the body to forward. `proxy_set_body` replaces it;
        // proxy_pass_request_body off ⇒ never forward; otherwise, pass the
        // worker-buffered body (Content-Length or decoded chunked).
        let set_body: Option<Vec<u8>> = proxy.set_body.map(|parts| {
            let mut body = Vec::new();
            render_parts(parts, &proxy_render_ctx, &mut body);
            body
        });
        let forward_body: &[u8] = match &set_body {
            Some(body) => body,
            None if proxy.pass_request_body => req.body,
            None => &[],
        };
        let forward_len = match &set_body {
            Some(body) => body.len() as u64,
            None if proxy.pass_request_body => req.body_len,
            None => 0,
        };
        // A body too large to keep in memory is only in the temp file;
        // `run_proxy` streams it after the header block.
        let body_file = req
            .body_file
            .filter(|_| forward_len > forward_body.len() as u64)
            .and_then(|spilled| spilled.reader().ok())
            .map(|file| crate::proxy::RequestBodyFile {
                file,
                len: forward_len,
            });
        // Synthesize Content-Length when forwarding a body; nginx always
        // emits CL on the upstream side, recomputed from the actual
        // forwarded byte count regardless of the client header.
        if !have_content_length_override {
            if forward_len > 0 {
                overrides_buf.push((b"Content-Length", forward_len.to_string().into_bytes()));
            } else if matches!(req.method, Method::Get | Method::Head) {
                // Drop Content-Length entirely for GET/HEAD with no body.
            } else {
                // Non-GET/HEAD with no forwarded body — emit CL: 0 so
                // the upstream doesn't wait for a body.
                overrides_buf.push((b"Content-Length", b"0".to_vec()));
            }
        }

        let mut headers: Vec<crate::proxy::ProxyHeader<'_>> =
            Vec::with_capacity(overrides_buf.len() + 8);
        for (name, value) in &overrides_buf {
            headers.push(crate::proxy::ProxyHeader {
                name,
                value: value.as_slice(),
            });
        }
        if proxy.pass_request_headers {
            // Forward client headers that aren't hop-by-hop, aren't
            // explicitly overridden, and aren't Content-Length / Host
            // (recomputed above). Iterate the raw header block; the
            // parser already lowercased names in place so the names
            // here are byte-for-byte the lowercased forms.
            // We can't extend `headers` while iterating because the
            // lifetime ties slice references to headers_raw.
            forward_client_headers(
                req.headers_raw,
                &overrides_buf,
                &mut headers,
                proxy.ignore_invalid_headers,
                proxy.underscores_in_headers,
            );
        }

        let request = crate::proxy::build_request_bytes_with_headers(
            req.method_bytes,
            request_uri,
            proxy.http_version,
            &headers,
            forward_body,
        );
        // Pre-render error_page targets when proxy_intercept_errors is on.
        // Rendering happens here so run_proxy doesn't need a RenderCtx
        // (its borrowed slices wouldn't survive into the worker await
        // anyway). Only build the list when both flags are set —
        // intercept off, or no rules, means no extra work per request.
        let intercept = if proxy.intercept_errors && !loc.error_pages.is_empty() {
            let mut rules = Vec::with_capacity(loc.error_pages.len());
            for ep in loc.error_pages {
                let mut buf = Vec::with_capacity(64);
                render_parts(ep.target, &proxy_render_ctx, &mut buf);
                rules.push(crate::proxy::InterceptRule {
                    status: ep.status,
                    action: ep.action,
                    target: buf,
                });
            }
            Some(rules)
        } else {
            None
        };
        return Response::Proxy(crate::proxy::ProxyPlan {
            upstream: proxy.upstream,
            initial_peer,
            request: bytes::Bytes::from(request),
            method: req.method,
            server_bytes,
            connect_timeout: std::time::Duration::from_millis(proxy.connect_timeout_ms),
            read_timeout: std::time::Duration::from_millis(proxy.read_timeout_ms),
            send_timeout: std::time::Duration::from_millis(proxy.send_timeout_ms),
            limit_rate: proxy.limit_rate,
            bad_gateway: &http.bad_gateway,
            gateway_timeout: &http.gateway_timeout,
            keepalive_eligible: pool_eligible,
            next_upstream: proxy.next_upstream,
            next_upstream_tries: proxy.next_upstream_tries,
            next_upstream_timeout: std::time::Duration::from_millis(proxy.next_upstream_timeout_ms),
            body_file,
            keep_upstream_headers: !loc.add_headers.is_empty()
                || !loc.add_trailers.is_empty()
                || loc.access_logs.iter().any(|l| l.reads_upstream_headers),
            response: proxy.response,
            method_idempotent: !matches!(req.method_bytes, b"POST" | b"LOCK" | b"PATCH"),
            in_error_page,
            intercept,
        });
    }
    let inner = match loc.handler {
        PreparedHandler::Return(PreparedReturn::Static(response)) => {
            Response::Prebuilt(response.pick(req.method))
        }
        PreparedHandler::Return(PreparedReturn::Template { status, parts }) => Response::Owned(
            build_templated_return(*status, parts, &render_ctx_base, req.method, server_bytes),
        ),
        PreparedHandler::Proxy(_) => unreachable!("handled above"),
        // Static-file mapping follows the configured path mode:
        // `root` appends the whole normalized URI, while `alias` strips the
        // matched location prefix first. `PreparedRoot` carries that choice.
        PreparedHandler::Root(root) => {
            if !matches!(req.method, Method::Get | Method::Head) {
                return Response::Owned(file::method_not_allowed(req.method, server_bytes));
            }
            let last_modified_override =
                last_modified_override_for_conditionals(loc.add_headers, &render_ctx_base);
            match fs_resolve::resolve(root, url_path, &render_ctx_base) {
                fs_resolve::Outcome::Serve(opened) => file::serve_path(
                    opened,
                    req.method,
                    file::Conditionals {
                        if_modified_since: req.if_modified_since,
                        if_unmodified_since: req.if_unmodified_since,
                        if_none_match: req.if_none_match,
                        if_match: req.if_match,
                        range: req.range,
                        if_range: req.if_range,
                        last_modified_override: last_modified_override.as_deref(),
                    },
                    server_bytes,
                    loc.sendfile,
                ),
                fs_resolve::Outcome::Redirect(location) => {
                    let abs = build_absolute_redirect_location(
                        &location,
                        req.host.unwrap_or(server.primary_server_name),
                        server.listen_port,
                        req.tls.is_some(),
                    );
                    Response::Owned(http::build_redirect_response(
                        301,
                        &abs,
                        req.method,
                        server_bytes,
                    ))
                }
                fs_resolve::Outcome::Reroute(target) => {
                    return Response::Reroute(phase::Reroute {
                        target,
                        args: None,
                        error_page_status: None,
                        enters_error_page: false,
                        preserved_location: None,
                        preserved_www_authenticate: Vec::new(),
                    });
                }
                fs_resolve::Outcome::NotFound => {
                    Response::Prebuilt(http.not_found.pick(req.method))
                }
                fs_resolve::Outcome::Forbidden => {
                    Response::Prebuilt(http.forbidden.pick(req.method))
                }
                fs_resolve::Outcome::StatusPrebuilt(prebuilt) => {
                    Response::Prebuilt(prebuilt.pick(req.method))
                }
                fs_resolve::Outcome::Autoindex {
                    dir_path,
                    uri,
                    exact_size,
                    localtime,
                    format,
                } => match format {
                    AutoindexFormat::Html => {
                        match autoindex::render_html(&dir_path, &uri, exact_size, localtime) {
                            Ok(body) => {
                                Response::Owned(http::build_response_bytes_with_content_type(
                                    200,
                                    &body,
                                    b"text/html",
                                    req.method,
                                    server_bytes,
                                ))
                            }
                            Err(e) => {
                                eprintln!(
                                    "ruxen: autoindex render failed for {} (uri={}): {e}",
                                    dir_path.display(),
                                    String::from_utf8_lossy(&uri)
                                );
                                Response::Owned(http::build_response_for_method(
                                    500,
                                    "Internal Server Error\n",
                                    req.method,
                                    server_bytes,
                                ))
                            }
                        }
                    }
                    AutoindexFormat::Xml => match autoindex::render_xml(&dir_path) {
                        Ok(body) => Response::Owned(http::build_response_bytes_with_content_type(
                            200,
                            &body,
                            b"text/xml; charset=utf-8",
                            req.method,
                            server_bytes,
                        )),
                        Err(e) => {
                            eprintln!(
                                "ruxen: autoindex xml render failed for {} (uri={}): {e}",
                                dir_path.display(),
                                String::from_utf8_lossy(&uri)
                            );
                            Response::Owned(http::build_response_for_method(
                                500,
                                "Internal Server Error\n",
                                req.method,
                                server_bytes,
                            ))
                        }
                    },
                    AutoindexFormat::Json => {
                        match autoindex::render_json(&dir_path, autoindex::JsonMode::Json) {
                            Ok(body) => {
                                Response::Owned(http::build_response_bytes_with_content_type(
                                    200,
                                    &body,
                                    b"application/json",
                                    req.method,
                                    server_bytes,
                                ))
                            }
                            Err(e) => {
                                eprintln!(
                                    "ruxen: autoindex json render failed for {} (uri={}): {e}",
                                    dir_path.display(),
                                    String::from_utf8_lossy(&uri)
                                );
                                Response::Owned(http::build_response_for_method(
                                    500,
                                    "Internal Server Error\n",
                                    req.method,
                                    server_bytes,
                                ))
                            }
                        }
                    }
                    AutoindexFormat::Jsonp => {
                        match autoindex::render_json(
                            &dir_path,
                            autoindex::JsonMode::Jsonp {
                                args: render_ctx_base.args,
                            },
                        ) {
                            Ok(body) => {
                                Response::Owned(http::build_response_bytes_with_content_type(
                                    200,
                                    &body,
                                    b"application/json",
                                    req.method,
                                    server_bytes,
                                ))
                            }
                            Err(e) => {
                                eprintln!(
                                    "ruxen: autoindex jsonp render failed for {} (uri={}): {e}",
                                    dir_path.display(),
                                    String::from_utf8_lossy(&uri)
                                );
                                Response::Owned(http::build_response_for_method(
                                    500,
                                    "Internal Server Error\n",
                                    req.method,
                                    server_bytes,
                                ))
                            }
                        }
                    }
                },
                fs_resolve::Outcome::InternalServerError => {
                    Response::Owned(http::build_response_for_method(
                        500,
                        "Internal Server Error\n",
                        req.method,
                        server_bytes,
                    ))
                }
            }
        }
    };
    let intercepted = maybe_intercept_error_page(
        inner,
        loc.error_pages,
        req,
        &render_ctx_base,
        in_error_page,
        loc.recursive_error_pages,
        server_bytes,
    );
    let trailers_allowed =
        req.http_11 && !matches!(req.method, Method::Head) && loc.chunked_transfer_encoding;
    finalize_location_response(
        intercepted,
        loc.add_headers,
        loc.add_trailers,
        trailers_allowed,
        &render_ctx_base,
        error_page_status,
        preserved_location,
        preserved_www_authenticate,
        loc.expires,
    )
}

thread_local! {
    /// `(prebuilt ptr, add_headers ptr)` → the prebuilt with those headers
    /// applied, or `None` when some value has variables. Both keys are
    /// `'static` config data, so the map is bounded by the config.
    static PREBUILT_ADD_HEADERS: std::cell::RefCell<
        std::collections::HashMap<(usize, usize), Option<&'static [u8]>>,
    > = std::cell::RefCell::new(std::collections::HashMap::new());
}

/// A static `return` with `add_header`s whose values are all literals
/// produces the same bytes on every request, so build them once per worker
/// and serve them as a prebuilt. Before this, every request copied the
/// response, rendered and spliced each header, and re-scanned the result
/// (`add_header_many` ran at ~93% of nginx).
///
/// The bytes come from `inject_add_headers` itself, so the output is the
/// same as the per-request path, including the `Last-Modified` / `ETag`
/// special cases. `status` is fixed for a given prebuilt here (no error-page
/// override), which is all `add_header`'s status eligibility depends on.
fn prebuilt_with_literal_add_headers(
    bytes: &'static [u8],
    add_headers: &'static [PreparedAddHeader],
    status: u16,
    render_ctx_base: &RenderCtx<'_>,
) -> Option<&'static [u8]> {
    let key = (bytes.as_ptr() as usize, add_headers.as_ptr() as usize);
    PREBUILT_ADD_HEADERS.with(|cache| {
        if let Some(hit) = cache.borrow().get(&key) {
            return *hit;
        }
        let literal = add_headers.iter().all(|h| {
            h.value
                .iter()
                .all(|p| matches!(p, PreparedValuePart::Literal(_)))
        });
        let built = literal.then(|| {
            // Literal values ignore the render context; it is only needed
            // to satisfy the signature (and `status` for eligibility).
            let ctx = RenderCtx {
                status,
                ..*render_ctx_base
            };
            let out = inject_add_headers(bytes.to_vec(), add_headers, &ctx);
            &*Box::leak(out.into_boxed_slice())
        });
        cache.borrow_mut().insert(key, built);
        built
    })
}
