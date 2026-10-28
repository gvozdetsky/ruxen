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

#[allow(clippy::too_many_arguments)] // hot path: a parameter struct needs ABBA numbers first
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
        Response::Upgrade(upgraded) => Response::Upgrade(upgraded),
        Response::ProxyStream(s) => Response::ProxyStream(s),
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
                && let Some(cached) =
                    prebuilt_with_literal_add_headers(bytes, add_headers, status, render_ctx_base)
            {
                return Response::Prebuilt(cached);
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
            if status == 204 {
                // `error_page … =204`: header-only, the file isn't sent.
                return Response::Owned(out);
            }
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

/// `proxy_ssl_certificate` with variables (#434): the pair rendered for
/// this request, and its client config; `None` without a certificate.
/// `Err`: it doesn't load, and the error log says why.
#[cold]
fn dynamic_client_config(
    d: &crate::upstream_tls::DynamicCert,
    ctx: &RenderCtx<'_>,
) -> Result<Option<std::sync::Arc<rustls::ClientConfig>>, ()> {
    use crate::worker::PreparedCertPath;
    let render = |path: &PreparedCertPath| match path {
        PreparedCertPath::File(path) => {
            use std::os::unix::ffi::OsStrExt;
            path.as_os_str().as_bytes().to_vec()
        }
        PreparedCertPath::Vars { parts, .. } => {
            let mut out = Vec::new();
            render_parts(parts, ctx, &mut out);
            out
        }
    };
    let cert = render(&d.cert);
    let key = if cert.is_empty() {
        Vec::new()
    } else {
        render(&d.key)
    };
    d.config(&cert, &key)
        .map_err(|e| crate::fs_resolve::note_failed_lookup(e, false))
}

/// The client framed a body (even an empty one): it sent Content-Length
/// or Transfer-Encoding. nginx's `content_length_n` is -1 otherwise. A
/// proxied GET without a body asks, so the scan is cheap: line starts by
/// memchr, a line ruled out by its first byte (it was ~1% of a proxied
/// GET's instructions, byte by byte).
#[inline(never)]
fn body_framed(headers: &[u8]) -> bool {
    let named = |line: &[u8], name: &[u8]| {
        line.len() > name.len()
            && line[name.len()] == b':'
            && line[..name.len()].eq_ignore_ascii_case(name)
    };
    let mut start = 0;
    while let Some(line) = headers.get(start..) {
        let framed = match line.first() {
            Some(b'c' | b'C') => named(line, b"content-length"),
            Some(b't' | b'T') => named(line, b"transfer-encoding"),
            _ => false,
        };
        if framed {
            return true;
        }
        match memchr::memchr(b'\n', line) {
            Some(end) => start += end + 1,
            None => return false,
        }
    }
    false
}

/// nginx's `r->quoted_uri`: a `%` in the path of the client's request
/// target (not in its arguments). Out of line, as `write_upstream_path`:
/// inlined, both made the proxy handler slower for every request (#575).
#[inline(never)]
fn path_is_quoted(target: &[u8]) -> bool {
    let path = target.split(|&b| b == b'?').next().unwrap_or(target);
    path.contains(&b'%')
}

/// The (decoded) path into the upstream request target: escaped as
/// NGX_ESCAPE_URI, or as it is (#575).
#[inline(never)]
fn write_upstream_path(path: &[u8], escape: bool, out: &mut Vec<u8>) {
    if escape {
        crate::worker::render::escape_uri_into(path, out);
    } else {
        out.extend_from_slice(path);
    }
}

/// A `proxy_pass` with variables whose rendered URI has a CR, LF or NUL
/// (a decoded `$uri` or capture): a 500 with an `[error]` line, instead of
/// a request line split in two (#541).
#[cold]
fn bad_proxy_uri(uri: &[u8], method: Method) -> Response {
    crate::fs_resolve::note_failed_lookup(
        format!(
            "invalid URI \"{}\" to proxy: a CR, LF or NUL byte",
            uri.escape_ascii()
        ),
        false,
    );
    crate::worker::internal_error_response(method)
}

/// `proxy_cache` for one request (#233, ngx_http_upstream_cache): the
/// zone, the key, and what the cache holds for it. `None` when the method
/// isn't cached or `proxy_cache $var` renders empty or `off`; `Err` (a
/// 500) when it names no zone.
fn cache_plan(
    conf: &'static crate::worker::PreparedProxyCache,
    req: &phase::RequestCtx<'_>,
    ctx: &RenderCtx<'_>,
    request_uri: &[u8],
    host_header: &[u8],
) -> Result<Option<Box<crate::proxy::CachePlan>>, ()> {
    use crate::proxy::{CacheHit, CachePlan};
    use crate::proxy_cache::{CacheStatus, Entry, Lookup};
    // proxy_cache_methods: GET and HEAD always.
    if !matches!(req.method, Method::Get | Method::Head)
        && !(conf.methods_post && req.method_bytes == b"POST")
    {
        return Ok(None);
    }
    let zone = match conf.zone {
        crate::worker::PreparedCacheZone::Zone(zone) => zone,
        crate::worker::PreparedCacheZone::Var(parts, zones) => {
            let mut name = Vec::new();
            render_parts(parts, ctx, &mut name);
            if name.is_empty() || name == b"off" {
                return Ok(None);
            }
            match zones.iter().copied().find(|z| z.name.as_bytes() == name) {
                Some(zone) => zone,
                None => {
                    crate::fs_resolve::note_failed_lookup(
                        format!("cache \"{}\" not found", String::from_utf8_lossy(&name)),
                        false,
                    );
                    return Err(());
                }
            }
        }
    };
    // Without proxy_cache_key: the upstream URL, as nginx's proxy module
    // keys it.
    let mut key = Vec::with_capacity(64);
    match conf.key {
        Some(parts) => render_parts(parts, ctx, &mut key),
        None => {
            key.extend_from_slice(if ctx.proxy_tls {
                b"https://"
            } else {
                b"http://"
            });
            key.extend_from_slice(host_header);
            key.extend_from_slice(request_uri);
        }
    }
    let main = crate::proxy_cache::hash_key(&key);
    let mut hash = main;
    let mut secondary = false;
    // ngx_http_test_predicates: a condition holds when it renders
    // non-empty and not "0".
    let holds = |conditions: &[&[PreparedValuePart]]| {
        conditions.iter().any(|parts| {
            let mut value = Vec::new();
            render_parts(parts, ctx, &mut value);
            !value.is_empty() && value != b"0"
        })
    };
    let no_cache = holds(conf.no_cache);
    let mut status = CacheStatus::Miss;
    let mut hit = None;
    let mut stale = None;
    let mut store = !no_cache;
    // nginx's NGX_HTTP_CACHE_SCARCE: below proxy_cache_min_uses.
    let mut cacheable = true;
    let mut token = None;
    let mut wait_until = None;
    let mut background = false;
    let mut stale_error = false;
    if holds(conf.bypass) {
        // The response still refreshes the cache.
        status = CacheStatus::Bypass;
    } else {
        let now = crate::proxy_cache::now_secs();
        let headers = req.headers_raw;
        // ngx_http_file_cache_reopen: the main key holds a response stored
        // for another variant (its `Vary` names headers this request has
        // other values of), so the lookup goes on at the request's own
        // variant's key, once.
        loop {
            let path = || zone.file_path(&hash);
            let mut other = None;
            match zone.lookup(&hash, conf.min_uses, now) {
                Lookup::Error(code) => {
                    status = CacheStatus::Hit;
                    hit = Some(CacheHit::Error(code));
                }
                Lookup::Hit => match Entry::read(&path(), &key) {
                    Some(entry) => match entry.other_variant(&main, headers) {
                        None => {
                            status = CacheStatus::Hit;
                            hit = Some(CacheHit::Entry(entry));
                        }
                        variant => other = variant,
                    },
                    None => zone.forget_file(&hash),
                },
                Lookup::Stale {
                    token: updater,
                    stale_updating,
                    stale_error: covered,
                } => {
                    // ngx_http_upstream_cache: STALE (this request updates)
                    // or UPDATING (another one does).
                    token = updater;
                    stale_error = covered;
                    let serve_stale = conf.use_stale.updating || stale_updating;
                    // Read only when something may answer with it; else
                    // only its header, for the variant.
                    let entry = if serve_stale || covered || conf.revalidate || conf.use_stale.any()
                    {
                        Entry::read(&path(), &key)
                    } else {
                        other =
                            crate::proxy_cache::stored_other_variant(&path(), &key, &main, headers);
                        None
                    };
                    if let Some(e) = &entry {
                        other = e.other_variant(&main, headers);
                    }
                    match entry {
                        _ if other.is_some() => {}
                        Some(entry)
                            if serve_stale && updater.is_some() && conf.background_update =>
                        {
                            status = CacheStatus::Stale;
                            hit = Some(CacheHit::Entry(entry));
                            background = true;
                        }
                        Some(entry) if serve_stale && updater.is_none() => {
                            status = CacheStatus::Updating;
                            hit = Some(CacheHit::Entry(entry));
                        }
                        // Fetched again; kept to revalidate with, or to
                        // answer with if the upstream fails
                        // (proxy_cache_use_stale).
                        entry => {
                            status = CacheStatus::Expired;
                            stale = entry;
                        }
                    }
                }
                Lookup::Miss {
                    store: enough,
                    probe,
                } => {
                    store &= enough;
                    cacheable = enough;
                    // A file from before a restart (nginx's cold cache).
                    if probe && let Some(entry) = Entry::read(&path(), &key) {
                        zone.adopt(&hash, &entry);
                        store = !no_cache;
                        cacheable = true;
                        other = entry.other_variant(&main, headers);
                        if other.is_some() {
                        } else if entry.valid_sec < now {
                            status = CacheStatus::Expired;
                            stale = Some(entry);
                        } else {
                            status = CacheStatus::Hit;
                            hit = Some(CacheHit::Entry(entry));
                        }
                    }
                    // proxy_cache_lock: one request fetches a missing
                    // response, the others wait for it.
                    if other.is_none() && status == CacheStatus::Miss && store && conf.lock {
                        match zone.try_lock(&hash, conf.lock_age_ms) {
                            Some(lock) => token = Some(lock),
                            None if conf.lock_timeout_ms == 0 => store = false,
                            None => {
                                wait_until = Some(
                                    std::time::Instant::now()
                                        + std::time::Duration::from_millis(conf.lock_timeout_ms),
                                );
                            }
                        }
                    }
                }
            }
            // A variant's key holding yet another variant is a miss, as
            // nginx's "incorrect vary hash".
            let Some(variant) = other.filter(|_| !secondary) else {
                break;
            };
            if let Some(t) = token.take() {
                zone.release(&hash, t);
            }
            hash = variant;
            secondary = true;
            status = CacheStatus::Miss;
            store = !no_cache;
            cacheable = true;
            stale_error = false;
        }
    }
    // ngx_http_upstream_cache_check_range: a range from too far into the
    // response isn't worth fetching it whole for the cache; it goes
    // upstream as asked, and nothing is stored. A `proxy_cache_lock` taken
    // stays with the request, released when it ends, as nginx's (#864).
    if hit.is_none()
        && cacheable
        && let Some(max) = conf.max_range_offset
        && let Some(range) = req.range
        && range_too_far(range, max)
    {
        cacheable = false;
        store = false;
    }
    Ok(Some(Box::new(CachePlan {
        conf,
        zone,
        main,
        hash,
        secondary,
        status,
        store,
        cacheable,
        // A hit needs neither, unless it is updated in the background, or
        // the request is conditional (the not-modified check, #349).
        request_headers: if hit.is_some()
            && !background
            && req.if_none_match.is_none()
            && req.if_modified_since.is_none()
            && req.if_match.is_none()
            && req.if_unmodified_since.is_none()
        {
            Vec::new()
        } else {
            req.headers_raw.to_vec()
        },
        key,
        hit,
        stale,
        head_as_get: conf.convert_head && matches!(req.method, Method::Head),
        token,
        wait_until,
        background,
        stale_error,
    })))
}

pub(crate) fn forward_client_headers<'a>(
    headers_raw: &'a [u8],
    overrides: &[(&[u8], Vec<u8>)],
    out: &mut Vec<crate::proxy::ProxyHeader<'a>>,
    ignore_invalid_headers: bool,
    underscores_in_headers: bool,
) -> bool {
    // Whether the client sent `Upgrade` (not forwarded: hop-by-hop).
    let mut upgrade = false;
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
            upgrade |= name.eq_ignore_ascii_case(b"upgrade");
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
    upgrade
}

/// Dispatch a location's matched handler for a given URL path. Called from
/// `phase::process` inside the reroute loop — the URL may differ from
/// `req.path` on subsequent hops after an internal redirect.
///
/// Return semantics: on `Response::Reroute`, `phase::process` re-runs
/// location matching with the new URL. All other variants are terminal.
/// The variable-render context of a request in a location: the `return`
/// body, `add_header` values and error pages share it.
#[inline(always)]
#[allow(clippy::too_many_arguments)] // hot path: a parameter struct needs ABBA numbers first
fn location_render_ctx<'a>(
    http: &'static PreparedHttp,
    server: &'static PreparedServer,
    req: &'a phase::RequestCtx<'_>,
    url_path: &'a [u8],
    current_args: Option<&'a [u8]>,
    remote_user: Option<&'a [u8]>,
    rewrite_state: &'a RewriteState,
    server_name_captures: Option<&'a phase::ServerNameCaptures>,
) -> RenderCtx<'a> {
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
    RenderCtx {
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
        request_id: req.request_id,
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
        proxy_tls: false,
        upstream_headers: req.upstream.map_or(&[], |u| &u.headers),
        upstream_states: req.upstream.map_or(&[], |u| &u.states),
        upstream_cache_status: req.upstream.map_or(&[], |u| u.cache_status_bytes()),
        sent_trailers: &[],
        tls: req.tls,
        conn: req.conn,
    }
}

/// A 401 or 403 from the access phase, sent as nginx's special response:
/// the location's `error_page` and `add_header … always` apply. A body
/// over `client_max_body_size` gets its 413 first, as the find_config
/// phase runs before the access phase.
#[cold]
#[inline(never)]
#[allow(clippy::too_many_arguments)] // hot path: a parameter struct needs ABBA numbers first
pub(crate) fn finish_access_denial(
    http: &'static PreparedHttp,
    server: &'static PreparedServer,
    loc: MatchedLocation<'static>,
    req: &phase::RequestCtx<'_>,
    url_path: &[u8],
    current_args: Option<&[u8]>,
    rewrite_state: &RewriteState,
    error_page_status: Option<phase::ErrorPageStatus>,
    in_error_page: bool,
    preserved_location: Option<&[u8]>,
    preserved_www_authenticate: &[Vec<u8>],
    server_name_captures: Option<&phase::ServerNameCaptures>,
    response: Response,
    // False for a `return` with text from the rewrite phase, which nginx
    // sends without `error_page` (#362).
    takes_error_page: bool,
) -> Response {
    let render_ctx_base = location_render_ctx(
        http,
        server,
        req,
        url_path,
        current_args,
        None,
        rewrite_state,
        server_name_captures,
    );
    let body_limit = loc
        .client_max_body_size
        .unwrap_or(DEFAULT_CLIENT_MAX_BODY_SIZE);
    if body_limit > 0 && req.body_len > body_limit && !in_error_page && error_page_status.is_none()
    {
        return entity_too_large(
            &loc,
            req,
            &render_ctx_base,
            in_error_page,
            preserved_www_authenticate,
        );
    }
    let intercepted = if takes_error_page {
        maybe_intercept_error_page(
            response,
            loc.error_pages,
            req,
            &render_ctx_base,
            in_error_page,
            loc.recursive_error_pages,
            loc.server_header,
        )
    } else {
        response
    };
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

/// ngx_http_upstream_cache_check_range: `Range` starts at or past `max`
/// (always, for `0`), or counts from the end.
fn range_too_far(range: &[u8], max: u64) -> bool {
    if max == 0 {
        return true;
    }
    let Some(spec) = range
        .get(..6)
        .filter(|p| p.eq_ignore_ascii_case(b"bytes="))
        .map(|_| &range[6..])
        .filter(|_| range.len() >= 7)
    else {
        return false;
    };
    let spec = spec.trim_ascii_start();
    if spec.first() == Some(&b'-') {
        return true;
    }
    let digits = spec.iter().take_while(|b| b.is_ascii_digit()).count();
    std::str::from_utf8(&spec[..digits])
        .ok()
        .and_then(|d| d.parse::<u64>().ok())
        .is_some_and(|offset| offset >= max)
}

#[allow(clippy::too_many_arguments)] // hot path: a parameter struct needs ABBA numbers first
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
    // Not again on the way to an error page: nginx has discarded the body
    // by then (`!r->discard_body` in ngx_http_core_find_config_phase).
    let body_limit = loc
        .client_max_body_size
        .unwrap_or(DEFAULT_CLIENT_MAX_BODY_SIZE);
    let too_large = body_limit > 0
        && req.body_len > body_limit
        && !in_error_page
        && error_page_status.is_none();

    let render_ctx_base = location_render_ctx(
        http,
        server,
        req,
        url_path,
        current_args,
        remote_user,
        rewrite_state,
        server_name_captures,
    );
    let args = render_ctx_base.args;

    let server_bytes = loc.server_header;
    if too_large {
        return entity_too_large(
            &loc,
            req,
            &render_ctx_base,
            in_error_page,
            preserved_www_authenticate,
        );
    }
    // The proxy handler of an earlier `if` with the configuration of a
    // later one that has no `proxy_pass` (#703): nginx 1.3.10+ answers 500
    // with an alert (ngx_http_upstream_init_request), through error_page.
    if rewrite_state.if_proxy && !matches!(loc.handler, PreparedHandler::Proxy(_)) {
        return no_upstream_configuration(
            http,
            &loc,
            req,
            &render_ctx_base,
            in_error_page,
            preserved_www_authenticate,
        );
    }
    // The plan carries everything `proxy::run_proxy` needs for async work.
    // The worker awaits it after `process_with_meta`, then applies the
    // location's proxy add_header/add_trailer state with `$upstream_*`
    // variables populated.
    if let PreparedHandler::Proxy(proxy) = loc.handler {
        // `proxy_pass` with variables: where this request goes (#100).
        let variable = match proxy.url {
            None => None,
            Some(url) => match resolve_variable_url(http, proxy, url, &render_ctx_base) {
                Ok(target) => Some(target),
                Err(status) => {
                    return variable_url_failed(
                        http,
                        status,
                        &loc,
                        req,
                        &render_ctx_base,
                        in_error_page,
                        preserved_www_authenticate,
                    );
                }
            },
        };
        let upstream = variable.as_ref().map_or(proxy.upstream, |v| v.upstream);
        let host_header: &[u8] = variable
            .as_ref()
            .map_or(proxy.host_header, |v| &v.host_header);
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
        // The upstream request target, as ngx_http_proxy_create_request
        // builds it (#541). The decoded URI goes into the request line
        // escaped (NGX_ESCAPE_URI) when the client's path had a `%` (nginx's
        // `r->quoted_uri`: a `%0D%0A` would otherwise split the line) or
        // the request is internal (`r->internal`: a rewrite of the URI or
        // an internal redirect cleared `unparsed_uri`); otherwise nginx
        // copies it as it is (#575).
        let escape = || !rewrite_state.unparsed_uri || path_is_quoted(req.path);
        let rewritten_uri: Vec<u8>;
        let request_uri: &[u8] = if let Some(uri) = variable.as_ref().and_then(|v| v.uri.as_deref())
        {
            // With variables, a URI part is the whole upstream URI. nginx
            // copies it as rendered; one that a decoded variable gave a CR,
            // LF or NUL is refused instead.
            if uri.iter().any(|&b| matches!(b, b'\r' | b'\n' | 0)) {
                return bad_proxy_uri(uri, req.method);
            }
            uri
        } else if request_path.is_empty() {
            if rewrite_state.unparsed_uri && current_args.is_none() && req.path.starts_with(b"/") {
                // Unchanged: the client's own request target (nginx's
                // `r->unparsed_uri`).
                req.path
            } else {
                let mut buf = Vec::with_capacity(url_path.len() + 1 + args.len());
                write_upstream_path(url_path, escape(), &mut buf);
                if !args.is_empty() {
                    buf.push(b'?');
                    buf.extend_from_slice(args);
                }
                rewritten_uri = buf;
                rewritten_uri.as_slice()
            }
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
            write_upstream_path(suffix, escape(), &mut buf);
            if !args.is_empty() {
                buf.push(b'?');
                buf.extend_from_slice(args);
            }
            rewritten_uri = buf;
            rewritten_uri.as_slice()
        };
        // Render proxy_set_header values with $proxy_host populated for
        // this location's upstream URL authority. The other RenderCtx
        // fields are inherited from the base built above.
        let mut proxy_render_ctx = render_ctx_base;
        proxy_render_ctx.proxy_host = host_header;
        proxy_render_ctx.proxy_tls = variable.as_ref().map_or(proxy.tls.is_some(), |v| v.tls);
        // `proxy_cache` (#233): what the cache has for this request.
        let cache = match proxy.cache {
            Some(conf) => {
                match cache_plan(conf, req, &proxy_render_ctx, request_uri, host_header) {
                    Ok(cache) => cache,
                    Err(()) => return crate::worker::internal_error_response(req.method),
                }
            }
            None => None,
        };
        // Pick the first peer via the per-worker LB. None means every
        // peer is `down` or in a `max_fails` cooldown: `run_proxy` answers
        // 502 and reports `no live upstreams` for the error log. A cache
        // hit needs none.
        let mut hash = crate::upstream::HashPick::for_request(
            upstream,
            |key| {
                let mut out = Vec::new();
                render_parts(key, &render_ctx_base, &mut out);
                out
            },
            render_ctx_base.remote_addr,
        );
        let initial_peer = if cache
            .as_ref()
            .is_some_and(|c| c.hit.is_some() && !c.background)
        {
            None
        } else {
            crate::upstream::pick_peer(upstream, &Default::default(), hash.as_deref_mut())
        };

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
            http::make_header_value_safe(&mut value);
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
            overrides_buf.insert(0, (b"Host", host_header.to_vec()));
        }

        // Pool eligibility: HTTP/1.1 + the upstream block has a keepalive
        // pool (every `upstream {}` block unless `keepalive 0;`). Drives
        // both the Connection-header default below and `run_proxy`'s
        // pool-release decision.
        let pool_eligible = proxy.http_version == 1 && upstream.keepalive_max_idle.is_some();

        // nginx 1.29.7 sends no Connection header by default
        // (ngx_http_proxy_headers). Over HTTP/1.1 with no pool to take the
        // connection back, ruxen still says `close`, as before 1.29.7: the
        // backend then closes first and holds the TIME_WAIT, not ruxen,
        // whose ephemeral ports would run out under load (#582).
        if !have_connection_override && proxy.http_version == 1 && !pool_eligible {
            overrides_buf.push((b"Connection", b"close".to_vec()));
        }

        if cache.as_ref().is_some_and(|c| c.cacheable) {
            // ngx_http_proxy_cache_headers: with a cache (once
            // proxy_cache_min_uses is reached) the upstream gets no
            // conditional or range request headers, so what comes back can
            // be stored whole; a revalidation asks with the stale entry's
            // validators.
            let (last_modified, etag) = cache
                .as_ref()
                .filter(|c| c.conf.revalidate)
                .and_then(|c| c.stale.as_ref())
                .map_or((None, None), |stale| stale.validators());
            let none = None;
            for (name, value) in [
                (&b"If-Modified-Since"[..], last_modified),
                (&b"If-Unmodified-Since"[..], none),
                (&b"If-None-Match"[..], etag),
                (&b"If-Match"[..], none),
                (&b"Range"[..], none),
                (&b"If-Range"[..], none),
            ] {
                if !overrides_buf
                    .iter()
                    .any(|(n, _)| n.eq_ignore_ascii_case(name))
                {
                    overrides_buf.push((name, value.map_or(Vec::new(), <[u8]>::to_vec)));
                }
            }
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
            None if proxy.pass_request_body && req.body_file.is_some() => req.body_len,
            // A body dropped unread (discarded, or over the limit, on the
            // way to an error page) has a length and no bytes: none go
            // upstream, as in nginx.
            None if proxy.pass_request_body => req.body.len() as u64,
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
        // Content-Length is the length of the body forwarded, as nginx's
        // `$proxy_internal_body_length`: an empty one says 0 when the
        // client framed a body (a Content-Length, a chunked body, an
        // HTTP/2 stream with DATA) or `proxy_set_body` gave one, whatever
        // the method; a request without body framing has none (#493).
        if !have_content_length_override {
            if forward_len > 0 {
                overrides_buf.push((b"Content-Length", forward_len.to_string().into_bytes()));
            } else if set_body.is_some() || body_framed(req.headers_raw) {
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
        let client_upgrade = if proxy.pass_request_headers {
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
            )
        } else {
            lookup_request_header(req.headers_raw, b"upgrade").is_some()
        };

        // A large client body is sent from its own buffer, after the
        // header block, instead of being copied into it (#289). A small
        // one is copied: one buffer, one write.
        let (forward_body, separate_body) =
            if set_body.is_none() && forward_body.len() > crate::proxy::SEPARATE_BODY_MIN {
                (&[][..], req.body.clone())
            } else {
                (forward_body, bytes::Bytes::new())
            };
        // Pooled: with the body in it the buffer is as large as the body,
        // and a fresh one per request faults its pages in each time (#289).
        let mut request = crate::worker::take_body_buffer(0);
        // The method sent upstream, in nginx's order
        // (ngx_http_proxy_create_request): a HEAD the cache turns into a
        // GET, then `proxy_method`, then the client's.
        let mut proxy_method = Vec::new();
        let method_bytes = if cache.as_ref().is_some_and(|c| c.head_as_get) {
            &b"GET"[..]
        } else if let Some(parts) = proxy.proxy_method {
            render_parts(parts, &proxy_render_ctx, &mut proxy_method);
            &proxy_method[..]
        } else {
            req.method_bytes
        };
        crate::proxy::write_request(
            &mut request,
            method_bytes,
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
        // `proxy_force_ranges` (#370).
        let force_ranges = proxy.force_ranges;
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
        let upstream_head = method_bytes.eq_ignore_ascii_case(b"HEAD");
        let bind = proxy
            .bind
            .and_then(|bind| resolve_bind(bind, &proxy_render_ctx));
        // TLS to the upstream (#116): a URL with variables says per request.
        let tls = match proxy
            .tls
            .filter(|_| variable.as_ref().is_none_or(|v| v.tls))
        {
            None => None,
            Some(t) => {
                let name = match (t.name_vars, variable.as_ref()) {
                    (Some(parts), _) => {
                        let mut rendered = Vec::with_capacity(32);
                        render_parts(parts, &proxy_render_ctx, &mut rendered);
                        crate::upstream_tls::server_name(&rendered)
                    }
                    (None, Some(v)) if t.default_name => {
                        crate::upstream_tls::server_name(&v.host_header)
                    }
                    (None, _) => t.name.clone(),
                };
                let config = match &t.dynamic_cert {
                    None => t.config.clone(),
                    Some(d) => match dynamic_client_config(d, &proxy_render_ctx) {
                        Ok(Some(config)) => config,
                        Ok(None) => t.config.clone(),
                        Err(()) => return crate::worker::internal_error_response(req.method),
                    },
                };
                Some(Box::new(crate::upstream_tls::TlsPlan { config, name }))
            }
        };
        return Response::Proxy(Box::new(crate::proxy::ProxyPlan {
            upstream,
            tls,
            adhoc: variable.and_then(|v| v.adhoc).map(Box::new),
            initial_peer,
            request: bytes::Bytes::from_owner(crate::worker::PooledBody(request)),
            body: separate_body,
            method: req.method,
            upstream_head,
            server_bytes,
            connect_timeout: std::time::Duration::from_millis(proxy.connect_timeout_ms),
            read_timeout: std::time::Duration::from_millis(proxy.read_timeout_ms),
            send_timeout: std::time::Duration::from_millis(proxy.send_timeout_ms),
            limit_rate: proxy.limit_rate,
            bad_gateway: &http.bad_gateway,
            gateway_timeout: &http.gateway_timeout,
            keepalive_eligible: pool_eligible,
            pool_tag: proxy.pool_tag(upstream),
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
            error_page_status,
            intercept,
            upgrade: client_upgrade,
            force_ranges,
            ignore_client_abort: proxy.ignore_client_abort,
            cache,
            hash,
            bind,
        }));
    }
    let inner = match loc.handler {
        PreparedHandler::Return(PreparedReturn::Static(response, types), _) => typed_return(
            Response::Prebuilt(response.pick(req.method)),
            *types,
            url_path,
        ),
        PreparedHandler::Return(
            PreparedReturn::Template {
                status,
                parts,
                types,
            },
            _,
        ) => {
            let response = Response::Owned(build_templated_return(
                *status,
                parts,
                &render_ctx_base,
                req.method,
                server_bytes,
                phase::RedirectCtx::new(loc.redirect, req, server),
            ));
            typed_return(response, *types, url_path)
        }
        PreparedHandler::Proxy(_) => unreachable!("handled above"),
        // ngx_http_stub_status_handler: GET and HEAD only, text/plain.
        PreparedHandler::StubStatus => match req.method {
            Method::Get => Response::Owned(http::build_response(
                200,
                &super::stats::status_text(),
                server_bytes,
            )),
            Method::Head => Response::Owned(http::build_head_response(
                200,
                super::stats::status_text().len(),
                server_bytes,
            )),
            _ => Response::Owned(crate::file::method_not_allowed(req.method, server_bytes)),
        },
        // Static-file mapping follows the configured path mode:
        // `root` appends the whole normalized URI, while `alias` strips the
        // matched location prefix first. `PreparedRoot` carries that choice.
        PreparedHandler::Root(root) => 'root: {
            // The static module takes GET, HEAD and POST; it refuses a POST
            // only once the file is found (ngx_http_static_handler).
            let get_or_head = matches!(req.method, Method::Get | Method::Head);
            // Another method gets the static module's 405, unless a
            // `try_files` fallback takes the request first: nginx's
            // try_files phase runs for every method, so a PUT goes on to
            // `@app` (ngx_http_core_try_files_phase checks no method).
            let not_static = !get_or_head && req.method_bytes != b"POST";
            if not_static && root.try_files.is_none() {
                break 'root Response::Owned(file::method_not_allowed(req.method, server_bytes));
            }
            // An `alias` after a rewrite: nothing to map (#589).
            if !matches!(root.path_mapping, PreparedPathMapping::Root)
                && loc.doc_root.alias_refused(rewrite_state)
            {
                break 'root crate::worker::internal_error_response(req.method);
            }
            let last_modified_override =
                last_modified_override_for_conditionals(loc.add_headers, &render_ctx_base);
            match fs_resolve::resolve(root, url_path, &render_ctx_base) {
                fs_resolve::Outcome::Serve(_) if !get_or_head => {
                    Response::Owned(file::method_not_allowed(req.method, server_bytes))
                }
                fs_resolve::Outcome::Serve(opened) => {
                    // An error page that goes out with another status than
                    // 200 is sent whole: nginx's not_modified and range
                    // filters only act on a 200, so no 304, no 206 and no
                    // `Accept-Ranges` (a 304 turned into a 404 had no body
                    // and no length).
                    if let Some(
                        phase::ErrorPageStatus::Preserve(status)
                        | phase::ErrorPageStatus::Override(status),
                    ) = error_page_status
                        && status != 200
                    {
                        break 'root file::serve_path(
                            opened,
                            req.method,
                            file::Conditionals {
                                if_modified_since: None,
                                if_unmodified_since: None,
                                if_none_match: None,
                                if_match: None,
                                range: None,
                                if_range: None,
                                last_modified_override: last_modified_override.as_deref(),
                                max_ranges: Some(0),
                                ims_mode: root.if_modified_since,
                                etag: root.etag,
                            },
                            server_bytes,
                            loc.sendfile,
                        );
                    }
                    // `max_ranges 0`: nginx's range filter declines, so
                    // the file goes whole, without `Accept-Ranges` (#370).
                    let accept_ranges = loc.max_ranges != Some(0);
                    // A file gzip will compress is sent whole, as nginx's
                    // range filter (after gzip) finds no length to cut.
                    let range = match (req.range.filter(|_| accept_ranges), loc.gzip) {
                        (Some(_), Some(gz))
                            if super::gzip::would_compress(
                                gz,
                                &super::gzip::GzipRequest::from_headers(
                                    req.http_11,
                                    req.headers_raw,
                                ),
                                opened.mime,
                                opened.size,
                            ) =>
                        {
                            None
                        }
                        (range, _) => range,
                    };
                    let vary_cut = match (range, loc.gzip) {
                        (Some(_), Some(gz)) if gz.vary => Some((gz, opened.mime, opened.size)),
                        _ => None,
                    };
                    let response = file::serve_path(
                        opened,
                        req.method,
                        file::Conditionals {
                            if_modified_since: req.if_modified_since,
                            if_unmodified_since: req.if_unmodified_since,
                            if_none_match: req.if_none_match,
                            if_match: req.if_match,
                            range,
                            if_range: req.if_range,
                            last_modified_override: last_modified_override.as_deref(),
                            max_ranges: loc.max_ranges,
                            ims_mode: root.if_modified_since,
                            etag: root.etag,
                        },
                        server_bytes,
                        loc.sendfile,
                    );
                    match vary_cut {
                        Some((gz, mime, size)) => {
                            super::gzip::vary_cut_file(gz, mime, size, response)
                        }
                        None => response,
                    }
                }
                // What try_files found (a directory, a listing) is the
                // static module's, and so its 405.
                fs_resolve::Outcome::Redirect(_) | fs_resolve::Outcome::Autoindex { .. }
                    if not_static =>
                {
                    Response::Owned(file::method_not_allowed(req.method, server_bytes))
                }
                fs_resolve::Outcome::Redirect(location) => {
                    // ngx_http_static_handler: the URI escaped
                    // (NGX_ESCAPE_URI), its arguments kept (#15).
                    let mut location = phase::escape_redirect_uri(&location);
                    if !render_ctx_base.args.is_empty() {
                        location.push(b'?');
                        location.extend_from_slice(render_ctx_base.args);
                    }
                    let abs = phase::RedirectCtx::new(loc.redirect, req, server).apply(&location);
                    Response::Owned(http::build_redirect_response(
                        301,
                        &abs,
                        req.method,
                        server_bytes,
                    ))
                }
                fs_resolve::Outcome::Reroute(target) => {
                    // A try_files fallback such as `/index.php?$args`
                    // brings its own arguments: nginx's internal redirect
                    // takes the part after `?` as the new `$args`.
                    let (target, args) = match target {
                        phase::RerouteTarget::Uri(mut uri) => {
                            match uri.iter().position(|&b| b == b'?') {
                                Some(q) => {
                                    let args = uri[q + 1..].to_vec();
                                    uri.truncate(q);
                                    (phase::RerouteTarget::Uri(uri), Some(args))
                                }
                                None => (phase::RerouteTarget::Uri(uri), None),
                            }
                        }
                        named => (named, None),
                    };
                    return Response::Reroute(phase::Reroute {
                        target,
                        args,
                        error_page_status: None,
                        enters_error_page: false,
                        preserved_location: None,
                        preserved_www_authenticate: Vec::new(),
                        closes: false,
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
                                Response::Owned(http::error_response_for_method(
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
                            Response::Owned(http::error_response_for_method(
                                500,
                                "Internal Server Error\n",
                                req.method,
                                server_bytes,
                            ))
                        }
                    },
                    AutoindexFormat::Json | AutoindexFormat::Jsonp => {
                        let callback = if format == AutoindexFormat::Jsonp {
                            autoindex::jsonp_callback(render_ctx_base.args)
                        } else {
                            Ok(&[][..])
                        };
                        match callback {
                            Err(()) => Response::Owned(http::error_response_for_method(
                                400,
                                "Bad Request\n",
                                req.method,
                                server_bytes,
                            )),
                            Ok(callback) => match autoindex::render_json(&dir_path, callback) {
                                // ngx_http_autoindex_handler: JSONP only with a callback.
                                Ok(body) => {
                                    let content_type: &[u8] = if callback.is_empty() {
                                        b"application/json"
                                    } else {
                                        b"application/javascript"
                                    };
                                    Response::Owned(http::build_response_bytes_with_content_type(
                                        200,
                                        &body,
                                        content_type,
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
                                    Response::Owned(http::error_response_for_method(
                                        500,
                                        "Internal Server Error\n",
                                        req.method,
                                        server_bytes,
                                    ))
                                }
                            },
                        }
                    }
                },
                fs_resolve::Outcome::InternalServerError => {
                    Response::Owned(http::error_response_for_method(
                        500,
                        "Internal Server Error\n",
                        req.method,
                        server_bytes,
                    ))
                }
            }
        }
    };
    let intercepted = if matches!(loc.handler, PreparedHandler::Return(_, false)) {
        inner
    } else {
        maybe_intercept_error_page(
            inner,
            loc.error_pages,
            req,
            &render_ctx_base,
            in_error_page,
            loc.recursive_error_pages,
            server_bytes,
        )
    };
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

/// The 413 for a body over the location's `client_max_body_size`, sent as
/// nginx's special response: the location's `error_page` and `add_header
/// … always` apply (ngx_http_finalize_request(r, 413) from the find_config
/// phase). Cold.
#[cold]
#[inline(never)]
fn entity_too_large(
    loc: &MatchedLocation<'static>,
    req: &phase::RequestCtx<'_>,
    render_ctx_base: &RenderCtx<'_>,
    in_error_page: bool,
    preserved_www_authenticate: &[Vec<u8>],
) -> Response {
    let response = http::error_response_for_method(
        413,
        "Request Entity Too Large\n",
        req.method,
        loc.server_header,
    );
    let intercepted = maybe_intercept_error_page(
        Response::Owned(response),
        loc.error_pages,
        req,
        render_ctx_base,
        in_error_page,
        loc.recursive_error_pages,
        loc.server_header,
    );
    let trailers_allowed =
        req.http_11 && !matches!(req.method, Method::Head) && loc.chunked_transfer_encoding;
    finalize_location_response(
        intercepted,
        loc.add_headers,
        loc.add_trailers,
        trailers_allowed,
        render_ctx_base,
        None,
        None,
        preserved_www_authenticate,
        loc.expires,
    )
}

/// `(prebuilt ptr, add_headers ptr)` → the prebuilt with those headers
/// applied, or `None` when some value has variables.
type PrebuiltAddHeaders = std::collections::HashMap<(usize, usize), Option<&'static [u8]>>;

thread_local! {
    /// Both keys are `'static` config data, so the map is bounded by the
    /// config.
    static PREBUILT_ADD_HEADERS: std::cell::RefCell<PrebuiltAddHeaders> =
        std::cell::RefCell::new(std::collections::HashMap::new());
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

/// Where a `proxy_pass` with variables sends one request (#100).
struct VariableTarget {
    upstream: &'static PreparedUpstream,
    /// The URL's own address (an IP literal or `unix:` path), or its host
    /// name for the resolver (#133); `None` when it named an `upstream`
    /// block.
    adhoc: Option<crate::proxy::Adhoc>,
    /// `$proxy_host` and the default `Host`.
    host_header: Vec<u8>,
    /// The URL's URI part, sent as the whole request URI; `None`: the
    /// request's own.
    uri: Option<Vec<u8>>,
    /// `https://` (#116).
    tls: bool,
}

/// Render and parse a `proxy_pass` URL with variables, as nginx's
/// ngx_http_proxy_eval and ngx_http_upstream_init_request do: an `upstream`
/// block of that name (when the URL has no port), else an IP literal or a
/// `unix:` path as the one peer, else a name for the location's `resolver`
/// (#133), which `run_proxy` resolves; without one, a 502 and nginx's `no
/// resolver defined to resolve` line. A malformed URL is a 500. The error
/// lines are logged with the request's context once processing returns.
#[cold]
#[inline(never)]
fn resolve_variable_url(
    http: &'static PreparedHttp,
    proxy: &PreparedProxy,
    url: &[PreparedValuePart],
    ctx: &RenderCtx<'_>,
) -> Result<VariableTarget, u16> {
    let placeholder = proxy.upstream;
    let one = |peer| {
        Some(crate::proxy::Adhoc {
            peers: vec![peer],
            resolve: None,
        })
    };
    use crate::config::ErrorLogLevel;
    use crate::worker::PeerAddr;
    let mut rendered = Vec::with_capacity(64);
    render_parts(url, ctx, &mut rendered);
    let fail = |status: u16, message: String| {
        crate::fs_resolve::note_failed_lookup_at(message, false, ErrorLogLevel::Error);
        Err(status)
    };
    // `https://`: TLS to the upstream (#116), port 443 by default.
    let (rest, tls) = match (rendered.get(..7), rendered.get(..8)) {
        (Some(scheme), _) if scheme.eq_ignore_ascii_case(b"http://") && rendered.len() > 7 => {
            (&rendered[7..], false)
        }
        (_, Some(scheme)) if scheme.eq_ignore_ascii_case(b"https://") && rendered.len() > 8 => {
            (&rendered[8..], true)
        }
        _ => {
            return fail(
                500,
                format!(
                    "invalid URL prefix in \"{}\"",
                    String::from_utf8_lossy(&rendered)
                ),
            );
        }
    };
    let in_upstream =
        |what: &str| format!("{what} in upstream \"{}\"", String::from_utf8_lossy(rest));
    // `unix:/path[:uri]`: the path ends at the next `:`.
    if rest.len() >= 5 && rest[..5].eq_ignore_ascii_case(b"unix:") {
        let after = &rest[5..];
        let (path, uri) = match after.iter().position(|&b| b == b':') {
            Some(colon) => (&after[..colon], &after[colon + 1..]),
            None => (after, &b""[..]),
        };
        if path.is_empty() {
            return fail(500, in_upstream("no path in the unix domain socket"));
        }
        if path.len() + 1 > 108 {
            return fail(500, in_upstream("too long path in the unix domain socket"));
        }
        let Some(path) = intern_unix_path(path) else {
            return fail(502, in_upstream("too many unix: upstream paths"));
        };
        return Ok(VariableTarget {
            upstream: placeholder,
            adhoc: one(PeerAddr::Unix(path)),
            host_header: b"localhost".to_vec(),
            uri: (!uri.is_empty()).then(|| uri.to_vec()),
            tls,
        });
    }
    // host[:port] up to the URI, which starts at `/` or `?`.
    let end = rest
        .iter()
        .position(|&b| b == b'/' || b == b'?')
        .unwrap_or(rest.len());
    let (authority, uri) = rest.split_at(end);
    let (host, port): (&[u8], Option<&[u8]>) = if authority.first() == Some(&b'[') {
        let Some(close) = authority.iter().position(|&b| b == b']') else {
            return fail(500, in_upstream("invalid host"));
        };
        match &authority[close + 1..] {
            [] => (&authority[..=close], None),
            [b':', port @ ..] => (&authority[..=close], Some(port)),
            _ => return fail(500, in_upstream("invalid host")),
        }
    } else {
        match authority.iter().rposition(|&b| b == b':') {
            Some(colon) => (&authority[..colon], Some(&authority[colon + 1..])),
            None => (authority, None),
        }
    };
    if host.is_empty() {
        return fail(500, in_upstream("no host"));
    }
    let port = match port {
        None => None,
        Some(p) => match std::str::from_utf8(p)
            .ok()
            .and_then(|p| p.parse::<u16>().ok())
        {
            Some(n) if n > 0 => Some(n),
            _ => return fail(500, in_upstream("invalid port")),
        },
    };
    // ngx_http_proxy_set_vars: the scheme's port isn't repeated.
    let default_port = if tls { 443 } else { 80 };
    let host_header = match port {
        None => host.to_vec(),
        Some(p) if p == default_port => host.to_vec(),
        Some(_) => authority.to_vec(),
    };
    let uri = match uri {
        [] => None,
        [b'?', ..] => Some([&b"/"[..], uri].concat()),
        _ => Some(uri.to_vec()),
    };
    let literal = std::str::from_utf8(host).ok().and_then(|h| {
        h.strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(h)
            .parse::<std::net::IpAddr>()
            .ok()
    });
    if let Some(ip) = literal {
        return Ok(VariableTarget {
            upstream: placeholder,
            adhoc: one(PeerAddr::Inet(std::net::SocketAddr::new(
                ip,
                port.unwrap_or(default_port),
            ))),
            host_header,
            uri,
            tls,
        });
    }
    // An `upstream` block matches only a URL without a port, as its
    // name has none; the implicit upstream of another location's
    // `proxy_pass http://host:port` matches by host and port
    // (ngx_http_upstream_init_request).
    let block = || {
        http.upstreams
            .iter()
            .find(|(name, _)| name.as_bytes().eq_ignore_ascii_case(host))
            .map(|(_, upstream)| *upstream)
    };
    let implicit = || {
        http.implicit_upstreams
            .iter()
            .find(|(name, p, _)| {
                *p == port.unwrap_or(default_port) && name.eq_ignore_ascii_case(host)
            })
            .map(|(_, _, upstream)| *upstream)
    };
    if let Some(upstream) = port.is_none().then(block).flatten().or_else(implicit) {
        return Ok(VariableTarget {
            upstream,
            adhoc: None,
            host_header,
            uri,
            tls,
        });
    }
    let Some(resolver) = proxy.resolver else {
        return fail(
            502,
            format!(
                "no resolver defined to resolve {}",
                String::from_utf8_lossy(host)
            ),
        );
    };
    Ok(VariableTarget {
        upstream: placeholder,
        adhoc: Some(crate::proxy::Adhoc {
            peers: Vec::new(),
            resolve: Some(crate::proxy::ResolveName {
                resolver,
                host: host.into(),
                port: port.unwrap_or(default_port),
                timeout: std::time::Duration::from_millis(proxy.resolver_timeout_ms),
            }),
        }),
        host_header,
        uri,
        tls,
    })
}

thread_local! {
    /// `unix:` paths that requests have named through `proxy_pass` with
    /// variables, kept for the life of the worker so a peer can hold a
    /// `&'static Path`. Bounded: the URL may come from the client.
    static UNIX_PATHS: std::cell::RefCell<Vec<&'static std::path::Path>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

const UNIX_PATHS_MAX: usize = 1024;

fn intern_unix_path(path: &[u8]) -> Option<&'static std::path::Path> {
    use std::os::unix::ffi::OsStrExt;
    let path = std::path::Path::new(std::ffi::OsStr::from_bytes(path));
    UNIX_PATHS.with(|paths| {
        let mut paths = paths.borrow_mut();
        if let Some(known) = paths.iter().find(|p| **p == path) {
            return Some(*known);
        }
        if paths.len() >= UNIX_PATHS_MAX {
            return None;
        }
        let leaked: &'static std::path::Path = Box::leak(path.to_path_buf().into_boxed_path());
        paths.push(leaked);
        Some(leaked)
    })
}

/// The 500 of a proxy handler with no upstream (#703), with nginx's alert.
#[cold]
#[inline(never)]
fn no_upstream_configuration(
    http: &'static PreparedHttp,
    loc: &MatchedLocation<'static>,
    req: &phase::RequestCtx<'_>,
    render_ctx_base: &RenderCtx<'_>,
    in_error_page: bool,
    preserved_www_authenticate: &[Vec<u8>],
) -> Response {
    crate::fs_resolve::note_failed_lookup_at(
        "no upstream configuration".to_string(),
        false,
        crate::config::ErrorLogLevel::Alert,
    );
    variable_url_failed(
        http,
        500,
        loc,
        req,
        render_ctx_base,
        in_error_page,
        preserved_www_authenticate,
    )
}

/// The 500 or 502 for a `proxy_pass` URL that can't be used, through the
/// location's `error_page` as nginx finalizes it.
#[cold]
fn variable_url_failed(
    http: &'static PreparedHttp,
    status: u16,
    loc: &MatchedLocation<'static>,
    req: &phase::RequestCtx<'_>,
    render_ctx_base: &RenderCtx<'_>,
    in_error_page: bool,
    preserved_www_authenticate: &[Vec<u8>],
) -> Response {
    let prebuilt = if status == 502 {
        &http.bad_gateway
    } else {
        &http.internal_error
    };
    let intercepted = maybe_intercept_error_page(
        Response::Prebuilt(prebuilt.pick(req.method)),
        loc.error_pages,
        req,
        render_ctx_base,
        in_error_page,
        loc.recursive_error_pages,
        loc.server_header,
    );
    let trailers_allowed =
        req.http_11 && !matches!(req.method, Method::Head) && loc.chunked_transfer_encoding;
    finalize_location_response(
        intercepted,
        loc.add_headers,
        loc.add_trailers,
        trailers_allowed,
        render_ctx_base,
        None,
        None,
        preserved_www_authenticate,
        loc.expires,
    )
}

/// The request's `proxy_bind` address (ngx_http_upstream_set_local): the
/// literal one, or the value rendered now. An empty value binds nothing;
/// one that isn't an address is logged and binds nothing either.
fn resolve_bind(
    bind: &'static super::PreparedBind,
    ctx: &RenderCtx<'_>,
) -> Option<crate::proxy::LocalBind> {
    let addr = match bind.addr {
        Some(addr) => addr,
        None => {
            let mut value = Vec::new();
            render_parts(bind.value, ctx, &mut value);
            if value.is_empty() {
                return None;
            }
            let parsed = std::str::from_utf8(&value)
                .ok()
                .and_then(crate::config::parse_bind_addr);
            let Some(addr) = parsed else {
                crate::fs_resolve::note_failed_lookup_at(
                    format!(
                        "invalid local address \"{}\"",
                        String::from_utf8_lossy(&value)
                    ),
                    false,
                    ErrorLogLevel::Error,
                );
                return None;
            };
            addr
        }
    };
    Some(crate::proxy::LocalBind {
        addr,
        transparent: bind.transparent,
    })
}

#[cfg(test)]
mod body_framed_tests {
    use super::body_framed;

    #[test]
    fn body_framing_is_found_by_its_header_names() {
        assert!(!body_framed(b""));
        assert!(!body_framed(b"Host: x\r\nX-A: 1\r\n"));
        assert!(body_framed(b"Host: x\r\nContent-Length: 0\r\n"));
        assert!(body_framed(b"content-length: 0\r\n"));
        assert!(body_framed(b"Host: x\r\nTRANSFER-ENCODING: chunked"));
        // Only the whole name before the colon counts.
        assert!(!body_framed(b"Content-Lengths: 0\r\nTransfer: x\r\n"));
        assert!(!body_framed(
            b"Content-Type: text/plain\r\nCookie: content-length:1\r\n"
        ));
    }
}

#[cfg(test)]
mod range_offset_tests {

    use super::range_too_far;

    /// ngx_http_upstream_cache_check_range's cases.
    #[test]
    fn ranges_past_the_offset() {
        assert!(!range_too_far(b"bytes=1-", 2));
        assert!(range_too_far(b"bytes=3-", 2));
        assert!(range_too_far(b"bytes=2-5", 2));
        assert!(range_too_far(b"bytes=-1", 2));
        assert!(range_too_far(b"bytes= -1", 2));
        assert!(!range_too_far(b"bytes=1-1,3-", 2));
        assert!(range_too_far(b"bytes=0-0", 0));
        assert!(!range_too_far(b"items=5-", 2));
        assert!(!range_too_far(b"bytes=", 2));
    }
}
