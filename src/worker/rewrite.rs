//! Rewrite-engine runtime: `run_rewrite_program`, `execute_rewrite_ops`,
//! and the guard / `if` / variable-render helpers they use. The IR comes
//! from `prepare::prepare_rewrite_ops`.

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

pub enum RewriteOutcome {
    Continue,
    /// The program ended on `break` (or `rewrite ... break`): the rest of
    /// the location's rewrite-module directives, including a top-level
    /// `return`, must not run.
    Break,
    Reroute,
    Respond(Response),
}

pub(crate) enum RewriteControl {
    Continue,
    Stop,
    Reroute,
    Respond(Response),
}

pub(crate) fn guard_file_test(kind: FileTestKind, path: &[u8]) -> bool {
    use std::os::unix::ffi::OsStrExt;

    let os_path = std::ffi::OsStr::from_bytes(path);
    match kind {
        FileTestKind::File => std::fs::metadata(std::path::Path::new(os_path))
            .map(|m| m.is_file())
            .unwrap_or(false),
        FileTestKind::Dir => std::fs::metadata(std::path::Path::new(os_path))
            .map(|m| m.is_dir())
            .unwrap_or(false),
        FileTestKind::Exists => std::fs::metadata(std::path::Path::new(os_path)).is_ok(),
        FileTestKind::Exec => {
            let Ok(cpath) = std::ffi::CString::new(path) else {
                return false;
            };
            unsafe { libc::access(cpath.as_ptr(), libc::X_OK) == 0 }
        }
    }
}

pub(crate) fn eval_guard(guard: &PreparedGuard, ctx: &RenderCtx<'_>) -> bool {
    match guard {
        PreparedGuard::VarTruthy(var) => {
            let rendered = render_variable_to_vec(var, ctx);
            condition_is_truthy(&rendered)
        }
        PreparedGuard::Eq { left, right } => {
            let left = render_variable_to_vec(left, ctx);
            let mut right_rendered = Vec::with_capacity(32);
            render_parts(right, ctx, &mut right_rendered);
            left == right_rendered
        }
        PreparedGuard::NotEq { left, right } => {
            let left = render_variable_to_vec(left, ctx);
            let mut right_rendered = Vec::with_capacity(32);
            render_parts(right, ctx, &mut right_rendered);
            left != right_rendered
        }
        PreparedGuard::Regex {
            left,
            regex,
            negated,
        } => {
            let left = render_variable_to_vec(left, ctx);
            let matched = regex.is_match(&left);
            if *negated { !matched } else { matched }
        }
        PreparedGuard::FileTest {
            kind,
            path,
            negated,
        } => {
            let mut rendered = Vec::with_capacity(64);
            render_parts(path, ctx, &mut rendered);
            let ok = guard_file_test(*kind, &rendered);
            if *negated { !ok } else { ok }
        }
    }
}

pub(crate) fn rewrite_target_is_external(rendered: &[u8]) -> bool {
    rendered.starts_with(b"http://") || rendered.starts_with(b"https://")
}

/// Build an absolute `Location:` URL from a relative path. Mirrors nginx's
/// `ngx_http_static_handler` directory-redirect behaviour with the default
/// `absolute_redirect on`: scheme + Host header (or primary server_name as
/// fallback) + listen port (omitted when it matches the scheme default) +
/// the path. The path is expected to be already in URL form.
pub(crate) fn build_absolute_redirect_location(
    path: &[u8],
    host: &[u8],
    port: u16,
    tls: bool,
) -> Vec<u8> {
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

pub(crate) fn escape_redirect_location(raw: &[u8]) -> Vec<u8> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = Vec::with_capacity(raw.len());
    for &b in raw {
        if b <= 0x20 || b >= 0x7f {
            out.push(b'%');
            out.push(HEX[(b >> 4) as usize]);
            out.push(HEX[(b & 0x0f) as usize]);
        } else {
            out.push(b);
        }
    }
    out
}

/// The request's `limit_rate` and `limit_rate_after` in bytes: `set
/// $limit_rate` if the rewrite program ran it, else the location's
/// directives, rendered (they may hold variables) and parsed as nginx
/// sizes; an invalid size is 0 (unlimited), as `ngx_http_complex_value_size`
/// falls back to its default.
#[allow(clippy::too_many_arguments)]
#[cold]
#[inline(never)]
pub(crate) fn evaluate_limit_rate(
    http: &'static PreparedHttp,
    server: &'static PreparedServer,
    req: &phase::RequestCtx<'_>,
    uri: &[u8],
    current_args: Option<&[u8]>,
    rewrite_state: &RewriteState,
    server_name_captures: Option<&phase::ServerNameCaptures>,
    limits: PreparedLimitRate,
) -> (u64, u64) {
    let args = current_args.unwrap_or_else(|| request_args(req.path));
    let captures_slice: &[(&'static str, Vec<u8>)] = match server_name_captures {
        Some(caps) => caps.names.as_slice(),
        None => &[],
    };
    let ctx = build_rewrite_ctx(http, server, req, uri, args, captures_slice, rewrite_state);
    let size = |parts: Option<&'static [PreparedValuePart]>| {
        parts.map_or(0, |parts| {
            let mut value = Vec::with_capacity(16);
            render_parts(parts, &ctx, &mut value);
            crate::config::parse_size(&value).unwrap_or(0)
        })
    };
    let rate = match rewrite_state.user_var("limit_rate") {
        Some(value) => crate::config::parse_size(value).unwrap_or(0),
        None => size(limits.rate),
    };
    (rate, size(limits.after))
}

pub(crate) fn build_rewrite_ctx<'a>(
    http: &'static PreparedHttp,
    server: &'static PreparedServer,
    req: &'a phase::RequestCtx<'a>,
    uri: &'a [u8],
    args: &'a [u8],
    captures_slice: &'a [(&'static str, Vec<u8>)],
    rewrite_state: &'a RewriteState,
) -> RenderCtx<'a> {
    RenderCtx {
        uri,
        request_uri: req.path,
        request_method: req.method_bytes,
        request_line: req.request_line,
        host: req.host.unwrap_or(b""),
        remote_addr: req.remote_addr,
        remote_port: req.remote_port,
        remote_user: b"",
        server_name: server.primary_server_name,
        status: 0,
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
        conn: req.conn,
    }
}

pub(crate) fn execute_rewrite_ops(
    ops: &'static [PreparedRewriteOp],
    http: &'static PreparedHttp,
    server: &'static PreparedServer,
    // `Server:` for a `return` response: the location's, or the server's
    // for the server-level program.
    server_header: &'static [u8],
    req: &phase::RequestCtx<'_>,
    uri_path: &mut Vec<u8>,
    current_args: &mut Option<Vec<u8>>,
    rewrite_state: &mut RewriteState,
    server_name_captures: Option<&phase::ServerNameCaptures>,
) -> RewriteControl {
    let request_uri = req.path;
    let captures_slice: &[(&'static str, Vec<u8>)] = match server_name_captures {
        Some(caps) => caps.names.as_slice(),
        None => &[],
    };

    for op in ops {
        match op {
            PreparedRewriteOp::Set { name, value } => {
                let args = current_args
                    .as_deref()
                    .unwrap_or_else(|| request_args(request_uri));
                let ctx = build_rewrite_ctx(
                    http,
                    server,
                    req,
                    uri_path.as_slice(),
                    args,
                    captures_slice,
                    rewrite_state,
                );
                let mut rendered = Vec::with_capacity(64);
                render_parts(value, &ctx, &mut rendered);
                rewrite_state.set_user_var(name, rendered);
            }
            PreparedRewriteOp::If { guard, body } => {
                let args = current_args
                    .as_deref()
                    .unwrap_or_else(|| request_args(request_uri));
                let ctx = build_rewrite_ctx(
                    http,
                    server,
                    req,
                    uri_path.as_slice(),
                    args,
                    captures_slice,
                    rewrite_state,
                );
                if eval_guard(guard, &ctx) {
                    match execute_rewrite_ops(
                        body,
                        http,
                        server,
                        server_header,
                        req,
                        uri_path,
                        current_args,
                        rewrite_state,
                        server_name_captures,
                    ) {
                        RewriteControl::Continue => {}
                        other => return other,
                    }
                }
            }
            PreparedRewriteOp::Rewrite {
                regex,
                replacement_uri,
                replacement_args,
                flag,
                drop_args,
            } => {
                let Some(captures) = regex.captures(uri_path.as_slice()) else {
                    continue;
                };
                rewrite_state.set_numbered_from_regex_captures(&captures, uri_path);

                let args = current_args
                    .as_deref()
                    .unwrap_or_else(|| request_args(request_uri));
                let ctx = build_rewrite_ctx(
                    http,
                    server,
                    req,
                    uri_path.as_slice(),
                    args,
                    captures_slice,
                    rewrite_state,
                );
                let mut new_uri = Vec::with_capacity(uri_path.len() + 32);
                render_parts(replacement_uri, &ctx, &mut new_uri);
                let mut new_args: Option<Vec<u8>> = replacement_args.map(|parts| {
                    let mut buf = Vec::with_capacity(32);
                    render_parts_with_arg_escape(parts, &ctx, &mut buf);
                    buf
                });

                let external_redirect = matches!(
                    flag,
                    PreparedRewriteFlag::Redirect | PreparedRewriteFlag::Permanent
                ) || matches!(flag, PreparedRewriteFlag::None)
                    && rewrite_target_is_external(&new_uri);

                if external_redirect {
                    let status = match flag {
                        PreparedRewriteFlag::Permanent => 301,
                        PreparedRewriteFlag::Redirect => 302,
                        _ => 302,
                    };
                    // Compose `uri[?args][&original_args]` for the
                    // Location target. Trailing `?` in the source
                    // (drop_args) suppresses original-args merging.
                    let mut rendered = new_uri;
                    if let Some(args_buf) = new_args.as_ref() {
                        rendered.push(b'?');
                        rendered.extend_from_slice(args_buf);
                    }
                    if !*drop_args && !args.is_empty() {
                        rendered.push(if rendered.contains(&b'?') { b'&' } else { b'?' });
                        rendered.extend_from_slice(args);
                    }
                    let location = escape_redirect_location(&rendered);
                    return RewriteControl::Respond(Response::Owned(
                        http::build_redirect_response(status, &location, req.method, server_header),
                    ));
                }

                if new_uri.is_empty() {
                    new_uri.push(b'/');
                }
                *uri_path = new_uri;
                // Internal rewrite: append the original request args to
                // the replacement-side args (separated by `&`) unless the
                // trailing `?` suppressed it. When the replacement had no
                // `?`, the original args carry over unchanged.
                if let Some(args_buf) = new_args.as_mut() {
                    if !*drop_args && !args.is_empty() {
                        args_buf.push(b'&');
                        args_buf.extend_from_slice(args);
                    }
                    *current_args = Some(std::mem::take(args_buf));
                } else if *drop_args {
                    *current_args = Some(Vec::new());
                }
                // nginx: a successful in-place rewrite (no `last`/external
                // redirect) clears `r->valid_location`, which `proxy_pass`
                // checks to decide whether to apply its configured URI
                // prefix substitution. Without this, a `rewrite ...; break;
                // proxy_pass http://up/PATH;` would still send `PATH` to
                // upstream — see nginx-tests/rewrite.t valid_location reset.
                rewrite_state.valid_location = false;
                match flag {
                    PreparedRewriteFlag::Last => return RewriteControl::Reroute,
                    PreparedRewriteFlag::Break => return RewriteControl::Stop,
                    PreparedRewriteFlag::None => {}
                    PreparedRewriteFlag::Redirect | PreparedRewriteFlag::Permanent => {}
                }
            }
            PreparedRewriteOp::Return(prepared) => {
                let args = current_args
                    .as_deref()
                    .unwrap_or_else(|| request_args(request_uri));
                let ctx = build_rewrite_ctx(
                    http,
                    server,
                    req,
                    uri_path.as_slice(),
                    args,
                    captures_slice,
                    rewrite_state,
                );
                let response = match prepared {
                    PreparedReturn::Static(prebuilt) => {
                        Response::Prebuilt(prebuilt.pick(req.method))
                    }
                    PreparedReturn::Template { status, parts } => Response::Owned(
                        build_templated_return(*status, parts, &ctx, req.method, server_header),
                    ),
                };
                return RewriteControl::Respond(response);
            }
            PreparedRewriteOp::Break => return RewriteControl::Stop,
        }
    }
    RewriteControl::Continue
}

/// The server-level rewrite program, nginx's SERVER_REWRITE phase: it
/// runs before the location is searched, so a server-level `return`
/// answers every request. `break` and `rewrite … last` end it; the
/// location search follows either way.
#[allow(clippy::too_many_arguments)]
pub(crate) fn run_server_rewrite(
    http: &'static PreparedHttp,
    server: &'static PreparedServer,
    req: &phase::RequestCtx<'_>,
    uri_path: &mut Vec<u8>,
    current_args: &mut Option<Vec<u8>>,
    rewrite_state: &mut RewriteState,
    server_name_captures: Option<&phase::ServerNameCaptures>,
) -> Option<Response> {
    match execute_rewrite_ops(
        server.rewrite_program,
        http,
        server,
        server.server_header,
        req,
        uri_path,
        current_args,
        rewrite_state,
        server_name_captures,
    ) {
        RewriteControl::Respond(response) => Some(response),
        RewriteControl::Continue | RewriteControl::Stop | RewriteControl::Reroute => None,
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn run_rewrite_program(
    http: &'static PreparedHttp,
    server: &'static PreparedServer,
    loc: MatchedLocation<'static>,
    req: &phase::RequestCtx<'_>,
    uri_path: &mut Vec<u8>,
    current_args: &mut Option<Vec<u8>>,
    rewrite_state: &mut RewriteState,
    server_name_captures: Option<&phase::ServerNameCaptures>,
) -> RewriteOutcome {
    if loc.rewrite_program.is_empty() {
        return RewriteOutcome::Continue;
    }
    match execute_rewrite_ops(
        loc.rewrite_program,
        http,
        server,
        loc.server_header,
        req,
        uri_path,
        current_args,
        rewrite_state,
        server_name_captures,
    ) {
        RewriteControl::Continue => RewriteOutcome::Continue,
        RewriteControl::Stop => RewriteOutcome::Break,
        RewriteControl::Reroute => RewriteOutcome::Reroute,
        RewriteControl::Respond(resp) => RewriteOutcome::Respond(resp),
    }
}
