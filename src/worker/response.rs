//! Response shaping: status-line rewriting, header injection (`add_header`,
//! `Connection`, `Last-Modified`), conditional / range short-circuits, and
//! the prebuilt-variant cache.

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
use crate::{autoindex, file, fs_resolve, http_date, uri};

use super::*;

pub(crate) fn is_redirect_status(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

pub(crate) fn is_redirect_return(status: u16, body: &[ValuePart]) -> bool {
    is_redirect_status(status) && !body.is_empty()
}

pub(crate) fn build_templated_return(
    status: u16,
    parts: &[PreparedValuePart],
    ctx: &RenderCtx<'_>,
    method: Method,
    server: &[u8],
) -> Vec<u8> {
    let mut body = Vec::with_capacity(64);
    render_parts(parts, ctx, &mut body);
    if is_redirect_status(status) && !body.is_empty() {
        http::build_redirect_response(status, &body, method, server)
    } else if matches!(method, Method::Head) {
        http::build_head_response(status, body.len(), server)
    } else {
        http::build_response_bytes(status, &body, server)
    }
}

/// Statuses that receive `add_header` without the `always` modifier —
/// matches nginx's `ngx_http_headers_filter_module.c` (2xx success,
/// 206 partial, and the 3xx redirect family).
pub(crate) fn add_header_status_eligible(status: u16) -> bool {
    matches!(
        status,
        200 | 201 | 204 | 206 | 301 | 302 | 303 | 304 | 307 | 308
    )
}

/// Render the effective `add_header Last-Modified ...` value that should
/// participate in static-file conditional checks (`If-Modified-Since`,
/// date-form `If-Range`). `None` means "no override directive"; an empty
/// vec means "explicitly suppressed".
pub(crate) fn last_modified_override_for_conditionals(
    headers: &[PreparedAddHeader],
    render_ctx_base: &RenderCtx<'_>,
) -> Option<Vec<u8>> {
    if headers.is_empty() {
        return None;
    }
    // For static-file conditionals, the response status family is 200/206/304;
    // plain `add_header` (without `always`) applies to all of them. We render
    // with status=200 so `$status`-dependent templates are deterministic.
    let ctx = RenderCtx {
        status: 200,
        ..*render_ctx_base
    };
    let mut out: Option<Vec<u8>> = None;
    for h in headers {
        if !h.name.eq_ignore_ascii_case(b"Last-Modified") {
            continue;
        }
        if !h.always && !add_header_status_eligible(ctx.status) {
            continue;
        }
        let mut rendered = Vec::with_capacity(64);
        render_parts(h.value, &ctx, &mut rendered);
        out = Some(rendered);
    }
    out
}

/// Extract a header value (trimmed of leading SP/HT) from response bytes.
/// Returns the first match, case-insensitive on the name. Used by
/// `error_page` interception to preserve `Location:` from a 3xx response
/// across an internal redirect.
pub(crate) fn response_header_value<'a>(response: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    let head_end = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or(response.len());
    let mut block = &response[..head_end];
    let line_end = block
        .windows(2)
        .position(|w| w == b"\r\n")
        .map(|i| i + 2)
        .unwrap_or(block.len());
    block = &block[line_end..];
    while !block.is_empty() {
        let rel_end = match block.windows(2).position(|w| w == b"\r\n") {
            Some(i) => i,
            None => block.len(),
        };
        let line = &block[..rel_end];
        if let Some(colon) = line.iter().position(|&b| b == b':')
            && line[..colon].eq_ignore_ascii_case(name)
        {
            let mut v = &line[colon + 1..];
            while let Some((&c, rest)) = v.split_first() {
                if c == b' ' || c == b'\t' {
                    v = rest;
                } else {
                    break;
                }
            }
            return Some(v);
        }
        let advance = (rel_end + 2).min(block.len());
        block = &block[advance..];
    }
    None
}

/// Extract every header value (trimmed of leading SP/HT) for `name` from
/// response bytes — multi-valued headers (`WWW-Authenticate`, `Set-Cookie`)
/// can appear multiple times. Used by `error_page` interception of a 401
/// to preserve all `WWW-Authenticate:` values across the internal redirect.
pub(crate) fn response_header_values_all(response: &[u8], name: &[u8]) -> Vec<Vec<u8>> {
    let mut values = Vec::new();
    let head_end = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or(response.len());
    let mut block = &response[..head_end];
    let line_end = block
        .windows(2)
        .position(|w| w == b"\r\n")
        .map(|i| i + 2)
        .unwrap_or(block.len());
    block = &block[line_end..];
    while !block.is_empty() {
        let rel_end = match block.windows(2).position(|w| w == b"\r\n") {
            Some(i) => i,
            None => block.len(),
        };
        let line = &block[..rel_end];
        if let Some(colon) = line.iter().position(|&b| b == b':')
            && line[..colon].eq_ignore_ascii_case(name)
        {
            let mut v = &line[colon + 1..];
            while let Some((&c, rest)) = v.split_first() {
                if c == b' ' || c == b'\t' {
                    v = rest;
                } else {
                    break;
                }
            }
            values.push(v.to_vec());
        }
        let advance = (rel_end + 2).min(block.len());
        block = &block[advance..];
    }
    values
}

pub(crate) fn response_status(bytes: &[u8]) -> u16 {
    if bytes.len() < 12 {
        return 0;
    }
    let d = &bytes[9..12];
    if !d.iter().all(|b| b.is_ascii_digit()) {
        return 0;
    }
    ((d[0] - b'0') as u16) * 100 + ((d[1] - b'0') as u16) * 10 + (d[2] - b'0') as u16
}

/// Drop any line in `block` whose header name matches `name` (case-
/// insensitive). The buffer is a sequence of `Name: Value\r\n` lines
/// without status line or body terminator — used when prior `add_header`
/// entries staged inside `insert` need to be stripped before a later
/// replacing-handler entry (ETag/Last-Modified).
pub(crate) fn strip_inserted_lines(block: Vec<u8>, name: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(block.len());
    let mut cursor = 0;
    while cursor < block.len() {
        let Some(rel_end) = block[cursor..].windows(2).position(|w| w == b"\r\n") else {
            out.extend_from_slice(&block[cursor..]);
            break;
        };
        let end = cursor + rel_end;
        let line = &block[cursor..end];
        let drop_line = line
            .iter()
            .position(|&b| b == b':')
            .is_some_and(|colon| line[..colon].eq_ignore_ascii_case(name));
        if !drop_line {
            out.extend_from_slice(line);
            out.extend_from_slice(b"\r\n");
        }
        cursor = end + 2;
    }
    out
}

pub(crate) fn strip_header_lines(response: Vec<u8>, name: &[u8]) -> Vec<u8> {
    let Some(sep) = response.windows(4).position(|w| w == b"\r\n\r\n") else {
        return response;
    };
    let Some(line_end) = response.windows(2).position(|w| w == b"\r\n") else {
        return response;
    };
    let mut out = Vec::with_capacity(response.len());
    out.extend_from_slice(&response[..line_end + 2]); // status line

    // Header lines run from the byte after the status line CRLF to the CRLF
    // immediately before the empty-line terminator at `sep`.
    let mut cursor = line_end + 2;
    while cursor < sep + 2 {
        let Some(rel_end) = response[cursor..].windows(2).position(|w| w == b"\r\n") else {
            return response;
        };
        let end = cursor + rel_end;
        let line = &response[cursor..end];
        let drop_line = line
            .iter()
            .position(|&b| b == b':')
            .is_some_and(|colon| line[..colon].eq_ignore_ascii_case(name));
        if !drop_line {
            out.extend_from_slice(line);
            out.extend_from_slice(b"\r\n");
        }
        cursor = end + 2;
    }

    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(&response[sep + 4..]);
    out
}

/// Insert rendered `add_header` lines between the final response header
/// CRLF and the blank line separator. Operates on fully-formed response
/// bytes so every response builder (file, return, redirect, error prebuilts)
/// gets the same treatment without touching its body-build code.
///
/// Semantics: we splice at the CRLF *before* the blank line, so every
/// existing header is preserved in order and the new headers trail them —
/// same as how nginx's header filter runs after the content handler has
/// populated `r->headers_out`.
pub(crate) fn inject_add_headers(
    mut response: Vec<u8>,
    headers: &[PreparedAddHeader],
    ctx: &RenderCtx<'_>,
) -> Vec<u8> {
    if headers.is_empty() {
        return response;
    }

    // Build the insertion bytes incrementally so each `add_header`'s
    // `$sent_http_*` lookup sees headers added by earlier directives in the
    // same location. Mirrors nginx's headers filter, where `r->headers_out`
    // is updated in-place as it walks the array.
    let mut insert = Vec::with_capacity(headers.len() * 64);
    let mut rewrite_last_modified = false;
    let mut rewrite_etag = false;
    let render_ctx = *ctx;
    // Effective response view used by `$sent_http_*`: starts as the base
    // response and grows as we render each `add_header`. We insert at the
    // same `\r\n\r\n` boundary at the end, so the view we expose to the
    // renderer must drop the trailing empty-line CRLF and instead end with
    // the most recently appended header's CRLF (so the value-scanner finds
    // it on the line walk).
    let sep_pos = response.windows(4).position(|w| w == b"\r\n\r\n");
    let mut sent_view: Vec<u8> = match sep_pos {
        // Keep the trailing `\r\n` of the last existing header so the
        // scanner's "split on `\n`" loop yields it; trim only the empty
        // line that ends the headers section.
        Some(p) => response[..p + 2].to_vec(),
        None => response.clone(),
    };
    for h in headers {
        if !h.always && !add_header_status_eligible(render_ctx.status) {
            continue;
        }
        let is_last_modified = h.name.eq_ignore_ascii_case(b"Last-Modified");
        let is_etag = h.name.eq_ignore_ascii_case(b"ETag");
        if is_last_modified {
            // nginx has a special-case here: `add_header Last-Modified ...`
            // overrides/suppresses the builtin static-file Last-Modified
            // header instead of creating duplicates.
            rewrite_last_modified = true;
        }
        if is_etag {
            // nginx's `ngx_http_set_response_header` for ETag replaces (not
            // appends). An empty value removes the header outright.
            rewrite_etag = true;
        }

        // Re-borrow `sent_view` afresh on each iteration; we need to mutate
        // it after rendering, which would otherwise overlap.
        let mut rendered = Vec::with_capacity(64);
        {
            let mut local_ctx = render_ctx;
            local_ctx.sent_headers = sent_view.as_slice();
            render_parts(h.value, &local_ctx, &mut rendered);
        }
        if is_last_modified && rendered.is_empty() {
            // Explicit empty value means "suppress Last-Modified entirely".
            continue;
        }
        if is_etag {
            // Replace-or-clear semantics: drop any prior ETag from both
            // the staged insert buffer and the visible-headers view.
            insert = strip_inserted_lines(insert, b"ETag");
            sent_view = strip_header_lines(sent_view, b"ETag");
        }
        if is_etag && rendered.is_empty() {
            continue;
        }
        // nginx's headers filter (`ngx_http_headers_filter_module.c::
        // ngx_http_add_header`) skips entries whose rendered value is
        // empty — emitting `X-Foo: \r\n` is a wire-level oddity and
        // multiple test cases (e.g. http_request_port.t with
        // `add_header X-Port $is_request_port$request_port;`) rely on
        // the empty header just disappearing when the variable is empty.
        if rendered.is_empty() {
            continue;
        }

        insert.extend_from_slice(h.name);
        insert.extend_from_slice(b": ");
        insert.extend_from_slice(&rendered);
        insert.extend_from_slice(b"\r\n");
        // Mirror the same line into `sent_view` so subsequent
        // `$sent_http_*` lookups can see it.
        sent_view.extend_from_slice(h.name);
        sent_view.extend_from_slice(b": ");
        sent_view.extend_from_slice(&rendered);
        sent_view.extend_from_slice(b"\r\n");
    }
    if rewrite_last_modified {
        response = strip_header_lines(response, b"Last-Modified");
    }
    if rewrite_etag {
        response = strip_header_lines(response, b"ETag");
    }
    if insert.is_empty() {
        return response;
    }
    let Some(sep) = response.windows(4).position(|w| w == b"\r\n\r\n") else {
        // Not a well-formed response; leave it alone rather than corrupt it.
        return response;
    };

    // `sep` points at the first byte of `\r\n\r\n`. Split point is `sep + 2`:
    // that's immediately after the last header's closing CRLF, before the
    // empty-line CRLF that ends the header section.
    let split = sep + 2;
    let mut out = Vec::with_capacity(response.len() + insert.len());
    out.extend_from_slice(&response[..split]);
    out.extend_from_slice(&insert);
    out.extend_from_slice(&response[split..]);
    out
}

/// Status codes for which the headers filter applies `expires` (and only
/// `add_header` entries without `always`). Mirrors the safe-status switch
/// in `ngx_http_headers_filter` (200, 201, 204, 206, 301, 302, 303, 304,
/// 307, 308).
pub(crate) fn is_safe_status_for_expires_pub(status: u16) -> bool {
    is_safe_status_for_expires(status)
}

fn is_safe_status_for_expires(status: u16) -> bool {
    matches!(
        status,
        200 | 201 | 204 | 206 | 301 | 302 | 303 | 304 | 307 | 308
    )
}

fn read_last_modified_time(response: &[u8]) -> Option<i64> {
    let value = scan_response_header_value(response, b"Last-Modified")?;
    let secs = crate::file::parse_http_date(value)?;
    Some(secs as i64)
}

fn scan_response_header_value<'a>(response: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    let sep = response.windows(4).position(|w| w == b"\r\n\r\n")?;
    let line_end = response.windows(2).position(|w| w == b"\r\n")?;
    let mut cursor = line_end + 2;
    while cursor < sep + 2 {
        let rel_end = response[cursor..].windows(2).position(|w| w == b"\r\n")?;
        let end = cursor + rel_end;
        let line = &response[cursor..end];
        if let Some(colon) = line.iter().position(|&b| b == b':') {
            if line[..colon].eq_ignore_ascii_case(name) {
                let mut value = &line[colon + 1..];
                while let [b' ' | b'\t', rest @ ..] = value {
                    value = rest;
                }
                return Some(value);
            }
        }
        cursor = end + 2;
    }
    None
}

/// Apply the location's `expires` directive to a response. Replaces any
/// existing `Expires` and `Cache-Control` headers; emits no headers when
/// `expires` is `Off` or the response status is not eligible. Mirrors
/// `ngx_http_set_expires` in semantics, with the `Variable` variants
/// re-parsed at request time via `parse_expires_static`.
pub(crate) fn apply_expires(
    response: Vec<u8>,
    expires: PreparedExpires,
    ctx: &RenderCtx<'_>,
) -> Vec<u8> {
    let status = response_status(&response);
    if !is_safe_status_for_expires(status) {
        return response;
    }
    let directive = match expires {
        PreparedExpires::Off => return response,
        PreparedExpires::Epoch => crate::config::ExpiresDirective::Epoch,
        PreparedExpires::Max => crate::config::ExpiresDirective::Max,
        PreparedExpires::Access(s) => crate::config::ExpiresDirective::Access(s),
        PreparedExpires::Modified(s) => crate::config::ExpiresDirective::Modified(s),
        PreparedExpires::Daily(s) => crate::config::ExpiresDirective::Daily(s),
        PreparedExpires::Variable(parts) | PreparedExpires::VariableModified(parts) => {
            let modified = matches!(expires, PreparedExpires::VariableModified(_));
            let mut buf = Vec::with_capacity(32);
            render_parts(parts, ctx, &mut buf);
            let s = match std::str::from_utf8(&buf) {
                Ok(v) => v,
                Err(_) => return response,
            };
            // nginx silently keeps the response as-is when the runtime
            // value fails to parse (`rc != NGX_OK` returns NGX_OK from
            // ngx_http_set_expires without emitting headers).
            match crate::config::parse_expires_static(s, modified) {
                Ok(d) => d,
                Err(_) => return response,
            }
        }
    };
    if matches!(directive, crate::config::ExpiresDirective::Off) {
        return response;
    }
    let last_modified = read_last_modified_time(&response);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let (expires_value, cache_control) = compute_expires_headers(&directive, now, last_modified);
    let stripped = strip_header_lines(response, b"Expires");
    let stripped = strip_header_lines(stripped, b"Cache-Control");
    insert_headers(
        stripped,
        &[
            (b"Expires", &expires_value),
            (b"Cache-Control", &cache_control),
        ],
    )
}

/// Computes the `Expires` value and `Cache-Control` value for an
/// `expires` directive. `now` is the current epoch second; `last_modified`
/// is the Last-Modified epoch second from the response, or `None` when the
/// response has no Last-Modified header.
fn compute_expires_headers(
    directive: &crate::config::ExpiresDirective,
    now: i64,
    last_modified: Option<i64>,
) -> (Vec<u8>, Vec<u8>) {
    use crate::config::ExpiresDirective;
    match directive {
        ExpiresDirective::Off => (Vec::new(), Vec::new()),
        ExpiresDirective::Epoch => (
            b"Thu, 01 Jan 1970 00:00:01 GMT".to_vec(),
            b"no-cache".to_vec(),
        ),
        ExpiresDirective::Max => (
            b"Thu, 31 Dec 2037 23:55:55 GMT".to_vec(),
            b"max-age=315360000".to_vec(),
        ),
        ExpiresDirective::Daily(secs_of_day) => {
            let expires_time = next_daily_time(now, *secs_of_day);
            let max_age = expires_time - now;
            let expires_str = format_http_date_clamped(expires_time);
            if max_age < 0 {
                (expires_str, b"no-cache".to_vec())
            } else {
                (expires_str, format!("max-age={}", max_age).into_bytes())
            }
        }
        ExpiresDirective::Access(secs) | ExpiresDirective::Modified(secs) => {
            let modified = matches!(directive, ExpiresDirective::Modified(_));
            // nginx's headers filter clamps the rendered `Expires:` line at
            // exactly 29 bytes (sizeof IMF-fixdate string). For `expires_time
            // == 0` and not Daily, render today's HTTP-date. We follow the
            // same rule.
            if *secs == 0 {
                let expires_str = format_http_date_clamped(now);
                return (expires_str, b"max-age=0".to_vec());
            }
            let (expires_time, max_age) = if modified {
                match last_modified {
                    Some(lm) => {
                        let et = lm + *secs;
                        (et, et - now)
                    }
                    // No Last-Modified — fall back to access semantics
                    // (matches nginx: when last_modified_time == -1).
                    None => (now + *secs, *secs),
                }
            } else {
                (now + *secs, *secs)
            };
            let expires_str = format_http_date_clamped(expires_time);
            // nginx's `conf->expires_time < 0 || max_age < 0` test: if the
            // configured offset is negative OR the resulting max_age is
            // negative, emit `no-cache`.
            if *secs < 0 || max_age < 0 {
                (expires_str, b"no-cache".to_vec())
            } else {
                (expires_str, format!("max-age={}", max_age).into_bytes())
            }
        }
        ExpiresDirective::Variable(_) | ExpiresDirective::VariableModified(_) => {
            // Resolved by caller; should not reach here.
            (Vec::new(), Vec::new())
        }
    }
}

fn format_http_date_clamped(secs: i64) -> Vec<u8> {
    let s = if secs < 0 { 0u64 } else { secs as u64 };
    crate::file::format_http_date(s).to_vec()
}

/// nginx's `ngx_next_time(when)` computed in **local** time: walk to the
/// next epoch second whose local time-of-day equals `when_secs_of_day`.
fn next_daily_time(now: i64, when_secs_of_day: u32) -> i64 {
    unsafe {
        let mut tm: libc::tm = std::mem::zeroed();
        let now_t = now as libc::time_t;
        libc::localtime_r(&now_t, &mut tm);
        tm.tm_hour = (when_secs_of_day / 3600) as i32;
        let rem = when_secs_of_day % 3600;
        tm.tm_min = (rem / 60) as i32;
        tm.tm_sec = (rem % 60) as i32;
        tm.tm_isdst = -1;
        let next = libc::mktime(&mut tm);
        if next == -1 {
            return now;
        }
        if next - now_t > 0 {
            return next as i64;
        }
        tm.tm_mday += 1;
        tm.tm_isdst = -1;
        let next2 = libc::mktime(&mut tm);
        if next2 == -1 {
            return now;
        }
        next2 as i64
    }
}

fn insert_headers(mut response: Vec<u8>, headers: &[(&[u8], &[u8])]) -> Vec<u8> {
    let Some(sep) = response.windows(4).position(|w| w == b"\r\n\r\n") else {
        return response;
    };
    let split = sep + 2;
    let mut insert = Vec::with_capacity(headers.len() * 64);
    for (name, value) in headers {
        insert.extend_from_slice(name);
        insert.extend_from_slice(b": ");
        insert.extend_from_slice(value);
        insert.extend_from_slice(b"\r\n");
    }
    let tail = response.split_off(split);
    response.extend_from_slice(&insert);
    response.extend_from_slice(&tail);
    response
}

pub(crate) fn should_apply_error_page_status(base_status: u16) -> bool {
    (200..300).contains(&base_status) || base_status == 304
}

pub(crate) fn effective_error_page_status(
    base_status: u16,
    forced: Option<phase::ErrorPageStatus>,
) -> u16 {
    if !should_apply_error_page_status(base_status) {
        return base_status;
    }
    match forced {
        Some(phase::ErrorPageStatus::Preserve(status))
        | Some(phase::ErrorPageStatus::Override(status)) => status,
        None => base_status,
    }
}

pub(crate) fn status_reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        206 => "Partial Content",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Not Allowed",
        410 => "Gone",
        416 => "Range Not Satisfiable",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "OK",
    }
}

pub(crate) fn rewrite_response_status(response: Vec<u8>, status: u16) -> Vec<u8> {
    let Some(line_end) = response.windows(2).position(|w| w == b"\r\n") else {
        return response;
    };
    let mut out = Vec::with_capacity(response.len() + 16);
    out.extend_from_slice(b"HTTP/1.1 ");
    write_u16_decimal(&mut out, status);
    out.push(b' ');
    out.extend_from_slice(status_reason(status).as_bytes());
    out.extend_from_slice(&response[line_end..]);
    out
}

/// Apply the proxy location's `add_header` and `add_trailer` directives to
/// an upstream response. Both `$upstream_http_*` / `$upstream_cookie_*` and
/// `$upstream_response_length` resolve against the materialized upstream
/// response. Bypasses non-`Owned` variants because the proxy response path
/// always materializes an `Owned` buffer (or a 502/504 prebuilt that has no
/// add_header context to apply).
pub(crate) fn apply_proxy_add_headers(
    response: Response,
    http: &'static PreparedHttp,
    ctx: &phase::RequestCtx<'_>,
    meta: &phase::ProcessMeta,
    upstream_headers: &[u8],
) -> Response {
    let needs_expires = !matches!(meta.proxy_expires, PreparedExpires::Off);
    if meta.proxy_add_headers.is_empty() && meta.proxy_add_trailers.is_empty() && !needs_expires {
        return response;
    }
    let bytes = match response {
        Response::Owned(bytes) => bytes,
        // A 502/504 the proxy produced itself: `add_header ... always`
        // applies to it too.
        Response::Prebuilt(bytes) => bytes.to_vec(),
        other => return other,
    };
    // `$upstream_http_*` read the upstream's own header lines, which still
    // include the ones hidden from the client (Server, Date, X-Accel-*).
    let render_ctx = proxy_render_ctx(http, ctx, meta, response_status(&bytes), upstream_headers);
    let mut out = bytes;
    if needs_expires {
        out = apply_expires(out, meta.proxy_expires, &render_ctx);
    }
    out = inject_add_headers(out, meta.proxy_add_headers, &render_ctx);
    let trailers_allowed = ctx.http_11
        && !matches!(ctx.method, crate::http::Method::Head)
        && meta.proxy_chunked_transfer_encoding;
    if trailers_allowed {
        // Refresh `$msec` / `$time_local` / `$time_iso8601` to wall-clock-now
        // for the trailer block. Trailers are emitted after the upstream body
        // has finished arriving, which under `proxy_limit_rate` can lag the
        // request-start epoch by seconds; nginx's variable cache likewise
        // advances across that gap. Headers keep the request-start epoch via
        // the outer `render_ctx`, so a `$msec` rendered into both `add_header`
        // and `add_trailer` reflects the time difference.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let render_ctx = RenderCtx {
            status: response_status(&out),
            epoch_secs: now.as_secs(),
            epoch_ms: (now.subsec_millis()) as u16,
            ..render_ctx
        };
        out = inject_add_trailers(out, meta.proxy_add_trailers, &render_ctx);
    }
    Response::Owned(out)
}

/// A 502/504 the proxy produced itself (every attempt failed) goes through
/// the location's `error_page`, as nginx's special response handler does;
/// `proxy_intercept_errors` is only about responses from the upstream.
pub(crate) fn intercept_proxy_error(
    response: Response,
    error_pages: &[PreparedErrorPage],
    recursive: bool,
    http: &'static PreparedHttp,
    ctx: &phase::RequestCtx<'_>,
    meta: &phase::ProcessMeta,
    server: &'static [u8],
) -> Response {
    if error_pages.is_empty() {
        return response;
    }
    let Response::Prebuilt(bytes) = response else {
        return response;
    };
    let render_ctx = proxy_render_ctx(http, ctx, meta, response_status(bytes), &[]);
    maybe_intercept_error_page(
        Response::Prebuilt(bytes),
        error_pages,
        ctx,
        &render_ctx,
        false,
        recursive,
        server,
    )
}

/// The variable context for rendering against a proxied response
/// (`add_header`, `proxy_redirect`).
fn proxy_render_ctx<'a>(
    http: &'static PreparedHttp,
    ctx: &'a phase::RequestCtx<'a>,
    meta: &'a phase::ProcessMeta,
    status: u16,
    upstream_headers: &'a [u8],
) -> RenderCtx<'a> {
    let request_uri = ctx.path;
    let args = request_args(request_uri);
    let uri = request_uri
        .iter()
        .position(|&b| b == b'?')
        .map(|i| &request_uri[..i])
        .unwrap_or(request_uri);
    RenderCtx {
        uri,
        request_uri,
        request_method: ctx.method_bytes,
        request_line: ctx.request_line,
        host: ctx.host.unwrap_or(b""),
        remote_addr: ctx.remote_addr,
        remote_port: ctx.remote_port,
        remote_user: b"",
        server_name: meta.server_name,
        status,
        args,
        is_args: if args.is_empty() { b"" } else { b"?" },
        scheme: if ctx.tls.is_some() { b"https" } else { b"http" },
        hostname: hostname(),
        headers_raw: ctx.headers_raw,
        underscores_in_headers: meta.underscores_in_headers,
        // `inject_add_headers` re-derives the sent-headers view from its
        // `response` argument and overwrites `render_ctx.sent_headers`
        // per-iteration, so the placeholder we pass here is unused.
        sent_headers: &[],
        connection_id: ctx.connection_id,
        connection_requests: ctx.connection_requests,
        connection_time_us: ctx.connection_time_us,
        request_time_us: ctx.request_time_us,
        server_port: meta.server_port,
        request_port: ctx.request_port,
        pipe: ctx.pipe,
        request_length: ctx.request_length,
        request_body: ctx.body,
        request_body_file: ctx.body_file,
        bytes_sent: 0,
        body_bytes_sent: 0,
        epoch_secs: ctx.epoch_secs,
        epoch_ms: ctx.epoch_ms,
        server_name_captures: &[],
        rewrite_state: meta.rewrite_state.as_deref(),
        split_clients: Some(&http.split_clients),
        maps: Some(&http.maps),
        proxy_host: meta.proxy_host,
        upstream_headers,
        upstream_states: &meta.upstream_states,
        sent_trailers: &[],
        tls: ctx.tls,
        proxy_protocol: ctx.proxy_protocol,
    }
}

/// A response produced at the server level, before any location: a
/// refused request (bad Host, Transfer-Encoding, TRACE) or the server
/// rewrite program's `return`. nginx's special response handler and
/// header filter run with the server's configuration then: its
/// `error_page` (a match becomes a `Reroute`), else its `add_header`s.
pub(crate) fn finish_server_response(
    http: &'static PreparedHttp,
    req: &phase::RequestCtx<'_>,
    server: &'static PreparedServer,
    response: Response,
    in_error_page: bool,
) -> Response {
    if server.error_pages.is_empty() && server.add_headers.is_empty() {
        return response;
    }
    let request_uri = req.path;
    let args = request_args(request_uri);
    let uri = request_uri
        .iter()
        .position(|&b| b == b'?')
        .map(|i| &request_uri[..i])
        .unwrap_or(request_uri);
    let ctx = RenderCtx {
        uri,
        request_uri,
        request_method: req.method_bytes,
        request_line: req.request_line,
        host: req.host.unwrap_or(server.primary_server_name),
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
        request_body_file: req.body_file,
        bytes_sent: 0,
        body_bytes_sent: 0,
        epoch_secs: req.epoch_secs,
        epoch_ms: req.epoch_ms,
        server_name_captures: &[],
        rewrite_state: None,
        split_clients: Some(&http.split_clients),
        maps: Some(&http.maps),
        proxy_host: &[],
        upstream_headers: &[],
        upstream_states: req.upstream_states,
        sent_trailers: &[],
        tls: req.tls,
        proxy_protocol: req.proxy_protocol,
    };
    let response = maybe_intercept_error_page(
        response,
        server.error_pages,
        req,
        &ctx,
        in_error_page,
        false,
        server.server_header,
    );
    if server.add_headers.is_empty() {
        return response;
    }
    let bytes = match response {
        Response::Owned(bytes) => bytes,
        Response::Prebuilt(bytes) => bytes.to_vec(),
        other => return other,
    };
    let ctx = RenderCtx {
        status: response_status(&bytes),
        ..ctx
    };
    Response::Owned(inject_add_headers(bytes, server.add_headers, &ctx))
}

/// `proxy_redirect`: rewrite the proxied response's `Location` and
/// `Refresh` (after `url=`) headers with the first matching rule, as
/// ngx_http_proxy_rewrite_redirect does. A prefix rule replaces the
/// matched prefix; a regex rule replaces the whole value. A rewritten
/// `Location` that ends up relative is made absolute with this request's
/// scheme, host and port, as nginx's header filter does with
/// `absolute_redirect on`.
pub(crate) fn rewrite_proxy_redirects(
    response: Response,
    rules: &[PreparedRedirect],
    http: &'static PreparedHttp,
    ctx: &phase::RequestCtx<'_>,
    meta: &phase::ProcessMeta,
    upstream_headers: &[u8],
) -> Response {
    let Response::Owned(bytes) = response else {
        return response;
    };
    let Some(head_end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") else {
        return Response::Owned(bytes);
    };
    let render_ctx = proxy_render_ctx(http, ctx, meta, response_status(&bytes), upstream_headers);

    let mut out = Vec::with_capacity(bytes.len() + 64);
    let mut changed = false;
    let mut lines = bytes[..head_end]
        .split(|&b| b == b'\n')
        .map(|l| l.strip_suffix(b"\r").unwrap_or(l));
    if let Some(status_line) = lines.next() {
        out.extend_from_slice(status_line);
    }
    for line in lines {
        out.extend_from_slice(b"\r\n");
        let rewritten = line.iter().position(|&b| b == b':').and_then(|colon| {
            let name = line[..colon].trim_ascii();
            let value = line[colon + 1..].trim_ascii();
            let is_location = name.eq_ignore_ascii_case(b"location");
            let prefix = if is_location {
                0
            } else if name.eq_ignore_ascii_case(b"refresh") {
                find_ascii_ci(value, b"url=")? + 4
            } else {
                return None;
            };
            let mut new = apply_redirect_rules(rules, value, prefix, &render_ctx)?;
            if is_location && new.first() == Some(&b'/') {
                new = build_absolute_redirect_location(
                    &new,
                    ctx.host.unwrap_or(meta.server_name),
                    meta.server_port,
                    ctx.tls.is_some(),
                );
            }
            let mut line_out = line[..colon + 1].to_vec();
            line_out.push(b' ');
            line_out.extend_from_slice(&new);
            Some(line_out)
        });
        match rewritten {
            Some(new_line) => {
                out.extend_from_slice(&new_line);
                changed = true;
            }
            None => out.extend_from_slice(line),
        }
    }
    if !changed {
        return Response::Owned(bytes);
    }
    out.extend_from_slice(&bytes[head_end..]);
    Response::Owned(out)
}

/// The first rule that matches `value[prefix..]`, applied; `None` if none
/// does (the header is left as the upstream sent it).
fn apply_redirect_rules(
    rules: &[PreparedRedirect],
    value: &[u8],
    prefix: usize,
    render_ctx: &RenderCtx<'_>,
) -> Option<Vec<u8>> {
    let tail = &value[prefix..];
    for rule in rules {
        match rule {
            PreparedRedirect::Prefix {
                pattern,
                replacement,
            } => {
                let mut pat = Vec::new();
                render_parts(pattern, render_ctx, &mut pat);
                if !tail.starts_with(&pat) {
                    continue;
                }
                let mut new = value[..prefix].to_vec();
                render_parts(replacement, render_ctx, &mut new);
                new.extend_from_slice(&tail[pat.len()..]);
                return Some(new);
            }
            PreparedRedirect::Regex { regex, replacement } => {
                let Some(captures) = regex.captures(tail) else {
                    continue;
                };
                let mut state = RewriteState::default();
                state.set_numbered_from_regex_captures(&captures, tail);
                let ctx = RenderCtx {
                    rewrite_state: Some(&state),
                    ..*render_ctx
                };
                let mut new = value[..prefix].to_vec();
                render_parts(replacement, &ctx, &mut new);
                return Some(new);
            }
        }
    }
    None
}

fn find_ascii_ci(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|w| w.eq_ignore_ascii_case(needle))
}

/// Whether the response status family permits a chunked-encoded body. nginx's
/// chunked filter (`ngx_http_chunked_filter_module.c::ngx_http_chunked_header_filter`)
/// skips chunking for 1xx/204/304 — those status families either forbid a
/// body outright or use a closed-connection signal instead. With no chunked
/// frame there's no place to append trailers, so the trailer filter
/// short-circuits on the same set.
pub(crate) fn chunked_status_eligible(status: u16) -> bool {
    !(status < 200 || status == 204 || status == 304)
}

/// Apply `add_trailer` directives to a response: switch the response to
/// chunked transfer-encoding and append the rendered trailers after the
/// final `0\r\n` chunk. `$sent_trailer_*` references in trailer values
/// resolve against the trailer block built so far (mirroring how
/// `$sent_http_*` works for `add_header`); `$sent_http_*` references see
/// the response headers as written by the upstream/handler.
///
/// nginx does not advertise the trailer names with a `Trailer:` response
/// header (chunked_filter_module just appends the rendered block after the
/// final chunk), so neither do we.
pub(crate) fn inject_add_trailers(
    response: Vec<u8>,
    trailers: &[PreparedAddHeader],
    ctx: &RenderCtx<'_>,
) -> Vec<u8> {
    if trailers.is_empty() || !chunked_status_eligible(ctx.status) {
        return response;
    }
    // Build the `sent_headers` view from the actual response so
    // `$sent_http_*` lookups inside trailer values can see the headers the
    // handler/upstream emitted (matches nginx's trailer filter, where
    // `r->headers_out` is fully populated by the time trailers are rendered).
    let sep_pos = response.windows(4).position(|w| w == b"\r\n\r\n");
    let sent_view: &[u8] = match sep_pos {
        Some(p) => &response[..p + 2],
        None => &response[..],
    };

    // Render each trailer's value, building the trailer block incrementally
    // so subsequent `$sent_trailer_*` lookups can see prior entries. Skip
    // entries with empty rendered values (matches `add_header`).
    let mut trailer_block: Vec<u8> = Vec::with_capacity(trailers.len() * 64);
    for t in trailers {
        if !t.always && !add_header_status_eligible(ctx.status) {
            continue;
        }
        let mut rendered = Vec::with_capacity(64);
        {
            let mut local_ctx = *ctx;
            local_ctx.sent_headers = sent_view;
            local_ctx.sent_trailers = trailer_block.as_slice();
            render_parts(t.value, &local_ctx, &mut rendered);
        }
        if rendered.is_empty() {
            continue;
        }
        trailer_block.extend_from_slice(t.name);
        trailer_block.extend_from_slice(b": ");
        trailer_block.extend_from_slice(&rendered);
        trailer_block.extend_from_slice(b"\r\n");
    }
    if trailer_block.is_empty() {
        return response;
    }

    // Split status line + headers vs body. Without a well-formed split we
    // can't safely chunked-rewrite, so leave the response untouched.
    let Some(sep) = response.windows(4).position(|w| w == b"\r\n\r\n") else {
        return response;
    };
    let body_start = sep + 4;
    let body = response[body_start..].to_vec();

    // Drop the existing `Content-Length:` line and inject
    // `Transfer-Encoding: chunked` immediately before the empty-line
    // terminator. `strip_header_lines` preserves the rest of the headers
    // and keeps the trailing `\r\n\r\n` boundary.
    let stripped = strip_header_lines(response, b"Content-Length");
    let Some(sep2) = stripped.windows(4).position(|w| w == b"\r\n\r\n") else {
        return stripped;
    };
    let split = sep2 + 2;

    let header_inject: &[u8] = b"Transfer-Encoding: chunked\r\n";

    let chunked_body = build_single_chunk_body(&body);

    let mut out = Vec::with_capacity(
        stripped.len() + header_inject.len() + chunked_body.len() + trailer_block.len() + 16,
    );
    out.extend_from_slice(&stripped[..split]);
    out.extend_from_slice(header_inject);
    out.extend_from_slice(&stripped[split..sep2 + 4]);
    out.extend_from_slice(&chunked_body);
    out.extend_from_slice(b"0\r\n");
    out.extend_from_slice(&trailer_block);
    out.extend_from_slice(b"\r\n");
    out
}

/// Wrap a body buffer as a single chunked-transfer chunk (`<hex-len>\r\n
/// <body>\r\n`). Empty body yields an empty buffer — caller emits the
/// final `0\r\n` separately, so no zero-length chunk is needed before it.
pub(crate) fn build_single_chunk_body(body: &[u8]) -> Vec<u8> {
    if body.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(body.len() + 16);
    let hex = format!("{:x}", body.len());
    out.extend_from_slice(hex.as_bytes());
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body);
    out.extend_from_slice(b"\r\n");
    out
}

/// Inject a `Location:` header into a response, but only if it doesn't
/// already carry one. Used when an `error_page` intercept of a 3xx
/// preserves the original handler's Location across the internal
/// redirect — nginx semantics: `r->headers_out.location` survives the
/// redirect and gets overwritten only if the new handler sets its own.
pub(crate) fn replace_location_header(response: Vec<u8>, value: &[u8]) -> Vec<u8> {
    if response_header_value(&response, b"location").is_some() {
        return response;
    }
    let Some(sep) = response.windows(4).position(|w| w == b"\r\n\r\n") else {
        return response;
    };
    let mut out = Vec::with_capacity(response.len() + 16 + value.len());
    out.extend_from_slice(&response[..sep + 2]);
    out.extend_from_slice(b"Location: ");
    out.extend_from_slice(value);
    out.extend_from_slice(b"\r\n\r\n");
    out.extend_from_slice(&response[sep + 4..]);
    out
}

/// Append one or more `WWW-Authenticate:` header lines to a response.
/// Used when an `error_page` intercepts a 401 — nginx preserves
/// `r->headers_out.www_authenticate` across the internal redirect so the
/// client still sees the challenge from the original handler/upstream.
/// Skipped if the response already carries any `WWW-Authenticate:` header
/// (the new handler set its own challenge).
pub(crate) fn inject_www_authenticate_headers(response: Vec<u8>, values: &[Vec<u8>]) -> Vec<u8> {
    if values.is_empty() {
        return response;
    }
    if response_header_value(&response, b"www-authenticate").is_some() {
        return response;
    }
    let Some(sep) = response.windows(4).position(|w| w == b"\r\n\r\n") else {
        return response;
    };
    let extra: usize = values.iter().map(|v| v.len() + 22).sum();
    let mut out = Vec::with_capacity(response.len() + extra);
    out.extend_from_slice(&response[..sep + 2]);
    for v in values {
        out.extend_from_slice(b"WWW-Authenticate: ");
        out.extend_from_slice(v);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(&response[sep + 4..]);
    out
}

pub(crate) fn render_error_page_target(
    parts: &[PreparedValuePart],
    ctx: &RenderCtx<'_>,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    render_parts(parts, ctx, &mut out);
    out
}

pub(crate) fn split_target_uri_and_args(target: Vec<u8>) -> (Vec<u8>, Option<Vec<u8>>) {
    match target.iter().position(|&b| b == b'?') {
        Some(i) => (target[..i].to_vec(), Some(target[i + 1..].to_vec())),
        None => (target, None),
    }
}

pub(crate) fn external_error_page_status(action: PreparedErrorPageAction) -> u16 {
    match action {
        PreparedErrorPageAction::Override(code) if is_redirect_status(code) => code,
        _ => 302,
    }
}

pub(crate) fn maybe_intercept_error_page(
    response: Response,
    error_pages: &[PreparedErrorPage],
    req: &phase::RequestCtx<'_>,
    render_ctx_base: &RenderCtx<'_>,
    in_error_page: bool,
    // The location's `recursive_error_pages`: taking this error page
    // doesn't stop a later one (nginx leaves `r->error_page` unset).
    recursive: bool,
    server: &[u8],
) -> Response {
    if in_error_page || error_pages.is_empty() {
        return response;
    }

    let status = match &response {
        Response::Prebuilt(bytes) => response_status(bytes),
        Response::Owned(bytes) => response_status(bytes),
        Response::File { headers, .. } => response_status(headers),
        Response::Reroute(_) => return response,
        // Proxy intercept is handled inside `proxy::run_proxy` from
        // pre-rendered plan rules; unresolved proxy plans pass through here.
        Response::Proxy(_) => return response,
    };
    let Some(rule) = error_pages.iter().find(|rule| rule.status == status) else {
        return response;
    };
    // Preserve the `Location:` header for 3xx responses across the
    // internal redirect — nginx's `r->headers_out.location` survives
    // because `ngx_http_send_header` later rewrites the status to
    // `r->err_status`. We re-inject this at finalize time when the
    // preserved status is in the 3xx range.
    let preserved_location: Option<Vec<u8>> = if is_redirect_status(status) {
        let bytes: &[u8] = match &response {
            Response::Prebuilt(b) => b,
            Response::Owned(b) => b,
            Response::File { headers, .. } => headers,
            _ => &[],
        };
        response_header_value(bytes, b"location").map(<[u8]>::to_vec)
    } else {
        None
    };
    // Same idea for `WWW-Authenticate` on 401 — multi-valued (ticket
    // #485), so collect every challenge.
    let preserved_www_authenticate: Vec<Vec<u8>> = if status == 401 {
        let bytes: &[u8] = match &response {
            Response::Prebuilt(b) => b,
            Response::Owned(b) => b,
            Response::File { headers, .. } => headers,
            _ => &[],
        };
        response_header_values_all(bytes, b"www-authenticate")
    } else {
        Vec::new()
    };

    let ctx = RenderCtx {
        status,
        ..*render_ctx_base
    };
    let target = render_error_page_target(rule.target, &ctx);
    if target.is_empty() {
        return response;
    }
    if target[0] == b'/' {
        let (uri, args) = split_target_uri_and_args(target);
        let error_page_status = match rule.action {
            PreparedErrorPageAction::PreserveOriginal => {
                Some(phase::ErrorPageStatus::Preserve(status))
            }
            PreparedErrorPageAction::UseTargetStatus => None,
            PreparedErrorPageAction::Override(code) => Some(phase::ErrorPageStatus::Override(code)),
        };
        return Response::Reroute(phase::Reroute {
            target: phase::RerouteTarget::Uri(uri),
            args,
            error_page_status,
            enters_error_page: !recursive,
            preserved_location,
            preserved_www_authenticate,
        });
    }
    if target[0] == b'@' {
        let error_page_status = match rule.action {
            PreparedErrorPageAction::PreserveOriginal => {
                Some(phase::ErrorPageStatus::Preserve(status))
            }
            PreparedErrorPageAction::UseTargetStatus => None,
            PreparedErrorPageAction::Override(code) => Some(phase::ErrorPageStatus::Override(code)),
        };
        return Response::Reroute(phase::Reroute {
            target: phase::RerouteTarget::Named(target),
            args: None,
            error_page_status,
            enters_error_page: !recursive,
            preserved_location,
            preserved_www_authenticate,
        });
    }
    Response::Owned(http::build_redirect_response(
        external_error_page_status(rule.action),
        &target,
        req.method,
        server,
    ))
}

pub(crate) fn fallback_body(code: u16) -> &'static str {
    match code {
        400 => "Bad Request\n",
        401 => "Unauthorized\n",
        403 => "Forbidden\n",
        404 => "Not Found\n",
        405 => "Method Not Allowed\n",
        410 => "Gone\n",
        500 => "Internal Server Error\n",
        502 => "Bad Gateway\n",
        503 => "Service Unavailable\n",
        _ => "",
    }
}

pub(crate) fn leak_bytes(b: &[u8]) -> &'static [u8] {
    Box::leak(b.to_vec().into_boxed_slice())
}

pub(crate) fn response_has_header(bytes: &[u8], name: &[u8]) -> bool {
    let Some(head_end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") else {
        return false;
    };
    for line in bytes[..head_end].split(|&b| b == b'\n').skip(1) {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            continue;
        };
        if line[..colon].eq_ignore_ascii_case(name) {
            return true;
        }
    }
    false
}

pub(crate) fn inject_connection_header(response: &mut Vec<u8>, close: bool) {
    if response_has_header(response, b"Connection") {
        return;
    }
    let Some(sep) = response.windows(4).position(|w| w == b"\r\n\r\n") else {
        return;
    };
    let split = sep + 2;
    let header: &[u8] = if close {
        b"Connection: close\r\n"
    } else {
        b"Connection: keep-alive\r\n"
    };
    splice_bytes(response, split, header);
}

/// Single-pass summary of the response header block. One walk replaces
/// the three calls the hot path used to stack — `response_header_is`
/// for Connection:close, `response_has_header` for Keep-Alive and
/// Connection, and `response_header_size`. The returned `head_end` is
/// the byte offset of the `\r\n\r\n` terminator (not past it); add 4
/// to get the total header size. Returns `None` only if the response
/// was malformed (no terminator found) — callers handle that via
/// `unwrap_or_default()` and let the slow-path helpers run.
#[derive(Clone, Copy, Default)]
pub(crate) struct ResponseHeaderScan {
    pub(crate) head_end: usize,
    pub(crate) has_connection: bool,
    pub(crate) connection_is_close: bool,
    pub(crate) has_keep_alive: bool,
    /// Offset of the `Date` value when the head has a `Date: ` line with an
    /// IMF-fixdate (`http_date::LEN` bytes) — what `stamp_date` overwrites.
    pub(crate) date_at: Option<usize>,
}

pub(crate) fn scan_response_headers(bytes: &[u8]) -> Option<ResponseHeaderScan> {
    let head_end = bytes.windows(4).position(|w| w == b"\r\n\r\n")?;
    let mut scan = ResponseHeaderScan {
        head_end,
        ..ResponseHeaderScan::default()
    };
    for line in bytes[..head_end].split(|&b| b == b'\n').skip(1) {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            continue;
        };
        let name = &line[..colon];
        if name.eq_ignore_ascii_case(b"Connection") {
            scan.has_connection = true;
            // Trim OWS and test the value against "close" case-insensitively.
            let mut v = &line[colon + 1..];
            while v.first().is_some_and(|b| *b == b' ' || *b == b'\t') {
                v = &v[1..];
            }
            while v.last().is_some_and(|b| *b == b' ' || *b == b'\t') {
                v = &v[..v.len() - 1];
            }
            if v.eq_ignore_ascii_case(b"close") {
                scan.connection_is_close = true;
            }
        } else if name.eq_ignore_ascii_case(b"Keep-Alive") {
            scan.has_keep_alive = true;
        } else if name.eq_ignore_ascii_case(b"Date")
            && line.len() == colon + 2 + http_date::LEN
            && line[colon + 1] == b' '
        {
            scan.date_at = Some(line.as_ptr() as usize - bytes.as_ptr() as usize + colon + 2);
        }
    }
    Some(scan)
}

/// Put the current time into a finished response head: overwrite the `Date`
/// value the builder wrote (prebuilt heads carry the time they were built),
/// or add the header at the end of the head if it has none. nginx's header
/// filter writes `Date` into every response the same way.
pub(crate) fn stamp_date(response: &mut Vec<u8>, scan: &mut ResponseHeaderScan) {
    // No header block (a malformed or empty response): nothing to stamp,
    // and no offset to insert at.
    if response.get(scan.head_end..scan.head_end + 4) != Some(b"\r\n\r\n") {
        return;
    }
    let now = http_date::now();
    if let Some(at) = scan.date_at {
        response[at..at + http_date::LEN].copy_from_slice(&now);
        return;
    }
    let mut line = [0u8; 6 + http_date::LEN + 2];
    line[..6].copy_from_slice(b"Date: ");
    line[6..6 + http_date::LEN].copy_from_slice(&now);
    line[6 + http_date::LEN..].copy_from_slice(b"\r\n");
    let at = scan.head_end + 2 + 6;
    insert_header_at(response, &mut scan.head_end, &line);
    scan.date_at = Some(at);
}

/// `stamp_date` for the early-error paths, which don't keep a scan.
pub(crate) fn refresh_date_header(response: &mut Vec<u8>) {
    if let Some(mut scan) = scan_response_headers(response) {
        stamp_date(response, &mut scan);
    }
}

#[derive(Clone, Copy, Hash, PartialEq, Eq)]
pub(crate) struct PrebuiltVariantKey {
    base_ptr: usize,
    close: bool,
    keep_alive_timeout_secs: Option<u64>,
}

#[derive(Clone, Copy)]
pub(crate) struct PrebuiltVariant {
    pub(crate) bytes: &'static [u8],
    pub(crate) scan: ResponseHeaderScan,
}

thread_local! {
    static PREBUILT_SCAN_LAST: Cell<Option<(usize, ResponseHeaderScan)>> = const { Cell::new(None) };
    static PREBUILT_VARIANT_LAST: Cell<Option<(PrebuiltVariantKey, PrebuiltVariant)>> = const { Cell::new(None) };
    static PREBUILT_SCAN_CACHE: RefCell<std::collections::HashMap<usize, ResponseHeaderScan>> =
        RefCell::new(std::collections::HashMap::new());
    static PREBUILT_VARIANT_CACHE: RefCell<std::collections::HashMap<PrebuiltVariantKey, PrebuiltVariant>> =
        RefCell::new(std::collections::HashMap::new());
}

pub(crate) fn cached_scan_response_headers(bytes: &'static [u8]) -> ResponseHeaderScan {
    let key = bytes.as_ptr() as usize;
    if let Some((last_key, last_scan)) = PREBUILT_SCAN_LAST.with(|last| last.get()) {
        if last_key == key {
            return last_scan;
        }
    }
    PREBUILT_SCAN_CACHE.with(|cache| {
        if let Some(scan) = cache.borrow().get(&key).copied() {
            PREBUILT_SCAN_LAST.with(|last| last.set(Some((key, scan))));
            return scan;
        }
        let scan = scan_response_headers(bytes).unwrap_or_default();
        cache.borrow_mut().insert(key, scan);
        PREBUILT_SCAN_LAST.with(|last| last.set(Some((key, scan))));
        scan
    })
}

pub(crate) fn cached_prebuilt_variant(
    base: &'static [u8],
    close: bool,
    keep_alive_timeout_secs: Option<u64>,
) -> PrebuiltVariant {
    let key = PrebuiltVariantKey {
        base_ptr: base.as_ptr() as usize,
        close,
        keep_alive_timeout_secs,
    };
    if let Some((last_key, last_variant)) = PREBUILT_VARIANT_LAST.with(|last| last.get()) {
        if last_key == key {
            return last_variant;
        }
    }
    PREBUILT_VARIANT_CACHE.with(|cache| {
        if let Some(variant) = cache.borrow().get(&key).copied() {
            PREBUILT_VARIANT_LAST.with(|last| last.set(Some((key, variant))));
            return variant;
        }

        let mut out = base.to_vec();
        let mut scan = scan_response_headers(&out).unwrap_or_default();
        if !close && !scan.has_keep_alive {
            if let Some(timeout_secs) = keep_alive_timeout_secs {
                let mut buf: [u8; 48] = [0; 48];
                let n = format_keep_alive_header(timeout_secs, &mut buf);
                insert_header_at(&mut out, &mut scan.head_end, &buf[..n]);
            }
        }
        if !scan.has_connection {
            let header: &[u8] = if close {
                b"Connection: close\r\n"
            } else {
                b"Connection: keep-alive\r\n"
            };
            insert_header_at(&mut out, &mut scan.head_end, header);
        }
        let final_scan = scan_response_headers(&out).unwrap_or_default();
        let bytes: &'static [u8] = Box::leak(out.into_boxed_slice());
        let variant = PrebuiltVariant {
            bytes,
            scan: final_scan,
        };
        cache.borrow_mut().insert(key, variant);
        PREBUILT_VARIANT_LAST.with(|last| last.set(Some((key, variant))));
        variant
    })
}

/// Splice a pre-built header line into `response` at the known
/// `\r\n\r\n` terminator position, advancing `head_end` to reflect the
/// insertion. Skips the re-scan that the public `inject_*` helpers
/// would otherwise do; the caller is responsible for having already
/// checked `has_*` duplication.
pub(crate) fn insert_header_at(response: &mut Vec<u8>, head_end: &mut usize, header: &[u8]) {
    let split = *head_end + 2;
    splice_bytes(response, split, header);
    *head_end += header.len();
}

pub(crate) fn format_keep_alive_header(timeout_secs: u64, out: &mut [u8; 48]) -> usize {
    let mut n = 0;
    for &b in b"Keep-Alive: timeout=" {
        out[n] = b;
        n += 1;
    }
    n += write_u64_decimal_into(&mut out[n..], timeout_secs);
    for &b in b"\r\n" {
        out[n] = b;
        n += 1;
    }
    n
}

/// Insert `bytes` into `out` starting at `at`, shifting the tail right.
/// In-place; reuses existing capacity when available.
pub(crate) fn splice_bytes(out: &mut Vec<u8>, at: usize, bytes: &[u8]) {
    let old_len = out.len();
    out.resize(old_len + bytes.len(), 0);
    out.copy_within(at..old_len, at + bytes.len());
    out[at..at + bytes.len()].copy_from_slice(bytes);
}

/// Write `n` as decimal ASCII into the start of `out`; return bytes written.
pub(crate) fn write_u64_decimal_into(out: &mut [u8], mut n: u64) -> usize {
    if n == 0 {
        out[0] = b'0';
        return 1;
    }
    let mut tmp = [0u8; 20];
    let mut k = tmp.len();
    while n > 0 {
        k -= 1;
        tmp[k] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    let len = tmp.len() - k;
    out[..len].copy_from_slice(&tmp[k..]);
    len
}
