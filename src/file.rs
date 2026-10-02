// Static file handler.
//
// `serve` path in three steps:
// 1. stat_only: metadata + stable response headers
// 2. decide: conditional GET / If-Range / Range outcome
// 3. read_slice: whole file or byte-range body

use std::os::unix::io::AsRawFd;

use crate::fs_resolve::Opened;
use crate::http::Method;
use crate::phase::{FileBody, Response};

/// Mini mime table, keyed on lowercased extension. Matches the handful of
/// types nginx ships by default in `conf/mime.types` with the widest
/// real-world coverage.
const MIME_TYPES: &[(&[u8], &[u8])] = &[
    (b"html", b"text/html; charset=utf-8"),
    (b"htm", b"text/html; charset=utf-8"),
    (b"css", b"text/css; charset=utf-8"),
    (b"js", b"text/javascript; charset=utf-8"),
    (b"mjs", b"text/javascript; charset=utf-8"),
    (b"json", b"application/json"),
    (b"txt", b"text/plain; charset=utf-8"),
    (b"xml", b"application/xml"),
    (b"png", b"image/png"),
    (b"jpg", b"image/jpeg"),
    (b"jpeg", b"image/jpeg"),
    (b"gif", b"image/gif"),
    (b"svg", b"image/svg+xml"),
    (b"webp", b"image/webp"),
    (b"ico", b"image/x-icon"),
    (b"woff2", b"font/woff2"),
    (b"pdf", b"application/pdf"),
    (b"wasm", b"application/wasm"),
];
pub(crate) const DEFAULT_MIME: &[u8] = b"application/octet-stream";
const INLINE_BODY_LIMIT: u64 = 8 * 1024;
/// With `sendfile on`, bodies at least this large go out zero-copy. Below
/// it, `pread` into the response buffer plus one io_uring write beats the
/// two direct syscalls of the sendfile path (measured break-even ~2 KiB:
/// 1 KiB −3%, 4 KiB +6%, 8 KiB +8% vs inline on loopback, 16×512 wrk).
const SENDFILE_MIN_BODY: u64 = 4 * 1024;

pub struct Conditionals<'a> {
    pub if_modified_since: Option<&'a [u8]>,
    pub if_unmodified_since: Option<&'a [u8]>,
    pub if_none_match: Option<&'a [u8]>,
    pub if_match: Option<&'a [u8]>,
    pub range: Option<&'a [u8]>,
    pub if_range: Option<&'a [u8]>,
    /// Effective `Last-Modified` value after `add_header Last-Modified ...`
    /// rewriting. `None` means "use filesystem mtime", `Some(b\"\")` means
    /// "Last-Modified suppressed", and non-empty values are parsed as
    /// HTTP-date for conditional comparisons.
    pub last_modified_override: Option<&'a [u8]>,
}

struct FileMeta {
    size: u64,
    mime: &'static [u8],
    mtime: u64,
    last_modified: [u8; 29],
    etag: Etag,
}

/// Inline-buffered ETag value. The wire form is
/// `"<hex-mtime>-<hex-size>"`, so the longest possible render is
/// `1 + 16 + 1 + 16 + 1 = 35` bytes (both u64 fields hitting their
/// 16-hex-digit max). Keeping the bytes inline avoids a per-request
/// `Vec<u8>` allocation on the file-serving hot path — one of the
/// last `alloc`s left in that path.
#[derive(Debug, Clone, Copy)]
struct Etag {
    buf: [u8; Etag::MAX_LEN],
    len: u8,
}

impl Etag {
    const MAX_LEN: usize = 35;

    #[inline]
    fn as_slice(&self) -> &[u8] {
        &self.buf[..self.len as usize]
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Decision {
    NotModified,
    Full,
    Range {
        start: u64,
        end: u64,
    },
    UnsatisfiableRange,
    /// `If-Match` failed against a resource that *does* exist — RFC 9110
    /// §13.1.1 says 412. We return this from `decide` and let the content
    /// builder emit the bare 412 with no body.
    PreconditionFailed,
}

#[derive(Debug, PartialEq, Eq)]
enum RangeParse {
    Ignore,
    Slice { start: u64, end: u64 },
    Unsatisfiable,
}

/// Serve an already-opened, root-contained file. The resolver has done
/// location matching, URI normalization, index probing, `try_files`, and
/// root-containment — and has also done the `fstat`, so this function
/// never touches the filesystem name space: it only `pread`s (inline body)
/// or hands the fd off to the streaming path.
///
/// `server` is the `Server:` header value to emit — derived from the
/// effective `server_tokens` for the matched location.
///
/// Bodies up to `INLINE_BODY_LIMIT` are `pread` into the response buffer.
/// With `sendfile` on, only bodies below `SENDFILE_MIN_BODY` are; larger ones
/// go out as `Response::File` so the worker can send them without copying.
pub fn serve_path(
    opened: Opened,
    method: Method,
    cond: Conditionals<'_>,
    server: &[u8],
    sendfile: bool,
) -> Response {
    let inline_limit = if sendfile {
        SENDFILE_MIN_BODY - 1
    } else {
        INLINE_BODY_LIMIT
    };
    if !matches!(method, Method::Get | Method::Head) {
        // Caller should already have 405'd the method, but handle the
        // defensive case here too. Drop the fd on return.
        return Response::Owned(method_not_allowed(method, server));
    }

    let meta = meta_from_opened(&opened);

    match decide(&meta, cond) {
        Decision::NotModified => Response::Owned(build_not_modified_response(&meta, server)),
        Decision::Full => {
            let body_len = meta.size;
            let mut headers = build_content_headers(&meta, 200, None, server);
            if matches!(method, Method::Head) || body_len == 0 {
                Response::Owned(headers)
            } else if body_len <= inline_limit {
                if let Err(e) = read_at_into(opened.fd.as_raw_fd(), 0, body_len, &mut headers) {
                    Response::Owned(io_error_response(e, method, server))
                } else {
                    Response::Owned(headers)
                }
            } else {
                Response::File {
                    headers,
                    body: FileBody {
                        fd: opened.fd,
                        offset: 0,
                        len: body_len,
                    },
                }
            }
        }
        Decision::Range { start, end } => {
            let body_len = end - start + 1;
            let mut headers = build_content_headers(&meta, 206, Some((start, end)), server);
            if matches!(method, Method::Head) || body_len == 0 {
                Response::Owned(headers)
            } else if body_len <= inline_limit {
                if let Err(e) = read_at_into(opened.fd.as_raw_fd(), start, body_len, &mut headers) {
                    Response::Owned(io_error_response(e, method, server))
                } else {
                    Response::Owned(headers)
                }
            } else {
                Response::File {
                    headers,
                    body: FileBody {
                        fd: opened.fd,
                        offset: start,
                        len: body_len,
                    },
                }
            }
        }
        Decision::UnsatisfiableRange => {
            Response::Owned(build_range_not_satisfiable_response(&meta, server))
        }
        Decision::PreconditionFailed => {
            Response::Owned(error_response(412, "Precondition Failed\n", method, server))
        }
    }
}

pub fn method_not_allowed(method: Method, server: &[u8]) -> Vec<u8> {
    error_response(405, "Method Not Allowed\n", method, server)
}

fn meta_from_opened(o: &Opened) -> FileMeta {
    FileMeta {
        size: o.size,
        mime: o.mime,
        mtime: o.mtime,
        last_modified: format_http_date(o.mtime),
        etag: make_etag(o.mtime, o.size),
    }
}

fn decide(meta: &FileMeta, cond: Conditionals<'_>) -> Decision {
    // Callers (currently only `serve_path`) 405 non-GET/HEAD at entry, so
    // everything here runs with a "safe" method and the RFC 9110 §13.1.2
    // special case (If-None-Match match → 412 on unsafe methods) is
    // unreachable. Precondition ordering is §13.2.2:
    //   If-Match → If-Unmodified-Since → If-None-Match → If-Modified-Since → If-Range
    let has_if_match = cond.if_match.is_some();
    if let Some(if_match) = cond.if_match {
        // Strong comparison per §13.1.1: a weak ETag (`W/…`) never matches.
        if !etag_list_matches_strong(if_match, meta.etag.as_slice()) {
            return Decision::PreconditionFailed;
        }
    }

    let conditional_last_modified =
        resolve_conditional_last_modified(meta, cond.last_modified_override);

    // `If-Unmodified-Since` is only evaluated when `If-Match` is absent
    // (RFC 9110 §13.1.4 / §13.2.2 ordering). A stale date precondition
    // fails with 412 before cache validators (`If-None-Match` / IMS).
    if !has_if_match {
        if let Some(if_unmodified_since) = cond.if_unmodified_since {
            if let Some(current_last_modified) = conditional_last_modified {
                if let Some(since) = parse_http_date(if_unmodified_since) {
                    if current_last_modified > since {
                        return Decision::PreconditionFailed;
                    }
                }
            }
        }
    }

    if let Some(if_none_match) = cond.if_none_match {
        if etag_list_matches(if_none_match, meta.etag.as_slice()) {
            return Decision::NotModified;
        }
        // When `If-None-Match` is present, `If-Modified-Since` MUST be
        // ignored (§13.1.3). Falling through skips it.
    } else if let Some(if_modified_since) = cond.if_modified_since {
        // Plain `mtime <= since` compare — no weak-validator freshness
        // gate. Tests rely on files written just before the request
        // still 304ing.
        if let Some(current_last_modified) = conditional_last_modified {
            if let Some(since) = parse_http_date(if_modified_since) {
                if current_last_modified <= since {
                    return Decision::NotModified;
                }
            }
        }
    }

    let mut range = cond.range;
    if let (Some(_), Some(if_range)) = (range, cond.if_range) {
        if !if_range_matches(if_range, meta, conditional_last_modified) {
            range = None;
        }
    }

    match range {
        Some(value) => match parse_range(value, meta.size) {
            RangeParse::Ignore => Decision::Full,
            RangeParse::Slice { start, end } => Decision::Range { start, end },
            RangeParse::Unsatisfiable => Decision::UnsatisfiableRange,
        },
        None => Decision::Full,
    }
}

fn resolve_conditional_last_modified(
    meta: &FileMeta,
    override_value: Option<&[u8]>,
) -> Option<u64> {
    match override_value {
        None => Some(meta.mtime),
        Some(raw) if raw.is_empty() => None,
        Some(raw) => parse_http_date(raw),
    }
}

/// Strong entity-tag comparison per RFC 9110 §8.8.3.2: weak ETags on either
/// side make any concrete compare fail. `*` always matches a resource that
/// exists. Our emitted ETag is syntactically strong (`"hex-hex"`), though
/// its semantics are only weak-ish because it is derived from mtime+size.
fn etag_list_matches_strong(value: &[u8], current: &[u8]) -> bool {
    let value = trim_ows(value);
    if value == b"*" {
        return true;
    }
    if current.starts_with(b"W/") {
        return false;
    }

    let mut i = 0;
    let n = value.len();
    while i < n {
        while i < n && matches!(value[i], b' ' | b'\t' | b',') {
            i += 1;
        }
        if i >= n {
            break;
        }

        let start = i;
        let weak = i + 1 < n && value[i] == b'W' && value[i + 1] == b'/';
        if weak {
            i += 2;
        }
        if i >= n || value[i] != b'"' {
            while i < n && value[i] != b',' {
                i += 1;
            }
            continue;
        }

        i += 1;
        while i < n && value[i] != b'"' {
            if value[i] == b'\\' && i + 1 < n {
                i += 2;
            } else {
                i += 1;
            }
        }
        if i >= n {
            break;
        }
        i += 1;
        if weak {
            // Weak client-side validator → strong compare fails; skip.
            continue;
        }
        if &value[start..i] == current {
            return true;
        }
    }
    false
}

fn build_content_headers(
    meta: &FileMeta,
    status: u16,
    range: Option<(u64, u64)>,
    server: &[u8],
) -> Vec<u8> {
    let body_len = range
        .map(|(start, end)| end - start + 1)
        .unwrap_or(meta.size);
    let mut out = Vec::with_capacity(256);
    write_status_line(&mut out, status);
    out.extend_from_slice(b"\r\nServer: ");
    out.extend_from_slice(server);
    out.extend_from_slice(b"\r\nAccept-Ranges: bytes");
    out.extend_from_slice(b"\r\nContent-Type: ");
    out.extend_from_slice(meta.mime);
    out.extend_from_slice(b"\r\nContent-Length: ");
    write_u64(&mut out, body_len);
    out.extend_from_slice(b"\r\nLast-Modified: ");
    out.extend_from_slice(&meta.last_modified);
    out.extend_from_slice(b"\r\nETag: ");
    out.extend_from_slice(meta.etag.as_slice());
    if let Some((start, end)) = range {
        out.extend_from_slice(b"\r\nContent-Range: bytes ");
        write_u64(&mut out, start);
        out.push(b'-');
        write_u64(&mut out, end);
        out.push(b'/');
        write_u64(&mut out, meta.size);
    }
    out.extend_from_slice(b"\r\n\r\n");
    out
}

fn build_not_modified_response(meta: &FileMeta, server: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    write_status_line(&mut out, 304);
    out.extend_from_slice(b"\r\nServer: ");
    out.extend_from_slice(server);
    out.extend_from_slice(b"\r\nAccept-Ranges: bytes");
    out.extend_from_slice(b"\r\nLast-Modified: ");
    out.extend_from_slice(&meta.last_modified);
    out.extend_from_slice(b"\r\nETag: ");
    out.extend_from_slice(meta.etag.as_slice());
    out.extend_from_slice(b"\r\n\r\n");
    out
}

fn build_range_not_satisfiable_response(meta: &FileMeta, server: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    write_status_line(&mut out, 416);
    out.extend_from_slice(b"\r\nServer: ");
    out.extend_from_slice(server);
    out.extend_from_slice(b"\r\nAccept-Ranges: bytes");
    out.extend_from_slice(b"\r\nContent-Range: bytes */");
    write_u64(&mut out, meta.size);
    out.extend_from_slice(b"\r\nContent-Length: 0");
    out.extend_from_slice(b"\r\nLast-Modified: ");
    out.extend_from_slice(&meta.last_modified);
    out.extend_from_slice(b"\r\nETag: ");
    out.extend_from_slice(meta.etag.as_slice());
    out.extend_from_slice(b"\r\n\r\n");
    out
}

fn if_range_matches(value: &[u8], meta: &FileMeta, conditional_last_modified: Option<u64>) -> bool {
    // If-Range with an entity-tag uses strong comparison.
    if let Some(first) = value.first() {
        if *first == b'"' {
            return value == meta.etag.as_slice();
        }
    }

    // Otherwise parse as HTTP-date and compare against second-granularity mtime.
    parse_http_date(value).is_some_and(|date| conditional_last_modified == Some(date))
}

/// Append exactly `len` bytes starting at `start` from `fd` onto `out`.
/// Uses `pread(2)` so the fd's file position isn't touched — lets the
/// same fd be handed to the streaming path afterwards without extra seeks,
/// and skips the second `open` that the old `read_slice` paid.
fn read_at_into(
    fd: std::os::unix::io::RawFd,
    start: u64,
    len: u64,
    out: &mut Vec<u8>,
) -> std::io::Result<()> {
    let want = len as usize;
    let begin = out.len();
    out.resize(begin + want, 0);
    let mut total: usize = 0;
    while total < want {
        let ret = unsafe {
            libc::pread(
                fd,
                out[begin + total..].as_mut_ptr() as *mut libc::c_void,
                want - total,
                (start + total as u64) as libc::off_t,
            )
        };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            out.truncate(begin);
            return Err(err);
        }
        if ret == 0 {
            out.truncate(begin);
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "short read while serving file",
            ));
        }
        total += ret as usize;
    }
    Ok(())
}

/// Parse an If-None-Match value as a comma-separated list of entity-tags,
/// respecting quoted-string boundaries so that a comma inside a tag body
/// does not split the entry. Comparison is weak per RFC 9110: strip any
/// `W/` prefix on both sides, then byte-compare the opaque-tag.
fn etag_list_matches(value: &[u8], current: &[u8]) -> bool {
    let value = trim_ows(value);
    if value == b"*" {
        return true;
    }
    let mut i = 0;
    let n = value.len();
    while i < n {
        while i < n && matches!(value[i], b' ' | b'\t' | b',') {
            i += 1;
        }
        if i >= n {
            break;
        }
        let start = i;
        if i + 1 < n && value[i] == b'W' && value[i + 1] == b'/' {
            i += 2;
        }
        if i >= n || value[i] != b'"' {
            // Not a well-formed entity-tag — skip to the next comma and move on.
            while i < n && value[i] != b',' {
                i += 1;
            }
            continue;
        }
        i += 1;
        while i < n && value[i] != b'"' {
            if value[i] == b'\\' && i + 1 < n {
                i += 2;
            } else {
                i += 1;
            }
        }
        if i >= n {
            break;
        }
        i += 1;
        if etag_weak_equal(&value[start..i], current) {
            return true;
        }
    }
    false
}

fn etag_weak_equal(a: &[u8], b: &[u8]) -> bool {
    let a = a.strip_prefix(b"W/").unwrap_or(a);
    let b = b.strip_prefix(b"W/").unwrap_or(b);
    a == b
}

fn parse_range(value: &[u8], size: u64) -> RangeParse {
    if !value.starts_with(b"bytes=") {
        return RangeParse::Ignore;
    }
    let spec = &value[6..];
    if spec.is_empty() || spec.contains(&b',') {
        return RangeParse::Ignore;
    }
    let Some(dash) = spec.iter().position(|&b| b == b'-') else {
        return RangeParse::Ignore;
    };
    let start = trim_ows(&spec[..dash]);
    let end = trim_ows(&spec[dash + 1..]);

    if start.is_empty() {
        let Some(suffix_len) = parse_u64_ascii(end) else {
            return RangeParse::Ignore;
        };
        if suffix_len == 0 || size == 0 {
            return RangeParse::Unsatisfiable;
        }
        let body_len = suffix_len.min(size);
        return RangeParse::Slice {
            start: size - body_len,
            end: size - 1,
        };
    }

    let Some(start) = parse_u64_ascii(start) else {
        return RangeParse::Ignore;
    };
    if start >= size {
        return RangeParse::Unsatisfiable;
    }
    if end.is_empty() {
        return RangeParse::Slice {
            start,
            end: size - 1,
        };
    }
    let Some(end) = parse_u64_ascii(end) else {
        return RangeParse::Ignore;
    };
    if end < start {
        return RangeParse::Ignore;
    }
    RangeParse::Slice {
        start,
        end: end.min(size - 1),
    }
}

fn parse_u64_ascii(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() {
        return None;
    }

    let mut out = 0u64;
    for &b in bytes {
        if !b.is_ascii_digit() {
            return None;
        }
        out = out.checked_mul(10)?.checked_add((b - b'0') as u64)?;
    }
    Some(out)
}

fn trim_ows(mut bytes: &[u8]) -> &[u8] {
    while let Some((&b, rest)) = bytes.split_first() {
        if b != b' ' && b != b'\t' {
            break;
        }
        bytes = rest;
    }
    while let Some((&b, rest)) = bytes.split_last() {
        if b != b' ' && b != b'\t' {
            break;
        }
        bytes = rest;
    }
    bytes
}

/// ETag in nginx's default wire format: `"<hex-mtime>-<hex-size>"`.
/// Syntactically strong (no `W/` prefix), semantically only a weak-ish
/// validator because it is derived from mtime+size. Writes directly into
/// an inline `Etag` buffer so the file-serving path doesn't heap-allocate
/// to produce it — the response builder copies the bytes straight out.
fn make_etag(mtime: u64, size: u64) -> Etag {
    let mut buf = [0u8; Etag::MAX_LEN];
    let mut pos = 0;
    buf[pos] = b'"';
    pos += 1;
    pos += write_u64_hex_into(&mut buf[pos..], mtime);
    buf[pos] = b'-';
    pos += 1;
    pos += write_u64_hex_into(&mut buf[pos..], size);
    buf[pos] = b'"';
    pos += 1;
    Etag {
        buf,
        len: pos as u8,
    }
}

/// Write `n` as lowercase hex into the start of `out`; return how many
/// bytes were written (1..=16). Caller is responsible for sizing `out`;
/// 16 bytes is always enough for a `u64`. No allocation.
fn write_u64_hex_into(out: &mut [u8], mut n: u64) -> usize {
    if n == 0 {
        out[0] = b'0';
        return 1;
    }
    // Render right-to-left into a stack scratch, then copy the tail.
    let mut tmp = [0u8; 16];
    let mut k = tmp.len();
    while n > 0 {
        k -= 1;
        let d = (n & 0x0f) as u8;
        tmp[k] = if d < 10 { b'0' + d } else { b'a' + (d - 10) };
        n >>= 4;
    }
    let len = tmp.len() - k;
    out[..len].copy_from_slice(&tmp[k..]);
    len
}

fn io_error_response(e: std::io::Error, method: Method, server: &[u8]) -> Vec<u8> {
    use std::io::ErrorKind::*;
    match e.kind() {
        // NotADirectory: a non-final component of the request path is a file,
        // e.g. /foo.txt/bar when foo.txt exists. nginx returns 404 here, not 500.
        NotFound | NotADirectory => error_response(404, "Not Found\n", method, server),
        PermissionDenied => error_response(403, "Forbidden\n", method, server),
        _ => error_response(500, "Internal Server Error\n", method, server),
    }
}

fn error_response(status: u16, body: &str, method: Method, server: &[u8]) -> Vec<u8> {
    crate::http::build_response_for_method(status, body, method, server)
}

pub(crate) fn mime_for(ext: &[u8]) -> &'static [u8] {
    // ext is raw bytes from the filesystem — compare case-insensitively on
    // ASCII. This doesn't allocate; we match character-by-character.
    for &(e, m) in MIME_TYPES {
        if ext.len() == e.len()
            && ext
                .iter()
                .zip(e.iter())
                .all(|(a, b)| a.eq_ignore_ascii_case(b))
        {
            return m;
        }
    }
    DEFAULT_MIME
}

fn write_status_line(out: &mut Vec<u8>, status: u16) {
    out.extend_from_slice(b"HTTP/1.1 ");
    write_u16(out, status);
    out.push(b' ');
    out.extend_from_slice(reason_phrase(status));
}

fn reason_phrase(status: u16) -> &'static [u8] {
    match status {
        200 => b"OK",
        206 => b"Partial Content",
        304 => b"Not Modified",
        403 => b"Forbidden",
        404 => b"Not Found",
        405 => b"Method Not Allowed",
        412 => b"Precondition Failed",
        416 => b"Range Not Satisfiable",
        500 => b"Internal Server Error",
        _ => b"Unknown",
    }
}

fn write_u16(out: &mut Vec<u8>, mut n: u16) {
    let mut tmp = [0u8; 5];
    let mut k = tmp.len();
    if n == 0 {
        out.push(b'0');
        return;
    }
    while n > 0 {
        k -= 1;
        tmp[k] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    out.extend_from_slice(&tmp[k..]);
}

fn write_u64(out: &mut Vec<u8>, mut n: u64) {
    let mut tmp = [0u8; 20];
    let mut k = tmp.len();
    if n == 0 {
        out.push(b'0');
        return;
    }
    while n > 0 {
        k -= 1;
        tmp[k] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    out.extend_from_slice(&tmp[k..]);
}

/// Latest Unix timestamp we can render as a 4-digit-year IMF-fixdate:
/// 9999-12-31 23:59:59 UTC. Anything larger saturates to this value
/// (see `format_http_date` — inputs above this produce a well-formed
/// date, just pinned to the ceiling). Pre-computed; the pure-int
/// year walk can't build this at `const`-eval time without bringing in
/// a full calendar routine.
const MAX_HTTP_DATE_SECS: u64 = 253_402_300_799;

/// RFC 7231 IMF-fixdate, always exactly 29 bytes.
/// Example: `Sun, 06 Nov 1994 08:49:37 GMT`.
///
/// **Contract:** infallible for every `u64`. Inputs past
/// `MAX_HTTP_DATE_SECS` saturate to `Fri, 31 Dec 9999 23:59:59 GMT`.
/// This avoids a panic if a filesystem ever hands back a garbage future
/// `mtime`; practical mtimes are many orders of magnitude below the cap
/// (year 2286 is still under 1 × 10¹⁰ seconds).
pub(crate) fn format_http_date(secs: u64) -> [u8; 29] {
    // 1970-01-01 was a Thursday, so `days % 7 == 0` → index 0 is Thu.
    const DOW: [&[u8; 3]; 7] = [b"Thu", b"Fri", b"Sat", b"Sun", b"Mon", b"Tue", b"Wed"];
    const MON: [&[u8; 3]; 12] = [
        b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov",
        b"Dec",
    ];

    let secs = secs.min(MAX_HTTP_DATE_SECS);
    let days = secs / 86_400;
    let hms = secs % 86_400;
    let hour = (hms / 3_600) as u8;
    let minute = ((hms % 3_600) / 60) as u8;
    let second = (hms % 60) as u8;
    let dow_idx = (days % 7) as usize;

    let (year, mon, day) = civil_from_days(days);

    let mut buf = *b"Thu, 00 Jan 1970 00:00:00 GMT";
    buf[..3].copy_from_slice(DOW[dow_idx]);
    buf[5] = b'0' + day / 10;
    buf[6] = b'0' + day % 10;
    buf[8..11].copy_from_slice(MON[mon]);
    buf[12] = b'0' + ((year / 1000) % 10) as u8;
    buf[13] = b'0' + ((year / 100) % 10) as u8;
    buf[14] = b'0' + ((year / 10) % 10) as u8;
    buf[15] = b'0' + (year % 10) as u8;
    buf[17] = b'0' + hour / 10;
    buf[18] = b'0' + hour % 10;
    buf[20] = b'0' + minute / 10;
    buf[21] = b'0' + minute % 10;
    buf[23] = b'0' + second / 10;
    buf[24] = b'0' + second % 10;
    buf
}

/// Days since 1970-01-01 → (year, month index 0..=11, day of month 1..=31),
/// in O(1). Howard Hinnant's `civil_from_days` for the proleptic Gregorian
/// calendar, restricted to non-negative day counts (`days` is unsigned).
/// Replaces a year-by-year walk from 1970 that ran on every response
/// (`format_http_date` was ~1.3% of CPU on the 304 bench).
fn civil_from_days(days: u64) -> (u32, usize, u8) {
    // Shift the epoch to 0000-03-01 so leap days fall at the end of each
    // 400-year era.
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // March-based month [0, 11]
    let day = (doy - (153 * mp + 2) / 5 + 1) as u8; // [1, 31]
    let mon = if mp < 10 { mp + 2 } else { mp - 10 } as usize; // Jan = 0
    let year = (yoe + era * 400) as u32 + u32::from(mon <= 1);
    (year, mon, day)
}

/// RFC 7231 §7.1.1.1 requires servers to accept three `HTTP-date` formats:
///
/// ```text
/// IMF-fixdate: Sun, 06 Nov 1994 08:49:37 GMT   (exactly 29 bytes)
/// RFC 850:     Sunday, 06-Nov-94 08:49:37 GMT  (variable DoW, total 28–31)
/// asctime():   Sun Nov  6 08:49:37 1994        (exactly 24 bytes, no GMT)
/// ```
///
/// Format disambiguation is by the first `,`:
/// - at position 3 → IMF-fixdate (3-char DoW),
/// - at positions 6..=9 → RFC 850 (DoW is Monday..Sunday),
/// - absent → asctime.
///
/// IMF is overwhelmingly the common shape on the modern web, so it's the
/// first arm. The other two exist for older clients and interop parity
/// with nginx (`ngx_parse_time.c:15–277`).
pub(crate) fn parse_http_date(bytes: &[u8]) -> Option<u64> {
    match bytes.iter().position(|&b| b == b',') {
        Some(3) => parse_imf_fixdate(bytes),
        Some(n) if (6..=9).contains(&n) => parse_rfc850(bytes, n),
        Some(_) => None,
        None => parse_asctime(bytes),
    }
}

fn parse_imf_fixdate(bytes: &[u8]) -> Option<u64> {
    if bytes.len() != 29 || !is_dow_short(&bytes[0..3]) {
        return None;
    }
    if bytes[3] != b','
        || bytes[4] != b' '
        || bytes[7] != b' '
        || bytes[11] != b' '
        || bytes[16] != b' '
        || bytes[19] != b':'
        || bytes[22] != b':'
        || bytes[25] != b' '
        || &bytes[26..29] != b"GMT"
    {
        return None;
    }
    let day = parse_2_digits(&bytes[5..7])?;
    let month = month_from_name(&bytes[8..11])?;
    let year = parse_4_digits(&bytes[12..16])?;
    let hour = parse_2_digits(&bytes[17..19])?;
    let minute = parse_2_digits(&bytes[20..22])?;
    let second = parse_2_digits(&bytes[23..25])?;
    epoch_from_ymdhms(year as u32, month, day, hour, minute, second)
}

fn parse_rfc850(bytes: &[u8], comma: usize) -> Option<u64> {
    if !is_dow_long(&bytes[0..comma]) {
        return None;
    }
    // Everything after the comma is fixed-width: ` DD-MON-YY HH:MM:SS GMT`
    // = 23 bytes.
    let rest = bytes.get(comma + 1..)?;
    if rest.len() != 23 {
        return None;
    }
    if rest[0] != b' '
        || rest[3] != b'-'
        || rest[7] != b'-'
        || rest[10] != b' '
        || rest[13] != b':'
        || rest[16] != b':'
        || rest[19] != b' '
        || &rest[20..23] != b"GMT"
    {
        return None;
    }
    let day = parse_2_digits(&rest[1..3])?;
    let month = month_from_name(&rest[4..7])?;
    let yy = parse_2_digits(&rest[8..10])?;
    // Two-digit-year pivot: 00..=69 → 2000..=2069, 70..=99 → 1970..=1999.
    // Matches nginx (`ngx_parse_time.c:145`) and keeps `year >= 1970`
    // unconditionally — so the downstream epoch compute never underflows.
    let year: u32 = if yy < 70 {
        2000 + yy as u32
    } else {
        1900 + yy as u32
    };
    let hour = parse_2_digits(&rest[11..13])?;
    let minute = parse_2_digits(&rest[14..16])?;
    let second = parse_2_digits(&rest[17..19])?;
    epoch_from_ymdhms(year, month, day, hour, minute, second)
}

fn parse_asctime(bytes: &[u8]) -> Option<u64> {
    // `Sun Nov  6 08:49:37 1994` — fixed 24 bytes, no GMT suffix.
    // Single-digit days are space-padded so column positions don't shift.
    if bytes.len() != 24 || !is_dow_short(&bytes[0..3]) {
        return None;
    }
    if bytes[3] != b' '
        || bytes[7] != b' '
        || bytes[10] != b' '
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b' '
    {
        return None;
    }
    let month = month_from_name(&bytes[4..7])?;
    let day = if bytes[8] == b' ' {
        if !bytes[9].is_ascii_digit() {
            return None;
        }
        bytes[9] - b'0'
    } else {
        parse_2_digits(&bytes[8..10])?
    };
    let hour = parse_2_digits(&bytes[11..13])?;
    let minute = parse_2_digits(&bytes[14..16])?;
    let second = parse_2_digits(&bytes[17..19])?;
    let year = parse_4_digits(&bytes[20..24])?;
    epoch_from_ymdhms(year as u32, month, day, hour, minute, second)
}

fn epoch_from_ymdhms(
    year: u32,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
) -> Option<u64> {
    if year < 1970 || day == 0 || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    if day > days_in_month(year, month) {
        return None;
    }

    // Days from 1970-01-01 to year-01-01 in closed form: 365 days per year
    // plus the count of leap years in [1970, year). Leap-count uses the
    // standard prefix formula shifted to 1970 (1969 has 477 leap years
    // since year 1).
    let prev = year - 1;
    let leap_days_since_1970 =
        (prev / 4 - prev / 100 + prev / 400) as u64 - 477;
    let mut days = 365u64 * (year - 1970) as u64 + leap_days_since_1970;

    // Cumulative non-leap-year days at the start of each month (index 1..=12).
    const MONTH_OFFSETS: [u16; 13] = [
        0, 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334,
    ];
    days += MONTH_OFFSETS[month as usize] as u64;
    if month > 2 && is_leap(year) {
        days += 1;
    }
    days += (day - 1) as u64;

    Some(days * 86_400 + (hour as u64) * 3_600 + (minute as u64) * 60 + second as u64)
}

fn is_dow_short(bytes: &[u8]) -> bool {
    const DOW: [&[u8; 3]; 7] = [b"Mon", b"Tue", b"Wed", b"Thu", b"Fri", b"Sat", b"Sun"];
    bytes.len() == 3 && DOW.iter().any(|&name| name == bytes)
}

fn is_dow_long(bytes: &[u8]) -> bool {
    matches!(
        bytes,
        b"Monday" | b"Tuesday" | b"Wednesday" | b"Thursday" | b"Friday" | b"Saturday" | b"Sunday"
    )
}

fn month_from_name(name: &[u8]) -> Option<u8> {
    Some(match name {
        b"Jan" => 1,
        b"Feb" => 2,
        b"Mar" => 3,
        b"Apr" => 4,
        b"May" => 5,
        b"Jun" => 6,
        b"Jul" => 7,
        b"Aug" => 8,
        b"Sep" => 9,
        b"Oct" => 10,
        b"Nov" => 11,
        b"Dec" => 12,
        _ => return None,
    })
}

fn parse_2_digits(bytes: &[u8]) -> Option<u8> {
    if bytes.len() != 2 || !bytes[0].is_ascii_digit() || !bytes[1].is_ascii_digit() {
        return None;
    }
    Some((bytes[0] - b'0') * 10 + (bytes[1] - b'0'))
}

fn parse_4_digits(bytes: &[u8]) -> Option<u16> {
    if bytes.len() != 4 {
        return None;
    }
    let mut out = 0u16;
    for &b in bytes {
        if !b.is_ascii_digit() {
            return None;
        }
        out = out * 10 + (b - b'0') as u16;
    }
    Some(out)
}

fn days_in_month(year: u32, month: u8) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap(year) {
                29
            } else {
                28
            }
        }
        _ => unreachable!("invalid month: {}", month),
    }
}

fn is_leap(y: u32) -> bool {
    (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn meta(size: u64, mtime: u64) -> FileMeta {
        FileMeta {
            size,
            mime: b"text/plain; charset=utf-8",
            mtime,
            last_modified: format_http_date(mtime),
            etag: make_etag(mtime, size),
        }
    }

    /// Plain `open(2)` into an `Opened`, for tests that don't want to set
    /// up a root dir. Production code always goes through `openat2` —
    /// this helper is only for exercising the post-resolve serve path.
    fn open_for_test(path: &std::path::Path) -> Opened {
        use std::os::fd::{FromRawFd, IntoRawFd, OwnedFd};
        let f = std::fs::File::open(path).expect("open test file");
        let meta = f.metadata().expect("stat test file");
        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let fd = unsafe { OwnedFd::from_raw_fd(f.into_raw_fd()) };
        // Mime doesn't matter for these tests; use text/plain.
        Opened {
            fd,
            size: meta.len(),
            mtime,
            mime: b"text/plain; charset=utf-8",
        }
    }

    fn no_cond() -> Conditionals<'static> {
        Conditionals {
            if_modified_since: None,
            if_unmodified_since: None,
            if_none_match: None,
            if_match: None,
            range: None,
            if_range: None,
            last_modified_override: None,
        }
    }

    fn unique_dir() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let d = std::env::temp_dir().join(format!(
            "ruxen-file-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir(&d).unwrap();
        d
    }

    #[test]
    fn serve_path_get_large_body_returns_file_variant() {
        let dir = unique_dir();
        let file_path = dir.join("body.txt");
        let body = vec![b'a'; (INLINE_BODY_LIMIT as usize) + 16];
        std::fs::write(&file_path, &body).unwrap();

        let r = serve_path(
            open_for_test(&file_path),
            Method::Get,
            no_cond(),
            b"nginx/1.29.2",
            false,
        );
        match r {
            Response::File { headers, body } => {
                let s = std::str::from_utf8(&headers).unwrap();
                assert!(s.starts_with("HTTP/1.1 200 OK\r\n"));
                assert!(s.contains("Content-Length: 8208\r\n"));
                // Body now carries an OwnedFd; assert the shape matches.
                assert_eq!(body.offset, 0);
                assert_eq!(body.len, (INLINE_BODY_LIMIT as usize + 16) as u64);
            }
            Response::Owned(_) | Response::Prebuilt(_) | Response::Reroute(_) | Response::Proxy(_) => {
                panic!("expected streamed file response")
            }
        }

        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn serve_path_head_returns_owned_headers() {
        let dir = unique_dir();
        let file_path = dir.join("head.txt");
        std::fs::write(&file_path, b"abcdef").unwrap();

        let r = serve_path(
            open_for_test(&file_path),
            Method::Head,
            no_cond(),
            b"nginx/1.29.2",
            false,
        );
        match r {
            Response::Owned(bytes) => {
                let s = std::str::from_utf8(&bytes).unwrap();
                assert!(s.starts_with("HTTP/1.1 200 OK\r\n"));
                assert!(s.contains("Content-Length: 6\r\n"));
                assert!(s.ends_with("\r\n\r\n"));
            }
            Response::File { .. } | Response::Prebuilt(_) | Response::Reroute(_) | Response::Proxy(_) => {
                panic!("expected buffered headers-only response")
            }
        }

        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn serve_path_get_small_body_is_inlined_in_owned_response() {
        let dir = unique_dir();
        let file_path = dir.join("small.txt");
        std::fs::write(&file_path, b"abcdef").unwrap();

        let r = serve_path(
            open_for_test(&file_path),
            Method::Get,
            no_cond(),
            b"nginx/1.29.2",
            false,
        );
        match r {
            Response::Owned(bytes) => {
                let s = std::str::from_utf8(&bytes).unwrap();
                assert!(s.starts_with("HTTP/1.1 200 OK\r\n"));
                assert!(s.contains("Content-Length: 6\r\n"));
                assert!(s.ends_with("abcdef"));
            }
            Response::File { .. } | Response::Prebuilt(_) | Response::Reroute(_) | Response::Proxy(_) => {
                panic!("expected inlined small response")
            }
        }

        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn serve_path_get_zero_length_returns_owned_headers() {
        let dir = unique_dir();
        let file_path = dir.join("zero.txt");
        std::fs::write(&file_path, &[] as &[u8]).unwrap();

        let r = serve_path(
            open_for_test(&file_path),
            Method::Get,
            no_cond(),
            b"nginx/1.29.2",
            false,
        );
        match r {
            Response::Owned(bytes) => {
                let s = std::str::from_utf8(&bytes).unwrap();
                assert!(s.starts_with("HTTP/1.1 200 OK\r\n"));
                assert!(s.contains("Content-Length: 0\r\n"));
                assert!(s.ends_with("\r\n\r\n"));
            }
            Response::File { .. } | Response::Prebuilt(_) | Response::Reroute(_) | Response::Proxy(_) => {
                panic!("expected buffered headers-only response for zero-length file")
            }
        }

        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn mime_table_lookup() {
        assert_eq!(mime_for(b"html"), b"text/html; charset=utf-8");
        assert_eq!(mime_for(b"HTML"), b"text/html; charset=utf-8");
        assert_eq!(mime_for(b"png"), b"image/png");
        assert_eq!(mime_for(b"unknown"), DEFAULT_MIME);
        assert_eq!(mime_for(b""), DEFAULT_MIME);
    }

    #[test]
    fn http_date_epoch() {
        assert_eq!(&format_http_date(0), b"Thu, 01 Jan 1970 00:00:00 GMT");
    }

    #[test]
    fn http_date_known_examples() {
        assert_eq!(
            &format_http_date(784111777),
            b"Sun, 06 Nov 1994 08:49:37 GMT"
        );
        assert_eq!(
            &format_http_date(951782400),
            b"Tue, 29 Feb 2000 00:00:00 GMT"
        );
    }

    #[test]
    fn http_date_round_trip() {
        for secs in [0, 1, 60, 784111777, 951782400, 1_700_000_000] {
            assert_eq!(parse_http_date(&format_http_date(secs)), Some(secs));
        }
    }

    #[test]
    fn http_date_rejects_pre_unix_epoch_year() {
        assert_eq!(parse_http_date(b"Mon, 01 Jan 1969 00:00:00 GMT"), None);
    }

    #[test]
    fn http_date_rejects_invalid_weekday_token() {
        assert_eq!(parse_http_date(b"Abc, 06 Nov 1994 08:49:37 GMT"), None);
    }

    // 784111777 is `Sun, 06 Nov 1994 08:49:37 GMT` — the canonical RFC 7231
    // example. Same instant rendered in each of the three accepted formats
    // must parse to the same epoch value.
    #[test]
    fn http_date_rfc850_parses_to_same_instant_as_imf() {
        assert_eq!(
            parse_http_date(b"Sunday, 06-Nov-94 08:49:37 GMT"),
            Some(784111777)
        );
    }

    #[test]
    fn http_date_asctime_parses_to_same_instant_as_imf() {
        assert_eq!(
            parse_http_date(b"Sun Nov  6 08:49:37 1994"),
            Some(784111777)
        );
    }

    #[test]
    fn http_date_asctime_two_digit_day() {
        // `16` has no leading space — the column layout makes `day` live at
        // bytes [8..10] in both cases.
        assert_eq!(
            parse_http_date(b"Wed Nov 16 08:49:37 1994"),
            parse_http_date(b"Wed, 16 Nov 1994 08:49:37 GMT"),
        );
    }

    #[test]
    fn http_date_rfc850_y2k_pivot_maps_two_digit_year() {
        // Per nginx / RFC 7231: `00..=69` → 2000..=2069, `70..=99` → 1970..=1999.
        // Probe both sides of the boundary.
        let rfc850_2069 = parse_http_date(b"Tuesday, 06-Nov-69 08:49:37 GMT").unwrap();
        let imf_2069 = parse_http_date(b"Tue, 06 Nov 2069 08:49:37 GMT").unwrap();
        assert_eq!(rfc850_2069, imf_2069);

        let rfc850_1970 = parse_http_date(b"Friday, 06-Nov-70 08:49:37 GMT").unwrap();
        let imf_1970 = parse_http_date(b"Fri, 06 Nov 1970 08:49:37 GMT").unwrap();
        assert_eq!(rfc850_1970, imf_1970);
    }

    #[test]
    fn http_date_rfc850_rejects_garbage_in_fixed_positions() {
        // Wrong separator between DD-MON.
        assert_eq!(parse_http_date(b"Sunday, 06 Nov-94 08:49:37 GMT"), None);
        // Unknown weekday token ("Funday" is the right length but not real).
        assert_eq!(parse_http_date(b"Funday, 06-Nov-94 08:49:37 GMT"), None);
        // Missing GMT suffix.
        assert_eq!(parse_http_date(b"Sunday, 06-Nov-94 08:49:37 UTC"), None);
    }

    #[test]
    fn http_date_asctime_rejects_garbage_in_fixed_positions() {
        // Trailing space instead of four-digit year.
        assert_eq!(parse_http_date(b"Sun Nov  6 08:49:37    "), None);
        // Letters in day slot.
        assert_eq!(parse_http_date(b"Sun Nov AB 08:49:37 1994"), None);
        // Month abbreviation unknown.
        assert_eq!(parse_http_date(b"Sun Zzz  6 08:49:37 1994"), None);
    }

    #[test]
    fn http_date_rejects_unknown_format_shapes() {
        // Comma at position 4 (neither 3 nor 6..=9) → straight reject, no
        // parser tries to handle this.
        assert_eq!(parse_http_date(b"Sunn, 06 Nov 1994 08:49:37 GMT"), None);
        // Empty input.
        assert_eq!(parse_http_date(b""), None);
    }

    #[test]
    fn format_http_date_renders_max_boundary_exactly() {
        // `MAX_HTTP_DATE_SECS` must match the literal ceiling the contract
        // promises. If the calendar walk or the constant ever drifts,
        // this lights up.
        assert_eq!(
            &format_http_date(MAX_HTTP_DATE_SECS),
            b"Fri, 31 Dec 9999 23:59:59 GMT"
        );
    }

    #[test]
    fn format_http_date_saturates_past_year_9999() {
        // Any u64 beyond the cap must still produce a well-formed
        // 29-byte IMF-fixdate pinned to the ceiling. No panics.
        let at_cap = format_http_date(MAX_HTTP_DATE_SECS);
        assert_eq!(format_http_date(MAX_HTTP_DATE_SECS + 1), at_cap);
        assert_eq!(format_http_date(MAX_HTTP_DATE_SECS + 86_400), at_cap);
        assert_eq!(format_http_date(u64::MAX), at_cap);
    }

    #[test]
    fn days_in_month_handles_century_rules() {
        assert_eq!(days_in_month(1900, 2), 28);
        assert_eq!(days_in_month(2000, 2), 29);
        assert_eq!(days_in_month(2100, 2), 28);
    }

    #[test]
    fn range_parser_table() {
        assert_eq!(
            parse_range(b"bytes=0-9", 100),
            RangeParse::Slice { start: 0, end: 9 }
        );
        assert_eq!(
            parse_range(b"bytes=0-", 100),
            RangeParse::Slice { start: 0, end: 99 }
        );
        assert_eq!(
            parse_range(b"bytes=-9", 100),
            RangeParse::Slice { start: 91, end: 99 }
        );
        assert_eq!(parse_range(b"bytes=9-0", 100), RangeParse::Ignore);
        assert_eq!(
            parse_range(b"bytes=1000-2000", 100),
            RangeParse::Unsatisfiable
        );
        assert_eq!(parse_range(b"items=0-9", 100), RangeParse::Ignore);
        assert_eq!(parse_range(b"bytes=0-9,20-29", 100), RangeParse::Ignore);
        assert_eq!(parse_range(b"bytes=wat", 100), RangeParse::Ignore);
        assert_eq!(parse_range(b"bytes=-1", 0), RangeParse::Unsatisfiable);
    }

    #[test]
    fn if_none_match_beats_if_modified_since() {
        let meta = meta(10, 100);
        let decision = decide(
            &meta,
            Conditionals {
                if_modified_since: Some(b"Thu, 01 Jan 1970 00:03:20 GMT"),
                if_unmodified_since: None,
                if_none_match: Some(b"W/\"999-999\""),
                if_match: None,
                range: None,
                if_range: None,
                last_modified_override: None,
            },
        );
        assert_eq!(decision, Decision::Full);
    }

    #[test]
    fn matching_if_none_match_returns_not_modified() {
        let meta = meta(10, 100);
        let decision = decide(
            &meta,
            Conditionals {
                if_modified_since: None,
                if_unmodified_since: None,
                if_none_match: Some(meta.etag.as_slice()),
                if_match: None,
                range: None,
                if_range: None,
                last_modified_override: None,
            },
        );
        assert_eq!(decision, Decision::NotModified);
    }

    #[test]
    fn if_modified_since_equal_to_mtime_is_not_modified() {
        // nginx compares `mtime <= since` unconditionally — no "is this
        // mtime fresh enough for a weak validator?" gate. An IMS that
        // exactly matches the file's mtime must 304, even when the file
        // was written within the last second. Tests in not_modified.t
        // rely on this with just-written files.
        let meta = meta(10, 999);
        let decision = decide(
            &meta,
            Conditionals {
                if_modified_since: Some(b"Thu, 01 Jan 1970 00:16:39 GMT"),
                if_unmodified_since: None,
                if_none_match: None,
                if_match: None,
                range: None,
                if_range: None,
                last_modified_override: None,
            },
        );
        assert_eq!(decision, Decision::NotModified);
    }

    #[test]
    fn if_modified_since_uses_overridden_last_modified_value() {
        // Filesystem mtime is much newer than the validator date; only the
        // override should make this 304.
        let meta = meta(10, 9_999);
        let decision = decide(
            &meta,
            Conditionals {
                if_modified_since: Some(b"Thu, 01 Jan 1970 00:00:01 GMT"),
                if_unmodified_since: None,
                if_none_match: None,
                if_match: None,
                range: None,
                if_range: None,
                last_modified_override: Some(b"Thu, 01 Jan 1970 00:00:01 GMT"),
            },
        );
        assert_eq!(decision, Decision::NotModified);
    }

    #[test]
    fn if_modified_since_is_ignored_when_last_modified_is_suppressed() {
        let meta = meta(10, 999);
        let decision = decide(
            &meta,
            Conditionals {
                if_modified_since: Some(b"Thu, 01 Jan 1970 00:16:39 GMT"),
                if_unmodified_since: None,
                if_none_match: None,
                if_match: None,
                range: None,
                if_range: None,
                last_modified_override: Some(b""),
            },
        );
        assert_eq!(decision, Decision::Full);
    }

    #[test]
    fn stale_if_unmodified_since_returns_precondition_failed() {
        let meta = meta(10, 120);
        let decision = decide(
            &meta,
            Conditionals {
                if_modified_since: None,
                if_unmodified_since: Some(b"Thu, 01 Jan 1970 00:01:00 GMT"),
                if_none_match: None,
                if_match: None,
                range: None,
                if_range: None,
                last_modified_override: None,
            },
        );
        assert_eq!(decision, Decision::PreconditionFailed);
    }

    #[test]
    fn if_unmodified_since_equal_last_modified_allows_request() {
        let meta = meta(10, 120);
        let decision = decide(
            &meta,
            Conditionals {
                if_modified_since: None,
                if_unmodified_since: Some(b"Thu, 01 Jan 1970 00:02:00 GMT"),
                if_none_match: None,
                if_match: None,
                range: None,
                if_range: None,
                last_modified_override: None,
            },
        );
        assert_eq!(decision, Decision::Full);
    }

    #[test]
    fn if_unmodified_since_is_ignored_when_if_match_is_present() {
        // If-Match is present and succeeds, so IUS must be ignored and
        // downstream validators are still evaluated.
        let meta = meta(10, 120);
        let decision = decide(
            &meta,
            Conditionals {
                if_modified_since: None,
                if_unmodified_since: Some(b"Thu, 01 Jan 1970 00:01:00 GMT"),
                if_none_match: Some(meta.etag.as_slice()),
                if_match: Some(meta.etag.as_slice()),
                range: None,
                if_range: None,
                last_modified_override: None,
            },
        );
        assert_eq!(decision, Decision::NotModified);
    }

    #[test]
    fn if_unmodified_since_uses_overridden_last_modified_value() {
        let meta = meta(10, 9_999);
        let decision = decide(
            &meta,
            Conditionals {
                if_modified_since: None,
                if_unmodified_since: Some(b"Thu, 01 Jan 1970 00:00:01 GMT"),
                if_none_match: None,
                if_match: None,
                range: None,
                if_range: None,
                last_modified_override: Some(b"Thu, 01 Jan 1970 00:00:01 GMT"),
            },
        );
        assert_eq!(decision, Decision::Full);
    }

    #[test]
    fn if_unmodified_since_is_ignored_when_last_modified_is_suppressed() {
        let meta = meta(10, 999);
        let decision = decide(
            &meta,
            Conditionals {
                if_modified_since: None,
                if_unmodified_since: Some(b"Thu, 01 Jan 1970 00:00:00 GMT"),
                if_none_match: None,
                if_match: None,
                range: None,
                if_range: None,
                last_modified_override: Some(b""),
            },
        );
        assert_eq!(decision, Decision::Full);
    }

    #[test]
    fn if_range_mismatch_falls_back_to_full_200() {
        let meta = meta(100, 100);
        let decision = decide(
            &meta,
            Conditionals {
                if_modified_since: None,
                if_unmodified_since: None,
                if_none_match: None,
                if_match: None,
                range: Some(b"bytes=0-9"),
                if_range: Some(b"W/\"other\""),
                last_modified_override: None,
            },
        );
        assert_eq!(decision, Decision::Full);
    }

    #[test]
    fn if_range_exact_etag_honors_range() {
        // Our emitted ETag is strong-form (`"hex-hex"`); a client echoing
        // it verbatim in If-Range must succeed and produce a 206.
        let meta = meta(100, 100);
        let decision = decide(
            &meta,
            Conditionals {
                if_modified_since: None,
                if_unmodified_since: None,
                if_none_match: None,
                if_match: None,
                range: Some(b"bytes=0-9"),
                if_range: Some(meta.etag.as_slice()),
                last_modified_override: None,
            },
        );
        assert_eq!(decision, Decision::Range { start: 0, end: 9 });
    }

    #[test]
    fn if_range_date_uses_overridden_last_modified_value() {
        // Filesystem mtime (100) does not match 1 second since epoch; the
        // override does.
        let meta = meta(100, 100);
        let decision = decide(
            &meta,
            Conditionals {
                if_modified_since: None,
                if_unmodified_since: None,
                if_none_match: None,
                if_match: None,
                range: Some(b"bytes=0-9"),
                if_range: Some(b"Thu, 01 Jan 1970 00:00:01 GMT"),
                last_modified_override: Some(b"Thu, 01 Jan 1970 00:00:01 GMT"),
            },
        );
        assert_eq!(decision, Decision::Range { start: 0, end: 9 });
    }

    #[test]
    fn if_range_weak_prefix_falls_back_to_full_200() {
        // `If-Range` ETag comparison is strong (§13.1.5); a client-side
        // weak marker (`W/…`) never matches and should drop the Range.
        let meta = meta(100, 100);
        let mut weak: Vec<u8> = b"W/".to_vec();
        weak.extend_from_slice(meta.etag.as_slice());
        let decision = decide(
            &meta,
            Conditionals {
                if_modified_since: None,
                if_unmodified_since: None,
                if_none_match: None,
                if_match: None,
                range: Some(b"bytes=0-9"),
                if_range: Some(&weak),
                last_modified_override: None,
            },
        );
        assert_eq!(decision, Decision::Full);
    }

    #[test]
    fn if_range_date_match_honors_range() {
        let meta = meta(100, 100);
        let decision = decide(
            &meta,
            Conditionals {
                if_modified_since: None,
                if_unmodified_since: None,
                if_none_match: None,
                if_match: None,
                range: Some(b"bytes=0-9"),
                if_range: Some(&meta.last_modified),
                last_modified_override: None,
            },
        );
        assert_eq!(decision, Decision::Range { start: 0, end: 9 });
    }

    #[test]
    fn if_none_match_star_returns_not_modified() {
        let meta = meta(10, 100);
        let decision = decide(
            &meta,
            Conditionals {
                if_modified_since: None,
                if_unmodified_since: None,
                if_none_match: Some(b"*"),
                if_match: None,
                range: None,
                if_range: None,
                last_modified_override: None,
            },
        );
        assert_eq!(decision, Decision::NotModified);
    }

    #[test]
    fn etag_is_hex_encoded() {
        // mtime 0x1a, size 0xff → "\"1a-ff\"". nginx emits strong-form
        // even though the tag's semantics are weak — tests expect the
        // leading quote so their capture regexes match.
        let tag = make_etag(0x1a, 0xff);
        assert_eq!(tag.as_slice(), b"\"1a-ff\"");
    }

    #[test]
    fn etag_fits_inline_buffer_at_max_inputs() {
        // Both u64 fields at their 16-hex-digit max — `"<16>-<16>"` is
        // exactly `Etag::MAX_LEN` bytes. If the inline-buffer capacity
        // or `make_etag`'s bookkeeping ever drift, this asserts it.
        let tag = make_etag(u64::MAX, u64::MAX);
        assert_eq!(tag.as_slice().len(), Etag::MAX_LEN);
        assert_eq!(tag.as_slice(), b"\"ffffffffffffffff-ffffffffffffffff\"");
    }

    #[test]
    fn etag_weak_comparison_accepts_both_forms() {
        // Our emitted tag is strong-form; on the client side weak (`W/`)
        // form must still match via weak comparison per RFC 9110 §13.2.2.
        let meta = meta(0x10, 0x100);
        let strong: &[u8] = meta.etag.as_slice();
        let weak: Vec<u8> = {
            let mut v = Vec::from(b"W/".as_slice());
            v.extend_from_slice(strong);
            v
        };
        for inm in [strong, weak.as_slice()] {
            let decision = decide(
                &meta,
                Conditionals {
                    if_modified_since: None,
                    if_unmodified_since: None,
                    if_none_match: Some(inm),
                    if_match: None,
                    range: None,
                    if_range: None,
                    last_modified_override: None,
                },
            );
            assert_eq!(decision, Decision::NotModified, "INM={:?}", inm);
        }
    }

    #[test]
    fn strong_etag_match_rejects_weak_client_tag() {
        let meta = meta(10, 100);
        let mut weak: Vec<u8> = b"W/".to_vec();
        weak.extend_from_slice(meta.etag.as_slice());
        assert!(!etag_list_matches_strong(&weak, meta.etag.as_slice()));
        assert!(etag_list_matches_strong(b"*", meta.etag.as_slice()));
    }

    #[test]
    fn etag_list_respects_comma_inside_quoted_tag() {
        // A single tag whose opaque body contains a literal comma — the
        // list parser must not split on the inner comma.
        let current = br#""a,b""#;
        assert!(etag_list_matches(br#""a,b""#, current));
        assert!(etag_list_matches(br#"W/"a,b""#, current));
        assert!(!etag_list_matches(br#""a", "b""#, current));
    }

    #[test]
    fn etag_list_scans_multiple_entries() {
        let current = br#""abc""#;
        assert!(etag_list_matches(br#""xyz", W/"abc""#, current));
        assert!(etag_list_matches(br#"W/"abc", "xyz""#, current));
        // Bare strong form in the list also matches (weak comparison).
        assert!(etag_list_matches(br#""xyz", "abc""#, current));
        assert!(!etag_list_matches(br#""xyz", "def""#, current));
    }

    #[test]
    fn etag_list_tolerates_garbage_entries() {
        // A malformed leading entry (no quotes) is skipped; later entries still evaluated.
        let current = br#"W/"abc""#;
        assert!(etag_list_matches(br#"*, W/"abc""#, current));
    }

    #[test]
    fn not_modified_response_has_no_content_length() {
        let meta = meta(10, 100);
        let out = build_not_modified_response(&meta, b"nginx/1.29.2");
        let s = std::str::from_utf8(&out).unwrap();
        assert!(s.starts_with("HTTP/1.1 304 Not Modified\r\n"));
        assert!(!s.contains("Content-Length:"));
        assert!(s.contains("Accept-Ranges: bytes\r\n"));
        assert!(s.ends_with("\r\n\r\n"));
    }

    #[test]
    fn content_headers_head_shape_has_no_body_bytes() {
        let meta = meta(5, 100);
        let out = build_content_headers(&meta, 200, None, b"nginx/1.29.2");
        let s = std::str::from_utf8(&out).unwrap();
        assert!(s.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(s.contains("Content-Length: 5\r\n"));
        assert!(s.contains("Content-Type: text/plain; charset=utf-8\r\n"));
        assert!(s.contains("Accept-Ranges: bytes\r\n"));
        assert!(s.contains("Last-Modified: "));
        assert!(s.contains("ETag: "));
        assert!(s.ends_with("\r\n\r\n"));
    }

    #[test]
    fn content_headers_206_include_content_range_without_body() {
        let meta = meta(100, 100);
        let out = build_content_headers(&meta, 206, Some((5, 14)), b"nginx/1.29.2");
        let s = std::str::from_utf8(&out).unwrap();
        assert!(s.starts_with("HTTP/1.1 206 Partial Content\r\n"));
        assert!(s.contains("Content-Length: 10\r\n"));
        assert!(s.contains("Content-Range: bytes 5-14/100\r\n"));
        assert!(s.ends_with("\r\n\r\n"));
    }

    #[test]
    fn range_not_satisfiable_includes_content_range() {
        let meta = meta(10, 100);
        let out = build_range_not_satisfiable_response(&meta, b"nginx/1.29.2");
        let s = std::str::from_utf8(&out).unwrap();
        assert!(s.starts_with("HTTP/1.1 416 Range Not Satisfiable\r\n"));
        assert!(s.contains("Content-Range: bytes */10\r\n"));
        assert!(s.contains("Content-Length: 0\r\n"));
    }

    #[test]
    fn sendfile_sends_large_bodies_as_file_and_keeps_small_ones_inline() {
        let dir = unique_dir();
        let small = dir.join("small.txt");
        let large = dir.join("large.txt");
        std::fs::write(&small, vec![b's'; (SENDFILE_MIN_BODY - 1) as usize]).unwrap();
        std::fs::write(&large, vec![b'l'; SENDFILE_MIN_BODY as usize]).unwrap();

        let serve = |path: &std::path::Path, sendfile: bool| {
            serve_path(open_for_test(path), Method::Get, no_cond(), b"nginx/1.29.2", sendfile)
        };
        assert!(matches!(serve(&small, true), Response::Owned(_)));
        assert!(matches!(serve(&large, true), Response::File { .. }));
        // sendfile off keeps the old rule: everything up to 8 KiB is inline.
        assert!(matches!(serve(&large, false), Response::Owned(_)));
    }

    /// The year/month walk `civil_from_days` replaced, kept as the oracle.
    fn civil_from_days_walk(days: u64) -> (u32, usize, u8) {
        const DAYS_PER_MONTH: [u64; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
        let mut year: u32 = 1970;
        let mut d = days;
        loop {
            let yd = if is_leap(year) { 366 } else { 365 };
            if d < yd {
                break;
            }
            d -= yd;
            year += 1;
        }
        let mut mon = 0usize;
        loop {
            let md = if mon == 1 && is_leap(year) { 29 } else { DAYS_PER_MONTH[mon] };
            if d < md {
                break;
            }
            d -= md;
            mon += 1;
        }
        (year, mon, (d + 1) as u8)
    }

    #[test]
    fn civil_from_days_matches_calendar_walk() {
        // Every day through 2400 covers a full 400-year Gregorian cycle
        // (including the 2100/2200/2300 non-leap centuries and 2400); then
        // a coprime stride plus the last day reaches the 9999 cap.
        let full_until = 157_000; // ~2399-11
        let last_day = MAX_HTTP_DATE_SECS / 86_400;
        let sampled = (full_until..=last_day).step_by(97).chain(std::iter::once(last_day));
        for days in (0..full_until).chain(sampled) {
            assert_eq!(civil_from_days(days), civil_from_days_walk(days), "day {days}");
        }
    }

}
