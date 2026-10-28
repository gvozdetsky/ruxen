//! The gzip filter: nginx's `ngx_http_gzip_filter_module` with the
//! `ngx_http_gzip_ok` checks of the core module (#93).
//!
//! It runs once per response, after the location, `error_page` and the
//! proxy have settled it, and only where `gzip on` (`ProcessMeta::gzip`).
//! A response it compresses gets `Content-Encoding: gzip`, loses
//! `Content-Length` and `Accept-Ranges`, and its ETag becomes weak, as in
//! nginx. A body already in memory (`return`, error pages, proxied
//! responses) is compressed whole and sent with the new `Content-Length`.
//! A file is compressed as it is sent (`stream_file_gzip`), chunked for
//! HTTP/1.1 and followed by a close for HTTP/1.0, since its compressed
//! length is unknown up front. Ranges (206) are not compressed.

use zlib_rs::{Deflate, DeflateConfig, DeflateFlush, Status};

use crate::phase::Response;

use super::PreparedGzip;

/// The parts of the request the filter looks at.
pub(crate) struct GzipRequest<'a> {
    pub http_11: bool,
    /// A HEAD request: a body in memory is empty because nothing is sent,
    /// not because the response has none.
    pub head_only: bool,
    pub accept_encoding: Option<&'a [u8]>,
    pub user_agent: Option<&'a [u8]>,
    pub via: bool,
    pub authorization: bool,
}

impl<'a> GzipRequest<'a> {
    pub(crate) fn from_headers(http_11: bool, headers_raw: &'a [u8]) -> Self {
        use super::lookup_request_header as h;
        GzipRequest {
            http_11,
            head_only: false,
            accept_encoding: h(headers_raw, b"accept-encoding"),
            user_agent: h(headers_raw, b"user-agent"),
            via: h(headers_raw, b"via").is_some(),
            authorization: h(headers_raw, b"authorization").is_some(),
        }
    }
}

/// gzip compresses this in-memory response (`filter` would): the range
/// filter, which nginx runs after gzip, then leaves it alone (#370).
pub(crate) fn compresses(gz: &PreparedGzip, req: &GzipRequest<'_>, response: &[u8]) -> bool {
    let Some(head_end) = response.windows(4).position(|w| w == b"\r\n\r\n") else {
        return false;
    };
    parse_head(&response[..head_end + 4])
        .is_some_and(|head| matches!(decide(gz, req, &head), Decision::Compress))
}

/// `ngx_http_gzip_header_filter`'s checks on the response alone.
fn candidate(gz: &PreparedGzip, head: &Head<'_>) -> bool {
    matches!(head.status, 200 | 403 | 404)
        && !head.content_encoding
        && !head.transfer_encoding
        && !head.content_length.is_some_and(|l| l < gz.min_length)
        && type_matches(gz, head.content_type)
}

/// Whether a whole static file of this type and size would be
/// compressed: then a `Range` is ignored and the client gets the whole
/// file, compressed, with a 200, as from nginx (its range filter runs
/// after gzip and finds no length).
pub(crate) fn would_compress(
    gz: &PreparedGzip,
    req: &GzipRequest<'_>,
    content_type: &[u8],
    size: u64,
) -> bool {
    let head = Head {
        status: 200,
        content_type: Some(content_type),
        content_length: Some(size),
        etag: true,
        last_modified: true,
        ..Head::default()
    };
    matches!(decide(gz, req, &head), Decision::Compress)
}

/// A static file's 206 or 416 under `gzip_vary`: nginx's gzip filter sees
/// the whole 200 before its range filter cuts or refuses it, so the 206 or
/// 416 carries `Vary` when the file is a gzip candidate (by type and
/// `gzip_min_length`).
#[cold]
#[inline(never)]
pub(crate) fn vary_cut_file(
    gz: &PreparedGzip,
    content_type: &[u8],
    size: u64,
    response: Response,
) -> Response {
    let head = Head {
        status: 200,
        content_type: Some(content_type),
        content_length: Some(size),
        ..Head::default()
    };
    if !gz.vary || !candidate(gz, &head) {
        return response;
    }
    match response {
        Response::Owned(bytes) if matches!(crate::worker::response_status(&bytes), 206 | 416) => {
            let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") else {
                return Response::Owned(bytes);
            };
            let mut out = rewrite_head(&bytes[..end + 4], true, None);
            out.extend_from_slice(&bytes[end + 4..]);
            Response::Owned(out)
        }
        Response::File { headers, body } if crate::worker::response_status(&headers) == 206 => {
            Response::File {
                headers: rewrite_head(&headers, true, None),
                body,
            }
        }
        other => other,
    }
}

/// How to send a file body that is compressed on the way out.
#[derive(Debug, Clone, Copy)]
pub(crate) struct GzipStream {
    pub level: u32,
    pub window_bits: u8,
    /// HTTP/1.1: chunked. HTTP/1.0: raw, and the connection closes after.
    pub chunked: bool,
}

/// What the response header says, as far as the filter cares.
#[derive(Default)]
struct Head<'a> {
    status: u16,
    content_type: Option<&'a [u8]>,
    content_length: Option<u64>,
    content_encoding: bool,
    transfer_encoding: bool,
    etag: bool,
    expires: Option<&'a [u8]>,
    date: Option<&'a [u8]>,
    cache_control: Option<&'a [u8]>,
    last_modified: bool,
}

fn parse_head(head: &[u8]) -> Option<Head<'_>> {
    let status = head
        .get(9..12)
        .and_then(|s| std::str::from_utf8(s).ok())
        .and_then(|s| s.parse().ok())?;
    let mut h = Head {
        status,
        ..Head::default()
    };
    for line in head.split(|&b| b == b'\n').skip(1) {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            continue;
        };
        let (name, value) = (&line[..colon], line[colon + 1..].trim_ascii());
        let is = |n: &[u8]| name.eq_ignore_ascii_case(n);
        if is(b"content-type") {
            h.content_type = Some(value);
        } else if is(b"content-length") {
            h.content_length = std::str::from_utf8(value).ok().and_then(|v| v.parse().ok());
        } else if is(b"content-encoding") {
            h.content_encoding |= !value.is_empty();
        } else if is(b"transfer-encoding") {
            h.transfer_encoding = true;
        } else if is(b"etag") {
            h.etag = true;
        } else if is(b"expires") {
            h.expires = Some(value);
        } else if is(b"date") {
            h.date = Some(value);
        } else if is(b"cache-control") {
            h.cache_control = Some(value);
        } else if is(b"last-modified") {
            h.last_modified = true;
        }
    }
    Some(h)
}

/// `ngx_http_test_content_type`: the type without parameters, matched
/// case-insensitively against `gzip_types`.
fn type_matches(gz: &PreparedGzip, content_type: Option<&[u8]>) -> bool {
    let Some(ct) = content_type else {
        return false;
    };
    if gz.any_type {
        return true;
    }
    let base = ct.split(|&b| b == b';').next().unwrap_or(ct).trim_ascii();
    gz.types
        .iter()
        .any(|t| t.as_bytes().eq_ignore_ascii_case(base))
}

/// `ngx_http_gzip_accept_encoding` / `ngx_http_gzip_quantity`: a `gzip`
/// token whose q-value, if any, is above zero.
pub(crate) fn accepts_gzip(ae: &[u8]) -> bool {
    if ae.len() < 4 {
        return false;
    }
    if ae.starts_with(b"gzip,") {
        return true;
    }
    let mut start = 0;
    let p = loop {
        let Some(off) = ae[start..]
            .windows(4)
            .position(|w| w.eq_ignore_ascii_case(b"gzip"))
        else {
            return false;
        };
        let p = start + off;
        if p == 0 || matches!(ae[p - 1], b',' | b' ') {
            break p + 4;
        }
        start = p + 4;
    };
    let mut i = p;
    // After the token: `,` or the end accept, `;` starts parameters.
    loop {
        match ae.get(i) {
            None | Some(b',') => return true,
            Some(b' ') => i += 1,
            Some(b';') => {
                i += 1;
                break;
            }
            Some(_) => return false,
        }
    }
    loop {
        match ae.get(i) {
            None => return true,
            Some(b'q' | b'Q') => {
                i += 1;
                break;
            }
            Some(b' ') => i += 1,
            Some(_) => return false,
        }
    }
    if ae.get(i) != Some(&b'=') || i + 2 > ae.len() {
        return false;
    }
    quantity(&ae[i + 1..]) > 0
}

/// `ngx_http_gzip_quantity`: q-value × 1000, 0 when invalid.
fn quantity(v: &[u8]) -> u32 {
    let mut it = v.iter();
    let q = match it.next() {
        Some(b'0') => 0,
        Some(b'1') => 1000,
        _ => return 0,
    };
    match it.next() {
        None | Some(b',' | b' ') => return q,
        Some(b'.') => {}
        Some(_) => return 0,
    }
    let (mut frac, mut n) = (0u32, 0);
    for &c in it {
        if matches!(c, b',' | b' ') {
            break;
        }
        // More than three digits is invalid, and would overflow `frac`.
        if !c.is_ascii_digit() || n == 3 {
            return 0;
        }
        frac = frac * 10 + u32::from(c - b'0');
        n += 1;
    }
    let total = q + frac * 10u32.pow(3 - n);
    if total > 1000 { 0 } else { total }
}

/// nginx's `r->headers_in.msie6` (ngx_http_user_agent): the first `MSIE `
/// followed by at least three bytes, version 4, 5 or 6 (6 without `SV1`
/// after it), and no `Opera` anywhere.
pub(crate) fn is_msie6(ua: &[u8]) -> bool {
    let find = |hay: &[u8], needle: &[u8]| hay.windows(needle.len()).any(|w| w == needle);
    let Some(at) = ua.windows(5).position(|w| w == b"MSIE ") else {
        return false;
    };
    if at + 7 >= ua.len() || ua[at + 6] != b'.' {
        return false;
    }
    let msie6 = match ua[at + 5] {
        b'4' | b'5' => true,
        b'6' => !find(&ua[at + 8..], b"SV1"),
        _ => false,
    };
    msie6 && !find(ua, b"Opera")
}

/// `ngx_http_gzip_ok`: may this client get a compressed response?
fn gzip_ok(gz: &PreparedGzip, req: &GzipRequest<'_>, head: &Head<'_>) -> bool {
    use crate::config::gzip_proxied as p;
    match req.accept_encoding {
        Some(ae) if accepts_gzip(ae) => {}
        _ => return false,
    }
    if gz.disable_msie6 && req.user_agent.is_some_and(is_msie6) {
        return false;
    }
    if !req.http_11 && !gz.http_10 {
        return false;
    }
    let proxied_ok = !req.via || {
        let f = gz.proxied;
        if f & p::OFF != 0 {
            false
        } else if f & p::ANY != 0 || (req.authorization && f & p::AUTH != 0) {
            true
        } else if let Some(expires) = head.expires {
            f & p::EXPIRED != 0
                && match crate::file::parse_http_date(expires) {
                    Some(exp) => {
                        let date = head
                            .date
                            .and_then(crate::file::parse_http_date)
                            .unwrap_or_else(|| {
                                std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .map_or(0, |d| d.as_secs())
                            });
                        exp < date
                    }
                    None => false,
                }
        } else if let Some(cc) = head.cache_control {
            let has = |token: &[u8]| {
                cc.split(|&b| b == b',')
                    .any(|t| t.trim_ascii().eq_ignore_ascii_case(token))
            };
            (f & p::NO_CACHE != 0 && has(b"no-cache"))
                || (f & p::NO_STORE != 0 && has(b"no-store"))
                || (f & p::PRIVATE != 0 && has(b"private"))
        } else {
            !(f & p::NO_LM != 0 && head.last_modified) && !(f & p::NO_ETAG != 0 && head.etag)
        }
    };
    if !proxied_ok {
        return false;
    }
    if let (Some(set), Some(ua)) = (&gz.disable, req.user_agent)
        && set.is_match(ua)
    {
        return false;
    }
    true
}

/// nginx's `ngx_http_gzip_filter_memory`: a smaller window for a short
/// known length ("the actual zlib window size is smaller by 262 bytes").
fn window_bits(content_length: Option<u64>) -> u8 {
    let mut wbits: u8 = 15;
    if let Some(len) = content_length.filter(|&l| l > 0) {
        while wbits > 9 && len < (1u64 << (wbits - 1)).saturating_sub(262) {
            wbits -= 1;
        }
    }
    wbits
}

/// Runs the filter over a settled response. Returns the response to send
/// and, for a file to compress on the way out, how to stream it.
pub(crate) fn filter(
    gz: &PreparedGzip,
    req: &GzipRequest<'_>,
    response: Response,
) -> (Response, Option<GzipStream>) {
    match response {
        Response::Prebuilt(bytes) => match filter_bytes(gz, req, bytes) {
            Some(out) => (Response::Owned(out), None),
            None => (Response::Prebuilt(bytes), None),
        },
        Response::Owned(bytes) => match filter_bytes(gz, req, &bytes) {
            Some(out) => (Response::Owned(out), None),
            None => (Response::Owned(bytes), None),
        },
        Response::File { headers, body } => {
            let Some(head) = parse_head(&headers) else {
                return (Response::File { headers, body }, None);
            };
            match decide(gz, req, &head) {
                Decision::Pass => (Response::File { headers, body }, None),
                Decision::Vary => {
                    let out = rewrite_head(&headers, gz.vary, None);
                    (Response::File { headers: out, body }, None)
                }
                Decision::Compress if body.len <= WHOLE_FILE_MAX => {
                    match compress_file(gz, req.http_11, &headers, body) {
                        Ok(out) => (Response::Owned(out), None),
                        // A read error: the plain path reports it.
                        Err(body) => (Response::File { headers, body }, None),
                    }
                }
                Decision::Compress => {
                    let stream = GzipStream {
                        level: gz.comp_level,
                        window_bits: window_bits(head.content_length),
                        chunked: req.http_11,
                    };
                    let framing: &[u8] = if req.http_11 {
                        b"Transfer-Encoding: chunked\r\n"
                    } else {
                        b""
                    };
                    let out = rewrite_head(&headers, gz.vary, Some(framing));
                    (Response::File { headers: out, body }, Some(stream))
                }
            }
        }
        // A proxied body relayed as it arrives (#88): compressed on the
        // way, as nginx's gzip filter does over the upstream's buffers.
        Response::ProxyStream(mut s) => {
            let decision = parse_head(&s.head).map(|head| {
                let compress = match decide(gz, req, &head) {
                    Decision::Pass => None,
                    Decision::Vary => Some(false),
                    Decision::Compress => Some(true),
                };
                (compress, window_bits(head.content_length))
            });
            match decision {
                Some((Some(true), window_bits)) => {
                    // No length; the worker frames the body (chunked, or
                    // the close for HTTP/1.0).
                    s.head = rewrite_head(&s.head, gz.vary, Some(b""));
                    s.gzip = Some(GzipStream {
                        level: gz.comp_level,
                        window_bits,
                        chunked: req.http_11,
                    });
                }
                Some((Some(false), _)) => s.head = rewrite_head(&s.head, gz.vary, None),
                _ => {}
            }
            (Response::ProxyStream(s), None)
        }
        other => (other, None),
    }
}

/// Files up to this size are read and compressed whole: the header and
/// the body then go out in one write (`compressed_response`), as other
/// bodies in memory do. Larger ones are streamed.
const WHOLE_FILE_MAX: u64 = 64 * 1024;

/// A small file read and compressed into a complete response; the file
/// back when it can't be read whole.
fn compress_file(
    gz: &PreparedGzip,
    http_11: bool,
    headers: &[u8],
    body: crate::phase::FileBody,
) -> Result<Vec<u8>, crate::phase::FileBody> {
    use std::os::unix::fs::FileExt;
    let len = body.len as usize;
    let mut buffers = BUFFER_POOL
        .with(|p| p.borrow_mut().pop())
        .unwrap_or_else(|| (Vec::new(), Vec::new()));
    let input = &mut buffers.0;
    if input.len() < len {
        input.resize(len, 0);
    }
    let file = std::fs::File::from(body.fd);
    let mut read = 0;
    while read < len {
        match file.read_at(&mut input[read..len], body.offset + read as u64) {
            Ok(0) | Err(_) => break,
            Ok(n) => read += n,
        }
    }
    let result = if read == len {
        let compressed = compress_all(&input[..len], gz.comp_level, window_bits(Some(body.len)));
        Ok(compressed_response(headers, gz.vary, http_11, &compressed))
    } else {
        Err(crate::phase::FileBody {
            fd: file.into(),
            offset: body.offset,
            len: body.len,
        })
    };
    BUFFER_POOL.with(|p| {
        let mut p = p.borrow_mut();
        if p.len() < DEFLATE_POOL_MAX {
            p.push(buffers);
        }
    });
    result
}

enum Decision {
    /// Not a candidate: the response goes out as it is.
    Pass,
    /// A candidate the client can't take: only `Vary` (with `gzip_vary`).
    Vary,
    Compress,
}

/// `ngx_http_gzip_header_filter`'s checks, then `ngx_http_gzip_ok`.
fn decide(gz: &PreparedGzip, req: &GzipRequest<'_>, head: &Head<'_>) -> Decision {
    if !candidate(gz, head) {
        return Decision::Pass;
    }
    if gzip_ok(gz, req, head) {
        Decision::Compress
    } else if gz.vary {
        Decision::Vary
    } else {
        Decision::Pass
    }
}

/// A whole response in memory: `None` when it goes out unchanged.
fn filter_bytes(gz: &PreparedGzip, req: &GzipRequest<'_>, bytes: &[u8]) -> Option<Vec<u8>> {
    let head_end = bytes.windows(4).position(|w| w == b"\r\n\r\n")?;
    let headers = &bytes[..head_end + 4];
    let body = &bytes[head_end + 4..];
    let head = parse_head(headers)?;
    match decide(gz, req, &head) {
        Decision::Pass => None,
        Decision::Vary => {
            let mut out = rewrite_head(headers, gz.vary, None);
            out.extend_from_slice(body);
            Some(out)
        }
        Decision::Compress => {
            // A HEAD response gets the compressed response's header only,
            // without a length, as nginx's (its header filter runs before
            // the body is known). An empty body of a GET is compressed, as
            // nginx does (20 bytes of gzip, proxy_cache.t).
            if body.is_empty() && req.head_only {
                return Some(rewrite_head(headers, gz.vary, Some(b"")));
            }
            let compressed =
                compress_all(body, gz.comp_level, window_bits(Some(body.len() as u64)));
            Some(compressed_response(
                headers,
                gz.vary,
                req.http_11,
                &compressed,
            ))
        }
    }
}

/// A response compressed whole, framed as nginx frames it: its gzip filter
/// drops the length (ngx_http_clear_content_length), so HTTP/1.1 gets
/// the body as one chunk (proxy_cache.t). HTTP/1.0 keeps a
/// `Content-Length`, where nginx would end with the connection; it
/// compresses for HTTP/1.0 only with `gzip_http_version 1.0`.
fn compressed_response(headers: &[u8], vary: bool, http_11: bool, compressed: &[u8]) -> Vec<u8> {
    let mut framing = Vec::with_capacity(40);
    if http_11 {
        framing.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
    } else {
        framing.extend_from_slice(b"Content-Length: ");
        framing.extend_from_slice(compressed.len().to_string().as_bytes());
        framing.extend_from_slice(b"\r\n");
    }
    let mut out = rewrite_head(headers, vary, Some(&framing));
    out.reserve(compressed.len() + 16);
    if http_11 {
        out.extend_from_slice(format!("{:x}\r\n", compressed.len()).as_bytes());
        out.extend_from_slice(compressed);
        out.extend_from_slice(b"\r\n0\r\n\r\n");
    } else {
        out.extend_from_slice(compressed);
    }
    out
}

/// The header block with gzip's changes. `framing`: `None` keeps the
/// response as it is apart from `Vary`; `Some(lines)` makes it the
/// compressed response, with `lines` (a new length or chunked) added.
fn rewrite_head(headers: &[u8], vary: bool, framing: Option<&[u8]>) -> Vec<u8> {
    let end = headers
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or(headers.len());
    let mut out = Vec::with_capacity(headers.len() + 96);
    let mut lines = headers[..end].split(|&b| b == b'\n');
    if let Some(status) = lines.next() {
        out.extend_from_slice(status);
        out.push(b'\n');
    }
    for line in lines {
        let bare = line.strip_suffix(b"\r").unwrap_or(line);
        let name = bare
            .iter()
            .position(|&b| b == b':')
            .map_or(bare, |c| &bare[..c]);
        if framing.is_some() {
            if name.eq_ignore_ascii_case(b"content-length")
                || name.eq_ignore_ascii_case(b"accept-ranges")
            {
                continue;
            }
            // ngx_http_weak_etag: a strong ETag becomes weak.
            if name.eq_ignore_ascii_case(b"etag") {
                let value = bare[name.len() + 1..].trim_ascii();
                if value.starts_with(b"\"") {
                    out.extend_from_slice(b"ETag: W/");
                    out.extend_from_slice(value);
                    out.extend_from_slice(b"\r\n");
                    continue;
                }
            }
        }
        out.extend_from_slice(bare);
        out.extend_from_slice(b"\r\n");
    }
    if let Some(extra) = framing {
        out.extend_from_slice(b"Content-Encoding: gzip\r\n");
        out.extend_from_slice(extra);
    }
    if vary {
        out.extend_from_slice(b"Vary: Accept-Encoding\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out
}

/// The zlib-rs level for nginx's `gzip_comp_level`. zlib-rs, like
/// zlib-ng, runs level 1 as `deflate_quick`, whose output is far larger
/// than zlib's level 1 (an 8 KiB HTML page 30 % larger, a 2 MiB stylesheet
/// 82 %); its level 2 matches zlib's level 1 in size. The other levels
/// are close to zlib's.
fn zlib_level(level: u32) -> i32 {
    if level == 1 { 2 } else { level as i32 }
}

/// A gzip deflate state sized like nginx's (`ngx_http_gzip_filter_memory`):
/// memLevel shrinks with the window, so a short body's hash table, which
/// every reset clears, is small too.
fn new_deflate(level: u32, window_bits: u8) -> Deflate {
    Deflate::new_with_config(DeflateConfig {
        level: zlib_level(level),
        // 16 + bits: a gzip header and trailer around the deflate data.
        window_bits: 16 + i32::from(window_bits),
        mem_level: (8 - (15 - i32::from(window_bits))).max(1),
        ..DeflateConfig::default()
    })
}

/// One `deflate` call into the spare capacity of `out`.
fn deflate_into(
    d: &mut Deflate,
    input: &[u8],
    out: &mut Vec<u8>,
    flush: DeflateFlush,
) -> Option<Status> {
    let before = d.total_out();
    let res = d.compress_uninit(input, out.spare_capacity_mut(), flush);
    let produced = (d.total_out() - before) as usize;
    // SAFETY: deflate initialized the `produced` bytes it wrote at the
    // start of the spare capacity.
    unsafe { out.set_len(out.len() + produced) };
    res.ok()
}

thread_local! {
    /// This worker's idle deflate states, by (level, window bits). A
    /// deflate state is a few hundred KiB, which glibc maps and unmaps for
    /// every allocation that size: per response, the page faults, the
    /// zeroing and the TLB shootdowns across worker threads cost as much
    /// as compressing (gzip_html_8k: 51 % of nginx). nginx takes the same
    /// memory from the request pool. Reused states are only reset.
    static DEFLATE_POOL: std::cell::RefCell<Vec<(u32, u8, Deflate)>> =
        const { std::cell::RefCell::new(Vec::new()) };
    /// Read and output buffers of `stream_file_gzip`, for the same reason:
    /// freed per response, glibc's thread arenas hand their pages back
    /// (top-chunk trim) and the next response faults them in again.
    static BUFFER_POOL: std::cell::RefCell<Vec<(Vec<u8>, Vec<u8>)>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// Idle states kept per worker: one per response being compressed at
/// the same moment, which for whole bodies is one.
const DEFLATE_POOL_MAX: usize = 16;

fn take_compress(level: u32, window_bits: u8) -> Deflate {
    let pooled = DEFLATE_POOL.with(|p| {
        let mut p = p.borrow_mut();
        let i = p
            .iter()
            .position(|(l, w, _)| *l == level && *w == window_bits)?;
        Some(p.swap_remove(i).2)
    });
    match pooled {
        Some(mut c) => {
            c.reset();
            c
        }
        None => new_deflate(level, window_bits),
    }
}

fn give_compress(level: u32, window_bits: u8, c: Deflate) {
    DEFLATE_POOL.with(|p| {
        let mut p = p.borrow_mut();
        if p.len() < DEFLATE_POOL_MAX {
            p.push((level, window_bits, c));
        }
    });
}

/// A complete gzip member of `body`.
pub(crate) fn compress_all(body: &[u8], level: u32, window_bits: u8) -> Vec<u8> {
    let mut c = take_compress(level, window_bits);
    let mut out = Vec::with_capacity(body.len() / 2 + 64);
    loop {
        let consumed = c.total_in() as usize;
        match deflate_into(&mut c, &body[consumed..], &mut out, DeflateFlush::Finish) {
            Some(Status::StreamEnd) => break,
            Some(_) => out.reserve(out.capacity().max(4096)),
            // Only on misuse of the stream; an empty member would be
            // wrong, so keep what deflate made and stop.
            None => break,
        }
    }
    give_compress(level, window_bits, c);
    out
}

/// A streaming compressor for a file body: feed blocks, get gzip bytes.
/// Its deflate state and its two buffers go back to the worker's pools
/// when dropped.
pub(crate) struct Deflater {
    c: Option<Deflate>,
    level: u32,
    window_bits: u8,
    /// File blocks are read into this one.
    pub(crate) input: Vec<u8>,
    /// Compressed bytes (with chunk framing) are written from this one.
    pub(crate) out: Vec<u8>,
}

impl Deflater {
    pub(crate) fn new(stream: GzipStream) -> Self {
        let (input, out) = BUFFER_POOL
            .with(|p| p.borrow_mut().pop())
            .unwrap_or_else(|| (Vec::new(), Vec::new()));
        Deflater {
            c: Some(take_compress(stream.level, stream.window_bits)),
            level: stream.level,
            window_bits: stream.window_bits,
            input,
            out,
        }
    }

    /// Compresses `input` into `out` (appending); `last` finishes the
    /// member.
    pub(crate) fn push(&mut self, input: &[u8], out: &mut Vec<u8>, last: bool) {
        let Some(c) = self.c.as_mut() else {
            return;
        };
        let flush = if last {
            DeflateFlush::Finish
        } else {
            DeflateFlush::NoFlush
        };
        let start = c.total_in();
        loop {
            let used = (c.total_in() - start) as usize;
            if out.capacity() - out.len() < 1024 {
                out.reserve(input.len().max(8192));
            }
            match deflate_into(c, &input[used..], out, flush) {
                Some(Status::StreamEnd) => return,
                Some(_) => {
                    let used = (c.total_in() - start) as usize;
                    // Not finishing: done once all input is taken and
                    // deflate had room left (it isn't holding output back).
                    if !last && used == input.len() && out.capacity() > out.len() {
                        return;
                    }
                }
                None => return,
            }
        }
    }
}

impl Drop for Deflater {
    fn drop(&mut self) {
        if let Some(c) = self.c.take() {
            give_compress(self.level, self.window_bits, c);
        }
        let buffers = (
            std::mem::take(&mut self.input),
            std::mem::take(&mut self.out),
        );
        BUFFER_POOL.with(|p| {
            let mut p = p.borrow_mut();
            if p.len() < DEFLATE_POOL_MAX {
                p.push(buffers);
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn gunzip(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        flate2::read::GzDecoder::new(data)
            .read_to_end(&mut out)
            .unwrap();
        out
    }

    fn gz(types: &'static [&'static str]) -> PreparedGzip {
        PreparedGzip {
            any_type: false,
            types,
            min_length: 20,
            comp_level: 1,
            vary: true,
            http_10: false,
            proxied: crate::config::gzip_proxied::OFF,
            disable_msie6: false,
            disable: None,
        }
    }

    fn req(ae: Option<&'static [u8]>) -> GzipRequest<'static> {
        GzipRequest {
            http_11: true,
            head_only: false,
            accept_encoding: ae,
            user_agent: None,
            via: false,
            authorization: false,
        }
    }

    const RESP: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 64\r\n\
        Accept-Ranges: bytes\r\nETag: \"abc\"\r\n\r\n\
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";

    #[test]
    fn accept_encoding_like_nginx() {
        for ok in [
            &b"gzip"[..],
            b"gzip, deflate",
            b"deflate, gzip",
            b"GZIP",
            b"gzip;q=0.5",
            b"gzip; q=1",
            b"gzip;q=0.001",
        ] {
            assert!(accepts_gzip(ok), "{}", String::from_utf8_lossy(ok));
        }
        for no in [
            &b"deflate"[..],
            b"gzip;q=0",
            b"gzip;q=0.000",
            b"xgzip",
            b"gzipx",
            b"gzip;q=1.5",
            b"gzip;q=0.0001",
            // Overflowed the fraction before the length check (#477).
            b"gzip;q=0.99999999999999999999",
        ] {
            assert!(!accepts_gzip(no), "{}", String::from_utf8_lossy(no));
        }
    }

    #[test]
    fn msie6_as_nginx_user_agent() {
        for yes in [
            &b"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)"[..],
            b"Mozilla/4.0 (compatible; MSIE 5.5; Windows 98)",
            b"MSIE 4.01",
            b"MSIE 6.0",
            // `SV1` counts after the version only (msie + 8).
            b"MSIE 6.SV1",
        ] {
            assert!(is_msie6(yes), "{}", String::from_utf8_lossy(yes));
        }
        for no in [
            &b"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)"[..],
            b"Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)",
            // Too short: nginx wants three bytes after `MSIE `.
            b"MSIE 6.",
            // Opera said it was MSIE; nginx clears msie then.
            b"Opera/9.80 (compatible; MSIE 6.0; Windows NT 5.1)",
            b"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1) Opera 7.54",
        ] {
            assert!(!is_msie6(no), "{}", String::from_utf8_lossy(no));
        }
    }

    #[test]
    fn compresses_a_buffered_response() {
        let conf = gz(&["text/html"]);
        let (out, stream) = filter(&conf, &req(Some(b"gzip")), Response::Prebuilt(RESP));
        assert!(stream.is_none());
        let Response::Owned(bytes) = out else {
            panic!("not owned");
        };
        let end = bytes.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
        let head = String::from_utf8_lossy(&bytes[..end]);
        assert!(head.contains("Content-Encoding: gzip"), "{head}");
        assert!(head.contains("ETag: W/\"abc\""), "{head}");
        assert!(head.contains("Vary: Accept-Encoding"), "{head}");
        assert!(!head.contains("Accept-Ranges"), "{head}");
        // nginx's framing: no length, the body as one chunk.
        assert!(head.contains("Transfer-Encoding: chunked"), "{head}");
        assert!(!head.contains("Content-Length"), "{head}");
        let chunked = &bytes[end + 4..];
        let crlf = chunked.windows(2).position(|w| w == b"\r\n").unwrap();
        let size =
            usize::from_str_radix(std::str::from_utf8(&chunked[..crlf]).unwrap(), 16).unwrap();
        let body = &chunked[crlf + 2..crlf + 2 + size];
        assert_eq!(&chunked[crlf + 2 + size..], b"\r\n0\r\n\r\n");
        assert_eq!(gunzip(body), vec![b'X'; 64]);

        // HTTP/1.0 (`gzip_http_version 1.0`) keeps a length: it has no
        // chunked framing.
        let conf_10 = PreparedGzip {
            http_10: true,
            ..gz(&["text/html"])
        };
        let old = GzipRequest {
            http_11: false,
            ..req(Some(b"gzip"))
        };
        let (out, _) = filter(&conf_10, &old, Response::Prebuilt(RESP));
        let Response::Owned(bytes) = out else {
            panic!("not owned");
        };
        let end = bytes.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
        let head = String::from_utf8_lossy(&bytes[..end]);
        let body = &bytes[end + 4..];
        assert!(
            head.contains(&format!("Content-Length: {}", body.len())),
            "{head}"
        );
        assert_eq!(gunzip(body), vec![b'X'; 64]);
    }

    #[test]
    fn leaves_what_nginx_leaves() {
        let conf = gz(&["text/html"]);
        // No Accept-Encoding: only Vary.
        let (out, _) = filter(&conf, &req(None), Response::Prebuilt(RESP));
        let Response::Owned(bytes) = out else {
            panic!("vary expected");
        };
        assert!(String::from_utf8_lossy(&bytes).contains("Vary: Accept-Encoding"));
        assert!(!String::from_utf8_lossy(&bytes).contains("Content-Encoding"));
        // Other type, short body, other status: untouched.
        for resp in [
            &b"HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: 64\r\n\r\n"[..],
            b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 5\r\n\r\nhello",
            b"HTTP/1.1 302 Found\r\nContent-Type: text/html\r\nContent-Length: 64\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Encoding: br\r\n\r\n",
        ] {
            let leaked: &'static [u8] = Box::leak(resp.to_vec().into_boxed_slice());
            let (out, _) = filter(&conf, &req(Some(b"gzip")), Response::Prebuilt(leaked));
            assert!(matches!(out, Response::Prebuilt(_)));
        }
    }

    #[test]
    fn deflater_streams_a_member() {
        let data: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let mut d = Deflater::new(GzipStream {
            level: 1,
            window_bits: 15,
            chunked: true,
        });
        let mut out = Vec::new();
        for (i, block) in data.chunks(65536).enumerate() {
            let last = (i + 1) * 65536 >= data.len();
            d.push(block, &mut out, last);
        }
        assert_eq!(gunzip(&out), data);
    }

    #[test]
    fn pooled_states_make_valid_members() {
        for i in 0..5 {
            let body = vec![b'a' + i as u8; 1000 + i * 100];
            assert_eq!(gunzip(&compress_all(&body, 1, 12)), body);
        }
    }

    #[test]
    fn window_shrinks_for_short_bodies() {
        assert_eq!(window_bits(None), 15);
        assert_eq!(window_bits(Some(64)), 9);
        assert_eq!(window_bits(Some(1 << 20)), 15);
    }
}
