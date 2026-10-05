// HTTP/1.1 request parser + response pre-builder.
//
// Zero-alloc on the hot path: the parser never copies or owns bytes from the
// input buffer — it returns offsets into the caller's buffer. The response is
// built once at startup and written verbatim on every matching request.

/// Per-connection read buffer size. nginx defaults to 1024 B
/// (`client_header_buffer_size`), but on our allocator (glibc malloc on
/// kernel 6.17) an 8 KiB alloc round-trip turned out measurably *cheaper*
/// than 1 KiB on the benchmark (likely different glibc size-class paths).
/// So we stay at 8 KiB and take the win.
pub const READ_BUF: usize = 8192;

/// Parsed request — all byte ranges index into the caller's buffer.
#[derive(Debug)]
pub struct Request {
    pub method_start: usize,
    pub method_end: usize,
    pub path_start: usize,
    pub path_end: usize,
    /// Absolute-form requests may omit the path (`GET http://host HTTP/1.0`);
    /// in that case the effective URI is `/`.
    pub implicit_path: bool,
    pub keep_alive: bool,
    /// Did the request use HTTP/1.1? (Missing Host on HTTP/1.1 is a 400;
    /// HTTP/1.0 is allowed through.)
    pub http_11: bool,
    /// Raw range of the `Host` header value. Port-stripping, lowercasing,
    /// trailing-dot trimming, and validation happen later in-place on the
    /// worker's mutable read buffer.
    pub host: Option<(usize, usize)>,
    /// Raw authority from an absolute-form or CONNECT request line. Like
    /// `host`, this is validated later on the mutable worker buffer.
    pub request_line_host: Option<(usize, usize)>,
    /// Query string bytes (including the leading `?`) captured when the
    /// request target is absolute-form with no path, e.g.
    /// `GET http://host?args HTTP/1.1`. The worker splices these after a
    /// synthesized `/` to produce the effective request URI.
    pub absolute_query: Option<(usize, usize)>,
    pub if_modified_since: Option<(usize, usize)>,
    pub if_unmodified_since: Option<(usize, usize)>,
    pub if_none_match: Option<(usize, usize)>,
    pub if_match: Option<(usize, usize)>,
    pub range: Option<(usize, usize)>,
    pub if_range: Option<(usize, usize)>,
    /// Parsed `Content-Length` value. None means no header / not numeric.
    /// The worker buffers this body form before proxy forwarding.
    pub content_length: Option<u64>,
    /// `Transfer-Encoding: chunked` flag. Set when any token in the value
    /// is `chunked` (case-insensitive). The worker validates the header
    /// shape, decodes chunked request bodies, and passes decoded bytes to
    /// `$request_body` / proxy forwarding.
    #[allow(dead_code)]
    pub transfer_encoding_chunked: bool,
    /// Byte range of the raw header block — from the first byte after the
    /// request line's CRLF to (but not including) the terminating blank
    /// line. Used by `$http_NAME` expansion, which has to scan by name at
    /// render time because only a handful of headers are classified
    /// during parse.
    pub headers_start: usize,
    pub headers_end: usize,
    /// Number of bytes consumed from the input buffer (end of headers).
    pub consumed: usize,
}

/// Classification of the request method. Only `GET` and `HEAD` are handled
/// by any current handler; everything else answers 405. Keep this as a
/// small enum rather than a full method table — nginx's `NGX_HTTP_*`
/// bitmask is only useful when modules specify `allowed_methods`.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Method {
    Get,
    Head,
    Trace,
    Connect,
    Other,
}

pub fn classify_method(bytes: &[u8]) -> Method {
    match bytes {
        b"GET" => Method::Get,
        b"HEAD" => Method::Head,
        b"TRACE" => Method::Trace,
        b"CONNECT" => Method::Connect,
        _ => Method::Other,
    }
}

/// Incremental parse state carried across reads on the same connection. Lets
/// the parser resume mid-request without re-scanning the bytes it already
/// validated — matches how nginx's `ngx_http_parse_*` save `b->pos` and
/// `r->state` on NGX_AGAIN.
///
/// Safe stopping points are between complete lines: after the request line's
/// CRLF, and after each header's CRLF. Partial lines re-parse from the saved
/// line start, but completed lines are never rescanned.
#[derive(Debug, Default)]
pub struct ParseState {
    /// Offset into the caller's buffer at which the *next* line starts.
    /// Advances only after a complete CRLF-terminated line.
    pub cursor: usize,
    pub rline_done: bool,
    pub method_start: usize,
    pub method_end: usize,
    pub path_start: usize,
    pub path_end: usize,
    pub implicit_path: bool,
    pub keep_alive: bool,
    pub http_11: bool,
    /// Offset of the first byte of the header block (= byte after the
    /// request line's terminator). Captured once the request line is
    /// complete so it survives Incomplete resumes.
    pub headers_start: usize,
    /// Raw Host header value range. Validation happens later on the mutable
    /// read buffer.
    pub host_start: usize,
    pub host_end: usize,
    pub has_host: bool,
    pub request_line_host_start: usize,
    pub request_line_host_end: usize,
    pub has_request_line_host: bool,
    pub absolute_query_start: usize,
    pub absolute_query_end: usize,
    pub has_absolute_query: bool,
    pub if_modified_since_start: usize,
    pub if_modified_since_end: usize,
    pub has_if_modified_since: bool,
    pub if_unmodified_since_start: usize,
    pub if_unmodified_since_end: usize,
    pub has_if_unmodified_since: bool,
    pub if_none_match_start: usize,
    pub if_none_match_end: usize,
    pub has_if_none_match: bool,
    pub if_match_start: usize,
    pub if_match_end: usize,
    pub has_if_match: bool,
    pub range_start: usize,
    pub range_end: usize,
    pub has_range: bool,
    pub if_range_start: usize,
    pub if_range_end: usize,
    pub has_if_range: bool,
    pub content_length: Option<u64>,
    pub has_content_length: bool,
    pub transfer_encoding_chunked: bool,
    pub has_transfer_encoding: bool,
    pub has_content_range: bool,
    pub has_expect: bool,
    pub has_authorization: bool,
}

impl ParseState {
    pub fn reset(&mut self) {
        *self = ParseState::default();
    }
}

#[derive(Debug)]
pub enum Parse {
    Complete(Request),
    Incomplete,
    Invalid,
}

pub fn parse_request(buf: &[u8], st: &mut ParseState) -> Parse {
    let n = buf.len();

    if !st.rline_done {
        match parse_request_line(buf, st.cursor) {
            LineParse::Ok {
                next,
                method_start,
                method_end,
                path_start,
                path_end,
                implicit_path,
                request_line_host,
                absolute_query,
                http_11,
            } => {
                st.rline_done = true;
                st.cursor = next;
                st.headers_start = next;
                st.method_start = method_start;
                st.method_end = method_end;
                st.path_start = path_start;
                st.path_end = path_end;
                st.implicit_path = implicit_path;
                st.keep_alive = http_11;
                st.http_11 = http_11;
                if let Some((start, end)) = request_line_host {
                    st.request_line_host_start = start;
                    st.request_line_host_end = end;
                    st.has_request_line_host = true;
                }
                if let Some((start, end)) = absolute_query {
                    st.absolute_query_start = start;
                    st.absolute_query_end = end;
                    st.has_absolute_query = true;
                }
            }
            LineParse::Incomplete => return Parse::Incomplete,
            LineParse::Invalid => return Parse::Invalid,
        }
    }

    // Header loop. Each iteration either: (a) consumes a full header line and
    // advances `cursor`, (b) recognizes the terminating blank line and
    // finishes, or (c) returns Incomplete without advancing `cursor`.
    loop {
        let i = st.cursor;
        if i >= n {
            return Parse::Incomplete;
        }
        if buf[i] == b'\n' {
            return Parse::Complete(Request {
                method_start: st.method_start,
                method_end: st.method_end,
                path_start: st.path_start,
                path_end: st.path_end,
                implicit_path: st.implicit_path,
                keep_alive: st.keep_alive,
                http_11: st.http_11,
                host: if st.has_host {
                    Some((st.host_start, st.host_end))
                } else {
                    None
                },
                request_line_host: if st.has_request_line_host {
                    Some((st.request_line_host_start, st.request_line_host_end))
                } else {
                    None
                },
                absolute_query: if st.has_absolute_query {
                    Some((st.absolute_query_start, st.absolute_query_end))
                } else {
                    None
                },
                if_modified_since: if st.has_if_modified_since {
                    Some((st.if_modified_since_start, st.if_modified_since_end))
                } else {
                    None
                },
                if_unmodified_since: if st.has_if_unmodified_since {
                    Some((st.if_unmodified_since_start, st.if_unmodified_since_end))
                } else {
                    None
                },
                if_none_match: if st.has_if_none_match {
                    Some((st.if_none_match_start, st.if_none_match_end))
                } else {
                    None
                },
                if_match: if st.has_if_match {
                    Some((st.if_match_start, st.if_match_end))
                } else {
                    None
                },
                range: if st.has_range {
                    Some((st.range_start, st.range_end))
                } else {
                    None
                },
                if_range: if st.has_if_range {
                    Some((st.if_range_start, st.if_range_end))
                } else {
                    None
                },
                headers_start: st.headers_start,
                content_length: st.content_length,
                transfer_encoding_chunked: st.transfer_encoding_chunked,
                headers_end: i,
                consumed: i + 1,
            });
        }
        if buf[i] == b'\r' {
            if i + 1 >= n {
                return Parse::Incomplete;
            }
            if buf[i + 1] != b'\n' {
                return Parse::Invalid;
            }
            return Parse::Complete(Request {
                method_start: st.method_start,
                method_end: st.method_end,
                path_start: st.path_start,
                path_end: st.path_end,
                implicit_path: st.implicit_path,
                keep_alive: st.keep_alive,
                http_11: st.http_11,
                host: if st.has_host {
                    Some((st.host_start, st.host_end))
                } else {
                    None
                },
                request_line_host: if st.has_request_line_host {
                    Some((st.request_line_host_start, st.request_line_host_end))
                } else {
                    None
                },
                absolute_query: if st.has_absolute_query {
                    Some((st.absolute_query_start, st.absolute_query_end))
                } else {
                    None
                },
                if_modified_since: if st.has_if_modified_since {
                    Some((st.if_modified_since_start, st.if_modified_since_end))
                } else {
                    None
                },
                if_unmodified_since: if st.has_if_unmodified_since {
                    Some((st.if_unmodified_since_start, st.if_unmodified_since_end))
                } else {
                    None
                },
                if_none_match: if st.has_if_none_match {
                    Some((st.if_none_match_start, st.if_none_match_end))
                } else {
                    None
                },
                if_match: if st.has_if_match {
                    Some((st.if_match_start, st.if_match_end))
                } else {
                    None
                },
                range: if st.has_range {
                    Some((st.range_start, st.range_end))
                } else {
                    None
                },
                if_range: if st.has_if_range {
                    Some((st.if_range_start, st.if_range_end))
                } else {
                    None
                },
                headers_start: st.headers_start,
                content_length: st.content_length,
                transfer_encoding_chunked: st.transfer_encoding_chunked,
                headers_end: i,
                consumed: i + 2,
            });
        }

        match parse_header_line(buf, i) {
            HeaderParse::Ok {
                next,
                known,
                val_start,
                val_end,
            } => {
                match known {
                    Some(KnownHeader::Connection) => {
                        // RFC 7230 §6.1: the field value is a comma-separated
                        // token list. `close` wins over `keep-alive` if both
                        // appear. Real-world clients send things like
                        // `close, upgrade` or `Upgrade, keep-alive` — an
                        // exact-match compare misses both, stranding the
                        // connection on whatever the HTTP-version default was.
                        // nginx does roughly the same via `ngx_strcasestrn`
                        // (a case-insensitive substring search) at
                        // `ngx_http_request.c:1925-1930`; we use token
                        // scanning so that `Connection: closely` doesn't
                        // over-match.
                        let v = &buf[val_start..val_end];
                        if connection_has_token(v, b"close") {
                            st.keep_alive = false;
                        } else if connection_has_token(v, b"keep-alive") {
                            st.keep_alive = true;
                        }
                    }
                    Some(KnownHeader::Host) => {
                        // Duplicate Host headers: RFC 7230 §5.4 says "MUST
                        // respond with 400". Match nginx's
                        // ngx_http_process_host behavior.
                        if st.has_host {
                            return Parse::Invalid;
                        }
                        st.host_start = val_start;
                        st.host_end = val_end;
                        st.has_host = true;
                    }
                    Some(KnownHeader::IfModifiedSince) => {
                        if st.has_if_modified_since {
                            return Parse::Invalid;
                        }
                        st.if_modified_since_start = val_start;
                        st.if_modified_since_end = val_end;
                        st.has_if_modified_since = true;
                    }
                    Some(KnownHeader::IfUnmodifiedSince) => {
                        if st.has_if_unmodified_since {
                            return Parse::Invalid;
                        }
                        st.if_unmodified_since_start = val_start;
                        st.if_unmodified_since_end = val_end;
                        st.has_if_unmodified_since = true;
                    }
                    Some(KnownHeader::IfNoneMatch) => {
                        if st.has_if_none_match {
                            return Parse::Invalid;
                        }
                        st.if_none_match_start = val_start;
                        st.if_none_match_end = val_end;
                        st.has_if_none_match = true;
                    }
                    Some(KnownHeader::IfMatch) => {
                        if st.has_if_match {
                            return Parse::Invalid;
                        }
                        st.if_match_start = val_start;
                        st.if_match_end = val_end;
                        st.has_if_match = true;
                    }
                    Some(KnownHeader::Range) => {
                        st.range_start = val_start;
                        st.range_end = val_end;
                        st.has_range = true;
                    }
                    Some(KnownHeader::IfRange) => {
                        if st.has_if_range {
                            return Parse::Invalid;
                        }
                        st.if_range_start = val_start;
                        st.if_range_end = val_end;
                        st.has_if_range = true;
                    }
                    Some(KnownHeader::ContentRange) => {
                        if st.has_content_range {
                            return Parse::Invalid;
                        }
                        st.has_content_range = true;
                    }
                    Some(KnownHeader::Expect) => {
                        if st.has_expect {
                            return Parse::Invalid;
                        }
                        st.has_expect = true;
                    }
                    Some(KnownHeader::Authorization) => {
                        if st.has_authorization {
                            return Parse::Invalid;
                        }
                        st.has_authorization = true;
                    }
                    Some(KnownHeader::ContentLength) => {
                        // Decimal-only, no leading sign / whitespace beyond
                        // the OWS the parser already trimmed. Reject any
                        // non-digit or empty value as a malformed request
                        // — matches nginx's `ngx_http_process_header_line`
                        // which rejects non-numeric Content-Length.
                        let v = &buf[val_start..val_end];
                        let mut n: u64 = 0;
                        if v.is_empty() {
                            return Parse::Invalid;
                        }
                        for &b in v {
                            if !b.is_ascii_digit() {
                                return Parse::Invalid;
                            }
                            n = match n
                                .checked_mul(10)
                                .and_then(|x| x.checked_add((b - b'0') as u64))
                            {
                                Some(x) => x,
                                None => return Parse::Invalid,
                            };
                        }
                        // Content-Length is a unique header per nginx's
                        // ngx_http_process_unique_header_line: any duplicate
                        // (even with the same value) is a 400.
                        if st.has_content_length {
                            return Parse::Invalid;
                        }
                        st.content_length = Some(n);
                        st.has_content_length = true;
                    }
                    Some(KnownHeader::TransferEncoding) => {
                        // Unique header — duplicate Transfer-Encoding is a 400.
                        if st.has_transfer_encoding {
                            return Parse::Invalid;
                        }
                        st.has_transfer_encoding = true;
                        // RFC 7230 §3.3.1: comma-separated list. We only
                        // care whether `chunked` appears; nginx does the
                        // same case-insensitive substring check.
                        let v = &buf[val_start..val_end];
                        if connection_has_token(v, b"chunked") {
                            st.transfer_encoding_chunked = true;
                        }
                    }
                    None => {}
                }
                st.cursor = next;
            }
            HeaderParse::Incomplete => return Parse::Incomplete,
            HeaderParse::Invalid => return Parse::Invalid,
        }
    }
}

/// Which known header a just-parsed name matched, for dispatch. Unknown
/// headers get no classification and are silently ignored.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum KnownHeader {
    Host,
    Connection,
    IfModifiedSince,
    IfUnmodifiedSince,
    IfNoneMatch,
    IfMatch,
    Range,
    IfRange,
    ContentLength,
    ContentRange,
    TransferEncoding,
    Expect,
    Authorization,
}

/// Nginx's header hash (`ngx_hash(key, c) = key * 31 + c`, lowercased).
/// Computed at compile time for the static entries in `KNOWN_HEADERS`.
const fn h_hash(name: &[u8]) -> u32 {
    let mut h: u32 = 0;
    let mut i = 0;
    while i < name.len() {
        h = h.wrapping_mul(31).wrapping_add(name[i] as u32);
        i += 1;
    }
    h
}

/// Perfect-ish-for-now static table of (hash, lowercased name, classification).
/// Adding a new header is a one-line addition here plus a handler arm in the
/// `parse_request` match — no build-time hash table generation needed.
const KNOWN_HEADERS: &[(u32, &[u8], KnownHeader)] = &[
    (h_hash(b"host"), b"host", KnownHeader::Host),
    (
        h_hash(b"connection"),
        b"connection",
        KnownHeader::Connection,
    ),
    (
        h_hash(b"if-modified-since"),
        b"if-modified-since",
        KnownHeader::IfModifiedSince,
    ),
    (
        h_hash(b"if-unmodified-since"),
        b"if-unmodified-since",
        KnownHeader::IfUnmodifiedSince,
    ),
    (
        h_hash(b"if-none-match"),
        b"if-none-match",
        KnownHeader::IfNoneMatch,
    ),
    (h_hash(b"if-match"), b"if-match", KnownHeader::IfMatch),
    (h_hash(b"range"), b"range", KnownHeader::Range),
    (h_hash(b"if-range"), b"if-range", KnownHeader::IfRange),
    (
        h_hash(b"content-length"),
        b"content-length",
        KnownHeader::ContentLength,
    ),
    (
        h_hash(b"content-range"),
        b"content-range",
        KnownHeader::ContentRange,
    ),
    (
        h_hash(b"transfer-encoding"),
        b"transfer-encoding",
        KnownHeader::TransferEncoding,
    ),
    (h_hash(b"expect"), b"expect", KnownHeader::Expect),
    (
        h_hash(b"authorization"),
        b"authorization",
        KnownHeader::Authorization,
    ),
];

enum LineParse {
    Ok {
        next: usize,
        method_start: usize,
        method_end: usize,
        path_start: usize,
        path_end: usize,
        implicit_path: bool,
        request_line_host: Option<(usize, usize)>,
        absolute_query: Option<(usize, usize)>,
        http_11: bool,
    },
    Incomplete,
    Invalid,
}

fn parse_request_line(buf: &[u8], start: usize) -> LineParse {
    let n = buf.len();
    let mut i = start;

    // Method: RFC 7230 token chars are a looser set, but we only need to
    // detect the SP delimiter and reject obviously-bogus control bytes.
    let method_start = i;
    while i < n && buf[i] != b' ' {
        if buf[i] < b'!' {
            return LineParse::Invalid;
        }
        i += 1;
    }
    if i >= n {
        return LineParse::Incomplete;
    }
    if i == method_start {
        return LineParse::Invalid;
    }
    let method_end = i;
    let method = classify_method(&buf[method_start..method_end]);
    i += 1;

    let ParsedTarget {
        version_start,
        path_start,
        path_end,
        implicit_path,
        request_line_host,
        absolute_query,
    } = match method {
        Method::Connect => match parse_connect_target(buf, i) {
            Some(target) => target,
            None => {
                return if buf[i..].contains(&b' ') {
                    LineParse::Invalid
                } else {
                    LineParse::Incomplete
                };
            }
        },
        _ if looks_like_absolute_form(buf, i, n) => match parse_absolute_form_target(buf, i) {
            Some(target) => target,
            None => {
                return if buf[i..].contains(&b' ') {
                    LineParse::Invalid
                } else {
                    LineParse::Incomplete
                };
            }
        },
        _ => match parse_origin_form_target(buf, i) {
            Some(target) => target,
            None => {
                return if buf[i..].contains(&b' ') {
                    LineParse::Invalid
                } else {
                    LineParse::Incomplete
                };
            }
        },
    };
    i = version_start;

    if i + 8 > n {
        return LineParse::Incomplete;
    }
    let v = &buf[i..i + 8];
    if &v[..7] != b"HTTP/1." || (v[7] != b'0' && v[7] != b'1') {
        return LineParse::Invalid;
    }
    let http_11 = v[7] == b'1';
    i += 8;

    if i >= n {
        return LineParse::Incomplete;
    }
    let next = if buf[i] == b'\n' {
        i + 1
    } else if buf[i] == b'\r' {
        if i + 1 >= n {
            return LineParse::Incomplete;
        }
        if buf[i + 1] != b'\n' {
            return LineParse::Invalid;
        }
        i + 2
    } else {
        return LineParse::Invalid;
    };

    LineParse::Ok {
        next,
        method_start,
        method_end,
        path_start,
        path_end,
        implicit_path,
        request_line_host,
        absolute_query,
        http_11,
    }
}

struct ParsedTarget {
    version_start: usize,
    path_start: usize,
    path_end: usize,
    implicit_path: bool,
    request_line_host: Option<(usize, usize)>,
    /// Absolute-form request-targets can carry a query with no path — e.g.
    /// `GET http://host?args HTTP/1.1`. nginx synthesizes `/?args` as the
    /// effective request URI; we record the raw `?args…` bytes here so the
    /// worker can splice a leading `/` and feed the rest through normal
    /// URI / variable expansion (`$args`, `$request_uri`).
    absolute_query: Option<(usize, usize)>,
}

fn parse_origin_form_target(buf: &[u8], start: usize) -> Option<ParsedTarget> {
    let mut i = start;
    // `#` ends the request target — fragments are not part of the
    // request-line per RFC 7230 §5.3. Clients sometimes leak them anyway;
    // nginx strips. We consume until space for the HTTP version split.
    let mut fragment_seen = false;
    let mut path_end = 0;
    while i < buf.len() && buf[i] != b' ' {
        let c = buf[i];
        if c == b'#' && !fragment_seen {
            path_end = i;
            fragment_seen = true;
        }
        if !is_uri_char(c) {
            return None;
        }
        i += 1;
    }
    if i >= buf.len() || i == start {
        return None;
    }
    if !fragment_seen {
        path_end = i;
    }
    Some(ParsedTarget {
        version_start: i + 1,
        path_start: start,
        path_end,
        implicit_path: false,
        request_line_host: None,
        absolute_query: None,
    })
}

fn parse_absolute_form_target(buf: &[u8], start: usize) -> Option<ParsedTarget> {
    let mut i = start;
    while i < buf.len() && buf[i] != b':' {
        let c = buf[i];
        let ok = if i == start {
            c.is_ascii_alphabetic()
        } else {
            c.is_ascii_alphanumeric() || matches!(c, b'+' | b'-' | b'.')
        };
        if !ok {
            return None;
        }
        i += 1;
    }
    if i + 3 > buf.len() || &buf[i..i + 3] != b"://" {
        return None;
    }
    i += 3;
    let host_start = i;
    i = parse_authority(buf, i, false)?;
    let request_line_host = Some((host_start, i));
    match *buf.get(i)? {
        b'/' => {
            let path_start = i;
            let mut path_end = 0;
            let mut fragment_seen = false;
            while i < buf.len() && buf[i] != b' ' {
                let c = buf[i];
                if c == b'#' && !fragment_seen {
                    path_end = i;
                    fragment_seen = true;
                }
                if !is_uri_char(c) {
                    return None;
                }
                i += 1;
            }
            if i >= buf.len() {
                return None;
            }
            if !fragment_seen {
                path_end = i;
            }
            Some(ParsedTarget {
                version_start: i + 1,
                path_start,
                path_end,
                implicit_path: false,
                request_line_host,
                absolute_query: None,
            })
        }
        b'?' => {
            let q_start = i;
            let mut q_end = 0;
            let mut fragment_seen = false;
            i += 1;
            while i < buf.len() && buf[i] != b' ' {
                let c = buf[i];
                if c == b'#' && !fragment_seen {
                    q_end = i;
                    fragment_seen = true;
                }
                if !is_uri_char(c) {
                    return None;
                }
                i += 1;
            }
            if i >= buf.len() {
                return None;
            }
            if !fragment_seen {
                q_end = i;
            }
            Some(ParsedTarget {
                version_start: i + 1,
                path_start: 0,
                path_end: 0,
                implicit_path: true,
                request_line_host,
                absolute_query: Some((q_start, q_end)),
            })
        }
        b' ' => Some(ParsedTarget {
            version_start: i + 1,
            path_start: 0,
            path_end: 0,
            implicit_path: true,
            request_line_host,
            absolute_query: None,
        }),
        _ => None,
    }
}

fn parse_connect_target(buf: &[u8], start: usize) -> Option<ParsedTarget> {
    let host_start = start;
    let i = parse_authority(buf, start, true)?;
    if *buf.get(i)? != b' ' {
        return None;
    }
    Some(ParsedTarget {
        version_start: i + 1,
        path_start: 0,
        path_end: 0,
        implicit_path: false,
        request_line_host: Some((host_start, i)),
        absolute_query: None,
    })
}

fn parse_authority(buf: &[u8], start: usize, require_port_digits: bool) -> Option<usize> {
    let mut i = start;
    if *buf.get(i)? == b'[' {
        i += 1;
        while i < buf.len() {
            let c = buf[i];
            if c == b']' {
                i += 1;
                break;
            }
            if !is_host_literal_char(c) {
                return None;
            }
            i += 1;
        }
        if i > buf.len() || buf.get(i - 1) != Some(&b']') {
            return None;
        }
    } else {
        while i < buf.len() {
            let c = buf[i];
            if matches!(c, b':' | b'/' | b'?' | b' ') {
                break;
            }
            if !is_host_char(c) {
                return None;
            }
            i += 1;
        }
        if i == start {
            return None;
        }
    }

    if buf.get(i) == Some(&b':') {
        i += 1;
        let digits_start = i;
        while i < buf.len() && buf[i].is_ascii_digit() {
            i += 1;
        }
        if require_port_digits && i == digits_start {
            return None;
        }
    } else if require_port_digits {
        return None;
    }

    Some(i)
}

fn looks_like_absolute_form(buf: &[u8], start: usize, end: usize) -> bool {
    if start >= end || !buf[start].is_ascii_alphabetic() {
        return false;
    }
    let mut i = start + 1;
    while i < end {
        let c = buf[i];
        if c == b':' {
            return i + 2 < end && buf[i + 1] == b'/' && buf[i + 2] == b'/';
        }
        if !(c.is_ascii_alphanumeric() || matches!(c, b'+' | b'-' | b'.')) {
            return false;
        }
        i += 1;
    }
    false
}

enum HeaderParse {
    Ok {
        next: usize,
        /// `Some(_)` if the header name hashes + compares equal to one of
        /// `KNOWN_HEADERS`. Unknown headers parse normally but skip dispatch.
        known: Option<KnownHeader>,
        val_start: usize,
        val_end: usize,
    },
    Incomplete,
    Invalid,
}

/// Size of the stack buffer used to accumulate the lowercased header name.
/// 64 covers every header any real-world server dispatches on (longest in
/// IANA is 31 bytes: `Access-Control-Allow-Credentials`). Names longer than
/// this will never match any KNOWN_HEADERS entry, so the overflow just
/// suppresses the classification — which is the correct outcome anyway.
const LC_NAME_MAX: usize = 64;

fn parse_header_line(buf: &[u8], start: usize) -> HeaderParse {
    let n = buf.len();
    let mut i = start;

    // Walk the name, lowercasing + hashing byte-by-byte (nginx's
    // `ngx_http_parse_header_line` builds `r->header_hash` the same way).
    // Using a stack buffer + rolling hash avoids any allocation; a
    // collision-free match against the tiny KNOWN_HEADERS table makes the
    // subsequent memcmp a simple length + slice compare.
    let name_start = i;
    let mut lc: [u8; LC_NAME_MAX] = [0; LC_NAME_MAX];
    let mut lc_len: usize = 0;
    let mut hash: u32 = 0;
    while i < n && buf[i] != b':' && buf[i] != b'\r' && buf[i] != b'\n' {
        let c = buf[i];
        // HTTP field-name is a token (RFC 9110): spaces/control bytes are
        // always invalid and must fail the request as 400.
        if c <= 0x20 || c == 0x7f {
            return HeaderParse::Invalid;
        }
        let lc_c = if c.is_ascii_uppercase() { c | 0x20 } else { c };
        if lc_len < LC_NAME_MAX {
            lc[lc_len] = lc_c;
        }
        lc_len += 1;
        hash = hash.wrapping_mul(31).wrapping_add(lc_c as u32);
        i += 1;
    }
    if i >= n {
        return HeaderParse::Incomplete;
    }
    if buf[i] != b':' {
        return HeaderParse::Invalid;
    }
    let name_end = i;
    if name_end == name_start {
        return HeaderParse::Invalid;
    }
    i += 1;

    while i < n && (buf[i] == b' ' || buf[i] == b'\t') {
        i += 1;
    }
    let val_start = i;
    while i < n {
        match buf[i] {
            b'\r' | b'\n' => break,
            // nginx rejects a NUL anywhere in a field value
            // (ngx_http_parse_header_line → NGX_HTTP_PARSE_INVALID_HEADER);
            // forwarded upstream it would truncate or confuse a C backend.
            0 => return HeaderParse::Invalid,
            _ => i += 1,
        }
    }
    if i >= n {
        return HeaderParse::Incomplete;
    }
    let next = if buf[i] == b'\n' {
        i + 1
    } else {
        if i + 1 >= n {
            return HeaderParse::Incomplete;
        }
        if buf[i + 1] != b'\n' {
            return HeaderParse::Invalid;
        }
        i + 2
    };
    let mut val_end = i;
    while val_end > val_start && matches!(buf[val_end - 1], b' ' | b'\t') {
        val_end -= 1;
    }

    // Names that overflowed our buffer never match.
    let known = if lc_len <= LC_NAME_MAX {
        classify_header(hash, &lc[..lc_len])
    } else {
        None
    };

    HeaderParse::Ok {
        next,
        known,
        val_start,
        val_end,
    }
}

#[inline]
fn classify_header(hash: u32, lc: &[u8]) -> Option<KnownHeader> {
    // Tiny linear scan; the hash compare is the fast discriminator. The full
    // memcmp only runs on hash collisions, which don't exist within our
    // current known set. At ~20 headers this beats a real hash table because
    // the whole array fits in one cache line.
    for &(h, name, cls) in KNOWN_HEADERS {
        if h == hash && name.len() == lc.len() && name == lc {
            return Some(cls);
        }
    }
    None
}

#[inline(always)]
fn is_uri_char(c: u8) -> bool {
    matches!(
        c,
        b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9'
        // unreserved
        | b'-' | b'.' | b'_' | b'~'
        // gen-delims allowed in request-target
        | b'/' | b'?' | b'#' | b'[' | b']' | b'@' | b':'
        // sub-delims
        | b'!' | b'$' | b'&' | b'\'' | b'(' | b')'
        | b'*' | b'+' | b',' | b';' | b'='
        // pct-encoded triplet marker (we don't decode in v0.1 but must accept)
        | b'%'
    )
}

/// Reg-name character set for a hostname in authority (RFC 3986 §3.2.2):
/// unreserved / pct-encoded / sub-delims. No `:` (separator to port) and
/// no `/` or `?` (start of path/query).
#[inline(always)]
fn is_host_char(c: u8) -> bool {
    matches!(
        c,
        b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9'
        | b'-' | b'.' | b'_' | b'~'
        | b'!' | b'$' | b'&' | b'\'' | b'(' | b')'
        | b'*' | b'+' | b',' | b';' | b'='
        | b'%'
    )
}

/// Character set inside an IP-literal `[...]` (RFC 3986 §3.2.2). IPv6 only
/// needs hex + `:` + `.`, but `IPvFuture` allows the full unreserved set —
/// `ALPHA / DIGIT / "-" / "." / "_" / "~"` — plus sub-delims and `:`. We
/// only gate the byte set here; there is no deeper structural check for
/// `v` <HEXDIG>+ `.` … yet, so malformed IP-literals that stay inside the
/// charset will parse and get rejected (or not) by downstream consumers.
#[inline(always)]
fn is_host_literal_char(c: u8) -> bool {
    matches!(
        c,
        b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9'
        | b':' | b'.'
        | b'-' | b'_' | b'~'
        | b'!' | b'$' | b'&' | b'\'' | b'(' | b')'
        | b'*' | b'+' | b',' | b';' | b'='
    )
}

#[inline]
fn eq_ignore_ascii(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for k in 0..a.len() {
        if !a[k].eq_ignore_ascii_case(&b[k]) {
            return false;
        }
    }
    true
}

/// Case-insensitive scan of `value` for a bare `target` token. `value` is a
/// Connection-style comma-separated list with optional OWS around each entry;
/// `target` is the lowercased token to look for (`b"close"` or
/// `b"keep-alive"`). Matches only whole tokens, not substrings — so
/// `Connection: closely` correctly does *not* match `close`.
fn connection_has_token(value: &[u8], target: &[u8]) -> bool {
    let n = value.len();
    let mut i = 0;
    while i < n {
        while i < n && matches!(value[i], b' ' | b'\t' | b',') {
            i += 1;
        }
        let start = i;
        while i < n && value[i] != b',' {
            i += 1;
        }
        let mut end = i;
        while end > start && matches!(value[end - 1], b' ' | b'\t') {
            end -= 1;
        }
        if end - start == target.len() && eq_ignore_ascii(&value[start..end], target) {
            return true;
        }
    }
    false
}

/// Result of normalizing a Host header value (or absolute-form authority)
/// in place. `host` is the lowercased, port-stripped, trailing-dot-trimmed
/// hostname range. `port` is the digits-only port range (no leading colon)
/// when the input contained `:NNNN`, or `None`. Both are absolute buffer
/// offsets into the same `buf` passed in.
pub struct NormalizedHost {
    pub host: (usize, usize),
    pub port: Option<(usize, usize)>,
}

pub fn normalize_host_in_place(buf: &mut [u8], start: usize, end: usize) -> Option<NormalizedHost> {
    #[derive(Copy, Clone)]
    enum State {
        HostStart,
        Host,
        HostIpLiteral,
        HostEnd,
        Port,
    }

    let mut state = State::HostStart;
    let mut dot_pos = end.saturating_sub(start);
    let mut host_len = end.saturating_sub(start);
    let mut port: u32 = 0;
    let mut port_start: Option<usize> = None;

    for i in start..end {
        let ch = buf[i];
        match state {
            State::HostStart => {
                if ch == b'[' {
                    state = State::HostIpLiteral;
                    continue;
                }
                state = State::Host;
            }
            State::HostEnd => {
                if ch == b':' {
                    state = State::Port;
                    port_start = Some(i + 1);
                    continue;
                }
                return None;
            }
            State::Port => {
                if ch.is_ascii_digit() {
                    let digit = (ch - b'0') as u32;
                    if port > 6553 || (port == 6553 && digit > 5) {
                        return None;
                    }
                    port = port * 10 + digit;
                    continue;
                }
                return None;
            }
            State::Host | State::HostIpLiteral => {}
        }

        match state {
            State::Host => {
                if ch.is_ascii_uppercase() {
                    buf[i] = ch.to_ascii_lowercase();
                    continue;
                }
                if ch.is_ascii_lowercase() || ch.is_ascii_digit() {
                    continue;
                }
                match ch {
                    b':' => {
                        host_len = i - start;
                        state = State::Port;
                        port_start = Some(i + 1);
                    }
                    b'-' => {}
                    b'.' => {
                        if i == start || dot_pos == i - start - 1 {
                            return None;
                        }
                        dot_pos = i - start;
                    }
                    b'_' | b'~' | b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b','
                    | b';' | b'=' | b'%' => {}
                    _ => return None,
                }
            }
            State::HostIpLiteral => {
                if ch.is_ascii_uppercase() {
                    buf[i] = ch.to_ascii_lowercase();
                    continue;
                }
                if ch.is_ascii_lowercase() || ch.is_ascii_digit() {
                    continue;
                }
                match ch {
                    b':' => {}
                    b']' => {
                        host_len = i + 1 - start;
                        state = State::HostEnd;
                    }
                    b'-' => {}
                    b'.' => {
                        if i == start || dot_pos == i - start - 1 {
                            return None;
                        }
                        dot_pos = i - start;
                    }
                    b'_' | b'~' | b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b','
                    | b';' | b'=' => {}
                    _ => return None,
                }
            }
            State::HostStart | State::HostEnd | State::Port => unreachable!(),
        }
    }

    if matches!(state, State::HostIpLiteral) {
        return None;
    }
    if host_len > 0 && dot_pos == host_len - 1 {
        host_len -= 1;
    }
    if host_len == 0 {
        return None;
    }
    let port_range = port_start.and_then(|ps| {
        // Reject `localhost:` (colon with no digits) and the
        // accept-but-ignore default-port `:0` form? nginx accepts `:0`.
        // We already validated each digit during the State::Port arm,
        // so we just need to confirm at least one digit was present.
        if ps < end { Some((ps, end)) } else { None }
    });
    let _ = port; // value validated; bytes returned to caller
    Some(NormalizedHost {
        host: (start, start + host_len),
        port: port_range,
    })
}

/// The name the `Server` header and the built-in error pages' footer
/// carry: `versioned` for `server_tokens on|build` (the default), `plain`
/// for `off`.
pub struct Identity {
    pub versioned: &'static [u8],
    pub plain: &'static [u8],
}

pub const RUXEN_IDENTITY: Identity = Identity {
    versioned: concat!("ruxen/", env!("CARGO_PKG_VERSION")).as_bytes(),
    plain: b"ruxen",
};

/// What nginx-tests expects (`server_tokens.t`, error-page bodies): the
/// nginx version `-V` reports.
pub const NGINX_IDENTITY: Identity = Identity {
    versioned: b"nginx/1.29.2",
    plain: b"nginx",
};

/// Set by `scripts/run_nginx_tests.sh` so responses name nginx, as the
/// upstream tests assert. Everyone else gets ruxen's own name.
pub const NGINX_IDENTITY_ENV: &str = "RUXEN_NGINX_IDENTITY";

/// Read once; only config preparation calls this, never the request path.
pub fn identity() -> &'static Identity {
    static IDENTITY: std::sync::OnceLock<&'static Identity> = std::sync::OnceLock::new();
    IDENTITY.get_or_init(|| {
        if std::env::var_os(NGINX_IDENTITY_ENV).is_some_and(|v| v == "1") {
            &NGINX_IDENTITY
        } else {
            &RUXEN_IDENTITY
        }
    })
}

/// Resolve the `Server:` header value for a given `server_tokens` setting.
pub fn server_header_value(t: crate::config::ServerTokens) -> &'static [u8] {
    use crate::config::ServerTokens::*;
    match t {
        Off => identity().plain,
        On | Build => identity().versioned,
    }
}

/// Write the `Server` and `Date` lines that open every response head, in
/// nginx's order (`ngx_http_header_filter`). Called right after the status
/// line; the caller continues with the next `\r\n`. The worker write path
/// re-stamps `Date` before sending, so prebuilt heads built at config time
/// carry a current value too.
pub fn write_server_and_date(out: &mut Vec<u8>, server: &[u8]) {
    out.extend_from_slice(b"\r\nServer: ");
    out.extend_from_slice(server);
    out.extend_from_slice(b"\r\nDate: ");
    out.extend_from_slice(&crate::http_date::now());
}

/// Default error-page body (`<html>...<center>ruxen/X.Y.Z</center>...`)
/// for the given status. `None` if the status doesn't have a canned
/// nginx page (matches `ngx_http_error_pages` in
/// `ngx_http_special_response.c`). The footer is the `Server` value, so
/// it follows `server_tokens` and the identity (see `identity`).
pub fn default_error_page_body(status: u16, t: crate::config::ServerTokens) -> Option<Vec<u8>> {
    let (title, h1) = error_page_title(status)?;
    let mut body = Vec::with_capacity(title.len() + h1.len() + 96);
    write_default_error_page_into(&mut body, title, h1, t);
    Some(body)
}

fn write_default_error_page_into(
    out: &mut Vec<u8>,
    title: &str,
    h1: &str,
    t: crate::config::ServerTokens,
) {
    out.extend_from_slice(b"<html>\r\n<head><title>");
    out.extend_from_slice(title.as_bytes());
    out.extend_from_slice(b"</title></head>\r\n<body>\r\n<center><h1>");
    out.extend_from_slice(h1.as_bytes());
    out.extend_from_slice(b"</h1></center>\r\n<hr><center>");
    out.extend_from_slice(server_header_value(t));
    out.extend_from_slice(b"</center>\r\n</body>\r\n</html>\r\n");
}

/// Title and `<h1>` text for the default error page corresponding to
/// `status`. Mirrors the per-status string tables in
/// `ngx_http_special_response.c` (the title and h1 text are identical there).
fn error_page_title(status: u16) -> Option<(&'static str, &'static str)> {
    let s = match status {
        400 => "400 Bad Request",
        401 => "401 Authorization Required",
        402 => "402 Payment Required",
        403 => "403 Forbidden",
        404 => "404 Not Found",
        405 => "405 Not Allowed",
        406 => "406 Not Acceptable",
        408 => "408 Request Time-out",
        409 => "409 Conflict",
        410 => "410 Gone",
        411 => "411 Length Required",
        412 => "412 Precondition Failed",
        413 => "413 Request Entity Too Large",
        414 => "414 Request-URI Too Large",
        415 => "415 Unsupported Media Type",
        416 => "416 Requested Range Not Satisfiable",
        421 => "421 Misdirected Request",
        429 => "429 Too Many Requests",
        500 => "500 Internal Server Error",
        501 => "501 Not Implemented",
        502 => "502 Bad Gateway",
        503 => "503 Service Temporarily Unavailable",
        504 => "504 Gateway Time-out",
        505 => "505 HTTP Version Not Supported",
        507 => "507 Insufficient Storage",
        _ => return None,
    };
    Some((s, s))
}

pub fn build_response(status: u16, body: &str, server: &[u8]) -> Vec<u8> {
    build_response_bytes(status, body.as_bytes(), server)
}

pub fn build_response_bytes(status: u16, body: &[u8], server: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(96 + body.len());
    write_response_bytes(&mut out, status, body, server);
    out
}

/// Hot-path variant of `build_response_bytes` — appends a full response
/// (headers + body) into the caller-supplied buffer so the worker can
/// reuse a per-connection scratch `Vec<u8>` across requests.
pub fn write_response_bytes(out: &mut Vec<u8>, status: u16, body: &[u8], server: &[u8]) {
    write_head(out, status, body.len(), server);
    if status != 204 {
        out.extend_from_slice(body);
    }
}

/// Build a redirect response. Status is usually 301; body is a tiny HTML
/// stub so clients that don't follow redirects still see something. HEAD
/// responses omit the body per RFC 9110 §9.3.2 but keep the `Location`
/// header and the would-be `Content-Length`.
pub fn build_redirect_response(
    status: u16,
    location: &[u8],
    method: Method,
    server: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(128 + location.len() + REDIRECT_BODY.len());
    write_redirect_response(&mut out, status, location, method, server);
    out
}

const REDIRECT_BODY: &[u8] = b"<html><body>Moved</body></html>\n";

/// Hot-path variant of `build_redirect_response`.
pub fn write_redirect_response(
    out: &mut Vec<u8>,
    status: u16,
    location: &[u8],
    method: Method,
    server: &[u8],
) {
    let body_len = REDIRECT_BODY.len();
    let reason = match status {
        301 => "Moved Permanently",
        302 => "Found",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        _ => "Moved Permanently",
    };
    out.extend_from_slice(b"HTTP/1.1 ");
    write_u16(out, status);
    out.push(b' ');
    out.extend_from_slice(reason.as_bytes());
    write_server_and_date(out, server);
    out.extend_from_slice(b"\r\nLocation: ");
    out.extend_from_slice(location);
    out.extend_from_slice(b"\r\nContent-Type: text/html\r\nContent-Length: ");
    write_usize(out, body_len);
    out.extend_from_slice(b"\r\n\r\n");
    if !matches!(method, Method::Head) {
        out.extend_from_slice(REDIRECT_BODY);
    }
}

/// Same headers as `build_response`, but without the message body.
/// RFC 9110 §9.3.2: responses to HEAD MUST NOT include a body, yet the
/// `Content-Length` still advertises the body size the equivalent GET would
/// have produced.
pub fn build_head_response(status: u16, body_len: usize, server: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(96);
    write_head(&mut out, status, body_len, server);
    out
}

/// Hot-path variant of `build_head_response`.
pub fn write_head_response(out: &mut Vec<u8>, status: u16, body_len: usize, server: &[u8]) {
    write_head(out, status, body_len, server);
}

/// Build either the full response or the HEAD variant for the same payload.
pub fn build_response_for_method(
    status: u16,
    body: &str,
    method: Method,
    server: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(96 + body.len());
    write_response_for_method(&mut out, status, body, method, server);
    out
}

/// Hot-path variant of `build_response_for_method`.
pub fn write_response_for_method(
    out: &mut Vec<u8>,
    status: u16,
    body: &str,
    method: Method,
    server: &[u8],
) {
    if matches!(method, Method::Head) {
        write_head_response(out, status, body.len(), server);
    } else {
        write_response_bytes(out, status, body.as_bytes(), server);
    }
}

pub fn build_response_bytes_with_content_type(
    status: u16,
    body: &[u8],
    content_type: &[u8],
    method: Method,
    server: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(96 + body.len() + content_type.len());
    write_response_bytes_with_content_type(&mut out, status, body, content_type, method, server);
    out
}

pub fn write_response_bytes_with_content_type(
    out: &mut Vec<u8>,
    status: u16,
    body: &[u8],
    content_type: &[u8],
    method: Method,
    server: &[u8],
) {
    write_head_with_content_type(out, status, body.len(), content_type, server);
    if !matches!(method, Method::Head) && status != 204 {
        out.extend_from_slice(body);
    }
}

fn write_head(out: &mut Vec<u8>, status: u16, body_len: usize, server: &[u8]) {
    write_head_with_content_type(out, status, body_len, b"text/plain", server);
}

fn write_head_with_content_type(
    out: &mut Vec<u8>,
    status: u16,
    body_len: usize,
    content_type: &[u8],
    server: &[u8],
) {
    let reason = reason_phrase(status);
    out.extend_from_slice(b"HTTP/1.1 ");
    write_u16(out, status);
    out.push(b' ');
    out.extend_from_slice(reason.as_bytes());
    write_server_and_date(out, server);
    // nginx's header filter sends a 204 header-only, without Content-Type
    // and Content-Length (RFC 9110 §8.6: it MUST NOT have the latter).
    if status == 204 {
        out.extend_from_slice(b"\r\n\r\n");
        return;
    }
    out.extend_from_slice(b"\r\nContent-Type: ");
    out.extend_from_slice(content_type);
    out.extend_from_slice(b"\r\nContent-Length: ");
    write_usize(out, body_len);
    out.extend_from_slice(b"\r\n\r\n");
}

fn reason_phrase(status: u16) -> &'static str {
    let reason = match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Not Allowed",
        412 => "Precondition Failed",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "OK",
    };
    reason
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

fn write_usize(out: &mut Vec<u8>, mut n: usize) {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_fresh(buf: &[u8]) -> Parse {
        let mut st = ParseState::default();
        parse_request(buf, &mut st)
    }

    #[test]
    fn simple_get() {
        let req = b"GET /hello HTTP/1.1\r\nHost: x\r\n\r\n";
        match parse_fresh(req) {
            Parse::Complete(r) => {
                assert_eq!(&req[r.method_start..r.method_end], b"GET");
                assert_eq!(&req[r.path_start..r.path_end], b"/hello");
                assert!(r.keep_alive);
                assert_eq!(r.consumed, req.len());
            }
            other => panic!("want Complete, got {other:?}"),
        }
    }

    #[test]
    fn lf_only_request_is_accepted() {
        let req = b"GET / HTTP/1.0\nHost: l\n\n";
        match parse_fresh(req) {
            Parse::Complete(r) => {
                let (s, e) = r.host.unwrap();
                assert_eq!(&req[s..e], b"l");
                assert!(!r.http_11);
            }
            other => panic!("want Complete, got {other:?}"),
        }
    }

    #[test]
    fn lf_only_trace_request_is_accepted() {
        let req = b"TRACE / HTTP/1.1\nHost: localhost\n\n";
        match parse_fresh(req) {
            Parse::Complete(r) => {
                assert_eq!(
                    classify_method(&req[r.method_start..r.method_end]),
                    Method::Trace
                );
                let (s, e) = r.host.unwrap();
                assert_eq!(&req[s..e], b"localhost");
            }
            other => panic!("want Complete, got {other:?}"),
        }
    }

    #[test]
    fn captures_method() {
        for (raw, expect) in [
            (&b"GET / HTTP/1.1\r\n\r\n"[..], Method::Get),
            (&b"HEAD / HTTP/1.1\r\n\r\n"[..], Method::Head),
            (&b"POST / HTTP/1.1\r\n\r\n"[..], Method::Other),
            (&b"DELETE / HTTP/1.1\r\n\r\n"[..], Method::Other),
        ] {
            match parse_fresh(raw) {
                Parse::Complete(r) => {
                    assert_eq!(
                        classify_method(&raw[r.method_start..r.method_end]),
                        expect,
                        "raw: {:?}",
                        std::str::from_utf8(raw).unwrap()
                    );
                }
                other => panic!("{other:?}"),
            }
        }
    }

    #[test]
    fn http_1_0_defaults_closed() {
        let req = b"GET / HTTP/1.0\r\n\r\n";
        match parse_fresh(req) {
            Parse::Complete(r) => assert!(!r.keep_alive),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn http_1_0_keep_alive_header_reopens() {
        let req = b"GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n";
        match parse_fresh(req) {
            Parse::Complete(r) => assert!(r.keep_alive),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn http_1_1_close_header_overrides() {
        let req = b"GET / HTTP/1.1\r\nConnection: close\r\n\r\n";
        match parse_fresh(req) {
            Parse::Complete(r) => assert!(!r.keep_alive),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn connection_multi_token_close_still_wins() {
        // Regression: an exact-match compare on the header value silently
        // dropped `close` when the client sent it alongside another option
        // such as `upgrade` (common for WebSocket handshakes on HTTP/1.1).
        // RFC 7230 §6.1 makes the value a comma-separated token list;
        // `close` MUST close the connection even if other tokens are present.
        for raw in [
            &b"GET / HTTP/1.1\r\nConnection: close, upgrade\r\n\r\n"[..],
            &b"GET / HTTP/1.1\r\nConnection: upgrade, close\r\n\r\n"[..],
            &b"GET / HTTP/1.1\r\nConnection: Close, Keep-Alive\r\n\r\n"[..],
        ] {
            match parse_fresh(raw) {
                Parse::Complete(r) => assert!(
                    !r.keep_alive,
                    "close token should close: {:?}",
                    std::str::from_utf8(raw).unwrap()
                ),
                other => panic!("{other:?}"),
            }
        }
    }

    #[test]
    fn connection_multi_token_keep_alive_reopens_http_1_0() {
        // HTTP/1.0 defaults to close. A multi-token Connection header that
        // includes `keep-alive` (e.g., `Upgrade, keep-alive`) must flip the
        // connection back to reusable.
        let req = b"GET / HTTP/1.0\r\nConnection: Upgrade, keep-alive\r\n\r\n";
        match parse_fresh(req) {
            Parse::Complete(r) => assert!(r.keep_alive),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn connection_token_scan_rejects_substring_matches() {
        // Token scan, not substring scan: `closely` shares five chars with
        // `close` but is a different option. An over-eager substring search
        // (nginx's `ngx_strcasestrn` approach) would incorrectly close here.
        let req = b"GET / HTTP/1.1\r\nConnection: closely\r\n\r\n";
        match parse_fresh(req) {
            Parse::Complete(r) => assert!(r.keep_alive),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn incomplete_partial_request() {
        assert!(matches!(
            parse_fresh(b"GET / HTTP/1.1\r\nHost: x"),
            Parse::Incomplete
        ));
    }

    #[test]
    fn pipelined_measures_only_first_request() {
        let req = b"GET /a HTTP/1.1\r\n\r\nGET /b HTTP/1.1\r\n\r\n";
        match parse_fresh(req) {
            Parse::Complete(r) => {
                assert_eq!(&req[r.path_start..r.path_end], b"/a");
                assert_eq!(r.consumed, 19);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn invalid_version() {
        assert!(matches!(
            parse_fresh(b"GET / HTTP/2.0\r\n\r\n"),
            Parse::Invalid
        ));
    }

    #[test]
    fn rejects_nul_in_path() {
        let mut req = b"GET /a\0b HTTP/1.1\r\n\r\n".to_vec();
        assert!(matches!(parse_fresh(&req), Parse::Invalid));
        // And at offset 1 too:
        req = b"GET \0foo HTTP/1.1\r\n\r\n".to_vec();
        assert!(matches!(parse_fresh(&req), Parse::Invalid));
    }

    #[test]
    fn rejects_nul_in_header_value() {
        // nginx: NGX_HTTP_PARSE_INVALID_HEADER → 400, wherever the NUL sits.
        for req in [
            &b"GET / HTTP/1.1\r\nHost: x\r\nX-A: a\0b\r\n\r\n"[..],
            b"GET / HTTP/1.1\r\nHost: x\r\nX-A: \0\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: x\r\nX-A: ab\0\r\n\r\n",
        ] {
            assert!(matches!(parse_fresh(req), Parse::Invalid), "{req:?}");
        }
        assert!(matches!(
            parse_fresh(b"GET / HTTP/1.1\r\nHost: x\r\nX-A: ab\r\n\r\n"),
            Parse::Complete(_)
        ));
    }

    #[test]
    fn rejects_delim_chars_in_path() {
        // `<`, `>`, `{`, `}`, `|`, `\`, `^`, backtick, `"` are all outside
        // RFC 3986's URI char set. Also DEL (0x7f).
        for bad in [b'<', b'>', b'{', b'}', b'|', b'\\', b'^', b'`', b'"', 0x7f] {
            let mut req = Vec::new();
            req.extend_from_slice(b"GET /a");
            req.push(bad);
            req.extend_from_slice(b"b HTTP/1.1\r\n\r\n");
            assert!(
                matches!(parse_fresh(&req), Parse::Invalid),
                "byte 0x{bad:02x} should be rejected in path"
            );
        }
    }

    #[test]
    fn accepts_encoded_and_reserved_chars_in_path() {
        // Percent-encoded space, query string, reserved chars.
        for ok in [
            &b"GET /foo%20bar HTTP/1.1\r\n\r\n"[..],
            &b"GET /a/b?c=1&d=2 HTTP/1.1\r\n\r\n"[..],
            &b"GET /with(parens)+and!bangs HTTP/1.1\r\n\r\n"[..],
            &b"GET /unreserved-._~ HTTP/1.1\r\n\r\n"[..],
        ] {
            assert!(
                matches!(parse_fresh(ok), Parse::Complete(_)),
                "should accept {:?}",
                std::str::from_utf8(ok).unwrap()
            );
        }
    }

    #[test]
    fn resume_skips_already_parsed_bytes() {
        // A real fragmented-read scenario: first read gives us the request
        // line + one complete header; second read appends the terminating
        // blank line. After call 1 the parser must have advanced past the
        // first header so call 2 only sees "\r\n".
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(b"GET /p HTTP/1.1\r\nHost: x\r\n");
        let mut st = ParseState::default();
        assert!(matches!(parse_request(&buf, &mut st), Parse::Incomplete));
        assert!(st.rline_done);
        assert_eq!(st.cursor, buf.len()); // advanced past the Host: header

        // Overwrite the already-consumed prefix with garbage — a non-resumable
        // parser would re-scan these bytes and return Invalid. A resumable
        // one ignores them because cursor > 0.
        for b in &mut buf[..st.cursor] {
            *b = 0;
        }
        buf.extend_from_slice(b"\r\n");
        match parse_request(&buf, &mut st) {
            Parse::Complete(r) => {
                assert_eq!(r.consumed, buf.len());
                assert!(r.keep_alive);
                // path offsets were saved in state during call 1, before we
                // stomped the prefix — they still reference the original
                // /p location.
                assert_eq!(r.path_start, 4);
                assert_eq!(r.path_end, 6);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn captures_host_value() {
        let req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        match parse_fresh(req) {
            Parse::Complete(r) => {
                let (s, e) = r.host.expect("Host captured");
                assert_eq!(&req[s..e], b"example.com");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn host_port_is_stripped() {
        let mut req = b"GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n".to_vec();
        match parse_fresh(&req) {
            Parse::Complete(r) => {
                let (s, e) = r.host.unwrap();
                assert_eq!(&req[s..e], b"example.com:8080");
                let nh = normalize_host_in_place(&mut req, s, e).unwrap();
                let (s, e) = nh.host;
                assert_eq!(&req[s..e], b"example.com");
                let (ps, pe) = nh.port.unwrap();
                assert_eq!(&req[ps..pe], b"8080");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn host_ipv6_bracketed_with_port() {
        let mut req = b"GET / HTTP/1.1\r\nHost: [::1]:8080\r\n\r\n".to_vec();
        match parse_fresh(&req) {
            Parse::Complete(r) => {
                let (s, e) = r.host.unwrap();
                assert_eq!(&req[s..e], b"[::1]:8080");
                let nh = normalize_host_in_place(&mut req, s, e).unwrap();
                let (s, e) = nh.host;
                assert_eq!(&req[s..e], b"[::1]");
                let (ps, pe) = nh.port.unwrap();
                assert_eq!(&req[ps..pe], b"8080");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn host_ipv6_bracketed_no_port() {
        let mut req = b"GET / HTTP/1.1\r\nHost: [::1]\r\n\r\n".to_vec();
        match parse_fresh(&req) {
            Parse::Complete(r) => {
                let (s, e) = r.host.unwrap();
                let nh = normalize_host_in_place(&mut req, s, e).unwrap();
                let (s, e) = nh.host;
                assert_eq!(&req[s..e], b"[::1]");
                assert!(nh.port.is_none());
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn host_normalizer_trims_trailing_dot_and_lowercases() {
        let mut host = b"Example.COM.:8080".to_vec();
        let end = host.len();
        let nh = normalize_host_in_place(&mut host, 0, end).unwrap();
        let (s, e) = nh.host;
        assert_eq!(&host[s..e], b"example.com");
        let (ps, pe) = nh.port.unwrap();
        assert_eq!(&host[ps..pe], b"8080");
    }

    #[test]
    fn host_normalizer_rejects_empty_dot_host() {
        let mut host = b".".to_vec();
        assert!(normalize_host_in_place(&mut host, 0, 1).is_none());
    }

    #[test]
    fn duplicate_host_is_invalid() {
        let req = b"GET / HTTP/1.1\r\nHost: a.example.com\r\nHost: b.example.com\r\n\r\n";
        assert!(matches!(parse_fresh(req), Parse::Invalid));
    }

    #[test]
    fn missing_host_on_http_1_1_is_flagged() {
        let req = b"GET / HTTP/1.1\r\n\r\n";
        match parse_fresh(req) {
            Parse::Complete(r) => {
                assert!(r.http_11);
                assert!(r.host.is_none());
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn header_name_is_case_insensitive() {
        // HOST in caps should still produce a Host classification.
        let req = b"GET / HTTP/1.1\r\nHOST: example.com\r\n\r\n";
        match parse_fresh(req) {
            Parse::Complete(r) => {
                let (s, e) = r.host.unwrap();
                assert_eq!(&req[s..e], b"example.com");
            }
            other => panic!("{other:?}"),
        }
        // Mixed case on Connection still triggers close.
        let req = b"GET / HTTP/1.1\r\nCoNnEcTiOn: close\r\n\r\n";
        match parse_fresh(req) {
            Parse::Complete(r) => assert!(!r.keep_alive),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn captures_conditional_and_range_headers() {
        let req = b"GET / HTTP/1.1\r\nHost: x\r\nIf-Modified-Since: Sun, 06 Nov 1994 08:49:37 GMT\r\nIf-Unmodified-Since: Sun, 06 Nov 1994 08:49:37 GMT\r\nIf-None-Match: W/\"1-2\"\r\nRange: bytes=0-9\r\nIf-Range: W/\"1-2\"\r\n\r\n";
        match parse_fresh(req) {
            Parse::Complete(r) => {
                let (s, e) = r.if_modified_since.unwrap();
                assert_eq!(&req[s..e], b"Sun, 06 Nov 1994 08:49:37 GMT");
                let (s, e) = r.if_unmodified_since.unwrap();
                assert_eq!(&req[s..e], b"Sun, 06 Nov 1994 08:49:37 GMT");
                let (s, e) = r.if_none_match.unwrap();
                assert_eq!(&req[s..e], b"W/\"1-2\"");
                let (s, e) = r.range.unwrap();
                assert_eq!(&req[s..e], b"bytes=0-9");
                let (s, e) = r.if_range.unwrap();
                assert_eq!(&req[s..e], b"W/\"1-2\"");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn unknown_header_is_ignored_without_side_effects() {
        let req = b"GET / HTTP/1.1\r\nX-Forwarded-For: 1.2.3.4\r\nHost: x\r\n\r\n";
        match parse_fresh(req) {
            Parse::Complete(r) => {
                assert_eq!(&req[r.host.unwrap().0..r.host.unwrap().1], b"x");
                assert!(r.keep_alive);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn header_hash_is_collision_free_for_known_set() {
        // Distinct hashes = the dispatch match doesn't require a memcmp
        // fallback within the known set. If this ever trips, the linear
        // `classify_header` scan still works — but we've lost the perfect-ish
        // property and should pick different hash constants.
        let mut hashes: Vec<u32> = KNOWN_HEADERS.iter().map(|&(h, _, _)| h).collect();
        hashes.sort();
        for w in hashes.windows(2) {
            assert_ne!(w[0], w[1], "hash collision in KNOWN_HEADERS");
        }
    }

    #[test]
    fn response_has_content_length_and_body() {
        let out = build_response(200, "hello", NGINX_IDENTITY.versioned);
        let s = std::str::from_utf8(&out).unwrap();
        assert!(s.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(s.contains("Server: nginx/1.29.2\r\n"));
        assert!(s.contains("Content-Length: 5\r\n"));
        assert!(s.ends_with("\r\n\r\nhello"));
    }

    #[test]
    fn head_response_has_headers_but_no_body() {
        let out = build_head_response(200, 5, NGINX_IDENTITY.versioned);
        let s = std::str::from_utf8(&out).unwrap();
        assert!(s.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(s.contains("Content-Length: 5\r\n"));
        assert!(s.ends_with("\r\n\r\n"));
        let head_end = s.find("\r\n\r\n").unwrap();
        assert_eq!(&out[head_end + 4..], b"");
    }

    #[test]
    fn server_header_value_respects_tokens() {
        use crate::config::ServerTokens::*;
        assert_eq!(server_header_value(Off), identity().plain);
        assert_eq!(server_header_value(On), identity().versioned);
        assert_eq!(server_header_value(Build), identity().versioned);
    }

    #[test]
    fn identities() {
        assert_eq!(
            RUXEN_IDENTITY.versioned,
            format!("ruxen/{}", env!("CARGO_PKG_VERSION")).as_bytes()
        );
        assert_eq!(RUXEN_IDENTITY.plain, b"ruxen");
        // Must match the `nginx version:` line of `-V`.
        assert_eq!(NGINX_IDENTITY.versioned, b"nginx/1.29.2");
        assert_eq!(NGINX_IDENTITY.plain, b"nginx");
    }

    #[test]
    fn default_error_page_body_includes_signature() {
        use crate::config::ServerTokens::*;
        let on = default_error_page_body(404, On).unwrap();
        let off = default_error_page_body(404, Off).unwrap();
        let on_str = std::str::from_utf8(&on).unwrap();
        let off_str = std::str::from_utf8(&off).unwrap();
        let footer = |name: &[u8]| {
            format!(
                "<hr><center>{}</center>",
                std::str::from_utf8(name).unwrap()
            )
        };
        assert!(on_str.contains("<title>404 Not Found</title>"));
        assert!(on_str.contains(&footer(identity().versioned)));
        assert!(off_str.contains(&footer(identity().plain)));
        assert!(!off_str.contains(std::str::from_utf8(identity().versioned).unwrap()));
        assert!(default_error_page_body(200, On).is_none());
    }
}
