//! nginx's range filter (`ngx_http_range_filter_module`) over a proxied
//! response held whole in memory (#370), or a cached one, whose body may
//! be in its file (#515). Static
//! files (`file.rs`) use its parse, multipart layout and 416 page, with the
//! parts read from the file (#401).
//!
//! The filter runs after gzip and add_header, on a 200 of known length,
//! when the response allows ranges (`RangeAllow`, nginx's
//! `r->allow_ranges` / `r->single_range`): one range gives a 206 with
//! `Content-Range`, several a `multipart/byteranges` 206, none satisfiable
//! a 416. Otherwise the response gains `Accept-Ranges: bytes`.

use std::sync::atomic::{AtomicU64, Ordering};

/// Whether, and how far, the range filter may cut a response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum RangeAllow {
    /// The response goes out as it is.
    #[default]
    No,
    /// One range at most (nginx's `single_range`): `proxy_force_ranges`,
    /// or a cacheable response whose upstream sent `Accept-Ranges`.
    Single,
    /// As many as `max_ranges` allows: a response from the cache.
    Multi,
}

/// The request headers the filter reads.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct RangeRequest<'a> {
    pub range: Option<&'a [u8]>,
    pub if_range: Option<&'a [u8]>,
    /// A HEAD request: the response has no body, only its length.
    pub head_only: bool,
}

/// nginx's `ngx_http_range_parse` outcome.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Parsed {
    Ranges(Ranges),
    NotSatisfiable,
    /// The whole response, as if there were no `Range`.
    Declined,
}

/// `[start, end)` pairs, at least one. The first is held inline, so a
/// single range (the common case) allocates nothing.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Ranges {
    pub first: (u64, u64),
    pub rest: Vec<(u64, u64)>,
}

impl Ranges {
    pub(crate) fn len(&self) -> usize {
        1 + self.rest.len()
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (u64, u64)> + '_ {
        std::iter::once(self.first).chain(self.rest.iter().copied())
    }

    /// The bytes the ranges take in total.
    pub(crate) fn size(&self) -> u64 {
        self.iter().map(|(start, end)| end - start).sum()
    }
}

/// The range limit without `max_ranges`: nginx merges an unset
/// `max_ranges` to `NGX_MAX_INT32_VALUE`, and `ngx_http_range_parse`
/// tells the default by that value.
pub(crate) const DEFAULT_LIMIT: u64 = i32::MAX as u64;

/// The range limit for a location's `max_ranges` (`None`: unset).
pub(crate) fn limit(max_ranges: Option<u32>) -> u64 {
    max_ranges.map_or(DEFAULT_LIMIT, u64::from)
}

/// A `Range` header's ranges for a body of `len` bytes: `None` when the
/// filter passes it by (no `bytes=` unit), as nginx's header filter does.
pub(crate) fn parse_header(value: &[u8], len: u64, limit: u64) -> Option<Parsed> {
    (value.len() >= 7 && value[..6].eq_ignore_ascii_case(b"bytes="))
        .then(|| parse(&value[6..], len, limit))
}

/// `value` after `bytes=`, against a body of `len` bytes, at most `limit`
/// ranges (nginx's `ranges`; more is declined). Several ranges are
/// declined when they add up to more than the body, and with the default
/// limit also when, with 256 bytes per part for the multipart headers,
/// they add up to more than the body plus 4096 (nginx 1.29.5).
fn parse(value: &[u8], len: u64, limit: u64) -> Parsed {
    let mut p = 0;
    let at = |i: usize| value.get(i).copied().unwrap_or(0);
    let mut first: Option<(u64, u64)> = None;
    let mut rest = Vec::new();
    let mut push = |range: (u64, u64)| match first {
        None => first = Some(range),
        Some(_) => rest.push(range),
    };
    // u128: a body near 2^64 bytes (an upstream's Content-Length) would
    // wrap a u64 sum past the checks below.
    let mut size: u128 = 0;
    let mut left = limit;
    let digits = |p: &mut usize| -> Option<u64> {
        let mut n: u64 = 0;
        while at(*p).is_ascii_digit() {
            n = n.checked_mul(10)?.checked_add(u64::from(at(*p) - b'0'))?;
            *p += 1;
        }
        // nginx's cutoff: the value must fit an off_t.
        (n <= i64::MAX as u64).then_some(n)
    };
    loop {
        let (mut start, mut end);
        while at(p) == b' ' {
            p += 1;
        }
        let suffix;
        if at(p) != b'-' {
            if !at(p).is_ascii_digit() {
                return Parsed::NotSatisfiable;
            }
            let Some(n) = digits(&mut p) else {
                return Parsed::NotSatisfiable;
            };
            start = n;
            while at(p) == b' ' {
                p += 1;
            }
            if at(p) != b'-' {
                return Parsed::NotSatisfiable;
            }
            p += 1;
            while at(p) == b' ' {
                p += 1;
            }
            if at(p) == b',' || at(p) == 0 {
                end = len;
                if start < end {
                    push((start, end));
                    size += u128::from(end - start);
                    if left == 0 {
                        return Parsed::Declined;
                    }
                    left -= 1;
                } else if start == 0 {
                    return Parsed::Declined;
                }
                if at(p) != b',' {
                    break;
                }
                p += 1;
                continue;
            }
            suffix = false;
        } else {
            start = 0;
            suffix = true;
            p += 1;
        }
        if !at(p).is_ascii_digit() {
            return Parsed::NotSatisfiable;
        }
        let Some(n) = digits(&mut p) else {
            return Parsed::NotSatisfiable;
        };
        end = n;
        while at(p) == b' ' {
            p += 1;
        }
        if at(p) != b',' && at(p) != 0 {
            return Parsed::NotSatisfiable;
        }
        if suffix {
            start = len.saturating_sub(end);
            end = len.saturating_sub(1);
        }
        if end >= len {
            end = len;
        } else {
            end += 1;
        }
        if start < end {
            push((start, end));
            size += u128::from(end - start);
            if left == 0 {
                return Parsed::Declined;
            }
            left -= 1;
        } else if start == 0 {
            return Parsed::Declined;
        }
        if at(p) != b',' {
            break;
        }
        p += 1;
    }
    let Some(first) = first else {
        return Parsed::NotSatisfiable;
    };
    // ngx_http_range_parse (1.30.6): one range is always taken.
    if rest.is_empty() {
        return Parsed::Ranges(Ranges { first, rest });
    }
    if size > u128::from(len) {
        return Parsed::Declined;
    }
    let parts = rest.len() as u128 + 1;
    if limit == DEFAULT_LIMIT && size + parts * 256 > u128::from(len) + 4096 {
        return Parsed::Declined;
    }
    Parsed::Ranges(Ranges { first, rest })
}

/// The value of header `name` in `head` (without the status line), trimmed.
fn header<'a>(head: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    head.split(|&b| b == b'\n').skip(1).find_map(|line| {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let colon = line.iter().position(|&b| b == b':')?;
        line[..colon]
            .eq_ignore_ascii_case(name)
            .then(|| line[colon + 1..].trim_ascii())
    })
}

/// The header lines of `head` (status line and final CRLF excluded)
/// without the `drop`ped names, then `add`, as one header block.
fn rebuild(status_line: &[u8], head: &[u8], drop: &[&[u8]], add: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(head.len() + add.len() + 32);
    out.extend_from_slice(status_line);
    for line in head.split(|&b| b == b'\n').skip(1) {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        let name = line
            .iter()
            .position(|&b| b == b':')
            .map_or(line, |c| &line[..c]);
        if drop.iter().any(|d| name.eq_ignore_ascii_case(d)) {
            continue;
        }
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(line);
    }
    out.extend_from_slice(add);
    out.extend_from_slice(b"\r\n\r\n");
    out
}

/// nginx's multipart boundary: a counter, 20 digits.
fn next_boundary() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

/// The head of a response relayed as it comes (#88), which no range can
/// cut (a request with `Range` reads it whole): `Accept-Ranges: bytes`
/// where the filter would allow ranges.
pub(crate) fn relayed_head(head: Vec<u8>, max_ranges: Option<u32>) -> Vec<u8> {
    let Some(head_end) = head.windows(4).position(|w| w == b"\r\n\r\n") else {
        return head;
    };
    let lines = &head[..head_end];
    if max_ranges == Some(0)
        || lines.get(9..12) != Some(b"200")
        || header(lines, b"content-length").is_none()
    {
        return head;
    }
    let status_line = lines.split(|&b| b == b'\n').next().unwrap_or(lines);
    let status_line = status_line.strip_suffix(b"\r").unwrap_or(status_line);
    rebuild(
        status_line,
        lines,
        &[b"accept-ranges"],
        b"\r\nAccept-Ranges: bytes",
    )
}

/// What the filter does to a response.
enum Cut {
    /// It goes out as it is.
    Pass,
    /// Whole, with `Accept-Ranges: bytes`.
    Whole,
    /// The 416 for a body of this length.
    NotSatisfiable(u64),
    /// These ranges of a body of this length.
    Ranges(Ranges, u64),
}

/// nginx's range header filter over a response whose head is `head`
/// (status line included, final CRLF not) and whose body is `body_len`
/// bytes.
fn decide(
    head: &[u8],
    body_len: u64,
    allow: RangeAllow,
    max_ranges: Option<u32>,
    req: RangeRequest<'_>,
) -> Cut {
    if head.get(9..12) != Some(b"200") || header(head, b"transfer-encoding").is_some() {
        return Cut::Pass;
    }
    let Some(len) = header(head, b"content-length")
        .and_then(|v| std::str::from_utf8(v).ok())
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&l| req.head_only || l == body_len)
    else {
        return Cut::Pass;
    };
    let Some(range) = req
        .range
        .filter(|r| r.len() >= 7 && r[..6].eq_ignore_ascii_case(b"bytes="))
    else {
        return Cut::Whole;
    };
    // Checked above.
    let range = &range[6..];
    if let Some(if_range) = req.if_range {
        let matches = if if_range.len() >= 2 && if_range.ends_with(b"\"") {
            header(head, b"etag") == Some(if_range)
        } else {
            match header(head, b"last-modified") {
                Some(lm) => {
                    crate::file::parse_http_date(if_range).is_some()
                        && crate::file::parse_http_date(if_range)
                            == crate::file::parse_http_date(lm)
                }
                None => false,
            }
        };
        if !matches {
            return Cut::Whole;
        }
    }
    let limit = match allow {
        RangeAllow::Single => 1,
        _ => limit(max_ranges),
    };
    match parse(range, len, limit) {
        Parsed::Declined => Cut::Whole,
        Parsed::NotSatisfiable => Cut::NotSatisfiable(len),
        Parsed::Ranges(ranges) => Cut::Ranges(ranges, len),
    }
}

/// `head` with `Accept-Ranges: bytes`.
fn with_accept_ranges(head: &[u8]) -> Vec<u8> {
    let status_line = head.split(|&b| b == b'\n').next().unwrap_or(head);
    let status_line = status_line.strip_suffix(b"\r").unwrap_or(status_line);
    rebuild(
        status_line,
        head,
        &[b"accept-ranges"],
        b"\r\nAccept-Ranges: bytes",
    )
}

/// The 206's head for the one range `[start, end)` of `len` bytes.
fn single_head(head: &[u8], start: u64, end: u64, len: u64) -> Vec<u8> {
    let add = format!(
        "\r\nContent-Length: {}\r\nContent-Range: bytes {}-{}/{len}",
        end - start,
        start,
        end - 1
    );
    rebuild(
        b"HTTP/1.1 206 Partial Content",
        head,
        &[b"content-length", b"content-range", b"accept-ranges"],
        add.as_bytes(),
    )
}

/// Run the filter over `response` (head and body). `max_ranges`: the
/// location's `max_ranges` (`None`: no limit; 0 turns ranges off).
/// `not_satisfiable(len, server)` builds the 416 answer (`server`: the
/// response's `Server`).
pub(crate) fn filter(
    response: Vec<u8>,
    allow: RangeAllow,
    max_ranges: Option<u32>,
    req: RangeRequest<'_>,
    not_satisfiable: impl FnOnce(u64, &[u8]) -> Vec<u8>,
) -> Vec<u8> {
    if allow == RangeAllow::No || max_ranges == Some(0) {
        return response;
    }
    let Some(head_end) = response.windows(4).position(|w| w == b"\r\n\r\n") else {
        return response;
    };
    let head = &response[..head_end];
    let body = &response[head_end + 4..];
    match decide(head, body.len() as u64, allow, max_ranges, req) {
        Cut::Pass => response,
        Cut::Whole => {
            let mut out = with_accept_ranges(head);
            out.extend_from_slice(body);
            out
        }
        Cut::NotSatisfiable(len) => {
            not_satisfiable(len, header(head, b"server").unwrap_or_default())
        }
        Cut::Ranges(ranges, len) if ranges.len() == 1 => {
            let (start, end) = ranges.first;
            let mut out = single_head(head, start, end, len);
            if !req.head_only {
                out.extend_from_slice(&body[start as usize..end as usize]);
            }
            out
        }
        Cut::Ranges(ranges, len) => {
            let read = |start: u64, end: u64, out: &mut Vec<u8>| {
                out.extend_from_slice(&body[start as usize..end as usize]);
                Ok(())
            };
            multipart(head, len, &ranges, req.head_only, read).unwrap_or_default()
        }
    }
}

/// `filter` for a response whose body is in a file (a cache hit): one
/// range is a part of the file, several are read for their multipart
/// response up to `multipart_max` bytes, beyond which the body goes whole,
/// as a static file's does (#401).
pub(crate) fn filter_file(
    headers: Vec<u8>,
    body: crate::phase::FileBody,
    allow: RangeAllow,
    max_ranges: Option<u32>,
    req: RangeRequest<'_>,
    not_satisfiable: impl FnOnce(u64, &[u8]) -> Vec<u8>,
) -> std::io::Result<crate::phase::Response> {
    use crate::phase::{FileBody, Response};
    if allow == RangeAllow::No || max_ranges == Some(0) {
        return Ok(Response::File { headers, body });
    }
    let Some(head_end) = headers.windows(4).position(|w| w == b"\r\n\r\n") else {
        return Ok(Response::File { headers, body });
    };
    let head = &headers[..head_end];
    let whole = |body| Response::File {
        headers: with_accept_ranges(head),
        body,
    };
    Ok(match decide(head, body.len, allow, max_ranges, req) {
        Cut::Pass => Response::File { headers, body },
        Cut::Whole => whole(body),
        Cut::NotSatisfiable(len) => Response::Owned(not_satisfiable(
            len,
            header(head, b"server").unwrap_or_default(),
        )),
        Cut::Ranges(ranges, len) if ranges.len() == 1 => {
            let (start, end) = ranges.first;
            Response::File {
                headers: single_head(head, start, end, len),
                body: FileBody {
                    offset: body.offset + start,
                    len: end - start,
                    fd: body.fd,
                },
            }
        }
        Cut::Ranges(ranges, _) if ranges.size() > crate::file::MULTIPART_MAX => whole(body),
        Cut::Ranges(ranges, len) => {
            use std::os::fd::AsRawFd;
            let fd = body.fd.as_raw_fd();
            let read = |start: u64, end: u64, out: &mut Vec<u8>| {
                crate::file::read_at_into(fd, body.offset + start, end - start, out)
            };
            Response::Owned(multipart(head, len, &ranges, req.head_only, read)?)
        }
    })
}

/// nginx's multipart/byteranges 206 (ngx_http_range_multipart_header,
/// ngx_http_range_multipart_body) for a 200 whose head is `head` (status
/// line included, final CRLF not) and whose body is `len` bytes: the
/// parts' headers, with `read(start, end, out)` appending each part's
/// bytes. `head_only`: the length only, no body.
pub(crate) fn multipart(
    head: &[u8],
    len: u64,
    ranges: &Ranges,
    head_only: bool,
    mut read: impl FnMut(u64, u64, &mut Vec<u8>) -> std::io::Result<()>,
) -> std::io::Result<Vec<u8>> {
    let boundary = format!("{:020}", next_boundary());
    let part_type = header(head, b"content-type")
        .map(|t| format!("\r\nContent-Type: {}", String::from_utf8_lossy(t)))
        .unwrap_or_default();
    let mut parts =
        Vec::with_capacity(if head_only { 0 } else { ranges.size() as usize } + ranges.len() * 96);
    // A HEAD response counts the parts' bodies without them.
    let mut skipped = 0;
    for (start, end) in ranges.iter() {
        parts.extend_from_slice(
            format!(
                "\r\n--{boundary}{part_type}\r\nContent-Range: bytes {}-{}/{len}\r\n\r\n",
                start,
                end - 1
            )
            .as_bytes(),
        );
        if head_only {
            skipped += end - start;
        } else {
            read(start, end, &mut parts)?;
        }
    }
    parts.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    let add = format!(
        "\r\nContent-Type: multipart/byteranges; boundary={boundary}\r\nContent-Length: {}",
        parts.len() as u64 + skipped
    );
    let status_line = b"HTTP/1.1 206 Partial Content";
    let mut out = rebuild(
        status_line,
        head,
        &[
            b"content-length",
            b"content-range",
            b"accept-ranges",
            b"content-type",
        ],
        add.as_bytes(),
    );
    if !head_only {
        out.extend_from_slice(&parts);
    }
    Ok(out)
}

/// The 416 the range filter finalizes the request with: nginx's page
/// for it (ngx_http_range_not_satisfiable, then the special response),
/// with `Content-Range: bytes */<length>`.
pub(crate) fn not_satisfiable(len: u64, head_only: bool, server: &[u8]) -> Vec<u8> {
    use crate::http::Method;
    let page = crate::http::default_error_page_body_for(416, server).unwrap_or_default();
    let method = if head_only { Method::Head } else { Method::Get };
    let mut out = crate::http::build_response_bytes_with_content_type(
        416,
        &page,
        b"text/html",
        method,
        server,
    );
    if let Some(end) = out.windows(4).position(|w| w == b"\r\n\r\n") {
        let line = format!("\r\nContent-Range: bytes */{len}");
        out.splice(end..end, line.into_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(body: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\
             Content-Range: stub\r\nETag: \"e1\"\r\nAccept-Ranges: bytes\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    fn run(allow: RangeAllow, range: &str, if_range: Option<&str>) -> String {
        let out = filter(
            response("SEE-THIS"),
            allow,
            None,
            RangeRequest {
                range: Some(range.as_bytes()),
                if_range: if_range.map(str::as_bytes),
                head_only: false,
            },
            |len, _| format!("HTTP/1.1 416 X\r\nContent-Range: bytes */{len}\r\n\r\n").into_bytes(),
        );
        String::from_utf8(out).unwrap()
    }

    fn ranges(first: (u64, u64), rest: &[(u64, u64)]) -> Parsed {
        Parsed::Ranges(Ranges {
            first,
            rest: rest.to_vec(),
        })
    }

    #[test]
    fn parses_as_nginx() {
        assert_eq!(parse(b"0-4", 8, 9), ranges((0, 5), &[]));
        assert_eq!(parse(b"4-", 8, 9), ranges((4, 8), &[]));
        assert_eq!(parse(b"-2", 8, 9), ranges((6, 8), &[]));
        assert_eq!(parse(b"0-2,4-", 8, 9), ranges((0, 3), &[(4, 8)]));
        assert_eq!(parse(b"0-2, 4-", 8, 1), Parsed::Declined);
        assert_eq!(parse(b"1000-", 8, 9), Parsed::NotSatisfiable);
        assert_eq!(parse(b"0-100", 8, 9), ranges((0, 8), &[]));
        assert_eq!(parse(b"x", 8, 9), Parsed::NotSatisfiable);
        // More than the whole body in total: the whole body instead.
        assert_eq!(parse(b"0-7,0-7", 8, 9), Parsed::Declined);
        // Also where the total doesn't fit 64 bits (#477, found by the
        // `range` fuzz target): an upstream's Content-Length near 2^64.
        assert_eq!(
            parse(b"0-,0-,0-", u64::MAX, DEFAULT_LIMIT),
            Parsed::Declined
        );
        assert_eq!(parse(b"5-,5-,5-", u64::MAX - 65406, 9), Parsed::Declined);
    }

    /// nginx 1.29.5: without `max_ranges`, several ranges are declined
    /// when they and 256 bytes per part pass the body and 4096.
    #[test]
    fn default_limit_counts_the_multipart_overhead() {
        let one_byte = |n: u64| {
            (0..n)
                .map(|i| format!("{0}-{0}", 2 * i))
                .collect::<Vec<_>>()
                .join(",")
        };
        // 16 + 16 * 256 = 4112 <= 100 + 4096; 17 + 17 * 256 > it.
        let r16 = one_byte(16);
        let r17 = one_byte(17);
        assert!(
            matches!(parse(r16.as_bytes(), 100, DEFAULT_LIMIT), Parsed::Ranges(r) if r.len() == 16)
        );
        assert_eq!(parse(r17.as_bytes(), 100, DEFAULT_LIMIT), Parsed::Declined);
        // At the edge: 16 + 16 * 256 == 16 + 4096 is taken.
        let edge = (0..16)
            .map(|i| format!("{i}-{i}"))
            .collect::<Vec<_>>()
            .join(",");
        assert!(
            matches!(parse(edge.as_bytes(), 16, DEFAULT_LIMIT), Parsed::Ranges(r) if r.len() == 16)
        );
        // An explicit max_ranges keeps the old rule only.
        assert!(matches!(parse(r17.as_bytes(), 100, 17), Parsed::Ranges(r) if r.len() == 17));
        assert!(matches!(parse(r17.as_bytes(), 100, 100), Parsed::Ranges(_)));
        // One range is always taken, whatever its size.
        assert_eq!(parse(b"0-0", 1, DEFAULT_LIMIT), ranges((0, 1), &[]));
        // nginx's unset is NGX_MAX_INT32_VALUE: `max_ranges 2147483647`
        // is the default too.
        assert_eq!(limit(None), DEFAULT_LIMIT);
        assert_eq!(limit(Some(i32::MAX as u32)), DEFAULT_LIMIT);
        assert_eq!(limit(Some(u32::MAX)), u64::from(u32::MAX));
        // No overflow on a huge length (a HEAD's Content-Length).
        assert!(matches!(
            parse(b"0-0,2-2", u64::MAX, DEFAULT_LIMIT),
            Parsed::Ranges(_)
        ));
    }

    #[test]
    fn single_range_is_206_with_its_own_content_range() {
        let out = run(RangeAllow::Single, "bytes=0-4", None);
        assert!(out.starts_with("HTTP/1.1 206 Partial Content\r\n"), "{out}");
        assert!(out.contains("\r\nContent-Range: bytes 0-4/8\r\n"), "{out}");
        assert!(
            !out.contains("stub") && !out.contains("Accept-Ranges"),
            "{out}"
        );
        assert!(out.ends_with("\r\nContent-Length: 5\r\nContent-Range: bytes 0-4/8\r\n\r\nSEE-T"));
    }

    #[test]
    fn several_ranges_are_multipart_only_where_allowed() {
        let out = run(RangeAllow::Multi, "bytes=0-2,4-", None);
        assert!(
            out.contains("Content-Type: multipart/byteranges; boundary="),
            "{out}"
        );
        assert!(out.contains(
            "\r\nContent-Type: text/plain\r\nContent-Range: bytes 0-2/8\r\n\r\nSEE\r\n--"
        ));
        assert!(
            out.contains("Content-Range: bytes 4-7/8\r\n\r\nTHIS\r\n--"),
            "{out}"
        );
        assert!(!out.contains("stub"), "{out}");
        // single_range: declined, the whole body.
        let out = run(RangeAllow::Single, "bytes=0-2,4-", None);
        assert!(
            out.starts_with("HTTP/1.1 200 OK\r\n") && out.ends_with("SEE-THIS"),
            "{out}"
        );
        assert_eq!(out.matches("Accept-Ranges: bytes").count(), 1, "{out}");
    }

    #[test]
    fn unsatisfiable_and_if_range() {
        assert!(run(RangeAllow::Multi, "bytes=1000-", None).contains("bytes */8"));
        assert!(run(RangeAllow::Single, "bytes=4-", Some("\"e1\"")).ends_with("THIS"));
        let stale = run(RangeAllow::Single, "bytes=4-", Some("\"other\""));
        assert!(
            stale.starts_with("HTTP/1.1 200 ") && stale.ends_with("SEE-THIS"),
            "{stale}"
        );
        // Not allowed: untouched.
        assert_eq!(
            run(RangeAllow::No, "bytes=4-", None).as_bytes(),
            response("SEE-THIS")
        );
    }
}
