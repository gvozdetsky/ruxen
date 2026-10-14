//! nginx's range filter (`ngx_http_range_filter_module`) over a response
//! held whole in memory: a proxied response (#370) or a cached one. Static
//! files take their single range in `file.rs`.
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
enum Parsed {
    /// `[start, end)` pairs.
    Ranges(Vec<(u64, u64)>),
    NotSatisfiable,
    /// The whole response, as if there were no `Range`.
    Declined,
}

/// `value` after `bytes=`, against a body of `len` bytes, at most `limit`
/// ranges (nginx's `ranges`; more is declined).
fn parse(value: &[u8], len: u64, limit: u64) -> Parsed {
    let mut p = 0;
    let at = |i: usize| value.get(i).copied().unwrap_or(0);
    let mut ranges = Vec::new();
    let mut size: u64 = 0;
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
                    ranges.push((start, end));
                    size += end - start;
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
            ranges.push((start, end));
            size += end - start;
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
    if ranges.is_empty() {
        return Parsed::NotSatisfiable;
    }
    if size > len {
        return Parsed::Declined;
    }
    Parsed::Ranges(ranges)
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
    if head.get(9..12) != Some(b"200") || header(head, b"transfer-encoding").is_some() {
        return response;
    }
    let Some(len) = header(head, b"content-length")
        .and_then(|v| std::str::from_utf8(v).ok())
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&l| req.head_only || l == body.len() as u64)
    else {
        return response;
    };
    let accept_ranges = |response: Vec<u8>| {
        let head = &response[..head_end];
        let status_line = head.split(|&b| b == b'\n').next().unwrap_or(head);
        let status_line = status_line.strip_suffix(b"\r").unwrap_or(status_line);
        let mut out = rebuild(
            status_line,
            head,
            &[b"accept-ranges"],
            b"\r\nAccept-Ranges: bytes",
        );
        out.extend_from_slice(&response[head_end + 4..]);
        out
    };
    let Some(range) = req
        .range
        .filter(|r| r.len() >= 7 && r[..6].eq_ignore_ascii_case(b"bytes="))
    else {
        return accept_ranges(response);
    };
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
            return accept_ranges(response);
        }
    }
    let limit = match allow {
        RangeAllow::Single => 1,
        _ => max_ranges.map_or(u64::MAX, u64::from),
    };
    match parse(&range[6..], len, limit) {
        Parsed::Declined => accept_ranges(response),
        Parsed::NotSatisfiable => not_satisfiable(len, header(head, b"server").unwrap_or_default()),
        Parsed::Ranges(ranges) if ranges.len() == 1 => {
            let (start, end) = ranges[0];
            let add = format!(
                "\r\nContent-Length: {}\r\nContent-Range: bytes {}-{}/{len}",
                end - start,
                start,
                end - 1
            );
            let mut out = rebuild(
                b"HTTP/1.1 206 Partial Content",
                head,
                &[b"content-length", b"content-range", b"accept-ranges"],
                add.as_bytes(),
            );
            if !req.head_only {
                out.extend_from_slice(&body[start as usize..end as usize]);
            }
            out
        }
        Parsed::Ranges(ranges) => {
            let boundary = format!("{:020}", next_boundary());
            let part_type = header(head, b"content-type")
                .map(|t| format!("\r\nContent-Type: {}", String::from_utf8_lossy(t)))
                .unwrap_or_default();
            let mut parts = Vec::with_capacity(body.len() + ranges.len() * 96);
            // A HEAD response counts the parts' bodies without them.
            let mut skipped = 0;
            for &(start, end) in &ranges {
                parts.extend_from_slice(
                    format!(
                        "\r\n--{boundary}{part_type}\r\nContent-Range: bytes {}-{}/{len}\r\n\r\n",
                        start,
                        end - 1
                    )
                    .as_bytes(),
                );
                if req.head_only {
                    skipped += end - start;
                } else {
                    parts.extend_from_slice(&body[start as usize..end as usize]);
                }
            }
            parts.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
            let add = format!(
                "\r\nContent-Type: multipart/byteranges; boundary={boundary}\r\nContent-Length: {}",
                parts.len() as u64 + skipped
            );
            let mut out = rebuild(
                b"HTTP/1.1 206 Partial Content",
                head,
                &[
                    b"content-length",
                    b"content-range",
                    b"accept-ranges",
                    b"content-type",
                ],
                add.as_bytes(),
            );
            if !req.head_only {
                out.extend_from_slice(&parts);
            }
            out
        }
    }
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

    #[test]
    fn parses_as_nginx() {
        assert_eq!(parse(b"0-4", 8, 9), Parsed::Ranges(vec![(0, 5)]));
        assert_eq!(parse(b"4-", 8, 9), Parsed::Ranges(vec![(4, 8)]));
        assert_eq!(parse(b"-2", 8, 9), Parsed::Ranges(vec![(6, 8)]));
        assert_eq!(parse(b"0-2,4-", 8, 9), Parsed::Ranges(vec![(0, 3), (4, 8)]));
        assert_eq!(parse(b"0-2, 4-", 8, 1), Parsed::Declined);
        assert_eq!(parse(b"1000-", 8, 9), Parsed::NotSatisfiable);
        assert_eq!(parse(b"0-100", 8, 9), Parsed::Ranges(vec![(0, 8)]));
        assert_eq!(parse(b"x", 8, 9), Parsed::NotSatisfiable);
        // More than the whole body in total: the whole body instead.
        assert_eq!(parse(b"0-7,0-7", 8, 9), Parsed::Declined);
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
