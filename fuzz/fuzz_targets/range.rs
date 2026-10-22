//! The `Range` header (#370, #401, #477): nginx's `ngx_http_range_parse`
//! for any body length and range limit, and the range filter over a
//! response held in memory. Beyond not crashing:
//! - the ranges are within the body, not empty, at most the limit, and
//!   several add up to no more than the body (plus room for the parts'
//!   headers under the default limit, nginx 1.29.5);
//! - a 206's `Content-Length` is the length of what follows, and a single
//!   range's body is those bytes of the original.
#![no_main]

use libfuzzer_sys::fuzz_target;
use ruxen::fuzzing::{RANGE_DEFAULT_LIMIT, range_filter, range_parse};

fuzz_target!(|data: &[u8]| {
    // 8 bytes of length, 1 of limit, 1 of flags, then the header value.
    let [l0, l1, l2, l3, l4, l5, l6, l7, limit, flags, value @ ..] = data else {
        return;
    };
    let len = u64::from_le_bytes([*l0, *l1, *l2, *l3, *l4, *l5, *l6, *l7]);
    // Small lengths half of the time, where the bodies can be built.
    let len = if flags & 1 == 0 { len % 4096 } else { len };
    let limit = match limit {
        255 => RANGE_DEFAULT_LIMIT,
        n => u64::from(*n),
    };
    let mut header = b"bytes=".to_vec();
    header.extend_from_slice(value);
    if let Some(Ok(ranges)) = range_parse(&header, len, limit) {
        assert!(!ranges.is_empty());
        assert!(
            ranges.len() as u64 <= limit,
            "{} ranges over {limit}",
            ranges.len()
        );
        for &(start, end) in &ranges {
            assert!(start < end && end <= len, "{start}-{end} of {len}");
        }
        if ranges.len() > 1 {
            let size: u128 = ranges.iter().map(|(s, e)| u128::from(e - s)).sum();
            assert!(size <= u128::from(len), "{size} bytes of {len}");
            if limit == RANGE_DEFAULT_LIMIT {
                let parts = ranges.len() as u128 * 256;
                assert!(size + parts <= u128::from(len) + 4096);
            }
        }
    }

    // The filter, over a body it can hold.
    if len > 4096 {
        return;
    }
    let body: Vec<u8> = (0..len).map(|i| b'a' + (i % 26) as u8).collect();
    let head_only = flags & 2 != 0;
    let multi = flags & 4 != 0;
    let max_ranges = (flags & 8 != 0).then_some(u32::from(flags >> 4));
    let out = range_filter(&body, &header, head_only, multi, max_ranges);
    let head_end = out
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("a head");
    let head = std::str::from_utf8(&out[..head_end]).expect("an ASCII head");
    let rest = &out[head_end + 4..];
    let content_length: u64 = head
        .lines()
        .find_map(|l| l.strip_prefix("Content-Length: "))
        .expect("Content-Length")
        .parse()
        .expect("a number");
    if head_only {
        assert!(rest.is_empty());
    } else {
        assert_eq!(content_length, rest.len() as u64, "{head}");
    }
    if head.starts_with("HTTP/1.1 200") && !head_only {
        assert_eq!(rest, &body[..]);
    }
    if let Some(range) = head
        .lines()
        .find_map(|l| l.strip_prefix("Content-Range: bytes "))
    {
        if head.starts_with("HTTP/1.1 206") {
            let (span, total) = range.split_once('/').expect("a total");
            let (start, end) = span.split_once('-').expect("a span");
            let (start, end): (usize, usize) = (start.parse().unwrap(), end.parse().unwrap());
            assert_eq!(total, len.to_string());
            assert_eq!(content_length as usize, end + 1 - start);
            if !head_only {
                assert_eq!(rest, &body[start..=end]);
            }
        }
    }
});
