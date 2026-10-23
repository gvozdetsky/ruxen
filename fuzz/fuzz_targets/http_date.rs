//! HTTP dates (#477): `If-Modified-Since` / `If-Range` in IMF-fixdate,
//! RFC 850 and asctime form (nginx's ngx_parse_http_time). Beyond not
//! crashing: a date that parses formats back to one that parses to the
//! same second, and any second up to the end of year 9999 survives
//! format then parse.
#![no_main]

use libfuzzer_sys::fuzz_target;
use ruxen::fuzzing::{MAX_HTTP_DATE_SECS, format_http_date, parse_http_date};

fuzz_target!(|data: &[u8]| {
    if let Some(secs) = parse_http_date(data) {
        assert!(secs <= MAX_HTTP_DATE_SECS, "{secs}");
        assert_eq!(parse_http_date(&format_http_date(secs)), Some(secs));
    }
    if let Some(bytes) = data.get(..8) {
        let secs = u64::from_le_bytes(bytes.try_into().unwrap()) % (MAX_HTTP_DATE_SECS + 1);
        let formatted = format_http_date(secs);
        assert_eq!(
            parse_http_date(&formatted),
            Some(secs),
            "{}",
            String::from_utf8_lossy(&formatted)
        );
    }
});
