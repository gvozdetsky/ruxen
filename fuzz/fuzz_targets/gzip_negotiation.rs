//! gzip's request checks (#477) against a port of nginx's own code:
//! `Accept-Encoding` (`ngx_http_gzip_accept_encoding` and
//! `ngx_http_gzip_quantity`, src/http/ngx_http_core_module.c, with the
//! shortcuts of `ngx_http_gzip_ok`), and the `User-Agent` test behind
//! `gzip_disable msie6` (`ngx_http_user_agent`, ngx_http_request.c).
#![no_main]

use libfuzzer_sys::fuzz_target;
use ruxen::fuzzing::{accepts_gzip, is_msie6};

fuzz_target!(|data: &[u8]| {
    // nginx's header values have no NUL (its parser refuses them), and its
    // string searches stop at one.
    if data.contains(&0) {
        return;
    }
    assert_eq!(
        accepts_gzip(data),
        nginx_accepts_gzip(data),
        "{:?}",
        data.escape_ascii().to_string()
    );
    assert_eq!(
        is_msie6(data),
        nginx_msie6(data),
        "{:?}",
        data.escape_ascii().to_string()
    );
});

/// `ngx_strcasestrn(s, "gzip", 3)`: the first `gzip`, any case, at or
/// after `from`.
fn find_gzip(ae: &[u8], from: usize) -> Option<usize> {
    (from..ae.len().saturating_sub(3)).find(|&i| ae[i..i + 4].eq_ignore_ascii_case(b"gzip"))
}

fn nginx_accepts_gzip(ae: &[u8]) -> bool {
    // ngx_http_gzip_ok's shortcuts.
    if ae.len() >= 5 && &ae[..5] == b"gzip," {
        return true;
    }
    if ae.len() < 4 {
        return false;
    }
    let mut start = 0;
    let mut p = loop {
        let Some(p) = find_gzip(ae, start) else {
            return false;
        };
        if p == 0 || ae[p - 1] == b',' || ae[p - 1] == b' ' {
            break p;
        }
        start = p + 4;
    };
    p += 4;
    let last = ae.len();
    // After the token.
    loop {
        if p >= last {
            return true;
        }
        let c = ae[p];
        p += 1;
        match c {
            b',' => return true,
            b';' => break,
            b' ' => continue,
            _ => return false,
        }
    }
    // quantity:
    loop {
        if p >= last {
            return true;
        }
        let c = ae[p];
        p += 1;
        match c {
            b'q' | b'Q' => break,
            b' ' => continue,
            _ => return false,
        }
    }
    // equal:
    if p + 2 > last || ae[p] != b'=' {
        return false;
    }
    p += 1;
    nginx_quantity(&ae[p..]) != 0
}

fn nginx_quantity(v: &[u8]) -> u64 {
    let mut p = 0;
    let c = v[p];
    p += 1;
    if c != b'0' && c != b'1' {
        return 0;
    }
    let mut q = u64::from(c - b'0') * 100;
    if p == v.len() {
        return q;
    }
    let c = v[p];
    p += 1;
    if c == b',' || c == b' ' {
        return q;
    }
    if c != b'.' {
        return 0;
    }
    let mut n = 0;
    while p < v.len() {
        let c = v[p];
        p += 1;
        if c == b',' || c == b' ' {
            break;
        }
        if c.is_ascii_digit() {
            q += u64::from(c - b'0');
            n += 1;
            continue;
        }
        return 0;
    }
    if q > 100 || n > 3 { 0 } else { q }
}

/// `ngx_strstrn`: case-sensitive.
fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn nginx_msie6(ua: &[u8]) -> bool {
    let mut msie6 = false;
    if let Some(m) = find(ua, b"MSIE ")
        && m + 7 < ua.len()
        && ua[m + 6] == b'.'
    {
        msie6 = match ua[m + 5] {
            b'4' | b'5' => true,
            b'6' => find(&ua[m + 8..], b"SV1").is_none(),
            _ => false,
        };
    }
    if find(ua, b"Opera").is_some() {
        msie6 = false;
    }
    msie6
}
