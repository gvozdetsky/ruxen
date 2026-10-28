//! Rewrite rendering (#477): requests through a server with a fixed set of
//! `rewrite` rules, against a model of nginx's script code
//! (`ngx_http_script_regex_start_code` / `_end_code`,
//! `ngx_http_script_copy_capture_code`, `ngx_escape_uri`'s args table):
//! captures into the target, `$args` carried over or dropped, the redirect's
//! unescaping, the empty URI, the internal redirection cycle. A `Location`
//! never carries a control byte, a space or a byte above DEL.
//!
//! Also `unescape_redirect` against a port of `ngx_unescape_uri(…,
//! NGX_UNESCAPE_REDIRECT)`, and the `Location` escaping, which a decoder
//! undoes when the input has no `%`.
#![no_main]

use libfuzzer_sys::fuzz_target;
use regex::bytes::Regex;
use ruxen::fuzzing::{Server, escape_redirect_location, normalize_uri, unescape_redirect};

const CONFIG: &str = r#"
error_log /dev/null crit;
events {}
http {
    access_log off;
    absolute_redirect off;
    server {
        listen 127.0.0.1:8080;
        location / {
            rewrite ^/a/([^/]*)/(.*)$ /in/$2?x=$1 last;
            rewrite ^/b/(.*)$ /in/$1? last;
            rewrite ^/n/(.*)$ /in/$1;
            rewrite ^/e(/.*)?$ $1 last;
            rewrite ^/r/(.*)$ /t/$1 redirect;
            rewrite ^/p/([^/]*)$ /t/$1?q=$1 permanent;
            return 200 "root $uri|$args";
        }
        location /in/ {
            return 200 "in $uri|$args";
        }
    }
}
"#;

struct Rules {
    a: Regex,
    b: Regex,
    n: Regex,
    e: Regex,
    r: Regex,
    p: Regex,
}

thread_local! {
    static SERVER: Server = Server::new(CONFIG);
    // As ruxen compiles them.
    static RULES: Rules = Rules {
        a: Regex::new("^/a/([^/]*)/(.*)$").unwrap(),
        b: Regex::new("^/b/(.*)$").unwrap(),
        n: Regex::new("^/n/(.*)$").unwrap(),
        e: Regex::new("^/e(/.*)?$").unwrap(),
        r: Regex::new("^/r/(.*)$").unwrap(),
        p: Regex::new("^/p/([^/]*)$").unwrap(),
    };
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    if mode & 1 == 1 {
        assert_eq!(unescape_redirect(rest), nginx_unescape_redirect(rest));
        let escaped = escape_redirect_location(rest);
        assert!(escaped.iter().all(|&b| b > 0x20 && b < 0x7f));
        if !rest.contains(&b'%') {
            assert_eq!(percent_decode(&escaped), rest);
        }
        return;
    }
    if rest.first() != Some(&b'/') {
        return;
    }
    let Some(got) = SERVER.with(|s| s.get(rest)) else {
        return;
    };
    // The request target as the parser found it.
    let want = RULES.with(|rules| model(rules, &got.target));
    let target = String::from_utf8_lossy(&got.target);
    match want {
        Want::Status(status) => assert_eq!(got.status, status, "{target:?}"),
        Want::Body(body) => {
            assert_eq!(got.status, 200, "{target:?}");
            assert_eq!(
                String::from_utf8_lossy(&got.body),
                String::from_utf8_lossy(&body),
                "{target:?}"
            );
        }
        Want::Redirect(status, location) => {
            assert_eq!(got.status, status, "{target:?}");
            let got = got.location.expect("Location");
            assert!(got.iter().all(|&b| b > 0x20 && b < 0x7f), "{target:?}");
            assert_eq!(
                String::from_utf8_lossy(&got),
                String::from_utf8_lossy(&escape_redirect_location(&location)),
                "{target:?}"
            );
        }
    }
});

enum Want {
    Status(u16),
    Body(Vec<u8>),
    /// The status and the target before ruxen's `Location` escaping.
    Redirect(u16, Vec<u8>),
}

/// The configuration above as nginx runs it.
fn model(rules: &Rules, target: &[u8]) -> Want {
    // A fragment is no part of the request.
    let target = &target[..target
        .iter()
        .position(|&b| b == b'#')
        .unwrap_or(target.len())];
    let (path, mut args) = match target.iter().position(|&b| b == b'?') {
        Some(q) => (&target[..q], target[q + 1..].to_vec()),
        None => (target, Vec::new()),
    };
    let Ok(mut uri) = normalize_uri(path, true) else {
        return Want::Status(400);
    };
    // r->quoted_uri || r->plus_in_uri: captures are escaped then.
    let quoted = path.contains(&b'%') || path.contains(&b'+');
    let esc = |cap: &[u8]| {
        if quoted {
            escape_args(cap)
        } else {
            cap.to_vec()
        }
    };
    let cap = |c: &regex::bytes::Captures<'_>, n: usize| {
        c.get(n).map_or(&[][..], |m| m.as_bytes()).to_vec()
    };
    // NGX_HTTP_MAX_URI_CHANGES.
    for _ in 0..=10 {
        if uri.starts_with(b"/in/") {
            return Want::Body([b"in ", &uri[..], b"|", &args[..]].concat());
        }
        let mut reroute = false;
        if let Some(c) = rules.a.captures(&uri) {
            let mut new_args = [b"x=", &esc(&cap(&c, 1))[..]].concat();
            if !args.is_empty() {
                new_args.push(b'&');
                new_args.extend_from_slice(&args);
            }
            uri = [b"/in/", &cap(&c, 2)[..]].concat();
            args = new_args;
            reroute = true;
        } else if let Some(c) = rules.b.captures(&uri) {
            uri = [b"/in/", &cap(&c, 1)[..]].concat();
            args.clear();
            reroute = true;
        } else {
            // No flag: the program goes on with the new URI.
            if let Some(c) = rules.n.captures(&uri) {
                uri = [b"/in/", &cap(&c, 1)[..]].concat();
            }
            if let Some(c) = rules.e.captures(&uri) {
                uri = cap(&c, 1);
                if uri.is_empty() {
                    return Want::Status(500);
                }
                reroute = true;
            } else if let Some(c) = rules.r.captures(&uri) {
                let mut location =
                    nginx_unescape_redirect(&[b"/t/", &esc(&cap(&c, 1))[..]].concat());
                if !args.is_empty() {
                    location.push(b'?');
                    location.extend_from_slice(&args);
                }
                return Want::Redirect(302, location);
            } else if let Some(c) = rules.p.captures(&uri) {
                let one = esc(&cap(&c, 1));
                let mut location =
                    nginx_unescape_redirect(&[b"/t/", &one[..], b"?q=", &one[..]].concat());
                if !args.is_empty() {
                    location.push(b'&');
                    location.extend_from_slice(&args);
                }
                return Want::Redirect(301, location);
            }
        }
        if !reroute {
            return Want::Body([b"root ", &uri[..], b"|", &args[..]].concat());
        }
    }
    // "rewrite or internal redirection cycle".
    Want::Status(500)
}

/// `ngx_escape_uri(…, NGX_ESCAPE_ARGS)`, from its table.
fn escape_args(src: &[u8]) -> Vec<u8> {
    const ARGS: [u32; 8] = [
        0xffffffff, 0xd800086d, 0x50000000, 0xb8000001, 0xffffffff, 0xffffffff, 0xffffffff,
        0xffffffff,
    ];
    let mut out = Vec::new();
    for &b in src {
        if ARGS[usize::from(b >> 5)] & (1 << (b & 0x1f)) != 0 {
            out.extend_from_slice(format!("%{b:02X}").as_bytes());
        } else {
            out.push(b);
        }
    }
    out
}

/// `ngx_unescape_uri(…, NGX_UNESCAPE_REDIRECT)` as `ngx_string.c` writes
/// it, and `ngx_http_script_regex_end_code` copying what follows a `?`.
fn nginx_unescape_redirect(src: &[u8]) -> Vec<u8> {
    let mut d = Vec::new();
    let (mut state, mut decoded) = (0, 0u8);
    let mut i = 0;
    while i < src.len() {
        let ch = src[i];
        i += 1;
        match state {
            0 => {
                if ch == b'?' {
                    d.push(ch);
                    d.extend_from_slice(&src[i..]);
                    return d;
                }
                if ch == b'%' {
                    state = 1;
                } else {
                    d.push(ch);
                }
            }
            1 => {
                let c = ch | 0x20;
                if ch.is_ascii_digit() {
                    decoded = ch - b'0';
                    state = 2;
                } else if (b'a'..=b'f').contains(&c) {
                    decoded = c - b'a' + 10;
                    state = 2;
                } else {
                    state = 0;
                    d.push(ch);
                }
            }
            _ => {
                state = 0;
                let c = ch | 0x20;
                let value = if ch.is_ascii_digit() {
                    (decoded << 4) + (ch - b'0')
                } else if (b'a'..=b'f').contains(&c) {
                    let v = (decoded << 4) + (c - b'a') + 10;
                    if v == b'?' {
                        d.push(v);
                        d.extend_from_slice(&src[i..]);
                        return d;
                    }
                    v
                } else {
                    continue;
                };
                if value > b'%' && value < 0x7f {
                    d.push(value);
                } else {
                    d.extend_from_slice(&[b'%', src[i - 2], src[i - 1]]);
                }
            }
        }
    }
    d
}

fn percent_decode(src: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < src.len() {
        if src[i] == b'%' {
            let hex = std::str::from_utf8(&src[i + 1..i + 3]).unwrap();
            out.push(u8::from_str_radix(hex, 16).unwrap());
            i += 3;
        } else {
            out.push(src[i]);
            i += 1;
        }
    }
    out
}
