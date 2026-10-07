//! M87 — the access module: `allow` / `deny`, `satisfy`, and
//! `limit_except`. Before, `allow` and `deny` were unknown directives,
//! `limit_except` was refused and `satisfy` ignored. A 401 or 403 from the
//! access phase now goes through `error_page`, which auth_basic's 401 used
//! to skip. Checked against nginx 1.24.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

/// `METHOD path [user:password]` → "status body".
fn request(port: u16, line: &str) -> String {
    let mut words = line.split(' ');
    let (method, path) = (words.next().unwrap(), words.next().unwrap());
    let auth = match words.next() {
        Some(creds) => format!("Authorization: Basic {}\r\n", base64(creds.as_bytes())),
        None => String::new(),
    };
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(
        s,
        "{method} {path} HTTP/1.1\r\nHost: x\r\n{auth}Content-Length: 0\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    let code = out.get(9..12).unwrap_or("").to_string();
    let body = out.split_once("\r\n\r\n").map_or("", |(_, b)| b).trim();
    // HEAD and the built-in error pages: the status is enough.
    let reason = out.lines().next().and_then(|l| l.get(13..)).unwrap_or("");
    if body.is_empty() || body.contains(reason) || body.contains(&code) {
        return code;
    }
    format!("{code} {body}")
}

fn base64(input: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(T[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[test]
fn access_rules_satisfy_and_limit_except() {
    let setup = common::ports::setup_lock();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let d = std::env::temp_dir().join(format!("ruxen-m87-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(d.join("html/page")).unwrap();
    for dir in ["w", "d", "v6", "nest/in", "nest/inherit", "le-allow"] {
        std::fs::create_dir_all(d.join("html").join(dir)).unwrap();
        std::fs::write(d.join("html").join(dir).join("index.html"), dir).unwrap();
    }
    std::fs::write(d.join("html/page/denied.html"), "denied page").unwrap();
    std::fs::write(d.join("htpasswd"), "u:{PLAIN}p\n").unwrap();
    let dd = d.display();
    let auth = format!("auth_basic \"r\"; auth_basic_user_file {dd}/htpasswd;");
    std::fs::write(
        d.join("nginx.conf"),
        format!(
            "pid {dd}/ruxen.pid;\nerror_log {dd}/error.log;\nevents {{}}\nhttp {{\n\
             access_log off;\n\
             server {{ listen 127.0.0.1:{port}; root {dd}/html;\n\
               location /w {{ allow 127.0.0.1; deny all; }}\n\
               location /d {{ deny 127.0.0.0/8; allow all; }}\n\
               location /all {{ deny all; error_page 403 /page/denied.html; }}\n\
               location /v6 {{ deny ::1; }}\n\
               location /nest {{ deny all;\n\
                 location /nest/in {{ allow all; }}\n\
                 location /nest/inherit {{ }}\n\
               }}\n\
               location /any {{ satisfy any; allow 10.0.0.1; deny all; {auth} }}\n\
               location /any-ok {{ satisfy any; allow 127.0.0.1; deny all; {auth} }}\n\
               location /both {{ allow 127.0.0.1; deny all; {auth} error_page 401 /page/denied.html; }}\n\
               location /le {{ limit_except GET {{ deny all; }} return 200 \"le\"; }}\n\
               location /le-allow {{ limit_except GET {{ allow 127.0.0.1; deny all; }} return 200 \"le\"; }}\n\
               location /le-auth {{ {auth} limit_except GET {{ auth_basic off; }} }}\n\
             }}\n\
             }}\n"
        ),
    )
    .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .arg("-c")
        .arg(d.join("nginx.conf"))
        .env("TMPDIR", &d)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    while !d.join("ruxen.pid").exists() {
        assert!(
            Instant::now() < deadline && child.try_wait().unwrap().is_none(),
            "ruxen did not start"
        );
        sleep(Duration::from_millis(10));
    }
    drop(setup);

    let cases = [
        // The first matching rule decides.
        ("GET /w/", "200 w"),
        ("GET /d/", "403"),
        // error_page applies to the access phase's 403.
        ("GET /all", "403 denied page"),
        // IPv4 clients don't match IPv6 rules.
        ("GET /v6/", "200 v6"),
        // A nested location without rules inherits its parent's list,
        // one with rules replaces it.
        ("GET /nest/in/", "200 nest/in"),
        ("GET /nest/inherit/", "403"),
        // satisfy any: no rule allows, so auth_basic decides, and its 401
        // wins over the rules' 403.
        ("GET /any", "401"),
        ("GET /any u:p", "404"),
        ("GET /any u:bad", "401"),
        // satisfy any: an allow skips auth_basic, broken user file and all.
        ("GET /any-ok", "404"),
        // satisfy all: both must pass; error_page applies to the 401.
        ("GET /both", "401 denied page"),
        ("GET /both u:p", "404"),
        // limit_except: GET and HEAD pass; for the other methods the
        // location's `return` doesn't run, as in nginx.
        ("GET /le", "200 le"),
        ("HEAD /le", "200"),
        ("POST /le", "403"),
        ("DELETE /le", "403"),
        ("PATCH /le", "403"),
        // Allowed by the block: not `return` but the static handler
        // answers, which refuses a POST to an existing file.
        ("GET /le-allow", "200 le"),
        ("POST /le-allow/index.html", "405"),
        // The block turns the location's auth_basic off for other methods.
        ("GET /le-auth/", "401"),
        ("PUT /le-auth/", "405"),
    ];
    let got: Vec<String> = cases.iter().map(|(r, _)| request(port, r)).collect();
    let _ = child.kill();
    let _ = child.wait();
    let log = std::fs::read_to_string(d.join("error.log")).unwrap_or_default();
    let _ = std::fs::remove_dir_all(&d);
    for ((req, want), got) in cases.iter().zip(&got) {
        assert_eq!(got, want, "{req}");
    }
    // One error line per 403 from the rules (not for satisfy any's 401s).
    let forbidden: Vec<&str> = log
        .lines()
        .filter(|l| l.contains("access forbidden by rule"))
        .collect();
    assert_eq!(forbidden.len(), 6, "{log}");
    assert!(
        forbidden[0].contains("[error]")
            && forbidden[0].contains("client: 127.0.0.1")
            && forbidden[0].contains("request: \"GET /d/ HTTP/1.1\""),
        "{}",
        forbidden[0]
    );
}

#[test]
fn bad_access_directives_fail_to_load() {
    let d = std::env::temp_dir().join(format!("ruxen-m87-t-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    let check = |body: &str| {
        std::fs::write(
            d.join("nginx.conf"),
            format!("events {{}}\nhttp {{ server {{ listen 127.0.0.1:1; {body} }} }}\n"),
        )
        .unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_ruxen"))
            .arg("-t")
            .arg("-c")
            .arg(d.join("nginx.conf"))
            .output()
            .unwrap();
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    };
    let cases = [
        ("allow 10.0.0.0/33;", "bad value for allow: 10.0.0.0/33"),
        ("deny example.com;", "bad value for deny: example.com"),
        ("satisfy some;", "bad value for satisfy: some"),
        (
            "location / { limit_except GET FETCH { deny all; } }",
            "bad value for limit_except method: FETCH",
        ),
        (
            "location / { limit_except GET { proxy_pass http://127.0.0.1:1; } }",
            "unknown directive `proxy_pass` in limit_except",
        ),
        (
            "location / { limit_except GET { deny all; } limit_except POST { deny all; } }",
            "duplicate directive `limit_except`",
        ),
    ];
    for (body, want) in cases {
        let (ok, stderr) = check(body);
        assert!(!ok && stderr.contains(want), "{body}: {stderr}");
    }
    // Host bits in a CIDR block are cleared with a warning.
    let (ok, stderr) = check("allow 127.0.0.1/8;");
    let _ = std::fs::remove_dir_all(&d);
    assert!(ok, "{stderr}");
    assert!(
        stderr.contains("[warn]")
            && stderr.contains("low address bits of 127.0.0.1/8 are meaningless"),
        "{stderr}"
    );
}
