// End-to-end test for M3 static file serving.
//
// Spawns the ruxen binary against a tempdir tree on a free port, then runs
// a series of HTTP/1.1 requests over a single keep-alive connection and
// asserts the responses. Everything cleans up via a guard that kills the
// child on drop — no zombie processes if an assertion panics.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, MutexGuard};
use std::thread::sleep;
use std::time::{Duration, Instant};

struct ServerGuard {
    child: Child,
    tempdir: PathBuf,
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.tempdir);
    }
}

// Serializes port-picking + spawn + readiness across parallel tests. Without
// this, `pick_port` drops its `:0` listener before ruxen binds, leaving a
// window where a sibling test's `bind :0` can return the same port; both
// ruxens then bind it via `SO_REUSEPORT` and the kernel load-balances
// requests across two different tempdirs, producing empty / wrong responses.
// Holding the lock until `wait_for_listen` returns guarantees ruxen owns the
// port before the next test's `pick_port` runs — Linux won't hand out a port
// whose binder has `SO_REUSEPORT` to a caller that doesn't request it.
static SETUP_LOCK: Mutex<()> = Mutex::new(());

fn pick_port() -> (u16, MutexGuard<'static, ()>) {
    let g = SETUP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let p = l.local_addr().unwrap().port();
    drop(l);
    (p, g)
}

fn unique_dir() -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let d = std::env::temp_dir().join(format!(
        "ruxen-it-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir(&d).unwrap();
    d
}

fn setup_server() -> (ServerGuard, u16) {
    let (port, _lock) = pick_port();
    let dir = unique_dir();
    std::fs::write(dir.join("index.html"), b"<h1>ok</h1>").unwrap();
    std::fs::write(dir.join("data.json"), br#"{"ok":true}"#).unwrap();
    std::fs::create_dir(dir.join("sub")).unwrap();
    std::fs::write(dir.join("sub/nested.txt"), b"nested body").unwrap();

    let conf = dir.join("ruxen.conf");
    std::fs::write(
        &conf,
        format!(
            "http {{ server {{ listen {port}; location / {{ root {}; }} }} }}\n",
            dir.display()
        ),
    )
    .unwrap();

    let child = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .arg(&conf)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ruxen");

    // Poll for readiness — the server should be up within a second.
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        if Instant::now() > deadline {
            panic!("ruxen did not start listening on port {port}");
        }
        sleep(Duration::from_millis(20));
    }

    (
        ServerGuard {
            child,
            tempdir: dir,
        },
        port,
    )
}

fn setup_prefixed_root_server() -> (ServerGuard, u16) {
    let (port, _lock) = pick_port();
    let dir = unique_dir();
    // nginx `root` semantics: the request URI is appended verbatim to the
    // configured root. So with `location /static { root <dir>/www; }` and
    // `GET /static/file.txt`, the file on disk must live at
    // `<dir>/www/static/file.txt` — not `<dir>/www/file.txt` (that would be
    // `alias` behavior).
    std::fs::create_dir_all(dir.join("www/static")).unwrap();
    std::fs::write(dir.join("www/static/file.txt"), b"ok").unwrap();

    let conf = dir.join("ruxen.conf");
    std::fs::write(
        &conf,
        format!(
            "http {{ server {{ listen {port}; location /static {{ root {}/www; }} }} }}\n",
            dir.display()
        ),
    )
    .unwrap();

    let child = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .arg(&conf)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ruxen");

    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        if Instant::now() > deadline {
            panic!("ruxen did not start listening on port {port}");
        }
        sleep(Duration::from_millis(20));
    }

    (
        ServerGuard {
            child,
            tempdir: dir,
        },
        port,
    )
}

fn setup_return_server() -> (ServerGuard, u16) {
    let (port, _lock) = pick_port();
    let dir = unique_dir();

    let conf = dir.join("ruxen.conf");
    std::fs::write(
        &conf,
        format!("http {{ server {{ listen {port}; location / {{ return 200 \"hello\"; }} }} }}\n",),
    )
    .unwrap();

    let child = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .arg(&conf)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ruxen");

    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        if Instant::now() > deadline {
            panic!("ruxen did not start listening on port {port}");
        }
        sleep(Duration::from_millis(20));
    }

    (
        ServerGuard {
            child,
            tempdir: dir,
        },
        port,
    )
}

/// Send one request on a fresh connection, return the raw response bytes.
/// Sized for small static files only; reads until the server closes or 8 KiB.
fn request(port: u16, raw: &[u8]) -> Vec<u8> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    s.write_all(raw).unwrap();
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match s.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                out.extend_from_slice(&buf[..n]);
                if out.len() > 64 * 1024 {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    out
}

fn status_line(resp: &[u8]) -> &str {
    let end = resp.iter().position(|&b| b == b'\r').unwrap_or(resp.len());
    std::str::from_utf8(&resp[..end]).unwrap()
}

fn header(resp: &[u8], name: &str) -> Option<String> {
    let s = std::str::from_utf8(resp).ok()?;
    let head_end = s.find("\r\n\r\n")?;
    let head = &s[..head_end];
    for line in head.lines().skip(1) {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case(name) {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

fn body(resp: &[u8]) -> &[u8] {
    resp.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| &resp[i + 4..])
        .unwrap_or(&[])
}

#[test]
fn m3_end_to_end() {
    let (_guard, port) = setup_server();

    // 1. Basic GET
    let r = request(
        port,
        b"GET /index.html HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_line(&r), "HTTP/1.1 200 OK");
    assert_eq!(
        header(&r, "Content-Type").as_deref(),
        Some("text/html; charset=utf-8")
    );
    assert_eq!(header(&r, "Content-Length").as_deref(), Some("11"));
    assert!(header(&r, "Last-Modified").is_some());
    assert_eq!(body(&r), b"<h1>ok</h1>");

    // 2. JSON mime lookup
    let r = request(
        port,
        b"GET /data.json HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_line(&r), "HTTP/1.1 200 OK");
    assert_eq!(
        header(&r, "Content-Type").as_deref(),
        Some("application/json")
    );
    assert_eq!(body(&r), br#"{"ok":true}"#);

    // 3. HEAD omits body but keeps headers
    let r = request(
        port,
        b"HEAD /index.html HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_line(&r), "HTTP/1.1 200 OK");
    assert_eq!(header(&r, "Content-Length").as_deref(), Some("11"));
    assert_eq!(body(&r), b"");

    // 4. 404 for missing file
    let r = request(
        port,
        b"GET /nope HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_line(&r), "HTTP/1.1 404 Not Found");

    // 5. Traversal attempts all blocked (403 from URI normalizer)
    for raw in [
        &b"GET /../../etc/passwd HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"[..],
        &b"GET /%2e%2e/%2e%2e/etc/passwd HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"[..],
    ] {
        let r = request(port, raw);
        assert_eq!(
            status_line(&r),
            "HTTP/1.1 403 Forbidden",
            "request: {:?}",
            std::str::from_utf8(raw).unwrap()
        );
    }

    // 6. Nested path works
    let r = request(
        port,
        b"GET /sub/nested.txt HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_line(&r), "HTTP/1.1 200 OK");
    assert_eq!(body(&r), b"nested body");

    // 7. Query string stripped, file still served
    let r = request(
        port,
        b"GET /index.html?v=42 HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_line(&r), "HTTP/1.1 200 OK");
    assert_eq!(body(&r), b"<h1>ok</h1>");

    // 8. Non-GET/HEAD method rejected
    let r = request(
        port,
        b"POST /index.html HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_line(&r), "HTTP/1.1 405 Not Allowed");

    // 9. Keep-alive across two requests on one connection
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    s.write_all(b"GET /index.html HTTP/1.1\r\nHost: x\r\n\r\n")
        .unwrap();
    s.write_all(b"GET /data.json HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut all = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match s.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => all.extend_from_slice(&buf[..n]),
            Err(_) => break,
        }
    }
    // Both responses concatenated in order.
    let s = std::str::from_utf8(&all).unwrap();
    assert!(s.contains("<h1>ok</h1>"));
    assert!(s.contains(r#"{"ok":true}"#));
    let first = s.find("HTTP/1.1 200").unwrap();
    let second = s.rfind("HTTP/1.1 200").unwrap();
    assert!(first < second, "expected two 200 responses");
}

#[test]
fn head_return_response_has_no_body() {
    let (_guard, port) = setup_return_server();

    let r = request(
        port,
        b"HEAD / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_line(&r), "HTTP/1.1 200 OK");
    assert_eq!(header(&r, "Content-Length").as_deref(), Some("5"));
    assert_eq!(body(&r), b"");
}

/// Build a ruxen config with whatever http-block body the caller hands in, spin
/// it up on a free port, and return the guard + port. All M4 multi-server tests
/// share this helper so a change to startup (new env knob, a flag) is a
/// one-line fix.
fn setup_with_http(body_fmt: impl FnOnce(u16) -> String) -> (ServerGuard, u16) {
    let (port, _lock) = pick_port();
    let dir = unique_dir();
    let conf = dir.join("ruxen.conf");
    std::fs::write(&conf, body_fmt(port)).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .arg(&conf)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ruxen");
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        if Instant::now() > deadline {
            panic!("ruxen did not start listening on port {port}");
        }
        sleep(Duration::from_millis(20));
    }
    (
        ServerGuard {
            child,
            tempdir: dir,
        },
        port,
    )
}

#[test]
fn m4_host_routes_to_matching_server() {
    let (_guard, port) = setup_with_http(|port| {
        format!(
            "http {{\n\
             server {{ listen {port}; server_name a.example; location / {{ return 200 \"A\"; }} }}\n\
             server {{ listen {port}; server_name b.example; location / {{ return 200 \"B\"; }} }}\n\
             }}\n"
        )
    });
    let r = request(
        port,
        b"GET / HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(body(&r), b"A");
    let r = request(
        port,
        b"GET / HTTP/1.1\r\nHost: b.example\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(body(&r), b"B");
}

#[test]
fn m4_host_port_suffix_is_stripped_before_match() {
    let (_guard, port) = setup_with_http(|port| {
        format!(
            "http {{\n\
             server {{ listen {port}; server_name a.example; location / {{ return 200 \"A\"; }} }}\n\
             server {{ listen {port}; server_name b.example; location / {{ return 200 \"B\"; }} }}\n\
             }}\n"
        )
    });
    // `Host: a.example:12345` must still match server_name `a.example`.
    let r = request(
        port,
        b"GET / HTTP/1.1\r\nHost: a.example:12345\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(body(&r), b"A");
}

#[test]
fn m4_unknown_host_falls_to_default_server() {
    let (_guard, port) = setup_with_http(|port| {
        format!(
            "http {{\n\
             server {{ listen {port}; server_name a.example; location / {{ return 200 \"A\"; }} }}\n\
             server {{ listen {port}; server_name b.example; location / {{ return 200 \"B\"; }} }}\n\
             }}\n"
        )
    });
    // Host doesn't match any server_name — default is the first block (A).
    let r = request(
        port,
        b"GET / HTTP/1.1\r\nHost: nope.example\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(body(&r), b"A");
}

#[test]
fn m4_missing_host_on_http_11_is_400() {
    let (_guard, port) = setup_with_http(|port| {
        format!("http {{ server {{ listen {port}; location / {{ return 200 \"ok\"; }} }} }}\n")
    });
    let r = request(port, b"GET / HTTP/1.1\r\nConnection: close\r\n\r\n");
    assert_eq!(status_line(&r), "HTTP/1.1 400 Bad Request");
}

#[test]
fn m4_exact_location_wins_over_prefix() {
    let (_guard, port) = setup_with_http(|port| {
        format!(
            "http {{ server {{ listen {port};\n\
             location = / {{ return 200 \"root\"; }}\n\
             location / {{ return 200 \"prefix\"; }}\n\
             }} }}\n"
        )
    });
    // Exact `= /` should serve "root" for `/`.
    let r = request(
        port,
        b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(body(&r), b"root");
    // Anything else falls through to the prefix handler.
    let r = request(
        port,
        b"GET /anything HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(body(&r), b"prefix");
}

#[test]
fn m4_longest_prefix_wins() {
    let (_guard, port) = setup_with_http(|port| {
        format!(
            "http {{ server {{ listen {port};\n\
             location /a {{ return 200 \"a\"; }}\n\
             location /a/b {{ return 200 \"ab\"; }}\n\
             location / {{ return 200 \"root\"; }}\n\
             }} }}\n"
        )
    });
    let r = request(
        port,
        b"GET /a/b/c HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(body(&r), b"ab");
    let r = request(
        port,
        b"GET /a/xyz HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(body(&r), b"a");
    let r = request(
        port,
        b"GET /z HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(body(&r), b"root");
}

#[test]
fn head_worker_404_has_no_body() {
    let (_guard, port) = setup_server();

    let r = request(
        port,
        b"HEAD /missing HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_line(&r), "HTTP/1.1 404 Not Found");
    assert_eq!(header(&r, "Content-Length").as_deref(), Some("10"));
    assert_eq!(body(&r), b"");
}

#[test]
fn head_worker_403_has_no_body() {
    let (_guard, port) = setup_server();

    let r = request(
        port,
        b"HEAD /../../etc/passwd HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_line(&r), "HTTP/1.1 403 Forbidden");
    assert_eq!(header(&r, "Content-Length").as_deref(), Some("10"));
    assert_eq!(body(&r), b"");
}

#[test]
fn head_bad_request_has_no_body_when_request_line_parsed() {
    let (_guard, port) = setup_server();

    let r = request(
        port,
        b"HEAD /index.html HTTP/1.1\r\nBroken-Header\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_line(&r), "HTTP/1.1 400 Bad Request");
    assert_eq!(header(&r, "Content-Length").as_deref(), Some("12"));
    assert_eq!(body(&r), b"");
}

#[test]
fn empty_host_on_http_11_is_400() {
    let (_guard, port) = setup_return_server();

    let r = request(
        port,
        b"GET / HTTP/1.1\r\nHost:\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_line(&r), "HTTP/1.1 400 Bad Request");
}

#[test]
fn root_appends_full_request_uri_under_non_root_location() {
    let (_guard, port) = setup_prefixed_root_server();

    // `location /static { root <dir>/www; }` — per nginx root semantics,
    // `GET /static/file.txt` resolves to `<dir>/www/static/file.txt`.
    let r = request(
        port,
        b"GET /static/file.txt HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_line(&r), "HTTP/1.1 200 OK");
    assert_eq!(body(&r), b"ok");
}

#[test]
fn m5_if_none_match_returns_304_without_body() {
    let (_guard, port) = setup_server();

    let first = request(
        port,
        b"GET /index.html HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    let etag = header(&first, "ETag").expect("etag");

    let r = request(
        port,
        format!(
            "GET /index.html HTTP/1.1\r\nHost: x\r\nIf-None-Match: {etag}\r\nConnection: close\r\n\r\n"
        )
        .as_bytes(),
    );
    assert_eq!(status_line(&r), "HTTP/1.1 304 Not Modified");
    assert_eq!(header(&r, "ETag").as_deref(), Some(etag.as_str()));
    assert!(header(&r, "Last-Modified").is_some());
    assert!(header(&r, "Content-Length").is_none());
    assert_eq!(body(&r), b"");
}

#[test]
fn m5_if_modified_since_returns_304_for_old_file() {
    let (_guard, port) = setup_server();
    sleep(Duration::from_secs(2));

    let first = request(
        port,
        b"GET /index.html HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    let last_modified = header(&first, "Last-Modified").expect("last-modified");

    let r = request(
        port,
        format!(
            "GET /index.html HTTP/1.1\r\nHost: x\r\nIf-Modified-Since: {last_modified}\r\nConnection: close\r\n\r\n"
        )
        .as_bytes(),
    );
    assert_eq!(status_line(&r), "HTTP/1.1 304 Not Modified");
    assert_eq!(body(&r), b"");
}

#[test]
fn m5_single_range_returns_206_with_slice_body() {
    let (_guard, port) = setup_server();

    let r = request(
        port,
        b"GET /index.html HTTP/1.1\r\nHost: x\r\nRange: bytes=0-3\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_line(&r), "HTTP/1.1 206 Partial Content");
    assert_eq!(header(&r, "Content-Range").as_deref(), Some("bytes 0-3/11"));
    assert_eq!(header(&r, "Content-Length").as_deref(), Some("4"));
    assert_eq!(body(&r), b"<h1>");
}

#[test]
fn m5_head_range_returns_206_without_body() {
    let (_guard, port) = setup_server();

    let r = request(
        port,
        b"HEAD /index.html HTTP/1.1\r\nHost: x\r\nRange: bytes=0-3\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_line(&r), "HTTP/1.1 206 Partial Content");
    assert_eq!(header(&r, "Content-Range").as_deref(), Some("bytes 0-3/11"));
    assert_eq!(header(&r, "Content-Length").as_deref(), Some("4"));
    assert_eq!(body(&r), b"");
}

#[test]
fn m5_unsatisfiable_range_returns_416() {
    let (_guard, port) = setup_server();

    let r = request(
        port,
        b"GET /index.html HTTP/1.1\r\nHost: x\r\nRange: bytes=100-200\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_line(&r), "HTTP/1.1 416 Range Not Satisfiable");
    assert_eq!(header(&r, "Content-Range").as_deref(), Some("bytes */11"));
}

#[test]
fn m5_if_range_controls_whether_range_is_honored() {
    // `If-Range` requires strong comparison per RFC 9110 §13.1.5. We emit
    // our ETag in nginx's strong-form (`"hex-hex"`), so a client echoing
    // it verbatim succeeds; a Last-Modified that matches mtime also
    // succeeds; a weak client prefix (`W/…`) or a mismatching validator
    // both drop the range and fall back to 200.
    let (_guard, port) = setup_server();
    backdate(&_guard.tempdir.join("index.html"), Duration::from_secs(10));

    let first = request(
        port,
        b"GET /index.html HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    let last_modified = header(&first, "Last-Modified").expect("last-modified");

    let partial = request(
        port,
        format!(
            "GET /index.html HTTP/1.1\r\nHost: x\r\nRange: bytes=0-3\r\nIf-Range: {last_modified}\r\nConnection: close\r\n\r\n"
        )
        .as_bytes(),
    );
    assert_eq!(status_line(&partial), "HTTP/1.1 206 Partial Content");
    assert_eq!(body(&partial), b"<h1>");

    // Mismatched validator → fall back to full 200.
    let full = request(
        port,
        b"GET /index.html HTTP/1.1\r\nHost: x\r\nRange: bytes=0-3\r\nIf-Range: Thu, 01 Jan 1970 00:00:00 GMT\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_line(&full), "HTTP/1.1 200 OK");
    assert_eq!(body(&full), b"<h1>ok</h1>");

    // Echoing our strong-form ETag honors the range.
    let etag = header(&first, "ETag").expect("etag");
    let strong = request(
        port,
        format!(
            "GET /index.html HTTP/1.1\r\nHost: x\r\nRange: bytes=0-3\r\nIf-Range: {etag}\r\nConnection: close\r\n\r\n"
        )
        .as_bytes(),
    );
    assert_eq!(status_line(&strong), "HTTP/1.1 206 Partial Content");
    assert_eq!(body(&strong), b"<h1>");

    // A client-side weak marker (`W/…`) never satisfies a strong compare.
    let weak = request(
        port,
        format!(
            "GET /index.html HTTP/1.1\r\nHost: x\r\nRange: bytes=0-3\r\nIf-Range: W/{etag}\r\nConnection: close\r\n\r\n"
        )
        .as_bytes(),
    );
    assert_eq!(status_line(&weak), "HTTP/1.1 200 OK");
    assert_eq!(body(&weak), b"<h1>ok</h1>");
}

fn backdate(path: &std::path::Path, by: Duration) {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - by.as_secs();
    let status = Command::new("touch")
        .arg("-d")
        .arg(format!("@{ts}"))
        .arg(path)
        .status()
        .expect("invoke touch");
    assert!(status.success(), "touch failed on {}", path.display());
}

#[test]
fn m5_conditionals_are_ignored_on_return_locations() {
    let (_guard, port) = setup_return_server();

    let r = request(
        port,
        b"GET / HTTP/1.1\r\nHost: x\r\nIf-None-Match: W/\"anything\"\r\nRange: bytes=0-1\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_line(&r), "HTTP/1.1 200 OK");
    assert_eq!(body(&r), b"hello");
}

// ---- M6 integration tests ----

/// Spin up ruxen against a tempdir with a caller-configured tree + conf.
/// The `populate` closure sees the freshly-created root and can create
/// the exact file/dir/symlink layout the test needs. `conf_body` is the
/// raw contents of `http { ... }` appropriate for the test.
fn setup_m6(
    populate: impl FnOnce(&std::path::Path),
    conf_body_fmt: impl FnOnce(u16, &str) -> String,
) -> (ServerGuard, u16) {
    let (port, _lock) = pick_port();
    let dir = unique_dir();
    populate(&dir);
    let conf = dir.join("ruxen.conf");
    std::fs::write(&conf, conf_body_fmt(port, dir.to_str().unwrap())).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .arg(&conf)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ruxen");
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        if Instant::now() > deadline {
            panic!("ruxen did not start listening on port {port}");
        }
        sleep(Duration::from_millis(20));
    }
    (
        ServerGuard {
            child,
            tempdir: dir,
        },
        port,
    )
}

#[test]
fn m6_directory_without_trailing_slash_redirects_301() {
    let (_guard, port) = setup_m6(
        |d| {
            std::fs::create_dir(d.join("docs")).unwrap();
            std::fs::write(d.join("docs/index.html"), b"doc").unwrap();
        },
        |port, root| {
            format!("http {{ server {{ listen {port}; location / {{ root {root}; }} }} }}\n")
        },
    );
    let r = request(
        port,
        b"GET /docs HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_line(&r), "HTTP/1.1 301 Moved Permanently");
    assert_eq!(
        header(&r, "Location").as_deref(),
        Some(format!("http://x:{port}/docs/").as_str())
    );
}

#[test]
fn m6_default_index_is_index_html() {
    let (_guard, port) = setup_m6(
        |d| {
            std::fs::write(d.join("index.html"), b"home").unwrap();
        },
        |port, root| {
            format!("http {{ server {{ listen {port}; location / {{ root {root}; }} }} }}\n")
        },
    );
    let r = request(
        port,
        b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_line(&r), "HTTP/1.1 200 OK");
    assert_eq!(body(&r), b"home");
}

#[test]
fn m6_configured_index_probed_in_order() {
    let (_guard, port) = setup_m6(
        |d| {
            std::fs::write(d.join("second.html"), b"two").unwrap();
        },
        |port, root| {
            format!(
                "http {{ server {{ listen {port};\n\
                 location / {{ root {root}; index first.html second.html; }}\n\
                 }} }}\n"
            )
        },
    );
    // first.html missing → second.html wins.
    let r = request(
        port,
        b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_line(&r), "HTTP/1.1 200 OK");
    assert_eq!(body(&r), b"two");
}

#[test]
fn m6_location_index_overrides_server_index() {
    let (_guard, port) = setup_m6(
        |d| {
            std::fs::write(d.join("loc.html"), b"loc").unwrap();
        },
        |port, root| {
            format!(
                "http {{ server {{ listen {port}; index srv.html;\n\
                 location / {{ root {root}; index loc.html; }}\n\
                 }} }}\n"
            )
        },
    );
    let r = request(
        port,
        b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_line(&r), "HTTP/1.1 200 OK");
    assert_eq!(body(&r), b"loc");
}

#[test]
fn m6_directory_with_no_index_returns_403() {
    let (_guard, port) = setup_m6(
        |d| {
            std::fs::create_dir(d.join("empty")).unwrap();
        },
        |port, root| {
            format!("http {{ server {{ listen {port}; location / {{ root {root}; }} }} }}\n")
        },
    );
    let r = request(
        port,
        b"GET /empty/ HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_line(&r), "HTTP/1.1 403 Forbidden");
}

#[test]
fn m6_symlink_under_root_is_served() {
    let (_guard, port) = setup_m6(
        |d| {
            std::fs::write(d.join("real.txt"), b"real").unwrap();
            std::os::unix::fs::symlink("real.txt", d.join("link.txt")).unwrap();
        },
        |port, root| {
            format!("http {{ server {{ listen {port}; location / {{ root {root}; }} }} }}\n")
        },
    );
    let r = request(
        port,
        b"GET /link.txt HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_line(&r), "HTTP/1.1 200 OK");
    assert_eq!(body(&r), b"real");
}

#[test]
fn m6_symlink_escaping_root_is_403() {
    // Create an outside target and a symlink inside root that points to it.
    // Containment check must catch it even though the file exists.
    let outside = unique_dir();
    std::fs::write(outside.join("secret.txt"), b"pwned").unwrap();
    let outside_secret = outside.join("secret.txt").clone();

    let (_guard, port) = setup_m6(
        move |d| {
            std::os::unix::fs::symlink(&outside_secret, d.join("escape.txt")).unwrap();
        },
        |port, root| {
            format!("http {{ server {{ listen {port}; location / {{ root {root}; }} }} }}\n")
        },
    );
    let r = request(
        port,
        b"GET /escape.txt HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_line(&r), "HTTP/1.1 403 Forbidden");
    std::fs::remove_dir_all(&outside).ok();
}

#[test]
fn m6_try_files_uri_then_fallback_status() {
    let (_guard, port) = setup_m6(
        |d| {
            std::fs::write(d.join("exists.txt"), b"E").unwrap();
        },
        |port, root| {
            format!(
                "http {{ server {{ listen {port};\n\
                 location / {{ root {root}; try_files $uri =404; }}\n\
                 }} }}\n"
            )
        },
    );
    // Existing file → served.
    let r = request(
        port,
        b"GET /exists.txt HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_line(&r), "HTTP/1.1 200 OK");
    assert_eq!(body(&r), b"E");
    // Missing file → fallback status.
    let r = request(
        port,
        b"GET /nope.txt HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_line(&r), "HTTP/1.1 404 Not Found");
}

#[test]
fn m6_try_files_falls_back_to_literal_uri() {
    // SPA-style: try_files $uri $uri/ /index.html;
    let (_guard, port) = setup_m6(
        |d| {
            std::fs::write(d.join("index.html"), b"spa").unwrap();
        },
        |port, root| {
            format!(
                "http {{ server {{ listen {port};\n\
                 location / {{ root {root}; try_files $uri $uri/ /index.html; }}\n\
                 }} }}\n"
            )
        },
    );
    let r = request(
        port,
        b"GET /app/route HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_line(&r), "HTTP/1.1 200 OK");
    assert_eq!(body(&r), b"spa");
}

#[test]
fn m6_try_files_uri_slash_matches_directory() {
    let (_guard, port) = setup_m6(
        |d| {
            std::fs::create_dir(d.join("sub")).unwrap();
            std::fs::write(d.join("sub/index.html"), b"dir-index").unwrap();
        },
        |port, root| {
            format!(
                "http {{ server {{ listen {port};\n\
                 location / {{ root {root}; try_files $uri $uri/ =404; }}\n\
                 }} }}\n"
            )
        },
    );
    // /sub is a dir — $uri miss, $uri/ hit. nginx's try_files strips
    // the trailing slash from the probe at parse time, so the URI after
    // the hit is `/sub` (no slash), and the static handler then
    // 301-redirects bare-directory hits.
    let r = request(
        port,
        b"GET /sub HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_line(&r), "HTTP/1.1 301 Moved Permanently");
    // Following the redirect lands on /sub/, where index resolution runs
    // and serves sub/index.html.
    let r = request(
        port,
        b"GET /sub/ HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_line(&r), "HTTP/1.1 200 OK");
    assert_eq!(body(&r), b"dir-index");
}

#[test]
fn m6_traversal_via_normalized_uri_still_blocked() {
    // M3 regression guard under the M6 pipeline.
    let (_guard, port) = setup_m6(
        |d| {
            std::fs::write(d.join("ok.txt"), b"ok").unwrap();
        },
        |port, root| {
            format!("http {{ server {{ listen {port}; location / {{ root {root}; }} }} }}\n")
        },
    );
    let r = request(
        port,
        b"GET /../../etc/passwd HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_line(&r), "HTTP/1.1 403 Forbidden");
}
