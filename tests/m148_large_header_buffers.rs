//! M148 — request heads over the usual 8 KiB buffer (#482), as nginx's
//! `large_client_header_buffers` (default `4 8k`): each line up to `size`,
//! the head up to `size × number`. A longer request line is a 414, a longer
//! header line or head a 400 "Request Header Or Cookie Too Large"; both are
//! logged at `info`. Big cookies within the limits are served, and the
//! connection goes on.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use common::ports::setup_lock;

struct Server {
    child: Child,
    port: u16,
    dir: PathBuf,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn start(tag: &str, buffers: &str) -> Server {
    let ports = setup_lock();
    let port = {
        let probe = TcpListener::bind("127.0.0.1:0").unwrap();
        probe.local_addr().unwrap().port()
    };
    let dir = std::env::temp_dir().join(format!("ruxen-m148-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "events {{}}\nerror_log {}/error.log info;\nhttp {{ access_log off; {buffers}\n\
               server {{ listen 127.0.0.1:{port}; location / {{ return 200 \"ok\\n\"; }} }} }}\n",
            dir.display()
        ),
    )
    .unwrap();
    let mut server = Server {
        child: Command::new(env!("CARGO_BIN_EXE_ruxen"))
            .arg("-c")
            .arg(dir.join("nginx.conf"))
            .arg("-g")
            .arg(format!("pid {}/ruxen.pid;", dir.display()))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
        port,
        dir,
    };
    let pid_file = server.dir.join("ruxen.pid");
    common::ports::wait_for_pid_file(&mut server.child, &pid_file, Duration::from_secs(3));
    drop(ports);
    server
}

/// The status of each response to `requests`, sent on one connection.
fn statuses(port: u16, requests: &[String]) -> Vec<u16> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut out = Vec::new();
    for req in requests {
        if s.write_all(req.as_bytes()).is_err() {
            break;
        }
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            match s.read(&mut byte) {
                Ok(1) => head.push(byte[0]),
                _ => return out,
            }
        }
        let head = String::from_utf8_lossy(&head).into_owned();
        let status = head[9..12].parse().unwrap();
        let len: usize = head
            .lines()
            .find_map(|l| l.strip_prefix("Content-Length: "))
            .map_or(0, |v| v.trim().parse().unwrap());
        let mut body = vec![0u8; len];
        let _ = s.read_exact(&mut body);
        out.push(status);
    }
    out
}

fn get(target: &str, headers: &[(&str, usize)]) -> String {
    let mut req = format!("GET {target} HTTP/1.1\r\nHost: x\r\n");
    for (name, len) in headers {
        req.push_str(&format!("{name}: {}\r\n", "a".repeat(*len)));
    }
    req.push_str("\r\n");
    req
}

#[test]
fn default_buffers_are_nginx_4_8k() {
    let server = start("default", "");
    let s = |r: String| statuses(server.port, &[r]);
    assert_eq!(s(get("/", &[("Cookie", 10240)])), [400]);
    assert_eq!(s(get("/", &[("X-A", 8150)])), [200]);
    assert_eq!(
        s(get("/", &[("X-1", 7000), ("X-2", 7000), ("X-3", 7000)])),
        [200]
    );
    let five: Vec<(&str, usize)> = ["X-1", "X-2", "X-3", "X-4", "X-5"]
        .iter()
        .map(|n| (*n, 7000))
        .collect();
    assert_eq!(s(get("/", &five)), [400]);
    assert_eq!(s(get(&format!("/{}", "a".repeat(10240)), &[])), [414]);
    // A large head, then small requests on the same connection.
    assert_eq!(
        statuses(
            server.port,
            &[
                get("/", &[("X-1", 7000), ("X-2", 7000)]),
                get("/b", &[]),
                get("/c", &[])
            ]
        ),
        [200, 200, 200]
    );
    let log = std::fs::read_to_string(server.dir.join("error.log")).unwrap_or_default();
    assert!(
        log.contains("[info]")
            && log.contains("client sent too long header line: \"Cookie: aaaa")
            && log.contains("..\" while reading client request headers, client: 127.0.0.1"),
        "{log}"
    );
    assert!(
        log.contains("client sent too long URI while reading client request line"),
        "{log}"
    );
}

/// The whole answer to `request` (written whole), up to the close, and
/// whether the close was clean.
fn answer(port: u16, request: &[u8]) -> (String, bool) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let written = s.write_all(request).is_ok();
    let mut out = Vec::new();
    let clean = s.read_to_end(&mut out).is_ok() && written;
    (String::from_utf8_lossy(&out).into_owned(), clean)
}

/// A head refused for its size (#779, #780, #783): the server's
/// `add_header … always`, no body for HEAD, and a close without a reset
/// while the client is still sending.
#[test]
fn refused_heads_answer_as_nginx() {
    let server = start("refused", "add_header X-Srv s always;");
    let long = "a".repeat(60_000);
    let (r, clean) = answer(
        server.port,
        format!("GET /?{long} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes(),
    );
    assert!(r.starts_with("HTTP/1.1 414 "), "{r}");
    assert!(r.contains("\r\nX-Srv: s\r\n"), "{r}");
    assert!(clean, "{r}");
    let (r, clean) = answer(
        server.port,
        format!("GET / HTTP/1.1\r\nHost: x\r\nX-Long: {long}\r\n\r\n").as_bytes(),
    );
    assert!(r.starts_with("HTTP/1.1 400 "), "{r}");
    assert!(r.contains("\r\nX-Srv: s\r\n"), "{r}");
    assert!(clean, "{r}");
    let (r, _) = answer(
        server.port,
        format!("HEAD /?{} HTTP/1.1\r\nHost: x\r\n\r\n", "a".repeat(9000)).as_bytes(),
    );
    assert!(r.starts_with("HTTP/1.1 414 "), "{r}");
    assert!(r.ends_with("\r\n\r\n"), "a body: {r}");
    // Refused for its line or a header, before routing.
    for req in [
        "GET /%4 HTTP/1.1\r\nHost: x\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: x\r\nHost: y\r\n\r\n",
        "GET / HTTP/2.0\r\nHost: x\r\n\r\n",
        "HEAD /a\x01 HTTP/1.1\r\nHost: x\r\n\r\n",
    ] {
        let (r, _) = answer(server.port, req.as_bytes());
        assert!(r.contains("\r\nX-Srv: s\r\n"), "{req:?}: {r}");
        assert_eq!(req.starts_with("HEAD"), r.ends_with("\r\n\r\n"), "{r}");
    }
}

/// A request bad in its line and in a header gets the line's answer, as
/// nginx checks the line before it reads a header (#807).
#[test]
fn the_request_line_is_refused_before_a_header() {
    let server = start("line-first", "add_header X \"$request_method\" always;");
    let long = "a".repeat(9000);
    for (req, status, method) in [
        (
            format!("GET /?{long} HTTP/1.1\r\nHost: x\r\nContent-Length: -1\r\n\r\n"),
            "414",
            None,
        ),
        (
            "GET /x%4 HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: identity\r\n\r\n".to_string(),
            "400",
            Some("GET"),
        ),
        (
            format!("OPTIONS /x%00 HTTP/1.1\r\nHost: x\r\nX-Long: {long}\r\n\r\n"),
            "400",
            Some("OPTIONS"),
        ),
        (
            "GET * HTTP/1.1\r\nHost: x\r\nContent-Length: abc\r\n\r\n".to_string(),
            "400",
            None,
        ),
        ("GET /x%4 HTTP/1.1\r\n\r\n".to_string(), "400", Some("GET")),
    ] {
        let (r, _) = answer(server.port, req.as_bytes());
        assert!(
            r.starts_with(&format!("HTTP/1.1 {status} ")),
            "{}: {r}",
            &req[..40]
        );
        assert!(
            !r.contains("Too Large</title>") || status == "414",
            "{}: {r}",
            &req[..40]
        );
        if let Some(method) = method {
            assert!(
                r.contains(&format!("\r\nX: {method}\r\n")),
                "{}: {r}",
                &req[..40]
            );
        } else {
            assert!(!r.contains("\r\nX: G"), "{}: {r}", &req[..40]);
        }
    }
}

#[test]
fn smaller_buffers_limit_lines_and_the_head() {
    let server = start("small", "large_client_header_buffers 2 1k;");
    let s = |r: String| statuses(server.port, &[r]);
    assert_eq!(s(get("/", &[("X-A", 900)])), [200]);
    assert_eq!(s(get("/", &[("X-A", 1500)])), [400]);
    assert_eq!(
        s(get("/", &[("X-1", 900), ("X-2", 900), ("X-3", 900)])),
        [400]
    );
    assert_eq!(s(get(&format!("/{}", "a".repeat(1500)), &[])), [414]);
}

/// `client_header_buffer_size` (#467): the first read goes into a buffer
/// that small, and a head or body that doesn't fit moves on, as nginx
/// moves it to a large buffer. Heads of every size, a body, and pipelined
/// requests on one connection all come through.
#[test]
fn small_client_header_buffer() {
    let server = start("chb", "client_header_buffer_size 64;");
    let post = format!(
        "POST /p HTTP/1.1\r\nHost: x\r\nContent-Length: 3000\r\n\r\n{}",
        "b".repeat(3000)
    );
    assert_eq!(
        statuses(
            server.port,
            &[
                get("/", &[]),
                get("/", &[("X-A", 900)]),
                get("/", &[("X-A", 7000)]),
                get("/s", &[]),
                post.clone(),
                get("/", &[("X-1", 7000), ("X-2", 7000)]),
                get("/t", &[]),
            ]
        ),
        [200, 200, 200, 200, 200, 200, 200]
    );
    // Two requests in one write, the second past the first's buffer.
    let mut s = TcpStream::connect(("127.0.0.1", server.port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let pair = format!("{}{}", get("/1", &[]), get("/2", &[("X-A", 500)]));
    s.write_all(pair.as_bytes()).unwrap();
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    while got.windows(3).filter(|w| w == b"ok\n").count() < 2 {
        match s.read(&mut buf) {
            Ok(n) if n > 0 => got.extend_from_slice(&buf[..n]),
            _ => break,
        }
    }
    let text = String::from_utf8_lossy(&got);
    assert_eq!(text.matches("HTTP/1.1 200 OK").count(), 2, "{text}");
}

#[test]
fn bad_values_are_refused() {
    for (value, ok) in [
        ("4 8k", true),
        ("1 512", true),
        ("0 8k", false),
        // Under `connection_pool_size` (512 on 64-bit), as nginx refuses.
        ("4 256", false),
        ("4 0", false),
        ("4", false),
    ] {
        let dir = std::env::temp_dir().join(format!("ruxen-m148-t-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let conf = dir.join("nginx.conf");
        std::fs::write(
            &conf,
            format!(
                "events {{}}\nhttp {{ large_client_header_buffers {value};\n\
                   server {{ listen 127.0.0.1:1; }} }}\n"
            ),
        )
        .unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_ruxen"))
            .arg("-t")
            .arg("-c")
            .arg(&conf)
            .output()
            .unwrap();
        assert_eq!(
            out.status.success(),
            ok,
            "{value}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
