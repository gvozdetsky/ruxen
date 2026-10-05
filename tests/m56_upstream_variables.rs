//! M56 — nginx's per-attempt upstream variables: `$upstream_addr`,
//! `$upstream_status`, `$upstream_connect_time`, `$upstream_header_time`,
//! `$upstream_response_time`, `$upstream_response_length`,
//! `$upstream_bytes_received`, `$upstream_bytes_sent`. One value per
//! attempt, `, `-separated; they survive `proxy_intercept_errors`, and in
//! access_log they render too (with `$upstream_http_*`, `$proxy_host` and
//! `map` variables, which used to log empty).

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

use common::ports::DeadPort;

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

fn start(tag: &str, http_body: &str) -> Server {
    let port = {
        let probe = TcpListener::bind("127.0.0.1:0").unwrap();
        probe.local_addr().unwrap().port()
    };
    let dir = std::env::temp_dir().join(format!("ruxen-m56-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let body = http_body
        .replace("%%DIR%%", dir.to_str().unwrap())
        .replace("%%PORT%%", &port.to_string());
    std::fs::write(
        dir.join("nginx.conf"),
        format!("events {{}}\nhttp {{ {body} }}\n"),
    )
    .unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .arg("-c")
        .arg(dir.join("nginx.conf"))
        .arg("-e")
        .arg(dir.join("stderr.log"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "ruxen did not start");
        sleep(Duration::from_millis(20));
    }
    Server { child, port, dir }
}

const OK_REPLY: &[u8] =
    b"HTTP/1.1 200 OK\r\nX-Up: v\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello";

/// Backend: `/nf…` answers 404, anything else `OK_REPLY`.
fn spawn_backend() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut s in listener.incoming().flatten() {
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                if s.read(&mut byte).unwrap_or(0) == 0 {
                    break;
                }
                head.push(byte[0]);
            }
            let reply: &[u8] = if head.starts_with(b"GET /nf") {
                b"HTTP/1.1 404 Not Found\r\nContent-Length: 4\r\nConnection: close\r\n\r\nnope"
            } else {
                OK_REPLY
            };
            let _ = s.write_all(reply);
        }
    });
    port
}

fn get(port: u16, path: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

fn body(resp: &str) -> &str {
    resp.split_once("\r\n\r\n").map_or("", |(_, b)| b)
}

#[test]
fn attempts_are_listed_and_survive_intercept() {
    let dead = DeadPort::new();
    let backend = spawn_backend();
    let server = start(
        "intercept",
        &format!(
            "upstream u {{ server 127.0.0.1:{dead}; server 127.0.0.1:{backend}; }}\n\
             server {{ listen 127.0.0.1:%%PORT%%;\n\
               location / {{ proxy_pass http://u; proxy_intercept_errors on; error_page 404 /e; }}\n\
               location = /e {{ return 200 \"$upstream_addr|$upstream_status\"; }}\n\
             }}",
            dead = dead.port(),
        ),
    );
    // Round-robin may start with either peer: retry until the dead one
    // goes first, then the backend's 404 is intercepted.
    let want = format!("127.0.0.1:{}, 127.0.0.1:{backend}|502, 404", dead.port());
    let mut seen = Vec::new();
    for _ in 0..4 {
        let resp = get(server.port, "/nf");
        assert!(resp.starts_with("HTTP/1.1 404"), "{resp}");
        seen.push(body(&resp).to_string());
    }
    assert!(seen.contains(&want), "{seen:?}");
}

#[test]
fn access_log_renders_upstream_and_map_variables() {
    let dead = DeadPort::new();
    let backend = spawn_backend();
    let server = start(
        "log",
        &format!(
            "map $uri $kind {{ default other; /p proxied; }}\n\
             upstream gone {{ server 127.0.0.1:{dead} down; }}\n\
             log_format u '$uri $kind $proxy_host $upstream_addr $upstream_status \
               $upstream_response_length $upstream_bytes_received $upstream_bytes_sent \
               $upstream_http_x_up $upstream_connect_time $upstream_header_time \
               $upstream_response_time';\n\
             server {{ listen 127.0.0.1:%%PORT%%;\n\
               access_log %%DIR%%/u.log u;\n\
               location /p {{ proxy_pass http://127.0.0.1:{backend}; }}\n\
               location /local {{ return 200 \"x\"; }}\n\
               location /gone {{ proxy_pass http://gone; }}\n\
             }}",
            dead = dead.port(),
        ),
    );
    assert!(get(server.port, "/p").ends_with("hello"));
    assert!(get(server.port, "/local").ends_with("x"));
    assert!(get(server.port, "/gone").starts_with("HTTP/1.1 502"));
    sleep(Duration::from_millis(50));

    let log = std::fs::read_to_string(server.dir.join("u.log")).unwrap();
    let lines: Vec<&str> = log.lines().collect();
    assert_eq!(lines.len(), 3, "{log}");
    let f: Vec<&str> = lines[0].split(' ').collect();
    let peer = format!("127.0.0.1:{backend}");
    let received = OK_REPLY.len().to_string();
    assert_eq!(
        f[..7],
        ["/p", "proxied", &peer, &peer, "200", "5", &received],
        "{log}"
    );
    // The request ruxen sent upstream (request line and headers).
    assert!(f[7].parse::<u64>().unwrap() > 20, "{log}");
    assert_eq!(f[8], "v", "{log}");
    for t in &f[9..12] {
        assert!(
            t.len() == 5 && t.as_bytes()[1] == b'.',
            "time {t:?} in {log}"
        );
    }
    assert_eq!(lines[1], "/local other - - - - - - - - - -", "{log}");
    // No live upstreams: the upstream's name, a 502, nothing connected.
    assert_eq!(
        lines[2], "/gone other gone gone 502 0 0 0 - - - 0.000",
        "{log}"
    );
}

/// When every attempt fails, the proxy's own 502 goes through the
/// location's `error_page` (no `proxy_intercept_errors` needed) and gets
/// `add_header ... always`, as in nginx. It used to be the built-in page.
#[test]
fn proxy_generated_errors_use_error_page_and_add_header_always() {
    let dead = DeadPort::new();
    let server = start(
        "generated",
        &format!(
            "server {{ listen 127.0.0.1:%%PORT%%;\n\
               add_header X-IP $upstream_addr always;\n\
               location /plain {{ proxy_pass http://127.0.0.1:{dead}; }}\n\
               location /paged {{ proxy_pass http://127.0.0.1:{dead}; error_page 502 /e; }}\n\
               location = /e {{ return 200 \"page $upstream_addr|$upstream_status\"; }}\n\
             }}",
            dead = dead.port(),
        ),
    );
    let peer = format!("127.0.0.1:{}", dead.port());

    let resp = get(server.port, "/plain");
    assert!(resp.starts_with("HTTP/1.1 502"), "{resp}");
    assert!(resp.contains(&format!("\r\nX-IP: {peer}\r\n")), "{resp}");

    let resp = get(server.port, "/paged");
    assert!(resp.starts_with("HTTP/1.1 502"), "{resp}");
    assert_eq!(body(&resp), format!("page {peer}|502"), "{resp}");
}

/// While the response header is filtered, the try it came from is still
/// in flight: its `$upstream_response_time` is `-` (nginx sets it when the
/// upstream request is finalized), and only finished tries have a time.
/// The access log, written after the response, has a time for every try.
/// `add_header` used to show the header time for the current try.
#[test]
fn response_time_is_a_dash_while_in_flight() {
    let dead = DeadPort::new();
    let backend = spawn_backend();
    let server = start(
        "inflight",
        &format!(
            "log_format t '$upstream_response_time';\n\
             upstream u {{ server 127.0.0.1:{dead}; server 127.0.0.1:{backend}; }}\n\
             server {{ listen 127.0.0.1:%%PORT%%;\n\
               access_log %%DIR%%/t.log t;\n\
               add_header X-RT $upstream_response_time;\n\
               location / {{ proxy_pass http://u; }}\n\
             }}",
            dead = dead.port(),
        ),
    );
    let is_time = |t: &str| t.len() == 5 && t.as_bytes()[1] == b'.';
    // Round-robin may start with either peer; the dead one fails once and
    // is then skipped, so one of these has two tries.
    let mut headers = Vec::new();
    for _ in 0..3 {
        let resp = get(server.port, "/a");
        assert!(resp.ends_with("hello"), "{resp}");
        let rt = resp
            .lines()
            .find_map(|l| l.strip_prefix("X-RT: "))
            .unwrap_or_else(|| panic!("{resp}"));
        headers.push(rt.to_string());
    }
    for rt in &headers {
        let tries: Vec<&str> = rt.split(", ").collect();
        let (last, earlier) = tries.split_last().unwrap();
        assert_eq!(*last, "-", "{headers:?}");
        assert!(earlier.iter().all(|t| is_time(t)), "{headers:?}");
    }
    assert!(headers.iter().any(|rt| rt.contains(", ")), "{headers:?}");
    sleep(Duration::from_millis(50));
    let log = std::fs::read_to_string(server.dir.join("t.log")).unwrap();
    for line in log.lines() {
        assert!(line.split(", ").all(is_time), "{log}");
    }
    assert_eq!(log.lines().count(), 3, "{log}");
}
