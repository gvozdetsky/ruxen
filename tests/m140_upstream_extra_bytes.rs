//! M140 — an upstream connection that sent more than its framing isn't
//! pooled (#512): what followed may still be in the socket, and the next
//! request would read it as its response. nginx warns and closes it
//! (ngx_http_proxy_copy_filter, ngx_http_proxy_chunked_filter).
//!
//! The backend's first answer on each connection carries more than its
//! framing, followed by a complete second response. With the filler, the
//! second response starts at the 4 KiB read boundary and stays in the
//! socket; without it, it comes in the same read as the body.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

const SECOND: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nX-Injected: 1\r\n\r\ninjected\n";

/// `head`, padded with `z` up to 4096 bytes, then `SECOND`.
fn at_read_boundary(head: &[u8]) -> Vec<u8> {
    let mut out = head.to_vec();
    out.resize(4096, b'z');
    out.extend_from_slice(SECOND);
    out
}

/// A keep-alive backend: the first answer on each connection is `first`
/// (sent in pieces, `pause` between them), the later ones `answer for
/// <path>`. Returns its port and the count of accepted connections.
fn spawn_backend(first: Vec<Vec<u8>>, pause: Duration) -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepts = Arc::new(AtomicUsize::new(0));
    let counter = accepts.clone();
    thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut conn) = conn else { return };
            counter.fetch_add(1, Ordering::SeqCst);
            let first = first.clone();
            thread::spawn(move || {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                let mut served = 0;
                loop {
                    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        match conn.read(&mut chunk) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    }
                    let end = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
                    let head = String::from_utf8_lossy(&buf[..end]).into_owned();
                    buf.drain(..end);
                    let path = head.split(' ').nth(1).unwrap_or("").to_string();
                    if served == 0 {
                        for (i, piece) in first.iter().enumerate() {
                            if i > 0 {
                                thread::sleep(pause);
                            }
                            if conn.write_all(piece).is_err() {
                                return;
                            }
                        }
                    } else {
                        let body = format!("answer for {path}\n");
                        let answer = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                            body.len()
                        );
                        if conn.write_all(answer.as_bytes()).is_err() {
                            return;
                        }
                    }
                    served += 1;
                }
            });
        }
    });
    (port, accepts)
}

/// Three requests, one at a time, each on a new client connection, through
/// a keep-alive upstream to a backend whose first answer is `first`.
/// Returns the three raw responses, the backend's connection count and
/// the error log.
fn run(name: &str, first: Vec<Vec<u8>>, pause: Duration) -> (Vec<String>, usize, String) {
    let (upstream_port, accepts) = spawn_backend(first, pause);
    let dir = std::env::temp_dir().join(format!("ruxen-m140-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let setup = common::ports::setup_lock();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "worker_processes 1;\npid {d}/ruxen.pid;\nerror_log {d}/error.log warn;\n\
             events {{}}\nhttp {{\naccess_log off;\n\
             upstream u {{ server 127.0.0.1:{upstream_port}; keepalive 4; }}\n\
             server {{ listen 127.0.0.1:{port};\n\
             location / {{ proxy_pass http://u; proxy_http_version 1.1; \
             proxy_set_header Connection \"\"; }} }}\n}}\n",
            d = dir.display()
        ),
    )
    .unwrap();
    let mut child = common::KillOnDrop(
        Command::new(env!("CARGO_BIN_EXE_ruxen"))
            .arg("-c")
            .arg(dir.join("nginx.conf"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    common::ports::wait_for_pid_file(&mut child, &dir.join("ruxen.pid"), Duration::from_secs(5));
    drop(setup);
    let mut responses = Vec::new();
    for path in ["/one", "/two", "/three"] {
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        s.write_all(
            format!("GET {path} HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .unwrap();
        let mut raw = String::new();
        s.read_to_string(&mut raw).unwrap();
        responses.push(raw);
    }
    let _ = child.0.kill();
    let _ = child.0.wait();
    let log = std::fs::read_to_string(dir.join("error.log")).unwrap_or_default();
    let _ = std::fs::remove_dir_all(&dir);
    (responses, accepts.load(Ordering::SeqCst), log)
}

/// The body of a raw response, de-chunked when it is chunked.
fn body(raw: &str) -> String {
    let (head, mut rest) = raw.split_once("\r\n\r\n").unwrap_or((raw, ""));
    if !head.contains("Transfer-Encoding: chunked") {
        return rest.to_string();
    }
    let mut out = String::new();
    while let Some((size, tail)) = rest.split_once("\r\n") {
        let n = usize::from_str_radix(size, 16).unwrap_or(0);
        if n == 0 {
            break;
        }
        out.push_str(&tail[..n]);
        rest = &tail[n + 2..];
    }
    out
}

fn assert_not_pooled(name: &str, first: Vec<Vec<u8>>, pause: Duration, warning: &str) {
    let (responses, accepts, log) = run(name, first, pause);
    for raw in &responses {
        assert_eq!(body(raw), "first", "{name}: {raw:?}");
        assert!(!raw.contains("X-Injected"), "{name}: {raw:?}");
    }
    assert_eq!(
        accepts, 3,
        "{name}: each request on a new upstream connection"
    );
    assert_eq!(log.matches(warning).count(), 3, "{name}: {log}");
}

const MORE_THAN_LENGTH: &str = "upstream sent more data than specified in \"Content-Length\" \
                                header while reading upstream";
const AFTER_FINAL_CHUNK: &str = "upstream sent data after final chunk while reading upstream";

#[test]
fn length_overrun_at_a_read_boundary_is_not_pooled() {
    let first = at_read_boundary(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nfirst");
    assert_not_pooled("cl4k", vec![first], Duration::ZERO, MORE_THAN_LENGTH);
}

#[test]
fn chunked_overrun_at_a_read_boundary_is_not_pooled() {
    let first = at_read_boundary(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nfirst\r\n0\r\n\r\n",
    );
    assert_not_pooled("chunked4k", vec![first], Duration::ZERO, AFTER_FINAL_CHUNK);
}

#[test]
fn length_overrun_in_the_same_read_is_not_pooled() {
    let mut first = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nfirst".to_vec();
    first.extend_from_slice(SECOND);
    assert_not_pooled("small", vec![first], Duration::ZERO, MORE_THAN_LENGTH);
}

// The body comes after the head: the streaming relay (proxy_stream).
#[test]
fn streamed_overruns_are_not_pooled() {
    let mut rest = b"rst".to_vec();
    rest.extend_from_slice(SECOND);
    assert_not_pooled(
        "stream",
        vec![
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nfi".to_vec(),
            rest,
        ],
        Duration::from_millis(200),
        MORE_THAN_LENGTH,
    );
    let mut rest = b"5\r\nfirst\r\n0\r\n\r\n".to_vec();
    rest.extend_from_slice(SECOND);
    assert_not_pooled(
        "streamch",
        vec![
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec(),
            rest,
        ],
        Duration::from_millis(200),
        AFTER_FINAL_CHUNK,
    );
}

// The control: an exact answer leaves the connection in the pool.
#[test]
fn exact_answers_share_one_connection() {
    let (responses, accepts, log) = run(
        "exact",
        vec![b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nfirst".to_vec()],
        Duration::ZERO,
    );
    assert!(responses[0].ends_with("\r\n\r\nfirst"), "{responses:?}");
    assert!(responses[1].ends_with("answer for /two\n"), "{responses:?}");
    assert!(
        responses[2].ends_with("answer for /three\n"),
        "{responses:?}"
    );
    assert_eq!(accepts, 1);
    assert!(!log.contains("[warn]"), "{log}");
}
