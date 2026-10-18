//! M141 — a buffered response over ruxen's 64 MiB cap is a 502, but not
//! a failure of the peer (#513): no failover to the next peer, which
//! would answer the same, and nothing counted against `max_fails`, so one
//! request for a large object can't take the upstream group down.
//!
//! `proxy_cache` keeps the response on the buffered path. A
//! `Content-Length` over the cap is refused before the body is read, so
//! the backends only send the head.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

/// A backend that answers `/big` with a 70 MiB `Content-Length` and no
/// body, and anything else with `small`. Counts the `/big` requests.
fn spawn_backend() -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let big = Arc::new(AtomicUsize::new(0));
    let counter = big.clone();
    thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut conn) = conn else { return };
            let counter = counter.clone();
            thread::spawn(move || {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match conn.read(&mut chunk) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                let answer: &[u8] = if buf.starts_with(b"GET /big ") {
                    counter.fetch_add(1, Ordering::SeqCst);
                    b"HTTP/1.1 200 OK\r\nContent-Length: 73400320\r\nConnection: close\r\n\r\n"
                } else {
                    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nsmall"
                };
                let _ = conn.write_all(answer);
                // Hold the connection a moment: ruxen closes first.
                let _ = conn.read(&mut chunk);
            });
        }
    });
    (port, big)
}

fn get(port: u16, path: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.write_all(format!("GET {path} HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n").as_bytes())
        .unwrap();
    let mut raw = String::new();
    s.read_to_string(&mut raw).unwrap();
    raw
}

#[test]
fn too_big_is_a_502_without_blaming_the_peers() {
    let (a, big_a) = spawn_backend();
    let (b, big_b) = spawn_backend();
    let dir = std::env::temp_dir().join(format!("ruxen-m141-{}", std::process::id()));
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
            "worker_processes 1;\npid {d}/ruxen.pid;\nerror_log {d}/error.log;\n\
             events {{}}\nhttp {{\naccess_log off;\n\
             proxy_cache_path {d}/cache keys_zone=z:1m;\n\
             upstream u {{ server 127.0.0.1:{a}; server 127.0.0.1:{b}; }}\n\
             server {{ listen 127.0.0.1:{port};\n\
             location / {{ proxy_pass http://u; proxy_cache z; \
             proxy_cache_valid 200 10m; }} }}\n}}\n",
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

    let raw = get(port, "/big");
    assert!(raw.starts_with("HTTP/1.1 502 "), "{raw}");
    // One peer asked: the default `proxy_next_upstream error timeout`
    // doesn't move on.
    assert_eq!(
        big_a.load(Ordering::SeqCst) + big_b.load(Ordering::SeqCst),
        1
    );
    // Both peers still up (`max_fails=1` by default): main gave `no live
    // upstreams` here.
    for path in ["/s1", "/s2", "/s3", "/s4"] {
        let raw = get(port, path);
        assert!(
            raw.starts_with("HTTP/1.1 200 ") && raw.ends_with("small"),
            "{path}: {raw}"
        );
    }
    let raw = get(port, "/big");
    assert!(raw.starts_with("HTTP/1.1 502 "), "{raw}");
    assert_eq!(
        big_a.load(Ordering::SeqCst) + big_b.load(Ordering::SeqCst),
        2
    );

    let _ = child.0.kill();
    let _ = child.0.wait();
    let log = std::fs::read_to_string(dir.join("error.log")).unwrap_or_default();
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(
        log.matches("upstream response is too big to buffer")
            .count(),
        2,
        "{log}"
    );
    assert!(!log.contains("no live upstreams"), "{log}");
}
