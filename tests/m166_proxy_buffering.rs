//! M166 — `proxy_buffering` (#764): while the client is slow, the
//! upstream's response is read on into memory and a temp file, and the
//! upstream connection goes back to the pool once the body is in, as
//! nginx's event pipe does. `proxy_buffering off`, `X-Accel-Buffering: no`
//! and `proxy_max_temp_file_size 0` hold the upstream to the client's pace.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

const BIG: usize = 4 << 20;

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 % 251) as u8).collect()
}

/// A keep-alive backend counting its connections. `/big` is 4 MiB with a
/// length, `/chunked` the same chunked, `/noaccel` the same with
/// `X-Accel-Buffering: no`; anything else is a small 200.
fn spawn_backend(listener: TcpListener) -> Arc<AtomicUsize> {
    let conns = Arc::new(AtomicUsize::new(0));
    let counter = conns.clone();
    thread::spawn(move || {
        let body = Arc::new(pattern(BIG));
        for conn in listener.incoming() {
            let Ok(mut conn) = conn else { return };
            counter.fetch_add(1, Ordering::SeqCst);
            let body = body.clone();
            thread::spawn(move || {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
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
                    let ok = match path.as_str() {
                        "/big" | "/noaccel" => {
                            let accel = if path == "/noaccel" {
                                "X-Accel-Buffering: no\r\n"
                            } else {
                                ""
                            };
                            let head =
                                format!("HTTP/1.1 200 OK\r\nContent-Length: {BIG}\r\n{accel}\r\n");
                            conn.write_all(head.as_bytes()).is_ok() && conn.write_all(&body).is_ok()
                        }
                        "/chunked" => {
                            let mut out =
                                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
                            for part in body.chunks(60_000) {
                                out.extend_from_slice(format!("{:x}\r\n", part.len()).as_bytes());
                                out.extend_from_slice(part);
                                out.extend_from_slice(b"\r\n");
                            }
                            out.extend_from_slice(b"0\r\n\r\n");
                            conn.write_all(&out).is_ok()
                        }
                        _ => conn
                            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nok\n")
                            .is_ok(),
                    };
                    if !ok {
                        return;
                    }
                }
            });
        }
    });
    conns
}

fn get(port: u16, path: &str) -> Vec<u8> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    write!(s, "GET {path} HTTP/1.0\r\nHost: localhost\r\n\r\n").unwrap();
    let mut out = Vec::new();
    s.read_to_end(&mut out).unwrap();
    let end = out.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    assert!(out.starts_with(b"HTTP/1.1 200 "), "{path}");
    out.split_off(end)
}

/// `$upstream_response_time` of the last request for `uri`.
fn upstream_time(log: &std::path::Path, uri: &str) -> f64 {
    let log = std::fs::read_to_string(log).unwrap();
    let line = log
        .lines()
        .rfind(|l| l.split(' ').next() == Some(uri))
        .unwrap_or_else(|| panic!("no {uri} in {log}"));
    line.split(' ').nth(1).unwrap().parse().unwrap()
}

#[test]
fn a_slow_client_does_not_hold_the_upstream() {
    let dir = std::env::temp_dir().join(format!("ruxen-m166-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let backend = TcpListener::bind("127.0.0.1:0").unwrap();
    let backend_port = backend.local_addr().unwrap().port();
    let conns = spawn_backend(backend);
    let setup = common::ports::setup_lock();
    let [port] = common::ports::free_ports();
    let d = dir.display();
    // 4 MiB at 1 MiB a second, the first second's worth at once: about
    // three seconds for the client.
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "worker_processes 1;\npid {d}/ruxen.pid;\nerror_log {d}/error.log;\nevents {{}}\n\
             http {{\nlog_format t '$uri $upstream_response_time';\n\
             access_log {d}/access.log t;\n\
             upstream b {{ server 127.0.0.1:{backend_port}; keepalive 4; }}\n\
             server {{ listen 127.0.0.1:{port}; limit_rate 1m;\n\
             proxy_http_version 1.1; proxy_set_header Connection \"\";\n\
             location / {{ proxy_pass http://b; proxy_temp_path {d}/temp 1; }}\n\
             location /off/ {{ proxy_pass http://b/; proxy_buffering off; }}\n\
             location /mem/ {{ proxy_pass http://b/; proxy_max_temp_file_size 0; }}\n\
             }} }}\n"
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
    let log = dir.join("access.log");

    // Buffered: the body is in long before the client has it, and the
    // connection serves another request meanwhile.
    let slow = thread::spawn(move || get(port, "/big"));
    thread::sleep(Duration::from_millis(500));
    assert_eq!(get(port, "/small"), b"ok\n");
    assert!(slow.join().unwrap() == pattern(BIG));
    assert_eq!(conns.load(Ordering::SeqCst), 1, "the connection was pooled");
    assert!(upstream_time(&log, "/big") < 1.0);

    // The same through the decoder; then at the client's pace: buffering
    // off, or off for this response, or too little room without a temp
    // file.
    let uris = ["/chunked", "/off/big", "/noaccel", "/mem/big"];
    let clients: Vec<_> = uris
        .iter()
        .map(|&uri| thread::spawn(move || get(port, uri)))
        .collect();
    for (uri, client) in uris.iter().zip(clients) {
        assert!(client.join().unwrap() == pattern(BIG), "{uri}");
    }
    let t = upstream_time(&log, "/chunked");
    assert!(t < 1.0, "/chunked: {t}");
    for uri in &uris[1..] {
        let t = upstream_time(&log, uri);
        assert!(t > 1.0, "{uri}: {t}");
    }
}

#[test]
fn proxy_buffers_are_checked_as_nginx_does() {
    for (conf, ok) in [
        ("proxy_buffers 2 8k; proxy_busy_buffers_size 8k;", true),
        ("proxy_buffers 1 8k;", false),
        ("proxy_buffers 0 8k;", false),
        ("proxy_buffers 8 0;", false),
        ("proxy_buffers 4 4k; proxy_busy_buffers_size 16k;", false),
        ("proxy_buffer_size 16k;", false),
        ("proxy_buffer_size 16k; proxy_busy_buffers_size 16k;", true),
        ("proxy_max_temp_file_size 1k;", false),
        (
            "proxy_max_temp_file_size 0; proxy_temp_file_write_size 8k;",
            true,
        ),
        ("proxy_temp_file_write_size 1k;", false),
        ("proxy_buffering maybe;", false),
        ("proxy_temp_path /tmp/x 1 2 3 4;", false),
    ] {
        let dir = std::env::temp_dir().join(format!("ruxen-m166-t-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("nginx.conf");
        std::fs::write(
            &path,
            format!(
                "events {{}}\nhttp {{ server {{ listen 127.0.0.1:1; \
                 location / {{ proxy_pass http://127.0.0.1:2; {conf} }} }} }}\n"
            ),
        )
        .unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_ruxen"))
            .arg("-t")
            .arg("-c")
            .arg(&path)
            .output()
            .unwrap();
        assert_eq!(
            out.status.success(),
            ok,
            "{conf}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}
