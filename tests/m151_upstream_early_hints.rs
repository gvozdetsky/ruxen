//! M151 — a 103 Early Hints head from the upstream is an interim response
//! (#581). nginx (1.29.0+, `early_hints` unset) parses it, drops its
//! headers and reads the next status line (ngx_http_proxy_process_header,
//! ngx_http_upstream_process_early_hints); a 103 in an HTTP/1.0 response
//! is an invalid header, so a 502. ruxen sent the 103 as the final
//! response and the client waited for one that never came.
//!
//! The backend answers the first request on a connection with `first`,
//! written in pieces with a pause between them so they arrive in separate
//! reads, and the later ones with `answer for <path>`; it keeps the
//! connection open.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

const HINTS: &[u8] = b"HTTP/1.1 103 Early Hints\r\nLink: </s.css>; rel=preload\r\n\r\n";
const MORE_HINTS: &[u8] = b"HTTP/1.1 103 Early Hints\r\nLink: </t.js>; rel=preload\r\n\r\n";
const FINAL: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nok\n";
const PAUSE: Duration = Duration::from_millis(100);

fn spawn_backend(first: Vec<Vec<u8>>) -> (u16, Arc<AtomicUsize>) {
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
                                thread::sleep(PAUSE);
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

struct Run {
    /// The raw responses to `/one` and `/two`, each on its own client
    /// connection, through a keep-alive upstream.
    responses: Vec<String>,
    /// Connections the backend accepted.
    accepts: usize,
    error_log: String,
    /// `$upstream_status $upstream_response_length` per request.
    access_log: String,
}

fn run(name: &str, first: Vec<Vec<u8>>) -> Run {
    let (upstream_port, accepts) = spawn_backend(first);
    let dir = std::env::temp_dir().join(format!("ruxen-m151-{name}-{}", std::process::id()));
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
             events {{}}\nhttp {{\n\
             log_format u '$upstream_status $upstream_response_length';\n\
             access_log {d}/access.log u;\n\
             upstream u {{ server 127.0.0.1:{upstream_port}; keepalive 4; }}\n\
             server {{ listen 127.0.0.1:{port};\n\
             location / {{ proxy_pass http://u; proxy_http_version 1.1; \
             proxy_set_header Connection \"\"; proxy_read_timeout 3s; }} }}\n}}\n",
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
    for path in ["/one", "/two"] {
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        s.write_all(
            format!("GET {path} HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .unwrap();
        // A client left waiting for the final response times out here:
        // what came by then is the answer.
        let mut raw = Vec::new();
        let _ = s.read_to_end(&mut raw);
        responses.push(String::from_utf8_lossy(&raw).into_owned());
    }
    // The access log line is written after the response.
    thread::sleep(Duration::from_millis(200));
    let _ = child.0.kill();
    let _ = child.0.wait();
    let error_log = std::fs::read_to_string(dir.join("error.log")).unwrap_or_default();
    let access_log = std::fs::read_to_string(dir.join("access.log")).unwrap_or_default();
    let _ = std::fs::remove_dir_all(&dir);
    Run {
        responses,
        accepts: accepts.load(Ordering::SeqCst),
        error_log,
        access_log,
    }
}

/// The hints are dropped and the final response relayed; the upstream
/// connection goes back to the pool and serves the second request.
fn assert_final_relayed(name: &str, first: Vec<Vec<u8>>) {
    let run = run(name, first);
    let one = &run.responses[0];
    assert!(one.starts_with("HTTP/1.1 200 OK\r\n"), "{name}: {one:?}");
    assert!(one.ends_with("\r\n\r\nok\n"), "{name}: {one:?}");
    assert!(one.contains("\r\nContent-Length: 3\r\n"), "{name}: {one:?}");
    assert!(!one.contains("Link"), "{name}: {one:?}");
    assert!(!one.contains("103"), "{name}: {one:?}");
    let two = &run.responses[1];
    assert!(
        two.ends_with("\r\n\r\nanswer for /two\n"),
        "{name}: {two:?}"
    );
    assert_eq!(run.accepts, 1, "{name}: the connection is reused");
    // The final status, and the body's length: the hints aren't body.
    assert_eq!(
        run.access_log.lines().next(),
        Some("200 3"),
        "{name}: {}",
        run.access_log
    );
    assert!(
        !run.error_log.contains("[error]"),
        "{name}: {}",
        run.error_log
    );
}

fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

#[test]
fn hints_and_final_in_one_read() {
    assert_final_relayed("one", vec![cat(&[HINTS, FINAL])]);
}

#[test]
fn hints_and_final_in_two_reads() {
    assert_final_relayed("two", vec![HINTS.to_vec(), FINAL.to_vec()]);
}

#[test]
fn heads_split_mid_line() {
    // The 103's terminator, and the final head, each across two reads.
    let hints_end = HINTS.len() - 2;
    let all = cat(&[HINTS, FINAL]);
    assert_final_relayed(
        "mid",
        vec![
            all[..hints_end].to_vec(),
            all[hints_end..HINTS.len() + 10].to_vec(),
            all[HINTS.len() + 10..].to_vec(),
        ],
    );
}

#[test]
fn two_hints_in_one_read() {
    assert_final_relayed("twohints", vec![cat(&[HINTS, MORE_HINTS, FINAL])]);
}

#[test]
fn two_hints_in_separate_reads() {
    assert_final_relayed(
        "twohintssplit",
        vec![HINTS.to_vec(), MORE_HINTS.to_vec(), FINAL.to_vec()],
    );
}

#[test]
fn body_after_the_final_head_is_streamed() {
    // The body comes after the head: the streaming relay (proxy_stream).
    let head = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n";
    assert_final_relayed("stream", vec![cat(&[HINTS, head]), b"ok\n".to_vec()]);
}

#[test]
fn hints_in_an_http10_response_are_a_502() {
    let first = b"HTTP/1.0 103 Early Hints\r\nLink: </s.css>; rel=preload\r\n\r\n\
                  HTTP/1.0 200 OK\r\nContent-Length: 3\r\n\r\nok\n";
    let run = run("http10", vec![first.to_vec()]);
    let one = &run.responses[0];
    assert!(one.starts_with("HTTP/1.1 502 Bad Gateway\r\n"), "{one:?}");
    assert!(
        run.error_log.contains(
            "upstream sent HTTP/1.0 response with early hints while reading response header \
             from upstream"
        ),
        "{}",
        run.error_log
    );
    // The failed connection isn't reused: the second request gets a new
    // one, which answers the same.
    assert_eq!(run.accepts, 2);
    let two = &run.responses[1];
    assert!(two.starts_with("HTTP/1.1 502 Bad Gateway\r\n"), "{two:?}");
    assert_eq!(
        run.access_log.lines().next(),
        Some("502 0"),
        "{}",
        run.access_log
    );
}

#[test]
fn invalid_header_in_hints_is_a_502() {
    // Its header lines are parsed as any head's, so nginx refuses this one.
    let first = cat(&[b"HTTP/1.1 103 Early Hints\r\nLi nk: x\r\n\r\n", FINAL]);
    let run = run("badhints", vec![first]);
    let one = &run.responses[0];
    assert!(one.starts_with("HTTP/1.1 502 Bad Gateway\r\n"), "{one:?}");
    assert!(
        run.error_log
            .contains("upstream sent invalid header: \"Li\\x20...\" while reading response header"),
        "{}",
        run.error_log
    );
}
