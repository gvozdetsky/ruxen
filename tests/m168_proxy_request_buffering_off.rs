//! M168 — `proxy_request_buffering off` (#134): the request body goes
//! upstream as the client sends it, the head as soon as it is read.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

const PAUSE: Duration = Duration::from_millis(1000);

/// What the backend got: the head, the raw body, and when the head came.
struct Got {
    head: String,
    body: Vec<u8>,
    head_at: Instant,
}

/// A backend reading one request per connection: the body by its
/// Content-Length, or raw chunked up to the last chunk.
fn spawn_backend(listener: TcpListener) -> mpsc::Receiver<Got> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut conn) = conn else { return };
            let tx = tx.clone();
            thread::spawn(move || {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                let head_end = loop {
                    if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        break p + 4;
                    }
                    match conn.read(&mut chunk) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                };
                let head_at = Instant::now();
                let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
                let mut body = buf[head_end..].to_vec();
                let lower = head.to_ascii_lowercase();
                let len = lower
                    .split("\r\ncontent-length: ")
                    .nth(1)
                    .and_then(|v| v.split("\r\n").next())
                    .and_then(|v| v.parse::<usize>().ok());
                loop {
                    let done = match len {
                        Some(len) => body.len() >= len,
                        None => body.ends_with(b"0\r\n\r\n"),
                    };
                    if done {
                        break;
                    }
                    match conn.read(&mut chunk) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => body.extend_from_slice(&chunk[..n]),
                    }
                }
                let _ = conn.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nok\n",
                );
                let _ = tx.send(Got {
                    head,
                    body,
                    head_at,
                });
            });
        }
    });
    rx
}

struct Setup {
    dir: PathBuf,
    port: u16,
    got: mpsc::Receiver<Got>,
    _child: common::KillOnDrop,
}

impl Drop for Setup {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn setup(name: &str) -> Setup {
    let dir = std::env::temp_dir().join(format!("ruxen-m168-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let lock = common::ports::setup_lock();
    let [port] = common::ports::free_ports();
    let backend = TcpListener::bind("127.0.0.1:0").unwrap();
    let b = backend.local_addr().unwrap().port();
    let got = spawn_backend(backend);
    let d = dir.display();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "worker_processes 1;\nerror_log {d}/error.log;\n\
             events {{}}\nhttp {{ access_log off;\n\
             server {{ listen 127.0.0.1:{port};\n\
               proxy_request_buffering off; client_body_timeout 3s;\n\
               location / {{ proxy_pass http://127.0.0.1:{b}; }}\n\
               location /buf/ {{ proxy_request_buffering on; proxy_pass http://127.0.0.1:{b}/; }}\n\
               location /ret/ {{ return 200 \"ret\\n\"; }}\n\
             }} }}\n"
        ),
    )
    .unwrap();
    let pid_file = dir.join("ruxen.pid");
    let mut child = common::KillOnDrop(
        Command::new(env!("CARGO_BIN_EXE_ruxen"))
            .arg("-c")
            .arg(dir.join("nginx.conf"))
            .arg("-g")
            .arg(format!("pid {};", pid_file.display()))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    common::ports::wait_for_pid_file(&mut child, &pid_file, Duration::from_secs(5));
    drop(lock);
    Setup {
        dir,
        port,
        got,
        _child: child,
    }
}

/// Send `first`, pause, send `rest`; the response(s) until the close.
fn upload(port: u16, first: &str, rest: &str) -> (String, Instant) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.write_all(first.as_bytes()).unwrap();
    let sent_head = Instant::now();
    thread::sleep(PAUSE);
    let _ = s.write_all(rest.as_bytes());
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    (String::from_utf8_lossy(&out).into_owned(), sent_head)
}

#[test]
fn m168_length_body_goes_as_it_comes() {
    let s = setup("length");
    // The second request on the connection starts after the body.
    let (resp, sent_head) = upload(
        s.port,
        "POST /up HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\n01234",
        "56789GET /ret/ HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    let got = s.got.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(
        got.head_at < sent_head + PAUSE / 2,
        "the head waited for the body"
    );
    assert!(
        got.head.contains("\r\nContent-Length: 10\r\n"),
        "{}",
        got.head
    );
    assert_eq!(got.body, b"0123456789");
    assert!(resp.starts_with("HTTP/1.1 200 "), "{resp}");
    assert!(resp.contains("\r\n\r\nok\n"), "{resp}");
    assert!(resp.ends_with("\r\n\r\nret\n"), "{resp}");
}

#[test]
fn m168_chunked_body_is_rechunked() {
    let s = setup("chunked");
    let (resp, sent_head) = upload(
        s.port,
        "POST /up HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n01234\r\n",
        "3\r\n567\r\n2\r\n89\r\n0\r\n\r\nGET /ret/ HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    let got = s.got.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(
        got.head_at < sent_head + PAUSE / 2,
        "the head waited for the body"
    );
    assert!(
        got.head.contains("\r\nTransfer-Encoding: chunked\r\n"),
        "{}",
        got.head
    );
    assert!(!got.head.contains("Content-Length"), "{}", got.head);
    // What came at once goes as one chunk.
    assert_eq!(
        String::from_utf8_lossy(&got.body),
        "5\r\n01234\r\n5\r\n56789\r\n0\r\n\r\n"
    );
    assert!(resp.starts_with("HTTP/1.1 200 "), "{resp}");
    assert!(resp.ends_with("\r\n\r\nret\n"), "{resp}");
}

/// A body that stops coming: `client_body_timeout`, a 408.
#[test]
fn m168_stalled_body_times_out() {
    let s = setup("stall");
    let started = Instant::now();
    let mut c = TcpStream::connect(("127.0.0.1", s.port)).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    c.write_all(b"POST /up HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\n01234")
        .unwrap();
    let mut out = Vec::new();
    let _ = c.read_to_end(&mut out);
    let resp = String::from_utf8_lossy(&out);
    assert!(resp.starts_with("HTTP/1.1 408 "), "{resp}");
    assert!(started.elapsed() < Duration::from_secs(5));
}

/// `proxy_request_buffering on` (the default) still reads it first.
#[test]
fn m168_buffered_location_waits_for_the_body() {
    let s = setup("buffered");
    let (resp, sent_head) = upload(
        s.port,
        "POST /buf/up HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Length: 10\r\n\r\n01234",
        "56789",
    );
    let got = s.got.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(got.head_at >= sent_head + PAUSE / 2);
    assert_eq!(got.body, b"0123456789");
    assert!(resp.starts_with("HTTP/1.1 200 "), "{resp}");
}
