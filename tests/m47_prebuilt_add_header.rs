//! M47 — a static `return` with all-literal `add_header`s is served from a
//! per-worker prebuilt. Repeated requests on one keep-alive connection must
//! keep getting the same headers; variable values must still render per
//! request; an `error_page` status override must not reuse the prebuilt.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, MutexGuard};
use std::thread::sleep;
use std::time::{Duration, Instant};

struct ServerGuard {
    child: Child,
    dir: PathBuf,
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

static SETUP_LOCK: Mutex<()> = Mutex::new(());

fn pick_port() -> (u16, MutexGuard<'static, ()>) {
    let guard = SETUP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    (port, guard)
}

fn spawn() -> (ServerGuard, u16) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "ruxen-m47-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir(&dir).unwrap();
    let (port, _lock) = pick_port();
    let conf = dir.join("ruxen.conf");
    std::fs::write(
        &conf,
        format!(
            r#"pid {d}/ruxen.pid;
events {{}}
http {{
  access_log off;
  server {{
    listen 127.0.0.1:{port};
    location /lit {{
      add_header X-A one;
      add_header X-B "two words";
      return 200 "hello";
    }}
    location /var {{
      add_header X-Uri $request_uri;
      add_header X-Lit lit;
      return 200 "v";
    }}
    location /err {{
      add_header X-Lit lit;
      error_page 404 =200 /fallback;
      return 404;
    }}
    location /fallback {{
      return 200 "fb";
    }}
  }}
}}
"#,
            d = dir.display()
        ),
    )
    .unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .args(["-c", conf.to_str().unwrap()])
        .env("RUXEN_WORKERS", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ruxen");
    let deadline = Instant::now() + Duration::from_secs(3);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "ruxen did not start");
        sleep(Duration::from_millis(20));
    }
    (ServerGuard { child, dir }, port)
}

/// Send one request on `stream` and read back exactly one response
/// (Content-Length framed).
fn exchange(stream: &mut TcpStream, path: &str) -> (String, String) {
    write!(stream, "GET {path} HTTP/1.1\r\nHost: t\r\n\r\n").unwrap();
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        if let Some(i) = got.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8(got[..i + 4].to_vec()).unwrap();
            let len: usize = head
                .lines()
                .find_map(|l| {
                    let (k, v) = l.split_once(':')?;
                    k.eq_ignore_ascii_case("content-length").then(|| v.trim().parse().unwrap())
                })
                .unwrap_or(0);
            while got.len() < i + 4 + len {
                let n = stream.read(&mut buf).unwrap();
                assert!(n > 0);
                got.extend_from_slice(&buf[..n]);
            }
            let body = String::from_utf8(got[i + 4..i + 4 + len].to_vec()).unwrap();
            return (head, body);
        }
        let n = stream.read(&mut buf).unwrap();
        assert!(n > 0, "connection closed");
        got.extend_from_slice(&buf[..n]);
    }
}

#[test]
fn literal_add_headers_stay_correct_across_keepalive_requests() {
    let (_g, port) = spawn();
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    for _ in 0..5 {
        let (head, body) = exchange(&mut s, "/lit");
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        assert!(head.contains("\r\nX-A: one\r\n"), "{head}");
        assert!(head.contains("\r\nX-B: two words\r\n"), "{head}");
        assert!(head.contains("\r\nConnection: keep-alive\r\n"), "{head}");
        assert_eq!(head.matches("X-A:").count(), 1, "{head}");
        assert_eq!(body, "hello");
    }
}

#[test]
fn variable_add_headers_still_render_per_request() {
    let (_g, port) = spawn();
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    for q in ["a=1", "b=2", "c=3"] {
        let (head, _) = exchange(&mut s, &format!("/var?{q}"));
        assert!(head.contains(&format!("\r\nX-Uri: /var?{q}\r\n")), "{head}");
        assert!(head.contains("\r\nX-Lit: lit\r\n"), "{head}");
    }
}

#[test]
fn error_page_status_override_skips_the_prebuilt() {
    let (_g, port) = spawn();
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    for _ in 0..3 {
        let (head, body) = exchange(&mut s, "/err");
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        assert_eq!(body, "fb");
    }
}
