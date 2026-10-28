mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::MutexGuard;
use std::thread::sleep;
use std::time::Duration;

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

fn pick_port() -> (u16, MutexGuard<'static, ()>) {
    let g = common::ports::setup_lock();
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let p = l.local_addr().unwrap().port();
    drop(l);
    (p, g)
}

fn unique_dir() -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let d = std::env::temp_dir().join(format!(
        "ruxen-m18-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir(&d).unwrap();
    d
}

fn spawn_server() -> (ServerGuard, u16) {
    spawn_with(
        r#"
  server {
    listen 127.0.0.1:PORT;

    location = /short {
      keepalive_timeout 100ms;
      return 200 "short";
    }

    location = /none {
      return 200 "none";
    }
  }
"#,
    )
}

/// ruxen with this `http` block body, `PORT` its port.
fn spawn_with(http: &str) -> (ServerGuard, u16) {
    let (port, _lock) = pick_port();
    let dir = unique_dir();
    let conf_path = dir.join("ruxen.conf");
    let http = http.replace("PORT", &port.to_string());
    std::fs::write(&conf_path, format!("events {{ }}\nhttp {{\n{http}\n}}\n")).unwrap();

    let pid_file = dir.join("ruxen.pid");
    let child = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .args(["-c", conf_path.to_str().unwrap()])
        .arg("-g")
        .arg(format!("pid {};", pid_file.display()))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ruxen");
    // Owned by the guard before the wait: if it panics, ruxen still stops.
    let mut guard = ServerGuard {
        child,
        tempdir: dir,
    };
    common::ports::wait_for_pid_file(&mut guard.child, &pid_file, Duration::from_secs(5));
    (guard, port)
}

fn header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

fn content_length(buf: &[u8]) -> Option<usize> {
    let text = std::str::from_utf8(buf).ok()?;
    let head_end = text.find("\r\n\r\n")?;
    for line in text[..head_end].split("\r\n").skip(1) {
        let (k, v) = line.split_once(':')?;
        if k.eq_ignore_ascii_case("Content-Length") {
            return v.trim().parse().ok();
        }
    }
    None
}

fn read_one_response(stream: &mut TcpStream) -> Vec<u8> {
    let mut out = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        match stream.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&tmp[..n]),
            Err(_) => break,
        }

        let Some(end) = header_end(&out) else {
            continue;
        };
        let Some(cl) = content_length(&out) else {
            break;
        };
        if out.len() >= end + cl {
            out.truncate(end + cl);
            break;
        }
    }
    out
}

fn status_line(resp: &[u8]) -> &str {
    let end = resp.iter().position(|&b| b == b'\r').unwrap_or(resp.len());
    std::str::from_utf8(&resp[..end]).unwrap()
}

fn header_value<'a>(resp: &'a [u8], name: &str) -> Option<&'a str> {
    let s = std::str::from_utf8(resp).ok()?;
    let header_end = s.find("\r\n\r\n").unwrap_or(s.len());
    for line in s[..header_end].split("\r\n").skip(1) {
        if let Some((k, v)) = line.split_once(':')
            && k.eq_ignore_ascii_case(name)
        {
            return Some(v.trim());
        }
    }
    None
}

#[test]
fn keepalive_timeout_closes_idle_connection_after_deadline() {
    let (_guard, port) = spawn_server();
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(1))).unwrap();

    s.write_all(b"GET /short HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .unwrap();
    let first = read_one_response(&mut s);
    assert_eq!(status_line(&first), "HTTP/1.1 200 OK");
    assert_eq!(header_value(&first, "Connection"), Some("keep-alive"));
    assert_eq!(header_value(&first, "Keep-Alive"), None);

    sleep(Duration::from_millis(350));

    if s.write_all(b"GET /short HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .is_ok()
    {
        let second = read_one_response(&mut s);
        assert!(
            second.is_empty(),
            "connection stayed open past keepalive_timeout: {}",
            String::from_utf8_lossy(&second)
        );
    }
}

#[test]
fn no_keepalive_timeout_still_allows_connection_reuse() {
    let (_guard, port) = spawn_server();
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(1))).unwrap();

    s.write_all(b"GET /none HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .unwrap();
    let first = read_one_response(&mut s);
    assert_eq!(status_line(&first), "HTTP/1.1 200 OK");
    assert_eq!(header_value(&first, "Connection"), Some("keep-alive"));

    sleep(Duration::from_millis(350));

    s.write_all(b"GET /none HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    let second = read_one_response(&mut s);
    assert_eq!(status_line(&second), "HTTP/1.1 200 OK");
    assert_eq!(header_value(&second, "Connection"), Some("close"));
}

/// Seconds until the server closes `s`, at most `limit`.
fn closed_within(s: &mut TcpStream, limit: Duration) -> Option<Duration> {
    let start = std::time::Instant::now();
    s.set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let mut tmp = [0u8; 4096];
    while start.elapsed() < limit {
        match s.read(&mut tmp) {
            Ok(0) => return Some(start.elapsed()),
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {
                return Some(start.elapsed());
            }
            Err(_) => {}
        }
    }
    None
}

/// A server-level `return` answers before any location: the server's
/// keepalive_timeout bounds the wait after it, 0 closes (#773).
#[test]
fn server_level_return_uses_the_servers_keepalive_timeout() {
    let (_guard, port) = spawn_with(
        r#"
  server { listen 127.0.0.1:PORT; keepalive_timeout 300ms; return 200 "srv"; }
"#,
    );
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    s.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .unwrap();
    let first = read_one_response(&mut s);
    assert_eq!(status_line(&first), "HTTP/1.1 200 OK");
    let closed = closed_within(&mut s, Duration::from_secs(5));
    assert!(closed.is_some(), "idle connection still open after 5 s");

    let (_guard, port) = spawn_with(
        r#"
  server {
    listen 127.0.0.1:PORT;
    keepalive_timeout 0;
    return 200 "srv";
    location / { keepalive_timeout 10s; }
  }
"#,
    );
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    s.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .unwrap();
    let first = read_one_response(&mut s);
    assert_eq!(status_line(&first), "HTTP/1.1 200 OK");
    let closed = closed_within(&mut s, Duration::from_secs(2));
    assert!(closed.is_some(), "keepalive_timeout 0 kept the connection");
}

/// HTTP/2: until its first stream, a connection gets client_header_timeout,
/// however long keepalive_timeout is (ngx_http_v2_init).
#[test]
fn http2_without_streams_is_closed_after_client_header_timeout() {
    let (_guard, port) = spawn_with(
        r#"
  http2 on;
  client_header_timeout 500ms;
  keepalive_timeout 1h;
  server { listen 127.0.0.1:PORT; return 200 "srv"; }
"#,
    );
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    // The preface and an empty SETTINGS frame.
    s.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\0\0\0\x04\0\0\0\0\0")
        .unwrap();
    let closed = closed_within(&mut s, Duration::from_secs(10));
    assert!(closed.is_some(), "h2 connection without streams still open");
}
