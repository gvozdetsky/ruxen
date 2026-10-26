mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::MutexGuard;
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
        "ruxen-m25-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir(&d).unwrap();
    d
}

fn spawn_server() -> (ServerGuard, u16) {
    let (port, _lock) = pick_port();
    let dir = unique_dir();
    std::fs::write(dir.join("override.txt"), b"abcdefgh").unwrap();
    std::fs::write(dir.join("clear.txt"), b"abcdefgh").unwrap();

    let conf_path = dir.join("ruxen.conf");
    std::fs::write(
        &conf_path,
        format!(
            r#"
events {{ }}
http {{
  server {{
    listen 127.0.0.1:{port};
    root {root};

    location = /override.txt {{
      add_header Last-Modified "Mon, 28 Sep 1970 06:00:00 GMT";
    }}

    location = /clear.txt {{
      add_header Last-Modified "";
    }}
  }}
}}
"#,
            root = dir.display()
        ),
    )
    .unwrap();

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

fn request(port: u16, raw: &[u8]) -> Vec<u8> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    s.write_all(raw).unwrap();
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match s.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(_) => break,
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

fn body(resp: &[u8]) -> &[u8] {
    resp.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| &resp[i + 4..])
        .unwrap_or(&[])
}

/// nginx's not-modified filter runs before `add_header`: If-Modified-Since
/// is compared with the file's own mtime, not the Last-Modified the
/// location sets, so the date it sets is no 304. If-Range (the range
/// filter comes after) does see it.
#[test]
fn if_modified_since_ignores_overridden_last_modified_date() {
    let (_guard, port) = spawn_server();
    let r = request(
        port,
        b"GET /override.txt HTTP/1.1\r\nHost: localhost\r\nIf-Modified-Since: Mon, 28 Sep 1970 06:00:00 GMT\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_line(&r), "HTTP/1.1 200 OK");
    assert_eq!(
        header_value(&r, "Last-Modified"),
        Some("Mon, 28 Sep 1970 06:00:00 GMT")
    );
}

#[test]
fn if_range_date_uses_overridden_last_modified_date() {
    let (_guard, port) = spawn_server();
    let r = request(
        port,
        b"GET /override.txt HTTP/1.1\r\nHost: localhost\r\nRange: bytes=0-3\r\nIf-Range: Mon, 28 Sep 1970 06:00:00 GMT\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_line(&r), "HTTP/1.1 206 Partial Content");
    assert_eq!(body(&r), b"abcd");
}

#[test]
fn suppressed_last_modified_disables_if_modified_since_304() {
    let (_guard, port) = spawn_server();
    let r = request(
        port,
        b"GET /clear.txt HTTP/1.1\r\nHost: localhost\r\nIf-Modified-Since: Thu, 01 Jan 2099 00:00:00 GMT\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_line(&r), "HTTP/1.1 200 OK");
    assert_eq!(header_value(&r, "Last-Modified"), None);
}
