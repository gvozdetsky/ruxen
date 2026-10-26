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
        "ruxen-m26-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir(&d).unwrap();
    d
}

fn spawn_server() -> (ServerGuard, u16) {
    let (port, _lock) = pick_port();
    let dir = unique_dir();
    std::fs::write(dir.join("plain.txt"), b"abcdefgh").unwrap();
    std::fs::write(dir.join("override.txt"), b"abcdefgh").unwrap();
    std::fs::write(dir.join("clear.txt"), b"abcdefgh").unwrap();
    std::fs::write(dir.join("untagged.txt"), b"abcdefgh").unwrap();

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

    location = /untagged.txt {{
      etag off;
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

#[test]
fn stale_if_unmodified_since_returns_412() {
    let (_guard, port) = spawn_server();
    let r = request(
        port,
        b"GET /plain.txt HTTP/1.1\r\nHost: localhost\r\nIf-Unmodified-Since: Thu, 01 Jan 1970 00:00:00 GMT\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_line(&r), "HTTP/1.1 412 Precondition Failed");
}

/// nginx's not-modified filter runs before `add_header`: the file's own
/// mtime (now) is compared, not the 1970 date the location sets.
#[test]
fn if_unmodified_since_ignores_overridden_last_modified_date() {
    let (_guard, port) = spawn_server();
    let r = request(
        port,
        b"GET /override.txt HTTP/1.1\r\nHost: localhost\r\nIf-Unmodified-Since: Mon, 28 Sep 1970 06:00:00 GMT\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_line(&r), "HTTP/1.1 412 Precondition Failed");
}

/// `add_header Last-Modified ""` hides the date from the client only: the
/// precondition still fails against the file's mtime, as in nginx.
#[test]
fn suppressed_last_modified_keeps_if_unmodified_since_412() {
    let (_guard, port) = spawn_server();
    let r = request(
        port,
        b"GET /clear.txt HTTP/1.1\r\nHost: localhost\r\nIf-Unmodified-Since: Thu, 01 Jan 1970 00:00:00 GMT\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_line(&r), "HTTP/1.1 412 Precondition Failed");
    assert_eq!(header_value(&r, "Last-Modified"), None);
}

/// nginx checks If-Unmodified-Since whether or not If-Match came (not RFC
/// 9110's §13.2.2 order, where a present If-Match makes it ignored).
#[test]
fn if_unmodified_since_applies_with_if_match() {
    let (_guard, port) = spawn_server();
    let r = request(
        port,
        b"GET /plain.txt HTTP/1.1\r\nHost: localhost\r\nIf-Match: *\r\nIf-Unmodified-Since: Thu, 01 Jan 1970 00:00:00 GMT\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_line(&r), "HTTP/1.1 412 Precondition Failed");
}

/// A date that doesn't parse fails If-Unmodified-Since, as nginx's
/// ngx_http_test_if_unmodified takes it.
#[test]
fn garbage_if_unmodified_since_is_412() {
    let (_guard, port) = spawn_server();
    let r = request(
        port,
        b"GET /plain.txt HTTP/1.1\r\nHost: localhost\r\nIf-Unmodified-Since: garbage\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_line(&r), "HTTP/1.1 412 Precondition Failed");
}

/// `etag off`: no ETag goes out, and the conditionals see none: only `*`
/// matches If-Match or If-None-Match, and an If-Range tag sends it all.
#[test]
fn etag_off_sends_none_and_only_star_matches() {
    let (_guard, port) = spawn_server();
    let get = |extra: &str| {
        request(
            port,
            format!(
                "GET /untagged.txt HTTP/1.1\r\nHost: localhost\r\n{extra}Connection: close\r\n\r\n"
            )
            .as_bytes(),
        )
    };
    let tagged = request(
        port,
        b"GET /plain.txt HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    let tag = header_value(&tagged, "ETag").unwrap().to_string();
    let r = get("");
    assert_eq!(status_line(&r), "HTTP/1.1 200 OK");
    assert_eq!(header_value(&r, "ETag"), None);
    for (extra, want) in [
        (
            "If-None-Match: *\r\n".to_string(),
            "HTTP/1.1 304 Not Modified",
        ),
        (format!("If-None-Match: {tag}\r\n"), "HTTP/1.1 200 OK"),
        ("If-Match: *\r\n".to_string(), "HTTP/1.1 200 OK"),
        (
            format!("If-Match: {tag}\r\n"),
            "HTTP/1.1 412 Precondition Failed",
        ),
        (
            format!("Range: bytes=0-1\r\nIf-Range: {tag}\r\n"),
            "HTTP/1.1 200 OK",
        ),
    ] {
        let r = get(&extra);
        assert_eq!(status_line(&r), want, "{extra:?}");
        assert_eq!(header_value(&r, "ETag"), None, "{extra:?}");
    }
}

/// Of two Range headers the first counts (ngx_http_process_header_line).
#[test]
fn first_range_header_counts() {
    let (_guard, port) = spawn_server();
    let r = request(
        port,
        b"GET /plain.txt HTTP/1.1\r\nHost: localhost\r\nRange: bytes=0-1\r\nRange: bytes=2-3\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_line(&r), "HTTP/1.1 206 Partial Content");
    assert_eq!(header_value(&r, "Content-Range"), Some("bytes 0-1/8"));
}
