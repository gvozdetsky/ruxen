use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, MutexGuard};
use std::thread::sleep;
use std::time::{Duration, Instant};

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

static SETUP_LOCK: Mutex<()> = Mutex::new(());

fn pick_port() -> (u16, MutexGuard<'static, ()>) {
    let g = SETUP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let p = l.local_addr().unwrap().port();
    drop(l);
    (p, g)
}

fn unique_dir() -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let d = std::env::temp_dir().join(format!(
        "ruxen-m16-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir(&d).unwrap();
    d
}

fn wait_for_listen(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        if Instant::now() > deadline {
            panic!("ruxen did not start listening on port {port}");
        }
        sleep(Duration::from_millis(20));
    }
}

fn spawn_server() -> (ServerGuard, u16) {
    let (port, _lock) = pick_port();
    let dir = unique_dir();
    std::fs::write(dir.join("clear.txt"), b"abcdefgh").unwrap();
    std::fs::write(dir.join("override.txt"), b"abcdefgh").unwrap();

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

    location = /clear.txt {{
      add_header Last-Modified "";
    }}

    location = /override.txt {{
      add_header Last-Modified "Mon, 28 Sep 1970 06:00:00 GMT";
    }}
  }}
}}
"#,
            root = dir.display()
        ),
    )
    .unwrap();

    let child = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .args(["-c", conf_path.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ruxen");

    wait_for_listen(port);
    (
        ServerGuard {
            child,
            tempdir: dir,
        },
        port,
    )
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
        if let Some((k, v)) = line.split_once(':') {
            if k.eq_ignore_ascii_case(name) {
                return Some(v.trim());
            }
        }
    }
    None
}

#[test]
fn add_header_last_modified_empty_suppresses_builtin_static_header() {
    let (_g, port) = spawn_server();
    let r = request(
        port,
        b"GET /clear.txt HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_line(&r), "HTTP/1.1 200 OK");
    assert_eq!(header_value(&r, "Last-Modified"), None);
}

#[test]
fn add_header_last_modified_non_empty_overrides_builtin_value() {
    let (_g, port) = spawn_server();
    let r = request(
        port,
        b"GET /override.txt HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_line(&r), "HTTP/1.1 200 OK");
    assert_eq!(
        header_value(&r, "Last-Modified"),
        Some("Mon, 28 Sep 1970 06:00:00 GMT")
    );
}

#[test]
fn add_header_last_modified_override_applies_on_if_range_fallback_200() {
    let (_g, port) = spawn_server();
    let r = request(
        port,
        b"GET /override.txt HTTP/1.1\r\nHost: localhost\r\nRange: bytes=0-3\r\nIf-Range: wrong\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_line(&r), "HTTP/1.1 200 OK");
    assert_eq!(
        header_value(&r, "Last-Modified"),
        Some("Mon, 28 Sep 1970 06:00:00 GMT")
    );
}
