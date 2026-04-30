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
        "ruxen-m21-{}-{}",
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
    std::fs::write(dir.join("index.html"), b"").unwrap();
    std::fs::write(dir.join("safari"), b"").unwrap();
    std::fs::write(dir.join("none"), b"").unwrap();
    std::fs::write(dir.join("time"), b"").unwrap();

    let conf_path = dir.join("ruxen.conf");
    std::fs::write(
        &conf_path,
        format!(
            r#"
events {{ }}
http {{
  server {{
    listen 127.0.0.1:{port};
    root {};
    keepalive_requests 2;
    keepalive_timeout 1 9;

    location /time {{
      keepalive_requests 100;
      keepalive_timeout 75s;
      keepalive_time 1s;
    }}

    location /safari {{
      keepalive_disable safari;
    }}

    location /none {{
      keepalive_disable none;
    }}
  }}
}}
"#,
            dir.display()
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
        let n = stream.read(&mut tmp).unwrap_or(0);
        if n == 0 {
            break;
        }
        out.extend_from_slice(&tmp[..n]);

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
        if let Some((k, v)) = line.split_once(':') {
            if k.eq_ignore_ascii_case(name) {
                return Some(v.trim());
            }
        }
    }
    None
}

#[test]
fn keepalive_disable_matches_nginx_cases() {
    let (_guard, port) = spawn_server();

    // Default policy is msie6-only disable: old MSIE POST closes.
    let mut msie5 = TcpStream::connect(("127.0.0.1", port)).unwrap();
    msie5
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    msie5
        .write_all(b"POST / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: MSIE 5.0\r\n\r\n")
        .unwrap();
    let r1 = read_one_response(&mut msie5);
    assert_eq!(status_line(&r1), "HTTP/1.1 405 Not Allowed");
    assert_eq!(header_value(&r1, "Connection"), Some("close"));

    // Modern MSIE POST should keep-alive.
    let mut msie7 = TcpStream::connect(("127.0.0.1", port)).unwrap();
    msie7
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    msie7
        .write_all(b"POST / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: MSIE 7.0\r\n\r\n")
        .unwrap();
    let r2 = read_one_response(&mut msie7);
    assert_eq!(status_line(&r2), "HTTP/1.1 405 Not Allowed");
    assert_eq!(header_value(&r2, "Connection"), Some("keep-alive"));

    // `keepalive_disable safari;` should close Safari requests.
    let mut safari = TcpStream::connect(("127.0.0.1", port)).unwrap();
    safari
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    safari
        .write_all(
            b"GET /safari HTTP/1.1\r\nHost: localhost\r\nUser-Agent: Mac OS X Safari/7534.48.3\r\n\r\n",
        )
        .unwrap();
    let r3 = read_one_response(&mut safari);
    assert_eq!(status_line(&r3), "HTTP/1.1 200 OK");
    assert_eq!(header_value(&r3, "Connection"), Some("close"));

    // `keepalive_disable none;` should keep old MSIE POST alive.
    let mut none = TcpStream::connect(("127.0.0.1", port)).unwrap();
    none.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    none.write_all(b"POST /none HTTP/1.1\r\nHost: localhost\r\nUser-Agent: MSIE 5.0\r\n\r\n")
        .unwrap();
    let r4 = read_one_response(&mut none);
    assert_eq!(status_line(&r4), "HTTP/1.1 405 Not Allowed");
    assert_eq!(header_value(&r4, "Connection"), Some("keep-alive"));
}

#[test]
fn keepalive_time_closes_after_elapsed_connection_age() {
    let (_guard, port) = spawn_server();
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();

    // Mirrors nginx-tests helper behavior: first request is written,
    // then the client sleeps before reading the response.
    s.write_all(b"GET /time HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .unwrap();
    sleep(Duration::from_millis(1200));
    let first = read_one_response(&mut s);
    assert_eq!(status_line(&first), "HTTP/1.1 200 OK");
    assert_eq!(header_value(&first, "Connection"), Some("keep-alive"));

    s.write_all(b"GET /time HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .unwrap();
    let second = read_one_response(&mut s);
    assert_eq!(status_line(&second), "HTTP/1.1 200 OK");
    assert_eq!(header_value(&second, "Connection"), Some("close"));
}
