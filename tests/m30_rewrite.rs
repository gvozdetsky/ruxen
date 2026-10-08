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
        "ruxen-m30-{}-{}",
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

fn spawn_server(conf_body: &str) -> (ServerGuard, u16) {
    let (port, _lock) = pick_port();
    let dir = unique_dir();
    let conf_path = dir.join("ruxen.conf");
    std::fs::write(
        &conf_path,
        conf_body
            .replace("%%PORT%%", &port.to_string())
            .replace("%%DIR%%", dir.to_str().unwrap()),
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

fn http_get(port: u16, path: &str) -> Vec<u8> {
    let req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    s.write_all(req.as_bytes()).unwrap();
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
    let end = resp.windows(4).position(|w| w == b"\r\n\r\n")?;
    let mut i = 0;
    let headers = &resp[..end];
    while i < headers.len() {
        let line_end = headers[i..]
            .windows(2)
            .position(|w| w == b"\r\n")
            .map(|p| i + p)
            .unwrap_or(headers.len());
        let line = &headers[i..line_end];
        if let Some(colon) = line.iter().position(|&b| b == b':') {
            let (n, v) = line.split_at(colon);
            if n.eq_ignore_ascii_case(name.as_bytes()) {
                let mut v = &v[1..];
                while let Some((&b, rest)) = v.split_first() {
                    if b != b' ' && b != b'\t' {
                        break;
                    }
                    v = rest;
                }
                return std::str::from_utf8(v).ok();
            }
        }
        i = line_end + 2;
    }
    None
}

fn body(resp: &[u8]) -> &[u8] {
    resp.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| &resp[i + 4..])
        .unwrap_or(&[])
}

#[test]
fn rewrite_redirect_last_and_location_captures_work() {
    let conf = r#"
events {}
http {
  server {
    listen 127.0.0.1:%%PORT%%;

    location /t1 {
      rewrite ^ $arg_r? redirect;
    }

    location /from {
      rewrite ^ /to last;
      return 200 "from";
    }

    location /to {
      return 200 "to";
    }

    location ~ ^/cap/(.*)$ {
      set $x $1;
      return 200 "$x";
    }
  }
}
"#;

    let (_guard, port) = spawn_server(conf);

    let escaped = http_get(port, "/t1?r=http%3A%2F%2Fexample.com%2F%3Ffrom");
    assert_eq!(status_line(&escaped), "HTTP/1.1 302 Moved Temporarily");
    assert_eq!(
        header_value(&escaped, "Location"),
        Some("http://example.com/?from")
    );

    let split = http_get(port, "/t1?r=http%3A%2F%2Fexample.com%0D%0Asplit");
    assert_eq!(status_line(&split), "HTTP/1.1 302 Moved Temporarily");
    assert_eq!(
        header_value(&split, "Location"),
        Some("http://example.com%0D%0Asplit")
    );

    let rerouted = http_get(port, "/from");
    assert_eq!(status_line(&rerouted), "HTTP/1.1 200 OK");
    assert_eq!(body(&rerouted), b"to");

    let captured = http_get(port, "/cap/value");
    assert_eq!(status_line(&captured), "HTTP/1.1 200 OK");
    assert_eq!(body(&captured), b"value");
}
