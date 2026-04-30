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
        "ruxen-m22-{}-{}",
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

fn spawn_server(conf_body: &str) -> (ServerGuard, u16, PathBuf) {
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
            tempdir: dir.clone(),
        },
        port,
        dir,
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

#[test]
fn access_log_if_and_sent_http_variables_are_emitted() {
    let conf = r#"
events {}
http {
  log_format test1 $sent_http_connection;
  log_format test2 $sent_http_keep_alive;
  access_log %%DIR%%/test1.log test1 if=$arg_l;
  access_log %%DIR%%/test2.log test2 if=$arg_l;

  server {
    listen 127.0.0.1:%%PORT%%;
    keepalive_requests 2;
    keepalive_timeout 1 9;
    location / { return 200 ""; }
  }
}
"#;
    let (_guard, port, dir) = spawn_server(conf);
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();

    s.write_all(b"GET /?l=ok HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .unwrap();
    let _ = read_one_response(&mut s);

    s.write_all(b"GET /?l=ok HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .unwrap();
    let _ = read_one_response(&mut s);

    // Give the worker a moment to flush append writes.
    sleep(Duration::from_millis(50));

    let c1 = std::fs::read_to_string(dir.join("test1.log")).unwrap();
    let c2 = std::fs::read_to_string(dir.join("test2.log")).unwrap();
    assert_eq!(c1, "keep-alive\nclose\n");
    assert_eq!(c2, "timeout=9\n-\n");
}

#[test]
fn bare_access_log_uses_minimal_combined_fallback() {
    let conf = r#"
events {}
http {
  access_log %%DIR%%/access.log;
  server {
    listen 127.0.0.1:%%PORT%%;
    location / { return 200 ""; }
  }
}
"#;
    let (_guard, port, dir) = spawn_server(conf);
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    s.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    let _ = read_one_response(&mut s);
    sleep(Duration::from_millis(30));

    let access = std::fs::read_to_string(dir.join("access.log")).unwrap();
    assert!(access.contains("\"GET /\" 200 0"));
}
