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
        "ruxen-m33-{}-{}",
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

fn spawn_server<F>(build_server_body: F) -> (ServerGuard, u16)
where
    F: FnOnce(&PathBuf) -> String,
{
    let (port, _lock) = pick_port();
    let dir = unique_dir();
    std::fs::write(dir.join("index.html"), b"ok").unwrap();

    let server_body = build_server_body(&dir);
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
{server_body}
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

#[test]
fn m33_error_log_level_filter_and_multiple_sinks() {
    let (guard, port) = spawn_server(|dir| {
        format!(
            r#"
    location /crit/ {{
      error_log {root}/crit.log crit;
    }}
    location /warn/ {{
      error_log {root}/warn.log warn;
    }}
    location /multi/ {{
      error_log {root}/multi-a.log error;
      error_log {root}/multi-b.log info;
    }}
"#,
            root = dir.display()
        )
    });

    let crit = request(
        port,
        b"GET /crit/missing HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_line(&crit), "HTTP/1.1 404 Not Found");

    let warn = request(
        port,
        b"GET /warn/missing HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_line(&warn), "HTTP/1.1 404 Not Found");

    let multi = request(
        port,
        b"GET /multi/missing HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_line(&multi), "HTTP/1.1 404 Not Found");

    sleep(Duration::from_millis(20));
    let crit_log = std::fs::read_to_string(guard.tempdir.join("crit.log")).unwrap_or_default();
    let warn_log = std::fs::read_to_string(guard.tempdir.join("warn.log")).unwrap_or_default();
    let multi_a = std::fs::read_to_string(guard.tempdir.join("multi-a.log")).unwrap_or_default();
    let multi_b = std::fs::read_to_string(guard.tempdir.join("multi-b.log")).unwrap_or_default();

    assert!(!crit_log.contains("/crit/missing"));
    assert!(warn_log.contains("/warn/missing"));
    assert!(multi_a.contains("/multi/missing"));
    assert!(multi_b.contains("/multi/missing"));
}
