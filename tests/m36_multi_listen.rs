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

fn pick_two_ports() -> (u16, u16, MutexGuard<'static, ()>) {
    let g = SETUP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let l1 = TcpListener::bind("127.0.0.1:0").unwrap();
    let l2 = TcpListener::bind("127.0.0.1:0").unwrap();
    let p1 = l1.local_addr().unwrap().port();
    let p2 = l2.local_addr().unwrap().port();
    drop(l1);
    drop(l2);
    (p1, p2, g)
}

fn unique_dir() -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let d = std::env::temp_dir().join(format!(
        "ruxen-m36-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir(&d).unwrap();
    d
}

fn wait_for_listen(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if TcpListener::bind(("127.0.0.1", port)).is_err() {
            return;
        }
        if Instant::now() > deadline {
            panic!("ruxen did not start listening on port {port}");
        }
        sleep(Duration::from_millis(20));
    }
}

fn spawn_server(conf_body: &str) -> (ServerGuard, u16, u16) {
    let (port1, port2, _lock) = pick_two_ports();
    let dir = unique_dir();

    let conf_path = dir.join("ruxen.conf");
    std::fs::write(
        &conf_path,
        conf_body
            .replace("%%PORT1%%", &port1.to_string())
            .replace("%%PORT2%%", &port2.to_string()),
    )
    .unwrap();

    let child = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .args(["-c", conf_path.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ruxen");

    wait_for_listen(port1);
    wait_for_listen(port2);
    (
        ServerGuard {
            child,
            tempdir: dir,
        },
        port1,
        port2,
    )
}

fn http_get_with_host(port: u16, path: &str, host: &str) -> Vec<u8> {
    let req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
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

fn body(resp: &[u8]) -> &[u8] {
    resp.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| &resp[i + 4..])
        .unwrap_or(&[])
}

#[test]
fn m36_multi_listen_scopes_server_selection_and_server_port() {
    let conf = r#"
events {}
http {
  server {
    listen 127.0.0.1:%%PORT1%%;
    server_name same.example;
    location / { return 200 "L1:$server_port"; }
  }
  server {
    listen 127.0.0.1:%%PORT1%%;
    server_name other.example;
    location / { return 200 "OTHER1:$server_port"; }
  }

  server {
    listen 127.0.0.1:%%PORT2%%;
    server_name same.example;
    location / { return 200 "L2:$server_port"; }
  }
  server {
    listen 127.0.0.1:%%PORT2%%;
    server_name other2.example;
    location / { return 200 "OTHER2:$server_port"; }
  }
}
"#;

    let (_guard, port1, port2) = spawn_server(conf);

    let resp1 = http_get_with_host(port1, "/", "same.example");
    assert_eq!(body(&resp1), format!("L1:{port1}").as_bytes());

    let resp2 = http_get_with_host(port2, "/", "same.example");
    assert_eq!(body(&resp2), format!("L2:{port2}").as_bytes());

    let unknown1 = http_get_with_host(port1, "/", "unknown.example");
    assert_eq!(body(&unknown1), format!("L1:{port1}").as_bytes());

    let unknown2 = http_get_with_host(port2, "/", "unknown.example");
    assert_eq!(body(&unknown2), format!("L2:{port2}").as_bytes());
}
