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
        "ruxen-m35-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir(&d).unwrap();
    d
}

fn spawn_server(conf_body: &str, workers: usize) -> (ServerGuard, u16) {
    let (port, _lock) = pick_port();
    let dir = unique_dir();
    std::fs::write(dir.join("index.one.html"), b"first").unwrap();
    std::fs::write(dir.join("index.two.html"), b"second").unwrap();
    std::fs::write(dir.join("index.three.html"), b"third").unwrap();

    let conf_path = dir.join("ruxen.conf");
    std::fs::write(
        &conf_path,
        conf_body
            .replace("%%PORT%%", &port.to_string())
            .replace("%%DIR%%", dir.to_str().unwrap()),
    )
    .unwrap();

    let pid_file = dir.join("ruxen.pid");
    let child = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .args(["-c", conf_path.to_str().unwrap()])
        .arg("-g")
        .arg(format!("pid {};", pid_file.display()))
        .env("RUXEN_WORKERS", workers.to_string())
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

fn body(resp: &[u8]) -> &[u8] {
    resp.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| &resp[i + 4..])
        .unwrap_or(&[])
}

#[test]
fn split_clients_connection_distribution_is_stable_with_multi_workers() {
    let conf = r#"
events {}
http {
  split_clients $connection $variant {
    51.2%  ".one";
    10%    ".two";
    *      ".three";
  }

  server {
    listen 127.0.0.1:%%PORT%%;
    root %%DIR%%;
    location / {
      index index${variant}.html;
    }
  }
}
"#;

    let (_guard, port) = spawn_server(conf, 2);

    let mut first = 0;
    let mut second = 0;
    let mut third = 0;

    for _ in 0..20 {
        let resp = http_get(port, "/");
        match body(&resp) {
            b"first" => first += 1,
            b"second" => second += 1,
            b"third" => third += 1,
            other => panic!("unexpected body: {:?}", String::from_utf8_lossy(other)),
        }
    }

    assert_eq!((first, second, third), (12, 2, 6));
}
