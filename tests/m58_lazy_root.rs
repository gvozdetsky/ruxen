//! M58 — like nginx, a `root` that doesn't exist yet doesn't stop the
//! server: requests get 404 until the directory appears, then it's served.
//! A location without `root`, `alias`, `return` or `proxy_pass` uses
//! nginx's default `root html` (relative to the prefix, ruxen's working
//! directory). Both used to be startup errors.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

struct Server {
    child: Child,
    port: u16,
    dir: PathBuf,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn start(tag: &str, http_body: &str) -> Server {
    start_with_workers(tag, http_body, 1)
}

fn start_with_workers(tag: &str, http_body: &str, workers: usize) -> Server {
    let port = {
        let probe = TcpListener::bind("127.0.0.1:0").unwrap();
        probe.local_addr().unwrap().port()
    };
    let dir = std::env::temp_dir().join(format!("ruxen-m58-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "events {{}}\nhttp {{ {} }}\n",
            http_body
                .replace("%%PORT%%", &port.to_string())
                .replace("%%DIR%%", dir.to_str().unwrap())
        ),
    )
    .unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .arg("-p")
        .arg(&dir)
        .arg("-c")
        .arg(dir.join("nginx.conf"))
        .arg("-e")
        .arg(dir.join("error.log"))
        .env("RUXEN_WORKERS", workers.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "ruxen did not start");
        sleep(Duration::from_millis(20));
    }
    Server { child, port, dir }
}

fn get(port: u16, path: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

fn put_file(path: &Path, body: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, body).unwrap();
}

#[test]
fn missing_root_is_404_until_it_appears() {
    let server = start(
        "missing",
        "server { listen 127.0.0.1:%%PORT%%; location / { root %%DIR%%/later; } }",
    );
    let resp = get(server.port, "/a.txt");
    assert!(resp.starts_with("HTTP/1.1 404"), "{resp}");

    put_file(&server.dir.join("later/a.txt"), "here");
    let resp = get(server.port, "/a.txt");
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
    assert!(resp.ends_with("here"), "{resp}");
}

#[test]
fn location_without_handler_serves_default_html_root() {
    let server = start(
        "default",
        "server { listen 127.0.0.1:%%PORT%%; location / { } }",
    );
    // No html/ yet: 404, not a startup failure.
    assert!(get(server.port, "/").starts_with("HTTP/1.1 404"));

    put_file(&server.dir.join("html/index.html"), "default root");
    let resp = get(server.port, "/");
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
    assert!(resp.ends_with("default root"), "{resp}");
}

/// Each worker has its own fd table, so a root opened after startup must
/// be opened by every worker that serves from it. It used to be opened
/// once and its fd number shared, which other workers resolved in their
/// own tables (an unrelated fd: 403s, or files from another directory).
#[test]
fn late_root_is_served_by_every_worker() {
    let server = start_with_workers(
        "workers",
        "server { listen 127.0.0.1:%%PORT%%; location / { root %%DIR%%/later; } }",
        4,
    );
    // Open some fds in every worker first so fd numbers differ.
    for _ in 0..16 {
        assert!(get(server.port, "/a.txt").starts_with("HTTP/1.1 404"));
    }
    put_file(&server.dir.join("later/a.txt"), "here");
    for i in 0..64 {
        let resp = get(server.port, "/a.txt");
        assert!(
            resp.starts_with("HTTP/1.1 200") && resp.ends_with("here"),
            "request {i}: {resp}"
        );
    }
}
