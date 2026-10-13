//! M109 — `limit_req_zone` / `limit_req` (#94): nginx's leaky bucket on a
//! zone shared by all workers. A burst passes, the next request gets
//! `limit_req_status` and an error-log line, `$limit_req_status` says
//! which, a request within the burst without `nodelay` is held, and a zone
//! nobody declares fails at startup.

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Server(Child, std::path::PathBuf);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
        let _ = std::fs::remove_dir_all(&self.1);
    }
}

fn start() -> (Server, u16) {
    let dir = std::env::temp_dir().join(format!("ruxen-m109-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("html")).unwrap();
    std::fs::write(dir.join("html/index.html"), "hi").unwrap();
    let _setup = common::ports::setup_lock();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let d = dir.display();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "worker_processes 4;\nerror_log {d}/error.log warn;\nevents {{}}\nhttp {{ access_log off;\n\
             limit_req_zone $binary_remote_addr zone=one:1m rate=1r/m;\n\
             limit_req_zone $arg_k zone=two:1m rate=2r/s;\n\
             server {{ listen 127.0.0.1:{port}; root {d}/html;\n\
             add_header X-Status $limit_req_status always;\n\
             location / {{ limit_req zone=one burst=2 nodelay; limit_req_status 429; }}\n\
             location /slow/ {{ limit_req zone=two burst=5; alias {d}/html/; }}\n\
             }} }}\n"
        ),
    )
    .unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .arg("-c")
        .arg(dir.join("nginx.conf"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "ruxen did not start");
        std::thread::sleep(Duration::from_millis(20));
    }
    (Server(child, dir), port)
}

/// Status code and `X-Status` of one request, each on a new connection (so
/// they land on different workers).
fn get(port: u16, path: &str) -> (u16, String) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(s, "GET {path} HTTP/1.0\r\n\r\n").unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    let status = out[9..12].parse().unwrap();
    let x = out
        .lines()
        .find_map(|l| l.strip_prefix("X-Status: "))
        .unwrap_or("")
        .to_string();
    (status, x)
}

#[test]
fn m109_burst_reject_and_delay() {
    let (server, port) = start();
    // One address, four workers, one shared bucket: 1 + burst 2, then 429.
    let got: Vec<(u16, String)> = (0..5).map(|_| get(port, "/")).collect();
    assert_eq!(
        got,
        [
            (200, "PASSED".into()),
            (200, "PASSED".into()),
            (200, "PASSED".into()),
            (429, "REJECTED".into()),
            (429, "REJECTED".into())
        ]
    );
    // 2 r/s with a burst and no nodelay: the second request waits ~0.5 s.
    let first = Instant::now();
    assert_eq!(get(port, "/slow/?k=a"), (200, "PASSED".into()));
    assert!(first.elapsed() < Duration::from_millis(300));
    let second = Instant::now();
    assert_eq!(get(port, "/slow/?k=a"), (200, "DELAYED".into()));
    let waited = second.elapsed();
    assert!(
        waited >= Duration::from_millis(400) && waited < Duration::from_millis(900),
        "{waited:?}"
    );
    let log = std::fs::read_to_string(server.1.join("error.log")).unwrap();
    assert!(
        // 1 + burst 2 used up at 1 r/m: 3 requests' worth over.
        log.contains("[error] ") && log.contains(" limiting requests, excess: 3.000 by zone"),
        "{log}"
    );
    assert!(
        log.contains(" by zone \"one\", client: 127.0.0.1,"),
        "{log}"
    );
    assert!(
        log.contains("[warn] ")
            && log.contains(" delaying request, excess: ")
            && log.contains(", by zone \"two\", client: 127.0.0.1,"),
        "{log}"
    );
}

#[test]
fn m109_undeclared_zone_fails_at_startup() {
    let dir = std::env::temp_dir().join(format!("ruxen-m109-bad-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("nginx.conf"),
        "events {}\nhttp { server { listen 127.0.0.1:18109;\n\
         location / { limit_req zone=nope; } } }\n",
    )
    .unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .arg("-t")
        .arg("-c")
        .arg(dir.join("nginx.conf"))
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{stderr}");
    assert!(
        stderr.contains("zero size shared memory zone \"nope\""),
        "{stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
