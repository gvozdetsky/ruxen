//! M107 — `client_body_timeout` and `send_timeout` of the server and
//! location a request is routed to (#147), not only of the address's
//! default server: a stalled body under a name-based server's or a
//! location's 1 s timeout is cut after a second, while the default server
//! keeps its 60 s.

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
    let dir = std::env::temp_dir().join(format!("ruxen-m107-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("html")).unwrap();
    std::fs::write(dir.join("html/big"), vec![b'x'; 32 << 20]).unwrap();
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
            "events {{}}\nhttp {{ access_log off; root {d}/html;\n\
             server {{ listen 127.0.0.1:{port}; server_name default; location / {{ return 200; }} }}\n\
             server {{ listen 127.0.0.1:{port}; server_name vhost; client_body_timeout 1s;\n\
               location / {{ return 200; }} }}\n\
             server {{ listen 127.0.0.1:{port}; server_name loc;\n\
               location / {{ client_body_timeout 1s; return 200; }}\n\
               location /big {{ send_timeout 1s; }} }}\n\
             }}\n"
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

/// Send 2 of 10 body bytes and stall; how long until the server closes.
fn stalled_body(port: u16, host: &str) -> Duration {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(4))).unwrap();
    write!(
        s,
        "POST / HTTP/1.1\r\nHost: {host}\r\nContent-Length: 10\r\n\r\nab"
    )
    .unwrap();
    let start = Instant::now();
    let mut buf = [0u8; 64];
    let _ = s.read(&mut buf);
    start.elapsed()
}

#[test]
fn m107_body_timeout_of_the_routed_server_and_location() {
    let (_server, port) = start();
    for host in ["vhost", "loc"] {
        let waited = stalled_body(port, host);
        assert!(
            waited >= Duration::from_millis(900) && waited < Duration::from_millis(2500),
            "{host}: {waited:?}"
        );
    }
    // The default server's 60 s: still open after the 4 s read timeout.
    assert!(stalled_body(port, "default") >= Duration::from_secs(4));
}

#[test]
fn m107_send_timeout_of_the_location() {
    let (_server, port) = start();
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    // A small receive buffer, and nothing read: the server's writes stall.
    write!(s, "GET /big HTTP/1.1\r\nHost: loc\r\n\r\n").unwrap();
    std::thread::sleep(Duration::from_millis(2500));
    // The connection was closed after the location's 1 s: reading drains
    // what was in flight, then EOF well short of 32 MiB.
    s.set_read_timeout(Some(Duration::from_secs(4))).unwrap();
    let mut total = 0usize;
    let mut buf = vec![0u8; 1 << 16];
    loop {
        match s.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(e) => panic!("still open after {total} bytes: {e}"),
        }
    }
    assert!(total < 32 << 20, "{total}");
}
