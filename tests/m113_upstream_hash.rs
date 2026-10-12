//! M113 — `hash` and `ip_hash` (#97): one key, or one client /24, always
//! reaches the same server; an empty key is round-robin. A retry that
//! finds no live server answers 502 and shows the group in
//! `$upstream_addr`, as nginx.

mod common;

use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
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

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn start() -> (Server, u16, [u16; 3]) {
    let dir = std::env::temp_dir().join(format!("ruxen-m113-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let _setup = common::ports::setup_lock();
    let port = free_port();
    let b = [free_port(), free_port(), free_port()];
    let refused = free_port();
    let servers = || {
        b.iter()
            .map(|p| format!("server 127.0.0.1:{p};"))
            .collect::<String>()
    };
    let d = dir.display();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "worker_processes 1;\nerror_log {d}/error.log info;\nevents {{}}\nhttp {{ access_log off;\n\
             upstream h {{ hash $arg_k; {s} }}\n\
             upstream c {{ hash $arg_k consistent; {s} }}\n\
             upstream i {{ ip_hash; {s} }}\n\
             upstream n {{ server 127.0.0.1:{b0}; server 127.0.0.1:{refused}; }}\n\
             server {{ listen 127.0.0.1:{port};\n\
             set_real_ip_from 127.0.0.1; real_ip_header X-Real-IP;\n\
             location /h {{ proxy_pass http://h; }}\n\
             location /c {{ proxy_pass http://c; }}\n\
             location /i {{ proxy_pass http://i; }}\n\
             location /n {{ proxy_pass http://n; proxy_next_upstream error http_404;\n\
               add_header X-A $upstream_addr always; }}\n\
             }}\n\
             server {{ listen 127.0.0.1:{b0}; listen 127.0.0.1:{b1}; listen 127.0.0.1:{b2};\n\
               location /n {{ return 404; }}\n\
               location / {{ return 200 $server_port; }} }}\n\
             }}\n",
            s = servers(),
            b0 = b[0],
            b1 = b[1],
            b2 = b[2],
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
    (Server(child, dir), port, b)
}

fn get(port: u16, path: &str, real_ip: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(s, "GET {path} HTTP/1.0\r\nX-Real-IP: {real_ip}\r\n\r\n").unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

fn body(response: &str) -> String {
    response
        .split_once("\r\n\r\n")
        .map_or("", |(_, b)| b)
        .to_string()
}

#[test]
fn m113_upstream_hash() {
    let (_server, port, b) = start();
    for kind in ["h", "c"] {
        // One key, one server; different keys spread.
        let mut seen = HashSet::new();
        for k in 0..30 {
            let first = body(&get(port, &format!("/{kind}?k={k}"), "1.1.1.1"));
            for _ in 0..3 {
                assert_eq!(
                    body(&get(port, &format!("/{kind}?k={k}"), "1.1.1.1")),
                    first
                );
            }
            seen.insert(first);
        }
        assert!(seen.len() > 1, "{kind}: {seen:?}");
        // An empty key: round-robin over all three.
        let rr: HashSet<String> = (0..3)
            .map(|_| body(&get(port, &format!("/{kind}"), "1.1.1.1")))
            .collect();
        assert_eq!(rr.len(), 3, "{kind}: {rr:?}");
    }
    // ip_hash: the /24 decides.
    let mut seen = HashSet::new();
    for net in 0..30 {
        let first = body(&get(port, "/i", &format!("10.0.{net}.1")));
        assert_eq!(body(&get(port, "/i", &format!("10.0.{net}.200"))), first);
        seen.insert(first);
    }
    assert!(seen.len() > 1, "{seen:?}");

    // The first request marks the refused server failed; the second's
    // retry finds no live server.
    let first = get(port, "/n", "1.1.1.1");
    assert!(first.starts_with("HTTP/1.1 502"), "{first}");
    let second = get(port, "/n", "1.1.1.1");
    assert!(second.starts_with("HTTP/1.1 502"), "{second}");
    assert!(
        second.contains(&format!("X-A: 127.0.0.1:{}, n\r\n", b[0])),
        "{second}"
    );
}
