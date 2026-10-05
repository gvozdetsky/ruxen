//! M70 — an upstream connection that answered `101 Switching Protocols`
//! never goes back to the keep-alive pool: it now speaks another protocol,
//! and a later request from another client written into it would land in
//! the first client's tunnel. nginx sets `u->keepalive = 0` for a 101.

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread::sleep;
use std::time::{Duration, Instant};

/// Read one request head; `None` on EOF.
fn read_head(r: &mut BufReader<TcpStream>) -> Option<String> {
    let mut head = String::new();
    loop {
        let mut line = String::new();
        if r.read_line(&mut line).ok()? == 0 {
            return None;
        }
        head.push_str(&line);
        if line == "\r\n" {
            return Some(head);
        }
    }
}

#[test]
fn a_switched_connection_is_not_reused() {
    let setup = common::ports::setup_lock();
    let backend = TcpListener::bind("127.0.0.1:0").unwrap();
    let backend_port = backend.local_addr().unwrap().port();
    let front = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    // Backend: `/ws` switches protocols and then only listens; anything that
    // arrives on that connection afterwards is a request that leaked into
    // the tunnel. Everything else is a keep-alive 200.
    let leaked = Arc::new(AtomicBool::new(false));
    let connections = Arc::new(AtomicUsize::new(0));
    {
        let leaked = leaked.clone();
        let connections = connections.clone();
        std::thread::spawn(move || {
            for conn in backend.incoming().flatten() {
                connections.fetch_add(1, Ordering::SeqCst);
                let leaked = leaked.clone();
                std::thread::spawn(move || {
                    let mut w = conn.try_clone().unwrap();
                    let mut r = BufReader::new(conn);
                    while let Some(head) = read_head(&mut r) {
                        if head.starts_with("GET /ws ") {
                            let _ = w.write_all(
                                b"HTTP/1.1 101 Switching Protocols\r\n\
                                  Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
                            );
                            let mut byte = [0u8; 1];
                            if matches!(r.read(&mut byte), Ok(n) if n > 0) {
                                leaked.store(true, Ordering::SeqCst);
                            }
                            return;
                        }
                        let _ = w.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nfresh");
                    }
                });
            }
        });
    }

    let dir = std::env::temp_dir().join(format!("ruxen-m70-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "pid {d}/ruxen.pid;\nevents {{}}\nhttp {{\n\
             upstream u {{ server 127.0.0.1:{backend_port}; keepalive 4; }}\n\
             server {{ listen 127.0.0.1:{front};\n\
               location / {{ proxy_pass http://u; proxy_http_version 1.1;\n\
                 proxy_set_header Upgrade $http_upgrade;\n\
                 proxy_set_header Connection upgrade;\n\
                 proxy_read_timeout 1s; }} }}\n\
             }}\n",
            d = dir.display()
        ),
    )
    .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .arg("-c")
        .arg(dir.join("nginx.conf"))
        .env("RUXEN_WORKERS", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    while !dir.join("ruxen.pid").exists() {
        assert!(
            Instant::now() < deadline && child.try_wait().unwrap().is_none(),
            "ruxen did not start"
        );
        sleep(Duration::from_millis(10));
    }
    drop(setup);

    // First client: the upstream switches protocols.
    let mut first = TcpStream::connect(("127.0.0.1", front)).unwrap();
    first
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    first
        .write_all(
            b"GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
        )
        .unwrap();
    let mut buf = [0u8; 1024];
    let n = first.read(&mut buf).unwrap_or(0);
    assert!(
        String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 101"),
        "{}",
        String::from_utf8_lossy(&buf[..n])
    );

    // Second client: its request must go to a new upstream connection.
    let mut second = TcpStream::connect(("127.0.0.1", front)).unwrap();
    second
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    second
        .write_all(b"GET /next HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut resp = String::new();
    let _ = second.read_to_string(&mut resp);
    sleep(Duration::from_millis(100));
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        !leaked.load(Ordering::SeqCst),
        "the second request was written into the switched connection"
    );
    assert!(resp.ends_with("fresh"), "{resp}");
    assert_eq!(connections.load(Ordering::SeqCst), 2);
}
