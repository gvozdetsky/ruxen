//! M123 — `gzip on` doesn't stop a proxied body from being relayed as it
//! comes (#88) when gzip wouldn't compress it anyway: server-sent events
//! (`text/event-stream` isn't a `gzip_types` default) go to the client
//! event by event, as through nginx. A response gzip does compress still
//! arrives compressed.

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

/// The server stops when the test ends, also when an assertion panics.
struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn events_are_relayed_as_they_come_with_gzip_on() {
    let dir = std::env::temp_dir().join(format!("ruxen-m123-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // The backend: the head and a first event, then the rest only once the
    // test has seen that event through ruxen.
    let backend = TcpListener::bind("127.0.0.1:0").unwrap();
    let up = backend.local_addr().unwrap().port();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    std::thread::spawn(move || {
        for conn in backend.incoming().take(2) {
            let mut c = conn.unwrap();
            let mut req = [0u8; 4096];
            let n = c.read(&mut req).unwrap();
            if req[..n].starts_with(b"GET /html") {
                let body = "<html>".to_string() + &"hello world ".repeat(500) + "</html>";
                write!(
                    c,
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                )
                .unwrap();
                continue;
            }
            c.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\
                  Transfer-Encoding: chunked\r\n\r\n8\r\ndata: 1\n\r\n",
            )
            .unwrap();
            let _ = release_rx.recv_timeout(Duration::from_secs(10));
            c.write_all(b"8\r\ndata: 2\n\r\n0\r\n\r\n").unwrap();
        }
    });

    // Held until ruxen listens.
    let setup = common::ports::setup_lock();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "worker_processes 1;\npid {d}/ruxen.pid;\nevents {{}}\nhttp {{\naccess_log off;\n\
             gzip on;\n\
             server {{ listen 127.0.0.1:{port};\n\
             location / {{ proxy_pass http://127.0.0.1:{up}; proxy_http_version 1.1; }} }} }}\n",
            d = dir.display()
        ),
    )
    .unwrap();
    let mut child = KillOnDrop(
        Command::new(env!("CARGO_BIN_EXE_ruxen"))
            .arg("-c")
            .arg(dir.join("nginx.conf"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    common::ports::wait_for_pid_file(&mut child.0, &dir.join("ruxen.pid"), Duration::from_secs(5));
    drop(setup);

    // The first event arrives while the upstream still holds the rest.
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(
        b"GET /events HTTP/1.1\r\nHost: x\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n",
    )
    .unwrap();
    let mut reader = BufReader::new(s);
    let mut seen = String::new();
    loop {
        let mut line = String::new();
        assert!(
            reader.read_line(&mut line).unwrap() > 0,
            "closed before the first event: {seen}"
        );
        seen.push_str(&line);
        if line == "data: 1\n" {
            break;
        }
    }
    assert!(!seen.contains("Content-Encoding"), "{seen}");
    release_tx.send(()).unwrap();
    let mut rest = String::new();
    reader.read_to_string(&mut rest).unwrap();
    assert!(rest.contains("data: 2\n"), "{rest}");

    // A type gzip compresses: still compressed.
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(
        b"GET /html HTTP/1.1\r\nHost: x\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n",
    )
    .unwrap();
    let mut out = Vec::new();
    s.read_to_end(&mut out).unwrap();
    let head =
        String::from_utf8_lossy(&out[..out.windows(4).position(|w| w == b"\r\n\r\n").unwrap()]);
    assert!(head.contains("Content-Encoding: gzip"), "{head}");
    let _ = std::fs::remove_dir_all(&dir);
}
