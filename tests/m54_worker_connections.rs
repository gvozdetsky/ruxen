//! M54 — `worker_connections` caps one worker's connections (nginx's
//! default 512; each listening socket uses one). Like nginx, when the
//! worker runs out it closes the new connection with an `[alert]`, and it
//! asks idle connections (waiting for a request) to close so later clients
//! get in: idle sockets can't hold the server hostage until they time out.

use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
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

fn start(events: &str) -> Server {
    let port = {
        let probe = TcpListener::bind("127.0.0.1:0").unwrap();
        probe.local_addr().unwrap().port()
    };
    let dir = std::env::temp_dir().join(format!("ruxen-m54-{}-{port}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "events {{ {events} }}\nhttp {{ server {{ listen 127.0.0.1:{port}; \
             location / {{ return 200 \"ok\"; }} }} }}\n"
        ),
    )
    .unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .arg("-c")
        .arg(dir.join("nginx.conf"))
        .arg("-e")
        .arg(dir.join("error.log"))
        .env("RUXEN_WORKERS", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let server = Server { child, port, dir };
    let deadline = Instant::now() + Duration::from_secs(3);
    while get(port).is_none() {
        assert!(Instant::now() < deadline, "ruxen did not start");
        sleep(Duration::from_millis(20));
    }
    server
}

fn get(port: u16) -> Option<String> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .ok()?;
    let mut out = String::new();
    s.read_to_string(&mut out).ok()?;
    out.starts_with("HTTP/1.1 200").then_some(out)
}

/// The server closed `s` (EOF or reset) within `within`.
fn closed(s: &mut TcpStream, within: Duration) -> bool {
    s.set_read_timeout(Some(within)).unwrap();
    let mut buf = [0u8; 64];
    match s.read(&mut buf) {
        Ok(0) => true,
        Ok(_) => false,
        Err(e) => !matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut),
    }
}

#[test]
fn full_worker_rejects_then_reuses_idle_connections() {
    // 4 connections, 1 listening socket: 3 client slots.
    let server = start("worker_connections 4;");
    sleep(Duration::from_millis(100)); // let the startup probe's connection finish
    let mut idle: Vec<TcpStream> = (0..3)
        .map(|_| TcpStream::connect(("127.0.0.1", server.port)).unwrap())
        .collect();
    sleep(Duration::from_millis(200));

    // No slot left: the kernel accepts, ruxen closes it at once.
    let mut extra = TcpStream::connect(("127.0.0.1", server.port)).unwrap();
    assert!(
        closed(&mut extra, Duration::from_secs(1)),
        "4th connection kept open"
    );

    // That also asked an idle connection to make room, within one 50 ms tick.
    sleep(Duration::from_millis(300));
    let reclaimed = idle
        .iter_mut()
        .map(|s| closed(s, Duration::from_millis(50)))
        .filter(|&was_closed| was_closed)
        .count();
    assert!(reclaimed >= 1, "no idle connection was closed to make room");
    assert!(
        get(server.port).is_some(),
        "no room after reusing idle connections"
    );

    let log = std::fs::read_to_string(server.dir.join("error.log")).unwrap_or_default();
    assert!(
        log.contains("[alert]") && log.contains(": 4 worker_connections are not enough"),
        "{log}"
    );
}

#[test]
fn default_allows_many_connections() {
    // nginx's default is 512; 100 idle connections must not be refused.
    let server = start("");
    let mut held: Vec<TcpStream> = (0..100)
        .map(|_| TcpStream::connect(("127.0.0.1", server.port)).unwrap())
        .collect();
    sleep(Duration::from_millis(200));
    assert!(get(server.port).is_some());
    assert!(!closed(&mut held[0], Duration::from_millis(100)));
}
