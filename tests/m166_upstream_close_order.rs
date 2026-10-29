//! M166 — a proxied connection that isn't kept is closed after the
//! upstream closes its end (#249), so the TIME_WAIT is the upstream's and
//! not one of ruxen's ephemeral ports. An upstream that never closes is
//! closed anyway, and the client never waits for either.

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use common::ports::setup_lock;

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

/// What the upstream saw of ruxen's end after answering.
#[derive(Debug, PartialEq)]
enum Seen {
    /// ruxen closed within `wait`.
    Closed(Duration),
    /// ruxen still had it open after `wait`.
    Open,
}

/// An upstream answering one request per connection, then watching for
/// ruxen's close for `wait` before closing its own end.
fn spawn_upstream(wait: Duration) -> (u16, mpsc::Receiver<(Seen, Instant)>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for s in listener.incoming().flatten() {
            let tx = tx.clone();
            std::thread::spawn(move || {
                let mut w = s.try_clone().unwrap();
                let mut r = BufReader::new(s);
                loop {
                    let mut line = String::new();
                    if r.read_line(&mut line).unwrap_or(0) == 0 {
                        return;
                    }
                    if line == "\r\n" {
                        break;
                    }
                }
                w.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nok\n")
                    .unwrap();
                let sent = Instant::now();
                r.get_ref().set_read_timeout(Some(wait)).unwrap();
                let seen = match r.read(&mut [0u8; 16]) {
                    Ok(0) => Seen::Closed(sent.elapsed()),
                    _ => Seen::Open,
                };
                let _ = tx.send((seen, Instant::now()));
            });
        }
    });
    (port, rx)
}

fn start(up: u16, name: &str) -> Server {
    let ports = setup_lock();
    let port = {
        let probe = TcpListener::bind("127.0.0.1:0").unwrap();
        probe.local_addr().unwrap().port()
    };
    let dir = std::env::temp_dir().join(format!("ruxen-m166-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "worker_processes 1;\nevents {{}}\nhttp {{ access_log off;\n\
               server {{ listen 127.0.0.1:{port};\n\
                 location / {{ proxy_pass http://127.0.0.1:{up}; }}\n\
             }} }}\n"
        ),
    )
    .unwrap();
    let mut server = Server {
        child: Command::new(env!("CARGO_BIN_EXE_ruxen"))
            .arg("-c")
            .arg(dir.join("nginx.conf"))
            .arg("-g")
            .arg(format!("pid {}/ruxen.pid;", dir.display()))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
        port,
        dir,
    };
    let pid_file = server.dir.join("ruxen.pid");
    common::ports::wait_for_pid_file(&mut server.child, &pid_file, Duration::from_secs(3));
    drop(ports);
    server
}

/// One request on a keep-alive client connection; when its response came.
fn get(s: &mut TcpStream) -> Instant {
    s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
    let mut got = Vec::new();
    let mut buf = [0u8; 1024];
    while !got.ends_with(b"ok\n") {
        let n = s.read(&mut buf).unwrap();
        assert!(n > 0, "closed: {}", String::from_utf8_lossy(&got));
        got.extend_from_slice(&buf[..n]);
    }
    assert!(
        got.starts_with(b"HTTP/1.1 200"),
        "{}",
        String::from_utf8_lossy(&got)
    );
    Instant::now()
}

#[test]
fn ruxen_closes_after_the_upstream() {
    // The upstream closes 100 ms after answering, as if its FIN were late.
    let (up, seen) = spawn_upstream(Duration::from_millis(100));
    let server = start(up, "late");
    let mut client = TcpStream::connect(("127.0.0.1", server.port)).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    for i in 0..5 {
        let answered = get(&mut client);
        let (seen, upstream_closed) = seen.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(seen, Seen::Open, "request {i}: ruxen closed first");
        assert!(answered < upstream_closed, "request {i}: the client waited");
    }
}

#[test]
fn an_upstream_that_keeps_the_connection_is_closed_anyway() {
    let (up, seen) = spawn_upstream(Duration::from_secs(10));
    let server = start(up, "never");
    let mut client = TcpStream::connect(("127.0.0.1", server.port)).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    for i in 0..3 {
        get(&mut client);
        match seen.recv_timeout(Duration::from_secs(15)).unwrap().0 {
            Seen::Closed(after) => {
                assert!(after < Duration::from_secs(5), "request {i}: {after:?}")
            }
            Seen::Open => panic!("request {i}: never closed"),
        }
    }
}
