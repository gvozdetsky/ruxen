//! M159 — a request whose head never completes is logged, as nginx does
//! (#509): no response, an `[info]` line in the error log, and an
//! access-log line with 408 when `client_header_timeout` passes, 400 when
//! the client closes; `$request` as far as it came, `$request_length` the
//! complete lines. A connection that sends nothing isn't a request and
//! isn't logged.

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Server(Child, PathBuf);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
        let _ = std::fs::remove_dir_all(&self.1);
    }
}

fn start() -> (Server, u16) {
    let dir = std::env::temp_dir().join(format!("ruxen-m159-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // Held until ruxen listens: released earlier, another test could take
    // the same free port, and ruxen would fail to bind it.
    let setup = common::ports::setup_lock();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let d = dir.display();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "error_log {d}/error.log info;\n\
             events {{}}\nhttp {{\n\
             log_format t '\"$request\" $status $request_length $bytes_sent';\n\
             access_log {d}/access.log t;\n\
             client_header_timeout 1s;\n\
             server {{ listen 127.0.0.1:{port}; location / {{ return 200 ok; }} }}\n\
             }}\n"
        ),
    )
    .unwrap();
    // Owned by `Server` before the wait: if it panics, ruxen still stops.
    let mut server = Server(
        Command::new(env!("CARGO_BIN_EXE_ruxen"))
            .arg("-c")
            .arg(dir.join("nginx.conf"))
            .arg("-g")
            .arg(format!("pid {d}/ruxen.pid;"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
        dir.clone(),
    );
    common::ports::wait_for_pid_file(
        &mut server.0,
        &dir.join("ruxen.pid"),
        Duration::from_secs(5),
    );
    drop(setup);
    (server, port)
}

/// Send `data`, then wait for the server to close (`hang_up`: close first),
/// and return what came back.
fn send(port: u16, data: &[u8], hang_up: bool) -> Vec<u8> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(data).unwrap();
    // Two reads: the second is the server's, not the first's.
    std::thread::sleep(Duration::from_millis(100));
    let mut out = Vec::new();
    if hang_up {
        return out;
    }
    let started = Instant::now();
    let _ = s.read_to_end(&mut out);
    assert!(started.elapsed() < Duration::from_secs(4), "still open");
    out
}

#[test]
fn m159_a_head_cut_short_is_logged() {
    let (server, port) = start();
    std::thread::scope(|scope| {
        scope.spawn(|| assert!(send(port, b"GET / HTTP/1.1\r\nHost: x\r\n", false).is_empty()));
        scope.spawn(|| assert!(send(port, b"G", false).is_empty()));
        scope.spawn(|| assert!(send(port, b"", false).is_empty()));
        scope.spawn(|| send(port, b"GET /c HTTP/1.1\r\nHost: x\r\n", true));
    });
    let read = |name: &str, count: usize| {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let text = std::fs::read_to_string(server.1.join(name)).unwrap_or_default();
            if text.lines().count() >= count || Instant::now() > deadline {
                let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
                lines.sort();
                return lines;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    };
    assert_eq!(
        read("access.log", 3),
        [
            "\"G\" 408 0 0",
            "\"GET / HTTP/1.1\" 408 25 0",
            "\"GET /c HTTP/1.1\" 400 26 0",
        ]
    );
    let errors: Vec<String> = read("error.log", 0)
        .into_iter()
        .filter(|l| l.contains("[info]"))
        .map(|l| l[l.find(" client").unwrap() + 1..].to_string())
        .collect();
    let mut errors = errors;
    errors.sort();
    assert_eq!(
        errors,
        [
            "client prematurely closed connection while reading client request headers, \
             client: 127.0.0.1, server: , request: \"GET /c HTTP/1.1\", host: \"x\"",
            "client timed out (110: Connection timed out) while reading client request headers, \
             client: 127.0.0.1, server: , request: \"GET / HTTP/1.1\", host: \"x\"",
            "client timed out (110: Connection timed out) while reading client request line, \
             client: 127.0.0.1, server: , request: \"G\"",
        ]
    );
}
