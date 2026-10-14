//! M98 — `client_body_buffer_size` (#246): a request body up to it stays
//! in memory (no `$request_body_file`), a larger one goes to a temp file,
//! as nginx's `ngx_http_write_request_body` does once the buffer is full.

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

struct Server(Child, std::path::PathBuf);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
        let _ = std::fs::remove_dir_all(&self.1);
    }
}

fn start() -> (Server, u16) {
    let dir = std::env::temp_dir().join(format!("ruxen-m98-{}", std::process::id()));
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
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "events {{}}\nhttp {{ server {{ listen 127.0.0.1:{port};\n\
             location / {{ return 200 \"[$request_body_file]\"; }}\n\
             location /small {{ client_body_buffer_size 1k; return 200 \"[$request_body_file]\"; }}\n\
             }} }}\n"
        ),
    )
    .unwrap();
    // Owned by `Server` before the wait: if it panics, ruxen still stops.
    let mut server = Server(
        Command::new(env!("CARGO_BIN_EXE_ruxen"))
            .arg("-c")
            .arg(dir.join("nginx.conf"))
            .arg("-g")
            .arg(format!("pid {}/ruxen.pid;", dir.display()))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
        dir,
    );
    let pid_file = server.1.join("ruxen.pid");
    common::ports::wait_for_pid_file(&mut server.0, &pid_file, Duration::from_secs(5));
    drop(setup);
    (server, port)
}

/// POSTs `len` bytes to `path`; returns `$request_body_file` as rendered.
fn body_file(port: u16, path: &str, len: usize) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(
        s,
        "POST {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Length: {len}\r\n\r\n"
    )
    .unwrap();
    s.write_all(&vec![b'x'; len]).unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    assert!(out.starts_with("HTTP/1.1 200"), "{out}");
    let body = out.split_once("\r\n\r\n").unwrap().1;
    body.trim_start_matches('[')
        .trim_end_matches(']')
        .to_string()
}

#[test]
fn m98_body_goes_to_a_file_only_past_the_buffer() {
    let (_server, port) = start();
    // nginx's default, 16k: 4 KiB and exactly 16 KiB stay in memory.
    assert_eq!(body_file(port, "/", 4096), "");
    assert_eq!(body_file(port, "/", 16 * 1024), "");
    assert!(!body_file(port, "/", 16 * 1024 + 1).is_empty());
    // A location's own size.
    assert_eq!(body_file(port, "/small", 1024), "");
    assert!(!body_file(port, "/small", 4096).is_empty());
}
