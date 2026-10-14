//! M124 — `return 444;` closes the connection without a response, as
//! nginx's NGX_HTTP_CLOSE (#397), and logs 444; with text it is an
//! ordinary response with that status.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

/// The server stops when the test ends, also when an assertion panics.
struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn raw(port: u16, path: &str) -> Vec<u8> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut out = Vec::new();
    // A close without a response may come as a reset.
    let _ = s.read_to_end(&mut out);
    out
}

#[test]
fn return_444_closes_without_a_response() {
    let dir = std::env::temp_dir().join(format!("ruxen-m124-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // Held until ruxen listens.
    let setup = common::ports::setup_lock();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let d = dir.display();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "worker_processes 1;\npid {d}/ruxen.pid;\nevents {{}}\nhttp {{\n\
             log_format s '$request_uri $status $bytes_sent';\n\
             access_log {d}/access.log s;\n\
             server {{ listen 127.0.0.1:{port};\n\
             location / {{ return 444; }}\n\
             location /text {{ return 444 \"text\"; }} }} }}\n"
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

    assert_eq!(raw(port, "/"), b"", "a response was sent");
    let text = String::from_utf8(raw(port, "/text")).unwrap();
    assert!(text.starts_with("HTTP/1.1 444 "), "{text}");
    assert!(text.ends_with("\r\n\r\ntext"), "{text}");

    drop(child);
    let log = std::fs::read_to_string(dir.join("access.log")).unwrap();
    let lines: Vec<&str> = log.lines().collect();
    assert_eq!(lines[0], "/ 444 0", "{log}");
    assert!(lines[1].starts_with("/text 444 "), "{log}");
    let _ = std::fs::remove_dir_all(&dir);
}
