//! M106 — `$binary_remote_addr`, `$document_uri` and `$https`, which were
//! empty with a "not supported yet" warning: the client address as 4 (or
//! 16) bytes, `$uri` under its other name, and `on` over TLS only.

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
fn m106_binary_remote_addr_document_uri_https() {
    let dir = std::env::temp_dir().join(format!("ruxen-m106-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let port = {
        let _setup = common::ports::setup_lock();
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    };
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "events {{}}\nhttp {{ server {{ listen 127.0.0.1:{port};\n\
             location / {{ rewrite ^/old(.*)$ /new$1 break;\n\
             return 200 \"[$binary_remote_addr][$document_uri][$https]\"; }}\n\
             }} }}\n"
        ),
    )
    .unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .arg("-t")
        .arg("-c")
        .arg(dir.join("nginx.conf"))
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stderr.contains("not supported yet"), "{stderr}");
    let mut child = Command::new(env!("CARGO_BIN_EXE_ruxen"))
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
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.write_all(b"GET /old/x HTTP/1.0\r\n\r\n").unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    let body = &out[out.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4..];
    assert_eq!(body, b"[\x7f\x00\x00\x01][/new/x][]");
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&dir);
}
