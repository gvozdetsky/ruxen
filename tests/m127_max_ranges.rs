//! M127 — `max_ranges 0` turns byte ranges off for static files (#370):
//! nginx's range filter declines (ngx_http_range_header_filter), so a
//! `Range` gets the whole file as a 200 and there is no `Accept-Ranges`.
//! The setting is inherited from the server into nested locations.

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

fn request(port: u16, method: &str, path: &str, range: Option<&str>) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let range = range.map(|r| format!("Range: {r}\r\n")).unwrap_or_default();
    write!(
        s,
        "{method} {path} HTTP/1.1\r\nHost: x\r\n{range}Connection: close\r\n\r\n"
    )
    .unwrap();
    let mut out = Vec::new();
    s.read_to_end(&mut out).unwrap();
    String::from_utf8(out).unwrap()
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[test]
fn max_ranges_0_serves_static_files_whole_without_accept_ranges() {
    let dir = std::env::temp_dir().join(format!("ruxen-m127-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    for sub in ["off", "on", "srv"] {
        std::fs::create_dir_all(dir.join("html").join(sub)).unwrap();
        std::fs::write(dir.join("html").join(sub).join("f.txt"), b"abcdefghij").unwrap();
    }
    // Held until ruxen listens.
    let setup = common::ports::setup_lock();
    let (port, port_srv) = (free_port(), free_port());
    let d = dir.display();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "worker_processes 1;\npid {d}/ruxen.pid;\nevents {{}}\nhttp {{\n\
             server {{ listen 127.0.0.1:{port}; root {d}/html;\n\
             location /off/ {{ max_ranges 0; }}\n\
             location /on/ {{ }} }}\n\
             server {{ listen 127.0.0.1:{port_srv}; root {d}/html; max_ranges 0;\n\
             location /srv/ {{ location /srv/f {{ }} }} }} }}\n"
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

    let whole = |port: u16, method: &str, path: &str, range: Option<&str>| {
        let r = request(port, method, path, range);
        assert!(r.starts_with("HTTP/1.1 200 OK\r\n"), "{range:?}: {r}");
        assert!(r.contains("\r\nContent-Length: 10\r\n"), "{range:?}: {r}");
        assert!(!r.contains("Accept-Ranges"), "{range:?}: {r}");
        assert!(!r.contains("Content-Range"), "{range:?}: {r}");
        let body = if method == "HEAD" { "" } else { "abcdefghij" };
        assert!(r.ends_with(&format!("\r\n\r\n{body}")), "{range:?}: {r}");
    };
    for range in [
        None,
        Some("bytes=0-1"),
        Some("bytes=100-"),
        Some("bytes=0-1,3-4"),
    ] {
        whole(port, "GET", "/off/f.txt", range);
    }
    whole(port, "HEAD", "/off/f.txt", Some("bytes=0-1"));
    // Set on the server: its locations and their nested ones have it.
    whole(port_srv, "GET", "/srv/f.txt", Some("bytes=0-1"));
    whole(port_srv, "GET", "/srv/f.txt", None);

    // Without it, ranges as before.
    let r = request(port, "GET", "/on/f.txt", Some("bytes=0-1"));
    assert!(r.starts_with("HTTP/1.1 206 "), "{r}");
    assert!(r.contains("\r\nContent-Range: bytes 0-1/10\r\n"), "{r}");
    assert!(r.ends_with("\r\n\r\nab"), "{r}");
    let r = request(port, "GET", "/on/f.txt", None);
    assert!(r.contains("\r\nAccept-Ranges: bytes\r\n"), "{r}");

    drop(child);
    let _ = std::fs::remove_dir_all(&dir);
}
