//! M148 — request heads over the usual 8 KiB buffer (#482), as nginx's
//! `large_client_header_buffers` (default `4 8k`): each line up to `size`,
//! the head up to `size × number`. A longer request line is a 414, a longer
//! header line or head a 400 "Request Header Or Cookie Too Large"; both are
//! logged at `info`. Big cookies within the limits are served, and the
//! connection goes on.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

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

fn start(tag: &str, buffers: &str) -> Server {
    let ports = setup_lock();
    let port = {
        let probe = TcpListener::bind("127.0.0.1:0").unwrap();
        probe.local_addr().unwrap().port()
    };
    let dir = std::env::temp_dir().join(format!("ruxen-m148-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "events {{}}\nerror_log {}/error.log info;\nhttp {{ access_log off; {buffers}\n\
               server {{ listen 127.0.0.1:{port}; location / {{ return 200 \"ok\\n\"; }} }} }}\n",
            dir.display()
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

/// The status of each response to `requests`, sent on one connection.
fn statuses(port: u16, requests: &[String]) -> Vec<u16> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut out = Vec::new();
    for req in requests {
        if s.write_all(req.as_bytes()).is_err() {
            break;
        }
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            match s.read(&mut byte) {
                Ok(1) => head.push(byte[0]),
                _ => return out,
            }
        }
        let head = String::from_utf8_lossy(&head).into_owned();
        let status = head[9..12].parse().unwrap();
        let len: usize = head
            .lines()
            .find_map(|l| l.strip_prefix("Content-Length: "))
            .map_or(0, |v| v.trim().parse().unwrap());
        let mut body = vec![0u8; len];
        let _ = s.read_exact(&mut body);
        out.push(status);
    }
    out
}

fn get(target: &str, headers: &[(&str, usize)]) -> String {
    let mut req = format!("GET {target} HTTP/1.1\r\nHost: x\r\n");
    for (name, len) in headers {
        req.push_str(&format!("{name}: {}\r\n", "a".repeat(*len)));
    }
    req.push_str("\r\n");
    req
}

#[test]
fn default_buffers_are_nginx_4_8k() {
    let server = start("default", "");
    let s = |r: String| statuses(server.port, &[r]);
    assert_eq!(s(get("/", &[("Cookie", 10240)])), [400]);
    assert_eq!(s(get("/", &[("X-A", 8150)])), [200]);
    assert_eq!(
        s(get("/", &[("X-1", 7000), ("X-2", 7000), ("X-3", 7000)])),
        [200]
    );
    let five: Vec<(&str, usize)> = ["X-1", "X-2", "X-3", "X-4", "X-5"]
        .iter()
        .map(|n| (*n, 7000))
        .collect();
    assert_eq!(s(get("/", &five)), [400]);
    assert_eq!(s(get(&format!("/{}", "a".repeat(10240)), &[])), [414]);
    // A large head, then small requests on the same connection.
    assert_eq!(
        statuses(
            server.port,
            &[
                get("/", &[("X-1", 7000), ("X-2", 7000)]),
                get("/b", &[]),
                get("/c", &[])
            ]
        ),
        [200, 200, 200]
    );
    let log = std::fs::read_to_string(server.dir.join("error.log")).unwrap_or_default();
    assert!(
        log.contains("[info]")
            && log.contains("client sent too long header line: \"Cookie: aaaa")
            && log.contains("..\" while reading client request headers, client: 127.0.0.1"),
        "{log}"
    );
    assert!(
        log.contains("client sent too long URI while reading client request line"),
        "{log}"
    );
}

#[test]
fn smaller_buffers_limit_lines_and_the_head() {
    let server = start("small", "large_client_header_buffers 2 1k;");
    let s = |r: String| statuses(server.port, &[r]);
    assert_eq!(s(get("/", &[("X-A", 900)])), [200]);
    assert_eq!(s(get("/", &[("X-A", 1500)])), [400]);
    assert_eq!(
        s(get("/", &[("X-1", 900), ("X-2", 900), ("X-3", 900)])),
        [400]
    );
    assert_eq!(s(get(&format!("/{}", "a".repeat(1500)), &[])), [414]);
}

#[test]
fn bad_values_are_refused() {
    for (value, ok) in [
        ("4 8k", true),
        ("1 512", true),
        ("0 8k", false),
        // Under `connection_pool_size` (512 on 64-bit), as nginx refuses.
        ("4 256", false),
        ("4 0", false),
        ("4", false),
    ] {
        let dir = std::env::temp_dir().join(format!("ruxen-m148-t-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let conf = dir.join("nginx.conf");
        std::fs::write(
            &conf,
            format!(
                "events {{}}\nhttp {{ large_client_header_buffers {value};\n\
                   server {{ listen 127.0.0.1:1; }} }}\n"
            ),
        )
        .unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_ruxen"))
            .arg("-t")
            .arg("-c")
            .arg(&conf)
            .output()
            .unwrap();
        assert_eq!(
            out.status.success(),
            ok,
            "{value}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
