//! M100 — a body nothing reads is dropped as it is read (#289): a
//! `return` location without rewrites, `if`, `error_page`,
//! `post_action` or `limit_except`, in a config that never reads
//! `$request_body` or `$request_body_file`, reads the body through a small
//! buffer and drops it, as nginx's ngx_http_discard_request_body does. The
//! response goes out first, before the body has come (#627). The
//! connection stays usable: keep-alive and a pipelined request after the
//! body work, and `$request_length` still counts the whole body.

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
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

fn start(name: &str) -> (Server, u16) {
    let dir = std::env::temp_dir().join(format!("ruxen-m100-{name}-{}", std::process::id()));
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
            "events {{}}\nhttp {{\n\
             log_format len '$request_uri $request_length';\n\
             server {{ listen 127.0.0.1:{port};\n\
             access_log {d}/access.log len;\n\
             client_max_body_size 10m;\n\
             location / {{ return 200 \"ok $content_length\\n\"; }}\n\
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

/// Read `count` responses with Content-Length bodies off `s`.
fn responses(s: &mut TcpStream, count: usize) -> Vec<String> {
    let mut raw = Vec::new();
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    while out.len() < count {
        let n = s.read(&mut buf).unwrap();
        assert!(n > 0, "connection closed after {} responses", out.len());
        raw.extend_from_slice(&buf[..n]);
        while let Some(end) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&raw[..end]).to_string();
            let len: usize = head
                .lines()
                .find_map(|l| l.strip_prefix("Content-Length: "))
                .unwrap()
                .parse()
                .unwrap();
            if raw.len() < end + 4 + len {
                break;
            }
            let body = String::from_utf8_lossy(&raw[end + 4..end + 4 + len]).to_string();
            out.push(format!("{} | {body}", head.lines().next().unwrap()));
            raw.drain(..end + 4 + len);
        }
    }
    out
}

fn log_lines(path: &Path, count: usize) -> Vec<String> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        let lines: Vec<String> = text.lines().map(str::to_string).collect();
        if lines.len() >= count {
            return lines;
        }
        assert!(Instant::now() < deadline, "{text}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn m100_dropped_body_keeps_the_connection_in_step() {
    let (server, port) = start("step");
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let big = vec![b'x'; 200 * 1024 + 3];
    // A large body in pieces, with pauses, and a second request pipelined
    // right behind it in the last write.
    let head = format!(
        "POST /a HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n",
        big.len()
    );
    s.write_all(head.as_bytes()).unwrap();
    for part in big[..big.len() - 10].chunks(50 * 1024) {
        s.write_all(part).unwrap();
        std::thread::sleep(Duration::from_millis(20));
    }
    let mut last = big[big.len() - 10..].to_vec();
    last.extend_from_slice(b"POST /b HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello");
    last.extend_from_slice(b"GET /c HTTP/1.1\r\nHost: x\r\n\r\n");
    s.write_all(&last).unwrap();
    assert_eq!(
        responses(&mut s, 3),
        [
            format!("HTTP/1.1 200 OK | ok {}\n", big.len()),
            "HTTP/1.1 200 OK | ok 5\n".to_string(),
            "HTTP/1.1 200 OK | ok \n".to_string(),
        ]
    );
    let lines = log_lines(&server.1.join("access.log"), 3);
    let len_a: usize = lines[0].strip_prefix("/a ").unwrap().parse().unwrap();
    assert_eq!(len_a, head.len() + big.len(), "{lines:?}");
    assert!(lines[1].starts_with("/b "), "{lines:?}");
}

#[test]
fn m100_client_stopping_mid_body_closes_the_connection() {
    let (_server, port) = start("stop");
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 100000\r\n\r\n")
        .unwrap();
    s.write_all(&[b'x'; 1000]).unwrap();
    s.shutdown(std::net::Shutdown::Write).unwrap();
    // The response went out at once (#627); the rest of the body never
    // comes, so the connection then closes.
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    let out = String::from_utf8_lossy(&out);
    assert!(out.starts_with("HTTP/1.1 200 OK"), "{out}");
    assert_eq!(out.matches("HTTP/1.1").count(), 1, "{out}");
}

/// The response doesn't wait for a body nothing reads (#627): it comes
/// while the body is still on its way, as nginx answers before discarding.
/// A chunked body that is still coming gets the response too, and then the
/// connection closes, its end being unknown.
#[test]
fn m100_the_response_comes_before_the_body() {
    let (_server, port) = start("first");
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    s.write_all(b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\nabc")
        .unwrap();
    assert_eq!(
        responses(&mut s, 1),
        ["HTTP/1.1 200 OK | ok 10\n".to_string()]
    );
    // The rest of it, and a next request on the same connection.
    s.write_all(b"defghijGET /two HTTP/1.1\r\nHost: x\r\n\r\n")
        .unwrap();
    assert_eq!(
        responses(&mut s, 1),
        ["HTTP/1.1 200 OK | ok \n".to_string()]
    );

    let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    c.write_all(b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n")
        .unwrap();
    let mut out = Vec::new();
    let _ = c.read_to_end(&mut out);
    let out = String::from_utf8_lossy(&out);
    assert!(out.starts_with("HTTP/1.1 200 OK"), "{out}");
}
