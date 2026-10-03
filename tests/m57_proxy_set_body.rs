//! M57 — `proxy_set_body` replaces the request body sent upstream (with
//! variables, and a matching Content-Length), at server or location scope.
//! It used to be accepted and ignored.

use std::io::{Read, Write};
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

fn start(http_body: &str) -> Server {
    let port = {
        let probe = TcpListener::bind("127.0.0.1:0").unwrap();
        probe.local_addr().unwrap().port()
    };
    let dir = std::env::temp_dir().join(format!("ruxen-m57-{}-{port}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "events {{}}\nhttp {{ {} }}\n",
            http_body.replace("%%PORT%%", &port.to_string())
        ),
    )
    .unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .arg("-c")
        .arg(dir.join("nginx.conf"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "ruxen did not start");
        sleep(Duration::from_millis(20));
    }
    Server { child, port, dir }
}

/// Upstream that answers with the body it got: `[<len>]<body>`.
fn spawn_echo_upstream() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut s in listener.incoming().flatten() {
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                if s.read(&mut byte).unwrap_or(0) == 0 {
                    break;
                }
                head.push(byte[0]);
            }
            let head = String::from_utf8_lossy(&head).to_lowercase();
            let len: usize = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .map_or(0, |v| v.trim().parse().unwrap());
            let mut body = vec![0u8; len];
            let _ = s.read_exact(&mut body);
            let reply = format!("[{len}]{}", String::from_utf8_lossy(&body));
            let _ = write!(
                s,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
                reply.len()
            );
        }
    });
    port
}

fn send(port: u16, raw: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(raw.as_bytes()).unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

#[test]
fn proxy_set_body_replaces_the_request_body() {
    let up = spawn_echo_upstream();
    let server = start(&format!(
        "server {{ listen 127.0.0.1:%%PORT%%;\n\
           proxy_set_body \"server-$request_method\";\n\
           location /set {{ proxy_pass http://127.0.0.1:{up}; proxy_set_body \"b-$arg_x\"; }}\n\
           location /inherit {{ proxy_pass http://127.0.0.1:{up}; }}\n\
         }}"
    ));

    let resp = send(
        server.port,
        "GET /set?x=42 HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert!(resp.ends_with("\r\n\r\n[4]b-42"), "{resp}");

    // The client's body is not sent; the server-level value is.
    let resp = send(
        server.port,
        "POST /inherit HTTP/1.1\r\nHost: x\r\nContent-Length: 6\r\nConnection: close\r\n\r\nclient",
    );
    assert!(resp.ends_with("\r\n\r\n[11]server-POST"), "{resp}");
}
