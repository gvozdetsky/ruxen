//! M55 — request bodies above 1 MiB (#37). `client_max_body_size` is
//! honoured as in nginx: default 1m, `0` = unlimited, larger values allow
//! larger bodies. Bodies over 1 MiB are kept in a temp file instead of
//! memory and proxied from there; both Content-Length and chunked bodies.
//! Over the limit is 413 (it used to be 400 and a reset for anything over
//! 1 MiB, whatever the configuration said).

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

/// Upstream that reads a Content-Length body and answers with its length
/// and a checksum.
fn spawn_echo_upstream() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || serve_one(stream));
        }
    });
    port
}

fn serve_one(mut s: TcpStream) {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if s.read(&mut byte).unwrap_or(0) == 0 {
            return;
        }
        head.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&head).to_lowercase();
    let len: usize = head
        .lines()
        .find_map(|l| l.strip_prefix("content-length:"))
        .map(|v| v.trim().parse().unwrap())
        .unwrap_or(0);
    let mut body = vec![0u8; len];
    s.read_exact(&mut body).unwrap();
    let reply = format!("len={} sum={}", body.len(), checksum(&body));
    let _ = write!(
        s,
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
        reply.len()
    );
}

fn checksum(b: &[u8]) -> u64 {
    b.iter().enumerate().fold(0u64, |acc, (i, &x)| {
        acc.wrapping_mul(31).wrapping_add(x as u64 ^ i as u64)
    })
}

fn payload(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 % 251) as u8).collect()
}

fn start(conf_http: &str) -> Server {
    let port = {
        let probe = TcpListener::bind("127.0.0.1:0").unwrap();
        probe.local_addr().unwrap().port()
    };
    let dir = std::env::temp_dir().join(format!("ruxen-m55-{}-{port}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "events {{}}\nhttp {{ {} }}\n",
            conf_http.replace("%%PORT%%", &port.to_string())
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

fn exchange(port: u16, head: &str, body: &[u8]) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.write_all(head.as_bytes()).unwrap();
    let _ = s.write_all(body);
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    String::from_utf8_lossy(&out).into_owned()
}

fn post_cl(port: u16, path: &str, body: &[u8]) -> String {
    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    exchange(port, &head, body)
}

fn post_chunked(port: u16, path: &str, body: &[u8], chunk: usize) -> String {
    let mut framed = Vec::new();
    for part in body.chunks(chunk) {
        framed.extend_from_slice(format!("{:x}\r\n", part.len()).as_bytes());
        framed.extend_from_slice(part);
        framed.extend_from_slice(b"\r\n");
    }
    framed.extend_from_slice(b"0\r\n\r\n");
    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n\r\n"
    );
    exchange(port, &head, &framed)
}

fn proxy_conf(upstream: u16) -> String {
    format!(
        "server {{ listen 127.0.0.1:%%PORT%%;\n\
           location /big/ {{ client_max_body_size 10m; proxy_pass http://127.0.0.1:{upstream}; }}\n\
           location /small/ {{ client_max_body_size 1k; proxy_pass http://127.0.0.1:{upstream}; }}\n\
           location /default/ {{ proxy_pass http://127.0.0.1:{upstream}; }}\n\
         }}"
    )
}

#[test]
fn large_content_length_body_is_proxied_intact() {
    let upstream = spawn_echo_upstream();
    let server = start(&proxy_conf(upstream));
    let body = payload(3 * 1024 * 1024 + 17);
    let resp = post_cl(server.port, "/big/", &body);
    assert!(
        resp.starts_with("HTTP/1.1 200"),
        "{}",
        &resp[..resp.len().min(300)]
    );
    assert!(
        resp.ends_with(&format!("len={} sum={}", body.len(), checksum(&body))),
        "{resp}"
    );
}

#[test]
fn large_chunked_body_is_proxied_intact() {
    let upstream = spawn_echo_upstream();
    let server = start(&proxy_conf(upstream));
    let body = payload(3 * 1024 * 1024 + 5);
    // One chunk bigger than the in-memory limit, then many small ones.
    for chunk in [body.len(), 4096] {
        let resp = post_chunked(server.port, "/big/", &body, chunk);
        assert!(
            resp.starts_with("HTTP/1.1 200"),
            "{}",
            &resp[..resp.len().min(300)]
        );
        assert!(
            resp.ends_with(&format!("len={} sum={}", body.len(), checksum(&body))),
            "chunk {chunk}: {resp}"
        );
    }
}

#[test]
fn limits_follow_client_max_body_size() {
    let upstream = spawn_echo_upstream();
    let server = start(&proxy_conf(upstream));
    // Over the largest limit of any location (10m): 413 from the
    // Content-Length alone, before any body is sent.
    let head = "POST /big/ HTTP/1.1\r\nHost: x\r\nContent-Length: 11534336\r\n\r\n";
    let resp = exchange(server.port, head, b"");
    assert!(resp.starts_with("HTTP/1.1 413"), "{resp}");
    // nginx's default is 1m. Bodies are read before routing, so this one
    // is read, then refused by the location (nginx refuses it up front).
    let resp = post_cl(server.port, "/default/", &payload(2 * 1024 * 1024));
    assert!(
        resp.starts_with("HTTP/1.1 413"),
        "{}",
        &resp[..resp.len().min(200)]
    );
    // Within the default: fine.
    let small = payload(1000);
    assert!(post_cl(server.port, "/default/", &small).starts_with("HTTP/1.1 200"));
    // The location's own 1k limit applies even though /big/ allows 10m.
    assert!(post_cl(server.port, "/small/", &payload(4096)).starts_with("HTTP/1.1 413"));
    assert!(post_chunked(server.port, "/small/", &payload(4096), 512).starts_with("HTTP/1.1 413"));
    // Over the largest limit anywhere (10m), chunked: 413 while reading.
    let resp = post_chunked(server.port, "/big/", &payload(11 * 1024 * 1024), 1 << 20);
    assert!(
        resp.starts_with("HTTP/1.1 413"),
        "{}",
        &resp[..resp.len().min(200)]
    );
}

#[test]
fn zero_means_unlimited() {
    let server = start(
        "client_max_body_size 0;\n\
         server { listen 127.0.0.1:%%PORT%%; location / { return 200 \"read\"; } }",
    );
    let resp = post_cl(server.port, "/", &payload(12 * 1024 * 1024));
    assert!(
        resp.starts_with("HTTP/1.1 200"),
        "{}",
        &resp[..resp.len().min(200)]
    );
    assert!(resp.ends_with("read"));
}
