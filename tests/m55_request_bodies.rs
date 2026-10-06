//! M55 — request bodies above 1 MiB (#37). `client_max_body_size` is
//! honoured as in nginx: default 1m, `0` = unlimited, larger values allow
//! larger bodies. Bodies over 1 MiB are kept in a temp file instead of
//! memory and proxied from there; both Content-Length and chunked bodies.
//! Over the limit is 413 (it used to be 400 and a reset for anything over
//! 1 MiB, whatever the configuration said). A Content-Length over the
//! limit of the location the request is routed to is refused before the
//! body is read, as nginx's find_config phase does.

mod common;

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
    let listener = {
        let _setup = common::ports::setup_lock();
        TcpListener::bind("127.0.0.1:0").unwrap()
    };
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
    let _setup = common::ports::setup_lock();
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
            conf_http
                .replace("%%PORT%%", &port.to_string())
                .replace("%%DIR%%", &dir.display().to_string())
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
    // nginx's default is 1m.
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

/// Refusing a body by its Content-Length while the client is still sending
/// it: ruxen keeps reading (and discarding) the upload until the client is
/// done, as nginx's lingering close, so the client's send completes and it
/// reads the 413. It used to close with unread input, and the kernel's RST
/// failed the client's send (and, off loopback, could lose the response).
#[test]
fn refused_upload_is_drained_not_reset() {
    let server = start(
        "client_max_body_size 1k;\n\
         server { listen 127.0.0.1:%%PORT%%; location / { return 200 \"ok\"; } }",
    );
    let len = 20 * 1024 * 1024;
    let mut s = TcpStream::connect(("127.0.0.1", server.port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    write!(
        s,
        "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: {len}\r\n\r\n"
    )
    .unwrap();
    let mut writer = s.try_clone().unwrap();
    let upload = std::thread::spawn(move || {
        let chunk = vec![b'x'; 64 * 1024];
        let mut sent = 0;
        while sent < len {
            writer.write_all(&chunk)?;
            sent += chunk.len();
        }
        // Done sending: the server sees EOF and closes.
        writer.shutdown(std::net::Shutdown::Write)
    });
    let mut resp = Vec::new();
    let _ = s.read_to_end(&mut resp);
    let sent = upload.join().unwrap();
    assert!(sent.is_ok(), "upload failed: {sent:?}");
    let resp = String::from_utf8_lossy(&resp);
    assert!(resp.starts_with("HTTP/1.1 413"), "{resp}");
}

/// Sends only the request head and returns the first response head that
/// comes back within 3 s (a `100 Continue` counts), or what arrived.
fn head_only(port: u16, head: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.write_all(head.as_bytes()).unwrap();
    let mut out = Vec::new();
    let mut byte = [0u8; 1];
    while !out.ends_with(b"\r\n\r\n") && s.read(&mut byte).unwrap_or(0) == 1 {
        out.push(byte[0]);
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// One location without a limit used to lift the read bound for every
/// location in every server: a body over the location's own limit was read
/// in full (to a temp file past 1 MiB) and only then refused. Now the
/// limit of the location the request is routed to is checked against the
/// Content-Length first, as nginx's find_config phase does: 413 at once,
/// with nginx's error-log line, and no `100 Continue`.
#[test]
fn oversized_content_length_is_refused_unread() {
    let server = start(
        "error_log %%DIR%%/error.log;\n\
         server { listen 127.0.0.1:%%PORT%%;\n\
           location / { return 200 \"ok\"; }\n\
           location /upload { client_max_body_size 0; return 200 \"upload\"; } }",
    );
    let big = 50_000_000;

    let resp = head_only(
        server.port,
        &format!("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: {big}\r\n\r\n"),
    );
    assert!(resp.starts_with("HTTP/1.1 413"), "{resp:?}");
    let log = std::fs::read_to_string(server.dir.join("error.log")).unwrap_or_default();
    let line = format!("client intended to send too large body: {big} bytes, client: 127.0.0.1");
    assert!(log.contains("[error]") && log.contains(&line), "{log}");

    // Expect: 100-continue gets the 413 straight away, without a 100.
    let resp = head_only(
        server.port,
        &format!(
            "POST / HTTP/1.1\r\nHost: x\r\nExpect: 100-continue\r\n\
             Content-Length: {big}\r\n\r\n"
        ),
    );
    assert!(resp.starts_with("HTTP/1.1 413"), "{resp:?}");

    // The unlimited location still asks for the body.
    let resp = head_only(
        server.port,
        &format!(
            "POST /upload HTTP/1.1\r\nHost: x\r\nExpect: 100-continue\r\n\
             Content-Length: {big}\r\n\r\n"
        ),
    );
    assert!(resp.starts_with("HTTP/1.1 100 Continue"), "{resp:?}");
}

/// The 413 for a body over `client_max_body_size` goes through the
/// location's `error_page` and `add_header … always`, as nginx's special
/// response (ngx_http_finalize_request(r, 413)), and closes the connection
/// (nginx clears keepalive for 413). The error page doesn't check the size
/// again. It used to be the built-in 413 page.
#[test]
fn oversized_body_gets_the_locations_error_page() {
    let upstream = spawn_echo_upstream();
    let server = start(&format!(
        "server {{ listen 127.0.0.1:%%PORT%%;\n\
           location / {{ client_max_body_size 1k; error_page 413 /e413;\n\
             return 200 \"ok\"; }}\n\
           location /up {{ client_max_body_size 1k; error_page 413 /e413;\n\
             add_header X-Always yes always;\n\
             proxy_pass http://127.0.0.1:{upstream}; }}\n\
           location /plain {{ client_max_body_size 1k; add_header X-Always yes always;\n\
             return 200 \"ok\"; }}\n\
           location = /e413 {{ client_max_body_size 1k; return 200 \"custom 413 page\"; }} }}"
    ));
    let body = vec![b'z'; 5000];

    // Refused from the Content-Length, unread.
    let resp = post_cl(server.port, "/", &body);
    assert!(resp.starts_with("HTTP/1.1 413"), "{resp}");
    assert!(resp.ends_with("custom 413 page"), "{resp}");
    assert!(resp.contains("\r\nConnection: close\r\n"), "{resp}");

    // Chunked, refused while reading it.
    let resp = post_chunked(server.port, "/up", &body, 700);
    assert!(resp.starts_with("HTTP/1.1 413"), "{resp}");
    assert!(resp.ends_with("custom 413 page"), "{resp}");

    // No error_page: the built-in page, with the location's headers.
    let resp = post_cl(server.port, "/plain", &body);
    assert!(resp.starts_with("HTTP/1.1 413"), "{resp}");
    assert!(resp.contains("\r\nX-Always: yes\r\n"), "{resp}");
}
