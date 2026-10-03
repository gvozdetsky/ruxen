//! M63 — `listen … proxy_protocol`: every connection starts with a PROXY
//! protocol header (v1 text or v2 binary), which ruxen reads before HTTP
//! or TLS and exposes as `$proxy_protocol_addr` / `_port` /
//! `_server_addr` / `_server_port`. A connection without a valid header is
//! closed with a `broken header` error-log line. The flag used to be
//! accepted and ignored, so every request behind a PROXY-speaking load
//! balancer got 400.

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

const BODY: &str = "\"$proxy_protocol_addr:$proxy_protocol_port \
                    $proxy_protocol_server_addr:$proxy_protocol_server_port $remote_addr\"";

fn start(tag: &str, listen_extra: &str, server_extra: &str) -> Server {
    start_with(tag, "", listen_extra, server_extra)
}

fn start_with(tag: &str, events: &str, listen_extra: &str, server_extra: &str) -> Server {
    let port = {
        let probe = TcpListener::bind("127.0.0.1:0").unwrap();
        probe.local_addr().unwrap().port()
    };
    let dir = std::env::temp_dir().join(format!("ruxen-m63-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "pid {d}/ruxen.pid;\nevents {{ {events} }}\nhttp {{ server {{ \
             listen 127.0.0.1:{port} proxy_protocol {listen_extra}; {server_extra}\n\
             location / {{ return 200 {BODY}; }} }} }}\n",
            d = dir.display()
        ),
    )
    .unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .arg("-c")
        .arg(dir.join("nginx.conf"))
        .arg("-e")
        .arg(dir.join("error.log"))
        .env("RUXEN_WORKERS", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    while !dir.join("ruxen.pid").exists() {
        assert!(Instant::now() < deadline, "ruxen did not start");
        sleep(Duration::from_millis(10));
    }
    Server { child, port, dir }
}

fn exchange(port: u16, parts: &[&[u8]]) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    for (i, part) in parts.iter().enumerate() {
        if i > 0 {
            sleep(Duration::from_millis(30));
        }
        s.write_all(part).unwrap();
    }
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    String::from_utf8_lossy(&out).into_owned()
}

fn body(resp: &str) -> &str {
    resp.split("\r\n\r\n").last().unwrap_or("")
}

const GET: &[u8] = b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
const V1: &[u8] = b"PROXY TCP4 192.0.2.1 192.0.2.2 51000 80\r\n";

#[test]
fn v1_and_v2_headers_are_read() {
    let server = start("plain", "", "");
    let want = "192.0.2.1:51000 192.0.2.2:80 127.0.0.1";

    // Header and request in one packet, and in two.
    assert_eq!(body(&exchange(server.port, &[&[V1, GET].concat()])), want);
    assert_eq!(body(&exchange(server.port, &[V1, GET])), want);

    // v2, IPv4.
    let mut v2 = b"\r\n\r\n\0\r\nQUIT\n".to_vec();
    v2.extend_from_slice(&[
        0x21, 0x11, 0, 12, 192, 0, 2, 1, 192, 0, 2, 2, 0xc7, 0x38, 0, 80,
    ]);
    assert_eq!(
        body(&exchange(server.port, &[&[&v2[..], GET].concat()])),
        want
    );

    // UNKNOWN: the connection's own addresses; the variables are empty.
    let resp = exchange(server.port, &[b"PROXY UNKNOWN\r\n", GET]);
    assert_eq!(body(&resp), ": : 127.0.0.1", "{resp}");

    // The header comes once per connection, not per request.
    let two =
        b"GET / HTTP/1.1\r\nHost: x\r\n\r\nGET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
    let resp = exchange(server.port, &[&[V1, &two[..]].concat()]);
    assert_eq!(resp.matches(want).count(), 2, "{resp}");
}

#[test]
fn a_connection_without_the_header_is_closed() {
    let server = start("broken", "", "");
    assert_eq!(exchange(server.port, &[GET]), "");
    sleep(Duration::from_millis(50));
    let log = std::fs::read_to_string(server.dir.join("error.log")).unwrap_or_default();
    assert!(
        log.contains("[error]") && log.contains("broken header: \"GET / HTTP/1.1"),
        "{log}"
    );
}

/// A connection that never sends a valid header still gives back its
/// `worker_connections` slot. It used to keep it: with one worker and
/// three slots, three broken connections locked every later client out,
/// and SIGQUIT waited for them forever.
#[test]
fn broken_headers_give_back_their_slot() {
    let mut server = start_with("slots", "worker_connections 4;", "", "");
    for _ in 0..8 {
        assert_eq!(exchange(server.port, &[GET]), "");
        // Closed before sending anything.
        drop(TcpStream::connect(("127.0.0.1", server.port)).unwrap());
    }
    sleep(Duration::from_millis(50));
    let want = "192.0.2.1:51000 192.0.2.2:80 127.0.0.1";
    assert_eq!(body(&exchange(server.port, &[V1, GET])), want);

    let rc = unsafe { libc::kill(server.child.id() as i32, libc::SIGQUIT) };
    assert_eq!(rc, 0);
    let deadline = Instant::now() + Duration::from_secs(3);
    while server.child.try_wait().unwrap().is_none() {
        assert!(
            Instant::now() < deadline,
            "ruxen did not exit after SIGQUIT"
        );
        sleep(Duration::from_millis(20));
    }
}

#[test]
fn tls_after_the_header() {
    let certs = common::tls::make_self_signed("localhost");
    let server = start(
        "tls",
        "ssl",
        &format!(
            "ssl_certificate {}; ssl_certificate_key {};",
            certs.cert_path().display(),
            certs.key_path().display()
        ),
    );
    let out = Command::new("curl")
        .args([
            "-sk",
            "--haproxy-protocol",
            "--haproxy-clientip",
            "203.0.113.7",
        ])
        .arg(format!("https://localhost:{}/", server.port))
        .output()
        .expect("curl");
    let body = String::from_utf8_lossy(&out.stdout);
    assert!(
        body.starts_with("203.0.113.7:") && body.ends_with(" 127.0.0.1"),
        "{body} / {}",
        String::from_utf8_lossy(&out.stderr)
    );
}
