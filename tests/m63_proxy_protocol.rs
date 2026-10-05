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
        log.contains("[error]")
            && log.contains(&format!(
                "broken header: \"GET / HTTP/1.1\" while reading PROXY protocol, \
                 client: 127.0.0.1, server: 127.0.0.1:{}",
                server.port
            )),
        "{log}"
    );
}

/// A client that closes or times out before sending the header is logged
/// at info, as nginx (ngx_http_wait_request_handler), with the action once
/// and the listening address as `server:`. ruxen used to log both at
/// error, with "while reading PROXY protocol" twice and no `server:`.
#[test]
fn a_client_gone_before_the_header_is_info() {
    let dir = std::env::temp_dir().join(format!("ruxen-m63-gone-{}", std::process::id()));
    let server = start(
        "gone",
        "",
        &format!(
            "client_header_timeout 1s; error_log {} info;",
            dir.join("info.log").display()
        ),
    );
    drop(TcpStream::connect(("127.0.0.1", server.port)).unwrap());
    let started = Instant::now();
    assert_eq!(exchange(server.port, &[]), "");
    assert!(started.elapsed() >= Duration::from_millis(900));
    sleep(Duration::from_millis(50));
    let log = std::fs::read_to_string(dir.join("info.log")).unwrap_or_default();
    let context = format!(
        " while reading PROXY protocol, client: 127.0.0.1, server: 127.0.0.1:{}",
        server.port
    );
    for line in [
        "client closed connection",
        "client timed out (110: Connection timed out)",
    ] {
        assert!(
            log.lines()
                .any(|l| l.contains("[info]") && l.ends_with(&format!("{line}{context}"))),
            "{line}: {log}"
        );
    }
}

/// What arrives first is all nginx looks at (ngx_http_wait_request_handler
/// reads once), so a header cut short is refused at once. ruxen used to
/// poll the socket every 5 ms until client_header_timeout (60 s), even
/// after the client had closed: the bytes it peeked never went away.
#[test]
fn a_header_cut_short_is_refused_at_once() {
    let server = start("cut", "", "");
    let mut v2 = b"\r\n\r\n\0\r\nQUIT\n".to_vec();
    v2.extend_from_slice(&[0x21, 0x11, 0, 12, 192, 0, 2, 1]);
    for (part, logged) in [
        (&b"PROXY TCP4 "[..], "broken header: \"PROXY TCP4 \""),
        (&v2[..], "header is too large"),
    ] {
        let started = Instant::now();
        assert_eq!(exchange(server.port, &[part]), "");
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "{logged}: closed after {:?}",
            started.elapsed()
        );
        sleep(Duration::from_millis(50));
        let log = std::fs::read_to_string(server.dir.join("error.log")).unwrap_or_default();
        assert!(log.contains(logged), "{log}");
    }
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
    // `--haproxy-protocol` alone (curl 7.60+; `--haproxy-clientip` needs
    // 8.2, newer than Ubuntu 22.04's) sends the connection's own
    // addresses: the header was read if its ports show up.
    let out = Command::new("curl")
        .args(["-sk", "--haproxy-protocol"])
        .arg(format!("https://localhost:{}/", server.port))
        .output()
        .expect("curl");
    let body = String::from_utf8_lossy(&out.stdout);
    let fields: Vec<&str> = body.split(' ').collect();
    let port_of = |addr: &str| addr.rsplit_once(':').map(|(_, p)| p.to_string());
    assert!(
        fields.len() == 3
            && fields[0].starts_with("127.0.0.1:")
            && port_of(fields[0]).is_some_and(|p| p.parse::<u16>().is_ok())
            && fields[1] == format!("127.0.0.1:{}", server.port)
            && fields[2] == "127.0.0.1",
        "{body} / {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// `$proxy_protocol_tlv_*` read the v2 header's TLVs, as nginx: by name,
/// by hex type, inside the SSL TLV, and its verify field. They used to be
/// unsupported variables that rendered empty.
#[test]
fn v2_tlvs_are_variables() {
    let server = start(
        "tlv",
        "",
        "add_header X-ALPN $proxy_protocol_tlv_alpn-$proxy_protocol_tlv_0x01;\n\
         add_header X-SSL-CN $proxy_protocol_tlv_ssl_cn;\n\
         add_header X-VERIFY $proxy_protocol_tlv_ssl_verify;\n\
         add_header X-NONE [$proxy_protocol_tlv_authority];",
    );
    let tlv = |ty: u8, value: &[u8]| {
        let mut out = vec![ty];
        out.extend_from_slice(&(value.len() as u16).to_be_bytes());
        out.extend_from_slice(value);
        out
    };
    // SSL TLV: client, verify = 255, then a CN sub-TLV.
    let mut ssl = vec![0x01, 0, 0, 0, 255];
    ssl.extend(tlv(0x22, b"example.com"));
    let tlvs = [tlv(0x01, b"ALPN1"), tlv(0x20, &ssl)].concat();
    let mut v2 = b"\r\n\r\n\0\r\nQUIT\n".to_vec();
    v2.extend_from_slice(&[0x21, 0x11]);
    v2.extend_from_slice(&((12 + tlvs.len()) as u16).to_be_bytes());
    v2.extend_from_slice(&[192, 0, 2, 1, 192, 0, 2, 2, 0xc7, 0x38, 0, 80]);
    v2.extend_from_slice(&tlvs);
    let resp = exchange(server.port, &[&[&v2[..], GET].concat()]);
    assert!(resp.contains("\r\nX-ALPN: ALPN1-ALPN1\r\n"), "{resp}");
    assert!(resp.contains("\r\nX-SSL-CN: example.com\r\n"), "{resp}");
    assert!(resp.contains("\r\nX-VERIFY: 255\r\n"), "{resp}");
    assert!(resp.contains("\r\nX-NONE: []\r\n"), "{resp}");

    // A v1 header has no TLVs: the variables are empty.
    let resp = exchange(server.port, &[V1, GET]);
    assert!(resp.contains("\r\nX-NONE: []\r\n"), "{resp}");
    assert!(!resp.contains("X-SSL-CN"), "{resp}");
}
