//! M129 — `proxy_pass https://` (#116): TLS to upstreams with nginx's
//! defaults (no SNI unless `proxy_ssl_server_name on`, session reuse on,
//! the certificate not verified), the keep-alive pool, and the failures.
//! The upstream is a TLS server block of the same ruxen.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

struct Server {
    child: common::KillOnDrop,
    dir: PathBuf,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.0.kill();
        let _ = self.child.0.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn start(name: &str, http: impl FnOnce(&Path) -> String) -> Server {
    let dir = std::env::temp_dir().join(format!("ruxen-m129-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let setup = common::ports::setup_lock();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "pid {d}/ruxen.pid;\nerror_log {d}/error.log info;\nevents {{}}\n\
             http {{\naccess_log off;\n{http}\n}}\n",
            d = dir.display(),
            http = http(&dir)
        ),
    )
    .unwrap();
    let mut child = common::KillOnDrop(
        Command::new(env!("CARGO_BIN_EXE_ruxen"))
            .arg("-c")
            .arg(dir.join("nginx.conf"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    common::ports::wait_for_pid_file(&mut child, &dir.join("ruxen.pid"), Duration::from_secs(5));
    drop(setup);
    Server { child, dir }
}

/// One request with `Connection: close`: (status, body).
fn get(port: u16, path: &str) -> (u16, String) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: front\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).unwrap();
    let text = String::from_utf8_lossy(&raw).into_owned();
    let status = text.get(9..12).and_then(|s| s.parse().ok()).unwrap_or(0);
    let body = text
        .split_once("\r\n\r\n")
        .map_or("", |(_, b)| b)
        .to_string();
    (status, body)
}

#[test]
fn https_upstreams_like_nginx() {
    let cert = common::tls::make_self_signed("backend.test");
    let (front, backend, plain) = (free_port(), free_port(), free_port());
    let s = start("main", |_| {
        format!(
            "upstream b {{ server 127.0.0.1:{backend}; keepalive 4; }}\n\
             server {{ listen 127.0.0.1:{backend} ssl;\n\
               ssl_certificate {cert}; ssl_certificate_key {key};\n\
               ssl_session_cache shared:s:1m;\n\
               location / {{ return 200 \"$ssl_protocol|$ssl_server_name|$connection_requests|$ssl_session_reused|$http_x_port|$host\"; }} }}\n\
             server {{ listen 127.0.0.1:{plain}; location / {{ return 200 plain; }} }}\n\
             server {{ listen 127.0.0.1:{front};\n\
               location /direct/ {{ proxy_pass https://127.0.0.1:{backend}/; }}\n\
               location /sni/ {{ proxy_pass https://127.0.0.1:{backend}/;\n\
                 proxy_ssl_server_name on; proxy_ssl_name backend.test; }}\n\
               location /pool/ {{ proxy_pass https://b/; proxy_http_version 1.1;\n\
                 proxy_set_header Connection \"\"; proxy_set_header X-Port $proxy_port; }}\n\
               location /noreuse/ {{ proxy_pass https://127.0.0.1:{backend}/;\n\
                 proxy_ssl_session_reuse off; }}\n\
               location /handshake/ {{ proxy_pass https://127.0.0.1:{plain}/; }} }}",
            cert = cert.cert_path().display(),
            key = cert.key_path().display(),
        )
    });

    // nginx's defaults: TLS, and no SNI.
    let (status, body) = get(front, "/direct/");
    assert_eq!(status, 200, "{body}");
    let fields: Vec<&str> = body.split('|').collect();
    assert!(fields[0].starts_with("TLSv1."), "{body}");
    assert_eq!(fields[1], "", "no SNI by default: {body}");
    // `Host` is the proxy_pass authority, port included.
    assert_eq!(fields[5], "127.0.0.1", "{body}");

    // proxy_ssl_server_name on: the ClientHello names proxy_ssl_name.
    let (status, body) = get(front, "/sni/");
    assert_eq!(status, 200, "{body}");
    assert_eq!(body.split('|').nth(1), Some("backend.test"), "{body}");

    // The pool keeps the TLS connection: the second request reuses it.
    // `$proxy_port` of `https://b` is 443.
    let (_, first) = get(front, "/pool/");
    let (_, second) = get(front, "/pool/");
    let requests = |b: &str| b.split('|').nth(2).unwrap_or("").to_string();
    assert_eq!(requests(&first), "1", "{first}");
    assert_eq!(requests(&second), "2", "{second}");
    assert_eq!(first.split('|').nth(4), Some("443"), "{first}");

    // Without keep-alive, the session is resumed on the next connection,
    // unless proxy_ssl_session_reuse is off.
    let reused = |b: &str| b.split('|').nth(3).unwrap_or("").to_string();
    get(front, "/direct/");
    let (_, body) = get(front, "/direct/");
    assert_eq!(reused(&body), "r", "{body}");
    get(front, "/noreuse/");
    let (_, body) = get(front, "/noreuse/");
    assert_eq!(reused(&body), ".", "{body}");

    // A plain HTTP server where TLS is expected: 502, and nginx's line.
    let (status, _) = get(front, "/handshake/");
    assert_eq!(status, 502);
    let log = std::fs::read_to_string(s.dir.join("error.log")).unwrap_or_default();
    assert!(
        log.contains("SSL_do_handshake() failed")
            && log.contains("while SSL handshaking to upstream")
            && log.contains(&format!("upstream: \"https://127.0.0.1:{plain}/\"")),
        "{log}"
    );
}

/// `proxy_ssl_verify on` can't be honoured until certificates are
/// verified (#117): the configuration is refused, not served unverified.
#[test]
fn proxy_ssl_verify_on_is_refused() {
    let dir = std::env::temp_dir().join(format!("ruxen-m129-verify-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let check = |verify: &str| {
        std::fs::write(
            dir.join("nginx.conf"),
            format!(
                "events {{}}\nhttp {{ server {{ listen 127.0.0.1:1;\n\
                 location / {{ proxy_pass https://127.0.0.1:2; proxy_ssl_verify {verify}; }} }} }}\n"
            ),
        )
        .unwrap();
        Command::new(env!("CARGO_BIN_EXE_ruxen"))
            .arg("-t")
            .arg("-c")
            .arg(dir.join("nginx.conf"))
            .output()
            .unwrap()
    };
    let on = check("on");
    let off = check("off");
    let _ = std::fs::remove_dir_all(&dir);
    assert!(!on.status.success());
    assert!(
        String::from_utf8_lossy(&on.stderr).contains("proxy_ssl_verify"),
        "{}",
        String::from_utf8_lossy(&on.stderr)
    );
    assert!(
        off.status.success(),
        "{}",
        String::from_utf8_lossy(&off.stderr)
    );
}

/// A 101 over TLS (#87 with #116): the tunnel shares the TLS connection
/// between its two directions, and bytes go both ways.
#[test]
fn upgrade_through_an_https_upstream() {
    use std::sync::Arc;
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert = rustls::pki_types::CertificateDer::from(ck.cert.der().to_vec());
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
        ck.signing_key.serialize_der(),
    ));
    let config = Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let backend = listener.local_addr().unwrap().port();
    // The upstream: answers the upgrade, then echoes what comes.
    let echo = std::thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let conn = rustls::ServerConnection::new(config).unwrap();
        let mut tls = rustls::StreamOwned::new(conn, tcp);
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            if tls.read(&mut byte).unwrap() == 0 {
                return;
            }
            head.push(byte[0]);
        }
        tls.write_all(
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
        )
        .unwrap();
        tls.flush().unwrap();
        let mut buf = [0u8; 64];
        for _ in 0..2 {
            let n = tls.read(&mut buf).unwrap();
            tls.write_all(&buf[..n]).unwrap();
            tls.flush().unwrap();
        }
    });
    let front = free_port();
    let _s = start("upgrade", |_| {
        format!(
            "server {{ listen 127.0.0.1:{front};\n\
               location / {{ proxy_pass https://127.0.0.1:{backend};\n\
                 proxy_http_version 1.1; proxy_set_header Upgrade $http_upgrade;\n\
                 proxy_set_header Connection upgrade; }} }}"
        )
    });
    let mut c = TcpStream::connect(("127.0.0.1", front)).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    c.write_all(
        b"GET /ws HTTP/1.1\r\nHost: front\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
    )
    .unwrap();
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        assert_eq!(
            c.read(&mut byte).unwrap(),
            1,
            "{}",
            String::from_utf8_lossy(&head)
        );
        head.push(byte[0]);
    }
    assert!(
        head.starts_with(b"HTTP/1.1 101"),
        "{}",
        String::from_utf8_lossy(&head)
    );
    for word in [&b"ping"[..], b"second"] {
        c.write_all(word).unwrap();
        let mut got = vec![0u8; word.len()];
        c.read_exact(&mut got).unwrap();
        assert_eq!(got, word);
    }
    drop(c);
    echo.join().unwrap();
}
