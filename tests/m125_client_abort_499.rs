//! M125 — a client that closes while the upstream is awaited ends the
//! exchange (#136), as nginx's ngx_http_upstream_check_broken_connection:
//! the upstream connection is closed, the access log has 499 and the error
//! log nginx's `[info]` line. `proxy_ignore_client_abort on` keeps the
//! exchange. Over TLS too (#489), where nginx checks the socket under it.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

/// The server stops when the test ends, also when an assertion panics.
struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Wait up to 5 s for `path` to contain `n` lines.
fn lines(path: &std::path::Path, n: usize) -> Vec<String> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        let lines: Vec<String> = text.lines().map(str::to_owned).collect();
        if lines.len() >= n || Instant::now() > deadline {
            return lines;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// An upstream that answers each request after 2 s and reports, per
/// connection, whether the proxy closed its side first.
fn backend() -> (u16, mpsc::Receiver<bool>) {
    let backend = TcpListener::bind("127.0.0.1:0").unwrap();
    let up = backend.local_addr().unwrap().port();
    let (closed_tx, closed_rx) = mpsc::channel::<bool>();
    std::thread::spawn(move || {
        for conn in backend.incoming() {
            let mut c = conn.unwrap();
            let closed_tx = closed_tx.clone();
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                let _ = c.read(&mut buf);
                c.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                // EOF before the answer: the proxy gave up the exchange.
                let early = matches!(c.read(&mut buf), Ok(0));
                let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
                let _ = closed_tx.send(early);
            });
        }
    });
    (up, closed_rx)
}

/// ruxen proxying to `up`, on `listen` (`""` or `" ssl"`) with `extra` in
/// its server block. Returns the server, its port and its directory.
fn start(name: &str, up: u16, listen: &str, extra: &str) -> (KillOnDrop, u16, PathBuf) {
    let dir = std::env::temp_dir().join(format!("ruxen-m125-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // Held until ruxen listens.
    let setup = common::ports::setup_lock();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let d = dir.display();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "worker_processes 1;\npid {d}/ruxen.pid;\nerror_log {d}/error.log info;\n\
             events {{}}\nhttp {{\n\
             log_format t '$request_uri $status $upstream_status $upstream_header_time $upstream_response_time';\naccess_log {d}/access.log t;\n\
             server {{ listen 127.0.0.1:{port}{listen}; {extra}\n\
             location / {{ proxy_pass http://127.0.0.1:{up}; }}\n\
             location /keep {{ proxy_ignore_client_abort on; proxy_pass http://127.0.0.1:{up}; }} }} }}\n"
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
    (child, port, dir)
}

/// nginx: `499 - - 0.497`: no status or header from the upstream, and the
/// time until the close.
fn assert_499(line: &str, path: &str) {
    let fields: Vec<&str> = line.split(' ').collect();
    assert_eq!(fields[..4], [path, "499", "-", "-"], "{line}");
    let rt: f64 = fields[4].parse().unwrap_or_else(|_| panic!("{line}"));
    assert!((0.1..2.0).contains(&rt), "{line}");
}

#[test]
fn a_client_gone_while_the_upstream_is_awaited_is_499() {
    let (up, closed_rx) = backend();
    let (_server, port, dir) = start("plain", up, "", "");

    let gone = |path: &str| {
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        write!(s, "GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        std::thread::sleep(Duration::from_millis(300));
        drop(s);
    };

    gone("/");
    assert!(
        closed_rx.recv_timeout(Duration::from_secs(5)).unwrap(),
        "the upstream connection outlived the client"
    );
    assert_499(&lines(&dir.join("access.log"), 1)[0], "/");
    let error_log = std::fs::read_to_string(dir.join("error.log")).unwrap();
    assert!(
        error_log.contains("[info] ")
            && error_log.contains(
                "client prematurely closed connection, so upstream connection is closed too"
            ),
        "{error_log}"
    );

    gone("/keep");
    assert!(
        !closed_rx.recv_timeout(Duration::from_secs(5)).unwrap(),
        "proxy_ignore_client_abort on: the exchange should have gone on"
    );
    assert!(
        lines(&dir.join("access.log"), 2)[1].starts_with("/keep 200 200 "),
        "{:?}",
        lines(&dir.join("access.log"), 2)
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Over TLS a client that closes cleanly sends a close_notify alert ahead
/// of its FIN: those bytes are no next request, the FIN behind them ends
/// the exchange. A request pipelined behind the first is no close.
#[test]
fn a_tls_client_gone_while_the_upstream_is_awaited_is_499() {
    let certs = common::tls::make_ca_and_leaf("localhost");
    let (up, closed_rx) = backend();
    let extra = format!(
        "ssl_certificate {}; ssl_certificate_key {};",
        certs.cert_path().display(),
        certs.key_path().display()
    );
    let (_server, port, dir) = start("tls", up, " ssl", &extra);

    let mut roots = rustls::RootCertStore::empty();
    let ca = std::fs::read(certs.ca_path().unwrap()).unwrap();
    for cert in
        <rustls::pki_types::CertificateDer as rustls::pki_types::pem::PemObject>::pem_slice_iter(
            &ca,
        )
    {
        roots.add(cert.unwrap()).unwrap();
    }
    let config = Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let connect = || {
        let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let conn = rustls::ClientConnection::new(config.clone(), name).unwrap();
        let sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        rustls::StreamOwned::new(conn, sock)
    };

    // close_notify, then the FIN.
    let mut s = connect();
    s.write_all(b"GET /notify HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .unwrap();
    std::thread::sleep(Duration::from_millis(300));
    s.conn.send_close_notify();
    s.flush().unwrap();
    drop(s);
    assert!(
        closed_rx.recv_timeout(Duration::from_secs(5)).unwrap(),
        "close_notify and FIN: the upstream connection outlived the client"
    );
    assert_499(&lines(&dir.join("access.log"), 1)[0], "/notify");

    // The FIN alone.
    let mut s = connect();
    s.write_all(b"GET /abrupt HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .unwrap();
    std::thread::sleep(Duration::from_millis(300));
    drop(s);
    assert!(
        closed_rx.recv_timeout(Duration::from_secs(5)).unwrap(),
        "FIN: the upstream connection outlived the client"
    );
    assert_499(&lines(&dir.join("access.log"), 2)[1], "/abrupt");

    // Two requests at once: both are answered.
    let mut s = connect();
    s.write_all(
        b"GET /first HTTP/1.1\r\nHost: localhost\r\n\r\n\
          GET /second HTTP/1.1\r\nHost: localhost\r\n\r\n",
    )
    .unwrap();
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    while got.windows(9).filter(|w| w == b"HTTP/1.1 ").count() < 2 || !got.ends_with(b"ok") {
        let n = s.read(&mut buf).unwrap();
        assert!(n > 0, "{}", String::from_utf8_lossy(&got));
        got.extend_from_slice(&buf[..n]);
    }
    for _ in 0..2 {
        assert!(
            !closed_rx.recv_timeout(Duration::from_secs(5)).unwrap(),
            "a pipelined request taken for a close"
        );
    }
    let log = lines(&dir.join("access.log"), 4);
    assert!(log[2].starts_with("/first 200 200 "), "{log:?}");
    assert!(log[3].starts_with("/second 200 200 "), "{log:?}");
    let _ = std::fs::remove_dir_all(&dir);
}
