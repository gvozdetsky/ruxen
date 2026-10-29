//! M166 — `ssl_conf_command Options KTLS` (#673): after the handshake the
//! kernel seals and opens the records, and `sendfile` sends file bodies.
//! Where the `tls` module isn't loaded the connections stay in userspace;
//! the answers are the same either way, and with the module the kernel's
//! counters show the switch. Both io_uring and epoll.

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// `/proc/net/tls_stat`'s connections switched so far; `None` without the
/// `tls` module, where ruxen can't switch either.
fn ktls_tx_count() -> Option<u64> {
    let stat = std::fs::read_to_string("/proc/net/tls_stat").ok()?;
    stat.lines()
        .find_map(|l| l.strip_prefix("TlsTxSw"))
        .and_then(|v| v.trim().parse().ok())
}

fn client_config(ca_pem: &Path, suite: rustls::SupportedCipherSuite) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    let pem = std::fs::read(ca_pem).unwrap();
    for cert in
        <rustls::pki_types::CertificateDer as rustls::pki_types::pem::PemObject>::pem_slice_iter(
            &pem,
        )
    {
        roots.add(cert.unwrap()).unwrap();
    }
    let provider = rustls::crypto::CryptoProvider {
        cipher_suites: vec![suite],
        ..rustls::crypto::aws_lc_rs::default_provider()
    };
    let version = match suite {
        rustls::SupportedCipherSuite::Tls13(_) => &rustls::version::TLS13,
        rustls::SupportedCipherSuite::Tls12(_) => &rustls::version::TLS12,
    };
    Arc::new(
        rustls::ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[version])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

type Client = rustls::StreamOwned<rustls::ClientConnection, TcpStream>;

fn connect(port: u16, config: &Arc<rustls::ClientConfig>) -> Client {
    let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let conn = rustls::ClientConnection::new(config.clone(), name).unwrap();
    let sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    rustls::StreamOwned::new(conn, sock)
}

/// One Content-Length framed response off `c`: status line and body.
fn read_response(c: &mut Client) -> std::io::Result<(String, Vec<u8>)> {
    let mut got = Vec::new();
    let mut buf = [0u8; 16384];
    loop {
        if let Some(i) = got.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&got[..i]).into_owned();
            let len: usize = head
                .lines()
                .find_map(|l| l.strip_prefix("Content-Length: "))
                .map_or(0, |v| v.trim().parse().unwrap());
            while got.len() < i + 4 + len {
                let n = c.read(&mut buf)?;
                if n == 0 {
                    return Err(std::io::ErrorKind::UnexpectedEof.into());
                }
                got.extend_from_slice(&buf[..n]);
            }
            let status = head.lines().next().unwrap_or_default().to_string();
            return Ok((status, got[i + 4..i + 4 + len].to_vec()));
        }
        let n = c.read(&mut buf)?;
        if n == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        got.extend_from_slice(&buf[..n]);
    }
}

#[test]
fn m166_ktls_serves_the_same_bytes() {
    for driver in ["io_uring", "epoll"] {
        serve_over_ktls(driver);
    }
}

fn serve_over_ktls(driver: &str) {
    let certs = common::tls::make_ca_and_leaf("localhost");
    let ca = certs.ca_path().unwrap().to_path_buf();
    let dir = std::env::temp_dir().join(format!("ruxen-m166-{}-{driver}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("www")).unwrap();
    // Not a multiple of a record or a page.
    let big: Vec<u8> = (0..1_234_567u32)
        .map(|i| ((i * 2_654_435_761) >> 13) as u8)
        .collect();
    std::fs::write(dir.join("www/big.bin"), &big).unwrap();
    std::fs::write(dir.join("www/small.txt"), "hello\n").unwrap();
    let setup = common::ports::setup_lock();
    let [port] = common::ports::free_ports();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "pid {d}/ruxen.pid;\nerror_log {d}/error.log info;\nevents {{}}\nhttp {{ access_log off; sendfile on;\n\
             server {{ listen 127.0.0.1:{port} ssl; ssl_certificate {c}; ssl_certificate_key {k};\n\
             ssl_conf_command Options KTLS;\n\
             root {d}/www; }} }}\n",
            d = dir.display(),
            c = certs.cert_path().display(),
            k = certs.key_path().display()
        ),
    )
    .unwrap();
    let mut child = KillOnDrop(
        Command::new(env!("CARGO_BIN_EXE_ruxen"))
            .arg("-c")
            .arg(dir.join("nginx.conf"))
            .env("RUXEN_DRIVER", driver)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    common::ports::wait_for_pid_file(&mut child.0, &dir.join("ruxen.pid"), Duration::from_secs(5));
    drop(setup);
    let before = ktls_tx_count();

    let suites = rustls::crypto::aws_lc_rs::default_provider().cipher_suites;
    let mut connections = 0;
    // The certificate is ECDSA: not the TLS 1.2 `_RSA_` suites.
    for &suite in suites
        .iter()
        .filter(|s| !format!("{:?}", s.suite()).contains("_RSA_"))
    {
        let config = client_config(&ca, suite);
        // The first request goes with the client's Finished, ahead of the
        // switch; the second after it, and the server closes.
        let mut c = connect(port, &config);
        c.write_all(b"GET /big.bin HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .unwrap();
        let (status, body) = read_response(&mut c).unwrap();
        assert_eq!(status, "HTTP/1.1 200 OK", "{suite:?} ({driver})");
        assert!(body == big, "{suite:?} ({driver}): body differs");
        c.write_all(b"GET /small.txt HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .unwrap();
        let (status, body) = read_response(&mut c).unwrap();
        assert_eq!(
            (status.as_str(), &body[..]),
            ("HTTP/1.1 200 OK", &b"hello\n"[..])
        );
        // close_notify ends it: rustls calls a bare FIN an error.
        let mut rest = Vec::new();
        c.read_to_end(&mut rest)
            .unwrap_or_else(|e| panic!("{suite:?} ({driver}): {e}"));
        assert!(rest.is_empty());
        connections += 1;

        // A client that sends close_notify right after its request still
        // gets the response.
        let mut c = connect(port, &config);
        c.write_all(b"GET /small.txt HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .unwrap();
        c.conn.send_close_notify();
        c.flush().unwrap();
        let (status, body) = read_response(&mut c).unwrap();
        assert_eq!(
            (status.as_str(), &body[..]),
            ("HTTP/1.1 200 OK", &b"hello\n"[..])
        );
        connections += 1;
    }

    // TLS 1.3 KeyUpdates (#852), each asking for ours: the next keys on
    // both sides, a few generations, every TLS 1.3 suite (SHA-384 too).
    let mut updated = Vec::new();
    for &suite in suites
        .iter()
        .filter(|s| matches!(s, rustls::SupportedCipherSuite::Tls13(_)))
    {
        let mut c = connect(port, &client_config(&ca, suite));
        c.write_all(b"GET /small.txt HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .unwrap();
        read_response(&mut c).unwrap();
        let mut result = Ok(());
        for _ in 0..3 {
            c.conn.refresh_traffic_keys().unwrap();
            result = c
                .write_all(b"GET /big.bin HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .and_then(|()| read_response(&mut c))
                .map(|(_, body)| assert!(body == big, "{suite:?} ({driver}): body differs"));
            if result.is_err() {
                break;
            }
        }
        updated.push((suite, result));
        connections += 1;
    }

    if let (Some(before), Some(after)) = (before, ktls_tx_count()) {
        // Other tests may switch connections too, never fewer.
        assert!(
            after - before >= connections,
            "{} of {connections} connections on kTLS ({driver})",
            after - before
        );
    }
    // Without kTLS rustls updates the keys; with it the kernel does, where
    // it takes new keys (Linux 6.14, `TlsRxRekeyOk`), else the connection
    // closes.
    let rekeys = ktls_tx_count().is_none()
        || std::fs::read_to_string("/proc/net/tls_stat").is_ok_and(|s| s.contains("TlsRxRekeyOk"));
    for (suite, result) in updated {
        assert_eq!(result.is_ok(), rekeys, "{suite:?} ({driver}): {result:?}");
    }
    let log = std::fs::read_to_string(dir.join("error.log")).unwrap_or_default();
    assert!(!log.contains("[alert]") && !log.contains("[crit]"), "{log}");
    drop(child);
    let _ = std::fs::remove_dir_all(&dir);
}
