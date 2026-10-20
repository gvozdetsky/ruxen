//! M149 — OCSP stapling (#141): `ssl_stapling_file` stapled as it is, and
//! responses fetched from the responder in the certificate (a GET with the
//! base64 request), verified, and stapled while they say `good`. The
//! first handshake goes without, as in nginx.

mod common;

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};

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

/// `setup` is the port lock, taken before the test picked its ports.
fn start(name: &str, setup: std::sync::MutexGuard<'static, ()>, http: &str) -> Server {
    let dir = std::env::temp_dir().join(format!("ruxen-m149-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "pid {d}/ruxen.pid;\nerror_log {d}/error.log info;\nevents {{}}\n\
             http {{\naccess_log off;\n{http}\n}}\n",
            d = dir.display(),
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

/// `openssl` with `command`'s words, in `dir`.
fn openssl(dir: &Path, command: &str) {
    let out = Command::new("openssl")
        .args(command.split_whitespace())
        .current_dir(dir)
        .output()
        .expect("openssl");
    assert!(
        out.status.success(),
        "openssl {command}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A root, an intermediate and `end` signed by it, made as ssl_stapling.t
/// makes them, with the OCSP responder `http://127.0.0.1:<responder>` in
/// `end`'s AIA; `noaia` has none. `good.der` and, once `end` is revoked,
/// `revoked.der` are the responder's answers for `end`, signed by the
/// intermediate; `by-root.der` says `good`, signed by the root.
fn make_pki(name: &str, responder: u16) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ruxen-m149-pki-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let d = dir.display();
    std::fs::write(
        dir.join("openssl.conf"),
        "[ req ]\ndefault_bits = 2048\nencrypt_key = no\n\
         distinguished_name = req_distinguished_name\nx509_extensions = ext\n\
         [ req_distinguished_name ]\n[ ext ]\nbasicConstraints = critical,CA:TRUE\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("ca.conf"),
        format!(
            "[ ca ]\ndefault_ca = myca\n[ myca ]\nnew_certs_dir = {d}\n\
             database = {d}/certindex\ndefault_md = sha256\npolicy = policy\n\
             serial = {d}/certserial\ndefault_days = 1\nx509_extensions = aia\n\
             [ policy ]\ncommonName = supplied\n\
             [ aia ]\nbasicConstraints = critical,CA:TRUE\n\
             authorityInfoAccess = OCSP;URI:http://127.0.0.1:{responder}\n\
             [ noaia ]\nbasicConstraints = critical,CA:TRUE\n"
        ),
    )
    .unwrap();
    std::fs::write(dir.join("certserial"), "1000").unwrap();
    std::fs::write(dir.join("certindex"), "").unwrap();
    openssl(
        &dir,
        "req -x509 -new -config openssl.conf -subj /CN=root/ -out root.crt -keyout root.key",
    );
    for n in ["int", "end", "noaia"] {
        openssl(
            &dir,
            &format!("req -new -config openssl.conf -subj /CN={n}/ -out {n}.csr -keyout {n}.key"),
        );
    }
    let ca = "ca -batch -config ca.conf";
    openssl(
        &dir,
        &format!("{ca} -keyfile root.key -cert root.crt -subj /CN=int/ -in int.csr -out int.crt"),
    );
    openssl(
        &dir,
        &format!("{ca} -keyfile int.key -cert int.crt -subj /CN=end/ -in end.csr -out end.crt"),
    );
    openssl(
        &dir,
        &format!(
            "{ca} -extensions noaia -keyfile int.key -cert int.crt -subj /CN=noaia/ \
             -in noaia.csr -out noaia.crt"
        ),
    );
    let cat = |out: &str, a: &str, b: &str| {
        let mut both = std::fs::read(dir.join(a)).unwrap();
        both.extend(std::fs::read(dir.join(b)).unwrap());
        std::fs::write(dir.join(out), both).unwrap();
    };
    cat("end-int.crt", "end.crt", "int.crt");
    cat("noaia-int.crt", "noaia.crt", "int.crt");
    openssl(&dir, "ocsp -issuer int.crt -cert end.crt -reqout req.der");
    let respond = |signer: &str, out: &str| {
        openssl(
            &dir,
            &format!(
                "ocsp -index certindex -CA int.crt -rsigner {signer}.crt -rkey {signer}.key \
                 -reqin req.der -respout {out} -ndays 1"
            ),
        );
    };
    respond("int", "good.der");
    // Signed by the root, which isn't `end`'s issuer: trusted only where
    // OCSP signing is explicitly trusted ("root ca not trusted").
    respond("root", "by-root.der");
    openssl(
        &dir,
        &format!("{ca} -revoke end.crt -keyfile int.key -cert int.crt"),
    );
    respond("int", "revoked.der");
    dir
}

/// A responder that answers every request with `answer`, and keeps the
/// request heads it got.
struct Responder {
    port: u16,
    answer: Arc<Mutex<Vec<u8>>>,
    heads: Arc<Mutex<Vec<String>>>,
}

fn responder() -> Responder {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let answer = Arc::new(Mutex::new(Vec::new()));
    let heads = Arc::new(Mutex::new(Vec::new()));
    let (a, h) = (answer.clone(), heads.clone());
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut conn) = conn else { continue };
            let mut reader = BufReader::new(conn.try_clone().unwrap());
            let mut head = String::new();
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                    break;
                }
                head.push_str(&line);
            }
            h.lock().unwrap().push(head);
            let body = a.lock().unwrap().clone();
            let _ = conn
                .write_all(b"HTTP/1.0 200 OK\r\nContent-Type: application/ocsp-response\r\n\r\n");
            let _ = conn.write_all(&body);
        }
    });
    Responder {
        port,
        answer,
        heads,
    }
}

/// Takes any server certificate, and keeps the OCSP response stapled to
/// it.
#[derive(Debug)]
struct Stapled(Arc<rustls::crypto::CryptoProvider>, Mutex<Option<Vec<u8>>>);

impl ServerCertVerifier for Stapled {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        ocsp_response: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        *self.1.lock().unwrap() = (!ocsp_response.is_empty()).then(|| ocsp_response.to_vec());
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// One handshake with `port` over `version`: the OCSP response stapled,
/// if any.
fn staple(port: u16, version: &'static rustls::SupportedProtocolVersion) -> Option<Vec<u8>> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let verifier = Arc::new(Stapled(provider.clone(), Mutex::new(None)));
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[version])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(verifier.clone())
        .with_no_client_auth();
    let mut conn =
        rustls::ClientConnection::new(Arc::new(config), ServerName::try_from("localhost").unwrap())
            .unwrap();
    let mut tcp = TcpStream::connect(("127.0.0.1", port)).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    while conn.is_handshaking() {
        conn.complete_io(&mut tcp).unwrap();
    }
    verifier.1.lock().unwrap().take()
}

/// The first handshake's staple, then the one of the first handshake
/// within 5 s that has one, or the last's.
fn staples(port: u16) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
    let first = staple(port, &rustls::version::TLS13);
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        std::thread::sleep(Duration::from_millis(50));
        let later = staple(port, &rustls::version::TLS13);
        if later.is_some() || Instant::now() > deadline {
            return (first, later);
        }
    }
}

#[test]
fn stapling_file_is_stapled_as_it_is() {
    let pki = make_pki("file", 9);
    let p = pki.display();
    let setup = common::ports::setup_lock();
    let port = free_port();
    let _s = start(
        "file",
        setup,
        &format!(
            "server {{ listen 127.0.0.1:{port} ssl; ssl_certificate {p}/end-int.crt; \
             ssl_certificate_key {p}/end.key; ssl_stapling on; \
             ssl_stapling_file {p}/revoked.der; }}"
        ),
    );
    // Whatever it says: a revoked one too, from the first handshake on.
    let revoked = std::fs::read(pki.join("revoked.der")).unwrap();
    assert_eq!(
        staple(port, &rustls::version::TLS13).as_ref(),
        Some(&revoked)
    );
    assert_eq!(
        staple(port, &rustls::version::TLS12).as_ref(),
        Some(&revoked)
    );
    let _ = std::fs::remove_dir_all(&pki);
}

#[test]
fn responses_are_fetched_verified_and_stapled() {
    let r = responder();
    let pki = make_pki("fetch", r.port);
    let p = pki.display();
    let good = std::fs::read(pki.join("good.der")).unwrap();
    *r.answer.lock().unwrap() = good.clone();
    let setup = common::ports::setup_lock();
    let port = free_port();
    let s = start(
        "fetch",
        setup,
        &format!(
            "server {{ listen 127.0.0.1:{port} ssl; ssl_certificate {p}/end-int.crt; \
             ssl_certificate_key {p}/end.key; ssl_stapling on; ssl_stapling_verify on; \
             ssl_trusted_certificate {p}/root.crt; }}"
        ),
    );
    let (first, later) = staples(port);
    assert_eq!(first, None, "the first handshake goes without");
    assert_eq!(later.as_ref(), Some(&good));
    assert_eq!(staple(port, &rustls::version::TLS12).as_ref(), Some(&good));
    // One fetch, a GET with the request base64'd and escaped after the
    // responder's URI.
    let heads = r.heads.lock().unwrap().clone();
    assert_eq!(heads.len(), 1, "{heads:?}");
    let target = heads[0]
        .strip_prefix("GET /")
        .and_then(|h| h.split_once(" HTTP/1.0\r\nHost: 127.0.0.1\r\n"))
        .map(|(t, _)| t)
        .unwrap_or_else(|| panic!("{}", heads[0]));
    assert!(target.starts_with("MEMwQTA"), "{target}");
    assert!(!target.contains(['/', '+', '=']), "{target}");
    let log = std::fs::read_to_string(s.dir.join("error.log")).unwrap();
    assert!(!log.contains("[error]") && !log.contains("[crit]"), "{log}");
    // An IPv4 address isn't resolved, so no resolver is missed.
    assert!(!log.contains("no resolver defined"), "{log}");
    let _ = std::fs::remove_dir_all(&pki);
}

#[test]
fn bad_responses_are_not_stapled() {
    let r = responder();
    let pki = make_pki("bad", r.port);
    let p = pki.display();
    *r.answer.lock().unwrap() = std::fs::read(pki.join("revoked.der")).unwrap();
    let setup = common::ports::setup_lock();
    let [revoked, untrusted] = common::ports::free_ports();
    let s = start(
        "bad",
        setup,
        &format!(
            "ssl_certificate {p}/end-int.crt; ssl_certificate_key {p}/end.key; ssl_stapling on;\n\
             server {{ listen 127.0.0.1:{revoked} ssl; }}\n\
             server {{ listen 127.0.0.1:{untrusted} ssl; ssl_stapling_verify on; \
             ssl_trusted_certificate {p}/root.crt; \
             ssl_stapling_responder http://127.0.0.1:{}/ocsp; }}",
            r.port
        ),
    );
    let log_has = |what: &str| {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let log = std::fs::read_to_string(s.dir.join("error.log")).unwrap_or_default();
            if log.contains(what) {
                return;
            }
            assert!(Instant::now() < deadline, "no {what:?} in\n{log}");
            std::thread::sleep(Duration::from_millis(50));
        }
    };
    assert_eq!(staple(revoked, &rustls::version::TLS13), None);
    log_has(&format!(
        "certificate status \"revoked\" in the OCSP response while requesting \
         certificate status, responder: 127.0.0.1, peer: 127.0.0.1:{}, certificate: \"{p}/end-int.crt\"",
        r.port
    ));
    assert_eq!(staple(revoked, &rustls::version::TLS13), None);
    // Signed by the root, which doesn't issue `end`, with
    // `ssl_stapling_verify`: refused, as in ssl_stapling.t.
    *r.answer.lock().unwrap() = std::fs::read(pki.join("by-root.der")).unwrap();
    assert_eq!(staple(untrusted, &rustls::version::TLS13), None);
    log_has("OCSP_basic_verify() failed (SSL: ");
    log_has("ROOT_CA_NOT_TRUSTED");
    assert_eq!(staple(untrusted, &rustls::version::TLS13), None);
    let heads = r.heads.lock().unwrap().clone();
    assert!(
        heads.iter().any(|h| h.starts_with("GET /ocsp/MEMwQTA")),
        "{heads:?}"
    );
    let _ = std::fs::remove_dir_all(&pki);
}

/// A name server on UDP that answers `localhost` with 127.0.0.1 (A), or
/// every name with NXDOMAIN when `nx`; and the number of queries for
/// `localhost` it got.
fn dns(nx: bool) -> (u16, Arc<Mutex<u32>>) {
    let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = udp.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(0));
    let s = seen.clone();
    std::thread::spawn(move || {
        let mut buf = [0u8; 512];
        while let Ok((n, from)) = udp.recv_from(&mut buf) {
            let query = &buf[..n];
            let mut i = 12;
            while query[i] != 0 {
                i += 1 + query[i] as usize;
            }
            let qtype = u16::from_be_bytes([query[i + 1], query[i + 2]]);
            if &query[12..i] == b"\x09localhost" {
                *s.lock().unwrap() += 1;
            }
            let a = !nx && qtype == 1 && &query[12..i] == b"\x09localhost";
            let mut reply = query[..2].to_vec();
            reply.extend_from_slice(&[0x81, if nx { 0x83 } else { 0x80 }, 0, 1, 0, a as u8]);
            reply.extend_from_slice(&[0, 0, 0, 0]);
            reply.extend_from_slice(&query[12..i + 5]);
            if a {
                reply.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1]);
            }
            let _ = udp.send_to(&reply, from);
        }
    });
    (port, seen)
}

#[test]
fn responder_names_are_resolved_on_each_fetch() {
    let r = responder();
    let pki = make_pki("resolve", r.port);
    let p = pki.display();
    let good = std::fs::read(pki.join("good.der")).unwrap();
    *r.answer.lock().unwrap() = good.clone();
    let (dns_port, dns_seen) = dns(false);
    let (nx_port, nx_seen) = dns(true);
    let setup = common::ports::setup_lock();
    let [none, resolved, unresolved] = common::ports::free_ports();
    let s = start(
        "resolve",
        setup,
        &format!(
            "ssl_certificate {p}/end-int.crt; ssl_certificate_key {p}/end.key; ssl_stapling on;\n\
             ssl_stapling_responder http://localhost:{}/;\n\
             server {{ listen 127.0.0.1:{none} ssl; }}\n\
             server {{ listen 127.0.0.1:{resolved} ssl; resolver 127.0.0.1:{dns_port}; }}\n\
             server {{ listen 127.0.0.1:{unresolved} ssl; resolver 127.0.0.1:{nx_port}; \
             resolver_timeout 2s; }}",
            r.port
        ),
    );
    let log_has = |what: &str| {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let log = std::fs::read_to_string(s.dir.join("error.log")).unwrap_or_default();
            if log.contains(what) {
                return log;
            }
            assert!(Instant::now() < deadline, "no {what:?} in\n{log}");
            std::thread::sleep(Duration::from_millis(50));
        }
    };
    // Without a resolver: the startup addresses, with a warning.
    assert_eq!(staples(none).1.as_ref(), Some(&good));
    let warning = format!(
        "no resolver defined to resolve localhost while requesting certificate status, \
         responder: localhost, certificate: \"{p}/end-int.crt\""
    );
    let log = log_has(&warning);
    let line = log.lines().find(|l| l.contains(&warning)).unwrap();
    assert!(line.contains("[warn]"), "{line}");
    // With one: asked on the fetch.
    assert_eq!(*dns_seen.lock().unwrap(), 0);
    assert_eq!(staples(resolved).1.as_ref(), Some(&good));
    assert!(*dns_seen.lock().unwrap() > 0);
    // A name it doesn't know fails the fetch.
    assert_eq!(staple(unresolved, &rustls::version::TLS13), None);
    let log = log_has(&format!(
        "localhost could not be resolved (3: Host not found) while requesting certificate \
         status, responder: localhost, certificate: \"{p}/end-int.crt\""
    ));
    assert!(*nx_seen.lock().unwrap() > 0);
    assert_eq!(staple(unresolved, &rustls::version::TLS13), None);
    assert_eq!(log.matches("no resolver defined").count(), 1, "{log}");
    assert_eq!(r.heads.lock().unwrap().len(), 2);
    let _ = std::fs::remove_dir_all(&pki);
}

#[test]
fn stapling_problems_at_startup_are_nginx_s() {
    let pki = make_pki("startup", 9);
    let p = pki.display();
    std::fs::write(pki.join("bad.der"), "garbage\n").unwrap();
    let check = |http: &str| {
        let conf = pki.join("nginx.conf");
        std::fs::write(&conf, format!("events {{}}\nhttp {{\n{http}\n}}\n")).unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_ruxen"))
            .arg("-t")
            .arg("-c")
            .arg(&conf)
            .output()
            .unwrap();
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    };
    let (ok, stderr) = check(&format!(
        "ssl_stapling on;\n\
         server {{ listen 127.0.0.1:1 ssl; ssl_certificate {p}/noaia-int.crt; ssl_certificate_key {p}/noaia.key; }}\n\
         server {{ listen 127.0.0.1:2 ssl; ssl_certificate {p}/end.crt; ssl_certificate_key {p}/end.key; }}\n\
         server {{ listen 127.0.0.1:3 ssl; ssl_certificate {p}/end-int.crt; ssl_certificate_key {p}/end.key; \
         ssl_stapling_responder https://127.0.0.1/; }}"
    ));
    assert!(ok, "{stderr}");
    for line in [
        format!(
            "ruxen: [warn] \"ssl_stapling\" ignored, no OCSP responder URL in the certificate \"{p}/noaia-int.crt\""
        ),
        format!(
            "ruxen: [warn] \"ssl_stapling\" ignored, issuer certificate not found for certificate \"{p}/end.crt\""
        ),
        format!(
            "ruxen: [warn] \"ssl_stapling\" ignored, invalid URL prefix in OCSP responder \"https://127.0.0.1/\" in the certificate \"{p}/end-int.crt\""
        ),
    ] {
        assert!(stderr.contains(&line), "no {line:?} in\n{stderr}");
    }
    let (ok, stderr) = check(&format!(
        "server {{ listen 127.0.0.1:1 ssl; ssl_certificate {p}/end-int.crt; ssl_certificate_key {p}/end.key; \
         ssl_stapling on; ssl_stapling_file {p}/bad.der; }}"
    ));
    assert!(!ok);
    assert!(
        stderr.contains(&format!(
            "[emerg] d2i_OCSP_RESPONSE_bio(\"{p}/bad.der\") failed (SSL: "
        )),
        "{stderr}"
    );
    // Without `ssl_stapling on`, the file isn't read.
    let (ok, stderr) = check(&format!(
        "server {{ listen 127.0.0.1:1 ssl; ssl_certificate {p}/end-int.crt; ssl_certificate_key {p}/end.key; \
         ssl_stapling_file {p}/bad.der; }}"
    ));
    assert!(ok, "{stderr}");
    let _ = std::fs::remove_dir_all(&pki);
}
