//! M165 — `ssl_ocsp` (#142): a client certificate's revocation status is
//! read from its OCSP responder before the first request, as nginx reads
//! it, and a certificate that isn't `good`, or whose status can't be read,
//! is refused with 495 and `$ssl_client_verify` saying why.

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
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

fn conf_dir(name: &str, http: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ruxen-m165-{name}-{}", std::process::id()));
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
    dir
}

/// `setup` is the port lock, taken before the test picked its ports.
fn start(name: &str, setup: std::sync::MutexGuard<'static, ()>, http: &str) -> Server {
    let dir = conf_dir(name, http);
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

/// `ruxen -t` of `http`: whether it passes, and what it said.
fn check(name: &str, http: &str) -> (bool, String) {
    let dir = conf_dir(name, http);
    let out = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .arg("-t")
        .arg("-c")
        .arg(dir.join("nginx.conf"))
        .output()
        .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

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

/// As ssl_ocsp.t makes them: a root, `int` signed by it with the responder
/// `http://127.0.0.1:<int_responder>` in its AIA, and `end` signed by
/// `int` with `http://127.0.0.1:<end_responder>`. The answers: `good.der`
/// and `revoked.der` for `end` (signed by `int`), `int-good.der` for `int`
/// (signed by the root).
fn make_pki(name: &str, end_responder: u16, int_responder: u16) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ruxen-m165-pki-{name}-{}", std::process::id()));
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
             serial = {d}/certserial\ndefault_days = 1\nx509_extensions = to_end\n\
             [ policy ]\ncommonName = supplied\n\
             [ to_end ]\nbasicConstraints = critical,CA:TRUE\n\
             authorityInfoAccess = OCSP;URI:http://127.0.0.1:{end_responder}\n\
             [ to_int ]\nbasicConstraints = critical,CA:TRUE\n\
             authorityInfoAccess = OCSP;URI:http://127.0.0.1:{int_responder}\n"
        ),
    )
    .unwrap();
    std::fs::write(dir.join("certserial"), "1000").unwrap();
    std::fs::write(dir.join("certindex"), "").unwrap();
    openssl(
        &dir,
        "req -x509 -new -config openssl.conf -subj /CN=root/ -out root.crt -keyout root.key",
    );
    for n in ["int", "end"] {
        openssl(
            &dir,
            &format!("req -new -config openssl.conf -subj /CN={n}/ -out {n}.csr -keyout {n}.key"),
        );
    }
    let ca = "ca -batch -config ca.conf";
    openssl(
        &dir,
        &format!(
            "{ca} -extensions to_int -keyfile root.key -cert root.crt -subj /CN=int/ \
             -in int.csr -out int.crt"
        ),
    );
    openssl(
        &dir,
        &format!("{ca} -keyfile int.key -cert int.crt -subj /CN=end/ -in end.csr -out end.crt"),
    );
    let mut trusted = std::fs::read(dir.join("int.crt")).unwrap();
    trusted.extend(std::fs::read(dir.join("root.crt")).unwrap());
    std::fs::write(dir.join("trusted.crt"), trusted).unwrap();
    openssl(&dir, "ocsp -issuer int.crt -cert end.crt -reqout req.der");
    openssl(
        &dir,
        "ocsp -issuer root.crt -cert int.crt -reqout int-req.der",
    );
    let respond = |ca: &str, req: &str, out: &str| {
        openssl(
            &dir,
            &format!(
                "ocsp -index certindex -CA {ca}.crt -rsigner {ca}.crt -rkey {ca}.key \
                 -reqin {req} -respout {out} -ndays 1"
            ),
        );
    };
    respond("int", "req.der", "good.der");
    respond("root", "int-req.der", "int-good.der");
    openssl(
        &dir,
        &format!("{ca} -revoke end.crt -keyfile int.key -cert int.crt"),
    );
    respond("int", "req.der", "revoked.der");
    dir
}

/// A responder that answers every request with `answer`, and counts them.
struct Responder {
    port: u16,
    answer: Arc<Mutex<Vec<u8>>>,
    asked: Arc<Mutex<usize>>,
}

fn responder() -> Responder {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let answer = Arc::new(Mutex::new(Vec::new()));
    let asked = Arc::new(Mutex::new(0));
    let (a, n) = (answer.clone(), asked.clone());
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut conn) = conn else { continue };
            let mut reader = BufReader::new(conn.try_clone().unwrap());
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                    break;
                }
            }
            *n.lock().unwrap() += 1;
            let body = a.lock().unwrap().clone();
            let _ = conn
                .write_all(b"HTTP/1.0 200 OK\r\nContent-Type: application/ocsp-response\r\n\r\n");
            let _ = conn.write_all(&body);
        }
    });
    Responder {
        port,
        answer,
        asked,
    }
}

impl Responder {
    fn answer(&self, pki: &Path, file: &str) {
        *self.answer.lock().unwrap() = std::fs::read(pki.join(file)).unwrap();
    }

    fn asked(&self) -> usize {
        *self.asked.lock().unwrap()
    }
}

#[derive(Debug)]
struct AnyServer(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for AnyServer {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
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

/// One request on its own connection with `end`'s certificate: the
/// status and the body.
fn get(port: u16, pki: &Path) -> (u16, String) {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let chain = <CertificateDer as rustls::pki_types::pem::PemObject>::pem_slice_iter(
        &std::fs::read(pki.join("end.crt")).unwrap(),
    )
    .collect::<Result<Vec<_>, _>>()
    .unwrap();
    let key: PrivateKeyDer<'static> = rustls::pki_types::pem::PemObject::from_pem_slice(
        &std::fs::read(pki.join("end.key")).unwrap(),
    )
    .unwrap();
    let config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyServer(provider)))
        .with_client_auth_cert(chain, key)
        .unwrap();
    let conn =
        rustls::ClientConnection::new(Arc::new(config), ServerName::try_from("localhost").unwrap())
            .unwrap();
    let tcp = TcpStream::connect(("127.0.0.1", port)).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut tls = rustls::StreamOwned::new(conn, tcp);
    write!(
        tls,
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut response = Vec::new();
    let _ = tls.read_to_end(&mut response);
    let response = String::from_utf8_lossy(&response).into_owned();
    let status = response
        .get(9..12)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = response
        .split_once("\r\n\r\n")
        .map_or("", |(_, b)| b)
        .to_string();
    (status, body)
}

#[test]
fn client_certificates_are_checked_with_ocsp() {
    let end_responder = responder();
    let int_responder = responder();
    let pki = make_pki("check", end_responder.port, int_responder.port);
    let p = pki.display();
    end_responder.answer(&pki, "good.der");
    int_responder.answer(&pki, "int-good.der");
    let setup = common::ports::setup_lock();
    let [leaf, on, cached] = common::ports::free_ports();
    let s = start(
        "check",
        setup,
        &format!(
            "ssl_certificate {p}/root.crt; ssl_certificate_key {p}/root.key;\n\
             ssl_verify_client on; ssl_verify_depth 2; ssl_client_certificate {p}/trusted.crt;\n\
             ssl_ocsp leaf;\n\
             error_page 495 /denied;\n\
             server {{ listen 127.0.0.1:{leaf} ssl;\n\
               location / {{ return 200 \"$ssl_client_verify\"; }}\n\
               location = /denied {{ return 403 \"$ssl_client_verify\"; }} }}\n\
             server {{ listen 127.0.0.1:{on} ssl; ssl_ocsp on;\n\
               location / {{ return 200 \"$ssl_client_verify\"; }}\n\
               location = /denied {{ return 403 \"$ssl_client_verify\"; }} }}\n\
             server {{ listen 127.0.0.1:{cached} ssl; ssl_ocsp_cache shared:OCSP:1m;\n\
               location / {{ return 200 \"$ssl_client_verify\"; }}\n\
               location = /denied {{ return 403 \"$ssl_client_verify\"; }} }}"
        ),
    );
    let success = (200, "SUCCESS".to_string());
    let refused = |why: &str| (403, format!("FAILED:{why}"));

    // `leaf` asks about `end` only; `on` about `int` too, each at its
    // AIA responder.
    assert_eq!(get(leaf, &pki), success);
    assert_eq!((end_responder.asked(), int_responder.asked()), (1, 0));
    assert_eq!(get(on, &pki), success);
    assert_eq!((end_responder.asked(), int_responder.asked()), (2, 1));
    assert_eq!(get(cached, &pki), success);
    assert_eq!(end_responder.asked(), 3);

    // A status that can't be read fails, at any certificate.
    *int_responder.answer.lock().unwrap() = b"not a response".to_vec();
    assert_eq!(get(on, &pki), refused("certificate status request failed"));
    assert_eq!(get(leaf, &pki), success);

    // Revoked: refused, but not where the cache still says `good`, which
    // isn't asked again.
    end_responder.answer(&pki, "revoked.der");
    assert_eq!(get(leaf, &pki), refused("certificate revoked"));
    assert_eq!(get(on, &pki), refused("certificate revoked"));
    let asked = end_responder.asked();
    assert_eq!(get(cached, &pki), success);
    assert_eq!(end_responder.asked(), asked);

    // A responder that doesn't answer: refused too.
    drop(end_responder);
    let log = std::fs::read_to_string(s.dir.join("error.log")).unwrap();
    assert!(
        log.contains("client SSL certificate verify error: certificate revoked"),
        "{log}"
    );
    assert!(
        log.contains("d2i_OCSP_RESPONSE() failed")
            && log.contains(&format!(
                "while requesting certificate status, responder: 127.0.0.1, peer: 127.0.0.1:{}",
                int_responder.port
            )),
        "{log}"
    );
    assert!(!log.contains("[crit]"), "{log}");
    let _ = std::fs::remove_dir_all(&pki);
}

#[test]
fn responder_names_need_a_resolver() {
    // A certificate's responder named, not an address: without `resolver`
    // the status can't be read (ssl_ocsp.t, "ocsp many failed request").
    let r = responder();
    let pki = make_pki("name", r.port, r.port);
    let p = pki.display();
    std::fs::write(
        pki.join("byname.conf"),
        format!(
            "[ ca ]\ndefault_ca = myca\n[ myca ]\nnew_certs_dir = {p}\n\
             database = {p}/certindex\ndefault_md = sha256\npolicy = policy\n\
             serial = {p}/certserial\ndefault_days = 1\nx509_extensions = ext\n\
             [ policy ]\ncommonName = supplied\n\
             [ ext ]\nbasicConstraints = critical,CA:TRUE\n\
             authorityInfoAccess = OCSP;URI:http://localhost:{}\n",
            r.port
        ),
    )
    .unwrap();
    openssl(
        &pki,
        "ca -batch -config byname.conf -keyfile int.key -cert int.crt -subj /CN=end/ \
         -in end.csr -out end.crt",
    );
    let setup = common::ports::setup_lock();
    let port = common::ports::free_ports::<1>()[0];
    let s = start(
        "name",
        setup,
        &format!(
            "server {{ listen 127.0.0.1:{port} ssl;\n\
               ssl_certificate {p}/root.crt; ssl_certificate_key {p}/root.key;\n\
               ssl_verify_client on; ssl_verify_depth 2; ssl_client_certificate {p}/trusted.crt;\n\
               ssl_ocsp leaf; error_page 495 /denied;\n\
               location / {{ return 200 \"$ssl_client_verify\"; }}\n\
               location = /denied {{ return 403 \"$ssl_client_verify\"; }} }}"
        ),
    );
    assert_eq!(
        get(port, &pki),
        (403, "FAILED:certificate status request failed".into())
    );
    assert_eq!(r.asked(), 0);
    let log = std::fs::read_to_string(s.dir.join("error.log")).unwrap();
    assert!(
        log.lines().any(|l| l.contains("[error]")
            && l.ends_with(
                "*1 no resolver defined to resolve localhost while requesting certificate \
                 status, responder: localhost"
            )),
        "{log}"
    );
    let _ = std::fs::remove_dir_all(&pki);
}

#[test]
fn a_silent_responder_ends_with_the_handshake_timeout() {
    // Connects, never answers: the check waits as nginx's handshake does,
    // until client_header_timeout, and the connection closes.
    let silent = TcpListener::bind("127.0.0.1:0").unwrap();
    let r = silent.local_addr().unwrap().port();
    let pki = make_pki("silent", r, r);
    let p = pki.display();
    let setup = common::ports::setup_lock();
    let port = common::ports::free_ports::<1>()[0];
    let s = start(
        "silent",
        setup,
        &format!(
            "server {{ listen 127.0.0.1:{port} ssl; client_header_timeout 1s;\n\
               ssl_certificate {p}/root.crt; ssl_certificate_key {p}/root.key;\n\
               ssl_verify_client on; ssl_verify_depth 2; ssl_client_certificate {p}/trusted.crt;\n\
               ssl_ocsp leaf;\n\
               location / {{ return 200 \"$ssl_client_verify\"; }} }}"
        ),
    );
    let started = std::time::Instant::now();
    assert_eq!(get(port, &pki).0, 0);
    let took = started.elapsed();
    assert!(
        took >= Duration::from_millis(900) && took < Duration::from_secs(5),
        "{took:?}"
    );
    let log = std::fs::read_to_string(s.dir.join("error.log")).unwrap();
    assert!(
        log.contains("client timed out (110: Connection timed out) while SSL handshaking"),
        "{log}"
    );
    drop(silent);
    let _ = std::fs::remove_dir_all(&pki);
}

#[test]
fn ssl_ocsp_configuration_errors() {
    let ca = common::tls::make_self_signed("ca.test");
    let tls = format!(
        "listen 127.0.0.1:{} ssl; ssl_certificate {c}; ssl_certificate_key {k}; \
         ssl_client_certificate {c};",
        common::ports::free_ports::<1>()[0],
        c = ca.cert_path().display(),
        k = ca.key_path().display(),
    );
    let ok = |name: &str, lines: &str| {
        let (passed, said) = check(name, &format!("server {{ {tls} {lines} }}"));
        assert!(passed, "{lines}: {said}");
    };
    let fails = |name: &str, lines: &str, why: &str| {
        let (passed, said) = check(name, &format!("server {{ {tls} {lines} }}"));
        assert!(!passed && said.contains(why), "{lines}: {said}");
    };
    ok(
        "ok",
        "ssl_verify_client on; ssl_ocsp on; ssl_ocsp_responder http://127.0.0.1:9/; \
         ssl_ocsp_cache shared:OCSP:1m;",
    );
    ok(
        "off",
        "ssl_verify_client on; ssl_ocsp off; ssl_ocsp_cache off;",
    );
    fails(
        "noca",
        "ssl_verify_client optional_no_ca; ssl_ocsp leaf;",
        "\"ssl_ocsp\" is incompatible with \"ssl_verify_client optional_no_ca\"",
    );
    fails(
        "prefix",
        "ssl_verify_client on; ssl_ocsp on; ssl_ocsp_responder https://127.0.0.1/;",
        "invalid URL prefix in OCSP responder \"https://127.0.0.1/\" in \"ssl_ocsp_responder\"",
    );
    fails(
        "small",
        "ssl_ocsp_cache shared:OCSP:16k;",
        "OCSP cache \"shared:OCSP:16k\" is too small",
    );
    fails(
        "invalid",
        "ssl_ocsp_cache builtin:1000;",
        "invalid OCSP cache \"builtin:1000\"",
    );
    fails("mode", "ssl_ocsp maybe;", "ssl_ocsp");
    fails("twice", "ssl_ocsp on; ssl_ocsp off;", "ssl_ocsp");
}
