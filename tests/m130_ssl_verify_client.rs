//! M130 — `ssl_verify_client` (#113): client certificates asked for and
//! checked as nginx checks them. The handshake never fails over the
//! certificate; the request is refused with 495 / 496 (sent as 400, or
//! what `error_page` says), a Host naming another verifying server than
//! the SNI name is 421, and `$ssl_client_verify` reports the result.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
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

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn start(name: &str, http: &str) -> Server {
    let dir = std::env::temp_dir().join(format!("ruxen-m130-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let setup = common::ports::setup_lock();
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

/// Takes any server certificate: the server isn't what is tested.
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

fn client_config(cert: Option<(&Path, &Path)>) -> Arc<rustls::ClientConfig> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyServer(provider)));
    Arc::new(match cert {
        Some((cert, key)) => {
            let chain = rustls_pemfile::certs(&mut &std::fs::read(cert).unwrap()[..])
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            let key: PrivateKeyDer<'static> =
                rustls_pemfile::private_key(&mut &std::fs::read(key).unwrap()[..])
                    .unwrap()
                    .unwrap();
            builder.with_client_auth_cert(chain, key).unwrap()
        }
        None => builder.with_no_client_auth(),
    })
}

/// Requests over one TLS connection naming `sni`, with `Host: host` and
/// the client certificate `cert`: each (status, body), until the server
/// closes. `paths` are sent one after another on the connection.
fn requests(
    port: u16,
    sni: &str,
    host: &str,
    cert: Option<(&Path, &Path)>,
    paths: &[&str],
) -> Vec<(u16, String)> {
    let conn = rustls::ClientConnection::new(
        client_config(cert),
        ServerName::try_from(sni.to_string()).unwrap(),
    )
    .unwrap();
    let tcp = TcpStream::connect(("127.0.0.1", port)).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut tls = rustls::StreamOwned::new(conn, tcp);
    let mut out = Vec::new();
    for (i, path) in paths.iter().enumerate() {
        let close = if i + 1 == paths.len() {
            "close"
        } else {
            "keep-alive"
        };
        if write!(
            tls,
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: {close}\r\n\r\n"
        )
        .and_then(|()| tls.flush())
        .is_err()
        {
            break;
        }
        let Some(response) = read_response(&mut tls) else {
            break;
        };
        out.push(response);
    }
    out
}

/// One response with a Content-Length body.
fn read_response(s: &mut impl Read) -> Option<(u16, String)> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match s.read(&mut byte) {
            Ok(1) => head.push(byte[0]),
            _ => return None,
        }
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    let status = head.get(9..12)?.parse().ok()?;
    let len: usize = head
        .lines()
        .find_map(|l| {
            l.to_ascii_lowercase()
                .strip_prefix("content-length:")
                .map(|v| v.trim().parse().unwrap_or(0))
        })
        .unwrap_or(0);
    let mut body = vec![0u8; len];
    s.read_exact(&mut body).ok()?;
    Some((status, String::from_utf8_lossy(&body).into_owned()))
}

fn one(port: u16, sni: &str, cert: Option<(&Path, &Path)>) -> (u16, String) {
    requests(port, sni, sni, cert, &["/"])
        .pop()
        .unwrap_or((0, String::new()))
}

#[test]
fn ssl_verify_client_like_nginx() {
    let server = common::tls::make_self_signed("localhost");
    let client = common::tls::make_ca_and_leaf("client.test");
    let stranger = common::tls::make_self_signed("stranger.test");
    let port = free_port();
    let tls = format!(
        "listen 127.0.0.1:{port} ssl; ssl_certificate {}; ssl_certificate_key {};",
        server.cert_path().display(),
        server.key_path().display()
    );
    let ca = client.ca_path().unwrap().display().to_string();
    let s = start(
        "main",
        &format!(
            "server {{ {tls} server_name on;\n\
               ssl_verify_client on; ssl_client_certificate {ca};\n\
               location / {{ return 200 \"$ssl_client_verify\"; }} }}\n\
             server {{ {tls} server_name optional;\n\
               ssl_verify_client optional; ssl_client_certificate {ca};\n\
               location / {{ return 200 \"$ssl_client_verify\"; }} }}\n\
             server {{ {tls} server_name noca;\n\
               ssl_verify_client optional_no_ca;\n\
               location / {{ return 200 \"$ssl_client_verify\"; }} }}\n\
             server {{ {tls} server_name off;\n\
               location / {{ return 200 \"$ssl_client_verify\"; }} }}\n\
             server {{ {tls} server_name vars;\n\
               ssl_verify_client optional; ssl_client_certificate {ca};\n\
               location / {{ return 200 \"$ssl_client_s_dn|$ssl_client_i_dn_legacy|$ssl_client_v_remain\"; }} }}\n\
             server {{ {tls} server_name page;\n\
               ssl_verify_client on; ssl_client_certificate {ca};\n\
               error_page 495 496 /denied;\n\
               location / {{ return 200 \"$ssl_client_verify\"; }}\n\
               location = /denied {{ return 403 denied; }} }}"
        ),
    );
    let good = Some((client.cert_path(), client.key_path()));
    let bad = Some((stranger.cert_path(), stranger.key_path()));

    // `on`: a certificate the CA signed passes, on every request of the
    // connection; none, or one nobody vouches for, is refused.
    assert_eq!(
        requests(port, "on", "on", good, &["/", "/"]),
        [(200, "SUCCESS".into()), (200, "SUCCESS".into())]
    );
    assert_eq!(
        one(port, "on", None),
        (400, "No required SSL certificate was sent\n".into())
    );
    assert_eq!(
        one(port, "on", bad),
        (400, "The SSL certificate error\n".into())
    );
    // The connection closes after the refusal, as nginx closes it.
    assert_eq!(requests(port, "on", "on", None, &["/", "/"]).len(), 1);

    // `optional`: no certificate passes, a bad one doesn't.
    assert_eq!(one(port, "optional", None), (200, "NONE".into()));
    assert_eq!(one(port, "optional", good), (200, "SUCCESS".into()));
    assert_eq!(one(port, "optional", bad).0, 400);

    // `optional_no_ca`: a certificate nobody vouches for passes, and says
    // so in OpenSSL's words.
    let (status, body) = one(port, "noca", bad);
    assert_eq!(status, 200);
    assert!(
        body.starts_with("FAILED:") && body.contains("self"),
        "{body}"
    );

    // The certificate's fields (#114); empty without one.
    let (status, body) = one(port, "vars", good);
    assert_eq!(status, 200);
    let fields: Vec<&str> = body.split('|').collect();
    assert_eq!(
        fields[..2],
        ["CN=client.test", "/CN=ruxen-test-ca-ca"],
        "{body}"
    );
    assert!(fields[2].parse::<u32>().is_ok_and(|d| d > 0), "{body}");
    assert_eq!(one(port, "vars", None), (200, "||".into()));

    // Off: no certificate is asked for.
    assert_eq!(one(port, "off", good), (200, "NONE".into()));

    // error_page takes 495 and 496.
    assert_eq!(one(port, "page", None), (403, "denied".into()));
    assert_eq!(one(port, "page", bad), (403, "denied".into()));

    // A Host naming a verifying server other than the SNI name: 421, and
    // the connection stays.
    assert_eq!(
        requests(port, "optional", "on", good, &["/"]),
        [(421, "Misdirected Request\n".into())]
    );
    // Naming one that doesn't verify is fine.
    assert_eq!(
        requests(port, "optional", "off", None, &["/"]),
        [(200, "NONE".into())]
    );

    let log = std::fs::read_to_string(s.dir.join("error.log")).unwrap_or_default();
    for line in [
        "client sent no required SSL certificate",
        "client SSL certificate verify error: (",
        "client attempted to request the server name different from the one that was negotiated",
    ] {
        assert!(log.contains(line), "{line}\n{log}");
    }
}

/// nginx's checks at load: `on` and `optional` need
/// `ssl_client_certificate`; `optional_no_ca` doesn't; a server without a
/// certificate of its own isn't checked.
#[test]
fn ssl_verify_client_needs_a_client_certificate() {
    let server = common::tls::make_self_signed("localhost");
    let dir = std::env::temp_dir().join(format!("ruxen-m130-check-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let check = |servers: &str| {
        std::fs::write(
            dir.join("nginx.conf"),
            format!("events {{}}\nhttp {{ {servers} }}\n"),
        )
        .unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_ruxen"))
            .arg("-t")
            .arg("-c")
            .arg(dir.join("nginx.conf"))
            .output()
            .unwrap();
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    };
    let tls = format!(
        "listen 127.0.0.1:1 ssl; ssl_certificate {}; ssl_certificate_key {};",
        server.cert_path().display(),
        server.key_path().display()
    );
    let on = check(&format!("server {{ {tls} ssl_verify_client on; }}"));
    let no_ca = check(&format!(
        "server {{ {tls} ssl_verify_client optional_no_ca; }}"
    ));
    let no_cert = check(&format!(
        "server {{ {tls} }} server {{ listen 127.0.0.1:1 ssl; server_name x; ssl_verify_client on; }}"
    ));
    let missing = check(&format!(
        "server {{ {tls} ssl_verify_client on; ssl_client_certificate missing.pem; }}"
    ));
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        !on.0
            && on
                .1
                .contains("no ssl_client_certificate for ssl_verify_client"),
        "{}",
        on.1
    );
    assert!(no_ca.0, "{}", no_ca.1);
    assert!(no_cert.0, "{}", no_cert.1);
    assert!(
        !missing.0 && missing.1.contains("SSL_CTX_load_verify_locations"),
        "{}",
        missing.1
    );
}
