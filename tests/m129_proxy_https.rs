//! M129 — `proxy_pass https://` (#116): TLS to upstreams with nginx's
//! defaults (no SNI unless `proxy_ssl_server_name on`, session reuse on,
//! the certificate not verified), the keep-alive pool, and the failures;
//! `proxy_ssl_verify on` (#117). The upstream is a TLS server block of the
//! same ruxen.

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

/// `setup` is the port lock, taken before the test picked its ports:
/// released only once ruxen listens, so no parallel test takes them.
fn start(
    name: &str,
    setup: std::sync::MutexGuard<'static, ()>,
    http: impl FnOnce(&Path) -> String,
) -> Server {
    let dir = std::env::temp_dir().join(format!("ruxen-m129-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
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
    let setup = common::ports::setup_lock();
    let [front, backend, plain] = common::ports::free_ports();
    let s = start("main", setup, |_| {
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

/// root CA → intermediate CA → leaf for `name`, in `dir`: the leaf's
/// chain file (leaf, then the intermediate), its key, and the root.
fn chain_with_intermediate(dir: &Path, name: &str) -> (PathBuf, PathBuf, PathBuf) {
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
    let ca = |cn: &str| {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name.push(DnType::CommonName, cn);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
    };
    let root_key = KeyPair::generate().unwrap();
    let root_params = ca("ruxen-test-root");
    let root = root_params.self_signed(&root_key).unwrap();
    let root_issuer = Issuer::new(root_params, root_key);
    let int_key = KeyPair::generate().unwrap();
    let int_params = ca("ruxen-test-intermediate");
    let int = int_params.signed_by(&int_key, &root_issuer).unwrap();
    let int_issuer = Issuer::new(int_params, int_key);
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec![name.to_string()])
        .unwrap()
        .signed_by(&leaf_key, &int_issuer)
        .unwrap();
    let paths = (
        dir.join("deep.crt"),
        dir.join("deep.key"),
        dir.join("root.crt"),
    );
    std::fs::write(&paths.0, leaf.pem() + &int.pem()).unwrap();
    std::fs::write(&paths.1, leaf_key.serialize_pem()).unwrap();
    std::fs::write(&paths.2, root.pem()).unwrap();
    paths
}

/// `proxy_ssl_verify on` (#117): the chain, the depth and the name checked
/// as nginx's OpenSSL checks them, including certificates webpki refuses
/// (a self-signed CA:TRUE leaf named by its commonName only, X.509 v1),
/// and nginx's error-log lines for a refusal.
#[test]
fn proxy_ssl_verify_like_nginx() {
    let chain = common::tls::make_ca_and_leaf("backend.test");
    let data = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/testdata/tls");
    let ca_leaf = data.join("rsa.crt");
    let v1 = data.join("v1_ec.crt");
    let setup = common::ports::setup_lock();
    let [front, signed, ca_true, old, deep] = common::ports::free_ports();
    let s = start("verify", setup, |dir| {
        let (deep_crt, deep_key, root) = chain_with_intermediate(dir, "deep.test");
        format!(
            "server {{ listen 127.0.0.1:{signed} ssl;\n\
               ssl_certificate {cert}; ssl_certificate_key {key};\n\
               location / {{ return 200 signed; }} }}\n\
             server {{ listen 127.0.0.1:{ca_true} ssl;\n\
               ssl_certificate {ca_leaf}; ssl_certificate_key {ca_leaf_key};\n\
               location / {{ return 200 ca-leaf; }} }}\n\
             server {{ listen 127.0.0.1:{old} ssl;\n\
               ssl_certificate {v1}; ssl_certificate_key {v1_key};\n\
               location / {{ return 200 v1; }} }}\n\
             server {{ listen 127.0.0.1:{deep} ssl;\n\
               ssl_certificate {deep_crt}; ssl_certificate_key {deep_key};\n\
               location / {{ return 200 deep; }} }}\n\
             server {{ listen 127.0.0.1:{front};\n\
               proxy_ssl_verify on; proxy_ssl_trusted_certificate {ca};\n\
               proxy_ssl_session_reuse off;\n\
               location /ok/ {{ proxy_pass https://127.0.0.1:{signed}/;\n\
                 proxy_ssl_name backend.test; }}\n\
               location /depth0/ {{ proxy_pass https://127.0.0.1:{signed}/;\n\
                 proxy_ssl_name backend.test; proxy_ssl_verify_depth 0; }}\n\
               location /deep/ {{ proxy_pass https://127.0.0.1:{deep}/;\n\
                 proxy_ssl_name deep.test; proxy_ssl_trusted_certificate {root}; }}\n\
               location /deep0/ {{ proxy_pass https://127.0.0.1:{deep}/;\n\
                 proxy_ssl_name deep.test; proxy_ssl_trusted_certificate {root};\n\
                 proxy_ssl_verify_depth 0; }}\n\
               location /name/ {{ proxy_pass https://127.0.0.1:{signed}/;\n\
                 proxy_ssl_name other.test; }}\n\
               location /untrusted/ {{ proxy_pass https://127.0.0.1:{signed}/;\n\
                 proxy_ssl_name backend.test; proxy_ssl_trusted_certificate {v1}; }}\n\
               location /off/ {{ proxy_pass https://127.0.0.1:{signed}/;\n\
                 proxy_ssl_verify off; }}\n\
               location /ca-leaf/ {{ proxy_pass https://127.0.0.1:{ca_true}/;\n\
                 proxy_ssl_name test.ruxen.local; proxy_ssl_trusted_certificate {ca_leaf}; }}\n\
               location /v1/ {{ proxy_pass https://127.0.0.1:{old}/;\n\
                 proxy_ssl_name v1-ec; proxy_ssl_trusted_certificate {v1}; }}\n\
               location /v1-tls12/ {{ proxy_pass https://127.0.0.1:{old}/;\n\
                 proxy_ssl_name v1-ec; proxy_ssl_trusted_certificate {v1};\n\
                 proxy_ssl_protocols TLSv1.2; }} }}",
            cert = chain.cert_path().display(),
            key = chain.key_path().display(),
            ca = chain.ca_path().unwrap().display(),
            ca_leaf = ca_leaf.display(),
            ca_leaf_key = data.join("rsa.key").display(),
            v1 = v1.display(),
            v1_key = data.join("v1_ec.key").display(),
            deep_crt = deep_crt.display(),
            deep_key = deep_key.display(),
            root = root.display(),
        )
    });

    // The depth is OpenSSL's: intermediates below the trusted one, so 0
    // takes a leaf the trusted CA signed, and the default 1 one more CA.
    for (path, want) in [
        ("/ok/", "signed"),
        ("/depth0/", "signed"),
        ("/deep/", "deep"),
        ("/off/", "signed"),
        ("/ca-leaf/", "ca-leaf"),
        ("/v1/", "v1"),
        ("/v1-tls12/", "v1"),
    ] {
        assert_eq!(get(front, path), (200, want.to_string()), "{path}");
    }
    for path in ["/deep0/", "/name/", "/untrusted/"] {
        assert_eq!(get(front, path).0, 502, "{path}");
    }
    let log = std::fs::read_to_string(s.dir.join("error.log")).unwrap_or_default();
    assert!(
        log.contains(
            "upstream SSL certificate does not match \"other.test\" while SSL handshaking to upstream"
        ),
        "{log}"
    );
    assert!(
        log.contains("upstream SSL certificate verify error: (")
            && log.contains("while SSL handshaking to upstream"),
        "{log}"
    );
}

/// A kept-alive connection is only reused as it was opened (#117): not by a
/// location that verifies when it was opened without verification, nor
/// for a name it wasn't verified against. nginx's keepalive cache would
/// hand either over, being keyed by the peer alone.
#[test]
fn pooled_connections_keep_their_verification() {
    let chain = common::tls::make_ca_and_leaf("backend.test");
    let other = common::tls::make_ca_and_leaf("backend.test");
    let setup = common::ports::setup_lock();
    let [front, backend] = common::ports::free_ports();
    let s = start("pool-verify", setup, |_| {
        format!(
            "upstream b {{ server 127.0.0.1:{backend}; keepalive 4; }}\n\
             server {{ listen 127.0.0.1:{backend} ssl;\n\
               ssl_certificate {cert}; ssl_certificate_key {key};\n\
               location / {{ return 200 $connection_requests; }} }}\n\
             server {{ listen 127.0.0.1:{front};\n\
               proxy_http_version 1.1; proxy_set_header Connection \"\";\n\
               location /off/ {{ proxy_pass https://b/; proxy_ssl_name backend.test; }}\n\
               location /wrong-ca/ {{ proxy_pass https://b/; proxy_ssl_name backend.test;\n\
                 proxy_ssl_verify on; proxy_ssl_trusted_certificate {other_ca}; }}\n\
               location /right/ {{ proxy_pass https://b/; proxy_ssl_name backend.test;\n\
                 proxy_ssl_verify on; proxy_ssl_trusted_certificate {ca}; }}\n\
               location /wrong-name/ {{ proxy_pass https://b/; proxy_ssl_name other.test;\n\
                 proxy_ssl_verify on; proxy_ssl_trusted_certificate {ca}; }} }}",
            cert = chain.cert_path().display(),
            key = chain.key_path().display(),
            ca = chain.ca_path().unwrap().display(),
            other_ca = other.ca_path().unwrap().display(),
        )
    });
    // An unverified connection goes to the pool; verification refuses
    // the certificate on a new one.
    assert_eq!(get(front, "/off/"), (200, "1".to_string()));
    assert_eq!(get(front, "/wrong-ca/").0, 502);
    // The pooled unverified one still serves its own location.
    assert_eq!(get(front, "/off/"), (200, "2".to_string()));
    // Verified for backend.test, pooled, reused for backend.test only.
    assert_eq!(get(front, "/right/"), (200, "1".to_string()));
    assert_eq!(get(front, "/right/"), (200, "2".to_string()));
    assert_eq!(get(front, "/wrong-name/").0, 502);
    let log = std::fs::read_to_string(s.dir.join("error.log")).unwrap_or_default();
    assert!(log.contains("does not match \"other.test\""), "{log}");
}

/// nginx refuses `proxy_ssl_verify on` without trusted certificates, and
/// trusted certificates it can't load.
#[test]
fn proxy_ssl_verify_needs_trusted_certificates() {
    let dir = std::env::temp_dir().join(format!("ruxen-m129-check-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("empty.pem"), "").unwrap();
    let check = |directives: &str| {
        std::fs::write(
            dir.join("nginx.conf"),
            format!(
                "events {{}}\nhttp {{ server {{ listen 127.0.0.1:1;\n\
                 location / {{ proxy_pass https://127.0.0.1:2; {directives} }} }} }}\n"
            ),
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
    let none = check("proxy_ssl_verify on;");
    let missing = check("proxy_ssl_verify on; proxy_ssl_trusted_certificate missing.pem;");
    let empty = check("proxy_ssl_verify on; proxy_ssl_trusted_certificate empty.pem;");
    let off = check("proxy_ssl_verify off; proxy_ssl_trusted_certificate missing.pem;");
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        !none.0
            && none
                .1
                .contains("no proxy_ssl_trusted_certificate for proxy_ssl_verify"),
        "{}",
        none.1
    );
    assert!(
        !missing.0 && missing.1.contains("SSL_CTX_load_verify_locations(\""),
        "{}",
        missing.1
    );
    assert!(
        !empty.0 && empty.1.contains("SSL_CTX_load_verify_locations(\""),
        "{}",
        empty.1
    );
    // As nginx: with verification off, the file isn't loaded.
    assert!(off.0, "{}", off.1);
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
    let setup = common::ports::setup_lock();
    let front = free_port();
    let _s = start("upgrade", setup, |_| {
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

/// `proxy_ssl_certificate` (#138): the certificate goes to an upstream that
/// asks for one; `""` cancels an inherited one. With variables (#434), the
/// pair is the request's: none when it renders empty, a 500 when it
/// doesn't load. The upstream is a rustls server that answers with what
/// it got.
#[test]
fn client_certificates_to_upstreams() {
    use std::sync::Arc;
    let client = common::tls::make_ca_and_leaf("client.test");
    let ca_pem = std::fs::read(client.ca_path().unwrap()).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    for cert in
        <rustls::pki_types::CertificateDer as rustls::pki_types::pem::PemObject>::pem_slice_iter(
            &ca_pem,
        )
    {
        roots.add(cert.unwrap()).unwrap();
    }
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots),
        provider.clone(),
    )
    .allow_unauthenticated()
    .build()
    .unwrap();
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let config = Arc::new(
        rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_client_cert_verifier(verifier)
            .with_single_cert(
                vec![rustls::pki_types::CertificateDer::from(
                    ck.cert.der().to_vec(),
                )],
                rustls::pki_types::PrivateKeyDer::Pkcs8(
                    rustls::pki_types::PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der()),
                ),
            )
            .unwrap(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let backend = listener.local_addr().unwrap().port();
    let requests = 5;
    let upstream = std::thread::spawn(move || {
        for _ in 0..requests {
            let (tcp, _) = listener.accept().unwrap();
            tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
            let conn = rustls::ServerConnection::new(config.clone()).unwrap();
            let mut tls = rustls::StreamOwned::new(conn, tcp);
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                if tls.read(&mut byte).unwrap_or(0) == 0 {
                    break;
                }
                head.push(byte[0]);
            }
            let got = if tls.conn.peer_certificates().is_some() {
                "cert"
            } else {
                "none"
            };
            let _ = write!(
                tls,
                "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\n{got}"
            );
            let _ = tls.flush();
            tls.conn.send_close_notify();
            let _ = tls.flush();
        }
    });
    let setup = common::ports::setup_lock();
    let front = free_port();
    let _s = start("client-cert", setup, |_| {
        format!(
            "server {{ listen 127.0.0.1:{front};\n\
               proxy_ssl_certificate {cert}; proxy_ssl_certificate_key {key};\n\
               location /with/ {{ proxy_pass https://127.0.0.1:{backend}/; }}\n\
               location /cancel/ {{ proxy_pass https://127.0.0.1:{backend}/;\n\
                 proxy_ssl_certificate \"\"; }}\n\
               location /vars/ {{ proxy_pass https://127.0.0.1:{backend}/;\n\
                 proxy_ssl_certificate $arg_c; proxy_ssl_certificate_key $arg_k; }} }}",
            cert = client.cert_path().display(),
            key = client.key_path().display(),
        )
    });
    assert_eq!(get(front, "/with/"), (200, "cert".to_string()));
    assert_eq!(get(front, "/cancel/"), (200, "none".to_string()));
    let vars = format!(
        "/vars/?c={}&k={}",
        client.cert_path().display(),
        client.key_path().display()
    );
    assert_eq!(get(front, &vars), (200, "cert".to_string()));
    assert_eq!(get(front, &vars), (200, "cert".to_string()));
    assert_eq!(get(front, "/vars/"), (200, "none".to_string()));
    assert_eq!(get(front, "/vars/?c=/nonexistent&k=/nonexistent").0, 500);
    upstream.join().unwrap();
}

/// nginx's checks of `proxy_ssl_certificate` at load: a certificate needs
/// its key. Variables load per request; `data:` isn't supported yet, so it
/// is refused rather than served without a certificate.
#[test]
fn proxy_ssl_certificate_needs_its_key() {
    let client = common::tls::make_self_signed("client.test");
    let dir = std::env::temp_dir().join(format!("ruxen-m129-cc-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let check = |directives: &str| {
        std::fs::write(
            dir.join("nginx.conf"),
            format!(
                "events {{}}\nhttp {{ server {{ listen 127.0.0.1:1;\n\
                 location / {{ proxy_pass https://127.0.0.1:2; {directives} }} }} }}\n"
            ),
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
    let cert = client.cert_path().display().to_string();
    let key = client.key_path().display().to_string();
    let no_key = check(&format!("proxy_ssl_certificate {cert};"));
    let both = check(&format!(
        "proxy_ssl_certificate {cert}; proxy_ssl_certificate_key {key};"
    ));
    let wrong_key = check(&format!(
        "proxy_ssl_certificate {cert}; proxy_ssl_certificate_key {cert};"
    ));
    let vars = check("proxy_ssl_certificate $arg_c; proxy_ssl_certificate_key $arg_c;");
    let vars_no_key = check("proxy_ssl_certificate $arg_c;");
    let data = check("proxy_ssl_certificate data:x; proxy_ssl_certificate_key data:x;");
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        !no_key.0
            && no_key
                .1
                .contains("no \"proxy_ssl_certificate_key\" is defined"),
        "{}",
        no_key.1
    );
    assert!(both.0, "{}", both.1);
    assert!(
        !wrong_key.0 && wrong_key.1.contains("cannot load certificate"),
        "{}",
        wrong_key.1
    );
    assert!(vars.0, "{}", vars.1);
    assert!(
        !vars_no_key.0
            && vars_no_key
                .1
                .contains("no \"proxy_ssl_certificate_key\" is defined for certificate \"$arg_c\""),
        "{}",
        vars_no_key.1
    );
    assert!(
        !data.0 && data.1.contains("data: isn't supported yet"),
        "{}",
        data.1
    );
}
