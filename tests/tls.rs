// HTTPS integration tests.
//
// Cert generation, server-spawn, and curl helpers live here. The tests run
// a release-built ruxen binary against ephemeral certs so TLS behavior is
// exercised through the same CLI and worker path as production.

#![allow(dead_code)] // some helpers are shared by only a subset of TLS tests

mod common;

use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, MutexGuard};
use std::thread::sleep;
use std::time::{Duration, Instant};

use common::tls::{CertSet, make_ca_and_leaf, make_self_signed, make_wildcard};

// Same SETUP_LOCK rationale as `tests/file_serving.rs`: serialize port
// picking against the spawn + readiness-check of the previous setup so
// the kernel doesn't hand the same port to two concurrent tests.
static SETUP_LOCK: Mutex<()> = Mutex::new(());

fn pick_port() -> (u16, MutexGuard<'static, ()>) {
    let g = SETUP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let p = l.local_addr().unwrap().port();
    drop(l);
    (p, g)
}

fn unique_dir() -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let d = std::env::temp_dir().join(format!(
        "ruxen-tls-conf-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir(&d).unwrap();
    d
}

fn wait_for_listen(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        if Instant::now() > deadline {
            panic!("ruxen did not start listening on port {port}");
        }
        sleep(Duration::from_millis(20));
    }
}

pub struct ServerHandle {
    child: Child,
    pub port: u16,
    confdir: PathBuf,
    _certs: CertSet,
}

impl Drop for ServerHandle {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.confdir);
    }
}

/// Materialize `config_template` (with `%%PORT%%`, `%%CERT%%`, `%%KEY%%`
/// substitutions) into a tempdir and run the release binary against it.
/// The handle owns the child + tempdir + certs and cleans them on drop.
pub fn spawn_https_server(config_template: &str, certs: CertSet) -> ServerHandle {
    let (port, _lock) = pick_port();
    let confdir = unique_dir();
    let conf_path = confdir.join("nginx.conf");

    let conf = config_template
        .replace("%%PORT%%", &port.to_string())
        .replace("%%CERT%%", certs.cert_path().to_str().unwrap())
        .replace("%%KEY%%", certs.key_path().to_str().unwrap());
    std::fs::write(&conf_path, conf).unwrap();

    let child = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .args(["-c", conf_path.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ruxen");

    wait_for_listen(port);
    ServerHandle {
        child,
        port,
        confdir,
        _certs: certs,
    }
}

pub struct ServerHandleMulti {
    child: Child,
    pub port: u16,
    confdir: PathBuf,
    _certs: Vec<CertSet>,
}

impl Drop for ServerHandleMulti {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.confdir);
    }
}

/// Multi-cert variant: replaces `%%PORT%%`, then `%%CERT_N%%` / `%%KEY_N%%`
/// for each cert in `certs` (zero-indexed). Lets one config carry several
/// `server` blocks with their own keypairs — the shape SNI-dispatch tests
/// need. The handle owns child + tempdir + every cert in the vector.
pub fn spawn_https_server_multi(config_template: &str, certs: Vec<CertSet>) -> ServerHandleMulti {
    let (port, _lock) = pick_port();
    let confdir = unique_dir();
    let conf_path = confdir.join("nginx.conf");

    let mut conf = config_template.replace("%%PORT%%", &port.to_string());
    for (i, c) in certs.iter().enumerate() {
        conf = conf
            .replace(&format!("%%CERT_{i}%%"), c.cert_path().to_str().unwrap())
            .replace(&format!("%%KEY_{i}%%"), c.key_path().to_str().unwrap());
    }
    std::fs::write(&conf_path, conf).unwrap();

    let child = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .args(["-c", conf_path.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ruxen");

    wait_for_listen(port);
    ServerHandleMulti {
        child,
        port,
        confdir,
        _certs: certs,
    }
}

/// Run `ruxen -t -c <config>` and return (success, combined output). Used
/// by config-validation tests that don't need a live server.
pub fn run_config_test(config: &str) -> (bool, String) {
    let dir = unique_dir();
    let conf_path = dir.join("nginx.conf");
    std::fs::write(&conf_path, config).unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .args(["-t", "-c", conf_path.to_str().unwrap()])
        .output()
        .expect("run ruxen -t");

    let _ = std::fs::remove_dir_all(&dir);
    let mut combined = String::from_utf8_lossy(&out.stderr).into_owned();
    combined.push_str(&String::from_utf8_lossy(&out.stdout));
    (out.status.success(), combined)
}

/// Drive a single HTTPS GET via the system `curl`. `--resolve` pins the
/// SNI/Host name to the loopback port so server_name dispatch works.
pub struct CurlOut {
    pub ok: bool,
    pub stdout: String,
    pub stderr: String,
}

impl CurlOut {
    /// Status code from the `--write-out` trailer. `None` if curl bailed
    /// before getting a response.
    pub fn status(&self) -> Option<u16> {
        self.stdout
            .lines()
            .find_map(|l| l.strip_prefix("STATUS="))
            .and_then(|s| s.trim().parse().ok())
    }
}

pub fn curl_get(port: u16, host: &str, path: &str, ca: Option<&Path>, insecure: bool) -> CurlOut {
    curl_get_full(port, host, path, ca, insecure, &[])
}

/// Like `curl_get` but with arbitrary extra request headers (`-H`).
/// Used by SNI tests that send a `Host:` value distinct from the SNI
/// host (the `--resolve` arg fixes the SNI hostname from the URL).
pub fn curl_get_full(
    port: u16,
    host: &str,
    path: &str,
    ca: Option<&Path>,
    insecure: bool,
    extra_headers: &[&str],
) -> CurlOut {
    let mut cmd = Command::new("curl");
    cmd.arg("--silent")
        .arg("--show-error")
        .arg("--http1.1")
        .arg("--max-time")
        .arg("5")
        .arg("--resolve")
        .arg(format!("{host}:{port}:127.0.0.1"))
        .arg("--write-out")
        .arg("\nSTATUS=%{http_code}\n");
    if insecure {
        cmd.arg("--insecure");
    }
    if let Some(ca_path) = ca {
        cmd.arg("--cacert").arg(ca_path);
    }
    for h in extra_headers {
        cmd.arg("-H").arg(h);
    }
    cmd.arg(format!("https://{host}:{port}{path}"));

    let out = cmd
        .output()
        .expect("failed to spawn `curl` — install it or skip with `cargo test -- --skip tls::`");
    CurlOut {
        ok: out.status.success(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

const SMOKE_CONF: &str = r#"
daemon off;
events { }

http {
    server {
        listen 127.0.0.1:%%PORT%% ssl;
        server_name localhost;

        ssl_certificate     %%CERT%%;
        ssl_certificate_key %%KEY%%;

        location / {
            return 200 "ok\n";
        }
    }
}
"#;

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

/// `curl -k https://127.0.0.1:<port>/` returns 200 against `listen … ssl;`.
#[test]
fn smoke() {
    let certs = make_self_signed("localhost");
    let server = spawn_https_server(SMOKE_CONF, certs);
    let resp = curl_get(server.port, "localhost", "/", None, true);
    assert!(resp.ok, "curl failed: stderr={}", resp.stderr);
    assert_eq!(resp.status(), Some(200), "stdout={}", resp.stdout);
    assert!(resp.stdout.contains("ok"), "body: {}", resp.stdout);
}

/// X.509 v1 certificates (no extensions, which is what nginx-tests and a
/// bare `openssl req -x509` make) load and serve, as with nginx/OpenSSL.
/// webpki rejects them with `UnsupportedCertVersion`, so ruxen used to
/// refuse to start.
#[test]
fn x509_v1_certificates_serve() {
    let testdata = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/testdata/tls");
    for kind in ["rsa", "ec"] {
        let certs = common::tls::from_pem_files(
            &testdata.join(format!("v1_{kind}.crt")),
            &testdata.join(format!("v1_{kind}.key")),
        );
        let server = spawn_https_server(SMOKE_CONF, certs);
        let resp = curl_get(server.port, "localhost", "/", None, true);
        assert!(resp.ok, "{kind}: curl failed: stderr={}", resp.stderr);
        assert_eq!(resp.status(), Some(200), "{kind}: stdout={}", resp.stdout);
    }
}

const SNI_DISPATCH_CONF: &str = r#"
daemon off;
events { }

http {
    server {
        listen 127.0.0.1:%%PORT%% ssl;
        server_name a.test;

        ssl_certificate     %%CERT_0%%;
        ssl_certificate_key %%KEY_0%%;

        location / {
            return 200 "server-A\n";
        }
    }

    server {
        listen 127.0.0.1:%%PORT%% ssl;
        server_name b.test;

        ssl_certificate     %%CERT_1%%;
        ssl_certificate_key %%KEY_1%%;

        location / {
            return 200 "server-B\n";
        }
    }
}
"#;

/// Two `server { server_name … }` blocks on the same listen address with
/// distinct CA-signed certs. SNI selects which cert is presented and
/// which server block routes the request. Distinct CAs +
/// `--cacert` make a wrong cert fail validation, so a passing test
/// implies both the right cert *and* the right body.
#[test]
fn sni_dispatch() {
    let cert_a = make_ca_and_leaf("a.test");
    let cert_b = make_ca_and_leaf("b.test");
    let ca_a = cert_a.ca_path().unwrap().to_path_buf();
    let ca_b = cert_b.ca_path().unwrap().to_path_buf();

    let server = spawn_https_server_multi(SNI_DISPATCH_CONF, vec![cert_a, cert_b]);

    let resp_a = curl_get(server.port, "a.test", "/", Some(&ca_a), false);
    assert!(resp_a.ok, "a.test curl failed: stderr={}", resp_a.stderr);
    assert_eq!(resp_a.status(), Some(200), "stdout={}", resp_a.stdout);
    assert!(
        resp_a.stdout.contains("server-A"),
        "expected server-A body; got {}",
        resp_a.stdout,
    );

    let resp_b = curl_get(server.port, "b.test", "/", Some(&ca_b), false);
    assert!(resp_b.ok, "b.test curl failed: stderr={}", resp_b.stderr);
    assert_eq!(resp_b.status(), Some(200), "stdout={}", resp_b.stdout);
    assert!(
        resp_b.stdout.contains("server-B"),
        "expected server-B body; got {}",
        resp_b.stdout,
    );
}

const WILDCARD_SNI_CONF: &str = r#"
daemon off;
events { }

http {
    server {
        listen 127.0.0.1:%%PORT%% ssl;
        server_name *.example.test;

        ssl_certificate     %%CERT_0%%;
        ssl_certificate_key %%KEY_0%%;

        location / {
            return 200 "wildcard\n";
        }
    }
}
"#;

/// Wildcard cert (`*.example.test`) and a wildcard `server_name` cover
/// any single-label subdomain. Routes through the same `match_server_name`
/// ladder used by HTTP `Host` matching, exercising the leading-wildcard
/// branch of the SNI fallback.
#[test]
fn wildcard_sni() {
    let certs = make_wildcard("example.test");
    let ca = certs.ca_path().unwrap().to_path_buf();
    let server = spawn_https_server_multi(WILDCARD_SNI_CONF, vec![certs]);

    let resp = curl_get(server.port, "foo.example.test", "/", Some(&ca), false);
    assert!(resp.ok, "wildcard curl failed: stderr={}", resp.stderr);
    assert_eq!(resp.status(), Some(200), "stdout={}", resp.stdout);
    assert!(
        resp.stdout.contains("wildcard"),
        "expected wildcard body; got {}",
        resp.stdout,
    );
}

/// ALPN negotiates `http/1.1`. A client offering `h2,http/1.1` must come
/// back with `http/1.1` in the handshake summary; until h2 lands, that's
/// the only protocol we advertise.
#[test]
fn alpn_http11() {
    let certs = make_self_signed("localhost");
    let server = spawn_https_server(SMOKE_CONF, certs);

    let out = Command::new("openssl")
        .args([
            "s_client",
            "-alpn",
            "h2,http/1.1",
            "-connect",
            &format!("127.0.0.1:{}", server.port),
            "-servername",
            "localhost",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn openssl s_client");

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("ALPN protocol: http/1.1"),
        "expected ALPN http/1.1 in s_client output; got:\n{stdout}"
    );
}

/// nginx behavior: when SNI says `b.test` but the HTTP `Host:` header
/// says `a.test`, the Host header wins for routing (SNI only picks
/// the cert/TLS context). Verifies the SNI fallback in `find_config`
/// is exactly that — a fallback, not an override.
#[test]
fn host_overrides_sni() {
    let cert_a = make_ca_and_leaf("a.test");
    let cert_b = make_ca_and_leaf("b.test");
    let ca_b = cert_b.ca_path().unwrap().to_path_buf();

    let server = spawn_https_server_multi(SNI_DISPATCH_CONF, vec![cert_a, cert_b]);

    // SNI=b.test (from --resolve + URL), Host=a.test (from -H override).
    // --cacert ca_b verifies that we actually got server-B's cert (the
    // SNI-selected cert), proving the cert path didn't follow the Host
    // header. Body must be server-A — the Host header winning routing.
    let resp = curl_get_full(
        server.port,
        "b.test",
        "/",
        Some(&ca_b),
        false,
        &["Host: a.test"],
    );
    assert!(resp.ok, "host-override curl failed: stderr={}", resp.stderr);
    assert_eq!(resp.status(), Some(200), "stdout={}", resp.stdout);
    assert!(
        resp.stdout.contains("server-A"),
        "Host header should have won routing; got {}",
        resp.stdout,
    );
}

const SSL_VARS_CONF: &str = r#"
daemon off;
events { }

http {
    server {
        listen 127.0.0.1:%%PORT%% ssl;
        server_name localhost;

        ssl_certificate     %%CERT%%;
        ssl_certificate_key %%KEY%%;

        add_header X-Scheme        $scheme;
        add_header X-Proto         $ssl_protocol;
        add_header X-Cipher        $ssl_cipher;
        add_header X-Sni           $ssl_server_name;
        add_header X-Reused        $ssl_session_reused;

        location / {
            return 200 "ok\n";
        }
    }
}
"#;

const PLAIN_SCHEME_CONF: &str = r#"
daemon off;
events { }

http {
    server {
        listen 127.0.0.1:%%PORT%%;
        server_name localhost;

        add_header X-Scheme $scheme;
        add_header X-Proto  $ssl_protocol;

        location / {
            return 200 "ok\n";
        }
    }
}
"#;

fn header_value<'a>(stdout: &'a str, name: &str) -> Option<&'a str> {
    let prefix = format!("{name}: ");
    stdout
        .lines()
        .find_map(|l| l.strip_prefix(&prefix))
        .map(|s| s.trim_end_matches('\r').trim())
}

/// Drive `curl --include` so the response headers come back on stdout.
/// Used by the variable tests below where we need to read `add_header`
/// values out, not just the body.
fn curl_get_include(
    port: u16,
    host: &str,
    path: &str,
    ca: Option<&Path>,
    insecure: bool,
    https: bool,
) -> CurlOut {
    let mut cmd = Command::new("curl");
    cmd.arg("--silent")
        .arg("--show-error")
        .arg("--include")
        .arg("--http1.1")
        .arg("--max-time")
        .arg("5")
        .arg("--resolve")
        .arg(format!("{host}:{port}:127.0.0.1"))
        .arg("--write-out")
        .arg("\nSTATUS=%{http_code}\n");
    if insecure {
        cmd.arg("--insecure");
    }
    if let Some(ca_path) = ca {
        cmd.arg("--cacert").arg(ca_path);
    }
    let scheme = if https { "https" } else { "http" };
    cmd.arg(format!("{scheme}://{host}:{port}{path}"));

    let out = cmd.output().expect("failed to spawn curl");
    CurlOut {
        ok: out.status.success(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// `$ssl_protocol`, `$ssl_cipher`, `$ssl_server_name`, `$ssl_session_reused`,
/// and `$scheme` all render the values nginx would render when the request
/// arrived over a fresh TLS 1.3 handshake with SNI=`localhost`.
#[test]
fn ssl_variables_over_tls13() {
    let certs = make_self_signed("localhost");
    let server = spawn_https_server(SSL_VARS_CONF, certs);

    // curl negotiates TLS 1.3 by default against rustls; force it explicitly
    // so a future curl/openssl downgrade doesn't quietly turn this into a
    // TLS 1.2 test.
    let mut cmd = Command::new("curl");
    cmd.arg("--silent")
        .arg("--show-error")
        .arg("--include")
        .arg("--http1.1")
        .arg("--tls13-ciphers")
        .arg("TLS_AES_128_GCM_SHA256")
        .arg("--tlsv1.3")
        .arg("--insecure")
        .arg("--max-time")
        .arg("5")
        .arg("--resolve")
        .arg(format!("localhost:{}:127.0.0.1", server.port))
        .arg("--write-out")
        .arg("\nSTATUS=%{http_code}\n")
        .arg(format!("https://localhost:{}/", server.port));

    let out = cmd.output().expect("spawn curl");
    let resp = CurlOut {
        ok: out.status.success(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    };
    assert!(resp.ok, "curl failed: stderr={}", resp.stderr);
    assert_eq!(resp.status(), Some(200), "stdout={}", resp.stdout);

    let scheme = header_value(&resp.stdout, "X-Scheme")
        .unwrap_or_else(|| panic!("missing X-Scheme; stdout={}", resp.stdout));
    assert_eq!(scheme, "https");

    let proto = header_value(&resp.stdout, "X-Proto")
        .unwrap_or_else(|| panic!("missing X-Proto; stdout={}", resp.stdout));
    assert_eq!(proto, "TLSv1.3");

    let cipher = header_value(&resp.stdout, "X-Cipher")
        .unwrap_or_else(|| panic!("missing X-Cipher; stdout={}", resp.stdout));
    assert_eq!(
        cipher, "TLS_AES_128_GCM_SHA256",
        "expected the TLS 1.3 cipher curl pinned via --tls13-ciphers",
    );

    let sni = header_value(&resp.stdout, "X-Sni")
        .unwrap_or_else(|| panic!("missing X-Sni; stdout={}", resp.stdout));
    assert_eq!(sni, "localhost");

    let reused = header_value(&resp.stdout, "X-Reused")
        .unwrap_or_else(|| panic!("missing X-Reused; stdout={}", resp.stdout));
    assert_eq!(
        reused, ".",
        "fresh handshake should render `.` for $ssl_session_reused"
    );
}

/// `$scheme` renders `http` on a plain listener, and `$ssl_protocol`
/// expands to empty when the connection isn't over TLS.
#[test]
fn ssl_variables_on_plain_listener() {
    let (port, _lock) = pick_port();
    let confdir = unique_dir();
    let conf_path = confdir.join("nginx.conf");
    let conf = PLAIN_SCHEME_CONF.replace("%%PORT%%", &port.to_string());
    std::fs::write(&conf_path, conf).unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .args(["-c", conf_path.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ruxen");
    wait_for_listen(port);

    let resp = curl_get_include(port, "localhost", "/", None, false, false);
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&confdir);

    assert!(resp.ok, "curl failed: stderr={}", resp.stderr);
    assert_eq!(resp.status(), Some(200), "stdout={}", resp.stdout);

    let scheme = header_value(&resp.stdout, "X-Scheme")
        .unwrap_or_else(|| panic!("missing X-Scheme; stdout={}", resp.stdout));
    assert_eq!(scheme, "http");

    // `add_header` skips empty values; `$ssl_protocol` rendering empty
    // should produce no `X-Proto:` line at all on a plain listener.
    assert!(
        header_value(&resp.stdout, "X-Proto").is_none(),
        "expected no X-Proto header on plain HTTP; got {:?}",
        header_value(&resp.stdout, "X-Proto"),
    );
}

const KEEPALIVE_CONF: &str = r#"
daemon off;
events { }

http {
    keepalive_timeout %%TIMEOUT%%;
    server {
        listen 127.0.0.1:%%PORT%% ssl;
        server_name localhost;

        ssl_certificate     %%CERT%%;
        ssl_certificate_key %%KEY%%;

        location / {
            return 200 "ok\n";
        }
    }
}
"#;

type TlsClient = rustls::StreamOwned<rustls::ClientConnection, TcpStream>;

/// A rustls client that trusts `ca_pem`, for tests that need to hold a TLS
/// connection open between requests (curl can't).
fn tls_connect(port: u16, ca_pem: &Path) -> TlsClient {
    let mut roots = rustls::RootCertStore::empty();
    let pem = std::fs::read(ca_pem).unwrap();
    for cert in rustls_pemfile::certs(&mut pem.as_slice()) {
        roots.add(cert.unwrap()).unwrap();
    }
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let conn = rustls::ClientConnection::new(std::sync::Arc::new(config), name).unwrap();
    let sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    rustls::StreamOwned::new(conn, sock)
}

/// Send one keep-alive GET and read back one Content-Length framed
/// response; returns the head.
fn tls_get(c: &mut TlsClient) -> String {
    use std::io::{Read, Write};
    c.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .unwrap();
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        if let Some(i) = got.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8(got[..i + 4].to_vec()).unwrap();
            let len: usize = header_value(&head, "Content-Length")
                .map(|v| v.trim().parse().unwrap())
                .unwrap_or(0);
            while got.len() < i + 4 + len {
                let n = c.read(&mut buf).unwrap();
                assert!(n > 0, "connection closed mid-response");
                got.extend_from_slice(&buf[..n]);
            }
            return head;
        }
        let n = c.read(&mut buf).unwrap();
        assert!(n > 0, "connection closed before a response");
        got.extend_from_slice(&buf[..n]);
    }
}

/// `keepalive_timeout` closes an idle TLS connection, as it does a plain
/// one (it used to stay open until the client went away).
#[test]
fn tls_keepalive_idle_timeout_closes_connection() {
    use std::io::Read;
    let certs = make_ca_and_leaf("localhost");
    let ca = certs.ca_path().unwrap().to_path_buf();
    let server = spawn_https_server(&KEEPALIVE_CONF.replace("%%TIMEOUT%%", "1"), certs);
    let mut c = tls_connect(server.port, &ca);
    let head = tls_get(&mut c);
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");

    let idle_from = Instant::now();
    let mut rest = Vec::new();
    // Ends on close_notify (Ok) or a bare FIN (UnexpectedEof); a read
    // timeout (WouldBlock after 5s) means the connection was never closed.
    let res = c.read_to_end(&mut rest);
    let waited = idle_from.elapsed();
    if let Err(e) = &res {
        assert_eq!(e.kind(), std::io::ErrorKind::UnexpectedEof, "{e}");
    }
    assert!(rest.is_empty());
    assert!(
        waited >= Duration::from_millis(800) && waited < Duration::from_secs(4),
        "closed after {waited:?}"
    );
}

/// An idle TLS connection still wakes up for the next request before the
/// timeout, and a request sent right behind the handshake (possibly in the
/// same flight as the client's Finished) is answered without waiting for
/// more socket input.
#[test]
fn tls_keepalive_serves_requests_around_idle_waits() {
    let certs = make_ca_and_leaf("localhost");
    let ca = certs.ca_path().unwrap().to_path_buf();
    let server = spawn_https_server(&KEEPALIVE_CONF.replace("%%TIMEOUT%%", "3"), certs);

    for _ in 0..20 {
        let mut c = tls_connect(server.port, &ca);
        assert!(tls_get(&mut c).starts_with("HTTP/1.1 200"));
    }

    let mut c = tls_connect(server.port, &ca);
    assert!(tls_get(&mut c).starts_with("HTTP/1.1 200"));
    sleep(Duration::from_millis(1200));
    assert!(tls_get(&mut c).starts_with("HTTP/1.1 200"));
}
