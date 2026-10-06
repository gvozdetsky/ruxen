//! M73 — a TLS 1.2 client that tries to renegotiate mid-request is refused
//! at once, as nginx (OpenSSL with `SSL_OP_NO_RENEGOTIATION`) refuses it.
//! rustls queues a `no_renegotiation` alert while reading; ruxen used to
//! send it only with its next write, which never came while it waited for
//! the rest of the request, so both sides hung until a timeout.

mod common;

use std::io::Write;
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

#[test]
fn renegotiation_is_refused_at_once() {
    let certs = common::tls::make_self_signed("localhost");
    let setup = common::ports::setup_lock();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let dir = std::env::temp_dir().join(format!("ruxen-m73-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "pid {d}/ruxen.pid;\nevents {{}}\nhttp {{ server {{\n\
               listen 127.0.0.1:{port} ssl; ssl_protocols TLSv1.2;\n\
               ssl_certificate {c}; ssl_certificate_key {k};\n\
               location / {{ return 200 ok; }} }} }}\n",
            d = dir.display(),
            c = certs.cert_path().display(),
            k = certs.key_path().display()
        ),
    )
    .unwrap();
    let mut server = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .arg("-c")
        .arg(dir.join("nginx.conf"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    while !dir.join("ruxen.pid").exists() {
        assert!(
            Instant::now() < deadline && server.try_wait().unwrap().is_none(),
            "ruxen did not start"
        );
        sleep(Duration::from_millis(10));
    }
    drop(setup);

    // Half a request, then `R`: s_client renegotiates (a new ClientHello on
    // the established connection) and waits for the server's answer.
    let mut client = Command::new("openssl")
        .args(["s_client", "-tls1_2", "-connect"])
        .arg(format!("127.0.0.1:{port}"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("openssl");
    let mut stdin = client.stdin.take().unwrap();
    stdin.write_all(b"GET / HTTP/1.0\n").unwrap();
    sleep(Duration::from_millis(300));
    stdin.write_all(b"R\n").unwrap();
    let started = Instant::now();
    let mut done = None;
    while started.elapsed() < Duration::from_secs(5) {
        if let Some(status) = client.try_wait().unwrap() {
            done = Some(status);
            break;
        }
        sleep(Duration::from_millis(20));
    }
    let hung = done.is_none();
    let _ = client.kill();
    let out = client.wait_with_output().unwrap();
    let _ = server.kill();
    let _ = server.wait();
    let _ = std::fs::remove_dir_all(&dir);
    drop(stdin);

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!hung, "the renegotiation attempt hung: {stderr}");
    assert!(
        stderr.contains("no renegotiation") || stderr.contains("alert"),
        "{stderr}"
    );
}
