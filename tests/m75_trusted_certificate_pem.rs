//! M75 — `ssl_certificate` in OpenSSL's `-trustout` form (`-----BEGIN
//! TRUSTED CERTIFICATE-----`: the certificate followed by trust settings),
//! as nginx reads it with `PEM_read_bio_X509_AUX`. It used to be "no
//! certificates in …" and ruxen didn't start.

mod common;

use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

#[test]
fn a_trusted_certificate_block_is_served() {
    let certs = common::tls::make_self_signed("localhost");
    let trusted = certs.cert_path().with_file_name("trusted.pem");
    let status = Command::new("openssl")
        .args(["x509", "-addtrust", "serverAuth", "-trustout", "-in"])
        .arg(certs.cert_path())
        .arg("-out")
        .arg(&trusted)
        .status()
        .expect("openssl");
    assert!(status.success());
    let pem = std::fs::read_to_string(&trusted).unwrap();
    assert!(
        pem.starts_with("-----BEGIN TRUSTED CERTIFICATE-----"),
        "{pem}"
    );

    let setup = common::ports::setup_lock();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let dir = std::env::temp_dir().join(format!("ruxen-m75-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "pid {d}/ruxen.pid;\nevents {{}}\nhttp {{ server {{\n\
               listen 127.0.0.1:{port} ssl;\n\
               ssl_certificate {c}; ssl_certificate_key {k};\n\
               location / {{ return 200 ok; }} }} }}\n",
            d = dir.display(),
            c = trusted.display(),
            k = certs.key_path().display()
        ),
    )
    .unwrap();

    let check = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .arg("-t")
        .arg("-c")
        .arg(dir.join("nginx.conf"))
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "{}",
        String::from_utf8_lossy(&check.stderr)
    );

    let mut child = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .arg("-c")
        .arg(dir.join("nginx.conf"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    while !dir.join("ruxen.pid").exists() {
        assert!(
            Instant::now() < deadline && child.try_wait().unwrap().is_none(),
            "ruxen did not start"
        );
        sleep(Duration::from_millis(10));
    }
    drop(setup);
    let out = Command::new("curl")
        .args(["-sk", "--resolve"])
        .arg(format!("localhost:{port}:127.0.0.1"))
        .arg(format!("https://localhost:{port}/"))
        .output()
        .expect("curl");
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(String::from_utf8_lossy(&out.stdout), "ok");
}
