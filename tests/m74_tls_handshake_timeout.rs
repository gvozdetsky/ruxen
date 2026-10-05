//! M74 — the TLS handshake is bounded by the default server's
//! `client_header_timeout`, as nginx 1.24 (no separate handshake timeout:
//! the timer armed at accept covers the handshake). It used to be a fixed
//! 60 s, so a lower `client_header_timeout` didn't shed idle or slow
//! clients on HTTPS ports.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

/// Seconds until the server closes a connection that sent `bytes`.
fn closed_after(port: u16, bytes: &[u8]) -> Duration {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(8))).unwrap();
    s.write_all(bytes).unwrap();
    let started = Instant::now();
    let mut buf = [0u8; 64];
    // EOF (or a reset) when the server gives up; a read timeout otherwise.
    let _ = s.read(&mut buf);
    started.elapsed()
}

#[test]
fn an_idle_or_slow_handshake_times_out_with_client_header_timeout() {
    let certs = common::tls::make_self_signed("localhost");
    let setup = common::ports::setup_lock();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let dir = std::env::temp_dir().join(format!("ruxen-m74-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "pid {d}/ruxen.pid;\nevents {{}}\nhttp {{ client_header_timeout 1s;\n\
             server {{ listen 127.0.0.1:{port} ssl;\n\
               ssl_certificate {c}; ssl_certificate_key {k};\n\
               location / {{ return 200 ok; }} }} }}\n",
            d = dir.display(),
            c = certs.cert_path().display(),
            k = certs.key_path().display()
        ),
    )
    .unwrap();
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

    // Nothing at all, then the first 6 bytes of a ClientHello record.
    let idle = closed_after(port, b"");
    let partial = closed_after(port, &[0x16, 0x03, 0x01, 0x00, 0x05, 0x01]);
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&dir);

    for (what, took) in [("idle", idle), ("partial ClientHello", partial)] {
        assert!(
            took >= Duration::from_millis(800) && took < Duration::from_secs(3),
            "{what}: closed after {took:?}"
        );
    }
}
