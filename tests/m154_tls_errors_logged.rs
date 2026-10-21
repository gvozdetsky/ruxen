//! M154 — a TLS handshake that fails goes to `error_log` at `info` in
//! nginx's words (#595), not to stderr: what rustls refused as
//! `SSL_do_handshake() failed (SSL: …) while SSL handshaking`, a client that
//! hangs up as `peer closed connection in SSL handshake`, each with
//! `client:` and `server:`.

mod common;

use std::io::Write;
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

struct KillOnDrop(std::process::Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn m154_failed_handshakes_go_to_the_error_log() {
    let certs = common::tls::make_self_signed("localhost");
    let dir = std::env::temp_dir().join(format!("ruxen-m154-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let setup = common::ports::setup_lock();
    let [port] = common::ports::free_ports();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "pid {d}/ruxen.pid;\nerror_log {d}/error.log info;\nevents {{}}\nhttp {{ access_log off;\n\
             server {{ listen 127.0.0.1:{port} ssl; ssl_certificate {c}; ssl_certificate_key {k};\n\
             location / {{ return 200; }} }} }}\n",
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
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    common::ports::wait_for_pid_file(&mut child.0, &dir.join("ruxen.pid"), Duration::from_secs(5));
    drop(setup);

    // A handshake record whose message claims more than it holds.
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.write_all(b"\x16\x03\x01\x00\x05hello").unwrap();
    // The start of a record, then nothing: the client hangs up.
    let mut s2 = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s2.write_all(b"\x16\x03\x01").unwrap();
    drop(s2);

    let wanted = [
        "[info] ",
        "SSL_do_handshake() failed (SSL: ",
        "peer closed connection in SSL handshake while SSL handshaking",
    ];
    let server = format!("while SSL handshaking, client: 127.0.0.1, server: 127.0.0.1:{port}");
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let log = std::fs::read_to_string(dir.join("error.log")).unwrap_or_default();
        if wanted.iter().all(|w| log.contains(w)) && log.matches(&server).count() == 2 {
            break;
        }
        assert!(Instant::now() < deadline, "{log}");
        std::thread::sleep(Duration::from_millis(50));
    }
    drop(s);
    let _ = std::fs::remove_dir_all(&dir);
}
