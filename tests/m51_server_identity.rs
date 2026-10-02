//! M51 — responses name ruxen (`Server: ruxen/<version>`, and the same in
//! the footer of built-in HTML error pages, e.g. `return 404;`);
//! `server_tokens off` drops the version. Under
//! nginx-tests (`RUXEN_NGINX_IDENTITY=1`, set by
//! scripts/run_nginx_tests.sh) they name nginx/1.29.2, the version `-V`
//! reports, because the upstream tests assert it.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

struct Server {
    child: Child,
    port: u16,
    dir: std::path::PathBuf,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn start(nginx_identity: bool) -> Server {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let port = {
        let probe = TcpListener::bind("127.0.0.1:0").unwrap();
        probe.local_addr().unwrap().port()
    };
    let dir = std::env::temp_dir().join(format!(
        "ruxen-m51-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(dir.join("www")).unwrap();
    let conf = dir.join("nginx.conf");
    std::fs::write(
        &conf,
        format!(
            "events {{}}\nhttp {{ server {{ listen 127.0.0.1:{port}; root {}; \
             location /gone {{ return 404; }} \
             location /quiet/ {{ server_tokens off; return 404; }} }} }}\n",
            dir.join("www").display()
        ),
    )
    .unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ruxen"));
    cmd.arg("-c")
        .arg(&conf)
        .env_remove("RUXEN_NGINX_IDENTITY")
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if nginx_identity {
        cmd.env("RUXEN_NGINX_IDENTITY", "1");
    }
    let child = cmd.spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "ruxen did not start");
        sleep(Duration::from_millis(20));
    }
    Server { child, port, dir }
}

fn get(port: u16, path: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
    out
}

#[test]
fn responses_name_ruxen_by_default() {
    let server = start(false);
    let versioned = format!("ruxen/{}", env!("CARGO_PKG_VERSION"));

    let resp = get(server.port, "/missing");
    assert!(resp.starts_with("HTTP/1.1 404"), "{resp}");
    assert!(
        resp.contains(&format!("\r\nServer: {versioned}\r\n")),
        "{resp}"
    );
    assert!(!resp.contains("nginx"), "{resp}");

    let resp = get(server.port, "/gone");
    assert!(
        resp.contains(&format!("\r\nServer: {versioned}\r\n")),
        "{resp}"
    );
    assert!(
        resp.contains(&format!("<center>{versioned}</center>")),
        "{resp}"
    );
    assert!(!resp.contains("nginx"), "{resp}");

    let resp = get(server.port, "/quiet/");
    assert!(resp.contains("\r\nServer: ruxen\r\n"), "{resp}");
    assert!(resp.contains("<center>ruxen</center>"), "{resp}");
}

#[test]
fn nginx_identity_for_the_test_harness() {
    let server = start(true);
    let resp = get(server.port, "/gone");
    assert!(resp.contains("\r\nServer: nginx/1.29.2\r\n"), "{resp}");
    assert!(resp.contains("<center>nginx/1.29.2</center>"), "{resp}");
    let resp = get(server.port, "/quiet/");
    assert!(resp.contains("\r\nServer: nginx\r\n"), "{resp}");
    assert!(resp.contains("<center>nginx</center>"), "{resp}");
}
