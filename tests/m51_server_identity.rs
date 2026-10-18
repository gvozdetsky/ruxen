//! M51 — responses name ruxen (`Server: ruxen/<version>`, and the same in
//! the footer of built-in HTML error pages, e.g. `return 404;`);
//! `server_tokens off` drops the version. Under
//! nginx-tests (`RUXEN_NGINX_IDENTITY=1`, set by
//! scripts/run_nginx_tests.sh) they name nginx/1.29.2, because the upstream
//! tests assert it, and `-V` adds its `nginx version:` line.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

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
    // Held from the port pick until ruxen listens: a parallel test's
    // backend can't take the port in between (#230).
    let setup = common::ports::setup_lock();
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
        .arg("-g")
        .arg(format!("pid {}/ruxen.pid;", dir.display()))
        .env_remove("RUXEN_NGINX_IDENTITY")
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if nginx_identity {
        cmd.env("RUXEN_NGINX_IDENTITY", "1");
    }
    // Owned by `Server` before the wait: if it panics, ruxen still stops.
    let mut server = Server {
        child: cmd.spawn().unwrap(),
        port,
        dir,
    };
    let pid_file = server.dir.join("ruxen.pid");
    common::ports::wait_for_pid_file(&mut server.child, &pid_file, Duration::from_secs(3));
    drop(setup);
    server
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

fn version(nginx_identity: bool) -> String {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ruxen"));
    cmd.arg("-V").env_remove("RUXEN_NGINX_IDENTITY");
    if nginx_identity {
        cmd.env("RUXEN_NGINX_IDENTITY", "1");
    }
    let out = cmd.output().unwrap();
    assert!(out.status.success());
    String::from_utf8(out.stdout).unwrap()
}

#[test]
fn version_names_nginx_only_for_the_test_harness() {
    let ruxen = version(false);
    let first = format!("ruxen version: ruxen/{}\n", env!("CARGO_PKG_VERSION"));
    assert!(ruxen.starts_with(&first), "{ruxen}");
    assert!(!ruxen.contains("nginx version"), "{ruxen}");

    let nginx = version(true);
    assert_eq!(nginx, format!("nginx version: nginx/1.29.2\n{ruxen}"));
}
