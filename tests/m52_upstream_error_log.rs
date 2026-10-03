//! M52 — failed upstream attempts are logged like nginx:
//! `<date> [error] <pid>#<tid>: *<conn> connect() failed (111: Connection
//! refused) while connecting to upstream, client: …, server: …, request:
//! "…", upstream: "…", host: "…"`. Without an `error_log` the lines go to
//! stderr (here redirected by `-e`); with one, they go there instead.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

use common::ports::DeadPort;

struct Server {
    child: Child,
    port: u16,
    dir: PathBuf,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn start(tag: &str, server_body: &str) -> Server {
    let port = {
        let probe = TcpListener::bind("127.0.0.1:0").unwrap();
        probe.local_addr().unwrap().port()
    };
    let dir = std::env::temp_dir().join(format!("ruxen-m52-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(dir.join("www")).unwrap();
    let body = server_body.replace("%%DIR%%", dir.to_str().unwrap());
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "events {{}}\nhttp {{ {body} }}\n",
            body = body.replace("%%PORT%%", &port.to_string())
        ),
    )
    .unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .arg("-c")
        .arg(dir.join("nginx.conf"))
        .arg("-e")
        .arg(dir.join("stderr.log"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "ruxen did not start");
        sleep(Duration::from_millis(20));
    }
    Server { child, port, dir }
}

fn get(port: u16, path: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
    out
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

/// The line containing `needle`, checked for nginx's prefix.
fn line_with<'a>(log: &'a str, needle: &str) -> &'a str {
    let line = log
        .lines()
        .find(|l| l.contains(needle))
        .unwrap_or_else(|| panic!("no line with {needle:?} in:\n{log}"));
    // `2026/10/02 14:00:00 [error] 1234#1235: *1 `
    let b = line.as_bytes();
    assert!(
        b.len() > 20 && b[4] == b'/' && b[7] == b'/' && b[13] == b':' && b[16] == b':',
        "{line}"
    );
    assert!(line[19..].starts_with(" [error] "), "{line}");
    let after = &line[28..];
    let (pid_tid, rest) = after.split_once(": *").expect("pid#tid: *conn");
    assert!(pid_tid.contains('#'), "{line}");
    assert!(
        rest.split(' ').next().unwrap().parse::<u64>().is_ok(),
        "{line}"
    );
    line
}

#[test]
fn upstream_failures_are_logged_like_nginx() {
    let refused = DeadPort::new();
    let dead = DeadPort::new();
    let dead2 = DeadPort::new();
    // Accepts and never answers: a read timeout.
    let silent = TcpListener::bind("127.0.0.1:0").unwrap();
    let silent_port = silent.local_addr().unwrap().port();
    // Accepts, reads the request, closes without a response.
    let closing = TcpListener::bind("127.0.0.1:0").unwrap();
    let closing_port = closing.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in closing.incoming().flatten() {
            let mut s = s;
            let mut buf = [0u8; 4096];
            let _ = s.read(&mut buf);
        }
    });

    let server = start(
        "upstream",
        &format!(
            "upstream single {{ server 127.0.0.1:{refused} max_fails=1 fail_timeout=60s; }} \
             upstream down {{ server 127.0.0.1:{dead} max_fails=1 fail_timeout=60s; \
                              server 127.0.0.1:{dead2} max_fails=1 fail_timeout=60s; }} \
             server {{ listen 127.0.0.1:%%PORT%%; server_name example.test; root %%DIR%%/www; \
               location /refused/ {{ proxy_pass http://127.0.0.1:{refused}; }} \
               location /down/ {{ proxy_pass http://down; }} \
               location /single/ {{ proxy_pass http://single; }} \
               location /silent/ {{ proxy_pass http://127.0.0.1:{silent_port}; \
                                   proxy_read_timeout 1s; }} \
               location /closing/ {{ proxy_pass http://127.0.0.1:{closing_port}; }} \
             }}",
            dead = dead.port(),
            dead2 = dead2.port(),
            refused = refused.port(),
        ),
    );

    assert!(get(server.port, "/refused/x?a=1").starts_with("HTTP/1.1 502"));
    assert!(get(server.port, "/down/1").starts_with("HTTP/1.1 502"));
    assert!(get(server.port, "/down/2").starts_with("HTTP/1.1 502"));
    assert!(get(server.port, "/single/1").starts_with("HTTP/1.1 502"));
    assert!(get(server.port, "/single/2").starts_with("HTTP/1.1 502"));
    assert!(get(server.port, "/silent/").starts_with("HTTP/1.1 504"));
    assert!(get(server.port, "/closing/").starts_with("HTTP/1.1 502"));
    assert!(get(server.port, "/missing").starts_with("HTTP/1.1 404"));
    let log = read(&server.dir.join("stderr.log"));

    let line = line_with(&log, "/refused/x?a=1");
    assert!(
        line.ends_with(&format!(
            "connect() failed (111: Connection refused) while connecting to upstream, \
             client: 127.0.0.1, server: example.test, request: \"GET /refused/x?a=1 HTTP/1.1\", \
             upstream: \"http://127.0.0.1:{}/refused/x?a=1\", host: \"example.test\"",
            refused.port()
        )),
        "{line}"
    );
    // The first request tries both peers and marks them failed; the second
    // finds none.
    assert_eq!(
        log.lines()
            .filter(|l| l.contains("GET /down/1 ") && l.contains("connect() failed (111: "))
            .count(),
        2,
        "{log}"
    );
    let line = line_with(&log, "GET /down/2 ");
    assert!(
        line.contains("no live upstreams while connecting to upstream, client: 127.0.0.1"),
        "{line}"
    );
    assert!(!line.contains("upstream: \""), "{line}");
    // A lone server is never marked unavailable (nginx's `peers->single`):
    // both requests try it.
    for path in ["GET /single/1 ", "GET /single/2 "] {
        assert!(
            line_with(&log, path).contains("connect() failed (111: "),
            "{log}"
        );
    }
    assert!(line_with(&log, "GET /silent/ ").contains(
        "upstream timed out (110: Connection timed out) while reading response header from upstream"
    ));
    assert!(line_with(&log, "GET /closing/ ").contains(
        "upstream prematurely closed connection while reading response header from upstream"
    ));
    assert!(line_with(&log, "GET /missing ").contains(
        "/missing\" failed (2: No such file or directory), client: 127.0.0.1, server: example.test,"
    ));
    drop(silent);
}

#[test]
fn configured_error_log_takes_upstream_errors() {
    let refused = DeadPort::new();
    let server = start(
        "configured",
        &format!(
            "server {{ listen 127.0.0.1:%%PORT%%; server_name example.test; \
               error_log %%DIR%%/server.log; \
               location / {{ proxy_pass http://127.0.0.1:{}; }} }}",
            refused.port()
        ),
    );
    assert!(get(server.port, "/x").starts_with("HTTP/1.1 502"));
    let server_log = read(&server.dir.join("server.log"));
    line_with(&server_log, "connect() failed (111: Connection refused)");
    let stderr = read(&server.dir.join("stderr.log"));
    assert!(!stderr.contains("connect() failed"), "{stderr}");
}

/// error_log is inherited like nginx: server ← http ← top level. Before,
/// http- and top-level lines were ignored.
#[test]
fn error_log_inherits_from_http_and_top_level() {
    let port = {
        let probe = TcpListener::bind("127.0.0.1:0").unwrap();
        probe.local_addr().unwrap().port()
    };
    let dir = std::env::temp_dir().join(format!("ruxen-m52-inherit-{}", std::process::id()));
    std::fs::create_dir_all(dir.join("www")).unwrap();
    let d = dir.display();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "error_log {d}/main.log;\nevents {{}}\nhttp {{\n\
               server {{ listen 127.0.0.1:{port}; server_name main; root {d}/www; }}\n\
             }}\n"
        ),
    )
    .unwrap();
    // A second config adds http- and server-level logs.
    let port2 = {
        let probe = TcpListener::bind("127.0.0.1:0").unwrap();
        probe.local_addr().unwrap().port()
    };
    std::fs::write(
        dir.join("nginx2.conf"),
        format!(
            "error_log {d}/main2.log;\nevents {{}}\nhttp {{ error_log {d}/http.log;\n\
               server {{ listen 127.0.0.1:{port2}; server_name a; root {d}/www; }}\n\
               server {{ listen 127.0.0.1:{port2}; server_name b; root {d}/www;\n\
                         error_log {d}/server.log; }}\n\
             }}\n"
        ),
    )
    .unwrap();
    let spawn = |conf: &str, port: u16| {
        let child = Command::new(env!("CARGO_BIN_EXE_ruxen"))
            .arg("-c")
            .arg(dir.join(conf))
            .arg("-e")
            .arg(dir.join("stderr.log"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        while TcpStream::connect(("127.0.0.1", port)).is_err() {
            assert!(Instant::now() < deadline, "ruxen did not start");
            sleep(Duration::from_millis(20));
        }
        child
    };
    let get_host = |port: u16, host: &str, path: &str| {
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        write!(
            s,
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).unwrap();
        out
    };

    let mut one = spawn("nginx.conf", port);
    assert!(get_host(port, "main", "/from-main").starts_with("HTTP/1.1 404"));
    let mut two = spawn("nginx2.conf", port2);
    assert!(get_host(port2, "a", "/from-http").starts_with("HTTP/1.1 404"));
    assert!(get_host(port2, "b", "/from-server").starts_with("HTTP/1.1 404"));
    for c in [&mut one, &mut two] {
        let _ = c.kill();
        let _ = c.wait();
    }

    let read = |f: &str| std::fs::read_to_string(dir.join(f)).unwrap_or_default();
    // Top level only: it takes the request errors.
    line_with(&read("main.log"), "/from-main\" failed");
    // http overrides the top level; server overrides http.
    line_with(&read("http.log"), "/from-http\" failed");
    assert!(!read("main2.log").contains("from-http"));
    line_with(&read("server.log"), "/from-server\" failed");
    assert!(!read("http.log").contains("from-server"));
    // Nothing reached stderr: every request had a configured log.
    assert!(
        !read("stderr.log").contains("open()"),
        "{}",
        read("stderr.log")
    );
    let _ = std::fs::remove_dir_all(&dir);
}
