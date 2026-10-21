//! M99 — `unix:` upstream addresses (#101): `proxy_pass
//! http://unix:/path:/uri` and `server unix:/path;` in an upstream block,
//! with nginx's `Host: localhost`, `$upstream_addr` and connect() error
//! line.

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Server(Child, PathBuf);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
        let _ = std::fs::remove_dir_all(&self.1);
    }
}

/// A backend on `path`: every request is answered with its request line
/// and Host header, numbered by the connection it came on.
fn backend(path: &Path) {
    let listener = UnixListener::bind(path).unwrap();
    std::thread::spawn(move || {
        for (n, conn) in listener.incoming().enumerate() {
            let Ok(conn) = conn else { return };
            std::thread::spawn(move || {
                let mut reader = BufReader::new(conn.try_clone().unwrap());
                let mut conn = conn;
                loop {
                    let mut request_line = String::new();
                    if reader.read_line(&mut request_line).unwrap_or(0) == 0 {
                        return;
                    }
                    let mut host = String::from("-");
                    loop {
                        let mut line = String::new();
                        reader.read_line(&mut line).unwrap();
                        if line == "\r\n" {
                            break;
                        }
                        if let Some(value) = line.strip_prefix("Host: ") {
                            host = value.trim_end().to_string();
                        }
                    }
                    let body = format!("conn{n} {} {host}\n", request_line.trim_end());
                    write!(
                        conn,
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    )
                    .unwrap();
                }
            });
        }
    });
}

fn start(name: &str) -> (Server, u16) {
    let dir = std::env::temp_dir().join(format!("ruxen-m99-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    backend(&dir.join("up.sock"));
    // Held until ruxen listens: released earlier, another test could take
    // the same free port, and ruxen would fail to bind it.
    let setup = common::ports::setup_lock();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let d = dir.display();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "error_log {d}/error.log;\nevents {{}}\nhttp {{\n\
             log_format a '$upstream_addr';\n\
             upstream u {{ server unix:{d}/up.sock; keepalive 2; }}\n\
             server {{ listen 127.0.0.1:{port};\n\
             access_log {d}/access.log a;\n\
             location / {{ proxy_pass http://unix:{d}/up.sock:/; }}\n\
             location /bare {{ proxy_pass http://UNIX:{d}/up.sock; }}\n\
             location /u {{ proxy_pass http://u; proxy_http_version 1.1;\n\
             proxy_set_header Connection \"\"; }}\n\
             location /missing {{ proxy_pass http://unix:{d}/none.sock:/x; }}\n\
             }} }}\n"
        ),
    )
    .unwrap();
    // Owned by `Server` before the wait: if it panics, ruxen still stops.
    let mut server = Server(
        Command::new(env!("CARGO_BIN_EXE_ruxen"))
            .arg("-c")
            .arg(dir.join("nginx.conf"))
            .arg("-g")
            .arg(format!("pid {}/ruxen.pid;", dir.display()))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
        dir,
    );
    let pid_file = server.1.join("ruxen.pid");
    common::ports::wait_for_pid_file(&mut server.0, &pid_file, Duration::from_secs(5));
    drop(setup);
    (server, port)
}

fn get(port: u16, path: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

fn body(response: &str) -> &str {
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    response.split_once("\r\n\r\n").unwrap().1
}

/// The log line holding `needle`, waiting for it to be written.
fn log_line(path: &Path, needle: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        if let Some(line) = text.lines().find(|l| l.contains(needle)) {
            return line.to_string();
        }
        assert!(Instant::now() < deadline, "no {needle:?} in {text}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn m99_proxy_pass_to_a_unix_socket() {
    let (server, port) = start("pass");
    // The path ends at the next `:`; the URI after it replaces the
    // location prefix, and the upstream sees `Host: localhost`.
    let response = get(port, "/abc");
    assert!(
        body(&response).ends_with(" GET /abc HTTP/1.1 localhost\n"),
        "{response}"
    );
    // No URI part (and a scheme in any case, as ngx_parse_url): the
    // client URI goes through unchanged.
    assert!(body(&get(port, "/bare/q?x=1")).ends_with(" GET /bare/q?x=1 HTTP/1.1 localhost\n"));
    let dir = &server.1;
    assert_eq!(
        log_line(&dir.join("access.log"), "unix:"),
        format!("unix:{}/up.sock", dir.display())
    );
}

#[test]
fn m99_upstream_server_on_a_unix_socket_keeps_connections_alive() {
    let (_server, port) = start("upstream");
    let first = body(&get(port, "/u/1")).to_string();
    let second = body(&get(port, "/u/2")).to_string();
    assert!(first.ends_with(" GET /u/1 HTTP/1.1 u\n"), "{first}");
    assert!(second.ends_with(" GET /u/2 HTTP/1.1 u\n"), "{second}");
    // Both went over the same pooled connection.
    assert_eq!(first.split(' ').next(), second.split(' ').next());
}

#[test]
fn m99_missing_socket_is_a_502_with_nginx_error_line() {
    let (server, port) = start("missing");
    let response = get(port, "/missing");
    assert!(response.starts_with("HTTP/1.1 502"), "{response}");
    let dir = server.1.display();
    let line = log_line(&server.1.join("error.log"), "connect() to");
    // A missing socket file is `crit` in nginx; only refusals are `error`.
    assert!(line.contains("[crit] "), "{line}");
    assert!(
        line.contains(&format!(
            "connect() to unix:{dir}/none.sock failed (2: No such file or directory) \
             while connecting to upstream"
        )),
        "{line}"
    );
    assert!(
        line.contains(&format!("upstream: \"http://unix:{dir}/none.sock:/x\"")),
        "{line}"
    );
}

#[test]
fn m99_unix_address_needs_a_path() {
    let dir = std::env::temp_dir().join(format!("ruxen-m99-bad-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let long = format!("/{}", "a".repeat(107));
    for (server, error) in [
        ("server unix:;", "no path in the unix domain socket"),
        (
            &format!("server unix:{long};")[..],
            "too long path in the unix domain socket",
        ),
    ] {
        std::fs::write(
            dir.join("nginx.conf"),
            format!("events {{}}\nhttp {{ upstream u {{ {server} }} }}\n"),
        )
        .unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_ruxen"))
            .arg("-t")
            .arg("-c")
            .arg(dir.join("nginx.conf"))
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "{stderr}");
        assert!(stderr.contains(error), "{stderr}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}
