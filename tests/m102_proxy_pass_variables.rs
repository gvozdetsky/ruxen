//! M102 — `proxy_pass` with variables (#100): the URL is rendered per
//! request. An `upstream` block of that name (when the URL has no port),
//! an IP literal or a `unix:` path is used as nginx does; any other name
//! would need a resolver, so it is a 502 with nginx's `no resolver defined
//! to resolve` line. A URI part in the URL is the whole upstream URI;
//! without one the request's own URI goes up. `$proxy_host` and `Host`
//! come from the rendered URL.

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
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

/// A backend answering with the request line and the Host header.
/// Answers with the request line and `Host`. It listens on `[::1]` too,
/// with the same port: `localhost` resolves to `::1` first on some
/// systems (GitHub's runners), and ruxen takes the first address.
fn backend() -> u16 {
    let (listener, v6) = {
        let _setup = common::ports::setup_lock();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        (listener, TcpListener::bind(("::1", port)).ok())
    };
    let port = listener.local_addr().unwrap().port();
    for listener in std::iter::once(listener).chain(v6) {
        std::thread::spawn(move || serve(listener));
    }
    port
}

fn serve(listener: TcpListener) {
    for conn in listener.incoming().flatten() {
        std::thread::spawn(move || {
            let mut reader = BufReader::new(conn.try_clone().unwrap());
            let mut conn = conn;
            let mut request_line = String::new();
            reader.read_line(&mut request_line).unwrap();
            let mut host = String::from("-");
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                    break;
                }
                if let Some(v) = line.strip_prefix("Host: ") {
                    host = v.trim_end().to_string();
                }
            }
            let body = format!("{} | {host}", request_line.trim_end());
            let _ = write!(
                conn,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
        });
    }
}

fn start(conf: impl FnOnce(&str, u16) -> String) -> (Server, u16) {
    let dir = std::env::temp_dir().join(format!("ruxen-m102-{}-{}", std::process::id(), {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        N.fetch_add(1, Ordering::Relaxed)
    }));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let _setup = common::ports::setup_lock();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    std::fs::write(
        dir.join("nginx.conf"),
        conf(&dir.display().to_string(), port),
    )
    .unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .arg("-c")
        .arg(dir.join("nginx.conf"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "ruxen did not start");
        std::thread::sleep(Duration::from_millis(20));
    }
    (Server(child, dir), port)
}

fn get(port: u16, target: &str) -> (u16, String) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(
        s,
        "GET {target} HTTP/1.1\r\nHost: front\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    let status = out[9..12].parse().unwrap();
    let body = out.split_once("\r\n\r\n").unwrap().1.to_string();
    (status, body)
}

fn config(backend: u16) -> impl FnOnce(&str, u16) -> String {
    move |dir, port| {
        format!(
            "error_log {dir}/error.log;\nevents {{}}\nhttp {{\n\
             access_log {dir}/access.log up;\n\
             log_format up '$upstream_addr';\n\
             upstream u {{ server 127.0.0.1:{backend}; }}\n\
             server {{ listen 127.0.0.1:{port};\n\
             location / {{ proxy_pass http://$arg_b; }}\n\
             location /static/ {{ proxy_pass http://localhost:{backend}/s/; }}\n\
             location /fixed/ {{ proxy_pass http://$arg_b/up$arg_c;\n\
             proxy_set_header X-Proxy-Host $proxy_host; }}\n\
             }} }}\n"
        )
    }
}

#[test]
fn m102_upstream_name_or_ip_literal() {
    let backend = backend();
    let (server, port) = start(config(backend));
    // An IP literal with a port: one peer; `Host` is the authority.
    assert_eq!(
        get(port, &format!("/a?b=127.0.0.1:{backend}")),
        (
            200,
            format!("GET /a?b=127.0.0.1:{backend} HTTP/1.0 | 127.0.0.1:{backend}")
        )
    );
    // An upstream block's name; any case.
    assert_eq!(
        get(port, "/a?b=U"),
        (200, "GET /a?b=U HTTP/1.0 | U".to_string())
    );
    // A host name that another location's `proxy_pass` names with the
    // same port: nginx's implicit upstream, no resolver needed.
    assert_eq!(
        get(port, &format!("/a?b=localhost:{backend}")),
        (
            200,
            format!("GET /a?b=localhost:{backend} HTTP/1.0 | localhost:{backend}")
        )
    );
    // A URI part, with a `?` in it, is the whole upstream URI.
    assert_eq!(
        get(port, &format!("/fixed/x?b=127.0.0.1:{backend}&c=?q=1")),
        (200, format!("GET /up?q=1 HTTP/1.0 | 127.0.0.1:{backend}"))
    );
    let log = std::fs::read_to_string(server.1.join("access.log")).unwrap();
    let want = format!("127.0.0.1:{backend}");
    assert_eq!(log.lines().collect::<Vec<_>>(), [want.as_str(); 4]);
}

#[test]
fn m102_name_without_resolver_is_502() {
    let backend = backend();
    let (server, port) = start(config(backend));
    // A host name that isn't an upstream block, and an upstream name with
    // a port, would need a resolver.
    assert_eq!(get(port, "/a?b=example.org").0, 502);
    assert_eq!(get(port, "/a?b=u:80").0, 502);
    // Not http://: nginx's 500.
    assert_eq!(get(port, "/a?b=").0, 500);
    let log = std::fs::read_to_string(server.1.join("error.log")).unwrap();
    assert!(
        log.contains("[error] ")
            && log.contains(" no resolver defined to resolve example.org, client: 127.0.0.1,"),
        "{log}"
    );
    assert!(log.contains(" no resolver defined to resolve u, "), "{log}");
    assert!(log.contains(" invalid URL prefix in \"http://\""), "{log}");
}

#[test]
fn m102_unix_path_in_the_url() {
    let backend = backend();
    let (server, port) = start(config(backend));
    let sock = server.1.join("up.sock");
    let listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
    std::thread::spawn(move || {
        for conn in listener.incoming().flatten() {
            let mut reader = BufReader::new(conn.try_clone().unwrap());
            let mut conn = conn;
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let body = line.trim_end().to_string();
            let _ = write!(
                conn,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    assert_eq!(
        get(port, &format!("/a?b=unix:{}:/z", sock.display())),
        (200, "GET /z HTTP/1.0".to_string())
    );
}

#[test]
fn m102_proxy_redirect_default_is_refused_with_variables() {
    let dir = std::env::temp_dir().join(format!("ruxen-m102-t-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("nginx.conf"),
        "events {}\nhttp { server { listen 127.0.0.1:18102;\n\
         location / { proxy_pass http://$arg_b; proxy_redirect default; } } }\n",
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
    assert!(
        stderr.contains(
            "\"proxy_redirect default\" cannot be used with \"proxy_pass\" directive with variables"
        ),
        "{stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
