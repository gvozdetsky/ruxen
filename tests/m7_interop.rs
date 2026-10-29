mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::MutexGuard;
use std::thread::sleep;
use std::time::{Duration, Instant};

#[cfg(unix)]
unsafe extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
}

#[cfg(unix)]
const SIGQUIT: i32 = 3;

struct ServerGuard {
    child: Child,
    tempdir: PathBuf,
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.tempdir);
    }
}

fn pick_port() -> (u16, MutexGuard<'static, ()>) {
    let g = common::ports::setup_lock();
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let p = l.local_addr().unwrap().port();
    drop(l);
    (p, g)
}

fn unique_dir() -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let d = std::env::temp_dir().join(format!(
        "ruxen-m7-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir(&d).unwrap();
    d
}

fn spawn_server(conf: &str) -> (ServerGuard, u16, PathBuf) {
    let (port, _lock) = pick_port();
    let dir = unique_dir();
    let conf_path = dir.join("nginx.conf");
    std::fs::write(&conf_path, conf.replace("%%PORT%%", &port.to_string())).unwrap();

    let pid_file = dir.join("ruxen.pid");
    let child = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .args(["-c", conf_path.to_str().unwrap()])
        .arg("-g")
        .arg(format!("pid {};", pid_file.display()))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ruxen");
    // Owned by the guard before the wait: if it panics, ruxen still stops.
    let mut guard = ServerGuard {
        child,
        tempdir: dir.clone(),
    };
    common::ports::wait_for_pid_file(&mut guard.child, &pid_file, Duration::from_secs(5));
    (guard, port, dir)
}

fn request(port: u16, raw: &[u8]) -> Vec<u8> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    s.write_all(raw).unwrap();
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match s.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(_) => break,
        }
    }
    out
}

fn status_line(resp: &[u8]) -> &str {
    let end = resp.iter().position(|&b| b == b'\r').unwrap_or(resp.len());
    std::str::from_utf8(&resp[..end]).unwrap()
}

fn body(resp: &[u8]) -> &[u8] {
    resp.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| &resp[i + 4..])
        .unwrap_or(&[])
}

#[test]
fn m7_t_validates_repo_configs_and_rejects_broken_conf() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for rel in [
        "bench/m1/nginx.conf",
        "bench/m3/nginx.conf",
        "bench/m5/nginx.conf",
    ] {
        // `-t` opens the error log the config names (under /tmp for the
        // bench configs): remove the ones this check created, not a
        // benchmark run's.
        let conf = std::fs::read_to_string(root.join(rel)).unwrap();
        let logs: Vec<PathBuf> = conf
            .lines()
            .filter_map(|l| l.trim().strip_prefix("error_log"))
            .filter_map(|rest| rest.split_whitespace().next())
            .map(|p| PathBuf::from(p.trim_end_matches(';')))
            .filter(|p| p.is_absolute() && !p.exists())
            .collect();
        let status = Command::new(env!("CARGO_BIN_EXE_ruxen"))
            .args(["-t", "-c"])
            .arg(root.join(rel))
            .status()
            .unwrap();
        for log in logs {
            let _ = std::fs::remove_file(log);
        }
        assert!(status.success(), "{rel} should validate");
    }

    let dir = unique_dir();
    let broken = dir.join("broken.conf");
    std::fs::write(
        &broken,
        "http { server { listen 80; not_a_real_directive on; } }\n",
    )
    .unwrap();
    let status = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .args(["-t", "-c"])
        .arg(&broken)
        .status()
        .unwrap();
    assert!(!status.success(), "broken config should fail validation");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn m7_pid_file_and_quit_work() {
    let (port, _lock) = pick_port();
    let dir = unique_dir();
    let pid_path = dir.join("nginx.pid");
    let conf_path = dir.join("nginx.conf");
    std::fs::write(
        &conf_path,
        format!(
            "pid {};\n\
             events {{}}\n\
             http {{ server {{ listen {port}; location / {{ return 200 \"ok\"; }} }} }}\n",
            pid_path.display()
        ),
    )
    .unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .args(["-c", conf_path.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    let deadline = Instant::now() + Duration::from_secs(1);
    while !pid_path.exists() {
        assert!(Instant::now() <= deadline, "pid file was not written");
        sleep(Duration::from_millis(10));
    }

    #[cfg(unix)]
    unsafe {
        assert_eq!(kill(child.id() as i32, SIGQUIT), 0);
    }

    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success() || !status.success());
            break;
        }
        assert!(
            Instant::now() <= deadline,
            "server did not exit after SIGQUIT"
        );
        sleep(Duration::from_millis(10));
    }

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn m7_method_handling_matches_nginx_tests_shape() {
    let (_guard, port, _dir) = spawn_server(
        r#"
            events {}
            http {
                server {
                    listen 127.0.0.1:%%PORT%%;
                    location / { return 200; }
                }
            }
        "#,
    );

    let trace = request(
        port,
        b"TRACE / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_line(&trace), "HTTP/1.1 405 Not Allowed");

    let connect = request(
        port,
        b"CONNECT localhost:8080 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_line(&connect), "HTTP/1.1 405 Not Allowed");

    let connect_uri = request(
        port,
        b"CONNECT / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_line(&connect_uri), "HTTP/1.1 400 Bad Request");

    let connect_no_port = request(
        port,
        b"CONNECT localhost HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_line(&connect_no_port), "HTTP/1.1 400 Bad Request");
}

#[test]
fn m7_return_host_uses_validated_host_and_absolute_form() {
    let (_guard, port, _dir) = spawn_server(
        r#"
            events {}
            http {
                server {
                    listen 127.0.0.1:%%PORT%%;
                    location / { return 200 $host; }
                }
            }
        "#,
    );

    let header_host = request(
        port,
        b"GET / HTTP/1.0\r\nHost: AbC-d93.0.34ZhGt-s.nk.Ru:88\r\n\r\n",
    );
    assert_eq!(status_line(&header_host), "HTTP/1.1 200 OK");
    assert_eq!(body(&header_host), b"abc-d93.0.34zhgt-s.nk.ru");

    let absolute = request(
        port,
        b"GET http://abcd-ef.g02.xyz:/ HTTP/1.0\r\nHost: localhost\r\n\r\n",
    );
    assert_eq!(status_line(&absolute), "HTTP/1.1 200 OK");
    assert_eq!(body(&absolute), b"abcd-ef.g02.xyz");

    let invalid = request(port, b"GET / HTTP/1.0\r\nHost: .\r\n\r\n");
    assert_eq!(status_line(&invalid), "HTTP/1.1 400 Bad Request");

    let invalid_absolute = request(
        port,
        b"GET http://123.40.56.78:9000:80/ HTTP/1.0\r\nHost: localhost\r\n\r\n",
    );
    assert_eq!(status_line(&invalid_absolute), "HTTP/1.1 400 Bad Request");
}

fn header_value<'a>(resp: &'a [u8], name: &str) -> Option<&'a [u8]> {
    let end = resp.windows(4).position(|w| w == b"\r\n\r\n")?;
    let mut i = 0;
    let headers = &resp[..end];
    while i < headers.len() {
        let line_end = headers[i..]
            .windows(2)
            .position(|w| w == b"\r\n")
            .map(|p| i + p)
            .unwrap_or(headers.len());
        let line = &headers[i..line_end];
        if let Some(colon) = line.iter().position(|&b| b == b':') {
            let (n, v) = line.split_at(colon);
            if n.eq_ignore_ascii_case(name.as_bytes()) {
                let mut v = &v[1..];
                while let Some((&b, rest)) = v.split_first() {
                    if b != b' ' && b != b'\t' {
                        break;
                    }
                    v = rest;
                }
                return Some(v);
            }
        }
        i = line_end + 2;
    }
    None
}

#[test]
fn add_header_emits_static_and_variable_values() {
    // Covers the nginx-tests shape: `add_header X-URI $uri;` on a location,
    // fetched via `GET /some/path`, and asserted in the response headers.
    let (_guard, port, _dir) = spawn_server(
        r#"
            events {}
            http {
                server {
                    listen 127.0.0.1:%%PORT%%;
                    server_name localhost;
                    add_header X-Scheme $scheme;
                    location / {
                        add_header X-URI "x $uri x";
                        add_header X-Status-Code $status;
                        return 204;
                    }
                    location /inherit {
                        return 200 "ok";
                    }
                }
            }
        "#,
    );

    // Location with its own add_header — server-level list is replaced.
    let r = request(
        port,
        b"GET /hello HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_line(&r), "HTTP/1.1 204 No Content");
    assert_eq!(header_value(&r, "X-URI"), Some(&b"x /hello x"[..]));
    assert_eq!(header_value(&r, "X-Status-Code"), Some(&b"204"[..]));
    // Server-level X-Scheme is NOT inherited because location has its own list.
    assert_eq!(header_value(&r, "X-Scheme"), None);

    // Location without add_header — inherits the server list.
    let r = request(
        port,
        b"GET /inherit HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_line(&r), "HTTP/1.1 200 OK");
    assert_eq!(header_value(&r, "X-Scheme"), Some(&b"http"[..]));
}

#[test]
fn add_header_skips_error_responses_without_always() {
    // `add_header` without `always` should not fire on 4xx/5xx (matches
    // nginx's headers-filter default). `always` unlocks it.
    let (_guard, port, _dir) = spawn_server(
        r#"
            events {}
            http {
                server {
                    listen 127.0.0.1:%%PORT%%;
                    location /plain {
                        add_header X-Plain "no-always";
                        return 500 "oops";
                    }
                    location /always {
                        add_header X-Always "always-on" always;
                        return 500 "oops";
                    }
                }
            }
        "#,
    );

    let r = request(
        port,
        b"GET /plain HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_line(&r), "HTTP/1.1 500 Internal Server Error");
    assert_eq!(header_value(&r, "X-Plain"), None);

    let r = request(
        port,
        b"GET /always HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_line(&r), "HTTP/1.1 500 Internal Server Error");
    assert_eq!(header_value(&r, "X-Always"), Some(&b"always-on"[..]));
}

#[test]
fn return_body_expands_variables() {
    let (_guard, port, _dir) = spawn_server(
        r#"
            events {}
            http {
                server {
                    listen 127.0.0.1:%%PORT%%;
                    location / { return 200 "uri=$uri host=$host"; }
                }
            }
        "#,
    );
    let r = request(
        port,
        b"GET /p/q HTTP/1.1\r\nHost: Example.COM\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_line(&r), "HTTP/1.1 200 OK");
    assert_eq!(body(&r), b"uri=/p/q host=example.com");
}

// #778: empty lines before a request line are skipped, as nginx does.
#[test]
fn empty_lines_before_a_request_line_are_skipped() {
    let (_guard, port, _dir) = spawn_server(
        r#"
            events {}
            http {
                server {
                    listen 127.0.0.1:%%PORT%%;
                    location / { return 200 "ok\n"; }
                }
            }
        "#,
    );
    let ok = |r: &[u8]| r.windows(15).filter(|w| *w == b"HTTP/1.1 200 OK").count();
    // A CRLF after a body, then the next request.
    let r = request(
        port,
        b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello\r\n\
          GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(ok(&r), 2, "{}", String::from_utf8_lossy(&r));
    let r = request(
        port,
        b"\r\n\n\r\nGET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_line(&r), "HTTP/1.1 200 OK");
    // The empty lines in reads of their own.
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    for part in [&b"\r\n"[..], b"\r", b"\nGET / HTTP/1.1\r\nHost: x\r\n"] {
        s.write_all(part).unwrap();
        sleep(Duration::from_millis(50));
    }
    s.write_all(b"Connection: close\r\n\r\n").unwrap();
    let mut r = Vec::new();
    let _ = s.read_to_end(&mut r);
    assert_eq!(status_line(&r), "HTTP/1.1 200 OK");
}

// #784: an HTTP/0.9 request line is refused at once, not left waiting
// for headers until client_header_timeout.
#[test]
fn http_09_request_line_is_refused_at_once() {
    let (_guard, port, _dir) = spawn_server(
        r#"
            events {}
            http {
                server {
                    listen 127.0.0.1:%%PORT%%;
                    location / { return 200 "ok\n"; }
                }
            }
        "#,
    );
    for line in [&b"GET /\r\n"[..], b"GET /a\n", b"HEAD /\r\n"] {
        let r = request(port, line);
        assert_eq!(status_line(&r), "HTTP/1.1 400 Bad Request", "{line:?}");
    }
}

// #781: HTTP/1.1 needs `Host` whatever the target's form; HTTP/1.0 doesn't.
#[test]
fn absolute_form_without_host_is_a_400_on_http_11() {
    let (_guard, port, _dir) = spawn_server(
        r#"
            events {}
            http {
                server {
                    listen 127.0.0.1:%%PORT%%;
                    location / { return 200 "ok\n"; }
                }
            }
        "#,
    );
    for (req, status) in [
        (
            &b"GET http://localhost/ HTTP/1.1\r\n\r\n"[..],
            "400 Bad Request",
        ),
        (
            b"GET https://localhost/ HTTP/1.1\r\n\r\n",
            "400 Bad Request",
        ),
        (b"GET http://localhost/ HTTP/1.0\r\n\r\n", "200 OK"),
        (
            b"GET http://localhost/ HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
            "200 OK",
        ),
    ] {
        let r = request(port, req);
        assert_eq!(status_line(&r), format!("HTTP/1.1 {status}"), "{req:?}");
    }
}
