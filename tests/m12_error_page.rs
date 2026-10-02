use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, MutexGuard};
use std::thread::sleep;
use std::time::{Duration, Instant};

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

// See the SETUP_LOCK comment in tests/file_serving.rs for why port picking
// has to be serialized against the spawn + readiness-check of the previous
// setup.
static SETUP_LOCK: Mutex<()> = Mutex::new(());

fn pick_port() -> (u16, MutexGuard<'static, ()>) {
    let g = SETUP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let p = l.local_addr().unwrap().port();
    drop(l);
    (p, g)
}

fn unique_dir() -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let d = std::env::temp_dir().join(format!(
        "ruxen-m12-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir(&d).unwrap();
    d
}

fn wait_for_listen(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        if Instant::now() > deadline {
            panic!("ruxen did not start listening on port {port}");
        }
        sleep(Duration::from_millis(20));
    }
}

fn spawn_server(conf: &str) -> (ServerGuard, u16) {
    let (port, _lock) = pick_port();
    let dir = unique_dir();
    let conf_path = dir.join("nginx.conf");
    std::fs::write(&conf_path, conf.replace("%%PORT%%", &port.to_string())).unwrap();

    let child = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .args(["-c", conf_path.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ruxen");

    wait_for_listen(port);
    (
        ServerGuard {
            child,
            tempdir: dir,
        },
        port,
    )
}

fn http_get(port: u16, path: &str) -> Vec<u8> {
    let req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    s.write_all(req.as_bytes()).unwrap();
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

fn header_value<'a>(resp: &'a [u8], name: &str) -> Option<&'a str> {
    let s = std::str::from_utf8(resp).ok()?;
    let header_end = s.find("\r\n\r\n").unwrap_or(s.len());
    for line in s[..header_end].split("\r\n").skip(1) {
        if let Some((k, v)) = line.split_once(':') {
            if k.eq_ignore_ascii_case(name) {
                return Some(v.trim());
            }
        }
    }
    None
}

fn body(resp: &[u8]) -> &[u8] {
    resp.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| &resp[i + 4..])
        .unwrap_or(&[])
}

const M12_CONF: &str = r#"
daemon off;

events { }

http {
    server {
        listen       127.0.0.1:%%PORT%%;
        server_name  localhost;

        error_page 404 /server-ok;

        location /server-hit {
            add_header X-Source original always;
            return 404;
        }

        location /server-ok {
            add_header X-Status $status always;
            return 200 "server-body";
        }

        location /preserve {
            error_page 404 /body200;
            return 404 "first";
        }

        location /override {
            error_page 404 =200 /body200;
            return 404 "first";
        }

        location /body200 {
            add_header X-Status $status always;
            return 200 "replacement";
        }

        location /redir {
            error_page 405 /return302;
            return 405 "first";
        }

        location /return302 {
            return 302 "http://example.com/";
        }

        location /varredir {
            error_page 302 /return302args?$arg_a;
            return 302 "first";
        }

        location /return302args {
            return 302 "http://example.com/$args";
        }
    }
}
"#;

#[test]
fn m12_return_redirect_form_uses_location_header() {
    let (_g, port) = spawn_server(M12_CONF);

    let resp = http_get(port, "/return302");
    assert_eq!(status_line(&resp), "HTTP/1.1 302 Found");
    assert_eq!(header_value(&resp, "Location"), Some("http://example.com/"));
}

#[test]
fn m12_error_page_preserves_or_overrides_status_for_success_targets() {
    let (_g, port) = spawn_server(M12_CONF);

    let preserve = http_get(port, "/preserve");
    assert_eq!(status_line(&preserve), "HTTP/1.1 404 Not Found");
    assert_eq!(header_value(&preserve, "X-Status"), Some("404"));
    assert_eq!(body(&preserve), b"replacement");

    let override_200 = http_get(port, "/override");
    assert_eq!(status_line(&override_200), "HTTP/1.1 200 OK");
    assert_eq!(header_value(&override_200, "X-Status"), Some("200"));
    assert_eq!(body(&override_200), b"replacement");
}

#[test]
fn m12_server_error_page_inherits_and_original_headers_do_not_leak() {
    let (_g, port) = spawn_server(M12_CONF);

    let resp = http_get(port, "/server-hit");
    assert_eq!(status_line(&resp), "HTTP/1.1 404 Not Found");
    assert_eq!(header_value(&resp, "X-Status"), Some("404"));
    assert_eq!(header_value(&resp, "X-Source"), None);
    assert_eq!(body(&resp), b"server-body");
}

#[test]
fn m12_error_page_redirect_targets_clear_old_location_and_update_args() {
    let (_g, port) = spawn_server(M12_CONF);

    let redirect = http_get(port, "/redir");
    assert_eq!(status_line(&redirect), "HTTP/1.1 302 Found");
    assert_eq!(
        header_value(&redirect, "Location"),
        Some("http://example.com/")
    );
    assert!(
        !std::str::from_utf8(&redirect)
            .unwrap()
            .contains("Location: first")
    );

    let var_redirect = http_get(port, "/varredir?a=2");
    assert_eq!(status_line(&var_redirect), "HTTP/1.1 302 Found");
    assert_eq!(
        header_value(&var_redirect, "Location"),
        Some("http://example.com/2")
    );
    assert!(
        !std::str::from_utf8(&var_redirect)
            .unwrap()
            .contains("Location: first")
    );
}

fn raw_exchange(port: u16, raw: &[u8]) -> Vec<u8> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    s.write_all(raw).unwrap();
    let mut out = Vec::new();
    // A timeout here means the connection was left open.
    s.read_to_end(&mut out)
        .expect("connection closed after the response");
    out
}

/// Requests refused before any location (invalid or missing Host,
/// Transfer-Encoding, TRACE) get the server's own `error_page`, as in
/// nginx: the default server's for an invalid Host, the Host's server
/// otherwise. They used to always get the built-in page.
#[test]
fn m12_server_error_page_applies_to_refused_requests() {
    let conf = r#"
events {}
http {
  server {
    listen 127.0.0.1:%%PORT%%;
    server_name dflt;
    error_page 400 /bad;
    location = /bad { return 200 "dflt bad"; }
  }
  server {
    listen 127.0.0.1:%%PORT%%;
    server_name other;
    error_page 400 /bad;
    error_page 501 =200 /te;
    error_page 405 /m;
    location = /bad { return 200 "other bad"; }
    location = /te { return 200 "other te"; }
    location = /m { return 200 "other method"; }
  }
}
"#;
    let (_guard, port) = spawn_server(conf);

    // Invalid Host: the default server, without waiting for the body.
    let r = raw_exchange(
        port,
        b"POST / HTTP/1.1\r\nHost: other/x\r\nContent-Length: 100\r\n\r\n",
    );
    assert_eq!(status_line(&r), "HTTP/1.1 400 Bad Request", "{r:?}");
    assert_eq!(body(&r), b"dflt bad");
    assert_eq!(header_value(&r, "connection"), Some("close"));

    // Missing Host on HTTP/1.1: also the default server.
    let r = raw_exchange(port, b"GET / HTTP/1.1\r\n\r\n");
    assert_eq!(status_line(&r), "HTTP/1.1 400 Bad Request");
    assert_eq!(body(&r), b"dflt bad");

    // Transfer-Encoding problems: the server chosen by Host.
    let r = raw_exchange(
        port,
        b"POST / HTTP/1.1\r\nHost: other\r\nTransfer-Encoding: gzip\r\n\r\n",
    );
    assert_eq!(status_line(&r), "HTTP/1.1 200 OK");
    assert_eq!(body(&r), b"other te");
    let r = raw_exchange(
        port,
        b"POST / HTTP/1.1\r\nHost: other\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n",
    );
    assert_eq!(status_line(&r), "HTTP/1.1 400 Bad Request");
    assert_eq!(body(&r), b"other bad");

    // TRACE: 405 with the Host's server page.
    let r = raw_exchange(port, b"TRACE / HTTP/1.1\r\nHost: other\r\n\r\n");
    assert_eq!(status_line(&r), "HTTP/1.1 405 Not Allowed");
    assert_eq!(body(&r), b"other method");
}
