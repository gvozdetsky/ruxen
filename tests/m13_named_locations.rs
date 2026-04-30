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
        "ruxen-m13-{}-{}",
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
    let conf = conf
        .replace("%%PORT%%", &port.to_string())
        .replace("%%TESTDIR%%", dir.to_str().unwrap());
    std::fs::write(&conf_path, conf).unwrap();

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

const M13_CONF: &str = r#"
daemon off;

events { }

http {
    server {
        listen       127.0.0.1:%%PORT%%;
        server_name  localhost;
        root         %%TESTDIR%%;

        location /try/ {
            try_files $uri @fallback;
        }

        location = /error {
            error_page 404 =200 @named_404;
            return 404 "first";
        }

        location = /error-preserve {
            error_page 404 @named_404;
            return 404 "first";
        }

        location @fallback {
            add_header X-URI $uri always;
            add_header X-Args $args always;
            return 200 "tf:$uri$is_args$args";
        }

        location @named_404 {
            add_header X-URI $uri always;
            add_header X-Args $args always;
            return 201 "ep:$uri$is_args$args";
        }
    }
}
"#;

#[test]
fn m13_try_files_named_fallback_preserves_uri_and_args() {
    let (_g, port) = spawn_server(M13_CONF);

    let resp = http_get(port, "/try/miss?a=1");
    assert_eq!(status_line(&resp), "HTTP/1.1 200 OK");
    assert_eq!(header_value(&resp, "X-URI"), Some("/try/miss"));
    assert_eq!(header_value(&resp, "X-Args"), Some("a=1"));
    assert_eq!(body(&resp), b"tf:/try/miss?a=1");
}

#[test]
fn m13_error_page_named_location_preserves_and_overrides_status() {
    let (_g, port) = spawn_server(M13_CONF);

    let override_200 = http_get(port, "/error?a=2");
    assert_eq!(status_line(&override_200), "HTTP/1.1 200 OK");
    assert_eq!(header_value(&override_200, "X-URI"), Some("/error"));
    assert_eq!(header_value(&override_200, "X-Args"), Some("a=2"));
    assert_eq!(body(&override_200), b"ep:/error?a=2");

    let preserve_404 = http_get(port, "/error-preserve?a=3");
    assert_eq!(status_line(&preserve_404), "HTTP/1.1 404 Not Found");
    assert_eq!(
        header_value(&preserve_404, "X-URI"),
        Some("/error-preserve")
    );
    assert_eq!(header_value(&preserve_404, "X-Args"), Some("a=3"));
    assert_eq!(body(&preserve_404), b"ep:/error-preserve?a=3");
}

#[test]
fn m13_named_locations_are_internal_only() {
    let (_g, port) = spawn_server(M13_CONF);

    let resp = http_get(port, "/@fallback?a=1");
    assert_eq!(status_line(&resp), "HTTP/1.1 404 Not Found");
}
