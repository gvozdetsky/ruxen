//! M41 — proxy_set_header, request body forwarding, proxy_*_timeout,
//! and the standard `$proxy_host` / `$proxy_add_x_forwarded_for` recipe.
//!
//! Spawns a tiny in-process backend that captures the request bytes it
//! received, then asserts the exact request line + headers ruxen sent
//! over the upstream socket.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, MutexGuard};
use std::thread;
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

static SETUP_LOCK: Mutex<()> = Mutex::new(());

fn pick_port() -> (u16, MutexGuard<'static, ()>) {
    let guard = SETUP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    (port, guard)
}

fn unique_dir() -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "ruxen-m41-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir(&dir).unwrap();
    dir
}

fn wait_for_listen(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        if Instant::now() > deadline {
            panic!("server did not start listening on port {port}");
        }
        sleep(Duration::from_millis(20));
    }
}

fn spawn_ruxen(conf_body: &str) -> (ServerGuard, u16) {
    let (port, _lock) = pick_port();
    let dir = unique_dir();
    let conf_path = dir.join("ruxen.conf");
    std::fs::write(&conf_path, conf_body.replace("%%PORT%%", &port.to_string())).unwrap();

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

/// Backend that reads exactly one request including a Content-Length body
/// and stores the raw request bytes for later inspection. Returns a
/// canned response so the proxy completes its read loop.
struct Backend {
    addr: SocketAddr,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    seen: std::sync::Arc<Mutex<Option<Vec<u8>>>>,
}

impl Backend {
    fn spawn(response: Vec<u8>) -> Self {
        // Bind under SETUP_LOCK so a parallel test can't grab this port in the
        // window between its pick_port() drop and its ruxen's bind.
        let listener = {
            let _g = SETUP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            TcpListener::bind("127.0.0.1:0").unwrap()
        };
        let addr = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let seen = std::sync::Arc::new(Mutex::new(None));
        let stop_clone = stop.clone();
        let seen_clone = seen.clone();
        thread::spawn(move || {
            loop {
                if stop_clone.load(std::sync::atomic::Ordering::SeqCst) {
                    return;
                }
                let (mut s, _) = match listener.accept() {
                    Ok(v) => v,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(_) => return,
                };
                s.set_read_timeout(Some(Duration::from_secs(2))).ok();
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                // Read until we have the headers, then read body if CL given.
                let mut head_end: Option<usize> = None;
                loop {
                    match s.read(&mut tmp) {
                        Ok(0) => break,
                        Ok(n) => {
                            buf.extend_from_slice(&tmp[..n]);
                            if head_end.is_none() {
                                if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                                    head_end = Some(p + 4);
                                }
                            }
                            if let Some(he) = head_end {
                                // Look up Content-Length in headers.
                                let head = &buf[..he];
                                let mut cl: usize = 0;
                                for line in std::str::from_utf8(head).unwrap_or("").lines() {
                                    if let Some(rest) = line
                                        .strip_prefix("Content-Length:")
                                        .or_else(|| line.strip_prefix("content-length:"))
                                    {
                                        if let Ok(n) = rest.trim().parse::<usize>() {
                                            cl = n;
                                        }
                                    }
                                }
                                if buf.len() >= he + cl {
                                    break;
                                }
                            }
                        }
                        Err(_) => break,
                    }
                }
                *seen_clone.lock().unwrap() = Some(buf.clone());
                let _ = s.write_all(&response);
            }
        });
        Backend { addr, stop, seen }
    }

    fn last_request(&self) -> Option<Vec<u8>> {
        self.seen.lock().unwrap().clone()
    }
}

impl Drop for Backend {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

fn http_send(port: u16, request: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream.write_all(request).unwrap();
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(_) => break,
        }
    }
    out
}

fn header_value<'a>(req: &'a [u8], name: &str) -> Option<&'a str> {
    let head_end = req.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = std::str::from_utf8(&req[..head_end]).ok()?;
    for line in head.lines().skip(1) {
        if let Some((k, v)) = line.split_once(':') {
            if k.eq_ignore_ascii_case(name) {
                return Some(v.trim());
            }
        }
    }
    None
}

fn body_after_headers(req: &[u8]) -> &[u8] {
    req.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| &req[i + 4..])
        .unwrap_or(&[])
}

#[test]
fn m41_proxy_set_header_overrides_host_and_adds_xff() {
    let backend = Backend::spawn(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec());
    let conf = format!(
        r#"
http {{
    server {{
        listen %%PORT%%;
        location / {{
            proxy_pass http://127.0.0.1:{};
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }}
    }}
}}
"#,
        backend.addr.port()
    );
    let (_guard, port) = spawn_ruxen(&conf);
    let resp = http_send(
        port,
        b"GET /hi HTTP/1.1\r\nHost: client.example\r\nConnection: close\r\n\r\n",
    );
    assert!(resp.starts_with(b"HTTP/1.1 200"));
    let req = backend.last_request().expect("backend saw request");
    assert!(
        std::str::from_utf8(&req)
            .unwrap()
            .starts_with("GET /hi HTTP/1.0\r\n"),
        "request line: {}",
        String::from_utf8_lossy(&req[..req.len().min(80)])
    );
    assert_eq!(header_value(&req, "Host"), Some("client.example"));
    assert_eq!(header_value(&req, "X-Real-IP"), Some("127.0.0.1"));
    // No incoming XFF, so it's just $remote_addr.
    assert_eq!(header_value(&req, "X-Forwarded-For"), Some("127.0.0.1"));
}

#[test]
fn m41_x_forwarded_for_appends_to_existing() {
    let backend = Backend::spawn(b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec());
    let conf = format!(
        r#"
http {{
    server {{
        listen %%PORT%%;
        location / {{
            proxy_pass http://127.0.0.1:{};
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }}
    }}
}}
"#,
        backend.addr.port()
    );
    let (_guard, port) = spawn_ruxen(&conf);
    let _ = http_send(
        port,
        b"GET / HTTP/1.1\r\nHost: c\r\nX-Forwarded-For: 10.1.1.1\r\nConnection: close\r\n\r\n",
    );
    let req = backend.last_request().unwrap();
    assert_eq!(
        header_value(&req, "X-Forwarded-For"),
        Some("10.1.1.1, 127.0.0.1")
    );
}

#[test]
fn m41_proxy_pass_request_body_forwards_content_length_body() {
    let backend = Backend::spawn(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec());
    let conf = format!(
        r#"
http {{
    server {{
        listen %%PORT%%;
        location / {{
            proxy_pass http://127.0.0.1:{};
        }}
    }}
}}
"#,
        backend.addr.port()
    );
    let (_guard, port) = spawn_ruxen(&conf);
    let body = "hello body";
    let req = format!(
        "POST /thing HTTP/1.1\r\nHost: c\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let resp = http_send(port, req.as_bytes());
    assert!(resp.starts_with(b"HTTP/1.1 200"));
    let captured = backend.last_request().unwrap();
    assert_eq!(header_value(&captured, "Content-Length"), Some("10"));
    assert_eq!(body_after_headers(&captured), body.as_bytes());
}

#[test]
fn m41_proxy_pass_request_body_off_drops_body() {
    let backend = Backend::spawn(b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec());
    let conf = format!(
        r#"
http {{
    server {{
        listen %%PORT%%;
        location / {{
            proxy_pass http://127.0.0.1:{};
            proxy_pass_request_body off;
        }}
    }}
}}
"#,
        backend.addr.port()
    );
    let (_guard, port) = spawn_ruxen(&conf);
    let req = b"POST / HTTP/1.1\r\nHost: c\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello";
    let _ = http_send(port, req);
    let captured = backend.last_request().unwrap();
    assert_eq!(header_value(&captured, "Content-Length"), Some("0"));
    assert!(body_after_headers(&captured).is_empty());
}

#[test]
fn m41_proxy_pass_request_headers_off_strips_client_headers() {
    let backend = Backend::spawn(b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec());
    let conf = format!(
        r#"
http {{
    server {{
        listen %%PORT%%;
        location / {{
            proxy_pass http://127.0.0.1:{};
            proxy_pass_request_headers off;
        }}
    }}
}}
"#,
        backend.addr.port()
    );
    let (_guard, port) = spawn_ruxen(&conf);
    let _ = http_send(
        port,
        b"GET / HTTP/1.1\r\nHost: c\r\nX-App: yes\r\nConnection: close\r\n\r\n",
    );
    let captured = backend.last_request().unwrap();
    assert!(
        header_value(&captured, "X-App").is_none(),
        "X-App must be stripped when proxy_pass_request_headers off; head:\n{}",
        String::from_utf8_lossy(&captured)
    );
    // Host still synthesized to upstream authority.
    assert!(header_value(&captured, "Host").is_some());
}

#[test]
fn m41_proxy_connect_timeout_triggers_504() {
    // 192.0.2.0/24 is TEST-NET-1 (RFC 5737). Every connect attempt to
    // an address in that block silently drops on Linux; the kernel does
    // not return RST. So `connect(2)` blocks until the SYN times out,
    // which our `proxy_connect_timeout 1ms;` should preempt with 504.
    let conf = r#"
http {
    server {
        listen %%PORT%%;
        location / {
            proxy_pass http://192.0.2.1:80;
            proxy_connect_timeout 100ms;
        }
    }
}
"#;
    let (_guard, port) = spawn_ruxen(conf);
    let resp = http_send(
        port,
        b"GET / HTTP/1.1\r\nHost: c\r\nConnection: close\r\n\r\n",
    );
    let s = std::str::from_utf8(&resp).unwrap_or("");
    assert!(
        s.starts_with("HTTP/1.1 504"),
        "expected 504 Gateway Timeout, got: {}",
        &s[..s.len().min(120)]
    );
}

#[test]
fn m41_proxy_set_header_empty_value_drops_header() {
    let backend = Backend::spawn(b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec());
    let conf = format!(
        r#"
http {{
    server {{
        listen %%PORT%%;
        location / {{
            proxy_pass http://127.0.0.1:{};
            proxy_set_header Accept "";
        }}
    }}
}}
"#,
        backend.addr.port()
    );
    let (_guard, port) = spawn_ruxen(&conf);
    let _ = http_send(
        port,
        b"GET / HTTP/1.1\r\nHost: c\r\nAccept: text/plain\r\nConnection: close\r\n\r\n",
    );
    let captured = backend.last_request().unwrap();
    assert!(
        header_value(&captured, "Accept").is_none(),
        "Accept should have been suppressed by proxy_set_header Accept \"\"; got:\n{}",
        String::from_utf8_lossy(&captured)
    );
}
