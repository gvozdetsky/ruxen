//! M40 — Minimum-viable reverse proxy.
//!
//! Spawns a tiny in-process HTTP/1.0 backend, points ruxen at it via
//! `proxy_pass`, and asserts wire-level forwarding behavior. Two config
//! shapes are exercised in parallel: literal `proxy_pass http://127.0.0.1:N`
//! and `proxy_pass http://upstream_name` with a declared `upstream {}` block.

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
        "ruxen-m40-{}-{}",
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

fn spawn_ruxen(conf_body: &str) -> (ServerGuard, u16, PathBuf) {
    let (port, _lock) = pick_port();
    let dir = unique_dir();
    let conf_path = dir.join("ruxen.conf");
    std::fs::write(
        &conf_path,
        conf_body
            .replace("%%PORT%%", &port.to_string())
            .replace("%%DIR%%", dir.to_str().unwrap()),
    )
    .unwrap();

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
            tempdir: dir.clone(),
        },
        port,
        dir,
    )
}

/// Tiny one-shot HTTP/1.0 backend. Serves a single request per connection,
/// echoing what the proxy sent so the test can assert request-line forwarding.
/// Returns `(SocketAddr, JoinHandle)` — the JoinHandle's thread keeps
/// accepting connections until the test drops the receiver pair.
struct Backend {
    addr: SocketAddr,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Captured first-line + Host header of the most recent request seen.
    seen: std::sync::Arc<Mutex<Option<(String, Option<String>)>>>,
}

impl Backend {
    fn spawn(response: Vec<u8>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(false).unwrap();
        let addr = listener.local_addr().unwrap();
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let seen = std::sync::Arc::new(Mutex::new(None));
        let stop_clone = stop.clone();
        let seen_clone = seen.clone();
        thread::spawn(move || {
            listener.set_nonblocking(true).unwrap();
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
                loop {
                    match s.read(&mut tmp) {
                        Ok(0) => break,
                        Ok(n) => {
                            buf.extend_from_slice(&tmp[..n]);
                            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                let text = String::from_utf8_lossy(&buf).to_string();
                let first_line = text.lines().next().unwrap_or("").to_string();
                let host = text
                    .lines()
                    .skip(1)
                    .find_map(|l| {
                        l.split_once(':').and_then(|(k, v)| {
                            if k.eq_ignore_ascii_case("Host") {
                                Some(v.trim().to_string())
                            } else {
                                None
                            }
                        })
                    });
                *seen_clone.lock().unwrap() = Some((first_line, host));
                let _ = s.write_all(&response);
                // No shutdown — closing the stream by drop is enough; the
                // upstream side sent Connection: close so the proxy reads
                // until EOF.
            }
        });
        Backend { addr, stop, seen }
    }

    fn last_request(&self) -> Option<(String, Option<String>)> {
        self.seen.lock().unwrap().clone()
    }
}

impl Drop for Backend {
    fn drop(&mut self) {
        self.stop
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

fn http_get_close(port: u16, path: &str) -> Vec<u8> {
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    );
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    stream.write_all(req.as_bytes()).unwrap();
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

fn status_code(resp: &[u8]) -> u16 {
    if resp.len() < 12 {
        return 0;
    }
    let d = &resp[9..12];
    if !d.iter().all(|b| b.is_ascii_digit()) {
        return 0;
    }
    ((d[0] - b'0') as u16) * 100 + ((d[1] - b'0') as u16) * 10 + (d[2] - b'0') as u16
}

fn body(resp: &[u8]) -> &[u8] {
    resp.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| &resp[i + 4..])
        .unwrap_or(&[])
}

fn has_header(resp: &[u8], name: &str) -> bool {
    let head_end = resp.windows(4).position(|w| w == b"\r\n\r\n");
    let head = match head_end {
        Some(p) => &resp[..p],
        None => return false,
    };
    std::str::from_utf8(head)
        .ok()
        .map(|s| {
            s.split("\r\n").skip(1).any(|l| {
                l.split_once(':')
                    .map(|(k, _)| k.eq_ignore_ascii_case(name))
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false)
}

#[test]
fn m40_proxy_pass_direct_forwards_get() {
    let backend = Backend::spawn(
        b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello"
            .to_vec(),
    );
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
    let (_guard, port, _dir) = spawn_ruxen(&conf);

    let resp = http_get_close(port, "/some/path?a=1");
    assert_eq!(status_code(&resp), 200, "response: {}", String::from_utf8_lossy(&resp));
    assert_eq!(body(&resp), b"hello");

    // Backend saw the forwarded request.
    let (line, host) = backend
        .last_request()
        .expect("backend should have received the proxied request");
    assert!(line.starts_with("GET /some/path?a=1 "), "first line: {line}");
    // M40 sends the upstream URL's authority as the Host header — for a
    // literal `proxy_pass http://127.0.0.1:N`, that's `127.0.0.1:N`, not
    // the client's `localhost`.
    let host = host.expect("backend should have seen a Host header");
    assert!(host.starts_with("127.0.0.1:"), "Host: {host}");
}

#[test]
fn m40_proxy_pass_upstream_block_forwards() {
    let backend = Backend::spawn(
        b"HTTP/1.0 201 Created\r\nContent-Length: 6\r\n\r\nworld!"
            .to_vec(),
    );
    let conf = format!(
        r#"
http {{
    upstream backend_pool {{
        server 127.0.0.1:{};
    }}
    server {{
        listen %%PORT%%;
        location / {{
            proxy_pass http://backend_pool;
        }}
    }}
}}
"#,
        backend.addr.port()
    );
    let (_guard, port, _dir) = spawn_ruxen(&conf);

    let resp = http_get_close(port, "/up");
    assert_eq!(status_code(&resp), 201, "response: {}", String::from_utf8_lossy(&resp));
    assert_eq!(body(&resp), b"world!");

    let (line, host) = backend.last_request().unwrap();
    assert!(line.starts_with("GET /up "), "first line: {line}");
    // Upstream-ref Host header defaults to the upstream block name in
    // M40 — nginx's `$proxy_host` is the URL authority, which for an
    // upstream-ref is the bare name.
    assert_eq!(host.as_deref(), Some("backend_pool"));
}

#[test]
fn m40_strips_hop_by_hop_headers_from_upstream() {
    // Upstream returns Connection, Keep-Alive, Transfer-Encoding (illegal
    // here since there's no chunked body, but we just want to assert it
    // gets stripped). Plus a regular header that should pass through.
    let backend = Backend::spawn(
        b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\nKeep-Alive: timeout=5\r\nUpgrade: x\r\nX-App: yes\r\n\r\nok"
            .to_vec(),
    );
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
    let (_guard, port, _dir) = spawn_ruxen(&conf);

    let resp = http_get_close(port, "/");
    assert_eq!(status_code(&resp), 200);
    assert!(has_header(&resp, "X-App"));
    // Connection is RE-injected by the worker hot path; the upstream's
    // value would be "keep-alive" but the client used Connection: close,
    // so the worker should land on `Connection: close`.
    let head_end = resp.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head_str = std::str::from_utf8(&resp[..head_end]).unwrap();
    let connection_lines: Vec<&str> = head_str
        .split("\r\n")
        .filter(|l| {
            l.split_once(':')
                .map(|(k, _)| k.eq_ignore_ascii_case("Connection"))
                .unwrap_or(false)
        })
        .collect();
    assert_eq!(connection_lines.len(), 1, "exactly one Connection header in {head_str}");
    assert!(
        !has_header(&resp, "Keep-Alive"),
        "Keep-Alive must be stripped; full head:\n{head_str}"
    );
    assert!(
        !has_header(&resp, "Upgrade"),
        "Upgrade must be stripped; full head:\n{head_str}"
    );
}

#[test]
fn m40_502_when_upstream_unreachable() {
    // No backend bound here — pick an ephemeral port then close it before
    // ruxen even starts. The address will refuse connections.
    let probe = TcpListener::bind("127.0.0.1:0").unwrap();
    let dead = probe.local_addr().unwrap();
    drop(probe);

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
        dead.port()
    );
    let (_guard, port, _dir) = spawn_ruxen(&conf);
    let resp = http_get_close(port, "/x");
    assert_eq!(
        status_code(&resp),
        502,
        "expected 502 Bad Gateway; got: {}",
        String::from_utf8_lossy(&resp)
    );
}

#[test]
fn m40_unknown_upstream_name_fails_config_validation() {
    // proxy_pass http://nope; references no upstream block — should fail
    // -t. We check `-t` exit code rather than spawning the server (which
    // would panic at prepare).
    let conf = r#"
http {
    server {
        listen 65535;
        location / {
            proxy_pass http://nope;
        }
    }
}
"#;
    let dir = unique_dir();
    let conf_path = dir.join("ruxen.conf");
    std::fs::write(&conf_path, conf).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .args(["-t", "-c", conf_path.to_str().unwrap()])
        .output()
        .expect("run ruxen -t");
    assert!(!out.status.success(), "ruxen -t should reject unknown upstream");
    let _ = std::fs::remove_dir_all(&dir);
}
