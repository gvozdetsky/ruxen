//! M44 — proxy_method: the upstream request method override, its
//! inheritance, and its duplicate check.
//!
//! Spawns a tiny in-process backend that captures the request bytes it
//! received and replies with a canned response.

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
        "ruxen-m44-{}-{}",
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

fn write_conf(conf_body: &str, port: u16) -> (PathBuf, PathBuf) {
    let dir = unique_dir();
    let conf_path = dir.join("ruxen.conf");
    std::fs::write(&conf_path, conf_body.replace("%%PORT%%", &port.to_string())).unwrap();
    (dir, conf_path)
}

fn spawn_ruxen(conf_body: &str) -> (ServerGuard, u16) {
    let (port, _lock) = pick_port();
    let (dir, conf_path) = write_conf(conf_body, port);
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

/// Config-check only: `ruxen -t`, returning whether it was accepted.
fn config_test_passes(conf_body: &str) -> bool {
    let (dir, conf_path) = write_conf(conf_body, 1);
    let status = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .args(["-t", "-c", conf_path.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("run ruxen -t");
    let _ = std::fs::remove_dir_all(dir);
    status.success()
}

/// Backend that reads one request (headers plus any Content-Length body),
/// records it, and writes `response` back.
struct Backend {
    addr: SocketAddr,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    seen: std::sync::Arc<Mutex<Option<Vec<u8>>>>,
}

impl Backend {
    fn spawn(response: Vec<u8>) -> Self {
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
                let mut head_end: Option<usize> = None;
                loop {
                    match s.read(&mut tmp) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            buf.extend_from_slice(&tmp[..n]);
                            if head_end.is_none() {
                                if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                                    head_end = Some(p + 4);
                                }
                            }
                            if let Some(he) = head_end {
                                let cl = std::str::from_utf8(&buf[..he])
                                    .unwrap_or("")
                                    .lines()
                                    .find_map(|l| {
                                        let (k, v) = l.split_once(':')?;
                                        k.eq_ignore_ascii_case("content-length")
                                            .then(|| v.trim().parse::<usize>().ok())
                                            .flatten()
                                    })
                                    .unwrap_or(0);
                                if buf.len() >= he + cl {
                                    break;
                                }
                            }
                        }
                    }
                }
                *seen_clone.lock().unwrap() = Some(buf);
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

/// Send one request and read until the server closes.
fn http_send(port: u16, request: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(request).unwrap();
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
        }
    }
    out
}

fn request_line(req: &[u8]) -> &str {
    let end = req
        .windows(2)
        .position(|w| w == b"\r\n")
        .unwrap_or(req.len());
    std::str::from_utf8(&req[..end]).unwrap_or("")
}

fn status_code(resp: &[u8]) -> u16 {
    std::str::from_utf8(resp.get(9..12).unwrap_or(b""))
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

#[test]
fn m44_proxy_method_overrides_request_line() {
    let backend = Backend::spawn(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec());
    let conf = format!(
        r#"
http {{
    server {{
        listen %%PORT%%;
        location / {{
            proxy_pass http://127.0.0.1:{};
            proxy_method POST;
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
    assert_eq!(status_code(&resp), 200);
    let req = backend.last_request().expect("backend saw request");
    assert_eq!(request_line(&req), "POST /hi HTTP/1.0");
}

#[test]
fn m44_proxy_method_accepts_variables() {
    let backend = Backend::spawn(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec());
    let conf = format!(
        r#"
http {{
    server {{
        listen %%PORT%%;
        location / {{
            proxy_pass http://127.0.0.1:{};
            proxy_method $request_method;
        }}
    }}
}}
"#,
        backend.addr.port()
    );
    let (_guard, port) = spawn_ruxen(&conf);
    let resp = http_send(
        port,
        b"PUT /v HTTP/1.1\r\nHost: client.example\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_code(&resp), 200);
    let req = backend.last_request().expect("backend saw request");
    assert_eq!(request_line(&req), "PUT /v HTTP/1.0");
}

#[test]
fn m44_proxy_method_inherits_and_location_overrides() {
    let backend = Backend::spawn(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec());
    let conf = format!(
        r#"
http {{
    proxy_method PUT;
    server {{
        listen %%PORT%%;
        location /inherit {{
            proxy_pass http://127.0.0.1:{};
        }}
        location /own {{
            proxy_pass http://127.0.0.1:{};
            proxy_method DELETE;
        }}
    }}
}}
"#,
        backend.addr.port(),
        backend.addr.port()
    );
    let (_guard, port) = spawn_ruxen(&conf);
    let resp = http_send(
        port,
        b"GET /inherit HTTP/1.1\r\nHost: c\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_code(&resp), 200);
    let req = backend.last_request().expect("request seen");
    assert_eq!(request_line(&req), "PUT /inherit HTTP/1.0");

    let resp = http_send(
        port,
        b"GET /own HTTP/1.1\r\nHost: c\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_code(&resp), 200);
    let req = backend.last_request().expect("request seen");
    assert_eq!(request_line(&req), "DELETE /own HTTP/1.0");
}

#[test]
fn m44_duplicate_proxy_method_is_a_config_error() {
    let conf = r#"
http {
    server {
        listen 8080;
        location / {
            proxy_pass http://127.0.0.1:9;
            proxy_method POST;
            proxy_method PUT;
        }
    }
}
"#;
    assert!(!config_test_passes(conf));
}
