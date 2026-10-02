//! M40 — Minimum-viable reverse proxy.
//!
//! Spawns a tiny in-process HTTP/1.0 backend, points ruxen at it via
//! `proxy_pass`, and asserts wire-level forwarding behavior. Two config
//! shapes are exercised in parallel: literal `proxy_pass http://127.0.0.1:N`
//! and `proxy_pass http://upstream_name` with a declared `upstream {}` block.

mod common;

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
        // Bind under SETUP_LOCK so a parallel test can't grab this port in the
        // window between its pick_port() drop and its ruxen's bind.
        let listener = {
            let _g = SETUP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            TcpListener::bind("127.0.0.1:0").unwrap()
        };
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
                let host = text.lines().skip(1).find_map(|l| {
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
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

fn http_get_close(port: u16, path: &str) -> Vec<u8> {
    let req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
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
        b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello".to_vec(),
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
    assert_eq!(
        status_code(&resp),
        200,
        "response: {}",
        String::from_utf8_lossy(&resp)
    );
    assert_eq!(body(&resp), b"hello");

    // Backend saw the forwarded request.
    let (line, host) = backend
        .last_request()
        .expect("backend should have received the proxied request");
    assert!(
        line.starts_with("GET /some/path?a=1 "),
        "first line: {line}"
    );
    // M40 sends the upstream URL's authority as the Host header — for a
    // literal `proxy_pass http://127.0.0.1:N`, that's `127.0.0.1:N`, not
    // the client's `localhost`.
    let host = host.expect("backend should have seen a Host header");
    assert!(host.starts_with("127.0.0.1:"), "Host: {host}");
}

#[test]
fn m40_proxy_pass_upstream_block_forwards() {
    let backend =
        Backend::spawn(b"HTTP/1.0 201 Created\r\nContent-Length: 6\r\n\r\nworld!".to_vec());
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
    assert_eq!(
        status_code(&resp),
        201,
        "response: {}",
        String::from_utf8_lossy(&resp)
    );
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
    assert_eq!(
        connection_lines.len(),
        1,
        "exactly one Connection header in {head_str}"
    );
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
    let dead_port = common::ports::DeadPort::new();
    let dead = SocketAddr::from(([127, 0, 0, 1], dead_port.port()));

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
    assert!(
        !out.status.success(),
        "ruxen -t should reject unknown upstream"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A hostile or broken upstream response must cost one 502, not the
/// server: a chunk size near `u64::MAX` used to overflow and panic the
/// worker (taking the process down), and a huge `Content-Length` was
/// reserved up front and aborted the process on allocation.
#[test]
fn m40_malformed_upstream_framing_is_502_and_server_survives() {
    let responses: [&[u8]; 2] = [
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nFFFFFFFFFFFFFFFF\r\nabc\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 1000000000000\r\n\r\nabc",
    ];
    for response in responses {
        let backend = Backend::spawn(response.to_vec());
        let conf = format!(
            r#"
http {{
    server {{
        listen %%PORT%%;
        location /up/ {{
            proxy_pass http://127.0.0.1:{};
        }}
        location /alive {{
            return 200 "alive";
        }}
    }}
}}
"#,
            backend.addr.port()
        );
        let (mut guard, port, _dir) = spawn_ruxen(&conf);

        let resp = http_get_close(port, "/up/");
        assert_eq!(
            status_code(&resp),
            502,
            "upstream {:?}: {}",
            String::from_utf8_lossy(response),
            String::from_utf8_lossy(&resp)
        );
        assert!(
            guard.child.try_wait().unwrap().is_none(),
            "ruxen exited after upstream {:?}",
            String::from_utf8_lossy(response)
        );
        let resp = http_get_close(port, "/alive");
        assert_eq!(status_code(&resp), 200);
        assert_eq!(body(&resp), b"alive");
    }
}

fn proxy_conf(backend_port: u16) -> String {
    format!(
        r#"
http {{
    server {{
        listen %%PORT%%;
        location /up/ {{
            proxy_pass http://127.0.0.1:{backend_port};
        }}
        location /alive {{
            return 200 "alive";
        }}
    }}
}}
"#
    )
}

/// Upstream framing is validated like nginx
/// (ngx_http_upstream_process_content_length / _transfer_encoding): each
/// of these is a 502, never forwarded. A duplicated Content-Length used to
/// reach the client as two headers with an injected second response in
/// the body.
#[test]
fn m40_invalid_upstream_framing_is_502() {
    let responses: [&[u8]; 6] = [
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 30\r\n\r\nhelloHTTP/1.1 200 OK\r\nX-Inj: 1\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: abc\r\n\r\nhello",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
    ];
    for response in responses {
        let backend = Backend::spawn(response.to_vec());
        let (_guard, port, _dir) = spawn_ruxen(&proxy_conf(backend.addr.port()));
        let resp = http_get_close(port, "/up/");
        assert_eq!(
            status_code(&resp),
            502,
            "upstream {:?}: {}",
            String::from_utf8_lossy(response),
            String::from_utf8_lossy(&resp)
        );
        assert_eq!(status_code(&http_get_close(port, "/alive")), 200);
    }
}

/// nginx keeps the first of a repeated single-valued header (Expires,
/// Content-Type, Location, …) and drops the rest
/// (proxy_duplicate_headers.t "duplicate expires ignored").
#[test]
fn m40_repeated_single_headers_keep_the_first() {
    let backend = Backend::spawn(
        b"HTTP/1.0 200 OK\r\nExpires: foo\r\nExpires: bar\r\nContent-Type: text/a\r\n\
          Content-Type: text/b\r\nX-Multi: 1\r\nX-Multi: 2\r\nContent-Length: 2\r\n\r\nok"
            .to_vec(),
    );
    let (_guard, port, _dir) = spawn_ruxen(&proxy_conf(backend.addr.port()));
    let resp = String::from_utf8_lossy(&http_get_close(port, "/up/")).into_owned();
    assert!(resp.contains("\r\nExpires: foo\r\n"), "{resp}");
    assert!(!resp.contains("bar"), "{resp}");
    assert!(resp.contains("\r\nContent-Type: text/a\r\n"), "{resp}");
    assert!(!resp.contains("text/b"), "{resp}");
    // Headers nginx doesn't treat as single-valued pass through repeated.
    assert_eq!(resp.matches("\r\nX-Multi: ").count(), 2, "{resp}");
}

/// A body delimited by the upstream closing (HTTP/1.0, no Content-Length)
/// is buffered whole, so ruxen frames it with Content-Length for the
/// client. It used to go out with neither Content-Length nor chunked on a
/// keep-alive connection: the client hung, and a pipelined second response
/// was glued onto the body.
#[test]
fn m40_close_delimited_upstream_body_is_framed_for_keepalive_clients() {
    let backend = Backend::spawn(
        b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\nbody-until-eof".to_vec(),
    );
    let (_guard, port, _dir) = spawn_ruxen(&proxy_conf(backend.addr.port()));

    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    // Two requests on one keep-alive connection.
    stream
        .write_all(b"GET /up/ HTTP/1.1\r\nHost: x\r\n\r\nGET /alive HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut out = Vec::new();
    let _ = stream.read_to_end(&mut out);
    let text = String::from_utf8_lossy(&out);
    let (first, second) = text
        .split_once("body-until-eof")
        .unwrap_or_else(|| panic!("no proxied body in: {text}"));
    assert!(first.starts_with("HTTP/1.1 200"), "{text}");
    assert!(first.contains("\r\nContent-Length: 14\r\n"), "{text}");
    assert!(second.starts_with("HTTP/1.1 200"), "{text}");
    assert!(second.ends_with("alive"), "{text}");
}
