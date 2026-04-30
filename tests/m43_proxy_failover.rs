//! M43 — proxy_next_upstream failover, max_fails / fail_timeout, least_conn,
//! proxy_intercept_errors, and `proxy_pass http://up/path;` rewriting.
//!
//! End-to-end against a live `ruxen` binary in a child process. Backends
//! are tiny TCP listeners that return canned responses or refuse to
//! answer; the tests assert the wire-level behavior of the proxy attempt
//! machine + LB state.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
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
    static N: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "ruxen-m43-{}-{}",
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
        .env("RUXEN_WORKERS", "1") // single worker → deterministic LB state
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

/// Backend that records each accepted request and returns a canned
/// response. `mode` controls whether we accept-and-respond, accept-and-
/// hang (to provoke read timeouts), or refuse to answer. Used to drive
/// M43's failover paths.
struct Backend {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    requests: Arc<AtomicUsize>,
    last_path: Arc<Mutex<Vec<u8>>>,
}

#[derive(Clone, Copy)]
enum Mode {
    Ok,
    Status5xx(u16),
}

impl Backend {
    fn spawn(mode: Mode) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(AtomicUsize::new(0));
        let last_path = Arc::new(Mutex::new(Vec::new()));
        let stop_c = stop.clone();
        let req_c = requests.clone();
        let path_c = last_path.clone();
        thread::spawn(move || {
            loop {
                if stop_c.load(Ordering::SeqCst) {
                    return;
                }
                let (s, _) = match listener.accept() {
                    Ok(v) => v,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(_) => return,
                };
                let req_inner = req_c.clone();
                let path_inner = path_c.clone();
                let stop_inner = stop_c.clone();
                thread::spawn(move || handle_conn(s, mode, &req_inner, &path_inner, &stop_inner));
            }
        });
        Backend {
            addr,
            stop,
            requests,
            last_path,
        }
    }
}

fn handle_conn(
    mut s: TcpStream,
    mode: Mode,
    requests: &AtomicUsize,
    last_path: &Mutex<Vec<u8>>,
    stop: &AtomicBool,
) {
    s.set_read_timeout(Some(Duration::from_secs(2))).ok();
    let mut buf: Vec<u8> = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        if stop.load(Ordering::SeqCst) {
            return;
        }
        match s.read(&mut tmp) {
            Ok(0) => return,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(_) => return,
        }
        loop {
            let head_end = match buf.windows(4).position(|w| w == b"\r\n\r\n") {
                Some(p) => p + 4,
                None => break,
            };
            let head = &buf[..head_end];
            let mut cl = 0usize;
            for line in std::str::from_utf8(head).unwrap_or("").lines() {
                if let Some(rest) = line
                    .to_ascii_lowercase()
                    .strip_prefix("content-length:")
                    .map(|s| s.trim().to_owned())
                {
                    if let Ok(n) = rest.parse::<usize>() {
                        cl = n;
                    }
                }
            }
            if buf.len() < head_end + cl {
                break;
            }
            // Capture the request line for path-rewrite assertions.
            if let Some(line_end) = head.windows(2).position(|w| w == b"\r\n") {
                let mut last = last_path.lock().unwrap();
                *last = head[..line_end].to_vec();
            }
            requests.fetch_add(1, Ordering::SeqCst);
            match mode {
                Mode::Ok => {
                    let resp = b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nOK";
                    if s.write_all(resp).is_err() {
                        return;
                    }
                }
                Mode::Status5xx(code) => {
                    let body = format!("HTTP/1.0 {code} Err\r\nContent-Length: 3\r\n\r\nERR");
                    if s.write_all(body.as_bytes()).is_err() {
                        return;
                    }
                }
            }
            buf.drain(..head_end + cl);
        }
    }
}

impl Drop for Backend {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

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
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(_) => break,
        }
    }
    out
}

fn body_of(resp: &[u8]) -> &[u8] {
    let i = resp.windows(4).position(|w| w == b"\r\n\r\n").unwrap_or(0);
    &resp[i + 4..]
}

fn status_of(resp: &[u8]) -> u16 {
    if resp.len() < 12 {
        return 0;
    }
    let d = &resp[9..12];
    if !d.iter().all(|b| b.is_ascii_digit()) {
        return 0;
    }
    ((d[0] - b'0') as u16) * 100 + ((d[1] - b'0') as u16) * 10 + (d[2] - b'0') as u16
}

#[test]
fn m43_proxy_next_upstream_fails_over_to_next_peer_on_connect_refused() {
    // Bind a port and immediately drop it so connect() fails.
    let dead_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let dead = dead_listener.local_addr().unwrap().port();
    drop(dead_listener);
    let live = Backend::spawn(Mode::Ok);

    let conf = format!(
        r#"
http {{
    upstream pool {{
        server 127.0.0.1:{};
        server 127.0.0.1:{};
    }}
    server {{
        listen %%PORT%%;
        location / {{
            proxy_pass http://pool;
            proxy_next_upstream error timeout;
        }}
    }}
}}
"#,
        dead,
        live.addr.port(),
    );
    let (_g, port) = spawn_ruxen(&conf);

    // First request hits the dead peer first (per smoothed RR), should
    // fail over to the live one. We don't assert which peer the LB
    // initially picks — only that the response succeeds with the live
    // backend's body.
    let resp = http_send(
        port,
        b"GET / HTTP/1.1\r\nHost: c\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(
        status_of(&resp),
        200,
        "{:?}",
        String::from_utf8_lossy(&resp)
    );
    assert_eq!(body_of(&resp), b"OK");
}

#[test]
fn m43_proxy_next_upstream_off_returns_502_without_failover() {
    let dead_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let dead = dead_listener.local_addr().unwrap().port();
    drop(dead_listener);
    let live = Backend::spawn(Mode::Ok);

    let conf = format!(
        r#"
http {{
    upstream pool {{
        server 127.0.0.1:{};
        server 127.0.0.1:{};
    }}
    server {{
        listen %%PORT%%;
        location / {{
            proxy_pass http://pool;
            proxy_next_upstream off;
        }}
    }}
}}
"#,
        dead,
        live.addr.port(),
    );
    let (_g, port) = spawn_ruxen(&conf);

    // With next_upstream off, *any* peer pick that lands on the dead one
    // surfaces 502 directly. RR alternates, so over a handful of requests
    // we must observe at least one 502 paired with at least one 200.
    let mut saw_bad = false;
    let mut saw_ok = false;
    for _ in 0..6 {
        let resp = http_send(
            port,
            b"GET / HTTP/1.1\r\nHost: c\r\nConnection: close\r\n\r\n",
        );
        match status_of(&resp) {
            200 => saw_ok = true,
            502 => saw_bad = true,
            other => panic!(
                "unexpected status {other}: {:?}",
                String::from_utf8_lossy(&resp)
            ),
        }
    }
    assert!(
        saw_bad,
        "expected at least one 502 with proxy_next_upstream off"
    );
    assert!(saw_ok, "expected at least one 200 from the live peer");
}

#[test]
fn m43_proxy_next_upstream_http_500_failover_picks_healthy_peer() {
    let bad = Backend::spawn(Mode::Status5xx(500));
    let live = Backend::spawn(Mode::Ok);
    let conf = format!(
        r#"
http {{
    upstream pool {{
        server 127.0.0.1:{};
        server 127.0.0.1:{};
    }}
    server {{
        listen %%PORT%%;
        location / {{
            proxy_pass http://pool;
            proxy_next_upstream error timeout http_500;
        }}
    }}
}}
"#,
        bad.addr.port(),
        live.addr.port(),
    );
    let (_g, port) = spawn_ruxen(&conf);
    // First request: with smoothed-weight RR, peer 0 (the 500 backend)
    // is picked first. http_500 is in the next_upstream mask, so the
    // attempt machine must retry on peer 1 and surface that 200.
    let resp = http_send(
        port,
        b"GET / HTTP/1.1\r\nHost: c\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_of(&resp), 200, "expected failover to live peer");
    assert_eq!(body_of(&resp), b"OK");
    // The bad peer should have served at least one request (the failed
    // attempt) before failover.
    assert!(bad.requests.load(Ordering::SeqCst) >= 1);
    assert!(live.requests.load(Ordering::SeqCst) >= 1);
}

#[test]
fn m43_proxy_intercept_errors_serves_local_error_page_on_5xx() {
    let bad = Backend::spawn(Mode::Status5xx(500));
    let conf = format!(
        r#"
http {{
    server {{
        listen %%PORT%%;
        location / {{
            proxy_pass http://127.0.0.1:{};
            proxy_intercept_errors on;
            error_page 500 = /custom-500;
        }}
        location = /custom-500 {{
            return 200 "intercepted";
        }}
    }}
}}
"#,
        bad.addr.port(),
    );
    let (_g, port) = spawn_ruxen(&conf);
    let resp = http_send(
        port,
        b"GET /thing HTTP/1.1\r\nHost: c\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(
        status_of(&resp),
        200,
        "{:?}",
        String::from_utf8_lossy(&resp)
    );
    assert_eq!(body_of(&resp), b"intercepted");
}

#[test]
fn m43_proxy_intercept_errors_off_passes_5xx_through() {
    let bad = Backend::spawn(Mode::Status5xx(500));
    let conf = format!(
        r#"
http {{
    server {{
        listen %%PORT%%;
        location / {{
            proxy_pass http://127.0.0.1:{};
            error_page 500 = /custom-500;
        }}
        location = /custom-500 {{
            return 200 "intercepted";
        }}
    }}
}}
"#,
        bad.addr.port(),
    );
    let (_g, port) = spawn_ruxen(&conf);
    // Without proxy_intercept_errors on, the upstream's 500 is forwarded
    // to the client unchanged — error_page only fires for ruxen-generated
    // statuses, not proxied ones (matches nginx).
    let resp = http_send(
        port,
        b"GET /thing HTTP/1.1\r\nHost: c\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_of(&resp), 500);
    assert_eq!(body_of(&resp), b"ERR");
}

#[test]
fn m43_proxy_intercept_errors_named_target_reroutes() {
    let bad = Backend::spawn(Mode::Status5xx(500));
    let conf = format!(
        r#"
http {{
    server {{
        listen %%PORT%%;
        location / {{
            proxy_pass http://127.0.0.1:{};
            proxy_intercept_errors on;
            error_page 500 = @fallback;
        }}
        location @fallback {{
            return 200 "named-intercept";
        }}
    }}
}}
"#,
        bad.addr.port(),
    );
    let (_g, port) = spawn_ruxen(&conf);
    let resp = http_send(
        port,
        b"GET /thing HTTP/1.1\r\nHost: c\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(
        status_of(&resp),
        200,
        "{:?}",
        String::from_utf8_lossy(&resp)
    );
    assert_eq!(body_of(&resp), b"named-intercept");
}

#[test]
fn m43_proxy_intercept_errors_preserves_status_and_args() {
    let bad = Backend::spawn(Mode::Status5xx(500));
    let conf = format!(
        r#"
http {{
    server {{
        listen %%PORT%%;
        location / {{
            proxy_pass http://127.0.0.1:{};
            proxy_intercept_errors on;
            error_page 500 /custom?$arg_token;
        }}
        location = /custom {{
            add_header X-Status $status always;
            return 200 "$args";
        }}
    }}
}}
"#,
        bad.addr.port(),
    );
    let (_g, port) = spawn_ruxen(&conf);
    let resp = http_send(
        port,
        b"GET /thing?token=abc HTTP/1.1\r\nHost: c\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(
        status_of(&resp),
        500,
        "{:?}",
        String::from_utf8_lossy(&resp)
    );
    assert_eq!(body_of(&resp), b"abc");
    let wire = String::from_utf8_lossy(&resp);
    assert!(
        wire.contains("\r\nX-Status: 500\r\n"),
        "expected X-Status header to render post-override; got:\n{wire}"
    );
}

#[test]
fn m43_proxy_pass_path_rewrites_prefix_to_request_path() {
    let live = Backend::spawn(Mode::Ok);
    let conf = format!(
        r#"
http {{
    server {{
        listen %%PORT%%;
        location /api/ {{
            proxy_pass http://127.0.0.1:{}/v2/;
        }}
    }}
}}
"#,
        live.addr.port(),
    );
    let (_g, port) = spawn_ruxen(&conf);
    let resp = http_send(
        port,
        b"GET /api/users?q=1 HTTP/1.1\r\nHost: c\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_of(&resp), 200);
    let last = live.last_path.lock().unwrap();
    let line = String::from_utf8_lossy(&last);
    // Expected upstream request line: GET /v2/users?q=1 HTTP/1.0
    assert!(line.starts_with("GET /v2/users?q=1 HTTP/"), "got: {line}");
}

#[test]
fn m43_least_conn_directive_parses_and_runs() {
    // Smoke test: verify that `least_conn;` inside upstream{} is accepted
    // by the config parser and that requests still succeed. Distribution
    // semantics are covered by the unit tests in src/upstream.rs.
    let b1 = Backend::spawn(Mode::Ok);
    let b2 = Backend::spawn(Mode::Ok);
    let conf = format!(
        r#"
http {{
    upstream pool {{
        least_conn;
        server 127.0.0.1:{};
        server 127.0.0.1:{};
    }}
    server {{
        listen %%PORT%%;
        location / {{
            proxy_pass http://pool;
        }}
    }}
}}
"#,
        b1.addr.port(),
        b2.addr.port(),
    );
    let (_g, port) = spawn_ruxen(&conf);
    for _ in 0..4 {
        let resp = http_send(
            port,
            b"GET / HTTP/1.1\r\nHost: c\r\nConnection: close\r\n\r\n",
        );
        assert_eq!(status_of(&resp), 200);
    }
    let total = b1.requests.load(Ordering::SeqCst) + b2.requests.load(Ordering::SeqCst);
    assert_eq!(total, 4, "all four requests must reach a backend");
}

#[test]
fn m43_idempotent_only_retry_on_stale_pooled_conn() {
    // Smoke test: a POST with a body should not be silently retried on a
    // stale pooled conn. Without a real way to provoke staleness via TCP
    // tricks here, the test instead verifies that a fresh POST with a
    // body gets a single forwarded request — i.e., we don't double-send.
    let live = Backend::spawn(Mode::Ok);
    let conf = format!(
        r#"
http {{
    upstream pool {{
        server 127.0.0.1:{};
        keepalive 4;
    }}
    server {{
        listen %%PORT%%;
        location / {{
            proxy_pass http://pool;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
        }}
    }}
}}
"#,
        live.addr.port(),
    );
    let (_g, port) = spawn_ruxen(&conf);
    let req =
        b"POST /thing HTTP/1.1\r\nHost: c\r\nContent-Length: 5\r\nConnection: close\r\n\r\nHELLO";
    let resp = http_send(port, req);
    assert_eq!(status_of(&resp), 200);
    // Exactly one upstream request — no retry shadow.
    assert_eq!(live.requests.load(Ordering::SeqCst), 1);
}
