//! M42 — round-robin across multiple upstream peers, weight + down,
//! `proxy_http_version 1.1`, and `keepalive N;` upstream pool reuse.
//!
//! Spawns small in-process backends that count both *connections* and
//! *requests*. Pool reuse is verified by sending N client requests
//! against a single upstream peer and checking that the backend saw
//! fewer accept events than requests.

mod common;

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
        "ruxen-m42-{}-{}",
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
    std::fs::write(
        &conf_path,
        conf_body.replace("%%PORT%%", &port.to_string()),
    )
    .unwrap();

    let child = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .args(["-c", conf_path.to_str().unwrap()])
        .env("RUXEN_WORKERS", "1") // single worker → deterministic pool reuse
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

/// Backend that handles many requests over the same socket if the client
/// keeps it alive. Counts accepted connections and total requests served.
struct Backend {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    accepts: Arc<AtomicUsize>,
    requests: Arc<AtomicUsize>,
}

impl Backend {
    fn spawn(response: &'static [u8]) -> Self {
        // Bind under SETUP_LOCK so a parallel test can't grab this port in the
        // window between its pick_port() drop and its ruxen's bind.
        let listener = {
            let _g = SETUP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            TcpListener::bind("127.0.0.1:0").unwrap()
        };
        let addr = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let accepts = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(AtomicUsize::new(0));
        let stop_c = stop.clone();
        let accepts_c = accepts.clone();
        let requests_c = requests.clone();
        thread::spawn(move || loop {
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
            accepts_c.fetch_add(1, Ordering::SeqCst);
            let requests_inner = requests_c.clone();
            let stop_inner = stop_c.clone();
            thread::spawn(move || {
                handle_conn(s, response, &requests_inner, &stop_inner);
            });
        });
        Backend {
            addr,
            stop,
            accepts,
            requests,
        }
    }
}

fn handle_conn(
    mut s: TcpStream,
    response: &[u8],
    requests: &AtomicUsize,
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
        // Process as many complete HTTP requests as the buffer holds.
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
            requests.fetch_add(1, Ordering::SeqCst);
            if s.write_all(response).is_err() {
                return;
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
    stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
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

fn header_value<'a>(req: &'a [u8], name: &str) -> Option<String> {
    let head_end = req.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = std::str::from_utf8(&req[..head_end]).ok()?;
    for line in head.lines().skip(1) {
        if let Some((k, v)) = line.split_once(':') {
            if k.eq_ignore_ascii_case(name) {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

#[test]
fn m42_round_robin_distributes_across_two_backends() {
    let b1 = Backend::spawn(b"HTTP/1.0 200 OK\r\nContent-Length: 1\r\n\r\nA");
    let b2 = Backend::spawn(b"HTTP/1.0 200 OK\r\nContent-Length: 1\r\n\r\nB");
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
        }}
    }}
}}
"#,
        b1.addr.port(),
        b2.addr.port(),
    );
    let (_g, port) = spawn_ruxen(&conf);

    let mut hits1 = 0usize;
    let mut hits2 = 0usize;
    for _ in 0..6 {
        let resp = http_send(
            port,
            b"GET / HTTP/1.1\r\nHost: c\r\nConnection: close\r\n\r\n",
        );
        let body_start = resp.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        let body = &resp[body_start..];
        if body == b"A" {
            hits1 += 1;
        } else if body == b"B" {
            hits2 += 1;
        } else {
            panic!("unexpected body: {:?}", body);
        }
    }
    assert_eq!((hits1, hits2), (3, 3), "expected 3:3 RR distribution");
}

#[test]
fn m42_down_peer_is_skipped() {
    let live = Backend::spawn(b"HTTP/1.0 200 OK\r\nContent-Length: 1\r\n\r\nL");
    // Pick a port that's almost certainly free; using a random :0 binding
    // and immediately closing it gives us a "should-fail-to-connect" port.
    let dead = common::ports::DeadPort::new();
    let dead_port = dead.port();

    let conf = format!(
        r#"
http {{
    upstream pool {{
        server 127.0.0.1:{} down;
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
        dead_port,
        live.addr.port(),
    );
    let (_g, port) = spawn_ruxen(&conf);

    for _ in 0..3 {
        let resp = http_send(
            port,
            b"GET / HTTP/1.1\r\nHost: c\r\nConnection: close\r\n\r\n",
        );
        assert!(resp.starts_with(b"HTTP/1.1 200"));
        let body_start = resp.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        assert_eq!(&resp[body_start..], b"L");
    }
}

#[test]
fn m42_weight_skews_distribution() {
    let b1 = Backend::spawn(b"HTTP/1.0 200 OK\r\nContent-Length: 1\r\n\r\nA");
    let b2 = Backend::spawn(b"HTTP/1.0 200 OK\r\nContent-Length: 1\r\n\r\nB");
    let conf = format!(
        r#"
http {{
    upstream pool {{
        server 127.0.0.1:{} weight=3;
        server 127.0.0.1:{} weight=1;
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

    let mut a = 0usize;
    let mut b = 0usize;
    for _ in 0..8 {
        let resp = http_send(
            port,
            b"GET / HTTP/1.1\r\nHost: c\r\nConnection: close\r\n\r\n",
        );
        let body_start = resp.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        match &resp[body_start..] {
            b"A" => a += 1,
            b"B" => b += 1,
            _ => panic!("unexpected body"),
        }
    }
    assert_eq!((a, b), (6, 2));
}

#[test]
fn m42_proxy_http_version_1_1_uses_http11_on_upstream() {
    let backend = Backend::spawn(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
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
        backend.addr.port(),
    );
    let (_g, port) = spawn_ruxen(&conf);

    let resp = http_send(
        port,
        b"GET / HTTP/1.1\r\nHost: c\r\nConnection: close\r\n\r\n",
    );
    assert!(resp.starts_with(b"HTTP/1.1 200"));
    // Wait briefly so the backend handler has flushed/recorded.
    sleep(Duration::from_millis(20));
    assert!(backend.requests.load(Ordering::SeqCst) >= 1);
}

#[test]
fn m42_keepalive_pool_reuses_upstream_socket() {
    // Single backend, HTTP/1.1, with `keepalive 4;`. Send several client
    // requests; each opens a new client conn (Connection: close on the
    // client side), but ruxen should reuse the *upstream* socket via
    // the pool.
    let backend = Backend::spawn(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nK");
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
        backend.addr.port(),
    );
    let (_g, port) = spawn_ruxen(&conf);

    const N: usize = 6;
    for _ in 0..N {
        let resp = http_send(
            port,
            b"GET / HTTP/1.1\r\nHost: c\r\nConnection: close\r\n\r\n",
        );
        assert!(
            resp.starts_with(b"HTTP/1.1 200"),
            "got: {:?}",
            String::from_utf8_lossy(&resp[..resp.len().min(80)])
        );
    }
    sleep(Duration::from_millis(50));
    let accepts = backend.accepts.load(Ordering::SeqCst);
    let requests = backend.requests.load(Ordering::SeqCst);
    assert_eq!(requests, N, "backend served all {N} requests");
    assert!(
        accepts < N,
        "expected pool to reuse upstream socket; saw {accepts} accepts for {N} requests"
    );
}

#[test]
fn m42_pool_disabled_without_keepalive_directive() {
    // No `keepalive` directive on the upstream → fresh socket per request,
    // even with proxy_http_version 1.1.
    let backend = Backend::spawn(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nN");
    let conf = format!(
        r#"
http {{
    upstream pool {{
        server 127.0.0.1:{};
    }}
    server {{
        listen %%PORT%%;
        location / {{
            proxy_pass http://pool;
            proxy_http_version 1.1;
        }}
    }}
}}
"#,
        backend.addr.port(),
    );
    let (_g, port) = spawn_ruxen(&conf);

    const N: usize = 4;
    for _ in 0..N {
        let _ = http_send(
            port,
            b"GET / HTTP/1.1\r\nHost: c\r\nConnection: close\r\n\r\n",
        );
    }
    sleep(Duration::from_millis(50));
    assert_eq!(
        backend.accepts.load(Ordering::SeqCst),
        N,
        "expected one upstream socket per request when keepalive is unset"
    );
}

#[test]
fn m42_chunked_upstream_response_decoded_for_client() {
    // Backend speaks HTTP/1.1 with chunked transfer-encoding. Ruxen
    // should decode + re-frame as Content-Length for the client.
    let response: &'static [u8] = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
    let backend = Backend::spawn(response);
    let conf = format!(
        r#"
http {{
    upstream pool {{
        server 127.0.0.1:{};
    }}
    server {{
        listen %%PORT%%;
        location / {{
            proxy_pass http://pool;
            proxy_http_version 1.1;
        }}
    }}
}}
"#,
        backend.addr.port(),
    );
    let (_g, port) = spawn_ruxen(&conf);

    let resp = http_send(
        port,
        b"GET / HTTP/1.1\r\nHost: c\r\nConnection: close\r\n\r\n",
    );
    assert!(resp.starts_with(b"HTTP/1.1 200"));
    assert_eq!(header_value(&resp, "Content-Length").as_deref(), Some("11"));
    assert_eq!(header_value(&resp, "Transfer-Encoding"), None);
    let body_start = resp.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    assert_eq!(&resp[body_start..], b"hello world");
}
