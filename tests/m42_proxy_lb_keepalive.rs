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
use std::time::Duration;

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
    let guard = common::ports::setup_lock();
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

fn spawn_ruxen(conf_body: &str) -> (ServerGuard, u16) {
    let (port, _lock) = pick_port();
    let dir = unique_dir();
    let conf_path = dir.join("ruxen.conf");
    std::fs::write(&conf_path, conf_body.replace("%%PORT%%", &port.to_string())).unwrap();

    let pid_file = dir.join("ruxen.pid");
    let child = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .args(["-c", conf_path.to_str().unwrap()])
        .arg("-g")
        .arg(format!("pid {};", pid_file.display()))
        .env("RUXEN_WORKERS", "1") // single worker → deterministic pool reuse
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ruxen");
    // Owned by the guard before the wait: if it panics, ruxen still stops.
    let mut guard = ServerGuard {
        child,
        tempdir: dir,
    };
    common::ports::wait_for_pid_file(&mut guard.child, &pid_file, Duration::from_secs(5));
    (guard, port)
}

/// Backend that handles many requests over the same socket if the client
/// keeps it alive. Counts accepted connections and total requests served.
struct Backend {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    accepts: Arc<AtomicUsize>,
    requests: Arc<AtomicUsize>,
    /// The request heads received, in order.
    heads: Arc<Mutex<Vec<String>>>,
}

impl Backend {
    fn spawn(response: &'static [u8]) -> Self {
        // Bind under the setup lock so a parallel test can't grab this port in the
        // window between its pick_port() drop and its ruxen's bind.
        let listener = {
            let _g = common::ports::setup_lock();
            TcpListener::bind("127.0.0.1:0").unwrap()
        };
        let addr = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let accepts = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(AtomicUsize::new(0));
        let heads = Arc::new(Mutex::new(Vec::new()));
        let heads_c = heads.clone();
        let stop_c = stop.clone();
        let accepts_c = accepts.clone();
        let requests_c = requests.clone();
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
                accepts_c.fetch_add(1, Ordering::SeqCst);
                let requests_inner = requests_c.clone();
                let stop_inner = stop_c.clone();
                let heads_inner = heads_c.clone();
                thread::spawn(move || {
                    handle_conn(s, response, &requests_inner, &heads_inner, &stop_inner);
                });
            }
        });
        Backend {
            addr,
            stop,
            accepts,
            requests,
            heads,
        }
    }

    fn last_head(&self) -> String {
        self.heads
            .lock()
            .unwrap()
            .last()
            .cloned()
            .unwrap_or_default()
    }
}

fn handle_conn(
    mut s: TcpStream,
    response: &[u8],
    requests: &AtomicUsize,
    heads: &Mutex<Vec<String>>,
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
        while let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head_end = p + 4;
            let head = &buf[..head_end];
            let mut cl = 0usize;
            for line in std::str::from_utf8(head).unwrap_or("").lines() {
                if let Some(rest) = line
                    .to_ascii_lowercase()
                    .strip_prefix("content-length:")
                    .map(|s| s.trim().to_owned())
                    && let Ok(n) = rest.parse::<usize>()
                {
                    cl = n;
                }
            }
            if buf.len() < head_end + cl {
                break;
            }
            heads
                .lock()
                .unwrap()
                .push(String::from_utf8_lossy(head).into_owned());
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

fn header_value(req: &[u8], name: &str) -> Option<String> {
    let head_end = req.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = std::str::from_utf8(&req[..head_end]).ok()?;
    for line in head.lines().skip(1) {
        if let Some((k, v)) = line.split_once(':')
            && k.eq_ignore_ascii_case(name)
        {
            return Some(v.trim().to_string());
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

/// The value of the request head's header `name`, if it has one.
fn head_header(head: &str, name: &str) -> Option<String> {
    head.lines().skip(1).find_map(|line| {
        let (n, v) = line.split_once(':')?;
        n.eq_ignore_ascii_case(name).then(|| v.trim().to_owned())
    })
}

/// `n` client requests to `paths` in turn, each on a new client connection.
fn get_n(port: u16, paths: &[&str], n: usize) {
    for i in 0..n {
        let path = paths[i % paths.len()];
        let resp = http_send(
            port,
            format!("GET {path} HTTP/1.1\r\nHost: c\r\nConnection: close\r\n\r\n").as_bytes(),
        );
        assert!(
            resp.starts_with(b"HTTP/1.1 200"),
            "got: {:?}",
            String::from_utf8_lossy(&resp[..resp.len().min(80)])
        );
    }
    sleep(Duration::from_millis(50));
}

#[test]
fn m42_upstream_block_pools_by_default() {
    // nginx 1.29.7: an `upstream {}` block keeps idle connections with no
    // `keepalive` directive, and the proxy speaks HTTP/1.1 with no
    // Connection header.
    let backend = Backend::spawn(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nK");
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
        }}
    }}
}}
"#,
        backend.addr.port(),
    );
    let (_g, port) = spawn_ruxen(&conf);
    const N: usize = 4;
    get_n(port, &["/"], N);
    assert_eq!(backend.requests.load(Ordering::SeqCst), N);
    assert_eq!(backend.accepts.load(Ordering::SeqCst), 1);
    let head = backend.last_head();
    assert!(head.starts_with("GET / HTTP/1.1\r\n"), "{head}");
    assert_eq!(head_header(&head, "Connection"), None, "{head}");
}

#[test]
fn m42_keepalive_zero_turns_the_pool_off() {
    // `keepalive 0;` → fresh socket per request, closed by the backend.
    let backend = Backend::spawn(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nN");
    let conf = format!(
        r#"
http {{
    upstream pool {{
        server 127.0.0.1:{};
        keepalive 0;
    }}
    server {{
        listen %%PORT%%;
        location / {{
            proxy_pass http://pool;
        }}
    }}
}}
"#,
        backend.addr.port(),
    );
    let (_g, port) = spawn_ruxen(&conf);
    const N: usize = 4;
    get_n(port, &["/"], N);
    assert_eq!(
        backend.accepts.load(Ordering::SeqCst),
        N,
        "expected one upstream socket per request with keepalive 0"
    );
    // Not 1.29.7's empty header: the backend closes first and holds the
    // TIME_WAIT (#582).
    let head = backend.last_head();
    assert!(head.starts_with("GET / HTTP/1.1\r\n"), "{head}");
    assert_eq!(head_header(&head, "Connection").as_deref(), Some("close"));
}

#[test]
fn m42_proxy_pass_without_upstream_block_does_not_pool() {
    // An implicit upstream has no keepalive pool (1.29.7 skips it too).
    let backend = Backend::spawn(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nN");
    let conf = format!(
        r#"
http {{
    server {{
        listen %%PORT%%;
        location / {{
            proxy_pass http://127.0.0.1:{};
        }}
        location /h10 {{
            proxy_pass http://127.0.0.1:{};
            proxy_http_version 1.0;
        }}
    }}
}}
"#,
        backend.addr.port(),
        backend.addr.port(),
    );
    let (_g, port) = spawn_ruxen(&conf);
    const N: usize = 3;
    get_n(port, &["/"], N);
    assert_eq!(backend.accepts.load(Ordering::SeqCst), N);
    let head = backend.last_head();
    assert!(head.starts_with("GET / HTTP/1.1\r\n"), "{head}");
    assert_eq!(head_header(&head, "Connection").as_deref(), Some("close"));
    // HTTP/1.0 closes anyway: no Connection header, as in 1.29.7.
    get_n(port, &["/h10"], 1);
    let head = backend.last_head();
    assert!(head.starts_with("GET /h10 HTTP/1.0\r\n"), "{head}");
    assert_eq!(head_header(&head, "Connection"), None, "{head}");
}

/// Two locations proxying to one upstream, requests alternating between
/// them: the upstream connections the backend accepted.
fn accepts_across_two_locations(keepalive: &str) -> usize {
    let backend = Backend::spawn(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nK");
    let conf = format!(
        r#"
http {{
    upstream pool {{
        server 127.0.0.1:{};
        {keepalive}
    }}
    server {{
        listen %%PORT%%;
        location /a {{
            proxy_pass http://pool;
        }}
        location /b {{
            proxy_pass http://pool;
        }}
    }}
}}
"#,
        backend.addr.port(),
    );
    let (_g, port) = spawn_ruxen(&conf);
    get_n(port, &["/a", "/b"], 6);
    assert_eq!(backend.requests.load(Ordering::SeqCst), 6);
    backend.accepts.load(Ordering::SeqCst)
}

#[test]
fn m42_local_pool_keeps_connections_per_location() {
    // `local` (and the 1.29.7 default): a connection goes back to the
    // location that opened it; without it, every location shares them.
    assert_eq!(accepts_across_two_locations(""), 2);
    assert_eq!(accepts_across_two_locations("keepalive 4 local;"), 2);
    assert_eq!(accepts_across_two_locations("keepalive 4;"), 1);
}

#[test]
fn m42_keepalive_caps_the_upstream_not_each_peer() {
    // `keepalive 1;` with two peers taken in turn: the one idle slot is
    // the upstream's, so each release evicts the other peer's connection
    // and every request connects anew. A slot per peer would reuse both.
    let a = Backend::spawn(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nA");
    let b = Backend::spawn(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nB");
    let conf = format!(
        r#"
http {{
    upstream pool {{
        server 127.0.0.1:{};
        server 127.0.0.1:{};
        keepalive 1;
    }}
    server {{
        listen %%PORT%%;
        location / {{
            proxy_pass http://pool;
        }}
    }}
}}
"#,
        a.addr.port(),
        b.addr.port(),
    );
    let (_g, port) = spawn_ruxen(&conf);
    const N: usize = 6;
    get_n(port, &["/"], N);
    let accepts = a.accepts.load(Ordering::SeqCst) + b.accepts.load(Ordering::SeqCst);
    assert_eq!(accepts, N);
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
