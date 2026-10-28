//! M165 — proxied responses that used to be read whole are relayed as
//! they arrive (#463): a response going into `proxy_cache` is written to
//! the cache file on the way, and a status that fails over or is
//! intercepted is decided on the header, before the body.

mod common;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const CHUNK: usize = 64 * 1024;
const CHUNKS: usize = 5;
const PAUSE: Duration = Duration::from_millis(300);
const BIG: usize = 70 << 20;

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 % 251) as u8).collect()
}

type Hits = Arc<Mutex<HashMap<String, usize>>>;

/// A backend counting the requests per target. `/slow` is chunked, 64 KiB
/// at a time with pauses, `/slowlen` the same with a length; `/big` is
/// 70 MiB at once; `/cut` closes early; `/s502` and `/s404` send their
/// head, then their body seconds later. `plain` answers everything with
/// a small 200.
fn spawn_backend(listener: TcpListener, plain: bool) -> Hits {
    let hits: Hits = Arc::default();
    let counter = hits.clone();
    thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut conn) = conn else { return };
            let counter = counter.clone();
            thread::spawn(move || {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match conn.read(&mut chunk) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                let line = String::from_utf8_lossy(&buf);
                let target = line.split(' ').nth(1).unwrap_or("").to_string();
                *counter.lock().unwrap().entry(target.clone()).or_default() += 1;
                let path = target.split('?').next().unwrap_or("");
                let body = pattern(CHUNK * CHUNKS);
                let _ = match path {
                    _ if plain => conn.write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nok\n",
                    ),
                    "/slow" | "/slowlen" => {
                        let framing = if path == "/slow" {
                            "Transfer-Encoding: chunked".to_string()
                        } else {
                            format!("Content-Length: {}\r\nAccept-Ranges: bytes", body.len())
                        };
                        let _ = conn.write_all(
                            format!(
                                "HTTP/1.1 200 OK\r\n{framing}\r\nETag: \"v1\"\r\n\
                                 Connection: close\r\n\r\n"
                            )
                            .as_bytes(),
                        );
                        for part in body.chunks(CHUNK) {
                            thread::sleep(PAUSE);
                            let out = if path == "/slow" {
                                let mut out = format!("{:x}\r\n", part.len()).into_bytes();
                                out.extend_from_slice(part);
                                out.extend_from_slice(b"\r\n");
                                out
                            } else {
                                part.to_vec()
                            };
                            if conn.write_all(&out).is_err() {
                                return;
                            }
                        }
                        if path == "/slow" {
                            let _ = conn.write_all(b"0\r\n\r\n");
                        }
                        Ok(())
                    }
                    "/big" => {
                        let _ = conn.write_all(
                            format!(
                                "HTTP/1.1 200 OK\r\nContent-Length: {BIG}\r\n\
                                 Connection: close\r\n\r\n"
                            )
                            .as_bytes(),
                        );
                        conn.write_all(&pattern(BIG))
                    }
                    "/cut" => {
                        let _ = conn.write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 1048576\r\n\
                              Connection: close\r\n\r\n",
                        );
                        let _ = conn.write_all(&body[..CHUNK]);
                        return;
                    }
                    "/s502" | "/s404" => {
                        let status = if path == "/s502" { "502" } else { "404" };
                        let _ = conn.write_all(
                            format!(
                                "HTTP/1.1 {status} X\r\nContent-Length: {}\r\n\
                                 Connection: close\r\n\r\n",
                                body.len()
                            )
                            .as_bytes(),
                        );
                        thread::sleep(Duration::from_secs(3));
                        conn.write_all(&body)
                    }
                    "/xar" => conn.write_all(
                        b"HTTP/1.1 200 OK\r\nX-Accel-Redirect: /in/slow\r\nX-Carried: no\r\n\
                          Content-Type: text/x-carried\r\nContent-Length: 0\r\n\
                          Connection: close\r\n\r\n",
                    ),
                    _ => conn.write_all(
                        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    ),
                };
                // Hold the connection a moment: ruxen closes first.
                let _ = conn.read(&mut chunk);
            });
        }
    });
    hits
}

struct Setup {
    dir: PathBuf,
    port: u16,
    hits: Hits,
    child: common::KillOnDrop,
}

impl Drop for Setup {
    fn drop(&mut self) {
        let _ = self.child.0.kill();
        let _ = self.child.0.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Setup {
    fn hits(&self, target: &str) -> usize {
        self.hits.lock().unwrap().get(target).copied().unwrap_or(0)
    }
}

fn setup(name: &str) -> Setup {
    let dir = std::env::temp_dir().join(format!("ruxen-m165-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let lock = common::ports::setup_lock();
    let [port] = common::ports::free_ports();
    let backend = TcpListener::bind("127.0.0.1:0").unwrap();
    let plain = TcpListener::bind("127.0.0.1:0").unwrap();
    let b = backend.local_addr().unwrap().port();
    let p = plain.local_addr().unwrap().port();
    let hits = spawn_backend(backend, false);
    spawn_backend(plain, true);
    let d = dir.display();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "worker_processes 1;\nerror_log {d}/error.log;\n\
             events {{}}\nhttp {{ access_log off;\n\
             proxy_cache_path {d}/cache levels=1:2 keys_zone=z:1m;\n\
             upstream fo {{ server 127.0.0.1:{b}; server 127.0.0.1:{p}; }}\n\
             server {{ listen 127.0.0.1:{port};\n\
               add_header X-Cache $upstream_cache_status;\n\
               location / {{ proxy_pass http://127.0.0.1:{b}; proxy_cache z;\n\
                 proxy_cache_valid 200 10m; proxy_cache_lock on; }}\n\
               location /fo/ {{ proxy_pass http://fo/; proxy_next_upstream http_502; }}\n\
               location /ic/ {{ proxy_pass http://127.0.0.1:{b}/; proxy_intercept_errors on;\n\
                 error_page 404 = @e; }}\n\
               location @e {{ return 200 \"intercepted\\n\"; }}\n\
               location /x/ {{ proxy_pass http://127.0.0.1:{b}/; }}\n\
               location /fr/ {{ proxy_pass http://127.0.0.1:{b}/; proxy_force_ranges on; }}\n\
               location /tr/ {{ proxy_pass http://127.0.0.1:{b}/; add_trailer X-Length $upstream_response_length;\n\
                 add_trailer X-Sent $sent_http_transfer_encoding; }}\n\
               location /in/ {{ internal; proxy_pass http://127.0.0.1:{b}/; }}\n\
             }} }}\n"
        ),
    )
    .unwrap();
    let pid_file = dir.join("ruxen.pid");
    let mut child = common::KillOnDrop(
        Command::new(env!("CARGO_BIN_EXE_ruxen"))
            .arg("-c")
            .arg(dir.join("nginx.conf"))
            .arg("-g")
            .arg(format!("pid {};", pid_file.display()))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    common::ports::wait_for_pid_file(&mut child, &pid_file, Duration::from_secs(5));
    drop(lock);
    Setup {
        dir,
        port,
        hits,
        child,
    }
}

struct Reply {
    ttfb: Duration,
    total: Duration,
    head: String,
    body: Vec<u8>,
}

fn send(port: u16, raw: &str) -> Reply {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    let start = Instant::now();
    s.write_all(raw.as_bytes()).unwrap();
    let mut out = Vec::new();
    let mut buf = vec![0u8; 256 * 1024];
    let mut ttfb = None;
    loop {
        match s.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                ttfb.get_or_insert_with(|| start.elapsed());
                out.extend_from_slice(&buf[..n]);
            }
        }
    }
    let total = start.elapsed();
    let end = out
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map_or(out.len(), |p| p + 4);
    let body = out.split_off(end);
    Reply {
        ttfb: ttfb.unwrap_or(total),
        total,
        head: String::from_utf8_lossy(&out).into_owned(),
        body,
    }
}

fn get(port: u16, target: &str) -> Reply {
    send(
        port,
        &format!("GET {target} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"),
    )
}

/// The answer once `target` is a hit: the file is put in place after the
/// last byte went out, so a request right after may still miss.
fn hit(port: u16, target: &str) -> Reply {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let r = get(port, target);
        if r.head.contains("\r\nX-Cache: HIT\r\n") || Instant::now() > deadline {
            return r;
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn vm_hwm(pid: u32) -> u64 {
    std::fs::read_to_string(format!("/proc/{pid}/status"))
        .unwrap()
        .lines()
        .find_map(|l| l.strip_prefix("VmHWM:"))
        .and_then(|v| v.trim().strip_suffix(" kB"))
        .unwrap()
        .parse()
        .unwrap()
}

/// The repro of #463: the first chunk of a slow chunked response reaches
/// the client at once, though the response is being cached, and the
/// cache serves the whole body afterwards.
#[test]
fn m165_cached_response_is_relayed() {
    let s = setup("ttfb");
    let r = get(s.port, "/slow");
    assert!(r.head.starts_with("HTTP/1.1 200 "), "{}", r.head);
    assert!(r.head.contains("\r\nX-Cache: MISS\r\n"), "{}", r.head);
    assert!(r.body.len() > CHUNK * CHUNKS, "{} bytes", r.body.len());
    // The whole body takes 1.5 s; the head and the first chunk come with
    // the first pause.
    assert!(r.ttfb < Duration::from_millis(1000), "ttfb {:?}", r.ttfb);
    assert!(r.total >= PAUSE * CHUNKS as u32, "{:?}", r.total);
    let r = hit(s.port, "/slow");
    assert!(r.head.contains("\r\nX-Cache: HIT\r\n"), "{}", r.head);
    assert!(r.body == pattern(CHUNK * CHUNKS), "{} bytes", r.body.len());
    assert_eq!(s.hits("/slow"), 1);
}

/// A response over the old 64 MiB cap is relayed and cached, not a 502,
/// and the worker's memory doesn't hold it.
#[test]
fn m165_large_response_is_cached_without_buffering() {
    let s = setup("big");
    let before = vm_hwm(s.child.0.id());
    let r = get(s.port, "/big");
    assert!(r.head.starts_with("HTTP/1.1 200 "), "{}", r.head);
    assert!(r.head.contains("\r\nX-Cache: MISS\r\n"), "{}", r.head);
    assert_eq!(r.body.len(), BIG);
    let after = vm_hwm(s.child.0.id());
    assert!(
        after < before + 32 * 1024,
        "VmHWM {before} kB before the miss, {after} kB after"
    );
    let r = hit(s.port, "/big");
    assert!(r.head.contains("\r\nX-Cache: HIT\r\n"), "{}", r.head);
    assert!(r.body == pattern(BIG), "{} bytes", r.body.len());
    assert_eq!(s.hits("/big"), 1);
}

/// The client goes away, gets a 304, or asked with HEAD: the body still
/// goes into the cache. An upstream that closes early leaves nothing.
#[test]
fn m165_cache_fills_without_the_client() {
    let s = setup("fill");
    // Gone after the first bytes.
    for target in ["/slow?gone", "/slowlen?gone"] {
        let mut c = TcpStream::connect(("127.0.0.1", s.port)).unwrap();
        c.write_all(format!("GET {target} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
            .unwrap();
        let mut buf = [0u8; 1024];
        assert!(c.read(&mut buf).unwrap() > 0);
        drop(c);
    }
    // A 304 for the client, the body for the cache.
    let r = send(
        s.port,
        "GET /slow?cond HTTP/1.1\r\nHost: x\r\nIf-None-Match: \"v1\"\r\n\
         Connection: close\r\n\r\n",
    );
    assert!(r.head.starts_with("HTTP/1.1 304 "), "{}", r.head);
    assert!(r.ttfb < Duration::from_millis(1000), "ttfb {:?}", r.ttfb);
    // HEAD goes up as a GET (proxy_cache_convert_head).
    let r = send(
        s.port,
        "HEAD /slow?head HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert!(r.head.starts_with("HTTP/1.1 200 "), "{}", r.head);
    assert!(r.body.is_empty());
    for target in ["/slow?gone", "/slowlen?gone", "/slow?cond", "/slow?head"] {
        let r = hit(s.port, target);
        assert!(
            r.head.contains("\r\nX-Cache: HIT\r\n"),
            "{target}: {}",
            r.head
        );
        assert!(
            r.body == pattern(CHUNK * CHUNKS),
            "{target}: {} bytes",
            r.body.len()
        );
        assert_eq!(s.hits(target), 1, "{target}");
    }
    // Cut short: not stored.
    let r = get(s.port, "/cut");
    assert!(r.head.starts_with("HTTP/1.1 200 "), "{}", r.head);
    assert_eq!(r.body.len(), CHUNK);
    let r = get(s.port, "/cut");
    assert!(r.head.contains("\r\nX-Cache: MISS\r\n"), "{}", r.head);
    assert_eq!(s.hits("/cut"), 2);
    let tmp = std::fs::read_dir(s.dir.join("cache"))
        .unwrap()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with(".tmp-"))
        .count();
    assert_eq!(tmp, 0);
}

/// proxy_cache_lock: a second request waits for the first one's file,
/// which is in place only once the relayed body is complete.
#[test]
fn m165_lock_is_held_until_the_file_is_stored() {
    let s = setup("lock");
    let port = s.port;
    let first = thread::spawn(move || get(port, "/slow?lock"));
    thread::sleep(Duration::from_millis(100));
    let second = get(port, "/slow?lock");
    let first = first.join().unwrap();
    for r in [&first, &second] {
        assert!(r.head.starts_with("HTTP/1.1 200 "), "{}", r.head);
        assert!(r.body.len() >= CHUNK * CHUNKS, "{} bytes", r.body.len());
    }
    assert!(
        second.head.contains("\r\nX-Cache: HIT\r\n"),
        "{}",
        second.head
    );
    assert_eq!(s.hits("/slow?lock"), 1);
}

/// A chunked body: its data, and the trailer section.
fn dechunk(mut wire: &[u8]) -> (Vec<u8>, String) {
    let mut body = Vec::new();
    loop {
        let nl = wire.windows(2).position(|w| w == b"\r\n").unwrap();
        let size = usize::from_str_radix(std::str::from_utf8(&wire[..nl]).unwrap(), 16).unwrap();
        wire = &wire[nl + 2..];
        if size == 0 {
            return (body, String::from_utf8_lossy(wire).into_owned());
        }
        body.extend_from_slice(&wire[..size]);
        assert_eq!(&wire[size..size + 2], b"\r\n");
        wire = &wire[size + 2..];
    }
}

/// `add_trailer` on a relayed body: chunked, the trailers rendered once
/// the body is out.
#[test]
fn m165_trailers_follow_a_relayed_body() {
    let s = setup("trailers");
    let whole = pattern(CHUNK * CHUNKS);
    for target in ["/tr/slowlen", "/tr/slow"] {
        let r = get(s.port, target);
        assert!(r.head.starts_with("HTTP/1.1 200 "), "{}", r.head);
        assert!(
            r.head.contains("\r\nTransfer-Encoding: chunked\r\n"),
            "{}",
            r.head
        );
        assert!(!r.head.contains("Content-Length"), "{}", r.head);
        assert!(r.ttfb < Duration::from_millis(1000), "ttfb {:?}", r.ttfb);
        let (body, trailers) = dechunk(&r.body);
        assert!(body == whole, "{target}: {} bytes", body.len());
        assert_eq!(
            trailers,
            format!(
                "X-Length: {}\r\nX-Sent: chunked\r\n\r\n",
                if target.ends_with("len") {
                    whole.len()
                } else {
                    // The wire bytes, chunk framing included.
                    whole.len() + CHUNKS * 9 + 5
                }
            ),
            "{target}"
        );
    }
    // HTTP/1.0: no trailers, the body as it is.
    let r = send(s.port, "GET /tr/slowlen HTTP/1.0\r\nHost: x\r\n\r\n");
    assert!(
        r.head
            .contains(&format!("\r\nContent-Length: {}\r\n", whole.len())),
        "{}",
        r.head
    );
    assert!(r.body == whole);
}

fn ranged(port: u16, target: &str, range: &str) -> Reply {
    send(
        port,
        &format!("GET {target} HTTP/1.1\r\nHost: x\r\nRange: {range}\r\nConnection: close\r\n\r\n"),
    )
}

/// The range filter cuts one range from a relayed body: under
/// `proxy_force_ranges`, and from a cacheable miss, whose whole body
/// still goes into the cache.
#[test]
fn m165_ranges_are_cut_from_the_relay() {
    let s = setup("range");
    let whole = pattern(CHUNK * CHUNKS);
    let len = whole.len();
    for (target, range, start, end) in [
        ("/fr/slowlen", "bytes=100000-199999", 100_000, 200_000),
        ("/fr/slowlen", "bytes=-10", len - 10, len),
        ("/fr/slowlen", "bytes=0-0", 0, 1),
        ("/slowlen?r", "bytes=70000-", 70_000, len),
    ] {
        let r = ranged(s.port, target, range);
        assert!(r.head.starts_with("HTTP/1.1 206 "), "{range}: {}", r.head);
        assert!(
            r.head.contains(&format!(
                "\r\nContent-Range: bytes {start}-{}/{len}\r\n",
                end - 1
            )),
            "{range}: {}",
            r.head
        );
        assert!(
            r.head
                .contains(&format!("\r\nContent-Length: {}\r\n", end - start)),
            "{range}: {}",
            r.head
        );
        assert!(
            r.body == whole[start..end],
            "{range}: {} bytes",
            r.body.len()
        );
        // Relayed: the first byte doesn't wait for the rest.
        if end == 1 {
            assert!(r.total < Duration::from_millis(1000), "{:?}", r.total);
        }
    }
    // Not satisfiable, and several ranges where one is allowed.
    let r = ranged(s.port, "/fr/slowlen", "bytes=999999-");
    assert!(r.head.starts_with("HTTP/1.1 416 "), "{}", r.head);
    let r = ranged(s.port, "/fr/slowlen", "bytes=0-9,20-29");
    assert!(r.head.starts_with("HTTP/1.1 200 "), "{}", r.head);
    assert!(
        r.head.contains("\r\nAccept-Ranges: bytes\r\n"),
        "{}",
        r.head
    );
    assert!(r.body == whole);
    // The miss cut for the client stored the whole body.
    let r = hit(s.port, "/slowlen?r");
    assert!(r.head.contains("\r\nX-Cache: HIT\r\n"), "{}", r.head);
    assert!(r.body == whole, "{} bytes", r.body.len());
    assert_eq!(s.hits("/slowlen?r"), 1);
}

/// Failover and interception are decided on the status line: the body
/// the upstream sends seconds later isn't waited for.
#[test]
fn m165_failover_and_intercept_on_the_header() {
    let s = setup("status");
    for _ in 0..2 {
        let r = get(s.port, "/fo/s502");
        assert!(r.head.starts_with("HTTP/1.1 200 "), "{}", r.head);
        assert_eq!(r.body, b"ok\n");
        assert!(r.total < Duration::from_millis(2000), "{:?}", r.total);
    }
    assert_eq!(s.hits("/s502"), 1);
    let r = get(s.port, "/ic/s404");
    assert!(r.head.starts_with("HTTP/1.1 200 "), "{}", r.head);
    assert_eq!(r.body, b"intercepted\n");
    assert!(r.total < Duration::from_millis(2000), "{:?}", r.total);
}

/// After an X-Accel-Redirect, the target's upstream body is relayed too,
/// with the headers the redirect carries.
#[test]
fn m165_second_pass_is_relayed() {
    let s = setup("xar");
    let r = get(s.port, "/x/xar");
    assert!(r.head.starts_with("HTTP/1.1 200 "), "{}", r.head);
    assert!(
        r.head.contains("\r\nContent-Type: text/x-carried\r\n"),
        "{}",
        r.head
    );
    assert!(!r.head.contains("X-Carried"), "{}", r.head);
    assert!(r.ttfb < Duration::from_millis(1000), "ttfb {:?}", r.ttfb);
    assert!(r.body.len() > CHUNK * CHUNKS, "{} bytes", r.body.len());
    assert_eq!(s.hits("/slow"), 1);
}
