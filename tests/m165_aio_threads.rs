//! `aio threads` (#526): file bodies read, and sent with `sendfile`, on a
//! thread pool. The bytes must be those of the worker's own reads on every
//! path (inline, sendfile, streamed, ranges, gzip, `limit_rate`, TLS,
//! HTTP/2), on both drivers; a slow reader doesn't block the worker.
//! A slow disk (the issue's FUSE repro) is checked by hand: see the PR.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::MutexGuard;
use std::thread::sleep;
use std::time::{Duration, Instant};

struct ServerGuard {
    child: Child,
    dir: PathBuf,
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
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
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "ruxen-m165-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir(&dir).unwrap();
    dir
}

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| ((i * 31 + seed as usize) % 251) as u8)
        .collect()
}

const SIZES: &[usize] = &[1, 4095, 4096, 8192, 8193, 65_536, 3_000_001];

/// `aio threads` everywhere; `sendfile` as given. `/d/` uses the default
/// pool, the rest `io` (two threads).
fn conf(sendfile: &'static str) -> impl Fn(u16, &Path) -> String {
    move |port, dir| {
        format!(
            "pid {d}/ruxen.pid;\nthread_pool io threads=2 max_queue=100;\nevents {{}}\n\
             http {{\n  access_log off;\n  sendfile {sendfile};\n  aio threads=io;\n\
               server {{\n    listen 127.0.0.1:{port};\n    http2 on;\n    root {d};\n\
                 location /d/ {{ alias {d}/; aio threads; }}\n\
                 location /gz/ {{ alias {d}/; gzip on; gzip_types application/octet-stream; }}\n\
                 location /slow/ {{ alias {d}/; limit_rate 2m; }}\n\
               }}\n}}\n",
            d = dir.display()
        )
    }
}

fn spawn_with(
    conf_body: impl Fn(u16, &Path) -> String,
    driver: Option<&str>,
) -> (ServerGuard, u16, PathBuf) {
    let (port, _lock) = pick_port();
    let dir = unique_dir();
    for (i, &len) in SIZES.iter().enumerate() {
        std::fs::write(dir.join(format!("f{len}.bin")), pattern(len, i as u8)).unwrap();
    }
    let conf_path = dir.join("ruxen.conf");
    std::fs::write(&conf_path, conf_body(port, &dir)).unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ruxen"));
    cmd.args(["-c", conf_path.to_str().unwrap()])
        .env("RUXEN_WORKERS", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(driver) = driver {
        cmd.env("RUXEN_DRIVER", driver);
    }
    let child = cmd.spawn().expect("spawn ruxen");
    let mut guard = ServerGuard {
        child,
        dir: dir.clone(),
    };
    common::ports::wait_for_pid_file(
        &mut guard.child,
        &dir.join("ruxen.pid"),
        Duration::from_secs(5),
    );
    (guard, port, dir)
}

/// One HTTP/1.1 response framed by Content-Length (none for HEAD).
fn read_response(
    stream: &mut TcpStream,
    pending: &mut Vec<u8>,
    head_only: bool,
) -> (String, Vec<u8>) {
    let mut buf = [0u8; 65_536];
    let head_end = loop {
        if let Some(i) = pending.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        let n = stream.read(&mut buf).expect("read head");
        assert!(n > 0, "connection closed before response head");
        pending.extend_from_slice(&buf[..n]);
    };
    let head = String::from_utf8(pending[..head_end].to_vec()).unwrap();
    let len: usize = head
        .lines()
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.eq_ignore_ascii_case("content-length")
                .then(|| v.trim().parse().unwrap())
        })
        .unwrap_or(0);
    let body_len = if head_only { 0 } else { len };
    while pending.len() < head_end + body_len {
        let n = stream.read(&mut buf).expect("read body");
        assert!(n > 0, "connection closed mid-body");
        pending.extend_from_slice(&buf[..n]);
    }
    let body = pending[head_end..head_end + body_len].to_vec();
    pending.drain(..head_end + body_len);
    (head, body)
}

/// Every size under `prefix`, on one keep-alive connection, then a range,
/// several ranges and a HEAD, pipelined.
fn check_http1(port: u16, dir: &Path, prefix: &str) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut pending = Vec::new();
    for &len in SIZES {
        write!(stream, "GET {prefix}f{len}.bin HTTP/1.1\r\nHost: t\r\n\r\n").unwrap();
        let (head, body) = read_response(&mut stream, &mut pending, false);
        assert!(head.starts_with("HTTP/1.1 200"), "{len}: {head}");
        assert!(head.contains("Connection: keep-alive"), "{len}: {head}");
        let expected = std::fs::read(dir.join(format!("f{len}.bin"))).unwrap();
        assert!(body == expected, "{prefix}: body mismatch for {len} bytes");
    }
    write!(
        stream,
        "GET {prefix}f3000001.bin HTTP/1.1\r\nHost: t\r\nRange: bytes=1000000-1009999\r\n\r\n\
         GET {prefix}f65536.bin HTTP/1.1\r\nHost: t\r\nRange: bytes=10-19\r\n\r\n\
         HEAD {prefix}f65536.bin HTTP/1.1\r\nHost: t\r\n\r\n"
    )
    .unwrap();
    let full = std::fs::read(dir.join("f3000001.bin")).unwrap();
    let (h, b) = read_response(&mut stream, &mut pending, false);
    assert!(h.starts_with("HTTP/1.1 206"), "{h}");
    assert!(b == full[1_000_000..1_010_000]);
    let (h, b) = read_response(&mut stream, &mut pending, false);
    assert!(h.starts_with("HTTP/1.1 206"), "{h}");
    assert!(b == std::fs::read(dir.join("f65536.bin")).unwrap()[10..20]);
    let (h, b) = read_response(&mut stream, &mut pending, true);
    assert!(h.contains("Content-Length: 65536"), "{h}");
    assert!(b.is_empty());
}

fn curl(args: &[&str]) -> Vec<u8> {
    let out = Command::new("curl")
        .args(["-s", "--fail", "--max-time", "20"])
        .args(args)
        .output()
        .expect("run curl");
    assert!(out.status.success(), "curl {args:?} failed");
    out.stdout
}

#[test]
fn sendfile_on_serves_identical_bytes() {
    let (_g, port, dir) = spawn_with(conf("on"), None);
    check_http1(port, &dir, "/");
    check_http1(port, &dir, "/d/");
}

#[test]
fn sendfile_off_serves_identical_bytes() {
    let (_g, port, dir) = spawn_with(conf("off"), None);
    check_http1(port, &dir, "/");
    check_http1(port, &dir, "/d/");
}

#[test]
fn epoll_driver_serves_identical_bytes() {
    for sendfile in ["on", "off"] {
        let (_g, port, dir) = spawn_with(conf(sendfile), Some("epoll"));
        check_http1(port, &dir, "/");
    }
}

#[test]
fn gzip_limit_rate_and_http2_read_on_the_pool() {
    let (_g, port, dir) = spawn_with(conf("on"), None);
    for &len in &[8192usize, 65_536, 3_000_001] {
        let expected = std::fs::read(dir.join(format!("f{len}.bin"))).unwrap();
        let gz = curl(&[
            "--compressed",
            &format!("http://127.0.0.1:{port}/gz/f{len}.bin"),
        ]);
        assert!(gz == expected, "gzip: {len}");
        let h2 = curl(&[
            "--http2-prior-knowledge",
            &format!("http://127.0.0.1:{port}/f{len}.bin"),
        ]);
        assert!(h2 == expected, "h2: {len}");
    }
    for &len in &[4095usize, 65_536] {
        let expected = std::fs::read(dir.join(format!("f{len}.bin"))).unwrap();
        let paced = curl(&[&format!("http://127.0.0.1:{port}/slow/f{len}.bin")]);
        assert!(paced == expected, "limit_rate: {len}");
    }
}

#[test]
fn tls_reads_on_the_pool() {
    let certs = common::tls::make_self_signed("localhost");
    let (cert, key) = (
        certs.cert_path().to_path_buf(),
        certs.key_path().to_path_buf(),
    );
    let (_g, port, dir) = spawn_with(
        move |port, dir| {
            format!(
                "pid {d}/ruxen.pid;\nevents {{}}\nhttp {{\n  access_log off;\n  sendfile on;\n  \
                 aio threads;\n  server {{\n    listen 127.0.0.1:{port} ssl;\n    http2 on;\n    \
                 ssl_certificate {c};\n    ssl_certificate_key {k};\n    root {d};\n  }}\n}}\n",
                d = dir.display(),
                c = cert.display(),
                k = key.display(),
            )
        },
        None,
    );
    for &len in &[4095usize, 8193, 3_000_001] {
        let expected = std::fs::read(dir.join(format!("f{len}.bin"))).unwrap();
        for proto in ["--http1.1", "--http2"] {
            let got = curl(&["-k", proto, &format!("https://127.0.0.1:{port}/f{len}.bin")]);
            assert!(got == expected, "{proto}: {len}");
        }
    }
}

#[test]
fn stalled_reader_does_not_block_the_worker() {
    // Client A takes 3 MB and stops reading: the pool's `sendfile` gets
    // EAGAIN and the worker waits for room. Client B is served meanwhile;
    // then A's body arrives whole.
    let (_g, port, dir) = spawn_with(conf("on"), None);
    let mut slow = TcpStream::connect(("127.0.0.1", port)).unwrap();
    slow.set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    slow.write_all(b"GET /f3000001.bin HTTP/1.1\r\nHost: t\r\n\r\n")
        .unwrap();
    sleep(Duration::from_millis(200));

    let started = Instant::now();
    let mut fast = TcpStream::connect(("127.0.0.1", port)).unwrap();
    fast.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    fast.write_all(b"GET /f8192.bin HTTP/1.1\r\nHost: t\r\n\r\n")
        .unwrap();
    let mut pending = Vec::new();
    let (h, b) = read_response(&mut fast, &mut pending, false);
    assert!(h.starts_with("HTTP/1.1 200"), "{h}");
    assert!(b == std::fs::read(dir.join("f8192.bin")).unwrap());
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "worker was blocked"
    );

    let mut pending = Vec::new();
    let (h, b) = read_response(&mut slow, &mut pending, false);
    assert!(h.starts_with("HTTP/1.1 200"), "{h}");
    assert!(b == std::fs::read(dir.join("f3000001.bin")).unwrap());
}

#[test]
fn an_undefined_pool_is_refused_with_its_place() {
    let dir = unique_dir();
    let conf = dir.join("nginx.conf");
    std::fs::write(
        &conf,
        "events {}\nhttp {\n  server {\n    listen 127.0.0.1:1;\n    aio threads=nope;\n  }\n}\n",
    )
    .unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .arg("-t")
        .arg("-c")
        .arg(&conf)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{stderr}");
    assert!(
        stderr.contains(&format!(
            "unknown thread pool \"nope\" in {}:5",
            conf.display()
        )),
        "{stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
