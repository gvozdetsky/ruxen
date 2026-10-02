//! M45 — `sendfile on` sends file bodies zero-copy on plain TCP. The wire
//! bytes must be identical to the copying path: full bodies around the
//! inline / zero-copy thresholds, several responses on one keep-alive
//! connection, pipelined requests, ranges, HEAD, and TLS (which can't use
//! sendfile and must fall back).

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, MutexGuard};
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
        "ruxen-m45-{}-{}",
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
            panic!("ruxen did not start listening on port {port}");
        }
        sleep(Duration::from_millis(20));
    }
}

/// Deterministic, non-repeating-looking content so offset bugs show up.
fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| ((i * 31 + seed as usize) % 251) as u8).collect()
}

const SIZES: &[usize] = &[
    1,
    4095,
    4096,
    8192,
    8193,
    65_536,
    3_000_001,
];

fn spawn(conf_body: impl Fn(u16, &Path) -> String) -> (ServerGuard, u16, PathBuf) {
    let (port, _lock) = pick_port();
    let dir = unique_dir();
    for (i, &len) in SIZES.iter().enumerate() {
        std::fs::write(dir.join(format!("f{len}.bin")), pattern(len, i as u8)).unwrap();
    }
    let conf_path = dir.join("ruxen.conf");
    std::fs::write(&conf_path, conf_body(port, &dir)).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .args(["-c", conf_path.to_str().unwrap()])
        .env("RUXEN_WORKERS", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ruxen");
    wait_for_listen(port);
    (ServerGuard { child, dir: dir.clone() }, port, dir)
}

fn plain_conf(sendfile: &'static str) -> impl Fn(u16, &Path) -> String {
    move |port, dir| {
        format!(
            "pid {d}/ruxen.pid;\nevents {{}}\nhttp {{\n  access_log off;\n  sendfile {sendfile};\n  server {{\n    listen 127.0.0.1:{port};\n    root {d};\n  }}\n}}\n",
            d = dir.display()
        )
    }
}

/// Read one HTTP/1.1 response framed by Content-Length (or header-only for
/// HEAD / 304) off `stream`, consuming exactly its bytes.
fn read_response(stream: &mut TcpStream, pending: &mut Vec<u8>, head_only: bool) -> (String, Vec<u8>) {
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
            k.eq_ignore_ascii_case("content-length").then(|| v.trim().parse().unwrap())
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

fn get_all_on_one_connection(port: u16, dir: &Path) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut pending = Vec::new();
    for &len in SIZES {
        write!(stream, "GET /f{len}.bin HTTP/1.1\r\nHost: t\r\n\r\n").unwrap();
        let (head, body) = read_response(&mut stream, &mut pending, false);
        assert!(head.starts_with("HTTP/1.1 200"), "{len}: {head}");
        assert!(head.contains("Connection: keep-alive"), "{len}: {head}");
        let expected = std::fs::read(dir.join(format!("f{len}.bin"))).unwrap();
        assert!(body == expected, "body mismatch for {len} bytes");
    }
}

#[test]
fn sendfile_on_serves_identical_bytes_over_keepalive() {
    let (_g, port, dir) = spawn(plain_conf("on"));
    get_all_on_one_connection(port, &dir);
}

#[test]
fn sendfile_off_serves_identical_bytes_over_keepalive() {
    let (_g, port, dir) = spawn(plain_conf("off"));
    get_all_on_one_connection(port, &dir);
}

#[test]
fn sendfile_on_handles_pipelining_ranges_and_head() {
    let (_g, port, dir) = spawn(plain_conf("on"));
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    // Three requests in one write: two full bodies above the zero-copy
    // threshold, then a range from the middle of the large file.
    stream
        .write_all(
            b"GET /f8192.bin HTTP/1.1\r\nHost: t\r\n\r\n\
              GET /f65536.bin HTTP/1.1\r\nHost: t\r\n\r\n\
              GET /f3000001.bin HTTP/1.1\r\nHost: t\r\nRange: bytes=1000000-1009999\r\n\r\n\
              HEAD /f65536.bin HTTP/1.1\r\nHost: t\r\n\r\n",
        )
        .unwrap();
    let mut pending = Vec::new();

    let (h, b) = read_response(&mut stream, &mut pending, false);
    assert!(h.starts_with("HTTP/1.1 200"), "{h}");
    assert!(b == std::fs::read(dir.join("f8192.bin")).unwrap());

    let (h, b) = read_response(&mut stream, &mut pending, false);
    assert!(h.starts_with("HTTP/1.1 200"), "{h}");
    assert!(b == std::fs::read(dir.join("f65536.bin")).unwrap());

    let (h, b) = read_response(&mut stream, &mut pending, false);
    assert!(h.starts_with("HTTP/1.1 206"), "{h}");
    assert!(h.contains("Content-Range: bytes 1000000-1009999/3000001"), "{h}");
    let full = std::fs::read(dir.join("f3000001.bin")).unwrap();
    assert!(b == full[1_000_000..1_010_000]);

    let (h, b) = read_response(&mut stream, &mut pending, true);
    assert!(h.starts_with("HTTP/1.1 200"), "{h}");
    assert!(h.contains("Content-Length: 65536"), "{h}");
    assert!(b.is_empty());
}

#[test]
fn sendfile_on_over_tls_falls_back_to_copying() {
    let certs = common::tls::make_self_signed("localhost");
    let (cert, key) = (certs.cert_path().to_path_buf(), certs.key_path().to_path_buf());
    let (_g, port, dir) = spawn(move |port, dir| {
        format!(
            "pid {d}/ruxen.pid;\nevents {{}}\nhttp {{\n  access_log off;\n  sendfile on;\n  server {{\n    listen 127.0.0.1:{port} ssl;\n    ssl_certificate {c};\n    ssl_certificate_key {k};\n    root {d};\n  }}\n}}\n",
            d = dir.display(),
            c = cert.display(),
            k = key.display(),
        )
    });
    for len in [8192usize, 3_000_001] {
        let out = Command::new("curl")
            .args(["-sk", "--max-time", "10"])
            .arg(format!("https://127.0.0.1:{port}/f{len}.bin"))
            .output()
            .expect("run curl");
        assert!(out.status.success(), "curl failed for {len}");
        assert!(out.stdout == std::fs::read(dir.join(format!("f{len}.bin"))).unwrap());
    }
}

#[test]
fn stalled_reader_does_not_block_the_worker() {
    // One worker. Client A asks for 3 MB and stops reading, so sendfile hits
    // EAGAIN once the socket buffers fill. The worker must keep serving
    // client B meanwhile, then finish A's body intact once A drains.
    let (_g, port, dir) = spawn(plain_conf("on"));
    let mut slow = TcpStream::connect(("127.0.0.1", port)).unwrap();
    slow.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    slow.write_all(b"GET /f3000001.bin HTTP/1.1\r\nHost: t\r\n\r\n").unwrap();
    sleep(Duration::from_millis(200));

    let started = Instant::now();
    let mut fast = TcpStream::connect(("127.0.0.1", port)).unwrap();
    fast.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    fast.write_all(b"GET /f8192.bin HTTP/1.1\r\nHost: t\r\n\r\n").unwrap();
    let mut pending = Vec::new();
    let (h, b) = read_response(&mut fast, &mut pending, false);
    assert!(h.starts_with("HTTP/1.1 200"), "{h}");
    assert!(b == std::fs::read(dir.join("f8192.bin")).unwrap());
    assert!(started.elapsed() < Duration::from_secs(1), "worker was blocked");

    let mut pending = Vec::new();
    let (h, b) = read_response(&mut slow, &mut pending, false);
    assert!(h.starts_with("HTTP/1.1 200"), "{h}");
    assert!(b == std::fs::read(dir.join("f3000001.bin")).unwrap());
}
