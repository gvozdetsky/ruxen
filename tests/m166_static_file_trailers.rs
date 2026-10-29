//! M166 — `add_trailer` on a static file too big to be read into the
//! response (#844): sent chunked from the file with the trailers, as
//! nginx's chunked filter does, whatever the send path.

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

struct Server {
    child: Child,
    dir: PathBuf,
    _certs: common::tls::CertSet,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

const LARGE: usize = 300_000;

fn start() -> (Server, u16, u16) {
    let setup_lock = common::ports::setup_lock();
    let [port, tls_port] = common::ports::free_ports();
    static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("ruxen-m166-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("html")).unwrap();
    std::fs::write(dir.join("html/small"), "a".repeat(100)).unwrap();
    std::fs::write(dir.join("html/large"), "b".repeat(LARGE)).unwrap();
    std::fs::write(dir.join("html/large.txt"), "c".repeat(LARGE)).unwrap();
    let certs = common::tls::make_self_signed("localhost");
    let d = dir.display();
    let trailer = "add_trailer X-V \"$uri $status $sent_http_accept_ranges $host\";";
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "pid {d}/ruxen.pid;\nevents {{}}\nhttp {{ access_log off; {trailer}\n\
             server {{ listen 127.0.0.1:{port}; http2 on; root {d}/html;\n\
               location /sf/ {{ alias {d}/html/; sendfile on; }}\n\
               location /gz/ {{ alias {d}/html/; gzip on; gzip_types text/plain;\n\
                 gzip_min_length 0; }}\n\
               location /rate/ {{ alias {d}/html/; limit_rate 4m; }}\n\
             }}\n\
             server {{ listen 127.0.0.1:{tls_port} ssl; http2 on; root {d}/html;\n\
               ssl_certificate {}; ssl_certificate_key {}; }} }}\n",
            certs.cert_path().display(),
            certs.key_path().display(),
        ),
    )
    .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .arg("-c")
        .arg(dir.join("nginx.conf"))
        .env("RUXEN_WORKERS", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    common::ports::wait_for_pid_file(&mut child, &dir.join("ruxen.pid"), Duration::from_secs(5));
    drop(setup_lock);
    let server = Server {
        child,
        dir,
        _certs: certs,
    };
    (server, port, tls_port)
}

/// One response off `stream`: its head, its body (chunks decoded) and its
/// trailer block.
fn read_response(stream: &mut TcpStream, pending: &mut Vec<u8>) -> (String, Vec<u8>, String) {
    fn fill(stream: &mut TcpStream, pending: &mut Vec<u8>, need: usize) {
        let mut buf = [0u8; 65_536];
        while pending.len() < need {
            let n = stream.read(&mut buf).unwrap();
            assert!(n > 0, "closed early");
            pending.extend_from_slice(&buf[..n]);
        }
    }
    fn line(stream: &mut TcpStream, pending: &mut Vec<u8>) -> Vec<u8> {
        loop {
            if let Some(i) = pending.windows(2).position(|w| w == b"\r\n") {
                let l = pending[..i].to_vec();
                pending.drain(..i + 2);
                return l;
            }
            let need = pending.len() + 1;
            fill(stream, pending, need);
        }
    }
    let mut head = String::new();
    loop {
        let l = String::from_utf8(line(stream, pending)).unwrap();
        if l.is_empty() {
            break;
        }
        head.push_str(&l);
        head.push_str("\r\n");
    }
    let mut body = Vec::new();
    let mut trailers = String::new();
    if head.contains("Transfer-Encoding: chunked") {
        loop {
            let size = String::from_utf8(line(stream, pending)).unwrap();
            let size = usize::from_str_radix(size.trim(), 16).unwrap();
            if size == 0 {
                break;
            }
            fill(stream, pending, size + 2);
            body.extend_from_slice(&pending[..size]);
            pending.drain(..size + 2);
        }
        loop {
            let l = String::from_utf8(line(stream, pending)).unwrap();
            if l.is_empty() {
                break;
            }
            trailers.push_str(&l);
            trailers.push_str("\r\n");
        }
    } else if let Some(len) = head
        .lines()
        .find_map(|l| l.strip_prefix("Content-Length: "))
    {
        let len: usize = len.parse().unwrap();
        if !head.starts_with("HEAD") {
            fill(stream, pending, len);
            body = pending.drain(..len).collect();
        }
    }
    (head, body, trailers)
}

fn gunzip(data: &[u8], dir: &Path) -> Vec<u8> {
    let path = dir.join("gz.bin");
    std::fs::write(&path, data).unwrap();
    let out = Command::new("gzip").arg("-dc").arg(&path).output().unwrap();
    assert!(out.status.success());
    out.stdout
}

#[test]
fn large_files_carry_their_trailers_on_every_send_path() {
    let (server, port, _) = start();
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut pending = Vec::new();
    // Pipelined on one connection: each chunked response ends where the
    // next begins.
    let paths = [
        "/small",
        "/large",
        "/sf/large",
        "/rate/large",
        "/gz/large.txt",
    ];
    let mut req = String::new();
    for p in paths {
        let gz = if p.starts_with("/gz/") {
            "Accept-Encoding: gzip\r\n"
        } else {
            ""
        };
        req.push_str(&format!("GET {p} HTTP/1.1\r\nHost: localhost\r\n{gz}\r\n"));
    }
    stream.write_all(req.as_bytes()).unwrap();
    for p in paths {
        let (head, body, trailers) = read_response(&mut stream, &mut pending);
        assert!(head.starts_with("HTTP/1.1 200"), "{p}: {head}");
        assert!(!head.contains("Content-Length"), "{p}: {head}");
        // gzip drops Accept-Ranges.
        let (body, ranges) = match p {
            "/gz/large.txt" => (gunzip(&body, &server.dir), ""),
            _ => (body, "bytes"),
        };
        let expect = match p {
            "/small" => "a".repeat(100),
            "/gz/large.txt" => "c".repeat(LARGE),
            _ => "b".repeat(LARGE),
        };
        assert!(body == expect.as_bytes(), "{p}: {} bytes", body.len());
        assert_eq!(
            trailers,
            format!("X-V: {p} 200 {ranges} localhost\r\n"),
            "{p}"
        );
    }

    // No trailers without chunks: HEAD, HTTP/1.0.
    for req in [
        "HEAD /large HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        "GET /large HTTP/1.0\r\nHost: localhost\r\n\r\n",
    ] {
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        s.write_all(req.as_bytes()).unwrap();
        let mut out = Vec::new();
        let _ = s.read_to_end(&mut out);
        let out = String::from_utf8_lossy(&out);
        assert!(
            out.contains(&format!("Content-Length: {LARGE}\r\n")),
            "{req}: {out}"
        );
        assert!(!out.contains("X-V"), "{req}: {out}");
    }
}

/// curl's header output: the head, then the trailers.
fn curl(args: &[&str]) -> (String, usize) {
    let out = Command::new("curl")
        .args([
            "-s",
            "-k",
            "-D",
            "-",
            "-o",
            "/dev/null",
            "-w",
            "%{size_download}",
        ])
        .args(args)
        .output()
        .unwrap();
    assert!(out.status.success(), "{args:?}");
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let (headers, size) = text.rsplit_once("\r\n").unwrap();
    (headers.to_ascii_lowercase(), size.parse().unwrap())
}

#[test]
fn large_files_carry_their_trailers_over_http2_and_tls() {
    let (_server, port, tls_port) = start();
    let h2c = format!("http://127.0.0.1:{port}/large");
    let tls = format!("https://127.0.0.1:{tls_port}/large");
    for args in [
        vec!["--http2-prior-knowledge", h2c.as_str()],
        vec!["--http1.1", tls.as_str()],
        vec!["--http2", tls.as_str()],
    ] {
        let (headers, size) = curl(&args);
        assert_eq!(size, LARGE, "{args:?}");
        assert!(
            headers.contains("x-v: /large 200 bytes 127.0.0.1"),
            "{args:?}: {headers}"
        );
    }
}
