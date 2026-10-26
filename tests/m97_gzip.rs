//! M97 — the gzip filter (#93): what nginx compresses and how, for static
//! files (whole and streamed), `return`, and proxied responses.

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

struct Server {
    child: Child,
    dir: PathBuf,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn start() -> (Server, u16) {
    let dir = std::env::temp_dir().join(format!("ruxen-m97-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("www")).unwrap();
    std::fs::write(dir.join("www/index.html"), "X".repeat(64)).unwrap();
    std::fs::write(dir.join("www/tiny.html"), "short").unwrap();
    std::fs::write(dir.join("www/pic.png"), "P".repeat(500)).unwrap();
    // Big enough to go out through the streamed (sendfile-path) branch.
    let big: String = (0..200_000)
        .map(|i| ["alpha ", "beta ", "gamma "][i % 3])
        .collect();
    std::fs::write(dir.join("www/big.css"), big).unwrap();
    // Held until ruxen listens: released earlier, another test could take
    // the same free port, and ruxen would fail to bind it.
    let setup = common::ports::setup_lock();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let conf = dir.join("ruxen.conf");
    std::fs::write(
        &conf,
        format!(
            "events {{}}\nhttp {{\n access_log off;\n sendfile on;\n gzip_types text/css;\n types {{ text/css css; text/html html; }}\n \
             server {{\n listen 127.0.0.1:{port};\n \
             location / {{ gzip on; gzip_vary on; root {www}; }}\n \
             location /ret {{ gzip on; default_type text/plain; gzip_types text/plain; \
             return 200 \"{body}\"; }}\n \
             location /proxy/ {{ gzip on; proxy_pass http://127.0.0.1:{port}/local/; }}\n \
             location /relay/ {{ gzip on; proxy_pass http://127.0.0.1:{port}/local/; }}\n \
             location /local/ {{ alias {www}/; }}\n }}\n}}\n",
            www = dir.join("www").display(),
            body = "one ".repeat(30),
        ),
    )
    .unwrap();
    // Owned by `Server` before the wait: if it panics, ruxen still stops.
    let mut server = Server {
        child: Command::new(env!("CARGO_BIN_EXE_ruxen"))
            .args(["-c", conf.to_str().unwrap()])
            .arg("-g")
            .arg(format!("pid {}/ruxen.pid;", dir.display()))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
        dir,
    };
    let pid_file = server.dir.join("ruxen.pid");
    common::ports::wait_for_pid_file(&mut server.child, &pid_file, Duration::from_secs(5));
    drop(setup);
    (server, port)
}

/// One request with `Connection: close`; returns (header block, body).
fn get(port: u16, path: &str, extra: &str, version: &str) -> (String, Vec<u8>) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(
        s,
        "GET {path} HTTP/{version}\r\nHost: t\r\nConnection: close\r\n{extra}\r\n"
    )
    .unwrap();
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).unwrap();
    let end = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    (
        String::from_utf8_lossy(&raw[..end]).into_owned(),
        raw[end + 4..].to_vec(),
    )
}

fn dechunk(mut body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let line_end = body.windows(2).position(|w| w == b"\r\n").unwrap();
        let size =
            usize::from_str_radix(std::str::from_utf8(&body[..line_end]).unwrap(), 16).unwrap();
        body = &body[line_end + 2..];
        if size == 0 {
            return out;
        }
        out.extend_from_slice(&body[..size]);
        body = &body[size + 2..];
    }
}

fn gunzip(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(data)
        .read_to_end(&mut out)
        .unwrap();
    out
}

const GZ: &str = "Accept-Encoding: gzip, deflate\r\n";

#[test]
fn m97_gzip_like_nginx() {
    let (_server, port) = start();

    // A small static file: compressed whole, and sent without a length,
    // as nginx's gzip filter drops it: chunked (proxy_cache.t).
    let (head, body) = get(port, "/", GZ, "1.1");
    assert!(head.contains("Content-Encoding: gzip"), "{head}");
    assert!(head.contains("Vary: Accept-Encoding"), "{head}");
    assert!(!head.contains("Accept-Ranges"), "{head}");
    assert!(head.contains("ETag: W/\""), "{head}");
    assert!(head.contains("Transfer-Encoding: chunked"), "{head}");
    assert!(!head.contains("Content-Length"), "{head}");
    assert_eq!(gunzip(&dechunk(&body)), b"X".repeat(64));

    // Without Accept-Encoding: as it was, plus Vary.
    let (head, body) = get(port, "/", "", "1.1");
    assert!(!head.contains("Content-Encoding"), "{head}");
    assert!(head.contains("Vary: Accept-Encoding"), "{head}");
    assert_eq!(body, b"X".repeat(64));

    // Under gzip_min_length (20) and a type not in gzip_types: as they were.
    for path in ["/tiny.html", "/pic.png"] {
        let (head, _) = get(port, path, GZ, "1.1");
        assert!(!head.contains("Content-Encoding"), "{path}: {head}");
    }

    // A big file is compressed as it is sent, in chunks.
    let (head, body) = get(port, "/big.css", GZ, "1.1");
    assert!(head.contains("Transfer-Encoding: chunked"), "{head}");
    assert!(!head.contains("Content-Length"), "{head}");
    let expected: Vec<u8> = (0..200_000)
        .flat_map(|i| ["alpha ", "beta ", "gamma "][i % 3].bytes())
        .collect();
    assert_eq!(gunzip(&dechunk(&body)), expected);

    // A Range on a file gzip compresses: the whole file, 200.
    let (head, body) = get(
        port,
        "/big.css",
        &format!("{GZ}Range: bytes=0-9\r\n"),
        "1.1",
    );
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(gunzip(&dechunk(&body)), expected);
    let (head, _) = get(port, "/big.css", "Range: bytes=0-9\r\n", "1.1");
    assert!(head.starts_with("HTTP/1.1 206"), "{head}");

    // HTTP/1.0: gzip_http_version is 1.1 by default.
    let (head, _) = get(port, "/big.css", GZ, "1.0");
    assert!(!head.contains("Content-Encoding"), "{head}");

    // `return` and a proxied response.
    let (head, body) = get(port, "/ret", GZ, "1.1");
    assert!(head.contains("Content-Encoding: gzip"), "{head}");
    assert_eq!(gunzip(&dechunk(&body)), "one ".repeat(30).into_bytes());
    let (head, body) = get(port, "/proxy/index.html", GZ, "1.1");
    assert!(head.contains("Content-Encoding: gzip"), "{head}");
    assert_eq!(gunzip(&dechunk(&body)), b"X".repeat(64));
    // A proxied body too big to come with the head is relayed as it
    // arrives, and compressed on the way (#88): chunked, no length.
    let (head, body) = get(port, "/relay/big.css", GZ, "1.1");
    assert!(head.contains("Content-Encoding: gzip"), "{head}");
    assert!(head.contains("Transfer-Encoding: chunked"), "{head}");
    assert!(!head.contains("Content-Length"), "{head}");
    assert_eq!(gunzip(&dechunk(&body)), expected);
    // Not to a client that doesn't ask for it.
    let (head, body) = get(port, "/relay/big.css", "", "1.1");
    assert!(!head.contains("Content-Encoding"), "{head}");
    assert!(
        head.contains(&format!("Content-Length: {}", expected.len())),
        "{head}"
    );
    assert_eq!(body, expected);

    // q=0 refuses gzip.
    let (head, _) = get(port, "/", "Accept-Encoding: gzip;q=0\r\n", "1.1");
    assert!(!head.contains("Content-Encoding"), "{head}");

    // A range of a file gzip would take, to a client that doesn't ask for
    // gzip: a 206 with `Vary`, as nginx's gzip filter saw the whole 200
    // first. Small (in memory) and big (streamed), one range and several.
    for (path, range) in [("/", "0-3"), ("/big.css", "0-3"), ("/big.css", "0-3,10-20")] {
        let (head, _) = get(port, path, &format!("Range: bytes={range}\r\n"), "1.1");
        assert!(head.starts_with("HTTP/1.1 206"), "{head}");
        assert_eq!(head.matches("Vary: Accept-Encoding").count(), 1, "{head}");
    }
    // An unsatisfiable range: the 416 carries it too.
    for path in ["/", "/big.css"] {
        let (head, _) = get(port, path, "Range: bytes=99999999-\r\n", "1.1");
        assert!(head.starts_with("HTTP/1.1 416"), "{head}");
        assert_eq!(head.matches("Vary: Accept-Encoding").count(), 1, "{head}");
    }
    // Not for a type gzip doesn't take.
    let (head, _) = get(port, "/pic.png", "Range: bytes=0-3\r\n", "1.1");
    assert!(head.starts_with("HTTP/1.1 206"), "{head}");
    assert!(!head.contains("Vary"), "{head}");
}
