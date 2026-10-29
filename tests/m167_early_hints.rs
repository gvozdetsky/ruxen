//! M167 — `early_hints` (#848): an upstream's 103 Early Hints reaches the
//! client while the final response is still awaited, less the hidden
//! headers, when a condition holds and the client speaks HTTP/1.1.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

struct Server {
    _child: common::KillOnDrop,
    dir: PathBuf,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// HTTP/1.1 backend: a 103 at once, the 200 after `DELAY`; `/only` sends
/// the 103 and closes.
fn backend(listener: TcpListener) {
    std::thread::spawn(move || {
        for conn in listener.incoming().flatten() {
            std::thread::spawn(move || serve(conn));
        }
    });
}

const DELAY: Duration = Duration::from_millis(500);

fn serve(mut conn: TcpStream) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        match conn.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    let head = String::from_utf8_lossy(&buf).into_owned();
    let path = head.split(' ').nth(1).unwrap_or("/").to_string();
    let _ = conn.write_all(
        b"HTTP/1.1 103 Early Hints\r\nLink: </s.css>; rel=preload\r\nServer: up\r\n\
          X-Hide: h\r\n\r\n",
    );
    if path.ends_with("/only") {
        return;
    }
    std::thread::sleep(DELAY);
    let _ = conn
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nSEE-THIS");
}

fn start(conf: String) -> Server {
    let dir = std::env::temp_dir().join(format!("ruxen-m167-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "pid {d}/ruxen.pid;\nerror_log {d}/error.log info;\nevents {{}}\n\
             http {{\naccess_log off;\n{conf}\n}}\n",
            d = dir.display(),
        ),
    )
    .unwrap();
    let mut child = common::KillOnDrop(
        Command::new(env!("CARGO_BIN_EXE_ruxen"))
            .arg("-c")
            .arg(dir.join("nginx.conf"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    common::ports::wait_for_pid_file(&mut child, &dir.join("ruxen.pid"), Duration::from_secs(5));
    Server { _child: child, dir }
}

/// The whole response, and how long the first bytes took.
fn request(port: u16, raw: &str) -> (String, Duration) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let started = Instant::now();
    s.write_all(raw.as_bytes()).unwrap();
    let mut out = Vec::new();
    let mut chunk = [0u8; 4096];
    let mut first = None;
    loop {
        match s.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                first.get_or_insert_with(|| started.elapsed());
                out.extend_from_slice(&chunk[..n]);
            }
        }
    }
    (
        String::from_utf8_lossy(&out).into_owned(),
        first.unwrap_or_default(),
    )
}

fn get(port: u16, path: &str) -> (String, Duration) {
    request(
        port,
        &format!("GET {path} HTTP/1.1\r\nHost: front\r\nConnection: close\r\n\r\n"),
    )
}

#[test]
fn m167_early_hints() {
    let setup = common::ports::setup_lock();
    let up = TcpListener::bind("127.0.0.1:0").unwrap();
    let up_port = up.local_addr().unwrap().port();
    backend(up);
    let [front, h2c] = common::ports::free_ports();
    let _s = start(format!(
        "server {{ listen 127.0.0.1:{front};\n\
           early_hints 1; proxy_hide_header X-Hide;\n\
           location / {{ proxy_pass http://127.0.0.1:{up_port};\n\
             location /off/ {{ proxy_pass http://127.0.0.1:{up_port}; early_hints 0; }} }}\n\
           location /var/ {{ proxy_pass http://127.0.0.1:{up_port}; early_hints $arg_h; }}\n\
           location /abort/ {{ proxy_pass http://127.0.0.1:{up_port};\n\
             proxy_ignore_client_abort on; }}\n\
           location /h2/ {{ proxy_pass http://127.0.0.1:{h2c}/; proxy_http_version 2; }} }}\n\
         server {{ listen 127.0.0.1:{h2c}; http2 on; early_hints 1;\n\
           location / {{ proxy_pass http://127.0.0.1:{up_port}; }} }}",
    ));
    drop(setup);

    // The 103 goes out before the 200 is in, without the hidden headers.
    // `/h2/`: an HTTP/2 upstream, whose 103 came to it from an HTTP/2
    // client (both sides of HTTP/2).
    for path in ["/", "/abort/", "/var/?h=1", "/h2/"] {
        let (out, first) = get(front, path);
        assert!(
            out.to_ascii_lowercase().starts_with(
                "http/1.1 103 early hints\r\nlink: </s.css>; rel=preload\r\n\r\nhttp/1.1 200 ok\r\n"
            ),
            "{path}: {out}"
        );
        assert!(out.ends_with("SEE-THIS"), "{path}: {out}");
        assert!(
            first < DELAY - Duration::from_millis(100),
            "{path}: {first:?}"
        );
    }
    // Off, a condition that doesn't hold, HTTP/1.0: none.
    for (path, version) in [
        ("/off/", "1.1"),
        ("/var/?h=0", "1.1"),
        ("/var/", "1.1"),
        ("/", "1.0"),
    ] {
        let (out, _) = request(
            front,
            &format!("GET {path} HTTP/{version}\r\nHost: front\r\nConnection: close\r\n\r\n"),
        );
        assert!(
            out.starts_with("HTTP/1.1 200 OK\r\n"),
            "{path} {version}: {out}"
        );
    }
    // Only the 103: a 502 after it.
    let (out, _) = get(front, "/only");
    assert!(out.starts_with("HTTP/1.1 103 Early Hints\r\n"), "{out}");
    assert!(
        out.contains("\r\n\r\nHTTP/1.1 502 Bad Gateway\r\n"),
        "{out}"
    );
}
