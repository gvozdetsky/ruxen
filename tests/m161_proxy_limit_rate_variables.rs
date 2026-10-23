//! M161 — `proxy_limit_rate` with variables (nginx 1.27.0, #601), read
//! once the upstream's header is in: `$upstream_http_*` sets the rate of
//! the response it came with, on the relayed path and on the one that
//! reads the body whole (`add_trailer`); and a body that comes at once
//! is paced too (#700).

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const BODY: usize = 400_000;

struct Server(Child, PathBuf);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
        let _ = std::fs::remove_dir_all(&self.1);
    }
}

fn start(name: &str) -> (Server, u16) {
    let dir = std::env::temp_dir().join(format!("ruxen-m161-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("data"), "X".repeat(BODY)).unwrap();
    std::fs::write(dir.join("small"), "X".repeat(40000)).unwrap();
    // Held until ruxen listens: released earlier, another test could take
    // the same free port, and ruxen would fail to bind it.
    let setup = common::ports::setup_lock();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let d = dir.display();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "error_log {d}/error.log info;\n\
             events {{}}\nhttp {{\n\
             access_log off;\n\
             server {{ listen 127.0.0.1:{port};\n\
               proxy_limit_rate $upstream_http_x_rate;\n\
                              location / {{ proxy_pass http://127.0.0.1:{port}/data; }}\n\
               location /whole/ {{ proxy_pass http://127.0.0.1:{port}/data;\n\
                 add_trailer X-T t; }}\n\
               location /data {{ root {d}; add_header X-Rate $arg_e; }}\n\
               location /fixed/ {{ proxy_pass http://127.0.0.1:{port}/small;\n\
                 proxy_limit_rate 20000; }}\n\
               location /small {{ root {d}; }}\n\
             }}\n}}\n"
        ),
    )
    .unwrap();
    // Owned by `Server` before the wait: if it panics, ruxen still stops.
    let mut server = Server(
        Command::new(env!("CARGO_BIN_EXE_ruxen"))
            .arg("-c")
            .arg(dir.join("nginx.conf"))
            .arg("-g")
            .arg(format!("pid {d}/ruxen.pid;"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
        dir.clone(),
    );
    common::ports::wait_for_pid_file(
        &mut server.0,
        &dir.join("ruxen.pid"),
        Duration::from_secs(5),
    );
    drop(setup);
    (server, port)
}

/// The response's body length and how long it took.
fn get(port: u16, path: &str) -> (usize, Duration) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let started = Instant::now();
    write!(s, "GET {path} HTTP/1.0\r\nHost: localhost\r\n\r\n").unwrap();
    let mut out = Vec::new();
    s.read_to_end(&mut out).unwrap();
    let elapsed = started.elapsed();
    let head_end = out.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    assert!(
        out.starts_with(b"HTTP/1.1 200"),
        "{}",
        String::from_utf8_lossy(&out)
    );
    (out.len() - head_end, elapsed)
}

#[test]
fn the_upstreams_header_sets_the_rate() {
    let (_server, port) = start("vars");
    for prefix in ["/", "/whole/"] {
        // 400 KB at 200 KB/s.
        let (len, took) = get(port, &format!("{prefix}?e=200000"));
        assert_eq!(len, BODY, "{prefix}");
        assert!(took >= Duration::from_millis(900), "{prefix}: {took:?}");
        // 0: unlimited; so is a value that isn't a size.
        for e in ["0", "fast"] {
            let (len, took) = get(port, &format!("{prefix}?e={e}"));
            assert_eq!(len, BODY, "{prefix} {e}");
            assert!(took < Duration::from_millis(500), "{prefix} {e}: {took:?}");
        }
    }
}

#[test]
fn a_literal_rate_is_still_checked_as_a_size() {
    let dir = std::env::temp_dir().join(format!("ruxen-m161-bad-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("nginx.conf"),
        "events {}\nhttp { server { listen 127.0.0.1:1; \
         location / { proxy_pass http://127.0.0.1:2; proxy_limit_rate 10x; } } }\n",
    )
    .unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .arg("-t")
        .arg("-c")
        .arg(dir.join("nginx.conf"))
        .output()
        .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("proxy_limit_rate"), "{stderr}");
}

/// A body that comes in one read with the head is paced too (#700): the
/// head is read into a small buffer, and each relayed read waits until
/// it's due before it goes out.
#[test]
fn a_body_that_comes_at_once_is_paced() {
    let (_server, port) = start("once");
    // 40000 bytes at 20000 bytes/s; nginx 1.30.6 takes 1.8 s.
    let (len, took) = get(port, "/fixed/");
    assert_eq!(len, 40000);
    assert!(took >= Duration::from_millis(900), "{took:?}");
}
