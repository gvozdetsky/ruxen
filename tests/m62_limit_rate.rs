//! M62 — `limit_rate` / `limit_rate_after` pace the response as nginx's
//! write filter does (`rate * (elapsed + 1 s)` past the first `after`
//! bytes), with variables allowed; `set $limit_rate` overrides them and
//! `$limit_rate` shows it. They used to be accepted and ignored.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

struct Server {
    child: Child,
    port: u16,
    dir: PathBuf,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn start() -> Server {
    let port = {
        let probe = TcpListener::bind("127.0.0.1:0").unwrap();
        probe.local_addr().unwrap().port()
    };
    let dir = std::env::temp_dir().join(format!("ruxen-m62-{}-{port}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("data"), vec![b'x'; 30_000]).unwrap();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "events {{}}\nhttp {{ server {{ listen 127.0.0.1:{port}; root {d};\n\
             location /slow {{ alias {d}/data; limit_rate 20k; }}\n\
             location /var {{ alias {d}/data; limit_rate $arg_l; limit_rate_after $arg_a; }}\n\
             location /set {{ set $limit_rate $arg_l; add_header X-Rate $limit_rate; \
               return 200 ok; }}\n\
             }} }}\n",
            d = dir.display()
        ),
    )
    .unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .arg("-c")
        .arg(dir.join("nginx.conf"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "ruxen did not start");
        sleep(Duration::from_millis(20));
    }
    Server { child, port, dir }
}

/// The response and how long it took.
fn timed_get(port: u16, path: &str) -> (Vec<u8>, Duration) {
    let started = Instant::now();
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    (out, started.elapsed())
}

fn body_len(resp: &[u8]) -> usize {
    resp.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map_or(0, |p| resp.len() - p - 4)
}

#[test]
fn limit_rate_paces_the_response() {
    let server = start();
    // 30000 bytes at 20k/s with a one-second allowance: about 0.47 s.
    let (resp, took) = timed_get(server.port, "/slow");
    assert_eq!(body_len(&resp), 30_000);
    assert!(
        took >= Duration::from_millis(350) && took < Duration::from_secs(3),
        "{took:?}"
    );

    // Variables: unset means unlimited; everything within `after` is too.
    let (resp, took) = timed_get(server.port, "/var");
    assert_eq!(body_len(&resp), 30_000);
    assert!(took < Duration::from_millis(300), "{took:?}");
    let (_, took) = timed_get(server.port, "/var?l=1k&a=40k");
    assert!(took < Duration::from_millis(300), "{took:?}");
    let (_, took) = timed_get(server.port, "/var?l=20k&a=0");
    assert!(took >= Duration::from_millis(350), "{took:?}");
}

#[test]
fn set_limit_rate_shows_in_the_variable() {
    let server = start();
    let (resp, _) = timed_get(server.port, "/set?l=40k");
    let resp = String::from_utf8_lossy(&resp);
    assert!(resp.contains("\r\nX-Rate: 40960\r\n"), "{resp}");
    // Not a size: 0, as nginx.
    let (resp, _) = timed_get(server.port, "/set?l=fast");
    let resp = String::from_utf8_lossy(&resp);
    assert!(resp.contains("\r\nX-Rate: 0\r\n"), "{resp}");
}
