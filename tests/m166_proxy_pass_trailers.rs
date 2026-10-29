//! M166 — `proxy_pass_trailers` (#823): a chunked upstream body's trailers
//! reach the client, less the hidden ones, before `add_trailer`'s.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

struct Server {
    _child: common::KillOnDrop,
    dir: PathBuf,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

const TRAILERS: &str = "X-Up: 1\r\nServer: up\r\nX-Hide: h\r\n";
const BIG: usize = 300_000;

/// A keep-alive HTTP/1.1 backend. Each answer is chunked with
/// `TRAILERS` and says which connection it came on (`X-Conn`); `/slow`
/// sends the trailers in a second write, `/huge` a trailer section over
/// nginx's 4 KiB, `/big` a `BIG`-byte chunk, then the trailers later.
fn backend(listener: TcpListener) {
    std::thread::spawn(move || {
        for (id, conn) in listener.incoming().flatten().enumerate() {
            std::thread::spawn(move || serve(conn, id));
        }
    });
}

fn serve(mut conn: TcpStream, id: usize) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
            match conn.read(&mut chunk) {
                Ok(0) | Err(_) => return,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
            continue;
        };
        let head = String::from_utf8_lossy(&buf[..end]).into_owned();
        buf.drain(..end + 4);
        let path = head.split(' ').nth(1).unwrap_or("/").to_string();
        let start = format!(
            "HTTP/1.1 200 OK\r\nX-Conn: {id}\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n"
        );
        let rest = if path == "/huge" {
            format!(
                "0\r\n{}\r\n",
                format!("X: {}\r\n", "v".repeat(1000)).repeat(5)
            )
        } else {
            format!("0\r\n{TRAILERS}\r\n")
        };
        if path == "/big" {
            let chunk = format!("{BIG:x}\r\n{}\r\n", "b".repeat(BIG));
            let _ = conn.write_all(format!("{start}{chunk}").as_bytes());
            std::thread::sleep(Duration::from_millis(100));
            let _ = conn.write_all(rest.as_bytes());
        } else if path == "/slow" {
            let _ = conn.write_all(start.as_bytes());
            std::thread::sleep(Duration::from_millis(200));
            let _ = conn.write_all(rest.as_bytes());
        } else {
            let _ = conn.write_all(format!("{start}{rest}").as_bytes());
        }
        if path == "/huge" {
            return;
        }
    }
}

fn start(conf: String) -> Server {
    let dir = std::env::temp_dir().join(format!("ruxen-m166-{}", std::process::id()));
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

/// (head, body as on the wire).
fn request(port: u16, path: &str, version: &str) -> (String, String) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    write!(
        s,
        "GET {path} HTTP/{version}\r\nHost: front\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut out = Vec::new();
    s.read_to_end(&mut out).unwrap();
    let out = String::from_utf8_lossy(&out).into_owned();
    let at = out.find("\r\n\r\n").expect("a response head");
    (out[..at].to_string(), out[at + 4..].to_string())
}

/// The data of a chunked body, and what follows its last chunk.
fn dechunk(mut wire: &str) -> (String, String) {
    let mut data = String::new();
    loop {
        let (size, rest) = wire.split_once("\r\n").expect("a chunk size");
        let n = usize::from_str_radix(size, 16).expect("hex");
        if n == 0 {
            return (data, rest.to_string());
        }
        data.push_str(&rest[..n]);
        wire = &rest[n + 2..];
    }
}

#[test]
fn m166_proxy_pass_trailers() {
    let setup = common::ports::setup_lock();
    let up = TcpListener::bind("127.0.0.1:0").unwrap();
    let up_port = up.local_addr().unwrap().port();
    backend(up);
    let [front] = common::ports::free_ports();
    let _s = start(format!(
        "upstream b {{ server 127.0.0.1:{up_port}; keepalive 2; }}\n\
         server {{ listen 127.0.0.1:{front};\n\
           proxy_http_version 1.1; proxy_set_header Connection \"\";\n\
           proxy_pass_trailers on;\n\
           location /on/ {{ proxy_pass http://b/; proxy_hide_header X-Hide; }}\n\
           location /add/ {{ proxy_pass http://b/; add_trailer X-Add $sent_trailer_x_up; }}\n\
           location /off/ {{ proxy_pass http://b/; proxy_pass_trailers off; }} }}",
    ));
    drop(setup);

    // Whole with the head, and relayed: the upstream's trailers less the
    // hidden ones (Server by default, X-Hide by proxy_hide_header).
    for path in ["/on/small", "/on/slow"] {
        let (head, body) = request(front, path, "1.1");
        assert!(
            head.contains("Transfer-Encoding: chunked"),
            "{path}: {head}"
        );
        assert_eq!(body, "5\r\nhello\r\n0\r\nX-Up: 1\r\n\r\n", "{path}");
    }
    // The connection goes back to the pool after the trailers.
    let conn = |head: &str| head.split("X-Conn: ").nth(1).map(|s| s[..1].to_string());
    let (a, _) = request(front, "/on/small", "1.1");
    let (b, _) = request(front, "/on/small", "1.1");
    assert_eq!(conn(&a), conn(&b), "{a}\n{b}");

    // add_trailer's after them, and it sees them.
    let (_, body) = request(front, "/add/small", "1.1");
    assert_eq!(
        body,
        "5\r\nhello\r\n0\r\nX-Up: 1\r\nX-Hide: h\r\nX-Add: 1\r\n\r\n"
    );

    // Over more than one read: through the relay's pipe (#764).
    let (_, body) = request(front, "/on/big", "1.1");
    let (data, after) = dechunk(&body);
    assert!(
        data == format!("hello{}", "b".repeat(BIG)),
        "{}",
        data.len()
    );
    assert_eq!(after, "X-Up: 1\r\n\r\n");

    // Off: dropped.
    let (_, body) = request(front, "/off/slow", "1.1");
    assert_eq!(body, "5\r\nhello\r\n0\r\n\r\n");

    // HTTP/1.0 has no trailers.
    let (_, body) = request(front, "/on/slow", "1.0");
    assert_eq!(body, "hello");

    // Over 4 KiB: the body is cut, without its last chunk.
    let (_, body) = request(front, "/on/huge", "1.1");
    assert_eq!(body, "5\r\nhello\r\n");
}
