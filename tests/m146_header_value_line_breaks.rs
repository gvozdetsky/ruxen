//! M146 — values rendered from variables into a head (#516): a decoded
//! `$uri` with `%0D%0A` can't add a header line. In `proxy_set_header`,
//! `add_header` and `add_trailer` a CR, LF or NUL becomes a space (RFC 9110
//! §5.5); in a `Location` it is percent-encoded. nginx 1.24 sends them as
//! they are.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use common::ports::setup_lock;

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

/// An upstream that answers with the `X-Uri` line it got and the number
/// of header lines.
fn spawn_target_echo() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in listener.incoming().flatten() {
            let mut s = s;
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                if s.read(&mut byte).unwrap_or(0) == 0 {
                    break;
                }
                head.push(byte[0]);
            }
            let head = String::from_utf8_lossy(&head).into_owned();
            let lines = head.trim_end().split("\r\n").count() - 1;
            let x_uri = head
                .split("\r\n")
                .find(|l| l.starts_with("X-Uri:"))
                .unwrap_or("")
                .to_string();
            let body = format!("[{x_uri}] lines={lines}");
            let _ = write!(
                s,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    port
}

fn start(up: u16) -> Server {
    let ports = setup_lock();
    let port = {
        let probe = TcpListener::bind("127.0.0.1:0").unwrap();
        probe.local_addr().unwrap().port()
    };
    let dir = std::env::temp_dir().join(format!("ruxen-m146-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "events {{}}\nhttp {{ access_log off; server {{ listen 127.0.0.1:{port};\n\
               location / {{ proxy_set_header X-Uri $uri; add_header X-Uri $uri; \
                             add_trailer X-T $uri; proxy_pass http://127.0.0.1:{up}; }}\n\
               location /ret/ {{ return 302 /x$uri; }}\n\
             }} }}\n"
        ),
    )
    .unwrap();
    let mut server = Server {
        child: Command::new(env!("CARGO_BIN_EXE_ruxen"))
            .arg("-c")
            .arg(dir.join("nginx.conf"))
            .arg("-e")
            .arg(dir.join("stderr.log"))
            .arg("-g")
            .arg(format!("pid {}/ruxen.pid;", dir.display()))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
        port,
        dir,
    };
    let pid_file = server.dir.join("ruxen.pid");
    common::ports::wait_for_pid_file(&mut server.child, &pid_file, Duration::from_secs(3));
    drop(ports);
    server
}

fn get(port: u16, target: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(
        s,
        "GET {target} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

#[test]
fn rendered_header_values_keep_to_one_line() {
    let up = spawn_target_echo();
    let server = start(up);
    // The request target itself is #541's; here only the header values.
    let resp = get(server.port, "/a%0D%0AX-Injected:%201");
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
    // To the upstream: the X-Uri line whole.
    assert!(resp.contains("[X-Uri: /a  X-Injected: 1]"), "{resp}");
    // To the client: no header line of its own.
    assert!(resp.contains("\r\nX-Uri: /a  X-Injected: 1\r\n"), "{resp}");
    assert!(!resp.contains("\r\nX-Injected"), "{resp}");

    let resp = get(server.port, "/ret/a%0D%0AX-Inj:%201");
    assert!(resp.starts_with("HTTP/1.1 302"), "{resp}");
    assert!(resp.contains("/x/ret/a%0D%0AX-Inj: 1\r\n"), "{resp}");
    assert!(!resp.contains("\r\nX-Inj"), "{resp}");
}
