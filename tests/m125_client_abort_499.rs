//! M125 — a client that closes while the upstream is awaited ends the
//! exchange (#136), as nginx's ngx_http_upstream_check_broken_connection:
//! the upstream connection is closed, the access log has 499 and the error
//! log nginx's `[info]` line. `proxy_ignore_client_abort on` keeps the
//! exchange.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// The server stops when the test ends, also when an assertion panics.
struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Wait up to 5 s for `path` to contain `n` lines.
fn lines(path: &std::path::Path, n: usize) -> Vec<String> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        let lines: Vec<String> = text.lines().map(str::to_owned).collect();
        if lines.len() >= n || Instant::now() > deadline {
            return lines;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn a_client_gone_while_the_upstream_is_awaited_is_499() {
    let dir = std::env::temp_dir().join(format!("ruxen-m125-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // The upstream answers after 2 s, and reports whether the proxy
    // closed its side first.
    let backend = TcpListener::bind("127.0.0.1:0").unwrap();
    let up = backend.local_addr().unwrap().port();
    let (closed_tx, closed_rx) = mpsc::channel::<bool>();
    std::thread::spawn(move || {
        for conn in backend.incoming().take(2) {
            let mut c = conn.unwrap();
            let closed_tx = closed_tx.clone();
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                let _ = c.read(&mut buf);
                c.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                // EOF before the answer: the proxy gave up the exchange.
                let early = matches!(c.read(&mut buf), Ok(0));
                let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
                let _ = closed_tx.send(early);
            });
        }
    });

    // Held until ruxen listens.
    let setup = common::ports::setup_lock();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let d = dir.display();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "worker_processes 1;\npid {d}/ruxen.pid;\nerror_log {d}/error.log info;\n\
             events {{}}\nhttp {{\n\
             log_format t '$request_uri $status $upstream_status $upstream_header_time $upstream_response_time';\naccess_log {d}/access.log t;\n\
             server {{ listen 127.0.0.1:{port};\n\
             location / {{ proxy_pass http://127.0.0.1:{up}; }}\n\
             location /keep {{ proxy_ignore_client_abort on; proxy_pass http://127.0.0.1:{up}; }} }} }}\n"
        ),
    )
    .unwrap();
    let mut child = KillOnDrop(
        Command::new(env!("CARGO_BIN_EXE_ruxen"))
            .arg("-c")
            .arg(dir.join("nginx.conf"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    common::ports::wait_for_pid_file(&mut child.0, &dir.join("ruxen.pid"), Duration::from_secs(5));
    drop(setup);

    let gone = |path: &str| {
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        write!(s, "GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        std::thread::sleep(Duration::from_millis(300));
        drop(s);
    };

    gone("/");
    assert!(
        closed_rx.recv_timeout(Duration::from_secs(5)).unwrap(),
        "the upstream connection outlived the client"
    );
    // nginx: `499 - - 0.497`: no status or header from the upstream, and
    // the time until the close.
    let line = lines(&dir.join("access.log"), 1)[0].clone();
    let fields: Vec<&str> = line.split(' ').collect();
    assert_eq!(fields[..4], ["/", "499", "-", "-"], "{line}");
    let rt: f64 = fields[4].parse().unwrap_or_else(|_| panic!("{line}"));
    assert!((0.1..2.0).contains(&rt), "{line}");
    let error_log = std::fs::read_to_string(dir.join("error.log")).unwrap();
    assert!(
        error_log.contains("[info] ")
            && error_log.contains(
                "client prematurely closed connection, so upstream connection is closed too"
            ),
        "{error_log}"
    );

    gone("/keep");
    assert!(
        !closed_rx.recv_timeout(Duration::from_secs(5)).unwrap(),
        "proxy_ignore_client_abort on: the exchange should have gone on"
    );
    assert!(
        lines(&dir.join("access.log"), 2)[1].starts_with("/keep 200 200 "),
        "{:?}",
        lines(&dir.join("access.log"), 2)
    );
    let _ = std::fs::remove_dir_all(&dir);
}
