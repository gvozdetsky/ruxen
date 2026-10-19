//! M147 — pooled upstream connections the upstream closes while they are
//! idle (#488). Upstreams close idle keep-alive connections after a few
//! seconds (Node.js, gunicorn); the next request must open a new one, a
//! POST included, and the closed sockets must not sit in CLOSE_WAIT. nginx
//! watches each cached connection for that
//! (ngx_http_upstream_keepalive_close_handler).

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
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

/// A keep-alive upstream that closes a connection after 300 ms without a
/// request, and counts the connections it accepts.
fn spawn_closing_upstream(accepted: Arc<AtomicUsize>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in listener.incoming().flatten() {
            accepted.fetch_add(1, Ordering::SeqCst);
            std::thread::spawn(move || serve(s));
        }
    });
    port
}

fn serve(s: TcpStream) {
    s.set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();
    let mut w = s.try_clone().unwrap();
    let mut r = BufReader::new(s);
    loop {
        let mut len = 0usize;
        let mut first = true;
        loop {
            let mut line = String::new();
            match r.read_line(&mut line) {
                Ok(0) | Err(_) => return, // closed, or idle for 300 ms
                Ok(_) => {}
            }
            if line == "\r\n" && !first {
                break;
            }
            first = false;
            if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                len = v.trim().parse().unwrap_or(0);
            }
        }
        let mut body = vec![0u8; len];
        if r.read_exact(&mut body).is_err() {
            return;
        }
        if w.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nok\n")
            .is_err()
        {
            return;
        }
    }
}

fn start(up: u16) -> Server {
    let ports = setup_lock();
    let port = {
        let probe = TcpListener::bind("127.0.0.1:0").unwrap();
        probe.local_addr().unwrap().port()
    };
    let dir = std::env::temp_dir().join(format!("ruxen-m147-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "worker_processes 1;\nevents {{}}\nhttp {{ access_log off;\n\
               upstream u {{ server 127.0.0.1:{up}; keepalive 4; }}\n\
               server {{ listen 127.0.0.1:{port};\n\
                 location / {{ proxy_pass http://u; proxy_http_version 1.1; \
                               proxy_set_header Connection \"\"; }}\n\
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

fn post(port: u16) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(b"POST / HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Length: 3\r\n\r\nx=1")
        .unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

/// Sockets to `port` in CLOSE_WAIT (`/proc/net/tcp` state 08).
fn close_wait_to(port: u16) -> usize {
    let tcp = std::fs::read_to_string("/proc/net/tcp").unwrap_or_default();
    let port = format!(":{port:04X}");
    tcp.lines()
        .skip(1)
        .filter(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            f.len() > 3 && f[2].ends_with(&port) && f[3] == "08"
        })
        .count()
}

#[test]
fn a_pooled_connection_the_upstream_closed_is_not_used() {
    let accepted = Arc::new(AtomicUsize::new(0));
    let up = spawn_closing_upstream(accepted.clone());
    let server = start(up);
    for round in 0..3 {
        assert!(
            post(server.port).starts_with("HTTP/1.1 200"),
            "round {round}"
        );
        // Past the upstream's 300 ms: the pooled connection is closed.
        std::thread::sleep(Duration::from_millis(600));
        let resp = post(server.port);
        assert!(resp.starts_with("HTTP/1.1 200"), "round {round}: {resp}");
        std::thread::sleep(Duration::from_millis(600));
    }
    // Each POST went on a connection of its own: every one was closed first.
    assert_eq!(accepted.load(Ordering::SeqCst), 6);
    // The last one closed too; the worker's sweep drops it within a second.
    std::thread::sleep(Duration::from_millis(1500));
    assert_eq!(close_wait_to(up), 0);
    let log = std::fs::read_to_string(server.dir.join("stderr.log")).unwrap_or_default();
    assert!(!log.contains("prematurely closed"), "{log}");
}
