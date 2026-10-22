//! M111 — `limit_conn_zone` / `limit_conn` (#95): requests in progress per
//! key, on a zone shared by all workers. While a slow request holds the
//! only slot, another one from the same address gets `limit_conn_status`;
//! once it is answered, or its client closes, the slot is free again. `$limit_conn_status` says
//! which, and an undeclared zone fails at startup.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

struct Server(Child, std::path::PathBuf);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
        let _ = std::fs::remove_dir_all(&self.1);
    }
}

/// An upstream that answers after `delay`.
fn slow_backend(delay: Duration) -> u16 {
    let listener = {
        let _setup = common::ports::setup_lock();
        TcpListener::bind("127.0.0.1:0").unwrap()
    };
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut conn in listener.incoming().flatten() {
            std::thread::spawn(move || {
                let mut buf = [0u8; 1024];
                let _ = conn.read(&mut buf);
                std::thread::sleep(delay);
                let _ = conn.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nslow",
                );
            });
        }
    });
    port
}

fn start(backend: u16) -> (Server, u16) {
    let dir = std::env::temp_dir().join(format!("ruxen-m111-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("html")).unwrap();
    std::fs::write(dir.join("html/index.html"), "hi").unwrap();
    // Held until ruxen listens: released earlier, another test could take
    // the same free port, and ruxen would fail to bind it.
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
            "worker_processes 4;\nerror_log {d}/error.log info;\nevents {{}}\nhttp {{ access_log off;\n\
             limit_conn_zone $binary_remote_addr zone=one:1m;\n\
             server {{ listen 127.0.0.1:{port}; root {d}/html;\n\
             add_header X-Status $limit_conn_status always;\n\
             limit_conn one 1; limit_conn_status 429; limit_conn_log_level info;\n\
             location /slow {{ proxy_pass http://127.0.0.1:{backend}; }}\n\
             location / {{ }}\n\
             }} }}\n"
        ),
    )
    .unwrap();
    // Owned by `Server` before the wait: if it panics, ruxen still stops.
    let mut server = Server(
        Command::new(env!("CARGO_BIN_EXE_ruxen"))
            .arg("-c")
            .arg(dir.join("nginx.conf"))
            .arg("-g")
            .arg(format!("pid {}/ruxen.pid;", dir.display()))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
        dir,
    );
    let pid_file = server.1.join("ruxen.pid");
    common::ports::wait_for_pid_file(&mut server.0, &pid_file, Duration::from_secs(5));
    drop(setup);
    (server, port)
}

fn send(port: u16, path: &str) -> TcpStream {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(s, "GET {path} HTTP/1.0\r\n\r\n").unwrap();
    s
}

fn answer(mut s: TcpStream) -> (u16, String) {
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    let status = out[9..12].parse().unwrap();
    let x = out
        .lines()
        .find_map(|l| l.strip_prefix("X-Status: "))
        .unwrap_or("")
        .to_string();
    (status, x)
}

#[test]
fn m111_one_request_at_a_time_per_address() {
    let backend = slow_backend(Duration::from_millis(800));
    let (server, port) = start(backend);
    let slow = send(port, "/slow");
    std::thread::sleep(Duration::from_millis(200));
    // The slot is held by the slow request, on whichever worker.
    assert_eq!(answer(send(port, "/")), (429, "REJECTED".into()));
    assert_eq!(answer(slow), (200, "PASSED".into()));
    // Answered: the slot is free again.
    assert_eq!(answer(send(port, "/")), (200, "PASSED".into()));
    // A client that closes gives its slot back at once, as nginx's
    // limit_conn.t expects: the next request a moment later passes, while
    // the upstream still works on the first.
    drop(send(port, "/slow"));
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(answer(send(port, "/")), (200, "PASSED".into()));
    let log = std::fs::read_to_string(server.1.join("error.log")).unwrap();
    assert!(
        log.contains("[info] ")
            && log.contains(" limiting connections by zone \"one\", client: 127.0.0.1,"),
        "{log}"
    );
}

#[test]
fn m111_undeclared_zone_fails_at_startup() {
    let dir = std::env::temp_dir().join(format!("ruxen-m111-bad-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("nginx.conf"),
        "events {}\nhttp { server { listen 127.0.0.1:18111;\n\
         location / { limit_conn nope 1; } } }\n",
    )
    .unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .arg("-t")
        .arg("-c")
        .arg(dir.join("nginx.conf"))
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{stderr}");
    assert!(
        stderr.contains("zero size shared memory zone \"nope\""),
        "{stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
