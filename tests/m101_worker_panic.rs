//! M101 — what a panic does (#130), forced with `RUXEN_TEST_PANIC`. A panic
//! while serving a connection closes that connection only; the worker keeps
//! serving, and the error log has the message and where it happened. A
//! worker that panics outside a connection stops the server: exit status 1,
//! the pid file removed, and an `alert` saying which worker it was.

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::MutexGuard;
use std::time::Duration;

/// The server stops when the test ends, also when an assertion panics:
/// an orphaned ruxen otherwise keeps its port and CPU after the run.
struct KillOnDrop(std::process::Child);

impl KillOnDrop {
    fn stop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        self.stop();
    }
}

/// The directory, the port, and the port lock, held until ruxen listens
/// (or has exited): released earlier, another test could take the same
/// free port, and ruxen would fail to bind it.
fn setup(name: &str) -> (PathBuf, u16, MutexGuard<'static, ()>) {
    let dir = std::env::temp_dir().join(format!("ruxen-m101-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
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
            "worker_processes 1;\nerror_log {d}/error.log;\npid {d}/ruxen.pid;\n\
             events {{}}\nhttp {{ access_log off;\n\
             server {{ listen 127.0.0.1:{port}; location / {{ return 200 ok; }} }} }}\n"
        ),
    )
    .unwrap();
    (dir, port, setup)
}

fn request(port: u16, method: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(
        s,
        "{method} / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

#[test]
fn m101_panic_in_a_connection_closes_only_that_connection() {
    let (dir, port, setup) = setup("conn");
    let mut child = KillOnDrop(
        Command::new(env!("CARGO_BIN_EXE_ruxen"))
            .arg("-c")
            .arg(dir.join("nginx.conf"))
            .env("RUXEN_TEST_PANIC", "trace")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    common::ports::wait_for_pid_file(&mut child.0, &dir.join("ruxen.pid"), Duration::from_secs(5));
    drop(setup);
    // The TRACE connection is dropped without an answer.
    assert_eq!(request(port, "TRACE"), "");
    // The one worker is still there, and keeps answering.
    for _ in 0..3 {
        let response = request(port, "GET");
        assert!(response.ends_with("\r\n\r\nok"), "{response}");
    }
    assert!(child.0.try_wait().unwrap().is_none(), "ruxen exited");
    child.stop();
    let log = std::fs::read_to_string(dir.join("error.log")).unwrap();
    assert!(
        log.contains("[alert] ") && log.contains("ruxen-worker-0 panicked at src/phase.rs:"),
        "{log}"
    );
    assert!(log.contains(": RUXEN_TEST_PANIC=trace\n"), "{log}");
    assert!(
        log.contains("connection closed after the panic above, client: 127.0.0.1"),
        "{log}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn m101_worker_that_panics_stops_the_server() {
    // The lock stays held while this ruxen binds the port and exits.
    let (dir, _port, setup) = setup("worker");
    let out = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .arg("-c")
        .arg(dir.join("nginx.conf"))
        .env("RUXEN_TEST_PANIC", "worker")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .unwrap();
    drop(setup);
    assert_eq!(out.status.code(), Some(1));
    assert!(!dir.join("ruxen.pid").exists(), "pid file left behind");
    let log = std::fs::read_to_string(dir.join("error.log")).unwrap();
    assert!(log.contains("ruxen-worker-0 panicked at "), "{log}");
    assert!(
        log.contains("[alert] ") && log.contains(": worker 0 exited after a panic, stopping\n"),
        "{log}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
