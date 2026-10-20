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

#[test]
fn m101_panic_in_a_background_task_ends_only_that_task() {
    // A task outside any connection (#496): here a buffered access_log's
    // flush timer, which `RUXEN_TEST_PANIC=task` makes panic.
    let (dir, port, setup) = setup("task");
    let d = dir.display();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "worker_processes 1;\nerror_log {d}/error.log;\npid {d}/ruxen.pid;\n\
             events {{}}\nhttp {{ access_log {d}/access.log combined buffer=4k flush=100ms;\n\
             server {{ listen 127.0.0.1:{port}; location / {{ return 200 ok; }} }} }}\n"
        ),
    )
    .unwrap();
    let mut child = KillOnDrop(
        Command::new(env!("CARGO_BIN_EXE_ruxen"))
            .arg("-c")
            .arg(dir.join("nginx.conf"))
            .env("RUXEN_TEST_PANIC", "task")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    common::ports::wait_for_pid_file(&mut child.0, &dir.join("ruxen.pid"), Duration::from_secs(5));
    drop(setup);
    // The first request arms the timer; it panics 100 ms later.
    assert!(request(port, "GET").ends_with("\r\n\r\nok"));
    std::thread::sleep(Duration::from_millis(400));
    // The worker is still there, and keeps answering (each request arms the
    // timer again, which panics again).
    for _ in 0..3 {
        let response = request(port, "GET");
        assert!(response.ends_with("\r\n\r\nok"), "{response}");
        std::thread::sleep(Duration::from_millis(200));
    }
    assert!(child.0.try_wait().unwrap().is_none(), "ruxen exited");
    child.stop();
    let log = std::fs::read_to_string(dir.join("error.log")).unwrap();
    assert!(log.contains(": RUXEN_TEST_PANIC=task\n"), "{log}");
    assert!(
        log.contains("[alert] ")
            && log.contains("an access_log flush timer stopped after the panic above"),
        "{log}"
    );
    assert!(!log.contains("exited after a panic"), "{log}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn m101_stop_after_a_worker_panic_is_bounded() {
    // #495: worker 1 panics while downloads run on both workers. New
    // connections are refused at once instead of waiting in a backlog
    // nobody accepts from, the panicked worker's downloads end, and ruxen
    // exits 1 within the default bound, though the downloads on worker 0
    // would take minutes.
    // The lock stays held: once ruxen closes the port, another test could
    // take it, and the refused connect below would reach that test's server.
    let (dir, port, _setup) = setup("later");
    let d = dir.display();
    std::fs::create_dir_all(dir.join("html")).unwrap();
    std::fs::write(dir.join("html/big"), vec![b'x'; 8 << 20]).unwrap();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "worker_processes 2;\nerror_log {d}/error.log;\npid {d}/ruxen.pid;\n\
             events {{}}\nhttp {{ access_log off;\n\
             server {{ listen 127.0.0.1:{port}; root {d}/html; limit_rate 64k; }} }}\n"
        ),
    )
    .unwrap();
    let mut child = KillOnDrop(
        Command::new(env!("CARGO_BIN_EXE_ruxen"))
            .arg("-c")
            .arg(dir.join("nginx.conf"))
            .env("RUXEN_TEST_PANIC", "later")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    common::ports::wait_for_pid_file(&mut child.0, &dir.join("ruxen.pid"), Duration::from_secs(5));
    // Spread over both workers by the kernel; each has started when its
    // first bytes arrive. Worker 1 panics a second after it began to accept.
    let mut downloads: Vec<TcpStream> = (0..16)
        .map(|_| {
            let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            write!(s, "GET /big HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
            let mut first = [0u8; 1];
            assert_eq!(s.read(&mut first).unwrap(), 1);
            s
        })
        .collect();
    let panicked = ": worker 1 exited after a panic, stopping\n";
    let started = std::time::Instant::now();
    while !std::fs::read_to_string(dir.join("error.log"))
        .unwrap_or_default()
        .contains(panicked)
    {
        assert!(started.elapsed() < Duration::from_secs(5), "no panic");
        std::thread::sleep(Duration::from_millis(20));
    }
    let stopping = std::time::Instant::now();
    // Refused, not queued.
    loop {
        match TcpStream::connect(("127.0.0.1", port)) {
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => break,
            other => assert!(
                stopping.elapsed() < Duration::from_secs(1),
                "still accepting connections: {other:?}"
            ),
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    // The panicked worker's downloads end at once; the others go on.
    for s in &downloads {
        s.set_nonblocking(true).unwrap();
    }
    let mut ended = vec![false; downloads.len()];
    let mut buf = vec![0u8; 1 << 16];
    while stopping.elapsed() < Duration::from_millis(1500) {
        for (s, ended) in downloads.iter_mut().zip(&mut ended) {
            while !*ended {
                match s.read(&mut buf) {
                    Ok(0) => *ended = true,
                    Ok(_) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(_) => *ended = true,
                }
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let ended = ended.iter().filter(|&&e| e).count();
    assert!(ended > 0 && ended < downloads.len(), "{ended} ended");
    let status = loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            break status;
        }
        assert!(
            stopping.elapsed() < Duration::from_secs(10),
            "still running after the panic"
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    assert_eq!(status.code(), Some(1));
    // The downloads on worker 0 kept the server up until the bound.
    assert!(stopping.elapsed() >= Duration::from_secs(4));
    assert!(!dir.join("ruxen.pid").exists(), "pid file left behind");
    drop(downloads);
    let _ = std::fs::remove_dir_all(&dir);
}
