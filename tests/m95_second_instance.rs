//! M95 — a second ruxen on a port another process listens on fails like
//! nginx (`bind() … failed (98: Address already in use)`, then `still
//! could not bind()`), unless the listen says `reuseport`.

mod common;

use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn conf(tag: &str, listen: &str) -> (PathBuf, u16) {
    let dir = std::env::temp_dir().join(format!("ruxen-m95-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir).unwrap();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let path = dir.join("ruxen.conf");
    std::fs::write(
        &path,
        format!(
            "worker_processes 2;\nevents {{}}\nhttp {{ access_log off; server {{ \
             listen 127.0.0.1:{port}{listen}; location / {{ return 200 ok; }} }} }}\n"
        ),
    )
    .unwrap();
    (path, port)
}

fn start(path: &PathBuf, port: u16) -> Server {
    let child = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .args(["-c", path.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "ruxen did not start");
        std::thread::sleep(Duration::from_millis(20));
    }
    Server(child)
}

#[test]
fn m95_second_instance_fails_with_address_in_use() {
    let _setup = common::ports::setup_lock();
    let (path, port) = conf("busy", "");
    let _first = start(&path, port);

    let started = Instant::now();
    let second = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .args(["-c", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!second.status.success());
    let stderr = String::from_utf8_lossy(&second.stderr);
    let busy = format!(
        "[emerg] bind() to 127.0.0.1:{port} failed ({})",
        common::errno_text(98)
    );
    // nginx's five tries, 500 ms apart.
    assert_eq!(stderr.matches(&busy).count(), 5, "{stderr}");
    assert!(
        stderr.contains("[emerg] still could not bind()"),
        "{stderr}"
    );
    assert!(started.elapsed() >= Duration::from_secs(2));

    // `-t` doesn't bind, as nginx's ignores EADDRINUSE.
    let test = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .args(["-t", "-c", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(test.status.success());
}

#[test]
fn m95_reuseport_lets_a_second_instance_share_the_port() {
    let _setup = common::ports::setup_lock();
    let (path, port) = conf("reuseport", " reuseport");
    let _first = start(&path, port);
    let mut second = Server(
        Command::new(env!("CARGO_BIN_EXE_ruxen"))
            .args(["-c", path.to_str().unwrap()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    std::thread::sleep(Duration::from_millis(500));
    assert!(
        second.0.try_wait().unwrap().is_none(),
        "the second instance exited"
    );
}
