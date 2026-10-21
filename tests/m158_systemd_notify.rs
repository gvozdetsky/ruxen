//! M158 — systemd's notification protocol (#502): `READY=1` once ruxen
//! accepts, `RELOADING=1` (with `MONOTONIC_USEC`) and `READY=1` around a
//! reload, `STOPPING=1` on SIGTERM, and with `WATCHDOG_USEC` a
//! `WATCHDOG=1` every half interval, but only while every worker turns
//! its accept loop: a worker stuck in a blocking call stops the pings and
//! is logged at `alert`. The test is systemd: a datagram socket.

mod common;

use std::io::Write;
use std::net::TcpStream;
use std::os::unix::net::UnixDatagram;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

struct KillOnDrop(std::process::Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The messages that arrive within `wait`.
fn messages(sock: &UnixDatagram, wait: Duration) -> Vec<String> {
    let deadline = Instant::now() + wait;
    let mut out = Vec::new();
    let mut buf = [0u8; 512];
    while let Some(left) = deadline.checked_duration_since(Instant::now()) {
        sock.set_read_timeout(Some(left.max(Duration::from_millis(1))))
            .unwrap();
        match sock.recv(&mut buf) {
            Ok(n) => out.push(String::from_utf8_lossy(&buf[..n]).into_owned()),
            Err(_) => break,
        }
    }
    out
}

/// Until a message starting with `prefix` arrives; it.
fn wait_for(sock: &UnixDatagram, prefix: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut buf = [0u8; 512];
    loop {
        let left = deadline
            .checked_duration_since(Instant::now())
            .unwrap_or_else(|| panic!("no {prefix}"));
        sock.set_read_timeout(Some(left)).unwrap();
        let n = sock
            .recv(&mut buf)
            .unwrap_or_else(|_| panic!("no {prefix}"));
        let message = String::from_utf8_lossy(&buf[..n]).into_owned();
        if message.starts_with(prefix) {
            return message;
        }
    }
}

#[test]
fn m158_notify_and_watchdog() {
    let dir = std::env::temp_dir().join(format!("ruxen-m158-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let sock = UnixDatagram::bind(dir.join("notify.sock")).unwrap();
    // An access_log FIFO without a reader, opened per line (the path has a
    // variable): a request naming it blocks its worker in `open()`.
    let fifo = dir.join("log-fifo");
    let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
    // SAFETY: a NUL-terminated path.
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    let setup = common::ports::setup_lock();
    let [port] = common::ports::free_ports();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "worker_processes 1;\nerror_log {d}/error.log;\npid {d}/ruxen.pid;\nevents {{}}\n\
             http {{ access_log {d}/log-$arg_f;\n\
             server {{ listen 127.0.0.1:{port}; root {d}; location / {{ return 200; }} }} }}\n",
            d = dir.display()
        ),
    )
    .unwrap();
    let mut child = KillOnDrop(
        Command::new(env!("CARGO_BIN_EXE_ruxen"))
            .arg("-c")
            .arg(dir.join("nginx.conf"))
            .env("NOTIFY_SOCKET", dir.join("notify.sock"))
            .env("WATCHDOG_USEC", "400000")
            // A blocking open blocks the thread (io_uring would take it to
            // its own workers).
            .env("RUXEN_DRIVER", "epoll")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    common::ports::wait_for_pid_file(&mut child.0, &dir.join("ruxen.pid"), Duration::from_secs(5));
    drop(setup);
    assert_eq!(wait_for(&sock, "READY=1"), "READY=1");
    wait_for(&sock, "WATCHDOG=1");
    wait_for(&sock, "WATCHDOG=1");

    // SAFETY: signals to the child we started.
    assert_eq!(unsafe { libc::kill(child.0.id() as i32, libc::SIGHUP) }, 0);
    let reloading = wait_for(&sock, "RELOADING=1");
    assert!(reloading.contains("\nMONOTONIC_USEC="), "{reloading:?}");
    wait_for(&sock, "READY=1");
    wait_for(&sock, "WATCHDOG=1");

    // Stall the worker: its access log line opens the FIFO.
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.write_all(b"GET /?f=fifo HTTP/1.0\r\n\r\n").unwrap();
    // A ping already on its way may still come; then none.
    let _ = messages(&sock, Duration::from_millis(500));
    let later = messages(&sock, Duration::from_millis(1200));
    assert!(!later.iter().any(|m| m == "WATCHDOG=1"), "{later:?}");
    let log = std::fs::read_to_string(dir.join("error.log")).unwrap();
    assert!(
        log.contains("[alert]") && log.contains("worker 0 made no progress"),
        "{log}"
    );

    assert_eq!(unsafe { libc::kill(child.0.id() as i32, libc::SIGTERM) }, 0);
    wait_for(&sock, "STOPPING=1");
    let _ = child.0.wait();
    drop(s);
    let _ = std::fs::remove_dir_all(&dir);
}
