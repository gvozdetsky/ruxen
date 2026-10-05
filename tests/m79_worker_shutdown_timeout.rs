//! M79 — `worker_shutdown_timeout` bounds a graceful shutdown (`-s quit`),
//! as nginx (ngx_set_shutdown_timer, ngx_cycle.c): the connections still
//! open when it fires are closed and the process exits. Without it a
//! client that stops reading kept ruxen alive indefinitely.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

unsafe extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
}

const SIGQUIT: i32 = 3;

fn start(dir: &Path, directive: &str) -> (Child, u16) {
    let setup = common::ports::setup_lock();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "pid {d}/ruxen.pid;\n{directive}\nevents {{}}\nhttp {{\n\
             server {{ listen 127.0.0.1:{port}; location / {{ root {d}; }} }}\n\
             }}\n",
            d = dir.display()
        ),
    )
    .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .arg("-c")
        .arg(dir.join("nginx.conf"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    while !dir.join("ruxen.pid").exists() {
        assert!(
            Instant::now() < deadline && child.try_wait().unwrap().is_none(),
            "ruxen did not start"
        );
        sleep(Duration::from_millis(10));
    }
    drop(setup);
    (child, port)
}

/// Starts a download of `big.bin` and reads only its first bytes, so the
/// response stays in flight: ruxen is blocked writing it.
fn stalled_download(port: u16) -> TcpStream {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.write_all(b"GET /big.bin HTTP/1.1\r\nHost: x\r\n\r\n")
        .unwrap();
    let mut head = [0; 64];
    s.read_exact(&mut head).unwrap();
    assert!(head.starts_with(b"HTTP/1.1 200"));
    sleep(Duration::from_millis(100));
    s
}

/// How long the process takes to exit after SIGQUIT, `None` if it is still
/// running after `wait`.
fn quit(child: &mut Child, wait: Duration) -> Option<Duration> {
    let sent = Instant::now();
    unsafe {
        assert_eq!(kill(child.id() as i32, SIGQUIT), 0);
    }
    while sent.elapsed() < wait {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success(), "{status}");
            return Some(sent.elapsed());
        }
        sleep(Duration::from_millis(10));
    }
    None
}

#[test]
fn the_timeout_closes_in_flight_connections() {
    let dir = std::env::temp_dir().join(format!("ruxen-m79-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // Sparse: far more than the socket buffers hold.
    std::fs::File::create(dir.join("big.bin"))
        .unwrap()
        .set_len(256 << 20)
        .unwrap();

    // Without the directive the shutdown waits for the download.
    let (mut child, port) = start(&dir, "");
    let client = stalled_download(port);
    let exited = quit(&mut child, Duration::from_millis(1500));
    let _ = child.kill();
    let _ = child.wait();
    drop(client);
    assert_eq!(exited, None, "exited with a download in flight");
    let _ = std::fs::remove_file(dir.join("ruxen.pid"));

    let (mut child, port) = start(&dir, "worker_shutdown_timeout 300ms;");
    let mut client = stalled_download(port);
    let exited = quit(&mut child, Duration::from_secs(5));
    if exited.is_none() {
        let _ = child.kill();
        let _ = child.wait();
    }
    let pid_file_left = dir.join("ruxen.pid").exists();
    // The client sees the response cut short.
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut rest = Vec::new();
    let read = client.read_to_end(&mut rest);
    let _ = std::fs::remove_dir_all(&dir);

    let exited = exited.expect("still running 5 s after SIGQUIT");
    assert!(exited >= Duration::from_millis(250), "{exited:?}");
    assert!(!pid_file_left);
    assert!(
        read.is_err_and(|e| e.kind() == std::io::ErrorKind::ConnectionReset)
            || rest.len() < 256 << 20,
        "the whole body arrived"
    );
}
