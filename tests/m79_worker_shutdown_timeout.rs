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

fn start(dir: &Path, directive: &str) -> (common::KillOnDrop, u16) {
    let location = format!("root {};", dir.display());
    start_with(dir, directive, &location)
}

fn start_with(dir: &Path, directive: &str, location: &str) -> (common::KillOnDrop, u16) {
    let setup = common::ports::setup_lock();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "pid {d}/ruxen.pid;\nerror_log {d}/error.log;\n{directive}\nevents {{}}\n\
             http {{\n\
             server {{ listen 127.0.0.1:{port}; location / {{ {location} }} }}\n\
             }}\n",
            d = dir.display()
        ),
    )
    .unwrap();
    // Owned by the guard before the wait: if it panics, ruxen still stops.
    let mut child = common::KillOnDrop(
        Command::new(env!("CARGO_BIN_EXE_ruxen"))
            .arg("-c")
            .arg(dir.join("nginx.conf"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    common::ports::wait_for_pid_file(&mut child, &dir.join("ruxen.pid"), Duration::from_secs(3));
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
    drop(child);
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

/// SIGQUIT closes the listening sockets at once, as nginx does
/// (ngx_close_listening_sockets in the master and each worker): a client
/// that connects during the drain is refused instead of waiting in a
/// backlog nobody accepts from, while the download in flight goes on (#552).
#[test]
fn quit_refuses_new_connections_during_the_drain() {
    let dir = std::env::temp_dir().join(format!("ruxen-m79-refuse-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::File::create(dir.join("big.bin"))
        .unwrap()
        .set_len(256 << 20)
        .unwrap();
    // Two workers: each has its own socket for the address.
    let (mut child, port) = start(&dir, "worker_processes 2;");
    let mut client = stalled_download(port);
    // Held from here: once ruxen lets the port go, another test could take
    // it, and the connect below would reach that test's server.
    let _setup = common::ports::setup_lock();
    unsafe {
        assert_eq!(kill(child.id() as i32, SIGQUIT), 0);
    }
    let sent = Instant::now();
    loop {
        match TcpStream::connect(("127.0.0.1", port)) {
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => break,
            other => assert!(
                sent.elapsed() < Duration::from_secs(1),
                "still accepting connections: {other:?}"
            ),
        }
        sleep(Duration::from_millis(10));
    }
    // The download goes on, and keeps the server up.
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut buf = vec![0; 1 << 20];
    for _ in 0..16 {
        assert!(client.read(&mut buf).unwrap() > 0);
    }
    assert!(
        child.try_wait().unwrap().is_none(),
        "exited during the drain"
    );
    drop(child);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The timeout closes the connections and lets their requests end, as
/// nginx's ngx_shutdown_timer_handler does: a request waiting for a silent
/// upstream sees it close, and that is logged before the process exits.
#[test]
fn the_timeout_ends_requests_in_progress() {
    let dir = std::env::temp_dir().join(format!("ruxen-m79-proxy-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // Takes the request and never answers.
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_port = upstream.local_addr().unwrap().port();
    let silent = std::thread::spawn(move || {
        let (mut s, _) = upstream.accept().unwrap();
        let mut buf = [0; 1024];
        let _ = s.read(&mut buf);
        sleep(Duration::from_secs(3));
    });

    let (mut child, port) = start_with(
        &dir,
        "worker_shutdown_timeout 100ms;",
        &format!("proxy_pass http://127.0.0.1:{upstream_port}; proxy_read_timeout 10s;"),
    );
    let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        .unwrap();
    sleep(Duration::from_millis(200));
    let exited = quit(&mut child, Duration::from_secs(3));
    if exited.is_none() {
        let _ = child.kill();
        let _ = child.wait();
    }
    let error_log = std::fs::read_to_string(dir.join("error.log")).unwrap_or_default();
    let _ = std::fs::remove_dir_all(&dir);
    drop(client);
    silent.join().unwrap();

    exited.expect("still running 3 s after SIGQUIT");
    assert!(
        error_log.contains("upstream prematurely closed connection"),
        "{error_log}"
    );
}
