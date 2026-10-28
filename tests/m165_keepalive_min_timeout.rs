//! M165 — `keepalive_min_timeout` (nginx 1.27.4, #601): for that long
//! after a response a keep-alive connection isn't closed by a graceful
//! shutdown (or a reload, or a drain), as ngx_http_set_keepalive keeps it
//! out of the idle ones. A request in that time is served, with
//! `Connection: close`; after it the connection closes.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::thread::sleep;
use std::time::{Duration, Instant};

unsafe extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
}

const SIGQUIT: i32 = 3;

fn start(dir: &Path, http: &str) -> (common::KillOnDrop, u16) {
    let setup = common::ports::setup_lock();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "pid {d}/ruxen.pid;\nerror_log {d}/error.log;\nevents {{}}\n\
             http {{ access_log off; {http}\n\
             server {{ listen 127.0.0.1:{port}; location / {{ return 200 ok; }} }}\n\
             }}\n",
            d = dir.display()
        ),
    )
    .unwrap();
    let mut child = common::KillOnDrop(
        std::process::Command::new(env!("CARGO_BIN_EXE_ruxen"))
            .arg("-c")
            .arg(dir.join("nginx.conf"))
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap(),
    );
    common::ports::wait_for_pid_file(&mut child, &dir.join("ruxen.pid"), Duration::from_secs(3));
    drop(setup);
    (child, port)
}

/// One request on `s`; the response head and body as text.
fn get(s: &mut TcpStream) -> String {
    s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
    let mut out = Vec::new();
    let mut buf = [0; 1024];
    while !out.ends_with(b"\r\n\r\nok") {
        let n = s.read(&mut buf).unwrap_or(0);
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n]);
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// How long until the server closes `s`, which sends nothing more.
fn closed_after(s: &mut TcpStream, since: Instant) -> Duration {
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut byte = [0; 1];
    assert!(matches!(s.read(&mut byte), Ok(0) | Err(_)));
    since.elapsed()
}

fn scratch(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("ruxen-m165-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn quit(child: &common::KillOnDrop) -> Instant {
    unsafe {
        assert_eq!(kill(child.0.id() as i32, SIGQUIT), 0);
    }
    Instant::now()
}

#[test]
fn shutdown_waits_for_the_minimum() {
    let dir = scratch("shutdown");
    let (mut child, port) = start(&dir, "keepalive_timeout 10s; keepalive_min_timeout 1500ms;");
    let mut a = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let mut b = TcpStream::connect(("127.0.0.1", port)).unwrap();
    assert!(get(&mut a).starts_with("HTTP/1.1 200"));
    assert!(get(&mut b).starts_with("HTTP/1.1 200"));
    let sent = quit(&child);
    sleep(Duration::from_millis(300));
    // Still open, and served: the response says it is the last one.
    let r = get(&mut a);
    assert!(r.starts_with("HTTP/1.1 200"), "{r}");
    assert!(r.contains("Connection: close"), "{r}");
    let waited = closed_after(&mut b, sent);
    assert!(
        waited >= Duration::from_millis(1300) && waited < Duration::from_secs(5),
        "{waited:?}"
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    while child.0.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "still running");
        sleep(Duration::from_millis(20));
    }
}

#[test]
fn without_it_shutdown_closes_idle_connections() {
    let dir = scratch("idle");
    let (child, port) = start(&dir, "keepalive_timeout 10s;");
    let mut b = TcpStream::connect(("127.0.0.1", port)).unwrap();
    assert!(get(&mut b).starts_with("HTTP/1.1 200"));
    let sent = quit(&child);
    let waited = closed_after(&mut b, sent);
    assert!(waited < Duration::from_millis(1000), "{waited:?}");
}

/// Not shutting down, the minimum doesn't add to `keepalive_timeout`.
#[test]
fn the_idle_timeout_is_unchanged() {
    let dir = scratch("timeout");
    let (_child, port) = start(
        &dir,
        "keepalive_timeout 1500ms; keepalive_min_timeout 500ms;",
    );
    let mut b = TcpStream::connect(("127.0.0.1", port)).unwrap();
    assert!(get(&mut b).starts_with("HTTP/1.1 200"));
    let waited = closed_after(&mut b, Instant::now());
    assert!(
        waited >= Duration::from_millis(1300) && waited < Duration::from_millis(3000),
        "{waited:?}"
    );
}
