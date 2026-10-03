//! M60 — `-s stop|quit|reopen` signal the running instance through the
//! config's `pid` file, as nginx's `ngx_signal_process`. `-s reload` is
//! refused (ruxen can't re-read its config); unknown names are nginx's
//! `invalid option`. It used to be "not supported yet" for every name.

use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

struct Dir(PathBuf);

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn setup(tag: &str) -> (Dir, u16) {
    let port = {
        let probe = TcpListener::bind("127.0.0.1:0").unwrap();
        probe.local_addr().unwrap().port()
    };
    let dir = std::env::temp_dir().join(format!("ruxen-m60-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "pid {d}/ruxen.pid;\nevents {{}}\nhttp {{ server {{ listen 127.0.0.1:{port}; \
             location / {{ return 200 ok; }} }} }}\n",
            d = dir.display()
        ),
    )
    .unwrap();
    (Dir(dir), port)
}

fn ruxen(dir: &Dir, args: &[&str]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ruxen"));
    cmd.args(args).arg("-c").arg(dir.0.join("nginx.conf"));
    cmd
}

fn run(dir: &Dir, args: &[&str]) -> Output {
    ruxen(dir, args).output().unwrap()
}

fn start(dir: &Dir, port: u16) -> Child {
    let child = ruxen(dir, &[])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    while TcpStream::connect(("127.0.0.1", port)).is_err() || !dir.0.join("ruxen.pid").exists() {
        assert!(Instant::now() < deadline, "ruxen did not start");
        sleep(Duration::from_millis(20));
    }
    child
}

#[test]
fn quit_signals_the_running_instance() {
    let (dir, port) = setup("quit");
    let mut child = start(&dir, port);

    let out = run(&dir, &["-s", "reopen"]);
    assert!(out.status.success(), "{out:?}");
    assert!(child.try_wait().unwrap().is_none(), "reopen stopped it");

    let out = run(&dir, &["-s", "quit"]);
    assert!(out.status.success(), "{out:?}");
    let deadline = Instant::now() + Duration::from_secs(5);
    while child.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "-s quit didn't stop it");
        sleep(Duration::from_millis(20));
    }
}

/// Waits for `child` to exit and returns its exit code; `None` if a signal
/// killed it.
fn exit_code(child: &mut Child, within: Duration, what: &str) -> Option<i32> {
    let deadline = Instant::now() + within;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status.code();
        }
        assert!(Instant::now() < deadline, "{what} didn't stop it");
        sleep(Duration::from_millis(20));
    }
}

/// A request that has started but will never finish: SIGQUIT would wait
/// for it, SIGTERM / SIGINT must not.
fn hold_a_request(port: u16) -> TcpStream {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n").unwrap();
    sleep(Duration::from_millis(50));
    s
}

#[test]
fn stop_is_a_fast_shutdown() {
    let (dir, port) = setup("stop");
    let mut child = start(&dir, port);
    let _held = hold_a_request(port);

    let out = run(&dir, &["-s", "stop"]);
    assert!(out.status.success(), "{out:?}");
    // nginx exits 0 and deletes its pid file; the default SIGTERM action
    // killed ruxen and left the file behind.
    assert_eq!(
        exit_code(&mut child, Duration::from_secs(2), "-s stop"),
        Some(0)
    );
    assert!(!dir.0.join("ruxen.pid").exists(), "pid file left behind");
}

#[test]
fn sigint_is_a_fast_shutdown() {
    let (dir, port) = setup("int");
    let mut child = start(&dir, port);
    let _held = hold_a_request(port);

    assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGINT) }, 0);
    assert_eq!(
        exit_code(&mut child, Duration::from_secs(2), "SIGINT"),
        Some(0)
    );
    assert!(!dir.0.join("ruxen.pid").exists(), "pid file left behind");
}

/// `-s stop` during a graceful shutdown that is waiting for a request
/// turns it into a fast one, as in nginx.
#[test]
fn stop_cuts_a_graceful_shutdown_short() {
    let (dir, port) = setup("quit-then-stop");
    let mut child = start(&dir, port);
    let _held = hold_a_request(port);

    let out = run(&dir, &["-s", "quit"]);
    assert!(out.status.success(), "{out:?}");
    sleep(Duration::from_millis(200));
    assert!(
        child.try_wait().unwrap().is_none(),
        "quit didn't wait for the request"
    );

    assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGTERM) }, 0);
    assert_eq!(
        exit_code(&mut child, Duration::from_secs(2), "SIGTERM"),
        Some(0)
    );
    assert!(!dir.0.join("ruxen.pid").exists(), "pid file left behind");
}

#[test]
fn errors_like_nginx() {
    let (dir, _port) = setup("errors");
    // Nothing running: no pid file.
    let out = run(&dir, &["-s", "stop"]);
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(&format!(
            "[error] open() \"{}\" failed (2: No such file or directory)",
            dir.0.join("ruxen.pid").display()
        )),
        "{stderr}"
    );

    let out = run(&dir, &["-s", "reload"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("`-s reload` is not supported yet"));

    let out = run(&dir, &["-s", "bogus"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("invalid option: \"-s bogus\""));
}
