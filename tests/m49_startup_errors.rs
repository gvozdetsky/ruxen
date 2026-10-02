//! M49 — startup failures are `[emerg]` lines and exit status 1, never a
//! panic. Everything that depends on the filesystem (certificates, root
//! directories, log files) is checked by `-t` as well, like `nginx -t`; a
//! busy port is reported once, not once per worker, and leaves no pid file.

mod common;

use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "ruxen-m49-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir(&dir).unwrap();
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn write_conf(&self, http_body: &str) -> PathBuf {
        let conf = self.0.join("nginx.conf");
        std::fs::write(
            &conf,
            format!(
                "pid {}/ruxen.pid;\nevents {{}}\nhttp {{\n{http_body}\n}}\n",
                self.0.display()
            ),
        )
        .unwrap();
        conf
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn ruxen(dir: &TempDir, conf: &Path, extra: &[&str]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ruxen"));
    cmd.arg("-p")
        .arg(format!("{}/", dir.path().display()))
        .arg("-c")
        .arg(conf)
        .args(extra)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd
}

/// Run to completion, failing the test instead of hanging if ruxen starts
/// serving when it should have refused to.
fn run_expecting_exit(mut cmd: Command) -> Output {
    let mut child = cmd.spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("ruxen kept running; expected a startup failure");
        }
        sleep(Duration::from_millis(20));
    }
    child.wait_with_output().unwrap()
}

fn assert_emerg(out: &Output, expected: &str) {
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "stderr: {stderr}");
    assert!(!stderr.contains("panicked"), "stderr: {stderr}");
    assert_eq!(stderr.matches("[emerg]").count(), 1, "stderr: {stderr}");
    assert!(
        stderr.contains(&format!("ruxen: [emerg] {expected}")),
        "stderr: {stderr}"
    );
}

#[test]
fn test_mode_rejects_certificate_that_does_not_match_key() {
    let a = common::tls::make_self_signed("a.example");
    let b = common::tls::make_self_signed("b.example");
    let dir = TempDir::new("certkey");
    let conf = dir.write_conf(&format!(
        "server {{ listen 127.0.0.1:1 ssl; ssl_certificate {}; ssl_certificate_key {}; }}",
        a.cert_path().display(),
        b.key_path().display()
    ));

    let out = run_expecting_exit(ruxen(&dir, &conf, &["-t"]));
    assert_emerg(
        &out,
        &format!(
            "cannot load certificate \"{}\" with key \"{}\"",
            a.cert_path().display(),
            b.key_path().display()
        ),
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(&format!(
            "configuration file {} test failed",
            conf.display()
        )),
        "stderr: {stderr}"
    );

    // Without `-t` it is the same single line, not a panic.
    let out = run_expecting_exit(ruxen(&dir, &conf, &[]));
    assert_emerg(&out, "cannot load certificate");
    assert!(!dir.path().join("ruxen.pid").exists());
}

#[test]
fn test_mode_rejects_missing_root() {
    let dir = TempDir::new("root");
    let missing = dir.path().join("no-such-dir");
    let conf = dir.write_conf(&format!(
        "server {{ listen 127.0.0.1:1; root {}; }}",
        missing.display()
    ));

    let expected = format!(
        "root \"{}\" is not accessible: realpath() failed (2: No such file or directory)",
        missing.display()
    );
    let out = run_expecting_exit(ruxen(&dir, &conf, &["-t"]));
    assert_emerg(&out, &expected);

    // Like nginx, a config-time `[emerg]` also goes to the `-e` log, which
    // Test::Nginx reads after the test.
    let errlog = dir.path().join("error.log");
    let out = run_expecting_exit(ruxen(&dir, &conf, &["-e", errlog.to_str().unwrap()]));
    assert_emerg(&out, &expected);
    let logged = std::fs::read_to_string(&errlog).unwrap();
    assert!(
        logged.contains(&format!("ruxen: [emerg] {expected}")),
        "error.log: {logged}"
    );
}

#[test]
fn busy_port_is_one_emerg_and_no_pid_file() {
    // A plain listener has no SO_REUSEPORT, so ruxen's bind must fail.
    let held = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = held.local_addr().unwrap().port();
    let dir = TempDir::new("busy");
    let conf = dir.write_conf(&format!(
        "server {{ listen 127.0.0.1:{port}; location / {{ return 200 ok; }} }}"
    ));

    let mut cmd = ruxen(&dir, &conf, &[]);
    cmd.env("RUXEN_WORKERS", "4");
    let out = run_expecting_exit(cmd);
    assert_emerg(
        &out,
        &format!("bind() to 127.0.0.1:{port} failed (98: Address already in use)"),
    );
    assert!(!dir.path().join("ruxen.pid").exists());
}

#[test]
fn pid_file_appears_once_listening() {
    let port = {
        let probe = TcpListener::bind("127.0.0.1:0").unwrap();
        probe.local_addr().unwrap().port()
    };
    let dir = TempDir::new("pid");
    let conf = dir.write_conf(&format!(
        "server {{ listen 127.0.0.1:{port}; location / {{ return 200 ok; }} }}"
    ));
    let pid_path = dir.path().join("ruxen.pid");

    let mut cmd = ruxen(&dir, &conf, &[]);
    cmd.env("RUXEN_WORKERS", "4")
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = cmd.spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !pid_path.exists() {
        assert!(Instant::now() < deadline, "pid file never appeared");
        sleep(Duration::from_millis(5));
    }
    // Test::Nginx treats the pid file as "started": the port must already
    // accept connections at that point.
    let connected = TcpStream::connect(("127.0.0.1", port));
    let _ = child.kill();
    let _ = child.wait();
    connected.expect("pid file written before the listener was bound");
}

#[test]
fn http_without_servers_starts() {
    // nginx runs with an empty `http {}`; it just listens nowhere.
    let dir = TempDir::new("noservers");
    let conf = dir.write_conf("");

    let out = run_expecting_exit(ruxen(&dir, &conf, &["-t"]));
    assert_eq!(out.status.code(), Some(0));

    let mut child = ruxen(&dir, &conf, &[]).spawn().unwrap();
    let pid_path = dir.path().join("ruxen.pid");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !pid_path.exists() {
        assert!(
            child.try_wait().unwrap().is_none(),
            "ruxen exited with no servers"
        );
        assert!(Instant::now() < deadline, "pid file never appeared");
        sleep(Duration::from_millis(5));
    }
    let _ = child.kill();
    let _ = child.wait();
}
