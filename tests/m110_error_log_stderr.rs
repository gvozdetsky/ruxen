//! M110 — `error_log stderr` with `-e` (#309): as nginx's log_use_stderr,
//! a configuration that logs to stderr keeps the real stderr; `-e` then
//! only takes the lines that have no error_log of their own. Without
//! `error_log stderr`, `-e` takes over stderr as before.

mod common;

use std::net::TcpStream;
use std::process::{Command, Stdio};
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

fn run(name: &str, location_log: &str) -> (String, String) {
    let dir = std::env::temp_dir().join(format!("ruxen-m110-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("html")).unwrap();
    // Held until ruxen listens: released earlier, another test could take
    // the same free port, and requests would reach its server.
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
            "events {{}}\nhttp {{ access_log off;\n\
             server {{ listen 127.0.0.1:{port}; root {d}/html;\n\
             location /logged {{ {location_log} }}\n\
             location /plain {{ }}\n\
             }} }}\n"
        ),
    )
    .unwrap();
    let stderr = std::fs::File::create(dir.join("stderr")).unwrap();
    let mut child = KillOnDrop(
        Command::new(env!("CARGO_BIN_EXE_ruxen"))
            .arg("-e")
            .arg(dir.join("error.log"))
            .arg("-c")
            .arg(dir.join("nginx.conf"))
            .arg("-g")
            .arg(format!("pid {d}/ruxen.pid;"))
            .stdout(Stdio::null())
            .stderr(stderr)
            .spawn()
            .unwrap(),
    );
    common::ports::wait_for_pid_file(&mut child.0, &dir.join("ruxen.pid"), Duration::from_secs(5));
    drop(setup);
    for path in ["/logged/missing-a", "/plain/missing-b"] {
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        use std::io::{Read, Write};
        write!(s, "GET {path} HTTP/1.0\r\n\r\n").unwrap();
        let _ = s.read_to_end(&mut Vec::new());
    }
    std::thread::sleep(Duration::from_millis(200));
    child.stop();
    let read = |f: &str| std::fs::read_to_string(dir.join(f)).unwrap_or_default();
    let out = (read("stderr"), read("error.log"));
    let _ = std::fs::remove_dir_all(&dir);
    out
}

#[test]
fn m110_error_log_stderr_keeps_stderr() {
    let (stderr, errlog) = run("kept", "error_log stderr info;");
    assert!(stderr.contains("missing-a\" failed"), "stderr: {stderr}");
    assert!(!errlog.contains("missing-a"), "error.log: {errlog}");
    // No error_log of its own: the -e file.
    assert!(errlog.contains("missing-b\" failed"), "error.log: {errlog}");
    assert!(!stderr.contains("missing-b"), "stderr: {stderr}");
}

#[test]
fn m110_without_error_log_stderr_e_takes_stderr() {
    let (stderr, errlog) = run("taken", "");
    assert!(errlog.contains("missing-a\" failed"), "error.log: {errlog}");
    assert!(errlog.contains("missing-b\" failed"), "error.log: {errlog}");
    assert!(!stderr.contains("failed"), "stderr: {stderr}");
}
