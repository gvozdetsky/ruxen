//! M59 — SIGUSR1 reopens the log files, as nginx does: after logrotate's
//! `mv access.log access.log.1; kill -USR1`, new lines go to a fresh
//! `access.log` (and the `-e` error log is reopened too). ruxen used to
//! ignore SIGUSR1 and keep writing into the rotated file.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread::sleep;
use std::time::Duration;

struct Server {
    child: Child,
    port: u16,
    dir: PathBuf,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// `extra`: more directives for the server, with `{d}` for its directory.
fn start(extra: &str) -> Server {
    // Held from the port pick until ruxen listens: a parallel test's
    // backend can't take the port in between (#230).
    let setup = common::ports::setup_lock();
    let port = {
        let probe = TcpListener::bind("127.0.0.1:0").unwrap();
        probe.local_addr().unwrap().port()
    };
    let dir = std::env::temp_dir().join(format!("ruxen-m59-{}-{port}", std::process::id()));
    std::fs::create_dir_all(dir.join("www")).unwrap();
    std::fs::create_dir_all(dir.join("b")).unwrap();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "events {{}}\nhttp {{ log_format p $uri; server {{ listen 127.0.0.1:{port};\n\
             access_log {d}/access.log p;\n{extra}\n\
             location / {{ root {d}/www; }} }} }}\n",
            d = dir.display(),
            extra = extra.replace("{d}", &dir.display().to_string()),
        ),
    )
    .unwrap();
    // Owned by `Server` before the wait: if it panics, ruxen still stops.
    let mut server = Server {
        child: Command::new(env!("CARGO_BIN_EXE_ruxen"))
            .arg("-c")
            .arg(dir.join("nginx.conf"))
            .arg("-g")
            .arg(format!("pid {}/ruxen.pid;", dir.display()))
            .arg("-e")
            .arg(dir.join("error.log"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
        port,
        dir,
    };
    let pid_file = server.dir.join("ruxen.pid");
    common::ports::wait_for_pid_file(&mut server.child, &pid_file, Duration::from_secs(3));
    drop(setup);
    server
}

fn get(port: u16, path: &str) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
}

fn read(path: PathBuf) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

#[test]
fn sigusr1_reopens_rotated_logs() {
    let server = start("");
    let dir = &server.dir;
    get(server.port, "/before");
    sleep(Duration::from_millis(50));

    std::fs::rename(dir.join("access.log"), dir.join("access.log.1")).unwrap();
    std::fs::rename(dir.join("error.log"), dir.join("error.log.1")).unwrap();
    let rc = unsafe { libc::kill(server.child.id() as i32, libc::SIGUSR1) };
    assert_eq!(rc, 0);
    sleep(Duration::from_millis(100));

    // A missing file under the root logs an `[error]` line too.
    get(server.port, "/after");
    sleep(Duration::from_millis(50));

    assert_eq!(read(dir.join("access.log.1")), "/before\n");
    assert_eq!(read(dir.join("access.log")), "/after\n");
    let errors = read(dir.join("error.log"));
    assert!(
        errors.contains("/www/after\" failed"),
        "new: {errors:?} old: {:?}",
        read(dir.join("error.log.1"))
    );
    assert!(
        !read(dir.join("error.log.1")).contains("/after"),
        "error line went to the rotated file"
    );
    // Still alive.
    assert!(server.child.id() > 0);
    get(server.port, "/again");
}

/// Each access_log is reopened on its own, as ngx_reopen_files: one that
/// can't be opened keeps its old file and is logged at `emerg`, and the
/// others still move to their new files (#522).
#[test]
fn a_log_that_cant_be_reopened_keeps_its_file_alone() {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } == 0 {
        return; // root opens the read-only directory anyway
    }
    let server = start("access_log {d}/b/b.log p;");
    let dir = &server.dir;
    get(server.port, "/before");
    sleep(Duration::from_millis(50));
    std::fs::rename(dir.join("access.log"), dir.join("access.log.1")).unwrap();
    std::fs::rename(dir.join("b/b.log"), dir.join("b/b.log.1")).unwrap();
    let b = dir.join("b");
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&b, std::fs::Permissions::from_mode(0o555)).unwrap();
    let rc = unsafe { libc::kill(server.child.id() as i32, libc::SIGUSR1) };
    assert_eq!(rc, 0);
    sleep(Duration::from_millis(100));
    get(server.port, "/after");
    sleep(Duration::from_millis(50));
    std::fs::set_permissions(&b, std::fs::Permissions::from_mode(0o755)).unwrap();

    assert_eq!(read(dir.join("access.log.1")), "/before\n");
    assert_eq!(read(dir.join("access.log")), "/after\n");
    assert_eq!(read(dir.join("b/b.log.1")), "/before\n/after\n");
    assert!(!dir.join("b/b.log").exists());
    let errors = read(dir.join("error.log"));
    assert!(
        errors.contains("[emerg]") && errors.contains("b.log\" failed (13: Permission denied)"),
        "{errors}"
    );
}
