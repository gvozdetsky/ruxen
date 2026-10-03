//! M59 — SIGUSR1 reopens the log files, as nginx does: after logrotate's
//! `mv access.log access.log.1; kill -USR1`, new lines go to a fresh
//! `access.log` (and the `-e` error log is reopened too). ruxen used to
//! ignore SIGUSR1 and keep writing into the rotated file.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

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

fn start() -> Server {
    let port = {
        let probe = TcpListener::bind("127.0.0.1:0").unwrap();
        probe.local_addr().unwrap().port()
    };
    let dir = std::env::temp_dir().join(format!("ruxen-m59-{}-{port}", std::process::id()));
    std::fs::create_dir_all(dir.join("www")).unwrap();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "events {{}}\nhttp {{ log_format p $uri; server {{ listen 127.0.0.1:{port};\n\
             access_log {d}/access.log p;\n\
             location / {{ root {d}/www; }} }} }}\n",
            d = dir.display()
        ),
    )
    .unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .arg("-c")
        .arg(dir.join("nginx.conf"))
        .arg("-e")
        .arg(dir.join("error.log"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "ruxen did not start");
        sleep(Duration::from_millis(20));
    }
    Server { child, port, dir }
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
    let server = start();
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
        errors.contains("open() \"/after\" failed"),
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
