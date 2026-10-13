//! M104 — buffered access logs (#151): `buffer=`, `flush=` and `gzip`, as
//! nginx's log module keeps them: lines collect in a per-worker buffer per
//! file and go out when it is full, `flush` after the first line, before a
//! reopen (SIGUSR1), when ruxen stops (SIGQUIT) and at SIGTERM. With
//! `gzip` each write is a gzip member.

mod common;

use std::io::Read;
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn setup(name: &str) -> (PathBuf, u16) {
    let dir = std::env::temp_dir().join(format!("ruxen-m104-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let port = {
        let _setup = common::ports::setup_lock();
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    };
    let d = dir.display();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "worker_processes 1;\npid {d}/ruxen.pid;\nevents {{}}\nhttp {{\n\
             log_format u '$uri';\n\
             server {{ listen 127.0.0.1:{port};\n\
             location /b {{ access_log {d}/b.log u buffer=1k; return 200; }}\n\
             location /f {{ access_log {d}/f.log u buffer=64k flush=200ms; return 200; }}\n\
             location /z {{ access_log {d}/z.log u gzip; return 200; }}\n\
             location /k {{ access_log {d}/k.log u buffer=64k; return 200; }}\n\
             }} }}\n"
        ),
    )
    .unwrap();
    (dir, port)
}

fn start(dir: &Path, port: u16) -> Child {
    let child = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .arg("-c")
        .arg(dir.join("nginx.conf"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "ruxen did not start");
        std::thread::sleep(Duration::from_millis(20));
    }
    child
}

fn get(port: u16, path: &str) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    use std::io::Write;
    write!(s, "GET {path} HTTP/1.0\r\n\r\n").unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    assert!(out.starts_with("HTTP/1.1 200"), "{out}");
}

fn lines(path: &Path) -> usize {
    std::fs::read_to_string(path).map_or(0, |t| t.lines().count())
}

fn signal(child: &Child, sig: &str) {
    Command::new("kill")
        .args([sig, &child.id().to_string()])
        .status()
        .unwrap();
}

#[test]
fn m104_buffer_flush_and_gzip() {
    let (dir, port) = setup("buf");
    let mut child = start(&dir, port);
    // 1k buffer, 45-byte lines: 22 fit, the 23rd makes them go out.
    for i in 0..30 {
        get(port, &format!("/b/{i:041}"));
    }
    assert_eq!(lines(&dir.join("b.log")), 22);
    // `flush=200ms`: nothing at first, the line after the timer.
    get(port, "/f/one");
    assert_eq!(lines(&dir.join("f.log")), 0);
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(lines(&dir.join("f.log")), 1);
    for i in 0..3 {
        get(port, &format!("/z/{i}"));
    }
    // SIGQUIT: the worker writes its buffers on its way out.
    signal(&child, "-QUIT");
    child.wait().unwrap();
    assert_eq!(lines(&dir.join("b.log")), 30);
    let gz = std::fs::read(dir.join("z.log")).unwrap();
    let mut text = String::new();
    flate2::read::MultiGzDecoder::new(&gz[..])
        .read_to_string(&mut text)
        .unwrap();
    assert_eq!(text, "/z/0\n/z/1\n/z/2\n");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn m104_reopen_and_sigterm_write_the_buffer() {
    let (dir, port) = setup("term");
    let mut child = start(&dir, port);
    get(port, "/k/before-reopen");
    // logrotate: move the file, then SIGUSR1. The buffered line belongs
    // to the old file.
    std::fs::rename(dir.join("k.log"), dir.join("k.log.1")).unwrap();
    signal(&child, "-USR1");
    std::thread::sleep(Duration::from_millis(300));
    get(port, "/k/after-reopen");
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(
        std::fs::read_to_string(dir.join("k.log.1")).unwrap(),
        "/k/before-reopen\n"
    );
    // SIGTERM: the lines still buffered aren't lost.
    signal(&child, "-TERM");
    child.wait().unwrap();
    assert_eq!(
        std::fs::read_to_string(dir.join("k.log")).unwrap(),
        "/k/after-reopen\n"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn m104_conflicting_buffers_for_one_file_are_refused() {
    let dir = std::env::temp_dir().join(format!("ruxen-m104-conf-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let d = dir.display();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "events {{}}\nhttp {{ server {{ listen 127.0.0.1:18104;\n\
             location /a {{ access_log {d}/x.log combined buffer=16k; }}\n\
             location /b {{ access_log {d}/x.log combined buffer=32k; }}\n\
             }} }}\n"
        ),
    )
    .unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .arg("-t")
        .arg("-c")
        .arg(dir.join("nginx.conf"))
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{stderr}");
    assert!(
        stderr.contains("already defined with conflicting parameters"),
        "{stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
