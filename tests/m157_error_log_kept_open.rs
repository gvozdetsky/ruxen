//! M157 — an `error_log` file is opened once, in `prepare`, and each thread
//! writes to its descriptor for it, as nginx keeps `open_files` (#648),
//! instead of opening, writing and closing it for every line on the event
//! loop. A FIFO's reader then stays (it used to get end of file at startup,
//! and the first error line blocked the worker in `open()`), and SIGUSR1
//! still moves the lines to a new file after logrotate.

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

struct KillOnDrop(std::process::Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn start(dir: &Path, error_log: &Path) -> (KillOnDrop, u16) {
    let setup = common::ports::setup_lock();
    let [port] = common::ports::free_ports();
    std::fs::create_dir_all(dir.join("www")).unwrap();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "worker_processes 1;\nerror_log {e} error;\npid {d}/ruxen.pid;\nevents {{}}\n\
             http {{ access_log off; server {{ listen 127.0.0.1:{port}; root {d}/www; }} }}\n",
            d = dir.display(),
            e = error_log.display()
        ),
    )
    .unwrap();
    let mut child = KillOnDrop(
        Command::new(env!("CARGO_BIN_EXE_ruxen"))
            .arg("-c")
            .arg(dir.join("nginx.conf"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    common::ports::wait_for_pid_file(&mut child.0, &dir.join("ruxen.pid"), Duration::from_secs(5));
    drop(setup);
    (child, port)
}

/// A request for a missing file: a 404 and an `open() … failed` line.
fn missing(port: u16, name: &str) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    write!(s, "GET /{name} HTTP/1.0\r\n\r\n").unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    assert!(out.starts_with("HTTP/1.1 404"), "{name}: {out}");
}

#[test]
fn m157_a_fifo_error_log_keeps_its_reader() {
    let dir = std::env::temp_dir().join(format!("ruxen-m157-fifo-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let fifo = dir.join("fifo");
    let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
    // SAFETY: a NUL-terminated path.
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    let (tx, rx) = mpsc::channel();
    let reader = fifo.clone();
    std::thread::spawn(move || {
        let mut text = String::new();
        let _ = std::fs::File::open(reader).and_then(|mut f| f.read_to_string(&mut text));
        let _ = tx.send(text);
    });
    let (child, port) = start(&dir, &fifo);
    for name in ["a", "b", "c"] {
        missing(port, name);
    }
    assert!(rx.try_recv().is_err(), "the reader got end of file early");
    drop(child);
    let text = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    for name in ["a", "b", "c"] {
        assert!(text.contains(&format!("/www/{name}\" failed")), "{text}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn m157_sigusr1_moves_error_lines_to_the_new_file() {
    let dir = std::env::temp_dir().join(format!("ruxen-m157-rot-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let log = dir.join("error.log");
    let (child, port) = start(&dir, &log);
    missing(port, "before");
    std::fs::rename(&log, dir.join("error.log.1")).unwrap();
    // SAFETY: a signal to the child we started.
    assert_eq!(unsafe { libc::kill(child.0.id() as i32, libc::SIGUSR1) }, 0);
    std::thread::sleep(Duration::from_millis(300));
    missing(port, "after");
    std::thread::sleep(Duration::from_millis(100));
    let old = std::fs::read_to_string(dir.join("error.log.1")).unwrap();
    let new = std::fs::read_to_string(&log).unwrap();
    assert!(
        old.contains("/www/before\"") && !old.contains("/www/after\""),
        "{old}"
    );
    assert!(
        new.contains("/www/after\"") && !new.contains("/www/before\""),
        "{new}"
    );
    drop(child);
    let _ = std::fs::remove_dir_all(&dir);
}
