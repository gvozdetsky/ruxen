//! M156 — each access_log is opened once, in `prepare`, and the workers
//! write to `dup`s of it, as nginx's workers inherit the master's
//! descriptor (#523). A FIFO's reader then sees one writer: it isn't sent
//! end of file by an open and close in `prepare`, and the workers don't
//! wait for a reader to open it again.

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
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

#[test]
fn m156_a_fifo_access_log_keeps_its_reader() {
    let dir = std::env::temp_dir().join(format!("ruxen-m156-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let fifo = dir.join("fifo");
    let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
    // SAFETY: a NUL-terminated path.
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    // The reader reads until end of file, as `cat` or a log shipper would.
    let (tx, rx) = mpsc::channel();
    let reader_path = fifo.clone();
    std::thread::spawn(move || {
        let mut text = String::new();
        let _ = std::fs::File::open(reader_path).and_then(|mut f| f.read_to_string(&mut text));
        let _ = tx.send(text);
    });
    let setup = common::ports::setup_lock();
    let [port] = common::ports::free_ports();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "worker_processes 2;\npid {d}/ruxen.pid;\nevents {{}}\nhttp {{\n\
             log_format u '$uri';\naccess_log {f} u;\n\
             server {{ listen 127.0.0.1:{port}; location / {{ return 200; }} }} }}\n",
            d = dir.display(),
            f = fifo.display()
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
    for path in ["/r1", "/r2", "/r3"] {
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        write!(s, "GET {path} HTTP/1.0\r\n\r\n").unwrap();
        let mut out = String::new();
        let _ = s.read_to_string(&mut out);
        assert!(out.starts_with("HTTP/1.1 200"), "{path}: {out}");
    }
    // The reader is still there: nothing has closed the last writer.
    assert!(rx.try_recv().is_err(), "the reader got end of file early");
    drop(child);
    let text = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(text, "/r1\n/r2\n/r3\n");
    let _ = std::fs::remove_dir_all(&dir);
}
