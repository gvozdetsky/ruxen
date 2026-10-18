//! M142 — a FIFO under `root` is a 404 with nginx's `[crit] "<path>" is
//! not a regular file`, and doesn't stop the worker (#520): the request's
//! file is opened with O_NONBLOCK, as ngx_open_and_stat_file does, where a
//! blocking open would wait for a writer on the worker thread.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::time::Duration;

fn get(port: u16, path: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(format!("GET {path} HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n").as_bytes())
        .unwrap();
    let mut raw = String::new();
    s.read_to_string(&mut raw)
        .unwrap_or_else(|e| panic!("{path}: {e} (the worker is stuck)"));
    raw
}

#[test]
fn fifo_under_root_is_a_404_and_the_worker_goes_on() {
    let dir = std::env::temp_dir().join(format!("ruxen-m142-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let html = dir.join("html");
    std::fs::create_dir_all(&html).unwrap();
    std::fs::write(html.join("a.txt"), "a\n").unwrap();
    let fifo = html.join("fifo");
    let c_fifo = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(c_fifo.as_ptr(), 0o644) }, 0);
    let setup = common::ports::setup_lock();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "worker_processes 1;\npid {d}/ruxen.pid;\nerror_log {d}/error.log;\n\
             events {{}}\nhttp {{\naccess_log off;\n\
             server {{ listen 127.0.0.1:{port}; root {d}/html;\n\
             location /strict/ {{ disable_symlinks on; alias {d}/html/; }} }}\n}}\n",
            d = dir.display()
        ),
    )
    .unwrap();
    let mut child = common::KillOnDrop(
        Command::new(env!("CARGO_BIN_EXE_ruxen"))
            .arg("-c")
            .arg(dir.join("nginx.conf"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    common::ports::wait_for_pid_file(&mut child, &dir.join("ruxen.pid"), Duration::from_secs(5));
    drop(setup);

    // `disable_symlinks on` opens through openat2_no_symlinks, the
    // default through openat2_beneath.
    for path in ["/fifo", "/strict/fifo"] {
        let raw = get(port, path);
        assert!(raw.starts_with("HTTP/1.1 404 "), "{path}: {raw}");
    }
    let raw = get(port, "/a.txt");
    assert!(
        raw.starts_with("HTTP/1.1 200 ") && raw.ends_with("a\n"),
        "{raw}"
    );

    let _ = child.0.kill();
    let _ = child.0.wait();
    let log = std::fs::read_to_string(dir.join("error.log")).unwrap_or_default();
    let _ = std::fs::remove_dir_all(&dir);
    let line = "[crit] ";
    let wanted = format!("\"{}\" is not a regular file", fifo.display());
    assert_eq!(
        log.lines()
            .filter(|l| l.contains(line) && l.contains(&wanted))
            .count(),
        2,
        "{log}"
    );
}
