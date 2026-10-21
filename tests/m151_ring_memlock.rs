//! M151 — io_uring rings under a small `RLIMIT_MEMLOCK` (#612). Linux 7.0
//! charges each ring to the user's memlock limit; when the workers'
//! 4096-entry rings don't fit it together, they take smaller ones instead
//! of failing the start. The only test in its binary: the limit is summed
//! over the user's processes, so other servers' rings would eat into it.

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::Duration;

struct KillOnDrop(std::process::Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn m151_workers_fit_their_rings_into_rlimit_memlock() {
    let dir = std::env::temp_dir().join(format!("ruxen-m151-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let setup = common::ports::setup_lock();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "worker_processes 4;\nerror_log {}/error.log warn;\n\
             events {{}}\nhttp {{ access_log off;\n\
             server {{ listen 127.0.0.1:{port}; location / {{ return 200 \"ok\\n\"; }} }} }}\n",
            dir.display()
        ),
    )
    .unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ruxen"));
    cmd.arg("-c")
        .arg(dir.join("nginx.conf"))
        .arg("-g")
        .arg(format!("pid {}/ruxen.pid;", dir.display()))
        .env_remove("RUXEN_DRIVER")
        .env_remove("RUXEN_WORKERS")
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // Four 4096-entry rings take about 2 MiB; four 1024-entry ones fit.
    // SAFETY: setrlimit is async-signal-safe and touches only the child.
    unsafe {
        cmd.pre_exec(|| {
            let lim = libc::rlimit {
                rlim_cur: 1536 << 10,
                rlim_max: 1536 << 10,
            };
            if libc::setrlimit(libc::RLIMIT_MEMLOCK, &lim) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = KillOnDrop(cmd.spawn().unwrap());
    common::ports::wait_for_pid_file(&mut child.0, &dir.join("ruxen.pid"), Duration::from_secs(5));
    drop(setup);
    let log = std::fs::read_to_string(dir.join("error.log")).unwrap_or_default();
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    write!(s, "GET / HTTP/1.0\r\n\r\n").unwrap();
    let mut body = String::new();
    let _ = s.read_to_string(&mut body);
    assert!(body.starts_with("HTTP/1.1 200"), "{body}\n{log}");
    assert!(log.contains("[warn]"), "{log}");
    assert!(
        log.contains(
            "the io_uring rings of 4 workers at 4096 entries exceed \
             RLIMIT_MEMLOCK (1536 KiB), using 1024 entries"
        ),
        "{log}"
    );
    drop(child);
    let _ = std::fs::remove_dir_all(&dir);
}
