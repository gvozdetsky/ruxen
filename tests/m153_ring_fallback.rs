//! M153 — a worker that can't get an io_uring ring of any size (ENOMEM:
//! the user's `RLIMIT_MEMLOCK` is held by other rings) runs on epoll
//! instead of failing the start or a reload (#635). During a reload the
//! old generation's rings are still there, so a limit that fits one
//! generation fits only part of the next. Its own binary: the limit is
//! summed over the user's processes.

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

struct KillOnDrop(std::process::Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn get(port: u16) -> String {
    let Ok(mut s) = TcpStream::connect(("127.0.0.1", port)) else {
        return String::new();
    };
    let _ = write!(s, "GET / HTTP/1.0\r\n\r\n");
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out.split_once("\r\n\r\n")
        .map_or(String::new(), |(_, b)| b.to_string())
}

#[test]
fn m153_workers_without_a_ring_run_on_epoll() {
    let dir = std::env::temp_dir().join(format!("ruxen-m153-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let setup = common::ports::setup_lock();
    let [port] = common::ports::free_ports();
    let conf = |text: &str| {
        std::fs::write(
            dir.join("nginx.conf"),
            format!(
                "worker_processes 4;\nerror_log {d}/error.log warn;\npid {d}/ruxen.pid;\n\
                 events {{}}\nhttp {{ access_log off;\n\
                 server {{ listen 127.0.0.1:{port}; location / {{ return 200 \"{text}\"; }} }} }}\n",
                d = dir.display()
            ),
        )
        .unwrap();
    };
    conf("one");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ruxen"));
    cmd.arg("-c")
        .arg(dir.join("nginx.conf"))
        .env_remove("RUXEN_DRIVER")
        .env_remove("RUXEN_WORKERS")
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // Four 1024-entry rings by ruxen's estimate (512 KiB), and less than
    // the kernel charges for them with what the next generation needs.
    // SAFETY: setrlimit is async-signal-safe and touches only the child.
    unsafe {
        cmd.pre_exec(|| {
            let lim = libc::rlimit {
                rlim_cur: 600 << 10,
                rlim_max: 600 << 10,
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
    assert_eq!(get(port), "one");
    for text in ["two", "three"] {
        conf(text);
        // SAFETY: a signal to the child we started.
        assert_eq!(unsafe { libc::kill(child.0.id() as i32, libc::SIGHUP) }, 0);
        let deadline = Instant::now() + Duration::from_secs(5);
        while get(port) != text {
            let log = std::fs::read_to_string(dir.join("error.log")).unwrap_or_default();
            assert!(
                Instant::now() < deadline,
                "the reload didn't take over:\n{log}"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    let log = std::fs::read_to_string(dir.join("error.log")).unwrap_or_default();
    assert!(!log.contains("[emerg]"), "{log}");
    let _ = std::fs::remove_dir_all(&dir);
}
