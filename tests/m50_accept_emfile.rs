//! M50 — running out of file descriptors doesn't spin the accept loop.
//! With `RLIMIT_NOFILE` exhausted, `accept` fails immediately while the
//! connection stays queued; ruxen used to retry at once and pin a core.
//! Like nginx it now logs `accept() failed (24: …)` at `crit` and pauses
//! accepting for 500 ms, and serves again once descriptors free up.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

/// utime + stime of a process, in clock ticks.
fn cpu_ticks(pid: u32) -> u64 {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    // Fields after the parenthesised comm; utime and stime are 14 and 15.
    let rest = &stat[stat.rfind(')').unwrap() + 2..];
    let fields: Vec<&str> = rest.split(' ').collect();
    fields[11].parse::<u64>().unwrap() + fields[12].parse::<u64>().unwrap()
}

fn get(port: u16) -> Option<String> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(3))).ok()?;
    s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .ok()?;
    let mut out = String::new();
    s.read_to_string(&mut out).ok()?;
    Some(out)
}

#[test]
fn fd_exhaustion_backs_off_instead_of_spinning() {
    let port = {
        let probe = TcpListener::bind("127.0.0.1:0").unwrap();
        probe.local_addr().unwrap().port()
    };
    let dir = std::env::temp_dir().join(format!("ruxen-m50-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let conf = dir.join("nginx.conf");
    std::fs::write(
        &conf,
        format!(
            "events {{}}\nhttp {{ server {{ listen 127.0.0.1:{port}; \
             location / {{ return 200 ok; }} }} }}\n"
        ),
    )
    .unwrap();
    let errlog = dir.join("error.log");

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ruxen"));
    cmd.arg("-c")
        .arg(&conf)
        .arg("-e")
        .arg(&errlog)
        .env("RUXEN_WORKERS", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: setrlimit is async-signal-safe and touches only the child.
    unsafe {
        cmd.pre_exec(|| {
            let lim = libc::rlimit {
                rlim_cur: 64,
                rlim_max: 64,
            };
            if libc::setrlimit(libc::RLIMIT_NOFILE, &lim) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = cmd.spawn().unwrap();
    let pid = child.id();

    let deadline = Instant::now() + Duration::from_secs(3);
    while get(port).is_none() {
        assert!(Instant::now() < deadline, "ruxen did not start");
        sleep(Duration::from_millis(20));
    }

    // Hold more idle connections than ruxen has descriptors.
    let held: Vec<TcpStream> = (0..100)
        .filter_map(|_| TcpStream::connect(("127.0.0.1", port)).ok())
        .collect();
    sleep(Duration::from_millis(300));

    let before = cpu_ticks(pid);
    sleep(Duration::from_secs(1));
    let used = cpu_ticks(pid) - before;

    drop(held);
    // Descriptors free up as ruxen sees the closed connections.
    let deadline = Instant::now() + Duration::from_secs(5);
    let recovered = loop {
        if let Some(resp) = get(port) {
            break resp;
        }
        assert!(Instant::now() < deadline, "ruxen did not recover");
        sleep(Duration::from_millis(50));
    };

    let _ = child.kill();
    let _ = child.wait();
    let log = std::fs::read_to_string(&errlog).unwrap_or_default();
    let _ = std::fs::remove_dir_all(&dir);

    // A spinning accept loop burns ~100 ticks per second; backing off
    // costs next to nothing.
    assert!(used < 30, "accept loop used {used} CPU ticks in 1 s");
    assert!(
        log.lines().any(|l| l.contains(" [crit] ")
            && l.ends_with(": accept() failed (24: Too many open files)")),
        "error log: {log}"
    );
    assert!(recovered.starts_with("HTTP/1.1 200"), "{recovered}");
}
