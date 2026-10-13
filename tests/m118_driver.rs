//! M118 — the I/O driver (#215): io_uring by default, epoll (monoio's
//! legacy driver) with `RUXEN_DRIVER=epoll` or where io_uring is
//! unavailable. The worker threads' fd tables show which one runs.

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Start ruxen with `driver` as `RUXEN_DRIVER` (`None`: unset), check it
/// serves, and return the anon-inode kinds its threads hold (`io_uring`,
/// `eventpoll`, ...).
fn kinds_with(name: &str, driver: Option<&str>) -> Vec<String> {
    let dir = std::env::temp_dir().join(format!("ruxen-m118-{name}-{}", std::process::id()));
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
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "events {{}}\nhttp {{ access_log off;\n\
             server {{ listen 127.0.0.1:{port}; location / {{ return 200 \"ok\\n\"; }} }} }}\n"
        ),
    )
    .unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ruxen"));
    cmd.arg("-e")
        .arg(dir.join("error.log"))
        .arg("-c")
        .arg(dir.join("nginx.conf"))
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    match driver {
        Some(d) => cmd.env("RUXEN_DRIVER", d),
        None => cmd.env_remove("RUXEN_DRIVER"),
    };
    let mut child = cmd.spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let body = loop {
        if let Ok(mut s) = TcpStream::connect(("127.0.0.1", port)) {
            write!(s, "GET / HTTP/1.0\r\n\r\n").unwrap();
            let mut out = String::new();
            let _ = s.read_to_string(&mut out);
            break out;
        }
        assert!(Instant::now() < deadline, "ruxen did not start");
        std::thread::sleep(Duration::from_millis(20));
    };
    assert!(body.starts_with("HTTP/1.1 200"), "{body}");
    assert!(body.ends_with("ok\n"), "{body}");
    let mut kinds = Vec::new();
    for task in std::fs::read_dir(format!("/proc/{}/task", child.id())).unwrap() {
        let Ok(fds) = std::fs::read_dir(task.unwrap().path().join("fd")) else {
            continue;
        };
        for fd in fds.flatten() {
            if let Ok(target) = std::fs::read_link(fd.path()) {
                let target = target.to_string_lossy().into_owned();
                if let Some(kind) = target
                    .strip_prefix("anon_inode:[")
                    .and_then(|k| k.strip_suffix(']'))
                {
                    kinds.push(kind.to_string());
                }
            }
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&dir);
    kinds
}

#[test]
fn m118_epoll_driver_serves_without_io_uring() {
    let kinds = kinds_with("epoll", Some("epoll"));
    assert!(kinds.iter().any(|k| k == "eventpoll"), "{kinds:?}");
    assert!(!kinds.iter().any(|k| k == "io_uring"), "{kinds:?}");
}

#[test]
fn m118_io_uring_is_the_default() {
    let kinds = kinds_with("default", None);
    assert!(kinds.iter().any(|k| k == "io_uring"), "{kinds:?}");
}

#[test]
fn m118_unknown_driver_is_refused() {
    let out = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .arg("-c")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/examples/minimal.conf"
        ))
        .env("RUXEN_DRIVER", "kqueue")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("[emerg] RUXEN_DRIVER=\"kqueue\" is not a driver"),
        "{stderr}"
    );
}
