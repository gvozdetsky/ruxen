//! M144 — a request body over `client_body_buffer_size` that stops coming
//! goes to the temp file (#507): a stalled upload holds the buffer's worth
//! of memory, as in nginx, not the body. One that arrives at once stays in
//! memory (`BODY_IN_MEMORY_FOR`). Either way the upstream gets it whole.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

/// A backend that answers each request with its body's length and a
/// checksum.
fn spawn_backend() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut conn) = conn else { return };
            thread::spawn(move || {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 65536];
                let head_end = loop {
                    if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        break i + 4;
                    }
                    match conn.read(&mut chunk) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                };
                let head = String::from_utf8_lossy(&buf[..head_end]).to_ascii_lowercase();
                let len: usize = head
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length:"))
                    .map_or(0, |v| v.trim().parse().unwrap());
                while buf.len() < head_end + len {
                    match conn.read(&mut chunk) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                let body = &buf[head_end..head_end + len];
                let sum = body
                    .iter()
                    .fold(0u32, |a, &b| a.wrapping_mul(31).wrapping_add(b.into()));
                let answer = format!("len={len} sum={sum}");
                let _ = conn.write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{answer}",
                        answer.len()
                    )
                    .as_bytes(),
                );
            });
        }
    });
    port
}

/// Files in `temp` that ruxen has open. Each worker thread has a fd table
/// of its own (`unshare(CLONE_FILES)`), so every thread's is looked at.
fn open_temp_files(pid: u32, temp: &Path) -> usize {
    std::fs::read_dir(format!("/proc/{pid}/task"))
        .unwrap()
        .filter_map(|task| std::fs::read_dir(task.ok()?.path().join("fd")).ok())
        .flatten()
        .filter_map(|e| std::fs::read_link(e.ok()?.path()).ok())
        .filter(|target| target.starts_with(temp))
        .count()
}

fn expected(body: &[u8]) -> String {
    let sum = body
        .iter()
        .fold(0u32, |a, &b| a.wrapping_mul(31).wrapping_add(b.into()));
    format!("len={} sum={sum}", body.len())
}

#[test]
fn stalled_bodies_go_to_the_temp_file() {
    let upstream = spawn_backend();
    let dir = std::env::temp_dir().join(format!("ruxen-m144-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let temp = dir.join("temp");
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
             events {{}}\nhttp {{\naccess_log off;\nclient_body_temp_path {t};\n\
             server {{ listen 127.0.0.1:{port}; client_max_body_size 4m;\n\
             location / {{ proxy_pass http://127.0.0.1:{upstream}; }} }}\n}}\n",
            d = dir.display(),
            t = temp.display()
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
    // The process that serves (the one started may stay as a helper).
    let pid: u32 = std::fs::read_to_string(dir.join("ruxen.pid"))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let body: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    let post = |s: &mut TcpStream| {
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        s.write_all(
            format!(
                "POST / HTTP/1.1\r\nHost: h\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .as_bytes(),
        )
        .unwrap();
    };
    let answer = |s: &mut TcpStream| {
        let mut raw = String::new();
        s.read_to_string(&mut raw).unwrap();
        raw.split_once("\r\n\r\n")
            .map(|(_, b)| b.to_string())
            .unwrap_or(raw)
    };

    // 100 KB, then a pause: the body moves to the temp file while the
    // client is quiet, and the rest follows it there.
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    post(&mut s);
    s.write_all(&body[..100_000]).unwrap();
    thread::sleep(Duration::from_millis(300));
    assert_eq!(
        open_temp_files(pid, &temp),
        1,
        "stalled body not in the temp file"
    );
    s.write_all(&body[100_000..]).unwrap();
    assert_eq!(answer(&mut s), expected(&body));

    // All at once: whole either way, and no temp file left behind.
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    post(&mut s);
    s.write_all(&body).unwrap();
    assert_eq!(answer(&mut s), expected(&body));
    assert_eq!(open_temp_files(pid, &temp), 0);

    let _ = child.0.kill();
    let _ = child.0.wait();
    let _ = std::fs::remove_dir_all(&dir);
}
