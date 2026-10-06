//! M77 — a request-body temp file has no name on disk unless
//! `client_body_in_file_only on` keeps it, as nginx's ngx_create_temp_file
//! (non-persistent files are deleted right after they are opened). The
//! open descriptor carries the body to the upstream. Before, the file kept
//! its name until the request ended, so a fast shutdown left it behind,
//! along with ruxen's private temp directory.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

/// Every file under `dir`, recursively.
fn files_under(dir: &Path) -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                out.extend(files_under(&path));
            } else {
                out.push(path.display().to_string());
            }
        }
    }
    out
}

#[test]
fn a_spilled_body_leaves_nothing_behind_a_fast_shutdown() {
    let setup = common::ports::setup_lock();
    // An upstream that reads the request and never answers.
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_port = upstream.local_addr().unwrap().port();
    let received = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    {
        let received = received.clone();
        std::thread::spawn(move || {
            if let Ok((mut conn, _)) = upstream.accept() {
                let mut buf = vec![0u8; 64 * 1024];
                while let Ok(n) = conn.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    received.fetch_add(n, std::sync::atomic::Ordering::SeqCst);
                }
            }
        });
    }
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let dir = std::env::temp_dir().join(format!("ruxen-m77-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let tmp = dir.join("tmp");
    std::fs::create_dir_all(&tmp).unwrap();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "pid {d}/ruxen.pid;\nevents {{}}\nhttp {{ client_max_body_size 10m;\n\
             server {{ listen 127.0.0.1:{port};\n\
               location / {{ proxy_pass http://127.0.0.1:{upstream_port}; }} }} }}\n",
            d = dir.display()
        ),
    )
    .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .arg("-c")
        .arg(dir.join("nginx.conf"))
        .env("TMPDIR", &tmp)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    while !dir.join("ruxen.pid").exists() {
        assert!(
            Instant::now() < deadline && child.try_wait().unwrap().is_none(),
            "ruxen did not start"
        );
        sleep(Duration::from_millis(10));
    }
    drop(setup);

    // 2 MiB: over the 1 MiB kept in memory, so it is spilled to a file.
    let body = vec![b'z'; 2 << 20];
    let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
    write!(
        client,
        "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .unwrap();
    client.write_all(&body).unwrap();
    // The whole body reaches the upstream (read back through the open
    // descriptor), while no file has a name in the temp directory.
    let deadline = Instant::now() + Duration::from_secs(5);
    while received.load(std::sync::atomic::Ordering::SeqCst) < body.len() {
        assert!(
            Instant::now() < deadline,
            "the body didn't reach the upstream"
        );
        sleep(Duration::from_millis(20));
    }
    let during = files_under(&tmp);

    // Fast shutdown with the request in flight.
    let rc = unsafe { libc::kill(child.id() as i32, libc::SIGTERM) };
    assert_eq!(rc, 0);
    let _ = child.wait();
    let after: Vec<String> = std::fs::read_dir(&tmp)
        .unwrap()
        .flatten()
        .map(|e| e.path().display().to_string())
        .collect();
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        during.is_empty(),
        "named temp files during the request: {during:?}"
    );
    assert!(after.is_empty(), "left in the temp directory: {after:?}");
}
