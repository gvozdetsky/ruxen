//! M72 — an upstream body larger than ruxen could buffer is relayed as it
//! arrives (#88), as nginx does: the head and the first bytes reach the
//! client at once, and when the upstream then stalls, `proxy_read_timeout`
//! ends the response by closing the connection. It used to be a 502.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

#[test]
fn a_body_too_large_to_buffer_is_relayed() {
    let setup = common::ports::setup_lock();
    let backend = TcpListener::bind("127.0.0.1:0").unwrap();
    let backend_port = backend.local_addr().unwrap().port();
    let front = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    // Announces 1 GiB, sends a little, then holds the connection open.
    std::thread::spawn(move || {
        for mut conn in backend.incoming().flatten() {
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                let _ = conn.read(&mut buf);
                let _ =
                    conn.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1073741824\r\n\r\nstart");
                sleep(Duration::from_secs(10));
            });
        }
    });
    let dir = std::env::temp_dir().join(format!("ruxen-m72-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "pid {d}/ruxen.pid;\nevents {{}}\nhttp {{\n\
             server {{ listen 127.0.0.1:{front}; error_log {d}/error.log;\n\
               location / {{ proxy_pass http://127.0.0.1:{backend_port};\n\
                 proxy_read_timeout 5s; }} }}\n\
             }}\n",
            d = dir.display()
        ),
    )
    .unwrap();
    // Owned by the guard before the wait: if it panics, ruxen still stops.
    let mut child = common::KillOnDrop(
        Command::new(env!("CARGO_BIN_EXE_ruxen"))
            .arg("-c")
            .arg(dir.join("nginx.conf"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    common::ports::wait_for_pid_file(&mut child, &dir.join("ruxen.pid"), Duration::from_secs(3));
    drop(setup);

    let started = Instant::now();
    let mut s = TcpStream::connect(("127.0.0.1", front)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(8))).unwrap();
    s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .unwrap();
    // The head and the first body bytes come before the upstream is done.
    let mut resp = Vec::new();
    let mut buf = [0u8; 4096];
    while !resp.ends_with(b"start") {
        let n = s.read(&mut buf).unwrap();
        assert!(n > 0, "{}", String::from_utf8_lossy(&resp));
        resp.extend_from_slice(&buf[..n]);
    }
    let first_bytes = started.elapsed();
    // Then proxy_read_timeout (5 s) ends it: the connection closes.
    let _ = s.read_to_end(&mut resp);
    let closed = started.elapsed();
    sleep(Duration::from_millis(50));
    let log = std::fs::read_to_string(dir.join("error.log")).unwrap_or_default();
    drop(child);
    let _ = std::fs::remove_dir_all(&dir);

    let resp = String::from_utf8_lossy(&resp);
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
    assert!(
        resp.contains("\r\nContent-Length: 1073741824\r\n"),
        "{resp}"
    );
    assert!(first_bytes < Duration::from_secs(2), "{first_bytes:?}");
    assert!(closed >= Duration::from_secs(4), "{closed:?}");
    assert!(
        log.contains("upstream timed out (110: Connection timed out) while reading upstream"),
        "{log}"
    );
}
