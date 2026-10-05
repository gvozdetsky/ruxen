//! M72 — an upstream body larger than ruxen buffers is refused with a 502
//! however it is framed. Chunked and close-delimited bodies already were;
//! a `Content-Length` body used to be read into memory whole, whatever its
//! size, until the response streams (#88).

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

#[test]
fn an_oversized_content_length_body_is_refused() {
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
    let mut child = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .arg("-c")
        .arg(dir.join("nginx.conf"))
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

    let started = Instant::now();
    let mut s = TcpStream::connect(("127.0.0.1", front)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(8))).unwrap();
    s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut resp = String::new();
    let _ = s.read_to_string(&mut resp);
    let elapsed = started.elapsed();
    sleep(Duration::from_millis(50));
    let log = std::fs::read_to_string(dir.join("error.log")).unwrap_or_default();
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&dir);

    assert!(resp.starts_with("HTTP/1.1 502"), "{resp}");
    // Refused on the header, not after a read timeout.
    assert!(elapsed < Duration::from_secs(2), "{elapsed:?}");
    assert!(
        log.contains("upstream response is too big to buffer"),
        "{log}"
    );
}
