//! M64 — `listen 127.0.0.1:A-B;` listens on every port of the range, as
//! nginx (`ngx_parse_inet_url`; nginx-tests' http_listen.t). It used to be
//! `bad value for listen address`.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

/// Two consecutive free ports.
fn free_pair() -> (u16, TcpListener, TcpListener) {
    loop {
        let a = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = a.local_addr().unwrap().port();
        if port == u16::MAX {
            continue;
        }
        if let Ok(b) = TcpListener::bind(("127.0.0.1", port + 1)) {
            return (port, a, b);
        }
    }
}

fn get(port: u16) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

#[test]
fn every_port_of_the_range_is_served() {
    let (port, a, b) = free_pair();
    let dir = std::env::temp_dir().join(format!("ruxen-m64-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "pid {d}/ruxen.pid;\nevents {{}}\nhttp {{ server {{ listen 127.0.0.1:{port}-{}; \
             location / {{ return 200 \"$server_port\"; }} }} }}\n",
            port + 1,
            d = dir.display()
        ),
    )
    .unwrap();
    drop((a, b));
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
    let first = get(port);
    let second = get(port + 1);
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(first.ends_with(&port.to_string()), "{first}");
    assert!(second.ends_with(&(port + 1).to_string()), "{second}");
}
