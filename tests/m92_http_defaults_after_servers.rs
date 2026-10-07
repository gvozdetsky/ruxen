//! M92 — http-level settings written below a `server` block still apply
//! to it, and a server's `root` written below its locations still applies
//! to them: nginx merges configurations once the whole `http {}` block is
//! read (`ngx_http_merge_servers`). ruxen handed http values to servers,
//! and server roots to locations, while parsing, so only what came first
//! counted. Checked against nginx 1.24.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

/// "status connection-header body".
fn get(port: u16, path: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    // HTTP/1.1 without `Connection: close`: keep-alive unless the server
    // turns it off.
    write!(s, "GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
    let mut buf = [0u8; 4096];
    let n = s.read(&mut buf).unwrap_or(0);
    let out = String::from_utf8_lossy(&buf[..n]).into_owned();
    let code = out.get(9..12).unwrap_or("").to_string();
    let (head, body) = out.split_once("\r\n\r\n").unwrap_or((&out, ""));
    let connection = head
        .lines()
        .find_map(|l| l.strip_prefix("Connection: "))
        .unwrap_or("-");
    format!("{code} {connection} {}", body.trim())
}

#[test]
fn http_settings_below_a_server_apply_to_it() {
    let setup = common::ports::setup_lock();
    let probes: Vec<TcpListener> = (0..2)
        .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    let ports: Vec<u16> = probes
        .iter()
        .map(|l| l.local_addr().unwrap().port())
        .collect();
    drop(probes);
    let d = std::env::temp_dir().join(format!("ruxen-m92-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(d.join("http-root")).unwrap();
    std::fs::create_dir_all(d.join("server-root")).unwrap();
    std::fs::write(d.join("http-root/f"), "from http root").unwrap();
    std::fs::write(d.join("server-root/g"), "from server root").unwrap();
    let dd = d.display();
    std::fs::write(
        d.join("nginx.conf"),
        format!(
            "pid {dd}/ruxen.pid;\nevents {{}}\nhttp {{\n\
             access_log off;\n\
             server {{ listen 127.0.0.1:{}; location /f {{ }} }}\n\
             server {{ listen 127.0.0.1:{}; location / {{ }} root {dd}/server-root; }}\n\
             root {dd}/http-root;\n\
             keepalive_timeout 0;\n\
             }}\n",
            ports[0], ports[1]
        ),
    )
    .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .arg("-c")
        .arg(d.join("nginx.conf"))
        .env("TMPDIR", &d)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    while !d.join("ruxen.pid").exists() {
        assert!(
            Instant::now() < deadline && child.try_wait().unwrap().is_none(),
            "ruxen did not start"
        );
        sleep(Duration::from_millis(10));
    }
    drop(setup);

    let first = get(ports[0], "/f");
    let second = get(ports[1], "/g");
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&d);
    assert_eq!(first, "200 close from http root");
    assert_eq!(second, "200 close from server root");
}
