//! M86 — `index`, `error_page`, `recursive_error_pages` and `merge_slashes`
//! at http level are inherited by servers without their own, also when
//! they come after the server block, and repeated `index` lines append.
//! Before, the first three were unknown at http level, a second `index`
//! was a duplicate, and an http-level `merge_slashes off` was ignored.
//! Checked against nginx 1.24.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

fn get(port: u16, path: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    let code = out.get(9..12).unwrap_or("").to_string();
    let body = out.split_once("\r\n\r\n").map_or("", |(_, b)| b).trim();
    format!("{code} {body}")
}

#[test]
fn http_level_server_defaults_apply() {
    let setup = common::ports::setup_lock();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let d = std::env::temp_dir().join(format!("ruxen-m86-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(d.join("html/a")).unwrap();
    std::fs::write(d.join("html/index.htm"), "idx").unwrap();
    std::fs::write(d.join("html/404.html"), "nf").unwrap();
    std::fs::write(d.join("html/a/b"), "file").unwrap();
    let dd = d.display();
    std::fs::write(
        d.join("nginx.conf"),
        format!(
            "pid {dd}/ruxen.pid;\nevents {{}}\nhttp {{\n\
             access_log off;\n\
             server {{ listen 127.0.0.1:{port}; root {dd}/html;\n\
               location /a/b {{ return 200 \"merged\"; }}\n\
             }}\n\
             index index.html;\n\
             index index.htm;\n\
             error_page 404 /404.html;\n\
             merge_slashes off;\n\
             }}\n"
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

    let cases = [
        // index.html is missing; the second `index` line adds index.htm.
        ("/", "200 idx"),
        ("/missing", "404 nf"),
        // merge_slashes off: `//a//b` isn't `/a/b`, so it is the file.
        ("//a//b", "200 file"),
        ("/a/b", "200 merged"),
    ];
    let got: Vec<String> = cases.iter().map(|(p, _)| get(port, p)).collect();
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&d);
    for ((path, want), got) in cases.iter().zip(&got) {
        assert_eq!(got, want, "{path}");
    }
}
