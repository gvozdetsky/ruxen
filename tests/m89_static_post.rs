//! M89 — the static module takes POST as far as the file lookup: a missing
//! file is a 404, an existing one a 405, a directory without an index a
//! 403. Other methods get the 405 at once. The 405 goes through
//! error_page. ruxen refused every method but GET and HEAD with a 405
//! that skipped error_page. Checked against nginx 1.24.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

/// `METHOD path` → "status", or "status body" for the error page.
fn request(port: u16, line: &str) -> String {
    let (method, path) = line.split_once(' ').unwrap();
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(
        s,
        "{method} {path} HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\nConnection: close\r\n\r\nx"
    )
    .unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    let code = out.get(9..12).unwrap_or("").to_string();
    let body = out.split_once("\r\n\r\n").map_or("", |(_, b)| b).trim();
    if body == "error page" {
        return format!("{code} {body}");
    }
    code
}

#[test]
fn post_to_static_files_follows_the_lookup() {
    let setup = common::ports::setup_lock();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let d = std::env::temp_dir().join(format!("ruxen-m89-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    for dir in ["d", "noidx", "ai"] {
        std::fs::create_dir_all(d.join("html").join(dir)).unwrap();
    }
    std::fs::write(d.join("html/f.txt"), "f").unwrap();
    std::fs::write(d.join("html/d/index.html"), "i").unwrap();
    std::fs::write(d.join("html/ai/a.txt"), "a").unwrap();
    let dd = d.display();
    std::fs::write(
        d.join("nginx.conf"),
        format!(
            "pid {dd}/ruxen.pid;\nerror_log {dd}/error.log;\nevents {{}}\nhttp {{\n\
             access_log off;\n\
             server {{ listen 127.0.0.1:{port}; root {dd}/html;\n\
               location / {{ }}\n\
               location /ai/ {{ autoindex on; }}\n\
               location /tf/ {{ try_files /f.txt =418; }}\n\
               location /tm/ {{ try_files /missing =418; }}\n\
               location /ep/ {{ error_page 405 /e405; }}\n\
               location = /e405 {{ return 200 \"error page\"; }}\n\
             }}\n\
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
        ("POST /missing", "404"),
        ("POST /f.txt", "405"),
        // A directory: the redirect to the slash form, the index file
        // (refused like any file), or no index and no listing for POST.
        ("POST /d", "301"),
        ("POST /d/", "405"),
        ("POST /noidx/", "403"),
        ("POST /ai/", "403"),
        ("GET /ai/", "200"),
        // try_files probes for POST too.
        ("POST /tf/", "405"),
        ("POST /tm/", "418"),
        // The other methods are refused before the lookup.
        ("PATCH /missing", "405"),
        ("DELETE /f.txt", "405"),
        // The 405 is a special response: error_page applies.
        ("PUT /ep/missing", "405 error page"),
        ("GET /f.txt", "200"),
    ];
    let got: Vec<String> = cases.iter().map(|(r, _)| request(port, r)).collect();
    let _ = child.kill();
    let _ = child.wait();
    let log = std::fs::read_to_string(d.join("error.log")).unwrap_or_default();
    let _ = std::fs::remove_dir_all(&d);
    for ((req, want), got) in cases.iter().zip(&got) {
        assert_eq!(got, want, "{req}");
    }
    assert!(
        log.contains("directory index of \"") && log.contains("/ai/\" is forbidden"),
        "{log}"
    );
}
