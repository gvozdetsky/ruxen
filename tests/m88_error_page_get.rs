//! M88 — an error_page that sends the request to a URI turns it into a
//! GET, as nginx's `ngx_http_send_error_page` does (HEAD stays HEAD, a
//! named location keeps the method). ruxen kept the method, so a POST
//! ending in an error page got the static module's 405 instead of the
//! page. Checked against nginx 1.24.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

/// `METHOD path` → "status body".
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
    format!("{code} {body}").trim_end().to_string()
}

#[test]
fn error_page_redirects_continue_as_get() {
    let setup = common::ports::setup_lock();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let d = std::env::temp_dir().join(format!("ruxen-m88-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(d.join("html/e")).unwrap();
    std::fs::write(d.join("html/e/err.html"), "error page").unwrap();
    let dd = d.display();
    std::fs::write(
        d.join("nginx.conf"),
        format!(
            "pid {dd}/ruxen.pid;\nevents {{}}\nhttp {{\n\
             access_log off;\n\
             server {{ listen 127.0.0.1:{port}; root {dd}/html;\n\
               location /static {{ return 404; error_page 404 /e/err.html; }}\n\
               location /method {{ return 404; error_page 404 /var; }}\n\
               location /named {{ return 404; error_page 404 @named; }}\n\
               location @named {{ return 200 \"named $request_method\"; }}\n\
               location /var {{ return 200 \"$request_method\"; }}\n\
               location /proxied {{ proxy_pass http://127.0.0.1:{port}/teapot;\n\
                 proxy_intercept_errors on; error_page 418 /var; }}\n\
               location /teapot {{ return 418; }}\n\
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
        // The static module serves the page to the GET it has become.
        ("POST /static", "404 error page"),
        ("PUT /static", "404 error page"),
        ("POST /method", "404 GET"),
        // HEAD stays HEAD: no body.
        ("HEAD /method", "404"),
        // A named location keeps the method.
        ("POST /named", "404 named POST"),
        // Also for an upstream status taken by proxy_intercept_errors.
        ("POST /proxied", "418 GET"),
    ];
    let got: Vec<String> = cases.iter().map(|(r, _)| request(port, r)).collect();
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&d);
    for ((req, want), got) in cases.iter().zip(&got) {
        assert_eq!(got, want, "{req}");
    }
}
