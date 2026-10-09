//! M93 — status-line reason phrases match nginx's `ngx_http_status_lines[]`
//! (ngx_http_header_filter_module.c). Before, codes missing from ruxen's
//! tables fell back to "OK" (`413 OK`), and a few phrases differed from
//! nginx's. Codes nginx has no phrase for get an empty one (`418 `).
//! Taken from the nginx 1.24.0 source (ngx_http_header_filter_module.c).

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

fn status_line(port: u16, path: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out.split("\r\n").next().unwrap_or("").to_string()
}

#[test]
fn status_lines_match_nginx() {
    let setup = common::ports::setup_lock();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let d = std::env::temp_dir().join(format!("ruxen-m93-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(d.join("html")).unwrap();
    std::fs::write(d.join("html/ok.txt"), "ok").unwrap();
    let dd = d.display();
    std::fs::write(
        d.join("nginx.conf"),
        format!(
            "pid {dd}/ruxen.pid;\nevents {{}}\nhttp {{\n\
             access_log off;\n\
             server {{ listen 127.0.0.1:{port}; root {dd}/html;\n\
               location = /413 {{ return 413; }}\n\
               location = /504 {{ return 504; }}\n\
               location = /503 {{ return 503; }}\n\
               location = /418 {{ return 418; }}\n\
               location = /205 {{ return 205; }}\n\
               location = /599 {{ return 599; }}\n\
               location = /307 {{ return 307 /x; }}\n\
               location = /302 {{ return 302 /x; }}\n\
               location /override/ {{ error_page 404 =503 /ok.txt; }}\n\
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
        ("/413", "HTTP/1.1 413 Request Entity Too Large"),
        ("/504", "HTTP/1.1 504 Gateway Time-out"),
        ("/503", "HTTP/1.1 503 Service Temporarily Unavailable"),
        // nginx has no phrase for these, so it sends the code and a space.
        ("/418", "HTTP/1.1 418 "),
        ("/205", "HTTP/1.1 205 "),
        ("/599", "HTTP/1.1 599 "),
        // redirects go through their own writer
        ("/307", "HTTP/1.1 307 Temporary Redirect"),
        ("/302", "HTTP/1.1 302 Moved Temporarily"),
        // error_page status override rewrites the status line of a file response
        (
            "/override/missing",
            "HTTP/1.1 503 Service Temporarily Unavailable",
        ),
    ];
    let got: Vec<String> = cases.iter().map(|(p, _)| status_line(port, p)).collect();
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&d);
    for ((path, want), got) in cases.iter().zip(&got) {
        assert_eq!(got, want, "{path}");
    }
}
