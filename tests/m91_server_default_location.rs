//! M91 — a request that matches none of a server's locations is handled
//! with the server's own configuration, as nginx does: its static handler
//! serves from the server's root (or `html`), with the server's index and
//! add_header. ruxen answered 404 unless the server had a root and no
//! `/` location; `location = /` counted as one. Checked against nginx 1.24.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

/// "status [X-S header] body".
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
    let (head, body) = out.split_once("\r\n\r\n").unwrap_or((&out, ""));
    let header = head
        .lines()
        .find_map(|l| l.strip_prefix("X-S: "))
        .map_or(String::new(), |v| format!(" [{v}]"));
    let body = if code == "200" { body.trim() } else { "" };
    format!("{code}{header} {body}").trim_end().to_string()
}

#[test]
fn unmatched_requests_use_the_server_configuration() {
    let setup = common::ports::setup_lock();
    let probes: Vec<TcpListener> = (0..2)
        .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    let ports: Vec<u16> = probes
        .iter()
        .map(|l| l.local_addr().unwrap().port())
        .collect();
    drop(probes);
    let d = std::env::temp_dir().join(format!("ruxen-m91-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(d.join("site/sub")).unwrap();
    std::fs::create_dir_all(d.join("prefix/html")).unwrap();
    std::fs::write(d.join("site/f.txt"), "file").unwrap();
    std::fs::write(d.join("site/sub/index.html"), "index").unwrap();
    std::fs::write(d.join("prefix/html/g.txt"), "default root").unwrap();
    let dd = d.display();
    std::fs::write(
        d.join("nginx.conf"),
        format!(
            "pid {dd}/ruxen.pid;\nevents {{}}\nhttp {{\n\
             access_log off;\n\
             server {{ listen 127.0.0.1:{}; root {dd}/site; add_header X-S srv;\n\
               location = / {{ return 200 \"exact\"; }}\n\
               location /api/ {{ return 200 \"api\"; }}\n\
             }}\n\
             server {{ listen 127.0.0.1:{};\n\
               location = /x {{ return 200 \"x\"; }}\n\
             }}\n\
             }}\n",
            ports[0], ports[1]
        ),
    )
    .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .arg("-p")
        .arg(d.join("prefix"))
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
        (ports[0], "/f.txt", "200 [srv] file"),
        (ports[0], "/sub/", "200 [srv] index"),
        (ports[0], "/sub", "301 [srv]"),
        (ports[0], "/missing", "404"),
        (ports[0], "/", "200 [srv] exact"),
        (ports[0], "/api/x", "200 [srv] api"),
        // No root anywhere: nginx's `html` under the prefix.
        (ports[1], "/g.txt", "200 default root"),
        (ports[1], "/x", "200 x"),
    ];
    let got: Vec<String> = cases.iter().map(|(p, path, _)| get(*p, path)).collect();
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&d);
    for ((_, path, want), got) in cases.iter().zip(&got) {
        assert_eq!(got, want, "{path}");
    }
}
