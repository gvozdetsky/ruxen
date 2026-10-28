//! M165 — `root` and `alias` with variables and captures, rendered per
//! request as nginx's ngx_http_map_uri_to_path (#232). A regex location's
//! `alias` is the whole path; `$document_root` and `$request_filename`
//! follow the rendered value. A `..` a variable brings in is refused (403),
//! where nginx would follow it. Checked against nginx 1.30.6.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::symlink;
use std::process::{Command, Stdio};
use std::time::Duration;

fn get(port: u16, host: &str, path: &str) -> (u16, String) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    let status = out
        .get(9..12)
        .and_then(|s| s.parse().ok())
        .unwrap_or_default();
    let body = out
        .split_once("\r\n\r\n")
        .map_or("", |(_, b)| b)
        .trim()
        .to_string();
    (status, body)
}

#[test]
fn root_and_alias_render_variables_and_captures() {
    let setup = common::ports::setup_lock();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let d = std::env::temp_dir().join(format!("ruxen-m165-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(d.join("t/sub")).unwrap();
    std::fs::create_dir_all(d.join("t/a.example")).unwrap();
    std::fs::write(d.join("t/empty.html"), "empty").unwrap();
    std::fs::write(d.join("t/sub/index.html"), "subindex").unwrap();
    std::fs::write(d.join("t/a.example/f.txt"), "hostfile").unwrap();
    std::fs::write(d.join("secret.txt"), "secret").unwrap();
    symlink("empty.html", d.join("t/link")).unwrap();
    let dd = d.display();
    std::fs::write(
        d.join("nginx.conf"),
        format!(
            "pid {dd}/ruxen.pid;\nevents {{}}\nhttp {{\n\
             server {{ listen 127.0.0.1:{port};\n\
               location ~ ^/x/(.+)$ {{ alias {dd}/t/$1; }}\n\
               location ~ ^/dr/(.+)$ {{ alias {dd}/t/$1;\n\
                 return 200 \"$document_root|$request_filename\"; }}\n\
               location /h/ {{ alias {dd}/t/$host/; }}\n\
               location /hr/ {{ root {dd}/t/$host/; return 200 \"$document_root\"; }}\n\
               location /arg/ {{ alias {dd}/t/$arg_d/; }}\n\
               location ~ ^/tf/(\\w+)/ {{ root {dd}/t/$1; try_files /index.html =418; }}\n\
               location ~ ^/on/(.+)$ {{ disable_symlinks on; alias {dd}/t/$1; }}\n\
               location ~ ^/from/(.+)$ {{ disable_symlinks on from=$document_root;\n\
                 alias {dd}/t/$1; }}\n\
               location /if/ {{ alias {dd}/t/$arg_d/;\n\
                 if (-f $request_filename) {{ return 200 \"file\"; }} return 200 \"none\"; }}\n\
             }} }}\n"
        ),
    )
    .unwrap();
    // Owned by the guard before the wait: if it panics, ruxen still stops.
    let mut child = common::KillOnDrop(
        Command::new(env!("CARGO_BIN_EXE_ruxen"))
            .arg("-c")
            .arg(d.join("nginx.conf"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    common::ports::wait_for_pid_file(&mut child, &d.join("ruxen.pid"), Duration::from_secs(3));
    drop(setup);

    let cases = [
        ("x", "/x/empty.html", 200, "empty".to_string()),
        ("x", "/x/link", 200, "empty".to_string()),
        ("x", "/x/sub/", 200, "subindex".to_string()),
        ("x", "/x/sub", 301, String::new()),
        ("x", "/x/nope", 404, String::new()),
        // The whole path: no prefix stripped.
        ("x", "/dr/link", 200, format!("{dd}/t/link|{dd}/t/link")),
        ("a.example", "/h/f.txt", 200, "hostfile".to_string()),
        ("A.Example", "/h/f.txt", 200, "hostfile".to_string()),
        // A root's trailing slash goes, as nginx drops it before compiling.
        ("a.example", "/hr/", 200, format!("{dd}/t/a.example")),
        ("x", "/arg/index.html?d=sub", 200, "subindex".to_string()),
        // nginx serves `secret.txt` here; ruxen refuses the `..`.
        ("x", "/arg/secret.txt?d=..", 403, String::new()),
        ("x", "/tf/sub/", 200, "subindex".to_string()),
        ("x", "/tf/nope/", 418, String::new()),
        ("x", "/on/link", 403, String::new()),
        ("x", "/on/empty.html", 200, "empty".to_string()),
        // `from=` the whole path: nothing left to check.
        ("x", "/from/link", 200, "empty".to_string()),
        ("x", "/if/index.html?d=sub", 200, "file".to_string()),
        ("x", "/if/nope?d=sub", 200, "none".to_string()),
    ];
    let got: Vec<(u16, String)> = cases
        .iter()
        .map(|(host, path, _, _)| get(port, host, path))
        .collect();
    drop(child);
    let _ = std::fs::remove_dir_all(&d);
    for ((host, path, status, body), (got_status, got_body)) in cases.iter().zip(&got) {
        assert_eq!(got_status, status, "{host}{path}: {got_body}");
        if !body.is_empty() || *status == 200 {
            assert_eq!(got_body, body, "{host}{path}");
        }
    }
}
