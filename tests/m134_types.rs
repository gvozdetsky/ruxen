//! M134 — `types {}` and `default_type` (#38), as nginx sets Content-Type
//! (ngx_http_set_content_type): by the URI's extension, case folded, from
//! the nearest level's `types` (else nginx's built-in html / gif / jpg),
//! else `default_type` (else `text/plain`). No charset is added.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::time::Duration;

fn content_type(port: u16, host: &str, path: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    write!(
        s,
        "HEAD {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut raw = String::new();
    s.read_to_string(&mut raw).unwrap();
    assert!(raw.starts_with("HTTP/1.1 200"), "{path}: {raw}");
    raw.lines()
        .find_map(|l| l.strip_prefix("Content-Type: "))
        .unwrap_or("")
        .to_string()
}

#[test]
fn content_types_like_nginx() {
    let dir = std::env::temp_dir().join(format!("ruxen-m134-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("www")).unwrap();
    for f in ["a.html", "a.css", "a.FOO", "a.gif", "noext", "a.later"] {
        std::fs::write(dir.join("www").join(f), "x").unwrap();
    }
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let www = dir.join("www").display().to_string();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "pid {d}/ruxen.pid;\nevents {{}}\nhttp {{\naccess_log off;\n\
             types {{ text/html html; text/css css; text/x-foo foo; text/a later; text/b later; }}\n\
             default_type text/x-default;\n\
             server {{ listen 127.0.0.1:{port}; server_name http; root {www};\n\
               location /own/ {{ alias {www}/; types {{ image/x-own css; }} }}\n\
               location /def/ {{ alias {www}/; default_type application/x-def; }} }}\n\
             server {{ listen 127.0.0.1:{port}; server_name builtin; root {www};\n\
               types {{ }} }}\n\
             }}\n",
            d = dir.display()
        ),
    )
    .unwrap();
    // A second configuration with no `types` and no `default_type` at all.
    let port2 = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    std::fs::create_dir_all(dir.join("bare")).unwrap();
    std::fs::write(
        dir.join("bare/nginx.conf"),
        format!(
            "pid {d}/bare/ruxen.pid;\nevents {{}}\nhttp {{ access_log off;\n\
             server {{ listen 127.0.0.1:{port2}; root {www}; }} }}\n",
            d = dir.display()
        ),
    )
    .unwrap();
    let setup = common::ports::setup_lock();
    let mut servers = Vec::new();
    for (conf, pid) in [
        (dir.join("nginx.conf"), dir.join("ruxen.pid")),
        (dir.join("bare/nginx.conf"), dir.join("bare/ruxen.pid")),
    ] {
        let mut child = common::KillOnDrop(
            Command::new(env!("CARGO_BIN_EXE_ruxen"))
                .arg("-c")
                .arg(&conf)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        common::ports::wait_for_pid_file(&mut child, &pid, Duration::from_secs(5));
        servers.push(child);
    }
    drop(setup);

    // http's types: case folded, the later of two lines wins, the default
    // for what has no type or no extension.
    assert_eq!(content_type(port, "http", "/a.html"), "text/html");
    assert_eq!(content_type(port, "http", "/a.css"), "text/css");
    assert_eq!(content_type(port, "http", "/a.FOO"), "text/x-foo");
    assert_eq!(content_type(port, "http", "/a.later"), "text/b");
    assert_eq!(content_type(port, "http", "/a.gif"), "text/x-default");
    assert_eq!(content_type(port, "http", "/noext"), "text/x-default");
    // A location's own types replace the inherited ones; its default_type
    // keeps them.
    assert_eq!(content_type(port, "http", "/own/a.css"), "image/x-own");
    assert_eq!(content_type(port, "http", "/own/a.html"), "text/x-default");
    assert_eq!(content_type(port, "http", "/def/a.css"), "text/css");
    assert_eq!(
        content_type(port, "http", "/def/noext"),
        "application/x-def"
    );
    // `types { }`: nothing has a type.
    assert_eq!(content_type(port, "builtin", "/a.html"), "text/x-default");
    // No types anywhere: nginx's built-in three, else text/plain.
    assert_eq!(content_type(port2, "x", "/a.html"), "text/html");
    assert_eq!(content_type(port2, "x", "/a.gif"), "image/gif");
    assert_eq!(content_type(port2, "x", "/a.css"), "text/plain");

    drop(servers);
    let _ = std::fs::remove_dir_all(&dir);
}
