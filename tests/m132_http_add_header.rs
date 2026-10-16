//! M132 — `add_header` / `add_trailer` at `http {}` (#17), merged as nginx
//! merges them (ngx_http_headers_merge_conf): a level with any of its own
//! replaces the inherited list, one without takes it whole. An http line
//! below a server still applies to it.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::time::Duration;

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// The response head and body of one `Connection: close` request.
fn get(port: u16, host: &str, path: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nTE: trailers\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).unwrap();
    String::from_utf8_lossy(&raw).into_owned()
}

#[test]
fn http_level_add_header_is_inherited_until_a_level_has_its_own() {
    let port = free_port();
    let dir = std::env::temp_dir().join(format!("ruxen-m132-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let setup = common::ports::setup_lock();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "pid {d}/ruxen.pid;\nevents {{}}\nhttp {{\naccess_log off;\n\
             add_header X-Http http;\n\
             server {{ listen 127.0.0.1:{port}; server_name inherits;\n\
               location / {{ return 200 ok; }}\n\
               location /own/ {{ add_header X-Location location; return 200 ok; }}\n\
               location /missing {{ return 404; }} }}\n\
             server {{ listen 127.0.0.1:{port}; server_name replaces;\n\
               add_header X-Server server;\n\
               location / {{ return 200 ok; }} }}\n\
             add_header X-Always always always;\n\
             add_trailer X-Trailer trailer;\n\
             }}\n",
            d = dir.display()
        ),
    )
    .unwrap();
    let mut child = common::KillOnDrop(
        Command::new(env!("CARGO_BIN_EXE_ruxen"))
            .arg("-c")
            .arg(dir.join("nginx.conf"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    common::ports::wait_for_pid_file(&mut child, &dir.join("ruxen.pid"), Duration::from_secs(5));
    drop(setup);

    // The http list, with the line after the server block, and the
    // trailer.
    let r = get(port, "inherits", "/");
    assert!(r.contains("X-Http: http\r\n"), "{r}");
    assert!(r.contains("X-Always: always\r\n"), "{r}");
    assert!(r.contains("X-Trailer: trailer\r\n"), "{r}");
    // Without `always`, not on a 404; `always` is.
    let r = get(port, "inherits", "/missing");
    assert!(r.starts_with("HTTP/1.1 404"), "{r}");
    assert!(
        !r.contains("X-Http") && r.contains("X-Always: always"),
        "{r}"
    );
    // A location with its own replaces the inherited list.
    let r = get(port, "inherits", "/own/");
    assert!(r.contains("X-Location: location\r\n"), "{r}");
    assert!(!r.contains("X-Http") && !r.contains("X-Always"), "{r}");
    // So does a server, for its locations.
    let r = get(port, "replaces", "/");
    assert!(r.contains("X-Server: server\r\n"), "{r}");
    assert!(!r.contains("X-Http") && !r.contains("X-Always"), "{r}");
    // add_trailer is a list of its own: the server's add_header doesn't
    // replace it.
    assert!(r.contains("X-Trailer: trailer\r\n"), "{r}");

    let _ = child.0.kill();
    let _ = child.0.wait();
    let _ = std::fs::remove_dir_all(&dir);
}
