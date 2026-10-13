//! M105 — variables in an `access_log` path (#303): the path is rendered
//! per request and the line goes to that file, as nginx's
//! ngx_http_log_script_write does, but only when the location's root
//! exists, so a bogus `Host` can't create files. Buffered logs can't have
//! variables in the name.

mod common;

use std::io::Read;
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
fn m105_access_log_path_is_rendered_per_request() {
    let dir = std::env::temp_dir().join(format!("ruxen-m105-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("html")).unwrap();
    let port = {
        let _setup = common::ports::setup_lock();
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    };
    let d = dir.display();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "error_log {d}/error.log;\nevents {{}}\nhttp {{ log_format u $uri;\n\
             server {{ listen 127.0.0.1:{port}; root {d}/html;\n\
             location / {{ access_log {d}/v_$arg_n.log u; access_log {d}/w_${{arg_n}}.log u; return 200; }}\n\
             location /gone {{ root {d}/missing; access_log {d}/g_$arg_n.log u; return 200; }}\n\
             }} }}\n"
        ),
    )
    .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .arg("-c")
        .arg(dir.join("nginx.conf"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "ruxen did not start");
        std::thread::sleep(Duration::from_millis(20));
    }
    let get = |target: &str| {
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        use std::io::Write;
        write!(s, "GET {target} HTTP/1.0\r\n\r\n").unwrap();
        let mut out = String::new();
        let _ = s.read_to_string(&mut out);
        assert!(out.starts_with("HTTP/1.1 200"), "{out}");
    };
    get("/a?n=1");
    get("/b?n=2");
    get("/c?n=1");
    get("/gone/x?n=3");
    std::thread::sleep(Duration::from_millis(200));
    let _ = child.kill();
    let _ = child.wait();
    let read = |name: &str| std::fs::read_to_string(dir.join(name)).unwrap_or_default();
    assert_eq!(read("v_1.log"), "/a\n/c\n");
    assert_eq!(read("v_2.log"), "/b\n");
    assert_eq!(read("w_1.log"), "/a\n/c\n");
    // The location's root doesn't exist: no file, and nginx's line.
    assert!(!dir.join("g_3.log").exists());
    let log = read("error.log");
    assert!(
        log.contains(&format!(
            "testing \"{d}/missing\" existence failed (2: No such file or directory)"
        )),
        "{log}"
    );

    // Buffered logs can't have variables in the name.
    std::fs::write(
        dir.join("bad.conf"),
        format!(
            "events {{}}\nhttp {{ server {{ listen 127.0.0.1:{port};\n\
             access_log {d}/v_$host.log combined buffer=16k; }} }}\n"
        ),
    )
    .unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .arg("-t")
        .arg("-c")
        .arg(dir.join("bad.conf"))
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{stderr}");
    assert!(
        stderr.contains("buffered logs cannot have variables in name"),
        "{stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
