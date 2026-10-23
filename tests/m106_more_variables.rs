//! M106 — `$binary_remote_addr`, `$document_uri`, `$https` and `$pid`,
//! which were empty with a "not supported yet" warning: the client address
//! as 4 (or 16) bytes, `$uri` under its other name, `on` over TLS only, and
//! the process ID (#559).

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::time::Duration;

/// The server stops when the test ends, also when an assertion panics:
/// an orphaned ruxen otherwise keeps its port and CPU after the run.
struct KillOnDrop(std::process::Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn m106_binary_remote_addr_document_uri_https() {
    let dir = std::env::temp_dir().join(format!("ruxen-m106-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // Held until ruxen listens: released earlier, another test could take
    // the same free port, and ruxen would fail to bind it.
    let setup = common::ports::setup_lock();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "events {{}}\nhttp {{ server {{ listen 127.0.0.1:{port};\n\
             location / {{ rewrite ^/old(.*)$ /new$1;\n\
             return 200 \"[$binary_remote_addr][$document_uri][$https][$pid]\"; }}\n\
             }} }}\n"
        ),
    )
    .unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .arg("-t")
        .arg("-c")
        .arg(dir.join("nginx.conf"))
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stderr.contains("not supported yet"), "{stderr}");
    let mut child = KillOnDrop(
        Command::new(env!("CARGO_BIN_EXE_ruxen"))
            .arg("-c")
            .arg(dir.join("nginx.conf"))
            .arg("-g")
            .arg(format!("pid {}/ruxen.pid;", dir.display()))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    common::ports::wait_for_pid_file(&mut child.0, &dir.join("ruxen.pid"), Duration::from_secs(5));
    drop(setup);
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.write_all(b"GET /old/x HTTP/1.0\r\n\r\n").unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    let body = &out[out.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4..];
    let mut want = b"[\x7f\x00\x00\x01][/new/x][]".to_vec();
    want.extend_from_slice(format!("[{}]", child.0.id()).as_bytes());
    assert_eq!(body, want);
    drop(child);
    let _ = std::fs::remove_dir_all(&dir);
}

/// `$http_x_foo` finds an `x_foo` header where nginx keeps one
/// (`underscores_in_headers on`, `ignore_invalid_headers off`), comparing
/// a header's `-` and `_` alike as ngx_http_variable_unknown_header does;
/// `$http_user_agent`, which nginx serves from `headers_in`, doesn't take
/// `user_agent` (#624). With neither directive the header isn't seen.
#[test]
fn m106_http_variables_find_header_names_with_underscores() {
    let dir = std::env::temp_dir().join(format!("ruxen-m106-us-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let setup = common::ports::setup_lock();
    let [on, off, plain] = common::ports::free_ports();
    let body = "return 200 \"[$http_x_foo][$http_user_agent]\";";
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "events {{}}\nhttp {{\n\
             server {{ listen 127.0.0.1:{on}; underscores_in_headers on; location / {{ {body} }} }}\n\
             server {{ listen 127.0.0.1:{off}; ignore_invalid_headers off; location / {{ {body} }} }}\n\
             server {{ listen 127.0.0.1:{plain}; location / {{ {body} }} }}\n\
             }}\n"
        ),
    )
    .unwrap();
    let mut child = KillOnDrop(
        Command::new(env!("CARGO_BIN_EXE_ruxen"))
            .arg("-c")
            .arg(dir.join("nginx.conf"))
            .arg("-g")
            .arg(format!("pid {}/ruxen.pid;", dir.display()))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    common::ports::wait_for_pid_file(&mut child.0, &dir.join("ruxen.pid"), Duration::from_secs(5));
    drop(setup);
    let get = |port: u16, headers: &str| {
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.write_all(format!("GET / HTTP/1.0\r\n{headers}\r\n").as_bytes())
            .unwrap();
        let mut out = Vec::new();
        let _ = s.read_to_end(&mut out);
        let at = out.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        String::from_utf8_lossy(&out[at..]).into_owned()
    };
    let headers = "X_Foo: x-bar\r\nuser_agent: u\r\n";
    assert_eq!(get(on, headers), "[x-bar][]");
    assert_eq!(get(off, headers), "[x-bar][]");
    assert_eq!(get(plain, headers), "[][]");
    assert_eq!(get(on, "X-Foo: dash\r\nUser-Agent: u\r\n"), "[dash][u]");
    drop(child);
    let _ = std::fs::remove_dir_all(&dir);
}

/// `$request_id` (#487): 32 lowercase hex digits, one value for the whole
/// request (a header, the body and the access log agree), another for the
/// next request.
#[test]
fn m106_request_id_is_one_per_request() {
    let dir = std::env::temp_dir().join(format!("ruxen-m106-rid-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let setup = common::ports::setup_lock();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let d = dir.display();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "events {{}}\nhttp {{ log_format rid '$request_id'; access_log {d}/access.log rid;\n\
             server {{ listen 127.0.0.1:{port};\n\
             location / {{ add_header X-Request-ID $request_id; return 200 $request_id; }}\n\
             }} }}\n"
        ),
    )
    .unwrap();
    let mut child = KillOnDrop(
        Command::new(env!("CARGO_BIN_EXE_ruxen"))
            .arg("-c")
            .arg(dir.join("nginx.conf"))
            .arg("-g")
            .arg(format!("pid {d}/ruxen.pid;"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    common::ports::wait_for_pid_file(&mut child.0, &dir.join("ruxen.pid"), Duration::from_secs(5));
    drop(setup);
    let get = || {
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
        let mut out = String::new();
        let _ = s.read_to_string(&mut out);
        let (head, body) = out.split_once("\r\n\r\n").unwrap();
        let header = head
            .lines()
            .find_map(|l| l.strip_prefix("X-Request-ID: "))
            .unwrap()
            .to_string();
        assert_eq!(header, body, "{out}");
        assert_eq!(body.len(), 32, "{out}");
        assert!(
            body.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
        body.to_string()
    };
    let (first, second) = (get(), get());
    assert_ne!(first, second);
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let log = loop {
        let log = std::fs::read_to_string(dir.join("access.log")).unwrap_or_default();
        if log.lines().count() >= 2 || std::time::Instant::now() > deadline {
            break log;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(log, format!("{first}\n{second}\n"));
    drop(child);
    let _ = std::fs::remove_dir_all(&dir);
}
