mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::MutexGuard;
use std::time::Duration;

struct ServerGuard {
    child: Child,
    tempdir: PathBuf,
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.tempdir);
    }
}

fn pick_port() -> (u16, MutexGuard<'static, ()>) {
    let g = common::ports::setup_lock();
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let p = l.local_addr().unwrap().port();
    drop(l);
    (p, g)
}

fn unique_dir() -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let d = std::env::temp_dir().join(format!(
        "ruxen-m11-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir(&d).unwrap();
    d
}

fn spawn_server(conf: &str) -> (ServerGuard, u16) {
    let (port, _lock) = pick_port();
    let dir = unique_dir();
    std::fs::write(dir.join("choice.html"), b"choice-body").unwrap();

    let conf_path = dir.join("nginx.conf");
    let conf = conf
        .replace("%%PORT%%", &port.to_string())
        .replace("%%TESTDIR%%", dir.to_str().unwrap());
    std::fs::write(&conf_path, conf).unwrap();

    let pid_file = dir.join("ruxen.pid");
    let child = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .args(["-c", conf_path.to_str().unwrap()])
        .arg("-g")
        .arg(format!("pid {};", pid_file.display()))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ruxen");
    // Owned by the guard before the wait: if it panics, ruxen still stops.
    let mut guard = ServerGuard {
        child,
        tempdir: dir,
    };
    common::ports::wait_for_pid_file(&mut guard.child, &pid_file, Duration::from_secs(5));
    (guard, port)
}

fn http_get(port: u16, path: &str) -> Vec<u8> {
    let req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    s.write_all(req.as_bytes()).unwrap();
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match s.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(_) => break,
        }
    }
    out
}

fn status_line(resp: &[u8]) -> &str {
    let end = resp.iter().position(|&b| b == b'\r').unwrap_or(resp.len());
    std::str::from_utf8(&resp[..end]).unwrap()
}

fn header_value<'a>(resp: &'a [u8], name: &str) -> Option<&'a [u8]> {
    let end = resp.windows(4).position(|w| w == b"\r\n\r\n")?;
    let mut i = 0;
    let headers = &resp[..end];
    while i < headers.len() {
        let line_end = headers[i..]
            .windows(2)
            .position(|w| w == b"\r\n")
            .map(|p| i + p)
            .unwrap_or(headers.len());
        let line = &headers[i..line_end];
        if let Some(colon) = line.iter().position(|&b| b == b':') {
            let (n, v) = line.split_at(colon);
            if n.eq_ignore_ascii_case(name.as_bytes()) {
                let mut v = &v[1..];
                while let Some((&b, rest)) = v.split_first() {
                    if b != b' ' && b != b'\t' {
                        break;
                    }
                    v = rest;
                }
                return Some(v);
            }
        }
        i = line_end + 2;
    }
    None
}

fn body(resp: &[u8]) -> &[u8] {
    resp.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| &resp[i + 4..])
        .unwrap_or(&[])
}

const M11_CONF: &str = r#"
daemon off;

events { }

http {
    server {
        listen       127.0.0.1:%%PORT%%;
        server_name  localhost;

        location /echo/ {
            add_header X-Args $args;
            add_header X-Is-Args $is_args;
            add_header X-Arg-Foo $arg_foo;
            return 200 "uri=$uri request_uri=$request_uri args=$args is_args=$is_args foo=$arg_foo empty=$arg_empty missing=$arg_missing";
        }

        location /index/ {
            alias %%TESTDIR%%/;
            add_header X-URI $uri;
            index $arg_i.html;
        }
    }
}
"#;

#[test]
fn m11_query_variables_render_in_return_and_headers() {
    let (_g, port) = spawn_server(M11_CONF);

    let resp = http_get(port, "/echo/./path?foo=42&empty=");
    assert_eq!(status_line(&resp), "HTTP/1.1 200 OK");
    assert_eq!(header_value(&resp, "X-Args"), Some(&b"foo=42&empty="[..]));
    assert_eq!(header_value(&resp, "X-Is-Args"), Some(&b"?"[..]));
    assert_eq!(header_value(&resp, "X-Arg-Foo"), Some(&b"42"[..]));
    assert_eq!(
        body(&resp),
        b"uri=/echo/path request_uri=/echo/./path?foo=42&empty= args=foo=42&empty= is_args=? foo=42 empty= missing="
    );
}

#[test]
fn m11_query_variables_drive_index_templates() {
    let (_g, port) = spawn_server(M11_CONF);

    let resp = http_get(port, "/index/?i=choice");
    assert_eq!(status_line(&resp), "HTTP/1.1 200 OK");
    assert_eq!(
        header_value(&resp, "X-URI"),
        Some(&b"/index/choice.html"[..])
    );
    assert_eq!(body(&resp), b"choice-body");
}
