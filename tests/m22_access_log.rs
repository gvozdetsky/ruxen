use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, MutexGuard};
use std::thread::sleep;
use std::time::{Duration, Instant};

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

static SETUP_LOCK: Mutex<()> = Mutex::new(());

fn pick_port() -> (u16, MutexGuard<'static, ()>) {
    let g = SETUP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let p = l.local_addr().unwrap().port();
    drop(l);
    (p, g)
}

fn unique_dir() -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let d = std::env::temp_dir().join(format!(
        "ruxen-m22-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir(&d).unwrap();
    d
}

fn wait_for_listen(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        if Instant::now() > deadline {
            panic!("ruxen did not start listening on port {port}");
        }
        sleep(Duration::from_millis(20));
    }
}

fn spawn_server(conf_body: &str) -> (ServerGuard, u16, PathBuf) {
    let (port, _lock) = pick_port();
    let dir = unique_dir();
    let conf_path = dir.join("ruxen.conf");
    std::fs::write(
        &conf_path,
        conf_body
            .replace("%%PORT%%", &port.to_string())
            .replace("%%DIR%%", dir.to_str().unwrap()),
    )
    .unwrap();

    let child = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .args(["-c", conf_path.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ruxen");

    wait_for_listen(port);
    (
        ServerGuard {
            child,
            tempdir: dir.clone(),
        },
        port,
        dir,
    )
}

fn header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

fn content_length(buf: &[u8]) -> Option<usize> {
    let text = std::str::from_utf8(buf).ok()?;
    let head_end = text.find("\r\n\r\n")?;
    for line in text[..head_end].split("\r\n").skip(1) {
        let (k, v) = line.split_once(':')?;
        if k.eq_ignore_ascii_case("Content-Length") {
            return v.trim().parse().ok();
        }
    }
    None
}

fn read_one_response(stream: &mut TcpStream) -> Vec<u8> {
    let mut out = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        let n = stream.read(&mut tmp).unwrap_or(0);
        if n == 0 {
            break;
        }
        out.extend_from_slice(&tmp[..n]);

        let Some(end) = header_end(&out) else {
            continue;
        };
        let Some(cl) = content_length(&out) else {
            break;
        };
        if out.len() >= end + cl {
            out.truncate(end + cl);
            break;
        }
    }
    out
}

#[test]
fn access_log_if_and_sent_http_variables_are_emitted() {
    let conf = r#"
events {}
http {
  log_format test1 $sent_http_connection;
  log_format test2 $sent_http_keep_alive;
  access_log %%DIR%%/test1.log test1 if=$arg_l;
  access_log %%DIR%%/test2.log test2 if=$arg_l;

  server {
    listen 127.0.0.1:%%PORT%%;
    keepalive_requests 2;
    keepalive_timeout 1 9;
    location / { return 200 ""; }
  }
}
"#;
    let (_guard, port, dir) = spawn_server(conf);
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();

    s.write_all(b"GET /?l=ok HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .unwrap();
    let _ = read_one_response(&mut s);

    s.write_all(b"GET /?l=ok HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .unwrap();
    let _ = read_one_response(&mut s);

    // Give the worker a moment to flush append writes.
    sleep(Duration::from_millis(50));

    let c1 = std::fs::read_to_string(dir.join("test1.log")).unwrap();
    let c2 = std::fs::read_to_string(dir.join("test2.log")).unwrap();
    assert_eq!(c1, "keep-alive\nclose\n");
    assert_eq!(c2, "timeout=9\n-\n");
}

/// A bare `access_log` uses nginx's predefined `combined` format.
#[test]
fn bare_access_log_uses_combined_format() {
    let conf = r#"
events {}
http {
  access_log %%DIR%%/access.log;
  server {
    listen 127.0.0.1:%%PORT%%;
    location / { return 200 ""; }
  }
}
"#;
    let (_guard, port, dir) = spawn_server(conf);
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    s.write_all(
        b"GET /?a=1 HTTP/1.1\r\nHost: localhost\r\nUser-Agent: t/1\r\nConnection: close\r\n\r\n",
    )
    .unwrap();
    let _ = read_one_response(&mut s);
    sleep(Duration::from_millis(30));

    let access = std::fs::read_to_string(dir.join("access.log")).unwrap();
    let line = access.lines().next().unwrap_or_default();
    assert!(line.starts_with("127.0.0.1 - - ["), "{line}");
    assert!(
        line.ends_with("] \"GET /?a=1 HTTP/1.1\" 200 0 \"-\" \"t/1\""),
        "{line}"
    );
}

/// Variable values are escaped as in nginx, and a variable that isn't set
/// is `-` (`escape=default`), or empty with `escape=json` / `none`.
#[test]
fn log_values_are_escaped_and_unset_ones_are_dashes() {
    let conf = r#"
events {}
http {
  log_format d '$request|$server_protocol|$http_x|$http_none|$arg_none|$remote_user|$uri';
  log_format j escape=json '{"x":"$http_x","none":"$http_none"}';
  log_format n escape=none '$http_x|$http_none';
  server {
    listen 127.0.0.1:%%PORT%%;
    access_log %%DIR%%/d.log d;
    access_log %%DIR%%/j.log j;
    access_log %%DIR%%/n.log n;
    location / { return 200 ""; }
  }
}
"#;
    let (_guard, port, dir) = spawn_server(conf);
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    s.write_all(b"GET /p HTTP/1.0\r\nHost: localhost\r\nX: a\"b\\c\x01\xc3\xa9\r\n\r\n")
        .unwrap();
    let _ = read_one_response(&mut s);
    sleep(Duration::from_millis(30));

    let read = |name: &str| std::fs::read(dir.join(name)).unwrap();
    assert_eq!(
        String::from_utf8_lossy(&read("d.log")),
        "GET /p HTTP/1.0|HTTP/1.0|a\\x22b\\x5Cc\\x01\\xC3\\xA9|-|-|-|/p\n"
    );
    assert_eq!(
        String::from_utf8_lossy(&read("j.log")),
        "{\"x\":\"a\\\"b\\\\c\\u0001\u{e9}\",\"none\":\"\"}\n"
    );
    assert_eq!(read("n.log"), b"a\"b\\c\x01\xc3\xa9|\n");
}

/// Requests refused with 400/405/501 are logged like nginx: before a server is
/// chosen to the default server's access_log, and with a refused URI
/// (`/../x`) with an empty `$uri`. They used to leave no log line.
#[test]
fn rejected_requests_are_logged() {
    let conf = r#"
events {}
http {
  log_format t "$connection_requests $status $request_method [$request_uri] [$uri]";
  server {
    listen 127.0.0.1:%%PORT%%;
    access_log %%DIR%%/t.log t;
    location / { return 200 ""; }
  }
}
"#;
    let (_guard, port, dir) = spawn_server(conf);
    let send = |raw: &[u8]| {
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        s.write_all(raw).unwrap();
        let mut out = Vec::new();
        let _ = s.read_to_end(&mut out);
        String::from_utf8_lossy(&out).into_owned()
    };
    assert!(send(b"GET\r\n\r\n").starts_with("HTTP/1.1 400"));
    assert!(
        send(b"POST /te HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip\r\n\r\n")
            .starts_with("HTTP/1.1 501")
    );
    assert!(send(b"GET /nohost HTTP/1.1\r\n\r\n").starts_with("HTTP/1.1 400"));
    assert!(
        send(b"TRACE /t HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .starts_with("HTTP/1.1 405")
    );
    // Refused after the server is chosen (403 today; nginx says 400).
    let resp = send(b"GET /../x HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    assert!(resp.starts_with("HTTP/1.1 4"), "{resp}");
    sleep(Duration::from_millis(50));

    let log = std::fs::read_to_string(dir.join("t.log")).unwrap_or_default();
    let lines: Vec<&str> = log.lines().collect();
    assert!(lines.contains(&"1 400 GET [] []"), "{log}");
    assert!(lines.contains(&"1 501 POST [/te] [/te]"), "{log}");
    assert!(lines.contains(&"1 400 GET [/nohost] [/nohost]"), "{log}");
    assert!(lines.contains(&"1 405 TRACE [/t] [/t]"), "{log}");
    assert!(
        lines
            .iter()
            .any(|l| l.starts_with("1 4") && l.ends_with(" GET [/../x] []")),
        "{log}"
    );
}
