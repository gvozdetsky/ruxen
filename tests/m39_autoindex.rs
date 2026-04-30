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
        "ruxen-m39-{}-{}",
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

fn header(resp: &[u8], name: &str) -> Option<String> {
    let s = std::str::from_utf8(resp).ok()?;
    let head_end = s.find("\r\n\r\n")?;
    let head = &s[..head_end];
    for line in head.lines().skip(1) {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case(name) {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

fn body(resp: &[u8]) -> &[u8] {
    resp.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| &resp[i + 4..])
        .unwrap_or(&[])
}

#[test]
fn default_autoindex_off_returns_403() {
    let conf = r#"
events {}
http {
  server {
    listen 127.0.0.1:%%PORT%%;
    location / {
      root %%DIR%%;
    }
  }
}
"#;
    let (_g, port, dir) = spawn_server(conf);
    std::fs::write(dir.join("a.txt"), b"a").unwrap();

    let r = http_get(port, "/");
    assert_eq!(status_line(&r), "HTTP/1.1 403 Forbidden");
}

#[test]
fn autoindex_html_lists_entries_and_is_sorted() {
    let conf = r#"
events {}
http {
  server {
    listen 127.0.0.1:%%PORT%%;
    location / {
      root %%DIR%%;
      autoindex on;
    }
  }
}
"#;
    let (_g, port, dir) = spawn_server(conf);
    std::fs::write(dir.join("b.txt"), b"b").unwrap();
    std::fs::write(dir.join("a.txt"), b"a").unwrap();
    std::fs::create_dir_all(dir.join("sub")).unwrap();

    let r = http_get(port, "/");
    assert_eq!(status_line(&r), "HTTP/1.1 200 OK");
    assert_eq!(header(&r, "Content-Type").as_deref(), Some("text/html"));

    let b = std::str::from_utf8(body(&r)).unwrap();
    let ia = b.find("href=\"a.txt\"").unwrap();
    let ib = b.find("href=\"b.txt\"").unwrap();
    assert!(ia < ib, "expected a.txt before b.txt");
    assert!(b.contains("href=\"sub/\""));
}

#[test]
fn autoindex_subpath_shows_parent_entry() {
    let conf = r#"
events {}
http {
  server {
    listen 127.0.0.1:%%PORT%%;
    location / {
      root %%DIR%%;
      autoindex on;
    }
  }
}
"#;
    let (_g, port, dir) = spawn_server(conf);
    std::fs::create_dir_all(dir.join("sub")).unwrap();
    std::fs::write(dir.join("sub/x.txt"), b"x").unwrap();

    let r = http_get(port, "/sub/");
    assert_eq!(status_line(&r), "HTTP/1.1 200 OK");
    let b = std::str::from_utf8(body(&r)).unwrap();
    assert!(b.contains("href=\"../\""));
    assert!(b.contains(">../<"));
}

#[test]
fn autoindex_exact_size_off_rounds_units() {
    let conf = r#"
events {}
http {
  server {
    listen 127.0.0.1:%%PORT%%;
    location / {
      root %%DIR%%;
      autoindex on;
      autoindex_exact_size off;
    }
  }
}
"#;
    let (_g, port, dir) = spawn_server(conf);
    std::fs::write(dir.join("big.bin"), vec![b'x'; 1100]).unwrap();

    let r = http_get(port, "/");
    assert_eq!(status_line(&r), "HTTP/1.1 200 OK");
    let b = std::str::from_utf8(body(&r)).unwrap();
    assert!(
        b.contains("2K"),
        "expected rounded size in K units, got: {b}"
    );
}

#[test]
fn autoindex_url_encodes_href() {
    let conf = r#"
events {}
http {
  server {
    listen 127.0.0.1:%%PORT%%;
    location / {
      root %%DIR%%;
      autoindex on;
    }
  }
}
"#;
    let (_g, port, dir) = spawn_server(conf);
    std::fs::write(dir.join("test-colon:blah"), b"").unwrap();
    std::fs::write(dir.join("test-escape-url2-?"), b"").unwrap();
    std::fs::write(dir.join("test-escape-url-%"), b"").unwrap();

    let r = http_get(port, "/");
    assert_eq!(status_line(&r), "HTTP/1.1 200 OK");
    let b = std::str::from_utf8(body(&r)).unwrap();
    assert!(b.contains("href=\"test-colon%3Ablah\""));
    assert!(b.contains("href=\"test-escape-url2-%3F\""));
    assert!(b.contains("href=\"test-escape-url-%25\""));
}

#[test]
fn autoindex_json_format_returns_array() {
    let conf = r#"
events {}
http {
  server {
    listen 127.0.0.1:%%PORT%%;
    location / {
      root %%DIR%%;
      autoindex on;
      autoindex_format json;
    }
  }
}
"#;
    let (_g, port, dir) = spawn_server(conf);
    std::fs::write(dir.join("a.txt"), b"abc").unwrap();
    std::fs::create_dir(dir.join("sub")).unwrap();

    let r = http_get(port, "/");
    assert_eq!(status_line(&r), "HTTP/1.1 200 OK");
    assert_eq!(
        header(&r, "content-type").as_deref(),
        Some("application/json")
    );
    let b = std::str::from_utf8(body(&r)).unwrap();
    assert!(b.starts_with('[') && b.ends_with(']'), "body: {b}");
    assert!(b.contains(r#""name":"a.txt""#), "body: {b}");
    assert!(b.contains(r#""type":"file""#), "body: {b}");
    assert!(b.contains(r#""size":3"#), "body: {b}");
    assert!(b.contains(r#""name":"sub""#), "body: {b}");
    assert!(b.contains(r#""type":"directory""#), "body: {b}");
}

#[test]
fn autoindex_xml_format_renders_list() {
    let conf = r#"
events {}
http {
  server {
    listen 127.0.0.1:%%PORT%%;
    location / {
      root %%DIR%%;
      autoindex on;
      autoindex_format xml;
    }
  }
}
"#;
    let (_g, port, dir) = spawn_server(conf);
    std::fs::write(dir.join("a.txt"), b"abc").unwrap();
    std::fs::create_dir(dir.join("sub")).unwrap();

    let r = http_get(port, "/");
    assert_eq!(status_line(&r), "HTTP/1.1 200 OK");
    assert_eq!(
        header(&r, "content-type").as_deref(),
        Some("text/xml; charset=utf-8")
    );
    let b = std::str::from_utf8(body(&r)).unwrap();
    assert!(b.starts_with(r#"<?xml version="1.0"?>"#), "body: {b}");
    assert!(b.contains("<list>") && b.contains("</list>"), "body: {b}");
    assert!(b.contains(r#"<file mtime=""#), "body: {b}");
    assert!(b.contains(r#" size="3""#), "body: {b}");
    assert!(b.contains(">a.txt</file>"), "body: {b}");
    assert!(b.contains(">sub</directory>"), "body: {b}");
}

#[test]
fn autoindex_jsonp_format_wraps_in_callback() {
    let conf = r#"
events {}
http {
  server {
    listen 127.0.0.1:%%PORT%%;
    location / {
      root %%DIR%%;
      autoindex on;
      autoindex_format jsonp;
    }
  }
}
"#;
    let (_g, port, dir) = spawn_server(conf);
    std::fs::write(dir.join("a.txt"), b"abc").unwrap();

    let r = http_get(port, "/?callback=cb");
    assert_eq!(status_line(&r), "HTTP/1.1 200 OK");
    assert_eq!(
        header(&r, "content-type").as_deref(),
        Some("application/json")
    );
    let b = std::str::from_utf8(body(&r)).unwrap();
    assert!(b.starts_with("cb("), "body: {b}");
    assert!(b.ends_with(");"), "body: {b}");
    assert!(b.contains(r#""name":"a.txt""#), "body: {b}");

    // No callback => bare JSON array.
    let r = http_get(port, "/");
    let b = std::str::from_utf8(body(&r)).unwrap();
    assert!(b.starts_with('[') && b.ends_with(']'), "body: {b}");
}
