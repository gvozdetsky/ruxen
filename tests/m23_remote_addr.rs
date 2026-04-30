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
        "ruxen-m23-{}-{}",
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

fn status_line(resp: &[u8]) -> &str {
    let i = resp
        .windows(2)
        .position(|w| w == b"\r\n")
        .expect("status line");
    std::str::from_utf8(&resp[..i]).unwrap()
}

fn header_value<'a>(resp: &'a [u8], name: &str) -> Option<&'a str> {
    let txt = std::str::from_utf8(resp).ok()?;
    let head_end = txt.find("\r\n\r\n")?;
    for line in txt[..head_end].split("\r\n").skip(1) {
        let (k, v) = line.split_once(':')?;
        if k.eq_ignore_ascii_case(name) {
            return Some(v.trim());
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
fn remote_addr_and_port_render_in_return_and_add_header() {
    let conf = r#"
events {}
http {
  server {
    listen 127.0.0.1:%%PORT%%;
    location / {
      add_header X-Remote "$remote_addr:$remote_port";
      return 200 "$remote_addr|$remote_port";
    }
  }
}
"#;
    let (_guard, port, _dir) = spawn_server(conf);
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let client_port = s.local_addr().unwrap().port();
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    s.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();

    let r = read_one_response(&mut s);
    let expected_header = format!("127.0.0.1:{client_port}");
    let expected_body = format!("127.0.0.1|{client_port}");
    assert_eq!(status_line(&r), "HTTP/1.1 200 OK");
    assert_eq!(header_value(&r, "X-Remote"), Some(expected_header.as_str()));
    assert_eq!(body(&r), expected_body.as_bytes());
}

#[test]
fn access_log_renders_remote_addr_and_port() {
    let conf = r#"
events {}
http {
  log_format m23 "$remote_addr:$remote_port";
  access_log %%DIR%%/access.log m23;

  server {
    listen 127.0.0.1:%%PORT%%;
    location / { return 200 ""; }
  }
}
"#;
    let (_guard, port, dir) = spawn_server(conf);
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let client_port = s.local_addr().unwrap().port();
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    s.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    let _ = read_one_response(&mut s);

    sleep(Duration::from_millis(50));
    let access = std::fs::read_to_string(dir.join("access.log")).unwrap();
    assert_eq!(access, format!("127.0.0.1:{client_port}\n"));
}
