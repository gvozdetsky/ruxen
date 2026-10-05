use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::UnixDatagram;
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
        "ruxen-m34-{}-{}",
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

fn spawn_server<F>(build_server_body: F) -> (ServerGuard, u16)
where
    F: FnOnce(&PathBuf) -> String,
{
    let (port, _lock) = pick_port();
    let dir = unique_dir();
    std::fs::write(dir.join("index.html"), b"ok").unwrap();

    let server_body = build_server_body(&dir);
    let conf_path = dir.join("ruxen.conf");
    std::fs::write(
        &conf_path,
        format!(
            r#"
events {{ }}
http {{
  server {{
    listen 127.0.0.1:{port};
    root {root};
{server_body}
  }}
}}
"#,
            root = dir.display()
        ),
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
            tempdir: dir,
        },
        port,
    )
}

fn request(port: u16, raw: &[u8]) -> Vec<u8> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    s.write_all(raw).unwrap();
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

#[test]
fn m34_error_log_syslog_unix_sink_and_level_filter() {
    let dir = unique_dir();
    let sock_path = dir.join("ruxen-error-log.sock");
    let sock = UnixDatagram::bind(&sock_path).unwrap();

    let (guard, port) = spawn_server(|_| {
        format!(
            r#"
    location /off/ {{
      error_log syslog:server=unix:{sock},tag=m34 crit;
    }}
    location /on/ {{
      error_log syslog:server=unix:{sock},tag=m34 warn;
    }}
"#,
            sock = sock_path.display(),
        )
    });

    let off = request(
        port,
        b"GET /off/missing HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_line(&off), "HTTP/1.1 404 Not Found");

    sock.set_read_timeout(Some(Duration::from_millis(150)))
        .unwrap();
    let mut buf = [0u8; 2048];
    match sock.recv(&mut buf) {
        Ok(n) => panic!(
            "unexpected syslog datagram after /off request: {}",
            String::from_utf8_lossy(&buf[..n])
        ),
        Err(e)
            if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut => {}
        Err(e) => panic!("recv failed: {e}"),
    }

    let on = request(
        port,
        b"GET /on/missing HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_line(&on), "HTTP/1.1 404 Not Found");

    sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let n = sock.recv(&mut buf).expect("recv syslog datagram");
    let msg = String::from_utf8_lossy(&buf[..n]);
    // nginx's datagram: local7 with the line's level (error), the RFC 3164
    // header, then the whole error-log line.
    let re = regex::Regex::new(
        r#"^<187>[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d \S+ m34: \d{4}/\d\d/\d\d \d\d:\d\d:\d\d \[error\] \d+#\d+: \*\d+ open\(\) ".*/on/missing" failed"#,
    )
    .unwrap();
    assert!(re.is_match(&msg), "{msg:?}");

    drop(guard);
    let _ = std::fs::remove_dir_all(&dir);
}

/// `facility=` and `nohostname` apply, over UDP; `severity=` doesn't (the
/// line's level does), as nginx's ngx_syslog_writer. They used to be
/// parsed and ignored, with facility user always.
#[test]
fn m34_error_log_syslog_facility_and_nohostname() {
    let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    udp.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let peer = udp.local_addr().unwrap();
    let (guard, port) = spawn_server(|_| {
        format!(
            "    location / {{ error_log syslog:server={peer},facility=user,severity=alert,nohostname; }}\n"
        )
    });
    let resp = request(
        port,
        b"GET /missing HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_line(&resp), "HTTP/1.1 404 Not Found");
    let mut buf = [0u8; 2048];
    let n = udp.recv(&mut buf).expect("recv syslog datagram");
    let msg = String::from_utf8_lossy(&buf[..n]);
    // user.error = 1 * 8 + 3; no host before the tag.
    let re = regex::Regex::new(
        r#"^<11>[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d ruxen: \d{4}/\d\d/\d\d \d\d:\d\d:\d\d \[error\] .*/missing" failed"#,
    )
    .unwrap();
    assert!(re.is_match(&msg), "{msg:?}");
    drop(guard);
}
