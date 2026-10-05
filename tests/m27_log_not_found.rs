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
        "ruxen-m27-{}-{}",
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
        .env("RUXEN_WORKERS", "1")
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
fn location_log_not_found_off_suppresses_404_error_log_line() {
    let (guard, port) = spawn_server(|dir| {
        format!(
            r#"
    location /on/ {{
      error_log {root}/on.log;
    }}
    location /off/ {{
      error_log {root}/off.log;
      log_not_found off;
    }}
"#,
            root = dir.display()
        )
    });

    let on = request(
        port,
        b"GET /on/missing HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_line(&on), "HTTP/1.1 404 Not Found");

    let off = request(
        port,
        b"GET /off/missing HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_line(&off), "HTTP/1.1 404 Not Found");

    sleep(Duration::from_millis(20));
    let on_log = std::fs::read_to_string(guard.tempdir.join("on.log")).unwrap_or_default();
    let off_log = std::fs::read_to_string(guard.tempdir.join("off.log")).unwrap_or_default();
    assert!(on_log.contains("error"));
    assert!(!off_log.contains("error"));
}

#[test]
fn server_log_not_found_off_can_be_overridden_in_location() {
    let (guard, port) = spawn_server(|dir| {
        format!(
            r#"
    error_log {root}/server.log;
    log_not_found off;
    location /inherit/ {{ }}
    location /override/ {{
      log_not_found on;
    }}
"#,
            root = dir.display()
        )
    });

    let inherit = request(
        port,
        b"GET /inherit/missing HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_line(&inherit), "HTTP/1.1 404 Not Found");

    let override_on = request(
        port,
        b"GET /override/missing HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_line(&override_on), "HTTP/1.1 404 Not Found");

    sleep(Duration::from_millis(20));
    let server_log = std::fs::read_to_string(guard.tempdir.join("server.log")).unwrap_or_default();
    assert!(!server_log.contains("/inherit/missing"));
    assert!(server_log.contains("/override/missing"));
}

/// The error-log lines name the file nginx tried, in its static and index
/// modules' words; a 404 that isn't a file lookup (`return 404`) logs
/// nothing. ruxen used to print `open() "<uri>" failed (2: …)` for every
/// 404, whatever produced it.
#[test]
fn lookup_errors_name_the_path_like_nginx() {
    let (guard, port) = spawn_server(|dir| {
        std::fs::create_dir(dir.join("noindex")).unwrap();
        format!(
            r#"
    error_log {root}/e.log;
    location = /ret {{ return 404; }}
"#,
            root = dir.display()
        )
    });
    let root = guard.tempdir.canonicalize().unwrap();
    let get = |path: &str| {
        let raw = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        status_line(&request(port, raw.as_bytes())).to_string()
    };
    assert_eq!(get("/missing.txt"), "HTTP/1.1 404 Not Found");
    assert_eq!(get("/nodir/"), "HTTP/1.1 404 Not Found");
    assert_eq!(get("/noindex/"), "HTTP/1.1 403 Forbidden");
    assert_eq!(get("/ret"), "HTTP/1.1 404 Not Found");
    sleep(Duration::from_millis(30));

    let log = std::fs::read_to_string(guard.tempdir.join("e.log")).unwrap_or_default();
    let lines: Vec<&str> = log.lines().collect();
    assert_eq!(lines.len(), 3, "{log}");
    let root = root.display();
    assert!(
        lines[0].contains(&format!(
            "open() \"{root}/missing.txt\" failed (2: No such file or directory)"
        )),
        "{log}"
    );
    assert!(
        lines[1].contains(&format!(
            "\"{root}/nodir/\" is not found (2: No such file or directory)"
        )),
        "{log}"
    );
    assert!(
        lines[2].contains(&format!(
            "directory index of \"{root}/noindex/\" is forbidden"
        )),
        "{log}"
    );
}

/// Two connections on one worker: the first is stalled writing a large
/// error page while the second asks for another missing file. Each request
/// gets its own `open() failed` line, with its own context, as nginx logs
/// the line where the open fails. The note used to be read only after the
/// response was written, so the stalled request's line went missing (or
/// carried the other request's context).
#[test]
fn concurrent_lookups_each_log_their_own_line() {
    let (guard, port) = spawn_server(|dir| {
        std::fs::write(dir.join("big"), vec![b'x'; 8 << 20]).unwrap();
        format!(
            "    error_log {root}/e.log;\n    error_page 404 /big;\n    location / {{ }}\n",
            root = dir.display()
        )
    });
    let mut stalled = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stalled
        .write_all(b"GET /a-miss HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .unwrap();
    sleep(Duration::from_millis(200));
    let other = request(
        port,
        b"GET /b-miss HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_line(&other), "HTTP/1.1 404 Not Found");
    stalled
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut rest = Vec::new();
    let _ = stalled.read_to_end(&mut rest);
    assert_eq!(status_line(&rest), "HTTP/1.1 404 Not Found");
    sleep(Duration::from_millis(100));

    let log = std::fs::read_to_string(guard.tempdir.join("e.log")).unwrap_or_default();
    for name in ["a-miss", "b-miss"] {
        let lines: Vec<&str> = log
            .lines()
            .filter(|l| l.contains(&format!("/{name}\" failed")))
            .collect();
        assert_eq!(lines.len(), 1, "{name}: {log}");
        assert!(
            lines[0].contains(&format!("request: \"GET /{name} HTTP/1.1\"")),
            "{name}: {log}"
        );
    }
}
