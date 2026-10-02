//! M48 — every response carries one current `Date`, right after `Server`
//! like nginx: prebuilt `return`s (with and without literal `add_header`),
//! per-request responses, static files, 304s, error pages, early 400s, and
//! proxied responses (the upstream's `Date` is replaced, as nginx hides it).
//! Prebuilt heads are cached per worker, so a later request must not see the
//! date from when they were built.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, MutexGuard};
use std::thread::sleep;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

struct ServerGuard {
    child: Child,
    dir: PathBuf,
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

static SETUP_LOCK: Mutex<()> = Mutex::new(());

fn pick_port() -> (u16, MutexGuard<'static, ()>) {
    let guard = SETUP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    (port, guard)
}

/// Upstream that always answers with its own (old) `Date` and `Server`.
fn spawn_upstream() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut conn) = conn else { continue };
            let mut got = Vec::new();
            let mut buf = [0u8; 1024];
            while !got.windows(4).any(|w| w == b"\r\n\r\n") {
                match conn.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => got.extend_from_slice(&buf[..n]),
                }
            }
            let _ = conn.write_all(
                b"HTTP/1.1 200 OK\r\nServer: up\r\nDate: Mon, 01 Jan 2001 00:00:00 GMT\r\n\
                  Content-Length: 2\r\nConnection: close\r\n\r\nup",
            );
        }
    });
    port
}

fn spawn() -> (ServerGuard, u16) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "ruxen-m48-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(dir.join("html/static")).unwrap();
    std::fs::write(dir.join("html/static/a.txt"), "file\n").unwrap();
    let upstream = spawn_upstream();
    let (port, _lock) = pick_port();
    let conf = dir.join("ruxen.conf");
    std::fs::write(
        &conf,
        format!(
            r#"pid {d}/ruxen.pid;
events {{}}
http {{
  access_log off;
  server {{
    listen 127.0.0.1:{port};
    root {d}/html;
    location /ret {{
      return 200 "hello";
    }}
    location /lit {{
      add_header X-A one;
      return 200 "lit";
    }}
    location /var {{
      add_header X-Uri $request_uri;
      return 200 "var";
    }}
    location /proxy {{
      proxy_pass http://127.0.0.1:{upstream};
    }}
  }}
}}
"#,
            d = dir.display()
        ),
    )
    .unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .args(["-c", conf.to_str().unwrap()])
        .env("RUXEN_WORKERS", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ruxen");
    let deadline = Instant::now() + Duration::from_secs(3);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "ruxen did not start");
        sleep(Duration::from_millis(20));
    }
    (ServerGuard { child, dir }, port)
}

/// Send one request on `stream` and read back exactly one response head
/// (the body is Content-Length framed and skipped).
fn exchange(stream: &mut TcpStream, request: &str) -> String {
    stream.write_all(request.as_bytes()).unwrap();
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        if let Some(i) = got.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8(got[..i + 4].to_vec()).unwrap();
            let len: usize = header(&head, "content-length")
                .map(|v| v.parse().unwrap())
                .unwrap_or(0);
            while got.len() < i + 4 + len {
                let n = stream.read(&mut buf).unwrap();
                assert!(n > 0);
                got.extend_from_slice(&buf[..n]);
            }
            return head;
        }
        let n = stream.read(&mut buf).unwrap();
        assert!(n > 0, "connection closed");
        got.extend_from_slice(&buf[..n]);
    }
}

fn get(stream: &mut TcpStream, path: &str) -> String {
    exchange(stream, &format!("GET {path} HTTP/1.1\r\nHost: t\r\n\r\n"))
}

fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

/// Parse an IMF-fixdate (`Sun, 06 Nov 1994 08:49:37 GMT`) to Unix seconds.
fn parse_http_date(s: &str) -> u64 {
    assert_eq!(s.len(), 29, "{s}");
    assert!(s.ends_with(" GMT"), "{s}");
    const MON: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let day: i64 = s[5..7].parse().unwrap();
    let month = MON.iter().position(|m| *m == &s[8..11]).unwrap() as i64 + 1;
    let year: i64 = s[12..16].parse().unwrap();
    let h: u64 = s[17..19].parse().unwrap();
    let m: u64 = s[20..22].parse().unwrap();
    let sec: u64 = s[23..25].parse().unwrap();
    // Howard Hinnant's days_from_civil.
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = (era * 146_097 + doe - 719_468) as u64;
    days * 86_400 + h * 3_600 + m * 60 + sec
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Exactly one `Date`, directly after `Server`, within a couple of seconds
/// of now. Returns its value.
fn assert_current_date<'a>(head: &'a str, after_server: bool) -> &'a str {
    assert_eq!(head.matches("\r\nDate: ").count(), 1, "{head}");
    if after_server {
        let server = format!("\r\nServer: ruxen/{}\r\nDate: ", env!("CARGO_PKG_VERSION"));
        assert!(head.contains(&server), "{head}");
    }
    let date = header(head, "date").unwrap();
    let at = parse_http_date(date);
    let now = unix_now();
    assert!(at + 2 >= now && at <= now + 1, "Date {date} vs now {now}");
    date
}

#[test]
fn every_response_kind_carries_a_current_date() {
    let (_g, port) = spawn();
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();

    for path in ["/ret", "/lit", "/var?a=1", "/static/a.txt", "/missing"] {
        let head = get(&mut s, path);
        assert_current_date(&head, true);
    }

    let head = get(&mut s, "/proxy");
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_current_date(&head, false);
}

#[test]
fn not_modified_has_date_and_no_accept_ranges() {
    let (_g, port) = spawn();
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let head = get(&mut s, "/static/a.txt");
    let lm = header(&head, "last-modified").unwrap().to_string();
    let head = exchange(
        &mut s,
        &format!("GET /static/a.txt HTTP/1.1\r\nHost: t\r\nIf-Modified-Since: {lm}\r\n\r\n"),
    );
    assert!(head.starts_with("HTTP/1.1 304"), "{head}");
    assert_current_date(&head, true);
    assert!(!head.contains("Accept-Ranges"), "{head}");
}

#[test]
fn early_bad_request_carries_a_date() {
    let (_g, port) = spawn();
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    // Transfer-Encoding together with Content-Length: rejected before routing.
    s.write_all(
        b"POST /ret HTTP/1.1\r\nHost: t\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n",
    )
    .unwrap();
    let mut got = String::new();
    s.read_to_string(&mut got).unwrap();
    assert!(got.starts_with("HTTP/1.1 400"), "{got}");
    assert_current_date(&got, true);
}

#[test]
fn prebuilt_responses_do_not_keep_a_stale_date() {
    let (_g, port) = spawn();
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    for path in ["/ret", "/lit"] {
        let first = assert_current_date(&get(&mut s, path), true).to_string();
        // Wait for the wall clock to move past the first response's second.
        let deadline = Instant::now() + Duration::from_secs(3);
        while parse_http_date(&first) >= unix_now() {
            assert!(Instant::now() < deadline);
            sleep(Duration::from_millis(50));
        }
        sleep(Duration::from_millis(50)); // let the coarse clock tick over too
        let head = get(&mut s, path);
        let second = assert_current_date(&head, true);
        assert_ne!(first, second, "{path}: same Date a second later");
    }
}
