mod common;

use std::fs::File;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::MutexGuard;
use std::thread::sleep;
use std::time::Duration;

const ONE_MIB: usize = 1024 * 1024;
const SIXTEEN_MIB: usize = 16 * 1024 * 1024;

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

fn unique_dir(tag: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let d = std::env::temp_dir().join(format!(
        "ruxen-m19-{}-{}-{}",
        tag,
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir(&d).unwrap();
    d
}

fn pattern_byte(i: usize) -> u8 {
    (i % 251) as u8
}

fn expected_pattern(offset: usize, len: usize) -> Vec<u8> {
    (offset..offset + len).map(pattern_byte).collect()
}

fn write_pattern_file(path: &Path, len: usize) {
    let mut file = File::create(path).unwrap();
    let mut i = 0usize;
    let mut chunk = vec![0u8; 65_536];
    while i < len {
        let n = (len - i).min(chunk.len());
        for (j, b) in chunk[..n].iter_mut().enumerate() {
            *b = pattern_byte(i + j);
        }
        file.write_all(&chunk[..n]).unwrap();
        i += n;
    }
}

fn spawn_server() -> (ServerGuard, u16) {
    let (port, _lock) = pick_port();
    let dir = unique_dir("main");

    std::fs::write(dir.join("small.txt"), b"small-streaming-body\n").unwrap();
    write_pattern_file(&dir.join("1m.bin"), ONE_MIB);
    write_pattern_file(&dir.join("16m.bin"), SIXTEEN_MIB);

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
    location / {{ }}
    location /sf/ {{ alias {root}/; sendfile on; }}
    location /lr/ {{ alias {root}/; limit_rate 100m; }}
  }}
}}
"#,
            root = dir.display()
        ),
    )
    .unwrap();

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

fn spawn_race_server() -> (ServerGuard, u16, PathBuf) {
    let (port, _lock) = pick_port();
    let dir = unique_dir("race");

    let race_path = dir.join("race.bin");
    write_pattern_file(&race_path, 64 * ONE_MIB);

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
    location / {{ }}
  }}
}}
"#,
            root = dir.display()
        ),
    )
    .unwrap();

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
    (guard, port, race_path)
}

fn header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

fn content_length(buf: &[u8]) -> Option<usize> {
    let head_end = header_end(buf)?;
    for line in buf[..head_end - 2].split(|&b| b == b'\n').skip(1) {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let colon = line.iter().position(|&b| b == b':')?;
        if line[..colon].eq_ignore_ascii_case(b"Content-Length") {
            let mut v = &line[colon + 1..];
            while v.first().is_some_and(|b| *b == b' ' || *b == b'\t') {
                v = &v[1..];
            }
            return std::str::from_utf8(v).ok()?.trim().parse().ok();
        }
    }
    None
}

fn read_one_response(stream: &mut TcpStream) -> Vec<u8> {
    let mut out = Vec::new();
    let mut tmp = [0u8; 65_536];
    loop {
        match stream.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&tmp[..n]),
            Err(_) => break,
        }

        let Some(end) = header_end(&out) else {
            continue;
        };
        let Some(cl) = content_length(&out) else {
            continue;
        };
        if out.len() >= end + cl {
            out.truncate(end + cl);
            break;
        }
    }
    out
}

fn request(port: u16, raw: &[u8]) -> Vec<u8> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(raw).unwrap();
    read_one_response(&mut s)
}

fn status_line(resp: &[u8]) -> &str {
    let end = resp.iter().position(|&b| b == b'\r').unwrap_or(resp.len());
    std::str::from_utf8(&resp[..end]).unwrap()
}

fn header_value<'a>(resp: &'a [u8], name: &str) -> Option<&'a str> {
    let head_end = header_end(resp)?;
    for line in resp[..head_end - 2].split(|&b| b == b'\n').skip(1) {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if let Some(colon) = line.iter().position(|&b| b == b':')
            && line[..colon].eq_ignore_ascii_case(name.as_bytes())
        {
            let mut v = &line[colon + 1..];
            while v.first().is_some_and(|b| *b == b' ' || *b == b'\t') {
                v = &v[1..];
            }
            while v.last().is_some_and(|b| *b == b' ' || *b == b'\t') {
                v = &v[..v.len() - 1];
            }
            return std::str::from_utf8(v).ok();
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
fn small_file_round_trip_streaming() {
    let (_guard, port) = spawn_server();
    let r = request(
        port,
        b"GET /small.txt HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_line(&r), "HTTP/1.1 200 OK");
    assert_eq!(body(&r), b"small-streaming-body\n");
}

#[test]
fn one_meg_file_round_trip_streaming() {
    let (_guard, port) = spawn_server();
    let r = request(
        port,
        b"GET /1m.bin HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_line(&r), "HTTP/1.1 200 OK");
    assert_eq!(header_value(&r, "Content-Length"), Some("1048576"));
    assert_eq!(body(&r), expected_pattern(0, ONE_MIB).as_slice());
}

#[test]
fn sixteen_meg_file_round_trip_streaming() {
    let (_guard, port) = spawn_server();
    let r = request(
        port,
        b"GET /16m.bin HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_line(&r), "HTTP/1.1 200 OK");
    assert_eq!(header_value(&r, "Content-Length"), Some("16777216"));
    assert_eq!(body(&r), expected_pattern(0, SIXTEEN_MIB).as_slice());
}

#[test]
fn head_has_no_body_and_content_length() {
    let (_guard, port) = spawn_server();
    let r = request(
        port,
        b"HEAD /16m.bin HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_line(&r), "HTTP/1.1 200 OK");
    assert_eq!(header_value(&r, "Content-Length"), Some("16777216"));
    assert_eq!(body(&r), b"");
}

#[test]
fn range_206_streams_requested_slice() {
    let (_guard, port) = spawn_server();
    let r = request(
        port,
        b"GET /16m.bin HTTP/1.1\r\nHost: localhost\r\nRange: bytes=12345-22344\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_line(&r), "HTTP/1.1 206 Partial Content");
    assert_eq!(header_value(&r, "Content-Length"), Some("10000"));
    assert_eq!(
        header_value(&r, "Content-Range"),
        Some("bytes 12345-22344/16777216")
    );
    assert_eq!(body(&r), expected_pattern(12_345, 10_000).as_slice());
}

/// #414: several ranges larger than 1 MiB in total are a multipart 206
/// sent from the file (sendfile, read-and-write, paced), and the
/// connection carries on after it.
#[test]
fn large_multipart_ranges_stream_from_the_file() {
    let (_guard, port) = spawn_server();
    let ranges = [(0usize, 1_000_000usize), (2_000_000, 3_000_000), (5, 6)];
    for prefix in ["/", "/sf/", "/lr/"] {
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        write!(
            s,
            "GET {prefix}16m.bin HTTP/1.1\r\nHost: localhost\r\n\
             Range: bytes=0-999999,2000000-2999999,5-5\r\n\r\n"
        )
        .unwrap();
        let r = read_one_response(&mut s);
        assert_eq!(status_line(&r), "HTTP/1.1 206 Partial Content", "{prefix}");
        let boundary = header_value(&r, "Content-Type")
            .and_then(|t| t.strip_prefix("multipart/byteranges; boundary="))
            .unwrap()
            .to_string();
        let mut want = Vec::new();
        for (start, end) in ranges {
            want.extend_from_slice(
                format!(
                    "\r\n--{boundary}\r\nContent-Type: text/plain\r\n\
                     Content-Range: bytes {start}-{}/16777216\r\n\r\n",
                    end - 1
                )
                .as_bytes(),
            );
            want.extend_from_slice(&expected_pattern(start, end - start));
        }
        want.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        assert_eq!(
            header_value(&r, "Content-Length"),
            Some(want.len().to_string().as_str())
        );
        assert!(body(&r) == want.as_slice(), "{prefix}: body differs");

        s.write_all(b"GET /small.txt HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .unwrap();
        let r = read_one_response(&mut s);
        assert_eq!(body(&r), b"small-streaming-body\n", "{prefix}");
    }
}

#[test]
#[ignore = "flaky by nature; run manually"]
fn racing_truncate_can_produce_truncated_stream_without_hanging_server() {
    let (_guard, port, race_path) = spawn_race_server();

    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.write_all(b"GET /race.bin HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();

    sleep(Duration::from_millis(20));
    let f = File::options().write(true).open(&race_path).unwrap();
    f.set_len(ONE_MIB as u64).unwrap();

    let resp = read_one_response(&mut s);
    assert_eq!(status_line(&resp), "HTTP/1.1 200 OK");

    let promised = header_value(&resp, "Content-Length")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    assert!(
        body(&resp).len() < promised,
        "expected truncated body after racing truncate"
    );
}
