//! M53 — client_header_timeout, client_body_timeout and send_timeout. A
//! client that connects and sends nothing, sends half a header, stops in
//! the middle of a body, or stops reading a large response is
//! disconnected after the timeout (nginx's default is 60 s; the tests set
//! 1 s). Before, such connections stayed open indefinitely.

use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

struct Server {
    child: Child,
    port: u16,
    dir: PathBuf,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

const BIG: usize = 64 * 1024 * 1024;

fn start(tag: &str, sendfile: bool) -> Server {
    let port = {
        let probe = TcpListener::bind("127.0.0.1:0").unwrap();
        probe.local_addr().unwrap().port()
    };
    let dir = std::env::temp_dir().join(format!("ruxen-m53-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("big.bin"), vec![b'x'; BIG]).unwrap();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "events {{}}\nhttp {{\n  client_header_timeout 1s;\n  client_body_timeout 1s;\n\
             server {{ listen 127.0.0.1:{port}; root {}; sendfile {}; send_timeout 1s;\n\
               location = /echo {{ return 200 \"ok\"; }} }} }}\n",
            dir.display(),
            if sendfile { "on" } else { "off" }
        ),
    )
    .unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .arg("-c")
        .arg(dir.join("nginx.conf"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "ruxen did not start");
        sleep(Duration::from_millis(20));
    }
    Server { child, port, dir }
}

/// Seconds until the server closes `s` (EOF or reset), reading and
/// discarding anything it sends; `None` if still open after `limit`.
fn closed_after(s: &mut TcpStream, limit: Duration) -> Option<Duration> {
    let start = Instant::now();
    s.set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let mut buf = [0u8; 65536];
    while start.elapsed() < limit {
        match s.read(&mut buf) {
            Ok(0) => return Some(start.elapsed()),
            Ok(_) => {}
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(_) => return Some(start.elapsed()),
        }
    }
    None
}

#[test]
fn silent_connection_is_closed_after_client_header_timeout() {
    let server = start("silent", false);
    let mut s = TcpStream::connect(("127.0.0.1", server.port)).unwrap();
    let t = closed_after(&mut s, Duration::from_secs(5)).expect("still open after 5 s");
    assert!(t >= Duration::from_millis(800), "closed too early: {t:?}");
}

#[test]
fn header_deadline_covers_the_whole_header() {
    let server = start("drip", false);
    let mut s = TcpStream::connect(("127.0.0.1", server.port)).unwrap();
    let start = Instant::now();
    s.write_all(b"GET /echo HTTP/1.1\r\n").unwrap();
    // One byte every 300 ms: each read is quick, the header never ends.
    let mut closed = false;
    for b in b"Host: example.test\r\nX-Slow: yes\r\n".iter() {
        sleep(Duration::from_millis(300));
        if s.write_all(&[*b]).is_err() {
            closed = true;
            break;
        }
        if start.elapsed() > Duration::from_secs(4) {
            break;
        }
    }
    let closed = closed || closed_after(&mut s, Duration::from_secs(2)).is_some();
    assert!(closed, "a dripped header kept the connection open");
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "{:?}",
        start.elapsed()
    );
}

#[test]
fn stalled_body_is_closed_after_client_body_timeout() {
    let server = start("body", false);
    let mut s = TcpStream::connect(("127.0.0.1", server.port)).unwrap();
    s.write_all(b"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\nabc")
        .unwrap();
    let t = closed_after(&mut s, Duration::from_secs(5)).expect("still open after 5 s");
    assert!(t >= Duration::from_millis(800), "closed too early: {t:?}");
}

#[test]
fn keepalive_still_works_within_the_timeouts() {
    let server = start("ok", false);
    let mut s = TcpStream::connect(("127.0.0.1", server.port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    for _ in 0..3 {
        s.write_all(b"GET /echo HTTP/1.1\r\nHost: x\r\n\r\n")
            .unwrap();
        let mut buf = [0u8; 1024];
        let n = s.read(&mut buf).unwrap();
        assert!(buf[..n].starts_with(b"HTTP/1.1 200"));
        assert!(buf[..n].ends_with(b"ok"));
        sleep(Duration::from_millis(400));
    }
}

fn stalled_reader_is_cut_off(sendfile: bool) {
    let server = start(if sendfile { "send-sf" } else { "send" }, sendfile);
    let mut s = TcpStream::connect(("127.0.0.1", server.port)).unwrap();
    s.write_all(b"GET /big.bin HTTP/1.1\r\nHost: x\r\n\r\n")
        .unwrap();
    // Don't read: the socket buffers fill and every send stalls.
    sleep(Duration::from_secs(3));
    // send_timeout has fired by now: draining yields less than the file,
    // then EOF. Without it the server would resume and send everything.
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut total = 0usize;
    let mut buf = vec![0u8; 1 << 20];
    loop {
        match s.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                panic!("connection still open after send_timeout; read {total} bytes")
            }
            Err(_) => break,
        }
    }
    assert!(total < BIG, "the whole file arrived ({total} bytes)");
}

#[test]
fn stalled_reader_is_cut_off_by_send_timeout() {
    stalled_reader_is_cut_off(false);
}

#[test]
fn stalled_reader_is_cut_off_by_send_timeout_with_sendfile() {
    stalled_reader_is_cut_off(true);
}
