//! M53 — client_header_timeout, client_body_timeout and send_timeout. A
//! client that connects and sends nothing, sends half a header, stops in
//! the middle of a body, or stops reading a large response is
//! disconnected after the timeout (nginx's default is 60 s; the tests set
//! 1 s). Before, such connections stayed open indefinitely.

mod common;

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
    // Held from the port pick until ruxen listens: a parallel test's
    // backend can't take the port in between (#230).
    let dir = std::env::temp_dir().join(format!("ruxen-m53-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("big.bin"), vec![b'x'; BIG]).unwrap();
    let setup = common::ports::setup_lock();
    let port = {
        let probe = TcpListener::bind("127.0.0.1:0").unwrap();
        probe.local_addr().unwrap().port()
    };
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "events {{}}\nhttp {{\n  client_header_timeout 1s;\n  client_body_timeout 1s;\n\
             log_format cut '$request $status $request_length';\n\
             access_log {}/access.log cut;\n\
             server {{ listen 127.0.0.1:{port}; root {}; sendfile {}; send_timeout 1s;\n\
               location = /echo {{ return 200 \"ok\"; }}\n\
               location = /up {{ proxy_pass http://127.0.0.1:{port}/echo; }} }} }}\n",
            dir.display(),
            dir.display(),
            if sendfile { "on" } else { "off" }
        ),
    )
    .unwrap();
    // Owned by `Server` before the wait: if it panics, ruxen still stops.
    let mut server = Server {
        child: Command::new(env!("CARGO_BIN_EXE_ruxen"))
            .arg("-c")
            .arg(dir.join("nginx.conf"))
            .arg("-g")
            .arg(format!("pid {}/ruxen.pid;", dir.display()))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
        port,
        dir,
    };
    let pid_file = server.dir.join("ruxen.pid");
    common::ports::wait_for_pid_file(&mut server.child, &pid_file, Duration::from_secs(3));
    drop(setup);
    server
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

/// #858: a chunked one too, unanswered, as nginx terminates on 408.
#[test]
fn stalled_chunked_body_is_closed_unanswered() {
    let server = start("chunked", false);
    let mut s = TcpStream::connect(("127.0.0.1", server.port)).unwrap();
    // Proxied: the body is read before the response.
    s.write_all(b"POST /up HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nabc")
        .unwrap();
    let start = Instant::now();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut out = Vec::new();
    s.read_to_end(&mut out).unwrap();
    assert!(out.is_empty(), "{}", String::from_utf8_lossy(&out));
    let t = start.elapsed();
    assert!(t >= Duration::from_millis(800), "closed too early: {t:?}");
}

/// #866: a request cut while its body is read is logged as nginx does:
/// 408 on the timeout, 400 for a client gone; the bytes read so far.
#[test]
fn cut_body_is_logged() {
    let server = start("cutlog", false);
    let cases: [(&[u8], bool); 3] = [
        (
            b"POST /up HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\nabc",
            false,
        ),
        (
            b"POST /up HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nabc",
            false,
        ),
        (
            b"POST /up HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\nabc",
            true,
        ),
    ];
    for (head, close) in cases {
        let mut s = TcpStream::connect(("127.0.0.1", server.port)).unwrap();
        s.write_all(head).unwrap();
        if close {
            sleep(Duration::from_millis(200));
            s.shutdown(std::net::Shutdown::Write).unwrap();
        }
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut out = Vec::new();
        let _ = s.read_to_end(&mut out);
        assert!(out.is_empty(), "{}", String::from_utf8_lossy(&out));
    }
    sleep(Duration::from_millis(200));
    let log = std::fs::read_to_string(server.dir.join("access.log")).unwrap();
    assert_eq!(
        log,
        "POST /up HTTP/1.1 408 53\nPOST /up HTTP/1.1 408 64\nPOST /up HTTP/1.1 400 53\n"
    );
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

/// The server's ESTABLISHED TCP sockets on 127.0.0.1:`port`, from
/// /proc/net/tcp (local address, then state `01`).
fn established_on(port: u16) -> usize {
    let local = format!("0100007F:{port:04X}");
    std::fs::read_to_string("/proc/net/tcp")
        .unwrap()
        .lines()
        .skip(1)
        .filter(|l| {
            let mut f = l.split_whitespace();
            f.nth(1) == Some(&local) && f.nth(1) == Some("01")
        })
        .count()
}

/// #510: the 400 for a bad request is sent under send_timeout. Clients
/// pipeline `n` good requests and a bad one and never read: for some `n`
/// the responses fill the buffers just before the 400, which then waits
/// for the client. nginx closes every such connection; ruxen kept one.
#[test]
fn rejected_request_is_cut_off_by_send_timeout() {
    let dir = std::env::temp_dir().join(format!("ruxen-m53-reject-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let setup = common::ports::setup_lock();
    let [port] = common::ports::free_ports();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "events {{}}\nhttp {{ access_log off; send_timeout 1s;\n\
             server {{ listen 127.0.0.1:{port} sndbuf=4k;\n\
               location / {{ return 200 \"{}\"; }} }} }}\n",
            "a".repeat(512)
        ),
    )
    .unwrap();
    let mut server = Server {
        child: Command::new(env!("CARGO_BIN_EXE_ruxen"))
            .arg("-c")
            .arg(dir.join("nginx.conf"))
            .arg("-g")
            .arg(format!("pid {}/ruxen.pid;", dir.display()))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
        port,
        dir,
    };
    let pid_file = server.dir.join("ruxen.pid");
    common::ports::wait_for_pid_file(&mut server.child, &pid_file, Duration::from_secs(3));
    drop(setup);

    let clients: Vec<socket2::Socket> = (0..40)
        .map(|n| {
            let s =
                socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
            s.set_recv_buffer_size(1024).unwrap();
            s.connect(&std::net::SocketAddr::from(([127, 0, 0, 1], server.port)).into())
                .unwrap();
            let mut requests = "GET / HTTP/1.1\r\nHost: x\r\n\r\n".repeat(n);
            requests.push_str("BAD\x01 / HTTP/1.1\r\nHost: x\r\n\r\n");
            let mut s = s;
            s.write_all(requests.as_bytes()).unwrap();
            s
        })
        .collect();
    let deadline = Instant::now() + Duration::from_secs(8);
    while established_on(server.port) > 0 {
        assert!(
            Instant::now() < deadline,
            "{} connections still open",
            established_on(server.port)
        );
        sleep(Duration::from_millis(100));
    }
    drop(clients);
}
