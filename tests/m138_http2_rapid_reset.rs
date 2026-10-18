//! M138 — HTTP/2 "rapid reset" (CVE-2023-44487): a client that opens
//! streams and resets them at once gets no more requests running than
//! `http2_max_concurrent_streams`, and a reset ends the upstream exchange
//! behind its stream with 499, as nginx's ngx_http_v2_state_rst_stream
//! does. Driven with hand-made frames, since curl doesn't reset streams.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// The server stops when the test ends, also when an assertion panics.
struct Server {
    child: Child,
    dir: std::path::PathBuf,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// ruxen with an HTTP/2 server on the port returned, configured by `conf`
/// (given the port).
fn start(name: &str, conf: impl FnOnce(u16) -> String) -> (Server, u16) {
    let dir = std::env::temp_dir().join(format!("ruxen-m138-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let setup = common::ports::setup_lock();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let d = dir.display();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "worker_processes 1;\npid {d}/ruxen.pid;\nerror_log {d}/error.log info;\n\
             events {{}}\nhttp {{\nlog_format t '$request_uri $status';\n\
             access_log {d}/access.log t;\n{}\n}}\n",
            conf(port)
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
    let mut s = Server { child, dir };
    common::ports::wait_for_pid_file(
        &mut s.child,
        &s.dir.join("ruxen.pid"),
        Duration::from_secs(5),
    );
    drop(setup);
    (s, port)
}

fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let mut f = (payload.len() as u32).to_be_bytes()[1..].to_vec();
    f.extend_from_slice(&[kind, flags]);
    f.extend_from_slice(&stream.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

/// HEADERS with END_STREAM and END_HEADERS: `GET path`, the fields
/// HPACK-coded without Huffman or indexing.
fn get(stream: u32, path: &str) -> Vec<u8> {
    // :method GET, :scheme http (static table 2, 6).
    let mut block = vec![0x82, 0x86];
    // :path, :authority: literal values, names from the static table.
    for (index, value) in [(4u8, path), (1, "localhost")] {
        block.push(index);
        block.push(value.len() as u8);
        block.extend_from_slice(value.as_bytes());
    }
    frame(0x1, 0x5, stream, &block)
}

/// RST_STREAM CANCEL, as a browser sends for a request it no longer needs.
fn cancel(stream: u32) -> Vec<u8> {
    frame(0x3, 0, stream, &0x8u32.to_be_bytes())
}

/// A client connection past the preface and its SETTINGS.
fn connect(port: u16) -> TcpStream {
    let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
    c.write_all(PREFACE).unwrap();
    c.write_all(&frame(0x4, 0, 0, &[])).unwrap();
    c
}

/// The next frame: type, flags, stream, payload.
fn read_frame(c: &mut TcpStream) -> std::io::Result<(u8, u8, u32, Vec<u8>)> {
    let mut head = [0u8; 9];
    c.read_exact(&mut head)?;
    let len = u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize;
    let stream = u32::from_be_bytes([head[5], head[6], head[7], head[8]]) & 0x7fff_ffff;
    let mut payload = vec![0; len];
    c.read_exact(&mut payload)?;
    Ok((head[3], head[4], stream, payload))
}

/// An upstream that takes connections and never answers. Counts them, and
/// sends on `closed` when the proxy closes one.
fn silent_backend() -> (u16, Arc<AtomicUsize>, mpsc::Receiver<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = Arc::new(AtomicUsize::new(0));
    let (closed_tx, closed_rx) = mpsc::channel();
    let count = accepted.clone();
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut c) = conn else { return };
            count.fetch_add(1, Ordering::SeqCst);
            let closed_tx = closed_tx.clone();
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                while matches!(c.read(&mut buf), Ok(n) if n > 0) {}
                let _ = closed_tx.send(());
            });
        }
    });
    (port, accepted, closed_rx)
}

#[test]
fn reset_streams_do_not_run_past_max_concurrent_streams() {
    let (up, accepted, _closed) = silent_backend();
    // The exchanges outlive their streams here, as they may behind any
    // reset stream until the upstream answers.
    let (_s, port) = start("limit", |port| {
        format!(
            "server {{ listen 127.0.0.1:{port}; http2 on; http2_max_concurrent_streams 4;\n\
               location / {{ proxy_ignore_client_abort on;\n\
                 proxy_pass http://127.0.0.1:{up}; }} }}"
        )
    });
    let mut c = connect(port);
    let mut drain = c.try_clone().unwrap();
    std::thread::spawn(move || while read_frame(&mut drain).is_ok() {});
    // Each stream is reset right after ruxen has had time to take it up.
    for i in 0..12u32 {
        c.write_all(&get(2 * i + 1, "/")).unwrap();
        std::thread::sleep(Duration::from_millis(30));
        c.write_all(&cancel(2 * i + 1)).unwrap();
    }
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        4,
        "upstream requests from one connection of reset streams"
    );
}

#[test]
fn a_reset_stream_ends_its_upstream_exchange() {
    let (up, accepted, closed) = silent_backend();
    // One stream at a time: the next is served only once the reset one
    // has ended.
    let (s, port) = start("cancel", |port| {
        format!(
            "server {{ listen 127.0.0.1:{port}; http2 on; http2_max_concurrent_streams 1;\n\
               location / {{ proxy_pass http://127.0.0.1:{up}; }}\n\
               location = /ok {{ return 200 ok; }} }}"
        )
    });
    let mut c = connect(port);
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    c.write_all(&get(1, "/slow")).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while accepted.load(Ordering::SeqCst) == 0 {
        assert!(
            Instant::now() < deadline,
            "the request never reached the upstream"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    c.write_all(&cancel(1)).unwrap();
    closed
        .recv_timeout(Duration::from_secs(3))
        .expect("the upstream exchange outlived its reset stream");

    c.write_all(&get(3, "/ok")).unwrap();
    loop {
        let (kind, _, stream, payload) = read_frame(&mut c).expect("no response on stream 3");
        if kind == 0x1 && stream == 3 {
            // :status 200 (static table 8).
            assert_eq!(payload.first(), Some(&0x88), "{payload:?}");
            break;
        }
    }

    let deadline = Instant::now() + Duration::from_secs(5);
    let log = loop {
        let log = std::fs::read_to_string(s.dir.join("access.log")).unwrap_or_default();
        if log.lines().count() >= 2 || Instant::now() > deadline {
            break log;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    assert_eq!(
        log.lines().collect::<Vec<_>>(),
        ["/slow 499", "/ok 200"],
        "{log}"
    );
}
