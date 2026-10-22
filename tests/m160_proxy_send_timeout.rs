//! M160 — `proxy_send_timeout` is the time between two writes to the
//! upstream, as nginx sets its write timer again whenever a send makes
//! progress (ngx_http_upstream_send_request, #490), not a limit on the
//! whole request. An upstream that reads a large body slowly but steadily
//! gets all of it; one that stops reading gets a 504 after the timeout.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// A body in memory larger than the socket buffers between ruxen and the
/// upstream (4 MiB at most on Linux), so the upstream's pace shows.
const BODY: usize = 12 << 20;

/// An upstream that reads `per_step` bytes every 50 ms (0: never), then
/// answers with how many body bytes it got.
fn slow_upstream(per_step: usize) -> u16 {
    let setup = common::ports::setup_lock();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    drop(setup);
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut c) = conn else { return };
            std::thread::spawn(move || {
                let mut got = 0usize;
                let mut buf = vec![0u8; per_step.max(1)];
                let mut head = Vec::new();
                loop {
                    if per_step == 0 {
                        std::thread::sleep(Duration::from_secs(10));
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(50));
                    let Ok(n) = c.read(&mut buf) else { return };
                    if n == 0 {
                        return;
                    }
                    if head.len() < 4096 && got == 0 {
                        head.extend_from_slice(&buf[..n]);
                        if let Some(end) = head.windows(4).position(|w| w == b"\r\n\r\n") {
                            got = head.len() - end - 4;
                        }
                    } else {
                        got += n;
                    }
                    if got >= BODY {
                        let body = format!("got {got}");
                        let _ = write!(
                            c,
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        return;
                    }
                }
            });
        }
    });
    port
}

fn post(port: u16, path: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    write!(
        s,
        "POST {path} HTTP/1.1\r\nHost: x\r\nContent-Length: {BODY}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    s.write_all(&vec![b'x'; BODY]).unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

#[test]
fn m160_send_timeout_runs_between_writes() {
    // About 5 MiB/s: the 12 MiB body takes over two seconds, each write
    // waits 50 ms at most.
    let steady = slow_upstream(256 << 10);
    let stuck = slow_upstream(0);
    let setup = common::ports::setup_lock();
    let [front] = common::ports::free_ports();
    let dir = std::env::temp_dir().join(format!("ruxen-m160-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "pid {d}/ruxen.pid;\nerror_log {d}/error.log info;\nevents {{}}\nhttp {{\n\
             client_max_body_size 64m; client_body_buffer_size 32m;\n\
             proxy_send_timeout 1s; proxy_read_timeout 10s;\n\
             server {{ listen 127.0.0.1:{front};\n\
               location /steady {{ proxy_pass http://127.0.0.1:{steady}; }}\n\
               location /stuck {{ proxy_pass http://127.0.0.1:{stuck}; }}\n\
             }} }}\n",
            d = dir.display()
        ),
    )
    .unwrap();
    let mut child = common::KillOnDrop(
        Command::new(env!("CARGO_BIN_EXE_ruxen"))
            .arg("-c")
            .arg(dir.join("nginx.conf"))
            .env("RUXEN_WORKERS", "1")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    common::ports::wait_for_pid_file(&mut child, &dir.join("ruxen.pid"), Duration::from_secs(3));
    drop(setup);

    let started = Instant::now();
    let steady = post(front, "/steady");
    let took = started.elapsed();
    let stuck = post(front, "/stuck");
    let log = std::fs::read_to_string(dir.join("error.log")).unwrap_or_default();
    drop(child);
    let _ = std::fs::remove_dir_all(&dir);

    assert!(steady.starts_with("HTTP/1.1 200 OK"), "{steady}\n{log}");
    assert!(steady.ends_with(&format!("got {BODY}")), "{steady}");
    // The upstream's pace made the write longer than proxy_send_timeout,
    // or the test shows nothing.
    assert!(took > Duration::from_millis(1500), "{took:?}");
    assert!(stuck.starts_with("HTTP/1.1 504"), "{stuck}");
    assert!(
        log.contains(
            "upstream timed out (110: Connection timed out) while sending request to upstream"
        ),
        "{log}"
    );
}
