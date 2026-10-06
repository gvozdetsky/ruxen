//! M81 — upstream connections count against `worker_connections`, as in
//! nginx, where they come from the same connection table as accepted ones
//! (ngx_event_connect_peer → ngx_get_connection). With no slot left a
//! request gets a 500 and the worker logs "worker_connections are not
//! enough" (ngx_http_upstream_connect); an idle keep-alive upstream
//! connection is closed first to make room. Before, only client
//! connections were counted.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread::sleep;
use std::time::{Duration, Instant};

/// A keep-alive upstream: `/slow` answers after a second. Counts the
/// connections that ruxen closes.
fn spawn_upstream(closed: Arc<AtomicUsize>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for conn in listener.incoming().flatten() {
            let closed = closed.clone();
            std::thread::spawn(move || {
                let mut conn = conn;
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                loop {
                    match conn.read(&mut byte) {
                        Ok(1) => head.push(byte[0]),
                        _ => {
                            closed.fetch_add(1, Ordering::SeqCst);
                            return;
                        }
                    }
                    if head.ends_with(b"\r\n\r\n") {
                        if head.windows(5).any(|w| w == b"/slow") {
                            sleep(Duration::from_secs(1));
                        }
                        let _ = conn.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
                        head.clear();
                    }
                }
            });
        }
    });
    port
}

fn get(port: u16, path: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

#[test]
fn upstream_connections_take_worker_connection_slots() {
    let setup = common::ports::setup_lock();
    let closed = Arc::new(AtomicUsize::new(0));
    let up = spawn_upstream(closed.clone());
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let dir = std::env::temp_dir().join(format!("ruxen-m81-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // Four slots: the listener and three connections.
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "pid {d}/ruxen.pid;\nerror_log {d}/error.log;\nevents {{ worker_connections 4; }}\n\
             http {{ upstream u {{ server 127.0.0.1:{up}; keepalive 4; }}\n\
               server {{ listen 127.0.0.1:{port};\n\
                 location / {{ proxy_pass http://u; proxy_http_version 1.1;\n\
                   proxy_set_header Connection \"\"; }} }} }}\n",
            d = dir.display()
        ),
    )
    .unwrap();
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .arg("-c")
        .arg(dir.join("nginx.conf"))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    while !dir.join("ruxen.pid").exists() {
        assert!(Instant::now() < deadline, "ruxen did not start");
        sleep(Duration::from_millis(10));
    }
    drop(setup);

    // The first request holds a client and an upstream slot; the second
    // gets its client slot but none for its upstream connection.
    let first = std::thread::spawn(move || get(port, "/slow"));
    sleep(Duration::from_millis(300));
    let started = Instant::now();
    let second = get(port, "/slow");
    let second_took = started.elapsed();
    let first = first.join().unwrap();
    let log = std::fs::read_to_string(dir.join("error.log")).unwrap_or_default();

    // The first upstream connection is now idle in the pool, holding a
    // slot. Two idle clients fill the rest; a third client gets in by
    // closing the pooled connection.
    let idle: Vec<TcpStream> = (0..2)
        .map(|_| TcpStream::connect(("127.0.0.1", port)).unwrap())
        .collect();
    sleep(Duration::from_millis(100));
    let closed_before = closed.load(Ordering::SeqCst);
    let third = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    while closed.load(Ordering::SeqCst) == closed_before && Instant::now() < deadline {
        sleep(Duration::from_millis(10));
    }
    let closed_after = closed.load(Ordering::SeqCst);
    drop((idle, third));
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&dir);

    assert!(first.starts_with("HTTP/1.1 200"), "{first}");
    assert!(second.starts_with("HTTP/1.1 500"), "{second}");
    assert!(second_took < Duration::from_millis(700), "{second_took:?}");
    assert!(
        log.contains("[alert]") && log.contains("4 worker_connections are not enough"),
        "{log}"
    );
    assert_eq!(
        closed_after,
        closed_before + 1,
        "the pooled connection stayed open"
    );
}
