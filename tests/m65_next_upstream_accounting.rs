//! M65 — which `proxy_next_upstream` statuses count against a peer's
//! `max_fails`, as nginx's ngx_http_upstream_next: http_403 / http_404
//! only move on to the next peer (NGX_PEER_NEXT), and the last try's
//! response is the answer, not a failure. ruxen used to count both, so
//! one 404 took a healthy backend out of rotation for `fail_timeout`.
//! Also: the last try's response goes through proxy_intercept_errors, and
//! failover can reach every peer of an upstream of more than 64.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

struct Server {
    child: Child,
    dir: PathBuf,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn free_ports<const N: usize>() -> [u16; N] {
    let probes: Vec<TcpListener> = (0..N)
        .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    std::array::from_fn(|i| probes[i].local_addr().unwrap().port())
}

/// `front` proxies to an upstream of `a` and `b`, and has `/err` for
/// error pages. The backends answer `/bad` with `a_bad` / `b_bad` and
/// everything else with their name.
fn start(tag: &str, location_extra: &str, a_bad: u16, b_bad: u16) -> (Server, u16, [u16; 2]) {
    let _setup = common::ports::setup_lock();
    let [front, a, b] = free_ports::<3>();
    let dir = std::env::temp_dir().join(format!("ruxen-m65-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "pid {d}/ruxen.pid;\nevents {{}}\nhttp {{\n\
             upstream u {{ server 127.0.0.1:{a}; server 127.0.0.1:{b}; }}\n\
             server {{ listen 127.0.0.1:{front};\n\
               location / {{ proxy_pass http://u; {location_extra} }}\n\
               location /err {{ return 200 \"$upstream_addr\"; }} }}\n\
             server {{ listen 127.0.0.1:{a};\n\
               location / {{ return 200 A; }} location /bad {{ return {a_bad}; }} }}\n\
             server {{ listen 127.0.0.1:{b};\n\
               location / {{ return 200 B; }} location /bad {{ return {b_bad}; }} }}\n\
             }}\n",
            d = dir.display()
        ),
    )
    .unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .arg("-c")
        .arg(dir.join("nginx.conf"))
        .env("RUXEN_WORKERS", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    while !dir.join("ruxen.pid").exists() {
        assert!(Instant::now() < deadline, "ruxen did not start");
        sleep(Duration::from_millis(10));
    }
    (Server { child, dir }, front, [a, b])
}

fn get(port: u16, path: &str) -> (u16, String) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    let status = out[9..12].parse().unwrap();
    (
        status,
        out.split("\r\n\r\n").last().unwrap_or("").to_string(),
    )
}

/// Both peers still answer after the bad request: the four plain requests
/// are shared between them, not all sent to one.
fn assert_both_in_rotation(port: u16) {
    let bodies: Vec<String> = (0..4).map(|_| get(port, "/ok").1).collect();
    let a = bodies.iter().filter(|b| *b == "A").count();
    assert_eq!(a, 2, "{bodies:?}");
}

#[test]
fn a_404_moves_on_without_failing_the_peer() {
    let (_server, port, _) = start("404", "proxy_next_upstream http_404;", 404, 404);
    assert_eq!(get(port, "/bad").0, 404);
    assert_both_in_rotation(port);
}

#[test]
fn a_403_moves_on_without_failing_the_peer() {
    let (_server, port, _) = start("403", "proxy_next_upstream http_403;", 403, 403);
    assert_eq!(get(port, "/bad").0, 403);
    assert_both_in_rotation(port);
}

#[test]
fn the_last_try_is_not_a_failure() {
    let (_server, port, _) = start(
        "last",
        "proxy_next_upstream http_500; proxy_next_upstream_tries 1;",
        500,
        500,
    );
    assert_eq!(get(port, "/bad").0, 500);
    assert_both_in_rotation(port);
}

#[test]
fn a_500_with_a_try_left_still_fails_the_peer() {
    // A answers /bad with 500, B with 200: whichever is tried first, A
    // ends up failed (max_fails=1), so the plain requests all go to B.
    let (_server, port, _) = start("500", "proxy_next_upstream http_500;", 500, 200);
    for _ in 0..2 {
        assert_eq!(get(port, "/bad").0, 200);
    }
    let bodies: Vec<String> = (0..4).map(|_| get(port, "/ok").1).collect();
    assert!(bodies.iter().all(|b| b == "B"), "{bodies:?}");
}

/// When no try is left, a status in the mask is the answer like any other
/// and goes through proxy_intercept_errors (nginx's test_next declines,
/// then ngx_http_upstream_intercept_errors). It used to be passed through
/// as-is, skipping the error_page.
#[test]
fn the_last_try_goes_through_intercept_errors() {
    let (_server, port, [a, b]) = start(
        "intercept",
        "proxy_next_upstream http_404; proxy_intercept_errors on; error_page 404 /err;",
        404,
        404,
    );
    let (status, body) = get(port, "/bad");
    assert_eq!(status, 404);
    let mut tried: Vec<&str> = body.split(", ").collect();
    tried.sort();
    let mut want = [format!("127.0.0.1:{a}"), format!("127.0.0.1:{b}")];
    want.sort();
    assert_eq!(tried, want, "{body}");
}

/// An upstream of more than 64 peers: every peer has its own "tried" bit.
/// Peers from index 63 up used to share one, so once one of them failed
/// the others counted as tried, and failover ended in a 502 before it
/// reached the live peer at the end.
#[test]
fn failover_reaches_every_peer_of_a_large_upstream() {
    let setup = common::ports::setup_lock();
    let dead = common::ports::DeadPort::new();
    let [front, live] = free_ports::<2>();
    let dir = std::env::temp_dir().join(format!("ruxen-m65-large-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let servers: String = (0..69)
        .map(|_| format!("server 127.0.0.1:{} max_fails=0; ", dead.port()))
        .collect();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "pid {d}/ruxen.pid;\nevents {{}}\nhttp {{\n\
             upstream u {{ {servers}server 127.0.0.1:{live} max_fails=0; }}\n\
             server {{ listen 127.0.0.1:{front}; location / {{ proxy_pass http://u; }} }}\n\
             server {{ listen 127.0.0.1:{live}; location / {{ return 200 live; }} }}\n\
             }}\n",
            d = dir.display()
        ),
    )
    .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .arg("-c")
        .arg(dir.join("nginx.conf"))
        .env("RUXEN_WORKERS", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    while !dir.join("ruxen.pid").exists() {
        assert!(Instant::now() < deadline, "ruxen did not start");
        sleep(Duration::from_millis(10));
    }
    drop(setup);
    let results: Vec<(u16, String)> = (0..10).map(|_| get(front, "/")).collect();
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        results
            .iter()
            .all(|(status, body)| *status == 200 && body == "live"),
        "{results:?}"
    );
}
