//! M122 — a client that closes while a `limit_rate` response waits for its
//! next write is noticed at once (#383), as nginx's `ngx_http_test_reading`
//! does: the connection leaves the `stub_status` counters right away
//! instead of at the next paced write.

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// The server stops when the test ends, also when an assertion panics.
struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn get(port: u16, path: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    write!(s, "GET {path} HTTP/1.0\r\nHost: localhost\r\n\r\n").unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
    out
}

#[test]
fn a_paced_response_notices_the_client_closing() {
    let dir = std::env::temp_dir().join(format!("ruxen-m122-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // Held until ruxen listens: released earlier, another test could take
    // the same free port.
    let setup = common::ports::setup_lock();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let d = dir.display();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "worker_processes 1;\npid {d}/ruxen.pid;\nevents {{}}\nhttp {{\naccess_log off;\n\
             server {{ listen 127.0.0.1:{port}; root {d};\n\
             add_header X-Active $connections_active;\n\
             location /rate {{ limit_rate 15; }}\n\
             location /stub {{ stub_status; }} }} }}\n"
        ),
    )
    .unwrap();
    let mut child = KillOnDrop(
        Command::new(env!("CARGO_BIN_EXE_ruxen"))
            .arg("-c")
            .arg(dir.join("nginx.conf"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    while !dir.join("ruxen.pid").exists() {
        assert!(child.0.try_wait().unwrap().is_none(), "ruxen exited");
        assert!(Instant::now() < deadline, "ruxen did not start");
        std::thread::sleep(Duration::from_millis(20));
    }
    drop(setup);

    // A 404 page at 15 bytes a second: about ten seconds of writing.
    let mut slow = TcpStream::connect(("127.0.0.1", port)).unwrap();
    slow.write_all(b"GET /rate HTTP/1.0\r\nHost: localhost\r\n\r\n")
        .unwrap();
    std::thread::sleep(Duration::from_millis(300));
    assert!(get(port, "/stub").contains("X-Active: 2\r\n"));
    drop(slow);
    // At once: this request is the only connection left.
    let status = get(port, "/stub");
    assert!(status.contains("X-Active: 1\r\n"), "{status}");
    let _ = std::fs::remove_dir_all(&dir);
}
