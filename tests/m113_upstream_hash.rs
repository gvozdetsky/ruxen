//! M113 — `hash` and `ip_hash` (#97): one key, or one client /24, always
//! reaches the same server; an empty key is round-robin. A retry that
//! finds no live server answers 502 and shows the group in
//! `$upstream_addr`, as nginx.

mod common;

use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

struct Server(Child, std::path::PathBuf);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
        let _ = std::fs::remove_dir_all(&self.1);
    }
}

fn start() -> (Server, u16, [u16; 3]) {
    let dir = std::env::temp_dir().join(format!("ruxen-m113-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // Held until ruxen listens on all of them: released earlier, another
    // test could take one of these free ports, and ruxen would fail to
    // bind it.
    let setup = common::ports::setup_lock();
    let [port, b0, b1, b2, refused] = common::ports::free_ports();
    let b = [b0, b1, b2];
    let servers = || {
        b.iter()
            .map(|p| format!("server 127.0.0.1:{p};"))
            .collect::<String>()
    };
    let d = dir.display();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "worker_processes 1;\nerror_log {d}/error.log info;\nevents {{}}\nhttp {{ access_log off;\n\
             upstream h {{ hash $arg_k; {s} }}\n\
             upstream c {{ hash $arg_k consistent; {s} }}\n\
             upstream i {{ ip_hash; {s} }}\n\
             upstream n {{ server 127.0.0.1:{b0}; server 127.0.0.1:{refused}; }}\n\
             server {{ listen 127.0.0.1:{port};\n\
             set_real_ip_from 127.0.0.1; real_ip_header X-Real-IP;\n\
             location /h {{ proxy_pass http://h; }}\n\
             location /c {{ proxy_pass http://c; }}\n\
             location /i {{ proxy_pass http://i; }}\n\
             location /n {{ proxy_pass http://n; proxy_next_upstream error http_404;\n\
               add_header X-A $upstream_addr always; }}\n\
             }}\n\
             server {{ listen 127.0.0.1:{b0}; listen 127.0.0.1:{b1}; listen 127.0.0.1:{b2};\n\
               location /n {{ return 404; }}\n\
               location / {{ return 200 $server_port; }} }}\n\
             }}\n",
            s = servers(),
            b0 = b[0],
            b1 = b[1],
            b2 = b[2],
        ),
    )
    .unwrap();
    // Owned by `Server` before the wait: if it panics, ruxen still stops.
    let mut server = Server(
        Command::new(env!("CARGO_BIN_EXE_ruxen"))
            .arg("-c")
            .arg(dir.join("nginx.conf"))
            .arg("-g")
            .arg(format!("pid {}/ruxen.pid;", dir.display()))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
        dir,
    );
    let pid_file = server.1.join("ruxen.pid");
    common::ports::wait_for_pid_file(&mut server.0, &pid_file, Duration::from_secs(5));
    drop(setup);
    (server, port, b)
}

fn get(port: u16, path: &str, real_ip: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(s, "GET {path} HTTP/1.0\r\nX-Real-IP: {real_ip}\r\n\r\n").unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

fn body(response: &str) -> String {
    response
        .split_once("\r\n\r\n")
        .map_or("", |(_, b)| b)
        .to_string()
}

#[test]
fn m113_upstream_hash() {
    let (_server, port, b) = start();
    for kind in ["h", "c"] {
        // One key, one server; different keys spread.
        let mut seen = HashSet::new();
        for k in 0..30 {
            let first = body(&get(port, &format!("/{kind}?k={k}"), "1.1.1.1"));
            for _ in 0..3 {
                assert_eq!(
                    body(&get(port, &format!("/{kind}?k={k}"), "1.1.1.1")),
                    first
                );
            }
            seen.insert(first);
        }
        assert!(seen.len() > 1, "{kind}: {seen:?}");
        // An empty key: round-robin over all three.
        let rr: HashSet<String> = (0..3)
            .map(|_| body(&get(port, &format!("/{kind}"), "1.1.1.1")))
            .collect();
        assert_eq!(rr.len(), 3, "{kind}: {rr:?}");
    }
    // ip_hash: the /24 decides.
    let mut seen = HashSet::new();
    for net in 0..30 {
        let first = body(&get(port, "/i", &format!("10.0.{net}.1")));
        assert_eq!(body(&get(port, "/i", &format!("10.0.{net}.200"))), first);
        seen.insert(first);
    }
    assert!(seen.len() > 1, "{seen:?}");

    // The first request marks the refused server failed; the second's
    // retry finds no live server.
    let first = get(port, "/n", "1.1.1.1");
    assert!(first.starts_with("HTTP/1.1 502"), "{first}");
    let second = get(port, "/n", "1.1.1.1");
    assert!(second.starts_with("HTTP/1.1 502"), "{second}");
    assert!(
        second.contains(&format!("X-A: 127.0.0.1:{}, n\r\n", b[0])),
        "{second}"
    );
}
