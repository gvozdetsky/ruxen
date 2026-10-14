//! M117 — stale responses from `proxy_cache` (#233, step 3):
//! `proxy_cache_use_stale` answers an upstream failure from the cache, and
//! `proxy_cache_background_update` sends the stale response while it is
//! fetched again.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Server(Child, std::path::PathBuf);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
        let _ = std::fs::remove_dir_all(&self.1);
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn get(port: u16, path: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(s, "GET {path} HTTP/1.0\r\nHost: localhost\r\n\r\n").unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    String::from_utf8_lossy(&out).into_owned()
}

fn cache_status(resp: &str) -> &str {
    resp.split("\r\nX-Cache: ")
        .nth(1)
        .and_then(|rest| rest.split("\r\n").next())
        .unwrap_or("")
}

fn body(resp: &str) -> &str {
    resp.split("\r\n\r\n").nth(1).unwrap_or("")
}

#[test]
fn m117_use_stale_and_background_update() {
    let dir = std::env::temp_dir().join(format!("ruxen-m117-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let html = dir.join("html");
    std::fs::create_dir_all(&html).unwrap();
    std::fs::write(html.join("e.txt"), "OLD-E").unwrap();
    std::fs::write(html.join("b.txt"), "OLD-B").unwrap();
    let setup = common::ports::setup_lock();
    let port = free_port();
    let backend = free_port();
    let d = dir.display();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "events {{}}\nhttp {{ access_log off;\n\
             proxy_cache_path {d}/cache keys_zone=one:1m;\n\
             server {{ listen 127.0.0.1:{port};\n\
               add_header X-Cache $upstream_cache_status;\n\
               proxy_cache one; proxy_cache_valid 200 1s;\n\
               location /e/ {{ proxy_pass http://127.0.0.1:{backend}/;\n\
                 proxy_cache_use_stale http_500; }}\n\
               location /b/ {{ proxy_pass http://127.0.0.1:{backend}/;\n\
                 proxy_cache_use_stale updating; proxy_cache_background_update on; }}\n\
             }}\n\
             server {{ listen 127.0.0.1:{backend}; root {d}/html;\n\
               location / {{ try_files $uri =500; }} }} }}\n"
        ),
    )
    .unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .arg("-c")
        .arg(dir.join("nginx.conf"))
        .arg("-g")
        .arg(format!("pid {d}/ruxen.pid;"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut server = Server(child, dir.clone());
    common::ports::wait_for_pid_file(
        &mut server.0,
        &dir.join("ruxen.pid"),
        Duration::from_secs(5),
    );
    drop(setup);

    let r = get(port, "/e/e.txt");
    assert_eq!((cache_status(&r), body(&r)), ("MISS", "OLD-E"), "{r}");
    let r = get(port, "/b/b.txt");
    assert_eq!((cache_status(&r), body(&r)), ("MISS", "OLD-B"), "{r}");
    std::fs::remove_file(html.join("e.txt")).unwrap();
    std::fs::write(html.join("b.txt"), "NEW-B").unwrap();
    std::thread::sleep(Duration::from_millis(2100));

    // The upstream answers 500: the stale response stands in for it.
    let r = get(port, "/e/e.txt");
    assert!(r.starts_with("HTTP/1.1 200"), "{r}");
    assert_eq!((cache_status(&r), body(&r)), ("STALE", "OLD-E"), "{r}");

    // The stale response goes out at once and is updated behind it.
    let r = get(port, "/b/b.txt");
    assert_eq!((cache_status(&r), body(&r)), ("STALE", "OLD-B"), "{r}");
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let r = get(port, "/b/b.txt");
        if body(&r) == "NEW-B" {
            assert_eq!(cache_status(&r), "HIT", "{r}");
            break;
        }
        assert!(Instant::now() < deadline, "never updated: {r}");
        std::thread::sleep(Duration::from_millis(50));
    }
}
