//! M167 — `proxy_no_cache` reading the response (`$upstream_http_*`, or a
//! `map` of one) is tested once the upstream's header is in, as nginx
//! does (#826): a response it holds for isn't stored.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

/// Answers each request with its number; `/nc*` with `X-No-Cache: 1`.
fn spawn_backend(listener: TcpListener) -> Arc<AtomicUsize> {
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut conn) = conn else { return };
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                match conn.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                }
            }
            let n = counter.fetch_add(1, Ordering::SeqCst) + 1;
            let path = String::from_utf8_lossy(&buf)
                .split(' ')
                .nth(1)
                .unwrap_or("")
                .to_string();
            let extra = if path.starts_with("/nc") {
                "X-No-Cache: 1\r\n"
            } else {
                ""
            };
            let body = format!("{n}\n");
            let _ = conn.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n{extra}Connection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            );
        }
    });
    hits
}

fn get(port: u16, path: &str) -> (String, String) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    write!(s, "GET {path} HTTP/1.0\r\nHost: localhost\r\n\r\n").unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
    let (head, body) = out.split_once("\r\n\r\n").unwrap();
    let status = head
        .lines()
        .find_map(|l| l.strip_prefix("X-Cache: "))
        .unwrap_or("")
        .to_string();
    (status, body.to_string())
}

#[test]
fn proxy_no_cache_reads_the_response() {
    let dir = std::env::temp_dir().join(format!("ruxen-m167-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let backend = TcpListener::bind("127.0.0.1:0").unwrap();
    let backend_port = backend.local_addr().unwrap().port();
    spawn_backend(backend);
    let setup = common::ports::setup_lock();
    let [port] = common::ports::free_ports();
    let d = dir.display();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "worker_processes 1;\npid {d}/ruxen.pid;\nerror_log {d}/error.log;\nevents {{}}\n\
             http {{\naccess_log off;\nproxy_cache_path {d}/cache keys_zone=z:1m;\n\
             map $upstream_http_x_no_cache $mapped {{ default 0; 1 1; }}\n\
             server {{ listen 127.0.0.1:{port};\n\
             proxy_cache z; proxy_cache_valid 200 1m; add_header X-Cache $upstream_cache_status;\n\
             location /nc {{ proxy_pass http://127.0.0.1:{backend_port};\n\
             proxy_no_cache $upstream_http_x_no_cache; }}\n\
             location /ncmap {{ proxy_pass http://127.0.0.1:{backend_port}; proxy_no_cache $mapped; }}\n\
             location /plain {{ proxy_pass http://127.0.0.1:{backend_port};\n\
             proxy_no_cache $upstream_http_x_no_cache; }}\n\
             location /arg {{ proxy_pass http://127.0.0.1:{backend_port}; proxy_no_cache $arg_nc; }}\n\
             }} }}\n"
        ),
    )
    .unwrap();
    let mut child = common::KillOnDrop(
        Command::new(env!("CARGO_BIN_EXE_ruxen"))
            .arg("-c")
            .arg(dir.join("nginx.conf"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    common::ports::wait_for_pid_file(&mut child, &dir.join("ruxen.pid"), Duration::from_secs(5));
    drop(setup);

    // The upstream says not to keep it: a miss each time.
    for path in ["/nc", "/ncmap"] {
        let (first, a) = get(port, path);
        let (second, b) = get(port, path);
        assert_eq!(
            (first.as_str(), second.as_str()),
            ("MISS", "MISS"),
            "{path}"
        );
        assert_ne!(a, b, "{path}");
    }
    // Without the header, the same predicate lets it be stored.
    assert_eq!(get(port, "/plain").0, "MISS");
    assert_eq!(get(port, "/plain").0, "HIT");
    // A request variable is still read before.
    assert_eq!(get(port, "/arg?nc=1").0, "MISS");
    assert_eq!(get(port, "/arg?nc=1").0, "MISS");
}
