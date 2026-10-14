//! M128 — nginx's range filter on proxied responses (#370): with
//! `proxy_force_ranges` (one range), for a cacheable response whose
//! upstream sent `Accept-Ranges` (one range), and on a cache hit
//! (multipart too). Otherwise the upstream's response goes out as it is.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

/// The server stops when the test ends, also when an assertion panics.
struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn request(port: u16, method: &str, path: &str, headers: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(
        s,
        "{method} {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n{headers}\r\n"
    )
    .unwrap();
    let mut out = Vec::new();
    s.read_to_end(&mut out).unwrap();
    String::from_utf8_lossy(&out).into_owned()
}

fn get(port: u16, path: &str, range: &str) -> String {
    request(port, "GET", path, &format!("Range: {range}\r\n"))
}

#[test]
fn proxied_responses_take_ranges_as_nginx() {
    let dir = std::env::temp_dir().join(format!("ruxen-m128-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // Held until ruxen listens.
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
            "worker_processes 1;\npid {d}/ruxen.pid;\nevents {{}}\nhttp {{\n\
             access_log off;\n\
             proxy_cache_path {d}/cache levels=1:2 keys_zone=NAME:1m;\n\
             server {{ listen 127.0.0.1:{port};\n\
             location /cached/ {{ proxy_pass http://127.0.0.1:{port}/stub/;\n\
               proxy_cache NAME; proxy_cache_valid 200 1m; }}\n\
             location /force/ {{ proxy_pass http://127.0.0.1:{port}/stub/;\n\
               proxy_force_ranges on; }}\n\
             location /gzip/ {{ proxy_pass http://127.0.0.1:{port}/stub/;\n\
               proxy_force_ranges on; gzip on; gzip_min_length 1;\n\
               gzip_types text/plain; }}\n\
             location /plain/ {{ proxy_pass http://127.0.0.1:{port}/stub/; }}\n\
             location /stub/ {{ add_header Content-Range stub; add_header Accept-Ranges bytes;\n\
               add_header ETag '\"e1\"'; default_type text/plain;\n\
               return 200 \"SEE-THIS\"; }} }} }}\n"
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
    common::ports::wait_for_pid_file(&mut child.0, &dir.join("ruxen.pid"), Duration::from_secs(5));
    drop(setup);

    // proxy_force_ranges: one range, the filter's own Content-Range.
    let r = get(port, "/force/a", "bytes=0-4");
    assert!(r.starts_with("HTTP/1.1 206 Partial Content\r\n"), "{r}");
    assert!(r.contains("\r\nContent-Range: bytes 0-4/8\r\n"), "{r}");
    assert!(r.contains("\r\nETag: \"e1\"\r\n"), "{r}");
    assert!(!r.contains("stub") && !r.contains("Accept-Ranges"), "{r}");
    assert!(r.ends_with("\r\n\r\nSEE-T"), "{r}");
    // Two ranges are more than it allows: the whole response.
    let r = get(port, "/force/a", "bytes=0-2,4-");
    assert!(r.starts_with("HTTP/1.1 200 "), "{r}");
    assert_eq!(r.matches("Accept-Ranges: bytes").count(), 1, "{r}");
    assert!(r.ends_with("\r\n\r\nSEE-THIS"), "{r}");
    // None satisfiable: nginx's 416 page.
    let r = get(port, "/force/a", "bytes=1000-");
    assert!(
        r.starts_with("HTTP/1.1 416 Requested Range Not Satisfiable\r\n"),
        "{r}"
    );
    assert!(r.contains("\r\nContent-Range: bytes */8\r\n"), "{r}");
    assert!(r.contains("\r\nContent-Type: text/html\r\n"), "{r}");
    assert!(!r.contains("ETag"), "{r}");
    assert!(
        r.contains("<h1>416 Requested Range Not Satisfiable</h1>"),
        "{r}"
    );
    // HEAD: the 206's head alone.
    let r = request(port, "HEAD", "/force/a", "Range: bytes=4-\r\n");
    assert!(r.starts_with("HTTP/1.1 206 "), "{r}");
    assert!(r.contains("\r\nContent-Length: 4\r\n"), "{r}");
    assert!(r.ends_with("\r\n\r\n"), "{r}");
    // If-Range that doesn't match: the whole response.
    let r = request(
        port,
        "GET",
        "/force/a",
        "Range: bytes=4-\r\nIf-Range: \"other\"\r\n",
    );
    assert!(
        r.starts_with("HTTP/1.1 200 ") && r.ends_with("SEE-THIS"),
        "{r}"
    );
    // Without Range, relayed or not: it says it takes ranges.
    let r = request(port, "GET", "/force/a", "");
    assert!(r.starts_with("HTTP/1.1 200 "), "{r}");
    assert_eq!(r.matches("Accept-Ranges: bytes").count(), 1, "{r}");

    // gzip compresses it: no range then (nginx's filter needs a length).
    let r = request(
        port,
        "GET",
        "/gzip/a",
        "Range: bytes=0-4\r\nAccept-Encoding: gzip\r\n",
    );
    assert!(r.starts_with("HTTP/1.1 200 "), "{r}");
    assert!(r.contains("\r\nContent-Encoding: gzip\r\n"), "{r}");
    // Not compressed: cut.
    let r = get(port, "/gzip/a", "bytes=0-4");
    assert!(
        r.starts_with("HTTP/1.1 206 ") && r.ends_with("SEE-T"),
        "{r}"
    );

    // Cacheable, and the upstream sent Accept-Ranges: one range.
    let r = get(port, "/cached/a", "bytes=0-4");
    assert!(
        r.starts_with("HTTP/1.1 206 ") && r.ends_with("SEE-T"),
        "{r}"
    );
    // A cache hit takes several.
    let r = get(port, "/cached/a", "bytes=0-2,4-");
    assert!(r.starts_with("HTTP/1.1 206 "), "{r}");
    assert!(
        r.contains("\r\nContent-Type: multipart/byteranges; boundary="),
        "{r}"
    );
    assert!(
        r.contains("\r\nContent-Range: bytes 0-2/8\r\n\r\nSEE\r\n"),
        "{r}"
    );
    assert!(
        r.contains("\r\nContent-Range: bytes 4-7/8\r\n\r\nTHIS\r\n"),
        "{r}"
    );

    // Otherwise the upstream's response, its Content-Range included.
    let r = get(port, "/plain/a", "bytes=0-4");
    assert!(
        r.starts_with("HTTP/1.1 200 ") && r.ends_with("SEE-THIS"),
        "{r}"
    );
    assert!(r.contains("\r\nContent-Range: stub\r\n"), "{r}");
    assert!(r.contains("\r\nAccept-Ranges: bytes\r\n"), "{r}");

    drop(child);
    let _ = std::fs::remove_dir_all(&dir);
}
