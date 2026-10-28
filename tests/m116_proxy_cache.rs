//! M116 — `proxy_cache` (#233, step 1): responses are stored, served
//! again while fresh, refreshed when stale or bypassed, and the index
//! finds the files again after a restart.

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Start ruxen and wait for its pid file, written once every worker is
/// bound. A killed server leaves its pid file behind: a restart removes
/// it first.
fn start(conf: &Path) -> Server {
    let pid_file = conf.with_file_name("ruxen.pid");
    let _ = std::fs::remove_file(&pid_file);
    // Owned by `Server` before the wait: if it panics, ruxen still stops.
    let mut server = Server(
        Command::new(env!("CARGO_BIN_EXE_ruxen"))
            .arg("-c")
            .arg(conf)
            .arg("-g")
            .arg(format!("pid {};", pid_file.display()))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    common::ports::wait_for_pid_file(&mut server.0, &pid_file, Duration::from_secs(5));
    server
}

fn request(port: u16, raw: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(raw.as_bytes()).unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    String::from_utf8_lossy(&out).into_owned()
}

fn get(port: u16, path: &str) -> String {
    request(
        port,
        &format!("GET {path} HTTP/1.0\r\nHost: localhost\r\n\r\n"),
    )
}

fn status_of(resp: &str) -> &str {
    resp.split("\r\nX-Cache: ")
        .nth(1)
        .and_then(|rest| rest.split("\r\n").next())
        .unwrap_or("")
}

fn body_of(resp: &str) -> &str {
    resp.split("\r\n\r\n").nth(1).unwrap_or("")
}

struct Setup {
    dir: PathBuf,
    port: u16,
}

impl Drop for Setup {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn setup(name: &str) -> Setup {
    let dir = std::env::temp_dir().join(format!("ruxen-m116-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("html")).unwrap();
    let [port, backend] = common::ports::free_ports();
    let d = dir.display();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "events {{}}\nhttp {{ access_log off;\n\
             proxy_cache_path {d}/cache levels=1:2 keys_zone=one:1m;\n\
             proxy_cache_path {d}/cache2 keys_zone=two:1m;\n\
             server {{ listen 127.0.0.1:{port};\n\
               add_header X-Cache $upstream_cache_status;\n\
               location / {{ proxy_pass http://127.0.0.1:{backend}; proxy_cache one;\n\
                 proxy_cache_valid 200 1m; proxy_cache_bypass $arg_bypass;\n\
                 proxy_intercept_errors on; error_page 404 = @fallback; }}\n\
               location /short/ {{ proxy_pass http://127.0.0.1:{backend}/; proxy_cache one;\n\
                 proxy_cache_valid 1s; }}\n\
               location /reval/ {{ proxy_pass http://127.0.0.1:{backend}/; proxy_cache one;\n\
                 proxy_cache_valid 1s; proxy_cache_revalidate on; }}\n\
               location /var/ {{ proxy_pass http://127.0.0.1:{backend}/; proxy_cache $arg_c;\n\
                 proxy_cache_valid 1m; }}\n\
               location /vary/ {{ proxy_pass http://127.0.0.1:{backend}; proxy_cache one;\n\
                 proxy_cache_valid 1m; }}\n\
               location @fallback {{ return 403; }}\n\
               location /nch/ {{ proxy_pass http://127.0.0.1:{backend}/; proxy_cache one;\n\
                 proxy_cache_valid 1m; proxy_cache_convert_head off;\n\
                 proxy_cache_key $request_uri; }}\n\
             }}\n\
             server {{ listen 127.0.0.1:{backend}; root {d}/html;\n\
               location /cc {{ add_header Cache-Control no-store; }}\n\
               location /vary/ {{ add_header Vary Accept-Encoding; }}\n\
             }} }}\n"
        ),
    )
    .unwrap();
    Setup { dir, port }
}

#[test]
fn m116_store_hit_bypass_and_errors() {
    let _setup_lock = common::ports::setup_lock();
    let s = setup("main");
    let html = s.dir.join("html");
    std::fs::write(html.join("t.txt"), "ONE").unwrap();
    std::fs::write(html.join("cc"), "CC1").unwrap();
    let _server = start(&s.dir.join("nginx.conf"));
    drop(_setup_lock);

    let r = get(s.port, "/t.txt");
    assert_eq!((status_of(&r), body_of(&r)), ("MISS", "ONE"), "{r}");
    std::fs::write(html.join("t.txt"), "TWO").unwrap();
    let r = get(s.port, "/t.txt");
    assert_eq!((status_of(&r), body_of(&r)), ("HIT", "ONE"), "{r}");
    assert!(r.contains("\r\nContent-Length: 3\r\n"), "{r}");

    // HEAD is served from the cache, without the body.
    let r = request(s.port, "HEAD /t.txt HTTP/1.0\r\nHost: localhost\r\n\r\n");
    assert_eq!((status_of(&r), body_of(&r)), ("HIT", ""), "{r}");
    assert!(r.contains("\r\nContent-Length: 3\r\n"), "{r}");

    // A bypassed request goes upstream and refreshes the cache.
    let r = get(s.port, "/t.txt?bypass=1");
    assert_eq!((status_of(&r), body_of(&r)), ("BYPASS", "TWO"), "{r}");
    // The key is the upstream URL, arguments included: a new key.
    let r = get(s.port, "/t.txt");
    assert_eq!(body_of(&r), "ONE", "{r}");

    // Cache-Control: no-store is never stored.
    let r = get(s.port, "/cc");
    assert_eq!((status_of(&r), body_of(&r)), ("MISS", "CC1"), "{r}");
    std::fs::write(html.join("cc"), "CC2").unwrap();
    let r = get(s.port, "/cc");
    assert_eq!((status_of(&r), body_of(&r)), ("MISS", "CC2"), "{r}");

    // An intercepted 404 isn't in proxy_cache_valid: not cached, so the
    // file appearing later is found.
    let r = get(s.port, "/late.txt");
    assert!(r.starts_with("HTTP/1.1 403"), "{r}");
    std::fs::write(html.join("late.txt"), "LATE").unwrap();
    let r = get(s.port, "/late.txt");
    assert_eq!(body_of(&r), "LATE", "{r}");

    // A HEAD miss goes upstream as a GET: the next GET is a hit.
    std::fs::write(html.join("h.txt"), "HEAD-BODY").unwrap();
    let r = request(s.port, "HEAD /h.txt HTTP/1.0\r\nHost: localhost\r\n\r\n");
    assert_eq!((status_of(&r), body_of(&r)), ("MISS", ""), "{r}");
    assert!(r.contains("\r\nContent-Length: 9\r\n"), "{r}");
    let r = get(s.port, "/h.txt");
    assert_eq!((status_of(&r), body_of(&r)), ("HIT", "HEAD-BODY"), "{r}");

    // proxy_cache $arg_c: a zone by name, none when empty, 500 when unknown.
    let r = get(s.port, "/var/t.txt?c=two");
    assert_eq!((status_of(&r), body_of(&r)), ("MISS", "TWO"), "{r}");
    let r = get(s.port, "/var/t.txt?c=two");
    assert_eq!(status_of(&r), "HIT", "{r}");
    let r = get(s.port, "/var/t.txt");
    assert_eq!((status_of(&r), body_of(&r)), ("", "TWO"), "{r}");
    let r = get(s.port, "/var/t.txt?c=nope");
    assert!(r.starts_with("HTTP/1.1 500"), "{r}");
}

/// `proxy_cache_convert_head off`: a HEAD goes up as a HEAD and its answer
/// is stored, as nginx stores it. A GET then hits the head without its
/// body, and the connection closes rather than leave the client waiting
/// for it (nginx keeps it; proxy_cache_convert_head.t 3–4).
#[test]
fn m116_head_answer_is_stored_without_convert_head() {
    let s = setup("convert-head-off");
    std::fs::write(s.dir.join("html/t.html"), "SEE-THIS").unwrap();
    let _server = start(&s.dir.join("nginx.conf"));
    let head = "HEAD /nch/t.html HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    let r = request(s.port, head);
    assert_eq!(status_of(&r), "MISS", "{r}");
    let r = request(s.port, head);
    assert_eq!(status_of(&r), "HIT", "{r}");
    assert!(r.contains("\r\nContent-Length: 8\r\n"), "{r}");
    // A keep-alive GET: the head, no body, then the close.
    let mut c = TcpStream::connect(("127.0.0.1", s.port)).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    c.write_all(b"GET /nch/t.html HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .unwrap();
    let mut out = Vec::new();
    c.read_to_end(&mut out).unwrap();
    let r = String::from_utf8_lossy(&out);
    assert_eq!(status_of(&r), "HIT", "{r}");
    assert!(r.contains("\r\nConnection: close\r\n"), "{r}");
    assert_eq!(body_of(&r), "", "{r}");
}

#[test]
fn m116_expiry_vary_and_restart() {
    let setup_lock = common::ports::setup_lock();
    let s = setup("expiry");
    let html = s.dir.join("html");
    std::fs::write(html.join("s.txt"), "OLD").unwrap();
    std::fs::create_dir_all(html.join("vary")).unwrap();
    std::fs::write(html.join("vary/v.txt"), "V").unwrap();
    let server = start(&s.dir.join("nginx.conf"));
    drop(setup_lock);

    std::fs::write(html.join("r.txt"), "SAME").unwrap();
    let r = get(s.port, "/short/s.txt");
    assert_eq!(status_of(&r), "MISS", "{r}");
    let r = get(s.port, "/reval/r.txt");
    assert_eq!(status_of(&r), "MISS", "{r}");
    std::fs::write(html.join("s.txt"), "NEW").unwrap();
    std::thread::sleep(Duration::from_millis(2100));
    let r = get(s.port, "/short/s.txt");
    assert_eq!((status_of(&r), body_of(&r)), ("EXPIRED", "NEW"), "{r}");
    let r = get(s.port, "/short/s.txt");
    assert_eq!((status_of(&r), body_of(&r)), ("HIT", "NEW"), "{r}");
    // Unchanged upstream: a 304 renews the stale entry.
    let r = get(s.port, "/reval/r.txt");
    assert_eq!((status_of(&r), body_of(&r)), ("REVALIDATED", "SAME"), "{r}");
    assert!(r.starts_with("HTTP/1.1 200"), "{r}");
    let r = get(s.port, "/reval/r.txt");
    assert_eq!((status_of(&r), body_of(&r)), ("HIT", "SAME"), "{r}");

    // Vary: a hit only for the same Accept-Encoding.
    let gz = "GET /vary/v.txt HTTP/1.0\r\nHost: localhost\r\nAccept-Encoding: gzip\r\n\r\n";
    let r = request(s.port, gz);
    assert_eq!(status_of(&r), "MISS", "{r}");
    let r = request(s.port, gz);
    assert_eq!(status_of(&r), "HIT", "{r}");
    let r = get(s.port, "/vary/v.txt");
    assert_eq!(status_of(&r), "MISS", "{r}");
    // Each variant is kept (the second at its own key): both are hits.
    let r = get(s.port, "/vary/v.txt");
    assert_eq!(status_of(&r), "HIT", "{r}");
    let r = request(s.port, gz);
    assert_eq!(status_of(&r), "HIT", "{r}");

    // After a restart the files are found again.
    std::fs::write(html.join("keep.txt"), "KEPT").unwrap();
    let r = get(s.port, "/keep.txt");
    assert_eq!((status_of(&r), body_of(&r)), ("MISS", "KEPT"), "{r}");
    drop(server);
    // A killed server's io_uring lets go of the listener a little later:
    // wait for it, or the restart check connects to the old one.
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(("127.0.0.1", s.port)).is_ok() {
        assert!(Instant::now() < deadline, "old listener stays open");
        std::thread::sleep(Duration::from_millis(20));
    }
    std::fs::write(html.join("keep.txt"), "CHANGED").unwrap();
    let setup_lock = common::ports::setup_lock();
    let _server = start(&s.dir.join("nginx.conf"));
    drop(setup_lock);
    let r = get(s.port, "/keep.txt");
    assert_eq!((status_of(&r), body_of(&r)), ("HIT", "KEPT"), "{r}");
}

/// A conditional request answered from the cache (#349): 304 when every
/// condition says "unchanged", 412 for a failed precondition, the full
/// response otherwise, as nginx's not-modified filter on a cacheable
/// upstream response.
#[test]
fn m116_conditional_hits() {
    let _setup_lock = common::ports::setup_lock();
    let s = setup("cond");
    std::fs::write(s.dir.join("html").join("c.txt"), "COND").unwrap();
    let _server = start(&s.dir.join("nginx.conf"));
    drop(_setup_lock);

    let r = get(s.port, "/c.txt");
    assert_eq!(status_of(&r), "MISS", "{r}");
    let header = |name: &str| {
        r.lines()
            .find_map(|l| l.strip_prefix(name))
            .unwrap_or_else(|| panic!("{name} in {r}"))
            .trim()
            .to_string()
    };
    let (etag, last_modified) = (header("ETag:"), header("Last-Modified:"));
    let conditional = |h: &str| {
        request(
            s.port,
            &format!("GET /c.txt HTTP/1.0\r\nHost: x\r\n{h}\r\n\r\n"),
        )
    };

    let r = conditional(&format!("If-None-Match: {etag}"));
    assert!(r.starts_with("HTTP/1.1 304 Not Modified\r\n"), "{r}");
    assert!(r.contains(&format!("ETag: {etag}")), "{r}");
    assert!(
        !r.contains("Content-Length") && !r.contains("Content-Type"),
        "{r}"
    );
    assert_eq!(body_of(&r), "", "{r}");
    let r = conditional(&format!("If-Modified-Since: {last_modified}"));
    assert!(r.starts_with("HTTP/1.1 304"), "{r}");
    // `if_modified_since exact`: another date is "modified".
    let r = conditional("If-Modified-Since: Fri, 01 Jan 2100 00:00:00 GMT");
    assert_eq!(body_of(&r), "COND", "{r}");
    let r = conditional("If-None-Match: \"other\"");
    assert_eq!(body_of(&r), "COND", "{r}");
    let r = conditional("If-Unmodified-Since: Thu, 01 Jan 1970 00:00:00 GMT");
    assert!(r.starts_with("HTTP/1.1 412"), "{r}");
    let r = conditional("If-Match: \"other\"");
    assert!(r.starts_with("HTTP/1.1 412"), "{r}");

    // A response fetched now and stored (a bypass refreshes the cache)
    // gets the same answer.
    let r = request(
        s.port,
        &format!("GET /c.txt?bypass=1 HTTP/1.0\r\nHost: x\r\nIf-None-Match: {etag}\r\n\r\n"),
    );
    assert!(r.starts_with("HTTP/1.1 304"), "{r}");
    assert_eq!(status_of(&r), "BYPASS", "{r}");
    assert_eq!(body_of(&r), "", "{r}");
}

/// The response to `raw`, as bytes, with `Connection: close` added.
fn request_bytes(port: u16, raw: &str) -> (String, Vec<u8>) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.write_all(
        raw.replace("\r\n\r\n", "\r\nConnection: close\r\n\r\n")
            .as_bytes(),
    )
    .unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    let end = out.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    let body = out.split_off(end);
    (String::from_utf8(out).unwrap(), body)
}

/// The peak resident memory of process `pid`, in kB.
fn vm_hwm(pid: u32) -> u64 {
    std::fs::read_to_string(format!("/proc/{pid}/status"))
        .unwrap()
        .lines()
        .find_map(|l| l.strip_prefix("VmHWM:"))
        .and_then(|v| v.trim().strip_suffix(" kB"))
        .unwrap()
        .parse()
        .unwrap()
}

/// #515: a hit sends the body from the cache file, as nginx's
/// ngx_http_cache_send does, instead of reading the file into memory:
/// over HTTP/1.1 with and without sendfile, TLS and HTTP/2, cut by ranges.
#[test]
fn m116_large_hits_come_from_the_file() {
    let setup_lock = common::ports::setup_lock();
    let dir = std::env::temp_dir().join(format!("ruxen-m116-large-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("html")).unwrap();
    let _cleanup = Setup {
        dir: dir.clone(),
        port: 0,
    };
    let big: Vec<u8> = (0..8u32 << 20).map(|i| (i * 7 % 251) as u8).collect();
    std::fs::write(dir.join("html/big.bin"), &big).unwrap();
    // Just past what a hit reads with the header.
    let mid = &big[..20_000];
    std::fs::write(dir.join("html/mid.bin"), mid).unwrap();
    let cert = common::tls::make_self_signed("localhost");
    let [port, tls, backend] = common::ports::free_ports();
    let d = dir.display();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "events {{}}\nhttp {{ access_log off;\n\
             proxy_cache_path {d}/cache levels=1:2 keys_zone=one:1m;\n\
             server {{ listen 127.0.0.1:{port}; listen 127.0.0.1:{tls} ssl; http2 on;\n\
               ssl_certificate {}; ssl_certificate_key {};\n\
               add_header X-Cache $upstream_cache_status;\n\
               proxy_cache one; proxy_cache_valid 200 1m;\n\
               location / {{ proxy_pass http://127.0.0.1:{backend}; }}\n\
               location /sf/ {{ proxy_pass http://127.0.0.1:{backend}/; sendfile on; }}\n\
             }}\n\
             server {{ listen 127.0.0.1:{backend}; root {d}/html; }} }}\n",
            cert.cert_path().display(),
            cert.key_path().display(),
        ),
    )
    .unwrap();
    let conf = dir.join("nginx.conf");
    let get = |path: &str, extra: &str| {
        request_bytes(
            port,
            &format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n{extra}\r\n"),
        )
    };
    {
        let _server = start(&conf);
        // `/sf/big.bin` has the same key, the upstream URL.
        for path in ["/big.bin", "/mid.bin"] {
            let (head, _) = get(path, "");
            assert!(head.contains("\r\nX-Cache: MISS\r\n"), "{head}");
        }
    }
    // After a restart, so that the misses' buffering doesn't count.
    let server = start(&conf);
    drop(setup_lock);
    let before = vm_hwm(server.0.id());

    for path in ["/big.bin", "/sf/big.bin"] {
        let (head, body) = get(path, "");
        assert!(head.starts_with("HTTP/1.1 200 OK\r\n"), "{head}");
        assert!(head.contains("\r\nX-Cache: HIT\r\n"), "{head}");
        assert!(
            head.contains(&format!("\r\nContent-Length: {}\r\n", big.len())),
            "{head}"
        );
        assert!(body == big, "{path}: {} bytes", body.len());
    }
    let (head, body) = get("/mid.bin", "");
    assert!(head.contains("\r\nX-Cache: HIT\r\n"), "{head}");
    assert!(body == mid, "{} bytes", body.len());
    let after = vm_hwm(server.0.id());
    assert!(
        after < before + 4096,
        "VmHWM {before} kB before the hits, {after} kB after"
    );

    // HEAD: the length, no body.
    let (head, body) = request_bytes(port, "HEAD /big.bin HTTP/1.1\r\nHost: x\r\n\r\n");
    assert!(
        head.contains(&format!("\r\nContent-Length: {}\r\n", big.len())),
        "{head}"
    );
    assert!(body.is_empty());

    // Ranges: one is a part of the file, several a multipart response.
    for path in ["/big.bin", "/sf/big.bin"] {
        let (head, body) = get(path, "Range: bytes=1000000-1000099\r\n");
        assert!(head.starts_with("HTTP/1.1 206 "), "{head}");
        assert!(
            head.contains(&format!(
                "\r\nContent-Range: bytes 1000000-1000099/{}\r\n",
                big.len()
            )),
            "{head}"
        );
        assert!(body == big[1_000_000..1_000_100], "{body:?}");
    }
    let (head, body) = get("/big.bin", "Range: bytes=0-9,5000000-5000009\r\n");
    assert!(head.contains("multipart/byteranges; boundary="), "{head}");
    let body = String::from_utf8_lossy(&body);
    assert!(body.contains(&format!(
        "Content-Range: bytes 5000000-5000009/{}",
        big.len()
    )));
    assert!(body.contains(&*String::from_utf8_lossy(&big[5_000_000..5_000_010])));
    let (head, _) = get("/big.bin", "Range: bytes=9000000-\r\n");
    assert!(head.starts_with("HTTP/1.1 416 "), "{head}");

    // TLS, HTTP/1.1 and HTTP/2.
    let out = dir.join("out.bin");
    for proto in ["--http1.1", "--http2"] {
        let status = Command::new("curl")
            .args(["-sSk", "--max-time", "20", proto, "-o"])
            .arg(&out)
            .args(["-w", "%{http_version} %{http_code}"])
            .arg(format!("https://localhost:{tls}/big.bin"))
            .args(["--resolve", &format!("localhost:{tls}:127.0.0.1")])
            .output()
            .unwrap();
        let status = String::from_utf8_lossy(&status.stdout).into_owned();
        assert!(status.ends_with(" 200"), "{proto}: {status}");
        assert!(std::fs::read(&out).unwrap() == big, "{proto}");
    }
}
