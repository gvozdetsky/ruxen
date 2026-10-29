//! M100 — a body nothing reads is dropped as it is read (#289): a
//! `return` location without rewrites, `if`, `error_page`,
//! `post_action` or `limit_except`, in a config that never reads
//! `$request_body` or `$request_body_file`, reads the body through a small
//! buffer and drops it, as nginx's ngx_http_discard_request_body does. The
//! response goes out first, before the body has come (#627). The
//! connection stays usable: keep-alive and a pipelined request after the
//! body work, and `$request_length` still counts the whole body. A static
//! file discards it too, as nginx's static module does, unless an `index`
//! or `error_page` can take the request to something that reads it.

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Server(Child, PathBuf);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
        let _ = std::fs::remove_dir_all(&self.1);
    }
}

fn start(name: &str) -> (Server, u16) {
    start_with(name, |_, _| {
        "location / { return 200 \"ok $content_length\\n\"; }".to_string()
    })
}

/// A server whose locations `locations` gives, from the temp dir and the
/// port.
fn start_with(name: &str, locations: impl FnOnce(&Path, u16) -> String) -> (Server, u16) {
    let dir = std::env::temp_dir().join(format!("ruxen-m100-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // Held until ruxen listens: released earlier, another test could take
    // the same free port, and ruxen would fail to bind it.
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
            "events {{}}\nhttp {{\n\
             log_format len '$request_uri $request_length';\n\
             server {{ listen 127.0.0.1:{port};\n\
             access_log {d}/access.log len;\n\
             client_max_body_size 10m;\n\
             {locations}\n\
             }} }}\n",
            locations = locations(&dir, port)
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
    (server, port)
}

/// Read `count` responses with Content-Length bodies off `s`.
fn responses(s: &mut TcpStream, count: usize) -> Vec<String> {
    let mut raw = Vec::new();
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    while out.len() < count {
        let n = s.read(&mut buf).unwrap();
        assert!(n > 0, "connection closed after {} responses", out.len());
        raw.extend_from_slice(&buf[..n]);
        while let Some(end) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&raw[..end]).to_string();
            let len: usize = head
                .lines()
                .find_map(|l| l.strip_prefix("Content-Length: "))
                .unwrap()
                .parse()
                .unwrap();
            if raw.len() < end + 4 + len {
                break;
            }
            let body = String::from_utf8_lossy(&raw[end + 4..end + 4 + len]).to_string();
            out.push(format!("{} | {body}", head.lines().next().unwrap()));
            raw.drain(..end + 4 + len);
        }
    }
    out
}

fn log_lines(path: &Path, count: usize) -> Vec<String> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        let lines: Vec<String> = text.lines().map(str::to_string).collect();
        if lines.len() >= count {
            return lines;
        }
        assert!(Instant::now() < deadline, "{text}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn m100_dropped_body_keeps_the_connection_in_step() {
    let (server, port) = start("step");
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let big = vec![b'x'; 200 * 1024 + 3];
    // A large body in pieces, with pauses, and a second request pipelined
    // right behind it in the last write.
    let head = format!(
        "POST /a HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n",
        big.len()
    );
    s.write_all(head.as_bytes()).unwrap();
    for part in big[..big.len() - 10].chunks(50 * 1024) {
        s.write_all(part).unwrap();
        std::thread::sleep(Duration::from_millis(20));
    }
    let mut last = big[big.len() - 10..].to_vec();
    last.extend_from_slice(b"POST /b HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello");
    last.extend_from_slice(b"GET /c HTTP/1.1\r\nHost: x\r\n\r\n");
    s.write_all(&last).unwrap();
    assert_eq!(
        responses(&mut s, 3),
        [
            format!("HTTP/1.1 200 OK | ok {}\n", big.len()),
            "HTTP/1.1 200 OK | ok 5\n".to_string(),
            "HTTP/1.1 200 OK | ok \n".to_string(),
        ]
    );
    let lines = log_lines(&server.1.join("access.log"), 3);
    let len_a: usize = lines[0].strip_prefix("/a ").unwrap().parse().unwrap();
    assert_eq!(len_a, head.len() + big.len(), "{lines:?}");
    assert!(lines[1].starts_with("/b "), "{lines:?}");
}

/// A body that came whole is dropped before the response, as nginx reads
/// what has arrived, and the requests queued behind it are read from the
/// socket at once (#757); with the body dropped by the read instead.
#[test]
fn m100_a_body_already_there_and_requests_behind_it() {
    let (server, port) = start("there");
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let body = vec![b'y'; 100 * 1024];
    let mut all = Vec::new();
    for path in ["/a", "/b"] {
        all.extend_from_slice(
            format!(
                "POST {path} HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .as_bytes(),
        );
        all.extend_from_slice(&body);
    }
    all.extend_from_slice(b"GET /c HTTP/1.1\r\nHost: x\r\n\r\n");
    s.write_all(&all).unwrap();
    let ok = format!("HTTP/1.1 200 OK | ok {}\n", body.len());
    assert_eq!(
        responses(&mut s, 3),
        [ok.clone(), ok, "HTTP/1.1 200 OK | ok \n".to_string()]
    );
    let lines = log_lines(&server.1.join("access.log"), 3);
    assert!(lines[1].starts_with("/b "), "{lines:?}");
    assert!(lines[2].starts_with("/c "), "{lines:?}");
}

#[test]
fn m100_client_stopping_mid_body_closes_the_connection() {
    let (_server, port) = start("stop");
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 100000\r\n\r\n")
        .unwrap();
    s.write_all(&[b'x'; 1000]).unwrap();
    s.shutdown(std::net::Shutdown::Write).unwrap();
    // The response went out at once (#627); the rest of the body never
    // comes, so the connection then closes.
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    let out = String::from_utf8_lossy(&out);
    assert!(out.starts_with("HTTP/1.1 200 OK"), "{out}");
    assert_eq!(out.matches("HTTP/1.1").count(), 1, "{out}");
}

/// The response doesn't wait for a body nothing reads (#627): it comes
/// while the body is still on its way, as nginx answers before discarding.
/// A chunked body that is still coming gets the response too, and the
/// rest is read and dropped after it, chunk by chunk, so the next request
/// on the connection is served (ngx_http_discard_request_body_filter).
#[test]
fn m100_the_response_comes_before_the_body() {
    let (_server, port) = start("first");
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    s.write_all(b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\nabc")
        .unwrap();
    assert_eq!(
        responses(&mut s, 1),
        ["HTTP/1.1 200 OK | ok 10\n".to_string()]
    );
    // The rest of it, and a next request on the same connection.
    s.write_all(b"defghijGET /two HTTP/1.1\r\nHost: x\r\n\r\n")
        .unwrap();
    assert_eq!(
        responses(&mut s, 1),
        ["HTTP/1.1 200 OK | ok \n".to_string()]
    );

    let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    c.write_all(b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel")
        .unwrap();
    assert_eq!(
        responses(&mut c, 1),
        ["HTTP/1.1 200 OK | ok \n".to_string()]
    );
    let mut rest = b"lo\r\n".to_vec();
    rest.extend_from_slice(
        &[b"8000\r\n".as_slice(), &[b'x'; 0x8000], b"\r\n"]
            .concat()
            .repeat(8),
    );
    rest.extend_from_slice(b"0\r\nX-Trailer: 1\r\n\r\nGET /two HTTP/1.1\r\nHost: x\r\n\r\n");
    c.write_all(&rest).unwrap();
    assert_eq!(
        responses(&mut c, 1),
        ["HTTP/1.1 200 OK | ok \n".to_string()]
    );
}

/// A chunked body nothing reads is parsed as far as it came with the head
/// before the response, as nginx's discard does: a framing error there is
/// a 400, and a whole body leaves a pipelined request behind it to be
/// served. One that turns out malformed after the response closes the
/// connection.
#[test]
fn m100_a_dropped_chunked_body_is_still_parsed() {
    let (_server, port) = start("chunked");
    let exchange = |raw: &[u8]| {
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        s.write_all(raw).unwrap();
        let mut out = Vec::new();
        let _ = s.read_to_end(&mut out);
        String::from_utf8_lossy(&out).to_string()
    };
    let out = exchange(
        b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nhello\r\n0\r\n\r\n",
    );
    assert!(out.starts_with("HTTP/1.1 400"), "{out}");
    let out = exchange(
        b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n\
          GET /two HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(out.matches("HTTP/1.1 200 OK").count(), 2, "{out}");

    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    s.write_all(b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel")
        .unwrap();
    assert_eq!(
        responses(&mut s, 1),
        ["HTTP/1.1 200 OK | ok \n".to_string()]
    );
    s.write_all(b"lo\r\nzz\r\n0\r\n\r\nGET /two HTTP/1.1\r\nHost: x\r\n\r\n")
        .unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    assert!(out.is_empty(), "{}", String::from_utf8_lossy(&out));
}

/// An upstream that answers each request with how many body bytes it got
/// and the Content-Length it was told: `got N of CL`.
fn counting_upstream() -> u16 {
    // Bound under the lock: it could take the port another test has just
    // picked for its ruxen.
    let setup = common::ports::setup_lock();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    drop(setup);
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut c) = conn else { return };
            c.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut raw = Vec::new();
            let mut buf = [0u8; 4096];
            let end = loop {
                if let Some(end) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                    break end + 4;
                }
                match c.read(&mut buf) {
                    Ok(n) if n > 0 => raw.extend_from_slice(&buf[..n]),
                    _ => break raw.len(),
                }
            };
            let head = String::from_utf8_lossy(&raw[..end]).to_ascii_lowercase();
            let cl: usize = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length: "))
                .map_or(0, |v| v.trim().parse().unwrap());
            while raw.len() < end + cl {
                match c.read(&mut buf) {
                    Ok(n) if n > 0 => raw.extend_from_slice(&buf[..n]),
                    _ => break,
                }
            }
            let body = format!("got {} of {cl}", raw.len() - end);
            let _ = write!(
                c,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    port
}

fn static_locations(dir: &Path, upstream: u16) -> String {
    let html = dir.join("html");
    std::fs::create_dir_all(&html).unwrap();
    std::fs::write(html.join("index.html"), "index").unwrap();
    std::fs::write(html.join("f.txt"), "file").unwrap();
    format!(
        "root {html};\n\
         add_header X-Body \"[$request_body]\";\n\
         location / {{ error_page 400 /up/; }}\n\
         location /e404/ {{ error_page 404 /up/; }}\n\
         location /small {{ client_max_body_size 4; error_page 413 /up/; }}\n\
         location /up/ {{ proxy_pass http://127.0.0.1:{upstream}; }}",
        html = html.display()
    )
}

/// A static file answers before its body has come, as nginx's static
/// module discards it (#627), though the config reads `$request_body`
/// (empty here, as in nginx) and an `error_page` the static path can't
/// reach proxies. The rest is dropped and the connection goes on. A POST,
/// which the static module refuses, gets its 405 at once too.
#[test]
fn m100_a_static_file_answers_before_the_body() {
    let upstream = counting_upstream();
    let (_server, port) = start_with("static", |dir, _| static_locations(dir, upstream));
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    s.write_all(b"GET /f.txt HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\nabc")
        .unwrap();
    assert_eq!(responses(&mut s, 1), ["HTTP/1.1 200 OK | file".to_string()]);
    s.write_all(b"defghijGET / HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\nxy")
        .unwrap();
    assert_eq!(
        responses(&mut s, 1),
        ["HTTP/1.1 200 OK | index".to_string()]
    );

    let mut p = TcpStream::connect(("127.0.0.1", port)).unwrap();
    p.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    p.write_all(b"POST /f.txt HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\nabc")
        .unwrap();
    let mut buf = [0u8; 4096];
    let n = p.read(&mut buf).unwrap();
    let out = String::from_utf8_lossy(&buf[..n]);
    assert!(out.starts_with("HTTP/1.1 405 Not Allowed"), "{out}");
}

/// Where an `error_page` the static path can reach proxies, the body is
/// read and goes upstream, as nginx redirects to the error page before
/// the static module would discard it.
#[test]
fn m100_an_error_page_that_proxies_gets_the_body() {
    let upstream = counting_upstream();
    let (_server, port) = start_with("static-404", |dir, _| static_locations(dir, upstream));
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(b"POST /e404/none HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello")
        .unwrap();
    let out = responses(&mut s, 1);
    assert!(out[0].ends_with("| got 5 of 5"), "{out:?}");
}

/// A body refused as too large isn't read, and an `error_page` that
/// proxies sends none upstream: nginx's `Content-Length: 0`, where the
/// client's length with no bytes behind it left the upstream waiting.
#[test]
fn m100_a_refused_body_goes_upstream_empty() {
    let upstream = counting_upstream();
    let (_server, port) = start_with("static-413", |dir, _| static_locations(dir, upstream));
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(b"POST /small HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\n0123456789")
        .unwrap();
    let out = responses(&mut s, 1);
    assert!(out[0].ends_with("| got 0 of 0"), "{out:?}");
}

/// What answers before a location (a server-level `return`, a bad target,
/// a missing Host) and `try_files` to a file (also via an SPA's `@router`)
/// answer before the body has come, as nginx discards it (#776); a
/// `try_files` that ends in a proxy still sends the body upstream.
#[test]
fn m100_unrouted_answers_and_try_files_come_before_the_body() {
    let upstream = counting_upstream();
    let (_server, port) = start_with("unrouted", |dir, _| {
        let html = dir.join("html");
        std::fs::create_dir_all(&html).unwrap();
        std::fs::write(html.join("index.html"), "index").unwrap();
        format!(
            "root {html};\n\
             if ($http_x_redirect) {{ return 301 https://example.com/; }}\n\
             location / {{ try_files $uri $uri/ @router; }}\n\
             location @router {{ rewrite ^ /index.html last; }}\n\
             location /p/ {{ try_files $uri @up; }}\n\
             location @up {{ proxy_pass http://127.0.0.1:{upstream}; }}",
            html = html.display()
        )
    });
    let first = |head: &str| {
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        s.write_all(format!("{head}Content-Length: 10\r\n\r\nabc").as_bytes())
            .unwrap();
        let out = responses(&mut s, 1).remove(0);
        (s, out)
    };
    let (_, out) = first("POST /x HTTP/1.1\r\nHost: x\r\nX-Redirect: 1\r\n");
    assert!(out.starts_with("HTTP/1.1 301 "), "{out}");
    let (_, out) = first("GET /%4 HTTP/1.1\r\nHost: x\r\n");
    assert!(out.starts_with("HTTP/1.1 400 "), "{out}");
    let (_, out) = first("GET / HTTP/1.1\r\n");
    assert!(out.starts_with("HTTP/1.1 400 "), "{out}");
    let (mut s, out) = first("GET /missing HTTP/1.1\r\nHost: x\r\n");
    assert_eq!(out, "HTTP/1.1 200 OK | index");
    s.write_all(b"defghijGET /index.html HTTP/1.1\r\nHost: x\r\n\r\n")
        .unwrap();
    assert_eq!(
        responses(&mut s, 1),
        ["HTTP/1.1 200 OK | index".to_string()]
    );

    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(b"POST /p/none HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello")
        .unwrap();
    let out = responses(&mut s, 1);
    assert!(out[0].ends_with("| got 5 of 5"), "{out:?}");
}
