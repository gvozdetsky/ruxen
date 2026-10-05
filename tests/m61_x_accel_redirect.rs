//! M61 — an upstream `X-Accel-Redirect` redirects the request internally
//! (to a URI with its args, or to a named location), as a GET, and the
//! upstream's body is dropped; `proxy_ignore_headers X-Accel-Redirect`
//! forwards the response instead. Both used to be ignored.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

struct Server {
    child: Child,
    port: u16,
    dir: PathBuf,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn start(http_body: &str) -> Server {
    let port = {
        let probe = TcpListener::bind("127.0.0.1:0").unwrap();
        probe.local_addr().unwrap().port()
    };
    let dir = std::env::temp_dir().join(format!("ruxen-m61-{}-{port}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "events {{}}\nhttp {{ {} }}\n",
            http_body.replace("%%PORT%%", &port.to_string())
        ),
    )
    .unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .arg("-c")
        .arg(dir.join("nginx.conf"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "ruxen did not start");
        sleep(Duration::from_millis(20));
    }
    Server { child, port, dir }
}

/// Backend: `/to-named` redirects to `@named`, `/loop/` to itself,
/// anything else to `/internal/x?a=1`; the body is `upstream body`.
fn spawn_backend() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut s in listener.incoming().flatten() {
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                if s.read(&mut byte).unwrap_or(0) == 0 {
                    break;
                }
                head.push(byte[0]);
            }
            let target = if head.windows(9).any(|w| w == b"/to-named") {
                "@named"
            } else if head.windows(6).any(|w| w == b"/loop/") {
                "/loop/"
            } else {
                "/internal/x?a=1"
            };
            let _ = write!(
                s,
                "HTTP/1.1 200 OK\r\nX-Accel-Redirect: {target}\r\nContent-Length: 13\r\n\
                 Connection: close\r\n\r\nupstream body"
            );
        }
    });
    port
}

fn send(port: u16, method: &str, path: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(
        s,
        "{method} {path} HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

fn body(resp: &str) -> &str {
    resp.split_once("\r\n\r\n").map_or("", |(_, b)| b)
}

#[test]
fn x_accel_redirect_redirects_internally() {
    let up = spawn_backend();
    let server = start(&format!(
        "server {{ listen 127.0.0.1:%%PORT%%;\n\
           location /p/ {{ proxy_pass http://127.0.0.1:{up}; }}\n\
           location /to-named {{ proxy_pass http://127.0.0.1:{up}; }}\n\
           location /ignored/ {{ proxy_pass http://127.0.0.1:{up}; \
             proxy_ignore_headers X-Accel-Redirect; }}\n\
           location /internal/ {{ internal; return 200 \"internal $request_method $uri $args\"; }}\n\
           location @named {{ return 200 \"named\"; }}\n\
           location /loop/ {{ proxy_pass http://127.0.0.1:{up}; }}\n\
         }}"
    ));

    let resp = send(server.port, "POST", "/p/");
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
    assert_eq!(body(&resp), "internal GET /internal/x a=1", "{resp}");
    assert!(!resp.contains("X-Accel-Redirect"), "{resp}");

    assert_eq!(body(&send(server.port, "GET", "/to-named")), "named");

    // Ignored: the upstream response as is (the header stays hidden).
    let resp = send(server.port, "GET", "/ignored/");
    assert_eq!(body(&resp), "upstream body", "{resp}");
    assert!(!resp.contains("X-Accel-Redirect"), "{resp}");

    // A redirect cycle ends in 500, as nginx's `uri_changes` limit.
    assert!(send(server.port, "GET", "/loop/").starts_with("HTTP/1.1 500"));
}

/// Backend for the carried headers: redirects `/c/file` to `/f.txt`,
/// `/c/missing` to a file that doesn't exist and anything else to
/// `/internal/show`, with the headers nginx carries over
/// an X-Accel-Redirect and two it doesn't.
fn spawn_carrying_backend() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut s in listener.incoming().flatten() {
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                if s.read(&mut byte).unwrap_or(0) == 0 {
                    break;
                }
                head.push(byte[0]);
            }
            let target = if head.windows(7).any(|w| w == b"/c/file") {
                "/f.txt"
            } else if head.windows(10).any(|w| w == b"/c/missing") {
                "/missing.txt"
            } else {
                "/internal/show"
            };
            let _ = write!(
                s,
                "HTTP/1.1 200 OK\r\nX-Accel-Redirect: {target}\r\nContent-Type: text/blah\r\n\
                 Set-Cookie: a=1\r\nSet-Cookie: b=2\r\nContent-Disposition: attachment\r\n\
                 Cache-Control: no-cache\r\nExpires: fake\r\nAccept-Ranges: parrots\r\n\
                 Something: other\r\nX-Extra: 7\r\nContent-Length: 0\r\n\
                 Connection: close\r\n\r\n"
            );
        }
    });
    port
}

fn header_lines<'a>(resp: &'a str, name: &str) -> Vec<&'a str> {
    let head = resp.split_once("\r\n\r\n").map_or(resp, |(h, _)| h);
    head.lines()
        .filter_map(|l| l.split_once(": "))
        .filter(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v)
        .collect()
}

/// The target of an X-Accel-Redirect gets the upstream's Content-Type,
/// Set-Cookie, Content-Disposition, Cache-Control, Expires and
/// Accept-Ranges, and still reads `$upstream_http_*`, as in nginx
/// (ngx_http_upstream_process_headers). Both used to be lost.
#[test]
fn x_accel_redirect_keeps_upstream_headers() {
    let up = spawn_carrying_backend();
    let root = std::env::temp_dir().join(format!("ruxen-m61-root-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("f.txt"), "file").unwrap();
    let server = start(&format!(
        "log_format x \"$uri $upstream_http_x_extra\";\n\
         server {{ listen 127.0.0.1:%%PORT%%; root {root};\n\
           access_log {root}/access.log x;\n\
           location /c/ {{ proxy_pass http://127.0.0.1:{up}; }}\n\
           location /internal/ {{ internal;\n\
             return 200 \"xar=$upstream_http_x_accel_redirect extra=$upstream_http_x_extra\"; }}\n\
         }}",
        root = root.display()
    ));

    let resp = send(server.port, "GET", "/c/show");
    assert_eq!(body(&resp), "xar=/internal/show extra=7", "{resp}");
    assert_eq!(header_lines(&resp, "Content-Type"), ["text/blah"], "{resp}");
    assert_eq!(header_lines(&resp, "Set-Cookie"), ["a=1", "b=2"], "{resp}");
    assert_eq!(header_lines(&resp, "Content-Disposition"), ["attachment"]);
    assert_eq!(header_lines(&resp, "Cache-Control"), ["no-cache"]);
    assert_eq!(header_lines(&resp, "Expires"), ["fake"]);
    assert_eq!(header_lines(&resp, "Accept-Ranges"), ["parrots"]);
    assert!(header_lines(&resp, "Something").is_empty(), "{resp}");
    assert!(header_lines(&resp, "X-Extra").is_empty(), "{resp}");

    // A static file: the carried type replaces the file's, and the file
    // has its own Accept-Ranges too (both, as nginx 1.24 sends them).
    let resp = send(server.port, "GET", "/c/file");
    assert_eq!(body(&resp), "file", "{resp}");
    assert_eq!(header_lines(&resp, "Content-Type"), ["text/blah"], "{resp}");
    let mut ranges = header_lines(&resp, "Accept-Ranges");
    ranges.sort();
    assert_eq!(ranges, ["bytes", "parrots"], "{resp}");
    assert_eq!(header_lines(&resp, "Set-Cookie"), ["a=1", "b=2"], "{resp}");

    // An error page keeps its own type and has no Accept-Ranges, as
    // nginx's special response; the cookies still go out.
    let resp = send(server.port, "GET", "/c/missing");
    assert!(resp.starts_with("HTTP/1.1 404"), "{resp}");
    assert_eq!(header_lines(&resp, "Content-Type"), ["text/plain"], "{resp}");
    assert!(header_lines(&resp, "Accept-Ranges").is_empty(), "{resp}");
    assert_eq!(header_lines(&resp, "Set-Cookie"), ["a=1", "b=2"], "{resp}");

    let log = std::fs::read_to_string(root.join("access.log")).unwrap();
    let _ = std::fs::remove_dir_all(&root);
    assert_eq!(log, "/internal/show 7\n/f.txt 7\n/missing.txt 7\n");
}
