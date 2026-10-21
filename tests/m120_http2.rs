//! M120 — HTTP/2 (#144): `http2 on` / `listen … http2`, cleartext with
//! prior knowledge (the connection preface) and over TLS through ALPN.
//! Each stream goes through the same request handling as HTTP/1.1, so
//! static files, `return`, the proxy and the access log work as they do
//! there. Checked with curl's HTTP/2 client.

mod common;

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
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

/// `setup` is the port lock, taken before the test picked its ports:
/// released only once ruxen listens, so no parallel test takes them.
fn start(
    name: &str,
    setup: std::sync::MutexGuard<'static, ()>,
    http: impl FnOnce(&Path) -> String,
) -> Server {
    let dir = std::env::temp_dir().join(format!("ruxen-m120-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("html")).unwrap();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "pid {d}/ruxen.pid;\nerror_log {d}/error.log info;\nevents {{}}\n\
             http {{\naccess_log {d}/access.log;\n{http}\n}}\n",
            d = dir.display(),
            http = http(&dir)
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
    let mut s = Server { child, dir };
    let deadline = Instant::now() + Duration::from_secs(3);
    while !s.dir.join("ruxen.pid").exists() {
        assert!(
            Instant::now() < deadline && s.child.try_wait().unwrap().is_none(),
            "ruxen did not start: {}",
            std::fs::read_to_string(s.dir.join("error.log")).unwrap_or_default()
        );
        sleep(Duration::from_millis(10));
    }
    drop(setup);
    s
}

/// curl with `args`; `-sS`, and `%{http_version} %{http_code}` after the
/// body on a line of its own.
fn curl(args: &[&str]) -> (String, String) {
    let out: Output = Command::new("curl")
        .args([
            "-sS",
            "--max-time",
            "10",
            "-w",
            "\n%{http_version} %{http_code}",
        ])
        .args(args)
        .output()
        .expect("curl");
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let (body, status) = text.rsplit_once('\n').unwrap_or((&text, ""));
    (body.to_string(), status.to_string())
}

#[test]
fn cleartext_http2_with_prior_knowledge() {
    let setup = common::ports::setup_lock();
    let [port, backend] = common::ports::free_ports();
    let s = start("h2c", setup, |dir| {
        std::fs::write(dir.join("html/index.html"), "static\n").unwrap();
        // More than the 64 KiB initial stream window.
        std::fs::write(dir.join("html/big.bin"), vec![b'x'; 300_000]).unwrap();
        format!(
            "server {{ listen 127.0.0.1:{port}; http2 on; root {d}/html;\n\
               location /r {{ return 200 \"$server_protocol $http2 $request\\n\"; }}\n\
               location /p {{ proxy_pass http://127.0.0.1:{backend}/; }} }}\n\
             server {{ listen 127.0.0.1:{backend};\n\
               location / {{ return 200 \"got [$request_body] $content_length\\n\"; }} }}",
            d = dir.display()
        )
    });
    let url = |path: &str| format!("http://127.0.0.1:{port}{path}");

    let (body, status) = curl(&["--http2-prior-knowledge", &url("/r")]);
    assert_eq!(status, "2 200");
    assert_eq!(body, "HTTP/2.0 h2c GET /r HTTP/2.0\n");

    let (body, status) = curl(&["--http2-prior-knowledge", &url("/")]);
    assert_eq!((body.as_str(), status.as_str()), ("static\n", "2 200"));

    let (body, status) = curl(&["--http2-prior-knowledge", &url("/big.bin")]);
    assert_eq!(status, "2 200");
    assert_eq!(body.len(), 300_000);

    let (body, status) = curl(&["--http2-prior-knowledge", "-I", &url("/big.bin")]);
    assert_eq!(status, "2 200");
    assert!(body.contains("content-length: 300000"), "{body}");

    // A request body, proxied.
    let (body, status) = curl(&["--http2-prior-knowledge", "-d", "a=1&b=2", &url("/p")]);
    assert_eq!(
        (body.as_str(), status.as_str()),
        ("got [a=1&b=2] 7\n", "2 200")
    );

    let (_, status) = curl(&["--http2-prior-knowledge", &url("/missing")]);
    assert_eq!(status, "2 404");

    // HTTP/1.1 on the same address.
    let (body, status) = curl(&["--http1.1", &url("/r")]);
    assert_eq!(status, "1.1 200");
    assert_eq!(body, "HTTP/1.1  GET /r HTTP/1.1\n");

    let log = std::fs::read_to_string(s.dir.join("access.log")).unwrap();
    assert!(log.contains("\"GET /r HTTP/2.0\" 200"), "{log}");
    // The error log quotes the request line as the client sent it, as
    // nginx's r->request_line.
    let errors = std::fs::read_to_string(s.dir.join("error.log")).unwrap();
    assert!(
        errors.contains("request: \"GET /missing HTTP/2.0\""),
        "{errors}"
    );
}

#[test]
fn http2_over_tls_through_alpn() {
    let certs = common::tls::make_self_signed("localhost");
    let setup = common::ports::setup_lock();
    let [port, plain] = common::ports::free_ports();
    let (cert, key) = (certs.cert_path().to_owned(), certs.key_path().to_owned());
    let _s = start("tls", setup, |dir| {
        std::fs::write(dir.join("html/index.html"), "static\n").unwrap();
        format!(
            "ssl_certificate {c}; ssl_certificate_key {k};\n\
             server {{ listen 127.0.0.1:{port} ssl; server_name localhost; http2 on;\n\
               root {d}/html; location /r {{ return 200 \"$http2 $https\\n\"; }} }}\n\
             server {{ listen 127.0.0.1:{port} ssl; server_name old; http2 off;\n\
               location / {{ return 200 \"old\\n\"; }} }}\n\
             server {{ listen 127.0.0.1:{plain}; location / {{ return 200 \"h1\\n\"; }} }}",
            c = cert.display(),
            k = key.display(),
            d = dir.display()
        )
    });
    let resolve = format!("localhost:{port}:127.0.0.1");
    let url = format!("https://localhost:{port}/r");
    let (body, status) = curl(&["-k", "--http2", "--resolve", &resolve, &url]);
    assert_eq!((body.as_str(), status.as_str()), ("h2 on\n", "2 200"));

    // A client that offers only HTTP/1.1 gets it.
    let (body, status) = curl(&["-k", "--http1.1", "--resolve", &resolve, &url]);
    assert_eq!((body.as_str(), status.as_str()), (" on\n", "1.1 200"));

    // The SNI name of a server with HTTP/2 off: ALPN doesn't offer h2.
    let old = format!("old:{port}:127.0.0.1");
    let (body, status) = curl(&[
        "-k",
        "--http2",
        "--resolve",
        &old,
        &format!("https://old:{port}/"),
    ]);
    assert_eq!((body.as_str(), status.as_str()), ("old\n", "1.1 200"));

    // HTTP/2 negotiated for one server, a request for the other: 421, as
    // nginx.
    let (_, status) = curl(&[
        "-k",
        "--http2",
        "--resolve",
        &resolve,
        "-H",
        "Host: old",
        &url,
    ]);
    assert_eq!(status, "2 421");

    // Without `http2`, a preface is just a bad HTTP/1.1 request.
    let (_, status) = curl(&[
        "--http2-prior-knowledge",
        &format!("http://127.0.0.1:{plain}/"),
    ]);
    assert_ne!(status, "2 200");
}

/// One request on a connection of its own, in hand-made frames (curl turns
/// a `Host` into the `:authority` and sends no `host`): GET `/` with these
/// `:authority` and `host` fields, HPACK literals without indexing. The
/// answer's status (200 or 400) and body.
fn h2_get(port: u16, authority: Option<&str>, host: Option<&str>) -> (u16, String) {
    use std::io::{Read, Write};
    fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
        let mut f = (payload.len() as u32).to_be_bytes()[1..].to_vec();
        f.extend_from_slice(&[kind, flags]);
        f.extend_from_slice(&stream.to_be_bytes());
        f.extend_from_slice(payload);
        f
    }
    // :method GET, :scheme http, :path / (static table 2, 6, 4).
    let mut block = vec![0x82, 0x86, 0x84];
    if let Some(a) = authority {
        // :authority, its name from the static table (1).
        block.extend_from_slice(&[0x01, a.len() as u8]);
        block.extend_from_slice(a.as_bytes());
    }
    if let Some(h) = host {
        // host, a literal name.
        block.extend_from_slice(&[0x00, 4]);
        block.extend_from_slice(b"host");
        block.push(h.len() as u8);
        block.extend_from_slice(h.as_bytes());
    }
    let mut c = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    c.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").unwrap();
    c.write_all(&frame(0x4, 0, 0, &[])).unwrap();
    c.write_all(&frame(0x1, 0x5, 1, &block)).unwrap();
    let (mut status, mut body) = (0, Vec::new());
    loop {
        let mut head = [0u8; 9];
        c.read_exact(&mut head).expect("a response");
        let len = u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize;
        let stream = u32::from_be_bytes([head[5], head[6], head[7], head[8]]) & 0x7fff_ffff;
        let mut payload = vec![0; len];
        c.read_exact(&mut payload).unwrap();
        let (kind, flags) = (head[3], head[4]);
        if stream != 1 {
            continue;
        }
        match kind {
            0x1 => {
                // `:status` 200 and 400 are in the static table (8, 12).
                status = match payload.first() {
                    Some(0x88) => 200,
                    Some(0x8c) => 400,
                    _ => panic!("status other than 200 or 400: {payload:x?}"),
                };
            }
            0x0 => body.extend_from_slice(&payload),
            0x3 => panic!("RST_STREAM"),
            _ => {}
        }
        // END_STREAM on HEADERS or DATA.
        if kind <= 0x1 && flags & 0x1 != 0 {
            return (status, String::from_utf8_lossy(&body).into_owned());
        }
    }
}

/// `:authority` and a `Host` that differs: 400, as nginx since 1.29.1
/// (ngx_http_v2_run_request), from the server `:authority` names, whose
/// `error_page` applies. Equal values, or either field alone, are served.
#[test]
fn authority_and_a_different_host_are_refused() {
    let setup = common::ports::setup_lock();
    let [port] = common::ports::free_ports();
    let s = start("authority", setup, |dir| {
        std::fs::write(dir.join("html/e400.html"), "custom 400\n").unwrap();
        format!(
            "server {{ listen 127.0.0.1:{port}; http2 on; server_name a.test; root {d}/html;\n\
               error_page 400 /e400.html;\n\
               location / {{ return 200 \"a $http_host\\n\"; }}\n\
               location = /e400.html {{ }} }}\n\
             server {{ listen 127.0.0.1:{port}; http2 on; server_name b.test;\n\
               location / {{ return 200 \"b $http_host\\n\"; }} }}",
            d = dir.display()
        )
    });

    let (status, body) = h2_get(port, Some("a.test"), Some("b.test"));
    assert_eq!((status, body.as_str()), (400, "custom 400\n"));
    let (status, body) = h2_get(port, Some("b.test"), Some("a.test"));
    assert_eq!(status, 400);
    assert!(body.contains("400 Bad Request"), "{body}");
    // Compared as sent, as nginx's memcmp: case and port count.
    assert_eq!(h2_get(port, Some("a.test"), Some("A.test")).0, 400);
    assert_eq!(h2_get(port, Some("a.test"), Some("a.test:80")).0, 400);

    let ok = (200, "b b.test\n".to_string());
    assert_eq!(h2_get(port, Some("b.test"), Some("b.test")), ok);
    assert_eq!(h2_get(port, Some("b.test"), None), ok);
    assert_eq!(h2_get(port, None, Some("b.test")), ok);

    let errors = std::fs::read_to_string(s.dir.join("error.log")).unwrap();
    assert!(
        errors.lines().any(|l| l.contains("[info] ")
            && l.contains("client sent \":authority\" and \"Host\" headers with different values")),
        "{errors}"
    );
    let log = std::fs::read_to_string(s.dir.join("access.log")).unwrap();
    assert!(log.contains("\"GET / HTTP/2.0\" 400"), "{log}");
}

/// GET `/` with `:authority` `a` and these fields (literals without
/// indexing, of any length) on a connection of its own: the response's
/// status, or the GOAWAY's error code.
fn h2_fields(port: u16, fields: &[(&str, &str)]) -> Result<u16, u32> {
    use std::io::{Read, Write};
    fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
        let mut f = (payload.len() as u32).to_be_bytes()[1..].to_vec();
        f.extend_from_slice(&[kind, flags]);
        f.extend_from_slice(&stream.to_be_bytes());
        f.extend_from_slice(payload);
        f
    }
    // A string literal, its length a 7-bit prefix integer (RFC 7541, 5.1).
    fn string(block: &mut Vec<u8>, s: &str) {
        let mut n = s.len();
        if n < 127 {
            block.push(n as u8);
        } else {
            block.push(127);
            n -= 127;
            while n >= 128 {
                block.push((n % 128) as u8 | 0x80);
                n /= 128;
            }
            block.push(n as u8);
        }
        block.extend_from_slice(s.as_bytes());
    }
    // :method GET, :scheme http, :path / (static table 2, 6, 4), then
    // :authority a, its name from the static table (1).
    let mut block = vec![0x82, 0x86, 0x84, 0x01];
    string(&mut block, "a");
    for (name, value) in fields {
        block.push(0x00);
        string(&mut block, name);
        string(&mut block, value);
    }
    let mut c = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    c.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").unwrap();
    c.write_all(&frame(0x4, 0, 0, &[])).unwrap();
    c.write_all(&frame(0x1, 0x5, 1, &block)).unwrap();
    loop {
        let mut head = [0u8; 9];
        c.read_exact(&mut head).expect("a response or GOAWAY");
        let len = u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize;
        let mut payload = vec![0; len];
        c.read_exact(&mut payload).unwrap();
        match head[3] {
            // `:status` 200 and 400 are in the static table (8, 12).
            0x1 => {
                return Ok(match payload.first() {
                    Some(0x88) => 200,
                    Some(0x8c) => 400,
                    _ => panic!("status other than 200 or 400: {payload:x?}"),
                });
            }
            0x7 => return Err(u32::from_be_bytes(payload[4..8].try_into().unwrap())),
            _ => {}
        }
    }
}

/// `large_client_header_buffers` on HTTP/2 (#623), as
/// ngx_http_v2_state_field_len and ngx_http_v2_state_process_header: a
/// name or value over the buffer size, or names and values together
/// (pseudo-headers included) over size × number, end the connection with
/// GOAWAY ENHANCE_YOUR_CALM. The rebuilt head's lines aren't checked: two
/// `cookie` fields within the size are served, though joined they aren't.
#[test]
fn large_client_header_buffers_bound_fields_and_the_list() {
    const ENHANCE_YOUR_CALM: u32 = 0xb;
    let setup = common::ports::setup_lock();
    let [field, list] = common::ports::free_ports();
    let s = start("header-limits", setup, |_| {
        format!(
            "server {{ listen 127.0.0.1:{field}; http2 on; large_client_header_buffers 4 512;\n\
               location / {{ return 200; }} }}\n\
             server {{ listen 127.0.0.1:{list}; http2 on; large_client_header_buffers 1 512;\n\
               location / {{ return 200; }} }}"
        )
    });

    let x = |n| "x".repeat(n);
    assert_eq!(h2_fields(field, &[(&x(512), "v")]), Ok(200));
    assert_eq!(h2_fields(field, &[("n", &x(512))]), Ok(200));
    assert_eq!(h2_fields(field, &[(&x(513), "v")]), Err(ENHANCE_YOUR_CALM));
    assert_eq!(h2_fields(field, &[("n", &x(513))]), Err(ENHANCE_YOUR_CALM));
    let (a, b) = (format!("a={}", x(300)), format!("b={}", x(300)));
    assert_eq!(h2_fields(field, &[("cookie", &a), ("cookie", &b)]), Ok(200));

    // :method GET 10, :scheme http 11, :path / 6, :authority a 11, and
    // `longname` 8: 46 bytes before the value.
    assert_eq!(h2_fields(list, &[("longname", &x(466))]), Ok(200));
    assert_eq!(
        h2_fields(list, &[("longname", &x(467))]),
        Err(ENHANCE_YOUR_CALM)
    );

    let errors = std::fs::read_to_string(s.dir.join("error.log")).unwrap();
    for message in [
        "client sent too large header field while processing HTTP/2 connection",
        "client sent too large header while processing HTTP/2 connection",
    ] {
        assert!(
            errors
                .lines()
                .any(|l| l.contains("[info] ") && l.contains(message)),
            "{errors}"
        );
    }
}

/// A stream whose body nothing reads gets its response at once, then
/// RST_STREAM NO_ERROR, which asks the client to stop sending, as nginx's
/// ngx_http_v2_close_stream (#627): the body is never waited for.
#[test]
fn a_body_nothing_reads_is_reset_with_no_error_after_the_response() {
    use std::io::{Read, Write};
    let setup = common::ports::setup_lock();
    let [port] = common::ports::free_ports();
    let _s = start("discard", setup, |_| {
        format!("server {{ listen 127.0.0.1:{port}; http2 on; location / {{ return 200 ok; }} }}")
    });
    fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
        let mut f = (payload.len() as u32).to_be_bytes()[1..].to_vec();
        f.extend_from_slice(&[kind, flags]);
        f.extend_from_slice(&stream.to_be_bytes());
        f.extend_from_slice(payload);
        f
    }
    let mut c = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    c.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").unwrap();
    c.write_all(&frame(0x4, 0, 0, &[])).unwrap();
    // POST / with :authority a, END_HEADERS only: a body is to follow.
    c.write_all(&frame(0x1, 0x4, 1, &[0x83, 0x86, 0x84, 0x01, 1, b'a']))
        .unwrap();
    let (mut status, mut reset) = (None, None);
    while reset.is_none() {
        let mut head = [0u8; 9];
        c.read_exact(&mut head).expect("a frame");
        let len = u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize;
        let stream = u32::from_be_bytes([head[5], head[6], head[7], head[8]]) & 0x7fff_ffff;
        let mut payload = vec![0; len];
        c.read_exact(&mut payload).unwrap();
        match (head[3], stream) {
            (0x1, 1) => status = payload.first().copied(),
            (0x3, 1) => reset = Some(u32::from_be_bytes(payload[..4].try_into().unwrap())),
            _ => {}
        }
    }
    // `:status` 200 is static-table entry 8.
    assert_eq!(status, Some(0x88));
    assert_eq!(reset, Some(0), "RST_STREAM NO_ERROR");
}
