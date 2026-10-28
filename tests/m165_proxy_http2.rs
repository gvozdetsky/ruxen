//! M165 — `proxy_http_version 2` (#599): HTTP/2 to the upstream, h2c by
//! prior knowledge for `http://`, ALPN `h2` for `https://`, one stream at a
//! time on a connection the keep-alive pool reuses. The upstream is an
//! HTTP/2 server block of the same ruxen, which proxies `/echo` on to a
//! plain HTTP/1.1 backend here that answers with the request's body.

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

struct Server {
    child: common::KillOnDrop,
    dir: PathBuf,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.0.kill();
        let _ = self.child.0.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// An HTTP/1.1 backend: answers each request with its method, the body it
/// got, and `X-A`; `/stream` sends the answer in two writes, chunked.
fn echo_backend(listener: TcpListener) {
    std::thread::spawn(move || {
        for conn in listener.incoming().flatten() {
            std::thread::spawn(move || {
                let mut w = conn.try_clone().unwrap();
                let mut r = BufReader::new(conn);
                loop {
                    let mut head = Vec::new();
                    loop {
                        let mut line = String::new();
                        if r.read_line(&mut line).unwrap_or(0) == 0 {
                            return;
                        }
                        if line == "\r\n" {
                            break;
                        }
                        head.push(line);
                    }
                    let field = |name: &str| {
                        head.iter().find_map(|l| {
                            let (n, v) = l.split_once(':')?;
                            n.eq_ignore_ascii_case(name).then(|| v.trim().to_string())
                        })
                    };
                    let len: usize = field("content-length").map_or(0, |v| v.parse().unwrap());
                    let mut body = vec![0; len];
                    r.read_exact(&mut body).unwrap();
                    let method = head[0].split(' ').next().unwrap().to_string();
                    let answer = format!(
                        "{method}|{}|{}",
                        String::from_utf8_lossy(&body),
                        field("x-a").unwrap_or_default()
                    );
                    if head[0].contains(" /stream ") {
                        let _ = write!(
                            w,
                            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{answer}\r\n",
                            answer.len()
                        );
                        std::thread::sleep(Duration::from_millis(200));
                        let _ = w.write_all(b"4\r\n|end\r\n0\r\n\r\n");
                    } else {
                        let _ = write!(
                            w,
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{answer}",
                            answer.len()
                        );
                    }
                }
            });
        }
    });
}

fn start(conf: String) -> Server {
    let dir = std::env::temp_dir().join(format!("ruxen-m165-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::create_dir_all(dir.join("html")).unwrap();
    let big: Vec<u8> = (0..300_000u32).map(|i| b'a' + (i % 26) as u8).collect();
    std::fs::write(dir.join("html/big.txt"), &big).unwrap();
    std::fs::write(dir.join("html/index.html"), "SEE-THIS").unwrap();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "pid {d}/ruxen.pid;\nerror_log {d}/error.log info;\nevents {{}}\n\
             http {{\naccess_log off;\nroot {d}/html;\n{conf}\n}}\n",
            d = dir.display(),
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
    Server { child, dir }
}

/// One request with `Connection: close`: (status, head, body).
fn request(port: u16, raw: &str) -> (u16, String, Vec<u8>) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.write_all(raw.as_bytes()).unwrap();
    let mut out = Vec::new();
    s.read_to_end(&mut out).unwrap();
    let at = out
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("a response head");
    let head = String::from_utf8_lossy(&out[..at]).into_owned();
    let status = head.get(9..12).and_then(|s| s.parse().ok()).unwrap_or(0);
    (status, head, out[at + 4..].to_vec())
}

fn get(port: u16, path: &str) -> (u16, String, Vec<u8>) {
    request(
        port,
        &format!("GET {path} HTTP/1.1\r\nHost: front\r\nConnection: close\r\n\r\n"),
    )
}

fn text(body: &[u8]) -> String {
    String::from_utf8_lossy(body).into_owned()
}

/// A chunked body's data.
fn dechunk(mut body: &[u8]) -> String {
    let mut out = Vec::new();
    loop {
        let at = body.windows(2).position(|w| w == b"\r\n").unwrap();
        let len = usize::from_str_radix(std::str::from_utf8(&body[..at]).unwrap(), 16).unwrap();
        if len == 0 {
            return text(&out);
        }
        out.extend_from_slice(&body[at + 2..at + 2 + len]);
        body = &body[at + 4 + len..];
    }
}

#[test]
fn proxy_http_version_2() {
    let cert = common::tls::make_self_signed("backend.test");
    let setup = common::ports::setup_lock();
    let echo = TcpListener::bind("127.0.0.1:0").unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    echo_backend(echo);
    let [front, h2c, h2tls] = common::ports::free_ports();
    let s = start(format!(
        "upstream u {{ server 127.0.0.1:{h2c}; keepalive 4; }}\n\
         server {{ listen 127.0.0.1:{h2c}; http2 on;\n\
           location /info {{ return 200 \"$server_protocol|$connection_requests|$host|$http_te\"; }}\n\
           location /echo {{ proxy_pass http://127.0.0.1:{echo_port}; }}\n\
           location /stream {{ proxy_pass http://127.0.0.1:{echo_port}; }} }}\n\
         server {{ listen 127.0.0.1:{h2tls} ssl; http2 on;\n\
           ssl_certificate {cert}; ssl_certificate_key {key};\n\
           location / {{ return 200 \"$server_protocol|$ssl_protocol\"; }} }}\n\
         server {{ listen 127.0.0.1:{front};\n\
           proxy_http_version 2;\n\
           location / {{ proxy_pass http://u; }}\n\
           location /nobuf/ {{ proxy_pass http://u/; proxy_buffering off; }}\n\
           location /host/ {{ proxy_pass http://u/; proxy_set_header Host example.org; }}\n\
           location /tls/ {{ proxy_pass https://127.0.0.1:{h2tls}/; }} }}",
        cert = cert.cert_path().display(),
        key = cert.key_path().display(),
    ));
    drop(setup);

    // HTTP/2 upstream, `:authority` the proxy_pass host, `TE` not passed;
    // the second request reuses the connection.
    let (status, _, body) = request(
        front,
        "GET /info HTTP/1.1\r\nHost: front\r\nTE: trailers\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status, 200);
    assert_eq!(text(&body), "HTTP/2.0|1|u|");
    let (_, _, body) = get(front, "/info");
    assert_eq!(text(&body), "HTTP/2.0|2|u|");
    // proxy_set_header Host goes as `host`.
    let (_, _, body) = get(front, "/host/info");
    assert_eq!(text(&body), "HTTP/2.0|3|example.org|");

    // A request body, and the client's headers.
    let (status, _, body) = request(
        front,
        "POST /echo HTTP/1.1\r\nHost: front\r\nX-A: aa\r\nContent-Length: 5\r\n\
         Connection: close\r\n\r\nhello",
    );
    assert_eq!(status, 200);
    assert_eq!(text(&body), "POST|hello|aa");
    let big = "x".repeat(200_000);
    let (status, _, body) = request(
        front,
        &format!(
            "PUT /echo HTTP/1.1\r\nHost: front\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n{big}",
            big.len()
        ),
    );
    assert_eq!(status, 200);
    assert_eq!(text(&body), format!("PUT|{big}|"));

    // A body without a length (the upstream's DATA as it came), buffered
    // and relayed.
    for path in ["/stream", "/nobuf/stream"] {
        let (status, head, body) = get(front, path);
        assert_eq!(status, 200, "{path}");
        assert!(
            head.contains("Transfer-Encoding: chunked"),
            "{path}: {head}"
        );
        assert_eq!(dechunk(&body), "GET|||end", "{path}");
    }

    // A body over the flow-control windows, buffered and relayed.
    let expect: Vec<u8> = (0..300_000u32).map(|i| b'a' + (i % 26) as u8).collect();
    for path in ["/big.txt", "/nobuf/big.txt"] {
        let (status, _, body) = get(front, path);
        assert_eq!(status, 200, "{path}");
        assert!(body == expect, "{path}: {} bytes", body.len());
    }

    // HEAD: the length, no body.
    let (status, head, body) = request(
        front,
        "HEAD /big.txt HTTP/1.1\r\nHost: front\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status, 200);
    assert!(
        head.to_ascii_lowercase().contains("content-length: 300000"),
        "{head}"
    );
    assert!(body.is_empty());

    // 404 from the upstream passes.
    let (status, _, _) = get(front, "/none");
    assert_eq!(status, 404);

    // Over TLS, ALPN gets HTTP/2.
    let (status, _, body) = get(front, "/tls/");
    assert_eq!(status, 200);
    assert!(
        text(&body).starts_with("HTTP/2.0|TLSv1."),
        "{}",
        text(&body)
    );

    drop(s);
}
