//! M120 — HTTP/2 (#144): `http2 on` / `listen … http2`, cleartext with
//! prior knowledge (the connection preface) and over TLS through ALPN.
//! Each stream goes through the same request handling as HTTP/1.1, so
//! static files, `return`, the proxy and the access log work as they do
//! there. Checked with curl's HTTP/2 client.

mod common;

use std::net::TcpListener;
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

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
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
    let (port, backend) = (free_port(), free_port());
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
    let (port, plain) = (free_port(), free_port());
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
