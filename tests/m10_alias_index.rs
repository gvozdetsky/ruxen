use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, MutexGuard};
use std::thread::sleep;
use std::time::{Duration, Instant};

struct ServerGuard {
    child: Child,
    tempdir: PathBuf,
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.tempdir);
    }
}

// See the SETUP_LOCK comment in tests/file_serving.rs for why port picking
// has to be serialized against the spawn + readiness-check of the previous
// setup.
static SETUP_LOCK: Mutex<()> = Mutex::new(());

fn pick_port() -> (u16, MutexGuard<'static, ()>) {
    let g = SETUP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let p = l.local_addr().unwrap().port();
    drop(l);
    (p, g)
}

fn unique_dir() -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let d = std::env::temp_dir().join(format!(
        "ruxen-m10-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir(&d).unwrap();
    d
}

fn wait_for_listen(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        if Instant::now() > deadline {
            panic!("ruxen did not start listening on port {port}");
        }
        sleep(Duration::from_millis(20));
    }
}

fn spawn_server(conf: &str) -> (ServerGuard, u16) {
    let (port, _lock) = pick_port();
    let dir = unique_dir();
    std::fs::write(dir.join("index.html"), b"body").unwrap();
    std::fs::write(dir.join("many.html"), b"manybody").unwrap();
    std::fs::write(dir.join("re.html"), b"rebody").unwrap();
    std::fs::write(dir.join("localhost.html"), b"varbody").unwrap();
    std::fs::write(dir.join("exact.txt"), b"exactbody").unwrap();

    let conf_path = dir.join("nginx.conf");
    let conf = conf
        .replace("%%PORT%%", &port.to_string())
        .replace("%%TESTDIR%%", dir.to_str().unwrap());
    std::fs::write(&conf_path, conf).unwrap();

    let child = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .args(["-c", conf_path.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ruxen");

    wait_for_listen(port);
    (
        ServerGuard {
            child,
            tempdir: dir,
        },
        port,
    )
}

fn http_get(port: u16, path: &str) -> Vec<u8> {
    let req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    s.write_all(req.as_bytes()).unwrap();
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match s.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(_) => break,
        }
    }
    out
}

fn status_line(resp: &[u8]) -> &str {
    let end = resp.iter().position(|&b| b == b'\r').unwrap_or(resp.len());
    std::str::from_utf8(&resp[..end]).unwrap()
}

fn header_value<'a>(resp: &'a [u8], name: &str) -> Option<&'a str> {
    let s = std::str::from_utf8(resp).ok()?;
    let header_end = s.find("\r\n\r\n").unwrap_or(s.len());
    for line in s[..header_end].split("\r\n").skip(1) {
        if let Some((k, v)) = line.split_once(':') {
            if k.eq_ignore_ascii_case(name) {
                return Some(v.trim());
            }
        }
    }
    None
}

fn body(resp: &[u8]) -> &[u8] {
    resp.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| &resp[i + 4..])
        .unwrap_or(&[])
}

const M10_CONF: &str = r#"
daemon off;

events { }

http {
    server {
        listen       127.0.0.1:%%PORT%%;
        server_name  localhost;
        add_header   X-URI $uri;

        location / {
            root %%TESTDIR%%;
        }

        location /redirect/ {
            root %%TESTDIR%%;
            index /re.html;
        }

        location /loop/ {
            root %%TESTDIR%%;
            index /loop/;
        }

        location /many/ {
            alias %%TESTDIR%%/;
            index nonexisting.html many.html;
        }

        location /var/ {
            alias %%TESTDIR%%/;
            index $server_name.html;
        }

        location /va2/ {
            alias %%TESTDIR%%/;
            index ${server_name}.html;
        }

        location = /exact.txt {
            alias %%TESTDIR%%/exact.txt;
        }
    }
}
"#;

#[test]
fn m10_alias_and_index_parity_matches_core_index_t_cases() {
    let (_g, port) = spawn_server(M10_CONF);

    let cases: &[(&str, &str, &[u8])] = &[
        ("/", "/index.html", b"body"),
        ("/many/", "/many/many.html", b"manybody"),
        ("/var/", "/var/localhost.html", b"varbody"),
        ("/va2/", "/va2/localhost.html", b"varbody"),
        ("/redirect/", "/re.html", b"rebody"),
        ("/exact.txt", "/exact.txt", b"exactbody"),
    ];

    for (path, expected_uri, expected_body) in cases {
        let resp = http_get(port, path);
        assert_eq!(status_line(&resp), "HTTP/1.1 200 OK", "GET {path}");
        assert_eq!(
            header_value(&resp, "X-URI"),
            Some(*expected_uri),
            "GET {path}: wrong X-URI"
        );
        assert_eq!(body(&resp), *expected_body, "GET {path}: wrong body");
    }

    let looped = http_get(port, "/loop/");
    assert_eq!(status_line(&looped), "HTTP/1.1 500 Internal Server Error");
}
