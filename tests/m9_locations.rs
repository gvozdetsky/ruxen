// M9 end-to-end: regex (`~`, `~*`) and `^~` location modifiers.
//
// Mirrors the cases in upstream nginx-tests/http_location.t against a
// live ruxen binary so the precedence ladder is checked through the
// real parser/prepare/match path, not just unit tests on `match_location`.

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
        "ruxen-m9-{}-{}",
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
    let conf_path = dir.join("nginx.conf");
    std::fs::write(&conf_path, conf.replace("%%PORT%%", &port.to_string())).unwrap();

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

const M9_CONF: &str = r#"
daemon off;

events { }

http {
    server {
        listen       127.0.0.1:%%PORT%%;
        server_name  localhost;

        location = / {
            add_header X-Location exactlyroot;
            return 204;
        }

        location / {
            add_header X-Location root;
            return 204;
        }

        location ^~ /images/ {
            add_header X-Location images;
            return 204;
        }

        location ~* \.(gif|jpg|jpeg)$ {
            add_header X-Location regex;
            return 204;
        }

        location ~ casefull {
            add_header X-Location casefull;
            return 204;
        }

        location = /foo {
            add_header X-Location "/foo exact";
            return 204;
        }

        location /foo {
            add_header X-Location "/foo prefix";
            return 204;
        }

        location = /foo/ {
            add_header X-Location "/foo/ exact";
            return 204;
        }

        location /foo/ {
            add_header X-Location "/foo/ prefix";
            return 204;
        }

        location /lowercase {
            add_header X-Location lowercase;
            return 204;
        }

        location /UPPERCASE {
            add_header X-Location uppercase;
            return 204;
        }
    }
}
"#;

#[test]
fn m9_location_precedence_matches_http_location_t() {
    let (_g, port) = spawn_server(M9_CONF);

    // Each tuple maps directly to one `like(http_get('...'), qr/.../, '...')`
    // line in upstream `http_location.t`. Keep the same order so future
    // drift is easy to spot.
    let cases: &[(&str, &str)] = &[
        ("/", "exactlyroot"),
        ("/x", "root"),
        ("/images/t.gif", "images"),
        ("/t.gif", "regex"),
        ("/t.GIF", "regex"),
        ("/casefull/t.gif", "regex"),
        ("/casefull/", "casefull"),
        ("/foo", "/foo exact"),
        ("/foobar", "/foo prefix"),
        ("/foo/", "/foo/ exact"),
        ("/foo/bar", "/foo/ prefix"),
        ("/CASEFULL/", "root"),
        ("/lowercase", "lowercase"),
        ("/UPPERCASE", "uppercase"),
    ];

    for (path, expected) in cases {
        let resp = http_get(port, path);
        let got = header_value(&resp, "X-Location").unwrap_or_else(|| {
            panic!(
                "GET {path}: no X-Location header in response:\n{}",
                String::from_utf8_lossy(&resp)
            )
        });
        assert_eq!(got, *expected, "GET {path}: wrong X-Location");
    }
}
