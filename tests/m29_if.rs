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
        "ruxen-m29-{}-{}",
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

fn spawn_server(conf_body: &str) -> (ServerGuard, u16, PathBuf) {
    let (port, _lock) = pick_port();
    let dir = unique_dir();
    std::fs::write(dir.join("file"), b"x").unwrap();
    std::fs::create_dir(dir.join("dir")).unwrap();

    let conf_path = dir.join("ruxen.conf");
    std::fs::write(
        &conf_path,
        conf_body
            .replace("%%PORT%%", &port.to_string())
            .replace("%%DIR%%", dir.to_str().unwrap()),
    )
    .unwrap();

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
            tempdir: dir.clone(),
        },
        port,
        dir,
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

#[test]
fn if_conditions_run_rewrite_guards() {
    let conf = r#"
events {}
http {
  server {
    listen 127.0.0.1:%%PORT%%;

    location /truthy {
      if ($arg_c) { return 204; }
    }

    location /eq {
      if ($arg_c = 1) { return 204; }
    }

    location /regex {
      if ($arg_c ~* foo) { return 204; }
    }

    location /file {
      if (-f %%DIR%%/$arg_c) { return 204; }
    }

    location /not_exist {
      if (!-e %%DIR%%/$arg_c) { return 204; }
    }
  }
}
"#;

    let (_guard, port, _dir) = spawn_server(conf);

    assert_eq!(
        status_line(&http_get(port, "/truthy?c=1")),
        "HTTP/1.1 204 No Content"
    );
    assert_eq!(
        status_line(&http_get(port, "/truthy?c=0")),
        "HTTP/1.1 404 Not Found"
    );

    assert_eq!(
        status_line(&http_get(port, "/eq?c=1")),
        "HTTP/1.1 204 No Content"
    );
    assert_eq!(
        status_line(&http_get(port, "/eq?c=2")),
        "HTTP/1.1 404 Not Found"
    );

    assert_eq!(
        status_line(&http_get(port, "/regex?c=FooD")),
        "HTTP/1.1 204 No Content"
    );
    assert_eq!(
        status_line(&http_get(port, "/regex?c=bar")),
        "HTTP/1.1 404 Not Found"
    );

    assert_eq!(
        status_line(&http_get(port, "/file?c=file")),
        "HTTP/1.1 204 No Content"
    );
    assert_eq!(
        status_line(&http_get(port, "/file?c=missing")),
        "HTTP/1.1 404 Not Found"
    );

    assert_eq!(
        status_line(&http_get(port, "/not_exist?c=missing")),
        "HTTP/1.1 204 No Content"
    );
    assert_eq!(
        status_line(&http_get(port, "/not_exist?c=file")),
        "HTTP/1.1 404 Not Found"
    );
}

/// `if ($var = "")`: the quoted empty string is the value compared
/// against (#243). It used to be lost when the condition was rejoined
/// into one string. Checked against nginx 1.24.
#[test]
fn if_compares_against_empty_and_quoted_values() {
    let conf = r#"
events {}
http {
  server {
    listen 127.0.0.1:%%PORT%%;

    location /empty {
      if ($arg_z = "") { return 204; }
    }

    location /not_empty {
      if ( $arg_z != '' ) { return 204; }
    }

    location /paren {
      if ($arg_w = "a)") { return 204; }
    }
  }
}
"#;

    let (_guard, port, _dir) = spawn_server(conf);
    let status = |path: &str| status_line(&http_get(port, path)).to_string();

    assert_eq!(status("/empty?y=1"), "HTTP/1.1 204 No Content");
    assert_eq!(status("/empty?z="), "HTTP/1.1 204 No Content");
    assert_eq!(status("/empty?z=1"), "HTTP/1.1 404 Not Found");
    assert_eq!(status("/not_empty?z=1"), "HTTP/1.1 204 No Content");
    assert_eq!(status("/not_empty?y=1"), "HTTP/1.1 404 Not Found");
    assert_eq!(status("/paren?w=a)"), "HTTP/1.1 204 No Content");
    assert_eq!(status("/paren?w=a"), "HTTP/1.1 404 Not Found");
}
