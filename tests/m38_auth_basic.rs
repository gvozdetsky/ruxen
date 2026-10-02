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
    let guard = SETUP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    (port, guard)
}

fn unique_dir() -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "ruxen-m38-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir(&dir).unwrap();
    dir
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
    spawn_server_with_args(conf_body, &[])
}

/// `extra_args` go before `-c`, e.g. `["-p", "/some/prefix/"]`.
fn spawn_server_with_args(conf_body: &str, extra_args: &[&str]) -> (ServerGuard, u16, PathBuf) {
    let (port, _lock) = pick_port();
    let dir = unique_dir();
    let conf_path = dir.join("ruxen.conf");
    std::fs::write(
        &conf_path,
        conf_body
            .replace("%%PORT%%", &port.to_string())
            .replace("%%DIR%%", dir.to_str().unwrap()),
    )
    .unwrap();

    let child = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .args(extra_args)
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

fn http_get(port: u16, path: &str, extra_headers: &[(&str, &str)]) -> Vec<u8> {
    let mut req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n");
    for (name, value) in extra_headers {
        req.push_str(name);
        req.push_str(": ");
        req.push_str(value);
        req.push_str("\r\n");
    }
    req.push_str("\r\n");

    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream.write_all(req.as_bytes()).unwrap();
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(_) => break,
        }
    }
    out
}

fn status(resp: &[u8]) -> u16 {
    if resp.len() < 12 {
        return 0;
    }
    let d = &resp[9..12];
    if !d.iter().all(|b| b.is_ascii_digit()) {
        return 0;
    }
    ((d[0] - b'0') as u16) * 100 + ((d[1] - b'0') as u16) * 10 + (d[2] - b'0') as u16
}

fn header(resp: &[u8], name: &str) -> Option<String> {
    let head_end = resp.windows(4).position(|w| w == b"\r\n\r\n")?;
    let text = std::str::from_utf8(&resp[..head_end]).ok()?;
    for line in text.split("\r\n").skip(1) {
        let (k, v) = line.split_once(':')?;
        if k.eq_ignore_ascii_case(name) {
            return Some(v.trim().to_string());
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

fn write_htpasswd(path: &std::path::Path) {
    std::fs::write(
        path,
        concat!(
            "# users\n",
            "alice:{PLAIN}secret\n",
            "bob:{SHA}5en6G6MezRroT3XKqkdPOmY/BfQ=\n",
            "carol:$apr1$salt$VEpBc9VHGUKwI9.yg13Iu0\n",
            "dave:$1$salt$ez2vlPGdaLYkJam5pWs/Y1\n",
        ),
    )
    .unwrap();
}

/// Static file served through the content phase. Auth tests need a content
/// handler: a location `return` answers in nginx's rewrite phase, before
/// access control runs.
fn write_ok_file(dir: &std::path::Path) {
    std::fs::write(dir.join("ok.txt"), "ok").unwrap();
}

#[test]
fn missing_and_malformed_authorization_get_401_with_realm_header() {
    let conf = r#"
events {}
http {
  server {
    listen 127.0.0.1:%%PORT%%;
    auth_basic "Admin Zone";
    auth_basic_user_file %%DIR%%/users.htpasswd;
    location / { root %%DIR%%; }
  }
}
"#;
    let (_guard, port, dir) = spawn_server(conf);
    write_htpasswd(&dir.join("users.htpasswd"));
    write_ok_file(&dir);

    let no_header = http_get(port, "/ok.txt", &[]);
    assert_eq!(status(&no_header), 401);
    assert_eq!(
        header(&no_header, "WWW-Authenticate").as_deref(),
        Some(r#"Basic realm="Admin Zone""#)
    );

    let bad_b64 = http_get(port, "/ok.txt", &[("Authorization", "Basic !!!")]);
    assert_eq!(status(&bad_b64), 401);
    assert_eq!(
        header(&bad_b64, "WWW-Authenticate").as_deref(),
        Some(r#"Basic realm="Admin Zone""#)
    );
}

#[test]
fn plain_sha_apr1_and_md5_crypt_entries_authenticate() {
    let conf = r#"
events {}
http {
  server {
    listen 127.0.0.1:%%PORT%%;
    auth_basic "Ruxen";
    auth_basic_user_file %%DIR%%/users.htpasswd;
    location / { root %%DIR%%; }
  }
}
"#;
    let (_guard, port, dir) = spawn_server(conf);
    write_htpasswd(&dir.join("users.htpasswd"));
    write_ok_file(&dir);

    let alice = http_get(
        port,
        "/ok.txt",
        &[("Authorization", "Basic YWxpY2U6c2VjcmV0")],
    );
    assert_eq!(status(&alice), 200);
    assert_eq!(body(&alice), b"ok");

    let bob = http_get(
        port,
        "/ok.txt",
        &[("Authorization", "Basic Ym9iOnNlY3JldA==")],
    );
    assert_eq!(status(&bob), 200);

    let carol = http_get(
        port,
        "/ok.txt",
        &[("Authorization", "Basic Y2Fyb2w6c2VjcmV0")],
    );
    assert_eq!(status(&carol), 200);

    let dave = http_get(
        port,
        "/ok.txt",
        &[("Authorization", "Basic ZGF2ZTpzZWNyZXQ=")],
    );
    assert_eq!(status(&dave), 200);

    let wrong = http_get(
        port,
        "/ok.txt",
        &[("Authorization", "Basic YWxpY2U6d3Jvbmc=")],
    );
    assert_eq!(status(&wrong), 401);
}

#[test]
fn auth_basic_off_overrides_parent_scope() {
    let conf = r#"
events {}
http {
  auth_basic "Parent";
  auth_basic_user_file %%DIR%%/users.htpasswd;
  server {
    listen 127.0.0.1:%%PORT%%;
    root %%DIR%%;
    location /secure/ { }
    location /open/ {
      auth_basic off;
    }
  }
}
"#;
    let (_guard, port, dir) = spawn_server(conf);
    write_htpasswd(&dir.join("users.htpasswd"));
    for sub in ["secure", "open"] {
        std::fs::create_dir(dir.join(sub)).unwrap();
        write_ok_file(&dir.join(sub));
    }

    let secure = http_get(port, "/secure/ok.txt", &[]);
    assert_eq!(status(&secure), 401);

    let open = http_get(port, "/open/ok.txt", &[]);
    assert_eq!(status(&open), 200);
    assert_eq!(body(&open), b"ok");
}

#[test]
fn remote_user_is_available_in_access_log_rendering() {
    let conf = r#"
events {}
http {
  log_format userfmt "$remote_user";
  access_log %%DIR%%/access.log userfmt;
  server {
    listen 127.0.0.1:%%PORT%%;
    auth_basic "Logs";
    auth_basic_user_file %%DIR%%/users.htpasswd;
    location / { return 200 "ok"; }
  }
}
"#;
    let (_guard, port, dir) = spawn_server(conf);
    write_htpasswd(&dir.join("users.htpasswd"));

    let resp = http_get(port, "/", &[("Authorization", "Basic YWxpY2U6c2VjcmV0")]);
    assert_eq!(status(&resp), 200);

    sleep(Duration::from_millis(50));
    let logged = std::fs::read_to_string(dir.join("access.log")).unwrap();
    assert_eq!(logged, "alice\n");
}

#[test]
fn return_answers_in_rewrite_phase_before_auth_basic() {
    // nginx: `return` is a rewrite-module directive, so it responds before
    // the access phase and auth_basic never runs. A `break` ends the rewrite
    // program before the `return` is reached, so access control does run.
    let conf = r#"
events {}
http {
  server {
    listen 127.0.0.1:%%PORT%%;
    auth_basic "Zone";
    auth_basic_user_file %%DIR%%/users.htpasswd;
    location /ret { return 200 "ret"; }
    location /brk {
      break;
      return 200 "brk";
    }
    location /if {
      if ($arg_x) { return 200 "if"; }
      return 200 "after-if";
    }
  }
}
"#;
    let (_guard, port, dir) = spawn_server(conf);
    write_htpasswd(&dir.join("users.htpasswd"));

    let ret = http_get(port, "/ret", &[]);
    assert_eq!(status(&ret), 200);
    assert_eq!(body(&ret), b"ret");

    let brk = http_get(port, "/brk", &[]);
    assert_eq!(status(&brk), 401);

    let in_if = http_get(port, "/if?x=1", &[]);
    assert_eq!(status(&in_if), 200);
    assert_eq!(body(&in_if), b"if");

    let after_if = http_get(port, "/if", &[]);
    assert_eq!(status(&after_if), 200);
    assert_eq!(body(&after_if), b"after-if");
}

#[test]
fn relative_user_file_resolves_against_config_dir_not_prefix() {
    // The config lives in %%DIR%%; the `-p` prefix is a different, empty
    // directory. nginx resolves auth_basic_user_file against the config
    // directory (conf prefix), for literal and variable paths alike.
    let conf = r#"
events {}
http {
  server {
    listen 127.0.0.1:%%PORT%%;
    root %%DIR%%;
    location /lit/ {
      auth_basic "Lit";
      auth_basic_user_file users.htpasswd;
    }
    location /var/ {
      auth_basic "Var";
      auth_basic_user_file $arg_f;
    }
  }
}
"#;
    let prefix = unique_dir();
    let prefix_arg = format!("{}/", prefix.display());
    let (_guard, port, dir) = spawn_server_with_args(conf, &["-p", &prefix_arg]);
    write_htpasswd(&dir.join("users.htpasswd"));
    for sub in ["lit", "var"] {
        std::fs::create_dir(dir.join(sub)).unwrap();
        write_ok_file(&dir.join(sub));
    }
    let alice = [("Authorization", "Basic YWxpY2U6c2VjcmV0")];

    let lit = http_get(port, "/lit/ok.txt", &alice);
    assert_eq!(status(&lit), 200);
    assert_eq!(body(&lit), b"ok");
    assert_eq!(status(&http_get(port, "/lit/ok.txt", &[])), 401);

    let var = http_get(port, "/var/ok.txt?f=users.htpasswd", &alice);
    assert_eq!(status(&var), 200);
    assert_eq!(body(&var), b"ok");

    let _ = std::fs::remove_dir_all(&prefix);
}
