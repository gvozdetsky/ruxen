//! M44 — relative `include`, `ssl_certificate`, and `ssl_certificate_key`
//! paths resolve against the main config's directory (nginx's conf prefix),
//! not the `-p` prefix. Every test runs ruxen with `-p` pointing at an empty
//! directory that differs from the config directory, so a cwd-relative
//! lookup fails loudly.

mod common;

use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, MutexGuard};
use std::thread::sleep;
use std::time::{Duration, Instant};

struct ServerGuard {
    child: Child,
    dirs: Vec<PathBuf>,
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        for d in &self.dirs {
            let _ = std::fs::remove_dir_all(d);
        }
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

fn unique_dir(tag: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "ruxen-m44-{tag}-{}-{}",
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

fn write(path: &Path, contents: &str) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, contents).unwrap();
}

fn prefix_arg(prefix: &Path) -> String {
    format!("{}/", prefix.display())
}

#[test]
fn include_and_ssl_paths_resolve_against_config_dir() {
    let certs = common::tls::make_self_signed("localhost");
    let conf_dir = unique_dir("conf");
    let prefix = unique_dir("prefix");

    std::fs::create_dir(conf_dir.join("certs")).unwrap();
    std::fs::copy(certs.cert_path(), conf_dir.join("certs/cert.pem")).unwrap();
    std::fs::copy(certs.key_path(), conf_dir.join("certs/key.pem")).unwrap();

    let (port, _lock) = pick_port();
    write(
        &conf_dir.join("nginx.conf"),
        &format!("pid {}/ruxen.pid;\nevents {{}}\nhttp {{\n  include conf.d/server.conf;\n}}\n", conf_dir.display()),
    );
    // The nested include is written relative to the config directory, not
    // to conf.d/ — nginx resolves every include against the conf prefix.
    write(
        &conf_dir.join("conf.d/server.conf"),
        &format!(
            r#"server {{
  listen 127.0.0.1:{port} ssl;
  ssl_certificate certs/cert.pem;
  ssl_certificate_key certs/key.pem;
  include conf.d/locations.conf;
}}
"#
        ),
    );
    write(
        &conf_dir.join("conf.d/locations.conf"),
        "location / { return 200 \"tls-ok\"; }\n",
    );

    let child = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .args(["-p", &prefix_arg(&prefix), "-c"])
        .arg(conf_dir.join("nginx.conf"))
        .env("RUXEN_WORKERS", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ruxen");
    let _guard = ServerGuard {
        child,
        dirs: vec![conf_dir.clone(), prefix.clone()],
    };
    wait_for_listen(port);
    drop(_lock);

    let out = Command::new("curl")
        .args(["-sk", "--max-time", "5"])
        .arg(format!("https://127.0.0.1:{port}/"))
        .output()
        .expect("run curl");
    assert!(out.status.success(), "curl failed: {}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(out.stdout, b"tls-ok");
}

#[test]
fn missing_include_is_reported_under_config_dir() {
    let conf_dir = unique_dir("conf");
    let prefix = unique_dir("prefix");
    write(
        &conf_dir.join("nginx.conf"),
        "events {}\nhttp {\n  include missing.conf;\n}\n",
    );

    let out = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .args(["-p", &prefix_arg(&prefix), "-t", "-c"])
        .arg(conf_dir.join("nginx.conf"))
        .output()
        .expect("run ruxen -t");
    let stderr = String::from_utf8_lossy(&out.stderr);
    let _ = std::fs::remove_dir_all(&conf_dir);
    let _ = std::fs::remove_dir_all(&prefix);

    assert!(!out.status.success(), "-t should fail; stderr: {stderr}");
    let expected = conf_dir.join("missing.conf");
    assert!(
        stderr.contains(&expected.display().to_string()),
        "expected {} in stderr: {stderr}",
        expected.display()
    );
}
