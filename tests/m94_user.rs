//! M94 — `user`: started as root, ruxen serves as the configured user,
//! with a root helper for the rotated logs and the pid file.
//!
//! The switch needs root, so the root tests return early otherwise, as
//! nginx-tests skips its `must be root` files. They run in a container:
//!
//!   docker run --rm --security-opt seccomp=contrib/docker/seccomp-io_uring.json \
//!       -v "$PWD:/src" -w /src rust:1.99 cargo test --release --test m94_user
//!
//! Without root, `user` is ignored with nginx's warning; that part runs
//! everywhere.

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() == 0 }
}

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

fn temp_dir(tag: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU32, Ordering};
    static N: AtomicU32 = AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!(
        "ruxen-m94-{tag}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir).unwrap();
    // Reachable by `nobody` (the root tests' user), like a web root.
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    dir
}

/// Starts ruxen on `conf` (with `%%DIR%%` and `%%PORT%%` filled in) and
/// waits until it accepts.
fn start(tag: &str, user_line: &str, conf: &str) -> (Server, u16, PathBuf) {
    let dir = temp_dir(tag);
    // Held until ruxen listens: released earlier, another test could take
    // the same free port, and the readiness probe would reach its server.
    let setup = common::ports::setup_lock();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let conf = format!("{user_line}\n{conf}")
        .replace("%%DIR%%", dir.to_str().unwrap())
        .replace("%%PORT%%", &port.to_string());
    let conf_path = dir.join("ruxen.conf");
    std::fs::write(&conf_path, conf).unwrap();
    // Owned by `Server` before the wait: if it panics, ruxen still stops.
    let server = Server {
        child: Command::new(env!("CARGO_BIN_EXE_ruxen"))
            .args(["-c", conf_path.to_str().unwrap()])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
        dir: dir.clone(),
    };
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "ruxen did not start");
        std::thread::sleep(Duration::from_millis(20));
    }
    drop(setup);
    (server, port, dir)
}

fn get(port: u16, path: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(s, "GET {path} HTTP/1.0\r\nHost: t\r\n\r\n").unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

/// The effective uid of every thread of `pid`.
fn thread_uids(pid: u32) -> Vec<u32> {
    let mut uids = Vec::new();
    for task in std::fs::read_dir(format!("/proc/{pid}/task")).unwrap() {
        let status = std::fs::read_to_string(task.unwrap().path().join("status")).unwrap();
        let line = status.lines().find(|l| l.starts_with("Uid:")).unwrap();
        // Uid: real effective saved fs
        let ids: Vec<u32> = line[4..]
            .split_whitespace()
            .map(|v| v.parse().unwrap())
            .collect();
        uids.extend(&ids[..3]);
    }
    uids
}

const CONF: &str = r#"
worker_processes 2;
events {}
http {
    access_log %%DIR%%/access.log;
    client_body_temp_path %%DIR%%/body;
    server {
        listen 127.0.0.1:%%PORT%%;
        root %%DIR%%/www;
        location /up { return 200 "ok"; }
    }
}
"#;

fn web_root(dir: &Path) {
    let www = dir.join("www");
    std::fs::create_dir(&www).unwrap();
    std::fs::set_permissions(&www, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::write(www.join("public.txt"), "public").unwrap();
    std::fs::set_permissions(
        www.join("public.txt"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    std::fs::write(www.join("secret.txt"), "secret").unwrap();
    std::fs::set_permissions(
        www.join("secret.txt"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
}

#[test]
fn m94_root_switches_every_thread_to_the_user() {
    if !is_root() {
        return;
    }
    // The web root is made before the start, so build the files in a
    // directory of our own and point `root` at it.
    let (server, port, dir) = start("switch", "user nobody nogroup;", CONF);
    web_root(&dir);
    let pid = server.child.id();
    let nobody = 65534;
    let uids = thread_uids(pid);
    assert!(uids.iter().all(|&u| u == nobody), "uids {uids:?}");

    assert!(get(port, "/public.txt").starts_with("HTTP/1.1 200"));
    // Only root may read it: served as `nobody`, it is a 403.
    let secret = get(port, "/secret.txt");
    assert!(secret.starts_with("HTTP/1.1 403"), "{secret}");

    // Handed over at startup: the access log and the temp directory.
    let log = std::fs::metadata(dir.join("access.log")).unwrap();
    assert_eq!(log.uid(), nobody);
    let body = std::fs::metadata(dir.join("body")).unwrap();
    assert_eq!(body.uid(), nobody);
    assert_eq!(body.mode() & 0o777, 0o700);
}

#[test]
fn m94_root_defaults_to_nobody() {
    if !is_root() {
        return;
    }
    let (server, port, _dir) = start("default", "", CONF);
    assert!(get(port, "/up").starts_with("HTTP/1.1 200"));
    let uids = thread_uids(server.child.id());
    assert!(uids.iter().all(|&u| u == 65534), "uids {uids:?}");
}

#[test]
fn m94_user_root_stays_root() {
    if !is_root() {
        return;
    }
    let (server, port, _dir) = start("root", "user root;", CONF);
    assert!(get(port, "/up").starts_with("HTTP/1.1 200"));
    let uids = thread_uids(server.child.id());
    assert!(uids.iter().all(|&u| u == 0), "uids {uids:?}");
}

#[test]
fn m94_unknown_user_is_an_emerg_in_test_mode() {
    if !is_root() {
        return;
    }
    let dir = temp_dir("unknown");
    let conf = dir.join("ruxen.conf");
    std::fs::write(
        &conf,
        "user no-such-user-ruxen;\nevents {}\nhttp { server { listen 127.0.0.1:1; } }\n",
    )
    .unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .args(["-t", "-c", conf.to_str().unwrap()])
        .output()
        .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("[emerg] getpwnam(\"no-such-user-ruxen\") failed"),
        "{stderr}"
    );
}

#[test]
fn m94_not_root_ignores_user_with_a_warning() {
    if is_root() {
        return;
    }
    let (mut server, port, _dir) = start("ignored", "user nobody;", CONF);
    assert!(get(port, "/up").starts_with("HTTP/1.1 200"));
    let _ = server.child.kill();
    let _ = server.child.wait();
    let mut stderr = String::new();
    server
        .child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    assert!(
        stderr.contains(
            "[warn] the \"user\" directive makes sense only if the master process runs \
             with super-user privileges, ignored"
        ),
        "{stderr}"
    );
}

/// Child processes of `pid`, with their real uid.
fn children(pid: u32) -> Vec<(u32, u32)> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir("/proc").unwrap().flatten() {
        let Ok(child) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let Ok(status) = std::fs::read_to_string(entry.path().join("status")) else {
            continue;
        };
        let field = |name: &str| -> Option<u32> {
            let line = status.lines().find(|l| l.starts_with(name))?;
            line[name.len()..].split_whitespace().next()?.parse().ok()
        };
        if field("PPid:") == Some(pid) {
            out.push((child, field("Uid:").unwrap()));
        }
    }
    out
}

/// Gone, or a zombie nobody reaps (the test binary may be the
/// container's pid 1).
fn exited(pid: u32) -> bool {
    match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Err(_) => true,
        Ok(stat) => stat
            .rsplit(')')
            .next()
            .unwrap()
            .trim_start()
            .starts_with('Z'),
    }
}

#[test]
fn m94_root_helper_reopens_logs_and_removes_the_pid_file() {
    if !is_root() {
        return;
    }
    // The pid file and the logs are in a directory only root may write,
    // like /run and /var/log.
    let conf = format!("pid %%DIR%%/ruxen.pid;\n{CONF}");
    let (mut server, port, dir) = start("helper", "user nobody nogroup;", &conf);
    let pid = server.child.id();
    let helpers = children(pid);
    assert_eq!(helpers.len(), 1, "{helpers:?}");
    let (helper, helper_uid) = helpers[0];
    assert_eq!(helper_uid, 0);

    // logrotate without `create`: the helper makes the new file for the
    // user before the workers reopen it.
    assert!(get(port, "/up").starts_with("HTTP/1.1 200"));
    std::fs::rename(dir.join("access.log"), dir.join("access.log.1")).unwrap();
    // SAFETY: signalling the child we spawned.
    unsafe { libc::kill(pid as i32, libc::SIGUSR1) };
    std::thread::sleep(Duration::from_millis(300));
    assert!(get(port, "/up").starts_with("HTTP/1.1 200"));
    std::thread::sleep(Duration::from_millis(300));
    let log = dir.join("access.log");
    assert_eq!(std::fs::metadata(&log).unwrap().uid(), 65534);
    assert_eq!(std::fs::read_to_string(&log).unwrap().lines().count(), 1);

    // SAFETY: as above.
    unsafe { libc::kill(pid as i32, libc::SIGQUIT) };
    assert!(server.child.wait().unwrap().success());
    let deadline = Instant::now() + Duration::from_secs(3);
    while !exited(helper) {
        assert!(Instant::now() < deadline, "the helper outlived the server");
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(!dir.join("ruxen.pid").exists());
}

#[test]
fn m94_no_helper_without_a_switch() {
    if !is_root() {
        return;
    }
    let (server, port, _dir) = start("nohelper", "user root;", CONF);
    assert!(get(port, "/up").starts_with("HTTP/1.1 200"));
    assert_eq!(children(server.child.id()), vec![]);
}

/// After a reload the helper recreates the new configuration's log files,
/// which it takes from its own parse, and no longer the old ones (#498).
#[test]
fn m94_root_helper_follows_a_reload() {
    if !is_root() {
        return;
    }
    let conf = |extra: &str| {
        format!(
            "pid %%DIR%%/ruxen.pid;\nevents {{}}\nhttp {{ access_log %%DIR%%/a.log; {extra}\n\
             server {{ listen 127.0.0.1:%%PORT%%; location / {{ return 200 \"ok\\n\"; }} }} }}\n"
        )
    };
    let (server, port, dir) = start("reload", "user nobody nogroup;", &conf(""));
    let pid = server.child.id();
    // The user can't create files in the directory: the reload finds
    // `b.log` made for it, as logrotate's `create` would.
    let b = dir.join("b.log");
    std::fs::write(&b, "").unwrap();
    std::os::unix::fs::chown(&b, Some(65534), Some(65534)).unwrap();
    let with_b = conf(&format!("access_log {};", b.display()))
        .replace("%%DIR%%", dir.to_str().unwrap())
        .replace("%%PORT%%", &port.to_string());
    std::fs::write(
        dir.join("ruxen.conf"),
        format!("user nobody nogroup;\n{with_b}"),
    )
    .unwrap();
    // SAFETY: signalling the child we spawned.
    unsafe { libc::kill(pid as i32, libc::SIGHUP) };
    std::thread::sleep(Duration::from_millis(1000));
    assert!(get(port, "/before").starts_with("HTTP/1.1 200"));

    std::fs::rename(dir.join("a.log"), dir.join("a.log.1")).unwrap();
    std::fs::rename(&b, dir.join("b.log.1")).unwrap();
    // SAFETY: as above.
    unsafe { libc::kill(pid as i32, libc::SIGUSR1) };
    std::thread::sleep(Duration::from_millis(300));
    assert!(get(port, "/after").starts_with("HTTP/1.1 200"));
    std::thread::sleep(Duration::from_millis(300));
    for name in ["a.log", "b.log"] {
        let log = dir.join(name);
        assert_eq!(std::fs::metadata(&log).unwrap().uid(), 65534, "{name}");
        let lines = std::fs::read_to_string(&log).unwrap();
        assert!(
            lines.contains("/after") && !lines.contains("/before"),
            "{name}: {lines}"
        );
    }
}
