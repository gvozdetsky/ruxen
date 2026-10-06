//! M69 — request-body temp files are private, as nginx's: `0600`,
//! created with `O_EXCL`, in a `0700` directory: `client_body_temp_path`
//! (http scope) or a private directory of the process. They used to be
//! `0644` files with predictable names straight in the system temp
//! directory, readable by every local user.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
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

fn start(tag: &str, http_extra: &str) -> Server {
    let port = {
        let probe = TcpListener::bind("127.0.0.1:0").unwrap();
        probe.local_addr().unwrap().port()
    };
    let dir = std::env::temp_dir().join(format!("ruxen-m69-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "events {{}}\nhttp {{ {} server {{ listen 127.0.0.1:{port};\n\
             location / {{ client_max_body_size 10m; client_body_in_file_only on; \
             return 200 \"$request_body_file\"; }} }} }}\n",
            http_extra.replace("%%DIR%%", &dir.display().to_string())
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

/// POSTs `body` and returns `$request_body_file`.
fn post(port: u16, body: &[u8]) -> PathBuf {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(
        s,
        "POST / HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .unwrap();
    s.write_all(body).unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    assert!(out.starts_with("HTTP/1.1 200"), "{out}");
    PathBuf::from(out.split("\r\n\r\n").nth(1).unwrap())
}

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

/// Both spill paths: a body over 2 KiB written after the read, and one
/// over 1 MiB streamed to the file while it arrives.
const SIZES: [usize; 2] = [5000, 3 << 20];

#[test]
fn configured_client_body_temp_path_is_private() {
    let server = start("conf", "client_body_temp_path %%DIR%%/body_temp 1 2;");
    let temp = server.dir.join("body_temp");
    for size in SIZES {
        let body: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let file = post(server.port, &body);
        // Levels `1 2`: `<temp>/<last digit>/<two before it>/<name>`.
        let name = file.file_name().unwrap().to_str().unwrap().to_string();
        let inner = file.parent().unwrap();
        let outer = inner.parent().unwrap();
        assert_eq!(outer.parent(), Some(temp.as_path()), "{}", file.display());
        assert_eq!(outer.file_name().unwrap().to_str(), Some(&name[9..]));
        assert_eq!(inner.file_name().unwrap().to_str(), Some(&name[7..9]));
        assert_eq!((mode(outer), mode(inner)), (0o700, 0o700));
        assert_eq!(std::fs::read(&file).unwrap(), body);
        assert_eq!(mode(&file), 0o600, "{}", file.display());
    }
    assert_eq!(mode(&temp), 0o700);
}

#[test]
fn default_temp_directory_is_private() {
    let server = start("default", "");
    for size in SIZES {
        let body = vec![b'x'; size];
        let file = post(server.port, &body);
        let dir = file.parent().unwrap().to_path_buf();
        assert_eq!(dir.parent(), Some(std::env::temp_dir().as_path()));
        assert!(
            dir.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(&format!("ruxen-{}-", server.child.id())),
            "{}",
            dir.display()
        );
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&file), 0o600);
        // Kept by client_body_in_file_only on. Removing the directory as
        // well, as a temp-directory cleaner might, makes ruxen create a new
        // one for the next body.
        std::fs::remove_file(&file).unwrap();
        std::fs::remove_dir(&dir).unwrap();
    }
}

#[test]
fn bad_levels_are_rejected_like_nginx() {
    let dir = std::env::temp_dir().join(format!("ruxen-m69-levels-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    for levels in ["0", "x", "5 5 1", "1 1 1 1"] {
        std::fs::write(
            dir.join("nginx.conf"),
            format!(
                "events {{}}\nhttp {{ client_body_temp_path t {levels}; \
                 server {{ listen 127.0.0.1:1; }} }}\n"
            ),
        )
        .unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_ruxen"))
            .arg("-t")
            .arg("-c")
            .arg(dir.join("nginx.conf"))
            .output()
            .unwrap();
        assert!(!out.status.success(), "levels {levels:?} accepted");
    }
    let _ = std::fs::remove_dir_all(&dir);
}
