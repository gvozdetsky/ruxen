//! M108 — `listen unix:/path` (#263): HTTP over a unix-domain socket, with
//! nginx's `$remote_addr` (`unix:`), `allow unix:` / `deny unix:` for such
//! clients, a socket file left behind refused at startup, and the file
//! removed when ruxen stops.

mod common;

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn get(sock: &std::path::Path, path: &str) -> String {
    let mut s = UnixStream::connect(sock).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(s, "GET {path} HTTP/1.0\r\nHost: x\r\n\r\n").unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

#[test]
fn m108_http_over_a_unix_socket() {
    let dir = std::env::temp_dir().join(format!("ruxen-m108-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("http.sock");
    let d = dir.display();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "worker_processes 2;\npid {d}/ruxen.pid;\nevents {{}}\nhttp {{ access_log off;\n\
             server {{ listen unix:{d}/http.sock;\n\
             location / {{ return 200 \"[$remote_addr][$remote_port][$server_addr]\"; }}\n\
             location /unix-only {{ allow unix:; deny all; }}\n\
             location /no-unix {{ deny unix:; allow all; }}\n\
             location /inet-only {{ allow 127.0.0.1; deny all; }}\n\
             }} }}\n"
        ),
    )
    .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .arg("-c")
        .arg(dir.join("nginx.conf"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !dir.join("ruxen.pid").exists() {
        assert!(Instant::now() < deadline, "ruxen did not start");
        std::thread::sleep(Duration::from_millis(20));
    }
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777,
        0o666
    );
    let r = get(&sock, "/");
    assert!(r.ends_with("\r\n\r\n[unix:][][unix:]"), "{r}");
    // Access rules run before the (missing) file: 404 means allowed.
    // (`return` would answer before them, as in nginx.)
    assert!(get(&sock, "/unix-only").starts_with("HTTP/1.1 404"));
    assert!(get(&sock, "/no-unix").starts_with("HTTP/1.1 403"));
    // An IPv4 rule doesn't match a unix-domain client.
    assert!(get(&sock, "/inet-only").starts_with("HTTP/1.1 403"));

    // A second instance finds the socket file in place.
    let second = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .arg("-c")
        .arg(dir.join("nginx.conf"))
        .output()
        .unwrap();
    assert!(!second.status.success());
    let stderr = String::from_utf8_lossy(&second.stderr);
    assert!(
        stderr.contains(&format!(
            "bind() to unix:{d}/http.sock failed (98: Address already in use)"
        )),
        "{stderr}"
    );

    // SIGQUIT: the socket file goes away with the server.
    Command::new("kill")
        .args(["-QUIT", &child.id().to_string()])
        .status()
        .unwrap();
    child.wait().unwrap();
    assert!(!sock.exists(), "socket file left behind");
    let _ = std::fs::remove_dir_all(&dir);
}
