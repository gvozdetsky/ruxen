//! M135 — `proxy_pass` inside `limit_except` (proxy_if.t): the methods the
//! block doesn't list go to its own `proxy_pass`, the others to the
//! location's; as in nginx, the block's `proxy_pass` takes no URI part.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::time::Duration;

fn send(port: u16, method: &str, path: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    write!(
        s,
        "{method} {path} HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut raw = String::new();
    s.read_to_string(&mut raw).unwrap();
    raw
}

#[test]
fn limit_except_with_its_own_proxy_pass() {
    let dir = std::env::temp_dir().join(format!("ruxen-m135-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let free = || {
        TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    };
    let (front, back) = (free(), free());
    let conf = |extra: &str| {
        format!(
            "pid {d}/ruxen.pid;\nevents {{}}\nhttp {{ access_log off;\n\
             server {{ listen 127.0.0.1:{front};\n\
               location /lmt {{ proxy_pass http://127.0.0.1:{back}/replacement;\n\
                 limit_except POST {{ {extra} }} }} }}\n\
             server {{ listen 127.0.0.1:{back}; return 200 \"uri:$uri $request_method\"; }} }}\n",
            d = dir.display()
        )
    };
    // A URI part is refused, as ngx_http_proxy_pass refuses it there.
    std::fs::write(
        dir.join("nginx.conf"),
        conf(&format!("proxy_pass http://127.0.0.1:{back}/x;")),
    )
    .unwrap();
    let check = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .arg("-t")
        .arg("-c")
        .arg(dir.join("nginx.conf"))
        .output()
        .unwrap();
    assert!(!check.status.success());
    assert!(
        String::from_utf8_lossy(&check.stderr).contains("limit_except"),
        "{}",
        String::from_utf8_lossy(&check.stderr)
    );

    std::fs::write(
        dir.join("nginx.conf"),
        conf(&format!("proxy_pass http://127.0.0.1:{back};")),
    )
    .unwrap();
    let setup = common::ports::setup_lock();
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
    drop(setup);
    // GET isn't listed: the block's proxy_pass, the URI as it came.
    let r = send(front, "GET", "/lmt");
    assert!(r.ends_with("uri:/lmt GET"), "{r}");
    // POST is: the location's, with its URI.
    let r = send(front, "POST", "/lmt");
    assert!(r.ends_with("uri:/replacement POST"), "{r}");
    drop(child);
    let _ = std::fs::remove_dir_all(&dir);
}
