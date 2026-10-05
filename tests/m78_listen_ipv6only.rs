//! M78 — a `[::]` listen is IPv6-only unless `ipv6only=off`, as nginx
//! (`IPV6_V6ONLY` on by default, ngx_http_core_module.c): it doesn't take
//! IPv4 clients. ruxen's sockets used to be dual-stack whatever the config
//! said, so `listen [::]:80;` alone also served IPv4.

mod common;

use std::io::{Read, Write};
use std::net::{Ipv6Addr, TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

fn get(addr: &str) -> Option<String> {
    let mut s = TcpStream::connect(addr).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .ok()?;
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    Some(out.split("\r\n\r\n").last().unwrap_or("").to_string())
}

#[test]
fn a_wildcard_ipv6_listen_is_ipv6_only_by_default() {
    // No IPv6 here (some containers): nothing to check.
    let Ok(probe) = TcpListener::bind((Ipv6Addr::UNSPECIFIED, 0)) else {
        eprintln!("skipped: no IPv6");
        return;
    };
    drop(probe);
    let setup = common::ports::setup_lock();
    let free = || {
        TcpListener::bind((Ipv6Addr::UNSPECIFIED, 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    };
    let (v6only, dual) = (free(), free());
    let dir = std::env::temp_dir().join(format!("ruxen-m78-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "pid {d}/ruxen.pid;\nevents {{}}\nhttp {{\n\
             server {{ listen [::]:{v6only}; location / {{ return 200 v6; }} }}\n\
             server {{ listen [::]:{dual} ipv6only=off; location / {{ return 200 dual; }} }}\n\
             }}\n",
            d = dir.display()
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
    let deadline = Instant::now() + Duration::from_secs(3);
    while !dir.join("ruxen.pid").exists() {
        assert!(
            Instant::now() < deadline && child.try_wait().unwrap().is_none(),
            "ruxen did not start"
        );
        sleep(Duration::from_millis(10));
    }
    drop(setup);

    let v4_to_v6only = get(&format!("127.0.0.1:{v6only}"));
    let v6_to_v6only = get(&format!("[::1]:{v6only}"));
    let v4_to_dual = get(&format!("127.0.0.1:{dual}"));
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(v4_to_v6only, None, "an IPv4 client reached [::]:{v6only}");
    assert_eq!(v6_to_v6only.as_deref(), Some("v6"));
    assert_eq!(v4_to_dual.as_deref(), Some("dual"));
}
