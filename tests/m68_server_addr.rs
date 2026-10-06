//! M68 — `$server_addr`: the local address of the connection, without
//! brackets for IPv6, as nginx's ngx_http_variable_server_addr. A listen on
//! a specific address gives that address; a wildcard listen gives the
//! address the client connected to (getsockname). It used to be an
//! unsupported variable that rendered empty.

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

fn get(addr: SocketAddr) -> String {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out.split("\r\n\r\n").last().unwrap_or("").to_string()
}

#[test]
fn server_addr_is_the_local_address() {
    let setup = common::ports::setup_lock();
    let free = |host: &str| {
        TcpListener::bind((host, 0))
            .ok()
            .map(|l| l.local_addr().unwrap().port())
    };
    let v4 = free("127.0.0.1").unwrap();
    let wildcard = free("0.0.0.0").unwrap();
    let v6 = free("::1");
    let dir = std::env::temp_dir().join(format!("ruxen-m68-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let v6_listen = v6.map_or(String::new(), |p| format!("listen [::1]:{p};"));
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "pid {d}/ruxen.pid;\nevents {{}}\nhttp {{\n\
             server {{ listen 127.0.0.1:{v4}; {v6_listen}\n\
               location / {{ return 200 \"$server_addr:$server_port\"; }} }}\n\
             server {{ listen {wildcard};\n\
               location / {{ return 200 \"$server_addr:$server_port\"; }} }}\n\
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

    let specific = get(([127, 0, 0, 1], v4).into());
    let via_wildcard = get(([127, 0, 0, 1], wildcard).into());
    let ipv6 = v6.map(|p| get(SocketAddr::new("::1".parse().unwrap(), p)));
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(specific, format!("127.0.0.1:{v4}"));
    assert_eq!(via_wildcard, format!("127.0.0.1:{wildcard}"));
    if let (Some(p), Some(body)) = (v6, ipv6) {
        assert_eq!(body, format!("::1:{p}"));
    }
}
