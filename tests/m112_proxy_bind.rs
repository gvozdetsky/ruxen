//! M112 — `proxy_bind` (#135): upstream connections from a given local
//! address, literal or rendered per request, inherited and turned `off`.
//! A value that isn't an address is logged and ignored; a bind() that
//! fails ends the request with a 500 and nginx's `[crit]` line.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Server(Child, std::path::PathBuf);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
        let _ = std::fs::remove_dir_all(&self.1);
    }
}

/// An upstream that answers with the address the connection came from.
fn backend() -> u16 {
    let listener = {
        let _setup = common::ports::setup_lock();
        TcpListener::bind("127.0.0.1:0").unwrap()
    };
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut conn in listener.incoming().flatten() {
            let peer = conn.peer_addr().unwrap().ip().to_string();
            let mut buf = [0u8; 1024];
            let _ = conn.read(&mut buf);
            let _ = write!(
                conn,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{peer}",
                peer.len()
            );
        }
    });
    port
}

fn start(backend: u16) -> (Server, u16) {
    let dir = std::env::temp_dir().join(format!("ruxen-m112-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let _setup = common::ports::setup_lock();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let d = dir.display();
    let up = format!("http://127.0.0.1:{backend}");
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "error_log {d}/error.log info;\nevents {{}}\nhttp {{ access_log off;\n\
             server {{ listen 127.0.0.1:{port}; proxy_bind 127.0.0.2;\n\
             location /inherit {{ proxy_pass {up}; }}\n\
             location /own {{ proxy_bind 127.0.0.3; proxy_pass {up}; }}\n\
             location /off {{ proxy_bind off; proxy_pass {up}; }}\n\
             location /var {{ proxy_bind $arg_b; proxy_pass {up}; }}\n\
             location /taken {{ proxy_bind 127.0.0.1:{backend}; proxy_pass {up}; }}\n\
             }} }}\n"
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
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "ruxen did not start");
        std::thread::sleep(Duration::from_millis(20));
    }
    (Server(child, dir), port)
}

/// Status and body.
fn get(port: u16, path: &str) -> (u16, String) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(s, "GET {path} HTTP/1.0\r\n\r\n").unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    let status = out[9..12].parse().unwrap();
    let body = out.split_once("\r\n\r\n").map_or("", |(_, b)| b);
    (status, body.to_string())
}

#[test]
fn m112_proxy_bind() {
    let (server, port) = start(backend());
    assert_eq!(get(port, "/inherit"), (200, "127.0.0.2".into()));
    assert_eq!(get(port, "/own"), (200, "127.0.0.3".into()));
    assert_eq!(get(port, "/off"), (200, "127.0.0.1".into()));
    assert_eq!(get(port, "/var?b=127.0.0.4"), (200, "127.0.0.4".into()));
    // Empty: no bind.
    assert_eq!(get(port, "/var"), (200, "127.0.0.1".into()));
    // Not an address: logged, no bind.
    assert_eq!(get(port, "/var?b=bogus"), (200, "127.0.0.1".into()));
    // The backend's own listening address is taken.
    assert_eq!(get(port, "/taken").0, 500);
    std::thread::sleep(Duration::from_millis(100));
    let log = std::fs::read_to_string(server.1.join("error.log")).unwrap();
    assert!(
        log.contains("[error] ") && log.contains(" invalid local address \"bogus\", client: "),
        "{log}"
    );
    assert!(
        log.contains("[crit] ")
            && log.contains(" failed (98: Address already in use) while connecting to upstream"),
        "{log}"
    );
}
