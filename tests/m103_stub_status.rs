//! M103 — `stub_status` and `$connections_*` (#96): nginx's text, GET and
//! HEAD only, and connection states counted as nginx counts them (an idle
//! connection is waiting, one sending its head is reading, one being
//! answered is writing).

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

struct Server(Child, std::path::PathBuf);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
        let _ = std::fs::remove_dir_all(&self.1);
    }
}

fn start() -> (Server, u16) {
    let dir = std::env::temp_dir().join(format!("ruxen-m103-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // Held until ruxen listens: released earlier, another test could take
    // the same free port, and ruxen would fail to bind it.
    let setup = common::ports::setup_lock();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "worker_processes 2;\nevents {{}}\nhttp {{ access_log off;\n\
             server {{ listen 127.0.0.1:{port};\n\
             add_header X-Gauges \"$connections_active $connections_reading $connections_writing $connections_waiting\";\n\
             location / {{ return 200 ok; }}\n\
             location /s {{ stub_status; }}\n\
             }} }}\n"
        ),
    )
    .unwrap();
    // Owned by `Server` before the wait: if it panics, ruxen still stops.
    let mut server = Server(
        Command::new(env!("CARGO_BIN_EXE_ruxen"))
            .arg("-c")
            .arg(dir.join("nginx.conf"))
            .arg("-g")
            .arg(format!("pid {}/ruxen.pid;", dir.display()))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
        dir,
    );
    let pid_file = server.1.join("ruxen.pid");
    common::ports::wait_for_pid_file(&mut server.0, &pid_file, Duration::from_secs(5));
    drop(setup);
    (server, port)
}

fn request(port: u16, method: &str, path: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(s, "{method} {path} HTTP/1.0\r\nHost: x\r\n\r\n").unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

fn numbers(body: &str) -> Vec<u64> {
    body.split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty())
        .map(|s| s.parse().unwrap())
        .collect()
}

#[test]
fn m103_stub_status_text_and_states() {
    // The connection probe above counts too.
    let (_server, port) = start();
    let r = request(port, "GET", "/s");
    assert!(r.starts_with("HTTP/1.1 200 OK\r\n"), "{r}");
    assert!(r.contains("Content-Type: text/plain\r\n"), "{r}");
    let body = r.split_once("\r\n\r\n").unwrap().1;
    // nginx's layout, trailing spaces included.
    let n = numbers(body);
    assert_eq!(
        body,
        format!(
            "Active connections: {} \nserver accepts handled requests\n {} {} {} \n\
             Reading: {} Writing: {} Waiting: {} \n",
            n[0], n[1], n[2], n[3], n[4], n[5], n[6]
        )
    );
    // This connection, writing; the accepted ones all handled.
    assert_eq!((n[0], n[4], n[5], n[6]), (1, 0, 1, 0), "{body}");
    assert_eq!(n[1], n[2]);
    assert_eq!(n[3], 1);

    // An idle connection is waiting; with half a head, reading.
    let mut idle = TcpStream::connect(("127.0.0.1", port)).unwrap();
    std::thread::sleep(Duration::from_millis(200));
    let n = numbers(request(port, "GET", "/s").split_once("\r\n\r\n").unwrap().1);
    assert_eq!((n[0], n[4], n[5], n[6]), (2, 0, 1, 1));
    idle.write_all(b"GET / HTTP/1.0\r\n").unwrap();
    std::thread::sleep(Duration::from_millis(200));
    let n = numbers(request(port, "GET", "/s").split_once("\r\n\r\n").unwrap().1);
    assert_eq!((n[0], n[4], n[5], n[6]), (2, 1, 1, 0));
    drop(idle);
    // Let the server see it close.
    std::thread::sleep(Duration::from_millis(200));

    // HEAD has no body; POST is refused.
    let r = request(port, "HEAD", "/s");
    assert!(
        r.starts_with("HTTP/1.1 200 OK\r\n") && r.ends_with("\r\n\r\n"),
        "{r}"
    );
    assert!(request(port, "POST", "/s").starts_with("HTTP/1.1 405 "));

    // The variables, anywhere.
    let r = request(port, "GET", "/");
    assert!(r.contains("\r\nX-Gauges: 1 0 1 0\r\n"), "{r}");
}
