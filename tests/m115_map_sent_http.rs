//! M115 — `$sent_http_*` in a `map` key: the `expires` idiom
//! (`map $sent_http_content_type $expires { … } expires $expires;`) and
//! `add_header` read the response's headers, as in nginx.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
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

fn head(port: u16, path: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(s, "HEAD {path} HTTP/1.0\r\n\r\n").unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

#[test]
fn m115_map_on_sent_http_content_type() {
    let dir = std::env::temp_dir().join(format!("ruxen-m115-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("html")).unwrap();
    std::fs::write(dir.join("html/a.png"), "x").unwrap();
    std::fs::write(dir.join("html/b.txt"), "x").unwrap();
    let setup = common::ports::setup_lock();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let d = dir.display();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "events {{}}\nhttp {{ access_log off;\n\
             types {{ image/png png; text/plain txt; }}\n\
             map $sent_http_content_type $expires {{ default off; ~image/ 1h; }}\n\
             map $sent_http_content_type $kind {{ default other; ~image/ image; }}\n\
             server {{ listen 127.0.0.1:{port}; root {d}/html;\n\
             expires $expires; add_header X-Kind $kind; }} }}\n"
        ),
    )
    .unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .arg("-c")
        .arg(dir.join("nginx.conf"))
        .arg("-g")
        .arg(format!("pid {}/ruxen.pid;", dir.display()))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut server = Server(child, dir);
    let pid_file = server.1.join("ruxen.pid");
    common::ports::wait_for_pid_file(&mut server.0, &pid_file, Duration::from_secs(5));
    drop(setup);

    let png = head(port, "/a.png");
    assert!(png.contains("\r\nCache-Control: max-age=3600\r\n"), "{png}");
    assert!(png.contains("\r\nX-Kind: image\r\n"), "{png}");
    let txt = head(port, "/b.txt");
    assert!(!txt.contains("Cache-Control"), "{txt}");
    assert!(txt.contains("\r\nX-Kind: other\r\n"), "{txt}");
}
