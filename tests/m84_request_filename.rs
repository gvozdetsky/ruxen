//! M84 — `$request_filename`, `$document_root` and `$realpath_root`, as
//! nginx's ngx_http_map_uri_to_path: the current location's root or alias
//! (whatever its handler, else the server's), with the URI mapped under
//! it. `if (-f $request_filename)` works, and under `disable_symlinks` a
//! refused link fails the test like a missing file. They used to be
//! unsupported variables that rendered empty. All cases checked against
//! nginx 1.24.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::symlink;
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

fn body(port: u16, path: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out.split_once("\r\n\r\n")
        .map_or("", |(_, b)| b)
        .trim()
        .to_string()
}

#[test]
fn request_filename_maps_the_uri_like_nginx() {
    let setup = common::ports::setup_lock();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let d = std::env::temp_dir().join(format!("ruxen-m84-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(d.join("www")).unwrap();
    std::fs::write(d.join("www/real.txt"), "real").unwrap();
    symlink("real.txt", d.join("www/link.txt")).unwrap();
    symlink("www", d.join("wwwlink")).unwrap();
    let dd = d.display();
    std::fs::write(
        d.join("nginx.conf"),
        format!(
            "pid {dd}/ruxen.pid;\nevents {{}}\nhttp {{\n\
             server {{ listen 127.0.0.1:{port}; root {dd}/wwwlink;\n\
               location /f/ {{ alias {dd}/www/;\n\
                 if (-f $request_filename) {{ return 200 \"file $request_filename\"; }}\n\
                 return 200 \"nofile $request_filename\"; }}\n\
               location /d {{ return 200 \"$request_filename|$document_root|$realpath_root\"; }}\n\
               location ~ ^/rx/ {{ alias {dd}/www/; return 200 \"rx $request_filename\"; }}\n\
               location /on/ {{ alias {dd}/www/; disable_symlinks on;\n\
                 if (-f $request_filename) {{ return 200 \"file\"; }}\n\
                 if (!-e $request_filename) {{ return 200 \"absent\"; }}\n\
                 return 200 \"other\"; }}\n\
             }} }}\n"
        ),
    )
    .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .arg("-c")
        .arg(d.join("nginx.conf"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    while !d.join("ruxen.pid").exists() {
        assert!(
            Instant::now() < deadline && child.try_wait().unwrap().is_none(),
            "ruxen did not start"
        );
        sleep(Duration::from_millis(10));
    }
    drop(setup);

    let cases = [
        ("/f/real.txt", format!("file {dd}/www/real.txt")),
        ("/f/nope.txt", format!("nofile {dd}/www/nope.txt")),
        (
            "/d/q",
            format!(
                "{dd}/wwwlink/d/q|{dd}/wwwlink|{}",
                d.join("www").canonicalize().unwrap().display()
            ),
        ),
        ("/rx/k", format!("rx {dd}/www/")),
        ("/on/real.txt", "file".to_string()),
        ("/on/link.txt", "absent".to_string()),
    ];
    let got: Vec<String> = cases.iter().map(|(p, _)| body(port, p)).collect();
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&d);
    for ((path, want), got) in cases.iter().zip(&got) {
        assert_eq!(got, want, "{path}");
    }
}
