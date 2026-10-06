//! M85 — variables in try_files probes and in its URI fallback, as nginx
//! compiles every argument as a complex value: `$uri.html`, `/cache$uri`,
//! `/index.php?q=$uri&$args`. A fallback's `?args` become the redirected
//! request's `$args`, as nginx's internal redirect. Before, any variable
//! other than a bare `$uri` was refused at startup, and a literal
//! fallback's arguments were dropped. Checked against nginx 1.24.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

fn get(port: u16, path: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    let code = out.get(9..12).unwrap_or("").to_string();
    let body = out.split_once("\r\n\r\n").map_or("", |(_, b)| b).trim();
    format!("{code} {body}")
}

#[test]
fn try_files_renders_variables_in_probes_and_fallback() {
    let setup = common::ports::setup_lock();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let d = std::env::temp_dir().join(format!("ruxen-m85-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(d.join("html/cache/c")).unwrap();
    std::fs::write(d.join("html/page.html"), "page").unwrap();
    std::fs::write(d.join("html/cache/c/x"), "cached").unwrap();
    let dd = d.display();
    std::fs::write(
        d.join("nginx.conf"),
        format!(
            "pid {dd}/ruxen.pid;\nevents {{}}\nhttp {{\n\
             server {{ listen 127.0.0.1:{port}; root {dd}/html;\n\
               location /p/ {{ alias {dd}/html/; try_files $uri $uri.html =404; }}\n\
               location /w/ {{ try_files $uri $uri/ /index.php?q=$uri&$args; }}\n\
               location /l/ {{ try_files $uri /index.php?fixed=1; }}\n\
               location /c/ {{ try_files /cache$uri @fb; }}\n\
               location @fb {{ return 200 \"fb $uri\"; }}\n\
               location = /index.php {{ return 200 \"idx $uri $args\"; }}\n\
             }} }}\n"
        ),
    )
    .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .arg("-c")
        .arg(d.join("nginx.conf"))
        .env("TMPDIR", &d)
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
        ("/p/page", "200 page"),
        ("/p/nope", "404"),
        (
            "/w/missing?a=1&b=2",
            "200 idx /index.php q=/w/missing&a=1&b=2",
        ),
        ("/w/zz", "200 idx /index.php q=/w/zz&"),
        ("/l/zz?a=1", "200 idx /index.php fixed=1"),
        ("/c/x", "200 cached"),
        ("/c/nope", "200 fb /c/nope"),
    ];
    let got: Vec<String> = cases.iter().map(|(p, _)| get(port, p)).collect();
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&d);
    for ((path, want), got) in cases.iter().zip(&got) {
        assert!(got.starts_with(want), "{path}: {got}");
    }
}
