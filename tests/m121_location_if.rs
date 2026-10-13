//! M121 — an `if` block inside a location can set more than rewrite
//! directives (#137): `proxy_pass`, `add_header`, `root`, … make it an
//! anonymous location that inherits the enclosing one, and the request
//! switches to it when the condition holds, as nginx's
//! `ngx_http_rewrite_if` / `ngx_http_script_if_code`. Without a handler of
//! its own the block keeps the location's, `proxy_pass` URI included
//! (nginx ticket #645).

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn get(port: u16, path: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
    out
}

#[test]
fn if_blocks_switch_the_location() {
    let (port, up) = (free_port(), free_port());
    let dir = std::env::temp_dir().join(format!("ruxen-m121-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("html/static")).unwrap();
    std::fs::create_dir_all(dir.join("other/static")).unwrap();
    std::fs::write(dir.join("html/static/index.html"), "main\n").unwrap();
    std::fs::write(dir.join("other/static/index.html"), "other\n").unwrap();
    let setup = common::ports::setup_lock();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "pid {d}/ruxen.pid;\nevents {{}}\nhttp {{ access_log off;\n\
             server {{ listen 127.0.0.1:{port};\n\
               location /variables {{\n\
                 proxy_pass http://127.0.0.1:{up}/outer;\n\
                 if ($arg_if) {{ proxy_pass http://127.0.0.1:{up}; }}\n\
               }}\n\
               location /keep {{\n\
                 proxy_pass http://127.0.0.1:{up}/replacement;\n\
                 add_header X-Loc yes;\n\
                 if ($arg_h) {{ add_header X-If yes; }}\n\
               }}\n\
               location /static/ {{\n\
                 root {d}/html;\n\
                 if ($arg_o) {{ root {d}/other; }}\n\
               }}\n\
             }}\n\
             server {{ listen 127.0.0.1:{up}; return 200 \"uri:$uri\\n\"; }}\n\
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

    let outer = get(port, "/variables");
    let inner = get(port, "/variables?if=1");
    let keep = get(port, "/keep");
    let keep_if = get(port, "/keep?h=1");
    let main = get(port, "/static/");
    let other = get(port, "/static/?o=1");
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&dir);

    assert!(outer.ends_with("uri:/outer\n"), "{outer}");
    assert!(inner.ends_with("uri:/variables\n"), "{inner}");
    assert!(
        keep.contains("X-Loc: yes") && keep.ends_with("uri:/replacement\n"),
        "{keep}"
    );
    // The block's `add_header` replaces the location's; its `proxy_pass`
    // URI is the location's.
    assert!(
        keep_if.contains("X-If: yes")
            && !keep_if.contains("X-Loc")
            && keep_if.ends_with("uri:/replacement\n"),
        "{keep_if}"
    );
    assert!(main.ends_with("main\n"), "{main}");
    assert!(other.ends_with("other\n"), "{other}");
}
