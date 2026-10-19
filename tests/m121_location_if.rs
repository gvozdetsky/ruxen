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
use std::time::Duration;

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
    let dir = std::env::temp_dir().join(format!("ruxen-m121-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("html/static")).unwrap();
    std::fs::create_dir_all(dir.join("other/static")).unwrap();
    std::fs::write(dir.join("html/static/index.html"), "main\n").unwrap();
    std::fs::write(dir.join("other/static/index.html"), "other\n").unwrap();
    // Held from the port pick until ruxen listens.
    let setup = common::ports::setup_lock();
    let (port, up) = (free_port(), free_port());
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
    // Owned by the guard before the wait: if it panics, ruxen still stops.
    let mut child = common::KillOnDrop(
        Command::new(env!("CARGO_BIN_EXE_ruxen"))
            .arg("-c")
            .arg(dir.join("nginx.conf"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    common::ports::wait_for_pid_file(&mut child, &dir.join("ruxen.pid"), Duration::from_secs(3));
    drop(setup);

    let outer = get(port, "/variables");
    let inner = get(port, "/variables?if=1");
    let keep = get(port, "/keep");
    let keep_if = get(port, "/keep?h=1");
    let main = get(port, "/static/");
    let other = get(port, "/static/?o=1");
    drop(child);
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

/// What the request does once an `if` holds, case by case against nginx:
/// the location's own `return` still answers, a `return` in the block
/// uses its configuration, `root` alone keeps the location's handler, the
/// root (the server's too, set below) and a regex location's alias carry
/// into the block, and a later
/// block of rewrite directives only goes back to the location's settings.
#[test]
fn if_locations_follow_nginx() {
    let dir = std::env::temp_dir().join(format!("ruxen-m121b-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("html/static")).unwrap();
    std::fs::create_dir_all(dir.join("other")).unwrap();
    std::fs::write(dir.join("html/static/index.html"), "main\n").unwrap();
    // Held from the port pick until ruxen listens.
    let setup = common::ports::setup_lock();
    let (port, up) = (free_port(), free_port());
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "pid {d}/ruxen.pid;\nevents {{}}\nhttp {{ access_log off;\n\
             server {{ listen 127.0.0.1:{port};\n\
               location /guard {{ if ($arg_x) {{ proxy_pass http://127.0.0.1:{up}; }} return 403; }}\n\
               location /h {{\n\
                 access_log {d}/access.log;\n\
                 if ($arg_q) {{ access_log off; return 200 \"hc\\n\"; }}\n\
                 return 204;\n\
               }}\n\
               location ~ ^/img/a$ {{ alias {d}/html/static/index.html; if ($arg_x) {{ add_header X-Img 1; }} }}\n\
               location /alt {{ proxy_pass http://127.0.0.1:{up}; if ($arg_s) {{ root {d}/other; }} }}\n\
               location /app {{\n\
                 root {d}/html;\n\
                 proxy_set_header X-Root $document_root;\n\
                 if ($arg_x) {{ proxy_pass http://127.0.0.1:{up}; }}\n\
               }}\n\
               location /two {{\n\
                 add_header X-Loc 1;\n\
                 if ($arg_a) {{ add_header X-A 1; }}\n\
                 if ($arg_b) {{ set $v 1; }}\n\
                 return 200 \"two\\n\";\n\
               }}\n\
               location /late/ {{\n\
                 proxy_pass http://127.0.0.1:{up};\n\
                 proxy_set_header X-Root $document_root;\n\
                 if ($arg_h) {{ add_header X-H 1; }}\n\
               }}\n\
               root {d}/html;\n\
             }}\n\
             server {{ listen 127.0.0.1:{up}; return 200 \"uri:$uri$http_x_root\\n\"; }}\n\
             }}\n",
            d = dir.display()
        ),
    )
    .unwrap();
    // Owned by the guard before the wait: if it panics, ruxen still stops.
    let mut child = common::KillOnDrop(
        Command::new(env!("CARGO_BIN_EXE_ruxen"))
            .arg("-c")
            .arg(dir.join("nginx.conf"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    common::ports::wait_for_pid_file(&mut child, &dir.join("ruxen.pid"), Duration::from_secs(3));
    drop(setup);

    let guard = get(port, "/guard?x=1");
    let quiet = get(port, "/h?q=1");
    let logged = get(port, "/h");
    let img = get(port, "/img/a?x=1");
    let alt = get(port, "/alt?s=1");
    let app = get(port, "/app?x=1");
    let two_a = get(port, "/two?a=1");
    let two_ab = get(port, "/two?a=1&b=1");
    let late = get(port, "/late/?h=1");
    // The line of `/h` is written after its response: wait for it rather
    // than a fixed time, which the full test run's load can outlast.
    let mut log = String::new();
    for _ in 0..60 {
        log = std::fs::read_to_string(dir.join("access.log")).unwrap_or_default();
        if log.contains("GET /h ") {
            break;
        }
        sleep(Duration::from_millis(50));
    }
    drop(child);
    let _ = std::fs::remove_dir_all(&dir);

    assert!(guard.starts_with("HTTP/1.1 403"), "{guard}");
    assert!(quiet.ends_with("hc\n"), "{quiet}");
    assert!(logged.starts_with("HTTP/1.1 204"), "{logged}");
    assert!(!log.contains("/h?q=1") && log.contains("GET /h "), "{log}");
    assert!(img.contains("X-Img: 1") && img.ends_with("main\n"), "{img}");
    assert!(alt.ends_with("uri:/alt\n"), "{alt}");
    assert!(
        app.ends_with(&format!("uri:/app{}/html\n", dir.display())),
        "{app}"
    );
    assert!(
        two_a.contains("X-A: 1") && !two_a.contains("X-Loc"),
        "{two_a}"
    );
    assert!(
        two_ab.contains("X-Loc: 1") && !two_ab.contains("X-A"),
        "{two_ab}"
    );
    // The server's root, below the location, reaches the block too.
    assert!(
        late.contains("X-H: 1") && late.ends_with(&format!("uri:/late/{}/html\n", dir.display())),
        "{late}"
    );
}
