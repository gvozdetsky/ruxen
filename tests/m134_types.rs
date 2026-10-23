//! M134 — `types {}` and `default_type` (#38), as nginx sets Content-Type
//! (ngx_http_set_content_type): by the URI's extension, case folded, from
//! the nearest level's `types` (else nginx's built-in html / gif / jpg),
//! else `default_type` (else `text/plain`). `charset` adds a charset to
//! the types in `charset_types` (#464).

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::time::Duration;

fn content_type(port: u16, host: &str, path: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    write!(
        s,
        "HEAD {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut raw = String::new();
    s.read_to_string(&mut raw).unwrap();
    assert!(raw.starts_with("HTTP/1.1 200"), "{path}: {raw}");
    raw.lines()
        .find_map(|l| l.strip_prefix("Content-Type: "))
        .unwrap_or("")
        .to_string()
}

#[test]
fn content_types_like_nginx() {
    let dir = std::env::temp_dir().join(format!("ruxen-m134-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("www")).unwrap();
    for f in [
        "a.html", "a.css", "a.FOO", "a.gif", "noext", "a.later", "a.two",
    ] {
        std::fs::write(dir.join("www").join(f), "x").unwrap();
    }
    // Both ports at once, held from the pick until ruxen listens: two
    // picks one after the other may return the same port (#565).
    let setup = common::ports::setup_lock();
    let [port, port2] = common::ports::free_ports();
    let www = dir.join("www").display().to_string();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "pid {d}/ruxen.pid;\nevents {{}}\nhttp {{\naccess_log off;\n\
             types {{ text/html html; text/css css; text/x-foo foo; text/a later; text/b later; }}\n\
             types {{ text/x-two two; text/c later; }}\n\
             default_type text/x-default;\n\
             server {{ listen 127.0.0.1:{port}; server_name http; root {www};\n\
               location /own/ {{ alias {www}/; types {{ image/x-own css; }} }}\n\
               location /def/ {{ alias {www}/; default_type application/x-def; }} }}\n\
             server {{ listen 127.0.0.1:{port}; server_name builtin; root {www};\n\
               types {{ }} }}\n\
             }}\n",
            d = dir.display()
        ),
    )
    .unwrap();
    // A second configuration with no `types` and no `default_type` at all.
    std::fs::create_dir_all(dir.join("bare")).unwrap();
    std::fs::write(
        dir.join("bare/nginx.conf"),
        format!(
            "pid {d}/bare/ruxen.pid;\nevents {{}}\nhttp {{ access_log off;\n\
             server {{ listen 127.0.0.1:{port2}; root {www}; }} }}\n",
            d = dir.display()
        ),
    )
    .unwrap();
    let mut servers = Vec::new();
    for (conf, pid) in [
        (dir.join("nginx.conf"), dir.join("ruxen.pid")),
        (dir.join("bare/nginx.conf"), dir.join("bare/ruxen.pid")),
    ] {
        let mut child = common::KillOnDrop(
            Command::new(env!("CARGO_BIN_EXE_ruxen"))
                .arg("-c")
                .arg(&conf)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        common::ports::wait_for_pid_file(&mut child, &pid, Duration::from_secs(5));
        servers.push(child);
    }
    drop(setup);

    // http's types: case folded, the later of two lines wins, the default
    // for what has no type or no extension.
    assert_eq!(content_type(port, "http", "/a.html"), "text/html");
    assert_eq!(content_type(port, "http", "/a.css"), "text/css");
    assert_eq!(content_type(port, "http", "/a.FOO"), "text/x-foo");
    // A second `types {}` at the same level adds to the first; a repeated
    // extension takes the later type.
    assert_eq!(content_type(port, "http", "/a.later"), "text/c");
    assert_eq!(content_type(port, "http", "/a.two"), "text/x-two");
    assert_eq!(content_type(port, "http", "/a.gif"), "text/x-default");
    assert_eq!(content_type(port, "http", "/noext"), "text/x-default");
    // A location's own types replace the inherited ones; its default_type
    // keeps them.
    assert_eq!(content_type(port, "http", "/own/a.css"), "image/x-own");
    assert_eq!(content_type(port, "http", "/own/a.html"), "text/x-default");
    assert_eq!(content_type(port, "http", "/def/a.css"), "text/css");
    assert_eq!(
        content_type(port, "http", "/def/noext"),
        "application/x-def"
    );
    // `types { }`: nothing has a type.
    assert_eq!(content_type(port, "builtin", "/a.html"), "text/x-default");
    // No types anywhere: nginx's built-in three, else text/plain.
    assert_eq!(content_type(port2, "x", "/a.html"), "text/html");
    assert_eq!(content_type(port2, "x", "/a.gif"), "image/gif");
    assert_eq!(content_type(port2, "x", "/a.css"), "text/plain");

    drop(servers);
    let _ = std::fs::remove_dir_all(&dir);
}

/// `charset` (#464), as nginx's charset filter: `; charset=…` after a type
/// in `charset_types` (by default text/html, text/plain, application/
/// javascript, …; text/html always), on static files, `return`, built-in
/// error pages and proxied responses, not where the response has one
/// already; `charset off` and `if` blocks as levels of their own.
#[test]
fn charset_labels_content_type_like_nginx() {
    let dir = std::env::temp_dir().join(format!("ruxen-m134-charset-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("www")).unwrap();
    for f in ["a.html", "a.css", "a.js", "x.noext"] {
        std::fs::write(dir.join("www").join(f), "x").unwrap();
    }
    let setup = common::ports::setup_lock();
    let [port] = common::ports::free_ports();
    let www = dir.join("www").display().to_string();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "pid {d}/ruxen.pid;\nevents {{}}\nhttp {{\naccess_log off;\n\
             types {{ text/html html; text/css css; application/javascript js; }}\n\
             charset utf-8;\n\
             server {{ listen 127.0.0.1:{port}; root {www};\n\
               location /r {{ return 200 x; }}\n\
               location /m {{ return 301 /r; }}\n\
               location /pp/ {{ alias {www}/; default_type \"text/html; foo=bar\"; }}\n\
               location /p {{ proxy_pass http://127.0.0.1:{port}/a.html; }}\n\
               location /pc {{ proxy_pass http://127.0.0.1:{port}/up/a.html; }}\n\
               location /up/ {{ alias {www}/; charset koi8-r; }}\n\
               location /css/ {{ alias {www}/; charset_types text/css; }}\n\
               location /any/ {{ alias {www}/; charset_types *; }}\n\
               location /off/ {{ alias {www}/; charset off; if ($arg_c) {{ charset windows-1251; }} }}\n\
             }} }}\n",
            d = dir.display()
        ),
    )
    .unwrap();
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
    let get = |path: &str| -> String {
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        write!(
            s,
            "GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
        let mut raw = String::new();
        s.read_to_string(&mut raw).unwrap();
        raw.lines()
            .find_map(|l| l.strip_prefix("Content-Type: "))
            .unwrap_or("")
            .to_string()
    };
    for (path, wanted) in [
        ("/a.html", "text/html; charset=utf-8"),
        ("/a.js", "application/javascript; charset=utf-8"),
        ("/a.css", "text/css"),
        ("/r", "text/plain; charset=utf-8"),
        // Not on a 301 or 302; a type with parameters isn't the bare type.
        ("/m", "text/html"),
        ("/pp/x.noext", "text/html; foo=bar"),
        ("/none", "text/html; charset=utf-8"),
        ("/p", "text/html; charset=utf-8"),
        ("/pc", "text/html; charset=koi8-r"),
        ("/css/a.css", "text/css; charset=utf-8"),
        ("/css/a.html", "text/html; charset=utf-8"),
        ("/any/a.css", "text/css; charset=utf-8"),
        ("/off/a.html", "text/html"),
        ("/off/a.html?c=1", "text/html; charset=windows-1251"),
    ] {
        assert_eq!(get(path), wanted, "{path}");
    }
    drop(child);
    let _ = std::fs::remove_dir_all(&dir);
}

/// `return` types its response as nginx types any (#691): by the URI's
/// extension, else `default_type`, with text or without; a 204 has no
/// type, and a redirect keeps its page's.
#[test]
fn return_takes_the_type_of_the_uri() {
    let dir = std::env::temp_dir().join(format!("ruxen-m134-return-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let setup = common::ports::setup_lock();
    let [port] = common::ports::free_ports();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "pid {d}/ruxen.pid;\nevents {{}}\nhttp {{\naccess_log off;\n\
             types {{ text/html html; }}\ndefault_type application/octet-stream;\n\
             server {{ listen 127.0.0.1:{port};\n\
               location /a {{ return 200; }}\n\
               location /b {{ return 200 x; }}\n\
               location /c {{ return 404 nf; }}\n\
               location /d {{ if ($arg_x) {{ return 200 $arg_x; }} return 204; }}\n\
               location /e {{ default_type application/json; return 200 '{{}}'; }}\n\
               location /m {{ return 301 /b; }}\n\
             }} }}\n",
            d = dir.display()
        ),
    )
    .unwrap();
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
    let get = |path: &str| -> String {
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        write!(
            s,
            "GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
        let mut raw = String::new();
        s.read_to_string(&mut raw).unwrap();
        raw.lines()
            .find_map(|l| l.strip_prefix("Content-Type: "))
            .unwrap_or("")
            .to_string()
    };
    for (path, wanted) in [
        ("/a", "application/octet-stream"),
        ("/b", "application/octet-stream"),
        ("/b.html", "text/html"),
        ("/c", "application/octet-stream"),
        ("/d?x=1", "application/octet-stream"),
        ("/d", ""),
        ("/e", "application/json"),
        ("/m", "text/html"),
    ] {
        assert_eq!(get(path), wanted, "{path}");
    }
    drop(child);
    let _ = std::fs::remove_dir_all(&dir);
}
