//! Nested locations searched as nginx's ngx_http_core_find_location does:
//! a regex location nested in a prefix one is only tried for URIs that
//! prefix matches, and before the server's own regex locations. Flattened
//! into one list, the nested regex matched every URI in configuration
//! order, so a server-level `deny`/`return 403` regex after it was skipped,
//! and a nested one was shadowed by an earlier server-level one (and with
//! it the prefix location's `auth_basic`).

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

struct Server {
    child: Child,
    dir: PathBuf,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn start(tag: &str, server_body: &str) -> (Server, u16) {
    let dir = std::env::temp_dir().join(format!("ruxen-m163-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("htpasswd"), "u:{PLAIN}p\n").unwrap();
    let setup = common::ports::setup_lock();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let conf = dir.join("ruxen.conf");
    std::fs::write(
        &conf,
        format!(
            "events {{}}\nhttp {{ access_log off; server {{ listen 127.0.0.1:{port}; {} }} }}\n",
            server_body.replace("%DIR%", &dir.display().to_string())
        ),
    )
    .unwrap();
    let mut server = Server {
        child: Command::new(env!("CARGO_BIN_EXE_ruxen"))
            .args(["-c", conf.to_str().unwrap()])
            .arg("-g")
            .arg(format!("pid {}/ruxen.pid;", dir.display()))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
        dir,
    };
    let pid_file = server.dir.join("ruxen.pid");
    common::ports::wait_for_pid_file(&mut server.child, &pid_file, Duration::from_secs(5));
    drop(setup);
    (server, port)
}

/// Status and body of a GET.
fn get(port: u16, path: &str) -> (u16, String) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).unwrap();
    let text = String::from_utf8_lossy(&raw).into_owned();
    let status = text[9..12].parse().unwrap();
    let body = text
        .split_once("\r\n\r\n")
        .map_or("", |(_, b)| b)
        .trim()
        .to_string();
    (status, body)
}

#[test]
fn a_nested_regex_belongs_to_its_prefix() {
    let (_s, port) = start(
        "deny",
        r#"
        location /a/ { location ~ \.txt$ { return 200 "nested"; } }
        location ~ \.txt$ { return 403; }
        location ~ \.php$ { return 200 "top-php"; }
        location /admin/ {
            auth_basic "admin"; auth_basic_user_file %DIR%/htpasswd;
            location ~ \.php$ { return 401; }
        }
        "#,
    );
    // Inside /a/: the nested regex.
    assert_eq!(get(port, "/a/x.txt"), (200, "nested".into()));
    // Outside it: the server's regex, its 403 not skipped.
    assert_eq!(get(port, "/x.txt").0, 403);
    assert_eq!(get(port, "/b/x.txt").0, 403);
    // Inside /admin/: the nested regex first, not the server's earlier one.
    assert_eq!(get(port, "/admin/index.php").0, 401);
    assert_eq!(get(port, "/x.php"), (200, "top-php".into()));
}

#[test]
fn nested_search_order_is_nginx_s() {
    let (_s, port) = start(
        "order",
        r#"
        location / {
            return 200 "root";
            location /img/ {
                return 200 "img";
                location ~ \.png$ { return 200 "img-png"; }
                location = /img/logo.png { return 200 "logo"; }
            }
            location ^~ /static/ {
                return 200 "static";
                location ~ \.js$ { return 200 "static-js"; }
            }
        }
        location ~ \.png$ { return 200 "png"; }
        location ~ \.js$ { return 200 "js"; }
        location /a/bc { return 200 "a-bc"; }
        location /a/ { return 200 "a"; location /a/bcd { return 200 "a-bcd"; } }
        "#,
    );
    for (path, want) in [
        ("/img/x.png", "img-png"),
        ("/img/logo.png", "logo"),
        ("/other/x.png", "png"),
        // `^~` stops the server's regexes, not its own nested ones.
        ("/static/x.js", "static-js"),
        ("/static/x.css", "static"),
        ("/x.js", "js"),
        ("/x", "root"),
        // The longest prefix of the server's level, then its nested ones.
        ("/a/bcde", "a-bc"),
        ("/a/bx", "a"),
    ] {
        assert_eq!(get(port, path), (200, want.to_string()), "{path}");
    }
}
