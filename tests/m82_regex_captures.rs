//! M82 — `$1`…`$9` in every complex value (`return`, `add_header`, a
//! proxied response's `add_header`, `error_page`, …), with nginx's rules
//! for which regex they come from: a regex `location`, `rewrite` or `if`
//! that matches sets them (`!~` too), a `rewrite` or `if` that doesn't
//! match clears them, a regex location that doesn't match leaves them, and
//! a regex `server_name` sets them first. They survive an internal
//! redirect. Before, only `set`, `rewrite` and `proxy_redirect` understood
//! them and everything else printed a literal `$1`. All cases checked
//! against nginx 1.24.

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
        "GET {path} HTTP/1.1\r\nHost: abc.cap.test\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

fn body(resp: &str) -> &str {
    resp.split_once("\r\n\r\n").map_or("", |(_, b)| b)
}

fn header<'a>(resp: &'a str, name: &str) -> Option<&'a str> {
    let head = resp.split_once("\r\n\r\n").map_or(resp, |(h, _)| h);
    head.lines()
        .filter_map(|l| l.split_once(": "))
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v)
}

#[test]
fn numbered_captures_render_everywhere() {
    let setup = common::ports::setup_lock();
    let free = || {
        TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    };
    let (port, up) = (free(), free());
    let dir = std::env::temp_dir().join(format!("ruxen-m82-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            r#"pid {d}/ruxen.pid;
events {{}}
http {{
  server {{ listen 127.0.0.1:{port}; server_name ~^(\w+)\.cap\.test$;
    location ~ ^/loc/(\w+)$ {{ add_header X-D $1; return 200 "loc $1"; }}
    location /if {{ if ($arg_v ~ ^(\d+)-(\d+)$) {{ return 200 "if $2 $1"; }} return 200 "no $1"; }}
    location /neg {{ if ($arg_v !~ ^(\d+)$) {{ return 200 "neg-true $1"; }} return 200 "neg-false $1"; }}
    location /rw {{ rewrite ^/nomatch(\d)$ /x; return 200 "rw $1"; }}
    location /srv {{ return 200 "srv $1"; }}
    location /redir/ {{ rewrite ^/redir/(\w+)$ /target last; }}
    location /target {{ return 200 "t $1"; }}
    location ~ ^/px/(\w+)$ {{ proxy_pass http://127.0.0.1:{up}; add_header X-Px $1; }}
    location ~ ^/ep/(\w+)$ {{ error_page 404 /e/$1; return 404; }}
    location /e/ {{ return 200 "ep $uri"; }}
  }}
  server {{ listen 127.0.0.1:{up}; location / {{ return 200 "up"; }} }}
}}
"#,
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

    let loc = get(port, "/loc/zz");
    let cases: Vec<(&str, String)> = [
        "/if?v=12-34",
        "/if?v=x",
        "/neg?v=42",
        "/neg?v=x",
        "/rw",
        "/srv",
        "/redir/qq",
        "/ep/kk",
    ]
    .iter()
    .map(|p| (*p, body(&get(port, p)).to_string()))
    .collect();
    let px = get(port, "/px/qq");
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(body(&loc), "loc zz");
    assert_eq!(header(&loc, "X-D"), Some("zz"));
    let expected = [
        "if 34 12",     // the if regex's own captures
        "no ",          // a failed if regex clears the server_name's
        "neg-false 42", // `!~` that matches sets them
        "neg-true ",    // and one that doesn't clears them
        "rw ",          // as a rewrite that doesn't match
        "srv abc",      // regex server_name; prefix location keeps them
        "t qq",         // survive `rewrite … last`
        "ep /e/kk",     // error_page target
    ];
    for ((path, got), want) in cases.iter().zip(expected) {
        assert_eq!(got, want, "{path}");
    }
    assert_eq!(body(&px), "up");
    assert_eq!(header(&px, "X-Px"), Some("qq"), "{px}");
}
