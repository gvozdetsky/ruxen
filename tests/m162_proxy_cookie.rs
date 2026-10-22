//! M162 — `proxy_cookie_domain` and `proxy_cookie_path` (#40): the
//! `Domain` and `Path` of the upstream's `Set-Cookie` rewritten with the
//! first matching rule, as nginx's ngx_http_proxy_rewrite_cookie. A literal
//! domain matches the whole domain after a leading dot, caseless; a literal
//! path is a prefix; `~` (caseless for domains) and `~*` are regexes whose
//! captures the replacement may use. `off` in a nested location undoes the
//! rules it would inherit.

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::time::Duration;

/// The `Set-Cookie` lines of the response to `path`.
fn cookies(port: u16, path: &str) -> Vec<String> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(s, "GET {path} HTTP/1.0\r\nHost: localhost\r\n\r\n").unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
    out.lines()
        .filter_map(|l| l.strip_prefix("Set-Cookie: "))
        .map(str::to_string)
        .collect()
}

#[test]
fn set_cookie_domain_and_path_are_rewritten() {
    let dir = std::env::temp_dir().join(format!("ruxen-m162-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("static")).unwrap();
    std::fs::write(dir.join("static/f.txt"), "f").unwrap();
    // Held from the port pick until ruxen listens.
    let setup = common::ports::setup_lock();
    let [port, up] = common::ports::free_ports();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "pid {d}/ruxen.pid;\nevents {{}}\nhttp {{ access_log off;\n\
             server {{ listen 127.0.0.1:{port}; server_name localhost;\n\
               location / {{\n\
                 proxy_pass http://127.0.0.1:{up};\n\
                 proxy_cookie_domain www.example.org .example.com;\n\
                 proxy_cookie_domain .$server_name.com en.$server_name.org;\n\
                 proxy_cookie_domain ~^(.+)\\.com$ $1.org;\n\
                 proxy_cookie_path /path/ /new/;\n\
                 proxy_cookie_path ~*^/caseless/(.+)$ /$1;\n\
                 location /off/ {{ proxy_pass http://127.0.0.1:{up};\n\
                   proxy_cookie_domain off; proxy_cookie_path off; }}\n\
               }}\n\
               location /xar {{ proxy_pass http://127.0.0.1:{up};\n\
                 proxy_cookie_domain ~^(?<dd>.+)\\.example\\.com$ $dd.test; }}\n\
               location /static/ {{ root {d}; \n\
               }}\n\
             }}\n\
             server {{ listen 127.0.0.1:{up};\n\
               location /xar {{ add_header X-Accel-Redirect /static/f.txt;\n\
                 add_header Set-Cookie \"x=1; Domain=sub.example.com\"; return 200; }}\n\
               location / {{\n\
                 add_header Set-Cookie \"a=1; Domain=www.Example.org; Path=/path/x; Secure\";\n\
                 add_header Set-Cookie \"b=2;Domain=.LocalHost.com;path=/CASEless/y\";\n\
                 add_header Set-Cookie \"c=3; Domain=www.example.COM\";\n\
                 add_header Set-Cookie \"d=4; Domain=other.net; Path=/kept/\";\n\
                 add_header Set-Cookie \"flag; Domain=www.example.org\";\n\
                 return 200 ok;\n\
               }}\n\
             }}\n\
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

    let rewritten = cookies(port, "/");
    let off = cookies(port, "/off/");
    let xar = cookies(port, "/xar");
    drop(child);
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(
        rewritten,
        [
            "a=1; Domain=example.com; Path=/new/x; Secure",
            "b=2; Domain=.en.localhost.org; path=/y",
            "c=3; Domain=www.example.org",
            "d=4; Domain=other.net; Path=/kept/",
            // Not `name=value` first: left alone, as nginx does.
            "flag; Domain=www.example.org",
        ]
    );
    assert_eq!(
        off,
        [
            "a=1; Domain=www.Example.org; Path=/path/x; Secure",
            "b=2;Domain=.LocalHost.com;path=/CASEless/y",
            "c=3; Domain=www.example.COM",
            "d=4; Domain=other.net; Path=/kept/",
            "flag; Domain=www.example.org",
        ]
    );
    // X-Accel-Redirect: the Set-Cookie it carries to the target is the
    // proxied location's to rewrite, as nginx does before it redirects;
    // `(?<dd>…)` is `$dd` in the replacement.
    assert_eq!(xar, ["x=1; Domain=sub.test"]);
}
