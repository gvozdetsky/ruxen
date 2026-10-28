//! M165 — a `{` that doesn't start a quantifier is a literal, as in
//! nginx's PCRE2, in every configuration regex (#763); PCRE2 10.43+'s
//! `{,n}` and `{ n }` quantifiers too. Responses checked against nginx
//! 1.30.6 with PCRE2 10.46.

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::time::Duration;

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
    out
}

#[test]
fn literal_braces_in_regexes() {
    let dir = std::env::temp_dir().join(format!("ruxen-m165-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let setup = common::ports::setup_lock();
    let [port] = common::ports::free_ports();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            r#"pid {d}/ruxen.pid;
events {{}}
http {{
  access_log off;
  map $uri $m {{ "~^/m{{x}}" m; "~^/n{{,2}}$" n; default -; }}
  server {{ listen 127.0.0.1:{port}; server_name "~^w{{x}}\.example$" x;
    gzip_disable "a{{x}}";
    location ~ "^/a{{x}}(.*)$" {{ return 200 "a:$1"; }}
    location ~ "^${{PREFIX}}(.*)$" {{ return 200 "p:$1"; }}
    location ~ "^/b{{ 2 }}$" {{ return 200 "b2"; }}
    location ~ "^/c{{,2}}$" {{ return 200 "c"; }}
    location /r {{ rewrite "^/r{{y}}(.*)$" "/a{{x}}$1" last;
                   if ($uri ~ "^/r{{z}}") {{ return 200 "if"; }} return 200 "r"; }}
    location / {{ return 200 "m:$m"; }}
  }}
}}
"#,
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

    let cases = [
        ("/a%7Bx%7D/q", "a:/q"),
        ("/bb", "b2"),
        ("/b", "m:-"),
        ("/c", "c"),
        ("/cc", "c"),
        ("/ccc", "m:-"),
        ("/r%7By%7D/k", "a:/k"),
        ("/r%7Bz%7D", "if"),
        ("/m%7Bx%7D", "m:m"),
        ("/nn", "m:n"),
        ("/nnn", "m:-"),
    ];
    let got: Vec<String> = cases
        .iter()
        .map(|(path, _)| {
            let resp = get(port, path);
            resp.split_once("\r\n\r\n")
                .map_or("", |(_, b)| b)
                .to_string()
        })
        .collect();
    drop(child);
    let _ = std::fs::remove_dir_all(&dir);
    for ((path, want), got) in cases.iter().zip(&got) {
        assert_eq!(got, want, "{path}");
    }
}
