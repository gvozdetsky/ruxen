//! M66 — variables from `set` stay visible after the location handler:
//! in a proxied response's `add_header` and `proxy_redirect`, and in the
//! access log (nginx's `r->variables` live as long as the request). They
//! used to render empty there, so `add_header X $v` vanished.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

fn get(port: u16, path: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

fn header<'a>(resp: &'a str, name: &str) -> Option<&'a str> {
    resp.split("\r\n\r\n").next()?.lines().find_map(|l| {
        let (n, v) = l.split_once(':')?;
        n.eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

#[test]
fn set_variables_reach_the_proxied_response_and_the_log() {
    let ports: Vec<TcpListener> = (0..2)
        .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    let [front, back] = [0, 1].map(|i| ports[i].local_addr().unwrap().port());
    drop(ports);
    let dir = std::env::temp_dir().join(format!("ruxen-m66-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let d = dir.display();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "pid {d}/ruxen.pid;\nevents {{}}\nhttp {{\n\
             log_format f \"$uri v=$v\";\n\
             server {{ listen 127.0.0.1:{front}; access_log {d}/access.log f;\n\
               location / {{\n\
                 set $v var_here;\n\
                 proxy_pass http://127.0.0.1:{back};\n\
                 proxy_redirect http://127.0.0.1:{back}/a/ /$v/;\n\
                 proxy_redirect http://127.0.0.1:{back}/$v/ /replaced/;\n\
                 add_header X-V \"$v\";\n\
               }}\n\
               location /local {{ set $v loc; return 200 ok; }}\n\
             }}\n\
             server {{ listen 127.0.0.1:{back}; access_log off;\n\
               location / {{ return 302 http://127.0.0.1:{back}$uri; }}\n\
               location /ok {{ return 200 ok; }} }}\n\
             }}\n"
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
        assert!(Instant::now() < deadline, "ruxen did not start");
        sleep(Duration::from_millis(10));
    }

    let ok = get(front, "/ok");
    let first = get(front, "/a/x");
    let second = get(front, "/var_here/x");
    let local = get(front, "/local");
    sleep(Duration::from_millis(100));
    let log = std::fs::read_to_string(dir.join("access.log")).unwrap_or_default();
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(header(&ok, "x-v"), Some("var_here"), "{ok}");
    let base = format!("http://x:{front}");
    assert_eq!(
        header(&first, "location"),
        Some(&*format!("{base}/var_here/x")),
        "{first}"
    );
    assert_eq!(header(&first, "x-v"), Some("var_here"), "{first}");
    assert_eq!(
        header(&second, "location"),
        Some(&*format!("{base}/replaced/x")),
        "{second}"
    );
    assert!(local.ends_with("ok"), "{local}");
    assert_eq!(
        log.lines().collect::<Vec<_>>(),
        [
            "/ok v=var_here",
            "/a/x v=var_here",
            "/var_here/x v=var_here",
            "/local v=loc"
        ],
        "{log}"
    );
}
