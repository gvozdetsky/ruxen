//! M133 — `include` with a pattern (#35), as ngx_conf_include does it:
//! glob(3) with its default flags, so the matches are sorted and `*`
//! skips dot files; a pattern that matches nothing is fine; `-T` dumps
//! every file in the order it was read.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::time::Duration;

fn ruxen(flag: &str, conf: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .arg(flag)
        .arg("-c")
        .arg(conf)
        .output()
        .unwrap()
}

#[test]
fn include_patterns_like_nginx() {
    let dir = std::env::temp_dir().join(format!("ruxen-m133-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("conf.d")).unwrap();
    std::fs::create_dir_all(dir.join("snippets")).unwrap();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "pid {d}/ruxen.pid;\nevents {{}}\nhttp {{\naccess_log off;\n\
             include conf.d/*.conf;\ninclude nothing/*.conf;\n}}\n",
            d = dir.display()
        ),
    )
    .unwrap();
    std::fs::write(
        dir.join("conf.d/b.conf"),
        format!(
            "server {{ listen 127.0.0.1:{port};\n\
             location / {{ include snippets/??-*.conf; return 200 ok; }} }}\n"
        ),
    )
    .unwrap();
    std::fs::write(dir.join("conf.d/a.conf"), "map $uri $m { default 1; }\n").unwrap();
    // Not matched by `*`, as glob(3) skips dot files.
    std::fs::write(dir.join("conf.d/.hidden.conf"), "not a directive\n").unwrap();
    std::fs::write(dir.join("snippets/20-b.conf"), "add_header X-Order b;\n").unwrap();
    std::fs::write(dir.join("snippets/10-a.conf"), "add_header X-Order a;\n").unwrap();

    // -T: each file once, in the order read.
    let dump = ruxen("-T", &dir.join("nginx.conf"));
    let stdout = String::from_utf8_lossy(&dump.stdout);
    assert!(
        dump.status.success(),
        "{}",
        String::from_utf8_lossy(&dump.stderr)
    );
    let order: Vec<&str> = stdout
        .lines()
        .filter_map(|l| l.strip_prefix("# configuration file "))
        .map(|l| l.rsplit('/').next().unwrap())
        .collect();
    assert_eq!(
        order,
        [
            "nginx.conf:",
            "a.conf:",
            "b.conf:",
            "10-a.conf:",
            "20-b.conf:"
        ],
        "{stdout}"
    );

    // The matches apply in sorted order.
    let setup = common::ports::setup_lock();
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
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut raw = String::new();
    s.read_to_string(&mut raw).unwrap();
    let a = raw.find("X-Order: a\r\n").expect(&raw);
    let b = raw.find("X-Order: b\r\n").expect(&raw);
    assert!(a < b, "{raw}");
    let _ = child.0.kill();
    let _ = child.0.wait();

    // A bad directive in a matched file is reported in that file.
    std::fs::write(dir.join("conf.d/c.conf"), "bogus_directive;\n").unwrap();
    let check = ruxen("-t", &dir.join("nginx.conf"));
    let stderr = String::from_utf8_lossy(&check.stderr);
    assert!(!check.status.success());
    assert!(stderr.contains("conf.d/c.conf:1"), "{stderr}");
    let _ = std::fs::remove_dir_all(&dir);
}
