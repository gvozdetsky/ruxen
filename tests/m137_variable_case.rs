//! M137 — variable names are case-insensitive, as nginx lowercases each
//! one it defines or looks up (#459): `${SSL_REDIRECT}` after
//! `set $ssl_redirect`, `$Host`, `$Http_X_Foo`; `$ARG_A` finds `a` (and
//! `A`), since ngx_http_arg matches the argument's name whatever its case.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::time::Duration;

#[test]
fn variable_names_ignore_case() {
    let dir = std::env::temp_dir().join(format!("ruxen-m137-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "pid {d}/ruxen.pid;\nevents {{}}\nhttp {{\naccess_log off;\n\
             map $Arg_M $Mapped {{ default none; x yes; }}\n\
             server {{ listen 127.0.0.1:{port};\n\
             set $ssl_redirect \"x\"; set $MyVar \"m\";\n\
             return 200 \"[$Host] [${{SSL_REDIRECT}}] [$ARG_A] [$Http_X_Foo] [$myvar] [$mapped]\";\n\
             }}\n}}\n",
            d = dir.display()
        ),
    )
    .unwrap();
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
    let get = |target: &str| {
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        write!(
            s,
            "GET {target} HTTP/1.1\r\nHost: h\r\nX-Foo: bar\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
        let mut raw = String::new();
        s.read_to_string(&mut raw).unwrap();
        raw.split_once("\r\n\r\n").unwrap().1.to_string()
    };
    assert_eq!(get("/?a=1&m=x"), "[h] [x] [1] [bar] [m] [yes]");
    assert_eq!(get("/?A=2&M=x"), "[h] [x] [2] [bar] [m] [yes]");
    let _ = child.0.kill();
    let _ = child.0.wait();
    let _ = std::fs::remove_dir_all(&dir);
}
