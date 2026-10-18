//! M139 — `$hostname` is `gethostname()` lowercased, as nginx's
//! ngx_init_cycle sets `cycle->hostname` (#491). The mixed-case name runs
//! ruxen in a UTS namespace of its own (`unshare --user --uts`), where
//! unprivileged user namespaces are allowed.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::time::Duration;

/// Starts ruxen through `wrap` (a command line ruxen's arguments are
/// appended to, or none), `main` heading its configuration, and returns
/// the body of its `$hostname` answer.
fn served_hostname(name: &str, wrap: &[&str], main: &str) -> String {
    let dir = std::env::temp_dir().join(format!("ruxen-m139-{name}-{}", std::process::id()));
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
            "{main}pid {d}/ruxen.pid;\nevents {{}}\nhttp {{\naccess_log off;\n\
             server {{ listen 127.0.0.1:{port}; return 200 \"[$hostname]\"; }}\n}}\n",
            d = dir.display()
        ),
    )
    .unwrap();
    let ruxen = env!("CARGO_BIN_EXE_ruxen");
    let mut cmd = match wrap.split_first() {
        Some((program, args)) => {
            let mut cmd = Command::new(program);
            cmd.args(args).arg(ruxen);
            cmd
        }
        None => Command::new(ruxen),
    };
    let setup = common::ports::setup_lock();
    let mut child = common::KillOnDrop(
        cmd.arg("-c")
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
    s.write_all(b"GET / HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut raw = String::new();
    s.read_to_string(&mut raw).unwrap();
    let _ = child.0.kill();
    let _ = child.0.wait();
    let _ = std::fs::remove_dir_all(&dir);
    raw.split_once("\r\n\r\n").unwrap().1.to_string()
}

#[test]
fn hostname_is_the_machine_name_lowercased() {
    let mut buf = [0u8; 256];
    // SAFETY: the buffer is valid for `buf.len()` bytes.
    assert_eq!(
        unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) },
        0
    );
    let len = buf.iter().position(|&b| b == 0).unwrap();
    let expected = String::from_utf8_lossy(&buf[..len]).to_ascii_lowercase();
    assert_eq!(served_hostname("host", &[], ""), format!("[{expected}]"));
}

#[test]
fn mixed_case_hostname_is_lowercased() {
    let unshare = ["unshare", "--user", "--map-root-user", "--uts"];
    let probe = Command::new(unshare[0])
        .args(&unshare[1..])
        .args(["hostname", "probe"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    if !probe.is_ok_and(|s| s.success()) {
        eprintln!("skipped: no unprivileged UTS namespace");
        return;
    }
    // `hostname` in the new namespace, then ruxen in place of the shell.
    let mut wrap = unshare.to_vec();
    wrap.extend([
        "sh",
        "-c",
        "hostname Ruxen-M139.Example && exec \"$0\" \"$@\"",
    ]);
    // Root in the namespace: without `user root` ruxen would switch to
    // nobody, whose uid isn't mapped there.
    assert_eq!(
        served_hostname("uts", &wrap, "user root;\n"),
        "[ruxen-m139.example]"
    );
}
