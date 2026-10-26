//! M164 — shadow mode (#751): ruxen logs the shadow's JSON lines with the
//! `log_format` docs/shadow.md gives, keyed by nginx's request id, and
//! scripts/shadow-report.py joins them with nginx's log.

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// The shadow side's `log_format` from docs/shadow.md, so the guide and
/// this test can't drift apart.
fn guide_log_format() -> String {
    let guide =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/shadow.md"))
            .unwrap();
    let start = guide
        .find("log_format ruxen_shadow escape=json '{\"id\":\"$http_x_shadow_request_id\"")
        .expect("the shadow's log_format in docs/shadow.md");
    let end = start + guide[start..].find("';").unwrap() + 2;
    guide[start..end].to_string()
}

fn get(port: u16, path: &str, id: &str) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: shadow\r\nX-Shadow-Request-Id: {id}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
}

#[test]
fn m164_shadow_log_joins_with_nginx_log() {
    let python = Command::new("python3").arg("--version").output();
    if !python.is_ok_and(|o| o.status.success()) {
        eprintln!("skipped: no python3");
        return;
    }
    let dir = std::env::temp_dir().join(format!("ruxen-m164-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("html")).unwrap();
    std::fs::write(dir.join("html/a.txt"), "hello").unwrap();
    let setup = common::ports::setup_lock();
    let [port] = common::ports::free_ports::<1>();
    let d = dir.display();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "events {{}}\nhttp {{ types {{ text/plain txt; }}\n{}\n\
             server {{ listen 127.0.0.1:{port}; root {d}/html;\n\
             access_log {d}/shadow.log ruxen_shadow;\n\
             location /gone {{ return 404; }} }} }}\n",
            guide_log_format()
        ),
    )
    .unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .arg("-c")
        .arg(dir.join("nginx.conf"))
        .arg("-g")
        .arg(format!("pid {d}/ruxen.pid; error_log {d}/error.log;"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut server = common::KillOnDrop(child);
    common::ports::wait_for_pid_file(&mut server, &dir.join("ruxen.pid"), Duration::from_secs(5));
    drop(setup);

    get(port, "/a.txt", "id-same");
    get(port, "/gone", "id-status");
    let log = dir.join("shadow.log");
    let deadline = Instant::now() + Duration::from_secs(5);
    let lines = loop {
        let text = std::fs::read_to_string(&log).unwrap_or_default();
        if text.lines().count() >= 2 || Instant::now() > deadline {
            break text;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    assert!(
        lines.contains(
            r#"{"id":"id-same","method":"GET","uri":"/a.txt","status":"200","bytes":"5","length":"5","type":"text/plain","encoding":"","location":"","upstream_status":""}"#
        ),
        "{lines}"
    );

    // nginx's side: the same answer, a different status, a request it
    // didn't mirror (a POST) and one ruxen never got.
    let entry = |id: &str, mirrored: &str, method: &str, uri: &str, status: &str| {
        format!(
            r#"{{"id":"{id}","mirrored":"{mirrored}","method":"{method}","uri":"{uri}","status":"{status}","bytes":"5","length":"5","type":"text/plain","encoding":"","location":"","upstream_status":""}}"#
        )
    };
    let nginx_log = dir.join("nginx.log");
    std::fs::write(
        &nginx_log,
        [
            entry("id-same", "1", "GET", "/a.txt", "200"),
            entry("id-status", "1", "GET", "/gone", "200"),
            entry("id-post", "0", "POST", "/a.txt", "200"),
            entry("id-lost", "1", "GET", "/a.txt", "200"),
        ]
        .join("\n"),
    )
    .unwrap();
    let out = Command::new("python3")
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/shadow-report.py"))
        .arg(&nginx_log)
        .arg(&log)
        .output()
        .unwrap();
    let report = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{report}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    for want in [
        "nginx answered 4 requests; 3 were mirrored to ruxen",
        "compared: 2; the same: 1 (50.0%); different: 1",
        "no ruxen answer for 1 mirrored requests",
        "| status | 1 | `200` → `404` (1) |",
        "| `GET /gone` | `200 size=5` | `404 size=",
    ] {
        assert!(report.contains(want), "missing {want:?} in\n{report}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}
