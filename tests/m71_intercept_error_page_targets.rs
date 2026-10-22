//! M71 — `proxy_intercept_errors` with an `error_page` whose target is an
//! absolute URL, or a variable that renders empty, as nginx's
//! ngx_http_send_error_page: a redirect to the URL (302 unless `=30x`
//! says otherwise), or no error page at all. Both used to produce an
//! empty response that made the worker panic.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::time::Duration;

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

#[test]
fn absolute_and_empty_intercept_targets() {
    let setup = common::ports::setup_lock();
    let [front, back] = [0, 0].map(|_| {
        TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    });
    let dir = std::env::temp_dir().join(format!("ruxen-m71-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "pid {d}/ruxen.pid;\nevents {{}}\nhttp {{\n\
             server {{ listen 127.0.0.1:{front};\n\
               proxy_intercept_errors on;\n\
               location /abs {{ proxy_pass http://127.0.0.1:{back};\n\
                 error_page 404 http://example.test/nf; }}\n\
               location /moved {{ proxy_pass http://127.0.0.1:{back};\n\
                 error_page 404 =301 http://example.test/gone; }}\n\
               location /empty {{ proxy_pass http://127.0.0.1:{back};\n\
                 error_page 404 $arg_page; }}\n\
             }}\n\
             server {{ listen 127.0.0.1:{back}; location / {{ return 404 upstream404; }} }}\n\
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
            .env("RUXEN_WORKERS", "1")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    common::ports::wait_for_pid_file(&mut child, &dir.join("ruxen.pid"), Duration::from_secs(3));
    drop(setup);

    let abs = get(front, "/abs");
    let moved = get(front, "/moved");
    let empty = get(front, "/empty");
    // The single worker is still serving.
    let again = get(front, "/abs");
    let alive = child.try_wait().unwrap().is_none();
    drop(child);
    let _ = std::fs::remove_dir_all(&dir);

    assert!(alive, "ruxen exited");
    assert!(abs.starts_with("HTTP/1.1 302"), "{abs}");
    assert!(
        abs.contains("\r\nLocation: http://example.test/nf\r\n"),
        "{abs}"
    );
    assert!(moved.starts_with("HTTP/1.1 301"), "{moved}");
    assert!(
        moved.contains("\r\nLocation: http://example.test/gone\r\n"),
        "{moved}"
    );
    assert!(empty.starts_with("HTTP/1.1 404"), "{empty}");
    assert!(empty.ends_with("upstream404"), "{empty}");
    assert!(again.starts_with("HTTP/1.1 302"), "{again}");
}

/// An `error_page` that leads to `proxy_pass` keeps the error's status
/// (404 here, the upstream answering 200), as nginx's `r->err_status`
/// replaces the upstream's; `=` takes the upstream's and `=202` its own
/// (#675).
#[test]
fn a_proxied_error_page_keeps_the_error_status() {
    let setup = common::ports::setup_lock();
    let [front, back] = common::ports::free_ports();
    let dir = std::env::temp_dir().join(format!("ruxen-m71-status-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("html")).unwrap();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "pid {d}/ruxen.pid;\nevents {{}}\nhttp {{\n\
             server {{ listen 127.0.0.1:{front}; root {d}/html;\n\
               location /plain/ {{ error_page 404 /up/plain; }}\n\
               location /same/ {{ error_page 404 = /up/same; }}\n\
               location /code/ {{ error_page 404 =202 /up/code; }}\n\
               location /up/ {{ proxy_pass http://127.0.0.1:{back}; }}\n\
             }}\n\
             server {{ listen 127.0.0.1:{back}; location / {{ return 200 \"from $uri\"; }} }}\n\
             }}\n",
            d = dir.display()
        ),
    )
    .unwrap();
    let mut child = common::KillOnDrop(
        Command::new(env!("CARGO_BIN_EXE_ruxen"))
            .arg("-c")
            .arg(dir.join("nginx.conf"))
            .env("RUXEN_WORKERS", "1")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    common::ports::wait_for_pid_file(&mut child, &dir.join("ruxen.pid"), Duration::from_secs(3));
    drop(setup);

    let plain = get(front, "/plain/none");
    let same = get(front, "/same/none");
    let code = get(front, "/code/none");
    drop(child);
    let _ = std::fs::remove_dir_all(&dir);

    assert!(plain.starts_with("HTTP/1.1 404 Not Found\r\n"), "{plain}");
    assert!(plain.ends_with("from /up/plain"), "{plain}");
    assert!(same.starts_with("HTTP/1.1 200 OK\r\n"), "{same}");
    assert!(same.ends_with("from /up/same"), "{same}");
    assert!(code.starts_with("HTTP/1.1 202 Accepted\r\n"), "{code}");
    assert!(code.ends_with("from /up/code"), "{code}");
}
