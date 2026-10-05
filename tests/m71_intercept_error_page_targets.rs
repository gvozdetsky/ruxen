//! M71 — `proxy_intercept_errors` with an `error_page` whose target is an
//! absolute URL, or a variable that renders empty, as nginx's
//! ngx_http_send_error_page: a redirect to the URL (302 unless `=30x`
//! says otherwise), or no error page at all. Both used to produce an
//! empty response that made the worker panic.

mod common;

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
    let mut child = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .arg("-c")
        .arg(dir.join("nginx.conf"))
        .env("RUXEN_WORKERS", "1")
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

    let abs = get(front, "/abs");
    let moved = get(front, "/moved");
    let empty = get(front, "/empty");
    // The single worker is still serving.
    let again = get(front, "/abs");
    let alive = child.try_wait().unwrap().is_none();
    let _ = child.kill();
    let _ = child.wait();
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
