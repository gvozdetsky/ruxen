//! M126 — `auth_request` (#358): a subrequest decides access, as nginx's
//! ngx_http_auth_request_module. 2xx lets the request through, 401
//! answers with the subrequest's `WWW-Authenticate`; `auth_request_set`
//! takes values from the subrequest's upstream; the subrequest keeps the
//! request's `$request_uri`, and an `internal` auth location isn't
//! reachable from outside.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

/// The server stops when the test ends, also when an assertion panics.
struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn get(port: u16, path: &str, headers: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: x\r\n{headers}Connection: close\r\n\r\n"
    )
    .unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
    out
}

#[test]
fn auth_request_decides_with_a_subrequest() {
    let dir = std::env::temp_dir().join(format!("ruxen-m126-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("html/private")).unwrap();
    std::fs::write(dir.join("html/private/x"), "secret\n").unwrap();
    // Held until ruxen listens.
    let setup = common::ports::setup_lock();
    let pick = || {
        TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    };
    let (port, auth) = (pick(), pick());
    let d = dir.display();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "worker_processes 1;\npid {d}/ruxen.pid;\nevents {{}}\nhttp {{\naccess_log off;\n\
             server {{ listen 127.0.0.1:{port};\n\
               location /private/ {{\n\
                 auth_request /auth;\n\
                 auth_request_set $user $upstream_http_x_user;\n\
                 auth_request_set $seen $upstream_http_x_seen;\n\
                 add_header X-User $user;\n\
                 add_header X-Seen $seen;\n\
                 root {d}/html; }}\n\
               location = /auth {{ internal;\n\
                 proxy_pass http://127.0.0.1:{auth};\n\
                 proxy_set_header X-Original-URI $request_uri; }} }}\n\
             server {{ listen 127.0.0.1:{auth};\n\
               location / {{\n\
                 if ($http_authorization = \"\") {{\n\
                   add_header WWW-Authenticate 'Basic realm=\"sso\"' always; return 401; }}\n\
                 add_header X-User alice;\n\
                 add_header X-Seen $http_x_original_uri;\n\
                 return 204; }} }} }}\n"
        ),
    )
    .unwrap();
    let mut child = KillOnDrop(
        Command::new(env!("CARGO_BIN_EXE_ruxen"))
            .arg("-c")
            .arg(dir.join("nginx.conf"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    common::ports::wait_for_pid_file(&mut child.0, &dir.join("ruxen.pid"), Duration::from_secs(5));
    drop(setup);

    let denied = get(port, "/private/x", "");
    assert!(denied.starts_with("HTTP/1.1 401 "), "{denied}");
    assert!(
        denied.contains("\r\nWWW-Authenticate: Basic realm=\"sso\"\r\n"),
        "{denied}"
    );

    let allowed = get(port, "/private/x?q=1", "Authorization: Basic x\r\n");
    assert!(allowed.starts_with("HTTP/1.1 200 "), "{allowed}");
    assert!(allowed.contains("\r\nX-User: alice\r\n"), "{allowed}");
    assert!(
        allowed.contains("\r\nX-Seen: /private/x?q=1\r\n"),
        "{allowed}"
    );
    assert!(allowed.ends_with("\r\n\r\nsecret\n"), "{allowed}");

    let direct = get(port, "/auth", "Authorization: Basic x\r\n");
    assert!(direct.starts_with("HTTP/1.1 404 "), "{direct}");
    let _ = std::fs::remove_dir_all(&dir);
}
