//! M145 — the upstream request target (#541), as nginx's
//! ngx_http_proxy_create_request builds it: without a URI part the client's
//! own target while the URI is unchanged, else the decoded URI, escaped
//! (NGX_ESCAPE_URI) when the client's path had a `%` or the request is
//! internal (#575). A `%0D%0A` in the path never becomes a CR LF in the
//! upstream request line. With variables, a rendered URI with a CR, LF or
//! NUL is a 500.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use common::ports::setup_lock;

struct Server {
    child: Child,
    port: u16,
    dir: PathBuf,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// An upstream that answers with the request target it got, between `[`
/// and `]`, and the number of header lines.
fn spawn_target_echo() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in listener.incoming().flatten() {
            let mut s = s;
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                if s.read(&mut byte).unwrap_or(0) == 0 {
                    break;
                }
                head.push(byte[0]);
            }
            let head = String::from_utf8_lossy(&head).into_owned();
            let first = head.split("\r\n").next().unwrap_or("");
            // Everything between the method and the last " HTTP/".
            let target = first
                .split_once(' ')
                .and_then(|(_, rest)| rest.rsplit_once(" HTTP/"))
                .map_or("", |(t, _)| t);
            let lines = head.trim_end().split("\r\n").count() - 1;
            let body = format!("[{target}] lines={lines}");
            let _ = write!(
                s,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    port
}

fn start(up: u16) -> Server {
    let ports = setup_lock();
    let port = {
        let probe = TcpListener::bind("127.0.0.1:0").unwrap();
        probe.local_addr().unwrap().port()
    };
    // One directory per server: the tests run in parallel.
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("ruxen-m145-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "events {{}}\nhttp {{ access_log off; server {{ listen 127.0.0.1:{port};\n\
               location / {{ add_header X-RU $request_uri; proxy_pass http://127.0.0.1:{up}; }}\n\
               location /p/ {{ proxy_pass http://127.0.0.1:{up}/x/; }}\n\
               location /r/ {{ rewrite ^/r/(.*)$ /n/$1 break; proxy_pass http://127.0.0.1:{up}; }}\n\
               location /v/ {{ proxy_pass http://127.0.0.1:{up}$uri; }}\n\
               location /sa/ {{ set $args \"a=1\"; proxy_pass http://127.0.0.1:{up}; }}\n\
               location /se/ {{ set $args \"\"; proxy_pass http://127.0.0.1:{up}; }}\n\
               location /si/ {{ if ($arg_b) {{ set $args \"$args&i=1\"; }}\n\
                 proxy_pass http://127.0.0.1:{up}; }}\n\
               location /sr/ {{ set $args \"a=1\";\n\
                 return 200 \"$args|$arg_a|$arg_b|$is_args|$query_string|$request_uri\"; }}\n\
               location /ru {{ return 200 \"$request_uri|$uri|$args|$is_args\"; }}\n\
               location /t/ {{ try_files $uri @app; }}\n\
               location /e/ {{ error_page 404 = @app; }}\n\
               location /tr/ {{ rewrite ^/tr/(.*)$ /n/$1 break; try_files $uri @app; }}\n\
               location /tu/ {{ try_files $uri /n/; }}\n\
               location @app {{ proxy_pass http://127.0.0.1:{up}; }}\n\
             }} }}\n"
        ),
    )
    .unwrap();
    let mut server = Server {
        child: Command::new(env!("CARGO_BIN_EXE_ruxen"))
            .arg("-c")
            .arg(dir.join("nginx.conf"))
            .arg("-e")
            .arg(dir.join("stderr.log"))
            .arg("-g")
            .arg(format!("pid {}/ruxen.pid;", dir.display()))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
        port,
        dir,
    };
    let pid_file = server.dir.join("ruxen.pid");
    common::ports::wait_for_pid_file(&mut server.child, &pid_file, Duration::from_secs(3));
    drop(ports);
    server
}

fn get(port: u16, target: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(
        s,
        "GET {target} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

#[test]
fn upstream_request_target_is_never_the_raw_decoded_uri() {
    let up = spawn_target_echo();
    let server = start(up);
    for (target, upstream_gets) in [
        // No URI part, URI unchanged: the client's own target.
        ("/a%0D%0AX-Injected:%201", "/a%0D%0AX-Injected:%201"),
        (
            "/a%0D%0A%0D%0AGET%20/admin%20HTTP/1.1",
            "/a%0D%0A%0D%0AGET%20/admin%20HTTP/1.1",
        ),
        ("/a/../b%2Fc?x=1&y=%0D", "/a/../b%2Fc?x=1&y=%0D"),
        ("/plain?q", "/plain?q"),
        // A URI part: the decoded path past the prefix, escaped when the
        // client's path had a `%`.
        ("/p/a%0D%0AX%20%22%7B?q=1", "/x/a%0D%0AX%20%22%7B?q=1"),
        ("/p/caf%C3%A9", "/x/caf%C3%A9"),
        // Rewritten: the new URI, escaped (the request is internal).
        ("/r/a%20b", "/n/a%20b"),
        ("/r/a{b}^c", "/n/a%7Bb%7D%5Ec"),
        // With variables, a clean URI goes as rendered.
        ("/v/ok", "/v/ok"),
        // Bytes nginx takes unencoded in a target (#483): as sent, with a
        // URI part too while the path has no `%` (#575), escaped with one.
        ("/a?j={\"x\":1}&q=a|b", "/a?j={\"x\":1}&q=a|b"),
        ("/p/a{b}^c", "/x/a{b}^c"),
        ("/p/a{b}%20c", "/x/a%7Bb%7D%20c"),
    ] {
        let resp = get(server.port, target);
        assert!(resp.starts_with("HTTP/1.1 200"), "{target}: {resp}");
        // Host and Connection: no injected line.
        assert!(
            resp.ends_with(&format!("[{upstream_gets}] lines=2")),
            "{target}: {resp}"
        );
    }
    // With variables, a decoded CR LF in the rendered URI is refused.
    let resp = get(server.port, "/v/a%0D%0AX-Injected:%201");
    assert!(resp.starts_with("HTTP/1.1 500"), "{resp}");
    let log = std::fs::read_to_string(server.dir.join("stderr.log")).unwrap_or_default();
    assert!(
        log.contains("[error]")
            && log
                .contains("invalid URI \"/v/a\\r\\nX-Injected: 1\" to proxy: a CR, LF or NUL byte"),
        "{log}"
    );
}

/// #543: `set $args` replaces the request's arguments, as nginx's
/// ngx_http_variable_set_args replaces `r->args`: `$args`, `$arg_*` and the
/// upstream request see the new ones.
#[test]
fn set_args_replaces_the_arguments() {
    let up = spawn_target_echo();
    let server = start(up);
    for (target, upstream_gets) in [
        ("/sa/x?b=2", "/sa/x?a=1"),
        ("/sa/x", "/sa/x?a=1"),
        ("/sa/a%20b?b=2", "/sa/a%20b?a=1"),
        // Empty: no `?` at all.
        ("/se/x?b=2", "/se/x"),
        // In an `if`, from the old value.
        ("/si/x?b=2", "/si/x?b=2&i=1"),
        ("/si/x", "/si/x"),
    ] {
        let resp = get(server.port, target);
        assert!(
            resp.ends_with(&format!("[{upstream_gets}] lines=2")),
            "{target}: {resp}"
        );
    }
    let resp = get(server.port, "/sr/x?b=2");
    assert!(resp.ends_with("\r\n\r\na=1|1||?|a=1|/sr/x?b=2"), "{resp}");
}

/// #748: a `#fragment` stays in the client's target, as nginx keeps it in
/// `r->unparsed_uri`: `$request_uri` and an unchanged upstream target have
/// it; `$uri`, `$args` and a URI part stop at the `#`.
#[test]
fn fragment_stays_in_the_unparsed_uri() {
    let up = spawn_target_echo();
    let server = start(up);
    for (target, upstream_gets) in [
        ("/a?b=1#frag", "/a?b=1#frag"),
        ("/a#f?x", "/a#f?x"),
        ("/a%61#f", "/a%61#f"),
        ("http://h/a#f", "/a#f"),
        ("/p/x?y#frag", "/x/x?y"),
        ("/r/x#frag", "/n/x"),
    ] {
        let resp = get(server.port, target);
        assert!(
            resp.ends_with(&format!("[{upstream_gets}] lines=2")),
            "{target}: {resp}"
        );
    }
    for (target, body) in [
        ("/ru?b=1#frag", "/ru?b=1#frag|/ru|b=1|?"),
        ("/ru#f?x", "/ru#f?x|/ru||"),
        ("/ru#", "/ru#|/ru||"),
        ("/ru?a=1#f#g", "/ru?a=1#f#g|/ru|a=1|?"),
        ("http://h/ru#f", "/ru#f|/ru||"),
        ("/ru?a", "/ru?a|/ru|a|?"),
    ] {
        let resp = get(server.port, target);
        assert!(
            resp.ends_with(&format!("\r\n\r\n{body}")),
            "{target}: {resp}"
        );
    }
}

/// #769: an absolute-form target without a path has `$request_uri` from
/// its `?`, as nginx's unparsed_uri; the upstream still gets `/?…`.
#[test]
fn absolute_target_without_a_path() {
    let up = spawn_target_echo();
    let server = start(up);
    for (target, ru, upstream_gets) in [
        ("http://h?a=1", "?a=1", "/?a=1"),
        ("http://h?a=1#f", "?a=1#f", "/?a=1"),
        ("http://h", "/", "/"),
        ("http://h/?a=1", "/?a=1", "/?a=1"),
    ] {
        let resp = get(server.port, target);
        assert!(
            resp.contains(&format!("\r\nX-RU: {ru}\r\n")),
            "{target}: {resp}"
        );
        assert!(
            resp.ends_with(&format!("[{upstream_gets}] lines=2")),
            "{target}: {resp}"
        );
    }
}

/// A jump to a named location (`try_files … @app`, `error_page … @app`)
/// keeps the client's target; a rewrite before it, or a redirect to a URI,
/// sends the escaped `$uri` (#777).
#[test]
fn named_location_keeps_the_client_target() {
    let up = spawn_target_echo();
    let server = start(up);
    for (target, upstream_gets) in [
        ("/t/a%2Fb", "/t/a%2Fb"),
        ("/t/x/../a", "/t/x/../a"),
        ("/t//a", "/t//a"),
        ("/t/%41?q=1", "/t/%41?q=1"),
        ("/t/a\\b", "/t/a\\b"),
        ("/e/a%2Fb", "/e/a%2Fb"),
        ("/tr/a%2Fb", "/n/a/b"),
        ("/tr/a\\b", "/n/a%5Cb"),
        ("/tu/a%2Fb", "/n/"),
    ] {
        let resp = get(server.port, target);
        assert!(
            resp.ends_with(&format!("[{upstream_gets}] lines=2")),
            "{target}: {resp}"
        );
    }
}
