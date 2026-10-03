// End-to-end tests for M14 changes — variable liberalization, nested
// `location`, server-scope `return`, strict `$http_NAME` lookup,
// `merge_slashes off`, strong-form ETag wire format, and conditional-GET
// / `If-Match` / `If-Range` polish. Each test spins up a real ruxen
// process against a small config so we cover the full parse + prepare +
// worker path that the upstream Perl suite exercises.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, MutexGuard};
use std::thread::sleep;
use std::time::{Duration, Instant};

struct ServerGuard {
    child: Child,
    tempdir: PathBuf,
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.tempdir);
    }
}

static SETUP_LOCK: Mutex<()> = Mutex::new(());

fn pick_port() -> (u16, MutexGuard<'static, ()>) {
    let g = SETUP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let p = l.local_addr().unwrap().port();
    drop(l);
    (p, g)
}

fn unique_dir() -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let d = std::env::temp_dir().join(format!(
        "ruxen-m14-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir(&d).unwrap();
    d
}

fn wait_for_listen(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        if Instant::now() > deadline {
            panic!("ruxen did not start listening on port {port}");
        }
        sleep(Duration::from_millis(20));
    }
}

fn spawn_server(conf: &str) -> (ServerGuard, u16) {
    let (port, _lock) = pick_port();
    let dir = unique_dir();
    let conf_path = dir.join("ruxen.conf");
    let conf = conf
        .replace("%%PORT%%", &port.to_string())
        .replace("%%TESTDIR%%", dir.to_str().unwrap());
    std::fs::write(&conf_path, conf).unwrap();

    let child = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .args(["-c", conf_path.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ruxen");

    wait_for_listen(port);
    (
        ServerGuard {
            child,
            tempdir: dir,
        },
        port,
    )
}

fn send_request(port: u16, req: &[u8]) -> Vec<u8> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    s.write_all(req).unwrap();
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match s.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(_) => break,
        }
    }
    out
}

fn http_get(port: u16, path: &str) -> Vec<u8> {
    let req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    send_request(port, req.as_bytes())
}

fn status_line(resp: &[u8]) -> &str {
    let end = resp.iter().position(|&b| b == b'\r').unwrap_or(resp.len());
    std::str::from_utf8(&resp[..end]).unwrap()
}

fn header_value<'a>(resp: &'a [u8], name: &str) -> Option<&'a str> {
    let s = std::str::from_utf8(resp).ok()?;
    let header_end = s.find("\r\n\r\n").unwrap_or(s.len());
    for line in s[..header_end].split("\r\n").skip(1) {
        if let Some((k, v)) = line.split_once(':') {
            if k.eq_ignore_ascii_case(name) {
                return Some(v.trim());
            }
        }
    }
    None
}

fn body(resp: &[u8]) -> &[u8] {
    resp.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| &resp[i + 4..])
        .unwrap_or(&[])
}

#[test]
fn unsupported_nginx_variable_renders_empty() {
    // A variable nginx has but ruxen doesn't implement yet loads with a
    // warning and renders empty. (A name nginx doesn't know is an
    // `unknown "x" variable` error, as in nginx.)
    let conf = r#"
events { }
http {
  server {
    listen 127.0.0.1:%%PORT%%;
    location / {
      add_header X-Known $uri;
      add_header X-Undef $tcpinfo_rtt;
      return 200 "before|$tcpinfo_rtt|after";
    }
  }
}
"#;
    let (_g, port) = spawn_server(conf);
    let r = http_get(port, "/path");
    assert_eq!(status_line(&r), "HTTP/1.1 200 OK");
    assert_eq!(header_value(&r, "X-Known"), Some("/path"));
    // nginx omits add_header entries whose rendered value is empty
    // (`ngx_http_headers_filter_module.c::ngx_http_add_header`); the
    // variable still expands to empty in the body, just no header is
    // emitted on the wire.
    assert_eq!(header_value(&r, "X-Undef"), None);
    assert_eq!(body(&r), b"before||after");
}

#[test]
fn http_name_variable_reads_request_header() {
    // `$http_x_foo` should case-insensitively pluck the `X-Foo` header
    // from the request. Underscores on the variable name map to dashes
    // on the wire, matching nginx.
    let conf = r#"
events { }
http {
  server {
    listen 127.0.0.1:%%PORT%%;
    location / {
      add_header X-Seen $http_x_custom_header;
      return 200 "";
    }
  }
}
"#;
    let (_g, port) = spawn_server(conf);
    let r = send_request(
        port,
        b"GET / HTTP/1.1\r\nHost: localhost\r\nX-Custom-Header: hello world\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_line(&r), "HTTP/1.1 200 OK");
    assert_eq!(header_value(&r, "X-Seen"), Some("hello world"));

    // Missing request header renders the variable empty, and nginx skips
    // emitting `add_header` entries with empty values — so X-Seen is
    // absent here, not an empty-valued header.
    let r2 = http_get(port, "/");
    assert_eq!(header_value(&r2, "X-Seen"), None);
}

#[test]
fn connection_variables_count_requests_on_reused_connection() {
    // `$connection_requests` increments across keep-alive requests on the
    // same connection. Run three GETs on a single TCP session and check
    // the header values rise 1, 2, 3.
    let conf = r#"
events { }
http {
  server {
    listen 127.0.0.1:%%PORT%%;
    location / {
      add_header X-Req $connection_requests;
      return 200 "";
    }
  }
}
"#;
    let (_g, port) = spawn_server(conf);

    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    // Pipeline three requests; read them back one response at a time.
    for _ in 0..3 {
        s.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .unwrap();
    }
    let mut all = Vec::new();
    let mut buf = [0u8; 4096];
    // Keep reading until we've seen three `\r\n\r\n` terminators or EOF.
    let deadline = Instant::now() + Duration::from_secs(2);
    while all.windows(4).filter(|w| *w == b"\r\n\r\n").count() < 3 && Instant::now() < deadline {
        match s.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => all.extend_from_slice(&buf[..n]),
            Err(_) => break,
        }
    }
    let text = std::str::from_utf8(&all).unwrap();
    let counts: Vec<&str> = text
        .split("\r\n")
        .filter(|l| l.starts_with("X-Req:"))
        .map(|l| l["X-Req:".len()..].trim())
        .collect();
    assert_eq!(counts, vec!["1", "2", "3"]);
}

#[test]
fn server_scope_return_answers_every_request() {
    // `return 204;` at server scope runs in nginx's SERVER_REWRITE phase,
    // before the location search, so it answers every request (checked
    // against nginx 1.24). It used to fire only when no location matched.
    let conf = r#"
events { }
http {
  server {
    listen 127.0.0.1:%%PORT%%;
    return 204;
    location = /hit { return 200 "hit"; }
  }
}
"#;
    let (_g, port) = spawn_server(conf);
    assert!(status_line(&http_get(port, "/hit")).starts_with("HTTP/1.1 204"));
    assert!(status_line(&http_get(port, "/miss")).starts_with("HTTP/1.1 204"));
}

#[test]
fn server_scope_rewrite_set_and_if() {
    // The server rewrite program runs before the location search: `if`,
    // `set` and `rewrite` at server scope, as nginx. They used to fail the
    // config (`unknown directive "if" in server`).
    let conf = r#"
events { }
http {
  server {
    listen 127.0.0.1:%%PORT%%;
    set $who server;
    if ($arg_deny) { return 403; }
    rewrite ^/old/(.*)$ /new/$1;
    location /new/ { return 200 "new $uri $who"; }
    location / { return 200 "other $who"; }
  }
}
"#;
    let (_g, port) = spawn_server(conf);
    let r = http_get(port, "/old/x");
    assert_eq!(body(&r), b"new /new/x server");
    assert_eq!(body(&http_get(port, "/y")), b"other server");
    assert!(status_line(&http_get(port, "/y?deny=1")).starts_with("HTTP/1.1 403"));
}

#[test]
fn nested_location_is_flattened_into_siblings() {
    // A `location` declared inside another location is parsed successfully
    // and participates in normal longest-prefix matching at the server
    // level. Before M14 the parser rejected this with `unknown directive
    // "location" in location`.
    let conf = r#"
events { }
http {
  server {
    listen 127.0.0.1:%%PORT%%;
    location /outer/ {
      return 200 "outer";
      location /outer/inner/ {
        return 200 "inner";
      }
    }
    location / { return 404 "none"; }
  }
}
"#;
    let (_g, port) = spawn_server(conf);
    assert_eq!(body(&http_get(port, "/outer/other")), b"outer");
    assert_eq!(body(&http_get(port, "/outer/inner/x")), b"inner");
    assert_eq!(status_line(&http_get(port, "/")), "HTTP/1.1 404 Not Found");
}

#[test]
fn merge_slashes_off_preserves_empty_segments() {
    // With `merge_slashes off`, `/foo//../bar` resolves to `/foo/bar`
    // (the `..` removes the empty segment between the two slashes, not
    // the `foo` segment as it would when merging is on).
    let conf = r#"
events { }
http {
  server {
    listen 127.0.0.1:%%PORT%%;
    merge_slashes off;
    location / {
      add_header X-URI $uri;
      return 204;
    }
  }
}
"#;
    let (_g, port) = spawn_server(conf);
    let r = http_get(port, "/foo//../bar");
    assert_eq!(header_value(&r, "X-URI"), Some("/foo/bar"));
    let r = http_get(port, "/foo///../bar");
    assert_eq!(header_value(&r, "X-URI"), Some("/foo//bar"));
}

#[test]
fn merge_slashes_on_by_default_collapses_duplicate_slashes() {
    // Default behavior: `/foo//bar` normalizes to `/foo/bar`.
    let conf = r#"
events { }
http {
  server {
    listen 127.0.0.1:%%PORT%%;
    location / {
      add_header X-URI $uri;
      return 204;
    }
  }
}
"#;
    let (_g, port) = spawn_server(conf);
    let r = http_get(port, "/foo//bar");
    assert_eq!(header_value(&r, "X-URI"), Some("/foo/bar"));
}

#[test]
fn absolute_form_request_with_query_and_no_path_synthesises_slash() {
    // `GET http://host?args HTTP/1.1` has no path byte but carries a
    // query. The worker splices a `/` in front of `?args` so normal URI
    // variables populate correctly.
    let conf = r#"
events { }
http {
  server {
    listen 127.0.0.1:%%PORT%%;
    location / {
      add_header X-URI $uri;
      add_header X-Args $args;
      add_header X-Req  $request_uri;
      return 204;
    }
  }
}
"#;
    let (_g, port) = spawn_server(conf);
    let r = send_request(
        port,
        b"GET http://localhost?k=v HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_line(&r), "HTTP/1.1 204 No Content");
    assert_eq!(header_value(&r, "X-URI"), Some("/"));
    assert_eq!(header_value(&r, "X-Args"), Some("k=v"));
    assert_eq!(header_value(&r, "X-Req"), Some("/?k=v"));
}

#[test]
fn uri_normalizer_strips_dot_segments_before_query_and_fragment() {
    // `/foo/bar/.?args` previously produced `/foo/bar` because the `?`
    // arm popped both the `.` and the preceding `/`. Fixed so only the
    // `.` comes off, preserving the slash.
    let conf = r#"
events { }
http {
  server {
    listen 127.0.0.1:%%PORT%%;
    location / {
      add_header X-URI $uri;
      add_header X-Args $args;
      return 204;
    }
  }
}
"#;
    let (_g, port) = spawn_server(conf);
    let r = send_request(
        port,
        b"GET /foo/bar/.?a=1 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(header_value(&r, "X-URI"), Some("/foo/bar/"));
    assert_eq!(header_value(&r, "X-Args"), Some("a=1"));

    let r = send_request(
        port,
        b"GET /foo/bar/..?a=1 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(header_value(&r, "X-URI"), Some("/foo/"));
    assert_eq!(header_value(&r, "X-Args"), Some("a=1"));
}

#[test]
fn strong_form_etag_matches_if_match_and_rejects_weak_prefix() {
    // Our emitted ETag is the strong-form `"hex-hex"` (no `W/`), matching
    // nginx's wire format. `If-Match` uses strong comparison: echoing the
    // header verbatim succeeds (200), prefixing with `W/` forces 412.
    let dir = unique_dir();
    std::fs::write(dir.join("t"), b"abc").unwrap();
    let testdir = dir.to_str().unwrap().to_string();
    let conf = format!(
        r#"
events {{ }}
http {{
  server {{
    listen 127.0.0.1:%%PORT%%;
    root {testdir};
    location / {{ }}
  }}
}}
"#
    );
    let (_g, port) = spawn_server(&conf);
    let first = http_get(port, "/t");
    let etag = header_value(&first, "ETag").expect("etag");
    assert!(
        etag.starts_with('"'),
        "ETag should be strong-form, got {etag}"
    );

    // Exact echo → strong compare succeeds → 200.
    let ok = send_request(
        port,
        format!(
            "GET /t HTTP/1.1\r\nHost: localhost\r\nIf-Match: {etag}\r\nConnection: close\r\n\r\n"
        )
        .as_bytes(),
    );
    assert_eq!(status_line(&ok), "HTTP/1.1 200 OK");

    // Prefix with W/ → strong compare fails → 412.
    let pf = send_request(
        port,
        format!(
            "GET /t HTTP/1.1\r\nHost: localhost\r\nIf-Match: W/{etag}\r\nConnection: close\r\n\r\n"
        )
        .as_bytes(),
    );
    assert_eq!(status_line(&pf), "HTTP/1.1 412 Precondition Failed");

    // `*` always matches an existing resource.
    let star = send_request(
        port,
        b"GET /t HTTP/1.1\r\nHost: localhost\r\nIf-Match: *\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_line(&star), "HTTP/1.1 200 OK");

    // If-Match on a missing file is ignored — the 404 short-circuits
    // precondition evaluation (RFC 9110 §13.1.1).
    let miss = send_request(
        port,
        b"GET /nx HTTP/1.1\r\nHost: localhost\r\nIf-Match: \"whatever\"\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_line(&miss), "HTTP/1.1 404 Not Found");
}

#[test]
fn if_none_match_accepts_comma_separated_list_and_weak_form() {
    let dir = unique_dir();
    std::fs::write(dir.join("t"), b"abc").unwrap();
    let testdir = dir.to_str().unwrap().to_string();
    let conf = format!(
        r#"
events {{ }}
http {{
  server {{
    listen 127.0.0.1:%%PORT%%;
    root {testdir};
    location / {{ }}
  }}
}}
"#
    );
    let (_g, port) = spawn_server(&conf);
    let first = http_get(port, "/t");
    let etag = header_value(&first, "ETag").expect("etag");

    // Tag buried in the middle of a comma list → 304.
    let list = format!("\"foo\", \"bar\", {etag}, \"baz\"");
    let r = send_request(
        port,
        format!("GET /t HTTP/1.1\r\nHost: localhost\r\nIf-None-Match: {list}\r\nConnection: close\r\n\r\n").as_bytes(),
    );
    assert_eq!(status_line(&r), "HTTP/1.1 304 Not Modified");

    // Weak form (`W/`) on client side still matches via weak comparison.
    let weak = format!("W/{etag}");
    let r = send_request(
        port,
        format!("GET /t HTTP/1.1\r\nHost: localhost\r\nIf-None-Match: {weak}\r\nConnection: close\r\n\r\n").as_bytes(),
    );
    assert_eq!(status_line(&r), "HTTP/1.1 304 Not Modified");

    // No-match → full 200.
    let r = send_request(
        port,
        b"GET /t HTTP/1.1\r\nHost: localhost\r\nIf-None-Match: \"nope\"\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status_line(&r), "HTTP/1.1 200 OK");
}

#[test]
fn server_scope_return_takes_server_error_page_and_add_header_once() {
    // nginx 1.24: the 404 goes to `error_page 404 /e`, whose internal
    // redirect runs the server `return 404` again; the second 404 doesn't
    // take the error page again, and the server's `add_header … always`
    // is on the final response.
    let conf = r#"
events { }
http {
  server {
    listen 127.0.0.1:%%PORT%%;
    add_header X-S s always;
    error_page 404 /e;
    return 404;
    location = /e { return 200 "e"; }
  }
}
"#;
    let (_g, port) = spawn_server(conf);
    let r = http_get(port, "/x");
    assert!(status_line(&r).starts_with("HTTP/1.1 404"));
    assert_eq!(header_value(&r, "X-S"), Some("s"));
    assert_ne!(body(&r), b"e");
}
