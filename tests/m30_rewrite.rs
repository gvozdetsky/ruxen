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
        "ruxen-m30-{}-{}",
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

fn spawn_server(conf_body: &str) -> (ServerGuard, u16) {
    let (port, _lock) = pick_port();
    let dir = unique_dir();
    let conf_path = dir.join("ruxen.conf");
    std::fs::write(
        &conf_path,
        conf_body
            .replace("%%PORT%%", &port.to_string())
            .replace("%%DIR%%", dir.to_str().unwrap()),
    )
    .unwrap();

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

fn http_get(port: u16, path: &str) -> Vec<u8> {
    let req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    s.write_all(req.as_bytes()).unwrap();
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

fn status_line(resp: &[u8]) -> &str {
    let end = resp.iter().position(|&b| b == b'\r').unwrap_or(resp.len());
    std::str::from_utf8(&resp[..end]).unwrap()
}

fn header_value<'a>(resp: &'a [u8], name: &str) -> Option<&'a str> {
    let end = resp.windows(4).position(|w| w == b"\r\n\r\n")?;
    let mut i = 0;
    let headers = &resp[..end];
    while i < headers.len() {
        let line_end = headers[i..]
            .windows(2)
            .position(|w| w == b"\r\n")
            .map(|p| i + p)
            .unwrap_or(headers.len());
        let line = &headers[i..line_end];
        if let Some(colon) = line.iter().position(|&b| b == b':') {
            let (n, v) = line.split_at(colon);
            if n.eq_ignore_ascii_case(name.as_bytes()) {
                let mut v = &v[1..];
                while let Some((&b, rest)) = v.split_first() {
                    if b != b' ' && b != b'\t' {
                        break;
                    }
                    v = rest;
                }
                return std::str::from_utf8(v).ok();
            }
        }
        i = line_end + 2;
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
fn rewrite_redirect_last_and_location_captures_work() {
    let conf = r#"
events {}
http {
  server {
    listen 127.0.0.1:%%PORT%%;

    location /t1 {
      rewrite ^ $arg_r? redirect;
    }

    location /from {
      rewrite ^ /to last;
      return 200 "from";
    }

    location /to {
      return 200 "to";
    }

    location ~ ^/cap/(.*)$ {
      set $x $1;
      return 200 "$x";
    }
  }
}
"#;

    let (_guard, port) = spawn_server(conf);

    let escaped = http_get(port, "/t1?r=http%3A%2F%2Fexample.com%2F%3Ffrom");
    assert_eq!(status_line(&escaped), "HTTP/1.1 302 Moved Temporarily");
    assert_eq!(
        header_value(&escaped, "Location"),
        Some("http://example.com/?from")
    );

    let split = http_get(port, "/t1?r=http%3A%2F%2Fexample.com%0D%0Asplit");
    assert_eq!(status_line(&split), "HTTP/1.1 302 Moved Temporarily");
    assert_eq!(
        header_value(&split, "Location"),
        Some("http://example.com%0D%0Asplit")
    );

    let rerouted = http_get(port, "/from");
    assert_eq!(status_line(&rerouted), "HTTP/1.1 200 OK");
    assert_eq!(body(&rerouted), b"to");

    let captured = http_get(port, "/cap/value");
    assert_eq!(status_line(&captured), "HTTP/1.1 200 OK");
    assert_eq!(body(&captured), b"value");
}

/// A response from the location's rewrite program goes through the
/// location's `add_header` and `error_page` like a handler's (#362); one
/// from inside an `if` with settings, through the block's. A `return` with
/// text skips `error_page`, as nginx sends it directly.
#[test]
fn rewrite_responses_get_the_location_filters() {
    let conf = r#"
events {}
http {
  access_log off;
  server {
    listen 127.0.0.1:%%PORT%%;

    location /hdr {
      add_header X-A a always;
      if ($arg_a) { return 200 "if"; }
      rewrite ^/hdr/r$ http://example.com/ redirect;
      return 200 "loc";
    }

    location /err {
      error_page 403 /page;
      if ($arg_a) { return 403; }
      if ($arg_b) { error_page 403 /other; return 403; }
      if ($arg_t) { return 403 "text"; }
      return 200 "ok";
    }

    location = /page { return 200 "page"; }
    location = /other { return 200 "other"; }
  }
}
"#;

    let (_guard, port) = spawn_server(conf);

    let in_if = http_get(port, "/hdr?a=1");
    assert_eq!(header_value(&in_if, "X-A"), Some("a"));
    assert_eq!(body(&in_if), b"if");

    let redirect = http_get(port, "/hdr/r");
    assert_eq!(status_line(&redirect), "HTTP/1.1 302 Moved Temporarily");
    assert_eq!(header_value(&redirect, "X-A"), Some("a"));

    let page = http_get(port, "/err?a=1");
    assert_eq!(status_line(&page), "HTTP/1.1 403 Forbidden");
    assert_eq!(body(&page), b"page");

    let other = http_get(port, "/err?b=1");
    assert_eq!(status_line(&other), "HTTP/1.1 403 Forbidden");
    assert_eq!(body(&other), b"other");

    // A `return` with text is sent as it is, error_page or not.
    let text = http_get(port, "/err?t=1");
    assert_eq!(status_line(&text), "HTTP/1.1 403 Forbidden");
    assert_eq!(body(&text), b"text");
}

/// `return URL;` (#16): a 302 to the URL, variables rendered, in a server,
/// a location and an `if`.
#[test]
fn return_url_alone_redirects_with_302() {
    let conf = r#"
events {}
http {
  server {
    listen 127.0.0.1:%%PORT%%;
    location /lit { return http://example.com/new; }
    location /var { return https://example.com$uri?a=$arg_a; }
    location /if {
      if ($arg_go) { return $scheme://other.example$uri; }
      return 200 stay;
    }
  }
}
"#;
    let (_s, port) = spawn_server(conf);
    let r = http_get(port, "/lit");
    assert!(
        status_line(&r).contains("302"),
        "{}",
        String::from_utf8_lossy(&r)
    );
    assert_eq!(header_value(&r, "Location"), Some("http://example.com/new"));
    let r = http_get(port, "/var?a=1");
    assert!(status_line(&r).contains("302"));
    assert_eq!(
        header_value(&r, "Location"),
        Some("https://example.com/var?a=1")
    );
    let r = http_get(port, "/if?go=1");
    assert_eq!(
        header_value(&r, "Location"),
        Some("http://other.example/if")
    );
    assert_eq!(body(&http_get(port, "/if")), b"stay");
}

/// `absolute_redirect`, `server_name_in_redirect`, `port_in_redirect`
/// (#15): a Location that starts with `/` is made absolute as nginx's
/// header filter makes it, whoever set it (`return`, `rewrite`, the
/// directory redirect), with the Host, else the local address, and the
/// port unless it is off; `absolute_redirect off` leaves it a path.
#[test]
fn redirects_follow_absolute_redirect() {
    let conf = r#"
events {}
http {
  server {
    listen 127.0.0.1:%%PORT%%;
    server_name named.example;
    root %%DIR%%;
    location /ret { return 301 /target; }
    location /rw { rewrite ^ /rewritten redirect; }
    location /name { server_name_in_redirect on; return 302 /n; }
    location /noport { port_in_redirect off; return 302 /p; }
    location /off { absolute_redirect off; return 302 /rel; }
  }
}
"#;
    let (s, port) = spawn_server(conf);
    std::fs::create_dir_all(s.tempdir.join("a dir")).unwrap();
    let loc = |path: &str| {
        let r = http_get(port, path);
        header_value(&r, "Location").map(str::to_string)
    };
    assert_eq!(
        loc("/ret").as_deref(),
        Some(format!("http://localhost:{port}/target").as_str())
    );
    assert_eq!(
        loc("/rw").as_deref(),
        Some(format!("http://localhost:{port}/rewritten").as_str())
    );
    assert_eq!(
        loc("/name").as_deref(),
        Some(format!("http://named.example:{port}/n").as_str())
    );
    assert_eq!(loc("/noport").as_deref(), Some("http://localhost/p"));
    assert_eq!(loc("/off").as_deref(), Some("/rel"));
    // The directory redirect escapes the URI and keeps the arguments.
    assert_eq!(
        loc("/a%20dir?x=1").as_deref(),
        Some(format!("http://localhost:{port}/a%20dir/?x=1").as_str())
    );
}

/// A `rewrite` without a flag changes the URI, and once the location's
/// rewrite directives are done the locations are searched again, as
/// nginx's post-rewrite phase does (#682): a `proxy_pass` with a URI part
/// there substitutes it, an `alias` maps the new URI. A top-level `return`
/// answers first; `break` keeps the request where it is, `proxy_pass` then
/// sending the new URI as it is; a rewrite back into the same location
/// ends in a 500.
#[test]
fn a_rewrite_without_a_flag_searches_the_locations_again() {
    let (g, port) = spawn_server(
        "events {}\nhttp {\n\
         server { listen 127.0.0.1:%%PORT%%;\n\
           location /a/ { rewrite ^/a/(.*)$ /b/$1; }\n\
           location /b/ { proxy_pass http://127.0.0.1:%%PORT%%/x/; }\n\
           location /k/ { rewrite ^/k/(.*)$ /x/$1; break; proxy_pass http://127.0.0.1:%%PORT%%/x/z/; }\n\
           location /x/ { return 200 \"x:$uri\"; }\n\
           location /al/ { rewrite ^/al/(.*)$ /bar/$1; }\n\
           location /bar/ { alias %%DIR%%/bar/; }\n\
           location /once/ { rewrite ^/once/(.*)$ /once/x$1; return 200 \"uri:$uri\"; }\n\
           location /loop/ { rewrite ^/loop/(.*)$ /loop/$1; }\n\
         } }\n",
    );
    std::fs::create_dir_all(g.tempdir.join("bar")).unwrap();
    std::fs::write(g.tempdir.join("bar/1"), "one").unwrap();

    let a = http_get(port, "/a/1");
    assert_eq!(body(&a), b"x:/x/1", "{}", String::from_utf8_lossy(&a));
    let k = http_get(port, "/k/1");
    assert_eq!(body(&k), b"x:/x/1", "{}", String::from_utf8_lossy(&k));
    let al = http_get(port, "/al/1");
    assert_eq!(body(&al), b"one", "{}", String::from_utf8_lossy(&al));
    let once = http_get(port, "/once/1");
    assert_eq!(
        body(&once),
        b"uri:/once/x1",
        "{}",
        String::from_utf8_lossy(&once)
    );
    let looped = http_get(port, "/loop/1");
    assert_eq!(status_line(&looped), "HTTP/1.1 500 Internal Server Error");
}

/// An `alias` location maps nothing once a `rewrite` changed the URI in
/// it, as nginx 1.30's ngx_http_map_uri_to_path refuses (#589):
/// `$request_filename` is empty after a flagless rewrite (a `return`
/// answering before the locations are searched again), and a file is a
/// 500 after `rewrite … break`, both with an `[alert]`. Without a rewrite
/// the alias maps as usual.
#[test]
fn an_alias_maps_nothing_after_a_rewrite() {
    let (g, port) = spawn_server(
        "error_log %%DIR%%/error.log info;\nevents {}\nhttp {\n\
         server { listen 127.0.0.1:%%PORT%%;\n\
           location /foo/ { alias %%DIR%%/bar/; rewrite ^/foo/.*$ /x; return 200 \"rf=[$request_filename]\"; }\n\
           location /brk/ { alias %%DIR%%/bar/; rewrite ^/brk/(.*)$ /brk/x break; }\n\
           location /set/ { alias %%DIR%%/bar/; return 200 \"rf=[$request_filename]\"; }\n\
         } }\n",
    );
    std::fs::create_dir_all(g.tempdir.join("bar")).unwrap();
    std::fs::write(g.tempdir.join("bar/x"), "x").unwrap();
    let dir = g.tempdir.display().to_string();

    let foo = http_get(port, "/foo/1");
    assert_eq!(body(&foo), b"rf=[]", "{}", String::from_utf8_lossy(&foo));
    let brk = http_get(port, "/brk/1");
    assert_eq!(status_line(&brk), "HTTP/1.1 500 Internal Server Error");
    let plain = http_get(port, "/set/1");
    assert_eq!(
        String::from_utf8_lossy(body(&plain)),
        format!("rf=[{dir}/bar/1]")
    );
    let log = std::fs::read_to_string(g.tempdir.join("error.log")).unwrap_or_default();
    for name in ["/foo/", "/brk/"] {
        let alert =
            format!("\"alias\" cannot be used in location \"{name}\" where URI was rewritten");
        assert!(
            log.lines()
                .any(|l| l.contains("[alert]") && l.contains(&alert)),
            "{alert}\n{log}"
        );
    }
}

/// What clears the rewrite flags (#682), as nginx: `last` and every new
/// location search clear `uri_changed`, and an internal redirect
/// (`error_page`, `try_files`) sets `valid_location` again, so an alias
/// location found after them maps as usual; ten flagless rewrites in a
/// row are within nginx's budget of URI changes.
#[test]
fn rewrites_before_a_redirect_leave_no_trace() {
    let mut chain = String::new();
    for i in 1..10 {
        chain.push_str(&format!(
            "location /l{i}/ {{ rewrite ^/l{i}/(.*) /l{}/$1; }}\n",
            i + 1
        ));
    }
    let (g, port) = spawn_server(&format!(
        "events {{}}\nhttp {{\n\
         server {{ listen 127.0.0.1:%%PORT%%; root %%DIR%%;\n\
           location /a/ {{ rewrite ^/a/(.*) /b/$1; rewrite ^/b/(.*) /c/$1 last; }}\n\
           location /c/ {{ alias %%DIR%%/c/; }}\n\
           location /d/ {{ rewrite ^/d/(.*) /e/$1; error_page 404 /err/404.html; return 404; }}\n\
           location /err/ {{ alias %%DIR%%/err/; }}\n\
           location /g/ {{ rewrite ^/g/(.*) /h/$1 break; error_page 404 /err/404.html; }}\n\
           location /t/ {{ rewrite ^/t/(.*) /u/$1 break; try_files $uri /c/f.txt; }}\n\
           {chain}\
           location /l10/ {{ return 200 \"end $uri\"; }}\n\
         }} }}\n"
    ));
    std::fs::create_dir_all(g.tempdir.join("c")).unwrap();
    std::fs::create_dir_all(g.tempdir.join("err")).unwrap();
    std::fs::write(g.tempdir.join("c/f.txt"), "file").unwrap();
    std::fs::write(g.tempdir.join("err/404.html"), "err").unwrap();

    for (path, status, wanted) in [
        ("/a/f.txt", "HTTP/1.1 200 OK", &b"file"[..]),
        ("/d/x", "HTTP/1.1 404 Not Found", b"err"),
        ("/g/x", "HTTP/1.1 404 Not Found", b"err"),
        ("/t/x", "HTTP/1.1 200 OK", b"file"),
        ("/l1/x", "HTTP/1.1 200 OK", b"end /l10/x"),
    ] {
        let resp = http_get(port, path);
        assert_eq!(status_line(&resp), status, "{path}");
        assert_eq!(body(&resp), wanted, "{path}");
    }
}

/// A top-level `return` is a rewrite directive in nginx: after `break`
/// (the directive or the flag, in an `if` too) the static module answers
/// instead (#697); without a break the `return` answers as before.
#[test]
fn a_break_stops_before_the_return() {
    let (g, port) = spawn_server(
        "events {}\nhttp {\n\
         server { listen 127.0.0.1:%%PORT%%; root %%DIR%%;\n\
           location /k { rewrite ^ /k.txt break; return 200 ret; }\n\
           location /j { set $a 1; break; return 200 ret; }\n\
           location /i { if ($arg_b) { break; } return 200 ret; }\n\
         } }\n",
    );
    std::fs::write(g.tempdir.join("k.txt"), "file").unwrap();
    for (path, status, wanted) in [
        ("/k", "HTTP/1.1 200 OK", Some(&b"file"[..])),
        ("/j", "HTTP/1.1 404 Not Found", None),
        ("/i?b=1", "HTTP/1.1 404 Not Found", None),
        ("/i", "HTTP/1.1 200 OK", Some(b"ret")),
    ] {
        let resp = http_get(port, path);
        assert_eq!(status_line(&resp), status, "{path}");
        if let Some(wanted) = wanted {
            assert_eq!(body(&resp), wanted, "{path}");
        }
    }
}
