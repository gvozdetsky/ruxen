// Milestone 37 — `map $source $dest { ... }` at http scope.
//
// Covers:
// - `default` fallback when nothing matches.
// - Exact string entries (byte-equal against the rendered source).
// - Regex entries (`~` case-sensitive, `~*` case-insensitive) with
//   declaration-order dispatch for multiple hits.
// - Source expression composition (`$arg_x` feeding a `map`) and
//   expansion of variable references on the RHS.
// - Config validation for duplicate exact keys and bad regex patterns.
//
// These mirror nginx's `map` behavior verified against
// `ngx_http_map_module.c` — exact-match table is hit first, regexes
// second in declaration order, `default` last.

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
        "ruxen-m37-{}-{}",
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

fn body(resp: &[u8]) -> &[u8] {
    resp.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| &resp[i + 4..])
        .unwrap_or(&[])
}

#[test]
fn map_exact_regex_and_default_dispatch() {
    // Exact entry `apple` wins over `~^ap` regex thanks to table priority.
    // `~*BANANA` matches `banana` (case-insensitive).
    // `~^pear` matches `pear-pie` (prefix regex, case-sensitive).
    // Missing source / unmatched source falls through to `default`.
    let conf = r#"
events {}
http {
  map $arg_fruit $flavor {
    default   "unknown";
    "apple"   "crisp";
    ~*BANANA  "sweet";
    ~^pear    "grainy";
  }

  server {
    listen 127.0.0.1:%%PORT%%;
    location / {
      return 200 "flavor=$flavor";
    }
  }
}
"#;
    let (_g, port) = spawn_server(conf);

    assert_eq!(body(&http_get(port, "/?fruit=apple")), b"flavor=crisp");
    // nginx's map hash is case-insensitive (checked against nginx 1.24).
    assert_eq!(body(&http_get(port, "/?fruit=Apple")), b"flavor=crisp");
    assert_eq!(body(&http_get(port, "/?fruit=banana")), b"flavor=sweet");
    assert_eq!(body(&http_get(port, "/?fruit=BANANA")), b"flavor=sweet");
    assert_eq!(body(&http_get(port, "/?fruit=pear-pie")), b"flavor=grainy");
    assert_eq!(body(&http_get(port, "/?fruit=kiwi")), b"flavor=unknown");
    assert_eq!(body(&http_get(port, "/")), b"flavor=unknown");
}

#[test]
fn map_value_can_reference_other_variables() {
    // The RHS of a map entry is a full value expression: references to
    // other variables expand at render time, same contract as
    // `return "... $var ..."`.
    let conf = r#"
events {}
http {
  map $arg_lang $greeting {
    default  "hello, $arg_name";
    "es"     "hola, $arg_name";
    "fr"     "bonjour, $arg_name";
  }

  server {
    listen 127.0.0.1:%%PORT%%;
    location / {
      return 200 "$greeting";
    }
  }
}
"#;
    let (_g, port) = spawn_server(conf);

    assert_eq!(body(&http_get(port, "/?lang=es&name=Ada")), b"hola, Ada");
    assert_eq!(body(&http_get(port, "/?lang=fr&name=Ada")), b"bonjour, Ada");
    assert_eq!(body(&http_get(port, "/?lang=de&name=Ada")), b"hello, Ada");
}

#[test]
fn map_multiple_programs_coexist() {
    // Two map programs on two distinct output variables. Independent
    // dispatch — the `$color` map does not inherit from `$flavor`.
    let conf = r#"
events {}
http {
  map $arg_x $flavor {
    default  "neutral";
    "hot"    "spicy";
  }
  map $arg_y $color {
    default  "black";
    "fire"   "red";
    "ocean"  "blue";
  }

  server {
    listen 127.0.0.1:%%PORT%%;
    location / {
      return 200 "$flavor/$color";
    }
  }
}
"#;
    let (_g, port) = spawn_server(conf);

    assert_eq!(body(&http_get(port, "/?x=hot&y=fire")), b"spicy/red");
    assert_eq!(body(&http_get(port, "/?x=cold&y=ocean")), b"neutral/blue");
    assert_eq!(body(&http_get(port, "/")), b"neutral/black");
}

#[test]
fn map_missing_default_renders_empty() {
    // No `default` means unmatched source renders as empty bytes,
    // matching nginx's default-of-default behavior.
    let conf = r#"
events {}
http {
  map $arg_v $out {
    "one"  "ONE";
  }

  server {
    listen 127.0.0.1:%%PORT%%;
    location / {
      return 200 "[$out]";
    }
  }
}
"#;
    let (_g, port) = spawn_server(conf);

    assert_eq!(body(&http_get(port, "/?v=one")), b"[ONE]");
    assert_eq!(body(&http_get(port, "/?v=nope")), b"[]");
    assert_eq!(body(&http_get(port, "/")), b"[]");
}

fn assert_config_rejected(conf_body: &str, reason: &str) {
    // `-t` doesn't open listen sockets, so we skip `pick_port` (which
    // serializes on SETUP_LOCK) entirely — using a fixed placeholder
    // keeps this test parallel-safe across invocations.
    let dir = unique_dir();
    let p = dir.join("ruxen.conf");
    std::fs::write(
        &p,
        conf_body
            .replace("%%PORT%%", "12345")
            .replace("%%DIR%%", dir.to_str().unwrap()),
    )
    .unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .args(["-t", "-c", p.to_str().unwrap()])
        .output()
        .expect("run -t");
    assert!(!out.status.success(), "{reason}: -t should have failed");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn map_rejects_duplicate_exact_and_bad_regex() {
    // `-t` must reject both a duplicate exact key and a malformed regex
    // so misconfigurations surface at config test time, not at runtime.
    assert_config_rejected(
        r#"
events {}
http {
  map $arg_k $out {
    default "d";
    "a" "one";
    "a" "two";
  }
  server { listen 127.0.0.1:%%PORT%%; location / { return 200 "$out"; } }
}
"#,
        "duplicate map exact key",
    );

    assert_config_rejected(
        r#"
events {}
http {
  map $arg_k $out {
    default "d";
    ~(      "broken";
  }
  server { listen 127.0.0.1:%%PORT%%; location / { return 200 "$out"; } }
}
"#,
        "bad map regex",
    );
}

#[test]
fn map_hostnames_wildcards_and_escaped_keys() {
    // `hostnames`: a trailing dot is ignored, `*.x` / `.x` / `x.*`
    // wildcards (the longest wins), regexes see the value as sent; `\key`
    // is a literal key even when it spells a keyword. As nginx's map.t.
    let conf = r#"
events {}
http {
  map $args $y {
    hostnames;
    default            0;
    example.com        foo;
    example.*          right;
    *.example.com      left;
    .dot.example.com   special;
    ~^REGEX\.ORG$      regex;
    \include           include;
  }

  server {
    listen 127.0.0.1:%%PORT%%;
    location / {
      return 200 "y=$y";
    }
  }
}
"#;
    let (_g, port) = spawn_server(conf);
    for (args, want) in [
        ("EXAMPLE.COM.", "foo"),
        ("example.org", "right"),
        ("a.example.com", "left"),
        ("dot.example.com", "special"),
        ("www.dot.example.com", "special"),
        ("REGEX.ORG", "regex"),
        ("regex.org", "0"),
        ("include", "include"),
    ] {
        let got = body(&http_get(port, &format!("/?{args}"))).to_vec();
        assert_eq!(String::from_utf8_lossy(&got), format!("y={want}"), "{args}");
    }
}

#[test]
fn map_result_is_cached_for_the_request_unless_volatile() {
    // nginx caches a map's first result for the rest of the request, past
    // internal redirects and into the access log (`r->variables`); a
    // `volatile` map is evaluated on every reference. ruxen used to
    // re-evaluate every map and reject `volatile`.
    let conf = r#"
events {}
http {
  map $uri $first { default $uri; }
  map $uri $every { volatile; default $uri; }
  log_format m "$uri $first $every";

  server {
    listen 127.0.0.1:%%PORT%%;
    access_log %%DIR%%/access.log m;
    location = /a { rewrite ^ /b?f=$first:$every last; }
    location = /b { return 200 "$arg_f $first $every"; }
  }
}
"#;
    let (g, port) = spawn_server(conf);

    assert_eq!(body(&http_get(port, "/a")), b"/a:/a /a /b");
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    let log = loop {
        let log = std::fs::read_to_string(g.tempdir.join("access.log")).unwrap_or_default();
        if !log.is_empty() || std::time::Instant::now() > deadline {
            break log;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(log, "/b /a /b\n");
}
