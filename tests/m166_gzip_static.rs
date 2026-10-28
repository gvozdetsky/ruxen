//! M166 — `gzip_static on|always` (#760): `file.gz` with `Content-Encoding:
//! gzip` and its own length, `ETag` and `Last-Modified`, to clients
//! `ngx_http_gzip_ok` lets have it (`on`) or to all (`always`). Expected
//! headers are nginx 1.30.6's for the same files and configuration.

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

struct Server {
    child: Child,
    dir: PathBuf,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn start() -> (Server, u16) {
    let dir = std::env::temp_dir().join(format!("ruxen-m166-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let www = dir.join("www");
    std::fs::create_dir_all(www.join("d")).unwrap();
    std::fs::create_dir_all(www.join("dir.gz")).unwrap();
    for (name, body) in [
        ("a.txt", "hello plain text\n\n"),
        ("a.txt.gz", "compressed-ish body that is 35 byte"),
        ("only.txt.gz", "only-gz"),
        ("dir", "dirfile\n"),
        ("d/index.html", "idx\n"),
        ("d/index.html.gz", "IDXGZ"),
    ] {
        std::fs::write(www.join(name), body).unwrap();
    }
    let setup = common::ports::setup_lock();
    let [port] = common::ports::free_ports();
    let conf = dir.join("ruxen.conf");
    std::fs::write(
        &conf,
        format!(
            "events {{}}\nhttp {{\n access_log off;\n types {{ text/plain txt; text/html html; }}\n \
             server {{\n listen 127.0.0.1:{port};\n \
             location /on/ {{ alias {www}/; gzip_static on; }}\n \
             location /onv/ {{ alias {www}/; gzip_static on; gzip_vary on; }}\n \
             location /always/ {{ alias {www}/; gzip_static always; gzip_vary on; }}\n \
             location /gz/ {{ alias {www}/; gzip_static on; gzip on; gzip_vary on; \
               gzip_types text/plain; gzip_min_length 1; }}\n \
             location /via/ {{ alias {www}/; gzip_static on; gzip_proxied expired; }}\n \
             location /file {{ alias {www}/a.txt; gzip_static always; }}\n }}\n}}\n",
            www = www.display(),
        ),
    )
    .unwrap();
    // Owned by `Server` before the wait: if it panics, ruxen still stops.
    let mut server = Server {
        child: Command::new(env!("CARGO_BIN_EXE_ruxen"))
            .args(["-c", conf.to_str().unwrap()])
            .arg("-g")
            .arg(format!("pid {}/ruxen.pid;", dir.display()))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
        dir,
    };
    let pid_file = server.dir.join("ruxen.pid");
    common::ports::wait_for_pid_file(&mut server.child, &pid_file, Duration::from_secs(5));
    drop(setup);
    (server, port)
}

/// (status, headers lowercased as `name: value` lines, body).
fn get(port: u16, method: &str, path: &str, extra: &str) -> (u16, Vec<String>, Vec<u8>) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(
        s,
        "{method} {path} HTTP/1.1\r\nHost: t\r\nConnection: close\r\n{extra}\r\n"
    )
    .unwrap();
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).unwrap();
    let end = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = String::from_utf8_lossy(&raw[..end]).into_owned();
    let mut lines = head.lines();
    let status = lines.next().unwrap()[9..12].parse().unwrap();
    let headers = lines.map(|l| l.to_ascii_lowercase()).collect();
    (status, headers, raw[end + 4..].to_vec())
}

fn count(headers: &[String], line: &str) -> usize {
    headers.iter().filter(|h| *h == line).count()
}

fn has_name(headers: &[String], name: &str) -> bool {
    headers
        .iter()
        .any(|h| h.split_once(':').is_some_and(|(n, _)| n == name))
}

const AE: &str = "Accept-Encoding: gzip\r\n";
const CE: &str = "content-encoding: gzip";
const VARY: &str = "vary: accept-encoding";

#[test]
fn gzip_static() {
    let (_server, port) = start();
    let gz = b"compressed-ish body that is 35 byte".as_slice();
    let plain = b"hello plain text\n\n".as_slice();

    // `on`: the .gz to a client that takes gzip, with its own length.
    let (status, h, body) = get(port, "GET", "/on/a.txt", AE);
    assert_eq!((status, body.as_slice()), (200, gz));
    assert_eq!(count(&h, CE), 1, "{h:?}");
    assert_eq!(count(&h, "content-length: 35"), 1, "{h:?}");
    assert_eq!(count(&h, "content-type: text/plain"), 1, "{h:?}");
    assert_eq!(count(&h, VARY), 0, "{h:?}");
    // The file itself to one that doesn't, or refuses it with q=0.
    for extra in [
        "",
        "Accept-Encoding: gzip;q=0\r\n",
        "Accept-Encoding: br\r\n",
    ] {
        let (status, h, body) = get(port, "GET", "/on/a.txt", extra);
        assert_eq!((status, body.as_slice()), (200, plain), "{extra}");
        assert!(!has_name(&h, "content-encoding"), "{extra} {h:?}");
    }
    // HEAD: the .gz's length, no body.
    let (_, h, body) = get(port, "HEAD", "/on/a.txt", AE);
    assert!(body.is_empty());
    assert_eq!(count(&h, "content-length: 35"), 1, "{h:?}");
    assert_eq!(count(&h, CE), 1, "{h:?}");

    // `gzip_vary`: a .gz that exists makes either answer vary.
    for extra in [AE, ""] {
        let (_, h, _) = get(port, "GET", "/onv/a.txt", extra);
        assert_eq!(count(&h, VARY), 1, "{extra} {h:?}");
    }
    // No .gz, no Vary.
    let (_, h, _) = get(port, "GET", "/onv/d/index.html.gz", AE);
    assert_eq!(count(&h, VARY), 0, "{h:?}");

    // `always`: to anyone, without Vary.
    let (status, h, body) = get(port, "GET", "/always/a.txt", "");
    assert_eq!((status, body.as_slice()), (200, gz));
    assert_eq!(count(&h, CE), 1, "{h:?}");
    assert_eq!(count(&h, VARY), 0, "{h:?}");
    // A .gz alone is enough; a directory named .gz is not.
    let (status, _, body) = get(port, "GET", "/always/only.txt", "");
    assert_eq!((status, body.as_slice()), (200, b"only-gz".as_slice()));
    let (status, h, body) = get(port, "GET", "/always/dir", "");
    assert_eq!((status, body.as_slice()), (200, b"dirfile\n".as_slice()));
    assert!(!has_name(&h, "content-encoding"), "{h:?}");
    // An index file's .gz, after the index redirect.
    let (_, _, body) = get(port, "GET", "/always/d/", "");
    assert_eq!(body, b"IDXGZ");
    // An alias naming a file: the .gz beside it.
    let (_, _, body) = get(port, "GET", "/file", "");
    assert_eq!(body, gz);
    // Other methods aren't the module's.
    let (status, _, _) = get(port, "POST", "/always/a.txt", "");
    assert_eq!(status, 405);

    // Ranges of the .gz.
    let (status, h, body) = get(
        port,
        "GET",
        "/onv/a.txt",
        "Accept-Encoding: gzip\r\nRange: bytes=0-4\r\n",
    );
    assert_eq!((status, body.as_slice()), (206, b"compr".as_slice()));
    assert_eq!(count(&h, "content-range: bytes 0-4/35"), 1, "{h:?}");
    assert_eq!(count(&h, CE), 1, "{h:?}");
    // A 304 drops Content-Encoding, as nginx's not_modified filter.
    let (_, h, _) = get(port, "GET", "/onv/a.txt", AE);
    let etag = h
        .iter()
        .find_map(|l| l.strip_prefix("etag: "))
        .unwrap()
        .to_string();
    assert_eq!(etag.trim_matches('"').split('-').nth(1), Some("23"));
    let (status, h, _) = get(
        port,
        "GET",
        "/onv/a.txt",
        &format!("{AE}If-None-Match: {etag}\r\n"),
    );
    assert_eq!(status, 304);
    assert_eq!(count(&h, CE), 0, "{h:?}");
    assert_eq!(count(&h, VARY), 1, "{h:?}");

    // With `gzip on`: the .gz isn't compressed again, and Vary is sent once.
    let (_, h, body) = get(port, "GET", "/gz/a.txt", AE);
    assert_eq!(body, gz);
    assert_eq!((count(&h, CE), count(&h, VARY)), (1, 1), "{h:?}");
    let (_, h, body) = get(port, "GET", "/gz/a.txt", "");
    assert_eq!(body, plain);
    assert_eq!((count(&h, CE), count(&h, VARY)), (0, 1), "{h:?}");

    // `gzip_proxied` with a Via: in the content phase only `off` refuses.
    let (_, h, _) = get(
        port,
        "GET",
        "/via/a.txt",
        "Accept-Encoding: gzip\r\nVia: 1.1 p\r\n",
    );
    assert_eq!(count(&h, CE), 1, "{h:?}");
    let (_, h, _) = get(
        port,
        "GET",
        "/on/a.txt",
        "Accept-Encoding: gzip\r\nVia: 1.1 p\r\n",
    );
    assert_eq!(count(&h, CE), 0, "{h:?}");
}
