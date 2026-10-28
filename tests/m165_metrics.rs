//! M165 — `ruxen_metrics;` (#481): the `stub_status` counters, per server
//! and per upstream peer series in Prometheus text format, label values
//! escaped, and counters that start again at zero after a reload.

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

unsafe extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
}

struct Server(Child, PathBuf);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
        let _ = std::fs::remove_dir_all(&self.1);
    }
}

impl Server {
    fn write_conf(&self, http: &str) {
        write_conf(&self.1, http);
    }

    fn hup(&self) {
        // SAFETY: a signal to our own child.
        unsafe {
            assert_eq!(kill(self.0.id() as i32, 1), 0);
        }
    }
}

fn write_conf(dir: &std::path::Path, http: &str) {
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "pid {d}/ruxen.pid;\nerror_log {d}/error.log;\nworker_processes 1;\n\
             events {{}}\nhttp {{ access_log off;\n{http}\n}}\n",
            d = dir.display()
        ),
    )
    .unwrap();
}

/// Start ruxen on `http`; the caller holds the port lock.
fn start(name: &str, http: &str) -> Server {
    let dir = std::env::temp_dir().join(format!("ruxen-m165-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    write_conf(&dir, http);
    let mut server = Server(
        Command::new(env!("CARGO_BIN_EXE_ruxen"))
            .arg("-c")
            .arg(dir.join("nginx.conf"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
        dir,
    );
    let pid_file = server.1.join("ruxen.pid");
    common::ports::wait_for_pid_file(&mut server.0, &pid_file, Duration::from_secs(5));
    server
}

fn request(port: u16, method: &str, path: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(s, "{method} {path} HTTP/1.0\r\nHost: x\r\n\r\n").unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

/// The scrape's body.
fn scrape(port: u16) -> String {
    let r = request(port, "GET", "/metrics");
    assert!(r.starts_with("HTTP/1.1 200 OK\r\n"), "{r}");
    assert!(
        r.contains("Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n"),
        "{r}"
    );
    r.split_once("\r\n\r\n").unwrap().1.to_string()
}

/// The value of the series `series` (name and labels, as printed).
fn value(page: &str, series: &str) -> u64 {
    page.lines()
        .find_map(|l| l.strip_prefix(series)?.strip_prefix(' '))
        .unwrap_or_else(|| panic!("no {series} in\n{page}"))
        .parse()
        .unwrap()
}

#[test]
fn m165_series_after_traffic() {
    let dead = common::ports::dead_port();
    let setup = common::ports::setup_lock();
    let [front, back] = common::ports::free_ports::<2>();
    let d = dead.port();
    let _server = start(
        "traffic",
        &format!(
            "upstream app {{ server 127.0.0.1:{back}; server 127.0.0.1:{d}; }}\n\
             server {{ listen 127.0.0.1:{back}; location / {{ return 200 \"ok\\n\"; }} }}\n\
             server {{ listen 127.0.0.1:{front}; server_name \"we\\\"ird\";\n\
             location /metrics {{ ruxen_metrics; }}\n\
             location /missing {{ return 404; }}\n\
             location / {{ proxy_pass http://app; }} }}"
        ),
    );
    drop(setup);
    // One worker: round robin takes the live peer, then the dead one
    // (which fails over to the live one and then cools off), then the live
    // one twice.
    for _ in 0..4 {
        let r = request(front, "GET", "/");
        assert!(r.starts_with("HTTP/1.1 200 OK\r\n"), "{r}");
    }
    request(front, "GET", "/missing");

    let page = scrape(front);
    // Each family has its TYPE line once.
    for family in [
        "ruxen_connections_active gauge",
        "ruxen_http_requests_total counter",
        "ruxen_server_responses_total counter",
        "ruxen_server_sent_bytes_total counter",
        "ruxen_upstream_peer_requests_total counter",
        "ruxen_upstream_peer_failures_total counter",
        "ruxen_upstream_peer_response_seconds histogram",
        "ruxen_upstream_peer_up gauge",
    ] {
        assert_eq!(
            page.matches(&format!("# TYPE {family}\n")).count(),
            1,
            "{family}\n{page}"
        );
    }
    // The 5 front requests and the 5 tries upstream, then this one.
    assert_eq!(value(&page, "ruxen_http_requests_total"), 10);
    assert_eq!(value(&page, "ruxen_connections_writing"), 1);

    // The quote in the server name is escaped.
    let front_labels = format!("server=\"we\\\"ird\",listen=\"127.0.0.1:{front}\"");
    let s = |code: &str| {
        value(
            &page,
            &format!("ruxen_server_responses_total{{{front_labels},code=\"{code}\"}}"),
        )
    };
    assert_eq!(
        (s("1xx"), s("2xx"), s("3xx"), s("4xx"), s("5xx")),
        (0, 4, 0, 1, 0)
    );
    assert!(
        value(
            &page,
            &format!("ruxen_server_sent_bytes_total{{{front_labels}}}")
        ) > 0
    );
    let back_labels = format!("server=\"\",listen=\"127.0.0.1:{back}\"");
    assert_eq!(
        value(
            &page,
            &format!("ruxen_server_responses_total{{{back_labels},code=\"2xx\"}}")
        ),
        4
    );

    let live = format!("upstream=\"app\",peer=\"127.0.0.1:{back}\"");
    let gone = format!("upstream=\"app\",peer=\"127.0.0.1:{d}\"");
    let p = |name: &str, labels: &str| value(&page, &format!("{name}{{{labels}}}"));
    assert_eq!(p("ruxen_upstream_peer_requests_total", &live), 4);
    assert_eq!(p("ruxen_upstream_peer_requests_total", &gone), 1);
    assert_eq!(p("ruxen_upstream_peer_failures_total", &live), 0);
    assert_eq!(p("ruxen_upstream_peer_failures_total", &gone), 1);
    assert_eq!(p("ruxen_upstream_peer_response_seconds_count", &live), 4);
    assert_eq!(
        p(
            "ruxen_upstream_peer_response_seconds_bucket",
            &format!("{live},le=\"+Inf\"")
        ),
        4
    );
    assert_eq!(p("ruxen_upstream_peer_up", &live), 1);
    assert_eq!(p("ruxen_upstream_peer_up", &gone), 0);

    // GET and HEAD only, as stub_status.
    let r = request(front, "HEAD", "/metrics");
    assert!(r.starts_with("HTTP/1.1 200 OK\r\n"), "{r}");
    assert!(r.ends_with("\r\n\r\n"), "{r}");
    let r = request(front, "POST", "/metrics");
    assert!(r.starts_with("HTTP/1.1 405 "), "{r}");
}

#[test]
fn m165_reload_starts_again_at_zero() {
    let setup = common::ports::setup_lock();
    let [front, back] = common::ports::free_ports::<2>();
    let http = |extra: &str| {
        format!(
            "server {{ listen 127.0.0.1:{back}; location / {{ return 200 \"ok\\n\"; }} }}\n\
             server {{ listen 127.0.0.1:{front};\n\
             location /metrics {{ ruxen_metrics; }}\n{extra}\n\
             location / {{ proxy_pass http://127.0.0.1:{back}; }} }}"
        )
    };
    let server = start("reload", &http(""));
    drop(setup);
    for _ in 0..3 {
        request(front, "GET", "/");
    }
    let page = scrape(front);
    let peer = format!("upstream=\"127.0.0.1:{back}\",peer=\"127.0.0.1:{back}\"");
    assert_eq!(
        value(
            &page,
            &format!("ruxen_upstream_peer_requests_total{{{peer}}}")
        ),
        3
    );
    let requests_before = value(&page, "ruxen_http_requests_total");

    server.write_conf(&http("location /gen2 { return 200 \"2\\n\"; }"));
    server.hup();
    // The first answer from the new workers
    let deadline = Instant::now() + Duration::from_secs(5);
    // (The old ones proxy it.)
    while !request(front, "GET", "/gen2").ends_with("\r\n\r\n2\n") {
        assert!(Instant::now() < deadline, "the reload didn't take");
        sleep(Duration::from_millis(20));
    }
    let page = scrape(front);
    let front_labels = format!("server=\"\",listen=\"127.0.0.1:{front}\"");
    assert_eq!(
        value(
            &page,
            &format!("ruxen_server_responses_total{{{front_labels},code=\"2xx\"}}")
        ),
        1,
        "{page}"
    );
    assert_eq!(
        value(
            &page,
            &format!("ruxen_upstream_peer_requests_total{{{peer}}}")
        ),
        0
    );
    // The stub_status counters belong to the process, as nginx's to shm.
    assert!(value(&page, "ruxen_http_requests_total") > requests_before);
}

#[test]
fn m165_takes_no_arguments() {
    let dir = std::env::temp_dir().join(format!("ruxen-m165-args-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    write_conf(
        &dir,
        "server { listen 127.0.0.1:1; location /m { ruxen_metrics on; } }",
    );
    let out = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .arg("-t")
        .arg("-c")
        .arg(dir.join("nginx.conf"))
        .output()
        .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(
        stderr.contains("\"ruxen_metrics\" directive takes no arguments"),
        "{stderr}"
    );
}
