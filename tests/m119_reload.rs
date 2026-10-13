//! M119 — `-s reload` / SIGHUP reloads the configuration (#89), as nginx's
//! master does (ngx_master_process_cycle, ngx_init_cycle): new workers
//! start with the new configuration on the same listening sockets, the old
//! ones finish their requests and exit, and a configuration that fails
//! leaves the running one in place.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

unsafe extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
}

const SIGHUP: i32 = 1;
const SIGQUIT: i32 = 3;

struct Server {
    child: Child,
    dir: PathBuf,
}

impl Server {
    fn conf(&self) -> PathBuf {
        self.dir.join("nginx.conf")
    }

    fn write_conf(&self, main: &str, http: &str) {
        write_conf(&self.dir, main, http);
    }

    /// `ruxen -s reload`, then a pause for the new workers to take over.
    fn reload(&self) {
        let out = Command::new(env!("CARGO_BIN_EXE_ruxen"))
            .arg("-c")
            .arg(self.conf())
            .args(["-s", "reload"])
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
        sleep(Duration::from_millis(300));
    }

    fn hup(&self) {
        unsafe {
            assert_eq!(kill(self.child.id() as i32, SIGHUP), 0);
        }
        sleep(Duration::from_millis(300));
    }

    fn error_log(&self) -> String {
        std::fs::read_to_string(self.dir.join("error.log")).unwrap_or_default()
    }

    /// Threads of the process: main and the workers (and none else here).
    fn threads(&self) -> usize {
        std::fs::read_dir(format!("/proc/{}/task", self.child.id()))
            .unwrap()
            .count()
    }

    fn wait_threads(&self, n: usize) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while self.threads() != n {
            assert!(Instant::now() < deadline, "{} threads", self.threads());
            sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn write_conf(dir: &Path, main: &str, http: &str) {
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "pid {d}/ruxen.pid;\nerror_log {d}/error.log info;\n{main}\n\
             events {{}}\nhttp {{\naccess_log off;\n{http}\n}}\n",
            d = dir.display()
        ),
    )
    .unwrap();
}

fn start(name: &str, main: &str, http: &str) -> Server {
    let dir = std::env::temp_dir().join(format!("ruxen-m119-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let setup = common::ports::setup_lock();
    write_conf(&dir, main, http);
    let child = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .arg("-c")
        .arg(dir.join("nginx.conf"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut s = Server {
        child,
        dir: dir.clone(),
    };
    let deadline = Instant::now() + Duration::from_secs(3);
    while !dir.join("ruxen.pid").exists() {
        assert!(
            Instant::now() < deadline && s.child.try_wait().unwrap().is_none(),
            "ruxen did not start"
        );
        sleep(Duration::from_millis(10));
    }
    drop(setup);
    s
}

fn get(port: u16, path: &str) -> std::io::Result<String> {
    let mut s = TcpStream::connect(("127.0.0.1", port))?;
    s.set_read_timeout(Some(Duration::from_secs(5)))?;
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
    )?;
    let mut out = String::new();
    s.read_to_string(&mut out)?;
    Ok(out)
}

fn body(port: u16) -> String {
    let response = get(port, "/").unwrap();
    response
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or(response)
}

fn returning(port: u16, text: &str) -> String {
    format!("server {{ listen 127.0.0.1:{port}; location / {{ return 200 \"{text}\\n\"; }} }}")
}

#[test]
fn reload_applies_the_new_configuration() {
    let port = free_port();
    let s = start("apply", "worker_processes 2;", &returning(port, "one"));
    assert_eq!(body(port), "one\n");

    s.write_conf("worker_processes 2;", &returning(port, "two"));
    s.reload();
    assert_eq!(body(port), "two\n");
    assert!(
        s.error_log().contains("[notice] ")
            && s.error_log()
                .contains("signal 1 (SIGHUP) received, reconfiguring"),
        "{}",
        s.error_log()
    );
    // The old workers are gone: main and two workers.
    s.wait_threads(3);

    // A configuration that fails keeps the running one, as nginx. (`-s
    // reload` reads it too, and refuses, so the signal is sent directly.)
    s.write_conf(
        "worker_processes 2;",
        "server { listen 127.0.0.1:1; bogus; }",
    );
    s.hup();
    assert_eq!(body(port), "two\n");
    assert!(
        s.error_log().contains("[emerg] ") && s.error_log().contains("bogus"),
        "{}",
        s.error_log()
    );

    // More workers, then fewer: each one answers with the new text.
    s.write_conf("worker_processes 4;", &returning(port, "four"));
    s.reload();
    s.wait_threads(5);
    for _ in 0..20 {
        assert_eq!(body(port), "four\n");
    }
    s.write_conf("worker_processes 1;", &returning(port, "single"));
    s.reload();
    s.wait_threads(2);
    for _ in 0..20 {
        assert_eq!(body(port), "single\n");
    }
}

#[test]
fn reload_moves_listen_addresses() {
    let (a, b) = (free_port(), free_port());
    let s = start("listen", "worker_processes 2;", &returning(a, "a"));
    let unix = s.dir.join("u.sock");
    let both = format!(
        "{}\n{}\nserver {{ listen unix:{}; location / {{ return 200 \"unix\\n\"; }} }}",
        returning(a, "a2"),
        returning(b, "b"),
        unix.display()
    );
    s.write_conf("worker_processes 2;", &both);
    s.reload();
    assert_eq!(body(a), "a2\n");
    assert_eq!(body(b), "b\n");
    assert!(unix.exists());

    s.write_conf("worker_processes 2;", &returning(b, "b2"));
    s.reload();
    s.wait_threads(3);
    assert_eq!(body(b), "b2\n");
    assert_eq!(
        TcpStream::connect(("127.0.0.1", a))
            .map(|_| ())
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::ConnectionRefused
    );
    assert!(!unix.exists(), "the removed unix socket's file is left");

    // A port someone else holds fails the reload, after nginx's retries;
    // the running configuration stays, with its sockets.
    let busy = TcpListener::bind("127.0.0.1:0").unwrap();
    let c = busy.local_addr().unwrap().port();
    s.write_conf(
        "worker_processes 2;",
        &format!("{}\n{}", returning(b, "b3"), returning(c, "c")),
    );
    s.hup();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !s.error_log().contains("still could not bind()") {
        assert!(Instant::now() < deadline, "{}", s.error_log());
        sleep(Duration::from_millis(50));
    }
    assert!(s.error_log().contains("[emerg] "), "{}", s.error_log());
    assert_eq!(body(b), "b2\n");
    s.wait_threads(3);
}

/// A download in flight when the reload comes: the old worker finishes it,
/// while new connections get the new configuration.
fn stalled_download(port: u16) -> TcpStream {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.write_all(b"GET /big.bin HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut head = [0; 64];
    s.read_exact(&mut head).unwrap();
    assert!(head.starts_with(b"HTTP/1.1 200"));
    sleep(Duration::from_millis(100));
    s
}

fn static_server(dir: &Path, port: u16, text: &str) -> String {
    format!(
        "server {{ listen 127.0.0.1:{port}; location / {{ return 200 \"{text}\\n\"; }} \
         location /big.bin {{ root {}; }} }}",
        dir.display()
    )
}

const BIG: u64 = 64 << 20;

#[test]
fn in_flight_requests_finish_on_the_old_workers() {
    let port = free_port();
    let s = start("inflight", "", "");
    std::fs::File::create(s.dir.join("big.bin"))
        .unwrap()
        .set_len(BIG)
        .unwrap();
    s.write_conf("", &static_server(&s.dir, port, "one"));
    s.reload();
    s.wait_threads(2);

    let mut download = stalled_download(port);
    s.write_conf("", &static_server(&s.dir, port, "two"));
    s.reload();
    assert_eq!(body(port), "two\n");
    // The old worker still runs, for the download.
    assert_eq!(s.threads(), 3);
    download
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut rest = Vec::new();
    download.read_to_end(&mut rest).unwrap();
    assert!(rest.len() as u64 >= BIG - 64, "{} bytes", rest.len());
    s.wait_threads(2);
}

#[test]
fn worker_shutdown_timeout_ends_the_old_workers_connections() {
    let port = free_port();
    let s = start("timeout", "", "");
    std::fs::File::create(s.dir.join("big.bin"))
        .unwrap()
        .set_len(BIG)
        .unwrap();
    let main = "worker_shutdown_timeout 300ms;";
    s.write_conf(main, &static_server(&s.dir, port, "one"));
    s.reload();
    s.wait_threads(2);

    let mut download = stalled_download(port);
    let reloaded = Instant::now();
    s.write_conf(main, &static_server(&s.dir, port, "two"));
    s.reload();
    // The old worker ends the download and exits; the server goes on.
    s.wait_threads(2);
    assert!(reloaded.elapsed() >= Duration::from_millis(250));
    download
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut rest = Vec::new();
    let read = download.read_to_end(&mut rest);
    assert!(
        read.is_err_and(|e| e.kind() == std::io::ErrorKind::ConnectionReset)
            || (rest.len() as u64) < BIG,
        "the whole body arrived"
    );
    assert_eq!(body(port), "two\n");
}

/// Connections are handed over, not dropped: a client connecting all the
/// time sees no error across reloads (nginx keeps its listening sockets,
/// ruxen keeps each worker's accept queue).
#[test]
fn no_connection_fails_across_reloads() {
    let port = free_port();
    let s = start("handoff", "worker_processes 2;", &returning(port, "0"));
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let clients: Vec<_> = (0..4)
        .map(|_| {
            let stop = stop.clone();
            std::thread::spawn(move || {
                let mut n = 0;
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    let response = get(port, "/").unwrap_or_else(|e| panic!("request {n}: {e}"));
                    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
                    n += 1;
                }
                n
            })
        })
        .collect();
    for i in 1..=10 {
        s.write_conf("worker_processes 2;", &returning(port, &i.to_string()));
        unsafe {
            assert_eq!(kill(s.child.id() as i32, SIGHUP), 0);
        }
        sleep(Duration::from_millis(100));
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    for client in clients {
        assert!(client.join().unwrap() > 0);
    }
    sleep(Duration::from_millis(200));
    assert_eq!(body(port), "10\n");
    unsafe {
        assert_eq!(kill(s.child.id() as i32, SIGQUIT), 0);
    }
}

/// `limit_req` zones keep their state across a reload when declared the
/// same way, as nginx keeps a shared zone of the same name and size (#342);
/// another key for the zone fails the reload, as in nginx.
#[test]
fn limit_req_state_survives_a_reload() {
    let port = free_port();
    let s = start("limitreq", "", "");
    std::fs::write(s.dir.join("index.html"), "x").unwrap();
    let conf = |key: &str, text: &str| {
        format!(
            "limit_req_zone {key} zone=one:1m rate=1r/m;\n\
             server {{ listen 127.0.0.1:{port}; root {d};\n\
               location / {{ limit_req zone=one; add_header X-T {text} always; }} }}",
            d = s.dir.display()
        )
    };
    let status = || get(port, "/").unwrap()[9..12].to_string();
    s.write_conf("", &conf("$binary_remote_addr", "a"));
    s.reload();
    s.wait_threads(2);
    assert_eq!(status(), "200");
    assert_eq!(status(), "503");

    s.write_conf("", &conf("$binary_remote_addr", "b"));
    s.reload();
    assert!(
        get(port, "/").unwrap().contains("503"),
        "the bucket was reset"
    );

    s.write_conf("", &conf("$remote_addr", "c"));
    s.hup();
    assert!(
        s.error_log()
            .contains("limit_req \"one\" uses the \"$remote_addr\" key while previously it used the \"$binary_remote_addr\" key"),
        "{}",
        s.error_log()
    );
    let response = get(port, "/").unwrap();
    assert!(
        response.contains("503") && response.contains("X-T: b"),
        "{response}"
    );
}
