//! M155 — a cache manager pass that panics doesn't end the zone's upkeep
//! (#524): the panic is logged at `alert`, and the next pass runs, so
//! `inactive` still removes what nobody asked for, as nginx's master
//! respawns its cache manager. `RUXEN_TEST_PANIC=cache` makes the first
//! pass panic.

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

struct KillOnDrop(std::process::Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn files(dir: &std::path::Path) -> usize {
    fn walk(dir: &std::path::Path) -> usize {
        std::fs::read_dir(dir).map_or(0, |entries| {
            entries
                .flatten()
                .map(|e| {
                    let path = e.path();
                    if path.is_dir() { walk(&path) } else { 1 }
                })
                .sum()
        })
    }
    walk(dir)
}

#[test]
fn m155_cache_upkeep_survives_a_panicking_pass() {
    let dir = std::env::temp_dir().join(format!("ruxen-m155-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let setup = common::ports::setup_lock();
    let [front, back] = common::ports::free_ports();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "pid {d}/ruxen.pid;\nerror_log {d}/error.log info;\nevents {{}}\nhttp {{ access_log off;\n\
             proxy_cache_path {d}/cache keys_zone=z:1m inactive=2s;\n\
             server {{ listen 127.0.0.1:{front}; location / {{ proxy_pass http://127.0.0.1:{back};\n\
             proxy_cache z; proxy_cache_valid 200 1h; }} }}\n\
             server {{ listen 127.0.0.1:{back}; location / {{ return 200 \"ok\\n\"; }} }} }}\n",
            d = dir.display()
        ),
    )
    .unwrap();
    let mut child = KillOnDrop(
        Command::new(env!("CARGO_BIN_EXE_ruxen"))
            .arg("-c")
            .arg(dir.join("nginx.conf"))
            .env("RUXEN_TEST_PANIC", "cache")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    common::ports::wait_for_pid_file(&mut child.0, &dir.join("ruxen.pid"), Duration::from_secs(5));
    drop(setup);
    let mut s = TcpStream::connect(("127.0.0.1", front)).unwrap();
    s.write_all(b"GET /a HTTP/1.0\r\n\r\n").unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    assert!(out.starts_with("HTTP/1.1 200"), "{out}");
    assert_eq!(files(&dir.join("cache")), 1);

    // The first pass panicked; a later one applies `inactive=2s`.
    let deadline = Instant::now() + Duration::from_secs(10);
    while files(&dir.join("cache")) != 0 {
        let log = std::fs::read_to_string(dir.join("error.log")).unwrap_or_default();
        assert!(Instant::now() < deadline, "the cache file stayed:\n{log}");
        std::thread::sleep(Duration::from_millis(200));
    }
    let log = std::fs::read_to_string(dir.join("error.log")).unwrap();
    assert!(
        log.contains("[alert]")
            && log.contains("ruxen-cache-z panicked")
            && log.contains("RUXEN_TEST_PANIC=cache"),
        "{log}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
