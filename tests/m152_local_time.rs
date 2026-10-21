//! M152 — log times in the local zone, as nginx (#614): `$time_local` and
//! `$time_iso8601` carry the zone's offset, and the error-log prefix is
//! local time too. The zone comes from `TZ` here (a POSIX rule, no tzdata
//! needed): `ABC-2:30` is UTC+2:30.

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::time::Duration;

struct KillOnDrop(std::process::Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn get(port: u16, path: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.write_all(format!("GET {path} HTTP/1.0\r\n\r\n").as_bytes())
        .unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    let at = out.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    String::from_utf8_lossy(&out[at..]).into_owned()
}

/// Seconds into the day of an `hh:mm:ss`.
fn day_secs(hms: &str) -> i64 {
    let mut parts = hms.split(':').map(|p| p.parse::<i64>().unwrap());
    let (h, m, s) = (
        parts.next().unwrap(),
        parts.next().unwrap(),
        parts.next().unwrap(),
    );
    h * 3600 + m * 60 + s
}

#[test]
fn m152_log_times_are_local() {
    let dir = std::env::temp_dir().join(format!("ruxen-m152-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let setup = common::ports::setup_lock();
    let [port] = common::ports::free_ports();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "error_log {d}/error.log info;\nevents {{}}\nhttp {{ server {{ listen 127.0.0.1:{port};\n\
             location /missing {{ root {d}/nope; }}\n\
             location / {{ return 200 \"$time_local|$time_iso8601\"; }} }} }}\n",
            d = dir.display()
        ),
    )
    .unwrap();
    let mut child = KillOnDrop(
        Command::new(env!("CARGO_BIN_EXE_ruxen"))
            .arg("-c")
            .arg(dir.join("nginx.conf"))
            .arg("-g")
            .arg(format!("pid {}/ruxen.pid;", dir.display()))
            .env("TZ", "ABC-2:30")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    common::ports::wait_for_pid_file(&mut child.0, &dir.join("ruxen.pid"), Duration::from_secs(5));
    drop(setup);

    let utc = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let body = get(port, "/");
    let (local, iso) = body.split_once('|').expect("two times");
    assert!(local.ends_with(" +0230"), "{local}");
    assert!(iso.ends_with("+02:30"), "{iso}");
    // The clock is UTC + 2:30, a second or two after `utc`.
    let expected = (utc + 9000).rem_euclid(86_400);
    let shown = day_secs(&iso[11..19]);
    assert!((shown - expected).rem_euclid(86_400) <= 5, "{iso}");
    assert_eq!(&local[12..20], &iso[11..19], "{body}");

    get(port, "/missing");
    std::thread::sleep(Duration::from_millis(100));
    let errors = std::fs::read_to_string(dir.join("error.log")).unwrap();
    let line = errors
        .lines()
        .find(|l| l.contains("[error]") && l.contains("open()"))
        .unwrap_or_else(|| panic!("{errors}"));
    let logged = day_secs(&line[11..19]);
    assert!((logged - expected).rem_euclid(86_400) <= 5, "{line}");
    drop(child);
    let _ = std::fs::remove_dir_all(&dir);
}
