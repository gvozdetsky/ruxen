//! M67 — `access_log syslog:…` sends each line to syslog, as nginx's
//! ngx_http_log_module with ngx_syslog.c: one RFC 3164 datagram,
//! `<PRI>Mmm dd hh:mm:ss host tag: line`, facility local7 and severity info
//! unless set. It used to write the lines to a file named
//! `syslog:server=…`.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, MutexGuard};
use std::thread::sleep;
use std::time::{Duration, Instant};

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

/// Held from picking a port until ruxen listens on it, so a parallel test
/// can't take it in between.
fn ports_lock() -> MutexGuard<'static, ()> {
    static PORTS: Mutex<()> = Mutex::new(());
    PORTS.lock().unwrap_or_else(|e| e.into_inner())
}

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ruxen-m67-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn write_conf(dir: &Path, port: u16, http_extra: &str, access_log: &str) -> PathBuf {
    let conf = dir.join("nginx.conf");
    std::fs::write(
        &conf,
        format!(
            "pid {d}/ruxen.pid;\nevents {{}}\nhttp {{ {http_extra}\n\
             server {{ listen 127.0.0.1:{port}; access_log {access_log};\n\
               location / {{ return 200 ok; }} }} }}\n",
            d = dir.display()
        ),
    )
    .unwrap();
    conf
}

fn start(tag: &str, http_extra: &str, access_log: &str) -> Server {
    let _ports = ports_lock();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let dir = temp_dir(tag);
    let conf = write_conf(&dir, port, http_extra, access_log);
    let mut child = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .arg("-c")
        .arg(&conf)
        .current_dir(&dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    while !dir.join("ruxen.pid").exists() {
        assert!(
            Instant::now() < deadline && child.try_wait().unwrap().is_none(),
            "ruxen did not start"
        );
        sleep(Duration::from_millis(10));
    }
    Server { child, port, dir }
}

fn get(port: u16, path: &str) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    assert!(out.starts_with("HTTP/1.1 200"), "{out}");
}

fn udp_listener() -> UdpSocket {
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    sock
}

fn recv(sock: &UdpSocket) -> String {
    let mut buf = [0u8; 4096];
    let n = sock.recv(&mut buf).expect("no syslog datagram");
    String::from_utf8_lossy(&buf[..n]).into_owned()
}

/// `<PRI>Mmm dd hh:mm:ss ` — the RFC 3164 header up to the host.
const HEADER: &str = r"^<(\d{1,3})>[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d ";

#[test]
fn lines_go_to_syslog_like_nginx() {
    let udp = udp_listener();
    let peer = format!("syslog:server={}", udp.local_addr().unwrap());
    let server = start("default", "", &peer);
    get(server.port, "/a");
    let msg = recv(&udp);
    // local7.info = 23 * 8 + 6; then the host, the tag and the combined
    // line, without a trailing newline.
    let re = regex::Regex::new(&format!(
        r#"{HEADER}\S+ ruxen: 127\.0\.0\.1 - - \[[^\]]+\] "GET /a HTTP/1\.1" 200 2 "-" "-"$"#
    ))
    .unwrap();
    let caps = re.captures(&msg).unwrap_or_else(|| panic!("{msg:?}"));
    assert_eq!(&caps[1], "190", "{msg:?}");
    // Nothing was written to a file named after the argument.
    let stray: Vec<_> = std::fs::read_dir(&server.dir)
        .unwrap()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with("syslog"))
        .collect();
    assert!(stray.is_empty(), "{stray:?}");
}

#[test]
fn facility_severity_tag_nohostname_and_format() {
    let udp = udp_listener();
    let access_log = format!(
        "syslog:facility=user,severity=alert,server={},tag=SEETHIS,nohostname f",
        udp.local_addr().unwrap()
    );
    let server = start("options", "log_format f \"uri=$uri\";", &access_log);
    get(server.port, "/b");
    let msg = recv(&udp);
    // user.alert = 1 * 8 + 1, and no host before the tag.
    let re = regex::Regex::new(&format!("{HEADER}SEETHIS: uri=/b$")).unwrap();
    let caps = re.captures(&msg).unwrap_or_else(|| panic!("{msg:?}"));
    assert_eq!(&caps[1], "9", "{msg:?}");
}

#[test]
fn unix_socket_server() {
    let dir = temp_dir("unix-sock");
    let path = dir.join("log.sock");
    let sock = UnixDatagram::bind(&path).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let server = start(
        "unix",
        "log_format f \"$uri\";",
        &format!("syslog:server=unix:{},nohostname f", path.display()),
    );
    get(server.port, "/c");
    let mut buf = [0u8; 4096];
    let n = sock.recv(&mut buf).expect("no syslog datagram");
    let msg = String::from_utf8_lossy(&buf[..n]);
    assert!(
        msg.starts_with("<190>") && msg.ends_with(" ruxen: /c"),
        "{msg:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn bad_parameters_are_config_errors() {
    for (tag, access_log) in [
        ("nosrv", "syslog:facility=user"),
        ("fac", "syslog:server=127.0.0.1:1,facility=bogus"),
        ("sev", "syslog:server=127.0.0.1:1,severity=err"),
        ("tag", "syslog:server=127.0.0.1:1,tag=no-dash"),
        ("dup", "syslog:server=127.0.0.1:1,server=127.0.0.1:2"),
        ("param", "syslog:server=127.0.0.1:1,bogus"),
    ] {
        let dir = temp_dir(&format!("bad-{tag}"));
        let conf = write_conf(&dir, 1, "", access_log);
        let out = Command::new(env!("CARGO_BIN_EXE_ruxen"))
            .arg("-t")
            .arg("-c")
            .arg(&conf)
            .current_dir(&dir)
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            !out.status.success() && stderr.contains("[emerg]"),
            "{access_log}: {stderr}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
