//! M165 — `server NAME resolve` in an upstream with a `zone` (#597): the
//! name is asked again when its answer expires, and the peers follow the
//! answers; an error keeps them, a name that doesn't exist leaves none,
//! and a reload starts from the addresses the last configuration had.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

unsafe extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
}

#[derive(Clone)]
enum Reply {
    Addrs(Vec<[u8; 4]>),
    Rcode(u16),
    /// SRV records (priority, port), all for target `t.test`, and the
    /// target's addresses.
    Service(Vec<(u16, u16)>, Vec<[u8; 4]>),
}

/// A name server for `svc.test`: what it answers, and how many questions
/// it had.
struct Dns {
    port: u16,
    reply: Arc<Mutex<Reply>>,
    asked: Arc<AtomicU32>,
}

impl Dns {
    fn start(reply: Reply) -> Dns {
        let udp = {
            let _setup = common::ports::setup_lock();
            UdpSocket::bind("127.0.0.1:0").unwrap()
        };
        let port = udp.local_addr().unwrap().port();
        let reply = Arc::new(Mutex::new(reply));
        let asked = Arc::new(AtomicU32::new(0));
        let (r, a) = (reply.clone(), asked.clone());
        std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            while let Ok((n, from)) = udp.recv_from(&mut buf) {
                let answer = answer(&buf[..n], &r.lock().unwrap());
                a.fetch_add(1, Ordering::SeqCst);
                let _ = udp.send_to(&answer, from);
            }
        });
        Dns { port, reply, asked }
    }

    fn set(&self, reply: Reply) {
        *self.reply.lock().unwrap() = reply;
    }

    /// Until ruxen has asked `n` more times.
    fn wait_asked(&self, n: u32) {
        let target = self.asked.load(Ordering::SeqCst) + n;
        let deadline = Instant::now() + Duration::from_secs(10);
        while self.asked.load(Ordering::SeqCst) < target {
            assert!(Instant::now() < deadline, "not asked again");
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

fn answer(query: &[u8], reply: &Reply) -> Vec<u8> {
    let mut i = 12;
    while query[i] != 0 {
        i += 1 + query[i] as usize;
    }
    let question = &query[12..i + 5];
    let srv = query[i + 2] == 33;
    let (rcode, addrs, srvs) = match reply {
        Reply::Addrs(addrs) => (0, addrs.as_slice(), &[][..]),
        Reply::Rcode(code) => (*code, &[][..], &[][..]),
        Reply::Service(srvs, _) if srv => (0, &[][..], srvs.as_slice()),
        Reply::Service(_, addrs) => (0, addrs.as_slice(), &[][..]),
    };
    let mut out = query[..2].to_vec();
    out.extend_from_slice(&(0x8180 | rcode).to_be_bytes());
    out.extend_from_slice(&[0, 1]);
    out.extend_from_slice(&((addrs.len() + srvs.len()) as u16).to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(question);
    for ip in addrs {
        // TTL 1.
        out.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4]);
        out.extend_from_slice(ip);
    }
    for (priority, port) in srvs {
        let target = b"\x01t\x04test\x00";
        out.extend_from_slice(&[0xc0, 12, 0, 33, 0, 1, 0, 0, 0, 1, 0]);
        out.push(6 + target.len() as u8);
        out.extend_from_slice(&priority.to_be_bytes());
        out.extend_from_slice(&[0, 1]);
        out.extend_from_slice(&port.to_be_bytes());
        out.extend_from_slice(target);
    }
    out
}

/// Backends on 127.0.0.1 and 127.0.0.2, one port, answering `one` and
/// `two`, keeping connections open if `keepalive`; and how many
/// connections 127.0.0.1 accepted.
fn backends(keepalive: bool) -> (u16, Arc<AtomicU32>) {
    let accepted = Arc::new(AtomicU32::new(0));
    let _setup = common::ports::setup_lock();
    let (one, two) = loop {
        let one = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = one.local_addr().unwrap().port();
        if let Ok(two) = TcpListener::bind(("127.0.0.2", port)) {
            break (one, two);
        }
    };
    let port = one.local_addr().unwrap().port();
    let close = if keepalive {
        ""
    } else {
        "Connection: close\r\n"
    };
    for (listener, body) in [(one, "one"), (two, "two")] {
        let count = (body == "one").then(|| accepted.clone());
        std::thread::spawn(move || {
            for mut conn in listener.incoming().flatten() {
                if let Some(count) = &count {
                    count.fetch_add(1, Ordering::SeqCst);
                }
                std::thread::spawn(move || {
                    loop {
                        let mut head = Vec::new();
                        let mut byte = [0u8; 1];
                        while !head.ends_with(b"\r\n\r\n") {
                            if conn.read(&mut byte).unwrap_or(0) != 1 {
                                return;
                            }
                            head.push(byte[0]);
                        }
                        let reply =
                            format!("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n{close}\r\n{body}");
                        if conn.write_all(reply.as_bytes()).is_err() || !keepalive {
                            return;
                        }
                    }
                });
            }
        });
    }
    (port, accepted)
}

struct Server {
    child: common::KillOnDrop,
    dir: PathBuf,
    port: u16,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn new_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ruxen-m165-{}-{}", std::process::id(), {
        static N: AtomicU32 = AtomicU32::new(0);
        N.fetch_add(1, Ordering::Relaxed)
    }));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn conf(dir: &std::path::Path, port: u16, http: &str) {
    let d = dir.display();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "error_log {d}/error.log notice;\nevents {{}}\nhttp {{\n\
             log_format up '$status $upstream_addr';\n\
             access_log {d}/access.log up;\n\
             {http}\n\
             server {{ listen 127.0.0.1:{port};\n\
             location / {{ proxy_pass http://u; }}\n\
             }} }}\n"
        ),
    )
    .unwrap();
}

fn start(http: &str) -> Server {
    start_with(http, 3)
}

fn start_with(http: &str, workers: u32) -> Server {
    let dir = new_dir();
    let setup = common::ports::setup_lock();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    conf(&dir, port, http);
    let mut child = common::KillOnDrop(
        Command::new(env!("CARGO_BIN_EXE_ruxen"))
            .arg("-c")
            .arg(dir.join("nginx.conf"))
            .arg("-g")
            .arg(format!("pid {}/ruxen.pid;", dir.display()))
            // The resolving is one worker's; the others see its peers.
            .env("RUXEN_WORKERS", workers.to_string())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    common::ports::wait_for_pid_file(&mut child, &dir.join("ruxen.pid"), Duration::from_secs(5));
    drop(setup);
    Server { child, dir, port }
}

impl Server {
    fn get(&self) -> (u16, String) {
        let mut s = TcpStream::connect(("127.0.0.1", self.port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        write!(s, "GET / HTTP/1.0\r\nHost: front\r\n\r\n").unwrap();
        let mut out = String::new();
        let _ = s.read_to_string(&mut out);
        let status = out[9..12].parse().unwrap();
        let body = out.split_once("\r\n\r\n").unwrap().1.to_string();
        (status, body)
    }

    /// Until a response is `want` (a status and body), within 10 s.
    fn wait_for(&self, want: (u16, &str)) {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let (status, body) = self.get();
            if status == want.0 && (status != 200 || body == want.1) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "still {status} {body}:\n{}",
                self.error_log()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn bodies(&self, n: usize) -> Vec<String> {
        (0..n)
            .map(|_| {
                let (status, body) = self.get();
                assert_eq!(status, 200, "{}", self.error_log());
                body
            })
            .collect()
    }

    fn error_log(&self) -> String {
        std::fs::read_to_string(self.dir.join("error.log")).unwrap_or_default()
    }
}

const ONE: [u8; 4] = [127, 0, 0, 1];
const TWO: [u8; 4] = [127, 0, 0, 2];

#[test]
fn m165_peers_follow_the_answers() {
    let dns = Dns::start(Reply::Addrs(vec![ONE]));
    let (backend, _) = backends(false);
    let server = start(&format!(
        "resolver 127.0.0.1:{} valid=1s ipv6=off; resolver_timeout 1s;\n\
         upstream u {{ zone z 64k; server svc.test:{backend} resolve max_fails=0; }}",
        dns.port
    ));
    server.wait_for((200, "one"));
    // Changed: every worker moves to the new address.
    dns.set(Reply::Addrs(vec![TWO]));
    server.wait_for((200, "two"));
    assert!(server.bodies(12).iter().all(|b| b == "two"));
    // One more: both serve.
    dns.set(Reply::Addrs(vec![ONE, TWO]));
    let deadline = Instant::now() + Duration::from_secs(10);
    while !server.bodies(6).iter().any(|b| b == "one") {
        assert!(Instant::now() < deadline, "127.0.0.1 not added back");
    }
    assert!(server.bodies(6).iter().any(|b| b == "two"));
    // A failure keeps the peers.
    dns.set(Reply::Rcode(2));
    dns.wait_asked(1);
    assert_eq!(server.get().0, 200);
    // A name that doesn't exist leaves none.
    dns.set(Reply::Rcode(3));
    server.wait_for((502, ""));
    let log = server.error_log();
    assert!(
        log.contains("[error] ")
            && log.contains(" svc.test could not be resolved (2: Server failure)"),
        "{log}"
    );
    assert!(
        log.contains(" svc.test could not be resolved (3: Host not found)")
            && log.contains(" no live upstreams while connecting to upstream"),
        "{log}"
    );
    // And it comes back.
    dns.set(Reply::Addrs(vec![ONE]));
    server.wait_for((200, "one"));
    let access = std::fs::read_to_string(server.dir.join("access.log")).unwrap();
    assert!(
        access.contains(&format!("200 127.0.0.2:{backend}\n")) && access.contains("502 u\n"),
        "{access}"
    );
}

#[test]
fn m165_reload_keeps_the_addresses() {
    let dns = Dns::start(Reply::Addrs(vec![TWO]));
    let (backend, _) = backends(false);
    let http = format!(
        "upstream u {{ zone z 64k; server 127.0.0.3:1 down; \
         server svc.test:{backend} resolve; \
         resolver 127.0.0.1:{} valid=1s ipv6=off; resolver_timeout 1s; }}",
        dns.port
    );
    let server = start(&http);
    server.wait_for((200, "two"));
    dns.set(Reply::Rcode(2));
    dns.wait_asked(1);
    conf(&server.dir, server.port, &format!("{http}\n# reloaded"));
    unsafe {
        assert_eq!(kill(server.child.id() as i32, 1), 0);
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    // The old workers go once the new ones run.
    while !server.error_log().contains("gracefully shutting down") {
        assert!(Instant::now() < deadline, "{}", server.error_log());
        std::thread::sleep(Duration::from_millis(20));
    }
    // The new configuration asks, fails, and serves what the last one had.
    dns.wait_asked(1);
    assert!(server.bodies(6).iter().all(|b| b == "two"));
}

#[test]
fn m165_configuration_errors() {
    let check = |http: &str| {
        let dir = new_dir();
        conf(&dir, 1, http);
        let out = Command::new(env!("CARGO_BIN_EXE_ruxen"))
            .arg("-t")
            .arg("-c")
            .arg(dir.join("nginx.conf"))
            .output()
            .unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    };
    let (ok, err) = check("upstream u { server svc.test resolve; resolver 127.0.0.1; }");
    assert!(
        !ok && err
            .contains("resolving names at run time requires upstream \"u\" to be in shared memory"),
        "{err}"
    );
    let (ok, err) = check("upstream u { zone z; server svc.test resolve; }");
    assert!(
        !ok && err.contains("no resolver defined to resolve names at run time in upstream \"u\""),
        "{err}"
    );
    // The http block's resolver, wherever it is; an address is no name.
    let (ok, err) = check(
        "upstream u { zone z; server svc.test resolve; server 127.0.0.1:81 resolve; }\n\
         resolver 127.0.0.1;",
    );
    assert!(ok, "{err}");
    let (ok, err) = check("upstream u { server 127.0.0.1:81 resolve; }");
    assert!(ok, "{err}");
    // Fails closed until sticky follows resolved peers.
    let (ok, err) = check(
        "upstream u { zone z; sticky cookie s; server svc.test resolve; }\n\
         resolver 127.0.0.1;",
    );
    assert!(
        !ok && err.contains("\"sticky\" with \"resolve\" servers is not supported yet"),
        "{err}"
    );
    for (line, problem) in [
        ("svc.test service=http", "requires \"resolve\" parameter"),
        ("svc.test:80 resolve service=http", "may not have port"),
        ("127.0.0.1 resolve service=http", "requires domain name"),
    ] {
        let (ok, err) = check(&format!(
            "upstream u {{ zone z; server {line}; }} resolver 127.0.0.1;"
        ));
        let want = format!(
            "service upstream \"{}\" {problem}",
            line.split(' ').next().unwrap()
        );
        assert!(!ok && err.contains(&want), "{line}: {err}");
    }
    let (ok, err) = check("upstream u { zone z; server svc.test resolve service=; }");
    assert!(!ok && err.contains("service is empty"), "{err}");
}

#[test]
fn m165_services_give_ports_and_backups() {
    let (backend, _) = backends(false);
    let dead = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let dns = Dns::start(Reply::Service(vec![(1, backend)], vec![ONE]));
    let server = start(&format!(
        "resolver 127.0.0.1:{} valid=1s ipv6=off; resolver_timeout 1s;\n\
         upstream u {{ zone z 64k; server svc.test resolve service=http max_fails=0; }}",
        dns.port
    ));
    server.wait_for((200, "one"));
    // The target's address changes.
    dns.set(Reply::Service(vec![(1, backend)], vec![TWO]));
    server.wait_for((200, "two"));
    // A port nothing listens on first, the backend as a lower priority:
    // a backup peer.
    dns.set(Reply::Service(vec![(1, dead), (2, backend)], vec![ONE]));
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let access = std::fs::read_to_string(server.dir.join("access.log")).unwrap();
        if access.contains(&format!("200 127.0.0.1:{dead}, 127.0.0.1:{backend}\n")) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "{access}\n{}",
            server.error_log()
        );
        let _ = server.get();
        std::thread::sleep(Duration::from_millis(50));
    }
    // No SRV records: no peers.
    dns.set(Reply::Rcode(3));
    server.wait_for((502, ""));
    let log = server.error_log();
    assert!(
        log.contains("service http of svc.test could not be resolved (3: Host not found)"),
        "{log}"
    );
}

#[test]
fn m165_kept_peers_keep_their_connections() {
    let dns = Dns::start(Reply::Addrs(vec![ONE]));
    let (backend, accepted) = backends(true);
    let server = start_with(
        &format!(
            "resolver 127.0.0.1:{} valid=1s ipv6=off;\n\
             proxy_http_version 1.1; proxy_set_header Connection \"\";\n\
             upstream u {{ zone z 64k; server svc.test:{backend} resolve; }}",
            dns.port
        ),
        1,
    );
    server.wait_for((200, "one"));
    assert_eq!(accepted.load(Ordering::SeqCst), 1);
    // A new list: the idle connection to 127.0.0.1 moves to it.
    dns.set(Reply::Addrs(vec![ONE, TWO]));
    server.wait_for((200, "two"));
    assert!(server.bodies(6).iter().any(|b| b == "one"));
    assert_eq!(accepted.load(Ordering::SeqCst), 1, "{}", server.error_log());
}
