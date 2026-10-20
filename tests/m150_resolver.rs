//! M150 — `resolver` (#133): a `proxy_pass` with variables whose host is a
//! name asks the location's resolver at run time. The answers are cached,
//! every address is tried in turn, a truncated answer is asked again over
//! TCP, CNAMEs are followed; a name that doesn't resolve is a 502 with
//! nginx's `could not be resolved` line.

mod common;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The ruxen process (stopped on drop) and its directory.
struct Server(#[allow(dead_code)] common::KillOnDrop, PathBuf);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.1);
    }
}

/// Queries seen, by name.
type Seen = Arc<Mutex<HashMap<String, u32>>>;

/// A name server on UDP and TCP of one port, with a few test names.
fn dns() -> (u16, Seen) {
    let seen: Seen = Arc::default();
    let (udp, tcp) = {
        let _setup = common::ports::setup_lock();
        loop {
            let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            let port = udp.local_addr().unwrap().port();
            if let Ok(tcp) = TcpListener::bind(("127.0.0.1", port)) {
                break (udp, tcp);
            }
        }
    };
    let port = udp.local_addr().unwrap().port();
    let s = seen.clone();
    std::thread::spawn(move || {
        let mut buf = [0u8; 512];
        while let Ok((n, from)) = udp.recv_from(&mut buf) {
            if let Some(reply) = answer(&buf[..n], false, &s) {
                let _ = udp.send_to(&reply, from);
            }
        }
    });
    let s = seen.clone();
    std::thread::spawn(move || {
        for mut conn in tcp.incoming().flatten() {
            let mut len = [0u8; 2];
            if conn.read_exact(&mut len).is_err() {
                continue;
            }
            let mut query = vec![0u8; u16::from_be_bytes(len) as usize];
            if conn.read_exact(&mut query).is_err() {
                continue;
            }
            if let Some(reply) = answer(&query, true, &s) {
                let _ = conn.write_all(&(reply.len() as u16).to_be_bytes());
                let _ = conn.write_all(&reply);
            }
        }
    });
    (port, seen)
}

/// The reply to one query, or `None` to stay silent.
fn answer(query: &[u8], tcp: bool, seen: &Seen) -> Option<Vec<u8>> {
    let mut i = 12;
    let mut labels = Vec::new();
    while query[i] != 0 {
        let len = query[i] as usize;
        labels.push(String::from_utf8_lossy(&query[i + 1..i + 1 + len]).to_lowercase());
        i += 1 + len;
    }
    let name = labels.join(".");
    let qtype = u16::from_be_bytes([query[i + 1], query[i + 2]]);
    let question = &query[12..i + 5];
    *seen.lock().unwrap().entry(name.clone()).or_default() += 1;

    let a = |ip: [u8; 4]| {
        let mut r = vec![0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4];
        r.extend_from_slice(&ip);
        r
    };
    let cname = |target: &str| {
        let mut data = Vec::new();
        for label in target.split('.') {
            data.push(label.len() as u8);
            data.extend_from_slice(label.as_bytes());
        }
        data.push(0);
        let mut r = vec![0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 60];
        r.extend_from_slice(&(data.len() as u16).to_be_bytes());
        r.extend_from_slice(&data);
        r
    };
    let (mut flags, mut records): (u16, Vec<Vec<u8>>) = (0x8180, Vec::new());
    match (name.as_str(), qtype) {
        ("good.test", 1) => records.push(a([127, 0, 0, 1])),
        // The first address refuses: nothing listens there.
        ("two.test", 1) => records.extend([a([127, 0, 0, 2]), a([127, 0, 0, 1])]),
        ("nx.test", _) => flags |= 3,
        ("slow.test", _) => return None,
        ("tc.test", 1) if !tcp => {
            flags |= 0x0200;
            records.push(a([127, 0, 0, 9]));
        }
        ("tc.test", 1) => records.push(a([127, 0, 0, 1])),
        ("alias.test", _) => records.push(cname("good.test")),
        _ => {}
    }
    let mut reply = query[..2].to_vec();
    reply.extend_from_slice(&flags.to_be_bytes());
    reply.extend_from_slice(&[0, 1]);
    reply.extend_from_slice(&(records.len() as u16).to_be_bytes());
    reply.extend_from_slice(&[0, 0, 0, 0]);
    reply.extend_from_slice(question);
    for r in records {
        reply.extend_from_slice(&r);
    }
    Some(reply)
}

/// An HTTP backend on 127.0.0.1 answering `backend`.
fn backend() -> u16 {
    let listener = {
        let _setup = common::ports::setup_lock();
        TcpListener::bind("127.0.0.1:0").unwrap()
    };
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut conn in listener.incoming().flatten() {
            std::thread::spawn(move || {
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") && conn.read(&mut byte).unwrap_or(0) == 1 {
                    head.push(byte[0]);
                }
                let _ = conn.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nbackend",
                );
            });
        }
    });
    port
}

fn start(dns: u16, backend: u16) -> (Server, u16) {
    let dir = std::env::temp_dir().join(format!("ruxen-m150-{}-{}", std::process::id(), {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        N.fetch_add(1, Ordering::Relaxed)
    }));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let setup = common::ports::setup_lock();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let d = dir.display();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "error_log {d}/error.log;\nevents {{}}\nhttp {{\n\
             log_format up '$arg_h $status $upstream_addr';\n\
             access_log {d}/access.log up;\n\
             resolver 127.0.0.1:{dns} ipv6=off;\n\
             resolver_timeout 700ms;\n\
             server {{ listen 127.0.0.1:{port};\n\
             location / {{ proxy_pass http://$arg_h:{backend}/; }}\n\
             location /none/ {{ resolver_timeout 30s;\n\
             location /none/in/ {{ proxy_pass http://$arg_h:{backend}/; }} }}\n\
             }} }}\n"
        ),
    )
    .unwrap();
    let mut child = common::KillOnDrop(
        Command::new(env!("CARGO_BIN_EXE_ruxen"))
            .arg("-c")
            .arg(dir.join("nginx.conf"))
            .arg("-g")
            .arg(format!("pid {d}/ruxen.pid;"))
            // The query counts assume one cache: each worker has its own.
            .env_remove("RUXEN_WORKERS")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    common::ports::wait_for_pid_file(&mut child, &dir.join("ruxen.pid"), Duration::from_secs(5));
    drop(setup);
    (Server(child, dir), port)
}

fn get(port: u16, target: &str) -> (u16, String) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    write!(s, "GET {target} HTTP/1.0\r\nHost: front\r\n\r\n").unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    let status = out[9..12].parse().unwrap();
    let body = out.split_once("\r\n\r\n").unwrap().1.to_string();
    (status, body)
}

fn read(server: &Server, file: &str) -> String {
    std::fs::read_to_string(server.1.join(file)).unwrap_or_default()
}

#[test]
fn m150_names_resolve_and_are_cached() {
    let (dns, seen) = dns();
    let (server, port) = start(dns, backend());
    assert_eq!(get(port, "/?h=good.test"), (200, "backend".into()));
    // Cached, whatever the case.
    assert_eq!(get(port, "/?h=GOOD.test.").0, 200);
    assert_eq!(seen.lock().unwrap()["good.test"], 1);
    // A CNAME, followed to a name already in the cache.
    assert_eq!(get(port, "/?h=alias.test").0, 200);
    assert_eq!(seen.lock().unwrap()["good.test"], 1);
    // The second address after the first refuses.
    assert_eq!(get(port, "/?h=two.test").0, 200);
    // Truncated over UDP, answered over TCP.
    assert_eq!(get(port, "/?h=tc.test").0, 200);
    let log = read(&server, "access.log");
    let backend_port = log
        .lines()
        .next()
        .and_then(|l| l.rsplit(':').next())
        .unwrap()
        .to_string();
    assert!(
        log.contains(&format!(
            "two.test 200 127.0.0.2:{backend_port}, 127.0.0.1:{backend_port}\n"
        )),
        "{log}"
    );
    assert!(
        log.contains(&format!("tc.test 200 127.0.0.1:{backend_port}\n")),
        "{log}"
    );
}

#[test]
fn m150_names_that_dont_resolve() {
    let (dns, _) = dns();
    let (server, port) = start(dns, backend());
    assert_eq!(get(port, "/?h=nx.test").0, 502);
    let started = Instant::now();
    assert_eq!(get(port, "/?h=slow.test").0, 502);
    // resolver_timeout, not the 5 s of a resend.
    let took = started.elapsed();
    assert!(
        took >= Duration::from_millis(600) && took < Duration::from_secs(4),
        "{took:?}"
    );
    // A label too long to ask is not found at once.
    assert_eq!(get(port, &format!("/?h={}.test", "a".repeat(64))).0, 502);
    let log = read(&server, "error.log");
    assert!(
        log.contains("[error] ")
            && log
                .contains(" nx.test could not be resolved (3: Host not found), client: 127.0.0.1,"),
        "{log}"
    );
    assert!(
        log.contains(" slow.test could not be resolved (110: Operation timed out), client: "),
        "{log}"
    );
}

#[test]
fn m150_inherited_resolver_and_timeout() {
    let (dns, seen) = dns();
    let (server, port) = start(dns, backend());
    // The http block's resolver, with the outer location's timeout: the
    // client gives up first, and the query is dropped with it.
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    write!(s, "GET /none/in/?h=slow.test HTTP/1.0\r\n\r\n").unwrap();
    std::thread::sleep(Duration::from_millis(1500));
    drop(s);
    assert_eq!(seen.lock().unwrap()["slow.test"], 1);
    // The same cache as `/`.
    assert_eq!(get(port, "/?h=good.test").0, 200);
    assert_eq!(get(port, "/none/in/?h=good.test").0, 200);
    assert_eq!(seen.lock().unwrap()["good.test"], 1);
    assert!(!read(&server, "error.log").contains("[alert]"));
}
