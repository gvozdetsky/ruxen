//! M114 — WebSocket and other upgrades through proxy_pass (#87): an
//! upstream 101 to a client that asked to upgrade turns the connection
//! into a tunnel. Bytes sent early on either side go first, both
//! directions run at once, `proxy_read_timeout` without traffic ends it
//! with nginx's error line, and the access log counts the tunnelled bytes.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Server(Child, std::path::PathBuf);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
        let _ = std::fs::remove_dir_all(&self.1);
    }
}

/// Answers any request with a 101 and `hello`, then echoes what it reads.
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
                while !head.ends_with(b"\r\n\r\n") {
                    if conn.read(&mut byte).unwrap_or(0) == 0 {
                        return;
                    }
                    head.push(byte[0]);
                }
                conn.write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
                      Connection: Upgrade\r\n\r\nhello",
                )
                .unwrap();
                let mut reader = conn.try_clone().unwrap();
                let mut buf = [0u8; 65536];
                loop {
                    match reader.read(&mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if conn.write_all(&buf[..n]).is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    port
}

fn start(backend: u16, name: &str) -> (Server, u16) {
    start_with(backend, name, "", "")
}

/// `listen_extra` goes on the listen line, `server_extra` into the server.
fn start_with(backend: u16, name: &str, listen_extra: &str, server_extra: &str) -> (Server, u16) {
    let dir = std::env::temp_dir().join(format!("ruxen-m114-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // Held until ruxen listens: released earlier, another test could take
    // the same free port, and ruxen would fail to bind it.
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
            "error_log {d}/error.log info;\nevents {{}}\nhttp {{\n\
             log_format t \"$status $bytes_sent $body_bytes_sent $upstream_bytes_received\";\n\
             access_log {d}/access.log t;\n\
             server {{ listen 127.0.0.1:{port}{listen_extra}; {server_extra}\n\
             location / {{ proxy_pass http://127.0.0.1:{backend};\n\
               proxy_http_version 1.1; proxy_set_header Upgrade $http_upgrade;\n\
               proxy_set_header Connection upgrade; proxy_read_timeout 1s; }}\n\
             }} }}\n"
        ),
    )
    .unwrap();
    // Owned by `Server` before the wait: if it panics, ruxen still stops.
    let mut server = Server(
        Command::new(env!("CARGO_BIN_EXE_ruxen"))
            .arg("-c")
            .arg(dir.join("nginx.conf"))
            .arg("-g")
            .arg(format!("pid {}/ruxen.pid;", dir.display()))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
        dir,
    );
    let pid_file = server.1.join("ruxen.pid");
    common::ports::wait_for_pid_file(&mut server.0, &pid_file, Duration::from_secs(5));
    drop(setup);
    (server, port)
}

/// Read until `want` bytes past the response head have arrived; returns
/// the head and those bytes.
fn read_head_and(s: &mut TcpStream, want: usize) -> (String, Vec<u8>) {
    let mut got = Vec::new();
    let mut buf = [0u8; 65536];
    loop {
        if let Some(end) = got.windows(4).position(|w| w == b"\r\n\r\n")
            && got.len() >= end + 4 + want
        {
            let head = String::from_utf8_lossy(&got[..end + 4]).into_owned();
            return (head, got[end + 4..].to_vec());
        }
        let n = s.read(&mut buf).unwrap();
        assert!(n > 0, "closed early: {}", String::from_utf8_lossy(&got));
        got.extend_from_slice(&buf[..n]);
    }
}

#[test]
fn m114_websocket_tunnel() {
    let (server, port) = start(backend(), "tunnel");
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    // Bytes right behind the request head go to the upstream first.
    s.write_all(
        b"GET /chat HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n\
          Connection: Upgrade\r\n\r\nearly",
    )
    .unwrap();
    let (head, body) = read_head_and(&mut s, 10);
    assert!(
        head.starts_with("HTTP/1.1 101 Switching Protocols\r\n"),
        "{head}"
    );
    assert!(head.contains("\r\nConnection: upgrade\r\n"), "{head}");
    assert!(head.contains("\r\nUpgrade: websocket\r\n"), "{head}");
    assert_eq!(body, b"helloearly");

    // A megabyte each way, written before anything is read back: the
    // directions don't wait for each other.
    let big: Vec<u8> = (0..1 << 20).map(|i| (i % 251) as u8).collect();
    let mut writer = s.try_clone().unwrap();
    let sent = big.clone();
    let t = std::thread::spawn(move || writer.write_all(&sent).unwrap());
    let mut echoed = vec![0u8; big.len()];
    s.read_exact(&mut echoed).unwrap();
    t.join().unwrap();
    assert!(echoed == big);

    // Nothing for proxy_read_timeout (1s): the tunnel ends.
    let started = Instant::now();
    let mut rest = Vec::new();
    let _ = s.read_to_end(&mut rest);
    assert!(rest.is_empty());
    assert!(started.elapsed() < Duration::from_secs(4));

    std::thread::sleep(Duration::from_millis(200));
    let log = std::fs::read_to_string(server.1.join("error.log")).unwrap();
    assert!(
        log.contains(
            "upstream timed out (110: Connection timed out) while proxying upgraded connection"
        ),
        "{log}"
    );
    let access = std::fs::read_to_string(server.1.join("access.log")).unwrap();
    let fields: Vec<u64> = access
        .split_whitespace()
        .map(|f| f.parse().unwrap())
        .collect();
    let to_client = 10 + (1 << 20) as u64;
    assert_eq!(fields[0], 101);
    assert_eq!(fields[1], head.len() as u64 + to_client, "{access}");
    assert_eq!(fields[2], to_client, "{access}");
}

#[test]
fn m114_no_tunnel_unless_the_client_asked() {
    // The upstream switches anyway: without the client's `Upgrade` the
    // 101 is an ordinary response, sent without a body, as nginx does.
    let (_server, port) = start(backend(), "plain");
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    assert!(out.starts_with("HTTP/1.1 101"), "{out}");
    assert!(out.ends_with("\r\n\r\n"), "{out}");
}

/// The same tunnel over TLS, where a read and a write of the client
/// stream are in flight at once (`TlsStream::begin_tunnel`): rounds of
/// 256 KiB each way, echoed while they are still being sent.
#[test]
fn m114_websocket_tunnel_over_tls() {
    use std::sync::Arc;
    let certs = common::tls::make_ca_and_leaf("localhost");
    let server_extra = format!(
        "ssl_certificate {}; ssl_certificate_key {};",
        certs.cert_path().display(),
        certs.key_path().display()
    );
    let (_server, port) = start_with(backend(), "tls", " ssl", &server_extra);

    let mut roots = rustls::RootCertStore::empty();
    let ca = std::fs::read(certs.ca_path().unwrap()).unwrap();
    for cert in
        <rustls::pki_types::CertificateDer as rustls::pki_types::pem::PemObject>::pem_slice_iter(
            &ca,
        )
    {
        roots.add(cert.unwrap()).unwrap();
    }
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let conn = rustls::ClientConnection::new(Arc::new(config), name).unwrap();
    let sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut s = rustls::StreamOwned::new(conn, sock);
    s.write_all(
        b"GET /chat HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n\
          Connection: Upgrade\r\n\r\n",
    )
    .unwrap();
    let mut got = Vec::new();
    let mut buf = [0u8; 65536];
    while !got.windows(9).any(|w| w == b"\r\n\r\nhello") {
        let n = s.read(&mut buf).unwrap();
        assert!(n > 0, "{}", String::from_utf8_lossy(&got));
        got.extend_from_slice(&buf[..n]);
    }
    assert!(got.starts_with(b"HTTP/1.1 101 "));
    for round in 0..4u8 {
        let chunk: Vec<u8> = (0..256 * 1024).map(|i| (i as u8) ^ round).collect();
        s.write_all(&chunk).unwrap();
        let mut echoed = vec![0u8; chunk.len()];
        s.read_exact(&mut echoed).unwrap();
        assert!(echoed == chunk, "round {round}");
    }
}

/// Answers `/ws` with a 101 and `ws<tag>` and then holds the connection;
/// anything else with a 200 and `<tag>`.
fn tagged_backend(tag: char) -> u16 {
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
                while !head.ends_with(b"\r\n\r\n") {
                    if conn.read(&mut byte).unwrap_or(0) == 0 {
                        return;
                    }
                    head.push(byte[0]);
                }
                if head.starts_with(b"GET /ws ") {
                    let _ = write!(
                        conn,
                        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
                         Connection: Upgrade\r\n\r\nws{tag}"
                    );
                    let _ = conn.read(&mut [0u8; 16]);
                } else {
                    let _ = write!(
                        conn,
                        "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\n\r\n{tag}"
                    );
                }
            });
        }
    });
    port
}

#[test]
fn m114_least_conn_counts_open_tunnels() {
    let (a, b) = (tagged_backend('A'), tagged_backend('B'));
    let dir = std::env::temp_dir().join(format!("ruxen-m114-lc-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let setup = common::ports::setup_lock();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "events {{}}\nhttp {{ access_log off;\n\
             upstream u {{ least_conn; server 127.0.0.1:{a}; server 127.0.0.1:{b}; }}\n\
             server {{ listen 127.0.0.1:{port};\n\
             location / {{ proxy_pass http://u; proxy_http_version 1.1;\n\
               proxy_set_header Upgrade $http_upgrade; proxy_set_header Connection $http_connection; }}\n\
             }} }}\n"
        ),
    )
    .unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .arg("-c")
        .arg(dir.join("nginx.conf"))
        .arg("-g")
        .arg(format!("pid {}/ruxen.pid;", dir.display()))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut server = Server(child, dir);
    let pid_file = server.1.join("ruxen.pid");
    common::ports::wait_for_pid_file(&mut server.0, &pid_file, Duration::from_secs(5));
    drop(setup);

    let mut ws = TcpStream::connect(("127.0.0.1", port)).unwrap();
    ws.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    ws.write_all(
        b"GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
    )
    .unwrap();
    let (head, body) = read_head_and(&mut ws, 3);
    assert!(head.starts_with("HTTP/1.1 101 "), "{head}");
    let busy = body[2] as char;

    // The open tunnel counts as a connection to its peer, as in nginx:
    // every plain request goes to the other one.
    for _ in 0..4 {
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        s.write_all(b"GET /plain HTTP/1.0\r\nHost: x\r\n\r\n")
            .unwrap();
        let mut out = String::new();
        let _ = s.read_to_string(&mut out);
        assert!(out.starts_with("HTTP/1.1 200 "), "{out}");
        assert_ne!(out.chars().last(), Some(busy), "{out}");
    }
    drop(ws);
}
