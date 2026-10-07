//! M90 — the realip module: `set_real_ip_from`, `real_ip_header`
//! (X-Real-IP, X-Forwarded-For, proxy_protocol, any header) and
//! `real_ip_recursive`, at http, server and location level. The address
//! it sets is `$remote_addr` / `$remote_port` for the rest of the
//! request, what `allow` / `deny` match and what the access log shows;
//! `$realip_remote_addr` / `$realip_remote_port` keep the peer. Before,
//! the directives were unknown. Checked against nginx 1.24.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

/// Send `head` (request line and headers, CRLF-separated, without the
/// final blank line), after `prefix` (a PROXY protocol line), and return
/// "status body".
fn request(port: u16, prefix: &str, head: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(s, "{prefix}{head}\r\nHost: x\r\nConnection: close\r\n\r\n").unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    let code = out.get(9..12).unwrap_or("").to_string();
    let body = out.split_once("\r\n\r\n").map_or("", |(_, b)| b).trim();
    let reason = out.lines().next().and_then(|l| l.get(13..)).unwrap_or("");
    if body.is_empty() || body.contains(reason) || body.contains(&code) {
        return code;
    }
    format!("{code} {body}")
}

#[test]
fn realip_sets_the_client_address() {
    let setup = common::ports::setup_lock();
    // Bound together, so the three ports differ.
    let probes: Vec<TcpListener> = (0..3)
        .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    let ports: Vec<u16> = probes
        .iter()
        .map(|l| l.local_addr().unwrap().port())
        .collect();
    drop(probes);
    let (port, rec_port, pp_port) = (ports[0], ports[1], ports[2]);
    let d = std::env::temp_dir().join(format!("ruxen-m90-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    for dir in ["deny", "loc"] {
        std::fs::create_dir_all(d.join("html").join(dir)).unwrap();
        std::fs::write(d.join("html").join(dir).join("index.html"), "allowed").unwrap();
    }
    let dd = d.display();
    let show = "return 200 \"$remote_addr [$remote_port] $realip_remote_addr\"";
    std::fs::write(
        d.join("nginx.conf"),
        format!(
            "pid {dd}/ruxen.pid;\nevents {{}}\nhttp {{\n\
             log_format t '$remote_addr $realip_remote_addr $request_uri';\n\
             access_log {dd}/access.log t;\n\
             set_real_ip_from 127.0.0.1/32;\n\
             set_real_ip_from 192.0.2.0/24;\n\
             real_ip_header X-Forwarded-For;\n\
             server {{ listen 127.0.0.1:{port}; root {dd}/html;\n\
               location /off {{ {show}; }}\n\
               location /deny/ {{ deny 10.0.0.0/8; }}\n\
               location /loc/ {{ set_real_ip_from 127.0.0.1; real_ip_header X-Client; deny 10.9.9.9; }}\n\
             }}\n\
             server {{ listen 127.0.0.1:{rec_port}; real_ip_recursive on;\n\
               location /on {{ {show}; }}\n\
             }}\n\
             server {{ listen 127.0.0.1:{pp_port} proxy_protocol; root {dd}/html;\n\
               set_real_ip_from 127.0.0.1;\n\
               real_ip_header proxy_protocol;\n\
               location / {{ {show}; }}\n\
               location /header {{ set_real_ip_from 192.0.2.1; real_ip_header X-Client; {show}; }}\n\
               location /deny/ {{ deny 192.0.2.1; }}\n\
             }}\n\
             }}\n"
        ),
    )
    .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .arg("-c")
        .arg(d.join("nginx.conf"))
        .env("TMPDIR", &d)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    while !d.join("ruxen.pid").exists() {
        assert!(
            Instant::now() < deadline && child.try_wait().unwrap().is_none(),
            "ruxen did not start"
        );
        sleep(Duration::from_millis(10));
    }
    drop(setup);

    let xff = |list: &str| format!("\r\nX-Forwarded-For: {list}");
    let pp = "PROXY TCP4 192.0.2.1 127.0.0.1 4321 80\r\n";
    let cases = [
        // Not recursive: the last entry, no port.
        (
            port,
            "",
            format!("GET /off HTTP/1.1{}", xff("10.0.0.1, 192.0.2.7")),
            "200 192.0.2.7 [] 127.0.0.1",
        ),
        // Recursive: right to left past the trusted entries.
        (
            rec_port,
            "",
            format!("GET /on HTTP/1.1{}", xff("10.0.0.1, 192.0.2.7")),
            "200 10.0.0.1 [] 127.0.0.1",
        ),
        // Several header lines are one list; a port is taken.
        (
            rec_port,
            "",
            format!("GET /on HTTP/1.1{}{}", xff("10.0.0.1:81"), xff("192.0.2.7")),
            "200 10.0.0.1 [81] 127.0.0.1",
        ),
        // A bad entry: the peer stays.
        (
            port,
            "",
            format!("GET /off HTTP/1.1{}", xff("bogus")),
            "OWN",
        ),
        // `deny` sees the new address, also after the index redirect.
        (
            port,
            "",
            format!("GET /deny/ HTTP/1.1{}", xff("10.1.2.3")),
            "403",
        ),
        (
            port,
            "",
            format!("GET /deny/ HTTP/1.1{}", xff("192.0.2.9")),
            "200 allowed",
        ),
        // No X-Forwarded-For: the server's settings set nothing, so the
        // location's (another header) apply before the access phase.
        (
            port,
            "",
            "GET /loc/ HTTP/1.1\r\nX-Client: 10.9.9.9".to_string(),
            "403",
        ),
        (
            port,
            "",
            "GET /loc/ HTTP/1.1\r\nX-Client: 10.9.9.8".to_string(),
            "200 allowed",
        ),
        (
            port,
            "",
            format!(
                "GET /loc/ HTTP/1.1\r\nX-Client: 10.9.9.9{}",
                xff("192.0.2.9")
            ),
            "200 allowed",
        ),
        // PROXY protocol: its source address and port.
        (
            pp_port,
            pp,
            "GET / HTTP/1.1".to_string(),
            "200 192.0.2.1 [4321] 127.0.0.1",
        ),
        (pp_port, pp, "GET /deny/ HTTP/1.1".to_string(), "403"),
        // The server's settings already set the address: the location's
        // own (another header) don't apply.
        (
            pp_port,
            pp,
            "GET /header HTTP/1.1\r\nX-Client: 10.9.9.9".to_string(),
            "200 192.0.2.1 [4321] 127.0.0.1",
        ),
    ]
    .map(|(p, prefix, head, want)| (p, prefix, head, want.to_string()));
    let got: Vec<String> = cases
        .iter()
        .map(|(p, prefix, head, _)| request(*p, prefix, head))
        .collect();
    let _ = child.kill();
    let _ = child.wait();
    let log = std::fs::read_to_string(d.join("access.log")).unwrap_or_default();
    let _ = std::fs::remove_dir_all(&d);
    for ((_, _, head, want), got) in cases.iter().zip(&got) {
        if want == "OWN" {
            assert!(
                got.starts_with("200 127.0.0.1 [") && got.ends_with("] 127.0.0.1"),
                "{head}: {got}"
            );
        } else {
            assert_eq!(got, want, "{head}");
        }
    }
    // The access log shows the address realip set, and the peer.
    assert!(log.contains("192.0.2.7 127.0.0.1 /off\n"), "{log}");
    assert!(log.contains("10.1.2.3 127.0.0.1 /deny/\n"), "{log}");
}
