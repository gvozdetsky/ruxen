//! M76 — the TLS certificate is chosen by SNI for every `server_name`
//! form, as nginx's ngx_http_ssl_servername (the same lookup as `Host`):
//! exact, `*.leading`, `trailing.*` (longest wins), then regexes in order.
//! Trailing wildcards and regexes used to get the default certificate,
//! although `Host` routed the request to the right server.

mod common;

use std::io::Write;
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

/// The subject CN of the certificate served for `sni`.
fn served_cn(port: u16, sni: &str) -> String {
    let mut client = Command::new("openssl")
        .args(["s_client", "-connect"])
        .arg(format!("127.0.0.1:{port}"))
        .args(["-servername", sni])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("openssl");
    drop(client.stdin.take().map(|mut s| s.write_all(b"")));
    let out = client.wait_with_output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines()
        .find_map(|l| l.strip_prefix("subject=").map(|s| s.replace(" ", "")))
        .unwrap_or_else(|| panic!("no subject for {sni}: {text}"))
}

#[test]
fn certificates_follow_trailing_wildcard_and_regex_names() {
    let default = common::tls::make_self_signed("default");
    let trail = common::tls::make_self_signed("trail");
    let longer = common::tls::make_self_signed("longer");
    let re = common::tls::make_self_signed("re");
    let setup = common::ports::setup_lock();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let server = |names: &str, certs: &common::tls::CertSet| {
        format!(
            "server {{ listen 127.0.0.1:{port} ssl; server_name {names};\n\
               ssl_certificate {}; ssl_certificate_key {};\n\
               location / {{ return 200 ok; }} }}\n",
            certs.cert_path().display(),
            certs.key_path().display()
        )
    };
    let dir = std::env::temp_dir().join(format!("ruxen-m76-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "pid {d}/ruxen.pid;\nevents {{}}\nhttp {{\n{}{}{}{}}}\n",
            server("default.test", &default),
            server("www.example.*", &trail),
            server("www.example.co.*", &longer),
            server("~^re\\d+\\.", &re),
            d = dir.display()
        ),
    )
    .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .arg("-c")
        .arg(dir.join("nginx.conf"))
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
    drop(setup);

    let got: Vec<(&str, String)> = [
        "www.example.org",
        "www.example.co.uk",
        "re42.example",
        "re.example",
        "other.test",
    ]
    .into_iter()
    .map(|sni| (sni, served_cn(port, sni)))
    .collect();
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&dir);

    let cn = |sni: &str| got.iter().find(|(s, _)| *s == sni).unwrap().1.clone();
    assert!(cn("www.example.org").ends_with("CN=trail"), "{got:?}");
    assert!(cn("www.example.co.uk").ends_with("CN=longer"), "{got:?}");
    assert!(cn("re42.example").ends_with("CN=re"), "{got:?}");
    // Not `re<digits>.`: no match, the default server's certificate.
    assert!(cn("re.example").ends_with("CN=default"), "{got:?}");
    assert!(cn("other.test").ends_with("CN=default"), "{got:?}");
}
