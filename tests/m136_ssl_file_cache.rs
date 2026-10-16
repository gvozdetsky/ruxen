//! M136 — certificate and key files are read once per configuration load,
//! however many directives name them, as nginx's SSL object cache does
//! (1.27.2+, ssl_cache.t): each file here is a FIFO with content on the
//! first read only.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

/// `path` as a FIFO: `content` to its first reader, nothing after.
fn fifo(path: &Path, content: Vec<u8>) {
    let made = Command::new("mkfifo").arg(path).status().unwrap();
    assert!(made.success());
    let path = path.to_path_buf();
    std::thread::spawn(move || {
        let mut content = content;
        loop {
            let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(&path) else {
                return;
            };
            let _ = f.write_all(&content);
            content.clear();
        }
    });
}

#[test]
fn certificate_files_are_read_once() {
    let dir = std::env::temp_dir().join(format!("ruxen-m136-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let tls = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/testdata/tls");
    for name in ["rsa.crt", "rsa.key"] {
        fifo(
            &dir.join(format!("{name}.fifo")),
            std::fs::read(tls.join(name)).unwrap(),
        );
    }
    let ssl = format!(
        "ssl_certificate {d}/rsa.crt.fifo; ssl_certificate_key {d}/rsa.key.fifo;",
        d = dir.display()
    );
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "events {{}}\nhttp {{\n\
             server {{ listen 127.0.0.1:1 ssl; {ssl} }}\n\
             server {{ listen 127.0.0.1:2 ssl; {ssl} }}\n\
             server {{ listen 127.0.0.1:3; location / {{ proxy_pass https://127.0.0.1:1;\n\
             proxy_ssl_certificate {d}/rsa.crt.fifo;\n\
             proxy_ssl_certificate_key {d}/rsa.key.fifo; }} }}\n}}\n",
            d = dir.display()
        ),
    )
    .unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .arg("-t")
        .arg("-c")
        .arg(dir.join("nginx.conf"))
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let _ = std::fs::remove_dir_all(&dir);
}
