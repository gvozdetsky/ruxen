//! M131 — `ssl_password_file` (#139): an encrypted key (OpenSSL 3's
//! `genrsa -aes128`, PKCS#8 PBES2) is opened with the file's passwords,
//! tried in order as nginx tries them; none that fits is an `[emerg]`.

mod common;

use std::path::Path;
use std::process::Command;

fn openssl(args: &[&str], dir: &Path) {
    let out = Command::new("openssl")
        .args(args)
        .current_dir(dir)
        .output()
        .expect("openssl");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn check(dir: &Path, directives: &str) -> (bool, String) {
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "events {{}}\nhttp {{ server {{ listen 127.0.0.1:1 ssl;\n\
             ssl_certificate {d}/key.crt; ssl_certificate_key {d}/key.pem;\n\
             {directives} }} }}\n",
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
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn encrypted_keys_open_with_the_password_file() {
    let dir = std::env::temp_dir().join(format!("ruxen-m131-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    openssl(
        &[
            "genrsa",
            "-out",
            "key.pem",
            "-passout",
            "pass:secret",
            "-aes128",
            "2048",
        ],
        &dir,
    );
    openssl(
        &[
            "req",
            "-x509",
            "-new",
            "-key",
            "key.pem",
            "-passin",
            "pass:secret",
            "-subj",
            "/CN=localhost/",
            "-out",
            "key.crt",
        ],
        &dir,
    );
    let key = std::fs::read_to_string(dir.join("key.pem")).unwrap();
    assert!(key.contains("ENCRYPTED"), "{key}");
    std::fs::write(dir.join("two"), "wrong\r\n\r\nsecret\r\n").unwrap();
    std::fs::write(dir.join("bad"), "wrong\n").unwrap();

    let two = check(&dir, &format!("ssl_password_file {}/two;", dir.display()));
    let bad = check(&dir, &format!("ssl_password_file {}/bad;", dir.display()));
    let none = check(&dir, "");
    let missing = check(
        &dir,
        &format!("ssl_password_file {}/missing;", dir.display()),
    );
    let _ = std::fs::remove_dir_all(&dir);
    assert!(two.0, "{}", two.1);
    for (ok, stderr) in [&bad, &none] {
        assert!(
            !ok && stderr.contains("PEM_read_bio_PrivateKey"),
            "{stderr}"
        );
    }
    assert!(
        !missing.0 && missing.1.contains("open() \""),
        "{}",
        missing.1
    );
}
