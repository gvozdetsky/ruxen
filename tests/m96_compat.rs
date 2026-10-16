//! M96 — `ruxen --compat`: the whole configuration checked in one run,
//! with `file:line`, and `-t` errors with nginx's ` in file:line` (#278).

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("ruxen-m96-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir(&d).unwrap();
    d
}

fn ruxen(args: &[&str], conf: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .args(args)
        .arg("-c")
        .arg(conf)
        .output()
        .unwrap()
}

#[test]
fn m96_compat_lists_everything_with_positions() {
    let d = dir("all");
    std::fs::write(
        d.join("site.conf"),
        "server {\n    listen 127.0.0.1:1;\n    fastcgi_pass 127.0.0.1:9000;\n}\n",
    )
    .unwrap();
    let conf = d.join("nginx.conf");
    std::fs::write(
        &conf,
        format!(
            "events {{}}\nhttp {{\n    ssi on;\n    tcp_nopush on;\n    include {};\n    \
             include {}/missing.conf;\n    server {{\n        listen 127.0.0.1:1;\n        \
             secure_link $arg_s;\n    }}\n}}\n",
            d.join("site.conf").display(),
            d.display()
        ),
    )
    .unwrap();
    let out = ruxen(&["--compat"], &conf);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let c = conf.display();
    let site = d.join("site.conf");
    let s = site.display();
    for line in [
        format!(
            "{s}:3: unsupported: fastcgi_pass 127.0.0.1:9000 — unknown directive in a server block"
        ),
        format!(
            "{c}:6: unsupported: include {}/missing.conf — open() \"{}/missing.conf\" failed",
            d.display(),
            d.display()
        ),
        format!("{c}:9: unsupported: secure_link $arg_s — unknown directive in a server block"),
        format!("{c}:3: differs: ssi on — server-side includes are not processed"),
        "ignored: 1 tuning directive with no effect in ruxen: tcp_nopush".to_string(),
        "ruxen does not start with this configuration: 3 unsupported, 1 behaving differently"
            .to_string(),
    ] {
        assert!(stdout.contains(&line), "missing {line:?} in:\n{stdout}");
    }
    assert_eq!(out.status.code(), Some(1));
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn m96_compat_passes_a_supported_configuration() {
    let d = dir("ok");
    let conf = d.join("nginx.conf");
    std::fs::write(
        &conf,
        "events {}\nhttp {\n    access_log off;\n    gzip off;\n    server {\n        \
         listen 127.0.0.1:1;\n        location / { return 200 ok; }\n    }\n}\n",
    )
    .unwrap();
    let out = ruxen(&["--compat"], &conf);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout
            .contains("ruxen starts with this configuration and nothing in it behaves differently"),
        "{stdout}"
    );
    assert!(!stdout.contains("differs"), "{stdout}");
    assert_eq!(out.status.code(), Some(0));
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn m96_test_mode_errors_say_where() {
    let d = dir("where");
    let conf = d.join("nginx.conf");
    std::fs::write(
        &conf,
        "events {}\nhttp {\n    server {\n        fastcgi_pass x;\n    }\n}\n",
    )
    .unwrap();
    let out = ruxen(&["-t"], &conf);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(&format!(
            "[emerg] unknown directive `fastcgi_pass` in a server block in {}:4",
            conf.display()
        )),
        "{stderr}"
    );
    let _ = std::fs::remove_dir_all(&d);
}
