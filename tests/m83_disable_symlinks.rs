//! M83 — `disable_symlinks on|if_not_owner [from=…]`, as nginx's
//! ngx_open_file_wrapper: a symlink in the last component is a 403
//! (ELOOP), one before it a 404 (ENOTDIR, nginx opens those components as
//! directories with O_NOFOLLOW), the root's own components count unless
//! `from=` covers them, `if_not_owner` only refuses links owned unlike
//! their targets, a try_files probe through a refused link is a miss and
//! an index file one a 403. Until now the directive was refused at
//! startup (0.1.1), and before that ignored. Every case here was checked
//! against nginx 1.24.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::{MetadataExt, symlink};
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

fn status(port: u16, path: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    let code = out.get(9..12).unwrap_or("").to_string();
    let body = out.split_once("\r\n\r\n").map_or("", |(_, b)| b).trim();
    if code == "200" {
        format!("200 {body}")
    } else {
        code
    }
}

#[test]
fn symlinks_are_refused_as_nginx_does() {
    let setup = common::ports::setup_lock();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let tmp = std::env::temp_dir();
    let d = tmp.join(format!("ruxen-m83-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    for sub in ["www/dir", "r/try", "r/idx"] {
        std::fs::create_dir_all(d.join(sub)).unwrap();
    }
    std::fs::write(d.join("www/real.txt"), "real").unwrap();
    symlink("real.txt", d.join("www/link.txt")).unwrap();
    std::fs::write(d.join("www/dir/f.txt"), "f").unwrap();
    symlink("dir", d.join("www/dirlink")).unwrap();
    symlink("www", d.join("wwwlink")).unwrap();
    symlink(&tmp, d.join("tmplink")).unwrap();
    std::fs::write(d.join("r/try/real.txt"), "tryreal").unwrap();
    symlink("real.txt", d.join("r/try/link.txt")).unwrap();
    std::fs::write(d.join("r/fallback.txt"), "fallback").unwrap();
    symlink("../try/real.txt", d.join("r/idx/index.html")).unwrap();
    let name = d.file_name().unwrap().to_str().unwrap().to_string();
    let (dd, t) = (d.display(), tmp.display());
    std::fs::write(
        d.join("nginx.conf"),
        format!(
            "pid {dd}/ruxen.pid;\nerror_log {dd}/error.log;\nevents {{}}\nhttp {{\n\
             server {{ listen 127.0.0.1:{port};\n\
               location / {{ root {dd}/r; }}\n\
               location /on/ {{ alias {dd}/www/; disable_symlinks on; }}\n\
               location /onroot/ {{ alias {dd}/wwwlink/; disable_symlinks on; }}\n\
               location /onfrom/ {{ alias {dd}/wwwlink/; disable_symlinks on from=$document_root; }}\n\
               location /owner/ {{ alias {dd}/www/; disable_symlinks if_not_owner; }}\n\
               location /ownertmp/ {{ alias {t}/; disable_symlinks if_not_owner; }}\n\
               location /off/ {{ alias {dd}/www/; disable_symlinks off; }}\n\
               location /try/ {{ root {dd}/r; disable_symlinks on; try_files $uri /fallback.txt; }}\n\
               location /idx/ {{ root {dd}/r; disable_symlinks on; }}\n\
             }} }}\n"
        ),
    )
    .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .arg("-c")
        .arg(d.join("nginx.conf"))
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

    let mut cases = vec![
        ("/on/real.txt", "200 real"),
        ("/on/link.txt", "403"),
        ("/on/dirlink/f.txt", "404"),
        ("/on/nope.txt", "404"),
        ("/onroot/real.txt", "404"),
        ("/onfrom/real.txt", "200 real"),
        ("/onfrom/link.txt", "403"),
        ("/owner/link.txt", "200 real"),
        ("/owner/dirlink/f.txt", "200 f"),
        ("/off/link.txt", "200 real"),
        ("/try/real.txt", "200 tryreal"),
        ("/try/link.txt", "200 fallback"),
        ("/idx/", "403"),
    ];
    let through_tmp = format!("/ownertmp/{name}/tmplink/{name}/www/real.txt");
    // The link is ours and the temp directory isn't (root's), unless the
    // tests run as its owner.
    let tmp_owner = std::fs::metadata(&tmp).unwrap().uid();
    let me = std::fs::symlink_metadata(d.join("tmplink")).unwrap().uid();
    if tmp_owner != me {
        cases.push((&through_tmp, "403"));
    }
    let got: Vec<(String, String)> = cases
        .iter()
        .map(|(p, _)| (p.to_string(), status(port, p)))
        .collect();
    sleep(Duration::from_millis(50));
    let log = std::fs::read_to_string(d.join("error.log")).unwrap_or_default();
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&d);

    for ((path, want), (_, got)) in cases.iter().zip(&got) {
        assert_eq!(got, want, "{path}");
    }
    let www = format!("{dd}/www");
    for line in [
        "[error]".to_string(),
        format!("openat() \"{www}/link.txt\" failed (40: "),
        format!("openat() \"{www}/dirlink/f.txt\" failed (20: "),
        "[crit]".to_string(),
        format!("openat() \"{dd}/r/try/link.txt\" failed (40: "),
    ] {
        assert!(log.contains(&line), "{line} not in\n{log}");
    }
}
