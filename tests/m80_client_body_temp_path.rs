//! M80 — `client_body_temp_path` at every level (http, server, location,
//! inherited by nested locations), with its `level1 [level2 [level3]]`
//! subdirectories, as nginx: the levels are named by the file number's last
//! digits (ngx_create_hashed_filename) and made `0700` on demand. Before,
//! only the http-level path was used, and without levels.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

/// POSTs a 4 KiB body (past ruxen's in-memory threshold) and returns the
/// response body: the `$request_body_file` the location renders.
fn post(port: u16, path: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let body = vec![b'x'; 4096];
    write!(
        s,
        "POST {path} HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .unwrap();
    s.write_all(&body).unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out.split_once("\r\n\r\n")
        .map_or("", |(_, b)| b)
        .to_string()
}

/// Checks `file` is `<dir>/<levels…>/<name>` with the levels taken from the
/// end of the name, the file `0600` and each level directory `0700`.
fn assert_placed(file: &str, dir: &Path, levels: &[usize]) {
    let file = Path::new(file);
    let name = file.file_name().unwrap().to_str().unwrap();
    assert_eq!(name.len(), 10, "{file:?}");
    let mut expected = dir.to_path_buf();
    let mut end = name.len();
    for &level in levels {
        expected.push(&name[end - level..end]);
        end -= level;
    }
    expected.push(name);
    assert_eq!(file, expected);
    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(file), 0o600, "{file:?}");
    let mut level_dir = file.parent().unwrap();
    while level_dir != dir {
        assert_eq!(mode(level_dir), 0o700, "{level_dir:?}");
        level_dir = level_dir.parent().unwrap();
    }
}

#[test]
fn temp_files_go_to_the_locations_directory_and_levels() {
    let setup = common::ports::setup_lock();
    let free = || {
        TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    };
    let (a, b) = (free(), free());
    let dir = std::env::temp_dir().join(format!("ruxen-m80-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let d = dir.display();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "pid {d}/ruxen.pid;\nevents {{}}\n\
             http {{ client_body_temp_path {d}/http 2;\n\
               server {{ listen 127.0.0.1:{a};\n\
                 location /up {{ client_body_temp_path {d}/up 1 2; client_body_in_file_only on; return 200 $request_body_file; }}\n\
                 location /h {{ client_body_in_file_only on; return 200 $request_body_file; }} }}\n\
               server {{ listen 127.0.0.1:{b}; client_body_temp_path {d}/srv/ 1 1 1;\n\
                 location / {{ client_body_in_file_only on; return 200 $request_body_file;\n\
                   location /in {{ client_body_in_file_only on; return 200 $request_body_file; }} }} }} }}\n"
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

    let up = post(a, "/up");
    let http = post(a, "/h");
    let srv = post(b, "/x");
    let nested = post(b, "/in");
    let _ = child.kill();
    let _ = child.wait();

    assert_placed(&up, &dir.join("up"), &[1, 2]);
    assert_placed(&http, &dir.join("http"), &[2]);
    assert_placed(&srv, &dir.join("srv"), &[1, 1, 1]);
    assert_placed(&nested, &dir.join("srv"), &[1, 1, 1]);
    let _ = std::fs::remove_dir_all(&dir);
}
