//! M151 — the `http2_*` directives nginx takes in a location (#594):
//! `http2_chunk_size` sizes the DATA frames of that location's responses
//! (ngx_http_v2_send_chain reads it from the request's location), and
//! `http2_push` / `http2_push_preload` load with the warning they get at
//! server level, obsolete since nginx 1.25.1.

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::time::Duration;

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let mut f = (payload.len() as u32).to_be_bytes()[1..].to_vec();
    f.extend_from_slice(&[kind, flags]);
    f.extend_from_slice(&stream.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

fn read_frame(s: &mut TcpStream) -> Option<(u8, u8, u32, Vec<u8>)> {
    let mut head = [0u8; 9];
    s.read_exact(&mut head).ok()?;
    let len = u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize;
    let mut payload = vec![0u8; len];
    s.read_exact(&mut payload).ok()?;
    let sid = u32::from_be_bytes([head[5], head[6], head[7], head[8]]) & 0x7fff_ffff;
    Some((head[3], head[4], sid, payload))
}

/// GET `path` on stream `sid`; the sizes of the response's DATA frames.
fn data_frames(s: &mut TcpStream, sid: u32, path: &str) -> Vec<usize> {
    // :method GET, :scheme http, :path (literal, not indexed),
    // :authority h.
    let mut block = vec![0x82, 0x86, 0x04, path.len() as u8];
    block.extend_from_slice(path.as_bytes());
    block.extend_from_slice(&[0x41, 0x01, b'h']);
    s.write_all(&frame(0x1, 0x5, sid, &block)).unwrap();
    let mut sizes = Vec::new();
    loop {
        let (kind, flags, id, payload) = read_frame(s).expect("the response");
        assert_ne!(kind, 0x7, "GOAWAY {payload:?}");
        if id != sid {
            continue;
        }
        assert_ne!(kind, 0x3, "RST_STREAM {payload:?}");
        if kind == 0x0 {
            sizes.push(payload.len());
        }
        if flags & 0x1 != 0 {
            return sizes;
        }
    }
}

#[test]
fn location_http2_directives() {
    let dir = std::env::temp_dir().join(format!("ruxen-m151-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("html")).unwrap();
    std::fs::write(dir.join("html/f"), vec![b'x'; 20000]).unwrap();
    let setup = common::ports::setup_lock();
    let [port] = common::ports::free_ports::<1>();
    std::fs::write(
        dir.join("nginx.conf"),
        format!(
            "worker_processes 1;\npid {d}/ruxen.pid;\nerror_log {d}/error.log;\n\
             events {{}}\nhttp {{\naccess_log off;\n\
             server {{ listen 127.0.0.1:{port} http2; root {d}/html;\n\
               location /one/ {{ http2_chunk_size 1; http2_push_preload on;\n\
                 http2_push /style.css; return 200 \"body\"; }}\n\
               location /big/ {{ http2_chunk_size 16k; alias {d}/html/; }}\n\
               location /outer/ {{ http2_chunk_size 2;\n\
                 location /outer/inner {{ return 200 \"abcde\"; }} }}\n\
               location /redirected/ {{ http2_chunk_size 3; error_page 404 /one/; }}\n\
             }}\n}}\n",
            d = dir.display()
        ),
    )
    .unwrap();
    let conf = dir.join("nginx.conf");

    // nginx 1.30.6: syntax ok, with the push ones' warning.
    let check = Command::new(env!("CARGO_BIN_EXE_ruxen"))
        .arg("-t")
        .arg("-c")
        .arg(&conf)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&check.stderr);
    assert!(check.status.success(), "{stderr}");
    for name in ["http2_push_preload", "http2_push"] {
        let warning = format!("[warn] the \"{name}\" directive is obsolete, ignored");
        assert!(stderr.contains(&warning), "{stderr}");
    }

    let mut child = common::KillOnDrop(
        Command::new(env!("CARGO_BIN_EXE_ruxen"))
            .arg("-c")
            .arg(&conf)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    common::ports::wait_for_pid_file(&mut child, &dir.join("ruxen.pid"), Duration::from_secs(5));
    drop(setup);

    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(PREFACE).unwrap();
    s.write_all(&frame(0x4, 0, 0, &[])).unwrap();
    s.write_all(&frame(0x4, 0x1, 0, &[])).unwrap();

    // The location's chunk size, as h2.t's /chunk_size checks it.
    assert_eq!(data_frames(&mut s, 1, "/one/"), [1, 1, 1, 1]);
    // nginx's 8k by default, and 16k where the location says so.
    assert_eq!(data_frames(&mut s, 3, "/f"), [8192, 8192, 3616]);
    assert_eq!(data_frames(&mut s, 5, "/big/f"), [16384, 3616]);
    // A nested location inherits it.
    assert_eq!(data_frames(&mut s, 7, "/outer/inner"), [2, 2, 1]);
    // After an internal redirect, the location that answers decides.
    assert_eq!(data_frames(&mut s, 9, "/redirected/x"), [1, 1, 1, 1]);

    let _ = child.0.kill();
    let _ = child.0.wait();
    let _ = std::fs::remove_dir_all(&dir);
}
