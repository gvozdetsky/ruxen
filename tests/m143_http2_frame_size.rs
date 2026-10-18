//! M143 — HTTP/2 frame size (#506): ruxen announces no SETTINGS_MAX_FRAME_SIZE,
//! so the default 16384 holds, and a client frame over it ends the
//! connection with FRAME_SIZE_ERROR at once. Announcing 2^24-1 as nginx
//! does would let a client make each connection hold a 16 MiB frame, since
//! the `h2` crate reads a frame whole before it looks at it.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
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

/// The next frame: type, flags, stream and payload; `None` at EOF.
fn read_frame(s: &mut TcpStream) -> Option<(u8, u8, u32, Vec<u8>)> {
    let mut head = [0u8; 9];
    s.read_exact(&mut head).ok()?;
    let len = u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize;
    let mut payload = vec![0u8; len];
    s.read_exact(&mut payload).ok()?;
    let sid = u32::from_be_bytes([head[5], head[6], head[7], head[8]]) & 0x7fff_ffff;
    Some((head[3], head[4], sid, payload))
}

#[test]
fn frames_over_16384_are_refused() {
    let dir = std::env::temp_dir().join(format!("ruxen-m143-{}", std::process::id()));
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
            "worker_processes 1;\npid {d}/ruxen.pid;\nerror_log {d}/error.log;\n\
             events {{}}\nhttp {{\naccess_log off;\n\
             server {{ listen 127.0.0.1:{port} http2; return 200 \"ok\\n\"; }}\n}}\n",
            d = dir.display()
        ),
    )
    .unwrap();
    let mut child = common::KillOnDrop(
        Command::new(env!("CARGO_BIN_EXE_ruxen"))
            .arg("-c")
            .arg(dir.join("nginx.conf"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    common::ports::wait_for_pid_file(&mut child, &dir.join("ruxen.pid"), Duration::from_secs(5));
    drop(setup);

    let connect = || {
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        s.write_all(PREFACE).unwrap();
        s.write_all(&frame(0x4, 0, 0, &[])).unwrap();
        // The server's SETTINGS come first.
        let (kind, flags, _, settings) = read_frame(&mut s).expect("SETTINGS");
        assert_eq!((kind, flags), (0x4, 0));
        s.write_all(&frame(0x4, 0x1, 0, &[])).unwrap();
        (s, settings)
    };

    // No SETTINGS_MAX_FRAME_SIZE over the default.
    let (mut s, settings) = connect();
    for param in settings.chunks(6) {
        let id = u16::from_be_bytes([param[0], param[1]]);
        let value = u32::from_be_bytes([param[2], param[3], param[4], param[5]]);
        assert!(id != 0x5 || value <= 16384, "MAX_FRAME_SIZE {value}");
    }
    // A frame of the largest allowed size, of a type the server ignores,
    // then a request: answered.
    s.write_all(&frame(0xf0, 0, 0, &vec![0u8; 16384])).unwrap();
    // :method GET, :scheme http, :path /, :authority h.
    let block = [0x82, 0x86, 0x84, 0x41, 0x01, b'h'];
    s.write_all(&frame(0x1, 0x5, 1, &block)).unwrap();
    let status = loop {
        let (kind, _, sid, payload) = read_frame(&mut s).expect("an answer");
        assert_ne!(kind, 0x7, "GOAWAY {payload:?}");
        if kind == 0x1 && sid == 1 {
            break payload;
        }
    };
    // :status 200 is index 8 of the static table.
    assert_eq!(status.first(), Some(&0x88), "{status:?}");

    // One byte more: GOAWAY with FRAME_SIZE_ERROR (6), then the end.
    let (mut s, _) = connect();
    let mut big = frame(0xf0, 0, 0, &[]);
    big[..3].copy_from_slice(&16385u32.to_be_bytes()[1..]);
    s.write_all(&big).unwrap();
    let _ = s.write_all(&vec![0u8; 16385]);
    let goaway = loop {
        match read_frame(&mut s) {
            Some((0x7, _, _, payload)) => break payload,
            Some(_) => continue,
            None => panic!("closed without GOAWAY"),
        }
    };
    let code = u32::from_be_bytes([goaway[4], goaway[5], goaway[6], goaway[7]]);
    assert_eq!(code, 6, "{goaway:?}");
    let mut rest = Vec::new();
    let _ = s.read_to_end(&mut rest);

    let _ = child.0.kill();
    let _ = child.0.wait();
    let _ = std::fs::remove_dir_all(&dir);
}
