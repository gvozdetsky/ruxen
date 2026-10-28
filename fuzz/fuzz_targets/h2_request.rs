//! Client bytes into the `h2` crate's server over `PollIo` (#477), read
//! in input-chosen pieces. Each stream the crate accepts becomes the
//! HTTP/1.1-style head `StreamIo` hands `handle`, and the request parser
//! must take it whole, with the stream's method and path, or refuse it;
//! never wait for more. Its header block size (#409) is at least the three
//! pseudo-header fields.
#![no_main]

use libfuzzer_sys::fuzz_target;
use ruxen::fuzzing::{h2_connection, h2_header_blocks, parse_h2_head};

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

fuzz_target!(|data: &[u8]| {
    // The first byte is the read size (0: as much as fits); the rest is
    // frames.
    let Some((&piece, frames)) = data.split_first() else {
        return;
    };
    let piece = if piece == 0 {
        usize::MAX
    } else {
        usize::from(piece)
    };
    let mut input = PREFACE.to_vec();
    input.extend_from_slice(frames);
    // `PollIo` keeps the sizes of 256 streams at most.
    let crowded = h2_header_blocks(&input, &[]).len() >= 256;
    for stream in h2_connection(&input, piece) {
        let head = String::from_utf8_lossy(&stream.head);
        assert!(stream.head.ends_with(b"\r\n\r\n"), "{head:?}");
        assert!(
            crowded || stream.header_block >= 3,
            "header block {} for {head:?}",
            stream.header_block
        );
        match parse_h2_head(&stream.head) {
            None => panic!("incomplete: {head:?}"),
            Some(Ok((consumed, method, path))) => {
                assert_eq!(consumed, stream.head.len(), "{head:?}");
                assert_eq!(method, stream.method.as_bytes(), "{head:?}");
                assert_eq!(path, stream.target.as_bytes(), "{head:?}");
            }
            Some(Err(())) => {}
        }
    }
});
