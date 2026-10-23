//! The HTTP/2 header-block sizes `$request_length` starts from (#409,
//! #477): `PollIo` walks the client's frame heads as the bytes go by. The
//! sizes must not depend on how the bytes were cut into reads, and must
//! be what a plain parse of the whole input gives: per stream, each
//! HEADERS payload less its priority fields and padding, plus each
//! CONTINUATION payload.
#![no_main]

use libfuzzer_sys::fuzz_target;
use ruxen::fuzzing::h2_header_blocks;

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

fuzz_target!(|data: &[u8]| {
    // The first bytes cut the input into reads; the rest is frames.
    let Some((&ncuts, rest)) = data.split_first() else {
        return;
    };
    let ncuts = usize::from(ncuts % 8);
    if rest.len() < ncuts {
        return;
    }
    let (cut_bytes, frames) = rest.split_at(ncuts);
    let mut input = PREFACE.to_vec();
    input.extend_from_slice(frames);
    let mut cuts: Vec<usize> = cut_bytes
        .iter()
        .map(|&b| usize::from(b) * input.len() / 256)
        .collect();
    cuts.sort_unstable();
    let whole = h2_header_blocks(&input, &[]);
    let split = h2_header_blocks(&input, &cuts);
    assert_eq!(whole, split, "cuts {cuts:?}");
    assert_eq!(whole, model(frames));
});

/// A plain parse of whole frames, keeping a pending padded HEADERS whose
/// pad-length byte didn't arrive out, as the scan does.
fn model(mut frames: &[u8]) -> Vec<(u32, u64)> {
    let mut sizes: Vec<(u32, u64)> = Vec::new();
    let mut add = |sid: u32, n: u64| match sizes.iter_mut().rev().find(|(id, _)| *id == sid) {
        Some(entry) => entry.1 += n,
        None => {
            if sizes.len() == 256 {
                sizes.remove(0);
            }
            sizes.push((sid, n));
        }
    };
    while frames.len() >= 9 {
        let h = &frames[..9];
        let len = u32::from_be_bytes([0, h[0], h[1], h[2]]) as u64;
        let sid = u32::from_be_bytes([h[5], h[6], h[7], h[8]]) & 0x7fff_ffff;
        let payload = &frames[9..];
        match h[3] {
            0x1 => {
                let rest = len.saturating_sub(if h[4] & 0x20 != 0 { 5 } else { 0 });
                if h[4] & 0x8 != 0 && len > 0 {
                    // The pad length is the payload's first byte.
                    match payload.first() {
                        Some(&pad) => add(sid, rest.saturating_sub(u64::from(pad) + 1)),
                        None => break,
                    }
                } else {
                    add(sid, rest);
                }
            }
            0x9 => add(sid, len),
            _ => {}
        }
        let skip = (len as usize).min(payload.len());
        frames = &payload[skip..];
    }
    sizes
}
