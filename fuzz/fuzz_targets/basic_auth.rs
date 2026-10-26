//! `Authorization: Basic` (#477), as auth_basic and `$remote_user` read
//! it. Beyond not crashing on any header block: credentials encoded with a
//! plain base64 encoder decode to the (non-empty) user before the first
//! `:` and the password after it, however the scheme name is cased and
//! spaced.
#![no_main]

use libfuzzer_sys::fuzz_target;
use ruxen::fuzzing::basic_authorization;

fuzz_target!(|data: &[u8]| {
    // Any header block.
    let _ = basic_authorization(data);

    // A well-formed header around the input as credentials.
    let Some((&shape, creds)) = data.split_first() else {
        return;
    };
    let scheme: &[u8] = match shape & 3 {
        0 => b"Basic",
        1 => b"basic",
        2 => b"BASIC",
        _ => b"bAsIc",
    };
    let space: &[u8] = if shape & 4 == 0 { b" " } else { b"   " };
    let mut headers = b"Host: x\r\nAuthorization: ".to_vec();
    headers.extend_from_slice(scheme);
    headers.extend_from_slice(space);
    headers.extend_from_slice(&base64(creds));
    headers.extend_from_slice(b"\r\n");
    match creds.iter().position(|&b| b == b':') {
        Some(colon) if colon > 0 => assert_eq!(
            basic_authorization(&headers),
            Ok((creds[..colon].to_vec(), creds[colon + 1..].to_vec()))
        ),
        // No `:`, an empty user (as ngx_http_auth_basic_user refuses it),
        // or nothing at all: malformed.
        _ => assert_eq!(basic_authorization(&headers), Err(false)),
    }
});

/// RFC 4648 base64 with padding.
fn base64(input: &[u8]) -> Vec<u8> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[(n >> (18 - 6 * i)) as usize & 63]);
            } else {
                out.push(b'=');
            }
        }
    }
    out
}
