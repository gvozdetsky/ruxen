//! The chunked request-body decoder. Besides not crashing or hanging, it
//! must give the same answer however the input is split into reads: all
//! of it with the request head, or in pieces of any size.
#![no_main]

use libfuzzer_sys::fuzz_target;
use ruxen::fuzzing::chunked_body;

fuzz_target!(|data: &[u8]| {
    // The first two bytes choose how the rest is split, so the fuzzer
    // explores splits over time without trying all of them per input.
    let (initial, piece, data) = match data {
        [a, b, rest @ ..] => (usize::from(*a), usize::from(*b) + 1, rest),
        _ => return,
    };
    let max_body = 64 * 1024;
    let whole = chunked_body(data, data.len(), 1, max_body);
    let split = chunked_body(data, initial, piece, max_body);
    assert_eq!(whole, split, "initial {initial}, piece {piece}");
    if let Ok((body, raw)) = &whole {
        assert!(body.len() as u64 <= max_body);
        assert!(*raw <= data.len() as u64);
    }
});
