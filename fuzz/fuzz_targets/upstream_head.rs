//! An upstream's response head, as `proxy::attempt` reads it (#217): a
//! malicious or broken upstream sends these bytes. Besides not crashing,
//! finding the head's end must not depend on how the bytes arrive (the
//! entry point asserts that), and what is found must lie inside the input.
#![no_main]

use libfuzzer_sys::fuzz_target;
use ruxen::fuzzing::upstream_head;

fuzz_target!(|data: &[u8]| {
    let (at, data) = match data {
        [a, b, rest @ ..] => (usize::from(u16::from_le_bytes([*a, *b])), rest),
        _ => return,
    };
    if let Some((end, term, status, fields, _length)) = upstream_head(data, at) {
        assert!(end + term <= data.len());
        assert!(term == 2 || term == 4);
        assert!(status < 1000);
        assert!(fields <= end);
    }
});
