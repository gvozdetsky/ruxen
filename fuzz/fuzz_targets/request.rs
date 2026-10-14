//! The HTTP/1.x request parser. Besides not crashing, the parser is
//! incremental: fed the same bytes in two pieces (as reads deliver them),
//! it must give the same answer as for the whole buffer.
#![no_main]

use libfuzzer_sys::fuzz_target;
use ruxen::fuzzing::{parse_request, parse_request_split};

fuzz_target!(|data: &[u8]| {
    let whole = parse_request(data);
    // Split at a point chosen by the input itself, so the fuzzer explores
    // every position over time without trying all of them per input.
    let at = data.first().map_or(0, |&b| usize::from(b)) % (data.len() + 1);
    let split = parse_request_split(data, at);
    assert_eq!(whole, split, "split at {at} changed the parse");
    if let Some(Ok(consumed)) = whole {
        assert!(consumed <= data.len());
    }
});
