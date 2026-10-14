//! The decoder of a chunked upstream body relayed to the client
//! (`proxy_stream::ChunkedDecoder`, #88, #217): it must give the same
//! answer whatever the reads' sizes, never use more bytes than it got, and
//! never produce more body than it was given.
#![no_main]

use libfuzzer_sys::fuzz_target;
use ruxen::fuzzing::upstream_chunked;

fuzz_target!(|data: &[u8]| {
    let (piece, data) = match data {
        [a, rest @ ..] => (usize::from(*a) + 1, rest),
        _ => return,
    };
    let whole = upstream_chunked(data, data.len().max(1));
    let split = upstream_chunked(data, piece);
    match (&whole, &split) {
        (Ok(w), Ok(s)) => assert_eq!(w, s, "piece {piece}"),
        // A refused body is refused however it is split, unless the split
        // run ended (or stopped) before the bytes that make it bad.
        (Err(()), Ok((_, done, _))) => assert!(!*done || data.is_empty(), "piece {piece}"),
        (Ok((_, done, _)), Err(())) => assert!(!*done, "piece {piece}"),
        (Err(()), Err(())) => {}
    }
    if let Ok((body, _, used)) = &whole {
        assert!(*used <= data.len());
        assert!(body.len() <= data.len());
    }
});
