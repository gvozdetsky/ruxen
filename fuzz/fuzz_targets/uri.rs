//! URI path normalization (percent-decoding, dot segments, merge_slashes).
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&flags, path)) = data.split_first() else {
        return;
    };
    if let Ok(out) = ruxen::fuzzing::normalize_uri(path, flags & 1 == 1) {
        // A normalized path is absolute and never climbs above the root.
        assert!(out.starts_with(b"/"), "{out:?}");
        assert!(!out.windows(4).any(|w| w == b"/../"), "{out:?}");
    }
});
