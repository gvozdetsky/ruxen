//! `Host` header validation and normalization.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Some(((start, end), port)) = ruxen::fuzzing::normalize_host(data) {
        assert!(start <= end && end <= data.len());
        if let Some((ps, pe)) = port {
            assert!(ps <= pe && pe <= data.len());
        }
    }
});
