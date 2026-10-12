//! The configuration parser (`include` is refused under the `fuzzing`
//! feature, so only the input is read).
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let _ = ruxen::fuzzing::parse_config(&text);
});
