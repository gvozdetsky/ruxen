//! The PROXY protocol v1 / v2 header parser.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    ruxen::fuzzing::proxy_protocol(data);
});
