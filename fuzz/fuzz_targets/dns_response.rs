//! A name server's response to the resolver (#133): whoever can send
//! packets to the query's port controls these bytes. Besides not crashing,
//! no more addresses can come out than records fit in the input, and a
//! CNAME's target stays within what compression pointers can build.
#![no_main]

use libfuzzer_sys::fuzz_target;
use ruxen::fuzzing::dns_response;

fuzz_target!(|data: &[u8]| {
    let (tcp, data) = match data {
        [flag, rest @ ..] => (flag & 1 == 1, rest),
        _ => return,
    };
    if let Some((addrs, target)) = dns_response(data, tcp) {
        assert!(addrs * 14 <= data.len());
        assert!(target.is_none_or(|len| len < 128 * 64));
    }
});
