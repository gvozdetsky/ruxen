//! realip's walk of an `X-Forwarded-For` value (#477) against a model of
//! `ngx_http_get_forwarded_addr_internal`: the entries are the runs
//! between spaces and commas; from the right, each is taken while the
//! address in hand (the peer's first) is trusted, only the last without
//! `real_ip_recursive`, up to one that doesn't parse.
#![no_main]

use std::net::IpAddr;

use libfuzzer_sys::fuzz_target;
use ruxen::fuzzing::{forwarded_addr, parse_addr_port};

fuzz_target!(|data: &[u8]| {
    let Some((&flags, list)) = data.split_first() else {
        return;
    };
    let peers: [IpAddr; 4] = [
        "127.0.0.1".parse().unwrap(),
        "10.0.0.1".parse().unwrap(),
        "::ffff:192.0.2.1".parse().unwrap(),
        "2001:db8::5".parse().unwrap(),
    ];
    let from: [(IpAddr, u8); 3] = [
        ("127.0.0.0".parse().unwrap(), 8),
        ("192.0.2.0".parse().unwrap(), 24),
        ("2001:db8::".parse().unwrap(), 32),
    ];
    let peer = peers[usize::from(flags & 3)];
    let recursive = flags & 4 != 0;
    let got = forwarded_addr(peer, list, &from, recursive);
    assert_eq!(got, model(peer, list, &from, recursive));
});

fn model(
    peer: IpAddr,
    list: &[u8],
    from: &[(IpAddr, u8)],
    recursive: bool,
) -> Option<(IpAddr, u16)> {
    let sep = |b: &u8| *b == b' ' || *b == b',';
    let mut entries: Vec<(usize, usize)> = Vec::new();
    let mut at = 0;
    while let Some(start) = list[at..].iter().position(|b| !sep(b)).map(|i| at + i) {
        let end = list[start..]
            .iter()
            .position(sep)
            .map_or(list.len(), |i| start + i);
        entries.push((start, end));
        at = end;
    }
    // nginx's scan stops at the list's first byte without testing it: an
    // entry after a single separator there keeps it, and doesn't parse.
    if let Some(first) = entries.first_mut().filter(|e| e.0 == 1) {
        first.0 = 0;
    }
    let mut addr = peer;
    let mut found = None;
    for entry in entries.iter().rev().map(|&(start, end)| &list[start..end]) {
        if !trusted(addr, from) {
            break;
        }
        let Some(next) = parse_addr_port(entry) else {
            break;
        };
        found = Some(next);
        addr = next.0;
        if !recursive {
            break;
        }
    }
    found
}

/// `ngx_cidr_match`: an IPv4-mapped address matches as IPv4.
fn trusted(ip: IpAddr, from: &[(IpAddr, u8)]) -> bool {
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    };
    from.iter().any(|&(net, prefix)| match (net, ip) {
        (IpAddr::V4(net), IpAddr::V4(ip)) => {
            let shift = 32 - u32::from(prefix);
            u32::from(net).checked_shr(shift) == u32::from(ip).checked_shr(shift)
        }
        (IpAddr::V6(net), IpAddr::V6(ip)) => {
            let shift = 128 - u32::from(prefix);
            u128::from(net).checked_shr(shift) == u128::from(ip).checked_shr(shift)
        }
        _ => false,
    })
}
