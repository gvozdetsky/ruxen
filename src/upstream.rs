// Per-worker upstream LB selection + connection pool. This module owns
// smoothed weighted round-robin, least_conn, keepalive pooling, and
// per-peer liveness accounting:
//
//   - max_fails / fail_timeout enforcement (cooldown window per peer)
//   - least_conn algorithm (active-request count tracking + min-pick)
//   - report_failure / report_success accounting points called from the
//     proxy attempt loop
//   - LeasedPeer guard that decrements active-conn counters on Drop
//
// All state is thread-local and shared-nothing — per-worker. Keying both
// maps on the *raw pointer* `*const PreparedUpstream` is safe because:
//
//   - PreparedUpstream is `Box::leak`ed once at startup and lives for the
//     whole process.
//   - The pointer is never deref'd here — it's only a HashMap key.
//   - Address equality is what we want: two locations sharing the same
//     `upstream { ... }` block point at the same struct, and direct-form
//     `proxy_pass` synthesizes one PreparedUpstream per location, so each
//     location gets its own independent LB / pool keyspace, exactly as
//     nginx does.
//
// Round-robin selection mirrors `ngx_http_upstream_round_robin.c`'s
// smoothed weighted variant. least_conn mirrors
// `ngx_http_upstream_least_conn.c::ngx_http_upstream_get_least_conn_peer`:
// among eligible peers, pick the one with the smallest `conns / weight`
// ratio, breaking ties via the same smoothed-weight pick — matches nginx
// behavior where a tied least-conn fallback is round-robin-fair.
//
// The pool is a `VecDeque` per (upstream, peer_index) pair. Take from the
// front; push back to the front so the most-recently-used connection is
// the next to be reused (LIFO). Eviction is opportunistic at take-time
// (drop entries past idle/lifetime/max-requests) — a separate sweeper
// would be O(idle slots) per request and isn't worth it at v0.1 scale.
//
// The pool stores `monoio::net::TcpStream` directly. monoio's TcpStream
// is `!Send` because the io_uring backing is per-thread, which is exactly
// what we want — RefCell-in-thread_local is the right primitive.

use std::cell::RefCell;
use std::collections::HashMap;
use std::collections::VecDeque;

/// The per-worker maps here are keyed by configuration addresses, not by
/// anything a client sends: FxHash (`NameHasher`) instead of SipHash, which
/// cost about 1% of `proxy_hello`'s instructions (callgrind).
type FxBuild = std::hash::BuildHasherDefault<crate::worker::NameHasher>;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::Duration;
use std::time::Instant;

use crate::config::LbAlgorithm;
use crate::worker::PreparedPeer;
use crate::worker::PreparedUpstream;
use crate::worker::PreparedValuePart;

/// A peer's state shared by all workers, for an upstream with `zone`
/// (#143): connections in progress and the failure window, so every
/// worker sees the same `max_conns` count, the same `least_conn` load
/// and the same peer health. The smoothed round-robin weights stay per
/// worker: only the interleaving of picks across workers differs from
/// nginx's locked pick. One cache line per peer.
#[derive(Debug, Default)]
#[repr(align(64))]
pub struct PeerShared {
    conns: AtomicU32,
    fails: AtomicU32,
    /// When the current failure window opened, in ms since `origin()`
    /// plus one; 0 = no failure recorded.
    fails_started_ms: AtomicU64,
}

impl PeerShared {
    pub(crate) fn for_peers(n: usize) -> &'static [PeerShared] {
        crate::arena::leak((0..n).map(|_| PeerShared::default()).collect())
    }
}

fn origin() -> Instant {
    static ORIGIN: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    *ORIGIN.get_or_init(Instant::now)
}

fn ms_since_origin(t: Instant) -> u64 {
    t.saturating_duration_since(origin()).as_millis() as u64 + 1
}

/// Requests in progress on peer `i`.
fn active(rt: &UpstreamRt, up: &PreparedUpstream, i: usize) -> u32 {
    match up.shared {
        Some(shared) => shared[i].conns.load(Ordering::Relaxed),
        None => rt.peers[i].active,
    }
}

/// Peer `i`'s failures in the current window and when the window opened.
fn fail_state(rt: &UpstreamRt, up: &PreparedUpstream, i: usize) -> (u32, Option<Instant>) {
    match up.shared {
        Some(shared) => {
            let started = shared[i].fails_started_ms.load(Ordering::Relaxed);
            let opened = (started != 0).then(|| origin() + Duration::from_millis(started - 1));
            (shared[i].fails.load(Ordering::Relaxed), opened)
        }
        None => (rt.peers[i].fails, rt.peers[i].fails_started),
    }
}

/// An upstream's balancing method, prepared.
#[derive(Debug, Clone, Copy)]
pub enum Lb {
    RoundRobin,
    LeastConn,
    Hash(&'static HashLb),
    IpHash,
}

/// `hash key [consistent]`.
#[derive(Debug)]
pub struct HashLb {
    pub key: &'static [PreparedValuePart],
    /// `consistent`: the ring of points, sorted by hash.
    pub ring: Option<Box<[ChashPoint]>>,
}

/// A point of the consistent-hash ring, and the peer it maps to (the
/// first one with that `server` text).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChashPoint {
    pub hash: u32,
    pub peer: u32,
}

impl Lb {
    pub(crate) fn prepare(lb: LbAlgorithm, peers: &[PreparedPeer]) -> Lb {
        match lb {
            LbAlgorithm::RoundRobin => Lb::RoundRobin,
            LbAlgorithm::LeastConn => Lb::LeastConn,
            LbAlgorithm::IpHash => Lb::IpHash,
            LbAlgorithm::Hash { key, consistent } => {
                Lb::Hash(crate::arena::leak(Box::new(HashLb {
                    key: crate::worker::prepare_value_parts(key),
                    ring: consistent.then(|| chash_ring(peers)),
                })))
            }
        }
    }
}

/// CRC-32 as nginx's ngx_crc32_* (the zlib polynomial).
fn crc32_update(mut crc: u32, data: &[u8]) -> u32 {
    const TABLE: [u32; 256] = {
        let mut table = [0u32; 256];
        let mut i = 0;
        while i < 256 {
            let mut c = i as u32;
            let mut k = 0;
            while k < 8 {
                c = if c & 1 != 0 {
                    0xedb8_8320 ^ (c >> 1)
                } else {
                    c >> 1
                };
                k += 1;
            }
            table[i] = c;
            i += 1;
        }
        table
    };
    for &b in data {
        crc = TABLE[((crc ^ b as u32) & 0xff) as usize] ^ (crc >> 8);
    }
    crc
}

fn crc32(data: &[u8]) -> u32 {
    crc32_update(0xffff_ffff, data) ^ 0xffff_ffff
}

/// ngx_http_upstream_init_chash: `160 × weight` points per primary peer,
/// each `crc32(HOST \0 PORT PREV_HASH)` from the `server` text as written,
/// sorted, equal hashes kept once.
fn chash_ring(peers: &[PreparedPeer]) -> Box<[ChashPoint]> {
    let mut points = Vec::new();
    for (i, peer) in peers.iter().enumerate().filter(|(_, p)| !p.backup) {
        let server = peer.display;
        let (host, port): (&[u8], &[u8]) = if server.len() >= 5
            && server[..5].eq_ignore_ascii_case(b"unix:")
        {
            (&server[5..], b"")
        } else {
            // The port is the run of digits after the last `:`.
            let digits = server
                .iter()
                .rev()
                .take_while(|b| b.is_ascii_digit())
                .count();
            match server.len().checked_sub(digits + 1) {
                Some(colon) if server[colon] == b':' => (&server[..colon], &server[colon + 1..]),
                _ => (server, b""),
            }
        };
        let mut base = crc32_update(0xffff_ffff, host);
        base = crc32_update(base, b"\0");
        base = crc32_update(base, port);
        // Owners are the first peer with this text, as nginx compares
        // the point's server string with each peer's.
        let owner = peers
            .iter()
            .position(|p| p.display == server && !p.backup)
            .unwrap_or(i) as u32;
        let mut prev: u32 = 0;
        for _ in 0..peer.weight as usize * 160 {
            let hash = crc32_update(base, &prev.to_le_bytes()) ^ 0xffff_ffff;
            points.push(ChashPoint { hash, peer: owner });
            prev = hash;
        }
    }
    // ngx_qsort isn't stable, but points with one hash collapse to the
    // first, and nginx's choice between two servers on one hash is
    // arbitrary too.
    points.sort_by_key(|p| p.hash);
    points.dedup_by_key(|p| p.hash);
    points.into_boxed_slice()
}

/// ngx_http_upstream_find_chash_point: the first point at or after
/// `hash` (`len` when past the last; taken modulo the ring size).
fn find_chash_point(ring: &[ChashPoint], hash: u32) -> usize {
    ring.partition_point(|p| p.hash < hash)
}

/// The per-request state of a hash balancer across tries, as nginx keeps
/// it in the peer data: picks after a failed try go on from it.
#[derive(Debug)]
pub enum HashPick {
    /// `hash key`: the key, the running hash and the rehash count.
    Hash {
        key: Box<[u8]>,
        hash: u32,
        rehash: u32,
        tries: u32,
    },
    /// `hash key consistent`: the ring position.
    Chash { point: usize, tries: u32 },
    /// `ip_hash`: the address bytes hashed and the running hash.
    IpHash {
        addr: [u8; 16],
        len: u8,
        hash: u32,
        tries: u32,
    },
    /// An empty key: round-robin.
    RoundRobin,
}

impl HashPick {
    /// The state for one request: `key` renders the `hash` key,
    /// `remote_addr` is the client address (realip's, if any). `None` for
    /// the other methods.
    pub(crate) fn for_request(
        upstream: &PreparedUpstream,
        key: impl FnOnce(&'static [PreparedValuePart]) -> Vec<u8>,
        remote_addr: &[u8],
    ) -> Option<Box<HashPick>> {
        let pick = match upstream.lb {
            Lb::RoundRobin | Lb::LeastConn => return None,
            Lb::Hash(h) => {
                let key = key(h.key);
                if key.is_empty() {
                    HashPick::RoundRobin
                } else if let Some(ring) = &h.ring {
                    HashPick::Chash {
                        point: find_chash_point(ring, crc32(&key)),
                        tries: 0,
                    }
                } else {
                    HashPick::Hash {
                        key: key.into_boxed_slice(),
                        hash: 0,
                        rehash: 0,
                        tries: 0,
                    }
                }
            }
            Lb::IpHash => {
                // IPv4: the first three octets; IPv6: all sixteen; anything
                // else (a unix-domain client): three zero bytes.
                let mut addr = [0u8; 16];
                let len = match std::str::from_utf8(remote_addr)
                    .ok()
                    .and_then(|a| a.parse::<std::net::IpAddr>().ok())
                {
                    Some(std::net::IpAddr::V4(ip)) => {
                        addr[..3].copy_from_slice(&ip.octets()[..3]);
                        3
                    }
                    Some(std::net::IpAddr::V6(ip)) => {
                        addr = ip.octets();
                        16
                    }
                    None => 3,
                };
                HashPick::IpHash {
                    addr,
                    len,
                    hash: 89,
                    tries: 0,
                }
            }
        };
        Some(Box::new(pick))
    }
}

/// Primary peers with their weights, in order: what the hash walks.
fn primary(peers: &[PreparedPeer]) -> impl Iterator<Item = (usize, &PreparedPeer)> {
    peers.iter().enumerate().filter(|(_, p)| !p.backup)
}

/// The primary peer `w` falls on when walking the weights.
fn weighted_peer(peers: &[PreparedPeer], mut w: u32) -> usize {
    for (i, p) in primary(peers) {
        if w < p.weight {
            return i;
        }
        w -= p.weight;
    }
    unreachable!("w is below the total weight")
}

/// ngx_http_upstream_get_hash_peer / _get_chash_peer / _get_ip_hash_peer.
/// `None`: fall back to round-robin (an empty key, a single peer, or 20
/// tries without a usable peer).
fn hash_pick(
    rt: &mut UpstreamRt,
    upstream: &PreparedUpstream,
    state: &mut HashPick,
    tried: &Tried,
    now: Instant,
) -> Option<usize> {
    let peers = upstream.peers;
    if primary(peers).nth(1).is_none() {
        return None;
    }
    let total: u32 = primary(peers).map(|(_, p)| p.weight).sum();
    let usable = |rt: &UpstreamRt, i: usize| peer_eligible(rt, upstream, i, false, tried, now);
    match state {
        HashPick::RoundRobin => None,
        HashPick::Hash {
            key,
            hash,
            rehash,
            tries,
        } => loop {
            if *tries > 20 {
                return None;
            }
            // ((crc32([REHASH] KEY) >> 16) & 0x7fff) + PREV_HASH, as
            // Cache::Memcached; no REHASH the first time.
            let mut crc = 0xffff_ffff;
            if *rehash > 0 {
                crc = crc32_update(crc, rehash.to_string().as_bytes());
            }
            crc = crc32_update(crc, key) ^ 0xffff_ffff;
            *hash = hash.wrapping_add((crc >> 16) & 0x7fff);
            *rehash += 1;
            let i = weighted_peer(peers, *hash % total);
            if usable(rt, i) {
                return Some(i);
            }
            *tries += 1;
        },
        HashPick::IpHash {
            addr,
            len,
            hash,
            tries,
        } => {
            let mut h = *hash;
            loop {
                if *tries > 20 {
                    return None;
                }
                for &b in &addr[..*len as usize] {
                    h = (h * 113 + b as u32) % 6271;
                }
                let i = weighted_peer(peers, h % total);
                if usable(rt, i) {
                    // Kept only once a peer is taken, as nginx does.
                    *hash = h;
                    return Some(i);
                }
                *tries += 1;
            }
        }
        HashPick::Chash { point, tries } => {
            let Lb::Hash(HashLb {
                ring: Some(ring), ..
            }) = upstream.lb
            else {
                return None;
            };
            loop {
                if *tries > 20 {
                    return None;
                }
                let owner = &peers[ring[*point % ring.len()].peer as usize];
                // The peers with that server text, by smoothed weight.
                let mut total = 0i64;
                let mut best: Option<usize> = None;
                for (i, p) in primary(peers) {
                    if p.display != owner.display || !usable(rt, i) {
                        continue;
                    }
                    let s = &mut rt.peers[i];
                    s.current_weight += s.effective_weight;
                    total += s.effective_weight;
                    if s.effective_weight < p.weight as i64 {
                        s.effective_weight += 1;
                    }
                    let current = s.current_weight;
                    if best.is_none_or(|b| current > rt.peers[b].current_weight) {
                        best = Some(i);
                    }
                }
                if let Some(b) = best {
                    rt.peers[b].current_weight -= total;
                    return Some(b);
                }
                *point += 1;
                *tries += 1;
            }
        }
    }
}

/// Per-peer mutable state for the smoothed weighted round-robin algorithm,
/// failure tracking, and active-conn counters. Field meanings mirror
/// `ngx_http_upstream_rr_peer_t`.
#[derive(Debug)]
struct PeerRtState {
    current_weight: i64,
    effective_weight: i64,
    /// Consecutive-failure count within the current `fail_timeout` window.
    /// Resets on a success or when the window elapses.
    fails: u32,
    /// When the current failure window opened. Used together with
    /// `fail_timeout_ms` to know when to expire `fails` and lift the
    /// cooldown. `None` means "no failure recorded yet".
    fails_started: Option<Instant>,
    /// Active in-flight requests on this peer — decremented when the
    /// `LeasedPeer` guard drops. Drives the least_conn pick.
    active: u32,
}

#[derive(Debug)]
struct UpstreamRt {
    peers: Vec<PeerRtState>,
}

thread_local! {
    static LB_STATE: RefCell<HashMap<*const PreparedUpstream, UpstreamRt, FxBuild>> =
        RefCell::new(HashMap::default());
}

/// Peers already tried on this request, nginx's `rrp->tried`: one word
/// inline, and a heap bitmap only once a peer past index 63 is tried
/// (`ngx_http_upstream_round_robin.c:284`, `:404`). Empty and
/// allocation-free by default.
#[derive(Default)]
pub struct Tried {
    low: u64,
    /// Peers from index 64 up. Boxed so the set stays two words.
    high: Option<Box<Vec<u64>>>,
}

impl Tried {
    #[inline]
    pub fn contains(&self, i: usize) -> bool {
        if i < 64 {
            self.low & (1u64 << i) != 0
        } else {
            self.contains_high(i - 64)
        }
    }

    #[inline]
    pub fn insert(&mut self, i: usize) {
        if i < 64 {
            self.low |= 1u64 << i;
        } else {
            self.insert_high(i - 64);
        }
    }

    /// Cold: only upstreams of more than 64 peers get here.
    #[cold]
    #[inline(never)]
    fn contains_high(&self, i: usize) -> bool {
        self.high
            .as_ref()
            .and_then(|h| h.get(i / 64))
            .is_some_and(|w| w & (1u64 << (i % 64)) != 0)
    }

    #[cold]
    #[inline(never)]
    fn insert_high(&mut self, i: usize) {
        let high = self.high.get_or_insert_with(Box::default);
        if i / 64 >= high.len() {
            high.resize(i / 64 + 1, 0);
        }
        high[i / 64] |= 1u64 << (i % 64);
    }
}

/// One primary peer and no backups: nginx's `peers->single`.
fn is_single(upstream: &PreparedUpstream) -> bool {
    matches!(upstream.peers, [only] if !only.backup)
}

/// Pick the next peer for `upstream`. Returns the index into
/// `upstream.peers`, or `None` if every peer is `down`/cooling-off — that
/// maps to a 502 in the proxy attempt. The returned `LeasedPeer` decrements
/// the active-conn counter when dropped, which least_conn relies on.
///
/// `tried` holds the peers already attempted on this request (empty for
/// the first pick). Used by the `proxy_next_upstream` retry loop in
/// `proxy.rs` to avoid re-trying a peer that already failed.
///
/// `hash` carries a hash balancer's state for the request (`None` for
/// round-robin and least_conn).
pub fn pick_peer(
    upstream: &'static PreparedUpstream,
    tried: &Tried,
    hash: Option<&mut HashPick>,
) -> Option<LeasedPeer> {
    let now = Instant::now();
    LB_STATE.with(|state| {
        let mut map = state.borrow_mut();
        let key = upstream as *const PreparedUpstream;
        let rt = map.entry(key).or_insert_with(|| ensure_rt(upstream));
        let pick = match upstream.lb {
            Lb::LeastConn => least_conn_pick(rt, upstream, false, tried, now)
                .or_else(|| least_conn_pick(rt, upstream, true, tried, now)),
            // A hash balancer falls back to round-robin.
            Lb::Hash(_) | Lb::IpHash => hash
                .and_then(|h| hash_pick(rt, upstream, h, tried, now))
                .or_else(|| rr_pick_with_filter(rt, upstream, false, tried, now))
                .or_else(|| rr_pick_with_filter(rt, upstream, true, tried, now)),
            Lb::RoundRobin => rr_pick_with_filter(rt, upstream, false, tried, now)
                .or_else(|| rr_pick_with_filter(rt, upstream, true, tried, now)),
        };
        let idx = pick?;
        match upstream.shared {
            Some(shared) => {
                shared[idx].conns.fetch_add(1, Ordering::Relaxed);
            }
            None => rt.peers[idx].active = rt.peers[idx].active.saturating_add(1),
        }
        Some(LeasedPeer {
            upstream,
            peer_idx: idx,
        })
    })
}

fn peer_eligible(
    rt: &UpstreamRt,
    up: &PreparedUpstream,
    i: usize,
    backup_tier: bool,
    tried: &Tried,
    now: Instant,
) -> bool {
    let p = &up.peers[i];
    if p.down {
        return false;
    }
    if p.backup != backup_tier {
        return false;
    }
    if tried.contains(i) {
        return false;
    }
    if p.max_conns > 0 && active(rt, up, i) >= p.max_conns {
        return false;
    }
    let (fails, fails_started) = fail_state(rt, up, i);
    if let Some(opened) = fails_started {
        if fails >= p.max_fails && p.max_fails > 0 {
            // Cooldown is active until fail_timeout has elapsed since the
            // most recent failure.
            if now.saturating_duration_since(opened) < Duration::from_millis(p.fail_timeout_ms) {
                return false;
            }
        }
    }
    true
}

fn rr_pick_with_filter(
    rt: &mut UpstreamRt,
    up: &PreparedUpstream,
    backup_tier: bool,
    tried: &Tried,
    now: Instant,
) -> Option<usize> {
    let peers = up.peers;
    let mut total: i64 = 0;
    let mut best: Option<usize> = None;
    for i in 0..peers.len() {
        if !peer_eligible(rt, up, i, backup_tier, tried, now) {
            continue;
        }
        let s = &mut rt.peers[i];
        s.current_weight = s.current_weight.saturating_add(s.effective_weight);
        total = total.saturating_add(s.effective_weight);
        if s.effective_weight < peers[i].weight as i64 {
            s.effective_weight += 1;
        }
        match best {
            None => best = Some(i),
            Some(b) if s.current_weight > rt.peers[b].current_weight => best = Some(i),
            _ => {}
        }
    }
    if let Some(b) = best {
        rt.peers[b].current_weight = rt.peers[b].current_weight.saturating_sub(total);
    }
    best
}

fn least_conn_pick(
    rt: &mut UpstreamRt,
    up: &PreparedUpstream,
    backup_tier: bool,
    tried: &Tried,
    now: Instant,
) -> Option<usize> {
    let peers = up.peers;
    // First pass: find the smallest active/weight ratio across eligible
    // peers. nginx compares fractions via the cross-multiplication
    // `c1 * w2 vs c2 * w1` to avoid float math; we mirror that with i128.
    let mut best: Option<usize> = None;
    for i in 0..peers.len() {
        if !peer_eligible(rt, up, i, backup_tier, tried, now) {
            continue;
        }
        match best {
            None => best = Some(i),
            Some(b) => {
                let pi = &peers[i];
                let pb = &peers[b];
                let ci = active(rt, up, i) as i128;
                let cb = active(rt, up, b) as i128;
                let wi = pi.weight.max(1) as i128;
                let wb = pb.weight.max(1) as i128;
                if ci * wb < cb * wi {
                    best = Some(i);
                }
            }
        }
    }
    let candidate = best?;
    let candidate_active = active(rt, up, candidate);
    let candidate_weight = peers[candidate].weight.max(1) as i128;
    // Tie-break: among peers tied with the candidate on `c/w`, run the
    // smoothed weighted RR pick to keep the distribution fair. This is
    // exactly what `ngx_http_upstream_get_least_conn_peer` does at the
    // `n == many` fallback (lc.c:171–219).
    let mut tie_count = 0;
    for i in 0..peers.len() {
        if !peer_eligible(rt, up, i, backup_tier, tried, now) {
            continue;
        }
        let pi = &peers[i];
        let ci = active(rt, up, i) as i128;
        let wi = pi.weight.max(1) as i128;
        if ci * candidate_weight == candidate_active as i128 * wi {
            tie_count += 1;
        }
    }
    if tie_count <= 1 {
        return Some(candidate);
    }
    // Run a constrained RR pick over the tied subset. Walking the same
    // peer list twice is cheap (peer count tops out in the dozens).
    let mut total: i64 = 0;
    let mut tie_best: Option<usize> = None;
    for i in 0..peers.len() {
        if !peer_eligible(rt, up, i, backup_tier, tried, now) {
            continue;
        }
        let pi = &peers[i];
        let ci = active(rt, up, i) as i128;
        let wi = pi.weight.max(1) as i128;
        if ci * candidate_weight != candidate_active as i128 * wi {
            continue;
        }
        let s = &mut rt.peers[i];
        s.current_weight = s.current_weight.saturating_add(s.effective_weight);
        total = total.saturating_add(s.effective_weight);
        if s.effective_weight < peers[i].weight as i64 {
            s.effective_weight += 1;
        }
        match tie_best {
            None => tie_best = Some(i),
            Some(b) if s.current_weight > rt.peers[b].current_weight => tie_best = Some(i),
            _ => {}
        }
    }
    if let Some(b) = tie_best {
        rt.peers[b].current_weight = rt.peers[b].current_weight.saturating_sub(total);
    }
    tie_best.or(Some(candidate))
}

/// Record a failed attempt against `peer_idx`. Mirrors nginx's
/// `ngx_http_upstream_round_robin.c::ngx_http_upstream_free_round_robin_peer`
/// PEER_FAILED branch (line 1025–1080): increment `fails`; subtract
/// `weight / max_fails` from `effective_weight` (floor at 0). Failures are
/// counted within a `fail_timeout` window measured from the most recent fail.
pub fn report_failure(upstream: &'static PreparedUpstream, peer_idx: usize) {
    // nginx never marks a lone server unavailable: with one peer and no
    // backups (`peers->single`), max_fails and fail_timeout are ignored and
    // failures aren't even counted (ngx_http_upstream_free_round_robin_peer
    // returns early). Otherwise one bad response would turn the next
    // fail_timeout seconds into `no live upstreams` 502s.
    if is_single(upstream) {
        return;
    }
    LB_STATE.with(|state| {
        let mut map = state.borrow_mut();
        let key = upstream as *const PreparedUpstream;
        let rt = map.entry(key).or_insert_with(|| ensure_rt(upstream));
        let Some(peer) = upstream.peers.get(peer_idx) else {
            return;
        };
        let s = &mut rt.peers[peer_idx];
        let now = Instant::now();
        let window = Duration::from_millis(peer.fail_timeout_ms);
        if let Some(shared) = upstream.shared {
            // Every worker counts into the same window.
            let shared = &shared[peer_idx];
            let started = shared.fails_started_ms.load(Ordering::Relaxed);
            if started != 0
                && ms_since_origin(now).saturating_sub(started) >= window.as_millis() as u64
            {
                shared.fails.store(0, Ordering::Relaxed);
            }
            shared.fails.fetch_add(1, Ordering::Relaxed);
            shared
                .fails_started_ms
                .store(ms_since_origin(now), Ordering::Relaxed);
        } else {
            if let Some(opened) = s.fails_started {
                if now.saturating_duration_since(opened) >= window {
                    // Prior window elapsed — start a fresh failure window.
                    s.fails = 0;
                }
            }
            s.fails = s.fails.saturating_add(1);
            s.fails_started = Some(now);
        }
        // effective_weight penalty per nginx (rr.c:1051):
        //   weight - weight / max_fails  (i.e. lose 1/max_fails per fail).
        if peer.max_fails > 0 {
            let penalty = peer.weight as i64 / peer.max_fails as i64;
            s.effective_weight = (s.effective_weight - penalty).max(0);
        }
    });
}

fn ensure_rt(upstream: &'static PreparedUpstream) -> UpstreamRt {
    UpstreamRt {
        peers: upstream
            .peers
            .iter()
            .map(|p| PeerRtState {
                current_weight: 0,
                effective_weight: p.weight as i64,
                fails: 0,
                fails_started: None,
                active: 0,
            })
            .collect(),
    }
}

/// Record a successful attempt. The per-pick `effective_weight++` ramp
/// (mirroring nginx rr.c:887-889) lives in the pick loop, not here.
/// Fail counters are time-windowed: clear them only once the most recent
/// failure is older than `fail_timeout`, so intermittent failures still
/// accumulate and can trip `max_fails`.
pub fn report_success(upstream: &'static PreparedUpstream, peer_idx: usize) {
    if let Some(shared) = upstream.shared {
        let (Some(shared), Some(peer)) = (shared.get(peer_idx), upstream.peers.get(peer_idx))
        else {
            return;
        };
        let started = shared.fails_started_ms.load(Ordering::Relaxed);
        if started != 0
            && ms_since_origin(Instant::now()).saturating_sub(started) >= peer.fail_timeout_ms
        {
            shared.fails.store(0, Ordering::Relaxed);
            shared.fails_started_ms.store(0, Ordering::Relaxed);
        }
        return;
    }
    LB_STATE.with(|state| {
        let mut map = state.borrow_mut();
        let key = upstream as *const PreparedUpstream;
        let rt = map.entry(key).or_insert_with(|| ensure_rt(upstream));
        let Some(peer) = upstream.peers.get(peer_idx) else {
            return;
        };
        let s = &mut rt.peers[peer_idx];
        if let Some(opened) = s.fails_started {
            if Instant::now().saturating_duration_since(opened)
                >= Duration::from_millis(peer.fail_timeout_ms)
            {
                s.fails = 0;
                s.fails_started = None;
            }
        }
    });
}

/// RAII guard returned by `pick_peer`. Decrements the active-conn
/// counter on Drop. Used by least_conn for accurate pick state and by
/// the metrics surface (eventual `$upstream_*` variables).
pub struct LeasedPeer {
    upstream: &'static PreparedUpstream,
    pub peer_idx: usize,
}

impl LeasedPeer {
    #[allow(dead_code)]
    pub fn addr(&self) -> crate::worker::PeerAddr {
        self.upstream.peers[self.peer_idx].addr
    }
    #[allow(dead_code)]
    pub fn upstream(&self) -> &'static PreparedUpstream {
        self.upstream
    }
}

impl Drop for LeasedPeer {
    fn drop(&mut self) {
        if let Some(shared) = self.upstream.shared {
            shared[self.peer_idx].conns.fetch_sub(1, Ordering::Relaxed);
            return;
        }
        LB_STATE.with(|state| {
            let mut map = state.borrow_mut();
            let key = self.upstream as *const PreparedUpstream;
            if let Some(rt) = map.get_mut(&key)
                && let Some(s) = rt.peers.get_mut(self.peer_idx)
            {
                s.active = s.active.saturating_sub(1);
            }
        });
    }
}

/// One pooled upstream connection awaiting reuse. The stream is the raw
/// monoio handle; the metadata fields drive eviction at take-time.
pub struct PooledConn {
    pub stream: crate::upstream_io::UpstreamIo,
    pub last_used: Instant,
    pub opened_at: Instant,
    pub requests_served: u32,
    /// Its `worker_connections` slot, freed with the socket.
    pub slot: crate::worker::UpstreamSlot,
    /// For a TLS connection, who it was opened as (`TlsPlan::identity`).
    pub tls: Option<crate::upstream_tls::TlsIdentity>,
}

thread_local! {
    /// Keyed by upstream, peer and, for TLS, the rustls config the
    /// connection was opened with (0 for plain TCP): a location proxying
    /// over `https://` never gets a plain connection to the same peer, nor
    /// one opened with other `proxy_ssl_*` settings, such as without
    /// verification (#116, #117). Within a queue a TLS connection is only
    /// taken for the name it was opened for (`PooledConn::tls`).
    static POOL: RefCell<HashMap<(*const PreparedUpstream, usize, usize), VecDeque<PooledConn>, FxBuild>> =
        RefCell::new(HashMap::default());
}

/// Take an idle connection from the pool. Drops entries that are past
/// idle timeout; keepalive-time is enforced on release so over-age conns
/// may be reused once and then retired (nginx behavior).
pub fn pool_take(
    upstream: &'static PreparedUpstream,
    peer_idx: usize,
    tls: Option<&crate::upstream_tls::TlsPlan>,
) -> Option<PooledConn> {
    if upstream.keepalive_max_idle.is_none() {
        return None;
    }
    let idle_max = Duration::from_millis(upstream.keepalive_idle_timeout_ms);
    let now = Instant::now();
    POOL.with(|p| {
        let mut map = p.borrow_mut();
        let key = (
            upstream as *const PreparedUpstream,
            peer_idx,
            tls.map_or(0, |t| t.config_id()),
        );
        let q = map.get_mut(&key)?;
        // From the front; LIFO since we push at the front. Drop any
        // entries that have aged out on the way to the first live one
        // opened for this name.
        let mut i = 0;
        while i < q.len() {
            if now.saturating_duration_since(q[i].last_used) >= idle_max {
                q.remove(i);
                continue;
            }
            if tls.is_none_or(|t| q[i].tls.as_ref().is_some_and(|(_, name)| *name == t.name)) {
                return q.remove(i);
            }
            i += 1;
        }
        None
    })
}

/// Close one idle keep-alive connection, the least recently used of some
/// pool, to free its `worker_connections` slot. `false` if every pool is
/// empty.
pub fn pool_close_one() -> bool {
    POOL.with(|p| {
        let mut map = p.borrow_mut();
        map.values_mut().find_map(|q| q.pop_back()).is_some()
    })
}

/// Return an upstream connection to the pool. Caller has already verified
/// the connection is reusable (no Connection: close from upstream, no
/// protocol error, request fully sent + response fully read).
///
/// Drops the conn instead of pooling when:
///  - upstream has no `keepalive` configured
///  - the pool is at `keepalive_max_idle` capacity
///  - `requests_served` has reached `keepalive_requests`
///  - lifetime exceeds `keepalive_time`
pub fn pool_release(upstream: &'static PreparedUpstream, peer_idx: usize, mut conn: PooledConn) {
    let Some(max_idle) = upstream.keepalive_max_idle else {
        return;
    };
    if conn.requests_served as u64 >= upstream.keepalive_requests {
        return;
    }
    let now = Instant::now();
    if now.saturating_duration_since(conn.opened_at)
        >= Duration::from_millis(upstream.keepalive_max_lifetime_ms)
    {
        return;
    }
    conn.last_used = now;
    let tls = conn.tls.as_ref().map_or(0, |(config, _)| *config);
    POOL.with(|p| {
        let mut map = p.borrow_mut();
        let key = (upstream as *const PreparedUpstream, peer_idx, tls);
        let q = map.entry(key).or_default();
        if q.len() as u32 >= max_idle {
            // Pool full — evict the oldest (back of the deque) to make
            // room. Matches nginx's `ngx_http_upstream_keepalive_module`
            // FIFO drop policy when the queue is at capacity.
            q.pop_back();
        }
        q.push_front(conn);
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn mk_upstream(specs: &[(u32, bool, bool)]) -> &'static PreparedUpstream {
        mk_upstream_lb(specs, Lb::RoundRobin)
    }

    fn mk_upstream_lb(specs: &[(u32, bool, bool)], lb: Lb) -> &'static PreparedUpstream {
        mk_upstream_lb_with_timeout(specs, lb, 10_000)
    }

    fn mk_upstream_lb_with_timeout(
        specs: &[(u32, bool, bool)],
        lb: Lb,
        fail_timeout_ms: u64,
    ) -> &'static PreparedUpstream {
        let peers: Vec<PreparedPeer> = specs
            .iter()
            .map(|(w, down, backup)| PreparedPeer {
                addr: crate::worker::PeerAddr::Inet("127.0.0.1:1".parse::<SocketAddr>().unwrap()),
                display: b"x",
                weight: *w,
                max_fails: 1,
                fail_timeout_ms,
                max_conns: 0,
                down: *down,
                backup: *backup,
            })
            .collect();
        let peers: &'static [PreparedPeer] = crate::arena::leak(peers.into_boxed_slice());
        crate::arena::leak(Box::new(PreparedUpstream {
            name: b"t",
            peers,
            keepalive_max_idle: None,
            keepalive_requests: 1000,
            keepalive_idle_timeout_ms: 60_000,
            keepalive_max_lifetime_ms: 3_600_000,
            lb,
            shared: None,
        }))
    }

    fn pick_release(u: &'static PreparedUpstream) -> Option<usize> {
        let leased = pick_peer(u, &Tried::default(), None)?;
        let i = leased.peer_idx;
        drop(leased);
        Some(i)
    }

    #[test]
    fn round_robin_distributes_weight_one() {
        let u = mk_upstream(&[(1, false, false), (1, false, false), (1, false, false)]);
        let mut hits = [0usize; 3];
        for _ in 0..30 {
            hits[pick_release(u).unwrap()] += 1;
        }
        assert_eq!(hits, [10, 10, 10]);
    }

    #[test]
    fn weighted_picks_proportionally() {
        let u = mk_upstream(&[(3, false, false), (1, false, false)]);
        let mut hits = [0usize; 2];
        for _ in 0..40 {
            hits[pick_release(u).unwrap()] += 1;
        }
        // 3:1 → 30 hits on peer 0, 10 on peer 1.
        assert_eq!(hits, [30, 10]);
    }

    #[test]
    fn down_peers_are_skipped() {
        let u = mk_upstream(&[(1, true, false), (1, false, false)]);
        for _ in 0..5 {
            assert_eq!(pick_release(u), Some(1));
        }
    }

    #[test]
    fn backup_used_only_when_primary_all_down() {
        let u = mk_upstream(&[(1, false, false), (1, false, true)]);
        for _ in 0..5 {
            assert_eq!(pick_release(u), Some(0));
        }
        let u2 = mk_upstream(&[(1, true, false), (1, false, true)]);
        for _ in 0..5 {
            assert_eq!(pick_release(u2), Some(1));
        }
    }

    #[test]
    fn all_down_returns_none() {
        let u = mk_upstream(&[(1, true, false), (1, true, true)]);
        assert!(pick_peer(u, &Tried::default(), None).is_none());
    }

    #[test]
    fn tried_peers_are_excluded_within_attempt() {
        let u = mk_upstream(&[(1, false, false), (1, false, false), (1, false, false)]);
        let mut tried = Tried::default();
        let l0 = pick_peer(u, &tried, None).unwrap();
        tried.insert(l0.peer_idx);
        let l1 = pick_peer(u, &tried, None).unwrap();
        assert_ne!(l0.peer_idx, l1.peer_idx);
        tried.insert(l1.peer_idx);
        let l2 = pick_peer(u, &tried, None).unwrap();
        assert_ne!(l2.peer_idx, l0.peer_idx);
        assert_ne!(l2.peer_idx, l1.peer_idx);
        tried.insert(l2.peer_idx);
        assert!(pick_peer(u, &tried, None).is_none());
    }

    /// Peers past index 63 each have their own bit; they used to share
    /// one, so trying any of them excluded all the others.
    #[test]
    fn tried_set_fits_any_upstream_size() {
        let mut tried = Tried::default();
        for i in [0, 63, 64, 70, 200] {
            assert!(!tried.contains(i));
            tried.insert(i);
            assert!(tried.contains(i));
        }
        for i in [1, 62, 65, 69, 71, 127, 128, 199, 201, 1000] {
            assert!(!tried.contains(i), "{i}");
        }

        let u = mk_upstream(&[(1, false, false); 70]);
        let mut tried = Tried::default();
        let mut seen = std::collections::HashSet::new();
        while let Some(leased) = pick_peer(u, &tried, None) {
            assert!(
                seen.insert(leased.peer_idx),
                "{} picked twice",
                leased.peer_idx
            );
            tried.insert(leased.peer_idx);
        }
        assert_eq!(seen.len(), 70);
    }

    #[test]
    fn max_fails_cools_down_then_recovers() {
        let u = mk_upstream_lb_with_timeout(
            &[(1, false, false), (1, false, false)],
            Lb::RoundRobin,
            20,
        );
        // Drive enough failures into peer 0 to trip its cooldown.
        report_failure(u, 0);
        // Now peer 0 should be skipped on the next pick.
        for _ in 0..4 {
            assert_eq!(pick_release(u), Some(1));
        }
        // After fail_timeout elapses, peer 0 is eligible again.
        std::thread::sleep(Duration::from_millis(30));
        // RR will eventually return peer 0.
        let mut saw_zero = false;
        for _ in 0..6 {
            if pick_release(u) == Some(0) {
                saw_zero = true;
                break;
            }
        }
        assert!(saw_zero, "peer 0 should be eligible after fail_timeout");
    }

    #[test]
    fn intermittent_failures_still_trip_max_fails_within_window() {
        let u = mk_upstream(&[(1, false, false), (1, false, false)]);
        report_failure(u, 0);
        report_success(u, 0);
        report_failure(u, 0);
        report_success(u, 0);
        report_failure(u, 0);
        // Third failure inside fail_timeout should cool peer 0 down.
        for _ in 0..4 {
            assert_eq!(pick_release(u), Some(1));
        }
    }

    #[test]
    fn least_conn_picks_lowest_active() {
        let u = mk_upstream_lb(&[(1, false, false), (1, false, false)], Lb::LeastConn);
        // Hold a lease on peer 0, force least_conn to pick peer 1.
        let l0 = pick_peer(u, &Tried::default(), None).unwrap();
        let next = pick_peer(u, &Tried::default(), None).unwrap();
        assert_ne!(next.peer_idx, l0.peer_idx);
        drop(next);
        drop(l0);
    }

    #[test]
    fn least_conn_falls_back_to_weighted_rr_on_ties() {
        let u = mk_upstream_lb(&[(3, false, false), (1, false, false)], Lb::LeastConn);
        // No active connections held — both peers are tied at 0/w. The
        // weighted-RR fallback should distribute 3:1 over many picks.
        let mut hits = [0usize; 2];
        for _ in 0..40 {
            hits[pick_release(u).unwrap()] += 1;
        }
        assert_eq!(hits, [30, 10]);
    }

    /// The upstreams of the nginx 1.24.0 comparison: four servers with
    /// weights 1, 2, 3, 1, the second possibly `down`.
    fn hashed(lb: LbAlgorithm, second_down: bool) -> &'static PreparedUpstream {
        let servers: [(&'static [u8], u32); 4] = [
            (b"127.0.0.1:18411", 1),
            (b"127.0.0.1:18412", 2),
            (b"127.0.0.1:18413", 3),
            (b"localhost:18414", 1),
        ];
        let peers: Vec<PreparedPeer> = servers
            .iter()
            .enumerate()
            .map(|(i, (display, weight))| PreparedPeer {
                addr: crate::worker::PeerAddr::Inet(
                    format!("127.0.0.1:{}", 18411 + i).parse().unwrap(),
                ),
                display,
                weight: *weight,
                max_fails: 1,
                fail_timeout_ms: 10_000,
                max_conns: 0,
                down: second_down && i == 1,
                backup: false,
            })
            .collect();
        let peers: &'static [PreparedPeer] = crate::arena::leak(peers.into_boxed_slice());
        crate::arena::leak(Box::new(PreparedUpstream {
            name: b"t",
            peers,
            keepalive_max_idle: None,
            keepalive_requests: 1000,
            keepalive_idle_timeout_ms: 60_000,
            keepalive_max_lifetime_ms: 3_600_000,
            lb: Lb::prepare(lb, peers),
            shared: None,
        }))
    }

    /// The port `key` (or the client `addr`) goes to on a first pick.
    fn hashed_port(u: &'static PreparedUpstream, key: &str, addr: &str) -> u16 {
        let mut state = HashPick::for_request(u, |_| key.as_bytes().to_vec(), addr.as_bytes());
        let leased = pick_peer(u, &Tried::default(), state.as_deref_mut()).unwrap();
        match leased.addr() {
            crate::worker::PeerAddr::Inet(a) => a.port(),
            _ => unreachable!(),
        }
    }

    fn hash_key(consistent: bool) -> LbAlgorithm {
        LbAlgorithm::Hash {
            key: vec![crate::config::ValuePart::Var(
                crate::config::Variable::RequestUri,
            )],
            consistent,
        }
    }

    #[test]
    fn crc32_matches_zlib() {
        assert_eq!(crc32(b""), 0);
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
    }

    // Golden assignments: what nginx 1.24.0 picked for these keys and
    // client addresses on the same upstreams.
    #[test]
    fn hash_picks_as_nginx() {
        let u = hashed(hash_key(false), false);
        let got: Vec<u16> = ["1", "2", "3", "4", "5", "abc"]
            .iter()
            .map(|k| hashed_port(u, k, ""))
            .collect();
        assert_eq!(got, [18412, 18412, 18412, 18413, 18413, 18413]);
        // Rehashed past the down server.
        let u = hashed(hash_key(false), true);
        assert_eq!(hashed_port(u, "1", ""), 18413);
    }

    #[test]
    fn consistent_hash_picks_as_nginx() {
        let u = hashed(hash_key(true), false);
        let got: Vec<u16> = ["1", "2", "3", "4", "5", "abc"]
            .iter()
            .map(|k| hashed_port(u, k, ""))
            .collect();
        assert_eq!(got, [18412, 18411, 18413, 18413, 18413, 18413]);
        // Only the down server's keys move.
        let u = hashed(hash_key(true), true);
        let got: Vec<u16> = ["1", "2", "3"]
            .iter()
            .map(|k| hashed_port(u, k, ""))
            .collect();
        assert_eq!(got, [18413, 18411, 18413]);
    }

    #[test]
    fn ip_hash_picks_as_nginx() {
        let u = hashed(LbAlgorithm::IpHash, false);
        let got: Vec<u16> = [
            "10.0.0.1",
            "10.0.1.1",
            "1.2.3.4",
            "8.8.8.8",
            "100.64.1.1",
            "2001:db8::1",
            "::1",
        ]
        .iter()
        .map(|a| hashed_port(u, "", a))
        .collect();
        assert_eq!(got, [18413, 18413, 18412, 18414, 18414, 18413, 18412]);
    }

    #[test]
    fn hash_retry_moves_on_and_empty_key_is_round_robin() {
        let u = hashed(hash_key(false), false);
        let mut state = HashPick::for_request(u, |_| b"1".to_vec(), b"");
        let mut tried = Tried::default();
        let first = pick_peer(u, &tried, state.as_deref_mut()).unwrap();
        tried.insert(first.peer_idx);
        let second = pick_peer(u, &tried, state.as_deref_mut()).unwrap();
        assert_ne!(first.peer_idx, second.peer_idx);
        // An empty key: round-robin by weight, 1 + 2 + 3 + 1.
        let mut counts = [0; 4];
        for _ in 0..7 {
            let mut state = HashPick::for_request(u, |_| Vec::new(), b"");
            counts[pick_peer(u, &Tried::default(), state.as_deref_mut())
                .unwrap()
                .peer_idx] += 1;
        }
        assert_eq!(counts, [1, 2, 3, 1]);
    }

    fn zoned(max_conns: u32, zone: bool) -> &'static PreparedUpstream {
        let peers: Vec<PreparedPeer> = (0..2)
            .map(|i| PreparedPeer {
                addr: crate::worker::PeerAddr::Inet(
                    format!("127.0.0.1:{}", 1 + i).parse().unwrap(),
                ),
                display: b"x",
                weight: 1,
                max_fails: 1,
                fail_timeout_ms: 10_000,
                max_conns,
                down: false,
                backup: false,
            })
            .collect();
        let peers: &'static [PreparedPeer] = crate::arena::leak(peers.into_boxed_slice());
        crate::arena::leak(Box::new(PreparedUpstream {
            name: b"z",
            peers,
            keepalive_max_idle: None,
            keepalive_requests: 1000,
            keepalive_idle_timeout_ms: 60_000,
            keepalive_max_lifetime_ms: 3_600_000,
            lb: Lb::RoundRobin,
            shared: zone.then(|| PeerShared::for_peers(peers.len())),
        }))
    }

    #[test]
    fn max_conns_caps_each_peer() {
        // Without a zone the cap is per worker (thread), as nginx's per
        // process.
        let u = zoned(1, false);
        let a = pick_peer(u, &Tried::default(), None).unwrap();
        let b = pick_peer(u, &Tried::default(), None).unwrap();
        assert_ne!(a.peer_idx, b.peer_idx);
        assert!(pick_peer(u, &Tried::default(), None).is_none());
        let other = std::thread::spawn(move || pick_peer(u, &Tried::default(), None).is_some());
        assert!(other.join().unwrap());
        drop(a);
        assert!(pick_peer(u, &Tried::default(), None).is_some());
    }

    #[test]
    fn a_zone_shares_counts_and_failures_across_workers() {
        let u = zoned(1, true);
        let a = pick_peer(u, &Tried::default(), None).unwrap();
        let b = pick_peer(u, &Tried::default(), None).unwrap();
        // Another worker sees both peers busy.
        let other = std::thread::spawn(move || pick_peer(u, &Tried::default(), None).is_none());
        assert!(other.join().unwrap());
        drop((a, b));
        // A failure seen by one worker keeps the peer out for all of them.
        std::thread::spawn(move || report_failure(u, 0))
            .join()
            .unwrap();
        for _ in 0..4 {
            let l = pick_peer(u, &Tried::default(), None).unwrap();
            assert_eq!(l.peer_idx, 1);
        }
    }
}
