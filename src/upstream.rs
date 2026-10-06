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
use std::time::Duration;
use std::time::Instant;

use monoio::net::TcpStream;

use crate::config::LbAlgorithm;
use crate::worker::PreparedPeer;
use crate::worker::PreparedUpstream;

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
    static LB_STATE: RefCell<HashMap<*const PreparedUpstream, UpstreamRt>> =
        RefCell::new(HashMap::new());
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
pub fn pick_peer(upstream: &'static PreparedUpstream, tried: &Tried) -> Option<LeasedPeer> {
    let now = Instant::now();
    LB_STATE.with(|state| {
        let mut map = state.borrow_mut();
        let key = upstream as *const PreparedUpstream;
        let rt = map.entry(key).or_insert_with(|| ensure_rt(upstream));
        let pick = match upstream.lb {
            LbAlgorithm::RoundRobin => rr_pick_with_filter(rt, upstream.peers, false, tried, now)
                .or_else(|| rr_pick_with_filter(rt, upstream.peers, true, tried, now)),
            LbAlgorithm::LeastConn => least_conn_pick(rt, upstream.peers, false, tried, now)
                .or_else(|| least_conn_pick(rt, upstream.peers, true, tried, now)),
        };
        let idx = pick?;
        rt.peers[idx].active = rt.peers[idx].active.saturating_add(1);
        Some(LeasedPeer {
            upstream,
            peer_idx: idx,
        })
    })
}

fn peer_eligible(
    rt: &UpstreamRt,
    peers: &[PreparedPeer],
    i: usize,
    backup_tier: bool,
    tried: &Tried,
    now: Instant,
) -> bool {
    let p = &peers[i];
    if p.down {
        return false;
    }
    if p.backup != backup_tier {
        return false;
    }
    if tried.contains(i) {
        return false;
    }
    let s = &rt.peers[i];
    if let Some(opened) = s.fails_started {
        if s.fails >= p.max_fails && p.max_fails > 0 {
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
    peers: &[PreparedPeer],
    backup_tier: bool,
    tried: &Tried,
    now: Instant,
) -> Option<usize> {
    let mut total: i64 = 0;
    let mut best: Option<usize> = None;
    for i in 0..peers.len() {
        if !peer_eligible(rt, peers, i, backup_tier, tried, now) {
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
    peers: &[PreparedPeer],
    backup_tier: bool,
    tried: &Tried,
    now: Instant,
) -> Option<usize> {
    // First pass: find the smallest active/weight ratio across eligible
    // peers. nginx compares fractions via the cross-multiplication
    // `c1 * w2 vs c2 * w1` to avoid float math; we mirror that with i128.
    let mut best: Option<usize> = None;
    for i in 0..peers.len() {
        if !peer_eligible(rt, peers, i, backup_tier, tried, now) {
            continue;
        }
        match best {
            None => best = Some(i),
            Some(b) => {
                let pi = &peers[i];
                let pb = &peers[b];
                let ci = rt.peers[i].active as i128;
                let cb = rt.peers[b].active as i128;
                let wi = pi.weight.max(1) as i128;
                let wb = pb.weight.max(1) as i128;
                if ci * wb < cb * wi {
                    best = Some(i);
                }
            }
        }
    }
    let candidate = best?;
    let candidate_active = rt.peers[candidate].active;
    let candidate_weight = peers[candidate].weight.max(1) as i128;
    // Tie-break: among peers tied with the candidate on `c/w`, run the
    // smoothed weighted RR pick to keep the distribution fair. This is
    // exactly what `ngx_http_upstream_get_least_conn_peer` does at the
    // `n == many` fallback (lc.c:171–219).
    let mut tie_count = 0;
    for i in 0..peers.len() {
        if !peer_eligible(rt, peers, i, backup_tier, tried, now) {
            continue;
        }
        let pi = &peers[i];
        let ci = rt.peers[i].active as i128;
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
        if !peer_eligible(rt, peers, i, backup_tier, tried, now) {
            continue;
        }
        let pi = &peers[i];
        let ci = rt.peers[i].active as i128;
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
        if let Some(opened) = s.fails_started {
            if now.saturating_duration_since(opened) >= Duration::from_millis(peer.fail_timeout_ms)
            {
                // Prior window elapsed — start a fresh failure window.
                s.fails = 0;
            }
        }
        s.fails = s.fails.saturating_add(1);
        s.fails_started = Some(now);
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
    pub fn addr(&self) -> std::net::SocketAddr {
        self.upstream.peers[self.peer_idx].addr
    }
    #[allow(dead_code)]
    pub fn upstream(&self) -> &'static PreparedUpstream {
        self.upstream
    }
}

impl Drop for LeasedPeer {
    fn drop(&mut self) {
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
    pub stream: TcpStream,
    pub last_used: Instant,
    pub opened_at: Instant,
    pub requests_served: u32,
    /// Its `worker_connections` slot, freed with the socket.
    pub slot: crate::worker::UpstreamSlot,
}

thread_local! {
    static POOL: RefCell<HashMap<(*const PreparedUpstream, usize), VecDeque<PooledConn>>> =
        RefCell::new(HashMap::new());
}

/// Take an idle connection from the pool. Drops entries that are past
/// idle timeout; keepalive-time is enforced on release so over-age conns
/// may be reused once and then retired (nginx behavior).
pub fn pool_take(upstream: &'static PreparedUpstream, peer_idx: usize) -> Option<PooledConn> {
    if upstream.keepalive_max_idle.is_none() {
        return None;
    }
    let idle_max = Duration::from_millis(upstream.keepalive_idle_timeout_ms);
    let now = Instant::now();
    POOL.with(|p| {
        let mut map = p.borrow_mut();
        let key = (upstream as *const PreparedUpstream, peer_idx);
        let q = map.get_mut(&key)?;
        // Pop from the front; LIFO since we push at the front. Drop any
        // entries that have aged out before returning the first live one.
        while let Some(c) = q.pop_front() {
            if now.saturating_duration_since(c.last_used) >= idle_max {
                continue;
            }
            return Some(c);
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
    POOL.with(|p| {
        let mut map = p.borrow_mut();
        let key = (upstream as *const PreparedUpstream, peer_idx);
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
        mk_upstream_lb(specs, LbAlgorithm::RoundRobin)
    }

    fn mk_upstream_lb(specs: &[(u32, bool, bool)], lb: LbAlgorithm) -> &'static PreparedUpstream {
        mk_upstream_lb_with_timeout(specs, lb, 10_000)
    }

    fn mk_upstream_lb_with_timeout(
        specs: &[(u32, bool, bool)],
        lb: LbAlgorithm,
        fail_timeout_ms: u64,
    ) -> &'static PreparedUpstream {
        let peers: Vec<PreparedPeer> = specs
            .iter()
            .map(|(w, down, backup)| PreparedPeer {
                addr: "127.0.0.1:1".parse::<SocketAddr>().unwrap(),
                display: b"x",
                weight: *w,
                max_fails: 1,
                fail_timeout_ms,
                down: *down,
                backup: *backup,
            })
            .collect();
        let peers: &'static [PreparedPeer] = Box::leak(peers.into_boxed_slice());
        Box::leak(Box::new(PreparedUpstream {
            name: b"t",
            peers,
            keepalive_max_idle: None,
            keepalive_requests: 1000,
            keepalive_idle_timeout_ms: 60_000,
            keepalive_max_lifetime_ms: 3_600_000,
            lb,
        }))
    }

    fn pick_release(u: &'static PreparedUpstream) -> Option<usize> {
        let leased = pick_peer(u, &Tried::default())?;
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
        assert!(pick_peer(u, &Tried::default()).is_none());
    }

    #[test]
    fn tried_peers_are_excluded_within_attempt() {
        let u = mk_upstream(&[(1, false, false), (1, false, false), (1, false, false)]);
        let mut tried = Tried::default();
        let l0 = pick_peer(u, &tried).unwrap();
        tried.insert(l0.peer_idx);
        let l1 = pick_peer(u, &tried).unwrap();
        assert_ne!(l0.peer_idx, l1.peer_idx);
        tried.insert(l1.peer_idx);
        let l2 = pick_peer(u, &tried).unwrap();
        assert_ne!(l2.peer_idx, l0.peer_idx);
        assert_ne!(l2.peer_idx, l1.peer_idx);
        tried.insert(l2.peer_idx);
        assert!(pick_peer(u, &tried).is_none());
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
        while let Some(leased) = pick_peer(u, &tried) {
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
            LbAlgorithm::RoundRobin,
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
        let u = mk_upstream_lb(
            &[(1, false, false), (1, false, false)],
            LbAlgorithm::LeastConn,
        );
        // Hold a lease on peer 0, force least_conn to pick peer 1.
        let l0 = pick_peer(u, &Tried::default()).unwrap();
        let next = pick_peer(u, &Tried::default()).unwrap();
        assert_ne!(next.peer_idx, l0.peer_idx);
        drop(next);
        drop(l0);
    }

    #[test]
    fn least_conn_falls_back_to_weighted_rr_on_ties() {
        let u = mk_upstream_lb(
            &[(3, false, false), (1, false, false)],
            LbAlgorithm::LeastConn,
        );
        // No active connections held — both peers are tied at 0/w. The
        // weighted-RR fallback should distribute 3:1 over many picks.
        let mut hits = [0usize; 2];
        for _ in 0..40 {
            hits[pick_release(u).unwrap()] += 1;
        }
        assert_eq!(hits, [30, 10]);
    }
}
