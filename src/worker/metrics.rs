//! `ruxen_metrics;` (#481): the `stub_status` counters, per server and per
//! upstream peer counters, in Prometheus text format 0.0.4.
//!
//! Kept only when a location uses the handler: `PreparedHttp::metrics` is
//! `None` otherwise, and every update site checks that first. As in
//! `stats`, each worker owns its slots (cache-line aligned) and is their
//! only writer: an update is a relaxed load and store. The handler sums
//! the workers' slots. Slots belong to a configuration generation, so a
//! reload starts the counters again at zero.
//!
//! `limit_req`, `limit_conn` and cache zones that a reload keeps keep their
//! counters too (`ZoneCounters`); those are counted whether or not a
//! location shows them.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering::Relaxed};
use std::sync::{Mutex, OnceLock};

use super::{PreparedPeer, PreparedUpstream};

/// Upper bounds of the response-time histogram, in µs (Prometheus's
/// default buckets).
const BUCKETS_US: [u64; 11] = [
    5_000, 10_000, 25_000, 50_000, 100_000, 250_000, 500_000, 1_000_000, 2_500_000, 5_000_000,
    10_000_000,
];

#[repr(align(64))]
#[derive(Default)]
struct ServerSlot {
    /// Responses by status class, 1xx to 5xx (anything else counts as 5xx).
    by_class: [AtomicU64; 5],
    bytes: AtomicU64,
}

#[repr(align(64))]
#[derive(Default)]
struct PeerSlot {
    requests: AtomicU64,
    failures: AtomicU64,
    /// Per bucket (not cumulative), the last one past the largest bound.
    buckets: [AtomicU64; BUCKETS_US.len() + 1],
    sum_us: AtomicU64,
}

/// One worker's counters.
struct WorkerSlots {
    servers: Box<[ServerSlot]>,
    peers: Box<[PeerSlot]>,
}

struct ServerLabels {
    server: String,
    listen: String,
}

struct PeerLabels {
    upstream: String,
    peer: String,
    /// The peer whose state the scrape shows.
    of: Option<(&'static PreparedUpstream, usize)>,
    /// A slot of a pool, `peer` set at run time.
    pooled: Option<(&'static PeerPool, usize)>,
}

/// Slots a pool has: the distinct addresses an upstream's `resolve`
/// servers can have at once and be counted.
const POOL_SLOTS: usize = 64;

/// Slots for the peers an upstream's `resolve` servers give at run time
/// (#879). A slot is taken by an address when a peer list with it is
/// built, and freed when no list has it any more; counts from before it
/// was taken are kept as a base and subtracted.
pub struct PeerPool {
    first: u32,
    /// The static peers' slots, by address.
    statics: Vec<(String, u32)>,
    taken: Mutex<Vec<Option<Taken>>>,
    metrics: OnceLock<&'static Metrics>,
    /// The configured upstream, whose current peers the scrape shows.
    of: OnceLock<&'static PreparedUpstream>,
}

impl std::fmt::Debug for PeerPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerPool")
            .field("first", &self.first)
            .finish_non_exhaustive()
    }
}

struct Taken {
    peer: String,
    base: Counts,
}

/// A peer slot's counts, summed over the workers.
#[derive(Default, Clone, Copy)]
struct Counts {
    requests: u64,
    failures: u64,
    buckets: [u64; BUCKETS_US.len() + 1],
    sum_us: u64,
}

impl Counts {
    fn of(workers: &[&'static WorkerSlots], slot: usize) -> Counts {
        let mut c = Counts::default();
        for w in workers {
            let Some(p) = w.peers.get(slot) else {
                continue;
            };
            c.requests = c.requests.wrapping_add(p.requests.load(Relaxed));
            c.failures = c.failures.wrapping_add(p.failures.load(Relaxed));
            for (b, n) in c.buckets.iter_mut().zip(&p.buckets) {
                *b = b.wrapping_add(n.load(Relaxed));
            }
            c.sum_us = c.sum_us.wrapping_add(p.sum_us.load(Relaxed));
        }
        c
    }

    fn since(self, base: Counts) -> Counts {
        let mut c = Counts {
            requests: self.requests.wrapping_sub(base.requests),
            failures: self.failures.wrapping_sub(base.failures),
            buckets: self.buckets,
            sum_us: self.sum_us.wrapping_sub(base.sum_us),
        };
        for (b, base) in c.buckets.iter_mut().zip(base.buckets) {
            *b = b.wrapping_sub(base);
        }
        c
    }
}

impl PeerPool {
    /// The slot of a peer on `addr`: a static peer's, the one the address
    /// has, or a free one; `u32::MAX` (not counted) when none is free.
    pub(crate) fn slot(&self, addr: &str) -> u32 {
        if let Some((_, slot)) = self.statics.iter().find(|(a, _)| a == addr) {
            return *slot;
        }
        let mut taken = self.taken.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(k) = taken
            .iter()
            .position(|t| t.as_ref().is_some_and(|t| t.peer == addr))
        {
            return self.first + k as u32;
        }
        let Some(k) = taken.iter().position(Option::is_none) else {
            return u32::MAX;
        };
        let base = match self.metrics.get() {
            Some(m) => {
                let workers = m.workers.lock().unwrap_or_else(|e| e.into_inner());
                Counts::of(&workers, self.first as usize + k)
            }
            None => Counts::default(),
        };
        taken[k] = Some(Taken {
            peer: addr.to_string(),
            base,
        });
        self.first + k as u32
    }

    /// Free the slots `used` doesn't keep.
    pub(crate) fn keep(&self, used: impl Fn(u32) -> bool) {
        let mut taken = self.taken.lock().unwrap_or_else(|e| e.into_inner());
        for (k, t) in taken.iter_mut().enumerate() {
            if t.is_some() && !used(self.first + k as u32) {
                *t = None;
            }
        }
    }

    /// `upstream`, now prepared, is the one the pool counts for.
    pub(crate) fn note(&self, upstream: &'static PreparedUpstream) {
        let _ = self.of.set(upstream);
    }
}

/// A configuration's metrics: what the slots stand for, and every
/// worker's slots.
pub struct Metrics {
    servers: Box<[ServerLabels]>,
    peers: Box<[PeerLabels]>,
    workers: Mutex<Vec<&'static WorkerSlots>>,
    limit_req: Box<[(String, &'static ZoneCounters<5>)]>,
    limit_conn: Box<[(String, &'static ZoneCounters<3>)]>,
    caches: Box<[(String, &'static ZoneCounters<7>)]>,
}

/// Slots per `ZoneCounters`.
const ZONE_SLOTS: usize = 64;

#[repr(align(64))]
struct ZoneSlot<const N: usize>([AtomicU64; N]);

/// The counters of a zone a reload keeps, which outlive any generation's
/// workers. A slot per worker thread by thread number, so threads rarely
/// share a line; `fetch_add`, since numbers wrap past `ZONE_SLOTS`.
pub struct ZoneCounters<const N: usize> {
    slots: Box<[ZoneSlot<N>]>,
}

impl<const N: usize> Default for ZoneCounters<N> {
    fn default() -> Self {
        ZoneCounters {
            slots: (0..ZONE_SLOTS)
                .map(|_| ZoneSlot(std::array::from_fn(|_| AtomicU64::new(0))))
                .collect(),
        }
    }
}

thread_local! {
    /// This thread's slot in every `ZoneCounters`.
    static ZONE_SLOT: usize = {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        NEXT.fetch_add(1, Relaxed) % ZONE_SLOTS
    };
}

impl<const N: usize> ZoneCounters<N> {
    /// Count one in `i`.
    pub(crate) fn add(&self, i: usize) {
        let slot = ZONE_SLOT.with(|s| *s);
        self.slots[slot].0[i].fetch_add(1, Relaxed);
    }

    /// Move one count from `from` to `i`: `from` was premature.
    pub(crate) fn moved(&self, from: usize, i: usize) {
        let slot = &self.slots[ZONE_SLOT.with(|s| *s)];
        slot.0[from].fetch_sub(1, Relaxed);
        slot.0[i].fetch_add(1, Relaxed);
    }

    pub(crate) fn total(&self, i: usize) -> u64 {
        self.slots
            .iter()
            .fold(0u64, |n, s| n.wrapping_add(s.0[i].load(Relaxed)))
    }
}

impl std::fmt::Debug for Metrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Metrics")
            .field("servers", &self.servers.len())
            .field("peers", &self.peers.len())
            .finish()
    }
}

impl Drop for Metrics {
    fn drop(&mut self) {
        let workers = self.workers.get_mut().unwrap_or_else(|e| e.into_inner());
        for slots in workers.drain(..) {
            // SAFETY: leaked by `attach`; the generation's workers, the
            // only other holders, are gone once its configuration drops.
            drop(unsafe { Box::from_raw(slots as *const WorkerSlots as *mut WorkerSlots) });
        }
    }
}

thread_local! {
    /// This worker's slots, set by `attach`.
    static MINE: Cell<Option<&'static WorkerSlots>> = const { Cell::new(None) };
    /// The labels of the configuration being prepared.
    static BUILD: RefCell<Option<Builder>> = const { RefCell::new(None) };
}

#[derive(Default)]
struct Builder {
    servers: Vec<ServerLabels>,
    server_index: HashMap<(String, String), u32>,
    peers: Vec<PeerLabels>,
    peer_index: HashMap<(String, String), u32>,
    pools: Vec<&'static PeerPool>,
    limit_req: Vec<(String, &'static ZoneCounters<5>)>,
    limit_conn: Vec<(String, &'static ZoneCounters<3>)>,
    caches: Vec<(String, &'static ZoneCounters<7>)>,
}

/// Start preparing a configuration; `on` when a location uses the handler.
pub(crate) fn begin(on: bool) {
    BUILD.with(|b| *b.borrow_mut() = on.then(Builder::default));
}

/// The slot of a server on `listen` (0 when metrics are off). Servers with
/// the same name on the same address share one, so no series repeats.
pub(crate) fn server_slot(name: &[u8], listen: String) -> u32 {
    BUILD.with(|b| {
        let mut b = b.borrow_mut();
        let Some(b) = b.as_mut() else { return 0 };
        let key = (String::from_utf8_lossy(name).into_owned(), listen);
        if let Some(&i) = b.server_index.get(&key) {
            return i;
        }
        let i = b.servers.len() as u32;
        b.servers.push(ServerLabels {
            server: key.0.clone(),
            listen: key.1.clone(),
        });
        b.server_index.insert(key, i);
        i
    })
}

/// The slot of each of an upstream's peers, by upstream name and peer
/// address (two `server` lines with one address share one); `None` when
/// metrics are off.
pub(crate) fn peer_slots(upstream: &[u8], peers: &[PreparedPeer]) -> Option<&'static [u32]> {
    BUILD.with(|b| {
        let mut b = b.borrow_mut();
        let b = b.as_mut()?;
        let name = String::from_utf8_lossy(upstream).into_owned();
        let slots: Vec<u32> = peers
            .iter()
            .map(|p| {
                let key = (name.clone(), p.addr.to_string());
                if let Some(&i) = b.peer_index.get(&key) {
                    return i;
                }
                let i = b.peers.len() as u32;
                b.peers.push(PeerLabels {
                    upstream: key.0.clone(),
                    peer: key.1.clone(),
                    of: None,
                    pooled: None,
                });
                b.peer_index.insert(key, i);
                i
            })
            .collect();
        Some(&*crate::arena::leak(slots.into_boxed_slice()))
    })
}

/// A pool for the run-time peers of upstream `upstream`, whose static
/// peers have `slots`; `None` when metrics are off.
pub(crate) fn peer_pool(
    upstream: &[u8],
    statics: &[PreparedPeer],
    slots: Option<&[u32]>,
) -> Option<&'static PeerPool> {
    BUILD.with(|b| {
        let mut b = b.borrow_mut();
        let b = b.as_mut()?;
        let pool: &'static PeerPool = crate::arena::leak(Box::new(PeerPool {
            first: b.peers.len() as u32,
            statics: statics
                .iter()
                .zip(slots.unwrap_or_default())
                .map(|(p, &slot)| (p.addr.to_string(), slot))
                .collect(),
            taken: Mutex::new((0..POOL_SLOTS).map(|_| None).collect()),
            metrics: OnceLock::new(),
            of: OnceLock::new(),
        }));
        let name = String::from_utf8_lossy(upstream).into_owned();
        for k in 0..POOL_SLOTS {
            b.peers.push(PeerLabels {
                upstream: name.clone(),
                peer: String::new(),
                of: None,
                pooled: Some((pool, k)),
            });
        }
        b.pools.push(pool);
        Some(pool)
    })
}

/// `upstream`, now prepared, shows its peers' state, unless another one
/// with the same slots came first.
pub(crate) fn note_upstream(upstream: &'static PreparedUpstream) {
    let Some(slots) = upstream.metrics else {
        return;
    };
    BUILD.with(|b| {
        if let Some(b) = b.borrow_mut().as_mut() {
            for (i, &slot) in slots.iter().enumerate() {
                let labels = &mut b.peers[slot as usize];
                labels.of.get_or_insert((upstream, i));
            }
        }
    });
}

/// The configuration's `limit_req_zone` `name` counts in `counters`.
pub(crate) fn note_limit_req_zone(name: &str, counters: &'static ZoneCounters<5>) {
    BUILD.with(|b| {
        if let Some(b) = b.borrow_mut().as_mut() {
            b.limit_req.push((name.to_string(), counters));
        }
    });
}

/// The configuration's `limit_conn_zone` `name` counts in `counters`.
pub(crate) fn note_limit_conn_zone(name: &str, counters: &'static ZoneCounters<3>) {
    BUILD.with(|b| {
        if let Some(b) = b.borrow_mut().as_mut() {
            b.limit_conn.push((name.to_string(), counters));
        }
    });
}

/// The configuration's cache zone `name` counts in `counters`.
pub(crate) fn note_cache_zone(name: &str, counters: &'static ZoneCounters<7>) {
    BUILD.with(|b| {
        if let Some(b) = b.borrow_mut().as_mut() {
            b.caches.push((name.to_string(), counters));
        }
    });
}

/// The configuration's metrics, or `None` when no location reads them.
pub(crate) fn finish() -> Option<&'static Metrics> {
    let b = BUILD.with(|b| b.borrow_mut().take())?;
    let m: &'static Metrics = crate::arena::leak(Box::new(Metrics {
        servers: b.servers.into_boxed_slice(),
        peers: b.peers.into_boxed_slice(),
        workers: Mutex::new(Vec::new()),
        limit_req: b.limit_req.into_boxed_slice(),
        limit_conn: b.limit_conn.into_boxed_slice(),
        caches: b.caches.into_boxed_slice(),
    }));
    for pool in b.pools {
        let _ = pool.metrics.set(m);
    }
    Some(m)
}

impl Metrics {
    /// Give the calling worker its slots, until `detach`.
    pub(crate) fn attach(&'static self) {
        let slots: &'static WorkerSlots = Box::leak(Box::new(WorkerSlots {
            servers: (0..self.servers.len())
                .map(|_| Default::default())
                .collect(),
            peers: (0..self.peers.len()).map(|_| Default::default()).collect(),
        }));
        self.workers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(slots);
        MINE.with(|m| m.set(Some(slots)));
    }
}

/// The worker is done with its configuration's slots.
pub(crate) fn detach() {
    MINE.with(|m| m.set(None));
}

/// Owner-only update: a load and a store, both relaxed.
fn add(counter: &AtomicU64, n: u64) {
    counter.store(counter.load(Relaxed).wrapping_add(n), Relaxed);
}

/// A response (`head` the head it had) went out from server slot
/// `server`.
#[cold]
#[inline(never)]
pub(crate) fn response(server: u32, head: &[u8], bytes: u64) {
    let status = super::response::response_status(head);
    MINE.with(|m| {
        let Some(slot) = m.get().and_then(|s| s.servers.get(server as usize)) else {
            return;
        };
        let class = (status / 100).clamp(1, 5) as usize - 1;
        add(&slot.by_class[class], 1);
        add(&slot.bytes, bytes);
    });
}

/// An attempt on peer `peer` of an upstream with slots `slots` ended
/// after `took`.
#[cold]
#[inline(never)]
pub(crate) fn peer_attempt(slots: &[u32], peer: usize, took: std::time::Duration) {
    let us = took.as_micros() as u64;
    with_peer(slots, peer, |slot| {
        add(&slot.requests, 1);
        let bucket = BUCKETS_US
            .iter()
            .position(|&le| us <= le)
            .unwrap_or(BUCKETS_US.len());
        add(&slot.buckets[bucket], 1);
        add(&slot.sum_us, us);
    });
}

/// An attempt failed, as `max_fails` counts failures.
#[cold]
#[inline(never)]
pub(crate) fn peer_failure(slots: &[u32], peer: usize) {
    with_peer(slots, peer, |slot| add(&slot.failures, 1));
}

fn with_peer(slots: &[u32], peer: usize, f: impl FnOnce(&PeerSlot)) {
    MINE.with(|m| {
        if let Some(slot) = m
            .get()
            .zip(slots.get(peer))
            .and_then(|(s, &i)| s.peers.get(i as usize))
        {
            f(slot);
        }
    });
}

/// A label value, escaped as the text format wants.
fn escape(value: &str, out: &mut String) {
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
}

fn header(out: &mut String, name: &str, kind: &str, help: &str) {
    let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} {kind}");
}

/// Seconds from µs, as text.
fn seconds(us: u64) -> String {
    format!("{}.{:06}", us / 1_000_000, us % 1_000_000)
}

/// A bucket bound: `0.005`, `1`, `10`.
fn bound(us: u64) -> String {
    let s = seconds(us);
    s.trim_end_matches('0').trim_end_matches('.').to_string()
}

/// The page: the `stub_status` counters, then the configuration's.
pub(crate) fn render(m: &Metrics) -> String {
    let mut out = String::with_capacity(4096);
    let t = super::stats::totals();
    for (name, kind, help, value) in [
        (
            "ruxen_connections_active",
            "gauge",
            "Client connections open, waiting ones included.",
            t.active,
        ),
        (
            "ruxen_connections_reading",
            "gauge",
            "Connections reading a request head.",
            t.reading,
        ),
        (
            "ruxen_connections_writing",
            "gauge",
            "Connections processing a request or writing its response.",
            t.writing,
        ),
        (
            "ruxen_connections_waiting",
            "gauge",
            "Idle keep-alive connections.",
            t.waiting,
        ),
        (
            "ruxen_connections_accepted_total",
            "counter",
            "Client connections accepted.",
            t.accepted,
        ),
        (
            "ruxen_connections_handled_total",
            "counter",
            "Client connections handled (not refused at worker_connections).",
            t.handled,
        ),
        (
            "ruxen_http_requests_total",
            "counter",
            "Client requests.",
            t.requests,
        ),
    ] {
        header(&mut out, name, kind, help);
        let _ = writeln!(out, "{name} {value}");
    }

    let workers: Vec<&'static WorkerSlots> =
        m.workers.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let sum = |f: &dyn Fn(&WorkerSlots) -> u64| workers.iter().map(|w| f(w)).sum::<u64>();
    let mut labels = String::new();

    if !m.servers.is_empty() {
        header(
            &mut out,
            "ruxen_server_responses_total",
            "counter",
            "Responses by server block and status class.",
        );
        for (i, s) in m.servers.iter().enumerate() {
            labels.clear();
            labels.push_str("server=\"");
            escape(&s.server, &mut labels);
            labels.push_str("\",listen=\"");
            escape(&s.listen, &mut labels);
            labels.push('"');
            for class in 0..5 {
                let n = sum(&|w| w.servers[i].by_class[class].load(Relaxed));
                let _ = writeln!(
                    out,
                    "ruxen_server_responses_total{{{labels},code=\"{}xx\"}} {n}",
                    class + 1
                );
            }
        }
        header(
            &mut out,
            "ruxen_server_sent_bytes_total",
            "counter",
            "Bytes sent to clients by server block, heads included.",
        );
        for (i, s) in m.servers.iter().enumerate() {
            labels.clear();
            labels.push_str("server=\"");
            escape(&s.server, &mut labels);
            labels.push_str("\",listen=\"");
            escape(&s.listen, &mut labels);
            labels.push('"');
            let n = sum(&|w| w.servers[i].bytes.load(Relaxed));
            let _ = writeln!(out, "ruxen_server_sent_bytes_total{{{labels}}} {n}");
        }
    }

    if !m.peers.is_empty() {
        // The slots shown: label, counts, and the state of the peer.
        let mut up_of_pooled = HashMap::new();
        for p in m
            .peers
            .iter()
            .filter_map(|p| p.pooled)
            .filter(|(_, k)| *k == 0)
        {
            if let Some(&of) = p.0.of.get() {
                let now = crate::upstream::UpstreamRef::current(of);
                if let Some(slots) = now.metrics {
                    for (i, &slot) in slots.iter().enumerate() {
                        let up = crate::upstream::peer_up(&now, i);
                        let was = up_of_pooled.entry(slot).or_insert(false);
                        *was |= up;
                    }
                }
            }
        }
        let mut rows: Vec<(String, Counts, bool)> = Vec::with_capacity(m.peers.len());
        for (i, p) in m.peers.iter().enumerate() {
            let (peer, base) = match p.pooled {
                None => (p.peer.clone(), Counts::default()),
                Some((pool, k)) => {
                    let taken = pool.taken.lock().unwrap_or_else(|e| e.into_inner());
                    match &taken[k] {
                        Some(t) => (t.peer.clone(), t.base),
                        None => continue,
                    }
                }
            };
            let mut l = String::from("upstream=\"");
            escape(&p.upstream, &mut l);
            l.push_str("\",peer=\"");
            escape(&peer, &mut l);
            l.push('"');
            let up = match up_of_pooled.get(&(i as u32)) {
                Some(&up) => up,
                None => {
                    p.of.is_none_or(|(upstream, i)| crate::upstream::peer_up(upstream, i))
                }
            };
            rows.push((l, Counts::of(&workers, i).since(base), up));
        }
        header(
            &mut out,
            "ruxen_upstream_peer_requests_total",
            "counter",
            "Attempts on an upstream peer.",
        );
        for (l, c, _) in &rows {
            let _ = writeln!(
                out,
                "ruxen_upstream_peer_requests_total{{{l}}} {}",
                c.requests
            );
        }
        header(
            &mut out,
            "ruxen_upstream_peer_failures_total",
            "counter",
            "Failed attempts on an upstream peer, as max_fails counts them.",
        );
        for (l, c, _) in &rows {
            let _ = writeln!(
                out,
                "ruxen_upstream_peer_failures_total{{{l}}} {}",
                c.failures
            );
        }
        header(
            &mut out,
            "ruxen_upstream_peer_response_seconds",
            "histogram",
            "Time from the start of an attempt until the upstream's response \
             was in (its head, for a streamed body).",
        );
        for (l, c, _) in &rows {
            let mut cumulative = 0;
            for (b, le) in BUCKETS_US.iter().enumerate() {
                cumulative += c.buckets[b];
                let _ = writeln!(
                    out,
                    "ruxen_upstream_peer_response_seconds_bucket{{{l},le=\"{}\"}} {cumulative}",
                    bound(*le)
                );
            }
            cumulative += c.buckets[BUCKETS_US.len()];
            let _ = writeln!(
                out,
                "ruxen_upstream_peer_response_seconds_bucket{{{l},le=\"+Inf\"}} {cumulative}"
            );
            let total_us = c.sum_us;
            let _ = writeln!(
                out,
                "ruxen_upstream_peer_response_seconds_sum{{{l}}} {}\n\
                 ruxen_upstream_peer_response_seconds_count{{{l}}} {cumulative}",
                seconds(total_us)
            );
        }
        header(
            &mut out,
            "ruxen_upstream_peer_up",
            "gauge",
            "1 if the peer can be picked, 0 if it is down or cooling off after \
             max_fails (without a zone, as the scraping worker sees it).",
        );
        for (l, _, up) in &rows {
            let _ = writeln!(out, "ruxen_upstream_peer_up{{{l}}} {}", *up as u8);
        }
    }

    zone_family(
        &mut out,
        "ruxen_limit_req_requests_total",
        "Requests by limit_req zone (the one that decided) and $limit_req_status.",
        &m.limit_req,
        |i| super::limit_req::status::text(i as u8 + 1),
    );
    zone_family(
        &mut out,
        "ruxen_limit_conn_requests_total",
        "Requests by limit_conn zone and $limit_conn_status.",
        &m.limit_conn,
        |i| super::limit_conn::status::text(i as u8 + 1),
    );
    zone_family(
        &mut out,
        "ruxen_cache_requests_total",
        "Requests by proxy_cache zone and $upstream_cache_status.",
        &m.caches,
        |i| crate::proxy_cache::CacheStatus::ALL[i].as_bytes(),
    );
    out
}

/// A counter family over zones, `status` naming each counter.
fn zone_family<const N: usize>(
    out: &mut String,
    name: &str,
    help: &str,
    zones: &[(String, &'static ZoneCounters<N>)],
    status: impl Fn(usize) -> &'static [u8],
) {
    if zones.is_empty() {
        return;
    }
    header(out, name, "counter", help);
    for (zone, counters) in zones {
        let mut l = String::from("zone=\"");
        escape(zone, &mut l);
        l.push('"');
        for i in 0..N {
            let status = String::from_utf8_lossy(status(i));
            let _ = writeln!(
                out,
                "{name}{{{l},status=\"{status}\"}} {}",
                counters.total(i)
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_values_are_escaped() {
        let mut out = String::new();
        escape("a\"b\\c\nd", &mut out);
        assert_eq!(out, r#"a\"b\\c\nd"#);
    }

    #[test]
    fn bucket_bounds_print_as_seconds() {
        let shown: Vec<String> = BUCKETS_US.iter().map(|&us| bound(us)).collect();
        assert_eq!(
            shown,
            [
                "0.005", "0.01", "0.025", "0.05", "0.1", "0.25", "0.5", "1", "2.5", "5", "10"
            ]
        );
        assert_eq!(seconds(1_234_567), "1.234567");
    }
}
