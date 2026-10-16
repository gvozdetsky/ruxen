//! `limit_req` (#94): nginx's leaky-bucket request limit
//! (ngx_http_limit_req_module), on zones shared by all worker threads.
//!
//! nginx keeps a zone in shared memory behind one mutex. Here a zone is a
//! heap value every worker reaches through `&'static`, split into shards by
//! the key's hash, each a `Mutex` around a hash map and an LRU list, so two
//! workers only wait for each other on the same shard. The capacity comes
//! from the configured size, as nginx's slab does (an entry per 128
//! bytes), and is fixed: a full shard evicts its least recently used entry,
//! nothing grows. The bucket arithmetic is nginx's, in thousandths of a
//! request.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::time::Instant;

use crate::config::ErrorLogLevel;

use super::PreparedValuePart;

/// Milliseconds on a process-wide monotonic clock (nginx's
/// `ngx_current_msec`).
fn now_ms() -> u64 {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    // Start at one minute so an entry's `last = 0` is never "now".
    EPOCH.get_or_init(Instant::now).elapsed().as_millis() as u64 + 60_000
}

const NIL: usize = usize::MAX;

struct Node {
    key: Box<[u8]>,
    /// Thousandths of a request over the rate, never below zero.
    excess: i64,
    /// When `excess` was last brought up to date (`now_ms`).
    last: u64,
    /// Requests between a lookup and their accounting: not evictable.
    count: u32,
    prev: usize,
    next: usize,
}

/// One shard: the entries in a slab, by key, and an LRU list through them
/// (`head` most recent).
struct Shard {
    map: HashMap<Box<[u8]>, usize>,
    nodes: Vec<Node>,
    free: Vec<usize>,
    head: usize,
    tail: usize,
    capacity: usize,
}

impl Shard {
    fn unlink(&mut self, i: usize) {
        let (prev, next) = (self.nodes[i].prev, self.nodes[i].next);
        match prev {
            NIL => self.head = next,
            p => self.nodes[p].next = next,
        }
        match next {
            NIL => self.tail = prev,
            n => self.nodes[n].prev = prev,
        }
    }

    fn push_front(&mut self, i: usize) {
        self.nodes[i].prev = NIL;
        self.nodes[i].next = self.head;
        if self.head != NIL {
            self.nodes[self.head].prev = i;
        }
        self.head = i;
        if self.tail == NIL {
            self.tail = i;
        }
    }

    fn remove(&mut self, i: usize) {
        self.unlink(i);
        let key = std::mem::take(&mut self.nodes[i].key);
        self.map.remove(&key);
        self.free.push(i);
    }

    /// ngx_http_limit_req_expire: from the LRU end, drop one or two
    /// entries idle for a minute whose bucket has drained; with `force`,
    /// drop the oldest one first whatever it holds. Entries in use stop it.
    fn expire(&mut self, rate: u64, force: bool, now: u64) {
        let mut n = if force { 0 } else { 1 };
        while n < 3 {
            let i = self.tail;
            if i == NIL || self.nodes[i].count != 0 {
                return;
            }
            if n != 0 {
                let ms = now.abs_diff(self.nodes[i].last);
                if ms < 60_000 {
                    return;
                }
                if self.nodes[i].excess - (rate * ms / 1000) as i64 > 0 {
                    return;
                }
            }
            n += 1;
            self.remove(i);
        }
    }
}

/// A `limit_req_zone`.
pub struct LimitReqZone {
    pub name: &'static str,
    pub key: &'static [PreparedValuePart],
    /// Requests per second × 1000.
    pub rate: u64,
    shards: &'static [Mutex<Shard>],
}

/// The zones' state, by name, for the next configuration: a reload that
/// declares a zone of the same name and size gets its state, as nginx
/// keeps a shared memory zone (`ngx_init_cycle`,
/// `ngx_http_limit_req_init_zone`) (#342).
static KEPT: Mutex<Vec<Kept>> = Mutex::new(Vec::new());

struct Kept {
    name: String,
    size: u64,
    key_text: String,
    shards: &'static [Mutex<Shard>],
}

impl LimitReqZone {
    /// The zone `limit_req_zone` declares, with the state of the one
    /// declared the same way before a reload. A different key for a kept
    /// zone is nginx's error.
    pub(crate) fn declare(
        name: &'static str,
        key: &'static [PreparedValuePart],
        key_text: &str,
        size: u64,
        rate: u64,
    ) -> Result<LimitReqZone, String> {
        // Unit tests prepare many configurations in one process.
        if cfg!(test) {
            return Ok(LimitReqZone::new(name, key, size, rate));
        }
        let mut kept = KEPT.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(k) = kept.iter().find(|k| k.name == name && k.size == size) {
            if k.key_text != key_text {
                return Err(format!(
                    "limit_req \"{name}\" uses the \"{key_text}\" key while previously it used the \"{}\" key",
                    k.key_text
                ));
            }
            // The rate isn't part of the state: the new one applies.
            return Ok(LimitReqZone {
                name,
                key,
                rate,
                shards: k.shards,
            });
        }
        let zone = LimitReqZone::new(name, key, size, rate);
        kept.retain(|k| k.name != name);
        kept.push(Kept {
            name: name.to_string(),
            size,
            key_text: key_text.to_string(),
            shards: zone.shards,
        });
        Ok(zone)
    }

    pub(crate) fn new(
        name: &'static str,
        key: &'static [PreparedValuePart],
        size: u64,
        rate: u64,
    ) -> Self {
        // Enough shards that workers rarely meet on one.
        const SHARDS: usize = 64;
        let entries = (size / 128).max(SHARDS as u64) as usize;
        let capacity = entries.div_ceil(SHARDS);
        let shards: Box<[Mutex<Shard>]> = (0..SHARDS)
            .map(|_| {
                Mutex::new(Shard {
                    map: HashMap::new(),
                    nodes: Vec::new(),
                    free: Vec::new(),
                    head: NIL,
                    tail: NIL,
                    capacity,
                })
            })
            .collect();
        LimitReqZone {
            name,
            key,
            rate,
            shards: Box::leak(shards),
        }
    }

    fn shard_of(&self, key: &[u8]) -> usize {
        use std::hash::{BuildHasher, Hasher};
        static STATE: OnceLock<std::collections::hash_map::RandomState> = OnceLock::new();
        let mut h = STATE.get_or_init(Default::default).build_hasher();
        h.write(key);
        (h.finish() as usize) % self.shards.len()
    }

    fn lock(&self, shard: usize) -> std::sync::MutexGuard<'_, Shard> {
        self.shards[shard].lock().unwrap_or_else(|e| e.into_inner())
    }

    /// ngx_http_limit_req_lookup. `account`: this is the request's last
    /// limit, so a pass is committed now; otherwise the entry is held
    /// (`count`) until `account` or `unlock`.
    fn lookup(&self, limit: &PreparedLimit, key: &[u8], account: bool) -> Lookup {
        let shard_no = self.shard_of(key);
        let mut shard = self.lock(shard_no);
        let now = now_ms();
        if let Some(&i) = shard.map.get(key) {
            shard.unlink(i);
            shard.push_front(i);
            let node = &mut shard.nodes[i];
            let ms = elapsed(now, node.last);
            let excess = (node.excess - (self.rate * ms / 1000) as i64 + 1000).max(0);
            if excess as u64 > limit.burst {
                return Lookup::Busy { excess };
            }
            if account {
                node.excess = excess;
                if ms != 0 {
                    node.last = now;
                }
                return Lookup::Ok { excess };
            }
            node.count += 1;
            return Lookup::Again {
                held: (shard_no, i),
            };
        }
        shard.expire(self.rate, false, now);
        if shard.map.len() >= shard.capacity {
            shard.expire(self.rate, true, now);
            if shard.map.len() >= shard.capacity {
                return Lookup::Error;
            }
        }
        let node = Node {
            key: key.into(),
            excess: 0,
            last: if account { now } else { 0 },
            count: if account { 0 } else { 1 },
            prev: NIL,
            next: NIL,
        };
        let i = match shard.free.pop() {
            Some(i) => {
                shard.nodes[i] = node;
                i
            }
            None => {
                shard.nodes.push(node);
                shard.nodes.len() - 1
            }
        };
        shard.map.insert(key.into(), i);
        shard.push_front(i);
        if account {
            Lookup::Ok { excess: 0 }
        } else {
            Lookup::Again {
                held: (shard_no, i),
            }
        }
    }
}

/// `now - last` as nginx takes it: a clock that went back more than a
/// minute counts as 1 ms, less as 0.
fn elapsed(now: u64, last: u64) -> u64 {
    let ms = now as i64 - last as i64;
    if ms < -60_000 { 1 } else { ms.max(0) as u64 }
}

enum Lookup {
    /// Over `burst`.
    Busy { excess: i64 },
    /// The zone is full and nothing could be evicted.
    Error,
    /// Passed, not yet committed: the entry held for `account`.
    Again { held: (usize, usize) },
    /// Passed and committed.
    Ok { excess: i64 },
}

/// One `limit_req` of a location.
#[derive(Debug, Clone, Copy)]
pub struct PreparedLimit {
    pub zone: &'static LimitReqZone,
    /// × 1000.
    pub burst: u64,
    /// × 1000.
    pub delay: u64,
}

impl std::fmt::Debug for LimitReqZone {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LimitReqZone({})", self.name)
    }
}

/// A location's resolved `limit_req*` settings.
#[derive(Debug)]
pub struct PreparedLimitReq {
    pub limits: &'static [PreparedLimit],
    pub status: u16,
    pub log_level: ErrorLogLevel,
    /// One level below `log_level` (`info` stays `info`).
    pub delay_log_level: ErrorLogLevel,
    pub dry_run: bool,
}

/// `$limit_req_status`, as `RewriteState::limit_req_status` keeps it.
pub mod status {
    pub const PASSED: u8 = 1;
    pub const DELAYED: u8 = 2;
    pub const REJECTED: u8 = 3;
    pub const DELAYED_DRY_RUN: u8 = 4;
    pub const REJECTED_DRY_RUN: u8 = 5;

    pub fn text(s: u8) -> &'static [u8] {
        match s {
            PASSED => b"PASSED",
            DELAYED => b"DELAYED",
            REJECTED => b"REJECTED",
            DELAYED_DRY_RUN => b"DELAYED_DRY_RUN",
            REJECTED_DRY_RUN => b"REJECTED_DRY_RUN",
            _ => b"",
        }
    }
}

/// What the limits say about a request.
pub(crate) struct Verdict {
    /// `$limit_req_status`; 0 when no limit applied (all keys empty).
    pub status: u8,
    /// Answer with `limit_req_status`.
    pub reject: bool,
    /// Hold the request this long first.
    pub delay_ms: u64,
    /// The line for the error log, and its level.
    pub log: Option<(ErrorLogLevel, String)>,
}

/// ngx_http_limit_req_handler over the location's limits, with each zone's
/// key rendered by `render`.
pub(crate) fn check(
    lr: &PreparedLimitReq,
    mut render: impl FnMut(&LimitReqZone) -> Vec<u8>,
) -> Verdict {
    let mut held: Vec<(usize, (usize, usize))> = Vec::new();
    let mut excess: i64 = 0;
    let mut current: Option<usize> = None;
    let mut outcome = None;
    let last = lr.limits.len() - 1;
    for (n, limit) in lr.limits.iter().enumerate() {
        let key = render(limit.zone);
        if key.is_empty() || key.len() > 65_535 {
            continue;
        }
        current = Some(n);
        match limit.zone.lookup(limit, &key, n == last) {
            Lookup::Again { held: h } => {
                excess = 0;
                held.push((n, h));
                outcome = Some(true);
            }
            Lookup::Ok { excess: e } => {
                excess = e;
                outcome = Some(true);
                break;
            }
            Lookup::Busy { excess: e } => {
                excess = e;
                outcome = Some(false);
                break;
            }
            Lookup::Error => {
                unlock(lr, &held);
                return reject(lr, None, 0);
            }
        }
    }
    let (Some(passed), Some(n)) = (outcome, current) else {
        return Verdict {
            status: 0,
            reject: false,
            delay_ms: 0,
            log: None,
        };
    };
    if !passed {
        unlock(lr, &held);
        return reject(lr, Some(n), excess);
    }
    // ngx_http_limit_req_account: commit the held entries and take the
    // longest delay any limit asks for.
    let mut limit_n = n;
    let mut max_delay = delay_for(&lr.limits[n], excess);
    for &(i, (shard, node)) in held.iter().rev() {
        let limit = &lr.limits[i];
        let zone = limit.zone;
        let mut s = zone.lock(shard);
        let now = now_ms();
        let entry = &mut s.nodes[node];
        let ms = elapsed(now, entry.last);
        let e = (entry.excess - (zone.rate * ms / 1000) as i64 + 1000).max(0);
        if ms != 0 {
            entry.last = now;
        }
        entry.excess = e;
        entry.count = entry.count.saturating_sub(1);
        drop(s);
        let d = delay_for(limit, e);
        if d > max_delay {
            max_delay = d;
            excess = e;
            limit_n = i;
        }
    }
    if max_delay == 0 {
        return Verdict {
            status: status::PASSED,
            reject: false,
            delay_ms: 0,
            log: None,
        };
    }
    let line = format!(
        "delaying request{}, excess: {}.{:03}, by zone \"{}\"",
        if lr.dry_run { ", dry run" } else { "" },
        excess / 1000,
        excess % 1000,
        lr.limits[limit_n].zone.name
    );
    Verdict {
        status: if lr.dry_run {
            status::DELAYED_DRY_RUN
        } else {
            status::DELAYED
        },
        reject: false,
        delay_ms: if lr.dry_run { 0 } else { max_delay },
        log: Some((lr.delay_log_level, line)),
    }
}

fn delay_for(limit: &PreparedLimit, excess: i64) -> u64 {
    if excess as u64 <= limit.delay {
        0
    } else {
        (excess as u64 - limit.delay) * 1000 / limit.zone.rate
    }
}

/// ngx_http_limit_req_unlock: release the entries held for this request.
fn unlock(lr: &PreparedLimitReq, held: &[(usize, (usize, usize))]) {
    for &(i, (shard, node)) in held {
        let mut s = lr.limits[i].zone.lock(shard);
        let entry = &mut s.nodes[node];
        entry.count = entry.count.saturating_sub(1);
    }
}

/// Over a limit (`n`, with `excess`), or no room in a zone (`None`).
fn reject(lr: &PreparedLimitReq, n: Option<usize>, excess: i64) -> Verdict {
    let log = n.map(|n| {
        (
            lr.log_level,
            format!(
                "limiting requests{}, excess: {}.{:03} by zone \"{}\"",
                if lr.dry_run { ", dry run" } else { "" },
                excess / 1000,
                excess % 1000,
                lr.limits[n].zone.name
            ),
        )
    });
    Verdict {
        status: if lr.dry_run {
            status::REJECTED_DRY_RUN
        } else {
            status::REJECTED
        },
        reject: !lr.dry_run,
        delay_ms: 0,
        log,
    }
}

thread_local! {
    /// Set while a delayed request is processed again (`resume_after_delay`).
    static RESUMED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// The worker processes a delayed request again after its delay: limit_req
/// then lets it pass as DELAYED instead of counting it twice.
pub(crate) fn resume_after_delay(on: bool) {
    RESUMED.with(|r| r.set(on));
}

/// The pre-access phase's `limit_req` for one request: the keys rendered
/// as the request stands after the rewrite phase, the verdict logged with
/// the request's context, and `$limit_req_status` noted. `Some` response:
/// the rejection (`limit_req_status`), to go through the location's
/// error_page. The delay is the caller's to keep.
#[allow(clippy::too_many_arguments)]
#[cold]
#[inline(never)]
pub(crate) fn run(
    http: &'static super::PreparedHttp,
    server: &'static super::PreparedServer,
    req: &crate::phase::RequestCtx<'_>,
    uri: &[u8],
    current_args: Option<&[u8]>,
    rewrite_state: &mut super::RewriteState,
    captures: Option<&crate::phase::ServerNameCaptures>,
    lr: &PreparedLimitReq,
    log: &crate::phase::LogMeta,
    server_name: &'static [u8],
    server_header: &'static [u8],
) -> (Option<crate::phase::Response>, u64) {
    if RESUMED.with(|r| r.replace(false)) {
        rewrite_state.limit_req_status = status::DELAYED;
        return (None, 0);
    }
    let verdict = {
        let args = current_args.unwrap_or_else(|| super::request_args(req.path));
        let captures_slice: &[(&'static str, Vec<u8>)] = match captures {
            Some(caps) => caps.names.as_slice(),
            None => &[],
        };
        let ctx =
            super::build_rewrite_ctx(http, server, req, uri, args, captures_slice, rewrite_state);
        check(lr, |zone| {
            let mut key = Vec::with_capacity(16);
            super::render_parts(zone.key, &ctx, &mut key);
            key
        })
    };
    rewrite_state.limit_req_status = verdict.status;
    if let Some((level, line)) = &verdict.log {
        super::write_error_log(
            log.error_logs,
            *level,
            &super::ErrorLogRequest::new(req, server_name),
            line.as_bytes(),
            None,
        );
    }
    if verdict.reject {
        let body = format!("{}\n", crate::http::reason_phrase(lr.status));
        let response = crate::phase::Response::Owned(crate::http::error_response_for_method(
            lr.status,
            &body,
            req.method,
            server_header,
        ));
        return (Some(response), 0);
    }
    (None, verdict.delay_ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zone(rate_per_s: u64, size: u64) -> &'static LimitReqZone {
        Box::leak(Box::new(LimitReqZone::new(
            "z",
            &[],
            size,
            rate_per_s * 1000,
        )))
    }

    fn limits(list: Vec<PreparedLimit>, dry_run: bool) -> PreparedLimitReq {
        PreparedLimitReq {
            limits: Box::leak(list.into_boxed_slice()),
            status: 503,
            log_level: ErrorLogLevel::Error,
            delay_log_level: ErrorLogLevel::Warn,
            dry_run,
        }
    }

    fn limit(zone: &'static LimitReqZone, burst: u64, delay: u64) -> PreparedLimit {
        PreparedLimit {
            zone,
            burst: burst * 1000,
            delay: delay * 1000,
        }
    }

    #[test]
    fn burst_then_reject_with_nodelay() {
        let lr = limits(
            vec![limit(zone(1, 1 << 20), 2, u64::MAX / 1000 / 1000)],
            false,
        );
        let statuses: Vec<(u8, bool)> = (0..5)
            .map(|_| {
                let v = check(&lr, |_| b"k".to_vec());
                (v.status, v.reject)
            })
            .collect();
        assert_eq!(
            statuses,
            [
                (status::PASSED, false),
                (status::PASSED, false),
                (status::PASSED, false),
                (status::REJECTED, true),
                (status::REJECTED, true)
            ]
        );
        // Another key has its own bucket.
        assert_eq!(check(&lr, |_| b"other".to_vec()).status, status::PASSED);
        // An empty key isn't counted at all.
        assert_eq!(check(&lr, |_| Vec::new()).status, 0);
    }

    #[test]
    fn excess_within_burst_is_delayed() {
        // 2 r/s, burst 3, no nodelay: the second request waits ~0.5 s.
        let lr = limits(vec![limit(zone(2, 1 << 20), 3, 0)], false);
        assert_eq!(check(&lr, |_| b"k".to_vec()).delay_ms, 0);
        let v = check(&lr, |_| b"k".to_vec());
        assert_eq!(v.status, status::DELAYED);
        assert!((450..=500).contains(&v.delay_ms), "{}", v.delay_ms);
        // Dry run: logged and marked, neither delayed nor rejected.
        let dry = limits(vec![limit(zone(1, 1 << 20), 0, 0)], true);
        assert_eq!(check(&dry, |_| b"k".to_vec()).status, status::PASSED);
        let v = check(&dry, |_| b"k".to_vec());
        assert_eq!((v.status, v.reject), (status::REJECTED_DRY_RUN, false));
    }

    #[test]
    fn every_limit_is_checked_and_a_rejection_holds_nothing() {
        let wide = zone(100, 1 << 20);
        let narrow = zone(1, 1 << 20);
        let lr = limits(vec![limit(wide, 10, 10), limit(narrow, 0, 0)], false);
        assert_eq!(check(&lr, |_| b"k".to_vec()).status, status::PASSED);
        // The narrow one rejects; the wide one's entry isn't left held.
        let v = check(&lr, |_| b"k".to_vec());
        assert!(v.reject);
        let shard = wide.lock(wide.shard_of(b"k"));
        let i = shard.map[&b"k"[..]];
        assert_eq!(shard.nodes[i].count, 0);
    }

    #[test]
    fn a_full_zone_evicts_its_oldest_entry() {
        // The smallest zone: one entry per shard.
        let z = zone(1, 64 * 128);
        let lr = limits(vec![limit(z, 0, 0)], false);
        for i in 0..1000u32 {
            assert!(!check(&lr, |_| i.to_be_bytes().to_vec()).reject);
        }
        let entries: usize = z.shards.iter().map(|s| s.lock().unwrap().map.len()).sum();
        assert!(entries <= 64, "{entries}");
    }
}
