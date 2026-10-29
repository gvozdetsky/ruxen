//! `server NAME resolve [service=…]` in an upstream with a `zone` (#597),
//! as nginx 1.27.3+ re-resolves such names (ngx_http_upstream_zone_module.c):
//!
//! - One worker asks the upstream's resolver for each name, again when the
//!   answer's TTL (or `valid=`) ends, plus a second
//!   (ngx_http_upstream_zone_resolve_handler). Peers whose address is no
//!   longer in the answer go; new ones come with the `server` line's
//!   parameters and port. An error keeps the peers and asks again after
//!   `resolver_timeout` (1 s at least); a name that doesn't exist (or has
//!   no address) leaves no peers.
//! - With `service=`, the SRV records give the targets and ports: the
//!   lowest priority's addresses are the server's peers, the others backup
//!   peers (dropped where the balancer has no backup tier), each with the
//!   record's weight unless the line sets one, named after its target.
//! - The peer list is a whole `PreparedUpstream` (a version) that requests
//!   take when they start (`UpstreamRef::current`), so the request path
//!   keeps indexing a fixed slice; a request keeps the version it started
//!   with. Peers that stay keep their failure state; keep-alive
//!   connections move to the new version in each worker.
//! - A version is freed once no worker holds it. A worker holds the one
//!   it last took (its keep-alive pool and balancer state are keyed by
//!   it) and those its requests still use; the holds are counted per
//!   worker, and in the version per worker. Each name's peers are kept
//!   sorted, so an answer in another order is the same list.
//! - A reload starts from the peers the last generation had for the same
//!   zone, upstream, name and service (ngx_http_upstream_zone_preresolve),
//!   with the new `server` line's port and parameters.

use std::cell::RefCell;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use crate::resolver::{Failure, SrvAddr};
use crate::upstream::{HashLb, Lb, PeerShared};
use crate::worker::{PeerAddr, PreparedHttp, PreparedPeer, PreparedUpstream, RuntimeState};

/// A `server … resolve` line.
struct Host {
    /// The name as the resolver asks it.
    name: Box<[u8]>,
    /// `service=`, as written.
    service: Option<Box<[u8]>>,
    port: u16,
    /// What each of its addresses becomes, but for the address.
    template: PreparedPeer,
}

/// `PreparedUpstream::dynamic`: the upstream a peer list (a version) is
/// of, and how many workers hold it. The configured upstream has one too,
/// held for good.
pub struct Version {
    dynamic: &'static Dynamic,
    holds: AtomicUsize,
}

impl std::fmt::Debug for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.dynamic.fmt(f)
    }
}

impl Version {
    /// The version requests take now, held by this worker.
    pub(crate) fn current(&self) -> &'static PreparedUpstream {
        self.dynamic.current()
    }

    /// The version this worker took last.
    pub(crate) fn seen(&self) -> &'static PreparedUpstream {
        self.dynamic.seen()
    }
}

fn holds(version: &PreparedUpstream) -> &AtomicUsize {
    &version.dynamic.expect("a version").holds
}

/// An upstream with `resolve` servers: its peer list changes at run time.
pub struct Dynamic {
    zone: &'static str,
    /// The upstream's settings and its static peers.
    template: PreparedUpstream,
    hosts: Box<[Host]>,
    resolver: &'static crate::resolver::Resolver,
    timeout: Duration,
    /// When each host is first asked: at once, or when the addresses kept
    /// from the last generation expire.
    first: Box<[Instant]>,
    /// The version requests take now.
    current: AtomicPtr<PreparedUpstream>,
    /// Workers between loading `current` and holding it.
    loading: AtomicUsize,
    /// Whether a worker resolves for it already (nginx: worker 0).
    claimed: AtomicBool,
    state: Mutex<State>,
    /// Metrics slots for its peers (#879), with `ruxen_metrics`.
    pool: Option<&'static crate::worker::metrics::PeerPool>,
}

impl std::fmt::Debug for Dynamic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Dynamic")
            .field("upstream", &String::from_utf8_lossy(self.template.name))
            .finish_non_exhaustive()
    }
}

/// A peer a name resolved to.
#[derive(Debug, Clone)]
struct Resolved {
    host: usize,
    addr: SocketAddr,
    backup: bool,
    weight: u32,
    /// An SRV target: the peer's `server` name.
    server: Option<Box<[u8]>>,
}

impl Resolved {
    /// The order each name's peers are kept in.
    fn order(&self) -> (usize, bool, SocketAddr, Option<&[u8]>, u32) {
        (
            self.host,
            self.backup,
            self.addr,
            self.server.as_deref(),
            self.weight,
        )
    }
}

/// A peer an answer gives.
struct Candidate<'a> {
    addr: SocketAddr,
    backup: bool,
    weight: u32,
    server: Option<&'a [u8]>,
}

struct State {
    /// The resolved peers, each name's sorted.
    resolved: Vec<Resolved>,
    /// The versions not freed yet, each with what it owns.
    versions: Vec<(&'static PreparedUpstream, crate::arena::Owner)>,
    owner: crate::arena::Owner,
}

/// A server line of the configuration being prepared.
pub(crate) struct HostConf {
    pub name: String,
    pub service: Option<String>,
    pub port: u16,
    pub template: PreparedPeer,
}

impl Dynamic {
    /// The upstream `template` describes (with its static peers), whose
    /// `hosts` are resolved at run time.
    pub(crate) fn prepare(
        template: PreparedUpstream,
        zone: &str,
        hosts: Vec<HostConf>,
        resolver: &'static crate::resolver::Resolver,
        timeout: Duration,
        pool: Option<&'static crate::worker::metrics::PeerPool>,
    ) -> &'static PreparedUpstream {
        let now = Instant::now();
        let zone: &'static str = crate::arena::leak(zone.into());
        let hosts: Box<[Host]> = hosts
            .into_iter()
            .map(|h| Host {
                name: crate::resolver::normalize(h.name.as_bytes()),
                service: h.service.map(|s| s.into_bytes().into_boxed_slice()),
                port: h.port,
                template: h.template,
            })
            .collect();
        let backup_tier = has_backup_tier(&template);
        let mut resolved = Vec::new();
        let mut first = Vec::with_capacity(hosts.len());
        for (i, host) in hosts.iter().enumerate() {
            let Some((peers, valid)) = kept(zone, template.name, host) else {
                first.push(now);
                continue;
            };
            first.push(valid.max(now));
            let t = &host.template;
            for p in peers {
                resolved.push(match p.server {
                    None => Resolved {
                        host: i,
                        addr: SocketAddr::new(p.addr.ip(), host.port),
                        backup: t.backup,
                        weight: t.weight,
                        server: None,
                    },
                    Some(_) if p.backup && !t.backup && !backup_tier => continue,
                    Some(server) => Resolved {
                        host: i,
                        addr: p.addr,
                        backup: p.backup,
                        weight: if t.weight != 1 { t.weight } else { p.weight },
                        server: Some(server),
                    },
                });
            }
        }
        resolved.sort_by(|a, b| a.order().cmp(&b.order()));
        let dynamic: &'static Dynamic = crate::arena::leak(Box::new(Dynamic {
            zone,
            template,
            hosts,
            resolver,
            timeout,
            first: first.into(),
            current: AtomicPtr::new(std::ptr::null_mut()),
            loading: AtomicUsize::new(0),
            claimed: AtomicBool::new(false),
            pool,
            state: Mutex::new(State {
                resolved,
                versions: Vec::new(),
                // SAFETY: inside `dynamic`, which the generation's arena
                // frees with the rest of its configuration.
                owner: unsafe { crate::arena::Owner::new() },
            }),
        }));
        let mut state = dynamic.lock();
        dynamic.publish(&mut state);
        // Held for good: it never goes.
        let version = state.owner.leak(Box::new(Version {
            dynamic,
            holds: AtomicUsize::new(1),
        }));
        state.owner.leak(Box::new(PreparedUpstream {
            dynamic: Some(version),
            ..dynamic.template
        }))
    }

    /// The version requests take now, held by this worker; the worker
    /// moves to it if it is new.
    #[inline(never)]
    pub(crate) fn current(&'static self) -> &'static PreparedUpstream {
        let now = self.current.load(Ordering::Acquire);
        let seen = SEEN.with(|seen| seen.borrow().get(&key(self)).copied());
        let version = match seen {
            Some(seen) if std::ptr::eq(seen, now) => seen,
            _ => self.switch(),
        };
        hold(version);
        version
    }

    /// The version this worker took last (its pool's), or the current one.
    pub(crate) fn seen(&'static self) -> &'static PreparedUpstream {
        match SEEN.with(|seen| seen.borrow().get(&key(self)).copied()) {
            Some(seen) => seen,
            None => self.switch(),
        }
    }

    /// This worker takes the current version.
    #[cold]
    #[inline(never)]
    fn switch(&'static self) -> &'static PreparedUpstream {
        // Loaded and held under `loading`, so that `sweep` doesn't free
        // it in between.
        self.loading.fetch_add(1, Ordering::SeqCst);
        // SAFETY: set by `publish` before the upstream is handed out, and
        // not freed while `loading` counts this worker.
        let version = unsafe { &*self.current.load(Ordering::SeqCst) };
        let first = HELD.with(|held| {
            let mut held = held.borrow_mut();
            let n = held.entry(key(version)).or_insert(0);
            *n += 1;
            *n == 1
        });
        if first {
            holds(version).fetch_add(1, Ordering::SeqCst);
        }
        self.loading.fetch_sub(1, Ordering::SeqCst);
        let old = SEEN.with(|seen| seen.borrow_mut().insert(key(self), version));
        if let Some(old) = old {
            crate::upstream::switch_version(old, version);
            release(old);
        }
        version
    }

    fn version(&self) -> &'static PreparedUpstream {
        // SAFETY: set by `publish` before the upstream is handed out; the
        // current version isn't freed.
        unsafe { &*self.current.load(Ordering::Acquire) }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Make the version for the current peers current: the one that has
    /// them already, or a new one.
    fn publish(&'static self, state: &mut State) {
        // The peers, and the SRV target each is named after.
        let mut wanted = Vec::with_capacity(self.template.peers.len() + state.resolved.len());
        for backup in [false, true] {
            wanted.extend(
                self.template
                    .peers
                    .iter()
                    .filter(|p| p.backup == backup)
                    .map(|p| (*p, None)),
            );
            wanted.extend(
                state
                    .resolved
                    .iter()
                    .filter(|r| r.backup == backup)
                    .map(|r| {
                        let peer = PreparedPeer {
                            addr: PeerAddr::Inet(r.addr),
                            weight: r.weight,
                            backup: r.backup,
                            ..self.hosts[r.host].template
                        };
                        (peer, r.server.as_deref())
                    }),
            );
        }
        if let Some((version, _)) = state.versions.iter().find(|(v, _)| {
            v.peers.len() == wanted.len()
                && v.peers
                    .iter()
                    .zip(&wanted)
                    .all(|(a, (b, name))| same_peer(a, b, *name))
        }) {
            self.current
                .store(std::ptr::from_ref(*version).cast_mut(), Ordering::SeqCst);
            self.sweep(state);
            return;
        }
        // SAFETY: kept in `state.versions` until the version is freed,
        // when nothing uses it (`sweep`), or with `self`.
        let mut owner = unsafe { crate::arena::Owner::new() };
        let peers: Vec<PreparedPeer> = wanted
            .into_iter()
            .map(|(peer, name)| match name {
                None => peer,
                Some(name) => PreparedPeer {
                    display: owner.leak(name.into()),
                    ..peer
                },
            })
            .collect();
        let before = (!self.current.load(Ordering::Acquire).is_null()).then(|| self.version());
        let shared: Box<[PeerShared]> = peers
            .iter()
            .map(|p| {
                let slot = PeerShared::default();
                // A peer that stays keeps its failures.
                if let Some(before) = before
                    && let Some(i) = before.peers.iter().position(|b| same_peer(b, p, None))
                    && let Some(old) = before.shared
                {
                    slot.carry(&old[i]);
                }
                slot
            })
            .collect();
        let peers: &'static [PreparedPeer] = owner.leak(peers.into_boxed_slice());
        let lb = match self.template.lb {
            Lb::Hash(h) if h.ring.is_some() => Lb::Hash(owner.leak(Box::new(HashLb {
                key: h.key,
                ring: Some(crate::upstream::chash_ring(peers)),
            }))),
            lb => lb,
        };
        let shared: &'static [PeerShared] = owner.leak(shared);
        let metrics = self.pool.map(|pool| -> &'static [u32] {
            let slots: Box<[u32]> = peers
                .iter()
                .map(|p| pool.slot(&p.addr.to_string()))
                .collect();
            owner.leak(slots)
        });
        let tag: &'static Version = owner.leak(Box::new(Version {
            dynamic: self,
            holds: AtomicUsize::new(0),
        }));
        let version: &'static PreparedUpstream = owner.leak(Box::new(PreparedUpstream {
            peers,
            lb,
            shared: Some(shared),
            dynamic: Some(tag),
            metrics,
            ..self.template
        }));
        state.versions.push((version, owner));
        self.current
            .store(std::ptr::from_ref(version).cast_mut(), Ordering::SeqCst);
        self.sweep(state);
    }

    /// Free the versions no worker holds or is about to.
    fn sweep(&self, state: &mut State) {
        let current = self.current.load(Ordering::SeqCst);
        if self.loading.load(Ordering::SeqCst) != 0 {
            // The next sweep frees them.
            return;
        }
        state
            .versions
            .retain(|(v, _)| std::ptr::eq(*v, current) || holds(v).load(Ordering::SeqCst) != 0);
        // An address no list has any more gives its slot up.
        if let Some(pool) = self.pool {
            pool.keep(|slot| {
                state
                    .versions
                    .iter()
                    .any(|(v, _)| v.metrics.is_some_and(|m| m.contains(&slot)))
            });
        }
    }

    /// The number of versions not freed, for tests.
    #[cfg(test)]
    fn live(&self) -> usize {
        self.lock().versions.len()
    }

    /// Host `h`'s new addresses.
    fn apply(&'static self, h: usize, addrs: &[IpAddr], valid: Instant) {
        let host = &self.hosts[h];
        let candidates = addrs
            .iter()
            .map(|&ip| Candidate {
                addr: SocketAddr::new(ip, host.port),
                backup: host.template.backup,
                weight: host.template.weight,
                server: None,
            })
            .collect();
        self.update(h, candidates, valid);
    }

    /// Host `h`'s service resolved to `addrs` (ngx_resolver_report_srv's
    /// list): the lowest priority are its peers, the others backup ones.
    fn apply_service(&'static self, h: usize, addrs: &[SrvAddr], valid: Instant) {
        let host = &self.hosts[h];
        let t = &host.template;
        let lowest = addrs.iter().map(|a| a.priority).min();
        let backup_tier = has_backup_tier(&self.template);
        let candidates = addrs
            .iter()
            .filter_map(|a| {
                let low = Some(a.priority) != lowest;
                if low && (t.backup || !backup_tier) {
                    return None;
                }
                Some(Candidate {
                    addr: a.addr,
                    backup: t.backup || low,
                    weight: if t.weight != 1 {
                        t.weight
                    } else {
                        u32::from(a.weight)
                    },
                    server: Some(&a.name),
                })
            })
            .collect();
        self.update(h, candidates, valid);
    }

    /// Match host `h`'s peers against an answer as
    /// ngx_http_upstream_zone_resolve_handler does: a peer stays for a
    /// peer of the answer not taken yet, goes otherwise; the rest of the
    /// answer is added, and the name's peers sorted.
    fn update(&'static self, h: usize, candidates: Vec<Candidate<'_>>, valid: Instant) {
        let host = &self.hosts[h];
        // A record's weight counts only when the line doesn't set one.
        let weighted = host.service.is_some() && host.template.weight == 1;
        let mut taken = vec![false; candidates.len()];
        let mut state = self.lock();
        state.resolved.retain(|r| {
            if r.host != h {
                return true;
            }
            let found = candidates.iter().enumerate().position(|(i, c)| {
                !taken[i]
                    && c.addr == r.addr
                    && c.backup == r.backup
                    && c.server == r.server.as_deref()
                    && (!weighted || c.weight == r.weight)
            });
            match found {
                Some(i) => {
                    taken[i] = true;
                    true
                }
                None => false,
            }
        });
        for (c, taken) in candidates.iter().zip(taken) {
            if taken {
                continue;
            }
            state.resolved.push(Resolved {
                host: h,
                addr: c.addr,
                backup: c.backup,
                weight: c.weight,
                server: c.server.map(Box::from),
            });
        }
        state.resolved.sort_by(|a, b| a.order().cmp(&b.order()));
        self.publish(&mut state);
        let peers: Vec<KeptPeer> = state
            .resolved
            .iter()
            .filter(|r| r.host == h)
            .map(|r| KeptPeer {
                addr: r.addr,
                backup: r.backup,
                weight: r.weight,
                server: r.server.clone(),
            })
            .collect();
        drop(state);
        keep(self.zone, self.template.name, host, peers, valid);
    }
}

fn key<T>(p: &T) -> usize {
    std::ptr::from_ref(p) as usize
}

thread_local! {
    /// The version of each resolved upstream this worker took last.
    static SEEN: RefCell<HashMap<usize, &'static PreparedUpstream, crate::upstream::FxBuild>> =
        RefCell::new(HashMap::default());
    /// This worker's holds of each version: its requests', and one for
    /// the version in `SEEN`.
    static HELD: RefCell<HashMap<usize, u32, crate::upstream::FxBuild>> =
        RefCell::new(HashMap::default());
}

/// One more hold of `version`, which this worker holds already.
pub(crate) fn hold(version: &PreparedUpstream) {
    let _ = HELD.try_with(|held| {
        if let Some(n) = held.borrow_mut().get_mut(&key(version)) {
            *n += 1;
        }
    });
}

/// One hold of `version` less; the last of this worker's lets it go: its
/// pool moves to the version the worker took last.
pub(crate) fn release(version: &PreparedUpstream) {
    let last = HELD
        .try_with(|held| {
            let mut held = held.borrow_mut();
            let Some(n) = held.get_mut(&key(version)) else {
                return false;
            };
            *n -= 1;
            if *n != 0 {
                return false;
            }
            held.remove(&key(version));
            true
        })
        .unwrap_or(false);
    if last {
        let_go(version);
    }
}

#[cold]
#[inline(never)]
fn let_go(version: &PreparedUpstream) {
    let Some(tag) = version.dynamic else {
        return;
    };
    let dynamic = tag.dynamic;
    if let Ok(Some(seen)) = SEEN.try_with(|seen| seen.borrow().get(&key(dynamic)).copied()) {
        crate::upstream::switch_version(version, seen);
    }
    if tag.holds.fetch_sub(1, Ordering::SeqCst) == 1 {
        dynamic.sweep(&mut dynamic.lock());
    }
}

/// Whether `a` is `b` (named `name` instead, an SRV target).
fn same_peer(a: &PreparedPeer, b: &PreparedPeer, name: Option<&[u8]>) -> bool {
    a.addr == b.addr
        && a.display == name.unwrap_or(b.display)
        && a.weight == b.weight
        && a.max_fails == b.max_fails
        && a.fail_timeout_ms == b.fail_timeout_ms
        && a.max_conns == b.max_conns
        && a.down == b.down
        && a.backup == b.backup
}

/// Whether the balancer keeps backup peers, where the lower priorities of
/// a service go (nginx's `peers->next`).
fn has_backup_tier(upstream: &PreparedUpstream) -> bool {
    matches!(upstream.lb, Lb::RoundRobin | Lb::LeastConn) || upstream.peers.iter().any(|p| p.backup)
}

/// The peers a generation last had for a name, for the next one.
struct Kept {
    zone: Box<str>,
    upstream: Box<[u8]>,
    name: Box<[u8]>,
    service: Option<Box<[u8]>>,
    backup: bool,
    peers: Vec<KeptPeer>,
    valid: Instant,
}

#[derive(Clone)]
struct KeptPeer {
    addr: SocketAddr,
    backup: bool,
    weight: u32,
    server: Option<Box<[u8]>>,
}

static KEPT: Mutex<Vec<Kept>> = Mutex::new(Vec::new());

fn kept_list() -> std::sync::MutexGuard<'static, Vec<Kept>> {
    KEPT.lock().unwrap_or_else(|e| e.into_inner())
}

fn kept_matches(k: &Kept, zone: &str, upstream: &[u8], host: &Host) -> bool {
    *k.zone == *zone
        && *k.upstream == *upstream
        && k.name == host.name
        && k.service == host.service
        && k.backup == host.template.backup
}

fn kept(zone: &str, upstream: &[u8], host: &Host) -> Option<(Vec<KeptPeer>, Instant)> {
    kept_list()
        .iter()
        .find(|k| kept_matches(k, zone, upstream, host))
        .map(|k| (k.peers.clone(), k.valid))
}

fn keep(zone: &str, upstream: &[u8], host: &Host, peers: Vec<KeptPeer>, valid: Instant) {
    let mut list = kept_list();
    match list
        .iter_mut()
        .find(|k| kept_matches(k, zone, upstream, host))
    {
        Some(k) => {
            k.peers = peers;
            k.valid = valid;
        }
        None => list.push(Kept {
            zone: zone.into(),
            upstream: upstream.into(),
            name: host.name.clone(),
            service: host.service.clone(),
            backup: host.template.backup,
            peers,
            valid,
        }),
    }
}

/// In a worker that has just started: resolve the names of every upstream
/// no other worker of the generation looks after yet.
pub(crate) fn start(http: &'static PreparedHttp, state: &'static RuntimeState) {
    for upstream in http.upstreams.values() {
        let Some(dynamic) = upstream.dynamic.map(|v| v.dynamic) else {
            continue;
        };
        if dynamic.claimed.swap(true, Ordering::AcqRel) {
            continue;
        }
        for h in 0..dynamic.hosts.len() {
            crate::worker::spawn_contained(
                "an upstream name resolution",
                || {},
                keep_resolving(dynamic, h, state),
            );
        }
    }
}

/// A second past the answer's end, as nginx's timer.
const AFTER_VALID: Duration = Duration::from_secs(1);

/// nginx's default `valid` of an error (ngx_resolver.c).
const ERROR_VALID: Duration = Duration::from_secs(10);

async fn keep_resolving(dynamic: &'static Dynamic, h: usize, state: &'static RuntimeState) {
    let host = &dynamic.hosts[h];
    let name = String::from_utf8_lossy(&host.name);
    let mut at = dynamic.first[h];
    loop {
        monoio::time::sleep(at.saturating_duration_since(Instant::now())).await;
        if state.is_shutting_down() {
            return;
        }
        let now = Instant::now();
        let resolver = dynamic.resolver;
        let failure = match &host.service {
            None => {
                match crate::resolver::resolve_valid(resolver, &host.name, dynamic.timeout).await {
                    Ok((addrs, valid)) => {
                        dynamic.apply(h, &addrs, valid);
                        at = valid.max(now) + AFTER_VALID;
                        continue;
                    }
                    Err(failure) => {
                        crate::resolver::log(&format!("{name} could not be resolved ({failure})"));
                        failure
                    }
                }
            }
            Some(service) => {
                let service_text = String::from_utf8_lossy(service);
                let resolved = crate::resolver::resolve_service(
                    resolver,
                    &host.name,
                    service,
                    dynamic.timeout,
                )
                .await;
                let log_targets = |failed: &[(Box<[u8]>, Failure)]| {
                    for (target, failure) in failed {
                        crate::resolver::log(&format!(
                            "{} could not be resolved ({failure}) while resolving service \
                             {service_text} of {name}",
                            String::from_utf8_lossy(target)
                        ));
                    }
                };
                match resolved {
                    Ok(found) => {
                        log_targets(&found.failed);
                        dynamic.apply_service(h, &found.addrs, found.valid);
                        at = found.valid.max(now) + AFTER_VALID;
                        continue;
                    }
                    Err((failure, failed)) => {
                        log_targets(&failed);
                        crate::resolver::log(&format!(
                            "service {service_text} of {name} could not be resolved ({failure})"
                        ));
                        failure
                    }
                }
            }
        };
        at = if failure.0 == crate::resolver::NXDOMAIN {
            let valid = now + resolver.valid.unwrap_or(ERROR_VALID);
            dynamic.update(h, Vec::new(), valid);
            valid + AFTER_VALID
        } else {
            now + dynamic.timeout.max(Duration::from_secs(1))
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(addr: &str, backup: bool) -> PreparedPeer {
        PreparedPeer {
            addr: PeerAddr::Inet(addr.parse().unwrap()),
            display: b"x",
            weight: 1,
            max_fails: 1,
            fail_timeout_ms: 10_000,
            max_conns: 0,
            down: false,
            backup,
        }
    }

    fn upstream(zone: &str, port: u16) -> &'static PreparedUpstream {
        upstream_with(zone, port, None, 1)
    }

    fn upstream_with(
        zone: &str,
        port: u16,
        service: Option<&str>,
        weight: u32,
    ) -> &'static PreparedUpstream {
        let statics: &'static [PreparedPeer] =
            Box::leak(vec![peer("127.0.0.9:80", false)].into_boxed_slice());
        let template = PreparedUpstream {
            name: b"u",
            peers: statics,
            keepalive_max_idle: None,
            keepalive_local: false,
            keepalive_requests: 1000,
            keepalive_idle_timeout_ms: 60_000,
            keepalive_max_lifetime_ms: 3_600_000,
            lb: Lb::RoundRobin,
            shared: None,
            dynamic: None,
            sticky: None,
            metrics: None,
        };
        let resolver = Box::leak(Box::new(crate::resolver::Resolver {
            servers: Box::new(["127.0.0.1:53".parse().unwrap()]),
            valid: None,
            ipv4: true,
            ipv6: true,
        }));
        let host = |name: &str, backup: bool| HostConf {
            name: name.into(),
            service: service.map(String::from),
            port,
            template: PreparedPeer {
                display: b"a.test",
                weight,
                ..peer("0.0.0.0:0", backup)
            },
        };
        Dynamic::prepare(
            template,
            zone,
            vec![host("A.test", false), host("b.test", true)],
            resolver,
            Duration::from_secs(1),
            None,
        )
    }

    fn ips(list: &[&str]) -> Vec<IpAddr> {
        list.iter().map(|a| a.parse().unwrap()).collect()
    }

    fn addrs(v: &PreparedUpstream) -> Vec<(String, bool)> {
        v.peers
            .iter()
            .map(|p| (p.addr.to_string(), p.backup))
            .collect()
    }

    fn primary(list: &[&str]) -> Vec<(String, bool)> {
        list.iter().map(|a| (a.to_string(), false)).collect()
    }

    fn version(d: &'static Dynamic) -> &'static PreparedUpstream {
        d.version()
    }

    #[test]
    fn answers_change_the_peers_as_nginx() {
        let base = upstream("t1", 8080);
        let d = base.dynamic.unwrap().dynamic;
        assert_eq!(addrs(version(d)), primary(&["127.0.0.9:80"]));
        let later = Instant::now() + Duration::from_secs(5);
        // Each name's peers in address order.
        d.apply(0, &ips(&["10.0.0.2", "10.0.0.1"]), later);
        assert_eq!(
            addrs(version(d)),
            primary(&["127.0.0.9:80", "10.0.0.1:8080", "10.0.0.2:8080"])
        );
        d.apply(0, &ips(&["10.0.0.3", "10.0.0.2"]), later);
        assert_eq!(
            addrs(version(d)),
            primary(&["127.0.0.9:80", "10.0.0.2:8080", "10.0.0.3:8080"])
        );
        let second = version(d);
        assert!(second.shared.is_some_and(|s| s.len() == 3));
        // The same list in another order is no change.
        d.apply(0, &ips(&["10.0.0.2", "10.0.0.3"]), later);
        assert!(std::ptr::eq(version(d), second));
        // A backup server's peers stay in the backup tier; an address
        // twice is two peers, as in nginx.
        d.apply(1, &ips(&["10.0.1.1", "10.0.1.1"]), later);
        let mut want = primary(&["127.0.0.9:80", "10.0.0.2:8080", "10.0.0.3:8080"]);
        want.push(("10.0.1.1:8080".into(), true));
        want.push(("10.0.1.1:8080".into(), true));
        assert_eq!(addrs(version(d)), want);
        assert!(std::ptr::eq(version(d).dynamic.unwrap().dynamic, d));
        let taken = crate::upstream::UpstreamRef::current(base);
        assert!(std::ptr::eq(&*taken, version(d)));
        drop(taken);
        // No address: the server has no peers.
        d.apply(0, &[], later);
        d.apply(1, &[], later);
        assert_eq!(addrs(version(d)), primary(&["127.0.0.9:80"]));
    }

    #[test]
    fn versions_nothing_holds_are_freed() {
        let base = upstream("t4", 8080);
        let d = base.dynamic.unwrap().dynamic;
        let later = Instant::now() + Duration::from_secs(5);
        let churn = |round: u32| {
            for i in 0..500u32 {
                let a = format!("10.{round}.{}.{}", i / 250, i % 250);
                d.apply(0, &ips(&[&a, "10.255.0.1"]), later);
            }
        };
        churn(0);
        assert_eq!(d.live(), 1);
        // A request keeps its version through the changes; the ones
        // between go.
        let held = crate::upstream::UpstreamRef::current(base);
        let peers = addrs(&held);
        churn(1);
        assert_eq!(d.live(), 2);
        let copy = held.clone();
        drop(held);
        churn(2);
        assert_eq!(addrs(&copy), peers);
        drop(copy);
        // The worker still holds the version it took last, until it
        // takes another.
        assert_eq!(d.live(), 2);
        let now = crate::upstream::UpstreamRef::current(base);
        assert!(std::ptr::eq(&*now, version(d)));
        assert_eq!(d.live(), 1);
        drop(now);
        churn(3);
        assert_eq!(d.live(), 2);
    }

    #[test]
    fn the_next_generation_starts_from_the_last_answers() {
        let d = upstream("t2", 8080).dynamic.unwrap().dynamic;
        let later = Instant::now() + Duration::from_secs(60);
        d.apply(0, &ips(&["10.0.0.1", "10.0.0.2"]), later);
        // Same zone, upstream and name; the new line's port.
        let next = upstream("t2", 9090).dynamic.unwrap().dynamic;
        assert_eq!(
            addrs(version(next)),
            primary(&["127.0.0.9:80", "10.0.0.1:9090", "10.0.0.2:9090"])
        );
        assert_eq!(next.first[0], later);
        assert!(next.first[1] <= Instant::now());
        // Another zone starts empty.
        let other = upstream("t3", 8080).dynamic.unwrap().dynamic;
        assert_eq!(addrs(version(other)), primary(&["127.0.0.9:80"]));
    }

    fn srv(addr: &str, name: &str, priority: u16, weight: u16) -> SrvAddr {
        SrvAddr {
            addr: addr.parse().unwrap(),
            name: name.as_bytes().into(),
            priority,
            weight,
        }
    }

    fn peers(v: &PreparedUpstream) -> Vec<(String, String, u32, bool)> {
        v.peers
            .iter()
            .map(|p| {
                let display = String::from_utf8_lossy(p.display).into_owned();
                (p.addr.to_string(), display, p.weight, p.backup)
            })
            .collect()
    }

    fn row(addr: &str, name: &str, weight: u32, backup: bool) -> (String, String, u32, bool) {
        (addr.into(), name.into(), weight, backup)
    }

    #[test]
    fn services_give_ports_weights_and_backups() {
        let d = upstream_with("s1", 80, Some("http"), 1)
            .dynamic
            .unwrap()
            .dynamic;
        let later = Instant::now() + Duration::from_secs(5);
        let answer = [
            srv("10.0.0.1:8081", "a.example", 1, 5),
            srv("10.0.0.2:8082", "b.example", 2, 1),
        ];
        d.apply_service(0, &answer, later);
        // The lowest priority is primary, the rest backup; the record's
        // port, weight and target.
        let statics = row("127.0.0.9:80", "x", 1, false);
        assert_eq!(
            peers(version(d)),
            [
                statics.clone(),
                row("10.0.0.1:8081", "a.example", 5, false),
                row("10.0.0.2:8082", "b.example", 1, true),
            ]
        );
        // A new weight is a new peer.
        let answer = [srv("10.0.0.1:8081", "a.example", 1, 3)];
        d.apply_service(0, &answer, later);
        assert_eq!(
            peers(version(d)),
            [statics.clone(), row("10.0.0.1:8081", "a.example", 3, false)]
        );
        // A backup server has no lower tier to put them in.
        let answer = [srv("10.0.1.1:1", "c", 1, 1), srv("10.0.1.2:2", "d", 9, 1)];
        d.apply_service(1, &answer, later);
        assert_eq!(
            peers(version(d)),
            [
                statics.clone(),
                row("10.0.0.1:8081", "a.example", 3, false),
                row("10.0.1.1:1", "c", 1, true),
            ]
        );
        // The line's weight wins over the record's.
        let w = upstream_with("s2", 80, Some("http"), 7)
            .dynamic
            .unwrap()
            .dynamic;
        w.apply_service(0, &[srv("10.0.0.1:8081", "a.example", 1, 5)], later);
        assert_eq!(
            peers(version(w)),
            [statics, row("10.0.0.1:8081", "a.example", 7, false)]
        );
        // The next generation starts from the same peers.
        let next = upstream_with("s1", 80, Some("http"), 1)
            .dynamic
            .unwrap()
            .dynamic;
        assert_eq!(peers(version(next)), peers(version(d)));
        // Targets named anew each time: their names go with the versions.
        for i in 0..500 {
            let name = format!("pod-{i}.example");
            d.apply_service(0, &[srv("10.0.0.1:8081", &name, 1, 1)], later);
        }
        assert_eq!(d.live(), 1);
        assert_eq!(
            peers(version(d)),
            [
                row("127.0.0.9:80", "x", 1, false),
                row("10.0.0.1:8081", "pod-499.example", 1, false),
                row("10.0.1.1:1", "c", 1, true)
            ]
        );
    }
}
