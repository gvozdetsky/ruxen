//! `server NAME resolve` in an upstream with a `zone` (#597), as nginx
//! 1.27.3+ re-resolves such names (ngx_http_upstream_zone_module.c):
//!
//! - One worker asks the upstream's resolver for each name, again when the
//!   answer's TTL (or `valid=`) ends, plus a second
//!   (ngx_http_upstream_zone_resolve_handler). Peers whose address is no
//!   longer in the answer go; new ones come with the `server` line's
//!   parameters and port. An error keeps the peers and asks again after
//!   `resolver_timeout` (1 s at least); a name that doesn't exist (or has
//!   no address) leaves no peers.
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
//! - A reload starts from the addresses the last generation had for the
//!   same zone, upstream and name (ngx_http_upstream_zone_preresolve),
//!   with the new `server` line's port.

use std::cell::RefCell;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use crate::upstream::{HashLb, Lb, PeerShared};
use crate::worker::{PeerAddr, PreparedHttp, PreparedPeer, PreparedUpstream, RuntimeState};

/// A `server … resolve` line.
struct Host {
    /// The name as the resolver asks it.
    name: Box<[u8]>,
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
}

impl std::fmt::Debug for Dynamic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Dynamic")
            .field("upstream", &String::from_utf8_lossy(self.template.name))
            .finish_non_exhaustive()
    }
}

struct State {
    /// The resolved peers: host and address, each host's sorted.
    resolved: Vec<(usize, SocketAddr)>,
    /// The versions not freed yet, each with what it owns.
    versions: Vec<(&'static PreparedUpstream, crate::arena::Owner)>,
    owner: crate::arena::Owner,
}

/// A server line of the configuration being prepared.
pub(crate) struct HostConf {
    pub name: String,
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
    ) -> &'static PreparedUpstream {
        let now = Instant::now();
        let zone: &'static str = crate::arena::leak(zone.into());
        let hosts: Box<[Host]> = hosts
            .into_iter()
            .map(|h| Host {
                name: crate::resolver::normalize(h.name.as_bytes()),
                port: h.port,
                template: h.template,
            })
            .collect();
        let mut resolved = Vec::new();
        let mut first = Vec::with_capacity(hosts.len());
        for (i, host) in hosts.iter().enumerate() {
            match kept(zone, template.name, host) {
                Some((addrs, valid)) => {
                    resolved.extend(
                        addrs
                            .into_iter()
                            .map(|ip| (i, SocketAddr::new(ip, host.port))),
                    );
                    first.push(valid.max(now));
                }
                None => first.push(now),
            }
        }
        resolved.sort();
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
        let mut peers = Vec::with_capacity(self.template.peers.len() + state.resolved.len());
        for backup in [false, true] {
            peers.extend(
                self.template
                    .peers
                    .iter()
                    .filter(|p| p.backup == backup)
                    .copied(),
            );
            peers.extend(
                state
                    .resolved
                    .iter()
                    .filter(|(h, _)| self.hosts[*h].template.backup == backup)
                    .map(|&(h, addr)| PreparedPeer {
                        addr: PeerAddr::Inet(addr),
                        ..self.hosts[h].template
                    }),
            );
        }
        if let Some((version, _)) = state
            .versions
            .iter()
            .find(|(v, _)| same_peers(v.peers, &peers))
        {
            self.current
                .store(std::ptr::from_ref(*version).cast_mut(), Ordering::SeqCst);
            self.sweep(state);
            return;
        }
        let before = (!self.current.load(Ordering::Acquire).is_null()).then(|| self.version());
        let shared: Box<[PeerShared]> = peers
            .iter()
            .map(|p| {
                let slot = PeerShared::default();
                // A peer that stays keeps its failures.
                if let Some(before) = before
                    && let Some(i) = before.peers.iter().position(|b| same_peer(b, p))
                    && let Some(old) = before.shared
                {
                    slot.carry(&old[i]);
                }
                slot
            })
            .collect();
        // SAFETY: kept in `state.versions` until the version is freed,
        // when nothing uses it (`sweep`), or with `self`.
        let mut owner = unsafe { crate::arena::Owner::new() };
        let peers: &'static [PreparedPeer] = owner.leak(peers.into_boxed_slice());
        let lb = match self.template.lb {
            Lb::Hash(h) if h.ring.is_some() => Lb::Hash(owner.leak(Box::new(HashLb {
                key: h.key,
                ring: Some(crate::upstream::chash_ring(peers)),
            }))),
            lb => lb,
        };
        let shared: &'static [PeerShared] = owner.leak(shared);
        let tag: &'static Version = owner.leak(Box::new(Version {
            dynamic: self,
            holds: AtomicUsize::new(0),
        }));
        let version: &'static PreparedUpstream = owner.leak(Box::new(PreparedUpstream {
            peers,
            lb,
            shared: Some(shared),
            dynamic: Some(tag),
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
    }

    /// The number of versions not freed, for tests.
    #[cfg(test)]
    fn live(&self) -> usize {
        self.lock().versions.len()
    }

    /// Host `h`'s new addresses, matched against its peers as
    /// ngx_http_upstream_zone_resolve_handler does: a peer stays for an
    /// address of the answer not taken yet, goes otherwise; the rest of
    /// the answer is added.
    fn apply(&'static self, h: usize, addrs: &[IpAddr], valid: Instant) {
        let host = &self.hosts[h];
        let mut answer: Vec<Option<SocketAddr>> = addrs
            .iter()
            .map(|&ip| Some(SocketAddr::new(ip, host.port)))
            .collect();
        let mut state = self.lock();
        state.resolved.retain(|&(owner, addr)| {
            if owner != h {
                return true;
            }
            match answer.iter_mut().find(|a| **a == Some(addr)) {
                Some(taken) => {
                    *taken = None;
                    true
                }
                None => false,
            }
        });
        state
            .resolved
            .extend(answer.into_iter().flatten().map(|addr| (h, addr)));
        state.resolved.sort();
        self.publish(&mut state);
        drop(state);
        keep(self.zone, self.template.name, host, addrs, valid);
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

fn same_peer(a: &PreparedPeer, b: &PreparedPeer) -> bool {
    a.addr == b.addr
        && std::ptr::eq(a.display, b.display)
        && a.weight == b.weight
        && a.max_fails == b.max_fails
        && a.fail_timeout_ms == b.fail_timeout_ms
        && a.max_conns == b.max_conns
        && a.down == b.down
        && a.backup == b.backup
}

fn same_peers(a: &[PreparedPeer], b: &[PreparedPeer]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(a, b)| same_peer(a, b))
}

/// The addresses a generation last had for a name, for the next one.
struct Kept {
    zone: Box<str>,
    upstream: Box<[u8]>,
    name: Box<[u8]>,
    backup: bool,
    addrs: Vec<IpAddr>,
    valid: Instant,
}

static KEPT: Mutex<Vec<Kept>> = Mutex::new(Vec::new());

fn kept_list() -> std::sync::MutexGuard<'static, Vec<Kept>> {
    KEPT.lock().unwrap_or_else(|e| e.into_inner())
}

fn kept_matches(k: &Kept, zone: &str, upstream: &[u8], host: &Host) -> bool {
    *k.zone == *zone
        && *k.upstream == *upstream
        && k.name == host.name
        && k.backup == host.template.backup
}

fn kept(zone: &str, upstream: &[u8], host: &Host) -> Option<(Vec<IpAddr>, Instant)> {
    kept_list()
        .iter()
        .find(|k| kept_matches(k, zone, upstream, host))
        .map(|k| (k.addrs.clone(), k.valid))
}

fn keep(zone: &str, upstream: &[u8], host: &Host, addrs: &[IpAddr], valid: Instant) {
    let mut list = kept_list();
    match list
        .iter_mut()
        .find(|k| kept_matches(k, zone, upstream, host))
    {
        Some(k) => {
            k.addrs = addrs.to_vec();
            k.valid = valid;
        }
        None => list.push(Kept {
            zone: zone.into(),
            upstream: upstream.into(),
            name: host.name.clone(),
            backup: host.template.backup,
            addrs: addrs.to_vec(),
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
    let mut at = dynamic.first[h];
    loop {
        monoio::time::sleep(at.saturating_duration_since(Instant::now())).await;
        if state.is_shutting_down() {
            return;
        }
        let now = Instant::now();
        at = match crate::resolver::resolve_valid(dynamic.resolver, &host.name, dynamic.timeout)
            .await
        {
            Ok((addrs, valid)) => {
                dynamic.apply(h, &addrs, valid);
                valid.max(now) + AFTER_VALID
            }
            Err(failure) => {
                crate::resolver::log(&format!(
                    "{} could not be resolved ({failure})",
                    String::from_utf8_lossy(&host.name)
                ));
                if failure.0 == crate::resolver::NXDOMAIN {
                    let valid = now + dynamic.resolver.valid.unwrap_or(ERROR_VALID);
                    dynamic.apply(h, &[], valid);
                    valid + AFTER_VALID
                } else {
                    now + dynamic.timeout.max(Duration::from_secs(1))
                }
            }
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
            port,
            template: PreparedPeer {
                display: b"a.test",
                ..peer("0.0.0.0:0", backup)
            },
        };
        Dynamic::prepare(
            template,
            zone,
            vec![host("A.test", false), host("b.test", true)],
            resolver,
            Duration::from_secs(1),
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
}
