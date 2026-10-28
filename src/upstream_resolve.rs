//! `server NAME resolve` in an upstream with a `zone` (#597), as nginx
//! 1.27.3+ re-resolves such names (ngx_http_upstream_zone_module.c):
//!
//! - One worker asks the upstream's resolver for each name, again when the
//!   answer's TTL (or `valid=`) ends, plus a second
//!   (ngx_http_upstream_zone_resolve_handler). Peers whose address is no
//!   longer in the answer go; new addresses are added at the end of the
//!   list with the `server` line's parameters and port. An error keeps the
//!   peers and asks again after `resolver_timeout` (1 s at least); a name
//!   that doesn't exist (or has no address) leaves no peers.
//! - The peer list is a whole `PreparedUpstream` (a version) that requests
//!   take when they start (`PreparedUpstream::current`), so the request
//!   path keeps indexing a fixed slice; a request keeps the version it
//!   started with. Peers that stay keep their failure state; keep-alive
//!   connections move to the new version in each worker.
//! - A version is kept until the configuration is freed, and reused when
//!   its peer list comes back: the memory grows with the number of
//!   distinct lists seen, not with the number of answers.
//! - A reload starts from the addresses the last generation had for the
//!   same zone, upstream and name (ngx_http_upstream_zone_preresolve),
//!   with the new `server` line's port.

use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
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
    /// The resolved peers in nginx's list order: host and address.
    resolved: Vec<(usize, SocketAddr)>,
    versions: Vec<&'static PreparedUpstream>,
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
        let dynamic: &'static Dynamic = crate::arena::leak(Box::new(Dynamic {
            zone,
            template,
            hosts,
            resolver,
            timeout,
            first: first.into(),
            current: AtomicPtr::new(std::ptr::null_mut()),
            claimed: AtomicBool::new(false),
            state: Mutex::new(State {
                resolved,
                versions: Vec::new(),
                // SAFETY: inside `dynamic`, which the generation's arena
                // frees with the rest of its configuration.
                owner: unsafe { crate::arena::Owner::new() },
            }),
        }));
        dynamic.publish(&mut dynamic.lock());
        crate::arena::leak(Box::new(PreparedUpstream {
            dynamic: Some(dynamic),
            ..dynamic.template
        }))
    }

    /// The version requests take now; the worker notices a change.
    #[inline(never)]
    pub(crate) fn current(&'static self) -> &'static PreparedUpstream {
        let version = self.version();
        crate::upstream::notice_version(self, version);
        version
    }

    pub(crate) fn version(&self) -> &'static PreparedUpstream {
        // SAFETY: set by `publish` before the upstream is handed out, to a
        // version `state` keeps for as long as `self` lives.
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
        if let Some(version) = state.versions.iter().find(|v| same_peers(v.peers, &peers)) {
            self.current
                .store(std::ptr::from_ref(*version).cast_mut(), Ordering::Release);
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
        let owner = &mut state.owner;
        let peers: &'static [PreparedPeer] = owner.leak(peers.into_boxed_slice());
        let lb = match self.template.lb {
            Lb::Hash(h) if h.ring.is_some() => Lb::Hash(owner.leak(Box::new(HashLb {
                key: h.key,
                ring: Some(crate::upstream::chash_ring(peers)),
            }))),
            lb => lb,
        };
        let shared: &'static [PeerShared] = owner.leak(shared);
        let version: &'static PreparedUpstream = owner.leak(Box::new(PreparedUpstream {
            peers,
            lb,
            shared: Some(shared),
            dynamic: Some(self),
            ..self.template
        }));
        state.versions.push(version);
        self.current
            .store(std::ptr::from_ref(version).cast_mut(), Ordering::Release);
    }

    /// Host `h`'s new addresses, matched against its peers as
    /// ngx_http_upstream_zone_resolve_handler does: a peer stays for an
    /// address of the answer not taken yet, goes otherwise; the rest of
    /// the answer is added at the end.
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
        self.publish(&mut state);
        drop(state);
        keep(self.zone, self.template.name, host, addrs, valid);
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
        let Some(dynamic) = upstream.dynamic else {
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

    #[test]
    fn answers_change_the_peers_as_nginx() {
        let base = upstream("t1", 8080);
        let d = base.dynamic.unwrap();
        assert_eq!(addrs(d.version()), primary(&["127.0.0.9:80"]));
        let later = Instant::now() + Duration::from_secs(5);
        d.apply(0, &ips(&["10.0.0.1", "10.0.0.2"]), later);
        assert_eq!(
            addrs(d.version()),
            primary(&["127.0.0.9:80", "10.0.0.1:8080", "10.0.0.2:8080"])
        );
        let first = d.version();
        // Staying peers keep their place; new ones go last.
        d.apply(0, &ips(&["10.0.0.3", "10.0.0.2"]), later);
        assert_eq!(
            addrs(d.version()),
            primary(&["127.0.0.9:80", "10.0.0.2:8080", "10.0.0.3:8080"])
        );
        let second = d.version();
        assert!(second.shared.is_some_and(|s| s.len() == 3));
        // The same list in another order is no change.
        d.apply(0, &ips(&["10.0.0.3", "10.0.0.2"]), later);
        assert!(std::ptr::eq(d.version(), second));
        // A list seen before takes its version again.
        d.apply(0, &ips(&["10.0.0.1", "10.0.0.2"]), later);
        d.apply(0, &ips(&["10.0.0.3"]), later);
        d.apply(0, &ips(&["10.0.0.1", "10.0.0.2"]), later);
        assert!(std::ptr::eq(d.version(), first));
        // A backup server's peers stay in the backup tier; an address
        // twice is two peers, as in nginx.
        d.apply(1, &ips(&["10.0.1.1", "10.0.1.1"]), later);
        let mut want = primary(&["127.0.0.9:80", "10.0.0.1:8080", "10.0.0.2:8080"]);
        want.push(("10.0.1.1:8080".into(), true));
        want.push(("10.0.1.1:8080".into(), true));
        assert_eq!(addrs(d.version()), want);
        assert!(std::ptr::eq(d.version().dynamic.unwrap(), d));
        assert!(std::ptr::eq(base.current(), d.version()));
        // No address: the server has no peers.
        d.apply(0, &[], later);
        d.apply(1, &[], later);
        assert_eq!(addrs(d.version()), primary(&["127.0.0.9:80"]));
    }

    #[test]
    fn the_next_generation_starts_from_the_last_answers() {
        let d = upstream("t2", 8080).dynamic.unwrap();
        let later = Instant::now() + Duration::from_secs(60);
        d.apply(0, &ips(&["10.0.0.1", "10.0.0.2"]), later);
        // Same zone, upstream and name; the new line's port.
        let next = upstream("t2", 9090).dynamic.unwrap();
        assert_eq!(
            addrs(next.version()),
            primary(&["127.0.0.9:80", "10.0.0.1:9090", "10.0.0.2:9090"])
        );
        assert_eq!(next.first[0], later);
        assert!(next.first[1] <= Instant::now());
        // Another zone starts empty.
        let other = upstream("t3", 8080).dynamic.unwrap();
        assert_eq!(addrs(other.version()), primary(&["127.0.0.9:80"]));
    }
}
