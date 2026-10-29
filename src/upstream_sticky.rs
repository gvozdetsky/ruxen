//! `sticky` (#600): session affinity, as ngx_http_upstream_sticky_module
//! (nginx 1.29.6).
//!
//! Every peer of an upstream with `sticky` has an ID (nginx's SID): its
//! `route=`, else the MD5 of its address in hex. A request names one,
//! through its cookie (`sticky cookie`), a variable (`sticky route`), or a
//! session the zone of `sticky learn` maps to it; the balancer then takes
//! that peer if it can (`upstream::pick_peer_sticky`), else picks as
//! usual. `drain` peers are down except for such requests.
//!
//! A `learn` zone is a map every worker thread shares behind one mutex, as
//! nginx's is in shared memory, and survives a reload that declares it the
//! same way for the same upstream. Sessions expire `timeout` after their
//! last use; a full zone drops its least recently used one.

use std::collections::{BTreeSet, HashMap};
use std::sync::Mutex;
use std::sync::OnceLock;
use std::time::Instant;

use crate::config::{StickyConf, StickyExpires, UpstreamServer, Variable};
use crate::worker::{PeerAddr, PreparedValuePart};

/// nginx's NGX_HTTP_STICKY_COOKIE_MAX_EXPIRES `expires=max` cookie tail.
const EXPIRES_MAX: &[u8] = b"; expires=Thu, 31-Dec-37 23:55:55 GMT; max-age=315360000";

/// An upstream's `sticky`, prepared.
#[derive(Debug)]
pub struct Sticky {
    /// Each peer's ID, by peer index.
    pub sids: &'static [&'static [u8]],
    /// Peers marked `drain` (also `down` for the balancer), by index.
    pub draining: &'static [bool],
    /// The variables naming the server or session, first non-empty wins.
    pub lookup: &'static [&'static [PreparedValuePart]],
    pub mode: Mode,
}

#[derive(Debug)]
pub enum Mode {
    Cookie(Cookie),
    Route,
    Learn(Learn),
}

#[derive(Debug)]
pub struct Cookie {
    /// `name=`.
    pub prefix: &'static [u8],
    pub domain: Option<&'static [PreparedValuePart]>,
    /// `; path=...`, or empty.
    pub path: &'static [u8],
    pub expires: Option<StickyExpires>,
    pub httponly: bool,
    pub secure: bool,
    pub samesite: Option<SameSite>,
}

#[derive(Debug)]
pub enum SameSite {
    Static(&'static [u8]),
    /// Rendered per request; an invalid value is `strict`.
    Var(&'static [PreparedValuePart]),
}

#[derive(Debug)]
pub struct Learn {
    pub create: &'static [&'static [PreparedValuePart]],
    pub zone: &'static SessionZone,
    pub header: bool,
    /// A `create` variable reads the upstream's header.
    pub reads_upstream: bool,
}

impl Sticky {
    pub(crate) fn prepare(
        conf: StickyConf,
        servers: &[UpstreamServer],
        upstream: &str,
    ) -> &'static Sticky {
        let sids = servers
            .iter()
            .map(|s| match &s.route {
                Some(route) => leak(route.as_bytes()),
                None => leak(&addr_sid(PeerAddr::from_config(s.addr.clone()))),
            })
            .collect::<Vec<_>>();
        let draining = servers.iter().map(|s| s.drain).collect::<Vec<_>>();
        let vars =
            |v: Vec<Vec<crate::config::ValuePart>>| -> &'static [&'static [PreparedValuePart]] {
                crate::arena::leak(
                    v.into_iter()
                        .map(crate::worker::prepare_value_parts)
                        .collect::<Vec<_>>()
                        .into_boxed_slice(),
                )
            };
        let (lookup, mode) = match conf {
            StickyConf::Cookie(c) => {
                let lookup = vec![vec![crate::config::ValuePart::Var(Variable::Cookie(
                    c.name.clone(),
                ))]];
                let samesite = c.samesite.map(|parts| {
                    if parts
                        .iter()
                        .all(|p| matches!(p, crate::config::ValuePart::Literal(_)))
                    {
                        let text: String = parts
                            .iter()
                            .map(|p| match p {
                                crate::config::ValuePart::Literal(s) => s.as_str(),
                                _ => "",
                            })
                            .collect();
                        SameSite::Static(leak(text.as_bytes()))
                    } else {
                        SameSite::Var(crate::worker::prepare_value_parts(parts))
                    }
                });
                let cookie = Cookie {
                    prefix: leak(format!("{}=", c.name).as_bytes()),
                    domain: c.domain.map(crate::worker::prepare_value_parts),
                    path: leak(
                        c.path
                            .map_or(String::new(), |p| format!("; path={p}"))
                            .as_bytes(),
                    ),
                    expires: c.expires,
                    httponly: c.httponly,
                    secure: c.secure,
                    samesite,
                };
                (vars(lookup), Mode::Cookie(cookie))
            }
            StickyConf::Route { lookup } => (vars(lookup), Mode::Route),
            StickyConf::Learn(l) => {
                let reads_upstream = l.create.iter().any(|v| {
                    matches!(
                        v.as_slice(),
                        [crate::config::ValuePart::Var(
                            Variable::UpstreamCookie(_) | Variable::UpstreamHttp(_)
                        )]
                    )
                });
                let zone = SessionZone::declare(&l.zone, l.zone_size, l.timeout_ms, upstream);
                let learn = Learn {
                    create: vars(l.create),
                    zone,
                    header: l.header,
                    reads_upstream,
                };
                (vars(l.lookup), Mode::Learn(learn))
            }
        };
        crate::arena::leak(Box::new(Sticky {
            sids: crate::arena::leak(sids.into_boxed_slice()),
            draining: crate::arena::leak(draining.into_boxed_slice()),
            lookup,
            mode,
        }))
    }

    pub fn learn(&self) -> Option<&Learn> {
        match &self.mode {
            Mode::Learn(l) => Some(l),
            _ => None,
        }
    }
}

fn leak(b: &[u8]) -> &'static [u8] {
    crate::arena::leak(b.to_vec().into_boxed_slice())
}

/// A peer's ID without `route=`: the MD5 of its address as nginx prints
/// it, in hex (ngx_http_upstream_init_round_robin_sid).
fn addr_sid(addr: PeerAddr) -> Vec<u8> {
    let digest = crate::auth::md5(addr.to_string().as_bytes());
    let mut out = Vec::with_capacity(32);
    for b in digest {
        out.extend_from_slice(format!("{b:02x}").as_bytes());
    }
    out
}

/// One request's view of its upstream's `sticky`.
pub struct StickyReq {
    pub conf: &'static Sticky,
    /// What the lookup variables gave (a server ID or a session); empty:
    /// nothing.
    id: Box<[u8]>,
    /// The ID of the peer to prefer; empty: none.
    pub hint: Box<[u8]>,
    /// `sticky cookie`: the rendered `domain=` and `samesite=`.
    domain: Box<[u8]>,
    samesite: Box<[u8]>,
    /// `sticky learn`: the `create` values, `None` for one read from the
    /// upstream's header.
    create: Vec<Option<Box<[u8]>>>,
    /// The peer of the attempt in progress.
    pub peer: usize,
}

impl StickyReq {
    /// ngx_http_upstream_sticky_init_peer: `render` gives a variable's
    /// value for the request.
    pub(crate) fn new(
        conf: &'static Sticky,
        mut render: impl FnMut(&'static [PreparedValuePart]) -> Vec<u8>,
    ) -> Box<StickyReq> {
        let id: Box<[u8]> = conf
            .lookup
            .iter()
            .map(|v| render(v))
            .find(|v| !v.is_empty())
            .unwrap_or_default()
            .into();
        let mut req = StickyReq {
            conf,
            hint: Box::default(),
            domain: Box::default(),
            samesite: Box::default(),
            create: Vec::new(),
            peer: 0,
            id,
        };
        match &conf.mode {
            Mode::Cookie(c) => {
                req.hint = req.id.clone();
                if let Some(domain) = c.domain {
                    req.domain = render(domain).into();
                }
                req.samesite = match c.samesite {
                    None => Box::default(),
                    Some(SameSite::Static(v)) => v.into(),
                    Some(SameSite::Var(parts)) => {
                        let v = render(parts);
                        if v.is_empty() || crate::config::is_samesite(&v) {
                            v.into()
                        } else {
                            (*b"strict").into()
                        }
                    }
                };
            }
            Mode::Route => req.hint = req.id.clone(),
            Mode::Learn(l) => {
                if !req.id.is_empty() {
                    req.hint = l
                        .zone
                        .lookup(&crate::auth::md5(&req.id))
                        .unwrap_or_default();
                }
                req.create = l
                    .create
                    .iter()
                    .map(|v| (!reads_upstream(v)).then(|| render(v).into()))
                    .collect();
            }
        }
        Box::new(req)
    }

    /// The `Set-Cookie` line of `sticky cookie` for peer `self.peer`, with
    /// its CRLF (ngx_http_upstream_sticky_cookie_insert).
    pub fn write_cookie(&self, out: &mut Vec<u8>) {
        let Mode::Cookie(c) = &self.conf.mode else {
            return;
        };
        out.extend_from_slice(b"Set-Cookie: ");
        out.extend_from_slice(c.prefix);
        out.extend_from_slice(self.conf.sids[self.peer]);
        match c.expires {
            None => {}
            Some(StickyExpires::Max) => out.extend_from_slice(EXPIRES_MAX),
            Some(StickyExpires::Secs(secs)) => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs());
                out.extend_from_slice(b"; expires=");
                out.extend_from_slice(&cookie_time(now.saturating_add(secs)));
                out.extend_from_slice(format!("; max-age={secs}").as_bytes());
            }
        }
        if !self.domain.is_empty() {
            out.extend_from_slice(b"; domain=");
            out.extend_from_slice(&self.domain);
        }
        if c.httponly {
            out.extend_from_slice(b"; httponly");
        }
        if c.secure {
            out.extend_from_slice(b"; secure");
        }
        if !self.samesite.is_empty() {
            out.extend_from_slice(b"; samesite=");
            out.extend_from_slice(&self.samesite);
        }
        out.extend_from_slice(c.path);
        out.extend_from_slice(b"\r\n");
    }

    /// The session `sticky learn` keeps for this request, and whether it
    /// may be created: the first non-empty `create` value, else the
    /// looked-up one, which only refreshes (ngx_http_upstream_sticky_learn_peer).
    /// `upstream_headers` are the upstream's header lines.
    pub fn session(&self, upstream_headers: &[u8]) -> Option<PendingLearn> {
        let learn = self.conf.learn()?;
        for (value, var) in self.create.iter().zip(learn.create) {
            let value: Box<[u8]> = match value {
                Some(v) => v.clone(),
                None => {
                    let mut out = Vec::new();
                    match var {
                        [PreparedValuePart::Var(Variable::UpstreamCookie(name))] => {
                            crate::worker::write_upstream_cookie_value(
                                &mut out,
                                upstream_headers,
                                name.as_bytes(),
                            )
                        }
                        [PreparedValuePart::Var(Variable::UpstreamHttp(name))] => {
                            crate::worker::write_all_request_header_values(
                                &mut out,
                                upstream_headers,
                                name.as_bytes(),
                            )
                        }
                        _ => {}
                    }
                    out.into()
                }
            };
            if !value.is_empty() {
                return Some(PendingLearn {
                    session: value,
                    create: true,
                });
            }
        }
        (!self.id.is_empty()).then(|| PendingLearn {
            session: self.id.clone(),
            create: false,
        })
    }
}

fn reads_upstream(v: &[PreparedValuePart]) -> bool {
    matches!(
        v,
        [PreparedValuePart::Var(
            Variable::UpstreamCookie(_) | Variable::UpstreamHttp(_)
        )]
    )
}

/// A session to record against the peer that served it, once the request
/// is done with the peer (nginx's free_peer) or at once with `header`.
pub struct PendingLearn {
    session: Box<[u8]>,
    create: bool,
}

impl PendingLearn {
    pub fn record(&self, sticky: &Sticky, peer: usize) {
        if let Some(learn) = sticky.learn() {
            learn.zone.learn(
                &crate::auth::md5(&self.session),
                self.create,
                sticky.sids[peer],
            );
        }
    }
}

/// `Thu, 31-Dec-37 23:55:55 GMT`, ngx_http_cookie_time: a two-digit year
/// up to 2037.
fn cookie_time(secs: u64) -> Vec<u8> {
    let d = crate::file::format_http_date(secs);
    // `Www, DD Mon YYYY HH:MM:SS GMT`
    let year: u32 = std::str::from_utf8(&d[12..16])
        .ok()
        .and_then(|y| y.parse().ok())
        .unwrap_or(0);
    let mut out = Vec::with_capacity(29);
    out.extend_from_slice(&d[..7]);
    out.push(b'-');
    out.extend_from_slice(&d[8..11]);
    out.push(b'-');
    if year > 2037 {
        out.extend_from_slice(&d[12..16]);
    } else {
        out.extend_from_slice(&d[14..16]);
    }
    out.extend_from_slice(&d[16..]);
    out
}

/// Milliseconds on a process-wide monotonic clock.
fn now_ms() -> u64 {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    EPOCH.get_or_init(Instant::now).elapsed().as_millis() as u64
}

/// The sessions of a `sticky learn` zone: the session's MD5 to the peer
/// ID, and the same ordered by last use.
struct Sessions {
    map: HashMap<[u8; 16], Session>,
    by_last: BTreeSet<(u64, [u8; 16])>,
    capacity: usize,
}

struct Session {
    sid: Box<[u8]>,
    last: u64,
}

impl Sessions {
    /// Drop the sessions unused for `timeout` (the zone's timer in nginx),
    /// or with `force` the least recently used one at least.
    fn expire(&mut self, now: u64, timeout: u64, mut force: bool) {
        while let Some(&(last, key)) = self.by_last.first() {
            if !force && last + timeout > now {
                break;
            }
            force = false;
            self.by_last.pop_first();
            self.map.remove(&key);
        }
    }

    fn touch(&mut self, key: [u8; 16], now: u64) {
        if let Some(s) = self.map.get_mut(&key) {
            self.by_last.remove(&(s.last, key));
            s.last = now;
            self.by_last.insert((now, key));
        }
    }
}

/// A `sticky learn` zone.
pub struct SessionZone {
    pub name: &'static str,
    timeout_ms: u64,
    sessions: &'static Mutex<Sessions>,
}

impl std::fmt::Debug for SessionZone {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionZone")
            .field("name", &self.name)
            .finish()
    }
}

/// The zones' state for the next configuration, as `limit_req`'s (#342).
static KEPT: Mutex<Vec<Kept>> = Mutex::new(Vec::new());

struct Kept {
    name: String,
    size: u64,
    upstream: String,
    sessions: &'static Mutex<Sessions>,
}

impl SessionZone {
    /// The zone, with the sessions of the one a reload's previous
    /// configuration declared alike.
    fn declare(name: &str, size: u64, timeout_ms: u64, upstream: &str) -> &'static SessionZone {
        // Kept past this generation: `Box::leak`, not its arena.
        let fresh = || -> &'static Mutex<Sessions> {
            Box::leak(Box::new(Mutex::new(Sessions {
                map: HashMap::new(),
                by_last: BTreeSet::new(),
                // About nginx's: 32k ~ 200 sessions, 1m ~ 8000.
                capacity: (size / 128).max(1) as usize,
            })))
        };
        let sessions = if cfg!(test) {
            fresh()
        } else {
            let mut kept = KEPT.lock().unwrap_or_else(|e| e.into_inner());
            match kept
                .iter()
                .find(|k| k.name == name && k.size == size && k.upstream == upstream)
            {
                Some(k) => k.sessions,
                None => {
                    let sessions = fresh();
                    kept.retain(|k| k.name != name);
                    kept.push(Kept {
                        name: name.to_string(),
                        size,
                        upstream: upstream.to_string(),
                        sessions,
                    });
                    sessions
                }
            }
        };
        crate::arena::leak(Box::new(SessionZone {
            name: crate::arena::leak(name.to_string().into_boxed_str()),
            timeout_ms,
            sessions,
        }))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Sessions> {
        self.sessions.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The peer ID of session `key`.
    pub fn lookup(&self, key: &[u8; 16]) -> Option<Box<[u8]>> {
        let mut s = self.lock();
        s.expire(now_ms(), self.timeout_ms, false);
        s.map.get(key).map(|s| s.sid.clone())
    }

    /// Bind session `key` to peer `sid` and refresh it; a new one only
    /// with `create`.
    pub fn learn(&self, key: &[u8; 16], create: bool, sid: &[u8]) {
        let now = now_ms();
        let mut s = self.lock();
        s.expire(now, self.timeout_ms, false);
        if let Some(session) = s.map.get_mut(key) {
            if *session.sid != *sid {
                session.sid = sid.into();
            }
            s.touch(*key, now);
            return;
        }
        if !create {
            return;
        }
        if s.map.len() >= s.capacity {
            let logs = crate::worker::worker_http().map_or(&[][..], |h| h.error_logs);
            crate::worker::write_worker_log(
                logs,
                crate::config::ErrorLogLevel::Warn,
                &format!(
                    "could not allocate node in sticky session zone \"{}\", expiring least recently used session",
                    self.name
                ),
            );
            s.expire(now, self.timeout_ms, true);
        }
        s.map.insert(
            *key,
            Session {
                sid: sid.into(),
                last: now,
            },
        );
        s.by_last.insert((now, *key));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_time_as_nginx() {
        assert_eq!(cookie_time(0), b"Thu, 01-Jan-70 00:00:00 GMT");
        assert_eq!(cookie_time(2145916555), b"Thu, 31-Dec-37 23:55:55 GMT");
        assert_eq!(cookie_time(2208988800), b"Sun, 01-Jan-2040 00:00:00 GMT");
    }

    #[test]
    fn sid_is_md5_of_the_address() {
        // nginx: md5("127.0.0.1:8081") in hex.
        let addr = PeerAddr::Inet("127.0.0.1:8081".parse().unwrap());
        assert_eq!(addr_sid(addr), b"df2b80dc43705d28db9be6f29fe58da3");
    }

    #[test]
    fn sessions_expire_and_refresh() {
        let zone = SessionZone::declare("t", 32768, 50, "u");
        let k = crate::auth::md5(b"s1");
        zone.learn(&k, false, b"a");
        assert_eq!(zone.lookup(&k), None, "no create, no session");
        zone.learn(&k, true, b"a");
        assert_eq!(zone.lookup(&k).as_deref(), Some(&b"a"[..]));
        zone.learn(&k, false, b"b");
        assert_eq!(zone.lookup(&k).as_deref(), Some(&b"b"[..]), "rebound");
        std::thread::sleep(std::time::Duration::from_millis(80));
        assert_eq!(zone.lookup(&k), None, "expired");
    }

    #[test]
    fn a_full_zone_drops_the_oldest() {
        let zone = SessionZone::declare("t", 128 * 2, 60_000, "u");
        let (a, b, c) = (
            crate::auth::md5(b"a"),
            crate::auth::md5(b"b"),
            crate::auth::md5(b"c"),
        );
        zone.learn(&a, true, b"1");
        std::thread::sleep(std::time::Duration::from_millis(2));
        zone.learn(&b, true, b"2");
        std::thread::sleep(std::time::Duration::from_millis(2));
        zone.learn(&c, true, b"3");
        assert_eq!(zone.lookup(&a), None);
        assert!(zone.lookup(&b).is_some() && zone.lookup(&c).is_some());
    }
}
