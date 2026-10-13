//! `limit_conn` (#95): requests being processed at once per key
//! (ngx_http_limit_conn_module), on zones shared by all worker threads, as
//! `limit_req`'s are (`limit_req.rs`). A request that passes holds one
//! count in each zone it was counted in until it ends: the `Held` guard is
//! carried in `ProcessMeta`, which lives until the response is written and
//! logged, and gives the counts back when dropped, as nginx's request-pool
//! cleanup does.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::OnceLock;

use crate::config::ErrorLogLevel;

use super::PreparedValuePart;

/// A `limit_conn_zone`.
pub struct LimitConnZone {
    pub name: &'static str,
    pub key: &'static [PreparedValuePart],
    /// The key as written, for messages.
    pub key_text: &'static str,
    /// Keys a shard may hold at once (from the zone size).
    capacity: usize,
    shards: Box<[Mutex<HashMap<Box<[u8]>, u32>>]>,
}

impl std::fmt::Debug for LimitConnZone {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LimitConnZone({})", self.name)
    }
}

impl LimitConnZone {
    pub(crate) fn new(
        name: &'static str,
        key: &'static [PreparedValuePart],
        key_text: &'static str,
        size: u64,
    ) -> Self {
        const SHARDS: usize = 64;
        let entries = (size / 128).max(SHARDS as u64) as usize;
        LimitConnZone {
            name,
            key,
            key_text,
            capacity: entries.div_ceil(SHARDS),
            shards: (0..SHARDS).map(|_| Mutex::new(HashMap::new())).collect(),
        }
    }

    fn shard(&self, key: &[u8]) -> &Mutex<HashMap<Box<[u8]>, u32>> {
        use std::hash::{BuildHasher, Hasher};
        static STATE: OnceLock<std::collections::hash_map::RandomState> = OnceLock::new();
        let mut h = STATE.get_or_init(Default::default).build_hasher();
        h.write(key);
        &self.shards[(h.finish() as usize) % self.shards.len()]
    }

    /// Count one more request for `key`, unless `limit` are in already:
    /// `None` then, or when the zone has no room for a new key.
    fn acquire(&self, key: &[u8], limit: u32) -> Result<(), Refused> {
        let mut map = self.shard(key).lock().unwrap_or_else(|e| e.into_inner());
        if let Some(count) = map.get_mut(key) {
            if *count >= limit {
                return Err(Refused::Limit);
            }
            *count += 1;
            return Ok(());
        }
        if map.len() >= self.capacity {
            return Err(Refused::Full);
        }
        map.insert(key.into(), 1);
        Ok(())
    }

    /// Give one back; the key goes when none is left.
    fn release(&self, key: &[u8]) {
        let mut map = self.shard(key).lock().unwrap_or_else(|e| e.into_inner());
        if let Some(count) = map.get_mut(key) {
            *count -= 1;
            if *count == 0 {
                map.remove(key);
            }
        }
    }
}

enum Refused {
    Limit,
    Full,
}

/// One `limit_conn` of a location.
#[derive(Debug, Clone, Copy)]
pub struct PreparedLimitConn {
    pub zone: &'static LimitConnZone,
    pub conn: u32,
}

/// A location's resolved `limit_conn*` settings.
#[derive(Debug)]
pub struct PreparedLimitConns {
    pub limits: &'static [PreparedLimitConn],
    pub status: u16,
    pub log_level: ErrorLogLevel,
    pub dry_run: bool,
}

/// `$limit_conn_status`, as `RewriteState::limit_conn_status` keeps it.
pub mod status {
    pub const PASSED: u8 = 1;
    pub const REJECTED: u8 = 2;
    pub const REJECTED_DRY_RUN: u8 = 3;

    pub fn text(s: u8) -> &'static [u8] {
        match s {
            PASSED => b"PASSED",
            REJECTED => b"REJECTED",
            REJECTED_DRY_RUN => b"REJECTED_DRY_RUN",
            _ => b"",
        }
    }
}

/// The counts a request holds, given back when it is dropped.
#[derive(Debug, Default)]
pub struct Held(Vec<(&'static LimitConnZone, Box<[u8]>)>);

impl Drop for Held {
    fn drop(&mut self) {
        for (zone, key) in self.0.drain(..) {
            zone.release(&key);
        }
    }
}

/// What the limits say about a request.
pub(crate) struct Verdict {
    /// `$limit_conn_status`; 0 when no limit applied (all keys empty).
    pub status: u8,
    pub reject: bool,
    pub log: Option<(ErrorLogLevel, String)>,
    /// The counts taken, to hold until the request ends.
    pub held: Held,
}

/// ngx_http_limit_conn_handler over the location's limits.
pub(crate) fn check(
    lc: &PreparedLimitConns,
    mut render: impl FnMut(&LimitConnZone) -> Vec<u8>,
) -> Verdict {
    let mut held = Held::default();
    let mut status = 0;
    let mut log = None;
    for limit in lc.limits {
        let key = render(limit.zone);
        if key.is_empty() {
            continue;
        }
        if key.len() > 255 {
            log = Some((
                ErrorLogLevel::Error,
                format!(
                    "the value of the \"{}\" key is more than 255 bytes: \"{}\"",
                    limit.zone.key_text,
                    String::from_utf8_lossy(&key)
                ),
            ));
            continue;
        }
        status = status::PASSED;
        match limit.zone.acquire(&key, limit.conn) {
            Ok(()) => held.0.push((limit.zone, key.into_boxed_slice())),
            Err(refused) => {
                if matches!(refused, Refused::Limit) {
                    log = Some((
                        lc.log_level,
                        format!(
                            "limiting connections{} by zone \"{}\"",
                            if lc.dry_run { ", dry run," } else { "" },
                            limit.zone.name
                        ),
                    ));
                }
                // ngx_http_limit_conn_cleanup_all: the counts taken so far
                // go back now.
                drop(held);
                return Verdict {
                    status: if lc.dry_run {
                        status::REJECTED_DRY_RUN
                    } else {
                        status::REJECTED
                    },
                    reject: !lc.dry_run,
                    log,
                    held: Held::default(),
                };
            }
        }
    }
    Verdict {
        status,
        reject: false,
        log,
        held,
    }
}

/// The pre-access phase's `limit_conn` for one request, after limit_req's:
/// keys rendered as the request stands, the verdict logged with the
/// request's context, `$limit_conn_status` noted. `Some` response: the
/// rejection (`limit_conn_status`). The counts taken come back to hold.
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
    lc: &PreparedLimitConns,
    log: &crate::phase::LogMeta,
    server_name: &'static [u8],
    server_header: &'static [u8],
) -> (Option<crate::phase::Response>, Held) {
    let verdict = {
        let args = current_args.unwrap_or_else(|| super::request_args(req.path));
        let captures_slice: &[(&'static str, Vec<u8>)] = match captures {
            Some(caps) => caps.names.as_slice(),
            None => &[],
        };
        let ctx =
            super::build_rewrite_ctx(http, server, req, uri, args, captures_slice, rewrite_state);
        check(lc, |zone| {
            let mut key = Vec::with_capacity(16);
            super::render_parts(zone.key, &ctx, &mut key);
            key
        })
    };
    rewrite_state.limit_conn_status = verdict.status;
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
        let body = format!("{}\n", crate::http::reason_phrase(lc.status));
        let response = crate::phase::Response::Owned(crate::http::build_response_for_method(
            lc.status,
            &body,
            req.method,
            server_header,
        ));
        return (Some(response), verdict.held);
    }
    (None, verdict.held)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conns(limit: u32, size: u64) -> PreparedLimitConns {
        let zone: &'static LimitConnZone =
            Box::leak(Box::new(LimitConnZone::new("z", &[], "$k", size)));
        PreparedLimitConns {
            limits: Box::leak(Box::new([PreparedLimitConn { zone, conn: limit }])),
            status: 503,
            log_level: ErrorLogLevel::Error,
            dry_run: false,
        }
    }

    #[test]
    fn counts_held_until_dropped() {
        let lc = conns(2, 1 << 20);
        let a = check(&lc, |_| b"k".to_vec());
        let b = check(&lc, |_| b"k".to_vec());
        assert_eq!((a.status, b.status), (status::PASSED, status::PASSED));
        let c = check(&lc, |_| b"k".to_vec());
        assert!(c.reject && c.status == status::REJECTED);
        assert!(
            c.log
                .unwrap()
                .1
                .contains("limiting connections by zone \"z\"")
        );
        // Another key is counted apart.
        assert!(!check(&lc, |_| b"other".to_vec()).reject);
        drop(a);
        assert!(!check(&lc, |_| b"k".to_vec()).reject);
        drop(b);
        // An empty key isn't counted.
        assert_eq!(check(&lc, |_| Vec::new()).status, 0);
    }

    #[test]
    fn a_rejection_gives_back_what_it_took() {
        let wide: &'static LimitConnZone =
            Box::leak(Box::new(LimitConnZone::new("wide", &[], "$k", 1 << 20)));
        let narrow: &'static LimitConnZone =
            Box::leak(Box::new(LimitConnZone::new("narrow", &[], "$k", 1 << 20)));
        let lc = PreparedLimitConns {
            limits: Box::leak(Box::new([
                PreparedLimitConn {
                    zone: wide,
                    conn: 10,
                },
                PreparedLimitConn {
                    zone: narrow,
                    conn: 1,
                },
            ])),
            status: 503,
            log_level: ErrorLogLevel::Error,
            dry_run: false,
        };
        let first = check(&lc, |_| b"k".to_vec());
        assert!(!first.reject);
        let second = check(&lc, |_| b"k".to_vec());
        assert!(second.reject);
        // `wide` holds only the first request's count.
        let map = wide.shard(b"k").lock().unwrap();
        assert_eq!(map.get(&b"k"[..]), Some(&1));
    }
}
