//! `limit_req_zone` / `limit_req` (ngx_http_limit_req_module, #94): the
//! leaky-bucket request rate limit. Zones are declared at http level; the
//! limits, `limit_req_status`, `limit_req_log_level` and
//! `limit_req_dry_run` at http, server and location, inherited as nginx's
//! merge does (a level with any `limit_req` replaces the inherited list).

use super::*;

/// `limit_req_zone key zone=name:size rate=Nr/s|Nr/m`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LimitReqZoneDef {
    pub name: String,
    pub key: Vec<ValuePart>,
    /// The key as written, for messages.
    pub key_text: String,
    pub size: u64,
    /// Requests per second × 1000 (nginx's `ctx->rate`).
    pub rate: u64,
}

/// One `limit_req zone=name [burst=N] [nodelay | delay=N]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LimitReq {
    pub zone: String,
    /// × 1000, as nginx keeps it.
    pub burst: u64,
    /// × 1000; `nodelay` is "never delay".
    pub delay: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LimitReqConf {
    pub limits: Option<Vec<LimitReq>>,
    /// `limit_req_status`, 400..599; default 503.
    pub status: Option<u16>,
    /// `limit_req_log_level`; default error.
    pub log_level: Option<ErrorLogLevel>,
    /// `limit_req_dry_run`; default off.
    pub dry_run: Option<bool>,
}

impl LimitReqConf {
    const DIRECTIVES: &'static [&'static str] = &[
        "limit_req",
        "limit_req_status",
        "limit_req_log_level",
        "limit_req_dry_run",
    ];

    pub(crate) fn takes(name: &str) -> bool {
        Self::DIRECTIVES.contains(&name)
    }

    /// The level's own values win; unset ones come from `parent`. A level
    /// with any `limit_req` replaces the parent's list
    /// (ngx_http_limit_req_merge_conf).
    pub(crate) fn inherit(self, parent: &LimitReqConf) -> LimitReqConf {
        LimitReqConf {
            limits: self.limits.or_else(|| parent.limits.clone()),
            status: self.status.or(parent.status),
            log_level: self.log_level.or(parent.log_level),
            dry_run: self.dry_run.or(parent.dry_run),
        }
    }

    pub(crate) fn parse(&mut self, args: &[String]) -> Result<(), Error> {
        let bad = |what: &'static str, got: &str| Error::BadValue {
            what,
            got: got.to_string(),
        };
        match args[0].as_str() {
            "limit_req" => {
                let limit = parse_limit_req(&args[1..])?;
                let limits = self.limits.get_or_insert_with(Vec::new);
                if limits.iter().any(|l| l.zone == limit.zone) {
                    return Err(Error::Duplicate("limit_req"));
                }
                limits.push(limit);
            }
            "limit_req_status" => {
                let [v] = &args[1..] else {
                    return Err(bad("limit_req_status", &args[1..].join(" ")));
                };
                if self.status.is_some() {
                    return Err(Error::Duplicate("limit_req_status"));
                }
                // ngx_http_limit_req_status_bounds: 400..599.
                self.status = Some(
                    v.parse::<u16>()
                        .ok()
                        .filter(|s| (400..=599).contains(s))
                        .ok_or_else(|| bad("limit_req_status (400..599)", v))?,
                );
            }
            "limit_req_log_level" => {
                let [v] = &args[1..] else {
                    return Err(bad("limit_req_log_level", &args[1..].join(" ")));
                };
                if self.log_level.is_some() {
                    return Err(Error::Duplicate("limit_req_log_level"));
                }
                self.log_level = Some(match v.as_str() {
                    "info" => ErrorLogLevel::Info,
                    "notice" => ErrorLogLevel::Notice,
                    "warn" => ErrorLogLevel::Warn,
                    "error" => ErrorLogLevel::Error,
                    _ => return Err(bad("limit_req_log_level", v)),
                });
            }
            _ => {
                if self.dry_run.is_some() {
                    return Err(Error::Duplicate("limit_req_dry_run"));
                }
                self.dry_run = Some(parse_on_off_args(&args[1..], "limit_req_dry_run")?);
            }
        }
        Ok(())
    }
}

/// `limit_req zone=name [burst=N] [nodelay | delay=N]` (ngx_http_limit_req).
fn parse_limit_req(args: &[String]) -> Result<LimitReq, Error> {
    let bad = |what: &'static str, got: &str| Error::BadValue {
        what,
        got: got.to_string(),
    };
    let mut zone = None;
    let mut burst = 0u64;
    let mut delay = 0u64;
    let positive = |v: &str, what| {
        v.parse::<u64>()
            .ok()
            .filter(|&n| n > 0)
            .ok_or_else(|| bad(what, v))
    };
    for arg in args {
        if let Some(name) = arg.strip_prefix("zone=") {
            zone = Some(name.to_string());
        } else if let Some(v) = arg.strip_prefix("burst=") {
            burst = positive(v, "limit_req burst")?;
        } else if let Some(v) = arg.strip_prefix("delay=") {
            delay = positive(v, "limit_req delay")?;
        } else if arg == "nodelay" {
            delay = u64::MAX / 1000;
        } else {
            return Err(bad("limit_req parameter", arg));
        }
    }
    let zone = zone.ok_or(Error::MissingArg("limit_req zone"))?;
    Ok(LimitReq {
        zone,
        burst: burst * 1000,
        delay: delay * 1000,
    })
}

/// `limit_req_zone key zone=name:size rate=Nr/s|Nr/m`
/// (ngx_http_limit_req_zone).
pub(crate) fn parse_limit_req_zone(args: &[String]) -> Result<LimitReqZoneDef, Error> {
    let bad = |what: &'static str, got: &str| Error::BadValue {
        what,
        got: got.to_string(),
    };
    let (key_text, params) = args
        .split_first()
        .ok_or(Error::MissingArg("limit_req_zone"))?;
    if params.len() != 2 {
        return Err(bad("limit_req_zone", &args.join(" ")));
    }
    let key = parse_value_with_vars(key_text)?;
    let mut zone: Option<(String, u64)> = None;
    let mut rate: u64 = 1000;
    for p in params {
        if let Some(spec) = p.strip_prefix("zone=") {
            let (name, size) = spec
                .split_once(':')
                .ok_or_else(|| bad("limit_req_zone size", p))?;
            let size = parse_size_bytes(size).ok_or_else(|| bad("limit_req_zone size", p))?;
            // nginx refuses a zone under 8 pages.
            if size < 8 * 4096 {
                return Err(bad("limit_req_zone (zone is too small)", p));
            }
            zone = Some((name.to_string(), size));
        } else if let Some(spec) = p.strip_prefix("rate=") {
            let (number, scale) = if let Some(n) = spec.strip_suffix("r/s") {
                (n, 1)
            } else if let Some(n) = spec.strip_suffix("r/m") {
                (n, 60)
            } else {
                (spec, 1)
            };
            let n: u64 = number
                .parse()
                .ok()
                .filter(|&n| n > 0)
                .ok_or_else(|| bad("limit_req_zone rate", p))?;
            rate = n * 1000 / scale;
        } else {
            return Err(bad("limit_req_zone parameter", p));
        }
    }
    let (name, size) = zone.ok_or(Error::MissingArg("limit_req_zone zone"))?;
    Ok(LimitReqZoneDef {
        name,
        key,
        key_text: key_text.clone(),
        size,
        rate,
    })
}
