//! `limit_conn_zone` / `limit_conn` (ngx_http_limit_conn_module, #95):
//! requests being processed at once, per key. Zones are declared at http
//! level; the limits, `limit_conn_status`, `limit_conn_log_level` and
//! `limit_conn_dry_run` at http, server and location, inherited as nginx's
//! merge does (a level with any `limit_conn` replaces the inherited list).

use super::*;

/// `limit_conn_zone key zone=name:size`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LimitConnZoneDef {
    pub name: String,
    pub key: Vec<ValuePart>,
    /// The key as written, for messages.
    pub key_text: String,
    pub size: u64,
}

/// One `limit_conn zone number`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LimitConn {
    pub zone: String,
    pub conn: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LimitConnConf {
    pub limits: Option<Vec<LimitConn>>,
    /// `limit_conn_status`, 400..599; default 503.
    pub status: Option<u16>,
    /// `limit_conn_log_level`; default error.
    pub log_level: Option<ErrorLogLevel>,
    /// `limit_conn_dry_run`; default off.
    pub dry_run: Option<bool>,
}

impl LimitConnConf {
    const DIRECTIVES: &'static [&'static str] = &[
        "limit_conn",
        "limit_conn_status",
        "limit_conn_log_level",
        "limit_conn_dry_run",
    ];

    pub(crate) fn takes(name: &str) -> bool {
        Self::DIRECTIVES.contains(&name)
    }

    /// The level's own values win; unset ones come from `parent`. A level
    /// with any `limit_conn` replaces the parent's list
    /// (ngx_http_limit_conn_merge_conf).
    pub(crate) fn inherit(self, parent: &LimitConnConf) -> LimitConnConf {
        LimitConnConf {
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
            "limit_conn" => {
                let [zone, number] = &args[1..] else {
                    return Err(bad("limit_conn", &args[1..].join(" ")));
                };
                // ngx_http_limit_conn: 1..65535.
                let conn = number
                    .parse::<u32>()
                    .ok()
                    .filter(|n| (1..=65_535).contains(n))
                    .ok_or_else(|| bad("limit_conn (invalid number of connections)", number))?;
                let limits = self.limits.get_or_insert_with(Vec::new);
                if limits.iter().any(|l| &l.zone == zone) {
                    return Err(Error::Duplicate("limit_conn"));
                }
                limits.push(LimitConn {
                    zone: zone.clone(),
                    conn,
                });
            }
            "limit_conn_status" => {
                let [v] = &args[1..] else {
                    return Err(bad("limit_conn_status", &args[1..].join(" ")));
                };
                if self.status.is_some() {
                    return Err(Error::Duplicate("limit_conn_status"));
                }
                self.status = Some(
                    v.parse::<u16>()
                        .ok()
                        .filter(|s| (400..=599).contains(s))
                        .ok_or_else(|| bad("limit_conn_status (400..599)", v))?,
                );
            }
            "limit_conn_log_level" => {
                let [v] = &args[1..] else {
                    return Err(bad("limit_conn_log_level", &args[1..].join(" ")));
                };
                if self.log_level.is_some() {
                    return Err(Error::Duplicate("limit_conn_log_level"));
                }
                self.log_level = Some(match v.as_str() {
                    "info" => ErrorLogLevel::Info,
                    "notice" => ErrorLogLevel::Notice,
                    "warn" => ErrorLogLevel::Warn,
                    "error" => ErrorLogLevel::Error,
                    _ => return Err(bad("limit_conn_log_level", v)),
                });
            }
            _ => {
                if self.dry_run.is_some() {
                    return Err(Error::Duplicate("limit_conn_dry_run"));
                }
                self.dry_run = Some(parse_on_off_args(&args[1..], "limit_conn_dry_run")?);
            }
        }
        Ok(())
    }
}

/// `limit_conn_zone key zone=name:size` (ngx_http_limit_conn_zone).
pub(crate) fn parse_limit_conn_zone(args: &[String]) -> Result<LimitConnZoneDef, Error> {
    let bad = |what: &'static str, got: &str| Error::BadValue {
        what,
        got: got.to_string(),
    };
    let [key_text, spec] = args else {
        return Err(bad("limit_conn_zone", &args.join(" ")));
    };
    let key = parse_value_with_vars(key_text)?;
    let spec = spec
        .strip_prefix("zone=")
        .ok_or_else(|| bad("limit_conn_zone parameter", spec))?;
    let (name, size) = spec
        .split_once(':')
        .ok_or_else(|| bad("limit_conn_zone size", spec))?;
    let size = parse_size_bytes(size).ok_or_else(|| bad("limit_conn_zone size", spec))?;
    if size < 8 * 4096 {
        return Err(bad("limit_conn_zone (zone is too small)", spec));
    }
    Ok(LimitConnZoneDef {
        name: name.to_string(),
        key,
        key_text: key_text.clone(),
        size,
    })
}
