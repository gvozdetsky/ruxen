//! `log_format`, `access_log`, and `error_log` (including syslog target)
//! parsers. The error-log syslog grammar is the nginx-compatible
//! `syslog:server=...,facility=...,tag=...,severity=...` form.

use super::*;
use std::net::SocketAddr;

pub(crate) enum ParsedAccessLog {
    Off,
    Entry(AccessLog),
}

pub(crate) fn parse_log_format_args(args: &[String]) -> Result<LogFormatDef, Error> {
    if args.len() < 2 {
        return Err(Error::MissingArg("log_format"));
    }
    let name = args[0].clone();
    let mut rest = &args[1..];
    let mut escape = LogEscape::Default;
    if let Some(mode) = rest[0].strip_prefix("escape=") {
        escape = match mode {
            "default" => LogEscape::Default,
            "json" => LogEscape::Json,
            "none" => LogEscape::None,
            _ => {
                return Err(Error::BadValue {
                    what: "log_format escape",
                    got: mode.to_string(),
                });
            }
        };
        rest = &rest[1..];
    }
    let mut value = String::new();
    for chunk in rest {
        value.push_str(chunk);
    }
    Ok(LogFormatDef {
        name,
        escape,
        value: parse_value_with_vars(&value)?,
    })
}

pub(crate) fn parse_access_log_args(args: &[String]) -> Result<ParsedAccessLog, Error> {
    if args.is_empty() {
        return Err(Error::MissingArg("access_log"));
    }
    if args[0] == "off" {
        if args.len() != 1 {
            return Err(Error::BadValue {
                what: "access_log",
                got: args.join(" "),
            });
        }
        return Ok(ParsedAccessLog::Off);
    }

    let path = PathBuf::from(&args[0]);
    let syslog = match args[0].strip_prefix("syslog:") {
        Some(raw) => Some(parse_syslog_peer(raw)?),
        None => None,
    };
    let mut format: Option<String> = None;
    let mut condition: Option<Vec<ValuePart>> = None;
    let mut saw_condition = false;
    for token in &args[1..] {
        if let Some(expr) = token.strip_prefix("if=") {
            if condition.is_some() {
                return Err(Error::BadValue {
                    what: "access_log if",
                    got: token.clone(),
                });
            }
            condition = Some(parse_value_with_vars(expr)?);
            saw_condition = true;
            continue;
        }
        if saw_condition {
            return Err(Error::BadValue {
                what: "access_log",
                got: token.clone(),
            });
        }
        if format.is_none() {
            format = Some(token.clone());
            continue;
        }
        return Err(Error::BadValue {
            what: "access_log",
            got: token.clone(),
        });
    }

    Ok(ParsedAccessLog::Entry(AccessLog {
        path,
        syslog,
        format,
        condition,
    }))
}

pub(crate) fn parse_error_log_args(args: &[String]) -> Result<ErrorLog, Error> {
    if args.is_empty() {
        return Err(Error::MissingArg("error_log"));
    }
    if args.len() > 2 {
        return Err(Error::BadValue {
            what: "error_log",
            got: args.join(" "),
        });
    }
    let level = match args.get(1) {
        Some(raw) => parse_error_log_level(raw)?,
        None => ErrorLogLevel::Error,
    };
    Ok(ErrorLog {
        target: parse_error_log_target(&args[0])?,
        level,
    })
}

pub(crate) fn parse_error_log_target(raw: &str) -> Result<ErrorLogTarget, Error> {
    if raw == "stderr" {
        return Ok(ErrorLogTarget::Stderr);
    }
    if let Some(syslog) = raw.strip_prefix("syslog:") {
        return Ok(ErrorLogTarget::Syslog(parse_error_log_syslog_target(
            syslog,
        )?));
    }
    Ok(ErrorLogTarget::File(PathBuf::from(raw)))
}

pub(crate) fn parse_error_log_syslog_target(raw: &str) -> Result<ErrorLogSyslogTarget, Error> {
    let mut server: Option<ErrorLogSyslogServer> = None;
    let mut tag: Option<String> = None;

    for part in raw.split(',') {
        if part.is_empty() {
            return Err(Error::BadValue {
                what: "error_log syslog",
                got: raw.to_string(),
            });
        }
        if part == "nohostname" {
            continue;
        }
        if let Some(v) = part.strip_prefix("server=") {
            if server.is_some() {
                return Err(Error::BadValue {
                    what: "error_log syslog",
                    got: raw.to_string(),
                });
            }
            server = Some(parse_error_log_syslog_server(v)?);
            continue;
        }
        if let Some(v) = part.strip_prefix("tag=") {
            if v.is_empty() || tag.is_some() {
                return Err(Error::BadValue {
                    what: "error_log syslog",
                    got: raw.to_string(),
                });
            }
            tag = Some(v.to_string());
            continue;
        }
        // Accepted but currently not used for our `log_not_found` writes.
        if let Some(v) = part.strip_prefix("facility=") {
            if v.is_empty() {
                return Err(Error::BadValue {
                    what: "error_log syslog",
                    got: raw.to_string(),
                });
            }
            continue;
        }
        if let Some(v) = part.strip_prefix("severity=") {
            if parse_error_log_level(v).is_err() {
                return Err(Error::BadValue {
                    what: "error_log syslog",
                    got: raw.to_string(),
                });
            }
            continue;
        }
        return Err(Error::BadValue {
            what: "error_log syslog",
            got: raw.to_string(),
        });
    }

    let server = server.ok_or_else(|| Error::BadValue {
        what: "error_log syslog",
        got: raw.to_string(),
    })?;
    Ok(ErrorLogSyslogTarget { server, tag })
}

/// RFC 3164 facility names, by code, as nginx spells them.
const SYSLOG_FACILITIES: [&str; 24] = [
    "kern", "user", "mail", "daemon", "auth", "intern", "lpr", "news", "uucp", "clock", "authpriv",
    "ftp", "ntp", "audit", "alert", "cron", "local0", "local1", "local2", "local3", "local4",
    "local5", "local6", "local7",
];

/// RFC 3164 severities, by code, as nginx spells them ("error", "warn").
const SYSLOG_SEVERITIES: [&str; 8] = [
    "emerg", "alert", "crit", "error", "warn", "notice", "info", "debug",
];

/// The parameters after `syslog:`, as ngx_syslog_process_conf: `server=`
/// is required; `facility=` (default local7), `severity=` (default info),
/// `tag=` (up to 32 letters, digits and `_`) and `nohostname` are
/// optional, each at most once.
pub(crate) fn parse_syslog_peer(raw: &str) -> Result<SyslogPeer, Error> {
    let bad = |got: &str| Error::BadValue {
        what: "syslog",
        got: got.to_string(),
    };
    let lookup = |names: &[&str], v: &str| names.iter().position(|n| *n == v).map(|i| i as u8);
    let mut server = None;
    let mut facility = None;
    let mut severity = None;
    let mut tag = None;
    let mut nohostname = false;
    for part in raw.split(',') {
        if let Some(v) = part.strip_prefix("server=") {
            if server.is_some() {
                return Err(bad(part));
            }
            server = Some(parse_error_log_syslog_server(v)?);
        } else if let Some(v) = part.strip_prefix("facility=") {
            if facility.is_some() {
                return Err(bad(part));
            }
            facility = Some(lookup(&SYSLOG_FACILITIES, v).ok_or_else(|| bad(part))?);
        } else if let Some(v) = part.strip_prefix("severity=") {
            if severity.is_some() {
                return Err(bad(part));
            }
            severity = Some(lookup(&SYSLOG_SEVERITIES, v).ok_or_else(|| bad(part))?);
        } else if let Some(v) = part.strip_prefix("tag=") {
            let valid = !v.is_empty()
                && v.len() <= 32
                && v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
            if tag.is_some() || !valid {
                return Err(bad(part));
            }
            tag = Some(v.to_string());
        } else if part == "nohostname" {
            nohostname = true;
        } else {
            return Err(bad(part));
        }
    }
    Ok(SyslogPeer {
        server: server.ok_or_else(|| bad(raw))?,
        facility: facility.unwrap_or(23),
        severity: severity.unwrap_or(6),
        tag,
        nohostname,
    })
}

pub(crate) fn parse_error_log_syslog_server(raw: &str) -> Result<ErrorLogSyslogServer, Error> {
    if raw.is_empty() {
        return Err(Error::BadValue {
            what: "error_log syslog server",
            got: raw.to_string(),
        });
    }
    if let Some(path) = raw.strip_prefix("unix:") {
        if path.is_empty() {
            return Err(Error::BadValue {
                what: "error_log syslog server",
                got: raw.to_string(),
            });
        }
        return Ok(ErrorLogSyslogServer::Unix(PathBuf::from(path)));
    }
    if raw.parse::<SocketAddr>().is_ok() || raw.rfind(':').is_some() {
        return Ok(ErrorLogSyslogServer::Udp(raw.to_string()));
    }
    Ok(ErrorLogSyslogServer::Udp(format!("{raw}:514")))
}

pub(crate) fn parse_error_log_level(raw: &str) -> Result<ErrorLogLevel, Error> {
    match raw {
        "emerg" => Ok(ErrorLogLevel::Emerg),
        "alert" => Ok(ErrorLogLevel::Alert),
        "crit" => Ok(ErrorLogLevel::Crit),
        "error" => Ok(ErrorLogLevel::Error),
        "warn" => Ok(ErrorLogLevel::Warn),
        "notice" => Ok(ErrorLogLevel::Notice),
        "info" => Ok(ErrorLogLevel::Info),
        "debug" => Ok(ErrorLogLevel::Debug),
        _ => Err(Error::BadValue {
            what: "error_log level",
            got: raw.to_string(),
        }),
    }
}
