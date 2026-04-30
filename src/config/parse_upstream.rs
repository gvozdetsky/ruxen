//! `upstream { ... }` block parser, `proxy_pass` and the `proxy_*`
//! directive arg parsers. `validate_proxy_upstream_refs` cross-references
//! upstream block names against `proxy_pass` references after the full
//! tree has been parsed.

use std::net::SocketAddr;
use super::*;

/// Parse `try_files arg1 arg2 ... fallback`. The last argument is the
/// terminal fallback; everything before it is a probe. Matches
/// `ngx_http_try_files_module.c::ngx_http_try_files` — trailing `/` on a
/// non-final argument marks a directory-test probe; a final argument
/// starting with `=` is a status-code fallback; `@name` is a named
/// location fallback.
/// Cross-reference every `Handler::Proxy(ProxyPass::UpstreamRef)` against
/// the http-scope upstream block names. nginx itself defers this to its
/// post-parse pass (`ngx_http_init_upstream`); we run an equivalent walk
/// at the end of `parse()` so `ruxen -t` catches typos before startup.
pub(crate) fn validate_proxy_upstream_refs(http: &HttpConfig) -> Result<(), Error> {
    fn walk(loc: &Location, names: &[&str]) -> Result<(), Error> {
        if let Handler::Proxy(ProxyPass::UpstreamRef { name, .. }) = &loc.handler {
            if !names.iter().any(|n| *n == name) {
                return Err(Error::BadValue {
                    what: "proxy_pass upstream",
                    got: format!("undeclared upstream `{name}`"),
                });
            }
        }
        Ok(())
    }
    let names: Vec<&str> = http.upstreams.iter().map(|u| u.name.as_str()).collect();
    for s in &http.servers {
        for loc in &s.locations {
            walk(loc, &names)?;
        }
    }
    Ok(())
}

/// Parse `upstream NAME { server <host:port> [params]; ... }`. Validates
/// that the head args are `[NAME]` and the body has at least one `server`
/// entry (matching nginx's `ngx_http_upstream_module.c::ngx_http_upstream`).
pub(crate) fn parse_upstream_block(head: &[String], lx: &mut Lexer) -> Result<UpstreamBlock, Error> {
    if head.len() != 1 {
        return Err(Error::BadValue {
            what: "upstream",
            got: head.join(" "),
        });
    }
    let name = head[0].clone();
    if name.is_empty() {
        return Err(Error::MissingArg("upstream name"));
    }
    let mut servers: Vec<UpstreamServer> = Vec::new();
    let mut keepalive_max_idle: Option<u32> = None;
    let mut keepalive_requests: Option<u64> = None;
    let mut keepalive_idle_timeout_ms: Option<u64> = None;
    let mut keepalive_max_lifetime_ms: Option<u64> = None;
    let mut lb: LbAlgorithm = LbAlgorithm::RoundRobin;
    loop {
        let (args, term) = lx.read_directive()?;
        if args.is_empty() {
            return match term {
                Terminator::BlockClose => {
                    if servers.is_empty() {
                        return Err(Error::MissingArg("upstream server"));
                    }
                    Ok(UpstreamBlock {
                        name,
                        servers,
                        keepalive_max_idle,
                        keepalive_requests,
                        keepalive_idle_timeout_ms,
                        keepalive_max_lifetime_ms,
                        lb,
                    })
                }
                Terminator::Eof => Err(Error::UnclosedBlock),
                _ => Err(Error::UnexpectedEof),
            };
        }
        match (args[0].as_str(), &term) {
            ("server", Terminator::Semi) => {
                servers.push(parse_upstream_server_args(&args[1..])?);
            }
            ("server", _) => {
                return Err(Error::WrongTerminator {
                    name: "server".into(),
                    ctx: "upstream",
                });
            }
            ("least_conn", Terminator::Semi) => {
                if !matches!(lb, LbAlgorithm::RoundRobin) {
                    return Err(Error::Duplicate("least_conn"));
                }
                if args.len() != 1 {
                    return Err(Error::BadValue {
                        what: "least_conn",
                        got: args[1..].join(" "),
                    });
                }
                lb = LbAlgorithm::LeastConn;
            }
            ("keepalive", Terminator::Semi) => {
                if keepalive_max_idle.is_some() {
                    return Err(Error::Duplicate("keepalive"));
                }
                let v = args.get(1).ok_or(Error::MissingArg("keepalive"))?;
                let n: u32 = v.parse().map_err(|_| Error::BadValue {
                    what: "keepalive",
                    got: v.clone(),
                })?;
                if n == 0 {
                    return Err(Error::BadValue {
                        what: "keepalive (must be > 0)",
                        got: v.clone(),
                    });
                }
                keepalive_max_idle = Some(n);
            }
            ("keepalive_requests", Terminator::Semi) => {
                if keepalive_requests.is_some() {
                    return Err(Error::Duplicate("keepalive_requests"));
                }
                let v = args.get(1).ok_or(Error::MissingArg("keepalive_requests"))?;
                let n: u64 = v.parse().map_err(|_| Error::BadValue {
                    what: "keepalive_requests",
                    got: v.clone(),
                })?;
                keepalive_requests = Some(n);
            }
            ("keepalive_timeout", Terminator::Semi) => {
                if keepalive_idle_timeout_ms.is_some() {
                    return Err(Error::Duplicate("keepalive_timeout"));
                }
                let v = args.get(1).ok_or(Error::MissingArg("keepalive_timeout"))?;
                keepalive_idle_timeout_ms = Some(parse_duration_ms(v, "keepalive_timeout")?);
            }
            ("keepalive_time", Terminator::Semi) => {
                if keepalive_max_lifetime_ms.is_some() {
                    return Err(Error::Duplicate("keepalive_time"));
                }
                let v = args.get(1).ok_or(Error::MissingArg("keepalive_time"))?;
                keepalive_max_lifetime_ms = Some(parse_duration_ms(v, "keepalive_time")?);
            }
            (n, Terminator::Semi) if is_ignored_stmt(n) => {}
            (n, Terminator::BlockOpen) if is_ignored_block(n) => skip_block(lx)?,
            (other, _) => {
                return Err(Error::UnknownDirective {
                    name: other.into(),
                    ctx: "upstream",
                });
            }
        }
    }
}

pub(crate) fn parse_upstream_server_args(args: &[String]) -> Result<UpstreamServer, Error> {
    let host_port = args.first().ok_or(Error::MissingArg("server host:port"))?;
    if host_port.starts_with("unix:") {
        // UNIX-domain upstreams are out of v0.1 scope. Reject explicitly so
        // users get a clear "not yet" instead of a silent mis-resolution.
        return Err(Error::BadValue {
            what: "upstream server (unix: not supported)",
            got: host_port.clone(),
        });
    }
    let addr = resolve_host_port(host_port).map_err(|msg| Error::BadValue {
        what: "upstream server host:port",
        got: format!("{host_port}: {msg}"),
    })?;
    let mut weight: u32 = 1;
    let mut max_fails: u32 = 1;
    let mut fail_timeout_secs: u32 = 10;
    let mut down = false;
    let mut backup = false;
    for tok in &args[1..] {
        if let Some(v) = tok.strip_prefix("weight=") {
            weight = v.parse::<u32>().map_err(|_| Error::BadValue {
                what: "upstream weight",
                got: tok.clone(),
            })?;
            if weight == 0 {
                return Err(Error::BadValue {
                    what: "upstream weight",
                    got: tok.clone(),
                });
            }
        } else if let Some(v) = tok.strip_prefix("max_fails=") {
            max_fails = v.parse::<u32>().map_err(|_| Error::BadValue {
                what: "upstream max_fails",
                got: tok.clone(),
            })?;
        } else if let Some(v) = tok.strip_prefix("fail_timeout=") {
            fail_timeout_secs = parse_seconds_arg(v).map_err(|_| Error::BadValue {
                what: "upstream fail_timeout",
                got: tok.clone(),
            })?;
        } else if tok == "down" {
            down = true;
        } else if tok == "backup" {
            backup = true;
        } else {
            return Err(Error::BadValue {
                what: "upstream server param",
                got: tok.clone(),
            });
        }
    }
    Ok(UpstreamServer {
        addr,
        display: host_port.clone(),
        weight,
        max_fails,
        fail_timeout_secs,
        down,
        backup,
    })
}

/// Resolve `host:port` (or bare IPv4/IPv6 with port) using the OS resolver
/// at parse time. nginx itself does this via `getaddrinfo` for non-resolver
/// upstreams; we do the same. Picks the first resolved address — multi-A
/// expansion is not supported in v0.1.
pub(crate) fn resolve_host_port(s: &str) -> Result<SocketAddr, String> {
    use std::net::ToSocketAddrs;
    s.to_socket_addrs()
        .map_err(|e| e.to_string())?
        .next()
        .ok_or_else(|| "no addresses resolved".into())
}

/// Parse a `[N]s` / bare integer seconds value. Allows the `s` suffix only
/// (we don't need ms/m/h here — nginx's full time-value grammar is overkill
/// for `fail_timeout`).
pub(crate) fn parse_seconds_arg(s: &str) -> Result<u32, ()> {
    let core = s.strip_suffix('s').unwrap_or(s);
    core.parse::<u32>().map_err(|_| ())
}

/// Parse the single argument to `proxy_pass`. Accepted v0.1 forms:
///
/// - `http://NAME[/path]` — `NAME` is the upstream block name (resolved at
///   prepare time). `/path`, when present, triggers prefix-strip + prepend
///   path rewriting (only legal for prefix-match locations; rejected at
///   prepare time otherwise).
/// - `http://host:port[/path]` — literal peer; resolved at parse time.
/// - `http://host[/path]` — literal hostname, port defaults to 80.
///
/// `https://` is rejected (no TLS upstream in v0.1).
pub(crate) fn parse_proxy_pass_arg(args: &[String]) -> Result<ProxyPass, Error> {
    if args.len() != 1 {
        return Err(Error::BadValue {
            what: "proxy_pass",
            got: args.join(" "),
        });
    }
    let raw = &args[0];
    if raw.contains('$') {
        return Err(Error::BadValue {
            what: "proxy_pass ($var dynamic upstream not supported in v0.1; declare an upstream{} block)",
            got: raw.clone(),
        });
    }
    let after_scheme = raw.strip_prefix("http://").ok_or_else(|| Error::BadValue {
        what: "proxy_pass scheme (only http:// supported in v0.1)",
        got: raw.clone(),
    })?;
    if after_scheme.is_empty() {
        return Err(Error::MissingArg("proxy_pass authority"));
    }
    let (authority, request_path) = match after_scheme.find('/') {
        Some(slash) => {
            let path = &after_scheme[slash..];
            // A bare trailing "/" still counts as "URI part = /" for the
            // purposes of nginx's path-rewrite semantics. Pretending it
            // doesn't would forward the client URI unchanged; surprising.
            (&after_scheme[..slash], Some(path.to_string()))
        }
        None => (after_scheme, None),
    };
    if authority.is_empty() {
        return Err(Error::MissingArg("proxy_pass authority"));
    }
    // An "upstream name" is a bareword (no colon, no dot, no port). Anything
    // with a `:` or `.` is treated as a literal host:port. nginx itself
    // distinguishes by looking at whether the name matches a declared
    // upstream — we approximate by syntactic shape and resolve at prepare
    // time. (A bareword that doesn't match an upstream becomes a parse-time
    // error at prepare.)
    let looks_like_upstream_name = !authority.contains(':')
        && !authority.contains('.')
        && authority
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if looks_like_upstream_name {
        return Ok(ProxyPass::UpstreamRef {
            name: authority.to_string(),
            host_header: authority.to_string(),
            request_path,
        });
    }
    let host_port = if authority.contains(':') {
        authority.to_string()
    } else {
        format!("{authority}:80")
    };
    let addr = resolve_host_port(&host_port).map_err(|msg| Error::BadValue {
        what: "proxy_pass host:port",
        got: format!("{raw}: {msg}"),
    })?;
    Ok(ProxyPass::Direct {
        addr,
        host_header: authority.to_string(),
        request_path,
    })
}

/// Parse `proxy_set_header NAME VALUE;`. Empty values are legal — nginx
/// treats them as "do not forward this header" and so do we.
pub(crate) fn parse_proxy_set_header_args(args: &[String]) -> Result<ProxySetHeader, Error> {
    if args.len() != 2 {
        return Err(Error::BadValue {
            what: "proxy_set_header",
            got: args.join(" "),
        });
    }
    let name = args[0].clone();
    if name.is_empty() || !name.bytes().all(is_header_name_char) {
        return Err(Error::BadValue {
            what: "proxy_set_header name",
            got: name,
        });
    }
    let value = parse_value_with_vars(&args[1])?;
    Ok(ProxySetHeader { name, value })
}

pub(crate) fn parse_client_max_body_size_args(args: &[String]) -> Result<u64, Error> {
    if args.len() != 1 {
        return Err(Error::BadValue {
            what: "client_max_body_size",
            got: args.join(" "),
        });
    }
    let raw = &args[0];
    parse_size_bytes(raw).ok_or(Error::BadValue {
        what: "client_max_body_size",
        got: raw.clone(),
    })
}

/// Parse `proxy_next_upstream`'s flag list. Tokens come from a fixed set
/// (mirrors nginx's `ngx_http_proxy_next_upstream_masks` table). `off` is
/// a sentinel that turns the whole mask off and may not be combined with
/// other flags.
pub(crate) fn parse_proxy_next_upstream_args(args: &[String]) -> Result<ProxyNextUpstream, Error> {
    if args.is_empty() {
        return Err(Error::MissingArg("proxy_next_upstream"));
    }
    if args.len() == 1 && args[0] == "off" {
        return Ok(ProxyNextUpstream::OFF);
    }
    let mut mask = ProxyNextUpstream::default();
    for tok in args {
        match tok.as_str() {
            "off" => {
                return Err(Error::BadValue {
                    what: "proxy_next_upstream (`off` cannot combine with other flags)",
                    got: tok.clone(),
                });
            }
            "error" => mask.error = true,
            "timeout" => mask.timeout = true,
            "invalid_header" => mask.invalid_header = true,
            "http_500" => mask.http_500 = true,
            "http_502" => mask.http_502 = true,
            "http_503" => mask.http_503 = true,
            "http_504" => mask.http_504 = true,
            "http_403" => mask.http_403 = true,
            "http_404" => mask.http_404 = true,
            "http_429" => mask.http_429 = true,
            "non_idempotent" => mask.non_idempotent = true,
            // Accept-but-ignore the response-buffering-only flags so nginx
            // configs load cleanly. These trigger only when buffered
            // upstream output discovers an error mid-stream, which our
            // fully-buffered (M40) proxy can't reach.
            "updating" | "http_429_only" => {}
            other => {
                return Err(Error::BadValue {
                    what: "proxy_next_upstream flag",
                    got: other.to_string(),
                });
            }
        }
    }
    Ok(mask)
}

/// Parse a `proxy_*_timeout` argument. Single time-suffix value (`60s`,
/// `5000ms`, `1m`); bare integers default to seconds, matching nginx's
/// directive grammar (`ngx_conf_set_msec_slot`).
pub(crate) fn parse_proxy_timeout_args(args: &[String], what: &'static str) -> Result<u64, Error> {
    let raw = args.first().ok_or(Error::MissingArg(what))?;
    if args.len() != 1 {
        return Err(Error::BadValue {
            what,
            got: args.join(" "),
        });
    }
    parse_duration_ms(raw, what)
}

/// Parse `proxy_http_version 1.0|1.1;`. Stored as the minor digit so the
/// hot-path emit picks `b"HTTP/1.0"` or `b"HTTP/1.1"` with one byte swap.
pub(crate) fn parse_proxy_http_version_args(args: &[String]) -> Result<u8, Error> {
    let raw = args
        .first()
        .ok_or(Error::MissingArg("proxy_http_version"))?;
    if args.len() != 1 {
        return Err(Error::BadValue {
            what: "proxy_http_version",
            got: args.join(" "),
        });
    }
    match raw.as_str() {
        "1.0" => Ok(0),
        "1.1" => Ok(1),
        _ => Err(Error::BadValue {
            what: "proxy_http_version",
            got: raw.clone(),
        }),
    }
}

