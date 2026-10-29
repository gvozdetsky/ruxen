//! `upstream { ... }` block parser, `proxy_pass` and the `proxy_*`
//! directive arg parsers. `validate_proxy_upstream_refs` cross-references
//! upstream block names against `proxy_pass` references after the full
//! tree has been parsed.

use super::*;
use std::net::SocketAddr;

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
        if let Handler::Proxy(ProxyPass::UpstreamRef { name, .. }) = &loc.handler
            && !names.iter().any(|n| *n == name)
        {
            return Err(Error::BadValue {
                what: "proxy_pass upstream",
                got: format!("undeclared upstream `{name}`"),
            });
        }
        Ok(())
    }
    // ngx_http_upstream_sticky_learn: a zone serves one upstream.
    let mut zones: Vec<(&str, &str)> = Vec::new();
    for u in &http.upstreams {
        if let Some(StickyConf::Learn(learn)) = &u.sticky {
            if let Some((_, first)) = zones.iter().find(|(z, _)| *z == learn.zone) {
                return Err(sticky_message(format!(
                    "sticky zone \"{}\" is already used in upstream \"{first}\"",
                    learn.zone
                )));
            }
            zones.push((&learn.zone, &u.name));
        }
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
pub(crate) fn parse_upstream_block(
    head: &[String],
    lx: &mut Lexer,
) -> Result<UpstreamBlock, Error> {
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
    let mut keepalive_local = false;
    let mut keepalive_requests: Option<u64> = None;
    let mut keepalive_idle_timeout_ms: Option<u64> = None;
    let mut keepalive_max_lifetime_ms: Option<u64> = None;
    let mut lb: LbAlgorithm = LbAlgorithm::RoundRobin;
    let mut zone: Option<String> = None;
    let mut resolver: Option<ResolverConf> = None;
    let mut resolver_timeout_ms: Option<u64> = None;
    let mut sticky: Option<StickyConf> = None;
    loop {
        let (args, term) = lx.read_directive()?;
        if args.is_empty() {
            return match term {
                Terminator::BlockClose => {
                    if servers.is_empty() {
                        return Err(Error::MissingArg("upstream server"));
                    }
                    // ngx_http_upstream_init_round_robin.
                    if zone.is_none() && servers.iter().any(|s| s.resolve.is_some()) {
                        return Err(Error::Text(format!(
                            "resolving names at run time requires upstream \"{name}\" \
                             to be in shared memory"
                        )));
                    }
                    // Peer IDs are per configured peer yet (#600, #597).
                    if sticky.is_some() && servers.iter().any(|s| s.resolve.is_some()) {
                        return Err(Error::Text(format!(
                            "\"sticky\" with \"resolve\" servers is not supported yet \
                             in upstream \"{name}\""
                        )));
                    }
                    Ok(UpstreamBlock {
                        name,
                        servers,
                        keepalive_max_idle,
                        keepalive_local,
                        keepalive_requests,
                        keepalive_idle_timeout_ms,
                        keepalive_max_lifetime_ms,
                        lb,
                        zone,
                        resolver,
                        resolver_timeout_ms,
                        sticky,
                    })
                }
                Terminator::Eof => Err(Error::UnclosedBlock),
                _ => Err(Error::UnexpectedEof),
            };
        }
        match (args[0].as_str(), &term) {
            ("server", Terminator::Semi) => {
                let server = parse_upstream_server_args(&args[1..])?;
                if server[0].backup && matches!(lb, LbAlgorithm::Hash { .. } | LbAlgorithm::IpHash)
                {
                    return Err(Error::BadValue {
                        what: "upstream server param (balancing method does not support it)",
                        got: "backup".into(),
                    });
                }
                servers.extend(server);
            }
            ("server", _) => {
                return Err(Error::WrongTerminator {
                    name: "server".into(),
                    ctx: "upstream",
                });
            }
            ("least_conn", Terminator::Semi) => {
                if args.len() != 1 {
                    return Err(Error::BadValue {
                        what: "least_conn",
                        got: args[1..].join(" "),
                    });
                }
                warn_lb_redefined(lx, &lb, &mut sticky);
                lb = LbAlgorithm::LeastConn;
            }
            // ngx_http_upstream_hash / ngx_http_upstream_ip_hash: a method
            // set before is replaced with a warning. Neither takes `backup`
            // servers after it; ones listed before stay out of the hash and
            // serve only its round-robin fallback, as in nginx.
            ("hash", Terminator::Semi) => {
                let consistent = match &args[1..] {
                    [_] => false,
                    [_, c] if c == "consistent" => true,
                    [_, other] => {
                        return Err(Error::BadValue {
                            what: "hash parameter",
                            got: other.clone(),
                        });
                    }
                    [] => return Err(Error::MissingArg("hash key")),
                    _ => {
                        return Err(Error::BadValue {
                            what: "hash",
                            got: args[1..].join(" "),
                        });
                    }
                };
                warn_lb_redefined(lx, &lb, &mut sticky);
                lb = LbAlgorithm::Hash {
                    key: parse_value_with_vars(&args[1])?,
                    consistent,
                };
            }
            ("ip_hash", Terminator::Semi) => {
                if args.len() != 1 {
                    return Err(Error::BadValue {
                        what: "ip_hash",
                        got: args[1..].join(" "),
                    });
                }
                warn_lb_redefined(lx, &lb, &mut sticky);
                lb = LbAlgorithm::IpHash;
            }
            // ngx_http_upstream_zone: `zone name [size]`. Workers are
            // threads, so the size bounds nothing; it is checked as nginx
            // checks it.
            ("zone", Terminator::Semi) => {
                if zone.is_some() {
                    return Err(Error::Duplicate("zone"));
                }
                let (name, size) = match &args[1..] {
                    [name] => (name, None),
                    [name, size] => (name, Some(size)),
                    _ => {
                        return Err(Error::BadValue {
                            what: "zone",
                            got: args[1..].join(" "),
                        });
                    }
                };
                if name.is_empty() {
                    return Err(Error::BadValue {
                        what: "zone name",
                        got: name.clone(),
                    });
                }
                if let Some(size) = size {
                    let bytes = parse_size_bytes(size).ok_or_else(|| Error::BadValue {
                        what: "zone size",
                        got: size.clone(),
                    })?;
                    if bytes < 8 * 4096 {
                        return Err(Error::BadValue {
                            what: "zone (zone is too small)",
                            got: size.clone(),
                        });
                    }
                }
                zone = Some(name.clone());
            }
            // ngx_http_upstream_resolver and the msec slot (#597).
            ("resolver", Terminator::Semi) => {
                if resolver.is_some() {
                    return Err(Error::Duplicate("resolver"));
                }
                resolver = Some(parse_resolver_args(&args[1..])?);
            }
            ("resolver_timeout", Terminator::Semi) => {
                if resolver_timeout_ms.is_some() {
                    return Err(Error::Duplicate("resolver_timeout"));
                }
                resolver_timeout_ms =
                    Some(parse_proxy_timeout_args(&args[1..], "resolver_timeout")?);
            }
            ("sticky", Terminator::Semi) => {
                if sticky.is_some() {
                    return Err(sticky_error("is duplicate"));
                }
                sticky = Some(parse_sticky_args(&args[1..])?);
            }
            // ngx_http_upstream_keepalive: `keepalive N [local];`, where 0
            // turns off the pool that 1.29.7 gives every upstream block.
            ("keepalive", Terminator::Semi) => {
                if keepalive_max_idle.is_some() {
                    return Err(Error::Duplicate("keepalive"));
                }
                let v = args.get(1).ok_or(Error::MissingArg("keepalive"))?;
                let n: u32 = v.parse().map_err(|_| Error::BadValue {
                    what: "keepalive",
                    got: v.clone(),
                })?;
                match args.get(2).map(String::as_str) {
                    None => {}
                    Some("local") if args.len() == 3 => keepalive_local = true,
                    Some(_) => {
                        return Err(Error::BadValue {
                            what: "keepalive parameter",
                            got: args[2..].join(" "),
                        });
                    }
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
            (n, Terminator::Semi) if is_ignored_stmt(n) => compat::ignored(lx, &args),
            (n, Terminator::BlockOpen) if is_ignored_block(n) => {
                compat::ignored_block(lx, &args);
                skip_block(lx)?
            }
            (_, _) => {
                compat::unknown(lx, &args, &term, "upstream")?;
            }
        }
    }
}

/// A balancing method after another, or after `sticky`, replaces it with
/// a warning: nginx's `sticky` hooks the method set before it.
fn warn_lb_redefined(lx: &mut Lexer, lb: &LbAlgorithm, sticky: &mut Option<StickyConf>) {
    if !matches!(lb, LbAlgorithm::RoundRobin) || sticky.is_some() {
        lx.warn("load balancing method redefined".into());
    }
    *sticky = None;
}

fn sticky_error(msg: &str) -> Error {
    Error::Directive {
        name: "sticky",
        msg: msg.to_string(),
    }
}

/// A message nginx logs as it is (ngx_conf_log_error).
fn sticky_message(msg: String) -> Error {
    Error::Message(crate::arena::leak(msg.into_boxed_str()))
}

/// `$name` as one variable, the way ngx_http_get_variable_index takes it.
fn sticky_var(arg: &str) -> Result<Vec<ValuePart>, Error> {
    let parts = parse_value_with_vars(arg)?;
    match parts.as_slice() {
        [ValuePart::Var(_)] => Ok(parts),
        _ => Err(sticky_message(format!("invalid variable name \"{arg}\""))),
    }
}

/// `sticky cookie | route | learn ...` (ngx_http_upstream_sticky).
fn parse_sticky_args(args: &[String]) -> Result<StickyConf, Error> {
    if args.len() < 2 {
        return Err(sticky_message(
            "invalid number of arguments in \"sticky\" directive".into(),
        ));
    }
    match args[0].as_str() {
        "cookie" => parse_sticky_cookie(&args[1..]).map(StickyConf::Cookie),
        "route" => {
            let mut lookup = Vec::new();
            for a in &args[1..] {
                if !a.starts_with('$') {
                    return Err(sticky_message(format!("invalid variable name \"{a}\"")));
                }
                lookup.push(sticky_var(a)?);
            }
            Ok(StickyConf::Route { lookup })
        }
        "learn" => parse_sticky_learn(&args[1..]).map(StickyConf::Learn),
        other => Err(sticky_message(format!("unknown parameter \"{other}\""))),
    }
}

fn parse_sticky_cookie(args: &[String]) -> Result<StickyCookie, Error> {
    if args[0].is_empty() {
        return Err(sticky_error("empty cookie name"));
    }
    let mut c = StickyCookie {
        name: args[0].clone(),
        domain: None,
        path: None,
        expires: None,
        httponly: false,
        secure: false,
        samesite: None,
    };
    for a in &args[1..] {
        if let Some(v) = a.strip_prefix("domain=") {
            if c.domain.is_some() {
                return Err(sticky_error("parameter \"domain\" is duplicate"));
            }
            if v.is_empty() {
                return Err(sticky_error("no value for \"domain\""));
            }
            c.domain = Some(parse_value_with_vars(v)?);
        } else if let Some(v) = a.strip_prefix("path=") {
            if c.path.is_some() {
                return Err(sticky_error("parameter \"path\" is duplicate"));
            }
            if v.is_empty() {
                return Err(sticky_error("no value for \"path\""));
            }
            c.path = Some(v.to_string());
        } else if let Some(v) = a.strip_prefix("expires=") {
            if c.expires.is_some() {
                return Err(sticky_error("parameter \"expires\" is duplicate"));
            }
            c.expires = Some(if v == "max" {
                StickyExpires::Max
            } else {
                match parse_time(v, true) {
                    Some(secs) if secs >= 0 => StickyExpires::Secs(secs as u64),
                    _ => return Err(sticky_error("invalid \"expires\" parameter value")),
                }
            });
        } else if a == "httponly" {
            if c.httponly {
                return Err(sticky_error("parameter \"httponly\" is duplicate"));
            }
            c.httponly = true;
        } else if a == "secure" {
            if c.secure {
                return Err(sticky_error("parameter \"secure\" is duplicate"));
            }
            c.secure = true;
        } else if let Some(v) = a.strip_prefix("samesite=") {
            if c.samesite.is_some() {
                return Err(sticky_error("parameter \"samesite\" is duplicate"));
            }
            let parts = parse_value_with_vars(v)?;
            let is_static = parts.iter().all(|p| matches!(p, ValuePart::Literal(_)));
            if is_static && !is_samesite(v.as_bytes()) {
                return Err(sticky_error("invalid \"samesite\" parameter value"));
            }
            c.samesite = Some(parts);
        } else {
            return Err(sticky_message(format!("unknown parameter \"{a}\"")));
        }
    }
    Ok(c)
}

/// `strict`, `lax` or `none`, any case (ngx_http_upstream_sticky_samesite).
pub(crate) fn is_samesite(v: &[u8]) -> bool {
    [&b"strict"[..], b"lax", b"none"]
        .iter()
        .any(|s| s.eq_ignore_ascii_case(v))
}

fn parse_sticky_learn(args: &[String]) -> Result<StickyLearn, Error> {
    let mut zone: Option<(String, u64)> = None;
    let mut timeout_ms: Option<u64> = None;
    let mut lookup = Vec::new();
    let mut create = Vec::new();
    let mut header = false;
    for a in args {
        if let Some(v) = a.strip_prefix("zone=") {
            if zone.is_some() {
                return Err(sticky_error("duplicate zone"));
            }
            let Some((name, size)) = v.split_once(':') else {
                return Err(sticky_error("zone size is not specified"));
            };
            if name.is_empty() {
                return Err(sticky_error("zone name is not specified"));
            }
            let size = parse_size_bytes(size).ok_or_else(|| sticky_error("invalid zone size"))?;
            // 32k ~ 200 sessions, as nginx says.
            if size < 8 * 4096 {
                return Err(sticky_error("zone is too small"));
            }
            zone = Some((name.to_string(), size));
        } else if let Some(v) = a.strip_prefix("timeout=") {
            if timeout_ms.is_some() {
                return Err(sticky_error("duplicate timeout"));
            }
            match parse_time(v, false) {
                Some(ms) if ms > 0 => timeout_ms = Some(ms as u64),
                _ => return Err(sticky_error("invalid timeout")),
            }
        } else if let Some(v) = a.strip_prefix("create=") {
            if !v.starts_with('$') {
                return Err(sticky_error("missing variable in the \"create\" parameter"));
            }
            create.push(sticky_var(v)?);
        } else if let Some(v) = a.strip_prefix("lookup=") {
            if !v.starts_with('$') {
                return Err(sticky_error("missing variable in the \"lookup\" parameter"));
            }
            lookup.push(sticky_var(v)?);
        } else if a == "header" {
            header = true;
        } else {
            return Err(sticky_message(format!("unknown parameter \"{a}\"")));
        }
    }
    if lookup.is_empty() {
        return Err(sticky_error("\"lookup\" parameter is not specified"));
    }
    if create.is_empty() {
        return Err(sticky_error("\"create\" parameter is not specified"));
    }
    let Some((zone, zone_size)) = zone else {
        return Err(sticky_error("\"zone\" parameter is not specified"));
    };
    Ok(StickyLearn {
        lookup,
        create,
        zone,
        zone_size,
        timeout_ms: timeout_ms.unwrap_or(600_000),
        header,
    })
}

/// One `server` line: a server per address its name resolves to, all with
/// the line's parameters (ngx_http_upstream_init_round_robin counts
/// `server[i].naddrs` peers).
pub(crate) fn parse_upstream_server_args(args: &[String]) -> Result<Vec<UpstreamServer>, Error> {
    let host_port = args.first().ok_or(Error::MissingArg("server host:port"))?;
    // ngx_http_upstream_server: a name with `resolve` is asked at run time
    // (`u.no_resolve`); an address stays one.
    let resolve = args[1..].iter().any(|a| a == "resolve");
    let service = args[1..].iter().find_map(|a| a.strip_prefix("service="));
    let unix = strip_unix_prefix(host_port);
    let name = match unix {
        None if resolve => runtime_name(host_port)?,
        _ => None,
    };
    if let Some(service) = service {
        let refuse = |problem: &str| {
            Err(Error::Text(format!(
                "service upstream \"{host_port}\" {problem}"
            )))
        };
        if service.is_empty() {
            return Err(Error::Message("service is empty"));
        }
        if !resolve {
            return refuse("requires \"resolve\" parameter");
        }
        if with_default_port(host_port, 0) == *host_port {
            return refuse("may not have port");
        }
        if name.is_none() {
            return refuse("requires domain name");
        }
    }
    let addrs = match (unix, &name) {
        (Some(path), _) => vec![unix_socket_path(path).map_err(|what| Error::BadValue {
            what,
            got: host_port.clone(),
        })?],
        (None, Some((_, port))) => {
            vec![UpstreamAddr::Inet(SocketAddr::from(([0, 0, 0, 0], *port)))]
        }
        // ngx_http_upstream_server: the port defaults to 80.
        (None, None) => resolve_upstream_host(&with_default_port(host_port, 80), host_port)?
            .into_iter()
            .map(UpstreamAddr::Inet)
            .collect(),
    };
    let mut weight: u32 = 1;
    let mut max_fails: u32 = 1;
    let mut fail_timeout_secs: u32 = 10;
    let mut max_conns: u32 = 0;
    let mut down = false;
    let mut drain = false;
    let mut backup = false;
    let mut route: Option<String> = None;
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
        } else if let Some(v) = tok.strip_prefix("max_conns=") {
            max_conns = v.parse::<u32>().map_err(|_| Error::BadValue {
                what: "upstream max_conns",
                got: tok.clone(),
            })?;
        } else if tok == "down" {
            down = true;
            drain = false;
        } else if tok == "drain" {
            // ngx_http_upstream_server: the last of `down` / `drain` wins.
            down = true;
            drain = true;
        } else if let Some(v) = tok.strip_prefix("route=") {
            if v.is_empty() {
                return Err(Error::Message("route is empty"));
            }
            if v.len() > 32 {
                return Err(Error::Message("route is longer than 32"));
            }
            route = Some(v.to_string());
        } else if tok == "backup" {
            backup = true;
        } else if tok == "resolve" || tok.starts_with("service=") {
        } else {
            return Err(Error::BadValue {
                what: "upstream server param",
                got: tok.clone(),
            });
        }
    }
    Ok(addrs
        .into_iter()
        .map(|addr| UpstreamServer {
            addr,
            resolve: name.as_ref().map(|(host, _)| host.clone()),
            service: service.map(str::to_string),
            display: host_port.clone(),
            weight,
            max_fails,
            fail_timeout_secs,
            max_conns,
            down,
            backup,
            drain,
            route: route.clone(),
        })
        .collect())
}

/// `host[:port]` of a `resolve` server as ngx_parse_inet_url reads it
/// with `no_resolve`: the name (lower case, as the resolver asks it) and
/// the port (80 by default); `None` for an IP address.
fn runtime_name(host_port: &str) -> Result<Option<(String, u16)>, Error> {
    let with_port = with_default_port(host_port, 80);
    if with_port.parse::<SocketAddr>().is_ok() || host_port.starts_with('[') {
        return Ok(None);
    }
    let invalid_port = || Error::UpstreamUrl {
        problem: "invalid port",
        url: host_port.to_string(),
    };
    let (host, port) = with_port.rsplit_once(':').ok_or_else(invalid_port)?;
    let port: u16 = port.parse().map_err(|_| invalid_port())?;
    if port == 0 {
        return Err(invalid_port());
    }
    let host = host.strip_suffix('.').unwrap_or(host);
    if crate::resolver::encode_name(host.as_bytes()).is_none() {
        return Err(Error::UpstreamUrl {
            problem: "host not found",
            url: host_port.to_string(),
        });
    }
    Ok(Some((host.to_ascii_lowercase(), port)))
}

/// The part after `unix:` (any case, as ngx_parse_url), if `s` names a
/// UNIX-domain socket.
fn strip_unix_prefix(s: &str) -> Option<&str> {
    s.get(..5)
        .filter(|scheme| scheme.eq_ignore_ascii_case("unix:"))
        .map(|_| &s[5..])
}

/// A UNIX-domain socket address, checked as ngx_parse_unix_domain_url
/// does: a path is required, and it has to fit `sun_path` with its NUL.
/// The socket itself need not exist yet.
fn unix_socket_path(path: &str) -> Result<UpstreamAddr, &'static str> {
    const SUN_PATH_LEN: usize = 108;
    if path.is_empty() {
        return Err("upstream address (no path in the unix domain socket)");
    }
    if path.len() + 1 > SUN_PATH_LEN {
        return Err("upstream address (too long path in the unix domain socket)");
    }
    Ok(UpstreamAddr::Unix(PathBuf::from(path)))
}

/// Resolve `host:port` (or bare IPv4/IPv6 with port) using the OS resolver
/// at parse time. nginx itself does this via `getaddrinfo` for non-resolver
/// upstreams; we do the same. Picks the first resolved address — multi-A
/// expansion is not supported in v0.1.
/// `host[:port]` with `port` when it names none, as ngx_parse_inet_url's
/// `default_port`; an IPv6 address is in brackets (`[::1]`, `[::1]:8080`).
fn with_default_port(host_port: &str, port: u16) -> String {
    let has_port = match host_port.strip_prefix('[') {
        Some(rest) => rest.contains("]:"),
        None => host_port.contains(':'),
    };
    if has_port {
        host_port.to_string()
    } else {
        format!("{host_port}:{port}")
    }
}

pub(crate) fn resolve_host_port(s: &str) -> Result<Vec<SocketAddr>, String> {
    resolve_host_port_io(s).map_err(|e| e.to_string())
}

/// `resolve_host_port`, an `upstream` address's, refused in nginx's words:
/// `invalid port in upstream "…"` (std's `InvalidInput`), else `host not
/// found in upstream "…"`.
fn resolve_upstream_host(host_port: &str, as_written: &str) -> Result<Vec<SocketAddr>, Error> {
    resolve_host_port_io(host_port).map_err(|e| Error::UpstreamUrl {
        problem: if e.kind() == std::io::ErrorKind::InvalidInput {
            "invalid port"
        } else {
            "host not found"
        },
        url: as_written.to_string(),
    })
}

fn resolve_host_port_io(s: &str) -> std::io::Result<Vec<SocketAddr>> {
    use std::net::ToSocketAddrs;
    // Every address, in getaddrinfo's order: each is a peer, as
    // ngx_inet_resolve_host makes it (#330).
    let mut addrs: Vec<SocketAddr> = Vec::new();
    for addr in s.to_socket_addrs()? {
        if !addrs.contains(&addr) {
            addrs.push(addr);
        }
    }
    if addrs.is_empty() {
        return Err(std::io::Error::other("no addresses resolved"));
    }
    Ok(addrs)
}

/// `resolver address … [valid=time] [ipv4=on|off] [ipv6=on|off]`, as
/// ngx_resolver_create reads it: an address is `host[:port]` (port 53),
/// and a host name stands for all its addresses, looked up now.
pub(crate) fn parse_resolver_args(args: &[String]) -> Result<ResolverConf, Error> {
    static NEXT_ID: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    if args.is_empty() {
        return Err(Error::MissingArg("resolver"));
    }
    let invalid = |arg: &str| Error::BadValue {
        what: "resolver parameter",
        got: arg.to_string(),
    };
    let mut conf = ResolverConf {
        id: NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        servers: Vec::new(),
        valid_secs: None,
        ipv4: true,
        ipv6: true,
    };
    for arg in args {
        if let Some(time) = arg.strip_prefix("valid=") {
            let secs = super::parse_server::parse_duration_secs(time, "resolver valid")
                .map_err(|_| invalid(arg))?;
            conf.valid_secs = (secs > 0).then_some(secs);
        } else if let Some(on) = arg.strip_prefix("ipv4=") {
            conf.ipv4 = match on {
                "on" => true,
                "off" => false,
                _ => return Err(invalid(arg)),
            };
        } else if let Some(on) = arg.strip_prefix("ipv6=") {
            conf.ipv6 = match on {
                "on" => true,
                "off" => false,
                _ => return Err(invalid(arg)),
            };
        } else {
            let addrs =
                resolve_host_port(&with_default_port(arg, 53)).map_err(|e| Error::BadValue {
                    what: "resolver",
                    got: format!("{e} in resolver \"{arg}\""),
                })?;
            conf.servers.extend(addrs);
        }
    }
    if !conf.ipv4 && !conf.ipv6 {
        return Err(Error::BadValue {
            what: "resolver",
            got: "\"ipv4\" and \"ipv6\" cannot both be \"off\"".into(),
        });
    }
    if conf.servers.is_empty() {
        return Err(Error::BadValue {
            what: "resolver",
            got: "no name servers defined".into(),
        });
    }
    Ok(conf)
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
    // With variables the URL is rendered and parsed per request, as
    // nginx's ngx_http_proxy_eval does; its scheme is checked then.
    if raw.contains('$') {
        return Ok(ProxyPass::Variable {
            url: parse_value_with_vars(raw)?,
        });
    }
    // `https://`: TLS to the upstream (#116), port 443 by default.
    let (after_scheme, tls) = match (raw.strip_prefix("http://"), raw.strip_prefix("https://")) {
        (Some(rest), _) => (rest, false),
        (None, Some(rest)) => (rest, true),
        (None, None) => {
            return Err(Error::BadValue {
                what: "proxy_pass scheme (http:// or https://)",
                got: raw.clone(),
            });
        }
    };
    if after_scheme.is_empty() {
        return Err(Error::MissingArg("proxy_pass authority"));
    }
    // `unix:/path[:uri]`: the path ends at the next `:`, the URI follows
    // it, and the upstream sees `Host: localhost` (ngx_parse_unix_domain_url
    // with uri_part, ngx_http_proxy_set_vars).
    if let Some(rest) = strip_unix_prefix(after_scheme) {
        let (path, uri) = match rest.find(':') {
            Some(colon) => (&rest[..colon], &rest[colon + 1..]),
            None => (rest, ""),
        };
        let addr = unix_socket_path(path).map_err(|what| Error::BadValue {
            what,
            got: raw.clone(),
        })?;
        return Ok(ProxyPass::Direct {
            addrs: vec![addr],
            host_header: "localhost".to_string(),
            request_path: (!uri.is_empty()).then(|| uri.to_string()),
            tls,
        });
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
            tls,
        });
    }
    let host_port = with_default_port(authority, if tls { 443 } else { 80 });
    let addrs = resolve_upstream_host(&host_port, authority)?;
    Ok(ProxyPass::Direct {
        addrs: addrs.into_iter().map(UpstreamAddr::Inet).collect(),
        host_header: authority.to_string(),
        request_path,
        tls,
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

/// `client_body_buffer_size size;` (ngx_conf_set_size_slot).
pub(crate) fn parse_client_body_buffer_size_args(args: &[String]) -> Result<u64, Error> {
    match args {
        [v] => parse_size(v.as_bytes()).ok_or(Error::BadValue {
            what: "client_body_buffer_size",
            got: v.clone(),
        }),
        [] => Err(Error::MissingArg("client_body_buffer_size")),
        _ => Err(Error::BadValue {
            what: "client_body_buffer_size",
            got: args.join(" "),
        }),
    }
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

/// `max_ranges N` (#370), nginx's `ngx_conf_set_num_slot`: decimal digits
/// only (`ngx_atoi`: no sign, no suffix), up to `NGX_MAX_INT_T_VALUE`, else
/// "invalid number". A value past `u32::MAX` allows more ranges than any
/// request can have, so it is kept as `u32::MAX`.
pub(crate) fn parse_max_ranges_args(args: &[String]) -> Result<u32, Error> {
    let [raw] = args else {
        return Err(Error::BadValue {
            what: "max_ranges (invalid number of arguments)",
            got: args.join(" "),
        });
    };
    let invalid = || Error::BadValue {
        what: "max_ranges (invalid number)",
        got: raw.clone(),
    };
    if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid());
    }
    let n: u64 = raw.parse().map_err(|_| invalid())?;
    if n > i64::MAX as u64 {
        return Err(invalid());
    }
    Ok(u32::try_from(n).unwrap_or(u32::MAX))
}

/// `client_body_temp_path path [level1 [level2 [level3]]]`, validated as
/// nginx's ngx_conf_set_path_slot (each level at least 1, ten digits in
/// all).
pub(crate) fn parse_temp_path_args(args: &[String], what: &'static str) -> Result<TempPath, Error> {
    let bad = || Error::BadValue {
        what,
        got: args.join(" "),
    };
    let (path, levels) = args.split_first().ok_or(Error::MissingArg(what))?;
    if path.is_empty() || levels.len() > 3 {
        return Err(bad());
    }
    let mut digits = 0;
    let mut parsed = [0u8; 3];
    for (slot, level) in parsed.iter_mut().zip(levels) {
        match level.parse::<u8>() {
            Ok(n) if (1..=10).contains(&n) => {
                digits += usize::from(n);
                *slot = n;
            }
            _ => return Err(bad()),
        }
    }
    if digits > 10 {
        return Err(bad());
    }
    let trimmed = match path.strip_suffix('/') {
        Some(rest) if !rest.is_empty() => rest,
        _ => path.as_str(),
    };
    Ok(TempPath {
        path: PathBuf::from(trimmed),
        levels: parsed,
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

impl ProxyConf {
    /// The directives `parse` takes.
    pub(crate) const DIRECTIVES: &'static [&'static str] = &[
        "proxy_set_header",
        "proxy_pass_request_headers",
        "proxy_pass_request_body",
        "proxy_set_body",
        "proxy_ignore_headers",
        "proxy_connect_timeout",
        "proxy_read_timeout",
        "proxy_send_timeout",
        "proxy_limit_rate",
        "proxy_http_version",
        "proxy_next_upstream",
        "proxy_next_upstream_tries",
        "proxy_next_upstream_timeout",
        "proxy_intercept_errors",
        "proxy_force_ranges",
        "proxy_ignore_client_abort",
        "proxy_pass_trailers",
        "proxy_bind",
        "proxy_redirect",
        "proxy_cookie_domain",
        "proxy_cookie_path",
        "proxy_cookie_flags",
        "proxy_hide_header",
        "proxy_pass_header",
        "proxy_method",
        "proxy_cache",
        "proxy_cache_key",
        "proxy_cache_valid",
        "proxy_cache_methods",
        "proxy_cache_min_uses",
        "proxy_cache_bypass",
        "proxy_no_cache",
        "proxy_cache_convert_head",
        "proxy_cache_revalidate",
        "proxy_cache_use_stale",
        "proxy_cache_background_update",
        "proxy_cache_lock",
        "proxy_cache_lock_timeout",
        "proxy_cache_lock_age",
        "proxy_cache_max_range_offset",
        "proxy_ssl_server_name",
        "proxy_ssl_name",
        "proxy_ssl_session_reuse",
        "proxy_ssl_protocols",
        "proxy_ssl_verify",
        "proxy_ssl_trusted_certificate",
        "proxy_ssl_verify_depth",
        "proxy_ssl_crl",
        "proxy_ssl_certificate",
        "proxy_ssl_certificate_key",
        "proxy_ssl_password_file",
        "proxy_ssl_certificate_cache",
        "resolver",
        "resolver_timeout",
    ];

    pub(crate) fn takes(name: &str) -> bool {
        Self::DIRECTIVES.contains(&name)
    }

    /// Parse one of `DIRECTIVES` (`args[0]`) into `self`, at any level.
    /// File names are resolved against `conf_prefix`, as nginx's
    /// ngx_conf_full_name with the config prefix.
    pub(crate) fn parse(
        &mut self,
        args: &[String],
        conf_prefix: Option<&std::path::Path>,
    ) -> Result<(), Error> {
        match args[0].as_str() {
            "proxy_set_header" => {
                let entry = parse_proxy_set_header_args(&args[1..])?;
                self.set_headers.get_or_insert_with(Vec::new).push(entry);
            }
            "proxy_pass_request_headers" => {
                if self.pass_request_headers.is_some() {
                    return Err(Error::Duplicate("proxy_pass_request_headers"));
                }
                self.pass_request_headers =
                    Some(parse_on_off_args(&args[1..], "proxy_pass_request_headers")?);
            }
            // A bitmask in nginx: lines add up.
            "proxy_ignore_headers" => self
                .ignore_headers
                .get_or_insert_with(Vec::new)
                .extend(parse_proxy_ignore_headers(&args[1..])?),
            "proxy_set_body" => {
                if self.set_body.is_some() {
                    return Err(Error::Duplicate("proxy_set_body"));
                }
                if args.len() != 2 {
                    return Err(Error::BadValue {
                        what: "proxy_set_body",
                        got: args[1..].join(" "),
                    });
                }
                self.set_body = Some(parse_value_with_vars(&args[1])?);
            }
            "proxy_pass_request_body" => {
                if self.pass_request_body.is_some() {
                    return Err(Error::Duplicate("proxy_pass_request_body"));
                }
                self.pass_request_body =
                    Some(parse_on_off_args(&args[1..], "proxy_pass_request_body")?);
            }
            "resolver" => {
                if self.resolver.is_some() {
                    return Err(Error::Duplicate("resolver"));
                }
                self.resolver = Some(parse_resolver_args(&args[1..])?);
            }
            "resolver_timeout" => {
                if self.resolver_timeout_ms.is_some() {
                    return Err(Error::Duplicate("resolver_timeout"));
                }
                self.resolver_timeout_ms =
                    Some(parse_proxy_timeout_args(&args[1..], "resolver_timeout")?);
            }
            "proxy_connect_timeout" => {
                if self.connect_timeout_ms.is_some() {
                    return Err(Error::Duplicate("proxy_connect_timeout"));
                }
                self.connect_timeout_ms = Some(parse_proxy_timeout_args(
                    &args[1..],
                    "proxy_connect_timeout",
                )?);
            }
            "proxy_read_timeout" => {
                if self.read_timeout_ms.is_some() {
                    return Err(Error::Duplicate("proxy_read_timeout"));
                }
                self.read_timeout_ms =
                    Some(parse_proxy_timeout_args(&args[1..], "proxy_read_timeout")?);
            }
            "proxy_send_timeout" => {
                if self.send_timeout_ms.is_some() {
                    return Err(Error::Duplicate("proxy_send_timeout"));
                }
                self.send_timeout_ms =
                    Some(parse_proxy_timeout_args(&args[1..], "proxy_send_timeout")?);
            }
            "proxy_limit_rate" => {
                if self.limit_rate.is_some() {
                    return Err(Error::Duplicate("proxy_limit_rate"));
                }
                if args.len() < 2 {
                    return Err(Error::MissingArg("proxy_limit_rate"));
                }
                // Variables since nginx 1.27.0, read once the upstream's
                // header is in (ngx_http_upstream_send_response).
                self.limit_rate = Some(crate::config::parse_location::parse_size_value(
                    &args[1..],
                    "proxy_limit_rate",
                )?);
            }
            "proxy_ssl_server_name" => {
                if self.ssl_server_name.is_some() {
                    return Err(Error::Duplicate("proxy_ssl_server_name"));
                }
                self.ssl_server_name =
                    Some(parse_on_off_args(&args[1..], "proxy_ssl_server_name")?);
            }
            "proxy_ssl_session_reuse" => {
                if self.ssl_session_reuse.is_some() {
                    return Err(Error::Duplicate("proxy_ssl_session_reuse"));
                }
                self.ssl_session_reuse =
                    Some(parse_on_off_args(&args[1..], "proxy_ssl_session_reuse")?);
            }
            "proxy_ssl_name" => {
                if self.ssl_name.is_some() {
                    return Err(Error::Duplicate("proxy_ssl_name"));
                }
                if args.len() != 2 {
                    return Err(Error::BadValue {
                        what: "proxy_ssl_name",
                        got: args[1..].join(" "),
                    });
                }
                self.ssl_name = Some(parse_value_with_vars(&args[1])?);
            }
            "proxy_ssl_protocols" => {
                if self.ssl_protocols.is_some() {
                    return Err(Error::Duplicate("proxy_ssl_protocols"));
                }
                self.ssl_protocols = Some(super::parse_server::parse_tls_protocols(
                    &args[1..],
                    "proxy_ssl_protocols",
                )?);
            }
            "proxy_ssl_verify" => {
                if self.ssl_verify.is_some() {
                    return Err(Error::Duplicate("proxy_ssl_verify"));
                }
                self.ssl_verify = Some(parse_on_off_args(&args[1..], "proxy_ssl_verify")?);
            }
            "proxy_ssl_trusted_certificate" | "proxy_ssl_crl" => {
                let name: &'static str = if args[0] == "proxy_ssl_crl" {
                    "proxy_ssl_crl"
                } else {
                    "proxy_ssl_trusted_certificate"
                };
                let slot = if name == "proxy_ssl_crl" {
                    &mut self.ssl_crl
                } else {
                    &mut self.ssl_trusted_certificate
                };
                if slot.is_some() {
                    return Err(Error::Duplicate(name));
                }
                if args.len() != 2 {
                    return Err(Error::BadValue {
                        what: name,
                        got: args[1..].join(" "),
                    });
                }
                *slot = Some(super::resolve_conf_path(
                    conf_prefix,
                    std::path::PathBuf::from(&args[1]),
                ));
            }
            // With variables, rendered per request (#434). `data:` isn't
            // supported: refused, not served without the certificate.
            "proxy_ssl_certificate" | "proxy_ssl_certificate_key" => {
                let name: &'static str = if args[0] == "proxy_ssl_certificate" {
                    "proxy_ssl_certificate"
                } else {
                    "proxy_ssl_certificate_key"
                };
                let slot = if name == "proxy_ssl_certificate" {
                    &mut self.ssl_certificate
                } else {
                    &mut self.ssl_certificate_key
                };
                if slot.is_some() {
                    return Err(Error::Duplicate(name));
                }
                if args.len() != 2 {
                    return Err(Error::BadValue {
                        what: name,
                        got: args[1..].join(" "),
                    });
                }
                if args[1].starts_with("data:") {
                    return Err(Error::BadValue {
                        what: if name == "proxy_ssl_certificate" {
                            "proxy_ssl_certificate (data: isn't supported yet)"
                        } else {
                            "proxy_ssl_certificate_key (data: isn't supported yet)"
                        },
                        got: args[1].clone(),
                    });
                }
                *slot = Some(if args[1].is_empty() {
                    None
                } else if args[1].contains('$') {
                    Some(super::CertPath::Vars {
                        raw: args[1].clone(),
                        parts: parse_value_with_vars(&args[1])?,
                        prefix: conf_prefix.map(<std::path::Path>::to_path_buf),
                    })
                } else {
                    Some(super::CertPath::File(super::resolve_conf_path(
                        conf_prefix,
                        std::path::PathBuf::from(&args[1]),
                    )))
                });
            }
            "proxy_ssl_certificate_cache" => {
                if self.ssl_certificate_cache.is_some() {
                    return Err(Error::Duplicate("proxy_ssl_certificate_cache"));
                }
                self.ssl_certificate_cache = Some(super::parse_ssl_cache_args(
                    &args[1..],
                    "proxy_ssl_certificate_cache",
                )?);
            }
            "proxy_ssl_password_file" => {
                if self.ssl_password_file.is_some() {
                    return Err(Error::Duplicate("proxy_ssl_password_file"));
                }
                let [_, path] = args else {
                    return Err(Error::MissingArg("proxy_ssl_password_file"));
                };
                self.ssl_password_file = Some(super::resolve_conf_path(
                    conf_prefix,
                    std::path::PathBuf::from(path),
                ));
            }
            "proxy_ssl_verify_depth" => {
                if self.ssl_verify_depth.is_some() {
                    return Err(Error::Duplicate("proxy_ssl_verify_depth"));
                }
                let v = args
                    .get(1)
                    .filter(|_| args.len() == 2)
                    .ok_or(Error::MissingArg("proxy_ssl_verify_depth"))?;
                self.ssl_verify_depth = Some(v.parse::<u32>().map_err(|_| Error::BadValue {
                    what: "proxy_ssl_verify_depth",
                    got: v.clone(),
                })?);
            }
            "proxy_http_version" => {
                if self.http_version.is_some() {
                    return Err(Error::Duplicate("proxy_http_version"));
                }
                self.http_version = Some(parse_proxy_http_version_args(&args[1..])?);
            }
            "proxy_next_upstream" => {
                if self.next_upstream.is_some() {
                    return Err(Error::Duplicate("proxy_next_upstream"));
                }
                self.next_upstream = Some(parse_proxy_next_upstream_args(&args[1..])?);
            }
            "proxy_next_upstream_tries" => {
                if self.next_upstream_tries.is_some() {
                    return Err(Error::Duplicate("proxy_next_upstream_tries"));
                }
                let v = args
                    .get(1)
                    .ok_or(Error::MissingArg("proxy_next_upstream_tries"))?;
                self.next_upstream_tries = Some(v.parse::<u32>().map_err(|_| Error::BadValue {
                    what: "proxy_next_upstream_tries",
                    got: v.clone(),
                })?);
            }
            "proxy_next_upstream_timeout" => {
                if self.next_upstream_timeout_ms.is_some() {
                    return Err(Error::Duplicate("proxy_next_upstream_timeout"));
                }
                let v = args
                    .get(1)
                    .ok_or(Error::MissingArg("proxy_next_upstream_timeout"))?;
                self.next_upstream_timeout_ms =
                    Some(parse_duration_ms(v, "proxy_next_upstream_timeout")?);
            }
            "proxy_redirect" => parse_proxy_redirect(args, &mut self.redirect)?,
            "proxy_cookie_domain" => crate::config::parse_server::parse_proxy_cookie(
                args,
                &mut self.cookie_domain,
                true,
            )?,
            "proxy_cookie_path" => {
                crate::config::parse_server::parse_proxy_cookie(args, &mut self.cookie_path, false)?
            }
            "proxy_cookie_flags" => {
                crate::config::parse_server::parse_proxy_cookie_flags(args, &mut self.cookie_flags)?
            }
            "proxy_hide_header" => {
                let name = args.get(1).ok_or(Error::MissingArg("proxy_hide_header"))?;
                self.hide_headers
                    .get_or_insert_with(Vec::new)
                    .push(name.clone());
            }
            "proxy_pass_header" => {
                let name = args.get(1).ok_or(Error::MissingArg("proxy_pass_header"))?;
                self.pass_headers
                    .get_or_insert_with(Vec::new)
                    .push(name.clone());
            }
            // ngx_http_upstream_bind_set_slot: `off`, or an address with an
            // optional `transparent`; a literal one must parse now.
            "proxy_bind" => {
                if self.bind.is_some() {
                    return Err(Error::Duplicate("proxy_bind"));
                }
                self.bind = Some(match &args[1..] {
                    [off] if off == "off" => ProxyBind::Off,
                    [addr] | [addr, _] => {
                        let transparent = match args.get(2).map(String::as_str) {
                            None => false,
                            Some("transparent") => true,
                            Some(other) => {
                                return Err(Error::BadValue {
                                    what: "proxy_bind parameter",
                                    got: other.to_string(),
                                });
                            }
                        };
                        if !addr.contains('$') && parse_bind_addr(addr).is_none() {
                            return Err(Error::BadValue {
                                what: "proxy_bind (invalid address)",
                                got: addr.clone(),
                            });
                        }
                        ProxyBind::Addr {
                            value: parse_value_with_vars(addr)?,
                            transparent,
                        }
                    }
                    _ => {
                        return Err(Error::BadValue {
                            what: "proxy_bind",
                            got: args[1..].join(" "),
                        });
                    }
                });
            }
            "proxy_pass_trailers" => {
                if self.pass_trailers.is_some() {
                    return Err(Error::Duplicate("proxy_pass_trailers"));
                }
                self.pass_trailers = Some(parse_on_off_args(&args[1..], "proxy_pass_trailers")?);
            }
            "proxy_ignore_client_abort" => {
                if self.ignore_client_abort.is_some() {
                    return Err(Error::Duplicate("proxy_ignore_client_abort"));
                }
                self.ignore_client_abort =
                    Some(parse_on_off_args(&args[1..], "proxy_ignore_client_abort")?);
            }
            "proxy_intercept_errors" => {
                if self.intercept_errors.is_some() {
                    return Err(Error::Duplicate("proxy_intercept_errors"));
                }
                self.intercept_errors =
                    Some(parse_on_off_args(&args[1..], "proxy_intercept_errors")?);
            }
            "proxy_force_ranges" => {
                if self.force_ranges.is_some() {
                    return Err(Error::Duplicate("proxy_force_ranges"));
                }
                self.force_ranges = Some(parse_on_off_args(&args[1..], "proxy_force_ranges")?);
            }
            "proxy_cache" => {
                if self.cache.cache.is_some() {
                    return Err(Error::Duplicate("proxy_cache"));
                }
                let [_, value] = args else {
                    return Err(Error::MissingArg("proxy_cache"));
                };
                let parts = parse_value_with_vars(value)?;
                self.cache.cache = Some(if value == "off" {
                    ProxyCacheSetting::Off
                } else if parts.iter().any(|p| !matches!(p, ValuePart::Literal(_))) {
                    ProxyCacheSetting::Var(parts)
                } else {
                    ProxyCacheSetting::Zone(value.clone())
                });
            }
            "proxy_cache_key" => {
                if self.cache.key.is_some() {
                    return Err(Error::Duplicate("proxy_cache_key"));
                }
                let [_, value] = args else {
                    return Err(Error::MissingArg("proxy_cache_key"));
                };
                self.cache.key = Some(parse_value_with_vars(value)?);
            }
            "proxy_cache_valid" => {
                let entries = parse_proxy_cache_valid(&args[1..])?;
                self.cache
                    .valid
                    .get_or_insert_with(Vec::new)
                    .extend(entries);
            }
            "proxy_cache_methods" => {
                if args.len() < 2 {
                    return Err(Error::MissingArg("proxy_cache_methods"));
                }
                let mut post = self.cache.methods_post.unwrap_or(false);
                for method in &args[1..] {
                    match method.to_ascii_uppercase().as_str() {
                        "GET" | "HEAD" => {}
                        "POST" => post = true,
                        _ => {
                            return Err(Error::BadValue {
                                what: "proxy_cache_methods",
                                got: method.clone(),
                            });
                        }
                    }
                }
                self.cache.methods_post = Some(post);
            }
            "proxy_cache_min_uses" => {
                if self.cache.min_uses.is_some() {
                    return Err(Error::Duplicate("proxy_cache_min_uses"));
                }
                let v = args
                    .get(1)
                    .ok_or(Error::MissingArg("proxy_cache_min_uses"))?;
                self.cache.min_uses = Some(v.parse::<u32>().map_err(|_| Error::BadValue {
                    what: "proxy_cache_min_uses",
                    got: v.clone(),
                })?);
            }
            name @ ("proxy_cache_bypass" | "proxy_no_cache") => {
                if args.len() < 2 {
                    return Err(Error::MissingArg(if name == "proxy_no_cache" {
                        "proxy_no_cache"
                    } else {
                        "proxy_cache_bypass"
                    }));
                }
                let slot = if name == "proxy_no_cache" {
                    &mut self.cache.no_cache
                } else {
                    &mut self.cache.bypass
                };
                let list = slot.get_or_insert_with(Vec::new);
                for value in &args[1..] {
                    list.push(parse_value_with_vars(value)?);
                }
            }
            "proxy_cache_convert_head" => {
                if self.cache.convert_head.is_some() {
                    return Err(Error::Duplicate("proxy_cache_convert_head"));
                }
                self.cache.convert_head =
                    Some(parse_on_off_args(&args[1..], "proxy_cache_convert_head")?);
            }
            "proxy_cache_revalidate" => {
                if self.cache.revalidate.is_some() {
                    return Err(Error::Duplicate("proxy_cache_revalidate"));
                }
                self.cache.revalidate =
                    Some(parse_on_off_args(&args[1..], "proxy_cache_revalidate")?);
            }
            "proxy_cache_use_stale" => {
                if self.cache.use_stale.is_some() {
                    return Err(Error::Duplicate("proxy_cache_use_stale"));
                }
                self.cache.use_stale = Some(parse_proxy_cache_use_stale(&args[1..])?);
            }
            "proxy_cache_background_update" => {
                if self.cache.background_update.is_some() {
                    return Err(Error::Duplicate("proxy_cache_background_update"));
                }
                self.cache.background_update = Some(parse_on_off_args(
                    &args[1..],
                    "proxy_cache_background_update",
                )?);
            }
            "proxy_cache_lock" => {
                if self.cache.lock.is_some() {
                    return Err(Error::Duplicate("proxy_cache_lock"));
                }
                self.cache.lock = Some(parse_on_off_args(&args[1..], "proxy_cache_lock")?);
            }
            "proxy_cache_max_range_offset" => {
                if self.cache.max_range_offset.is_some() {
                    return Err(Error::Duplicate("proxy_cache_max_range_offset"));
                }
                let [_, v] = args else {
                    return Err(Error::MissingArg("proxy_cache_max_range_offset"));
                };
                self.cache.max_range_offset = Some(
                    super::parse_server::parse_size_bytes(v).ok_or(Error::BadValue {
                        what: "proxy_cache_max_range_offset",
                        got: v.clone(),
                    })?,
                );
            }
            name @ ("proxy_cache_lock_timeout" | "proxy_cache_lock_age") => {
                let (slot, what) = if name == "proxy_cache_lock_age" {
                    (&mut self.cache.lock_age_ms, "proxy_cache_lock_age")
                } else {
                    (&mut self.cache.lock_timeout_ms, "proxy_cache_lock_timeout")
                };
                if slot.is_some() {
                    return Err(Error::Duplicate(what));
                }
                *slot = Some(parse_proxy_timeout_args(&args[1..], what)?);
            }
            "proxy_method" => {
                if self.proxy_method.is_some() {
                    return Err(Error::Duplicate("proxy_method"));
                }
                let method = args.get(1).ok_or(Error::MissingArg("proxy_method"))?;
                if args.len() != 2 {
                    return Err(Error::BadValue {
                        what: "proxy_method",
                        got: args[1..].join(" "),
                    });
                }
                self.proxy_method = Some(parse_value_with_vars(method)?);
            }
            other => unreachable!("not a ProxyConf directive: {other}"),
        }
        Ok(())
    }
}

/// `proxy_cache_valid [code ...] time;` (ngx_http_file_cache_valid_set_slot):
/// a time alone is for 200, 301 and 302; `any` is every status.
pub(crate) fn parse_proxy_cache_valid(args: &[String]) -> Result<Vec<CacheValid>, Error> {
    let (time, codes) = args
        .split_last()
        .ok_or(Error::MissingArg("proxy_cache_valid"))?;
    let secs = super::parse_server::parse_duration_secs(time, "proxy_cache_valid")?;
    if codes.is_empty() {
        return Ok([200, 301, 302]
            .into_iter()
            .map(|status| CacheValid { status, secs })
            .collect());
    }
    codes
        .iter()
        .map(|code| {
            let status = if code == "any" {
                0
            } else {
                code.parse::<u16>()
                    .ok()
                    .filter(|s| (100..=599).contains(s))
                    .ok_or_else(|| Error::BadValue {
                        what: "proxy_cache_valid status",
                        got: code.clone(),
                    })?
            };
            Ok(CacheValid { status, secs })
        })
        .collect()
}

/// `proxy_cache_use_stale` (ngx_http_proxy_next_upstream_masks plus
/// `updating`); `off` alone turns every case off.
pub(crate) fn parse_proxy_cache_use_stale(args: &[String]) -> Result<UseStale, Error> {
    if args.is_empty() {
        return Err(Error::MissingArg("proxy_cache_use_stale"));
    }
    let mut stale = UseStale::default();
    if let [only] = args
        && only == "off"
    {
        return Ok(stale);
    }
    for arg in args {
        match arg.as_str() {
            "error" => stale.error = true,
            "timeout" => stale.timeout = true,
            "invalid_header" => stale.invalid_header = true,
            "updating" => stale.updating = true,
            other => {
                let slot = other
                    .strip_prefix("http_")
                    .and_then(|code| code.parse::<u16>().ok())
                    .and_then(|code| UseStale::STATUSES.iter().position(|&s| s == code))
                    .ok_or_else(|| Error::BadValue {
                        what: "proxy_cache_use_stale",
                        got: arg.clone(),
                    })?;
                stale.statuses[slot] = true;
            }
        }
    }
    Ok(stale)
}

/// `proxy_cache_path` (ngx_http_file_cache_set_slot). The loader's
/// tunables are checked and otherwise unused.
pub(crate) fn parse_proxy_cache_path(args: &[String]) -> Result<ProxyCachePath, Error> {
    let (path, params) = args
        .split_first()
        .ok_or(Error::MissingArg("proxy_cache_path"))?;
    let bad = |got: &String| Error::BadValue {
        what: "proxy_cache_path",
        got: got.clone(),
    };
    let path = match path.strip_suffix('/') {
        Some(rest) if !rest.is_empty() => rest,
        _ => path.as_str(),
    };
    let mut levels = [0u8; 3];
    let mut zone: Option<(String, u64)> = None;
    let mut inactive_secs = 600;
    let mut max_size = None;
    let mut min_free = None;
    let mut manager_files = 100;
    let mut manager_sleep_ms = 50;
    let mut manager_threshold_ms = 200;
    for param in params {
        let (name, value) = param.split_once('=').ok_or_else(|| bad(param))?;
        match name {
            "levels" => {
                let parts: Vec<&str> = value.split(':').collect();
                if parts.len() > 3 {
                    return Err(bad(param));
                }
                for (slot, part) in levels.iter_mut().zip(&parts) {
                    *slot = match *part {
                        "1" => 1,
                        "2" => 2,
                        _ => return Err(bad(param)),
                    };
                }
            }
            "keys_zone" => {
                let (zone_name, size) = value.split_once(':').ok_or_else(|| bad(param))?;
                let size = super::parse_server::parse_size_bytes(size).ok_or_else(|| bad(param))?;
                // nginx: "keys zone ... is too small" below two pages.
                if zone_name.is_empty() || size < 8192 {
                    return Err(bad(param));
                }
                zone = Some((zone_name.to_string(), size));
            }
            "inactive" => {
                inactive_secs = super::parse_server::parse_duration_secs(value, "inactive")?;
            }
            "max_size" => {
                max_size =
                    Some(super::parse_server::parse_size_bytes(value).ok_or_else(|| bad(param))?);
            }
            "use_temp_path" => {
                if value != "on" && value != "off" {
                    return Err(bad(param));
                }
            }
            "min_free" => {
                min_free =
                    Some(super::parse_server::parse_size_bytes(value).ok_or_else(|| bad(param))?);
            }
            "loader_files" | "manager_files" => {
                let n = value.parse::<u64>().map_err(|_| bad(param))?;
                if name == "manager_files" {
                    manager_files = n;
                }
            }
            "loader_sleep" | "loader_threshold" | "manager_sleep" | "manager_threshold" => {
                let ms = super::parse_server::parse_duration_ms(value, "proxy_cache_path")?;
                match name {
                    "manager_sleep" => manager_sleep_ms = ms,
                    "manager_threshold" => manager_threshold_ms = ms,
                    _ => {}
                }
            }
            _ => return Err(bad(param)),
        }
    }
    let (zone, size) = zone.ok_or(Error::MissingArg("proxy_cache_path keys_zone"))?;
    Ok(ProxyCachePath {
        path: PathBuf::from(path),
        levels,
        zone,
        size,
        inactive_secs,
        max_size,
        min_free,
        manager_files,
        manager_sleep_ms,
        manager_threshold_ms,
    })
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

/// Parse `proxy_http_version 1.0|1.1|2;`: 0, 1, or 2 for HTTP/2 (#599).
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
        "2" => Ok(2),
        _ => Err(Error::BadValue {
            what: "proxy_http_version",
            got: raw.clone(),
        }),
    }
}

/// `ip[:port]` or `[ipv6][:port]` (ngx_parse_addr_port), as `proxy_bind`
/// takes it; port 0 when none.
pub(crate) fn parse_bind_addr(s: &str) -> Option<SocketAddr> {
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return Some(addr);
    }
    let ip = s
        .strip_prefix('[')
        .and_then(|v6| v6.strip_suffix(']'))
        .unwrap_or(s)
        .parse::<std::net::IpAddr>()
        .ok()?;
    Some(SocketAddr::new(ip, 0))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proxy_pass(arg: &str) -> Result<ProxyPass, Error> {
        parse_proxy_pass_arg(&[arg.to_string()])
    }

    /// `keepalive N [local];` (ngx_http_upstream_keepalive), 0 included
    /// since 1.29.7.
    #[test]
    fn keepalive_takes_zero_and_local() {
        let keepalive = |line: &str| {
            crate::config::parse(&format!(
                "http {{ upstream u {{ server 127.0.0.1:1; {line} }} server {{ listen 80; }} }}"
            ))
            .map(|c| {
                let u = &c.upstreams[0];
                (u.keepalive_max_idle, u.keepalive_local)
            })
        };
        assert_eq!(keepalive("").unwrap(), (None, false));
        assert_eq!(keepalive("keepalive 0;").unwrap(), (Some(0), false));
        assert_eq!(keepalive("keepalive 8;").unwrap(), (Some(8), false));
        assert_eq!(keepalive("keepalive 8 local;").unwrap(), (Some(8), true));
        assert!(keepalive("keepalive 8 bogus;").is_err());
        assert!(keepalive("keepalive 8 local local;").is_err());
        assert!(keepalive("keepalive -1;").is_err());
        assert!(keepalive("keepalive 8; keepalive 0;").is_err());
    }

    /// `sticky` and `server … route= drain` (#600), with nginx's errors.
    #[test]
    fn sticky_directive() {
        let parse = |body: &str| {
            crate::config::parse(&format!(
                "http {{ upstream u {{ server 127.0.0.1:1; {body} }} server {{ listen 80; }} }}"
            ))
            .map(|c| c.upstreams[0].clone())
        };
        let err = |body: &str| parse(body).unwrap_err().to_string();
        let u =
            parse("sticky cookie srv expires=1h domain=$host path=/ httponly secure samesite=lax;")
                .unwrap();
        let Some(StickyConf::Cookie(c)) = u.sticky else {
            panic!("{u:?}");
        };
        assert_eq!(
            (c.name.as_str(), c.expires, c.path.as_deref()),
            ("srv", Some(StickyExpires::Secs(3600)), Some("/"))
        );
        assert!(c.httponly && c.secure && c.domain.is_some() && c.samesite.is_some());
        assert!(matches!(
            parse("sticky route $arg_a $cookie_b;").unwrap().sticky,
            Some(StickyConf::Route { lookup }) if lookup.len() == 2
        ));
        let Some(StickyConf::Learn(l)) =
            parse("sticky learn create=$upstream_cookie_s lookup=$cookie_s zone=z:1m header;")
                .unwrap()
                .sticky
        else {
            panic!()
        };
        assert_eq!(
            (l.zone.as_str(), l.timeout_ms, l.header),
            ("z", 600_000, true)
        );
        let s = parse("server 127.0.0.1:2 route=r2 drain;").unwrap().servers[1].clone();
        assert_eq!(
            (s.route.as_deref(), s.down, s.drain),
            (Some("r2"), true, true)
        );
        // A balancing method after `sticky` replaces it, as in nginx.
        assert_eq!(parse("sticky cookie s; least_conn;").unwrap().sticky, None);
        assert!(
            parse("least_conn; sticky cookie s;")
                .unwrap()
                .sticky
                .is_some()
        );

        assert_eq!(
            err("sticky cookie a; sticky cookie b;"),
            "\"sticky\" directive is duplicate"
        );
        assert_eq!(
            err("sticky cookie a samesite=bogus;"),
            "\"sticky\" directive invalid \"samesite\" parameter value"
        );
        assert_eq!(err("sticky route arg;"), "invalid variable name \"arg\"");
        assert_eq!(err("sticky bogus x;"), "unknown parameter \"bogus\"");
        assert_eq!(
            err("sticky learn lookup=$cookie_s zone=z:1m;"),
            "\"sticky\" directive \"create\" parameter is not specified"
        );
        assert_eq!(
            err("sticky learn create=$a lookup=$b zone=z:4k;"),
            "\"sticky\" directive zone is too small"
        );
        assert_eq!(
            err("server 127.0.0.1:2 route=123456789012345678901234567890123;"),
            "route is longer than 32"
        );
        assert!(
            crate::config::parse(
                "http { upstream a { server 127.0.0.1:1; sticky learn create=$a lookup=$b zone=z:1m; }
                        upstream b { server 127.0.0.1:1; sticky learn create=$a lookup=$b zone=z:1m; }
                        server { listen 80; } }"
            )
            .unwrap_err()
            .to_string()
            .contains("sticky zone \"z\" is already used in upstream \"a\"")
        );
    }

    #[test]
    fn proxy_pass_unix_path_ends_at_the_next_colon() {
        assert_eq!(
            proxy_pass("http://unix:/run/app.sock:/api/").unwrap(),
            ProxyPass::Direct {
                addrs: vec![UpstreamAddr::Unix("/run/app.sock".into())],
                host_header: "localhost".into(),
                request_path: Some("/api/".into()),
                tls: false,
            }
        );
        assert_eq!(
            proxy_pass("http://UNIX:/run/app.sock").unwrap(),
            ProxyPass::Direct {
                addrs: vec![UpstreamAddr::Unix("/run/app.sock".into())],
                host_header: "localhost".into(),
                request_path: None,
                tls: false,
            }
        );
        assert!(proxy_pass("http://unix::/x").is_err());
    }

    /// `https://` (#116): TLS, and port 443 when none is given.
    #[test]
    fn proxy_pass_https() {
        assert_eq!(
            proxy_pass("https://127.0.0.1/x").unwrap(),
            ProxyPass::Direct {
                addrs: vec![UpstreamAddr::Inet("127.0.0.1:443".parse().unwrap())],
                host_header: "127.0.0.1".into(),
                request_path: Some("/x".into()),
                tls: true,
            }
        );
        assert!(matches!(
            proxy_pass("https://backend").unwrap(),
            ProxyPass::UpstreamRef { tls: true, .. }
        ));
        assert!(matches!(
            proxy_pass("http://backend").unwrap(),
            ProxyPass::UpstreamRef { tls: false, .. }
        ));
        assert!(proxy_pass("ftp://127.0.0.1").is_err());
    }

    #[test]
    fn resolve_keeps_a_name_for_run_time() {
        let args = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        // Not looked up now: `svc.invalid` has no address anywhere.
        let s =
            parse_upstream_server_args(&args(&["Svc.Invalid.", "resolve", "weight=2"])).unwrap();
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].resolve.as_deref(), Some("svc.invalid"));
        assert_eq!(s[0].addr, UpstreamAddr::Inet("0.0.0.0:80".parse().unwrap()));
        assert_eq!((s[0].weight, s[0].display.as_str()), (2, "Svc.Invalid."));
        let s = parse_upstream_server_args(&args(&["svc.invalid:8080", "resolve"])).unwrap();
        assert_eq!(
            s[0].addr,
            UpstreamAddr::Inet("0.0.0.0:8080".parse().unwrap())
        );
        // An address stays one.
        for addr in ["127.0.0.1:81", "[::1]:81"] {
            let s = parse_upstream_server_args(&args(&[addr, "resolve"])).unwrap();
            assert_eq!(s[0].resolve, None);
            assert_eq!(s[0].addr, UpstreamAddr::Inet(addr.parse().unwrap()));
        }
        for bad in [
            "svc.invalid:x",
            "svc.invalid:0",
            "svc.invalid:65536",
            "a..b",
        ] {
            assert!(
                parse_upstream_server_args(&args(&[bad, "resolve"])).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn every_address_of_a_name_is_a_server() {
        use std::net::ToSocketAddrs;
        // As many servers as the name has distinct addresses here (one or
        // two for `localhost`), with the line's parameters on each.
        let mut want: Vec<std::net::SocketAddr> = Vec::new();
        for a in "localhost:8081".to_socket_addrs().unwrap() {
            if !want.contains(&a) {
                want.push(a);
            }
        }
        let servers =
            parse_upstream_server_args(&["localhost:8081".into(), "weight=3".into()]).unwrap();
        let got: Vec<UpstreamAddr> = servers.iter().map(|s| s.addr.clone()).collect();
        let want: Vec<UpstreamAddr> = want.into_iter().map(UpstreamAddr::Inet).collect();
        assert_eq!(got, want);
        assert!(
            servers
                .iter()
                .all(|s| s.weight == 3 && s.display == "localhost:8081")
        );
        match proxy_pass("http://localhost:8081/").unwrap() {
            ProxyPass::Direct { addrs, .. } => assert_eq!(addrs, want),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn the_port_defaults_to_80() {
        let addr = |a: &str| UpstreamAddr::Inet(a.parse().unwrap());
        let server = |arg: &str| {
            parse_upstream_server_args(&[arg.into(), "max_fails=3".into()]).unwrap()[0]
                .addr
                .clone()
        };
        assert_eq!(server("127.0.0.1"), addr("127.0.0.1:80"));
        assert_eq!(server("[::1]"), addr("[::1]:80"));
        assert_eq!(server("[::1]:8080"), addr("[::1]:8080"));
        for (url, want) in [
            ("http://[::1]/", "[::1]:80"),
            ("https://[::1]/", "[::1]:443"),
            ("http://[::1]:81/", "[::1]:81"),
            ("http://127.0.0.1/", "127.0.0.1:80"),
        ] {
            match proxy_pass(url).unwrap() {
                ProxyPass::Direct { addrs, .. } => assert_eq!(addrs, [addr(want)], "{url}"),
                other => panic!("{other:?}"),
            }
        }
    }

    #[test]
    fn upstream_server_unix_takes_the_whole_rest_as_path() {
        let server =
            parse_upstream_server_args(&["unix:///tmp/puma.sock".into(), "weight=2".into()])
                .unwrap();
        assert_eq!(server.len(), 1);
        assert_eq!(
            server[0].addr,
            UpstreamAddr::Unix("///tmp/puma.sock".into())
        );
        assert_eq!(server[0].weight, 2);
        let too_long = format!("unix:/{}", "a".repeat(107));
        assert!(parse_upstream_server_args(&[too_long]).is_err());
        let fits = format!("unix:/{}", "a".repeat(106));
        assert!(parse_upstream_server_args(&[fits]).is_ok());
    }

    #[test]
    fn hash_and_ip_hash_directives() {
        let upstream = |body: &str| {
            crate::config::parse(&format!(
                "http {{ upstream u {{ {body} }} server {{ listen 80; location / {{ proxy_pass http://u; }} }} }}"
            ))
        };
        let cfg = upstream("hash $arg_k consistent; server 127.0.0.1:1;").unwrap();
        assert!(matches!(
            cfg.upstreams[0].lb,
            LbAlgorithm::Hash {
                consistent: true,
                ..
            }
        ));
        // A method set before is replaced, with nginx's warning.
        let cfg = upstream("least_conn; ip_hash; server 127.0.0.1:1;").unwrap();
        assert_eq!(cfg.upstreams[0].lb, LbAlgorithm::IpHash);
        assert!(
            cfg.warnings
                .iter()
                .any(|w| w.contains("load balancing method redefined")),
            "{:?}",
            cfg.warnings
        );
        // `backup` after a hash method is refused; before, it is kept.
        assert!(upstream("hash $arg_k; server 127.0.0.1:1 backup;").is_err());
        assert!(upstream("server 127.0.0.1:1 backup; ip_hash; server 127.0.0.1:2;").is_ok());
        assert!(upstream("hash $arg_k foo; server 127.0.0.1:1;").is_err());
        assert!(upstream("hash; server 127.0.0.1:1;").is_err());
    }

    #[test]
    fn proxy_bind_addresses() {
        use std::net::SocketAddr;
        let addr = |s: &str| s.parse::<SocketAddr>().unwrap();
        assert_eq!(parse_bind_addr("127.0.0.2"), Some(addr("127.0.0.2:0")));
        assert_eq!(parse_bind_addr("127.0.0.2:81"), Some(addr("127.0.0.2:81")));
        assert_eq!(parse_bind_addr("[::1]"), Some(addr("[::1]:0")));
        assert_eq!(parse_bind_addr("::1"), Some(addr("[::1]:0")));
        assert_eq!(parse_bind_addr("[::1]:81"), Some(addr("[::1]:81")));
        assert_eq!(parse_bind_addr("localhost"), None);
        assert_eq!(parse_bind_addr("127.0.0.2:x"), None);

        let parse = |args: &[&str]| {
            let mut conf = ProxyConf::default();
            let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
            conf.parse(&args, None).map(|()| conf.bind.unwrap())
        };
        assert_eq!(parse(&["proxy_bind", "off"]).unwrap(), ProxyBind::Off);
        assert!(matches!(
            parse(&["proxy_bind", "127.0.0.2", "transparent"]).unwrap(),
            ProxyBind::Addr {
                transparent: true,
                ..
            }
        ));
        assert!(parse(&["proxy_bind", "$arg_b"]).is_ok());
        assert!(parse(&["proxy_bind", "bogus"]).is_err());
        assert!(parse(&["proxy_bind", "127.0.0.2", "foo"]).is_err());
    }

    #[test]
    fn resolver_args() {
        let parse = |line: &str| {
            let mut conf = ProxyConf::default();
            let args: Vec<String> = line.split(' ').map(String::from).collect();
            conf.parse(&args, None).map(|()| conf.resolver.unwrap())
        };
        let r = parse("resolver 127.0.0.1 [::1]:5353 valid=5s ipv6=off").unwrap();
        assert_eq!(
            r.servers,
            vec![
                "127.0.0.1:53".parse::<SocketAddr>().unwrap(),
                "[::1]:5353".parse().unwrap()
            ]
        );
        assert_eq!(r.valid_secs, Some(5));
        assert!(r.ipv4 && !r.ipv6);
        // Each directive is its own resolver.
        assert_ne!(parse("resolver 127.0.0.1").unwrap().id, r.id);
        assert_eq!(
            parse("resolver 127.0.0.1 valid=0").unwrap().valid_secs,
            None
        );
        assert!(parse("resolver valid=5s").is_err());
        assert!(parse("resolver 127.0.0.1 ipv4=off ipv6=off").is_err());
        assert!(parse("resolver 127.0.0.1 ipv6=no").is_err());
        assert!(parse("resolver 127.0.0.1 valid=x").is_err());
        assert!(parse("resolver 127.0.0.1:x").is_err());

        let mut conf = ProxyConf::default();
        let args = |line: &str| line.split(' ').map(String::from).collect::<Vec<_>>();
        conf.parse(&args("resolver_timeout 1500ms"), None).unwrap();
        assert_eq!(conf.resolver_timeout_ms, Some(1500));
        assert!(conf.parse(&args("resolver_timeout 2s"), None).is_err());
    }
}
