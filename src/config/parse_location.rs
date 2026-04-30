//! `location { ... }` block parser plus the directives most often used
//! at location scope: `try_files`, `index`, `add_header`, `auth_basic`,
//! `error_page`, `autoindex_*`, `return`, `on/off` parsing, and the
//! `try_files` probe/fallback classifier.

use std::path::PathBuf;
use super::*;

/// Shared `return STATUS [body]` parser used at both server and location
/// scope. The body (if any) is tokenized into the same `ValuePart` form
/// used by `add_header`, `index`, and `error_page` so variable expansion
/// behaves identically.
pub(crate) fn parse_return_args(args: &[String]) -> Result<(u16, Vec<ValuePart>), Error> {
    let status_s = args.first().ok_or(Error::MissingArg("return status"))?;
    let status = status_s.parse::<u16>().map_err(|_| Error::BadValue {
        what: "return status",
        got: status_s.clone(),
    })?;
    let body = match args.get(1) {
        Some(s) => {
            let parts = parse_value_with_vars(s)?;
            reject_sent_http_parts(&parts, "return body ($sent_http_* unavailable)")?;
            parts
        }
        None => Vec::new(),
    };
    Ok((status, body))
}

pub(crate) fn parse_post_action_args(args: &[String]) -> Result<String, Error> {
    let target = args.first().ok_or(Error::MissingArg("post_action"))?;
    if args.len() != 1 {
        return Err(Error::BadValue {
            what: "post_action",
            got: args.join(" "),
        });
    }
    if target.is_empty() {
        return Err(Error::BadValue {
            what: "post_action",
            got: target.clone(),
        });
    }
    Ok(target.clone())
}

/// Parse `expires` directive args (everything after the directive name).
///
/// Forms accepted (mirror `ngx_http_headers_expires`):
/// - `off` / `epoch` / `max`
/// - `[+|-]<duration>` (seconds when bare; nginx-style suffixes y/M/w/d/h/m/s)
/// - `modified <duration>`
/// - `@<time-of-day>` (e.g. `@15h30m33s`; max 24h)
/// - `$variable` / `modified $variable` — runtime-resolved
pub(crate) fn parse_expires_args(args: &[String]) -> Result<ExpiresDirective, Error> {
    let (modified, value) = match args.len() {
        1 => (false, args[0].as_str()),
        2 if args[0] == "modified" => (true, args[1].as_str()),
        _ => {
            return Err(Error::BadValue {
                what: "expires",
                got: args.join(" "),
            });
        }
    };
    let parts = parse_value_with_vars(value)?;
    let has_var = parts.iter().any(|p| matches!(p, ValuePart::Var(_)));
    if has_var {
        return Ok(if modified {
            ExpiresDirective::VariableModified(parts)
        } else {
            ExpiresDirective::Variable(parts)
        });
    }
    parse_expires_static(value, modified)
}

/// Parse the static (non-variable) form of an `expires` value. Shared by
/// the directive parser and the runtime evaluator that handles
/// `expires $var` after rendering.
pub(crate) fn parse_expires_static(
    value: &str,
    modified: bool,
) -> Result<ExpiresDirective, Error> {
    if !modified {
        match value {
            "epoch" => return Ok(ExpiresDirective::Epoch),
            "max" => return Ok(ExpiresDirective::Max),
            "off" => return Ok(ExpiresDirective::Off),
            _ => {}
        }
    }
    if let Some(rest) = value.strip_prefix('@') {
        if modified {
            return Err(Error::BadValue {
                what: "expires (daily time cannot be used with \"modified\")",
                got: value.to_string(),
            });
        }
        let secs = parse_compound_seconds(rest, "expires")?;
        if secs < 0 || secs > 24 * 60 * 60 {
            return Err(Error::BadValue {
                what: "expires (daily time must be < 24h)",
                got: value.to_string(),
            });
        }
        return Ok(ExpiresDirective::Daily(secs as u32));
    }
    let (negative, num) = if let Some(s) = value.strip_prefix('+') {
        (false, s)
    } else if let Some(s) = value.strip_prefix('-') {
        (true, s)
    } else {
        (false, value)
    };
    let secs = parse_compound_seconds(num, "expires")?;
    let signed = if negative { -secs } else { secs };
    Ok(if modified {
        ExpiresDirective::Modified(signed)
    } else {
        ExpiresDirective::Access(signed)
    })
}

/// Parse a duration spelled in nginx's compound seconds form (e.g.
/// `1h30m`, `15h30m33s`, `2048`, `7d`). Bare integers are seconds. We don't
/// support `ms` here because `expires` resolution is whole seconds. Months
/// (`M`) are 30 days, years (`y`) are 365 days — same as nginx.
fn parse_compound_seconds(raw: &str, what: &'static str) -> Result<i64, Error> {
    if raw.is_empty() {
        return Err(Error::BadValue {
            what,
            got: raw.to_string(),
        });
    }
    let bytes = raw.as_bytes();
    let mut total: i64 = 0;
    let mut cur: i64 = 0;
    let mut has_digit = false;
    for &b in bytes {
        if b.is_ascii_digit() {
            cur = cur
                .checked_mul(10)
                .and_then(|v| v.checked_add((b - b'0') as i64))
                .ok_or(Error::BadValue {
                    what,
                    got: raw.to_string(),
                })?;
            has_digit = true;
            continue;
        }
        if !has_digit {
            return Err(Error::BadValue {
                what,
                got: raw.to_string(),
            });
        }
        let mult: i64 = match b {
            b'y' => 365 * 24 * 60 * 60,
            b'M' => 30 * 24 * 60 * 60,
            b'w' => 7 * 24 * 60 * 60,
            b'd' => 24 * 60 * 60,
            b'h' => 60 * 60,
            b'm' => 60,
            b's' => 1,
            _ => {
                return Err(Error::BadValue {
                    what,
                    got: raw.to_string(),
                });
            }
        };
        total = total
            .checked_add(cur.checked_mul(mult).ok_or(Error::BadValue {
                what,
                got: raw.to_string(),
            })?)
            .ok_or(Error::BadValue {
                what,
                got: raw.to_string(),
            })?;
        cur = 0;
        has_digit = false;
    }
    if has_digit {
        total = total.checked_add(cur).ok_or(Error::BadValue {
            what,
            got: raw.to_string(),
        })?;
    }
    Ok(total)
}

/// Outcome of parsing the modifier+pattern that follow `location` and
/// precede `{`. `noregex` is meaningful only for `Prefix`; the parser sets
/// it for the `^~` form. Regex patterns are validated here so a malformed
/// regex fails `-t` rather than at first match.
pub(crate) struct LocationSpec {
    mode: MatchMode,
    pattern: String,
    noregex: bool,
}

/// Parse the arguments after `location` and before `{`:
///   location /foo      → Prefix("/foo")
///   location = /foo    → Exact("/foo")
///   location ^~ /foo   → Prefix("/foo") + noregex
///   location ~ ^re$    → Regex("^re$", case_sensitive)
///   location ~* ...    → Regex(..., case_insensitive)
///   location @named    → Named("@named")
pub(crate) fn parse_location_spec(args: &[String]) -> Result<LocationSpec, Error> {
    match args {
        [] => Err(Error::MissingArg("location pattern")),
        [single] => {
            if single.starts_with('@') {
                if single.len() == 1 {
                    return Err(Error::BadValue {
                        what: "named location",
                        got: single.clone(),
                    });
                }
                return Ok(LocationSpec {
                    mode: MatchMode::Named,
                    pattern: single.clone(),
                    noregex: false,
                });
            }
            Ok(LocationSpec {
                mode: MatchMode::Prefix,
                pattern: single.clone(),
                noregex: false,
            })
        }
        [modifier, pattern] => match modifier.as_str() {
            "=" => Ok(LocationSpec {
                mode: MatchMode::Exact,
                pattern: pattern.clone(),
                noregex: false,
            }),
            "^~" => Ok(LocationSpec {
                mode: MatchMode::Prefix,
                pattern: pattern.clone(),
                noregex: true,
            }),
            "~" | "~*" => {
                let case_insensitive = modifier == "~*";
                validate_regex(pattern, case_insensitive)?;
                Ok(LocationSpec {
                    mode: MatchMode::Regex { case_insensitive },
                    pattern: pattern.clone(),
                    noregex: false,
                })
            }
            other => Err(Error::UnsupportedLocationModifier(other.into())),
        },
        _ => Err(Error::UnexpectedToken(args[2].clone())),
    }
}

/// Compile-test a regex at parse time so `-t` catches bad patterns before
/// the server starts taking traffic. The compiled regex is recreated at
/// prepare time; storing it here would force `Location` to be non-`Debug`-
/// friendly and bloat the parser surface.
///
/// Uses `regex::bytes::RegexBuilder`: nginx matches PCRE against
/// `r->uri.data` as raw bytes, and our normalized path is also a `Vec<u8>`
/// (percent-decoding can produce arbitrary octets). Compiling here with
/// the same builder used in `prepare` keeps validation and runtime in sync.
pub(crate) fn validate_regex(pattern: &str, case_insensitive: bool) -> Result<(), Error> {
    regex::bytes::RegexBuilder::new(pattern)
        .case_insensitive(case_insensitive)
        .build()
        .map(|_| ())
        .map_err(|e| Error::InvalidRegex {
            pattern: pattern.to_string(),
            msg: e.to_string(),
        })
}

/// Parse one `location {}` block and push the resulting `Location` into
/// `sink`. Nested `location` blocks inside this one get flattened into the
/// same sink — nginx's own matcher (`ngx_http_core_find_static_location`)
/// descends into children only after the parent prefix matches, but since
/// all sibling/child patterns live in the same absolute URI space, a
/// flattened peer list + longest-prefix win produces the same routing
/// decision for the cases our tests exercise. Directives on the parent
/// (root/alias/add_header/error_page/return) do not cascade onto nested
/// children beyond what the explicit inherited arguments propagate — that's
/// a deliberate scope limit; if a test needs fuller nested inheritance,
/// revisit here.
pub(crate) fn parse_location_block(
    spec: LocationSpec,
    lx: &mut Lexer,
    inherited_root: Option<PathBuf>,
    inherited_alias: Option<(PathBuf, String)>,
    inherited_server_tokens: Option<ServerTokens>,
    inherited_autoindex: Option<bool>,
    inherited_autoindex_exact_size: Option<bool>,
    inherited_autoindex_localtime: Option<bool>,
    inherited_autoindex_format: Option<AutoindexFormat>,
    inherited_auth_basic: Option<AuthBasic>,
    inherited_auth_basic_user_file: Option<PathBuf>,
    inherited_auth_delay_ms: Option<u64>,
    inherited_client_max_body_size: Option<u64>,
    inherited_post_action: Option<String>,
    inherited_expires: Option<ExpiresDirective>,
    sink: &mut Vec<Location>,
) -> Result<(), Error> {
    let mut ret: Option<(u16, Vec<ValuePart>)> = None;
    let mut rewrite_ops: Vec<RewriteOp> = Vec::new();
    // An inherited alias from a prefix-alias ancestor outranks the
    // server-scope `root` for unset child locations: nginx's
    // `merge_loc_conf` does the same (alias replaces root from the parent
    // chain). Track the prefix so the worker can still strip the
    // ancestor's location prefix even when this child is a regex.
    let mut alias_prefix_override: Option<String> = None;
    let mut root = if let Some((path, prefix)) = inherited_alias.clone() {
        alias_prefix_override = Some(prefix);
        Some((path, PathMapping::Alias))
    } else {
        inherited_root.clone().map(|path| (path, PathMapping::Root))
    };
    let mut local_path_mapping: Option<PathMapping> = None;
    let mut index: Option<Vec<IndexEntry>> = None;
    let mut try_files: Option<TryFiles> = None;
    let mut add_headers: Option<Vec<AddHeader>> = None;
    let mut add_trailers: Option<Vec<AddHeader>> = None;
    let mut error_pages: Option<Vec<ErrorPage>> = None;
    let mut keepalive_timeout: Option<KeepaliveTimeout> = None;
    let mut keepalive_requests: Option<u64> = None;
    let mut keepalive_time_ms: Option<u64> = None;
    let mut keepalive_disable: Option<KeepaliveDisable> = None;
    let mut error_logs: Option<Vec<ErrorLog>> = None;
    let mut log_not_found: Option<bool> = None;
    let mut server_tokens: Option<ServerTokens> = None;
    let mut autoindex: Option<bool> = None;
    let mut autoindex_exact_size: Option<bool> = None;
    let mut autoindex_localtime: Option<bool> = None;
    let mut autoindex_format: Option<AutoindexFormat> = None;
    let mut access_logs: Option<Vec<AccessLog>> = None;
    let mut auth_basic: Option<AuthBasic> = None;
    let mut auth_basic_user_file: Option<PathBuf> = None;
    let mut auth_delay_ms: Option<u64> = None;
    let mut client_max_body_size: Option<u64> = None;
    let mut client_body_in_file_only: Option<ClientBodyInFileOnly> = None;
    let mut post_action: Option<String> = None;
    let mut expires: Option<ExpiresDirective> = None;
    let mut proxy_pass: Option<ProxyPass> = None;
    let mut proxy_set_headers: Option<Vec<ProxySetHeader>> = None;
    let mut proxy_pass_request_headers: Option<bool> = None;
    let mut proxy_pass_request_body: Option<bool> = None;
    let mut proxy_connect_timeout_ms: Option<u64> = None;
    let mut proxy_read_timeout_ms: Option<u64> = None;
    let mut proxy_send_timeout_ms: Option<u64> = None;
    let mut proxy_limit_rate: Option<u64> = None;
    let mut proxy_http_version: Option<u8> = None;
    let mut proxy_next_upstream: Option<ProxyNextUpstream> = None;
    let mut proxy_next_upstream_tries: Option<u32> = None;
    let mut proxy_next_upstream_timeout_ms: Option<u64> = None;
    let mut proxy_intercept_errors: Option<bool> = None;
    let mut chunked_transfer_encoding: Option<bool> = None;
    // Children parsed inside this block — appended to `sink` after the
    // parent so the parent's entry appears first in declaration order.
    let mut children: Vec<Location> = Vec::new();

    loop {
        let (args, term) = lx.read_directive()?;
        if args.is_empty() {
            return match term {
                Terminator::BlockClose => {
                    // `return` short-circuits the rewrite phase in nginx, so
                    // it wins over `root` / `alias` / `proxy_pass` if both
                    // are set. `proxy_pass` wins over `root`/`alias`
                    // (you can't have both in nginx — content phase
                    // dispatch is single-handler).
                    let handler = if let Some((status, body)) = ret {
                        Handler::Return { status, body }
                    } else if let Some(pp) = proxy_pass {
                        Handler::Proxy(pp)
                    } else if let Some((path, mapping)) = root {
                        Handler::Root { path, mapping }
                    } else if !rewrite_ops.is_empty() {
                        // Location-level rewrite directives are valid even
                        // without an explicit content handler. Match nginx by
                        // falling through to the default 404 content path.
                        Handler::Return {
                            status: 404,
                            body: Vec::new(),
                        }
                    } else {
                        return Err(Error::MissingArg("return or root/alias"));
                    };
                    // Propagate parent-location `server_tokens` into this
                    // location when this block didn't set its own — mirrors
                    // nginx's `merge_loc_conf` chain. The flat
                    // `Vec<Location>` AST doesn't carry the parent link, so
                    // we collapse the inheritance at parse time.
                    let effective_server_tokens = server_tokens.or(inherited_server_tokens);
                    let effective_autoindex = autoindex.or(inherited_autoindex);
                    let effective_autoindex_exact_size =
                        autoindex_exact_size.or(inherited_autoindex_exact_size);
                    let effective_autoindex_localtime =
                        autoindex_localtime.or(inherited_autoindex_localtime);
                    let effective_autoindex_format =
                        autoindex_format.or(inherited_autoindex_format);
                    let effective_auth_basic = auth_basic.or(inherited_auth_basic);
                    let effective_auth_basic_user_file =
                        auth_basic_user_file.or(inherited_auth_basic_user_file);
                    let effective_auth_delay_ms = auth_delay_ms.or(inherited_auth_delay_ms);
                    let effective_client_max_body_size =
                        client_max_body_size.or(inherited_client_max_body_size);
                    let effective_post_action = post_action.or(inherited_post_action);
                    let effective_expires = expires.or(inherited_expires);
                    sink.push(Location {
                        mode: spec.mode,
                        pattern: spec.pattern,
                        noregex: spec.noregex,
                        rewrite_ops,
                        handler,
                        index,
                        try_files,
                        add_headers,
                        add_trailers,
                        error_pages,
                        keepalive_timeout,
                        keepalive_requests,
                        keepalive_time_ms,
                        keepalive_disable,
                        error_logs,
                        log_not_found,
                        server_tokens: effective_server_tokens,
                        autoindex: effective_autoindex,
                        autoindex_exact_size: effective_autoindex_exact_size,
                        autoindex_localtime: effective_autoindex_localtime,
                        autoindex_format: effective_autoindex_format,
                        access_logs,
                        auth_basic: effective_auth_basic,
                        auth_basic_user_file: effective_auth_basic_user_file,
                        auth_delay_ms: effective_auth_delay_ms,
                        client_max_body_size: effective_client_max_body_size,
                        client_body_in_file_only,
                        post_action: effective_post_action,
                        expires: effective_expires,
                        proxy_set_headers,
                        proxy_pass_request_headers,
                        proxy_pass_request_body,
                        proxy_connect_timeout_ms,
                        proxy_read_timeout_ms,
                        proxy_send_timeout_ms,
                        proxy_limit_rate,
                        proxy_http_version,
                        proxy_next_upstream,
                        proxy_next_upstream_tries,
                        proxy_next_upstream_timeout_ms,
                        proxy_intercept_errors,
                        chunked_transfer_encoding,
                        alias_prefix_override,
                    });
                    sink.extend(children);
                    Ok(())
                }
                Terminator::Eof => Err(Error::UnclosedBlock),
                _ => Err(Error::UnexpectedEof),
            };
        }
        match (args[0].as_str(), &term) {
            ("set", Terminator::Semi) => {
                rewrite_ops.push(parse_set_op(&args[1..])?);
            }
            ("rewrite", Terminator::Semi) => {
                rewrite_ops.push(parse_rewrite_op(&args[1..])?);
            }
            ("break", Terminator::Semi) => {
                if args.len() != 1 {
                    return Err(Error::BadValue {
                        what: "break",
                        got: args[1..].join(" "),
                    });
                }
                rewrite_ops.push(RewriteOp::Break);
            }
            ("if", Terminator::BlockOpen) => {
                rewrite_ops.push(parse_if_op(&args[1..], lx)?);
            }
            ("return", Terminator::Semi) => {
                if ret.is_some() {
                    return Err(Error::Duplicate("return"));
                }
                ret = Some(parse_return_args(&args[1..])?);
            }
            ("add_header", Terminator::Semi) => {
                let entry = parse_add_header_args(&args[1..])?;
                add_headers.get_or_insert_with(Vec::new).push(entry);
            }
            ("add_trailer", Terminator::Semi) => {
                let entry = parse_add_header_args(&args[1..])?;
                add_trailers.get_or_insert_with(Vec::new).push(entry);
            }
            ("error_page", Terminator::Semi) => {
                let entries = parse_error_page_args(&args[1..])?;
                error_pages.get_or_insert_with(Vec::new).extend(entries);
            }
            ("keepalive_timeout", Terminator::Semi) => {
                if keepalive_timeout.is_some() {
                    return Err(Error::Duplicate("keepalive_timeout"));
                }
                keepalive_timeout = Some(parse_keepalive_timeout_args(&args[1..])?);
            }
            ("keepalive_requests", Terminator::Semi) => {
                if keepalive_requests.is_some() {
                    return Err(Error::Duplicate("keepalive_requests"));
                }
                keepalive_requests = Some(parse_keepalive_requests_args(&args[1..])?);
            }
            ("keepalive_time", Terminator::Semi) => {
                if keepalive_time_ms.is_some() {
                    return Err(Error::Duplicate("keepalive_time"));
                }
                keepalive_time_ms = Some(parse_keepalive_time_args(&args[1..])?);
            }
            ("keepalive_disable", Terminator::Semi) => {
                if keepalive_disable.is_some() {
                    return Err(Error::Duplicate("keepalive_disable"));
                }
                keepalive_disable = Some(parse_keepalive_disable_args(&args[1..])?);
            }
            ("error_log", Terminator::Semi) => {
                error_logs
                    .get_or_insert_with(Vec::new)
                    .push(parse_error_log_args(&args[1..])?);
            }
            ("log_not_found", Terminator::Semi) => {
                if log_not_found.is_some() {
                    return Err(Error::Duplicate("log_not_found"));
                }
                log_not_found = Some(parse_log_not_found_args(&args[1..])?);
            }
            ("server_tokens", Terminator::Semi) => {
                if server_tokens.is_some() {
                    return Err(Error::Duplicate("server_tokens"));
                }
                server_tokens = Some(parse_server_tokens_args(&args[1..])?);
            }
            ("autoindex", Terminator::Semi) => {
                if autoindex.is_some() {
                    return Err(Error::Duplicate("autoindex"));
                }
                autoindex = Some(parse_on_off_args(&args[1..], "autoindex")?);
            }
            ("autoindex_exact_size", Terminator::Semi) => {
                if autoindex_exact_size.is_some() {
                    return Err(Error::Duplicate("autoindex_exact_size"));
                }
                autoindex_exact_size = Some(parse_on_off_args(&args[1..], "autoindex_exact_size")?);
            }
            ("autoindex_localtime", Terminator::Semi) => {
                if autoindex_localtime.is_some() {
                    return Err(Error::Duplicate("autoindex_localtime"));
                }
                autoindex_localtime = Some(parse_on_off_args(&args[1..], "autoindex_localtime")?);
            }
            ("autoindex_format", Terminator::Semi) => {
                if autoindex_format.is_some() {
                    return Err(Error::Duplicate("autoindex_format"));
                }
                autoindex_format = Some(parse_autoindex_format_args(&args[1..])?);
            }
            ("access_log", Terminator::Semi) => {
                let list = access_logs.get_or_insert_with(Vec::new);
                match parse_access_log_args(&args[1..])? {
                    ParsedAccessLog::Off => list.clear(),
                    ParsedAccessLog::Entry(log) => list.push(log),
                }
            }
            ("auth_basic", Terminator::Semi) => {
                if auth_basic.is_some() {
                    return Err(Error::Duplicate("auth_basic"));
                }
                auth_basic = Some(parse_auth_basic_args(&args[1..])?);
            }
            ("auth_basic_user_file", Terminator::Semi) => {
                if auth_basic_user_file.is_some() {
                    return Err(Error::Duplicate("auth_basic_user_file"));
                }
                auth_basic_user_file = Some(parse_auth_basic_user_file_args(&args[1..])?);
            }
            ("auth_delay", Terminator::Semi) => {
                if auth_delay_ms.is_some() {
                    return Err(Error::Duplicate("auth_delay"));
                }
                let raw = args.get(1).ok_or(Error::MissingArg("auth_delay"))?;
                auth_delay_ms = Some(parse_duration_ms(raw, "auth_delay")?);
            }
            ("client_max_body_size", Terminator::Semi) => {
                if client_max_body_size.is_some() {
                    return Err(Error::Duplicate("client_max_body_size"));
                }
                client_max_body_size = Some(parse_client_max_body_size_args(&args[1..])?);
            }
            ("client_body_in_file_only", Terminator::Semi) => {
                if client_body_in_file_only.is_some() {
                    return Err(Error::Duplicate("client_body_in_file_only"));
                }
                let raw = args
                    .get(1)
                    .ok_or(Error::MissingArg("client_body_in_file_only"))?;
                client_body_in_file_only = Some(match raw.as_str() {
                    "on" => ClientBodyInFileOnly::On,
                    "off" => ClientBodyInFileOnly::Off,
                    "clean" => ClientBodyInFileOnly::Clean,
                    _ => {
                        return Err(Error::BadValue {
                            what: "client_body_in_file_only",
                            got: raw.clone(),
                        });
                    }
                });
            }
            ("post_action", Terminator::Semi) => {
                if post_action.is_some() {
                    return Err(Error::Duplicate("post_action"));
                }
                post_action = Some(parse_post_action_args(&args[1..])?);
            }
            ("expires", Terminator::Semi) => {
                if expires.is_some() {
                    return Err(Error::Duplicate("expires"));
                }
                expires = Some(parse_expires_args(&args[1..])?);
            }
            ("root", Terminator::Semi) => {
                if local_path_mapping.is_some() {
                    return Err(Error::Duplicate("root/alias"));
                }
                let path = args.get(1).ok_or(Error::MissingArg("root path"))?;
                root = Some((PathBuf::from(path), PathMapping::Root));
                local_path_mapping = Some(PathMapping::Root);
                alias_prefix_override = None;
            }
            ("alias", Terminator::Semi) => {
                if local_path_mapping.is_some() {
                    return Err(Error::Duplicate("root/alias"));
                }
                if matches!(spec.mode, MatchMode::Named) {
                    return Err(Error::BadValue {
                        what: "alias in named location",
                        got: spec.pattern.clone(),
                    });
                }
                let path = args.get(1).ok_or(Error::MissingArg("alias path"))?;
                root = Some((PathBuf::from(path), PathMapping::Alias));
                local_path_mapping = Some(PathMapping::Alias);
                alias_prefix_override = None;
            }
            ("index", Terminator::Semi) => {
                if index.is_some() {
                    return Err(Error::Duplicate("index"));
                }
                if args.len() < 2 {
                    return Err(Error::MissingArg("index"));
                }
                index = Some(parse_index_entries(&args[1..])?);
            }
            ("try_files", Terminator::Semi) => {
                if try_files.is_some() {
                    return Err(Error::Duplicate("try_files"));
                }
                // nginx requires 2+ args: one probe + one fallback.
                if args.len() < 3 {
                    return Err(Error::MissingArg("try_files"));
                }
                try_files = Some(parse_try_files(&args[1..])?);
            }
            ("proxy_pass", Terminator::Semi) => {
                if proxy_pass.is_some() {
                    return Err(Error::Duplicate("proxy_pass"));
                }
                proxy_pass = Some(parse_proxy_pass_arg(&args[1..])?);
            }
            ("proxy_set_header", Terminator::Semi) => {
                let entry = parse_proxy_set_header_args(&args[1..])?;
                proxy_set_headers.get_or_insert_with(Vec::new).push(entry);
            }
            ("proxy_pass_request_headers", Terminator::Semi) => {
                if proxy_pass_request_headers.is_some() {
                    return Err(Error::Duplicate("proxy_pass_request_headers"));
                }
                proxy_pass_request_headers =
                    Some(parse_on_off_args(&args[1..], "proxy_pass_request_headers")?);
            }
            ("proxy_pass_request_body", Terminator::Semi) => {
                if proxy_pass_request_body.is_some() {
                    return Err(Error::Duplicate("proxy_pass_request_body"));
                }
                proxy_pass_request_body =
                    Some(parse_on_off_args(&args[1..], "proxy_pass_request_body")?);
            }
            ("proxy_connect_timeout", Terminator::Semi) => {
                if proxy_connect_timeout_ms.is_some() {
                    return Err(Error::Duplicate("proxy_connect_timeout"));
                }
                proxy_connect_timeout_ms = Some(parse_proxy_timeout_args(
                    &args[1..],
                    "proxy_connect_timeout",
                )?);
            }
            ("proxy_read_timeout", Terminator::Semi) => {
                if proxy_read_timeout_ms.is_some() {
                    return Err(Error::Duplicate("proxy_read_timeout"));
                }
                proxy_read_timeout_ms =
                    Some(parse_proxy_timeout_args(&args[1..], "proxy_read_timeout")?);
            }
            ("proxy_send_timeout", Terminator::Semi) => {
                if proxy_send_timeout_ms.is_some() {
                    return Err(Error::Duplicate("proxy_send_timeout"));
                }
                proxy_send_timeout_ms =
                    Some(parse_proxy_timeout_args(&args[1..], "proxy_send_timeout")?);
            }
            ("proxy_limit_rate", Terminator::Semi) => {
                if proxy_limit_rate.is_some() {
                    return Err(Error::Duplicate("proxy_limit_rate"));
                }
                let v = args.get(1).ok_or(Error::MissingArg("proxy_limit_rate"))?;
                proxy_limit_rate =
                    Some(crate::config::parse_server::parse_size_bytes(v).ok_or(
                        Error::BadValue {
                            what: "proxy_limit_rate",
                            got: v.clone(),
                        },
                    )?);
            }
            ("proxy_http_version", Terminator::Semi) => {
                if proxy_http_version.is_some() {
                    return Err(Error::Duplicate("proxy_http_version"));
                }
                proxy_http_version = Some(parse_proxy_http_version_args(&args[1..])?);
            }
            ("proxy_next_upstream", Terminator::Semi) => {
                if proxy_next_upstream.is_some() {
                    return Err(Error::Duplicate("proxy_next_upstream"));
                }
                proxy_next_upstream = Some(parse_proxy_next_upstream_args(&args[1..])?);
            }
            ("proxy_next_upstream_tries", Terminator::Semi) => {
                if proxy_next_upstream_tries.is_some() {
                    return Err(Error::Duplicate("proxy_next_upstream_tries"));
                }
                let v = args
                    .get(1)
                    .ok_or(Error::MissingArg("proxy_next_upstream_tries"))?;
                proxy_next_upstream_tries =
                    Some(v.parse::<u32>().map_err(|_| Error::BadValue {
                        what: "proxy_next_upstream_tries",
                        got: v.clone(),
                    })?);
            }
            ("proxy_next_upstream_timeout", Terminator::Semi) => {
                if proxy_next_upstream_timeout_ms.is_some() {
                    return Err(Error::Duplicate("proxy_next_upstream_timeout"));
                }
                let v = args
                    .get(1)
                    .ok_or(Error::MissingArg("proxy_next_upstream_timeout"))?;
                proxy_next_upstream_timeout_ms =
                    Some(parse_duration_ms(v, "proxy_next_upstream_timeout")?);
            }
            ("proxy_intercept_errors", Terminator::Semi) => {
                if proxy_intercept_errors.is_some() {
                    return Err(Error::Duplicate("proxy_intercept_errors"));
                }
                proxy_intercept_errors =
                    Some(parse_on_off_args(&args[1..], "proxy_intercept_errors")?);
            }
            ("chunked_transfer_encoding", Terminator::Semi) => {
                if chunked_transfer_encoding.is_some() {
                    return Err(Error::Duplicate("chunked_transfer_encoding"));
                }
                chunked_transfer_encoding =
                    Some(parse_on_off_args(&args[1..], "chunked_transfer_encoding")?);
            }
            ("location", Terminator::BlockOpen) => {
                let child_spec = parse_location_spec(&args[1..])?;
                // Children see the closest ancestor's `server_tokens`:
                // this block's own value if set, else whatever was inherited
                // into this block. Their own directive still wins.
                let pass_tokens = server_tokens.or(inherited_server_tokens);
                let pass_autoindex = autoindex.or(inherited_autoindex);
                let pass_autoindex_exact_size =
                    autoindex_exact_size.or(inherited_autoindex_exact_size);
                let pass_autoindex_localtime =
                    autoindex_localtime.or(inherited_autoindex_localtime);
                let pass_autoindex_format = autoindex_format.or(inherited_autoindex_format);
                let pass_auth_basic = auth_basic.clone().or(inherited_auth_basic.clone());
                let pass_auth_file = auth_basic_user_file
                    .clone()
                    .or(inherited_auth_basic_user_file.clone());
                let pass_auth_delay_ms = auth_delay_ms.or(inherited_auth_delay_ms);
                let pass_client_max_body_size =
                    client_max_body_size.or(inherited_client_max_body_size);
                let pass_post_action = post_action.clone().or(inherited_post_action.clone());
                let pass_expires = expires.clone().or(inherited_expires.clone());
                // Cascade alias info to nested children (mirrors nginx's
                // `merge_loc_conf` for the core module's path bits): a
                // local `alias` here propagates as Alias-with-this-pattern;
                // a local `root` here shadows the inherited alias chain
                // for descendants; otherwise pass through whatever this
                // block inherited.
                let pass_inherited_alias = match local_path_mapping {
                    Some(PathMapping::Alias) => {
                        let path = root
                            .as_ref()
                            .map(|(p, _)| p.clone())
                            .expect("alias set implies root path captured");
                        Some((path, spec.pattern.clone()))
                    }
                    Some(PathMapping::Root) => None,
                    None => inherited_alias.clone(),
                };
                parse_location_block(
                    child_spec,
                    lx,
                    inherited_root.clone(),
                    pass_inherited_alias,
                    pass_tokens,
                    pass_autoindex,
                    pass_autoindex_exact_size,
                    pass_autoindex_localtime,
                    pass_autoindex_format,
                    pass_auth_basic,
                    pass_auth_file,
                    pass_auth_delay_ms,
                    pass_client_max_body_size,
                    pass_post_action,
                    pass_expires,
                    &mut children,
                )?;
            }
            (
                "set"
                | "rewrite"
                | "break"
                | "if"
                | "return"
                | "root"
                | "alias"
                | "index"
                | "try_files"
                | "add_header"
                | "error_page"
                | "keepalive_timeout"
                | "keepalive_requests"
                | "keepalive_time"
                | "keepalive_disable"
                | "error_log"
                | "log_not_found"
                | "server_tokens"
                | "autoindex"
                | "autoindex_exact_size"
                | "autoindex_localtime"
                | "autoindex_format"
                | "access_log"
                | "auth_basic"
                | "auth_basic_user_file"
                | "auth_delay"
                | "client_max_body_size"
                | "client_body_in_file_only"
                | "post_action"
                | "expires"
                | "proxy_pass"
                | "proxy_set_header"
                | "proxy_pass_request_headers"
                | "proxy_pass_request_body"
                | "proxy_connect_timeout"
                | "proxy_read_timeout"
                | "proxy_send_timeout"
                | "proxy_limit_rate"
                | "proxy_http_version"
                | "proxy_next_upstream"
                | "proxy_next_upstream_tries"
                | "proxy_next_upstream_timeout"
                | "proxy_intercept_errors"
                | "location",
                _,
            ) => {
                return Err(Error::WrongTerminator {
                    name: args[0].clone(),
                    ctx: "location",
                });
            }
            (n, Terminator::Semi) if is_ignored_stmt(n) => {}
            (n, Terminator::BlockOpen) if is_ignored_block(n) => skip_block(lx)?,
            (other, _) => {
                return Err(Error::UnknownDirective {
                    name: other.into(),
                    ctx: "location",
                });
            }
        }
    }
}

pub(crate) fn parse_try_files(args: &[String]) -> Result<TryFiles, Error> {
    // Invariant from caller: args.len() >= 2 (one probe + one fallback).
    let (fallback_raw, probe_raw) = args.split_last().unwrap();
    let mut probes: Vec<TryFilesProbe> = Vec::with_capacity(probe_raw.len());
    for s in probe_raw {
        probes.push(classify_probe(s)?);
    }
    let fallback = classify_fallback(fallback_raw)?;
    Ok(TryFiles { probes, fallback })
}

pub(crate) fn parse_auth_basic_args(args: &[String]) -> Result<AuthBasic, Error> {
    if args.len() != 1 {
        return Err(Error::BadValue {
            what: "auth_basic",
            got: args.join(" "),
        });
    }
    if args[0] == "off" {
        return Ok(AuthBasic::Off);
    }
    // Variables in the realm are unsupported — reject so the misconfig
    // surfaces at `-t` instead of silently producing `realm=""` at
    // request time.
    let parts = parse_value_with_vars(&args[0])?;
    let mut realm = Vec::with_capacity(args[0].len());
    for part in &parts {
        match part {
            ValuePart::Literal(s) => realm.extend_from_slice(s.as_bytes()),
            ValuePart::Var(_) => {
                return Err(Error::BadValue {
                    what: "auth_basic (variables are not supported in realm)",
                    got: args[0].clone(),
                });
            }
        }
    }
    Ok(AuthBasic::Realm(realm))
}

pub(crate) fn parse_auth_basic_user_file_args(args: &[String]) -> Result<PathBuf, Error> {
    if args.len() != 1 {
        return Err(Error::BadValue {
            what: "auth_basic_user_file",
            got: args.join(" "),
        });
    }
    Ok(PathBuf::from(&args[0]))
}

pub(crate) fn parse_on_off_args(args: &[String], what: &'static str) -> Result<bool, Error> {
    if args.len() != 1 {
        return Err(Error::BadValue {
            what,
            got: args.join(" "),
        });
    }
    match args[0].as_str() {
        "on" => Ok(true),
        "off" => Ok(false),
        _ => Err(Error::BadValue {
            what,
            got: args[0].clone(),
        }),
    }
}

pub(crate) fn parse_autoindex_format_args(args: &[String]) -> Result<AutoindexFormat, Error> {
    if args.len() != 1 {
        return Err(Error::BadValue {
            what: "autoindex_format",
            got: args.join(" "),
        });
    }
    match args[0].as_str() {
        "html" => Ok(AutoindexFormat::Html),
        "xml" => Ok(AutoindexFormat::Xml),
        "json" => Ok(AutoindexFormat::Json),
        "jsonp" => Ok(AutoindexFormat::Jsonp),
        _ => Err(Error::BadValue {
            what: "autoindex_format",
            got: args[0].clone(),
        }),
    }
}

pub(crate) fn parse_log_not_found_args(args: &[String]) -> Result<bool, Error> {
    parse_on_off_args(args, "log_not_found")
}

pub(crate) fn parse_error_page_args(args: &[String]) -> Result<Vec<ErrorPage>, Error> {
    if args.len() < 2 {
        return Err(Error::MissingArg("error_page"));
    }

    let (statuses, action, target_raw) = match args.get(args.len() - 2) {
        Some(marker) if marker.starts_with('=') => {
            if args.len() < 3 {
                return Err(Error::MissingArg("error_page"));
            }
            let action = if marker == "=" {
                ErrorPageAction::UseTargetStatus
            } else {
                let code = marker[1..].parse::<u16>().map_err(|_| Error::BadValue {
                    what: "error_page overwrite",
                    got: marker.clone(),
                })?;
                ErrorPageAction::Override(code)
            };
            (&args[..args.len() - 2], action, args.last().unwrap())
        }
        _ => (
            &args[..args.len() - 1],
            ErrorPageAction::PreserveOriginal,
            args.last().unwrap(),
        ),
    };

    if statuses.is_empty() {
        return Err(Error::MissingArg("error_page status"));
    }
    if target_raw == "@" || (target_raw.starts_with('@') && target_raw.contains('?')) {
        return Err(Error::BadValue {
            what: "error_page named location",
            got: target_raw.clone(),
        });
    }

    let target = parse_value_with_vars(target_raw)?;
    reject_sent_http_parts(&target, "error_page target ($sent_http_* unavailable)")?;
    let mut out = Vec::with_capacity(statuses.len());
    for status_s in statuses {
        let status = status_s.parse::<u16>().map_err(|_| Error::BadValue {
            what: "error_page status",
            got: status_s.clone(),
        })?;
        if status == 499 {
            return Err(Error::BadValue {
                what: "error_page status",
                got: status_s.clone(),
            });
        }
        out.push(ErrorPage {
            status,
            action,
            target: target.clone(),
        });
    }
    Ok(out)
}

pub(crate) fn classify_probe(s: &str) -> Result<TryFilesProbe, Error> {
    if s.is_empty() {
        return Err(Error::BadValue {
            what: "try_files probe",
            got: s.into(),
        });
    }
    let (name, is_slash) = if let Some(stripped) = s.strip_suffix('/') {
        (stripped, true)
    } else {
        (s, false)
    };
    if name == "$uri" {
        Ok(if is_slash {
            TryFilesProbe::UriSlash
        } else {
            TryFilesProbe::Uri
        })
    } else if name.contains('$') {
        // Any other variable reference is out of scope for M6.
        Err(Error::BadValue {
            what: "try_files probe (unsupported variable)",
            got: s.into(),
        })
    } else if is_slash {
        Ok(TryFilesProbe::LiteralSlash(name.into()))
    } else {
        Ok(TryFilesProbe::Literal(name.into()))
    }
}

pub(crate) fn classify_fallback(s: &str) -> Result<TryFilesFallback, Error> {
    if let Some(code_s) = s.strip_prefix('=') {
        let code = code_s.parse::<u16>().map_err(|_| Error::BadValue {
            what: "try_files fallback status",
            got: s.into(),
        })?;
        if !(100..=599).contains(&code) {
            return Err(Error::BadValue {
                what: "try_files fallback status (out of range)",
                got: s.into(),
            });
        }
        Ok(TryFilesFallback::Status(code))
    } else if s.starts_with('@') {
        if s.len() == 1 || s.contains('?') {
            return Err(Error::BadValue {
                what: "try_files fallback named location",
                got: s.into(),
            });
        }
        Ok(TryFilesFallback::Named(s.into()))
    } else if s.contains('$') {
        Err(Error::BadValue {
            what: "try_files fallback (variables not supported)",
            got: s.into(),
        })
    } else {
        Ok(TryFilesFallback::Uri(s.into()))
    }
}

pub(crate) fn parse_index_entries(args: &[String]) -> Result<Vec<IndexEntry>, Error> {
    let mut out = Vec::with_capacity(args.len());
    for arg in args {
        let parts = parse_value_with_vars(arg)?;
        reject_sent_http_parts(&parts, "index entry ($sent_http_* unavailable)")?;
        out.push(IndexEntry { parts });
    }
    Ok(out)
}

/// Parse the arguments after the `add_header` keyword. Accepts:
///   add_header NAME VALUE;
///   add_header NAME VALUE always;
/// `always` toggles emission on error responses; without it, only success/
/// redirect statuses receive the header (nginx's default).
pub(crate) fn parse_add_header_args(args: &[String]) -> Result<AddHeader, Error> {
    if args.len() < 2 || args.len() > 3 {
        return Err(Error::BadValue {
            what: "add_header",
            got: args.join(" "),
        });
    }
    let always = match args.get(2) {
        None => false,
        Some(s) if s == "always" => true,
        Some(s) => {
            return Err(Error::BadValue {
                what: "add_header modifier (expected `always`)",
                got: s.clone(),
            });
        }
    };
    let name = args[0].clone();
    if name.is_empty() || !name.bytes().all(is_header_name_char) {
        return Err(Error::BadValue {
            what: "add_header name",
            got: name,
        });
    }
    let value = parse_value_with_vars(&args[1])?;
    Ok(AddHeader {
        name,
        value,
        always,
    })
}
