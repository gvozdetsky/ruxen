// nginx.conf parser.
//
// Shape mirrors the C parser (tokenize-one-directive → dispatch) but without
// the int-code + out-param side channel: the lexer returns (args, terminator).
//
// Submodule layout:
//   - ast: typed AST emitted by parse() and consumed by `worker::prepare`
//   - error: parse-time Error type with nginx-shaped Display impl
//   - lexer: tokenizer + frame stack + include-directive resolution
//   - values: $var lowering and variable classification
//   - parse_{server,location,rewrite,upstream,log,map}: per-block parsers
//
// Cross-submodule helpers are `pub(crate)` and re-exported flat into the
// `config::` namespace so any submodule can call any other's helper without
// chasing the path. External crate consumers only see the public types
// (re-exported from `ast`) plus `parse`, `parse_with_main`, and
// `parse_value_with_vars`.

use std::path::{Path, PathBuf};

mod ast;
mod error;
mod lexer;
mod parse_location;
mod parse_log;
mod parse_map;
mod parse_rewrite;
mod parse_server;
mod parse_upstream;
mod values;

pub use ast::*;
pub use error::*;
pub use values::{SSL_SESSION_ID_USED, parse_value_with_vars};

pub(crate) use lexer::*;
pub(crate) use parse_location::*;
pub(crate) use parse_log::*;
pub(crate) use parse_map::*;
pub(crate) use parse_rewrite::*;
pub(crate) use parse_server::*;
pub(crate) use parse_upstream::*;
pub(crate) use values::*;

/// Test-only parse entry that takes inline source and synthesizes a single
/// nameless frame. Production code goes through `parse_with_main`.
#[cfg(test)]
pub fn parse(src: &str) -> Result<HttpConfig, Error> {
    parse_lexer(Lexer::new_inline(src))
}

/// Like `parse`, but ties the lexer's first frame to a real file path so
/// relative `include` targets resolve correctly and the `nginx -T` dump
/// includes the main config as its first entry. `globals_src` (from `-g`)
/// is layered on top as a synthetic frame so its directives are seen first
/// without polluting the main file's dump entry.
pub fn parse_with_main(
    main_path: PathBuf,
    src: String,
    globals_src: Option<String>,
) -> Result<HttpConfig, Error> {
    let mut lx = Lexer::new_with_main(main_path, src);
    if let Some(g) = globals_src {
        if !g.is_empty() {
            lx.push_inline(g);
        }
    }
    parse_lexer(lx)
}

pub(crate) fn parse_lexer(mut lx: Lexer) -> Result<HttpConfig, Error> {
    reset_variable_registry();
    let mut runtime = RuntimeOpts::default();
    let mut http: Option<HttpConfig> = None;

    loop {
        let (args, term) = lx.read_directive()?;
        if args.is_empty() {
            match term {
                Terminator::Eof => break,
                Terminator::BlockClose => return Err(Error::UnexpectedToken("}".into())),
                _ => continue,
            }
        }
        let name = args[0].as_str();
        match (name, &term) {
            ("http", Terminator::BlockOpen) => {
                if http.is_some() {
                    return Err(Error::Duplicate("http"));
                }
                let block = parse_http_block(&mut lx)?;
                validate_proxy_upstream_refs(&block)?;
                http = Some(block);
            }
            ("http", _) => {
                return Err(Error::WrongTerminator {
                    name: name.into(),
                    ctx: "top-level",
                });
            }
            ("events", Terminator::BlockOpen) => parse_events_block(&mut lx, &mut runtime)?,
            ("events", _) => {
                return Err(Error::WrongTerminator {
                    name: name.into(),
                    ctx: "top-level",
                });
            }
            ("pid", Terminator::Semi) => {
                if runtime.pid.is_some() {
                    return Err(Error::Duplicate("pid"));
                }
                let path = args.get(1).ok_or(Error::MissingArg("pid path"))?;
                runtime.pid = Some(PathBuf::from(path));
            }
            ("pid", _) => {
                return Err(Error::WrongTerminator {
                    name: name.into(),
                    ctx: "top-level",
                });
            }
            ("worker_processes", Terminator::Semi) => {
                if runtime.worker_processes.is_some() {
                    return Err(Error::Duplicate("worker_processes"));
                }
                let raw = args.get(1).ok_or(Error::MissingArg("worker_processes"))?;
                runtime.worker_processes = Some(if raw == "auto" {
                    WorkerProcesses::Auto
                } else {
                    let n: usize = raw.parse().map_err(|_| Error::BadValue {
                        what: "worker_processes",
                        got: raw.clone(),
                    })?;
                    if n == 0 {
                        return Err(Error::BadValue {
                            what: "worker_processes",
                            got: raw.clone(),
                        });
                    }
                    WorkerProcesses::Count(n)
                });
            }
            ("worker_processes", _) => {
                return Err(Error::WrongTerminator {
                    name: name.into(),
                    ctx: "top-level",
                });
            }
            ("error_log", Terminator::Semi) => {
                runtime.error_logs.push(parse_error_log_args(&args[1..])?);
            }
            // nginx's ngx_conf_set_num_slot / ngx_conf_set_off_slot.
            ("worker_rlimit_nofile" | "worker_rlimit_core", Terminator::Semi) => {
                let nofile = name == "worker_rlimit_nofile";
                let what = if nofile {
                    "worker_rlimit_nofile"
                } else {
                    "worker_rlimit_core"
                };
                let slot = if nofile {
                    &mut runtime.worker_rlimit_nofile
                } else {
                    &mut runtime.worker_rlimit_core
                };
                if slot.is_some() {
                    return Err(Error::Duplicate(what));
                }
                let [_, raw] = args.as_slice() else {
                    return Err(Error::BadValue {
                        what,
                        got: args[1..].join(" "),
                    });
                };
                let value = if nofile {
                    raw.parse::<u64>().ok()
                } else {
                    parse_size(raw.as_bytes())
                };
                *slot = Some(value.ok_or_else(|| Error::BadValue {
                    what,
                    got: raw.clone(),
                })?);
            }
            ("worker_shutdown_timeout", Terminator::Semi) => {
                if runtime.worker_shutdown_timeout_ms.is_some() {
                    return Err(Error::Duplicate("worker_shutdown_timeout"));
                }
                let [_, raw] = args.as_slice() else {
                    return Err(Error::BadValue {
                        what: "worker_shutdown_timeout",
                        got: args[1..].join(" "),
                    });
                };
                runtime.worker_shutdown_timeout_ms =
                    Some(parse_duration_ms(raw, "worker_shutdown_timeout")?);
            }
            // `user name [group];` — recorded so `main` can refuse a switch
            // it can't make (see `check_privileges`).
            ("user", Terminator::Semi) => {
                if runtime.user.is_some() {
                    return Err(Error::Duplicate("user"));
                }
                let user = args.get(1).ok_or(Error::MissingArg("user"))?;
                runtime.user = Some(user.clone());
            }
            ("user", _) => {
                return Err(Error::WrongTerminator {
                    name: name.into(),
                    ctx: "top-level",
                });
            }
            (n, Terminator::Semi) if is_ignored_stmt(n) => {}
            (n, Terminator::BlockOpen) if is_ignored_block(n) => skip_block(&mut lx)?,
            _ => {
                return Err(Error::UnknownDirective {
                    name: name.into(),
                    ctx: "top-level",
                });
            }
        }
    }

    let mut http = http.ok_or(Error::UnexpectedEof)?;
    http.warnings.extend(check_variable_references()?);
    http.runtime = runtime;
    http.dump_files = lx.take_dump_files();
    http.conf_prefix = lx.conf_prefix().map(Path::to_path_buf);
    Ok(http)
}

pub(crate) fn parse_http_block(lx: &mut Lexer) -> Result<HttpConfig, Error> {
    let mut servers = Vec::new();
    let mut root: Option<PathBuf> = None;
    let mut log_formats: Vec<LogFormatDef> = Vec::new();
    let mut access_logs: Vec<AccessLog> = Vec::new();
    let mut server_tokens: Option<ServerTokens> = None;
    let mut autoindex: Option<bool> = None;
    let mut autoindex_exact_size: Option<bool> = None;
    let mut autoindex_localtime: Option<bool> = None;
    let mut autoindex_format: Option<AutoindexFormat> = None;
    let mut split_clients: Vec<SplitClients> = Vec::new();
    let mut maps: Vec<MapBlock> = Vec::new();
    let mut auth_basic: Option<AuthBasic> = None;
    let mut auth_basic_user_file: Option<PathBuf> = None;
    let mut auth_delay_ms: Option<u64> = None;
    let mut client_max_body_size: Option<u64> = None;
    let mut client_body_temp_path: Option<TempPath> = None;
    let mut sendfile: Option<bool> = None;
    let mut disable_symlinks: Option<DisableSymlinks> = None;
    let mut limit_rate: Option<Vec<ValuePart>> = None;
    let mut limit_rate_after: Option<Vec<ValuePart>> = None;
    let mut keepalive_timeout: Option<KeepaliveTimeout> = None;
    let mut keepalive_requests: Option<u64> = None;
    let mut keepalive_time_ms: Option<u64> = None;
    let mut keepalive_disable: Option<KeepaliveDisable> = None;
    let mut client_timeouts = ClientTimeouts::default();
    let mut error_logs: Option<Vec<ErrorLog>> = None;
    let mut post_action: Option<String> = None;
    let mut expires: Option<ExpiresDirective> = None;
    let mut ignore_invalid_headers: Option<bool> = None;
    let mut underscores_in_headers: Option<bool> = None;
    let mut upstreams: Vec<UpstreamBlock> = Vec::new();
    // http-scope SSL defaults inherited by `server {}` blocks unless
    // they define their own cert/key pair.
    let mut ssl_certs: Vec<PathBuf> = Vec::new();
    let mut ssl_keys: Vec<PathBuf> = Vec::new();
    let mut ssl_protocols: Option<TlsVersionSet> = None;
    let mut ssl_ciphers: Option<String> = None;
    let mut ssl_prefer_server_ciphers: Option<bool> = None;
    let mut ssl_session_timeout_ms: Option<u64> = None;
    let mut resumption = SessionResumption::default();
    let mut warnings: Vec<String> = Vec::new();
    loop {
        let (args, term) = lx.read_directive()?;
        if args.is_empty() {
            return match term {
                Terminator::BlockClose => Ok(HttpConfig {
                    runtime: RuntimeOpts::default(),
                    error_logs,
                    log_formats,
                    access_logs,
                    server_tokens,
                    autoindex,
                    autoindex_exact_size,
                    autoindex_localtime,
                    autoindex_format,
                    split_clients,
                    maps,
                    auth_basic,
                    auth_basic_user_file,
                    auth_delay_ms,
                    client_max_body_size,
                    client_body_temp_path,
                    sendfile,
                    disable_symlinks,
                    limit_rate,
                    limit_rate_after,
                    post_action,
                    expires,
                    ignore_invalid_headers,
                    underscores_in_headers,
                    upstreams,
                    warnings: warn_ssl_without_ssl_listen(&servers, warnings),
                    servers,
                    dump_files: Vec::new(),
                    conf_prefix: None,
                }),
                Terminator::Eof => Err(Error::UnclosedBlock),
                _ => Err(Error::UnexpectedEof),
            };
        }
        match (args[0].as_str(), &term) {
            ("server", Terminator::BlockOpen) => servers.extend(parse_server_block(
                lx,
                root.clone(),
                &ssl_certs,
                &ssl_keys,
                ssl_protocols,
                ssl_ciphers.as_deref(),
                ssl_prefer_server_ciphers,
                ssl_session_timeout_ms,
                resumption,
                client_max_body_size,
                keepalive_timeout,
                keepalive_requests,
                keepalive_time_ms,
                keepalive_disable,
                client_timeouts,
                &mut warnings,
            )?),
            ("server", _) => {
                return Err(Error::WrongTerminator {
                    name: "server".into(),
                    ctx: "http",
                });
            }
            ("root", Terminator::Semi) => {
                let path = args.get(1).ok_or(Error::MissingArg("root path"))?;
                root = Some(PathBuf::from(path));
            }
            ("root", _) => {
                return Err(Error::WrongTerminator {
                    name: "root".into(),
                    ctx: "http",
                });
            }
            ("merge_slashes", Terminator::Semi) => {
                // Accepted at http scope so configs that set it once outside
                // the server block still parse. Inheritance: we don't plumb
                // an http-level merge-slashes into every server, so this is
                // effectively a no-op today — server-level `merge_slashes`
                // is what actually flips the normalizer. Documenting that
                // here so a future pass can wire inheritance if a test
                // needs it.
                let _ = args.get(1).ok_or(Error::MissingArg("merge_slashes"))?;
            }
            ("log_format", Terminator::Semi) => {
                log_formats.push(parse_log_format_args(&args[1..])?);
            }
            ("access_log", Terminator::Semi) => match parse_access_log_args(&args[1..])? {
                ParsedAccessLog::Off => access_logs.clear(),
                ParsedAccessLog::Entry(log) => access_logs.push(log),
            },
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
            ("split_clients", Terminator::BlockOpen) => {
                split_clients.push(parse_split_clients_block(&args[1..], lx)?);
            }
            ("map", Terminator::BlockOpen) => {
                maps.push(parse_map_block(&args[1..], lx)?);
            }
            ("map", _) => {
                return Err(Error::WrongTerminator {
                    name: "map".into(),
                    ctx: "http",
                });
            }
            ("upstream", Terminator::BlockOpen) => {
                let block = parse_upstream_block(&args[1..], lx)?;
                if upstreams.iter().any(|u| u.name == block.name) {
                    return Err(Error::Duplicate("upstream"));
                }
                upstreams.push(block);
            }
            ("upstream", _) => {
                return Err(Error::WrongTerminator {
                    name: "upstream".into(),
                    ctx: "http",
                });
            }
            ("ssl_certificate", Terminator::Semi) => {
                let path = args.get(1).ok_or(Error::MissingArg("ssl_certificate"))?;
                ssl_certs.push(resolve_ssl_file_arg(lx.conf_prefix(), path));
            }
            ("ssl_certificate_key", Terminator::Semi) => {
                let path = args
                    .get(1)
                    .ok_or(Error::MissingArg("ssl_certificate_key"))?;
                ssl_keys.push(resolve_ssl_file_arg(lx.conf_prefix(), path));
            }
            ("ssl_protocols", Terminator::Semi) => {
                if ssl_protocols.is_some() {
                    return Err(Error::Duplicate("ssl_protocols"));
                }
                if args.len() < 2 {
                    return Err(Error::MissingArg("ssl_protocols"));
                }
                let mut set = TlsVersionSet {
                    tlsv1_2: false,
                    tlsv1_3: false,
                };
                for v in &args[1..] {
                    match v.as_str() {
                        "TLSv1.2" => set.tlsv1_2 = true,
                        "TLSv1.3" => set.tlsv1_3 = true,
                        "SSLv2" | "SSLv3" | "TLSv1" | "TLSv1.1" => {
                            return Err(Error::BadValue {
                                what: "ssl_protocols (insecure version rejected)",
                                got: v.clone(),
                            });
                        }
                        _ => {
                            return Err(Error::BadValue {
                                what: "ssl_protocols",
                                got: v.clone(),
                            });
                        }
                    }
                }
                ssl_protocols = Some(set);
            }
            ("ssl_ciphers", Terminator::Semi) => {
                if ssl_ciphers.is_some() {
                    return Err(Error::Duplicate("ssl_ciphers"));
                }
                let v = args.get(1).ok_or(Error::MissingArg("ssl_ciphers"))?;
                ssl_ciphers = Some(v.clone());
                warn_ignored_tls_policy(&args, &mut warnings);
            }
            ("ssl_prefer_server_ciphers", Terminator::Semi) => {
                if ssl_prefer_server_ciphers.is_some() {
                    return Err(Error::Duplicate("ssl_prefer_server_ciphers"));
                }
                ssl_prefer_server_ciphers =
                    Some(parse_on_off_args(&args[1..], "ssl_prefer_server_ciphers")?);
            }
            ("ssl_session_timeout", Terminator::Semi) => {
                if ssl_session_timeout_ms.is_some() {
                    return Err(Error::Duplicate("ssl_session_timeout"));
                }
                let v = args
                    .get(1)
                    .ok_or(Error::MissingArg("ssl_session_timeout"))?;
                ssl_session_timeout_ms = Some(parse_duration_ms(v, "ssl_session_timeout")?);
            }
            (name @ ("ssl_session_cache" | "ssl_session_tickets"), Terminator::Semi) => {
                resumption.parse(name, &args)?;
            }
            (
                "ssl_session_ticket_key"
                | "ssl_buffer_size"
                | "ssl_dhparam"
                | "ssl_ecdh_curve"
                | "ssl_stapling"
                | "ssl_stapling_file"
                | "ssl_stapling_responder"
                | "ssl_stapling_verify"
                | "ssl_verify_client"
                | "ssl_verify_depth"
                | "ssl_client_certificate"
                | "ssl_trusted_certificate"
                | "ssl_crl"
                | "ssl_password_file"
                | "ssl_early_data"
                | "ssl_reject_handshake"
                | "ssl_conf_command",
                Terminator::Semi,
            ) => warn_ignored_tls_policy(&args, &mut warnings),
            (
                "log_format"
                | "access_log"
                | "server_tokens"
                | "autoindex"
                | "autoindex_exact_size"
                | "autoindex_localtime"
                | "autoindex_format"
                | "split_clients"
                | "ssl_certificate"
                | "ssl_certificate_key"
                | "ssl_protocols"
                | "ssl_ciphers"
                | "ssl_prefer_server_ciphers"
                | "ssl_session_timeout"
                | "ssl_session_cache"
                | "ssl_session_tickets"
                | "ssl_session_ticket_key"
                | "ssl_buffer_size"
                | "ssl_dhparam"
                | "ssl_ecdh_curve"
                | "ssl_stapling"
                | "ssl_stapling_file"
                | "ssl_stapling_responder"
                | "ssl_stapling_verify"
                | "ssl_verify_client"
                | "ssl_verify_depth"
                | "ssl_client_certificate"
                | "ssl_trusted_certificate"
                | "ssl_crl"
                | "ssl_password_file"
                | "ssl_early_data"
                | "ssl_reject_handshake"
                | "ssl_conf_command",
                _,
            ) => {
                return Err(Error::WrongTerminator {
                    name: args[0].clone(),
                    ctx: "http",
                });
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
                auth_basic_user_file = Some(parse_auth_basic_user_file_args(
                    &args[1..],
                    lx.conf_prefix(),
                )?);
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
            ("limit_rate", Terminator::Semi) => {
                if limit_rate.is_some() {
                    return Err(Error::Duplicate("limit_rate"));
                }
                limit_rate = Some(parse_size_value(&args[1..], "limit_rate")?);
            }
            ("limit_rate_after", Terminator::Semi) => {
                if limit_rate_after.is_some() {
                    return Err(Error::Duplicate("limit_rate_after"));
                }
                limit_rate_after = Some(parse_size_value(&args[1..], "limit_rate_after")?);
            }
            ("client_body_temp_path", Terminator::Semi) => {
                if client_body_temp_path.is_some() {
                    return Err(Error::Duplicate("client_body_temp_path"));
                }
                client_body_temp_path = Some(parse_temp_path_args(&args[1..])?);
            }
            ("disable_symlinks", Terminator::Semi) => {
                if disable_symlinks.is_some() {
                    return Err(Error::Duplicate("disable_symlinks"));
                }
                disable_symlinks = Some(parse_disable_symlinks_args(&args[1..])?);
            }
            ("sendfile", Terminator::Semi) => {
                if sendfile.is_some() {
                    return Err(Error::Duplicate("sendfile"));
                }
                sendfile = Some(parse_on_off_args(&args[1..], "sendfile")?);
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
            ("expires", _) => {
                return Err(Error::WrongTerminator {
                    name: args[0].clone(),
                    ctx: "http",
                });
            }
            ("ignore_invalid_headers", Terminator::Semi) => {
                if ignore_invalid_headers.is_some() {
                    return Err(Error::Duplicate("ignore_invalid_headers"));
                }
                ignore_invalid_headers =
                    Some(parse_on_off_args(&args[1..], "ignore_invalid_headers")?);
            }
            ("underscores_in_headers", Terminator::Semi) => {
                if underscores_in_headers.is_some() {
                    return Err(Error::Duplicate("underscores_in_headers"));
                }
                underscores_in_headers =
                    Some(parse_on_off_args(&args[1..], "underscores_in_headers")?);
            }
            ("auth_basic" | "auth_basic_user_file", _) => {
                return Err(Error::WrongTerminator {
                    name: args[0].clone(),
                    ctx: "http",
                });
            }
            ("client_max_body_size", _) => {
                return Err(Error::WrongTerminator {
                    name: args[0].clone(),
                    ctx: "http",
                });
            }
            ("post_action", _) => {
                return Err(Error::WrongTerminator {
                    name: args[0].clone(),
                    ctx: "http",
                });
            }
            ("auth_delay", _) => {
                return Err(Error::WrongTerminator {
                    name: args[0].clone(),
                    ctx: "http",
                });
            }
            ("ignore_invalid_headers" | "underscores_in_headers", _) => {
                return Err(Error::WrongTerminator {
                    name: args[0].clone(),
                    ctx: "http",
                });
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
            (
                name @ ("client_header_timeout" | "client_body_timeout" | "send_timeout"),
                Terminator::Semi,
            ) => {
                client_timeouts.parse(name, &args)?;
            }
            ("error_log", Terminator::Semi) => {
                error_logs
                    .get_or_insert_with(Vec::new)
                    .push(parse_error_log_args(&args[1..])?);
            }
            (n, Terminator::Semi) if is_ignored_stmt(n) => {}
            (n, Terminator::BlockOpen) if is_ignored_block(n) => skip_block(lx)?,
            (other, _) => {
                return Err(Error::UnknownDirective {
                    name: other.into(),
                    ctx: "http",
                });
            }
        }
    }
}

/// Directives that take a `;` and we accept-but-ignore. Union across scopes
/// (top-level / http / server / location) — scope-precision isn't load-bearing
/// for no-ops and keeps the match arms readable. Extend here when a test
/// config bumps into a new unhandled tuning knob.
///
/// Policy: explicit allowlist. Unknown directives still fail hard — that's
/// how a test config using a feature we don't implement surfaces as a clear
/// "not yet" failure instead of a silent wrong-answer.
pub(crate) const IGNORED_STMT: &[&str] = &[
    // Master / worker lifecycle knobs
    "daemon",
    "master_process",
    "worker_priority",
    "worker_cpu_affinity",
    "load_module",
    "error_log",
    "timer_resolution",
    "pcre_jit",
    "thread_pool",
    "lock_file",
    "working_directory",
    "debug_points",
    "env",
    // Logging / access-log / format
    "access_log",
    "log_format",
    "log_not_found",
    "log_subrequest",
    "rewrite_log",
    // Body / header buffer tuning
    "client_body_buffer_size",
    "client_body_timeout",
    "client_body_in_file_only",
    "client_body_in_single_buffer",
    "client_max_body_size",
    "client_header_buffer_size",
    "client_header_timeout",
    "large_client_header_buffers",
    "send_timeout",
    "connection_pool_size",
    "request_pool_size",
    // TCP / send tuning
    "sendfile",
    "sendfile_max_chunk",
    "tcp_nopush",
    "tcp_nodelay",
    "reset_timedout_connection",
    "lingering_close",
    "lingering_timeout",
    "lingering_time",
    // Response-surface tuning
    "default_type",
    "chunked_transfer_encoding",
    "output_buffers",
    "postpone_output",
    "server_name_in_redirect",
    "port_in_redirect",
    "absolute_redirect",
    "server_names_hash_bucket_size",
    "server_names_hash_max_size",
    "types_hash_bucket_size",
    "types_hash_max_size",
    "variables_hash_bucket_size",
    "variables_hash_max_size",
    "map_hash_bucket_size",
    "map_hash_max_size",
    // Misc request handling we treat as no-op for now
    "ignore_invalid_headers",
    "underscores_in_headers",
    "if_modified_since",
    "etag",
    "msie_padding",
    "msie_refresh",
    // Only `off` gets here: the other values are refused by
    // `reject_unenforced`.
    // Without allow/deny (not implemented, so an error), `satisfy any`
    // and `all` both reduce to auth_basic alone.
    "satisfy",
    // DNS resolver: accepted and unused, since proxy_pass addresses are
    // resolved at startup (runtime DNS is #133).
    "resolver",
    "resolver_timeout",
    // Proxy tuning knobs we don't implement yet but accept as no-ops so
    // upstream nginx-tests configs (which inject these via TEST_GLOBALS_HTTP)
    // load.
    "proxy_temp_path",
    "proxy_temp_file_write_size",
    "proxy_max_temp_file_size",
    "proxy_buffering",
    "proxy_buffers",
    "proxy_buffer_size",
    "proxy_busy_buffers_size",
    "proxy_request_buffering",
    "proxy_ignore_client_abort",
    // proxy_intercept_errors / proxy_next_upstream / _tries / _timeout are
    // explicitly handled at server + location scope; they remain in
    // this allowlist so http-scope occurrences (e.g., from upstream tests'
    // TEST_GLOBALS_HTTP preambles) are silently ignored.
    "proxy_intercept_errors",
    "proxy_next_upstream",
    "proxy_next_upstream_tries",
    "proxy_next_upstream_timeout",
    "proxy_redirect",
    "proxy_method",
    "proxy_http_version",
    "proxy_force_ranges",
    "proxy_pass_header",
    "proxy_hide_header",
    "proxy_cookie_domain",
    "proxy_cookie_path",
    "proxy_cookie_flags",
    "proxy_socket_keepalive",
    "proxy_bind",
    "proxy_store",
    "proxy_store_access",
    // File I/O knobs (we use std::fs; these are nginx-only tuning)
    "aio",
    "aio_write",
    "directio",
    "directio_alignment",
    "read_ahead",
    "open_file_cache",
    "open_file_cache_valid",
    "open_file_cache_min_uses",
    "open_file_cache_errors",
    // Modules we don't have but their directives appear in preambles
    "gzip",
    "gzip_http_version",
    "gzip_comp_level",
    "gzip_proxied",
    "gzip_types",
    "gzip_vary",
    "gzip_min_length",
    "gzip_buffers",
    "gzip_disable",
    "gzip_static",
    "ssi",
    "ssi_silent_errors",
    "ssi_types",
    "charset",
    "source_charset",
    "override_charset",
];

/// Block directives whose body we swallow wholesale (no inner parsing).
pub(crate) const IGNORED_BLOCK: &[&str] = &["events", "types", "charset_map"];

/// Fail closed on directives that restrict access, when ruxen can't
/// enforce them yet. The allowlist above is for tuning knobs; silently
/// dropping one of these would serve what the config says to protect.
/// Forms nginx itself doesn't enforce still load: `ssl_verify_client off`,
/// and `optional` / `optional_no_ca`, where nginx admits clients without a
/// certificate and the config decides via `$ssl_client_verify` — which
/// ruxen renders as `NONE`, so a `= SUCCESS` check denies (see
/// `warn_ignored_tls_policy`).
/// Called by the lexer for every directive, so no scope can miss it.
pub(crate) fn reject_unenforced(args: &[String]) -> Result<(), Error> {
    let value = args.get(1).map(String::as_str);
    let consequence = match args.first().map(String::as_str) {
        Some("limit_except") => "the method restrictions inside it would not apply",
        Some("ssl_verify_client") if value == Some("on") => {
            "clients would be accepted without a certificate"
        }
        Some("ssl_reject_handshake") if value == Some("on") => {
            "handshakes for unknown names would complete with the default certificate"
        }
        _ => return Ok(()),
    };
    Err(Error::Unenforced {
        name: args[0].clone(),
        consequence,
    })
}

/// Accepted with a warning: `ssl_ciphers` / `ssl_ecdh_curve`, because
/// rustls offers only AEAD suites and modern groups, so ignoring a
/// restriction can't enable a weak cipher, and nearly every real TLS
/// config sets them; `ssl_verify_client optional*` (see above).
pub(crate) fn warn_ignored_tls_policy(args: &[String], warnings: &mut Vec<String>) {
    let name = args[0].as_str();
    let w = match (name, args.get(1).map(String::as_str)) {
        ("ssl_ciphers", _) => format!(
            "\"{name}\" is not supported yet and is ignored: rustls's default cipher suites are used"
        ),
        ("ssl_ecdh_curve", _) => format!(
            "\"{name}\" is not supported yet and is ignored: rustls's default key exchange groups \
             are used"
        ),
        ("ssl_verify_client", Some(mode @ ("optional" | "optional_no_ca"))) => format!(
            "\"ssl_verify_client {mode}\" is not supported yet: client certificates are not \
             requested, and $ssl_client_verify is always \"NONE\""
        ),
        _ => return,
    };
    if !warnings.contains(&w) {
        warnings.push(w);
    }
}

/// A server's ssl_* lines take effect when any server on its address
/// listens with `ssl` (the flag belongs to the socket, as in nginx). Warn
/// only when none does: then they are ignored.
fn warn_ssl_without_ssl_listen(servers: &[Server], mut warnings: Vec<String>) -> Vec<String> {
    let ignored = servers.iter().any(|s| {
        s.ssl_directives
            && !servers
                .iter()
                .any(|other| other.listen.addr == s.listen.addr && other.listen.ssl)
    });
    if ignored {
        warnings.push(
            "server with ssl_* directives but no `listen … ssl;` on its address — TLS settings ignored"
                .into(),
        );
    }
    warnings
}

/// `events { … }`: `worker_connections` is used; the other event-module
/// knobs (`use`, `multi_accept`, `accept_mutex`, …) don't apply to
/// io_uring and are ignored, as the whole block used to be.
fn parse_events_block(lx: &mut Lexer, runtime: &mut RuntimeOpts) -> Result<(), Error> {
    loop {
        let (args, term) = lx.read_directive()?;
        match (args.first().map(String::as_str), term) {
            (None, Terminator::BlockClose) => return Ok(()),
            (None, Terminator::Eof) => return Err(Error::UnclosedBlock),
            (None, _) => continue,
            (Some("worker_connections"), Terminator::Semi) => {
                if runtime.worker_connections.is_some() {
                    return Err(Error::Duplicate("worker_connections"));
                }
                let raw = args.get(1).ok_or(Error::MissingArg("worker_connections"))?;
                let n: usize =
                    raw.parse()
                        .ok()
                        .filter(|&n| n > 0)
                        .ok_or_else(|| Error::BadValue {
                            what: "worker_connections",
                            got: raw.clone(),
                        })?;
                runtime.worker_connections = Some(n);
            }
            (Some(_), Terminator::BlockOpen) => skip_block(lx)?,
            (Some(_), _) => {}
        }
    }
}

#[inline]
pub(crate) fn is_ignored_stmt(name: &str) -> bool {
    IGNORED_STMT.iter().any(|&d| d == name)
}

#[inline]
pub(crate) fn is_ignored_block(name: &str) -> bool {
    IGNORED_BLOCK.iter().any(|&d| d == name)
}

pub(crate) fn skip_block(lx: &mut Lexer) -> Result<(), Error> {
    let mut depth = 0usize;
    loop {
        let (_args, term) = lx.read_directive()?;
        match term {
            Terminator::Semi => {}
            Terminator::BlockOpen => depth += 1,
            Terminator::BlockClose => {
                if depth == 0 {
                    return Ok(());
                }
                depth -= 1;
            }
            Terminator::Eof => return Err(Error::UnclosedBlock),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_index_literals(entries: &[IndexEntry], expected: &[&str]) {
        assert_eq!(entries.len(), expected.len());
        for (entry, expected) in entries.iter().zip(expected) {
            assert_eq!(entry.parts, vec![ValuePart::Literal((*expected).into())]);
        }
    }

    #[test]
    fn milestone_1_config() {
        let src = r#"
            http {
                server {
                    listen 8080;
                    location / { return 200 "hello"; }
                }
            }
        "#;
        let cfg = parse(src).unwrap();
        assert_eq!(cfg.servers.len(), 1);
        let s = &cfg.servers[0];
        assert_eq!(s.listen.addr.port(), 8080);
        assert!(s.server_names.is_empty());
        assert_eq!(s.locations.len(), 1);
        assert_eq!(s.locations[0].mode, MatchMode::Prefix);
        assert_eq!(s.locations[0].pattern, "/");
        match &s.locations[0].handler {
            Handler::Return { status, body } => {
                assert_eq!(*status, 200);
                assert_eq!(body, &vec![ValuePart::Literal("hello".into())]);
            }
            other => panic!("expected Return, got {other:?}"),
        }
    }

    #[test]
    fn root_directive() {
        let src = r#"
            http {
                server {
                    listen 8080;
                    location / { root /var/www; }
                }
            }
        "#;
        let cfg = parse(src).unwrap();
        match &cfg.servers[0].locations[0].handler {
            Handler::Root { path, mapping } => {
                assert_eq!(path, std::path::Path::new("/var/www"));
                assert_eq!(*mapping, PathMapping::Root);
            }
            other => panic!("expected Root, got {other:?}"),
        }
    }

    #[test]
    fn alias_directive_marks_location_as_alias() {
        let src = r#"
            http {
                server {
                    listen 8080;
                    location /img/ { alias /var/data/; }
                }
            }
        "#;
        let cfg = parse(src).unwrap();
        match &cfg.servers[0].locations[0].handler {
            Handler::Root { path, mapping } => {
                assert_eq!(path, std::path::Path::new("/var/data/"));
                assert_eq!(*mapping, PathMapping::Alias);
            }
            other => panic!("expected Root(alias), got {other:?}"),
        }
    }

    #[test]
    fn return_wins_over_root() {
        let src = r#"
            http {
                server {
                    listen 8080;
                    location / { root /var/www; return 200 "x"; }
                }
            }
        "#;
        let cfg = parse(src).unwrap();
        assert!(matches!(
            cfg.servers[0].locations[0].handler,
            Handler::Return { .. }
        ));
    }

    #[test]
    fn multi_server_with_server_names() {
        let src = r#"
            http {
                server {
                    listen 8080;
                    server_name example.com www.example.com;
                    location / { return 200 "a"; }
                }
                server {
                    listen 8080;
                    server_name api.example.com;
                    location / { return 200 "b"; }
                }
            }
        "#;
        let cfg = parse(src).unwrap();
        assert_eq!(cfg.servers.len(), 2);
        assert_eq!(
            cfg.servers[0].server_names,
            vec![
                ServerNameSpec::Exact("example.com".into()),
                ServerNameSpec::Exact("www.example.com".into()),
            ]
        );
        assert_eq!(
            cfg.servers[1].server_names,
            vec![ServerNameSpec::Exact("api.example.com".into())]
        );
    }

    #[test]
    fn multiple_server_name_directives_accumulate() {
        let src = r#"
            http {
                server {
                    listen 8080;
                    server_name a.example.com;
                    server_name b.example.com c.example.com;
                    location / { return 200 ""; }
                }
            }
        "#;
        let cfg = parse(src).unwrap();
        assert_eq!(
            cfg.servers[0].server_names,
            vec![
                ServerNameSpec::Exact("a.example.com".into()),
                ServerNameSpec::Exact("b.example.com".into()),
                ServerNameSpec::Exact("c.example.com".into()),
            ]
        );
    }

    #[test]
    fn location_with_exact_modifier() {
        let src = r#"
            http {
                server {
                    listen 8080;
                    location = / { return 200 "root"; }
                    location /static { return 200 "s"; }
                }
            }
        "#;
        let cfg = parse(src).unwrap();
        let locs = &cfg.servers[0].locations;
        assert_eq!(locs.len(), 2);
        assert_eq!(locs[0].mode, MatchMode::Exact);
        assert_eq!(locs[0].pattern, "/");
        assert_eq!(locs[1].mode, MatchMode::Prefix);
        assert_eq!(locs[1].pattern, "/static");
    }

    #[test]
    fn named_location_parses_as_internal_only_mode() {
        let src = "http { server { listen 80; location @named { return 200 \"\"; } } }";
        let cfg = parse(src).unwrap();
        let loc = &cfg.servers[0].locations[0];
        assert_eq!(loc.mode, MatchMode::Named);
        assert_eq!(loc.pattern, "@named");
    }

    #[test]
    fn parses_regex_and_caret_tilde_modifiers() {
        let src = r#"
            http {
                server {
                    listen 80;
                    location ^~ /assets/  { return 200 "a"; }
                    location ~ \.gif$     { return 200 "g"; }
                    location ~* \.png$    { return 200 "p"; }
                }
            }
        "#;
        let cfg = parse(src).unwrap();
        let locs = &cfg.servers[0].locations;
        assert_eq!(locs[0].mode, MatchMode::Prefix);
        assert!(locs[0].noregex);
        assert_eq!(
            locs[1].mode,
            MatchMode::Regex {
                case_insensitive: false
            }
        );
        assert!(!locs[1].noregex);
        assert_eq!(
            locs[2].mode,
            MatchMode::Regex {
                case_insensitive: true
            }
        );
    }

    #[test]
    fn rejects_invalid_regex_at_parse_time() {
        // `[unclosed` is not a valid Rust-regex pattern. Failing at -t is
        // the whole reason we compile the regex during config parsing.
        let src = r#"http { server { listen 80; location ~ "[unclosed" {
            return 200 "";
        } } }"#;
        let err = parse(src).expect_err("malformed regex must fail parse");
        assert!(matches!(err, Error::InvalidRegex { .. }), "got: {err:?}");
    }

    #[test]
    fn server_name_requires_at_least_one_arg() {
        let src = r#"
            http { server { listen 80; server_name; location / { return 200 ""; } } }
        "#;
        assert!(matches!(parse(src), Err(Error::MissingArg("server_name"))));
    }

    #[test]
    fn location_without_handler_defaults_to_root_html() {
        // nginx's default `root` is `html` under the prefix.
        let src = r#"
            http { server { listen 8080; location / {} } }
        "#;
        let cfg = parse(src).unwrap();
        assert!(matches!(
            &cfg.servers[0].locations[0].handler,
            Handler::Root { path, mapping: PathMapping::Root } if path == Path::new("html")
        ));
    }

    #[test]
    fn rejects_unknown_top_level() {
        let src = "foobar on;";
        assert!(parse(src).is_err());
    }

    #[test]
    fn accepts_top_level_nginx_preamble_and_pid() {
        let src = r#"
            daemon off;
            master_process off;
            worker_processes 1;
            user nobody nogroup;
            worker_rlimit_nofile 65535;
            load_module modules/ngx_fake.so;
            error_log logs/error.log debug;
            pid logs/nginx.pid;

            events {
                worker_connections 4096;
            }

            http {
                server {
                    listen 80;
                    location / { return 200 ""; }
                }
            }
        "#;
        let cfg = parse(src).unwrap();
        assert_eq!(
            cfg.runtime.pid.as_deref(),
            Some(std::path::Path::new("logs/nginx.pid"))
        );
    }

    #[test]
    fn worker_shutdown_timeout_is_a_main_level_time() {
        let with = |directive: &str| {
            parse(&format!(
                "{directive}\nevents {{}}\nhttp {{ server {{ listen 80; }} }}"
            ))
        };
        let timeout = |directive| with(directive).unwrap().runtime.worker_shutdown_timeout_ms;
        assert_eq!(timeout(""), None);
        assert_eq!(timeout("worker_shutdown_timeout 10ms;"), Some(10));
        assert_eq!(timeout("worker_shutdown_timeout 2m;"), Some(120_000));
        assert_eq!(timeout("worker_shutdown_timeout 0;"), Some(0));
        assert!(with("worker_shutdown_timeout;").is_err());
        assert!(with("worker_shutdown_timeout soon;").is_err());
        assert!(with("worker_shutdown_timeout 1s; worker_shutdown_timeout 2s;").is_err());
        // Main context only, as nginx.
        assert!(
            parse("events {} http { worker_shutdown_timeout 1s; server { listen 80; } }").is_err()
        );
    }

    #[test]
    fn comments_and_whitespace() {
        let src = r#"
            # top
            http { # inline
                server { listen 80; location / { return 200 ""; } }
            }
        "#;
        parse(src).unwrap();
    }

    #[test]
    fn escape_in_quoted_string() {
        let src = r#"http { server { listen 80; location / { return 200 "a\"b"; } } }"#;
        let cfg = parse(src).unwrap();
        match &cfg.servers[0].locations[0].handler {
            Handler::Return { body, .. } => {
                assert_eq!(body, &vec![ValuePart::Literal("a\"b".into())]);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn rejects_unterminated_block() {
        let src = "http { server { listen 80; ";
        assert!(parse(src).is_err());
    }

    #[test]
    fn socketaddr_listen() {
        let src = r#"http { server { listen 127.0.0.1:9000; location / { return 200 "x"; } } }"#;
        let cfg = parse(src).unwrap();
        assert_eq!(cfg.servers[0].listen.addr.port(), 9000);
    }

    #[test]
    fn index_at_server_scope() {
        let src = r#"
            http {
                server {
                    listen 80;
                    index default.html main.html;
                    location / { root /var/www; }
                }
            }
        "#;
        let cfg = parse(src).unwrap();
        assert_index_literals(
            cfg.servers[0].index.as_deref().unwrap(),
            &["default.html", "main.html"],
        );
    }

    #[test]
    fn accepts_http_and_server_allowlist_and_listen_flags() {
        let src = r#"
            http {
                access_log off;
                client_body_temp_path temp/client;
                default_type application/octet-stream;
                sendfile on;
                tcp_nopush on;
                tcp_nodelay on;
                keepalive_timeout 75;
                keepalive_requests 1000;
                log_format main "$remote_addr";
                server_tokens off;
                types {
                    text/plain txt;
                }

                server {
                    listen 127.0.0.1:8080 default_server reuseport backlog=4096;
                    access_log off;
                    sendfile on;
                    location / { return 200 ""; }
                }
            }
        "#;
        let cfg = parse(src).unwrap();
        assert_eq!(
            cfg.servers[0].listen.addr,
            "127.0.0.1:8080".parse().unwrap()
        );
        assert_eq!(cfg.servers[0].listen.backlog, Some(4096));
        assert!(cfg.servers[0].listen.default_server);
        assert!(cfg.servers[0].listen.reuseport);
        assert!(!cfg.servers[0].listen.ssl);
    }

    #[test]
    fn listen_ssl_flag_marks_listen_as_tls() {
        let src = r#"
            http {
                server {
                    listen 443 ssl;
                    ssl_certificate cert.pem;
                    ssl_certificate_key key.pem;
                    location / { return 200 ""; }
                }
            }
        "#;
        let cfg = parse(src).unwrap();
        let s = &cfg.servers[0];
        assert!(s.listen.ssl);
        assert_eq!(s.listen.addr.port(), 443);
        assert_eq!(s.ssl.certs, vec![PathBuf::from("cert.pem")]);
        assert_eq!(s.ssl.keys, vec![PathBuf::from("key.pem")]);
        // Default protocols when ssl_protocols omitted.
        assert_eq!(
            s.ssl.protocols,
            TlsVersionSet {
                tlsv1_2: true,
                tlsv1_3: true
            }
        );
        assert!(s.ssl.ciphers.is_none());
        assert!(cfg.warnings.is_empty());
    }

    #[test]
    fn listen_flag_order_is_tolerant() {
        // ssl can come before or after default_server, and key=value flags
        // can be interleaved with bare flags.
        let src = r#"
            http {
                server {
                    listen 0.0.0.0:8443 backlog=2048 ssl http2 default_server fastopen=128;
                    ssl_certificate cert.pem;
                    ssl_certificate_key key.pem;
                    location / { return 200 ""; }
                }
            }
        "#;
        let cfg = parse(src).unwrap();
        let l = &cfg.servers[0].listen;
        assert!(l.ssl);
        assert!(l.http2);
        assert!(l.default_server);
        assert_eq!(l.backlog, Some(2048));
        assert_eq!(l.fastopen, Some(128));
    }

    #[test]
    fn listen_unknown_flag_is_rejected() {
        let src = r#"
            http {
                server {
                    listen 80 not_a_real_flag;
                    location / { return 200 ""; }
                }
            }
        "#;
        let err = parse(src).unwrap_err();
        assert!(matches!(
            err,
            Error::BadValue {
                what: "listen flag",
                ..
            }
        ));
    }

    #[test]
    fn ssl_protocols_accepts_tls12_tls13_and_rejects_insecure() {
        let src = r#"
            http {
                server {
                    listen 443 ssl;
                    ssl_certificate c.pem;
                    ssl_certificate_key k.pem;
                    ssl_protocols TLSv1.2 TLSv1.3;
                    location / { return 200 ""; }
                }
            }
        "#;
        let cfg = parse(src).unwrap();
        assert_eq!(
            cfg.servers[0].ssl.protocols,
            TlsVersionSet {
                tlsv1_2: true,
                tlsv1_3: true
            }
        );

        for bad in ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"] {
            let src = format!(
                r#"http {{
                    server {{
                        listen 443 ssl;
                        ssl_certificate c.pem;
                        ssl_certificate_key k.pem;
                        ssl_protocols {bad};
                        location / {{ return 200 ""; }}
                    }}
                }}"#
            );
            let err = parse(&src).unwrap_err();
            match err {
                Error::BadValue { what, .. } => {
                    assert!(what.starts_with("ssl_protocols"), "got what={what}");
                }
                other => panic!("expected BadValue, got {other:?}"),
            }
        }
    }

    #[test]
    fn ssl_ciphers_stored_verbatim() {
        let src = r#"
            http {
                server {
                    listen 443 ssl;
                    ssl_certificate c.pem;
                    ssl_certificate_key k.pem;
                    ssl_ciphers HIGH:!aNULL:!MD5;
                    location / { return 200 ""; }
                }
            }
        "#;
        let cfg = parse(src).unwrap();
        assert_eq!(
            cfg.servers[0].ssl.ciphers.as_deref(),
            Some("HIGH:!aNULL:!MD5")
        );
    }

    fn unenforced_err(src: &str) -> String {
        match parse(src) {
            Err(e @ Error::Unenforced { .. }) => e.to_string(),
            other => panic!("expected Unenforced, got {other:?}"),
        }
    }

    #[test]
    fn access_restrictions_ruxen_cant_enforce_are_rejected() {
        let err = unenforced_err(
            "http { server { listen 80; location / { limit_except GET { deny all; } } } }",
        );
        assert_eq!(
            err,
            "\"limit_except\" is not supported yet, and ignoring it is unsafe: \
             the method restrictions inside it would not apply"
        );
        // `internal` is enforced now (phase::process).
        let cfg =
            parse("http { server { listen 80; location /a/ { internal; return 200; } } }").unwrap();
        assert!(cfg.servers[0].locations[0].internal);
        let tls = |directive: &str| {
            format!(
                "http {{ {directive} server {{ listen 443 ssl; ssl_certificate c.pem; \
                 ssl_certificate_key k.pem; {directive} }} }}"
            )
        };
        unenforced_err(&tls("ssl_verify_client on;"));
        unenforced_err(&tls("ssl_reject_handshake on;"));
        // disable_symlinks is enforced now (fs_resolve), at every level.
        let symlinks = |value: &str| {
            parse(&format!(
                "http {{ disable_symlinks {value}; server {{ listen 80; disable_symlinks {value}; \
                 location / {{ disable_symlinks {value}; }} }} }}"
            ))
        };
        for value in [
            "off",
            "on",
            "if_not_owner",
            "on from=$document_root",
            "from=/srv on",
        ] {
            let cfg = symlinks(value).unwrap();
            assert!(cfg.disable_symlinks.is_some(), "{value}");
            assert!(
                cfg.servers[0].locations[0].disable_symlinks.is_some(),
                "{value}"
            );
        }
        // nginx's errors: no mode, two modes, `from=` with `off`, a bad
        // word; and ruxen refuses a `from=` with other variables rather
        // than ignore it.
        for value in [
            "from=/srv",
            "on off",
            "off from=/srv",
            "maybe",
            "on from=$host",
            "on from=/a from=/b",
        ] {
            assert!(symlinks(value).is_err(), "{value}");
        }
        // The forms nginx doesn't enforce either still load; `optional*`
        // warns (nginx admits certless clients there too, and ruxen's
        // `$ssl_client_verify` is always NONE, never SUCCESS).
        parse(&tls("ssl_verify_client off;")).unwrap();
        for mode in ["optional", "optional_no_ca"] {
            let cfg = parse(&tls(&format!("ssl_verify_client {mode};"))).unwrap();
            let expected = format!("\"ssl_verify_client {mode}\" is not supported yet");
            assert!(
                cfg.warnings.iter().any(|w| w.starts_with(&expected)),
                "{:?}",
                cfg.warnings
            );
        }
        parse(&tls("ssl_reject_handshake off;")).unwrap();
        parse(&tls("ssl_client_certificate ca.pem;")).unwrap();
    }

    #[test]
    fn ignored_tls_policy_warns_once() {
        let cfg = parse(
            r#"
            http {
                ssl_ciphers HIGH;
                server { listen 443 ssl; ssl_certificate c.pem; ssl_certificate_key k.pem;
                         ssl_ciphers HIGH; ssl_ecdh_curve X25519; }
                server { listen 444 ssl; ssl_certificate c.pem; ssl_certificate_key k.pem;
                         ssl_ecdh_curve X25519; }
            }
        "#,
        )
        .unwrap();
        let tls_warnings: Vec<&String> = cfg
            .warnings
            .iter()
            .filter(|w| w.contains("rustls's default"))
            .collect();
        assert_eq!(tls_warnings.len(), 2, "{:?}", cfg.warnings);
        assert!(tls_warnings[0].starts_with("\"ssl_ciphers\" is not supported yet"));
        assert!(tls_warnings[1].starts_with("\"ssl_ecdh_curve\" is not supported yet"));
    }

    #[test]
    fn client_timeouts_parse_and_inherit() {
        let cfg = parse(
            r#"
            http {
                client_header_timeout 5s;
                send_timeout 7s;
                server { listen 80; client_body_timeout 3s; send_timeout 9s; }
                server { listen 81; }
            }
        "#,
        )
        .unwrap();
        assert_eq!(
            cfg.servers[0].client_timeouts,
            ClientTimeouts {
                header_ms: Some(5_000),
                body_ms: Some(3_000),
                send_ms: Some(9_000),
            }
        );
        assert_eq!(
            cfg.servers[1].client_timeouts,
            ClientTimeouts {
                header_ms: Some(5_000),
                body_ms: None,
                send_ms: Some(7_000),
            }
        );
        assert!(matches!(
            parse("http { send_timeout 1s; send_timeout 2s; }"),
            Err(Error::Duplicate("send_timeout"))
        ));
        assert!(parse("http { client_body_timeout soon; }").is_err());
    }

    #[test]
    fn events_block_reads_worker_connections() {
        let cfg =
            parse("events { worker_connections 2048; use epoll; multi_accept on; }\nhttp { }")
                .unwrap();
        assert_eq!(cfg.runtime.worker_connections, Some(2048));
        assert_eq!(
            parse("events { }\nhttp { }")
                .unwrap()
                .runtime
                .worker_connections,
            None
        );
        assert!(parse("events { worker_connections 0; }\nhttp { }").is_err());
        assert!(parse("events { worker_connections many; }\nhttp { }").is_err());
        assert!(matches!(
            parse("events { worker_connections 1; worker_connections 2; }\nhttp { }"),
            Err(Error::Duplicate("worker_connections"))
        ));
    }

    #[test]
    fn proxy_redirect_parses_like_nginx() {
        let loc = |body: &str| {
            let cfg = parse(&format!(
                "http {{ server {{ listen 80; location / {{ proxy_pass http://127.0.0.1:1/; {body} }} }} }}"
            ))?;
            Ok::<_, Error>(cfg.servers[0].locations[0].proxy_redirect.clone())
        };
        assert_eq!(loc("").unwrap(), None);
        assert_eq!(
            loc("proxy_redirect off;").unwrap(),
            Some(ProxyRedirect::Off)
        );
        match loc(
            "proxy_redirect default; proxy_redirect http://a/ /b/; proxy_redirect ~*^x(.*) /y$1;",
        )
        .unwrap()
        {
            Some(ProxyRedirect::Rules(rules)) => {
                assert_eq!(rules.len(), 3);
                assert_eq!(rules[0], ProxyRedirectRule::Default);
                assert!(matches!(rules[1], ProxyRedirectRule::Prefix { .. }));
                assert!(matches!(
                    rules[2],
                    ProxyRedirectRule::Regex {
                        case_insensitive: true,
                        ..
                    }
                ));
            }
            other => panic!("{other:?}"),
        }
        // `off` can't be combined with other lines in one scope.
        assert!(loc("proxy_redirect default; proxy_redirect off;").is_err());
        assert!(loc("proxy_redirect off; proxy_redirect default;").is_err());
        assert!(loc("proxy_redirect a b c;").is_err());
        assert!(loc("proxy_redirect ~( /x;").is_err());
    }

    #[test]
    fn ssl_session_cache_and_tickets_parse_and_inherit() {
        let cfg = parse(
            "http { ssl_session_cache shared:SSL:1m builtin:1000; ssl_session_tickets off;
                    server { listen 443 ssl; ssl_certificate c; ssl_certificate_key k; }
                    server { listen 444 ssl; ssl_certificate c; ssl_certificate_key k;
                             ssl_session_cache none; } }",
        )
        .unwrap();
        assert_eq!(
            cfg.servers[0].ssl.resumption,
            SessionResumption {
                cache: Some(true),
                tickets: Some(false)
            }
        );
        assert_eq!(cfg.servers[1].ssl.resumption.cache, Some(false));
        assert_eq!(cfg.servers[1].ssl.resumption.tickets, Some(false));
        assert!(parse("http { ssl_session_cache bogus; }").is_err());
        assert!(parse("http { ssl_session_tickets maybe; }").is_err());
    }

    #[test]
    fn user_directive_is_recorded() {
        let cfg = parse("user www-data www-data;\nhttp { }").unwrap();
        assert_eq!(cfg.runtime.user.as_deref(), Some("www-data"));
    }

    #[test]
    fn ssl_certificate_pairs_by_index() {
        let src = r#"
            http {
                server {
                    listen 443 ssl;
                    ssl_certificate rsa.pem;
                    ssl_certificate_key rsa.key;
                    ssl_certificate ecdsa.pem;
                    ssl_certificate_key ecdsa.key;
                    location / { return 200 ""; }
                }
            }
        "#;
        let cfg = parse(src).unwrap();
        assert_eq!(
            cfg.servers[0].ssl.certs,
            vec![PathBuf::from("rsa.pem"), PathBuf::from("ecdsa.pem")]
        );
        assert_eq!(
            cfg.servers[0].ssl.keys,
            vec![PathBuf::from("rsa.key"), PathBuf::from("ecdsa.key")]
        );
    }

    #[test]
    fn ssl_warning_considers_the_whole_address() {
        let warned = |src: &str| {
            parse(src)
                .unwrap()
                .warnings
                .iter()
                .any(|w| w.contains("TLS settings ignored"))
        };
        // Another server on the address listens with ssl: the settings apply.
        assert!(!warned(
            "http { server { listen 127.0.0.1:443 ssl; ssl_certificate a.pem; ssl_certificate_key a.key; }
                    server { listen 127.0.0.1:443; server_name b; ssl_certificate b.pem; ssl_certificate_key b.key; } }"
        ));
        // Nobody on the address does.
        assert!(warned(
            "http { server { listen 127.0.0.1:80; ssl_certificate b.pem; ssl_certificate_key b.key; } }"
        ));
    }

    #[test]
    fn http_scope_ssl_certificate_is_inherited_and_server_scope_overrides() {
        let src = r#"
            http {
                ssl_certificate http.crt;
                ssl_certificate_key http.key;

                server {
                    listen 443 ssl;
                    location / { return 200 ""; }
                }

                server {
                    listen 444 ssl;
                    ssl_certificate server.crt;
                    ssl_certificate_key server.key;
                    location / { return 200 ""; }
                }
            }
        "#;
        let cfg = parse(src).unwrap();
        assert_eq!(cfg.servers[0].ssl.certs, vec![PathBuf::from("http.crt")]);
        assert_eq!(cfg.servers[0].ssl.keys, vec![PathBuf::from("http.key")]);
        assert_eq!(cfg.servers[1].ssl.certs, vec![PathBuf::from("server.crt")]);
        assert_eq!(cfg.servers[1].ssl.keys, vec![PathBuf::from("server.key")]);
    }

    #[test]
    fn server_block_with_multiple_listen_directives_expands_servers() {
        let src = r#"
            http {
                ssl_certificate h.crt;
                ssl_certificate_key h.key;
                server {
                    listen 127.0.0.1:8085 ssl;
                    listen 127.0.0.1:8125;
                    server_name localhost;
                    location / { return 200 ""; }
                }
            }
        "#;
        let cfg = parse(src).unwrap();
        assert_eq!(cfg.servers.len(), 2);
        assert_eq!(
            cfg.servers[0].listen.addr,
            "127.0.0.1:8085".parse().unwrap()
        );
        assert!(cfg.servers[0].listen.ssl);
        assert_eq!(
            cfg.servers[1].listen.addr,
            "127.0.0.1:8125".parse().unwrap()
        );
        assert!(!cfg.servers[1].listen.ssl);
    }

    #[test]
    fn cert_key_count_mismatch_is_rejected() {
        let src = r#"
            http {
                server {
                    listen 443 ssl;
                    ssl_certificate a.pem;
                    ssl_certificate b.pem;
                    ssl_certificate_key a.key;
                    location / { return 200 ""; }
                }
            }
        "#;
        let err = parse(src).unwrap_err();
        match err {
            Error::BadValue { what, .. } => {
                assert!(what.contains("count mismatch"), "got what={what}");
            }
            other => panic!("expected BadValue, got {other:?}"),
        }
    }

    #[test]
    fn ssl_certificate_without_listen_ssl_is_warning_not_error() {
        let src = r#"
            http {
                server {
                    listen 80;
                    ssl_certificate cert.pem;
                    ssl_certificate_key key.pem;
                    location / { return 200 ""; }
                }
            }
        "#;
        let cfg = parse(src).unwrap();
        assert!(!cfg.servers[0].listen.ssl);
        assert_eq!(cfg.servers[0].ssl.certs.len(), 1);
        assert!(
            cfg.warnings.iter().any(|w| w.contains("listen … ssl")),
            "expected ssl-without-listen warning, got {:?}",
            cfg.warnings
        );
    }

    #[test]
    fn ssl_prefer_server_ciphers_off_emits_warning() {
        let src = r#"
            http {
                server {
                    listen 443 ssl;
                    ssl_certificate c.pem;
                    ssl_certificate_key k.pem;
                    ssl_prefer_server_ciphers off;
                    location / { return 200 ""; }
                }
            }
        "#;
        let cfg = parse(src).unwrap();
        assert_eq!(cfg.servers[0].ssl.prefer_server_ciphers, Some(false));
        assert!(
            cfg.warnings
                .iter()
                .any(|w| w.contains("prefer_server_ciphers")),
            "expected prefer-server-ciphers warning, got {:?}",
            cfg.warnings
        );
    }

    #[test]
    fn ssl_session_directives_are_silently_accepted() {
        let src = r#"
            http {
                server {
                    listen 443 ssl;
                    ssl_certificate c.pem;
                    ssl_certificate_key k.pem;
                    ssl_session_cache shared:SSL:1m;
                    ssl_session_timeout 5m;
                    ssl_session_tickets off;
                    ssl_buffer_size 4k;
                    ssl_dhparam /etc/ssl/dh.pem;
                    ssl_ecdh_curve secp384r1;
                    ssl_stapling on;
                    ssl_stapling_verify on;
                    ssl_verify_client off;
                    ssl_client_certificate /etc/ssl/ca.pem;
                    ssl_trusted_certificate /etc/ssl/trusted.pem;
                    ssl_crl /etc/ssl/ca.crl;
                    ssl_password_file /etc/ssl/keys.pwd;
                    ssl_early_data off;
                    location / { return 200 ""; }
                }
            }
        "#;
        let cfg = parse(src).unwrap();
        // Directives parsed without error and didn't disturb the populated SSL state.
        assert_eq!(cfg.servers[0].ssl.certs.len(), 1);
    }

    #[test]
    fn proxy_set_body_parses_at_server_and_location_only() {
        let cfg = parse(
            "http { server { listen 80; proxy_set_body a; \
             location / { proxy_set_body \"b-$arg_x\"; proxy_pass http://127.0.0.1:1; } } }",
        )
        .unwrap();
        assert_eq!(
            cfg.servers[0].proxy_set_body,
            Some(vec![ValuePart::Literal("a".into())])
        );
        assert_eq!(
            cfg.servers[0].locations[0].proxy_set_body,
            Some(vec![
                ValuePart::Literal("b-".into()),
                ValuePart::Var(Variable::Arg("x".into())),
            ])
        );
        // Not at http scope (like proxy_set_header), and once per block.
        assert!(parse("http { proxy_set_body a; server { listen 80; } }").is_err());
        assert!(
            parse(
                "http { server { listen 80; location / { proxy_set_body a; proxy_set_body b; } } }"
            )
            .is_err()
        );
    }

    #[test]
    fn listen_port_ranges_expand() {
        let cfg = parse(
            "http { server { listen 127.0.0.1:8000-8002 default_server; \
             listen [::1]:9000-9001; listen 7000-7000; location / { return 204; } } }",
        )
        .unwrap();
        let ports: Vec<String> = cfg
            .servers
            .iter()
            .map(|s| s.listen.addr.to_string())
            .collect();
        assert_eq!(
            ports,
            [
                "127.0.0.1:8000",
                "127.0.0.1:8001",
                "127.0.0.1:8002",
                "[::1]:9000",
                "[::1]:9001",
                "0.0.0.0:7000"
            ]
        );
        assert!(cfg.servers[..3].iter().all(|s| s.listen.default_server));
        for bad in ["127.0.0.1:8002-8000", "127.0.0.1:0-1", "127.0.0.1:1-x"] {
            assert!(
                parse(&format!(
                    "http {{ server {{ listen {bad}; location / {{ return 204; }} }} }}"
                ))
                .is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn log_format_and_access_log_parse_at_http_scope() {
        let src = r#"
            http {
                log_format test1 $sent_http_connection;
                access_log /tmp/test.log test1 if=$arg_l;
                server { listen 80; location / { return 200 ""; } }
            }
        "#;
        let cfg = parse(src).unwrap();
        assert_eq!(cfg.log_formats.len(), 1);
        assert_eq!(cfg.log_formats[0].name, "test1");
        assert_eq!(cfg.access_logs.len(), 1);
        assert_eq!(
            cfg.access_logs[0].path,
            std::path::Path::new("/tmp/test.log")
        );
        assert_eq!(cfg.access_logs[0].format.as_deref(), Some("test1"));
        assert!(cfg.access_logs[0].condition.is_some());
    }

    #[test]
    fn log_format_escape_modes() {
        let cfg = parse(
            "http { log_format a escape=json $uri; log_format b $uri; \
             server { listen 80; } }",
        )
        .unwrap();
        assert_eq!(cfg.log_formats[0].escape, LogEscape::Json);
        assert_eq!(
            cfg.log_formats[0].value,
            vec![ValuePart::Var(Variable::Uri)]
        );
        assert_eq!(cfg.log_formats[1].escape, LogEscape::Default);
        assert!(parse("http { log_format a escape=xml $uri; server { listen 80; } }").is_err());
    }

    #[test]
    fn access_log_off_clears_http_logs() {
        let src = r#"
            http {
                log_format test1 $sent_http_connection;
                access_log /tmp/one.log test1;
                access_log off;
                server { listen 80; location / { return 200 ""; } }
            }
        "#;
        let cfg = parse(src).unwrap();
        assert!(cfg.access_logs.is_empty());
    }

    #[test]
    fn access_log_rejects_format_after_if_parameter() {
        let src = r#"
            http {
                log_format test1 $sent_http_connection;
                access_log /tmp/test.log if=$arg_l test1;
                server { listen 80; location / { return 200 ""; } }
            }
        "#;
        assert!(matches!(
            parse(src),
            Err(Error::BadValue {
                what: "access_log",
                ..
            })
        ));
    }

    #[test]
    fn auth_basic_and_user_file_parse_at_http_server_and_location_scope() {
        let src = r#"
            http {
                auth_basic "http realm";
                auth_basic_user_file /tmp/http.htpasswd;
                server {
                    listen 80;
                    auth_basic "server realm";
                    auth_basic_user_file /tmp/server.htpasswd;
                    location / {
                        auth_basic "loc realm";
                        auth_basic_user_file /tmp/location.htpasswd;
                        return 200 "ok";
                    }
                }
            }
        "#;
        let cfg = parse(src).unwrap();
        match cfg.auth_basic.as_ref().expect("http auth_basic") {
            AuthBasic::Realm(bytes) => {
                assert_eq!(bytes.as_slice(), b"http realm");
            }
            AuthBasic::Off => panic!("expected realm"),
        }
        assert_eq!(
            cfg.auth_basic_user_file.as_deref(),
            Some(std::path::Path::new("/tmp/http.htpasswd"))
        );
        let server = &cfg.servers[0];
        match server.auth_basic.as_ref().expect("server auth_basic") {
            AuthBasic::Realm(bytes) => {
                assert_eq!(bytes.as_slice(), b"server realm");
            }
            AuthBasic::Off => panic!("expected realm"),
        }
        assert_eq!(
            server.auth_basic_user_file.as_deref(),
            Some(std::path::Path::new("/tmp/server.htpasswd"))
        );
        let loc = &server.locations[0];
        match loc.auth_basic.as_ref().expect("location auth_basic") {
            AuthBasic::Realm(bytes) => {
                assert_eq!(bytes.as_slice(), b"loc realm");
            }
            AuthBasic::Off => panic!("expected realm"),
        }
        assert_eq!(
            loc.auth_basic_user_file.as_deref(),
            Some(std::path::Path::new("/tmp/location.htpasswd"))
        );
    }

    #[test]
    fn nested_location_inherits_parent_auth_basic_and_user_file() {
        let src = r#"
            http {
                server {
                    listen 80;
                    location /parent {
                        auth_basic "parent realm";
                        auth_basic_user_file /tmp/parent.htpasswd;
                        return 200 "parent";
                        location /parent/child {
                            return 200 "ok";
                        }
                    }
                }
            }
        "#;
        let cfg = parse(src).unwrap();
        let child = cfg.servers[0]
            .locations
            .iter()
            .find(|loc| loc.pattern == "/parent/child")
            .expect("child location");
        match child.auth_basic.as_ref().expect("inherited auth_basic") {
            AuthBasic::Realm(bytes) => {
                assert_eq!(bytes.as_slice(), b"parent realm");
            }
            AuthBasic::Off => panic!("expected realm"),
        }
        assert_eq!(
            child.auth_basic_user_file.as_deref(),
            Some(std::path::Path::new("/tmp/parent.htpasswd"))
        );
    }

    #[test]
    fn auth_delay_parses_and_nested_location_inherits() {
        let src = r#"
            http {
                auth_delay 5s;
                server {
                    listen 80;
                    auth_delay 2s;
                    location /parent {
                        auth_delay 1s;
                        return 200 "parent";
                        location /parent/child {
                            return 200 "ok";
                        }
                    }
                }
            }
        "#;
        let cfg = parse(src).unwrap();
        assert_eq!(cfg.auth_delay_ms, Some(5_000));
        let server = &cfg.servers[0];
        assert_eq!(server.auth_delay_ms, Some(2_000));
        let parent = server
            .locations
            .iter()
            .find(|loc| loc.pattern == "/parent")
            .expect("parent location");
        assert_eq!(parent.auth_delay_ms, Some(1_000));
        let child = server
            .locations
            .iter()
            .find(|loc| loc.pattern == "/parent/child")
            .expect("child location");
        assert_eq!(child.auth_delay_ms, Some(1_000));
    }

    #[test]
    fn auth_basic_rejects_variable_in_realm() {
        let src = r#"
            http {
                server {
                    listen 80;
                    auth_basic "admin-$host";
                    auth_basic_user_file /tmp/x;
                    location / { return 200 "ok"; }
                }
            }
        "#;
        assert!(matches!(
            parse(src),
            Err(Error::BadValue { what, .. }) if what.starts_with("auth_basic")
        ));
    }

    #[test]
    fn error_log_and_log_not_found_parse_at_server_and_location_scope() {
        let src = r#"
            http {
                server {
                    listen 80;
                    error_log /tmp/server-error.log;
                    log_not_found off;
                    location / {
                        error_log /tmp/location-error.log info;
                        log_not_found on;
                        return 200 "ok";
                    }
                }
            }
        "#;
        let cfg = parse(src).unwrap();
        let server = &cfg.servers[0];
        let server_logs = server.error_logs.as_ref().expect("server error logs");
        assert_eq!(server_logs.len(), 1);
        assert_eq!(
            server_logs[0].target,
            ErrorLogTarget::File(std::path::Path::new("/tmp/server-error.log").into())
        );
        assert_eq!(server_logs[0].level, ErrorLogLevel::Error);
        assert_eq!(server.log_not_found, Some(false));
        let loc = server
            .locations
            .iter()
            .find(|l| l.pattern == "/")
            .expect("location /");
        let loc_logs = loc.error_logs.as_ref().expect("location error logs");
        assert_eq!(loc_logs.len(), 1);
        assert_eq!(
            loc_logs[0].target,
            ErrorLogTarget::File(std::path::Path::new("/tmp/location-error.log").into())
        );
        assert_eq!(loc_logs[0].level, ErrorLogLevel::Info);
        assert_eq!(loc.log_not_found, Some(true));
    }

    #[test]
    fn error_log_multiple_sinks_accumulate() {
        let src = r#"
            http {
                server {
                    listen 80;
                    error_log /tmp/one.log warn;
                    error_log /tmp/two.log crit;
                    location / { return 200 "ok"; }
                }
            }
        "#;
        let cfg = parse(src).unwrap();
        let logs = cfg.servers[0].error_logs.as_ref().expect("error logs");
        assert_eq!(logs.len(), 2);
        assert_eq!(
            logs[0].target,
            ErrorLogTarget::File(std::path::Path::new("/tmp/one.log").into())
        );
        assert_eq!(logs[0].level, ErrorLogLevel::Warn);
        assert_eq!(
            logs[1].target,
            ErrorLogTarget::File(std::path::Path::new("/tmp/two.log").into())
        );
        assert_eq!(logs[1].level, ErrorLogLevel::Crit);
    }

    #[test]
    fn error_log_syslog_parses_unix_server_and_tag() {
        let src = r#"
            http {
                server {
                    listen 80;
                    error_log syslog:server=unix:/tmp/ruxen.sock,facility=local7,severity=warn,tag=edge,nohostname info;
                    location / { return 200 "ok"; }
                }
            }
        "#;
        let cfg = parse(src).unwrap();
        let logs = cfg.servers[0].error_logs.as_ref().expect("error logs");
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].level, ErrorLogLevel::Info);
        assert_eq!(
            logs[0].target,
            ErrorLogTarget::Syslog(SyslogPeer {
                server: ErrorLogSyslogServer::Unix(std::path::Path::new("/tmp/ruxen.sock").into()),
                facility: 23,
                severity: 4,
                tag: Some("edge".into()),
                nohostname: true,
            })
        );
    }

    #[test]
    fn error_log_syslog_rejects_missing_server() {
        let src = r#"
            http {
                server {
                    listen 80;
                    error_log syslog:tag=edge warn;
                    location / { return 200 "ok"; }
                }
            }
        "#;
        assert!(matches!(
            parse(src),
            Err(Error::BadValue { what: "syslog", .. })
        ));
    }

    #[test]
    fn log_not_found_rejects_bad_values() {
        let src = r#"
            http {
                server {
                    listen 80;
                    log_not_found maybe;
                    location / { return 200 "ok"; }
                }
            }
        "#;
        assert!(matches!(
            parse(src),
            Err(Error::BadValue {
                what: "log_not_found",
                ..
            })
        ));
    }

    #[test]
    fn error_log_rejects_too_many_args() {
        let src = r#"
            http {
                server {
                    listen 80;
                    error_log /tmp/e.log info extra;
                    location / { return 200 "ok"; }
                }
            }
        "#;
        assert!(matches!(
            parse(src),
            Err(Error::BadValue {
                what: "error_log",
                ..
            })
        ));
    }

    #[test]
    fn error_log_rejects_unknown_level() {
        let src = r#"
            http {
                server {
                    listen 80;
                    error_log /tmp/e.log noisy;
                    location / { return 200 "ok"; }
                }
            }
        "#;
        assert!(matches!(
            parse(src),
            Err(Error::BadValue {
                what: "error_log level",
                ..
            })
        ));
    }

    #[test]
    fn keepalive_timeout_parses_server_and_location_scope() {
        let src = r#"
            http {
                server {
                    listen 80;
                    keepalive_timeout 1 9;
                    location / {
                        return 200 "ok";
                    }
                    location = /zero {
                        keepalive_timeout 0;
                        return 200 "z";
                    }
                }
            }
        "#;
        let cfg = parse(src).unwrap();
        let server = &cfg.servers[0];
        let server_ka = server.keepalive_timeout.expect("server keepalive");
        assert_eq!(server_ka.timeout_ms, 1_000);
        assert_eq!(server_ka.header_timeout_secs, Some(9));

        let zero = server
            .locations
            .iter()
            .find(|l| l.pattern == "/zero")
            .expect("location /zero");
        let zero_ka = zero.keepalive_timeout.expect("location keepalive");
        assert_eq!(zero_ka.timeout_ms, 0);
        assert_eq!(zero_ka.header_timeout_secs, None);
    }

    #[test]
    fn keepalive_timeout_rejects_bad_value() {
        let src = r#"
            http {
                server {
                    listen 80;
                    keepalive_timeout nope;
                    location / { return 200 "ok"; }
                }
            }
        "#;
        assert!(matches!(parse(src), Err(Error::BadValue { .. })));
    }

    #[test]
    fn keepalive_requests_parses_server_and_location_scope() {
        let src = r#"
            http {
                server {
                    listen 80;
                    keepalive_requests 2;
                    location / {
                        return 200 "ok";
                    }
                    location = /override {
                        keepalive_requests 4;
                        return 200 "o";
                    }
                }
            }
        "#;
        let cfg = parse(src).unwrap();
        let server = &cfg.servers[0];
        assert_eq!(server.keepalive_requests, Some(2));

        let override_loc = server
            .locations
            .iter()
            .find(|l| l.pattern == "/override")
            .expect("location /override");
        assert_eq!(override_loc.keepalive_requests, Some(4));

        let inherited = server
            .locations
            .iter()
            .find(|l| l.pattern == "/")
            .expect("location /");
        assert_eq!(inherited.keepalive_requests, None);
    }

    #[test]
    fn keepalive_requests_rejects_bad_value() {
        let src = r#"
            http {
                server {
                    listen 80;
                    keepalive_requests nope;
                    location / { return 200 "ok"; }
                }
            }
        "#;
        assert!(matches!(parse(src), Err(Error::BadValue { .. })));
    }

    #[test]
    fn keepalive_time_parses_server_and_location_scope() {
        let src = r#"
            http {
                server {
                    listen 80;
                    keepalive_time 2s;
                    location / { return 200 "ok"; }
                    location = /loc {
                        keepalive_time 100ms;
                        return 200 "l";
                    }
                }
            }
        "#;
        let cfg = parse(src).unwrap();
        let server = &cfg.servers[0];
        assert_eq!(server.keepalive_time_ms, Some(2_000));
        let loc = server
            .locations
            .iter()
            .find(|l| l.pattern == "/loc")
            .expect("location /loc");
        assert_eq!(loc.keepalive_time_ms, Some(100));
    }

    #[test]
    fn keepalive_disable_parses_and_rejects_bad_values() {
        let src = r#"
            http {
                server {
                    listen 80;
                    keepalive_disable msie6 safari;
                    location / {
                        keepalive_disable none;
                        return 200 "ok";
                    }
                }
            }
        "#;
        let cfg = parse(src).unwrap();
        let server = &cfg.servers[0];
        assert_eq!(
            server.keepalive_disable,
            Some(KeepaliveDisable {
                msie6: true,
                safari: true
            })
        );
        let loc = server
            .locations
            .iter()
            .find(|l| l.pattern == "/")
            .expect("location /");
        assert_eq!(
            loc.keepalive_disable,
            Some(KeepaliveDisable {
                msie6: false,
                safari: false
            })
        );

        let bad = r#"
            http {
                server {
                    listen 80;
                    keepalive_disable chrome;
                    location / { return 200 "ok"; }
                }
            }
        "#;
        assert!(matches!(parse(bad), Err(Error::BadValue { .. })));
    }

    #[test]
    fn index_at_location_scope_overrides() {
        let src = r#"
            http {
                server {
                    listen 80;
                    index s.html;
                    location / { root /var/www; index loc.html alt.html; }
                }
            }
        "#;
        let cfg = parse(src).unwrap();
        let loc = &cfg.servers[0].locations[0];
        assert_index_literals(loc.index.as_deref().unwrap(), &["loc.html", "alt.html"]);
    }

    #[test]
    fn root_inherits_from_http_and_server_scope() {
        let src = r#"
            http {
                root /http-root;

                server {
                    listen 80;
                    location /http { index index.html; }
                }

                server {
                    listen 80;
                    root /server-root;
                    location /server { index index.html; }
                }
            }
        "#;
        let cfg = parse(src).unwrap();
        match &cfg.servers[0].locations[0].handler {
            Handler::Root { path, mapping } => {
                assert_eq!(path, std::path::Path::new("/http-root"));
                assert_eq!(*mapping, PathMapping::Root);
            }
            other => panic!("expected Root, got {other:?}"),
        }
        match &cfg.servers[1].locations[0].handler {
            Handler::Root { path, mapping } => {
                assert_eq!(path, std::path::Path::new("/server-root"));
                assert_eq!(*mapping, PathMapping::Root);
            }
            other => panic!("expected Root, got {other:?}"),
        }
        assert_eq!(
            cfg.servers[1].root.as_deref(),
            Some(std::path::Path::new("/server-root"))
        );
    }

    #[test]
    fn alias_is_allowed_in_regex_locations() {
        let src = r#"
            http {
                server {
                    listen 80;
                    location ~ \.gif$ { alias /var/www; }
                }
            }
        "#;
        let cfg = parse(src).unwrap();
        assert_eq!(
            cfg.servers[0].locations[0].mode,
            MatchMode::Regex {
                case_insensitive: false
            }
        );
        match &cfg.servers[0].locations[0].handler {
            Handler::Root { path, mapping } => {
                assert_eq!(path, std::path::Path::new("/var/www"));
                assert_eq!(*mapping, PathMapping::Alias);
            }
            other => panic!("expected Root(alias), got {other:?}"),
        }
    }

    #[test]
    fn root_and_alias_are_mutually_exclusive() {
        let src = r#"
            http {
                server {
                    listen 80;
                    location / {
                        root /var/www;
                        alias /srv/files;
                    }
                }
            }
        "#;
        assert!(matches!(parse(src), Err(Error::Duplicate("root/alias"))));
    }

    #[test]
    fn try_files_parses_uri_and_uri_slash_and_status_fallback() {
        let src = r#"
            http {
                server {
                    listen 80;
                    location / {
                        root /var/www;
                        try_files $uri $uri/ =404;
                    }
                }
            }
        "#;
        let cfg = parse(src).unwrap();
        let tf = cfg.servers[0].locations[0].try_files.as_ref().unwrap();
        assert!(matches!(tf.probes[0], TryFilesProbe::Uri));
        assert!(matches!(tf.probes[1], TryFilesProbe::UriSlash));
        assert!(matches!(tf.fallback, TryFilesFallback::Status(404)));
    }

    #[test]
    fn try_files_literal_and_uri_fallback() {
        let src = r#"
            http {
                server {
                    listen 80;
                    location / {
                        root /var/www;
                        try_files $uri /index.html;
                    }
                }
            }
        "#;
        let cfg = parse(src).unwrap();
        let tf = cfg.servers[0].locations[0].try_files.as_ref().unwrap();
        assert!(matches!(tf.probes[0], TryFilesProbe::Uri));
        match &tf.fallback {
            TryFilesFallback::Uri(s) => assert_eq!(s, "/index.html"),
            _ => panic!("expected URI fallback"),
        }
    }

    #[test]
    fn try_files_accepts_named_location_fallback() {
        let src = r#"
            http { server { listen 80; location / {
                root /var/www;
                try_files $uri @backend;
            } } }
        "#;
        let cfg = parse(src).unwrap();
        let tf = cfg.servers[0].locations[0].try_files.as_ref().unwrap();
        match &tf.fallback {
            TryFilesFallback::Named(name) => assert_eq!(name, "@backend"),
            other => panic!("expected named fallback, got {other:?}"),
        }
    }

    #[test]
    fn try_files_rejects_unknown_variables() {
        let src = r#"
            http { server { listen 80; location / {
                root /var/www;
                try_files $uri $request_filename /index.html;
            } } }
        "#;
        assert!(parse(src).is_err());
    }

    #[test]
    fn accepts_wide_ignore_directives_at_every_scope() {
        // Mirror of what upstream nginx-tests preambles throw at us: the
        // tuning/logging/IO directives we explicitly don't implement must
        // parse without error when they appear in top-level, http, server,
        // or location scope.
        let src = r#"
            worker_shutdown_timeout 10ms;
            timer_resolution 100ms;

            events { worker_connections 4096; }

            http {
                server_names_hash_bucket_size 64;
                connection_pool_size 256;
                client_header_buffer_size 128;
                large_client_header_buffers 4 8k;
                client_max_body_size 1m;
                merge_slashes off;
                ignore_invalid_headers off;
                underscores_in_headers on;
                absolute_redirect off;
                resolver 8.8.8.8;
                aio threads;
                open_file_cache max=1000 inactive=20s;
                gzip on;
                gzip_types text/plain;
                charset utf-8;
                types_hash_bucket_size 64;
                map_hash_bucket_size 128;

                server {
                    listen 80;
                    server_names_hash_bucket_size 64;
                    keepalive_timeout 30s;
                    error_page 404 /404.html;
                    expires 1h;

                    location / {
                        expires epoch;
                        error_page 500 /fail.html;
                        return 200 "ok";
                    }
                }
            }
        "#;
        parse(src).unwrap();
    }

    #[test]
    fn add_header_at_server_and_location() {
        let src = r#"
            http {
                server {
                    listen 80;
                    add_header X-Global 1;
                    add_header X-Whoami $server_name;
                    location / {
                        return 200 "ok";
                    }
                    location /l {
                        add_header X-Local "$uri is $status";
                        return 204;
                    }
                }
            }
        "#;
        let cfg = parse(src).unwrap();
        let s = &cfg.servers[0];
        let server_hdrs = s.add_headers.as_ref().unwrap();
        assert_eq!(server_hdrs.len(), 2);
        assert_eq!(server_hdrs[0].name, "X-Global");
        assert_eq!(server_hdrs[0].value, vec![ValuePart::Literal("1".into())]);
        assert_eq!(
            server_hdrs[1].value,
            vec![ValuePart::Var(Variable::ServerName)]
        );
        // Location without add_header inherits: None at config level
        // (prepare-time merge is where the server list gets promoted down).
        assert!(s.locations[0].add_headers.is_none());
        let local = s.locations[1].add_headers.as_ref().unwrap();
        assert_eq!(local[0].name, "X-Local");
        assert_eq!(
            local[0].value,
            vec![
                ValuePart::Var(Variable::Uri),
                ValuePart::Literal(" is ".into()),
                ValuePart::Var(Variable::Status),
            ]
        );
    }

    #[test]
    fn add_header_always_modifier() {
        let src = r#"
            http { server { listen 80; location / {
                add_header X-Err "oops" always;
                return 500 "bad";
            } } }
        "#;
        let cfg = parse(src).unwrap();
        let hdr = &cfg.servers[0].locations[0].add_headers.as_ref().unwrap()[0];
        assert!(hdr.always);
    }

    #[test]
    fn unknown_variables_fail_like_nginx() {
        // A name nothing defines is an error, as in nginx.
        let err =
            parse("http { server { listen 80; location / { add_header X $nonexistent_var; return 204; } } }")
                .unwrap_err();
        assert_eq!(err.to_string(), "unknown \"nonexistent_var\" variable");
        // Defined later in the file by `set`, `map` or a named capture: fine.
        let cfg = parse(
            "http { server { listen 80; server_name ~^(?<sub>.+)\\.x$; \
               location / { add_header X \"$a $m $sub $cap\"; set $a 1; return 204; } \
               location ~ ^/(?P<cap>.+)$ { return 204; } } \
             map $uri $m { default 1; } }",
        )
        .unwrap();
        assert!(cfg.warnings.is_empty(), "{:?}", cfg.warnings);
        // A variable nginx has and ruxen doesn't: loads, with a warning.
        let cfg = parse(
            "http { server { listen 80; location / { add_header X $tcpinfo_rtt$ssl_early_data; return 204; } } }",
        )
        .unwrap();
        assert_eq!(
            cfg.warnings,
            [
                "variable \"$tcpinfo_rtt\" is not supported yet and is always empty",
                "variable \"$ssl_early_data\" is not supported yet and is always empty",
            ]
        );
    }

    #[test]
    fn add_header_accepts_remote_addr_and_port_variables() {
        let src = r#"
            http { server { listen 80; location / {
                add_header X-Client "$remote_addr:$remote_port";
                return 200 "";
            } } }
        "#;
        let cfg = parse(src).unwrap();
        let hdr = &cfg.servers[0].locations[0].add_headers.as_ref().unwrap()[0];
        assert_eq!(
            hdr.value,
            vec![
                ValuePart::Var(Variable::RemoteAddr),
                ValuePart::Literal(":".into()),
                ValuePart::Var(Variable::RemotePort),
            ]
        );
    }

    #[test]
    fn add_header_accepts_request_time_variable() {
        let src = r#"
            http { server { listen 80; location / {
                add_header X-Req-Time $request_time;
                return 200 "";
            } } }
        "#;
        let cfg = parse(src).unwrap();
        let hdr = &cfg.servers[0].locations[0].add_headers.as_ref().unwrap()[0];
        assert_eq!(hdr.value, vec![ValuePart::Var(Variable::RequestTime)]);
    }

    #[test]
    fn add_header_accepts_sent_http_variable() {
        let src = r#"
            http { server { listen 80; location / {
                add_header X-Len $sent_http_content_length;
                return 200 "";
            } } }
        "#;
        let cfg = parse(src).unwrap();
        let hdr = &cfg.servers[0].locations[0].add_headers.as_ref().unwrap()[0];
        assert_eq!(
            hdr.value,
            vec![ValuePart::Var(Variable::SentHttp("content-length".into()))]
        );
    }

    #[test]
    fn add_header_rejects_bad_modifier() {
        let src = r#"
            http { server { listen 80; location / {
                add_header X-Test y maybe;
                return 200 "";
            } } }
        "#;
        assert!(matches!(parse(src), Err(Error::BadValue { .. })));
    }

    #[test]
    fn return_body_parses_variables() {
        // Critical path for nginx-tests that do `return 200 $uri;`.
        let src = r#"
            http { server { listen 80; location / {
                return 200 "path=$uri host=$host";
            } } }
        "#;
        let cfg = parse(src).unwrap();
        match &cfg.servers[0].locations[0].handler {
            Handler::Return { body, .. } => {
                assert_eq!(body.len(), 4);
                assert_eq!(body[0], ValuePart::Literal("path=".into()));
                assert_eq!(body[1], ValuePart::Var(Variable::Uri));
                assert_eq!(body[2], ValuePart::Literal(" host=".into()));
                assert_eq!(body[3], ValuePart::Var(Variable::Host));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn return_body_empty_is_legal() {
        // `return 200;` — no body argument — parses to an empty parts list.
        let src = r#"http { server { listen 80; location / { return 200; } } }"#;
        let cfg = parse(src).unwrap();
        match &cfg.servers[0].locations[0].handler {
            Handler::Return { status, body } => {
                assert_eq!(*status, 200);
                assert!(body.is_empty());
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn return_body_rejects_sent_http_variable() {
        let src = r#"
            http { server { listen 80; location / {
                return 200 "$sent_http_content_length";
            } } }
        "#;
        assert!(matches!(
            parse(src),
            Err(Error::BadValue {
                what: "return body ($sent_http_* unavailable)",
                ..
            })
        ));
    }

    #[test]
    fn literal_dollar_without_var_name_is_kept() {
        let src = r#"http { server { listen 80; location / { return 200 "$ or $"; } } }"#;
        let cfg = parse(src).unwrap();
        match &cfg.servers[0].locations[0].handler {
            Handler::Return { body, .. } => {
                assert_eq!(body, &vec![ValuePart::Literal("$ or $".into())]);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn braced_variable_syntax_is_accepted() {
        let src = r#"
            http { server { listen 80; location / {
                index ${server_name}.html;
                return 200 "${uri}";
            } } }
        "#;
        let cfg = parse(src).unwrap();
        let index = cfg.servers[0].locations[0].index.as_ref().unwrap();
        assert_eq!(
            index[0].parts,
            vec![
                ValuePart::Var(Variable::ServerName),
                ValuePart::Literal(".html".into()),
            ]
        );
        match &cfg.servers[0].locations[0].handler {
            Handler::Return { body, .. } => {
                assert_eq!(body, &vec![ValuePart::Var(Variable::Uri)]);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn index_rejects_sent_http_variable() {
        let src = r#"
            http { server { listen 80; location / {
                index $sent_http_content_length;
                return 200 "";
            } } }
        "#;
        assert!(matches!(
            parse(src),
            Err(Error::BadValue {
                what: "index entry ($sent_http_* unavailable)",
                ..
            })
        ));
    }

    #[test]
    fn query_variables_are_accepted() {
        let src = r#"
            http { server { listen 80; location / {
                add_header X-Args "$args|$query_string|$is_args|$arg_name|${arg_}";
                return 200 "$request_uri";
            } } }
        "#;
        let cfg = parse(src).unwrap();
        let hdr = &cfg.servers[0].locations[0].add_headers.as_ref().unwrap()[0];
        assert_eq!(
            hdr.value,
            vec![
                ValuePart::Var(Variable::Args),
                ValuePart::Literal("|".into()),
                ValuePart::Var(Variable::Args),
                ValuePart::Literal("|".into()),
                ValuePart::Var(Variable::IsArgs),
                ValuePart::Literal("|".into()),
                ValuePart::Var(Variable::Arg("name".into())),
                ValuePart::Literal("|".into()),
                ValuePart::Var(Variable::Arg("".into())),
            ]
        );
        match &cfg.servers[0].locations[0].handler {
            Handler::Return { body, .. } => {
                assert_eq!(body, &vec![ValuePart::Var(Variable::RequestUri)]);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn error_page_parses_status_groups_and_overrides() {
        let src = r#"
            http {
                server {
                    listen 80;
                    error_page 404 500 /50x.html;
                    location / {
                        error_page 405 =200 /ok?$arg_a;
                        return 200 "ok";
                    }
                }
            }
        "#;
        let cfg = parse(src).unwrap();

        assert_eq!(
            cfg.servers[0].error_pages,
            Some(vec![
                ErrorPage {
                    status: 404,
                    action: ErrorPageAction::PreserveOriginal,
                    target: vec![ValuePart::Literal("/50x.html".into())],
                },
                ErrorPage {
                    status: 500,
                    action: ErrorPageAction::PreserveOriginal,
                    target: vec![ValuePart::Literal("/50x.html".into())],
                },
            ])
        );
        assert_eq!(
            cfg.servers[0].locations[0].error_pages,
            Some(vec![ErrorPage {
                status: 405,
                action: ErrorPageAction::Override(200),
                target: vec![
                    ValuePart::Literal("/ok?".into()),
                    ValuePart::Var(Variable::Arg("a".into())),
                ],
            }])
        );
    }

    #[test]
    fn error_page_accepts_named_location_targets() {
        let src = r#"
            http {
                server {
                    listen 80;
                    location / {
                        error_page 404 @fallback;
                        return 404;
                    }
                }
            }
        "#;
        let cfg = parse(src).unwrap();
        assert_eq!(
            cfg.servers[0].locations[0].error_pages,
            Some(vec![ErrorPage {
                status: 404,
                action: ErrorPageAction::PreserveOriginal,
                target: vec![ValuePart::Literal("@fallback".into())],
            }])
        );
    }

    #[test]
    fn error_page_target_rejects_sent_http_variable() {
        let src = r#"
            http {
                server {
                    listen 80;
                    location / {
                        error_page 404 /oops?$sent_http_content_length;
                        return 404;
                    }
                }
            }
        "#;
        assert!(matches!(
            parse(src),
            Err(Error::BadValue {
                what: "error_page target ($sent_http_* unavailable)",
                ..
            })
        ));
    }

    #[test]
    fn alias_is_rejected_inside_named_location() {
        let src = r#"
            http {
                server {
                    listen 80;
                    location @named { alias /var/www; }
                }
            }
        "#;
        assert!(matches!(
            parse(src),
            Err(Error::BadValue {
                what: "alias in named location",
                ..
            })
        ));
    }

    #[test]
    fn unknown_directive_still_fails() {
        // Explicit-allowlist contract: a directive we don't know and haven't
        // listed must fail — not silently accept. This is what makes a test
        // that needs `add_header` surface a clear error instead of a
        // silently-wrong pass.
        let src = r#"http { server { listen 80; location / {
            return 200 "";
            totally_not_a_real_directive on;
        } } }"#;
        let err = parse(src).expect_err("must reject unknown directive");
        assert!(
            matches!(err, Error::UnknownDirective { .. }),
            "got: {err:?}"
        );
    }

    #[test]
    fn try_files_requires_two_args() {
        let src = r#"
            http { server { listen 80; location / {
                root /var/www;
                try_files $uri;
            } } }
        "#;
        assert!(parse(src).is_err());
    }

    #[test]
    fn autoindex_directives_parse_across_scopes() {
        let src = r#"
            http {
                autoindex on;
                autoindex_exact_size off;
                autoindex_localtime on;
                autoindex_format jsonp;
                server {
                    listen 80;
                    autoindex off;
                    autoindex_exact_size on;
                    autoindex_localtime off;
                    autoindex_format xml;
                    location / {
                        root /var/www;
                        autoindex on;
                        autoindex_exact_size off;
                        autoindex_localtime on;
                        autoindex_format json;
                    }
                }
            }
        "#;
        let cfg = parse(src).unwrap();
        assert_eq!(cfg.autoindex, Some(true));
        assert_eq!(cfg.autoindex_exact_size, Some(false));
        assert_eq!(cfg.autoindex_localtime, Some(true));
        assert_eq!(cfg.autoindex_format, Some(AutoindexFormat::Jsonp));

        let server = &cfg.servers[0];
        assert_eq!(server.autoindex, Some(false));
        assert_eq!(server.autoindex_exact_size, Some(true));
        assert_eq!(server.autoindex_localtime, Some(false));
        assert_eq!(server.autoindex_format, Some(AutoindexFormat::Xml));

        let loc = &server.locations[0];
        assert_eq!(loc.autoindex, Some(true));
        assert_eq!(loc.autoindex_exact_size, Some(false));
        assert_eq!(loc.autoindex_localtime, Some(true));
        assert_eq!(loc.autoindex_format, Some(AutoindexFormat::Json));
    }

    #[test]
    fn autoindex_rejects_bad_values() {
        let src = r#"
            http {
                server {
                    listen 80;
                    location / {
                        root /var/www;
                        autoindex maybe;
                    }
                }
            }
        "#;
        assert!(matches!(
            parse(src),
            Err(Error::BadValue {
                what: "autoindex",
                ..
            })
        ));

        let src = r#"
            http {
                server {
                    listen 80;
                    location / {
                        root /var/www;
                        autoindex_format yaml;
                    }
                }
            }
        "#;
        assert!(matches!(
            parse(src),
            Err(Error::BadValue {
                what: "autoindex_format",
                ..
            })
        ));
    }
}
