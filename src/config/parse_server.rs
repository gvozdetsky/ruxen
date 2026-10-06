//! `server { ... }` block parser plus the directives that are most
//! naturally server-scoped: `listen`, `keepalive_*`, `server_name`,
//! `server_tokens`. Most location-scope directives that *also* appear
//! at server scope are dispatched directly inside `parse_server_block`
//! — only the helpers themselves live here.

use super::*;
use std::net::SocketAddr;
use std::path::PathBuf;

pub(crate) fn parse_server_block(
    lx: &mut Lexer,
    inherited_root: Option<PathBuf>,
    inherited_ssl_certs: &[PathBuf],
    inherited_ssl_keys: &[PathBuf],
    inherited_ssl_protocols: Option<TlsVersionSet>,
    inherited_ssl_ciphers: Option<&str>,
    inherited_ssl_prefer_server_ciphers: Option<bool>,
    inherited_ssl_session_timeout_ms: Option<u64>,
    inherited_resumption: SessionResumption,
    inherited_client_max_body_size: Option<u64>,
    inherited_keepalive_timeout: Option<KeepaliveTimeout>,
    inherited_keepalive_requests: Option<u64>,
    inherited_keepalive_time_ms: Option<u64>,
    inherited_keepalive_disable: Option<KeepaliveDisable>,
    inherited_client_timeouts: ClientTimeouts,
    warnings: &mut Vec<String>,
) -> Result<Vec<Server>, Error> {
    let mut client_timeouts = ClientTimeouts::default();
    let mut listens: Vec<Listen> = Vec::new();
    let mut ssl_certs: Vec<PathBuf> = Vec::new();
    let mut ssl_keys: Vec<PathBuf> = Vec::new();
    let mut saw_local_ssl_cert_or_key = false;
    let mut ssl_protocols: Option<TlsVersionSet> = None;
    let mut ssl_ciphers: Option<String> = None;
    let mut ssl_prefer_server_ciphers: Option<bool> = None;
    let mut ssl_session_timeout_ms: Option<u64> = None;
    let mut resumption = SessionResumption::default();
    let mut saw_any_ssl_directive = false;
    let mut server_names: Vec<ServerNameSpec> = Vec::new();
    let mut index: Option<Vec<IndexEntry>> = None;
    let mut root = inherited_root;
    let mut locations: Vec<Location> = Vec::new();
    let mut add_headers: Option<Vec<AddHeader>> = None;
    let mut add_trailers: Option<Vec<AddHeader>> = None;
    let mut error_pages: Option<Vec<ErrorPage>> = None;
    let mut rewrite_ops: Vec<RewriteOp> = Vec::new();
    let mut keepalive_timeout: Option<KeepaliveTimeout> = None;
    let mut keepalive_requests: Option<u64> = None;
    let mut keepalive_time_ms: Option<u64> = None;
    let mut keepalive_disable: Option<KeepaliveDisable> = None;
    let mut merge_slashes: bool = true;
    let mut ignore_invalid_headers: Option<bool> = None;
    let mut underscores_in_headers: Option<bool> = None;
    let mut error_logs: Option<Vec<ErrorLog>> = None;
    let mut log_not_found: Option<bool> = None;
    let mut recursive_error_pages: Option<bool> = None;
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
    let mut sendfile: Option<bool> = None;
    let mut client_body_temp_path: Option<TempPath> = None;
    let mut disable_symlinks: Option<DisableSymlinks> = None;
    let mut limit_rate: Option<Vec<ValuePart>> = None;
    let mut limit_rate_after: Option<Vec<ValuePart>> = None;
    let mut post_action: Option<String> = None;
    let mut expires: Option<ExpiresDirective> = None;
    let mut proxy_set_headers: Option<Vec<ProxySetHeader>> = None;
    let mut proxy_pass_request_headers: Option<bool> = None;
    let mut proxy_pass_request_body: Option<bool> = None;
    let mut proxy_set_body: Option<Vec<ValuePart>> = None;
    let mut proxy_ignore_headers: Option<Vec<String>> = None;
    let mut proxy_connect_timeout_ms: Option<u64> = None;
    let mut proxy_read_timeout_ms: Option<u64> = None;
    let mut proxy_send_timeout_ms: Option<u64> = None;
    let mut proxy_limit_rate: Option<u64> = None;
    let mut proxy_http_version: Option<u8> = None;
    let mut proxy_next_upstream: Option<ProxyNextUpstream> = None;
    let mut proxy_next_upstream_tries: Option<u32> = None;
    let mut proxy_next_upstream_timeout_ms: Option<u64> = None;
    let mut proxy_intercept_errors: Option<bool> = None;
    let mut proxy_redirect: Option<ProxyRedirect> = None;
    let mut proxy_hide_headers: Option<Vec<String>> = None;
    let mut proxy_pass_headers: Option<Vec<String>> = None;
    let mut chunked_transfer_encoding: Option<bool> = None;

    loop {
        let (args, term) = lx.read_directive()?;
        if args.is_empty() {
            return match term {
                Terminator::BlockClose => {
                    if !saw_local_ssl_cert_or_key {
                        ssl_certs = inherited_ssl_certs.to_vec();
                        ssl_keys = inherited_ssl_keys.to_vec();
                    }
                    if listens.is_empty() {
                        listens.push(Listen::from_addr(default_listen_addr()));
                    }
                    // Whether this server's certificates are required, and
                    // whether its ssl_* lines take effect, depends on the
                    // other servers on the same address (`ssl` belongs to
                    // the listening socket): `prepare` and
                    // `warn_ssl_without_ssl_listen` decide.
                    if ssl_certs.len() != ssl_keys.len() {
                        return Err(Error::BadValue {
                            what: "ssl_certificate / ssl_certificate_key count mismatch",
                            got: format!("{} cert(s), {} key(s)", ssl_certs.len(), ssl_keys.len()),
                        });
                    }
                    if matches!(ssl_prefer_server_ciphers, Some(false)) {
                        warnings.push(
                            "ssl_prefer_server_ciphers off: rustls always uses server preference for TLS 1.2; ignored"
                                .into(),
                        );
                    }
                    let ssl = ServerSsl {
                        certs: ssl_certs,
                        keys: ssl_keys,
                        protocols: ssl_protocols
                            .or(inherited_ssl_protocols)
                            .unwrap_or_default(),
                        ciphers: ssl_ciphers
                            .or_else(|| inherited_ssl_ciphers.map(|v| v.to_string())),
                        prefer_server_ciphers: ssl_prefer_server_ciphers
                            .or(inherited_ssl_prefer_server_ciphers),
                        session_timeout_ms: ssl_session_timeout_ms
                            .or(inherited_ssl_session_timeout_ms),
                        resumption: resumption.inherit(inherited_resumption),
                    };
                    let kat = keepalive_timeout.or(inherited_keepalive_timeout);
                    let kar = keepalive_requests.or(inherited_keepalive_requests);
                    let katm = keepalive_time_ms.or(inherited_keepalive_time_ms);
                    let kad = keepalive_disable.or(inherited_keepalive_disable);
                    let mut listens_iter = listens.into_iter();
                    let first_listen = listens_iter
                        .next()
                        .expect("a default listen is added above");
                    let mut out: Vec<Server> = Vec::new();
                    out.push(Server {
                        listen: first_listen,
                        server_names,
                        index,
                        root,
                        add_headers,
                        add_trailers,
                        error_pages,
                        rewrite_ops,
                        keepalive_timeout: kat,
                        keepalive_requests: kar,
                        keepalive_time_ms: katm,
                        keepalive_disable: kad,
                        ssl_directives: saw_any_ssl_directive || saw_local_ssl_cert_or_key,
                        client_timeouts: client_timeouts.inherit(inherited_client_timeouts),
                        merge_slashes,
                        ignore_invalid_headers,
                        underscores_in_headers,
                        error_logs,
                        log_not_found,
                        recursive_error_pages,
                        server_tokens,
                        autoindex,
                        autoindex_exact_size,
                        autoindex_localtime,
                        autoindex_format,
                        access_logs,
                        auth_basic,
                        auth_basic_user_file,
                        auth_delay_ms,
                        client_max_body_size,
                        client_body_temp_path: client_body_temp_path.clone(),
                        sendfile,
                        disable_symlinks: disable_symlinks.clone(),
                        limit_rate,
                        limit_rate_after,
                        post_action,
                        expires,
                        proxy_set_headers,
                        proxy_pass_request_headers,
                        proxy_pass_request_body,
                        proxy_set_body,
                        proxy_ignore_headers,
                        proxy_connect_timeout_ms,
                        proxy_read_timeout_ms,
                        proxy_send_timeout_ms,
                        proxy_limit_rate,
                        proxy_http_version,
                        proxy_next_upstream,
                        proxy_next_upstream_tries,
                        proxy_next_upstream_timeout_ms,
                        proxy_intercept_errors,
                        proxy_redirect,
                        proxy_hide_headers,
                        proxy_pass_headers,
                        chunked_transfer_encoding,
                        ssl,
                        locations,
                    });
                    // Multi-`listen` server blocks expand to one Server
                    // per listen address. Each request only matches one of
                    // them (the listen index drives routing in
                    // `phase::find_config`), so duplicating `access_logs`,
                    // `locations`, etc. doesn't multi-log or multi-match.
                    // Server / Location / Handler are plain data — no Arc,
                    // RefCell, or fd-bearing fields — so `.clone()` is a
                    // straight deep copy with no aliasing concerns.
                    for listen in listens_iter {
                        let mut dup = out[0].clone();
                        dup.listen = listen;
                        out.push(dup);
                    }
                    Ok(out)
                }
                Terminator::Eof => Err(Error::UnclosedBlock),
                _ => Err(Error::UnexpectedEof),
            };
        }
        match (args[0].as_str(), &term) {
            ("listen", Terminator::Semi) => {
                listens.extend(parse_listen_range_args(&args[1..])?);
            }
            ("ssl_certificate", Terminator::Semi) => {
                saw_any_ssl_directive = true;
                if !saw_local_ssl_cert_or_key {
                    saw_local_ssl_cert_or_key = true;
                    ssl_certs.clear();
                    ssl_keys.clear();
                }
                let path = args.get(1).ok_or(Error::MissingArg("ssl_certificate"))?;
                ssl_certs.push(resolve_ssl_file_arg(lx.conf_prefix(), path));
            }
            ("ssl_certificate_key", Terminator::Semi) => {
                saw_any_ssl_directive = true;
                if !saw_local_ssl_cert_or_key {
                    saw_local_ssl_cert_or_key = true;
                    ssl_certs.clear();
                    ssl_keys.clear();
                }
                let path = args
                    .get(1)
                    .ok_or(Error::MissingArg("ssl_certificate_key"))?;
                ssl_keys.push(resolve_ssl_file_arg(lx.conf_prefix(), path));
            }
            ("ssl_protocols", Terminator::Semi) => {
                saw_any_ssl_directive = true;
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
                saw_any_ssl_directive = true;
                if ssl_ciphers.is_some() {
                    return Err(Error::Duplicate("ssl_ciphers"));
                }
                let v = args.get(1).ok_or(Error::MissingArg("ssl_ciphers"))?;
                ssl_ciphers = Some(v.clone());
                warn_ignored_tls_policy(&args, warnings);
            }
            ("ssl_prefer_server_ciphers", Terminator::Semi) => {
                saw_any_ssl_directive = true;
                if ssl_prefer_server_ciphers.is_some() {
                    return Err(Error::Duplicate("ssl_prefer_server_ciphers"));
                }
                ssl_prefer_server_ciphers =
                    Some(parse_on_off_args(&args[1..], "ssl_prefer_server_ciphers")?);
            }
            ("ssl_session_timeout", Terminator::Semi) => {
                saw_any_ssl_directive = true;
                if ssl_session_timeout_ms.is_some() {
                    return Err(Error::Duplicate("ssl_session_timeout"));
                }
                let v = args
                    .get(1)
                    .ok_or(Error::MissingArg("ssl_session_timeout"))?;
                ssl_session_timeout_ms = Some(ssl_session_timeout_ms_arg(v)?);
            }
            // SSL directives we accept-and-ignore at server scope. Matched
            // here (rather than via the global IGNORED_STMT allowlist) so
            // that `saw_any_ssl_directive`
            // also catches "ssl_session_cache shared:foo:1m" without a real
            // ssl_certificate, which is still a misconfiguration we want to
            // warn about.
            (name @ ("ssl_session_cache" | "ssl_session_tickets"), Terminator::Semi) => {
                saw_any_ssl_directive = true;
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
            ) => {
                saw_any_ssl_directive = true;
                warn_ignored_tls_policy(&args, warnings);
            }
            ("server_name", Terminator::Semi) => {
                if args.len() < 2 {
                    return Err(Error::MissingArg("server_name"));
                }
                // nginx allows multiple `server_name` directives in a block;
                // names accumulate. Each name is classified now so the
                // request-time matcher reads tagged variants instead of
                // re-scanning the raw string per request.
                for name in &args[1..] {
                    for spec in classify_server_name(name)? {
                        server_names.push(spec);
                    }
                }
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
            ("root", Terminator::Semi) => {
                let path = args.get(1).ok_or(Error::MissingArg("root path"))?;
                root = Some(PathBuf::from(path));
            }
            ("return", Terminator::Semi) => {
                let (status, body) = parse_return_args(&args[1..])?;
                rewrite_ops.push(RewriteOp::Return { status, body });
            }
            ("set", Terminator::Semi) => rewrite_ops.push(parse_set_op(&args[1..])?),
            ("rewrite", Terminator::Semi) => rewrite_ops.push(parse_rewrite_op(&args[1..])?),
            ("break", Terminator::Semi) => {
                if args.len() != 1 {
                    return Err(Error::BadValue {
                        what: "break",
                        got: args[1..].join(" "),
                    });
                }
                rewrite_ops.push(RewriteOp::Break);
            }
            ("if", Terminator::BlockOpen) => rewrite_ops.push(parse_if_op(&args[1..], lx)?),
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
            ("merge_slashes", Terminator::Semi) => {
                let raw = args.get(1).ok_or(Error::MissingArg("merge_slashes"))?;
                merge_slashes = match raw.as_str() {
                    "on" => true,
                    "off" => false,
                    _ => {
                        return Err(Error::BadValue {
                            what: "merge_slashes",
                            got: raw.clone(),
                        });
                    }
                };
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
            ("error_log", Terminator::Semi) => {
                error_logs
                    .get_or_insert_with(Vec::new)
                    .push(parse_error_log_args(&args[1..])?);
            }
            ("recursive_error_pages", Terminator::Semi) => {
                if recursive_error_pages.is_some() {
                    return Err(Error::Duplicate("recursive_error_pages"));
                }
                recursive_error_pages =
                    Some(parse_on_off_args(&args[1..], "recursive_error_pages")?);
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
            ("client_body_temp_path", Terminator::Semi) => {
                if client_body_temp_path.is_some() {
                    return Err(Error::Duplicate("client_body_temp_path"));
                }
                client_body_temp_path = Some(parse_temp_path_args(&args[1..])?);
            }
            ("location", Terminator::BlockOpen) => {
                let spec = parse_location_spec(&args[1..])?;
                // Top-level locations inherit `server_tokens` from the
                // server block (or http above it) at prepare time, not
                // here — pass `None` so only nested locations propagate
                // through this chain.
                parse_location_block(
                    spec,
                    lx,
                    root.clone(),
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    client_max_body_size.or(inherited_client_max_body_size),
                    None,
                    None,
                    None,
                    None,
                    None,
                    &mut locations,
                )?;
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
            ("proxy_ignore_headers", Terminator::Semi) => {
                if proxy_ignore_headers.is_some() {
                    return Err(Error::Duplicate("proxy_ignore_headers"));
                }
                proxy_ignore_headers = Some(parse_proxy_ignore_headers(&args[1..])?);
            }
            ("proxy_set_body", Terminator::Semi) => {
                if proxy_set_body.is_some() {
                    return Err(Error::Duplicate("proxy_set_body"));
                }
                if args.len() != 2 {
                    return Err(Error::BadValue {
                        what: "proxy_set_body",
                        got: args[1..].join(" "),
                    });
                }
                proxy_set_body = Some(parse_value_with_vars(&args[1])?);
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
                proxy_limit_rate = Some(parse_size_bytes(v).ok_or(Error::BadValue {
                    what: "proxy_limit_rate",
                    got: v.clone(),
                })?);
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
            ("proxy_redirect", Terminator::Semi) => {
                parse_proxy_redirect(&args, &mut proxy_redirect)?;
            }
            ("proxy_hide_header", Terminator::Semi) => {
                let name = args.get(1).ok_or(Error::MissingArg("proxy_hide_header"))?;
                proxy_hide_headers
                    .get_or_insert_with(Vec::new)
                    .push(name.clone());
            }
            ("proxy_pass_header", Terminator::Semi) => {
                let name = args.get(1).ok_or(Error::MissingArg("proxy_pass_header"))?;
                proxy_pass_headers
                    .get_or_insert_with(Vec::new)
                    .push(name.clone());
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
            (
                "listen"
                | "server_name"
                | "index"
                | "root"
                | "location"
                | "add_header"
                | "error_page"
                | "return"
                | "set"
                | "rewrite"
                | "break"
                | "if"
                | "keepalive_timeout"
                | "keepalive_requests"
                | "keepalive_time"
                | "keepalive_disable"
                | "ignore_invalid_headers"
                | "underscores_in_headers"
                | "error_log"
                | "log_not_found"
                | "recursive_error_pages"
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
                | "client_body_temp_path"
                | "disable_symlinks"
                | "post_action"
                | "expires"
                | "proxy_set_header"
                | "proxy_pass_request_headers"
                | "proxy_pass_request_body"
                | "proxy_set_body"
                | "proxy_ignore_headers"
                | "proxy_connect_timeout"
                | "proxy_read_timeout"
                | "proxy_send_timeout"
                | "proxy_limit_rate"
                | "proxy_http_version"
                | "proxy_next_upstream"
                | "proxy_next_upstream_tries"
                | "proxy_next_upstream_timeout"
                | "proxy_intercept_errors"
                | "proxy_redirect"
                | "proxy_hide_header"
                | "proxy_pass_header"
                | "ssl_certificate"
                | "ssl_certificate_key"
                | "ssl_protocols"
                | "ssl_ciphers"
                | "ssl_prefer_server_ciphers"
                | "ssl_session_cache"
                | "ssl_session_timeout"
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
                    ctx: "server",
                });
            }
            (n, Terminator::Semi) if is_ignored_stmt(n) => {}
            (n, Terminator::BlockOpen) if is_ignored_block(n) => skip_block(lx)?,
            (other, _) => {
                return Err(Error::UnknownDirective {
                    name: other.into(),
                    ctx: "server",
                });
            }
        }
    }
}

/// Translate PCRE `\Q...\E` literal escapes into per-character regex
/// escapes that the `regex` crate accepts. Untouched outside the `\Q\E`
/// blocks; an unterminated `\Q` runs to end-of-string. Mirrors the way
/// nginx forwards `server_name ~^...$` patterns to PCRE — production
/// configs (and `http_server_name.t`) commonly bracket literal hostnames
/// with `\Q\E` so dots aren't misread as metacharacters.
pub(crate) fn expand_pcre_quote_escapes(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() && bytes[i + 1] == b'Q' {
            i += 2;
            while i < bytes.len() {
                if bytes[i] == b'\\' && i + 1 < bytes.len() && bytes[i + 1] == b'E' {
                    i += 2;
                    break;
                }
                let c = bytes[i] as char;
                if c.is_ascii_alphanumeric() {
                    out.push(c);
                } else {
                    out.push('\\');
                    out.push(c);
                }
                i += 1;
            }
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}

/// Classify one `server_name` argument into one or more `ServerNameSpec`
/// entries. Most names produce a single entry; `.foo.example.com` (leading
/// dot) is shorthand for two entries — `Exact("foo.example.com")` and
/// `WildcardLeading("foo.example.com")` — matching nginx's documented
/// expansion in `ngx_http_core_server_name`.
pub(crate) fn classify_server_name(raw: &str) -> Result<Vec<ServerNameSpec>, Error> {
    if raw.is_empty() {
        return Ok(vec![ServerNameSpec::Empty]);
    }
    // Regex form: `~pattern` (case-sensitive) or `~*pattern`
    // (case-insensitive). nginx also lets `\Q...\E` literals through to
    // PCRE; the `regex` crate accepts those without modification.
    if let Some(rest) = raw.strip_prefix('~') {
        let (raw_pattern, mut case_insensitive) = match rest.strip_prefix('*') {
            Some(p) => (p.to_string(), true),
            None => (rest.to_string(), false),
        };
        // nginx auto-flips a `~` regex to case-insensitive if its pattern
        // contains any uppercase ASCII letter (`ngx_http_core_module.c`,
        // server_names parser). The `Host` header is lowercased before
        // matching, so an uppercase literal in the pattern would never
        // match without this — and configs commonly write `~^EXAMPLE\.COM$`
        // expecting it to match `example.com`.
        if !case_insensitive && raw_pattern.bytes().any(|b| b.is_ascii_uppercase()) {
            case_insensitive = true;
        }
        // PCRE allows `\Q...\E` literal escapes; nginx forwards regexes to
        // PCRE so test configs use the form. Rust's `regex` crate doesn't
        // recognize `\Q\E`, so translate to per-character escapes before
        // compile.
        let pattern = expand_pcre_quote_escapes(&raw_pattern);
        // Validate at parse time so a typo fails `nginx -t` instead of
        // crashing a worker.
        let _ = regex::bytes::RegexBuilder::new(&pattern)
            .case_insensitive(case_insensitive)
            .build()
            .map_err(|_| Error::BadValue {
                what: "server_name regex",
                got: raw.to_string(),
            })?;
        return Ok(vec![ServerNameSpec::Regex {
            display: raw.to_string(),
            pattern,
            case_insensitive,
        }]);
    }
    // Wildcard prefix: `*.foo.example.com` — match suffix `foo.example.com`.
    if let Some(suffix) = raw.strip_prefix("*.") {
        if suffix.is_empty() {
            return Err(Error::BadValue {
                what: "server_name wildcard",
                got: raw.to_string(),
            });
        }
        return Ok(vec![ServerNameSpec::WildcardLeading {
            display: raw.to_string(),
            suffix: suffix.to_ascii_lowercase(),
        }]);
    }
    // Wildcard suffix: `mail.example.*` — match head `mail.example`.
    if let Some(head) = raw.strip_suffix(".*") {
        if head.is_empty() {
            return Err(Error::BadValue {
                what: "server_name wildcard",
                got: raw.to_string(),
            });
        }
        return Ok(vec![ServerNameSpec::WildcardTrailing {
            display: raw.to_string(),
            head: head.to_ascii_lowercase(),
        }]);
    }
    // Leading dot: `.foo.example.com` is shorthand for both
    // `foo.example.com` (exact) and `*.foo.example.com` (wildcard prefix).
    if let Some(stripped) = raw.strip_prefix('.') {
        if stripped.is_empty() {
            return Err(Error::BadValue {
                what: "server_name dot-prefix",
                got: raw.to_string(),
            });
        }
        let lc = stripped.to_ascii_lowercase();
        return Ok(vec![
            ServerNameSpec::Exact(lc.clone()),
            ServerNameSpec::WildcardLeading {
                display: stripped.to_string(),
                suffix: lc,
            },
        ]);
    }
    Ok(vec![ServerNameSpec::Exact(raw.to_ascii_lowercase())])
}

/// nginx resolves `ssl_certificate` / `ssl_certificate_key` against the
/// config directory. `data:` values and paths with variables are loaded per
/// handshake in nginx; ruxen supports neither, so they pass through as
/// written and fail at load time under their original spelling.
pub(crate) fn resolve_ssl_file_arg(conf_prefix: Option<&Path>, raw: &str) -> PathBuf {
    let path = PathBuf::from(raw);
    if raw.starts_with("data:") || raw.contains('$') {
        return path;
    }
    resolve_conf_path(conf_prefix, path)
}

pub(crate) fn parse_server_tokens_args(args: &[String]) -> Result<ServerTokens, Error> {
    if args.len() != 1 {
        return Err(Error::BadValue {
            what: "server_tokens",
            got: args.join(" "),
        });
    }
    match args[0].as_str() {
        "off" => Ok(ServerTokens::Off),
        "on" => Ok(ServerTokens::On),
        "build" => Ok(ServerTokens::Build),
        _ => Err(Error::BadValue {
            what: "server_tokens",
            got: args[0].clone(),
        }),
    }
}

pub(crate) fn parse_listen(s: &str) -> Result<SocketAddr, Error> {
    if let Ok(port) = s.parse::<u16>() {
        return Ok(SocketAddr::from(([0, 0, 0, 0], port)));
    }
    s.parse::<SocketAddr>().map_err(|_| Error::BadValue {
        what: "listen address",
        got: s.to_string(),
    })
}

/// `listen` with a port range (`127.0.0.1:8000-8003`, `8000-8003`,
/// `[::1]:8000-8003`): one listen per port, the flags on each, as nginx's
/// `ngx_parse_inet_url`. A single port is one listen.
pub(crate) fn parse_listen_range_args(args: &[String]) -> Result<Vec<Listen>, Error> {
    let addr_s = args.first().ok_or(Error::MissingArg("listen"))?;
    let bad = || Error::BadValue {
        what: "listen address",
        got: addr_s.to_string(),
    };
    let (host, ports) = match addr_s.rfind(':') {
        Some(i) if !addr_s.ends_with(']') => (Some(&addr_s[..i]), &addr_s[i + 1..]),
        _ => (None, addr_s.as_str()),
    };
    let Some((first, last)) = ports.split_once('-') else {
        return Ok(vec![parse_listen_args(args)?]);
    };
    let first: u16 = first.parse().map_err(|_| bad())?;
    let last: u16 = last.parse().map_err(|_| bad())?;
    if first == 0 || last < first {
        return Err(bad());
    }
    let mut listens = Vec::with_capacity(usize::from(last - first) + 1);
    for port in first..=last {
        let mut one = args.to_vec();
        one[0] = match host {
            Some(host) => format!("{host}:{port}"),
            None => port.to_string(),
        };
        listens.push(parse_listen_args(&one)?);
    }
    Ok(listens)
}

/// Parse a `listen` directive's argument list (address + zero or more flags).
/// Flags accepted in any order; unknown flags fail. `key=value` flags share
/// the same parser as bare flags — order against bare flags is not
/// significant. nginx's parser is permissive in the same way.
pub(crate) fn parse_listen_args(args: &[String]) -> Result<Listen, Error> {
    let addr_s = args.first().ok_or(Error::MissingArg("listen"))?;
    let mut listen = Listen::from_addr(parse_listen(addr_s)?);
    for raw in &args[1..] {
        let (name, value) = match raw.split_once('=') {
            Some((n, v)) => (n, Some(v)),
            None => (raw.as_str(), None),
        };
        match (name, value) {
            ("ssl", None) => listen.ssl = true,
            ("default_server" | "default", None) => listen.default_server = true,
            ("reuseport", None) => listen.reuseport = true,
            ("http2", None) => listen.http2 = true,
            ("http3", None) => listen.http3 = true,
            ("quic", None) => listen.quic = true,
            ("proxy_protocol", None) => listen.proxy_protocol = true,
            ("deferred", None) => listen.deferred = true,
            ("bind", None) => {} // implicit when address is given; nginx-tests configs use it
            ("ipv6only", Some(v)) => {
                listen.ipv6only = Some(match v {
                    "on" => true,
                    "off" => false,
                    _ => {
                        return Err(Error::BadValue {
                            what: "listen ipv6only",
                            got: v.to_string(),
                        });
                    }
                });
            }
            ("so_keepalive", Some(v)) => listen.so_keepalive = Some(parse_so_keepalive(v)?),
            ("setfib", Some(_)) => {}
            ("accept_filter", Some(_)) => {}
            ("fastopen", Some(v)) => {
                listen.fastopen = Some(v.parse::<u32>().map_err(|_| Error::BadValue {
                    what: "listen fastopen",
                    got: v.to_string(),
                })?);
            }
            ("backlog", Some(v)) => {
                listen.backlog = Some(v.parse::<u32>().map_err(|_| Error::BadValue {
                    what: "listen backlog",
                    got: v.to_string(),
                })?);
            }
            ("rcvbuf", Some(v)) => {
                listen.rcvbuf = Some(parse_size_bytes(v).ok_or(Error::BadValue {
                    what: "listen rcvbuf",
                    got: v.to_string(),
                })?);
            }
            ("sndbuf", Some(v)) => {
                listen.sndbuf = Some(parse_size_bytes(v).ok_or(Error::BadValue {
                    what: "listen sndbuf",
                    got: v.to_string(),
                })?);
            }
            _ => {
                return Err(Error::BadValue {
                    what: "listen flag",
                    got: raw.clone(),
                });
            }
        }
    }
    Ok(listen)
}

/// `so_keepalive=on|off|[keepidle]:[keepintvl]:[keepcnt]`, as nginx's
/// ngx_http_core_listen: idle and interval are times (seconds, with nginx's
/// suffixes), count a number; any of the three may be empty.
fn parse_so_keepalive(v: &str) -> Result<SoKeepalive, Error> {
    let bad = || Error::BadValue {
        what: "listen so_keepalive",
        got: v.to_string(),
    };
    match v {
        "on" => {
            return Ok(SoKeepalive::On {
                idle: None,
                intvl: None,
                cnt: None,
            });
        }
        "off" => return Ok(SoKeepalive::Off),
        _ => {}
    }
    let parts: Vec<&str> = v.split(':').collect();
    let [idle, intvl, cnt] = parts.as_slice() else {
        return Err(bad());
    };
    let secs = |s: &str| -> Result<Option<u32>, Error> {
        if s.is_empty() {
            return Ok(None);
        }
        let secs = parse_duration_secs(s, "listen so_keepalive")?;
        u32::try_from(secs)
            .ok()
            .filter(|&n| n > 0)
            .map(Some)
            .ok_or_else(bad)
    };
    let idle = secs(idle)?;
    let intvl = secs(intvl)?;
    let cnt = if cnt.is_empty() {
        None
    } else {
        Some(cnt.parse::<u32>().ok().filter(|&n| n > 0).ok_or_else(bad)?)
    };
    if idle.is_none() && intvl.is_none() && cnt.is_none() {
        return Err(bad());
    }
    Ok(SoKeepalive::On { idle, intvl, cnt })
}

/// Parse `1k` / `1K` / `1m` / `1M` size suffixes used by `rcvbuf` / `sndbuf`.
/// Returns `None` on parse failure so callers can wrap with the right
/// `BadValue { what }` context.
pub(crate) fn parse_size_bytes(raw: &str) -> Option<u64> {
    let bytes = raw.as_bytes();
    if bytes.is_empty() {
        return None;
    }
    let (num, mult): (&str, u64) = match bytes[bytes.len() - 1] {
        b'k' | b'K' => (&raw[..raw.len() - 1], 1024),
        b'm' | b'M' => (&raw[..raw.len() - 1], 1024 * 1024),
        b'g' | b'G' => (&raw[..raw.len() - 1], 1024 * 1024 * 1024),
        _ => (raw, 1),
    };
    num.parse::<u64>().ok()?.checked_mul(mult)
}

/// One `proxy_redirect off | default | <pattern> <replacement>;` into the
/// scope's `slot`, with nginx's rules: `off` can't be mixed with other
/// `proxy_redirect` lines in the same scope.
pub(crate) fn parse_proxy_redirect(
    args: &[String],
    slot: &mut Option<ProxyRedirect>,
) -> Result<(), Error> {
    let rule = match &args[1..] {
        [one] if one == "off" => {
            if slot.is_some() {
                return Err(Error::Duplicate("proxy_redirect"));
            }
            *slot = Some(ProxyRedirect::Off);
            return Ok(());
        }
        [one] if one == "default" => ProxyRedirectRule::Default,
        [pattern, replacement] => {
            if let Some(regex) = pattern.strip_prefix('~') {
                // A regex rule's replacement may use its captures, $1…$9.
                let replacement = super::values::parse_value_with_vars_rewrite(replacement)?;
                let (regex, case_insensitive) = match regex.strip_prefix('*') {
                    Some(r) => (r, true),
                    None => (regex, false),
                };
                regex::bytes::RegexBuilder::new(regex)
                    .case_insensitive(case_insensitive)
                    .build()
                    .map_err(|e| Error::InvalidRegex {
                        pattern: regex.to_string(),
                        msg: e.to_string(),
                    })?;
                ProxyRedirectRule::Regex {
                    pattern: regex.to_string(),
                    case_insensitive,
                    replacement,
                }
            } else {
                ProxyRedirectRule::Prefix {
                    pattern: crate::config::parse_value_with_vars(pattern)?,
                    replacement: crate::config::parse_value_with_vars(replacement)?,
                }
            }
        }
        _ => {
            return Err(Error::BadValue {
                what: "proxy_redirect",
                got: args[1..].join(" "),
            });
        }
    };
    match slot {
        None => *slot = Some(ProxyRedirect::Rules(vec![rule])),
        Some(ProxyRedirect::Rules(rules)) => rules.push(rule),
        Some(ProxyRedirect::Off) => return Err(Error::Duplicate("proxy_redirect")),
    }
    Ok(())
}

/// Where a `server` without `listen` listens: `*:80`, or `*:8000` when not
/// run by root (`ngx_http_core_server`, which checks the real uid).
fn default_listen_addr() -> SocketAddr {
    // SAFETY: getuid has no preconditions and cannot fail.
    let port = if unsafe { libc::getuid() } == 0 {
        80
    } else {
        8000
    };
    SocketAddr::from(([0, 0, 0, 0], port))
}

/// A time value of an msec directive (`ngx_conf_set_msec_slot`), in
/// milliseconds: `ms` is allowed, `y` and `M` are not.
pub(crate) fn parse_duration_ms(raw: &str, what: &'static str) -> Result<u64, Error> {
    parse_time(raw, false)
        .map(|v| v as u64)
        .ok_or_else(|| Error::BadValue {
            what,
            got: raw.to_string(),
        })
}

/// A time value of a seconds directive (`ngx_conf_set_sec_slot`), in
/// seconds: `y` and `M` are allowed, `ms` is not.
pub(crate) fn parse_duration_secs(raw: &str, what: &'static str) -> Result<u64, Error> {
    parse_time(raw, true)
        .map(|v| v as u64)
        .ok_or_else(|| Error::BadValue {
            what,
            got: raw.to_string(),
        })
}

/// `ssl_session_timeout` is a seconds directive; ruxen keeps it in ms.
pub(crate) fn ssl_session_timeout_ms_arg(raw: &str) -> Result<u64, Error> {
    let secs = parse_duration_secs(raw, "ssl_session_timeout")?;
    secs.checked_mul(1000).ok_or_else(|| Error::BadValue {
        what: "ssl_session_timeout",
        got: raw.to_string(),
    })
}

/// Port of `ngx_parse_time` (src/core/ngx_parse.c): parts such as `1h30m`
/// in descending unit order (`y M w d h m s ms`), each unit at most once;
/// a trailing bare number is seconds. Returns seconds when `is_sec`,
/// milliseconds otherwise; `None` where nginx returns NGX_ERROR.
pub(crate) fn parse_time(raw: &str, is_sec: bool) -> Option<i64> {
    #[derive(PartialEq, PartialOrd)]
    enum Step {
        Start,
        Year,
        Month,
        Week,
        Day,
        Hour,
        Min,
        Sec,
        Msec,
        Last,
    }
    const DAY: i64 = 60 * 60 * 24;
    let b = raw.as_bytes();
    let mut step = if is_sec { Step::Start } else { Step::Month };
    let (mut valid, mut value, mut total) = (false, 0_i64, 0_i64);
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        i += 1;
        if c.is_ascii_digit() {
            value = value.checked_mul(10)?.checked_add((c - b'0') as i64)?;
            valid = true;
            continue;
        }
        let (next, mut scale) = match c {
            b'y' if step == Step::Start => (Step::Year, 365 * DAY),
            b'M' if step < Step::Month => (Step::Month, 30 * DAY),
            b'w' if step < Step::Week => (Step::Week, 7 * DAY),
            b'd' if step < Step::Day => (Step::Day, DAY),
            b'h' if step < Step::Hour => (Step::Hour, 60 * 60),
            b'm' if b.get(i) == Some(&b's') => {
                if is_sec || step >= Step::Msec {
                    return None;
                }
                i += 1;
                (Step::Msec, 1)
            }
            b'm' if step < Step::Min => (Step::Min, 60),
            b's' if step < Step::Sec => (Step::Sec, 1),
            b' ' if step < Step::Sec => (Step::Last, 1),
            _ => return None,
        };
        if next != Step::Msec && !is_sec {
            scale *= 1000;
        }
        step = next;
        total = total.checked_add(value.checked_mul(scale)?)?;
        value = 0;
        while b.get(i) == Some(&b' ') {
            i += 1;
        }
    }
    if !valid {
        return None;
    }
    if !is_sec {
        value = value.checked_mul(1000)?;
    }
    total.checked_add(value)
}

pub(crate) fn parse_keepalive_timeout_args(args: &[String]) -> Result<KeepaliveTimeout, Error> {
    if args.is_empty() || args.len() > 2 {
        return Err(Error::BadValue {
            what: "keepalive_timeout",
            got: args.join(" "),
        });
    }
    let timeout_ms = parse_duration_ms(&args[0], "keepalive_timeout")?;
    // The second arg becomes the `Keep-Alive: timeout=N` hint, in whole
    // seconds: nginx parses it as seconds, so `ms` is rejected.
    let header_timeout_secs = match args.get(1) {
        Some(v) => Some(parse_duration_secs(v, "keepalive_timeout header")?),
        None => None,
    };
    Ok(KeepaliveTimeout {
        timeout_ms,
        header_timeout_secs,
    })
}

pub(crate) fn parse_keepalive_requests_args(args: &[String]) -> Result<u64, Error> {
    if args.len() != 1 {
        return Err(Error::BadValue {
            what: "keepalive_requests",
            got: args.join(" "),
        });
    }
    args[0].parse::<u64>().map_err(|_| Error::BadValue {
        what: "keepalive_requests",
        got: args[0].clone(),
    })
}

pub(crate) fn parse_keepalive_time_args(args: &[String]) -> Result<u64, Error> {
    if args.len() != 1 {
        return Err(Error::BadValue {
            what: "keepalive_time",
            got: args.join(" "),
        });
    }
    parse_duration_ms(&args[0], "keepalive_time")
}

pub(crate) fn parse_keepalive_disable_args(args: &[String]) -> Result<KeepaliveDisable, Error> {
    if args.is_empty() {
        return Err(Error::MissingArg("keepalive_disable"));
    }
    let mut out = KeepaliveDisable {
        msie6: false,
        safari: false,
    };
    for v in args {
        match v.as_str() {
            "none" => {}
            "msie6" => out.msie6 = true,
            "safari" => out.safari = true,
            _ => {
                return Err(Error::BadValue {
                    what: "keepalive_disable",
                    got: v.clone(),
                });
            }
        }
    }
    Ok(out)
}
