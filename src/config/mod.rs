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
pub mod compat;
mod error;
mod lexer;
mod parse_access;
mod parse_gzip;
mod parse_http2;
mod parse_limit_conn;
mod parse_limit_req;
mod parse_location;
mod parse_log;
mod parse_map;
mod parse_rewrite;
mod parse_server;
mod parse_upstream;
pub(crate) mod pcre;
mod values;

pub use ast::*;
pub use error::*;
pub use parse_gzip::{GzipConf, GzipStatic, proxied as gzip_proxied};
pub use parse_http2::Http2Conf;
pub use parse_limit_conn::{LimitConnConf, LimitConnZoneDef};
pub use parse_limit_req::{LimitReqConf, LimitReqZoneDef};
pub use values::{SSL_SESSION_ID_USED, parse_value_with_vars};

pub(crate) use lexer::*;
pub(crate) use parse_access::parse_inet_addr;
use parse_access::{parse_access_directive, parse_limit_except_block};
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
    if let Some(g) = globals_src
        && !g.is_empty()
    {
        lx.push_inline(g);
    }
    parse_lexer(lx)
}

pub(crate) fn parse_lexer(mut lx: Lexer) -> Result<HttpConfig, Error> {
    parse_lexer_inner(&mut lx).map_err(|error| match lx.position() {
        Some(position) if !matches!(error, Error::At { .. }) => Error::At {
            error: Box::new(error),
            position,
        },
        _ => error,
    })
}

fn parse_lexer_inner(lx: &mut Lexer) -> Result<HttpConfig, Error> {
    reset_variable_registry();
    AIO_POOLS_USED.with(|u| u.borrow_mut().clear());
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
                let block = parse_http_block(lx)?;
                validate_proxy_upstream_refs(&block)?;
                http = Some(block);
            }
            ("http", _) => {
                return Err(Error::WrongTerminator {
                    name: name.into(),
                    ctx: "top-level",
                });
            }
            ("events", Terminator::BlockOpen) => parse_events_block(lx, &mut runtime)?,
            ("events", _) => {
                return Err(Error::WrongTerminator {
                    name: name.into(),
                    ctx: "top-level",
                });
            }
            ("ssl_object_cache_inheritable", Terminator::Semi) => {
                if runtime.ssl_object_cache_inheritable.is_some() {
                    return Err(Error::Duplicate("ssl_object_cache_inheritable"));
                }
                runtime.ssl_object_cache_inheritable = Some(parse_on_off_args(
                    &args[1..],
                    "ssl_object_cache_inheritable",
                )?);
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
            // `user name [group];`: applied by `main` after binding (see
            // `privileges`).
            ("user", Terminator::Semi) => {
                if runtime.user.is_some() {
                    return Err(Error::Duplicate("user"));
                }
                let name = args.get(1).ok_or(Error::MissingArg("user"))?;
                if args.len() > 3 {
                    return Err(Error::BadValue {
                        what: "user",
                        got: args[1..].join(" "),
                    });
                }
                runtime.user = Some(UserDirective {
                    name: name.clone(),
                    group: args.get(2).cloned(),
                });
            }
            ("user", _) => {
                return Err(Error::WrongTerminator {
                    name: name.into(),
                    ctx: "top-level",
                });
            }
            ("thread_pool", Terminator::Semi) => {
                let def = parse_thread_pool_args(&args)?;
                if runtime.thread_pools.iter().any(|p| p.name == def.name) {
                    return Err(Error::Text(format!(
                        "duplicate thread pool \"{}\"",
                        def.name
                    )));
                }
                runtime.thread_pools.push(def);
            }
            (n, Terminator::Semi) if is_ignored_stmt(n) => check_ignored_args(lx, &args)?,
            (n, Terminator::BlockOpen) if is_ignored_block(n) => {
                compat::ignored_block(lx, &args);
                skip_block(lx)?
            }
            _ => {
                compat::unknown(lx, &args, &term, "top-level")?;
            }
        }
    }

    let mut http = http.ok_or(Error::UnexpectedEof)?;
    check_thread_pools(&mut runtime.thread_pools)?;
    http.warnings.extend(lx.take_warnings());
    http.uses_request_body_file = values::request_body_file_used();
    http.uses_request_body = values::request_body_used();
    http.uses_request_id = values::request_id_used();
    http.uses_stderr_log = values::stderr_log_used();
    http.uses_stats = values::stats_used();
    http.uses_metrics = values::metrics_used();
    http.warnings.extend(check_variable_references()?);
    http.runtime = runtime;
    http.dump_files = lx.take_dump_files();
    http.conf_prefix = lx.conf_prefix().map(Path::to_path_buf);
    Ok(http)
}

pub(crate) fn parse_http_block(lx: &mut Lexer) -> Result<HttpConfig, Error> {
    let mut servers: Vec<Server> = Vec::new();
    let mut proxy = ProxyConf::default();
    let mut gzip = GzipConf::default();
    let mut http2_conf = Http2Conf::default();
    let mut limit_req = LimitReqConf::default();
    let mut limit_req_zones: Vec<LimitReqZoneDef> = Vec::new();
    let mut limit_conn = LimitConnConf::default();
    let mut limit_conn_zones: Vec<LimitConnZoneDef> = Vec::new();
    let mut root: Option<PathBuf> = None;
    let mut log_formats: Vec<LogFormatDef> = Vec::new();
    let mut access_logs: Vec<AccessLog> = Vec::new();
    let mut open_log_file_cache: Option<Option<OpenLogFileCache>> = None;
    let mut server_tokens: Option<ServerTokens> = None;
    let mut autoindex: Option<bool> = None;
    let mut autoindex_exact_size: Option<bool> = None;
    let mut autoindex_localtime: Option<bool> = None;
    let mut autoindex_format: Option<AutoindexFormat> = None;
    let mut if_modified_since: Option<IfModifiedSince> = None;
    let mut etag: Option<bool> = None;
    let mut split_clients: Vec<SplitClients> = Vec::new();
    let mut maps: Vec<MapBlock> = Vec::new();
    let mut auth_basic: Option<AuthBasic> = None;
    let mut auth_basic_user_file: Option<PathBuf> = None;
    let mut auth_delay_ms: Option<u64> = None;
    let mut access = AccessConf::default();
    let mut client_max_body_size: Option<u64> = None;
    let mut max_ranges: Option<u32> = None;
    let mut client_body_buffer_size: Option<u64> = None;
    let mut client_body_temp_path: Option<TempPath> = None;
    let mut sendfile: Option<bool> = None;
    let mut aio: Option<Aio> = None;
    let mut http2: Option<bool> = None;
    let mut disable_symlinks: Option<DisableSymlinks> = None;
    let mut limit_rate: Option<Vec<ValuePart>> = None;
    let mut limit_rate_after: Option<Vec<ValuePart>> = None;
    let mut keepalive_timeout: Option<KeepaliveTimeout> = None;
    let mut keepalive_requests: Option<u64> = None;
    let mut keepalive_time_ms: Option<u64> = None;
    let mut keepalive_min_timeout_ms: Option<u64> = None;
    let mut keepalive_disable: Option<KeepaliveDisable> = None;
    let mut client_timeouts = ClientTimeouts::default();
    let mut error_logs: Option<Vec<ErrorLog>> = None;
    let mut post_action: Option<String> = None;
    let mut expires: Option<ExpiresDirective> = None;
    let mut ignore_invalid_headers: Option<bool> = None;
    let mut underscores_in_headers: Option<bool> = None;
    let mut upstreams: Vec<UpstreamBlock> = Vec::new();
    let mut proxy_cache_paths: Vec<ProxyCachePath> = Vec::new();
    // Server-level defaults set at http scope: servers without their own
    // inherit them once the block is closed (see `BlockClose`).
    let mut index: Option<Vec<IndexEntry>> = None;
    let mut error_pages: Option<Vec<ErrorPage>> = None;
    let mut add_headers: Option<Vec<AddHeader>> = None;
    let mut redirect = RedirectConf::default();
    let mut mime = MimeConf::default();
    let mut charset = CharsetConf::default();
    let mut add_trailers: Option<Vec<AddHeader>> = None;
    let mut add_header_inherit: Option<HeaderInherit> = None;
    let mut add_trailer_inherit: Option<HeaderInherit> = None;
    let mut recursive_error_pages: Option<bool> = None;
    let mut merge_slashes: Option<bool> = None;
    // http-scope SSL defaults inherited by `server {}` blocks unless
    // they define their own cert/key pair.
    let mut ssl_certs: Vec<PathBuf> = Vec::new();
    let mut ssl_keys: Vec<PathBuf> = Vec::new();
    let mut ssl_protocols: Option<TlsVersionSet> = None;
    let mut ssl_ciphers: Option<String> = None;
    let mut ssl_prefer_server_ciphers: Option<bool> = None;
    let mut ssl_session_timeout_ms: Option<u64> = None;
    let mut ssl_reject_handshake: Option<bool> = None;
    let mut ssl_certificate_compression: Option<bool> = None;
    let mut ssl_certificate_cache_seen = false;
    let mut resumption = SessionResumption::default();
    let mut client_verify = ClientVerifyConf::default();
    let mut stapling = StaplingConf::default();
    let mut ssl_password_file: Option<PathBuf> = None;
    let mut warnings: Vec<String> = Vec::new();
    loop {
        let (args, term) = lx.read_directive()?;
        if args.is_empty() {
            return match term {
                Terminator::BlockClose => {
                    // Every listen was `quic` (#593): nginx would serve
                    // QUIC only, ruxen serves nothing; say so.
                    if servers.is_empty()
                        && warnings.iter().any(|w| w.starts_with(QUIC_LISTEN_IGNORED))
                    {
                        warnings.push(
                            "no TCP listen is left (\"quic\" listens are ignored): \
                             no connections will be accepted"
                                .into(),
                        );
                    }
                    // After the whole block: an http-level proxy_* line
                    // below a server still applies to it, as in nginx.
                    for server in &mut servers {
                        server.proxy = std::mem::take(&mut server.proxy).inherit(&proxy);
                        server.gzip = std::mem::take(&mut server.gzip).inherit(&gzip);
                        server.limit_req =
                            std::mem::take(&mut server.limit_req).inherit(&limit_req);
                        server.limit_conn =
                            std::mem::take(&mut server.limit_conn).inherit(&limit_conn);
                        if server.index.is_none() {
                            server.index.clone_from(&index);
                        }
                        // A level with any error_page replaces the inherited
                        // list (ngx_http_core_merge_loc_conf).
                        if server.error_pages.is_none() {
                            server.error_pages.clone_from(&error_pages);
                        }
                        // add_header / add_trailer likewise
                        // (ngx_http_headers_merge_conf, #17), with
                        // add_header_inherit (#598); then each location's
                        // chain over the server's.
                        merge_add_headers(
                            server,
                            (&add_headers, add_header_inherit),
                            (&add_trailers, add_trailer_inherit),
                        );
                        // absolute_redirect and friends (#15): http into the
                        // server, the server into each location and its
                        // `if` blocks.
                        server.redirect = server.redirect.inherit(&redirect);
                        let server_redirect = server.redirect;
                        // types {} / default_type (#38) the same way.
                        server.mime.inherit(&mime);
                        let server_mime = server.mime.clone();
                        // charset (#464) likewise, into the `if` blocks too.
                        server.charset.inherit(&charset);
                        for loc in &mut server.locations {
                            loc.inherit_redirect(&server_redirect);
                            loc.mime.inherit(&server_mime);
                            loc.charset.inherit(&server.charset);
                            inherit_charset_in_ifs(&mut loc.rewrite_ops, &loc.charset);
                        }
                        inherit_charset_in_ifs(&mut server.rewrite_ops, &server.charset);
                        server.recursive_error_pages =
                            server.recursive_error_pages.or(recursive_error_pages);
                        server.merge_slashes = server.merge_slashes.or(merge_slashes);
                        if server.root.is_none() {
                            server.root.clone_from(&root);
                        }
                        if let Some(root) = &server.root {
                            for loc in server.locations.iter_mut().filter(|l| l.inherits_root) {
                                loc.inherit_root(root);
                            }
                        }
                        server.keepalive_timeout = server.keepalive_timeout.or(keepalive_timeout);
                        server.keepalive_requests =
                            server.keepalive_requests.or(keepalive_requests);
                        server.keepalive_time_ms = server.keepalive_time_ms.or(keepalive_time_ms);
                        server.keepalive_min_timeout_ms =
                            server.keepalive_min_timeout_ms.or(keepalive_min_timeout_ms);
                        server.keepalive_disable = server.keepalive_disable.or(keepalive_disable);
                        server.client_timeouts = server.client_timeouts.inherit(client_timeouts);
                        server.client_timeouts.check_large_header_buffers()?;
                        let ssl = &mut server.ssl;
                        // A server with its own ssl_certificate lines keeps
                        // only those.
                        if ssl.certs.is_empty() && ssl.keys.is_empty() {
                            ssl.certs.clone_from(&ssl_certs);
                            ssl.keys.clone_from(&ssl_keys);
                        }
                        ssl.protocols = ssl.protocols.or(ssl_protocols);
                        if ssl.ciphers.is_none() {
                            ssl.ciphers.clone_from(&ssl_ciphers);
                        }
                        ssl.prefer_server_ciphers =
                            ssl.prefer_server_ciphers.or(ssl_prefer_server_ciphers);
                        ssl.session_timeout_ms = ssl.session_timeout_ms.or(ssl_session_timeout_ms);
                        ssl.resumption = std::mem::take(&mut ssl.resumption).inherit(&resumption);
                        ssl.reject_handshake = ssl.reject_handshake.or(ssl_reject_handshake);
                        ssl.certificate_compression =
                            ssl.certificate_compression.or(ssl_certificate_compression);
                        ssl.client_verify =
                            std::mem::take(&mut ssl.client_verify).inherit(&client_verify);
                        if ssl.password_file.is_none() {
                            ssl.password_file.clone_from(&ssl_password_file);
                        }
                        ssl.stapling = std::mem::take(&mut ssl.stapling).inherit(&stapling);
                    }
                    Ok(HttpConfig {
                        runtime: RuntimeOpts::default(),
                        error_logs,
                        log_formats,
                        access_logs,
                        open_log_file_cache: open_log_file_cache.flatten(),
                        server_tokens,
                        autoindex,
                        autoindex_exact_size,
                        autoindex_localtime,
                        autoindex_format,
                        if_modified_since,
                        etag,
                        split_clients,
                        maps,
                        auth_basic,
                        auth_basic_user_file,
                        auth_delay_ms,
                        access,
                        client_max_body_size,
                        max_ranges,
                        client_body_buffer_size,
                        // Set once the whole config is read.
                        uses_request_body_file: false,
                        uses_request_body: false,
                        uses_request_id: false,
                        uses_stderr_log: false,
                        uses_stats: false,
                        uses_metrics: false,
                        client_body_temp_path,
                        sendfile,
                        aio,
                        http2,
                        http2_conf,
                        disable_symlinks,
                        limit_rate,
                        limit_rate_after,
                        post_action,
                        expires,
                        ignore_invalid_headers,
                        underscores_in_headers,
                        proxy_cache_paths,
                        upstreams,
                        limit_req_zones,
                        limit_conn_zones,
                        warnings: warn_ssl_without_ssl_listen(&servers, warnings),
                        servers,
                        dump_files: Vec::new(),
                        conf_prefix: None,
                    })
                }
                Terminator::Eof => Err(Error::UnclosedBlock),
                _ => Err(Error::UnexpectedEof),
            };
        }
        match (args[0].as_str(), &term) {
            ("types", Terminator::BlockOpen) | ("default_type", Terminator::Semi) => {
                parse_mime(lx, &args, &term, &mut mime)?;
            }
            ("charset" | "charset_types" | "source_charset", Terminator::Semi) => {
                parse_charset(lx, &args, &term, &mut charset)?;
            }
            ("server", Terminator::BlockOpen) => {
                servers.extend(parse_server_block(lx, &mut warnings)?)
            }
            ("server", _) => {
                return Err(Error::WrongTerminator {
                    name: "server".into(),
                    ctx: "http",
                });
            }
            ("root", Terminator::Semi) => {
                let path = args.get(1).ok_or(Error::MissingArg("root path"))?;
                root = Some(parse_root_path(false, path)?);
            }
            ("root", _) => {
                return Err(Error::WrongTerminator {
                    name: "root".into(),
                    ctx: "http",
                });
            }
            ("merge_slashes", Terminator::Semi) => {
                let raw = args.get(1).ok_or(Error::MissingArg("merge_slashes"))?;
                merge_slashes = match raw.as_str() {
                    "on" => Some(true),
                    "off" => Some(false),
                    _ => {
                        return Err(Error::BadValue {
                            what: "merge_slashes",
                            got: raw.clone(),
                        });
                    }
                };
            }
            ("index", Terminator::Semi) => {
                if args.len() < 2 {
                    return Err(Error::MissingArg("index"));
                }
                index
                    .get_or_insert_with(Vec::new)
                    .extend(parse_index_entries(&args[1..])?);
            }
            ("error_page", Terminator::Semi) => {
                let entries = parse_error_page_args(&args[1..])?;
                error_pages.get_or_insert_with(Vec::new).extend(entries);
            }
            ("add_header", Terminator::Semi) => {
                let entry = parse_add_header_args(&args[1..])?;
                add_headers.get_or_insert_with(Vec::new).push(entry);
            }
            (name, Terminator::Semi) if RedirectConf::takes(name) => redirect.parse(&args)?,
            ("add_trailer", Terminator::Semi) => {
                let entry = parse_add_header_args(&args[1..])?;
                add_trailers.get_or_insert_with(Vec::new).push(entry);
            }
            ("add_header_inherit", Terminator::Semi) => {
                parse_header_inherit(&mut add_header_inherit, &args)?;
            }
            ("add_trailer_inherit", Terminator::Semi) => {
                parse_header_inherit(&mut add_trailer_inherit, &args)?;
            }
            ("recursive_error_pages", Terminator::Semi) => {
                if recursive_error_pages.is_some() {
                    return Err(Error::Duplicate("recursive_error_pages"));
                }
                recursive_error_pages =
                    Some(parse_on_off_args(&args[1..], "recursive_error_pages")?);
            }
            ("log_format", Terminator::Semi) => {
                log_formats.push(parse_log_format_args(&args[1..])?);
            }
            ("access_log", Terminator::Semi) => match parse_access_log_args(&args[1..])? {
                ParsedAccessLog::Off => access_logs.clear(),
                ParsedAccessLog::Entry(log) => access_logs.push(log),
            },
            ("open_log_file_cache", Terminator::Semi) => {
                if open_log_file_cache.is_some() {
                    return Err(Error::Duplicate("open_log_file_cache"));
                }
                open_log_file_cache = Some(parse_open_log_file_cache_args(&args[1..])?);
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
            ("if_modified_since", Terminator::Semi) => {
                if if_modified_since.is_some() {
                    return Err(Error::Duplicate("if_modified_since"));
                }
                if_modified_since = Some(parse_if_modified_since_args(&args[1..])?);
            }
            ("etag", Terminator::Semi) => {
                if etag.is_some() {
                    return Err(Error::Duplicate("etag"));
                }
                etag = Some(parse_on_off_args(&args[1..], "etag")?);
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
            ("proxy_cache_path", Terminator::Semi) => {
                let cache_path = parse_upstream::parse_proxy_cache_path(&args[1..])?;
                if proxy_cache_paths.iter().any(|p| p.zone == cache_path.zone) {
                    return Err(Error::BadValue {
                        what: "proxy_cache_path duplicate zone",
                        got: cache_path.zone,
                    });
                }
                proxy_cache_paths.push(cache_path);
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
                let set = parse_tls_protocols(&args[1..], "ssl_protocols")?;
                warn_old_tls_protocols(&args, &mut warnings);
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
                ssl_session_timeout_ms = Some(ssl_session_timeout_ms_arg(v)?);
            }
            ("ssl_reject_handshake", Terminator::Semi) => {
                if ssl_reject_handshake.is_some() {
                    return Err(Error::Duplicate("ssl_reject_handshake"));
                }
                ssl_reject_handshake = Some(parse_on_off_args(&args[1..], "ssl_reject_handshake")?);
            }
            ("ssl_certificate_compression", Terminator::Semi) => {
                if ssl_certificate_compression.is_some() {
                    return Err(Error::Duplicate("ssl_certificate_compression"));
                }
                ssl_certificate_compression = Some(parse_on_off_args(
                    &args[1..],
                    "ssl_certificate_compression",
                )?);
            }
            ("ssl_certificate_cache", Terminator::Semi) => {
                if std::mem::replace(&mut ssl_certificate_cache_seen, true) {
                    return Err(Error::Duplicate("ssl_certificate_cache"));
                }
                parse_server::check_ssl_certificate_cache(&args[1..])?;
            }
            (name @ ("ssl_session_cache" | "ssl_session_tickets"), Terminator::Semi) => {
                resumption.parse(name, &args)?;
            }
            ("ssl_session_ticket_key", Terminator::Semi) => {
                let [_, path] = args.as_slice() else {
                    return Err(Error::MissingArg("ssl_session_ticket_key"));
                };
                resumption.add_ticket_key(resolve_ssl_file_arg(lx.conf_prefix(), path));
            }
            ("ssl_password_file", Terminator::Semi) => {
                if ssl_password_file.is_some() {
                    return Err(Error::Duplicate("ssl_password_file"));
                }
                let [_, path] = args.as_slice() else {
                    return Err(Error::MissingArg("ssl_password_file"));
                };
                ssl_password_file = Some(resolve_conf_path(lx.conf_prefix(), PathBuf::from(path)));
            }
            (name, Terminator::Semi) if ClientVerifyConf::takes(name) => {
                client_verify.parse(&args, lx.conf_prefix())?
            }
            (name, Terminator::Semi) if StaplingConf::takes(name) => {
                stapling.parse(&args, lx.conf_prefix())?
            }
            (
                "ssl_buffer_size" | "ssl_dhparam" | "ssl_ecdh_curve" | "ssl_early_data"
                | "ssl_conf_command",
                Terminator::Semi,
            ) => {
                warn_ignored_tls_policy(&args, &mut warnings);
                // ssl_ecdh_curve says so in its warning already.
                if args[0] != "ssl_ecdh_curve" {
                    compat::ignored(lx, &args);
                }
            }
            (
                "log_format"
                | "access_log"
                | "server_tokens"
                | "autoindex"
                | "autoindex_exact_size"
                | "autoindex_localtime"
                | "autoindex_format"
                | "if_modified_since"
                | "etag"
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
                | "ssl_certificate_compression"
                | "ssl_certificate_cache"
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
            (
                "allow" | "deny" | "satisfy" | "set_real_ip_from" | "real_ip_header"
                | "auth_request" | "auth_request_set" | "real_ip_recursive",
                Terminator::Semi,
            ) => {
                parse_access_directive(&mut access, &args, lx)?;
            }
            (
                "allow" | "deny" | "satisfy" | "set_real_ip_from" | "real_ip_header"
                | "auth_request" | "auth_request_set" | "real_ip_recursive",
                _,
            ) => {
                return Err(Error::WrongTerminator {
                    name: args[0].clone(),
                    ctx: "http",
                });
            }
            ("client_body_buffer_size", Terminator::Semi) => {
                if client_body_buffer_size.is_some() {
                    return Err(Error::Duplicate("client_body_buffer_size"));
                }
                client_body_buffer_size = Some(parse_client_body_buffer_size_args(&args[1..])?);
            }
            ("client_max_body_size", Terminator::Semi) => {
                if client_max_body_size.is_some() {
                    return Err(Error::Duplicate("client_max_body_size"));
                }
                client_max_body_size = Some(parse_client_max_body_size_args(&args[1..])?);
            }
            ("max_ranges", Terminator::Semi) => {
                if max_ranges.is_some() {
                    return Err(Error::Duplicate("max_ranges"));
                }
                max_ranges = Some(parse_max_ranges_args(&args[1..])?);
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
                client_body_temp_path =
                    Some(parse_temp_path_args(&args[1..], "client_body_temp_path")?);
            }
            ("disable_symlinks", Terminator::Semi) => {
                if disable_symlinks.is_some() {
                    return Err(Error::Duplicate("disable_symlinks"));
                }
                disable_symlinks = Some(parse_disable_symlinks_args(&args[1..])?);
            }
            ("http2", Terminator::Semi) => {
                if http2.is_some() {
                    return Err(Error::Duplicate("http2"));
                }
                http2 = Some(parse_on_off_args(&args[1..], "http2")?);
            }
            ("sendfile", Terminator::Semi) => {
                if sendfile.is_some() {
                    return Err(Error::Duplicate("sendfile"));
                }
                sendfile = Some(parse_on_off_args(&args[1..], "sendfile")?);
            }
            ("aio", Terminator::Semi) => {
                if aio.is_some() {
                    return Err(Error::Duplicate("aio"));
                }
                aio = Some(parse_aio_args(lx, &args)?);
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
            ("client_max_body_size" | "max_ranges", _) => {
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
            ("keepalive_min_timeout", Terminator::Semi) => {
                if keepalive_min_timeout_ms.is_some() {
                    return Err(Error::Duplicate("keepalive_min_timeout"));
                }
                keepalive_min_timeout_ms = Some(parse_keepalive_min_timeout_args(&args[1..])?);
            }
            ("keepalive_disable", Terminator::Semi) => {
                if keepalive_disable.is_some() {
                    return Err(Error::Duplicate("keepalive_disable"));
                }
                keepalive_disable = Some(parse_keepalive_disable_args(&args[1..])?);
            }
            (
                name @ ("client_header_timeout"
                | "client_body_timeout"
                | "send_timeout"
                | "large_client_header_buffers"
                | "client_header_buffer_size"
                | "max_headers"
                | "http2_chunk_size"),
                Terminator::Semi,
            ) => {
                client_timeouts.parse(name, &args)?;
            }
            // Ignored, but kept for nginx's check against
            // `large_client_header_buffers`.
            ("connection_pool_size", Terminator::Semi) => {
                check_ignored_args(lx, &args)?;
                client_timeouts.parse("connection_pool_size", &args)?;
            }
            (name, Terminator::Semi) if ProxyConf::takes(name) => {
                proxy.parse(&args, lx.conf_prefix())?
            }
            (name, Terminator::Semi) if GzipConf::takes(name) => gzip.parse(&args)?,
            (name, Terminator::Semi) if Http2Conf::takes(name) => {
                http2_conf.parse(&args, &mut warnings)?
            }
            (name, Terminator::Semi) if LimitReqConf::takes(name) => limit_req.parse(&args)?,
            (name, Terminator::Semi) if LimitConnConf::takes(name) => limit_conn.parse(&args)?,
            ("limit_conn_zone", Terminator::Semi) => {
                let zone = parse_limit_conn::parse_limit_conn_zone(&args[1..])?;
                if let Some(known) = limit_conn_zones.iter().find(|z| z.name == zone.name) {
                    return Err(Error::BadValue {
                        what: "limit_conn_zone (is already bound to key)",
                        got: format!("\"{}\" bound to \"{}\"", zone.name, known.key_text),
                    });
                }
                limit_conn_zones.push(zone);
            }
            ("limit_req_zone", Terminator::Semi) => {
                let zone = parse_limit_req::parse_limit_req_zone(&args[1..])?;
                // ngx_http_limit_req_zone: one key per zone name.
                if let Some(known) = limit_req_zones.iter().find(|z| z.name == zone.name) {
                    return Err(Error::BadValue {
                        what: "limit_req_zone (is already bound to key)",
                        got: format!("\"{}\" bound to \"{}\"", zone.name, known.key_text),
                    });
                }
                limit_req_zones.push(zone);
            }
            ("error_log", Terminator::Semi) => {
                error_logs
                    .get_or_insert_with(Vec::new)
                    .push(parse_error_log_args(&args[1..])?);
            }
            (n, Terminator::Semi) if is_ignored_stmt(n) => check_ignored_args(lx, &args)?,
            (n, Terminator::BlockOpen) if is_ignored_block(n) => {
                compat::ignored_block(lx, &args);
                skip_block(lx)?
            }
            (_, _) => {
                compat::unknown(lx, &args, &term, "http")?;
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
    "client_body_timeout",
    "client_body_in_file_only",
    "client_body_in_single_buffer",
    "client_max_body_size",
    "client_header_timeout",
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
    "chunked_transfer_encoding",
    "output_buffers",
    "postpone_output",
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
    "msie_padding",
    "msie_refresh",
    // Proxy tuning knobs we don't implement yet but accept as no-ops so
    // upstream nginx-tests configs (which inject these via TEST_GLOBALS_HTTP)
    // load.
    "proxy_temp_path",
    // rustls offers only strong suites, so ignoring the upstream cipher
    // list can't enable a weak one, as with ssl_ciphers (#116).
    "proxy_ssl_ciphers",
    "proxy_temp_file_write_size",
    "proxy_max_temp_file_size",
    "proxy_buffering",
    "proxy_buffers",
    "proxy_buffer_size",
    "proxy_busy_buffers_size",
    "proxy_request_buffering",
    // Temp directories of modules ruxen doesn't have (`fastcgi_pass` and
    // friends stay unknown), so never used. Container images' default
    // configurations set all of them. Arguments are checked
    // (`check_ignored_args`).
    "fastcgi_temp_path",
    "uwsgi_temp_path",
    "scgi_temp_path",
    "proxy_socket_keepalive",
    "proxy_store",
    "proxy_store_access",
    // File I/O knobs: nginx-only tuning. `aio_write`: temp-file writes
    // stay on the worker (#526).
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
    "ssi",
    "ssi_silent_errors",
    "ssi_types",
    "override_charset",
    // HTTP/3 (nginx ≥ 1.25): ruxen has none, and its `listen … quic` is
    // ignored with a warning already, so these settings have nothing to
    // apply to. Accepted so a config written for nginx with HTTP/3 starts
    // and serves HTTP/1.1 and HTTP/2 on its TCP listeners.
    "http3",
    "http3_hq",
    "http3_max_concurrent_streams",
    "http3_stream_buffer_size",
    "quic_active_connection_id_limit",
    "quic_bpf",
    "quic_gso",
    "quic_host_key",
    "quic_retry",
];

thread_local! {
    /// The pools `aio threads` names, with where: checked against the
    /// `thread_pool`s once the whole configuration is read, which may
    /// define them after the `http` block.
    static AIO_POOLS_USED: std::cell::RefCell<Vec<(String, Option<String>)>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// `aio off|on|threads[=pool]` (ngx_http_core_set_aio). `on` is Linux
/// native AIO, which ruxen doesn't have: accepted, a `--compat` finding.
pub(crate) fn parse_aio_args(lx: &Lexer, args: &[String]) -> Result<Aio, Error> {
    let [_, value] = args else {
        return Err(Error::BadValue {
            what: "aio",
            got: args[1..].join(" "),
        });
    };
    let aio = match value.as_str() {
        "off" => Aio::Off,
        "on" => Aio::On,
        "threads" => Aio::Threads("default".to_string()),
        v => match v.strip_prefix("threads=") {
            Some(name) if name.contains('$') => {
                return Err(Error::Directive {
                    name: "aio",
                    msg: "with a variable in the thread pool name is not supported".to_string(),
                });
            }
            Some(name) => Aio::Threads(name.to_string()),
            None => {
                return Err(Error::BadValue {
                    what: "aio",
                    got: v.to_string(),
                });
            }
        },
    };
    match &aio {
        Aio::Threads(name) => {
            AIO_POOLS_USED.with(|u| u.borrow_mut().push((name.clone(), lx.position())));
        }
        _ => compat::ignored(lx, args),
    }
    Ok(aio)
}

/// `thread_pool name threads=N [max_queue=M];` (ngx_thread_pool): other
/// parameters are ignored, as nginx does.
fn parse_thread_pool_args(args: &[String]) -> Result<ThreadPoolDef, Error> {
    if !(3..=4).contains(&args.len()) {
        return Err(Error::Text(
            "invalid number of arguments in \"thread_pool\" directive".to_string(),
        ));
    }
    let mut threads = 0;
    let mut max_queue = crate::aio::DEFAULT_MAX_QUEUE;
    for arg in &args[2..] {
        if let Some(n) = arg.strip_prefix("threads=") {
            threads = match n.parse::<usize>() {
                Ok(n) if n > 0 => n,
                _ => return Err(Error::Text(format!("invalid threads value \"{arg}\""))),
            };
        } else if let Some(n) = arg.strip_prefix("max_queue=") {
            max_queue = n
                .parse::<usize>()
                .map_err(|_| Error::Text(format!("invalid max_queue value \"{arg}\"")))?;
        }
    }
    if threads == 0 {
        return Err(Error::Text(
            "\"thread_pool\" must have \"threads\" parameter".to_string(),
        ));
    }
    Ok(ThreadPoolDef {
        name: args[1].clone(),
        threads,
        max_queue,
    })
}

/// Every pool an `aio threads` names is defined; `default` is when it
/// isn't (ngx_thread_pool_init_conf).
fn check_thread_pools(pools: &mut Vec<ThreadPoolDef>) -> Result<(), Error> {
    let used = AIO_POOLS_USED.with(|u| std::mem::take(&mut *u.borrow_mut()));
    for (name, position) in used {
        if pools.iter().any(|p| p.name == name) {
            continue;
        }
        if name == "default" {
            pools.push(ThreadPoolDef {
                name,
                threads: crate::aio::DEFAULT_THREADS,
                max_queue: crate::aio::DEFAULT_MAX_QUEUE,
            });
            continue;
        }
        let error = Error::Text(format!("unknown thread pool \"{name}\""));
        return Err(match position {
            Some(position) => Error::At {
                error: Box::new(error),
                position,
            },
            None => error,
        });
    }
    Ok(())
}

/// Block directives whose body we swallow wholesale (no inner parsing).
pub(crate) const IGNORED_BLOCK: &[&str] = &["events", "charset_map"];

/// The body of `types { TYPE EXT…; … }` (#38): extensions lowercased, a
/// repeated one taking the later type, as ngx_http_core_type does (it
/// warns too).
/// nginx's ngx_http_headers_merge_conf over a chain of levels (#598):
/// `parent` is the effective list above the first level and `mode` its
/// inherit mode; each level's own list and mode merge over what is above.
/// `None`: the parent's list as it is, no level changed it.
fn merge_header_levels<'a>(
    parent: Option<&Vec<AddHeader>>,
    mut mode: HeaderInherit,
    levels: impl IntoIterator<Item = (Option<&'a Vec<AddHeader>>, Option<HeaderInherit>)>,
) -> Option<Vec<AddHeader>> {
    let mut merged: Option<Vec<AddHeader>> = None;
    for (own, own_mode) in levels {
        mode = own_mode.unwrap_or(mode);
        merged = match (mode, own) {
            (HeaderInherit::Off, own) => Some(own.cloned().unwrap_or_default()),
            (_, None) => merged,
            (HeaderInherit::On, Some(own)) => Some(own.clone()),
            (HeaderInherit::Merge, Some(own)) => {
                let above = merged.as_ref().or(parent);
                Some(
                    own.iter()
                        .chain(above.into_iter().flatten())
                        .cloned()
                        .collect(),
                )
            }
        };
    }
    merged
}

/// A server's `add_header` / `add_trailer` over the http level's, and then
/// each location's (and `if` block's) chain over the server's (#598). A
/// location's lists become its effective ones; `None` where they are the
/// server's as they are, which `prepare` takes.
fn merge_add_headers(
    server: &mut Server,
    http_headers: (&Option<Vec<AddHeader>>, Option<HeaderInherit>),
    http_trailers: (&Option<Vec<AddHeader>>, Option<HeaderInherit>),
) {
    fn level(
        headers: &Option<Vec<AddHeader>>,
        mode: Option<HeaderInherit>,
    ) -> (Option<&Vec<AddHeader>>, Option<HeaderInherit>) {
        (headers.as_ref(), mode)
    }
    let on = HeaderInherit::On;
    let headers_mode = server.add_header_inherit.or(http_headers.1);
    let trailers_mode = server.add_trailer_inherit.or(http_trailers.1);
    let headers = merge_header_levels(
        http_headers.0.as_ref(),
        http_headers.1.unwrap_or(on),
        [level(&server.add_headers, server.add_header_inherit)],
    );
    let trailers = merge_header_levels(
        http_trailers.0.as_ref(),
        http_trailers.1.unwrap_or(on),
        [level(&server.add_trailers, server.add_trailer_inherit)],
    );
    server.add_headers = headers.or_else(|| http_headers.0.clone());
    server.add_trailers = trailers.or_else(|| http_trailers.0.clone());
    server.add_header_inherit = headers_mode;
    server.add_trailer_inherit = trailers_mode;
    let (server_headers, server_trailers) = (&server.add_headers, &server.add_trailers);
    let merge = |loc: &mut Location| {
        loc.add_headers = merge_header_levels(
            server_headers.as_ref(),
            headers_mode.unwrap_or(on),
            loc.header_ancestors
                .iter()
                .map(|l| level(&l.headers, l.headers_inherit))
                .chain([level(&loc.add_headers, loc.add_header_inherit)]),
        );
        loc.add_trailers = merge_header_levels(
            server_trailers.as_ref(),
            trailers_mode.unwrap_or(on),
            loc.header_ancestors
                .iter()
                .map(|l| level(&l.trailers, l.trailers_inherit))
                .chain([level(&loc.add_trailers, loc.add_trailer_inherit)]),
        );
    };
    fn in_ifs(ops: &mut [RewriteOp], merge: &dyn Fn(&mut Location)) {
        for op in ops {
            if let RewriteOp::If { body, location, .. } = op {
                if let Some(IfLocation::Parsed { location, .. }) = location {
                    merge(location);
                }
                in_ifs(body, merge);
            }
        }
    }
    for loc in &mut server.locations {
        in_ifs(&mut loc.rewrite_ops, &merge);
        merge(loc);
    }
    in_ifs(&mut server.rewrite_ops, &merge);
}

pub(crate) fn parse_types_block(lx: &mut Lexer) -> Result<Vec<(String, String)>, Error> {
    let mut out: Vec<(String, String)> = Vec::new();
    loop {
        let (args, term) = lx.read_directive()?;
        if args.is_empty() {
            match term {
                Terminator::BlockClose => return Ok(out),
                Terminator::Eof => return Err(Error::UnclosedBlock),
                _ => return Err(Error::UnexpectedEof),
            }
        }
        if !matches!(term, Terminator::Semi) || args.len() < 2 {
            return Err(Error::BadValue {
                what: "types",
                got: args.join(" "),
            });
        }
        for ext in &args[1..] {
            let ext = ext.to_ascii_lowercase();
            match out.iter_mut().find(|(e, _)| *e == ext) {
                Some(slot) => slot.1.clone_from(&args[0]),
                None => out.push((ext, args[0].clone())),
            }
        }
    }
}

/// `types {` or `default_type …;` into `mime` (#38); `false` if `args`
/// is neither.
/// A location's (or server's) charset settings into its `if` blocks, which
/// took only the location's own at parse time (#464).
fn inherit_charset_in_ifs(ops: &mut [RewriteOp], parent: &CharsetConf) {
    for op in ops {
        if let RewriteOp::If { body, location, .. } = op {
            match location {
                Some(IfLocation::Parsed { location, .. }) => {
                    location.charset.inherit(parent);
                    let own = location.charset.clone();
                    inherit_charset_in_ifs(body, &own);
                }
                _ => inherit_charset_in_ifs(body, parent),
            }
        }
    }
}

/// `charset`, `charset_types` and `source_charset` (#464), at the levels
/// the caller allows; `false` for any other directive. `if_block`: inside
/// a location's `if`, where `charset_types` isn't allowed.
pub(crate) fn parse_charset(
    lx: &Lexer,
    args: &[String],
    term: &Terminator,
    conf: &mut CharsetConf,
) -> Result<bool, Error> {
    if *term != Terminator::Semi {
        return Ok(false);
    }
    match args[0].as_str() {
        "charset" => {
            if conf.charset.is_some() {
                return Err(Error::Duplicate("charset"));
            }
            let [_, name] = args else {
                return Err(Error::BadValue {
                    what: "charset",
                    got: args[1..].join(" "),
                });
            };
            // A charset from a variable is not supported yet: none is
            // added, which `--compat` reports.
            if name.starts_with('$') {
                compat::ignored(lx, args);
            }
            conf.charset = Some((name != "off").then(|| name.clone()));
        }
        "charset_types" => {
            if conf.types.is_some() {
                return Err(Error::Duplicate("charset_types"));
            }
            if args.len() < 2 {
                return Err(Error::MissingArg("charset_types"));
            }
            conf.types = Some(args[1..].iter().map(|t| t.to_ascii_lowercase()).collect());
        }
        "source_charset" => {
            if conf.source.is_some() {
                return Err(Error::Duplicate("source_charset"));
            }
            let [_, name] = args else {
                return Err(Error::BadValue {
                    what: "source_charset",
                    got: args[1..].join(" "),
                });
            };
            // Nothing is converted: a different charset leaves the
            // response unlabelled (`worker::prepare_charset`).
            compat::ignored(lx, args);
            conf.source = Some(name.clone());
        }
        _ => return Ok(false),
    }
    Ok(true)
}

pub(crate) fn parse_mime(
    lx: &mut Lexer,
    args: &[String],
    term: &Terminator,
    mime: &mut MimeConf,
) -> Result<bool, Error> {
    match (args[0].as_str(), term) {
        // A second `types {}` at the same level adds to the first, a
        // repeated extension taking the later type: ngx_http_core_types
        // keeps one array per level (`include mime.types;` and then a few
        // more types is common).
        ("types", Terminator::BlockOpen) if args.len() == 1 => {
            let more = parse_types_block(lx)?;
            match &mut mime.types {
                None => mime.types = Some(std::sync::Arc::new(more)),
                Some(types) => {
                    let types = std::sync::Arc::make_mut(types);
                    for (ext, ty) in more {
                        match types.iter_mut().find(|(e, _)| *e == ext) {
                            Some(slot) => slot.1 = ty,
                            None => types.push((ext, ty)),
                        }
                    }
                }
            }
            Ok(true)
        }
        ("default_type", Terminator::Semi) => {
            if mime.default_type.is_some() {
                return Err(Error::Duplicate("default_type"));
            }
            let [_, value] = args else {
                return Err(Error::BadValue {
                    what: "default_type",
                    got: args[1..].join(" "),
                });
            };
            mime.default_type = Some(value.clone());
            Ok(true)
        }
        _ => Ok(false),
    }
}

/// A `root` or `alias` path. With variables it is rendered per request
/// (#232), but it may not read `$document_root` or `$realpath_root`, its
/// own value (ngx_http_core_root).
pub(crate) fn parse_root_path(alias: bool, path: &str) -> Result<PathBuf, Error> {
    let has =
        |name: &str| path.contains(&format!("${name}")) || path.contains(&format!("${{{name}}}"));
    let refused = match (has("document_root"), has("realpath_root"), alias) {
        (true, _, false) => "the $document_root variable cannot be used in the \"root\" directive",
        (true, _, true) => "the $document_root variable cannot be used in the \"alias\" directive",
        (_, true, false) => "the $realpath_root variable cannot be used in the \"root\" directive",
        (_, true, true) => "the $realpath_root variable cannot be used in the \"alias\" directive",
        _ => "",
    };
    if !refused.is_empty() {
        return Err(Error::Message(refused));
    }
    if path.contains('$') {
        // Notes the references for the unknown-variable check.
        parse_value_with_vars(path)?;
    }
    Ok(PathBuf::from(path))
}

/// Fail closed on directives that restrict access, when ruxen can't
/// enforce them yet. The allowlist above is for tuning knobs; silently
/// dropping one of these would serve what the config says to protect.
/// Called by the lexer for every directive, so no scope can miss it;
/// `term` tells a block from a line.
pub(crate) fn reject_unenforced(args: &[String], term: &Terminator) -> Result<(), Error> {
    let value = args.get(1).map(String::as_str);
    let consequence = match args.first().map(String::as_str) {
        // `location $var` (one argument, a leading `$`) is a predicate
        // location since nginx 1.31.5: it matches when the variable is
        // non-empty and not "0" (ngx_http_core_location). Read as a prefix,
        // as nginx 1.24 did, it never matches, and `location $blocked
        // { return 403; }` would block nothing (#596). A modifier, apart
        // or glued (`= $x`, `=$x`), still makes it literal in nginx. Only a
        // block: `location $x;` can be a `map` entry.
        Some("location")
            if *term == Terminator::BlockOpen
                && args.len() == 2
                && value.is_some_and(|v| v.starts_with('$')) =>
        {
            "predicate locations (nginx 1.31.5) aren't implemented, and as a literal prefix it \
             would never match"
        }
        _ => return Ok(()),
    };
    // For a location, the whole directive: "location" alone isn't what's
    // missing.
    let name = match args.first().map(String::as_str) {
        Some("location") => args.join(" "),
        _ => args[0].clone(),
    };
    Err(Error::Unenforced { name, consequence })
}

/// Accepted with a warning: `ssl_ecdh_curve`, because rustls offers only
/// modern groups, so ignoring a restriction can't enable a weak one, and
/// many real TLS configs set it. (`ssl_ciphers` is applied: `tls_ciphers`.)
pub(crate) fn warn_ignored_tls_policy(args: &[String], warnings: &mut Vec<String>) {
    let name = args[0].as_str();
    let w = match (name, args.get(1).map(String::as_str)) {
        ("ssl_ecdh_curve", _) => format!(
            "\"{name}\" is not supported yet and is ignored: rustls's default key exchange groups \
             are used"
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
    // `ssl` belongs to the listening socket: a block's ssl_* lines apply
    // on any of its addresses that some server makes TLS.
    let ignored = servers.iter().any(|s| {
        !s.ssl_directives.is_empty()
            && !servers.iter().any(|other| {
                other.listen.ssl
                    && s.ssl_directives.iter().any(|(addr, unix)| {
                        other.listen.addr == *addr && other.listen.unix == *unix
                    })
            })
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
    IGNORED_STMT.contains(&name)
}

/// Validate the arguments of the allowlisted directives whose grammar is
/// cheap to check, so that a typo still fails `-t` as in nginx. The rest of
/// `IGNORED_STMT` is accepted with any arguments.
pub(crate) fn check_ignored_args(lx: &Lexer, args: &[String]) -> Result<(), Error> {
    compat::ignored(lx, args);
    let what = match args[0].as_str() {
        "proxy_temp_path" => "proxy_temp_path",
        "fastcgi_temp_path" => "fastcgi_temp_path",
        "uwsgi_temp_path" => "uwsgi_temp_path",
        "scgi_temp_path" => "scgi_temp_path",
        "connection_pool_size" | "request_pool_size" => {
            return ast::parse_pool_size(args).map(drop);
        }
        _ => return Ok(()),
    };
    parse_temp_path_args(&args[1..], what).map(drop)
}

#[inline]
pub(crate) fn is_ignored_block(name: &str) -> bool {
    IGNORED_BLOCK.contains(&name)
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
    fn time_values_follow_ngx_parse_time() {
        let ms = |v| parse_time(v, false);
        let secs = |v| parse_time(v, true);
        assert_eq!(ms("500ms"), Some(500));
        assert_eq!(ms("30"), Some(30_000));
        assert_eq!(ms("1d"), Some(86_400_000));
        assert_eq!(ms("2w"), Some(14 * 86_400_000));
        assert_eq!(ms("1h30m"), Some(5_400_000));
        assert_eq!(ms("1h 30m"), Some(5_400_000));
        assert_eq!(ms("1m30"), Some(90_000));
        assert_eq!(ms("1s500ms"), Some(1_500));
        assert_eq!(secs("1y"), Some(365 * 86_400));
        assert_eq!(secs("1M"), Some(30 * 86_400));
        assert_eq!(secs("1d12h"), Some(129_600));
        assert_eq!(secs("0"), Some(0));
        // msec directives take neither years nor months, seconds ones no ms.
        assert_eq!(ms("1y"), None);
        assert_eq!(ms("1M"), None);
        assert_eq!(secs("500ms"), None);
        // Descending order, each unit once, at least one digit.
        assert_eq!(ms("1m1h"), None);
        assert_eq!(ms("1s1s"), None);
        assert_eq!(ms(""), None);
        assert_eq!(ms("h"), None);
        assert_eq!(ms("1x"), None);
        assert_eq!(ms("-1"), None);
        assert_eq!(secs("9223372036854775807"), Some(i64::MAX));
        assert_eq!(secs("9223372036854775808"), None);
        assert_eq!(ms("9223372036854775807"), None);
        assert_eq!(secs("300000000000y"), None);
    }

    #[test]
    fn time_directives_take_days() {
        let src = r#"
            http {
                ssl_session_timeout 1d;
                keepalive_timeout 1h 1d;
                client_body_timeout 1d;
                server { listen 80; proxy_read_timeout 1w; expires 1M;
                    location / { expires @1h30m; proxy_send_timeout 1d12h; return 200; }
                }
            }
        "#;
        parse(src).unwrap();
        for bad in [
            "http { ssl_session_timeout 500ms; server { listen 80; } }",
            "http { keepalive_timeout 1y; server { listen 80; } }",
            "http { server { listen 80; expires 1m1h; } }",
            "http { server { listen 80; expires @25h; } }",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn server_without_listen_listens_on_80_or_8000() {
        let cfg = parse("http { server { server_name a.test; return 200; } }").unwrap();
        let port = if unsafe { libc::getuid() } == 0 {
            80
        } else {
            8000
        };
        assert_eq!(cfg.servers.len(), 1);
        assert_eq!(
            cfg.servers[0].listen.addr,
            std::net::SocketAddr::from(([0, 0, 0, 0], port))
        );
        assert!(!cfg.servers[0].listen.default_server);
    }

    #[test]
    fn proxy_settings_inherit_from_http() {
        let cfg = parse(
            r#"
            http {
                proxy_connect_timeout 5s;
                proxy_set_header Host $host;
                proxy_hide_header X-Powered-By;
                server { listen 80; proxy_read_timeout 1m; location / { proxy_pass http://127.0.0.1:81; } }
                server { listen 81; proxy_set_header X-A a; proxy_connect_timeout 1s; }
                proxy_intercept_errors on;
            }
            "#,
        )
        .unwrap();
        let (a, b) = (&cfg.servers[0].proxy, &cfg.servers[1].proxy);
        assert_eq!(a.connect_timeout_ms, Some(5_000));
        assert_eq!(a.read_timeout_ms, Some(60_000));
        assert_eq!(a.set_headers.as_ref().unwrap()[0].name, "Host");
        assert_eq!(
            a.hide_headers.as_deref(),
            Some(&["X-Powered-By".to_string()][..])
        );
        // Below the servers, still inherited.
        assert_eq!(a.intercept_errors, Some(true));
        assert_eq!(b.connect_timeout_ms, Some(1_000));
        // Replaced whole, not appended to.
        let names: Vec<_> = b
            .set_headers
            .as_ref()
            .unwrap()
            .iter()
            .map(|h| &h.name)
            .collect();
        assert_eq!(names, ["X-A"]);
        // The location keeps only its own; prepare merges it with the server.
        assert_eq!(cfg.servers[0].locations[0].proxy.connect_timeout_ms, None);

        for bad in [
            "http { proxy_connect_timeout 1s; proxy_connect_timeout 2s; server { listen 80; } }",
            "http { proxy_http_version 2.0; server { listen 80; } }",
            "proxy_read_timeout 1s; http { server { listen 80; } }",
            "http { server { listen 80; location / { if ($arg_a) { proxy_redirect off; } } } }",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn proxy_force_ranges_parses_and_inherits() {
        let cfg = parse(
            r#"
            http {
                server {
                    listen 80;
                    location /own { proxy_force_ranges off; proxy_pass http://127.0.0.1:81; }
                    location /up {
                        proxy_pass http://127.0.0.1:81;
                        location /up/nested { proxy_pass http://127.0.0.1:81; }
                    }
                }
                server { listen 81; proxy_force_ranges off; }
                proxy_force_ranges on;
            }
            "#,
        )
        .unwrap();
        // The http-level line below the servers still reaches them.
        assert_eq!(cfg.servers[0].proxy.force_ranges, Some(true));
        assert_eq!(cfg.servers[1].proxy.force_ranges, Some(false));
        let loc = |p: &str| {
            cfg.servers[0]
                .locations
                .iter()
                .find(|l| l.pattern == p)
                .unwrap()
        };
        assert_eq!(loc("/own").proxy.force_ranges, Some(false));
        // Locations keep their own; prepare merges them with the server.
        assert_eq!(loc("/up").proxy.force_ranges, None);
        assert_eq!(loc("/up/nested").proxy.force_ranges, None);

        let nested = parse(
            "http { server { listen 80; location /a { proxy_force_ranges on; \
             location /a/b { proxy_pass http://127.0.0.1:81; } } } }",
        )
        .unwrap();
        let b = nested.servers[0]
            .locations
            .iter()
            .find(|l| l.pattern == "/a/b")
            .unwrap();
        assert_eq!(b.proxy.force_ranges, Some(true));

        assert!(matches!(
            parse("http { proxy_force_ranges on; proxy_force_ranges off; }"),
            Err(Error::Duplicate("proxy_force_ranges"))
        ));
        for bad in [
            "http { proxy_force_ranges yes; }",
            "http { proxy_force_ranges; }",
            "http { proxy_force_ranges on off; }",
            "http { server { listen 80; proxy_force_ranges on; proxy_force_ranges on; } }",
            "http { server { listen 80; location / { proxy_force_ranges on; proxy_force_ranges off; } } }",
            "http { server { listen 80; proxy_force_ranges on { } } }",
            "http { server { listen 80; location / { proxy_force_ranges on { } } } }",
            // Not one of the directives nginx allows in `if`.
            "http { server { listen 80; location / { if ($arg_a) { proxy_force_ranges on; } } } }",
            "proxy_force_ranges on; http { }",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn max_ranges_parses_at_every_scope_and_inherits_into_nested_blocks() {
        let cfg = parse(
            r#"
            http {
                server {
                    listen 80;
                    max_ranges 2;
                    location /own { max_ranges 0; }
                    location /plain { }
                    location /outer {
                        location /outer/inner { }
                        max_ranges 7;
                    }
                    location /if {
                        max_ranges 3;
                        if ($arg_a) { root /tmp; }
                    }
                }
                server { listen 81; }
                max_ranges 1;
            }
            "#,
        )
        .unwrap();
        assert_eq!(cfg.max_ranges, Some(1));
        assert_eq!(cfg.servers[0].max_ranges, Some(2));
        // The server keeps its own: prepare falls back to http.
        assert_eq!(cfg.servers[1].max_ranges, None);
        let loc = |p: &str| {
            cfg.servers[0]
                .locations
                .iter()
                .find(|l| l.pattern == p)
                .unwrap()
        };
        assert_eq!(loc("/own").max_ranges, Some(0));
        assert_eq!(loc("/plain").max_ranges, None);
        // A nested location takes its parent's, even one set after it.
        assert_eq!(loc("/outer/inner").max_ranges, Some(7));
        let RewriteOp::If {
            location: Some(IfLocation::Parsed { location, .. }),
            ..
        } = &loc("/if").rewrite_ops[0]
        else {
            panic!("an if location");
        };
        assert_eq!(location.max_ranges, Some(3));

        // ngx_conf_set_num_slot: digits only; a value past u32 is no limit.
        let at_http = |v: &str| parse(&format!("http {{ max_ranges {v}; }}")).map(|c| c.max_ranges);
        assert_eq!(at_http("0").unwrap(), Some(0));
        assert_eq!(at_http("4294967295").unwrap(), Some(u32::MAX));
        assert_eq!(at_http("99999999999").unwrap(), Some(u32::MAX));
        for bad in [
            "-1",
            "+1",
            "1k",
            "abc",
            "\"\"",
            "9223372036854775808",
            "1 2",
        ] {
            let err = at_http(bad).unwrap_err().to_string();
            assert!(err.contains("max_ranges"), "{bad}: {err}");
        }
        let err = at_http("x").unwrap_err().to_string();
        assert!(err.contains("invalid number"), "{err}");
        assert!(parse("http { max_ranges; }").is_err());

        for dup in [
            "http { max_ranges 1; max_ranges 2; }",
            "http { server { listen 80; max_ranges 1; max_ranges 2; } }",
            "http { server { listen 80; location / { max_ranges 1; max_ranges 2; } } }",
        ] {
            assert!(
                matches!(parse(dup), Err(Error::Duplicate("max_ranges"))),
                "{dup}"
            );
        }
        for bad in [
            "http { max_ranges 1 { } }",
            "http { server { listen 80; max_ranges 1 { } } }",
            "http { server { listen 80; location / { max_ranges 1 { } } } }",
            // Not one of the directives nginx allows in `if`.
            "http { server { listen 80; location / { if ($arg_a) { max_ranges 1; } } } }",
            "max_ranges 1; http { }",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
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
    fn parses_modifiers_written_against_the_pattern() {
        // nginx takes `location ~\.php$` as `location ~ \.php$` (#577).
        let src = r#"
            http {
                server {
                    listen 80;
                    location =/x       { return 200 "x"; }
                    location ^~/assets/ { return 200 "a"; }
                    location ~\.gif$   { return 200 "g"; }
                    location ~*\.png$  { return 200 "p"; }
                }
            }
        "#;
        let cfg = parse(src).unwrap();
        let locs = &cfg.servers[0].locations;
        assert_eq!(locs[0].mode, MatchMode::Exact);
        assert_eq!(locs[0].pattern, "/x");
        assert_eq!(locs[1].mode, MatchMode::Prefix);
        assert!(locs[1].noregex);
        assert_eq!(locs[1].pattern, "/assets/");
        assert_eq!(
            locs[2].mode,
            MatchMode::Regex {
                case_insensitive: false
            }
        );
        assert_eq!(locs[2].pattern, "\\.gif$");
        assert_eq!(
            locs[3].mode,
            MatchMode::Regex {
                case_insensitive: true
            }
        );
        assert_eq!(locs[3].pattern, "\\.png$");
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
        // No ssl_protocols: prepare takes the default (TLSv1.2, TLSv1.3).
        assert_eq!(s.ssl.protocols, None);
        assert_eq!(
            s.ssl.protocols.unwrap_or_default(),
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
    fn listen_quic_opens_no_socket() {
        // #593: nginx opens a UDP socket for `quic`; ruxen has no HTTP/3 and
        // must not open a TCP one in its place. A server whose listens are
        // all `quic` doesn't get the default `*:80` either.
        let cfg =
            parse("http { server { listen 127.0.0.1:28099 quic; location / { return 200 x; } } }")
                .unwrap();
        assert!(cfg.servers.is_empty(), "{:?}", cfg.servers);
        assert_eq!(
            cfg.warnings,
            [
                QUIC_LISTEN_IGNORED.to_string(),
                "no TCP listen is left (\"quic\" listens are ignored): no connections will be \
                 accepted"
                    .to_string(),
            ]
        );
        // The usual pair keeps its TLS socket; one warning per line, also
        // for a port range.
        let cfg = parse(
            "http { server { listen 127.0.0.1:443 ssl; listen 127.0.0.1:443 quic reuseport;
                             listen 127.0.0.1:8000-8003 quic;
                             ssl_certificate a.pem; ssl_certificate_key a.key; } }",
        )
        .unwrap();
        assert_eq!(cfg.servers.len(), 1);
        assert_eq!(cfg.servers[0].listen.addr.port(), 443);
        assert!(cfg.servers[0].listen.ssl);
        assert_eq!(
            cfg.warnings,
            [
                QUIC_LISTEN_IGNORED.to_string(),
                QUIC_LISTEN_IGNORED.to_string()
            ]
        );
    }

    #[test]
    fn http3_directives_are_accepted_without_effect() {
        // A config written for nginx with HTTP/3 starts; its TCP listen
        // serves as before, and only the `quic` listen warns.
        let cfg = parse(
            "http { quic_retry on; quic_gso on; http3_stream_buffer_size 64k;
                    server { listen 127.0.0.1:443 ssl; listen 127.0.0.1:443 quic reuseport;
                             http3 on; http3_hq off; http3_max_concurrent_streams 128;
                             quic_active_connection_id_limit 2; quic_host_key k.key;
                             ssl_certificate a.pem; ssl_certificate_key a.key; } }",
        )
        .unwrap();
        assert_eq!(cfg.servers.len(), 1);
        assert_eq!(cfg.warnings, [QUIC_LISTEN_IGNORED.to_string()]);
    }

    #[test]
    fn listen_quic_rejects_tcp_parameters() {
        // ngx_http_core_listen's checks, in its order.
        for (flags, param) in [
            ("ssl quic", "ssl"),
            ("quic http2", "http2"),
            ("quic fastopen=10", "fastopen"),
            ("quic backlog=10 deferred", "backlog"),
            ("quic deferred", "deferred"),
            ("quic so_keepalive=on", "so_keepalive"),
            ("quic proxy_protocol", "proxy_protocol"),
        ] {
            let err = parse(&format!("http {{ server {{ listen 443 {flags}; }} }}")).unwrap_err();
            assert_eq!(
                err.to_string(),
                format!("\"listen\" directive \"{param}\" parameter is incompatible with \"quic\""),
                "{flags}"
            );
        }
        // `http3` (the nginx-quic branch's spelling) is no nginx release's
        // parameter, and used to open a plain TCP socket too.
        let err = parse("http { server { listen 443 http3; } }").unwrap_err();
        assert!(matches!(
            err,
            Error::BadValue {
                what: "listen flag",
                ..
            }
        ));
    }

    /// nginx 1.27–1.29's `ssl_object_cache_inheritable`,
    /// `ssl_certificate_cache` and `ssl_certificate_compression` (#601):
    /// taken where nginx takes them, refused as nginx refuses them, and the
    /// compression flag inherited from http scope.
    #[test]
    fn ssl_cache_and_compression_directives() {
        let cfg = parse(
            "ssl_object_cache_inheritable off;\n\
             http { ssl_certificate_cache max=10 inactive=20s valid=1m;\n\
             ssl_certificate_compression on;\n\
             server { listen 80; ssl_certificate_cache off; }\n\
             server { listen 81; ssl_certificate_compression off; } }",
        )
        .unwrap();
        assert_eq!(cfg.servers[0].ssl.certificate_compression, Some(true));
        assert_eq!(cfg.servers[1].ssl.certificate_compression, Some(false));
        for bad in [
            "ssl_object_cache_inheritable on; ssl_object_cache_inheritable on; http { }",
            "ssl_object_cache_inheritable yes; http { }",
            "http { ssl_object_cache_inheritable on; }",
            "http { ssl_certificate_cache inactive=20s; }",
            "http { ssl_certificate_cache max=0; }",
            "http { ssl_certificate_cache max=1 valid=x; }",
            "http { ssl_certificate_cache foo; }",
            "http { ssl_certificate_cache off; ssl_certificate_cache off; }",
            "http { server { listen 80; location / { ssl_certificate_cache off; } } }",
            "http { ssl_certificate_compression yes; }",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }

    /// `proxy_ssl_certificate_cache` (#601), parsed as nginx's
    /// ngx_http_proxy_ssl_certificate_cache: seconds, `off` winning.
    #[test]
    fn proxy_ssl_certificate_cache_directive() {
        let cfg = parse(
            "http { server { listen 80; proxy_ssl_certificate_cache max=4 valid=2s;\n\
             location /a { proxy_ssl_certificate_cache max=1 inactive=1m; }\n\
             location /b { proxy_ssl_certificate_cache max=1 off; } } }",
        )
        .unwrap();
        let server = &cfg.servers[0];
        let Some(Some(cache)) = server.proxy.ssl_certificate_cache else {
            panic!("{:?}", server.proxy.ssl_certificate_cache);
        };
        assert_eq!(
            (cache.max, cache.inactive_secs, cache.valid_secs),
            (4, 10, 2)
        );
        let loc = |p: &str| {
            server
                .locations
                .iter()
                .find(|l| l.pattern == p)
                .unwrap()
                .proxy
                .ssl_certificate_cache
        };
        let Some(Some(a)) = loc("/a") else { panic!() };
        assert_eq!((a.max, a.inactive_secs, a.valid_secs), (1, 60, 60));
        assert_ne!(a.id, cache.id);
        assert_eq!(loc("/b"), Some(None));
        for bad in [
            "http { proxy_ssl_certificate_cache inactive=20s; }",
            "http { proxy_ssl_certificate_cache max=0; }",
            "http { proxy_ssl_certificate_cache max=-1; }",
            "http { proxy_ssl_certificate_cache max=1 valid=500ms; }",
            "http { proxy_ssl_certificate_cache max=1 foo; }",
            "http { proxy_ssl_certificate_cache; }",
            "http { proxy_ssl_certificate_cache off; proxy_ssl_certificate_cache off; }",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
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
            Some(TlsVersionSet {
                tlsv1_2: true,
                tlsv1_3: true
            })
        );

        // #36: the old names are skipped with a warning; only old ones is
        // still an error.
        let mixed = src.replace("TLSv1.2 TLSv1.3", "TLSv1 TLSv1.1 TLSv1.2 TLSv1.3");
        let cfg = parse(&mixed).unwrap();
        assert_eq!(
            cfg.servers[0].ssl.protocols,
            Some(TlsVersionSet {
                tlsv1_2: true,
                tlsv1_3: true
            })
        );
        assert_eq!(
            cfg.warnings,
            [
                "\"ssl_protocols\": TLSv1, TLSv1.1 not supported and ignored, rustls speaks TLSv1.2 and TLSv1.3 only"
            ]
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
    fn variables_in_root_and_alias() {
        // #232: rendered per request.
        for src in [
            "http { root /var/www/$host; server { listen 80; } }",
            "http { server { listen 80; root /srv/$server_name; } }",
            "http { server { listen 80; location ~ ^/i/(.+)$ { alias /srv/img/$1; } } }",
            "http { server { listen 80; location /a/ { alias /srv/${host}/; } } }",
        ] {
            parse(src).unwrap();
        }
        // Not their own value (ngx_http_core_root), nor an unknown one.
        for (src, want) in [
            (
                "http { server { listen 80; location / { root $document_root/x; } } }",
                "the $document_root variable cannot be used in the \"root\" directive",
            ),
            (
                "http { server { listen 80; location / { alias /x/${realpath_root}; } } }",
                "the $realpath_root variable cannot be used in the \"alias\" directive",
            ),
            (
                "http { server { listen 80; root /srv/$nosuch; } }",
                "unknown \"nosuch\" variable",
            ),
        ] {
            let e = parse(src).unwrap_err().to_string();
            assert!(e.starts_with(want), "{src}: {e}");
        }
    }

    #[test]
    fn predicate_locations_are_refused() {
        // #596: nginx 1.31.5 matches `location $var` when the variable is
        // non-empty and not "0"; ruxen would take it as a prefix that never
        // matches. Refused at server level, nested, and quoted.
        for (src, name) in [
            (
                "http { map $arg_x $blocked { default 0; 1 1; }
                 server { listen 80; location $blocked { return 403; } } }",
                "location $blocked",
            ),
            (
                "http { server { listen 80; location / { location $arg_b { return 403; } } } }",
                "location $arg_b",
            ),
            (
                "http { server { listen 80; location \"$arg_a\" { return 403; } } }",
                "location $arg_a",
            ),
        ] {
            assert_eq!(
                unenforced_err(src),
                format!(
                    "\"{name}\" is not supported yet, and ignoring it is unsafe: predicate \
                     locations (nginx 1.31.5) aren't implemented, and as a literal prefix it \
                     would never match"
                )
            );
        }
        // A modifier makes the `$` literal in nginx too, apart or glued
        // (#577); and a `map` entry named `location` is no location.
        for src in [
            "http { server { listen 80; location = $x { return 200; } } }",
            "http { server { listen 80; location =$x { return 200; } } }",
            "http { server { listen 80; location ^~ $x { return 200; } } }",
            "http { server { listen 80; location ~\\.php$ { return 403; } } }",
            "http { map $uri $m { default 0; location $uri; } server { listen 80; } }",
        ] {
            parse(src).unwrap_or_else(|e| panic!("{src}: {e}"));
        }
    }

    #[test]
    fn access_restrictions_ruxen_cant_enforce_are_rejected() {
        // `limit_except` and `internal` are enforced now (phase::process).
        let cfg =
            parse("http { server { listen 80; location /a/ { internal; return 200; } } }").unwrap();
        assert!(cfg.servers[0].locations[0].internal);
        let tls = |directive: &str| {
            format!(
                "http {{ {directive} server {{ listen 443 ssl; ssl_certificate c.pem; \
                 ssl_certificate_key k.pem; {directive} }} }}"
            )
        };
        // ssl_verify_client is enforced now (client_verify, #113), with
        // every level's settings.
        let cfg = parse(&tls("ssl_verify_client on; ssl_verify_depth 2;")).unwrap();
        let verify = &cfg.servers[0].ssl.client_verify;
        assert_eq!(verify.mode, Some(VerifyClient::On));
        assert_eq!(verify.depth, Some(2));
        // ssl_reject_handshake is enforced now (tls_stream::accept_or_reject).
        let cfg = parse(&tls("ssl_reject_handshake on;")).unwrap();
        assert_eq!(cfg.servers[0].ssl.reject_handshake, Some(true));
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
        for mode in ["off", "optional", "optional_no_ca"] {
            let cfg = parse(&tls(&format!("ssl_verify_client {mode};"))).unwrap();
            assert!(cfg.warnings.is_empty(), "{:?}", cfg.warnings);
        }
        assert!(parse(&tls("ssl_verify_client maybe;")).is_err());
        parse(&tls("ssl_reject_handshake off;")).unwrap();
        parse(&tls("ssl_client_certificate ca.pem;")).unwrap();
        // proxy_cookie_flags (#40): at every level; `off` stands alone.
        let cookie_flags = |directive: &str| {
            [
                format!("http {{ {directive} server {{ listen 80; }} }}"),
                format!("http {{ server {{ listen 80; {directive} }} }}"),
                format!(
                    "http {{ server {{ listen 80; location / {{ \
                     proxy_pass http://127.0.0.1:8081; {directive} }} }} }}"
                ),
            ]
        };
        for src in cookie_flags("proxy_cookie_flags ~ secure httponly samesite=strict;") {
            parse(&src).unwrap();
        }
        for src in cookie_flags("proxy_cookie_flags off;") {
            parse(&src).unwrap();
        }
        parse("http { server { listen 80; proxy_cookie_flags sid secure; } }").unwrap();
        // A cookie named `off`, as nginx reads it.
        parse("http { server { listen 80; proxy_cookie_flags off secure; } }").unwrap();
        assert!(parse("http { server { listen 80; proxy_cookie_flags; } }").is_err());
        assert!(
            parse("http { server { listen 80; proxy_cookie_flags a secure httponly samesite=lax nosamesite; } }")
                .is_err()
        );
        assert!(
            parse("http { server { listen 80; proxy_cookie_flags off; proxy_cookie_flags a secure; } }")
                .is_err()
        );
    }

    #[test]
    fn server_defaults_at_http_scope_are_inherited() {
        // index, error_page, recursive_error_pages and merge_slashes at http
        // level apply to servers without their own, even when they come
        // after the server block (nginx merges after parsing).
        let cfg = parse(
            r#"
            http {
                index a.html;
                index b.html;
                error_page 404 /404.html;
                error_page 500 502 /50x.html;
                server { listen 80; }
                server {
                    listen 81;
                    index own.html;
                    error_page 403 /403.html;
                    recursive_error_pages off;
                    merge_slashes on;
                }
                recursive_error_pages on;
                merge_slashes off;
            }
            "#,
        )
        .unwrap();
        let (inherits, own) = (&cfg.servers[0], &cfg.servers[1]);
        assert_eq!(inherits.index.as_ref().map(Vec::len), Some(2));
        let statuses =
            |s: &Server| -> Vec<u16> { s.error_pages.iter().flatten().map(|e| e.status).collect() };
        assert_eq!(statuses(inherits), [404, 500, 502]);
        assert_eq!(inherits.recursive_error_pages, Some(true));
        assert_eq!(inherits.merge_slashes, Some(false));
        // A level with its own list replaces the inherited one.
        assert_eq!(own.index.as_ref().map(Vec::len), Some(1));
        assert_eq!(statuses(own), [403]);
        assert_eq!(own.recursive_error_pages, Some(false));
        assert_eq!(own.merge_slashes, Some(true));
        // Unset everywhere: nginx's defaults are applied at prepare time.
        let cfg = parse("http { server { listen 80; } }").unwrap();
        assert_eq!(cfg.servers[0].index, None);
        assert_eq!(cfg.servers[0].merge_slashes, None);
    }

    #[test]
    fn repeated_index_directives_append() {
        let cfg = parse(
            "http { server { listen 80; index a.html; index b.html c.html; \
             location / { index x.html; index y.html; } } }",
        )
        .unwrap();
        assert_eq!(cfg.servers[0].index.as_ref().map(Vec::len), Some(3));
        assert_eq!(
            cfg.servers[0].locations[0].index.as_ref().map(Vec::len),
            Some(2)
        );
        assert!(parse("http { index; server { listen 80; } }").is_err());
        assert!(parse("http { merge_slashes maybe; server { listen 80; } }").is_err());
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
        // `ssl_ciphers` is applied (tls_ciphers): no warning.
        assert_eq!(tls_warnings.len(), 1, "{:?}", cfg.warnings);
        assert!(tls_warnings[0].starts_with("\"ssl_ecdh_curve\" is not supported yet"));
    }

    #[test]
    fn etag_parses_and_inherits() {
        let cfg = parse(
            "http { etag off;
                    server { listen 80; location / { } location /x { etag on; } } }",
        )
        .unwrap();
        assert_eq!(cfg.etag, Some(false));
        assert_eq!(cfg.servers[0].etag, None);
        assert_eq!(cfg.servers[0].locations[1].etag, Some(true));
        assert!(parse("http { etag maybe; }").is_err());
        assert!(parse("http { etag on; etag off; }").is_err());
    }

    #[test]
    fn if_modified_since_parses_and_inherits() {
        let cfg = parse(
            "http { if_modified_since before;
                    server { listen 80; location / { } location /x { if_modified_since off; } }
                    server { listen 81; if_modified_since exact; location / { } } }",
        )
        .unwrap();
        assert_eq!(cfg.if_modified_since, Some(IfModifiedSince::Before));
        assert_eq!(cfg.servers[0].if_modified_since, None);
        assert_eq!(
            cfg.servers[0].locations[1].if_modified_since,
            Some(IfModifiedSince::Off)
        );
        assert_eq!(
            cfg.servers[1].if_modified_since,
            Some(IfModifiedSince::Exact)
        );
        assert!(parse("http { if_modified_since sometimes; }").is_err());
        assert!(parse("http { if_modified_since exact; if_modified_since off; }").is_err());
    }

    #[test]
    fn alias_with_one_trailing_slash_warns() {
        let cfg = parse(
            "http { server { listen 80;
                location /a { alias /srv/a/; }
                location /b/ { alias /srv/b; }
                location /c/ { alias /srv/c/; }
                location /d { alias /srv/d; }
            } }",
        )
        .unwrap();
        let warned: Vec<&String> = cfg
            .warnings
            .iter()
            .filter(|w| w.contains("only one of them ends with"))
            .collect();
        assert_eq!(warned.len(), 2, "{:?}", cfg.warnings);
        assert!(warned[0].contains("nginx would map \"/a../x\" to \"/srv/a/../x\""));
        assert!(warned[1].contains("nginx would map \"/b/x\" to \"/srv/bx\""));
    }

    #[test]
    fn client_timeouts_parse_and_inherit() {
        let cfg = parse(
            r#"
            http {
                client_header_timeout 5s;
                send_timeout 7s;
                max_headers 50;
                client_header_buffer_size 2k;
                server { listen 80; client_body_timeout 3s; send_timeout 9s;
                         client_header_buffer_size 512;
                         http2_chunk_size 1; max_headers 0;
                         location / { http2_chunk_size 16k; http2_push_preload on; } }
                server { listen 81; }
                http2_chunk_size 4k;
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
                large_header_buffers: None,
                header_buffer: Some(512),
                h2_chunk_size: Some(1),
                max_headers: Some(0),
                connection_pool_size: None,
            }
        );
        assert_eq!(
            cfg.servers[0].locations[0].client_timeouts,
            ClientTimeouts {
                h2_chunk_size: Some(16384),
                ..ClientTimeouts::default()
            }
        );
        assert_eq!(
            cfg.servers[1].client_timeouts,
            ClientTimeouts {
                header_ms: Some(5_000),
                body_ms: None,
                send_ms: Some(7_000),
                large_header_buffers: None,
                header_buffer: Some(2048),
                h2_chunk_size: Some(4096),
                max_headers: Some(50),
                connection_pool_size: None,
            }
        );
        assert_eq!(
            cfg.warnings,
            ["the \"http2_push_preload\" directive is obsolete, ignored"]
        );
        assert!(matches!(
            parse("http { send_timeout 1s; send_timeout 2s; }"),
            Err(Error::Duplicate("send_timeout"))
        ));
        assert!(parse("http { client_body_timeout soon; }").is_err());
        assert!(parse("http { client_header_buffer_size big; }").is_err());
        assert!(matches!(
            parse("http { client_header_buffer_size 1k; client_header_buffer_size 2k; }"),
            Err(Error::Duplicate("client_header_buffer_size"))
        ));
        assert!(matches!(
            parse("http { server { location / { http2_chunk_size 1; http2_chunk_size 2; } } }"),
            Err(Error::Duplicate("http2_chunk_size"))
        ));
        // Not in an `if` (no NGX_HTTP_LIF_CONF in nginx).
        assert!(
            parse("http { server { location / { if ($uri) { http2_chunk_size 1; } } } }").is_err()
        );
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
            Ok::<_, Error>(cfg.servers[0].locations[0].proxy.redirect.clone())
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
                shared: true,
                shared_zone: Some("shared:SSL:1m".to_string()),
                tickets: Some(false),
                ticket_keys: None,
            }
        );
        assert_eq!(cfg.servers[1].ssl.resumption.cache, Some(false));
        assert_eq!(cfg.servers[1].ssl.resumption.tickets, Some(false));
        assert!(parse("http { ssl_session_cache bogus; }").is_err());
        assert!(parse("http { ssl_session_tickets maybe; }").is_err());
    }

    #[test]
    fn ssl_session_ticket_keys_parse_and_inherit() {
        let cfg = parse(
            "http { ssl_session_ticket_key /k/a.key; ssl_session_ticket_key /k/b.key;
                    ssl_session_cache builtin;
                    server { listen 443 ssl; ssl_certificate c; ssl_certificate_key k; }
                    server { listen 444 ssl; ssl_certificate c; ssl_certificate_key k;
                             ssl_session_ticket_key /k/c.key;
                             ssl_session_cache shared:SSL:1m; } }",
        )
        .unwrap();
        let first = &cfg.servers[0].ssl.resumption;
        assert_eq!(
            first.ticket_keys,
            Some(vec![PathBuf::from("/k/a.key"), PathBuf::from("/k/b.key")])
        );
        assert!(!first.shared);
        // A server's own lines replace the inherited list.
        let second = &cfg.servers[1].ssl.resumption;
        assert_eq!(second.ticket_keys, Some(vec![PathBuf::from("/k/c.key")]));
        assert!(second.shared);
        assert!(parse("http { ssl_session_ticket_key; }").is_err());
    }

    #[test]
    fn user_directive_is_recorded() {
        let cfg = parse("user www-data adm;\nhttp { }").unwrap();
        assert_eq!(
            cfg.runtime.user,
            Some(UserDirective {
                name: "www-data".into(),
                group: Some("adm".into()),
            })
        );
        let cfg = parse("user www-data;\nhttp { }").unwrap();
        assert_eq!(cfg.runtime.user.unwrap().group, None);
        assert!(parse("user a b c;\nhttp { }").is_err());
        assert!(parse("user;\nhttp { }").is_err());
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
        // The block's other address is TLS (#553), its own or another
        // server's `listen … ssl`.
        assert!(!warned(
            "http { server { listen 127.0.0.1:80; listen 127.0.0.1:443 ssl; \
             ssl_certificate a.pem; ssl_certificate_key a.key; } }"
        ));
        assert!(!warned(
            "http { server { listen 127.0.0.1:443 ssl; ssl_certificate a.pem; ssl_certificate_key a.key; }
                    server { listen 127.0.0.1:80; listen 127.0.0.1:443; server_name b;
                             ssl_certificate b.pem; ssl_certificate_key b.key; } }"
        ));
        // Unix sockets count by path, not by their placeholder address.
        assert!(warned(
            "http { server { listen unix:/tmp/a.sock ssl; ssl_certificate a.pem; ssl_certificate_key a.key; }
                    server { listen unix:/tmp/b.sock; ssl_certificate b.pem; ssl_certificate_key b.key; } }"
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
    fn ssl_prefer_server_ciphers_off_is_kept_without_warning() {
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
        // rustls's `ignore_client_order` is off by default, as nginx's.
        assert!(
            !cfg.warnings
                .iter()
                .any(|w| w.contains("prefer_server_ciphers")),
            "{:?}",
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
    fn ssl_stapling_merges_one_line_at_a_time() {
        let cfg = parse(
            "http { ssl_stapling on; ssl_stapling_responder http://ocsp.example/; \
             ssl_stapling_file /etc/ssl/a.der; \
             server { listen 443 ssl; ssl_certificate c.pem; ssl_certificate_key k.pem; \
             ssl_stapling_verify on; ssl_stapling_file b.der; } \
             server { listen 444 ssl; ssl_certificate c.pem; ssl_certificate_key k.pem; \
             ssl_stapling off; } }",
        )
        .unwrap();
        let a = &cfg.servers[0].ssl.stapling;
        assert_eq!(a.on, Some(true));
        assert_eq!(a.verify, Some(true));
        assert_eq!(a.responder.as_deref(), Some("http://ocsp.example/"));
        let file = a.file.as_deref().unwrap();
        assert!(file.ends_with("b.der"), "{file:?}");
        let b = &cfg.servers[1].ssl.stapling;
        assert_eq!((b.on, b.verify), (Some(false), None));
        assert_eq!(
            b.file.as_deref(),
            Some(std::path::Path::new("/etc/ssl/a.der"))
        );
        for bad in [
            "ssl_stapling on; ssl_stapling off;",
            "ssl_stapling_file a; ssl_stapling_file b;",
            "ssl_stapling_verify maybe;",
            "ssl_stapling_responder;",
        ] {
            assert!(
                parse(&format!("http {{ server {{ listen 80; {bad} }} }}")).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn proxy_set_body_parses_at_every_level() {
        let cfg = parse(
            "http { server { listen 80; proxy_set_body a; \
             location / { proxy_set_body \"b-$arg_x\"; proxy_pass http://127.0.0.1:1; } } }",
        )
        .unwrap();
        assert_eq!(
            cfg.servers[0].proxy.set_body,
            Some(vec![ValuePart::Literal("a".into())])
        );
        assert_eq!(
            cfg.servers[0].locations[0].proxy.set_body,
            Some(vec![
                ValuePart::Literal("b-".into()),
                ValuePart::Var(Variable::Arg("x".into())),
            ])
        );
        // At http scope too, inherited by servers; once per block.
        let cfg = parse("http { proxy_set_body a; server { listen 80; } }").unwrap();
        assert_eq!(
            cfg.servers[0].proxy.set_body,
            Some(vec![ValuePart::Literal("a".into())])
        );
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

    /// One server listing an address twice is refused, as nginx's "a
    /// duplicate listen" (#564); the address is compared parsed, and two
    /// servers on one address are name-based virtual hosts.
    #[test]
    fn a_duplicate_listen_in_one_server_is_refused() {
        for (listens, addr) in [
            (
                "listen 127.0.0.1:81; listen 127.0.0.1:81 ssl;",
                "127.0.0.1:81",
            ),
            ("listen 127.0.0.1:81; listen 127.0.0.1:081;", "127.0.0.1:81"),
            ("listen 81; listen 0.0.0.0:81;", "0.0.0.0:81"),
            ("listen 81; listen *:81;", "0.0.0.0:81"),
            ("listen [::1]:81; listen [::1]:80-82;", "[::1]:81"),
            ("listen unix:/tmp/s; listen unix:/tmp/s;", "unix:/tmp/s"),
        ] {
            let err = parse(&format!(
                "http {{ server {{ {listens} location / {{ return 204; }} }} }}"
            ))
            .unwrap_err()
            .to_string();
            assert!(
                err.starts_with(&format!("a duplicate listen {addr}")),
                "{err}"
            );
        }
        for fine in [
            "server { listen 127.0.0.1:81; listen 127.0.0.2:81; listen [::1]:81; }",
            "server { listen 127.0.0.1:81; } server { listen 127.0.0.1:81; server_name b; }",
        ] {
            parse(&format!("http {{ {fine} }}")).unwrap();
        }
    }

    /// `listen` takes nginx's address forms (#654): `*`, a host without a
    /// port (port 80), a bracketed IPv6 address alone, and a host name,
    /// one listen per address it resolves to.
    #[test]
    fn listen_takes_nginx_address_forms() {
        let addrs = |listen: &str| -> Vec<String> {
            parse(&format!(
                "http {{ server {{ listen {listen}; location / {{ return 204; }} }} }}"
            ))
            .unwrap()
            .servers
            .iter()
            .map(|s| s.listen.addr.to_string())
            .collect()
        };
        assert_eq!(addrs("*:8000"), ["0.0.0.0:8000"]);
        assert_eq!(addrs("*"), ["0.0.0.0:80"]);
        assert_eq!(addrs("127.0.0.1"), ["127.0.0.1:80"]);
        assert_eq!(addrs("[::1]"), ["[::1]:80"]);
        assert_eq!(addrs("*:8000-8001"), ["0.0.0.0:8000", "0.0.0.0:8001"]);
        assert!(addrs("localhost:8000").contains(&"127.0.0.1:8000".to_string()));
        let err = parse("http { server { listen nosuch.invalid:80; location / { return 204; } } }")
            .unwrap_err()
            .to_string();
        assert!(
            err.starts_with("host not found in \"nosuch.invalid:80\" of the \"listen\" directive"),
            "{err}"
        );
        for bad in [":80", "127.0.0.1:", "[::1]x", "[::1", "127.0.0.1:x"] {
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
    fn access_log_buffer_flush_gzip() {
        let parsed = |args: &str| {
            let args: Vec<String> = args.split(' ').map(str::to_string).collect();
            parse_log::parse_access_log_args(&args)
        };
        let Ok(parse_log::ParsedAccessLog::Entry(log)) =
            parsed("/tmp/a.log main buffer=32k flush=5s if=$x")
        else {
            panic!("not parsed");
        };
        assert_eq!(
            (log.buffer, log.flush_ms, log.gzip),
            (Some(32 * 1024), Some(5000), None)
        );
        assert!(log.condition.is_some());
        // `gzip` alone: level 1 and a 64k buffer.
        let Ok(parse_log::ParsedAccessLog::Entry(log)) = parsed("/tmp/a.log main gzip") else {
            panic!("not parsed");
        };
        assert_eq!((log.buffer, log.gzip), (Some(64 * 1024), Some(1)));
        assert!(
            parsed("/tmp/a.log main flush=1s").is_err(),
            "flush without buffer"
        );
        assert!(parsed("/tmp/a.log main gzip=10").is_err());
        assert!(parsed("/tmp/a.log main buffer=0").is_err());
        assert!(parsed("syslog:server=127.0.0.1 main buffer=1k").is_err());
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
        // The second argument is the format (`if=$arg_l`, as nginx reads
        // it), and `test1` is then no parameter.
        assert!(matches!(
            parse(src),
            Err(Error::BadValue {
                what: "access_log parameter",
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

    /// `add_header_inherit` / `add_trailer_inherit` (#598), as nginx's
    /// ngx_http_headers_merge_conf: `merge` puts the level's own list
    /// before the inherited one, `off` inherits nothing, and the mode is
    /// inherited itself, through nested locations (a directive after the
    /// nested block counts), `if` blocks and the http level.
    #[test]
    fn add_header_inherit_merges_as_nginx() {
        let src = r#"
            http {
                add_header X-H http;
                add_trailer X-T http;
                server {
                    listen 80;
                    add_header X-S server;
                    location /def { }
                    location /merge { add_header_inherit merge; add_header X-L merge; }
                    location /off { add_header_inherit off; add_trailer_inherit off; }
                    location /nest {
                        add_header_inherit merge;
                        location /nest/in { add_header X-N in; }
                        location /nest/on { add_header_inherit on; add_header X-N on; }
                        location /nest/deep {
                            add_header X-C c;
                            if ($arg_b) { add_header X-J j; }
                        }
                        add_header X-L nest;
                        if ($arg_a) { add_header X-I a; }
                    }
                }
                server {
                    listen 81;
                    add_header_inherit merge;
                    add_trailer_inherit merge;
                    add_header X-S two;
                    add_trailer X-T two;
                    location / { add_header X-L one; }
                }
            }
        "#;
        let cfg = parse(src).unwrap();
        let names = |list: &Option<Vec<AddHeader>>| -> Vec<String> {
            list.iter().flatten().map(|h| h.name.clone()).collect()
        };
        let one = &cfg.servers[0];
        let loc = |pattern: &str| {
            one.locations
                .iter()
                .find(|l| l.pattern == pattern)
                .unwrap_or_else(|| panic!("{pattern}"))
        };
        assert_eq!(names(&one.add_headers), ["X-S"]);
        assert_eq!(names(&one.add_trailers), ["X-T"]);
        // Nothing of its own: the server's, as `prepare` takes it.
        assert!(loc("/def").add_headers.is_none());
        assert_eq!(names(&loc("/merge").add_headers), ["X-L", "X-S"]);
        assert_eq!(loc("/off").add_headers, Some(Vec::new()));
        assert_eq!(loc("/off").add_trailers, Some(Vec::new()));
        assert_eq!(names(&loc("/nest").add_headers), ["X-L", "X-S"]);
        assert_eq!(names(&loc("/nest/in").add_headers), ["X-N", "X-L", "X-S"]);
        assert_eq!(names(&loc("/nest/on").add_headers), ["X-N"]);
        let RewriteOp::If {
            location: Some(IfLocation::Parsed {
                location: inside, ..
            }),
            ..
        } = &loc("/nest").rewrite_ops[0]
        else {
            panic!("{:?}", loc("/nest").rewrite_ops)
        };
        assert_eq!(names(&inside.add_headers), ["X-I", "X-L", "X-S"]);
        // An `if` in a nested location: each level once.
        let RewriteOp::If {
            location: Some(IfLocation::Parsed { location: deep, .. }),
            ..
        } = &loc("/nest/deep").rewrite_ops[0]
        else {
            panic!("{:?}", loc("/nest/deep").rewrite_ops)
        };
        assert_eq!(names(&deep.add_headers), ["X-J", "X-C", "X-L", "X-S"]);
        let two = &cfg.servers[1];
        assert_eq!(names(&two.add_headers), ["X-S", "X-H"]);
        assert_eq!(names(&two.add_trailers), ["X-T", "X-T"]);
        assert_eq!(names(&two.locations[0].add_headers), ["X-L", "X-S", "X-H"]);
        assert!(parse("http { add_header_inherit maybe; }").is_err());
        assert!(
            parse("http { server { listen 80; add_header_inherit on; add_header_inherit off; } }")
                .is_err()
        );
    }

    #[test]
    fn location_if_blocks_with_settings_are_anonymous_locations() {
        // #137: `proxy_pass`, `add_header` and the like make the block an
        // anonymous location that inherits the enclosing one; rewrite-only
        // blocks stay as they were.
        let src = r#"
            http {
                server {
                    listen 80;
                    location /a {
                        proxy_pass http://127.0.0.1:8081/outer;
                        add_header X-Loc yes;
                        if ($arg_p) { proxy_pass http://127.0.0.1:8081; }
                        if ($arg_h) { add_header X-If yes; }
                        if ($arg_r) { rewrite ^ /b; }
                    }
                }
            }
        "#;
        let cfg = parse(src).unwrap();
        let loc = &cfg.servers[0].locations[0];
        let ifs: Vec<_> = loc
            .rewrite_ops
            .iter()
            .map(|op| match op {
                RewriteOp::If { location, .. } => location.clone(),
                _ => panic!("{op:?}"),
            })
            .collect();
        let Some(IfLocation::Parsed {
            location: own,
            own_handler: true,
            ..
        }) = &ifs[0]
        else {
            panic!("{:?}", ifs[0])
        };
        assert!(matches!(own.handler, Handler::Proxy(_)));
        assert!(own.pattern.starts_with('@'), "{}", own.pattern);
        assert_eq!(own.add_headers.as_ref().unwrap()[0].name, "X-Loc");
        let Some(IfLocation::Parsed {
            location: inherited,
            own_handler: false,
            ..
        }) = &ifs[1]
        else {
            panic!("{:?}", ifs[1])
        };
        assert_eq!(inherited.pattern, "/a");
        assert!(
            matches!(&inherited.handler, Handler::Proxy(p) if format!("{p:?}").contains("/outer"))
        );
        assert_eq!(inherited.add_headers.as_ref().unwrap()[0].name, "X-If");
        assert!(ifs[2].is_none());

        for bad in [
            "http { server { listen 80; location / { if ($a) { proxy_redirect off; } } } }",
            "http { server { listen 80; location / { if ($a) { location /x { } } } } }",
            "http { server { listen 80; location / { if ($a) { proxy_pass http://u/x; } } } }",
        ] {
            let parsed = parse(bad);
            assert!(
                parsed.is_err() || crate::worker::prepare(parsed.unwrap()).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn nested_locations_inherit_the_parents_final_settings() {
        // #106: everything nginx merges from the parent location, also
        // what the parent sets after the nested block; lists as a whole.
        let src = r#"
            http {
                server {
                    listen 80;
                    add_header X-Server s;
                    location /p/ {
                        proxy_set_header X-Up parent;
                        add_header X-Parent yes;
                        location /p/c/ { proxy_pass http://127.0.0.1:8081; }
                        location /p/own/ {
                            add_header X-Own yes;
                            location /p/own/g/ { return 200; }
                        }
                        error_page 404 /nf;
                        proxy_read_timeout 7s;
                        gzip on;
                        keepalive_requests 5;
                    }
                }
            }
        "#;
        let cfg = parse(src).unwrap();
        let loc = |p: &str| {
            cfg.servers[0]
                .locations
                .iter()
                .find(|l| l.pattern == p)
                .unwrap_or_else(|| panic!("{p}"))
        };
        let names = |l: &Location| -> Vec<String> {
            l.add_headers
                .iter()
                .flatten()
                .map(|h| h.name.clone())
                .collect()
        };
        let c = loc("/p/c/");
        assert_eq!(names(c), ["X-Parent"]);
        assert!(c.proxy.set_headers.is_some());
        assert!(c.error_pages.is_some(), "after the nested block");
        assert_eq!(c.proxy.read_timeout_ms, Some(7000));
        assert_eq!(c.gzip.enable, Some(true));
        assert_eq!(c.keepalive_requests, Some(5));
        // A child's own list replaces the parent's, for its children too.
        assert_eq!(names(loc("/p/own/")), ["X-Own"]);
        assert_eq!(names(loc("/p/own/g/")), ["X-Own"]);
        assert_eq!(loc("/p/own/g/").keepalive_requests, Some(5));
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
    fn access_rules_parse_at_every_scope_and_nested_locations_inherit() {
        let src = r#"
            http {
                allow 10.0.0.0/8;
                deny all;
                satisfy any;
                server {
                    listen 80;
                    deny ::1;
                    location /a {
                        allow unix:;
                        satisfy all;
                        location /a/inherit { }
                        location /a/own { deny 192.168.1.1; }
                    }
                }
            }
        "#;
        let cfg = parse(src).unwrap();
        assert_eq!(
            cfg.access.rules,
            [
                AccessRule {
                    deny: false,
                    addr: AccessAddr::V4 {
                        addr: 0x0a00_0000,
                        mask: 0xff00_0000
                    }
                },
                AccessRule {
                    deny: true,
                    addr: AccessAddr::All
                },
            ]
        );
        assert_eq!(cfg.access.satisfy, Some(Satisfy::Any));
        let server = &cfg.servers[0];
        assert_eq!(
            server.access.rules,
            [AccessRule {
                deny: true,
                addr: AccessAddr::V6 {
                    addr: 1,
                    mask: u128::MAX
                }
            }]
        );
        let loc = |pattern: &str| {
            server
                .locations
                .iter()
                .find(|l| l.pattern == pattern)
                .unwrap()
                .access
                .clone()
        };
        let unix = [AccessRule {
            deny: false,
            addr: AccessAddr::Unix,
        }];
        assert_eq!(loc("/a").rules, unix);
        assert_eq!(loc("/a/inherit").rules, unix);
        assert_eq!(loc("/a/inherit").satisfy, Some(Satisfy::All));
        assert_eq!(
            loc("/a/own").rules,
            [AccessRule {
                deny: true,
                addr: AccessAddr::V4 {
                    addr: 0xc0a8_0101,
                    mask: u32::MAX
                }
            }]
        );
    }

    #[test]
    fn tls_and_keepalive_defaults_below_a_server_apply_to_it() {
        let src = r#"
            http {
                server { listen 443 ssl; }
                server {
                    listen 8443 ssl;
                    ssl_certificate own.pem;
                    ssl_certificate_key own.key;
                    ssl_protocols TLSv1.2;
                    keepalive_requests 7;
                }
                ssl_certificate c.pem;
                ssl_certificate_key k.pem;
                ssl_protocols TLSv1.3;
                ssl_session_timeout 10s;
                keepalive_requests 3;
            }
        "#;
        let cfg = parse(src).unwrap();
        let (a, b) = (&cfg.servers[0], &cfg.servers[1]);
        assert_eq!(a.ssl.certs, [PathBuf::from("c.pem")]);
        assert_eq!(
            a.ssl.protocols,
            Some(TlsVersionSet {
                tlsv1_2: false,
                tlsv1_3: true
            })
        );
        assert_eq!(a.ssl.session_timeout_ms, Some(10_000));
        assert_eq!(a.keepalive_requests, Some(3));
        // A server's own lines win.
        assert_eq!(b.ssl.certs, [PathBuf::from("own.pem")]);
        assert_eq!(
            b.ssl.protocols,
            Some(TlsVersionSet {
                tlsv1_2: true,
                tlsv1_3: false
            })
        );
        assert_eq!(b.ssl.session_timeout_ms, Some(10_000));
        assert_eq!(b.keepalive_requests, Some(7));
    }

    #[test]
    fn realip_directives_parse_and_inherit() {
        let src = r#"
            http {
                set_real_ip_from 10.0.0.0/8;
                set_real_ip_from unix:;
                set_real_ip_from localhost;
                real_ip_header X-Forwarded-For;
                server {
                    listen 80;
                    real_ip_recursive on;
                    location /a {
                        real_ip_header CF-Connecting-IP;
                        location /a/b { }
                    }
                }
            }
        "#;
        let cfg = parse(src).unwrap();
        let realip = &cfg.access.realip;
        assert_eq!(
            realip.from[..2],
            [
                AccessAddr::V4 {
                    addr: 0x0a00_0000,
                    mask: 0xff00_0000
                },
                AccessAddr::Unix
            ]
        );
        // localhost resolves to at least one full-length address.
        assert!(realip.from.len() > 2);
        assert_eq!(realip.header, Some(RealIpHeader::XForwardedFor));
        let server = &cfg.servers[0];
        assert_eq!(server.access.realip.recursive, Some(true));
        let child = server
            .locations
            .iter()
            .find(|l| l.pattern == "/a/b")
            .unwrap();
        assert_eq!(
            child.access.realip.header,
            Some(RealIpHeader::Other("cf-connecting-ip".into()))
        );
        for (src, want) in [
            (
                "set_real_ip_from 10.0.0.0/33;",
                "bad value for set_real_ip_from (host not found): 10.0.0.0/33",
            ),
            (
                "real_ip_header a; real_ip_header b;",
                "duplicate directive `real_ip_header`",
            ),
            (
                "real_ip_recursive maybe;",
                "bad value for real_ip_recursive: maybe",
            ),
        ] {
            let conf = format!("http {{ server {{ listen 80; {src} }} }}");
            assert_eq!(parse(&conf).expect_err(src).to_string(), want, "{src}");
        }
    }

    #[test]
    fn limit_except_parses_methods_and_access_directives() {
        let src = r#"
            http {
                server {
                    listen 80;
                    location /a {
                        limit_except get post {
                            allow 127.0.0.1;
                            deny all;
                            auth_basic off;
                        }
                    }
                    location /a/child { }
                }
            }
        "#;
        let cfg = parse(src).unwrap();
        let le = cfg.servers[0].locations[0]
            .limit_except
            .as_ref()
            .expect("limit_except");
        // GET implies HEAD.
        for (method, listed) in [
            ("GET", true),
            ("HEAD", true),
            ("POST", true),
            ("PUT", false),
        ] {
            let bit = limit_except_method_bit(method.as_bytes());
            assert_eq!(le.methods & bit != 0, listed, "{method}");
        }
        assert_eq!(limit_except_method_bit(b"get"), 0);
        assert_eq!(limit_except_method_bit(b"FOO"), 0);
        assert_eq!(le.rules.len(), 2);
        assert_eq!(le.auth_basic, Some(AuthBasic::Off));
        assert!(cfg.servers[0].locations[1].limit_except.is_none());
    }

    #[test]
    fn access_directive_errors() {
        for (src, want) in [
            ("allow;", "bad value for allow: "),
            (
                "deny 1.2.3.4 5.6.7.8;",
                "bad value for deny: 1.2.3.4 5.6.7.8",
            ),
            ("satisfy all; satisfy any;", "duplicate directive `satisfy`"),
            (
                "location / { limit_except { } }",
                "missing argument for `limit_except`",
            ),
            (
                "location / { limit_except GET { satisfy any; } }",
                "unknown directive `satisfy` in a limit_except block",
            ),
            (
                "location / { limit_except GET { location /x { } } }",
                "unknown directive `location` in a limit_except block",
            ),
            (
                "limit_except GET { }",
                "unknown directive `limit_except` in a server block",
            ),
        ] {
            let conf = format!("http {{ server {{ listen 80; {src} }} }}");
            let err = parse(&conf).expect_err(src).to_string();
            assert_eq!(err, want, "{src}");
        }
    }

    #[test]
    fn cidr_with_host_bits_warns() {
        let cfg = parse("http { allow 10.1.2.3/8; server { listen 80; } }").unwrap();
        assert_eq!(
            cfg.warnings,
            ["low address bits of 10.1.2.3/8 are meaningless"]
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

    /// `keepalive_min_timeout` (#601): http, server and location.
    #[test]
    fn keepalive_min_timeout_parses_and_inherits() {
        let src = r#"
            http {
                keepalive_min_timeout 2s;
                server {
                    listen 80;
                    location / { return 200 "ok"; }
                    location = /loc {
                        keepalive_min_timeout 100ms;
                        return 200 "l";
                    }
                }
                server { listen 81; keepalive_min_timeout 0; }
            }
        "#;
        let cfg = parse(src).unwrap();
        let server = &cfg.servers[0];
        assert_eq!(server.keepalive_min_timeout_ms, Some(2_000));
        let loc = |pattern: &str| {
            server
                .locations
                .iter()
                .find(|l| l.pattern == pattern)
                .unwrap()
                .keepalive_min_timeout_ms
        };
        // The server's applies to its locations in `resolve_keepalive`.
        assert_eq!(loc("/"), None);
        assert_eq!(loc("/loc"), Some(100));
        assert_eq!(cfg.servers[1].keepalive_min_timeout_ms, Some(0));
        for bad in [
            "http { keepalive_min_timeout 1s; keepalive_min_timeout 2s; }",
            "http { keepalive_min_timeout; }",
            "http { keepalive_min_timeout 1s 2s; }",
            "http { keepalive_min_timeout x; }",
            "keepalive_min_timeout 1s; http { }",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
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
    fn try_files_takes_variables_in_probes_and_fallback() {
        let src = r#"
            http { server { listen 80; location / {
                root /var/www;
                try_files $uri $uri.html /cache$uri/ /index.php?q=$uri&$args;
            } } }
        "#;
        let cfg = parse(src).unwrap();
        let tf = cfg.servers[0].locations[0].try_files.as_ref().unwrap();
        assert!(matches!(tf.probes[0], TryFilesProbe::Uri));
        assert!(matches!(
            tf.probes[1],
            TryFilesProbe::Template { dir: false, .. }
        ));
        assert!(matches!(
            tf.probes[2],
            TryFilesProbe::Template { dir: true, .. }
        ));
        assert!(matches!(tf.fallback, TryFilesFallback::UriTemplate(_)));
    }

    /// `open_log_file_cache` per scope (#371): `off` at a server, a
    /// nested location takes its parent's, defaults as nginx's.
    #[test]
    fn open_log_file_cache_is_parsed_per_scope() {
        let cfg = parse(
            r#"
            http {
                open_log_file_cache max=3 min_uses=2;
                server { listen 80; open_log_file_cache off;
                    location /a { open_log_file_cache max=5 inactive=1m valid=10s;
                        location /a/b { }
                    }
                    location /c { }
                }
            }
        "#,
        )
        .unwrap();
        let http = cfg;
        let top = http.open_log_file_cache.unwrap();
        assert_eq!(
            (top.max, top.min_uses, top.inactive_ms, top.valid_ms),
            (3, 2, 10_000, 60_000)
        );
        let server = &http.servers[0];
        assert_eq!(server.open_log_file_cache, Some(None));
        let a = server.locations.iter().find(|l| l.pattern == "/a").unwrap();
        let own = a.open_log_file_cache.unwrap().unwrap();
        assert_eq!(
            (own.max, own.inactive_ms, own.valid_ms),
            (5, 60_000, 10_000)
        );
        let nested = server
            .locations
            .iter()
            .find(|l| l.pattern == "/a/b")
            .unwrap();
        assert_eq!(nested.open_log_file_cache, Some(Some(own)));
        let c = server.locations.iter().find(|l| l.pattern == "/c").unwrap();
        assert_eq!(c.open_log_file_cache, None);
        for bad in [
            "open_log_file_cache max=1; open_log_file_cache max=2;",
            "location / { if ($a) { open_log_file_cache max=1; } }",
        ] {
            let src = format!("http {{ server {{ listen 80; {bad} }} }}");
            assert!(parse(&src).is_err(), "{bad}");
        }
    }

    #[test]
    fn module_temp_paths_are_checked_no_ops_and_open_log_file_cache_is_checked() {
        let src = r#"
            http {
                fastcgi_temp_path /var/cache/nginx/fastcgi_temp 1 2;
                uwsgi_temp_path /tmp/u;
                scgi_temp_path /tmp/s 1;
                proxy_temp_path /tmp/p 1 2;
                open_log_file_cache max=1000 inactive=20s valid=1m min_uses=2;
                server { listen 80; open_log_file_cache off;
                    location / { fastcgi_temp_path /tmp/f; return 200; }
                }
            }
        "#;
        parse(src).unwrap();
        for bad in [
            "fastcgi_temp_path;",
            "uwsgi_temp_path /tmp/u 3 0;",
            "scgi_temp_path /tmp/s 1 2 3 4;",
            "proxy_temp_path /tmp/p x;",
            "open_log_file_cache;",
            "open_log_file_cache inactive=20s;",
            "open_log_file_cache max=10 inactive=20x;",
            "open_log_file_cache max=10 valid=500ms;",
            "open_log_file_cache max=+10;",
            "open_log_file_cache max=10 maxx=1;",
            "fastcgi_pass 127.0.0.1:9000;",
        ] {
            let src = format!("http {{ {bad} server {{ listen 80; }} }}");
            assert!(parse(&src).is_err(), "{bad}");
        }
    }

    #[test]
    fn proxy_cache_directives_parse_at_every_level() {
        let src = r#"
            http {
                proxy_cache_path /tmp/c levels=1:2 keys_zone=one:1m inactive=1h max_size=1g
                                 use_temp_path=off loader_files=10 manager_sleep=50ms;
                proxy_cache_bypass $http_upgrade; proxy_cache_valid 1m;
                server { listen 80; proxy_no_cache $arg_x $arg_y; proxy_cache one;
                    location / { proxy_pass http://127.0.0.1:8080; proxy_cache_bypass $http_upgrade;
                        proxy_cache_valid 200 301 10m; proxy_cache_valid any 1y;
                        proxy_cache_key $uri; proxy_cache_methods GET POST;
                        proxy_cache_min_uses 2; proxy_cache_convert_head off;
                        proxy_cache_revalidate on;
                        proxy_cache_use_stale error timeout updating http_500 http_429;
                        proxy_cache_background_update on; proxy_cache_lock on;
                        proxy_cache_lock_timeout 200ms; proxy_cache_lock_age 1s;
                        proxy_ignore_headers Expires; proxy_ignore_headers Vary; }
                    location /v { proxy_pass http://127.0.0.1:8080; proxy_cache $arg_c; }
                    location /off { proxy_pass http://127.0.0.1:8080; proxy_cache off; }
            } }
        "#;
        let cfg = parse(src).unwrap();
        let path = &cfg.proxy_cache_paths[0];
        assert_eq!(path.zone, "one");
        assert_eq!(path.levels, [1, 2, 0]);
        assert_eq!(path.inactive_secs, 3600);
        assert_eq!(path.max_size, Some(1 << 30));
        assert_eq!(path.min_free, None);
        for bad in [
            "proxy_cache_path /tmp/c;",
            "proxy_cache_path /tmp/c keys_zone=one;",
            "proxy_cache_path /tmp/c keys_zone=one:1k;",
            "proxy_cache_path /tmp/c keys_zone=one:1m levels=3;",
            "proxy_cache_path /tmp/c keys_zone=one:1m levels=1:2:2:2;",
            "proxy_cache_path /tmp/c keys_zone=one:1m use_temp_path=maybe;",
            "proxy_cache_path /tmp/c keys_zone=one:1m bogus=1;",
            "proxy_cache_path /a keys_zone=one:1m; proxy_cache_path /b keys_zone=one:1m;",
            "proxy_cache_valid 999 1m;",
            "proxy_cache_valid 200 soon;",
            "proxy_cache_methods PUT;",
            "proxy_cache_use_stale http_418;",
            "proxy_cache_use_stale bogus;",
            "proxy_cache_lock maybe;",
            "proxy_cache one; proxy_cache two;",
        ] {
            let src = format!("http {{ {bad} server {{ listen 80; }} }}");
            assert!(parse(&src).is_err(), "{bad}");
        }
    }

    /// ngx_http_core_pool_size and ngx_http_core_merge_srv_conf: the pool
    /// sizes' bounds, and the large header buffers against the connection
    /// pool per server.
    #[test]
    fn pool_sizes_and_large_header_buffers_as_nginx() {
        const SMALL: &str = "the \"large_client_header_buffers\" size must be equal to or greater than \"connection_pool_size\"";
        let err = |src: &str| parse(src).unwrap_err().to_string();
        for (src, msg) in [
            (
                "http { large_client_header_buffers 2 256; server { listen 80; } }",
                SMALL,
            ),
            (
                "http { connection_pool_size 1k; server { listen 80; } server { listen 81; large_client_header_buffers 2 1000; } }",
                SMALL,
            ),
            (
                "http { server { listen 80; connection_pool_size 16k; } }",
                SMALL,
            ),
            (
                "http { connection_pool_size 96; }",
                "the pool size must be no less than 112",
            ),
            (
                "http { request_pool_size 4097; }",
                "the pool size must be a multiple of 16",
            ),
            (
                "http { server { connection_pool_size 120; } }",
                "the pool size must be a multiple of 16",
            ),
        ] {
            assert!(err(src).starts_with(msg), "{src}: {}", err(src));
        }
        assert!(
            err("http { connection_pool_size 1k; connection_pool_size 1k; }").contains("duplicate")
        );
        for ok in [
            "http { large_client_header_buffers 2 512; server { listen 80; } }",
            "http { connection_pool_size 1k; large_client_header_buffers 2 1k; server { listen 80; } }",
            "http { connection_pool_size 112; request_pool_size 4k; server { listen 80; connection_pool_size 8k; } }",
        ] {
            parse(ok).unwrap();
        }
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
    fn return_url_alone_is_a_302() {
        // #16, ngx_http_rewrite_return: one argument that starts as a URL.
        for (arg, parts) in [
            ("http://example.com/", 1),
            ("https://example.com$uri", 2),
            ("$scheme://$host$uri", 4),
        ] {
            let src = format!("http {{ server {{ listen 80; location / {{ return {arg}; }} }} }}");
            let cfg = parse(&src).unwrap();
            match &cfg.servers[0].locations[0].handler {
                Handler::Return { status, body } => {
                    assert_eq!(*status, 302, "{arg}");
                    assert_eq!(body.len(), parts, "{arg}: {body:?}");
                }
                other => panic!("{arg}: {other:?}"),
            }
        }
        // Anything else that isn't a number is still an invalid code, and
        // a URL needs to stand alone.
        for bad in ["return foo;", "return /local;", "return http://a b;"] {
            let src = format!("http {{ server {{ listen 80; location / {{ {bad} }} }} }}");
            assert!(
                matches!(
                    parse(&src),
                    Err(Error::BadValue {
                        what: "return status",
                        ..
                    })
                ),
                "{bad}"
            );
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

    #[test]
    fn thread_pools_and_aio_threads_as_nginx() {
        let cfg = parse(
            "thread_pool big threads=4 max_queue=10; \
             http { aio threads=big; server { aio off; location / { aio threads; } \
             location /n { location /n/x { } } } } thread_pool late foo=1 threads=2;",
        )
        .unwrap();
        let pools: Vec<(&str, usize, usize)> = cfg
            .runtime
            .thread_pools
            .iter()
            .map(|p| (p.name.as_str(), p.threads, p.max_queue))
            .collect();
        // `default` is added for the bare `aio threads`.
        assert_eq!(
            pools,
            [("big", 4, 10), ("late", 2, 65536), ("default", 32, 65536)]
        );
        assert_eq!(cfg.aio, Some(Aio::Threads("big".into())));
        let server = &cfg.servers[0];
        assert_eq!(server.aio, Some(Aio::Off));
        assert_eq!(
            server.locations[0].aio,
            Some(Aio::Threads("default".into()))
        );
        assert_eq!(server.locations[1].aio, None);

        let err = |src: &str| parse(src).unwrap_err().to_string();
        assert_eq!(
            err("http { server { aio threads=nope; } }"),
            "unknown thread pool \"nope\""
        );
        assert_eq!(
            err("thread_pool a threads=1; thread_pool a threads=2; http { }"),
            "duplicate thread pool \"a\""
        );
        assert_eq!(
            err("thread_pool a max_queue=1; http { }"),
            "\"thread_pool\" must have \"threads\" parameter"
        );
        assert_eq!(
            err("thread_pool a threads=0; http { }"),
            "invalid threads value \"threads=0\""
        );
        assert!(err("http { aio threads=$x; }").contains("variable"));
        assert!(err("http { aio maybe; }").contains("aio"));
        assert!(err("http { aio on; aio off; }").contains("duplicate"));
        // Not a main-context directive.
        assert!(matches!(
            parse("aio threads; http { }"),
            Err(Error::UnknownDirective { .. })
        ));
    }
}
