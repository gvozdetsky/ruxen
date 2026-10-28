//! Configuration → `&'static PreparedHttp` build pass, at startup and on
//! each reload. Its allocations go through `crate::arena::leak`, so `main`
//! can free a configuration once its workers are gone (#343). What a later
//! configuration keeps (zone state, cache zones, the buffered access-log
//! registry) is leaked with plain `Box::leak` instead. Nothing here runs
//! after the workers spawn.

#![allow(unused_imports)]

use std::cell::{Cell, RefCell};
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::SocketAddr;
use std::os::unix::net::UnixDatagram;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use monoio::RuntimeBuilder;
use monoio::buf::{IoBuf, IoBufMut};
use monoio::fs::File as AsyncFile;
use monoio::io::{AsyncReadRent, AsyncWriteRent, AsyncWriteRentExt};
use monoio::net::{ListenerOpts, TcpListener, TcpStream};

use crate::config::{
    AccessConf, AccessLog, AddHeader, AuthBasic, AutoindexFormat, ErrorLog, ErrorLogLevel,
    ErrorLogSyslogServer, ErrorLogTarget, ErrorPage, ErrorPageAction, ExpiresDirective,
    FileTestKind, Handler, HttpConfig, IfGuard, IndexEntry, KeepaliveDisable, KeepaliveTimeout,
    LimitExcept, Location, LogFormatDef, MapBlock, MapExactEntry, MapRegexEntry, MatchMode,
    OpenLogFileCache, PathMapping, ProxyConf, ProxyPass, ProxySetHeader, RealIpHeader,
    RewriteFlag as ConfigRewriteFlag, RewriteOp, RewriteRule, Server, SplitClients, TryFiles,
    TryFilesFallback, TryFilesProbe, ValuePart, Variable,
};
use crate::http::{self, Method, Parse, ParseState, READ_BUF};
use crate::phase::{self, Response};
use crate::{autoindex, file, fs_resolve, uri};

use super::*;

/// nginx's `(<errno>: <strerror>)` rendering of a failed syscall, e.g.
/// `2: No such file or directory`, for `[emerg] open() "…" failed (…)`.
pub(crate) fn errno_text(err: &std::io::Error) -> String {
    let text = err.to_string();
    match err.raw_os_error() {
        Some(code) => {
            let reason = text
                .strip_suffix(&format!(" (os error {code})"))
                .unwrap_or(&text);
            format!("{code}: {reason}")
        }
        None => text,
    }
}

/// Lower the parsed config into the leaked `PreparedHttp` the workers share.
///
/// This is also where config meets the filesystem — root directories,
/// certificates, log files — so it fails on things the parser can't see.
/// `-t` runs it too, like `nginx -t` runs module init. The error is the
/// message `main` prints after `[emerg]`.
pub fn prepare(cfg: HttpConfig) -> Result<&'static PreparedHttp, String> {
    crate::tls_certs::forget_files();
    STAPLED_KEYS.with(|k| k.borrow_mut().clear());
    ERROR_LOG_FILES.with(|f| f.borrow_mut().clear());
    let inheritable = cfg.runtime.ssl_object_cache_inheritable.unwrap_or(true);
    let prepared = prepare_http(cfg);
    // Whatever `prepare_http` left: `finish` took it unless it failed.
    super::metrics::begin(false);
    if prepared.is_ok() {
        crate::tls_certs::keep_files(inheritable);
    }
    crate::tls_certs::forget_files();
    STAPLED_KEYS.with(|k| k.borrow_mut().clear());
    ERROR_LOG_FILES.with(|f| f.borrow_mut().clear());
    prepared
}

thread_local! {
    /// The `error_log` files of the configuration being prepared, by path:
    /// each opened once (#648).
    static ERROR_LOG_FILES: std::cell::RefCell<
        std::collections::HashMap<std::path::PathBuf, &'static PreparedErrorLogFile>,
    > = std::cell::RefCell::new(std::collections::HashMap::new());
    /// The `[warn]` lines of the last `prepare` on this thread (nginx's
    /// warnings while it initialises modules), for `take_prepare_warnings`.
    static PREPARE_WARNINGS: std::cell::RefCell<Vec<String>> =
        const { std::cell::RefCell::new(Vec::new()) };
    /// The stapling certificates of the configuration being prepared, by
    /// what makes them (#141): a server on two addresses (`listen 443
    /// ssl; listen [::]:443 ssl;`) staples once, as nginx's one SSL_CTX
    /// per server does, and warns once.
    static STAPLED_KEYS: std::cell::RefCell<Vec<(StapledKeyId, crate::tls_certs::ServerKey)>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// The `[warn]` lines `prepare` had, taken: the caller logs them.
pub fn take_prepare_warnings() -> Vec<String> {
    PREPARE_WARNINGS.with(|w| std::mem::take(&mut *w.borrow_mut()))
}

fn prepare_warning(line: String) {
    PREPARE_WARNINGS.with(|w| w.borrow_mut().push(line));
}

/// A warning about a server, which the server's every address would repeat.
fn prepare_warning_once(line: String) {
    PREPARE_WARNINGS.with(|w| {
        let mut w = w.borrow_mut();
        if !w.contains(&line) {
            w.push(line);
        }
    });
}

fn prepare_http(cfg: HttpConfig) -> Result<&'static PreparedHttp, String> {
    let HttpConfig {
        limit_req_zones,
        limit_conn_zones,
        uses_request_body_file,
        uses_request_body,
        uses_request_id,
        uses_stderr_log,
        uses_stats,
        uses_metrics,
        runtime,
        error_logs: http_error_logs,
        log_formats,
        access_logs,
        open_log_file_cache,
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
        client_body_temp_path,
        sendfile,
        http2,
        http2_conf,
        disable_symlinks,
        limit_rate,
        limit_rate_after,
        post_action,
        expires: http_expires,
        ignore_invalid_headers,
        underscores_in_headers,
        upstreams,
        proxy_cache_paths,
        servers,
        warnings: _,
        dump_files: _,
        conf_prefix,
    } = cfg;

    super::metrics::begin(uses_metrics);
    // No `server` blocks is valid, as in nginx: workers start with nothing
    // to listen on and idle until shutdown.
    // Group server blocks by listen address while preserving declaration
    // order both across listen buckets and within each bucket.
    // A `unix:` socket is its own address (#263).
    type ListenKey = (SocketAddr, Option<std::path::PathBuf>);
    let mut grouped: Vec<(ListenKey, Vec<Server>)> = Vec::new();
    for server in servers {
        let key = (server.listen.addr, server.listen.unix.clone());
        if let Some((_, bucket)) = grouped.iter_mut().find(|(k, _)| *k == key) {
            bucket.push(server);
        } else {
            grouped.push((key, vec![server]));
        }
    }

    // Inheritance for server_tokens: location → server → http → On.
    // Resolve the http-scope baseline once here; per-server resolution
    // reads it via the closure in prepare_server.
    let http_tokens = server_tokens.unwrap_or(crate::config::ServerTokens::On);
    let http_autoindex = autoindex.unwrap_or(false);
    let http_autoindex_exact_size = autoindex_exact_size.unwrap_or(true);
    let http_autoindex_localtime = autoindex_localtime.unwrap_or(false);
    let http_autoindex_format = autoindex_format.unwrap_or(AutoindexFormat::Html);
    let http_if_modified_since = if_modified_since.unwrap_or(crate::config::IfModifiedSince::Exact);
    let http_etag = etag.unwrap_or(true);
    let http_access = resolve_access(
        access,
        auth_basic,
        auth_basic_user_file,
        auth_delay_ms,
        PreparedAccess::NONE,
    );
    let http_client_max_body_size = client_max_body_size;
    let http_max_ranges = max_ranges;
    let http_client_body_buffer_size = client_body_buffer_size;
    let http_sendfile = sendfile;
    let http_http2 = http2;
    let http_disable_symlinks = disable_symlinks;
    let http_limit_rate =
        PreparedLimitRate::inherit(limit_rate, limit_rate_after, PreparedLimitRate::default());
    let http_post_action = post_action.map(|target| leak_bytes(target.as_bytes()));
    let http_expires = http_expires
        .map(prepare_expires)
        .unwrap_or(PreparedExpires::Off);
    let http_ignore_invalid_headers = ignore_invalid_headers.unwrap_or(true);
    let http_underscores_in_headers = underscores_in_headers.unwrap_or(false);
    // Http-scope fallback Server bytes for the shared error prebuilts.
    // These fire only when no server matched (no per-location tokens
    // available), so the http-scope value is the right default.
    let http_server_bytes = http::server_header_value(http_tokens);

    // Build the union access-log table: every directive across http /
    // server / location scopes gets a unique `file_index`, and the
    // canonical list (returned by `finish` after all servers are
    // prepared) becomes `PreparedHttp::access_logs` for the per-worker fd
    // table.
    // error_log inheritance, as nginx: server ← http ← top level; with
    // none anywhere, lines go to stderr (`write_error_log`).
    let main_error_logs = prepare_error_logs(runtime.error_logs)?;
    let http_error_logs = match http_error_logs {
        Some(list) => prepare_error_logs(list)?,
        None => main_error_logs,
    };
    let mut alp = AccessLogPrep::new(&log_formats);
    alp.http_cache = open_log_file_cache;
    let http_access_logs: &'static [PreparedAccessLog] = alp.prepare_list(&access_logs)?;
    let http_access_logs = alp.with_cache(http_access_logs, open_log_file_cache);
    let prepared_split_clients = prepare_split_clients(split_clients);
    let prepared_maps = prepare_maps(maps);
    prepare_cache_zones(proxy_cache_paths)?;
    prepare_limit_req_zones(limit_req_zones)?;
    prepare_limit_conn_zones(limit_conn_zones)?;
    let prepared_upstreams: std::collections::HashMap<&'static str, &'static PreparedUpstream> =
        prepare_upstreams(upstreams);

    let http_scope = HttpScope {
        tokens: http_tokens,
        access_logs: http_access_logs,
        error_logs: http_error_logs,
        autoindex: http_autoindex,
        autoindex_exact_size: http_autoindex_exact_size,
        autoindex_localtime: http_autoindex_localtime,
        autoindex_format: http_autoindex_format,
        if_modified_since: http_if_modified_since,
        etag: http_etag,
        access: http_access,
        client_max_body_size: http_client_max_body_size,
        max_ranges: http_max_ranges,
        client_body_buffer_size: http_client_body_buffer_size,
        sendfile: http_sendfile,
        disable_symlinks: http_disable_symlinks,
        limit_rate: http_limit_rate,
        post_action: http_post_action,
        expires: http_expires,
        ignore_invalid_headers: http_ignore_invalid_headers,
        underscores_in_headers: http_underscores_in_headers,
    };
    let mut listens: Vec<PreparedListen> = Vec::with_capacity(grouped.len());
    for ((addr, unix), servers_for_addr) in grouped {
        let unix: Option<&'static Path> = unix.map(|p| &*crate::arena::leak(p.into_boxed_path()));
        // Snapshot the TLS-relevant fields up front: prepare_server consumes
        // each `Server`, and we want to feed the SNI resolver in the same
        // declaration order.
        let tls_inputs: Vec<TlsServerInput> = servers_for_addr
            .iter()
            .map(|s| TlsServerInput {
                ssl_listen: s.listen.ssl,
                default_server: s.listen.default_server,
                ssl: s.ssl.clone(),
                server_names: s.server_names.clone(),
                resolver: s.proxy.resolver.clone(),
                resolver_timeout_ms: s.proxy.resolver_timeout_ms,
            })
            .collect();
        let proxy_protocol = servers_for_addr.iter().any(|s| s.listen.proxy_protocol);
        // HTTP/2 (#144): `listen … http2` for the address, `http2 on` per
        // server (server, else http).
        let http2_listen = servers_for_addr.iter().any(|s| s.listen.http2);
        let server_http2: Vec<bool> = servers_for_addr
            .iter()
            .map(|s| http2_listen || s.http2.or(http_http2).unwrap_or(false))
            .collect();
        let http2 = server_http2.iter().any(|&on| on);
        let server_h2: Vec<crate::config::Http2Conf> = servers_for_addr
            .iter()
            .map(|s| s.http2_conf.inherit(&http2_conf))
            .collect();
        // The address's default server: `listen … default_server`, else
        // the first (ngx_http_add_addresses), for plain and TLS alike.
        let default_server = servers_for_addr
            .iter()
            .position(|s| s.listen.default_server)
            .unwrap_or(0);
        // Socket options belong to the address: one server may set them
        // (nginx's "duplicate listen options").
        let mut with_options = servers_for_addr
            .iter()
            .map(|s| &s.listen)
            .filter(|l| l.has_socket_options());
        let options = with_options.next();
        if with_options.next().is_some() {
            return Err(format!("duplicate listen options for {addr}"));
        }
        let socket = ListenSocket::from_listen(options);
        let mut servers: Vec<PreparedServer> = servers_for_addr
            .into_iter()
            .map(|s| prepare_server(s, &http_scope, &prepared_upstreams, &mut alp))
            .collect::<Result<_, _>>()?;
        for ((server, on), h2) in servers.iter_mut().zip(&server_http2).zip(&server_h2) {
            server.http2 = *on;
            server.h2 = *h2;
        }
        let h2_by_sni = server_http2.iter().any(|&on| on != http2);
        let tls = match build_listen_tls(addr, &tls_inputs, http2, h2_by_sni)? {
            Some((acceptor, contexts)) => {
                for ((server, context), input) in servers.iter_mut().zip(contexts).zip(&tls_inputs)
                {
                    server.tls_context = context;
                    server.client_verify = input
                        .ssl
                        .client_verify
                        .mode
                        .unwrap_or(crate::config::VerifyClient::Off);
                }
                Some(acceptor)
            }
            None => None,
        };
        let tls_contexts_by_sni = servers.iter().any(|s| s.tls_context.is_some());
        let client_verify = servers
            .iter()
            .any(|s| s.client_verify != crate::config::VerifyClient::Off);
        let h2_by_sni = h2_by_sni && tls.is_some();
        let reject_handshake = (tls.is_some()
            && tls_inputs
                .iter()
                .any(|i| i.ssl.reject_handshake == Some(true)))
        .then(|| {
            let flags = tls_inputs
                .iter()
                .map(|i| i.ssl.reject_handshake == Some(true))
                .collect();
            let default = tls_inputs
                .iter()
                .position(|i| i.default_server)
                .unwrap_or(0);
            (flags, default)
        });
        let mut name_index: Vec<(u32, u32)> = Vec::new();
        for (si, server) in servers.iter().enumerate() {
            for ni in 0..server.regex_names.len() {
                name_index.push((si as u32, ni as u32));
            }
        }
        let regex_name_set = first_match_set(
            servers
                .iter()
                .flat_map(|s| s.regex_names.iter().map(|n| n.set_pattern.as_str())),
        )
        .map(|set| (set, name_index));
        let mut exact_names = super::prepared::NameMap::default();
        for (si, server) in servers.iter().enumerate() {
            for &name in &server.exact_names {
                // The first server with a name keeps it (nginx warns about
                // the conflict and does the same).
                exact_names.entry(name).or_insert(si as u32);
            }
        }
        listens.push(PreparedListen {
            exact_names,
            regex_name_set,
            addr,
            unix,
            // nginx shows a unix socket's address as `unix:` (the client
            // side has no path).
            addr_text: if unix.is_some() {
                b"unix:"
            } else if addr.ip().is_unspecified() {
                b""
            } else {
                crate::arena::leak(addr.ip().to_string().into_bytes().into_boxed_slice())
            },
            servers,
            default_server,
            tls,
            reject_handshake,
            proxy_protocol,
            http2_listen,
            h2_plain: server_http2.get(default_server).copied().unwrap_or(false),
            h2_by_sni,
            tls_contexts_by_sni,
            client_verify,
            tls_default_server: default_server,
            socket,
        });
    }

    let canonical_access_logs = alp.finish();

    let max_request_body = largest_body_limit(&listens);
    RESOLVERS.with(|r| r.borrow_mut().clear());
    Ok(crate::arena::leak(Box::new(PreparedHttp {
        worker_connections: runtime.worker_connections.unwrap_or(512),
        error_logs: main_error_logs,
        max_request_body,
        uses_request_body_file,
        uses_request_body,
        uses_request_id,
        uses_stderr_log,
        stats: uses_stats,
        metrics: super::metrics::finish(),
        body_temp: BodyTempDir::new(client_body_temp_path),
        listens,
        access_logs: canonical_access_logs,
        split_clients: prepared_split_clients,
        maps: prepared_maps,
        not_found: Prebuilt::leak_error(404, "Not Found\n", http_server_bytes),
        bad_request: Prebuilt::leak_error(400, "Bad Request\n", http_server_bytes),
        version_not_supported: Prebuilt::leak_error(
            505,
            "HTTP Version Not Supported\n",
            http_server_bytes,
        ),
        plain_http: Prebuilt::leak_error(
            497,
            "The plain HTTP request was sent to HTTPS port\n",
            http_server_bytes,
        ),
        uri_too_large: Prebuilt::leak_error(414, "Request-URI Too Large\n", http_server_bytes),
        header_too_large: Prebuilt::leak_error(
            494,
            "Request Header Or Cookie Too Large\n",
            http_server_bytes,
        ),
        cert_error: Prebuilt::leak_error(495, "The SSL certificate error\n", http_server_bytes),
        no_cert: Prebuilt::leak_error(
            496,
            "No required SSL certificate was sent\n",
            http_server_bytes,
        ),
        misdirected: Prebuilt::leak_error(421, "Misdirected Request\n", http_server_bytes),
        not_implemented: Prebuilt::leak_error(501, "Not Implemented\n", http_server_bytes),
        forbidden: Prebuilt::leak_error(403, "Forbidden\n", http_server_bytes),
        bad_gateway: Prebuilt::leak_error(502, "Bad Gateway\n", http_server_bytes),
        gateway_timeout: Prebuilt::leak_error(504, "Gateway Timeout\n", http_server_bytes),
        internal_error: Prebuilt::leak_error(500, "Internal Server Error\n", http_server_bytes),
        upstreams: prepared_upstreams,
        cache_zones: CACHE_ZONES
            .with(|z| &*crate::arena::leak(z.borrow().clone().into_boxed_slice())),
        implicit_upstreams: IMPLICIT_UPSTREAMS
            .with(|i| crate::arena::leak(i.take().into_boxed_slice())),
        root_fds: ROOT_FDS.with(|fds| crate::arena::leak(fds.take().into_boxed_slice())),
        conf_prefix: conf_prefix.map(leak_path_buf),
        shutdown_timeout: runtime
            .worker_shutdown_timeout_ms
            .filter(|&ms| ms != 0)
            .map(Duration::from_millis),
    })))
}

/// The most any location accepts: `None` is nginx's default 1m, `0` means
/// unlimited.
fn largest_body_limit(listens: &[PreparedListen]) -> u64 {
    let limit = |l: Option<u64>| match l.unwrap_or(DEFAULT_CLIENT_MAX_BODY_SIZE) {
        0 => u64::MAX,
        n => n,
    };
    let mut max = DEFAULT_CLIENT_MAX_BODY_SIZE;
    for server in listens.iter().flat_map(|l| &l.servers) {
        let plain = server
            .exact_locations
            .iter()
            .chain(&server.prefix_locations)
            .chain(&server.named_locations)
            .chain(&server.server_default)
            .map(|l| l.client_max_body_size);
        let regex = server
            .regex_locations
            .iter()
            .map(|l| l.client_max_body_size);
        for l in plain.chain(regex) {
            max = max.max(limit(l));
        }
    }
    max
}

/// TLS-relevant snapshot for one `server {}` block, captured before
/// `prepare_server` consumes the original.
pub(crate) struct TlsServerInput {
    ssl_listen: bool,
    default_server: bool,
    ssl: crate::config::ServerSsl,
    server_names: Vec<crate::config::ServerNameSpec>,
    /// The server's `resolver` and `resolver_timeout`, for OCSP stapling.
    resolver: Option<crate::config::ResolverConf>,
    resolver_timeout_ms: Option<u64>,
}

/// A listen address's TLS acceptor, with each server's client-certificate
/// context (`tls_context`).
type ListenTls = (Arc<crate::tls::TlsAcceptor>, Vec<Option<u16>>);

/// Build the per-listen `TlsAcceptor`, or `None` when no server on this
/// address declared `listen … ssl;`. The parser already validated that
/// ssl listens carry `ssl_certificate`/`ssl_certificate_key` pairs, so a
/// load failure here is an unreadable file, a malformed PEM or a key that
/// doesn't match its certificate — a startup error, as in nginx.
/// With it, each server's client-certificate context (`tls_context`).
pub(crate) fn build_listen_tls(
    addr: SocketAddr,
    inputs: &[TlsServerInput],
    http2: bool,
    h2_by_sni: bool,
) -> Result<Option<ListenTls>, String> {
    use crate::config::ServerNameSpec;

    // As in nginx, `ssl` belongs to the listening socket: one `listen …
    // ssl` makes every server on the address TLS (ngx_http.c:
    // `ssl = lsopt->ssl || addr[i].opt.ssl`).
    if !inputs.iter().any(|i| i.ssl_listen) {
        // nginx still loads the certificates of every server that has
        // them (ngx_http_ssl_merge_srv_conf), so a bad key or password is
        // an [emerg] here too (#139).
        for input in inputs {
            let passwords = match &input.ssl.password_file {
                Some(path) if !input.ssl.certs.is_empty() => crate::tls_certs::password_file(path)?,
                _ => Arc::from(Vec::new()),
            };
            for (cert, key) in input.ssl.certs.iter().zip(input.ssl.keys.iter()) {
                server_key(input, cert, key, &passwords)?;
            }
        }
        return Ok(None);
    }
    // The address's default server — `default_server`, else the first —
    // must have a certificate (ngx_http_ssl_init); the others join SNI
    // when they have one and otherwise get the default's.
    let default_idx = inputs.iter().position(|i| i.default_server).unwrap_or(0);
    let default = &inputs[default_idx];
    // Unless it rejects every handshake that comes to it; then each other
    // server needs a certificate or to reject too.
    let rejects = |i: &TlsServerInput| i.ssl.reject_handshake == Some(true);
    if default.ssl.certs.is_empty()
        && (!rejects(default) || inputs.iter().any(|i| i.ssl.certs.is_empty() && !rejects(i)))
    {
        return Err(format!(
            "no \"ssl_certificate\" is defined for the \"listen ... ssl\" directive \
             (listen {addr})"
        ));
    }
    // The address's rustls config is the default server's: its protocols,
    // and the session timeout and ticket keys for every server, as nginx
    // keeps the default server's session context. A server chosen by SNI
    // has its own protocols (#586), as nginx 1.29.2+ selects the server
    // before the version is negotiated.
    // `ssl_ciphers` / `ssl_prefer_server_ciphers`: each server's, in its
    // context as its protocols are (an SNI-chosen server's own SSL_CTX in
    // nginx). A list that leaves no TLS 1.2 suite leaves TLS 1.3 alone.
    let cipher_policy = |input: &TlsServerInput| {
        crate::tls_ciphers::Policy::of(
            input.ssl.ciphers.as_deref(),
            input.ssl.prefer_server_ciphers,
        )
    };
    let versions_of = |input: &TlsServerInput| {
        cipher_policy(input).versions(
            input.ssl.protocols.unwrap_or_default(),
            input.ssl.ciphers.as_deref(),
            &mut |w| prepare_warning_once(w),
        )
    };
    let protocols = versions_of(default)?;
    let session_timeout_secs = default
        .ssl
        .session_timeout_ms
        .map(|ms| (ms / 1000).clamp(1, u32::MAX as u64) as u32);

    let mut resolver = crate::tls_certs::ServerNameResolver::new();
    let mut default_keys: Vec<crate::tls_certs::ServerKey> = Vec::new();

    for (idx, input) in inputs.iter().enumerate() {
        if input.ssl.certs.is_empty() {
            continue;
        }
        let mut keys: Vec<crate::tls_certs::ServerKey> = Vec::with_capacity(input.ssl.certs.len());
        let passwords = match &input.ssl.password_file {
            Some(path) => crate::tls_certs::password_file(path)?,
            None => Arc::from(Vec::new()),
        };
        for (cert, key) in input.ssl.certs.iter().zip(input.ssl.keys.iter()) {
            keys.push(server_key(input, cert, key, &passwords)?);
        }
        // Each is loaded and checked, as nginx loads it; the last of each
        // key type is the one served (#670).
        let keys = crate::tls_certs::last_per_key_type(keys);

        // Register each registered server_name against every key so an RSA
        // + ECDSA pair can both serve under the same hostname.
        for name in &input.server_names {
            for ck in &keys {
                match name {
                    ServerNameSpec::Exact(host) => resolver.add_exact(host, ck.clone()),
                    ServerNameSpec::WildcardLeading { suffix, .. } => {
                        resolver.add_wildcard(suffix, ck.clone());
                    }
                    ServerNameSpec::WildcardTrailing { head, .. } => {
                        resolver.add_wildcard_trailing(head, ck.clone());
                    }
                    ServerNameSpec::Regex {
                        pattern,
                        case_insensitive,
                        ..
                    } => {
                        let regex = crate::config::pcre::regex(pattern, *case_insensitive)
                            .map_err(|e| format!("server_name regex \"{pattern}\": {e}"))?;
                        resolver.add_regex(&regex, ck.clone());
                    }
                    // A request without a Host header; there's always an SNI
                    // name or none, so nothing to register.
                    ServerNameSpec::Empty => {}
                }
            }
        }
        if idx == default_idx {
            default_keys = keys;
        }
    }

    resolver.set_default(default_keys);
    // `ssl_session_ticket_key` files: 48 or 80 bytes each
    // (ngx_ssl_session_ticket_keys).
    let ticket_keys = match &default.ssl.resumption.ticket_keys {
        Some(paths) => {
            let mut keys = Vec::with_capacity(paths.len());
            for path in paths {
                let buf = std::fs::read(path).map_err(|e| {
                    format!("open() \"{}\" failed ({})", path.display(), errno_text(&e))
                })?;
                crate::privileges::note_read(path);
                keys.push(
                    crate::tls_ticket::TicketKey::from_file_bytes(&buf)
                        .ok_or_else(|| format!("\"{}\" must be 48 or 80 bytes", path.display()))?,
                );
            }
            Some(keys)
        }
        None => None,
    };
    let mut cfg = crate::tls_certs::build_server_config(
        resolver,
        protocols,
        session_timeout_secs,
        default.ssl.resumption.clone(),
        ticket_keys,
    )
    .map_err(|e| format!("listen {addr}: cannot build TLS config: {e}"))?;
    // ALPN offers h2 first where HTTP/2 is on (#144), as
    // ngx_http_ssl_alpn_select prefers it.
    if http2 && let Some(cfg) = Arc::get_mut(&mut cfg) {
        cfg.alpn_protocols.insert(0, b"h2".to_vec());
    }
    // `ssl_certificate_compression` (#601), the default server's for the
    // address's config.
    let compress = |input: &TlsServerInput| input.ssl.certificate_compression.unwrap_or(false);
    if compress(default)
        && let Some(cfg) = Arc::get_mut(&mut cfg)
    {
        crate::tls_certs::compress_certificates(cfg, true);
    }
    // Client certificates (#113) and protocols (#586): each server with
    // certificates of its own has its context; one without takes the
    // default server's, whose SSL_CTX its SNI name keeps in nginx. Equal
    // contexts are one.
    let mut auths: Vec<(ClientAuthKey, Arc<crate::client_verify::ClientAuth>)> = Vec::new();
    let mut auth_of = |input: &TlsServerInput| -> Result<Option<usize>, String> {
        let Some(key) = client_auth_key(input)? else {
            return Ok(None);
        };
        if let Some(i) = auths.iter().position(|(k, _)| *k == key) {
            return Ok(Some(i));
        }
        let auth = client_auth(&key)?;
        auths.push((key, Arc::new(auth)));
        Ok(Some(auths.len() - 1))
    };
    // And certificate compression (#601), an SSL_CTX option nginx copies
    // from the server chosen by SNI too.
    // And the cipher policy, an index into `policies`.
    let mut policies: Vec<crate::tls_ciphers::Policy> = vec![Default::default()];
    let mut policy_of = |input: &TlsServerInput| -> usize {
        let policy = cipher_policy(input);
        policies
            .iter()
            .position(|p| *p == policy)
            .unwrap_or_else(|| {
                policies.push(policy);
                policies.len() - 1
            })
    };
    type ContextKey = (Option<usize>, crate::config::TlsVersionSet, bool, usize);
    let default_key: ContextKey = (
        auth_of(default)?,
        protocols,
        compress(default),
        policy_of(default),
    );
    let mut server_keys: Vec<ContextKey> = Vec::with_capacity(inputs.len());
    for input in inputs {
        server_keys.push(if input.ssl.certs.is_empty() {
            default_key
        } else {
            (
                auth_of(input)?,
                versions_of(input)?,
                compress(input),
                policy_of(input),
            )
        });
    }
    // The address's config is the default server's context; the others
    // are configs of their own, indexed in `contexts`.
    let context_config = |(auth, versions, compressed, policy): ContextKey|
     -> Result<Arc<rustls::ServerConfig>, String> {
            if (auth, versions, compressed, policy) == (None, protocols, compress(default), 0) {
                return Ok(cfg.clone());
            }
            let mut config = crate::tls_certs::with_context(
                &cfg,
                versions,
                auth.map(|i| auths[i].1.verifier(crate::tls_certs::active_provider())),
                &policies[policy],
            )
            .map_err(|e| format!("listen {addr}: cannot build TLS config: {e}"))?;
            if let Some(config) = Arc::get_mut(&mut config) {
                crate::tls_certs::compress_certificates(config, compressed);
            }
            Ok(config)
        };
    let mut others: Vec<ContextKey> = Vec::new();
    let contexts: Vec<Option<u16>> = server_keys
        .iter()
        .map(|&key| {
            (key != default_key).then(|| {
                let i = others.iter().position(|&o| o == key).unwrap_or_else(|| {
                    others.push(key);
                    others.len() - 1
                });
                i as u16
            })
        })
        .collect();
    let main = context_config(default_key)?;
    let other_configs = others
        .iter()
        .map(|&key| Ok((context_config(key)?, key.0.map(|i| auths[i].1.clone()))))
        .collect::<Result<Vec<_>, String>>()?;
    let default_auth = default_key.0;
    let acceptor = crate::tls::acceptor_from_config(main)
        .with_contexts(default_auth.map(|i| auths[i].1.clone()), other_configs);
    Ok(Some((
        Arc::new(if h2_by_sni {
            acceptor.with_choice_of_h2()
        } else {
            acceptor
        }),
        contexts,
    )))
}

/// What makes a stapling certificate: the files, the server's stapling
/// lines and the trusted certificates its responses are checked with.
#[derive(PartialEq, Eq)]
struct StapledKeyId {
    cert: std::path::PathBuf,
    key: std::path::PathBuf,
    password_file: Option<std::path::PathBuf>,
    stapling: crate::config::StaplingConf,
    trust: crate::config::ClientVerifyConf,
    resolver: Option<crate::config::ResolverConf>,
    resolver_timeout_ms: Option<u64>,
}

/// A server's certificate `cert` with its key, loaded, and its OCSP
/// stapling set up when the server has `ssl_stapling on` (#141).
fn server_key(
    input: &TlsServerInput,
    cert: &std::path::Path,
    key: &std::path::Path,
    passwords: &[Vec<u8>],
) -> Result<crate::tls_certs::ServerKey, String> {
    let load = || {
        crate::tls_certs::load_certified_key(cert, key, passwords)
            .map(Arc::new)
            .map_err(|e| {
                format!(
                    "cannot load certificate \"{}\" with key \"{}\": {e}",
                    cert.display(),
                    key.display()
                )
            })
    };
    let conf = &input.ssl.stapling;
    if conf.on != Some(true) {
        return load().map(Into::into);
    }
    let id = StapledKeyId {
        cert: cert.to_path_buf(),
        key: key.to_path_buf(),
        password_file: input.ssl.password_file.clone(),
        stapling: conf.clone(),
        trust: stapling_trust(&input.ssl.client_verify),
        resolver: input.resolver.clone(),
        resolver_timeout_ms: input.resolver_timeout_ms,
    };
    if let Some(found) = STAPLED_KEYS.with(|k| {
        k.borrow()
            .iter()
            .find(|(i, _)| *i == id)
            .map(|(_, key)| key.clone())
    }) {
        return Ok(found);
    }
    let certified = load()?;
    let settings = crate::ocsp::Settings {
        file: conf.file.as_deref(),
        responder: conf.responder.as_deref(),
        verify: conf.verify.unwrap_or(false),
        store: Arc::new(stapling_store(&id.trust)?),
        resolver: id.resolver.clone().map(prepare_resolver),
        resolver_timeout: std::time::Duration::from_millis(
            id.resolver_timeout_ms
                .unwrap_or(ProxyEffective::defaults().resolver_timeout_ms),
        ),
    };
    let stapling =
        crate::ocsp::Stapling::new(certified.clone(), cert, &settings, &mut prepare_warning)?;
    let server_key = crate::tls_certs::ServerKey::stapled(certified, stapling);
    STAPLED_KEYS.with(|k| k.borrow_mut().push((id, server_key.clone())));
    Ok(server_key)
}

/// Of a server's `ssl_verify_client` lines, what goes into its store:
/// `ssl_client_certificate` only when client certificates are asked for.
fn stapling_trust(verify: &crate::config::ClientVerifyConf) -> crate::config::ClientVerifyConf {
    let asks = verify
        .mode
        .is_some_and(|m| m != crate::config::VerifyClient::Off);
    crate::config::ClientVerifyConf {
        mode: None,
        client_certificate: verify.client_certificate.clone().filter(|_| asks),
        trusted_certificate: verify.trusted_certificate.clone(),
        depth: None,
        crl: verify.crl.clone(),
    }
}

/// A server's SSL_CTX store, as OCSP stapling sees it: what
/// `ssl_client_certificate` (with `ssl_verify_client`),
/// `ssl_trusted_certificate` and `ssl_crl` load into it
/// (ngx_http_ssl_merge_srv_conf).
fn stapling_store(
    trust: &crate::config::ClientVerifyConf,
) -> Result<crate::x509_verify::Store, String> {
    let fail = |what: &str, e: String| format!("{what} failed (SSL: {e})");
    let read = |path: &std::path::Path, call: &str| {
        crate::tls_certs::pem_file(path)
            .map_err(|e| format!("{call}(\"{}\") failed ({})", path.display(), errno_text(&e)))
    };
    let mut store =
        crate::x509_verify::Store::without_depth().map_err(|e| fail("X509_STORE_new()", e))?;
    if let Some(path) = &trust.client_certificate {
        let pem = read(path, "SSL_CTX_load_verify_locations")?;
        store
            .add_trusted(&pem)
            .map_err(|e| fail("SSL_CTX_load_verify_locations(ssl_client_certificate)", e))?;
    }
    if let Some(path) = &trust.trusted_certificate {
        let pem = read(path, "SSL_CTX_load_verify_locations")?;
        store
            .add_trusted(&pem)
            .map_err(|e| fail("SSL_CTX_load_verify_locations(ssl_trusted_certificate)", e))?;
    }
    if let Some(path) = &trust.crl {
        let pem = read(path, "X509_LOOKUP_load_file")?;
        store
            .add_crl(&pem)
            .map_err(|e| fail("X509_LOOKUP_load_file(ssl_crl)", e))?;
    }
    Ok(store)
}

/// What a client-certificate context is made of: the files' contents and
/// the depth. `ssl_client_certificate`'s subjects are also the CA list.
#[derive(PartialEq, Eq)]
struct ClientAuthKey {
    client_certificate: Option<Vec<u8>>,
    trusted_certificate: Option<Vec<u8>>,
    crl: Option<Vec<u8>>,
    depth: u32,
}

/// A server's `ssl_verify_client` settings, read: `None` with it off.
/// The files load as nginx loads them (ngx_http_ssl_merge_srv_conf), and
/// fail as it fails: `on` / `optional` need `ssl_client_certificate` or,
/// since nginx 1.27.2, `ssl_trusted_certificate` alone (#587), which
/// verifies without sending a CA list.
fn client_auth_key(input: &TlsServerInput) -> Result<Option<ClientAuthKey>, String> {
    use crate::config::VerifyClient;
    let conf = &input.ssl.client_verify;
    let mode = conf.mode.unwrap_or(VerifyClient::Off);
    let read = |path: &Option<std::path::PathBuf>, call: &str| {
        path.as_ref()
            .map(|p| {
                crate::tls_certs::pem_file(p)
                    .map(|b| b.to_vec())
                    .map_err(|e| format!("{call}(\"{}\") failed ({})", p.display(), errno_text(&e)))
            })
            .transpose()
    };
    let trusted_certificate = read(&conf.trusted_certificate, "SSL_CTX_load_verify_locations")?;
    let crl = read(&conf.crl, "X509_LOOKUP_load_file")?;
    if mode == VerifyClient::Off {
        return Ok(None);
    }
    if conf.client_certificate.is_none()
        && conf.trusted_certificate.is_none()
        && mode != VerifyClient::OptionalNoCa
    {
        return Err(
            "no ssl_client_certificate or ssl_trusted_certificate for ssl_verify_client"
                .to_string(),
        );
    }
    Ok(Some(ClientAuthKey {
        client_certificate: read(&conf.client_certificate, "SSL_CTX_load_verify_locations")?,
        trusted_certificate,
        crl,
        depth: conf.depth.unwrap_or(1),
    }))
}

fn client_auth(key: &ClientAuthKey) -> Result<crate::client_verify::ClientAuth, String> {
    let fail = |what: &str, e: String| format!("{what} failed (SSL: {e})");
    let mut store =
        crate::x509_verify::Store::empty(key.depth).map_err(|e| fail("X509_STORE_new()", e))?;
    let mut hints = Vec::new();
    if let Some(pem) = &key.client_certificate {
        store
            .add_trusted(pem)
            .map_err(|e| fail("SSL_CTX_load_verify_locations(ssl_client_certificate)", e))?;
        hints = crate::x509_verify::subjects(pem)
            .map_err(|e| fail("SSL_load_client_CA_file(ssl_client_certificate)", e))?
            .into_iter()
            .map(rustls::DistinguishedName::from)
            .collect();
    }
    if let Some(pem) = &key.trusted_certificate {
        store
            .add_trusted(pem)
            .map_err(|e| fail("SSL_CTX_load_verify_locations(ssl_trusted_certificate)", e))?;
    }
    if let Some(pem) = &key.crl {
        store
            .add_crl(pem)
            .map_err(|e| fail("X509_LOOKUP_load_file(ssl_crl)", e))?;
    }
    Ok(crate::client_verify::ClientAuth {
        store: Arc::new(store),
        hints,
    })
}

pub(crate) fn prepare_upstreams(
    upstreams: Vec<crate::config::UpstreamBlock>,
) -> std::collections::HashMap<&'static str, &'static PreparedUpstream> {
    let mut out = std::collections::HashMap::new();
    for u in upstreams {
        let name_static: &'static str = crate::arena::leak(u.name.into_boxed_str());
        let mut peers_vec: Vec<PreparedPeer> = Vec::with_capacity(u.servers.len());
        for s in u.servers {
            let display: &'static [u8] =
                crate::arena::leak(s.display.into_bytes().into_boxed_slice());
            peers_vec.push(PreparedPeer {
                addr: PeerAddr::from_config(s.addr),
                display,
                weight: s.weight,
                max_fails: s.max_fails,
                fail_timeout_ms: (s.fail_timeout_secs as u64) * 1_000,
                max_conns: s.max_conns,
                down: s.down,
                backup: s.backup,
            });
        }
        let peers: &'static [PreparedPeer] = crate::arena::leak(peers_vec.into_boxed_slice());
        // ngx_http_upstream_keepalive_init_main_conf: since 1.29.7 every
        // `upstream {}` block keeps up to 32 idle connections, each for the
        // location that opened it, unless it says `keepalive 0;`.
        let (keepalive_max_idle, keepalive_local) = match u.keepalive_max_idle {
            None => (Some(32), true),
            Some(0) => (None, false),
            Some(n) => (Some(n), u.keepalive_local),
        };
        let prepared = crate::arena::leak(Box::new(PreparedUpstream {
            name: name_static.as_bytes(),
            peers,
            keepalive_max_idle,
            keepalive_local,
            keepalive_requests: u.keepalive_requests.unwrap_or(1000),
            keepalive_idle_timeout_ms: u.keepalive_idle_timeout_ms.unwrap_or(60_000),
            keepalive_max_lifetime_ms: u.keepalive_max_lifetime_ms.unwrap_or(3_600_000),
            lb: crate::upstream::Lb::prepare(u.lb, peers),
            shared: u
                .zone
                .map(|_| crate::upstream::PeerShared::for_peers(peers.len())),
            metrics: super::metrics::peer_slots(name_static.as_bytes(), peers),
        }));
        super::metrics::note_upstream(prepared);
        out.insert(name_static, &*prepared);
    }
    out
}

thread_local! {
    /// The http block's `proxy_cache_path` zones while a config is
    /// prepared (#233).
    static CACHE_ZONES: std::cell::RefCell<Vec<&'static crate::proxy_cache::CacheZone>> =
        const { std::cell::RefCell::new(Vec::new()) };
    /// The `resolver` directives seen while a config is prepared, by id.
    static RESOLVERS: std::cell::RefCell<Vec<(usize, &'static crate::resolver::Resolver)>> =
        const { std::cell::RefCell::new(Vec::new()) };
    /// Filled by `build_proxy` while a config is prepared, taken into
    /// `PreparedHttp::implicit_upstreams`.
    static IMPLICIT_UPSTREAMS: std::cell::Cell<
        Vec<(&'static [u8], u16, &'static PreparedUpstream)>,
    > = const { std::cell::Cell::new(Vec::new()) };
    /// The root directories opened while a config is prepared, taken into
    /// `PreparedHttp::root_fds`.
    static ROOT_FDS: std::cell::RefCell<Vec<std::os::unix::io::RawFd>> =
        const { std::cell::RefCell::new(Vec::new()) };
    /// The http block's `limit_req_zone`s by name while a config is
    /// prepared (#94).
    static LIMIT_REQ_ZONES: std::cell::RefCell<
        std::collections::HashMap<String, &'static super::limit_req::LimitReqZone>,
    > = std::cell::RefCell::new(std::collections::HashMap::new());
}

/// Build the zones of `proxy_cache_path` (#233). The directories are made
/// at startup, as nginx's ngx_create_paths does.
fn prepare_cache_zones(paths: Vec<crate::config::ProxyCachePath>) -> Result<(), String> {
    use std::os::unix::fs::DirBuilderExt;
    let mut zones = Vec::with_capacity(paths.len());
    for p in paths {
        match std::fs::DirBuilder::new().mode(0o700).create(&p.path) {
            Err(e) if e.kind() != std::io::ErrorKind::AlreadyExists => {
                return Err(format!(
                    "mkdir() \"{}\" failed ({})",
                    p.path.display(),
                    errno_text(&e)
                ));
            }
            _ => {}
        }
        crate::privileges::note_temp_dir(&p.path);
        zones.push(crate::proxy_cache::zone_for(crate::proxy_cache::ZoneConf {
            name: p.zone,
            path: p.path,
            levels: p.levels,
            size: p.size,
            inactive_secs: p.inactive_secs,
            max_size: p.max_size,
            min_free: p.min_free,
        }));
    }
    CACHE_ZONES.with(|z| *z.borrow_mut() = zones);
    Ok(())
}

/// A location's resolved `proxy_cache*` (`None` without `proxy_cache` or
/// with `proxy_cache off`). A zone no `proxy_cache_path` declares is
/// nginx's startup error.
fn prepare_proxy_cache(
    conf: &'static crate::config::ProxyCacheConf,
    ignore: crate::proxy_cache::Ignore,
) -> Result<Option<&'static PreparedProxyCache>, String> {
    use crate::config::ProxyCacheSetting;
    let zone = match &conf.cache {
        None | Some(ProxyCacheSetting::Off) => return Ok(None),
        Some(ProxyCacheSetting::Zone(name)) => {
            let zone = CACHE_ZONES
                .with(|z| z.borrow().iter().find(|z| z.name == name.as_str()).copied())
                .ok_or_else(|| format!("\"proxy_cache\" zone \"{name}\" is unknown"))?;
            PreparedCacheZone::Zone(zone)
        }
        Some(ProxyCacheSetting::Var(parts)) => {
            let zones: Vec<_> = CACHE_ZONES.with(|z| z.borrow().clone());
            PreparedCacheZone::Var(
                prepare_value_parts(parts.clone()),
                crate::arena::leak(zones.into_boxed_slice()),
            )
        }
    };
    let conditions = |list: &Option<Vec<Vec<crate::config::ValuePart>>>| {
        let list: Vec<&'static [PreparedValuePart]> = list
            .iter()
            .flatten()
            .map(|parts| prepare_value_parts(parts.clone()))
            .collect();
        &*crate::arena::leak(list.into_boxed_slice())
    };
    Ok(Some(crate::arena::leak(Box::new(PreparedProxyCache {
        zone,
        key: conf.key.clone().map(prepare_value_parts),
        valid: conf.valid.as_deref().unwrap_or(&[]),
        methods_post: conf.methods_post.unwrap_or(false),
        min_uses: conf.min_uses.unwrap_or(1),
        bypass: conditions(&conf.bypass),
        no_cache: conditions(&conf.no_cache),
        convert_head: conf.convert_head.unwrap_or(true),
        revalidate: conf.revalidate.unwrap_or(false),
        // ngx_http_proxy_merge_loc_conf: `error` covers "no live upstreams".
        use_stale: conf.use_stale.unwrap_or_default(),
        background_update: conf.background_update.unwrap_or(false),
        lock: conf.lock.unwrap_or(false),
        lock_timeout_ms: conf.lock_timeout_ms.unwrap_or(5000),
        lock_age_ms: conf.lock_age_ms.unwrap_or(5000),
        ignore,
        max_range_offset: conf.max_range_offset,
    }))))
}

/// Build the zones of `limit_req_zone` (#94).
fn prepare_limit_req_zones(zones: Vec<crate::config::LimitReqZoneDef>) -> Result<(), String> {
    let built = zones
        .into_iter()
        .map(|z| {
            let name: &'static str = crate::arena::leak(z.name.into_boxed_str());
            let zone: &'static super::limit_req::LimitReqZone =
                crate::arena::leak(Box::new(super::limit_req::LimitReqZone::declare(
                    name,
                    prepare_value_parts(z.key),
                    &z.key_text,
                    z.size,
                    z.rate,
                )?));
            Ok((name.to_string(), zone))
        })
        .collect::<Result<_, String>>()?;
    LIMIT_REQ_ZONES.with(|m| *m.borrow_mut() = built);
    Ok(())
}

/// A location's resolved `limit_req*` (`None` without `limit_req`). A zone
/// no `limit_req_zone` declares is nginx's startup error.
fn prepare_limit_req(
    conf: crate::config::LimitReqConf,
) -> Result<Option<&'static super::limit_req::PreparedLimitReq>, String> {
    use super::limit_req::{PreparedLimit, PreparedLimitReq};
    let Some(limits) = conf.limits.filter(|l| !l.is_empty()) else {
        return Ok(None);
    };
    let limits = limits
        .into_iter()
        .map(|l| {
            let zone = LIMIT_REQ_ZONES
                .with(|m| m.borrow().get(&l.zone).copied())
                .ok_or_else(|| format!("zero size shared memory zone \"{}\"", l.zone))?;
            Ok(PreparedLimit {
                zone,
                burst: l.burst,
                delay: l.delay,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let log_level = conf.log_level.unwrap_or(ErrorLogLevel::Error);
    Ok(Some(crate::arena::leak(Box::new(PreparedLimitReq {
        limits: crate::arena::leak(limits.into_boxed_slice()),
        status: conf.status.unwrap_or(503),
        log_level,
        // ngx_http_limit_req_merge_conf: delays log one level lower.
        delay_log_level: match log_level {
            ErrorLogLevel::Info => ErrorLogLevel::Info,
            ErrorLogLevel::Notice => ErrorLogLevel::Info,
            ErrorLogLevel::Warn => ErrorLogLevel::Notice,
            _ => ErrorLogLevel::Warn,
        },
        dry_run: conf.dry_run.unwrap_or(false),
    }))))
}

thread_local! {
    /// The http block's `limit_conn_zone`s by name while a config is
    /// prepared (#95).
    static LIMIT_CONN_ZONES: std::cell::RefCell<
        std::collections::HashMap<String, &'static super::limit_conn::LimitConnZone>,
    > = std::cell::RefCell::new(std::collections::HashMap::new());
}

/// Build the zones of `limit_conn_zone` (#95).
fn prepare_limit_conn_zones(zones: Vec<crate::config::LimitConnZoneDef>) -> Result<(), String> {
    let built = zones
        .into_iter()
        .map(|z| {
            let name: &'static str = crate::arena::leak(z.name.into_boxed_str());
            let zone: &'static super::limit_conn::LimitConnZone =
                crate::arena::leak(Box::new(super::limit_conn::LimitConnZone::declare(
                    name,
                    prepare_value_parts(z.key),
                    crate::arena::leak(z.key_text.into_boxed_str()),
                    z.size,
                )?));
            Ok((name.to_string(), zone))
        })
        .collect::<Result<_, String>>()?;
    LIMIT_CONN_ZONES.with(|m| *m.borrow_mut() = built);
    Ok(())
}

/// A location's resolved `limit_conn*` (`None` without `limit_conn`).
fn prepare_limit_conn(
    conf: crate::config::LimitConnConf,
) -> Result<Option<&'static super::limit_conn::PreparedLimitConns>, String> {
    use super::limit_conn::{PreparedLimitConn, PreparedLimitConns};
    let Some(limits) = conf.limits.filter(|l| !l.is_empty()) else {
        return Ok(None);
    };
    let limits = limits
        .into_iter()
        .map(|l| {
            let zone = LIMIT_CONN_ZONES
                .with(|m| m.borrow().get(&l.zone).copied())
                .ok_or_else(|| format!("zero size shared memory zone \"{}\"", l.zone))?;
            Ok(PreparedLimitConn { zone, conn: l.conn })
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(Some(crate::arena::leak(Box::new(PreparedLimitConns {
        limits: crate::arena::leak(limits.into_boxed_slice()),
        status: conf.status.unwrap_or(503),
        log_level: conf.log_level.unwrap_or(ErrorLogLevel::Error),
        dry_run: conf.dry_run.unwrap_or(false),
    }))))
}

/// Note the upstream of `proxy_pass http://<authority>` by host and port.
fn note_implicit_upstream(authority: &str, upstream: &'static PreparedUpstream) {
    // `[::1]` has colons of its own; its port parse fails and it keeps 80.
    let (host, port) = match authority
        .rsplit_once(':')
        .and_then(|(host, port)| Some((host, port.parse::<u16>().ok()?)))
    {
        Some((host, port)) if !host.is_empty() => (host, port),
        _ => (authority, 80),
    };
    let host: &'static [u8] =
        crate::arena::leak(host.to_ascii_lowercase().into_bytes().into_boxed_slice());
    IMPLICIT_UPSTREAMS.with(|i| {
        let mut all = i.take();
        all.push((host, port, upstream));
        i.set(all);
    });
}

pub(crate) type UpstreamMap = std::collections::HashMap<&'static str, &'static PreparedUpstream>;

/// Resolve a parsed `proxy_pass` argument against the http-scope upstream
/// map. For `Direct` forms we synthesize a single-peer no-keepalive
/// `PreparedUpstream` so downstream code only deals with one shape.
pub(crate) fn build_proxy(
    pp: ProxyPass,
    upstreams: &UpstreamMap,
    eff: ProxyEffective,
    location_pattern: &'static [u8],
    is_regex_location: bool,
) -> Result<PreparedProxy, String> {
    // nginx rejects a URI part wherever there is no location prefix to
    // replace (ngx_http_proxy_pass), with this one message for all cases.
    const URI_PART_NOT_ALLOWED: &str = "\"proxy_pass\" cannot have URI part in location given by \
         regular expression, or inside named location, or inside \"if\" statement, or inside \
         \"limit_except\" block";
    let (request_path, location_prefix) = match (&pp, is_regex_location) {
        (
            ProxyPass::Direct {
                request_path: Some(p),
                ..
            },
            false,
        )
        | (
            ProxyPass::UpstreamRef {
                request_path: Some(p),
                ..
            },
            false,
        ) => {
            // Named locations (pattern starts with `@`) and regex
            // locations have nothing to strip from a client URI — nginx
            // rejects `proxy_pass http://up/path;` in those modes.
            if location_pattern.first() == Some(&b'@') {
                return Err(URI_PART_NOT_ALLOWED.to_string());
            }
            let path: &'static [u8] = crate::arena::leak(p.clone().into_bytes().into_boxed_slice());
            (path, location_pattern)
        }
        (
            ProxyPass::Direct {
                request_path: Some(_),
                ..
            },
            true,
        )
        | (
            ProxyPass::UpstreamRef {
                request_path: Some(_),
                ..
            },
            true,
        ) => {
            return Err(URI_PART_NOT_ALLOWED.to_string());
        }
        _ => (b"".as_slice(), b"".as_slice()),
    };
    let redirects = match &pp {
        ProxyPass::Direct {
            host_header,
            request_path,
            ..
        }
        | ProxyPass::UpstreamRef {
            host_header,
            request_path,
            ..
        } => prepare_redirects(
            eff.redirect,
            host_header,
            request_path.as_deref(),
            location_pattern,
        )?,
        // With variables there is no URL to derive `default` from: no
        // implicit rule, and an explicit one is an error
        // (ngx_http_proxy_redirect, ngx_http_proxy_merge_loc_conf).
        ProxyPass::Variable { .. } => match eff.redirect {
            None | Some(crate::config::ProxyRedirect::Off) => &[],
            Some(crate::config::ProxyRedirect::Rules(rules))
                if rules
                    .iter()
                    .any(|r| matches!(r, crate::config::ProxyRedirectRule::Default)) =>
            {
                return Err(
                    "\"proxy_redirect default\" cannot be used with \"proxy_pass\" \
                     directive with variables"
                        .to_string(),
                );
            }
            Some(_) => prepare_redirects(eff.redirect, "", None, location_pattern)?,
        },
    };
    let cache = prepare_proxy_cache(eff.cache, eff.cache_ignore)?;
    let response = prepare_response_rules(redirects, &eff)?;
    Ok(match pp {
        ProxyPass::Direct {
            addrs,
            host_header,
            tls,
            ..
        } => {
            let inet = matches!(addrs.first(), Some(crate::config::UpstreamAddr::Inet(_)));
            let display: &'static [u8] =
                crate::arena::leak(host_header.clone().into_bytes().into_boxed_slice());
            // A peer per address, as nginx's implicit upstream
            // (ngx_http_upstream_init_round_robin, `u.naddrs`; #330).
            let peers: Box<[PreparedPeer]> = addrs
                .into_iter()
                .map(|addr| PreparedPeer {
                    addr: PeerAddr::from_config(addr),
                    display,
                    weight: 1,
                    max_fails: 1,
                    fail_timeout_ms: 10_000,
                    max_conns: 0,
                    down: false,
                    backup: false,
                })
                .collect::<Vec<_>>()
                .into_boxed_slice();
            let peers: &'static [PreparedPeer] = crate::arena::leak(peers);
            let host_header_static: &'static [u8] =
                crate::arena::leak(host_header.into_bytes().into_boxed_slice());
            let upstream: &'static PreparedUpstream =
                crate::arena::leak(Box::new(PreparedUpstream {
                    name: host_header_static,
                    peers,
                    keepalive_max_idle: None,
                    keepalive_local: false,
                    keepalive_requests: 1000,
                    keepalive_idle_timeout_ms: 60_000,
                    keepalive_max_lifetime_ms: 3_600_000,
                    lb: crate::upstream::Lb::RoundRobin,
                    shared: None,
                    metrics: super::metrics::peer_slots(host_header_static, peers),
                }));
            super::metrics::note_upstream(upstream);
            if inet && let Ok(authority) = std::str::from_utf8(host_header_static) {
                note_implicit_upstream(authority, upstream);
            }
            PreparedProxy {
                upstream,
                host_header: without_default_port(host_header_static, tls),
                set_headers: eff.set_headers,
                pass_request_headers: eff.pass_request_headers,
                pass_request_body: eff.pass_request_body,
                set_body: eff.set_body,
                connect_timeout_ms: eff.connect_timeout_ms,
                read_timeout_ms: eff.read_timeout_ms,
                send_timeout_ms: eff.send_timeout_ms,
                limit_rate: literal_limit_rate(eff.limit_rate).unwrap_or(0),
                http_version: eff.http_version,
                next_upstream: eff.next_upstream,
                next_upstream_tries: eff.next_upstream_tries,
                next_upstream_timeout_ms: eff.next_upstream_timeout_ms,
                intercept_errors: eff.intercept_errors,
                force_ranges: eff.force_ranges,
                ignore_client_abort: eff.ignore_client_abort,
                ignore_invalid_headers: eff.ignore_invalid_headers,
                underscores_in_headers: eff.underscores_in_headers,
                location_prefix,
                request_path,
                response,
                proxy_method: eff.proxy_method,
                cache,
                url: None,
                bind: eff.bind,
                resolver: eff.resolver,
                resolver_timeout_ms: eff.resolver_timeout_ms,
                tls: tls
                    .then(|| prepare_upstream_tls(eff.tls, host_header_static))
                    .transpose()?,
            }
        }
        ProxyPass::UpstreamRef {
            name,
            host_header,
            tls,
            ..
        } => {
            let upstream = *upstreams.get(name.as_str()).unwrap_or_else(|| {
                panic!("ruxen: proxy_pass http://{name} references undeclared upstream block")
            });
            if upstream.peers.is_empty() {
                panic!("ruxen: upstream {name} has no servers (parser invariant violated)");
            }
            let host_header_static: &'static [u8] =
                crate::arena::leak(host_header.into_bytes().into_boxed_slice());
            PreparedProxy {
                upstream,
                host_header: host_header_static,
                set_headers: eff.set_headers,
                pass_request_headers: eff.pass_request_headers,
                pass_request_body: eff.pass_request_body,
                set_body: eff.set_body,
                connect_timeout_ms: eff.connect_timeout_ms,
                read_timeout_ms: eff.read_timeout_ms,
                send_timeout_ms: eff.send_timeout_ms,
                limit_rate: literal_limit_rate(eff.limit_rate).unwrap_or(0),
                http_version: eff.http_version,
                next_upstream: eff.next_upstream,
                next_upstream_tries: eff.next_upstream_tries,
                next_upstream_timeout_ms: eff.next_upstream_timeout_ms,
                intercept_errors: eff.intercept_errors,
                force_ranges: eff.force_ranges,
                ignore_client_abort: eff.ignore_client_abort,
                ignore_invalid_headers: eff.ignore_invalid_headers,
                underscores_in_headers: eff.underscores_in_headers,
                location_prefix,
                request_path,
                response,
                proxy_method: eff.proxy_method,
                cache,
                url: None,
                bind: eff.bind,
                resolver: eff.resolver,
                resolver_timeout_ms: eff.resolver_timeout_ms,
                tls: tls
                    .then(|| prepare_upstream_tls(eff.tls, host_header_static))
                    .transpose()?,
            }
        }
        ProxyPass::Variable { url } => {
            // One peer, never marked down (`max_fails=0`): each request
            // brings its own address, as nginx creates a peer per request
            // (ngx_http_upstream_create_round_robin_peer).
            let peer = PreparedPeer {
                addr: PeerAddr::Inet(std::net::SocketAddr::from(([0, 0, 0, 0], 0))),
                display: b"",
                weight: 1,
                max_fails: 0,
                fail_timeout_ms: 10_000,
                max_conns: 0,
                down: false,
                backup: false,
            };
            let peers: &'static [PreparedPeer] = crate::arena::leak(Box::new([peer]));
            let upstream: &'static PreparedUpstream =
                crate::arena::leak(Box::new(PreparedUpstream {
                    name: b"",
                    peers,
                    keepalive_max_idle: None,
                    keepalive_local: false,
                    keepalive_requests: 1000,
                    keepalive_idle_timeout_ms: 60_000,
                    keepalive_max_lifetime_ms: 3_600_000,
                    lb: crate::upstream::Lb::RoundRobin,
                    shared: None,
                    // A request's own peers: not counted.
                    metrics: None,
                }));
            PreparedProxy {
                upstream,
                host_header: b"",
                set_headers: eff.set_headers,
                pass_request_headers: eff.pass_request_headers,
                pass_request_body: eff.pass_request_body,
                set_body: eff.set_body,
                connect_timeout_ms: eff.connect_timeout_ms,
                read_timeout_ms: eff.read_timeout_ms,
                send_timeout_ms: eff.send_timeout_ms,
                limit_rate: literal_limit_rate(eff.limit_rate).unwrap_or(0),
                http_version: eff.http_version,
                next_upstream: eff.next_upstream,
                next_upstream_tries: eff.next_upstream_tries,
                next_upstream_timeout_ms: eff.next_upstream_timeout_ms,
                intercept_errors: eff.intercept_errors,
                force_ranges: eff.force_ranges,
                ignore_client_abort: eff.ignore_client_abort,
                ignore_invalid_headers: eff.ignore_invalid_headers,
                underscores_in_headers: eff.underscores_in_headers,
                location_prefix: b"",
                request_path: b"",
                response,
                cache,
                url: Some(prepare_value_parts(url)),
                bind: eff.bind,
                resolver: eff.resolver,
                resolver_timeout_ms: eff.resolver_timeout_ms,
                tls: Some(prepare_upstream_tls(eff.tls, b"")?),
                proxy_method: eff.proxy_method,
            }
        }
    })
}

/// `$proxy_host` and the upstream `Host` for a `proxy_pass` authority: a
/// port equal to the scheme's default (80; only `http://` is proxied) is
/// dropped, as ngx_http_proxy_set_vars does. The URL as written still
/// names the peer and feeds `proxy_redirect default`.
/// `proxy_ssl_*` for a location that proxies over TLS: the shared client
/// config, and the name (`proxy_ssl_name`, else `host`, the host of
/// `proxy_pass`; empty for a URL with variables, whose host is rendered).
fn prepare_upstream_tls(
    settings: super::prepared::UpstreamTlsSettings,
    host: &[u8],
) -> Result<&'static crate::upstream_tls::PreparedUpstreamTls, String> {
    // `proxy_ssl_verify on` needs the certificates to trust, as nginx's
    // ngx_http_proxy_set_ssl refuses it without them.
    let store = match (settings.verify, settings.trusted) {
        (false, _) => None,
        (true, None) => {
            return Err("no proxy_ssl_trusted_certificate for proxy_ssl_verify".to_string());
        }
        (true, Some(trusted)) => Some(crate::upstream_tls::trust_store(
            crate::upstream_tls::VerifySettings {
                trusted,
                depth: settings.verify_depth,
                crl: settings.crl,
            },
        )?),
    };
    // A certificate needs its key (ngx_http_proxy_set_ssl); a key alone
    // is unused. With variables in either, the pair loads per request.
    use super::prepared::PreparedCertPath;
    let passwords = || match settings.password_file {
        Some(path) => crate::tls_certs::password_file(path),
        None => Ok(Arc::from(Vec::new())),
    };
    let mut dynamic_cert = None;
    let client_cert = match (settings.certificate, settings.certificate_key) {
        (None, _) => None,
        (Some(cert), None) => {
            return Err(format!(
                "no \"proxy_ssl_certificate_key\" is defined for certificate \"{}\"",
                cert.text()
            ));
        }
        (Some(PreparedCertPath::File(cert)), Some(PreparedCertPath::File(key))) => Some(
            crate::upstream_tls::client_certificate(cert, key, &passwords()?)?,
        ),
        (Some(cert), Some(key)) => {
            dynamic_cert = Some(crate::upstream_tls::DynamicCert::new(
                cert,
                key,
                passwords()?,
                settings.protocols,
                settings.server_name,
                settings.session_reuse,
                store.clone(),
            ));
            None
        }
    };
    let config = crate::upstream_tls::client_config(
        settings.protocols,
        settings.server_name,
        settings.session_reuse,
        store,
        client_cert,
    )?;
    let literal = |parts: &[PreparedValuePart]| -> Option<Vec<u8>> {
        let mut out = Vec::new();
        for p in parts {
            match p {
                PreparedValuePart::Literal(b) => out.extend_from_slice(b),
                PreparedValuePart::Var(_) => return None,
            }
        }
        Some(out)
    };
    let (name_vars, name) = match settings.name {
        Some(parts) => match literal(parts) {
            Some(text) => (
                None,
                crate::upstream_tls::leak_name(crate::upstream_tls::server_name(&text)),
            ),
            None => (
                Some(parts),
                crate::upstream_tls::leak_name(crate::upstream_tls::server_name(host)),
            ),
        },
        None => (
            None,
            crate::upstream_tls::leak_name(crate::upstream_tls::server_name(host)),
        ),
    };
    Ok(crate::arena::leak(Box::new(
        crate::upstream_tls::PreparedUpstreamTls {
            config,
            name_vars,
            name,
            default_name: settings.name.is_none(),
            dynamic_cert,
        },
    )))
}

fn without_default_port(authority: &'static [u8], tls: bool) -> &'static [u8] {
    let host_end = authority
        .iter()
        .rposition(|&b| b == b']')
        .map_or(0, |i| i + 1);
    match authority[host_end..].iter().rposition(|&b| b == b':') {
        Some(i) => {
            let colon = host_end + i;
            let port = std::str::from_utf8(&authority[colon + 1..])
                .ok()
                .and_then(|p| p.parse::<u16>().ok());
            if port == Some(if tls { 443 } else { 80 }) {
                &authority[..colon]
            } else {
                authority
            }
        }
        None => authority,
    }
}

/// A `proxy_limit_rate` without variables, in bytes/sec; `Some(0)` when
/// unset. `None` when it has variables.
fn literal_limit_rate(parts: Option<&[PreparedValuePart]>) -> Option<u64> {
    let mut value = Vec::new();
    for part in parts.unwrap_or(&[]) {
        match part {
            PreparedValuePart::Literal(bytes) => value.extend_from_slice(bytes),
            PreparedValuePart::Var(_) => return None,
        }
    }
    // Checked as a size when parsed.
    Some(crate::config::parse_size(&value).unwrap_or(0))
}

/// nginx's hidden set: its defaults, plus `proxy_hide_header`, minus
/// `proxy_pass_header` (ngx_http_upstream_hide_headers_hash).
fn prepare_response_rules(
    redirects: &'static [PreparedRedirect],
    eff: &ProxyEffective,
) -> Result<&'static ProxyResponseRules, String> {
    let pass = eff.pass_headers.unwrap_or(&[]);
    let passed = |name: &str| pass.iter().any(|p| p.eq_ignore_ascii_case(name));
    let pass_mask = pass
        .iter()
        .filter_map(|p| crate::proxy::default_hidden_bit(p.as_bytes()))
        .fold(0, |mask, bit| mask | bit);
    let hide: Vec<&'static [u8]> = eff
        .hide_headers
        .unwrap_or(&[])
        .iter()
        .filter(|h| !passed(h) && crate::proxy::default_hidden_bit(h.as_bytes()).is_none())
        .map(|h| leak_bytes(h.to_ascii_lowercase().as_bytes()))
        .collect();
    let domains = prepare_cookie_rules(eff.cookie_domain, "proxy_cookie_domain")?;
    let paths = prepare_cookie_rules(eff.cookie_path, "proxy_cookie_path")?;
    let flags = prepare_cookie_flags(eff.cookie_flags)?;
    let cookies = (!domains.is_empty() || !paths.is_empty() || !flags.is_empty()).then(|| {
        &*crate::arena::leak(Box::new(PreparedCookieRules {
            domains,
            paths,
            flags,
        }))
    });
    Ok(crate::arena::leak(Box::new(ProxyResponseRules {
        redirects,
        error_pages: eff.error_pages,
        recursive_error_pages: eff.recursive_error_pages,
        ignore_accel_redirect: eff.ignore_accel_redirect,
        ignore_accel_limit_rate: eff.ignore_accel_limit_rate,
        limit_rate: eff
            .limit_rate
            .filter(|parts| literal_limit_rate(Some(parts)).is_none()),
        cookies,
        hide: crate::arena::leak(hide.into_boxed_slice()),
        passes_date: crate::proxy::default_hidden_bit(b"date")
            .is_some_and(|bit| pass_mask & bit != 0),
        pass_mask,
    })))
}

/// The `proxy_cookie_flags` lines in scope: none when unset or `off`.
fn prepare_cookie_flags(
    config: Option<&'static [crate::config::CookieFlagsRule]>,
) -> Result<&'static [PreparedCookieFlags], String> {
    use crate::config::CookieName;
    let rules = config
        .unwrap_or(&[])
        .iter()
        .map(|rule| {
            let cookie = match &rule.cookie {
                CookieName::Name(parts) => {
                    PreparedCookieName::Name(prepare_value_parts(parts.clone()))
                }
                CookieName::Regex(pattern) => PreparedCookieName::Regex(leak_regex(
                    crate::config::pcre::regex(pattern, true).map_err(|e| {
                        format!("invalid proxy_cookie_flags regex \"{pattern}\": {e}")
                    })?,
                )),
            };
            let flags: Vec<&'static [PreparedValuePart]> = rule
                .flags
                .iter()
                .map(|f| prepare_value_parts(f.clone()))
                .collect();
            Ok(PreparedCookieFlags {
                cookie,
                flags: crate::arena::leak(flags.into_boxed_slice()),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(crate::arena::leak(rules.into_boxed_slice()))
}

/// The rules of `proxy_cookie_domain` or `proxy_cookie_path`: none when
/// unset or `off`.
fn prepare_cookie_rules(
    config: Option<&'static crate::config::ProxyRedirect>,
    what: &str,
) -> Result<&'static [PreparedRedirect], String> {
    use crate::config::{ProxyRedirect, ProxyRedirectRule};
    let Some(ProxyRedirect::Rules(rules)) = config else {
        return Ok(&[]);
    };
    let rules = rules
        .iter()
        .filter_map(|rule| match rule {
            // Only `proxy_redirect` has a `default`.
            ProxyRedirectRule::Default => None,
            ProxyRedirectRule::Prefix {
                pattern,
                replacement,
            } => Some(Ok(PreparedRedirect::Prefix {
                pattern: prepare_value_parts(pattern.clone()),
                replacement: prepare_value_parts(replacement.clone()),
            })),
            ProxyRedirectRule::Regex {
                pattern,
                case_insensitive,
                replacement,
            } => Some(
                crate::config::pcre::regex(pattern, *case_insensitive)
                    .map_err(|e| format!("invalid {what} regex \"{pattern}\": {e}"))
                    .map(|regex| PreparedRedirect::Regex {
                        regex: leak_regex(regex),
                        replacement: prepare_value_parts(replacement.clone()),
                    }),
            ),
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(crate::arena::leak(rules.into_boxed_slice()))
}

/// The `proxy_redirect` rules for one `proxy_pass`. Without any
/// `proxy_redirect` in scope nginx applies `default`: with a URI part in
/// `proxy_pass`, the whole URL is replaced by the location prefix
/// (`http://up:1/` → `/d/` in `location /d/`); without one, the URL plus
/// `/` becomes `/` (ngx_http_proxy_merge_loc_conf).
fn prepare_redirects(
    config: Option<&'static crate::config::ProxyRedirect>,
    authority: &str,
    uri: Option<&str>,
    location: &'static [u8],
) -> Result<&'static [PreparedRedirect], String> {
    use crate::config::{ProxyRedirect, ProxyRedirectRule};
    let literal = |s: String| prepare_value_parts(vec![ValuePart::Literal(s)]);
    let default_rule = || {
        let url = format!("http://{authority}{}", uri.unwrap_or(""));
        let (pattern, replacement) = match uri {
            Some(_) => (url, String::from_utf8_lossy(location).into_owned()),
            None => (format!("{url}/"), "/".to_string()),
        };
        PreparedRedirect::Prefix {
            pattern: literal(pattern),
            replacement: literal(replacement),
        }
    };
    let rules: Vec<PreparedRedirect> = match config {
        None => vec![default_rule()],
        Some(ProxyRedirect::Off) => Vec::new(),
        Some(ProxyRedirect::Rules(rules)) => rules
            .iter()
            .map(|rule| match rule {
                ProxyRedirectRule::Default => Ok(default_rule()),
                ProxyRedirectRule::Prefix {
                    pattern,
                    replacement,
                } => Ok(PreparedRedirect::Prefix {
                    pattern: prepare_value_parts(pattern.clone()),
                    replacement: prepare_value_parts(replacement.clone()),
                }),
                ProxyRedirectRule::Regex {
                    pattern,
                    case_insensitive,
                    replacement,
                } => {
                    let regex = crate::config::pcre::regex(pattern, *case_insensitive)
                        .map_err(|e| format!("invalid proxy_redirect regex \"{pattern}\": {e}"))?;
                    Ok(PreparedRedirect::Regex {
                        regex: leak_regex(regex),
                        replacement: prepare_value_parts(replacement.clone()),
                    })
                }
            })
            .collect::<Result<_, String>>()?,
    };
    Ok(crate::arena::leak(rules.into_boxed_slice()))
}

/// Server-scope proxy defaults — used as the parent in location-scope
/// inheritance. Built once per server in `prepare_server`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ServerProxyDefaults {
    pub set_headers: &'static [PreparedProxySetHeader],
    pub pass_request_headers: bool,
    pub pass_request_body: bool,
    pub set_body: Option<&'static [PreparedValuePart]>,
    pub ignore_accel_redirect: bool,
    pub ignore_accel_limit_rate: bool,
    pub connect_timeout_ms: u64,
    pub read_timeout_ms: u64,
    pub send_timeout_ms: u64,
    pub limit_rate: Option<&'static [PreparedValuePart]>,
    pub http_version: u8,
    pub next_upstream: crate::config::ProxyNextUpstream,
    pub next_upstream_tries: u32,
    pub next_upstream_timeout_ms: u64,
    pub intercept_errors: bool,
    pub force_ranges: bool,
    pub ignore_client_abort: bool,
    pub ignore_invalid_headers: bool,
    pub underscores_in_headers: bool,
    pub redirect: Option<&'static crate::config::ProxyRedirect>,
    pub cookie_domain: Option<&'static crate::config::ProxyRedirect>,
    pub cookie_path: Option<&'static crate::config::ProxyRedirect>,
    pub cookie_flags: Option<&'static [crate::config::CookieFlagsRule]>,
    pub hide_headers: Option<&'static [String]>,
    pub pass_headers: Option<&'static [String]>,
    pub proxy_method: Option<&'static [PreparedValuePart]>,
    pub cache: &'static crate::config::ProxyCacheConf,
    pub cache_ignore: crate::proxy_cache::Ignore,
    pub bind: Option<&'static PreparedBind>,
    pub resolver: Option<&'static crate::resolver::Resolver>,
    pub resolver_timeout_ms: u64,
    pub tls: super::prepared::UpstreamTlsSettings,
}

/// The cache fields of `proxy_ignore_headers` at one scope, the unset ones
/// from `parent`.
fn cache_ignore(
    list: Option<&[String]>,
    parent: crate::proxy_cache::Ignore,
) -> crate::proxy_cache::Ignore {
    if list.is_none() {
        return parent;
    }
    let has = |field| ignores(list, field).unwrap_or(false);
    crate::proxy_cache::Ignore {
        x_accel_expires: has("x-accel-expires"),
        expires: has("expires"),
        cache_control: has("cache-control"),
        set_cookie: has("set-cookie"),
        vary: has("vary"),
    }
}

/// `proxy_ignore_headers` as set at one scope: whether it lists `field`
/// (lowercase), or `None` when the scope didn't set it.
fn ignores(list: Option<&[String]>, field: &str) -> Option<bool> {
    list.map(|l| l.iter().any(|h| h == field))
}

/// Leak a directive's list for the lifetime of the config.
fn leak_list(list: Option<Vec<String>>) -> Option<&'static [String]> {
    list.map(|l| &*crate::arena::leak(l.into_boxed_slice()))
}

impl ServerProxyDefaults {
    pub(crate) fn build(
        conf: ProxyConf,
        ignore_invalid_headers: bool,
        underscores_in_headers: bool,
    ) -> Self {
        let defaults = ProxyEffective::defaults();
        let tls = super::prepared::UpstreamTlsSettings::DEFAULT.over(&conf);
        let set_headers: &'static [PreparedProxySetHeader] = match conf.set_headers {
            Some(list) => prepare_proxy_set_headers(list),
            None => &[],
        };
        Self {
            set_headers,
            pass_request_headers: conf
                .pass_request_headers
                .unwrap_or(defaults.pass_request_headers),
            pass_request_body: conf.pass_request_body.unwrap_or(defaults.pass_request_body),
            set_body: conf.set_body.map(prepare_value_parts),
            ignore_accel_redirect: ignores(conf.ignore_headers.as_deref(), "x-accel-redirect")
                .unwrap_or(false),
            ignore_accel_limit_rate: ignores(conf.ignore_headers.as_deref(), "x-accel-limit-rate")
                .unwrap_or(false),
            connect_timeout_ms: conf
                .connect_timeout_ms
                .unwrap_or(defaults.connect_timeout_ms),
            read_timeout_ms: conf.read_timeout_ms.unwrap_or(defaults.read_timeout_ms),
            send_timeout_ms: conf.send_timeout_ms.unwrap_or(defaults.send_timeout_ms),
            limit_rate: conf
                .limit_rate
                .map(prepare_value_parts)
                .or(defaults.limit_rate),
            http_version: conf.http_version.unwrap_or(defaults.http_version),
            next_upstream: conf.next_upstream.unwrap_or(defaults.next_upstream),
            next_upstream_tries: conf
                .next_upstream_tries
                .unwrap_or(defaults.next_upstream_tries),
            next_upstream_timeout_ms: conf
                .next_upstream_timeout_ms
                .unwrap_or(defaults.next_upstream_timeout_ms),
            intercept_errors: conf.intercept_errors.unwrap_or(defaults.intercept_errors),
            force_ranges: conf.force_ranges.unwrap_or(defaults.force_ranges),
            ignore_client_abort: conf
                .ignore_client_abort
                .unwrap_or(defaults.ignore_client_abort),
            ignore_invalid_headers,
            underscores_in_headers,
            redirect: conf.redirect.map(|r| &*crate::arena::leak(Box::new(r))),
            cookie_domain: conf
                .cookie_domain
                .map(|r| &*crate::arena::leak(Box::new(r))),
            cookie_path: conf.cookie_path.map(|r| &*crate::arena::leak(Box::new(r))),
            cookie_flags: conf
                .cookie_flags
                .map(|r| &*crate::arena::leak(r.into_boxed_slice())),
            hide_headers: leak_list(conf.hide_headers),
            pass_headers: leak_list(conf.pass_headers),
            proxy_method: conf.proxy_method.map(prepare_value_parts),
            cache_ignore: cache_ignore(conf.ignore_headers.as_deref(), defaults.cache_ignore),
            tls,
            cache: crate::arena::leak(Box::new(conf.cache)),
            bind: conf.bind.and_then(prepare_bind),
            resolver: conf.resolver.map(prepare_resolver),
            resolver_timeout_ms: conf
                .resolver_timeout_ms
                .unwrap_or(defaults.resolver_timeout_ms),
        }
    }
}

/// One `Resolver` per `resolver` directive, however many scopes inherit
/// it: they share its cache (nginx's `clcf->resolver` pointer).
fn prepare_resolver(conf: crate::config::ResolverConf) -> &'static crate::resolver::Resolver {
    RESOLVERS.with(|r| {
        let mut all = r.borrow_mut();
        if let Some((_, resolver)) = all.iter().find(|(id, _)| *id == conf.id) {
            return *resolver;
        }
        let resolver: &'static crate::resolver::Resolver =
            crate::arena::leak(Box::new(crate::resolver::Resolver {
                servers: conf.servers.into_boxed_slice(),
                valid: conf.valid_secs.map(std::time::Duration::from_secs),
                ipv4: conf.ipv4,
                ipv6: conf.ipv6,
            }));
        all.push((conf.id, resolver));
        resolver
    })
}

/// `proxy_bind`, `None` for `off`. A literal address was checked by the
/// parser.
fn prepare_bind(bind: crate::config::ProxyBind) -> Option<&'static PreparedBind> {
    let crate::config::ProxyBind::Addr { value, transparent } = bind else {
        return None;
    };
    let addr = match value.as_slice() {
        [ValuePart::Literal(text)] => crate::config::parse_bind_addr(text),
        _ => None,
    };
    Some(crate::arena::leak(Box::new(PreparedBind {
        addr,
        value: prepare_value_parts(value),
        transparent,
    })))
}

pub(crate) fn prepare_proxy_set_headers(
    list: Vec<ProxySetHeader>,
) -> &'static [PreparedProxySetHeader] {
    let mut out: Vec<PreparedProxySetHeader> = Vec::with_capacity(list.len());
    for h in list {
        let name: &'static [u8] = crate::arena::leak(h.name.into_bytes().into_boxed_slice());
        let value: &'static [PreparedValuePart] = prepare_value_parts(h.value);
        out.push(PreparedProxySetHeader { name, value });
    }
    crate::arena::leak(out.into_boxed_slice())
}

pub(crate) fn resolve_proxy_effective(
    location: ProxyConf,
    server_defaults: ServerProxyDefaults,
) -> ProxyEffective {
    let tls = server_defaults.tls.over(&location);
    let set_headers: &'static [PreparedProxySetHeader] = match location.set_headers {
        Some(list) => prepare_proxy_set_headers(list),
        None => server_defaults.set_headers,
    };
    ProxyEffective {
        set_headers,
        http_version: location
            .http_version
            .unwrap_or(server_defaults.http_version),
        pass_request_headers: location
            .pass_request_headers
            .unwrap_or(server_defaults.pass_request_headers),
        pass_request_body: location
            .pass_request_body
            .unwrap_or(server_defaults.pass_request_body),
        ignore_accel_redirect: ignores(location.ignore_headers.as_deref(), "x-accel-redirect")
            .unwrap_or(server_defaults.ignore_accel_redirect),
        ignore_accel_limit_rate: ignores(location.ignore_headers.as_deref(), "x-accel-limit-rate")
            .unwrap_or(server_defaults.ignore_accel_limit_rate),
        set_body: location
            .set_body
            .map(prepare_value_parts)
            .or(server_defaults.set_body),
        connect_timeout_ms: location
            .connect_timeout_ms
            .unwrap_or(server_defaults.connect_timeout_ms),
        read_timeout_ms: location
            .read_timeout_ms
            .unwrap_or(server_defaults.read_timeout_ms),
        send_timeout_ms: location
            .send_timeout_ms
            .unwrap_or(server_defaults.send_timeout_ms),
        limit_rate: location
            .limit_rate
            .map(prepare_value_parts)
            .or(server_defaults.limit_rate),
        next_upstream: location
            .next_upstream
            .unwrap_or(server_defaults.next_upstream),
        next_upstream_tries: location
            .next_upstream_tries
            .unwrap_or(server_defaults.next_upstream_tries),
        next_upstream_timeout_ms: location
            .next_upstream_timeout_ms
            .unwrap_or(server_defaults.next_upstream_timeout_ms),
        intercept_errors: location
            .intercept_errors
            .unwrap_or(server_defaults.intercept_errors),
        force_ranges: location
            .force_ranges
            .unwrap_or(server_defaults.force_ranges),
        ignore_client_abort: location
            .ignore_client_abort
            .unwrap_or(server_defaults.ignore_client_abort),
        ignore_invalid_headers: server_defaults.ignore_invalid_headers,
        underscores_in_headers: server_defaults.underscores_in_headers,
        redirect: match location.redirect {
            Some(r) => Some(&*crate::arena::leak(Box::new(r))),
            None => server_defaults.redirect,
        },
        cookie_domain: match location.cookie_domain {
            Some(r) => Some(&*crate::arena::leak(Box::new(r))),
            None => server_defaults.cookie_domain,
        },
        cookie_path: match location.cookie_path {
            Some(r) => Some(&*crate::arena::leak(Box::new(r))),
            None => server_defaults.cookie_path,
        },
        cookie_flags: match location.cookie_flags {
            Some(r) => Some(&*crate::arena::leak(r.into_boxed_slice())),
            None => server_defaults.cookie_flags,
        },
        cache_ignore: cache_ignore(
            location.ignore_headers.as_deref(),
            server_defaults.cache_ignore,
        ),
        cache: crate::arena::leak(Box::new(location.cache.inherit(server_defaults.cache))),
        hide_headers: leak_list(location.hide_headers).or(server_defaults.hide_headers),
        pass_headers: leak_list(location.pass_headers).or(server_defaults.pass_headers),
        tls,
        bind: match location.bind {
            Some(bind) => prepare_bind(bind),
            None => server_defaults.bind,
        },
        resolver: match location.resolver {
            Some(resolver) => Some(prepare_resolver(resolver)),
            None => server_defaults.resolver,
        },
        resolver_timeout_ms: location
            .resolver_timeout_ms
            .unwrap_or(server_defaults.resolver_timeout_ms),
        // Filled in by the location once its error_page list is resolved.
        error_pages: &[],
        recursive_error_pages: false,
        proxy_method: location
            .proxy_method
            .map(prepare_value_parts)
            .or(server_defaults.proxy_method),
    }
}

/// What every server inherits from the http block, resolved once.
pub(crate) struct HttpScope {
    pub(crate) tokens: crate::config::ServerTokens,
    pub(crate) access_logs: &'static [PreparedAccessLog],
    pub(crate) error_logs: &'static [PreparedErrorLog],
    pub(crate) autoindex: bool,
    pub(crate) autoindex_exact_size: bool,
    pub(crate) autoindex_localtime: bool,
    pub(crate) autoindex_format: AutoindexFormat,
    pub(crate) if_modified_since: crate::config::IfModifiedSince,
    pub(crate) etag: bool,
    pub(crate) access: PreparedAccess,
    pub(crate) client_max_body_size: Option<u64>,
    pub(crate) max_ranges: Option<u32>,
    pub(crate) client_body_buffer_size: Option<u64>,
    pub(crate) sendfile: Option<bool>,
    pub(crate) disable_symlinks: Option<crate::config::DisableSymlinks>,
    pub(crate) limit_rate: PreparedLimitRate,
    pub(crate) post_action: Option<&'static [u8]>,
    pub(crate) expires: PreparedExpires,
    pub(crate) ignore_invalid_headers: bool,
    pub(crate) underscores_in_headers: bool,
}

pub(crate) fn prepare_server(
    mut server: Server,
    http: &HttpScope,
    upstreams: &UpstreamMap,
    alp: &mut AccessLogPrep<'_>,
) -> Result<PreparedServer, String> {
    let listen_port = server.listen.addr.port();
    let merge_slashes = server.merge_slashes.unwrap_or(true);
    let server_ignore_invalid_headers = server
        .ignore_invalid_headers
        .unwrap_or(http.ignore_invalid_headers);
    let server_underscores_in_headers = server
        .underscores_in_headers
        .unwrap_or(http.underscores_in_headers);
    let server_gzip = std::mem::take(&mut server.gzip);
    let server_proxy_defaults = ServerProxyDefaults::build(
        std::mem::take(&mut server.proxy),
        server_ignore_invalid_headers,
        server_underscores_in_headers,
    );
    // Split the parsed `server_name` specs into the four match buckets
    // plus the `matches_empty` flag. Lowercasing is already handled
    // inside `classify_server_name`, but we lowercase again on the way
    // out as a safety net.
    use crate::config::ServerNameSpec;
    let mut exact_names: Vec<&'static [u8]> = Vec::new();
    let mut wildcard_leading: Vec<&'static [u8]> = Vec::new();
    let mut wildcard_trailing: Vec<&'static [u8]> = Vec::new();
    let mut regex_names: Vec<PreparedRegexName> = Vec::new();
    let mut matches_empty = false;
    let mut first_display: Option<&'static [u8]> = None;
    for spec in server.server_names {
        if first_display.is_none() {
            let s = spec.display().as_bytes();
            first_display = Some(leak_bytes(s));
        }
        match spec {
            ServerNameSpec::Exact(s) => {
                let mut b = s.into_bytes();
                b.make_ascii_lowercase();
                exact_names.push(crate::arena::leak(b.into_boxed_slice()));
            }
            ServerNameSpec::WildcardLeading { suffix, .. } => {
                wildcard_leading.push(leak_bytes(suffix.as_bytes()));
            }
            ServerNameSpec::WildcardTrailing { head, .. } => {
                wildcard_trailing.push(leak_bytes(head.as_bytes()));
            }
            ServerNameSpec::Regex {
                pattern,
                case_insensitive,
                ..
            } => {
                let regex = crate::config::pcre::regex(&pattern, case_insensitive).unwrap_or_else(|e| {
                        panic!(
                            "ruxen: server_name regex {:?} failed to compile after parse-time validation: {e}",
                            pattern
                        )
                    });
                let capture_names: Vec<&'static str> = regex
                    .capture_names()
                    .flatten()
                    .map(|n| &*crate::arena::leak(n.to_ascii_lowercase().into_boxed_str()))
                    .collect();
                regex_names.push(PreparedRegexName {
                    regex,
                    capture_names,
                    set_pattern: set_pattern(&pattern, case_insensitive),
                });
            }
            ServerNameSpec::Empty => {
                matches_empty = true;
            }
        }
    }
    // Sort wildcard tables by descending length so the longest match
    // wins on a linear scan — mirrors nginx's hash-bucket choice
    // (`ngx_hash_combined_t`) which orders keys by suffix specificity.
    wildcard_leading.sort_by_key(|a| std::cmp::Reverse(a.len()));
    wildcard_trailing.sort_by_key(|a| std::cmp::Reverse(a.len()));

    let primary_server_name: &'static [u8] = first_display.unwrap_or(b"");

    // Inheritance: locations without their own `index` fall back to the
    // server-level list; if neither is set, we default to ["index.html"]
    // at the Root leaf. This matches ngx_http_index_module.c's merge_loc
    // semantics: child → parent → default.
    let server_index: Option<&'static [PreparedIndexEntry]> =
        server.index.map(prepare_index_entries);

    // add_header inheritance mirrors nginx's headers-filter merge
    // (ngx_http_headers_filter_module.c): child list replaces parent's
    // entirely when the child has any entries. If the child has none,
    // inherit. Resolve once here so the per-request path just reads a
    // `&'static [PreparedAddHeader]`.
    let server_add_headers: &'static [PreparedAddHeader] = match server.add_headers {
        Some(list) => prepare_add_headers(list),
        None => &[],
    };
    let server_add_trailers: &'static [PreparedAddHeader] = match server.add_trailers {
        Some(list) => prepare_add_headers(list),
        None => &[],
    };
    let server_error_pages: &'static [PreparedErrorPage] = match server.error_pages {
        Some(list) => prepare_error_pages(list),
        None => &[],
    };
    let server_keepalive = prepare_keepalive(
        server.keepalive_timeout,
        server.keepalive_requests,
        server.keepalive_time_ms,
        server.keepalive_disable,
    );
    let server_error_logs: &'static [PreparedErrorLog] = match server.error_logs {
        Some(list) => prepare_error_logs(list)?,
        None => http.error_logs,
    };
    let server_log_not_found = server.log_not_found.unwrap_or(true);
    let server_recursive_error_pages = server.recursive_error_pages.unwrap_or(false);
    let server_access = resolve_access(
        std::mem::take(&mut server.access),
        server.auth_basic.take(),
        server.auth_basic_user_file.take(),
        server.auth_delay_ms,
        http.access,
    );
    let server_client_max_body_size = server.client_max_body_size.or(http.client_max_body_size);
    let server_max_ranges = server.max_ranges.or(http.max_ranges);
    let server_client_body_buffer_size = server
        .client_body_buffer_size
        .or(http.client_body_buffer_size);
    let server_sendfile = server.sendfile.or(http.sendfile).unwrap_or(false);
    // A server's own `client_body_temp_path`; without one its locations
    // use the http-level directory (`PreparedHttp::body_temp`).
    let server_body_temp = server.client_body_temp_path.clone().map(BodyTempDir::leak);
    let server_disable_symlinks = server
        .disable_symlinks
        .clone()
        .or_else(|| http.disable_symlinks.clone());
    let server_limit_rate = PreparedLimitRate::inherit(
        server.limit_rate.take(),
        server.limit_rate_after.take(),
        http.limit_rate,
    );
    let server_post_action = server
        .post_action
        .as_ref()
        .map(|target| leak_bytes(target.as_bytes()))
        .or(http.post_action);
    let server_expires = server
        .expires
        .clone()
        .map(prepare_expires)
        .unwrap_or(http.expires);
    // chunked_transfer_encoding has no http-scope inheritance pathway in
    // ruxen yet; default to nginx's `on` when unset at server scope.
    let server_chunked_transfer_encoding = server.chunked_transfer_encoding.unwrap_or(true);
    let server_redirect = server.redirect.policy();
    let server_autoindex = server.autoindex.unwrap_or(http.autoindex);
    let server_autoindex_exact_size = server
        .autoindex_exact_size
        .unwrap_or(http.autoindex_exact_size);
    let server_autoindex_localtime = server
        .autoindex_localtime
        .unwrap_or(http.autoindex_localtime);
    let server_autoindex_format = server.autoindex_format.unwrap_or(http.autoindex_format);
    let server_if_modified_since = server.if_modified_since.unwrap_or(http.if_modified_since);
    let server_etag = server.etag.unwrap_or(http.etag);
    // server_tokens inheritance: server scope wins over http scope; both
    // default to `On`. Resolved once here; prepare_handler downstream
    // bakes the right `Server:` bytes into static prebuilts.
    let server_tokens_value = server.server_tokens.unwrap_or(http.tokens);
    let server_rewrite_program = prepare_rewrite_ops(
        std::mem::take(&mut server.rewrite_ops),
        server_tokens_value,
        prepare_types(&server.mime),
    );
    let server_header_bytes = http::server_header_value(server_tokens_value);
    // access_log inheritance: server-scope list (if set) replaces http;
    // None inherits the http-scope list. Empty `Some(vec![])` means the
    // user wrote `access_log off;` at server scope — explicit silence.
    let server_access_logs: &'static [PreparedAccessLog] = match server.access_logs {
        Some(ref list) => alp.prepare_list(list)?,
        None => http.access_logs,
    };
    // The cache of the scope a line is written in (#371); the locations
    // fall back to this one.
    alp.server_cache = server.open_log_file_cache.unwrap_or(alp.http_cache);
    let server_access_logs = alp.with_cache(server_access_logs, alp.server_cache);
    // Done last because Server can't be partially moved further down.

    let mut exact: Vec<PreparedLocation> = Vec::new();
    let mut prefix: Vec<PreparedLocation> = Vec::new();
    let mut regex: Vec<PreparedRegexLocation> = Vec::new();
    let mut named: Vec<PreparedLocation> = Vec::new();
    // The anonymous locations of location-level `if` blocks (#137), into
    // a list of their own: no request finds them by URI, the `if` that
    // holds switches to one by index.
    let mut locations = server.locations;
    let mut if_parsed: Vec<Location> = Vec::new();
    for l in &mut locations {
        take_if_locations(&mut l.rewrite_ops, &mut if_parsed, None);
    }
    let scope = ServerScope {
        index: server_index,
        add_headers: server_add_headers,
        add_trailers: server_add_trailers,
        error_pages: server_error_pages,
        keepalive: server_keepalive,
        error_logs: server_error_logs,
        log_not_found: server_log_not_found,
        recursive_error_pages: server_recursive_error_pages,
        tokens: server_tokens_value,
        autoindex: server_autoindex,
        autoindex_exact_size: server_autoindex_exact_size,
        autoindex_localtime: server_autoindex_localtime,
        autoindex_format: server_autoindex_format,
        if_modified_since: server_if_modified_since,
        etag: server_etag,
        access_logs: server_access_logs,
        access: server_access,
        client_max_body_size: server_client_max_body_size,
        max_ranges: server_max_ranges,
        client_body_buffer_size: server_client_body_buffer_size,
        sendfile: server_sendfile,
        body_temp: server_body_temp,
        disable_symlinks: server_disable_symlinks.clone(),
        limit_rate: server_limit_rate,
        post_action: server_post_action,
        expires: server_expires,
        chunked_transfer_encoding: server_chunked_transfer_encoding,
        limit_req: &server.limit_req,
        limit_conn: &server.limit_conn,
        client_timeouts: server.client_timeouts,
        proxy_defaults: server_proxy_defaults,
        gzip: &server_gzip,
    };
    let mut if_locations: Vec<PreparedLocation> = Vec::with_capacity(if_parsed.len());
    for l in if_parsed {
        if_locations.push(build_prefix_or_exact(l, &scope, upstreams, alp)?);
    }
    // Nesting: what each location, by its place in `locations`, is nested
    // in. The parser lists a location's nested ones (`descendants`) right
    // after it.
    let nesting: Option<Vec<Option<usize>>> =
        locations.iter().any(|l| l.descendants > 0).then(|| {
            let mut stack: Vec<(usize, usize)> = Vec::new();
            locations
                .iter()
                .enumerate()
                .map(|(i, l)| {
                    while stack.last().is_some_and(|&(_, end)| i >= end) {
                        stack.pop();
                    }
                    let parent = stack.last().map(|&(p, _)| p);
                    if l.descendants > 0 {
                        stack.push((i, i + 1 + l.descendants));
                    }
                    parent
                })
                .collect()
        });
    // Where each one went: its kind and index in that list (before the
    // exact and prefix lists are sorted).
    let mut placed: Vec<(MatchMode, usize)> = Vec::with_capacity(locations.len());
    for l in locations {
        placed.push((
            l.mode,
            match l.mode {
                MatchMode::Exact => exact.len(),
                MatchMode::Prefix => prefix.len(),
                MatchMode::Named => named.len(),
                MatchMode::Regex { .. } => regex.len(),
            },
        ));
        match l.mode {
            MatchMode::Exact => exact.push(build_prefix_or_exact(l, &scope, upstreams, alp)?),
            MatchMode::Prefix => prefix.push(build_prefix_or_exact(l, &scope, upstreams, alp)?),
            MatchMode::Named => named.push(build_prefix_or_exact(l, &scope, upstreams, alp)?),
            MatchMode::Regex { case_insensitive } => regex.push(build_regex_location(
                l,
                case_insensitive,
                &scope,
                upstreams,
                alp,
            )?),
        }
    }
    // Sorted through a permutation, so `placed` can follow.
    let sorted = |len: usize, key: &dyn Fn(usize, usize) -> std::cmp::Ordering| {
        let mut order: Vec<usize> = (0..len).collect();
        order.sort_by(|&a, &b| key(a, b));
        let mut at = vec![0; len];
        for (new, &old) in order.iter().enumerate() {
            at[old] = new;
        }
        (order, at)
    };
    let (exact_order, exact_at) =
        sorted(exact.len(), &|a, b| exact[a].pattern.cmp(exact[b].pattern));
    let (prefix_order, prefix_at) = sorted(prefix.len(), &|a, b| {
        prefix[b].pattern.len().cmp(&prefix[a].pattern.len())
    });
    let exact = permute(exact, &exact_order);
    let prefix = permute(prefix, &prefix_order);
    for (mode, index) in &mut placed {
        match mode {
            MatchMode::Exact => *index = exact_at[*index],
            MatchMode::Prefix => *index = prefix_at[*index],
            _ => {}
        }
    }
    let location_tree = nesting
        .map(|parents| Box::new(location_tree(&placed, &parents, prefix.len(), regex.len())));
    // regex_locations stay in declaration order — first match wins.

    // Synthesize a nameless catch-all PreparedLocation for requests the
    // location search doesn't match: nginx then handles them with the
    // server's own configuration (ngx_http_core_find_config_phase keeps
    // the server's loc_conf), so its static handler serves from the
    // server's root, or `html`. Only a prefix `/` location matches every
    // URI and makes it unreachable; `location = /` doesn't.
    // (A server-scope `return` is part of the server rewrite program, which
    // runs before the location search, as in nginx.)
    // The prepared location inherits the server's add_header / error_page
    // lists via the same path explicit locations use.
    let have_root_catchall = prefix.iter().any(|l| l.pattern == b"/");
    // The server's own root (else nginx's `html`): its rewrite phase's
    // `$request_filename`, and its implicit `/` location's.
    let server_doc_root = leak_doc_root(
        (
            server.root.clone().unwrap_or_else(|| "html".into()),
            PathMapping::Root,
        ),
        b"/",
        false,
        None,
        server_disable_symlinks.clone(),
        prepare_charset(&server.charset),
    );
    let server_default = if !have_root_catchall {
        let root_path = server.root.clone().unwrap_or_else(|| "html".into());
        let pattern: &'static [u8] = b"/";
        let site = HandlerSite {
            pattern,
            is_regex: false,
            alias_prefix_override: None,
            server_index,
            autoindex: server_autoindex,
            autoindex_exact_size: server_autoindex_exact_size,
            autoindex_localtime: server_autoindex_localtime,
            autoindex_format: server_autoindex_format,
            if_modified_since: server_if_modified_since,
            etag: server_etag,
            disable_symlinks: server_disable_symlinks.clone(),
            mime: &server.mime,
            tokens: server_tokens_value,
            upstreams,
        };
        let handler = build_handler(
            Handler::Root {
                path: root_path,
                mapping: PathMapping::Root,
            },
            None,
            None,
            ProxyEffective::defaults(),
            &site,
        )?;
        Some(PreparedLocation {
            pattern,
            handler,
            auto_redirect: false,
            noregex: false,
            rewrite_program: &[],
            add_headers: server_add_headers,
            add_trailers: server_add_trailers,
            error_pages: server_error_pages,
            keepalive: server_keepalive,
            error_logs: server_error_logs,
            log_not_found: server_log_not_found,
            recursive_error_pages: server_recursive_error_pages,
            internal: false,
            server_header: server_header_bytes,
            access_logs: server_access_logs,
            access: server_access,
            limit_except: None,
            client_max_body_size: server_client_max_body_size,
            max_ranges: server_max_ranges,
            client_body_buffer_size: server_client_body_buffer_size,
            sendfile: server_sendfile,
            gzip: prepare_gzip(server_gzip.clone())?,
            limit_rate: server_limit_rate.for_location(),
            client_body_in_file_only: crate::config::ClientBodyInFileOnly::Off,
            body_temp: server_body_temp,
            doc_root: server_doc_root,
            post_action: server_post_action,
            expires: server_expires,
            chunked_transfer_encoding: server_chunked_transfer_encoding,
            redirect: server.redirect.policy(),
            limit_req: prepare_limit_req(server.limit_req.clone())?,
            limit_conn: prepare_limit_conn(server.limit_conn.clone())?,
            timeouts: crate::arena::leak(Box::new(PreparedClientTimeouts::resolve(
                server.client_timeouts,
            ))),
        })
    } else {
        None
    };

    Ok(PreparedServer {
        metrics_slot: super::metrics::server_slot(
            primary_server_name,
            match &server.listen.unix {
                Some(path) => format!("unix:{}", path.display()),
                None => server.listen.addr.to_string(),
            },
        ),
        doc_root: server_doc_root,
        charset: prepare_charset(&server.charset),
        // Set by the caller, which knows the http scope.
        http2: false,
        tls_context: None,
        client_verify: crate::config::VerifyClient::Off,
        h2: Default::default(),
        keepalive: server_keepalive,
        timeouts: PreparedClientTimeouts::resolve(server.client_timeouts),
        exact_names,
        wildcard_leading,
        wildcard_trailing,
        regex_names,
        matches_empty,
        primary_server_name,
        redirect: server_redirect,
        listen_port,
        exact_locations: exact,
        prefix_locations: prefix,
        regex_location_set: first_match_set(regex.iter().map(|r| r.set_pattern.as_str())),
        regex_locations: regex,
        named_locations: named,
        location_tree,
        if_locations,
        server_default,
        error_logs: server_error_logs,
        log_not_found: server_log_not_found,
        merge_slashes,
        server_header: server_header_bytes,
        access_logs: server_access_logs,
        access: server_access,
        // nginx's parser keeps a name with `_` with either (#624).
        underscores_in_headers: server_underscores_in_headers || !server_ignore_invalid_headers,
        post_action: server_post_action,
        rewrite_program: server_rewrite_program,
        add_headers: server_add_headers,
        error_pages: server_error_pages,
    })
}

/// `list` in the order of `order`'s indices.
fn permute<T>(list: Vec<T>, order: &[usize]) -> Vec<T> {
    let mut slots: Vec<Option<T>> = list.into_iter().map(Some).collect();
    order.iter().map(|&i| slots[i].take().unwrap()).collect()
}

/// The nesting nginx searches (ngx_http_core_find_location): each location
/// in its parent's level, the server's being level 0. `placed[i]` is where
/// the server's `i`th location went, `parents[i]` what it is nested in.
/// A level's prefix locations are kept longest first, as the sorted list
/// is, and its regex ones in declaration order.
fn location_tree(
    placed: &[(MatchMode, usize)],
    parents: &[Option<usize>],
    prefixes: usize,
    regexes: usize,
) -> LocationTree {
    let mut tree = LocationTree {
        levels: vec![LocationLevel::default()],
        prefix_children: vec![None; prefixes],
        regex_children: vec![None; regexes],
    };
    // The level of the locations nested in location `i`, made on first use.
    let level_of = |tree: &mut LocationTree, i: usize| -> usize {
        let slot = match placed[i] {
            (MatchMode::Prefix, k) => &mut tree.prefix_children[k],
            (MatchMode::Regex { .. }, k) => &mut tree.regex_children[k],
            // nginx refuses locations in exact or named ones; the flat
            // lists have them.
            _ => return 0,
        };
        match *slot {
            Some(level) => level as usize,
            None => {
                let level = tree.levels.len();
                *slot = Some(level as u16);
                tree.levels.push(LocationLevel::default());
                level
            }
        }
    };
    for (i, &(mode, index)) in placed.iter().enumerate() {
        let level = match parents[i] {
            Some(p) => level_of(&mut tree, p),
            None => 0,
        };
        let level = &mut tree.levels[level];
        match mode {
            MatchMode::Exact => level.exact.push(index as u16),
            MatchMode::Prefix => level.prefix.push(index as u16),
            MatchMode::Regex { .. } => level.regex.push(index as u16),
            MatchMode::Named => {}
        }
    }
    for level in &mut tree.levels {
        // Longest first: the sorted list's order is by index.
        level.prefix.sort_unstable();
    }
    tree
}

pub(crate) fn prepare_add_headers(list: Vec<AddHeader>) -> &'static [PreparedAddHeader] {
    let prepared: Vec<PreparedAddHeader> = list
        .into_iter()
        .map(|h| PreparedAddHeader {
            name: leak_bytes(h.name.as_bytes()),
            value: prepare_value_parts(h.value),
            always: h.always,
        })
        .collect();
    crate::arena::leak(prepared.into_boxed_slice())
}

pub(crate) fn prepare_index_entries(list: Vec<IndexEntry>) -> &'static [PreparedIndexEntry] {
    let prepared: Vec<PreparedIndexEntry> = list
        .into_iter()
        .map(|entry| PreparedIndexEntry {
            parts: prepare_value_parts(entry.parts),
        })
        .collect();
    crate::arena::leak(prepared.into_boxed_slice())
}

pub(crate) fn prepare_error_pages(list: Vec<ErrorPage>) -> &'static [PreparedErrorPage] {
    let prepared: Vec<PreparedErrorPage> = list
        .into_iter()
        .map(|ep| PreparedErrorPage {
            status: ep.status,
            action: match ep.action {
                ErrorPageAction::PreserveOriginal => PreparedErrorPageAction::PreserveOriginal,
                ErrorPageAction::UseTargetStatus => PreparedErrorPageAction::UseTargetStatus,
                ErrorPageAction::Override(code) => PreparedErrorPageAction::Override(code),
            },
            target: prepare_value_parts(ep.target),
        })
        .collect();
    crate::arena::leak(prepared.into_boxed_slice())
}

pub(crate) fn prepare_expires(d: ExpiresDirective) -> PreparedExpires {
    match d {
        ExpiresDirective::Off => PreparedExpires::Off,
        ExpiresDirective::Epoch => PreparedExpires::Epoch,
        ExpiresDirective::Max => PreparedExpires::Max,
        ExpiresDirective::Access(s) => PreparedExpires::Access(s),
        ExpiresDirective::Modified(s) => PreparedExpires::Modified(s),
        ExpiresDirective::Daily(s) => PreparedExpires::Daily(s),
        ExpiresDirective::Variable(parts) => PreparedExpires::Variable(prepare_value_parts(parts)),
        ExpiresDirective::VariableModified(parts) => {
            PreparedExpires::VariableModified(prepare_value_parts(parts))
        }
    }
}

pub(crate) fn prepare_value_parts(parts: Vec<ValuePart>) -> &'static [PreparedValuePart] {
    let v: Vec<PreparedValuePart> = parts
        .into_iter()
        .map(|p| match p {
            ValuePart::Literal(s) => PreparedValuePart::Literal(leak_bytes(s.as_bytes())),
            ValuePart::Var(v) => PreparedValuePart::Var(v),
        })
        .collect();
    crate::arena::leak(v.into_boxed_slice())
}

pub(crate) fn leak_regex(regex: regex::bytes::Regex) -> &'static regex::bytes::Regex {
    crate::arena::leak(Box::new(regex))
}

pub(crate) fn prepare_guard(guard: IfGuard) -> PreparedGuard {
    match guard {
        IfGuard::VarTruthy(var) => PreparedGuard::VarTruthy(var),
        IfGuard::Eq { left, right } => PreparedGuard::Eq {
            left,
            right: prepare_value_parts(right),
        },
        IfGuard::NotEq { left, right } => PreparedGuard::NotEq {
            left,
            right: prepare_value_parts(right),
        },
        IfGuard::Regex {
            left,
            pattern,
            case_insensitive,
            negated,
        } => {
            let regex = crate::config::pcre::regex(&pattern, case_insensitive)
                .unwrap_or_else(|e| panic!("ruxen: if regex {:?} failed to compile: {e}", pattern));
            PreparedGuard::Regex {
                left,
                regex: leak_regex(regex),
                negated,
            }
        }
        IfGuard::FileTest {
            kind,
            path,
            negated,
        } => PreparedGuard::FileTest {
            kind,
            path: prepare_value_parts(path),
            negated,
        },
    }
}

/// Move the anonymous locations of `ops`' `if` blocks (nested ones too)
/// into `out`, leaving their index there (#137). A block of rewrite
/// directives only inside one gets that one's index: nginx gives every
/// location-level `if` a configuration, merged from the enclosing one, so
/// the request goes on with the configuration it was in.
fn take_if_locations(ops: &mut [RewriteOp], out: &mut Vec<Location>, enclosing: Option<usize>) {
    use crate::config::IfLocation;
    for op in ops {
        if let RewriteOp::If { body, location, .. } = op {
            let slot = match location.take() {
                Some(IfLocation::Parsed {
                    location: parsed, ..
                }) => {
                    out.push(*parsed);
                    Some(out.len() - 1)
                }
                Some(IfLocation::Slot(n)) => Some(n),
                None => enclosing,
            };
            *location = slot.map(IfLocation::Slot);
            take_if_locations(body, out, slot);
        }
    }
}

pub(crate) fn prepare_rewrite_ops(
    ops: Vec<RewriteOp>,
    tokens: crate::config::ServerTokens,
    types: &'static PreparedTypes,
) -> &'static [PreparedRewriteOp] {
    if ops.is_empty() {
        return &[];
    }
    let mut prepared: Vec<PreparedRewriteOp> = Vec::with_capacity(ops.len());
    for op in ops {
        let prepared_op = match op {
            RewriteOp::Set { name, value } if name.eq_ignore_ascii_case("args") => {
                PreparedRewriteOp::SetArgs(prepare_value_parts(value))
            }
            RewriteOp::Set { name, value } => PreparedRewriteOp::Set {
                name: leak_bytes(name.as_bytes()),
                value: prepare_value_parts(value),
            },
            RewriteOp::If {
                guard,
                body,
                location,
            } => PreparedRewriteOp::If {
                guard: prepare_guard(guard),
                body: prepare_rewrite_ops(body, tokens, types),
                // `prepare_server` moved every parsed one into the server's
                // list first.
                location: match location {
                    Some(crate::config::IfLocation::Slot(n)) => Some(n as u32),
                    _ => None,
                },
            },
            RewriteOp::Rewrite(RewriteRule {
                regex,
                replacement,
                replacement_args,
                flag,
                drop_args,
            }) => {
                let regex = crate::config::pcre::regex(&regex, false).unwrap_or_else(|e| {
                    panic!("ruxen: rewrite regex {:?} failed to compile: {e}", regex)
                });
                PreparedRewriteOp::Rewrite {
                    regex: leak_regex(regex),
                    replacement_uri: prepare_value_parts(replacement),
                    replacement_args: replacement_args.map(prepare_value_parts),
                    flag: match flag {
                        ConfigRewriteFlag::None => PreparedRewriteFlag::None,
                        ConfigRewriteFlag::Last => PreparedRewriteFlag::Last,
                        ConfigRewriteFlag::Break => PreparedRewriteFlag::Break,
                        ConfigRewriteFlag::Redirect => PreparedRewriteFlag::Redirect,
                        ConfigRewriteFlag::Permanent => PreparedRewriteFlag::Permanent,
                    },
                    drop_args,
                }
            }
            RewriteOp::Return { status, body } => {
                let finalized = body.is_empty() || matches!(status, 301 | 302 | 303 | 307 | 308);
                PreparedRewriteOp::Return(prepare_return(status, body, tokens, types), finalized)
            }
            RewriteOp::Break => PreparedRewriteOp::Break,
        };
        prepared.push(prepared_op);
    }
    crate::arena::leak(prepared.into_boxed_slice())
}

pub(crate) fn prepare_split_clients(
    blocks: Vec<SplitClients>,
) -> std::collections::HashMap<&'static str, PreparedSplitClients> {
    let mut out = std::collections::HashMap::new();
    for block in blocks {
        let mut parts: Vec<PreparedSplitClientsPart> = Vec::with_capacity(block.parts.len());
        for part in block.parts {
            parts.push(PreparedSplitClientsPart {
                threshold: part.threshold,
                value: prepare_value_parts(part.value),
            });
        }
        let prepared = PreparedSplitClients {
            key: prepare_value_parts(block.key),
            parts: crate::arena::leak(parts.into_boxed_slice()),
        };
        let key: &'static str = crate::arena::leak(block.variable.into_boxed_str());
        out.insert(key, prepared);
    }
    out
}

/// Turn parsed `map` blocks into a `variable -> PreparedMap` lookup.
///
/// The exact-match table is a `HashMap<Vec<u8>, …>` keyed on the raw
/// rendered source bytes: nginx `map` matches are byte-exact on the
/// string value (unless the regex modifier is used), so we do the same.
/// Regex entries compile into `regex::bytes::Regex` so they match against
/// the same byte slice as the source render.
pub(crate) fn prepare_maps(
    blocks: Vec<MapBlock>,
) -> std::collections::HashMap<&'static str, PreparedMap> {
    let mut out = std::collections::HashMap::new();
    for (slot, block) in blocks.into_iter().enumerate() {
        let MapBlock {
            key,
            variable,
            exact,
            regex,
            default,
            hostnames,
            wildcards,
            volatile,
        } = block;
        // Caching only shows when a result could differ later in the
        // request; a map of request constants (headers, literals) gives
        // the same value every time.
        let cached = !volatile
            && !(request_constant(&key)
                && exact.iter().all(|e| request_constant(&e.value))
                && wildcards.iter().all(|e| request_constant(&e.value))
                && regex.iter().all(|e| request_constant(&e.value))
                && default.as_deref().is_none_or(request_constant));
        let mut exact_map: std::collections::HashMap<Vec<u8>, &'static [PreparedValuePart]> =
            std::collections::HashMap::with_capacity(exact.len());
        for MapExactEntry { key: k, value } in exact {
            exact_map.insert(
                k.to_ascii_lowercase().into_bytes(),
                prepare_value_parts(value),
            );
        }
        let mut wildcard_head = Vec::new();
        let mut wildcard_tail = Vec::new();
        for MapExactEntry { key: k, value } in wildcards {
            let k = k.to_ascii_lowercase();
            let value = prepare_value_parts(value);
            if let Some(suffix) = k.strip_prefix("*.") {
                wildcard_head.push((suffix.as_bytes().to_vec(), false, value));
            } else if let Some(suffix) = k.strip_prefix('.') {
                wildcard_head.push((suffix.as_bytes().to_vec(), true, value));
            } else if let Some(head) = k.strip_suffix(".*") {
                wildcard_tail.push((head.as_bytes().to_vec(), value));
            }
        }
        let mut regex_entries: Vec<PreparedMapRegex> = Vec::with_capacity(regex.len());
        let mut regex_set_patterns: Vec<String> = Vec::with_capacity(regex.len());
        for MapRegexEntry {
            pattern,
            case_insensitive,
            value,
        } in regex
        {
            let pattern = crate::config::pcre::translate(&pattern);
            regex_set_patterns.push(set_pattern(&pattern, case_insensitive));
            // Already validated at parse time; a failure here is a bug.
            let compiled = crate::config::pcre::regex(&pattern, case_insensitive)
                .expect("map regex validated at parse time");
            regex_entries.push(PreparedMapRegex {
                regex: compiled,
                value: prepare_value_parts(value),
            });
        }
        let regex_set = first_match_set(regex_set_patterns.iter().map(String::as_str));
        let prepared = PreparedMap {
            regex_set,
            key: prepare_value_parts(key),
            exact: exact_map,
            hostnames,
            wildcard_head: crate::arena::leak(wildcard_head.into_boxed_slice()),
            wildcard_tail: crate::arena::leak(wildcard_tail.into_boxed_slice()),
            regex: crate::arena::leak(regex_entries.into_boxed_slice()),
            default: default.map(prepare_value_parts),
            cached,
            slot,
        };
        let var_key: &'static str = crate::arena::leak(variable.into_boxed_str());
        out.insert(var_key, prepared);
    }
    out
}

/// Whether `parts` render the same all through a request: literals and
/// variables nothing in the request changes (not `$uri`, `$args`, `set`
/// or other maps' values, captures, `$request_method`, which an
/// X-Accel-Redirect turns into GET, `$remote_addr`, which a location's
/// realip settings change, or anything upstream or response).
fn request_constant(parts: &[ValuePart]) -> bool {
    parts.iter().all(|part| match part {
        ValuePart::Literal(_) => true,
        ValuePart::Var(v) => matches!(
            v,
            Variable::RequestUri
                | Variable::Host
                | Variable::Scheme
                | Variable::Https
                | Variable::Http(_)
                | Variable::Cookie(_)
                | Variable::ContentLength
                | Variable::ContentType
                | Variable::RealIpRemoteAddr
                | Variable::RealIpRemotePort
                | Variable::Hostname
                | Variable::Pid
                | Variable::RequestId
                | Variable::Connection
                | Variable::ConnectionRequests
                | Variable::ServerPort
                | Variable::ServerAddr
                | Variable::RequestPort
                | Variable::IsRequestPort
                | Variable::Request
                | Variable::ServerProtocol
                | Variable::Http2
                | Variable::SslProtocol
                | Variable::SslCipher
                | Variable::SslCiphers
                | Variable::SslServerName
                | Variable::SslSessionReused
                | Variable::SslSessionId
                | Variable::ProxyProtocolAddr
                | Variable::ProxyProtocolPort
                | Variable::ProxyProtocolServerAddr
                | Variable::ProxyProtocolServerPort
                | Variable::ProxyProtocolTlv(_)
        ),
    })
}

/// Builder used during `prepare()` to assign sequential `file_index`
/// values to every `PreparedAccessLog` across http / server / location
/// scopes. The canonical list (`PreparedHttp::access_logs`) is the
/// concatenation of every prepared sink in declaration order; per-scope
/// slices share `file_index` values that point back into it, so the
/// per-worker fd table opened from the canonical list serves all scopes.
/// A `syslog:` peer for `access_log` or `error_log`. A UDP server is
/// resolved now, so a bad host fails at startup, as nginx's ngx_parse_url
/// does.
fn prepare_syslog_peer(
    peer: &crate::config::SyslogPeer,
) -> Result<&'static PreparedSyslogPeer, String> {
    let server = match &peer.server {
        ErrorLogSyslogServer::Unix(path) => {
            PreparedErrorLogSyslogServer::Unix(crate::arena::leak(path.clone().into_boxed_path()))
        }
        ErrorLogSyslogServer::Udp(addr) => {
            crate::syslog::resolve(addr).map_err(|e| format!("syslog server \"{addr}\": {e}"))?;
            PreparedErrorLogSyslogServer::Udp(crate::arena::leak(addr.clone().into_boxed_str()))
        }
    };
    // nginx's default tag is `nginx`; ruxen's own name, unless it presents
    // itself as nginx (RUXEN_NGINX_IDENTITY, as for `Server:`).
    let tag: &'static [u8] = match &peer.tag {
        Some(tag) => crate::arena::leak(tag.clone().into_bytes().into_boxed_slice()),
        None => crate::http::identity().plain,
    };
    Ok(crate::arena::leak(Box::new(PreparedSyslogPeer {
        server,
        facility: peer.facility,
        severity: peer.severity,
        tag,
        nohostname: peer.nohostname,
    })))
}

pub(crate) struct AccessLogPrep<'a> {
    format_map: std::collections::HashMap<&'a str, &'a LogFormatDef>,
    canonical: Vec<PreparedAccessLog>,
    /// `open_log_file_cache` at http scope, and for the server being
    /// prepared (#371).
    pub(crate) http_cache: Option<OpenLogFileCache>,
    pub(crate) server_cache: Option<OpenLogFileCache>,
    /// One `&'static` per directive (`OpenLogFileCache::id`).
    caches: std::collections::HashMap<u32, &'static OpenLogFileCache>,
    /// Buffered files by path.
    buffers: std::collections::HashMap<std::path::PathBuf, &'static PreparedLogBuffer>,
    /// Each file opened once, by path (#523).
    files: std::collections::HashMap<std::path::PathBuf, &'static std::fs::File>,
}

impl<'a> AccessLogPrep<'a> {
    pub(crate) fn new(formats: &'a [LogFormatDef]) -> Self {
        let mut format_map: std::collections::HashMap<&'a str, &'a LogFormatDef> =
            std::collections::HashMap::new();
        for f in formats {
            format_map.insert(f.name.as_str(), f);
        }
        Self {
            format_map,
            canonical: Vec::new(),
            http_cache: None,
            server_cache: None,
            caches: std::collections::HashMap::new(),
            buffers: std::collections::HashMap::new(),
            files: std::collections::HashMap::new(),
        }
    }

    pub(crate) fn prepare_one(&mut self, log: &AccessLog) -> Result<PreparedAccessLog, String> {
        // nginx default format name.
        const DEFAULT_FORMAT_NAME: &str = "combined";
        let chosen_format = log.format.as_deref().unwrap_or(DEFAULT_FORMAT_NAME);
        let (format, escape) = if let Some(def) = self.format_map.get(chosen_format) {
            (prepare_value_parts(def.value.clone()), def.escape)
        } else if chosen_format == DEFAULT_FORMAT_NAME {
            // nginx's predefined `combined` format.
            let parts = crate::config::parse_value_with_vars(
                "$remote_addr - $remote_user [$time_local] \"$request\" $status \
                 $body_bytes_sent \"$http_referer\" \"$http_user_agent\"",
            )
            .map_err(|e| e.to_string())?;
            (prepare_value_parts(parts), LogEscape::Default)
        } else {
            return Err(format!("unknown log format \"{chosen_format}\""));
        };
        // Create the file up front, as nginx does at startup: an unwritable
        // path fails here rather than in every worker, and tests that read
        // the log don't hit ENOENT when no request matches `if=...`.
        // Once per path, kept open for the workers (#523): a FIFO's reader
        // sees one writer, not an open and close per worker.
        let (syslog, file) = match &log.syslog {
            Some(peer) => (Some(prepare_syslog_peer(peer)?), None),
            // Opened per line, under a name only a request gives.
            None if log.path_vars.is_some() => (None, None),
            None => match self.files.get(&log.path) {
                Some(file) => (None, Some(*file)),
                None => {
                    let file: &'static std::fs::File =
                        crate::arena::leak(Box::new(open_access_log_file(&log.path)?));
                    self.files.insert(log.path.clone(), file);
                    (None, Some(file))
                }
            },
        };

        let buffer = match log.buffer {
            None => None,
            Some(size) => {
                let wanted = (size as usize, log.flush_ms, log.gzip);
                if let Some(known) = self.buffers.get(&log.path) {
                    if (known.size, known.flush_ms, known.gzip) != wanted {
                        return Err(format!(
                            "access_log \"{}\" already defined with conflicting parameters",
                            log.path.display()
                        ));
                    }
                    Some(*known)
                } else {
                    // In the arena: `logbuf`'s registry lets go of it
                    // when the generation is retired (#528).
                    let buffer: &'static PreparedLogBuffer =
                        crate::arena::leak(Box::new(PreparedLogBuffer {
                            slot: self.buffers.len(),
                            size: wanted.0,
                            flush_ms: wanted.1,
                            gzip: wanted.2,
                            path: crate::arena::leak(log.path.clone().into_boxed_path()),
                        }));
                    self.buffers.insert(log.path.clone(), buffer);
                    Some(buffer)
                }
            }
        };
        let file_index = self.canonical.len();
        let path_vars = log.path_vars.clone().map(prepare_value_parts);
        let condition = log.condition.clone().map(prepare_value_parts);
        let reads_doc_root = [Some(format), path_vars, condition]
            .into_iter()
            .flatten()
            .flatten()
            .any(|p| {
                matches!(
                    p,
                    PreparedValuePart::Var(
                        Variable::DocumentRoot | Variable::RequestFilename | Variable::RealpathRoot
                    )
                )
            });
        let prepared = PreparedAccessLog {
            file,
            buffer,
            open_cache: None,
            path_vars,
            path: crate::arena::leak(log.path.clone().into_boxed_path()),
            format,
            escape,
            reads_upstream_headers: format.iter().any(|p| {
                matches!(
                    p,
                    PreparedValuePart::Var(Variable::UpstreamHttp(_) | Variable::UpstreamCookie(_))
                )
            }),
            reads_doc_root,
            condition,
            file_index,
            syslog,
        };
        self.canonical.push(prepared);
        Ok(prepared)
    }

    pub(crate) fn prepare_list(
        &mut self,
        list: &[AccessLog],
    ) -> Result<&'static [PreparedAccessLog], String> {
        if list.is_empty() {
            return Ok(&[]);
        }
        let prepared: Vec<PreparedAccessLog> = list
            .iter()
            .map(|l| self.prepare_one(l))
            .collect::<Result<_, _>>()?;
        Ok(crate::arena::leak(prepared.into_boxed_slice()))
    }

    /// `list` as written from a scope with `cache` as its
    /// `open_log_file_cache`: the entries with variables in the path take
    /// it, as nginx takes the cache of the location the line is written
    /// in. The same list when nothing changes.
    pub(crate) fn with_cache(
        &mut self,
        list: &'static [PreparedAccessLog],
        cache: Option<OpenLogFileCache>,
    ) -> &'static [PreparedAccessLog] {
        let cache = cache.map(|c| {
            *self
                .caches
                .entry(c.id)
                .or_insert_with(|| crate::arena::leak(Box::new(c)))
        });
        let same = |log: &PreparedAccessLog| {
            log.path_vars.is_none() || log.open_cache.map(|c| c.id) == cache.map(|c| c.id)
        };
        if list.iter().all(same) {
            return list;
        }
        let copied: Vec<PreparedAccessLog> = list
            .iter()
            .map(|log| PreparedAccessLog {
                open_cache: if log.path_vars.is_some() {
                    cache
                } else {
                    log.open_cache
                },
                ..*log
            })
            .collect();
        crate::arena::leak(copied.into_boxed_slice())
    }

    pub(crate) fn finish(self) -> &'static [PreparedAccessLog] {
        crate::arena::leak(self.canonical.into_boxed_slice())
    }
}

pub(crate) fn prepare_keepalive(
    timeout: Option<KeepaliveTimeout>,
    keepalive_requests: Option<u64>,
    keepalive_time_ms: Option<u64>,
    keepalive_disable: Option<KeepaliveDisable>,
) -> PreparedKeepalive {
    let max_requests = keepalive_requests.unwrap_or(DEFAULT_KEEPALIVE_REQUESTS);
    let max_time_ms = keepalive_time_ms.unwrap_or(DEFAULT_KEEPALIVE_TIME_MS);
    let keepalive_disable = keepalive_disable.unwrap_or(KeepaliveDisable {
        msie6: true,
        safari: false,
    });
    match timeout {
        Some(raw) => PreparedKeepalive {
            allow: raw.timeout_ms > 0,
            idle_timeout_ms: if raw.timeout_ms > 0 {
                Some(raw.timeout_ms)
            } else {
                None
            },
            header_timeout_secs: if raw.timeout_ms > 0 {
                raw.header_timeout_secs
            } else {
                None
            },
            max_requests,
            max_time_ms,
            disable_msie6: keepalive_disable.msie6,
            disable_safari: keepalive_disable.safari,
        },
        None => PreparedKeepalive {
            allow: true,
            idle_timeout_ms: None,
            header_timeout_secs: None,
            max_requests,
            max_time_ms,
            disable_msie6: keepalive_disable.msie6,
            disable_safari: keepalive_disable.safari,
        },
    }
}

pub(crate) fn prepare_auth_basic(raw: AuthBasic) -> PreparedAuthBasic {
    match raw {
        AuthBasic::Off => PreparedAuthBasic::Off,
        AuthBasic::Realm(bytes) => {
            PreparedAuthBasic::Realm(crate::arena::leak(bytes.into_boxed_slice()))
        }
    }
}

pub(crate) fn leak_path_buf(path: std::path::PathBuf) -> &'static Path {
    crate::arena::leak(path.into_boxed_path())
}

pub(crate) fn resolve_keepalive(
    location_keepalive: Option<KeepaliveTimeout>,
    location_keepalive_requests: Option<u64>,
    location_keepalive_time_ms: Option<u64>,
    location_keepalive_disable: Option<KeepaliveDisable>,
    server_keepalive: PreparedKeepalive,
) -> PreparedKeepalive {
    let mut resolved = server_keepalive;
    if let Some(raw) = location_keepalive {
        resolved.allow = raw.timeout_ms > 0;
        resolved.idle_timeout_ms = if raw.timeout_ms > 0 {
            Some(raw.timeout_ms)
        } else {
            None
        };
        resolved.header_timeout_secs = if raw.timeout_ms > 0 {
            raw.header_timeout_secs
        } else {
            None
        };
    }
    if let Some(max) = location_keepalive_requests {
        resolved.max_requests = max;
    }
    if let Some(max_time_ms) = location_keepalive_time_ms {
        resolved.max_time_ms = max_time_ms;
    }
    if let Some(disable) = location_keepalive_disable {
        resolved.disable_msie6 = disable.msie6;
        resolved.disable_safari = disable.safari;
    }
    resolved
}

pub(crate) fn all_literal(parts: &[ValuePart]) -> bool {
    parts.iter().all(|p| matches!(p, ValuePart::Literal(_)))
}

pub(crate) fn concat_literals(parts: &[ValuePart]) -> String {
    let mut out = String::new();
    for p in parts {
        if let ValuePart::Literal(s) = p {
            out.push_str(s);
        }
    }
    out
}

/// A top-level `return` is a rewrite directive in nginx: a `break` (the
/// directive, or `rewrite … break`) stops the location's rewrite program
/// before it, and the static module answers (#697). ruxen makes such a
/// `return` the location's handler; where the program can break, the
/// `return` goes to its end instead and the location serves files from
/// its root, as nginx's location would.
fn return_after_break(
    handler: Handler,
    mut ops: Vec<RewriteOp>,
    root: &(std::path::PathBuf, PathMapping),
) -> (Handler, Vec<RewriteOp>) {
    fn breaks(ops: &[RewriteOp]) -> bool {
        ops.iter().any(|op| match op {
            RewriteOp::Break => true,
            RewriteOp::Rewrite(rule) => rule.flag == crate::config::RewriteFlag::Break,
            RewriteOp::If { body, .. } => breaks(body),
            _ => false,
        })
    }
    match handler {
        Handler::Return { status, body } if breaks(&ops) => {
            ops.push(RewriteOp::Return { status, body });
            let handler = Handler::Root {
                path: root.0.clone(),
                mapping: root.1,
            };
            (handler, ops)
        }
        handler => (handler, ops),
    }
}

pub(crate) fn prepare_return(
    status: u16,
    body: Vec<ValuePart>,
    tokens: crate::config::ServerTokens,
    types: &'static PreparedTypes,
) -> PreparedReturn {
    let types = (!is_redirect_status(status)).then_some(types);
    let server_bytes = http::server_header_value(tokens);
    // A redirect to a path goes out as `absolute_redirect` makes it, with
    // the request's host (#15): rendered per request.
    let relative_redirect = is_redirect_status(status)
        && matches!(body.first(), Some(ValuePart::Literal(s)) if s.starts_with('/'));
    if all_literal(&body) && !relative_redirect {
        let concatenated = concat_literals(&body);
        // A redirect status is a redirect whatever its URL, an empty one
        // included: nginx's `ngx_http_send_response` sends an empty
        // `Location` then (#374).
        let prebuilt = if is_redirect_status(status) {
            Prebuilt::leak_redirect(status, concatenated.as_bytes(), server_bytes)
        } else if body.is_empty() {
            // `return STATUS;` with no body: when the status has a canned
            // nginx error page (4xx/5xx), substitute it — including the
            // `<center>nginx/X.Y.Z</center>` signature that respects
            // `server_tokens`.
            // 494–497 keep their code for `error_page` to find, which the
            // page, sent as 400, wouldn't (http_error_page.t "redirect 497").
            if (494..=497).contains(&status) {
                Prebuilt::leak(status, &concatenated, server_bytes)
            } else {
                Prebuilt::leak_error(status, &concatenated, server_bytes)
            }
        } else {
            Prebuilt::leak(status, &concatenated, server_bytes)
        };
        PreparedReturn::Static(prebuilt, types)
    } else {
        PreparedReturn::Template {
            status,
            parts: prepare_value_parts(body),
            types,
        }
    }
}

/// How a location maps a URI under its `root` / `alias` path.
pub(crate) fn prepare_path_mapping(
    mapping: PathMapping,
    location_pattern: &'static [u8],
    is_regex_location: bool,
    alias_prefix_override: Option<&'static [u8]>,
) -> PreparedPathMapping {
    match mapping {
        PathMapping::Root => PreparedPathMapping::Root,
        PathMapping::Alias => {
            if let Some(prefix) = alias_prefix_override {
                // Inherited from an ancestor prefix-alias location: strip
                // the ancestor's pattern, even when this location is a
                // regex (which has no pattern of its own to use as a
                // prefix).
                PreparedPathMapping::AliasPrefix { prefix }
            } else if is_regex_location {
                PreparedPathMapping::AliasRegex
            } else {
                PreparedPathMapping::AliasPrefix {
                    prefix: location_pattern,
                }
            }
        }
    }
}

/// A location's (or server's) `DocRoot`, leaked for the process.
pub(crate) fn leak_doc_root(
    (path, mapping): (std::path::PathBuf, PathMapping),
    location_pattern: &'static [u8],
    is_regex_location: bool,
    alias_prefix_override: Option<&'static [u8]>,
    disable_symlinks: Option<crate::config::DisableSymlinks>,
    charset: Option<&'static PreparedCharset>,
) -> &'static DocRoot {
    // nginx resolves a relative root under the prefix (ruxen's working
    // directory by now) and prints it absolute.
    let path = if path.is_relative() {
        std::env::current_dir().map_or(path.clone(), |cwd| cwd.join(&path))
    } else {
        path
    };
    crate::arena::leak(Box::new(DocRoot {
        path: leak_path_buf(path),
        location: location_pattern,
        mapping: prepare_path_mapping(
            mapping,
            location_pattern,
            is_regex_location,
            alias_prefix_override,
        ),
        symlinks: PreparedSymlinks::new(disable_symlinks),
        charset,
    }))
}

/// Resolve one scope's access phase over its parent's: `allow` / `deny`
/// lists replace each other whole, the rest inherits per directive.
fn resolve_access(
    access: AccessConf,
    auth_basic: Option<AuthBasic>,
    auth_basic_user_file: Option<std::path::PathBuf>,
    auth_delay_ms: Option<u64>,
    parent: PreparedAccess,
) -> PreparedAccess {
    PreparedAccess {
        rules: if access.rules.is_empty() {
            parent.rules
        } else {
            crate::arena::leak(access.rules.into_boxed_slice())
        },
        satisfy_any: access
            .satisfy
            .map_or(parent.satisfy_any, |s| s == crate::config::Satisfy::Any),
        auth_basic: auth_basic
            .map(prepare_auth_basic)
            .unwrap_or(parent.auth_basic),
        auth_basic_user_file: auth_basic_user_file
            .map(leak_path_buf)
            .or(parent.auth_basic_user_file),
        auth_delay_ms: auth_delay_ms.unwrap_or(parent.auth_delay_ms),
        auth_request: match access.auth_request {
            Some(Some(uri)) => Some(leak_bytes(uri.as_bytes())),
            Some(None) => None,
            None => parent.auth_request,
        },
        auth_request_set: if access.auth_request_set.is_empty() {
            parent.auth_request_set
        } else {
            crate::arena::leak(
                access
                    .auth_request_set
                    .into_iter()
                    .map(|(name, parts)| (leak_bytes(name.as_bytes()), prepare_value_parts(parts)))
                    .collect::<Vec<_>>()
                    .into_boxed_slice(),
            )
        },
        realip: PreparedRealIp {
            from: if access.realip.from.is_empty() {
                parent.realip.from
            } else {
                crate::arena::leak(access.realip.from.into_boxed_slice())
            },
            header: access
                .realip
                .header
                .map_or(parent.realip.header, |h| match h {
                    RealIpHeader::XRealIp => PreparedRealIpHeader::XRealIp,
                    RealIpHeader::XForwardedFor => PreparedRealIpHeader::XForwardedFor,
                    RealIpHeader::ProxyProtocol => PreparedRealIpHeader::ProxyProtocol,
                    RealIpHeader::Other(name) => {
                        PreparedRealIpHeader::Other(leak_bytes(name.as_bytes()))
                    }
                }),
            recursive: access.realip.recursive.unwrap_or(parent.realip.recursive),
        },
    }
}

/// Whether the requests a `limit_except` applies to need a content
/// handler of their own: without the location's rewrite directives (so
/// without its `return`) and without `try_files`, nginx serves them with
/// the static handler, or with the location's `proxy_pass`.
fn limit_except_rebuilds_handler(handler: &Handler, try_files: &Option<TryFiles>) -> bool {
    match handler {
        Handler::Proxy(_) | Handler::StubStatus | Handler::Metrics => false,
        Handler::Root { .. } => try_files.is_some(),
        Handler::Return { .. } => true,
    }
}

fn build_limit_except(
    le: LimitExcept,
    handler: Option<PreparedHandler>,
    location_access: PreparedAccess,
) -> &'static PreparedLimitExcept {
    let own = AccessConf {
        rules: le.rules,
        ..AccessConf::default()
    };
    let access = resolve_access(
        own,
        le.auth_basic,
        le.auth_basic_user_file,
        None,
        location_access,
    );
    crate::arena::leak(Box::new(PreparedLimitExcept {
        methods: le.methods,
        handler,
        access,
    }))
}

/// The lookup for `types {}` / `default_type` (#38), built once per table
/// and default for every location that has them. Without `types` at any
/// level, nginx's built-in three (ngx_http_core_default_types); without
/// `default_type`, `text/plain`.
fn prepare_types(mime: &crate::config::MimeConf) -> &'static PreparedTypes {
    type Key = (Option<*const Vec<(String, String)>>, Option<String>);
    thread_local! {
        static BUILT: std::cell::RefCell<Vec<(Key, &'static PreparedTypes)>> =
            const { std::cell::RefCell::new(Vec::new()) };
    }
    let key: Key = (
        mime.types.as_ref().map(std::sync::Arc::as_ptr),
        mime.default_type.clone(),
    );
    if let Some(t) = BUILT.with(|b| b.borrow().iter().find(|(k, _)| *k == key).map(|(_, t)| *t)) {
        return t;
    }
    const DEFAULT_TYPES: &[(&str, &str)] = &[
        ("html", "text/html"),
        ("gif", "image/gif"),
        ("jpg", "image/jpeg"),
    ];
    let mut map = std::collections::HashMap::default();
    let pairs: Vec<(String, String)> = match &mime.types {
        Some(t) => t.as_ref().clone(),
        None => DEFAULT_TYPES
            .iter()
            .map(|(e, m)| (e.to_string(), m.to_string()))
            .collect(),
    };
    for (ext, ty) in pairs {
        map.insert(
            ext.into_bytes().into_boxed_slice(),
            leak_bytes(ty.as_bytes()),
        );
    }
    let default = mime.default_type.as_deref().unwrap_or("text/plain");
    let types: &'static PreparedTypes = crate::arena::leak(Box::new(PreparedTypes {
        map,
        default: leak_bytes(default.as_bytes()),
        default_is_plain: default == "text/plain",
    }));
    BUILT.with(|b| b.borrow_mut().push((key, types)));
    types
}

/// The location a handler is built for, with the settings it inherits
/// resolved: what every `build_handler` call for one location shares.
pub(crate) struct HandlerSite<'a> {
    pub(crate) pattern: &'static [u8],
    pub(crate) is_regex: bool,
    pub(crate) alias_prefix_override: Option<&'static [u8]>,
    pub(crate) server_index: Option<&'static [PreparedIndexEntry]>,
    pub(crate) autoindex: bool,
    pub(crate) autoindex_exact_size: bool,
    pub(crate) autoindex_localtime: bool,
    pub(crate) autoindex_format: AutoindexFormat,
    pub(crate) if_modified_since: crate::config::IfModifiedSince,
    pub(crate) etag: bool,
    pub(crate) disable_symlinks: Option<crate::config::DisableSymlinks>,
    pub(crate) mime: &'a crate::config::MimeConf,
    pub(crate) tokens: crate::config::ServerTokens,
    pub(crate) upstreams: &'a UpstreamMap,
}

pub(crate) fn build_handler(
    handler: Handler,
    location_index: Option<Vec<IndexEntry>>,
    location_try_files: Option<TryFiles>,
    proxy_effective: ProxyEffective,
    site: &HandlerSite<'_>,
) -> Result<PreparedHandler, String> {
    Ok(match handler {
        Handler::Return { status, body } => {
            let finalized = body.is_empty() || matches!(status, 301 | 302 | 303 | 307 | 308);
            PreparedHandler::Return(
                prepare_return(status, body, site.tokens, prepare_types(site.mime)),
                finalized,
            )
        }
        Handler::StubStatus => PreparedHandler::StubStatus,
        Handler::Metrics => PreparedHandler::Metrics,
        Handler::Proxy(pp) => PreparedHandler::Proxy(build_proxy(
            pp,
            site.upstreams,
            proxy_effective,
            site.pattern,
            site.is_regex,
        )?),
        Handler::Root { path, mapping } => {
            // nginx resolves `root` per request and starts without it: a
            // missing root is a 404 at request time. ruxen opens the root
            // as an `openat2(RESOLVE_BENEATH)` anchor, at startup when it
            // exists, else on first use (`PreparedRoot::fd`).
            let root: &'static Path = crate::arena::leak(path.into_boxed_path());
            let root_fd = open_root(root).unwrap_or(-1);
            if root_fd != -1 {
                ROOT_FDS.with(|fds| fds.borrow_mut().push(root_fd));
            }
            let path_mapping = prepare_path_mapping(
                mapping,
                site.pattern,
                site.is_regex,
                site.alias_prefix_override,
            );

            // Index inheritance: location list wins; else server list; else
            // the built-in default from ngx_http_index_module.c
            // (NGX_HTTP_DEFAULT_INDEX).
            let index: &'static [PreparedIndexEntry] = match location_index {
                Some(names) => prepare_index_entries(names),
                None => match site.server_index {
                    Some(v) => v,
                    None => prepare_index_entries(vec![IndexEntry {
                        parts: vec![ValuePart::Literal("index.html".into())],
                    }]),
                },
            };

            let try_files = location_try_files.map(|tf| prepare_try_files(tf, site.tokens));

            PreparedHandler::Root(PreparedRoot {
                root,
                types: prepare_types(site.mime),
                root_fd,
                symlinks: PreparedSymlinks::new(site.disable_symlinks.clone()),
                path_mapping,
                index,
                autoindex: site.autoindex,
                autoindex_exact_size: site.autoindex_exact_size,
                autoindex_localtime: site.autoindex_localtime,
                autoindex_format: site.autoindex_format,
                if_modified_since: site.if_modified_since,
                etag: site.etag,
                try_files,
            })
        }
    })
}

pub(crate) fn resolve_add_headers(
    location_headers: Option<Vec<AddHeader>>,
    server_add_headers: &'static [PreparedAddHeader],
) -> &'static [PreparedAddHeader] {
    match location_headers {
        Some(list) => prepare_add_headers(list),
        None => server_add_headers,
    }
}

pub(crate) fn resolve_error_pages(
    location_error_pages: Option<Vec<ErrorPage>>,
    server_error_pages: &'static [PreparedErrorPage],
) -> &'static [PreparedErrorPage] {
    match location_error_pages {
        Some(list) => prepare_error_pages(list),
        None => server_error_pages,
    }
}

/// Create (or append-open) a log file the way nginx does at startup, so a
/// bad path is an `[emerg]` instead of a silent loss of log lines.
/// An access_log file, opened for appending (created if missing) and kept:
/// the workers write to `dup`s of it.
fn open_access_log_file(path: &Path) -> Result<std::fs::File, String> {
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("open() \"{}\" failed ({})", path.display(), errno_text(&e)))?;
    // Reopened after logrotate by the `user` ruxen switches to.
    crate::privileges::note_file(path);
    Ok(file)
}

pub(crate) fn prepare_error_log_target(
    target: ErrorLogTarget,
) -> Result<PreparedErrorLogTarget, String> {
    Ok(match target {
        ErrorLogTarget::File(path) => {
            // Created up front, as nginx does at startup, and kept open
            // with the configuration, once per path (#648).
            if let Some(file) = ERROR_LOG_FILES.with(|f| f.borrow().get(&path).copied()) {
                return Ok(PreparedErrorLogTarget::File(file));
            }
            let opened = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .map_err(|e| {
                    format!("open() \"{}\" failed ({})", path.display(), errno_text(&e))
                })?;
            // Reopened after logrotate by the `user` ruxen switches to.
            crate::privileges::note_file(&path);
            let file: &'static PreparedErrorLogFile =
                crate::arena::leak(Box::new(PreparedErrorLogFile {
                    path: crate::arena::leak(path.clone().into_boxed_path()),
                    file: Some(opened),
                    opened_gen: crate::worker::LOG_REOPEN_GEN.load(Ordering::Relaxed),
                }));
            ERROR_LOG_FILES.with(|f| f.borrow_mut().insert(path, file));
            PreparedErrorLogTarget::File(file)
        }
        ErrorLogTarget::Stderr => PreparedErrorLogTarget::Stderr,
        ErrorLogTarget::Syslog(peer) => PreparedErrorLogTarget::Syslog(prepare_syslog_peer(&peer)?),
    })
}

pub(crate) fn prepare_error_logs(
    list: Vec<ErrorLog>,
) -> Result<&'static [PreparedErrorLog], String> {
    let mut out: Vec<PreparedErrorLog> = Vec::with_capacity(list.len());
    for log in list {
        out.push(PreparedErrorLog {
            target: prepare_error_log_target(log.target)?,
            level: log.level,
        });
    }
    Ok(crate::arena::leak(out.into_boxed_slice()))
}

pub(crate) fn resolve_error_logs(
    location_error_logs: Option<Vec<ErrorLog>>,
    server_error_logs: &'static [PreparedErrorLog],
) -> Result<&'static [PreparedErrorLog], String> {
    match location_error_logs {
        Some(list) => prepare_error_logs(list),
        None => Ok(server_error_logs),
    }
}

/// What a server's locations inherit from it, resolved once in
/// `prepare_server` and shared by every location it builds.
pub(crate) struct ServerScope<'a> {
    pub(crate) index: Option<&'static [PreparedIndexEntry]>,
    pub(crate) add_headers: &'static [PreparedAddHeader],
    pub(crate) add_trailers: &'static [PreparedAddHeader],
    pub(crate) error_pages: &'static [PreparedErrorPage],
    pub(crate) keepalive: PreparedKeepalive,
    pub(crate) error_logs: &'static [PreparedErrorLog],
    pub(crate) log_not_found: bool,
    pub(crate) recursive_error_pages: bool,
    pub(crate) tokens: crate::config::ServerTokens,
    pub(crate) autoindex: bool,
    pub(crate) autoindex_exact_size: bool,
    pub(crate) autoindex_localtime: bool,
    pub(crate) autoindex_format: AutoindexFormat,
    pub(crate) if_modified_since: crate::config::IfModifiedSince,
    pub(crate) etag: bool,
    pub(crate) access_logs: &'static [PreparedAccessLog],
    pub(crate) access: PreparedAccess,
    pub(crate) client_max_body_size: Option<u64>,
    pub(crate) max_ranges: Option<u32>,
    pub(crate) client_body_buffer_size: Option<u64>,
    pub(crate) sendfile: bool,
    pub(crate) body_temp: Option<&'static BodyTempDir>,
    pub(crate) disable_symlinks: Option<crate::config::DisableSymlinks>,
    pub(crate) limit_rate: PreparedLimitRate,
    pub(crate) post_action: Option<&'static [u8]>,
    pub(crate) expires: PreparedExpires,
    pub(crate) chunked_transfer_encoding: bool,
    pub(crate) limit_req: &'a crate::config::LimitReqConf,
    pub(crate) limit_conn: &'a crate::config::LimitConnConf,
    pub(crate) client_timeouts: crate::config::ClientTimeouts,
    pub(crate) proxy_defaults: ServerProxyDefaults,
    pub(crate) gzip: &'a crate::config::GzipConf,
}

pub(crate) fn build_prefix_or_exact(
    l: Location,
    server: &ServerScope<'_>,
    upstreams: &UpstreamMap,
    alp: &mut AccessLogPrep<'_>,
) -> Result<PreparedLocation, String> {
    let Location {
        mime,
        mode,
        pattern,
        noregex,
        rewrite_ops,
        handler,
        index,
        try_files,
        add_headers: location_add_headers,
        add_trailers: location_add_trailers,
        error_pages: location_error_pages,
        keepalive_timeout,
        keepalive_requests,
        keepalive_time_ms,
        keepalive_disable,
        error_logs: location_error_logs,
        log_not_found: location_log_not_found,
        recursive_error_pages: location_recursive_error_pages,
        internal,
        server_tokens: location_server_tokens,
        autoindex: location_autoindex,
        autoindex_exact_size: location_autoindex_exact_size,
        autoindex_localtime: location_autoindex_localtime,
        autoindex_format: location_autoindex_format,
        if_modified_since: location_if_modified_since,
        etag: location_etag,
        access_logs: location_access_logs,
        open_log_file_cache: location_open_log_file_cache,
        auth_basic: location_auth_basic,
        auth_basic_user_file: location_auth_basic_user_file,
        auth_delay_ms: location_auth_delay_ms,
        access: location_access,
        limit_except,
        client_max_body_size: location_client_max_body_size,
        max_ranges: location_max_ranges,
        client_body_buffer_size: location_client_body_buffer_size,
        sendfile: location_sendfile,
        document_root,
        client_body_temp_path: location_client_body_temp_path,
        disable_symlinks: location_disable_symlinks,
        limit_rate: location_limit_rate,
        limit_req: location_limit_req,
        limit_conn: location_limit_conn,
        client_timeouts: location_client_timeouts,
        limit_rate_after: location_limit_rate_after,
        client_body_in_file_only: location_client_body_in_file_only,
        post_action: location_post_action,
        expires: location_expires,
        proxy: location_proxy,
        gzip: location_gzip,
        chunked_transfer_encoding: location_chunked_transfer_encoding,
        redirect,
        alias_prefix_override,
        inherits_root: _,
        explicit_return: _,
        descendants: _,
        add_header_inherit: _,
        add_trailer_inherit: _,
        header_ancestors: _,
        charset: location_charset,
    } = l;
    let proxy_effective = resolve_proxy_effective(location_proxy, server.proxy_defaults);
    let gzip = prepare_gzip(location_gzip.inherit(server.gzip))?;
    let charset = prepare_charset(&location_charset);
    // Only an `if` block's anonymous location in a regex location is
    // built here with a regex mode (#137): its alias takes the captures.
    let is_regex = matches!(mode, MatchMode::Regex { .. });
    let pattern: &'static [u8] = crate::arena::leak(pattern.into_bytes().into_boxed_slice());
    let alias_prefix_override: Option<&'static [u8]> = alias_prefix_override
        .map(|s| crate::arena::leak(s.into_bytes().into_boxed_slice()) as &'static [u8]);
    let keepalive = resolve_keepalive(
        keepalive_timeout,
        keepalive_requests,
        keepalive_time_ms,
        keepalive_disable,
        server.keepalive,
    );
    let tokens = location_server_tokens.unwrap_or(server.tokens);
    let (handler, rewrite_ops) = return_after_break(handler, rewrite_ops, &document_root);
    let rewrite_program = prepare_rewrite_ops(rewrite_ops, tokens, prepare_types(&mime));
    let error_pages = resolve_error_pages(location_error_pages, server.error_pages);
    let recursive_error_pages =
        location_recursive_error_pages.unwrap_or(server.recursive_error_pages);
    let proxy_effective = ProxyEffective {
        error_pages,
        recursive_error_pages,
        ..proxy_effective
    };
    let site = HandlerSite {
        pattern,
        is_regex,
        alias_prefix_override,
        server_index: server.index,
        autoindex: location_autoindex.unwrap_or(server.autoindex),
        autoindex_exact_size: location_autoindex_exact_size.unwrap_or(server.autoindex_exact_size),
        autoindex_localtime: location_autoindex_localtime.unwrap_or(server.autoindex_localtime),
        autoindex_format: location_autoindex_format.unwrap_or(server.autoindex_format),
        if_modified_since: location_if_modified_since.unwrap_or(server.if_modified_since),
        etag: location_etag.unwrap_or(server.etag),
        disable_symlinks: location_disable_symlinks.or_else(|| server.disable_symlinks.clone()),
        mime: &mime,
        tokens,
        upstreams,
    };
    let limited_handler = match &limit_except {
        // `proxy_pass` in the block: the other methods are proxied there,
        // with the location's proxy_* settings (proxy_if.t).
        Some(le) if le.proxy_pass.is_some() => Some(build_handler(
            Handler::Proxy(le.proxy_pass.clone().expect("checked")),
            None,
            None,
            proxy_effective,
            &site,
        )?),
        Some(_) if limit_except_rebuilds_handler(&handler, &try_files) => Some(build_handler(
            Handler::Root {
                path: document_root.0.clone(),
                mapping: document_root.1,
            },
            index.clone(),
            None,
            ProxyEffective::defaults(),
            &site,
        )?),
        _ => None,
    };
    let doc_root = leak_doc_root(
        document_root,
        pattern,
        is_regex,
        alias_prefix_override,
        site.disable_symlinks.clone(),
        charset,
    );
    let handler = build_handler(handler, index, try_files, proxy_effective, &site)?;
    let auto_redirect = matches!(&handler, PreparedHandler::Proxy(_)) && pattern.ends_with(b"/");
    let add_headers = resolve_add_headers(location_add_headers, server.add_headers);
    let add_trailers = resolve_add_headers(location_add_trailers, server.add_trailers);
    let error_logs = resolve_error_logs(location_error_logs, server.error_logs)?;
    let log_not_found = location_log_not_found.unwrap_or(server.log_not_found);
    let access_logs = match location_access_logs {
        Some(ref list) => alp.prepare_list(list)?,
        None => server.access_logs,
    };
    let access_logs = alp.with_cache(
        access_logs,
        location_open_log_file_cache.unwrap_or(alp.server_cache),
    );
    let access = resolve_access(
        location_access,
        location_auth_basic,
        location_auth_basic_user_file,
        location_auth_delay_ms,
        server.access,
    );
    let limit_except = limit_except.map(|le| build_limit_except(le, limited_handler, access));
    let client_max_body_size = location_client_max_body_size.or(server.client_max_body_size);
    let max_ranges = location_max_ranges.or(server.max_ranges);
    let client_body_buffer_size =
        location_client_body_buffer_size.or(server.client_body_buffer_size);
    let sendfile = location_sendfile.unwrap_or(server.sendfile);
    let body_temp = location_client_body_temp_path
        .map(BodyTempDir::leak)
        .or(server.body_temp);
    let limit_rate = PreparedLimitRate::inherit(
        location_limit_rate,
        location_limit_rate_after,
        server.limit_rate,
    );
    let post_action = location_post_action
        .map(|target| leak_bytes(target.as_bytes()))
        .or(server.post_action);
    let expires = location_expires
        .map(prepare_expires)
        .unwrap_or(server.expires);
    let chunked_transfer_encoding =
        location_chunked_transfer_encoding.unwrap_or(server.chunked_transfer_encoding);
    Ok(PreparedLocation {
        pattern,
        handler,
        auto_redirect,
        noregex,
        rewrite_program,
        add_headers,
        add_trailers,
        error_pages,
        keepalive,
        error_logs,
        log_not_found,
        recursive_error_pages,
        internal,
        server_header: http::server_header_value(tokens),
        access_logs,
        access,
        limit_except,
        client_max_body_size,
        max_ranges,
        client_body_buffer_size,
        sendfile,
        gzip,
        limit_rate: limit_rate.for_location(),
        client_body_in_file_only: location_client_body_in_file_only
            .unwrap_or(crate::config::ClientBodyInFileOnly::Off),
        body_temp,
        doc_root,
        post_action,
        expires,
        chunked_transfer_encoding,
        redirect: redirect.policy(),
        limit_req: prepare_limit_req(location_limit_req.inherit(server.limit_req))?,
        limit_conn: prepare_limit_conn(location_limit_conn.inherit(server.limit_conn))?,
        timeouts: crate::arena::leak(Box::new(PreparedClientTimeouts::resolve(
            location_client_timeouts.inherit(server.client_timeouts),
        ))),
    })
}

pub(crate) fn build_regex_location(
    l: Location,
    case_insensitive: bool,
    server: &ServerScope<'_>,
    upstreams: &UpstreamMap,
    alp: &mut AccessLogPrep<'_>,
) -> Result<PreparedRegexLocation, String> {
    let Location {
        mime,
        mode: _,
        pattern,
        noregex: _,
        rewrite_ops,
        handler,
        index,
        try_files,
        add_headers: location_add_headers,
        add_trailers: location_add_trailers,
        error_pages: location_error_pages,
        keepalive_timeout,
        keepalive_requests,
        keepalive_time_ms,
        keepalive_disable,
        error_logs: location_error_logs,
        log_not_found: location_log_not_found,
        recursive_error_pages: location_recursive_error_pages,
        internal,
        server_tokens: location_server_tokens,
        autoindex: location_autoindex,
        autoindex_exact_size: location_autoindex_exact_size,
        autoindex_localtime: location_autoindex_localtime,
        autoindex_format: location_autoindex_format,
        if_modified_since: location_if_modified_since,
        etag: location_etag,
        access_logs: location_access_logs,
        open_log_file_cache: location_open_log_file_cache,
        auth_basic: location_auth_basic,
        auth_basic_user_file: location_auth_basic_user_file,
        auth_delay_ms: location_auth_delay_ms,
        access: location_access,
        limit_except,
        client_max_body_size: location_client_max_body_size,
        max_ranges: location_max_ranges,
        client_body_buffer_size: location_client_body_buffer_size,
        sendfile: location_sendfile,
        document_root,
        client_body_temp_path: location_client_body_temp_path,
        disable_symlinks: location_disable_symlinks,
        limit_rate: location_limit_rate,
        limit_req: location_limit_req,
        limit_conn: location_limit_conn,
        client_timeouts: location_client_timeouts,
        limit_rate_after: location_limit_rate_after,
        client_body_in_file_only: location_client_body_in_file_only,
        post_action: location_post_action,
        expires: location_expires,
        proxy: location_proxy,
        gzip: location_gzip,
        chunked_transfer_encoding: location_chunked_transfer_encoding,
        redirect,
        alias_prefix_override,
        inherits_root: _,
        explicit_return: _,
        descendants: _,
        add_header_inherit: _,
        add_trailer_inherit: _,
        header_ancestors: _,
        charset: location_charset,
    } = l;
    let proxy_effective = resolve_proxy_effective(location_proxy, server.proxy_defaults);
    let gzip = prepare_gzip(location_gzip.inherit(server.gzip))?;
    let charset = prepare_charset(&location_charset);
    // The parser already validated it; the compiled `Regex` doesn't
    // survive the AST.
    let regex = crate::config::pcre::regex(&pattern, case_insensitive).unwrap_or_else(|e| {
        panic!(
            "ruxen: regex {:?} failed to compile after passing parse validation: {e}",
            pattern
        )
    });
    let location_pattern: &'static [u8] = b"";
    let alias_prefix_override: Option<&'static [u8]> = alias_prefix_override
        .map(|s| crate::arena::leak(s.into_bytes().into_boxed_slice()) as &'static [u8]);
    let keepalive = resolve_keepalive(
        keepalive_timeout,
        keepalive_requests,
        keepalive_time_ms,
        keepalive_disable,
        server.keepalive,
    );
    let tokens = location_server_tokens.unwrap_or(server.tokens);
    let (handler, rewrite_ops) = return_after_break(handler, rewrite_ops, &document_root);
    let rewrite_program = prepare_rewrite_ops(rewrite_ops, tokens, prepare_types(&mime));
    let error_pages = resolve_error_pages(location_error_pages, server.error_pages);
    let recursive_error_pages =
        location_recursive_error_pages.unwrap_or(server.recursive_error_pages);
    let proxy_effective = ProxyEffective {
        error_pages,
        recursive_error_pages,
        ..proxy_effective
    };
    let site = HandlerSite {
        pattern: location_pattern,
        is_regex: true,
        alias_prefix_override,
        server_index: server.index,
        autoindex: location_autoindex.unwrap_or(server.autoindex),
        autoindex_exact_size: location_autoindex_exact_size.unwrap_or(server.autoindex_exact_size),
        autoindex_localtime: location_autoindex_localtime.unwrap_or(server.autoindex_localtime),
        autoindex_format: location_autoindex_format.unwrap_or(server.autoindex_format),
        if_modified_since: location_if_modified_since.unwrap_or(server.if_modified_since),
        etag: location_etag.unwrap_or(server.etag),
        disable_symlinks: location_disable_symlinks.or_else(|| server.disable_symlinks.clone()),
        mime: &mime,
        tokens,
        upstreams,
    };
    let limited_handler = match &limit_except {
        // `proxy_pass` in the block: the other methods are proxied there,
        // with the location's proxy_* settings (proxy_if.t).
        Some(le) if le.proxy_pass.is_some() => Some(build_handler(
            Handler::Proxy(le.proxy_pass.clone().expect("checked")),
            None,
            None,
            proxy_effective,
            &site,
        )?),
        Some(_) if limit_except_rebuilds_handler(&handler, &try_files) => Some(build_handler(
            Handler::Root {
                path: document_root.0.clone(),
                mapping: document_root.1,
            },
            index.clone(),
            None,
            ProxyEffective::defaults(),
            &site,
        )?),
        _ => None,
    };
    let doc_root = leak_doc_root(
        document_root,
        location_pattern,
        true,
        alias_prefix_override,
        site.disable_symlinks.clone(),
        charset,
    );
    let handler = build_handler(handler, index, try_files, proxy_effective, &site)?;
    let add_headers = resolve_add_headers(location_add_headers, server.add_headers);
    let add_trailers = resolve_add_headers(location_add_trailers, server.add_trailers);
    let error_logs = resolve_error_logs(location_error_logs, server.error_logs)?;
    let log_not_found = location_log_not_found.unwrap_or(server.log_not_found);
    let access_logs = match location_access_logs {
        Some(ref list) => alp.prepare_list(list)?,
        None => server.access_logs,
    };
    let access_logs = alp.with_cache(
        access_logs,
        location_open_log_file_cache.unwrap_or(alp.server_cache),
    );
    let access = resolve_access(
        location_access,
        location_auth_basic,
        location_auth_basic_user_file,
        location_auth_delay_ms,
        server.access,
    );
    let limit_except = limit_except.map(|le| build_limit_except(le, limited_handler, access));
    let client_max_body_size = location_client_max_body_size.or(server.client_max_body_size);
    let max_ranges = location_max_ranges.or(server.max_ranges);
    let client_body_buffer_size =
        location_client_body_buffer_size.or(server.client_body_buffer_size);
    let sendfile = location_sendfile.unwrap_or(server.sendfile);
    let body_temp = location_client_body_temp_path
        .map(BodyTempDir::leak)
        .or(server.body_temp);
    let limit_rate = PreparedLimitRate::inherit(
        location_limit_rate,
        location_limit_rate_after,
        server.limit_rate,
    );
    let post_action = location_post_action
        .map(|target| leak_bytes(target.as_bytes()))
        .or(server.post_action);
    let expires = location_expires
        .map(prepare_expires)
        .unwrap_or(server.expires);
    let chunked_transfer_encoding =
        location_chunked_transfer_encoding.unwrap_or(server.chunked_transfer_encoding);
    Ok(PreparedRegexLocation {
        regex,
        set_pattern: set_pattern(&pattern, case_insensitive),
        handler,
        rewrite_program,
        add_headers,
        add_trailers,
        error_pages,
        keepalive,
        error_logs,
        log_not_found,
        recursive_error_pages,
        internal,
        server_header: http::server_header_value(tokens),
        access_logs,
        access,
        limit_except,
        client_max_body_size,
        max_ranges,
        client_body_buffer_size,
        sendfile,
        gzip,
        limit_rate: limit_rate.for_location(),
        client_body_in_file_only: location_client_body_in_file_only
            .unwrap_or(crate::config::ClientBodyInFileOnly::Off),
        body_temp,
        doc_root,
        post_action,
        expires,
        chunked_transfer_encoding,
        redirect: redirect.policy(),
        limit_req: prepare_limit_req(location_limit_req.inherit(server.limit_req))?,
        limit_conn: prepare_limit_conn(location_limit_conn.inherit(server.limit_conn))?,
        timeouts: crate::arena::leak(Box::new(PreparedClientTimeouts::resolve(
            location_client_timeouts.inherit(server.client_timeouts),
        ))),
    })
}

pub(crate) fn prepare_try_files(
    tf: TryFiles,
    tokens: crate::config::ServerTokens,
) -> &'static PreparedTryFiles {
    let probes: Vec<PreparedProbe> = tf
        .probes
        .into_iter()
        .map(|p| match p {
            TryFilesProbe::Uri => PreparedProbe::Uri,
            TryFilesProbe::UriSlash => PreparedProbe::UriSlash,
            TryFilesProbe::Literal(s) => PreparedProbe::Literal(leak_bytes(s.as_bytes())),
            TryFilesProbe::LiteralSlash(s) => PreparedProbe::LiteralSlash(leak_bytes(s.as_bytes())),
            TryFilesProbe::Template { parts, dir } => PreparedProbe::Template {
                parts: prepare_value_parts(parts),
                dir,
            },
        })
        .collect();
    let server_bytes = http::server_header_value(tokens);
    let fallback = match tf.fallback {
        TryFilesFallback::Status(code) => PreparedFallback::Status(Prebuilt::leak_error(
            code,
            fallback_body(code),
            server_bytes,
        )),
        TryFilesFallback::Uri(u) => PreparedFallback::Uri(leak_bytes(u.as_bytes())),
        TryFilesFallback::UriTemplate(parts) => {
            PreparedFallback::UriTemplate(prepare_value_parts(parts))
        }
        TryFilesFallback::Named(u) => PreparedFallback::Named(leak_bytes(u.as_bytes())),
    };
    crate::arena::leak(Box::new(PreparedTryFiles { probes, fallback }))
}

/// The effective `gzip*` settings of a location, or `None` when gzip is
/// off there: the filter then costs one check per response.
/// A level's charset settings as responses get them (#464), `None` where
/// nothing is added: no `charset`, `charset off`, a charset from a
/// variable (not supported yet), or a `source_charset` other than it, as
/// that would need a conversion ruxen doesn't do.
pub(crate) fn prepare_charset(
    conf: &crate::config::CharsetConf,
) -> Option<&'static PreparedCharset> {
    // ngx_http_charset_default_types.
    const DEFAULT_TYPES: &[&str] = &[
        "text/html",
        "text/xml",
        "text/plain",
        "text/vnd.wap.wml",
        "application/javascript",
        "application/rss+xml",
    ];
    let name = conf.charset.as_ref()?.as_ref()?;
    if name.starts_with('$')
        || conf
            .source
            .as_ref()
            .is_some_and(|s| !s.eq_ignore_ascii_case(name))
    {
        return None;
    }
    let leak =
        |s: &str| -> &'static [u8] { crate::arena::leak(s.as_bytes().to_vec().into_boxed_slice()) };
    let types: Option<&'static [&'static [u8]]> = match &conf.types {
        Some(list) if list.iter().any(|t| t == "*") => None,
        // Always with text/html, "in addition to" the list, as nginx's
        // charset_types takes it.
        Some(list) => Some(crate::arena::leak(
            std::iter::once("text/html")
                .chain(list.iter().map(String::as_str))
                .map(leak)
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        )),
        None => Some(crate::arena::leak(
            DEFAULT_TYPES
                .iter()
                .map(|t| leak(t))
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        )),
    };
    Some(crate::arena::leak(Box::new(PreparedCharset {
        name: leak(name),
        types,
    })))
}

pub(crate) fn prepare_gzip(
    conf: crate::config::GzipConf,
) -> Result<Option<&'static PreparedGzip>, String> {
    if conf.enable != Some(true) {
        return Ok(None);
    }
    let mut any_type = false;
    // nginx always compresses text/html (ngx_http_html_default_types).
    let mut types: Vec<&'static str> = vec!["text/html"];
    for t in conf.types.unwrap_or_default() {
        if t == "*" {
            any_type = true;
        } else if !types.contains(&t.as_str()) {
            types.push(crate::arena::leak(t.into_boxed_str()));
        }
    }
    let mut disable_msie6 = false;
    let mut patterns = Vec::new();
    for d in conf.disable.unwrap_or_default() {
        match d.as_str() {
            "msie6" => disable_msie6 = true,
            "degradation" => {}
            _ => patterns.push(set_pattern(&d, true)),
        }
    }
    let disable = if patterns.is_empty() {
        None
    } else {
        Some(
            crate::config::pcre::regex_set(patterns.iter().map(String::as_str))
                .map_err(|e| format!("gzip_disable: {e}"))?,
        )
    };
    Ok(Some(crate::arena::leak(Box::new(PreparedGzip {
        any_type,
        types: crate::arena::leak(types.into_boxed_slice()),
        min_length: conf.min_length.unwrap_or(20),
        comp_level: conf.comp_level.unwrap_or(1),
        vary: conf.vary.unwrap_or(false),
        http_10: conf.http_version == Some(10),
        proxied: conf.proxied.unwrap_or(crate::config::gzip_proxied::OFF),
        disable_msie6,
        disable,
    }))))
}

/// `pattern` as a `RegexSet` member, with the case flag its own `Regex`
/// was built with. Translated here: an unended `\Q` in the wrapped one
/// would take the `)`.
pub(crate) fn set_pattern(pattern: &str, case_insensitive: bool) -> String {
    let pattern = crate::config::pcre::translate(pattern);
    if case_insensitive {
        format!("(?i:{pattern})")
    } else {
        pattern.to_string()
    }
}

/// One `RegexSet` over a list of regexes nginx tries in order: the lowest
/// matching index is the first match, found in one pass (#248). `None`
/// for fewer than two (a set gains nothing), or if the set doesn't build
/// (size limits): the caller then tries the regexes one by one.
pub(crate) fn first_match_set<'a>(
    patterns: impl IntoIterator<Item = &'a str>,
) -> Option<regex::bytes::RegexSet> {
    let patterns: Vec<&str> = patterns.into_iter().collect();
    if patterns.len() < 2 {
        return None;
    }
    crate::config::pcre::regex_set(patterns).ok()
}

#[cfg(test)]
mod tests {
    use super::without_default_port;

    #[test]
    fn default_port_is_dropped_from_proxy_host() {
        for (authority, want) in [
            ("127.0.0.1:80", "127.0.0.1"),
            ("example.test:80", "example.test"),
            ("[::1]:80", "[::1]"),
            ("127.0.0.1:8080", "127.0.0.1:8080"),
            ("[::1]:8080", "[::1]:8080"),
            ("example.test", "example.test"),
            ("[::1]", "[::1]"),
            ("u", "u"),
        ] {
            let got = without_default_port(crate::arena::leak(authority.as_bytes().into()), false);
            assert_eq!(got, want.as_bytes(), "{authority}");
        }
    }

    fn prepare_src(src: &str) -> &'static crate::worker::PreparedHttp {
        super::prepare(crate::config::parse(src).unwrap()).expect("prepare")
    }

    /// The prefix location `pattern` of the first server on listen `listen`.
    fn prefix<'a>(
        http: &'a crate::worker::PreparedHttp,
        listen: usize,
        pattern: &[u8],
    ) -> &'a crate::worker::PreparedLocation {
        http.listens[listen].servers[0]
            .prefix_locations
            .iter()
            .find(|l| l.pattern == pattern)
            .unwrap()
    }

    #[test]
    fn max_ranges_resolves_location_server_http() {
        // An http-level line below the servers still applies (nginx's merge
        // runs after the whole block).
        let http = prepare_src(
            r#"
            http {
                server {
                    listen 127.0.0.1:8080;
                    location /http { return 200; }
                    location /own { max_ranges 0; return 200; }
                    location /outer {
                        max_ranges 5;
                        location /outer/inner { return 200; }
                    }
                    location /if {
                        max_ranges 0;
                        if ($arg_a) { root /tmp; }
                    }
                }
                server {
                    listen 127.0.0.1:8081;
                    max_ranges 2;
                    location /srv { return 200; }
                }
                max_ranges 1;
            }
            "#,
        );
        assert_eq!(prefix(http, 0, b"/http").max_ranges, Some(1));
        assert_eq!(prefix(http, 0, b"/own").max_ranges, Some(0));
        assert_eq!(prefix(http, 0, b"/outer/inner").max_ranges, Some(5));
        assert_eq!(prefix(http, 0, b"/if").max_ranges, Some(0));
        let server = &http.listens[0].servers[0];
        assert_eq!(server.if_locations.len(), 1);
        assert_eq!(server.if_locations[0].max_ranges, Some(0));
        assert_eq!(prefix(http, 1, b"/srv").max_ranges, Some(2));
        // The server's implicit location for unmatched URIs.
        let implicit = http.listens[1].servers[0].server_default.as_ref().unwrap();
        assert_eq!(implicit.max_ranges, Some(2));

        let default = prepare_src("http { server { listen 127.0.0.1:8082; location / { } } }");
        assert_eq!(prefix(default, 0, b"/").max_ranges, None);
    }

    #[test]
    fn proxy_force_ranges_resolves_location_server_http() {
        let http = prepare_src(
            r#"
            http {
                server {
                    listen 127.0.0.1:8080;
                    location /http { proxy_pass http://127.0.0.1:9; }
                    location /off { proxy_force_ranges off; proxy_pass http://127.0.0.1:9; }
                }
                server {
                    listen 127.0.0.1:8081;
                    proxy_force_ranges off;
                    location /srv { proxy_pass http://127.0.0.1:9; }
                    location /loc { proxy_force_ranges on; proxy_pass http://127.0.0.1:9; }
                }
                proxy_force_ranges on;
            }
            "#,
        );
        let force = |listen: usize, pattern: &[u8]| match &prefix(http, listen, pattern).handler {
            crate::worker::PreparedHandler::Proxy(p) => p.force_ranges,
            _ => panic!("a proxy location"),
        };
        assert!(force(0, b"/http"));
        assert!(!force(0, b"/off"));
        assert!(!force(1, b"/srv"));
        assert!(force(1, b"/loc"));

        let default = prepare_src(
            "http { server { listen 127.0.0.1:8082; \
             location / { proxy_pass http://127.0.0.1:9; } } }",
        );
        let crate::worker::PreparedHandler::Proxy(p) = &prefix(default, 0, b"/").handler else {
            panic!("a proxy location");
        };
        assert!(!p.force_ranges);
    }
}
