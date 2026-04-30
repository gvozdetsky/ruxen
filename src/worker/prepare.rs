//! Configuration → `&'static PreparedHttp` build pass. Owns every
//! `Box::leak` on the startup path; nothing here runs after the workers
//! spawn.

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
    AccessLog, AddHeader, AuthBasic, AutoindexFormat, ErrorLog, ErrorLogLevel,
    ErrorLogSyslogServer, ErrorLogTarget, ErrorPage, ErrorPageAction, ExpiresDirective,
    FileTestKind, Handler, HttpConfig, IfGuard, IndexEntry, KeepaliveDisable, KeepaliveTimeout,
    Location, LogFormatDef, MapBlock, MapExactEntry, MapRegexEntry, MatchMode, PathMapping,
    ProxyPass, ProxySetHeader, RewriteFlag as ConfigRewriteFlag, RewriteOp, RewriteRule, Server,
    SplitClients, TryFiles, TryFilesFallback, TryFilesProbe, ValuePart, Variable,
};
use crate::http::{self, Method, Parse, ParseState, READ_BUF};
use crate::phase::{self, Response};
use crate::{autoindex, file, fs_resolve, uri};

use super::*;

pub fn prepare(cfg: HttpConfig) -> &'static PreparedHttp {
    let HttpConfig {
        runtime: _,
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
        post_action,
        expires: http_expires,
        ignore_invalid_headers,
        underscores_in_headers,
        upstreams,
        servers,
        warnings: _,
        dump_files: _,
    } = cfg;

    if servers.is_empty() {
        panic!("ruxen: no server blocks in config");
    }
    // Group server blocks by listen address while preserving declaration
    // order both across listen buckets and within each bucket.
    let mut grouped: Vec<(SocketAddr, Vec<Server>)> = Vec::new();
    for server in servers {
        let addr = server.listen.addr;
        if let Some((_, bucket)) = grouped.iter_mut().find(|(a, _)| *a == addr) {
            bucket.push(server);
        } else {
            grouped.push((addr, vec![server]));
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
    let http_auth_basic = auth_basic
        .map(prepare_auth_basic)
        .unwrap_or(PreparedAuthBasic::Off);
    let http_auth_basic_user_file = auth_basic_user_file.map(leak_path_buf);
    let http_auth_delay_ms = auth_delay_ms.unwrap_or(0);
    let http_client_max_body_size = client_max_body_size;
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
    let mut alp = AccessLogPrep::new(&log_formats);
    let http_access_logs: &'static [PreparedAccessLog] = alp.prepare_list(&access_logs);
    let prepared_split_clients = prepare_split_clients(split_clients);
    let prepared_maps = prepare_maps(maps);
    let prepared_upstreams: std::collections::HashMap<&'static str, &'static PreparedUpstream> =
        prepare_upstreams(upstreams);

    let mut listens: Vec<PreparedListen> = Vec::with_capacity(grouped.len());
    for (addr, servers_for_addr) in grouped {
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
            })
            .collect();
        let servers: Vec<PreparedServer> = servers_for_addr
            .into_iter()
            .map(|s| {
                prepare_server(
                    s,
                    http_tokens,
                    http_access_logs,
                    http_autoindex,
                    http_autoindex_exact_size,
                    http_autoindex_localtime,
                    http_autoindex_format,
                    http_auth_basic,
                    http_auth_basic_user_file,
                    http_auth_delay_ms,
                    http_client_max_body_size,
                    http_post_action,
                    http_expires,
                    http_ignore_invalid_headers,
                    http_underscores_in_headers,
                    &prepared_upstreams,
                    &mut alp,
                )
            })
            .collect();
        let tls = build_listen_tls(addr, &tls_inputs);
        listens.push(PreparedListen {
            addr,
            servers,
            default_server: 0,
            tls,
        });
    }

    let canonical_access_logs = alp.finish();

    Box::leak(Box::new(PreparedHttp {
        listens,
        access_logs: canonical_access_logs,
        split_clients: prepared_split_clients,
        maps: prepared_maps,
        not_found: Prebuilt::leak(404, "Not Found\n", http_server_bytes),
        bad_request: Prebuilt::leak(400, "Bad Request\n", http_server_bytes),
        not_implemented: Prebuilt::leak(501, "Not Implemented\n", http_server_bytes),
        forbidden: Prebuilt::leak(403, "Forbidden\n", http_server_bytes),
        bad_gateway: Prebuilt::leak(502, "Bad Gateway\n", http_server_bytes),
        gateway_timeout: Prebuilt::leak(504, "Gateway Timeout\n", http_server_bytes),
        upstreams: prepared_upstreams,
    }))
}

/// TLS-relevant snapshot for one `server {}` block, captured before
/// `prepare_server` consumes the original.
pub(crate) struct TlsServerInput {
    ssl_listen: bool,
    default_server: bool,
    ssl: crate::config::ServerSsl,
    server_names: Vec<crate::config::ServerNameSpec>,
}

/// Build the per-listen `TlsAcceptor`, or `None` when no server on this
/// address declared `listen … ssl;`. Cert load failures or empty cert sets
/// abort startup — the parser already validated that ssl listens carry
/// matching `ssl_certificate`/`ssl_certificate_key` pairs, so anything
/// failing here is an unreadable file or a malformed PEM, neither of which
/// we can recover from.
pub(crate) fn build_listen_tls(
    addr: SocketAddr,
    inputs: &[TlsServerInput],
) -> Option<Arc<crate::tls::TlsAcceptor>> {
    use crate::config::ServerNameSpec;

    if !inputs.iter().any(|i| i.ssl_listen) {
        return None;
    }

    let mut resolver = crate::tls_certs::ServerNameResolver::new();
    let mut default_keys: Vec<Arc<rustls::sign::CertifiedKey>> = Vec::new();
    let mut default_idx: Option<usize> = None;
    let mut protocols = crate::config::TlsVersionSet::default();
    let mut saw_protocols = false;
    let mut session_timeout_secs: Option<u32> = None;

    for (idx, input) in inputs.iter().enumerate() {
        if !input.ssl_listen {
            continue;
        }
        if input.ssl.certs.is_empty() {
            panic!(
                "ruxen: listen {addr}: server with `listen ssl;` has no ssl_certificate \
                 (parser should have caught this; reaching prepare with an empty cert list \
                 is a bug)"
            );
        }
        if !saw_protocols {
            protocols = input.ssl.protocols;
            saw_protocols = true;
        }

        let mut keys: Vec<Arc<rustls::sign::CertifiedKey>> =
            Vec::with_capacity(input.ssl.certs.len());
        for (cert, key) in input.ssl.certs.iter().zip(input.ssl.keys.iter()) {
            let ck = crate::tls_certs::load_certified_key(cert, key)
                .unwrap_or_else(|e| panic!("ruxen: listen {addr}: {e}"));
            keys.push(Arc::new(ck));
        }

        // Register each registered server_name against every key so an RSA
        // + ECDSA pair can both serve under the same hostname.
        for name in &input.server_names {
            for ck in &keys {
                match name {
                    ServerNameSpec::Exact(host) => resolver.add_exact(host, ck.clone()),
                    ServerNameSpec::WildcardLeading { suffix, .. } => {
                        resolver.add_wildcard(suffix, ck.clone());
                    }
                    // WildcardTrailing / Regex / Empty don't map to TLS-layer
                    // SNI dispatch — rustls only sees the host, not the
                    // leading-label or pattern. The HTTP-layer match_server
                    // ladder still routes these correctly once the handshake
                    // settles on the default cert.
                    ServerNameSpec::WildcardTrailing { .. }
                    | ServerNameSpec::Regex { .. }
                    | ServerNameSpec::Empty => {}
                }
            }
        }

        // Default cert ladder: explicit `default_server` flag wins; otherwise
        // the first ssl server on this listen.
        if default_idx.is_none() || (input.default_server && default_idx != Some(idx)) {
            if input.default_server || default_idx.is_none() {
                default_keys = keys;
                default_idx = Some(idx);
                // Per-listener session timeout follows the default server.
                // Multiple ssl servers on one listen share one rustls
                // ServerConfig; nginx behaves the same way (the directive
                // is effectively a per-listen knob).
                session_timeout_secs = input
                    .ssl
                    .session_timeout_ms
                    .map(|ms| (ms / 1000).clamp(1, u32::MAX as u64) as u32);
            }
        }
    }

    resolver.set_default(default_keys);
    let cfg = crate::tls_certs::build_server_config(resolver, protocols, session_timeout_secs)
        .unwrap_or_else(|e| panic!("ruxen: listen {addr}: build TLS config: {e}"));
    Some(Arc::new(crate::tls::acceptor_from_config(cfg)))
}

pub(crate) fn prepare_upstreams(
    upstreams: Vec<crate::config::UpstreamBlock>,
) -> std::collections::HashMap<&'static str, &'static PreparedUpstream> {
    let mut out = std::collections::HashMap::new();
    for u in upstreams {
        let name_static: &'static str = Box::leak(u.name.into_boxed_str());
        let mut peers_vec: Vec<PreparedPeer> = Vec::with_capacity(u.servers.len());
        for s in u.servers {
            let display: &'static [u8] = Box::leak(s.display.into_bytes().into_boxed_slice());
            peers_vec.push(PreparedPeer {
                addr: s.addr,
                display,
                weight: s.weight,
                max_fails: s.max_fails,
                fail_timeout_ms: (s.fail_timeout_secs as u64) * 1_000,
                down: s.down,
                backup: s.backup,
            });
        }
        let peers: &'static [PreparedPeer] = Box::leak(peers_vec.into_boxed_slice());
        let prepared = Box::leak(Box::new(PreparedUpstream {
            name: name_static.as_bytes(),
            peers,
            keepalive_max_idle: u.keepalive_max_idle,
            keepalive_requests: u.keepalive_requests.unwrap_or(1000),
            keepalive_idle_timeout_ms: u.keepalive_idle_timeout_ms.unwrap_or(60_000),
            keepalive_max_lifetime_ms: u.keepalive_max_lifetime_ms.unwrap_or(3_600_000),
            lb: u.lb,
        }));
        out.insert(name_static, &*prepared);
    }
    out
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
) -> PreparedProxy {
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
                panic!(
                    "ruxen: proxy_pass URL path is not allowed inside named location {} (prefix-mode locations only)",
                    String::from_utf8_lossy(location_pattern)
                );
            }
            let path: &'static [u8] = Box::leak(p.clone().into_bytes().into_boxed_slice());
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
            panic!(
                "ruxen: proxy_pass URL path is not allowed in a regex location (matches nginx ngx_http_proxy_module.c)"
            );
        }
        _ => (b"".as_slice(), b"".as_slice()),
    };
    match pp {
        ProxyPass::Direct {
            addr, host_header, ..
        } => {
            let display: &'static [u8] =
                Box::leak(host_header.clone().into_bytes().into_boxed_slice());
            let peer = PreparedPeer {
                addr,
                display,
                weight: 1,
                max_fails: 1,
                fail_timeout_ms: 10_000,
                down: false,
                backup: false,
            };
            let peers: &'static [PreparedPeer] = Box::leak(Box::new([peer]));
            let host_header_static: &'static [u8] =
                Box::leak(host_header.into_bytes().into_boxed_slice());
            let upstream: &'static PreparedUpstream = Box::leak(Box::new(PreparedUpstream {
                name: host_header_static,
                peers,
                keepalive_max_idle: None,
                keepalive_requests: 1000,
                keepalive_idle_timeout_ms: 60_000,
                keepalive_max_lifetime_ms: 3_600_000,
                lb: crate::config::LbAlgorithm::RoundRobin,
            }));
            PreparedProxy {
                upstream,
                host_header: host_header_static,
                set_headers: eff.set_headers,
                pass_request_headers: eff.pass_request_headers,
                pass_request_body: eff.pass_request_body,
                connect_timeout_ms: eff.connect_timeout_ms,
                read_timeout_ms: eff.read_timeout_ms,
                send_timeout_ms: eff.send_timeout_ms,
                limit_rate: eff.limit_rate,
                http_version: eff.http_version,
                next_upstream: eff.next_upstream,
                next_upstream_tries: eff.next_upstream_tries,
                next_upstream_timeout_ms: eff.next_upstream_timeout_ms,
                intercept_errors: eff.intercept_errors,
                ignore_invalid_headers: eff.ignore_invalid_headers,
                underscores_in_headers: eff.underscores_in_headers,
                location_prefix,
                request_path,
            }
        }
        ProxyPass::UpstreamRef {
            name, host_header, ..
        } => {
            let upstream = *upstreams.get(name.as_str()).unwrap_or_else(|| {
                panic!("ruxen: proxy_pass http://{name} references undeclared upstream block")
            });
            if upstream.peers.is_empty() {
                panic!("ruxen: upstream {name} has no servers (parser invariant violated)");
            }
            let host_header_static: &'static [u8] =
                Box::leak(host_header.into_bytes().into_boxed_slice());
            PreparedProxy {
                upstream,
                host_header: host_header_static,
                set_headers: eff.set_headers,
                pass_request_headers: eff.pass_request_headers,
                pass_request_body: eff.pass_request_body,
                connect_timeout_ms: eff.connect_timeout_ms,
                read_timeout_ms: eff.read_timeout_ms,
                send_timeout_ms: eff.send_timeout_ms,
                limit_rate: eff.limit_rate,
                http_version: eff.http_version,
                next_upstream: eff.next_upstream,
                next_upstream_tries: eff.next_upstream_tries,
                next_upstream_timeout_ms: eff.next_upstream_timeout_ms,
                intercept_errors: eff.intercept_errors,
                ignore_invalid_headers: eff.ignore_invalid_headers,
                underscores_in_headers: eff.underscores_in_headers,
                location_prefix,
                request_path,
            }
        }
    }
}

/// Server-scope proxy defaults — used as the parent in location-scope
/// inheritance. Built once per server in `prepare_server`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ServerProxyDefaults {
    pub set_headers: &'static [PreparedProxySetHeader],
    pub pass_request_headers: bool,
    pub pass_request_body: bool,
    pub connect_timeout_ms: u64,
    pub read_timeout_ms: u64,
    pub send_timeout_ms: u64,
    pub limit_rate: u64,
    pub http_version: u8,
    pub next_upstream: crate::config::ProxyNextUpstream,
    pub next_upstream_tries: u32,
    pub next_upstream_timeout_ms: u64,
    pub intercept_errors: bool,
    pub ignore_invalid_headers: bool,
    pub underscores_in_headers: bool,
}

impl ServerProxyDefaults {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn build(
        proxy_set_headers: Option<Vec<ProxySetHeader>>,
        proxy_pass_request_headers: Option<bool>,
        proxy_pass_request_body: Option<bool>,
        proxy_connect_timeout_ms: Option<u64>,
        proxy_read_timeout_ms: Option<u64>,
        proxy_send_timeout_ms: Option<u64>,
        proxy_limit_rate: Option<u64>,
        proxy_http_version: Option<u8>,
        proxy_next_upstream: Option<crate::config::ProxyNextUpstream>,
        proxy_next_upstream_tries: Option<u32>,
        proxy_next_upstream_timeout_ms: Option<u64>,
        proxy_intercept_errors: Option<bool>,
        ignore_invalid_headers: bool,
        underscores_in_headers: bool,
    ) -> Self {
        let defaults = ProxyEffective::defaults();
        let set_headers: &'static [PreparedProxySetHeader] = match proxy_set_headers {
            Some(list) => prepare_proxy_set_headers(list),
            None => &[],
        };
        Self {
            set_headers,
            pass_request_headers: proxy_pass_request_headers
                .unwrap_or(defaults.pass_request_headers),
            pass_request_body: proxy_pass_request_body.unwrap_or(defaults.pass_request_body),
            connect_timeout_ms: proxy_connect_timeout_ms.unwrap_or(defaults.connect_timeout_ms),
            read_timeout_ms: proxy_read_timeout_ms.unwrap_or(defaults.read_timeout_ms),
            send_timeout_ms: proxy_send_timeout_ms.unwrap_or(defaults.send_timeout_ms),
            limit_rate: proxy_limit_rate.unwrap_or(defaults.limit_rate),
            http_version: proxy_http_version.unwrap_or(defaults.http_version),
            next_upstream: proxy_next_upstream.unwrap_or(defaults.next_upstream),
            next_upstream_tries: proxy_next_upstream_tries.unwrap_or(defaults.next_upstream_tries),
            next_upstream_timeout_ms: proxy_next_upstream_timeout_ms
                .unwrap_or(defaults.next_upstream_timeout_ms),
            intercept_errors: proxy_intercept_errors.unwrap_or(defaults.intercept_errors),
            ignore_invalid_headers,
            underscores_in_headers,
        }
    }
}

pub(crate) fn prepare_proxy_set_headers(list: Vec<ProxySetHeader>) -> &'static [PreparedProxySetHeader] {
    let mut out: Vec<PreparedProxySetHeader> = Vec::with_capacity(list.len());
    for h in list {
        let name: &'static [u8] = Box::leak(h.name.into_bytes().into_boxed_slice());
        let value: &'static [PreparedValuePart] = prepare_value_parts(h.value);
        out.push(PreparedProxySetHeader { name, value });
    }
    Box::leak(out.into_boxed_slice())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn resolve_proxy_effective(
    location_set_headers: Option<Vec<ProxySetHeader>>,
    location_pass_request_headers: Option<bool>,
    location_pass_request_body: Option<bool>,
    location_connect_timeout_ms: Option<u64>,
    location_read_timeout_ms: Option<u64>,
    location_send_timeout_ms: Option<u64>,
    location_limit_rate: Option<u64>,
    location_http_version: Option<u8>,
    location_next_upstream: Option<crate::config::ProxyNextUpstream>,
    location_next_upstream_tries: Option<u32>,
    location_next_upstream_timeout_ms: Option<u64>,
    location_intercept_errors: Option<bool>,
    server_defaults: ServerProxyDefaults,
) -> ProxyEffective {
    let set_headers: &'static [PreparedProxySetHeader] = match location_set_headers {
        Some(list) => prepare_proxy_set_headers(list),
        None => server_defaults.set_headers,
    };
    ProxyEffective {
        set_headers,
        http_version: location_http_version.unwrap_or(server_defaults.http_version),
        pass_request_headers: location_pass_request_headers
            .unwrap_or(server_defaults.pass_request_headers),
        pass_request_body: location_pass_request_body.unwrap_or(server_defaults.pass_request_body),
        connect_timeout_ms: location_connect_timeout_ms
            .unwrap_or(server_defaults.connect_timeout_ms),
        read_timeout_ms: location_read_timeout_ms.unwrap_or(server_defaults.read_timeout_ms),
        send_timeout_ms: location_send_timeout_ms.unwrap_or(server_defaults.send_timeout_ms),
        limit_rate: location_limit_rate.unwrap_or(server_defaults.limit_rate),
        next_upstream: location_next_upstream.unwrap_or(server_defaults.next_upstream),
        next_upstream_tries: location_next_upstream_tries
            .unwrap_or(server_defaults.next_upstream_tries),
        next_upstream_timeout_ms: location_next_upstream_timeout_ms
            .unwrap_or(server_defaults.next_upstream_timeout_ms),
        intercept_errors: location_intercept_errors.unwrap_or(server_defaults.intercept_errors),
        ignore_invalid_headers: server_defaults.ignore_invalid_headers,
        underscores_in_headers: server_defaults.underscores_in_headers,
    }
}

pub(crate) fn prepare_server(
    mut server: Server,
    http_tokens: crate::config::ServerTokens,
    http_access_logs: &'static [PreparedAccessLog],
    http_autoindex: bool,
    http_autoindex_exact_size: bool,
    http_autoindex_localtime: bool,
    http_autoindex_format: AutoindexFormat,
    http_auth_basic: PreparedAuthBasic,
    http_auth_basic_user_file: Option<&'static Path>,
    http_auth_delay_ms: u64,
    http_client_max_body_size: Option<u64>,
    http_post_action: Option<&'static [u8]>,
    http_expires: PreparedExpires,
    http_ignore_invalid_headers: bool,
    http_underscores_in_headers: bool,
    upstreams: &UpstreamMap,
    alp: &mut AccessLogPrep<'_>,
) -> PreparedServer {
    let listen_port = server.listen.addr.port();
    let merge_slashes = server.merge_slashes;
    let server_ignore_invalid_headers = server
        .ignore_invalid_headers
        .unwrap_or(http_ignore_invalid_headers);
    let server_underscores_in_headers = server
        .underscores_in_headers
        .unwrap_or(http_underscores_in_headers);
    // Take ownership of proxy_* fields up front. Partial moves below
    // (Option::map) would otherwise prevent later access.
    let server_proxy_defaults = ServerProxyDefaults::build(
        server.proxy_set_headers.take(),
        server.proxy_pass_request_headers,
        server.proxy_pass_request_body,
        server.proxy_connect_timeout_ms,
        server.proxy_read_timeout_ms,
        server.proxy_send_timeout_ms,
        server.proxy_limit_rate,
        server.proxy_http_version,
        server.proxy_next_upstream,
        server.proxy_next_upstream_tries,
        server.proxy_next_upstream_timeout_ms,
        server.proxy_intercept_errors,
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
                exact_names.push(Box::leak(b.into_boxed_slice()));
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
                let regex = regex::bytes::RegexBuilder::new(&pattern)
                    .case_insensitive(case_insensitive)
                    .build()
                    .unwrap_or_else(|e| {
                        panic!(
                            "ruxen: server_name regex {:?} failed to compile after parse-time validation: {e}",
                            pattern
                        )
                    });
                let capture_names: Vec<&'static str> = regex
                    .capture_names()
                    .flatten()
                    .map(|n| &*Box::leak(n.to_string().into_boxed_str()))
                    .collect();
                regex_names.push(PreparedRegexName {
                    regex,
                    capture_names,
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
    wildcard_leading.sort_by(|a, b| b.len().cmp(&a.len()));
    wildcard_trailing.sort_by(|a, b| b.len().cmp(&a.len()));

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
        Some(list) => prepare_error_logs(list),
        None => &[],
    };
    let server_log_not_found = server.log_not_found.unwrap_or(true);
    let server_auth_basic = server
        .auth_basic
        .map(prepare_auth_basic)
        .unwrap_or(http_auth_basic);
    let server_auth_basic_user_file = server
        .auth_basic_user_file
        .map(leak_path_buf)
        .or(http_auth_basic_user_file);
    let server_auth_delay_ms = server.auth_delay_ms.unwrap_or(http_auth_delay_ms);
    let server_client_max_body_size = server.client_max_body_size.or(http_client_max_body_size);
    let server_post_action = server
        .post_action
        .as_ref()
        .map(|target| leak_bytes(target.as_bytes()))
        .or(http_post_action);
    let server_expires = server
        .expires
        .clone()
        .map(prepare_expires)
        .unwrap_or(http_expires);
    // chunked_transfer_encoding has no http-scope inheritance pathway in
    // ruxen yet; default to nginx's `on` when unset at server scope.
    let server_chunked_transfer_encoding = server.chunked_transfer_encoding.unwrap_or(true);
    let server_autoindex = server.autoindex.unwrap_or(http_autoindex);
    let server_autoindex_exact_size = server
        .autoindex_exact_size
        .unwrap_or(http_autoindex_exact_size);
    let server_autoindex_localtime = server
        .autoindex_localtime
        .unwrap_or(http_autoindex_localtime);
    let server_autoindex_format = server.autoindex_format.unwrap_or(http_autoindex_format);
    // server_tokens inheritance: server scope wins over http scope; both
    // default to `On`. Resolved once here; prepare_handler downstream
    // bakes the right `Server:` bytes into static prebuilts.
    let server_tokens_value = server.server_tokens.unwrap_or(http_tokens);
    let server_header_bytes = http::server_header_value(server_tokens_value);
    // access_log inheritance: server-scope list (if set) replaces http;
    // None inherits the http-scope list. Empty `Some(vec![])` means the
    // user wrote `access_log off;` at server scope — explicit silence.
    let server_access_logs: &'static [PreparedAccessLog] = match server.access_logs {
        Some(ref list) => alp.prepare_list(list),
        None => http_access_logs,
    };
    // Done last because Server can't be partially moved further down.

    let mut exact: Vec<PreparedLocation> = Vec::new();
    let mut prefix: Vec<PreparedLocation> = Vec::new();
    let mut regex: Vec<PreparedRegexLocation> = Vec::new();
    let mut named: Vec<PreparedLocation> = Vec::new();
    for l in server.locations {
        match l.mode {
            MatchMode::Exact => exact.push(build_prefix_or_exact(
                l,
                server_index,
                server_add_headers,
                server_add_trailers,
                server_error_pages,
                server_keepalive,
                server_error_logs,
                server_log_not_found,
                server_tokens_value,
                server_autoindex,
                server_autoindex_exact_size,
                server_autoindex_localtime,
                server_autoindex_format,
                server_access_logs,
                server_auth_basic,
                server_auth_basic_user_file,
                server_auth_delay_ms,
                server_client_max_body_size,
                server_post_action,
                server_expires,
                server_chunked_transfer_encoding,
                server_proxy_defaults,
                upstreams,
                alp,
            )),
            MatchMode::Prefix => prefix.push(build_prefix_or_exact(
                l,
                server_index,
                server_add_headers,
                server_add_trailers,
                server_error_pages,
                server_keepalive,
                server_error_logs,
                server_log_not_found,
                server_tokens_value,
                server_autoindex,
                server_autoindex_exact_size,
                server_autoindex_localtime,
                server_autoindex_format,
                server_access_logs,
                server_auth_basic,
                server_auth_basic_user_file,
                server_auth_delay_ms,
                server_client_max_body_size,
                server_post_action,
                server_expires,
                server_chunked_transfer_encoding,
                server_proxy_defaults,
                upstreams,
                alp,
            )),
            MatchMode::Named => named.push(build_prefix_or_exact(
                l,
                server_index,
                server_add_headers,
                server_add_trailers,
                server_error_pages,
                server_keepalive,
                server_error_logs,
                server_log_not_found,
                server_tokens_value,
                server_autoindex,
                server_autoindex_exact_size,
                server_autoindex_localtime,
                server_autoindex_format,
                server_access_logs,
                server_auth_basic,
                server_auth_basic_user_file,
                server_auth_delay_ms,
                server_client_max_body_size,
                server_post_action,
                server_expires,
                server_chunked_transfer_encoding,
                server_proxy_defaults,
                upstreams,
                alp,
            )),
            MatchMode::Regex { case_insensitive } => regex.push(build_regex_location(
                l,
                case_insensitive,
                server_index,
                server_add_headers,
                server_add_trailers,
                server_error_pages,
                server_keepalive,
                server_error_logs,
                server_log_not_found,
                server_tokens_value,
                server_autoindex,
                server_autoindex_exact_size,
                server_autoindex_localtime,
                server_autoindex_format,
                server_access_logs,
                server_auth_basic,
                server_auth_basic_user_file,
                server_auth_delay_ms,
                server_client_max_body_size,
                server_post_action,
                server_expires,
                server_chunked_transfer_encoding,
                server_proxy_defaults,
                upstreams,
                alp,
            )),
        }
    }
    exact.sort_by(|a, b| a.pattern.cmp(b.pattern));
    prefix.sort_by(|a, b| b.pattern.len().cmp(&a.pattern.len()));
    // regex_locations stay in declaration order — first match wins.

    // Synthesize a nameless catch-all PreparedLocation that fires when the
    // normal ladder finds no match. Three sources, in priority:
    //   1. Server-scope `return STATUS [body]` (nginx rewrite-phase action).
    //   2. Server-scope `root` without an explicit `/` prefix location —
    //      nginx always has an implicit `/` that serves from root.
    //   3. None → real 404 fallback in phase::process.
    // The prepared location inherits the server's add_header / error_page
    // lists via the same path explicit locations use.
    let have_root_catchall =
        exact.iter().any(|l| l.pattern == b"/") || prefix.iter().any(|l| l.pattern == b"/");
    let server_default = if let Some((status, body)) = server.server_return {
        let pattern: &'static [u8] = b"";
        let handler = build_handler(
            Handler::Return { status, body },
            pattern,
            false,
            None,
            None,
            None,
            server_index,
            None,
            None,
            None,
            None,
            server_autoindex,
            server_autoindex_exact_size,
            server_autoindex_localtime,
            server_autoindex_format,
            server_tokens_value,
            upstreams,
            ProxyEffective::defaults(),
        );
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
            server_header: server_header_bytes,
            access_logs: server_access_logs,
            auth_basic: server_auth_basic,
            auth_basic_user_file: server_auth_basic_user_file,
            auth_delay_ms: server_auth_delay_ms,
            client_max_body_size: server_client_max_body_size,
            client_body_in_file_only: crate::config::ClientBodyInFileOnly::Off,
            post_action: server_post_action,
            expires: server_expires,
            chunked_transfer_encoding: server_chunked_transfer_encoding,
        })
    } else if let Some(root_path) = server.root.clone().filter(|_| !have_root_catchall) {
        let pattern: &'static [u8] = b"/";
        let handler = build_handler(
            Handler::Root {
                path: root_path,
                mapping: PathMapping::Root,
            },
            pattern,
            false,
            None,
            None,
            None,
            server_index,
            None,
            None,
            None,
            None,
            server_autoindex,
            server_autoindex_exact_size,
            server_autoindex_localtime,
            server_autoindex_format,
            server_tokens_value,
            upstreams,
            ProxyEffective::defaults(),
        );
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
            server_header: server_header_bytes,
            access_logs: server_access_logs,
            auth_basic: server_auth_basic,
            auth_basic_user_file: server_auth_basic_user_file,
            auth_delay_ms: server_auth_delay_ms,
            client_max_body_size: server_client_max_body_size,
            client_body_in_file_only: crate::config::ClientBodyInFileOnly::Off,
            post_action: server_post_action,
            expires: server_expires,
            chunked_transfer_encoding: server_chunked_transfer_encoding,
        })
    } else {
        None
    };

    PreparedServer {
        exact_names,
        wildcard_leading,
        wildcard_trailing,
        regex_names,
        matches_empty,
        primary_server_name,
        listen_port,
        exact_locations: exact,
        prefix_locations: prefix,
        regex_locations: regex,
        named_locations: named,
        server_default,
        error_logs: server_error_logs,
        log_not_found: server_log_not_found,
        merge_slashes,
        server_header: server_header_bytes,
        access_logs: server_access_logs,
        auth_basic: server_auth_basic,
        auth_basic_user_file: server_auth_basic_user_file,
        auth_delay_ms: server_auth_delay_ms,
        underscores_in_headers: server_underscores_in_headers,
        post_action: server_post_action,
    }
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
    Box::leak(prepared.into_boxed_slice())
}

pub(crate) fn prepare_index_entries(list: Vec<IndexEntry>) -> &'static [PreparedIndexEntry] {
    let prepared: Vec<PreparedIndexEntry> = list
        .into_iter()
        .map(|entry| PreparedIndexEntry {
            parts: prepare_value_parts(entry.parts),
        })
        .collect();
    Box::leak(prepared.into_boxed_slice())
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
    Box::leak(prepared.into_boxed_slice())
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
    Box::leak(v.into_boxed_slice())
}

pub(crate) fn leak_regex(regex: regex::bytes::Regex) -> &'static regex::bytes::Regex {
    Box::leak(Box::new(regex))
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
            let regex = regex::bytes::RegexBuilder::new(&pattern)
                .case_insensitive(case_insensitive)
                .build()
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

pub(crate) fn prepare_rewrite_ops(
    ops: Vec<RewriteOp>,
    tokens: crate::config::ServerTokens,
) -> &'static [PreparedRewriteOp] {
    if ops.is_empty() {
        return &[];
    }
    let mut prepared: Vec<PreparedRewriteOp> = Vec::with_capacity(ops.len());
    for op in ops {
        let prepared_op = match op {
            RewriteOp::Set { name, value } => PreparedRewriteOp::Set {
                name: leak_bytes(name.as_bytes()),
                value: prepare_value_parts(value),
            },
            RewriteOp::If { guard, body } => PreparedRewriteOp::If {
                guard: prepare_guard(guard),
                body: prepare_rewrite_ops(body, tokens),
            },
            RewriteOp::Rewrite(RewriteRule {
                regex,
                replacement,
                replacement_args,
                flag,
                drop_args,
            }) => {
                let regex = regex::bytes::Regex::new(&regex).unwrap_or_else(|e| {
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
                PreparedRewriteOp::Return(prepare_return(status, body, tokens))
            }
            RewriteOp::Break => PreparedRewriteOp::Break,
        };
        prepared.push(prepared_op);
    }
    Box::leak(prepared.into_boxed_slice())
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
            parts: Box::leak(parts.into_boxed_slice()),
        };
        let key: &'static str = Box::leak(block.variable.into_boxed_str());
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
pub(crate) fn prepare_maps(blocks: Vec<MapBlock>) -> std::collections::HashMap<&'static str, PreparedMap> {
    let mut out = std::collections::HashMap::new();
    for block in blocks {
        let MapBlock {
            key,
            variable,
            exact,
            regex,
            default,
        } = block;
        let mut exact_map: std::collections::HashMap<Vec<u8>, &'static [PreparedValuePart]> =
            std::collections::HashMap::with_capacity(exact.len());
        for MapExactEntry { key: k, value } in exact {
            exact_map.insert(k.into_bytes(), prepare_value_parts(value));
        }
        let mut regex_entries: Vec<PreparedMapRegex> = Vec::with_capacity(regex.len());
        for MapRegexEntry {
            pattern,
            case_insensitive,
            value,
        } in regex
        {
            // Already validated at parse time; a failure here is a bug.
            let compiled = regex::bytes::RegexBuilder::new(&pattern)
                .case_insensitive(case_insensitive)
                .build()
                .expect("map regex validated at parse time");
            regex_entries.push(PreparedMapRegex {
                regex: compiled,
                value: prepare_value_parts(value),
            });
        }
        let prepared = PreparedMap {
            key: prepare_value_parts(key),
            exact: exact_map,
            regex: Box::leak(regex_entries.into_boxed_slice()),
            default: default.map(prepare_value_parts),
        };
        let var_key: &'static str = Box::leak(variable.into_boxed_str());
        out.insert(var_key, prepared);
    }
    out
}

/// Builder used during `prepare()` to assign sequential `file_index`
/// values to every `PreparedAccessLog` across http / server / location
/// scopes. The canonical list (`PreparedHttp::access_logs`) is the
/// concatenation of every prepared sink in declaration order; per-scope
/// slices share `file_index` values that point back into it, so the
/// per-worker fd table opened from the canonical list serves all scopes.
pub(crate) struct AccessLogPrep<'a> {
    format_map: std::collections::HashMap<&'a str, &'a [ValuePart]>,
    canonical: Vec<PreparedAccessLog>,
}

impl<'a> AccessLogPrep<'a> {
    pub(crate) fn new(formats: &'a [LogFormatDef]) -> Self {
        let mut format_map: std::collections::HashMap<&'a str, &'a [ValuePart]> =
            std::collections::HashMap::new();
        for f in formats {
            format_map.insert(f.name.as_str(), f.value.as_slice());
        }
        Self {
            format_map,
            canonical: Vec::new(),
        }
    }

    pub(crate) fn prepare_one(&mut self, log: &AccessLog) -> PreparedAccessLog {
        // nginx default format name.
        const DEFAULT_FORMAT_NAME: &str = "combined";
        let chosen_format = log.format.as_deref().unwrap_or(DEFAULT_FORMAT_NAME);
        let format = if let Some(parts) = self.format_map.get(chosen_format) {
            prepare_value_parts(parts.to_vec())
        } else if chosen_format == DEFAULT_FORMAT_NAME {
            // Built-in fallback for bare `access_log /path;` in harness
            // preambles when no explicit `log_format combined ...` is
            // declared. It is intentionally narrower than nginx's full
            // combined format, but keeps the request line/status/size
            // fields that upstream tests inspect.
            prepare_value_parts(vec![
                ValuePart::Var(Variable::RemoteAddr),
                ValuePart::Literal(" - ".into()),
                ValuePart::Var(Variable::RemoteUser),
                ValuePart::Literal(" [".into()),
                ValuePart::Var(Variable::TimeLocal),
                ValuePart::Literal("] \"".into()),
                ValuePart::Var(Variable::RequestMethod),
                ValuePart::Literal(" ".into()),
                ValuePart::Var(Variable::RequestUri),
                ValuePart::Literal("\" ".into()),
                ValuePart::Var(Variable::Status),
                ValuePart::Literal(" ".into()),
                ValuePart::Var(Variable::BodyBytesSent),
            ])
        } else {
            panic!(
                "ruxen: access_log references unknown log_format `{}`",
                chosen_format
            );
        };
        // Ensure the file exists so tests that read it don't fail with
        // ENOENT even when no request matches `if=...`.
        let _ = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log.path);

        let file_index = self.canonical.len();
        let prepared = PreparedAccessLog {
            path: Box::leak(log.path.clone().into_boxed_path()),
            format,
            condition: log.condition.clone().map(prepare_value_parts),
            file_index,
        };
        self.canonical.push(prepared);
        prepared
    }

    pub(crate) fn prepare_list(&mut self, list: &[AccessLog]) -> &'static [PreparedAccessLog] {
        if list.is_empty() {
            return &[];
        }
        let prepared: Vec<PreparedAccessLog> = list.iter().map(|l| self.prepare_one(l)).collect();
        Box::leak(prepared.into_boxed_slice())
    }

    pub(crate) fn finish(self) -> &'static [PreparedAccessLog] {
        Box::leak(self.canonical.into_boxed_slice())
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
        AuthBasic::Realm(bytes) => PreparedAuthBasic::Realm(Box::leak(bytes.into_boxed_slice())),
    }
}

pub(crate) fn leak_path_buf(path: std::path::PathBuf) -> &'static Path {
    Box::leak(path.into_boxed_path())
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

pub(crate) fn prepare_return(
    status: u16,
    body: Vec<ValuePart>,
    tokens: crate::config::ServerTokens,
) -> PreparedReturn {
    let server_bytes = http::server_header_value(tokens);
    if all_literal(&body) {
        let concatenated = concat_literals(&body);
        PreparedReturn::Static(if is_redirect_return(status, &body) {
            Prebuilt::leak_redirect(status, concatenated.as_bytes(), server_bytes)
        } else if body.is_empty() {
            // `return STATUS;` with no body: when the status has a canned
            // nginx error page (4xx/5xx), substitute it — including the
            // `<center>nginx/X.Y.Z</center>` signature that respects
            // `server_tokens`.
            match http::default_error_page_body(status, tokens) {
                Some(default_body) => Prebuilt::leak_bytes(status, &default_body, server_bytes),
                None => Prebuilt::leak(status, &concatenated, server_bytes),
            }
        } else {
            Prebuilt::leak(status, &concatenated, server_bytes)
        })
    } else {
        PreparedReturn::Template {
            status,
            parts: prepare_value_parts(body),
        }
    }
}

pub(crate) fn build_handler(
    handler: Handler,
    location_pattern: &'static [u8],
    is_regex_location: bool,
    alias_prefix_override: Option<&'static [u8]>,
    location_index: Option<Vec<IndexEntry>>,
    location_try_files: Option<TryFiles>,
    server_index: Option<&'static [PreparedIndexEntry]>,
    location_autoindex: Option<bool>,
    location_autoindex_exact_size: Option<bool>,
    location_autoindex_localtime: Option<bool>,
    location_autoindex_format: Option<AutoindexFormat>,
    server_autoindex: bool,
    server_autoindex_exact_size: bool,
    server_autoindex_localtime: bool,
    server_autoindex_format: AutoindexFormat,
    tokens: crate::config::ServerTokens,
    upstreams: &UpstreamMap,
    proxy_effective: ProxyEffective,
) -> PreparedHandler {
    match handler {
        Handler::Return { status, body } => {
            PreparedHandler::Return(prepare_return(status, body, tokens))
        }
        Handler::Proxy(pp) => PreparedHandler::Proxy(build_proxy(
            pp,
            upstreams,
            proxy_effective,
            location_pattern,
            is_regex_location,
        )),
        Handler::Root { path, mapping } => {
            // Canonicalize once to fail fast on a bad root path; the
            // resolved inode will also be the one `openat2(RESOLVE_BENEATH)`
            // is anchored to, so symlinks in the configured root path can't
            // retarget the "beneath" set at runtime.
            let canonical = path.canonicalize().unwrap_or_else(|e| {
                panic!(
                    "ruxen: cannot canonicalize root {}: {e} (directory must exist at startup)",
                    path.display()
                )
            });
            let root: &'static Path = Box::leak(path.into_boxed_path());
            let root_fd = {
                use std::os::unix::fs::OpenOptionsExt;
                use std::os::unix::io::IntoRawFd;
                // No `O_DIRECTORY` — nginx allows `alias /some/file;` at
                // exact locations, so the configured "root" can legally
                // be a regular file. The resolver handles both shapes:
                // dir becomes an `openat2` anchor, file is `dup`'d back
                // out as the served fd when the URL-mapped rel is empty.
                let flags = libc::O_CLOEXEC;
                let f = std::fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(flags)
                    .open(&canonical)
                    .unwrap_or_else(|e| {
                        panic!("ruxen: cannot open root {}: {e}", canonical.display())
                    });
                // `into_raw_fd` suppresses the `File::drop`, so the fd
                // lives for process lifetime — paired with `PreparedHttp`
                // being leaked.
                f.into_raw_fd()
            };
            let path_mapping = match mapping {
                PathMapping::Root => PreparedPathMapping::Root,
                PathMapping::Alias => {
                    if let Some(prefix) = alias_prefix_override {
                        // Inherited from an ancestor prefix-alias location:
                        // strip the ancestor's pattern, even when this
                        // location is a regex (which has no pattern of
                        // its own to use as a prefix).
                        PreparedPathMapping::AliasPrefix { prefix }
                    } else if is_regex_location {
                        PreparedPathMapping::AliasRegex
                    } else {
                        PreparedPathMapping::AliasPrefix {
                            prefix: location_pattern,
                        }
                    }
                }
            };

            // Index inheritance: location list wins; else server list; else
            // the built-in default from ngx_http_index_module.c
            // (NGX_HTTP_DEFAULT_INDEX).
            let index: &'static [PreparedIndexEntry] = match location_index {
                Some(names) => prepare_index_entries(names),
                None => match server_index {
                    Some(v) => v,
                    None => prepare_index_entries(vec![IndexEntry {
                        parts: vec![ValuePart::Literal("index.html".into())],
                    }]),
                },
            };

            let try_files = location_try_files.map(|tf| prepare_try_files(tf, tokens));
            let autoindex = location_autoindex.unwrap_or(server_autoindex);
            let autoindex_exact_size =
                location_autoindex_exact_size.unwrap_or(server_autoindex_exact_size);
            let autoindex_localtime =
                location_autoindex_localtime.unwrap_or(server_autoindex_localtime);
            let autoindex_format = location_autoindex_format.unwrap_or(server_autoindex_format);

            PreparedHandler::Root(PreparedRoot {
                root,
                root_fd,
                path_mapping,
                index,
                autoindex,
                autoindex_exact_size,
                autoindex_localtime,
                autoindex_format,
                try_files,
            })
        }
    }
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

pub(crate) fn prepare_error_log_target(target: ErrorLogTarget) -> PreparedErrorLogTarget {
    match target {
        ErrorLogTarget::File(path) => {
            // Match access_log behavior: create eagerly so "no writes happened"
            // still leaves a readable file for assertions.
            let _ = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path);
            PreparedErrorLogTarget::File(Box::leak(path.into_boxed_path()))
        }
        ErrorLogTarget::Stderr => PreparedErrorLogTarget::Stderr,
        ErrorLogTarget::Syslog(s) => {
            let tag: &'static [u8] = match s.tag {
                Some(tag) => Box::leak(tag.into_bytes().into_boxed_slice()),
                None => b"ruxen",
            };
            let server = match s.server {
                ErrorLogSyslogServer::Unix(path) => {
                    PreparedErrorLogSyslogServer::Unix(Box::leak(path.into_boxed_path()))
                }
                ErrorLogSyslogServer::Udp(addr) => {
                    PreparedErrorLogSyslogServer::Udp(Box::leak(addr.into_boxed_str()))
                }
            };
            PreparedErrorLogTarget::Syslog(PreparedErrorLogSyslogTarget { server, tag })
        }
    }
}

pub(crate) fn prepare_error_logs(list: Vec<ErrorLog>) -> &'static [PreparedErrorLog] {
    let mut out: Vec<PreparedErrorLog> = Vec::with_capacity(list.len());
    for log in list {
        out.push(PreparedErrorLog {
            target: prepare_error_log_target(log.target),
            level: log.level,
        });
    }
    Box::leak(out.into_boxed_slice())
}

pub(crate) fn resolve_error_logs(
    location_error_logs: Option<Vec<ErrorLog>>,
    server_error_logs: &'static [PreparedErrorLog],
) -> &'static [PreparedErrorLog] {
    match location_error_logs {
        Some(list) => prepare_error_logs(list),
        None => server_error_logs,
    }
}

pub(crate) fn build_prefix_or_exact(
    l: Location,
    server_index: Option<&'static [PreparedIndexEntry]>,
    server_add_headers: &'static [PreparedAddHeader],
    server_add_trailers: &'static [PreparedAddHeader],
    server_error_pages: &'static [PreparedErrorPage],
    server_keepalive: PreparedKeepalive,
    server_error_logs: &'static [PreparedErrorLog],
    server_log_not_found: bool,
    server_tokens_value: crate::config::ServerTokens,
    server_autoindex: bool,
    server_autoindex_exact_size: bool,
    server_autoindex_localtime: bool,
    server_autoindex_format: AutoindexFormat,
    server_access_logs: &'static [PreparedAccessLog],
    server_auth_basic: PreparedAuthBasic,
    server_auth_basic_user_file: Option<&'static Path>,
    server_auth_delay_ms: u64,
    server_client_max_body_size: Option<u64>,
    server_post_action: Option<&'static [u8]>,
    server_expires: PreparedExpires,
    server_chunked_transfer_encoding: bool,
    server_proxy_defaults: ServerProxyDefaults,
    upstreams: &UpstreamMap,
    alp: &mut AccessLogPrep<'_>,
) -> PreparedLocation {
    let Location {
        mode: _,
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
        server_tokens: location_server_tokens,
        autoindex: location_autoindex,
        autoindex_exact_size: location_autoindex_exact_size,
        autoindex_localtime: location_autoindex_localtime,
        autoindex_format: location_autoindex_format,
        access_logs: location_access_logs,
        auth_basic: location_auth_basic,
        auth_basic_user_file: location_auth_basic_user_file,
        auth_delay_ms: location_auth_delay_ms,
        client_max_body_size: location_client_max_body_size,
        client_body_in_file_only: location_client_body_in_file_only,
        post_action: location_post_action,
        expires: location_expires,
        proxy_set_headers: location_proxy_set_headers,
        proxy_pass_request_headers: location_proxy_pass_request_headers,
        proxy_pass_request_body: location_proxy_pass_request_body,
        proxy_connect_timeout_ms: location_proxy_connect_timeout_ms,
        proxy_read_timeout_ms: location_proxy_read_timeout_ms,
        proxy_send_timeout_ms: location_proxy_send_timeout_ms,
        proxy_limit_rate: location_proxy_limit_rate,
        proxy_http_version: location_proxy_http_version,
        proxy_next_upstream: location_proxy_next_upstream,
        proxy_next_upstream_tries: location_proxy_next_upstream_tries,
        proxy_next_upstream_timeout_ms: location_proxy_next_upstream_timeout_ms,
        proxy_intercept_errors: location_proxy_intercept_errors,
        chunked_transfer_encoding: location_chunked_transfer_encoding,
        alias_prefix_override,
    } = l;
    let proxy_effective = resolve_proxy_effective(
        location_proxy_set_headers,
        location_proxy_pass_request_headers,
        location_proxy_pass_request_body,
        location_proxy_connect_timeout_ms,
        location_proxy_read_timeout_ms,
        location_proxy_send_timeout_ms,
        location_proxy_limit_rate,
        location_proxy_http_version,
        location_proxy_next_upstream,
        location_proxy_next_upstream_tries,
        location_proxy_next_upstream_timeout_ms,
        location_proxy_intercept_errors,
        server_proxy_defaults,
    );
    let pattern: &'static [u8] = Box::leak(pattern.into_bytes().into_boxed_slice());
    let alias_prefix_override: Option<&'static [u8]> = alias_prefix_override
        .map(|s| Box::leak(s.into_bytes().into_boxed_slice()) as &'static [u8]);
    let keepalive = resolve_keepalive(
        keepalive_timeout,
        keepalive_requests,
        keepalive_time_ms,
        keepalive_disable,
        server_keepalive,
    );
    let tokens = location_server_tokens.unwrap_or(server_tokens_value);
    let rewrite_program = prepare_rewrite_ops(rewrite_ops, tokens);
    let handler = build_handler(
        handler,
        pattern,
        false,
        alias_prefix_override,
        index,
        try_files,
        server_index,
        location_autoindex,
        location_autoindex_exact_size,
        location_autoindex_localtime,
        location_autoindex_format,
        server_autoindex,
        server_autoindex_exact_size,
        server_autoindex_localtime,
        server_autoindex_format,
        tokens,
        upstreams,
        proxy_effective,
    );
    let auto_redirect = matches!(&handler, PreparedHandler::Proxy(_)) && pattern.ends_with(b"/");
    let add_headers = resolve_add_headers(location_add_headers, server_add_headers);
    let add_trailers = resolve_add_headers(location_add_trailers, server_add_trailers);
    let error_pages = resolve_error_pages(location_error_pages, server_error_pages);
    let error_logs = resolve_error_logs(location_error_logs, server_error_logs);
    let log_not_found = location_log_not_found.unwrap_or(server_log_not_found);
    let access_logs = match location_access_logs {
        Some(ref list) => alp.prepare_list(list),
        None => server_access_logs,
    };
    let auth_basic = location_auth_basic
        .map(prepare_auth_basic)
        .unwrap_or(server_auth_basic);
    let auth_basic_user_file = location_auth_basic_user_file
        .map(leak_path_buf)
        .or(server_auth_basic_user_file);
    let auth_delay_ms = location_auth_delay_ms.unwrap_or(server_auth_delay_ms);
    let client_max_body_size = location_client_max_body_size.or(server_client_max_body_size);
    let post_action = location_post_action
        .map(|target| leak_bytes(target.as_bytes()))
        .or(server_post_action);
    let expires = location_expires
        .map(prepare_expires)
        .unwrap_or(server_expires);
    let chunked_transfer_encoding =
        location_chunked_transfer_encoding.unwrap_or(server_chunked_transfer_encoding);
    PreparedLocation {
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
        server_header: http::server_header_value(tokens),
        access_logs,
        auth_basic,
        auth_basic_user_file,
        auth_delay_ms,
        client_max_body_size,
        client_body_in_file_only: location_client_body_in_file_only
            .unwrap_or(crate::config::ClientBodyInFileOnly::Off),
        post_action,
        expires,
        chunked_transfer_encoding,
    }
}

pub(crate) fn build_regex_location(
    l: Location,
    case_insensitive: bool,
    server_index: Option<&'static [PreparedIndexEntry]>,
    server_add_headers: &'static [PreparedAddHeader],
    server_add_trailers: &'static [PreparedAddHeader],
    server_error_pages: &'static [PreparedErrorPage],
    server_keepalive: PreparedKeepalive,
    server_error_logs: &'static [PreparedErrorLog],
    server_log_not_found: bool,
    server_tokens_value: crate::config::ServerTokens,
    server_autoindex: bool,
    server_autoindex_exact_size: bool,
    server_autoindex_localtime: bool,
    server_autoindex_format: AutoindexFormat,
    server_access_logs: &'static [PreparedAccessLog],
    server_auth_basic: PreparedAuthBasic,
    server_auth_basic_user_file: Option<&'static Path>,
    server_auth_delay_ms: u64,
    server_client_max_body_size: Option<u64>,
    server_post_action: Option<&'static [u8]>,
    server_expires: PreparedExpires,
    server_chunked_transfer_encoding: bool,
    server_proxy_defaults: ServerProxyDefaults,
    upstreams: &UpstreamMap,
    alp: &mut AccessLogPrep<'_>,
) -> PreparedRegexLocation {
    let Location {
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
        server_tokens: location_server_tokens,
        autoindex: location_autoindex,
        autoindex_exact_size: location_autoindex_exact_size,
        autoindex_localtime: location_autoindex_localtime,
        autoindex_format: location_autoindex_format,
        access_logs: location_access_logs,
        auth_basic: location_auth_basic,
        auth_basic_user_file: location_auth_basic_user_file,
        auth_delay_ms: location_auth_delay_ms,
        client_max_body_size: location_client_max_body_size,
        client_body_in_file_only: location_client_body_in_file_only,
        post_action: location_post_action,
        expires: location_expires,
        proxy_set_headers: location_proxy_set_headers,
        proxy_pass_request_headers: location_proxy_pass_request_headers,
        proxy_pass_request_body: location_proxy_pass_request_body,
        proxy_connect_timeout_ms: location_proxy_connect_timeout_ms,
        proxy_read_timeout_ms: location_proxy_read_timeout_ms,
        proxy_send_timeout_ms: location_proxy_send_timeout_ms,
        proxy_limit_rate: location_proxy_limit_rate,
        proxy_http_version: location_proxy_http_version,
        proxy_next_upstream: location_proxy_next_upstream,
        proxy_next_upstream_tries: location_proxy_next_upstream_tries,
        proxy_next_upstream_timeout_ms: location_proxy_next_upstream_timeout_ms,
        proxy_intercept_errors: location_proxy_intercept_errors,
        chunked_transfer_encoding: location_chunked_transfer_encoding,
        alias_prefix_override,
    } = l;
    let proxy_effective = resolve_proxy_effective(
        location_proxy_set_headers,
        location_proxy_pass_request_headers,
        location_proxy_pass_request_body,
        location_proxy_connect_timeout_ms,
        location_proxy_read_timeout_ms,
        location_proxy_send_timeout_ms,
        location_proxy_limit_rate,
        location_proxy_http_version,
        location_proxy_next_upstream,
        location_proxy_next_upstream_tries,
        location_proxy_next_upstream_timeout_ms,
        location_proxy_intercept_errors,
        server_proxy_defaults,
    );
    // The parser already validated this with the same flags + the same
    // `regex::bytes` builder; rebuild here because the compiled `Regex`
    // doesn't survive the AST.
    let regex = regex::bytes::RegexBuilder::new(&pattern)
        .case_insensitive(case_insensitive)
        .build()
        .unwrap_or_else(|e| {
            panic!(
                "ruxen: regex {:?} failed to compile after passing parse validation: {e}",
                pattern
            )
        });
    let location_pattern: &'static [u8] = b"";
    let alias_prefix_override: Option<&'static [u8]> = alias_prefix_override
        .map(|s| Box::leak(s.into_bytes().into_boxed_slice()) as &'static [u8]);
    let keepalive = resolve_keepalive(
        keepalive_timeout,
        keepalive_requests,
        keepalive_time_ms,
        keepalive_disable,
        server_keepalive,
    );
    let tokens = location_server_tokens.unwrap_or(server_tokens_value);
    let rewrite_program = prepare_rewrite_ops(rewrite_ops, tokens);
    let handler = build_handler(
        handler,
        location_pattern,
        true,
        alias_prefix_override,
        index,
        try_files,
        server_index,
        location_autoindex,
        location_autoindex_exact_size,
        location_autoindex_localtime,
        location_autoindex_format,
        server_autoindex,
        server_autoindex_exact_size,
        server_autoindex_localtime,
        server_autoindex_format,
        tokens,
        upstreams,
        proxy_effective,
    );
    let add_headers = resolve_add_headers(location_add_headers, server_add_headers);
    let add_trailers = resolve_add_headers(location_add_trailers, server_add_trailers);
    let error_pages = resolve_error_pages(location_error_pages, server_error_pages);
    let error_logs = resolve_error_logs(location_error_logs, server_error_logs);
    let log_not_found = location_log_not_found.unwrap_or(server_log_not_found);
    let access_logs = match location_access_logs {
        Some(ref list) => alp.prepare_list(list),
        None => server_access_logs,
    };
    let auth_basic = location_auth_basic
        .map(prepare_auth_basic)
        .unwrap_or(server_auth_basic);
    let auth_basic_user_file = location_auth_basic_user_file
        .map(leak_path_buf)
        .or(server_auth_basic_user_file);
    let auth_delay_ms = location_auth_delay_ms.unwrap_or(server_auth_delay_ms);
    let client_max_body_size = location_client_max_body_size.or(server_client_max_body_size);
    let post_action = location_post_action
        .map(|target| leak_bytes(target.as_bytes()))
        .or(server_post_action);
    let expires = location_expires
        .map(prepare_expires)
        .unwrap_or(server_expires);
    let chunked_transfer_encoding =
        location_chunked_transfer_encoding.unwrap_or(server_chunked_transfer_encoding);
    PreparedRegexLocation {
        regex,
        handler,
        rewrite_program,
        add_headers,
        add_trailers,
        error_pages,
        keepalive,
        error_logs,
        log_not_found,
        server_header: http::server_header_value(tokens),
        access_logs,
        auth_basic,
        auth_basic_user_file,
        auth_delay_ms,
        client_max_body_size,
        client_body_in_file_only: location_client_body_in_file_only
            .unwrap_or(crate::config::ClientBodyInFileOnly::Off),
        post_action,
        expires,
        chunked_transfer_encoding,
    }
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
        })
        .collect();
    let server_bytes = http::server_header_value(tokens);
    let fallback = match tf.fallback {
        TryFilesFallback::Status(code) => {
            PreparedFallback::Status(Prebuilt::leak(code, fallback_body(code), server_bytes))
        }
        TryFilesFallback::Uri(u) => PreparedFallback::Uri(leak_bytes(u.as_bytes())),
        TryFilesFallback::Named(u) => PreparedFallback::Named(leak_bytes(u.as_bytes())),
    };
    Box::leak(Box::new(PreparedTryFiles { probes, fallback }))
}
