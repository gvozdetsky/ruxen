//! Configuration AST: types produced by the parser, consumed by the
//! preparation pass in `worker::prepare`. Pure data — no behavior beyond
//! a handful of small helpers on `Listen`, `ServerNameSpec`, and
//! `ProxyNextUpstream`.

use std::net::SocketAddr;
use std::path::PathBuf;

/// `client_header_timeout`, `client_body_timeout` and `send_timeout`
/// (milliseconds); `None` means nginx's default, 60 s.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ClientTimeouts {
    pub header_ms: Option<u64>,
    pub body_ms: Option<u64>,
    pub send_ms: Option<u64>,
}

impl ClientTimeouts {
    /// Parse one of the three directives into `self`; `false` when `name`
    /// is none of them.
    pub(crate) fn parse(
        &mut self,
        name: &str,
        args: &[String],
    ) -> Result<bool, super::error::Error> {
        use super::error::Error;
        let (slot, what) = match name {
            "client_header_timeout" => (&mut self.header_ms, "client_header_timeout"),
            "client_body_timeout" => (&mut self.body_ms, "client_body_timeout"),
            "send_timeout" => (&mut self.send_ms, "send_timeout"),
            _ => return Ok(false),
        };
        if slot.is_some() {
            return Err(Error::Duplicate(what));
        }
        let raw = args.get(1).ok_or(Error::MissingArg(what))?;
        *slot = Some(super::parse_server::parse_duration_ms(raw, what)?);
        Ok(true)
    }

    /// Server values win; unset ones come from http scope.
    pub(crate) fn inherit(self, parent: ClientTimeouts) -> ClientTimeouts {
        ClientTimeouts {
            header_ms: self.header_ms.or(parent.header_ms),
            body_ms: self.body_ms.or(parent.body_ms),
            send_ms: self.send_ms.or(parent.send_ms),
        }
    }
}

#[derive(Debug, Default)]
pub struct RuntimeOpts {
    pub pid: Option<PathBuf>,
    /// `worker_processes <N|auto>;`. `None` means "not set" (default 1,
    /// matching nginx). `Some(0)` represents `auto` — resolved at runtime
    /// via `available_parallelism()`.
    pub worker_processes: Option<WorkerProcesses>,
    /// `events { worker_connections N; }`. `None` means nginx's default,
    /// 512.
    pub worker_connections: Option<usize>,
    /// Top-level `error_log` lines: worker-level messages, and the
    /// fallback for servers and http without their own.
    pub error_logs: Vec<ErrorLog>,
    /// `user name [group];` — the user name only. ruxen doesn't switch
    /// users; `main` uses this to decide whether running as root is
    /// what the config asked for.
    pub user: Option<String>,
    /// `worker_rlimit_nofile N;`: the open-files limit set before the
    /// workers start.
    pub worker_rlimit_nofile: Option<u64>,
    /// `worker_rlimit_core size;`: the core-file size limit.
    pub worker_rlimit_core: Option<u64>,
    /// `worker_shutdown_timeout time;`: how long a graceful shutdown
    /// waits for in-flight connections, in ms. `None` (and nginx's `0`)
    /// waits without limit.
    pub worker_shutdown_timeout_ms: Option<u64>,
}

#[derive(Debug, Copy, Clone)]
pub enum WorkerProcesses {
    Auto,
    Count(usize),
}

#[derive(Debug)]
pub struct HttpConfig {
    pub runtime: RuntimeOpts,
    /// http-scope `error_log` lines; `None` inherits the top-level ones.
    pub error_logs: Option<Vec<ErrorLog>>,
    /// `log_format name <format...>;` definitions declared at http scope.
    pub log_formats: Vec<LogFormatDef>,
    /// `access_log` directives declared at http scope.
    pub access_logs: Vec<AccessLog>,
    /// http-scope `server_tokens`. `None` means "not set" — server/location
    /// blocks then default to `On`. Setting it here changes the inherited
    /// baseline for all child scopes.
    pub server_tokens: Option<ServerTokens>,
    /// http-scope `autoindex on|off;`. `None` means "not set"; server and
    /// location blocks then inherit and ultimately default to `off`.
    pub autoindex: Option<bool>,
    /// http-scope `autoindex_exact_size on|off;`. `None` means "not set";
    /// inheritance chain defaults to `on`.
    pub autoindex_exact_size: Option<bool>,
    /// http-scope `autoindex_localtime on|off;`. `None` means "not set";
    /// inheritance chain defaults to `off` (UTC timestamps).
    pub autoindex_localtime: Option<bool>,
    /// http-scope `autoindex_format ...;`. `None` means "not set";
    /// inheritance chain defaults to `html`.
    pub autoindex_format: Option<AutoindexFormat>,
    /// http-scope `split_clients` programs keyed by output variable name
    /// (without the leading `$`).
    pub split_clients: Vec<SplitClients>,
    /// http-scope `map $source $dest { ... }` programs in declaration order.
    /// Prepared side keys them by output variable name.
    pub maps: Vec<MapBlock>,
    /// http-scope `auth_basic` realm (or explicit `off`).
    pub auth_basic: Option<AuthBasic>,
    /// http-scope `auth_basic_user_file`.
    pub auth_basic_user_file: Option<PathBuf>,
    /// http-scope `auth_delay` in milliseconds. `None` means "not set"
    /// and child scopes inherit/default to no delay.
    pub auth_delay_ms: Option<u64>,
    /// http-scope `client_max_body_size` in bytes. `None` means "not set".
    pub client_max_body_size: Option<u64>,
    /// http-scope `client_body_temp_path` (the levels are accepted and not
    /// used). `None`: a private directory per process.
    pub client_body_temp_path: Option<PathBuf>,
    /// http-scope `sendfile on|off`. `None` means "not set" (nginx: off).
    pub sendfile: Option<bool>,
    /// `limit_rate` / `limit_rate_after` (sizes, variables allowed).
    /// `None` inherits.
    pub limit_rate: Option<Vec<ValuePart>>,
    pub limit_rate_after: Option<Vec<ValuePart>>,
    /// http-scope `post_action URI|@name;`. `None` means "not set";
    /// server/location scopes inherit it.
    pub post_action: Option<String>,
    /// http-scope `expires` directive. `None` means "not set"; child scopes
    /// inherit and ultimately treat absent as `Off` (no Expires/Cache-Control
    /// emitted).
    pub expires: Option<ExpiresDirective>,
    /// http-scope `ignore_invalid_headers on|off;`. `None` means "not set"
    /// and server scopes inherit/default to `on`.
    pub ignore_invalid_headers: Option<bool>,
    /// http-scope `underscores_in_headers on|off;`. `None` means "not set"
    /// and server scopes inherit/default to `off`.
    pub underscores_in_headers: Option<bool>,
    /// http-scope `upstream NAME { ... }` blocks. Referenced by name from
    /// `proxy_pass http://NAME;`. Names must be unique; duplicate
    /// declarations are rejected at parse time.
    pub upstreams: Vec<UpstreamBlock>,
    pub servers: Vec<Server>,
    /// Non-fatal diagnostics surfaced during parsing (e.g. an `ssl_certificate`
    /// in a server with no `listen … ssl;`). Printed by `main.rs` on `-t`;
    /// they do not fail validation. Order is declaration order.
    pub warnings: Vec<String>,
    /// Files visited during parsing (main config + each `include` target),
    /// each captured at most once and in first-encounter order. Drives the
    /// `nginx -T` dump emitted by `main.rs`. The first entry is the main
    /// config file (or absent for inline test parses).
    pub dump_files: Vec<DumpFile>,
    /// Directory of the main config file (nginx's conf prefix). Relative
    /// paths that nginx resolves against the config directory rather than
    /// the `-p` prefix use this. `None` for inline test parses.
    pub conf_prefix: Option<PathBuf>,
}

/// One entry in the `nginx -T` config dump: an absolute path plus the raw
/// bytes that were read for it, in original on-disk form.
#[derive(Debug, Clone)]
pub struct DumpFile {
    pub path: PathBuf,
    pub contents: String,
}

/// One `upstream NAME { server <host:port> [params]; ... }` block at http
/// scope. M42 also parses the upstream-side keepalive directives —
/// `keepalive N;`, `keepalive_requests N;`, `keepalive_timeout T;`,
/// `keepalive_time T;`. These configure the per-worker connection pool;
/// when `keepalive` is unset (`None`) no pool is used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamBlock {
    pub name: String,
    pub servers: Vec<UpstreamServer>,
    /// `keepalive N;` — max idle pool slots (per worker). `None` means
    /// no keepalive pool: each upstream attempt opens a fresh socket.
    pub keepalive_max_idle: Option<u32>,
    /// `keepalive_requests N;` — close a pooled conn after N requests.
    /// `None` defaults to nginx's 1000.
    pub keepalive_requests: Option<u64>,
    /// `keepalive_timeout T;` — drop idle conns older than this.
    /// `None` defaults to nginx's 60s.
    pub keepalive_idle_timeout_ms: Option<u64>,
    /// `keepalive_time T;` — hard lifetime cap from first use.
    /// `None` defaults to nginx's 1h.
    pub keepalive_max_lifetime_ms: Option<u64>,
    /// LB algorithm. Default is smoothed weighted RR; `least_conn;` is supported.
    pub lb: LbAlgorithm,
}

/// Load-balancing algorithm for an `upstream {}` block. Smoothed weighted
/// round-robin matches `ngx_http_upstream_round_robin.c`; least-connection
/// matches `ngx_http_upstream_least_conn.c`.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum LbAlgorithm {
    RoundRobin,
    LeastConn,
}

/// One `server <host:port> [weight=N] [max_fails=N] [fail_timeout=Ts]
/// [down] [backup];` entry inside an `upstream {}` block. The host+port
/// is resolved at parse time via `to_socket_addrs` — we don't carry a
/// runtime resolver. Hostname-only resolution picks the first address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamServer {
    /// Resolved peer address. nginx allows multiple addresses per host
    /// (one server entry expands to multiple peers); we pick the first
    /// resolution and document this as a v0.1 narrowing.
    pub addr: SocketAddr,
    /// Original `host:port` string as written. Used for the upstream
    /// `Host:` header default and for diagnostics.
    pub display: String,
    pub weight: u32,
    pub max_fails: u32,
    pub fail_timeout_secs: u32,
    pub down: bool,
    pub backup: bool,
}

/// One `listen` directive, address plus the flag bag. The current set of
/// flags is what nginx accepts on a stream socket — most are parsed-but-ignored
/// at runtime today (TLS-on-this-listen is consumed by the TLS work; the
/// rest are silently accepted so upstream `nginx-tests` configs load). Order
/// against `default_server` / `reuseport` etc. is not significant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listen {
    pub addr: SocketAddr,
    /// `listen … ssl;` — terminate TLS on this socket.
    pub ssl: bool,
    /// `default_server` — server block becomes the catch-all for its addr.
    /// Parsed-but-not-honored at routing time yet; first declaration wins
    /// today (nginx default behavior is the same when no flag is set).
    pub default_server: bool,
    /// `reuseport` — set `SO_REUSEPORT` per-listener. Already implicit in the
    /// thread-per-core design; presence is a parse-time noop.
    pub reuseport: bool,
    /// `http2` — accepted, ignored. v0.1 advertises HTTP/1.1 only.
    pub http2: bool,
    /// `http3` — accepted, ignored.
    pub http3: bool,
    /// `quic` — accepted, ignored.
    pub quic: bool,
    /// `proxy_protocol` — connections start with a PROXY protocol header.
    pub proxy_protocol: bool,
    /// `deferred` — Linux `TCP_DEFER_ACCEPT`; accepted, ignored.
    pub deferred: bool,
    /// `fastopen=N` — TCP fast-open queue length; accepted, ignored.
    pub fastopen: Option<u32>,
    /// `backlog=N` — listen backlog; accepted, ignored.
    pub backlog: Option<u32>,
    /// `rcvbuf=N` — `SO_RCVBUF`; accepted, ignored.
    pub rcvbuf: Option<u64>,
    /// `sndbuf=N` — `SO_SNDBUF`; accepted, ignored.
    pub sndbuf: Option<u64>,
}

impl Listen {
    pub(crate) fn from_addr(addr: SocketAddr) -> Self {
        Self {
            addr,
            ssl: false,
            default_server: false,
            reuseport: false,
            http2: false,
            http3: false,
            quic: false,
            proxy_protocol: false,
            deferred: false,
            fastopen: None,
            backlog: None,
            rcvbuf: None,
            sndbuf: None,
        }
    }
}

/// Set of TLS protocol versions accepted on `listen … ssl;` sockets.
/// Insecure versions (`SSLv2`, `SSLv3`, `TLSv1`, `TLSv1.1`) are rejected
/// at parse time rather than carried as bits — there is no runtime path
/// that could enable them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlsVersionSet {
    pub tlsv1_2: bool,
    pub tlsv1_3: bool,
}

impl Default for TlsVersionSet {
    /// nginx's default is `TLSv1 TLSv1.1 TLSv1.2 TLSv1.3` but the first two
    /// are insecure and rustls 0.23 won't speak them anyway; ruxen's
    /// effective default is `TLSv1.2 TLSv1.3`.
    fn default() -> Self {
        Self {
            tlsv1_2: true,
            tlsv1_3: true,
        }
    }
}

/// Server-scope SSL configuration. Empty `certs`/`keys` means "no SSL
/// directives in this block" — validated against `listen.ssl` after the
/// block parses. `certs[i]` pairs with `keys[i]` (nginx behavior: one
/// RSA + one ECDSA cert most commonly). Paths are taken verbatim and
/// resolved relative to `-p` at load time.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServerSsl {
    pub certs: Vec<PathBuf>,
    pub keys: Vec<PathBuf>,
    pub protocols: TlsVersionSet,
    /// `ssl_ciphers` — verbatim, not applied: rustls's default suites are
    /// used and the parser warns (`warn_ignored_tls_policy`).
    pub ciphers: Option<String>,
    /// `ssl_prefer_server_ciphers on|off;`. rustls always uses server
    /// preference for TLS 1.2, so explicit `off` is treated as a parse
    /// warning (see `HttpConfig.warnings`) but kept here for diagnostics.
    pub prefer_server_ciphers: Option<bool>,
    /// Parsed `ssl_session_timeout` for this server/listen context.
    /// `None` means directive absent. The prepared TLS config wraps
    /// rustls's session cache and ticketer with this timeout.
    pub session_timeout_ms: Option<u64>,
    /// `ssl_session_cache` / `ssl_session_tickets`, merged with http scope.
    pub resumption: SessionResumption,
}

/// How TLS sessions can be resumed. `None` fields take nginx's defaults:
/// no session-ID cache (`ssl_session_cache none`), tickets on.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SessionResumption {
    /// `ssl_session_cache`: `builtin` / `shared:…` = true, `off` / `none` =
    /// false.
    pub cache: Option<bool>,
    /// `ssl_session_tickets on|off`.
    pub tickets: Option<bool>,
}

impl SessionResumption {
    /// Parse `ssl_session_cache` or `ssl_session_tickets` into `self`;
    /// `false` when `name` is neither.
    pub(crate) fn parse(
        &mut self,
        name: &str,
        args: &[String],
    ) -> Result<bool, super::error::Error> {
        use super::error::Error;
        match name {
            "ssl_session_cache" => {
                if self.cache.is_some() {
                    return Err(Error::Duplicate("ssl_session_cache"));
                }
                // off | none | [builtin[:size]] [shared:name:size]
                let enabled = match &args[1..] {
                    [] => return Err(Error::MissingArg("ssl_session_cache")),
                    [one] if one == "off" || one == "none" => false,
                    caches => {
                        for c in caches {
                            if !(c == "builtin"
                                || c.starts_with("builtin:")
                                || c.starts_with("shared:"))
                            {
                                return Err(Error::BadValue {
                                    what: "ssl_session_cache",
                                    got: c.clone(),
                                });
                            }
                        }
                        true
                    }
                };
                self.cache = Some(enabled);
                Ok(true)
            }
            "ssl_session_tickets" => {
                if self.tickets.is_some() {
                    return Err(Error::Duplicate("ssl_session_tickets"));
                }
                self.tickets = Some(super::parse_location::parse_on_off_args(
                    &args[1..],
                    "ssl_session_tickets",
                )?);
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    pub(crate) fn inherit(self, parent: SessionResumption) -> SessionResumption {
        SessionResumption {
            cache: self.cache.or(parent.cache),
            tickets: self.tickets.or(parent.tickets),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Server {
    pub listen: Listen,
    /// Names the `Host` header can match to route to this server block.
    /// Each entry is one classified `server_name` argument
    /// (exact / wildcard / regex / empty). Empty vec means "no explicit
    /// names" — the server is reachable only as the default for its
    /// listen address.
    pub server_names: Vec<ServerNameSpec>,
    /// Server-scope `index` directive. `None` means "not set at server
    /// scope" — nginx's built-in default (`index.html`) is applied at
    /// prepare time. A location without its own `index` inherits from here.
    pub index: Option<Vec<IndexEntry>>,
    /// Server-scope `root`. Locations without their own `root` inherit this;
    /// if the server also omits it, the http-scope root can still supply it.
    pub root: Option<PathBuf>,
    /// Server-scope `add_header` stack. `None` = "not set at this scope"
    /// (locations inherit from their parent chain). `Some(empty)` never
    /// happens — the parser always emits a non-empty vec on the first
    /// `add_header` seen.
    pub add_headers: Option<Vec<AddHeader>>,
    /// Server-scope `add_trailer` stack. Same shape and merge rules as
    /// `add_headers`. Trailers force chunked transfer-encoding on the
    /// response when the list is non-empty.
    pub add_trailers: Option<Vec<AddHeader>>,
    /// Server-scope `error_page` stack. Multiple directives accumulate in
    /// declaration order; a location with its own list replaces the
    /// inherited server list entirely, mirroring nginx's merge behavior.
    pub error_pages: Option<Vec<ErrorPage>>,
    /// Server-scope rewrite-module directives (`rewrite`, `set`, `if`,
    /// `return`, `break`) in order: nginx's SERVER_REWRITE phase, run
    /// before the location is searched.
    pub rewrite_ops: Vec<RewriteOp>,
    /// Server-scope keepalive behavior. `None` keeps the runtime default:
    /// keepalive allowed, no `Keep-Alive` header hint.
    pub keepalive_timeout: Option<KeepaliveTimeout>,
    /// Server-scope `keepalive_requests` cap. `None` means "use the
    /// runtime default" (currently nginx's default of 1000 requests per
    /// connection).
    pub keepalive_requests: Option<u64>,
    /// Server-scope maximum keepalive connection lifetime.
    pub keepalive_time_ms: Option<u64>,
    /// Server-scope `keepalive_disable` policy.
    pub keepalive_disable: Option<KeepaliveDisable>,
    /// `client_header_timeout` / `client_body_timeout` / `send_timeout`,
    /// merged with the http-scope values.
    pub client_timeouts: ClientTimeouts,
    /// The block has its own ssl_* lines (for the "TLS settings ignored"
    /// warning when no server on its address listens with `ssl`).
    pub ssl_directives: bool,
    /// `merge_slashes off` disables the `//` → `/` collapse in URI
    /// normalization. Default (`true`) matches nginx's default `on`.
    pub merge_slashes: bool,
    /// Server-scope `ignore_invalid_headers on|off;`. `None` inherits from
    /// http scope (default `on`).
    pub ignore_invalid_headers: Option<bool>,
    /// Server-scope `underscores_in_headers on|off;`. `None` inherits from
    /// http scope (default `off`).
    pub underscores_in_headers: Option<bool>,
    /// Server-scope `error_log` sinks. `None` means "inherit default
    /// sink behavior" (no explicit server-local sink configured). When set,
    /// directives accumulate in declaration order.
    pub error_logs: Option<Vec<ErrorLog>>,
    /// Server-scope `log_not_found` policy. `None` means default (`on`).
    pub log_not_found: Option<bool>,
    /// Server-scope `recursive_error_pages`. `None` means default (`off`).
    pub recursive_error_pages: Option<bool>,
    /// Server-scope `server_tokens`. `None` inherits from http scope (which
    /// itself defaults to `On`).
    pub server_tokens: Option<ServerTokens>,
    /// Server-scope `autoindex on|off;`. `None` inherits from http.
    pub autoindex: Option<bool>,
    /// Server-scope `autoindex_exact_size on|off;`. `None` inherits from http.
    pub autoindex_exact_size: Option<bool>,
    /// Server-scope `autoindex_localtime on|off;`. `None` inherits from http.
    pub autoindex_localtime: Option<bool>,
    /// Server-scope `autoindex_format ...;`. `None` inherits from http.
    pub autoindex_format: Option<AutoindexFormat>,
    /// Server-scope `access_log` directives. `None` inherits the http-scope
    /// list. `Some(empty)` means `access_log off;` was used to disable
    /// logging at this scope (parser collapses `off` to an empty vec).
    pub access_logs: Option<Vec<AccessLog>>,
    /// Server-scope `auth_basic` realm or explicit `off`.
    pub auth_basic: Option<AuthBasic>,
    /// Server-scope `auth_basic_user_file`. `None` inherits from http scope.
    pub auth_basic_user_file: Option<PathBuf>,
    /// Server-scope `auth_delay` in milliseconds. `None` inherits from http.
    pub auth_delay_ms: Option<u64>,
    /// Server-scope `client_max_body_size` in bytes. `None` inherits from http.
    pub client_max_body_size: Option<u64>,
    /// Server-scope `sendfile on|off`. `None` inherits from http.
    pub sendfile: Option<bool>,
    /// `limit_rate` / `limit_rate_after` (sizes, variables allowed).
    /// `None` inherits.
    pub limit_rate: Option<Vec<ValuePart>>,
    pub limit_rate_after: Option<Vec<ValuePart>>,
    /// Server-scope `post_action URI|@name;`. `None` inherits from http.
    pub post_action: Option<String>,
    /// Server-scope `expires` directive. `None` inherits from http.
    pub expires: Option<ExpiresDirective>,
    /// Server-scope `proxy_set_header` stack. `None` inherits from http
    /// scope; `Some(list)` replaces the parent list outright (matches
    /// nginx's `ngx_http_proxy_module.c::ngx_http_proxy_merge_loc_conf`).
    pub proxy_set_headers: Option<Vec<ProxySetHeader>>,
    /// Server-scope `proxy_pass_request_headers on|off;`. `None` inherits.
    pub proxy_pass_request_headers: Option<bool>,
    /// Server-scope `proxy_pass_request_body on|off;`. `None` inherits.
    pub proxy_pass_request_body: Option<bool>,
    /// Server-scope `proxy_set_body VALUE;`. `None` inherits.
    pub proxy_set_body: Option<Vec<ValuePart>>,
    /// Server-scope `proxy_ignore_headers`, lowercased. `None` inherits.
    pub proxy_ignore_headers: Option<Vec<String>>,
    /// Server-scope `proxy_connect_timeout` in milliseconds.
    pub proxy_connect_timeout_ms: Option<u64>,
    /// Server-scope `proxy_read_timeout` in milliseconds.
    pub proxy_read_timeout_ms: Option<u64>,
    /// Server-scope `proxy_send_timeout` in milliseconds.
    pub proxy_send_timeout_ms: Option<u64>,
    /// Server-scope `proxy_limit_rate` in bytes/sec. `0` (and `None` defaulting
    /// to it) means unlimited.
    pub proxy_limit_rate: Option<u64>,
    /// Server-scope `proxy_http_version 1.0|1.1;`. `None` inherits.
    /// Stored as the minor digit (`0` or `1`).
    pub proxy_http_version: Option<u8>,
    /// Server-scope `proxy_next_upstream` bitmask. `None` inherits the
    /// nginx default (`error timeout`).
    pub proxy_next_upstream: Option<ProxyNextUpstream>,
    /// Server-scope `proxy_next_upstream_tries N;`. `0` means "no cap"
    /// in nginx; we mirror that. `None` inherits.
    pub proxy_next_upstream_tries: Option<u32>,
    /// Server-scope `proxy_next_upstream_timeout T;`. `0` means no cap.
    pub proxy_next_upstream_timeout_ms: Option<u64>,
    /// Server-scope `proxy_intercept_errors on|off;`. `None` inherits.
    pub proxy_intercept_errors: Option<bool>,
    /// Server-scope `proxy_redirect` directives. `None` inherits (nginx's
    /// implicit `default`).
    pub proxy_redirect: Option<ProxyRedirect>,
    /// Server-scope `proxy_hide_header` / `proxy_pass_header` names.
    /// `None` inherits.
    pub proxy_hide_headers: Option<Vec<String>>,
    pub proxy_pass_headers: Option<Vec<String>>,
    /// Server-scope `chunked_transfer_encoding on|off;`. `None` inherits the
    /// nginx default (`on`). When `false`, response bodies stay framed by
    /// `Content-Length` and `add_trailer` directives are silently dropped
    /// because there is no chunked body to append trailers to.
    pub chunked_transfer_encoding: Option<bool>,
    /// Server-scope SSL settings. `certs.is_empty()` means no SSL directives
    /// were declared; the parser validates the listen-flag/cert pairing and
    /// surfaces mismatches as either errors or warnings.
    pub ssl: ServerSsl,
    pub locations: Vec<Location>,
}

/// How a `location` pattern matches the request URI. M9 added regex (`~`,
/// `~*`) and `^~` (prefix that, when winning, suppresses the regex pass —
/// `clcf->noregex` in nginx). M13 adds named internal locations (`@name`),
/// which are prepared separately and never participate in external URI
/// matching.
///
/// `^~` doesn't get its own enum variant because the matching algorithm
/// still treats it as a prefix; the "skip regex" bit lives on `Location`
/// instead, which keeps the ladder in `match_location` linear.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum MatchMode {
    Exact,
    Prefix,
    Named,
    /// `~` or `~*`. The flag carries the case-insensitive bit (`~*`).
    Regex {
        case_insensitive: bool,
    },
}

#[derive(Debug, Clone)]
pub struct Location {
    pub mode: MatchMode,
    pub pattern: String,
    /// `^~` flag — only meaningful when `mode == Prefix`. When this prefix
    /// is the longest match for a request, the regex pass is skipped.
    /// Maps to `clcf->noregex` (ngx_http_core_module.h).
    pub noregex: bool,
    /// Rewrite-phase program attached to this location (`set`, `if`,
    /// `rewrite`, and `break`).
    pub rewrite_ops: Vec<RewriteOp>,
    pub handler: Handler,
    /// Location-scope `index`. `None` means "inherit from server, else
    /// built-in default". A location that sets `index` replaces the
    /// server-level list entirely (nginx: ngx_http_index_merge_loc_conf —
    /// child list, if non-null, wins outright; no concatenation).
    pub index: Option<Vec<IndexEntry>>,
    /// Location-scope `try_files`. Not inherited. A location without it
    /// goes straight to the static/index resolver for its `root`.
    pub try_files: Option<TryFiles>,
    /// Location-scope `add_header` stack. Inheritance: child list (if
    /// `Some`) replaces parent's entirely — nginx's
    /// `ngx_http_headers_filter_module.c::ngx_http_headers_merge_conf`
    /// semantics. `None` here means "inherit from server".
    pub add_headers: Option<Vec<AddHeader>>,
    /// Location-scope `add_trailer` stack. Same shape and merge rules as
    /// `add_headers`.
    pub add_trailers: Option<Vec<AddHeader>>,
    /// Location-scope `error_page` stack. Inheritance mirrors nginx core:
    /// if the child has any entries it replaces the parent's list outright;
    /// otherwise it inherits the server-level list.
    pub error_pages: Option<Vec<ErrorPage>>,
    /// Location-scope keepalive behavior. `None` inherits from server.
    pub keepalive_timeout: Option<KeepaliveTimeout>,
    /// Location-scope keepalive request cap. `None` inherits from server.
    pub keepalive_requests: Option<u64>,
    /// Location-scope keepalive lifetime cap. `None` inherits from server.
    pub keepalive_time_ms: Option<u64>,
    /// Location-scope keepalive-disable policy. `None` inherits from server.
    pub keepalive_disable: Option<KeepaliveDisable>,
    /// Location-scope `error_log` sinks. `None` inherits from server.
    pub error_logs: Option<Vec<ErrorLog>>,
    /// Location-scope `log_not_found` policy. `None` inherits from server.
    pub log_not_found: Option<bool>,
    /// Location-scope `recursive_error_pages`. `None` inherits from server.
    pub recursive_error_pages: Option<bool>,
    /// `internal;`: only internal redirects (rewrite, error_page,
    /// try_files, index, X-Accel-Redirect) may land here.
    pub internal: bool,
    /// Location-scope `server_tokens`. `None` inherits from server.
    pub server_tokens: Option<ServerTokens>,
    /// Location-scope `autoindex on|off;`. `None` inherits from server.
    pub autoindex: Option<bool>,
    /// Location-scope `autoindex_exact_size on|off;`. `None` inherits from
    /// server.
    pub autoindex_exact_size: Option<bool>,
    /// Location-scope `autoindex_localtime on|off;`. `None` inherits from
    /// server.
    pub autoindex_localtime: Option<bool>,
    /// Location-scope `autoindex_format ...;`. `None` inherits from server.
    pub autoindex_format: Option<AutoindexFormat>,
    /// Location-scope `access_log` directives. `None` inherits from server.
    /// `Some(empty)` is `access_log off;` — explicit suppression.
    pub access_logs: Option<Vec<AccessLog>>,
    /// Location-scope `auth_basic` realm or explicit `off`.
    pub auth_basic: Option<AuthBasic>,
    /// Location-scope `auth_basic_user_file`. `None` inherits from server.
    pub auth_basic_user_file: Option<PathBuf>,
    /// Location-scope `auth_delay` in milliseconds. `None` inherits from
    /// server.
    pub auth_delay_ms: Option<u64>,
    /// Location-scope `client_max_body_size` in bytes. `None` inherits from
    /// server.
    pub client_max_body_size: Option<u64>,
    /// Location-scope `sendfile on|off`, inherited through nested locations
    /// at parse time. `None` inherits from server/http at prepare time.
    pub sendfile: Option<bool>,
    /// `limit_rate` / `limit_rate_after` (sizes, variables allowed).
    /// `None` inherits.
    pub limit_rate: Option<Vec<ValuePart>>,
    pub limit_rate_after: Option<Vec<ValuePart>>,
    /// Location-scope `client_body_in_file_only on|clean|off;`. `None`
    /// inherits from server (default `off`). When `on`, the spilled
    /// request body file is kept after the request completes; `clean`
    /// also writes to file but unlinks at end of request. `off` (default)
    /// keeps current ruxen semantics where files are unlinked on drop.
    pub client_body_in_file_only: Option<ClientBodyInFileOnly>,
    /// Location-scope `post_action URI|@name;`. Inherited through the
    /// location chain at parse time for nested blocks, then from server/http
    /// at prepare time for top-level locations.
    pub post_action: Option<String>,
    /// Location-scope `expires` directive. Inherited through nested locations
    /// at parse time, then from server/http at prepare time. `None` after
    /// inheritance means "no expires header injection".
    pub expires: Option<ExpiresDirective>,
    /// Location-scope `proxy_set_header` stack. `None` inherits from server.
    pub proxy_set_headers: Option<Vec<ProxySetHeader>>,
    /// Location-scope `proxy_pass_request_headers`. `None` inherits.
    pub proxy_pass_request_headers: Option<bool>,
    /// Location-scope `proxy_pass_request_body`. `None` inherits.
    pub proxy_pass_request_body: Option<bool>,
    /// Location-scope `proxy_set_body`: the body sent upstream instead of
    /// the client's. `None` inherits.
    pub proxy_set_body: Option<Vec<ValuePart>>,
    /// Location-scope `proxy_ignore_headers`, lowercased. `None` inherits.
    pub proxy_ignore_headers: Option<Vec<String>>,
    /// Location-scope `proxy_connect_timeout`. `None` inherits.
    pub proxy_connect_timeout_ms: Option<u64>,
    /// Location-scope `proxy_read_timeout`. `None` inherits.
    pub proxy_read_timeout_ms: Option<u64>,
    /// Location-scope `proxy_send_timeout`. `None` inherits.
    pub proxy_send_timeout_ms: Option<u64>,
    /// Location-scope `proxy_limit_rate` in bytes/sec. `None` inherits.
    pub proxy_limit_rate: Option<u64>,
    /// Location-scope `proxy_http_version 1.0|1.1;`. `None` inherits.
    pub proxy_http_version: Option<u8>,
    /// Location-scope `proxy_next_upstream`. `None` inherits.
    pub proxy_next_upstream: Option<ProxyNextUpstream>,
    /// Location-scope `proxy_next_upstream_tries`. `None` inherits.
    pub proxy_next_upstream_tries: Option<u32>,
    /// Location-scope `proxy_next_upstream_timeout`. `None` inherits.
    pub proxy_next_upstream_timeout_ms: Option<u64>,
    /// Location-scope `proxy_intercept_errors`. `None` inherits.
    pub proxy_intercept_errors: Option<bool>,
    /// Location-scope `proxy_redirect` directives. `None` inherits.
    pub proxy_redirect: Option<ProxyRedirect>,
    /// Location-scope `proxy_hide_header` / `proxy_pass_header` names.
    /// `None` inherits.
    pub proxy_hide_headers: Option<Vec<String>>,
    pub proxy_pass_headers: Option<Vec<String>>,
    /// Location-scope `chunked_transfer_encoding on|off;`. `None` inherits
    /// from server scope, which itself defaults to nginx's `on`. When
    /// `false`, the response body uses `Content-Length` framing and any
    /// `add_trailer` directives in scope are silently dropped.
    pub chunked_transfer_encoding: Option<bool>,
    /// Override for the alias-prefix used when this location's
    /// `Handler::Root` was inherited from an ancestor prefix-alias
    /// location (rather than set directly here). Unlike a directly-set
    /// alias — where the prefix is the current location's pattern — an
    /// inherited alias must use the *ancestor's* pattern, even if this
    /// location is a regex (where there is no own prefix). `None` for
    /// direct root/alias and for inheritance from server scope (which
    /// is always Root mapping, no prefix needed).
    pub alias_prefix_override: Option<String>,
}

/// `proxy_next_upstream` bitmask. nginx's defaults are `error | timeout`.
/// `off` zeroes the mask, disabling failover entirely. `non_idempotent`
/// gates whether a non-idempotent request (POST/PATCH/etc.) may be retried
/// after the body has started flowing — without it, ruxen mirrors nginx
/// and stops at the first attempt for non-idempotent methods.
///
/// The "http_*" flags decide whether a particular upstream status counts
/// as a failover trigger (in addition to connect/protocol failures).
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
pub struct ProxyNextUpstream {
    pub error: bool,
    pub timeout: bool,
    pub invalid_header: bool,
    pub http_500: bool,
    pub http_502: bool,
    pub http_503: bool,
    pub http_504: bool,
    pub http_403: bool,
    pub http_404: bool,
    pub http_429: bool,
    pub non_idempotent: bool,
}

impl ProxyNextUpstream {
    /// nginx default: `error timeout`.
    pub const DEFAULT: Self = Self {
        error: true,
        timeout: true,
        invalid_header: false,
        http_500: false,
        http_502: false,
        http_503: false,
        http_504: false,
        http_403: false,
        http_404: false,
        http_429: false,
        non_idempotent: false,
    };

    /// `off` → no failover at all.
    pub const OFF: Self = Self {
        error: false,
        timeout: false,
        invalid_header: false,
        http_500: false,
        http_502: false,
        http_503: false,
        http_504: false,
        http_403: false,
        http_404: false,
        http_429: false,
        non_idempotent: false,
    };

    #[allow(dead_code)]
    pub fn is_off(self) -> bool {
        !self.error
            && !self.timeout
            && !self.invalid_header
            && !self.http_500
            && !self.http_502
            && !self.http_503
            && !self.http_504
            && !self.http_403
            && !self.http_404
            && !self.http_429
    }

    pub fn matches_status(self, status: u16) -> bool {
        match status {
            500 => self.http_500,
            502 => self.http_502,
            503 => self.http_503,
            504 => self.http_504,
            403 => self.http_403,
            404 => self.http_404,
            429 => self.http_429,
            _ => false,
        }
    }
}

/// Parsed `keepalive_timeout timeout [header_timeout];`
/// `timeout` controls whether keepalive is enabled (`0` disables it).
/// `header_timeout` drives `Keep-Alive: timeout=N` output when keepalive
/// remains enabled.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct KeepaliveTimeout {
    pub timeout_ms: u64,
    pub header_timeout_secs: Option<u64>,
}

/// Parsed `keepalive_disable ...;` policy flags.
/// `none` clears both flags by omission (directive present with no
/// `msie6`/`safari` tokens set).
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct KeepaliveDisable {
    pub msie6: bool,
    pub safari: bool,
}

/// One `add_header NAME VALUE [always];` entry. `always` toggles whether
/// the header is emitted on error responses (nginx defaults to
/// 200/201/204/206/301..308 without `always`). Value is pre-split into
/// literal / variable parts at parse time so the hot path doesn't re-scan
/// the string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddHeader {
    pub name: String,
    pub value: Vec<ValuePart>,
    pub always: bool,
}

/// `expires` directive — sets `Expires` and `Cache-Control: max-age=...`
/// (or `no-cache` for negative offsets) on safe-status responses
/// (2xx/3xx as enumerated by `ngx_http_headers_filter_module.c`).
///
/// All non-variable forms resolve to one of the static variants below at
/// parse time. The variable form (`expires $foo;` /
/// `expires modified $foo;`) defers parsing until response shaping; the
/// rendered string is then run through the same parser as the static form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpiresDirective {
    /// `expires off;` — emits no Expires/Cache-Control. Acts as an explicit
    /// override of an inherited value.
    Off,
    /// `expires epoch;` — `Expires: Thu, 01 Jan 1970 00:00:01 GMT`,
    /// `Cache-Control: no-cache`.
    Epoch,
    /// `expires max;` — `Expires: Thu, 31 Dec 2037 23:55:55 GMT`,
    /// `Cache-Control: max-age=315360000`.
    Max,
    /// `expires <duration>;` (with optional sign). Stored in seconds, signed.
    /// Negative renders `Cache-Control: no-cache`.
    Access(i64),
    /// `expires modified <duration>;`. Same units as `Access` but the
    /// `Expires` time is `Last-Modified + offset`, with `max-age` derived
    /// from `expires_time - now`.
    Modified(i64),
    /// `expires @HhMmSs;` — daily at the given time-of-day. Stored as
    /// seconds since midnight (0..=86400).
    Daily(u32),
    /// `expires $variable;` — resolved at request time.
    Variable(Vec<ValuePart>),
    /// `expires modified $variable;` — same, with the `modified` semantics
    /// hard-coded (the dynamic value cannot itself contain `modified`).
    VariableModified(Vec<ValuePart>),
}

/// One `proxy_set_header NAME VALUE;` entry. nginx's directive accumulates
/// at one scope; child scope replaces the parent list outright (same merge
/// shape as `add_header`). Empty-value entries are legal and mean "delete
/// this header before forwarding" — the proxy builder skips them so the
/// upstream never sees the name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxySetHeader {
    pub name: String,
    pub value: Vec<ValuePart>,
}

/// One `log_format NAME [escape=...] FORMAT...;` definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogFormatDef {
    pub name: String,
    pub escape: LogEscape,
    pub value: Vec<ValuePart>,
}

/// How `log_format` writes variable values (`escape=`).
#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
pub enum LogEscape {
    /// A value that isn't set is `-`; `"`, `\`, control and non-ASCII
    /// bytes become `\xHH`.
    #[default]
    Default,
    /// JSON string escaping; a value that isn't set is empty.
    Json,
    /// Bytes as they are; a value that isn't set is empty.
    None,
}

/// One `access_log path [format] [if=expr];` sink.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessLog {
    /// The file, or the `syslog:…` argument as written (for messages).
    pub path: PathBuf,
    /// `access_log syslog:…`: the peer to send the lines to instead.
    pub syslog: Option<SyslogPeer>,
    pub format: Option<String>,
    pub condition: Option<Vec<ValuePart>>,
}

/// Parsed `auth_basic` value. `off` explicitly disables inherited auth.
/// The realm is stored as pre-rendered bytes — `$var` interpolation inside
/// a realm is rejected at parse time. (There's no `RenderCtx` available on
/// the 401 response path, and parameterized realms are rare in practice.)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthBasic {
    Off,
    Realm(Vec<u8>),
}

/// `client_body_in_file_only on|clean|off;`. `Off` is nginx's default —
/// no spill required (ruxen still spills above its internal threshold for
/// `$request_body_file`). `On` keeps the spilled file after the request.
/// `Clean` writes to file then unlinks at end-of-request.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ClientBodyInFileOnly {
    Off,
    On,
    Clean,
}

/// Severity threshold for one `error_log` sink.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ErrorLogLevel {
    Emerg,
    Alert,
    Crit,
    Error,
    Warn,
    Notice,
    Info,
    Debug,
}

impl ErrorLogLevel {
    pub fn allows(self, message_level: ErrorLogLevel) -> bool {
        self.rank() >= message_level.rank()
    }

    fn rank(self) -> u8 {
        match self {
            Self::Emerg => 0,
            Self::Alert => 1,
            Self::Crit => 2,
            Self::Error => 3,
            Self::Warn => 4,
            Self::Notice => 5,
            Self::Info => 6,
            Self::Debug => 7,
        }
    }
}

/// Destination for one `error_log` sink.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorLogTarget {
    File(PathBuf),
    Stderr,
    Syslog(SyslogPeer),
}

/// `syslog:server=…[,facility=…][,severity=…][,tag=…][,nohostname]`, as
/// ngx_syslog_process_conf parses it. Used by `access_log` and
/// `error_log` (which takes the severity from each message's level).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyslogPeer {
    pub server: ErrorLogSyslogServer,
    /// RFC 3164 facility code (default 23, local7).
    pub facility: u8,
    /// RFC 3164 severity code (default 6, info).
    pub severity: u8,
    pub tag: Option<String>,
    pub nohostname: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorLogSyslogServer {
    /// `server=unix:/path/to/socket`
    Unix(PathBuf),
    /// `server=host:port` / `server=[ipv6]:port` / `server=host` (`:514` defaulted).
    Udp(String),
}

/// One `error_log target [level];` sink.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorLog {
    pub target: ErrorLogTarget,
    pub level: ErrorLogLevel,
}

/// One `index` directive argument. Stored as the same literal / variable
/// parts used by `return` and `add_header`, so `${server_name}.html` and
/// similar forms can be rendered at request time without inventing a second
/// templating surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexEntry {
    pub parts: Vec<ValuePart>,
}

/// How a matched `error_page` should treat the status from the target
/// location. Plain `error_page 404 /x;` preserves the original status when
/// the target completes successfully; bare `=` means "use the target's own
/// status"; `=NNN` pins the final status to that code for successful target
/// completions.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ErrorPageAction {
    PreserveOriginal,
    UseTargetStatus,
    Override(u16),
}

/// One `error_page` mapping after parse-time expansion of a single
/// directive. `error_page 404 500 /50x.html;` becomes two entries sharing
/// the same target and action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorPage {
    pub status: u16,
    pub action: ErrorPageAction,
    pub target: Vec<ValuePart>,
}

/// One `split_clients` declaration at http scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitClients {
    /// Rendered input key expression (e.g. `$connection`).
    pub key: Vec<ValuePart>,
    /// Output variable name without the leading `$`.
    pub variable: String,
    /// Bucket table in declaration order.
    pub parts: Vec<SplitClientsPart>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitClientsPart {
    /// Cumulative threshold in nginx hash space (`0..=0xffff_ffff`).
    /// `0` is nginx's sentinel for the catch-all `*` bucket.
    pub threshold: u32,
    pub value: Vec<ValuePart>,
}

/// One `map $source $dest { ... }` declaration at http scope.
///
/// Mirrors nginx's `ngx_http_map_module.c`: the source is a rendered value
/// expression (`$var` or composition), the destination is a bare variable
/// name, and the body lists match entries plus an optional `default`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapBlock {
    /// Rendered input key expression (typically a single `$var`).
    pub key: Vec<ValuePart>,
    /// Output variable name without the leading `$`.
    pub variable: String,
    /// Exact-string entries. Multiple matches on the same literal resolve
    /// to the first declaration (we reject duplicates at parse time).
    pub exact: Vec<MapExactEntry>,
    /// Regex entries (`~pattern` / `~*pattern`) in declaration order.
    pub regex: Vec<MapRegexEntry>,
    /// Fallback value when nothing matches. `None` renders empty, matching
    /// nginx when no `default` is declared.
    pub default: Option<Vec<ValuePart>>,
    /// `hostnames;`: the source value is a host name (a trailing dot is
    /// ignored) and keys may be wildcards (`*.example.com`,
    /// `.example.com`, `mail.*`).
    pub hostnames: bool,
    /// The wildcard keys of a `hostnames` map, as written.
    pub wildcards: Vec<MapExactEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapExactEntry {
    pub key: String,
    pub value: Vec<ValuePart>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapRegexEntry {
    pub pattern: String,
    pub case_insensitive: bool,
    pub value: Vec<ValuePart>,
}

/// Rewrite-phase directives valid in `location` and `if` blocks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RewriteOp {
    Set {
        /// Variable name without the leading `$`.
        name: String,
        value: Vec<ValuePart>,
    },
    If {
        guard: IfGuard,
        body: Vec<RewriteOp>,
    },
    Rewrite(RewriteRule),
    Return {
        status: u16,
        body: Vec<ValuePart>,
    },
    Break,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RewriteRule {
    pub regex: String,
    /// URI portion of the replacement: parts before the first literal `?`
    /// (or the whole replacement when no `?` appears).
    pub replacement: Vec<ValuePart>,
    /// Args portion: parts after the first literal `?`. `None` when the
    /// replacement contains no `?`. When present, captures rendered into
    /// these parts get arg-escaped (nginx's `NGX_ESCAPE_ARGS`).
    pub replacement_args: Option<Vec<ValuePart>>,
    pub flag: RewriteFlag,
    pub drop_args: bool,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum RewriteFlag {
    None,
    Last,
    Break,
    Redirect,
    Permanent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IfGuard {
    VarTruthy(Variable),
    Eq {
        left: Variable,
        right: Vec<ValuePart>,
    },
    NotEq {
        left: Variable,
        right: Vec<ValuePart>,
    },
    Regex {
        left: Variable,
        pattern: String,
        case_insensitive: bool,
        negated: bool,
    },
    FileTest {
        kind: FileTestKind,
        path: Vec<ValuePart>,
        negated: bool,
    },
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum FileTestKind {
    File,
    Dir,
    Exists,
    Exec,
}

/// A value string as a sequence of literal chunks and `$variable` references.
/// Used by both `add_header` values and `return` bodies so `$uri`, `$host`,
/// and friends resolve the same way in both directives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValuePart {
    Literal(String),
    Var(Variable),
}

/// Variables we recognize inside directive values. Core variables get
/// dedicated variants; `$http_NAME` / `$sent_http_NAME` / `$arg_NAME` go
/// through dynamic variants that carry the name. Anything we can neither
/// resolve nor recognize becomes `Unknown` — nginx renders unknown vars
/// as the empty string at runtime rather than failing the config, and
/// test suites rely on that leniency.
/// Which TLV a `$proxy_protocol_tlv_<name>` reads, resolved from the name
/// when the configuration is parsed (nginx resolves it per request).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyProtocolTlv {
    /// `alpn`, `authority`, `unique_id`, `ssl`, `netns`, or `0xNN`. `None`:
    /// a hex type over `0xff`, which no TLV has.
    Type(Option<u8>),
    /// `ssl_version`, `ssl_cn`, `ssl_cipher`, `ssl_sig_alg`, `ssl_key_alg`,
    /// or `ssl_0xNN`: a sub-TLV of the SSL TLV.
    Ssl(Option<u8>),
    /// `ssl_verify`: the SSL TLV's 32-bit verify field.
    SslVerify,
    /// A name nginx doesn't know: always empty (nginx logs "unknown PROXY
    /// protocol TLV" per request).
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Variable {
    /// Normalized request URI (no query string).
    Uri,
    /// Raw request URI as received from the request line, including the
    /// query string when present.
    RequestUri,
    /// Lowercased Host, port-stripped, trailing-dot trimmed; empty when
    /// the request is HTTP/1.0 with no Host.
    Host,
    /// First `server_name` of the matched `server {}` block; empty if none.
    ServerName,
    /// Response status as decimal (`200`, `404`, …). Useful in
    /// `add_header X-Status $status;` style tests.
    Status,
    /// Query string after `?`, without the leading question mark.
    Args,
    /// `?` when the request has a non-empty query string, else empty.
    IsArgs,
    /// Value of the named query argument. Missing argument ⇒ empty.
    Arg(String),
    /// `https` for connections accepted on a TLS listener, `http` otherwise.
    Scheme,
    /// Negotiated TLS protocol version (`TLSv1.3`, `TLSv1.2`, …). Empty
    /// outside a TLS connection.
    SslProtocol,
    /// Negotiated cipher suite, rendered in the same form nginx exposes:
    /// OpenSSL spelling for TLS 1.2, IANA name for TLS 1.3.
    SslCipher,
    /// Colon-separated list of ciphers available for this SSL connection.
    /// ruxen currently exposes the negotiated cipher as a single-entry list.
    SslCiphers,
    /// SNI hostname from the ClientHello, lowercased by rustls. Empty when
    /// the client didn't send SNI or on plain HTTP.
    SslServerName,
    /// `r` if the TLS session was resumed, `.` for a fresh handshake or a
    /// plain-HTTP connection. Mirrors nginx's `$ssl_session_reused`.
    SslSessionReused,
    /// Session identifier. ruxen currently renders this empty; rustls does
    /// not expose a stable nginx-style session-id string through the API we use.
    SslSessionId,
    /// Client cert verification result (`NONE`, `SUCCESS`, `FAILED:...`).
    SslClientVerify,
    /// Issuer DN in RFC2253-style form (`CN=issuer`).
    SslClientIDn,
    /// Issuer DN in legacy slash form (`/CN=issuer`).
    SslClientIDnLegacy,
    /// Subject DN in RFC2253-style form (`CN=subject`).
    SslClientSDn,
    /// Subject DN in legacy slash form (`/CN=subject`).
    SslClientSDnLegacy,
    /// Client cert notBefore timestamp.
    SslClientVStart,
    /// Client cert notAfter timestamp.
    SslClientVEnd,
    /// Whole days until client cert expiry.
    SslClientVRemain,
    /// Request body buffered by the parser.
    RequestBody,
    /// Path to the spilled request body temp file, when one was created.
    RequestBodyFile,
    /// Client IP address from the accepted peer socket (e.g. `127.0.0.1`,
    /// `::1`). Mirrors nginx's `$remote_addr`.
    RemoteAddr,
    /// Client source port from the accepted peer socket. Mirrors nginx's
    /// `$remote_port`.
    RemotePort,
    /// Username from successful HTTP Basic auth. Empty when no user was
    /// authenticated for the request.
    RemoteUser,
    /// Machine hostname, captured once at startup (`gethostname`).
    Hostname,
    /// `$http_NAME` — request header lookup. Name is stored lowercased
    /// with underscores replaced by dashes so a linear scan of the raw
    /// header block compares directly.
    Http(String),
    /// `$sent_http_NAME` — response header lookup. Only valid in contexts
    /// that run after response headers exist (e.g. `add_header`,
    /// `log_format`/`access_log`). Directives rendered before response
    /// header construction reject this variable at parse time.
    SentHttp(String),
    /// `$cookie_NAME` — request cookie lookup. Walks every `Cookie:` header,
    /// splits on `;`, returns the value of the first `name=value` pair whose
    /// (case-insensitive) name matches.
    Cookie(String),
    /// `$content_length` — request `Content-Length` header value.
    ContentLength,
    /// `$content_type` — request `Content-Type` header value (multi-valued
    /// joined with `, ` like other request headers).
    ContentType,
    /// `$upstream_http_NAME` — combined values of a header from the upstream
    /// response. Empty outside a proxy context or when the header is absent.
    UpstreamHttp(String),
    /// `$upstream_cookie_NAME` — value of a named cookie from the upstream
    /// `Set-Cookie` response header(s).
    UpstreamCookie(String),
    /// `$upstream_addr`, `$upstream_status`, `$upstream_connect_time`,
    /// `$upstream_header_time`, `$upstream_bytes_received`,
    /// `$upstream_bytes_sent`: one value per upstream attempt.
    UpstreamAddr,
    UpstreamStatus,
    UpstreamConnectTime,
    UpstreamHeaderTime,
    UpstreamBytesReceived,
    UpstreamBytesSent,
    /// `$upstream_response_length` — total bytes of the upstream response
    /// body (excluding upstream headers). Empty outside a proxy context.
    UpstreamResponseLength,
    /// `$upstream_response_time` — wall-clock seconds (millisecond precision,
    /// `0.000` format) spent waiting on the upstream. Empty outside a proxy
    /// context.
    UpstreamResponseTime,
    /// `$sent_trailer_NAME` — combined values of a trailer added via
    /// `add_trailer`. Empty when no matching trailer was registered.
    SentTrailer(String),
    /// Monotonic per-worker connection counter, incremented once per
    /// accepted connection before the first request on it is served.
    Connection,
    /// Number of requests already completed on this connection at the
    /// moment rendering runs. Zero on the first request.
    ConnectionRequests,
    /// Time since connection accept, in seconds with millisecond
    /// precision (`12.345`). Mirrors nginx's `$connection_time` format.
    ConnectionTime,
    /// Time spent processing this request, in seconds with millisecond
    /// precision (`12.345`). Mirrors nginx's `$request_time` format.
    RequestTime,
    /// Always `0` for now — no rate-limiting subsystem yet.
    LimitRate,
    /// Listening port from `listen NN;` for the matched server.
    ServerPort,
    /// Port part of the request authority — comes from `Host: host:port`
    /// or absolute-form `GET http://host:port/ ...`. Empty if no explicit
    /// port was sent.
    RequestPort,
    /// `:` when `$request_port` is non-empty, else empty. Mirrors nginx's
    /// `$is_args` shape so configs can build optional `:port` strings
    /// without conditionals.
    IsRequestPort,
    /// `p` if this request was already buffered when the previous request
    /// on the same connection completed (pipelined), `.` otherwise.
    /// Mirrors nginx's `r->pipeline`.
    Pipe,
    /// Total bytes received for this request (request line + headers +
    /// body). nginx's `r->request_length`.
    RequestLength,
    /// Total bytes written on the wire for the response (status line +
    /// headers + body). Set by the worker after the response is built.
    BytesSent,
    /// Body bytes only — `$bytes_sent` minus the response-header size.
    BodyBytesSent,
    /// ISO 8601 with TZ offset (`2026-04-23T12:34:56+00:00`). Always UTC
    /// in ruxen — nginx renders local time, but the test regex (and
    /// production log shipping) accepts any TZ offset.
    TimeIso8601,
    /// `[28/Sep/1970:06:00:00 +0000]`-style timestamp (Common Log Format
    /// date). Always UTC in ruxen for the same reason as `time_iso8601`.
    TimeLocal,
    /// Unix epoch with millisecond fraction (`1234567890.123`).
    Msec,
    /// Numbered regex capture (`$1`..`$9`) from rewrite/location regex
    /// matching.
    Capture(usize),
    /// `$proxy_host` — the host:port (or upstream block name) from the
    /// matched `proxy_pass` URL. Empty outside a proxy context.
    ProxyHost,
    /// `$proxy_port` — the port of the matched `proxy_pass` URL: the one
    /// written in `$proxy_host`, else 80. Empty outside a proxy context.
    ProxyPort,
    /// `$proxy_add_x_forwarded_for` — the incoming `X-Forwarded-For`
    /// header value (if any) followed by `, $remote_addr`. When the
    /// incoming header is absent the value is just `$remote_addr`.
    ProxyAddXForwardedFor,
    /// `$request_method` — uppercase request method bytes from the request
    /// line (`GET`, `POST`, `HEAD`, …). Mirrors nginx's
    /// `r->method_name` rendering.
    RequestMethod,
    /// `$request` — the request line as received, without the CRLF.
    Request,
    /// `$proxy_protocol_addr` / `_port` / `_server_addr` / `_server_port`:
    /// from the connection's PROXY protocol header.
    ProxyProtocolAddr,
    ProxyProtocolPort,
    ProxyProtocolServerAddr,
    ProxyProtocolServerPort,
    /// `$proxy_protocol_tlv_<name>`: a TLV of the connection's PROXY
    /// protocol v2 header.
    ProxyProtocolTlv(ProxyProtocolTlv),
    /// `$server_protocol` — `HTTP/1.0` or `HTTP/1.1` from the request line.
    ServerProtocol,
    /// Unrecognized `$name`. Renders empty at runtime, matching nginx's
    /// lenient lookup: unknown variables don't fail the config.
    Unknown(String),
}

/// How a static-file location maps the request URI onto the configured base
/// path. `root` appends the whole URI; `alias` is resolved in worker prepare:
/// prefix/exact aliases strip the matched prefix, while regex aliases use
/// nginx's `add_uri_to_alias` flow in the resolver.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum PathMapping {
    Root,
    Alias,
}

/// One parsed `server_name` argument, classified by shape so the
/// matcher in `find_config` doesn't re-scan the string per request.
/// Mirrors nginx's `ngx_http_server_name_t` flags
/// (`NGX_HTTP_WILDCARD_HEAD`, `_TAIL`, `*regex`, name-only).
///
/// `display` carries the original spelling — including the `~` prefix on
/// regex names and the `*` on wildcard names — so `$server_name` renders
/// the source form. The `pattern` / matched substring is normalized
/// separately for fast comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerNameSpec {
    /// `localhost`, `www.example.com` — case-insensitive exact match.
    Exact(String),
    /// `*.example.com` — matches `example.com` or any `*.example.com`
    /// subdomain. Stored as the lowercase suffix without the leading
    /// `*.` (here `example.com`); `display` keeps the original.
    WildcardLeading { display: String, suffix: String },
    /// `mail.example.*` — matches a host whose head equals `mail.example`
    /// or starts with `mail.example.`. Stored as the lowercase head
    /// without the trailing `.*`.
    WildcardTrailing { display: String, head: String },
    /// `~^pattern$` — PCRE regex. nginx `~*` is case-insensitive; ruxen
    /// gates that on the `case_insensitive` flag.
    Regex {
        display: String,
        pattern: String,
        case_insensitive: bool,
    },
    /// `""` — matches a request that has no `Host` header. Selected only
    /// when no other server matched and Host is absent.
    Empty,
}

impl ServerNameSpec {
    /// The string `$server_name` should render to when this spec wins
    /// the match. Empty for the empty server.
    pub fn display(&self) -> &str {
        match self {
            Self::Exact(s) => s.as_str(),
            Self::WildcardLeading { display, .. } => display.as_str(),
            Self::WildcardTrailing { display, .. } => display.as_str(),
            Self::Regex { display, .. } => display.as_str(),
            Self::Empty => "",
        }
    }
}

/// `server_tokens off|on|build;` — controls whether the version is exposed
/// in the `Server:` header and the default error-page footer signature.
/// Mirrors nginx's `NGX_HTTP_SERVER_TOKENS_*` constants in
/// `ngx_http_core_module.h`. Default at all scopes is `On`.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ServerTokens {
    /// `Server: nginx`, plain `<center>nginx</center>` body footer.
    Off,
    /// `Server: nginx/<ver>`, `<center>nginx/<ver></center>` body footer.
    On,
    /// `Server: nginx/<ver>` (with build tag in nginx; ruxen has no build
    /// tag so this is identical to `On` today, but we preserve the
    /// distinction so the directive parses and round-trips faithfully).
    Build,
}

/// `autoindex_format html|xml|json|jsonp;`
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum AutoindexFormat {
    Html,
    Xml,
    Json,
    Jsonp,
}

/// `try_files path... fallback;` — a PRECONTENT-phase probe list plus a
/// terminal fallback, mirroring nginx's
/// `ngx_http_try_files_module.c::ngx_http_try_files`. Each probe tests a
/// candidate filesystem path (relative to `root`); the first hit rewrites
/// the request URI and re-enters content dispatch. On full miss the
/// fallback fires — a status code (`=NNN`) or a URI that re-enters
/// location matching.
#[derive(Debug, Clone)]
pub struct TryFiles {
    pub probes: Vec<TryFilesProbe>,
    pub fallback: TryFilesFallback,
}

/// One non-terminal probe. `$uri` is the *only* variable we recognize in
/// M6 (generic variable expansion is deferred). The `_slash` variants
/// mean "candidate ends in `/`, test as a directory, not a file" — nginx
/// encodes this on the probe via `tf->test_dir` (try_files_module.c:318).
#[derive(Debug, Clone)]
pub enum TryFilesProbe {
    /// `$uri` — test file at `<root><uri>`.
    Uri,
    /// `$uri/` — test directory at `<root><uri>`.
    UriSlash,
    /// Literal path (joined with `root`), tested as a file.
    Literal(String),
    /// Literal path ending with `/`, tested as a directory.
    LiteralSlash(String),
}

#[derive(Debug, Clone)]
pub enum TryFilesFallback {
    /// `=NNN` — return this status directly. nginx parses this out of the
    /// final entry when it begins with `=` (try_files_module.c:350–362).
    Status(u16),
    /// A URI that re-enters location matching (internal redirect).
    Uri(String),
    /// An internal-only named location target.
    Named(String),
}

/// What a matched location produces. `Return` mirrors nginx's `return <code>
/// "<body>";` — a fixed response. `Root` serves static files rooted at
/// `path`, with `mapping` choosing `root`-style whole-URI append vs `alias`-
/// style matched-prefix stripping.
///
/// These are mutually exclusive inside a single `location` block. If both
/// `return` and `root`/`alias` appear, `return` wins (nginx semantics: the
/// rewrite phase's `return` short-circuits the content phase).
#[derive(Debug, Clone)]
pub enum Handler {
    Return {
        status: u16,
        /// Body, pre-split into literal and `$variable` parts. An empty
        /// vec is a legal "no body" response (`return 200;`), rendered as
        /// `Content-Length: 0` with no body bytes.
        body: Vec<ValuePart>,
    },
    Root {
        path: PathBuf,
        mapping: PathMapping,
    },
    /// `proxy_pass http://...;` — reverse proxy this location to an upstream.
    /// Resolution to a concrete peer happens at prepare time.
    Proxy(ProxyPass),
}

/// Parsed `proxy_pass` argument. nginx allows two forms:
///
/// - `proxy_pass http://NAME[/path];` where `NAME` matches an `upstream {}`
///   block's name → `UpstreamRef { name, request_path }`.
/// - `proxy_pass http://host:port[/path];` → `Direct { addr, host_header,
///   request_path }`. Host must resolve at parse time via `to_socket_addrs`.
///
/// `request_path` is the path part of the proxy_pass URL when present (the
/// "URI" half nginx uses to decide path-rewriting behavior). `None` means
/// "no path on the proxy_pass URL" — forward the client URI as-is.
/// `Some(path)` means "use this prefix" — when a prefix-match location is
/// configured with a proxy_pass URL that has a path, nginx rewrites the
/// outgoing path: strip the matched location prefix from the client URI,
/// prepend `request_path`.
/// The `proxy_redirect` directives of one scope: `off`, or rules tried in
/// order on upstream `Location` / `Refresh` headers.
#[derive(Debug, Clone, PartialEq)]
pub enum ProxyRedirect {
    Off,
    Rules(Vec<ProxyRedirectRule>),
}

#[derive(Debug, Clone, PartialEq)]
pub enum ProxyRedirectRule {
    /// `proxy_redirect default;`: derived from `proxy_pass` and the
    /// location at prepare time.
    Default,
    /// A prefix to replace; both sides may contain variables.
    Prefix {
        pattern: Vec<ValuePart>,
        replacement: Vec<ValuePart>,
    },
    /// `~` / `~*`: on a match the whole value becomes `replacement`, which
    /// may use `$1`…`$9`.
    Regex {
        pattern: String,
        case_insensitive: bool,
        replacement: Vec<ValuePart>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyPass {
    UpstreamRef {
        name: String,
        host_header: String,
        request_path: Option<String>,
    },
    Direct {
        addr: SocketAddr,
        host_header: String,
        request_path: Option<String>,
    },
}
