//! Prepared (immutable, leaked-static) data model: every type the worker
//! reads on the hot path. Built once during startup by `prepare::prepare`,
//! then handed to workers as `&'static`.

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
    ErrorLogSyslogServer, ErrorLogTarget, ErrorPage, ErrorPageAction, FileTestKind, Handler,
    HttpConfig, IfGuard, IndexEntry, KeepaliveDisable, KeepaliveTimeout, Location, LogFormatDef,
    MapBlock, MapExactEntry, MapRegexEntry, MatchMode, PathMapping, ProxyPass, ProxySetHeader,
    RewriteFlag as ConfigRewriteFlag, RewriteOp, RewriteRule, Server, SplitClients, TryFiles,
    TryFilesFallback, TryFilesProbe, ValuePart, Variable,
};
use crate::http::{self, Method, Parse, ParseState, READ_BUF};
use crate::phase::{self, Response};
use crate::{autoindex, file, fs_resolve, uri};

use super::*;

/// A response whose headers (and, for non-HEAD, body) are built once at
/// startup. `pick(method)` returns the correct variant: RFC 9110 §9.3.2
/// forbids a body in responses to HEAD, so we keep a parallel body-less
/// slice and route HEAD requests to it.
pub struct Prebuilt {
    pub full: &'static [u8],
    pub head: &'static [u8],
}

impl Prebuilt {
    pub(crate) fn from_built(full: Vec<u8>, head: Vec<u8>) -> Self {
        let full = Box::leak(full.into_boxed_slice());
        let head = Box::leak(head.into_boxed_slice());
        Prebuilt { full, head }
    }

    pub(crate) fn leak(status: u16, body: &str, server: &[u8]) -> Self {
        Self::from_built(
            http::build_response(status, body, server),
            http::build_head_response(status, body.len(), server),
        )
    }

    pub(crate) fn leak_bytes(status: u16, body: &[u8], server: &[u8]) -> Self {
        Self::from_built(
            http::build_response_bytes(status, body, server),
            http::build_head_response(status, body.len(), server),
        )
    }

    pub(crate) fn leak_redirect(status: u16, location: &[u8], server: &[u8]) -> Self {
        Self::from_built(
            http::build_redirect_response(status, location, Method::Get, server),
            http::build_redirect_response(status, location, Method::Head, server),
        )
    }

    #[inline]
    pub fn pick(&self, method: Method) -> &'static [u8] {
        if matches!(method, Method::Head) {
            self.head
        } else {
            self.full
        }
    }
}

pub enum PreparedReturn {
    /// Body has no variables — baked once at startup into a Prebuilt.
    Static(Prebuilt),
    /// Body contains at least one `$variable` reference. Rendered per
    /// request by walking `parts` and writing each literal chunk / variable
    /// value into a fresh `Vec<u8>`.
    Template {
        status: u16,
        parts: &'static [PreparedValuePart],
    },
}

/// Runtime-ready form of a `ValuePart`. Literals are promoted to `&'static
/// [u8]` so rendering is a straight byte-copy; variables carry the enum
/// discriminant unchanged.
#[derive(Debug, Clone)]
pub enum PreparedValuePart {
    Literal(&'static [u8]),
    Var(Variable),
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum PreparedRewriteFlag {
    None,
    Last,
    Break,
    Redirect,
    Permanent,
}

pub enum PreparedRewriteOp {
    Set {
        name: &'static [u8],
        value: &'static [PreparedValuePart],
    },
    If {
        guard: PreparedGuard,
        body: &'static [PreparedRewriteOp],
    },
    Rewrite {
        regex: &'static regex::bytes::Regex,
        replacement_uri: &'static [PreparedValuePart],
        replacement_args: Option<&'static [PreparedValuePart]>,
        flag: PreparedRewriteFlag,
        drop_args: bool,
    },
    Return(PreparedReturn),
    Break,
}

pub enum PreparedGuard {
    VarTruthy(Variable),
    Eq {
        left: Variable,
        right: &'static [PreparedValuePart],
    },
    NotEq {
        left: Variable,
        right: &'static [PreparedValuePart],
    },
    Regex {
        left: Variable,
        regex: &'static regex::bytes::Regex,
        negated: bool,
    },
    FileTest {
        kind: FileTestKind,
        path: &'static [PreparedValuePart],
        negated: bool,
    },
}

/// Prepared form of an `expires` directive. Variants mirror
/// `ExpiresDirective`, but the variable forms carry pre-leaked
/// `PreparedValuePart` slices for the hot path. `Off` is the inherited
/// default — no Expires/Cache-Control header injection.
#[derive(Debug, Copy, Clone)]
pub enum PreparedExpires {
    Off,
    Epoch,
    Max,
    Access(i64),
    Modified(i64),
    Daily(u32),
    Variable(&'static [PreparedValuePart]),
    VariableModified(&'static [PreparedValuePart]),
}

#[derive(Debug, Copy, Clone)]
pub struct PreparedSplitClientsPart {
    pub threshold: u32,
    pub value: &'static [PreparedValuePart],
}

pub struct PreparedSplitClients {
    pub key: &'static [PreparedValuePart],
    pub parts: &'static [PreparedSplitClientsPart],
}

/// One compiled `map` regex entry. We keep the pattern + case flag only for
/// debugging: the compiled `Regex` is the authoritative matcher.
pub struct PreparedMapRegex {
    pub regex: regex::bytes::Regex,
    pub value: &'static [PreparedValuePart],
}

/// Prepared form of one `map $source $dest { ... }` program.
///
/// `exact` is a HashMap so hot-path lookup is O(1) against the rendered
/// source value. `regex` is tried in declaration order only when no exact
/// entry matches, mirroring `ngx_http_map_module.c`.
pub struct PreparedMap {
    pub key: &'static [PreparedValuePart],
    /// Exact keys, lowercased: nginx's map hash is case-insensitive.
    pub exact: std::collections::HashMap<Vec<u8>, &'static [PreparedValuePart]>,
    /// `hostnames`: a trailing dot of the value is ignored, and the
    /// wildcards below apply.
    pub hostnames: bool,
    /// `*.example.com` / `.example.com` as (lowercased suffix, whether the
    /// bare `example.com` matches too, value); the longest match wins.
    pub wildcard_head: &'static [(Vec<u8>, bool, &'static [PreparedValuePart])],
    /// `mail.*` as (lowercased head, value); the longest match wins.
    pub wildcard_tail: &'static [(Vec<u8>, &'static [PreparedValuePart])],
    pub regex: &'static [PreparedMapRegex],
    pub default: Option<&'static [PreparedValuePart]>,
    /// Its first result is kept for the request (`RewriteState`): not
    /// `volatile`, and its key or values can change during a request.
    pub cached: bool,
    /// This map's index, for the request's cache (`RewriteState`).
    pub slot: usize,
}

#[derive(Debug, Clone)]
pub struct RewriteState {
    user_vars: Vec<(&'static [u8], Vec<u8>)>,
    numbered_captures: Vec<Vec<u8>>,
    /// nginx's `r->valid_location`: starts true, cleared whenever a
    /// `rewrite` directive replaces the URI in-place. Read by `proxy_pass`
    /// to decide whether to apply its configured URI prefix substitution
    /// (when false, the rewritten URI is forwarded as-is to upstream).
    pub(crate) valid_location: bool,
    /// `map` results already computed for this request, by map slot: nginx
    /// caches a variable's value in `r->variables` for the rest of the
    /// request, internal redirects included, unless the map is `volatile`.
    /// Filled while rendering, which only has `&self`.
    map_cache: std::cell::RefCell<Vec<(usize, Vec<u8>)>>,
    /// The chosen location's (or, in the server's rewrite phase, the
    /// server's) root, for `$request_filename` / `$document_root`.
    pub(crate) doc_root: Option<&'static DocRoot>,
}

impl Default for RewriteState {
    fn default() -> Self {
        Self {
            user_vars: Vec::new(),
            numbered_captures: Vec::new(),
            valid_location: true,
            map_cache: std::cell::RefCell::new(Vec::new()),
            doc_root: None,
        }
    }
}

impl RewriteState {
    pub(crate) fn clear_numbered_captures(&mut self) {
        if self.numbered_captures.is_empty() {
            return;
        }
        for capture in &mut self.numbered_captures {
            capture.clear();
        }
    }

    pub(crate) fn set_numbered_capture(&mut self, n: usize, bytes: &[u8]) {
        if n == 0 {
            return;
        }
        if self.numbered_captures.is_empty() {
            self.numbered_captures.resize_with(10, Vec::new);
        }
        if n < self.numbered_captures.len() {
            self.numbered_captures[n].clear();
            self.numbered_captures[n].extend_from_slice(bytes);
        }
    }

    /// `set_numbered_from_regex_captures` from capture ranges taken
    /// earlier (index 0 is the whole match).
    pub(crate) fn set_numbered_from_ranges(
        &mut self,
        subject: &[u8],
        ranges: &[Option<(usize, usize)>],
    ) {
        self.clear_numbered_captures();
        for (n, range) in ranges.iter().enumerate().take(10).skip(1) {
            if let Some((start, end)) = range {
                self.set_numbered_capture(n, &subject[*start..*end]);
            }
        }
    }

    /// Whether a regex left `$1`…`$9` to render later.
    pub(crate) fn has_numbered_captures(&self) -> bool {
        self.numbered_captures.iter().any(|c| !c.is_empty())
    }

    pub(crate) fn set_numbered_from_regex_captures(
        &mut self,
        captures: &regex::bytes::Captures<'_>,
        subject: &[u8],
    ) {
        self.clear_numbered_captures();
        for n in 1..=9 {
            if let Some(m) = captures.get(n) {
                self.set_numbered_capture(n, &subject[m.start()..m.end()]);
            }
        }
    }

    pub(crate) fn numbered_capture(&self, n: usize) -> Option<&[u8]> {
        self.numbered_captures
            .get(n)
            .filter(|v| !v.is_empty())
            .map(Vec::as_slice)
    }

    pub(crate) fn set_user_var(&mut self, name: &'static [u8], value: Vec<u8>) {
        for (existing_name, existing_value) in &mut self.user_vars {
            if *existing_name == name {
                *existing_value = value;
                return;
            }
        }
        self.user_vars.push((name, value));
    }

    /// No `set` ran (the common case; a field check, no name compare).
    pub(crate) fn has_user_vars(&self) -> bool {
        !self.user_vars.is_empty()
    }

    /// Something later rendering (the access log, a proxied response's
    /// `add_header`) needs from this state: `set` values or cached maps.
    pub(crate) fn worth_keeping(&self) -> bool {
        self.has_user_vars() || !self.map_cache.borrow().is_empty()
    }

    /// Appends the cached result of map `slot` to `out`, if there is one.
    pub(crate) fn cached_map(&self, slot: usize, out: &mut Vec<u8>) -> bool {
        let cache = self.map_cache.borrow();
        match cache.iter().find(|(s, _)| *s == slot) {
            Some((_, value)) => {
                out.extend_from_slice(value);
                true
            }
            None => false,
        }
    }

    pub(crate) fn cache_map(&self, slot: usize, value: &[u8]) {
        let mut cache = self.map_cache.borrow_mut();
        if !cache.iter().any(|(s, _)| *s == slot) {
            cache.push((slot, value.to_vec()));
        }
    }

    pub(crate) fn user_var(&self, name: &str) -> Option<&[u8]> {
        let name = name.as_bytes();
        self.user_vars
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| v.as_slice())
    }
}

/// `add_header NAME VALUE [always];` entry after prepare: name bytes,
/// pre-split value, and the `always` bit. Grouped into a slice per
/// `PreparedLocation` (inheritance is resolved at prepare time).
#[derive(Debug, Copy, Clone)]
pub struct PreparedAddHeader {
    pub name: &'static [u8],
    pub value: &'static [PreparedValuePart],
    pub always: bool,
}

/// Prepared `access_log` sink: append path, rendered format template, and
/// optional condition expression (`if=...`).
///
/// `file_index` is this sink's slot in `PreparedHttp::access_logs` — the
/// per-worker file-descriptor table is indexed by it. Per-location
/// `access_logs` slices share the same backing storage as the http-scope
/// list so the index stays valid across scopes.
#[derive(Debug, Copy, Clone)]
pub struct PreparedAccessLog {
    pub path: &'static Path,
    pub format: &'static [PreparedValuePart],
    pub escape: crate::config::LogEscape,
    /// The format uses `$upstream_http_*` / `$upstream_cookie_*`, so the
    /// upstream's header block has to be kept for the log line.
    pub reads_upstream_headers: bool,
    pub condition: Option<&'static [PreparedValuePart]>,
    pub file_index: usize,
    /// `access_log syslog:…`: lines go to this peer, not to `path`.
    pub syslog: Option<&'static PreparedSyslogPeer>,
}

/// A prepared `syslog:` peer (see `crate::syslog`).
#[derive(Debug, PartialEq, Eq)]
pub struct PreparedSyslogPeer {
    pub server: PreparedErrorLogSyslogServer,
    /// RFC 3164 facility code.
    pub facility: u8,
    /// RFC 3164 severity code: `access_log`'s; `error_log` uses each
    /// message's level instead, as nginx's ngx_syslog_writer.
    pub severity: u8,
    pub tag: &'static [u8],
    pub nohostname: bool,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct PreparedErrorLog {
    pub target: PreparedErrorLogTarget,
    pub level: ErrorLogLevel,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum PreparedErrorLogTarget {
    File(&'static Path),
    Stderr,
    Syslog(&'static PreparedSyslogPeer),
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum PreparedErrorLogSyslogServer {
    Unix(&'static Path),
    Udp(&'static str),
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum PreparedErrorPageAction {
    PreserveOriginal,
    UseTargetStatus,
    Override(u16),
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct PreparedKeepalive {
    pub allow: bool,
    pub idle_timeout_ms: Option<u64>,
    pub header_timeout_secs: Option<u64>,
    pub max_requests: u64,
    pub max_time_ms: u64,
    pub disable_msie6: bool,
    pub disable_safari: bool,
}

/// The access phase of a location (or of a server, for requests that
/// match no location), inheritance resolved.
#[derive(Debug, Copy, Clone)]
pub struct PreparedAccess {
    /// `allow` / `deny` in order; empty when none applies.
    pub rules: &'static [crate::config::AccessRule],
    /// `satisfy any`: one passing check is enough.
    pub satisfy_any: bool,
    pub auth_basic: PreparedAuthBasic,
    pub auth_basic_user_file: Option<&'static Path>,
    /// `auth_delay` in milliseconds.
    pub auth_delay_ms: u64,
    pub realip: PreparedRealIp,
}

impl PreparedAccess {
    /// No checks: the http scope's parent.
    pub const NONE: PreparedAccess = PreparedAccess {
        rules: &[],
        satisfy_any: false,
        auth_basic: PreparedAuthBasic::Off,
        auth_basic_user_file: None,
        auth_delay_ms: 0,
        realip: PreparedRealIp {
            from: &[],
            header: PreparedRealIpHeader::XRealIp,
            recursive: false,
        },
    };
}

/// The realip module's settings, inheritance resolved. Off while `from`
/// is empty.
#[derive(Debug, Copy, Clone)]
pub struct PreparedRealIp {
    /// `set_real_ip_from`: the peers whose header is believed.
    pub from: &'static [crate::config::AccessAddr],
    pub header: PreparedRealIpHeader,
    /// `real_ip_recursive on`.
    pub recursive: bool,
}

#[derive(Debug, Copy, Clone)]
pub enum PreparedRealIpHeader {
    XRealIp,
    XForwardedFor,
    ProxyProtocol,
    /// A lowercased header name.
    Other(&'static [u8]),
}

/// `limit_except`: what a request whose method the block doesn't list
/// gets instead of the location's own settings. nginx swaps in the
/// block's whole location configuration, merged with the location's, and
/// the merge keeps neither the rewrite directives nor `try_files`. So the
/// location's rewrite program doesn't run (`MatchedLocation::limited`).
pub struct PreparedLimitExcept {
    /// The listed methods, as `config::LIMIT_EXCEPT_METHODS` bits.
    pub methods: u16,
    /// The content handler without `try_files`, and the static handler
    /// where the location answers with `return`. `None`: the location's
    /// own handler.
    pub handler: Option<PreparedHandler>,
    pub access: PreparedAccess,
}

#[derive(Debug, Copy, Clone)]
pub enum PreparedAuthBasic {
    Off,
    /// Pre-rendered realm bytes. Variables in the realm are rejected at
    /// parse time (see `config::parse_auth_basic_args`), so we don't carry
    /// a `RenderCtx`-aware `PreparedValuePart` list here.
    Realm(&'static [u8]),
}

pub(crate) const DEFAULT_KEEPALIVE_REQUESTS: u64 = 1_000;

pub(crate) const DEFAULT_KEEPALIVE_TIME_MS: u64 = 3_600_000;

#[derive(Debug, Copy, Clone)]
pub struct PreparedErrorPage {
    pub status: u16,
    pub action: PreparedErrorPageAction,
    pub target: &'static [PreparedValuePart],
}

pub enum PreparedHandler {
    Return(PreparedReturn),
    Root(PreparedRoot),
    Proxy(PreparedProxy),
}

/// Per-location rules for an upstream's response headers, behind one
/// pointer so the proxy plan stays small.
#[derive(Debug)]
pub struct ProxyResponseRules {
    /// `proxy_redirect` rules for `Location` / `Refresh`, tried in order;
    /// empty for `proxy_redirect off`.
    pub redirects: &'static [PreparedRedirect],
    /// Lowercased `proxy_hide_header` names beyond nginx's default list.
    pub hide: &'static [&'static [u8]],
    /// Default-hidden headers let through by `proxy_pass_header`, as
    /// `proxy::default_hidden_bit` bits.
    pub pass_mask: u16,
    /// The location's `error_page` list, for a 502/504 the proxy itself
    /// produces (nginx applies it without `proxy_intercept_errors`).
    pub error_pages: &'static [PreparedErrorPage],
    /// The location's `recursive_error_pages`, for those and for
    /// `proxy_intercept_errors`.
    pub recursive_error_pages: bool,
    /// `proxy_ignore_headers X-Accel-Redirect`: forward the response
    /// instead of following the header.
    pub ignore_accel_redirect: bool,
    /// `proxy_ignore_headers X-Accel-Limit-Rate`.
    pub ignore_accel_limit_rate: bool,
}

/// One prepared `proxy_redirect` rule.
#[derive(Debug)]
pub enum PreparedRedirect {
    /// Replace this prefix of the header value.
    Prefix {
        pattern: &'static [PreparedValuePart],
        replacement: &'static [PreparedValuePart],
    },
    /// On a match, the whole value becomes `replacement` (with `$1`…).
    Regex {
        regex: &'static regex::bytes::Regex,
        replacement: &'static [PreparedValuePart],
    },
}

/// Resolved `proxy_pass` target for a prepared location. Always carries a
/// pointer to a `PreparedUpstream` — for `proxy_pass http://host:port`
/// direct forms, the prepare path synthesizes a single-peer upstream block
/// without keepalive so the LB and pool layers have one shape to dispatch
/// against.
#[derive(Debug, Copy, Clone)]
pub struct PreparedProxy {
    /// The upstream this proxy resolves through. Direct forms get a
    /// synthesized one-peer / no-keepalive block; named forms point at
    /// the http-scope `upstream {}` declaration.
    pub upstream: &'static PreparedUpstream,
    /// Bytes for the default `Host:` request header sent upstream. nginx's
    /// default is the upstream URL's authority — the literal host:port
    /// for direct, or the upstream block name for upstream-ref. A
    /// `proxy_set_header Host …;` override fires in front of this default.
    pub host_header: &'static [u8],
    /// Inheritance-resolved `proxy_set_header` list. Empty == none configured.
    pub set_headers: &'static [PreparedProxySetHeader],
    /// Inheritance-resolved `proxy_pass_request_headers` (default `true`).
    pub pass_request_headers: bool,
    /// Inheritance-resolved `proxy_pass_request_body` (default `true`).
    pub pass_request_body: bool,
    /// Inheritance-resolved `proxy_set_body`: rendered per request and sent
    /// instead of the client's body.
    pub set_body: Option<&'static [PreparedValuePart]>,
    /// Inheritance-resolved `proxy_connect_timeout` (default 60s).
    pub connect_timeout_ms: u64,
    /// Inheritance-resolved `proxy_read_timeout` (default 60s).
    pub read_timeout_ms: u64,
    /// Inheritance-resolved `proxy_send_timeout` (default 60s).
    pub send_timeout_ms: u64,
    /// Inheritance-resolved `proxy_limit_rate` in bytes/sec; `0` is unlimited.
    pub limit_rate: u64,
    /// 0 = HTTP/1.0 (default), 1 = HTTP/1.1. Drives the upstream
    /// request-line version and gates pool eligibility (HTTP/1.0 always
    /// closes after the response).
    pub http_version: u8,
    /// `proxy_next_upstream` mask. Default `error timeout`.
    pub next_upstream: crate::config::ProxyNextUpstream,
    /// `proxy_next_upstream_tries` cap. `0` = unbounded (cap by peer count).
    pub next_upstream_tries: u32,
    /// `proxy_next_upstream_timeout` overall budget in milliseconds.
    /// `0` = unbounded.
    pub next_upstream_timeout_ms: u64,
    /// `proxy_intercept_errors on;` flag. When true, an upstream
    /// status that matches a configured `error_page` rule turns into the
    /// rule's target instead of being forwarded.
    pub intercept_errors: bool,
    /// Effective `ignore_invalid_headers` policy from the matched server.
    /// When true, headers with non-fatal invalid names are dropped before
    /// forwarding upstream.
    pub ignore_invalid_headers: bool,
    /// Effective `underscores_in_headers` policy from the matched server.
    pub underscores_in_headers: bool,
    /// Location-prefix bytes used by path rewriting. Empty when no
    /// rewriting is configured. When non-empty, the upstream URI is
    /// `request_path + (client_path - location_prefix) + ?args`.
    pub location_prefix: &'static [u8],
    /// `proxy_pass http://up/path;` URI part. Empty when no path rewriting.
    pub request_path: &'static [u8],
    /// What to do with the upstream's response headers.
    pub response: &'static ProxyResponseRules,
}

/// One prepared `proxy_set_header NAME VALUE;` entry. Name is a static
/// byte slice (header tokens, no rendering); value is a prepared value
/// expression rendered per request from the `RenderCtx`.
#[derive(Debug, Copy, Clone)]
pub struct PreparedProxySetHeader {
    pub name: &'static [u8],
    pub value: &'static [PreparedValuePart],
}

/// Inheritance-resolved snapshot of all proxy_* directives. Built once
/// per location at prepare time and folded into `PreparedProxy`. Pulling
/// this into a struct keeps the `build_handler` / `build_proxy` argument
/// list manageable.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ProxyEffective {
    pub set_headers: &'static [PreparedProxySetHeader],
    pub pass_request_headers: bool,
    pub pass_request_body: bool,
    pub set_body: Option<&'static [PreparedValuePart]>,
    pub ignore_accel_redirect: bool,
    pub ignore_accel_limit_rate: bool,
    pub connect_timeout_ms: u64,
    pub read_timeout_ms: u64,
    pub send_timeout_ms: u64,
    /// `proxy_limit_rate` in bytes/sec; `0` means unlimited.
    pub limit_rate: u64,
    /// 0 = HTTP/1.0, 1 = HTTP/1.1. Matches nginx's default of 1.0.
    pub http_version: u8,
    pub next_upstream: crate::config::ProxyNextUpstream,
    pub next_upstream_tries: u32,
    pub next_upstream_timeout_ms: u64,
    pub intercept_errors: bool,
    pub ignore_invalid_headers: bool,
    pub underscores_in_headers: bool,
    /// The nearest scope's `proxy_redirect` lines; `None` = nginx's
    /// implicit `proxy_redirect default`.
    pub redirect: Option<&'static crate::config::ProxyRedirect>,
    /// The nearest scope's `proxy_hide_header` / `proxy_pass_header` names
    /// (each list inherits on its own, as in nginx).
    pub hide_headers: Option<&'static [String]>,
    pub pass_headers: Option<&'static [String]>,
    /// The location's `error_page` list (for the proxy's own 502/504).
    pub error_pages: &'static [PreparedErrorPage],
    pub recursive_error_pages: bool,
}

impl ProxyEffective {
    /// Defaults match nginx (`60s` for all three timeouts; `on` for both
    /// pass-through toggles) and a no-op set-header list.
    pub fn defaults() -> Self {
        Self {
            set_headers: &[],
            pass_request_headers: true,
            pass_request_body: true,
            set_body: None,
            ignore_accel_redirect: false,
            ignore_accel_limit_rate: false,
            connect_timeout_ms: 60_000,
            read_timeout_ms: 60_000,
            send_timeout_ms: 60_000,
            limit_rate: 0,
            http_version: 0,
            next_upstream: crate::config::ProxyNextUpstream::DEFAULT,
            next_upstream_tries: 0,
            next_upstream_timeout_ms: 0,
            intercept_errors: false,
            ignore_invalid_headers: true,
            underscores_in_headers: false,
            redirect: None,
            hide_headers: None,
            pass_headers: None,
            error_pages: &[],
            recursive_error_pages: false,
        }
    }
}

#[derive(Debug)]
pub struct PreparedUpstream {
    /// Display name. For named upstream blocks: the block name.
    /// For synthesized direct-form blocks: the literal host:port.
    /// `$upstream_addr` shows it when no peer could be tried.
    pub name: &'static [u8],
    pub peers: &'static [PreparedPeer],
    /// Max idle pool slots per worker (`keepalive N;`). `None` means no
    /// pool — every attempt opens a fresh socket.
    pub keepalive_max_idle: Option<u32>,
    /// `keepalive_requests N;` — close after N requests on a pooled conn.
    /// Default 1000 to match nginx.
    pub keepalive_requests: u64,
    /// `keepalive_timeout T;` — drop idle conns older than this.
    /// Default 60s to match nginx.
    pub keepalive_idle_timeout_ms: u64,
    /// `keepalive_time T;` — hard lifetime cap. Default 1h.
    pub keepalive_max_lifetime_ms: u64,
    /// LB algorithm. M43 added `least_conn`; default is smoothed weighted RR.
    pub lb: crate::config::LbAlgorithm,
}

/// Per-server entry inside an `upstream {}` block. The runtime consumes the
/// full peer surface for weighted/least-conn selection, backup eligibility,
/// and `max_fails` / `fail_timeout` liveness tracking.
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct PreparedPeer {
    pub addr: SocketAddr,
    pub display: &'static [u8],
    pub weight: u32,
    pub max_fails: u32,
    pub fail_timeout_ms: u64,
    pub down: bool,
    pub backup: bool,
}

/// Static-file handler state after M6 promotion: `root` plus the
/// resolved `index` list and the optional `try_files` program. Matches
/// nginx's post-merge (clcf->root + ngx_http_index_loc_conf_t::indices +
/// ngx_http_try_files_loc_conf_t::try_files) split.
/// Inheritance-resolved `limit_rate` / `limit_rate_after`, rendered and
/// parsed per request (they may hold variables). `None`: not set.
#[derive(Debug, Clone, Copy, Default)]
pub struct PreparedLimitRate {
    pub rate: Option<&'static [PreparedValuePart]>,
    pub after: Option<&'static [PreparedValuePart]>,
}

impl PreparedLimitRate {
    /// For a location: `None` (the common case, one word to copy per
    /// request) unless something is set.
    pub(crate) fn for_location(self) -> Option<&'static PreparedLimitRate> {
        (self.rate.is_some() || self.after.is_some()).then(|| &*Box::leak(Box::new(self)))
    }

    /// This scope's own directives over the parent's.
    pub(crate) fn inherit(
        rate: Option<Vec<ValuePart>>,
        after: Option<Vec<ValuePart>>,
        parent: PreparedLimitRate,
    ) -> PreparedLimitRate {
        PreparedLimitRate {
            rate: rate.map(prepare_value_parts).or(parent.rate),
            after: after.map(prepare_value_parts).or(parent.after),
        }
    }
}

pub struct PreparedRoot {
    pub root: &'static Path,
    /// Open dirfd for the canonicalized root, or -1 if it didn't exist at
    /// startup (read it through `fd()`). Used as the `dirfd` argument of
    /// `openat2(RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS)` so the kernel
    /// enforces symlink-escape containment in a single syscall — replaces
    /// the old stat + canonicalize + `starts_with` guard. Opened at prepare
    /// time if possible, else on first use; leaked for process lifetime
    /// (closed at exit only).
    pub root_fd: std::os::unix::io::RawFd,
    /// Effective `disable_symlinks` (`fs_resolve::open_and_stat`).
    pub symlinks: PreparedSymlinks,
    /// `root` appends the whole URI.
    /// Prefix/exact `alias` strips the matched location prefix before
    /// joining. Regex-location `alias` uses nginx's `add_uri_to_alias`
    /// behavior (handled in `fs_resolve`).
    pub path_mapping: PreparedPathMapping,
    /// Already inheritance-resolved: server-scope if no location list,
    /// else built-in default `index.html`.
    pub index: &'static [PreparedIndexEntry],
    /// Effective `autoindex on|off;` for this location.
    pub autoindex: bool,
    /// Effective `autoindex_exact_size on|off;` for this location.
    pub autoindex_exact_size: bool,
    /// Effective `autoindex_localtime on|off;` for this location.
    pub autoindex_localtime: bool,
    /// Effective `autoindex_format ...;` for this location.
    pub autoindex_format: AutoindexFormat,
    pub try_files: Option<&'static PreparedTryFiles>,
}

/// Where a location's URIs map on disk, whatever its handler: its `root`
/// or `alias` (else `html`), for `$request_filename` / `$document_root`.
#[derive(Debug)]
pub struct DocRoot {
    pub path: &'static Path,
    pub mapping: PreparedPathMapping,
    /// The location's `disable_symlinks`, for `if -f` and the like.
    pub symlinks: PreparedSymlinks,
}

/// Effective `disable_symlinks` of a location.
#[derive(Debug, Clone, Copy)]
pub struct PreparedSymlinks {
    pub mode: crate::config::SymlinkMode,
    pub from: PreparedSymlinkFrom,
}

#[derive(Debug, Clone, Copy)]
pub enum PreparedSymlinkFrom {
    None,
    /// `from=$document_root`: the location's root (or alias) path.
    DocumentRoot,
    Path(&'static [u8]),
}

impl PreparedSymlinks {
    pub(crate) fn new(config: Option<crate::config::DisableSymlinks>) -> Self {
        use std::os::unix::ffi::OsStrExt;
        let Some(config) = config else {
            return PreparedSymlinks {
                mode: crate::config::SymlinkMode::Off,
                from: PreparedSymlinkFrom::None,
            };
        };
        let from = match config.from {
            None => PreparedSymlinkFrom::None,
            Some(crate::config::SymlinkFrom::DocumentRoot) => PreparedSymlinkFrom::DocumentRoot,
            Some(crate::config::SymlinkFrom::Path(p)) => {
                PreparedSymlinkFrom::Path(Box::leak(p.as_os_str().as_bytes().into()))
            }
        };
        PreparedSymlinks {
            mode: config.mode,
            from,
        }
    }
}

thread_local! {
    /// Roots this worker opened lazily, by `PreparedRoot` address. Each
    /// worker has its own fd table (`unshare(CLONE_FILES)`), so an fd
    /// opened after startup is only valid in the worker that opened it.
    static LAZY_ROOT_FDS: std::cell::RefCell<Vec<(usize, std::os::unix::io::RawFd)>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

impl PreparedRoot {
    /// The root's dirfd. Opened at startup when the path existed (before
    /// the workers split their fd tables, so it's valid everywhere);
    /// otherwise opened on first use in each worker and kept there, so it
    /// works once the directory appears, as with nginx. Until then this is
    /// the open error (a 404 for ENOENT).
    pub fn fd(&self) -> std::io::Result<std::os::unix::io::RawFd> {
        if self.root_fd != -1 {
            return Ok(self.root_fd);
        }
        self.lazy_fd()
    }

    #[cold]
    fn lazy_fd(&self) -> std::io::Result<std::os::unix::io::RawFd> {
        let key = self as *const PreparedRoot as usize;
        LAZY_ROOT_FDS.with(|fds| {
            if let Some(&(_, fd)) = fds.borrow().iter().find(|(k, _)| *k == key) {
                return Ok(fd);
            }
            let fd = open_root(self.root)?;
            fds.borrow_mut().push((key, fd));
            Ok(fd)
        })
    }
}

/// Open a `root` / `alias` path as the `openat2` anchor. Canonicalized
/// first so the anchor is the resolved inode: symlinks in the configured
/// path can't retarget the "beneath" set later. No `O_DIRECTORY` — nginx
/// allows `alias /some/file;` at exact locations, so the anchor can be a
/// regular file (the resolver `dup`s it back out when the URL-mapped rel
/// is empty).
pub(crate) fn open_root(path: &Path) -> std::io::Result<std::os::unix::io::RawFd> {
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::IntoRawFd;
    let canonical = path.canonicalize()?;
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC)
        .open(canonical)?;
    Ok(f.into_raw_fd())
}

#[derive(Debug, Copy, Clone)]
pub enum PreparedPathMapping {
    Root,
    AliasPrefix { prefix: &'static [u8] },
    AliasRegex,
}

/// One prepared `index` entry. Uses the same ValuePart machinery as
/// `return` and `add_header`, so rendering is shared across directives.
#[derive(Debug, Copy, Clone)]
pub struct PreparedIndexEntry {
    pub parts: &'static [PreparedValuePart],
}

/// Compiled `try_files`. Probes are executed in order; on a hit the URL
/// is rewritten to the candidate and the static resolver runs on it. On
/// full miss the fallback fires.
pub struct PreparedTryFiles {
    pub probes: Vec<PreparedProbe>,
    pub fallback: PreparedFallback,
}

#[derive(Debug)]
pub enum PreparedProbe {
    /// `$uri` — test file at `<root><uri>`; on match, URL stays as-is.
    Uri,
    /// `$uri/` — test directory at `<root><uri>`; on match, URL gains a
    /// trailing `/` (required for the subsequent index pass).
    UriSlash,
    /// Literal path, tested as a file. URL rewrites to this on match.
    Literal(&'static [u8]),
    /// Literal ending in `/`, tested as a directory.
    LiteralSlash(&'static [u8]),
    /// A value with variables, rendered per request; `dir`: tested as a
    /// directory.
    Template {
        parts: &'static [PreparedValuePart],
        dir: bool,
    },
}

pub enum PreparedFallback {
    /// `=NNN` — pre-rendered response for GET + HEAD. Matches the
    /// prebuilt-response pattern the rest of worker uses for error pages.
    Status(Prebuilt),
    /// URI to internally redirect to. Re-enters location matching with
    /// the hop budget in `phase::process`.
    Uri(&'static [u8]),
    /// A URI with variables, rendered when the probes miss.
    UriTemplate(&'static [PreparedValuePart]),
    /// Internal-only named location target. Preserves the current `$uri`
    /// and `$args`; only the location context changes.
    Named(&'static [u8]),
}

pub struct PreparedLocation {
    pub pattern: &'static [u8],
    pub handler: PreparedHandler,
    /// nginx core `auto_redirect`: a prefix/exact location ending in `/`
    /// whose content handler is an upstream pass redirects `/foo` to
    /// `/foo/` before rewrite/content phases run.
    pub auto_redirect: bool,
    /// `^~` flag — when this prefix wins the longest-prefix scan, the
    /// regex pass is skipped entirely. Maps to nginx's `clcf->noregex`.
    /// Always `false` for exact locations (the bit is meaningless there).
    pub noregex: bool,
    pub rewrite_program: &'static [PreparedRewriteOp],
    /// Inheritance-resolved list: location's own if it had any, else the
    /// parent server's list, else empty. Empty → no injection cost on the
    /// hot path.
    pub add_headers: &'static [PreparedAddHeader],
    /// Inheritance-resolved `add_trailer` list. Same shape as add_headers;
    /// non-empty means the response is forced to chunked transfer-encoding
    /// so the trailers can be appended after the final chunk.
    pub add_trailers: &'static [PreparedAddHeader],
    /// Inheritance-resolved `error_page` list. Child list replaces parent
    /// when present; empty means "no interception rules".
    pub error_pages: &'static [PreparedErrorPage],
    /// Inheritance-resolved keepalive policy for this location.
    pub keepalive: PreparedKeepalive,
    /// Inheritance-resolved error-log sinks used for side-effect logging
    /// (`log_not_found` 404 entries).
    pub error_logs: &'static [PreparedErrorLog],
    /// Inheritance-resolved `log_not_found` policy.
    pub log_not_found: bool,
    /// Inheritance-resolved `recursive_error_pages`: an `error_page` taken
    /// here leaves the request free to take another one.
    pub recursive_error_pages: bool,
    /// `internal;`: an external request matching here gets 404.
    pub internal: bool,
    /// Pre-resolved `Server:` header value bytes for this location, derived
    /// from the effective `server_tokens` (location → server → http →
    /// default `On`). Static `return` responses bake these in at prepare;
    /// runtime paths read this directly so we never re-resolve per request.
    pub server_header: &'static [u8],
    /// Inheritance-resolved `access_log` sinks. Each entry's `file_index`
    /// points into `PreparedHttp::access_logs` so the per-worker fd table
    /// stays the same regardless of which scope produced the entry.
    pub access_logs: &'static [PreparedAccessLog],
    /// Effective access-phase settings for this location.
    pub access: PreparedAccess,
    pub limit_except: Option<&'static PreparedLimitExcept>,
    /// Effective `client_max_body_size` for this location in bytes.
    /// `None` means "unlimited"; `Some(0)` also disables the limit to
    /// mirror nginx's directive semantics.
    pub client_max_body_size: Option<u64>,
    /// Effective `client_body_in_file_only` for this location. `On` keeps
    /// the spilled body file after the request; `Clean` and `Off` unlink
    /// at end-of-request.
    pub client_body_in_file_only: crate::config::ClientBodyInFileOnly,
    /// The location's or its server's own `client_body_temp_path`; `None`
    /// uses `PreparedHttp::body_temp`.
    pub body_temp: Option<&'static BodyTempDir>,
    /// `$request_filename` / `$document_root` (`RewriteState::doc_root`).
    pub doc_root: &'static DocRoot,
    /// Effective `sendfile` (location → server → http, default off). When
    /// on, file bodies are sent zero-copy on plain TCP connections.
    pub sendfile: bool,
    pub limit_rate: Option<&'static PreparedLimitRate>,
    /// Effective `post_action` target, if any. A leading `/` is an
    /// internal URI redirect; a leading `@` is a named-location jump.
    pub post_action: Option<&'static [u8]>,
    /// Effective `expires` directive for this location.
    pub expires: PreparedExpires,
    /// Effective `chunked_transfer_encoding` for this location. Inherits
    /// from server, falling back to nginx's default `on`. The trailer
    /// filter consults this before injecting `add_trailer` lines: when
    /// chunked is off there is no chunked frame to append trailers to,
    /// so they are silently dropped (matching nginx's chunked filter).
    pub chunked_transfer_encoding: bool,
}

/// A regex-mode location after prepare. The compiled
/// `regex::bytes::Regex` is what matches at request time. Bytes-mode
/// (rather than `regex::Regex`) is the right
/// engine here: `uri::normalize` returns `Vec<u8>` because percent-decoding
/// can produce arbitrary octets — going through `&str` would silently
/// skip every regex location for any path containing non-UTF-8 bytes.
/// nginx matches PCRE against `r->uri.data` as raw bytes for the same
/// reason.
pub struct PreparedRegexLocation {
    pub regex: regex::bytes::Regex,
    pub handler: PreparedHandler,
    pub rewrite_program: &'static [PreparedRewriteOp],
    pub add_headers: &'static [PreparedAddHeader],
    pub add_trailers: &'static [PreparedAddHeader],
    pub error_pages: &'static [PreparedErrorPage],
    pub keepalive: PreparedKeepalive,
    pub error_logs: &'static [PreparedErrorLog],
    pub log_not_found: bool,
    pub recursive_error_pages: bool,
    pub internal: bool,
    pub server_header: &'static [u8],
    pub access_logs: &'static [PreparedAccessLog],
    pub access: PreparedAccess,
    pub limit_except: Option<&'static PreparedLimitExcept>,
    pub client_max_body_size: Option<u64>,
    pub client_body_in_file_only: crate::config::ClientBodyInFileOnly,
    pub body_temp: Option<&'static BodyTempDir>,
    pub doc_root: &'static DocRoot,
    /// Effective `sendfile` (location → server → http, default off). When
    /// on, file bodies are sent zero-copy on plain TCP connections.
    pub sendfile: bool,
    pub limit_rate: Option<&'static PreparedLimitRate>,
    pub post_action: Option<&'static [u8]>,
    pub expires: PreparedExpires,
    pub chunked_transfer_encoding: bool,
}

/// Common view onto a matched location. The matcher hands one of these to
/// `run_location_handler` so the caller doesn't need to care whether the
/// hit came from `exact_locations`, `prefix_locations`, or
/// `regex_locations`. Keeps the dispatch site straight-line.
#[derive(Copy, Clone)]
pub struct MatchedLocation<'a> {
    pub handler: &'a PreparedHandler,
    pub auto_redirect_to: Option<&'a [u8]>,
    pub rewrite_program: &'a [PreparedRewriteOp],
    pub add_headers: &'a [PreparedAddHeader],
    pub add_trailers: &'a [PreparedAddHeader],
    pub error_pages: &'a [PreparedErrorPage],
    pub keepalive: PreparedKeepalive,
    pub error_logs: &'static [PreparedErrorLog],
    pub log_not_found: bool,
    pub recursive_error_pages: bool,
    pub internal: bool,
    pub server_header: &'static [u8],
    pub access_logs: &'static [PreparedAccessLog],
    pub access: &'a PreparedAccess,
    pub limit_except: Option<&'static PreparedLimitExcept>,
    pub client_max_body_size: Option<u64>,
    pub client_body_in_file_only: crate::config::ClientBodyInFileOnly,
    pub body_temp: Option<&'static BodyTempDir>,
    pub doc_root: &'static DocRoot,
    /// Effective `sendfile` (location → server → http, default off). When
    /// on, file bodies are sent zero-copy on plain TCP connections.
    pub sendfile: bool,
    pub limit_rate: Option<&'static PreparedLimitRate>,
    pub post_action: Option<&'static [u8]>,
    pub expires: PreparedExpires,
    pub chunked_transfer_encoding: bool,
}

impl<'a> MatchedLocation<'a> {
    pub fn from_prefix(loc: &'a PreparedLocation) -> Self {
        Self {
            handler: &loc.handler,
            auto_redirect_to: None,
            rewrite_program: loc.rewrite_program,
            add_headers: loc.add_headers,
            add_trailers: loc.add_trailers,
            error_pages: loc.error_pages,
            keepalive: loc.keepalive,
            error_logs: loc.error_logs,
            log_not_found: loc.log_not_found,
            recursive_error_pages: loc.recursive_error_pages,
            internal: loc.internal,
            server_header: loc.server_header,
            access_logs: loc.access_logs,
            access: &loc.access,
            limit_except: loc.limit_except,
            client_max_body_size: loc.client_max_body_size,
            client_body_in_file_only: loc.client_body_in_file_only,
            body_temp: loc.body_temp,
            doc_root: loc.doc_root,
            sendfile: loc.sendfile,
            limit_rate: loc.limit_rate,
            post_action: loc.post_action,
            expires: loc.expires,
            chunked_transfer_encoding: loc.chunked_transfer_encoding,
        }
    }

    /// The location as a request sees it whose method its `limit_except`
    /// doesn't list.
    pub fn limited(self, le: &'a PreparedLimitExcept) -> Self {
        Self {
            handler: le.handler.as_ref().unwrap_or(self.handler),
            rewrite_program: &[],
            access: &le.access,
            limit_except: None,
            ..self
        }
    }

    pub fn from_auto_redirect(loc: &'a PreparedLocation) -> Self {
        let mut matched = Self::from_prefix(loc);
        matched.auto_redirect_to = Some(loc.pattern);
        matched
    }

    pub fn from_regex(loc: &'a PreparedRegexLocation) -> Self {
        Self {
            handler: &loc.handler,
            auto_redirect_to: None,
            rewrite_program: loc.rewrite_program,
            add_headers: loc.add_headers,
            add_trailers: loc.add_trailers,
            error_pages: loc.error_pages,
            keepalive: loc.keepalive,
            error_logs: loc.error_logs,
            log_not_found: loc.log_not_found,
            recursive_error_pages: loc.recursive_error_pages,
            internal: loc.internal,
            server_header: loc.server_header,
            access_logs: loc.access_logs,
            access: &loc.access,
            limit_except: loc.limit_except,
            client_max_body_size: loc.client_max_body_size,
            client_body_in_file_only: loc.client_body_in_file_only,
            body_temp: loc.body_temp,
            doc_root: loc.doc_root,
            sendfile: loc.sendfile,
            limit_rate: loc.limit_rate,
            post_action: loc.post_action,
            expires: loc.expires,
            chunked_transfer_encoding: loc.chunked_transfer_encoding,
        }
    }
}

/// One compiled regex `server_name` plus the named-capture names declared
/// in its pattern. The regex itself matches against the lowercased Host
/// (case-insensitive flag on the Regex when `~*` was used); `capture_names`
/// is captured up front so the request-time path can look up which groups
/// to surface as `$name` variables without re-querying the engine.
pub struct PreparedRegexName {
    pub regex: regex::bytes::Regex,
    pub capture_names: Vec<&'static str>,
}

/// `client_header_timeout`, `client_body_timeout`, `send_timeout`,
/// resolved against nginx's 60 s defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreparedClientTimeouts {
    pub header: Duration,
    pub body: Duration,
    pub send: Duration,
}

impl PreparedHttp {
    /// Client connections one worker may hold.
    pub(crate) fn client_slots(&self) -> usize {
        self.worker_connections
            .saturating_sub(self.listens.len())
            .max(1)
    }
}

impl PreparedClientTimeouts {
    pub(crate) fn resolve(t: crate::config::ClientTimeouts) -> Self {
        const DEFAULT_MS: u64 = 60_000;
        PreparedClientTimeouts {
            header: Duration::from_millis(t.header_ms.unwrap_or(DEFAULT_MS)),
            body: Duration::from_millis(t.body_ms.unwrap_or(DEFAULT_MS)),
            send: Duration::from_millis(t.send_ms.unwrap_or(DEFAULT_MS)),
        }
    }
}

/// One `server {}` block after preparation. `exact_locations` and
/// `prefix_locations` are pre-split: exact-match candidates are scanned
/// first and return immediately on a hit; prefix candidates are sorted by
/// descending pattern length so the first-hit is the longest match.
/// `regex_locations` are kept in **declaration order** — nginx tries them
/// linearly, first match wins (ngx_http_core_module.c:1454). Named
/// locations are internal-only and live in their own list so external URI
/// matching never sees them.
///
/// Server-name matching tables (`exact_names`, `wildcard_leading`,
/// `wildcard_trailing`, `regex_names`, `matches_empty`) live on each
/// server; cross-server selection happens in `phase::find_config` which
/// walks the table priorities in nginx order.
pub struct PreparedServer {
    /// The server's `root` (else `html`), for `$request_filename` in its
    /// rewrite phase.
    pub doc_root: &'static DocRoot,
    /// Client-side timeouts. The worker uses the listen's default server's
    /// values for the whole connection (see `handle`).
    pub timeouts: PreparedClientTimeouts,
    /// Lowercased exact-match names (e.g. `localhost`,
    /// `www.example.com`). HostCheck compares byte-for-byte.
    pub exact_names: Vec<&'static [u8]>,
    /// `*.example.com` form, stored as the suffix `example.com`.
    /// Matches when the host equals the suffix or ends with `.suffix`.
    pub wildcard_leading: Vec<&'static [u8]>,
    /// `mail.example.*` form, stored as the head `mail.example`. Matches
    /// when the host equals the head or starts with `head.`.
    pub wildcard_trailing: Vec<&'static [u8]>,
    /// Regex `~^pattern$` server names. Tried in declaration order across
    /// servers (first match wins); the engine's `case_insensitive` flag
    /// captures `~*`.
    pub regex_names: Vec<PreparedRegexName>,
    /// `server_name "";` — selected when the request has no Host header.
    pub matches_empty: bool,
    /// First `server_name` of this block as written, or empty. Rendered
    /// by `$server_name`. For `~^...` it includes the `~` prefix; for
    /// `*.foo` it includes the `*`.
    pub primary_server_name: &'static [u8],
    /// Listening port declared on this `server {}` block. Rendered by
    /// `$server_port`.
    pub listen_port: u16,
    pub exact_locations: Vec<PreparedLocation>,
    pub prefix_locations: Vec<PreparedLocation>,
    pub regex_locations: Vec<PreparedRegexLocation>,
    pub named_locations: Vec<PreparedLocation>,
    /// Server-scope `return STATUS [body]`. Fires when no explicit location
    /// matches, instead of the default 404. Inherits the server-level
    /// `add_header` list so `add_header X-Foo $uri;` at server scope still
    /// annotates the response.
    pub server_default: Option<PreparedLocation>,
    /// Server-scope logging defaults used for "no location matched" 404s.
    pub error_logs: &'static [PreparedErrorLog],
    pub log_not_found: bool,
    /// `merge_slashes` setting (default true). Read once per request in
    /// `phase::process` to pick the URI-normalizer variant.
    pub merge_slashes: bool,
    /// Resolved `Server:` header bytes for this server's effective
    /// `server_tokens` (server scope wins over http scope; default `On`).
    /// Used by phase.rs fallback paths that fire after server matching but
    /// before any location matched (e.g. server-default 500 / 405).
    pub server_header: &'static [u8],
    /// Inheritance-resolved `access_log` list for the server scope (used
    /// when no location matched). Falls back to the http-scope list.
    pub access_logs: &'static [PreparedAccessLog],
    /// Effective server-scope access-phase settings, for requests that
    /// match no location.
    pub access: PreparedAccess,
    /// Effective server-scope `underscores_in_headers`. When false,
    /// dynamic-name request-header lookups (`$http_*`, `$cookie_*`,
    /// `$sent_http_*` interpolation feed) skip headers whose names
    /// contain `_`, mirroring nginx.
    pub underscores_in_headers: bool,
    /// Effective server-scope `post_action`, used for server-default and
    /// no-location fallback paths.
    pub post_action: Option<&'static [u8]>,
    /// Server-scope rewrite program (`rewrite`, `set`, `if`, `return`,
    /// `break`), run before the location search. Empty: no cost.
    pub rewrite_program: &'static [PreparedRewriteOp],
    /// Server-scope `add_header` list, for responses made before any
    /// location (the rewrite program's `return`, refused requests).
    pub add_headers: &'static [PreparedAddHeader],
    /// Server-scope `error_page` list, for requests refused before any
    /// location (bad or missing Host, Transfer-Encoding, TRACE).
    pub error_pages: &'static [PreparedErrorPage],
}

/// One prepared listen address plus all `server {}` blocks bound to it.
/// Server-name matching and default-server fallback are evaluated inside
/// this bucket only.
pub struct PreparedListen {
    pub addr: SocketAddr,
    /// `addr`'s IP as `$server_addr` shows it (no brackets for IPv6); empty
    /// for a wildcard address, where each connection's own is used.
    pub addr_text: &'static [u8],
    pub servers: Vec<PreparedServer>,
    /// Index into `servers` for the default server on this listen
    /// address (first declared block today).
    pub default_server: usize,
    /// TLS acceptor for this listen address, or `None` for plain HTTP.
    /// Built once at startup from the per-server `ssl_certificate(_key)`
    /// directives via `tls_certs::build_server_config`. Wrapped in `Arc`
    /// so a future SIGHUP reload can swap it without invalidating
    /// references handed to in-flight connections.
    pub tls: Option<Arc<crate::tls::TlsAcceptor>>,
    /// `listen … proxy_protocol` on any server of this address: every
    /// connection starts with a PROXY protocol header.
    pub proxy_protocol: bool,
    /// The listening socket's options.
    pub socket: ListenSocket,
}

/// A listening socket's `listen` options (`backlog=`, `rcvbuf=`, …), from
/// the one server of the address that sets them, as nginx.
#[derive(Debug, Clone, Copy)]
pub struct ListenSocket {
    /// nginx's default is 511; ruxen keeps 4096 for its benchmarks'
    /// connection bursts unless `backlog=` says otherwise.
    pub backlog: i32,
    pub rcvbuf: Option<usize>,
    pub sndbuf: Option<usize>,
    pub deferred: bool,
    pub fastopen: Option<u32>,
    pub keepalive: Option<crate::config::SoKeepalive>,
    /// `IPV6_V6ONLY` for an IPv6 address: on unless `ipv6only=off`, as
    /// nginx (a `[::]` listen doesn't take IPv4 clients).
    pub ipv6only: bool,
}

impl ListenSocket {
    pub(crate) fn from_listen(listen: Option<&crate::config::Listen>) -> Self {
        ListenSocket {
            backlog: listen
                .and_then(|l| l.backlog)
                .map_or(4096, |n| n.min(i32::MAX as u32) as i32),
            rcvbuf: listen.and_then(|l| l.rcvbuf).map(|n| n as usize),
            sndbuf: listen.and_then(|l| l.sndbuf).map(|n| n as usize),
            deferred: listen.is_some_and(|l| l.deferred),
            fastopen: listen.and_then(|l| l.fastopen),
            keepalive: listen.and_then(|l| l.so_keepalive),
            ipv6only: listen.and_then(|l| l.ipv6only).unwrap_or(true),
        }
    }
}

/// Top-level prepared state.
pub struct PreparedHttp {
    pub listens: Vec<PreparedListen>,
    /// Top-level `error_log` sinks, for worker-level lines (`accept()
    /// failed`, `worker_connections are not enough`); empty = stderr.
    pub error_logs: &'static [PreparedErrorLog],
    /// `worker_connections` (nginx's default 512): the most connections one
    /// worker holds. As in nginx, each listening socket uses one of them;
    /// see `client_slots`.
    pub worker_connections: usize,
    /// The largest request body any location accepts
    /// (`client_max_body_size`, default 1m; `0` = no limit): bodies are
    /// read before routing, so this bounds the read, and the matched
    /// location checks its own limit afterwards.
    pub max_request_body: u64,
    /// Where request bodies too large for memory go.
    pub body_temp: BodyTempDir,
    pub access_logs: &'static [PreparedAccessLog],
    pub split_clients: std::collections::HashMap<&'static str, PreparedSplitClients>,
    /// http-scope `map` programs, keyed by output variable name. Rendered
    /// on demand from `RenderCtx::Unknown` when no other provider claims
    /// the name.
    pub maps: std::collections::HashMap<&'static str, PreparedMap>,
    /// Shared error responses — same bytes regardless of which server block
    /// the request would have landed on. Keeping them on PreparedHttp (not
    /// PreparedServer) avoids one copy per server block.
    pub not_found: Prebuilt,
    pub bad_request: Prebuilt,
    pub not_implemented: Prebuilt,
    pub forbidden: Prebuilt,
    pub bad_gateway: Prebuilt,
    pub gateway_timeout: Prebuilt,
    /// A request whose upstream connection got no `worker_connections` slot.
    pub internal_error: Prebuilt,
    /// http-scope `upstream {}` blocks keyed by name. `proxy_pass http://NAME`
    /// resolves through this map at prepare time. M42 reads it on the hot
    /// path for round-robin selection.
    #[allow(dead_code)]
    pub upstreams: std::collections::HashMap<&'static str, &'static PreparedUpstream>,
    /// Directory of the main config file, for resolving relative paths that
    /// are only known per request (e.g. `auth_basic_user_file $var`).
    pub conf_prefix: Option<&'static Path>,
}

#[derive(Default)]
pub struct RuntimeState {
    shutting_down: AtomicBool,
    active_connections: AtomicUsize,
    connection_ids: AtomicU64,
    /// Bumped each time the process receives SIGHUP. nginx's reload model
    /// re-execs new workers and tells the old workers to gracefully shut
    /// down; we don't have separate worker generations, so we instead use
    /// this counter to nudge already-accepted connections out of their
    /// idle keepalive wait and prevent them from re-entering it after a
    /// reload, while leaving the listener loop free to keep accepting new
    /// connections.
    reload_gen: AtomicU64,
}

impl RuntimeState {
    pub fn begin_shutdown(&self) {
        self.shutting_down.store(true, Ordering::SeqCst);
    }

    pub fn is_shutting_down(&self) -> bool {
        self.shutting_down.load(Ordering::SeqCst)
    }

    pub(crate) fn connection_started(&self) {
        self.active_connections.fetch_add(1, Ordering::SeqCst);
    }

    pub(crate) fn connection_finished(&self) {
        self.active_connections.fetch_sub(1, Ordering::SeqCst);
    }

    pub(crate) fn active_connections(&self) -> usize {
        self.active_connections.load(Ordering::SeqCst)
    }

    pub(crate) fn next_connection_id(&self) -> u64 {
        self.connection_ids
            .fetch_add(1, Ordering::SeqCst)
            .wrapping_add(1)
    }

    pub fn bump_reload_gen(&self) {
        self.reload_gen.fetch_add(1, Ordering::SeqCst);
    }

    pub(crate) fn reload_gen(&self) -> u64 {
        self.reload_gen.load(Ordering::SeqCst)
    }
}
