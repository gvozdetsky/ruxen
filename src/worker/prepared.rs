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
        let full = crate::arena::leak(full.into_boxed_slice());
        let head = crate::arena::leak(head.into_boxed_slice());
        Prebuilt { full, head }
    }

    pub(crate) fn leak(status: u16, body: &str, server: &[u8]) -> Self {
        Self::from_built(
            http::build_response(status, body, server),
            http::build_head_response(status, body.len(), server),
        )
    }

    /// nginx's page for an error status it answers itself, as `text/html`
    /// (`http::build_error_response`); a plain `fallback` for a status
    /// without one.
    pub(crate) fn leak_error(status: u16, fallback: &str, server: &[u8]) -> Self {
        match (
            http::build_error_response(status, Method::Get, server),
            http::build_error_response(status, Method::Head, server),
        ) {
            (Some(full), Some(head)) => Self::from_built(full, head),
            _ => Self::leak(status, fallback, server),
        }
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
    Static(Prebuilt, ReturnTypes),
    /// Body contains at least one `$variable` reference. Rendered per
    /// request by walking `parts` and writing each literal chunk / variable
    /// value into a fresh `Vec<u8>`.
    Template {
        status: u16,
        parts: &'static [PreparedValuePart],
        types: ReturnTypes,
    },
}

/// The level's `types` / `default_type` for a `return` whose response is
/// built as `text/plain` (#691): nginx types it as any response, by the
/// URI's extension, else `default_type` (ngx_http_set_content_type).
/// `None` for a redirect, which keeps nginx's `text/html` page.
pub type ReturnTypes = Option<&'static PreparedTypes>;

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
    /// `set $args`: the request's arguments, as nginx's
    /// ngx_http_variable_set_args replaces `r->args` (#543).
    SetArgs(&'static [PreparedValuePart]),
    If {
        guard: PreparedGuard,
        body: &'static [PreparedRewriteOp],
        /// The block's anonymous location, as an index into
        /// `PreparedServer::if_locations` (#137); for a block of rewrite
        /// directives only, the enclosing block's, or `None` for the
        /// location itself.
        location: Option<u32>,
    },
    Rewrite {
        regex: &'static regex::bytes::Regex,
        replacement_uri: &'static [PreparedValuePart],
        replacement_args: Option<&'static [PreparedValuePart]>,
        flag: PreparedRewriteFlag,
        drop_args: bool,
    },
    /// The `return`, and whether `error_page` can take its response:
    /// not for one with text (other than a redirect URL), which nginx's
    /// `ngx_http_script_return_code` sends as it is (#362).
    Return(PreparedReturn, bool),
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
    /// `regex` in one `RegexSet` (see `PreparedServer::regex_location_set`).
    pub regex_set: Option<regex::bytes::RegexSet>,
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
    /// nginx's `r->valid_location`: starts true, cleared when a `break`
    /// (the `rewrite` flag, or the directive after a changed URI) keeps
    /// the request in a location whose URI it changed. Read by
    /// `proxy_pass` to decide whether to apply its configured URI prefix
    /// substitution (when false, the rewritten URI is forwarded as-is to
    /// upstream).
    pub(crate) valid_location: bool,
    /// nginx's `r->uri_changed`: a `rewrite` without a flag changed the
    /// URI, so the locations are searched again once the rewrite
    /// directives are done (ngx_http_core_post_rewrite_phase, #682).
    pub(crate) uri_changed: bool,
    /// nginx's `r->valid_unparsed_uri`: the URI is still the one the client
    /// sent, so `proxy_pass` without a URI part forwards the client's own
    /// request target (#541). Cleared by a `rewrite` of the URI and by an
    /// internal redirect.
    pub(crate) unparsed_uri: bool,
    /// `map` results already computed for this request, by map slot: nginx
    /// caches a variable's value in `r->variables` for the rest of the
    /// request, internal redirects included, unless the map is `volatile`.
    /// Filled while rendering, which only has `&self`.
    map_cache: std::cell::RefCell<Vec<(usize, Vec<u8>)>>,
    /// The chosen location's (or, in the server's rewrite phase, the
    /// server's) root, for `$request_filename` / `$document_root`.
    pub(crate) doc_root: Option<&'static DocRoot>,
    /// `$limit_req_status` (`limit_req::status`); 0 before limit_req ran.
    /// Once set, limit_req doesn't run again for the request, as nginx's
    /// `r->main->limit_req_status` (#94).
    pub(crate) limit_req_status: u8,
    /// `$limit_conn_status` (`limit_conn::status`), likewise (#95).
    pub(crate) limit_conn_status: u8,
    /// The anonymous location of the last `if` whose condition held in the
    /// location's rewrite program (#137): the request goes on with its
    /// configuration, as nginx's `r->loc_conf = code->loc_conf`.
    pub(crate) if_location: Option<u32>,
    /// An `if` whose condition held had a `proxy_pass`: nginx keeps that
    /// content handler (`r->content_handler`) when a later `if` sets none,
    /// with the later configuration, which may have no upstream.
    pub(crate) if_proxy: bool,
}

impl Default for RewriteState {
    fn default() -> Self {
        Self {
            user_vars: Vec::new(),
            numbered_captures: Vec::new(),
            valid_location: true,
            uri_changed: false,
            unparsed_uri: true,
            map_cache: std::cell::RefCell::new(Vec::new()),
            doc_root: None,
            limit_req_status: 0,
            limit_conn_status: 0,
            if_location: None,
            if_proxy: false,
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
        self.has_user_vars()
            || !self.map_cache.borrow().is_empty()
            || self.limit_req_status != 0
            || self.limit_conn_status != 0
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
    /// The file `prepare` opened, once per path as nginx's master does
    /// (`ngx_init_cycle`, `open_files`); each worker writes to a `dup` of it
    /// (#523). Closed with the configuration. `None` for `syslog:` and a
    /// path with variables.
    pub file: Option<&'static std::fs::File>,
    pub format: &'static [PreparedValuePart],
    pub escape: crate::config::LogEscape,
    /// The format uses `$upstream_http_*` / `$upstream_cookie_*`, so the
    /// upstream's header block has to be kept for the log line.
    pub reads_upstream_headers: bool,
    /// The format, condition or path uses `$document_root`,
    /// `$request_filename` or `$realpath_root`: the line needs the
    /// location's root even when the request kept no rewrite state (#363).
    pub reads_doc_root: bool,
    pub condition: Option<&'static [PreparedValuePart]>,
    pub file_index: usize,
    /// `access_log syslog:…`: lines go to this peer, not to `path`.
    pub syslog: Option<&'static PreparedSyslogPeer>,
    /// `buffer=` / `flush=` / `gzip`: lines collect in a per-worker buffer
    /// for this file (#151).
    pub buffer: Option<&'static PreparedLogBuffer>,
    /// The path has variables: rendered, opened and closed per line (#303).
    pub path_vars: Option<&'static [PreparedValuePart]>,
    /// For a path with variables, the `open_log_file_cache` of the scope
    /// whose list this is (#371): the files stay open between lines.
    pub open_cache: Option<&'static crate::config::OpenLogFileCache>,
}

/// A buffered access_log file, shared by every `access_log` with buffer
/// parameters for the same path, as nginx attaches the buffer to the file.
#[derive(Debug)]
pub struct PreparedLogBuffer {
    /// Index into the worker's buffers.
    pub slot: usize,
    pub size: usize,
    pub flush_ms: Option<u64>,
    pub gzip: Option<u32>,
    pub path: &'static Path,
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
    File(&'static PreparedErrorLogFile),
    Stderr,
    Syslog(&'static PreparedSyslogPeer),
}

/// An `error_log` file: opened once by `prepare` and kept with the
/// configuration, as nginx's master keeps `open_files` (#648). A thread
/// writes to a `dup` of it (`log::emit`).
#[derive(Debug)]
pub struct PreparedErrorLogFile {
    pub path: &'static Path,
    /// `None` for the `-e` file as the default log, opened on first use.
    pub file: Option<std::fs::File>,
    /// `LOG_REOPEN_GEN` when it was opened: after a SIGUSR1 since, a thread
    /// opens the path instead.
    pub opened_gen: u64,
}

impl PartialEq for PreparedErrorLogFile {
    fn eq(&self, other: &Self) -> bool {
        self.path == other.path
    }
}

impl Eq for PreparedErrorLogFile {}

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
    /// `auth_request`'s URI (#358); `None`: off.
    pub auth_request: Option<&'static [u8]>,
    /// `auth_request_set`: each variable and the value rendered in the
    /// subrequest's context. Inherited apart from the URI, as nginx's.
    pub auth_request_set: &'static [(&'static [u8], &'static [PreparedValuePart])],
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
        auth_request: None,
        auth_request_set: &[],
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

/// nginx's `keepalive_timeout` when none is set (#773).
pub(crate) const DEFAULT_KEEPALIVE_TIMEOUT_MS: u64 = 75_000;

#[derive(Debug, Copy, Clone)]
pub struct PreparedErrorPage {
    pub status: u16,
    pub action: PreparedErrorPageAction,
    pub target: &'static [PreparedValuePart],
}

pub enum PreparedHandler {
    /// The `return`, and whether `error_page` can take its response: not
    /// for one with text (other than a redirect URL), which nginx's
    /// `ngx_http_script_return_code` sends as it is (#372).
    Return(PreparedReturn, bool),
    Root(PreparedRoot<'static>),
    Proxy(PreparedProxy),
    /// `stub_status` (#96).
    StubStatus,
    /// `ruxen_metrics` (#481).
    Metrics,
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
    /// `proxy_pass_header Date`: the upstream's `Date` goes out as it is,
    /// and none when it sent none (#360).
    pub passes_date: bool,
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
    /// A `proxy_limit_rate` with variables, rendered once the upstream's
    /// header is in, as nginx's ngx_http_upstream_send_response does
    /// (`$upstream_http_*` included). `None` when it has none: the plan's
    /// `limit_rate` holds its value then.
    pub limit_rate: Option<&'static [PreparedValuePart]>,
    /// `proxy_cookie_domain` / `proxy_cookie_path`; `None` when neither
    /// has a rule.
    pub cookies: Option<&'static PreparedCookieRules>,
}

/// A location's `proxy_cookie_domain` and `proxy_cookie_path` rules, for
/// the `Domain` and `Path` of the upstream's `Set-Cookie`. A `Prefix` rule
/// in `domains` matches the whole domain, caseless, after a leading dot.
#[derive(Debug)]
pub struct PreparedCookieRules {
    pub domains: &'static [PreparedRedirect],
    pub paths: &'static [PreparedRedirect],
    /// `proxy_cookie_flags`, the first whose cookie matches applies.
    pub flags: &'static [PreparedCookieFlags],
}

/// One `proxy_cookie_flags` line: which cookie, and its flags, rendered
/// per response.
#[derive(Debug)]
pub struct PreparedCookieFlags {
    pub cookie: PreparedCookieName,
    pub flags: &'static [&'static [PreparedValuePart]],
}

#[derive(Debug)]
pub enum PreparedCookieName {
    /// Compared with the cookie's name, caseless.
    Name(&'static [PreparedValuePart]),
    /// Caseless.
    Regex(&'static regex::bytes::Regex),
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
    /// Inheritance-resolved `proxy_limit_rate` in bytes/sec; `0` is
    /// unlimited, and so is one with variables here: it is read when the
    /// upstream's header is in (`ProxyResponseRules::limit_rate`).
    pub limit_rate: u64,
    /// 0 = HTTP/1.0, 1 = HTTP/1.1 (the default since nginx 1.29.7).
    /// Drives the upstream request-line version and gates pool
    /// eligibility (HTTP/1.0 always closes after the response).
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
    /// `proxy_force_ranges on;` (#370): the range filter may cut the
    /// response even when the upstream doesn't say it takes ranges.
    pub force_ranges: bool,
    /// `proxy_ignore_client_abort`: keep the upstream exchange when the
    /// client goes away (#136).
    pub ignore_client_abort: bool,
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
    /// What to do with the upstream's response headers. `build_proxy`
    /// leaks one per location, so its address also names the location
    /// (`pool_tag`).
    pub response: &'static ProxyResponseRules,
    /// Inheritance-resolved `proxy_method`: rendered per request and sent
    /// instead of the client's request method.
    pub proxy_method: Option<&'static [PreparedValuePart]>,
    /// `proxy_cache` (#233); `None` without one, or with `proxy_cache off`.
    pub cache: Option<&'static PreparedProxyCache>,
    /// `proxy_pass` with variables (#100): the URL, rendered and parsed per
    /// request. `upstream` is then a placeholder with one peer that the
    /// request's own address replaces, and `host_header` is unused.
    pub url: Option<&'static [PreparedValuePart]>,
    /// Inheritance-resolved `proxy_bind`; `None` when unset or `off`.
    pub bind: Option<&'static PreparedBind>,
    /// `resolver` (#133): turns a host name in `url` into addresses.
    pub resolver: Option<&'static crate::resolver::Resolver>,
    pub resolver_timeout_ms: u64,
    /// `proxy_pass https://` (#116); for a URL with variables, always
    /// set, and used when the rendered URL says `https://`.
    pub tls: Option<&'static crate::upstream_tls::PreparedUpstreamTls>,
}

/// A location's resolved `proxy_cache*` directives (#233).
pub struct PreparedProxyCache {
    pub zone: PreparedCacheZone,
    /// `proxy_cache_key`; `None`: the upstream URL, nginx's default key.
    pub key: Option<&'static [PreparedValuePart]>,
    pub valid: &'static [crate::config::CacheValid],
    pub methods_post: bool,
    pub min_uses: u32,
    pub bypass: &'static [&'static [PreparedValuePart]],
    pub no_cache: &'static [&'static [PreparedValuePart]],
    pub convert_head: bool,
    pub revalidate: bool,
    pub use_stale: crate::config::UseStale,
    pub background_update: bool,
    pub lock: bool,
    pub lock_timeout_ms: u64,
    pub lock_age_ms: u64,
    pub ignore: crate::proxy_cache::Ignore,
    /// `proxy_cache_max_range_offset`; `None` is no limit.
    pub max_range_offset: Option<u64>,
}

impl std::fmt::Debug for PreparedProxyCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedProxyCache").finish_non_exhaustive()
    }
}

/// The zone of `proxy_cache name`, or the zones a variable may name.
pub enum PreparedCacheZone {
    Zone(&'static crate::proxy_cache::CacheZone),
    Var(
        &'static [PreparedValuePart],
        &'static [&'static crate::proxy_cache::CacheZone],
    ),
}

impl PreparedProxy {
    /// The location a pooled connection of a `keepalive … local` upstream
    /// is kept for: nginx's cache item `tag`, the location's
    /// `ngx_http_upstream_conf_t` (ngx_http_upstream_keepalive_module.c).
    /// 0 when the pool is shared by every location.
    #[inline]
    pub fn pool_tag(&self, upstream: &PreparedUpstream) -> usize {
        if upstream.keepalive_local {
            std::ptr::from_ref(self.response) as usize
        } else {
            0
        }
    }
}

impl PreparedProxyCache {
    /// ngx_http_file_cache_valid: seconds a response with `status` stays
    /// fresh by `proxy_cache_valid`, 0 for not at all.
    pub fn valid_for(&self, status: u16) -> u64 {
        self.valid
            .iter()
            .find(|v| v.status == 0 || v.status == status)
            .map_or(0, |v| v.secs)
    }
}

/// `proxy_bind` (#135): the local address of upstream connections.
#[derive(Debug)]
pub struct PreparedBind {
    /// A literal address, parsed once; otherwise `value` is rendered per
    /// request.
    pub addr: Option<SocketAddr>,
    pub value: &'static [PreparedValuePart],
    pub transparent: bool,
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
    /// `proxy_limit_rate`, a size that may hold variables; `None`
    /// means unlimited.
    pub limit_rate: Option<&'static [PreparedValuePart]>,
    /// 0 = HTTP/1.0, 1 = HTTP/1.1. Matches nginx's default of 1.1 (1.29.7).
    pub http_version: u8,
    pub next_upstream: crate::config::ProxyNextUpstream,
    pub next_upstream_tries: u32,
    pub next_upstream_timeout_ms: u64,
    pub intercept_errors: bool,
    pub force_ranges: bool,
    /// `proxy_ignore_client_abort` (#136).
    pub ignore_client_abort: bool,
    pub ignore_invalid_headers: bool,
    pub underscores_in_headers: bool,
    /// The nearest scope's `proxy_redirect` lines; `None` = nginx's
    /// implicit `proxy_redirect default`.
    pub redirect: Option<&'static crate::config::ProxyRedirect>,
    /// The nearest scope's `proxy_cookie_domain` / `proxy_cookie_path`.
    pub cookie_domain: Option<&'static crate::config::ProxyRedirect>,
    pub cookie_path: Option<&'static crate::config::ProxyRedirect>,
    pub cookie_flags: Option<&'static [crate::config::CookieFlagsRule]>,
    /// The nearest scope's `proxy_hide_header` / `proxy_pass_header` names
    /// (each list inherits on its own, as in nginx).
    pub hide_headers: Option<&'static [String]>,
    pub pass_headers: Option<&'static [String]>,
    /// `proxy_bind`; `None` when unset or `off`.
    pub bind: Option<&'static PreparedBind>,
    /// `resolver` (#133) and `resolver_timeout`.
    pub resolver: Option<&'static crate::resolver::Resolver>,
    pub resolver_timeout_ms: u64,
    /// The location's `error_page` list (for the proxy's own 502/504).
    pub error_pages: &'static [PreparedErrorPage],
    pub recursive_error_pages: bool,
    pub proxy_method: Option<&'static [PreparedValuePart]>,
    /// The nearest scopes' `proxy_cache*` directives, and the cache fields
    /// of `proxy_ignore_headers`.
    pub cache: &'static crate::config::ProxyCacheConf,
    pub cache_ignore: crate::proxy_cache::Ignore,
    /// `proxy_ssl_*` (#116).
    pub tls: UpstreamTlsSettings,
}

fn leak_path(path: &std::path::Path) -> &'static std::path::Path {
    crate::arena::leak(path.to_path_buf().into_boxed_path())
}

/// `proxy_ssl_certificate` / `_key` (#138): a file, or a path with
/// variables, rendered per request and resolved against `prefix` (#434).
#[derive(Debug, Clone, Copy)]
pub(crate) enum PreparedCertPath {
    File(&'static Path),
    Vars {
        raw: &'static str,
        parts: &'static [PreparedValuePart],
        prefix: Option<&'static Path>,
    },
}

impl PreparedCertPath {
    fn new(path: &crate::config::CertPath) -> Self {
        match path {
            crate::config::CertPath::File(path) => Self::File(leak_path(path)),
            crate::config::CertPath::Vars { raw, parts, prefix } => Self::Vars {
                raw: crate::arena::leak(raw.clone().into_boxed_str()),
                parts: super::prepare::prepare_value_parts(parts.clone()),
                prefix: prefix.as_deref().map(leak_path),
            },
        }
    }

    /// The directive's value, for messages.
    pub fn text(&self) -> std::borrow::Cow<'static, str> {
        match self {
            Self::File(path) => path.to_string_lossy(),
            Self::Vars { raw, .. } => std::borrow::Cow::Borrowed(raw),
        }
    }
}

/// The `proxy_ssl_*` settings of a scope, resolved (#116).
#[derive(Debug, Clone, Copy)]
pub(crate) struct UpstreamTlsSettings {
    pub server_name: bool,
    pub session_reuse: bool,
    pub protocols: crate::config::TlsVersionSet,
    pub name: Option<&'static [PreparedValuePart]>,
    /// `proxy_ssl_verify` and what it checks against (#117).
    pub verify: bool,
    pub trusted: Option<&'static std::path::Path>,
    pub verify_depth: u32,
    pub crl: Option<&'static std::path::Path>,
    /// `proxy_ssl_certificate` and its key (#138); `None` for `""`.
    pub certificate: Option<PreparedCertPath>,
    pub certificate_key: Option<PreparedCertPath>,
    /// `proxy_ssl_password_file` (#139).
    pub password_file: Option<&'static std::path::Path>,
}

impl UpstreamTlsSettings {
    /// nginx's: no SNI, session reuse on; TLS 1.2 and 1.3 (rustls speaks
    /// no older one).
    pub const DEFAULT: Self = Self {
        server_name: false,
        session_reuse: true,
        protocols: crate::config::TlsVersionSet {
            tlsv1_2: true,
            tlsv1_3: true,
        },
        name: None,
        verify: false,
        trusted: None,
        verify_depth: 1,
        crl: None,
        certificate: None,
        certificate_key: None,
        password_file: None,
    };

    /// `conf`'s values over `self`.
    pub(crate) fn over(self, conf: &crate::config::ProxyConf) -> Self {
        Self {
            server_name: conf.ssl_server_name.unwrap_or(self.server_name),
            session_reuse: conf.ssl_session_reuse.unwrap_or(self.session_reuse),
            protocols: conf.ssl_protocols.unwrap_or(self.protocols),
            name: conf
                .ssl_name
                .clone()
                .map(super::prepare::prepare_value_parts)
                .or(self.name),
            verify: conf.ssl_verify.unwrap_or(self.verify),
            trusted: conf
                .ssl_trusted_certificate
                .as_deref()
                .map(leak_path)
                .or(self.trusted),
            verify_depth: conf.ssl_verify_depth.unwrap_or(self.verify_depth),
            crl: conf.ssl_crl.as_deref().map(leak_path).or(self.crl),
            certificate: match &conf.ssl_certificate {
                Some(path) => path.as_ref().map(PreparedCertPath::new),
                None => self.certificate,
            },
            password_file: conf
                .ssl_password_file
                .as_deref()
                .map(leak_path)
                .or(self.password_file),
            certificate_key: match &conf.ssl_certificate_key {
                Some(path) => path.as_ref().map(PreparedCertPath::new),
                None => self.certificate_key,
            },
        }
    }
}

/// No `proxy_cache*` directive anywhere.
pub(crate) static NO_CACHE_CONF: crate::config::ProxyCacheConf = crate::config::ProxyCacheConf {
    cache: None,
    key: None,
    valid: None,
    methods_post: None,
    min_uses: None,
    bypass: None,
    no_cache: None,
    convert_head: None,
    revalidate: None,
    use_stale: None,
    background_update: None,
    lock: None,
    lock_timeout_ms: None,
    lock_age_ms: None,
    max_range_offset: None,
};

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
            limit_rate: None,
            // ngx_http_proxy_merge_loc_conf: NGX_HTTP_VERSION_11 (1.29.7).
            http_version: 1,
            next_upstream: crate::config::ProxyNextUpstream::DEFAULT,
            next_upstream_tries: 0,
            next_upstream_timeout_ms: 0,
            intercept_errors: false,
            force_ranges: false,
            ignore_client_abort: false,
            ignore_invalid_headers: true,
            underscores_in_headers: false,
            redirect: None,
            cookie_domain: None,
            cookie_path: None,
            cookie_flags: None,
            hide_headers: None,
            pass_headers: None,
            bind: None,
            resolver: None,
            resolver_timeout_ms: 30_000,
            error_pages: &[],
            recursive_error_pages: false,
            proxy_method: None,
            tls: UpstreamTlsSettings::DEFAULT,
            cache: &NO_CACHE_CONF,
            cache_ignore: crate::proxy_cache::Ignore {
                x_accel_expires: false,
                expires: false,
                cache_control: false,
                set_cookie: false,
                vary: false,
            },
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
    /// Max idle pool slots per worker (`keepalive N;`), for the whole
    /// upstream as in nginx, not per peer. `None` means no pool — every
    /// attempt opens a fresh socket: `keepalive 0;`, or a `proxy_pass` with
    /// no `upstream {}` block.
    pub keepalive_max_idle: Option<u32>,
    /// `keepalive N local;`, and the default pool of an `upstream {}`
    /// block (nginx 1.29.7): a connection goes back only to the location
    /// that opened it (`PreparedProxy::pool_tag`).
    pub keepalive_local: bool,
    /// `keepalive_requests N;` — close after N requests on a pooled conn.
    /// Default 1000 to match nginx.
    pub keepalive_requests: u64,
    /// `keepalive_timeout T;` — drop idle conns older than this.
    /// Default 60s to match nginx.
    pub keepalive_idle_timeout_ms: u64,
    /// `keepalive_time T;` — hard lifetime cap. Default 1h.
    pub keepalive_max_lifetime_ms: u64,
    /// LB algorithm: smoothed weighted RR by default, `least_conn`, `hash`
    /// or `ip_hash`.
    pub lb: crate::upstream::Lb,
    /// `zone`: the peers' connection counts and failure state, shared by
    /// all workers (one slot per peer). `None`: per worker, as nginx's
    /// without a zone.
    pub shared: Option<&'static [crate::upstream::PeerShared]>,
    /// Each peer's metrics slot (#481); `None` without `ruxen_metrics`.
    pub metrics: Option<&'static [u32]>,
}

/// Where a peer listens. A UNIX-domain socket prints as `unix:/path`, as in
/// nginx's `$upstream_addr` and error log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerAddr {
    Inet(SocketAddr),
    Unix(&'static std::path::Path),
}

impl PeerAddr {
    pub(crate) fn from_config(addr: crate::config::UpstreamAddr) -> Self {
        match addr {
            crate::config::UpstreamAddr::Inet(addr) => PeerAddr::Inet(addr),
            crate::config::UpstreamAddr::Unix(path) => {
                PeerAddr::Unix(crate::arena::leak(path.into_boxed_path()))
            }
        }
    }
}

impl std::fmt::Display for PeerAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PeerAddr::Inet(addr) => addr.fmt(f),
            PeerAddr::Unix(path) => write!(f, "unix:{}", path.display()),
        }
    }
}

/// Per-server entry inside an `upstream {}` block. The runtime consumes the
/// full peer surface for weighted/least-conn selection, backup eligibility,
/// and `max_fails` / `fail_timeout` liveness tracking.
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct PreparedPeer {
    pub addr: PeerAddr,
    pub display: &'static [u8],
    pub weight: u32,
    pub max_fails: u32,
    pub fail_timeout_ms: u64,
    /// `max_conns=`; 0 = unlimited.
    pub max_conns: u32,
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
        (self.rate.is_some() || self.after.is_some()).then(|| &*crate::arena::leak(Box::new(self)))
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

/// A location's `types {}` and `default_type` (#38): the content type of a
/// file by the extension of its URI, as ngx_http_set_content_type finds it.
pub struct PreparedTypes {
    pub map: std::collections::HashMap<
        Box<[u8]>,
        &'static [u8],
        std::hash::BuildHasherDefault<super::NameHasher>,
    >,
    pub default: &'static [u8],
    /// `default` is `text/plain`: a `return` to a URI without an extension
    /// keeps the type it was built with (#691), without a compare.
    pub default_is_plain: bool,
}

impl PreparedTypes {
    /// The type for `url_path`'s extension (after the last `.` of the last
    /// segment), case-insensitively; `default_type` without one or without
    /// a match.
    #[inline]
    pub fn for_url(&self, url_path: &[u8]) -> &'static [u8] {
        let name = match url_path.iter().rposition(|&b| b == b'/') {
            Some(i) => &url_path[i + 1..],
            None => url_path,
        };
        let ext = match name.iter().rposition(|&b| b == b'.') {
            Some(d) if d + 1 < name.len() => &name[d + 1..],
            _ => return self.default,
        };
        if !ext.iter().any(u8::is_ascii_uppercase) {
            return self.map.get(ext).copied().unwrap_or(self.default);
        }
        let lower = ext.to_ascii_lowercase();
        self.map
            .get(lower.as_slice())
            .copied()
            .unwrap_or(self.default)
    }
}

/// `'a` is `'static` but for a root rendered per request (`template`),
/// which `fs_resolve` copies with the rendered path.
#[derive(Clone, Copy)]
pub struct PreparedRoot<'a> {
    pub root: &'a Path,
    /// `types {}` / `default_type` (#38).
    pub types: &'static PreparedTypes,
    /// Open dirfd for the canonicalized root, or -1 if it didn't exist at
    /// startup (read it through `fd()`). Used as the `dirfd` argument of
    /// `openat2(RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS)` so the kernel
    /// enforces symlink-escape containment in a single syscall — replaces
    /// the old stat + canonicalize + `starts_with` guard. Opened at prepare
    /// time if possible, else on first use; leaked for process lifetime
    /// (closed at exit only). In a rendered copy, the fd opened for the
    /// request, or `-1 - errno` when that failed.
    pub root_fd: std::os::unix::io::RawFd,
    /// `root` / `alias` with variables (#232): rendered per request, and
    /// `root` is then the path as written.
    pub template: Option<&'static RootTemplate>,
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
    pub if_modified_since: crate::config::IfModifiedSince,
    pub etag: bool,
    pub try_files: Option<&'static PreparedTryFiles>,
    /// `gzip_static on|always` (#760).
    pub gzip_static: Option<&'static PreparedGzipStatic>,
}

/// A location's `gzip_static on|always` (#760).
#[derive(Debug)]
pub struct PreparedGzipStatic {
    pub always: bool,
    /// The location's `gzip_vary`, `gzip_http_version`, `gzip_proxied` and
    /// `gzip_disable`: they apply with `gzip off` too.
    pub checks: &'static PreparedGzip,
}

/// Where a location's URIs map on disk, whatever its handler: its `root`
/// or `alias` (else `html`), for `$request_filename` / `$document_root`.
#[derive(Debug)]
pub struct DocRoot {
    pub path: &'static Path,
    pub mapping: PreparedPathMapping,
    /// The location's name, for nginx's `"alias" cannot be used in
    /// location …` (#589).
    pub location: &'static [u8],
    /// The location's charset for `Content-Type` (#464), here because the
    /// request's meta already points at its DocRoot: a field of its own in
    /// `MatchedLocation` and `ProcessMeta` cost h2c_hello about 1% (ABBA
    /// and callgrind, 2026-10-22).
    pub charset: Option<&'static PreparedCharset>,
    /// The location's `disable_symlinks`, for `if -f` and the like.
    pub symlinks: PreparedSymlinks,
    /// `path` with variables (#232), rendered per request (`path_for`).
    pub template: Option<&'static RootTemplate>,
}

impl DocRoot {
    /// The root or alias path for this request, as nginx's
    /// ngx_http_variable_document_root.
    #[inline]
    pub(crate) fn path_for(&self, ctx: &RenderCtx<'_>) -> std::borrow::Cow<'static, Path> {
        match self.template {
            None => std::borrow::Cow::Borrowed(self.path),
            Some(t) => std::borrow::Cow::Owned(t.render(ctx)),
        }
    }
}

/// A `root` or `alias` with variables (#232), nginx's `root_lengths` /
/// `root_values`.
#[derive(Debug)]
pub struct RootTemplate {
    pub parts: &'static [PreparedValuePart],
    /// For a path that starts with a variable: the prefix a relative
    /// result is taken under (ngx_get_full_name). Otherwise a relative
    /// path got it at startup.
    pub prefix: Option<&'static Path>,
    /// A literal part has `..`, so one in the result may be the config's.
    pub literal_dot_dot: bool,
}

impl RootTemplate {
    #[cold]
    pub(crate) fn render(&self, ctx: &RenderCtx<'_>) -> std::path::PathBuf {
        use std::os::unix::ffi::OsStrExt;
        let mut out = Vec::with_capacity(64);
        render_parts(self.parts, ctx, &mut out);
        let path = Path::new(std::ffi::OsStr::from_bytes(&out));
        match self.prefix {
            Some(prefix) if path.is_relative() => prefix.join(path),
            _ => path.to_path_buf(),
        }
    }

    /// A rendered path ruxen won't open: a NUL, which nginx's C string
    /// would cut the path at, or a `..` component a variable brought in.
    /// nginx follows such a `..`; ruxen refuses it, as it refuses one that
    /// climbs out of a root (`fs_resolve::open_and_stat`).
    pub(crate) fn is_unsafe(&self, path: &Path) -> bool {
        use std::os::unix::ffi::OsStrExt;
        let bytes = path.as_os_str().as_bytes();
        bytes.contains(&0)
            || (!self.literal_dot_dot && bytes.split(|&b| b == b'/').any(|c| c == b".."))
    }
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

impl DocRoot {
    /// nginx's ngx_http_map_uri_to_path refuses an `alias` once a
    /// `rewrite` changed the URI in the location (`uri_changed`, before
    /// the locations are searched again) or kept it there with `break`
    /// (`!valid_location`): there is no part of the new URI to replace
    /// (#589). The `[alert]` is noted for the request's error log.
    #[cold]
    pub(crate) fn alias_refused(&self, state: &RewriteState) -> bool {
        if matches!(self.mapping, PreparedPathMapping::Root)
            || (state.valid_location && !state.uri_changed)
        {
            return false;
        }
        crate::fs_resolve::note_failed_lookup_at(
            format!(
                "\"alias\" cannot be used in location \"{}\" where URI was rewritten",
                String::from_utf8_lossy(self.location)
            ),
            false,
            crate::config::ErrorLogLevel::Alert,
        );
        true
    }
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
                PreparedSymlinkFrom::Path(crate::arena::leak(p.as_os_str().as_bytes().into()))
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

impl PreparedRoot<'_> {
    /// The root's dirfd. Opened at startup when the path existed (before
    /// the workers split their fd tables, so it's valid everywhere);
    /// otherwise opened on first use in each worker and kept there, so it
    /// works once the directory appears, as with nginx. Until then this is
    /// the open error (a 404 for ENOENT).
    pub fn fd(&self) -> std::io::Result<std::os::unix::io::RawFd> {
        if self.root_fd >= 0 {
            return Ok(self.root_fd);
        }
        self.lazy_fd()
    }

    #[cold]
    fn lazy_fd(&self) -> std::io::Result<std::os::unix::io::RawFd> {
        if self.root_fd < -1 {
            // A rendered root that didn't open.
            return Err(std::io::Error::from_raw_os_error(-1 - self.root_fd));
        }
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
    /// Effective `max_ranges` (location → server → http, #370): `None` is
    /// no limit, `Some(0)` turns byte ranges off.
    pub max_ranges: Option<u32>,
    /// Effective `client_body_buffer_size`: bodies up to this size stay in
    /// memory. `None` is nginx's default, 16k.
    pub client_body_buffer_size: Option<u64>,
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
    /// Effective gzip settings; `None` when `gzip` is off.
    pub gzip: Option<&'static PreparedGzip>,
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
    /// `absolute_redirect` and friends, resolved (#15).
    pub redirect: crate::config::RedirectPolicy,
    /// `limit_req` for requests routed here (#94); `None` without.
    pub limit_req: Option<&'static super::limit_req::PreparedLimitReq>,
    /// `limit_conn` for requests routed here (#95); `None` without.
    pub limit_conn: Option<&'static super::limit_conn::PreparedLimitConns>,
    /// `client_body_timeout` / `send_timeout` for requests routed here
    /// (location → server → http; #147).
    pub timeouts: &'static PreparedClientTimeouts,
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
    /// `regex` as a member of the server's `regex_location_set`.
    pub set_pattern: String,
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
    pub max_ranges: Option<u32>,
    pub client_body_buffer_size: Option<u64>,
    pub client_body_in_file_only: crate::config::ClientBodyInFileOnly,
    pub body_temp: Option<&'static BodyTempDir>,
    pub doc_root: &'static DocRoot,
    /// Effective `sendfile` (location → server → http, default off). When
    /// on, file bodies are sent zero-copy on plain TCP connections.
    pub sendfile: bool,
    /// Effective gzip settings; `None` when `gzip` is off.
    pub gzip: Option<&'static PreparedGzip>,
    pub limit_rate: Option<&'static PreparedLimitRate>,
    pub post_action: Option<&'static [u8]>,
    pub expires: PreparedExpires,
    pub chunked_transfer_encoding: bool,
    /// `absolute_redirect` and friends, resolved (#15).
    pub redirect: crate::config::RedirectPolicy,
    /// `limit_req` for requests routed here (#94); `None` without.
    pub limit_req: Option<&'static super::limit_req::PreparedLimitReq>,
    /// `limit_conn` for requests routed here (#95); `None` without.
    pub limit_conn: Option<&'static super::limit_conn::PreparedLimitConns>,
    /// `client_body_timeout` / `send_timeout` for requests routed here
    /// (location → server → http; #147).
    pub timeouts: &'static PreparedClientTimeouts,
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
    pub max_ranges: Option<u32>,
    pub client_body_buffer_size: Option<u64>,
    pub client_body_in_file_only: crate::config::ClientBodyInFileOnly,
    pub body_temp: Option<&'static BodyTempDir>,
    pub doc_root: &'static DocRoot,
    /// Effective `sendfile` (location → server → http, default off). When
    /// on, file bodies are sent zero-copy on plain TCP connections.
    pub sendfile: bool,
    /// Effective gzip settings; `None` when `gzip` is off.
    pub gzip: Option<&'static PreparedGzip>,
    pub limit_rate: Option<&'static PreparedLimitRate>,
    pub post_action: Option<&'static [u8]>,
    pub expires: PreparedExpires,
    pub chunked_transfer_encoding: bool,
    /// `absolute_redirect` and friends, resolved (#15).
    pub redirect: crate::config::RedirectPolicy,
    /// `limit_req` for requests routed here (#94); `None` without.
    pub limit_req: Option<&'static super::limit_req::PreparedLimitReq>,
    /// `limit_conn` for requests routed here (#95); `None` without.
    pub limit_conn: Option<&'static super::limit_conn::PreparedLimitConns>,
    /// `client_body_timeout` / `send_timeout` for requests routed here
    /// (location → server → http; #147).
    pub timeouts: &'static PreparedClientTimeouts,
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
            max_ranges: loc.max_ranges,
            client_body_buffer_size: loc.client_body_buffer_size,
            client_body_in_file_only: loc.client_body_in_file_only,
            body_temp: loc.body_temp,
            doc_root: loc.doc_root,
            sendfile: loc.sendfile,
            gzip: loc.gzip,
            limit_rate: loc.limit_rate,
            post_action: loc.post_action,
            expires: loc.expires,
            chunked_transfer_encoding: loc.chunked_transfer_encoding,
            redirect: loc.redirect,
            limit_req: loc.limit_req,
            limit_conn: loc.limit_conn,
            timeouts: loc.timeouts,
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
            max_ranges: loc.max_ranges,
            client_body_buffer_size: loc.client_body_buffer_size,
            client_body_in_file_only: loc.client_body_in_file_only,
            body_temp: loc.body_temp,
            doc_root: loc.doc_root,
            sendfile: loc.sendfile,
            gzip: loc.gzip,
            limit_rate: loc.limit_rate,
            post_action: loc.post_action,
            expires: loc.expires,
            chunked_transfer_encoding: loc.chunked_transfer_encoding,
            redirect: loc.redirect,
            limit_req: loc.limit_req,
            limit_conn: loc.limit_conn,
            timeouts: loc.timeouts,
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
    /// `regex` as a member of the listen's `regex_name_set`.
    pub set_pattern: String,
}

/// `client_header_timeout`, `client_body_timeout`, `send_timeout`,
/// resolved against nginx's 60 s defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreparedClientTimeouts {
    pub header: Duration,
    pub body: Duration,
    pub send: Duration,
    /// `large_client_header_buffers` (#482): the longest line of a request
    /// head, and the largest head, `size × number`.
    pub large_header_line: usize,
    pub large_header: usize,
    /// `client_header_buffer_size` (#467): what a connection's first read
    /// of a head goes into, nginx's 1k by default. A connection whose head
    /// or body fills it moves to `READ_BUF` (`grow_head_buffer`).
    pub header_buffer: usize,
    /// `http2_chunk_size` (#594): the largest DATA frame of a response on
    /// an HTTP/2 stream, nginx's 8k by default.
    pub h2_chunk: usize,
    /// `max_headers` (#584), nginx's 1000 by default, and the shortest
    /// header block that can hold more lines (each takes 3 bytes at
    /// least, `a:\n`): a shorter one isn't counted.
    pub max_headers: usize,
    pub max_headers_span: usize,
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
        // nginx's default, `4 8k`.
        let (num, size) = t.large_header_buffers.unwrap_or((4, 8192));
        let max_headers = t.max_headers.unwrap_or(1000).min(usize::MAX as u64) as usize;
        PreparedClientTimeouts {
            header: Duration::from_millis(t.header_ms.unwrap_or(DEFAULT_MS)),
            body: Duration::from_millis(t.body_ms.unwrap_or(DEFAULT_MS)),
            send: Duration::from_millis(t.send_ms.unwrap_or(DEFAULT_MS)),
            large_header_line: size as usize,
            large_header: (num.saturating_mul(size)).min(usize::MAX as u64) as usize,
            header_buffer: t.header_buffer.unwrap_or(1024).clamp(1, usize::MAX as u64) as usize,
            h2_chunk: t.h2_chunk_size.unwrap_or(8 * 1024) as usize,
            max_headers,
            max_headers_span: max_headers.saturating_add(1).saturating_mul(3),
        }
    }
}

/// A server's locations as nginx nests them (ngx_http_core_find_location):
/// level 0 is the server's own, and each location with nested ones has a
/// level of its own. Indices are into the server's `exact_locations`,
/// `prefix_locations` and `regex_locations`.
#[derive(Debug, Default)]
pub struct LocationTree {
    pub levels: Vec<LocationLevel>,
    /// The level of the locations nested in each prefix location.
    pub prefix_children: Vec<Option<u16>>,
    /// The level of the locations nested in each regex location.
    pub regex_children: Vec<Option<u16>>,
}

/// One level's locations: exact, prefix (longest first) and regex (in
/// declaration order).
#[derive(Debug, Default)]
pub struct LocationLevel {
    pub exact: Vec<u16>,
    pub prefix: Vec<u16>,
    pub regex: Vec<u16>,
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
    /// This server's metrics slot (#481); 0 without `ruxen_metrics`.
    pub metrics_slot: u32,
    /// The server's `root` (else `html`), for `$request_filename` in its
    /// rewrite phase.
    pub doc_root: &'static DocRoot,
    /// The server's charset, for what it answers before a location
    /// (#464).
    pub charset: Option<&'static PreparedCharset>,
    /// Client-side timeouts. The worker uses the listen's default server's
    /// values for the whole connection (see `handle`).
    /// HTTP/2 for this server: `http2 on` (server, else http) or
    /// `listen … http2` (#144).
    pub http2: bool,
    /// The client-certificate context a ClientHello naming this server
    /// gets (`TlsAcceptor::with_contexts`); `None` for the address's own.
    pub tls_context: Option<u16>,
    /// `ssl_verify_client`, checked per request (#113).
    pub client_verify: crate::config::VerifyClient,
    /// Its `http2_*` settings, http's inherited (#346).
    pub h2: crate::config::Http2Conf,
    /// The server-level keep-alive settings, which an HTTP/2 connection
    /// follows (`keepalive_requests` per connection, as nginx does with
    /// its default server's).
    pub keepalive: PreparedKeepalive,
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
    /// `absolute_redirect` and friends at server level (#15), for its own
    /// rewrite program.
    pub redirect: crate::config::RedirectPolicy,
    /// Listening port declared on this `server {}` block. Rendered by
    /// `$server_port`.
    pub listen_port: u16,
    pub exact_locations: Vec<PreparedLocation>,
    pub prefix_locations: Vec<PreparedLocation>,
    pub regex_locations: Vec<PreparedRegexLocation>,
    /// All of `regex_locations` in one `RegexSet`: the first match in
    /// declaration order in one pass, instead of one search per regex
    /// (#248). `None` for fewer than two, or if the set didn't build.
    pub regex_location_set: Option<regex::bytes::RegexSet>,
    pub named_locations: Vec<PreparedLocation>,
    /// Locations nested in others, as nginx searches them
    /// (`phase::match_location`): `None` when none is, and the flat lists
    /// above decide alone.
    pub location_tree: Option<Box<LocationTree>>,
    /// The anonymous locations of its locations' `if` blocks, by the
    /// index `PreparedRewriteOp::If` carries (#137).
    pub if_locations: Vec<PreparedLocation>,
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
    /// Effective server-scope `underscores_in_headers`, or
    /// `ignore_invalid_headers off`: whether nginx's parser keeps a header
    /// whose name has `_`. When false, dynamic-name request-header lookups
    /// (`$http_*`, `$cookie_*`, `$sent_http_*` interpolation feed) skip
    /// such headers, mirroring nginx.
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
    /// `0.0.0.0:0` for a `unix:` socket.
    pub addr: SocketAddr,
    /// `listen unix:/path` (#263): bound once by `main` before the workers
    /// start, accepted on by each through its copy of the descriptor.
    pub unix: Option<&'static Path>,
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
    /// `ssl_reject_handshake on` in a server of this address (#112): which
    /// servers reject, by index into `servers`, and the TLS default
    /// server's index (a ClientHello without a matching name is its).
    /// `None` when no server rejects: the handshake needs no ClientHello
    /// look first.
    pub reject_handshake: Option<(Box<[bool]>, usize)>,
    /// `listen … proxy_protocol` on any server of this address: every
    /// connection starts with a PROXY protocol header.
    pub proxy_protocol: bool,
    /// `listen … http2` on the address: every server takes HTTP/2, as
    /// nginx's `addr_conf->http2`.
    pub http2_listen: bool,
    /// Plain connections are looked at for the preface: `listen … http2`,
    /// or `http2 on` in the default server (ngx_http_init_connection).
    pub h2_plain: bool,
    /// The servers differ in `http2`: the SNI name decides whether ALPN
    /// offers `h2` (`phase::tls_choice`).
    pub h2_by_sni: bool,
    /// The servers differ in client-certificate context: the SNI name
    /// picks the config (`phase::tls_choice`, #113).
    pub tls_contexts_by_sni: bool,
    /// Some server of the address has `ssl_verify_client` on: requests are
    /// checked (`phase::client_certificate_refusal`).
    pub client_verify: bool,
    /// The TLS default server (`default_server`, else the first), for a
    /// ClientHello without a name that selects one.
    pub tls_default_server: usize,
    /// The listening socket's options.
    pub socket: ListenSocket,
    /// Every regex `server_name` of `servers`, in the order they are tried
    /// (server by server), in one `RegexSet`, with each member's (server,
    /// name) index (#248). `None` for fewer than two.
    /// Every exact `server_name` of `servers` (lowercased) to the first
    /// server that declares it, as nginx's server-name hash: one lookup
    /// instead of comparing against every name of every server.
    pub exact_names: NameMap,
    pub regex_name_set: Option<(regex::bytes::RegexSet, Vec<(u32, u32)>)>,
}

/// `PreparedListen::exact_names`: hashed with `NameHasher`.
pub type NameMap =
    std::collections::HashMap<&'static [u8], u32, std::hash::BuildHasherDefault<NameHasher>>;

/// rustc's FxHash, for maps keyed by what the configuration made: server
/// names here, upstream addresses in `upstream.rs`. A lookup with any
/// `Host` can't degrade such a table, which is what SipHash guards
/// against; SipHash cost 2.8% of `m1_hello`'s instructions (callgrind).
#[derive(Default, Clone, Copy)]
pub struct NameHasher(u64);

const NAME_HASH_K: u64 = 0xf135_7aea_2e62_a9c5;

impl std::hash::Hasher for NameHasher {
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        let mut h = self.0;
        let (chunks, rest) = bytes.as_chunks::<8>();
        for c in chunks {
            h = (h.rotate_left(5) ^ u64::from_le_bytes(*c)).wrapping_mul(NAME_HASH_K);
        }
        if !rest.is_empty() {
            let mut last = [0u8; 8];
            last[..rest.len()].copy_from_slice(rest);
            h = (h.rotate_left(5) ^ u64::from_le_bytes(last)).wrapping_mul(NAME_HASH_K);
        }
        self.0 = h;
    }

    #[inline]
    fn write_usize(&mut self, n: usize) {
        self.0 = (self.0.rotate_left(5) ^ n as u64).wrapping_mul(NAME_HASH_K);
    }

    #[inline]
    fn finish(&self) -> u64 {
        // The multiply leaves the low bits weakest; hashbrown takes the
        // bucket from them.
        self.0.rotate_left(26)
    }
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
    /// `reuseport`: other processes may share the address. The workers
    /// always bind with `SO_REUSEPORT` (one accept queue each); without
    /// this option, startup first makes sure no one else holds the
    /// address (`runtime::claim_addresses`).
    pub reuseport: bool,
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
            reuseport: listen.is_some_and(|l| l.reuseport),
        }
    }
}

/// Top-level prepared state.
pub struct PreparedHttp {
    pub listens: Vec<PreparedListen>,
    /// `proxy_cache_path` zones, each looked after by a manager thread.
    pub cache_zones: &'static [&'static crate::proxy_cache::CacheZone],
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
    /// `$request_body_file` appears in the config. If not, a body that is
    /// in memory is never also written to a temp file: nothing would read
    /// it (#246).
    pub uses_request_body_file: bool,
    /// `$request_body` appears in the config. If not, a body that a
    /// `return` location gets is dropped as it is read (#289).
    pub uses_request_body: bool,
    /// `$request_id` appears in the config: each request draws one (#487).
    pub uses_request_id: bool,
    /// An `error_log stderr` appears in the config: `-e` doesn't take over
    /// stderr (nginx's `log_use_stderr`; #309).
    pub uses_stderr_log: bool,
    /// `stub_status` or `$connections_*` is used: keep the counters
    /// (`stats`).
    pub stats: bool,
    /// `ruxen_metrics` is used: the counters it shows (#481).
    pub metrics: Option<&'static super::metrics::Metrics>,
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
    /// A request line with an HTTP major version past 1: 505.
    pub version_not_supported: Prebuilt,
    /// nginx's 497 page: plain HTTP on an `ssl` port, sent as 400 (#384).
    pub plain_http: Prebuilt,
    /// A request line longer than `large_client_header_buffers` allows: 414
    /// (#482).
    pub uri_too_large: Prebuilt,
    /// A header line or head over `large_client_header_buffers`: nginx's
    /// 494, sent as 400 "Request Header Or Cookie Too Large" (#482).
    pub header_too_large: Prebuilt,
    /// nginx's 495 and 496 pages, sent as 400, and its 421 (#113).
    pub cert_error: Prebuilt,
    pub no_cert: Prebuilt,
    pub misdirected: Prebuilt,
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
    /// The upstreams of `proxy_pass http://host[:port]` without variables,
    /// by lowercased host and port (80 when none): nginx's implicit
    /// upstreams, which a `proxy_pass` with variables can name too (#100).
    pub implicit_upstreams: &'static [(&'static [u8], u16, &'static PreparedUpstream)],
    /// Directory of the main config file, for resolving relative paths that
    /// are only known per request (e.g. `auth_basic_user_file $var`).
    pub conf_prefix: Option<&'static Path>,
    /// `worker_shutdown_timeout` (unset or 0: none). Bounds an upgraded
    /// connection's life after a reload.
    pub shutdown_timeout: Option<Duration>,
    /// The `root` / `alias` directories opened at prepare time
    /// (`PreparedRoot::root_fd`), for `main` to close once a reload has
    /// retired this configuration's workers.
    pub root_fds: &'static [std::os::unix::io::RawFd],
}

impl PreparedHttp {
    /// After a reload, once no worker serves this configuration any more:
    /// close the directories it opened in `main`'s fd table, so the next
    /// generations don't inherit them. The configuration must not be used
    /// for requests after this.
    pub fn close_root_fds(&self) {
        for &fd in self.root_fds {
            // SAFETY: a descriptor `prepare` opened for this configuration
            // only, which nothing uses any more.
            unsafe { libc::close(fd) };
        }
    }
}

/// One generation of workers: the ones started at startup, or by a reload
/// (#89), with the configuration they serve.
#[derive(Default)]
pub struct RuntimeState {
    shutting_down: AtomicBool,
    /// `worker_shutdown_timeout` passed after a reload or SIGQUIT: the
    /// workers end their connections (`listeners::shut_down_sockets`).
    forced: AtomicBool,
    connection_ids: AtomicU64,
    /// Bumped when a reload retires these workers, along with the
    /// shutdown: an upgraded connection then lives until
    /// `worker_shutdown_timeout` (`tunnel`), as on an old nginx worker.
    reload_gen: AtomicU64,
    /// Set by `main` once root is dropped (`privileges`); workers bind,
    /// report ready, and wait for it before accepting.
    released: std::sync::Mutex<bool>,
    released_cv: std::sync::Condvar,
    /// One counter per worker, bumped on every turn of its accept loop
    /// (`notice_runtime_events`), for systemd's watchdog (#502): a worker
    /// whose counter stands still is stuck.
    heartbeats: std::sync::Mutex<Vec<std::sync::Arc<AtomicU64>>>,
}

impl RuntimeState {
    /// A worker of this generation starts beating.
    pub(crate) fn heartbeat(&self) -> std::sync::Arc<AtomicU64> {
        let beat = std::sync::Arc::new(AtomicU64::new(0));
        self.heartbeats
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(beat.clone());
        beat
    }

    /// Every worker's beat count, in order.
    pub fn heartbeats(&self) -> Vec<u64> {
        self.heartbeats
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|b| b.load(Ordering::Relaxed))
            .collect()
    }

    /// Lets the workers start accepting.
    pub fn release_workers(&self) {
        *self.released.lock().unwrap_or_else(|e| e.into_inner()) = true;
        self.released_cv.notify_all();
    }

    pub(crate) fn wait_released(&self) {
        let mut released = self.released.lock().unwrap_or_else(|e| e.into_inner());
        while !*released {
            released = self
                .released_cv
                .wait(released)
                .unwrap_or_else(|e| e.into_inner());
        }
    }

    pub fn begin_shutdown(&self) {
        self.shutting_down.store(true, Ordering::SeqCst);
    }

    pub fn is_shutting_down(&self) -> bool {
        self.shutting_down.load(Ordering::SeqCst)
    }

    pub fn force_close(&self) {
        self.forced.store(true, Ordering::SeqCst);
    }

    pub(crate) fn is_forced(&self) -> bool {
        self.forced.load(Ordering::SeqCst)
    }

    pub(crate) fn next_connection_id(&self) -> u64 {
        // Only uniqueness matters (`$connection`): no ordering.
        self.connection_ids
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1)
    }

    pub fn bump_reload_gen(&self) {
        self.reload_gen.fetch_add(1, Ordering::SeqCst);
    }

    pub(crate) fn reload_gen(&self) -> u64 {
        self.reload_gen.load(Ordering::SeqCst)
    }
}

/// A location's effective gzip settings (`gzip on`), see `worker::gzip`.
/// `charset` where a response gets it (#464): the name, and the
/// `charset_types` it applies to (`None`: any, `charset_types *`).
#[derive(Debug)]
pub struct PreparedCharset {
    pub name: &'static [u8],
    pub types: Option<&'static [&'static [u8]]>,
}

#[derive(Debug)]
pub struct PreparedGzip {
    /// `gzip_types *`.
    pub any_type: bool,
    /// Lowercased MIME types, `text/html` always among them.
    pub types: &'static [&'static str],
    pub min_length: u64,
    pub comp_level: u32,
    pub vary: bool,
    /// `gzip_http_version 1.0`: HTTP/1.0 clients get gzip too.
    pub http_10: bool,
    /// `gzip_proxied` flags (`config::gzip_proxied`).
    pub proxied: u16,
    pub disable_msie6: bool,
    /// `gzip_disable` User-Agent patterns, case-insensitive.
    pub disable: Option<regex::bytes::RegexSet>,
}
