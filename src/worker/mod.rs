// Per-core worker: owns an io_uring runtime, binds listen sockets via
// SO_REUSEPORT, accepts connections, drives the keep-alive request loop.
//
// Shared-nothing. `PreparedHttp` is built once at startup and handed to every
// worker through `&'static` borrows — no Arc cloning and no atomics on the
// hot path, since the config lives for the whole process.
//
// Submodule layout:
//   - prepared: leaked-static data model (Prepared* types + RuntimeState)
//   - prepare:  the prepare(cfg) builder that lowers the AST into `&'static PreparedHttp`
//   - render:   RenderCtx + variable expansion + numeric/time formatters
//   - response: response shaping (headers, status, conditionals, prebuilt cache)
//   - handler:  run_location_handler + finalize_location_response
//   - rewrite:  rewrite-engine runtime (`run_rewrite_program`)
//   - connection: ConnIo trait + ChunkedBody decoder + stream_file
//   - log:      per-request error-log emission
//   - runtime:  the monoio per-worker event loop and the request-driving `handle`
//
// Cross-submodule items are `pub(crate)` and re-exported flat into `worker::`
// so any submodule can call any other's helper without chasing the path.

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

mod connection;
mod handler;
mod log;
mod prepare;
mod prepared;
mod render;
mod response;
mod rewrite;
mod runtime;

pub(crate) use connection::*;
pub(crate) use handler::*;
pub(crate) use log::*;
pub(crate) use prepare::*;
pub(crate) use prepared::*;
pub(crate) use render::*;
pub(crate) use response::*;
pub(crate) use rewrite::*;
pub(crate) use runtime::*;

thread_local! {
    static ACCESS_LOG_FILES: Cell<Option<&'static [AsyncFile]>> = const { Cell::new(None) };
}

/// `prepare` already opened every access_log once, so a failure here
/// means the file changed underneath us during startup; it is reported
/// like any other startup error.
pub(crate) fn init_access_logs_for_worker(logs: &[PreparedAccessLog]) -> Result<(), String> {
    ACCESS_LOG_FILES.with(|cell| {
        if cell.get().is_some() {
            return Ok(());
        }
        if logs.is_empty() {
            cell.set(Some(&[]));
            return Ok(());
        }
        let mut opened: Vec<AsyncFile> = Vec::with_capacity(logs.len());
        for log in logs {
            let open_failed = |e: std::io::Error| {
                format!(
                    "open() \"{}\" failed ({})",
                    log.path.display(),
                    errno_text(&e)
                )
            };
            let std_file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(log.path)
                .map_err(open_failed)?;
            let f = AsyncFile::from_std(std_file).map_err(open_failed)?;
            opened.push(f);
        }
        cell.set(Some(Box::leak(opened.into_boxed_slice())));
        Ok(())
    })
}

/// Machine hostname, resolved once at startup for `$hostname` expansion.
/// `OnceLock`-style simple cached value; if `gethostname` ever fails we
/// fall back to an empty string rather than panicking the server boot.
pub(crate) static HOSTNAME: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();

pub(crate) fn hostname() -> &'static [u8] {
    HOSTNAME
        .get_or_init(|| {
            // `uname -n` is enough — no crate dependency. Read `/etc/hostname`
            // as a linux-friendly no-alloc-after-boot path; if that fails,
            // fall back to `$HOSTNAME` env or empty.
            if let Ok(s) = std::fs::read_to_string("/etc/hostname") {
                return s.trim().as_bytes().to_vec();
            }
            std::env::var_os("HOSTNAME")
                .map(|s| s.to_string_lossy().into_owned().into_bytes())
                .unwrap_or_default()
        })
        .as_slice()
}

/// Body size above which we spill to a temp file so `$request_body_file`
/// can be populated for nginx-tests cases.
pub(crate) const REQUEST_BODY_FILE_THRESHOLD: usize = 2 * 1024;

pub(crate) static REQUEST_BODY_FILE_SEQ: AtomicU64 = AtomicU64::new(0);

/// Owns the on-disk temp file for a spilled request body. The file is
/// unlinked when this guard drops at end-of-request, mirroring nginx's
/// default `client_body_in_file_only off`. Set `keep` to true (after the
/// matched location is known) when `client_body_in_file_only on` so the
/// file persists past the response.
pub(crate) struct SpilledBody {
    path: std::path::PathBuf,
    /// Cached UTF-8 bytes of `path` for cheap `&[u8]` rendering.
    path_bytes: Vec<u8>,
    keep: std::cell::Cell<bool>,
}

impl SpilledBody {
    pub(crate) fn path_bytes(&self) -> &[u8] {
        &self.path_bytes
    }

    pub(crate) fn set_keep(&self, keep: bool) {
        self.keep.set(keep);
    }
}

impl Drop for SpilledBody {
    fn drop(&mut self) {
        if !self.keep.get() {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

pub(crate) fn maybe_spill_request_body_to_file(body: &[u8]) -> Option<SpilledBody> {
    if body.len() <= REQUEST_BODY_FILE_THRESHOLD {
        return None;
    }
    let seq = REQUEST_BODY_FILE_SEQ.fetch_add(1, Ordering::Relaxed);
    let mut path = std::env::temp_dir();
    path.push(format!("ruxen-body-{}-{}.tmp", std::process::id(), seq));
    if std::fs::write(&path, body).is_err() {
        return None;
    }
    let path_bytes = path.to_string_lossy().into_owned().into_bytes();
    Some(SpilledBody {
        path,
        path_bytes,
        keep: std::cell::Cell::new(false),
    })
}

/// Request bodies up to this size stay in memory, where the proxy forwards
/// them without a copy; larger ones go to a temp file as they arrive, like
/// nginx past `client_body_buffer_size`.
pub(crate) const REQUEST_BODY_IN_MEMORY: usize = 1 << 20;

/// nginx's default `client_max_body_size`.
pub(crate) const DEFAULT_CLIENT_MAX_BODY_SIZE: u64 = 1 << 20;

/// Collects a request body: in memory up to `REQUEST_BODY_IN_MEMORY`, then
/// in a temp file (removed with the `SpilledBody` unless kept).
pub(crate) struct BodySink {
    mem: Vec<u8>,
    file: Option<(std::fs::File, SpilledBody)>,
    len: u64,
}

impl BodySink {
    pub(crate) fn with_capacity(expected: u64) -> Self {
        BodySink {
            mem: Vec::with_capacity(expected.min(REQUEST_BODY_IN_MEMORY as u64) as usize),
            file: None,
            len: 0,
        }
    }

    pub(crate) fn len(&self) -> u64 {
        self.len
    }

    /// Append `data`; `false` if the temp file couldn't be written.
    pub(crate) fn extend(&mut self, data: &[u8]) -> bool {
        if self.file.is_none() && self.mem.len() + data.len() > REQUEST_BODY_IN_MEMORY {
            let Some(spilled) = new_body_file() else {
                return false;
            };
            let Ok(mut file) = std::fs::OpenOptions::new().append(true).open(&spilled.path) else {
                return false;
            };
            if file.write_all(&self.mem).is_err() {
                return false;
            }
            self.mem = Vec::new();
            self.file = Some((file, spilled));
        }
        let ok = match &mut self.file {
            Some((file, _)) => file.write_all(data).is_ok(),
            None => {
                self.mem.extend_from_slice(data);
                true
            }
        };
        self.len += data.len() as u64;
        ok
    }

    /// The in-memory body (empty when spilled) and the file, if any.
    pub(crate) fn finish(self) -> (Vec<u8>, Option<SpilledBody>) {
        match self.file {
            Some((_, spilled)) => (Vec::new(), Some(spilled)),
            None => (self.mem, None),
        }
    }
}

fn new_body_file() -> Option<SpilledBody> {
    let seq = REQUEST_BODY_FILE_SEQ.fetch_add(1, Ordering::Relaxed);
    let mut path = std::env::temp_dir();
    path.push(format!("ruxen-body-{}-{}.tmp", std::process::id(), seq));
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .ok()?;
    let path_bytes = path.to_string_lossy().into_owned().into_bytes();
    Some(SpilledBody {
        path,
        path_bytes,
        keep: std::cell::Cell::new(false),
    })
}

/// Normalize the raw request path. Used by `phase::process` before entering
/// the reroute loop; bubbles URI errors up as appropriate status codes.
/// `merge_slashes` threads the per-server directive through — the
/// normalizer collapses `//` → `/` only when this is true.
pub(crate) fn normalize_request_uri_into(
    http: &'static PreparedHttp,
    req: &phase::RequestCtx<'_>,
    merge_slashes: bool,
    out: &mut Vec<u8>,
) -> Result<(), Response> {
    match uri::normalize_with(req.path, merge_slashes, out) {
        Ok(_) => Ok(()),
        Err(uri::UriError::EscapesRoot) => Err(Response::Prebuilt(http.forbidden.pick(req.method))),
        Err(_) => Err(Response::Prebuilt(http.bad_request.pick(req.method))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    pub(crate) fn parse_cfg(src: &str) -> HttpConfig {
        crate::config::parse(src).unwrap()
    }

    pub(crate) fn unique_dir() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let d = std::env::temp_dir().join(format!(
            "ruxen-worker-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir(&d).unwrap();
        d
    }

    pub(crate) fn response_body(bytes: &[u8]) -> &[u8] {
        bytes
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map(|i| &bytes[i + 4..])
            .unwrap_or(&[])
    }

    #[test]
    pub(crate) fn transfer_encoding_classifier_accepts_chunked_only() {
        assert_eq!(
            classify_request_transfer_encoding(b"chunked"),
            RequestTransferEncoding::ChunkedOnly
        );
        assert_eq!(
            classify_request_transfer_encoding(b" \tchunked\t "),
            RequestTransferEncoding::ChunkedOnly
        );
    }

    #[test]
    pub(crate) fn transfer_encoding_classifier_rejects_unsupported_values() {
        assert_eq!(
            classify_request_transfer_encoding(b"identity"),
            RequestTransferEncoding::Unsupported
        );
        assert_eq!(
            classify_request_transfer_encoding(b"chunked, identity"),
            RequestTransferEncoding::Unsupported
        );
    }

    #[test]
    pub(crate) fn transfer_encoding_classifier_rejects_malformed_lists() {
        assert_eq!(
            classify_request_transfer_encoding(b""),
            RequestTransferEncoding::Invalid
        );
        assert_eq!(
            classify_request_transfer_encoding(b",chunked"),
            RequestTransferEncoding::Invalid
        );
    }

    #[test]
    pub(crate) fn request_arg_helpers_parse_query_string() {
        let args = request_args(b"/p?q=1&empty=&flag&x=two");
        assert_eq!(args, b"q=1&empty=&flag&x=two");
        assert_eq!(request_arg_value(args, b"q"), Some(&b"1"[..]));
        assert_eq!(request_arg_value(args, b"empty"), Some(&b""[..]));
        assert_eq!(request_arg_value(args, b"flag"), Some(&b""[..]));
        assert_eq!(request_arg_value(args, b"x"), Some(&b"two"[..]));
        assert_eq!(request_arg_value(args, b"missing"), None);
    }

    #[test]
    pub(crate) fn prepare_accepts_multiple_servers_on_same_listen() {
        let cfg = parse_cfg(
            r#"
                http {
                    server {
                        listen 8080;
                        server_name a.example.com;
                        location / { return 200 "a"; }
                    }
                    server {
                        listen 8080;
                        server_name b.example.com;
                        location / { return 200 "b"; }
                    }
                }
            "#,
        );
        let http = prepare(cfg).expect("prepare");
        assert_eq!(http.listens.len(), 1);
        assert_eq!(http.listens[0].servers.len(), 2);
        assert_eq!(http.listens[0].default_server, 0);
        assert_eq!(
            http.listens[0].servers[0].exact_names,
            vec![&b"a.example.com"[..]]
        );
        assert_eq!(
            http.listens[0].servers[1].exact_names,
            vec![&b"b.example.com"[..]]
        );
    }

    #[test]
    pub(crate) fn prepare_groups_servers_by_listen() {
        let cfg = parse_cfg(
            r#"
                http {
                    server { listen 8080; location / { return 200 "a"; } }
                    server { listen 8081; location / { return 200 "b"; } }
                    server { listen 8080; location /x { return 200 "x"; } }
                }
            "#,
        );
        let http = prepare(cfg).expect("prepare");
        assert_eq!(http.listens.len(), 2);
        assert_eq!(http.listens[0].addr.port(), 8080);
        assert_eq!(http.listens[0].servers.len(), 2);
        assert_eq!(http.listens[1].addr.port(), 8081);
        assert_eq!(http.listens[1].servers.len(), 1);
    }

    #[test]
    pub(crate) fn prepare_accepts_zero_servers() {
        // nginx starts with an empty `http {}`; so do we, listening nowhere.
        let http = prepare(parse_cfg("http {}")).expect("prepare");
        assert!(http.listens.is_empty());
    }

    fn prepare_err(src: &str) -> String {
        prepare(parse_cfg(src)).err().expect("prepare must fail")
    }

    #[test]
    pub(crate) fn prepare_reports_missing_root() {
        let err =
            prepare_err("http { server { listen 127.0.0.1:8080; root /nonexistent-ruxen-root; } }");
        assert!(
            err.starts_with(
                "root \"/nonexistent-ruxen-root\" is not accessible: realpath() failed (2: "
            ),
            "{err}"
        );
    }

    #[test]
    pub(crate) fn prepare_reports_missing_alias() {
        let err = prepare_err(
            "http { server { listen 127.0.0.1:8080; location /a/ { alias /nonexistent-ruxen-alias/; } } }",
        );
        assert!(
            err.starts_with("alias \"/nonexistent-ruxen-alias/\""),
            "{err}"
        );
    }

    #[test]
    pub(crate) fn prepare_reports_unknown_log_format() {
        let err = prepare_err(
            "http { server { listen 127.0.0.1:8080; access_log /dev/null nosuchfmt; } }",
        );
        assert_eq!(err, "unknown log format \"nosuchfmt\"");
    }

    #[test]
    pub(crate) fn prepare_reports_unopenable_logs() {
        let err = prepare_err(
            "http { server { listen 127.0.0.1:8080; access_log /nonexistent-ruxen-dir/a.log; } }",
        );
        assert_eq!(
            err,
            "open() \"/nonexistent-ruxen-dir/a.log\" failed (2: No such file or directory)"
        );
        let err = prepare_err(
            "http { server { listen 127.0.0.1:8080; error_log /nonexistent-ruxen-dir/e.log; } }",
        );
        assert_eq!(
            err,
            "open() \"/nonexistent-ruxen-dir/e.log\" failed (2: No such file or directory)"
        );
    }

    #[test]
    pub(crate) fn ssl_address_needs_a_certificate_on_its_default_server() {
        // nginx (ngx_http_ssl_init): only the default server must have one.
        let err = prepare_err("http { server { listen 127.0.0.1:8443 ssl; } }");
        assert!(
            err.starts_with(
                "no \"ssl_certificate\" is defined for the \"listen ... ssl\" directive"
            ),
            "{err}"
        );
        let err = prepare_err(
            "http { server { listen 127.0.0.1:8443; }
                    server { listen 127.0.0.1:8443 ssl; server_name b; } }",
        );
        assert!(err.starts_with("no \"ssl_certificate\""), "{err}");
    }

    #[test]
    pub(crate) fn prepare_rejects_proxy_uri_in_regex_location() {
        let err = prepare_err(
            "http { server { listen 127.0.0.1:8080; location ~ ^/a { proxy_pass http://127.0.0.1:1/x; } } }",
        );
        assert!(
            err.starts_with("\"proxy_pass\" cannot have URI part"),
            "{err}"
        );
    }

    #[test]
    pub(crate) fn server_name_is_lowercased_at_prepare_time() {
        let cfg = parse_cfg(
            r#"
                http {
                    server {
                        listen 8080;
                        server_name Example.COM;
                        location / { return 200 "a"; }
                    }
                }
            "#,
        );
        let http = prepare(cfg).expect("prepare");
        assert_eq!(
            http.listens[0].servers[0].exact_names,
            vec![&b"example.com"[..]]
        );
    }

    #[test]
    pub(crate) fn locations_split_by_mode_and_prefix_sorted_by_length() {
        let cfg = parse_cfg(
            r#"
                http {
                    server {
                        listen 8080;
                        location = /exact { return 200 ""; }
                        location /short  { return 200 ""; }
                        location /longer-prefix { return 200 ""; }
                        location / { return 200 ""; }
                    }
                }
            "#,
        );
        let http = prepare(cfg).expect("prepare");
        let s = &http.listens[0].servers[0];
        assert_eq!(s.exact_locations.len(), 1);
        assert_eq!(s.exact_locations[0].pattern, b"/exact");
        let prefixes: Vec<&[u8]> = s.prefix_locations.iter().map(|l| l.pattern).collect();
        assert_eq!(
            prefixes,
            vec![&b"/longer-prefix"[..], &b"/short"[..], &b"/"[..]]
        );
    }

    #[test]
    pub(crate) fn prepare_keeps_named_locations_out_of_external_match_lists() {
        let cfg = parse_cfg(
            r#"
                http {
                    server {
                        listen 8080;
                        location / { return 200 "root"; }
                        location @fallback { return 200 "named"; }
                    }
                }
            "#,
        );
        let http = prepare(cfg).expect("prepare");
        let s = &http.listens[0].servers[0];
        assert_eq!(s.prefix_locations.len(), 1);
        assert_eq!(s.named_locations.len(), 1);
        assert_eq!(s.prefix_locations[0].pattern, b"/");
        assert_eq!(s.named_locations[0].pattern, b"@fallback");
    }

    #[test]
    fn sendfile_inherits_http_server_location_and_defaults_off() {
        // http-scope `sendfile` after the server block still applies, as in
        // nginx's merge: inheritance is resolved at prepare time.
        let cfg = parse_cfg(
            r#"
                http {
                    server {
                        listen 8080;
                        location /inherit { return 200; }
                        location /off { sendfile off; return 200; }
                        location /nested {
                            sendfile off;
                            return 200;
                            location /nested/child { return 200; }
                        }
                    }
                    server {
                        listen 8081;
                        sendfile off;
                        location /srv { return 200; }
                    }
                    sendfile on;
                }
            "#,
        );
        let http = prepare(cfg).expect("prepare");
        let find = |listen: usize, pat: &[u8]| {
            http.listens[listen].servers[0]
                .prefix_locations
                .iter()
                .find(|loc| loc.pattern == pat)
                .unwrap()
                .sendfile
        };
        assert!(find(0, b"/inherit"));
        assert!(!find(0, b"/off"));
        assert!(!find(0, b"/nested/child"));
        assert!(!find(1, b"/srv"));

        let default_off = prepare(parse_cfg(
            "http { server { listen 8082; location / { return 200; } } }",
        ))
        .expect("prepare");
        assert!(!default_off.listens[0].servers[0].prefix_locations[0].sendfile);
    }

    #[test]
    pub(crate) fn error_pages_inherit_and_replace_per_location() {
        let cfg = parse_cfg(
            r#"
                http {
                    server {
                        listen 8080;
                        error_page 404 /server-fallback;
                        location /inherit { return 404; }
                        location /replace {
                            error_page 404 /local-fallback;
                            return 404;
                        }
                    }
                }
            "#,
        );
        let http = prepare(cfg).expect("prepare");
        let server = &http.listens[0].servers[0];
        assert_eq!(server.prefix_locations.len(), 2);
        let replace = server
            .prefix_locations
            .iter()
            .find(|loc| loc.pattern == b"/replace")
            .unwrap();
        let inherit = server
            .prefix_locations
            .iter()
            .find(|loc| loc.pattern == b"/inherit")
            .unwrap();
        assert_eq!(replace.error_pages.len(), 1);
        assert_eq!(inherit.error_pages.len(), 1);

        let mut rendered = Vec::new();
        let ctx = RenderCtx {
            uri: b"/",
            request_uri: b"/",
            request_method: b"GET",
            host: b"",
            remote_addr: b"127.0.0.1",
            remote_port: 12345,
            remote_user: b"",
            server_name: b"",
            status: 404,
            args: b"",
            is_args: b"",
            scheme: b"http",
            hostname: b"",
            headers_raw: b"",
            underscores_in_headers: false,
            sent_headers: b"",
            connection_id: 0,
            connection_requests: 0,
            connection_time_us: 0,
            request_time_us: 0,
            server_port: 8080,
            request_port: &[],
            pipe: b'.',
            request_length: 0,
            request_body: b"",
            request_body_file: b"",
            bytes_sent: 0,
            body_bytes_sent: 0,
            epoch_secs: 0,
            epoch_ms: 0,
            server_name_captures: &[],
            rewrite_state: None,
            split_clients: None,
            maps: None,
            proxy_host: &[],
            upstream_headers: &[],
            upstream_response_length: None,
            upstream_response_time_ms: None,
            sent_trailers: &[],
            tls: None,
        };
        render_parts(replace.error_pages[0].target, &ctx, &mut rendered);
        assert_eq!(rendered, b"/local-fallback");

        rendered.clear();
        render_parts(inherit.error_pages[0].target, &ctx, &mut rendered);
        assert_eq!(rendered, b"/server-fallback");
    }

    #[test]
    pub(crate) fn head_internal_server_error_from_root_handler_has_no_body() {
        let root = unique_dir();
        std::os::unix::fs::symlink("loop", root.join("loop")).unwrap();

        let http = prepare(parse_cfg(&format!(
            "http {{ server {{ listen 80; location / {{ root {}; }} }} }}",
            root.display()
        )))
        .expect("prepare");
        let server = &http.listens[0].servers[0];
        let loc = MatchedLocation::from_prefix(&server.prefix_locations[0]);
        let req = phase::RequestCtx {
            method: Method::Head,
            method_bytes: b"HEAD",
            path: b"/loop",
            http_11: true,
            host: Some(b"h"),
            sni: None,
            listen_index: 0,
            remote_addr: b"127.0.0.1",
            remote_port: 12345,
            if_modified_since: None,
            if_unmodified_since: None,
            if_none_match: None,
            if_match: None,
            range: None,
            if_range: None,
            headers_raw: b"",
            connection_id: 0,
            connection_requests: 0,
            connection_time_us: 0,
            request_time_us: 0,
            request_port: &[],
            pipe: b'.',
            request_length: 0,
            epoch_secs: 0,
            epoch_ms: 0,
            body: &[],
            body_len: 0,
            body_file: &[],
            tls: None,
            refuse: None,
        };

        let rewrite_state = RewriteState::default();
        let r = match run_location_handler(
            http,
            server,
            loc,
            &req,
            b"/loop",
            None,
            None,
            &rewrite_state,
            None,
            false,
            None,
            &[],
            None,
        ) {
            Response::Owned(bytes) => bytes,
            Response::Prebuilt(bytes) => bytes.to_vec(),
            Response::File { .. } => panic!("error path should not return streamed file body"),
            Response::Reroute(_) => panic!("root handler should not reroute on metadata failure"),
            Response::Proxy(_) => panic!("root handler should not return proxy plan"),
        };
        assert!(
            std::str::from_utf8(&r)
                .unwrap()
                .starts_with("HTTP/1.1 500 Internal Server Error")
        );
        assert_eq!(response_body(&r), b"");

        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    pub(crate) fn inject_connection_header_adds_keep_alive() {
        let mut buf = b"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Length: 0\r\n\r\n".to_vec();
        inject_connection_header(&mut buf, false);
        let txt = std::str::from_utf8(&buf).unwrap();
        assert!(txt.contains("\r\nConnection: keep-alive\r\n\r\n"));
    }

    #[test]
    pub(crate) fn inject_connection_header_preserves_existing_header() {
        let base =
            b"HTTP/1.1 200 OK\r\nServer: nginx\r\nConnection: upgrade\r\nContent-Length: 0\r\n\r\n"
                .to_vec();
        let mut buf = base.clone();
        inject_connection_header(&mut buf, true);
        assert_eq!(buf, base);
    }

    #[test]
    pub(crate) fn scan_response_headers_finds_connection_close_and_keep_alive() {
        let buf = b"HTTP/1.1 200 OK\r\nServer: nginx\r\nConnection: Close\r\nKeep-Alive: timeout=3\r\n\r\n".to_vec();
        let scan = scan_response_headers(&buf).unwrap();
        assert!(scan.has_connection);
        assert!(scan.connection_is_close);
        assert!(scan.has_keep_alive);
        assert_eq!(scan.head_end + 4, buf.len());
    }

    #[test]
    pub(crate) fn scan_response_headers_ignores_non_close_connection_values() {
        let buf = b"HTTP/1.1 200 OK\r\nConnection: keep-alive\r\n\r\n".to_vec();
        let scan = scan_response_headers(&buf).unwrap();
        assert!(scan.has_connection);
        assert!(!scan.connection_is_close);
        assert!(!scan.has_keep_alive);
    }

    #[test]
    pub(crate) fn insert_header_at_advances_head_end() {
        let mut buf = b"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n".to_vec();
        let mut head_end = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
        insert_header_at(&mut buf, &mut head_end, b"Connection: close\r\n");
        assert_eq!(&buf[head_end..head_end + 4], b"\r\n\r\n");
        let txt = std::str::from_utf8(&buf).unwrap();
        assert!(txt.contains("\r\nConnection: close\r\n\r\n"));
    }

    #[test]
    pub(crate) fn format_keep_alive_header_writes_expected_line() {
        let mut buf = [0u8; 48];
        let n = format_keep_alive_header(42, &mut buf);
        assert_eq!(&buf[..n], b"Keep-Alive: timeout=42\r\n");
    }

    #[test]
    pub(crate) fn add_header_last_modified_empty_suppresses_builtin_header() {
        let response = b"HTTP/1.1 200 OK\r\nServer: nginx\r\nLast-Modified: Tue, 01 Jan 2030 00:00:00 GMT\r\nContent-Length: 0\r\n\r\n".to_vec();
        let headers: &[PreparedAddHeader] = &[PreparedAddHeader {
            name: b"Last-Modified",
            value: &[],
            always: false,
        }];
        let ctx = RenderCtx {
            uri: b"/",
            request_uri: b"/",
            request_method: b"GET",
            host: b"",
            remote_addr: b"127.0.0.1",
            remote_port: 12345,
            remote_user: b"",
            server_name: b"",
            status: 200,
            args: b"",
            is_args: b"",
            scheme: b"http",
            hostname: b"",
            headers_raw: b"",
            underscores_in_headers: false,
            sent_headers: b"",
            connection_id: 0,
            connection_requests: 0,
            connection_time_us: 0,
            request_time_us: 0,
            server_port: 8080,
            request_port: &[],
            pipe: b'.',
            request_length: 0,
            request_body: b"",
            request_body_file: b"",
            bytes_sent: 0,
            body_bytes_sent: 0,
            epoch_secs: 0,
            epoch_ms: 0,
            server_name_captures: &[],
            rewrite_state: None,
            split_clients: None,
            maps: None,
            proxy_host: &[],
            upstream_headers: &[],
            upstream_response_length: None,
            upstream_response_time_ms: None,
            sent_trailers: &[],
            tls: None,
        };
        let out = inject_add_headers(response, headers, &ctx);
        let text = std::str::from_utf8(&out).unwrap();
        assert!(!text.contains("Last-Modified:"));
    }

    #[test]
    pub(crate) fn add_header_last_modified_non_empty_replaces_builtin_value() {
        let response = b"HTTP/1.1 200 OK\r\nServer: nginx\r\nLast-Modified: Tue, 01 Jan 2030 00:00:00 GMT\r\nContent-Length: 0\r\n\r\n".to_vec();
        let headers: &[PreparedAddHeader] = &[PreparedAddHeader {
            name: b"Last-Modified",
            value: &[PreparedValuePart::Literal(b"Mon, 28 Sep 1970 06:00:00 GMT")],
            always: false,
        }];
        let ctx = RenderCtx {
            uri: b"/",
            request_uri: b"/",
            request_method: b"GET",
            host: b"",
            remote_addr: b"127.0.0.1",
            remote_port: 12345,
            remote_user: b"",
            server_name: b"",
            status: 200,
            args: b"",
            is_args: b"",
            scheme: b"http",
            hostname: b"",
            headers_raw: b"",
            underscores_in_headers: false,
            sent_headers: b"",
            connection_id: 0,
            connection_requests: 0,
            connection_time_us: 0,
            request_time_us: 0,
            server_port: 8080,
            request_port: &[],
            pipe: b'.',
            request_length: 0,
            request_body: b"",
            request_body_file: b"",
            bytes_sent: 0,
            body_bytes_sent: 0,
            epoch_secs: 0,
            epoch_ms: 0,
            server_name_captures: &[],
            rewrite_state: None,
            split_clients: None,
            maps: None,
            proxy_host: &[],
            upstream_headers: &[],
            upstream_response_length: None,
            upstream_response_time_ms: None,
            sent_trailers: &[],
            tls: None,
        };
        let out = inject_add_headers(response, headers, &ctx);
        let text = std::str::from_utf8(&out).unwrap();
        assert!(!text.contains("Tue, 01 Jan 2030"));
        assert!(text.contains("Last-Modified: Mon, 28 Sep 1970 06:00:00 GMT"));
    }

    #[test]
    pub(crate) fn add_header_sent_http_variable_reads_existing_response_header() {
        let response =
            b"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Length: 7\r\n\r\nexample".to_vec();
        let value = Box::leak(
            vec![PreparedValuePart::Var(Variable::SentHttp(
                "content-length".into(),
            ))]
            .into_boxed_slice(),
        );
        let headers: &[PreparedAddHeader] = &[PreparedAddHeader {
            name: b"X-Len",
            value,
            always: false,
        }];
        let ctx = RenderCtx {
            uri: b"/",
            request_uri: b"/",
            request_method: b"GET",
            host: b"",
            remote_addr: b"127.0.0.1",
            remote_port: 12345,
            remote_user: b"",
            server_name: b"",
            status: 200,
            args: b"",
            is_args: b"",
            scheme: b"http",
            hostname: b"",
            headers_raw: b"",
            underscores_in_headers: false,
            sent_headers: b"",
            connection_id: 0,
            connection_requests: 0,
            connection_time_us: 0,
            request_time_us: 0,
            server_port: 8080,
            request_port: &[],
            pipe: b'.',
            request_length: 0,
            request_body: b"",
            request_body_file: b"",
            bytes_sent: 0,
            body_bytes_sent: 0,
            epoch_secs: 0,
            epoch_ms: 0,
            server_name_captures: &[],
            rewrite_state: None,
            split_clients: None,
            maps: None,
            proxy_host: &[],
            upstream_headers: &[],
            upstream_response_length: None,
            upstream_response_time_ms: None,
            sent_trailers: &[],
            tls: None,
        };
        let out = inject_add_headers(response, headers, &ctx);
        let text = std::str::from_utf8(&out).unwrap();
        assert!(text.contains("X-Len: 7\r\n"));
    }
}
