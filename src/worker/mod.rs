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
    HttpConfig, IfGuard, IndexEntry, KeepaliveDisable, KeepaliveTimeout, Location, LogEscape,
    LogFormatDef, MapBlock, MapExactEntry, MapRegexEntry, MatchMode, PathMapping, ProxyPass,
    ProxySetHeader, RewriteFlag as ConfigRewriteFlag, RewriteOp, RewriteRule, Server, SplitClients,
    TryFiles, TryFilesFallback, TryFilesProbe, ValuePart, Variable,
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

/// Bumped on SIGUSR1; each worker reopens its access_log files before the
/// next write once it sees a new value (logrotate's `kill -USR1`).
pub(crate) static LOG_REOPEN_GEN: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// The `-e` file stderr goes to. Each worker has its own fd table
/// (`unshare(CLONE_FILES)`), so each one re-points its fd 2 on reopen.
pub(crate) static STDERR_LOG_PATH: std::sync::OnceLock<std::path::PathBuf> =
    std::sync::OnceLock::new();

/// Point fd 2 at `path` (append, created if missing).
pub(crate) fn redirect_stderr_to(path: &Path) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    // SAFETY: plain dup2 onto stderr; `file` stays open for the call.
    if unsafe { libc::dup2(file.as_raw_fd(), 2) } == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Before writing an error line: if SIGUSR1 came since this worker last
/// looked, re-point its stderr at the `-e` file.
pub(crate) fn reopen_stderr_if_needed() {
    let generation = LOG_REOPEN_GEN.load(std::sync::atomic::Ordering::Relaxed);
    STDERR_GEN.with(|seen| {
        if seen.get() == generation {
            return;
        }
        seen.set(generation);
        if let Some(path) = STDERR_LOG_PATH.get()
            && let Err(e) = redirect_stderr_to(path)
        {
            eprintln!("ruxen: [alert] reopening {}: {e}", path.display());
        }
    });
}

thread_local! {
    static STDERR_GEN: Cell<u64> = const { Cell::new(0) };
    /// This worker's access_log files (indexed by `file_index`) and the
    /// reopen generation they were opened at. An `Rc` so a write still in
    /// flight keeps the old files open across a reopen.
    static ACCESS_LOG_FILES: std::cell::RefCell<(u64, Option<std::rc::Rc<[AccessLogSink]>>)> =
        const { std::cell::RefCell::new((0, None)) };
}

/// Where one access_log's lines go in this worker.
pub(crate) enum AccessLogSink {
    File(AsyncFile),
    Syslog(crate::syslog::SyslogSocket),
}

fn open_access_logs(logs: &[PreparedAccessLog]) -> Result<std::rc::Rc<[AccessLogSink]>, String> {
    let mut opened: Vec<AccessLogSink> = Vec::with_capacity(logs.len());
    for log in logs {
        if let Some(peer) = log.syslog {
            let sock = crate::syslog::SyslogSocket::open(peer).map_err(|e| {
                format!(
                    "syslog \"{}\" failed ({})",
                    log.path.display(),
                    errno_text(&e)
                )
            })?;
            opened.push(AccessLogSink::Syslog(sock));
            continue;
        }
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
        opened.push(AccessLogSink::File(
            AsyncFile::from_std(std_file).map_err(open_failed)?,
        ));
    }
    Ok(opened.into())
}

/// `prepare` already opened every access_log once, so a failure here
/// means the file changed underneath us during startup; it is reported
/// like any other startup error.
pub(crate) fn init_access_logs_for_worker(logs: &[PreparedAccessLog]) -> Result<(), String> {
    if ACCESS_LOG_FILES.with(|cell| cell.borrow().1.is_some()) {
        return Ok(());
    }
    let files = open_access_logs(logs)?;
    let generation = LOG_REOPEN_GEN.load(std::sync::atomic::Ordering::Relaxed);
    ACCESS_LOG_FILES.with(|cell| *cell.borrow_mut() = (generation, Some(files)));
    Ok(())
}

/// This worker's access_log files, reopened first if SIGUSR1 arrived
/// since they were opened. `None` before `init_access_logs_for_worker`.
pub(crate) fn access_log_files(logs: &[PreparedAccessLog]) -> Option<std::rc::Rc<[AccessLogSink]>> {
    let generation = LOG_REOPEN_GEN.load(std::sync::atomic::Ordering::Relaxed);
    ACCESS_LOG_FILES.with(|cell| {
        let mut cell = cell.borrow_mut();
        if cell.1.is_some() && cell.0 != generation {
            cell.0 = generation;
            match open_access_logs(logs) {
                Ok(files) => cell.1 = Some(files),
                // nginx keeps writing to the old file when a reopen fails.
                Err(e) => eprintln!("ruxen: [alert] reopening access_log: {e}"),
            }
        }
        cell.1.clone()
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

/// Next request-body temp file number, nginx's `ngx_temp_number`: seeded
/// once per process, bumped by a jump when a name is taken.
static REQUEST_BODY_FILE_SEQ: AtomicU64 = AtomicU64::new(0);

/// Where request-body temp files go. Only the ruxen user can get at them:
/// the directory is created `0700` and each file `0600` with `O_EXCL`, as
/// nginx's `ngx_create_temp_file`. Without `client_body_temp_path` that is
/// a private directory of this process under the system temp directory,
/// made on first use: ruxen has no build-time prefix for nginx's default
/// `<prefix>/client_body_temp`.
pub(crate) struct BodyTempDir {
    /// `client_body_temp_path` (http scope), relative to the prefix.
    configured: Option<&'static Path>,
    /// The private directory, made on first use and again if it went
    /// away (a temp-directory cleaner): a new one, never the old name,
    /// which someone else could have taken by then.
    private: std::sync::Mutex<Option<std::path::PathBuf>>,
}

impl BodyTempDir {
    pub(crate) fn new(configured: Option<&'static Path>) -> Self {
        BodyTempDir {
            configured,
            private: std::sync::Mutex::new(None),
        }
    }

    /// The directory to create a file in. `gone`: the last one was
    /// missing, so the private directory is made anew.
    fn dir(&self, gone: bool) -> Option<std::path::PathBuf> {
        use std::os::unix::fs::DirBuilderExt;
        if let Some(dir) = self.configured {
            // nginx's ngx_create_paths: one level, 0700; an existing
            // directory is fine.
            match std::fs::DirBuilder::new().mode(0o700).create(dir) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(_) => return None,
            }
            return Some(dir.to_path_buf());
        }
        let mut private = self.private.lock().unwrap_or_else(|e| e.into_inner());
        if gone || private.is_none() {
            *private = make_private_dir();
        }
        private.clone()
    }

    /// Removes the private directory if nothing is left in it (files kept
    /// by `client_body_in_file_only on` stay, and so does it).
    pub(crate) fn remove_private_if_empty(&self) {
        let private = self.private.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(dir) = private.as_deref() {
            let _ = std::fs::remove_dir(dir);
        }
    }
}

/// `mkdtemp($TMPDIR/ruxen-<pid>-XXXXXX)`: a new directory, mode 0700.
fn make_private_dir() -> Option<std::path::PathBuf> {
    use std::os::unix::ffi::OsStringExt;
    let template = std::env::temp_dir().join(format!("ruxen-{}-XXXXXX", std::process::id()));
    let mut bytes = template.into_os_string().into_vec();
    bytes.push(0);
    // SAFETY: a NUL-terminated buffer we own, which mkdtemp edits in place.
    let made = unsafe { libc::mkdtemp(bytes.as_mut_ptr().cast()) };
    if made.is_null() {
        return None;
    }
    bytes.pop();
    Some(std::path::PathBuf::from(std::ffi::OsString::from_vec(
        bytes,
    )))
}

/// Creates a new request-body temp file in `temp`: `0600`, `O_EXCL` (a
/// name that exists, or a symlink there, is skipped, never opened), named
/// like nginx's (`0000000042`). Unless `persistent`, the name is removed
/// right away and only the open file remains, as nginx's
/// `ngx_create_temp_file`: nothing is left behind whatever happens to the
/// process.
fn new_body_file(temp: &BodyTempDir, persistent: bool) -> Option<SpilledBody> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut dir = temp.dir(false)?;
    let mut remade = false;
    if REQUEST_BODY_FILE_SEQ.load(Ordering::Relaxed) == 0 {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos() as u64)
            .unwrap_or(0)
            ^ ((std::process::id() as u64) << 20);
        let _ = REQUEST_BODY_FILE_SEQ.compare_exchange(
            0,
            seed % 1_000_000_000 + 1,
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
    }
    let mut step = 1;
    for _ in 0..64 {
        let n = REQUEST_BODY_FILE_SEQ.fetch_add(step, Ordering::Relaxed) % 10_000_000_000;
        let path = dir.join(format!("{n:010}"));
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
        {
            Ok(file) => {
                if !persistent {
                    let _ = std::fs::remove_file(&path);
                }
                let path_bytes = path.to_string_lossy().into_owned().into_bytes();
                return Some(SpilledBody {
                    file,
                    path,
                    path_bytes,
                    persistent,
                });
            }
            // Taken (another process, or a kept file): jump ahead, as
            // nginx's ngx_next_temp_number(1).
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => step = 0x10000 + n % 0x10000,
            // The directory went away: once, make it again.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && !remade => {
                remade = true;
                dir = temp.dir(true)?;
            }
            Err(_) => return None,
        }
    }
    None
}

/// A request body in a temp file. The file stays open: the proxy reads the
/// body back through it, from the start, for each attempt. Unless
/// `client_body_in_file_only on` made it persistent, its name is already
/// gone (`new_body_file`), and the space is freed when the last descriptor
/// closes. `$request_body_file` still shows the name, as in nginx.
pub(crate) struct SpilledBody {
    file: std::fs::File,
    path: std::path::PathBuf,
    /// Cached UTF-8 bytes of `path` for cheap `&[u8]` rendering.
    path_bytes: Vec<u8>,
    persistent: bool,
}

impl SpilledBody {
    pub(crate) fn path_bytes(&self) -> &[u8] {
        &self.path_bytes
    }

    /// A descriptor of its own for reading the body back.
    pub(crate) fn reader(&self) -> std::io::Result<std::fs::File> {
        self.file.try_clone()
    }

    /// After a failed write: a persistent file has a name to remove. (A
    /// non-persistent one has none, and removing by name could hit
    /// another request's file of the same name.)
    fn discard(&self) {
        if self.persistent {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

pub(crate) fn maybe_spill_request_body_to_file(
    body: &[u8],
    temp: &BodyTempDir,
    persistent: bool,
) -> Option<SpilledBody> {
    if body.len() <= REQUEST_BODY_FILE_THRESHOLD {
        return None;
    }
    let spilled = new_body_file(temp, persistent)?;
    if (&spilled.file).write_all(body).is_err() {
        spilled.discard();
        return None;
    }
    Some(spilled)
}

/// Request bodies up to this size stay in memory, where the proxy forwards
/// them without a copy; larger ones go to a temp file as they arrive, like
/// nginx past `client_body_buffer_size`.
pub(crate) const REQUEST_BODY_IN_MEMORY: usize = 1 << 20;

/// nginx's default `client_max_body_size`.
pub(crate) const DEFAULT_CLIENT_MAX_BODY_SIZE: u64 = 1 << 20;

/// Collects a request body: in memory up to `REQUEST_BODY_IN_MEMORY`, then
/// in a temp file (see `SpilledBody`).
pub(crate) struct BodySink<'t> {
    mem: Vec<u8>,
    file: Option<SpilledBody>,
    len: u64,
    temp: &'t BodyTempDir,
    /// `client_body_in_file_only on` for the location the request goes to.
    persistent: bool,
}

impl<'t> BodySink<'t> {
    pub(crate) fn with_capacity(expected: u64, temp: &'t BodyTempDir, persistent: bool) -> Self {
        BodySink {
            mem: Vec::with_capacity(expected.min(REQUEST_BODY_IN_MEMORY as u64) as usize),
            file: None,
            len: 0,
            temp,
            persistent,
        }
    }

    pub(crate) fn len(&self) -> u64 {
        self.len
    }

    /// Append `data`; `false` if the temp file couldn't be written.
    pub(crate) fn extend(&mut self, data: &[u8]) -> bool {
        if self.file.is_none() && self.mem.len() + data.len() > REQUEST_BODY_IN_MEMORY {
            let Some(spilled) = new_body_file(self.temp, self.persistent) else {
                return false;
            };
            if (&spilled.file).write_all(&self.mem).is_err() {
                spilled.discard();
                return false;
            }
            self.mem = Vec::new();
            self.file = Some(spilled);
        }
        let ok = match &self.file {
            Some(spilled) => {
                let ok = (&spilled.file).write_all(data).is_ok();
                if !ok {
                    spilled.discard();
                }
                ok
            }
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
            Some(spilled) => (Vec::new(), Some(spilled)),
            None => (self.mem, None),
        }
    }
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
    pub(crate) fn prepare_accepts_missing_root_and_alias() {
        // nginx resolves them per request (404 while missing); the anchor
        // is opened on first use.
        let http = prepare(parse_cfg(
            "http { server { listen 127.0.0.1:8080; root /nonexistent-ruxen-root; \
             location /a/ { alias /nonexistent-ruxen-alias/; } } }",
        ))
        .expect("prepare");
        let server = &http.listens[0].servers[0];
        let PreparedHandler::Root(root) = &server.prefix_locations[0].handler else {
            panic!("alias location is a root handler");
        };
        assert_eq!(root.root_fd, -1);
        assert_eq!(root.fd().unwrap_err().kind(), std::io::ErrorKind::NotFound);
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
            request_line: b"",
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
            upstream_states: &[],
            sent_trailers: &[],
            tls: None,
            conn: &phase::ConnInfo::NONE,
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
            request_line: b"",
            upstream: None,
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
            body_file: None,
            tls: None,
            conn: &phase::ConnInfo::NONE,
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
            request_line: b"",
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
            upstream_states: &[],
            sent_trailers: &[],
            tls: None,
            conn: &phase::ConnInfo::NONE,
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
            request_line: b"",
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
            upstream_states: &[],
            sent_trailers: &[],
            tls: None,
            conn: &phase::ConnInfo::NONE,
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
            request_line: b"",
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
            upstream_states: &[],
            sent_trailers: &[],
            tls: None,
            conn: &phase::ConnInfo::NONE,
        };
        let out = inject_add_headers(response, headers, &ctx);
        let text = std::str::from_utf8(&out).unwrap();
        assert!(text.contains("X-Len: 7\r\n"));
    }

    fn sockopt_int(fd: i32, level: i32, name: i32) -> i32 {
        let mut value: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: an int option into our own buffer.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                level,
                name,
                (&mut value as *mut libc::c_int).cast(),
                &mut len,
            )
        };
        assert_eq!(rc, 0, "getsockopt {level}/{name}");
        value
    }

    /// The `listen` options reach the socket, as nginx's
    /// ngx_configure_listening_sockets; they used to be parsed and dropped.
    #[test]
    pub(crate) fn listen_options_are_set_on_the_socket() {
        use std::os::fd::AsRawFd;
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let http = prepare(parse_cfg(&format!(
            "http {{ server {{ listen 127.0.0.1:{port} backlog=100 rcvbuf=64k sndbuf=32k \
             deferred fastopen=10 so_keepalive=30m:10:5; }} }}"
        )))
        .expect("prepare");
        let socket = listen_socket(http, &http.listens[0]).expect("listen");
        let fd = socket.as_raw_fd();
        // The kernel doubles SO_RCVBUF / SO_SNDBUF for bookkeeping.
        assert_eq!(
            sockopt_int(fd, libc::SOL_SOCKET, libc::SO_RCVBUF),
            128 * 1024
        );
        assert_eq!(
            sockopt_int(fd, libc::SOL_SOCKET, libc::SO_SNDBUF),
            64 * 1024
        );
        assert_eq!(sockopt_int(fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE), 1);
        assert_eq!(
            sockopt_int(fd, libc::IPPROTO_TCP, libc::TCP_KEEPIDLE),
            30 * 60
        );
        assert_eq!(sockopt_int(fd, libc::IPPROTO_TCP, libc::TCP_KEEPINTVL), 10);
        assert_eq!(sockopt_int(fd, libc::IPPROTO_TCP, libc::TCP_KEEPCNT), 5);
        assert!(sockopt_int(fd, libc::IPPROTO_TCP, libc::TCP_DEFER_ACCEPT) > 0);
        assert_eq!(sockopt_int(fd, libc::IPPROTO_TCP, libc::TCP_FASTOPEN), 10);
        drop(socket);

        // A second server with options on the same address is an error.
        let err = prepare(parse_cfg(&format!(
            "http {{ server {{ listen 127.0.0.1:{port} backlog=100; }} \
             server {{ listen 127.0.0.1:{port} rcvbuf=8k; }} }}"
        )))
        .err()
        .expect("duplicate options");
        assert!(err.contains("duplicate listen options"), "{err}");
    }
}
