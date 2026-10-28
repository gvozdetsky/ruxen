//! Per-worker monoio runtime: `run` builds the runtime + listeners,
//! `spawn_connection` enters the keep-alive request loop, and `handle`
//! drives one request through the phase pipeline.

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

/// An access-log write: `pwrite` at 0, as an `O_APPEND` file appends
/// anyway and io_uring takes 0 on a pipe as no offset. The epoll driver's
/// `pwrite` fails on a FIFO (ESPIPE): a plain `write` then (#523).
async fn write_log_file<T: monoio::buf::IoBuf>(file: &AsyncFile, data: T) -> std::io::Result<()> {
    let (res, data) = file.write_all_at(data, 0).await;
    match res {
        Err(e) if e.raw_os_error() == Some(libc::ESPIPE) => write_stream_log(file, &data),
        res => res,
    }
}

#[cold]
#[inline(never)]
fn write_stream_log<T: monoio::buf::IoBuf>(file: &AsyncFile, data: &T) -> std::io::Result<()> {
    use std::os::fd::{AsRawFd, FromRawFd};
    // SAFETY: borrows the open descriptor `file` owns for one write; the
    // ManuallyDrop keeps it from being closed here.
    let mut fd =
        std::mem::ManuallyDrop::new(unsafe { std::fs::File::from_raw_fd(file.as_raw_fd()) });
    // SAFETY: `read_ptr` and `bytes_init` describe the buffer's bytes.
    std::io::Write::write_all(&mut *fd, unsafe {
        std::slice::from_raw_parts(data.read_ptr(), data.bytes_init())
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn write_access_logs(
    logs: &'static [PreparedAccessLog],
    request_uri: &[u8],
    request_method: &[u8],
    request_line: &[u8],
    host: Option<&[u8]>,
    remote_addr: &[u8],
    remote_port: u16,
    remote_user: Option<&[u8]>,
    headers_raw: &[u8],
    response: &[u8],
    connection_id: u64,
    connection_requests: u64,
    request_id: u128,
    connection_time_us: u64,
    request_time_us: u64,
    server_port: u16,
    request_port: &[u8],
    pipe: u8,
    request_length: u64,
    bytes_sent: u64,
    body_bytes_sent: u64,
    epoch_secs: u64,
    epoch_ms: u16,
    tls: Option<&crate::tls::HandshakeInfo>,
    conn: &phase::ConnInfo,
    http: &'static PreparedHttp,
    // The request's processing result, for `$proxy_host` and the
    // upstream variables; `None` for a request refused before routing.
    meta: Option<&phase::ProcessMeta>,
    // `$uri`: the URI the request ended up with (after normalisation,
    // rewrites and internal redirects), or `None` to take the path of
    // `request_uri`.
    uri: Option<&[u8]>,
) {
    if logs.is_empty() {
        return;
    }
    // The client address the realip module set, if it did.
    let (remote_addr, remote_port, conn) = match meta.and_then(|m| m.realip.as_deref()) {
        Some(realip) => (&realip.addr[..], realip.port, &realip.conn),
        None => (remote_addr, remote_port, conn),
    };
    // The worker opens its access_log fds once at startup (see
    // `init_access_logs_for_worker`); if that hasn't run we have nothing to
    // write to, so bail quietly.
    let Some(files) = access_log_files(http.access_logs, http.error_logs) else {
        return;
    };

    let status = response_status(response);
    let args = request_args(request_uri);
    let uri: &[u8] = uri.unwrap_or_else(|| {
        request_uri
            .iter()
            .position(|&b| b == b'?')
            .map(|i| &request_uri[..i])
            .unwrap_or(request_uri)
    });
    // `$document_root` / `$request_filename` without a kept rewrite state:
    // the location's root alone, only when a log reads them (#363).
    let root_only = match meta {
        Some(m) if m.rewrite_state.is_none() && logs.iter().any(|l| l.reads_doc_root) => {
            super::response::root_only_state(m)
        }
        _ => None,
    };
    let ctx = RenderCtx {
        uri,
        request_uri,
        request_method,
        request_line,
        host: host.unwrap_or(b""),
        remote_addr,
        remote_port,
        remote_user: remote_user.unwrap_or(b""),
        server_name: b"",
        status,
        args,
        is_args: if args.is_empty() { b"" } else { b"?" },
        scheme: if tls.is_some() { b"https" } else { b"http" },
        hostname: hostname(),
        headers_raw,
        underscores_in_headers: false,
        sent_headers: response,
        connection_id,
        request_id,
        connection_requests,
        connection_time_us,
        request_time_us,
        server_port,
        request_port,
        pipe,
        request_length,
        request_body: &[],
        request_body_file: &[],
        bytes_sent,
        body_bytes_sent,
        epoch_secs,
        epoch_ms,
        // Access-log render runs after the response is on the wire; the
        // server-name regex captures from `find_config` no longer live by
        // this point. `$name` references in `log_format` therefore render
        // empty here, which mirrors nginx (where regex captures are
        // discarded after request termination).
        server_name_captures: &[],
        rewrite_state: meta
            .and_then(|m| m.rewrite_state.as_deref())
            .or(root_only.as_ref()),
        split_clients: Some(&http.split_clients),
        maps: Some(&http.maps),
        proxy_host: meta.map_or(&[][..], |m| m.proxy_host),
        proxy_tls: meta.is_some_and(|m| m.proxy_tls),
        upstream_headers: meta.map_or(&[][..], |m| &m.upstream_headers),
        upstream_states: meta.map_or(&[][..], |m| &m.upstream_states),
        upstream_cache_status: meta
            .and_then(|m| m.upstream_cache_status)
            .map_or(&[][..], |s| s.as_bytes()),
        sent_trailers: &[],
        tls,
        conn,
    };

    for log in logs.iter() {
        if let Some(cond) = log.condition {
            let mut rendered = Vec::with_capacity(32);
            render_parts(cond, &ctx, &mut rendered);
            if !condition_is_truthy(&rendered) {
                continue;
            }
        }

        if let Some(peer) = log.syslog {
            send_syslog_access_line(peer, &files, log, &ctx);
            continue;
        }
        let mut line = Vec::with_capacity(64);
        render_log_parts(log.format, log.escape, &ctx, &mut line);
        if line.is_empty() {
            line.push(b'-');
        }
        line.push(b'\n');

        // A path with variables: render, open, write, close (#303).
        if let Some(path) = log.path_vars {
            let error_logs = meta.map_or(&[][..], |m| m.log.error_logs);
            write_access_line_by_path(
                path,
                log.open_cache,
                meta.and_then(|m| m.doc_root),
                error_logs,
                &ctx,
                line,
            )
            .await;
            continue;
        }
        // `buffer=`: into this worker's buffer for the file (#151).
        if let Some(buffer) = log.buffer {
            write_buffered_access_line(http, &files, log, buffer, &line).await;
            continue;
        }

        // `write_at(_, 0)` is safe because the fd was opened with
        // `O_APPEND`: on Linux, pwrite ignores the offset for O_APPEND fds
        // and performs an atomic append under the inode lock (see
        // pwrite(2)). That gives us safe concurrent writes without any
        // per-file mutex.
        // `file_index` is the slot in `PreparedHttp::access_logs` (the
        // canonical list); the per-worker fd table is opened from that
        // same list so this lookup is always in range.
        let Some(AccessLogSink::File(file)) = files.get(log.file_index) else {
            continue;
        };
        let res = write_log_file(file, line).await;
        if let Err(e) = res {
            eprintln!(
                "ruxen: access_log write to {} failed: {e}",
                log.path.display()
            );
        }
    }
}

/// An access_log line for a path with variables, as nginx's
/// ngx_http_log_script_write: only when the location's root exists (so a
/// bogus `Host` can't make files), then to the rendered path, opened for
/// this line and closed after it.
#[cold]
#[inline(never)]
async fn write_access_line_by_path(
    path: &'static [PreparedValuePart],
    cache: Option<&'static crate::config::OpenLogFileCache>,
    doc_root: Option<&'static DocRoot>,
    error_logs: &'static [PreparedErrorLog],
    ctx: &RenderCtx<'_>,
    line: Vec<u8>,
) {
    if let Some(root) = doc_root
        && let Err(e) = std::fs::metadata(root.path)
    {
        write_worker_log(
            error_logs,
            ErrorLogLevel::Error,
            &format!(
                "testing \"{}\" existence failed ({}) while logging request",
                root.path.display(),
                errno_text(&e)
            ),
        );
        return;
    }
    let mut rendered = Vec::with_capacity(64);
    render_parts(path, ctx, &mut rendered);
    use std::os::unix::ffi::OsStrExt;
    let path = std::path::Path::new(std::ffi::OsStr::from_bytes(&rendered));
    // open_log_file_cache (#371): through this worker's cache.
    if let Some(cache) = cache {
        if let Err(e) = super::open_log_cache::write(cache, path, &line) {
            write_worker_log(
                error_logs,
                ErrorLogLevel::Error,
                &format!(
                    "open() \"{}\" failed ({}) while logging request",
                    path.display(),
                    errno_text(&e)
                ),
            );
        }
        return;
    }
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .and_then(AsyncFile::from_std);
    let file = match file {
        Ok(file) => file,
        Err(e) => {
            write_worker_log(
                error_logs,
                ErrorLogLevel::Error,
                &format!(
                    "open() \"{}\" failed ({}) while logging request",
                    path.display(),
                    errno_text(&e)
                ),
            );
            return;
        }
    };
    let res = write_log_file(&file, line).await;
    if let Err(e) = res {
        eprintln!("ruxen: access_log write to {} failed: {e}", path.display());
    }
}

/// A line for a buffered access_log: into the buffer, and whatever has to
/// go out now (a full buffer, a line larger than it). Cold: buffered logs
/// write rarely.
#[cold]
#[inline(never)]
async fn write_buffered_access_line(
    http: &'static PreparedHttp,
    files: &[AccessLogSink],
    log: &PreparedAccessLog,
    buffer: &'static PreparedLogBuffer,
    line: &[u8],
) {
    let appended = super::logbuf::append(buffer, log.file_index, line);
    if appended.arm_timer
        && let Some(ms) = buffer.flush_ms
    {
        super::panics::spawn_contained("an access_log flush timer", || {}, async move {
            monoio::time::sleep(Duration::from_millis(ms)).await;
            if super::panics::test_panic() == super::panics::TestPanic::Task {
                panic!("RUXEN_TEST_PANIC=task");
            }
            if let Some((file_index, data)) = super::logbuf::take_for_timer(buffer)
                && let Some(files) = access_log_files(http.access_logs, http.error_logs)
                && let Some(AccessLogSink::File(file)) = files.get(file_index)
            {
                let res = write_log_file(file, data).await;
                if let Err(e) = res {
                    eprintln!(
                        "ruxen: access_log write to {} failed: {e}",
                        buffer.path.display()
                    );
                }
            }
        });
    }
    let Some(AccessLogSink::File(file)) = files.get(log.file_index) else {
        return;
    };
    for data in appended.write {
        let res = write_log_file(file, data).await;
        if let Err(e) = res {
            eprintln!(
                "ruxen: access_log write to {} failed: {e}",
                log.path.display()
            );
        }
    }
}

/// `access_log syslog:…`: one datagram, the syslog header and the line
/// without a newline (nginx's ngx_http_log_handler). Cold: syslog access
/// logs are rare, and the send doesn't block.
#[cold]
#[inline(never)]
fn send_syslog_access_line(
    peer: &PreparedSyslogPeer,
    files: &[AccessLogSink],
    log: &PreparedAccessLog,
    ctx: &RenderCtx<'_>,
) {
    let Some(AccessLogSink::Syslog(sock)) = files.get(log.file_index) else {
        return;
    };
    let mut msg = Vec::with_capacity(128);
    crate::syslog::write_header(&mut msg, peer, peer.severity, crate::syslog::now_secs());
    let start = msg.len();
    render_log_parts(log.format, log.escape, ctx, &mut msg);
    if msg.len() == start {
        msg.push(b'-');
    }
    if let Err(e) = sock.send(&msg) {
        eprintln!(
            "ruxen: access_log send to {} failed: {e}",
            log.path.display()
        );
    }
}

/// `$uri` for the access log: nginx's `r->uri` at the end of the request,
/// which `phase::process` leaves in `url_scratch` (normalised, rewritten,
/// after internal redirects). Empty for a refused URI, as in nginx;
/// `None` (the request's own path) when processing never got that far.
fn final_uri<'a>(meta: &phase::ProcessMeta, url_scratch: &'a [u8]) -> Option<&'a [u8]> {
    if meta.invalid_uri {
        Some(b"")
    } else if url_scratch.is_empty() {
        None
    } else {
        Some(url_scratch)
    }
}

/// `line` without its trailing CRLF (or bare LF).
fn trim_crlf(line: &[u8]) -> &[u8] {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    line.strip_suffix(b"\r").unwrap_or(line)
}

/// What an early rejection needs for its access-log line.
pub(crate) struct ConnLogCtx<'a> {
    pub listen_index: usize,
    pub remote_addr: &'a [u8],
    pub remote_port: u16,
    pub connection_id: u64,
    pub connection_requests: u64,
    pub connection_start: Instant,
    pub tls: Option<&'a crate::tls::HandshakeInfo>,
    pub conn: &'a phase::ConnInfo,
}

/// Send a canned error for a request refused before a server is chosen (a
/// bad request line or header, an unsupported transfer coding, a body
/// over the limit), and log it as nginx does: to the access_log of the
/// address's default server. The connection is closed by the caller.
async fn reject_request<S: ConnIo>(
    stream: &mut S,
    scratch: &mut Vec<u8>,
    http: &'static PreparedHttp,
    response: &[u8],
    request_head: &[u8],
    refused: Refused,
    conn: &ConnLogCtx<'_>,
) {
    let listen = &http.listens[conn.listen_index];
    let server = &listen.servers[listen.default_server];
    let request_id = super::draw_request_id(http);
    scratch.clear();
    scratch.extend_from_slice(response);
    if !server.add_headers.is_empty() && refused != Refused::Body {
        *scratch = reject_add_headers(
            http,
            server,
            std::mem::take(scratch),
            request_head,
            refused == Refused::Headers,
            request_id,
            conn,
        );
    }
    inject_connection_header(scratch, true);
    refresh_date_header(scratch);
    let taken = std::mem::take(scratch);
    let len = taken.len();
    let head_len = taken
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map_or(len, |p| p + 4) as u64;
    // Under send_timeout, as nginx sends any response
    // (ngx_http_set_write_handler): a client that pipelined requests and
    // doesn't read can't hold the connection with a full socket buffer.
    // The timer starts far off, as a connection's do: `Timed` takes one
    // already set near the deadline for armed, and wouldn't poll it.
    let timer = std::pin::pin!(monoio::time::sleep(Duration::from_secs(3600)));
    let (res, _) = write_all_timed(stream, taken, len, timer, server.timeouts.send).await;
    let sent = res.map_or_else(|written| written, |()| len) as u64;

    log_before_routing(
        http,
        response,
        request_head,
        request_head.len() as u64,
        sent,
        sent.saturating_sub(head_len),
        request_id,
        conn,
    )
    .await;
}

/// What of a refused request was read.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Refused {
    /// Its request line was refused.
    Line,
    /// One of its headers.
    Headers,
    /// Its body, which nginx reads in the location, whose configuration
    /// then answers (not modelled: the default server's canned page).
    Body,
}

/// The default server's `add_header … always` on a request refused before
/// routing (#779): nginx answers it with that server's configuration, so
/// its header filter adds them. Rendered with what is known of the
/// request: the request line's variables once it parsed (`line_parsed`).
#[cold]
#[inline(never)]
fn reject_add_headers(
    http: &'static PreparedHttp,
    server: &PreparedServer,
    response: Vec<u8>,
    head: &[u8],
    line_parsed: bool,
    request_id: u128,
    conn: &ConnLogCtx<'_>,
) -> Vec<u8> {
    let line_end = head
        .iter()
        .position(|&b| b == b'\r' || b == b'\n')
        .unwrap_or(head.len());
    let request_line = if line_parsed { &head[..line_end] } else { b"" };
    let mut words = request_line.split(|&b| b == b' ').filter(|w| !w.is_empty());
    let method = words.next().unwrap_or(b"");
    let request_uri = words.next().unwrap_or(b"");
    let args = request_args(request_uri);
    let uri = request_uri
        .iter()
        .position(|&b| b == b'?')
        .map_or(request_uri, |i| &request_uri[..i]);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let ctx = RenderCtx {
        uri,
        request_uri,
        request_method: method,
        request_line,
        host: server.primary_server_name,
        remote_addr: conn.remote_addr,
        remote_port: conn.remote_port,
        remote_user: b"",
        server_name: server.primary_server_name,
        status: response_status(&response),
        args,
        is_args: if args.is_empty() { b"" } else { b"?" },
        scheme: if conn.tls.is_some() {
            b"https"
        } else {
            b"http"
        },
        hostname: hostname(),
        headers_raw: if line_parsed { &head[line_end..] } else { b"" },
        underscores_in_headers: server.underscores_in_headers,
        sent_headers: &[],
        connection_id: conn.connection_id,
        request_id,
        connection_requests: conn.connection_requests,
        connection_time_us: conn.connection_start.elapsed().as_micros() as u64,
        request_time_us: 0,
        server_port: server.listen_port,
        request_port: &[],
        pipe: b'.',
        request_length: head.len() as u64,
        request_body: &[],
        request_body_file: &[],
        bytes_sent: 0,
        body_bytes_sent: 0,
        epoch_secs: now.as_secs(),
        epoch_ms: now.subsec_millis() as u16,
        server_name_captures: &[],
        rewrite_state: None,
        split_clients: Some(&http.split_clients),
        maps: Some(&http.maps),
        proxy_host: &[],
        proxy_tls: false,
        upstream_headers: &[],
        upstream_states: &[],
        upstream_cache_status: &[],
        sent_trailers: &[],
        tls: conn.tls,
        conn: conn.conn,
    };
    super::response::inject_add_headers(response, server.add_headers, &ctx)
}

/// The access-log line of a request that ended before a server was chosen,
/// to the address's default server's logs: `response` holds the status,
/// `$request` is whatever of the request line arrived (nginx's then is up
/// to the first CR or LF).
#[allow(clippy::too_many_arguments)]
async fn log_before_routing(
    http: &'static PreparedHttp,
    response: &[u8],
    request_head: &[u8],
    request_length: u64,
    sent: u64,
    body_sent: u64,
    request_id: u128,
    conn: &ConnLogCtx<'_>,
) {
    let listen = &http.listens[conn.listen_index];
    let server = &listen.servers[listen.default_server];
    if server.access_logs.is_empty() {
        return;
    }
    let line_end = request_head
        .iter()
        .position(|&b| b == b'\r' || b == b'\n')
        .unwrap_or(request_head.len());
    let request_line = &request_head[..line_end];
    let mut words = request_line.split(|&b| b == b' ').filter(|w| !w.is_empty());
    let method = words.next().unwrap_or(b"");
    let uri = words.next().unwrap_or(b"");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    write_access_logs(
        server.access_logs,
        uri,
        method,
        request_line,
        None,
        conn.remote_addr,
        conn.remote_port,
        None,
        b"",
        response,
        conn.connection_id,
        conn.connection_requests,
        request_id,
        conn.connection_start.elapsed().as_micros() as u64,
        0,
        server.listen_port,
        b"",
        b'.',
        request_length,
        sent,
        body_sent,
        now.as_secs(),
        now.subsec_millis() as u16,
        conn.tls,
        conn.conn,
        http,
        None,
        None,
    )
    .await;
}

/// How a request head ended before it was complete (#509).
#[derive(Clone, Copy)]
enum HeadCut<'e> {
    /// `client_header_timeout` passed.
    TimedOut,
    /// The client closed the connection.
    Closed,
    /// The read failed.
    Failed(&'e std::io::Error),
}

/// A request whose head never completed, logged as nginx does
/// (ngx_http_process_request_line / _headers, ngx_http_read_request_header):
/// no response, an `[info]` line in the default server's error log, and an
/// access-log line with 408 when it timed out, 400 otherwise, `$bytes_sent`
/// 0 and `$request_length` the complete lines that came.
#[cold]
#[inline(never)]
async fn log_unfinished_head(
    http: &'static PreparedHttp,
    head: &[u8],
    rline_done: bool,
    cut: HeadCut<'_>,
    conn: &ConnLogCtx<'_>,
) {
    let listen = &http.listens[conn.listen_index];
    let server = &listen.servers[listen.default_server];
    let what = match cut {
        HeadCut::TimedOut => "client timed out (110: Connection timed out)".to_string(),
        HeadCut::Closed => "client prematurely closed connection".to_string(),
        HeadCut::Failed(e) => format!("recv() failed ({})", errno_text(e)),
    };
    let part = if rline_done { "headers" } else { "line" };
    let line_end = head
        .iter()
        .position(|&b| b == b'\r' || b == b'\n')
        .unwrap_or(head.len());
    // The Host header once its line is complete (nginx's
    // r->headers_in.host).
    let complete = head.iter().rposition(|&b| b == b'\n').map_or(0, |i| i + 1);
    let host = rline_done
        .then(|| lookup_request_header(&head[line_end.min(complete)..complete], b"host"))
        .flatten();
    write_error_log(
        server.error_logs,
        ErrorLogLevel::Info,
        &ErrorLogRequest {
            connection_id: conn.connection_id,
            client: conn.remote_addr,
            server: server.primary_server_name,
            request_line: &head[..line_end],
            host,
        },
        format!("{what} while reading client request {part}").as_bytes(),
        None,
    );
    let status = match cut {
        HeadCut::TimedOut => 408,
        _ => 400,
    };
    // `$request_length`: the lines parsed, as nginx's r->request_length.
    log_before_routing(
        http,
        &lost_head(status),
        head,
        complete as u64,
        0,
        0,
        super::draw_request_id(http),
        conn,
    )
    .await;
}

/// A response under `limit_rate`: the head, then the file body if any,
/// paced as nginx's write filter does. `false` if the connection failed.
#[allow(clippy::too_many_arguments)]
async fn write_response_paced<S: ConnIo>(
    stream: &mut S,
    scratch: &mut Vec<u8>,
    file_body: Option<phase::FileBody>,
    rate: u64,
    after: u64,
    request_start: Instant,
    mut timer: std::pin::Pin<&mut monoio::time::Sleep>,
    send_timeout: Duration,
) -> Result<(), u64> {
    let Some(mut pacer) = Pacer::new(rate, after, request_start) else {
        return Err(0);
    };
    let taken = std::mem::take(scratch);
    let len = taken.len();
    let (res, returned) =
        write_all_paced(stream, taken, len, &mut pacer, timer.as_mut(), send_timeout).await;
    *scratch = returned;
    if let Err(n) = res {
        return Err(n as u64);
    }
    match file_body {
        Some(body) => stream_file(stream, body, timer, send_timeout, Some(&mut pacer))
            .await
            .map_err(|n| len as u64 + n),
        None => Ok(()),
    }
}

/// The next request's first bytes if they are already in the socket after
/// a body read up to its end, as nginx's keep-alive handler reads at once
/// when the last read filled its buffer (`rev->ready`). A request queued
/// there is read while it is in the cache, not after a trip through the
/// ring (#757). `None`: wait in `idle_read`.
#[inline(never)]
fn read_queued<S: ConnIo>(
    stream: &mut S,
    buf: &mut [u8],
    state: &RuntimeState,
) -> Option<IdleRead> {
    if state.is_shutting_down() {
        return None;
    }
    match stream.read_queued(buf)? {
        Ok(n) if n > 0 => Some(IdleRead::Read(n)),
        _ => Some(IdleRead::Close),
    }
}

/// A read returns its `Vec` with the length set to the bytes it holds
/// (monoio's `IoBufMut::set_init` on a `Vec`), so after a 27-byte request
/// `buf` was 27 bytes long, and the next, longer head on the connection
/// came in pieces of that size, growing the buffer by half after each (a
/// 327-byte head took 8 reads). Back to the length it had: every byte below
/// it was initialized before the read, which only wrote into the buffer.
#[inline(always)]
fn restore_read_len(buf: &mut Vec<u8>, ptr: *const u8, len: usize) {
    // The same allocation, still at least `len` long in capacity: a read
    // that dropped the buffer gives back another one, left as it is.
    if buf.as_ptr() == ptr && buf.len() < len && len <= buf.capacity() {
        // SAFETY: `buf` held `len` initialized bytes in this allocation
        // before the read, which wrote only into it and shortened the
        // length; nothing below `len` is uninitialized.
        unsafe { buf.set_len(len) }
    }
}

/// Grow the read buffer for a head that doesn't fit (#482): by half
/// again, up to `limit` (`large_client_header_buffers`, `size × number`).
#[cold]
#[inline(never)]
fn grow_head_buffer(buf: &mut Vec<u8>, limit: usize) {
    // From `client_header_buffer_size` straight to `READ_BUF`, as nginx
    // moves a head that doesn't fit into a large buffer, then by half.
    let len = if buf.len() < READ_BUF {
        READ_BUF
    } else {
        buf.len() + buf.len() / 2
    };
    buf.resize(len.clamp(buf.len() + 1, limit), 0);
}

/// To `READ_BUF` for a client whose requests don't fit
/// `client_header_buffer_size` (#467).
#[cold]
#[inline(never)]
fn grow_read_buffer(buf: &mut Vec<u8>) {
    buf.resize(READ_BUF, 0);
}

/// Back to `READ_BUF` after a large head, once nothing of it is left.
#[cold]
#[inline(never)]
fn shrink_head_buffer(buf: &mut Vec<u8>) {
    buf.truncate(READ_BUF);
    buf.shrink_to_fit();
}

/// What nginx refuses while it reads the request line, before any header
/// (#807): a line past `large_client_header_buffers` (414), or a target
/// that doesn't normalise (400). Checked only on the way to a refusal for
/// the headers. `target`: its range in `head` (`None`: an implicit `/`).
#[cold]
#[inline(never)]
fn line_refusal(
    head: &[u8],
    target: Option<(usize, usize)>,
    max_line: usize,
) -> Option<LineRefusal> {
    let line_end = head.iter().position(|&b| b == b'\n').unwrap_or(head.len());
    let line = head[..line_end]
        .strip_suffix(b"\r")
        .unwrap_or(&head[..line_end]);
    if line.len() > max_line {
        return Some(LineRefusal::TooLong);
    }
    // CONNECT's target is an authority, not a path.
    if head.starts_with(b"CONNECT ") {
        return None;
    }
    let target = &head[target?.0..target?.1];
    let mut out = Vec::new();
    crate::uri::normalize_with(target, false, &mut out)
        .is_err()
        .then_some(LineRefusal::BadTarget(target.first() == Some(&b'/')))
}

/// See `line_refusal`.
enum LineRefusal {
    TooLong,
    /// A target that doesn't normalise; `true`: a path, where nginx has the
    /// method (`$request_method`), not a line it couldn't parse (`*`, `x`).
    BadTarget(bool),
}

/// The 414 or 400 of `line_refusal`, from the default server, as nginx
/// answers it while reading the request line.
#[cold]
#[inline(never)]
async fn refuse_line<S: ConnIo>(
    stream: &mut S,
    scratch: &mut Vec<u8>,
    http: &'static PreparedHttp,
    head: &[u8],
    refusal: LineRefusal,
    conn: &ConnLogCtx<'_>,
) {
    let line_parsed = match refusal {
        LineRefusal::TooLong => {
            head_too_large(stream, scratch, http, head, None, conn).await;
            return;
        }
        LineRefusal::BadTarget(line_parsed) => line_parsed,
    };
    // Before the headers: no host in the line.
    let line_end = head
        .iter()
        .position(|&b| b == b'\r' || b == b'\n')
        .unwrap_or(head.len());
    refused_head_log(
        http,
        conn,
        &head[..line_end],
        None,
        "client sent invalid request while reading client request line",
    );
    let (method, refused) = if line_parsed {
        (head_method(head), Refused::Headers)
    } else {
        (Method::Other, Refused::Line)
    };
    reject_request(
        stream,
        scratch,
        http,
        http.bad_request.pick(method),
        head,
        refused,
        conn,
    )
    .await;
}

/// `line_refusal` for a parsed request.
#[cold]
#[inline(never)]
fn parsed_line_refusal(head: &[u8], req: &http::Request, max_line: usize) -> Option<LineRefusal> {
    let target = (!req.implicit_path && req.absolute_query.is_none())
        .then_some((req.path_start, req.path_end));
    line_refusal(head, target, max_line)
}

/// The start of the first line of `head` longer than `max` bytes, without
/// its line end (0 for the request line), or of the line that takes the
/// head past `total`, as nginx's large buffers would run out there.
#[cold]
#[inline(never)]
fn overlong_head_line(head: &[u8], max: usize, total: usize) -> Option<usize> {
    let mut start = 0;
    for line in head.split(|&b| b == b'\n') {
        let len = line.strip_suffix(b"\r").unwrap_or(line).len();
        if len > max || (start > 0 && start + line.len() > total) {
            return Some(start);
        }
        start += line.len() + 1;
    }
    None
}

/// Whether a header block has more than `max` lines.
#[cold]
#[inline(never)]
fn too_many_header_lines(block: &[u8], max: usize) -> bool {
    block.iter().filter(|&&b| b == b'\n').count() > max
}

/// A request with more header lines than `max_headers` (#584), answered
/// and logged as nginx 1.30 does (`src/http/ngx_http_request.c:1497`,
/// `src/http/v2/ngx_http_v2.c:1828`): `[info] client sent too many header
/// lines` and 400 "Request Header Or Cookie Too Large" (494).
#[cold]
#[inline(never)]
async fn many_header_lines<S: ConnIo>(
    stream: &mut S,
    scratch: &mut Vec<u8>,
    http: &'static PreparedHttp,
    head: &[u8],
    conn: &ConnLogCtx<'_>,
) {
    let listen = &http.listens[conn.listen_index];
    let server = &listen.servers[listen.default_server];
    let request_end = head
        .iter()
        .position(|&b| b == b'\r' || b == b'\n')
        .unwrap_or(head.len());
    let host = lookup_request_header(&head[request_end..], b"host");
    write_error_log(
        server.error_logs,
        ErrorLogLevel::Info,
        &ErrorLogRequest {
            connection_id: conn.connection_id,
            client: conn.remote_addr,
            server: server.primary_server_name,
            request_line: &head[..request_end],
            host,
        },
        b"client sent too many header lines while reading client request headers",
        None,
    );
    let response = http.header_too_large.pick(head_method(head));
    reject_request(
        stream,
        scratch,
        http,
        response,
        head,
        Refused::Headers,
        conn,
    )
    .await;
    linger_after_reject(stream, scratch).await;
}

/// nginx's `[info]` line for a request refused while its head is read
/// (#663): `client sent invalid method while reading client request
/// line`, `client sent invalid header line: "…"`, …, with the default
/// server's error log, as nginx logs them before a server is chosen.
#[cold]
#[inline(never)]
fn refused_head_log(
    http: &'static PreparedHttp,
    conn: &ConnLogCtx<'_>,
    request_line: &[u8],
    host: Option<&[u8]>,
    message: &str,
) {
    let listen = &http.listens[conn.listen_index];
    let server = &listen.servers[listen.default_server];
    write_error_log(
        server.error_logs,
        ErrorLogLevel::Info,
        &ErrorLogRequest {
            connection_id: conn.connection_id,
            client: conn.remote_addr,
            server: server.primary_server_name,
            request_line,
            host,
        },
        message.as_bytes(),
        None,
    );
}

/// Why the parser refused `head` (`http::refusal_reason`), logged. True
/// for an HTTP version past 1, which nginx answers with 505.
#[cold]
#[inline(never)]
fn invalid_head_log(
    http: &'static PreparedHttp,
    conn: &ConnLogCtx<'_>,
    head: &[u8],
    h2: bool,
) -> bool {
    let refusal = http::refusal_reason(head, h2);
    refused_head_log(
        http,
        conn,
        refusal.request_line,
        refusal.host,
        &refusal.message,
    );
    refusal.version_not_supported
}

/// A parsed head refused for its `Host` or `Transfer-Encoding`, logged.
#[cold]
#[inline(never)]
fn refused_parsed_head_log(
    http: &'static PreparedHttp,
    conn: &ConnLogCtx<'_>,
    head: &[u8],
    message: &str,
) {
    let request_end = head
        .iter()
        .position(|&b| b == b'\r' || b == b'\n')
        .unwrap_or(head.len());
    let host = lookup_request_header(&head[request_end..], b"host");
    refused_head_log(http, conn, &head[..request_end], host, message);
}

/// A request head over `large_client_header_buffers` (#482), answered and
/// logged as nginx does (`src/http/ngx_http_request.c:1189`, `:1370`): a
/// request line that doesn't fit gets 414 and `client sent too long URI`;
/// a header line, or a head past `size × number`, 400 "Request Header Or
/// Cookie Too Large" (494) and `client sent too long header line`.
/// `header_line`: where the header line that didn't fit starts, `None`
/// for the request line.
#[cold]
#[inline(never)]
async fn head_too_large<S: ConnIo>(
    stream: &mut S,
    scratch: &mut Vec<u8>,
    http: &'static PreparedHttp,
    head: &[u8],
    header_line: Option<usize>,
    conn: &ConnLogCtx<'_>,
) {
    let listen = &http.listens[conn.listen_index];
    let server = &listen.servers[listen.default_server];
    let request_end = head
        .iter()
        .position(|&b| b == b'\r' || b == b'\n')
        .unwrap_or(head.len());
    // nginx's NGX_MAX_ERROR_STR - 300.
    const SHOWN: usize = 2048 - 300;
    let request_line = &head[..request_end.min(SHOWN)];
    let (message, response) = match header_line {
        None => (
            "client sent too long URI while reading client request line".to_string(),
            http.uri_too_large.pick(head_method(head)),
        ),
        Some(start) => {
            let line = &head[start..];
            let line = &line[..line
                .iter()
                .position(|&b| b == b'\r' || b == b'\n')
                .unwrap_or(line.len())
                .min(SHOWN)];
            (
                format!(
                    "client sent too long header line: \"{}...\" while reading client request \
                     headers",
                    String::from_utf8_lossy(line)
                ),
                http.header_too_large.pick(head_method(head)),
            )
        }
    };
    write_worker_log(
        server.error_logs,
        ErrorLogLevel::Info,
        &format!(
            "*{} {message}, client: {}, server: {}, request: \"{}\"",
            conn.connection_id,
            String::from_utf8_lossy(conn.remote_addr),
            String::from_utf8_lossy(server.primary_server_name),
            String::from_utf8_lossy(request_line),
        ),
    );
    let refused = match header_line {
        None => Refused::Line,
        Some(_) => Refused::Headers,
    };
    reject_request(stream, scratch, http, response, head, refused, conn).await;
    linger_after_reject(stream, scratch).await;
}

/// After a head refused for its size the rest of it is likely still
/// coming: a close with it unread would be a reset, which can lose the
/// response, so it is read and dropped first, as nginx's lingering close
/// does (#780).
#[cold]
#[inline(never)]
async fn linger_after_reject<S: ConnIo>(stream: &mut S, scratch: &mut Vec<u8>) {
    if !stream.h2() {
        Box::pin(lingering_close(stream, scratch)).await;
    }
}

/// The method of a refused head, once the request line got past it: a
/// `HEAD` gets its error without a body (#783).
#[cold]
#[inline(never)]
fn head_method(head: &[u8]) -> Method {
    match head.iter().position(|&b| b == b' ') {
        Some(end) => http::classify_method(&head[..end]),
        None => Method::Other,
    }
}

/// A response head for the access log when a timed-out write took the
/// real one with it (#410): the status line, which `$status` reads.
#[cold]
#[inline(never)]
fn lost_head(status: u16) -> Vec<u8> {
    format!("HTTP/1.1 {status:03} \r\n\r\n").into_bytes()
}

/// nginx's `[info]` line when the client goes away while the upstream is
/// awaited (ngx_http_upstream_check_broken_connection).
#[cold]
#[inline(never)]
fn client_closed_log(meta: &phase::ProcessMeta, ctx: &phase::RequestCtx<'_>) {
    write_error_log(
        meta.log.error_logs,
        ErrorLogLevel::Info,
        &ErrorLogRequest::new(ctx, meta.server_name).with_realip(meta),
        b"client prematurely closed connection, so upstream connection is closed too while sending request to upstream",
        None,
    );
}

/// nginx's `[info]` line when an HTTP/2 request's `:authority` and `Host`
/// differ (ngx_http_v2_run_request), in the error log of the server that
/// refused it. Its `host:` is the `:authority`, the only Host the head
/// carries; nginx's is the client's `Host`.
#[cold]
#[inline(never)]
fn authority_mismatch_log(meta: &phase::ProcessMeta, ctx: &phase::RequestCtx<'_>) {
    write_error_log(
        meta.log.error_logs,
        ErrorLogLevel::Info,
        &ErrorLogRequest::new(ctx, meta.server_name).with_realip(meta),
        b"client sent \":authority\" and \"Host\" headers with different values \
          while reading client request headers",
        None,
    );
}

async fn settle_proxy_response(
    http: &'static PreparedHttp,
    ctx: &phase::RequestCtx<'_>,
    url_scratch: &mut Vec<u8>,
    response: Response,
    process_meta: phase::ProcessMeta,
    // The client, watched while the upstream is awaited (`None`: nobody
    // waits for the answer, as for post_action).
    client: Option<&dyn super::client_watch::WatchClient>,
) -> (Response, phase::ProcessMeta) {
    let Response::Proxy(plan) = response else {
        return (response, process_meta);
    };
    // `$uri` for the response's add_header / proxy_redirect / error page.
    let uri = final_uri(&process_meta, url_scratch);

    // The first pass is inline (an `async fn` layer here costs on the
    // proxy hot path); later passes, after an internal redirect, are in
    // `settle_redirected`.
    let response_rules = plan.response;
    let server_bytes = plan.server_bytes;
    let recursive_error_pages = plan.response.recursive_error_pages;
    let error_pages: &'static [PreparedErrorPage] = if plan.in_error_page {
        &[]
    } else {
        plan.response.error_pages
    };
    let error_page_status = plan.error_page_status;
    let mut report = crate::proxy::ProxyReport::default();
    // nginx's ngx_http_upstream_check_broken_connection: a client that
    // closes ends the exchange, and with it the upstream connection (the
    // proxy future is dropped).
    let client = client.filter(|_| !plan.ignore_client_abort);
    let late_limit_rate = plan.response.limit_rate.map(|parts| {
        let meta = &process_meta;
        move |status: u16, headers: &[u8]| {
            super::render_proxy_limit_rate(parts, http, ctx, meta, status, headers, uri)
        }
    });
    let upstream_resp = {
        let late = late_limit_rate
            .as_ref()
            .map(|late| late as crate::proxy::LateLimitRate<'_>);
        let proxy = std::pin::pin!(crate::proxy::run_proxy(plan, &mut report, late));
        let watched = if process_meta.limit_conn_held.is_some() {
            super::client_watch::Watched::at_once(proxy, client)
        } else {
            super::client_watch::Watched::new(proxy, client)
        };
        watched.await
    };
    let Some(upstream_resp) = upstream_resp else {
        client_closed_log(&process_meta, ctx);
        // The attempt cut short is in the log, `$upstream_response_time`
        // up to the close, as ngx_http_upstream_finalize_request fills it.
        if let (Some(state), Some(started)) = (report.states.last_mut(), report.attempt_started)
            && state.response_ms.is_none()
        {
            state.response_ms = Some(started.elapsed().as_millis() as u64);
        }
        let mut process_meta = process_meta;
        process_meta.upstream_states = report.states;
        // The limit_conn counts go back now, as nginx frees them when it
        // finalizes the request, not once the connection is torn down.
        process_meta.limit_conn_held = None;
        return (Response::Prebuilt(super::CLIENT_CLOSED), process_meta);
    };
    if !report.failures.is_empty() {
        write_upstream_error_log(
            &process_meta.log,
            &ErrorLogRequest::new(ctx, process_meta.server_name).with_realip(&process_meta),
            &report.failures,
        );
    }
    let upstream_resp = if error_pages.is_empty() {
        upstream_resp
    } else {
        intercept_with_report(
            upstream_resp,
            &mut report,
            error_pages,
            recursive_error_pages,
            http,
            ctx,
            &process_meta,
            server_bytes,
            uri,
        )
    };
    let mut carried = Vec::new();
    let (reroute, as_get) = match upstream_resp {
        // `proxy_intercept_errors` or an `error_page` for the proxy's own
        // 502/504.
        Response::Reroute(reroute) => (reroute, false),
        // nginx's ngx_http_upstream_process_headers: the response is dropped
        // and the request redirected internally, as a GET.
        _ if report.accel.as_ref().is_some_and(|a| a.redirect.is_some()) => {
            accel_carried_headers(&report.upstream_headers, &mut carried);
            if let Some(rules) = response_rules.cookies {
                carried = super::rewrite_carried_cookies(
                    carried,
                    rules,
                    http,
                    ctx,
                    &process_meta,
                    &report.upstream_headers,
                    uri,
                );
            }
            match accel_redirect(&mut report) {
                Ok(reroute) => (reroute, !matches!(ctx.method, Method::Head)),
                Err(target) => match refuse_unsafe_accel(
                    &target,
                    &mut report,
                    error_pages,
                    recursive_error_pages,
                    http,
                    ctx,
                    &process_meta,
                    server_bytes,
                    uri,
                ) {
                    Response::Reroute(reroute) => (reroute, false),
                    response => {
                        let mut process_meta = process_meta;
                        process_meta.upstream_states = report.states;
                        process_meta.upstream_headers = report.upstream_headers;
                        process_meta.upstream_cache_status = report.cache_status;
                        return (carry_accel_headers(response, &carried, false), process_meta);
                    }
                },
            }
        }
        upstream_resp => {
            return finish_proxy_response(
                upstream_resp,
                report,
                response_rules,
                error_page_status,
                http,
                ctx,
                process_meta,
                uri,
            );
        }
    };
    // Cold. Boxed so its state doesn't grow every connection's future.
    let limit_rate = report.accel.as_ref().and_then(|a| a.limit_rate);
    let trail = crate::proxy::UpstreamTrail {
        states: report.states,
        headers: report.upstream_headers,
        cache_status: report.cache_status,
    };
    // The counts limit_conn took stay held through the redirect (#95).
    let held = process_meta.limit_conn_held.clone();
    let (response, mut meta) = Box::pin(settle_redirected(
        http,
        ctx,
        url_scratch,
        reroute,
        trail,
        carried,
        as_get,
        limit_rate,
    ))
    .await;
    if meta.limit_conn_held.is_none() {
        meta.limit_conn_held = held;
    }
    (response, meta)
}

/// `intercept_proxy_error` with this pass's attempts and upstream headers
/// visible to the error page's `$upstream_*`.
#[allow(clippy::too_many_arguments)]
fn intercept_with_report(
    upstream_resp: Response,
    report: &mut crate::proxy::ProxyReport,
    error_pages: &'static [PreparedErrorPage],
    recursive_error_pages: bool,
    http: &'static PreparedHttp,
    ctx: &phase::RequestCtx<'_>,
    process_meta: &phase::ProcessMeta,
    server_bytes: &'static [u8],
    uri: Option<&[u8]>,
) -> Response {
    let trail = crate::proxy::UpstreamTrail {
        states: std::mem::take(&mut report.states),
        headers: std::mem::take(&mut report.upstream_headers),
        cache_status: report.cache_status,
    };
    let pass_ctx = phase::RequestCtx {
        upstream: Some(&trail),
        ..*ctx
    };
    let response = intercept_proxy_error(
        upstream_resp,
        error_pages,
        recursive_error_pages,
        http,
        &pass_ctx,
        process_meta,
        server_bytes,
        uri,
    );
    report.states = trail.states;
    report.upstream_headers = trail.headers;
    response
}

/// The upstream response goes to the client: apply `proxy_redirect` and
/// the location's `add_header` / `add_trailer` / `expires`, with the
/// upstream headers visible to `$upstream_http_*` / `$upstream_cookie_*`.
#[allow(clippy::too_many_arguments)] // hot path: a parameter struct needs ABBA numbers first
fn finish_proxy_response(
    upstream_resp: Response,
    mut report: crate::proxy::ProxyReport,
    response_rules: &'static ProxyResponseRules,
    error_page_status: Option<phase::ErrorPageStatus>,
    http: &'static PreparedHttp,
    ctx: &phase::RequestCtx<'_>,
    mut process_meta: phase::ProcessMeta,
    // `$uri`: the current URI (`final_uri`).
    uri: Option<&[u8]>,
) -> (Response, phase::ProcessMeta) {
    process_meta.upstream_states = std::mem::take(&mut report.states);
    process_meta.upstream_cache_status = report.cache_status;
    process_meta.range_allow = report.range_allow;
    // Not for the proxy's own 502/504 (prebuilt at startup, so its `Date`
    // is old): nginx writes its own `Date` there.
    process_meta.keep_upstream_date =
        report.passes_date && !matches!(upstream_resp, Response::Prebuilt(_));
    // A relayed body (#88): the head is filtered as an `Owned` response
    // with no body, then goes back with the upstream connection.
    // A body in the cache file (#515) likewise: the head is filtered,
    // the ranges cut the file.
    let (upstream_resp, relayed, file) = match upstream_resp {
        Response::ProxyStream(mut body) => (
            Response::Owned(std::mem::take(&mut body.head)),
            Some(body),
            None,
        ),
        Response::File { headers, body } if process_meta.proxy_add_trailers.is_empty() => {
            (Response::Owned(headers), None, Some(body))
        }
        // Trailers go after a chunked body built in memory.
        Response::File { headers, body } => (read_file_body(headers, body, ctx), None, None),
        other => (other, None, None),
    };
    // Reached through an `error_page` without `=`: the error's status
    // (#675). Not the proxy's own 502/504, which stand as nginx's special
    // response sets them.
    let upstream_resp = match (error_page_status, upstream_resp) {
        (Some(forced), Response::Owned(head)) => {
            Response::Owned(error_page_status_on_proxied(head, forced))
        }
        (_, upstream_resp) => upstream_resp,
    };
    // `X-Accel-Limit-Rate` is the response's `limit_rate`.
    if let Some(rate) = report.accel.as_ref().and_then(|a| a.limit_rate) {
        process_meta.limit_rate =
            phase::ResponseLimit::with_rate(process_meta.limit_rate.take(), rate);
    }
    // nginx rewrites Location / Refresh while processing the upstream
    // header, before the add_header filter sees the response.
    let upstream_resp = if report.redirect_header {
        rewrite_proxy_redirects(
            upstream_resp,
            response_rules.redirects,
            http,
            ctx,
            &process_meta,
            &report.upstream_headers,
            uri,
        )
    } else {
        upstream_resp
    };
    let upstream_resp = match response_rules.cookies {
        Some(rules) => super::rewrite_proxy_cookies(
            upstream_resp,
            rules,
            http,
            ctx,
            &process_meta,
            &report.upstream_headers,
            uri,
        ),
        None => upstream_resp,
    };
    // The range filter (#370). nginx runs it after gzip, which then
    // leaves the response alone, and before the chunked filter writes
    // the trailers: here before `add_trailer`, on what gzip won't compress.
    let (upstream_resp, file) = if process_meta.range_allow != super::range::RangeAllow::No
        && may_cut_ranges(&process_meta, ctx.http_11, ctx.headers_raw, &upstream_resp)
    {
        match (upstream_resp, file) {
            (Response::Owned(head), Some(body)) => {
                match range_filter_file(head, body, &process_meta, ctx) {
                    Response::File { headers, body } => (Response::Owned(headers), Some(body)),
                    other => (other, None),
                }
            }
            (upstream_resp, file) => (
                range_filter(upstream_resp, relayed.is_some(), &process_meta, ctx),
                file,
            ),
        }
    } else {
        (upstream_resp, file)
    };
    let response = apply_proxy_add_headers(
        upstream_resp,
        http,
        ctx,
        &process_meta,
        &report.upstream_headers,
        uri,
    );
    let response = match (response, relayed, file) {
        (Response::Owned(head), Some(mut body), _) => {
            body.head = head;
            Response::ProxyStream(body)
        }
        (Response::Owned(headers), _, Some(body)) => Response::File { headers, body },
        (response, ..) => response,
    };
    // The header is filtered. A buffered body is already read, so the
    // upstream request is over; a relayed one ends after the write, where
    // its timing is filled in.
    if !matches!(response, Response::ProxyStream(_)) {
        crate::proxy::finish_answer(&mut process_meta.upstream_states);
    }
    process_meta.upstream_headers = report.upstream_headers;
    (response, process_meta)
}

/// A proxied response's head with the status of the `error_page` that led
/// to it, as nginx's ngx_http_send_header puts `r->err_status` over the
/// upstream's (#675).
#[cold]
#[inline(never)]
fn error_page_status_on_proxied(head: Vec<u8>, forced: phase::ErrorPageStatus) -> Vec<u8> {
    let status = response_status(&head);
    match effective_error_page_status(status, Some(forced)) {
        same if same == status => head,
        other => rewrite_response_status(head, other),
    }
}

/// The range filter may see `response` (#370): gzip won't compress it.
#[cold]
#[inline(never)]
fn may_cut_ranges(
    meta: &phase::ProcessMeta,
    http_11: bool,
    headers_raw: &[u8],
    response: &Response,
) -> bool {
    let Some(gz) = meta.gzip else {
        return true;
    };
    let bytes: &[u8] = match response {
        Response::Owned(b) => b,
        Response::ProxyStream(s) => &s.head,
        _ => return false,
    };
    !super::gzip::compresses(
        gz,
        &super::gzip::GzipRequest::from_headers(http_11, headers_raw),
        bytes,
    )
}

/// nginx's range filter over a proxied or cached response (#370): an
/// in-memory one is cut, a relayed one only says it could be.
#[cold]
#[inline(never)]
fn range_filter(
    response: Response,
    relayed: bool,
    meta: &phase::ProcessMeta,
    ctx: &phase::RequestCtx<'_>,
) -> Response {
    let req = super::range::RangeRequest {
        range: ctx.range,
        if_range: ctx.if_range,
        head_only: matches!(ctx.method, Method::Head),
    };
    match response {
        Response::Owned(head) if relayed => {
            Response::Owned(super::range::relayed_head(head, meta.max_ranges))
        }
        Response::Owned(bytes) => Response::Owned(super::range::filter(
            bytes,
            meta.range_allow,
            meta.max_ranges,
            req,
            |len, server| super::range::not_satisfiable(len, req.head_only, server),
        )),
        other => other,
    }
}

/// `range_filter` for a cached response whose body is in its file.
#[cold]
#[inline(never)]
fn range_filter_file(
    head: Vec<u8>,
    body: phase::FileBody,
    meta: &phase::ProcessMeta,
    ctx: &phase::RequestCtx<'_>,
) -> Response {
    let req = super::range::RangeRequest {
        range: ctx.range,
        if_range: ctx.if_range,
        head_only: matches!(ctx.method, Method::Head),
    };
    super::range::filter_file(
        head,
        body,
        meta.range_allow,
        meta.max_ranges,
        req,
        |len, server| super::range::not_satisfiable(len, req.head_only, server),
    )
    .unwrap_or_else(|_| internal_error_response(ctx.method))
}

/// A cached response's body read from its file after `head`, for the
/// filters that need it in memory (`add_trailer`).
#[cold]
#[inline(never)]
fn read_file_body(
    mut head: Vec<u8>,
    body: phase::FileBody,
    ctx: &phase::RequestCtx<'_>,
) -> Response {
    use std::os::fd::AsRawFd;
    match crate::file::read_at_into(body.fd.as_raw_fd(), body.offset, body.len, &mut head) {
        Ok(()) => Response::Owned(head),
        Err(_) => internal_error_response(ctx.method),
    }
}

#[allow(clippy::large_enum_variant)] // per request: boxing waits for #467's measurements
enum PassOutcome {
    /// The response to send, with its metadata.
    Done(Response, phase::ProcessMeta),
    /// The request is redirected internally: an error page (intercept or
    /// the proxy's own 502/504) or an upstream X-Accel-Redirect.
    Redirect {
        reroute: phase::Reroute,
        /// This pass's attempts and upstream headers.
        trail: crate::proxy::UpstreamTrail,
        /// For an X-Accel-Redirect, the upstream headers its target's
        /// response gets (`accel_carried_headers`).
        carried: Vec<u8>,
        as_get: bool,
        /// The upstream's `X-Accel-Limit-Rate`: it outlives the redirect
        /// (nginx's `r->limit_rate_set`).
        limit_rate: Option<u64>,
    },
}

/// One upstream pass: run the plan, then either finish the response
/// (proxy_redirect, add_header) or say where the request is redirected.
/// `as_get`: the request already went through an X-Accel-Redirect.
async fn run_proxy_pass(
    http: &'static PreparedHttp,
    ctx: &phase::RequestCtx<'_>,
    mut plan: Box<crate::proxy::ProxyPlan>,
    process_meta: phase::ProcessMeta,
    as_get: bool,
    uri: Option<&[u8]>,
) -> PassOutcome {
    // After an internal redirect the answer's head is rewritten further
    // (`carry_accel_headers`), which takes it whole: no relayed body (#88).
    plan.stream = false;
    let response_rules = plan.response;
    let server_bytes = plan.server_bytes;
    let recursive_error_pages = plan.response.recursive_error_pages;
    let error_pages: &'static [PreparedErrorPage] = if plan.in_error_page {
        &[]
    } else {
        plan.response.error_pages
    };
    let error_page_status = plan.error_page_status;
    let mut report = crate::proxy::ProxyReport::default();
    let late_limit_rate = plan.response.limit_rate.map(|parts| {
        let meta = &process_meta;
        move |status: u16, headers: &[u8]| {
            super::render_proxy_limit_rate(parts, http, ctx, meta, status, headers, uri)
        }
    });
    let late = late_limit_rate
        .as_ref()
        .map(|late| late as crate::proxy::LateLimitRate<'_>);
    let upstream_resp = crate::proxy::run_proxy(plan, &mut report, late).await;
    if !report.failures.is_empty() {
        write_upstream_error_log(
            &process_meta.log,
            &ErrorLogRequest::new(&pass_request(ctx, as_get), process_meta.server_name)
                .with_realip(&process_meta),
            &report.failures,
        );
    }
    let upstream_resp = if error_pages.is_empty() {
        upstream_resp
    } else {
        intercept_with_report(
            upstream_resp,
            &mut report,
            error_pages,
            recursive_error_pages,
            http,
            &pass_request(ctx, as_get),
            &process_meta,
            server_bytes,
            uri,
        )
    };
    let limit_rate = report.accel.as_ref().and_then(|a| a.limit_rate);
    match upstream_resp {
        // `proxy_intercept_errors` or an `error_page` for the proxy's own
        // 502/504.
        Response::Reroute(reroute) => PassOutcome::Redirect {
            reroute,
            trail: crate::proxy::UpstreamTrail {
                states: report.states,
                headers: report.upstream_headers,
                cache_status: report.cache_status,
            },
            carried: Vec::new(),
            as_get,
            limit_rate,
        },
        // nginx's ngx_http_upstream_process_headers: the response is dropped
        // and the request redirected internally, as a GET.
        _ if report.accel.as_ref().is_some_and(|a| a.redirect.is_some()) => {
            let mut carried = Vec::new();
            accel_carried_headers(&report.upstream_headers, &mut carried);
            if let Some(rules) = response_rules.cookies {
                carried = super::rewrite_carried_cookies(
                    carried,
                    rules,
                    http,
                    ctx,
                    &process_meta,
                    &report.upstream_headers,
                    uri,
                );
            }
            let (reroute, as_get) = match accel_redirect(&mut report) {
                Ok(reroute) => (reroute, !matches!(ctx.method, Method::Head)),
                Err(target) => match refuse_unsafe_accel(
                    &target,
                    &mut report,
                    error_pages,
                    recursive_error_pages,
                    http,
                    &pass_request(ctx, as_get),
                    &process_meta,
                    server_bytes,
                    uri,
                ) {
                    Response::Reroute(reroute) => (reroute, as_get),
                    response => {
                        let mut process_meta = process_meta;
                        process_meta.upstream_states = report.states;
                        process_meta.upstream_headers = report.upstream_headers;
                        process_meta.upstream_cache_status = report.cache_status;
                        let response = carry_accel_headers(response, &carried, false);
                        return PassOutcome::Done(response, process_meta);
                    }
                },
            };
            PassOutcome::Redirect {
                reroute,
                trail: crate::proxy::UpstreamTrail {
                    states: report.states,
                    headers: report.upstream_headers,
                    cache_status: report.cache_status,
                },
                carried,
                as_get,
                limit_rate,
            }
        }
        upstream_resp => {
            let (response, process_meta) = finish_proxy_response(
                upstream_resp,
                report,
                response_rules,
                error_page_status,
                http,
                ctx,
                process_meta,
                uri,
            );
            PassOutcome::Done(response, process_meta)
        }
    }
}

/// A proxied request redirected internally: process the target, and if it
/// proxies again, run that pass too. The attempts of every pass stay in
/// `$upstream_*`, as nginx keeps them across internal redirects, and so do
/// the last upstream's headers (`$upstream_http_*`). An X-Accel-Redirect's
/// `carried` headers go onto the target's response. Bounded like the
/// reroute loop in `phase` (nginx's `uri_changes`).
#[allow(clippy::too_many_arguments)]
async fn settle_redirected(
    http: &'static PreparedHttp,
    ctx: &phase::RequestCtx<'_>,
    url_scratch: &mut Vec<u8>,
    mut reroute: phase::Reroute,
    mut trail: crate::proxy::UpstreamTrail,
    mut carried: Vec<u8>,
    mut as_get: bool,
    mut accel_limit_rate: Option<u64>,
) -> (Response, phase::ProcessMeta) {
    for _ in 0..phase::MAX_REROUTES {
        let pass_ctx = phase::RequestCtx {
            upstream: Some(&trail),
            ..pass_request(ctx, as_get)
        };
        let (response, mut process_meta) =
            phase::process_with_meta_from_reroute(http, &pass_ctx, url_scratch, reroute);
        if let Some(rate) = accel_limit_rate {
            process_meta.limit_rate =
                phase::ResponseLimit::with_rate(process_meta.limit_rate.take(), rate);
        }
        let Response::Proxy(plan) = response else {
            process_meta.upstream_states = trail.states;
            process_meta.upstream_headers = trail.headers;
            process_meta.upstream_cache_status = trail.cache_status;
            return (carry_accel_headers(response, &carried, false), process_meta);
        };
        let uri = final_uri(&process_meta, url_scratch);
        match run_proxy_pass(http, ctx, plan, process_meta, as_get, uri).await {
            PassOutcome::Done(response, mut meta) => {
                trail.states.append(&mut meta.upstream_states);
                meta.upstream_states = trail.states;
                meta.upstream_cache_status = meta.upstream_cache_status.or(trail.cache_status);
                return (carry_accel_headers(response, &carried, true), meta);
            }
            PassOutcome::Redirect {
                reroute: next,
                trail: mut more,
                carried: more_carried,
                as_get: next_as_get,
                limit_rate,
            } => {
                trail.states.append(&mut more.states);
                trail.headers = more.headers;
                trail.cache_status = more.cache_status.or(trail.cache_status);
                carried.extend_from_slice(&more_carried);
                reroute = next;
                as_get = next_as_get;
                accel_limit_rate = limit_rate.or(accel_limit_rate);
            }
        }
    }
    // nginx: "rewrite or internal redirection cycle" → 500.
    let response = Response::Owned(http::error_response_for_method(
        500,
        "Internal Server Error\n",
        ctx.method,
        phase::default_server_header(http),
    ));
    (response, phase::ProcessMeta::default())
}

/// The request as a later upstream pass sees it: a GET after an
/// X-Accel-Redirect (HEAD stays HEAD).
fn pass_request<'a>(ctx: &phase::RequestCtx<'a>, as_get: bool) -> phase::RequestCtx<'a> {
    if as_get {
        phase::RequestCtx {
            method: Method::Get,
            method_bytes: b"GET",
            ..*ctx
        }
    } else {
        *ctx
    }
}

/// An `X-Accel-Redirect` value as an internal redirect: `@name` jumps to a
/// named location, anything else is a URI with optional `?args`.
/// The upstream's X-Accel-Redirect: its request is over (nginx finalizes
/// it before redirecting), and the request goes to the target.
/// An unsafe URI (`uri::is_unsafe`) is the `Err`, for a 404.
fn accel_redirect(report: &mut crate::proxy::ProxyReport) -> Result<phase::Reroute, Vec<u8>> {
    crate::proxy::finish_answer(&mut report.states);
    let target = report
        .accel
        .as_mut()
        .and_then(|a| a.redirect.take())
        .unwrap_or_default();
    if target.first() != Some(&b'@') {
        let path_end = target
            .iter()
            .position(|&b| b == b'?')
            .unwrap_or(target.len());
        if crate::uri::is_unsafe(&target[..path_end]) {
            return Err(target);
        }
    }
    Ok(accel_redirect_reroute(target))
}

/// An X-Accel-Redirect to an unsafe URI: nginx logs it and finalizes the
/// request with 404 (through the location's `error_page`), as
/// ngx_http_upstream_process_headers.
#[cold]
#[allow(clippy::too_many_arguments)]
fn refuse_unsafe_accel(
    target: &[u8],
    report: &mut crate::proxy::ProxyReport,
    error_pages: &'static [PreparedErrorPage],
    recursive_error_pages: bool,
    http: &'static PreparedHttp,
    ctx: &phase::RequestCtx<'_>,
    process_meta: &phase::ProcessMeta,
    server_bytes: &'static [u8],
    uri: Option<&[u8]>,
) -> Response {
    let mut message = b"unsafe URI \"".to_vec();
    message.extend_from_slice(target);
    message.extend_from_slice(b"\" was detected");
    write_error_log(
        process_meta.log.error_logs,
        ErrorLogLevel::Error,
        &ErrorLogRequest::new(ctx, process_meta.server_name).with_realip(process_meta),
        &message,
        None,
    );
    intercept_with_report(
        Response::Prebuilt(http.not_found.pick(ctx.method)),
        report,
        error_pages,
        recursive_error_pages,
        http,
        ctx,
        process_meta,
        server_bytes,
        uri,
    )
}

fn accel_redirect_reroute(target: Vec<u8>) -> phase::Reroute {
    let (target, args) = if target.first() == Some(&b'@') {
        (phase::RerouteTarget::Named(target), None)
    } else {
        match target.iter().position(|&b| b == b'?') {
            Some(i) => (
                phase::RerouteTarget::Uri(target[..i].to_vec()),
                Some(target[i + 1..].to_vec()),
            ),
            None => (phase::RerouteTarget::Uri(target), None),
        }
    };
    phase::Reroute {
        target,
        args,
        error_page_status: None,
        enters_error_page: false,
        preserved_location: None,
        preserved_www_authenticate: Vec::new(),
        closes: false,
    }
}

/// The upstream headers nginx copies onto the request before an
/// X-Accel-Redirect, so the target's response has them (`redirect` in
/// ngx_http_upstream_headers_in).
const ACCEL_CARRIED: [&[u8]; 6] = [
    b"content-type",
    b"set-cookie",
    b"content-disposition",
    b"cache-control",
    b"expires",
    b"accept-ranges",
];

/// Append the lines of `upstream_headers` (each ending in CRLF) that an
/// X-Accel-Redirect carries over.
fn accel_carried_headers(upstream_headers: &[u8], out: &mut Vec<u8>) {
    for line in upstream_headers.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            continue;
        };
        let name = line[..colon].trim_ascii();
        if ACCEL_CARRIED.iter().any(|h| h.eq_ignore_ascii_case(name)) {
            out.extend_from_slice(line);
            out.extend_from_slice(b"\r\n");
        }
    }
}

/// The X-Accel-Redirect target's response with the `carried` upstream
/// headers. As in nginx, the carried `Content-Type` wins over the
/// target's own type (it is already set when the target picks one),
/// unless the target is proxied and its upstream sends one. `Set-Cookie`
/// and `Accept-Ranges` add up (a static file then has two Accept-Ranges,
/// as in nginx). The others go in when the target doesn't set them
/// itself (`expires`). An error response (a missing file, say) is nginx's
/// special response, which sets its own `text/html` and clears
/// Accept-Ranges (ngx_http_send_special_response).
fn carry_accel_headers(response: Response, carried: &[u8], proxied: bool) -> Response {
    if carried.is_empty() {
        return response;
    }
    let merge = |head: Vec<u8>| {
        let mut head = head;
        let error = response_status(&head) >= 400;
        let mut extra = Vec::new();
        // Which of ACCEL_CARRIED are in `extra`; the first of a repeated
        // one wins, as for the upstream's own single-valued headers.
        let mut added = 0u8;
        for line in carried.split_inclusive(|&b| b == b'\n') {
            let Some(colon) = line.iter().position(|&b| b == b':') else {
                continue;
            };
            let name = line[..colon].trim_ascii();
            let Some(i) = ACCEL_CARRIED
                .iter()
                .position(|h| h.eq_ignore_ascii_case(name))
            else {
                continue;
            };
            if error && name.eq_ignore_ascii_case(b"accept-ranges") {
                continue;
            }
            if !name.eq_ignore_ascii_case(b"set-cookie")
                && !name.eq_ignore_ascii_case(b"accept-ranges")
            {
                if added & (1 << i) != 0 {
                    continue;
                }
                if i == 0 && !proxied && !error {
                    head = strip_header_lines(head, name);
                } else if response_header_value(&head, name).is_some() {
                    continue;
                }
                added |= 1 << i;
            }
            extra.extend_from_slice(line);
        }
        let Some(sep) = head.windows(4).position(|w| w == b"\r\n\r\n") else {
            return head;
        };
        let mut out = Vec::with_capacity(head.len() + extra.len());
        out.extend_from_slice(&head[..sep + 2]);
        out.extend_from_slice(&extra);
        out.extend_from_slice(&head[sep + 2..]);
        out
    };
    match response {
        Response::Prebuilt(bytes) => Response::Owned(merge(bytes.to_vec())),
        Response::Owned(bytes) => Response::Owned(merge(bytes)),
        Response::File { headers, body } => Response::File {
            headers: merge(headers),
            body,
        },
        other => other,
    }
}

async fn run_post_action(
    http: &'static PreparedHttp,
    base_ctx: &phase::RequestCtx<'_>,
    target: &'static [u8],
    request_start: Instant,
    url_scratch: &mut Vec<u8>,
) {
    if target.is_empty() {
        return;
    }

    // No recursion: nginx gates re-entry with `r->post_action == 1`. Here
    // the equivalent is structural — `run_post_action` is only invoked
    // from the main request handler, never from itself, and the inner
    // `post_meta.post_action` is intentionally discarded below.
    let post_path = if target.first() == Some(&b'/') {
        target
    } else {
        base_ctx.path
    };
    let post_ctx = phase::RequestCtx {
        path: post_path,
        body: &phase::NO_BODY,
        body_len: 0,
        body_file: None,
        refuse: None,
        ..*base_ctx
    };

    let initial = if target.first() == Some(&b'/') {
        phase::process_with_meta(http, &post_ctx, url_scratch)
    } else {
        phase::process_with_meta_from_reroute(
            http,
            &post_ctx,
            url_scratch,
            phase::Reroute {
                target: phase::RerouteTarget::Named(target.to_vec()),
                args: None,
                error_page_status: None,
                enters_error_page: false,
                preserved_location: None,
                preserved_www_authenticate: Vec::new(),
                closes: false,
            },
        )
    };
    let (response, post_meta) =
        settle_proxy_response(http, &post_ctx, url_scratch, initial.0, initial.1, None).await;

    let mut owned_response = Vec::new();
    let mut static_response: Option<&'static [u8]> = None;
    match response {
        Response::Prebuilt(bytes) => static_response = Some(bytes),
        Response::Owned(bytes) => owned_response = bytes,
        Response::File { headers, body: _ } => owned_response = headers,
        // post_action's answer isn't sent: the upstream connection closes.
        Response::ProxyStream(s) => owned_response = s.head,
        // nginx refuses an upgrade in a subrequest.
        Response::Reroute(_) | Response::Proxy(_) | Response::Upgrade(_) => return,
    }
    let response_for_logs = static_response.unwrap_or(owned_response.as_slice());
    let log_request_uri = post_path;

    if !post_meta.access_logs.is_empty() {
        write_access_logs(
            post_meta.access_logs,
            log_request_uri,
            base_ctx.method_bytes,
            base_ctx.request_line,
            base_ctx.host,
            base_ctx.remote_addr,
            base_ctx.remote_port,
            post_meta.remote_user.as_deref(),
            base_ctx.headers_raw,
            response_for_logs,
            base_ctx.connection_id,
            base_ctx.connection_requests,
            base_ctx.request_id,
            base_ctx.connection_time_us,
            // Nginx's post_action runs as an internal redirect on the
            // same `r`, so its access log sees `$request_time` measured
            // from the original request start. Match that semantic by
            // measuring from `request_start`, not the post-action's
            // own dispatch start.
            request_start.elapsed().as_micros() as u64,
            post_meta.server_port,
            base_ctx.request_port,
            base_ctx.pipe,
            base_ctx.request_length,
            0,
            0,
            base_ctx.epoch_secs,
            base_ctx.epoch_ms,
            base_ctx.tls,
            base_ctx.conn,
            http,
            Some(&post_meta),
            final_uri(&post_meta, url_scratch),
        )
        .await;
    }
}

/// Give this worker thread its own copy of the fd table.
///
/// Threads share one fd table, and every `open(2)` / `close(2)` takes its
/// spinlock (`alloc_fd`, `file_close_fd`). With one open + close per static
/// request and 32 workers, that lock was ~5–8% of CPU on the 304 bench.
/// nginx doesn't pay this: its workers are processes. After
/// `unshare(CLONE_FILES)` each worker has a private table, like an nginx
/// worker.
///
/// Safe because no fd crosses threads after startup: fds opened before the
/// workers spawn (root dirs, stdio) are copied into each private table, and
/// everything else — listeners, the io_uring ring, accepted sockets,
/// per-request files, access-log handles — is opened by the worker that
/// uses it. `RUXEN_UNSHARE_FILES=0` keeps the shared table (for A/B runs).
fn unshare_fd_table() -> bool {
    if matches!(std::env::var("RUXEN_UNSHARE_FILES").as_deref(), Ok("0")) {
        return false;
    }
    // Said once, not by every worker: they all fail the same way (a
    // seccomp profile without the rule in contrib/docker, say).
    static WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    // SAFETY: plain syscall; affects only the calling thread's fd table.
    if unsafe { libc::unshare(libc::CLONE_FILES) } == 0 {
        return true;
    }
    if !WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
        eprintln!(
            "ruxen: unshare(CLONE_FILES) failed: {}; workers keep the shared fd table",
            std::io::Error::last_os_error()
        );
    }
    false
}

/// Worker thread body. `ready` gets exactly one message once startup is
/// done — `Ok` when the worker is ready to accept on `listeners` (opened
/// by `main`, see `listeners`), or the `[emerg]` text of the first
/// failure, after which the worker exits. `main` waits for all of them
/// before writing the pid file, or before a reload retires the workers of
/// the configuration before. `ring_entries` is the io_uring ring size
/// (`ring_entries`).
pub fn run(
    http: &'static PreparedHttp,
    cpu: Option<usize>,
    state: &'static RuntimeState,
    ready: std::sync::mpsc::Sender<Result<(), String>>,
    listeners: super::listeners::WorkerListeners,
    ring_entries: u32,
) {
    let unshared = unshare_fd_table();
    let adopted = match super::listeners::adopt(listeners, unshared) {
        Ok(adopted) => adopted,
        Err(e) => {
            let _ = ready.send(Err(format!("dup() failed ({})", errno_text(&e))));
            return;
        }
    };
    // What `force_close` leaves alone: everything open now but the
    // listeners. Only with a table of its own, where the rest is this
    // worker's.
    let inherited = unshared.then(|| {
        use std::os::fd::AsRawFd;
        let own: Vec<_> = adopted.iter().map(|(_, fd)| fd.as_raw_fd()).collect();
        super::listeners::inherited_fds(&own)
    });
    let inherited_on_panic = inherited.clone();
    if let Some(c) = cpu {
        // Pin before building the runtime so io_uring setup + the submission
        // queue end up on the target CPU's kernel workers too.
        if let Err(e) = monoio::utils::bind_to_cpu_set([c]) {
            eprintln!("ruxen: worker pin to cpu {c} failed: {e}");
        }
    }

    // The worker's whole life; it runs on whichever driver `main` chose.
    let ready_on_failure = ready.clone();
    let body = async move {
        WORKER_CONNS.with(|w| w.http.set(Some(http)));
        // Open one fd per configured access_log for this worker. Kept in a
        // thread-local so `write_access_logs` can do io_uring writes without
        // re-opening the file per request.
        if let Err(e) = init_access_logs_for_worker(http.access_logs) {
            let _ = ready.send(Err(e));
            return;
        }

        let mut listeners = Vec::with_capacity(http.listens.len());
        // `listen unix:` sockets (#263).
        let mut unix_listeners = Vec::new();
        for (listen_index, fd) in adopted {
            let prepared = &http.listens[listen_index];
            let made = if prepared.unix.is_some() {
                monoio::net::UnixListener::from_std(std::os::unix::net::UnixListener::from(fd))
                    .map(|l| unix_listeners.push((listen_index, l)))
            } else {
                TcpListener::from_std(std::net::TcpListener::from(fd))
                    .map(|l| listeners.push((listen_index, l)))
            };
            if let Err(e) = made {
                let _ = ready.send(Err(format!(
                    "registering the listener of {} failed ({})",
                    prepared.addr,
                    errno_text(&e)
                )));
                return;
            }
        }
        let _ = ready.send(Ok(()));
        // Drop the sender so `main` sees a closed channel, not a hang, if
        // another worker dies before reporting.
        drop(ready);
        // Accept only once `main` has switched to the configured `user`.
        state.wait_released();
        // From now on its accept loop turns at least every ACCEPT_TICK.
        HEARTBEAT.with(|beat| {
            let _ = beat.set(state.heartbeat());
        });
        if test_panic() == TestPanic::Worker {
            panic!("{TEST_PANIC_ENV}=worker");
        }
        if test_panic() == TestPanic::Later
            && std::thread::current().name() == Some("ruxen-worker-1")
        {
            monoio::spawn(async {
                monoio::time::sleep(Duration::from_secs(1)).await;
                panic!("{TEST_PANIC_ENV}=later");
            });
        }

        if listeners.len() == 1 && unix_listeners.is_empty() {
            // Single-listen fast path: keep the accept loop in this top-level
            // task (the pre-m36 shape) to avoid an extra scheduler hop on
            // every accepted connection.
            let (listen_index, listener) = listeners.pop().expect("one listener");
            let prepared = &http.listens[listen_index];
            let mut tick = AcceptTick::new();
            loop {
                // Shutdown or a reload wakes the idle connections.
                notice_runtime_events(state);
                if state.is_shutting_down() {
                    worker_notice(http, "gracefully shutting down");
                    // Stop accepting at once: after a reload, the socket
                    // goes on with the next generation's worker, or is
                    // closed if the address went away.
                    drop(listener);
                    drain(state, inherited.as_deref()).await;
                    worker_notice(http, "exiting");
                    flush_access_log_buffers();
                    worker_notice(http, "exit");
                    return;
                }
                match accept_or_tick(&listener, &mut tick, state).await {
                    Ok(Some((stream, addr))) => {
                        let admitted = admit_connection(http);
                        if http.stats {
                            super::stats::accepted(admitted);
                        }
                        if !admitted {
                            continue;
                        }
                        let _ = stream.set_nodelay(true);
                        connection_started();
                        let connection_id = state.next_connection_id();
                        spawn_connection(
                            prepared,
                            stream,
                            addr,
                            listen_index,
                            http,
                            state,
                            connection_id,
                        );
                    }
                    Ok(None) => {}
                    Err(e) => accept_failed(http, state, &e).await,
                }
            }
        } else {
            let mut accepting = Vec::with_capacity(listeners.len() + unix_listeners.len());
            for (listen_index, listener) in listeners {
                accepting.push(monoio::spawn(run_listener(
                    listener,
                    listen_index,
                    http,
                    state,
                )));
            }
            for (listen_index, listener) in unix_listeners {
                accepting.push(monoio::spawn(run_unix_listener(
                    listener,
                    listen_index,
                    http,
                    state,
                )));
            }

            loop {
                // Shutdown or a reload wakes the idle connections.
                notice_runtime_events(state);
                if state.is_shutting_down() {
                    worker_notice(http, "gracefully shutting down");
                    // The accept loops cancel their accepts and close their
                    // sockets. Dropped with the runtime instead, an accept
                    // left in the ring kept the socket listening after a
                    // reload removed its address.
                    for task in accepting {
                        task.await;
                    }
                    drain(state, inherited.as_deref()).await;
                    worker_notice(http, "exiting");
                    flush_access_log_buffers();
                    worker_notice(http, "exit");
                    return;
                }
                monoio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    };

    let run_epoll = |body| match RuntimeBuilder::<monoio::LegacyDriver>::new()
        .enable_timer()
        .build()
    {
        Ok(mut rt) => end_connections_on_panic(inherited_on_panic.as_deref(), || rt.block_on(body)),
        Err(e) => {
            let _ =
                ready_on_failure.send(Err(format!("epoll_create() failed ({})", errno_text(&e))));
        }
    };
    match driver() {
        Driver::IoUring => match io_uring_runtime(http, ring_entries) {
            Ok(mut rt) => {
                end_connections_on_panic(inherited_on_panic.as_deref(), || rt.block_on(body))
            }
            // No ring fits what is left of the user's RLIMIT_MEMLOCK: the
            // old generation's rings during a reload, or another io_uring
            // process of the user, hold the rest. This worker runs on
            // epoll then, rather than failing the start or the reload
            // (#635); every worker has a runtime of its own.
            Err(e) if e.raw_os_error() == Some(libc::ENOMEM) => {
                static WARNED: AtomicBool = AtomicBool::new(false);
                if !WARNED.swap(true, Ordering::Relaxed) {
                    write_worker_log(
                        http.error_logs,
                        ErrorLogLevel::Warn,
                        "io_uring_setup() failed (12: Cannot allocate memory), using epoll: \
                         the rings count against RLIMIT_MEMLOCK (LimitMEMLOCK=, ulimit -l)",
                    );
                }
                run_epoll(body)
            }
            Err(e) => {
                let _ = ready_on_failure
                    .send(Err(format!("io_uring_setup() failed ({})", errno_text(&e))));
            }
        },
        Driver::Epoll => run_epoll(body),
    }
}

/// nginx's notice lines for a worker's end, from its own thread
/// (ngx_worker_process_cycle, ngx_worker_process_exit; #669).
#[cold]
fn worker_notice(http: &PreparedHttp, message: &str) {
    write_worker_log(http.error_logs, ErrorLogLevel::Notice, message);
}

/// Ring sizes, largest first: the size of a generation's rings, and the
/// smaller ones a worker tries on ENOMEM.
const RING_ENTRIES: [u32; 3] = [4096, 1024, 256];

/// What a ring takes per entry, rounded up: a 64-byte SQE, two 16-byte
/// CQEs and the SQ index, in page-rounded regions.
const RING_BYTES_PER_ENTRY: u64 = 128;

/// The ring size for a generation of `workers`. Without `CAP_IPC_LOCK`,
/// Linux 7.0 charges each ring to the user's `RLIMIT_MEMLOCK`, summed over
/// all of the user's processes: a 4096-entry ring is about 0.5 MiB, so the
/// common 8 MiB limit holds about 16 workers (#612). Chosen up front, as
/// the largest size whose rings all fit the limit, with a `[warn]` when
/// that is less than 4096. Workers that took the limit first would leave
/// the later ones none.
pub fn ring_entries(http: &PreparedHttp, workers: usize) -> u32 {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes into the struct we pass.
    if driver() != Driver::IoUring
        || unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut limit) } != 0
        || limit.rlim_cur == libc::RLIM_INFINITY
        || may_lock_memory()
    {
        return RING_ENTRIES[0];
    }
    let fits = |n: u32| workers as u64 * n as u64 * RING_BYTES_PER_ENTRY <= limit.rlim_cur;
    let size = RING_ENTRIES
        .iter()
        .copied()
        .find(|&n| fits(n))
        .unwrap_or(RING_ENTRIES[RING_ENTRIES.len() - 1]);
    if size != RING_ENTRIES[0] {
        write_worker_log(
            http.error_logs,
            ErrorLogLevel::Warn,
            &format!(
                "the io_uring rings of {workers} workers at {} entries exceed \
                 RLIMIT_MEMLOCK ({} KiB), using {size} entries: \
                 raise it (LimitMEMLOCK=, ulimit -l)",
                RING_ENTRIES[0],
                limit.rlim_cur >> 10
            ),
        );
    }
    size
}

/// `CAP_IPC_LOCK` in the effective set: the kernel then charges no ring to
/// `RLIMIT_MEMLOCK`.
fn may_lock_memory() -> bool {
    const CAP_IPC_LOCK: u32 = 14;
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            let caps = status.lines().find_map(|l| l.strip_prefix("CapEff:"))?;
            u64::from_str_radix(caps.trim(), 16).ok()
        })
        .is_some_and(|caps| caps & (1 << CAP_IPC_LOCK) != 0)
}

/// Set once the kernel refused `IORING_SETUP_DEFER_TASKRUN` (it came in
/// Linux 6.1): the workers build plain rings from then on.
static PLAIN_RINGS: AtomicBool = AtomicBool::new(false);

/// The worker's io_uring runtime, with a ring of `entries`. On ENOMEM (the
/// limit is shared with the user's other processes, and the rings of
/// workers a reload retired are freed some time after) a smaller ring,
/// with one `[warn]` per process.
///
/// The ring is `SINGLE_ISSUER | DEFER_TASKRUN`: the kernel runs the
/// completion work when the worker asks for completions, rather than
/// interrupting it for each one. The worker builds its runtime on its own
/// thread and is the only one that submits, which `SINGLE_ISSUER` requires.
fn io_uring_runtime(
    http: &PreparedHttp,
    entries: u32,
) -> std::io::Result<monoio::Runtime<monoio::time::TimeDriver<monoio::IoUringDriver>>> {
    static WARNED: AtomicBool = AtomicBool::new(false);
    let mut sizes = RING_ENTRIES
        .iter()
        .copied()
        .filter(|&n| n <= entries)
        .peekable();
    let mut size = sizes.next().unwrap_or(entries);
    loop {
        let deferred = !PLAIN_RINGS.load(Ordering::Relaxed);
        let mut builder = RuntimeBuilder::<monoio::IoUringDriver>::new()
            .enable_timer()
            .with_entries(size);
        if deferred {
            let mut ring = io_uring::IoUring::builder();
            ring.setup_single_issuer().setup_defer_taskrun();
            builder = builder.uring_builder(ring);
        }
        match builder.build() {
            Ok(rt) => {
                if size != entries && !WARNED.swap(true, Ordering::Relaxed) {
                    write_worker_log(
                        http.error_logs,
                        ErrorLogLevel::Warn,
                        &format!(
                            "io_uring_setup() of {entries} entries failed \
                             (12: Cannot allocate memory), using {size}: \
                             the rings count against RLIMIT_MEMLOCK \
                             (LimitMEMLOCK=, ulimit -l)"
                        ),
                    );
                }
                return Ok(rt);
            }
            Err(e) if deferred && e.raw_os_error() == Some(libc::EINVAL) => {
                PLAIN_RINGS.store(true, Ordering::Relaxed);
            }
            Err(e) if e.raw_os_error() == Some(libc::ENOMEM) && sizes.peek().is_some() => {
                size = sizes.next().unwrap_or(size);
            }
            Err(e) => return Err(e),
        }
    }
}

/// A worker that panicked outside a connection (where `Contained` doesn't
/// catch it) shuts its connections down before its thread ends, as
/// `force_close` would, so their clients see the end at once: an io_uring
/// keeps the operations in flight, and with them the sockets, after the
/// thread is gone (#495). `inherited` is `None` without a private fd table,
/// where the worker's connections can't be told apart.
fn end_connections_on_panic(inherited: Option<&[std::os::fd::RawFd]>, run: impl FnOnce()) {
    if let Err(panic) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(run)) {
        if let Some(inherited) = inherited {
            super::listeners::shut_down_sockets(inherited);
        }
        std::panic::resume_unwind(panic);
    }
}

/// The I/O driver every worker runs on, chosen once by `main` (#215).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Driver {
    IoUring,
    /// monoio's legacy driver: epoll, for where io_uring is unavailable.
    Epoll,
}

static EPOLL: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Set before the workers start.
pub fn set_driver(driver: Driver) {
    EPOLL.store(
        driver == Driver::Epoll,
        std::sync::atomic::Ordering::Relaxed,
    );
}

pub fn driver() -> Driver {
    if EPOLL.load(std::sync::atomic::Ordering::Relaxed) {
        Driver::Epoll
    } else {
        Driver::IoUring
    }
}

/// Wait for this worker's connections to finish once shutdown began. When
/// `main` forces the end (`worker_shutdown_timeout` after a reload or
/// SIGQUIT), shut their sockets down, again every second for connections
/// opened since (an upstream retry); `inherited` is `None` without a
/// private fd table, where that can't be told apart.
async fn drain(state: &RuntimeState, inherited: Option<&[std::os::fd::RawFd]>) {
    let mut swept: Option<Instant> = None;
    while worker_clients() != 0 {
        if state.is_forced()
            && let Some(inherited) = inherited
            && swept.is_none_or(|at| at.elapsed() >= Duration::from_secs(1))
        {
            super::listeners::shut_down_sockets(inherited);
            swept = Some(Instant::now());
        }
        monoio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// The accept loop of a `listen unix:` socket (#263). A connection is
/// carried as a `TcpStream`, as unix upstreams are (#101): its I/O is plain
/// recv/send on the descriptor, so the connection code is the same; the
/// listen's `unix` marks the peer as `unix:`.
pub(crate) async fn run_unix_listener(
    listener: monoio::net::UnixListener,
    listen_index: usize,
    http: &'static PreparedHttp,
    state: &'static RuntimeState,
) {
    use std::os::fd::{FromRawFd, IntoRawFd};
    let prepared = &http.listens[listen_index];
    let mut tick = AcceptTick::new();
    loop {
        if state.is_shutting_down() {
            return;
        }
        match unix_accept_or_tick(&listener, &mut tick, state).await {
            Ok(Some(stream)) => {
                let admitted = admit_connection(http);
                if http.stats {
                    super::stats::accepted(admitted);
                }
                if !admitted {
                    continue;
                }
                let fd = stream.into_raw_fd();
                // SAFETY: a connected stream socket nothing else owns.
                let Ok(stream) =
                    TcpStream::from_std(unsafe { std::net::TcpStream::from_raw_fd(fd) })
                else {
                    continue;
                };
                connection_started();
                let connection_id = state.next_connection_id();
                spawn_connection(
                    prepared,
                    stream,
                    SocketAddr::from(([0, 0, 0, 0], 0)),
                    listen_index,
                    http,
                    state,
                    connection_id,
                );
            }
            Ok(None) => {}
            Err(e) => accept_failed(http, state, &e).await,
        }
    }
}

/// `accept_or_tick` for a `listen unix:` socket: the same tick, and the
/// same cancel on shutdown.
async fn unix_accept_or_tick(
    listener: &monoio::net::UnixListener,
    tick: &mut AcceptTick,
    state: &RuntimeState,
) -> std::io::Result<Option<monoio::net::UnixStream>> {
    use std::pin::pin;

    let mut accept = pin!(listener.cancelable_accept(tick.canceller.handle()));
    loop {
        monoio::select! {
            res = &mut accept => return res.map(|(stream, _)| Some(stream)),
            _ = tick.timer.as_mut() => {
                tick.timer
                    .as_mut()
                    .reset(monoio::time::Instant::now() + ACCEPT_TICK);
                notice_runtime_events(state);
                if !state.is_shutting_down() {
                    continue;
                }
                tick.canceller = std::mem::take(&mut tick.canceller).cancel();
                return match accept.await {
                    Ok((stream, _)) => Ok(Some(stream)),
                    Err(_) => Ok(None),
                };
            }
        }
    }
}

/// A request limit_req delayed (#94): wait, then run it again past
/// limit_req, as nginx resumes its phases after the delay timer: the
/// handler, the upstream and `$request_time` come after the delay.
#[cold]
#[inline(never)]
/// `auth_request` (#358): run the subrequests the request needs, then
/// process it again with their outcomes (`phase::resume_auth_request`), as
/// nginx re-enters its access phase. Processing starts over each time, so
/// a location reached after an internal redirect may need another one;
/// the outcomes so far go along, by URI. The first pass's limit_conn
/// counts stay with the request.
async fn auth_subrequest(
    http: &'static PreparedHttp,
    ctx: &mut phase::RequestCtx<'_>,
    url_scratch: &mut Vec<u8>,
    first: phase::ProcessMeta,
    request_start: Instant,
) -> (Response, phase::ProcessMeta) {
    let held = first.limit_conn_held.clone();
    let mut meta = first;
    let mut outcomes: Vec<(&'static [u8], phase::AuthResume)> = Vec::new();
    // More subrequests than this means a loop of redirects.
    for _ in 0..8 {
        let Some(pending) = meta.auth_request.take() else {
            break;
        };
        let outcome = run_auth_subrequest(http, ctx, url_scratch, &pending, request_start).await;
        outcomes.push((pending.uri, outcome));
        phase::resume_auth_request(outcomes.clone());
        ctx.request_time_us = request_start.elapsed().as_micros() as u64;
        let (response, next) = phase::process_with_meta(http, ctx, url_scratch);
        phase::resume_auth_request(Vec::new());
        meta = next;
        if meta.limit_conn_held.is_none() {
            meta.limit_conn_held = held.clone();
        }
        if meta.auth_request.is_none() {
            return (response, meta);
        }
    }
    meta.auth_request = None;
    (
        Response::Prebuilt(http.internal_error.pick(ctx.method)),
        meta,
    )
}

/// One `auth_request` subrequest: a GET to its URI with the request's
/// headers and no body, through the internal-redirect path (so `internal`
/// locations answer). Its body isn't wanted (`header_only`); its status,
/// `WWW-Authenticate` and `auth_request_set` values are.
async fn run_auth_subrequest(
    http: &'static PreparedHttp,
    ctx: &phase::RequestCtx<'_>,
    url_scratch: &mut Vec<u8>,
    pending: &phase::AuthPending,
    request_start: Instant,
) -> phase::AuthResume {
    // `$request_uri` stays the request's, as for an nginx subrequest; the
    // auth URI is where it is routed, with its own arguments only.
    let sub_ctx = phase::RequestCtx {
        method: Method::Get,
        method_bytes: b"GET",
        body: &phase::NO_BODY,
        body_len: 0,
        body_file: None,
        refuse: None,
        upstream: None,
        ..*ctx
    };
    let (response, sub_meta) =
        phase::process_with_meta_from_reroute(http, &sub_ctx, url_scratch, {
            let (path, args) = match pending.uri.iter().position(|&b| b == b'?') {
                Some(q) => (&pending.uri[..q], pending.uri[q + 1..].to_vec()),
                None => (pending.uri, Vec::new()),
            };
            phase::Reroute {
                target: phase::RerouteTarget::Uri(path.to_vec()),
                args: Some(args),
                error_page_status: None,
                enters_error_page: false,
                preserved_location: None,
                preserved_www_authenticate: Vec::new(),
                closes: false,
            }
        });
    // `auth_request_set` reads the upstream's header (`$upstream_http_*`):
    // keep it, whatever the subrequest's location reads itself.
    let response = match response {
        Response::Proxy(mut plan) => {
            plan.keep_upstream_headers = true;
            Response::Proxy(plan)
        }
        other => other,
    };
    let (response, sub_meta) =
        settle_proxy_response(http, &sub_ctx, url_scratch, response, sub_meta, None).await;
    let head: &[u8] = match &response {
        Response::Prebuilt(b) => b,
        Response::Owned(b) => b,
        Response::File { headers, .. } => headers,
        Response::ProxyStream(stream) => &stream.head,
        _ => &[],
    };
    let head = head
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map_or(head, |end| &head[..end + 4]);
    let status = super::response_status(head);
    // nginx takes the subrequest's own `WWW-Authenticate`, else its
    // upstream's.
    let mut www_authenticate = super::response_header_values_all(head, b"www-authenticate");
    if www_authenticate.is_empty() && !sub_meta.upstream_headers.is_empty() {
        www_authenticate =
            super::response_header_values_all(&sub_meta.upstream_headers, b"www-authenticate");
    }
    let trail = crate::proxy::UpstreamTrail {
        states: sub_meta.upstream_states.clone(),
        headers: sub_meta.upstream_headers.clone(),
        cache_status: None,
    };
    let render_req = phase::RequestCtx {
        upstream: Some(&trail),
        request_time_us: request_start.elapsed().as_micros() as u64,
        ..sub_ctx
    };
    let vars = pending
        .sets
        .iter()
        .map(|(name, parts)| {
            let value = super::render_in_subrequest(
                http,
                &render_req,
                sub_meta.server_name,
                sub_meta.server_port,
                status,
                head,
                parts,
            );
            (*name, value)
        })
        .collect();
    phase::AuthResume {
        status,
        www_authenticate,
        vars,
        limit_req_status: pending.limit_req_status,
        limit_conn_status: pending.limit_conn_status,
    }
}

async fn limit_req_delayed(
    http: &'static PreparedHttp,
    ctx: &mut phase::RequestCtx<'_>,
    url_scratch: &mut Vec<u8>,
    delay_ms: u64,
    request_start: Instant,
) -> (Response, phase::ProcessMeta) {
    monoio::time::sleep(Duration::from_millis(delay_ms)).await;
    ctx.request_time_us = request_start.elapsed().as_micros() as u64;
    super::limit_req::resume_after_delay(true);
    let out = phase::process_with_meta(http, ctx, url_scratch);
    super::limit_req::resume_after_delay(false);
    out
}

pub(crate) async fn run_listener(
    listener: TcpListener,
    listen_index: usize,
    http: &'static PreparedHttp,
    state: &'static RuntimeState,
) {
    let prepared = &http.listens[listen_index];
    let mut tick = AcceptTick::new();
    loop {
        if state.is_shutting_down() {
            return;
        }
        match accept_or_tick(&listener, &mut tick, state).await {
            Ok(Some((stream, addr))) => {
                let admitted = admit_connection(http);
                if http.stats {
                    super::stats::accepted(admitted);
                }
                if !admitted {
                    continue;
                }
                let _ = stream.set_nodelay(true);
                connection_started();
                let connection_id = state.next_connection_id();
                spawn_connection(
                    prepared,
                    stream,
                    addr,
                    listen_index,
                    http,
                    state,
                    connection_id,
                );
            }
            Ok(None) => {}
            Err(e) => accept_failed(http, state, &e).await,
        }
    }
}

/// Branch on whether this listen address is TLS and spawn the matching
/// trampoline. Plain HTTP costs one `Option::is_some` check on the accept
/// path; the TLS branch clones an `Arc<TlsAcceptor>` (two atomics) before
/// the spawn.
#[inline]
pub(crate) fn spawn_connection(
    prepared: &'static PreparedListen,
    stream: TcpStream,
    peer_addr: SocketAddr,
    listen_index: usize,
    http: &'static PreparedHttp,
    state: &'static RuntimeState,
    connection_id: u64,
) {
    // The connection was counted on accept; whatever path it takes from
    // here, dropping the guard un-counts it.
    let guard = ConnectionGuard;
    if prepared.proxy_protocol {
        // Cold: `listen … proxy_protocol`.
        monoio::spawn(Contained::new(
            handle_proxy_protocol(
                prepared,
                stream,
                peer_addr,
                listen_index,
                http,
                state,
                connection_id,
                guard,
            ),
            http,
            connection_id,
            peer_addr,
        ));
        return;
    }
    match &prepared.tls {
        None => {
            // A panic ends this connection only (#130).
            monoio::spawn(Contained::new(
                handle_plain(
                    stream,
                    peer_addr,
                    listen_index,
                    http,
                    state,
                    connection_id,
                    None,
                    Instant::now(),
                    guard,
                ),
                http,
                connection_id,
                peer_addr,
            ));
        }
        Some(acceptor) => {
            let acceptor = acceptor.clone();
            monoio::spawn(Contained::new(
                handle_tls(
                    stream,
                    acceptor,
                    peer_addr,
                    listen_index,
                    http,
                    state,
                    connection_id,
                    None,
                    Instant::now(),
                    guard,
                ),
                http,
                connection_id,
                peer_addr,
            ));
        }
    }
}

/// `listen … proxy_protocol`: read the PROXY header (within the default
/// server's `client_header_timeout`), then serve the connection as usual.
/// A connection without a valid header is closed with an error-log line,
/// as nginx does ("broken header: …").
#[allow(clippy::too_many_arguments)] // hot path: a parameter struct needs ABBA numbers first
async fn handle_proxy_protocol(
    prepared: &'static PreparedListen,
    stream: TcpStream,
    peer_addr: SocketAddr,
    listen_index: usize,
    http: &'static PreparedHttp,
    state: &'static RuntimeState,
    connection_id: u64,
    guard: ConnectionGuard,
) {
    let accepted_at = Instant::now();
    let server = &prepared.servers[prepared.default_server];
    let header = match crate::proxy_protocol::read(&stream, server.timeouts.header).await {
        Ok(header) => header,
        Err((level, reason)) => {
            // There's no request yet, so nginx's context is the client and
            // the listening address.
            write_worker_log(
                server.error_logs,
                level,
                &format!(
                    "*{connection_id} {reason} while reading PROXY protocol, \
                     client: {}, server: {}",
                    peer_addr.ip(),
                    prepared.addr
                ),
            );
            return;
        }
    };
    match &prepared.tls {
        None => {
            handle_plain(
                stream,
                peer_addr,
                listen_index,
                http,
                state,
                connection_id,
                Some(header),
                accepted_at,
                guard,
            )
            .await
        }
        Some(acceptor) => {
            handle_tls(
                stream,
                acceptor.clone(),
                peer_addr,
                listen_index,
                http,
                state,
                connection_id,
                Some(header),
                accepted_at,
                guard,
            )
            .await
        }
    }
}

/// Before the workers bind: makes sure no other process holds a listen
/// address. Each worker binds its own `SO_REUSEPORT` socket, which a
/// second ruxen (or anything else with `SO_REUSEPORT`, same user) could
/// join, splitting the traffic without a word. nginx binds once without
/// `SO_REUSEPORT` unless `reuseport` is set, so a second instance fails
/// with `EADDRINUSE`. Here each such address is bound once without it and
/// closed again, which fails the same way. Like nginx's
/// ngx_open_listening_sockets: up to five tries 500 ms apart (an old
/// instance may still be letting go), an `[emerg]` per failed bind, then
/// `still could not bind()`. Addresses with `reuseport` are skipped, as
/// nginx shares them too.
pub(crate) fn claim_addresses(listens: &[&PreparedListen]) -> Result<(), String> {
    use socket2::{Domain, Protocol, Socket, Type};
    for tries in (0..5).rev() {
        let mut busy = false;
        for prepared in listens.iter().filter(|l| !l.socket.reuseport) {
            let addr = prepared.addr;
            let domain = if addr.is_ipv6() {
                Domain::IPV6
            } else {
                Domain::IPV4
            };
            let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))
                .map_err(|e| format!("socket() {addr} failed ({})", errno_text(&e)))?;
            // nginx sets SO_REUSEADDR, so sockets in TIME_WAIT don't count.
            let _ = socket.set_reuse_address(true);
            if addr.is_ipv6() {
                let _ = socket.set_only_v6(prepared.socket.ipv6only);
            }
            match socket.bind(&addr.into()) {
                Ok(()) => {}
                Err(e) if e.raw_os_error() == Some(libc::EADDRINUSE) => {
                    eprintln!(
                        "ruxen: [emerg] bind() to {addr} failed ({})",
                        errno_text(&e)
                    );
                    busy = true;
                }
                // Anything else (EADDRNOTAVAIL, EACCES) the workers' own
                // bind reports with the same words.
                Err(_) => {}
            }
        }
        if !busy {
            return Ok(());
        }
        if tries > 0 {
            std::thread::sleep(Duration::from_millis(500));
        }
    }
    Err("still could not bind()".to_string())
}

/// The listening socket for `prepared`, with its `listen` options, as
/// nginx's ngx_open_listening_sockets and ngx_configure_listening_sockets:
/// `IPV6_V6ONLY` before bind, the rest before listen. A failed option is an
/// `[alert] … ignored`, as in nginx; a failed bind or listen fails.
pub(crate) fn listen_socket(
    http: &PreparedHttp,
    prepared: &PreparedListen,
) -> std::io::Result<socket2::Socket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let addr = prepared.addr;
    let o = &prepared.socket;
    let domain = if addr.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_nonblocking(true)?;
    socket.set_reuse_port(true)?;
    socket.set_reuse_address(true)?;
    if addr.is_ipv6()
        && let Err(e) = socket.set_only_v6(o.ipv6only)
    {
        listen_alert(
            http,
            prepared,
            format!("IPV6_V6ONLY, {}", o.ipv6only as i32),
            e,
        );
    }
    socket.bind(&addr.into())?;
    set_listen_options(http, prepared, &socket);
    socket.listen(o.backlog)?;
    set_deferred(http, prepared, &socket, false);
    Ok(socket)
}

fn listen_alert(http: &PreparedHttp, prepared: &PreparedListen, what: String, e: std::io::Error) {
    write_worker_log(
        http.error_logs,
        ErrorLogLevel::Alert,
        &format!(
            "setsockopt({what}) {} failed ({}), ignored",
            prepared.addr,
            errno_text(&e)
        ),
    );
}

/// The options set between bind and listen. Also for a socket a reload
/// keeps (`listeners`).
pub(crate) fn set_listen_options(
    http: &PreparedHttp,
    prepared: &PreparedListen,
    socket: &socket2::Socket,
) {
    let o = &prepared.socket;
    let alert = |what: String, e| listen_alert(http, prepared, what, e);
    if let Some(n) = o.rcvbuf
        && let Err(e) = socket.set_recv_buffer_size(n)
    {
        alert(format!("SO_RCVBUF, {n}"), e);
    }
    if let Some(n) = o.sndbuf
        && let Err(e) = socket.set_send_buffer_size(n)
    {
        alert(format!("SO_SNDBUF, {n}"), e);
    }
    if let Some(keepalive) = o.keepalive {
        let on = !matches!(keepalive, crate::config::SoKeepalive::Off);
        if let Err(e) = socket.set_keepalive(on) {
            alert(format!("SO_KEEPALIVE, {}", on as i32), e);
        }
        if let crate::config::SoKeepalive::On { idle, intvl, cnt } = keepalive {
            for (opt, name, value) in [
                (libc::TCP_KEEPIDLE, "TCP_KEEPIDLE", idle),
                (libc::TCP_KEEPINTVL, "TCP_KEEPINTVL", intvl),
                (libc::TCP_KEEPCNT, "TCP_KEEPCNT", cnt),
            ] {
                if let Some(v) = value
                    && let Err(e) = setsockopt_int(socket, libc::IPPROTO_TCP, opt, v as i32)
                {
                    alert(format!("{name}, {v}"), e);
                }
            }
        }
    }
    if let Some(n) = o.fastopen
        && let Err(e) = setsockopt_int(socket, libc::IPPROTO_TCP, libc::TCP_FASTOPEN, n as i32)
    {
        alert(format!("TCP_FASTOPEN, {n}"), e);
    }
}

/// `deferred`, set after listen. nginx: a 1 s defer, since how long a
/// connection queued can't be known. `kept`: a socket a reload keeps, on
/// which the option is cleared again when the new `listen` drops it.
pub(crate) fn set_deferred(
    http: &PreparedHttp,
    prepared: &PreparedListen,
    socket: &socket2::Socket,
    kept: bool,
) {
    if !prepared.socket.deferred && !kept {
        return;
    }
    let on = prepared.socket.deferred as i32;
    if let Err(e) = setsockopt_int(socket, libc::IPPROTO_TCP, libc::TCP_DEFER_ACCEPT, on) {
        listen_alert(http, prepared, format!("TCP_DEFER_ACCEPT, {on}"), e);
    }
}

fn setsockopt_int(
    socket: &socket2::Socket,
    level: libc::c_int,
    name: libc::c_int,
    value: libc::c_int,
) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    // SAFETY: an int option on a socket we own.
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            name,
            (&value as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// A failed `accept`, logged as nginx's ngx_event_accept does: `crit` when
/// out of file descriptors, `error` for a connection the client aborted
/// before it was accepted, `alert` for anything else. An aborted connection
/// is just skipped. Any other error would come back on the next accept at
/// once: io_uring has no readiness gate (nginx only calls accept again when
/// epoll reports a pending connection), so the worker waits 500 ms, as
/// nginx's `accept_mutex_delay` does for EMFILE, instead of spinning. A
/// denied `IORING_OP_ACCEPT` under an io_uring restriction policy fails
/// that way on every call with no client at all (#280). Nothing is said
/// once the worker is stopping: after a worker panicked, `main` shuts the
/// listening sockets down, which fails the accepts in flight (#495).
pub(crate) async fn accept_failed(http: &PreparedHttp, state: &RuntimeState, err: &std::io::Error) {
    if state.is_shutting_down() {
        return;
    }
    let level = match err.raw_os_error() {
        Some(libc::EAGAIN | libc::EINTR | libc::ECANCELED) => return,
        Some(libc::ECONNABORTED) => ErrorLogLevel::Error,
        Some(libc::EMFILE | libc::ENFILE) => ErrorLogLevel::Crit,
        _ => ErrorLogLevel::Alert,
    };
    let message = format!("accept() failed ({})", errno_text(err));
    if level == ErrorLogLevel::Alert {
        // The same error twice a second from every worker would flood the
        // log: say it once a minute, with how often it happened since.
        if let Some(message) = ACCEPT_ALERTS.with(|a| a.borrow_mut().take(Instant::now(), message))
        {
            write_worker_log(http.error_logs, level, &message);
        }
    } else {
        write_worker_log(http.error_logs, level, &message);
    }
    if level != ErrorLogLevel::Error {
        monoio::time::sleep(Duration::from_millis(500)).await;
    }
}

thread_local! {
    static ACCEPT_ALERTS: std::cell::RefCell<RepeatedLine> =
        const { std::cell::RefCell::new(RepeatedLine { last: None, since: 0 }) };
}

/// One log line that may repeat: the first goes out, then at most one a
/// minute, which says how many were held back.
struct RepeatedLine {
    last: Option<Instant>,
    since: u64,
}

impl RepeatedLine {
    const EVERY: Duration = Duration::from_secs(60);

    fn take(&mut self, now: Instant, message: String) -> Option<String> {
        if self
            .last
            .is_some_and(|t| now.duration_since(t) < Self::EVERY)
        {
            self.since += 1;
            return None;
        }
        self.last = Some(now);
        Some(match std::mem::take(&mut self.since) {
            0 => message,
            n => format!("{message}, {n} more like it since the last one"),
        })
    }
}

pub(crate) async fn accept_or_tick(
    listener: &TcpListener,
    tick: &mut AcceptTick,
    state: &RuntimeState,
) -> std::io::Result<Option<(TcpStream, SocketAddr)>> {
    use std::pin::pin;

    let mut accept = pin!(listener.cancelable_accept(tick.canceller.handle()));
    loop {
        monoio::select! {
            res = &mut accept => return res.map(Some),
            _ = tick.timer.as_mut() => {
                tick.timer
                    .as_mut()
                    .reset(monoio::time::Instant::now() + ACCEPT_TICK);
                // Shutdown or a reload wakes the idle connections.
                notice_runtime_events(state);
                if !state.is_shutting_down() {
                    // The accept stays in flight: cancelling and submitting
                    // it again on every tick cost each idle worker CPU.
                    continue;
                }
                // If the accept SQE completed in the same poll batch as the
                // timer, dropping it here closes the accepted fd and the
                // client sees EOF. Cancel the op, then keep whatever the
                // kernel already handed back: a real success (race with
                // cancel) hands us the connection; a genuine cancel returns
                // the canceled-op error. `cancel` hands back a fresh
                // canceller.
                tick.canceller = std::mem::take(&mut tick.canceller).cancel();
                return match accept.await {
                    Ok(pair) => Ok(Some(pair)),
                    Err(_) => Ok(None),
                };
            }
        }
    }
}

/// How often an accept loop wakes without a connection, to notice
/// shutdown and reloads.
const ACCEPT_TICK: Duration = Duration::from_millis(50);

/// An accept loop's tick timer and canceller, kept across accepts: a
/// fresh timer and canceller per accepted connection cost a timer-wheel
/// insert and remove and an allocation each (#128).
pub(crate) struct AcceptTick {
    timer: std::pin::Pin<Box<monoio::time::Sleep>>,
    canceller: monoio::io::Canceller,
}

impl AcceptTick {
    pub(crate) fn new() -> Self {
        AcceptTick {
            timer: Box::pin(monoio::time::sleep(ACCEPT_TICK)),
            canceller: monoio::io::Canceller::new(),
        }
    }
}

pub(crate) async fn wait_readable_or_shutdown(
    stream: &TcpStream,
    state: &RuntimeState,
    idle_timeout: Option<Duration>,
    fresh: bool,
    timers: &mut ConnTimers<'_>,
) -> bool {
    use std::task::Poll;

    let due = idle_timeout.map(|t| monoio::time::Instant::now() + t);
    if let Some(due) = due {
        arm_idle(timers.idle.as_mut(), due);
    }
    let idle = IdleMark::new();
    let mut readable = std::pin::pin!(stream.readable(false));
    // Shutdown, a reload and a drain wake the wait (`IdleMark::register`):
    // no per-connection tick.
    std::future::poll_fn(|cx| {
        if (!fresh && state.is_shutting_down()) || idle.asked_to_close() {
            return Poll::Ready(false);
        }
        if let Poll::Ready(res) = readable.as_mut().poll(cx) {
            return Poll::Ready(res.is_ok());
        }
        if let Some(due) = due
            && idle_expired(timers.idle.as_mut(), due, cx)
        {
            return Poll::Ready(false);
        }
        idle.register(cx.waker());
        Poll::Pending
    })
    .await
}

/// `wait_readable_or_shutdown` with the request read in place of the
/// readiness poll: the read is submitted once and raced against the idle
/// deadline, shutdown, a reload and a drain. When the connection is to
/// close, the read is dropped, which cancels it (monoio's `async-cancel`
/// submits IORING_OP_ASYNC_CANCEL and keeps the buffer until the kernel is
/// done with it); the buffer goes with it, and an empty one comes back.
/// A request arriving just as the timeout fires isn't served then: the
/// connection closes, as nginx's keep-alive timer closes it. A monoio
/// `Canceller` would keep the buffer, but cost a `HashSet` insert and
/// remove (SipHash) per request, about 8% of `m1_hello`'s instructions.
/// `buf`: the request buffer's `[..len]` for plain TCP, or a TLS stream's
/// ciphertext buffer (#145); `None` back when the read was dropped.
pub(crate) async fn read_first_or_shutdown<T: monoio::buf::IoBufMut>(
    stream: &mut TcpStream,
    buf: T,
    state: &RuntimeState,
    idle_timeout: Option<Duration>,
    fresh: bool,
    timers: &mut ConnTimers<'_>,
) -> (IdleRead, Option<T>) {
    use std::task::Poll;

    let due = idle_timeout.map(|t| monoio::time::Instant::now() + t);
    if let Some(due) = due {
        arm_idle(timers.idle.as_mut(), due);
    }
    let idle = IdleMark::new();
    let mut read = std::pin::pin!(stream.read(buf));
    // Shutdown, a reload and a drain wake the wait (`IdleMark::register`):
    // no per-connection tick.
    let done = std::future::poll_fn(|cx| {
        if (!fresh && state.is_shutting_down()) || idle.asked_to_close() {
            return Poll::Ready(None);
        }
        if let Poll::Ready(done) = read.as_mut().poll(cx) {
            return Poll::Ready(Some(done));
        }
        if let Some(due) = due
            && idle_expired(timers.idle.as_mut(), due, cx)
        {
            return Poll::Ready(None);
        }
        idle.register(cx.waker());
        Poll::Pending
    })
    .await;
    match done {
        Some((Ok(n), returned)) if n > 0 => (IdleRead::Read(n), Some(returned)),
        Some((_, returned)) => (IdleRead::Close, Some(returned)),
        // The read is dropped with this frame, and cancelled with it.
        None => (IdleRead::Close, None),
    }
}

/// A connection's read buffer and scratch buffers (see `handle`).
struct ConnBufs {
    buf: Vec<u8>,
    scratch: Vec<u8>,
    url_scratch: Vec<u8>,
}

thread_local! {
    /// Buffers of finished connections, for the next ones.
    static CONN_BUFS: RefCell<Vec<ConnBufs>> = const { RefCell::new(Vec::new()) };
}

/// Sets kept per worker; beyond that, finished connections free theirs.
const CONN_BUFS_KEPT: usize = 64;
/// A scratch buffer that grew past this (a large response) isn't kept.
const CONN_SCRATCH_KEEP: usize = 64 * 1024;

impl ConnBufs {
    /// `size`: `client_header_buffer_size` (#467). An idle keep-alive
    /// connection holds its read buffer in the kernel's read, so it starts
    /// as small as nginx's; `scratch` is allocated when a response first
    /// needs it.
    fn take(size: usize) -> ConnBufs {
        let mut bufs = CONN_BUFS
            .with(|pool| pool.borrow_mut().pop())
            .unwrap_or_else(|| ConnBufs {
                buf: Vec::new(),
                scratch: Vec::new(),
                url_scratch: Vec::with_capacity(256),
            });
        bufs.buf.resize(size, 0);
        bufs
    }
}

impl Drop for ConnBufs {
    fn drop(&mut self) {
        // A buffer still lent to an I/O operation (empty here) or grown
        // large isn't kept.
        if self.buf.is_empty()
            || self.buf.capacity() > READ_BUF
            || self.scratch.capacity() > CONN_SCRATCH_KEEP
            || self.url_scratch.capacity() > CONN_SCRATCH_KEEP
        {
            return;
        }
        // `try_with`: the pool itself may be going away with the thread.
        let _ = CONN_BUFS.try_with(|pool| {
            let Ok(mut pool) = pool.try_borrow_mut() else {
                return;
            };
            if pool.len() >= CONN_BUFS_KEPT {
                return;
            }
            let mut kept = ConnBufs {
                buf: std::mem::take(&mut self.buf),
                scratch: std::mem::take(&mut self.scratch),
                url_scratch: std::mem::take(&mut self.url_scratch),
            };
            kept.scratch.clear();
            kept.url_scratch.clear();
            pool.push(kept);
        });
    }
}

pub(crate) struct ConnectionGuard;

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        WORKER_CONNS.with(|w| {
            w.active.set(w.active.get().saturating_sub(1));
            w.clients.set(w.clients.get().saturating_sub(1));
        });
    }
}

/// This worker's accepted connections that haven't finished: a shutting
/// down worker waits for them. Per worker, so an accept touches no cache
/// line another worker writes (#128).
/// The configuration this worker thread serves; `None` outside a worker.
pub(crate) fn worker_http() -> Option<&'static PreparedHttp> {
    WORKER_CONNS.with(|w| w.http.get())
}

fn worker_clients() -> usize {
    WORKER_CONNS.with(|w| w.clients.get())
}

fn connection_started() {
    WORKER_CONNS.with(|w| w.clients.set(w.clients.get() + 1));
}

/// This worker's share of `worker_connections`, and nginx's reuse of idle
/// connections when it runs low (`ngx_drain_connections`). A worker is a
/// thread that owns its connections, so thread-local cells are enough.
struct WorkerConns {
    /// Accepted connections that haven't finished, and upstream
    /// connections (`UpstreamSlot`): nginx takes both from the worker's
    /// one connection table.
    active: Cell<usize>,
    /// Accepted connections that haven't finished (`worker_clients`).
    clients: Cell<usize>,
    /// Connections waiting for a request — nginx's "reusable" ones.
    idle: Cell<usize>,
    /// How many idle connections are asked to close to make room.
    drain: Cell<usize>,
    /// The wakers of the idle connections (`IdleMark` slots), woken when
    /// one of the events they wait for happens: a drain, shutdown or a
    /// reload. Pushed to them like nginx's ngx_drain_connections /
    /// ngx_close_idle_connections, instead of each one polling (#127).
    idle_wakers: std::cell::RefCell<Vec<Option<std::task::Waker>>>,
    idle_free: std::cell::RefCell<Vec<usize>>,
    /// Shutdown and the reload generation as this worker last saw them.
    seen_shutdown: Cell<bool>,
    seen_reload_gen: Cell<u64>,
    /// UNIX second of the last "not enough" line: log once a second.
    logged_at: Cell<u64>,
    /// This worker's configuration, for upstream connections, which are
    /// opened where only the proxy plan is at hand.
    http: Cell<Option<&'static PreparedHttp>>,
}

thread_local! {
    static WORKER_CONNS: WorkerConns = const {
        WorkerConns {
            active: Cell::new(0),
            clients: Cell::new(0),
            idle: Cell::new(0),
            drain: Cell::new(0),
            idle_wakers: std::cell::RefCell::new(Vec::new()),
            idle_free: std::cell::RefCell::new(Vec::new()),
            seen_shutdown: Cell::new(false),
            seen_reload_gen: Cell::new(0),
            logged_at: Cell::new(0),
            http: Cell::new(None),
        }
    };
}

/// An upstream connection's slot in `worker_connections`, held as long as
/// the socket lives (in the pool too). Outside a worker (unit tests)
/// nothing is counted.
pub(crate) struct UpstreamSlot {
    counted: bool,
}

impl Drop for UpstreamSlot {
    fn drop(&mut self) {
        if self.counted {
            WORKER_CONNS.with(|w| w.active.set(w.active.get().saturating_sub(1)));
        }
    }
}

/// A slot for a new upstream connection, as nginx's ngx_event_connect_peer
/// takes one from ngx_get_connection. With none free, an idle keep-alive
/// upstream connection is closed to make room; failing that, `None`: the
/// worker logs "worker_connections are not enough", asks idle client
/// connections to close for later, and the request gets a 500
/// (`internal_error_response`), as nginx's ngx_http_upstream_connect.
pub(crate) fn take_upstream_slot() -> Option<UpstreamSlot> {
    WORKER_CONNS.with(|w| {
        let Some(http) = w.http.get() else {
            return Some(UpstreamSlot { counted: false });
        };
        if w.active.get() >= http.client_slots() && !crate::upstream::pool_close_one() {
            let idle = w.idle.get();
            if idle > 0 {
                w.drain.set(w.drain.get().max((idle / 8).clamp(1, 32)));
                wake_idle_in(w);
            }
            log_connections_not_enough(w, http, ErrorLogLevel::Alert, "");
            return None;
        }
        w.active.set(w.active.get() + 1);
        Some(UpstreamSlot { counted: true })
    })
}

/// The 500 for a request whose upstream connection got no slot.
#[cold]
pub(crate) fn internal_error_response(method: Method) -> Response {
    let http = WORKER_CONNS.with(|w| w.http.get());
    match http {
        Some(http) => Response::Prebuilt(http.internal_error.pick(method)),
        None => Response::Owned(http::error_response_for_method(
            500,
            "Internal Server Error\n",
            method,
            b"ruxen",
        )),
    }
}

/// Count a newly accepted connection against the worker's slots. When few
/// are left, ask up to 32 idle connections (an eighth of them) to close,
/// as nginx does below a sixteenth free; with none left, `false`: the new
/// connection is closed, as when nginx's ngx_get_connection fails.
pub(crate) fn admit_connection(http: &PreparedHttp) -> bool {
    let slots = http.client_slots();
    WORKER_CONNS.with(|w| {
        // An idle keep-alive upstream connection gives its slot first.
        if w.active.get() >= slots {
            crate::upstream::pool_close_one();
        }
        let active = w.active.get();
        let idle = w.idle.get();
        let full = active >= slots;
        if slots - active.min(slots) <= slots / 16 && idle > 0 {
            w.drain.set(w.drain.get().max((idle / 8).clamp(1, 32)));
            wake_idle_in(w);
            if !full {
                log_connections_not_enough(w, http, ErrorLogLevel::Warn, ", reusing connections");
            }
        }
        if full {
            log_connections_not_enough(w, http, ErrorLogLevel::Alert, "");
            return false;
        }
        w.active.set(active + 1);
        true
    })
}

fn log_connections_not_enough(
    w: &WorkerConns,
    http: &PreparedHttp,
    level: ErrorLogLevel,
    tail: &str,
) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if w.logged_at.replace(now) != now {
        write_worker_log(
            http.error_logs,
            level,
            &format!(
                "{} worker_connections are not enough{tail}",
                http.worker_connections
            ),
        );
    }
}

/// Wakes this worker's idle connections, to look at what changed.
fn wake_idle_in(w: &WorkerConns) {
    for waker in w.idle_wakers.borrow().iter().flatten() {
        waker.wake_by_ref();
    }
}

thread_local! {
    /// This worker's beat for systemd's watchdog (#502), set once it may
    /// accept.
    static HEARTBEAT: std::cell::OnceCell<std::sync::Arc<AtomicU64>> =
        const { std::cell::OnceCell::new() };
}

/// Called by the accept loops on every turn (they wake at least every
/// 50 ms): when shutdown began or a reload came since this worker last
/// looked, its idle connections are woken to close. Two atomic loads when
/// nothing changed.
pub(crate) fn notice_runtime_events(state: &RuntimeState) {
    // A turn of the accept loop: the worker isn't stuck.
    HEARTBEAT.with(|beat| {
        if let Some(beat) = beat.get() {
            beat.fetch_add(1, Ordering::Relaxed);
        }
    });
    WORKER_CONNS.with(|w| {
        let shutdown = state.is_shutting_down();
        let generation = state.reload_gen();
        if shutdown != w.seen_shutdown.get() || generation != w.seen_reload_gen.get() {
            w.seen_shutdown.set(shutdown);
            w.seen_reload_gen.set(generation);
            wake_idle_in(w);
        }
    })
}

/// Marks a connection idle (waiting for a request) while alive, so
/// `admit_connection` can ask it to make room, and holds its slot in the
/// worker's list of idle wakers.
struct IdleMark {
    slot: usize,
}

impl IdleMark {
    fn new() -> Self {
        WORKER_CONNS.with(|w| {
            w.idle.set(w.idle.get() + 1);
            let slot = match w.idle_free.borrow_mut().pop() {
                Some(slot) => slot,
                None => {
                    let mut wakers = w.idle_wakers.borrow_mut();
                    wakers.push(None);
                    wakers.len() - 1
                }
            };
            IdleMark { slot }
        })
    }

    /// The waker the events above wake.
    fn register(&self, waker: &std::task::Waker) {
        WORKER_CONNS.with(|w| {
            let mut wakers = w.idle_wakers.borrow_mut();
            match &mut wakers[self.slot] {
                Some(old) if old.will_wake(waker) => {}
                slot => *slot = Some(waker.clone()),
            }
        })
    }

    /// Whether this idle connection should close to free a slot.
    fn asked_to_close(&self) -> bool {
        WORKER_CONNS.with(|w| {
            let drain = w.drain.get();
            if drain == 0 {
                return false;
            }
            w.drain.set(drain - 1);
            true
        })
    }
}

/// Wakes a task on shutdown or reload like an idle connection, without
/// counting it as idle: an upgraded connection is busy, and isn't one to
/// close to make room.
pub(crate) struct EventWatch {
    slot: usize,
}

impl EventWatch {
    pub(crate) fn new() -> Self {
        WORKER_CONNS.with(|w| {
            let slot = match w.idle_free.borrow_mut().pop() {
                Some(slot) => slot,
                None => {
                    let mut wakers = w.idle_wakers.borrow_mut();
                    wakers.push(None);
                    wakers.len() - 1
                }
            };
            EventWatch { slot }
        })
    }

    pub(crate) fn register(&self, waker: &std::task::Waker) {
        WORKER_CONNS.with(|w| {
            let mut wakers = w.idle_wakers.borrow_mut();
            match &mut wakers[self.slot] {
                Some(old) if old.will_wake(waker) => {}
                slot => *slot = Some(waker.clone()),
            }
        })
    }
}

impl Drop for EventWatch {
    fn drop(&mut self) {
        WORKER_CONNS.with(|w| {
            w.idle_wakers.borrow_mut()[self.slot] = None;
            w.idle_free.borrow_mut().push(self.slot);
        });
    }
}

impl Drop for IdleMark {
    fn drop(&mut self) {
        WORKER_CONNS.with(|w| {
            w.idle.set(w.idle.get().saturating_sub(1));
            w.idle_wakers.borrow_mut()[self.slot] = None;
            w.idle_free.borrow_mut().push(self.slot);
        });
    }
}

/// Arms the idle timer for `due` without moving it on every request: a
/// timer already set for earlier stays, and when it fires early the wait
/// moves it to `due` (`idle_expired`). Moving a timer per keep-alive
/// request cost several percent (#127, #272).
fn arm_idle(mut timer: std::pin::Pin<&mut monoio::time::Sleep>, due: monoio::time::Instant) {
    if timer.is_elapsed() || timer.deadline() > due {
        timer.as_mut().reset(due);
    }
}

/// Whether the idle deadline `due` has passed; a timer that fired before
/// it is moved to it and polled again.
fn idle_expired(
    mut timer: std::pin::Pin<&mut monoio::time::Sleep>,
    due: monoio::time::Instant,
    cx: &mut std::task::Context<'_>,
) -> bool {
    if timer.as_mut().poll(cx).is_pending() {
        return false;
    }
    if monoio::time::Instant::now() < due {
        timer.as_mut().reset(due);
        return timer.as_mut().poll(cx).is_ready();
    }
    true
}

/// `$server_addr` for a connection: the listen address, formatted at
/// startup, or for a wildcard listen the socket's own local address. That
/// takes a `getsockname`, so it's done only when some value reads
/// `$server_addr` (nginx calls it lazily, `ngx_connection_local_sockaddr`).
fn server_addr_text(
    listen: &PreparedListen,
    stream: &TcpStream,
) -> std::borrow::Cow<'static, [u8]> {
    if !listen.addr_text.is_empty()
        || !crate::config::SERVER_ADDR_USED.load(std::sync::atomic::Ordering::Relaxed)
    {
        return std::borrow::Cow::Borrowed(listen.addr_text);
    }
    local_addr_text(stream)
}

#[cold]
#[inline(never)]
fn local_addr_text(stream: &TcpStream) -> std::borrow::Cow<'static, [u8]> {
    match stream.local_addr() {
        Ok(addr) => std::borrow::Cow::Owned(addr.ip().to_string().into_bytes()),
        Err(_) => std::borrow::Cow::Borrowed(b""),
    }
}

#[allow(clippy::too_many_arguments)] // hot path: a parameter struct needs ABBA numbers first
pub(crate) async fn handle_plain(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    listen_index: usize,
    http: &'static PreparedHttp,
    state: &'static RuntimeState,
    connection_id: u64,
    proxy_protocol: Option<crate::proxy_protocol::ProxyHeader>,
    accepted_at: Instant,
    _guard: ConnectionGuard,
) {
    let conn = phase::ConnInfo {
        server_addr: server_addr_text(&http.listens[listen_index], &stream),
        peer_ip: peer_addr.ip(),
        peer_unix: http.listens[listen_index].unix.is_some(),
        realip: None,
        proxy_protocol,
        plain_http: false,
        accepted_at: Some(accepted_at),
    };
    let listen = &http.listens[listen_index];
    // Boxed, here and in `handle_tls`: awaited in place, the HTTP/2
    // futures would make every connection's task larger.
    if listen.h2_plain {
        let wait = listen.servers[listen.default_server].timeouts.header;
        if Box::pin(super::h2::starts_with_preface(&stream, wait)).await {
            return serve_h2(
                stream,
                peer_addr,
                listen_index,
                None,
                None,
                conn,
                http,
                state,
                connection_id,
            )
            .await;
        }
    }
    // Boxed: the connection's future is about 10 KiB, and the task that
    // `spawn_connection` builds would otherwise be moved, all of it, into
    // the runtime on every accept. Here the task stays small and the big
    // future is placed once (#128).
    Box::pin(handle(
        &mut stream,
        peer_addr,
        listen_index,
        None,
        None,
        &conn,
        http,
        state,
        connection_id,
    ))
    .await;
}

/// A TLS handshake that failed, to the default server's error log at
/// `info` in nginx's words (ngx_ssl_handshake, ngx_ssl_connection_error;
/// 1.30.6 logs these at `info`), not on stderr (#595).
#[cold]
#[inline(never)]
fn handshake_failed(
    http: &PreparedHttp,
    listen_index: usize,
    connection_id: u64,
    peer_addr: SocketAddr,
    e: &crate::tls::AcceptError,
) {
    let listen = &http.listens[listen_index];
    let reason = match e {
        crate::tls::AcceptError::Timeout => {
            "client timed out (110: Connection timed out)".to_string()
        }
        crate::tls::AcceptError::Tls(e) => match e.kind() {
            std::io::ErrorKind::UnexpectedEof => {
                "peer closed connection in SSL handshake".to_string()
            }
            // What rustls refused: the ClientHello or a later message.
            std::io::ErrorKind::InvalidData => {
                let inner = e.get_ref().map_or_else(|| e.to_string(), |i| i.to_string());
                format!("SSL_do_handshake() failed (SSL: {inner})")
            }
            _ => format!("recv() failed ({})", errno_text(e)),
        },
    };
    write_worker_log(
        listen.servers[listen.default_server].error_logs,
        ErrorLogLevel::Info,
        &format!(
            "*{connection_id} {reason} while SSL handshaking, client: {}, server: {}",
            peer_addr.ip(),
            listen.addr
        ),
    );
}

/// A TLS record after the handshake that rustls refused, as nginx's
/// `SSL_read() failed` at `info` (#595): `while waiting for request` before
/// any byte of one, else while reading its head.
#[cold]
#[inline(never)]
fn tls_read_failed(
    http: &PreparedHttp,
    listen_index: usize,
    connection_id: u64,
    peer_addr: SocketAddr,
    filled: usize,
    e: &std::io::Error,
) {
    let listen = &http.listens[listen_index];
    let inner = e.get_ref().map_or_else(|| e.to_string(), |i| i.to_string());
    let action = if filled == 0 {
        "waiting for request"
    } else {
        "reading client request headers"
    };
    write_worker_log(
        listen.servers[listen.default_server].error_logs,
        ErrorLogLevel::Info,
        &format!(
            "*{connection_id} SSL_read() failed (SSL: {inner}) while {action}, client: {}, server: {}",
            peer_addr.ip(),
            listen.addr
        ),
    );
}

#[allow(clippy::too_many_arguments)] // hot path: a parameter struct needs ABBA numbers first
pub(crate) async fn handle_tls(
    stream: TcpStream,
    acceptor: Arc<crate::tls::TlsAcceptor>,
    peer_addr: SocketAddr,
    listen_index: usize,
    http: &'static PreparedHttp,
    state: &'static RuntimeState,
    connection_id: u64,
    proxy_protocol: Option<crate::proxy_protocol::ProxyHeader>,
    accepted_at: Instant,
    _guard: ConnectionGuard,
) {
    // nginx 1.24 has no separate handshake timeout: the handshake runs
    // under the default server's client_header_timeout, armed at accept
    // (ngx_http_init_connection), so a PROXY header read shares it.
    let listen = &http.listens[listen_index];
    let budget = listen.servers[listen.default_server].timeouts.header;
    let conn = phase::ConnInfo {
        server_addr: server_addr_text(&http.listens[listen_index], &stream),
        peer_ip: peer_addr.ip(),
        peer_unix: http.listens[listen_index].unix.is_some(),
        realip: None,
        proxy_protocol,
        plain_http: false,
        accepted_at: Some(accepted_at),
    };
    let budget = budget.saturating_sub(accepted_at.elapsed());
    let accepted =
        if listen.reject_handshake.is_some() || listen.h2_by_sni || listen.tls_contexts_by_sni {
            crate::tls::accept_choosing_with_timeout(&acceptor, stream, budget, |sni| {
                phase::tls_choice(listen, sni)
            })
            .await
        } else {
            crate::tls::accept_with_timeout(&acceptor, stream, budget).await
        };
    let (mut tls_stream, info) = match accepted {
        Ok(crate::tls::Handshake::Tls(stream, info)) => (stream, info),
        Ok(crate::tls::Handshake::Plain(stream, read)) => {
            // Plain HTTP on the `ssl` port (#384): read as HTTP/1, then
            // answered with 497 (`conn.plain_http`).
            let conn = phase::ConnInfo {
                plain_http: true,
                ..conn
            };
            let mut stream = super::connection::Preread::new(stream, read);
            Box::pin(handle(
                &mut stream,
                peer_addr,
                listen_index,
                None,
                None,
                &conn,
                http,
                state,
                connection_id,
            ))
            .await;
            return;
        }
        // `ssl_reject_handshake`: nginx logs nothing above debug for it.
        Err(crate::tls::AcceptError::Tls(e))
            if e.kind() == std::io::ErrorKind::ConnectionRefused =>
        {
            return;
        }
        Err(e) => {
            handshake_failed(http, listen_index, connection_id, peer_addr, &e);
            return;
        }
    };
    // Lowercase SNI once at handshake time so the per-request find_config
    // fallback can do byte-equal comparisons against prepared (already-
    // lowercased) server_name tables. rustls validates the SNI as a DNS
    // name but doesn't case-fold; we do it here once so the request hot
    // path stays a slice compare.
    let sni: Option<Vec<u8>> = info.server_name.as_deref().map(|s| {
        s.as_bytes()
            .iter()
            .map(|b| b.to_ascii_lowercase())
            .collect()
    });
    if info.alpn_protocol.as_deref() == Some(b"h2") {
        // A read and a write run at once on an HTTP/2 connection.
        tls_stream.begin_tunnel();
        let sni = sni.clone();
        return serve_h2(
            tls_stream,
            peer_addr,
            listen_index,
            sni,
            Some(info),
            conn,
            http,
            state,
            connection_id,
        )
        .await;
    }
    // Boxed, as in `handle_plain`.
    Box::pin(handle(
        &mut tls_stream,
        peer_addr,
        listen_index,
        sni.as_deref(),
        Some(&info),
        &conn,
        http,
        state,
        connection_id,
    ))
    .await;
    // close_notify before TCP FIN. Best-effort: peer may already have gone
    // away; we don't have anything useful to do with the error. A client
    // that doesn't read (a tunnel that ended on send_timeout) gets 3 s, as
    // ngx_ssl_shutdown gives it.
    let _ = monoio::time::timeout(
        Duration::from_secs(3),
        monoio::io::AsyncWriteRent::shutdown(&mut tls_stream),
    )
    .await;
}

/// An HTTP/2 connection (#144), cold: boxed so its future isn't part of
/// the HTTP/1.1 connection's.
#[cold]
#[inline(never)]
#[allow(clippy::too_many_arguments)]
fn serve_h2<S>(
    stream: S,
    peer_addr: SocketAddr,
    listen_index: usize,
    sni: Option<Vec<u8>>,
    tls: Option<crate::tls::HandshakeInfo>,
    conn: phase::ConnInfo,
    http: &'static PreparedHttp,
    state: &'static RuntimeState,
    connection_id: u64,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()>>>
where
    S: ConnIo + 'static,
{
    Box::pin(super::h2::serve(
        stream,
        super::h2::ConnCtx {
            peer_addr,
            listen_index,
            sni,
            tls,
            conn,
            http,
            state,
            connection_id,
        },
    ))
}

/// The `100 Continue` of a request whose body nobody reads, before its
/// response, where nginx's discard sends it: not before an error the
/// special response handler answers, as that sets `expect_tested` first
/// (`phase::discard_continue`). `false`: the write failed.
#[cold]
#[inline(never)]
async fn continue_first<S: ConnIo>(
    stream: &mut S,
    response: &Response,
    continue_status: Option<u16>,
    timer: std::pin::Pin<&mut monoio::time::Sleep>,
    send_timeout: Duration,
) -> bool {
    let head: &[u8] = match response {
        Response::Prebuilt(bytes) => bytes,
        Response::Owned(bytes) => bytes,
        Response::File { headers, .. } => headers,
        _ => return true,
    };
    let status = response_status(head);
    let continues = match continue_status {
        Some(returned) => status == returned,
        None => matches!(status, 200..=299 | 304 | 412 | 416),
    };
    if !continues {
        return true;
    }
    let resp = b"HTTP/1.1 100 Continue\r\n\r\n".to_vec();
    let len = resp.len();
    write_all_timed(stream, resp, len, timer, send_timeout)
        .await
        .0
        .is_ok()
}

/// The rest of a body nobody reads, after the response went out (#627),
/// as nginx's ngx_http_discarded_request_body_handler reads it: under
/// `lingering_timeout` per read and `lingering_time` in all
/// (ngx_http_finalize_connection), not `client_body_timeout`. `buf`: the
/// read buffer, where a chunked body starts. The bytes read past a chunked
/// body, which start the next request, when the connection may serve it;
/// `None` when it closes. An HTTP/2 stream ends instead (the `h2` crate
/// then resets it with NO_ERROR, which tells the client to stop sending,
/// as nginx's ngx_http_v2_close_stream does); a connection that closes
/// anyway gets a lingering close so the response isn't lost to a reset.
#[cold]
#[inline(never)]
async fn discard_after_response<S: ConnIo>(
    stream: &mut S,
    rest: PendingDiscard,
    buf: &[u8],
    close_after: bool,
    scratch: &mut Vec<u8>,
    timer: std::pin::Pin<&mut monoio::time::Sleep>,
) -> Option<Vec<u8>> {
    if stream.h2() {
        return None;
    }
    if close_after {
        lingering_close(stream, scratch).await;
        return None;
    }
    match rest {
        PendingDiscard::Chunked { from } => discard_chunked_body(stream, &buf[from..], timer).await,
        PendingDiscard::Length(rest) => monoio::time::timeout(
            LINGERING_TIME,
            discard_request_body(stream, rest, timer, LINGERING_TIMEOUT),
        )
        .await
        .unwrap_or(false)
        .then(Vec::new),
    }
}

/// What is left of a body nobody reads when its response goes out.
#[derive(Clone, Copy)]
enum PendingDiscard {
    /// This many bytes of a Content-Length body.
    Length(u64),
    /// A chunked one, all of it read so far starting at `from` in the
    /// read buffer.
    Chunked { from: usize },
}

#[allow(clippy::too_many_arguments)] // hot path: a parameter struct needs ABBA numbers first
pub(crate) async fn handle<S: ConnIo>(
    stream: &mut S,
    peer_addr: SocketAddr,
    listen_index: usize,
    sni: Option<&[u8]>,
    tls: Option<&crate::tls::HandshakeInfo>,
    conn: &phase::ConnInfo,
    http: &'static PreparedHttp,
    state: &'static RuntimeState,
    connection_id: u64,
) {
    // Mirrors nginx's keepalive_handler ↔ wait_request_handler dance: no
    // read buffer is held while the connection is idle. On idle-to-active
    // transition we PollAdd for readability (one io_uring SQE, no buffer),
    // then allocate the 8 KiB read buffer when data is actually arriving.
    //
    // Outer loop = idle ↔ active cycle; inner loop = within an active
    // session, read more / parse / write until the session drains back to
    // empty (→ idle) or the request-line overflows the buffer (→ close).
    let mut parse_state = ParseState {
        h2: stream.h2(),
        ..ParseState::default()
    };

    // Per-connection counters surfaced via `$connection*` variables.
    // `connection_id` is assigned once in the accept loop. `request_count` tracks
    // requests on this connection *including* the one being processed —
    // nginx increments `r->connection->requests` at request init, so
    // `$connection_requests` reads 1 on the first request, 2 on the
    // second, etc. Incrementing before rendering matches that contract.
    let (connection_start, mut request_count) = stream
        .conn_counters()
        .unwrap_or_else(|| (Instant::now(), 0));
    let mut remote_addr_buf = [0u8; 48];
    let (remote_addr, remote_port): (&[u8], u16) = if http.listens[listen_index].unix.is_some() {
        // A unix-domain client is `unix:`, with no port (#263).
        (b"unix:", 0)
    } else {
        // `$remote_addr`, written once into the connection's own state
        // rather than a heap string per connection (#128).
        use std::io::Write;
        let mut cursor = std::io::Cursor::new(&mut remote_addr_buf[..]);
        let _ = write!(cursor, "{}", peer_addr.ip());
        let n = cursor.position() as usize;
        (&remote_addr_buf[..n], peer_addr.port())
    };
    // The default server's client timeouts: the header is read before a
    // virtual server is chosen (as in nginx). A request's body and response
    // use its location's client_body_timeout and send_timeout (#147).
    // Borrowed, not copied: the connection's future holds a pointer, not
    // the struct, which grew with `h2_chunk` (#594).
    let timeouts: &'static PreparedClientTimeouts = {
        let listen = &http.listens[listen_index];
        &listen.servers[listen.default_server].timeouts
    };
    // A new connection's first request head, the wait for it included, is
    // due client_header_timeout after the accept, as under nginx's one
    // accept timer, which a TLS handshake or a PROXY header used part of
    // (#484). Later heads get it from their first bytes, and the waits
    // for them keepalive_timeout. An HTTP/2 stream's head comes whole.
    let mut first_head_due = conn
        .accepted_at
        .filter(|_| !stream.h2())
        .map(|at| at + timeouts.header);
    let mut keepalive_idle_timeout: Option<Duration> =
        Some(first_head_due.map_or(timeouts.header, |due| {
            due.saturating_duration_since(Instant::now())
        }));
    // When the current request's header must be complete; set on the first
    // read for it, cleared once the request is handled.
    let mut header_deadline: Option<monoio::time::Instant>;
    // Long-lived timers for this connection (see `ConnTimers`).
    let far = Duration::from_secs(3600);
    let mut timers = ConnTimers {
        io: std::pin::pin!(monoio::time::sleep(far)),
        idle: std::pin::pin!(monoio::time::sleep(far)),
    };
    // A reload bumps the retired generation's counter: an upgraded
    // connection then lives until `worker_shutdown_timeout` (`tunnel`).
    let start_reload_gen = state.reload_gen();
    // Waiting for the first request: a shutdown or reload doesn't close
    // the connection, as nginx's ngx_close_idle_connections closes only
    // keep-alive ones; client_header_timeout bounds the wait. A connection
    // an old worker accepted just before it stopped is served, not reset.
    let mut fresh = true;
    // The last request's body was read from the socket, up to its end: the
    // next request may be queued behind it (`read_queued`).
    let mut body_read = false;

    // Per-connection scratch buffers — allocated once and reused across
    // every request on this connection. `mem::take` during `write_all`
    // briefly leaves these empty, monoio returns the Vec after the I/O
    // completes, and we restore it. `buf` lives outside `'idle: loop`
    // because non-pipelining clients (wrk, curl) drain `buf` after each
    // response and `continue 'idle`, so a per-iteration alloc here was
    // showing up as ~3% memset / ~1% calloc in the proxy bench profile.
    // Taken from this worker's pool and given back when the connection
    // ends: a connection per request doesn't allocate (and zero) them each
    // time (#128).
    // An HTTP/2 stream's head is rebuilt here, with its body's start: not
    // nginx's client_header_buffer_size, whose body goes into
    // http2_body_preread_size.
    let mut bufs = ConnBufs::take(if stream.h2() {
        READ_BUF
    } else {
        timeouts.header_buffer
    });
    // Set once the zero-copy `sendfile` path has put the socket in
    // O_NONBLOCK mode; see `send_head_and_file`.
    let mut sock_nonblocking = false;
    let ConnBufs {
        buf,
        scratch,
        url_scratch,
    } = &mut bufs;

    // Context for `reject_request`'s access-log line.
    macro_rules! conn_log {
        () => {
            &ConnLogCtx {
                listen_index,
                remote_addr: &remote_addr,
                remote_port,
                connection_id,
                connection_requests: request_count,
                connection_start,
                tls,
                conn,
            }
        };
    }

    // stub_status / $connections_* (#96); inert unless the config reads them.
    let mut conn_stats = super::stats::ConnStats::new(http.stats);

    'idle: loop {
        conn_stats.set(super::stats::Phase::Waiting);
        let (buf_ptr, buf_len) = (buf.as_ptr(), buf.len());
        let next = match std::mem::take(&mut body_read) {
            true => read_queued(stream, buf, state),
            false => None,
        };
        let next = match next {
            Some(next) => next,
            None => {
                let (next, returned) = stream
                    .idle_read(
                        std::mem::take(&mut *buf),
                        state,
                        keepalive_idle_timeout,
                        std::mem::take(&mut fresh),
                        &mut timers,
                    )
                    .await;
                *buf = returned;
                next
            }
        };
        let mut filled: usize = match next {
            IdleRead::Close => return,
            IdleRead::Ready => 0,
            IdleRead::Read(n) => n,
        };
        restore_read_len(buf, buf_ptr, buf_len);
        conn_stats.set(super::stats::Phase::Reading);
        keepalive_idle_timeout = None;
        // The header's time starts with its first bytes, as nginx's
        // client_header_timeout after the keep-alive read; the first
        // request's runs from the accept.
        header_deadline = match first_head_due.take() {
            Some(due) => Some(monoio::time::Instant::from_std(due)),
            None => (filled > 0).then(|| monoio::time::Instant::now() + timeouts.header),
        };

        let mut read_start: usize = 0; // first unread byte of the current request
        // The first bytes came with the idle wait: parse before reading.
        let mut skip_read = filled > 0;

        loop {
            if std::mem::take(&mut skip_read) {
                // Fall through to the parse loop with what idle_read read.
            } else {
                // The read takes the buffer, and one that times out keeps
                // it: what came of the head is put aside for its log line
                // (#509). Only a head that didn't come in one read.
                if filled > read_start {
                    scratch.clear();
                    scratch.extend_from_slice(&buf[read_start..filled]);
                }
                let taken = std::mem::take(&mut *buf);
                let (buf_ptr, end) = (taken.as_ptr(), taken.len());
                let slice = taken.slice_mut(filled..end);
                let deadline = *header_deadline
                    .get_or_insert_with(|| monoio::time::Instant::now() + timeouts.header);
                let read = with_deadline(timers.io.as_mut(), deadline, stream.read(slice));
                // client_header_timeout: nginx closes without a response,
                // and logs the request if it had begun (#509).
                let Some((res, returned)) = read.await else {
                    if filled > read_start {
                        log_unfinished_head(
                            http,
                            &scratch[..],
                            parse_state.rline_done,
                            HeadCut::TimedOut,
                            conn_log!(),
                        )
                        .await;
                    }
                    return;
                };
                *buf = returned.into_inner();
                restore_read_len(buf, buf_ptr, end);
                match res {
                    Ok(n) if n > 0 => filled += n,
                    // What a TLS stream couldn't decrypt or rustls refused
                    // (#595); plain TCP never says InvalidData.
                    Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
                        tls_read_failed(http, listen_index, connection_id, peer_addr, filled, &e);
                        return;
                    }
                    res => {
                        if filled > read_start {
                            let cut = match &res {
                                Ok(_) => HeadCut::Closed,
                                Err(e) => HeadCut::Failed(e),
                            };
                            log_unfinished_head(
                                http,
                                &buf[read_start..filled],
                                parse_state.rline_done,
                                cut,
                                conn_log!(),
                            )
                            .await;
                        }
                        return;
                    }
                }
            }

            loop {
                let view = &buf[read_start..filled];
                match http::parse_request(view, &mut parse_state) {
                    Parse::Complete(req) => {
                        // Only a head longer than one line may hold: is
                        // each line within `large_client_header_buffers`?
                        // An HTTP/2 stream's fields were checked as nginx
                        // does when it arrived (#623); its head is rebuilt.
                        if req.consumed > timeouts.large_header_line
                            && !stream.h2()
                            && let Some(line) = overlong_head_line(
                                &buf[read_start..read_start + req.consumed],
                                timeouts.large_header_line,
                                timeouts.large_header,
                            )
                        {
                            let head = &buf[read_start..read_start + req.consumed];
                            if line > 0
                                && let Some(refusal) =
                                    parsed_line_refusal(head, &req, timeouts.large_header_line)
                            {
                                refuse_line(
                                    stream,
                                    &mut *scratch,
                                    http,
                                    head,
                                    refusal,
                                    conn_log!(),
                                )
                                .await;
                                return;
                            }
                            head_too_large(
                                stream,
                                &mut *scratch,
                                http,
                                head,
                                (line > 0).then_some(line),
                                conn_log!(),
                            )
                            .await;
                            return;
                        }
                        // `max_headers` (#584): only a block long enough
                        // to hold more lines is counted.
                        if req.headers_end - req.headers_start >= timeouts.max_headers_span
                            && too_many_header_lines(
                                &buf[read_start + req.headers_start..read_start + req.headers_end],
                                timeouts
                                    .max_headers
                                    .saturating_add(stream.h2_synthetic_lines()),
                            )
                        {
                            let head = &buf[read_start..read_start + req.consumed];
                            if let Some(refusal) =
                                parsed_line_refusal(head, &req, timeouts.large_header_line)
                            {
                                refuse_line(
                                    stream,
                                    &mut *scratch,
                                    http,
                                    head,
                                    refusal,
                                    conn_log!(),
                                )
                                .await;
                                return;
                            }
                            many_header_lines(stream, &mut *scratch, http, head, conn_log!()).await;
                            return;
                        }
                        conn_stats.request();
                        let request_start = Instant::now();
                        // Counted up front so a request refused below logs
                        // `$connection_requests` as nginx does.
                        request_count = request_count.saturating_add(1);
                        // All offsets in `req` are relative to `view`; shift
                        // to absolute buffer offsets before indexing.
                        let base = read_start;
                        // Copy the method out of the read buffer up front
                        // (from when the host was lowercased in it): onto
                        // the stack, or, for one longer than any standard
                        // method, to the heap; nginx has no length limit
                        // (#485).
                        let method_len = req.method_end - req.method_start;
                        let mut method_buf: [u8; 16] = [0; 16];
                        let long_method: Vec<u8>;
                        let method_bytes: &[u8] = if method_len <= method_buf.len() {
                            method_buf[..method_len].copy_from_slice(
                                &buf[base + req.method_start..base + req.method_end],
                            );
                            &method_buf[..method_len]
                        } else {
                            long_method =
                                buf[base + req.method_start..base + req.method_end].to_vec();
                            &long_method
                        };
                        let method = http::classify_method(method_bytes);
                        let method_is_post = method_bytes.eq_ignore_ascii_case(b"POST");
                        // Refused below at the server level, where its
                        // `error_page` applies (`phase::process`). The body
                        // is not read and the connection closes.
                        let mut refuse: Option<u16> = None;
                        // The parser noted whether there is one: no scan of
                        // the header block for a request without it.
                        if parse_state.has_transfer_encoding
                            && let Some(te) = lookup_request_header(
                                &buf[base + req.headers_start..base + req.headers_end],
                                b"transfer-encoding",
                            )
                        {
                            // nginx request-body gate:
                            // - Transfer-Encoding is HTTP/1.1-only.
                            // - Transfer-Encoding + Content-Length is rejected.
                            refuse = if !req.http_11 || req.content_length.is_some() {
                                Some(400)
                            } else {
                                match classify_request_transfer_encoding(te) {
                                    RequestTransferEncoding::ChunkedOnly => None,
                                    RequestTransferEncoding::Unsupported => Some(501),
                                    RequestTransferEncoding::Invalid => Some(400),
                                }
                            };
                            if refuse.is_some()
                                && parsed_line_refusal(
                                    &buf[base..base + req.consumed],
                                    &req,
                                    usize::MAX,
                                )
                                .is_none()
                            {
                                let message = if !req.http_11 {
                                    "client sent HTTP/1.0 request with \"Transfer-Encoding\" header"
                                        .to_string()
                                } else if req.content_length.is_some() {
                                    "client sent \"Content-Length\" and \"Transfer-Encoding\" \
                                     headers at the same time"
                                        .to_string()
                                } else {
                                    format!(
                                        "client sent unknown \"Transfer-Encoding\": \"{}\"",
                                        String::from_utf8_lossy(te)
                                    )
                                };
                                refused_parsed_head_log(
                                    http,
                                    conn_log!(),
                                    &buf[base..base + req.headers_end],
                                    &format!("{message} while reading client request headers"),
                                );
                            }
                        }
                        let mut bad_host = false;
                        let request_line_host =
                            req.request_line_host.map(|(s, e)| (base + s, base + e));
                        let header_host = req.host.map(|(s, e)| (base + s, base + e));
                        let request_line_host = match request_line_host {
                            Some((s, e)) => match http::normalize_host(&buf[..], s, e) {
                                Some(nh) => Some(nh),
                                None => {
                                    // An invalid Host is refused by the
                                    // default server, before the checks
                                    // above (nginx validates it while
                                    // reading the headers).
                                    refuse = Some(400);
                                    bad_host = true;
                                    if parsed_line_refusal(
                                        &buf[base..base + req.consumed],
                                        &req,
                                        usize::MAX,
                                    )
                                    .is_none()
                                    {
                                        refused_parsed_head_log(
                                            http,
                                            conn_log!(),
                                            &buf[base..base + req.headers_end],
                                            "client sent invalid host in request line while reading client request line",
                                        );
                                    }
                                    None
                                }
                            },
                            None => None,
                        };
                        let header_host = match header_host {
                            Some((s, e)) => match http::normalize_host(&buf[..], s, e) {
                                Some(nh) => Some(nh),
                                None => {
                                    // An invalid Host is refused by the
                                    // default server, before the checks
                                    // above (nginx validates it while
                                    // reading the headers).
                                    refuse = Some(400);
                                    bad_host = true;
                                    if parsed_line_refusal(
                                        &buf[base..base + req.consumed],
                                        &req,
                                        usize::MAX,
                                    )
                                    .is_none()
                                    {
                                        refused_parsed_head_log(
                                            http,
                                            conn_log!(),
                                            &buf[base..base + req.headers_end],
                                            "client sent invalid host header while reading client request headers",
                                        );
                                    }
                                    None
                                }
                            },
                            None => None,
                        };
                        // Pick request-line authority over Host header when both
                        // present (mirrors nginx's `r->headers_in.server`
                        // priority for absolute-form requests). Both `host`
                        // and `request_port` come from the same chosen
                        // authority so they stay consistent.
                        let chosen_authority = if bad_host {
                            None
                        } else {
                            request_line_host.as_ref().or(header_host.as_ref())
                        };
                        // Routing uses the host lowercased; the buffer keeps
                        // it as sent. A copy only when it has capitals.
                        let mut host_lowercased = Vec::new();
                        if let Some(nh) = chosen_authority.filter(|nh| nh.uppercase) {
                            host_lowercased.extend_from_slice(&buf[nh.host.0..nh.host.1]);
                            host_lowercased.make_ascii_lowercase();
                        }
                        let host = chosen_authority.map(|nh| {
                            if nh.uppercase {
                                host_lowercased.as_slice()
                            } else {
                                &buf[nh.host.0..nh.host.1]
                            }
                        });
                        let request_port: &[u8] = chosen_authority
                            .and_then(|nh| nh.port.map(|(s, e)| &buf[s..e]))
                            .unwrap_or(&[]);
                        // Absolute-form `GET http://host?args HTTP/1.1`
                        // has no path byte but a query. We splice `/` in
                        // front of the raw `?args…` so the rest of the
                        // pipeline (URI normalization, `$args`,
                        // `$request_uri`) sees a conventional origin-form.
                        let synthesized_path: Option<Vec<u8>> = req.absolute_query.map(|(s, e)| {
                            let mut v = Vec::with_capacity(1 + (e - s));
                            v.push(b'/');
                            v.extend_from_slice(&buf[base + s..base + e]);
                            v
                        });
                        let path: &[u8] = if let Some(ref p) = synthesized_path {
                            p.as_slice()
                        } else if req.implicit_path {
                            &b"/"[..]
                        } else {
                            &buf[base + req.path_start..base + req.path_end]
                        };
                        let if_modified_since =
                            req.if_modified_since.map(|(s, e)| &buf[base + s..base + e]);
                        let if_unmodified_since = req
                            .if_unmodified_since
                            .map(|(s, e)| &buf[base + s..base + e]);
                        let if_none_match =
                            req.if_none_match.map(|(s, e)| &buf[base + s..base + e]);
                        let if_match = req.if_match.map(|(s, e)| &buf[base + s..base + e]);
                        let range = req.range.map(|(s, e)| &buf[base + s..base + e]);
                        let if_range = req.if_range.map(|(s, e)| &buf[base + s..base + e]);
                        // HTTP/2 with an `:authority` and a `Host` that
                        // differs (#592): nginx answers 400 once the head is
                        // read, from the server the `:authority` chose
                        // (ngx_http_v2_run_request, since 1.29.1).
                        let authority_mismatch = stream.h2_authority_mismatch();
                        if authority_mismatch && refuse.is_none() {
                            refuse = Some(400);
                        }
                        // Plain HTTP on an `ssl` port (#384): once its head is
                        // read, nginx finalizes the request with 497
                        // (ngx_http_process_request), unless it was refused
                        // already.
                        if conn.plain_http && refuse.is_none() {
                            refuse = Some(497);
                        }
                        let headers_raw = &buf[base + req.headers_start..base + req.headers_end];
                        let keep_alive = req.keep_alive && refuse.is_none();
                        // `as u64` saturates only at ~584k years of uptime;
                        // the explicit clamp would be unreachable.
                        let connection_time_us = connection_start.elapsed().as_micros() as u64;
                        let request_time_us = request_start.elapsed().as_micros() as u64;
                        // `read_start > 0` ⇒ a previous request on this
                        // connection already consumed bytes from this read
                        // buffer ⇒ pipelined. Matches nginx's `r->pipeline`
                        // semantic.
                        let pipe_byte: u8 = if read_start > 0 { b'p' } else { b'.' };
                        let request_line =
                            trim_crlf(&buf[base + req.method_start..base + req.headers_start]);
                        // `$request_id`, one for the request (#487).
                        let request_id = super::draw_request_id(http);
                        macro_rules! request_ctx {
                            ($body:expr, $body_len:expr, $body_file:expr, $request_length:expr,
                             $epoch_secs:expr, $epoch_ms:expr) => {
                                phase::RequestCtx {
                                    method,
                                    method_bytes,
                                    path,
                                    request_line,
                                    upstream: None,
                                    http_11: req.http_11,
                                    host,
                                    sni,
                                    listen_index,
                                    remote_addr: &remote_addr,
                                    remote_port,
                                    if_modified_since,
                                    if_unmodified_since,
                                    if_none_match,
                                    if_match,
                                    range,
                                    if_range,
                                    headers_raw,
                                    connection_id,
                                    request_id,
                                    connection_requests: request_count,
                                    connection_time_us,
                                    request_time_us,
                                    request_port,
                                    pipe: pipe_byte,
                                    request_length: $request_length,
                                    epoch_secs: $epoch_secs,
                                    epoch_ms: $epoch_ms,
                                    body: $body,
                                    body_len: $body_len,
                                    body_file: $body_file,
                                    tls,
                                    conn,
                                    refuse,
                                }
                            };
                        }
                        // The read is bounded by the client_max_body_size
                        // of the location the request is routed to first,
                        // and a Content-Length over it is refused unread,
                        // as nginx's find_config phase does. Without a
                        // location (refused, answered by the server's
                        // rewrite phase) the bound is the largest of any
                        // location; the matched location checks its own
                        // limit after the read either way.
                        let mut max_body = http.max_request_body;
                        // `client_body_in_file_only on` where the request goes:
                        // a temp file holding the body outlives it.
                        let mut persistent_body = false;
                        // Bodies above it go to a temp file (#246).
                        let mut body_buffer = crate::worker::DEFAULT_CLIENT_BODY_BUFFER_SIZE;
                        // And its `client_body_temp_path`, else the http one.
                        let mut body_temp = &http.body_temp;
                        // Nothing will read the body: drop it as it comes.
                        let mut discard_body = false;
                        // With it, the response a 100 goes out before.
                        let mut continue_status = None;
                        // The routed location's client_body_timeout (#147).
                        let mut body_timeout = timeouts.body;
                        // A body is framed, even an empty one (`Content-Length:
                        // 0`, or chunked): nginx reads it, and with
                        // client_body_in_file_only writes its file (#628).
                        let has_body =
                            req.content_length.is_some() || req.transfer_encoding_chunked;
                        if refuse.is_none() && has_body {
                            let cl = req.content_length.unwrap_or(0);
                            let probe = request_ctx!(
                                &phase::NO_BODY,
                                cl,
                                None,
                                req.consumed as u64 + cl,
                                0,
                                0
                            );
                            if let Some(first) = phase::first_body_limit(
                                http,
                                &probe,
                                &mut *url_scratch,
                                parse_state.has_expect,
                            ) {
                                persistent_body = first.persistent;
                                discard_body = first.discard;
                                continue_status = first.continue_status;
                                body_timeout = first.body_timeout;
                                body_buffer = first.buffer;
                                body_temp = first.body_temp.unwrap_or(body_temp);
                                max_body = match first.max {
                                    0 => u64::MAX,
                                    n => n,
                                };
                                if cl > max_body {
                                    write_error_log(
                                        first.error_logs,
                                        ErrorLogLevel::Error,
                                        &ErrorLogRequest::new(&probe, first.server_name),
                                        format!(
                                            "client intended to send too large body: {cl} bytes"
                                        )
                                        .as_bytes(),
                                        None,
                                    );
                                }
                            }
                        }
                        // Expect: 100-continue (nginx ngx_http_test_expect):
                        // when the client sent the exact value "100-continue"
                        // on HTTP/1.1, send the interim `HTTP/1.1 100 Continue`
                        // response before reading the body. nginx fires this
                        // from both read_client_request_body and
                        // discard_request_body, so it applies regardless of
                        // whether the eventual handler consumes the body and
                        // regardless of Content-Length (CL: 0 with the header
                        // still gets a 100). Other Expect tokens (extensions
                        // / unknown) are silently ignored — RFC says 417, but
                        // nginx never implemented that branch and the upstream
                        // test marks it TODO.
                        // Not when the body is refused from its
                        // Content-Length below: nginx sets expect_tested
                        // before discarding it, so no 100 goes out.
                        let refused_unread = req.content_length.is_some_and(|cl| cl > max_body);
                        let expect_continue = req.http_11
                            && refuse.is_none()
                            && !refused_unread
                            && parse_state.has_expect
                            && lookup_request_header(
                                &buf[base + req.headers_start..base + req.headers_end],
                                b"expect",
                            )
                            .is_some_and(|e| e.eq_ignore_ascii_case(b"100-continue"));
                        // A body nobody reads gets its 100 with the response
                        // (#627), and none before an error nginx's special
                        // response handler answers: a client doesn't upload
                        // a body to a 401 (`continue_first`).
                        if expect_continue && !discard_body {
                            // nginx sends it in one send() and gives up
                            // the connection if it doesn't all go out;
                            // here send_timeout bounds the wait.
                            let resp: Vec<u8> = b"HTTP/1.1 100 Continue\r\n\r\n".to_vec();
                            let len = resp.len();
                            let (res, _) = write_all_timed(
                                stream,
                                resp,
                                len,
                                timers.io.as_mut(),
                                timeouts.send,
                            )
                            .await;
                            if res.is_err() {
                                return;
                            }
                        }
                        // Request bodies stay in memory up to the location's
                        // client_body_buffer_size and go to a temp file past
                        // that (`BodySink`), within `max_body` above. Past
                        // it, a body that arrives within BODY_IN_MEMORY_FOR
                        // stays in memory, unless something can tell: the
                        // body variables show whether it went to a file, and
                        // a chunked body is read without that timer.
                        let mut pipelined_tail: Vec<u8> = Vec::new();
                        let nginx_rule = http.uses_request_body
                            || http.uses_request_body_file
                            || body_buffer == 0
                            || req.transfer_encoding_chunked;
                        let mut sink = BodySink::with_capacity(
                            if discard_body {
                                0
                            } else {
                                req.content_length.unwrap_or(0)
                            },
                            body_buffer,
                            if nginx_rule {
                                body_buffer
                            } else {
                                body_buffer.max(crate::worker::BODY_IN_MEMORY_MAX)
                            },
                            body_temp,
                            persistent_body,
                        );
                        // The body is over the limit and isn't read: the
                        // location answers 413 through its error_page, and
                        // the connection closes after it (lingering).
                        let mut body_too_large = false;
                        // What of a body nobody reads is still to come: the
                        // response goes first, as nginx's
                        // ngx_http_discard_request_body, and the rest is
                        // read and dropped after it (#627). `u64::MAX`: a
                        // chunked one, whose end isn't known.
                        let mut pending_discard: Option<PendingDiscard> = None;
                        let (body_in_buf, request_body_len): (usize, u64) = if refuse.is_some() {
                            (0, 0)
                        } else if let Some(cl) = req.content_length {
                            'read: {
                                if cl > max_body {
                                    // nginx answers 413 from the Content-Length
                                    // alone, without reading the body.
                                    body_too_large = true;
                                    break 'read (0, cl);
                                }
                                let body_start = base + req.consumed;
                                let already = filled.saturating_sub(body_start);
                                let take = (already as u64).min(cl) as usize;
                                if discard_body {
                                    if cl > take as u64 {
                                        let rest = stream.discard_queued(cl - take as u64);
                                        if rest > 0 {
                                            pending_discard = Some(PendingDiscard::Length(rest));
                                        }
                                    }
                                    break 'read (take, cl);
                                }
                                if !sink.extend(&buf[body_start..body_start + take]) {
                                    return;
                                }
                                // Each read stops at the body's end so a
                                // pipelined next request isn't consumed. A body
                                // that stays in memory is read straight into
                                // its buffer: no copy, no second buffer (#289).
                                if sink.len() < cl {
                                    // From the start of the body: past
                                    // client_body_buffer_size, the body goes
                                    // to the temp file BODY_IN_MEMORY_FOR on.
                                    let started = monoio::time::Instant::now();
                                    while sink.len() < cl {
                                        let Some((mem, room)) = sink.take_read_buf() else {
                                            // Boxed: its timer and select!
                                            // stay out of every request's
                                            // future.
                                            if !Box::pin(read_body_past_buffer(
                                                stream,
                                                &mut sink,
                                                cl,
                                                body_buffer,
                                                started,
                                                timers.io.as_mut(),
                                                body_timeout,
                                            ))
                                            .await
                                            {
                                                return;
                                            }
                                            break;
                                        };
                                        let start = mem.len();
                                        let end = (start as u64 + (cl - sink.len()))
                                            .min(room as u64)
                                            as usize;
                                        let slice = mem.slice_mut(start..end);
                                        // client_body_timeout between reads.
                                        let Some((res, returned)) = with_timeout(
                                            timers.io.as_mut(),
                                            body_timeout,
                                            stream.read_now(slice),
                                        )
                                        .await
                                        else {
                                            return;
                                        };
                                        match res {
                                            Ok(0) | Err(_) => return,
                                            Ok(n) => sink.put_read_buf(returned.into_inner(), n),
                                        }
                                    }
                                }
                                (take, cl)
                            }
                        } else if req.transfer_encoding_chunked && discard_body {
                            // What came with the head is parsed first, as
                            // nginx's discard does: a framing error there is
                            // a 400, and the rest is read after the response.
                            let body_start = base + req.consumed;
                            match Box::pin(chunked_in_buffer(
                                &buf[body_start..filled],
                                timers.io.as_mut(),
                            ))
                            .await
                            {
                                Ok(body) => (body.consumed_initial, body.raw_consumed),
                                Err(ChunkedBodyError::Ended) => {
                                    pending_discard =
                                        Some(PendingDiscard::Chunked { from: body_start });
                                    let came = filled - body_start;
                                    (came, came as u64)
                                }
                                Err(_) => {
                                    reject_request(
                                        stream,
                                        &mut *scratch,
                                        http,
                                        http.bad_request.pick(method),
                                        &buf[read_start..filled],
                                        Refused::Body,
                                        conn_log!(),
                                    )
                                    .await;
                                    return;
                                }
                            }
                        } else if req.transfer_encoding_chunked {
                            let body_start = base + req.consumed;
                            let initial = &buf[body_start..filled];
                            match read_chunked_request_body(
                                stream,
                                initial,
                                max_body,
                                Some(&mut sink),
                                timers.io.as_mut(),
                                body_timeout,
                            )
                            .await
                            {
                                Ok(decoded) => {
                                    pipelined_tail = decoded.pipelined_tail;
                                    (decoded.consumed_initial, decoded.raw_consumed)
                                }
                                Err(ChunkedBodyError::TooLarge) => {
                                    body_too_large = true;
                                    (0, 0)
                                }
                                Err(_) => {
                                    reject_request(
                                        stream,
                                        &mut *scratch,
                                        http,
                                        http.bad_request.pick(method),
                                        &buf[read_start..filled],
                                        Refused::Body,
                                        conn_log!(),
                                    )
                                    .await;
                                    return;
                                }
                            }
                        } else {
                            (0, 0)
                        };
                        body_read = request_body_len > body_in_buf as u64;
                        // Over the limit: big enough for the location's check.
                        let body_len = if body_too_large {
                            request_body_len.max(max_body.saturating_add(1))
                        } else if discard_body && req.content_length.is_some() {
                            request_body_len
                        } else {
                            sink.len()
                        };
                        // client_body_in_file_only (a zero buffer): an empty
                        // body gets its file too (ngx_http_write_request_body).
                        if body_buffer == 0
                            && has_body
                            && !discard_body
                            && !body_too_large
                            && sink.len() == 0
                            && !sink.spill()
                        {
                            return;
                        }
                        let (body_vec, spooled) = sink.finish();
                        // Shared, so a proxied request sends it from here
                        // instead of a copy (#289); the buffer goes back to
                        // the pool when the last holder is done.
                        let body_vec = if body_vec.is_empty() {
                            bytes::Bytes::new()
                        } else {
                            bytes::Bytes::from_owner(body_vec)
                        };
                        // Bound to this request iteration; holds the
                        // temp-file path bytes for `$request_body_file`. A
                        // body over client_body_buffer_size (any body, with
                        // client_body_in_file_only) is already there.
                        let request_body_file = spooled;
                        let body_file = request_body_file.as_ref();
                        let request_total_consumed = req.consumed + body_in_buf;
                        // HTTP/2: the header block, and the body as it was
                        // read (DATA bytes), not when it was discarded:
                        // nginx counts it in ngx_http_v2_process_request_body.
                        let request_length = match stream.h2_header_block() {
                            Some(block) if discard_body || body_too_large => block,
                            Some(block) => block + body_len,
                            None => req.consumed as u64 + request_body_len,
                        };
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default();
                        let epoch_secs = now.as_secs();
                        let epoch_ms = (now.subsec_millis() as u16) % 1000;

                        let mut ctx = request_ctx!(
                            &body_vec,
                            body_len,
                            body_file,
                            request_length,
                            epoch_secs,
                            epoch_ms
                        );
                        let (mut response, mut process_meta) =
                            phase::process_with_meta(http, &ctx, &mut *url_scratch);
                        if authority_mismatch {
                            authority_mismatch_log(&process_meta, &ctx);
                        }
                        // limit_req delayed the request (#94): processing
                        // stopped before the content handler. Boxed, so the
                        // wait's timer isn't part of every connection's
                        // future.
                        if process_meta.limit_req_delay_ms > 0 {
                            (response, process_meta) = Box::pin(limit_req_delayed(
                                http,
                                &mut ctx,
                                &mut *url_scratch,
                                process_meta.limit_req_delay_ms,
                                request_start,
                            ))
                            .await;
                        }

                        // auth_request's subrequest (#358): the request is
                        // processed again with its outcome.
                        if process_meta.auth_request.is_some() {
                            (response, process_meta) = Box::pin(auth_subrequest(
                                http,
                                &mut ctx,
                                &mut *url_scratch,
                                process_meta,
                                request_start,
                            ))
                            .await;
                        }

                        // Only a proxied response has anything to settle;
                        // the call would move `process_meta` (~1 KB) in
                        // and out for nothing.
                        let response = if matches!(response, Response::Proxy(_)) {
                            let (response, settled_meta) = settle_proxy_response(
                                http,
                                &ctx,
                                &mut *url_scratch,
                                response,
                                process_meta,
                                Some(&*stream as &dyn super::client_watch::WatchClient),
                            )
                            .await;
                            process_meta = settled_meta;
                            response
                        } else {
                            response
                        };
                        // The location's send_timeout for this response (#147);
                        // the next request's header waits use the default
                        // server's values again, as in nginx.
                        let send_timeout = process_meta.timeouts.map_or(timeouts.send, |t| t.send);
                        if expect_continue
                            && discard_body
                            && !Box::pin(continue_first(
                                stream,
                                &response,
                                continue_status,
                                timers.io.as_mut(),
                                send_timeout,
                            ))
                            .await
                        {
                            return;
                        }
                        // And on an HTTP/2 stream, its http2_chunk_size (#594).
                        if let Some(t) = process_meta.timeouts {
                            stream.set_h2_chunk(t.h2_chunk);
                        }

                        // An upstream 101 to a client that asked to upgrade:
                        // the head goes out, then the connection is a tunnel
                        // until either side closes, and then it closes.
                        if let Response::Upgrade(upgraded) = response {
                            let crate::proxy::Upgraded {
                                head,
                                upstream,
                                leftover,
                                slot,
                                read_timeout,
                                send_timeout,
                                upstream_url,
                                lease,
                            } = *upgraded;
                            let head_len = head.len();
                            let (res, head) = write_all_timed(
                                stream,
                                head,
                                head_len,
                                timers.io.as_mut(),
                                timeouts.send,
                            )
                            .await;
                            // A head that didn't go out: no tunnel, but the
                            // request is logged all the same (#410).
                            let head_sent = res.is_ok();
                            let head_cut_at = res.err().unwrap_or(0) as u64;
                            let head = if head.is_empty() {
                                lost_head(101)
                            } else {
                                head
                            };
                            let tunnelled = if head_sent {
                                let early: &[u8] = if pipelined_tail.is_empty() {
                                    &buf[read_start + request_total_consumed..filled]
                                } else {
                                    &pipelined_tail
                                };
                                Box::pin(run_tunnel(
                                    stream,
                                    upstream,
                                    early,
                                    leftover,
                                    TunnelConf {
                                        read_timeout,
                                        upstream_send_timeout: send_timeout,
                                        client_send_timeout: timeouts.send,
                                        http,
                                        state,
                                        start_reload_gen,
                                    },
                                ))
                                .await
                            } else {
                                super::tunnel::Tunnelled {
                                    to_client: 0,
                                    to_upstream: 0,
                                    from_upstream: 0,
                                    end: TunnelEnd::Closed,
                                }
                            };
                            drop(slot);
                            drop(lease);
                            if tunnelled.end == TunnelEnd::ClientTimedOut {
                                // ngx_http_upstream_process_upgraded, at info.
                                write_error_log(
                                    process_meta.log.error_logs,
                                    ErrorLogLevel::Info,
                                    &ErrorLogRequest::new(&ctx, process_meta.server_name)
                                        .with_realip(&process_meta),
                                    b"client timed out (110: Connection timed out) while proxying upgraded connection",
                                    Some(&upstream_url),
                                );
                            }
                            if tunnelled.end == TunnelEnd::UpstreamTimedOut {
                                write_upstream_error_log(
                                    &process_meta.log,
                                    &ErrorLogRequest::new(&ctx, process_meta.server_name)
                                        .with_realip(&process_meta),
                                    &[crate::proxy::AttemptFailure {
                                        error: crate::proxy::UpstreamError::TimedOut(
                                            crate::proxy::Stage::Upgraded,
                                        ),
                                        upstream: upstream_url,
                                    }],
                                );
                            }
                            if let Some(last) = process_meta.upstream_states.last_mut() {
                                last.bytes_received += tunnelled.from_upstream;
                                last.bytes_sent += tunnelled.to_upstream;
                            }
                            if !process_meta.access_logs.is_empty() {
                                let request_time_us = request_start.elapsed().as_micros() as u64;
                                let bytes_sent = if head_sent {
                                    head_len as u64 + tunnelled.to_client
                                } else {
                                    head_cut_at
                                };
                                write_access_logs(
                                    process_meta.access_logs,
                                    path,
                                    method_bytes,
                                    request_line,
                                    host,
                                    remote_addr,
                                    remote_port,
                                    process_meta.remote_user.as_deref(),
                                    headers_raw,
                                    &head,
                                    connection_id,
                                    request_count,
                                    request_id,
                                    connection_time_us,
                                    request_time_us,
                                    process_meta.server_port,
                                    request_port,
                                    pipe_byte,
                                    request_length,
                                    bytes_sent,
                                    tunnelled.to_client,
                                    epoch_secs,
                                    epoch_ms,
                                    tls,
                                    conn,
                                    http,
                                    Some(&process_meta),
                                    final_uri(&process_meta, url_scratch),
                                )
                                .await;
                            }
                            return;
                        }

                        // Defer the response write per `auth_delay`. We
                        // sleep on the runtime, not the OS thread, so other
                        // connections on this worker keep progressing.
                        if process_meta.response_delay_ms > 0 {
                            monoio::time::sleep(Duration::from_millis(
                                process_meta.response_delay_ms,
                            ))
                            .await;
                        }

                        // gzip (`gzip on` in the location): a body in memory
                        // is compressed here, a file on its way out below.
                        let (mut response, gzip_stream) = match process_meta.gzip {
                            Some(gz) => super::gzip::filter(
                                gz,
                                &super::gzip::GzipRequest {
                                    head_only: method_bytes == b"HEAD",
                                    ..super::gzip::GzipRequest::from_headers(
                                        req.http_11,
                                        headers_raw,
                                    )
                                },
                                response,
                            ),
                            None => (response, None),
                        };
                        // `charset` (#464): the label on Content-Type, from
                        // the location's DocRoot, in place.
                        if let Some(charset) = process_meta.doc_root.and_then(|d| d.charset) {
                            super::add_charset(charset, &mut response);
                        }

                        // `return 444;` (no text) is nginx's NGX_HTTP_CLOSE: no
                        // response at all; the connection closes after the
                        // log line (#397). With text it is an ordinary response.
                        let closes = match &response {
                            Response::Prebuilt(b) => super::closes_unanswered(b),
                            Response::Owned(b) => super::closes_unanswered(b),
                            _ => false,
                        };
                        if closes {
                            if !process_meta.access_logs.is_empty() {
                                let logged: &[u8] = match &response {
                                    Response::Prebuilt(b) => b,
                                    Response::Owned(b) => b,
                                    _ => &[],
                                };
                                Box::pin(write_access_logs(
                                    process_meta.access_logs,
                                    path,
                                    method_bytes,
                                    request_line,
                                    host,
                                    remote_addr,
                                    remote_port,
                                    process_meta.remote_user.as_deref(),
                                    headers_raw,
                                    logged,
                                    connection_id,
                                    request_count,
                                    request_id,
                                    connection_time_us,
                                    request_start.elapsed().as_micros() as u64,
                                    process_meta.server_port,
                                    request_port,
                                    pipe_byte,
                                    request_length,
                                    0,
                                    0,
                                    epoch_secs,
                                    epoch_ms,
                                    tls,
                                    conn,
                                    http,
                                    Some(&process_meta),
                                    final_uri(&process_meta, url_scratch),
                                ))
                                .await;
                            }
                            return;
                        }

                        // Funnel the response bytes into `scratch`. Owned and
                        // File variants hand us a Vec the handler allocated
                        // this request — prefer whichever of the two buffers
                        // has the larger capacity so scratch converges to the
                        // high-water mark and stops allocating after a few
                        // iterations. Prebuilt responses stay as static slices:
                        // we can synthesize and cache finalized header variants
                        // once per worker and avoid per-request Vec copies.
                        scratch.clear();
                        let mut prebuilt_base: Option<&'static [u8]> = None;
                        // An upstream body relayed after the head (#88).
                        let mut proxy_body: Option<Box<crate::proxy_stream::ProxyStream>> = None;
                        let mut file_body: Option<phase::FileBody> = match response {
                            Response::Prebuilt(bytes) => {
                                prebuilt_base = Some(bytes);
                                None
                            }
                            // The buffer not kept goes back to the worker's
                            // pool, for the next response head built
                            // (`response::take_buf`).
                            Response::Owned(bytes) => {
                                if bytes.capacity() > scratch.capacity() {
                                    super::response::give_buf(std::mem::replace(
                                        &mut *scratch,
                                        bytes,
                                    ));
                                } else {
                                    scratch.extend_from_slice(&bytes);
                                    super::response::give_buf(bytes);
                                }
                                None
                            }
                            Response::File { headers, body } => {
                                if headers.capacity() > scratch.capacity() {
                                    super::response::give_buf(std::mem::replace(
                                        &mut *scratch,
                                        headers,
                                    ));
                                } else {
                                    scratch.extend_from_slice(&headers);
                                    super::response::give_buf(headers);
                                }
                                Some(body)
                            }
                            Response::ProxyStream(mut body) => {
                                let head = std::mem::take(&mut body.head);
                                if head.capacity() > scratch.capacity() {
                                    *scratch = head;
                                } else {
                                    scratch.extend_from_slice(&head);
                                }
                                proxy_body = Some(body);
                                None
                            }
                            // phase::process consumes Reroute internally
                            // via its hop loop; a Reroute reaching the
                            // worker means the loop terminated without a
                            // terminal outcome, which `process` already
                            // guards against with a 500. Defensive only.
                            Response::Reroute(_) => return,
                            // The Proxy variant is consumed above by
                            // `run_proxy` before this match runs; reaching
                            // here is a logic bug.
                            Response::Proxy(_) => return,
                            // Tunnelled above.
                            Response::Upgrade(_) => return,
                        };
                        // Single walk over the response header block replaces
                        // what used to be three separate scans. For static
                        // prebuilts, cache the result by pointer so repeat
                        // requests stay allocation-free.
                        let mut scan = match prebuilt_base {
                            Some(bytes) => cached_scan_response_headers(bytes),
                            None => {
                                let mut scan = scan_response_headers(scratch).unwrap_or_default();
                                if !process_meta.keep_upstream_date {
                                    stamp_date(&mut *scratch, &mut scan);
                                }
                                scan
                            }
                        };
                        let mut close_after = !keep_alive
                            || body_too_large
                            || !process_meta.keepalive.allow
                            || request_count >= process_meta.keepalive.max_requests
                            || connection_time_us / 1_000 > process_meta.keepalive.max_time_ms
                            || matches!(method, Method::Trace | Method::Connect)
                            || state.is_shutting_down()
                            || (scan.has_connection && scan.connection_is_close)
                            // A compressed file to an HTTP/1.0 client has no
                            // length or chunks: the close ends it.
                            || gzip_stream.is_some_and(|g| !g.chunked);
                        // A relayed body of unknown length: chunked to an
                        // HTTP/1.1 client, ended by the close otherwise.
                        let mut chunked_out = false;
                        if proxy_body.as_ref().is_some_and(|b| !b.length_known()) {
                            if req.http_11 {
                                insert_header_at(
                                    &mut *scratch,
                                    &mut scan.head_end,
                                    b"Transfer-Encoding: chunked\r\n",
                                );
                                chunked_out = true;
                            } else {
                                close_after = true;
                            }
                        }
                        // The client stopped taking the response: it is
                        // logged with what is known to have gone out, then
                        // the connection closes, as nginx's
                        // ngx_http_terminate_request after a failed send
                        // (#410). `cut_sent`: the bytes that went out then
                        // (nginx's c->sent), when the write here failed.
                        // to have gone out.
                        let mut cut_short = false;
                        let mut cut_sent: Option<u64> = None;
                        // Only scan the raw headers for User-Agent when a
                        // policy could actually trigger. disable_safari fires
                        // on any method; disable_msie6 only on POST. Skipping
                        // the scan in the common case (both flags off, or
                        // msie6-only + non-POST) removes a full header-block
                        // walk from the hot path.
                        let ua_scan_needed = process_meta.keepalive.disable_safari
                            || (process_meta.keepalive.disable_msie6 && method_is_post);
                        if ua_scan_needed
                            && should_disable_keepalive_for_user_agent(
                                method_is_post,
                                process_meta.keepalive,
                                lookup_request_header(headers_raw, b"user-agent"),
                            )
                        {
                            close_after = true;
                        }
                        // Capture file body length before `stream_file`
                        // consumes the value — `$bytes_sent` and
                        // `$body_bytes_sent` need it after the write
                        // completes.
                        let mut streamed_body_len = file_body.as_ref().map(|b| b.len).unwrap_or(0);
                        let response_for_logs: &[u8];
                        if let Some(base) = prebuilt_base {
                            let variant = cached_prebuilt_variant(
                                base,
                                close_after,
                                if close_after {
                                    None
                                } else {
                                    process_meta.keepalive.header_timeout_secs
                                },
                            );
                            // The cached variant is shared and its `Date` is
                            // from when it was built: send a stamped copy.
                            scratch.extend_from_slice(variant.bytes);
                            scan = variant.scan;
                            stamp_date(&mut *scratch, &mut scan);
                            let taken = std::mem::take(&mut *scratch);
                            let len = taken.len();
                            let (res, returned) = write_all_timed(
                                stream,
                                taken,
                                len,
                                timers.io.as_mut(),
                                send_timeout,
                            )
                            .await;
                            *scratch = returned;
                            if let Err(n) = res {
                                // A timed-out write took the buffer with it.
                                if scratch.is_empty() {
                                    scratch.extend_from_slice(variant.bytes);
                                }
                                cut_short = true;
                                cut_sent = Some(n as u64);
                            }
                            response_for_logs = &*scratch;
                        } else {
                            if !close_after
                                && !scan.has_keep_alive
                                && let Some(timeout_secs) =
                                    process_meta.keepalive.header_timeout_secs
                            {
                                let mut buf: [u8; 48] = [0; 48];
                                let n = format_keep_alive_header(timeout_secs, &mut buf);
                                insert_header_at(&mut *scratch, &mut scan.head_end, &buf[..n]);
                            }
                            if !scan.has_connection {
                                let header: &[u8] = if close_after {
                                    b"Connection: close\r\n"
                                } else {
                                    b"Connection: keep-alive\r\n"
                                };
                                insert_header_at(&mut *scratch, &mut scan.head_end, header);
                            }
                            // For the log, should a timed-out write take the
                            // head with it.
                            let status = response_status(scratch);
                            if let Some(body) = proxy_body.take() {
                                let pacer = process_meta.limit_rate.as_deref().and_then(|l| {
                                    super::Pacer::new(l.rate, l.after, request_start)
                                });
                                let head = std::mem::take(&mut *scratch);
                                let (end, head) = Box::pin(crate::proxy_stream::relay(
                                    body,
                                    stream,
                                    head,
                                    chunked_out,
                                    pacer,
                                    timers.io.as_mut(),
                                    send_timeout,
                                ))
                                .await;
                                *scratch = head;
                                streamed_body_len = end.body_sent;
                                if let Some(state) = process_meta.upstream_states.last_mut() {
                                    state.bytes_received += end.upstream_read;
                                    state.response_length += end.upstream_body;
                                    state.response_ms = Some(end.response_ms);
                                    state.in_flight = false;
                                }
                                if let Some(failure) = end.failure {
                                    write_upstream_error_log(
                                        &process_meta.log,
                                        &ErrorLogRequest::new(&ctx, process_meta.server_name)
                                            .with_realip(&process_meta),
                                        &[failure],
                                    );
                                }
                                // Cut short: the client can't tell, so the
                                // connection closes (nginx closes it too).
                                cut_short = !end.complete;
                            } else if let Some(limit) = process_meta.limit_rate.as_deref()
                                && limit.rate > 0
                                && gzip_stream.is_none()
                            {
                                // Cold: `limit_rate`. Boxed so the pacer
                                // doesn't grow every connection's future.
                                let body = file_body.take();
                                if let Err(n) = Box::pin(write_response_paced(
                                    stream,
                                    &mut *scratch,
                                    body,
                                    limit.rate,
                                    limit.after,
                                    request_start,
                                    timers.io.as_mut(),
                                    send_timeout,
                                ))
                                .await
                                {
                                    cut_short = true;
                                    cut_sent = Some(n);
                                }
                            } else if process_meta.sendfile
                                && file_body.is_some()
                                && gzip_stream.is_none()
                                && stream.sendfile_fd().is_some()
                            {
                                let body = file_body.take().expect("checked is_some");
                                if let Err(n) = send_head_and_file(
                                    &*stream,
                                    &mut sock_nonblocking,
                                    scratch,
                                    body,
                                    timers.io.as_mut(),
                                    send_timeout,
                                )
                                .await
                                {
                                    cut_short = true;
                                    cut_sent = Some(n);
                                }
                            } else {
                                // Hand scratch to monoio for the io_uring
                                // write; it returns the Vec after the write
                                // completes so we reuse the same allocation
                                // next request.
                                let taken = std::mem::take(&mut *scratch);
                                let len = taken.len();
                                let (res, returned) = write_all_timed(
                                    stream,
                                    taken,
                                    len,
                                    timers.io.as_mut(),
                                    send_timeout,
                                )
                                .await;
                                *scratch = returned;
                                if let Err(n) = res {
                                    cut_short = true;
                                    cut_sent = Some(n as u64);
                                }
                            }
                            if cut_short && scratch.is_empty() {
                                *scratch = lost_head(status);
                            }
                            response_for_logs = &*scratch;
                            if let Some(body) = file_body.take().filter(|_| !cut_short) {
                                let sent = match gzip_stream {
                                    Some(gz) => {
                                        stream_file_gzip(
                                            stream,
                                            body,
                                            gz,
                                            timers.io.as_mut(),
                                            send_timeout,
                                        )
                                        .await
                                    }
                                    None => match if stream.sends_file_bodies() {
                                        stream.send_file_body(&body).await
                                    } else {
                                        None
                                    } {
                                        // HTTP/2 doesn't say how much of
                                        // its DATA went out: none, then.
                                        Some(sent) => sent.then_some(streamed_body_len).ok_or(0),
                                        None => stream_file(
                                            stream,
                                            body,
                                            timers.io.as_mut(),
                                            send_timeout,
                                            None,
                                        )
                                        .await
                                        .map(|()| streamed_body_len),
                                    },
                                };
                                // The head went out whole: the body counts
                                // as far as it got.
                                match sent {
                                    Ok(n) => streamed_body_len = n,
                                    Err(n) => {
                                        streamed_body_len = n;
                                        cut_short = true;
                                    }
                                }
                            }
                        }

                        if !process_meta.access_logs.is_empty() {
                            let request_time_us = request_start.elapsed().as_micros() as u64;
                            // Body bytes = total minus header block. The header
                            // block is everything up to and including the
                            // `\r\n\r\n` separator; `scan.head_end` points at
                            // the terminator's first `\r` and was kept in sync
                            // through the Connection / Keep-Alive injections
                            // above, so we don't need a second `windows(4)`
                            // scan here.
                            let header_size = scan.head_end + 4;
                            let bytes_sent = cut_sent
                                .unwrap_or(response_for_logs.len() as u64 + streamed_body_len);
                            let body_bytes_sent = bytes_sent.saturating_sub(header_size as u64);
                            write_access_logs(
                                process_meta.access_logs,
                                path,
                                method_bytes,
                                request_line,
                                host,
                                remote_addr,
                                remote_port,
                                process_meta.remote_user.as_deref(),
                                headers_raw,
                                response_for_logs,
                                connection_id,
                                request_count,
                                request_id,
                                connection_time_us,
                                request_time_us,
                                process_meta.server_port,
                                request_port,
                                pipe_byte,
                                request_length,
                                bytes_sent,
                                body_bytes_sent,
                                epoch_secs,
                                epoch_ms,
                                tls,
                                conn,
                                http,
                                Some(&process_meta),
                                final_uri(&process_meta, url_scratch),
                            )
                            .await;
                        }

                        if let Some(target) = process_meta.post_action {
                            run_post_action(http, &ctx, target, request_start, &mut *url_scratch)
                                .await;
                        }
                        if cut_short {
                            return;
                        }
                        if let Some(rest) = pending_discard {
                            let Some(tail) = Box::pin(discard_after_response(
                                stream,
                                rest,
                                &buf[..filled],
                                close_after,
                                &mut *scratch,
                                timers.io.as_mut(),
                            ))
                            .await
                            else {
                                return;
                            };
                            pipelined_tail = tail;
                        }

                        read_start += request_total_consumed;
                        parse_state.reset();
                        header_deadline = None;

                        // Chunked decode may have read post-terminator
                        // bytes from the socket — those belong to the next
                        // pipelined request. The chunked path consumes all
                        // of `initial`, so `read_start == filled` here;
                        // compact the buffer and lay the tail down at
                        // offset 0 so the next parse iteration sees it.
                        if !pipelined_tail.is_empty() {
                            if pipelined_tail.len() > buf.len() {
                                if pipelined_tail.len() > READ_BUF {
                                    // Larger than READ_BUF: can't resume keep-alive.
                                    return;
                                }
                                grow_read_buffer(buf);
                            }
                            buf[..pipelined_tail.len()].copy_from_slice(&pipelined_tail);
                            read_start = 0;
                            filled = pipelined_tail.len();
                        }

                        if body_too_large {
                            // The client is likely still sending the body:
                            // let it, so it gets the 413 (nginx's lingering
                            // close; not for 400s, as nginx).
                            Box::pin(lingering_close(stream, &mut *scratch)).await;
                            return;
                        }
                        if close_after {
                            return;
                        }

                        keepalive_idle_timeout = process_meta
                            .keepalive
                            .idle_timeout_ms
                            .map(Duration::from_millis);
                    }
                    Parse::Incomplete => break,
                    Parse::Invalid => {
                        request_count = request_count.saturating_add(1);
                        if parse_state.rline_done
                            && let Some(refusal) = line_refusal(
                                &buf[read_start..filled],
                                (!parse_state.implicit_path && !parse_state.has_absolute_query)
                                    .then_some((parse_state.path_start, parse_state.path_end)),
                                timeouts.large_header_line,
                            )
                        {
                            refuse_line(
                                stream,
                                &mut *scratch,
                                http,
                                &buf[read_start..filled],
                                refusal,
                                conn_log!(),
                            )
                            .await;
                            return;
                        }
                        let bad_version = invalid_head_log(
                            http,
                            conn_log!(),
                            &buf[read_start..filled],
                            stream.h2(),
                        );
                        // Honor HEAD once the request line got past the
                        // method, as nginx knows it then; otherwise a full
                        // response.
                        let method = if parse_state.rline_done {
                            http::classify_method(
                                &buf[read_start + parse_state.method_start
                                    ..read_start + parse_state.method_end],
                            )
                        } else {
                            head_method(&buf[read_start..filled])
                        };
                        let page = if bad_version {
                            &http.version_not_supported
                        } else {
                            &http.bad_request
                        };
                        reject_request(
                            stream,
                            &mut *scratch,
                            http,
                            page.pick(method),
                            &buf[read_start..filled],
                            if parse_state.rline_done {
                                Refused::Headers
                            } else {
                                Refused::Line
                            },
                            conn_log!(),
                        )
                        .await;
                        return;
                    }
                }
            }

            if read_start == filled {
                // Drained everything — release the buffer and wait idle.
                if buf.len() > READ_BUF {
                    // A large head grew it (#482): back to the usual size,
                    // as nginx frees its large buffers for keep-alive.
                    shrink_head_buffer(buf);
                } else if filled == buf.len() && filled < READ_BUF {
                    // The request filled `client_header_buffer_size` (a
                    // body after the head): this client's next ones get
                    // `READ_BUF` and come in one read (#467).
                    grow_read_buffer(buf);
                }
                continue 'idle;
            }

            if filled == buf.len() {
                // No tail room left. If we have a prefix of consumed bytes,
                // compact the remaining partial request down to offset 0 and
                // keep reading. Otherwise the head itself is larger than the
                // buffer: it grows up to `large_client_header_buffers`, as
                // nginx moves it into a large buffer (#482), and past that
                // gets nginx's 414 or 400.
                if read_start == 0 {
                    // An HTTP/2 stream's rebuilt head adds the request
                    // line and `: ` and CRLF to fields within the total
                    // (#623): the crate's bound is its limit.
                    let limit = if stream.h2() {
                        super::h2::max_header_list(timeouts.large_header) as usize
                    } else {
                        timeouts.large_header
                    };
                    if buf.len() < limit {
                        grow_head_buffer(buf, limit);
                        continue;
                    }
                    if parse_state.rline_done
                        && let Some(refusal) = line_refusal(
                            &buf[..filled],
                            (!parse_state.implicit_path && !parse_state.has_absolute_query)
                                .then_some((parse_state.path_start, parse_state.path_end)),
                            usize::MAX,
                        )
                    {
                        refuse_line(
                            stream,
                            &mut *scratch,
                            http,
                            &buf[..filled],
                            refusal,
                            conn_log!(),
                        )
                        .await;
                        return;
                    }
                    head_too_large(
                        stream,
                        &mut *scratch,
                        http,
                        &buf[..filled],
                        parse_state.rline_done.then_some(parse_state.cursor),
                        conn_log!(),
                    )
                    .await;
                    return;
                }
                buf.copy_within(read_start..filled, 0);
                filled -= read_start;
                read_start = 0;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_read_buffer_gets_its_length_back() {
        use monoio::buf::{IoBufMut, SliceMut};
        let buf = vec![7u8; 64];
        let (ptr, len) = (buf.as_ptr(), buf.len());
        // What a 5-byte read into `[10..64)` leaves: monoio's set_init.
        let mut slice: SliceMut<Vec<u8>> = buf.slice_mut(10..64);
        unsafe { slice.set_init(5) };
        let mut buf = slice.into_inner();
        assert_eq!(buf.len(), 15);
        restore_read_len(&mut buf, ptr, len);
        assert_eq!(buf.len(), 64);
        assert_eq!(buf[63], 7);
        // Another allocation (a dropped read's) is left alone.
        let mut other = Vec::with_capacity(64);
        restore_read_len(&mut other, ptr, len);
        assert!(other.is_empty());
    }

    #[test]
    fn repeated_accept_error_is_logged_once_a_minute() {
        let mut line = RepeatedLine {
            last: None,
            since: 0,
        };
        let t0 = Instant::now();
        let msg = || "accept() failed (13: Permission denied)".to_string();
        assert_eq!(line.take(t0, msg()).as_deref(), Some(msg().as_str()));
        assert_eq!(line.take(t0 + Duration::from_millis(500), msg()), None);
        assert_eq!(line.take(t0 + Duration::from_secs(59), msg()), None);
        assert_eq!(
            line.take(t0 + Duration::from_secs(60), msg()).as_deref(),
            Some("accept() failed (13: Permission denied), 2 more like it since the last one")
        );
        assert_eq!(line.take(t0 + Duration::from_secs(61), msg()), None);
    }
}
