//! Per-request error-log emission in nginx's line format:
//! `write_not_found_error_log` for 404s, `write_upstream_error_log` for
//! failed proxy attempts, `send_syslog_error` for the syslog target.

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

/// Where error-log lines go when no `error_log` applies. nginx falls back
/// to its compiled-in error log; ruxen runs in the foreground, so it uses
/// stderr, which `-e` redirects to a file.
const DEFAULT_ERROR_LOGS: &[PreparedErrorLog] = &[PreparedErrorLog {
    target: PreparedErrorLogTarget::Stderr,
    level: ErrorLogLevel::Error,
}];

/// The request an error-log line is about, rendered as nginx's trailing
/// context: `, client: …, server: …, request: "…", upstream: "…", host: "…"`.
pub(crate) struct ErrorLogRequest<'a> {
    pub connection_id: u64,
    pub client: &'a [u8],
    pub server: &'a [u8],
    pub method: &'a [u8],
    pub uri: &'a [u8],
    pub http_11: bool,
    pub host: Option<&'a [u8]>,
}

impl<'a> ErrorLogRequest<'a> {
    pub(crate) fn new(ctx: &phase::RequestCtx<'a>, server: &'a [u8]) -> Self {
        ErrorLogRequest {
            connection_id: ctx.connection_id,
            client: ctx.remote_addr,
            server,
            method: ctx.method_bytes,
            uri: ctx.path,
            http_11: ctx.http_11,
            host: ctx.host,
        }
    }

    fn append_context(&self, out: &mut Vec<u8>, upstream: Option<&str>) {
        out.extend_from_slice(b", client: ");
        out.extend_from_slice(self.client);
        out.extend_from_slice(b", server: ");
        out.extend_from_slice(self.server);
        out.extend_from_slice(b", request: \"");
        out.extend_from_slice(self.method);
        out.push(b' ');
        out.extend_from_slice(self.uri);
        out.extend_from_slice(if self.http_11 {
            b" HTTP/1.1\""
        } else {
            b" HTTP/1.0\""
        });
        if let Some(upstream) = upstream.filter(|u| !u.is_empty()) {
            out.extend_from_slice(b", upstream: \"");
            out.extend_from_slice(upstream.as_bytes());
            out.push(b'"');
        }
        if let Some(host) = self.host {
            out.extend_from_slice(b", host: \"");
            out.extend_from_slice(host);
            out.push(b'"');
        }
    }
}

/// `2026/10/02 14:00:00 [error] 1234#1235: ` — nginx's error-log line
/// prefix (UTC here, like `$time_local`).
fn log_line_prefix(level: ErrorLogLevel) -> Vec<u8> {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (year, mon, day, hour, minute, second) = civil_from_secs(secs);
    let mut stamp = *b"0000/00/00 00:00:00";
    write_u4(&mut stamp[0..4], year);
    write_u2(&mut stamp[5..7], mon + 1);
    write_u2(&mut stamp[8..10], day + 1);
    write_u2(&mut stamp[11..13], hour);
    write_u2(&mut stamp[14..16], minute);
    write_u2(&mut stamp[17..19], second);
    let mut line = Vec::with_capacity(128);
    line.extend_from_slice(&stamp);
    line.extend_from_slice(b" [");
    line.extend_from_slice(level_name(level));
    // SAFETY: gettid has no preconditions and cannot fail.
    let tid = unsafe { libc::gettid() };
    line.extend_from_slice(format!("] {}#{}: ", std::process::id(), tid).as_bytes());
    line
}

/// A worker-level line not about any request (`accept() failed`,
/// `worker_connections are not enough`): to the top-level `error_log`, or
/// stderr (which `-e` redirects) when there is none, like nginx's main log.
pub(crate) fn write_worker_log(sinks: &[PreparedErrorLog], level: ErrorLogLevel, message: &str) {
    let sinks = if sinks.is_empty() {
        DEFAULT_ERROR_LOGS
    } else {
        sinks
    };
    if !sinks.iter().any(|s| s.level.allows(level)) {
        return;
    }
    let mut line = log_line_prefix(level);
    line.extend_from_slice(message.as_bytes());
    line.push(b'\n');
    emit(sinks, level, &line, message.as_bytes());
}

fn level_name(level: ErrorLogLevel) -> &'static [u8] {
    match level {
        ErrorLogLevel::Emerg => b"emerg",
        ErrorLogLevel::Alert => b"alert",
        ErrorLogLevel::Crit => b"crit",
        ErrorLogLevel::Error => b"error",
        ErrorLogLevel::Warn => b"warn",
        ErrorLogLevel::Notice => b"notice",
        ErrorLogLevel::Info => b"info",
        ErrorLogLevel::Debug => b"debug",
    }
}

/// syslog severity (RFC 5424) for a level; the variants are in that order.
fn syslog_severity(level: ErrorLogLevel) -> u8 {
    level as u8
}

/// Write one line about `req` to `sinks` (or stderr when none apply), in
/// nginx's layout: `2026/10/02 14:00:00 [error] 1234#1235: *7 <message>,
/// client: …`. Times are UTC, like `$time_local` here. Error paths only:
/// the sinks are opened and written synchronously.
pub(crate) fn write_error_log(
    sinks: &[PreparedErrorLog],
    level: ErrorLogLevel,
    req: &ErrorLogRequest<'_>,
    message: &[u8],
    upstream: Option<&str>,
) {
    let sinks = if sinks.is_empty() {
        DEFAULT_ERROR_LOGS
    } else {
        sinks
    };
    if !sinks.iter().any(|s| s.level.allows(level)) {
        return;
    }

    let mut text = Vec::with_capacity(message.len() + 160);
    text.extend_from_slice(message);
    req.append_context(&mut text, upstream);

    let mut line = log_line_prefix(level);
    line.extend_from_slice(format!("*{} ", req.connection_id).as_bytes());
    line.extend_from_slice(&text);
    line.push(b'\n');

    emit(sinks, level, &line, &text);
}

/// Write a finished line to every sink that takes `level`; syslog gets
/// `text`, the line without nginx's date/level/pid prefix.
fn emit(sinks: &[PreparedErrorLog], level: ErrorLogLevel, line: &[u8], text: &[u8]) {
    reopen_stderr_if_needed();
    for sink in sinks {
        if !sink.level.allows(level) {
            continue;
        }
        match sink.target {
            PreparedErrorLogTarget::Stderr => {
                let _ = std::io::stderr().write_all(line);
            }
            PreparedErrorLogTarget::File(path) => {
                match std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                {
                    Ok(mut file) => {
                        if let Err(e) = file.write_all(line) {
                            eprintln!("ruxen: error_log write to {} failed: {e}", path.display());
                        }
                    }
                    Err(e) => eprintln!("ruxen: error_log open {} failed: {e}", path.display()),
                }
            }
            PreparedErrorLogTarget::Syslog(target) => {
                if let Err(e) = send_syslog_error(target, syslog_severity(level), text) {
                    eprintln!("ruxen: error_log syslog send failed: {e}");
                }
            }
        }
    }
}

pub(crate) fn write_not_found_error_log(
    meta: phase::LogMeta,
    req: &ErrorLogRequest<'_>,
    response: &[u8],
) {
    if !meta.log_not_found || response_status(response) != 404 {
        return;
    }
    let uri = req
        .uri
        .iter()
        .position(|&b| b == b'?')
        .map(|i| &req.uri[..i])
        .unwrap_or(req.uri);
    let mut message = Vec::with_capacity(uri.len() + 48);
    message.extend_from_slice(b"open() \"");
    message.extend_from_slice(uri);
    message.extend_from_slice(b"\" failed (2: No such file or directory)");
    write_error_log(meta.error_logs, ErrorLogLevel::Error, req, &message, None);
}

/// Error-log lines for the failed upstream attempts behind a proxied
/// response (`connect() failed (111: Connection refused) while connecting
/// to upstream, …`). Cold: kept out of the proxy response path.
#[cold]
#[inline(never)]
pub(crate) fn write_upstream_error_log(
    meta: &phase::LogMeta,
    req: &ErrorLogRequest<'_>,
    failures: &[crate::proxy::AttemptFailure],
) {
    for failure in failures {
        let message = failure.error.to_string();
        write_error_log(
            meta.error_logs,
            ErrorLogLevel::Error,
            req,
            message.as_bytes(),
            Some(&failure.upstream),
        );
    }
}

pub(crate) fn send_syslog_error(
    target: PreparedErrorLogSyslogTarget,
    severity: u8,
    message: &[u8],
) -> std::io::Result<()> {
    // PRI = user facility (1) * 8 + severity.
    let mut payload = Vec::with_capacity(message.len() + target.tag.len() + 8);
    payload.extend_from_slice(format!("<{}>", 8 + severity).as_bytes());
    payload.extend_from_slice(target.tag);
    payload.extend_from_slice(b": ");
    payload.extend_from_slice(message);
    match target.server {
        PreparedErrorLogSyslogServer::Unix(path) => {
            let sock = UnixDatagram::unbound()?;
            sock.send_to(&payload, path).map(|_| ())
        }
        PreparedErrorLogSyslogServer::Udp(addr) => {
            let sock = std::net::UdpSocket::bind("0.0.0.0:0")
                .or_else(|_| std::net::UdpSocket::bind("[::]:0"))?;
            sock.send_to(&payload, addr).map(|_| ())
        }
    }
}
