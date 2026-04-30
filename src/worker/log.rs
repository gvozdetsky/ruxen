//! Per-request error-log emission: `write_not_found_error_log` for 404
//! lines and `send_syslog_error` for the syslog target.

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

pub(crate) fn write_not_found_error_log(meta: phase::LogMeta, request_uri: &[u8], response: &[u8]) {
    if !meta.log_not_found || response_status(response) != 404 {
        return;
    }
    if meta.error_logs.is_empty() {
        return;
    }

    const MESSAGE_LEVEL: ErrorLogLevel = ErrorLogLevel::Error;

    let uri = request_uri
        .iter()
        .position(|&b| b == b'?')
        .map(|i| &request_uri[..i])
        .unwrap_or(request_uri);
    let mut line = Vec::with_capacity(uri.len() + 64);
    line.extend_from_slice(b"error: *0 open() \"");
    line.extend_from_slice(uri);
    line.extend_from_slice(b"\" failed (2: No such file or directory)");
    let mut line_file = line.clone();
    line_file.push(b'\n');

    for sink in meta.error_logs {
        if !sink.level.allows(MESSAGE_LEVEL) {
            continue;
        }
        match sink.target {
            PreparedErrorLogTarget::Stderr => {
                let _ = std::io::stderr().write_all(&line_file);
            }
            PreparedErrorLogTarget::File(path) => {
                match std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                {
                    Ok(mut file) => {
                        if let Err(e) = file.write_all(&line_file) {
                            eprintln!("ruxen: error_log write to {} failed: {e}", path.display());
                        }
                    }
                    Err(e) => eprintln!("ruxen: error_log open {} failed: {e}", path.display()),
                }
            }
            PreparedErrorLogTarget::Syslog(target) => {
                if let Err(e) = send_syslog_error(target, &line) {
                    eprintln!("ruxen: error_log syslog send failed: {e}");
                }
            }
        }
    }
}

pub(crate) fn send_syslog_error(target: PreparedErrorLogSyslogTarget, message: &[u8]) -> std::io::Result<()> {
    // PRI 11 = user facility (1) + error severity (3).
    let mut payload = Vec::with_capacity(message.len() + target.tag.len() + 8);
    payload.extend_from_slice(b"<11>");
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

