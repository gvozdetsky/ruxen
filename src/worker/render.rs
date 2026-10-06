//! Variable rendering: `RenderCtx`, `render_parts`, request-header /
//! cookie / arg lookups, and the numeric/time formatters that the variable
//! impls need to push bytes without allocating.

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

/// Per-request values needed to render `$variable` references. Built in
/// `run_location_handler` once per request; threaded into both `return`
/// body rendering and `add_header` injection.
#[derive(Copy, Clone)]
pub(crate) struct RenderCtx<'a> {
    pub uri: &'a [u8],
    pub request_uri: &'a [u8],
    /// Raw request-line method bytes, uppercase. Empty when no request is
    /// in flight (e.g. some access-log paths reconstruct without it).
    pub request_method: &'a [u8],
    /// The request line without its CRLF (`$request`). Empty where no
    /// request line is at hand.
    pub request_line: &'a [u8],
    pub host: &'a [u8],
    pub remote_addr: &'a [u8],
    pub remote_port: u16,
    pub remote_user: &'a [u8],
    pub server_name: &'a [u8],
    pub status: u16,
    pub args: &'a [u8],
    pub is_args: &'a [u8],
    pub scheme: &'a [u8],
    pub hostname: &'a [u8],
    pub headers_raw: &'a [u8],
    /// Effective server-scope `underscores_in_headers`. Drives whether
    /// `$http_*` / `$cookie_*` lookups skip headers whose names contain
    /// `_`. Defaults to `false` (nginx default) for callers that don't
    /// thread it explicitly.
    pub underscores_in_headers: bool,
    pub sent_headers: &'a [u8],
    pub connection_id: u64,
    pub connection_requests: u64,
    pub connection_time_us: u64,
    pub request_time_us: u64,
    /// Listening port from the matched server's `listen` address.
    pub server_port: u16,
    /// Port substring of the request authority — empty when the client
    /// didn't send one in `Host` or absolute-form. Bytes only, no leading
    /// colon.
    pub request_port: &'a [u8],
    /// `p` if pipelined, `.` otherwise. Set from `read_start > 0` at
    /// parse time in the worker loop.
    pub pipe: u8,
    /// Bytes consumed by the parser for this request (request line +
    /// headers + body).
    pub request_length: u64,
    /// Request body bytes buffered for this request.
    pub request_body: &'a [u8],
    /// Temp-file path for a spilled request body. Empty when no file was
    /// created for this request.
    pub request_body_file: &'a [u8],
    /// Total response bytes that will go on the wire. Zero during the
    /// handler — only the access-log render path sees the post-write
    /// value.
    pub bytes_sent: u64,
    /// Body bytes only — `bytes_sent` minus header size.
    pub body_bytes_sent: u64,
    /// Wall-clock seconds since UNIX epoch (whole seconds component).
    /// Captured once per request so `$time_local` / `$time_iso8601` /
    /// `$msec` all agree on the same instant.
    pub epoch_secs: u64,
    /// Millisecond fraction component for `$msec`.
    pub epoch_ms: u16,
    /// Named regex captures from a winning `server_name ~^...$` match.
    /// Empty for non-regex server matches; consulted by `Variable::Unknown`
    /// at render time so `$name` resolves when configs use named groups.
    /// Owned `Vec<u8>` values keep the slice independent of the request
    /// borrow lifetime — see `phase::ServerNameCaptures`.
    pub server_name_captures: &'a [(&'static str, Vec<u8>)],
    /// Per-request rewrite state (`set` variables + `$1..$9` captures).
    pub rewrite_state: Option<&'a RewriteState>,
    /// http-scope split_clients tables keyed by output variable name.
    pub split_clients: Option<&'a std::collections::HashMap<&'static str, PreparedSplitClients>>,
    /// http-scope map programs keyed by output variable name. Consulted
    /// from the `Variable::Unknown` render path, after user vars / server-
    /// name captures / split_clients.
    pub maps: Option<&'a std::collections::HashMap<&'static str, PreparedMap>>,
    /// `$proxy_host` value for the matched location. Empty outside a
    /// proxy context (the location handler doesn't dispatch through
    /// `proxy_pass`).
    pub proxy_host: &'a [u8],
    /// Raw upstream response header block (everything between the status
    /// line CRLF and the empty CRLF that ends the header section, the
    /// trailing CRLF of the last header included). Empty outside a proxy
    /// context. Consulted by `$upstream_http_*` and `$upstream_cookie_*`.
    pub upstream_headers: &'a [u8],
    /// One entry per upstream attempt, for `$upstream_addr`,
    /// `$upstream_status`, `$upstream_response_time` and the rest. Empty
    /// outside a proxy context.
    pub upstream_states: &'a [crate::proxy::UpstreamState],
    /// Pre-rendered `add_trailer` lines, joined with CRLF and rendered as
    /// `Name: value\r\n` per entry. Used by `$sent_trailer_*` lookups via
    /// the same scanner that handles request/response headers.
    pub sent_trailers: &'a [u8],
    /// Negotiated TLS handshake info, taken once per connection at
    /// handshake completion. `None` for plain-HTTP. Source for `$scheme`
    /// (renders `https` when present) and the `$ssl_*` family.
    pub tls: Option<&'a crate::tls::HandshakeInfo>,
    /// The connection's PROXY protocol header (`listen … proxy_protocol`),
    /// for `$proxy_protocol_*`.
    /// The connection's PROXY protocol header and `$server_addr`.
    pub conn: &'a phase::ConnInfo,
}

impl RenderCtx<'_> {
    /// nginx's `$upstream_*` lists: one value per attempt, `, `-separated.
    fn write_upstream_list(
        &self,
        out: &mut Vec<u8>,
        one: impl Fn(&mut Vec<u8>, &crate::proxy::UpstreamState),
    ) {
        for (i, state) in self.upstream_states.iter().enumerate() {
            if i > 0 {
                out.extend_from_slice(b", ");
            }
            one(out, state);
        }
    }

    pub(crate) fn write_var(&self, var: &Variable, out: &mut Vec<u8>) {
        match var {
            Variable::Uri => out.extend_from_slice(self.uri),
            Variable::RequestUri => out.extend_from_slice(self.request_uri),
            Variable::RequestMethod => out.extend_from_slice(self.request_method),
            Variable::Request => out.extend_from_slice(self.request_line),
            Variable::ProxyProtocolAddr
            | Variable::ProxyProtocolPort
            | Variable::ProxyProtocolServerAddr
            | Variable::ProxyProtocolServerPort => {
                let header = self.conn.proxy_protocol.as_ref();
                let addr = match var {
                    Variable::ProxyProtocolAddr | Variable::ProxyProtocolPort => {
                        header.and_then(|h| h.source)
                    }
                    _ => header.and_then(|h| h.destination),
                };
                if let Some(addr) = addr {
                    use std::io::Write;
                    let _ = match var {
                        Variable::ProxyProtocolAddr | Variable::ProxyProtocolServerAddr => {
                            write!(out, "{}", addr.ip())
                        }
                        _ => write!(out, "{}", addr.port()),
                    };
                }
            }
            Variable::ProxyProtocolTlv(tlv) => {
                if let Some(header) = &self.conn.proxy_protocol {
                    crate::proxy_protocol::write_tlv(&header.tlvs, tlv, out);
                }
            }
            Variable::ServerProtocol => out.extend_from_slice(server_protocol(self.request_line)),
            Variable::Host => out.extend_from_slice(self.host),
            Variable::RemoteAddr => out.extend_from_slice(self.remote_addr),
            Variable::RemotePort => write_u16_decimal(out, self.remote_port),
            Variable::RemoteUser => {
                // Pre-resolved username from a successful auth_basic check
                // wins; otherwise nginx parses the `Authorization: Basic`
                // header on demand (`ngx_http_variable_remote_user`) so
                // `$remote_user` works even on locations without
                // `auth_basic`.
                if !self.remote_user.is_empty() {
                    out.extend_from_slice(self.remote_user);
                } else if let Ok(creds) = crate::auth::decode_basic_authorization(self.headers_raw)
                {
                    out.extend_from_slice(&creds.username);
                }
            }
            Variable::ServerName => out.extend_from_slice(self.server_name),
            Variable::Status => write_u16_decimal(out, self.status),
            Variable::Args => out.extend_from_slice(self.args),
            Variable::IsArgs => out.extend_from_slice(self.is_args),
            Variable::Arg(name) => {
                if let Some(value) = request_arg_value(self.args, name.as_bytes()) {
                    write_unescaped_arg_value(out, value);
                }
            }
            Variable::Scheme => out.extend_from_slice(self.scheme),
            Variable::SslProtocol => {
                if let Some(info) = self.tls
                    && let Some(v) = info.protocol_version
                {
                    out.extend_from_slice(crate::tls::protocol_version_str(v).as_bytes());
                }
            }
            Variable::SslCipher => {
                if let Some(info) = self.tls
                    && let Some(s) = info.negotiated_cipher_suite
                {
                    out.extend_from_slice(crate::tls::cipher_suite_iana_name(s).as_bytes());
                }
            }
            Variable::SslCiphers => {
                if let Some(info) = self.tls
                    && let Some(s) = info.negotiated_cipher_suite
                {
                    out.extend_from_slice(crate::tls::cipher_suite_iana_name(s).as_bytes());
                }
            }
            Variable::SslServerName => {
                if let Some(info) = self.tls
                    && let Some(name) = info.server_name.as_deref()
                {
                    out.extend_from_slice(name.as_bytes());
                }
            }
            Variable::SslSessionReused => {
                // nginx renders `r` for resumed, `.` for fresh. Outside a TLS
                // connection the variable expands to empty (`""`), matching
                // nginx's `ngx_ssl_get_session_reused` returning empty when
                // c->ssl is NULL. Source of truth is rustls's HandshakeKind;
                // tests that need a fresh handshake should use a fresh TCP
                // connection (rustls's session cache only resumes on the
                // same client).
                if let Some(info) = self.tls {
                    out.push(if info.session_reused { b'r' } else { b'.' });
                }
            }
            Variable::SslSessionId => {
                // nginx's ngx_ssl_get_session_id: the id in lowercase hex,
                // empty without one (or outside TLS).
                const HEX: &[u8; 16] = b"0123456789abcdef";
                if let Some(id) = self.tls.and_then(|info| info.session_id.as_ref()) {
                    for b in id {
                        out.push(HEX[(b >> 4) as usize]);
                        out.push(HEX[(b & 0xf) as usize]);
                    }
                }
            }
            Variable::SslClientVerify => {
                // ruxen does not request client certificates. nginx renders
                // "NONE" inside TLS when no cert was supplied, empty
                // otherwise. Once `ssl_verify_client` lands the rustls
                // peer-cert state will distinguish SUCCESS / FAILED.
                if self.tls.is_some() {
                    out.extend_from_slice(b"NONE");
                }
            }
            // Client-cert DNs and validity range are intentionally empty
            // until `ssl_verify_client` is implemented and we can decode
            // the peer certificate via rustls/x509-parser. Returning
            // hard-coded placeholder strings would let nginx-tests pass
            // for the wrong reason.
            Variable::SslClientIDn => {}
            Variable::SslClientIDnLegacy => {}
            Variable::SslClientSDn => {}
            Variable::SslClientSDnLegacy => {}
            Variable::SslClientVStart => {}
            Variable::SslClientVEnd => {}
            Variable::SslClientVRemain => {}
            Variable::Hostname => out.extend_from_slice(self.hostname),
            Variable::RequestBody => {
                // nginx leaves `$request_body` empty whenever the body was
                // spilled to disk — readers consult `$request_body_file`
                // to fetch the bytes. Mirror that here even though we
                // still keep the in-memory copy for proxy forwarding.
                if self.request_body_file.is_empty() {
                    out.extend_from_slice(self.request_body);
                }
            }
            Variable::RequestBodyFile => out.extend_from_slice(self.request_body_file),
            Variable::Http(name) => {
                write_all_request_header_values_with_policy(
                    out,
                    self.headers_raw,
                    name.as_bytes(),
                    self.underscores_in_headers,
                );
            }
            Variable::SentHttp(name) => {
                write_all_response_header_values(out, self.sent_headers, name.as_bytes());
            }
            Variable::Cookie(name) => {
                write_request_cookie_value(out, self.headers_raw, name.as_bytes());
            }
            Variable::ContentLength => {
                write_all_request_header_values(out, self.headers_raw, b"content-length");
            }
            Variable::ContentType => {
                write_all_request_header_values(out, self.headers_raw, b"content-type");
            }
            Variable::UpstreamHttp(name) => {
                write_all_request_header_values(out, self.upstream_headers, name.as_bytes());
            }
            Variable::UpstreamCookie(name) => {
                write_upstream_cookie_value(out, self.upstream_headers, name.as_bytes());
            }
            Variable::UpstreamAddr => self.write_upstream_list(out, |out, s| match s.peer {
                crate::proxy::UpstreamPeerName::Addr(addr) => {
                    use std::io::Write;
                    let _ = write!(out, "{addr}");
                }
                crate::proxy::UpstreamPeerName::Group(name) => out.extend_from_slice(name),
            }),
            Variable::UpstreamStatus => self.write_upstream_list(out, |out, s| {
                if s.status == 0 {
                    out.push(b'-');
                } else {
                    write_u64_decimal(out, s.status as u64);
                }
            }),
            Variable::UpstreamConnectTime => {
                self.write_upstream_list(out, |out, s| write_upstream_ms(out, s.connect_ms))
            }
            Variable::UpstreamHeaderTime => {
                self.write_upstream_list(out, |out, s| write_upstream_ms(out, s.header_ms))
            }
            Variable::UpstreamResponseTime => self.write_upstream_list(out, |out, s| {
                write_upstream_ms(out, if s.in_flight { None } else { s.response_ms })
            }),
            Variable::UpstreamResponseLength => {
                self.write_upstream_list(out, |out, s| write_u64_decimal(out, s.response_length))
            }
            Variable::UpstreamBytesReceived => {
                self.write_upstream_list(out, |out, s| write_u64_decimal(out, s.bytes_received))
            }
            Variable::UpstreamBytesSent => {
                self.write_upstream_list(out, |out, s| write_u64_decimal(out, s.bytes_sent))
            }
            Variable::SentTrailer(name) => {
                write_all_request_header_values(out, self.sent_trailers, name.as_bytes());
            }
            Variable::Connection => write_u64_decimal(out, self.connection_id),
            Variable::ConnectionRequests => write_u64_decimal(out, self.connection_requests),
            Variable::ConnectionTime => write_connection_time(out, self.connection_time_us),
            Variable::RequestTime => write_connection_time(out, self.request_time_us),
            // nginx's `r->limit_rate`: what `set $limit_rate` stored, as a
            // size in bytes (0 if it isn't one); 0 until something sets it
            // (`limit_rate` itself applies when the response is written).
            Variable::LimitRate => {
                let rate = self
                    .rewrite_state
                    .and_then(|state| state.user_var("limit_rate"))
                    .and_then(crate::config::parse_size)
                    .unwrap_or(0);
                write_u64_decimal(out, rate);
            }
            Variable::ServerPort => write_u16_decimal(out, self.server_port),
            Variable::ServerAddr => out.extend_from_slice(&self.conn.server_addr),
            Variable::RequestPort => out.extend_from_slice(self.request_port),
            Variable::IsRequestPort => {
                if !self.request_port.is_empty() {
                    out.push(b':');
                }
            }
            Variable::Pipe => out.push(self.pipe),
            Variable::RequestLength => write_u64_decimal(out, self.request_length),
            Variable::BytesSent => write_u64_decimal(out, self.bytes_sent),
            Variable::BodyBytesSent => write_u64_decimal(out, self.body_bytes_sent),
            Variable::TimeIso8601 => write_time_iso8601(out, self.epoch_secs),
            Variable::TimeLocal => write_time_local(out, self.epoch_secs),
            Variable::Msec => write_msec(out, self.epoch_secs, self.epoch_ms),
            Variable::Capture(n) => {
                if let Some(state) = self.rewrite_state
                    && let Some(value) = state.numbered_capture(*n)
                {
                    out.extend_from_slice(value);
                }
            }
            Variable::ProxyHost => out.extend_from_slice(self.proxy_host),
            Variable::ProxyPort => out.extend_from_slice(proxy_port(self.proxy_host)),
            Variable::ProxyAddXForwardedFor => {
                let existing =
                    lookup_request_header(self.headers_raw, b"x-forwarded-for").unwrap_or(b"");
                if !existing.is_empty() {
                    out.extend_from_slice(existing);
                    out.extend_from_slice(b", ");
                }
                out.extend_from_slice(self.remote_addr);
            }
            // Unknown variables fall back to server_name regex captures
            // (`~^(?P<name>...)$` exposes `$name`); anything else still
            // renders empty, matching nginx's lenient lookup.
            Variable::Unknown(name) => {
                for (cap_name, cap_value) in self.server_name_captures {
                    if name.as_bytes() == cap_name.as_bytes() {
                        out.extend_from_slice(cap_value);
                        return;
                    }
                }
                if let Some(state) = self.rewrite_state
                    && let Some(value) = state.user_var(name)
                {
                    out.extend_from_slice(value);
                    return;
                }
                if let Some(split_clients) = self.split_clients
                    && let Some(program) = split_clients.get(name.as_str())
                {
                    let mut key = Vec::with_capacity(32);
                    render_parts(program.key, self, &mut key);
                    let hash = murmur_hash2(&key);
                    for part in program.parts {
                        if part.threshold == 0 || hash < part.threshold {
                            render_parts(part.value, self, out);
                            return;
                        }
                    }
                }
                if let Some(maps) = self.maps
                    && let Some(program) = maps.get(name.as_str())
                {
                    // The first result stays for the rest of the request
                    // (nginx's cacheable variables), unless `volatile`.
                    match self.rewrite_state.filter(|_| !program.volatile) {
                        Some(state) => {
                            if !state.cached_map(program.slot, out) {
                                let start = out.len();
                                render_map(program, self, out);
                                state.cache_map(program.slot, &out[start..]);
                            }
                        }
                        None => render_map(program, self, out),
                    }
                }
            } // (Vec<u8> values keep the captures slice independent of the
              // request `Host` borrow — see `phase::ServerNameCaptures`.)
        }
    }
}

/// Scan the raw request-header block for a header by (lowercased, dashed)
/// name. Returns the trimmed value slice if found, `None` otherwise. Called
/// at most once per `$http_NAME` reference; test configs hit it rarely and
/// we don't build a lookup table for it.
pub(crate) fn lookup_request_header<'a>(mut block: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    while !block.is_empty() {
        // Each iteration: peel off one line, ending at LF. Lines are
        // guaranteed CRLF-terminated by the parser; the last line also
        // ends in CRLF before the blank-line terminator, and `headers_end`
        // excludes that terminator — but the last real header's CRLF is
        // still inside `block`.
        let line_end = match block.iter().position(|&b| b == b'\n') {
            Some(i) => i,
            None => block.len(),
        };
        let line = &block[..line_end];
        block = &block[(line_end + 1).min(block.len())..];

        // Strip trailing CR and split at the first colon. Silently skip
        // malformed lines — the parser already rejected those at read time.
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let colon = match line.iter().position(|&b| b == b':') {
            Some(i) => i,
            None => continue,
        };
        let header_name = &line[..colon];
        if !header_name_eq_ci(header_name, name) {
            continue;
        }

        // Trim OWS on both sides of the value, matching parse_header_line.
        let mut v = &line[colon + 1..];
        while let Some((&c, rest)) = v.split_first() {
            if c == b' ' || c == b'\t' {
                v = rest;
            } else {
                break;
            }
        }
        while let Some((&c, rest)) = v.split_last() {
            if c == b' ' || c == b'\t' {
                v = rest;
            } else {
                break;
            }
        }
        return Some(v);
    }
    None
}

/// Walk every occurrence of `name` in the raw header block and write each
/// trimmed value into `out`, joined with `, ` (or `; ` for Cookie, matching
/// nginx's `ngx_http_variables.c::ngx_http_variable_headers` /
/// `ngx_http_variable_unknown_header_in`). Empty when the header is absent.
pub(crate) fn write_all_request_header_values(out: &mut Vec<u8>, block: &[u8], name: &[u8]) {
    write_all_header_values_filtered(out, block, name, true);
}

/// Variant that drops headers with `_` in the name when
/// `underscores_in_headers` is false. nginx rejects such headers at parse
/// time so they're invisible to `$http_*` / `$cookie_*` lookups; we apply
/// the filter at iteration time to keep the parser policy-agnostic.
pub(crate) fn write_all_request_header_values_with_policy(
    out: &mut Vec<u8>,
    block: &[u8],
    name: &[u8],
    underscores_in_headers: bool,
) {
    write_all_header_values_filtered(out, block, name, underscores_in_headers);
}

pub(crate) fn write_all_header_values_filtered(
    out: &mut Vec<u8>,
    mut block: &[u8],
    name: &[u8],
    underscores_in_headers: bool,
) {
    let sep: &[u8] = if name == b"cookie" { b"; " } else { b", " };
    let mut first = true;
    while !block.is_empty() {
        let line_end = match block.iter().position(|&b| b == b'\n') {
            Some(i) => i,
            None => block.len(),
        };
        let line = &block[..line_end];
        block = &block[(line_end + 1).min(block.len())..];

        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let colon = match line.iter().position(|&b| b == b':') {
            Some(i) => i,
            None => continue,
        };
        let header_name = &line[..colon];
        if !underscores_in_headers && header_name.contains(&b'_') {
            continue;
        }
        if !header_name_eq_ci(header_name, name) {
            continue;
        }

        let mut v = &line[colon + 1..];
        while let Some((&c, rest)) = v.split_first() {
            if c == b' ' || c == b'\t' {
                v = rest;
            } else {
                break;
            }
        }
        while let Some((&c, rest)) = v.split_last() {
            if c == b' ' || c == b'\t' {
                v = rest;
            } else {
                break;
            }
        }
        if !first {
            out.extend_from_slice(sep);
        }
        out.extend_from_slice(v);
        first = false;
    }
}

pub(crate) fn write_all_response_header_values(out: &mut Vec<u8>, response: &[u8], name: &[u8]) {
    let head_end = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or(response.len());
    let mut block = &response[..head_end];

    let line_end = block
        .windows(2)
        .position(|w| w == b"\r\n")
        .map(|i| i + 2)
        .unwrap_or(block.len());
    block = &block[line_end..];

    write_all_request_header_values(out, block, name);
}

/// `$cookie_NAME` lookup: walk every `Cookie:` request header, split each on
/// `;`, and return the first `name=value` pair whose name matches (case-
/// insensitive). Mirrors nginx's `ngx_http_parse_multi_header_lines`.
/// `Cookie` itself is always a syntactically valid header name, so no
/// `underscores_in_headers` filter is needed at the header level.
pub(crate) fn write_request_cookie_value(out: &mut Vec<u8>, mut block: &[u8], name: &[u8]) {
    while !block.is_empty() {
        let line_end = match block.iter().position(|&b| b == b'\n') {
            Some(i) => i,
            None => block.len(),
        };
        let line = &block[..line_end];
        block = &block[(line_end + 1).min(block.len())..];

        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let colon = match line.iter().position(|&b| b == b':') {
            Some(i) => i,
            None => continue,
        };
        if !header_name_eq_ci(&line[..colon], b"cookie") {
            continue;
        }
        let mut v = &line[colon + 1..];
        while let Some((&c, rest)) = v.split_first() {
            if c == b' ' || c == b'\t' {
                v = rest;
            } else {
                break;
            }
        }
        if let Some(value) = find_cookie_pair(v, name) {
            out.extend_from_slice(value);
            return;
        }
    }
}

/// Walk a Cookie-header value splitting on `;` and return the value for the
/// first `name=...` pair whose name matches. Per nginx's behavior, the
/// returned value extends to the next `;` even if it embeds `,`.
pub(crate) fn find_cookie_pair<'a>(mut v: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    while !v.is_empty() {
        let end = v.iter().position(|&b| b == b';').unwrap_or(v.len());
        let pair = &v[..end];
        v = if end < v.len() { &v[end + 1..] } else { &[] };

        let pair = trim_ascii_ws(pair);
        let eq = match pair.iter().position(|&b| b == b'=') {
            Some(i) => i,
            None => continue,
        };
        let pname = trim_ascii_ws(&pair[..eq]);
        if pname.eq_ignore_ascii_case(name) {
            let val = trim_ascii_ws(&pair[eq + 1..]);
            return Some(val);
        }
    }
    None
}

/// `$upstream_cookie_NAME` lookup: walk every `Set-Cookie:` upstream header
/// and return the value of the first cookie whose name matches. Mirrors
/// nginx's `ngx_http_parse_set_cookie_lines`: the cookie name must be a
/// case-insensitive prefix of the header value (after OWS strip), only ' '
/// (not '\t') is skipped before/after '=', and the value extends up to the
/// first ';' without further trimming.
pub(crate) fn write_upstream_cookie_value(out: &mut Vec<u8>, mut block: &[u8], name: &[u8]) {
    while !block.is_empty() {
        let line_end = match block.iter().position(|&b| b == b'\n') {
            Some(i) => i,
            None => block.len(),
        };
        let line = &block[..line_end];
        block = &block[(line_end + 1).min(block.len())..];

        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let colon = match line.iter().position(|&b| b == b':') {
            Some(i) => i,
            None => continue,
        };
        if !header_name_eq_ci(&line[..colon], b"set-cookie") {
            continue;
        }
        // Strip leading HTTP OWS (SP / HTAB) from the field value.
        let mut v = &line[colon + 1..];
        while let Some((&c, rest)) = v.split_first() {
            if c == b' ' || c == b'\t' {
                v = rest;
            } else {
                break;
            }
        }
        if v.len() <= name.len() {
            continue;
        }
        if !v[..name.len()].eq_ignore_ascii_case(name) {
            continue;
        }
        let mut start = name.len();
        while start < v.len() && v[start] == b' ' {
            start += 1;
        }
        if start >= v.len() || v[start] != b'=' {
            continue;
        }
        start += 1;
        while start < v.len() && v[start] == b' ' {
            start += 1;
        }
        let end = v[start..]
            .iter()
            .position(|&b| b == b';')
            .map(|i| start + i)
            .unwrap_or(v.len());
        out.extend_from_slice(&v[start..end]);
        return;
    }
}

pub(crate) fn trim_ascii_ws(mut v: &[u8]) -> &[u8] {
    while let Some((&c, rest)) = v.split_first() {
        if c == b' ' || c == b'\t' {
            v = rest;
        } else {
            break;
        }
    }
    while let Some((&c, rest)) = v.split_last() {
        if c == b' ' || c == b'\t' {
            v = rest;
        } else {
            break;
        }
    }
    v
}

/// Case-insensitive ASCII compare. `name` is raw header-block bytes
/// (mixed-case possible); `target` is already lowercased.
pub(crate) fn header_name_eq_ci(name: &[u8], target: &[u8]) -> bool {
    if name.len() != target.len() {
        return false;
    }
    name.iter()
        .zip(target.iter())
        .all(|(a, b)| a.to_ascii_lowercase() == *b)
}

pub(crate) fn contains_ascii_case_insensitive(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack.windows(needle.len()).any(|w| {
        w.iter()
            .zip(needle.iter())
            .all(|(a, b)| a.to_ascii_lowercase() == b.to_ascii_lowercase())
    })
}

pub(crate) fn user_agent_is_msie6(ua: &[u8]) -> bool {
    let Some(pos) = ua.windows(5).position(|w| w.eq_ignore_ascii_case(b"MSIE ")) else {
        return false;
    };
    let mut major: u32 = 0;
    let mut any = false;
    for &b in &ua[pos + 5..] {
        if b.is_ascii_digit() {
            any = true;
            major = major.saturating_mul(10).saturating_add((b - b'0') as u32);
        } else {
            break;
        }
    }
    any && major <= 6
}

pub(crate) fn user_agent_is_safari(ua: &[u8]) -> bool {
    contains_ascii_case_insensitive(ua, b"Safari/")
        && contains_ascii_case_insensitive(ua, b"Mac OS X")
}

pub(crate) fn should_disable_keepalive_for_user_agent(
    method_is_post: bool,
    keepalive: phase::KeepaliveMeta,
    user_agent: Option<&[u8]>,
) -> bool {
    let Some(ua) = user_agent else {
        return false;
    };
    if keepalive.disable_msie6 && method_is_post && user_agent_is_msie6(ua) {
        return true;
    }
    keepalive.disable_safari && user_agent_is_safari(ua)
}

pub(crate) fn render_parts(parts: &[PreparedValuePart], ctx: &RenderCtx<'_>, out: &mut Vec<u8>) {
    for p in parts {
        match p {
            PreparedValuePart::Literal(b) => out.extend_from_slice(b),
            PreparedValuePart::Var(v) => ctx.write_var(v, out),
        }
    }
}

/// Milliseconds as nginx's `%T.%03M`, or `-` when the stage wasn't reached.
fn write_upstream_ms(out: &mut Vec<u8>, ms: Option<u64>) {
    let Some(ms) = ms else {
        out.push(b'-');
        return;
    };
    write_u64_decimal(out, ms / 1_000);
    let frac = ms % 1_000;
    out.extend_from_slice(&[
        b'.',
        b'0' + (frac / 100) as u8,
        b'0' + (frac / 10 % 10) as u8,
        b'0' + (frac % 10) as u8,
    ]);
}

/// One `map` lookup: render the source key, try exact → wildcards → regex
/// → default (nginx's `ngx_http_map_module.c` lookup order).
fn render_map(program: &PreparedMap, ctx: &RenderCtx<'_>, out: &mut Vec<u8>) {
    let mut key = Vec::with_capacity(32);
    render_parts(program.key, ctx, &mut key);
    if program.hostnames && key.last() == Some(&b'.') {
        key.pop();
    }
    // The hash lookup is case-insensitive; regexes see the value as it is.
    let lower = key.to_ascii_lowercase();
    if let Some(value) = program.exact.get(lower.as_slice()) {
        render_parts(value, ctx, out);
        return;
    }
    if let Some(value) = map_wildcard(program, &lower) {
        render_parts(value, ctx, out);
        return;
    }
    for entry in program.regex {
        if entry.regex.is_match(&key) {
            render_parts(entry.value, ctx, out);
            return;
        }
    }
    if let Some(default) = program.default {
        render_parts(default, ctx, out);
    }
}

/// A `hostnames` map's wildcard match for a lowercased host: the longest
/// `*.suffix` / `.suffix`, then the longest `head.*`.
fn map_wildcard(map: &PreparedMap, host: &[u8]) -> Option<&'static [PreparedValuePart]> {
    let head = map
        .wildcard_head
        .iter()
        .filter(|(suffix, bare, _)| {
            (*bare && host == suffix.as_slice())
                || (host.len() > suffix.len()
                    && host.ends_with(suffix)
                    && host[host.len() - suffix.len() - 1] == b'.')
        })
        .max_by_key(|(suffix, _, _)| suffix.len());
    if let Some((_, _, value)) = head {
        return Some(value);
    }
    map.wildcard_tail
        .iter()
        .filter(|(head, _)| {
            host.len() > head.len() && host.starts_with(head) && host[head.len()] == b'.'
        })
        .max_by_key(|(head, _)| head.len())
        .map(|(_, value)| *value)
}

/// `HTTP/1.x` at the end of a request line; empty if there is none.
fn server_protocol(request_line: &[u8]) -> &[u8] {
    match request_line.iter().rposition(|&b| b == b' ') {
        Some(i) if request_line[i + 1..].starts_with(b"HTTP/") => &request_line[i + 1..],
        _ => b"",
    }
}

/// Render a `log_format` line the way nginx's log module does: variable
/// values are escaped per `escape=`, and with the default escaping a
/// variable that isn't set is written as `-`.
pub(crate) fn render_log_parts(
    parts: &[PreparedValuePart],
    escape: LogEscape,
    ctx: &RenderCtx<'_>,
    out: &mut Vec<u8>,
) {
    let mut value = Vec::new();
    for p in parts {
        match p {
            PreparedValuePart::Literal(b) => out.extend_from_slice(b),
            PreparedValuePart::Var(v) => {
                value.clear();
                ctx.write_var(v, &mut value);
                if value.is_empty() && unset_when_empty(v) {
                    if escape == LogEscape::Default {
                        out.push(b'-');
                    }
                    continue;
                }
                match escape {
                    LogEscape::Default => log_escape_into(&value, out),
                    LogEscape::Json => json_escape_into(&value, out),
                    LogEscape::None => out.extend_from_slice(&value),
                }
            }
        }
    }
}

/// Variables that nginx reports as "not found", rather than as an empty
/// value, when there is nothing to show: absent headers, cookies and
/// arguments, no authenticated user, no upstream, no TLS, no body.
fn unset_when_empty(v: &Variable) -> bool {
    matches!(
        v,
        Variable::Http(_)
            | Variable::SentHttp(_)
            | Variable::SentTrailer(_)
            | Variable::Cookie(_)
            | Variable::Arg(_)
            | Variable::Args
            | Variable::ContentLength
            | Variable::ContentType
            | Variable::RemoteUser
            | Variable::RequestBody
            | Variable::RequestBodyFile
            | Variable::ProxyHost
            | Variable::ProxyPort
            | Variable::UpstreamHttp(_)
            | Variable::UpstreamCookie(_)
            | Variable::UpstreamResponseLength
            | Variable::UpstreamResponseTime
            | Variable::UpstreamAddr
            | Variable::UpstreamStatus
            | Variable::UpstreamConnectTime
            | Variable::UpstreamHeaderTime
            | Variable::UpstreamBytesReceived
            | Variable::UpstreamBytesSent
            | Variable::SslProtocol
            | Variable::SslCipher
            | Variable::SslCiphers
            | Variable::SslServerName
            | Variable::SslSessionId
            | Variable::SslClientVerify
            | Variable::SslClientIDn
            | Variable::SslClientIDnLegacy
            | Variable::SslClientSDn
            | Variable::SslClientSDnLegacy
            | Variable::SslClientVStart
            | Variable::SslClientVEnd
            | Variable::SslClientVRemain
            | Variable::ProxyProtocolAddr
            | Variable::ProxyProtocolPort
            | Variable::ProxyProtocolServerAddr
            | Variable::ProxyProtocolServerPort
            | Variable::ProxyProtocolTlv(_)
    )
}

/// nginx's `ngx_http_log_escape`: `"`, `\`, control bytes, DEL and
/// non-ASCII bytes become `\xHH`.
fn log_escape_into(value: &[u8], out: &mut Vec<u8>) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for &b in value {
        if b < 0x20 || b >= 0x7f || b == b'"' || b == b'\\' {
            out.extend_from_slice(&[b'\\', b'x', HEX[(b >> 4) as usize], HEX[(b & 0xf) as usize]]);
        } else {
            out.push(b);
        }
    }
}

/// nginx's `ngx_escape_json`.
fn json_escape_into(value: &[u8], out: &mut Vec<u8>) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for &b in value {
        match b {
            b'"' | b'\\' => out.extend_from_slice(&[b'\\', b]),
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\t' => out.extend_from_slice(b"\\t"),
            0x08 => out.extend_from_slice(b"\\b"),
            0x0c => out.extend_from_slice(b"\\f"),
            0..=0x1f => {
                out.extend_from_slice(b"\\u00");
                out.push(HEX[(b >> 4) as usize]);
                out.push(HEX[(b & 0xf) as usize]);
            }
            _ => out.push(b),
        }
    }
}

/// Render parts for the args side of a rewrite replacement. Numbered
/// regex captures (`$1`..`$9`) get arg-escaped (nginx's `NGX_ESCAPE_ARGS`),
/// since they were captured from the decoded URI and may contain bytes
/// that need percent-encoding to be safe in args context (e.g. `%`).
/// Literals and other variables pass through unchanged — nginx applies
/// the escape only to capture variables in this context.
pub(crate) fn render_parts_with_arg_escape(
    parts: &[PreparedValuePart],
    ctx: &RenderCtx<'_>,
    out: &mut Vec<u8>,
) {
    for p in parts {
        match p {
            PreparedValuePart::Literal(b) => out.extend_from_slice(b),
            PreparedValuePart::Var(v @ Variable::Capture(_)) => {
                let mut buf = Vec::with_capacity(16);
                ctx.write_var(v, &mut buf);
                escape_args_into(&buf, out);
            }
            PreparedValuePart::Var(v) => ctx.write_var(v, out),
        }
    }
}

/// nginx's `ngx_escape_uri(... NGX_ESCAPE_ARGS)`: percent-encode bytes
/// that aren't safe inside a URL query string. Conservative: covers
/// control bytes, high bytes, space, and the args-meta characters
/// (`#`, `%`, `&`, `+`, `?`) plus a handful of non-args-safe ASCII
/// punctuation.
pub(crate) fn escape_args_into(input: &[u8], out: &mut Vec<u8>) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for &b in input {
        let escape = b < 0x21
            || b >= 0x7f
            || matches!(
                b,
                b'"' | b'#' | b'%' | b'&' | b'+' | b'<' | b'>' | b'?' | b'`'
            );
        if escape {
            out.push(b'%');
            out.push(HEX[(b >> 4) as usize]);
            out.push(HEX[(b & 0x0f) as usize]);
        } else {
            out.push(b);
        }
    }
}

pub(crate) fn condition_is_truthy(raw: &[u8]) -> bool {
    let mut s = raw;
    while let Some((&c, rest)) = s.split_first() {
        if c == b' ' || c == b'\t' {
            s = rest;
        } else {
            break;
        }
    }
    while let Some((&c, rest)) = s.split_last() {
        if c == b' ' || c == b'\t' {
            s = rest;
        } else {
            break;
        }
    }
    !s.is_empty() && s != b"0"
}

pub(crate) fn request_args(request_uri: &[u8]) -> &[u8] {
    match request_uri.iter().position(|&b| b == b'?') {
        Some(i) if i + 1 < request_uri.len() => &request_uri[i + 1..],
        Some(_) | None => &[],
    }
}

pub(crate) fn request_arg_value<'a>(args: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    if args.is_empty() {
        return None;
    }
    for pair in args.split(|&b| b == b'&') {
        let (key, value) = match pair.iter().position(|&b| b == b'=') {
            Some(eq) => (&pair[..eq], &pair[eq + 1..]),
            None => (pair, &[][..]),
        };
        if key == name {
            return Some(value);
        }
    }
    None
}

pub(crate) fn write_unescaped_arg_value(out: &mut Vec<u8>, raw: &[u8]) {
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == b'%'
            && i + 2 < raw.len()
            && let (Some(hi), Some(lo)) = (hex_nibble(raw[i + 1]), hex_nibble(raw[i + 2]))
        {
            out.push((hi << 4) | lo);
            i += 3;
            continue;
        }
        out.push(raw[i]);
        i += 1;
    }
}

pub(crate) fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

pub(crate) fn murmur_hash2(data: &[u8]) -> u32 {
    const M: u32 = 0x5bd1e995;
    let mut h = data.len() as u32;
    let mut i = 0usize;
    while i + 4 <= data.len() {
        let mut k = (data[i] as u32)
            | ((data[i + 1] as u32) << 8)
            | ((data[i + 2] as u32) << 16)
            | ((data[i + 3] as u32) << 24);
        k = k.wrapping_mul(M);
        k ^= k >> 24;
        k = k.wrapping_mul(M);

        h = h.wrapping_mul(M);
        h ^= k;
        i += 4;
    }

    match data.len() - i {
        3 => {
            h ^= (data[i + 2] as u32) << 16;
            h ^= (data[i + 1] as u32) << 8;
            h ^= data[i] as u32;
            h = h.wrapping_mul(M);
        }
        2 => {
            h ^= (data[i + 1] as u32) << 8;
            h ^= data[i] as u32;
            h = h.wrapping_mul(M);
        }
        1 => {
            h ^= data[i] as u32;
            h = h.wrapping_mul(M);
        }
        _ => {}
    }

    h ^= h >> 13;
    h = h.wrapping_mul(M);
    h ^= h >> 15;
    h
}

pub(crate) fn write_u16_decimal(out: &mut Vec<u8>, mut n: u16) {
    let mut tmp = [0u8; 5];
    let mut k = tmp.len();
    if n == 0 {
        out.push(b'0');
        return;
    }
    while n > 0 {
        k -= 1;
        tmp[k] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    out.extend_from_slice(&tmp[k..]);
}

pub(crate) fn write_u64_decimal(out: &mut Vec<u8>, mut n: u64) {
    let mut tmp = [0u8; 20];
    let mut k = tmp.len();
    if n == 0 {
        out.push(b'0');
        return;
    }
    while n > 0 {
        k -= 1;
        tmp[k] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    out.extend_from_slice(&tmp[k..]);
}

/// Duration variables (`$connection_time`, `$request_time`) render as
/// `seconds.milliseconds` (e.g. `0.012`, `3.456`). nginx formats both
/// families with 3-digit fractional precision; we match that shape.
pub(crate) fn write_connection_time(out: &mut Vec<u8>, us: u64) {
    let ms_total = us / 1_000;
    let secs = ms_total / 1_000;
    let ms = (ms_total % 1_000) as u32;
    write_u64_decimal(out, secs);
    out.push(b'.');
    out.push(b'0' + ((ms / 100) % 10) as u8);
    out.push(b'0' + ((ms / 10) % 10) as u8);
    out.push(b'0' + (ms % 10) as u8);
}

/// Decompose a Unix-epoch second count into (year, month-1, day-1, hour,
/// minute, second). Mirrors the calendar walk in `file::format_http_date`
/// but returns the raw components so multiple formatters can share it.
pub(crate) fn civil_from_secs(secs: u64) -> (u32, u32, u32, u32, u32, u32) {
    pub(crate) fn is_leap(y: u32) -> bool {
        (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
    }
    const DAYS_PER_MONTH: [u32; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let days = secs / 86_400;
    let hms = secs % 86_400;
    let hour = (hms / 3_600) as u32;
    let minute = ((hms % 3_600) / 60) as u32;
    let second = (hms % 60) as u32;

    let mut year: u32 = 1970;
    let mut day_of_year = days;
    loop {
        let yd = if is_leap(year) { 366 } else { 365 } as u64;
        if day_of_year < yd {
            break;
        }
        day_of_year -= yd;
        year += 1;
    }

    let mut mon: u32 = 0;
    loop {
        let md = if mon == 1 && is_leap(year) {
            29
        } else {
            DAYS_PER_MONTH[mon as usize]
        } as u64;
        if day_of_year < md {
            break;
        }
        day_of_year -= md;
        mon += 1;
    }
    (year, mon, day_of_year as u32, hour, minute, second)
}

/// `2026-04-23T12:34:56+00:00` — UTC. nginx renders local time with the
/// system TZ offset; ruxen always emits `+00:00`. Both shapes match the
/// `\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d[+-]\d\d:\d\d` pattern that
/// `access_log_variables.t` checks for.
pub(crate) fn write_time_iso8601(out: &mut Vec<u8>, secs: u64) {
    let (year, mon, day, hour, minute, second) = civil_from_secs(secs);
    let mut buf = *b"0000-00-00T00:00:00+00:00";
    write_u4(&mut buf[0..4], year);
    write_u2(&mut buf[5..7], mon + 1);
    write_u2(&mut buf[8..10], day + 1);
    write_u2(&mut buf[11..13], hour);
    write_u2(&mut buf[14..16], minute);
    write_u2(&mut buf[17..19], second);
    out.extend_from_slice(&buf);
}

/// `23/Apr/2026:12:34:56 +0000` — Common Log Format date in UTC. Matches
/// the regex `\d\d/[A-Z][a-z]{2}/\d{4}:\d\d:\d\d:\d\d [+-]\d{4}` used by
/// `access_log_variables.t`. nginx emits local time; we emit UTC for
/// reproducibility.
pub(crate) fn write_time_local(out: &mut Vec<u8>, secs: u64) {
    const MON: [&[u8; 3]; 12] = [
        b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov",
        b"Dec",
    ];
    let (year, mon, day, hour, minute, second) = civil_from_secs(secs);
    let mut buf = *b"00/Mon/0000:00:00:00 +0000";
    write_u2(&mut buf[0..2], day + 1);
    buf[3..6].copy_from_slice(MON[mon as usize]);
    write_u4(&mut buf[7..11], year);
    write_u2(&mut buf[12..14], hour);
    write_u2(&mut buf[15..17], minute);
    write_u2(&mut buf[18..20], second);
    out.extend_from_slice(&buf);
}

/// `$proxy_port`: the port written in `$proxy_host` (`host:port`,
/// `[v6]:port`), else the scheme's default, as nginx's
/// ngx_http_proxy_set_vars. Only `http://` is proxied today, so that's 80.
/// Empty outside a proxy context, like `$proxy_host`.
fn proxy_port(proxy_host: &[u8]) -> &[u8] {
    if proxy_host.is_empty() {
        return b"";
    }
    let after_host = match proxy_host.iter().rposition(|&b| b == b']') {
        Some(i) => &proxy_host[i + 1..],
        None => proxy_host,
    };
    match after_host.iter().rposition(|&b| b == b':') {
        Some(i) => &after_host[i + 1..],
        None => b"80",
    }
}

/// `Oct  5 09:04:07` — the RFC 3164 timestamp nginx puts in syslog
/// messages (`ngx_cached_syslog_time`: the day space-padded), in UTC.
pub(crate) fn write_time_syslog(out: &mut Vec<u8>, secs: u64) {
    const MON: [&[u8; 3]; 12] = [
        b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov",
        b"Dec",
    ];
    let (_, mon, day, hour, minute, second) = civil_from_secs(secs);
    let mut buf = *b"Mon 00 00:00:00";
    buf[0..3].copy_from_slice(MON[mon as usize]);
    write_u2(&mut buf[4..6], day + 1);
    if buf[4] == b'0' {
        buf[4] = b' ';
    }
    write_u2(&mut buf[7..9], hour);
    write_u2(&mut buf[10..12], minute);
    write_u2(&mut buf[13..15], second);
    out.extend_from_slice(&buf);
}

/// `1234567890.123` — UNIX seconds, dot, three-digit ms fraction.
pub(crate) fn write_msec(out: &mut Vec<u8>, secs: u64, ms: u16) {
    write_u64_decimal(out, secs);
    out.push(b'.');
    let ms = ms as u32;
    out.push(b'0' + ((ms / 100) % 10) as u8);
    out.push(b'0' + ((ms / 10) % 10) as u8);
    out.push(b'0' + (ms % 10) as u8);
}

#[inline]
pub(crate) fn write_u2(dst: &mut [u8], n: u32) {
    dst[0] = b'0' + ((n / 10) % 10) as u8;
    dst[1] = b'0' + (n % 10) as u8;
}

#[inline]
pub(crate) fn write_u4(dst: &mut [u8], n: u32) {
    dst[0] = b'0' + ((n / 1000) % 10) as u8;
    dst[1] = b'0' + ((n / 100) % 10) as u8;
    dst[2] = b'0' + ((n / 10) % 10) as u8;
    dst[3] = b'0' + (n % 10) as u8;
}

pub(crate) fn render_variable_to_vec(var: &Variable, ctx: &RenderCtx<'_>) -> Vec<u8> {
    let mut out = Vec::with_capacity(32);
    ctx.write_var(var, &mut out);
    out
}
