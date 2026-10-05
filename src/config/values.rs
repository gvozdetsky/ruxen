//! `ValuePart` lowering: parses strings with embedded `$var` / `${var}`
//! references into a sequence of literal/variable parts, classifies
//! variables by family (request/response/connection/configured), and
//! enforces `$sent_http_*` rejection in scopes where it isn't valid.

use super::*;

/// Token char for an HTTP field-name (RFC 9110 §5.1). Conservative; `add_header`
/// names going over the wire need to be real tokens or we'll produce malformed
/// response headers.
#[inline]
pub(crate) fn is_header_name_char(c: u8) -> bool {
    matches!(
        c,
        b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*'
        | b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~'
        | b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z'
    )
}

/// Some value in the configuration reads `$server_addr`. Connections on a
/// wildcard listen then look up their local address (`getsockname`) once;
/// otherwise the accept path doesn't pay for it.
pub static SERVER_ADDR_USED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Parse a value string into alternating literal + variable parts. A `$`
/// that isn't followed by at least one variable-name char is treated as a
/// literal dollar sign (matches nginx's tokenizer for directive values).
/// Unknown variable names are accepted as `Variable::Unknown` and rendered as
/// empty at request time, matching nginx's lenient variable lookup.
pub fn parse_value_with_vars(s: &str) -> Result<Vec<ValuePart>, Error> {
    parse_value_with_vars_impl(s, false)
}

pub(crate) fn parse_value_with_vars_rewrite(s: &str) -> Result<Vec<ValuePart>, Error> {
    parse_value_with_vars_impl(s, true)
}

pub(crate) fn parse_value_with_vars_impl(
    s: &str,
    allow_numeric_capture: bool,
) -> Result<Vec<ValuePart>, Error> {
    let bytes = s.as_bytes();
    let mut out: Vec<ValuePart> = Vec::new();
    let mut lit_start = 0;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'$' {
            let (name_start, mut j, braced) = if bytes.get(i + 1) == Some(&b'{') {
                let name_start = i + 2;
                if name_start >= bytes.len() || !is_var_name_first(bytes[name_start]) {
                    i += 1;
                    continue;
                }
                let mut j = name_start + 1;
                while j < bytes.len() && is_var_name_cont(bytes[j]) {
                    j += 1;
                }
                if bytes.get(j) != Some(&b'}') {
                    return Err(Error::BadValue {
                        what: "unsupported variable",
                        got: s[i..].to_string(),
                    });
                }
                (name_start, j, true)
            } else {
                // Variable-name = [A-Za-z_][A-Za-z0-9_]* (nginx's rule). If
                // the next byte doesn't match, the `$` is a literal, except
                // in rewrite replacement mode where `$1`..`$9` are numbered
                // regex captures.
                let name_start = i + 1;
                if name_start >= bytes.len() {
                    i += 1;
                    continue;
                }
                if allow_numeric_capture && bytes[name_start].is_ascii_digit() {
                    if (b'1'..=b'9').contains(&bytes[name_start]) {
                        if lit_start < i {
                            out.push(ValuePart::Literal(s[lit_start..i].to_string()));
                        }
                        out.push(ValuePart::Var(Variable::Capture(
                            (bytes[name_start] - b'0') as usize,
                        )));
                        i = name_start + 1;
                        lit_start = i;
                    } else {
                        i += 1;
                    }
                    continue;
                }
                if !is_var_name_first(bytes[name_start]) {
                    i += 1;
                    continue;
                }
                let mut j = name_start + 1;
                while j < bytes.len() && is_var_name_cont(bytes[j]) {
                    j += 1;
                }
                (name_start, j, false)
            };
            let var = classify_variable(&bytes[name_start..j])?;
            if lit_start < i {
                out.push(ValuePart::Literal(s[lit_start..i].to_string()));
            }
            if braced {
                j += 1;
            }
            out.push(ValuePart::Var(var));
            i = j;
            lit_start = j;
        } else {
            i += 1;
        }
    }
    if lit_start < bytes.len() {
        out.push(ValuePart::Literal(s[lit_start..].to_string()));
    }
    Ok(out)
}

pub(crate) fn parse_single_variable(
    token: &str,
    allow_numeric_capture: bool,
) -> Result<Variable, Error> {
    let parts = parse_value_with_vars_impl(token, allow_numeric_capture)?;
    if parts.len() != 1 {
        return Err(Error::BadValue {
            what: "variable",
            got: token.to_string(),
        });
    }
    match &parts[0] {
        ValuePart::Var(var) => Ok(var.clone()),
        _ => Err(Error::BadValue {
            what: "variable",
            got: token.to_string(),
        }),
    }
}

pub(crate) fn reject_sent_http_parts(parts: &[ValuePart], what: &'static str) -> Result<(), Error> {
    for part in parts {
        if let ValuePart::Var(Variable::SentHttp(name)) = part {
            return Err(Error::BadValue {
                what,
                got: format!("$sent_http_{}", name.replace('-', "_")),
            });
        }
    }
    Ok(())
}

// Variables ruxen resolves only at run time (`Variable::Unknown`): the
// names referenced, and the ones the config defines. nginx rejects a
// reference to a name nothing defines (`unknown "x" variable`); the check
// runs once the whole config is read, since `set` / `map` may come later.
thread_local! {
    static VARIABLES: std::cell::RefCell<VariableRegistry> =
        std::cell::RefCell::new(VariableRegistry::default());
}

#[derive(Default)]
struct VariableRegistry {
    referenced: Vec<String>,
    defined: std::collections::HashSet<String>,
}

pub(crate) fn reset_variable_registry() {
    VARIABLES.with(|v| *v.borrow_mut() = VariableRegistry::default());
}

/// Note the names a directive defines: `set $x`, `map … $x`,
/// `split_clients … $x`, and named captures in any regex argument
/// (`(?<x>…)`, `(?P<x>…)`, `(?'x'…)`).
pub(crate) fn note_defined_variables(args: &[String]) {
    let target = match args.first().map(String::as_str) {
        Some("set") => args.get(1),
        Some("map" | "split_clients") => args.get(2),
        _ => None,
    };
    VARIABLES.with(|v| {
        let mut v = v.borrow_mut();
        if let Some(name) = target.and_then(|t| t.strip_prefix('$')) {
            v.defined.insert(name.to_string());
        }
        for arg in args {
            for (open, close) in [("(?<", '>'), ("(?P<", '>'), ("(?'", '\'')] {
                let mut rest = arg.as_str();
                while let Some(i) = rest.find(open) {
                    rest = &rest[i + open.len()..];
                    if let Some(end) = rest.find(close) {
                        v.defined.insert(rest[..end].to_string());
                    }
                }
            }
        }
    });
}

/// After the whole config is read: an error for the first reference
/// nothing defines, and a warning per variable nginx has but ruxen
/// doesn't implement yet (those render empty).
pub(crate) fn check_variable_references() -> Result<Vec<String>, Error> {
    VARIABLES.with(|v| {
        let v = v.borrow();
        let mut warnings = Vec::new();
        for name in &v.referenced {
            if v.defined.contains(name) {
                continue;
            }
            if !is_nginx_variable(name) {
                return Err(Error::UnknownVariable(name.clone()));
            }
            let w = format!("variable \"${name}\" is not supported yet and is always empty");
            if !warnings.contains(&w) {
                warnings.push(w);
            }
        }
        Ok(warnings)
    })
}

/// Variables of nginx 1.24 (core and the modules of a default build) that
/// ruxen doesn't implement as such.
fn is_nginx_variable(name: &str) -> bool {
    const NAMES: &[&str] = &[
        "binary_remote_addr",
        "bytes_received",
        "date_gmt",
        "date_local",
        "document_root",
        "document_uri",
        "fastcgi_path_info",
        "fastcgi_script_name",
        "gzip_ratio",
        "http2",
        "http3",
        "https",
        "invalid_referer",
        "limit_conn_status",
        "limit_req_status",
        "memcached_key",
        "msie",
        "nginx_version",
        "pid",
        "proxy_internal_body_length",
        "proxy_internal_chunked",
        "quic",
        "realip_remote_addr",
        "realip_remote_port",
        "realpath_root",
        "request_completion",
        "request_filename",
        "request_id",
        "secure_link",
        "secure_link_expires",
        "slice_range",
        "tcpinfo_rcv_space",
        "tcpinfo_rtt",
        "tcpinfo_rttvar",
        "tcpinfo_snd_cwnd",
        "uid_got",
        "uid_reset",
        "uid_set",
        "upstream_cache_status",
        "upstream_cache_last_modified",
    ];
    const PREFIXES: &[&str] = &["ssl_", "upstream_trailer_", "geoip_"];
    NAMES.contains(&name) || PREFIXES.iter().any(|p| name.starts_with(p))
}

fn note_unknown_variable(name: &str) {
    VARIABLES.with(|v| v.borrow_mut().referenced.push(name.to_string()));
}

/// The TLV a `$proxy_protocol_tlv_<name>` names, as nginx's
/// ngx_proxy_protocol_get_tlv reads `<name>`: an `ssl_` prefix moves to the
/// SSL TLV's sub-TLVs, `0x…` is a hex type, else one of nginx's names.
fn classify_proxy_protocol_tlv(name: &[u8]) -> ProxyProtocolTlv {
    const TOP: &[(&[u8], u8)] = &[
        (b"alpn", 0x01),
        (b"authority", 0x02),
        (b"unique_id", 0x05),
        (b"ssl", 0x20),
        (b"netns", 0x30),
    ];
    const SSL: &[(&[u8], u8)] = &[
        (b"version", 0x21),
        (b"cn", 0x22),
        (b"cipher", 0x23),
        (b"sig_alg", 0x24),
        (b"key_alg", 0x25),
    ];
    let (ssl, rest) = match name.strip_prefix(b"ssl_") {
        Some(rest) => (true, rest),
        None => (false, name),
    };
    if ssl && rest == b"verify" {
        return ProxyProtocolTlv::SslVerify;
    }
    let ty = if let Some(hex) = rest.strip_prefix(b"0x") {
        // nginx's ngx_hextoi: one or more hex digits.
        match std::str::from_utf8(hex)
            .ok()
            .filter(|h| !h.is_empty() && h.bytes().all(|b| b.is_ascii_hexdigit()))
            .map(|h| u64::from_str_radix(h, 16))
        {
            Some(Ok(n)) => u8::try_from(n).ok(),
            _ => return ProxyProtocolTlv::Unknown,
        }
    } else {
        let table = if ssl { SSL } else { TOP };
        match table.iter().find(|(n, _)| *n == rest) {
            Some(&(_, ty)) => Some(ty),
            None => return ProxyProtocolTlv::Unknown,
        }
    };
    if ssl {
        ProxyProtocolTlv::Ssl(ty)
    } else {
        ProxyProtocolTlv::Type(ty)
    }
}

/// Some value in the configuration reads `$ssl_session_id`. TLS listens
/// with session resumption then give each session an id (see
/// `TlsAcceptor::with_session_ids`); otherwise handshakes don't pay for it.
pub static SSL_SESSION_ID_USED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

pub(crate) fn classify_variable(name: &[u8]) -> Result<Variable, Error> {
    Ok(match name {
        b"uri" => Variable::Uri,
        b"request_uri" => Variable::RequestUri,
        b"request_method" => Variable::RequestMethod,
        b"request" => Variable::Request,
        b"proxy_protocol_addr" => Variable::ProxyProtocolAddr,
        b"proxy_protocol_port" => Variable::ProxyProtocolPort,
        b"proxy_protocol_server_addr" => Variable::ProxyProtocolServerAddr,
        b"proxy_protocol_server_port" => Variable::ProxyProtocolServerPort,
        _ if name.starts_with(b"proxy_protocol_tlv_") => Variable::ProxyProtocolTlv(
            classify_proxy_protocol_tlv(&name[b"proxy_protocol_tlv_".len()..]),
        ),
        b"server_protocol" => Variable::ServerProtocol,
        b"host" => Variable::Host,
        b"server_name" => Variable::ServerName,
        b"status" => Variable::Status,
        b"args" | b"query_string" => Variable::Args,
        b"is_args" => Variable::IsArgs,
        b"scheme" => Variable::Scheme,
        b"ssl_protocol" => Variable::SslProtocol,
        b"ssl_cipher" => Variable::SslCipher,
        b"ssl_ciphers" => Variable::SslCiphers,
        b"ssl_server_name" => Variable::SslServerName,
        b"ssl_session_reused" => Variable::SslSessionReused,
        b"ssl_session_id" => {
            SSL_SESSION_ID_USED.store(true, std::sync::atomic::Ordering::Relaxed);
            Variable::SslSessionId
        }
        b"ssl_client_verify" => Variable::SslClientVerify,
        b"ssl_client_i_dn" => Variable::SslClientIDn,
        b"ssl_client_i_dn_legacy" => Variable::SslClientIDnLegacy,
        b"ssl_client_s_dn" => Variable::SslClientSDn,
        b"ssl_client_s_dn_legacy" => Variable::SslClientSDnLegacy,
        b"ssl_client_v_start" => Variable::SslClientVStart,
        b"ssl_client_v_end" => Variable::SslClientVEnd,
        b"ssl_client_v_remain" => Variable::SslClientVRemain,
        b"request_body" => Variable::RequestBody,
        b"request_body_file" => Variable::RequestBodyFile,
        b"remote_addr" => Variable::RemoteAddr,
        b"remote_port" => Variable::RemotePort,
        b"remote_user" => Variable::RemoteUser,
        b"hostname" => Variable::Hostname,
        b"connection" => Variable::Connection,
        b"connection_requests" => Variable::ConnectionRequests,
        b"connection_time" => Variable::ConnectionTime,
        b"request_time" => Variable::RequestTime,
        b"limit_rate" => Variable::LimitRate,
        b"server_port" => Variable::ServerPort,
        b"server_addr" => {
            SERVER_ADDR_USED.store(true, std::sync::atomic::Ordering::Relaxed);
            Variable::ServerAddr
        }
        b"request_port" => Variable::RequestPort,
        b"is_request_port" => Variable::IsRequestPort,
        b"pipe" => Variable::Pipe,
        b"request_length" => Variable::RequestLength,
        b"bytes_sent" => Variable::BytesSent,
        b"body_bytes_sent" => Variable::BodyBytesSent,
        b"time_iso8601" => Variable::TimeIso8601,
        b"time_local" => Variable::TimeLocal,
        b"msec" => Variable::Msec,
        b"proxy_host" => Variable::ProxyHost,
        b"proxy_port" => Variable::ProxyPort,
        b"proxy_add_x_forwarded_for" => Variable::ProxyAddXForwardedFor,
        b"content_length" => Variable::ContentLength,
        b"content_type" => Variable::ContentType,
        _ if name.starts_with(b"arg_") => {
            Variable::Arg(String::from_utf8_lossy(&name[4..]).into_owned())
        }
        _ if name.starts_with(b"sent_http_") => {
            Variable::SentHttp(header_var_name(&name[b"sent_http_".len()..]))
        }
        _ if name.starts_with(b"sent_trailer_") => {
            Variable::SentTrailer(header_var_name(&name[b"sent_trailer_".len()..]))
        }
        b"upstream_response_length" => Variable::UpstreamResponseLength,
        b"upstream_addr" => Variable::UpstreamAddr,
        b"upstream_status" => Variable::UpstreamStatus,
        b"upstream_connect_time" => Variable::UpstreamConnectTime,
        b"upstream_header_time" => Variable::UpstreamHeaderTime,
        b"upstream_bytes_received" => Variable::UpstreamBytesReceived,
        b"upstream_bytes_sent" => Variable::UpstreamBytesSent,
        b"upstream_response_time" => Variable::UpstreamResponseTime,
        _ if name.starts_with(b"upstream_http_") => {
            Variable::UpstreamHttp(header_var_name(&name[b"upstream_http_".len()..]))
        }
        _ if name.starts_with(b"upstream_cookie_") => {
            // Cookie names are case-sensitive in transit; we lowercase here
            // to match nginx's variable lookup which downcases the suffix.
            let mut s = String::with_capacity(name.len() - b"upstream_cookie_".len());
            for &b in &name[b"upstream_cookie_".len()..] {
                s.push(b.to_ascii_lowercase() as char);
            }
            Variable::UpstreamCookie(s)
        }
        _ if name.starts_with(b"cookie_") => {
            let mut s = String::with_capacity(name.len() - b"cookie_".len());
            for &b in &name[b"cookie_".len()..] {
                s.push(b.to_ascii_lowercase() as char);
            }
            Variable::Cookie(s)
        }
        _ if name.starts_with(b"http_") => Variable::Http(header_var_name(&name[b"http_".len()..])),
        _ => {
            let name = String::from_utf8_lossy(name).into_owned();
            note_unknown_variable(&name);
            Variable::Unknown(name)
        }
    })
}

/// Nginx maps `$http_x_forwarded_for` → the `X-Forwarded-For` header: the
/// `http_` prefix is stripped, underscores become dashes, and the match
/// is case-insensitive. We store the name already lower-cased with dashes
/// so the request-time scan can memcmp byte-for-byte against the raw
/// header block (which we lowercase on the fly).
pub(crate) fn header_var_name(tail: &[u8]) -> String {
    let mut s = String::with_capacity(tail.len());
    for &b in tail {
        let c = b.to_ascii_lowercase();
        s.push(if c == b'_' { '-' } else { c as char });
    }
    s
}

#[inline]
pub(crate) fn is_var_name_first(c: u8) -> bool {
    matches!(c, b'A'..=b'Z' | b'a'..=b'z' | b'_')
}

#[inline]
pub(crate) fn is_var_name_cont(c: u8) -> bool {
    matches!(c, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_')
}

#[cfg(test)]
mod tests {
    use super::classify_proxy_protocol_tlv as c;
    use crate::config::ProxyProtocolTlv as T;

    #[test]
    fn proxy_protocol_tlv_names_like_nginx() {
        assert_eq!(c(b"alpn"), T::Type(Some(0x01)));
        assert_eq!(c(b"ssl"), T::Type(Some(0x20)));
        assert_eq!(c(b"0x01"), T::Type(Some(0x01)));
        assert_eq!(c(b"0x000ae"), T::Type(Some(0xae)));
        assert_eq!(c(b"0x100"), T::Type(None));
        assert_eq!(c(b"ssl_cn"), T::Ssl(Some(0x22)));
        assert_eq!(c(b"ssl_0x22"), T::Ssl(Some(0x22)));
        assert_eq!(c(b"ssl_verify"), T::SslVerify);
        assert_eq!(c(b"0x"), T::Unknown);
        assert_eq!(c(b"0xzz"), T::Unknown);
        assert_eq!(c(b"nope"), T::Unknown);
        assert_eq!(c(b"ssl_nope"), T::Unknown);
    }
}
