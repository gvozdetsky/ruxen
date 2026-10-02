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

pub(crate) fn classify_variable(name: &[u8]) -> Result<Variable, Error> {
    Ok(match name {
        b"uri" => Variable::Uri,
        b"request_uri" => Variable::RequestUri,
        b"request_method" => Variable::RequestMethod,
        b"request" => Variable::Request,
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
        b"ssl_session_id" => Variable::SslSessionId,
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
        _ => Variable::Unknown(String::from_utf8_lossy(name).into_owned()),
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
