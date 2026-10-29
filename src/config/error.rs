//! Parse-time error type. Display impl mirrors nginx's `open() "<path>"
//! failed (<reason>)` shape for `IncludeOpen` so the upstream `nginx -T`
//! tests don't accidentally match parser errors as include hits.

#[derive(Debug)]
pub enum Error {
    UnexpectedEof,
    UnterminatedString,
    UnclosedBlock,
    UnexpectedToken(String),
    UnknownDirective {
        name: String,
        ctx: &'static str,
    },
    WrongTerminator {
        name: String,
        /// The block it was in: nginx's message doesn't name it, `Debug`
        /// shows it.
        #[allow(dead_code)]
        ctx: &'static str,
    },
    MissingArg(&'static str),
    BadValue {
        what: &'static str,
        got: String,
    },
    Duplicate(&'static str),
    UnsupportedLocationModifier(String),
    InvalidRegex {
        pattern: String,
        msg: String,
    },
    /// `include <path>;` failed to open the target. Formatted to match
    /// nginx's `open() "<path>" failed (<reason>)` shape so the upstream
    /// `nginx -T` test regexes — which scan for `file <path>/foo.conf` —
    /// don't accidentally match this error.
    IncludeOpen {
        path: String,
        reason: String,
    },
    /// A security-relevant directive ruxen can't enforce yet. Ignoring it
    /// would leave a config that looks protected and isn't.
    Unenforced {
        name: String,
        consequence: &'static str,
    },
    /// Arguments of a directive that don't go together, as nginx's
    /// `"listen" directive "ssl" parameter is incompatible with "quic"`.
    Directive {
        name: &'static str,
        msg: String,
    },
    /// One server listing an address twice, nginx's `a duplicate listen
    /// 127.0.0.1:80` (ngx_http_add_server); the address as nginx prints it.
    DuplicateListen(String),
    /// A host name that doesn't resolve, nginx's `host not found in
    /// "name:80" of the "listen" directive`.
    HostNotFound {
        url: String,
        directive: &'static str,
    },
    /// A `proxy_pass` or upstream `server` address nginx refuses, in its
    /// words: `host not found in upstream "name"`, `invalid port in
    /// upstream "name:99999"` (ngx_parse_url's error, ngx_http_upstream_add,
    /// ngx_http_upstream_server).
    UpstreamUrl {
        problem: &'static str,
        url: String,
    },
    /// `$name` that is neither a variable nginx knows nor one the config
    /// defines (`set`, `map`, `split_clients`, a named regex capture).
    UnknownVariable(String),
    /// `set` on a built-in nginx doesn't let change (#574).
    DuplicateVariable(String),
    /// A message nginx logs as it is, with no directive name around it
    /// (`the pool size must be no less than 112`).
    Message(&'static str),
    /// The same, built at parse time (`unknown thread pool "x"`).
    Text(String),
    /// Any of the above with where it happened, nginx's ` in file:line`.
    At {
        error: Box<Error>,
        position: String,
    },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::UnexpectedEof => write!(f, "unexpected end of config"),
            Error::UnterminatedString => write!(f, "unterminated quoted string"),
            Error::UnclosedBlock => write!(f, "unclosed block"),
            Error::UnexpectedToken(s) => write!(f, "unexpected token: {s}"),
            Error::UnknownDirective { name, ctx } => {
                write!(f, "unknown directive `{name}` {}", in_block(ctx))
            }
            // nginx's words (ngx_conf_handler): a block directive without
            // its `{`, any other without its `;`.
            Error::WrongTerminator { name, .. } if is_block_directive(name) => {
                write!(f, "directive \"{name}\" has no opening \"{{\"")
            }
            Error::WrongTerminator { name, .. } => {
                write!(f, "directive \"{name}\" is not terminated by \";\"")
            }
            Error::MissingArg(w) => write!(f, "missing argument for `{w}`"),
            Error::BadValue { what, got } => write!(f, "bad value for {what}: {got}"),
            Error::Duplicate(w) => write!(f, "duplicate directive `{w}`"),
            Error::UnsupportedLocationModifier(m) => {
                write!(f, "unsupported location modifier `{m}`")
            }
            Error::InvalidRegex { pattern, msg } => {
                write!(f, "invalid location regex `{pattern}`: {msg}")
            }
            Error::IncludeOpen { path, reason } => {
                write!(f, "open() \"{path}\" failed ({reason})")
            }
            Error::Unenforced { name, consequence } => write!(
                f,
                "\"{name}\" is not supported yet, and ignoring it is unsafe: {consequence}"
            ),
            Error::Directive { name, msg } => write!(f, "\"{name}\" directive {msg}"),
            Error::DuplicateListen(addr) => write!(f, "a duplicate listen {addr}"),
            Error::UpstreamUrl { problem, url } => {
                write!(f, "{problem} in upstream \"{url}\"")
            }
            Error::HostNotFound { url, directive } => {
                write!(
                    f,
                    "host not found in \"{url}\" of the \"{directive}\" directive"
                )
            }
            Error::UnknownVariable(name) => write!(f, "unknown \"{name}\" variable"),
            Error::DuplicateVariable(name) => write!(f, "the duplicate \"{name}\" variable"),
            Error::Message(msg) => f.write_str(msg),
            Error::Text(msg) => f.write_str(msg),
            Error::At { error, position } => write!(f, "{error} in {position}"),
        }
    }
}

impl std::error::Error for Error {}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Terminator {
    Semi,
    BlockOpen,
    BlockClose,
    Eof,
}

/// Where a directive was, for messages: `in a server block`, `at the top
/// level`. A position may follow (` in /etc/nginx/nginx.conf:12`).
pub(crate) fn in_block(ctx: &str) -> String {
    match ctx {
        "top-level" => "at the top level".to_string(),
        ctx => format!("in a {ctx} block"),
    }
}

/// The directives nginx declares `NGX_CONF_BLOCK` that ruxen parses.
fn is_block_directive(name: &str) -> bool {
    matches!(
        name,
        "http"
            | "events"
            | "server"
            | "location"
            | "upstream"
            | "types"
            | "map"
            | "if"
            | "limit_except"
            | "split_clients"
            | "geo"
            | "charset_map"
            | "match"
            | "stream"
            | "mail"
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn in_nginx_words() {
        let parse = |src: &str| crate::config::parse(src).unwrap_err().to_string();
        assert_eq!(
            parse("http { server { listen 80 { } } }"),
            "directive \"listen\" is not terminated by \";\""
        );
        assert_eq!(
            parse("http { server { location / ; } }"),
            "directive \"location\" has no opening \"{\""
        );
        assert_eq!(
            parse("http { server { location / { proxy_pass http://nosuch.invalid; } } }"),
            "host not found in upstream \"nosuch.invalid\""
        );
        assert_eq!(
            parse("http { upstream u { server nosuch.invalid:8080; } }"),
            "host not found in upstream \"nosuch.invalid:8080\""
        );
        assert_eq!(
            parse("http { server { location / { proxy_pass http://127.0.0.1:99999; } } }"),
            "invalid port in upstream \"127.0.0.1:99999\""
        );
    }
}
