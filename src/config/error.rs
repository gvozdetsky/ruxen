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
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::UnexpectedEof => write!(f, "unexpected end of config"),
            Error::UnterminatedString => write!(f, "unterminated quoted string"),
            Error::UnclosedBlock => write!(f, "unclosed block"),
            Error::UnexpectedToken(s) => write!(f, "unexpected token: {s}"),
            Error::UnknownDirective { name, ctx } => {
                write!(f, "unknown directive `{name}` in {ctx}")
            }
            Error::WrongTerminator { name, ctx } => {
                write!(f, "directive `{name}` in {ctx} has wrong terminator")
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
