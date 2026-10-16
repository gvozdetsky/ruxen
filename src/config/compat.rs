//! `ruxen --compat`: one pass over a whole nginx configuration that lists
//! everything ruxen doesn't do as nginx, with `file:line`, instead of
//! stopping at the first unknown directive (#278).
//!
//! While collecting, an unknown directive or an access restriction ruxen
//! can't enforce is recorded and skipped rather than returned as an error,
//! and every directive on the accept-and-ignore list is recorded. Any
//! other error still ends the parse. Outside `--compat` nothing is
//! collected and the parser behaves as before.

use std::cell::RefCell;

use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// ruxen refuses to start.
    Unsupported,
    /// ruxen starts, and does something other than nginx would.
    Differs,
    /// Accepted, no visible effect (a tuning knob).
    Ignored,
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub severity: Severity,
    /// `file:line`, or `command line` for `-g`.
    pub position: Option<String>,
    /// The directive as written, arguments included.
    pub directive: String,
    pub note: String,
}

thread_local! {
    static FINDINGS: RefCell<Option<Vec<Finding>>> = const { RefCell::new(None) };
}

/// Starts collecting for this thread's next parse.
pub fn begin() {
    FINDINGS.with(|f| *f.borrow_mut() = Some(Vec::new()));
}

/// Stops collecting and returns what was found, in configuration order.
pub fn finish() -> Vec<Finding> {
    FINDINGS.with(|f| f.borrow_mut().take()).unwrap_or_default()
}

fn collecting() -> bool {
    FINDINGS.with(|f| f.borrow().is_some())
}

fn record(lx: &Lexer, severity: Severity, args: &[String], note: String) {
    let finding = Finding {
        severity,
        position: lx.position(),
        directive: args.join(" "),
        note,
    };
    FINDINGS.with(|f| {
        if let Some(list) = f.borrow_mut().as_mut() {
            list.push(finding);
        }
    });
}

/// An unknown directive: an error, or, while collecting, a finding and the
/// directive skipped (with its whole block).
pub(crate) fn unknown(
    lx: &mut Lexer,
    args: &[String],
    term: &Terminator,
    ctx: &'static str,
) -> Result<(), Error> {
    if !collecting() {
        return Err(Error::UnknownDirective {
            name: args[0].clone(),
            ctx,
        });
    }
    record(
        lx,
        Severity::Unsupported,
        args,
        format!("unknown directive {}", super::error::in_block(ctx)),
    );
    if matches!(term, Terminator::BlockOpen) {
        skip_block(lx)?;
    }
    Ok(())
}

/// `reject_unenforced`'s error: while collecting, a finding, and the
/// directive goes on to its normal parse.
pub(crate) fn unenforced(lx: &Lexer, args: &[String], err: Error) -> Result<(), Error> {
    if !collecting() {
        return Err(err);
    }
    let note = match &err {
        Error::Unenforced { consequence, .. } => {
            format!("not enforced yet, so ruxen refuses it: {consequence}")
        }
        other => other.to_string(),
    };
    record(lx, Severity::Unsupported, args, note);
    Ok(())
}

/// An `include` that couldn't be read: an error, or, while collecting, a
/// finding (ruxen can't start with it either) and the check goes on
/// without the file.
pub(crate) fn include_failed(lx: &Lexer, args: &[String], err: Error) -> Result<(), Error> {
    if !collecting() {
        return Err(err);
    }
    let note = format!("{err}; the check goes on without it");
    record(lx, Severity::Unsupported, args, note);
    Ok(())
}

/// Values ruxen rejects where nginx starts, common enough in real
/// configurations that the check should go past them: while collecting,
/// a finding, and the directive goes on without the rejected part.
pub(crate) fn precheck(lx: &Lexer, args: &mut Vec<String>) {
    if !collecting() || args.first().map(String::as_str) != Some("ssl_protocols") {
        return;
    }
    // Every distribution's default nginx.conf lists TLSv1 and TLSv1.1.
    let old: Vec<String> = args[1..]
        .iter()
        .filter(|v| matches!(v.as_str(), "SSLv2" | "SSLv3" | "TLSv1" | "TLSv1.1"))
        .cloned()
        .collect();
    if old.is_empty() {
        return;
    }
    // With TLSv1.2 or TLSv1.3 left, the line loads and its `[warn]` says
    // the old names are ignored (#36).
    if old.len() + 1 < args.len() {
        return;
    }
    record(
        lx,
        Severity::Unsupported,
        args,
        format!(
            "{} rejected: ruxen speaks TLSv1.2 and TLSv1.3 only, and nothing else is listed",
            old.join(", ")
        ),
    );
    args.retain(|v| !old.contains(v));
    if args.len() == 1 {
        args.push("TLSv1.2".to_string());
    }
}

/// A directive from the accept-and-ignore list (`IGNORED_STMT`).
pub(crate) fn ignored(lx: &Lexer, args: &[String]) {
    if !collecting() {
        return;
    }
    let (severity, note) = classify(args);
    record(lx, severity, args, note);
}

/// A block ruxen skips (`IGNORED_BLOCK`).
pub(crate) fn ignored_block(lx: &Lexer, args: &[String]) {
    if !collecting() {
        return;
    }
    let (severity, note) = match args[0].as_str() {
        // Read by nginx only to size its connection table; ruxen takes
        // `worker_connections` from it.
        "events" => return,
        "types" => (
            Severity::Differs,
            "MIME types come from ruxen's built-in table, not from this block (#38)".to_string(),
        ),
        _ => (
            Severity::Ignored,
            "accepted, no effect in ruxen".to_string(),
        ),
    };
    record(lx, severity, args, note);
}

/// Ignored directives whose effect a user would notice: nginx's default
/// value (a directive set to it changes nothing), or `None` when any use
/// differs, and what happens in ruxen instead.
const DIFFERS: &[(&str, Option<&str>, &str)] = &[
    // gzip works at http, server and location level; only inside `if`
    // it is still accepted and ignored.
    (
        "gzip",
        Some("off"),
        "not applied inside `if`: set it in the location instead",
    ),
    (
        "gzip_static",
        Some("off"),
        "precompressed .gz files are not served (#93)",
    ),
    ("ssi", Some("off"), "server-side includes are not processed"),
    (
        "charset",
        Some("off"),
        "no charset is added to Content-Type, and nothing is converted",
    ),
    ("override_charset", Some("off"), "nothing is converted"),
    ("source_charset", None, "nothing is converted"),
    (
        "default_type",
        Some("text/plain"),
        "files of unknown types get ruxen's built-in default (#38)",
    ),
    (
        "absolute_redirect",
        Some("on"),
        "redirects ruxen makes are absolute URLs",
    ),
    (
        "server_name_in_redirect",
        Some("off"),
        "redirects use the request's Host, not the server_name",
    ),
    ("port_in_redirect", Some("on"), "redirects keep the port"),
    ("etag", Some("on"), "static responses still carry an ETag"),
    (
        "if_modified_since",
        Some("exact"),
        "If-Modified-Since is still compared exactly",
    ),
    (
        "chunked_transfer_encoding",
        Some("on"),
        "not applied at this level (ruxen reads it in location only)",
    ),
    (
        "proxy_buffering",
        Some("on"),
        "upstream responses are still buffered whole before they are sent (#88)",
    ),
    (
        "proxy_request_buffering",
        Some("on"),
        "request bodies are still read whole before they are proxied (#134)",
    ),
    (
        "proxy_cookie_domain",
        Some("off"),
        "Set-Cookie domains are not rewritten (#40)",
    ),
    (
        "proxy_cookie_path",
        Some("off"),
        "Set-Cookie paths are not rewritten (#40)",
    ),
    (
        "proxy_store",
        Some("off"),
        "proxied responses are not stored",
    ),
    (
        "resolver",
        None,
        "upstream names are resolved once at startup, not at run time (#133)",
    ),
];

fn classify(args: &[String]) -> (Severity, String) {
    let name = args[0].as_str();
    let value = args[1..].join(" ");
    match DIFFERS.iter().find(|(d, _, _)| *d == name) {
        Some((_, Some(default), _)) if value == *default => (
            Severity::Ignored,
            "nginx's default value, accepted".to_string(),
        ),
        Some((_, _, note)) => (Severity::Differs, (*note).to_string()),
        None => (
            Severity::Ignored,
            "accepted, no effect in ruxen".to_string(),
        ),
    }
}

/// The report for `ruxen --compat`: one line per finding that matters,
/// the tuning knobs summed up, and a verdict.
pub fn report(
    findings: &[Finding],
    warnings: &[String],
    fatal: Option<&str>,
    prepare_error: Option<&str>,
) -> String {
    let mut out = String::new();
    let line = |f: &Finding| {
        let at = f.position.as_deref().unwrap_or("-");
        let label = match f.severity {
            Severity::Unsupported => "unsupported",
            Severity::Differs => "differs",
            Severity::Ignored => "ignored",
        };
        format!("{at}: {label}: {} — {}\n", f.directive, f.note)
    };
    for severity in [Severity::Unsupported, Severity::Differs] {
        for f in findings.iter().filter(|f| f.severity == severity) {
            out.push_str(&line(f));
        }
        if severity == Severity::Differs {
            // `[warn]` lines from parsing (`ssl_ciphers`, …): accepted with
            // a difference ruxen already explains.
            for w in warnings {
                out.push_str(&format!("-: differs: {w}\n"));
            }
        }
    }
    let ignored: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.severity == Severity::Ignored)
        .collect();
    if !ignored.is_empty() {
        let mut names: Vec<&str> = ignored
            .iter()
            .map(|f| f.directive.split(' ').next().unwrap_or(""))
            .collect();
        names.sort_unstable();
        names.dedup();
        out.push_str(&format!(
            "ignored: {} tuning directive{} with no effect in ruxen: {}\n",
            ignored.len(),
            if ignored.len() == 1 { "" } else { "s" },
            names.join(", ")
        ));
    }
    if let Some(e) = fatal {
        out.push_str(&format!("error: {e}\n"));
        out.push_str("the check stopped here: ruxen does not start with this configuration\n");
        return out;
    }
    let unsupported = findings
        .iter()
        .filter(|f| f.severity == Severity::Unsupported)
        .count();
    let differs = findings
        .iter()
        .filter(|f| f.severity == Severity::Differs)
        .count()
        + warnings.len();
    if unsupported > 0 {
        out.push_str(&format!(
            "ruxen does not start with this configuration: {unsupported} unsupported, \
             {differs} behaving differently\n"
        ));
    } else if let Some(e) = prepare_error {
        out.push_str(&format!("error: {e}\n"));
        out.push_str(
            "ruxen reads this configuration, but does not start with it on this machine\n",
        );
    } else if differs > 0 {
        out.push_str(&format!(
            "ruxen starts with this configuration; {differs} directive{} behave{} differently \
             from nginx\n",
            if differs == 1 { "" } else { "s" },
            if differs == 1 { "s" } else { "" },
        ));
    } else {
        out.push_str(
            "ruxen starts with this configuration and nothing in it behaves differently\n",
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn findings(src: &str) -> (Vec<Finding>, Result<HttpConfig, Error>) {
        begin();
        let res = parse(src);
        (finish(), res)
    }

    #[test]
    fn collects_every_unknown_directive_and_skips_blocks() {
        let (found, res) = findings(
            "http { server { fastcgi_pass 127.0.0.1:9000; secure_link $arg_s; \
             location / { uwsgi_pass x; } } map_x { a b; } }",
        );
        let names: Vec<&str> = found.iter().map(|f| f.directive.as_str()).collect();
        assert_eq!(
            names,
            [
                "fastcgi_pass 127.0.0.1:9000",
                "secure_link $arg_s",
                "uwsgi_pass x",
                "map_x"
            ]
        );
        assert!(found.iter().all(|f| f.severity == Severity::Unsupported));
        assert!(res.is_ok(), "{res:?}");
    }

    #[test]
    fn a_block_not_allowed_in_if_is_skipped_once() {
        // The `return` after the skipped block stays in the `if` (#137).
        let (found, res) = findings(
            "http { server { location / { if ($arg_a) { location /x { } return 403; } \
             proxy_pass http://127.0.0.1:1; } } }",
        );
        let names: Vec<&str> = found.iter().map(|f| f.directive.as_str()).collect();
        assert_eq!(names, ["location /x"]);
        assert!(res.is_ok(), "{res:?}");
    }

    #[test]
    fn ignored_directives_differ_unless_set_to_the_default() {
        let (found, _) = findings(
            "http { ssi on; etag on; tcp_nopush on; types { text/html html; } server { } }",
        );
        let got: Vec<(Severity, &str)> = found
            .iter()
            .map(|f| (f.severity, f.directive.as_str()))
            .collect();
        assert_eq!(
            got,
            [
                (Severity::Differs, "ssi on"),
                (Severity::Ignored, "etag on"),
                (Severity::Ignored, "tcp_nopush on"),
                (Severity::Differs, "types"),
            ]
        );
    }

    #[test]
    fn unenforced_restrictions_are_unsupported() {
        let (found, _) = findings("http { server { ssl_verify_client on; } }");
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].severity, Severity::Unsupported);
        assert_eq!(found[0].directive, "ssl_verify_client on");
    }

    #[test]
    fn nothing_is_collected_outside_compat() {
        assert!(matches!(
            parse("http { server { fastcgi_pass x; } }"),
            Err(Error::UnknownDirective { .. })
        ));
        assert!(finish().is_empty());
    }
}
