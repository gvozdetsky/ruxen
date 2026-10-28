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
    let mut note = format!("unknown directive {}", super::error::in_block(ctx));
    if let Some(module) = missing_module(&args[0]) {
        note.push_str(&format!(" ({module} isn't in ruxen: README, Limitations)"));
    }
    record(lx, Severity::Unsupported, args, note);
    if matches!(term, Terminator::BlockOpen) {
        skip_block(lx)?;
    }
    Ok(())
}

/// The nginx module a directive ruxen doesn't know belongs to, for the
/// ones a configuration commonly has and ruxen doesn't implement.
fn missing_module(name: &str) -> Option<&'static str> {
    const PREFIXES: &[(&str, &str)] = &[
        ("fastcgi_", "FastCGI"),
        ("uwsgi_", "uwsgi"),
        ("scgi_", "SCGI"),
        ("memcached_", "memcached"),
        ("grpc_", "gRPC proxying"),
        ("ssi_", "SSI"),
        ("sub_filter", "sub_filter"),
        ("geoip", "GeoIP"),
        ("perl", "embedded Perl"),
        ("js_", "njs"),
        ("image_filter", "image_filter"),
        ("xslt", "XSLT"),
        ("mp4", "MP4 streaming"),
        ("flv", "FLV streaming"),
        ("dav_", "WebDAV"),
        ("slice", "slice"),
        ("mirror", "mirror"),
        ("userid", "userid"),
        ("secure_link", "secure_link"),
    ];
    match name {
        "geo" => Some("geo"),
        "stream" => Some("the stream module"),
        "mail" => Some("the mail module"),
        "ssi" => Some("SSI"),
        _ if name.contains("_by_lua") || name.starts_with("lua_") => Some("Lua (OpenResty)"),
        _ => PREFIXES
            .iter()
            .find(|(p, _)| name.starts_with(p))
            .map(|(_, m)| *m),
    }
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
    // Already a finding here: refused as unenforced (`ssl_verify_client
    // on`), which says more than "ignored".
    let directive = args.join(" ");
    let position = lx.position();
    let seen = FINDINGS.with(|f| {
        f.borrow().as_ref().is_some_and(|list| {
            list.last()
                .is_some_and(|last| last.position == position && last.directive == directive)
        })
    });
    if seen {
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
        None,
        "a charset from a variable is not supported yet: none is added to Content-Type",
    ),
    ("override_charset", Some("off"), "nothing is converted"),
    (
        "source_charset",
        None,
        "nothing is converted: a response is labelled only when it is already in `charset`",
    ),
    (
        "chunked_transfer_encoding",
        Some("on"),
        "not applied at this level (ruxen reads it in location only)",
    ),
    (
        "proxy_request_buffering",
        Some("on"),
        "request bodies are still read whole before they are proxied (#134)",
    ),
    (
        "proxy_store",
        Some("off"),
        "proxied responses are not stored",
    ),
    // The ssl_* lines the server parser takes and doesn't apply.
    (
        "ssl_early_data",
        Some("off"),
        "TLS 1.3 early data is not accepted",
    ),
    (
        "ssl_conf_command",
        None,
        "OpenSSL commands are not applied: ruxen's TLS is rustls",
    ),
    (
        "ssl_password_file",
        None,
        "encrypted private keys can't be loaded yet (#139)",
    ),
    (
        "ssl_verify_client",
        Some("off"),
        "client certificates are not requested yet (#113)",
    ),
    (
        "ssl_client_certificate",
        None,
        "client certificates are not requested yet (#113)",
    ),
    (
        "ssl_trusted_certificate",
        None,
        "client certificates are not requested yet (#113)",
    ),
    (
        "ssl_verify_depth",
        None,
        "client certificates are not requested yet (#113)",
    ),
    (
        "ssl_crl",
        None,
        "client certificates are not requested yet (#113)",
    ),
    (
        "http3",
        None,
        "no HTTP/3 in ruxen: `quic` listens are ignored, the TCP listens serve HTTP/1.1 and HTTP/2",
    ),
    (
        "http3_hq",
        None,
        "no HTTP/3 in ruxen: `quic` listens are ignored, the TCP listens serve HTTP/1.1 and HTTP/2",
    ),
    (
        "http3_max_concurrent_streams",
        None,
        "no HTTP/3 in ruxen: `quic` listens are ignored, the TCP listens serve HTTP/1.1 and HTTP/2",
    ),
    (
        "http3_stream_buffer_size",
        None,
        "no HTTP/3 in ruxen: `quic` listens are ignored, the TCP listens serve HTTP/1.1 and HTTP/2",
    ),
    (
        "quic_active_connection_id_limit",
        None,
        "no HTTP/3 in ruxen: `quic` listens are ignored, the TCP listens serve HTTP/1.1 and HTTP/2",
    ),
    (
        "quic_bpf",
        None,
        "no HTTP/3 in ruxen: `quic` listens are ignored, the TCP listens serve HTTP/1.1 and HTTP/2",
    ),
    (
        "quic_gso",
        None,
        "no HTTP/3 in ruxen: `quic` listens are ignored, the TCP listens serve HTTP/1.1 and HTTP/2",
    ),
    (
        "quic_host_key",
        None,
        "no HTTP/3 in ruxen: `quic` listens are ignored, the TCP listens serve HTTP/1.1 and HTTP/2",
    ),
    (
        "quic_retry",
        None,
        "no HTTP/3 in ruxen: `quic` listens are ignored, the TCP listens serve HTTP/1.1 and HTTP/2",
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

/// A warning's trailing ` in <file>:<line>`, split off: (text, place).
fn split_position(w: &str) -> Option<(&str, &str)> {
    let (text, at) = w.rsplit_once(" in ")?;
    let (_, line) = at.rsplit_once(':')?;
    (!line.is_empty() && line.bytes().all(|b| b.is_ascii_digit())).then_some((text, at))
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
        // A directive that comes back with the same note (`fastcgi_param`
        // from fastcgi_params, 20 lines and more) is one line, its first,
        // and how many more there are.
        let of_severity: Vec<&Finding> =
            findings.iter().filter(|f| f.severity == severity).collect();
        let name = |f: &Finding| f.directive.split(' ').next().unwrap_or("").to_string();
        let mut done = vec![false; of_severity.len()];
        for (i, f) in of_severity.iter().enumerate() {
            if done[i] {
                continue;
            }
            let mut more = 0;
            for (j, g) in of_severity.iter().enumerate().skip(i + 1) {
                if !done[j] && g.note == f.note && name(g) == name(f) {
                    done[j] = true;
                    more += 1;
                }
            }
            let mut text = line(f);
            if more > 0 {
                text.pop();
                text.push_str(&format!(
                    " (and {more} more `{}` line{})\n",
                    name(f),
                    if more == 1 { "" } else { "s" }
                ));
            }
            out.push_str(&text);
        }
        if severity == Severity::Differs {
            // `[warn]` lines from parsing (a `quic` listen, …): accepted
            // with a difference ruxen already explains; where the warning
            // ends with its place, the place goes first, as for findings.
            for w in warnings {
                out.push_str(&match split_position(w) {
                    Some((text, at)) => format!("{at}: differs: {text}\n"),
                    None => format!("-: differs: {w}\n"),
                });
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
            "http { ssi on; override_charset off; tcp_nopush on; types { text/html html; } server { } }",
        );
        let got: Vec<(Severity, &str)> = found
            .iter()
            .map(|f| (f.severity, f.directive.as_str()))
            .collect();
        assert_eq!(
            got,
            [
                (Severity::Differs, "ssi on"),
                (Severity::Ignored, "override_charset off"),
                (Severity::Ignored, "tcp_nopush on"),
            ]
        );
    }

    #[test]
    fn unenforced_restrictions_are_unsupported() {
        let (found, _) = findings("http { server { root /srv/$host; } }");
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].severity, Severity::Unsupported);
        assert_eq!(found[0].directive, "root /srv/$host");
    }

    #[test]
    fn repeated_findings_are_one_line_and_modules_are_named() {
        let (found, _) = findings(
            "http { server { location ~ \\.php$ { fastcgi_param A a; fastcgi_param B b; \
             fastcgi_param C c; fastcgi_pass x; } } }",
        );
        let out = report(&found, &[], None, None);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 3, "{out}");
        assert!(
            lines[0].contains("unsupported: fastcgi_param A a — unknown directive")
                && lines[0].ends_with("(FastCGI isn't in ruxen: README, Limitations) (and 2 more `fastcgi_param` lines)"),
            "{out}"
        );
        assert!(lines[1].contains("unsupported: fastcgi_pass x"), "{out}");
        assert!(
            lines[2].starts_with("ruxen does not start with this configuration: 4 unsupported"),
            "{out}"
        );
    }

    #[test]
    fn a_warning_with_its_place_starts_with_it() {
        let out = report(
            &[],
            &[
                "the listen is ignored in /etc/nginx/x.conf:12".to_string(),
                "no place here".to_string(),
            ],
            None,
            None,
        );
        assert!(
            out.starts_with("/etc/nginx/x.conf:12: differs: the listen is ignored\n"),
            "{out}"
        );
        assert!(out.contains("-: differs: no place here\n"), "{out}");
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
