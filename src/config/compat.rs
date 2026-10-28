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
    /// What to do about it: the section of `docs/migrating.md`.
    pub section: &'static str,
}

/// The migration guide, as of this version.
const GUIDE: &str = concat!(
    "https://github.com/gvozdetsky/ruxen/blob/v",
    env!("CARGO_PKG_VERSION"),
    "/docs/migrating.md"
);

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

fn record(lx: &Lexer, severity: Severity, args: &[String], note: String, section: &'static str) {
    let finding = Finding {
        severity,
        position: lx.position(),
        directive: args.join(" "),
        note,
        section,
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
    let mut section = "other-modules-and-unknown-directives";
    if let Some((module, s)) = missing_module(&args[0]) {
        note.push_str(&format!(" ({module} isn't in ruxen: README, Limitations)"));
        section = s;
    }
    record(lx, Severity::Unsupported, args, note, section);
    if matches!(term, Terminator::BlockOpen) {
        skip_block(lx)?;
    }
    Ok(())
}

/// The nginx module a directive ruxen doesn't know belongs to, for the
/// ones a configuration commonly has and ruxen doesn't implement, and its
/// section of the guide.
fn missing_module(name: &str) -> Option<(&'static str, &'static str)> {
    const UPSTREAMS: &str = "fastcgi-uwsgi-scgi-memcached";
    const OTHER: &str = "other-modules-and-unknown-directives";
    const PREFIXES: &[(&str, &str, &str)] = &[
        ("fastcgi_", "FastCGI", UPSTREAMS),
        ("uwsgi_", "uwsgi", UPSTREAMS),
        ("scgi_", "SCGI", UPSTREAMS),
        ("memcached_", "memcached", UPSTREAMS),
        ("grpc_", "gRPC proxying", "grpc_pass"),
        ("ssi_", "SSI", "ssi"),
        ("sub_filter", "sub_filter", "sub_filter"),
        ("geoip", "GeoIP", OTHER),
        ("perl", "embedded Perl", OTHER),
        ("js_", "njs", OTHER),
        ("image_filter", "image_filter", OTHER),
        ("xslt", "XSLT", OTHER),
        ("mp4", "MP4 streaming", OTHER),
        ("flv", "FLV streaming", OTHER),
        ("dav_", "WebDAV", OTHER),
        ("slice", "slice", OTHER),
        ("mirror", "mirror", OTHER),
        ("userid", "userid", OTHER),
        ("secure_link", "secure_link", OTHER),
    ];
    match name {
        "geo" => Some(("geo", OTHER)),
        "stream" => Some(("the stream module", "stream-and-mail")),
        "mail" => Some(("the mail module", "stream-and-mail")),
        "ssi" => Some(("SSI", "ssi")),
        _ if name.contains("_by_lua") || name.starts_with("lua_") => {
            Some(("Lua (OpenResty)", OTHER))
        }
        _ => PREFIXES
            .iter()
            .find(|(p, _, _)| name.starts_with(p))
            .map(|(_, m, s)| (*m, *s)),
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
    // `location $var` is the only one left (#596).
    record(lx, Severity::Unsupported, args, note, "location-var");
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
    record(
        lx,
        Severity::Unsupported,
        args,
        note,
        "an-include-that-cant-be-read",
    );
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
        "ssl_protocols",
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
    let (severity, note, section) = classify(args);
    record(lx, severity, args, note, section);
}

/// A block ruxen skips (`IGNORED_BLOCK`).
pub(crate) fn ignored_block(lx: &Lexer, args: &[String]) {
    if !collecting() {
        return;
    }
    // `events`: read by nginx only to size its connection table; ruxen
    // takes `worker_connections` from it.
    if args[0] == "events" {
        return;
    }
    record(
        lx,
        Severity::Ignored,
        args,
        "accepted, no effect in ruxen".to_string(),
        IGNORED,
    );
}

/// Ignored directives whose effect a user would notice: nginx's default
/// value (a directive set to it changes nothing), or `None` when any use
/// differs, what happens in ruxen instead, and the guide's section.
const DIFFERS: &[(&str, Option<&str>, &str, &str)] = &[
    // gzip works at http, server and location level, and in a location's
    // `if`; only in a server's `if` it is still accepted and ignored.
    (
        "gzip",
        Some("off"),
        "not applied inside `if`: set it in the location instead",
        "gzip-in-if",
    ),
    (
        "ssi",
        Some("off"),
        "server-side includes are not processed",
        "ssi",
    ),
    (
        "charset",
        None,
        "a charset from a variable is not supported yet: none is added to Content-Type",
        "charset-conversion",
    ),
    (
        "override_charset",
        Some("off"),
        "nothing is converted",
        "charset-conversion",
    ),
    (
        "source_charset",
        None,
        "nothing is converted: a response is labelled only when it is already in `charset`",
        "charset-conversion",
    ),
    (
        "chunked_transfer_encoding",
        Some("on"),
        "not applied at this level (ruxen reads it in server and location only)",
        "chunked_transfer_encoding",
    ),
    (
        "proxy_request_buffering",
        Some("on"),
        "request bodies are still read whole before they are proxied (#134)",
        "proxy_request_buffering-off",
    ),
    (
        "proxy_store",
        Some("off"),
        "proxied responses are not stored",
        "proxy_store",
    ),
    // The ssl_* lines the server parser takes and doesn't apply.
    (
        "ssl_early_data",
        Some("off"),
        "TLS 1.3 early data is not accepted",
        "ssl_early_data-on",
    ),
    (
        "ssl_conf_command",
        None,
        "OpenSSL commands are not applied: ruxen's TLS is rustls",
        "ssl_conf_command",
    ),
    ("http3", None, NO_HTTP3, "http3-and-quic"),
    ("http3_hq", None, NO_HTTP3, "http3-and-quic"),
    (
        "http3_max_concurrent_streams",
        None,
        NO_HTTP3,
        "http3-and-quic",
    ),
    ("http3_stream_buffer_size", None, NO_HTTP3, "http3-and-quic"),
    (
        "quic_active_connection_id_limit",
        None,
        NO_HTTP3,
        "http3-and-quic",
    ),
    ("quic_bpf", None, NO_HTTP3, "http3-and-quic"),
    ("quic_gso", None, NO_HTTP3, "http3-and-quic"),
    ("quic_host_key", None, NO_HTTP3, "http3-and-quic"),
    ("quic_retry", None, NO_HTTP3, "http3-and-quic"),
];

const NO_HTTP3: &str =
    "no HTTP/3 in ruxen: `quic` listens are ignored, the TCP listens serve HTTP/1.1 and HTTP/2";

/// The guide's section for the tuning directives ruxen accepts and ignores.
const IGNORED: &str = "ignored-tuning-directives";

fn classify(args: &[String]) -> (Severity, String, &'static str) {
    let name = args[0].as_str();
    let value = args[1..].join(" ");
    match DIFFERS.iter().find(|(d, ..)| *d == name) {
        Some((_, Some(default), ..)) if value == *default => (
            Severity::Ignored,
            "nginx's default value, accepted".to_string(),
            IGNORED,
        ),
        Some((_, _, note, section)) => (Severity::Differs, (*note).to_string(), section),
        None => (
            Severity::Ignored,
            "accepted, no effect in ruxen".to_string(),
            IGNORED,
        ),
    }
}

/// The guide's section for a parser or `prepare` warning, by how it
/// starts; `None` for the ones nginx gives as well.
fn warning_section(w: &str) -> Option<&'static str> {
    WARNING_SECTIONS
        .iter()
        .find(|(start, _)| w.starts_with(start))
        .map(|(_, section)| *section)
}

const WARNING_SECTIONS: &[(&str, &str)] = &[
    ("\"ssl_protocols\"", "ssl_protocols"),
    ("\"ssl_ciphers\"", "ssl_ciphers"),
    ("\"ssl_ecdh_curve\"", "ssl_ecdh_curve"),
    (
        "server with ssl_* directives",
        "tls-settings-in-a-server-without-tls",
    ),
    ("\"alias ", "alias-and-the-trailing-slash"),
    ("variable \"$", "variables-that-are-always-empty"),
    (QUIC_LISTEN_IGNORED, "http3-and-quic"),
    ("no TCP listen is left", "http3-and-quic"),
];

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
    // The guide's sections for what is listed, in order, once each.
    let mut sections: Vec<&'static str> = Vec::new();
    let mut see = |s: &'static str| {
        if !sections.contains(&s) {
            sections.push(s);
        }
    };
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
            see(f.section);
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
                if let Some(s) = warning_section(w) {
                    see(s);
                }
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
    let unsupported = findings
        .iter()
        .filter(|f| f.severity == Severity::Unsupported)
        .count();
    if fatal.is_some() || (unsupported == 0 && prepare_error.is_some()) {
        see("when-the-check-stops");
    }
    for s in &sections {
        out.push_str(&format!("what to do: {GUIDE}#{s}\n"));
    }
    if let Some(e) = fatal {
        out.push_str(&format!("error: {e}\n"));
        out.push_str("the check stopped here: ruxen does not start with this configuration\n");
        return out;
    }
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
        let (found, _) = findings("http { server { location $arg_x { return 403; } } }");
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].severity, Severity::Unsupported);
        assert_eq!(found[0].directive, "location $arg_x");
    }

    #[test]
    fn repeated_findings_are_one_line_and_modules_are_named() {
        let (found, _) = findings(
            "http { server { location ~ \\.php$ { fastcgi_param A a; fastcgi_param B b; \
             fastcgi_param C c; fastcgi_pass x; } } }",
        );
        let out = report(&found, &[], None, None);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 4, "{out}");
        assert!(
            lines[0].contains("unsupported: fastcgi_param A a — unknown directive")
                && lines[0].ends_with("(FastCGI isn't in ruxen: README, Limitations) (and 2 more `fastcgi_param` lines)"),
            "{out}"
        );
        assert!(lines[1].contains("unsupported: fastcgi_pass x"), "{out}");
        assert!(
            lines[3].starts_with("ruxen does not start with this configuration: 4 unsupported"),
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

    #[test]
    fn the_report_links_each_section_once() {
        let (found, _) = findings(
            "http { server { location / { proxy_request_buffering off; fastcgi_pass x; \
             uwsgi_pass y; } } }",
        );
        let out = report(
            &found,
            &["variable \"$date_gmt\" …".to_string()],
            None,
            None,
        );
        let links: Vec<&str> = out
            .lines()
            .filter_map(|l| l.strip_prefix("what to do: "))
            .collect();
        assert_eq!(
            links,
            [
                format!("{GUIDE}#fastcgi-uwsgi-scgi-memcached"),
                format!("{GUIDE}#proxy_request_buffering-off"),
                format!("{GUIDE}#variables-that-are-always-empty"),
            ],
            "{out}"
        );
        assert!(
            out.ends_with("2 unsupported, 2 behaving differently\n"),
            "{out}"
        );
    }

    /// Every section a finding can link to is a heading of the guide, by
    /// GitHub's anchor for it.
    #[test]
    fn every_section_is_in_the_guide() {
        let anchor = |heading: &str| -> String {
            heading
                .trim()
                .to_lowercase()
                .chars()
                .filter(|c| c.is_alphanumeric() || matches!(c, ' ' | '-' | '_'))
                .map(|c| if c == ' ' { '-' } else { c })
                .collect()
        };
        let headings: Vec<String> = include_str!("../../docs/migrating.md")
            .lines()
            .filter_map(|l| l.strip_prefix("## ").or_else(|| l.strip_prefix("### ")))
            .map(anchor)
            .collect();

        let mut sections: Vec<&str> = vec![IGNORED, "when-the-check-stops"];
        sections.extend(DIFFERS.iter().map(|d| d.3));
        sections.extend(WARNING_SECTIONS.iter().map(|w| w.1));
        // The other findings, as the parser records them.
        let (found, _) = findings(
            "http { ssl_protocols TLSv1; include /nonexistent/x.conf; server { \
             location $x { } \
             no_such_directive; fastcgi_pass a; grpc_pass b; sub_filter c d; ssi_value_length 9; \
             mirror /m; } } stream { } mail { }",
        );
        assert_eq!(found.len(), 11, "{found:?}");
        sections.extend(found.iter().map(|f| f.section));
        for s in sections {
            assert!(
                headings.iter().any(|h| h == s),
                "no section #{s} in docs/migrating.md"
            );
        }
    }
}
