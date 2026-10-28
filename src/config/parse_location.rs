//! `location { ... }` block parser plus the directives most often used
//! at location scope: `try_files`, `index`, `add_header`, `auth_basic`,
//! `error_page`, `autoindex_*`, `return`, `on/off` parsing, and the
//! `try_files` probe/fallback classifier.

use super::*;
use std::path::PathBuf;

/// Shared `return STATUS [body]` parser used at both server and location
/// scope. The body (if any) is tokenized into the same `ValuePart` form
/// used by `add_header`, `index`, and `error_page` so variable expansion
/// behaves identically.
pub(crate) fn parse_return_args(args: &[String]) -> Result<(u16, Vec<ValuePart>), Error> {
    let status_s = args.first().ok_or(Error::MissingArg("return status"))?;
    // `return URL;`: a lone argument that starts as a URL is a 302 to it
    // (ngx_http_rewrite_return, #16).
    if args.len() == 1
        && status_s.parse::<u16>().is_err()
        && ["http://", "https://", "$scheme"]
            .iter()
            .any(|p| status_s.starts_with(p))
    {
        let parts = parse_value_with_vars(status_s)?;
        reject_sent_http_parts(&parts, "return body ($sent_http_* unavailable)")?;
        return Ok((302, parts));
    }
    let status = status_s.parse::<u16>().map_err(|_| Error::BadValue {
        what: "return status",
        got: status_s.clone(),
    })?;
    let body = match args.get(1) {
        Some(s) => {
            let parts = parse_value_with_vars(s)?;
            reject_sent_http_parts(&parts, "return body ($sent_http_* unavailable)")?;
            parts
        }
        None => Vec::new(),
    };
    Ok((status, body))
}

pub(crate) fn parse_post_action_args(args: &[String]) -> Result<String, Error> {
    let target = args.first().ok_or(Error::MissingArg("post_action"))?;
    if args.len() != 1 {
        return Err(Error::BadValue {
            what: "post_action",
            got: args.join(" "),
        });
    }
    if target.is_empty() {
        return Err(Error::BadValue {
            what: "post_action",
            got: target.clone(),
        });
    }
    Ok(target.clone())
}

/// `disable_symlinks off|on|if_not_owner [from=part];`, validated as
/// nginx's ngx_http_disable_symlinks. `from=` takes `$document_root` or a
/// literal path; other variables are refused rather than ignored, since
/// ignoring them would allow symlinks nginx refuses.
pub(crate) fn parse_disable_symlinks_args(args: &[String]) -> Result<DisableSymlinks, Error> {
    let bad = |got: &str| Error::BadValue {
        what: "disable_symlinks",
        got: got.to_string(),
    };
    if args.is_empty() || args.len() > 2 {
        return Err(bad(&args.join(" ")));
    }
    let mut mode: Option<SymlinkMode> = None;
    let mut from: Option<SymlinkFrom> = None;
    for arg in args {
        let parsed = match arg.as_str() {
            "off" => SymlinkMode::Off,
            "on" => SymlinkMode::On,
            "if_not_owner" => SymlinkMode::NotOwner,
            other => {
                let Some(value) = other.strip_prefix("from=") else {
                    return Err(bad(other));
                };
                if from.is_some() {
                    return Err(bad(&args.join(" ")));
                }
                from = Some(if value == "$document_root" {
                    SymlinkFrom::DocumentRoot
                } else if value.contains('$') {
                    return Err(Error::BadValue {
                        what: "disable_symlinks from= (only $document_root or a literal path \
                               is supported)",
                        got: value.to_string(),
                    });
                } else {
                    SymlinkFrom::Path(PathBuf::from(value))
                });
                continue;
            }
        };
        if mode.is_some() {
            return Err(bad(&args.join(" ")));
        }
        mode = Some(parsed);
    }
    let Some(mode) = mode else {
        return Err(bad(&args.join(" ")));
    };
    if mode == SymlinkMode::Off && from.is_some() {
        return Err(bad(&args.join(" ")));
    }
    Ok(DisableSymlinks { mode, from })
}

/// Parse `expires` directive args (everything after the directive name).
///
/// Forms accepted (mirror `ngx_http_headers_expires`):
/// - `off` / `epoch` / `max`
/// - `[+|-]<duration>` (seconds when bare; nginx-style suffixes y/M/w/d/h/m/s)
/// - `modified <duration>`
/// - `@<time-of-day>` (e.g. `@15h30m33s`; max 24h)
/// - `$variable` / `modified $variable` — runtime-resolved
pub(crate) fn parse_expires_args(args: &[String]) -> Result<ExpiresDirective, Error> {
    let (modified, value) = match args.len() {
        1 => (false, args[0].as_str()),
        2 if args[0] == "modified" => (true, args[1].as_str()),
        _ => {
            return Err(Error::BadValue {
                what: "expires",
                got: args.join(" "),
            });
        }
    };
    let parts = parse_value_with_vars(value)?;
    let has_var = parts.iter().any(|p| matches!(p, ValuePart::Var(_)));
    if has_var {
        return Ok(if modified {
            ExpiresDirective::VariableModified(parts)
        } else {
            ExpiresDirective::Variable(parts)
        });
    }
    parse_expires_static(value, modified)
}

/// Parse the static (non-variable) form of an `expires` value. Shared by
/// the directive parser and the runtime evaluator that handles
/// `expires $var` after rendering.
pub(crate) fn parse_expires_static(value: &str, modified: bool) -> Result<ExpiresDirective, Error> {
    if !modified {
        match value {
            "epoch" => return Ok(ExpiresDirective::Epoch),
            "max" => return Ok(ExpiresDirective::Max),
            "off" => return Ok(ExpiresDirective::Off),
            _ => {}
        }
    }
    if let Some(rest) = value.strip_prefix('@') {
        if modified {
            return Err(Error::BadValue {
                what: "expires (daily time cannot be used with \"modified\")",
                got: value.to_string(),
            });
        }
        let secs = parse_expires_time(rest)?;
        if !(0..=24 * 60 * 60).contains(&secs) {
            return Err(Error::BadValue {
                what: "expires (daily time must be < 24h)",
                got: value.to_string(),
            });
        }
        return Ok(ExpiresDirective::Daily(secs as u32));
    }
    let (negative, num) = if let Some(s) = value.strip_prefix('+') {
        (false, s)
    } else if let Some(s) = value.strip_prefix('-') {
        (true, s)
    } else {
        (false, value)
    };
    let secs = parse_expires_time(num)?;
    let signed = if negative { -secs } else { secs };
    Ok(if modified {
        ExpiresDirective::Modified(signed)
    } else {
        ExpiresDirective::Access(signed)
    })
}

fn parse_expires_time(raw: &str) -> Result<i64, Error> {
    parse_time(raw, true).ok_or_else(|| Error::BadValue {
        what: "expires",
        got: raw.to_string(),
    })
}

/// Outcome of parsing the modifier+pattern that follow `location` and
/// precede `{`. `noregex` is meaningful only for `Prefix`; the parser sets
/// it for the `^~` form. Regex patterns are validated here so a malformed
/// regex fails `-t` rather than at first match.
pub(crate) struct LocationSpec {
    mode: MatchMode,
    pattern: String,
    noregex: bool,
}

/// Parse the arguments after `location` and before `{`:
///   location /foo      → Prefix("/foo")
///   location = /foo    → Exact("/foo")
///   location ^~ /foo   → Prefix("/foo") + noregex
///   location ~ ^re$    → Regex("^re$", case_sensitive)
///   location ~* ...    → Regex(..., case_insensitive)
///   location @named    → Named("@named")
pub(crate) fn parse_location_spec(args: &[String]) -> Result<LocationSpec, Error> {
    match args {
        [] => Err(Error::MissingArg("location pattern")),
        [single] => {
            // A modifier written against the pattern (`location ~\.php$`,
            // `location =/x`) is read off its front, as nginx's
            // `ngx_http_core_location` does with a single argument (#577).
            for modifier in ["=", "^~", "~*", "~"] {
                if let Some(pattern) = single.strip_prefix(modifier) {
                    return parse_location_spec(&[modifier.to_string(), pattern.to_string()]);
                }
            }
            if single.starts_with('@') {
                if single.len() == 1 {
                    return Err(Error::BadValue {
                        what: "named location",
                        got: single.clone(),
                    });
                }
                return Ok(LocationSpec {
                    mode: MatchMode::Named,
                    pattern: single.clone(),
                    noregex: false,
                });
            }
            Ok(LocationSpec {
                mode: MatchMode::Prefix,
                pattern: single.clone(),
                noregex: false,
            })
        }
        [modifier, pattern] => match modifier.as_str() {
            "=" => Ok(LocationSpec {
                mode: MatchMode::Exact,
                pattern: pattern.clone(),
                noregex: false,
            }),
            "^~" => Ok(LocationSpec {
                mode: MatchMode::Prefix,
                pattern: pattern.clone(),
                noregex: true,
            }),
            "~" | "~*" => {
                let case_insensitive = modifier == "~*";
                validate_regex(pattern, case_insensitive)?;
                Ok(LocationSpec {
                    mode: MatchMode::Regex { case_insensitive },
                    pattern: pattern.clone(),
                    noregex: false,
                })
            }
            other => Err(Error::UnsupportedLocationModifier(other.into())),
        },
        _ => Err(Error::UnexpectedToken(args[2].clone())),
    }
}

/// Compile-test a regex at parse time so `-t` catches bad patterns before
/// the server starts taking traffic. The compiled regex is recreated at
/// prepare time; storing it here would force `Location` to be non-`Debug`-
/// friendly and bloat the parser surface.
///
/// Uses `regex::bytes::RegexBuilder`: nginx matches PCRE against
/// `r->uri.data` as raw bytes, and our normalized path is also a `Vec<u8>`
/// (percent-decoding can produce arbitrary octets). Compiling here with
/// the same builder used in `prepare` keeps validation and runtime in sync.
pub(crate) fn validate_regex(pattern: &str, case_insensitive: bool) -> Result<(), Error> {
    regex::bytes::RegexBuilder::new(pattern)
        .case_insensitive(case_insensitive)
        .build()
        .map(|_| ())
        .map_err(|e| Error::InvalidRegex {
            pattern: pattern.to_string(),
            msg: e.to_string(),
        })
}

/// `parent`'s place in a descendant's `header_ancestors`: its own chain,
/// then its own lists (#598).
fn header_chain(parent: &Location) -> Vec<HeaderLevel> {
    let mut chain = parent.header_ancestors.clone();
    chain.push(HeaderLevel {
        headers: parent.add_headers.clone(),
        trailers: parent.add_trailers.clone(),
        headers_inherit: parent.add_header_inherit,
        trailers_inherit: parent.add_trailer_inherit,
    });
    chain
}

/// What a nested location takes from its parent where it sets nothing
/// itself (#106), as nginx's `merge_loc_conf` of each module: a list
/// directive (`add_header`, `error_page`, `proxy_set_header`, …) comes as a
/// whole. The content handler, rewrites, `try_files`, `internal` and
/// `limit_except` belong to the location itself.
fn inherit_from_parent(child: &mut Location, parent: &Location) {
    fn or<T: Clone>(child: &mut Option<T>, parent: &Option<T>) {
        if child.is_none() {
            child.clone_from(parent);
        }
    }
    or(&mut child.index, &parent.index);
    child.redirect = child.redirect.inherit(&parent.redirect);
    child.mime.inherit(&parent.mime);
    // add_header / add_trailer: the parent's own lists and modes go in
    // front of the chain the server's are merged over (#598,
    // `merge_add_headers`). In front: a nested location's own children
    // closed first, and joined the chain then.
    let mut chain = header_chain(parent);
    chain.append(&mut child.header_ancestors);
    child.header_ancestors = chain;
    child.charset.inherit(&parent.charset);
    or(&mut child.error_pages, &parent.error_pages);
    or(&mut child.keepalive_timeout, &parent.keepalive_timeout);
    or(&mut child.keepalive_requests, &parent.keepalive_requests);
    or(&mut child.keepalive_time_ms, &parent.keepalive_time_ms);
    or(&mut child.keepalive_disable, &parent.keepalive_disable);
    or(&mut child.error_logs, &parent.error_logs);
    or(&mut child.log_not_found, &parent.log_not_found);
    or(&mut child.open_log_file_cache, &parent.open_log_file_cache);
    or(
        &mut child.recursive_error_pages,
        &parent.recursive_error_pages,
    );
    or(&mut child.server_tokens, &parent.server_tokens);
    or(&mut child.autoindex, &parent.autoindex);
    or(
        &mut child.autoindex_exact_size,
        &parent.autoindex_exact_size,
    );
    or(&mut child.autoindex_localtime, &parent.autoindex_localtime);
    or(&mut child.autoindex_format, &parent.autoindex_format);
    or(&mut child.if_modified_since, &parent.if_modified_since);
    or(&mut child.etag, &parent.etag);
    or(&mut child.access_logs, &parent.access_logs);
    or(&mut child.auth_basic, &parent.auth_basic);
    or(
        &mut child.auth_basic_user_file,
        &parent.auth_basic_user_file,
    );
    or(&mut child.auth_delay_ms, &parent.auth_delay_ms);
    or(
        &mut child.client_max_body_size,
        &parent.client_max_body_size,
    );
    or(&mut child.max_ranges, &parent.max_ranges);
    or(
        &mut child.client_body_buffer_size,
        &parent.client_body_buffer_size,
    );
    or(&mut child.sendfile, &parent.sendfile);
    or(
        &mut child.client_body_temp_path,
        &parent.client_body_temp_path,
    );
    or(&mut child.disable_symlinks, &parent.disable_symlinks);
    or(&mut child.limit_rate, &parent.limit_rate);
    or(&mut child.limit_rate_after, &parent.limit_rate_after);
    or(
        &mut child.client_body_in_file_only,
        &parent.client_body_in_file_only,
    );
    or(&mut child.post_action, &parent.post_action);
    or(&mut child.expires, &parent.expires);
    or(
        &mut child.chunked_transfer_encoding,
        &parent.chunked_transfer_encoding,
    );
    child.access = child.access.inherit(&parent.access);
    child.proxy = std::mem::take(&mut child.proxy).inherit(&parent.proxy);
    child.gzip = std::mem::take(&mut child.gzip).inherit(&parent.gzip);
    child.limit_req = std::mem::take(&mut child.limit_req).inherit(&parent.limit_req);
    child.limit_conn = std::mem::take(&mut child.limit_conn).inherit(&parent.limit_conn);
    child.client_timeouts = child.client_timeouts.inherit(parent.client_timeouts);
    // Its `if` blocks' anonymous locations, merged with it before it had
    // the parent's settings, get them too (an unset field takes them).
    if has_if_locations(&child.rewrite_ops) {
        let snapshot = child.clone();
        merge_if_locations(&mut child.rewrite_ops, &snapshot);
    }
}

/// Whether `ops` has an `if` block with an anonymous location (#137), at
/// the top: nested ones are inside one that has.
fn has_if_locations(ops: &[RewriteOp]) -> bool {
    ops.iter().any(|op| {
        matches!(
            op,
            RewriteOp::If {
                location: Some(_),
                ..
            }
        )
    })
}

/// What `parse_location_block` found in an `if` block's body.
#[derive(Default)]
pub(crate) struct IfBody {
    /// Something besides rewrite directives: the block is an anonymous
    /// location (#137).
    settings: bool,
    /// `proxy_pass` of its own.
    own_handler: bool,
    /// `root` of its own.
    own_root: bool,
}

/// A location-level `if (…) { … }` (#137): its rewrite directives, and,
/// when the block sets anything else, the anonymous location the request
/// switches to when the condition holds, as nginx's `ngx_http_rewrite_if`
/// parses the block with location context.
fn parse_location_if(args: &[String], lx: &mut Lexer) -> Result<RewriteOp, Error> {
    let guard = parse_if_guard(args)?;
    let mut sink = Vec::with_capacity(1);
    let mut info = IfBody::default();
    let spec = LocationSpec {
        mode: MatchMode::Prefix,
        pattern: String::new(),
        noregex: false,
    };
    parse_location_block(spec, lx, Inherited::default(), &mut sink, Some(&mut info))?;
    let mut location = sink.pop().expect("an if block makes one location");
    let body = std::mem::take(&mut location.rewrite_ops);
    let location = info.settings.then(|| IfLocation::Parsed {
        location: Box::new(location),
        own_handler: info.own_handler,
        own_root: info.own_root,
    });
    Ok(RewriteOp::If {
        guard,
        body,
        location,
    })
}

/// Give the anonymous locations of `ops`' `if` blocks what they inherit
/// from `parent` (nested ones from their enclosing block): everything
/// `inherit_from_parent` passes on, the parent's root unless the block
/// sets `root`, and the parent's content handler unless the block has a
/// `proxy_pass`, or a `root` for what would be a static handler: nginx
/// keeps the location's handler when the `if` configuration sets none
/// (`ngx_http_update_location_config`). The parent's own `return` runs
/// after the `if` in the same code array, so it is the handler whatever
/// the block sets. With a `proxy_pass` of its own, the pattern starts with
/// `@`: like a named location, there is no location prefix for a
/// `proxy_pass` URI to replace (nginx: "cannot have URI part … inside
/// "if" statement").
fn merge_if_locations(ops: &mut [RewriteOp], parent: &Location) {
    for op in ops {
        let RewriteOp::If { body, location, .. } = op else {
            continue;
        };
        match location {
            Some(IfLocation::Parsed {
                location,
                own_handler,
                own_root,
            }) => {
                inherit_from_parent(location, parent);
                // Set, not prepended: this runs again each time an
                // enclosing location closes, from the parent's chain as
                // it then is (#598).
                location.header_ancestors = header_chain(parent);
                location.mode = parent.mode;
                if !*own_root {
                    location.document_root = parent.document_root.clone();
                    location.alias_prefix_override = parent.alias_prefix_override.clone();
                    location.inherits_root = parent.inherits_root;
                }
                let static_parent = !matches!(
                    parent.handler,
                    Handler::Proxy(_) | Handler::StubStatus | Handler::Metrics
                );
                let keeps_own =
                    !parent.explicit_return && (*own_handler || (*own_root && static_parent));
                if keeps_own && *own_handler {
                    location.pattern = format!("@if:{}", parent.pattern);
                } else {
                    location.pattern = parent.pattern.clone();
                }
                if !keeps_own {
                    location.handler = parent.handler.clone();
                    location.explicit_return = parent.explicit_return;
                }
                let snapshot = (**location).clone();
                merge_if_locations(body, &snapshot);
            }
            _ => merge_if_locations(body, parent),
        }
    }
}

/// What a nested location inherits from the enclosing one while it is
/// parsed. Top-level and `if` locations start from `Inherited::default()`.
#[derive(Default)]
pub(crate) struct Inherited {
    pub(crate) root: Option<PathBuf>,
    pub(crate) alias: Option<(PathBuf, String)>,
    pub(crate) server_tokens: Option<ServerTokens>,
    pub(crate) autoindex: Option<bool>,
    pub(crate) autoindex_exact_size: Option<bool>,
    pub(crate) autoindex_localtime: Option<bool>,
    pub(crate) autoindex_format: Option<AutoindexFormat>,
    pub(crate) if_modified_since: Option<IfModifiedSince>,
    pub(crate) etag: Option<bool>,
    pub(crate) auth_basic: Option<AuthBasic>,
    pub(crate) auth_basic_user_file: Option<PathBuf>,
    pub(crate) auth_delay_ms: Option<u64>,
    pub(crate) access: AccessConf,
    pub(crate) client_max_body_size: Option<u64>,
    pub(crate) client_body_buffer_size: Option<u64>,
    pub(crate) post_action: Option<String>,
    pub(crate) expires: Option<ExpiresDirective>,
    pub(crate) sendfile: Option<bool>,
    pub(crate) client_body_temp_path: Option<TempPath>,
    pub(crate) disable_symlinks: Option<DisableSymlinks>,
}

/// Parse one `location {}` block and push the resulting `Location` into
/// `sink`. Nested `location` blocks inside this one get flattened into the
/// same sink — nginx's own matcher (`ngx_http_core_find_static_location`)
/// descends into children only after the parent prefix matches, but since
/// all sibling/child patterns live in the same absolute URI space, a
/// flattened peer list + longest-prefix win produces the same routing
/// decision for the cases our tests exercise. The parent's settings reach
/// them through `inherit_from_parent` when the parent's block ends (#106).
pub(crate) fn parse_location_block(
    spec: LocationSpec,
    lx: &mut Lexer,
    inherited: Inherited,
    sink: &mut Vec<Location>,
    mut if_body: Option<&mut IfBody>,
) -> Result<(), Error> {
    let mut ret: Option<(u16, Vec<ValuePart>)> = None;
    let mut rewrite_ops: Vec<RewriteOp> = Vec::new();
    // An inherited alias from a prefix-alias ancestor outranks the
    // server-scope `root` for unset child locations: nginx's
    // `merge_loc_conf` does the same (alias replaces root from the parent
    // chain). Track the prefix so the worker can still strip the
    // ancestor's location prefix even when this child is a regex.
    let mut alias_prefix_override: Option<String> = None;
    let mut root = if let Some((path, prefix)) = inherited.alias.clone() {
        alias_prefix_override = Some(prefix);
        Some((path, PathMapping::Alias))
    } else {
        inherited.root.clone().map(|path| (path, PathMapping::Root))
    };
    let mut local_path_mapping: Option<PathMapping> = None;
    let mut index: Option<Vec<IndexEntry>> = None;
    let mut try_files: Option<TryFiles> = None;
    let mut add_headers: Option<Vec<AddHeader>> = None;
    let mut add_trailers: Option<Vec<AddHeader>> = None;
    let mut add_header_inherit: Option<HeaderInherit> = None;
    let mut add_trailer_inherit: Option<HeaderInherit> = None;
    let mut error_pages: Option<Vec<ErrorPage>> = None;
    let mut keepalive_timeout: Option<KeepaliveTimeout> = None;
    let mut keepalive_requests: Option<u64> = None;
    let mut keepalive_time_ms: Option<u64> = None;
    let mut keepalive_disable: Option<KeepaliveDisable> = None;
    let mut error_logs: Option<Vec<ErrorLog>> = None;
    let mut log_not_found: Option<bool> = None;
    let mut recursive_error_pages: Option<bool> = None;
    let mut internal = false;
    let mut server_tokens: Option<ServerTokens> = None;
    let mut autoindex: Option<bool> = None;
    let mut autoindex_exact_size: Option<bool> = None;
    let mut autoindex_localtime: Option<bool> = None;
    let mut autoindex_format: Option<AutoindexFormat> = None;
    let mut if_modified_since: Option<IfModifiedSince> = None;
    let mut etag: Option<bool> = None;
    let mut access_logs: Option<Vec<AccessLog>> = None;
    let mut open_log_file_cache: Option<Option<OpenLogFileCache>> = None;
    let mut auth_basic: Option<AuthBasic> = None;
    let mut auth_basic_user_file: Option<PathBuf> = None;
    let mut auth_delay_ms: Option<u64> = None;
    let mut access = AccessConf::default();
    let mut limit_except: Option<LimitExcept> = None;
    let mut client_max_body_size: Option<u64> = None;
    let mut max_ranges: Option<u32> = None;
    let mut client_body_buffer_size: Option<u64> = None;
    let mut client_body_in_file_only: Option<ClientBodyInFileOnly> = None;
    let mut post_action: Option<String> = None;
    let mut expires: Option<ExpiresDirective> = None;
    let mut proxy_pass: Option<ProxyPass> = None;
    let mut stub_status = false;
    let mut metrics = false;
    let mut proxy = ProxyConf::default();
    let mut gzip = GzipConf::default();
    let mut limit_req = LimitReqConf::default();
    let mut limit_conn = LimitConnConf::default();
    let mut chunked_transfer_encoding: Option<bool> = None;
    let mut redirect = RedirectConf::default();
    let mut mime = MimeConf::default();
    let mut charset = CharsetConf::default();
    let mut sendfile: Option<bool> = None;
    let mut client_body_temp_path: Option<TempPath> = None;
    let mut disable_symlinks: Option<DisableSymlinks> = None;
    let mut limit_rate: Option<Vec<ValuePart>> = None;
    let mut client_timeouts = ClientTimeouts::default();
    let mut limit_rate_after: Option<Vec<ValuePart>> = None;
    // Children parsed inside this block — appended to `sink` after the
    // parent so the parent's entry appears first in declaration order.
    let mut children: Vec<Location> = Vec::new();

    loop {
        let (args, term) = lx.read_directive()?;
        if let (Some(info), Some(name)) = (if_body.as_deref_mut(), args.first()) {
            match name.as_str() {
                "set" | "rewrite" | "break" | "return" | "if" => {}
                // What nginx allows in an `if` in a location
                // (`NGX_HTTP_LIF_CONF`) and ruxen implements.
                "proxy_pass"
                | "root"
                | "add_header"
                | "add_trailer"
                | "add_header_inherit"
                | "add_trailer_inherit"
                | "error_page"
                | "charset"
                | "source_charset"
                | "access_log"
                | "expires"
                | "gzip"
                | "limit_rate"
                | "limit_rate_after"
                | "post_action"
                | "sendfile" => info.settings = true,
                // Accepted and ignored anywhere, as they were in `if`.
                n if term == Terminator::Semi && is_ignored_stmt(n) => {
                    check_ignored_args(lx, &args)?;
                    continue;
                }
                // nginx: "… directive is not allowed here". While
                // collecting, `unknown` skips a block itself.
                _ => {
                    compat::unknown(lx, &args, &term, "if")?;
                    continue;
                }
            }
        }
        if args.is_empty() {
            return match term {
                Terminator::BlockClose => {
                    if let Some(info) = if_body.as_deref_mut() {
                        info.own_handler = proxy_pass.is_some();
                        info.own_root = local_path_mapping.is_some();
                    }
                    // `return` short-circuits the rewrite phase in nginx, so
                    // it wins over `root` / `alias` / `proxy_pass` if both
                    // are set. `proxy_pass` wins over `root`/`alias`
                    // (you can't have both in nginx — content phase
                    // dispatch is single-handler).
                    let inherits_root = local_path_mapping.is_none() && inherited.alias.is_none();
                    let document_root = root
                        .clone()
                        .unwrap_or_else(|| (PathBuf::from("html"), PathMapping::Root));
                    let explicit_return = ret.is_some();
                    let handler = if let Some((status, body)) = ret {
                        Handler::Return { status, body }
                    } else if stub_status {
                        Handler::StubStatus
                    } else if metrics {
                        Handler::Metrics
                    } else if let Some(pp) = proxy_pass {
                        Handler::Proxy(pp)
                    } else if let Some((path, mapping)) = root {
                        Handler::Root { path, mapping }
                    } else {
                        // nginx's default `root`: `html` under the prefix
                        // (ruxen's working directory, set by `-p`), or the
                        // server's, set below the location
                        // (`inherits_root`). Rewrite directives don't change
                        // the static handler (#364).
                        Handler::Root {
                            path: PathBuf::from("html"),
                            mapping: PathMapping::Root,
                        }
                    };
                    // Propagate parent-location `server_tokens` into this
                    // location when this block didn't set its own — mirrors
                    // nginx's `merge_loc_conf` chain. The flat
                    // `Vec<Location>` AST doesn't carry the parent link, so
                    // we collapse the inheritance at parse time.
                    let effective_server_tokens = server_tokens.or(inherited.server_tokens);
                    let effective_autoindex = autoindex.or(inherited.autoindex);
                    let effective_autoindex_exact_size =
                        autoindex_exact_size.or(inherited.autoindex_exact_size);
                    let effective_autoindex_localtime =
                        autoindex_localtime.or(inherited.autoindex_localtime);
                    let effective_autoindex_format =
                        autoindex_format.or(inherited.autoindex_format);
                    let effective_if_modified_since =
                        if_modified_since.or(inherited.if_modified_since);
                    let effective_etag = etag.or(inherited.etag);
                    let effective_auth_basic = auth_basic.or(inherited.auth_basic);
                    let effective_auth_basic_user_file =
                        auth_basic_user_file.or(inherited.auth_basic_user_file);
                    let effective_auth_delay_ms = auth_delay_ms.or(inherited.auth_delay_ms);
                    let effective_access = access.inherit(&inherited.access);
                    let effective_client_max_body_size =
                        client_max_body_size.or(inherited.client_max_body_size);
                    let effective_client_body_buffer_size =
                        client_body_buffer_size.or(inherited.client_body_buffer_size);
                    let effective_post_action = post_action.or(inherited.post_action);
                    let effective_expires = expires.or(inherited.expires);
                    let effective_sendfile = sendfile.or(inherited.sendfile);
                    let effective_client_body_temp_path = client_body_temp_path
                        .clone()
                        .or_else(|| inherited.client_body_temp_path.clone());
                    let effective_disable_symlinks = disable_symlinks
                        .clone()
                        .or_else(|| inherited.disable_symlinks.clone());
                    let location = Location {
                        mode: spec.mode,
                        pattern: spec.pattern,
                        noregex: spec.noregex,
                        rewrite_ops,
                        handler,
                        index,
                        try_files,
                        add_headers,
                        add_trailers,
                        add_header_inherit,
                        add_trailer_inherit,
                        header_ancestors: Vec::new(),
                        error_pages,
                        keepalive_timeout,
                        keepalive_requests,
                        keepalive_time_ms,
                        keepalive_disable,
                        error_logs,
                        log_not_found,
                        open_log_file_cache,
                        recursive_error_pages,
                        internal,
                        server_tokens: effective_server_tokens,
                        autoindex: effective_autoindex,
                        autoindex_exact_size: effective_autoindex_exact_size,
                        autoindex_localtime: effective_autoindex_localtime,
                        autoindex_format: effective_autoindex_format,
                        if_modified_since: effective_if_modified_since,
                        etag: effective_etag,
                        access_logs,
                        auth_basic: effective_auth_basic,
                        auth_basic_user_file: effective_auth_basic_user_file,
                        auth_delay_ms: effective_auth_delay_ms,
                        access: effective_access,
                        limit_except,
                        client_max_body_size: effective_client_max_body_size,
                        max_ranges,
                        client_body_buffer_size: effective_client_body_buffer_size,
                        sendfile: effective_sendfile,
                        document_root,
                        client_body_temp_path: effective_client_body_temp_path,
                        disable_symlinks: effective_disable_symlinks,
                        limit_rate: limit_rate.clone(),
                        limit_rate_after: limit_rate_after.clone(),
                        client_body_in_file_only,
                        post_action: effective_post_action,
                        expires: effective_expires,
                        proxy,
                        gzip,
                        limit_req,
                        limit_conn,
                        chunked_transfer_encoding,
                        redirect,
                        mime,
                        charset,
                        client_timeouts,
                        alias_prefix_override,
                        inherits_root,
                        explicit_return,
                        descendants: 0,
                    };
                    // The anonymous locations of its `if` blocks (#137).
                    let mut location = location;
                    if if_body.is_none() && has_if_locations(&location.rewrite_ops) {
                        let snapshot = location.clone();
                        merge_if_locations(&mut location.rewrite_ops, &snapshot);
                    }
                    // nginx merges each nested location with its parent's
                    // final configuration (ngx_http_merge_locations), so a
                    // directive after the nested block counts too. The
                    // children already hold their own descendants' merge.
                    for child in &mut children {
                        inherit_from_parent(child, &location);
                    }
                    location.descendants = children.len();
                    sink.push(location);
                    sink.extend(children);
                    Ok(())
                }
                Terminator::Eof => Err(Error::UnclosedBlock),
                _ => Err(Error::UnexpectedEof),
            };
        }
        match (args[0].as_str(), &term) {
            ("types", Terminator::BlockOpen) | ("default_type", Terminator::Semi) => {
                parse_mime(lx, &args, &term, &mut mime)?;
            }
            ("charset" | "charset_types" | "source_charset", Terminator::Semi) => {
                parse_charset(lx, &args, &term, &mut charset)?;
            }
            ("set", Terminator::Semi) => {
                rewrite_ops.push(parse_set_op(&args[1..])?);
            }
            ("rewrite", Terminator::Semi) => {
                rewrite_ops.push(parse_rewrite_op(&args[1..])?);
            }
            ("break", Terminator::Semi) => {
                if args.len() != 1 {
                    return Err(Error::BadValue {
                        what: "break",
                        got: args[1..].join(" "),
                    });
                }
                rewrite_ops.push(RewriteOp::Break);
            }
            ("if", Terminator::BlockOpen) => {
                rewrite_ops.push(parse_location_if(&args[1..], lx)?);
            }
            // In an `if` block, `return` is one of its rewrite directives.
            ("return", Terminator::Semi) if if_body.is_some() => {
                let (status, body) = parse_return_args(&args[1..])?;
                rewrite_ops.push(RewriteOp::Return { status, body });
            }
            ("return", Terminator::Semi) => {
                if ret.is_some() {
                    return Err(Error::Duplicate("return"));
                }
                ret = Some(parse_return_args(&args[1..])?);
            }
            ("add_header", Terminator::Semi) => {
                let entry = parse_add_header_args(&args[1..])?;
                add_headers.get_or_insert_with(Vec::new).push(entry);
            }
            ("add_trailer", Terminator::Semi) => {
                let entry = parse_add_header_args(&args[1..])?;
                add_trailers.get_or_insert_with(Vec::new).push(entry);
            }
            ("add_header_inherit", Terminator::Semi) => {
                parse_header_inherit(&mut add_header_inherit, &args)?;
            }
            ("add_trailer_inherit", Terminator::Semi) => {
                parse_header_inherit(&mut add_trailer_inherit, &args)?;
            }
            ("error_page", Terminator::Semi) => {
                let entries = parse_error_page_args(&args[1..])?;
                error_pages.get_or_insert_with(Vec::new).extend(entries);
            }
            ("keepalive_timeout", Terminator::Semi) => {
                if keepalive_timeout.is_some() {
                    return Err(Error::Duplicate("keepalive_timeout"));
                }
                keepalive_timeout = Some(parse_keepalive_timeout_args(&args[1..])?);
            }
            ("keepalive_requests", Terminator::Semi) => {
                if keepalive_requests.is_some() {
                    return Err(Error::Duplicate("keepalive_requests"));
                }
                keepalive_requests = Some(parse_keepalive_requests_args(&args[1..])?);
            }
            ("keepalive_time", Terminator::Semi) => {
                if keepalive_time_ms.is_some() {
                    return Err(Error::Duplicate("keepalive_time"));
                }
                keepalive_time_ms = Some(parse_keepalive_time_args(&args[1..])?);
            }
            ("keepalive_disable", Terminator::Semi) => {
                if keepalive_disable.is_some() {
                    return Err(Error::Duplicate("keepalive_disable"));
                }
                keepalive_disable = Some(parse_keepalive_disable_args(&args[1..])?);
            }
            ("error_log", Terminator::Semi) => {
                error_logs
                    .get_or_insert_with(Vec::new)
                    .push(parse_error_log_args(&args[1..])?);
            }
            ("internal", Terminator::Semi) => {
                if args.len() != 1 {
                    return Err(Error::BadValue {
                        what: "internal",
                        got: args[1..].join(" "),
                    });
                }
                internal = true;
            }
            ("recursive_error_pages", Terminator::Semi) => {
                if recursive_error_pages.is_some() {
                    return Err(Error::Duplicate("recursive_error_pages"));
                }
                recursive_error_pages =
                    Some(parse_on_off_args(&args[1..], "recursive_error_pages")?);
            }
            ("log_not_found", Terminator::Semi) => {
                if log_not_found.is_some() {
                    return Err(Error::Duplicate("log_not_found"));
                }
                log_not_found = Some(parse_log_not_found_args(&args[1..])?);
            }
            ("server_tokens", Terminator::Semi) => {
                if server_tokens.is_some() {
                    return Err(Error::Duplicate("server_tokens"));
                }
                server_tokens = Some(parse_server_tokens_args(&args[1..])?);
            }
            ("autoindex", Terminator::Semi) => {
                if autoindex.is_some() {
                    return Err(Error::Duplicate("autoindex"));
                }
                autoindex = Some(parse_on_off_args(&args[1..], "autoindex")?);
            }
            ("autoindex_exact_size", Terminator::Semi) => {
                if autoindex_exact_size.is_some() {
                    return Err(Error::Duplicate("autoindex_exact_size"));
                }
                autoindex_exact_size = Some(parse_on_off_args(&args[1..], "autoindex_exact_size")?);
            }
            ("autoindex_localtime", Terminator::Semi) => {
                if autoindex_localtime.is_some() {
                    return Err(Error::Duplicate("autoindex_localtime"));
                }
                autoindex_localtime = Some(parse_on_off_args(&args[1..], "autoindex_localtime")?);
            }
            ("autoindex_format", Terminator::Semi) => {
                if autoindex_format.is_some() {
                    return Err(Error::Duplicate("autoindex_format"));
                }
                autoindex_format = Some(parse_autoindex_format_args(&args[1..])?);
            }
            ("if_modified_since", Terminator::Semi) => {
                if if_modified_since.is_some() {
                    return Err(Error::Duplicate("if_modified_since"));
                }
                if_modified_since = Some(parse_if_modified_since_args(&args[1..])?);
            }
            ("etag", Terminator::Semi) => {
                if etag.is_some() {
                    return Err(Error::Duplicate("etag"));
                }
                etag = Some(parse_on_off_args(&args[1..], "etag")?);
            }
            ("access_log", Terminator::Semi) => {
                let list = access_logs.get_or_insert_with(Vec::new);
                match parse_access_log_args(&args[1..])? {
                    ParsedAccessLog::Off => list.clear(),
                    ParsedAccessLog::Entry(log) => list.push(log),
                }
            }
            ("open_log_file_cache", Terminator::Semi) => {
                if open_log_file_cache.is_some() {
                    return Err(Error::Duplicate("open_log_file_cache"));
                }
                open_log_file_cache = Some(parse_open_log_file_cache_args(&args[1..])?);
            }
            ("auth_basic", Terminator::Semi) => {
                if auth_basic.is_some() {
                    return Err(Error::Duplicate("auth_basic"));
                }
                auth_basic = Some(parse_auth_basic_args(&args[1..])?);
            }
            ("auth_basic_user_file", Terminator::Semi) => {
                if auth_basic_user_file.is_some() {
                    return Err(Error::Duplicate("auth_basic_user_file"));
                }
                auth_basic_user_file = Some(parse_auth_basic_user_file_args(
                    &args[1..],
                    lx.conf_prefix(),
                )?);
            }
            ("auth_delay", Terminator::Semi) => {
                if auth_delay_ms.is_some() {
                    return Err(Error::Duplicate("auth_delay"));
                }
                let raw = args.get(1).ok_or(Error::MissingArg("auth_delay"))?;
                auth_delay_ms = Some(parse_duration_ms(raw, "auth_delay")?);
            }
            (
                "allow" | "deny" | "satisfy" | "set_real_ip_from" | "real_ip_header"
                | "auth_request" | "auth_request_set" | "real_ip_recursive",
                Terminator::Semi,
            ) => {
                parse_access_directive(&mut access, &args, lx)?;
            }
            ("limit_except", Terminator::BlockOpen) => {
                if limit_except.is_some() {
                    return Err(Error::Duplicate("limit_except"));
                }
                limit_except = Some(parse_limit_except_block(&args, lx)?);
            }
            ("client_body_buffer_size", Terminator::Semi) => {
                if client_body_buffer_size.is_some() {
                    return Err(Error::Duplicate("client_body_buffer_size"));
                }
                client_body_buffer_size = Some(parse_client_body_buffer_size_args(&args[1..])?);
            }
            ("client_max_body_size", Terminator::Semi) => {
                if client_max_body_size.is_some() {
                    return Err(Error::Duplicate("client_max_body_size"));
                }
                client_max_body_size = Some(parse_client_max_body_size_args(&args[1..])?);
            }
            ("max_ranges", Terminator::Semi) => {
                if max_ranges.is_some() {
                    return Err(Error::Duplicate("max_ranges"));
                }
                max_ranges = Some(parse_max_ranges_args(&args[1..])?);
            }
            ("client_body_in_file_only", Terminator::Semi) => {
                if client_body_in_file_only.is_some() {
                    return Err(Error::Duplicate("client_body_in_file_only"));
                }
                let raw = args
                    .get(1)
                    .ok_or(Error::MissingArg("client_body_in_file_only"))?;
                client_body_in_file_only = Some(match raw.as_str() {
                    "on" => ClientBodyInFileOnly::On,
                    "off" => ClientBodyInFileOnly::Off,
                    "clean" => ClientBodyInFileOnly::Clean,
                    _ => {
                        return Err(Error::BadValue {
                            what: "client_body_in_file_only",
                            got: raw.clone(),
                        });
                    }
                });
            }
            ("post_action", Terminator::Semi) => {
                if post_action.is_some() {
                    return Err(Error::Duplicate("post_action"));
                }
                post_action = Some(parse_post_action_args(&args[1..])?);
            }
            ("expires", Terminator::Semi) => {
                if expires.is_some() {
                    return Err(Error::Duplicate("expires"));
                }
                expires = Some(parse_expires_args(&args[1..])?);
            }
            ("root", Terminator::Semi) => {
                if local_path_mapping.is_some() {
                    return Err(Error::Duplicate("root/alias"));
                }
                let path = args.get(1).ok_or(Error::MissingArg("root path"))?;
                root = Some((PathBuf::from(path), PathMapping::Root));
                local_path_mapping = Some(PathMapping::Root);
                alias_prefix_override = None;
            }
            ("alias", Terminator::Semi) => {
                if local_path_mapping.is_some() {
                    return Err(Error::Duplicate("root/alias"));
                }
                if matches!(spec.mode, MatchMode::Named) {
                    return Err(Error::BadValue {
                        what: "alias in named location",
                        got: spec.pattern.clone(),
                    });
                }
                let path = args.get(1).ok_or(Error::MissingArg("alias path"))?;
                // The classic misconfiguration: nginx joins location and
                // alias as written. `location /img { alias /data/img/; }`
                // maps `/img../x` to `/data/img/../x`, outside the
                // directory; `location /img/ { alias /data/img; }` maps
                // `/img/x` to `/data/imgx`. ruxen joins them with one `/`
                // and stays in the directory, but the configuration likely
                // doesn't say what was meant (gixy's "alias traversal").
                if matches!(spec.mode, MatchMode::Prefix)
                    && !path.contains('$')
                    && spec.pattern.len() > 1
                    && spec.pattern.ends_with('/') != path.ends_with('/')
                {
                    let (loc, dir) = (
                        spec.pattern.trim_end_matches('/'),
                        path.trim_end_matches('/'),
                    );
                    let example = if path.ends_with('/') {
                        format!("\"{loc}../x\" to \"{dir}/../x\", outside the directory")
                    } else {
                        format!("\"{loc}/x\" to \"{dir}x\"")
                    };
                    lx.warnings_mut().push(format!(
                        "\"alias {path}\" in location \"{}\": only one of them ends with \"/\"; \
                         nginx would map {example}, ruxen joins them with one \"/\"",
                        spec.pattern,
                    ));
                }
                root = Some((PathBuf::from(path), PathMapping::Alias));
                local_path_mapping = Some(PathMapping::Alias);
                alias_prefix_override = None;
            }
            ("index", Terminator::Semi) => {
                if args.len() < 2 {
                    return Err(Error::MissingArg("index"));
                }
                // Repeated `index` lines append, as in nginx.
                index
                    .get_or_insert_with(Vec::new)
                    .extend(parse_index_entries(&args[1..])?);
            }
            ("try_files", Terminator::Semi) => {
                if try_files.is_some() {
                    return Err(Error::Duplicate("try_files"));
                }
                // nginx requires 2+ args: one probe + one fallback.
                if args.len() < 3 {
                    return Err(Error::MissingArg("try_files"));
                }
                try_files = Some(parse_try_files(&args[1..])?);
            }
            // Location settings in nginx; `client_header_timeout` is not.
            (name @ ("client_body_timeout" | "send_timeout"), Terminator::Semi) => {
                client_timeouts.parse(name, &args)?;
            }
            // Location settings of ngx_http_v2_module too (#594): the
            // largest DATA frame of the location's responses, and the
            // server push ones, obsolete since nginx 1.25.1, with the
            // warning they get at server level.
            ("http2_chunk_size", Terminator::Semi) => {
                client_timeouts.parse("http2_chunk_size", &args)?;
            }
            ("http2_push" | "http2_push_preload", Terminator::Semi) => {
                Http2Conf::default().parse(&args, lx.warnings_mut())?;
            }
            // An optional argument is ignored, as nginx does for old
            // configurations (`stub_status on;`).
            ("stub_status", Terminator::Semi) if args.len() <= 2 => {
                stub_status = true;
                crate::config::values::note_stats_used();
            }
            // ruxen's own (#481), where `stub_status` goes.
            ("ruxen_metrics", Terminator::Semi) => {
                if args.len() != 1 {
                    return Err(Error::Directive {
                        name: "ruxen_metrics",
                        msg: "takes no arguments".to_string(),
                    });
                }
                metrics = true;
                crate::config::values::note_metrics_used();
            }
            ("proxy_pass", Terminator::Semi) => {
                if proxy_pass.is_some() {
                    return Err(Error::Duplicate("proxy_pass"));
                }
                proxy_pass = Some(parse_proxy_pass_arg(&args[1..])?);
            }
            (name, Terminator::Semi) if ProxyConf::takes(name) => {
                proxy.parse(&args, lx.conf_prefix())?
            }
            (name, Terminator::Semi) if GzipConf::takes(name) => gzip.parse(&args)?,
            (name, Terminator::Semi) if LimitReqConf::takes(name) => limit_req.parse(&args)?,
            (name, Terminator::Semi) if LimitConnConf::takes(name) => limit_conn.parse(&args)?,
            ("limit_rate", Terminator::Semi) => {
                if limit_rate.is_some() {
                    return Err(Error::Duplicate("limit_rate"));
                }
                limit_rate = Some(parse_size_value(&args[1..], "limit_rate")?);
            }
            ("limit_rate_after", Terminator::Semi) => {
                if limit_rate_after.is_some() {
                    return Err(Error::Duplicate("limit_rate_after"));
                }
                limit_rate_after = Some(parse_size_value(&args[1..], "limit_rate_after")?);
            }
            ("client_body_temp_path", Terminator::Semi) => {
                if client_body_temp_path.is_some() {
                    return Err(Error::Duplicate("client_body_temp_path"));
                }
                client_body_temp_path =
                    Some(parse_temp_path_args(&args[1..], "client_body_temp_path")?);
            }
            ("disable_symlinks", Terminator::Semi) => {
                if disable_symlinks.is_some() {
                    return Err(Error::Duplicate("disable_symlinks"));
                }
                disable_symlinks = Some(parse_disable_symlinks_args(&args[1..])?);
            }
            ("sendfile", Terminator::Semi) => {
                if sendfile.is_some() {
                    return Err(Error::Duplicate("sendfile"));
                }
                sendfile = Some(parse_on_off_args(&args[1..], "sendfile")?);
            }
            (name, Terminator::Semi) if RedirectConf::takes(name) => redirect.parse(&args)?,
            ("chunked_transfer_encoding", Terminator::Semi) => {
                if chunked_transfer_encoding.is_some() {
                    return Err(Error::Duplicate("chunked_transfer_encoding"));
                }
                chunked_transfer_encoding =
                    Some(parse_on_off_args(&args[1..], "chunked_transfer_encoding")?);
            }
            ("location", Terminator::BlockOpen) => {
                let child_spec = parse_location_spec(&args[1..])?;
                // Children see the closest ancestor's `server_tokens`:
                // this block's own value if set, else whatever was inherited
                // into this block. Their own directive still wins.
                let pass_tokens = server_tokens.or(inherited.server_tokens);
                let pass_autoindex = autoindex.or(inherited.autoindex);
                let pass_autoindex_exact_size =
                    autoindex_exact_size.or(inherited.autoindex_exact_size);
                let pass_autoindex_localtime =
                    autoindex_localtime.or(inherited.autoindex_localtime);
                let pass_autoindex_format = autoindex_format.or(inherited.autoindex_format);
                let pass_if_modified_since = if_modified_since.or(inherited.if_modified_since);
                let pass_etag = etag.or(inherited.etag);
                let pass_auth_basic = auth_basic.clone().or(inherited.auth_basic.clone());
                let pass_auth_file = auth_basic_user_file
                    .clone()
                    .or(inherited.auth_basic_user_file.clone());
                let pass_auth_delay_ms = auth_delay_ms.or(inherited.auth_delay_ms);
                let pass_access = access.inherit(&inherited.access);
                let pass_client_max_body_size =
                    client_max_body_size.or(inherited.client_max_body_size);
                let pass_client_body_buffer_size =
                    client_body_buffer_size.or(inherited.client_body_buffer_size);
                let pass_post_action = post_action.clone().or(inherited.post_action.clone());
                let pass_expires = expires.clone().or(inherited.expires.clone());
                let pass_sendfile = sendfile.or(inherited.sendfile);
                let pass_client_body_temp_path = client_body_temp_path
                    .clone()
                    .or_else(|| inherited.client_body_temp_path.clone());
                let pass_disable_symlinks = disable_symlinks
                    .clone()
                    .or_else(|| inherited.disable_symlinks.clone());
                // Cascade alias info to nested children (mirrors nginx's
                // `merge_loc_conf` for the core module's path bits): a
                // local `alias` here propagates as Alias-with-this-pattern;
                // a local `root` here shadows the inherited alias chain
                // for descendants; otherwise pass through whatever this
                // block inherited.
                let pass_inherited_alias = match local_path_mapping {
                    Some(PathMapping::Alias) => {
                        let path = root
                            .as_ref()
                            .map(|(p, _)| p.clone())
                            .expect("alias set implies root path captured");
                        Some((path, spec.pattern.clone()))
                    }
                    Some(PathMapping::Root) => None,
                    None => inherited.alias.clone(),
                };
                parse_location_block(
                    child_spec,
                    lx,
                    Inherited {
                        root: inherited.root.clone(),
                        alias: pass_inherited_alias,
                        server_tokens: pass_tokens,
                        autoindex: pass_autoindex,
                        autoindex_exact_size: pass_autoindex_exact_size,
                        autoindex_localtime: pass_autoindex_localtime,
                        autoindex_format: pass_autoindex_format,
                        if_modified_since: pass_if_modified_since,
                        etag: pass_etag,
                        auth_basic: pass_auth_basic,
                        auth_basic_user_file: pass_auth_file,
                        auth_delay_ms: pass_auth_delay_ms,
                        access: pass_access,
                        client_max_body_size: pass_client_max_body_size,
                        client_body_buffer_size: pass_client_body_buffer_size,
                        post_action: pass_post_action,
                        expires: pass_expires,
                        sendfile: pass_sendfile,
                        client_body_temp_path: pass_client_body_temp_path,
                        disable_symlinks: pass_disable_symlinks,
                    },
                    &mut children,
                    None,
                )?;
            }
            (
                "set"
                | "rewrite"
                | "break"
                | "if"
                | "return"
                | "root"
                | "alias"
                | "index"
                | "try_files"
                | "add_header"
                | "add_header_inherit"
                | "add_trailer_inherit"
                | "error_page"
                | "keepalive_timeout"
                | "keepalive_requests"
                | "keepalive_time"
                | "keepalive_disable"
                | "error_log"
                | "log_not_found"
                | "recursive_error_pages"
                | "internal"
                | "server_tokens"
                | "autoindex"
                | "autoindex_exact_size"
                | "autoindex_localtime"
                | "autoindex_format"
                | "if_modified_since"
                | "etag"
                | "access_log"
                | "auth_basic"
                | "auth_basic_user_file"
                | "auth_delay"
                | "allow"
                | "deny"
                | "satisfy"
                | "set_real_ip_from"
                | "real_ip_header"
                | "real_ip_recursive"
                | "auth_request"
                | "auth_request_set"
                | "limit_except"
                | "client_max_body_size"
                | "max_ranges"
                | "client_body_temp_path"
                | "disable_symlinks"
                | "client_body_in_file_only"
                | "post_action"
                | "expires"
                | "proxy_pass"
                | "proxy_set_header"
                | "proxy_pass_request_headers"
                | "proxy_pass_request_body"
                | "proxy_set_body"
                | "proxy_ignore_headers"
                | "proxy_connect_timeout"
                | "proxy_read_timeout"
                | "proxy_send_timeout"
                | "proxy_limit_rate"
                | "proxy_http_version"
                | "proxy_next_upstream"
                | "proxy_next_upstream_tries"
                | "proxy_next_upstream_timeout"
                | "proxy_intercept_errors"
                | "proxy_force_ranges"
                | "proxy_ignore_client_abort"
                | "proxy_redirect"
                | "proxy_hide_header"
                | "proxy_pass_header"
                | "proxy_method"
                | "location",
                _,
            ) => {
                return Err(Error::WrongTerminator {
                    name: args[0].clone(),
                    ctx: "location",
                });
            }
            (n, Terminator::Semi) if is_ignored_stmt(n) => check_ignored_args(lx, &args)?,
            (n, Terminator::BlockOpen) if is_ignored_block(n) => {
                compat::ignored_block(lx, &args);
                skip_block(lx)?
            }
            (_, _) => {
                compat::unknown(lx, &args, &term, "location")?;
            }
        }
    }
}

pub(crate) fn parse_try_files(args: &[String]) -> Result<TryFiles, Error> {
    // Invariant from caller: args.len() >= 2 (one probe + one fallback).
    let (fallback_raw, probe_raw) = args.split_last().unwrap();
    let mut probes: Vec<TryFilesProbe> = Vec::with_capacity(probe_raw.len());
    for s in probe_raw {
        probes.push(classify_probe(s)?);
    }
    let fallback = classify_fallback(fallback_raw)?;
    Ok(TryFiles { probes, fallback })
}

pub(crate) fn parse_auth_basic_args(args: &[String]) -> Result<AuthBasic, Error> {
    if args.len() != 1 {
        return Err(Error::BadValue {
            what: "auth_basic",
            got: args.join(" "),
        });
    }
    if args[0] == "off" {
        return Ok(AuthBasic::Off);
    }
    // Variables in the realm are unsupported — reject so the misconfig
    // surfaces at `-t` instead of silently producing `realm=""` at
    // request time.
    let parts = parse_value_with_vars(&args[0])?;
    let mut realm = Vec::with_capacity(args[0].len());
    for part in &parts {
        match part {
            ValuePart::Literal(s) => realm.extend_from_slice(s.as_bytes()),
            ValuePart::Var(_) => {
                return Err(Error::BadValue {
                    what: "auth_basic (variables are not supported in realm)",
                    got: args[0].clone(),
                });
            }
        }
    }
    Ok(AuthBasic::Realm(realm))
}

/// nginx resolves `auth_basic_user_file` against the config directory, not
/// the `-p` prefix. Literal paths are resolved here, once; paths containing
/// variables are resolved after rendering, per request.
pub(crate) fn parse_auth_basic_user_file_args(
    args: &[String],
    conf_prefix: Option<&Path>,
) -> Result<PathBuf, Error> {
    if args.len() != 1 {
        return Err(Error::BadValue {
            what: "auth_basic_user_file",
            got: args.join(" "),
        });
    }
    let path = PathBuf::from(&args[0]);
    if args[0].contains('$') {
        return Ok(path);
    }
    Ok(resolve_conf_path(conf_prefix, path))
}

/// Resolve `path` against the config directory when it is relative
/// (`ngx_conf_full_name(cycle, name, 1)`). Absolute paths, and every path
/// when there is no config directory (inline test parses), pass through.
pub fn resolve_conf_path(conf_prefix: Option<&Path>, path: PathBuf) -> PathBuf {
    match conf_prefix {
        Some(prefix) if path.is_relative() => prefix.join(path),
        _ => path,
    }
}

pub(crate) fn parse_on_off_args(args: &[String], what: &'static str) -> Result<bool, Error> {
    if args.len() != 1 {
        return Err(Error::BadValue {
            what,
            got: args.join(" "),
        });
    }
    match args[0].as_str() {
        "on" => Ok(true),
        "off" => Ok(false),
        _ => Err(Error::BadValue {
            what,
            got: args[0].clone(),
        }),
    }
}

pub(crate) fn parse_if_modified_since_args(args: &[String]) -> Result<IfModifiedSince, Error> {
    match args {
        [v] => match v.as_str() {
            "off" => Ok(IfModifiedSince::Off),
            "exact" => Ok(IfModifiedSince::Exact),
            "before" => Ok(IfModifiedSince::Before),
            _ => Err(Error::BadValue {
                what: "if_modified_since",
                got: v.clone(),
            }),
        },
        _ => Err(Error::MissingArg("if_modified_since")),
    }
}

pub(crate) fn parse_autoindex_format_args(args: &[String]) -> Result<AutoindexFormat, Error> {
    if args.len() != 1 {
        return Err(Error::BadValue {
            what: "autoindex_format",
            got: args.join(" "),
        });
    }
    match args[0].as_str() {
        "html" => Ok(AutoindexFormat::Html),
        "xml" => Ok(AutoindexFormat::Xml),
        "json" => Ok(AutoindexFormat::Json),
        "jsonp" => Ok(AutoindexFormat::Jsonp),
        _ => Err(Error::BadValue {
            what: "autoindex_format",
            got: args[0].clone(),
        }),
    }
}

pub(crate) fn parse_log_not_found_args(args: &[String]) -> Result<bool, Error> {
    parse_on_off_args(args, "log_not_found")
}

pub(crate) fn parse_error_page_args(args: &[String]) -> Result<Vec<ErrorPage>, Error> {
    if args.len() < 2 {
        return Err(Error::MissingArg("error_page"));
    }

    let (statuses, action, target_raw) = match args.get(args.len() - 2) {
        Some(marker) if marker.starts_with('=') => {
            if args.len() < 3 {
                return Err(Error::MissingArg("error_page"));
            }
            let action = if marker == "=" {
                ErrorPageAction::UseTargetStatus
            } else {
                let code = marker[1..].parse::<u16>().map_err(|_| Error::BadValue {
                    what: "error_page overwrite",
                    got: marker.clone(),
                })?;
                ErrorPageAction::Override(code)
            };
            (&args[..args.len() - 2], action, args.last().unwrap())
        }
        _ => (
            &args[..args.len() - 1],
            ErrorPageAction::PreserveOriginal,
            args.last().unwrap(),
        ),
    };

    if statuses.is_empty() {
        return Err(Error::MissingArg("error_page status"));
    }
    if target_raw == "@" || (target_raw.starts_with('@') && target_raw.contains('?')) {
        return Err(Error::BadValue {
            what: "error_page named location",
            got: target_raw.clone(),
        });
    }

    let target = parse_value_with_vars(target_raw)?;
    reject_sent_http_parts(&target, "error_page target ($sent_http_* unavailable)")?;
    let mut out = Vec::with_capacity(statuses.len());
    for status_s in statuses {
        let status = status_s.parse::<u16>().map_err(|_| Error::BadValue {
            what: "error_page status",
            got: status_s.clone(),
        })?;
        if status == 499 {
            return Err(Error::BadValue {
                what: "error_page status",
                got: status_s.clone(),
            });
        }
        out.push(ErrorPage {
            status,
            action,
            target: target.clone(),
        });
    }
    Ok(out)
}

pub(crate) fn classify_probe(s: &str) -> Result<TryFilesProbe, Error> {
    if s.is_empty() {
        return Err(Error::BadValue {
            what: "try_files probe",
            got: s.into(),
        });
    }
    let (name, is_slash) = if let Some(stripped) = s.strip_suffix('/') {
        (stripped, true)
    } else {
        (s, false)
    };
    if name == "$uri" {
        Ok(if is_slash {
            TryFilesProbe::UriSlash
        } else {
            TryFilesProbe::Uri
        })
    } else if name.contains('$') {
        // nginx compiles every probe as a complex value.
        Ok(TryFilesProbe::Template {
            parts: parse_value_with_vars(name)?,
            dir: is_slash,
        })
    } else if is_slash {
        Ok(TryFilesProbe::LiteralSlash(name.into()))
    } else {
        Ok(TryFilesProbe::Literal(name.into()))
    }
}

pub(crate) fn classify_fallback(s: &str) -> Result<TryFilesFallback, Error> {
    if let Some(code_s) = s.strip_prefix('=') {
        let code = code_s.parse::<u16>().map_err(|_| Error::BadValue {
            what: "try_files fallback status",
            got: s.into(),
        })?;
        if !(100..=599).contains(&code) {
            return Err(Error::BadValue {
                what: "try_files fallback status (out of range)",
                got: s.into(),
            });
        }
        Ok(TryFilesFallback::Status(code))
    } else if s.starts_with('@') {
        if s.len() == 1 || s.contains('?') {
            return Err(Error::BadValue {
                what: "try_files fallback named location",
                got: s.into(),
            });
        }
        Ok(TryFilesFallback::Named(s.into()))
    } else if s.contains('$') {
        Ok(TryFilesFallback::UriTemplate(parse_value_with_vars(s)?))
    } else {
        Ok(TryFilesFallback::Uri(s.into()))
    }
}

pub(crate) fn parse_index_entries(args: &[String]) -> Result<Vec<IndexEntry>, Error> {
    let mut out = Vec::with_capacity(args.len());
    for arg in args {
        let parts = parse_value_with_vars(arg)?;
        reject_sent_http_parts(&parts, "index entry ($sent_http_* unavailable)")?;
        out.push(IndexEntry { parts });
    }
    Ok(out)
}

/// `add_header_inherit` / `add_trailer_inherit` (nginx 1.29.3, #598):
/// `on`, `off` or `merge`, once per level, as nginx's enum slot.
pub(crate) fn parse_header_inherit(
    slot: &mut Option<HeaderInherit>,
    args: &[String],
) -> Result<(), Error> {
    let what = if args[0] == "add_header_inherit" {
        "add_header_inherit"
    } else {
        "add_trailer_inherit"
    };
    if slot.is_some() {
        return Err(Error::Duplicate(what));
    }
    let [_, value] = args else {
        return Err(Error::BadValue {
            what,
            got: args[1..].join(" "),
        });
    };
    *slot = Some(match value.as_str() {
        "on" => HeaderInherit::On,
        "off" => HeaderInherit::Off,
        "merge" => HeaderInherit::Merge,
        _ => {
            return Err(Error::BadValue {
                what,
                got: value.clone(),
            });
        }
    });
    Ok(())
}

/// Parse the arguments after the `add_header` keyword. Accepts:
///   add_header NAME VALUE;
///   add_header NAME VALUE always;
/// `always` toggles emission on error responses; without it, only success/
/// redirect statuses receive the header (nginx's default).
pub(crate) fn parse_add_header_args(args: &[String]) -> Result<AddHeader, Error> {
    if args.len() < 2 || args.len() > 3 {
        return Err(Error::BadValue {
            what: "add_header",
            got: args.join(" "),
        });
    }
    let always = match args.get(2) {
        None => false,
        Some(s) if s == "always" => true,
        Some(s) => {
            return Err(Error::BadValue {
                what: "add_header modifier (expected `always`)",
                got: s.clone(),
            });
        }
    };
    let name = args[0].clone();
    if name.is_empty() || !name.bytes().all(is_header_name_char) {
        return Err(Error::BadValue {
            what: "add_header name",
            got: name,
        });
    }
    let value = parse_value_with_vars(&args[1])?;
    Ok(AddHeader {
        name,
        value,
        always,
    })
}

/// `proxy_ignore_headers`: the fields nginx accepts there. Only
/// X-Accel-Redirect changes anything in ruxen (no cache, no X-Accel-*
/// buffering or rate controls), the others are already not acted on.
pub(crate) fn parse_proxy_ignore_headers(args: &[String]) -> Result<Vec<String>, Error> {
    const FIELDS: &[&str] = &[
        "x-accel-redirect",
        "x-accel-expires",
        "x-accel-limit-rate",
        "x-accel-buffering",
        "x-accel-charset",
        "expires",
        "cache-control",
        "set-cookie",
        "vary",
    ];
    if args.is_empty() {
        return Err(Error::MissingArg("proxy_ignore_headers"));
    }
    args.iter()
        .map(|a| {
            let lower = a.to_ascii_lowercase();
            if FIELDS.contains(&lower.as_str()) {
                Ok(lower)
            } else {
                Err(Error::BadValue {
                    what: "proxy_ignore_headers",
                    got: a.clone(),
                })
            }
        })
        .collect()
}

/// A size directive whose value may hold variables (`limit_rate 12k;`,
/// `limit_rate $arg_l;`): checked as a size here when it's literal,
/// rendered and parsed per request otherwise.
pub(crate) fn parse_size_value(
    args: &[String],
    what: &'static str,
) -> Result<Vec<ValuePart>, Error> {
    let [value] = args else {
        return Err(Error::BadValue {
            what,
            got: args.join(" "),
        });
    };
    let parts = parse_value_with_vars(value)?;
    if parts.iter().all(|p| matches!(p, ValuePart::Literal(_)))
        && parse_size(value.as_bytes()).is_none()
    {
        return Err(Error::BadValue {
            what,
            got: value.clone(),
        });
    }
    Ok(parts)
}

/// nginx's `ngx_parse_size`: a decimal number with an optional `k`/`K` or
/// `m`/`M` suffix.
pub(crate) fn parse_size(value: &[u8]) -> Option<u64> {
    let (digits, scale) = match value.last()? {
        b'k' | b'K' => (&value[..value.len() - 1], 1024),
        b'm' | b'M' => (&value[..value.len() - 1], 1024 * 1024),
        _ => (value, 1),
    };
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(digits)
        .ok()?
        .parse::<u64>()
        .ok()?
        .checked_mul(scale)
}
