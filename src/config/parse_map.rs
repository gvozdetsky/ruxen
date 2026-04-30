//! `split_clients $key $var { ... }` and `map $src $dst { ... }` block
//! parsers. Exact entries are deduped at parse time; regex entries
//! (`~pattern` / `~*pattern`) compile here so `-t` rejects bad patterns.

use super::*;

pub(crate) fn parse_split_clients_block(args: &[String], lx: &mut Lexer) -> Result<SplitClients, Error> {
    if args.len() != 2 {
        return Err(Error::BadValue {
            what: "split_clients",
            got: args.join(" "),
        });
    }
    let key = parse_value_with_vars(&args[0])?;
    reject_sent_http_parts(&key, "split_clients key ($sent_http_* unavailable)")?;
    let variable = parse_rewrite_variable_name(&args[1], "split_clients variable")?;

    let mut parts_raw: Vec<(Option<u32>, Vec<ValuePart>)> = Vec::new();
    let mut saw_catch_all = false;
    loop {
        let (line_args, term) = lx.read_directive()?;
        if line_args.is_empty() {
            match term {
                Terminator::BlockClose => break,
                Terminator::Eof => return Err(Error::UnclosedBlock),
                _ => return Err(Error::UnexpectedEof),
            }
        }
        if !matches!(term, Terminator::Semi) {
            return Err(Error::WrongTerminator {
                name: line_args[0].clone(),
                ctx: "split_clients",
            });
        }
        if line_args.len() != 2 {
            return Err(Error::BadValue {
                what: "split_clients entry",
                got: line_args.join(" "),
            });
        }
        let percent = if line_args[0] == "*" {
            if saw_catch_all {
                return Err(Error::BadValue {
                    what: "split_clients catch-all",
                    got: line_args[0].clone(),
                });
            }
            saw_catch_all = true;
            None
        } else {
            if saw_catch_all {
                return Err(Error::BadValue {
                    what: "split_clients catch-all must be last",
                    got: line_args[0].clone(),
                });
            }
            Some(parse_split_percent_hundredths(&line_args[0])?)
        };
        let value = parse_value_with_vars(&line_args[1])?;
        reject_sent_http_parts(&value, "split_clients value ($sent_http_* unavailable)")?;
        parts_raw.push((percent, value));
    }

    if parts_raw.is_empty() {
        return Err(Error::MissingArg("split_clients entry"));
    }

    let mut sum = 0u32;
    let mut last = 0u32;
    let mut parts: Vec<SplitClientsPart> = Vec::with_capacity(parts_raw.len());
    for (percent, value) in parts_raw {
        let threshold = if let Some(p) = percent {
            sum = sum.saturating_add(p);
            if sum > 10_000 {
                return Err(Error::BadValue {
                    what: "split_clients percent total",
                    got: "greater than 100%".to_string(),
                });
            }
            last = last.wrapping_add(((p as u64 * 0xffff_ffffu64) / 10_000) as u32);
            last
        } else {
            0
        };
        parts.push(SplitClientsPart { threshold, value });
    }

    Ok(SplitClients {
        key,
        variable,
        parts,
    })
}

pub(crate) fn parse_split_percent_hundredths(raw: &str) -> Result<u32, Error> {
    let Some(number) = raw.strip_suffix('%') else {
        return Err(Error::BadValue {
            what: "split_clients percent",
            got: raw.to_string(),
        });
    };
    if number.is_empty() {
        return Err(Error::BadValue {
            what: "split_clients percent",
            got: raw.to_string(),
        });
    }

    let (whole, frac) = match number.split_once('.') {
        Some((w, f)) => (w, f),
        None => (number, ""),
    };
    if whole.is_empty() || !whole.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::BadValue {
            what: "split_clients percent",
            got: raw.to_string(),
        });
    }
    if frac.len() > 2 || !frac.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::BadValue {
            what: "split_clients percent",
            got: raw.to_string(),
        });
    }

    let whole_n = whole.parse::<u32>().map_err(|_| Error::BadValue {
        what: "split_clients percent",
        got: raw.to_string(),
    })?;
    let frac_n = match frac.len() {
        0 => 0,
        1 => frac.parse::<u32>().unwrap() * 10,
        _ => frac.parse::<u32>().unwrap(),
    };
    let value = whole_n
        .checked_mul(100)
        .and_then(|v| v.checked_add(frac_n))
        .ok_or_else(|| Error::BadValue {
            what: "split_clients percent",
            got: raw.to_string(),
        })?;
    if value == 0 {
        return Err(Error::BadValue {
            what: "split_clients percent",
            got: raw.to_string(),
        });
    }
    Ok(value)
}

/// Parse a `map $source $dest { ... }` block. The body allows three entry
/// shapes plus a `default` clause:
///
/// ```text
/// map $src $dst {
///     default   fallback;
///     "exact"   v1;
///     ~regex    v2;
///     ~*regex   v3;   # case-insensitive
/// }
/// ```
///
/// Verified against `ngx_http_map_module.c::ngx_http_map_block`: exact
/// strings go into a hash, regexes stay in declaration order and are
/// tried linearly, `default` is optional. Modifiers `hostnames` and
/// `volatile` are not yet supported. `include` is handled transparently
/// by the lexer.
pub(crate) fn parse_map_block(args: &[String], lx: &mut Lexer) -> Result<MapBlock, Error> {
    if args.len() != 2 {
        return Err(Error::BadValue {
            what: "map",
            got: args.join(" "),
        });
    }
    let key = parse_value_with_vars(&args[0])?;
    reject_sent_http_parts(&key, "map key ($sent_http_* unavailable)")?;
    let variable = parse_rewrite_variable_name(&args[1], "map variable")?;

    let mut exact: Vec<MapExactEntry> = Vec::new();
    let mut regex: Vec<MapRegexEntry> = Vec::new();
    let mut default: Option<Vec<ValuePart>> = None;

    loop {
        let (line_args, term) = lx.read_directive()?;
        if line_args.is_empty() {
            match term {
                Terminator::BlockClose => break,
                Terminator::Eof => return Err(Error::UnclosedBlock),
                _ => return Err(Error::UnexpectedEof),
            }
        }
        if !matches!(term, Terminator::Semi) {
            return Err(Error::WrongTerminator {
                name: line_args[0].clone(),
                ctx: "map",
            });
        }
        // Reject modifiers we don't yet support rather than letting them
        // masquerade as an exact-match pattern. (`include` is handled by
        // the lexer before we ever see it here.)
        if matches!(line_args[0].as_str(), "hostnames" | "volatile") && line_args.len() == 1 {
            return Err(Error::UnknownDirective {
                name: line_args[0].clone(),
                ctx: "map",
            });
        }
        if line_args.len() != 2 {
            return Err(Error::BadValue {
                what: "map entry",
                got: line_args.join(" "),
            });
        }
        let (lhs, rhs) = (&line_args[0], &line_args[1]);
        let value = parse_value_with_vars(rhs)?;
        reject_sent_http_parts(&value, "map value ($sent_http_* unavailable)")?;

        if lhs == "default" {
            if default.is_some() {
                return Err(Error::Duplicate("map default"));
            }
            default = Some(value);
            continue;
        }

        if let Some(pattern) = lhs.strip_prefix("~*") {
            if pattern.is_empty() {
                return Err(Error::BadValue {
                    what: "map regex",
                    got: lhs.clone(),
                });
            }
            // Validate now so bad patterns fail `-t`.
            compile_map_regex(pattern, true)?;
            regex.push(MapRegexEntry {
                pattern: pattern.to_string(),
                case_insensitive: true,
                value,
            });
        } else if let Some(pattern) = lhs.strip_prefix('~') {
            if pattern.is_empty() {
                return Err(Error::BadValue {
                    what: "map regex",
                    got: lhs.clone(),
                });
            }
            compile_map_regex(pattern, false)?;
            regex.push(MapRegexEntry {
                pattern: pattern.to_string(),
                case_insensitive: false,
                value,
            });
        } else {
            if exact.iter().any(|e| e.key == *lhs) {
                return Err(Error::Duplicate("map exact key"));
            }
            exact.push(MapExactEntry {
                key: lhs.clone(),
                value,
            });
        }
    }

    Ok(MapBlock {
        key,
        variable,
        exact,
        regex,
        default,
    })
}

/// Compile a `map` regex pattern for `-t` validation. Runtime compilation
/// happens again in `prepare_maps`, but we do it here so malformed
/// patterns surface during `-t` rather than at worker startup.
pub(crate) fn compile_map_regex(pattern: &str, case_insensitive: bool) -> Result<(), Error> {
    let mut builder = regex::bytes::RegexBuilder::new(pattern);
    builder.case_insensitive(case_insensitive);
    builder.build().map(|_| ()).map_err(|_| Error::BadValue {
        what: "map regex",
        got: pattern.to_string(),
    })
}

