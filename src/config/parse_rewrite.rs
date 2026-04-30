//! Rewrite-engine parser: `set`, `if`, `rewrite`, `break`. Nginx's
//! "rewrite phase" mini-language as it appears at parse time, lowered
//! to the `RewriteOp` IR that `worker::rewrite_runtime` executes.

use super::*;

pub(crate) fn parse_set_op(args: &[String]) -> Result<RewriteOp, Error> {
    if args.len() != 2 {
        return Err(Error::BadValue {
            what: "set",
            got: args.join(" "),
        });
    }
    let name = parse_rewrite_variable_name(&args[0], "set variable")?;
    let value = parse_value_with_vars_rewrite(&args[1])?;
    reject_sent_http_parts(&value, "set value ($sent_http_* unavailable)")?;
    Ok(RewriteOp::Set { name, value })
}

pub(crate) fn parse_rewrite_op(args: &[String]) -> Result<RewriteOp, Error> {
    if args.len() < 2 || args.len() > 3 {
        return Err(Error::BadValue {
            what: "rewrite",
            got: args.join(" "),
        });
    }
    let pattern = expand_pcre_quote_escapes(&args[0]);
    validate_regex(&pattern, false)?;

    let raw_replacement = &args[1];
    let drop_args = raw_replacement.ends_with('?');
    let replacement_src = if drop_args {
        &raw_replacement[..raw_replacement.len() - 1]
    } else {
        raw_replacement.as_str()
    };
    let parsed = parse_value_with_vars_rewrite(replacement_src)?;
    reject_sent_http_parts(&parsed, "rewrite replacement ($sent_http_* unavailable)")?;
    let (replacement, replacement_args) = split_replacement_at_question(parsed);

    let flag = match args.get(2).map(String::as_str) {
        None => RewriteFlag::None,
        Some("last") => RewriteFlag::Last,
        Some("break") => RewriteFlag::Break,
        Some("redirect") => RewriteFlag::Redirect,
        Some("permanent") => RewriteFlag::Permanent,
        Some(other) => {
            return Err(Error::BadValue {
                what: "rewrite flag",
                got: other.to_string(),
            });
        }
    };

    Ok(RewriteOp::Rewrite(RewriteRule {
        regex: pattern,
        replacement,
        replacement_args,
        flag,
        drop_args,
    }))
}

/// Split a parsed rewrite replacement at the first literal `?`. nginx
/// treats this `?` as the URI/args boundary inside the replacement string;
/// captures rendered into the args side get arg-escaped at runtime.
pub(crate) fn split_replacement_at_question(
    parts: Vec<ValuePart>,
) -> (Vec<ValuePart>, Option<Vec<ValuePart>>) {
    let mut uri: Vec<ValuePart> = Vec::new();
    let mut iter = parts.into_iter();
    while let Some(part) = iter.next() {
        match part {
            ValuePart::Literal(s) => {
                if let Some(idx) = s.find('?') {
                    let (left, right) = s.split_at(idx);
                    if !left.is_empty() {
                        uri.push(ValuePart::Literal(left.to_string()));
                    }
                    let mut args: Vec<ValuePart> = Vec::new();
                    let after = &right[1..];
                    if !after.is_empty() {
                        args.push(ValuePart::Literal(after.to_string()));
                    }
                    args.extend(iter);
                    return (uri, Some(args));
                }
                uri.push(ValuePart::Literal(s));
            }
            other => uri.push(other),
        }
    }
    (uri, None)
}

pub(crate) fn parse_if_op(args: &[String], lx: &mut Lexer) -> Result<RewriteOp, Error> {
    let guard = parse_if_guard(args)?;
    let body = parse_rewrite_block(lx)?;
    Ok(RewriteOp::If { guard, body })
}

pub(crate) fn parse_rewrite_block(lx: &mut Lexer) -> Result<Vec<RewriteOp>, Error> {
    let mut body: Vec<RewriteOp> = Vec::new();
    loop {
        let (args, term) = lx.read_directive()?;
        if args.is_empty() {
            return match term {
                Terminator::BlockClose => Ok(body),
                Terminator::Eof => Err(Error::UnclosedBlock),
                _ => Err(Error::UnexpectedEof),
            };
        }
        match (args[0].as_str(), &term) {
            ("set", Terminator::Semi) => body.push(parse_set_op(&args[1..])?),
            ("rewrite", Terminator::Semi) => body.push(parse_rewrite_op(&args[1..])?),
            ("return", Terminator::Semi) => {
                let (status, body_parts) = parse_return_args(&args[1..])?;
                body.push(RewriteOp::Return {
                    status,
                    body: body_parts,
                });
            }
            ("break", Terminator::Semi) => {
                if args.len() != 1 {
                    return Err(Error::BadValue {
                        what: "break",
                        got: args[1..].join(" "),
                    });
                }
                body.push(RewriteOp::Break);
            }
            ("if", Terminator::BlockOpen) => body.push(parse_if_op(&args[1..], lx)?),
            ("set" | "rewrite" | "return" | "break" | "if", _) => {
                return Err(Error::WrongTerminator {
                    name: args[0].clone(),
                    ctx: "if",
                });
            }
            (n, Terminator::Semi) if is_ignored_stmt(n) => {}
            (n, Terminator::BlockOpen) if is_ignored_block(n) => skip_block(lx)?,
            (other, _) => {
                return Err(Error::UnknownDirective {
                    name: other.into(),
                    ctx: "if",
                });
            }
        }
    }
}

pub(crate) fn parse_if_guard(args: &[String]) -> Result<IfGuard, Error> {
    if args.is_empty() {
        return Err(Error::MissingArg("if condition"));
    }
    let joined = args.join(" ");
    let trimmed = joined.trim();
    if !trimmed.starts_with('(') || !trimmed.ends_with(')') {
        return Err(Error::BadValue {
            what: "if condition",
            got: joined,
        });
    }
    let inner = trimmed[1..trimmed.len() - 1].trim();
    if inner.is_empty() {
        return Err(Error::MissingArg("if condition"));
    }
    parse_if_guard_inner(inner)
}

pub(crate) fn parse_if_guard_inner(inner: &str) -> Result<IfGuard, Error> {
    if let Some(rest) = inner.strip_prefix("!-") {
        return parse_if_file_test(rest, true);
    }
    if let Some(rest) = inner.strip_prefix('-') {
        return parse_if_file_test(rest, false);
    }

    let (left, rest) = split_if_left_var(inner)?;
    if rest.is_empty() {
        return Ok(IfGuard::VarTruthy(left));
    }

    let (op, rhs) = if let Some(rhs) = rest.strip_prefix("!=") {
        ("!=", rhs.trim_start())
    } else if let Some(rhs) = rest.strip_prefix('=') {
        ("=", rhs.trim_start())
    } else if let Some(rhs) = rest.strip_prefix("!~*") {
        ("!~*", rhs.trim_start())
    } else if let Some(rhs) = rest.strip_prefix("!~") {
        ("!~", rhs.trim_start())
    } else if let Some(rhs) = rest.strip_prefix("~*") {
        ("~*", rhs.trim_start())
    } else if let Some(rhs) = rest.strip_prefix('~') {
        ("~", rhs.trim_start())
    } else {
        return Err(Error::BadValue {
            what: "if condition",
            got: inner.to_string(),
        });
    };
    if rhs.is_empty() {
        return Err(Error::BadValue {
            what: "if condition",
            got: inner.to_string(),
        });
    }

    match op {
        "=" => {
            let right = parse_value_with_vars(rhs)?;
            reject_sent_http_parts(&right, "if comparison ($sent_http_* unavailable)")?;
            Ok(IfGuard::Eq { left, right })
        }
        "!=" => {
            let right = parse_value_with_vars(rhs)?;
            reject_sent_http_parts(&right, "if comparison ($sent_http_* unavailable)")?;
            Ok(IfGuard::NotEq { left, right })
        }
        "~" | "~*" | "!~" | "!~*" => {
            let pattern = expand_pcre_quote_escapes(rhs);
            let case_insensitive = op.ends_with('*');
            validate_regex(&pattern, case_insensitive)?;
            Ok(IfGuard::Regex {
                left,
                pattern,
                case_insensitive,
                negated: op.starts_with('!'),
            })
        }
        _ => unreachable!(),
    }
}

pub(crate) fn parse_if_file_test(rest: &str, negated: bool) -> Result<IfGuard, Error> {
    let mut chars = rest.chars();
    let Some(kind_ch) = chars.next() else {
        return Err(Error::BadValue {
            what: "if file test",
            got: if negated {
                format!("!-{rest}")
            } else {
                format!("-{rest}")
            },
        });
    };
    let kind = match kind_ch {
        'f' => FileTestKind::File,
        'd' => FileTestKind::Dir,
        'e' => FileTestKind::Exists,
        'x' => FileTestKind::Exec,
        _ => {
            return Err(Error::BadValue {
                what: "if file test",
                got: if negated {
                    format!("!-{rest}")
                } else {
                    format!("-{rest}")
                },
            });
        }
    };
    let path = chars.as_str().trim_start();
    if path.is_empty() {
        return Err(Error::MissingArg("if file test path"));
    }
    let path_parts = parse_value_with_vars(path)?;
    reject_sent_http_parts(&path_parts, "if file test path ($sent_http_* unavailable)")?;
    Ok(IfGuard::FileTest {
        kind,
        path: path_parts,
        negated,
    })
}

pub(crate) fn split_if_left_var(cond: &str) -> Result<(Variable, &str), Error> {
    if !cond.starts_with('$') {
        return Err(Error::BadValue {
            what: "if condition",
            got: cond.to_string(),
        });
    }
    let bytes = cond.as_bytes();
    let end = if bytes.get(1) == Some(&b'{') {
        let mut i = 2;
        while i < bytes.len() && bytes[i] != b'}' {
            i += 1;
        }
        if i >= bytes.len() {
            return Err(Error::BadValue {
                what: "if condition",
                got: cond.to_string(),
            });
        }
        i + 1
    } else if bytes.get(1).is_some_and(|b| b.is_ascii_digit()) {
        2
    } else {
        if bytes.len() < 2 || !is_var_name_first(bytes[1]) {
            return Err(Error::BadValue {
                what: "if condition",
                got: cond.to_string(),
            });
        }
        let mut i = 2;
        while i < bytes.len() && is_var_name_cont(bytes[i]) {
            i += 1;
        }
        i
    };
    let left_token = &cond[..end];
    let left = parse_single_variable(left_token, true)?;
    if matches!(left, Variable::SentHttp(_)) {
        return Err(Error::BadValue {
            what: "if condition ($sent_http_* unavailable)",
            got: left_token.to_string(),
        });
    }
    Ok((left, cond[end..].trim_start()))
}

pub(crate) fn parse_rewrite_variable_name(raw: &str, what: &'static str) -> Result<String, Error> {
    let Some(name) = raw.strip_prefix('$') else {
        return Err(Error::BadValue {
            what,
            got: raw.to_string(),
        });
    };
    let bytes = name.as_bytes();
    if bytes.is_empty()
        || !is_var_name_first(bytes[0])
        || !bytes[1..].iter().all(|b| is_var_name_cont(*b))
    {
        return Err(Error::BadValue {
            what,
            got: raw.to_string(),
        });
    }
    Ok(name.to_string())
}

