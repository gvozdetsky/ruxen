//! nginx hands configuration regexes to PCRE2 unchanged; the `regex` crate
//! reads some PCRE syntax differently. `translate` rewrites those parts
//! before every compile.

use std::borrow::Cow;

/// `pattern` as the `regex` crate should read it to match what PCRE2
/// (10.43 and later, as nginx 1.30 links on current systems) does:
/// - `\Q…\E` becomes per-character escapes;
/// - a `{` that doesn't start a quantifier is a literal (`\{`), as in
///   PCRE2; `regex` refuses it (#763);
/// - quantifiers in PCRE2's wider forms (`{,n}`, spaces or tabs inside)
///   become `{n}`, `{n,}`, `{n,m}`.
///
/// Idempotent, so a pattern translated at parse time may be translated again.
pub(crate) fn translate(pattern: &str) -> Cow<'_, str> {
    if !pattern.contains('{') && !pattern.contains("\\Q") {
        return Cow::Borrowed(pattern);
    }
    let b = pattern.as_bytes();
    let mut out = String::with_capacity(pattern.len() + 8);
    let mut i = 0;
    let mut in_class = false;
    while i < b.len() {
        match b[i] {
            b'\\' if b.get(i + 1) == Some(&b'Q') => {
                // Runs to `\E` or the end, as in PCRE.
                let start = i + 2;
                let end = pattern[start..].find("\\E").map_or(b.len(), |n| start + n);
                out.push_str(&regex::escape(&pattern[start..end]));
                i = (end + 2).min(b.len());
            }
            b'\\' => {
                let mut end = i + 1;
                if let Some(c) = pattern[end..].chars().next() {
                    end += c.len_utf8();
                    match c {
                        // `\x{41}`, `\p{L}`, …: the braces belong to the escape.
                        'x' | 'o' | 'p' | 'P' | 'N' | 'g' | 'k' if b.get(end) == Some(&b'{') => {
                            end = pattern[end..].find('}').map_or(b.len(), |n| end + n + 1);
                        }
                        // `\cX`: X is any character, `{` too.
                        'c' => {
                            end += pattern[end..].chars().next().map_or(0, char::len_utf8);
                        }
                        _ => {}
                    }
                }
                out.push_str(&pattern[i..end]);
                i = end;
            }
            b'[' if !in_class => {
                in_class = true;
                let mut end = i + 1;
                if b.get(end) == Some(&b'^') {
                    end += 1;
                }
                // A leading `]` is a member.
                if b.get(end) == Some(&b']') {
                    end += 1;
                }
                out.push_str(&pattern[i..end]);
                i = end;
            }
            // `[:alpha:]` inside a class.
            b'[' if b.get(i + 1) == Some(&b':') => {
                let end = pattern[i + 2..].find(":]").map_or(i + 1, |n| i + 2 + n + 2);
                out.push_str(&pattern[i..end]);
                i = end;
            }
            b']' if in_class => {
                in_class = false;
                out.push(']');
                i += 1;
            }
            b'{' if !in_class => match quantifier(&b[i..]) {
                Some((q, len)) => {
                    out.push_str(&q);
                    i += len;
                }
                None => {
                    out.push_str("\\{");
                    i += 1;
                }
            },
            _ => {
                let c = pattern[i..].chars().next().unwrap_or_default();
                out.push(c);
                i += c.len_utf8();
            }
        }
    }
    Cow::Owned(out)
}

/// A PCRE2 quantifier at the start of `b` (which starts with `{`), as
/// `regex` spells it, and its length: `{` [ws] [min] [ws] [`,` [ws] [max]
/// [ws]] `}` with at least one number; ws is spaces and tabs
/// (`read_repeat_counts` in PCRE2 10.43+).
fn quantifier(b: &[u8]) -> Option<(String, usize)> {
    let ws = |b: &[u8], mut i: usize| {
        while matches!(b.get(i), Some(b' ' | b'\t')) {
            i += 1;
        }
        i
    };
    let digits = |b: &[u8], mut i: usize| {
        while b.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
        i
    };
    let mut i = ws(b, 1);
    let min_end = digits(b, i);
    let min = std::str::from_utf8(&b[i..min_end]).ok()?;
    i = ws(b, min_end);
    let mut max = None;
    if b.get(i) == Some(&b',') {
        let start = ws(b, i + 1);
        let end = digits(b, start);
        max = Some(std::str::from_utf8(&b[start..end]).ok()?);
        i = ws(b, end);
    }
    if b.get(i) != Some(&b'}') {
        return None;
    }
    let q = match (min, max) {
        ("", None | Some("")) => return None,
        (min, None) => format!("{{{min}}}"),
        ("", Some(max)) => format!("{{0,{max}}}"),
        (min, Some(max)) => format!("{{{min},{max}}}"),
    };
    Some((q, i + 1))
}

#[cfg(test)]
mod tests {
    use super::translate;

    #[test]
    fn braces_that_are_not_quantifiers_are_literal() {
        for (pattern, want) in [
            ("^/a{x}(.*)$", "^/a\\{x}(.*)$"),
            ("^${PREFIX}(.*)$", "^$\\{PREFIX}(.*)$"),
            ("a{", "a\\{"),
            ("{", "\\{"),
            ("a{}", "a\\{}"),
            ("a{,}", "a\\{,}"),
            ("a{ , }", "a\\{ , }"),
            ("a{1 2}", "a\\{1 2}"),
            ("a{2x}", "a\\{2x}"),
            ("a{1,2,3}", "a\\{1,2,3}"),
            ("a{-1}", "a\\{-1}"),
            ("a{2}{x}", "a{2}\\{x}"),
            // Quantifiers, in every form PCRE2 10.46 reads as one.
            ("a{2}", "a{2}"),
            ("a{2,}", "a{2,}"),
            ("a{1,2}?", "a{1,2}?"),
            ("a{,2}", "a{0,2}"),
            ("a{ 2 }", "a{2}"),
            ("a{\t2 ,\t3 }", "a{2,3}"),
            ("a{ 2, }", "a{2,}"),
            ("a{ ,2}", "a{0,2}"),
            // Braces that belong to something else.
            ("[{]", "[{]"),
            ("[]{]", "[]{]"),
            ("[^]{]{2}", "[^]{]{2}"),
            ("[[:alpha:]{]", "[[:alpha:]{]"),
            ("\\{", "\\{"),
            ("\\x{41}{2}", "\\x{41}{2}"),
            ("\\p{L}{x}", "\\p{L}\\{x}"),
            ("\\\\{x}", "\\\\\\{x}"),
            // `\Q…\E`.
            ("^\\Qa.b{1}\\E$", "^a\\.b\\{1\\}$"),
            ("\\Q{", "\\{"),
            ("\\Qé<\\E", "é<"),
            ("\\\\Q.", "\\\\Q."),
            ("é{x}", "é\\{x}"),
        ] {
            assert_eq!(translate(pattern), want, "{pattern}");
            // Idempotent.
            assert_eq!(translate(want), want, "{want}");
        }
    }

    #[test]
    fn translated_patterns_compile_and_match_as_in_pcre() {
        // Subjects that match in full, from a PCRE2 10.46 run.
        for (pattern, matching, not) in [
            ("^/a{x}(.*)$", "/a{x}/b", "/aa/b"),
            ("^a{,2}$", "aa", "aaa"),
            ("^a{ 2 }$", "aa", "a{ 2 }"),
            ("^a}$", "a}", "a"),
            ("^a{2}}$", "aa}", "aa"),
            ("^a*{x}$", "a{x}", "aa"),
        ] {
            let re = regex::bytes::Regex::new(&translate(pattern)).unwrap();
            assert!(re.is_match(matching.as_bytes()), "{pattern} {matching}");
            assert!(!re.is_match(not.as_bytes()), "{pattern} {not}");
        }
        // Errors in PCRE too.
        for pattern in ["{2}", "a{2,1}"] {
            assert!(
                regex::bytes::Regex::new(&translate(pattern)).is_err(),
                "{pattern}"
            );
        }
    }

    #[test]
    fn untouched_patterns_are_borrowed() {
        assert!(matches!(
            translate("^/static/(.*)\\.(css|js)$"),
            std::borrow::Cow::Borrowed(_)
        ));
    }
}
