//! nginx hands configuration regexes to PCRE2 unchanged; the `regex` crate
//! reads some PCRE syntax differently. `translate` rewrites those parts
//! before every compile.
//!
//! nginx compiles without UTF mode (`ngx_regex_compile` sets only
//! CASELESS/MULTILINE), so a pattern matches bytes: `.` and negated
//! classes match any byte, `\w \d \s \b` and `(?i)` are ASCII (PCRE's
//! default tables). [`regex`] and [`regex_set`] build them so (#797).

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

/// `pattern` in the terms the `regex` crate accepts outside Unicode mode:
/// - a non-ASCII char is spelled as its UTF-8 bytes. Byte by byte is what
///   PCRE sees: `é+` repeats the last byte, `[é]` is a class of two bytes;
/// - `\x{HH}` is a byte (the crate reads it as a char);
/// - `\p{..}` / `\P{..}` is the class of bytes whose Latin-1 char has the
///   property, as PCRE does without UTF (`http_server_name.t` uses
///   `\p{N}`). Caseless, PCRE's `\p{Lu}` takes lowercase Latin-1 too;
///   this folds ASCII only;
/// - inside a class, `[`, `&&` and `~~` are literals, not the crate's
///   set operators.
fn bytes_pattern(pattern: &str) -> Cow<'_, str> {
    if pattern.is_ascii()
        && !["\\x{", "\\p", "\\P", "["]
            .iter()
            .any(|e| pattern.contains(e))
    {
        return Cow::Borrowed(pattern);
    }
    let mut out = String::with_capacity(pattern.len() * 2);
    let mut chars = pattern.chars();
    let mut in_class = false;
    while let Some(c) = chars.next() {
        let c = match c {
            '[' if !in_class => {
                in_class = true;
                out.push('[');
                // `[^]...]` and `[]...]`: the `]` is a member.
                let rest = chars.as_str();
                let lead = if rest.starts_with("^]") {
                    2
                } else {
                    usize::from(rest.starts_with(['^', ']']))
                };
                out.push_str(&rest[..lead]);
                chars = rest[lead..].chars();
                continue;
            }
            '[' if chars.as_str().starts_with(':') => {
                // A POSIX class, `[:alpha:]`, inside a class.
                let rest = chars.as_str();
                let end = rest.find(":]").map_or(0, |e| e + 2);
                out.push('[');
                out.push_str(&rest[..end]);
                chars = rest[end..].chars();
                continue;
            }
            ']' if in_class => {
                in_class = false;
                ']'
            }
            // Set operators and nested classes to the crate, literals to PCRE.
            '[' | '&' | '~' if in_class => {
                out.push('\\');
                c
            }
            // An escaped ASCII char stays an escape; `\é` is a literal.
            '\\' => match chars.next() {
                Some('x') if chars.as_str().starts_with('{') => {
                    let rest = chars.as_str();
                    match braced_byte(rest) {
                        Some((b, len)) => {
                            push_byte(&mut out, b);
                            chars = rest[len..].chars();
                        }
                        None => out.push_str("\\x"),
                    }
                    continue;
                }
                Some(p @ ('p' | 'P')) => {
                    let rest = chars.as_str();
                    match property_bytes(rest, p == 'P') {
                        Some((set, len)) => {
                            push_byte_class(&mut out, &set, in_class);
                            chars = rest[len..].chars();
                        }
                        // The crate refuses it: an error at -t.
                        None => {
                            out.push('\\');
                            out.push(p);
                        }
                    }
                    continue;
                }
                Some(next) if next.is_ascii() => {
                    out.push('\\');
                    out.push(next);
                    continue;
                }
                Some(next) => next,
                None => {
                    out.push('\\');
                    break;
                }
            },
            c => c,
        };
        if c.is_ascii() {
            out.push(c);
        } else {
            for b in c.encode_utf8(&mut [0; 4]).bytes() {
                push_byte(&mut out, b);
            }
        }
    }
    Cow::Owned(out)
}

fn push_byte(out: &mut String, b: u8) {
    out.push_str(&format!("\\x{b:02X}"));
}

/// The byte of `{HH}` at the start of `s`, and the length it takes.
fn braced_byte(s: &str) -> Option<(u8, usize)> {
    let (hex, _) = s.strip_prefix('{')?.split_once('}')?;
    Some((u8::from_str_radix(hex, 16).ok()?, hex.len() + 2))
}

/// The bytes of `\p` / `\P` (`negated`) followed by `s`: `{Name}`,
/// `{^Name}` or a one-letter `L`. With the length of the name taken.
fn property_bytes(s: &str, negated: bool) -> Option<([bool; 256], usize)> {
    let (name, len) = match s.strip_prefix('{') {
        Some(braced) => {
            let (name, _) = braced.split_once('}')?;
            (name, name.len() + 2)
        }
        None => (s.get(..1)?, 1),
    };
    let (name, negated) = match name.strip_prefix('^') {
        Some(name) => (name, !negated),
        None => (name, negated),
    };
    let class = regex::Regex::new(&format!(r"\A\p{{{name}}}\z")).ok()?;
    let mut set = [false; 256];
    for (b, member) in set.iter_mut().enumerate() {
        let c = char::from(b as u8);
        *member = class.is_match(c.encode_utf8(&mut [0; 4])) != negated;
    }
    Some((set, len))
}

/// `set` as class items (inside a class) or as a class of its own.
fn push_byte_class(out: &mut String, set: &[bool; 256], in_class: bool) {
    if !in_class {
        out.push('[');
    }
    let mut b = 0;
    while b < 256 {
        if !set[b] {
            b += 1;
            continue;
        }
        let start = b;
        while b < 256 && set[b] {
            b += 1;
        }
        push_byte(out, start as u8);
        if b - 1 > start {
            out.push('-');
            push_byte(out, (b - 1) as u8);
        }
    }
    if !in_class {
        if !set.contains(&true) {
            // Nothing matches.
            out.push_str("^\\x00-\\xFF");
        }
        out.push(']');
    }
}

/// One regex as nginx's PCRE would match it.
pub(crate) fn regex(
    pattern: &str,
    case_insensitive: bool,
) -> Result<regex::bytes::Regex, regex::Error> {
    regex::bytes::RegexBuilder::new(&bytes_pattern(&translate(pattern)))
        .unicode(false)
        .case_insensitive(case_insensitive)
        .build()
}

/// A set of regexes, each matching as [`regex`] would build it: the
/// patterns are translated already (`worker::prepare::set_pattern`).
pub(crate) fn regex_set<'a>(
    patterns: impl IntoIterator<Item = &'a str>,
) -> Result<regex::bytes::RegexSet, regex::Error> {
    regex::bytes::RegexSetBuilder::new(patterns.into_iter().map(bytes_pattern))
        .unicode(false)
        .build()
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

#[cfg(test)]
mod bytes_tests {
    use super::*;

    fn m(pattern: &str, ci: bool, subject: &[u8]) -> bool {
        regex(pattern, ci).unwrap().is_match(subject)
    }

    // Expectations checked against PCRE2 10.46 as nginx 1.30.6 runs it.
    #[test]
    fn any_byte_matches() {
        assert!(m("^/private/.*$", false, b"/private/\xFF"));
        assert!(m("^/p/[^/]+$", false, b"/p/\xE9"));
        assert!(m("^/p/.$", false, b"/p/\x80"));
        // One byte, not one char.
        assert!(!m("^/p/.$", false, "/p/é".as_bytes()));
        assert!(m("^/p/..$", false, "/p/é".as_bytes()));
        assert!(!m("^.$", false, b"\n"));
    }

    #[test]
    fn classes_are_ascii() {
        assert!(m(r"^\w+$", false, b"az_09AZ"));
        assert!(!m(r"\w", false, "é".as_bytes()));
        assert!(!m(r"\w", false, b"\xE9"));
        assert!(m(r"^\W\W$", false, "é".as_bytes()));
        assert!(!m(r"\d", false, "٣".as_bytes()));
        assert!(m(r"^\s{6}$", false, b" \t\n\x0B\x0C\r"));
        assert!(!m(r"\s", false, "\u{a0}".as_bytes()));
        assert!(!m(r"\s", false, b"\x85"));
        // `é` is not a word char, so a boundary falls inside "aé".
        assert!(m(r"a\b", false, "aé".as_bytes()));
        assert!(m(r"^[[:alpha:]]+$", false, b"abc"));
        assert!(!m(r"[[:alpha:]]", false, b"\xE9"));
    }

    #[test]
    fn case_folding_is_ascii() {
        assert!(m("^/ABC$", true, b"/abc"));
        assert!(m("(?i)^/abc$", false, b"/ABC"));
        assert!(m("^/a(?i:b)c$", false, b"/aBc"));
        assert!(!m("^/a(?i:b)c$", false, b"/aBC"));
        // No Unicode folding: K is not the Kelvin sign, É not é.
        assert!(!m("k", true, "\u{212a}".as_bytes()));
        assert!(!m("é", true, "É".as_bytes()));
        assert!(!m("s", true, "ſ".as_bytes()));
    }

    #[test]
    fn non_ascii_literals_are_their_bytes() {
        assert!(m("^/café$", false, "/café".as_bytes()));
        assert!(m("^/café$", true, "/CAFé".as_bytes()));
        assert!(!m("^/café$", false, b"/caf\xE9"));
        assert!(m(r"^/caf\é$", false, "/café".as_bytes()));
        // A quantifier repeats the last byte.
        assert!(m("^é+$", false, b"\xC3\xA9\xA9\xA9"));
        assert!(!m("^é+$", false, "éé".as_bytes()));
        // A class holds each byte.
        assert!(m("^[é]$", false, b"\xA9"));
        assert!(m("^[^é]$", false, b"\xE9"));
        assert!(!m("^[^é]$", false, b"\xC3"));
    }

    #[test]
    fn captures_and_escapes() {
        let re = regex(r"^/(?<name>[^/]+)/(?P<rest>.*)$", false).unwrap();
        let c = re.captures(b"/\xFF/caf\xE9").unwrap();
        assert_eq!(&c["name"], b"\xFF");
        assert_eq!(&c["rest"], b"caf\xE9");
        assert!(m(r"^\\é$", false, "\\é".as_bytes()));
        assert!(m(r"^\xe9$", false, b"\xE9"));
        assert!(m(r"^\x{e9}$", false, b"\xE9"));
        // After `translate`: `\Q…\E` and a literal `{`.
        assert!(m(r"^/\Qcafé.{1}\E$", false, "/café.{1}".as_bytes()));
        assert!(m(r"^/a{x}/.$", false, b"/a{x}/\xFF"));
    }

    #[test]
    fn properties_are_latin1_bytes() {
        assert!(m(r"^www\p{N}+$", false, b"www1\xB2"));
        assert!(m(r"^\p{L}$", false, b"\xE9"));
        assert!(!m(r"^\p{L}$", false, "é".as_bytes()));
        assert!(m(r"^\P{L}$", false, b"1"));
        assert!(!m(r"^\p{^L}$", false, b"a"));
        assert!(m(r"^\pN$", false, b"7"));
        assert!(m(r"^[\p{L}_]+$", false, b"a_\xE9"));
        assert!(!m(r"^[^\p{L}]$", false, b"\xE9"));
        assert!(m(r"^\p{Lu}$", true, b"a"));
        assert!(regex(r"\p{Nope}", false).is_err());
    }

    #[test]
    fn class_punctuation_is_literal() {
        assert!(m("^[[]$", false, b"["));
        assert!(m("^[a&&b]$", false, b"&"));
        assert!(m("^[~-]$", false, b"~"));
        assert!(m("^[]a]$", false, b"]"));
        assert!(m("^[^]a]$", false, b"b"));
        assert!(!m("^[^]a]$", false, b"]"));
        assert!(m("^[[:digit:]x]+$", false, b"1x2"));
    }

    #[test]
    fn set_matches_as_the_regexes() {
        let set = regex_set(["^/a/.*$", "(?i:^/É)", "^/b$"]).unwrap();
        assert_eq!(set.matches(b"/a/\xFF").iter().next(), Some(0));
        assert_eq!(set.matches("/É".as_bytes()).iter().next(), Some(1));
        assert!(!set.is_match("/é".as_bytes()));
    }
}
