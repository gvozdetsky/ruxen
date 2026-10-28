//! Regexes compiled as nginx compiles them for PCRE: without UTF mode
//! (`ngx_regex_compile` sets only CASELESS/MULTILINE), so a pattern
//! matches bytes. `.` and negated classes match any byte, `\w \d \s \b`
//! and `(?i)` are ASCII (PCRE's default tables), and a non-ASCII char in
//! the pattern stands for its UTF-8 bytes (#797).

use std::borrow::Cow;

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
    regex::bytes::RegexBuilder::new(&bytes_pattern(pattern))
        .unicode(false)
        .case_insensitive(case_insensitive)
        .build()
}

/// A set of regexes, each matching as [`regex`] would build it.
pub(crate) fn regex_set<'a>(
    patterns: impl IntoIterator<Item = &'a str>,
) -> Result<regex::bytes::RegexSet, regex::Error> {
    regex::bytes::RegexSetBuilder::new(patterns.into_iter().map(bytes_pattern))
        .unicode(false)
        .build()
}

#[cfg(test)]
mod tests {
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
