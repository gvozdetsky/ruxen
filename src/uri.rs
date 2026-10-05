// URI decoding + path normalization.
//
// Port of nginx's ngx_http_parse_complex_uri (src/http/ngx_http_parse.c:1285).
// Given a raw request URI, produce the normalized path ready for filesystem
// lookup and the offset of the query string (if any). The six-state machine —
// sw_usual / sw_slash / sw_dot / sw_dot_dot / sw_quoted / sw_quoted_second —
// handles the subtle interaction between percent-decoding and path
// normalization that makes directory traversal via `%2e%2e` just as
// detectable as via literal `..`.
//
// Security invariant: a normalized path with a resolvable `..` that would
// back up past the root returns `UriError::EscapesRoot`, not a path — the
// caller must treat any non-Ok return as a 400/403.

#[derive(Debug, PartialEq, Eq)]
pub enum UriError {
    NotAbsolute,
    BadEscape,
    NulByte,
    TrailingPercent,
    EscapesRoot,
}

#[derive(Copy, Clone)]
enum State {
    Usual,
    Slash,
    Dot,
    DotDot,
    Quoted,
    QuotedSecond,
}

/// Offset into the *original* input past the `?` separator, or `None`
/// if the URI had no query string. Callers that don't care about the
/// query can ignore it.
pub type QueryStart = Option<usize>;

#[cfg(test)]
pub fn normalize(input: &[u8], out: &mut Vec<u8>) -> Result<QueryStart, UriError> {
    normalize_with(input, true, out)
}

/// As `normalize`, but lets the caller toggle nginx's `merge_slashes`
/// behavior. When `false`, `//` stays as `//` (the Slash state re-enters
/// Slash without discarding) and `..` only walks back one segment, even
/// if that segment is empty. Tests in `merge_slashes.t` cover the
/// difference: `/foo//../bar` becomes `/foo/bar` with merging off
/// (the `..` eats the empty segment between `//`) instead of `/bar`.
///
/// Writes the normalized path bytes into `out`, appending past whatever
/// was already there. Callers that want only the normalized result should
/// `out.clear()` first; passing a reusable scratch buffer lets the hot
/// path skip per-request allocation.
pub fn normalize_with(
    input: &[u8],
    merge_slashes: bool,
    out: &mut Vec<u8>,
) -> Result<QueryStart, UriError> {
    if !input.starts_with(b"/") {
        return Err(UriError::NotAbsolute);
    }

    // Fast path: for URIs that contain nothing the state machine would
    // transform — no percent-decoding, no query/fragment split, no
    // duplicate slashes, no dot-segments — the normalized output is
    // byte-identical to the input. Dot-segment handling only matters
    // when a `.` immediately follows a `/`, so we check for the `/.`
    // substring specifically (letting `/hello.txt` take the fast path).
    // URI-char validity was already enforced by the HTTP parser.
    if is_already_normalized(input) {
        out.extend_from_slice(input);
        return Ok(None);
    }

    out.reserve(input.len());
    // Emit the leading '/' unconditionally and start the state machine at
    // sw_slash so the first char is checked against slash-context rules.
    let out_base = out.len();
    out.push(b'/');
    let mut state = State::Slash;
    let mut quoted_state = State::Usual;
    let mut decoded: u8 = 0;
    let mut query_start: Option<usize> = None;

    let mut i = 1usize;
    while i < input.len() {
        let ch = input[i];
        i += 1;
        match state {
            State::Usual => match ch {
                b'/' => {
                    state = State::Slash;
                    out.push(b'/');
                }
                b'%' => {
                    quoted_state = State::Usual;
                    state = State::Quoted;
                }
                b'?' => {
                    query_start = Some(i);
                    break;
                }
                b'#' => break,
                c => out.push(c),
            },
            State::Slash => match ch {
                b'/' => {
                    // With merge_slashes on (default), `//` collapses — no
                    // push. With it off, `//` stays literal: push the new
                    // slash and re-enter Slash so the next char sees
                    // slash-context rules.
                    if !merge_slashes {
                        out.push(b'/');
                    }
                }
                b'.' => {
                    state = State::Dot;
                    out.push(b'.');
                }
                b'%' => {
                    quoted_state = State::Slash;
                    state = State::Quoted;
                }
                b'?' => {
                    query_start = Some(i);
                    break;
                }
                b'#' => break,
                c => {
                    state = State::Usual;
                    out.push(c);
                }
            },
            State::Dot => match ch {
                b'/' => {
                    // "/./" collapses. Drop the trailing '.' we wrote, stay
                    // in Slash for the next segment.
                    state = State::Slash;
                    out.pop();
                }
                b'.' => {
                    state = State::DotDot;
                    out.push(b'.');
                }
                b'%' => {
                    quoted_state = State::Dot;
                    state = State::Quoted;
                }
                b'?' => {
                    // "/.\?" — drop the trailing '.' like nginx does. Reset
                    // state so the trailing-state handler below doesn't
                    // pop a second time.
                    out.pop();
                    state = State::Slash;
                    query_start = Some(i);
                    break;
                }
                b'#' => {
                    out.pop();
                    state = State::Slash;
                    break;
                }
                c => {
                    state = State::Usual;
                    out.push(c);
                }
            },
            State::DotDot => match ch {
                b'/' | b'?' | b'#' => {
                    // Unwind `/..`. nginx (ngx_http_parse_complex_uri's
                    // sw_dot_dot `/` arm) does `u -= 4` then walks *u
                    // backward until it finds `/`, leaving u one past that
                    // slash. Crucially, the test at u happens *before* any
                    // decrement — so if `u[-4]` is already `/` (which is
                    // exactly the merge_slashes=off `/foo//..` case), we
                    // stop there and keep the slash. Mirror that here with
                    // an in-place truncate pointer so merge-on and
                    // merge-off both produce the right segment boundary.
                    // `out_base` is the floor: the caller may have pre-
                    // existing bytes before our leading '/', so we only
                    // walk back within the current path's span.
                    if out.len() - out_base < 4 {
                        return Err(UriError::EscapesRoot);
                    }
                    let mut j = out.len() - 4;
                    loop {
                        if out[j] == b'/' {
                            j += 1;
                            break;
                        }
                        if j == out_base {
                            return Err(UriError::EscapesRoot);
                        }
                        j -= 1;
                    }
                    out.truncate(j);
                    // Reset state before break so the trailing-state handler
                    // doesn't re-run the DotDot unwind on an already-
                    // unwound path.
                    state = State::Slash;
                    match ch {
                        b'?' => {
                            query_start = Some(i);
                            break;
                        }
                        b'#' => break,
                        _ => {}
                    }
                }
                b'%' => {
                    quoted_state = State::DotDot;
                    state = State::Quoted;
                }
                c => {
                    state = State::Usual;
                    out.push(c);
                }
            },
            State::Quoted => {
                let hv = hex(ch).ok_or(UriError::BadEscape)?;
                decoded = hv;
                state = State::QuotedSecond;
            }
            State::QuotedSecond => {
                let lv = hex(ch).ok_or(UriError::BadEscape)?;
                let byte = (decoded << 4) | lv;
                if byte == 0 {
                    return Err(UriError::NulByte);
                }
                // nginx (ngx_http_parse.c:1561-1583) short-circuits decoded
                // '%', '#', '?' as literals so they can't re-trigger the
                // metachar logic; everything else (including '+') flows back
                // through the state machine via `state = quoted_state`. For
                // '/' and '.' this is what makes `%2e%2e` equivalent to `..`
                // and catches the traversal.
                match byte {
                    b'%' | b'#' | b'?' => {
                        out.push(byte);
                        state = State::Usual;
                    }
                    _ => {
                        state = quoted_state;
                        feed(byte, &mut state, out, out_base, merge_slashes)?;
                    }
                }
            }
        }
    }

    // Handle trailing state. nginx does the same unwinding at the bottom of
    // the function for sw_dot and sw_dot_dot.
    match state {
        State::Dot => {
            out.pop();
        }
        State::DotDot => {
            if out.len() - out_base < 4 {
                return Err(UriError::EscapesRoot);
            }
            let mut j = out.len() - 4;
            loop {
                if out[j] == b'/' {
                    j += 1;
                    break;
                }
                if j == out_base {
                    return Err(UriError::EscapesRoot);
                }
                j -= 1;
            }
            out.truncate(j);
        }
        State::Quoted | State::QuotedSecond => return Err(UriError::TrailingPercent),
        _ => {}
    }

    Ok(query_start)
}

/// Quick check for whether `input` needs no transformation — i.e. the
/// state machine would emit it byte-for-byte. Requires a leading `/`
/// (already checked by the caller) and absence of:
///   - `%` — would trigger percent-decoding.
///   - `?` / `#` — would split off query/fragment and stop the copy.
///   - `//` — would collapse under `merge_slashes=on` or re-enter the
///     Slash state under `merge_slashes=off` (same output in both cases
///     only when absent).
///   - `/.` — may start a `/./`, `/..`, or trailing `/.` sequence that
///     the Dot/DotDot states would rewrite. Rejecting the substring
///     handles all four cases (including the trailing-state pop) without
///     needing a full scan. Bare `.` elsewhere (e.g. `/hello.txt`) stays
///     in the Usual state and emits verbatim.
#[inline]
fn is_already_normalized(input: &[u8]) -> bool {
    // Walk once with a tiny window instead of multiple `.contains()`
    // passes: we care about single-byte and the two-byte pairs `//` and
    // `/.`. Skipping the leading `/` avoids tripping on it.
    let mut prev = 0u8;
    for (i, &b) in input.iter().enumerate() {
        match b {
            b'%' | b'?' | b'#' => return false,
            _ => {}
        }
        if i > 0 && prev == b'/' && (b == b'/' || b == b'.') {
            return false;
        }
        prev = b;
    }
    true
}

/// Push one decoded byte through the state machine. Only ever invoked from
/// the %-decode branch, so we know the incoming `state` is one of Usual,
/// Slash, Dot, DotDot — never Quoted. The byte is the decoded value and is
/// known not to be %, #, ?, or + (those are handled as literals above).
///
/// This mirrors what nginx achieves by letting the outer loop re-enter the
/// switch on the decoded byte.
fn feed(
    byte: u8,
    state: &mut State,
    out: &mut Vec<u8>,
    out_base: usize,
    merge_slashes: bool,
) -> Result<(), UriError> {
    match *state {
        State::Usual => match byte {
            b'/' => {
                *state = State::Slash;
                out.push(b'/');
            }
            c => out.push(c),
        },
        State::Slash => match byte {
            b'/' => {
                // Mirror the main loop: only collapse when merging is on.
                if !merge_slashes {
                    out.push(b'/');
                }
            }
            b'.' => {
                *state = State::Dot;
                out.push(b'.');
            }
            c => {
                *state = State::Usual;
                out.push(c);
            }
        },
        State::Dot => match byte {
            b'/' => {
                *state = State::Slash;
                out.pop();
            }
            b'.' => {
                *state = State::DotDot;
                out.push(b'.');
            }
            c => {
                *state = State::Usual;
                out.push(c);
            }
        },
        State::DotDot => match byte {
            b'/' => {
                if out.len() - out_base < 4 {
                    return Err(UriError::EscapesRoot);
                }
                let mut j = out.len() - 4;
                loop {
                    if out[j] == b'/' {
                        j += 1;
                        break;
                    }
                    if j == out_base {
                        return Err(UriError::EscapesRoot);
                    }
                    j -= 1;
                }
                out.truncate(j);
                *state = State::Slash;
            }
            c => {
                *state = State::Usual;
                out.push(c);
            }
        },
        // Quoted / QuotedSecond can't reach here by construction.
        State::Quoted | State::QuotedSecond => unreachable!(),
    }
    Ok(())
}

#[inline]
/// nginx's ngx_http_parse_unsafe_uri, for an X-Accel-Redirect path (the
/// part before `?`): empty, `..` as a whole segment at the start or after
/// a `/`, or a NUL, as written or once percent-decoded.
pub fn is_unsafe(path: &[u8]) -> bool {
    fn unsafe_as_is(p: &[u8]) -> bool {
        let dot_dot_at =
            |i: usize| p[i..].starts_with(b"..") && (p.len() == i + 2 || p[i + 2] == b'/');
        dot_dot_at(0) || p.contains(&0) || (0..p.len()).any(|i| p[i] == b'/' && dot_dot_at(i + 1))
    }
    if path.is_empty() || unsafe_as_is(path) {
        return true;
    }
    if !path.contains(&b'%') {
        return false;
    }
    // ngx_unescape_uri: `%XX` decodes, anything else stays.
    let mut decoded = Vec::with_capacity(path.len());
    let mut i = 0;
    while i < path.len() {
        if path[i] == b'%'
            && let (Some(hi), Some(lo)) = (
                path.get(i + 1).copied().and_then(hex),
                path.get(i + 2).copied().and_then(hex),
            )
        {
            decoded.push(hi << 4 | lo);
            i += 3;
        } else {
            decoded.push(path[i]);
            i += 1;
        }
    }
    unsafe_as_is(&decoded)
}

fn hex(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsafe_uris_as_nginx() {
        for p in [
            &b""[..],
            b"..",
            b"../foo",
            b"/..",
            b"/foo/..",
            b"/foo/../bar",
            b"/foo/.%2e",
            b"/foo/%2E%2E/bar",
            b"%2e%2e",
            b"/a\0b",
            b"/a%00b",
        ] {
            assert!(is_unsafe(p), "{:?}", String::from_utf8_lossy(p));
        }
        for p in [
            &b"/"[..],
            b"/index.html",
            b"/foo bar",
            b"/foo%20bar",
            b"/..foo",
            b"/foo..",
            b"/foo/...",
            b"/foo/./bar",
            b"@named",
            b"/100%",
        ] {
            assert!(!is_unsafe(p), "{:?}", String::from_utf8_lossy(p));
        }
    }

    fn norm(s: &[u8]) -> Result<Vec<u8>, UriError> {
        let mut out = Vec::new();
        normalize(s, &mut out)?;
        Ok(out)
    }

    fn norm_full(s: &[u8]) -> Result<(Vec<u8>, QueryStart), UriError> {
        let mut out = Vec::new();
        let q = normalize(s, &mut out)?;
        Ok((out, q))
    }

    fn norm_with(s: &[u8], merge_slashes: bool) -> Result<Vec<u8>, UriError> {
        let mut out = Vec::new();
        normalize_with(s, merge_slashes, &mut out)?;
        Ok(out)
    }

    #[test]
    fn passthrough_simple() {
        assert_eq!(norm(b"/").unwrap(), b"/");
        assert_eq!(norm(b"/foo").unwrap(), b"/foo");
        assert_eq!(norm(b"/foo/bar.html").unwrap(), b"/foo/bar.html");
    }

    #[test]
    fn merges_double_slashes() {
        assert_eq!(norm(b"//foo").unwrap(), b"/foo");
        assert_eq!(norm(b"/foo//bar").unwrap(), b"/foo/bar");
        assert_eq!(norm(b"/a//b//c").unwrap(), b"/a/b/c");
    }

    #[test]
    fn strips_dot_segments() {
        assert_eq!(norm(b"/./foo").unwrap(), b"/foo");
        assert_eq!(norm(b"/foo/./bar").unwrap(), b"/foo/bar");
        assert_eq!(norm(b"/foo/.").unwrap(), b"/foo/");
    }

    #[test]
    fn resolves_dot_dot() {
        assert_eq!(norm(b"/foo/../bar").unwrap(), b"/bar");
        assert_eq!(norm(b"/a/b/../c").unwrap(), b"/a/c");
        assert_eq!(norm(b"/a/b/..").unwrap(), b"/a/");
    }

    #[test]
    fn rejects_dot_dot_escape() {
        assert_eq!(norm(b"/..").unwrap_err(), UriError::EscapesRoot);
        assert_eq!(norm(b"/../foo").unwrap_err(), UriError::EscapesRoot);
        assert_eq!(norm(b"/a/../../b").unwrap_err(), UriError::EscapesRoot);
    }

    #[test]
    fn percent_decodes() {
        assert_eq!(norm(b"/foo%20bar").unwrap(), b"/foo bar");
        assert_eq!(norm(b"/%41%42").unwrap(), b"/AB");
        assert_eq!(norm(b"/caf%C3%A9").unwrap(), "/café".as_bytes());
    }

    #[test]
    fn encoded_dot_dot_is_blocked() {
        // %2e = '.'. This is THE directory-traversal bug class.
        assert_eq!(
            norm(b"/%2e%2e/etc/passwd").unwrap_err(),
            UriError::EscapesRoot
        );
        assert_eq!(
            norm(b"/foo/%2E%2E/%2E%2E/etc").unwrap_err(),
            UriError::EscapesRoot
        );
    }

    #[test]
    fn encoded_slash_stays_literal_and_then_normalizes() {
        // %2f = '/'. After decoding, it's treated as a slash, so we DO
        // merge/normalize — same as nginx's `%2f` handling in complex_uri.
        assert_eq!(norm(b"/a%2fb").unwrap(), b"/a/b");
    }

    #[test]
    fn encoded_slash_respects_merge_slashes_off() {
        // With merge_slashes=off, a decoded '/' arriving in Slash state must
        // emit the literal slash rather than collapse. Regression for a bug
        // where feed() always merged.
        assert_eq!(norm_with(b"/a/%2f", false).unwrap(), b"/a//");
        // And the merge_slashes=on path still collapses.
        assert_eq!(norm_with(b"/a/%2f", true).unwrap(), b"/a/");
    }

    #[test]
    fn encoded_question_stays_literal() {
        // A decoded '?' must NOT start the query string — it's a literal
        // in the path. Nginx explicitly writes it out as sw_usual.
        assert_eq!(norm(b"/a%3Fb").unwrap(), b"/a?b");
    }

    #[test]
    fn encoded_nul_rejected() {
        assert_eq!(norm(b"/%00").unwrap_err(), UriError::NulByte);
        assert_eq!(norm(b"/foo%00bar").unwrap_err(), UriError::NulByte);
    }

    #[test]
    fn bad_escape_rejected() {
        assert_eq!(norm(b"/%GG").unwrap_err(), UriError::BadEscape);
        assert_eq!(norm(b"/%2").unwrap_err(), UriError::TrailingPercent);
        assert_eq!(norm(b"/%").unwrap_err(), UriError::TrailingPercent);
    }

    #[test]
    fn rejects_non_absolute() {
        assert_eq!(norm(b"foo").unwrap_err(), UriError::NotAbsolute);
        assert_eq!(norm(b"").unwrap_err(), UriError::NotAbsolute);
    }

    #[test]
    fn strips_query_string() {
        let (path, q) = norm_full(b"/foo?bar=1").unwrap();
        assert_eq!(path, b"/foo");
        // '?' is at byte 4; first query byte is at 5.
        assert_eq!(q, Some(5));
        assert_eq!(&b"/foo?bar=1"[5..], b"bar=1");
    }

    #[test]
    fn strips_fragment() {
        let (path, q) = norm_full(b"/foo#bar").unwrap();
        assert_eq!(path, b"/foo");
        assert_eq!(q, None);
    }

    #[test]
    fn trailing_dot_segments() {
        assert_eq!(norm(b"/foo/").unwrap(), b"/foo/");
        assert_eq!(norm(b"/foo/.").unwrap(), b"/foo/");
    }

    #[test]
    fn dot_segments_before_query_or_fragment_normalize() {
        // Regression: earlier these ended up with an extra trailing byte
        // popped because the `?`/`#` arms broke without resetting state,
        // and the trailing-state handler then ran a second pop.
        let (path, q) = norm_full(b"/foo/bar/.?args").unwrap();
        assert_eq!(path, b"/foo/bar/");
        assert_eq!(q, Some(11));
        let (path, q) = norm_full(b"/foo/bar/.#frag").unwrap();
        assert_eq!(path, b"/foo/bar/");
        assert_eq!(q, None);
        let (path, q) = norm_full(b"/foo/bar/..?args").unwrap();
        assert_eq!(path, b"/foo/");
        assert_eq!(q, Some(12));
        let (path, q) = norm_full(b"/foo/bar/..#frag").unwrap();
        assert_eq!(path, b"/foo/");
        assert_eq!(q, None);
    }

    #[test]
    fn appends_into_non_empty_scratch() {
        // Caller passes scratch with prior bytes; normalize_with should
        // only write past its own base and unwind stops at that floor.
        let mut out = b"PRE/".to_vec();
        let base = out.len();
        normalize(b"/a/../b", &mut out).unwrap();
        assert_eq!(&out[..base], b"PRE/");
        assert_eq!(&out[base..], b"/b");

        // `..` beyond the inserted path fails even if earlier scratch
        // bytes look like a segment — the floor is strict.
        let mut out = b"/prev/".to_vec();
        assert_eq!(
            normalize(b"/..", &mut out).unwrap_err(),
            UriError::EscapesRoot
        );
    }
}
