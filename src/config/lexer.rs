//! Hand-written tokenizer + `read_directive` driver. Frame stack supports
//! `include` directives with relative paths resolved against the main
//! config's directory. Maintains the `nginx -T` dump-order list as a side
//! effect of resolving frames.

use super::*;

/// One stack frame in the lexer — a single source file (or synthetic inline
/// chunk) currently being tokenized. `include` pushes a new frame; we pop on
/// EOF and resume the parent. The originating file path is captured at
/// `push_include` time and pushed straight into `dump_files`; relative
/// include targets resolve against the main config's directory (not the
/// including file's), so the per-frame path isn't needed at lex time.
pub(crate) struct LexerFrame {
    bytes: Vec<u8>,
    pos: usize,
    /// Where errors say they are: the file, or `None` for `-g` (nginx's
    /// "command line") and inline test parses.
    name: Option<std::rc::Rc<str>>,
    /// Offset of the last directive's terminator, for its line number
    /// (nginx reports the line it was reading when the error came up).
    last_end: usize,
}

pub(crate) struct Lexer {
    frames: Vec<LexerFrame>,
    /// Directory of the main config file — nginx's `cycle->conf_prefix`.
    /// `None` for inline test parses.
    conf_prefix: Option<PathBuf>,
    dump_files: Vec<DumpFile>,
    dump_seen: std::collections::HashSet<PathBuf>,
    /// `[warn]` lines from directives parsed so far.
    warnings: Vec<String>,
}

impl Lexer {
    #[cfg(test)]
    pub(crate) fn new_inline(src: &str) -> Self {
        Self {
            frames: vec![LexerFrame {
                bytes: src.as_bytes().to_vec(),
                pos: 0,
                name: None,
                last_end: 0,
            }],
            conf_prefix: None,
            dump_files: Vec::new(),
            dump_seen: std::collections::HashSet::new(),
            warnings: Vec::new(),
        }
    }

    pub(crate) fn new_with_main(path: PathBuf, src: String) -> Self {
        let mut s = Self {
            frames: Vec::new(),
            conf_prefix: path.parent().map(Path::to_path_buf),
            dump_files: Vec::new(),
            dump_seen: std::collections::HashSet::new(),
            warnings: Vec::new(),
        };
        s.dump_seen.insert(path.clone());
        let name = Some(std::rc::Rc::from(path.display().to_string()));
        s.dump_files.push(DumpFile {
            path,
            contents: src.clone(),
        });
        s.frames.push(LexerFrame {
            bytes: src.into_bytes(),
            pos: 0,
            name,
            last_end: 0,
        });
        s
    }

    /// Push an in-memory chunk onto the frame stack without recording it for
    /// the `-T` dump. Used for `-g` globals: directives take effect (the new
    /// frame is the top of stack and read first), but the main config's
    /// dump entry still contains only its on-disk contents.
    pub(crate) fn push_inline(&mut self, src: String) {
        self.frames.push(LexerFrame {
            bytes: src.into_bytes(),
            pos: 0,
            name: None,
            last_end: 0,
        });
    }

    /// Where the directive just read is, as nginx's `ngx_conf_log_error`
    /// puts it after a message: `/etc/nginx/nginx.conf:12`, or
    /// `command line` for `-g`. `None` for inline test parses.
    pub(crate) fn position(&self) -> Option<String> {
        let f = self.frames.last()?;
        let Some(name) = &f.name else {
            return (self.frames.len() > 1 || self.conf_prefix.is_some())
                .then(|| "command line".to_string());
        };
        let end = f.last_end.min(f.bytes.len());
        let line = 1 + f.bytes[..end].iter().filter(|&&b| b == b'\n').count();
        Some(format!("{name}:{line}"))
    }

    pub(crate) fn conf_prefix(&self) -> Option<&Path> {
        self.conf_prefix.as_deref()
    }

    pub(crate) fn take_dump_files(&mut self) -> Vec<DumpFile> {
        std::mem::take(&mut self.dump_files)
    }

    pub(crate) fn warn(&mut self, warning: String) {
        self.warnings.push(warning);
    }

    /// The `[warn]` lines so far, for a parser that adds each line once.
    pub(crate) fn warnings_mut(&mut self) -> &mut Vec<String> {
        &mut self.warnings
    }

    pub(crate) fn take_warnings(&mut self) -> Vec<String> {
        std::mem::take(&mut self.warnings)
    }

    fn skip_ws_and_comments(&mut self) {
        let f = self.frames.last_mut().unwrap();
        loop {
            while f.pos < f.bytes.len() && matches!(f.bytes[f.pos], b' ' | b'\t' | b'\r' | b'\n') {
                f.pos += 1;
            }
            if f.pos < f.bytes.len() && f.bytes[f.pos] == b'#' {
                while f.pos < f.bytes.len() && f.bytes[f.pos] != b'\n' {
                    f.pos += 1;
                }
            } else {
                return;
            }
        }
    }

    fn push_include(&mut self, raw_path: &str) -> Result<(), Error> {
        // The fuzz targets parse untrusted text: reading the files it names
        // (`include /dev/zero`) would only test the filesystem, or hang.
        if cfg!(feature = "fuzzing") {
            return Err(Error::IncludeOpen {
                path: raw_path.to_string(),
                reason: "include is disabled for fuzzing".to_string(),
            });
        }
        let path = PathBuf::from(raw_path);
        let resolved = if path.is_absolute() {
            path
        } else if let Some(prefix) = &self.conf_prefix {
            // nginx resolves relative include paths against the config
            // directory (`ngx_conf_full_name(cycle, file, 1)` in
            // `ngx_conf_include`), not the `-p` prefix.
            prefix.join(path)
        } else {
            // Inline test parses have no config file; fall back to cwd.
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join(path)
        };
        // A pattern (`*?[`, as ngx_conf_include tests it) includes every
        // file it matches, sorted, and none is fine (#35).
        let files = if resolved.to_string_lossy().contains(['*', '?', '[']) {
            glob(&resolved).map_err(|e| Error::IncludeOpen {
                path: resolved.display().to_string(),
                reason: format!("glob() failed: {e}"),
            })?
        } else {
            vec![resolved]
        };
        // Read them all first: the dump lists them in order, and the frames
        // go on the stack last first, so the first is read first.
        let mut frames = Vec::with_capacity(files.len());
        for resolved in files {
            let bytes = std::fs::read(&resolved).map_err(|e| Error::IncludeOpen {
                path: resolved.display().to_string(),
                reason: format!("{e}"),
            })?;
            crate::privileges::note_read(&resolved);
            let name = Some(std::rc::Rc::from(resolved.display().to_string()));
            let canonical = resolved.canonicalize().unwrap_or(resolved);
            let contents = String::from_utf8_lossy(&bytes).into_owned();
            if self.dump_seen.insert(canonical.clone()) {
                self.dump_files.push(DumpFile {
                    path: canonical,
                    contents,
                });
            }
            frames.push(LexerFrame {
                bytes,
                pos: 0,
                name,
                last_end: 0,
            });
        }
        self.frames.extend(frames.into_iter().rev());
        Ok(())
    }

    // Reads tokens up to (and consuming) the next terminator. Transparently
    // handles `include <path>;` by pushing a new frame and continuing; the
    // caller never sees an `include` directive.
    pub(crate) fn read_directive(&mut self) -> Result<(Vec<String>, Terminator), Error> {
        loop {
            let (args, term) = self.read_directive_one()?;
            super::note_defined_variables(&args);
            // EOF on a non-root frame: pop and continue reading from the parent.
            if args.is_empty() && matches!(term, Terminator::Eof) && self.frames.len() > 1 {
                self.frames.pop();
                continue;
            }
            // Transparent include: read file, push frame, keep reading.
            if matches!(term, Terminator::Semi)
                && args.first().map(String::as_str) == Some("include")
            {
                if args.len() != 2 {
                    return Err(Error::BadValue {
                        what: "include",
                        got: args.join(" "),
                    });
                }
                if let Err(err) = self.push_include(&args[1]) {
                    super::compat::include_failed(self, &args, err)?;
                }
                continue;
            }
            let mut args = args;
            super::compat::precheck(self, &mut args);
            if let Err(err) = super::reject_unenforced(&args, &term) {
                super::compat::unenforced(self, &args, err)?;
            }
            return Ok((args, term));
        }
    }

    fn read_directive_one(&mut self) -> Result<(Vec<String>, Terminator), Error> {
        let mut args: Vec<String> = Vec::new();

        loop {
            self.skip_ws_and_comments();
            let f = self.frames.last_mut().unwrap();
            if f.pos >= f.bytes.len() {
                f.last_end = f.pos;
                return if args.is_empty() {
                    Ok((args, Terminator::Eof))
                } else {
                    Err(Error::UnexpectedEof)
                };
            }

            match f.bytes[f.pos] {
                b';' => {
                    f.last_end = f.pos;
                    f.pos += 1;
                    return Ok((args, Terminator::Semi));
                }
                b'{' => {
                    f.last_end = f.pos;
                    f.pos += 1;
                    return Ok((args, Terminator::BlockOpen));
                }
                b'}' => {
                    f.last_end = f.pos;
                    if !args.is_empty() {
                        return Err(Error::UnexpectedToken("}".into()));
                    }
                    f.pos += 1;
                    return Ok((args, Terminator::BlockClose));
                }
                quote @ (b'"' | b'\'') => {
                    f.pos += 1;
                    let start = f.pos;
                    while f.pos < f.bytes.len() && f.bytes[f.pos] != quote {
                        // A backslash protects the next byte, so `\"`
                        // doesn't end the string.
                        if f.bytes[f.pos] == b'\\' && f.pos + 1 < f.bytes.len() {
                            f.pos += 1;
                        }
                        f.pos += 1;
                    }
                    if f.pos >= f.bytes.len() {
                        f.last_end = f.pos;
                        return Err(Error::UnterminatedString);
                    }
                    args.push(unescape(&f.bytes[start..f.pos]));
                    f.pos += 1;
                }
                _ => {
                    let start = f.pos;
                    while f.pos < f.bytes.len() {
                        if f.bytes[f.pos] == b'$'
                            && f.pos + 1 < f.bytes.len()
                            && f.bytes[f.pos + 1] == b'{'
                        {
                            f.pos += 2;
                            while f.pos < f.bytes.len() && f.bytes[f.pos] != b'}' {
                                f.pos += 1;
                            }
                            if f.pos < f.bytes.len() && f.bytes[f.pos] == b'}' {
                                f.pos += 1;
                            }
                            continue;
                        }
                        // As in quoted strings, a backslash protects the
                        // next byte: `a\;b` is one token.
                        if f.bytes[f.pos] == b'\\' && f.pos + 1 < f.bytes.len() {
                            f.pos += 2;
                            continue;
                        }
                        if matches!(
                            f.bytes[f.pos],
                            b' ' | b'\t' | b'\r' | b'\n' | b';' | b'{' | b'}'
                        ) {
                            break;
                        }
                        f.pos += 1;
                    }
                    args.push(unescape(&f.bytes[start..f.pos]));
                }
            }
        }
    }
}

/// The copy step of nginx's `ngx_conf_read_token`, applied to every token,
/// quoted or not: `\"`, `\'` and `\\` lose the backslash, `\t`, `\r` and
/// `\n` become the control characters, and any other pair (`\.` or `\d`
/// in a regex) is kept as written.
fn unescape(raw: &[u8]) -> String {
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == b'\\' && i + 1 < raw.len() {
            let replaced = match raw[i + 1] {
                c @ (b'"' | b'\'' | b'\\') => Some(c),
                b't' => Some(b'\t'),
                b'r' => Some(b'\r'),
                b'n' => Some(b'\n'),
                _ => None,
            };
            if let Some(c) = replaced {
                out.push(c);
                i += 2;
                continue;
            }
        }
        out.push(raw[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The paths `pattern` matches, as glob(3) with nginx's flags (none:
/// sorted, `*` doesn't match a leading dot) returns them; no match is an
/// empty list (ngx_open_glob with `test`).
fn glob(pattern: &Path) -> std::io::Result<Vec<PathBuf>> {
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    let c_pattern = std::ffi::CString::new(pattern.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let mut found: libc::glob_t = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::glob(c_pattern.as_ptr(), 0, None, &mut found) };
    let paths = match rc {
        0 => (0..found.gl_pathc)
            .map(|i| unsafe {
                let p = std::ffi::CStr::from_ptr(*found.gl_pathv.add(i));
                PathBuf::from(std::ffi::OsString::from_vec(p.to_bytes().to_vec()))
            })
            .collect(),
        libc::GLOB_NOMATCH => Vec::new(),
        _ => {
            unsafe { libc::globfree(&mut found) };
            return Err(std::io::Error::last_os_error());
        }
    };
    unsafe { libc::globfree(&mut found) };
    Ok(paths)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(src: &str) -> Vec<String> {
        let mut lexer = Lexer::new_inline(src);
        lexer.read_directive().unwrap().0
    }

    #[test]
    fn quoted_escapes_follow_nginx() {
        assert_eq!(args(r#"return 200 "a\tb\r\nc";"#)[2], "a\tb\r\nc");
        assert_eq!(args(r#"return 200 "say \"hi\"";"#)[2], "say \"hi\"");
        assert_eq!(args(r#"return 200 'it\'s';"#)[2], "it's");
        assert_eq!(args(r#"return 200 "a\\b";"#)[2], "a\\b");
        // `\\n` is an escaped backslash followed by `n`, not a newline.
        assert_eq!(args(r#"return 200 "a\\nb";"#)[2], "a\\nb");
        // Any other pair is kept as written.
        assert_eq!(args(r#"return 200 "a\.b\x";"#)[2], "a\\.b\\x");
    }

    #[test]
    fn unquoted_escapes_follow_nginx() {
        // Regex escapes other than \t \r \n \" \' \\ pass through.
        assert_eq!(args(r"location ~ \.(gif|jpg)$ {")[2], r"\.(gif|jpg)$");
        assert_eq!(args(r"rewrite ^/(\d+)$ /n/$1;")[1], r"^/(\d+)$");
        assert_eq!(args(r"set $a x\\y;")[2], r"x\y");
        // A backslash keeps `;` and a space inside the token; like any
        // other unlisted pair, the backslash itself stays.
        assert_eq!(args(r"set $a a\;b\ c;"), vec!["set", "$a", r"a\;b\ c"]);
    }
}
