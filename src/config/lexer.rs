//! Hand-written tokenizer + `read_directive` driver. Frame stack supports
//! `include` directives with relative-path resolution against the current
//! frame's source path. Maintains the `nginx -T` dump-order list as a
//! side effect of resolving frames.

use super::*;

/// One stack frame in the lexer — a single source file (or synthetic inline
/// chunk) currently being tokenized. `include` pushes a new frame; we pop on
/// EOF and resume the parent. The originating file path is captured at
/// `push_include` time and pushed straight into `dump_files`; relative
/// include targets resolve against cwd (which `main.rs` sets to the prefix
/// dir before parsing), so the per-frame path isn't needed at lex time.
pub(crate) struct LexerFrame {
    bytes: Vec<u8>,
    pos: usize,
}

pub(crate) struct Lexer {
    frames: Vec<LexerFrame>,
    dump_files: Vec<DumpFile>,
    dump_seen: std::collections::HashSet<PathBuf>,
}

impl Lexer {
    #[cfg(test)]
    pub(crate) fn new_inline(src: &str) -> Self {
        Self {
            frames: vec![LexerFrame {
                bytes: src.as_bytes().to_vec(),
                pos: 0,
            }],
            dump_files: Vec::new(),
            dump_seen: std::collections::HashSet::new(),
        }
    }

    pub(crate) fn new_with_main(path: PathBuf, src: String) -> Self {
        let mut s = Self {
            frames: Vec::new(),
            dump_files: Vec::new(),
            dump_seen: std::collections::HashSet::new(),
        };
        s.dump_seen.insert(path.clone());
        s.dump_files.push(DumpFile {
            path,
            contents: src.clone(),
        });
        s.frames.push(LexerFrame {
            bytes: src.into_bytes(),
            pos: 0,
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
        });
    }

    pub(crate) fn take_dump_files(&mut self) -> Vec<DumpFile> {
        std::mem::take(&mut self.dump_files)
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
        let resolved = if Path::new(raw_path).is_absolute() {
            PathBuf::from(raw_path)
        } else {
            // nginx resolves relative include paths against the cycle prefix
            // (`-p`). main.rs already chdir'd into that prefix before parsing,
            // so cwd-relative resolution gives the right answer.
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join(raw_path)
        };
        let bytes = std::fs::read(&resolved).map_err(|e| Error::IncludeOpen {
            path: resolved.display().to_string(),
            reason: format!("{e}"),
        })?;
        let canonical = resolved.canonicalize().unwrap_or(resolved);
        let contents = String::from_utf8_lossy(&bytes).into_owned();
        if self.dump_seen.insert(canonical.clone()) {
            self.dump_files.push(DumpFile {
                path: canonical,
                contents,
            });
        }
        self.frames.push(LexerFrame { bytes, pos: 0 });
        Ok(())
    }

    // Reads tokens up to (and consuming) the next terminator. Transparently
    // handles `include <path>;` by pushing a new frame and continuing; the
    // caller never sees an `include` directive.
    pub(crate) fn read_directive(&mut self) -> Result<(Vec<String>, Terminator), Error> {
        loop {
            let (args, term) = self.read_directive_one()?;
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
                self.push_include(&args[1])?;
                continue;
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
                return if args.is_empty() {
                    Ok((args, Terminator::Eof))
                } else {
                    Err(Error::UnexpectedEof)
                };
            }

            match f.bytes[f.pos] {
                b';' => {
                    f.pos += 1;
                    return Ok((args, Terminator::Semi));
                }
                b'{' => {
                    f.pos += 1;
                    return Ok((args, Terminator::BlockOpen));
                }
                b'}' => {
                    if !args.is_empty() {
                        return Err(Error::UnexpectedToken("}".into()));
                    }
                    f.pos += 1;
                    return Ok((args, Terminator::BlockClose));
                }
                quote @ (b'"' | b'\'') => {
                    f.pos += 1;
                    let mut out: Vec<u8> = Vec::new();
                    while f.pos < f.bytes.len() && f.bytes[f.pos] != quote {
                        let c = f.bytes[f.pos];
                        // nginx's ngx_conf_read_token only consumes the
                        // backslash for `\"`, `\'`, `\\` — every other byte
                        // pair is passed through verbatim, so `"a\tb"` is
                        // the four bytes `a\tb`, not `a<TAB>b`.
                        if c == b'\\' && f.pos + 1 < f.bytes.len() {
                            let next = f.bytes[f.pos + 1];
                            if matches!(next, b'"' | b'\'' | b'\\') {
                                f.pos += 1;
                                out.push(next);
                            } else {
                                out.push(c);
                            }
                        } else {
                            out.push(c);
                        }
                        f.pos += 1;
                    }
                    if f.pos >= f.bytes.len() {
                        return Err(Error::UnterminatedString);
                    }
                    f.pos += 1;
                    args.push(String::from_utf8_lossy(&out).into_owned());
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
                        if matches!(
                            f.bytes[f.pos],
                            b' ' | b'\t' | b'\r' | b'\n' | b';' | b'{' | b'}'
                        ) {
                            break;
                        }
                        f.pos += 1;
                    }
                    args.push(String::from_utf8_lossy(&f.bytes[start..f.pos]).into_owned());
                }
            }
        }
    }
}

