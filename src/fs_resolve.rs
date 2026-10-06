// Filesystem path resolution — the ResolveFsPath phase for Root handlers.
//
// Compresses what nginx spreads across three modules:
//   - ngx_http_try_files_module.c (PRECONTENT_PHASE): evaluate try_files
//     probes, rewrite r->uri on hit, fire fallback on miss.
//   - ngx_http_static_module.c (CONTENT_PHASE): map URI to filesystem,
//     301 on directory-without-trailing-slash, serve file otherwise.
//   - ngx_http_index_module.c (CONTENT_PHASE): on trailing-slash URI,
//     probe the index list; internal-redirect to the first hit.
//
// Our shape is a single pure function returning an `Outcome` enum — we
// don't have subrequests or a filter chain, so there's no value in
// maintaining the three-module split. Every outcome the worker can
// produce after this point maps 1:1 to an `Outcome` variant.

use std::ffi::CString;
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};

use crate::config::AutoindexFormat;
use crate::config::{ErrorLogLevel, SymlinkMode};
use crate::phase::RerouteTarget;
use crate::worker::{
    Prebuilt, PreparedFallback, PreparedIndexEntry, PreparedPathMapping, PreparedProbe,
    PreparedRoot, PreparedSymlinkFrom, PreparedSymlinks, PreparedTryFiles, RenderCtx, render_parts,
};

/// A file successfully opened under the server root, with its metadata
/// already read off the fd. The resolver has done all the containment and
/// stat work; downstream (`file::serve_path`) just builds headers and
/// reads the body — no more stat, no more canonicalize, no second open.
pub struct Opened {
    pub fd: OwnedFd,
    pub size: u64,
    /// Unix epoch seconds from fstat's `st_mtime`.
    pub mtime: u64,
    /// Resolved from the URL-path extension at resolve time.
    pub mime: &'static [u8],
}

/// What the resolver decided. Orthogonal to the HTTP response shape —
/// the caller (`worker::run_location_handler`) renders each variant.
pub enum Outcome {
    /// Serve this file. Root containment was enforced by the kernel via
    /// `openat2(RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS)`; the fd inside
    /// `Opened` is owned by the caller and must be consumed or dropped.
    Serve(Opened),
    /// 301 redirect. Value is the `Location:` header bytes (absolute path).
    /// Used only for the trailing-slash-on-directory case.
    Redirect(Vec<u8>),
    /// Rewrite the URL to this and re-run location matching. Emitted by
    /// `try_files` fallbacks and `index` hits; the caller loops with a hop
    /// budget and either rematches by URI or jumps to a named location.
    Reroute(RerouteTarget),
    NotFound,
    Forbidden,
    /// Pre-rendered response for a `try_files ... =NNN` fallback.
    StatusPrebuilt(&'static Prebuilt),
    /// Render directory listing from this path/URI using effective
    /// autoindex options.
    Autoindex {
        dir_path: PathBuf,
        uri: Vec<u8>,
        exact_size: bool,
        localtime: bool,
        format: AutoindexFormat,
    },
    /// Canonicalization or other I/O failure inside the resolver — not
    /// the same as the file genuinely being missing (which is NotFound).
    InternalServerError,
}

/// Entry point. If `try_files` is present, it runs first (nginx:
/// PRECONTENT_PHASE, before static/index). On a probe hit we continue
/// into the static/index pass with the rewritten URL; on full miss we
/// apply the configured fallback.
pub fn resolve(
    root: &'static PreparedRoot,
    url_path: &[u8],
    render_ctx: &RenderCtx<'_>,
) -> Outcome {
    if let Some(tf) = root.try_files {
        match run_try_files(root, tf, url_path) {
            TryFilesResult::Hit {
                new_url,
                add_uri_to_alias,
            } => return resolve_static(root, &new_url, render_ctx, add_uri_to_alias),
            TryFilesResult::Miss => return apply_fallback(&tf.fallback),
        }
    }
    resolve_static(root, url_path, render_ctx, false)
}

enum TryFilesResult {
    /// The rewritten URL (may equal the input URL; `$uri/` appends `/`).
    Hit {
        new_url: Vec<u8>,
        add_uri_to_alias: bool,
    },
    /// No probe matched; caller applies the terminal fallback.
    Miss,
}

fn run_try_files(root: &PreparedRoot, tf: &PreparedTryFiles, url_path: &[u8]) -> TryFilesResult {
    for probe in &tf.probes {
        let (fs_path, new_url, want_dir) = match probe {
            PreparedProbe::Uri => (
                map_uri_for_try_files_probe(root, url_path),
                url_path.to_vec(),
                false,
            ),
            PreparedProbe::UriSlash => {
                // `$uri/` — test as directory. nginx strips the trailing
                // `/` from the probe at parse time, so the rewritten URL
                // is the bare `$uri` (no trailing `/` appended) — the
                // static handler then 301-redirects bare-directory hits.
                let fs_path = map_uri_for_try_files_probe(root, url_path);
                (fs_path, url_path.to_vec(), true)
            }
            PreparedProbe::Literal(bytes) => {
                // Literal paths are URIs in try_files, not filesystem
                // paths. Join them with root the same way a request URI
                // would be joined.
                let fs_path = map_uri_for_try_files_probe(root, bytes);
                (fs_path, bytes.to_vec(), false)
            }
            PreparedProbe::LiteralSlash(bytes) => {
                // `bytes` already had its trailing `/` stripped at parse
                // time (matches nginx's `tf[i].name.len--`), so the
                // rewritten URL is the bare path. The static handler
                // then 301-redirects bare-directory hits.
                let fs_path = map_uri_for_try_files_probe(root, bytes);
                (fs_path, bytes.to_vec(), true)
            }
        };
        // nginx's try_files opens the probe like the static module: a
        // symlink `disable_symlinks` refuses is a miss.
        if let Some(errno) = symlinks_refused(root, &fs_path) {
            // nginx's try_files logs it at crit, except ENOTDIR.
            if errno == libc::ELOOP {
                note_failed_lookup_at(
                    format!(
                        "openat() \"{}\" failed ({})",
                        fs_path.display(),
                        crate::worker::errno_text(&std::io::Error::from_raw_os_error(errno))
                    ),
                    false,
                    ErrorLogLevel::Crit,
                );
            }
            continue;
        }
        match std::fs::metadata(&fs_path) {
            Ok(m) if want_dir && m.is_dir() => {
                return TryFilesResult::Hit {
                    new_url,
                    add_uri_to_alias: false,
                };
            }
            Ok(m) if !want_dir && m.is_file() => {
                let add_uri_to_alias = matches!(root.path_mapping, PreparedPathMapping::AliasRegex);
                return TryFilesResult::Hit {
                    new_url,
                    add_uri_to_alias,
                };
            }
            _ => continue,
        }
    }
    TryFilesResult::Miss
}

fn apply_fallback(fallback: &'static PreparedFallback) -> Outcome {
    match fallback {
        PreparedFallback::Status(prebuilt) => Outcome::StatusPrebuilt(prebuilt),
        PreparedFallback::Uri(bytes) => Outcome::Reroute(RerouteTarget::Uri(bytes.to_vec())),
        PreparedFallback::Named(name) => Outcome::Reroute(RerouteTarget::Named(name.to_vec())),
    }
}

thread_local! {
    /// The error-log line for this request's failed file lookup, as nginx's
    /// static and index modules word it, and whether it's a "not found"
    /// (logged only with `log_not_found`). Set on the cold failure paths
    /// here, taken (and logged) as soon as phase processing returns.
    static FAILED_LOOKUP: std::cell::RefCell<Option<(Vec<u8>, bool, ErrorLogLevel)>> =
        const { std::cell::RefCell::new(None) };
}

/// The failed lookup noted for this request, if any.
pub(crate) fn take_failed_lookup() -> Option<(Vec<u8>, bool, ErrorLogLevel)> {
    FAILED_LOOKUP.with(|f| f.borrow_mut().take())
}

#[cold]
fn note_failed_lookup(message: String, not_found: bool) {
    note_failed_lookup_at(message, not_found, ErrorLogLevel::Error);
}

#[cold]
fn note_failed_lookup_at(message: String, not_found: bool, level: ErrorLogLevel) {
    FAILED_LOOKUP.with(|f| *f.borrow_mut() = Some((message.into_bytes(), not_found, level)));
}

fn is_not_found(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
    )
}

/// `open() "<path>" failed (<errno>)`, nginx's static-module line.
#[cold]
fn open_failed(root: &PreparedRoot, rel: &[u8], e: std::io::Error) -> Outcome {
    // A path outside the root (EXDEV from RESOLVE_BENEATH) is ruxen's own
    // symlink policy, not an nginx open() failure.
    if e.raw_os_error() != Some(libc::EXDEV) {
        let path = if rel.is_empty() {
            root.root.to_path_buf()
        } else {
            join(root.root, rel)
        };
        // nginx's disable_symlinks walk opens with openat().
        let call = if matches!(root.symlinks.mode, SymlinkMode::Off) {
            "open()"
        } else {
            "openat()"
        };
        note_failed_lookup(
            format!(
                "{call} \"{}\" failed ({})",
                path.display(),
                crate::worker::errno_text(&e)
            ),
            is_not_found(&e),
        );
    }
    io_to_outcome(e)
}

/// The static+index half. Looks up `<root><url>`, deals with the four
/// shapes a request can take: file, directory-with-slash, directory-no-
/// slash, missing.
fn resolve_static(
    root: &PreparedRoot,
    url_path: &[u8],
    render_ctx: &RenderCtx<'_>,
    add_uri_to_alias: bool,
) -> Outcome {
    if url_path.ends_with(b"/") {
        // Index handling runs on trailing-slash URIs. Absolute entries
        // redirect immediately, even if `<root><uri>` doesn't exist as a
        // directory; relative entries need the directory metadata. Keep the
        // walk in declaration order so mixed relative/absolute lists behave
        // like nginx's index module.
        let fs_path = map_uri_for_static(root, url_path, add_uri_to_alias);
        let mut dir_meta: Option<std::io::Result<std::fs::Metadata>> = None;
        for name in root.index {
            let rendered = render_index(name, render_ctx);
            if rendered.first() == Some(&b'/') {
                return Outcome::Reroute(RerouteTarget::Uri(rendered));
            }

            let meta = dir_meta.get_or_insert_with(|| std::fs::metadata(&fs_path));
            let Ok(meta) = meta else {
                continue;
            };
            if !meta.is_dir() {
                continue;
            }

            let mut candidate = fs_path.clone();
            candidate.push(std::ffi::OsStr::from_bytes(&rendered));
            // nginx's index module: an index file `disable_symlinks`
            // refuses (ELOOP) is a 403 without a log line; a link before
            // it (ENOTDIR) a 404.
            match symlinks_refused(root, &candidate) {
                Some(libc::ELOOP) => return Outcome::Forbidden,
                Some(_) => return Outcome::NotFound,
                None => {}
            }
            match std::fs::metadata(&candidate) {
                Ok(m) if m.is_file() => {
                    let mut reroute = url_path.to_vec();
                    reroute.extend_from_slice(&rendered);
                    return Outcome::Reroute(RerouteTarget::Uri(reroute));
                }
                _ => continue,
            }
        }

        match dir_meta.unwrap_or_else(|| std::fs::metadata(&fs_path)) {
            Ok(m) if m.is_dir() => {
                if root.autoindex {
                    return Outcome::Autoindex {
                        dir_path: fs_path,
                        uri: url_path.to_vec(),
                        exact_size: root.autoindex_exact_size,
                        localtime: root.autoindex_localtime,
                        format: root.autoindex_format,
                    };
                }
                note_failed_lookup(
                    format!("directory index of \"{}\" is forbidden", fs_path.display()),
                    false,
                );
                return Outcome::Forbidden;
            }
            Ok(_) => return Outcome::NotFound,
            Err(e) => {
                // nginx's index module, testing the directory.
                note_failed_lookup(
                    format!(
                        "\"{}\" is not found ({})",
                        fs_path.display(),
                        crate::worker::errno_text(&e)
                    ),
                    is_not_found(&e),
                );
                return io_to_outcome(e);
            }
        }
    }

    // Non-trailing-slash URI: go straight to `openat2 + fstat`. The old
    // flow did a `metadata()` first just to branch between file/dir/special,
    // which cost a third syscall on the file path (the dominant case for
    // benchmark traffic). `open_and_stat` now handles the dir branch
    // itself by issuing the 301 redirect after fstat — same observable
    // behavior, one fewer syscall for files and misses.
    open_and_stat(root, url_path, add_uri_to_alias)
}

/// Open the request's target file under `root.root_fd` with kernel-enforced
/// containment. Replaces the stat + canonicalize + starts_with dance with a
/// single `openat2(2)` syscall: `RESOLVE_BENEATH` rejects any resolution
/// step that would land outside the root dirfd (covering both absolute
/// symlink targets and relative ones that `..` their way out), and
/// `RESOLVE_NO_MAGICLINKS` blocks `/proc/self/fd/N`-style escapes. The
/// returned `Opened` carries the fd and a fresh `fstat` result so the
/// serving path doesn't re-stat.
fn open_and_stat(root: &PreparedRoot, url_path: &[u8], add_uri_to_alias: bool) -> Outcome {
    let rel = relative_uri_path_for_static(root, url_path, add_uri_to_alias);

    // A direct file alias (`alias /some/file;`) and regex-location alias
    // without `add_uri_to_alias` both legitimately produce an empty rel —
    // the caller is asking for the aliased path verbatim. `openat2`
    // requires a non-empty pathname (there's no `AT_EMPTY_PATH` knob in
    // `open_how.resolve`), so we `dup(2)` the cached root fd instead:
    // one syscall, no path walk, no race between stat and open.
    let root_fd = match root.fd() {
        Ok(fd) => fd,
        Err(e) => return open_failed(root, rel, e),
    };
    let fd = if !matches!(root.symlinks.mode, SymlinkMode::Off) {
        match open_refusing_symlinks(root, root_fd, rel) {
            Ok(fd) => fd,
            Err(e) => return open_failed(root, rel, e),
        }
    } else if rel.is_empty() {
        match dup_fd(root_fd) {
            Ok(fd) => fd,
            Err(e) => return open_failed(root, rel, e),
        }
    } else {
        match openat2_beneath(root_fd, rel) {
            Ok(fd) => fd,
            Err(e) => return open_failed(root, rel, e),
        }
    };

    let stat = match fstat(fd.as_raw_fd()) {
        Ok(s) => s,
        Err(e) => return io_to_outcome(e),
    };

    // `openat2` happily opens a directory — if we landed on one, do the
    // 301-to-trailing-slash the nginx static module emits for a dir
    // without a trailing slash (static.c:148–204). Trailing-slash URIs
    // never reach this branch (the caller routes them through the index
    // walk), so seeing a dir here means the request was for a bare
    // directory path. Query preservation is deferred — the redirect
    // drops any `?query` from the original request, matching prior
    // behavior. Any other non-regular file (socket, device, …) stays a
    // 404.
    let mode = stat.st_mode & libc::S_IFMT;
    if mode == libc::S_IFDIR {
        let mut loc = Vec::with_capacity(url_path.len() + 1);
        loc.extend_from_slice(url_path);
        loc.push(b'/');
        return Outcome::Redirect(loc);
    }
    if mode != libc::S_IFREG {
        return Outcome::NotFound;
    }

    let mtime = if stat.st_mtime >= 0 {
        stat.st_mtime as u64
    } else {
        0
    };

    Outcome::Serve(Opened {
        fd,
        size: stat.st_size as u64,
        mtime,
        mime: mime_for_url(url_path),
    })
}

/// `open_and_stat` under `disable_symlinks on|if_not_owner`, nginx's
/// ngx_open_file_wrapper: the components of `<root>/<rel>` after the
/// `from=` boundary may not be symlinks (`on`), or only ones owned like
/// their targets (`if_not_owner`); ELOOP otherwise (a 403). The open
/// itself stays `RESOLVE_BENEATH` the root. Under `on`, the part of the
/// path below the root is opened with `RESOLVE_NO_SYMLINKS`, so a symlink
/// can't be swapped in between the check and the open; the root's own
/// components are checked as configured (the root fd was opened at
/// startup). `if_not_owner` is a walk with fstatat, racy as nginx's.
#[cold]
fn open_refusing_symlinks(
    root: &PreparedRoot,
    root_fd: RawFd,
    rel: &[u8],
) -> std::io::Result<OwnedFd> {
    let root_path = root.root.as_os_str().as_bytes();
    let full = join(root.root, rel);
    let full = full.as_os_str().as_bytes();
    let Some(boundary) = symlink_boundary(&root.symlinks, root_path, full) else {
        // `from=` is the whole path: nothing to check.
        return if rel.is_empty() {
            dup_fd(root_fd)
        } else {
            openat2_beneath(root_fd, rel)
        };
    };
    if matches!(root.symlinks.mode, SymlinkMode::NotOwner) {
        check_symlink_owners(full, boundary)?;
        return if rel.is_empty() {
            dup_fd(root_fd)
        } else {
            openat2_beneath(root_fd, rel)
        };
    }
    // `on`: the root's components first, then `rel` in one openat2.
    let root_len = root_path.len();
    if boundary < root_len {
        refuse_symlinks_after(&root_path[..root_len], boundary)?;
    }
    if rel.is_empty() {
        return dup_fd(root_fd);
    }
    // `from=` reaching into `rel`: its leading components may be links.
    let rel_start = full.len() - rel.len();
    let (anchor, rest) = if boundary > rel_start {
        let split = boundary - rel_start;
        (
            Some(openat2_with(
                root_fd,
                &rel[..split],
                libc::O_PATH | libc::O_DIRECTORY,
                0,
            )?),
            trim_leading_slashes(&rel[split..]),
        )
    } else {
        (None, rel)
    };
    if rest.is_empty() {
        // Nothing past `from=` to check; open it for reading.
        return openat2_beneath(root_fd, rel);
    }
    let dirfd = anchor.as_ref().map_or(root_fd, |fd| fd.as_raw_fd());
    openat2_no_symlinks(dirfd, rest, libc::O_RDONLY)
}

/// `openat2(RESOLVE_NO_SYMLINKS)` with nginx's errors for a refused
/// symlink: its walk opens the components before the last as directories
/// with O_NOFOLLOW, which fails with ENOTDIR on a link (a 404), and only a
/// link in the last component is ELOOP (a 403).
fn openat2_no_symlinks(dirfd: RawFd, rel: &[u8], flags: i32) -> std::io::Result<OwnedFd> {
    match openat2_with(dirfd, rel, flags, libc::RESOLVE_NO_SYMLINKS) {
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => {
            let parent = match rel.iter().rposition(|&b| b == b'/') {
                Some(i) => trim_trailing_slashes(&rel[..i]),
                None => &[][..],
            };
            let in_parent = !parent.is_empty()
                && matches!(
                    openat2_with(dirfd, parent, libc::O_PATH, libc::RESOLVE_NO_SYMLINKS),
                    Err(e) if e.raw_os_error() == Some(libc::ELOOP)
                );
            Err(std::io::Error::from_raw_os_error(if in_parent {
                libc::ENOTDIR
            } else {
                libc::ELOOP
            }))
        }
        other => other,
    }
}

fn trim_trailing_slashes(bytes: &[u8]) -> &[u8] {
    let n = bytes.iter().rev().take_while(|&&b| b == b'/').count();
    &bytes[..bytes.len() - n]
}

/// The error `disable_symlinks` refuses the absolute `path` with (a
/// try_files or index probe): ELOOP, or ENOTDIR for a link before the
/// last component under `on`. Other errors are left to the probe.
fn symlinks_refused(root: &PreparedRoot, path: &Path) -> Option<i32> {
    symlink_refusal(&root.symlinks, root.root, path.as_os_str().as_bytes())
}

/// `symlinks_refused` for a policy and document root, and a path that
/// isn't a static lookup (`if -f`): ELOOP or ENOTDIR when refused.
pub(crate) fn symlink_refusal(
    policy: &PreparedSymlinks,
    document_root: &Path,
    full: &[u8],
) -> Option<i32> {
    if matches!(policy.mode, SymlinkMode::Off) {
        return None;
    }
    let boundary = symlink_boundary(policy, document_root.as_os_str().as_bytes(), full)?;
    let checked = match policy.mode {
        SymlinkMode::NotOwner => check_symlink_owners(full, boundary),
        _ => refuse_symlinks_after(full, boundary),
    };
    let errno = checked.err()?.raw_os_error()?;
    matches!(errno, libc::ELOOP | libc::ENOTDIR).then_some(errno)
}

/// Where `disable_symlinks` starts checking `full`, nginx's
/// ngx_http_set_disable_symlinks: `None` when `from=` is the whole path
/// (nothing to check), else the byte offset of the `/` after which every
/// component is checked (0: all of them).
fn symlink_boundary(policy: &PreparedSymlinks, document_root: &[u8], full: &[u8]) -> Option<usize> {
    let from: &[u8] = match policy.from {
        PreparedSymlinkFrom::None => return Some(0),
        PreparedSymlinkFrom::DocumentRoot => document_root,
        PreparedSymlinkFrom::Path(p) => p,
    };
    if from.is_empty() || from.len() > full.len() || !full.starts_with(from) {
        return Some(0);
    }
    if from.len() == full.len() {
        return None;
    }
    if full[from.len()] == b'/' {
        return Some(from.len());
    }
    if from.ends_with(b"/") {
        return Some(from.len() - 1);
    }
    Some(0)
}

/// Where a `disable_symlinks` walk of `path` starts: the directory before
/// byte `boundary` (followed, links allowed), or for 0 `/` or, for a
/// relative path, the working directory (nginx's AT_FDCWD); and the rest.
fn walk_start(path: &[u8], boundary: usize) -> std::io::Result<(OwnedFd, &[u8])> {
    let start: &[u8] = match boundary {
        0 if path.first() == Some(&b'/') => b"/",
        0 => b".",
        n => &path[..n],
    };
    Ok((
        open_path_dir(start)?,
        trim_leading_slashes(&path[boundary..]),
    ))
}

/// ELOOP if a component of `path` after byte `boundary` is a symlink.
fn refuse_symlinks_after(path: &[u8], boundary: usize) -> std::io::Result<()> {
    let (start, rest) = walk_start(path, boundary)?;
    if !rest.is_empty() {
        openat2_no_symlinks(start.as_raw_fd(), rest, libc::O_PATH)?;
    }
    Ok(())
}

/// `if_not_owner`: ELOOP if a component of `path` after byte `boundary`
/// is a symlink owned by someone other than its target's owner, as
/// nginx's ngx_openat_file_owner (open, then compare the uid of what was
/// opened with fstatat(AT_SYMLINK_NOFOLLOW) of the name).
fn check_symlink_owners(path: &[u8], boundary: usize) -> std::io::Result<()> {
    let (mut at, rest) = walk_start(path, boundary)?;
    for component in rest.split(|&b| b == b'/') {
        if component.is_empty() {
            continue;
        }
        let name =
            CString::new(component).map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
        let raw = unsafe {
            libc::openat(
                at.as_raw_fd(),
                name.as_ptr(),
                libc::O_PATH | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let opened = unsafe { OwnedFd::from_raw_fd(raw) };
        let mut link: libc::stat = unsafe { core::mem::zeroed() };
        if unsafe {
            libc::fstatat(
                at.as_raw_fd(),
                name.as_ptr(),
                &mut link,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } < 0
        {
            return Err(std::io::Error::last_os_error());
        }
        if fstat(opened.as_raw_fd())?.st_uid != link.st_uid {
            return Err(std::io::Error::from_raw_os_error(libc::ELOOP));
        }
        at = opened;
    }
    Ok(())
}

/// An `O_PATH` fd of a directory path, following symlinks (the part
/// before the `disable_symlinks` boundary may have them).
fn open_path_dir(path: &[u8]) -> std::io::Result<OwnedFd> {
    let c = CString::new(path).map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
    let raw = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

/// `openat2(dirfd, rel, { flags | O_CLOEXEC, RESOLVE_BENEATH |
/// RESOLVE_NO_MAGICLINKS | extra })`.
fn openat2_with(dirfd: RawFd, rel: &[u8], flags: i32, extra: u64) -> std::io::Result<OwnedFd> {
    let c_rel = CString::new(rel).map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
    let mut how: libc::open_how = unsafe { core::mem::zeroed() };
    how.flags = (flags | libc::O_CLOEXEC) as u64;
    how.resolve = libc::RESOLVE_BENEATH | libc::RESOLVE_NO_MAGICLINKS | extra;
    let ret = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dirfd,
            c_rel.as_ptr(),
            &how as *const libc::open_how,
            core::mem::size_of::<libc::open_how>(),
        )
    };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(ret as RawFd) })
}

/// `openat2(dirfd, rel, { O_RDONLY | O_CLOEXEC, RESOLVE_BENEATH |
/// RESOLVE_NO_MAGICLINKS })` wrapper. Returns the mapped `OwnedFd`, or an
/// `io::Error` whose `kind()` already buckets the cases `io_to_outcome`
/// cares about. The CString conversion catches interior NULs as EINVAL
/// rather than panicking.
fn openat2_beneath(dirfd: RawFd, rel: &[u8]) -> std::io::Result<OwnedFd> {
    let c_rel = CString::new(rel).map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
    // `libc::open_how` is `#[non_exhaustive]`, so zero it and fill by
    // field write. That also future-proofs us against new trailing fields
    // — a zero value preserves default kernel behavior.
    let mut how: libc::open_how = unsafe { core::mem::zeroed() };
    how.flags = (libc::O_RDONLY | libc::O_CLOEXEC) as u64;
    how.mode = 0;
    how.resolve = libc::RESOLVE_BENEATH | libc::RESOLVE_NO_MAGICLINKS;
    let ret = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dirfd,
            c_rel.as_ptr(),
            &how as *const libc::open_how,
            core::mem::size_of::<libc::open_how>(),
        )
    };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(ret as RawFd) })
}

/// `fcntl(F_DUPFD_CLOEXEC)` on the cached root fd — used when the alias
/// target is a regular file and the URL maps to an empty rel.
fn dup_fd(fd: RawFd) -> std::io::Result<OwnedFd> {
    let ret = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(ret as RawFd) })
}

fn fstat(fd: RawFd) -> std::io::Result<libc::stat> {
    let mut buf: libc::stat = unsafe { core::mem::zeroed() };
    let rc = unsafe { libc::fstat(fd, &mut buf) };
    if rc < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(buf)
    }
}

/// MIME lookup from the URL-path extension. Mirrors the table in
/// `file.rs::mime_for`, but byte-driven and no `Path` allocation.
fn mime_for_url(url_path: &[u8]) -> &'static [u8] {
    let slash = url_path
        .iter()
        .rposition(|&b| b == b'/')
        .map(|i| i + 1)
        .unwrap_or(0);
    let filename = &url_path[slash..];
    let dot = match filename.iter().rposition(|&b| b == b'.') {
        Some(d) if d + 1 < filename.len() => d,
        _ => return crate::file::DEFAULT_MIME,
    };
    let ext_raw = &filename[dot + 1..];
    let mut lower = [0u8; 16];
    if ext_raw.len() > lower.len() {
        return crate::file::DEFAULT_MIME;
    }
    for (i, &b) in ext_raw.iter().enumerate() {
        lower[i] = b.to_ascii_lowercase();
    }
    crate::file::mime_for(&lower[..ext_raw.len()])
}

fn render_index(entry: &PreparedIndexEntry, render_ctx: &RenderCtx<'_>) -> Vec<u8> {
    let mut out = Vec::with_capacity(32);
    render_parts(entry.parts, render_ctx, &mut out);
    out
}

fn map_uri_for_try_files_probe(root: &PreparedRoot, probe_uri: &[u8]) -> PathBuf {
    join(
        root.root,
        relative_uri_path_for_try_files_probe(root, probe_uri),
    )
}

fn relative_uri_path_for_try_files_probe<'a>(root: &PreparedRoot, probe_uri: &'a [u8]) -> &'a [u8] {
    match root.path_mapping {
        PreparedPathMapping::Root => trim_leading_slashes(probe_uri),
        PreparedPathMapping::AliasPrefix { prefix } => {
            trim_leading_slashes(probe_uri.strip_prefix(prefix).unwrap_or(probe_uri))
        }
        // nginx's try_files handler always appends the probe URI for regex
        // aliases (`clcf->alias == NGX_MAX_SIZE_T_VALUE`), independent of
        // `add_uri_to_alias`.
        PreparedPathMapping::AliasRegex => trim_leading_slashes(probe_uri),
    }
}

/// `$request_filename`: `uri` under a location's root or alias.
pub(crate) fn request_filename(doc_root: &crate::worker::DocRoot, uri: &[u8]) -> PathBuf {
    let rel = match doc_root.mapping {
        PreparedPathMapping::Root => trim_leading_slashes(uri),
        PreparedPathMapping::AliasPrefix { prefix } => {
            trim_leading_slashes(uri.strip_prefix(prefix).unwrap_or(uri))
        }
        PreparedPathMapping::AliasRegex => b"",
    };
    join(doc_root.path, rel)
}

fn map_uri_for_static(root: &PreparedRoot, url_path: &[u8], add_uri_to_alias: bool) -> PathBuf {
    join(
        root.root,
        relative_uri_path_for_static(root, url_path, add_uri_to_alias),
    )
}

fn relative_uri_path_for_static<'a>(
    root: &PreparedRoot,
    url_path: &'a [u8],
    add_uri_to_alias: bool,
) -> &'a [u8] {
    match root.path_mapping {
        PreparedPathMapping::Root => trim_leading_slashes(url_path),
        PreparedPathMapping::AliasPrefix { prefix } => {
            trim_leading_slashes(url_path.strip_prefix(prefix).unwrap_or(url_path))
        }
        PreparedPathMapping::AliasRegex => {
            if add_uri_to_alias {
                trim_leading_slashes(url_path)
            } else {
                b""
            }
        }
    }
}

/// Strip *all* leading `/` bytes, not just one. `merge_slashes off;` can let
/// a URL like `//etc/passwd` reach us with two leading slashes; stripping
/// only one leaves an absolute path that `PathBuf::push` below would use to
/// *replace* the root entirely (its documented absolute-path behavior) —
/// that's a root-escape primitive. Matches nginx's string-concat shape
/// (`/srv` + `//etc` → `/srv//etc`, which the kernel collapses to
/// `/srv/etc`).
fn trim_leading_slashes(bytes: &[u8]) -> &[u8] {
    let n = bytes.iter().take_while(|&&b| b == b'/').count();
    &bytes[n..]
}

fn join(root: &Path, rel: &[u8]) -> PathBuf {
    // `rel` is expected to be relative — `trim_leading_slashes` is the
    // caller's contract. Asserted here as belt-and-braces defense: any
    // future code path that builds `rel` without going through one of the
    // `relative_uri_path_for_*` helpers still can't accidentally hand us an absolute
    // path and break root containment.
    debug_assert!(
        rel.first() != Some(&b'/'),
        "join() expects a relative byte path; got absolute"
    );
    let mut out = root.to_path_buf();
    if !rel.is_empty() {
        out.push(std::ffi::OsStr::from_bytes(rel));
    }
    out
}

fn io_to_outcome(e: std::io::Error) -> Outcome {
    use std::io::ErrorKind::*;
    // `openat2(RESOLVE_BENEATH)` signals a containment violation with
    // `EXDEV` (see `nd_jump_root` in fs/namei.c). Rust's `ErrorKind`
    // doesn't have a stable variant for it — `CrossesDevices` is
    // nightly-only — so we check the raw errno. ELOOP / EMLINK (a symlink
    // `disable_symlinks` refuses, or a loop) are 403, as in nginx's static
    // module.
    if matches!(
        e.raw_os_error(),
        Some(libc::EXDEV | libc::ELOOP | libc::EMLINK)
    ) {
        return Outcome::Forbidden;
    }
    match e.kind() {
        // ENOTDIR on a non-final component: /foo.txt/bar when foo.txt is
        // a file. nginx collapses this into the same 404 bucket.
        NotFound | NotADirectory => Outcome::NotFound,
        PermissionDenied => Outcome::Forbidden,
        _ => Outcome::InternalServerError,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_root(mapping: PreparedPathMapping) -> PreparedRoot {
        PreparedRoot {
            root: Path::new("/srv"),
            // `AT_FDCWD` is fine for tests that only exercise the path
            // utilities below — none of them hit `openat2`.
            root_fd: libc::AT_FDCWD,
            symlinks: PreparedSymlinks::new(None),
            path_mapping: mapping,
            index: &[],
            autoindex: false,
            autoindex_exact_size: true,
            autoindex_localtime: false,
            autoindex_format: AutoindexFormat::Html,
            try_files: None,
        }
    }

    #[test]
    fn join_appends_relative_path_to_root() {
        let p = join(Path::new("/var/www"), b"index.html");
        assert_eq!(p, PathBuf::from("/var/www/index.html"));
    }

    #[test]
    fn join_preserves_subdirs() {
        let p = join(Path::new("/srv"), b"a/b/c.txt");
        assert_eq!(p, PathBuf::from("/srv/a/b/c.txt"));
    }

    #[test]
    fn join_root_only() {
        let p = join(Path::new("/srv"), b"");
        assert_eq!(p, PathBuf::from("/srv"));
    }

    #[test]
    fn relative_uri_path_for_root_keeps_full_uri() {
        let root = fake_root(PreparedPathMapping::Root);
        assert_eq!(
            relative_uri_path_for_static(&root, b"/static/file.txt", false),
            b"static/file.txt"
        );
    }

    #[test]
    fn relative_uri_path_for_alias_strips_matched_prefix() {
        let root = fake_root(PreparedPathMapping::AliasPrefix {
            prefix: b"/static/",
        });
        assert_eq!(
            relative_uri_path_for_static(&root, b"/static/file.txt", false),
            b"file.txt"
        );
    }

    #[test]
    fn alias_relative_uri_path_falls_back_to_whole_uri_for_literal_probe() {
        let root = fake_root(PreparedPathMapping::AliasPrefix {
            prefix: b"/static/",
        });
        assert_eq!(
            relative_uri_path_for_try_files_probe(&root, b"/fallback.html"),
            b"fallback.html"
        );
    }

    #[test]
    fn regex_alias_static_path_is_empty_without_add_uri_to_alias() {
        let root = fake_root(PreparedPathMapping::AliasRegex);
        assert_eq!(
            relative_uri_path_for_static(&root, b"/alias-re.html", false),
            b""
        );
    }

    #[test]
    fn regex_alias_static_path_appends_uri_when_add_uri_to_alias_is_set() {
        let root = fake_root(PreparedPathMapping::AliasRegex);
        assert_eq!(
            relative_uri_path_for_static(&root, b"/alias-re.html", true),
            b"alias-re.html"
        );
    }

    #[test]
    fn regex_alias_try_files_probe_always_uses_probe_uri() {
        let root = fake_root(PreparedPathMapping::AliasRegex);
        assert_eq!(
            relative_uri_path_for_try_files_probe(&root, b"/alias-re.html"),
            b"alias-re.html"
        );
    }

    #[test]
    fn trim_leading_slashes_strips_all() {
        // Regression for `merge_slashes off;` + leading `//` root-escape:
        // with only one slash stripped, `PathBuf::push("/etc")` would
        // replace the root path entirely. All leading slashes must go.
        assert_eq!(trim_leading_slashes(b""), b"");
        assert_eq!(trim_leading_slashes(b"/"), b"");
        assert_eq!(trim_leading_slashes(b"//"), b"");
        assert_eq!(trim_leading_slashes(b"///foo"), b"foo");
        assert_eq!(trim_leading_slashes(b"/foo"), b"foo");
        assert_eq!(trim_leading_slashes(b"foo"), b"foo");
    }

    #[test]
    fn relative_uri_path_strips_all_leading_slashes() {
        let root = fake_root(PreparedPathMapping::Root);
        // A `//etc/passwd` URL (possible under `merge_slashes off;`) must
        // resolve relative to the server root, not to the filesystem root.
        assert_eq!(
            relative_uri_path_for_static(&root, b"//etc/passwd", false),
            b"etc/passwd"
        );
    }

    #[test]
    fn join_places_escape_attempt_under_root() {
        // End-to-end: even if an attacker feeds `//etc/passwd` to the URI
        // normalizer (and `merge_slashes off;` preserves the leading pair),
        // `join` must produce `<root>/etc/passwd`, never `/etc/passwd`.
        let root = fake_root(PreparedPathMapping::Root);
        let rel = relative_uri_path_for_static(&root, b"//etc/passwd", false);
        let p = join(root.root, rel);
        assert_eq!(p, PathBuf::from("/srv/etc/passwd"));
    }
}
