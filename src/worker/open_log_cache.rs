//! `open_log_file_cache` (#371): access_log files whose path has variables
//! stay open between lines, per worker, as nginx's `ngx_open_cached_file`
//! keeps them per process (`ngx_open_file_cache.c`).
//!
//! An entry counts its uses. Its descriptor is kept after a line once it
//! was used `min_uses` times, and reused without a look at the name while
//! younger than `valid`; after that the name is checked again (same inode:
//! kept; otherwise reopened). So lines keep going to a file that was
//! renamed, as with nginx, until `valid` passes. A failed open caches
//! nothing. The cache holds `max` names, least recently used out first,
//! and drops up to two entries unused for `inactive` after each line.
//!
//! These descriptors are opened after startup: they belong to this
//! worker's own fd table.

use std::cell::RefCell;
use std::collections::HashMap;
use std::fs::File;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::config::OpenLogFileCache;

struct Entry {
    name: Vec<u8>,
    /// Kept open: used `min_uses` times.
    file: Option<File>,
    /// Device and inode of what `file` is.
    ino: (u64, u64),
    uses: u32,
    /// When the name was last opened or checked.
    created: Instant,
    accessed: Instant,
}

thread_local! {
    /// Per `open_log_file_cache` directive (`OpenLogFileCache::id`); least
    /// recently used first.
    static CACHES: RefCell<HashMap<u32, Vec<Entry>>> = RefCell::new(HashMap::new());
}

fn open(path: &Path) -> std::io::Result<(File, (u64, u64))> {
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    let meta = file.metadata()?;
    Ok((file, (meta.dev(), meta.ino())))
}

/// Append `line` to `path` through `conf`'s cache. Fails as the open does.
pub(crate) fn write(conf: &OpenLogFileCache, path: &Path, line: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::ffi::OsStrExt;
    let name = path.as_os_str().as_bytes();
    let now = Instant::now();
    CACHES.with(|caches| {
        let mut caches = caches.borrow_mut();
        let entries = caches.entry(conf.id).or_default();
        let mut entry = match entries.iter().position(|e| e.name == name) {
            Some(i) => {
                let mut e = entries.remove(i);
                e.uses += 1;
                let reopen = match &e.file {
                    // Not used often enough to be kept open.
                    None => true,
                    Some(_)
                        if now.duration_since(e.created) < Duration::from_millis(conf.valid_ms) =>
                    {
                        false
                    }
                    // Checked again by name.
                    Some(_) => match std::fs::metadata(path) {
                        Ok(m) if (m.dev(), m.ino()) == e.ino => {
                            e.created = now;
                            false
                        }
                        _ => true,
                    },
                };
                if reopen {
                    // A failed open drops the entry: logs don't cache
                    // errors.
                    let (file, ino) = open(path)?;
                    e.file = Some(file);
                    e.ino = ino;
                    e.created = now;
                }
                e
            }
            None => {
                let (file, ino) = open(path)?;
                if entries.len() >= conf.max as usize {
                    entries.remove(0);
                }
                Entry {
                    name: name.to_vec(),
                    file: Some(file),
                    ino,
                    uses: 1,
                    created: now,
                    accessed: now,
                }
            }
        };
        let res = match entry.file.as_mut() {
            Some(file) => file.write_all(line),
            None => Ok(()),
        };
        entry.accessed = now;
        if entry.uses < conf.min_uses {
            entry.file = None;
        }
        entries.push(entry);
        // ngx_expire_old_cached_files(cache, 1): one or two inactive ones.
        let inactive = Duration::from_millis(conf.inactive_ms);
        for _ in 0..2 {
            if entries
                .first()
                .is_some_and(|e| now.duration_since(e.accessed) > inactive)
            {
                entries.remove(0);
            } else {
                break;
            }
        }
        res
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `access_log.t`'s `/cache` sequence: max=3 min_uses=2; lines keep
    /// going to the files kept open after their directory is moved.
    #[test]
    fn files_kept_open_follow_a_moved_directory() {
        let base = std::env::temp_dir().join(format!("ruxen-olfc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let dir = base.join("dir");
        std::fs::create_dir_all(&dir).unwrap();
        let conf = OpenLogFileCache {
            id: u32::MAX,
            max: 3,
            inactive_ms: 20_000,
            min_uses: 2,
            valid_ms: 60_000,
        };
        let log = |name: &str| {
            let _ = write(&conf, &dir.join(format!("cache_{name}")), b"x\n");
        };
        for name in ["lru", "lru", "once", "first", "first", "second", "second"] {
            log(name);
        }
        std::fs::rename(&dir, base.join("dir_moved")).unwrap();
        for name in ["lru", "once", "first", "second"] {
            log(name);
        }
        std::fs::rename(base.join("dir_moved"), &dir).unwrap();
        let lines = |name: &str| {
            std::fs::read_to_string(dir.join(format!("cache_{name}")))
                .unwrap()
                .lines()
                .count()
        };
        let counts: Vec<usize> = ["lru", "once", "first", "second"]
            .into_iter()
            .map(lines)
            .collect();
        let _ = std::fs::remove_dir_all(&base);
        assert_eq!(counts, [2, 1, 3, 3]);
    }
}
