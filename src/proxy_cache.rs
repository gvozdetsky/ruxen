//! `proxy_cache` (#233, step 1): upstream responses stored on disk and
//! served again while they are fresh (ngx_http_file_cache.c).
//!
//! nginx keeps a cache's index (`keys_zone`) in shared memory: a node per
//! key with its validity, use count, and whether a file holds the
//! response. Here the index is a heap value every worker reaches through
//! `&'static`, split into shards by the key's hash, each a `Mutex` around a
//! map and an LRU list, as the `limit_req` zones are. The capacity comes
//! from the zone's size (nginx's node is about 128 bytes) and is fixed: a
//! full shard drops its least recently used entry and that entry's file.
//!
//! The files are ruxen's own format, not nginx's (a cache directory is not
//! shared between the two): a fixed header, the key, the upstream's header
//! block, then the body. Their names are the hex of the first 16 bytes of
//! the key's SHA-256, spread over `levels` directories like nginx's md5
//! names; the key in the file guards against a collision.

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

/// The key's hash: names the file and indexes the zone.
pub type CacheHash = [u8; 16];

/// `$upstream_cache_status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheStatus {
    Miss,
    Bypass,
    Expired,
    Stale,
    Updating,
    Revalidated,
    Hit,
}

impl CacheStatus {
    pub fn as_bytes(self) -> &'static [u8] {
        match self {
            CacheStatus::Miss => b"MISS",
            CacheStatus::Bypass => b"BYPASS",
            CacheStatus::Expired => b"EXPIRED",
            CacheStatus::Stale => b"STALE",
            CacheStatus::Updating => b"UPDATING",
            CacheStatus::Revalidated => b"REVALIDATED",
            CacheStatus::Hit => b"HIT",
        }
    }
}

/// Milliseconds on a process-wide monotonic clock, for cache locks.
pub fn now_ms() -> u64 {
    static EPOCH: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    EPOCH
        .get_or_init(std::time::Instant::now)
        .elapsed()
        .as_millis() as u64
}

/// Seconds since the epoch (nginx's `ngx_time()`).
pub fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// The hash of a rendered `proxy_cache_key`.
pub fn hash_key(key: &[u8]) -> CacheHash {
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, key);
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&digest.as_ref()[..16]);
    hash
}

fn hex(hash: &CacheHash) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(32);
    for b in hash {
        s.push(DIGITS[usize::from(b >> 4)] as char);
        s.push(DIGITS[usize::from(b & 0xf)] as char);
    }
    s
}

const NIL: usize = usize::MAX;

struct Node {
    hash: CacheHash,
    /// Lookups of the key (`proxy_cache_min_uses`).
    uses: u32,
    /// Until when (seconds since the epoch) the entry is fresh.
    valid_sec: i64,
    /// `stale-while-revalidate` / `stale-if-error` seconds past
    /// `valid_sec` when a stale response may still answer.
    updating_sec: i64,
    error_sec: i64,
    /// A request is fetching the response (nginx's `updating`): an update
    /// of a stale entry, or the holder of `proxy_cache_lock`.
    updating: bool,
    /// Which request holds `updating`, and until when a lock counts
    /// (`proxy_cache_lock_age`, `now_ms`).
    lock_token: u64,
    lock_until_ms: u64,
    /// The status of a cached intercepted error, which has no file.
    error: u16,
    /// A file holds the response.
    exists: bool,
    /// The file's size, counted against `max_size`.
    fs_size: u64,
    /// Last lookup or store, for `inactive`.
    accessed: i64,
    prev: usize,
    next: usize,
}

struct Shard {
    map: HashMap<CacheHash, usize>,
    nodes: Vec<Node>,
    free: Vec<usize>,
    /// Most recently used.
    head: usize,
    tail: usize,
    capacity: usize,
}

impl Shard {
    fn unlink(&mut self, i: usize) {
        let (prev, next) = (self.nodes[i].prev, self.nodes[i].next);
        match prev {
            NIL => self.head = next,
            p => self.nodes[p].next = next,
        }
        match next {
            NIL => self.tail = prev,
            n => self.nodes[n].prev = prev,
        }
    }

    fn push_front(&mut self, i: usize) {
        self.nodes[i].prev = NIL;
        self.nodes[i].next = self.head;
        if self.head != NIL {
            self.nodes[self.head].prev = i;
        }
        self.head = i;
        if self.tail == NIL {
            self.tail = i;
        }
    }

    /// Drop node `i`, taking its file's size off `size`; the hash of the
    /// file to delete, if it had one.
    fn remove(&mut self, i: usize, size: &AtomicU64) -> Option<CacheHash> {
        self.unlink(i);
        let node = &self.nodes[i];
        let hash = node.hash;
        let file = node.exists.then_some(hash);
        if node.exists {
            size.fetch_sub(node.fs_size, Ordering::Relaxed);
        }
        self.map.remove(&hash);
        self.free.push(i);
        file
    }

    fn insert(&mut self, hash: CacheHash, now: i64) -> usize {
        let node = Node {
            hash,
            uses: 0,
            valid_sec: 0,
            updating_sec: 0,
            error_sec: 0,
            updating: false,
            lock_token: 0,
            lock_until_ms: 0,
            error: 0,
            exists: false,
            fs_size: 0,
            accessed: now,
            prev: NIL,
            next: NIL,
        };
        let i = match self.free.pop() {
            Some(i) => {
                self.nodes[i] = node;
                i
            }
            None => {
                self.nodes.push(node);
                self.nodes.len() - 1
            }
        };
        self.map.insert(hash, i);
        self.push_front(i);
        i
    }
}

/// What a lookup found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lookup {
    /// A fresh response is on disk.
    Hit,
    /// A cached intercepted error with this status.
    Error(u16),
    /// The response on disk is stale. `token`: this request now updates
    /// it (nginx's STALE); `None`: another request already does
    /// (UPDATING). `stale_updating` / `stale_error`: the response's own
    /// `stale-while-revalidate` / `stale-if-error` still cover it.
    Stale {
        token: Option<u64>,
        stale_updating: bool,
        stale_error: bool,
    },
    /// Nothing usable is cached. `store`: the key was asked for often
    /// enough (`proxy_cache_min_uses`) for the response to be stored.
    /// `probe`: the index doesn't know the key, so a file from before a
    /// restart may still hold it (nginx's cold cache).
    Miss { store: bool, probe: bool },
}

/// One `proxy_cache_path`.
pub struct CacheZone {
    pub name: &'static str,
    pub path: &'static Path,
    levels: [u8; 3],
    /// `inactive`: entries not asked for in this long go, with their files.
    inactive: i64,
    /// `max_size`: the files' total size; the least recently used go
    /// beyond it.
    max_size: u64,
    /// `min_free`: the free space the manager keeps on the cache's file
    /// system.
    min_free: u64,
    shards: Box<[Mutex<Shard>]>,
    /// Bytes of the files the index knows.
    size: AtomicU64,
    temp_seq: AtomicU64,
    lock_seq: AtomicU64,
}

/// A `proxy_cache_path` as configured.
pub struct ZoneConf {
    pub name: String,
    pub path: PathBuf,
    pub levels: [u8; 3],
    pub size: u64,
    pub inactive_secs: u64,
    pub max_size: Option<u64>,
    pub min_free: Option<u64>,
}

impl CacheZone {
    pub fn new(conf: ZoneConf) -> CacheZone {
        const SHARDS: usize = 16;
        let entries = (conf.size / 128).max(SHARDS as u64) as usize;
        let capacity = entries.div_ceil(SHARDS);
        let shards = (0..SHARDS)
            .map(|_| {
                Mutex::new(Shard {
                    map: HashMap::new(),
                    nodes: Vec::new(),
                    free: Vec::new(),
                    head: NIL,
                    tail: NIL,
                    capacity,
                })
            })
            .collect();
        CacheZone {
            name: Box::leak(conf.name.into_boxed_str()),
            path: Box::leak(conf.path.into_boxed_path()),
            levels: conf.levels,
            inactive: conf.inactive_secs as i64,
            max_size: conf.max_size.unwrap_or(u64::MAX),
            min_free: conf.min_free.unwrap_or(0),
            shards,
            size: AtomicU64::new(0),
            temp_seq: AtomicU64::new(0),
            lock_seq: AtomicU64::new(1),
        }
    }

    fn lock(&self, hash: &CacheHash) -> std::sync::MutexGuard<'_, Shard> {
        self.shards[usize::from(hash[0]) % self.shards.len()]
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    /// Where the file for `hash` lives: nginx's ngx_create_hashed_filename,
    /// each level named by the characters before the previous level's.
    pub fn file_path(&self, hash: &CacheHash) -> PathBuf {
        let name = hex(hash);
        let mut path = self.path.to_path_buf();
        let mut end = name.len();
        for level in self.levels {
            let level = usize::from(level);
            if level == 0 {
                break;
            }
            path.push(&name[end - level..end]);
            end -= level;
        }
        path.push(name);
        path
    }

    /// ngx_http_file_cache_exists for one request: count the use, and say
    /// what is cached.
    pub fn lookup(&self, hash: &CacheHash, min_uses: u32, now: i64) -> Lookup {
        let mut freed = Vec::new();
        let lookup = {
            let mut shard = self.lock(hash);
            let mut found = shard.map.get(hash).copied();
            if let Some(i) = found
                && now - shard.nodes[i].accessed > self.inactive
            {
                freed.extend(shard.remove(i, &self.size));
                found = None;
            }
            match found {
                Some(i) => {
                    shard.unlink(i);
                    shard.push_front(i);
                    let node = &mut shard.nodes[i];
                    node.uses = node.uses.saturating_add(1);
                    node.accessed = now;
                    if node.error != 0 && node.valid_sec >= now {
                        Lookup::Error(node.error)
                    } else if node.error != 0 {
                        // A stale error is forgotten (nginx's `renew`).
                        node.error = 0;
                        node.valid_sec = 0;
                        Lookup::Miss {
                            store: min_uses <= 1,
                            probe: false,
                        }
                    } else if node.exists && node.valid_sec >= now {
                        Lookup::Hit
                    } else if node.exists {
                        let stale_updating =
                            node.valid_sec.saturating_add(node.updating_sec) >= now;
                        let stale_error = node.valid_sec.saturating_add(node.error_sec) >= now;
                        let token = if node.updating {
                            None
                        } else {
                            let token = self.lock_seq.fetch_add(1, Ordering::Relaxed);
                            node.updating = true;
                            node.lock_token = token;
                            Some(token)
                        };
                        Lookup::Stale {
                            token,
                            stale_updating,
                            stale_error,
                        }
                    } else {
                        Lookup::Miss {
                            store: node.uses >= min_uses,
                            probe: false,
                        }
                    }
                }
                None => {
                    // nginx's forced expire when the zone is full.
                    while shard.map.len() >= shard.capacity && shard.tail != NIL {
                        let tail = shard.tail;
                        freed.extend(shard.remove(tail, &self.size));
                    }
                    let i = shard.insert(*hash, now);
                    shard.nodes[i].uses = 1;
                    Lookup::Miss {
                        store: min_uses <= 1,
                        probe: true,
                    }
                }
            }
        };
        self.delete_files(freed);
        lookup
    }

    /// A file from before a restart holds the key: the index learns it.
    pub fn adopt(&self, hash: &CacheHash, entry: &Entry) {
        let mut shard = self.lock(hash);
        let Some(&i) = shard.map.get(hash) else {
            return;
        };
        let node = &mut shard.nodes[i];
        if !node.exists {
            node.exists = true;
            node.valid_sec = entry.valid_sec;
            node.updating_sec = entry.updating_sec;
            node.error_sec = entry.error_sec;
            node.fs_size = entry.len();
            self.size.fetch_add(node.fs_size, Ordering::Relaxed);
        }
    }

    /// ngx_http_file_cache_lock: become the one request that fetches a
    /// missing response, unless another holds the lock and it is younger
    /// than `age_ms`. The token releases it.
    pub fn try_lock(&self, hash: &CacheHash, age_ms: u64) -> Option<u64> {
        let now = now_ms();
        let mut shard = self.lock(hash);
        let &i = shard.map.get(hash)?;
        let node = &mut shard.nodes[i];
        if node.updating && node.lock_until_ms > now {
            return None;
        }
        let token = self.lock_seq.fetch_add(1, Ordering::Relaxed);
        node.updating = true;
        node.lock_token = token;
        node.lock_until_ms = now + age_ms;
        Some(token)
    }

    /// When the lock on `hash` stops counting, or `None` when nobody holds
    /// it (or the key is gone).
    pub fn locked_until(&self, hash: &CacheHash) -> Option<u64> {
        let shard = self.lock(hash);
        let &i = shard.map.get(hash)?;
        let node = &shard.nodes[i];
        node.updating.then_some(node.lock_until_ms)
    }

    /// The request holding `token` is done (ngx_http_file_cache_free).
    pub fn release(&self, hash: &CacheHash, token: u64) {
        let mut shard = self.lock(hash);
        if let Some(&i) = shard.map.get(hash) {
            let node = &mut shard.nodes[i];
            if node.updating && node.lock_token == token {
                node.updating = false;
            }
        }
    }

    /// A fresh response is on disk for `hash`.
    pub fn is_fresh(&self, hash: &CacheHash, now: i64) -> bool {
        let shard = self.lock(hash);
        shard
            .map
            .get(hash)
            .is_some_and(|&i| shard.nodes[i].exists && shard.nodes[i].valid_sec >= now)
    }

    /// A stale response was revalidated (a 304): fresh again until
    /// `valid_sec`, in the index and in its file.
    pub fn refresh(&self, hash: &CacheHash, valid_sec: i64) {
        {
            let mut shard = self.lock(hash);
            let Some(&i) = shard.map.get(hash) else {
                return;
            };
            let node = &mut shard.nodes[i];
            if !node.exists {
                return;
            }
            node.valid_sec = valid_sec;
        }
        use std::os::unix::fs::FileExt;
        if let Ok(file) = std::fs::OpenOptions::new()
            .write(true)
            .open(self.file_path(hash))
        {
            let _ = file.write_all_at(&valid_sec.to_le_bytes(), 4);
        }
    }

    /// The file the index points to is gone or unreadable.
    pub fn forget_file(&self, hash: &CacheHash) {
        let mut shard = self.lock(hash);
        if let Some(&i) = shard.map.get(hash) {
            let node = &mut shard.nodes[i];
            if node.exists {
                node.exists = false;
                self.size.fetch_sub(node.fs_size, Ordering::Relaxed);
                node.fs_size = 0;
            }
        }
    }

    /// An intercepted error is cached as its status alone, as nginx's
    /// `fcn->error`.
    pub fn store_error(&self, hash: &CacheHash, status: u16, valid_sec: i64) {
        let old = {
            let mut shard = self.lock(hash);
            let Some(&i) = shard.map.get(hash) else {
                return;
            };
            let node = &mut shard.nodes[i];
            node.error = status;
            node.valid_sec = valid_sec;
            let old = node.exists.then_some(node.hash);
            if node.exists {
                self.size.fetch_sub(node.fs_size, Ordering::Relaxed);
            }
            node.exists = false;
            node.fs_size = 0;
            old
        };
        self.delete_files(old);
    }

    /// Write the response to a temporary file next to the cache and rename
    /// it into place, as nginx does with `use_temp_path=off`.
    pub fn store(&self, hash: &CacheHash, entry: &EntryParts<'_>) -> std::io::Result<()> {
        let path = self.file_path(hash);
        let seq = self.temp_seq.fetch_add(1, Ordering::Relaxed);
        let temp = self
            .path
            .join(format!(".tmp-{}-{seq:010}", std::process::id()));
        let written = (|| {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp)?;
            entry.write_to(&mut file)?;
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir)?;
            }
            std::fs::rename(&temp, &path)
        })();
        if let Err(e) = written {
            let _ = std::fs::remove_file(&temp);
            return Err(e);
        }
        let fs_size = entry.len();
        let mut freed = Vec::new();
        {
            let mut shard = self.lock(hash);
            match shard.map.get(hash).copied() {
                Some(i) => {
                    let node = &mut shard.nodes[i];
                    if node.exists {
                        self.size.fetch_sub(node.fs_size, Ordering::Relaxed);
                    }
                    node.exists = true;
                    node.error = 0;
                    node.valid_sec = entry.valid_sec;
                    node.updating_sec = entry.updating_sec;
                    node.error_sec = entry.error_sec;
                    node.fs_size = fs_size;
                    self.size.fetch_add(fs_size, Ordering::Relaxed);
                }
                // Evicted while the response was fetched: the file stays
                // for a later lookup to adopt.
                None => {}
            }
        }
        // `max_size`: the least recently used files go, in the other
        // shards too, never the one just stored.
        if self.size.load(Ordering::Relaxed) > self.max_size {
            for shard in self.shards.iter() {
                let mut shard = shard.lock().unwrap_or_else(|e| e.into_inner());
                let mut i = shard.tail;
                while i != NIL && self.size.load(Ordering::Relaxed) > self.max_size {
                    let prev = shard.nodes[i].prev;
                    if shard.nodes[i].exists && shard.nodes[i].hash != *hash {
                        freed.extend(shard.remove(i, &self.size));
                    }
                    i = prev;
                }
            }
        }
        self.delete_files(freed);
        Ok(())
    }

    /// One pass of nginx's cache manager (ngx_http_file_cache_expire and
    /// _forced_expire): entries not asked for in `inactive` go, then the
    /// least recently used while the files are over `max_size` or the file
    /// system has less than `min_free`.
    /// Entries a request is updating stay.
    pub fn manage(&self, now: i64) {
        let mut freed = Vec::new();
        for shard in self.shards.iter() {
            let mut shard = shard.lock().unwrap_or_else(|e| e.into_inner());
            let mut i = shard.tail;
            while i != NIL
                && now - shard.nodes[i].accessed > self.inactive
                && !shard.nodes[i].updating
            {
                let prev = shard.nodes[i].prev;
                freed.extend(shard.remove(i, &self.size));
                i = prev;
            }
        }
        // Over max_size, or under min_free: a shard's oldest file at a
        // time, round robin.
        let mut free = if self.min_free > 0 {
            free_space(self.path).unwrap_or(u64::MAX)
        } else {
            u64::MAX
        };
        let mut idle_rounds = 0;
        let mut next = 0;
        while (self.size.load(Ordering::Relaxed) > self.max_size || free < self.min_free)
            && idle_rounds < self.shards.len()
        {
            let mut shard = self.shards[next].lock().unwrap_or_else(|e| e.into_inner());
            next = (next + 1) % self.shards.len();
            let mut i = shard.tail;
            while i != NIL && (!shard.nodes[i].exists || shard.nodes[i].updating) {
                i = shard.nodes[i].prev;
            }
            if i == NIL {
                idle_rounds += 1;
                continue;
            }
            idle_rounds = 0;
            free = free.saturating_add(shard.nodes[i].fs_size);
            freed.extend(shard.remove(i, &self.size));
        }
        self.delete_files(freed);
    }

    /// nginx's cache loader: index the files already in the directory
    /// (from before a restart), so `inactive` and `max_size` count them.
    /// Leftover temp files go.
    pub fn load(&self, now: i64) {
        let mut dirs = vec![(self.path.to_path_buf(), 0usize)];
        while let Some((dir, depth)) = dirs.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            let levels = self.levels.iter().take_while(|&&l| l != 0).count();
            for entry in entries.flatten() {
                let name = entry.file_name();
                let Some(name) = name.to_str() else {
                    continue;
                };
                let path = entry.path();
                if name.starts_with(".tmp-") {
                    // Not this process's own: the workers may be writing them.
                    if !name.starts_with(&format!(".tmp-{}-", std::process::id())) {
                        let _ = std::fs::remove_file(&path);
                    }
                    continue;
                }
                let Ok(meta) = entry.metadata() else {
                    continue;
                };
                if meta.is_dir() {
                    if depth < levels {
                        dirs.push((path, depth + 1));
                    }
                    continue;
                }
                if depth != levels {
                    continue;
                }
                let Some(hash) = unhex(name) else {
                    continue;
                };
                let Some((valid_sec, updating_sec, error_sec)) = read_lifetimes(&path) else {
                    continue;
                };
                let mut shard = self.lock(&hash);
                if shard.map.contains_key(&hash) || shard.map.len() >= shard.capacity {
                    continue;
                }
                let i = shard.insert(hash, now);
                let node = &mut shard.nodes[i];
                node.uses = 1;
                node.exists = true;
                node.valid_sec = valid_sec;
                node.updating_sec = updating_sec;
                node.error_sec = error_sec;
                node.fs_size = meta.len();
                self.size.fetch_add(meta.len(), Ordering::Relaxed);
            }
        }
    }

    fn delete_files(&self, files: impl IntoIterator<Item = CacheHash>) {
        for hash in files {
            let _ = std::fs::remove_file(self.file_path(&hash));
        }
    }
}

/// Run the loader, then the manager every second, on a thread of its own
/// (nginx's cache loader and manager processes).
pub fn start_manager(zone: &'static CacheZone) {
    let _ = std::thread::Builder::new()
        .name(format!("ruxen-cache-{}", zone.name))
        .spawn(move || {
            zone.load(now_secs());
            loop {
                std::thread::sleep(std::time::Duration::from_secs(1));
                zone.manage(now_secs());
            }
        });
}

/// Bytes an unprivileged user may still write on `path`'s file system.
fn free_space(path: &Path) -> Option<u64> {
    use std::os::unix::ffi::OsStrExt;
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    // SAFETY: statvfs is plain data, for which all zeroes is a value.
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: a NUL-terminated path and a statvfs the call fills in.
    if unsafe { libc::statvfs(c_path.as_ptr(), &mut st) } != 0 {
        return None;
    }
    Some((st.f_bavail as u64).saturating_mul(st.f_frsize as u64))
}

fn unhex(name: &str) -> Option<CacheHash> {
    if name.len() != 32 {
        return None;
    }
    let mut hash = [0u8; 16];
    for (i, byte) in hash.iter_mut().enumerate() {
        *byte = u8::from_str_radix(name.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(hash)
}

/// `valid_sec`, `updating_sec` and `error_sec` from a cache file's fixed
/// header.
fn read_lifetimes(path: &Path) -> Option<(i64, i64, i64)> {
    use std::io::Read;
    let mut fixed = [0u8; 28];
    std::fs::File::open(path)
        .ok()?
        .read_exact(&mut fixed)
        .ok()?;
    if &fixed[..4] != MAGIC {
        return None;
    }
    let at = |i: usize| i64::from_le_bytes(fixed[i..i + 8].try_into().unwrap());
    Some((at(4), at(12), at(20)))
}

const MAGIC: &[u8; 4] = b"RXC1";
/// Magic, valid_sec, updating_sec, error_sec, the key's, Vary's and the
/// head's lengths, the body's length.
const FIXED: usize = 4 + 8 + 8 + 8 + 4 + 4 + 4 + 8;

/// A response to store.
pub struct EntryParts<'a> {
    pub valid_sec: i64,
    pub updating_sec: i64,
    pub error_sec: i64,
    pub key: &'a [u8],
    /// The `Vary` header the response came with, and the request's digest
    /// over the headers it names (`vary_digest`).
    pub vary: &'a [u8],
    pub variant: CacheHash,
    /// The upstream's status line and header lines, without the empty
    /// line that ends them.
    pub head: &'a [u8],
    pub body: &'a [u8],
}

impl EntryParts<'_> {
    fn len(&self) -> u64 {
        (FIXED + 16 + self.key.len() + self.vary.len() + self.head.len() + self.body.len()) as u64
    }

    fn write_to(&self, file: &mut std::fs::File) -> std::io::Result<()> {
        let mut fixed = Vec::with_capacity(FIXED + 16 + self.key.len() + self.vary.len());
        fixed.extend_from_slice(MAGIC);
        fixed.extend_from_slice(&self.valid_sec.to_le_bytes());
        fixed.extend_from_slice(&self.updating_sec.to_le_bytes());
        fixed.extend_from_slice(&self.error_sec.to_le_bytes());
        fixed.extend_from_slice(&(self.key.len() as u32).to_le_bytes());
        fixed.extend_from_slice(&(self.vary.len() as u32).to_le_bytes());
        fixed.extend_from_slice(&(self.head.len() as u32).to_le_bytes());
        fixed.extend_from_slice(&(self.body.len() as u64).to_le_bytes());
        fixed.extend_from_slice(&self.variant);
        fixed.extend_from_slice(self.key);
        fixed.extend_from_slice(self.vary);
        file.write_all(&fixed)?;
        file.write_all(self.head)?;
        file.write_all(self.body)
    }
}

/// A cached response read back.
pub struct Entry {
    pub valid_sec: i64,
    pub updating_sec: i64,
    pub error_sec: i64,
    bytes: Vec<u8>,
    variant: CacheHash,
    vary: (usize, usize),
    head: (usize, usize),
    body: (usize, usize),
}

impl Entry {
    /// The file for `key`, if it is one of ours and holds that key.
    pub fn read(path: &Path, key: &[u8]) -> Option<Entry> {
        let bytes = std::fs::read(path).ok()?;
        if bytes.len() < FIXED + 16 || &bytes[..4] != MAGIC {
            return None;
        }
        let u32_at = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()) as usize;
        let i64_at = |at: usize| i64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
        let valid_sec = i64_at(4);
        let updating_sec = i64_at(12);
        let error_sec = i64_at(20);
        let key_len = u32_at(28);
        let vary_len = u32_at(32);
        let head_len = u32_at(36);
        let body_len = i64_at(40) as usize;
        let mut variant = [0u8; 16];
        variant.copy_from_slice(&bytes[FIXED..FIXED + 16]);
        let key_at = FIXED + 16;
        let vary_at = key_at.checked_add(key_len)?;
        let head_at = vary_at.checked_add(vary_len)?;
        let body_at = head_at.checked_add(head_len)?;
        if body_at.checked_add(body_len)? != bytes.len() || &bytes[key_at..vary_at] != key {
            return None;
        }
        Some(Entry {
            valid_sec,
            updating_sec,
            error_sec,
            variant,
            vary: (vary_at, head_at),
            head: (head_at, body_at),
            body: (body_at, bytes.len()),
            bytes,
        })
    }

    pub fn head(&self) -> &[u8] {
        &self.bytes[self.head.0..self.head.1]
    }

    pub fn body(&self) -> &[u8] {
        &self.bytes[self.body.0..self.body.1]
    }

    pub fn len(&self) -> u64 {
        self.bytes.len() as u64
    }

    /// `Last-Modified` and `ETag` to revalidate with, kept only for 200 and
    /// 206 (nginx's `$upstream_cache_last_modified`, `$upstream_cache_etag`).
    pub fn validators(&self) -> (Option<&[u8]>, Option<&[u8]>) {
        let head = self.head();
        let status = head.get(9..12).unwrap_or(b"");
        if status != b"200" && status != b"206" {
            return (None, None);
        }
        let (mut last_modified, mut etag) = (None, None);
        for (name, value) in header_lines(head) {
            if last_modified.is_none() && name.eq_ignore_ascii_case(b"last-modified") {
                last_modified = Some(value);
            } else if etag.is_none() && name.eq_ignore_ascii_case(b"etag") {
                etag = Some(value);
            }
        }
        (last_modified, etag)
    }

    /// The status the response was stored with.
    pub fn status(&self) -> u16 {
        std::str::from_utf8(self.head().get(9..12).unwrap_or(b""))
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0)
    }

    /// The request is the variant the response was stored for: its
    /// headers named by the stored `Vary` have the same values.
    pub fn matches_variant(&self, request_headers: &[u8]) -> bool {
        let vary = &self.bytes[self.vary.0..self.vary.1];
        vary.is_empty() || vary_digest(vary, request_headers) == self.variant
    }
}

/// A header block's `(name, value)` lines, after its status line.
pub fn header_lines(head: &[u8]) -> impl Iterator<Item = (&[u8], &[u8])> {
    head.split(|&b| b == b'\n').skip(1).filter_map(|line| {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let colon = line.iter().position(|&b| b == b':')?;
        Some((line[..colon].trim_ascii(), line[colon + 1..].trim_ascii()))
    })
}

/// ngx_http_file_cache_vary: a digest over the request's values of the
/// headers a `Vary` value names, in its order. `request_headers` is the
/// raw request header block.
pub fn vary_digest(vary: &[u8], request_headers: &[u8]) -> CacheHash {
    let mut input = Vec::with_capacity(64);
    for name in vary.split(|&b| b == b',') {
        let name = name.trim_ascii();
        if name.is_empty() {
            continue;
        }
        for b in name {
            input.push(b.to_ascii_lowercase());
        }
        input.push(b':');
        let mut first = true;
        for line in request_headers.split(|&b| b == b'\n') {
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            let Some(colon) = line.iter().position(|&b| b == b':') else {
                continue;
            };
            if !line[..colon].trim_ascii().eq_ignore_ascii_case(name) {
                continue;
            }
            if !first {
                input.push(b',');
            }
            first = false;
            input.extend_from_slice(line[colon + 1..].trim_ascii());
        }
        input.extend_from_slice(b"\r\n");
    }
    hash_key(&input)
}

/// The cache fields of `proxy_ignore_headers`.
#[derive(Debug, Default, Clone, Copy)]
pub struct Ignore {
    pub x_accel_expires: bool,
    pub expires: bool,
    pub cache_control: bool,
    pub set_cookie: bool,
    pub vary: bool,
}

/// A cacheable response: until when it is fresh by its own headers (0:
/// they don't say, `proxy_cache_valid` decides), and its `Vary` value.
#[derive(Debug, PartialEq, Eq)]
pub struct Freshness<'a> {
    pub valid_sec: i64,
    /// `stale-while-revalidate` / `stale-if-error`.
    pub updating_sec: i64,
    pub error_sec: i64,
    pub vary: &'a [u8],
}

/// What the upstream's response header says about caching it (`None`: it
/// may not be cached), read in the order nginx's header handlers do
/// (ngx_http_upstream_process_cache_control, _expires, _accel_expires,
/// _set_cookie, _vary).
pub fn freshness<'a>(
    header_lines: impl Iterator<Item = (&'a [u8], &'a [u8])>,
    ignore: Ignore,
    now: i64,
) -> Option<Freshness<'a>> {
    let read = read_headers(header_lines, ignore, now);
    (read.cacheable && !read.no_cache && !read.expired).then_some(Freshness {
        valid_sec: read.valid_sec,
        updating_sec: read.updating_sec,
        error_sec: read.error_sec,
        vary: read.vary,
    })
}

/// The lifetime the headers give, whether or not they allow caching: what
/// a 304 revalidation renews an entry with (ngx_http_upstream_test_next's
/// `r->cache->valid_sec`).
pub fn header_valid_sec<'a>(
    header_lines: impl Iterator<Item = (&'a [u8], &'a [u8])>,
    ignore: Ignore,
    now: i64,
) -> i64 {
    read_headers(header_lines, ignore, now).valid_sec
}

struct HeaderRead<'a> {
    valid_sec: i64,
    updating_sec: i64,
    error_sec: i64,
    no_cache: bool,
    expired: bool,
    cacheable: bool,
    vary: &'a [u8],
}

fn read_headers<'a>(
    header_lines: impl Iterator<Item = (&'a [u8], &'a [u8])>,
    ignore: Ignore,
    now: i64,
) -> HeaderRead<'a> {
    let mut valid_sec: i64 = 0;
    let mut stale = (0, 0);
    let mut no_cache = false;
    let mut expired = false;
    let mut cacheable = true;
    let mut accel_seen = false;
    let mut expires_seen = false;
    let mut vary: &[u8] = b"";
    for (name, value) in header_lines {
        if name.eq_ignore_ascii_case(b"set-cookie") {
            if !ignore.set_cookie {
                cacheable = false;
            }
        } else if name.eq_ignore_ascii_case(b"cache-control") {
            if ignore.cache_control {
                continue;
            }
            match cache_control(value, valid_sec != 0 && accel_seen, now, &mut stale) {
                CacheControl::NotCacheable => cacheable = false,
                CacheControl::NoCache => no_cache = true,
                CacheControl::Valid(until) => {
                    valid_sec = until;
                    expired = false;
                }
                CacheControl::Silent => {}
            }
        } else if name.eq_ignore_ascii_case(b"expires") {
            // A second Expires is ignored (with nginx's warning).
            if expires_seen {
                continue;
            }
            expires_seen = true;
            if ignore.expires || valid_sec != 0 {
                continue;
            }
            match crate::file::parse_http_date(value) {
                Some(t) if t as i64 >= now => valid_sec = t as i64,
                _ => expired = true,
            }
        } else if name.eq_ignore_ascii_case(b"x-accel-expires") {
            if accel_seen {
                continue;
            }
            accel_seen = true;
            if ignore.x_accel_expires {
                continue;
            }
            let (at, digits) = match value.strip_prefix(b"@") {
                Some(rest) => (true, rest),
                None => (false, value),
            };
            let Some(n) = atoi(digits) else {
                continue;
            };
            if !at && n == 0 {
                cacheable = false;
                continue;
            }
            valid_sec = if at { n } else { now.saturating_add(n) };
            no_cache = false;
            expired = false;
        } else if name.eq_ignore_ascii_case(b"vary") {
            if ignore.vary {
                continue;
            }
            // NGX_HTTP_CACHE_VARY_LEN
            if value.len() > 128 || value == b"*" {
                cacheable = false;
            }
            vary = value;
        }
    }
    HeaderRead {
        valid_sec,
        updating_sec: stale.0,
        error_sec: stale.1,
        no_cache,
        expired,
        cacheable,
        vary,
    }
}

enum CacheControl {
    NotCacheable,
    NoCache,
    Valid(i64),
    Silent,
}

/// One Cache-Control line. `after_accel`: an X-Accel-Expires already set
/// the validity, so only the extensions are read. `stale`: the
/// `stale-while-revalidate` and `stale-if-error` seconds.
fn cache_control(
    value: &[u8],
    after_accel: bool,
    now: i64,
    stale: &mut (i64, i64),
) -> CacheControl {
    let mut out = CacheControl::Silent;
    if !after_accel {
        if find(value, b"no-cache").is_some()
            || find(value, b"no-store").is_some()
            || find(value, b"private").is_some()
        {
            return CacheControl::NoCache;
        }
        let at = find(value, b"s-maxage=")
            .map(|p| p + 9)
            .or_else(|| find(value, b"max-age=").map(|p| p + 8));
        if let Some(at) = at {
            let Some(n) = directive_number(&value[at..]) else {
                return CacheControl::NotCacheable;
            };
            if n == 0 {
                return CacheControl::NoCache;
            }
            out = CacheControl::Valid(now.saturating_add(n));
        }
    }
    // A malformed extension makes the response uncacheable.
    const SWR: &[u8] = b"stale-while-revalidate=";
    const SIE: &[u8] = b"stale-if-error=";
    if let Some(p) = find(value, SWR) {
        let Some(n) = directive_number(&value[p + SWR.len()..]) else {
            return CacheControl::NotCacheable;
        };
        *stale = (n, n);
    }
    if let Some(p) = find(value, SIE) {
        let Some(n) = directive_number(&value[p + SIE.len()..]) else {
            return CacheControl::NotCacheable;
        };
        stale.1 = n;
    }
    out
}

/// The digits of a Cache-Control value up to `,`, `;` or a space; `None`
/// for anything else in them. Saturates rather than wrapping.
fn directive_number(s: &[u8]) -> Option<i64> {
    let mut n: i64 = 0;
    for &b in s {
        match b {
            b',' | b';' | b' ' => break,
            b'0'..=b'9' => n = n.saturating_mul(10).saturating_add(i64::from(b - b'0')),
            _ => return None,
        }
    }
    Some(n)
}

/// ngx_atoi: digits only, at least one.
fn atoi(s: &[u8]) -> Option<i64> {
    if s.is_empty() || !s.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let mut n: i64 = 0;
    for &b in s {
        n = n.checked_mul(10)?.checked_add(i64::from(b - b'0'))?;
    }
    Some(n)
}

/// ngx_strlcasestrn: `needle` (lowercase) anywhere in `hay`, ignoring case.
fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len())
        .position(|w| w.eq_ignore_ascii_case(needle))
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_000_000;

    fn verdict(lines: &[(&str, &str)]) -> Option<i64> {
        freshness(
            lines.iter().map(|(n, v)| (n.as_bytes(), v.as_bytes())),
            Ignore::default(),
            NOW,
        )
        .map(|f| f.valid_sec)
    }

    #[test]
    fn freshness_follows_nginx_header_order() {
        let future = "Thu, 31 Dec 2037 23:55:55 GMT";
        let past = "Thu, 01 Jan 1970 00:00:01 GMT";
        assert_eq!(verdict(&[]), Some(0));
        assert_eq!(verdict(&[("Cache-Control", "max-age=60")]), Some(NOW + 60));
        assert_eq!(
            verdict(&[("Cache-Control", "max-age=1, s-maxage=10")]),
            Some(NOW + 10)
        );
        assert_eq!(verdict(&[("X-Accel-Expires", "60")]), Some(NOW + 60));
        assert_eq!(verdict(&[("X-Accel-Expires", "@60")]), Some(60));
        assert_eq!(
            verdict(&[("X-Accel-Expires", "60"), ("X-Accel-Expires", "0")]),
            Some(NOW + 60)
        );
        // Cache-Control wins over Expires, either order.
        assert_eq!(
            verdict(&[("Cache-Control", "max-age=60"), ("Expires", past)]),
            Some(NOW + 60)
        );
        assert_eq!(
            verdict(&[("Expires", past), ("Cache-Control", "max-age=60")]),
            Some(NOW + 60)
        );
        assert_eq!(
            verdict(&[("Cache-Control", "no-cache"), ("Expires", future)]),
            None
        );
        assert_eq!(
            verdict(&[("Expires", future), ("Cache-Control", "no-cache")]),
            None
        );
        // X-Accel-Expires wins over both.
        assert_eq!(
            verdict(&[
                ("X-Accel-Expires", "60"),
                ("Expires", past),
                ("Cache-Control", "no-cache")
            ]),
            Some(NOW + 60)
        );
        assert_eq!(
            verdict(&[
                ("Expires", past),
                ("Cache-Control", "no-cache"),
                ("X-Accel-Expires", "60")
            ]),
            Some(NOW + 60)
        );
        assert_eq!(
            verdict(&[("X-Accel-Expires", "0"), ("Cache-Control", "max-age=60")]),
            None
        );
        assert_eq!(
            verdict(&[("Cache-Control", "max-age=60"), ("X-Accel-Expires", "0")]),
            None
        );
        assert_eq!(verdict(&[("Cache-Control", "no-cache, max-age=60")]), None);
        assert_eq!(verdict(&[("Cache-Control", "max-age=x")]), None);
        assert_eq!(verdict(&[("Cache-Control", "max-age=0")]), None);
        assert_eq!(
            verdict(&[("Set-Cookie", "foo"), ("Cache-Control", "max-age=60")]),
            None
        );
        assert_eq!(verdict(&[("Vary", "*")]), None);
        assert_eq!(verdict(&[("Expires", "junk")]), None);
        assert_eq!(
            verdict(&[("Cache-Control", "max-age=9223372036854775808")]),
            Some(i64::MAX)
        );
    }

    #[test]
    fn ignored_headers_are_not_read() {
        let ignore = Ignore {
            x_accel_expires: true,
            expires: true,
            cache_control: true,
            set_cookie: true,
            vary: true,
        };
        let lines: [(&[u8], &[u8]); 4] = [
            (b"X-Accel-Expires", b"0"),
            (b"Cache-Control", b"no-store"),
            (b"Set-Cookie", b"a=b"),
            (b"Vary", b"*"),
        ];
        let f = freshness(lines.into_iter(), ignore, NOW).unwrap();
        assert_eq!(f.valid_sec, 0);
    }

    fn zone(dir: &Path, size: u64, max_size: Option<u64>) -> CacheZone {
        CacheZone::new(ZoneConf {
            name: "z".into(),
            path: dir.to_path_buf(),
            levels: [1, 2, 0],
            size,
            inactive_secs: 600,
            max_size,
            min_free: None,
        })
    }

    fn parts<'a>(key: &'a [u8], body: &'a [u8]) -> EntryParts<'a> {
        EntryParts {
            valid_sec: NOW + 60,
            updating_sec: 0,
            error_sec: 0,
            key,
            vary: b"",
            variant: [0; 16],
            head: b"HTTP/1.1 200 OK\r\nX-A: 1",
            body,
        }
    }

    #[test]
    fn store_then_hit_then_expire() {
        let dir = std::env::temp_dir().join(format!("ruxen-cache-unit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let z = zone(&dir, 1 << 20, None);
        let key = b"http://up/a";
        let hash = hash_key(key);
        assert_eq!(
            z.lookup(&hash, 1, NOW),
            Lookup::Miss {
                store: true,
                probe: true
            }
        );
        z.store(&hash, &parts(key, b"body")).unwrap();
        let path = z.file_path(&hash);
        let name = hex(&hash);
        assert!(path.ends_with(format!("{}/{}/{name}", &name[31..], &name[29..31])));
        assert_eq!(z.lookup(&hash, 1, NOW), Lookup::Hit);
        let entry = Entry::read(&path, key).unwrap();
        assert_eq!(entry.head(), b"HTTP/1.1 200 OK\r\nX-A: 1");
        assert_eq!(entry.body(), b"body");
        assert!(Entry::read(&path, b"other").is_none());
        let stale = z.lookup(&hash, 1, NOW + 61);
        let Lookup::Stale {
            token: Some(token), ..
        } = stale
        else {
            panic!("{stale:?}");
        };
        // A second request finds it being updated.
        assert!(matches!(
            z.lookup(&hash, 1, NOW + 61),
            Lookup::Stale { token: None, .. }
        ));
        z.release(&hash, token);
        // An error replaces the file.
        z.store_error(&hash, 404, NOW + 100);
        assert_eq!(z.lookup(&hash, 1, NOW + 62), Lookup::Error(404));
        assert!(!path.exists());
        assert_eq!(
            z.lookup(&hash, 1, NOW + 101),
            Lookup::Miss {
                store: true,
                probe: false
            }
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn min_uses_and_max_size() {
        let dir = std::env::temp_dir().join(format!("ruxen-cache-unit2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let z = zone(&dir, 1 << 20, Some(200));
        let (a, b) = (hash_key(b"a"), hash_key(b"b"));
        assert_eq!(
            z.lookup(&a, 2, NOW),
            Lookup::Miss {
                store: false,
                probe: true
            }
        );
        assert_eq!(
            z.lookup(&a, 2, NOW),
            Lookup::Miss {
                store: true,
                probe: false
            }
        );
        z.store(&a, &parts(b"a", &[b'x'; 100])).unwrap();
        z.lookup(&b, 1, NOW);
        z.store(&b, &parts(b"b", &[b'y'; 100])).unwrap();
        // Over 200 bytes: `a`, the least recently used, went.
        assert!(!z.file_path(&a).exists());
        assert!(z.file_path(&b).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn manager_drops_inactive_entries_and_loader_finds_files() {
        let dir = std::env::temp_dir().join(format!("ruxen-cache-unit4-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let z = zone(&dir, 1 << 20, None);
        let (a, b) = (hash_key(b"a"), hash_key(b"b"));
        z.lookup(&a, 1, NOW);
        z.store(&a, &parts(b"a", b"x")).unwrap();
        z.lookup(&b, 1, NOW + 500);
        z.store(&b, &parts(b"b", b"y")).unwrap();
        std::fs::write(dir.join(".tmp-1-0000000001"), "junk").unwrap();
        // A second zone on the same directory, as after a restart.
        let reloaded = zone(&dir, 1 << 20, None);
        reloaded.load(NOW + 500);
        assert!(!dir.join(".tmp-1-0000000001").exists());
        assert_eq!(reloaded.lookup(&a, 1, NOW + 50), Lookup::Hit);
        // `a` was last asked for 601 s before: inactive (600 s) and gone.
        z.manage(NOW + 601);
        assert!(!z.file_path(&a).exists());
        assert!(z.file_path(&b).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn stale_extensions_are_kept() {
        let f = freshness(
            [(
                &b"Cache-Control"[..],
                &b"max-age=10, stale-while-revalidate=5, stale-if-error=7"[..],
            )]
            .into_iter(),
            Ignore::default(),
            NOW,
        )
        .unwrap();
        assert_eq!((f.valid_sec, f.updating_sec, f.error_sec), (NOW + 10, 5, 7));
        assert_eq!(
            verdict(&[("Cache-Control", "max-age=10, stale-if-error=x")]),
            None
        );
    }

    #[test]
    fn locks_go_to_one_request_until_released_or_aged() {
        let dir = std::env::temp_dir().join(format!("ruxen-cache-unit3-{}", std::process::id()));
        let z = zone(&dir, 1 << 20, None);
        let hash = hash_key(b"k");
        z.lookup(&hash, 1, NOW);
        let token = z.try_lock(&hash, 60_000).unwrap();
        assert_eq!(z.try_lock(&hash, 60_000), None);
        assert!(z.locked_until(&hash).is_some());
        z.release(&hash, token);
        assert_eq!(z.locked_until(&hash), None);
        let _ = z.try_lock(&hash, 0).unwrap();
        // An aged lock is taken over.
        assert!(z.try_lock(&hash, 0).is_some());
    }

    #[test]
    fn variants_compare_the_named_request_headers() {
        let gz = b"Host: x\r\nAccept-Encoding: gzip\r\n";
        let plain = b"Host: x\r\n";
        assert_ne!(
            vary_digest(b"Accept-Encoding", gz),
            vary_digest(b"Accept-Encoding", plain)
        );
        assert_eq!(
            vary_digest(b"accept-encoding", gz),
            vary_digest(b"Accept-Encoding", b"accept-encoding:  gzip\r\n")
        );
    }
}
