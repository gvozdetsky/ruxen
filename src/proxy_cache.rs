//! `proxy_cache` (#233, step 1): upstream responses stored on disk and
//! served again while they are fresh (ngx_http_file_cache.c).
//!
//! nginx keeps a cache's index (`keys_zone`) in shared memory: a node per
//! key with its validity, use count, and whether a file holds the
//! response. Here the index is a heap value every worker reaches through
//! `&'static`, split into shards by the key's hash, each a `Mutex` around a
//! map and an LRU list, as the `limit_req` zones are. The capacity comes
//! from the zone's size (nginx's node is about 128 bytes) and is fixed: a
//! full shard drops its least recently used entry and that entry's file,
//! and sets the watermark the manager brings the zone under (#839).
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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

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
    /// Every status, in the order of `index`.
    pub const ALL: [CacheStatus; 7] = [
        CacheStatus::Miss,
        CacheStatus::Bypass,
        CacheStatus::Expired,
        CacheStatus::Stale,
        CacheStatus::Updating,
        CacheStatus::Revalidated,
        CacheStatus::Hit,
    ];

    /// The status's place in `ALL`.
    pub fn index(self) -> usize {
        self as usize
    }

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
    fn remove(&mut self, i: usize, size: &AtomicU64, count: &AtomicU64) -> Option<CacheHash> {
        self.unlink(i);
        count.fetch_sub(1, Ordering::Relaxed);
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

    fn insert(&mut self, hash: CacheHash, now: i64, count: &AtomicU64) -> usize {
        count.fetch_add(1, Ordering::Relaxed);
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
    /// Entries in the index, and how many the manager brings it under
    /// once the index was full (nginx's `sh->watermark`: 7/8 of what it
    /// held then).
    count: AtomicU64,
    watermark: AtomicU64,
    /// `manager_files`, `manager_sleep`, `manager_threshold`: a pass
    /// removes at most this many files, or works this long, then sleeps.
    /// A reload that keeps the zone sets them anew.
    manager_files: AtomicU64,
    manager_sleep_ms: AtomicU64,
    manager_threshold_ms: AtomicU64,
    temp_seq: AtomicU64,
    lock_seq: AtomicU64,
    /// The configured zone size (`keys_zone=name:size`).
    zone_size: u64,
    /// A manager thread looks after the zone (`start_manager`).
    managed: AtomicBool,
    /// No configuration uses the zone any more after a reload: its
    /// manager stops.
    retired: AtomicBool,
    /// Requests by `$upstream_cache_status` (`CacheStatus::ALL` order), for
    /// `ruxen_metrics` (#481).
    pub counters: crate::worker::metrics::ZoneCounters<7>,
}

/// The zones of the configurations workers serve. A reload that declares a
/// zone the same way gets the same one, with what its index knows, as
/// nginx keeps a shared memory zone of the same name and size (#89).
static ZONES: Mutex<Vec<&'static CacheZone>> = Mutex::new(Vec::new());

/// The zone for `conf`: the one already in use if it is the same,
/// otherwise a new one.
pub fn zone_for(conf: ZoneConf) -> &'static CacheZone {
    let mut zones = ZONES.lock().unwrap_or_else(|e| e.into_inner());
    let same = zones.iter().copied().find(|z| {
        z.name == conf.name
            && z.path == conf.path
            && z.levels == conf.levels
            && z.zone_size == conf.size
            && z.inactive == conf.inactive_secs as i64
            && z.max_size == conf.max_size.unwrap_or(u64::MAX)
            && z.min_free == conf.min_free.unwrap_or(0)
    });
    if let Some(zone) = same {
        zone.set_manager(&conf);
        return zone;
    }
    let zone: &'static CacheZone = Box::leak(Box::new(CacheZone::new(conf)));
    zones.push(zone);
    zone
}

/// After a reload: stop managing the zones `keep` (the new configuration's)
/// doesn't have.
pub fn retire_zones_but(keep: &[&'static CacheZone]) {
    let mut zones = ZONES.lock().unwrap_or_else(|e| e.into_inner());
    zones.retain(|z| {
        let kept = keep.iter().any(|k| std::ptr::eq(*k, *z));
        if !kept {
            z.retired.store(true, Ordering::Relaxed);
        }
        kept
    });
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
    pub manager_files: u64,
    pub manager_sleep_ms: u64,
    pub manager_threshold_ms: u64,
}

impl CacheZone {
    fn set_manager(&self, conf: &ZoneConf) {
        self.manager_files
            .store(conf.manager_files, Ordering::Relaxed);
        self.manager_sleep_ms
            .store(conf.manager_sleep_ms, Ordering::Relaxed);
        self.manager_threshold_ms
            .store(conf.manager_threshold_ms, Ordering::Relaxed);
    }

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
            count: AtomicU64::new(0),
            watermark: AtomicU64::new(u64::MAX),
            manager_files: AtomicU64::new(conf.manager_files),
            manager_sleep_ms: AtomicU64::new(conf.manager_sleep_ms),
            manager_threshold_ms: AtomicU64::new(conf.manager_threshold_ms),
            temp_seq: AtomicU64::new(0),
            lock_seq: AtomicU64::new(1),
            zone_size: conf.size,
            managed: AtomicBool::new(false),
            retired: AtomicBool::new(false),
            counters: Default::default(),
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
                freed.extend(shard.remove(i, &self.size, &self.count));
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
                    // The zone is full: nginx sets the watermark the
                    // manager brings it under, and expires the oldest now.
                    if shard.map.len() >= shard.capacity {
                        let count = self.count.load(Ordering::Relaxed);
                        self.watermark.store(count - count / 8, Ordering::Relaxed);
                    }
                    while shard.map.len() >= shard.capacity && shard.tail != NIL {
                        let tail = shard.tail;
                        freed.extend(shard.remove(tail, &self.size, &self.count));
                    }
                    let i = shard.insert(*hash, now, &self.count);
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
        self.fill(hash, entry)?.finish()
    }

    /// Start writing a response whose body is still coming (nginx's
    /// cacheable pipe, #463): the temp file gets the header and
    /// `entry.body`, `CacheFill::write` the rest.
    pub fn fill(&self, hash: &CacheHash, entry: &EntryParts<'_>) -> std::io::Result<CacheFill<'_>> {
        let seq = self.temp_seq.fetch_add(1, Ordering::Relaxed);
        let temp = self
            .path
            .join(format!(".tmp-{}-{seq:010}", std::process::id()));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)?;
        let mut fill = CacheFill {
            zone: self,
            hash: *hash,
            temp,
            file: None,
            valid_sec: entry.valid_sec,
            updating_sec: entry.updating_sec,
            error_sec: entry.error_sec,
            header_len: entry.len() - entry.body.len() as u64,
            body_len: entry.body.len() as u64,
            lock: None,
        };
        // On an error, dropping `fill` removes the temp file.
        entry.write_to(&mut file)?;
        fill.file = Some(file);
        Ok(fill)
    }

    /// A file renamed into place: the index counts it. Past `max_size`,
    /// the manager's next pass removes the oldest, as nginx's does.
    fn stored(&self, hash: &CacheHash, fill: &CacheFill<'_>) {
        let fs_size = fill.header_len + fill.body_len;
        let mut shard = self.lock(hash);
        // Evicted while the response was fetched: the file stays for a
        // later lookup to adopt.
        if let Some(i) = shard.map.get(hash).copied() {
            let node = &mut shard.nodes[i];
            if node.exists {
                self.size.fetch_sub(node.fs_size, Ordering::Relaxed);
            }
            node.exists = true;
            node.error = 0;
            node.valid_sec = fill.valid_sec;
            node.updating_sec = fill.updating_sec;
            node.error_sec = fill.error_sec;
            node.fs_size = fs_size;
            self.size.fetch_add(fs_size, Ordering::Relaxed);
        }
    }

    /// One pass of nginx's cache manager (ngx_http_file_cache_manager):
    /// entries not asked for in `inactive` go (_expire), then the least
    /// recently used while the files are over `max_size`, the index is at
    /// its watermark or the file system has less than `min_free`
    /// (_forced_expire). A pass removes at most `manager_files` entries and
    /// works at most `manager_threshold`; entries a request is updating
    /// stay. Returns how long to sleep before the next one.
    pub fn manage(&self, now: i64) -> std::time::Duration {
        use std::time::Duration;
        let started = std::time::Instant::now();
        let files_max = self.manager_files.load(Ordering::Relaxed);
        let sleep = Duration::from_millis(self.manager_sleep_ms.load(Ordering::Relaxed));
        let threshold = Duration::from_millis(self.manager_threshold_ms.load(Ordering::Relaxed));
        let mut files = 0u64;
        let mut freed = Vec::new();
        // A pass that did its share sleeps `manager_sleep`.
        let spent = |files: &mut u64| {
            *files += 1;
            *files >= files_max || started.elapsed() >= threshold
        };
        // Until the oldest entry left would expire, at most 10 s.
        let mut next = 10i64;
        for shard in self.shards.iter() {
            let mut shard = shard.lock().unwrap_or_else(|e| e.into_inner());
            let mut i = shard.tail;
            while i != NIL {
                let node = &shard.nodes[i];
                let wait = node.accessed + self.inactive - now;
                if wait >= 0 {
                    next = next.min(wait.max(1));
                    break;
                }
                let prev = node.prev;
                if !node.updating {
                    freed.extend(shard.remove(i, &self.size, &self.count));
                    if spent(&mut files) {
                        drop(shard);
                        self.delete_files(freed);
                        return sleep;
                    }
                }
                i = prev;
            }
        }
        let mut free = if self.min_free > 0 {
            free_space(self.path).unwrap_or(u64::MAX)
        } else {
            u64::MAX
        };
        // The least recently used entry of the zone at a time: the oldest of
        // the shards' oldest.
        let mut wait = Duration::from_secs(next as u64);
        while self.size.load(Ordering::Relaxed) > self.max_size
            || self.count.load(Ordering::Relaxed) >= self.watermark.load(Ordering::Relaxed)
            || free < self.min_free
        {
            let oldest = |shard: &Shard| {
                let mut i = shard.tail;
                while i != NIL && shard.nodes[i].updating {
                    i = shard.nodes[i].prev;
                }
                (i != NIL).then_some(i)
            };
            let mut pick: Option<(usize, i64)> = None;
            for (at, shard) in self.shards.iter().enumerate() {
                let shard = shard.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(i) = oldest(&shard)
                    && pick.is_none_or(|(_, accessed)| shard.nodes[i].accessed < accessed)
                {
                    pick = Some((at, shard.nodes[i].accessed));
                }
            }
            let Some((at, _)) = pick else {
                // Nothing to remove (all being updated): nginx waits 10 s.
                wait = Duration::from_secs(10);
                break;
            };
            let mut shard = self.shards[at].lock().unwrap_or_else(|e| e.into_inner());
            if let Some(i) = oldest(&shard) {
                if shard.nodes[i].exists {
                    free = free.saturating_add(shard.nodes[i].fs_size);
                }
                freed.extend(shard.remove(i, &self.size, &self.count));
            }
            drop(shard);
            if spent(&mut files) {
                wait = sleep;
                break;
            }
        }
        self.delete_files(freed);
        wait
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
                if shard.map.contains_key(&hash) {
                    continue;
                }
                if shard.map.len() >= shard.capacity {
                    // nginx's loader, when the zone is full.
                    let count = self.count.load(Ordering::Relaxed);
                    self.watermark.store(count - count / 8, Ordering::Relaxed);
                    continue;
                }
                let i = shard.insert(hash, now, &self.count);
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
    // A zone a reload kept has its manager already.
    if zone.managed.swap(true, Ordering::Relaxed) {
        return;
    }
    let spawned = std::thread::Builder::new()
        .name(format!("ruxen-cache-{}", zone.name))
        .spawn(move || {
            // A pass that panics is logged by the panic hook, and the next
            // one runs: the zone keeps its upkeep (`inactive`, `min_free`),
            // as nginx's master respawns its cache manager (#524). The
            // shard locks ignore poisoning.
            let pass = |f: &dyn Fn()| {
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
            };
            pass(&|| zone.load(now_secs()));
            let mut test_panic =
                crate::worker::panics::test_panic() == crate::worker::panics::TestPanic::Cache;
            let mut next = std::time::Duration::from_secs(1);
            while !zone.retired.load(Ordering::Relaxed) {
                // In steps of at most a second, for `retired`.
                let until = std::time::Instant::now() + next;
                loop {
                    let left = until.saturating_duration_since(std::time::Instant::now());
                    if left.is_zero() || zone.retired.load(Ordering::Relaxed) {
                        break;
                    }
                    std::thread::sleep(left.min(std::time::Duration::from_secs(1)));
                }
                let panic_now = std::mem::take(&mut test_panic);
                let wait = std::cell::Cell::new(std::time::Duration::from_secs(1));
                pass(&|| {
                    if panic_now {
                        panic!("RUXEN_TEST_PANIC=cache");
                    }
                    wait.set(zone.manage(now_secs()));
                });
                next = wait.get();
            }
        });
    if let Err(e) = spawned {
        // The next reload that keeps the zone tries again.
        zone.managed.store(false, Ordering::Relaxed);
        crate::worker::panics::write_running_log(
            crate::config::ErrorLogLevel::Alert,
            &format!(
                "starting the cache manager of \"{}\" failed ({e})",
                zone.name
            ),
        );
    }
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
/// Where the body's length is in the fixed header.
const BODY_LEN_AT: u64 = 4 + 8 + 8 + 8 + 4 + 4 + 4;

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

/// A response on its way into the cache: its temp file, written as the
/// body is relayed; `finish` puts it in place. Dropped unfinished (the
/// upstream failed, or the client went away and nothing reads on), the
/// temp file goes, as ngx_http_file_cache_free deletes it.
pub struct CacheFill<'z> {
    zone: &'z CacheZone,
    /// Where the file goes.
    hash: CacheHash,
    /// Empty once renamed into place.
    temp: PathBuf,
    /// `None` once a write failed: the entry isn't stored.
    file: Option<std::fs::File>,
    valid_sec: i64,
    updating_sec: i64,
    error_sec: i64,
    /// The file's bytes before the body.
    header_len: u64,
    body_len: u64,
    /// The update lock (`proxy_cache_lock`, a stale entry's update), held
    /// until the file is in place: the lookup hash and the token.
    lock: Option<(CacheHash, u64)>,
}

impl CacheFill<'_> {
    /// Hold the zone's lock for `hash` until the fill ends.
    pub fn hold_lock(&mut self, hash: CacheHash, token: u64) {
        self.lock = Some((hash, token));
    }

    /// The file is still being written.
    pub fn writing(&self) -> bool {
        self.file.is_some()
    }

    #[inline(never)]
    pub fn write(&mut self, body: &[u8]) {
        if let Some(file) = &mut self.file {
            if file.write_all(body).is_ok() {
                self.body_len += body.len() as u64;
            } else {
                self.file = None;
            }
        }
    }

    /// The body is complete: its length into the header, the file into
    /// place.
    pub fn finish(mut self) -> std::io::Result<()> {
        use std::os::unix::fs::FileExt;
        let Some(file) = self.file.take() else {
            return Err(std::io::ErrorKind::Other.into());
        };
        file.write_all_at(&self.body_len.to_le_bytes(), BODY_LEN_AT)?;
        drop(file);
        let path = self.zone.file_path(&self.hash);
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::rename(&self.temp, &path)?;
        self.temp = PathBuf::new();
        self.zone.stored(&self.hash, &self);
        Ok(())
    }
}

impl Drop for CacheFill<'_> {
    fn drop(&mut self) {
        if !self.temp.as_os_str().is_empty() {
            let _ = std::fs::remove_file(&self.temp);
        }
        if let Some((hash, token)) = self.lock {
            self.zone.release(&hash, token);
        }
    }
}

/// What a hit reads first: the fixed header, the key, `Vary` and the
/// upstream's head, and a small body with them. A longer body stays in the
/// file, sent from it (ngx_http_file_cache_read reads `body_start` bytes,
/// ngx_http_cache_send sends the rest as a file buffer).
const FIRST_READ: usize = 16 * 1024;

/// A cached response read back: its header in memory, its body in the
/// file, which stays open so that an eviction or a newer response renamed
/// over it doesn't change what this hit sends.
pub struct Entry {
    pub valid_sec: i64,
    pub updating_sec: i64,
    pub error_sec: i64,
    /// The file's start, through the head at least.
    bytes: Vec<u8>,
    variant: CacheHash,
    vary: (usize, usize),
    head: (usize, usize),
    /// The body's offset in the file, and its length.
    body: (u64, u64),
    file: std::fs::File,
}

impl Entry {
    /// The file for `key`, if it is one of ours and holds that key.
    pub fn read(path: &Path, key: &[u8]) -> Option<Entry> {
        use std::io::Read;
        let mut file = std::fs::File::open(path).ok()?;
        let size = file.metadata().ok()?.len();
        let mut bytes = vec![0u8; (size as usize).min(FIRST_READ)];
        file.read_exact(&mut bytes).ok()?;
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
        let body_len = i64_at(40) as u64;
        let mut variant = [0u8; 16];
        variant.copy_from_slice(&bytes[FIXED..FIXED + 16]);
        let key_at = FIXED + 16;
        let vary_at = key_at.checked_add(key_len)?;
        let head_at = vary_at.checked_add(vary_len)?;
        let body_at = head_at.checked_add(head_len)?;
        if (body_at as u64).checked_add(body_len)? != size {
            return None;
        }
        // A head longer than the first read: the rest of it.
        if body_at > bytes.len() {
            let have = bytes.len();
            bytes.resize(body_at, 0);
            file.read_exact(&mut bytes[have..]).ok()?;
        }
        if &bytes[key_at..vary_at] != key {
            return None;
        }
        Some(Entry {
            valid_sec,
            updating_sec,
            error_sec,
            variant,
            vary: (vary_at, head_at),
            head: (head_at, body_at),
            body: (body_at as u64, body_len),
            bytes,
            file,
        })
    }

    pub fn head(&self) -> &[u8] {
        &self.bytes[self.head.0..self.head.1]
    }

    pub fn body_len(&self) -> u64 {
        self.body.1
    }

    /// The body, when the first read got it whole.
    pub fn body_in_memory(&self) -> Option<&[u8]> {
        let at = self.body.0 as usize;
        (self.bytes.len() as u64 == self.body.0 + self.body.1).then(|| &self.bytes[at..])
    }

    /// The body as a part of the open file.
    pub fn into_file_body(self) -> crate::phase::FileBody {
        crate::phase::FileBody {
            fd: self.file.into(),
            offset: self.body.0,
            len: self.body.1,
        }
    }

    /// The file's size.
    pub fn len(&self) -> u64 {
        self.body.0 + self.body.1
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

    /// ngx_http_file_cache_read's vary check: `None` when the request is
    /// the variant the response was stored for (or it has no `Vary`), else
    /// the request's own variant, the key to look again at.
    pub fn other_variant(&self, main: &CacheHash, request_headers: &[u8]) -> Option<CacheHash> {
        other_variant(
            &self.bytes[self.vary.0..self.vary.1],
            &self.variant,
            main,
            request_headers,
        )
    }
}

fn other_variant(
    vary: &[u8],
    variant: &CacheHash,
    main: &CacheHash,
    request_headers: &[u8],
) -> Option<CacheHash> {
    if vary.is_empty() {
        return None;
    }
    let own = vary_digest(main, vary, request_headers);
    (own != *variant).then_some(own)
}

/// `Entry::other_variant` from the file's header alone, for a lookup that
/// doesn't read the response.
pub fn stored_other_variant(
    path: &Path,
    key: &[u8],
    main: &CacheHash,
    request_headers: &[u8],
) -> Option<CacheHash> {
    use std::io::Read;
    let mut file = std::fs::File::open(path).ok()?;
    let mut fixed = [0u8; FIXED + 16];
    file.read_exact(&mut fixed).ok()?;
    if &fixed[..4] != MAGIC {
        return None;
    }
    let u32_at = |at: usize| u32::from_le_bytes(fixed[at..at + 4].try_into().unwrap()) as usize;
    let (key_len, vary_len) = (u32_at(28), u32_at(32));
    if vary_len == 0 || key_len != key.len() || vary_len > 4096 {
        return None;
    }
    let mut rest = vec![0u8; key_len + vary_len];
    file.read_exact(&mut rest).ok()?;
    if &rest[..key_len] != key {
        return None;
    }
    let variant: CacheHash = fixed[FIXED..].try_into().unwrap();
    other_variant(&rest[key_len..], &variant, main, request_headers)
}

/// A header block's `(name, value)` lines, after its status line.
pub fn header_lines(head: &[u8]) -> impl Iterator<Item = (&[u8], &[u8])> {
    head.split(|&b| b == b'\n').skip(1).filter_map(|line| {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let colon = line.iter().position(|&b| b == b':')?;
        Some((line[..colon].trim_ascii(), line[colon + 1..].trim_ascii()))
    })
}

/// ngx_http_file_cache_vary: the variant's key, a digest over the main
/// key's and the request's values of the headers a `Vary` value names, in
/// its order. `request_headers` is the raw request header block.
pub fn vary_digest(main: &CacheHash, vary: &[u8], request_headers: &[u8]) -> CacheHash {
    let mut input = Vec::with_capacity(64);
    input.extend_from_slice(main);
    for name in list_items(vary) {
        for b in name {
            input.push(b.to_ascii_lowercase());
        }
        input.push(b':');
        // ngx_http_file_cache_vary_header: the values of every header of
        // that name, joined with ","; for these three, each list item.
        let normalize = [
            &b"accept-charset"[..],
            b"accept-encoding",
            b"accept-language",
        ]
        .iter()
        .any(|n| name.eq_ignore_ascii_case(n));
        let mut first = true;
        for line in request_headers.split(|&b| b == b'\n') {
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            let Some(colon) = line.iter().position(|&b| b == b':') else {
                continue;
            };
            if !line[..colon].trim_ascii().eq_ignore_ascii_case(name) {
                continue;
            }
            let value = line[colon + 1..].trim_ascii();
            let mut push = |item: &[u8]| {
                if !first {
                    input.push(b',');
                }
                first = false;
                input.extend_from_slice(item);
            };
            if normalize {
                list_items(value).for_each(push);
            } else {
                push(value);
            }
        }
        input.extend_from_slice(b"\r\n");
    }
    hash_key(&input)
}

/// A header list's items: between spaces and commas.
fn list_items(value: &[u8]) -> impl Iterator<Item = &[u8]> {
    value
        .split(|&b| b == b' ' || b == b',')
        .filter(|item| !item.is_empty())
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
    pub vary: std::borrow::Cow<'a, [u8]>,
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
    vary: std::borrow::Cow<'a, [u8]>,
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
    let mut vary = std::borrow::Cow::Borrowed(&b""[..]);
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
            if value == b"*" {
                cacheable = false;
            }
            // ngx_http_upstream_process_vary: several headers are one
            // list (ticket #1423).
            if vary.is_empty() {
                vary = std::borrow::Cow::Borrowed(value);
            } else {
                let joined = vary.to_mut();
                joined.extend_from_slice(b", ");
                joined.extend_from_slice(value);
            }
            // NGX_HTTP_CACHE_VARY_LEN
            if vary.len() > 128 {
                cacheable = false;
            }
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
        CacheZone::new(zone_conf(dir, size, max_size))
    }

    fn zone_conf(dir: &Path, size: u64, max_size: Option<u64>) -> ZoneConf {
        ZoneConf {
            name: "z".into(),
            path: dir.to_path_buf(),
            levels: [1, 2, 0],
            size,
            inactive_secs: 600,
            max_size,
            min_free: None,
            manager_files: 100,
            manager_sleep_ms: 50,
            manager_threshold_ms: 200,
        }
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
        assert_eq!(entry.body_in_memory(), Some(&b"body"[..]));
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
        z.lookup(&b, 1, NOW + 1);
        z.store(&b, &parts(b"b", &[b'y'; 100])).unwrap();
        // Over 200 bytes: the manager's next pass removes `a`, the least
        // recently used.
        assert!(z.file_path(&a).exists());
        z.manage(NOW + 1);
        assert!(!z.file_path(&a).exists());
        assert!(z.file_path(&b).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `manager_files` per pass, then `manager_sleep`; a full index sets
    /// the watermark the manager brings it under (#839).
    #[test]
    fn manager_files_and_watermark() {
        let dir = std::env::temp_dir().join(format!("ruxen-cache-unit5-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut conf = zone_conf(&dir, 1 << 20, Some(0));
        conf.manager_files = 2;
        conf.manager_sleep_ms = 5000;
        let z = CacheZone::new(conf);
        let keys: Vec<_> = (0..5u8).map(|k| hash_key(&[k])).collect();
        for (n, k) in keys.iter().enumerate() {
            z.lookup(k, 1, NOW + n as i64);
            z.store(k, &parts(b"k", b"body")).unwrap();
        }
        let on_disk = |z: &CacheZone| keys.iter().filter(|k| z.file_path(k).exists()).count();
        assert_eq!(z.manage(NOW + 5), std::time::Duration::from_secs(5));
        assert_eq!(on_disk(&z), 3);
        // The oldest went first.
        assert!(!z.file_path(&keys[0]).exists() && !z.file_path(&keys[1]).exists());
        z.manage(NOW + 5);
        z.manage(NOW + 5);
        assert_eq!(on_disk(&z), 0);

        // 16 entries fit (one per shard): filling past that sets the
        // watermark at 7/8, and a pass removes down below it.
        let z = zone(&dir, 2048, None);
        for k in 0..200u16 {
            z.lookup(&hash_key(&k.to_be_bytes()), 1, NOW);
        }
        let full = z.count.load(Ordering::Relaxed);
        let watermark = z.watermark.load(Ordering::Relaxed);
        assert!(watermark < full, "{watermark} {full}");
        z.manage(NOW);
        assert!(z.count.load(Ordering::Relaxed) < watermark);
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
        let main = hash_key(b"/");
        let gz = b"Host: x\r\nAccept-Encoding: gzip\r\n";
        let plain = b"Host: x\r\n";
        assert_ne!(
            vary_digest(&main, b"Accept-Encoding", gz),
            vary_digest(&main, b"Accept-Encoding", plain)
        );
        assert_ne!(
            vary_digest(&main, b"Accept-Encoding", gz),
            vary_digest(&hash_key(b"/other"), b"Accept-Encoding", gz)
        );
        assert_eq!(
            vary_digest(&main, b",, accept-encoding , ,", gz),
            vary_digest(&main, b"Accept-Encoding", b"accept-encoding:  gzip\r\n")
        );
        // Accept-Encoding's list items, whatever the spaces and empty items.
        let ae = |v: &str| format!("Accept-Encoding: {v}\r\n").into_bytes();
        let d = |v: &str| vary_digest(&main, b"Accept-Encoding", &ae(v));
        assert_eq!(d("foo, bar"), d("foo,bar"));
        assert_eq!(d("foo, bar"), d("foo,,  ,bar , "));
        assert_ne!(d("foo, bar"), d("foobar"));
        assert_ne!(d("foo, bar"), d("bar, foo"));
        // Other headers compare as they are; several of a name are one.
        let x = |h: &[u8]| vary_digest(&main, b"X", h);
        assert_ne!(x(b"X: a, b\r\n"), x(b"X: a,b\r\n"));
        assert_eq!(x(b"X: a\r\nX: b\r\n"), x(b"X: a,b\r\n"));
    }

    #[test]
    fn several_vary_headers_are_one_list() {
        let lines: [(&[u8], &[u8]); 2] = [(b"Vary", b"Accept-Encoding"), (b"Vary", b"Foo")];
        let f = freshness(lines.into_iter(), Ignore::default(), NOW).unwrap();
        assert_eq!(&*f.vary, b"Accept-Encoding, Foo");
        let long = [b'a'; 100];
        let lines: [(&[u8], &[u8]); 2] = [(b"Vary", &long), (b"Vary", &long)];
        assert!(freshness(lines.into_iter(), Ignore::default(), NOW).is_none());
    }

    #[test]
    fn the_header_alone_tells_the_variant() {
        let dir = std::env::temp_dir().join(format!("ruxen-vary-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let z = zone(&dir, 1 << 20, None);
        let main = hash_key(b"k");
        let gz = b"Accept-Encoding: gzip\r\n";
        let mut entry = parts(b"k", b"body");
        entry.vary = b"Accept-Encoding";
        entry.variant = vary_digest(&main, b"Accept-Encoding", gz);
        z.store(&main, &entry).unwrap();
        let path = z.file_path(&main);
        assert_eq!(stored_other_variant(&path, b"k", &main, gz), None);
        let own = vary_digest(&main, b"Accept-Encoding", b"");
        assert_eq!(stored_other_variant(&path, b"k", &main, b""), Some(own));
        let read = Entry::read(&path, b"k").unwrap();
        assert_eq!(read.other_variant(&main, gz), None);
        assert_eq!(read.other_variant(&main, b""), Some(own));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
