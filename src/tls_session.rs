// Time-expiring wrappers for rustls session resumption state.
//
// rustls 0.23 ships an LRU `ServerSessionMemoryCache` (capacity-bounded but
// not time-bounded) and a key-rotating ticketer with a fixed 12-hour
// lifetime. Neither honors a per-server `ssl_session_timeout` — so without
// these wrappers, configurations like `ssl_session_timeout 1;` are silently
// ignored: clients keep resuming long after they should have re-handshaked.
//
// This module provides:
//
// - `ExpiringSessionStorage`: wraps any `StoresServerSessions` and stamps
//   each `put()` value with the insert time (prefixed to the value, so the
//   inner cache's own capacity bounds it). `get`/`take` returns `None` for
//   any entry older than the configured timeout. Used for TLS 1.2 SessionID
//   resumption.
// - `ExpiringTicketer`: wraps any `ProducesTickets` and prepends a u64
//   wall-clock timestamp (seconds since UNIX epoch) to each plaintext
//   before delegating to the inner ticketer. `decrypt` strips the prefix
//   and rejects tickets older than the configured lifetime. Used for TLS
//   1.3 PSK ticket resumption (and the TLS 1.2 ticket extension if
//   negotiated). The reported `lifetime()` is also the configured value
//   so clients receive an honest hint.

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rustls::server::{ProducesTickets, StoresServerSessions};

#[derive(Debug)]
pub struct ExpiringSessionStorage {
    inner: Arc<dyn StoresServerSessions>,
    timeout: Duration,
}

/// The insert time travels with the stored value, as 8 bytes of
/// milliseconds since a process-wide origin in front of it. A side map
/// keyed by session id would keep entries for sessions the inner cache
/// evicted on its own, and grow with every handshake.
fn now_ms() -> u64 {
    static ORIGIN: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    ORIGIN.get_or_init(Instant::now).elapsed().as_millis() as u64
}

impl ExpiringSessionStorage {
    pub fn new(inner: Arc<dyn StoresServerSessions>, timeout: Duration) -> Self {
        Self { inner, timeout }
    }

    /// The stored value without its timestamp, if it's still fresh.
    fn unwrap_fresh(&self, stored: Vec<u8>) -> Option<Vec<u8>> {
        let stamp: [u8; 8] = stored.get(..8)?.try_into().ok()?;
        let age = now_ms().saturating_sub(u64::from_be_bytes(stamp));
        if age > self.timeout.as_millis() as u64 {
            return None;
        }
        Some(stored[8..].to_vec())
    }
}

impl StoresServerSessions for ExpiringSessionStorage {
    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
        let mut stamped = Vec::with_capacity(8 + value.len());
        stamped.extend_from_slice(&now_ms().to_be_bytes());
        stamped.extend_from_slice(&value);
        self.inner.put(key, stamped)
    }

    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        let value = self.unwrap_fresh(self.inner.get(key)?);
        if value.is_none() {
            // Drop the inner entry so a future client can't keep resuming
            // a session that's already past `ssl_session_timeout`.
            let _ = self.inner.take(key);
        }
        value
    }

    fn take(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.unwrap_fresh(self.inner.take(key)?)
    }

    fn can_cache(&self) -> bool {
        self.inner.can_cache()
    }
}

#[derive(Debug)]
pub struct ExpiringTicketer {
    inner: Arc<dyn ProducesTickets>,
    timeout_secs: u32,
}

impl ExpiringTicketer {
    pub fn new(inner: Arc<dyn ProducesTickets>, timeout_secs: u32) -> Self {
        Self {
            inner,
            timeout_secs,
        }
    }
}

impl ProducesTickets for ExpiringTicketer {
    fn enabled(&self) -> bool {
        self.inner.enabled()
    }

    fn lifetime(&self) -> u32 {
        // Clamp to the inner ticketer's lifetime so we never claim a longer
        // life than the keying material actually supports.
        self.timeout_secs.min(self.inner.lifetime())
    }

    fn encrypt(&self, plain: &[u8]) -> Option<Vec<u8>> {
        let issued = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut wrapped = Vec::with_capacity(8 + plain.len());
        wrapped.extend_from_slice(&issued.to_be_bytes());
        wrapped.extend_from_slice(plain);
        self.inner.encrypt(&wrapped)
    }

    fn decrypt(&self, cipher: &[u8]) -> Option<Vec<u8>> {
        let plain = self.inner.decrypt(cipher)?;
        if plain.len() < 8 {
            return None;
        }
        let mut ts_bytes = [0u8; 8];
        ts_bytes.copy_from_slice(&plain[..8]);
        let issued = u64::from_be_bytes(ts_bytes);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if now.saturating_sub(issued) > self.timeout_secs as u64 {
            return None;
        }
        Some(plain[8..].to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::server::ServerSessionMemoryCache;

    #[test]
    fn session_storage_expires_entries() {
        let inner = ServerSessionMemoryCache::new(8);
        let store = ExpiringSessionStorage::new(inner, Duration::from_millis(40));
        assert!(store.put(b"k".to_vec(), b"v".to_vec()));
        assert_eq!(store.get(b"k"), Some(b"v".to_vec()));
        std::thread::sleep(Duration::from_millis(80));
        assert_eq!(store.get(b"k"), None);
    }

    #[test]
    fn session_storage_take_within_window_returns_value() {
        let inner = ServerSessionMemoryCache::new(8);
        let store = ExpiringSessionStorage::new(inner, Duration::from_secs(60));
        assert!(store.put(b"k".to_vec(), b"v".to_vec()));
        assert_eq!(store.take(b"k"), Some(b"v".to_vec()));
        assert_eq!(store.get(b"k"), None);
    }

    /// Nothing outside the inner cache grows: many more sessions than it
    /// holds leave it at its capacity, and the newest ones still resume.
    /// The timestamps used to live in a side map that kept an entry for
    /// every session the inner cache had evicted.
    #[test]
    fn session_storage_stays_within_the_inner_capacity() {
        let inner = ServerSessionMemoryCache::new(16);
        let store = ExpiringSessionStorage::new(inner, Duration::from_secs(60));
        for i in 0..10_000u32 {
            assert!(store.put(i.to_be_bytes().to_vec(), b"v".to_vec()));
        }
        assert_eq!(store.get(&9_999u32.to_be_bytes()), Some(b"v".to_vec()));
    }
}
