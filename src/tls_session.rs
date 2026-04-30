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
//   each `put()` with the insert time. `get`/`take` returns `None` for any
//   entry older than the configured timeout. Used for TLS 1.2 SessionID
//   resumption.
// - `ExpiringTicketer`: wraps any `ProducesTickets` and prepends a u64
//   wall-clock timestamp (seconds since UNIX epoch) to each plaintext
//   before delegating to the inner ticketer. `decrypt` strips the prefix
//   and rejects tickets older than the configured lifetime. Used for TLS
//   1.3 PSK ticket resumption (and the TLS 1.2 ticket extension if
//   negotiated). The reported `lifetime()` is also the configured value
//   so clients receive an honest hint.

use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rustls::server::{ProducesTickets, StoresServerSessions};

#[derive(Debug)]
pub struct ExpiringSessionStorage {
    inner: Arc<dyn StoresServerSessions>,
    timeout: Duration,
    timestamps: Mutex<std::collections::HashMap<Vec<u8>, Instant>>,
}

impl ExpiringSessionStorage {
    pub fn new(inner: Arc<dyn StoresServerSessions>, timeout: Duration) -> Self {
        Self {
            inner,
            timeout,
            timestamps: Mutex::new(std::collections::HashMap::new()),
        }
    }

    fn is_fresh(&self, key: &[u8]) -> bool {
        let mut guard = self.timestamps.lock().unwrap();
        let Some(&inserted) = guard.get(key) else {
            return false;
        };
        if inserted.elapsed() > self.timeout {
            guard.remove(key);
            false
        } else {
            true
        }
    }
}

impl StoresServerSessions for ExpiringSessionStorage {
    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
        let stored = self.inner.put(key.clone(), value);
        if stored {
            self.timestamps
                .lock()
                .unwrap()
                .insert(key, Instant::now());
        }
        stored
    }

    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        if !self.is_fresh(key) {
            // Drop the inner entry so a future client can't keep resuming
            // a session that's already past `ssl_session_timeout`.
            let _ = self.inner.take(key);
            return None;
        }
        self.inner.get(key)
    }

    fn take(&self, key: &[u8]) -> Option<Vec<u8>> {
        let fresh = self.is_fresh(key);
        self.timestamps.lock().unwrap().remove(key);
        let value = self.inner.take(key);
        if fresh { value } else { None }
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
}
