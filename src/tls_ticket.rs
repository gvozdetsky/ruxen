// Session ticket keys as nginx keeps them (#140).
//
// A ticket is RFC 5077's recommended layout, as OpenSSL builds it for
// nginx's ticket key callback (ngx_ssl_ticket_key_callback):
//
//     key_name (16) | IV (16) | AES-CBC(state) | HMAC-SHA256(32)
//
// with the HMAC over everything before it. The key name is visible to
// clients, so operators (and nginx-tests) can tell which key issued a
// ticket. The encrypted state is rustls's session encoding, so tickets
// resume across ruxen instances sharing key files, not with nginx.
//
// Keys come from one of three places, as in nginx 1.24:
//
// - `ssl_session_ticket_key` files (48 bytes: name, AES-128 key, HMAC key;
//   80 bytes: name, HMAC key, AES-256 key): the first encrypts, every one
//   decrypts, nothing rotates (ngx_ssl_session_ticket_keys).
// - with `ssl_session_cache shared:…`, keys rotating every
//   `ssl_session_timeout`, the previous one still decrypting while
//   tickets under it may be alive (ngx_ssl_rotate_ticket_keys). nginx
//   keeps them in the cache zone for its worker processes; ruxen's
//   workers are threads and share this ticketer.
// - otherwise one random key for the life of the process, as OpenSSL's
//   own ticket keys.

use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

use aws_lc_rs::cipher::{
    AES_128, AES_256, DecryptionContext, EncryptionContext, PaddedBlockDecryptingKey,
    PaddedBlockEncryptingKey, UnboundCipherKey,
};
use aws_lc_rs::hmac;
use aws_lc_rs::iv::FixedLength;
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use rustls::server::ProducesTickets;

const NAME_LEN: usize = 16;
const IV_LEN: usize = 16;
const MAC_LEN: usize = 32;

/// One ticket key: its name and the AES / HMAC keys (16 bytes each for a
/// 48-byte key, 32 for an 80-byte one).
pub struct TicketKey {
    name: [u8; NAME_LEN],
    encrypt: PaddedBlockEncryptingKey,
    decrypt: PaddedBlockDecryptingKey,
    hmac: hmac::Key,
}

impl std::fmt::Debug for TicketKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TicketKey({:02x?})", &self.name[..4])
    }
}

impl TicketKey {
    /// A key file's contents, laid out as nginx reads them.
    pub fn from_file_bytes(buf: &[u8]) -> Option<TicketKey> {
        let (aes, mac) = match buf.len() {
            48 => (&buf[16..32], &buf[32..48]),
            80 => (&buf[48..80], &buf[16..48]),
            _ => return None,
        };
        let algorithm = if aes.len() == 16 { &AES_128 } else { &AES_256 };
        let cipher = || UnboundCipherKey::new(algorithm, aes).ok();
        Some(TicketKey {
            name: buf[..NAME_LEN].try_into().ok()?,
            encrypt: PaddedBlockEncryptingKey::cbc_pkcs7(cipher()?).ok()?,
            decrypt: PaddedBlockDecryptingKey::cbc_pkcs7(cipher()?).ok()?,
            hmac: hmac::Key::new(hmac::HMAC_SHA256, mac),
        })
    }

    /// A fresh 80-byte key, as nginx draws its automatic ones.
    fn random() -> Option<TicketKey> {
        let mut buf = [0u8; 80];
        SystemRandom::new().fill(&mut buf).ok()?;
        let key = TicketKey::from_file_bytes(&buf);
        buf.fill(0);
        key
    }

    fn seal(&self, plain: &[u8]) -> Option<Vec<u8>> {
        let mut iv = [0u8; IV_LEN];
        SystemRandom::new().fill(&mut iv).ok()?;
        let mut body = plain.to_vec();
        self.encrypt
            .less_safe_encrypt(&mut body, EncryptionContext::Iv128(FixedLength::from(iv)))
            .ok()?;
        let mut out = Vec::with_capacity(NAME_LEN + IV_LEN + body.len() + MAC_LEN);
        out.extend_from_slice(&self.name);
        out.extend_from_slice(&iv);
        out.extend_from_slice(&body);
        let tag = hmac::sign(&self.hmac, &out);
        out.extend_from_slice(tag.as_ref());
        Some(out)
    }

    /// The state in `ticket`, which carries this key's name.
    fn open(&self, ticket: &[u8]) -> Option<Vec<u8>> {
        if ticket.len() < NAME_LEN + IV_LEN + MAC_LEN {
            return None;
        }
        let (signed, tag) = ticket.split_at(ticket.len() - MAC_LEN);
        hmac::verify(&self.hmac, signed, tag).ok()?;
        let iv: [u8; IV_LEN] = signed[NAME_LEN..NAME_LEN + IV_LEN].try_into().ok()?;
        let mut body = signed[NAME_LEN + IV_LEN..].to_vec();
        let plain = self
            .decrypt
            .decrypt(&mut body, DecryptionContext::Iv128(FixedLength::from(iv)))
            .ok()?;
        Some(plain.to_vec())
    }
}

/// Automatic keys: the current one, the previous one and the next one,
/// with nginx's expiry times (seconds since the epoch).
#[derive(Debug)]
struct Rotation {
    current: TicketKey,
    current_expire: u64,
    previous: TicketKey,
    previous_expire: u64,
    next: TicketKey,
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)] // one per TLS context, built at startup and never moved
enum Keys {
    /// From files, or a single random key: the first encrypts.
    Fixed(Vec<TicketKey>),
    Rotating {
        timeout: u64,
        keys: RwLock<Rotation>,
    },
}

/// The `ProducesTickets` for a TLS address (see the module comment).
#[derive(Debug)]
pub struct NginxTicketer {
    keys: Keys,
    lifetime: u32,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl NginxTicketer {
    /// Keys from `ssl_session_ticket_key` files, in order.
    pub fn from_keys(keys: Vec<TicketKey>, lifetime: u32) -> Option<NginxTicketer> {
        (!keys.is_empty()).then_some(NginxTicketer {
            keys: Keys::Fixed(keys),
            lifetime,
        })
    }

    /// One random key that never changes.
    pub fn single(lifetime: u32) -> Option<NginxTicketer> {
        NginxTicketer::from_keys(vec![TicketKey::random()?], lifetime)
    }

    /// Keys rotating every `timeout` seconds (`ssl_session_timeout`).
    pub fn rotating(timeout: u32) -> Option<NginxTicketer> {
        // The state after nginx's first rotation: the first key is current
        // (and also "previous", as nginx copies it), the next one drawn.
        let expire = now_secs() + timeout as u64;
        let mut buf = [0u8; 80];
        SystemRandom::new().fill(&mut buf).ok()?;
        let first = TicketKey::from_file_bytes(&buf);
        let copy = TicketKey::from_file_bytes(&buf);
        buf.fill(0);
        let (first, copy) = (first?, copy?);
        Some(NginxTicketer {
            keys: Keys::Rotating {
                timeout: timeout as u64,
                keys: RwLock::new(Rotation {
                    current: first,
                    current_expire: expire,
                    previous: copy,
                    previous_expire: expire,
                    next: TicketKey::random()?,
                }),
            },
            lifetime: timeout,
        })
    }

    /// ngx_ssl_rotate_ticket_keys, on every encrypt and decrypt.
    fn rotate(timeout: u64, keys: &RwLock<Rotation>) {
        let now = now_secs();
        let expire = now + timeout;
        {
            let r = keys.read().unwrap_or_else(|e| e.into_inner());
            if r.current_expire >= expire && r.previous_expire >= now {
                return;
            }
        }
        let mut r = keys.write().unwrap_or_else(|e| e.into_inner());
        if r.previous_expire < now {
            // The previous key is no longer needed: the current one takes
            // its place, the next one becomes current, and a new next one
            // is drawn.
            let Some(fresh) = TicketKey::random() else {
                return;
            };
            let next = std::mem::replace(&mut r.next, fresh);
            let current = std::mem::replace(&mut r.current, next);
            r.previous = current;
            r.previous_expire = r.current_expire;
            r.current_expire = 0;
        }
        // The current key is needed at least until a ticket issued now
        // expires.
        if expire > r.current_expire {
            r.current_expire = expire;
        }
    }
}

impl ProducesTickets for NginxTicketer {
    fn enabled(&self) -> bool {
        true
    }

    fn lifetime(&self) -> u32 {
        self.lifetime
    }

    fn encrypt(&self, plain: &[u8]) -> Option<Vec<u8>> {
        match &self.keys {
            Keys::Fixed(keys) => keys.first()?.seal(plain),
            Keys::Rotating { timeout, keys } => {
                NginxTicketer::rotate(*timeout, keys);
                keys.read()
                    .unwrap_or_else(|e| e.into_inner())
                    .current
                    .seal(plain)
            }
        }
    }

    fn decrypt(&self, ticket: &[u8]) -> Option<Vec<u8>> {
        let name = ticket.get(..NAME_LEN)?;
        match &self.keys {
            Keys::Fixed(keys) => keys.iter().find(|k| k.name == name)?.open(ticket),
            Keys::Rotating { timeout, keys } => {
                NginxTicketer::rotate(*timeout, keys);
                let r = keys.read().unwrap_or_else(|e| e.into_inner());
                [&r.current, &r.previous]
                    .into_iter()
                    .find(|k| k.name == name)?
                    .open(ticket)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file_key(len: usize, seed: u8) -> TicketKey {
        let buf: Vec<u8> = (0..len as u8).map(|i| i.wrapping_mul(seed)).collect();
        TicketKey::from_file_bytes(&buf).unwrap()
    }

    #[test]
    fn tickets_round_trip_and_carry_the_key_name() {
        for len in [48, 80] {
            let key = file_key(len, 7);
            let t = NginxTicketer::from_keys(vec![key], 300).unwrap();
            let ticket = t.encrypt(b"session state").unwrap();
            let name: Vec<u8> = (0..16u8).map(|i| i.wrapping_mul(7)).collect();
            assert_eq!(&ticket[..16], &name[..]);
            // name + IV + one padded block + HMAC.
            assert_eq!(ticket.len(), 16 + 16 + 16 + 32);
            assert_eq!(t.decrypt(&ticket).unwrap(), b"session state");
        }
        assert!(TicketKey::from_file_bytes(&[0; 47]).is_none());
    }

    #[test]
    fn tampered_or_unknown_tickets_are_refused() {
        let t = NginxTicketer::from_keys(vec![file_key(80, 3)], 300).unwrap();
        let mut ticket = t.encrypt(b"state").unwrap();
        let last = ticket.len() - 40;
        ticket[last] ^= 1;
        assert!(t.decrypt(&ticket).is_none());
        let other = NginxTicketer::from_keys(vec![file_key(80, 5)], 300).unwrap();
        assert!(other.decrypt(&t.encrypt(b"state").unwrap()).is_none());
        assert!(t.decrypt(b"short").is_none());
    }

    #[test]
    fn the_first_key_encrypts_all_decrypt() {
        let old = NginxTicketer::from_keys(vec![file_key(48, 3)], 300).unwrap();
        let ticket = old.encrypt(b"state").unwrap();
        let t = NginxTicketer::from_keys(vec![file_key(80, 5), file_key(48, 3)], 300).unwrap();
        assert_eq!(t.decrypt(&ticket).unwrap(), b"state");
        assert_eq!(&t.encrypt(b"x").unwrap()[..16], &file_key(80, 5).name[..]);
    }

    #[test]
    fn automatic_keys_rotate_and_keep_the_previous_one() {
        let t = NginxTicketer::rotating(300).unwrap();
        let first = t.encrypt(b"state").unwrap();
        let Keys::Rotating { keys, .. } = &t.keys else {
            unreachable!()
        };
        // Pretend the timeout has passed for the previous key.
        keys.write().unwrap().previous_expire = 0;
        let second = t.encrypt(b"state").unwrap();
        assert_ne!(&first[..16], &second[..16]);
        // The first key is now the previous one: its tickets still open.
        assert_eq!(t.decrypt(&first).unwrap(), b"state");
        // Once it expires too, they don't.
        keys.write().unwrap().previous_expire = 0;
        let _ = t.encrypt(b"state");
        assert!(t.decrypt(&first).is_none());
        assert_eq!(t.decrypt(&second).unwrap(), b"state");
    }
}
