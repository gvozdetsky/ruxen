//! Kernel TLS (#673): with `ssl_conf_command Options KTLS`, rustls runs
//! the handshake and the kernel then encrypts and decrypts the records,
//! so `sendfile` works over TLS (nginx's `SSL_sendfile`,
//! ngx_event_openssl.c).
//!
//! The switch happens once, right after the handshake (`switch`). Rustls
//! is gone then. TLS 1.3 key updates (#852) go on with the application
//! traffic secrets rustls logs (`SecretLog`): rustls's buffered API has
//! no `KernelConnection`, so the next keys are derived here (RFC 8446,
//! 7.2), and the kernel takes them again (`TLS_RX` / `TLS_TX`, Linux 6.14
//! and later; on older kernels the connection closes). A client's
//! KeyUpdate rekeys RX, and answers with our own when asked; near the
//! AES-GCM record limit the server updates its keys itself.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Duration, Instant};

use monoio::BufResult;
use monoio::buf::{IoBuf, IoBufMut, IoVecBuf, IoVecBufMut};
use monoio::io::{AsyncReadRent, AsyncWriteRent};
use monoio::net::TcpStream;
use rustls::crypto::tls13::{Hkdf, OkmBlock};
use rustls::{ConnectionTrafficSecrets, ProtocolVersion, SupportedCipherSuite};

use crate::tls_stream::{IntoKtls, TlsStream};

/// Where a stream of TLS records stands: in a header, in a body, or
/// between records. Also its first bytes, for the ClientHello's random.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RecordCursor {
    header: [u8; 5],
    have: u8,
    body_left: usize,
    start: [u8; START],
    start_len: u8,
}

/// Record header, handshake header, version, random.
const START: usize = 5 + 4 + 2 + 32;

impl Default for RecordCursor {
    fn default() -> Self {
        RecordCursor {
            header: [0; 5],
            have: 0,
            body_left: 0,
            start: [0; START],
            start_len: 0,
        }
    }
}

impl RecordCursor {
    pub(crate) fn feed(&mut self, mut bytes: &[u8]) {
        let have = usize::from(self.start_len);
        if have < START {
            let n = (START - have).min(bytes.len());
            self.start[have..have + n].copy_from_slice(&bytes[..n]);
            self.start_len = (have + n) as u8;
        }
        while !bytes.is_empty() {
            if self.body_left > 0 {
                let n = self.body_left.min(bytes.len());
                self.body_left -= n;
                bytes = &bytes[n..];
                continue;
            }
            let have = usize::from(self.have);
            let n = (5 - have).min(bytes.len());
            self.header[have..have + n].copy_from_slice(&bytes[..n]);
            bytes = &bytes[n..];
            if have + n == 5 {
                self.have = 0;
                self.body_left = usize::from(u16::from_be_bytes([self.header[3], self.header[4]]));
            } else {
                self.have = (have + n) as u8;
            }
        }
    }

    pub(crate) fn at_boundary(&self) -> bool {
        self.have == 0 && self.body_left == 0
    }

    /// The ClientHello's random: the key `SecretLog` files secrets by.
    pub(crate) fn client_random(&self) -> Option<[u8; 32]> {
        let s = &self.start;
        (usize::from(self.start_len) == START && s[0] == HANDSHAKE && s[5] == 1)
            .then(|| s[11..].try_into().expect("32 bytes"))
    }
}

const CLIENT_SECRET: &str = "CLIENT_TRAFFIC_SECRET_0";
const SERVER_SECRET: &str = "SERVER_TRAFFIC_SECRET_0";
/// Logged secrets a worker keeps for handshakes not switched yet; the
/// oldest go first, and their connections close on a KeyUpdate.
const LOGGED_KEEP: usize = 256;

struct Logged {
    random: [u8; 32],
    client: bool,
    secret: OkmBlock,
}

thread_local! {
    /// What `SecretLog` got on this worker: rustls logs from inside the
    /// handshake calls, on the connection's thread.
    static LOGGED: RefCell<VecDeque<Logged>> = const { RefCell::new(VecDeque::new()) };
}

/// The `KeyLog` of kTLS configs: keeps the TLS 1.3 application traffic
/// secrets until `switch` takes them, by ClientHello random.
#[derive(Debug)]
pub(crate) struct SecretLog;

impl rustls::KeyLog for SecretLog {
    fn will_log(&self, label: &str) -> bool {
        label == CLIENT_SECRET || label == SERVER_SECRET
    }

    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        let (Ok(random), true) = (client_random.try_into(), secret.len() <= OkmBlock::MAX_LEN)
        else {
            return;
        };
        LOGGED.with_borrow_mut(|logged| {
            if logged.len() == LOGGED_KEEP {
                logged.pop_front();
            }
            logged.push_back(Logged {
                random,
                client: label == CLIENT_SECRET,
                secret: OkmBlock::new(secret),
            });
        });
    }
}

/// The client's and the server's secrets logged for `random`, taken.
fn take_logged(random: &[u8; 32]) -> (Option<OkmBlock>, Option<OkmBlock>) {
    LOGGED.with_borrow_mut(|logged| {
        let (mut client, mut server) = (None, None);
        logged.retain_mut(|l| {
            if l.random != *random {
                return true;
            }
            let secret = OkmBlock::new(l.secret.as_ref());
            if l.client {
                client = Some(secret);
            } else {
                server = Some(secret);
            }
            false
        });
        (client, server)
    })
}

/// HKDF-Expand-Label with an empty context (RFC 8446, 7.1).
fn expand_label(hkdf: &dyn Hkdf, secret: &OkmBlock, label: &[u8], out: &mut [u8]) {
    let len = (out.len() as u16).to_be_bytes();
    let label_len = [(6 + label.len()) as u8];
    hkdf.expander_for_okm(secret)
        .expand_slice(&[&len, &label_len, b"tls13 ", label, &[0]], out)
        .expect("short output");
}

/// A traffic secret's key and IV (RFC 8446, 7.3).
fn key_iv(hkdf: &dyn Hkdf, secret: &OkmBlock, key_len: usize) -> ([u8; 32], [u8; 12]) {
    let mut key = [0; 32];
    let mut iv = [0; 12];
    expand_label(hkdf, secret, b"key", &mut key[..key_len]);
    expand_label(hkdf, secret, b"iv", &mut iv);
    (key, iv)
}

/// The secret after a KeyUpdate (RFC 8446, 7.2).
fn next_secret(hkdf: &dyn Hkdf, secret: &OkmBlock) -> OkmBlock {
    let mut next = [0; OkmBlock::MAX_LEN];
    let len = hkdf.expander_for_okm(secret).hash_len();
    expand_label(hkdf, secret, b"traffic upd", &mut next[..len]);
    let next_block = OkmBlock::new(&next[..len]);
    wipe(&mut next);
    next_block
}

/// What a TLS 1.3 kTLS connection needs for key updates.
struct Rekey {
    hkdf: &'static dyn Hkdf,
    key_len: usize,
    client: OkmBlock,
    server: OkmBlock,
}

impl Rekey {
    /// From the logged secrets, checked against the keys rustls handed
    /// over: a client may have updated its keys already, before the switch.
    fn new(
        suite: SupportedCipherSuite,
        cipher: Cipher,
        random: [u8; 32],
        secrets: &rustls::ExtractedSecrets,
    ) -> Option<Rekey> {
        let SupportedCipherSuite::Tls13(suite) = suite else {
            return None;
        };
        let (Some(mut client), Some(server)) = take_logged(&random) else {
            return None;
        };
        let hkdf = suite.hkdf_provider;
        let key_len = cipher.key_len();
        let matches = |secret: &OkmBlock, (_, s): &(u64, ConnectionTrafficSecrets)| {
            let (key, iv) = key_iv(hkdf, secret, key_len);
            traffic_key_iv(s).is_some_and(|(k, i)| k == &key[..key_len] && i == &iv[..])
        };
        if !matches(&server, &secrets.tx) {
            return None;
        }
        for _ in 0..3 {
            if matches(&client, &secrets.rx) {
                return Some(Rekey {
                    hkdf,
                    key_len,
                    client,
                    server,
                });
            }
            client = next_secret(hkdf, &client);
        }
        None
    }

    /// The next generation of one direction's keys, set on the socket.
    fn update(&mut self, fd: RawFd, cipher: Cipher, dir: libc::c_int) -> io::Result<()> {
        let secret = if dir == libc::TLS_RX {
            &mut self.client
        } else {
            &mut self.server
        };
        *secret = next_secret(self.hkdf, secret);
        let (mut key, iv) = key_iv(self.hkdf, secret, self.key_len);
        let r = set_crypto(
            fd,
            dir,
            libc::TLS_1_3_VERSION,
            cipher,
            &key[..self.key_len],
            &iv,
            0,
        );
        wipe(&mut key);
        r
    }
}

fn traffic_key_iv(secrets: &ConnectionTrafficSecrets) -> Option<(&[u8], &[u8])> {
    match secrets {
        ConnectionTrafficSecrets::Aes128Gcm { key, iv }
        | ConnectionTrafficSecrets::Aes256Gcm { key, iv }
        | ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv } => {
            Some((key.as_ref(), iv.as_ref()))
        }
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cipher {
    Aes128Gcm,
    Aes256Gcm,
    Chacha20Poly1305,
}

impl Cipher {
    fn key_len(self) -> usize {
        match self {
            Cipher::Aes128Gcm => 16,
            Cipher::Aes256Gcm | Cipher::Chacha20Poly1305 => 32,
        }
    }
}

const CIPHERS: [Cipher; 3] = [
    Cipher::Aes128Gcm,
    Cipher::Aes256Gcm,
    Cipher::Chacha20Poly1305,
];

fn cipher_of(suite: SupportedCipherSuite) -> Option<Cipher> {
    use rustls::CipherSuite as C;
    Some(match suite.suite() {
        C::TLS13_AES_128_GCM_SHA256
        | C::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        | C::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 => Cipher::Aes128Gcm,
        C::TLS13_AES_256_GCM_SHA384
        | C::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        | C::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => Cipher::Aes256Gcm,
        C::TLS13_CHACHA20_POLY1305_SHA256
        | C::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
        | C::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => Cipher::Chacha20Poly1305,
        _ => return None,
    })
}

/// The kernel's version code, for the versions it takes.
fn version_code(version: ProtocolVersion) -> Option<u16> {
    match version {
        ProtocolVersion::TLSv1_3 => Some(libc::TLS_1_3_VERSION),
        ProtocolVersion::TLSv1_2 => Some(libc::TLS_1_2_VERSION),
        _ => None,
    }
}

fn support_bit(version: u16, cipher: Cipher) -> u8 {
    let v = if version == libc::TLS_1_3_VERSION {
        0
    } else {
        3
    };
    1 << (v + CIPHERS.iter().position(|&c| c == cipher).unwrap_or(0))
}

/// What `probe` found the kernel to take, a bit per (version, cipher).
static SUPPORTED: AtomicU8 = AtomicU8::new(0);

/// Find out what kTLS the kernel offers, once it does: at startup, as
/// root, setting the ULP also loads the `tls` module. An error says why
/// nothing works; then `switch` keeps every connection in userspace.
pub(crate) fn probe() -> Result<(), String> {
    if SUPPORTED.load(Ordering::Relaxed) != 0 {
        return Ok(());
    }
    let fail = |what: &str, e: io::Error| format!("{what}: {e}");
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .map_err(|e| fail("bind() on 127.0.0.1", e))?;
    let addr = listener
        .local_addr()
        .map_err(|e| fail("getsockname()", e))?;
    let mut bits = 0;
    for version in [libc::TLS_1_3_VERSION, libc::TLS_1_2_VERSION] {
        for cipher in CIPHERS {
            let client = std::net::TcpStream::connect(addr).map_err(|e| fail("connect()", e))?;
            let _server = listener.accept().map_err(|e| fail("accept()", e))?;
            let fd = client.as_raw_fd();
            attach_ulp(fd).map_err(|e| fail("setsockopt(TCP_ULP, \"tls\")", e))?;
            let key = [0; 32];
            let key = if cipher == Cipher::Aes128Gcm {
                &key[..16]
            } else {
                &key[..]
            };
            let iv = [0; 12];
            let ok = [libc::TLS_TX, libc::TLS_RX]
                .into_iter()
                .all(|dir| set_crypto(fd, dir, version, cipher, key, &iv, 0).is_ok());
            if ok {
                bits |= support_bit(version, cipher);
            }
        }
    }
    SUPPORTED.store(bits, Ordering::Relaxed);
    if bits == 0 {
        return Err("setsockopt(SOL_TLS) failed for every cipher".into());
    }
    Ok(())
}

fn setsockopt<T>(fd: RawFd, level: libc::c_int, name: libc::c_int, value: &T) -> io::Result<()> {
    // SAFETY: `value` is a live `T` of the size given.
    let r = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            (value as *const T).cast(),
            size_of::<T>() as libc::socklen_t,
        )
    };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn attach_ulp(fd: RawFd) -> io::Result<()> {
    setsockopt(fd, libc::SOL_TCP, libc::TCP_ULP, b"tls")
}

/// Overwrite key material on the stack before it goes out of scope.
fn wipe<T>(value: &mut T) {
    // SAFETY: the `tls12_crypto_info_*` structs are plain bytes, for which
    // all zeroes is a value.
    unsafe { std::ptr::write_volatile(value, std::mem::zeroed()) };
}

/// One direction's keys to the kernel. `iv` is rustls's 12 bytes: salt
/// and the rest for AES-GCM, all of it for ChaCha20-Poly1305.
fn set_crypto(
    fd: RawFd,
    dir: libc::c_int,
    version: u16,
    cipher: Cipher,
    key: &[u8],
    iv: &[u8; 12],
    seq: u64,
) -> io::Result<()> {
    let bad_key = || io::Error::new(io::ErrorKind::InvalidInput, "key length");
    let mut explicit: [u8; 8] = iv[4..].try_into().expect("8 bytes");
    if version == libc::TLS_1_2_VERSION && dir == libc::TLS_TX {
        // TLS 1.2 AES-GCM: the kernel sends `explicit`, `explicit + 1`, …
        // as nonces, rustls sent `explicit ^ seq`. Half the range away,
        // the two can't meet.
        explicit[0] ^= 0x80;
    }
    let rec_seq = seq.to_be_bytes();
    let salt: [u8; 4] = iv[..4].try_into().expect("4 bytes");
    match cipher {
        Cipher::Aes128Gcm => {
            let mut info = libc::tls12_crypto_info_aes_gcm_128 {
                info: libc::tls_crypto_info {
                    version,
                    cipher_type: libc::TLS_CIPHER_AES_GCM_128,
                },
                iv: explicit,
                key: key.try_into().map_err(|_| bad_key())?,
                salt,
                rec_seq,
            };
            let r = setsockopt(fd, libc::SOL_TLS, dir, &info);
            wipe(&mut info);
            r
        }
        Cipher::Aes256Gcm => {
            let mut info = libc::tls12_crypto_info_aes_gcm_256 {
                info: libc::tls_crypto_info {
                    version,
                    cipher_type: libc::TLS_CIPHER_AES_GCM_256,
                },
                iv: explicit,
                key: key.try_into().map_err(|_| bad_key())?,
                salt,
                rec_seq,
            };
            let r = setsockopt(fd, libc::SOL_TLS, dir, &info);
            wipe(&mut info);
            r
        }
        Cipher::Chacha20Poly1305 => {
            let mut info = libc::tls12_crypto_info_chacha20_poly1305 {
                info: libc::tls_crypto_info {
                    version,
                    cipher_type: libc::TLS_CIPHER_CHACHA20_POLY1305,
                },
                iv: *iv,
                key: key.try_into().map_err(|_| bad_key())?,
                salt: [],
                rec_seq,
            };
            let r = setsockopt(fd, libc::SOL_TLS, dir, &info);
            wipe(&mut info);
            r
        }
    }
}

fn set_secrets(
    fd: RawFd,
    dir: libc::c_int,
    version: u16,
    cipher: Cipher,
    (seq, secrets): &(u64, ConnectionTrafficSecrets),
) -> io::Result<()> {
    let (key, iv) =
        traffic_key_iv(secrets).ok_or_else(|| io::Error::from(io::ErrorKind::Unsupported))?;
    let iv: &[u8; 12] = iv
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "iv length"))?;
    set_crypto(fd, dir, version, cipher, key, iv, *seq)
}

/// How a TLS connection goes on after `switch`.
#[allow(clippy::large_enum_variant)] // once per connection, not kept
pub(crate) enum Switch {
    Kernel(Box<KtlsStream>),
    Userspace(TlsStream<TcpStream>),
    /// The connection can't go on: close it.
    Failed(io::Error),
}

/// Give a handshaken connection to the kernel, when its config asks for
/// that (`TlsStream::wants_ktls`) and the kernel takes its cipher.
pub(crate) fn switch(stream: TlsStream<TcpStream>) -> Switch {
    let mut chosen = None;
    let attach = |io: &TcpStream, version: ProtocolVersion, suite: SupportedCipherSuite| {
        let (Some(version), Some(cipher)) = (version_code(version), cipher_of(suite)) else {
            return false;
        };
        if SUPPORTED.load(Ordering::Relaxed) & support_bit(version, cipher) == 0
            || attach_ulp(io.as_raw_fd()).is_err()
        {
            return false;
        }
        chosen = Some((version, cipher, suite));
        true
    };
    match stream.into_ktls(attach) {
        IntoKtls::Userspace(stream) => Switch::Userspace(stream),
        IntoKtls::Failed(e) => Switch::Failed(e),
        IntoKtls::Kernel {
            io,
            secrets,
            read,
            closed,
            random,
        } => {
            let Some((version, cipher, suite)) = chosen else {
                return Switch::Failed(io::Error::other("kTLS: no cipher"));
            };
            let fd = io.as_raw_fd();
            if let Err(e) = set_secrets(fd, libc::TLS_TX, version, cipher, &secrets.tx)
                .and_then(|()| set_secrets(fd, libc::TLS_RX, version, cipher, &secrets.rx))
            {
                return Switch::Failed(io::Error::other(format!(
                    "setsockopt(SOL_TLS) failed ({e})"
                )));
            }
            let rekey = random.and_then(|r| Rekey::new(suite, cipher, r, &secrets));
            Switch::Kernel(Box::new(KtlsStream {
                io,
                read,
                pos: 0,
                closed,
                cipher,
                rekey: rekey.map(Box::new),
                next_check: Instant::now() + LIMIT_CHECK,
                shut: false,
            }))
        }
    }
}

/// Records an AES-GCM key may seal: RFC 8446, 5.5 allows 2^24.5. What
/// goes out between two checks (`LIMIT_CHECK`) stays below the rest.
/// TLS 1.3 updates its key there, TLS 1.2 closes.
const RECORD_LIMIT: u64 = 1 << 24;
const LIMIT_CHECK: Duration = Duration::from_secs(1);

/// A connection whose records the kernel seals and opens, with what
/// rustls decrypted before the switch read first.
pub(crate) struct KtlsStream {
    io: TcpStream,
    read: Vec<u8>,
    pos: usize,
    /// The client sent close_notify: reads end there.
    closed: bool,
    cipher: Cipher,
    /// TLS 1.3 with the secrets for key updates, else `None`: a KeyUpdate
    /// closes then.
    rekey: Option<Box<Rekey>>,
    next_check: Instant,
    /// close_notify went out (a lingering close shuts down first).
    shut: bool,
}

/// TLS record content types (RFC 8446, 5.1).
const ALERT: u8 = 21;
const HANDSHAKE: u8 = 22;
/// A KeyUpdate handshake message (RFC 8446, 4.6.3), without its
/// `request_update` byte.
const KEY_UPDATE: [u8; 4] = [24, 0, 0, 1];

impl KtlsStream {
    pub(crate) fn io(&self) -> &TcpStream {
        &self.io
    }

    pub(crate) fn io_mut(&mut self) -> &mut TcpStream {
        &mut self.io
    }

    /// Bytes or the end of them that a read returns without the socket.
    pub(crate) fn has_buffered_input(&self) -> bool {
        self.pos < self.read.len() || self.closed
    }

    /// Copy what is left of the bytes read before the switch to `dst`.
    ///
    /// # Safety
    /// `dst` is valid for writes of `len` bytes.
    pub(crate) unsafe fn take_into(&mut self, dst: *mut u8, len: usize) -> usize {
        let n = (self.read.len() - self.pos).min(len);
        // SAFETY: `n` bytes from our own buffer into `dst`, which the
        // caller vouches for; the two can't overlap.
        unsafe { std::ptr::copy_nonoverlapping(self.read.as_ptr().add(self.pos), dst, n) };
        self.pos += n;
        if self.pos == self.read.len() {
            self.read = Vec::new();
            self.pos = 0;
        }
        n
    }

    /// Whether the connection may go on sealing records: an AES-GCM key
    /// stops near `RECORD_LIMIT`, looked at once per `LIMIT_CHECK`.
    pub(crate) fn within_limit(&mut self) -> bool {
        if self.cipher == Cipher::Chacha20Poly1305 {
            return true;
        }
        let now = Instant::now();
        if now < self.next_check {
            return true;
        }
        self.next_check = now + LIMIT_CHECK;
        if tx_records(self.io.as_raw_fd(), self.cipher).is_none_or(|n| n < RECORD_LIMIT) {
            return true;
        }
        match self.update_tx() {
            Ok(()) => true,
            // The socket is full: again on the next write.
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                self.next_check = now;
                true
            }
            Err(_) => false,
        }
    }

    /// Our KeyUpdate, with the old key, then the new key for what follows.
    fn update_tx(&mut self) -> io::Result<()> {
        let fd = self.io.as_raw_fd();
        let Some(rekey) = &mut self.rekey else {
            return Err(io::Error::other("no key update on this connection"));
        };
        let mut message = [0; 5];
        message[..4].copy_from_slice(&KEY_UPDATE);
        send_record(fd, HANDSHAKE, &message)?;
        rekey.update(fd, self.cipher, libc::TLS_TX)
    }

    /// A read failed: `EIO` is a record that isn't data, which the kernel
    /// gives with a control buffer only. `None`: a KeyUpdate, handled;
    /// read again.
    async fn check_read(&mut self, res: io::Result<usize>) -> Option<io::Result<usize>> {
        match res {
            Err(e) if e.raw_os_error() == Some(libc::EIO) => self.control_record().await,
            other => Some(other),
        }
    }

    #[cold]
    async fn control_record(&mut self) -> Option<io::Result<usize>> {
        match self.recv_control() {
            Ok(Some(request_update)) => match self.key_update(request_update).await {
                Ok(()) => None,
                Err(e) => Some(Err(e)),
            },
            Ok(None) => Some(Ok(0)),
            Err(e) => Some(Err(e)),
        }
    }

    /// The client's KeyUpdate: its new keys for RX, and ours for TX when
    /// it asks (before any more data from us, RFC 8446, 4.6.3).
    async fn key_update(&mut self, request_update: bool) -> io::Result<()> {
        let fd = self.io.as_raw_fd();
        let Some(rekey) = &mut self.rekey else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "KeyUpdate without the secrets for it (kTLS)",
            ));
        };
        rekey.update(fd, self.cipher, libc::TLS_RX).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("KeyUpdate: setsockopt(TLS_RX) failed ({e})"),
            )
        })?;
        if request_update {
            loop {
                match self.update_tx() {
                    Ok(()) => break,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        self.io.writable(false).await?;
                    }
                    Err(e) => return Err(e),
                }
            }
        }
        Ok(())
    }

    /// Read the control record waiting: a close_notify is `Ok(None)`, a
    /// KeyUpdate `Ok(Some(request_update))`, anything else an error.
    fn recv_control(&mut self) -> io::Result<Option<bool>> {
        let mut payload = [0u8; 16];
        let mut control = [0u64; 4];
        let mut iov = libc::iovec {
            iov_base: payload.as_mut_ptr().cast(),
            iov_len: payload.len(),
        };
        // SAFETY: an all-zero msghdr is valid; the pointers set below
        // outlive the call.
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = size_of_val(&control);
        // SAFETY: `msg` points at buffers of ours, of the sizes it says.
        let n = unsafe { libc::recvmsg(self.io.as_raw_fd(), &mut msg, libc::MSG_DONTWAIT) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut record_type = None;
        // SAFETY: walking the control messages the kernel just wrote.
        unsafe {
            let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
            while !cmsg.is_null() {
                if (*cmsg).cmsg_level == libc::SOL_TLS
                    && (*cmsg).cmsg_type == libc::TLS_GET_RECORD_TYPE
                {
                    record_type = Some(*libc::CMSG_DATA(cmsg));
                }
                cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
            }
        }
        let n = n as usize;
        let invalid = |what: String| Err(io::Error::new(io::ErrorKind::InvalidData, what));
        match record_type {
            Some(ALERT) if n == 2 && payload[1] == 0 => {
                self.closed = true;
                Ok(None)
            }
            Some(ALERT) => invalid(format!("received fatal alert: {}", payload[1])),
            Some(HANDSHAKE) if n == 5 && payload[..4] == KEY_UPDATE && payload[4] <= 1 => {
                Ok(Some(payload[4] == 1))
            }
            Some(HANDSHAKE) => invalid("handshake message after the handshake (kTLS)".into()),
            other => invalid(format!("unexpected TLS record type {other:?} (kTLS)")),
        }
    }

    fn send_close_notify(&self) -> io::Result<()> {
        send_record(self.io.as_raw_fd(), ALERT, &[1, 0])
    }

    /// A read in a keep-alive wait failed or saw EOF: a KeyUpdate is
    /// handled there too (`Some(true)`: wait again).
    pub(crate) async fn idle_control_record(&mut self) -> bool {
        self.control_record().await.is_none()
    }
}

/// One record of `record_type` on a kTLS socket, without waiting.
fn send_record(fd: RawFd, record_type: u8, payload: &[u8]) -> io::Result<()> {
    let mut control = [0u64; 4];
    let mut iov = libc::iovec {
        iov_base: payload.as_ptr().cast_mut().cast(),
        iov_len: payload.len(),
    };
    // SAFETY: as in `recv_control`; the one control message fits
    // `control` (CMSG_SPACE(1) is 24 bytes), and the kernel only reads
    // the payload.
    unsafe {
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = libc::CMSG_SPACE(1) as usize;
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        (*cmsg).cmsg_level = libc::SOL_TLS;
        (*cmsg).cmsg_type = libc::TLS_SET_RECORD_TYPE;
        (*cmsg).cmsg_len = libc::CMSG_LEN(1) as usize;
        *libc::CMSG_DATA(cmsg) = record_type;
        let n = libc::sendmsg(fd, &msg, libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL);
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// The records sent so far, from the kernel's TX state.
fn tx_records(fd: RawFd, cipher: Cipher) -> Option<u64> {
    fn get<T>(fd: RawFd, rec_seq: impl FnOnce(&T) -> [u8; 8]) -> Option<u64> {
        // SAFETY: plain bytes, see `wipe`.
        let mut info: T = unsafe { std::mem::zeroed() };
        let mut len = size_of::<T>() as libc::socklen_t;
        // SAFETY: `info` has room for `len` bytes.
        let r = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_TLS,
                libc::TLS_TX,
                (&raw mut info).cast(),
                &mut len,
            )
        };
        let seq = (r == 0).then(|| u64::from_be_bytes(rec_seq(&info)));
        wipe(&mut info);
        seq
    }
    match cipher {
        Cipher::Aes128Gcm => get(fd, |i: &libc::tls12_crypto_info_aes_gcm_128| i.rec_seq),
        Cipher::Aes256Gcm => get(fd, |i: &libc::tls12_crypto_info_aes_gcm_256| i.rec_seq),
        Cipher::Chacha20Poly1305 => get(fd, |i: &libc::tls12_crypto_info_chacha20_poly1305| {
            i.rec_seq
        }),
    }
}

impl AsyncReadRent for KtlsStream {
    async fn read<T: IoBufMut>(&mut self, mut buf: T) -> BufResult<usize, T> {
        if self.pos < self.read.len() {
            // SAFETY: `write_ptr` is valid for `bytes_total` bytes, and the
            // first `n` are initialized once copied.
            unsafe {
                let n = self.take_into(buf.write_ptr(), buf.bytes_total());
                buf.set_init(n);
                return (Ok(n), buf);
            }
        }
        loop {
            if self.closed {
                return (Ok(0), buf);
            }
            let (res, returned) = self.io.read(buf).await;
            buf = returned;
            if let Some(res) = self.check_read(res).await {
                return (res, buf);
            }
        }
    }

    async fn readv<T: IoVecBufMut>(&mut self, mut buf: T) -> BufResult<usize, T> {
        if self.has_buffered_input() {
            // The first iovec only: a short read, which callers handle.
            // SAFETY: `buf` is owned here and outlives `raw`.
            let res = match unsafe { monoio::buf::RawBuf::new_from_iovec_mut(&mut buf) } {
                Some(raw) => self.read(raw).await.0,
                None => Ok(0),
            };
            if let Ok(n) = res {
                // SAFETY: `n` bytes of the first iovec were just written.
                unsafe { buf.set_init(n) };
            }
            return (res, buf);
        }
        loop {
            if self.closed {
                return (Ok(0), buf);
            }
            let (res, returned) = self.io.readv(buf).await;
            buf = returned;
            if let Some(res) = self.check_read(res).await {
                return (res, buf);
            }
        }
    }
}

fn limit_reached() -> io::Error {
    io::Error::other("AES-GCM record limit reached, and no key update (kTLS)")
}

impl AsyncWriteRent for KtlsStream {
    async fn write<T: IoBuf>(&mut self, buf: T) -> BufResult<usize, T> {
        if !self.within_limit() {
            return (Err(limit_reached()), buf);
        }
        self.io.write(buf).await
    }

    async fn writev<T: IoVecBuf>(&mut self, buf: T) -> BufResult<usize, T> {
        if !self.within_limit() {
            return (Err(limit_reached()), buf);
        }
        self.io.writev(buf).await
    }

    async fn flush(&mut self) -> io::Result<()> {
        self.io.flush().await
    }

    /// close_notify, then the FIN.
    async fn shutdown(&mut self) -> io::Result<()> {
        if std::mem::replace(&mut self.shut, true) {
            return Ok(());
        }
        loop {
            match self.send_close_notify() {
                Ok(()) => break,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    self.io.writable(false).await?;
                }
                Err(e) => return Err(e),
            }
        }
        self.io.shutdown().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Where the `tls` module is loaded (CI), every cipher rustls has.
    #[test]
    fn probe_finds_every_cipher_or_none() {
        match probe() {
            Ok(()) => assert_eq!(SUPPORTED.load(Ordering::Relaxed), 0b11_1111),
            Err(e) => eprintln!("no kTLS here: {e}"),
        }
    }

    /// RFC 8448, 3 (Simple 1-RTT Handshake): the server's application
    /// traffic secret, its key and IV; the KeyUpdate step is the same
    /// HKDF-Expand-Label, checked against rustls in `tests/m166_ktls.rs`.
    #[test]
    fn traffic_keys_derive_as_rfc_8448() {
        let unhex = |s: &str| -> Vec<u8> {
            let s: String = s.split_whitespace().collect();
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                .collect()
        };
        let suite = rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256;
        let SupportedCipherSuite::Tls13(suite) = suite else {
            unreachable!()
        };
        let secret = OkmBlock::new(&unhex(
            "a1 1a f9 f0 55 31 f8 56 ad 47 11 6b 45 a9 50 32 82 04 b4 f4 4b fb 6b 3a 4b 4f 1f 3f cb 63 16 43",
        ));
        let (key, iv) = key_iv(suite.hkdf_provider, &secret, 16);
        assert_eq!(
            key[..16],
            unhex("9f 02 28 3b 6c 9c 07 ef c2 6b b9 f2 ac 92 e3 56")[..]
        );
        assert_eq!(iv[..], unhex("cf 78 2b 88 dd 83 54 9a ad f1 e9 84")[..]);
        assert_eq!(next_secret(suite.hkdf_provider, &secret).as_ref().len(), 32);
    }

    #[test]
    fn client_random_from_the_first_record() {
        let mut c = RecordCursor::default();
        let mut hello = vec![22, 3, 1, 0, 200, 1, 0, 0, 196, 3, 3];
        hello.extend(1..=32u8);
        c.feed(&hello[..20]);
        assert_eq!(c.client_random(), None);
        c.feed(&hello[20..]);
        let want: Vec<u8> = (1..=32).collect();
        assert_eq!(c.client_random().map(|r| r.to_vec()), Some(want));
    }

    #[test]
    fn record_cursor_tracks_boundaries() {
        let mut c = RecordCursor::default();
        assert!(c.at_boundary());
        // A 3-byte record, fed in pieces.
        c.feed(&[22, 3, 3]);
        assert!(!c.at_boundary());
        c.feed(&[0, 3, 1]);
        assert!(!c.at_boundary());
        c.feed(&[2, 3]);
        assert!(c.at_boundary());
        // Two records at once, the second empty, then half a header.
        c.feed(&[23, 3, 3, 0, 1, 9, 21, 3, 3, 0, 0, 23, 3]);
        assert!(!c.at_boundary());
        c.feed(&[3, 1, 0]);
        assert!(!c.at_boundary());
        c.feed(&[0; 256]);
        assert!(c.at_boundary());
    }

    #[test]
    fn support_bits_are_distinct() {
        let mut seen = 0u8;
        for v in [libc::TLS_1_3_VERSION, libc::TLS_1_2_VERSION] {
            for c in CIPHERS {
                let b = support_bit(v, c);
                assert_eq!(seen & b, 0);
                seen |= b;
            }
        }
        assert_eq!(seen.count_ones(), 6);
    }

    #[test]
    fn suites_map_to_kernel_ciphers() {
        let provider = crate::tls_certs::active_provider();
        for suite in &provider.cipher_suites {
            assert!(cipher_of(*suite).is_some(), "{:?}", suite.suite());
        }
    }
}
