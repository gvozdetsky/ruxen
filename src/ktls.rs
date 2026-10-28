//! Kernel TLS (#673): with `ssl_conf_command Options KTLS`, rustls runs
//! the handshake and the kernel then encrypts and decrypts the records,
//! so `sendfile` works over TLS (nginx's `SSL_sendfile`,
//! ngx_event_openssl.c).
//!
//! The switch happens once, right after the handshake (`switch`). Rustls
//! is gone then, so: a TLS 1.3 KeyUpdate from the client closes the
//! connection (rustls's buffered API gives no traffic secret to derive
//! the next keys from), and the server never updates its own keys: an
//! AES-GCM connection ends near the record limit instead (`RECORD_LIMIT`).

use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Duration, Instant};

use monoio::BufResult;
use monoio::buf::{IoBuf, IoBufMut, IoVecBuf, IoVecBufMut};
use monoio::io::{AsyncReadRent, AsyncWriteRent};
use monoio::net::TcpStream;
use rustls::{ConnectionTrafficSecrets, ProtocolVersion, SupportedCipherSuite};

use crate::tls_stream::{IntoKtls, TlsStream};

/// Where a stream of TLS records stands: in a header, in a body, or
/// between records.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct RecordCursor {
    header: [u8; 5],
    have: u8,
    body_left: usize,
}

impl RecordCursor {
    pub(crate) fn feed(&mut self, mut bytes: &[u8]) {
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cipher {
    Aes128Gcm,
    Aes256Gcm,
    Chacha20Poly1305,
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
    let (key, iv) = match secrets {
        ConnectionTrafficSecrets::Aes128Gcm { key, iv }
        | ConnectionTrafficSecrets::Aes256Gcm { key, iv }
        | ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv } => (key, iv),
        _ => return Err(io::Error::from(io::ErrorKind::Unsupported)),
    };
    let iv: &[u8; 12] = iv
        .as_ref()
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "iv length"))?;
    set_crypto(fd, dir, version, cipher, key.as_ref(), iv, *seq)
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
        chosen = Some((version, cipher));
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
        } => {
            let Some((version, cipher)) = chosen else {
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
            Switch::Kernel(Box::new(KtlsStream {
                io,
                read,
                pos: 0,
                closed,
                cipher,
                next_check: Instant::now() + LIMIT_CHECK,
                shut: false,
            }))
        }
    }
}

/// Records an AES-GCM key may seal: RFC 8446, 5.5 allows 2^24.5. What
/// goes out between two checks (`LIMIT_CHECK`) stays below the rest.
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
    next_check: Instant,
    /// close_notify went out (a lingering close shuts down first).
    shut: bool,
}

/// TLS record content types (RFC 8446, 5.1).
const ALERT: u8 = 21;
const HANDSHAKE: u8 = 22;

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
        tx_records(self.io.as_raw_fd(), self.cipher).is_none_or(|n| n < RECORD_LIMIT)
    }

    fn check_read(&mut self, res: io::Result<usize>) -> io::Result<usize> {
        match res {
            // A record that isn't data: the kernel wants a control buffer.
            Err(e) if e.raw_os_error() == Some(libc::EIO) => self.control_record(),
            other => other,
        }
    }

    #[cold]
    fn control_record(&mut self) -> io::Result<usize> {
        let mut payload = [0u8; 2];
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
        let invalid = |what: String| Err(io::Error::new(io::ErrorKind::InvalidData, what));
        match record_type {
            Some(ALERT) if n == 2 && payload[1] == 0 => {
                self.closed = true;
                Ok(0)
            }
            Some(ALERT) => invalid(format!("received fatal alert: {}", payload[1])),
            Some(HANDSHAKE) => invalid("handshake message after the handshake (kTLS)".into()),
            other => invalid(format!("unexpected TLS record type {other:?} (kTLS)")),
        }
    }

    fn send_close_notify(&self) -> io::Result<()> {
        let mut payload = [1u8, 0];
        let mut control = [0u64; 4];
        let mut iov = libc::iovec {
            iov_base: payload.as_mut_ptr().cast(),
            iov_len: payload.len(),
        };
        // SAFETY: as in `control_record`; the one control message fits
        // `control` (CMSG_SPACE(1) is 24 bytes).
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
            *libc::CMSG_DATA(cmsg) = ALERT;
            let n = libc::sendmsg(
                self.io.as_raw_fd(),
                &msg,
                libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
            );
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }
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
        if self.closed {
            return (Ok(0), buf);
        }
        let (res, buf) = self.io.read(buf).await;
        (self.check_read(res), buf)
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
        let (res, buf) = self.io.readv(buf).await;
        (self.check_read(res), buf)
    }
}

fn limit_reached() -> io::Error {
    io::Error::other("AES-GCM record limit reached (kTLS)")
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
