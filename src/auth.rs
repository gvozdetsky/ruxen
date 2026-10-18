use crate::http;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::SystemTime;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BasicCredentials {
    pub username: Vec<u8>,
    pub password: Vec<u8>,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum BasicHeaderError {
    Missing,
    Malformed,
}

pub fn decode_basic_authorization(
    headers_raw: &[u8],
) -> Result<BasicCredentials, BasicHeaderError> {
    let raw =
        lookup_request_header(headers_raw, b"authorization").ok_or(BasicHeaderError::Missing)?;
    let mut value = trim_ows(raw);
    if value.len() < 6 || !value[..5].eq_ignore_ascii_case(b"basic") {
        return Err(BasicHeaderError::Malformed);
    }
    value = trim_ows(&value[5..]);
    if value.is_empty() {
        return Err(BasicHeaderError::Malformed);
    }
    if value.iter().any(|b| matches!(*b, b' ' | b'\t')) {
        return Err(BasicHeaderError::Malformed);
    }
    let decoded = decode_base64(value).ok_or(BasicHeaderError::Malformed)?;
    let Some(colon) = decoded.iter().position(|&b| b == b':') else {
        return Err(BasicHeaderError::Malformed);
    };
    Ok(BasicCredentials {
        username: decoded[..colon].to_vec(),
        password: decoded[colon + 1..].to_vec(),
    })
}

pub fn verify_credentials(user_file: &Path, creds: &BasicCredentials) -> io::Result<bool> {
    let entries = load_htpasswd_cached(user_file)?;
    for (username, stored) in entries.iter() {
        if username.as_slice() == creds.username.as_slice() {
            return Ok(verify_stored_password(stored, &creds.password));
        }
    }
    Ok(false)
}

/// Cached htpasswd entries, keyed on absolute path. Refreshed when the
/// file's (mtime, len) differs from the cached pair. nginx reads the
/// htpasswd file on every authenticated request; we cache across requests
/// to keep the hot path down to one `stat()` + in-memory scan.
struct CachedHtpasswd {
    mtime: SystemTime,
    len: u64,
    entries: std::sync::Arc<Vec<(Vec<u8>, Vec<u8>)>>,
}

fn htpasswd_cache() -> &'static Mutex<HashMap<PathBuf, CachedHtpasswd>> {
    static CACHE: OnceLock<Mutex<HashMap<PathBuf, CachedHtpasswd>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn load_htpasswd_cached(user_file: &Path) -> io::Result<std::sync::Arc<Vec<(Vec<u8>, Vec<u8>)>>> {
    let meta = std::fs::metadata(user_file)?;
    let mtime = meta.modified()?;
    let len = meta.len();

    {
        let guard = htpasswd_cache().lock().unwrap_or_else(|e| e.into_inner());
        if let Some(hit) = guard.get(user_file) {
            if hit.mtime == mtime && hit.len == len {
                return Ok(hit.entries.clone());
            }
        }
    }

    let raw = std::fs::read(user_file)?;
    let entries = std::sync::Arc::new(parse_htpasswd(&raw));

    let mut guard = htpasswd_cache().lock().unwrap_or_else(|e| e.into_inner());
    guard.insert(
        user_file.to_path_buf(),
        CachedHtpasswd {
            mtime,
            len,
            entries: entries.clone(),
        },
    );
    Ok(entries)
}

fn parse_htpasswd(raw: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut out = Vec::new();
    for line in raw.split(|b| *b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let line = trim_ows(line);
        if line.is_empty() || line[0] == b'#' {
            continue;
        }
        let Some(first_colon) = line.iter().position(|&b| b == b':') else {
            continue;
        };
        let username = &line[..first_colon];
        let mut rest = &line[first_colon + 1..];
        if let Some(extra_colon) = rest.iter().position(|&b| b == b':') {
            rest = &rest[..extra_colon];
        }
        out.push((username.to_vec(), rest.to_vec()));
    }
    out
}

pub fn build_unauthorized_response(method: http::Method, server: &[u8], realm: &[u8]) -> Vec<u8> {
    let mut response = http::error_response_for_method(401, "Unauthorized\n", method, server);
    let mut header = Vec::with_capacity(realm.len() + 48);
    header.extend_from_slice(b"\r\nWWW-Authenticate: Basic realm=\"");
    append_escaped_realm(&mut header, realm);
    header.extend_from_slice(b"\"");
    if let Some(head_end) = response.windows(4).position(|w| w == b"\r\n\r\n") {
        response.splice(head_end..head_end, header);
    }
    response
}

/// A 401 with the `WWW-Authenticate` values an `auth_request` subrequest
/// answered with (#358), as nginx copies them to the main request.
pub fn build_unauthorized_with(
    method: http::Method,
    server: &[u8],
    www_authenticate: &[Vec<u8>],
) -> Vec<u8> {
    let mut response = http::error_response_for_method(401, "Unauthorized\n", method, server);
    let mut headers = Vec::new();
    for value in www_authenticate {
        headers.extend_from_slice(b"\r\nWWW-Authenticate: ");
        headers.extend_from_slice(value);
    }
    if let Some(head_end) = response.windows(4).position(|w| w == b"\r\n\r\n") {
        response.splice(head_end..head_end, headers);
    }
    response
}

fn verify_stored_password(stored: &[u8], password: &[u8]) -> bool {
    if let Some(plain) = stored.strip_prefix(b"{PLAIN}") {
        return ct_eq(plain, password);
    }
    if let Some(sha_raw) = stored.strip_prefix(b"{SHA}") {
        let Some(expected) = decode_base64(sha_raw) else {
            return false;
        };
        return ct_eq(&expected, &sha1_digest(password));
    }
    if let Some(ssha_raw) = stored.strip_prefix(b"{SSHA}") {
        let Some(decoded) = decode_base64(ssha_raw) else {
            return false;
        };
        if decoded.len() < 20 {
            return false;
        }
        let (expected, salt) = decoded.split_at(20);
        let mut salted = Vec::with_capacity(password.len() + salt.len());
        salted.extend_from_slice(password);
        salted.extend_from_slice(salt);
        return ct_eq(expected, &sha1_digest(&salted));
    }
    // nginx hashes `$apr1$` itself; libxcrypt doesn't know it. `$1$` is the
    // same algorithm, which nginx leaves to libc: done here too, so it
    // doesn't depend on the libc having MD5-crypt.
    for magic in [&b"$apr1$"[..], b"$1$"] {
        if stored.starts_with(magic) {
            if password.contains(&0) {
                return false;
            }
            return ct_eq(&md5_crypt(magic, stored, password), stored);
        }
    }
    if stored.starts_with(b"{") {
        return false;
    }
    verify_crypt(stored, password)
}

/// Poul-Henning Kamp's MD5-crypt with `magic` (`$1$`, or Apache's `$apr1$`),
/// as nginx's ngx_crypt_apr1: `salt` is the stored hash, whose salt ends at
/// the first `$`, at most 8 bytes.
fn md5_crypt(magic: &[u8], salt: &[u8], key: &[u8]) -> Vec<u8> {
    let salt = &salt[magic.len()..];
    let salt = &salt[..salt.iter().take(8).take_while(|&&b| b != b'$').count()];

    let mut md5 = Md5::new();
    md5.update(key);
    md5.update(magic);
    md5.update(salt);

    let mut ctx1 = Md5::new();
    ctx1.update(key);
    ctx1.update(salt);
    ctx1.update(key);
    let mut fin = ctx1.finish();

    for chunk in key.chunks(16) {
        md5.update(&fin[..chunk.len()]);
    }

    fin = [0; 16];
    let mut i = key.len();
    while i != 0 {
        if i & 1 != 0 {
            md5.update(&fin[..1]);
        } else {
            md5.update(&key[..1]);
        }
        i >>= 1;
    }
    fin = md5.finish();

    for i in 0..1000 {
        let mut ctx1 = Md5::new();
        if i & 1 != 0 {
            ctx1.update(key);
        } else {
            ctx1.update(&fin);
        }
        if i % 3 != 0 {
            ctx1.update(salt);
        }
        if i % 7 != 0 {
            ctx1.update(key);
        }
        if i & 1 != 0 {
            ctx1.update(&fin);
        } else {
            ctx1.update(key);
        }
        fin = ctx1.finish();
    }

    let mut out = Vec::with_capacity(magic.len() + salt.len() + 1 + 22);
    out.extend_from_slice(magic);
    out.extend_from_slice(salt);
    out.push(b'$');
    let f = |i: usize| u32::from(fin[i]);
    crypt_to64(&mut out, (f(0) << 16) | (f(6) << 8) | f(12), 4);
    crypt_to64(&mut out, (f(1) << 16) | (f(7) << 8) | f(13), 4);
    crypt_to64(&mut out, (f(2) << 16) | (f(8) << 8) | f(14), 4);
    crypt_to64(&mut out, (f(3) << 16) | (f(9) << 8) | f(15), 4);
    crypt_to64(&mut out, (f(4) << 16) | (f(10) << 8) | f(5), 4);
    crypt_to64(&mut out, f(11), 2);
    out
}

fn crypt_to64(out: &mut Vec<u8>, mut v: u32, n: usize) {
    const ITOA64: &[u8; 64] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    for _ in 0..n {
        out.push(ITOA64[(v & 0x3f) as usize]);
        v >>= 6;
    }
}

/// MD5 from the AWS-LC that rustls already links.
struct Md5(aws_lc_sys::MD5_CTX);

impl Md5 {
    fn new() -> Self {
        // MD5_CTX is plain data; MD5_Init sets every field.
        let mut ctx: aws_lc_sys::MD5_CTX = unsafe { std::mem::zeroed() };
        unsafe { aws_lc_sys::MD5_Init(&mut ctx) };
        Md5(ctx)
    }

    fn update(&mut self, data: &[u8]) {
        unsafe { aws_lc_sys::MD5_Update(&mut self.0, data.as_ptr().cast(), data.len()) };
    }

    fn finish(mut self) -> [u8; 16] {
        let mut out = [0u8; 16];
        unsafe { aws_lc_sys::MD5_Final(out.as_mut_ptr(), &mut self.0) };
        out
    }
}

/// Compares a computed hash with the stored one in time that doesn't
/// depend on where they differ.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len()
        && unsafe { aws_lc_sys::CRYPTO_memcmp(a.as_ptr().cast(), b.as_ptr().cast(), a.len()) } == 0
}

fn append_escaped_realm(out: &mut Vec<u8>, realm: &[u8]) {
    for &b in realm {
        if b == b'\\' || b == b'"' {
            out.push(b'\\');
        }
        out.push(b);
    }
}

fn lookup_request_header<'a>(mut block: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    while !block.is_empty() {
        let line_end = match block.iter().position(|&b| b == b'\n') {
            Some(i) => i,
            None => block.len(),
        };
        let line = &block[..line_end];
        block = &block[(line_end + 1).min(block.len())..];

        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let colon = match line.iter().position(|&b| b == b':') {
            Some(i) => i,
            None => continue,
        };
        let header_name = &line[..colon];
        if !header_name.eq_ignore_ascii_case(name) {
            continue;
        }
        return Some(trim_ows(&line[colon + 1..]));
    }
    None
}

fn trim_ows(mut v: &[u8]) -> &[u8] {
    while let Some((&c, rest)) = v.split_first() {
        if c == b' ' || c == b'\t' {
            v = rest;
        } else {
            break;
        }
    }
    while let Some((&c, rest)) = v.split_last() {
        if c == b' ' || c == b'\t' {
            v = rest;
        } else {
            break;
        }
    }
    v
}

fn decode_base64(input: &[u8]) -> Option<Vec<u8>> {
    if input.is_empty() || !input.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(input.len() / 4 * 3);
    let mut i = 0usize;
    while i < input.len() {
        let a = input[i];
        let b = input[i + 1];
        let c = input[i + 2];
        let d = input[i + 3];
        let va = b64_value(a)?;
        let vb = b64_value(b)?;
        if c == b'=' {
            if d != b'=' || i + 4 != input.len() {
                return None;
            }
            out.push((va << 2) | (vb >> 4));
            return Some(out);
        }
        let vc = b64_value(c)?;
        out.push((va << 2) | (vb >> 4));
        out.push(((vb & 0x0f) << 4) | (vc >> 2));
        if d == b'=' {
            if i + 4 != input.len() {
                return None;
            }
            return Some(out);
        }
        let vd = b64_value(d)?;
        out.push(((vc & 0x03) << 6) | vd);
        i += 4;
    }
    Some(out)
}

fn b64_value(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn sha1_digest(data: &[u8]) -> [u8; 20] {
    let mut h0: u32 = 0x6745_2301;
    let mut h1: u32 = 0xefcd_ab89;
    let mut h2: u32 = 0x98ba_dcfe;
    let mut h3: u32 = 0x1032_5476;
    let mut h4: u32 = 0xc3d2_e1f0;

    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = Vec::with_capacity((data.len() + 9).next_multiple_of(64));
    msg.extend_from_slice(data);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    let mut w = [0u32; 80];
    for chunk in msg.chunks_exact(64) {
        for (i, slot) in w.iter_mut().take(16).enumerate() {
            let base = i * 4;
            *slot = u32::from_be_bytes([
                chunk[base],
                chunk[base + 1],
                chunk[base + 2],
                chunk[base + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let mut a = h0;
        let mut b = h1;
        let mut c = h2;
        let mut d = h3;
        let mut e = h4;
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5a82_7999),
                20..=39 => (b ^ c ^ d, 0x6ed9_eba1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
                _ => (b ^ c ^ d, 0xca62_c1d6),
            };
            let t = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    let mut out = [0u8; 20];
    out[0..4].copy_from_slice(&h0.to_be_bytes());
    out[4..8].copy_from_slice(&h1.to_be_bytes());
    out[8..12].copy_from_slice(&h2.to_be_bytes());
    out[12..16].copy_from_slice(&h3.to_be_bytes());
    out[16..20].copy_from_slice(&h4.to_be_bytes());
    out
}

// crypt_r() with a buffer per thread, as nginx's ngx_libc_crypt with
// NGX_HAVE_GNU_CRYPT_R: crypt() returns one static buffer, and a lock
// around it would let only one worker hash at a time (#521).
//
// `struct crypt_data` is opaque here, so the buffer is sized for the
// largest layout crypt_r may see: 131232 bytes in glibc's own libcrypt
// (before 2.39), 32768 in libxcrypt, 260 in musl. u64 for the alignment
// of glibc's `long` field. All three want it zeroed before first use and
// let it be reused after.
#[cfg(unix)]
const CRYPT_DATA_WORDS: usize = 131232usize.div_ceil(8);

#[cfg(unix)]
thread_local! {
    static CRYPT_DATA: std::cell::RefCell<Box<[u64]>> =
        std::cell::RefCell::new(vec![0u64; CRYPT_DATA_WORDS].into_boxed_slice());
}

// glibc has crypt_r() in libcrypt (libxcrypt); musl has it in libc itself,
// and linking a glibc libcrypt.a into a static musl binary fails.
#[cfg(unix)]
#[cfg_attr(not(target_env = "musl"), link(name = "crypt"))]
unsafe extern "C" {
    fn crypt_r(
        key: *const libc::c_char,
        salt: *const libc::c_char,
        data: *mut libc::c_void,
    ) -> *mut libc::c_char;
}

#[cfg(unix)]
fn verify_crypt(stored: &[u8], password: &[u8]) -> bool {
    if stored.contains(&0) || password.contains(&0) {
        return false;
    }
    let Ok(key) = CString::new(password) else {
        return false;
    };
    let Ok(salt) = CString::new(stored) else {
        return false;
    };
    CRYPT_DATA.with_borrow_mut(|data| {
        let ptr = unsafe { crypt_r(key.as_ptr(), salt.as_ptr(), data.as_mut_ptr().cast()) };
        if ptr.is_null() {
            return false;
        }
        let out = unsafe { CStr::from_ptr(ptr) }.to_bytes();
        ct_eq(out, stored)
    })
}

#[cfg(not(unix))]
fn verify_crypt(_stored: &[u8], _password: &[u8]) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_basic_authorization_accepts_valid_header() {
        let headers = b"host: localhost\r\nauthorization: Basic dGVzdDpzZWNyZXQ=\r\n";
        let creds = decode_basic_authorization(headers).expect("must decode");
        assert_eq!(creds.username, b"test");
        assert_eq!(creds.password, b"secret");
    }

    #[test]
    fn decode_basic_authorization_rejects_bad_base64() {
        let headers = b"authorization: Basic ***\r\n";
        assert_eq!(
            decode_basic_authorization(headers),
            Err(BasicHeaderError::Malformed)
        );
    }

    #[test]
    fn verify_stored_password_plain_and_sha() {
        assert!(verify_stored_password(b"{PLAIN}secret", b"secret"));
        assert!(!verify_stored_password(b"{PLAIN}secret", b"nope"));
        assert!(verify_stored_password(
            b"{SHA}5en6G6MezRroT3XKqkdPOmY/BfQ=",
            b"secret"
        ));
        assert!(!verify_stored_password(
            b"{SHA}5en6G6MezRroT3XKqkdPOmY/BfQ=",
            b"nope"
        ));
        assert!(verify_stored_password(
            b"{SSHA}gVK8WC9YyFT1gMsQHTGCgT3sSv5zYWx0",
            b"secret"
        ));
        assert!(!verify_stored_password(
            b"{SSHA}gVK8WC9YyFT1gMsQHTGCgT3sSv5zYWx0",
            b"nope"
        ));
    }

    #[test]
    fn verify_credentials_reads_htpasswd_file() {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "ruxen-auth-test-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::write(
            &path,
            b"# c\n\nalice:{PLAIN}secret\nbob:{SHA}5en6G6MezRroT3XKqkdPOmY/BfQ=\n",
        )
        .unwrap();
        let ok = verify_credentials(
            &path,
            &BasicCredentials {
                username: b"alice".to_vec(),
                password: b"secret".to_vec(),
            },
        )
        .unwrap();
        assert!(ok);
        let bad = verify_credentials(
            &path,
            &BasicCredentials {
                username: b"alice".to_vec(),
                password: b"nope".to_vec(),
            },
        )
        .unwrap();
        assert!(!bad);
        std::fs::remove_file(path).ok();
    }

    #[cfg(unix)]
    #[test]
    fn verify_stored_password_apr1_and_md5_crypt() {
        assert!(verify_stored_password(
            b"$apr1$salt$VEpBc9VHGUKwI9.yg13Iu0",
            b"secret"
        ));
        assert!(verify_stored_password(
            b"$1$salt$ez2vlPGdaLYkJam5pWs/Y1",
            b"secret"
        ));
        assert!(!verify_stored_password(
            b"$apr1$salt$VEpBc9VHGUKwI9.yg13Iu0",
            b"nope"
        ));
        assert!(!verify_stored_password(
            b"$1$salt$ez2vlPGdaLYkJam5pWs/Y1",
            b"nope"
        ));
    }

    // Vectors from `openssl passwd`; md5_crypt runs without it (#519).
    #[test]
    fn md5_crypt_matches_openssl_passwd() {
        let long = b"correct-horse-battery-staple-xyz";
        for (stored, key) in [
            (&b"$apr1$abcdefgh$f0WRNdlLse428rLJj4pW9/"[..], &long[..]),
            (b"$apr1$Q$YUyAkJFdbcKveyKiHvvuA/", b"x"),
            (b"$apr1$e$884UIJwaHzNF9yPyifJmN1", b""),
            (b"$1$12345678$AUgxp1tAyBUrjUNZb3kvq1", long),
            (b"$1$s/.Z$C2fr7q.Kb72EWjzrj7Ahs1", b"0123456789abcdef"),
        ] {
            assert!(verify_stored_password(stored, key), "{stored:?}");
            assert!(!verify_stored_password(stored, b"wrong"), "{stored:?}");
        }
        // The salt is at most 8 bytes and ends at the first `$`, as in
        // ngx_crypt_apr1; openssl keeps the whole `-salt`, so these hashes
        // never match in nginx either.
        assert!(!verify_stored_password(
            b"$apr1$abcdefghij$82JubPF2dQkt1tVfvLnXS.",
            b"x"
        ));
        assert!(!verify_stored_password(
            b"$apr1$ab$cd$7rEYXqIP64KlXze0eLGSI1",
            b"x"
        ));
        assert!(!verify_stored_password(b"$apr1$", b""));
        assert!(!verify_stored_password(
            b"$apr1$Q$YUyAkJFdbcKveyKiHvvuA/",
            b"x\0"
        ));
    }

    // Without CRYPT_LOCK, threads hashing at once must not see each
    // other's output (#521).
    #[cfg(unix)]
    #[test]
    fn verify_crypt_concurrent_threads() {
        const HASHES: [(&[u8], &[u8]); 8] = [
            (b"$6$aa$TLd/SdOZKspSe2HFCYee6gxldyAskJzGLmwa0LZPgJ1ZdGRlhqzHUnqUpU93D13RYTty9F8QkCR2HJ0ITxpZY0", b"pw-aa"),
            (b"$5$aa$oYTaHr3G4CF9tT3Tm2sbbrjG5ZVfXJEy0qxNYObcqk6", b"pw-aa"),
            (b"$6$bb$JkdUslJY7rwxMzOCl02i0YsYLRz6ZMgPg/iugrG9DF7dpXYj1TKDSp9WSz/LBJbuNijWawXXPuYZCyKgpt4MQ.", b"pw-bb"),
            (b"$5$bb$HjWZNtAkYBS1NZPluK6kLa30O.G1VBBWTy8dCzmTg34", b"pw-bb"),
            (b"$6$cc$m8Dboc8FP3OKh19LA8srXNCy1mRwNbkGgyG42v63FiCtPrO2Pu.1eQWHWD6av9xIyYWvHGJxvXFth383EgdYZ1", b"pw-cc"),
            (b"$5$cc$ThtmrLYUD3BkTYlGweOJgOujo2r1NbvoaWga1BjLlw7", b"pw-cc"),
            (b"$6$dd$ttnvYfPvkplHNNHVSg6q.B.LPv.D7Vjh7K5U.hcE.d0V9FEc08r83xPysAJ38EOfyfU7Cmprp.CqRQAazY5fP.", b"pw-dd"),
            (b"$5$dd$54/jofUh4P39bZLvG.Ryc0Fn2i78QDuVJ400nlFygTD", b"pw-dd"),
        ];
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(HASHES.len()));
        let threads: Vec<_> = HASHES
            .iter()
            .enumerate()
            .map(|(i, &(stored, password))| {
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    for _ in 0..50 {
                        assert!(verify_stored_password(stored, password), "hash {i}");
                        assert!(!verify_stored_password(stored, b"nope"), "hash {i}");
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
    }
}
