use crate::http;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::io;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
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
    let mut response = http::build_response_for_method(401, "Unauthorized\n", method, server);
    let mut header = Vec::with_capacity(realm.len() + 48);
    header.extend_from_slice(b"\r\nWWW-Authenticate: Basic realm=\"");
    append_escaped_realm(&mut header, realm);
    header.extend_from_slice(b"\"");
    if let Some(head_end) = response.windows(4).position(|w| w == b"\r\n\r\n") {
        response.splice(head_end..head_end, header);
    }
    response
}

fn verify_stored_password(stored: &[u8], password: &[u8]) -> bool {
    if let Some(plain) = stored.strip_prefix(b"{PLAIN}") {
        return plain == password;
    }
    if let Some(sha_raw) = stored.strip_prefix(b"{SHA}") {
        let Some(expected) = decode_base64(sha_raw) else {
            return false;
        };
        return expected.as_slice() == sha1_digest(password);
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
        return expected == sha1_digest(&salted);
    }
    if stored.starts_with(b"$apr1$") {
        return verify_crypt(stored, password)
            || verify_openssl_password(stored, password, b"$apr1$", "-apr1");
    }
    if stored.starts_with(b"$1$") {
        return verify_crypt(stored, password)
            || verify_openssl_password(stored, password, b"$1$", "-1");
    }
    if stored.starts_with(b"{") {
        return false;
    }
    verify_crypt(stored, password)
}

/// Fallback for `$apr1$` / `$1$` (MD5-crypt) verification when the system
/// `crypt(3)` doesn't recognize the prefix. On glibc this path is dormant
/// — libc handles both already — so the subprocess cost stays off the hot
/// path on our target (Linux 6.17). We keep it for portability to libcs
/// that only ship DES+SHA-crypt. Spawning `openssl passwd` blocks the
/// monoio worker; acceptable only because of the dormancy.
fn verify_openssl_password(stored: &[u8], password: &[u8], prefix: &[u8], mode: &str) -> bool {
    let Some(salt) = crypt_salt(stored, prefix) else {
        return false;
    };
    let Ok(salt) = std::str::from_utf8(salt) else {
        return false;
    };
    let Ok(mut child) = Command::new("openssl")
        .args(["passwd", mode, "-salt", salt, "-stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    else {
        return false;
    };
    if let Some(stdin) = child.stdin.as_mut() {
        if stdin.write_all(password).is_err() {
            let _ = child.kill();
            let _ = child.wait();
            return false;
        }
    } else {
        let _ = child.kill();
        let _ = child.wait();
        return false;
    }
    let Ok(output) = child.wait_with_output() else {
        return false;
    };
    if !output.status.success() {
        return false;
    }
    let actual = output
        .stdout
        .strip_suffix(b"\n")
        .or_else(|| output.stdout.strip_suffix(b"\r\n"))
        .unwrap_or(output.stdout.as_slice());
    actual == stored
}

fn crypt_salt<'a>(stored: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    if !stored.starts_with(prefix) {
        return None;
    }
    let salt_start = prefix.len();
    let salt_tail = &stored[salt_start..];
    let salt_end = salt_tail.iter().position(|&b| b == b'$')?;
    Some(&salt_tail[..salt_end])
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

#[cfg(unix)]
static CRYPT_LOCK: Mutex<()> = Mutex::new(());

// glibc has crypt() in libcrypt (libxcrypt); musl has it in libc itself,
// and linking a glibc libcrypt.a into a static musl binary fails.
#[cfg(unix)]
#[cfg_attr(not(target_env = "musl"), link(name = "crypt"))]
unsafe extern "C" {
    fn crypt(key: *const libc::c_char, salt: *const libc::c_char) -> *mut libc::c_char;
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
    let _guard = CRYPT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let ptr = unsafe { crypt(key.as_ptr(), salt.as_ptr()) };
    if ptr.is_null() {
        return false;
    }
    let out = unsafe { CStr::from_ptr(ptr) }.to_bytes();
    out == stored
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
    }
}
