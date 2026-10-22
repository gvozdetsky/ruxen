//! Certificate verification as nginx's OpenSSL does it, for upstreams
//! (`proxy_ssl_verify`, #117) and clients (`ssl_verify_client`, #113),
//! with the X.509 code of the AWS-LC that rustls already links: X509_verify_cert against the trusted
//! certificates, with nginx's verify depth and CRL flags, then
//! X509_check_host (ngx_ssl_check_host). webpki can't stand in for it: it
//! refuses certificates OpenSSL takes (a self-signed leaf marked CA:TRUE,
//! as `openssl req -x509` makes them; X.509 v1), has no commonName
//! fallback, and counts the depth differently.

use std::ffi::{CStr, c_char, c_int, c_long, c_void};
use std::net::IpAddr;
use std::ptr;

use aws_lc_sys as ffi;

/// A trust store: `proxy_ssl_trusted_certificate`, `proxy_ssl_verify_depth`
/// and `proxy_ssl_crl` (or the `ssl_*` ones of a server), loaded once and
/// shared by every worker.
#[derive(Debug)]
pub struct Store(*mut ffi::X509_STORE);

// X509_STORE is reference-counted and locks its own tables; once loaded it
// is only read.
unsafe impl Send for Store {}
unsafe impl Sync for Store {}

impl Drop for Store {
    fn drop(&mut self) {
        unsafe { ffi::X509_STORE_free(self.0) }
    }
}

/// Why a certificate was refused, in nginx's words.
#[derive(Debug)]
pub enum Failure {
    /// SSL_get_verify_result: the code and X509_verify_cert_error_string.
    Verify(c_long, String),
    /// ngx_ssl_check_host found no match for the name.
    Name(String),
    /// The certificate didn't parse.
    BadDer,
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Failure::Verify(code, text) => {
                write!(f, "upstream SSL certificate verify error: ({code}:{text})")
            }
            Failure::Name(name) => {
                write!(f, "upstream SSL certificate does not match \"{name}\"")
            }
            Failure::BadDer => f.write_str("upstream SSL certificate could not be parsed"),
        }
    }
}

impl std::error::Error for Failure {}

/// An owned X509.
pub(crate) struct Cert(pub(crate) *mut ffi::X509);

impl Drop for Cert {
    fn drop(&mut self) {
        unsafe { ffi::X509_free(self.0) }
    }
}

impl Cert {
    pub(crate) fn from_der(der: &[u8]) -> Option<Self> {
        let mut p = der.as_ptr();
        let x = unsafe { ffi::d2i_X509(ptr::null_mut(), &mut p, der.len() as c_long) };
        (!x.is_null()).then_some(Cert(x))
    }
}

/// The most recent error of this thread's queue, as OpenSSL prints it;
/// the queue is cleared.
pub(crate) fn ssl_error() -> String {
    let code = unsafe { ffi::ERR_get_error() };
    unsafe { ffi::ERR_clear_error() };
    if code == 0 {
        return "no certificate or crl found".to_string();
    }
    let mut buf = [0 as c_char; 256];
    unsafe {
        ffi::ERR_error_string_n(code, buf.as_mut_ptr(), buf.len());
        CStr::from_ptr(buf.as_ptr()).to_string_lossy().into_owned()
    }
}

impl Store {
    /// `trusted` is a PEM file's contents, `depth` is
    /// `proxy_ssl_verify_depth` (SSL_CTX_set_verify_depth). The file may
    /// hold certificates and CRLs, and must hold one of them, as
    /// X509_load_cert_crl_file wants. `Err` is the reason, OpenSSL's text.
    pub fn new(trusted: &[u8], depth: u32) -> Result<Store, String> {
        let mut store = Store::empty(depth)?;
        store.add_trusted(trusted)?;
        Ok(store)
    }

    /// A store that trusts nothing yet (`ssl_verify_client optional_no_ca`
    /// without certificates).
    pub fn empty(depth: u32) -> Result<Store, String> {
        let store = unsafe { ffi::X509_STORE_new() };
        if store.is_null() {
            return Err(ssl_error());
        }
        unsafe { ffi::X509_STORE_set_depth(store, depth.min(c_int::MAX as u32) as c_int) };
        Ok(Store(store))
    }

    /// A store with no depth of its own: a server's SSL_CTX store as
    /// OCSP_basic_verify uses it (`ssl_stapling_verify`, #141), since
    /// `ssl_verify_depth` limits the SSL_CTX, not its store.
    pub fn without_depth() -> Result<Store, String> {
        let store = unsafe { ffi::X509_STORE_new() };
        if store.is_null() {
            return Err(ssl_error());
        }
        Ok(Store(store))
    }

    pub(crate) fn as_ptr(&self) -> *mut ffi::X509_STORE {
        self.0
    }

    /// More trusted certificates (`ssl_client_certificate`, then
    /// `ssl_trusted_certificate`).
    pub fn add_trusted(&mut self, pem: &[u8]) -> Result<(), String> {
        self.load(pem)
    }

    /// `proxy_ssl_crl`: the file loaded as the trusted one is, and every
    /// certificate of the chain checked against the CRLs
    /// (X509_V_FLAG_CRL_CHECK_ALL, as ngx_ssl_crl sets).
    pub fn add_crl(&mut self, pem: &[u8]) -> Result<(), String> {
        self.load(pem)?;
        unsafe {
            ffi::X509_STORE_set_flags(
                self.0,
                (ffi::X509_V_FLAG_CRL_CHECK | ffi::X509_V_FLAG_CRL_CHECK_ALL) as _,
            );
        }
        Ok(())
    }

    /// Every certificate and CRL of a PEM text into the store.
    fn load(&self, pem: &[u8]) -> Result<(), String> {
        let mut found = 0;
        // PEM_read_bio_* skip the blocks of other types, so one pass per
        // type finds them all. The _AUX reader takes OpenSSL's `TRUSTED
        // CERTIFICATE` form too (`openssl x509 -trustout`), as
        // X509_load_cert_crl_file does (ssl_certificate_aux.t).
        let bio = || unsafe { ffi::BIO_new_mem_buf(pem.as_ptr() as *const c_void, pem.len() as _) };
        unsafe {
            let b = bio();
            loop {
                let x = ffi::PEM_read_bio_X509_AUX(b, ptr::null_mut(), None, ptr::null_mut());
                if x.is_null() {
                    break;
                }
                let added = ffi::X509_STORE_add_cert(self.0, x);
                ffi::X509_free(x);
                if added != 1 {
                    ffi::BIO_free(b);
                    return Err(ssl_error());
                }
                found += 1;
            }
            ffi::BIO_free(b);
            ffi::ERR_clear_error();
            let b = bio();
            loop {
                let crl = ffi::PEM_read_bio_X509_CRL(b, ptr::null_mut(), None, ptr::null_mut());
                if crl.is_null() {
                    break;
                }
                let added = ffi::X509_STORE_add_crl(self.0, crl);
                ffi::X509_CRL_free(crl);
                if added != 1 {
                    ffi::BIO_free(b);
                    return Err(ssl_error());
                }
                found += 1;
            }
            ffi::BIO_free(b);
            ffi::ERR_clear_error();
        }
        if found == 0 {
            return Err("no certificate or crl found".to_string());
        }
        Ok(())
    }

    /// nginx's check of an upstream's certificate: the chain the server
    /// sent (`leaf`, then `intermediates`) verified for TLS server use,
    /// then the leaf matched against `name` (ngx_ssl_check_host).
    pub fn verify(
        &self,
        leaf: &[u8],
        intermediates: &[&[u8]],
        name: &NameToCheck<'_>,
    ) -> Result<(), Failure> {
        let leaf = Cert::from_der(leaf).ok_or(Failure::BadDer)?;
        self.verify_chain(&leaf, intermediates, c"ssl_server")?;
        if name.matches(&leaf) {
            Ok(())
        } else {
            Err(Failure::Name(name.text.to_string()))
        }
    }

    /// A client's certificate (`ssl_verify_client`): the chain it sent,
    /// leaf first, verified for TLS client use, as OpenSSL verifies it in
    /// the handshake (SSL_get_verify_result).
    pub fn verify_client(&self, chain: &[&[u8]]) -> Result<(), Failure> {
        let (leaf, intermediates) = chain.split_first().ok_or(Failure::BadDer)?;
        let leaf = Cert::from_der(leaf).ok_or(Failure::BadDer)?;
        self.verify_chain(&leaf, intermediates, c"ssl_client")
    }

    fn verify_chain(
        &self,
        leaf: &Cert,
        intermediates: &[&[u8]],
        purpose: &CStr,
    ) -> Result<(), Failure> {
        let chain: Vec<Cert> = intermediates
            .iter()
            .map(|der| Cert::from_der(der).ok_or(Failure::BadDer))
            .collect::<Result<_, _>>()?;
        let code = unsafe {
            let stack = ffi::OPENSSL_sk_new_null();
            if stack.is_null() {
                return Err(Failure::BadDer);
            }
            for c in &chain {
                ffi::OPENSSL_sk_push(stack, c.0 as *mut c_void);
            }
            let ctx = ffi::X509_STORE_CTX_new();
            let code = if ctx.is_null()
                || ffi::X509_STORE_CTX_init(ctx, self.0, leaf.0, stack as *mut ffi::stack_st_X509)
                    != 1
            {
                ffi::X509_V_ERR_UNSPECIFIED as c_long
            } else {
                // As OpenSSL's ssl_verify_cert_chain, with nginx's
                // callback, which lets the chain be checked to the end
                // (ngx_ssl_verify_callback): the result is the last error,
                // as SSL_get_verify_result has it.
                ffi::X509_STORE_CTX_set_default(ctx, purpose.as_ptr());
                ffi::X509_STORE_CTX_set_verify_cb(ctx, Some(keep_going));
                ffi::X509_verify_cert(ctx);
                ffi::X509_STORE_CTX_get_error(ctx) as c_long
            };
            ffi::X509_STORE_CTX_free(ctx);
            // The certificates are `chain`'s, freed with it.
            ffi::OPENSSL_sk_free(stack);
            code
        };
        if code != ffi::X509_V_OK as c_long {
            let text = unsafe { CStr::from_ptr(ffi::X509_verify_cert_error_string(code)) };
            return Err(Failure::Verify(code, text.to_string_lossy().into_owned()));
        }
        Ok(())
    }
}

/// nginx's ngx_ssl_verify_error_optional: the errors `ssl_verify_client
/// optional_no_ca` lets through, those of a certificate nobody vouches for.
pub fn error_is_optional(code: c_long) -> bool {
    [
        ffi::X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT,
        ffi::X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN,
        ffi::X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY,
        ffi::X509_V_ERR_CERT_UNTRUSTED,
        ffi::X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE,
    ]
    .iter()
    .any(|&c| c as c_long == code)
}

/// The DER subject names of the certificates in a PEM text, each once:
/// the CA list a server sends with its CertificateRequest, as
/// SSL_load_client_CA_file reads it from `ssl_client_certificate`.
pub fn subjects(pem: &[u8]) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    unsafe {
        let b = ffi::BIO_new_mem_buf(pem.as_ptr() as *const c_void, pem.len() as _);
        loop {
            let x = ffi::PEM_read_bio_X509_AUX(b, ptr::null_mut(), None, ptr::null_mut());
            if x.is_null() {
                break;
            }
            let name = ffi::X509_get_subject_name(x);
            let len = ffi::i2d_X509_NAME(name, ptr::null_mut());
            if len > 0 {
                let mut der = vec![0u8; len as usize];
                let mut p = der.as_mut_ptr();
                if ffi::i2d_X509_NAME(name, &mut p) == len && !out.contains(&der) {
                    out.push(der);
                }
            }
            ffi::X509_free(x);
        }
        ffi::BIO_free(b);
        ffi::ERR_clear_error();
    }
    out
}

unsafe extern "C" fn keep_going(_ok: c_int, _ctx: *mut ffi::X509_STORE_CTX) -> c_int {
    1
}

/// The name an upstream certificate must carry: `proxy_ssl_name`, or the
/// host of `proxy_pass`.
pub struct NameToCheck<'a> {
    pub text: &'a str,
    pub ip: Option<IpAddr>,
}

impl NameToCheck<'_> {
    /// X509_check_host, as nginx 1.24 checks every name: subjectAltName
    /// DNS entries, and the commonName when there are none. An address
    /// also matches an iPAddress entry, as later nginx checks addresses
    /// (proxy_ssl_verify_ip.t), so a certificate made for the address
    /// works either way.
    fn matches(&self, leaf: &Cert) -> bool {
        if self.text.is_empty() {
            return false;
        }
        let ip_match = self.ip.is_some_and(|ip| {
            let bytes: Vec<u8> = match ip {
                IpAddr::V4(v4) => v4.octets().to_vec(),
                IpAddr::V6(v6) => v6.octets().to_vec(),
            };
            unsafe { ffi::X509_check_ip(leaf.0, bytes.as_ptr(), bytes.len(), 0) == 1 }
        });
        ip_match
            || unsafe {
                ffi::X509_check_host(
                    leaf.0,
                    self.text.as_ptr() as *const c_char,
                    self.text.len(),
                    0,
                    ptr::null_mut(),
                ) == 1
            }
    }
}

/// The DER SubjectPublicKeyInfo of a certificate, to check the handshake
/// signature with: OpenSSL takes certificates webpki won't parse.
pub fn spki(cert: &[u8]) -> Option<Vec<u8>> {
    let cert = Cert::from_der(cert)?;
    unsafe {
        let key = ffi::X509_get_X509_PUBKEY(cert.0);
        if key.is_null() {
            return None;
        }
        let len = ffi::i2d_X509_PUBKEY(key, ptr::null_mut());
        if len <= 0 {
            return None;
        }
        let mut out = vec![0u8; len as usize];
        let mut p = out.as_mut_ptr();
        if ffi::i2d_X509_PUBKEY(key, &mut p) != len {
            return None;
        }
        Some(out)
    }
}

/// A TLS 1.2 handshake signature checked with the key of `cert`, as
/// rustls's verify_tls12_signature does but from the bare key: OpenSSL
/// takes certificates webpki won't parse. TLS 1.2 names a scheme several
/// algorithms may stand for.
pub fn verify_tls12_signature(
    algs: &rustls::crypto::WebPkiSupportedAlgorithms,
    message: &[u8],
    cert: &rustls::pki_types::CertificateDer<'_>,
    dss: &rustls::DigitallySignedStruct,
) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
    let spki = spki_der(cert)?;
    let key = webpki::RawPublicKeyEntity::try_from(&spki).map_err(|_| bad_encoding())?;
    let candidates = algs
        .mapping
        .iter()
        .filter(|(scheme, _)| *scheme == dss.scheme)
        .flat_map(|(_, algs)| algs.iter());
    for alg in candidates {
        match key.verify_signature(*alg, message, dss.signature()) {
            Ok(()) => return Ok(rustls::client::danger::HandshakeSignatureValid::assertion()),
            Err(webpki::Error::UnsupportedSignatureAlgorithmForPublicKeyContext(_)) => continue,
            Err(_) => break,
        }
    }
    Err(rustls::Error::InvalidCertificate(
        rustls::CertificateError::BadSignature,
    ))
}

/// The TLS 1.3 handshake signature, likewise from the key of `cert`.
pub fn verify_tls13_signature(
    algs: &rustls::crypto::WebPkiSupportedAlgorithms,
    message: &[u8],
    cert: &rustls::pki_types::CertificateDer<'_>,
    dss: &rustls::DigitallySignedStruct,
) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
    rustls::crypto::verify_tls13_signature_with_raw_key(message, &spki_der(cert)?, dss, algs)
}

fn bad_encoding() -> rustls::Error {
    rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
}

fn spki_der(
    cert: &rustls::pki_types::CertificateDer<'_>,
) -> Result<rustls::pki_types::SubjectPublicKeyInfoDer<'static>, rustls::Error> {
    spki(cert)
        .map(rustls::pki_types::SubjectPublicKeyInfoDer::from)
        .ok_or_else(bad_encoding)
}

/// One `$ssl_client_*` field of a certificate, as nginx's ngx_ssl_get_*
/// prints it with OpenSSL (#114). Nothing for a certificate that doesn't
/// parse.
pub fn print_field(der: &[u8], field: crate::config::SslClientField, out: &mut Vec<u8>) {
    use crate::config::SslClientField as F;
    let Some(cert) = Cert::from_der(der) else {
        return;
    };
    let x = cert.0;
    unsafe {
        match field {
            F::RawCert => print_to(out, |b| ffi::PEM_write_bio_X509(b, x)),
            // ngx_ssl_get_certificate: the PEM without its last newline,
            // a TAB after each other one.
            F::Cert => {
                let mut pem = Vec::new();
                print_to(&mut pem, |b| ffi::PEM_write_bio_X509(b, x));
                pem.pop();
                for &byte in &pem {
                    out.push(byte);
                    if byte == b'\n' {
                        out.push(b'\t');
                    }
                }
            }
            F::EscapedCert => {
                let mut pem = Vec::new();
                print_to(&mut pem, |b| ffi::PEM_write_bio_X509(b, x));
                escape_uri_component(&pem, out);
            }
            F::SDn | F::IDn => {
                let name = if field == F::SDn {
                    ffi::X509_get_subject_name(x)
                } else {
                    ffi::X509_get_issuer_name(x)
                };
                print_to(out, |b| {
                    ffi::X509_NAME_print_ex(b, name, 0, ffi::XN_FLAG_RFC2253 as _)
                });
            }
            F::SDnLegacy | F::IDnLegacy => {
                let name = if field == F::SDnLegacy {
                    ffi::X509_get_subject_name(x)
                } else {
                    ffi::X509_get_issuer_name(x)
                };
                let text = ffi::X509_NAME_oneline(name, ptr::null_mut(), 0);
                if !text.is_null() {
                    out.extend_from_slice(CStr::from_ptr(text).to_bytes());
                    ffi::OPENSSL_free(text as *mut c_void);
                }
            }
            F::Serial => print_to(out, |b| {
                ffi::i2a_ASN1_INTEGER(b, ffi::X509_get_serialNumber(x))
            }),
            F::Fingerprint => {
                let mut digest = [0u8; 64];
                let mut len: std::ffi::c_uint = 0;
                if ffi::X509_digest(x, ffi::EVP_sha1(), digest.as_mut_ptr(), &mut len) == 1 {
                    const HEX: &[u8; 16] = b"0123456789abcdef";
                    for b in &digest[..len as usize] {
                        out.push(HEX[(b >> 4) as usize]);
                        out.push(HEX[(b & 0xf) as usize]);
                    }
                }
            }
            F::VStart => print_to(out, |b| {
                ffi::ASN1_TIME_print(b, ffi::X509_get0_notBefore(x))
            }),
            F::VEnd => print_to(out, |b| ffi::ASN1_TIME_print(b, ffi::X509_get0_notAfter(x))),
            // ngx_ssl_get_client_v_remain: whole days, 0 under one day.
            F::VRemain => {
                let mut end: i64 = 0;
                if ffi::ASN1_TIME_to_posix(ffi::X509_get0_notAfter(x), &mut end) == 1 {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |d| d.as_secs() as i64);
                    let days = if end < now + 86400 {
                        0
                    } else {
                        (end - now) / 86400
                    };
                    out.extend_from_slice(days.to_string().as_bytes());
                }
            }
        }
    }
}

/// What `print` writes into a memory BIO, appended to `out`.
unsafe fn print_to(out: &mut Vec<u8>, print: impl FnOnce(*mut ffi::BIO) -> c_int) {
    unsafe {
        let bio = ffi::BIO_new(ffi::BIO_s_mem());
        if bio.is_null() {
            return;
        }
        if print(bio) > 0 {
            let mut data: *const u8 = ptr::null();
            let mut len: usize = 0;
            if ffi::BIO_mem_contents(bio, &mut data, &mut len) == 1 && !data.is_null() {
                out.extend_from_slice(std::slice::from_raw_parts(data, len));
            }
        }
        ffi::BIO_free(bio);
        ffi::ERR_clear_error();
    }
}

/// nginx's ngx_escape_uri with NGX_ESCAPE_URI_COMPONENT.
pub(crate) fn escape_uri_component(input: &[u8], out: &mut Vec<u8>) {
    const ESCAPE: [u32; 8] = [
        0xffffffff, 0xfc009fff, 0x78000001, 0xb8000001, 0xffffffff, 0xffffffff, 0xffffffff,
        0xffffffff,
    ];
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for &b in input {
        if ESCAPE[(b >> 5) as usize] & (1 << (b & 0x1f)) != 0 {
            out.push(b'%');
            out.push(HEX[(b >> 4) as usize]);
            out.push(HEX[(b & 0xf) as usize]);
        } else {
            out.push(b);
        }
    }
}

/// An encrypted PEM private key (PKCS#8 `ENCRYPTED PRIVATE KEY`, or
/// OpenSSL's legacy `Proc-Type: 4,ENCRYPTED`) decrypted with the first of
/// `passwords` that opens it, as nginx tries `ssl_password_file`'s lines
/// with PEM_read_bio_PrivateKey (ngx_ssl_load_certificate_key). The key
/// comes back as unencrypted PKCS#8 DER. `Err` is OpenSSL's reason.
pub fn decrypt_private_key(pem: &[u8], passwords: &[Vec<u8>]) -> Result<Vec<u8>, String> {
    let mut reason = String::from("no password to decrypt it with (ssl_password_file)");
    for password in passwords {
        let mut c_password: Vec<u8> = password.iter().copied().filter(|&b| b != 0).collect();
        c_password.push(0);
        let key = unsafe {
            let bio = ffi::BIO_new_mem_buf(pem.as_ptr() as *const c_void, pem.len() as _);
            let key = ffi::PEM_read_bio_PrivateKey(
                bio,
                ptr::null_mut(),
                None,
                c_password.as_mut_ptr() as *mut c_void,
            );
            ffi::BIO_free(bio);
            ffi::OPENSSL_cleanse(c_password.as_mut_ptr() as *mut c_void, c_password.len());
            key
        };
        if key.is_null() {
            reason = ssl_error();
            continue;
        }
        let der = unsafe {
            let mut cbb: ffi::CBB = std::mem::zeroed();
            let mut out: *mut u8 = ptr::null_mut();
            let mut len: usize = 0;
            let ok = ffi::CBB_init(&mut cbb, 0) == 1
                && ffi::EVP_marshal_private_key(&mut cbb, key) == 1
                && ffi::CBB_finish(&mut cbb, &mut out, &mut len) == 1;
            ffi::EVP_PKEY_free(key);
            if !ok {
                ffi::CBB_cleanup(&mut cbb);
                return Err(ssl_error());
            }
            let der = std::slice::from_raw_parts(out, len).to_vec();
            ffi::OPENSSL_cleanse(out as *mut c_void, len);
            ffi::OPENSSL_free(out as *mut c_void);
            der
        };
        unsafe { ffi::ERR_clear_error() };
        return Ok(der);
    }
    Err(reason)
}

/// The key PEM is encrypted: PKCS#8 or OpenSSL's legacy form.
pub fn is_encrypted_key(pem: &[u8]) -> bool {
    let has = |needle: &[u8]| pem.windows(needle.len()).any(|w| w == needle);
    has(b"-----BEGIN ENCRYPTED PRIVATE KEY-----") || has(b"Proc-Type: 4,ENCRYPTED")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SslClientField as F;

    fn der(pem: &[u8]) -> Vec<u8> {
        use rustls::pki_types::pem::PemObject;
        rustls::pki_types::CertificateDer::from_pem_slice(pem)
            .unwrap()
            .to_vec()
    }

    fn field(der: &[u8], f: F) -> String {
        let mut out = Vec::new();
        print_field(der, f, &mut out);
        String::from_utf8(out).unwrap()
    }

    /// The values `openssl x509 -noout -subject -nameopt RFC2253 -serial
    /// -fingerprint -sha1 -startdate -enddate` prints for the file.
    #[test]
    fn fields_print_as_openssl_prints_them() {
        let pem = include_bytes!("testdata/tls/ec.crt");
        let d = der(pem);
        assert_eq!(field(&d, F::SDn), "CN=test.ruxen.local");
        assert_eq!(field(&d, F::IDnLegacy), "/CN=test.ruxen.local");
        assert_eq!(
            field(&d, F::Serial),
            "0130DB20D13F4A1CA436D5DB9BB517E9BBAACD84"
        );
        assert_eq!(
            field(&d, F::Fingerprint),
            "2b6995dd5d71a32053872757b729d6876f4eb9e4"
        );
        assert_eq!(field(&d, F::VStart), "Apr 28 15:17:31 2026 GMT");
        assert_eq!(field(&d, F::VEnd), "Apr  4 15:17:31 2126 GMT");
        let days: i64 = field(&d, F::VRemain).parse().unwrap();
        assert!((36_000..36_600).contains(&days), "{days}");
        // The PEM as PEM_write_bio_X509 writes it, and nginx's two forms.
        let raw = field(&d, F::RawCert);
        assert!(raw.starts_with("-----BEGIN CERTIFICATE-----\n") && raw.ends_with("-----\n"));
        assert_eq!(der(raw.as_bytes()), d);
        let tabbed = field(&d, F::Cert);
        assert_eq!(tabbed, raw.trim_end_matches('\n').replace('\n', "\n\t"));
        let escaped = field(&d, F::EscapedCert);
        assert!(
            escaped.starts_with("-----BEGIN%20CERTIFICATE-----%0A"),
            "{escaped}"
        );
        assert!(!escaped.contains('\n') && !escaped.contains('+') && !escaped.contains('/'));
    }

    /// RFC 2253: the RDNs last first, `,` escaped; the legacy form in
    /// order with `/`.
    #[test]
    fn names_with_several_attributes() {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CountryName, "NL");
        params
            .distinguished_name
            .push(rcgen::DnType::OrganizationName, "Acme, Inc.");
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "client");
        let cert = params.self_signed(&key).unwrap();
        let d = cert.der().to_vec();
        assert_eq!(field(&d, F::SDn), "CN=client,O=Acme\\, Inc.,C=NL");
        assert_eq!(field(&d, F::SDnLegacy), "/C=NL/O=Acme, Inc./CN=client");
        assert_eq!(field(b"not a certificate", F::SDn), "");
    }
}
