//! Upstream certificate verification as nginx's OpenSSL does it
//! (`proxy_ssl_verify`, #117), with the X.509 code of the AWS-LC that
//! rustls already links: X509_verify_cert against the trusted
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
/// and `proxy_ssl_crl`, loaded once and shared by every worker.
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
struct Cert(*mut ffi::X509);

impl Drop for Cert {
    fn drop(&mut self) {
        unsafe { ffi::X509_free(self.0) }
    }
}

impl Cert {
    fn from_der(der: &[u8]) -> Option<Self> {
        let mut p = der.as_ptr();
        let x = unsafe { ffi::d2i_X509(ptr::null_mut(), &mut p, der.len() as c_long) };
        (!x.is_null()).then_some(Cert(x))
    }
}

/// The most recent error of this thread's queue, as OpenSSL prints it;
/// the queue is cleared.
fn ssl_error() -> String {
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
        let store = unsafe { ffi::X509_STORE_new() };
        if store.is_null() {
            return Err(ssl_error());
        }
        let store = Store(store);
        store.load(trusted)?;
        unsafe { ffi::X509_STORE_set_depth(store.0, depth.min(c_int::MAX as u32) as c_int) };
        Ok(store)
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
        // type finds them all.
        let bio = || unsafe { ffi::BIO_new_mem_buf(pem.as_ptr() as *const c_void, pem.len() as _) };
        unsafe {
            let b = bio();
            loop {
                let x = ffi::PEM_read_bio_X509(b, ptr::null_mut(), None, ptr::null_mut());
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
                // As OpenSSL's ssl_verify_cert_chain for a client, with
                // nginx's callback, which lets the chain be checked to
                // the end (ngx_ssl_verify_callback; the verify mode is
                // SSL_VERIFY_NONE): the result is the last error, as
                // SSL_get_verify_result has it.
                ffi::X509_STORE_CTX_set_default(ctx, c"ssl_server".as_ptr());
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
        if name.matches(&leaf) {
            Ok(())
        } else {
            Err(Failure::Name(name.text.to_string()))
        }
    }
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
