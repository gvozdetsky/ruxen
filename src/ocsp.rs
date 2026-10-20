//! OCSP stapling (#141), as nginx's ngx_event_openssl_stapling.c staples,
//! with the OCSP code of the AWS-LC that rustls already links (as
//! `x509_verify` checks certificates with its X.509 code):
//!
//! - `ssl_stapling_file`: the DER response is read at startup and stapled
//!   as it is, whatever it says, and never fetched.
//! - Otherwise the response comes from the responder
//!   (`ssl_stapling_responder`, else the certificate's Authority
//!   Information Access URL), fetched when a handshake first wants it:
//!   that handshake goes without, as in nginx. A response that verifies
//!   (OCSP_basic_verify; the responder's chain too with
//!   `ssl_stapling_verify`) and says `good` is stapled until its
//!   nextUpdate, and fetched again 5 minutes before that, at least every
//!   hour; after a failure, in 5 minutes.
//!
//! One `Stapling` per certificate of a server, shared by the workers. The
//! fetch runs on the worker whose handshake started it, as a task of its
//! own (`spawn_contained`), so it ends with that worker's generation and
//! logs to its error log. The handshake itself takes a lock to clone an
//! `Arc`, and only for certificates that staple.

use std::ffi::{CStr, c_char, c_int, c_long, c_ulong, c_void};
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aws_lc_sys as ffi;
use rustls::sign::CertifiedKey;

use crate::config::ErrorLogLevel;
use crate::x509_verify::{Cert, Store};

/// nginx's staple->timeout: for the connection and for each direction.
const TIMEOUT: Duration = Duration::from_secs(60);
/// The response buffer of ngx_ssl_ocsp_read_handler; a longer response is
/// cut there.
const MAX_RESPONSE: usize = 16384;

/// A certificate that staples: `ssl_stapling on` for a server.
pub struct Stapling {
    /// The certificate as loaded, without a response.
    base: Arc<CertifiedKey>,
    /// The certificate with the response it staples, and the time (Unix
    /// seconds) it may until: nginx's staple and valid.
    staple: Mutex<Option<(Arc<CertifiedKey>, i64)>>,
    /// Where responses come from; `None` with `ssl_stapling_file`.
    fetch: Option<Fetch>,
    /// A fetch runs.
    loading: AtomicBool,
    /// No fetch starts before this time (Unix seconds).
    refresh: AtomicI64,
}

impl std::fmt::Debug for Stapling {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Stapling")
            .field("fetch", &self.fetch.as_ref().map(|f| &f.name))
            .finish_non_exhaustive()
    }
}

/// What a fetch needs. The certificates are kept as DER and parsed for
/// each fetch, once an hour or so.
struct Fetch {
    leaf: Vec<u8>,
    issuer: Vec<u8>,
    /// The certificates after the leaf in `ssl_certificate`: nginx's
    /// extra chain certificates, searched for the responder's.
    chain: Vec<Vec<u8>>,
    /// The server's trusted certificates (`ssl_trusted_certificate`, and
    /// `ssl_client_certificate` with `ssl_verify_client`).
    store: Arc<Store>,
    verify: bool,
    responder: Responder,
    /// The certificate file, for log lines.
    name: String,
}

struct Responder {
    /// As written in the URL, for `Host` and log lines.
    host: String,
    uri: String,
    addrs: Vec<SocketAddr>,
}

/// How a server staples: its `ssl_stapling_*` lines and the store its
/// `ssl_trusted_certificate` makes.
pub struct Settings<'a> {
    pub file: Option<&'a Path>,
    pub responder: Option<&'a str>,
    pub verify: bool,
    pub store: Arc<Store>,
}

impl Stapling {
    /// ngx_ssl_stapling_certificate for `key`, loaded from `cert_file`.
    /// `Ok(None)`: stapling is off for it, and `warn` says why, as nginx's
    /// `"ssl_stapling" ignored` lines do. `Err`: the configuration fails.
    pub fn new(
        key: Arc<CertifiedKey>,
        cert_file: &Path,
        settings: &Settings<'_>,
        warn: &mut dyn FnMut(String),
    ) -> Result<Option<Arc<Stapling>>, String> {
        let name = cert_file.display().to_string();
        if let Some(file) = settings.file {
            let response = read_response_file(file)?;
            let stapled = Arc::new(CertifiedKey {
                ocsp: Some(response),
                ..(*key).clone()
            });
            return Ok(Some(Arc::new(Stapling {
                base: key,
                staple: Mutex::new(Some((stapled, i64::MAX))),
                fetch: None,
                loading: AtomicBool::new(false),
                refresh: AtomicI64::new(0),
            })));
        }
        let leaf = key.cert.first().ok_or("no certificate")?.to_vec();
        let chain: Vec<Vec<u8>> = key.cert[1..].iter().map(|c| c.to_vec()).collect();
        let Some(issuer) = find_issuer(&leaf, &chain, &settings.store)? else {
            warn(format!(
                "\"ssl_stapling\" ignored, issuer certificate not found for certificate \"{name}\""
            ));
            return Ok(None);
        };
        let url = match settings.responder {
            Some(url) => url.to_string(),
            None => match responder_in(&leaf) {
                Some(url) => url,
                None => {
                    warn(format!(
                        "\"ssl_stapling\" ignored, no OCSP responder URL in the certificate \
                         \"{name}\""
                    ));
                    return Ok(None);
                }
            },
        };
        let responder = match parse_responder(&url) {
            Ok(r) => r,
            Err((err, url)) => {
                warn(format!(
                    "\"ssl_stapling\" ignored, {err} in OCSP responder \"{url}\" in the \
                     certificate \"{name}\""
                ));
                return Ok(None);
            }
        };
        Ok(Some(Arc::new(Stapling {
            base: key,
            staple: Mutex::new(None),
            fetch: Some(Fetch {
                leaf,
                issuer,
                chain,
                store: settings.store.clone(),
                verify: settings.verify,
                responder,
                name,
            }),
            loading: AtomicBool::new(false),
            refresh: AtomicI64::new(0),
        })))
    }

    /// The certificate for a handshake (ngx_ssl_certificate_status_callback):
    /// with the response while it is valid, and a fetch started when one
    /// is due.
    pub fn for_handshake(self: &Arc<Self>) -> Arc<CertifiedKey> {
        let now = unix_now();
        let key = match &*self.staple.lock().unwrap_or_else(|e| e.into_inner()) {
            Some((stapled, valid)) if *valid >= now => stapled.clone(),
            _ => self.base.clone(),
        };
        self.update(now);
        key
    }

    /// ngx_ssl_stapling_update.
    fn update(self: &Arc<Self>, now: i64) {
        if self.fetch.is_none()
            || self.refresh.load(Ordering::Relaxed) >= now
            || self.loading.swap(true, Ordering::Acquire)
        {
            return;
        }
        // Only a worker runs fetches: they log to its error log.
        if crate::worker::worker_http().is_none() {
            self.loading.store(false, Ordering::Release);
            return;
        }
        let this = self.clone();
        crate::worker::spawn_contained("the OCSP request", || {}, async move {
            this.refetch().await;
        });
    }

    /// One fetch, then the next one's time (ngx_ssl_stapling_ocsp_handler).
    async fn refetch(&self) {
        let fetch = self
            .fetch
            .as_ref()
            .expect("only a fetching stapling updates");
        // Also when the task ends early: a panic ends it, as does the end
        // of the worker.
        let mut done = Done {
            stapling: self,
            refresh: unix_now() + 300,
        };
        let Some((peer, response)) = fetch.request().await else {
            return;
        };
        let Some(valid) = fetch.check(&response, peer) else {
            return;
        };
        let stapled = Arc::new(CertifiedKey {
            ocsp: Some(response),
            ..(*self.base).clone()
        });
        *self.staple.lock().unwrap_or_else(|e| e.into_inner()) = Some((stapled, valid));
        // Before the response expires, but not earlier than in 5 minutes,
        // and at least in an hour.
        let now = unix_now();
        done.refresh = valid.saturating_sub(300).min(now + 3600).max(now + 300);
    }
}

/// Ends a fetch: `loading` cleared, the next one at `refresh`.
struct Done<'a> {
    stapling: &'a Stapling,
    refresh: i64,
}

impl Drop for Done<'_> {
    fn drop(&mut self) {
        self.stapling.refresh.store(self.refresh, Ordering::Relaxed);
        self.stapling.loading.store(false, Ordering::Release);
    }
}

impl Fetch {
    /// A line about this fetch, with nginx's context
    /// (ngx_ssl_ocsp_log_error).
    fn log(&self, level: ErrorLogLevel, message: &str, peer: Option<SocketAddr>) {
        let logs = crate::worker::worker_http().map_or(&[][..], |h| h.error_logs);
        let mut line = format!(
            "{message} while requesting certificate status, responder: {}",
            self.responder.host
        );
        if let Some(peer) = peer {
            line.push_str(&format!(", peer: {peer}"));
        }
        line.push_str(&format!(", certificate: \"{}\"", self.name));
        crate::worker::write_worker_log(logs, level, &line);
    }

    /// The responder's answer to the request for the certificate's
    /// status, from the first of its addresses that gives one: that
    /// address and the response, or `None` after logging why not. A
    /// status other than 200 is `None` without a line, as in nginx.
    async fn request(&self) -> Option<(SocketAddr, Vec<u8>)> {
        let request = match self.http_request() {
            Ok(r) => r,
            Err(e) => {
                self.log(ErrorLogLevel::Crit, &e, None);
                return None;
            }
        };
        for &addr in &self.responder.addrs {
            // A connection like an upstream's (ngx_event_connect_peer):
            // with none left, the fetch fails.
            let _slot = crate::worker::take_upstream_slot()?;
            match self.exchange(addr, &request).await {
                Ok((200, body)) => return Some((addr, body)),
                Ok(_) => return None,
                Err(e) => self.log(ErrorLogLevel::Error, &e, Some(addr)),
            }
        }
        None
    }

    /// One try at `addr`: the status code and the body, or what went
    /// wrong, in nginx's words.
    async fn exchange(&self, addr: SocketAddr, request: &[u8]) -> Result<(u16, Vec<u8>), String> {
        use monoio::io::{AsyncReadRent, AsyncWriteRentExt};
        let timed_out = || "OCSP responder timed out (110: Connection timed out)".to_string();
        let recv_failed = |e: &std::io::Error| {
            let text = format!("recv() failed ({})", crate::worker::errno_text(e));
            self.log(ErrorLogLevel::Error, &text, Some(addr));
        };
        let connected =
            match monoio::time::timeout(TIMEOUT, monoio::net::TcpStream::connect(addr)).await {
                Ok(c) => c,
                Err(_) => return Err(timed_out()),
            };
        let mut stream = match connected {
            Ok(s) => s,
            // What connect() itself refuses (ngx_event_connect_peer)...
            Err(e) if connect_fails_at_once(&e) => {
                return Err(format!(
                    "connect() failed ({})",
                    crate::worker::errno_text(&e)
                ));
            }
            // ... and what comes later, which nginx's read handler meets
            // first: as a read error, then an empty response.
            Err(e) => {
                recv_failed(&e);
                return parse_http_response(&[]);
            }
        };
        let exchange = async {
            let (written, _) = stream.write_all(request.to_vec()).await;
            written.map_err(|e| format!("send() failed ({})", crate::worker::errno_text(&e)))?;
            let mut response: Vec<u8> = Vec::with_capacity(MAX_RESPONSE);
            let mut buf = vec![0u8; MAX_RESPONSE];
            while response.len() < MAX_RESPONSE {
                let (read, b) = stream.read(buf).await;
                buf = b;
                match read {
                    Ok(0) => break,
                    Ok(n) => {
                        let n = n.min(MAX_RESPONSE - response.len());
                        response.extend_from_slice(&buf[..n]);
                    }
                    // nginx reads what came as the whole response.
                    Err(e) => {
                        recv_failed(&e);
                        break;
                    }
                }
            }
            Ok::<_, String>(response)
        };
        let response = match monoio::time::timeout(TIMEOUT, exchange).await {
            Ok(r) => r?,
            Err(_) => return Err(timed_out()),
        };
        parse_http_response(&response)
    }

    /// ngx_ssl_ocsp_create_request: a GET with the DER request, base64
    /// and escaped, after the responder's URI.
    fn http_request(&self) -> Result<Vec<u8>, String> {
        let der = unsafe {
            let leaf = Cert::from_der(&self.leaf).ok_or("d2i_X509() failed")?;
            let issuer = Cert::from_der(&self.issuer).ok_or("d2i_X509() failed")?;
            let request = ffi::OCSP_REQUEST_new();
            if request.is_null() {
                return Err("OCSP_REQUEST_new() failed".into());
            }
            let id = ffi::OCSP_cert_to_id(ptr::null(), leaf.0, issuer.0);
            let der = if id.is_null() {
                Err("OCSP_cert_to_id() failed".to_string())
            } else if ffi::OCSP_request_add0_id(request, id).is_null() {
                ffi::OCSP_CERTID_free(id);
                Err("OCSP_request_add0_id() failed".to_string())
            } else {
                i2d(|out| ffi::i2d_OCSP_REQUEST(request, out))
                    .ok_or_else(|| "i2d_OCSP_REQUEST() failed".to_string())
            };
            ffi::OCSP_REQUEST_free(request);
            ffi::ERR_clear_error();
            der?
        };
        let mut base64 = vec![0u8; der.len().div_ceil(3) * 4 + 1];
        let len = unsafe { ffi::EVP_EncodeBlock(base64.as_mut_ptr(), der.as_ptr(), der.len()) };
        base64.truncate(len);
        let uri = &self.responder.uri;
        let mut out = Vec::with_capacity(64 + uri.len() + 3 * base64.len());
        out.extend_from_slice(b"GET ");
        out.extend_from_slice(uri.as_bytes());
        if !uri.ends_with('/') {
            out.push(b'/');
        }
        crate::x509_verify::escape_uri_component(&base64, &mut out);
        out.extend_from_slice(b" HTTP/1.0\r\nHost: ");
        out.extend_from_slice(self.responder.host.as_bytes());
        out.extend_from_slice(b"\r\n\r\n");
        Ok(out)
    }

    /// ngx_ssl_ocsp_verify, then the status: the time the response from
    /// `peer` is valid until when it verifies and says `good`, else `None`
    /// after logging why.
    fn check(&self, response: &[u8], peer: SocketAddr) -> Option<i64> {
        let result = unsafe { self.verify(response) };
        unsafe { ffi::ERR_clear_error() };
        match result {
            Ok((status, valid)) if status == ffi::V_OCSP_CERTSTATUS_GOOD => Some(valid),
            Ok((status, _)) => {
                let text = unsafe { CStr::from_ptr(ffi::OCSP_cert_status_str(status as c_long)) };
                self.log(
                    ErrorLogLevel::Error,
                    &format!(
                        "certificate status \"{}\" in the OCSP response",
                        text.to_string_lossy()
                    ),
                    Some(peer),
                );
                None
            }
            Err((level, message)) => {
                self.log(level, &message, Some(peer));
                None
            }
        }
    }

    /// The certificate's status and the end of the response's validity.
    unsafe fn verify(&self, response: &[u8]) -> Result<(c_int, i64), (ErrorLogLevel, String)> {
        use ErrorLogLevel::{Crit, Error};
        let err = |what: &str| (Error, format!("{what} failed{}", ssl_error_suffix()));
        unsafe {
            let mut p = response.as_ptr();
            let ocsp = ffi::d2i_OCSP_RESPONSE(ptr::null_mut(), &mut p, response.len() as c_long);
            if ocsp.is_null() {
                return Err(err("d2i_OCSP_RESPONSE()"));
            }
            let ocsp = Owned(ocsp, ffi::OCSP_RESPONSE_free);
            let n = ffi::OCSP_response_status(ocsp.0);
            if n != ffi::OCSP_RESPONSE_STATUS_SUCCESSFUL {
                let text = CStr::from_ptr(ffi::OCSP_response_status_str(n as c_long));
                return Err((
                    Error,
                    format!(
                        "OCSP response not successful ({n}: {})",
                        text.to_string_lossy()
                    ),
                ));
            }
            let basic = ffi::OCSP_response_get1_basic(ocsp.0);
            if basic.is_null() {
                return Err(err("OCSP_response_get1_basic()"));
            }
            let basic = Owned(basic, ffi::OCSP_BASICRESP_free);
            let chain: Vec<Cert> = self
                .chain
                .iter()
                .filter_map(|c| Cert::from_der(c))
                .collect();
            let stack = ffi::OPENSSL_sk_new_null();
            if stack.is_null() {
                return Err((Crit, "OPENSSL_sk_new_null() failed".into()));
            }
            for c in &chain {
                ffi::OPENSSL_sk_push(stack, c.0 as *mut c_void);
            }
            let flags = if self.verify {
                ffi::OCSP_TRUSTOTHER
            } else {
                ffi::OCSP_NOVERIFY
            };
            let verified = ffi::OCSP_basic_verify(
                basic.0,
                stack as *mut ffi::stack_st_X509,
                self.store.as_ptr(),
                flags as c_ulong,
            );
            // The certificates are `chain`'s, freed with it.
            ffi::OPENSSL_sk_free(stack);
            if verified != 1 {
                return Err(err("OCSP_basic_verify()"));
            }
            let (Some(leaf), Some(issuer)) =
                (Cert::from_der(&self.leaf), Cert::from_der(&self.issuer))
            else {
                return Err((Crit, "d2i_X509() failed".into()));
            };
            let id = ffi::OCSP_cert_to_id(ptr::null(), leaf.0, issuer.0);
            if id.is_null() {
                return Err((
                    Crit,
                    format!("OCSP_cert_to_id() failed{}", ssl_error_suffix()),
                ));
            }
            let id = Owned(id, ffi::OCSP_CERTID_free);
            let mut status: c_int = 0;
            let mut this_update = ptr::null_mut();
            let mut next_update = ptr::null_mut();
            if ffi::OCSP_resp_find_status(
                basic.0,
                id.0,
                &mut status,
                ptr::null_mut(),
                ptr::null_mut(),
                &mut this_update,
                &mut next_update,
            ) != 1
            {
                return Err((
                    Error,
                    "certificate status not found in the OCSP response".into(),
                ));
            }
            if ffi::OCSP_check_validity(this_update, next_update, 300, -1) != 1 {
                return Err(err("OCSP_check_validity()"));
            }
            let valid = if next_update.is_null() {
                i64::MAX
            } else {
                let mut t: i64 = 0;
                if ffi::ASN1_TIME_to_posix(next_update, &mut t) != 1 {
                    return Err((
                        Error,
                        "invalid nextUpdate time in certificate status".into(),
                    ));
                }
                t
            };
            Ok((status, valid))
        }
    }
}

/// The errors a nonblocking connect() returns itself, rather than through
/// the socket later.
fn connect_fails_at_once(e: &std::io::Error) -> bool {
    matches!(
        e.raw_os_error(),
        Some(
            libc::ENETUNREACH
                | libc::EADDRNOTAVAIL
                | libc::EACCES
                | libc::EPERM
                | libc::EAFNOSUPPORT
        )
    )
}

/// An AWS-LC object freed with its function.
struct Owned<T>(*mut T, unsafe extern "C" fn(*mut T));

impl<T> Drop for Owned<T> {
    fn drop(&mut self) {
        unsafe { (self.1)(self.0) }
    }
}

/// ` (SSL: …)` with the error queue's last error, as ngx_ssl_error
/// appends it, or nothing when the queue is empty.
fn ssl_error_suffix() -> String {
    if unsafe { ffi::ERR_peek_error() } == 0 {
        return String::new();
    }
    format!(" (SSL: {})", crate::x509_verify::ssl_error())
}

/// What an i2d_* function writes.
unsafe fn i2d(encode: impl Fn(*mut *mut u8) -> c_int) -> Option<Vec<u8>> {
    let len = encode(ptr::null_mut());
    if len <= 0 {
        return None;
    }
    let mut der = vec![0u8; len as usize];
    let mut p = der.as_mut_ptr();
    (encode(&mut p) == len).then_some(der)
}

/// ngx_ssl_stapling_file: the response, which must parse as an
/// OCSPResponse; it is stapled as it is, whatever its status.
fn read_response_file(path: &Path) -> Result<Vec<u8>, String> {
    let bytes = std::fs::read(path).map_err(|e| {
        format!(
            "BIO_new_file(\"{}\") failed ({})",
            path.display(),
            crate::worker::errno_text(&e)
        )
    })?;
    unsafe {
        let mut p = bytes.as_ptr();
        let ocsp = ffi::d2i_OCSP_RESPONSE(ptr::null_mut(), &mut p, bytes.len() as c_long);
        if ocsp.is_null() {
            return Err(format!(
                "d2i_OCSP_RESPONSE_bio(\"{}\") failed{}",
                path.display(),
                ssl_error_suffix()
            ));
        }
        // Encoded again, as nginx does: what follows the response in the
        // file isn't sent.
        let der = i2d(|out| ffi::i2d_OCSP_RESPONSE(ocsp, out));
        ffi::OCSP_RESPONSE_free(ocsp);
        ffi::ERR_clear_error();
        der.ok_or_else(|| format!("i2d_OCSP_RESPONSE(\"{}\") failed", path.display()))
    }
}

/// ngx_ssl_stapling_issuer: the certificate that issued `leaf`, among the
/// certificates that follow it, then in the store. `Ok(None)`: none.
fn find_issuer(leaf: &[u8], chain: &[Vec<u8>], store: &Store) -> Result<Option<Vec<u8>>, String> {
    let leaf_cert = Cert::from_der(leaf).ok_or("d2i_X509() failed")?;
    for der in chain {
        let Some(c) = Cert::from_der(der) else {
            continue;
        };
        if unsafe { ffi::X509_check_issued(c.0, leaf_cert.0) } == ffi::X509_V_OK as c_int {
            return Ok(Some(der.clone()));
        }
    }
    unsafe {
        let ctx = ffi::X509_STORE_CTX_new();
        if ctx.is_null() {
            return Err(format!("X509_STORE_CTX_new() failed{}", ssl_error_suffix()));
        }
        if ffi::X509_STORE_CTX_init(ctx, store.as_ptr(), ptr::null_mut(), ptr::null_mut()) != 1 {
            ffi::X509_STORE_CTX_free(ctx);
            return Err(format!(
                "X509_STORE_CTX_init() failed{}",
                ssl_error_suffix()
            ));
        }
        let mut issuer: *mut ffi::X509 = ptr::null_mut();
        let rc = ffi::X509_STORE_CTX_get1_issuer(&mut issuer, ctx, leaf_cert.0);
        ffi::X509_STORE_CTX_free(ctx);
        if rc < 0 {
            return Err(format!(
                "X509_STORE_CTX_get1_issuer() failed{}",
                ssl_error_suffix()
            ));
        }
        ffi::ERR_clear_error();
        if rc == 0 || issuer.is_null() {
            return Ok(None);
        }
        let issuer = Cert(issuer);
        Ok(i2d(|out| ffi::i2d_X509(issuer.0, out)))
    }
}

/// The first OCSP URL of the certificate's Authority Information Access.
fn responder_in(leaf: &[u8]) -> Option<String> {
    let cert = Cert::from_der(leaf)?;
    unsafe {
        let urls = ffi::X509_get1_ocsp(cert.0);
        if urls.is_null() {
            return None;
        }
        let first = ffi::OPENSSL_sk_value(urls as *const ffi::OPENSSL_STACK, 0) as *const c_char;
        let url = (!first.is_null()).then(|| CStr::from_ptr(first).to_string_lossy().into_owned());
        ffi::X509_email_free(urls);
        url
    }
}

/// ngx_ssl_stapling_responder's checks and ngx_parse_url: an `http://`
/// URL, the host resolved now, as nginx resolves it while reading its
/// configuration. `Err` is nginx's reason and the URL it names.
fn parse_responder(url: &str) -> Result<Responder, (&'static str, String)> {
    let rest = match url.get(..7) {
        Some(scheme) if url.len() > 7 && scheme.eq_ignore_ascii_case("http://") => &url[7..],
        _ => return Err(("invalid URL prefix", url.to_string())),
    };
    let fail = |err: &'static str| Err((err, rest.to_string()));
    // The URI starts at the first `/` or `?`.
    let uri_at = rest.find(['/', '?']).unwrap_or(rest.len());
    let (authority, uri) = rest.split_at(uri_at);
    let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
        let Some(end) = v6.find(']') else {
            return fail("invalid host");
        };
        let after = &v6[end + 1..];
        let port = match after.strip_prefix(':') {
            Some(p) => Some(p),
            None if after.is_empty() => None,
            None => return fail("invalid host"),
        };
        (&authority[..end + 2], port)
    } else {
        match authority.rfind(':') {
            Some(i) => (&authority[..i], Some(&authority[i + 1..])),
            None => (authority, None),
        }
    };
    let port = match port {
        Some(p) => match p.parse::<u16>() {
            Ok(n) if n >= 1 && p.bytes().all(|b| b.is_ascii_digit()) => n,
            _ => return fail("invalid port"),
        },
        None => 80,
    };
    if host.is_empty() {
        return fail("no host");
    }
    let lookup = host.trim_start_matches('[').trim_end_matches(']');
    let addrs: Vec<SocketAddr> = match (lookup, port).to_socket_addrs() {
        Ok(addrs) => addrs.collect(),
        Err(_) => return fail("host not found"),
    };
    if addrs.is_empty() {
        return fail("host not found");
    }
    Ok(Responder {
        host: host.to_string(),
        uri: if uri.is_empty() { "/" } else { uri }.to_string(),
        addrs,
    })
}

/// The status code and body of the responder's HTTP response, as
/// ngx_ssl_ocsp_process_status_line and _headers read it: a
/// `Content-Type` other than `application/ocsp-response` is refused.
fn parse_http_response(response: &[u8]) -> Result<(u16, Vec<u8>), String> {
    let invalid = || "OCSP responder sent invalid response".to_string();
    let closed = || "OCSP responder prematurely closed connection".to_string();
    let mut lines = Lines {
        rest: response,
        complete: true,
    };
    let status = lines.next().ok_or_else(closed)?;
    let code = (|| {
        let rest = status.strip_prefix(b"HTTP/")?;
        let sp = rest.iter().position(|&b| b == b' ')?;
        let (version, rest) = rest.split_at(sp);
        let (major, minor) = version.split_at(version.iter().position(|&b| b == b'.')?);
        let minor = &minor[1..];
        if major.is_empty()
            || minor.is_empty()
            || !major.iter().chain(minor).all(u8::is_ascii_digit)
        {
            return None;
        }
        let rest = rest.trim_ascii_start();
        let digits = rest.get(..3)?;
        if !digits.iter().all(u8::is_ascii_digit) || rest.get(3).is_some_and(|&b| b != b' ') {
            return None;
        }
        std::str::from_utf8(digits).ok()?.parse::<u16>().ok()
    })()
    .ok_or_else(invalid)?;
    if !lines.complete {
        return Err(closed());
    }
    loop {
        let line = lines.next().ok_or_else(closed)?;
        if !lines.complete {
            return Err(closed());
        }
        if line.is_empty() {
            break;
        }
        let colon = line.iter().position(|&b| b == b':').ok_or_else(invalid)?;
        let (name, value) = (&line[..colon], line[colon + 1..].trim_ascii());
        if name.eq_ignore_ascii_case(b"Content-Type")
            && !value.eq_ignore_ascii_case(b"application/ocsp-response")
        {
            return Err(format!(
                "OCSP responder sent invalid \"Content-Type\" header: \"{}\"",
                String::from_utf8_lossy(value)
            ));
        }
    }
    Ok((code, lines.rest.to_vec()))
}

/// The lines of a response head, CRLF or LF; `complete` is false for a
/// last line without its end.
struct Lines<'a> {
    rest: &'a [u8],
    complete: bool,
}

impl<'a> Iterator for Lines<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        if self.rest.is_empty() {
            self.complete = false;
            return None;
        }
        match self.rest.iter().position(|&b| b == b'\n') {
            Some(i) => {
                let line = &self.rest[..i];
                self.rest = &self.rest[i + 1..];
                Some(line.strip_suffix(b"\r").unwrap_or(line))
            }
            None => {
                let line = self.rest;
                self.rest = &[];
                self.complete = false;
                Some(line)
            }
        }
    }
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn responder_urls_parse_as_nginx_parses_them() {
        let r = parse_responder("http://127.0.0.1:8081").unwrap();
        assert_eq!(r.host, "127.0.0.1");
        assert_eq!(r.uri, "/");
        assert_eq!(r.addrs, vec!["127.0.0.1:8081".parse().unwrap()]);
        let r = parse_responder("HTTP://127.0.0.1/ocsp?x").unwrap();
        assert_eq!((r.host.as_str(), r.uri.as_str()), ("127.0.0.1", "/ocsp?x"));
        assert_eq!(r.addrs[0].port(), 80);
        let r = parse_responder("http://[::1]:8080/").unwrap();
        assert_eq!(r.host, "[::1]");
        assert_eq!(r.addrs, vec!["[::1]:8080".parse().unwrap()]);
        assert_eq!(
            parse_responder("https://ocsp.example.com/").err(),
            Some(("invalid URL prefix", "https://ocsp.example.com/".into()))
        );
        assert_eq!(
            parse_responder("http://127.0.0.1:0/").err(),
            Some(("invalid port", "127.0.0.1:0/".into()))
        );
        assert_eq!(
            parse_responder("http://:80/").err(),
            Some(("no host", ":80/".into()))
        );
        assert_eq!(
            parse_responder("http://").err(),
            Some(("invalid URL prefix", "http://".into()))
        );
    }

    #[test]
    fn responses_are_read_as_nginx_reads_them() {
        let ok = b"HTTP/1.1 200 OK\r\nContent-Type: application/ocsp-response\r\n\r\n\x30\x03";
        assert_eq!(parse_http_response(ok), Ok((200, b"\x30\x03".to_vec())));
        let lf = b"HTTP/1.0 404 Not Found\nServer: x\n\nbody";
        assert_eq!(parse_http_response(lf), Ok((404, b"body".to_vec())));
        let html = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n";
        assert_eq!(
            parse_http_response(html),
            Err("OCSP responder sent invalid \"Content-Type\" header: \"text/html\"".into())
        );
        assert_eq!(
            parse_http_response(b"HTTP/1.1 200 OK\r\nServer: x\r\n"),
            Err("OCSP responder prematurely closed connection".into())
        );
        assert_eq!(
            parse_http_response(b"SSH-2.0-OpenSSH\r\n\r\n"),
            Err("OCSP responder sent invalid response".into())
        );
        assert_eq!(
            parse_http_response(b""),
            Err("OCSP responder prematurely closed connection".into())
        );
    }
}
