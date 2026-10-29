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
//! - The responder's host is resolved at startup, and again for each
//!   fetch with the server's `resolver` (ngx_ssl_ocsp_request); without
//!   one, a fetch warns and uses the startup addresses. An IPv4 address
//!   is used as written.
//!
//! One `Stapling` per certificate of a server, shared by the workers. The
//! fetch runs on the worker whose handshake started it, as a task of its
//! own (`spawn_contained`), so it ends with that worker's generation and
//! logs to its error log. The handshake itself takes a lock to clone an
//! `Arc`, and only for certificates that staple.
//!
//! `ClientOcsp` checks client certificates with the same requests
//! (`ssl_ocsp`, #142).

use std::ffi::{CStr, c_char, c_int, c_long, c_ulong, c_void};
use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs};
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
    /// Stapling: the certificates after the leaf in `ssl_certificate`,
    /// nginx's extra chain certificates. A client's: its verified chain.
    /// Searched for the responder's.
    chain: Vec<Vec<u8>>,
    /// The server's trusted certificates (`ssl_trusted_certificate`, and
    /// `ssl_client_certificate` with `ssl_verify_client`).
    store: Arc<Store>,
    /// OCSP_basic_verify's.
    flags: c_ulong,
    responder: Responder,
    /// The server's `resolver` and `resolver_timeout`.
    resolver: Option<&'static crate::resolver::Resolver>,
    resolver_timeout: Duration,
    /// The certificate file, for stapling's log lines.
    name: Option<String>,
    /// A client's check logs as its connection, to its server's log.
    connection: Option<(u64, &'static [crate::worker::PreparedErrorLog])>,
}

#[derive(Clone)]
struct Responder {
    /// As written in the URL, for `Host` and log lines.
    host: String,
    uri: String,
    port: u16,
    /// As resolved at startup.
    addrs: Vec<SocketAddr>,
}

/// How a server staples: its `ssl_stapling_*` lines and the store its
/// `ssl_trusted_certificate` makes.
pub struct Settings<'a> {
    pub file: Option<&'a Path>,
    pub responder: Option<&'a str>,
    pub verify: bool,
    pub store: Arc<Store>,
    pub resolver: Option<&'static crate::resolver::Resolver>,
    pub resolver_timeout: Duration,
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
        let responder = match parse_responder(&url, true) {
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
                flags: if settings.verify {
                    ffi::OCSP_TRUSTOTHER
                } else {
                    ffi::OCSP_NOVERIFY
                } as c_ulong,
                responder,
                resolver: settings.resolver,
                resolver_timeout: settings.resolver_timeout,
                name: Some(name),
                connection: None,
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
        let (mut line, logs) = match self.connection {
            Some((id, logs)) => (format!("*{id} "), logs),
            None => (
                String::new(),
                crate::worker::worker_http().map_or(&[][..], |h| h.error_logs),
            ),
        };
        line.push_str(&format!(
            "{message} while requesting certificate status, responder: {}",
            self.responder.host
        ));
        if let Some(peer) = peer {
            line.push_str(&format!(", peer: {peer}"));
        }
        if let Some(name) = &self.name {
            line.push_str(&format!(", certificate: \"{name}\""));
        }
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
        let addrs = self.responder_addrs().await?;
        for addr in addrs {
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

    /// Where this fetch connects (ngx_ssl_ocsp_request): an IPv4 address
    /// as written (ngx_resolve_start's quick path), else what the
    /// server's `resolver` answers now, else the startup addresses, with
    /// a warning. `None` after logging why the name gave none, as for a
    /// name from a client's certificate without a `resolver`.
    async fn responder_addrs(&self) -> Option<Vec<SocketAddr>> {
        let host = &self.responder.host;
        if let Ok(ip) = host.parse::<Ipv4Addr>() {
            return Some(vec![SocketAddr::new(ip.into(), self.responder.port)]);
        }
        let Some(resolver) = self.resolver else {
            let line = format!("no resolver defined to resolve {host}");
            if self.responder.addrs.is_empty() {
                self.log(ErrorLogLevel::Error, &line, None);
                return None;
            }
            self.log(ErrorLogLevel::Warn, &line, None);
            return Some(self.responder.addrs.clone());
        };
        match crate::resolver::resolve(resolver, host.as_bytes(), self.resolver_timeout).await {
            Ok(ips) => Some(
                ips.into_iter()
                    .map(|ip| SocketAddr::new(ip, self.responder.port))
                    .collect(),
            ),
            Err(failure) => {
                let line = format!("{host} could not be resolved ({failure})");
                self.log(ErrorLogLevel::Error, &line, None);
                None
            }
        }
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
        let (status, valid) = self.verified(response, peer)?;
        if status == ffi::V_OCSP_CERTSTATUS_GOOD {
            return Some(valid);
        }
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

    /// ngx_ssl_ocsp_verify: the status and the time the response is valid
    /// until, or `None` after logging why it doesn't verify.
    fn verified(&self, response: &[u8], peer: SocketAddr) -> Option<(c_int, i64)> {
        let result = unsafe { self.verify(response) };
        unsafe { ffi::ERR_clear_error() };
        match result {
            Ok(found) => Some(found),
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
            let verified = ffi::OCSP_basic_verify(
                basic.0,
                stack as *mut ffi::stack_st_X509,
                self.store.as_ptr(),
                self.flags,
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

/// `ssl_ocsp` for one client-certificate context (#142), as
/// ngx_ssl_ocsp_validate checks: after the handshake, the certificates of
/// the verified chain, leaf first, each but the last (`leaf`: the leaf
/// only), with the responder of `ssl_ocsp_responder` or of the
/// certificate's AIA, until one isn't `good`. Any failure is
/// `certificate status request failed`; nothing admits a client whose
/// status wasn't read.
pub struct ClientOcsp {
    leaf_only: bool,
    /// `ssl_ocsp_responder`, resolved at startup.
    responder: Option<Responder>,
    /// The server's trusted certificates, without its verify depth, as
    /// for stapling (the SSL_CTX's store).
    store: Arc<Store>,
    resolver: Option<&'static crate::resolver::Resolver>,
    resolver_timeout: Duration,
    cache: Option<Arc<Cache>>,
}

impl std::fmt::Debug for ClientOcsp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientOcsp")
            .field("leaf_only", &self.leaf_only)
            .field("responder", &self.responder.as_ref().map(|r| &r.host))
            .finish_non_exhaustive()
    }
}

/// A server's `ssl_ocsp*` lines, read.
pub struct ClientSettings<'a> {
    pub leaf_only: bool,
    pub responder: Option<&'a str>,
    pub store: Arc<Store>,
    pub resolver: Option<&'static crate::resolver::Resolver>,
    pub resolver_timeout: Duration,
    /// `ssl_ocsp_cache shared:NAME:SIZE`.
    pub cache: Option<(&'a str, u64)>,
}

/// Where a client's check logs what isn't about the responder: its
/// connection, as nginx's connection log does during the handshake.
pub struct ConnLog {
    pub id: u64,
    pub logs: &'static [crate::worker::PreparedErrorLog],
    /// ` while SSL handshaking, client: …, server: …`.
    pub context: String,
}

impl ConnLog {
    fn error(&self, message: &str) {
        let line = format!("*{} {message}{}", self.id, self.context);
        crate::worker::write_worker_log(self.logs, ErrorLogLevel::Error, &line);
    }
}

/// What makes `$ssl_client_verify` `FAILED:…` (ngx_ssl_ocsp_get_status).
pub const REQUEST_FAILED: &str = "certificate status request failed";

impl ClientOcsp {
    /// ngx_ssl_ocsp: `Err` is the `[emerg]`.
    pub fn new(settings: ClientSettings<'_>) -> Result<ClientOcsp, String> {
        let responder = match settings.responder {
            Some(url) => Some(parse_responder(url, true).map_err(|(err, url)| {
                format!("{err} in OCSP responder \"{url}\" in \"ssl_ocsp_responder\"")
            })?),
            None => None,
        };
        Ok(ClientOcsp {
            leaf_only: settings.leaf_only,
            responder,
            store: settings.store,
            resolver: settings.resolver,
            resolver_timeout: settings.resolver_timeout,
            cache: settings.cache.map(|(name, size)| Cache::zone(name, size)),
        })
    }

    /// The status of a client's verified `chain` (leaf to trust anchor):
    /// `Ok` when every certificate checked is `good`, else what
    /// `$ssl_client_verify` says after `FAILED:`.
    pub async fn validate(&self, chain: &[Vec<u8>], log: &ConnLog) -> Result<(), &'static str> {
        let last = chain.len().saturating_sub(1);
        let checked = if self.leaf_only { last.min(1) } else { last };
        for i in 0..checked {
            let status = self.status(&chain[i], &chain[i + 1], chain, log).await?;
            match status {
                ffi::V_OCSP_CERTSTATUS_GOOD => {}
                ffi::V_OCSP_CERTSTATUS_REVOKED => return Err("certificate revoked"),
                _ => return Err("certificate status unknown"),
            }
        }
        Ok(())
    }

    /// One certificate's status, from the cache or its responder
    /// (ngx_ssl_ocsp_validate_next and ngx_ssl_ocsp_handler).
    async fn status(
        &self,
        cert: &[u8],
        issuer: &[u8],
        chain: &[Vec<u8>],
        log: &ConnLog,
    ) -> Result<c_int, &'static str> {
        let responder = match &self.responder {
            Some(r) => r.clone(),
            None => responder_of(cert, log).ok_or(REQUEST_FAILED)?,
        };
        let key = match &self.cache {
            Some(cache) => {
                let key = cache_key(cert, issuer).ok_or(REQUEST_FAILED)?;
                if let Some(status) = cache.lookup(&key) {
                    return Ok(status);
                }
                Some((cache, key))
            }
            None => None,
        };
        let fetch = Fetch {
            leaf: cert.to_vec(),
            issuer: issuer.to_vec(),
            chain: chain.to_vec(),
            store: self.store.clone(),
            flags: 0,
            responder,
            resolver: self.resolver,
            resolver_timeout: self.resolver_timeout,
            name: None,
            connection: Some((log.id, log.logs)),
        };
        let (peer, response) = fetch.request().await.ok_or(REQUEST_FAILED)?;
        let (status, valid) = fetch.verified(&response, peer).ok_or(REQUEST_FAILED)?;
        if let Some((cache, key)) = key {
            cache.store(key, status, valid);
        }
        Ok(status)
    }
}

/// ngx_ssl_ocsp_responder for a certificate without `ssl_ocsp_responder`:
/// the first OCSP URL of its AIA, not resolved yet.
fn responder_of(cert: &[u8], log: &ConnLog) -> Option<Responder> {
    let Some(url) = responder_in(cert) else {
        log.error("no OCSP responder URL in certificate");
        return None;
    };
    match parse_responder(&url, false) {
        Ok(r) => Some(r),
        Err(("invalid URL prefix", url)) => {
            log.error(&format!(
                "invalid URL prefix in OCSP responder \"{url}\" in certificate"
            ));
            None
        }
        Err(("no host", _)) => {
            log.error("empty host in OCSP responder in certificate");
            None
        }
        Err((err, url)) => {
            log.error(&format!("{err} in OCSP responder \"{url}\" in certificate"));
            None
        }
    }
}

/// ngx_ssl_ocsp_create_key: SHA-1 of the issuer's name and of its key,
/// and the certificate's serial, zero-padded to 20 bytes.
fn cache_key(cert: &[u8], issuer: &[u8]) -> Option<[u8; 60]> {
    let (cert, issuer) = (Cert::from_der(cert)?, Cert::from_der(issuer)?);
    let mut key = [0u8; 60];
    unsafe {
        let name = ffi::X509_get_subject_name(issuer.0);
        let mut len = 0;
        if ffi::X509_NAME_digest(name, ffi::EVP_sha1(), key.as_mut_ptr(), &mut len) != 1
            || len != 20
            || ffi::X509_pubkey_digest(issuer.0, ffi::EVP_sha1(), key[20..].as_mut_ptr(), &mut len)
                != 1
            || len != 20
        {
            ffi::ERR_clear_error();
            return None;
        }
        let serial = ffi::X509_get_serialNumber(cert.0);
        let n = ffi::ASN1_STRING_length(serial);
        if !(0..=20).contains(&n) {
            return None;
        }
        let data = ffi::ASN1_STRING_get0_data(serial);
        if n > 0 {
            ptr::copy_nonoverlapping(data, key[40..].as_mut_ptr(), n as usize);
        }
    }
    Some(key)
}

/// An `ssl_ocsp_cache` zone: statuses by certificate until their
/// nextUpdate, shared by the workers and the servers that name it. When
/// full, the oldest entry goes, as nginx's zone frees its oldest node.
pub struct Cache {
    entries: Mutex<CacheEntries>,
    /// About what nginx's zone of that size holds: a node takes a 256-byte
    /// slab chunk.
    limit: usize,
}

#[derive(Default)]
struct CacheEntries {
    by_key: std::collections::HashMap<[u8; 60], (c_int, i64)>,
    /// Keys in the order they were stored, oldest first.
    order: std::collections::VecDeque<[u8; 60]>,
}

/// The zones of every configuration loaded, by name and size: a reload
/// that keeps a zone keeps its entries, as nginx keeps a shared zone.
static ZONES: Mutex<Vec<(String, u64, Arc<Cache>)>> = Mutex::new(Vec::new());

impl Cache {
    fn zone(name: &str, size: u64) -> Arc<Cache> {
        let mut zones = ZONES.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((_, _, cache)) = zones.iter().find(|(n, s, _)| n == name && *s == size) {
            return cache.clone();
        }
        let cache = Arc::new(Cache {
            entries: Mutex::default(),
            limit: (size / 256).max(1) as usize,
        });
        zones.push((name.to_string(), size, cache.clone()));
        cache
    }

    /// ngx_ssl_ocsp_cache_lookup: an expired entry goes.
    fn lookup(&self, key: &[u8; 60]) -> Option<c_int> {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let (status, valid) = *entries.by_key.get(key)?;
        if valid > unix_now() {
            return Some(status);
        }
        entries.by_key.remove(key);
        entries.order.retain(|k| k != key);
        None
    }

    /// ngx_ssl_ocsp_cache_store: a response without nextUpdate for an
    /// hour, an expired one not at all.
    fn store(&self, key: [u8; 60], status: c_int, valid: i64) {
        let now = unix_now();
        if valid < now {
            return;
        }
        let valid = if valid == i64::MAX { now + 3600 } else { valid };
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        if entries.by_key.insert(key, (status, valid)).is_some() {
            entries.order.retain(|k| *k != key);
        }
        entries.order.push_back(key);
        while entries.order.len() > self.limit {
            if let Some(old) = entries.order.pop_front() {
                entries.by_key.remove(&old);
            }
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
    crate::privileges::note_read(path);
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
/// URL, the host resolved now with `resolve`, as nginx resolves it while
/// reading its configuration; else only an address as written is one
/// (`no_resolve`). `Err` is nginx's reason and the URL it names.
fn parse_responder(url: &str, resolve: bool) -> Result<Responder, (&'static str, String)> {
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
    if !resolve {
        let addrs = lookup
            .parse::<std::net::IpAddr>()
            .map(|ip| vec![SocketAddr::new(ip, port)])
            .unwrap_or_default();
        return Ok(Responder {
            host: host.to_string(),
            uri: if uri.is_empty() { "/" } else { uri }.to_string(),
            port,
            addrs,
        });
    }
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
        port,
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
        let r = parse_responder("http://127.0.0.1:8081", true).unwrap();
        assert_eq!(r.host, "127.0.0.1");
        assert_eq!(r.uri, "/");
        assert_eq!(r.addrs, vec!["127.0.0.1:8081".parse().unwrap()]);
        let r = parse_responder("HTTP://127.0.0.1/ocsp?x", true).unwrap();
        assert_eq!((r.host.as_str(), r.uri.as_str()), ("127.0.0.1", "/ocsp?x"));
        assert_eq!(r.addrs[0].port(), 80);
        let r = parse_responder("http://[::1]:8080/", true).unwrap();
        assert_eq!(r.host, "[::1]");
        assert_eq!(r.addrs, vec!["[::1]:8080".parse().unwrap()]);
        assert_eq!(
            parse_responder("https://ocsp.example.com/", true).err(),
            Some(("invalid URL prefix", "https://ocsp.example.com/".into()))
        );
        assert_eq!(
            parse_responder("http://127.0.0.1:0/", true).err(),
            Some(("invalid port", "127.0.0.1:0/".into()))
        );
        assert_eq!(
            parse_responder("http://:80/", true).err(),
            Some(("no host", ":80/".into()))
        );
        assert_eq!(
            parse_responder("http://", true).err(),
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
