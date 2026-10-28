//! TLS to upstreams, `proxy_pass https://` (#116), as nginx's
//! ngx_http_upstream_ssl_init_connection with its defaults: no SNI unless
//! `proxy_ssl_server_name on`, session reuse on, and the certificate not
//! verified unless `proxy_ssl_verify on` (#117, `x509_verify`).

use std::sync::{Arc, Mutex, Weak};

use std::path::Path;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::sign::CertifiedKey;
use rustls::{CertificateError, ClientConfig, DigitallySignedStruct, SignatureScheme};

use crate::config::TlsVersionSet;
use crate::worker::PreparedValuePart;

/// A location's TLS to its upstream, prepared once.
#[derive(Debug)]
pub struct PreparedUpstreamTls {
    pub config: Arc<ClientConfig>,
    /// `proxy_ssl_name` with variables, rendered per request.
    pub name_vars: Option<&'static [PreparedValuePart]>,
    /// The name otherwise: `proxy_ssl_name`, or the host of `proxy_pass`.
    pub name: ServerName<'static>,
    /// No `proxy_ssl_name`: for a URL with variables, the rendered host.
    pub default_name: bool,
    /// `proxy_ssl_certificate` with variables: `config` has no
    /// certificate, and this picks the request's.
    pub dynamic_cert: Option<DynamicCert>,
}

/// `proxy_ssl_certificate` with variables (#434): the pair is rendered
/// per request, as ngx_http_upstream_ssl_certificate does per connection.
/// Its files are read each time, or taken from `proxy_ssl_certificate_cache`
/// (#601); a pair whose content was seen gets the client config it had,
/// so its sessions too.
#[derive(Debug)]
pub struct DynamicCert {
    pub(crate) cert: crate::worker::PreparedCertPath,
    pub(crate) key: crate::worker::PreparedCertPath,
    passwords: Arc<[Vec<u8>]>,
    protocols: TlsVersionSet,
    sni: bool,
    reuse: bool,
    verify: Option<Arc<crate::x509_verify::Store>>,
    /// `None`: `proxy_ssl_certificate_cache off`, nginx's default.
    cache: Option<Arc<Mutex<ObjectCache>>>,
    /// The configs handed out last, most recent first: `certified_pair`
    /// and `client_config` find theirs only while they are alive.
    recent: Mutex<Vec<Arc<ClientConfig>>>,
}

/// Configs kept alive per location.
const DYNAMIC_CONFIGS: usize = 64;

impl DynamicCert {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        cert: crate::worker::PreparedCertPath,
        key: crate::worker::PreparedCertPath,
        passwords: Arc<[Vec<u8>]>,
        protocols: TlsVersionSet,
        sni: bool,
        reuse: bool,
        verify: Option<Arc<crate::x509_verify::Store>>,
        cache: Option<crate::config::SslCertificateCache>,
    ) -> Self {
        Self {
            cert,
            key,
            passwords,
            protocols,
            sni,
            reuse,
            verify,
            cache: cache.map(ObjectCache::shared),
            recent: Mutex::new(Vec::new()),
        }
    }

    /// The config for the rendered pair: `None` for an empty certificate
    /// (the location's config, without one), else the pair's; `Err` is
    /// the error log's line, and the request fails with a 500, as nginx's
    /// does.
    #[cold]
    pub fn config(&self, cert: &[u8], key: &[u8]) -> Result<Option<Arc<ClientConfig>>, String> {
        if cert.is_empty() {
            return Ok(None);
        }
        let path = |rendered: &[u8], at: &crate::worker::PreparedCertPath| {
            use std::os::unix::ffi::OsStrExt;
            let path = Path::new(std::ffi::OsStr::from_bytes(rendered));
            match at {
                crate::worker::PreparedCertPath::Vars {
                    prefix: Some(prefix),
                    ..
                } if path.is_relative() => prefix.join(path),
                _ => path.to_path_buf(),
            }
        };
        let (cert_path, key_path) = (path(cert, &self.cert), path(key, &self.key));
        let certified = self.certified(&cert_path, &key_path)?;
        let config = client_config(
            self.protocols,
            self.sni,
            self.reuse,
            self.verify.clone(),
            Some(certified),
        )?;
        let mut recent = self.recent.lock().unwrap_or_else(|e| e.into_inner());
        match recent.iter().position(|c| Arc::ptr_eq(c, &config)) {
            Some(i) => {
                recent.remove(i);
            }
            None => recent.truncate(DYNAMIC_CONFIGS - 1),
        }
        recent.insert(0, config.clone());
        Ok(Some(config))
    }

    /// As ngx_ssl_connection_certificate: a key that isn't the
    /// certificate's (one file replaced before the other, say) has both
    /// fetched again past the cache's `valid`.
    fn certified(&self, cert: &Path, key: &Path) -> Result<Arc<CertifiedKey>, String> {
        use crate::tls_certs::LoadCertError;
        let mut invalidate = false;
        loop {
            let chain = self.fetch(Object::CERT, cert, invalidate)?;
            let pkey = self.fetch(Object::KEY, key, invalidate)?;
            let (Object::Chain(chain), Object::Key(pkey)) = (chain, pkey) else {
                unreachable!("fetched by kind");
            };
            match certified_pair(&chain, &pkey) {
                Ok(certified) => return Ok(certified),
                Err(LoadCertError::Rustls(rustls::Error::InconsistentKeys(
                    rustls::InconsistentKeys::KeyMismatch,
                ))) if !invalidate => invalidate = true,
                Err(e) => {
                    return Err(format!(
                        "SSL_use_PrivateKey(\"{}\") failed ({e})",
                        key.display()
                    ));
                }
            }
        }
    }

    fn fetch(&self, kind: u8, path: &Path, invalidate: bool) -> Result<Object, String> {
        let load = || Object::load(kind, path, &self.passwords);
        match &self.cache {
            None => load().map(|(object, _)| object),
            Some(cache) => cache.lock().unwrap_or_else(|e| e.into_inner()).fetch(
                kind,
                path,
                invalidate,
                std::time::Instant::now(),
                load,
            ),
        }
    }
}

/// A certificate chain or a key, as read from its file.
#[derive(Debug, Clone)]
enum Object {
    Chain(Arc<Vec<CertificateDer<'static>>>),
    Key(Arc<rustls::pki_types::PrivateKeyDer<'static>>),
}

impl Object {
    const CERT: u8 = 0;
    const KEY: u8 = 1;

    /// The object and whether it may be cached: an encrypted key isn't, as
    /// in nginx. `Err` is nginx's error line.
    fn load(kind: u8, path: &Path, passwords: &[Vec<u8>]) -> Result<(Object, bool), String> {
        let (what, call) = if kind == Self::CERT {
            ("certificate", "PEM_read_bio_X509_AUX")
        } else {
            ("certificate key", "PEM_read_bio_PrivateKey")
        };
        let fail =
            |e: &dyn std::fmt::Display| format!("cannot load {what} \"{}\": {e}", path.display());
        let pem = std::fs::read(path).map_err(|e| {
            fail(&format_args!(
                "BIO_new_file() failed ({})",
                crate::worker::errno_text(&e)
            ))
        })?;
        if kind == Self::CERT {
            let chain = crate::tls_certs::parse_cert_chain(&pem, path)
                .map_err(|e| fail(&format_args!("{call}() failed ({e})")))?;
            return Ok((Object::Chain(Arc::new(chain)), true));
        }
        let key = crate::tls_certs::parse_private_key(&pem, path, passwords)
            .map_err(|e| fail(&format_args!("{call}() failed ({e})")))?;
        let cacheable = !crate::x509_verify::is_encrypted_key(&pem);
        Ok((Object::Key(Arc::new(key)), cacheable))
    }
}

/// The pair as a `CertifiedKey`, one per content (weak, as `KEYS` in
/// `certificate_pair`), so that `client_config` finds its config again.
fn certified_pair(
    chain: &[CertificateDer<'static>],
    key: &rustls::pki_types::PrivateKeyDer<'static>,
) -> Result<Arc<CertifiedKey>, crate::tls_certs::LoadCertError> {
    type Key = (Vec<Vec<u8>>, Vec<u8>);
    static PAIRS: Mutex<Vec<(Key, Weak<CertifiedKey>)>> = Mutex::new(Vec::new());
    let k: Key = (
        chain.iter().map(|c| c.to_vec()).collect(),
        key.secret_der().to_vec(),
    );
    let mut pairs = PAIRS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(certified) = pairs
        .iter()
        .find_map(|(known, certified)| (*known == k).then(|| certified.upgrade()).flatten())
    {
        return Ok(certified);
    }
    let certified = Arc::new(crate::tls_certs::certified_key(
        chain.to_vec(),
        key.clone_key(),
    )?);
    pairs.retain(|(_, certified)| certified.strong_count() > 0);
    pairs.push((k, Arc::downgrade(&certified)));
    Ok(certified)
}

/// `proxy_ssl_certificate_cache` (#601): certificates and keys by file,
/// as nginx's ngx_ssl_cache_connection_fetch keeps them. At most `max`,
/// the least recently used going first; one unused for `inactive` goes
/// when another comes in; one older than `valid` is read again if its
/// file changed (inode or mtime) or is gone. Whole seconds, as nginx's
/// `ngx_time()`. One per declaration, shared by the locations that inherit
/// it and, unlike nginx's per process, by the worker threads.
#[derive(Debug)]
pub(crate) struct ObjectCache {
    max: usize,
    inactive: u64,
    valid: u64,
    /// The least recently used first.
    entries: Vec<CacheEntry>,
}

#[derive(Debug)]
struct CacheEntry {
    kind: u8,
    path: std::path::PathBuf,
    object: Object,
    /// Inode and mtime when read; `None` when the stat failed.
    file: Option<(u64, i64)>,
    created: std::time::Instant,
    accessed: std::time::Instant,
}

fn file_id(path: &Path) -> Option<(u64, i64)> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).ok().map(|m| (m.ino(), m.mtime()))
}

impl ObjectCache {
    /// The cache of the declaration `settings.id`; weak, as the stores
    /// above, so a reload's configuration starts with its own.
    fn shared(settings: crate::config::SslCertificateCache) -> Arc<Mutex<ObjectCache>> {
        type Shared = Arc<Mutex<ObjectCache>>;
        static CACHES: Mutex<Vec<(u64, Weak<Mutex<ObjectCache>>)>> = Mutex::new(Vec::new());
        let mut caches = CACHES.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(cache) = caches
            .iter()
            .find_map(|(id, cache)| (*id == settings.id).then(|| cache.upgrade()).flatten())
        {
            return cache;
        }
        let cache: Shared = Arc::new(Mutex::new(ObjectCache {
            max: settings.max,
            inactive: settings.inactive_secs,
            valid: settings.valid_secs,
            entries: Vec::new(),
        }));
        caches.retain(|(_, cache)| cache.strong_count() > 0);
        caches.push((settings.id, Arc::downgrade(&cache)));
        cache
    }

    fn fetch(
        &mut self,
        kind: u8,
        path: &Path,
        invalidate: bool,
        now: std::time::Instant,
        load: impl FnOnce() -> Result<(Object, bool), String>,
    ) -> Result<Object, String> {
        let secs = |since: std::time::Instant| now.duration_since(since).as_secs();
        if let Some(i) = self
            .entries
            .iter()
            .position(|e| e.kind == kind && e.path == path)
        {
            // Out while it is looked at; an object that fails to load or
            // can't be cached any more stays out.
            let mut entry = self.entries.remove(i);
            if invalidate || secs(entry.created) > self.valid {
                let file = file_id(path);
                if invalidate || file.is_none() || file != entry.file {
                    let (object, cacheable) = load()?;
                    if !cacheable {
                        return Ok(object);
                    }
                    entry.object = object;
                    entry.file = file;
                }
                entry.created = now;
            }
            entry.accessed = now;
            let object = entry.object.clone();
            self.entries.push(entry);
            return Ok(object);
        }
        let (object, cacheable) = load()?;
        if !cacheable {
            return Ok(object);
        }
        let file = file_id(path);
        self.expire(1, now);
        if self.entries.len() >= self.max {
            self.expire(0, now);
        }
        self.entries.push(CacheEntry {
            kind,
            path: path.to_path_buf(),
            object: object.clone(),
            file,
            created: now,
            accessed: now,
        });
        Ok(object)
    }

    /// ngx_ssl_cache_expire: from `n = 0` the least recently used goes
    /// whatever its age; then up to two more unused for `inactive`.
    fn expire(&mut self, mut n: u32, now: std::time::Instant) {
        while n < 3 {
            let Some(oldest) = self.entries.first() else {
                return;
            };
            if n != 0 && now.duration_since(oldest.accessed).as_secs() <= self.inactive {
                return;
            }
            n += 1;
            self.entries.remove(0);
        }
    }
}

/// What one proxied request connects with.
#[derive(Debug)]
pub struct TlsPlan {
    pub config: Arc<ClientConfig>,
    pub name: ServerName<'static>,
}

/// Who a pooled TLS connection was opened as: its client config (one per
/// combination of `proxy_ssl_*` settings) and the name it sent and was
/// verified against.
pub type TlsIdentity = (usize, ServerName<'static>);

impl TlsPlan {
    pub fn config_id(&self) -> usize {
        Arc::as_ptr(&self.config) as usize
    }

    /// A clone of a prepared name borrows (`leak_name`), so this costs no
    /// allocation unless the name was rendered for the request.
    pub fn identity(&self) -> TlsIdentity {
        (self.config_id(), self.name.clone())
    }
}

/// `name` borrowing a leaked copy of itself, so that clones of a name
/// prepared once (one per pooled connection) don't allocate.
pub fn leak_name(name: ServerName<'static>) -> ServerName<'static> {
    match name {
        ServerName::DnsName(dns) => {
            let text: &'static str = crate::arena::leak(dns.as_ref().to_string().into_boxed_str());
            rustls::pki_types::DnsName::try_from(text)
                .map_or(ServerName::DnsName(dns), ServerName::DnsName)
        }
        other => other,
    }
}

/// The name for the ClientHello and the session cache: `host` without a
/// port or IPv6 brackets. A host rustls can't take as a DNS name (an
/// upstream group named `my_backend`, say) becomes an unspecified address:
/// with SNI on nginx would send it, the session cache still keys on it,
/// and with `proxy_ssl_verify on` no certificate matches it.
pub fn server_name(host: &[u8]) -> ServerName<'static> {
    let host = std::str::from_utf8(host).unwrap_or("");
    let host = match host.strip_prefix('[') {
        Some(rest) => rest.split(']').next().unwrap_or(rest),
        None => host.rsplit_once(':').map_or(host, |(h, port)| {
            if port.bytes().all(|b| b.is_ascii_digit()) {
                h
            } else {
                host
            }
        }),
    };
    ServerName::try_from(host.to_string()).unwrap_or(ServerName::IpAddress(
        std::net::Ipv4Addr::UNSPECIFIED.into(),
    ))
}

/// `proxy_ssl_verify on`: what certificates are checked against.
#[derive(Debug, Clone, Copy)]
pub struct VerifySettings {
    pub trusted: &'static Path,
    pub depth: u32,
    pub crl: Option<&'static Path>,
}

/// The trust store for `settings`, loaded once per content of its files:
/// locations with the same files share it, and a reload that finds them
/// changed loads them again. `Err` is nginx's `[emerg]` text.
pub fn trust_store(settings: VerifySettings) -> Result<Arc<crate::x509_verify::Store>, String> {
    type Key = (Vec<u8>, Option<Vec<u8>>, u32);
    // Weak (#500): the prepared configurations own the stores, through
    // their client configs, and a retired one's go with it (#343).
    static STORES: Mutex<Vec<(Key, Weak<crate::x509_verify::Store>)>> = Mutex::new(Vec::new());
    let read = |path: &Path, call: &str| {
        crate::tls_certs::pem_file(path)
            .map(|b| b.to_vec())
            .map_err(|e| {
                format!(
                    "{call}(\"{}\") failed ({})",
                    path.display(),
                    crate::worker::errno_text(&e)
                )
            })
    };
    let trusted = read(settings.trusted, "SSL_CTX_load_verify_locations")?;
    let crl = settings
        .crl
        .map(|path| read(path, "X509_LOOKUP_load_file"))
        .transpose()?;
    let key = (trusted, crl, settings.depth);
    let mut stores = STORES.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(store) = stores
        .iter()
        .find_map(|(k, store)| (*k == key).then(|| store.upgrade()).flatten())
    {
        return Ok(store);
    }
    let mut store = crate::x509_verify::Store::new(&key.0, key.2).map_err(|e| {
        format!(
            "SSL_CTX_load_verify_locations(\"{}\") failed (SSL: {e})",
            settings.trusted.display()
        )
    })?;
    if let (Some(path), Some(pem)) = (settings.crl, &key.1) {
        store.add_crl(pem).map_err(|e| {
            format!(
                "X509_LOOKUP_load_file(\"{}\") failed (SSL: {e})",
                path.display()
            )
        })?;
    }
    let store = Arc::new(store);
    stores.retain(|(_, store)| store.strong_count() > 0);
    stores.push((key, Arc::downgrade(&store)));
    Ok(store)
}

/// `proxy_ssl_certificate` and its key (#138), loaded once per content of
/// the files, as the trust stores are. `Err` is the `[emerg]` text.
/// At load: the files are read once per load (`pem_file`); a request's
/// pair (`DynamicCert`) reads them itself.
/// An encrypted key opens with `passwords` (`proxy_ssl_password_file`).
pub fn client_certificate(
    cert: &Path,
    key: &Path,
    passwords: &[Vec<u8>],
) -> Result<Arc<CertifiedKey>, String> {
    certificate_pair(cert, key, passwords, |path| {
        crate::tls_certs::pem_file(path).map(|b| b.to_vec())
    })
}

fn certificate_pair(
    cert: &Path,
    key: &Path,
    passwords: &[Vec<u8>],
    read_file: impl Fn(&Path) -> std::io::Result<Vec<u8>>,
) -> Result<Arc<CertifiedKey>, String> {
    type Key = (Vec<u8>, Vec<u8>);
    // Weak, as the trust stores (#500).
    static KEYS: Mutex<Vec<(Key, Weak<CertifiedKey>)>> = Mutex::new(Vec::new());
    let fail = |e: &dyn std::fmt::Display| {
        format!(
            "cannot load certificate \"{}\" with key \"{}\": {e}",
            cert.display(),
            key.display()
        )
    };
    let read = |path: &Path| {
        read_file(path).map_err(|e| {
            fail(&format_args!(
                "reading {}: {}",
                path.display(),
                crate::worker::errno_text(&e)
            ))
        })
    };
    let k = (read(cert)?, read(key)?);
    let mut keys = KEYS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(certified) = keys
        .iter()
        .find_map(|(known, certified)| (*known == k).then(|| certified.upgrade()).flatten())
    {
        return Ok(certified);
    }
    let certified = crate::tls_certs::parse_certified_key(&k.0, &k.1, cert, key, passwords)
        .map_err(|e| fail(&e))?;
    let certified = Arc::new(certified);
    keys.retain(|(_, certified)| certified.strong_count() > 0);
    keys.push((k, Arc::downgrade(&certified)));
    Ok(certified)
}

/// The client config for this combination of settings, shared by every
/// location that has it, so they share the session cache too. `verify` is
/// the trust store of `proxy_ssl_verify on`, `client_cert` the
/// certificate of `proxy_ssl_certificate`: a session or a pooled
/// connection (keyed by this config) never crosses either.
pub fn client_config(
    protocols: TlsVersionSet,
    sni: bool,
    reuse: bool,
    verify: Option<Arc<crate::x509_verify::Store>>,
    client_cert: Option<Arc<CertifiedKey>>,
) -> Result<Arc<ClientConfig>, String> {
    // The store and the pair by address: an entry is used only while its
    // config is alive, which holds them, so an address can't be another's.
    // Weak, as the stores and pairs (#500).
    type Key = (bool, bool, bool, bool, usize, usize);
    static CONFIGS: Mutex<Vec<(Key, Weak<ClientConfig>)>> = Mutex::new(Vec::new());
    fn addr<T>(arc: &Option<Arc<T>>) -> usize {
        arc.as_ref().map_or(0, |a| Arc::as_ptr(a) as usize)
    }
    let wanted: Key = (
        protocols.tlsv1_2,
        protocols.tlsv1_3,
        sni,
        reuse,
        addr(&verify),
        addr(&client_cert),
    );
    let key = (verify, client_cert);
    let mut configs = CONFIGS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(config) = configs
        .iter()
        .find_map(|(k, config)| (*k == wanted).then(|| config.upgrade()).flatten())
    {
        return Ok(config);
    }
    let provider = crate::tls_certs::active_provider();
    let mut versions: Vec<&'static rustls::SupportedProtocolVersion> = Vec::new();
    if protocols.tlsv1_3 {
        versions.push(&rustls::version::TLS13);
    }
    if protocols.tlsv1_2 {
        versions.push(&rustls::version::TLS12);
    }
    let verifier: Arc<dyn ServerCertVerifier> = match &key.0 {
        Some(store) => Arc::new(Verification {
            store: store.clone(),
            provider: provider.clone(),
        }),
        None => Arc::new(NoVerification(provider.clone())),
    };
    let builder = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&versions)
        .map_err(|e| format!("proxy_ssl_protocols: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(verifier);
    // Sent when the server asks for one (a CertificateRequest), as OpenSSL
    // sends it.
    let mut config = match &key.1 {
        Some(certified) => {
            builder.with_client_cert_resolver(Arc::new(ClientCert(certified.clone())))
        }
        None => builder.with_no_client_auth(),
    };
    config.enable_sni = sni;
    // No certificate compression either way, as nginx's contexts (#601).
    config.cert_compressors = Vec::new();
    config.cert_decompressors = Vec::new();
    if !reuse {
        config.resumption = rustls::client::Resumption::disabled();
    }
    let config = Arc::new(config);
    configs.retain(|(_, config)| config.strong_count() > 0);
    configs.push((wanted, Arc::downgrade(&config)));
    Ok(config)
}

/// `proxy_ssl_certificate`: the one certificate, whatever the server asks.
#[derive(Debug)]
struct ClientCert(Arc<CertifiedKey>);

impl rustls::client::ResolvesClientCert for ClientCert {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }

    fn has_certs(&self) -> bool {
        true
    }
}

/// `proxy_ssl_verify off`: any certificate is taken, as nginx takes it,
/// and its handshake signature with it. Checking that signature against a
/// certificate nobody verified adds nothing (whoever is in the middle
/// signs with a key of their own), and webpki would refuse to parse what
/// OpenSSL takes, such as the X.509 v1 certificates of nginx-tests.
#[derive(Debug)]
struct NoVerification(Arc<CryptoProvider>);

impl ServerCertVerifier for NoVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// `proxy_ssl_verify on`: the chain and the name checked as nginx's
/// OpenSSL checks them (`x509_verify`), and the handshake signed with the
/// key of the certificate that passed.
#[derive(Debug)]
struct Verification {
    store: Arc<crate::x509_verify::Store>,
    provider: Arc<CryptoProvider>,
}

/// A refusal rustls carries to the handshake's caller, which logs it in
/// nginx's words (`verify_failure`).
fn refused(failure: crate::x509_verify::Failure) -> rustls::Error {
    rustls::Error::InvalidCertificate(CertificateError::Other(rustls::OtherError(Arc::new(
        failure,
    ))))
}

/// Why a failed upstream handshake failed, when it was the certificate
/// `proxy_ssl_verify` refused.
pub fn verify_failure(e: &std::io::Error) -> Option<&crate::x509_verify::Failure> {
    match e.get_ref()?.downcast_ref::<rustls::Error>()? {
        rustls::Error::InvalidCertificate(CertificateError::Other(other)) => other.0.downcast_ref(),
        _ => None,
    }
}

impl ServerCertVerifier for Verification {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let chain: Vec<&[u8]> = intermediates.iter().map(|c| c.as_ref()).collect();
        let text = server_name.to_str();
        let name = crate::x509_verify::NameToCheck {
            text: &text,
            ip: match server_name {
                ServerName::IpAddress(ip) => Some(std::net::IpAddr::from(*ip)),
                _ => None,
            },
        };
        self.store
            .verify(end_entity, &chain, &name)
            .map(|()| ServerCertVerified::assertion())
            .map_err(refused)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        crate::x509_verify::verify_tls12_signature(
            &self.provider.signature_verification_algorithms,
            message,
            cert,
            dss,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        crate::x509_verify::verify_tls13_signature(
            &self.provider.signature_verification_algorithms,
            message,
            cert,
            dss,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `ObjectCache` as ngx_ssl_cache_connection_fetch (#601), with
    /// objects that tell how many loads there were.
    #[test]
    fn object_cache_follows_nginx() {
        use std::time::{Duration, Instant};
        let dir = std::env::temp_dir().join(format!("ruxen-objcache-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = |name: &str| {
            let path = dir.join(name);
            std::fs::write(&path, name).unwrap();
            path
        };
        let (a, b, c) = (file("a"), file("b"), file("c"));
        let mut cache = ObjectCache {
            max: 2,
            inactive: 10,
            valid: 60,
            entries: Vec::new(),
        };
        let loads = std::cell::Cell::new(0u8);
        let t0 = Instant::now();
        let get =
            |cache: &mut ObjectCache, path: &Path, at: u64, invalidate: bool, cacheable: bool| {
                let now = t0 + Duration::from_secs(at);
                let object = cache
                    .fetch(Object::CERT, path, invalidate, now, || {
                        loads.set(loads.get() + 1);
                        let der = CertificateDer::from(vec![loads.get()]);
                        Ok((Object::Chain(Arc::new(vec![der])), cacheable))
                    })
                    .unwrap();
                let Object::Chain(chain) = object else {
                    unreachable!()
                };
                chain[0].as_ref()[0]
            };
        assert_eq!(get(&mut cache, &a, 0, false, true), 1);
        assert_eq!(get(&mut cache, &a, 1, false, true), 1, "cached");
        assert_eq!(get(&mut cache, &b, 1, false, true), 2);
        // Full: the least recently used, `a`, makes room for `c`.
        assert_eq!(get(&mut cache, &c, 2, false, true), 3);
        assert_eq!(get(&mut cache, &b, 2, false, true), 2);
        assert_eq!(get(&mut cache, &a, 2, false, true), 4, "evicted");
        // Past `valid`, an unchanged file isn't read again; invalidated,
        // it is.
        assert_eq!(get(&mut cache, &a, 100, false, true), 4);
        assert_eq!(get(&mut cache, &a, 100, true, true), 5);
        // A changed file is read again once `valid` is over. Renamed over
        // it, so it can't get the old inode back.
        std::fs::rename(file("a.new"), &a).unwrap();
        assert_eq!(get(&mut cache, &a, 101, false, true), 5);
        assert_eq!(get(&mut cache, &a, 200, false, true), 6);
        // What can't be cached (an encrypted key) takes its entry out.
        assert_eq!(get(&mut cache, &a, 200, true, false), 7);
        assert_eq!(cache.entries.len(), 1);
        // A new entry first drops up to two unused for `inactive`: `b`.
        assert_eq!(get(&mut cache, &a, 200, false, true), 8);
        assert_eq!(cache.entries.len(), 1);
        assert_eq!(get(&mut cache, &b, 200, false, true), 9);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn server_names_drop_the_port_and_brackets() {
        let dns = |s: &str| ServerName::try_from(s.to_string()).unwrap();
        assert_eq!(server_name(b"example.com"), dns("example.com"));
        assert_eq!(server_name(b"example.com:8443"), dns("example.com"));
        assert_eq!(server_name(b"127.0.0.1:8443"), dns("127.0.0.1"));
        assert_eq!(server_name(b"[::1]:8443"), dns("::1"));
        assert_eq!(server_name(b"backend"), dns("backend"));
    }

    /// The caches hold their entries weakly (#500): the same files give the
    /// same store and config while someone holds them, and once the last
    /// holder (a retired configuration) is gone, a new one is made.
    #[test]
    fn caches_share_while_held_and_let_go_after() {
        let dir = std::env::temp_dir().join(format!("ruxen-utls-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let ca = rcgen::generate_simple_self_signed(vec!["ca.test".to_string()]).unwrap();
        let path: &'static Path = Box::leak(dir.join("ca.pem").into_boxed_path());
        std::fs::write(path, ca.cert.pem()).unwrap();
        let settings = || VerifySettings {
            trusted: path,
            depth: 1,
            crl: None,
        };
        let protocols = TlsVersionSet {
            tlsv1_2: true,
            tlsv1_3: true,
        };
        let a = trust_store(settings()).unwrap();
        let b = trust_store(settings()).unwrap();
        assert!(Arc::ptr_eq(&a, &b));
        let config_a = client_config(protocols, true, true, Some(a.clone()), None).unwrap();
        let config_b = client_config(protocols, true, true, Some(b.clone()), None).unwrap();
        assert!(Arc::ptr_eq(&config_a, &config_b));
        // The config holds its store: dropping the configs lets both go.
        let weak = Arc::downgrade(&a);
        drop((a, b, config_a, config_b));
        assert_eq!(weak.strong_count(), 0);
        // Made again on the next call.
        assert!(trust_store(settings()).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
