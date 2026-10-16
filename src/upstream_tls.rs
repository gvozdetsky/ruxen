//! TLS to upstreams, `proxy_pass https://` (#116), as nginx's
//! ngx_http_upstream_ssl_init_connection with its defaults: no SNI unless
//! `proxy_ssl_server_name on`, session reuse on, and the certificate not
//! verified unless `proxy_ssl_verify on` (#117, `x509_verify`).

use std::sync::{Arc, Mutex};

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
/// per request, as ngx_http_upstream_ssl_certificate does per connection,
/// and the client config with it is kept, keyed by the rendered paths, so
/// a pair's files are read and parsed on its first use only.
#[derive(Debug)]
pub struct DynamicCert {
    pub(crate) cert: crate::worker::PreparedCertPath,
    pub(crate) key: crate::worker::PreparedCertPath,
    passwords: Arc<[Vec<u8>]>,
    protocols: TlsVersionSet,
    sni: bool,
    reuse: bool,
    verify: Option<Arc<crate::x509_verify::Store>>,
    configs: Mutex<Vec<(Vec<u8>, Vec<u8>, Arc<ClientConfig>)>>,
}

/// Pairs kept per location; more distinct renderings start it over.
const DYNAMIC_CONFIGS: usize = 64;

impl DynamicCert {
    pub(crate) fn new(
        cert: crate::worker::PreparedCertPath,
        key: crate::worker::PreparedCertPath,
        passwords: Arc<[Vec<u8>]>,
        protocols: TlsVersionSet,
        sni: bool,
        reuse: bool,
        verify: Option<Arc<crate::x509_verify::Store>>,
    ) -> Self {
        Self {
            cert,
            key,
            passwords,
            protocols,
            sni,
            reuse,
            verify,
            configs: Mutex::new(Vec::new()),
        }
    }

    /// The config for the rendered pair: `None` for an empty certificate
    /// (the location's config, without one), else the pair's, loaded on
    /// its first use; `Err` is the error log's line, and the request
    /// fails with a 500, as nginx's does.
    #[cold]
    pub fn config(&self, cert: &[u8], key: &[u8]) -> Result<Option<Arc<ClientConfig>>, String> {
        if cert.is_empty() {
            return Ok(None);
        }
        let found = self
            .configs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .find(|(c, k, _)| c == cert && k == key)
            .map(|(_, _, config)| config.clone());
        if let Some(config) = found {
            return Ok(Some(config));
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
        let certified =
            certificate_pair(&cert_path, &key_path, &self.passwords, |p| std::fs::read(p))?;
        let config = client_config(
            self.protocols,
            self.sni,
            self.reuse,
            self.verify.clone(),
            Some(certified),
        )?;
        let mut configs = self.configs.lock().unwrap_or_else(|e| e.into_inner());
        if configs.len() >= DYNAMIC_CONFIGS {
            configs.clear();
        }
        configs.push((cert.to_vec(), key.to_vec(), config.clone()));
        Ok(Some(config))
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
    static STORES: Mutex<Vec<(Key, Arc<crate::x509_verify::Store>)>> = Mutex::new(Vec::new());
    let read = |path: &Path, call: &str| {
        std::fs::read(path).map_err(|e| {
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
    if let Some((_, store)) = stores.iter().find(|(k, _)| *k == key) {
        return Ok(store.clone());
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
    stores.push((key, store.clone()));
    Ok(store)
}

/// `proxy_ssl_certificate` and its key (#138), loaded once per content of
/// the files, as the trust stores are. `Err` is the `[emerg]` text.
/// An encrypted key opens with `passwords` (`proxy_ssl_password_file`).
pub fn client_certificate(
    cert: &Path,
    key: &Path,
    passwords: &[Vec<u8>],
) -> Result<Arc<CertifiedKey>, String> {
    certificate_pair(cert, key, passwords, |path| std::fs::read(path))
}

fn certificate_pair(
    cert: &Path,
    key: &Path,
    passwords: &[Vec<u8>],
    read_file: impl Fn(&Path) -> std::io::Result<Vec<u8>>,
) -> Result<Arc<CertifiedKey>, String> {
    type Key = (Vec<u8>, Vec<u8>);
    static KEYS: Mutex<Vec<(Key, Arc<CertifiedKey>)>> = Mutex::new(Vec::new());
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
    if let Some((_, certified)) = keys.iter().find(|(known, _)| *known == k) {
        return Ok(certified.clone());
    }
    let certified = crate::tls_certs::parse_certified_key(&k.0, &k.1, cert, key, passwords)
        .map_err(|e| fail(&e))?;
    let certified = Arc::new(certified);
    keys.push((k, certified.clone()));
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
    type Key = (
        bool,
        bool,
        bool,
        bool,
        Option<Arc<crate::x509_verify::Store>>,
        Option<Arc<CertifiedKey>>,
    );
    static CONFIGS: Mutex<Vec<(Key, Arc<ClientConfig>)>> = Mutex::new(Vec::new());
    let key = (
        protocols.tlsv1_2,
        protocols.tlsv1_3,
        sni,
        reuse,
        verify,
        client_cert,
    );
    fn same_arc<T>(a: &Option<Arc<T>>, b: &Option<Arc<T>>) -> bool {
        match (a, b) {
            (None, None) => true,
            (Some(x), Some(y)) => Arc::ptr_eq(x, y),
            _ => false,
        }
    }
    let same = |a: &Key, b: &Key| {
        (a.0, a.1, a.2, a.3) == (b.0, b.1, b.2, b.3) && same_arc(&a.4, &b.4) && same_arc(&a.5, &b.5)
    };
    let mut configs = CONFIGS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((_, config)) = configs.iter().find(|(k, _)| same(k, &key)) {
        return Ok(config.clone());
    }
    let provider = crate::tls_certs::active_provider();
    let mut versions: Vec<&'static rustls::SupportedProtocolVersion> = Vec::new();
    if protocols.tlsv1_3 {
        versions.push(&rustls::version::TLS13);
    }
    if protocols.tlsv1_2 {
        versions.push(&rustls::version::TLS12);
    }
    let verifier: Arc<dyn ServerCertVerifier> = match &key.4 {
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
    let mut config = match &key.5 {
        Some(certified) => {
            builder.with_client_cert_resolver(Arc::new(ClientCert(certified.clone())))
        }
        None => builder.with_no_client_auth(),
    };
    config.enable_sni = sni;
    if !reuse {
        config.resumption = rustls::client::Resumption::disabled();
    }
    let config = Arc::new(config);
    configs.push((key, config.clone()));
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

    #[test]
    fn server_names_drop_the_port_and_brackets() {
        let dns = |s: &str| ServerName::try_from(s.to_string()).unwrap();
        assert_eq!(server_name(b"example.com"), dns("example.com"));
        assert_eq!(server_name(b"example.com:8443"), dns("example.com"));
        assert_eq!(server_name(b"127.0.0.1:8443"), dns("127.0.0.1"));
        assert_eq!(server_name(b"[::1]:8443"), dns("::1"));
        assert_eq!(server_name(b"backend"), dns("backend"));
    }
}
