//! TLS to upstreams, `proxy_pass https://` (#116), as nginx's
//! ngx_http_upstream_ssl_init_connection with its defaults: no SNI unless
//! `proxy_ssl_server_name on`, session reuse on, and the certificate not
//! verified unless `proxy_ssl_verify on` (#117, `x509_verify`).

use std::sync::{Arc, Mutex};

use std::path::Path;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, SubjectPublicKeyInfoDer, UnixTime};
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
}

/// What one proxied request connects with.
#[derive(Debug)]
pub struct TlsPlan {
    pub config: Arc<ClientConfig>,
    pub name: ServerName<'static>,
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

/// The client config for this combination of settings, shared by every
/// location that has it, so they share the session cache too. `verify` is
/// the trust store of `proxy_ssl_verify on`.
pub fn client_config(
    protocols: TlsVersionSet,
    sni: bool,
    reuse: bool,
    verify: Option<Arc<crate::x509_verify::Store>>,
) -> Result<Arc<ClientConfig>, String> {
    type Key = (
        bool,
        bool,
        bool,
        bool,
        Option<Arc<crate::x509_verify::Store>>,
    );
    static CONFIGS: Mutex<Vec<(Key, Arc<ClientConfig>)>> = Mutex::new(Vec::new());
    let key = (protocols.tlsv1_2, protocols.tlsv1_3, sni, reuse, verify);
    let same = |a: &Key, b: &Key| {
        (a.0, a.1, a.2, a.3) == (b.0, b.1, b.2, b.3)
            && match (&a.4, &b.4) {
                (None, None) => true,
                (Some(x), Some(y)) => Arc::ptr_eq(x, y),
                _ => false,
            }
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
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&versions)
        .map_err(|e| format!("proxy_ssl_protocols: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    config.enable_sni = sni;
    if !reuse {
        config.resumption = rustls::client::Resumption::disabled();
    }
    let config = Arc::new(config);
    configs.push((key, config.clone()));
    Ok(config)
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

impl Verification {
    fn spki(cert: &CertificateDer<'_>) -> Result<SubjectPublicKeyInfoDer<'static>, rustls::Error> {
        crate::x509_verify::spki(cert)
            .map(SubjectPublicKeyInfoDer::from)
            .ok_or(rustls::Error::InvalidCertificate(
                CertificateError::BadEncoding,
            ))
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
        // As rustls's verify_tls12_signature, from the key alone: TLS 1.2
        // names a scheme several algorithms may stand for.
        let spki = Self::spki(cert)?;
        let key = webpki::RawPublicKeyEntity::try_from(&spki)
            .map_err(|_| rustls::Error::InvalidCertificate(CertificateError::BadEncoding))?;
        let algs = &self.provider.signature_verification_algorithms;
        let candidates = algs
            .mapping
            .iter()
            .filter(|(scheme, _)| *scheme == dss.scheme)
            .flat_map(|(_, algs)| algs.iter());
        for alg in candidates {
            match key.verify_signature(*alg, message, dss.signature()) {
                Ok(()) => return Ok(HandshakeSignatureValid::assertion()),
                Err(webpki::Error::UnsupportedSignatureAlgorithmForPublicKeyContext(_)) => continue,
                Err(_) => break,
            }
        }
        Err(rustls::Error::InvalidCertificate(
            CertificateError::BadSignature,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature_with_raw_key(
            message,
            &Self::spki(cert)?,
            dss,
            &self.provider.signature_verification_algorithms,
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
