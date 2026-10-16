//! TLS to upstreams, `proxy_pass https://` (#116), as nginx's
//! ngx_http_upstream_ssl_init_connection with its defaults: no SNI unless
//! `proxy_ssl_server_name on`, session reuse on, and the certificate not
//! verified (`proxy_ssl_verify off`; `on` is refused until #117).

use std::sync::{Arc, Mutex};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};

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
/// with SNI on nginx would send it, but nothing checks it while
/// verification is off, and the session cache still keys on it.
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

/// The client config for this combination of settings, shared by every
/// location that has it, so they share the session cache too.
pub fn client_config(
    protocols: TlsVersionSet,
    sni: bool,
    reuse: bool,
) -> Result<Arc<ClientConfig>, String> {
    type Key = (bool, bool, bool, bool);
    static CONFIGS: Mutex<Vec<(Key, Arc<ClientConfig>)>> = Mutex::new(Vec::new());
    let key = (protocols.tlsv1_2, protocols.tlsv1_3, sni, reuse);
    let mut configs = CONFIGS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((_, config)) = configs.iter().find(|(k, _)| *k == key) {
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
    let mut config = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&versions)
        .map_err(|e| format!("proxy_ssl_protocols: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerification(provider)))
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
