//! `ssl_verify_client` (#113): client certificates requested and checked
//! as nginx's OpenSSL does. The handshake asks for a certificate and never
//! fails over it (nginx's verify callback always returns 1): the chain is
//! checked once the handshake is done, with the server's trust store
//! (`x509_verify`), and the request is refused with 495 / 496 at request
//! time, so `error_page` can answer it, as in ngx_http_process_request.

use std::sync::Arc;

use rustls::client::danger::HandshakeSignatureValid;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};

/// One server's client-certificate context: what the handshake asks with,
/// and what the certificate is checked against.
#[derive(Debug)]
pub struct ClientAuth {
    /// `ssl_client_certificate` + `ssl_trusted_certificate`, with
    /// `ssl_verify_depth` and `ssl_crl`.
    pub store: Arc<crate::x509_verify::Store>,
    /// The subjects of `ssl_client_certificate` only, each once: the CA
    /// list of the CertificateRequest (SSL_CTX_set_client_CA_list). Empty
    /// with only `ssl_trusted_certificate` (nginx ≥ 1.27.2, #587).
    pub hints: Vec<DistinguishedName>,
    /// `ssl_ocsp on|leaf` (#142).
    pub ocsp: Option<Arc<crate::ocsp::ClientOcsp>>,
}

impl ClientAuth {
    /// The rustls verifier for a `ServerConfig` with this context.
    pub fn verifier(&self, provider: Arc<CryptoProvider>) -> Arc<dyn ClientCertVerifier> {
        Arc::new(RequestCertificate {
            hints: self.hints.clone(),
            provider,
        })
    }

    /// The handshake's result for `$ssl_client_verify` and the request
    /// checks: the chain the client sent, if any, against the store. With
    /// `ssl_ocsp`, a chain that verifies is `OcspPending` until its
    /// status is read.
    pub fn check(&self, chain: Option<&[CertificateDer<'_>]>) -> ClientVerify {
        let Some(chain) = chain.filter(|c| !c.is_empty()) else {
            return ClientVerify::None;
        };
        let ders: Vec<&[u8]> = chain.iter().map(|c| c.as_ref()).collect();
        let mut verified = Vec::new();
        let out = self.ocsp.is_some().then_some(&mut verified);
        match self.store.verify_client(&ders, out) {
            Ok(()) => match &self.ocsp {
                Some(ocsp) => ClientVerify::OcspPending(Arc::new(OcspPending {
                    ocsp: ocsp.clone(),
                    chain: verified,
                })),
                None => ClientVerify::Success,
            },
            Err(crate::x509_verify::Failure::Verify(code, text)) => {
                ClientVerify::Failed(code, text.into())
            }
            // X509_V_ERR_UNSPECIFIED: the chain didn't even parse.
            Err(_) => ClientVerify::Failed(1, "unspecified certificate verification error".into()),
        }
    }
}

/// What the handshake established about the client's certificate
/// (ngx_ssl_get_client_verify).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum ClientVerify {
    /// No certificate: none was asked for, or the client sent none.
    #[default]
    None,
    Success,
    /// SSL_get_verify_result's code and X509_verify_cert_error_string.
    Failed(i64, Box<str>),
    /// The chain verified, its OCSP status not read yet: resolved before
    /// the first request, and refused like a failure if it ever isn't.
    OcspPending(Arc<OcspPending>),
    /// The chain verified, and OCSP says no: ngx_ssl_ocsp_get_status's
    /// words.
    Revoked(&'static str),
}

impl ClientVerify {
    /// The OCSP check of a pending chain, then its outcome in `self`.
    pub async fn resolve_ocsp(&mut self, log: &crate::ocsp::ConnLog) {
        let ClientVerify::OcspPending(pending) = &*self else {
            return;
        };
        let pending = pending.clone();
        *self = match pending.ocsp.validate(&pending.chain, log).await {
            Ok(()) => ClientVerify::Success,
            Err(text) => ClientVerify::Revoked(text),
        };
    }
}

/// A verified chain waiting for its OCSP check.
pub struct OcspPending {
    ocsp: Arc<crate::ocsp::ClientOcsp>,
    /// Leaf to trust anchor, DER.
    chain: Vec<Vec<u8>>,
}

impl std::fmt::Debug for OcspPending {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OcspPending")
            .field("certificates", &self.chain.len())
            .finish_non_exhaustive()
    }
}

impl PartialEq for OcspPending {
    fn eq(&self, other: &Self) -> bool {
        std::ptr::eq(self, other)
    }
}

impl Eq for OcspPending {}

/// Asks for a certificate, takes whatever chain comes (it is checked after
/// the handshake), and checks the handshake signature for real: that is
/// the client's proof that it holds the certificate's key.
#[derive(Debug)]
struct RequestCertificate {
    hints: Vec<DistinguishedName>,
    provider: Arc<CryptoProvider>,
}

impl ClientCertVerifier for RequestCertificate {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        false
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &self.hints
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        Ok(ClientCertVerified::assertion())
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
