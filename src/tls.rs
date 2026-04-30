// TLS adapter — thin wrapper over `monoio-rustls`.
//
// `monoio-rustls` already bridges rustls's sync state machine to monoio's
// owned-buffer async traits; this file is the ruxen-specific glue:
//
// - re-exports of the upstream types used elsewhere in the crate
// - `accept_with_timeout` so a stalled handshake can't pin a worker
// - `HandshakeInfo`, the post-handshake snapshot used by request routing
//   and `$ssl_*` variable rendering
//
#![allow(dead_code)] // helper API is partly test-only / future directive surface

// Note: `HandshakeInfo` reads post-handshake state via `Stream::get_ref()`,
// added upstream by an in-flight PR against monoio-rs/monoio-tls. The
// crate is pulled via a `[patch.crates-io]` entry in `Cargo.toml`; drop
// the patch once a published release carries the accessor.

use std::sync::Arc;
use std::time::Duration;

pub use monoio_rustls::{ServerTlsStream, TlsAcceptor, TlsError};
pub use rustls::ServerConfig;

use monoio::io::{AsyncReadRent, AsyncWriteRent};

/// Default handshake timeout. Matches nginx's `ssl_handshake_timeout 60s;`.
/// The directive is parsed as an accepted no-op elsewhere; runtime timeout
/// selection is still fixed at this default.
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug)]
pub enum AcceptError {
    Tls(TlsError),
    Timeout,
}

impl From<TlsError> for AcceptError {
    fn from(e: TlsError) -> Self {
        AcceptError::Tls(e)
    }
}

impl std::fmt::Display for AcceptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AcceptError::Tls(e) => write!(f, "tls handshake failed: {e}"),
            AcceptError::Timeout => write!(f, "tls handshake timed out"),
        }
    }
}

impl std::error::Error for AcceptError {}

/// Drive a TLS handshake to completion or abort after `timeout`.
///
/// On success returns the established stream plus a `HandshakeInfo`
/// snapshot of the negotiated parameters. The snapshot is taken once,
/// post-handshake, so request paths don't pay for accessor calls.
pub async fn accept_with_timeout<IO>(
    acceptor: &TlsAcceptor,
    stream: IO,
    timeout: Duration,
) -> Result<(ServerTlsStream<IO>, HandshakeInfo), AcceptError>
where
    IO: AsyncReadRent + AsyncWriteRent,
{
    match monoio::time::timeout(timeout, acceptor.accept(stream)).await {
        Ok(Ok(s)) => {
            let info = HandshakeInfo::from_stream(&s);
            Ok((s, info))
        }
        Ok(Err(e)) => Err(AcceptError::Tls(e)),
        Err(_elapsed) => Err(AcceptError::Timeout),
    }
}

/// Snapshot of negotiated TLS parameters, taken once after the handshake.
///
/// Stashed on the connection and read for `$ssl_*` variable rendering. We
/// snapshot rather than holding `&ServerConnection` so the
/// request hot path is a struct read, not a virtual call into rustls.
#[derive(Debug, Clone, Default)]
pub struct HandshakeInfo {
    pub alpn_protocol: Option<Vec<u8>>,
    pub server_name: Option<String>,
    pub protocol_version: Option<rustls::ProtocolVersion>,
    pub negotiated_cipher_suite: Option<rustls::SupportedCipherSuite>,
    /// `true` when rustls reported `HandshakeKind::Resumed` for this
    /// connection — drives `$ssl_session_reused`.
    pub session_reused: bool,
}

impl HandshakeInfo {
    fn from_stream<IO>(stream: &ServerTlsStream<IO>) -> Self {
        let (_io, conn) = stream.get_ref();
        Self {
            alpn_protocol: conn.alpn_protocol().map(|s| s.to_vec()),
            server_name: conn.server_name().map(|s| s.to_string()),
            protocol_version: conn.protocol_version(),
            negotiated_cipher_suite: conn.negotiated_cipher_suite(),
            session_reused: matches!(conn.handshake_kind(), Some(rustls::HandshakeKind::Resumed)),
        }
    }
}

/// Render `$ssl_protocol` for a negotiated TLS version. Mirrors nginx's
/// `ngx_ssl_get_protocol` which returns `SSL_get_version()` verbatim.
pub fn protocol_version_str(v: rustls::ProtocolVersion) -> &'static str {
    match v {
        rustls::ProtocolVersion::TLSv1_3 => "TLSv1.3",
        rustls::ProtocolVersion::TLSv1_2 => "TLSv1.2",
        rustls::ProtocolVersion::TLSv1_1 => "TLSv1.1",
        rustls::ProtocolVersion::TLSv1_0 => "TLSv1",
        // rustls only negotiates TLS 1.2/1.3 for application traffic; the
        // remaining variants (DTLS, SSLv2/3) cannot reach this code path,
        // but match nginx's catch-all "" return rather than panicking.
        _ => "",
    }
}

/// Map a rustls `SupportedCipherSuite` to the string nginx renders for
/// `$ssl_cipher`. nginx delegates to OpenSSL's `SSL_CIPHER_get_name`, which
/// returns the OpenSSL spelling for TLS 1.2 (e.g.
/// `ECDHE-RSA-AES128-GCM-SHA256`) and the IANA name for TLS 1.3 (e.g.
/// `TLS_AES_128_GCM_SHA256`). rustls names are always IANA, prefixed
/// `TLS13_` for 1.3 and `TLS_..._WITH_..._SHA*` for 1.2 — we translate.
///
/// Returns `""` for unknown suites so the variable renders empty (matches
/// nginx's behavior for ciphers it doesn't recognize).
pub fn cipher_suite_iana_name(s: rustls::SupportedCipherSuite) -> &'static str {
    use rustls::CipherSuite as C;
    match s.suite() {
        // TLS 1.3: drop the rustls-specific `13` infix to recover the IANA name.
        C::TLS13_AES_128_GCM_SHA256 => "TLS_AES_128_GCM_SHA256",
        C::TLS13_AES_256_GCM_SHA384 => "TLS_AES_256_GCM_SHA384",
        C::TLS13_CHACHA20_POLY1305_SHA256 => "TLS_CHACHA20_POLY1305_SHA256",
        C::TLS13_AES_128_CCM_SHA256 => "TLS_AES_128_CCM_SHA256",
        C::TLS13_AES_128_CCM_8_SHA256 => "TLS_AES_128_CCM_8_SHA256",
        // TLS 1.2 (only the suites rustls's ring/aws-lc-rs providers offer):
        // OpenSSL spelling is `ECDHE-{ECDSA,RSA}-{AES128,AES256,CHACHA20-POLY1305}{,-SHA*,-GCM-SHA*}`.
        C::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 => "ECDHE-ECDSA-AES128-GCM-SHA256",
        C::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 => "ECDHE-ECDSA-AES256-GCM-SHA384",
        C::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 => "ECDHE-ECDSA-CHACHA20-POLY1305",
        C::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 => "ECDHE-RSA-AES128-GCM-SHA256",
        C::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => "ECDHE-RSA-AES256-GCM-SHA384",
        C::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => "ECDHE-RSA-CHACHA20-POLY1305",
        _ => "",
    }
}

/// Wrap a fully-built `rustls::ServerConfig` as a clonable acceptor.
pub fn acceptor_from_config(cfg: Arc<ServerConfig>) -> TlsAcceptor {
    TlsAcceptor::from(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn find_suite(name: rustls::CipherSuite) -> rustls::SupportedCipherSuite {
        rustls::crypto::aws_lc_rs::ALL_CIPHER_SUITES
            .iter()
            .copied()
            .find(|s| s.suite() == name)
            .expect("suite present in default ring provider")
    }

    #[test]
    fn cipher_suite_iana_name_tls13() {
        assert_eq!(
            cipher_suite_iana_name(find_suite(rustls::CipherSuite::TLS13_AES_128_GCM_SHA256)),
            "TLS_AES_128_GCM_SHA256",
        );
        assert_eq!(
            cipher_suite_iana_name(find_suite(rustls::CipherSuite::TLS13_AES_256_GCM_SHA384)),
            "TLS_AES_256_GCM_SHA384",
        );
        assert_eq!(
            cipher_suite_iana_name(find_suite(rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256)),
            "TLS_CHACHA20_POLY1305_SHA256",
        );
    }

    #[test]
    fn cipher_suite_iana_name_tls12_openssl_form() {
        assert_eq!(
            cipher_suite_iana_name(find_suite(
                rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            )),
            "ECDHE-RSA-AES128-GCM-SHA256",
        );
        assert_eq!(
            cipher_suite_iana_name(find_suite(
                rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
            )),
            "ECDHE-ECDSA-CHACHA20-POLY1305",
        );
    }

    #[test]
    fn protocol_version_str_known_versions() {
        assert_eq!(protocol_version_str(rustls::ProtocolVersion::TLSv1_3), "TLSv1.3");
        assert_eq!(protocol_version_str(rustls::ProtocolVersion::TLSv1_2), "TLSv1.2");
    }
}
