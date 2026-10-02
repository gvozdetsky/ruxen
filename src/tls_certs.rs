// PEM cert/key loading and SNI-aware certificate resolution.
//
// Two responsibilities split inside one file:
//
// - `load_certified_key`: parse a PEM cert chain + matching private key into
//   a `rustls::sign::CertifiedKey`. Accepts PKCS#8, PKCS#1 (RSA), and SEC1
//   (EC) private keys via `rustls_pemfile::private_key`. Cert/key mismatch
//   is caught by comparing SubjectPublicKeyInfo bytes, like rustls's
//   `keys_match`, but without webpki so X.509 v1 leaves load too.
//
// - `ServerNameResolver`: a `rustls::server::ResolvesServerCert` that
//   dispatches by SNI host (exact then leading-wildcard `*.example.com`),
//   falling back to a configured default. Mirrors the existing HTTP
//   `match_server` ladder so an HTTPS server block selects the same
//   server identity at the TLS layer that it would in the HTTP layer.
//
// Multi-cert per server (RSA + ECDSA) is supported by registering several
// `Arc<CertifiedKey>` values under the same hostname. At resolve time the
// first key whose `SigningKey::choose_scheme` accepts one of the client's
// announced signature schemes wins; if none does, we fall through to the
// first registered key so rustls can produce a clear handshake error
// instead of us silently aborting the handshake here.

#![allow(dead_code)] // some parser/test entry points are not used in all builds

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::ServerConfig;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{SignatureScheme, SupportedProtocolVersion};

use crate::config::TlsVersionSet;

#[derive(Debug)]
pub enum LoadCertError {
    Io { path: PathBuf, err: std::io::Error },
    Pem { path: PathBuf, err: std::io::Error },
    NoCerts(PathBuf),
    NoKey(PathBuf),
    Rustls(rustls::Error),
}

impl std::fmt::Display for LoadCertError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, err } => write!(f, "reading {}: {err}", path.display()),
            Self::Pem { path, err } => write!(f, "parsing PEM {}: {err}", path.display()),
            Self::NoCerts(p) => write!(f, "no certificates in {}", p.display()),
            Self::NoKey(p) => write!(f, "no private key in {}", p.display()),
            Self::Rustls(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for LoadCertError {}

/// Parse a PEM cert chain and a matching PEM private key, building a
/// `CertifiedKey` whose private key was loaded by the active rustls
/// `CryptoProvider`. A key that doesn't match the leaf certificate is
/// rejected (`InconsistentKeys::KeyMismatch`).
pub fn load_certified_key(cert_pem: &Path, key_pem: &Path) -> Result<CertifiedKey, LoadCertError> {
    let cert_bytes = std::fs::read(cert_pem).map_err(|err| LoadCertError::Io {
        path: cert_pem.to_path_buf(),
        err,
    })?;
    let key_bytes = std::fs::read(key_pem).map_err(|err| LoadCertError::Io {
        path: key_pem.to_path_buf(),
        err,
    })?;
    parse_certified_key(&cert_bytes, &key_bytes, cert_pem, key_pem)
}

fn parse_certified_key(
    cert_pem: &[u8],
    key_pem: &[u8],
    cert_path: &Path,
    key_path: &Path,
) -> Result<CertifiedKey, LoadCertError> {
    let mut cert_reader = std::io::BufReader::new(cert_pem);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| LoadCertError::Pem {
            path: cert_path.to_path_buf(),
            err,
        })?;
    if certs.is_empty() {
        return Err(LoadCertError::NoCerts(cert_path.to_path_buf()));
    }

    let mut key_reader = std::io::BufReader::new(key_pem);
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|err| LoadCertError::Pem {
            path: key_path.to_path_buf(),
            err,
        })?
        .ok_or_else(|| LoadCertError::NoKey(key_path.to_path_buf()))?;

    let provider = active_provider();
    let signing_key = provider
        .key_provider
        .load_private_key(key)
        .map_err(LoadCertError::Rustls)?;
    let certified = CertifiedKey::new(certs, signing_key);
    keys_match(&certified).map_err(LoadCertError::Rustls)?;
    Ok(certified)
}

/// `CertifiedKey::from_der` checks the key against the leaf with webpki,
/// which rejects X.509 v1 certificates (`UnsupportedCertVersion`). OpenSSL,
/// and so nginx, serves them, and nginx-tests generates every certificate
/// as v1. Same check, same errors, minus the version requirement: compare
/// the key's SubjectPublicKeyInfo with the one in the leaf's
/// TBSCertificate. A key type that can't report its SPKI passes, as in
/// `from_der`.
fn keys_match(certified: &CertifiedKey) -> Result<(), rustls::Error> {
    let Some(key_spki) = certified.key.public_key() else {
        return Ok(());
    };
    let leaf = certified.end_entity_cert()?;
    let cert_spki = leaf_spki(leaf.as_ref()).ok_or(rustls::Error::InvalidCertificate(
        rustls::CertificateError::BadEncoding,
    ))?;
    if key_spki.as_ref() == cert_spki {
        Ok(())
    } else {
        Err(rustls::InconsistentKeys::KeyMismatch.into())
    }
}

/// The DER `SubjectPublicKeyInfo` (outer SEQUENCE included, as webpki
/// returns it) of a certificate of any version (RFC 5280 §4.1):
/// `Certificate ::= SEQUENCE { tbsCertificate SEQUENCE { [0] version
/// OPTIONAL, serialNumber, signature, issuer, validity, subject,
/// subjectPublicKeyInfo, … }, … }`. v1 certificates omit `[0] version`.
fn leaf_spki(cert: &[u8]) -> Option<&[u8]> {
    const SEQUENCE: u8 = 0x30;
    const EXPLICIT_VERSION: u8 = 0xa0;
    let (tag, _, cert, _) = der_tlv(cert)?;
    if tag != SEQUENCE {
        return None;
    }
    let (tag, _, mut tbs, _) = der_tlv(cert)?;
    if tag != SEQUENCE {
        return None;
    }
    if tbs.first() == Some(&EXPLICIT_VERSION) {
        tbs = der_tlv(tbs)?.3;
    }
    // serialNumber, signature, issuer, validity, subject
    for _ in 0..5 {
        tbs = der_tlv(tbs)?.3;
    }
    let (tag, spki, _, _) = der_tlv(tbs)?;
    (tag == SEQUENCE).then_some(spki)
}

/// Split one DER element off `input`: `(tag, whole element, contents,
/// rest)`. Single-byte tags only, which is all a certificate's top levels
/// use; lengths up to 4 bytes.
fn der_tlv(input: &[u8]) -> Option<(u8, &[u8], &[u8], &[u8])> {
    let (&tag, after_tag) = input.split_first()?;
    let (&first, after_len) = after_tag.split_first()?;
    let (len, body) = if first < 0x80 {
        (first as usize, after_len)
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 || after_len.len() < n {
            return None;
        }
        let len = after_len[..n]
            .iter()
            .fold(0usize, |acc, &b| (acc << 8) | b as usize);
        (len, &after_len[n..])
    };
    if body.len() < len {
        return None;
    }
    let header = input.len() - body.len();
    Some((tag, &input[..header + len], &body[..len], &body[len..]))
}

/// Returns the process-wide rustls `CryptoProvider`, falling back to the
/// `aws_lc_rs` default when nothing has been installed yet. Tests may run
/// without `CryptoProvider::install_default()` having been called; the
/// default-provider path keeps them green without leaking provider choice
/// into the public API.
fn active_provider() -> Arc<CryptoProvider> {
    if let Some(p) = CryptoProvider::get_default() {
        return p.clone();
    }
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

/// SNI-aware `ResolvesServerCert`.
///
/// Dispatch order on a `ClientHello`:
///   1. SNI present, exact match (lowercased, trailing dot stripped).
///   2. SNI present, leading-wildcard match. `*.example.com` is registered
///      under the suffix `example.com`; matches `example.com` exactly and
///      any `<sub>.example.com`. nginx and rustls's own
///      `ResolvesServerCertUsingSni` both accept multi-label subdomains
///      against a single wildcard, and we follow that.
///   3. The default cert(s) — the first SSL server on the listen, or the
///      one with `default_server`. Set via `set_default`.
///
/// Each slot holds a `Vec<Arc<CertifiedKey>>` so a server with both an RSA
/// and an ECDSA cert can register both under one name. The selector picks
/// the first key whose `SigningKey::choose_scheme` accepts one of the
/// client's offered signature schemes; if none match, the first registered
/// key is returned so rustls can surface the failure as a normal handshake
/// alert.
#[derive(Debug, Default)]
pub struct ServerNameResolver {
    exact: HashMap<String, Vec<Arc<CertifiedKey>>>,
    /// Lowercased suffix (without leading `*.`), in declaration order.
    wildcard: Vec<(String, Vec<Arc<CertifiedKey>>)>,
    default: Vec<Arc<CertifiedKey>>,
}

impl ServerNameResolver {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `key` under an exact-match hostname. Repeated calls with
    /// the same name accumulate (RSA + ECDSA on the same server).
    pub fn add_exact(&mut self, name: &str, key: Arc<CertifiedKey>) {
        let normalized = normalize_host(name);
        self.exact.entry(normalized).or_default().push(key);
    }

    /// Register `key` under a leading-wildcard suffix. `suffix` must be
    /// the form *without* the `*.` prefix (e.g. `example.com`).
    pub fn add_wildcard(&mut self, suffix: &str, key: Arc<CertifiedKey>) {
        let normalized = normalize_host(suffix);
        if let Some((_, slot)) = self.wildcard.iter_mut().find(|(s, _)| *s == normalized) {
            slot.push(key);
            return;
        }
        self.wildcard.push((normalized, vec![key]));
    }

    /// Set the keys returned when no SNI hostname matches (or when the
    /// client sent no SNI). Empty means "abort the handshake".
    pub fn set_default(&mut self, keys: Vec<Arc<CertifiedKey>>) {
        self.default = keys;
    }

    pub fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.wildcard.is_empty() && self.default.is_empty()
    }

    fn select(
        candidates: &[Arc<CertifiedKey>],
        schemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        if candidates.is_empty() {
            return None;
        }
        for c in candidates {
            if c.key.choose_scheme(schemes).is_some() {
                return Some(c.clone());
            }
        }
        // Nothing matched the client's announced signature schemes; hand
        // back the first cert anyway so rustls produces a clean handshake
        // alert rather than us silently choosing not to serve.
        Some(candidates[0].clone())
    }

    fn lookup(&self, host: &str, schemes: &[SignatureScheme]) -> Option<Arc<CertifiedKey>> {
        let normalized = normalize_host(host);
        if let Some(slot) = self.exact.get(&normalized) {
            return Self::select(slot, schemes);
        }
        for (suffix, slot) in &self.wildcard {
            if &normalized == suffix {
                return Self::select(slot, schemes);
            }
            if let Some(prefix) = normalized.strip_suffix(suffix.as_str()) {
                if prefix.ends_with('.') {
                    return Self::select(slot, schemes);
                }
            }
        }
        None
    }
}

impl ResolvesServerCert for ServerNameResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let schemes = client_hello.signature_schemes();
        if let Some(name) = client_hello.server_name() {
            if let Some(found) = self.lookup(name, schemes) {
                return Some(found);
            }
        }
        Self::select(&self.default, schemes)
    }
}

fn normalize_host(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

/// Build a rustls `ServerConfig` from a populated resolver and the parsed
/// `ssl_protocols` set.
///
/// Session resumption follows nginx: `ssl_session_cache` (default `none`)
/// turns on an in-memory session-ID cache shared by the workers, and
/// `ssl_session_tickets` (default `on`) stateless tickets. With neither,
/// every handshake is a full one: no cache, no ticketer, and no TLS 1.3
/// tickets sent. Both are bounded by `ssl_session_timeout` (default 5m).
pub fn build_server_config(
    resolver: ServerNameResolver,
    protocols: TlsVersionSet,
    session_timeout_secs: Option<u32>,
    resumption: crate::config::SessionResumption,
) -> Result<Arc<ServerConfig>, rustls::Error> {
    let versions: Vec<&'static SupportedProtocolVersion> =
        match (protocols.tlsv1_2, protocols.tlsv1_3) {
            (true, true) => vec![&rustls::version::TLS13, &rustls::version::TLS12],
            (true, false) => vec![&rustls::version::TLS12],
            (false, true) => vec![&rustls::version::TLS13],
            (false, false) => {
                return Err(rustls::Error::General(
                    "no TLS protocol versions enabled".into(),
                ));
            }
        };
    let mut cfg = ServerConfig::builder_with_protocol_versions(&versions)
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver));
    // nginx's default ssl_session_timeout.
    let timeout_secs = session_timeout_secs.unwrap_or(300);
    let cache = resumption.cache.unwrap_or(false);
    let tickets = resumption.tickets.unwrap_or(true);
    cfg.session_storage = if cache {
        Arc::new(crate::tls_session::ExpiringSessionStorage::new(
            rustls::server::ServerSessionMemoryCache::new(4096),
            std::time::Duration::from_secs(timeout_secs as u64),
        ))
    } else {
        Arc::new(rustls::server::NoServerSessionStorage {})
    };
    if tickets {
        let inner_ticketer = rustls::crypto::aws_lc_rs::Ticketer::new()?;
        cfg.ticketer = Arc::new(crate::tls_session::ExpiringTicketer::new(
            inner_ticketer,
            timeout_secs,
        ));
    } else if !cache {
        // Nothing to resume from: don't send TLS 1.3 tickets at all.
        cfg.send_tls13_tickets = 0;
    }
    // Extend this list when HTTP/2 lands.
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

#[cfg(test)]
mod tests {
    use super::*;

    const RSA_CRT: &[u8] = include_bytes!("testdata/tls/rsa.crt");
    const RSA_KEY_PKCS8: &[u8] = include_bytes!("testdata/tls/rsa.key");
    const RSA_KEY_PKCS1: &[u8] = include_bytes!("testdata/tls/rsa_pkcs1.key");
    const EC_CRT: &[u8] = include_bytes!("testdata/tls/ec.crt");
    const EC_KEY_PKCS8: &[u8] = include_bytes!("testdata/tls/ec_pkcs8.key");
    const EC_KEY_SEC1: &[u8] = include_bytes!("testdata/tls/ec_sec1.key");
    const ALT_CRT: &[u8] = include_bytes!("testdata/tls/alt.crt");
    const ALT_KEY: &[u8] = include_bytes!("testdata/tls/alt.key");
    // X.509 v1, made the way nginx-tests makes its certificates:
    // `openssl req -x509 -new` with a config that has no extensions.
    const V1_RSA_CRT: &[u8] = include_bytes!("testdata/tls/v1_rsa.crt");
    const V1_RSA_KEY: &[u8] = include_bytes!("testdata/tls/v1_rsa.key");
    const V1_EC_CRT: &[u8] = include_bytes!("testdata/tls/v1_ec.crt");
    const V1_EC_KEY: &[u8] = include_bytes!("testdata/tls/v1_ec.key");

    fn load(cert: &[u8], key: &[u8]) -> Result<CertifiedKey, LoadCertError> {
        parse_certified_key(cert, key, Path::new("cert"), Path::new("key"))
    }

    fn ck(cert: &[u8], key: &[u8]) -> Arc<CertifiedKey> {
        Arc::new(load(cert, key).expect("load test cert"))
    }

    /// Schemes a typical TLS 1.2/1.3 client offers; lets ECDSA-only and
    /// RSA-only keys both find a match.
    const ALL_SCHEMES: &[SignatureScheme] = &[
        SignatureScheme::ECDSA_NISTP256_SHA256,
        SignatureScheme::RSA_PSS_SHA256,
        SignatureScheme::RSA_PKCS1_SHA256,
    ];

    #[test]
    fn loads_pkcs8_rsa_key() {
        load(RSA_CRT, RSA_KEY_PKCS8).expect("PKCS#8 RSA");
    }

    #[test]
    fn loads_pkcs1_rsa_key() {
        load(RSA_CRT, RSA_KEY_PKCS1).expect("PKCS#1 RSA");
    }

    #[test]
    fn loads_pkcs8_ec_key() {
        load(EC_CRT, EC_KEY_PKCS8).expect("PKCS#8 EC");
    }

    #[test]
    fn loads_sec1_ec_key() {
        load(EC_CRT, EC_KEY_SEC1).expect("SEC1 EC");
    }

    #[test]
    fn rejects_mismatched_cert_and_key() {
        // RSA cert vs an unrelated RSA key → SPKI mismatch.
        let err = load(RSA_CRT, ALT_KEY).expect_err("must reject mismatched key");
        match err {
            LoadCertError::Rustls(rustls::Error::InconsistentKeys(_)) => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn loads_x509_v1_certificates() {
        load(V1_RSA_CRT, V1_RSA_KEY).expect("v1 RSA");
        load(V1_EC_CRT, V1_EC_KEY).expect("v1 EC");
    }

    #[test]
    fn rejects_x509_v1_certificate_with_wrong_key() {
        for (cert, key) in [(V1_RSA_CRT, RSA_KEY_PKCS8), (V1_EC_CRT, EC_KEY_PKCS8)] {
            let err = load(cert, key).expect_err("must reject mismatched key");
            assert!(
                matches!(
                    err,
                    LoadCertError::Rustls(rustls::Error::InconsistentKeys(
                        rustls::InconsistentKeys::KeyMismatch
                    ))
                ),
                "{err:?}"
            );
        }
    }

    #[test]
    fn leaf_spki_matches_webpki_for_v3_certificates() {
        // Same bytes webpki's `keys_match` compares, for certs it accepts.
        for (cert, key) in [(RSA_CRT, RSA_KEY_PKCS8), (EC_CRT, EC_KEY_PKCS8)] {
            let certified = ck(cert, key);
            let ours = leaf_spki(certified.cert[0].as_ref()).expect("spki");
            assert_eq!(ours, certified.key.public_key().unwrap().as_ref());
        }
    }

    #[test]
    fn leaf_spki_rejects_truncated_der() {
        let certified = ck(RSA_CRT, RSA_KEY_PKCS8);
        let der = certified.cert[0].as_ref();
        for cut in [0, 1, 4, 64, der.len() / 2] {
            assert!(leaf_spki(&der[..cut]).is_none(), "cut at {cut}");
        }
    }

    #[test]
    fn rejects_no_certs_in_pem() {
        let err = load(b"not a pem\n", RSA_KEY_PKCS8).expect_err("no certs");
        assert!(matches!(err, LoadCertError::NoCerts(_)));
    }

    #[test]
    fn rejects_no_key_in_pem() {
        let err = load(RSA_CRT, b"not a pem\n").expect_err("no key");
        assert!(matches!(err, LoadCertError::NoKey(_)));
    }

    #[test]
    fn resolver_exact_dispatch() {
        let primary = ck(RSA_CRT, RSA_KEY_PKCS8);
        let alt = ck(ALT_CRT, ALT_KEY);
        let mut r = ServerNameResolver::new();
        r.add_exact("test.ruxen.local", primary.clone());
        r.add_exact("alt.ruxen.local", alt.clone());

        let got = r.lookup("test.ruxen.local", ALL_SCHEMES).expect("hit");
        assert!(Arc::ptr_eq(&got, &primary));

        let got = r.lookup("alt.ruxen.local", ALL_SCHEMES).expect("hit");
        assert!(Arc::ptr_eq(&got, &alt));

        assert!(r.lookup("nope.example.com", ALL_SCHEMES).is_none());
    }

    #[test]
    fn resolver_normalizes_host_case_and_trailing_dot() {
        let key = ck(RSA_CRT, RSA_KEY_PKCS8);
        let mut r = ServerNameResolver::new();
        r.add_exact("Example.COM", key.clone());

        assert!(r.lookup("example.com", ALL_SCHEMES).is_some());
        assert!(r.lookup("EXAMPLE.com.", ALL_SCHEMES).is_some());
    }

    #[test]
    fn resolver_wildcard_dispatch() {
        let key = ck(RSA_CRT, RSA_KEY_PKCS8);
        let mut r = ServerNameResolver::new();
        r.add_wildcard("example.com", key.clone());

        // bare suffix matches
        assert!(r.lookup("example.com", ALL_SCHEMES).is_some());
        // subdomain matches
        assert!(r.lookup("foo.example.com", ALL_SCHEMES).is_some());
        // multi-label subdomain matches (nginx parity)
        assert!(r.lookup("a.b.example.com", ALL_SCHEMES).is_some());
        // unrelated suffix does not match
        assert!(r.lookup("notexample.com", ALL_SCHEMES).is_none());
        assert!(r.lookup("example.org", ALL_SCHEMES).is_none());
    }

    #[test]
    fn resolver_exact_beats_wildcard() {
        let exact = ck(RSA_CRT, RSA_KEY_PKCS8);
        let wild = ck(ALT_CRT, ALT_KEY);
        let mut r = ServerNameResolver::new();
        r.add_wildcard("ruxen.local", wild.clone());
        r.add_exact("test.ruxen.local", exact.clone());

        let got = r.lookup("test.ruxen.local", ALL_SCHEMES).expect("hit");
        assert!(Arc::ptr_eq(&got, &exact));

        let got = r.lookup("other.ruxen.local", ALL_SCHEMES).expect("hit");
        assert!(Arc::ptr_eq(&got, &wild));
    }

    #[test]
    fn resolver_default_fallback() {
        let default = ck(RSA_CRT, RSA_KEY_PKCS8);
        let mut r = ServerNameResolver::new();
        r.set_default(vec![default.clone()]);

        // `lookup` only handles SNI hits; the default path is exercised
        // through the public `resolve` trait method, but constructing a
        // `ClientHello` requires private fields. Verify the storage and
        // the `select` helper directly instead.
        let got = ServerNameResolver::select(&r.default, ALL_SCHEMES).expect("default");
        assert!(Arc::ptr_eq(&got, &default));
    }

    #[test]
    fn resolver_multi_cert_picks_by_signature_scheme() {
        let rsa = ck(RSA_CRT, RSA_KEY_PKCS8);
        let ec = ck(EC_CRT, EC_KEY_PKCS8);
        let mut r = ServerNameResolver::new();
        // Register RSA first, then ECDSA, under the same hostname.
        r.add_exact("test.ruxen.local", rsa.clone());
        r.add_exact("test.ruxen.local", ec.clone());

        // Client only offers ECDSA — should pick the ECDSA cert even
        // though RSA was registered first.
        let ecdsa_only = &[SignatureScheme::ECDSA_NISTP256_SHA256];
        let got = r.lookup("test.ruxen.local", ecdsa_only).expect("hit");
        assert!(Arc::ptr_eq(&got, &ec));

        // Client only offers RSA — should pick the RSA cert.
        let rsa_only = &[SignatureScheme::RSA_PSS_SHA256];
        let got = r.lookup("test.ruxen.local", rsa_only).expect("hit");
        assert!(Arc::ptr_eq(&got, &rsa));
    }

    #[test]
    fn resolver_falls_through_when_no_scheme_matches() {
        let rsa = ck(RSA_CRT, RSA_KEY_PKCS8);
        let mut r = ServerNameResolver::new();
        r.add_exact("test.ruxen.local", rsa.clone());

        // Client offers only schemes the RSA key doesn't speak; we still
        // hand it back so rustls produces a clear handshake alert.
        let unsupported = &[SignatureScheme::ED25519];
        let got = r.lookup("test.ruxen.local", unsupported).expect("hit");
        assert!(Arc::ptr_eq(&got, &rsa));
    }

    #[test]
    fn build_server_config_accepts_default_protocols() {
        let key = ck(RSA_CRT, RSA_KEY_PKCS8);
        let mut r = ServerNameResolver::new();
        r.add_exact("test.ruxen.local", key);
        let cfg = build_server_config(r, TlsVersionSet::default(), None, Default::default())
            .expect("default protocols build");
        assert_eq!(cfg.alpn_protocols, vec![b"http/1.1".to_vec()]);
    }

    #[test]
    fn session_resumption_follows_nginx() {
        use crate::config::SessionResumption;
        let build = |cache, tickets| {
            let mut r = ServerNameResolver::new();
            r.set_default(vec![ck(RSA_CRT, RSA_KEY_PKCS8)]);
            build_server_config(
                r,
                TlsVersionSet::default(),
                None,
                SessionResumption { cache, tickets },
            )
            .unwrap()
        };
        // nginx's defaults: no session-ID cache, tickets on.
        let cfg = build(None, None);
        assert!(!cfg.session_storage.can_cache());
        assert!(cfg.ticketer.enabled());
        // ssl_session_cache shared:…, tickets off: resumption by session ID.
        let cfg = build(Some(true), Some(false));
        assert!(cfg.session_storage.can_cache());
        assert!(!cfg.ticketer.enabled());
        assert_ne!(cfg.send_tls13_tickets, 0);
        // off/none + tickets off: nothing to resume, no tickets sent.
        let cfg = build(Some(false), Some(false));
        assert!(!cfg.session_storage.can_cache());
        assert!(!cfg.ticketer.enabled());
        assert_eq!(cfg.send_tls13_tickets, 0);
    }

    #[test]
    fn build_server_config_rejects_empty_protocol_set() {
        let r = ServerNameResolver::new();
        let empty = TlsVersionSet {
            tlsv1_2: false,
            tlsv1_3: false,
        };
        let err = build_server_config(r, empty, None, Default::default())
            .expect_err("empty set rejected");
        assert!(matches!(err, rustls::Error::General(_)));
    }
}
