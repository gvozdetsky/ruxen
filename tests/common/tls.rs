// Ephemeral cert generation for HTTPS integration tests.
//
// Everything is materialized at test start under a per-test tempdir that
// `CertSet::Drop` removes. No checked-in `.pem` files: that avoids the
// perpetual "is this cert expired?" question and keeps the SAN list
// in-source next to the test that needs it.
//
// rcgen is a sync, pure-Rust generator — no tokio creep.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose};

/// Files written into the per-test tempdir. The tempdir is removed when
/// the `CertSet` is dropped.
pub struct CertSet {
    dir: PathBuf,
    /// PEM cert chain — for `ssl_certificate`. For CA-signed leaves this
    /// is `leaf || ca` so curl `--cacert ca.pem` works against the chain.
    pub cert_path: PathBuf,
    /// PKCS#8 private key — for `ssl_certificate_key`.
    pub key_path: PathBuf,
    /// CA root (only set for `make_ca_and_leaf` / `make_wildcard`). Pass
    /// to clients via `--cacert` so they can verify without `-k`.
    pub ca_path: Option<PathBuf>,
}

impl CertSet {
    pub fn cert_path(&self) -> &Path {
        &self.cert_path
    }
    pub fn key_path(&self) -> &Path {
        &self.key_path
    }
    pub fn ca_path(&self) -> Option<&Path> {
        self.ca_path.as_deref()
    }
}

impl Drop for CertSet {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn unique_dir(tag: &str) -> PathBuf {
    static N: AtomicU64 = AtomicU64::new(0);
    let d = std::env::temp_dir().join(format!(
        "ruxen-tls-{tag}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir(&d).expect("create cert tempdir");
    d
}

/// Single self-signed cert for `cn` (also used as the SAN — curl rejects
/// CN-only matching since RFC 6125, so the SAN is what actually matters).
pub fn make_self_signed(cn: &str) -> CertSet {
    let dir = unique_dir("ss");
    let key = KeyPair::generate().expect("generate keypair");

    let mut params = CertificateParams::new(vec![cn.to_string()]).expect("cert params");
    params.distinguished_name.push(DnType::CommonName, cn);
    let cert = params.self_signed(&key).expect("self-sign");

    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    std::fs::write(&cert_path, cert.pem()).expect("write cert");
    std::fs::write(&key_path, key.serialize_pem()).expect("write key");

    CertSet {
        dir,
        cert_path,
        key_path,
        ca_path: None,
    }
}

/// Copy a checked-in PEM pair (e.g. from `src/testdata/tls/`) into a
/// tempdir, for certificates rcgen can't make, such as X.509 v1.
pub fn from_pem_files(cert: &Path, key: &Path) -> CertSet {
    let dir = unique_dir("pem");
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    std::fs::copy(cert, &cert_path).expect("copy cert");
    std::fs::copy(key, &key_path).expect("copy key");
    CertSet {
        dir,
        cert_path,
        key_path,
        ca_path: None,
    }
}

/// CA + leaf signed by it. Lets curl verify with `--cacert` instead of `-k`.
/// `cert.pem` is the concatenated `leaf || ca` chain (nginx-style).
pub fn make_ca_and_leaf(cn: &str) -> CertSet {
    make_ca_signed_for_sans(cn, &[cn.to_string()], "ca")
}

/// CA + wildcard leaf for `*.<domain>`. Used by SNI wildcard tests.
pub fn make_wildcard(domain: &str) -> CertSet {
    let wildcard = format!("*.{domain}");
    make_ca_signed_for_sans(&wildcard, &[wildcard.clone(), domain.to_string()], "wc")
}

fn make_ca_signed_for_sans(cn: &str, sans: &[String], tag: &str) -> CertSet {
    let dir = unique_dir(tag);

    let ca_key = KeyPair::generate().expect("generate ca key");
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
    ca_params
        .distinguished_name
        .push(DnType::CommonName, format!("ruxen-test-ca-{tag}"));
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    ca_params.key_usages.push(KeyUsagePurpose::CrlSign);
    let ca_cert = ca_params.self_signed(&ca_key).expect("self-sign ca");
    let ca_issuer = Issuer::new(ca_params, ca_key);

    let leaf_key = KeyPair::generate().expect("generate leaf key");
    let mut leaf_params = CertificateParams::new(sans.to_vec()).expect("leaf params");
    leaf_params.distinguished_name.push(DnType::CommonName, cn);
    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &ca_issuer)
        .expect("sign leaf");

    // nginx-style chain: leaf first, intermediates/root after.
    let mut chain_pem = leaf_cert.pem();
    chain_pem.push_str(&ca_cert.pem());

    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    let ca_path = dir.join("ca.pem");
    std::fs::write(&cert_path, chain_pem).expect("write cert chain");
    std::fs::write(&key_path, leaf_key.serialize_pem()).expect("write key");
    std::fs::write(&ca_path, ca_cert.pem()).expect("write ca");

    CertSet {
        dir,
        cert_path,
        key_path,
        ca_path: Some(ca_path),
    }
}
