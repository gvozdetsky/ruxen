//! `ssl_ciphers`: OpenSSL's cipher-list language, evaluated over the TLS 1.2
//! suites rustls has, so a configuration's list restricts and orders them as
//! it would under nginx. rustls offers six TLS 1.2 suites, all ECDHE with
//! AES-GCM or ChaCha20-Poly1305; every weaker suite a list may name (CBC,
//! DHE, RSA key exchange, …) simply isn't there, as if the list had excluded
//! it. TLS 1.3 suites aren't affected, as in OpenSSL, where `ssl_ciphers`
//! sets only the TLS 1.2 list.
//!
//! The rules, as OpenSSL's `ssl_cipher_process_rulestr` applies them (and as
//! `openssl ciphers -tls1_2` 3.5 lists them for the test vectors below):
//! elements separated by `:`, `,`, `;` or spaces; `A+B` selects the suites
//! that match both; a plain element appends the matching suites not yet in
//! the list, in OpenSSL's own order; `-X` removes them, `!X` removes them for
//! good, `+X` moves them to the end; `@STRENGTH` sorts by key length;
//! anything else (`@SECLEVEL=n`, a name OpenSSL knows but rustls hasn't, or
//! a typo) selects nothing.

use rustls::CipherSuite as C;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Auth {
    Ecdsa,
    Rsa,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Enc {
    Aes128Gcm,
    Aes256Gcm,
    Chacha20,
}

struct Suite {
    id: C,
    name: &'static str,
    auth: Auth,
    enc: Enc,
}

/// In OpenSSL's order (what `ALL` lists): AES-256-GCM, ChaCha20, AES-128-GCM,
/// ECDSA before RSA.
const SUITES: [Suite; 6] = [
    Suite {
        id: C::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        name: "ECDHE-ECDSA-AES256-GCM-SHA384",
        auth: Auth::Ecdsa,
        enc: Enc::Aes256Gcm,
    },
    Suite {
        id: C::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        name: "ECDHE-RSA-AES256-GCM-SHA384",
        auth: Auth::Rsa,
        enc: Enc::Aes256Gcm,
    },
    Suite {
        id: C::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        name: "ECDHE-ECDSA-CHACHA20-POLY1305",
        auth: Auth::Ecdsa,
        enc: Enc::Chacha20,
    },
    Suite {
        id: C::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        name: "ECDHE-RSA-CHACHA20-POLY1305",
        auth: Auth::Rsa,
        enc: Enc::Chacha20,
    },
    Suite {
        id: C::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        name: "ECDHE-ECDSA-AES128-GCM-SHA256",
        auth: Auth::Ecdsa,
        enc: Enc::Aes128Gcm,
    },
    Suite {
        id: C::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        name: "ECDHE-RSA-AES128-GCM-SHA256",
        auth: Auth::Rsa,
        enc: Enc::Aes128Gcm,
    },
];

/// Whether OpenSSL's alias or cipher name `word` selects `s`. All six are
/// ECDHE, AEAD and `HIGH`; key exchange `RSA` (`kRSA`), `DHE`, `NULL`, the
/// CBC MACs and the weak ciphers select none of them.
fn matches(word: &str, s: &Suite) -> bool {
    match word {
        "ALL" | "DEFAULT" | "HIGH" | "TLSv1.2" | "kECDHE" | "kEECDH" | "ECDHE" | "EECDH"
        | "ECDH" => true,
        "aRSA" => s.auth == Auth::Rsa,
        "aECDSA" | "ECDSA" => s.auth == Auth::Ecdsa,
        "AESGCM" | "AES" => s.enc != Enc::Chacha20,
        "AES128" => s.enc == Enc::Aes128Gcm,
        "AES256" => s.enc == Enc::Aes256Gcm,
        "CHACHA20" => s.enc == Enc::Chacha20,
        name => name == s.name,
    }
}

/// The TLS 1.2 suites `rule` selects, in order (the server's preference
/// with `ssl_prefer_server_ciphers on`).
pub fn select_tls12(rule: &str) -> Vec<C> {
    let mut list: Vec<usize> = Vec::new();
    let mut killed = [false; SUITES.len()];
    for element in rule.split([':', ',', ';', ' ']).filter(|e| !e.is_empty()) {
        if element == "@STRENGTH" {
            // Stable, by key length: AES-128 last, as OpenSSL counts
            // ChaCha20 as 256 bits.
            list.sort_by_key(|&i| SUITES[i].enc == Enc::Aes128Gcm);
            continue;
        }
        let (op, words) = match element.as_bytes()[0] {
            b'!' | b'-' | b'+' => (element.as_bytes()[0], &element[1..]),
            _ => (0, element),
        };
        let selected: Vec<usize> = (0..SUITES.len())
            .filter(|&i| words.split('+').all(|w| matches(w, &SUITES[i])))
            .collect();
        match op {
            b'!' => {
                list.retain(|i| !selected.contains(i));
                for &i in &selected {
                    killed[i] = true;
                }
            }
            b'-' => list.retain(|i| !selected.contains(i)),
            b'+' => {
                let (moved, kept): (Vec<usize>, Vec<usize>) =
                    list.iter().partition(|i| selected.contains(i));
                list = kept;
                list.extend(moved);
            }
            _ => {
                for i in selected {
                    if !killed[i] && !list.contains(&i) {
                        list.push(i);
                    }
                }
            }
        }
    }
    list.into_iter().map(|i| SUITES[i].id).collect()
}

/// A server's `ssl_ciphers` and `ssl_prefer_server_ciphers`: the TLS 1.2
/// suites (`None`: rustls's, the list unset) and whose order picks one.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Policy {
    pub tls12: Option<Vec<C>>,
    /// `ssl_prefer_server_ciphers on`: the server's order, else the
    /// client's, as rustls's `ignore_client_order` (nginx's default is off).
    pub server_order: bool,
}

impl Policy {
    pub fn of(ciphers: Option<&str>, prefer_server_ciphers: Option<bool>) -> Policy {
        Policy {
            tls12: ciphers.map(select_tls12),
            server_order: prefer_server_ciphers.unwrap_or(false),
        }
    }

    /// The versions to offer: without a TLS 1.2 suite left, TLS 1.3 alone,
    /// with a warning; nothing at all is an error. `what` names the server.
    pub fn versions(
        &self,
        mut versions: crate::config::TlsVersionSet,
        ciphers: Option<&str>,
        warn: &mut dyn FnMut(String),
    ) -> Result<crate::config::TlsVersionSet, String> {
        if versions.tlsv1_2 && self.tls12.as_ref().is_some_and(Vec::is_empty) {
            let list = ciphers.unwrap_or_default();
            if !versions.tlsv1_3 {
                return Err(format!(
                    "\"ssl_ciphers\" \"{list}\" selects none of the TLS 1.2 cipher suites ruxen \
                     has ({}), and TLS 1.3 is off",
                    SUITES.map(|s| s.name).join(", ")
                ));
            }
            warn(format!(
                "\"ssl_ciphers\" \"{list}\" selects none of the TLS 1.2 cipher suites ruxen \
                 has ({}): only TLS 1.3 is offered",
                SUITES.map(|s| s.name).join(", ")
            ));
            versions.tlsv1_2 = false;
        }
        Ok(versions)
    }
}

/// `base` with its TLS 1.2 suites replaced by `tls12`, in that order; its
/// TLS 1.3 suites stay as they are.
pub fn provider_with_tls12(
    base: &rustls::crypto::CryptoProvider,
    tls12: &[C],
) -> rustls::crypto::CryptoProvider {
    let mut provider = base.clone();
    let tls13 = base
        .cipher_suites
        .iter()
        .copied()
        .filter(|s| s.version() == &rustls::version::TLS13);
    let chosen = tls12.iter().filter_map(|id| {
        base.cipher_suites
            .iter()
            .copied()
            .find(|s| s.suite() == *id && s.version() == &rustls::version::TLS12)
    });
    provider.cipher_suites = tls13.chain(chosen).collect();
    provider
}

#[cfg(test)]
mod tests {
    use super::*;

    const E256: &str = "ECDHE-ECDSA-AES256-GCM-SHA384";
    const R256: &str = "ECDHE-RSA-AES256-GCM-SHA384";
    const ECH: &str = "ECDHE-ECDSA-CHACHA20-POLY1305";
    const RCH: &str = "ECDHE-RSA-CHACHA20-POLY1305";
    const E128: &str = "ECDHE-ECDSA-AES128-GCM-SHA256";
    const R128: &str = "ECDHE-RSA-AES128-GCM-SHA256";

    fn names(rule: &str) -> Vec<&'static str> {
        select_tls12(rule)
            .into_iter()
            .map(|id| SUITES.iter().find(|s| s.id == id).unwrap().name)
            .collect()
    }

    /// What `openssl ciphers -tls1_2 RULE` (OpenSSL 3.5.5) lists of these
    /// six, in its order.
    #[test]
    fn as_openssl_lists_them() {
        let all = vec![E256, R256, ECH, RCH, E128, R128];
        for (rule, want) in [
            ("HIGH:!aNULL:!MD5", all.clone()),
            ("ALL", all.clone()),
            ("DEFAULT", all.clone()),
            ("ALL:@STRENGTH", all.clone()),
            ("HIGH:+AES128", all.clone()),
            ("HIGH:-AES128:AES128", all.clone()),
            ("RSA", vec![]),
            ("kRSA", vec![]),
            ("ECDHE+RSA", vec![]),
            ("SHA256", vec![]),
            ("aNULL", vec![]),
            ("MEDIUM", vec![]),
            ("FOO", vec![]),
            ("DHE-RSA-AES256-GCM-SHA384", vec![]),
            ("ecdhe-rsa-aes128-gcm-sha256", vec![]),
            ("aRSA", vec![R256, RCH, R128]),
            ("ECDSA", vec![E256, ECH, E128]),
            ("AESGCM", vec![E256, R256, E128, R128]),
            ("AES128", vec![E128, R128]),
            ("CHACHA20", vec![ECH, RCH]),
            ("EECDH+AESGCM:EDH+AESGCM", vec![E256, R256, E128, R128]),
            (
                "ECDHE+AESGCM:ECDHE+CHACHA20",
                vec![E256, R256, E128, R128, ECH, RCH],
            ),
            ("HIGH:!AES128:AES128", vec![E256, R256, ECH, RCH]),
            ("!ECDSA:HIGH", vec![R256, RCH, R128]),
            (
                "HIGH:!ECDHE-RSA-AES128-GCM-SHA256",
                vec![E256, R256, ECH, RCH, E128],
            ),
            ("AESGCM+ECDSA:CHACHA20", vec![E256, E128, ECH, RCH]),
            ("ALL:-ECDSA:+aECDSA", vec![R256, RCH, R128]),
            ("kECDHE+aRSA", vec![R256, RCH, R128]),
            ("ECDHE+AES128:ECDHE+AES256", vec![E128, R128, E256, R256]),
            ("FOO:ECDHE-RSA-AES128-GCM-SHA256", vec![R128]),
            (
                "TLS_AES_128_GCM_SHA256:ECDHE-RSA-AES128-GCM-SHA256",
                vec![R128],
            ),
            (
                "ECDHE-RSA-AES128-GCM-SHA256 ECDHE-ECDSA-AES128-GCM-SHA256",
                vec![R128, E128],
            ),
            (
                "ECDHE-RSA-AES128-GCM-SHA256,ECDHE-ECDSA-AES128-GCM-SHA256",
                vec![R128, E128],
            ),
            (
                "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384",
                vec![R128, E256],
            ),
            // Certbot's options-ssl-nginx.conf and Mozilla's intermediate.
            (
                "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:\
                 ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:\
                 ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:\
                 DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384",
                vec![E128, R128, E256, R256, ECH, RCH],
            ),
        ] {
            assert_eq!(names(rule), want, "{rule}");
        }
    }

    #[test]
    fn the_provider_keeps_tls13_and_takes_the_tls12_order() {
        let base = rustls::crypto::aws_lc_rs::default_provider();
        let p = provider_with_tls12(&base, &select_tls12("AES128:CHACHA20"));
        let tls12: Vec<C> = p
            .cipher_suites
            .iter()
            .filter(|s| s.version() == &rustls::version::TLS12)
            .map(|s| s.suite())
            .collect();
        assert_eq!(
            tls12,
            [
                C::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                C::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                C::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                C::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            ]
        );
        let tls13 = |p: &rustls::crypto::CryptoProvider| -> Vec<C> {
            p.cipher_suites
                .iter()
                .filter(|s| s.version() == &rustls::version::TLS13)
                .map(|s| s.suite())
                .collect()
        };
        assert_eq!(tls13(&p), tls13(&base));
    }
}
