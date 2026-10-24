//! Standard `ClientHello` templates used by the probes.

use testls_data::cipher_suites;
use testls_wire::{
    ClientHello, EncodeError, Extension, KeyShareEntry, ProtocolVersion, Ssl2ClientHello,
};

/// `TLS_EMPTY_RENEGOTIATION_INFO_SCSV`.
pub const EMPTY_RENEGOTIATION_INFO_SCSV: u16 = 0x00ff;
/// `TLS_FALLBACK_SCSV`.
pub const FALLBACK_SCSV: u16 = 0x5600;

/// `x25519`.
pub const GROUP_X25519: u16 = 0x001d;

/// Groups offered in `supported_groups`.
pub const DEFAULT_GROUPS: &[u16] = &[
    GROUP_X25519,
    0x0017, // secp256r1
    0x0018, // secp384r1
    0x0019, // secp521r1
    0x001e, // x448
    0x0100, // ffdhe2048
    0x0101, // ffdhe3072
    0x0102, // ffdhe4096
];

/// Signature schemes offered in `signature_algorithms`.
pub const DEFAULT_SIGNATURE_SCHEMES: &[u16] = &[
    0x0403, 0x0503, 0x0603, // ecdsa_secp{256,384,521}r1_sha{256,384,512}
    0x0804, 0x0805, 0x0806, // rsa_pss_rsae_sha{256,384,512}
    0x0807, 0x0808, // ed25519, ed448
    0x0809, 0x080a, 0x080b, // rsa_pss_pss_sha{256,384,512}
    0x0401, 0x0501, 0x0601, // rsa_pkcs1_sha{256,384,512}
    0x0201, 0x0203, // rsa_pkcs1_sha1, ecdsa_sha1
];

/// All SSLv2 cipher specs.
pub const SSL2_CIPHER_SPECS: &[u32] = &[
    0x01_0080, // SSL_CK_RC4_128_WITH_MD5
    0x02_0080, // SSL_CK_RC4_128_EXPORT40_WITH_MD5
    0x03_0080, // SSL_CK_RC2_128_CBC_WITH_MD5
    0x04_0080, // SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5
    0x05_0080, // SSL_CK_IDEA_128_CBC_WITH_MD5
    0x06_0040, // SSL_CK_DES_64_CBC_WITH_MD5
    0x07_00c0, // SSL_CK_DES_192_EDE3_CBC_WITH_MD5
];

/// Whether `id` is a TLS 1.3 cipher suite (`TLS_AES_*`, `TLS_CHACHA20_*`, ...).
#[must_use]
pub fn is_tls13_suite(id: u16) -> bool {
    id >> 8 == 0x13
}

/// Whether `id` is a signalling value rather than a real cipher suite.
#[must_use]
pub fn is_scsv(id: u16) -> bool {
    matches!(id, EMPTY_RENEGOTIATION_INFO_SCSV | FALLBACK_SCSV)
}

/// Every registered SSLv3–TLS 1.2 cipher suite.
#[must_use]
pub fn legacy_suites() -> Vec<u16> {
    cipher_suites()
        .iter()
        .map(|c| c.id)
        .filter(|&id| !is_tls13_suite(id) && !is_scsv(id))
        .collect()
}

/// Every registered TLS 1.3 cipher suite.
#[must_use]
pub fn tls13_suites() -> Vec<u16> {
    cipher_suites()
        .iter()
        .map(|c| c.id)
        .filter(|&id| is_tls13_suite(id))
        .collect()
}

fn random<const N: usize>() -> [u8; N] {
    let mut buf = [0; N];
    // Probe randomness only needs to be unpredictable enough to avoid
    // caching quirks; fall back to a fixed pattern if the OS RNG fails.
    if getrandom::fill(&mut buf).is_err() {
        buf.fill(0x5a);
    }
    buf
}

/// A `ClientHello` for `version` offering `suites`.
///
/// SSLv3 hellos carry no extensions. TLS 1.3 hellos use
/// `supported_versions` with only TLS 1.3 and an `x25519` key share.
#[must_use]
pub fn client_hello(version: ProtocolVersion, suites: Vec<u16>, sni: Option<&str>) -> ClientHello {
    let tls13 = version >= ProtocolVersion::TLS13;
    let legacy_version = if tls13 {
        ProtocolVersion::TLS12
    } else {
        version
    };
    let mut extensions = Vec::new();
    if version > ProtocolVersion::SSL3 {
        if let Some(name) = sni {
            extensions.push(Extension::ServerName(name.to_owned()));
        }
        extensions.push(Extension::SupportedGroups(DEFAULT_GROUPS.to_vec()));
        extensions.push(Extension::EcPointFormats(vec![0]));
        extensions.push(Extension::SignatureAlgorithms(
            DEFAULT_SIGNATURE_SCHEMES.to_vec(),
        ));
        extensions.push(Extension::RenegotiationInfo);
    }
    if tls13 {
        extensions.push(Extension::SupportedVersions(vec![version]));
        extensions.push(Extension::KeyShare(vec![KeyShareEntry {
            group: GROUP_X25519,
            key_exchange: random::<32>().to_vec(),
        }]));
    }
    ClientHello {
        record_version: ProtocolVersion::TLS10.min(legacy_version),
        version: legacy_version,
        random: random(),
        session_id: if tls13 {
            random::<32>().to_vec()
        } else {
            Vec::new()
        },
        cipher_suites: suites,
        compression_methods: vec![0],
        extensions,
    }
}

/// Like [`client_hello`], but offering exactly `groups` in
/// `supported_groups`.
///
/// TLS 1.3 hellos carry an empty `key_share` list, which RFC 8446 §4.2.8
/// allows: a server that supports one of `groups` must answer with a
/// `HelloRetryRequest` naming its choice, so no key material is needed.
#[must_use]
pub fn group_hello(
    version: ProtocolVersion,
    suites: Vec<u16>,
    groups: &[u16],
    sni: Option<&str>,
) -> ClientHello {
    let mut hello = client_hello(version, suites, sni);
    for ext in &mut hello.extensions {
        match ext {
            Extension::SupportedGroups(g) => *g = groups.to_vec(),
            Extension::KeyShare(shares) => shares.clear(),
            _ => {}
        }
    }
    hello
}

/// An SSLv2 `CLIENT-HELLO` offering every SSLv2 cipher spec.
///
/// # Errors
/// Never fails in practice; propagates [`EncodeError`] from the encoder.
pub fn ssl2_client_hello() -> Result<Vec<u8>, EncodeError> {
    Ssl2ClientHello {
        version: ProtocolVersion::SSL2,
        cipher_specs: SSL2_CIPHER_SPECS.to_vec(),
        session_id: Vec::new(),
        challenge: random::<16>().to_vec(),
    }
    .encode()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suite_partition() {
        let legacy = legacy_suites();
        let modern = tls13_suites();
        assert!(legacy.contains(&0xc02f));
        assert!(!legacy.contains(&FALLBACK_SCSV));
        assert!(!legacy.contains(&0x1301));
        assert!(modern.contains(&0x1301));
    }

    #[test]
    fn ssl3_hello_has_no_extensions() {
        let h = client_hello(ProtocolVersion::SSL3, vec![0x000a], Some("example.com"));
        assert_eq!(h.extensions, vec![]);
        assert_eq!(h.record_version, ProtocolVersion::SSL3);
    }

    #[test]
    fn tls13_hello_shape() {
        let h = client_hello(ProtocolVersion::TLS13, tls13_suites(), Some("example.com"));
        assert_eq!(h.version, ProtocolVersion::TLS12);
        assert_eq!(h.record_version, ProtocolVersion::TLS10);
        assert_eq!(h.session_id.len(), 32);
        assert!(
            h.extensions
                .contains(&Extension::SupportedVersions(vec![ProtocolVersion::TLS13]))
        );
        assert!(h.encode().is_ok());
    }

    /// `group_hello` replaces the group list and empties the key shares.
    #[test]
    fn group_hello_shape() {
        let h = group_hello(ProtocolVersion::TLS13, tls13_suites(), &[0x11ec], None);
        assert!(
            h.extensions
                .contains(&Extension::SupportedGroups(vec![0x11ec]))
        );
        assert!(h.extensions.contains(&Extension::KeyShare(vec![])));
        assert!(h.encode().is_ok());
        let h = group_hello(ProtocolVersion::TLS12, vec![0xc02f], &[0x0017], None);
        assert!(
            h.extensions
                .contains(&Extension::SupportedGroups(vec![0x0017]))
        );
    }

    #[test]
    fn ssl2_hello_encodes() {
        let bytes = ssl2_client_hello().unwrap();
        assert_eq!(bytes[0] & 0x80, 0x80);
        assert_eq!(bytes[2], 1);
    }
}
