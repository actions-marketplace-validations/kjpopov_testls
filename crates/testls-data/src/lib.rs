//! TLS registry data (cipher suites, named groups, signature schemes)
//! generated from IANA registry snapshots.
//!
//! The tables live in `generated.rs`, produced by `scripts/gen-iana.py`.

mod generated;

/// IANA "Recommended" column value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Recommended {
    /// `Y`: recommended by the IETF.
    Yes,
    /// `N` or empty: not evaluated / not recommended.
    No,
    /// `D`: discouraged.
    Discouraged,
}

/// A TLS cipher suite registry entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CipherSuiteInfo {
    /// Two-byte code point.
    pub id: u16,
    /// IANA name, e.g. `TLS_AES_128_GCM_SHA256`.
    pub name: &'static str,
    /// IANA recommendation.
    pub recommended: Recommended,
}

/// A TLS supported-groups registry entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GroupInfo {
    /// Two-byte code point.
    pub id: u16,
    /// IANA name, e.g. `x25519`.
    pub name: &'static str,
    /// IANA recommendation.
    pub recommended: Recommended,
}

/// A TLS signature scheme registry entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SignatureSchemeInfo {
    /// Two-byte code point.
    pub id: u16,
    /// IANA name, e.g. `ecdsa_secp256r1_sha256`.
    pub name: &'static str,
    /// IANA recommendation.
    pub recommended: Recommended,
}

/// All registered cipher suites, sorted by code point.
#[must_use]
pub fn cipher_suites() -> &'static [CipherSuiteInfo] {
    generated::CIPHER_SUITES
}

/// All registered named groups, sorted by code point.
#[must_use]
pub fn groups() -> &'static [GroupInfo] {
    generated::GROUPS
}

/// All registered signature schemes, sorted by code point.
#[must_use]
pub fn signature_schemes() -> &'static [SignatureSchemeInfo] {
    generated::SIGNATURE_SCHEMES
}

/// Look up a cipher suite by code point.
#[must_use]
pub fn cipher_suite(id: u16) -> Option<&'static CipherSuiteInfo> {
    let t = generated::CIPHER_SUITES;
    t.binary_search_by_key(&id, |c| c.id).ok().map(|i| &t[i])
}

/// Look up a named group by code point.
#[must_use]
pub fn group(id: u16) -> Option<&'static GroupInfo> {
    let t = generated::GROUPS;
    t.binary_search_by_key(&id, |g| g.id).ok().map(|i| &t[i])
}

/// Look up a signature scheme by code point.
#[must_use]
pub fn signature_scheme(id: u16) -> Option<&'static SignatureSchemeInfo> {
    let t = generated::SIGNATURE_SCHEMES;
    t.binary_search_by_key(&id, |s| s.id).ok().map(|i| &t[i])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tables_are_sorted_and_unique() {
        assert!(cipher_suites().windows(2).all(|w| w[0].id < w[1].id));
        assert!(groups().windows(2).all(|w| w[0].id < w[1].id));
        assert!(signature_schemes().windows(2).all(|w| w[0].id < w[1].id));
    }

    #[test]
    fn known_cipher_suites() {
        let c = cipher_suite(0x1301).unwrap();
        assert_eq!(c.name, "TLS_AES_128_GCM_SHA256");
        assert_eq!(c.recommended, Recommended::Yes);
        assert_eq!(
            cipher_suite(0xc02f).unwrap().name,
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
        );
        assert_eq!(
            cipher_suite(0x00ff).unwrap().name,
            "TLS_EMPTY_RENEGOTIATION_INFO_SCSV"
        );
        assert!(cipher_suite(0x0a0a).is_none(), "GREASE is not a suite");
    }

    #[test]
    fn known_groups_and_schemes() {
        assert_eq!(group(29).unwrap().name, "x25519");
        assert_eq!(group(0x11ec).unwrap().name, "X25519MLKEM768");
        assert_eq!(
            signature_scheme(0x0804).unwrap().name,
            "rsa_pss_rsae_sha256"
        );
    }
}
