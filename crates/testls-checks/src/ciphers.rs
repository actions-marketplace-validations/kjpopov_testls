//! Cipher suite checks.
//!
//! Suites are rated from the components of their IANA name.

use testls_probe::{CipherOrder, CipherResult};
use testls_wire::ProtocolVersion;

use crate::{Finding, Severity};

/// One rating rule: a weakness, the name fragments that reveal it, and why.
struct Rule {
    key: &'static str,
    severity: Severity,
    reason: &'static str,
    matches: fn(&str) -> bool,
}

const RULES: &[Rule] = &[
    Rule {
        key: "null",
        severity: Severity::Critical,
        reason: "no encryption",
        matches: |n| n.contains("_WITH_NULL_") || n == "TLS_NULL_WITH_NULL_NULL",
    },
    Rule {
        key: "integrity_only",
        severity: Severity::Critical,
        reason: "integrity only, no encryption (RFC 9150)",
        matches: |n| matches!(n, "TLS_SHA256_SHA256" | "TLS_SHA384_SHA384"),
    },
    Rule {
        key: "anon",
        severity: Severity::Critical,
        reason: "anonymous key exchange, no authentication",
        matches: |n| n.contains("_anon_"),
    },
    Rule {
        key: "export",
        severity: Severity::Critical,
        reason: "export-grade cryptography",
        matches: |n| n.contains("EXPORT"),
    },
    Rule {
        key: "rc4",
        severity: Severity::High,
        reason: "RC4 is prohibited (RFC 7465)",
        matches: |n| n.contains("_RC4_"),
    },
    Rule {
        key: "des",
        severity: Severity::High,
        reason: "single DES, 56-bit key",
        matches: |n| n.contains("_DES_CBC_") || n.contains("_DES40_"),
    },
    Rule {
        key: "rc2",
        severity: Severity::High,
        reason: "RC2 is obsolete",
        matches: |n| n.contains("_RC2_"),
    },
    Rule {
        key: "md5",
        severity: Severity::High,
        reason: "MD5 MAC",
        matches: |n| n.ends_with("_MD5"),
    },
    Rule {
        key: "3des",
        severity: Severity::Medium,
        reason: "64-bit block cipher, vulnerable to Sweet32",
        matches: |n| n.contains("_3DES_"),
    },
    Rule {
        key: "no_pfs",
        severity: Severity::Low,
        reason: "no forward secrecy",
        matches: |n| {
            n.starts_with("TLS_RSA_")
                || n.starts_with("TLS_PSK_")
                || n.starts_with("TLS_DH_")
                || n.starts_with("TLS_ECDH_")
                || n.starts_with("TLS_RSA_PSK_")
        },
    },
    Rule {
        key: "cbc",
        severity: Severity::Low,
        reason: "CBC mode",
        matches: |n| n.contains("_CBC_"),
    },
];

/// SSLv2 cipher spec names; every one of them is broken.
fn ssl2_name(id: u32) -> &'static str {
    match id {
        0x01_0080 => "SSL_CK_RC4_128_WITH_MD5",
        0x02_0080 => "SSL_CK_RC4_128_EXPORT40_WITH_MD5",
        0x03_0080 => "SSL_CK_RC2_128_CBC_WITH_MD5",
        0x04_0080 => "SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5",
        0x05_0080 => "SSL_CK_IDEA_128_CBC_WITH_MD5",
        0x06_0040 => "SSL_CK_DES_64_CBC_WITH_MD5",
        0x07_00c0 => "SSL_CK_DES_192_EDE3_CBC_WITH_MD5",
        _ => "unknown",
    }
}

/// Keys of all rating rules; findings use them as `cipher.{key}`.
#[cfg(test)]
pub(crate) fn rule_keys() -> impl Iterator<Item = &'static str> {
    RULES.iter().map(|r| r.key)
}

/// Whether suite `name` has the weakness of rule `key`.
pub(crate) fn has_weakness(key: &str, name: &str) -> bool {
    RULES.iter().any(|r| r.key == key && (r.matches)(name))
}

/// Id of the finding [`cipher_findings`] emits for suite `id` under
/// `version`, or `None` for a strong suite.
pub(crate) fn finding_id(version: ProtocolVersion, id: u32) -> Option<&'static str> {
    Some(match cipher_severity(version, id).1 {
        "strong" => return None,
        "ssl2" => "cipher.ssl2",
        "null" => "cipher.null",
        "integrity_only" => "cipher.integrity_only",
        "anon" => "cipher.anon",
        "export" => "cipher.export",
        "rc4" => "cipher.rc4",
        "des" => "cipher.des",
        "rc2" => "cipher.rc2",
        "md5" => "cipher.md5",
        "3des" => "cipher.3des",
        "no_pfs" => "cipher.no_pfs",
        "cbc" => "cipher.cbc",
        _ => "cipher.unknown",
    })
}

/// Name of a suite as reported for `version`, or `"unknown"`.
#[must_use]
pub fn cipher_name(version: ProtocolVersion, id: u32) -> &'static str {
    if version == ProtocolVersion::SSL2 {
        return ssl2_name(id);
    }
    u16::try_from(id)
        .ok()
        .and_then(testls_data::cipher_suite)
        .map_or("unknown", |c| c.name)
}

/// Worst weakness of suite `id` offered with `version`, as
/// `(severity, key, reason)`. Strong suites rate [`Severity::Ok`].
#[must_use]
pub fn cipher_severity(
    version: ProtocolVersion,
    id: u32,
) -> (Severity, &'static str, &'static str) {
    if version == ProtocolVersion::SSL2 {
        return (Severity::Critical, "ssl2", "SSLv2 cipher spec");
    }
    let name = cipher_name(version, id);
    if name == "unknown" {
        return (Severity::Info, "unknown", "unknown cipher suite");
    }
    RULES
        .iter()
        .filter(|r| (r.matches)(name))
        .max_by_key(|r| r.severity)
        .map_or((Severity::Ok, "strong", "strong"), |r| {
            (r.severity, r.key, r.reason)
        })
}

/// Findings for the accepted suites of one protocol version.
///
/// Emits one finding per weak suite and a note when the server does not
/// enforce its own preference order.
#[must_use]
pub fn cipher_findings(result: &CipherResult) -> Vec<Finding> {
    let v = result.version;
    let mut out: Vec<Finding> = result
        .suites
        .iter()
        .filter_map(|&id| {
            let (severity, key, reason) = cipher_severity(v, id);
            (severity > Severity::Ok).then(|| {
                Finding::new(
                    format!("cipher.{key}"),
                    severity,
                    format!("{v} {}: {reason}", cipher_name(v, id)),
                )
            })
        })
        .collect();
    if result.order == CipherOrder::Client {
        out.push(Finding::new(
            "cipher.client_order",
            Severity::Info,
            format!("{v}: server follows the client's cipher order"),
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sev(id: u32) -> Severity {
        cipher_severity(ProtocolVersion::TLS12, id).0
    }

    #[test]
    fn ratings() {
        // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        assert_eq!(sev(0xc02f), Severity::Ok);
        // TLS_AES_128_GCM_SHA256
        assert_eq!(
            cipher_severity(ProtocolVersion::TLS13, 0x1301).0,
            Severity::Ok
        );
        // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
        assert_eq!(sev(0xc013), Severity::Low);
        // TLS_RSA_WITH_AES_128_GCM_SHA256
        assert_eq!(cipher_severity(ProtocolVersion::TLS12, 0x009c).1, "no_pfs");
        // TLS_RSA_WITH_3DES_EDE_CBC_SHA
        assert_eq!(sev(0x000a), Severity::Medium);
        // TLS_RSA_WITH_RC4_128_SHA
        assert_eq!(sev(0x0005), Severity::High);
        // TLS_RSA_WITH_DES_CBC_SHA
        assert_eq!(sev(0x0009), Severity::High);
        // TLS_RSA_EXPORT_WITH_RC4_40_MD5
        assert_eq!(sev(0x0003), Severity::Critical);
        // TLS_DH_anon_WITH_AES_128_CBC_SHA
        assert_eq!(sev(0x0034), Severity::Critical);
        // TLS_RSA_WITH_NULL_SHA
        assert_eq!(sev(0x0002), Severity::Critical);
        // TLS_SHA256_SHA256
        assert_eq!(
            cipher_severity(ProtocolVersion::TLS13, 0xc0b4).0,
            Severity::Critical
        );
        assert_eq!(sev(0xfefe), Severity::Info);
        assert_eq!(
            cipher_severity(ProtocolVersion::SSL2, 0x01_0080).0,
            Severity::Critical
        );
    }

    #[test]
    fn findings() {
        let r = CipherResult {
            version: ProtocolVersion::TLS12,
            suites: vec![0xc02f, 0x000a],
            order: CipherOrder::Client,
        };
        let f = cipher_findings(&r);
        let ids: Vec<_> = f.iter().map(|f| f.id.as_str()).collect();
        assert_eq!(ids, ["cipher.3des", "cipher.client_order"]);
        assert_eq!(
            f[0].message,
            "TLSv1.2 TLS_RSA_WITH_3DES_EDE_CBC_SHA: 64-bit block cipher, vulnerable to Sweet32"
        );
    }
}
