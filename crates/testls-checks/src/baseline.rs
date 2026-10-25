//! CA/Browser Forum Baseline Requirements checks for publicly trusted leaf
//! certificates: maximum validity period and embedded Certificate
//! Transparency timestamps.
//!
//! These rules only bind certificates from public CAs, so callers decide
//! whether a chain is publicly trusted before applying them.

use x509_parser::extensions::ParsedExtension;
use x509_parser::parse_x509_certificate;

use crate::{Finding, Severity};

/// Seconds in a day.
const DAY: i64 = 24 * 60 * 60;

/// Maximum validity period by issuance date, from Baseline Requirements
/// §6.3.2 as amended by ballot SC-081v3: `(issued from, limit in days)`,
/// latest first. 2026-03-15, 2027-03-15 and 2029-03-15 at 00:00 UTC.
const VALIDITY_LIMITS: [(i64, u32); 3] = [
    (1_867_795_200, 47),
    (1_804_982_400, 100),
    (1_773_532_800, 200),
];

/// Limit before the first SC-081v3 step (Baseline Requirements §6.3.2).
const LEGACY_LIMIT: u32 = 398;

/// One Signed Certificate Timestamp embedded in a certificate (RFC 6962
/// §3.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sct {
    /// SHA-256 hash of the log's public key.
    pub log_id: [u8; 32],
    /// Time the log saw the certificate, in milliseconds since the epoch.
    pub timestamp: u64,
}

/// Maximum validity period in days for a publicly trusted TLS certificate
/// whose `notBefore` is the Unix time `not_before` (Baseline Requirements
/// §6.3.2).
#[must_use]
pub fn max_validity_days(not_before: i64) -> u32 {
    VALIDITY_LIMITS
        .iter()
        .find(|(from, _)| not_before >= *from)
        .map_or(LEGACY_LIMIT, |(_, days)| *days)
}

/// Signed Certificate Timestamps embedded in the DER certificate `der`
/// (RFC 6962 §3.3); empty when the extension is absent.
///
/// # Errors
///
/// Returns a message when the certificate or the SCT list cannot be parsed.
pub fn embedded_scts(der: &[u8]) -> Result<Vec<Sct>, String> {
    let (_, cert) = parse_x509_certificate(der).map_err(|e| e.to_string())?;
    let mut scts = Vec::new();
    for ext in cert.extensions() {
        match ext.parsed_extension() {
            ParsedExtension::SCT(list) => scts.extend(list.iter().map(|sct| Sct {
                log_id: *sct.id.key_id,
                timestamp: sct.timestamp,
            })),
            ParsedExtension::UnsupportedExtension { .. } | ParsedExtension::ParseError { .. }
                if ext.oid.to_id_string() == "1.3.6.1.4.1.11129.2.4.2" =>
            {
                return Err("malformed SCT list".to_owned());
            }
            _ => {}
        }
    }
    Ok(scts)
}

/// Baseline Requirements findings for the leaf of a publicly trusted
/// `chain` (DER, leaf first).
///
/// Reports `cert.too_long` when the validity period exceeds the limit for
/// its issuance date, and `cert.no_sct` / `cert.sct_invalid` when the leaf
/// embeds no usable Certificate Transparency timestamps. SCTs delivered in
/// the TLS handshake or a stapled OCSP response are not seen here, so a
/// missing embedded SCT is informational.
#[must_use]
pub fn baseline_findings(chain: &[Vec<u8>]) -> Vec<Finding> {
    let Some(leaf) = chain.first() else {
        return Vec::new();
    };
    let Ok((_, cert)) = parse_x509_certificate(leaf) else {
        return Vec::new();
    };
    let mut findings = Vec::new();
    let validity = cert.validity();
    let not_before = validity.not_before.timestamp();
    // The period includes both endpoints (Baseline Requirements §1.6.1).
    let seconds = validity.not_after.timestamp() - not_before;
    let limit = max_validity_days(not_before);
    if seconds + 1 > i64::from(limit) * DAY {
        let days = seconds / DAY;
        findings.push(Finding::new(
            "cert.too_long",
            Severity::Medium,
            format!(
                "certificate is valid for {days} days, more than the {limit} days allowed when issued on {} (CA/B BR §6.3.2)",
                validity.not_before
            ),
        ));
    }
    match embedded_scts(leaf) {
        Ok(scts) if scts.is_empty() => findings.push(Finding::new(
            "cert.no_sct",
            Severity::Info,
            "certificate embeds no Certificate Transparency timestamps",
        )),
        Ok(_) => {}
        Err(e) => findings.push(Finding::new(
            "cert.sct_invalid",
            Severity::Low,
            format!("embedded Certificate Transparency timestamps are unreadable: {e}"),
        )),
    }
    findings
}

#[cfg(test)]
mod tests {
    //! Unit tests for the Baseline Requirements checks.

    use super::*;

    /// Self-signed leaf valid 2026-04-01 to 2027-04-01 with two SCTs.
    const CT_SCTS: &[u8] = include_bytes!("testdata/ct-scts.der");
    /// Leaf valid 2026-01-01 to 2027-01-01 without SCTs.
    const EC_LOCALHOST: &[u8] = include_bytes!("testdata/ec-localhost.der");

    /// Finding ids for a single-certificate chain.
    fn ids(der: &[u8]) -> Vec<String> {
        baseline_findings(&[der.to_vec()])
            .into_iter()
            .map(|f| f.id)
            .collect()
    }

    /// Limits step down on the SC-081v3 dates.
    #[test]
    fn validity_limits() {
        assert_eq!(max_validity_days(1_773_532_799), 398);
        assert_eq!(max_validity_days(1_773_532_800), 200);
        assert_eq!(max_validity_days(1_804_982_399), 200);
        assert_eq!(max_validity_days(1_804_982_400), 100);
        assert_eq!(max_validity_days(1_867_795_200), 47);
    }

    /// Embedded SCTs are listed with log id and timestamp.
    #[test]
    fn scts() {
        let scts = embedded_scts(CT_SCTS).unwrap();
        assert_eq!(scts.len(), 2);
        assert_eq!(scts[0].log_id, [0x11; 32]);
        assert_eq!(scts[1].log_id, [0x22; 32]);
        assert_eq!(scts[0].timestamp, 1_775_001_600_000);
        assert_eq!(embedded_scts(EC_LOCALHOST).unwrap(), []);
        assert!(embedded_scts(b"junk").is_err());
    }

    /// A one-year certificate is fine before 2026-03-15 and too long after.
    #[test]
    fn findings() {
        assert_eq!(ids(EC_LOCALHOST), ["cert.no_sct"]);
        let findings = baseline_findings(&[CT_SCTS.to_vec()]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "cert.too_long");
        assert!(
            findings[0]
                .message
                .contains("365 days, more than the 200 days")
        );
        assert_eq!(baseline_findings(&[]), []);
        assert_eq!(ids(b"junk"), [] as [String; 0]);
    }
}
