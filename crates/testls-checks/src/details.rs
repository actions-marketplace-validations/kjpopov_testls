//! Findings for extended master secret, the TLS 1.3 downgrade sentinel and
//! 0-RTT.

use testls_probe::HandshakeDetails;

use crate::{Finding, Severity};

/// Turns handshake detail probe results into findings.
///
/// A TLS 1.2-or-older handshake without extended master secret is open to
/// triple handshake attacks (RFC 7627 §1), a TLS 1.3 server that omits the
/// downgrade sentinel lets an attacker force an older version undetected
/// (RFC 8446 §4.1.3), and 0-RTT data can be replayed (RFC 8446 §8).
/// Untested details produce nothing.
#[must_use]
pub fn details_findings(details: &HandshakeDetails) -> Vec<Finding> {
    let version = details
        .legacy_version
        .map_or_else(String::new, |v| format!("{v}: "));
    let mut findings = Vec::new();
    if details.extended_master_secret == Some(false) {
        findings.push(Finding::new(
            "handshake.no_ems",
            Severity::Low,
            format!("{version}no extended master secret (RFC 7627)"),
        ));
    }
    if details.downgrade_sentinel == Some(false) {
        findings.push(Finding::new(
            "handshake.no_downgrade_sentinel",
            Severity::Medium,
            format!("{version}TLSv1.3 server omits the downgrade sentinel (RFC 8446 §4.1.3)"),
        ));
    }
    if let Some(size) = details.max_early_data.filter(|&s| s > 0) {
        findings.push(Finding::new(
            "handshake.early_data",
            Severity::Info,
            format!("TLSv1.3: 0-RTT early data accepted (up to {size} bytes), replayable"),
        ));
    }
    findings
}

#[cfg(test)]
mod tests {
    //! Unit tests for handshake detail findings.

    use testls_wire::ProtocolVersion;

    use super::*;

    /// A fully protected server without 0-RTT.
    fn good() -> HandshakeDetails {
        HandshakeDetails {
            legacy_version: Some(ProtocolVersion::TLS12),
            extended_master_secret: Some(true),
            downgrade_sentinel: Some(true),
            session_tickets: Some(true),
            max_early_data: Some(0),
        }
    }

    /// Protected and untested servers produce no findings.
    #[test]
    fn protected_or_untested() {
        assert_eq!(details_findings(&good()), []);
        let untested = HandshakeDetails {
            legacy_version: None,
            extended_master_secret: None,
            downgrade_sentinel: None,
            session_tickets: None,
            max_early_data: None,
        };
        assert_eq!(details_findings(&untested), []);
    }

    /// Each weakness yields its own finding.
    #[test]
    fn weaknesses() {
        let details = HandshakeDetails {
            extended_master_secret: Some(false),
            downgrade_sentinel: Some(false),
            max_early_data: Some(16384),
            ..good()
        };
        let findings = details_findings(&details);
        let summary: Vec<_> = findings
            .iter()
            .map(|f| (f.id.as_str(), f.severity, f.message.as_str()))
            .collect();
        assert_eq!(
            summary,
            [
                (
                    "handshake.no_ems",
                    Severity::Low,
                    "TLSv1.2: no extended master secret (RFC 7627)"
                ),
                (
                    "handshake.no_downgrade_sentinel",
                    Severity::Medium,
                    "TLSv1.2: TLSv1.3 server omits the downgrade sentinel (RFC 8446 §4.1.3)"
                ),
                (
                    "handshake.early_data",
                    Severity::Info,
                    "TLSv1.3: 0-RTT early data accepted (up to 16384 bytes), replayable"
                ),
            ]
        );
    }
}
