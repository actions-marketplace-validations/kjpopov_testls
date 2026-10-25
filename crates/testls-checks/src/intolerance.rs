//! Findings for servers that reject well-formed but unusual `ClientHello`s.

use testls_probe::Intolerance;

use crate::{Finding, Severity};

/// One intolerance test: id, severity, result accessor and what was sent.
type Rule = (
    &'static str,
    Severity,
    fn(&Intolerance) -> Option<bool>,
    &'static str,
);

/// Each test, in report order. Rejecting unknown versions or extensions
/// breaks negotiation with future clients (RFC 8446 §4.1.2, §4.2), so it
/// rates higher than GREASE (RFC 8701 §3) or record size quirks
/// (RFC 8446 §5.1, RFC 7685).
const RULES: [Rule; 5] = [
    (
        "intolerance.unknown_version",
        Severity::Medium,
        |i| i.unknown_version,
        "an unknown future protocol version",
    ),
    (
        "intolerance.unknown_extension",
        Severity::Medium,
        |i| i.unknown_extension,
        "an unknown extension",
    ),
    (
        "intolerance.grease",
        Severity::Low,
        |i| i.grease,
        "GREASE values (RFC 8701)",
    ),
    (
        "intolerance.oversized",
        Severity::Low,
        |i| i.oversized,
        "a ClientHello filling a whole record",
    ),
    (
        "intolerance.fragmented",
        Severity::Low,
        |i| i.fragmented,
        "a ClientHello split across small records",
    ),
];

/// Turns intolerance probe results into findings, one per rejected test.
///
/// Untested probes produce nothing.
#[must_use]
pub fn intolerance_findings(result: &Intolerance) -> Vec<Finding> {
    let version = result
        .version
        .map_or_else(String::new, |v| format!("{v}: "));
    RULES
        .iter()
        .filter(|(_, _, get, _)| get(result) == Some(false))
        .map(|(id, severity, _, what)| {
            Finding::new(*id, *severity, format!("{version}server rejects {what}"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    //! Unit tests for intolerance findings.

    use testls_wire::ProtocolVersion;

    use super::*;

    /// Builds a result with every test set to `value`.
    fn all(value: Option<bool>) -> Intolerance {
        Intolerance {
            version: Some(ProtocolVersion::TLS12),
            unknown_version: value,
            unknown_extension: value,
            grease: value,
            oversized: value,
            fragmented: value,
        }
    }

    /// Tolerant and untested servers produce no findings.
    #[test]
    fn tolerant_or_untested() {
        assert_eq!(intolerance_findings(&all(Some(true))), []);
        assert_eq!(intolerance_findings(&all(None)), []);
    }

    /// Each rejected test yields its own finding.
    #[test]
    fn rejections() {
        let findings = intolerance_findings(&all(Some(false)));
        let ids: Vec<_> = findings.iter().map(|f| f.id.as_str()).collect();
        assert_eq!(
            ids,
            [
                "intolerance.unknown_version",
                "intolerance.unknown_extension",
                "intolerance.grease",
                "intolerance.oversized",
                "intolerance.fragmented",
            ]
        );
        assert_eq!(findings[0].severity, Severity::Medium);
        assert_eq!(findings[2].severity, Severity::Low);
        assert_eq!(
            findings[0].message,
            "TLSv1.2: server rejects an unknown future protocol version"
        );

        let mut one = all(Some(true));
        one.grease = Some(false);
        one.version = None;
        let findings = intolerance_findings(&one);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].message,
            "server rejects GREASE values (RFC 8701)"
        );
    }
}
