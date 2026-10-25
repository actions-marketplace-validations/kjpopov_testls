//! Protocol version checks.

use testls_probe::{ProtocolResult, ProtocolSupport};
use testls_wire::ProtocolVersion;

use crate::{Finding, Severity};

/// Severity of a server offering `version`, with a short reason.
#[must_use]
pub fn protocol_severity(version: ProtocolVersion) -> (Severity, &'static str) {
    match version {
        ProtocolVersion::SSL2 => (Severity::Critical, "SSLv2 is broken (RFC 6176)"),
        ProtocolVersion::SSL3 => (Severity::High, "SSLv3 is broken (RFC 7568)"),
        ProtocolVersion::TLS10 | ProtocolVersion::TLS11 => {
            (Severity::Medium, "deprecated (RFC 8996)")
        }
        ProtocolVersion::TLS12 | ProtocolVersion::TLS13 => (Severity::Ok, "current"),
        _ => (Severity::Info, "unknown version"),
    }
}

/// Finding id for a protocol version, e.g. `protocol.tls10`.
pub(crate) fn id(version: ProtocolVersion) -> String {
    let name = version
        .to_string()
        .to_ascii_lowercase()
        .replace(['v', '.'], "");
    format!("protocol.{name}")
}

/// Findings for the result of protocol detection.
#[must_use]
pub fn protocol_findings(results: &[ProtocolResult]) -> Vec<Finding> {
    let mut out = Vec::new();
    for r in results {
        match &r.support {
            ProtocolSupport::Supported => {
                let (severity, reason) = protocol_severity(r.version);
                out.push(Finding::new(
                    id(r.version),
                    severity,
                    format!("{} offered: {reason}", r.version),
                ));
            }
            ProtocolSupport::NotSupported => {}
            ProtocolSupport::Error(e) => out.push(Finding::new(
                id(r.version),
                Severity::Info,
                format!("{} could not be tested: {e}", r.version),
            )),
        }
    }

    let offered = |v| {
        results
            .iter()
            .any(|r| r.version == v && r.support == ProtocolSupport::Supported)
    };
    if !offered(ProtocolVersion::TLS12) && !offered(ProtocolVersion::TLS13) {
        out.push(Finding::new(
            "protocol.no_modern",
            Severity::High,
            "neither TLSv1.2 nor TLSv1.3 is offered",
        ));
    } else if !offered(ProtocolVersion::TLS13) {
        out.push(Finding::new(
            "protocol.no_tls13",
            Severity::Info,
            "TLSv1.3 is not offered",
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result(version: ProtocolVersion, supported: bool) -> ProtocolResult {
        ProtocolResult {
            version,
            support: if supported {
                ProtocolSupport::Supported
            } else {
                ProtocolSupport::NotSupported
            },
        }
    }

    #[test]
    fn ids() {
        assert_eq!(id(ProtocolVersion::SSL3), "protocol.ssl3");
        assert_eq!(id(ProtocolVersion::TLS12), "protocol.tls12");
    }

    #[test]
    fn modern_only() {
        let r = [
            result(ProtocolVersion::TLS10, false),
            result(ProtocolVersion::TLS12, true),
            result(ProtocolVersion::TLS13, true),
        ];
        let f = protocol_findings(&r);
        assert_eq!(crate::max_severity(&f), Some(Severity::Ok));
        assert_eq!(f.len(), 2);
    }

    #[test]
    fn legacy_server() {
        let r = [
            result(ProtocolVersion::SSL3, true),
            result(ProtocolVersion::TLS10, true),
            result(ProtocolVersion::TLS12, false),
            result(ProtocolVersion::TLS13, false),
        ];
        let f = protocol_findings(&r);
        let ids: Vec<_> = f.iter().map(|f| f.id.as_str()).collect();
        assert_eq!(
            ids,
            ["protocol.ssl3", "protocol.tls10", "protocol.no_modern"]
        );
        assert_eq!(crate::max_severity(&f), Some(Severity::High));
    }

    #[test]
    fn missing_tls13_is_info() {
        let r = [
            result(ProtocolVersion::TLS12, true),
            result(ProtocolVersion::TLS13, false),
        ];
        let f = protocol_findings(&r);
        assert!(
            f.iter()
                .any(|f| f.id == "protocol.no_tls13" && f.severity == Severity::Info)
        );
    }
}
