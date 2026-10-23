//! Protocol version detection.

use testls_wire::ProtocolVersion;

use crate::hello::{client_hello, legacy_suites, ssl2_client_hello, tls13_suites};
use crate::{HelloResponse, ProbeError, Transport};

/// Outcome of offering a single protocol version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolSupport {
    /// The server completed a hello at this version.
    Supported,
    /// The server refused or answered with a different version.
    NotSupported,
    /// The probe could not be completed.
    Error(String),
}

/// Result for one protocol version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolResult {
    /// Version that was offered.
    pub version: ProtocolVersion,
    /// What happened.
    pub support: ProtocolSupport,
}

/// Interpret a server reply to a hello that offered exactly `version`.
#[must_use]
pub fn classify(version: ProtocolVersion, response: &HelloResponse) -> ProtocolSupport {
    match response {
        HelloResponse::Ssl2(hello) if version == ProtocolVersion::SSL2 => {
            if hello.cipher_specs.is_empty() {
                ProtocolSupport::NotSupported
            } else {
                ProtocolSupport::Supported
            }
        }
        HelloResponse::ServerHello { hello, .. } => match hello.negotiated_version() {
            Ok(v) if v == version => ProtocolSupport::Supported,
            Ok(_) => ProtocolSupport::NotSupported,
            Err(e) => ProtocolSupport::Error(e.to_string()),
        },
        HelloResponse::Ssl2(_) | HelloResponse::Alert(_) | HelloResponse::Closed => {
            ProtocolSupport::NotSupported
        }
    }
}

/// Offer exactly `version` with every cipher suite valid for it.
///
/// # Errors
/// Returns a [`ProbeError`] if the exchange itself fails.
pub async fn probe_protocol(
    transport: &Transport,
    version: ProtocolVersion,
    sni: Option<&str>,
) -> Result<ProtocolSupport, ProbeError> {
    let bytes = if version == ProtocolVersion::SSL2 {
        ssl2_client_hello()
    } else {
        let suites = if version >= ProtocolVersion::TLS13 {
            tls13_suites()
        } else {
            legacy_suites()
        };
        client_hello(version, suites, sni).encode()
    }
    .map_err(ProbeError::Encode)?;
    let response = transport.exchange(&bytes).await?;
    Ok(classify(version, &response))
}

/// Probe every version in [`ProtocolVersion::ALL`].
///
/// Probes run sequentially; a probe error is recorded rather than aborting.
pub async fn detect_protocols(transport: &Transport, sni: Option<&str>) -> Vec<ProtocolResult> {
    let mut results = Vec::with_capacity(ProtocolVersion::ALL.len());
    for version in ProtocolVersion::ALL {
        let support = match probe_protocol(transport, version, sni).await {
            Ok(s) => s,
            // Servers that drop the connection on unknown versions are
            // common; treat transport failures after connect as "no".
            Err(ProbeError::Io(_)) => ProtocolSupport::NotSupported,
            Err(e) => ProtocolSupport::Error(e.to_string()),
        };
        results.push(ProtocolResult { version, support });
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use testls_wire::{Alert, AlertLevel, RawExtension, ServerHello, Ssl2ServerHello};

    fn sh(legacy: ProtocolVersion, exts: Vec<RawExtension>) -> HelloResponse {
        HelloResponse::ServerHello {
            hello: ServerHello {
                legacy_version: legacy,
                random: [1; 32],
                session_id: vec![],
                cipher_suite: 0x1301,
                compression_method: 0,
                extensions: exts,
            },
            certificates: vec![],
        }
    }

    #[test]
    fn classify_versions() {
        let tls12 = sh(ProtocolVersion::TLS12, vec![]);
        assert_eq!(
            classify(ProtocolVersion::TLS12, &tls12),
            ProtocolSupport::Supported
        );
        assert_eq!(
            classify(ProtocolVersion::TLS11, &tls12),
            ProtocolSupport::NotSupported
        );
        let tls13 = sh(
            ProtocolVersion::TLS12,
            vec![RawExtension {
                typ: 43,
                data: vec![3, 4],
            }],
        );
        assert_eq!(
            classify(ProtocolVersion::TLS13, &tls13),
            ProtocolSupport::Supported
        );
        let alert = HelloResponse::Alert(Alert {
            level: AlertLevel::Fatal,
            description: Alert::PROTOCOL_VERSION,
        });
        assert_eq!(
            classify(ProtocolVersion::SSL3, &alert),
            ProtocolSupport::NotSupported
        );
    }

    #[test]
    fn classify_ssl2() {
        let mut hello = Ssl2ServerHello {
            version: ProtocolVersion::SSL2,
            certificate: vec![],
            cipher_specs: vec![0x01_0080],
        };
        let r = HelloResponse::Ssl2(hello.clone());
        assert_eq!(
            classify(ProtocolVersion::SSL2, &r),
            ProtocolSupport::Supported
        );
        hello.cipher_specs.clear();
        assert_eq!(
            classify(ProtocolVersion::SSL2, &HelloResponse::Ssl2(hello)),
            ProtocolSupport::NotSupported
        );
    }
}
