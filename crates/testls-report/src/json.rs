//! JSON report, schema documented in `docs/json-schema.md`.
//!
//! The serialized structs here are the schema; they are kept separate from
//! the probe and check types so internal refactors cannot change the output.

use std::net::SocketAddr;

use serde::Serialize;
use testls_checks::{Finding, cipher_name, cipher_severity};
use testls_probe::{CipherOrder, ProtocolResult, ProtocolSupport};

use crate::text::{CertificateSection, CipherSection, suite_id};

/// Version of the JSON schema. Bumped on any change that is not a pure
/// addition of fields.
pub const SCHEMA_VERSION: u32 = 1;

/// Everything a scan produced, borrowed for rendering.
#[derive(Debug, Clone, Copy)]
pub struct Report<'a> {
    /// Target as given on the command line.
    pub target: &'a str,
    /// Address that was scanned.
    pub addr: SocketAddr,
    /// SNI name sent, if any.
    pub sni: Option<&'a str>,
    /// Unix time the scan started.
    pub started_at: i64,
    /// Protocol support results.
    pub protocols: &'a [ProtocolResult],
    /// Cipher enumeration per offered protocol.
    pub ciphers: &'a [CipherSection],
    /// Certificate chain, or why it could not be retrieved.
    pub certificate: &'a Result<CertificateSection, String>,
    /// Findings, most severe first.
    pub findings: &'a [Finding],
}

/// Top-level JSON document.
#[derive(Debug, Serialize)]
struct Document<'a> {
    /// See [`SCHEMA_VERSION`].
    schema_version: u32,
    /// Producing tool and its version.
    tool: Tool,
    /// What was scanned.
    target: TargetJson<'a>,
    /// Unix time the scan started.
    started_at: i64,
    /// One entry per probed protocol version.
    protocols: Vec<ProtocolJson>,
    /// One entry per offered protocol version.
    ciphers: Vec<CiphersJson>,
    /// Certificate chain result.
    certificate: CertificateJson<'a>,
    /// Findings, most severe first.
    findings: Vec<FindingJson<'a>>,
}

/// Name and version of the producing tool.
#[derive(Debug, Serialize)]
struct Tool {
    /// Always `testls`.
    name: &'static str,
    /// Crate version.
    version: &'static str,
}

/// Scanned target.
#[derive(Debug, Serialize)]
struct TargetJson<'a> {
    /// Target as given on the command line.
    input: &'a str,
    /// Resolved socket address.
    address: String,
    /// SNI name sent, or `null`.
    sni: Option<&'a str>,
}

/// Support status of one protocol version.
#[derive(Debug, Serialize)]
struct ProtocolJson {
    /// Version name, e.g. `TLSv1.2`.
    version: String,
    /// `offered`, `not_offered`, or `error`.
    status: &'static str,
    /// Error message when `status` is `error`.
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// Cipher suites of one protocol version.
#[derive(Debug, Serialize)]
struct CiphersJson {
    /// Version name, e.g. `TLSv1.2`.
    protocol: String,
    /// `server`, `client`, or `null` when not applicable or unknown.
    order: Option<&'static str>,
    /// Suites in the order the server chose them.
    suites: Vec<SuiteJson>,
    /// Error message when enumeration failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// One cipher suite.
#[derive(Debug, Serialize)]
struct SuiteJson {
    /// Hex code point, e.g. `0xc02f` (six digits for SSLv2 cipher specs).
    id: String,
    /// IANA name.
    name: &'static str,
    /// Severity of the suite.
    severity: &'static str,
}

/// Certificate chain result.
#[derive(Debug, Serialize)]
struct CertificateJson<'a> {
    /// Version of the handshake that fetched the chain, or `null`.
    protocol: Option<String>,
    /// Certificates, leaf first.
    chain: Vec<CertJson<'a>>,
    /// Error message when the chain could not be retrieved.
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'a str>,
}

/// One certificate of the chain.
#[derive(Debug, Serialize)]
struct CertJson<'a> {
    /// Subject distinguished name.
    #[serde(skip_serializing_if = "Option::is_none")]
    subject: Option<&'a str>,
    /// Issuer distinguished name.
    #[serde(skip_serializing_if = "Option::is_none")]
    issuer: Option<&'a str>,
    /// Start of validity, Unix time.
    #[serde(skip_serializing_if = "Option::is_none")]
    not_before: Option<i64>,
    /// End of validity, Unix time.
    #[serde(skip_serializing_if = "Option::is_none")]
    not_after: Option<i64>,
    /// DNS names and IP addresses from the SAN extension.
    #[serde(skip_serializing_if = "Option::is_none")]
    names: Option<&'a [String]>,
    /// Key algorithm and size, e.g. `RSA 2048 bits`.
    #[serde(skip_serializing_if = "Option::is_none")]
    key: Option<&'a str>,
    /// Parse error when the certificate could not be read.
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'a str>,
}

/// One finding.
#[derive(Debug, Serialize)]
struct FindingJson<'a> {
    /// Stable identifier, e.g. `protocol.tls10`.
    id: &'a str,
    /// `info`, `low`, `medium`, `high`, or `critical`.
    severity: &'static str,
    /// Human-readable description.
    message: &'a str,
}

/// Renders `report` as pretty-printed JSON followed by a newline.
///
/// # Panics
///
/// Never in practice: the document contains only strings, integers, and
/// sequences, which `serde_json` always serializes.
#[must_use]
pub fn render(report: &Report<'_>) -> String {
    let doc = Document {
        schema_version: SCHEMA_VERSION,
        tool: Tool {
            name: "testls",
            version: env!("CARGO_PKG_VERSION"),
        },
        target: TargetJson {
            input: report.target,
            address: report.addr.to_string(),
            sni: report.sni,
        },
        started_at: report.started_at,
        protocols: report.protocols.iter().map(protocol).collect(),
        ciphers: report.ciphers.iter().map(ciphers).collect(),
        certificate: certificate(report.certificate),
        findings: report
            .findings
            .iter()
            .map(|f| FindingJson {
                id: &f.id,
                severity: f.severity.as_str(),
                message: &f.message,
            })
            .collect(),
    };
    let mut out = serde_json::to_string_pretty(&doc).expect("report serializes");
    out.push('\n');
    out
}

/// Converts one protocol result.
fn protocol(r: &ProtocolResult) -> ProtocolJson {
    let (status, error) = match &r.support {
        ProtocolSupport::Supported => ("offered", None),
        ProtocolSupport::NotSupported => ("not_offered", None),
        ProtocolSupport::Error(e) => ("error", Some(e.clone())),
    };
    ProtocolJson {
        version: r.version.to_string(),
        status,
        error,
    }
}

/// Converts one cipher section, labelling each suite with its severity.
fn ciphers(section: &CipherSection) -> CiphersJson {
    let version = section.version;
    match &section.outcome {
        Ok(c) => CiphersJson {
            protocol: version.to_string(),
            order: match c.order {
                CipherOrder::Server => Some("server"),
                CipherOrder::Client => Some("client"),
                CipherOrder::NotApplicable => None,
            },
            suites: c
                .suites
                .iter()
                .map(|&id| SuiteJson {
                    id: suite_id(version, id),
                    name: cipher_name(version, id),
                    severity: cipher_severity(version, id).0.as_str(),
                })
                .collect(),
            error: None,
        },
        Err(e) => CiphersJson {
            protocol: version.to_string(),
            order: None,
            suites: Vec::new(),
            error: Some(e.clone()),
        },
    }
}

/// Converts the certificate section.
fn certificate(section: &Result<CertificateSection, String>) -> CertificateJson<'_> {
    match section {
        Ok(chain) => CertificateJson {
            protocol: Some(chain.version.to_string()),
            chain: chain
                .certificates
                .iter()
                .map(|cert| match cert {
                    Ok(info) => CertJson {
                        subject: Some(&info.subject),
                        issuer: Some(&info.issuer),
                        not_before: Some(info.not_before_unix),
                        not_after: Some(info.not_after_unix),
                        names: Some(&info.names),
                        key: Some(&info.key),
                        error: None,
                    },
                    Err(e) => CertJson {
                        subject: None,
                        issuer: None,
                        not_before: None,
                        not_after: None,
                        names: None,
                        key: None,
                        error: Some(e),
                    },
                })
                .collect(),
            error: None,
        },
        Err(e) => CertificateJson {
            protocol: None,
            chain: Vec::new(),
            error: Some(e),
        },
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    use testls_checks::{CertificateInfo, Severity};
    use testls_probe::CipherResult;
    use testls_wire::ProtocolVersion;

    use super::*;

    /// Renders `report` and parses it back for comparison.
    fn value(report: &Report<'_>) -> Value {
        let out = render(report);
        assert!(out.ends_with("}\n"), "{out}");
        serde_json::from_str(&out).unwrap()
    }

    /// A full report maps every section onto the documented schema.
    #[test]
    fn full_report() {
        let protocols = [
            ProtocolResult {
                version: ProtocolVersion::TLS13,
                support: ProtocolSupport::Supported,
            },
            ProtocolResult {
                version: ProtocolVersion::TLS10,
                support: ProtocolSupport::NotSupported,
            },
            ProtocolResult {
                version: ProtocolVersion::SSL3,
                support: ProtocolSupport::Error("timed out".into()),
            },
        ];
        let ciphers = [
            CipherSection {
                version: ProtocolVersion::TLS13,
                outcome: Ok(CipherResult {
                    version: ProtocolVersion::TLS13,
                    suites: vec![0x1302],
                    order: CipherOrder::Server,
                }),
            },
            CipherSection {
                version: ProtocolVersion::TLS12,
                outcome: Err("reset".into()),
            },
        ];
        let certificate = Ok(CertificateSection {
            version: ProtocolVersion::TLS13,
            certificates: vec![
                Ok(CertificateInfo {
                    subject: "CN=localhost".into(),
                    issuer: "CN=test CA".into(),
                    not_before: String::new(),
                    not_after: String::new(),
                    not_before_unix: 1,
                    not_after_unix: 2,
                    names: vec!["localhost".into()],
                    key: "EC 256 bits".into(),
                }),
                Err("bad".into()),
            ],
        });
        let findings = [Finding::new(
            "cert.untrusted",
            Severity::High,
            "certificate chain is not trusted",
        )];
        let report = Report {
            target: "localhost:443",
            addr: "127.0.0.1:443".parse().unwrap(),
            sni: Some("localhost"),
            started_at: 1_700_000_000,
            protocols: &protocols,
            ciphers: &ciphers,
            certificate: &certificate,
            findings: &findings,
        };
        assert_eq!(
            value(&report),
            json!({
                "schema_version": 1,
                "tool": {"name": "testls", "version": env!("CARGO_PKG_VERSION")},
                "target": {"input": "localhost:443", "address": "127.0.0.1:443", "sni": "localhost"},
                "started_at": 1_700_000_000,
                "protocols": [
                    {"version": "TLSv1.3", "status": "offered"},
                    {"version": "TLSv1.0", "status": "not_offered"},
                    {"version": "SSLv3", "status": "error", "error": "timed out"},
                ],
                "ciphers": [
                    {
                        "protocol": "TLSv1.3",
                        "order": "server",
                        "suites": [{"id": "0x1302", "name": "TLS_AES_256_GCM_SHA384", "severity": "ok"}],
                    },
                    {"protocol": "TLSv1.2", "order": null, "suites": [], "error": "reset"},
                ],
                "certificate": {
                    "protocol": "TLSv1.3",
                    "chain": [
                        {
                            "subject": "CN=localhost",
                            "issuer": "CN=test CA",
                            "not_before": 1,
                            "not_after": 2,
                            "names": ["localhost"],
                            "key": "EC 256 bits",
                        },
                        {"error": "bad"},
                    ],
                },
                "findings": [
                    {"id": "cert.untrusted", "severity": "high", "message": "certificate chain is not trusted"},
                ],
            })
        );
    }

    /// Missing SNI is `null` and a failed certificate fetch carries the error.
    #[test]
    fn errors_and_nulls() {
        let certificate = Err("refused".into());
        let report = Report {
            target: "127.0.0.1",
            addr: "127.0.0.1:443".parse().unwrap(),
            sni: None,
            started_at: 0,
            protocols: &[],
            ciphers: &[],
            certificate: &certificate,
            findings: &[],
        };
        let v = value(&report);
        assert_eq!(v["target"]["sni"], Value::Null);
        assert_eq!(
            v["certificate"],
            json!({"protocol": null, "chain": [], "error": "refused"})
        );
        assert_eq!(v["findings"], json!([]));
    }
}
