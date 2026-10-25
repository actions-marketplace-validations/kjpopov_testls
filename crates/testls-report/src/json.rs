//! JSON report, schema documented in `docs/json-schema.md`.
//!
//! The serialized structs here are the schema; they are kept separate from
//! the probe and check types so internal refactors cannot change the output.

use std::collections::BTreeMap;
use std::net::SocketAddr;

use serde::Serialize;
use testls_checks::{
    CertStatus, Finding, OcspStatus, RevocationCheck, RevocationMethod, cipher_name,
    cipher_severity, group_name, group_severity, parse_hsts, revocation_reason_name,
};
use testls_probe::{CipherOrder, HttpResponse, ProtocolResult, ProtocolSupport};

use crate::text::{
    CertificateSection, CipherSection, KeyExchangeSection, SECURITY_HEADERS, suite_id,
};

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
    /// Key exchange probe per offered protocol.
    pub key_exchange: &'a [KeyExchangeSection],
    /// Certificate chain, or why it could not be retrieved.
    pub certificate: &'a Result<CertificateSection, String>,
    /// Reply to `GET /`, or why it could not be fetched.
    pub http: &'a Result<HttpResponse, String>,
    /// Revocation checks against the issuer's services, or why they could
    /// not run; `None` when not requested.
    pub revocation: Option<&'a Result<Vec<RevocationCheck>, String>>,
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
    /// One entry per offered protocol version.
    key_exchange: Vec<KeyExchangeJson>,
    /// Certificate chain result.
    certificate: CertificateJson<'a>,
    /// HTTP security headers result.
    http: HttpJson<'a>,
    /// Revocation check result, or `null` when not requested.
    revocation: Option<RevocationJson<'a>>,
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

/// Key exchange groups and DH parameter size of one protocol version.
#[derive(Debug, Serialize)]
struct KeyExchangeJson {
    /// Version name, e.g. `TLSv1.2`.
    protocol: String,
    /// `server`, `client`, or `null` when not applicable or unknown.
    group_order: Option<&'static str>,
    /// Supported groups in the order the server chose them.
    groups: Vec<GroupJson>,
    /// Size of the ephemeral DH prime in bits, or `null` without DHE.
    dh_bits: Option<usize>,
    /// Error message when the probe failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// One supported group.
#[derive(Debug, Serialize)]
struct GroupJson {
    /// Hex code point, e.g. `0x001d`.
    id: String,
    /// IANA name.
    name: &'static str,
    /// Severity of the group.
    severity: &'static str,
}

/// Certificate chain result.
#[derive(Debug, Serialize)]
struct CertificateJson<'a> {
    /// Version of the handshake that fetched the chain, or `null`.
    protocol: Option<String>,
    /// Certificates, leaf first.
    chain: Vec<CertJson<'a>>,
    /// Stapled OCSP response, or `null` when the chain could not be
    /// retrieved.
    ocsp: Option<OcspJson<'a>>,
    /// Error message when the chain could not be retrieved.
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'a str>,
}

/// Stapled OCSP response for the leaf certificate.
#[derive(Debug, Serialize)]
struct OcspJson<'a> {
    /// Whether the server stapled a response.
    stapled: bool,
    /// `good`, `revoked`, `unknown`, `invalid`, or `null` when not stapled.
    status: Option<&'static str>,
    /// When the response was signed, Unix time.
    #[serde(skip_serializing_if = "Option::is_none")]
    produced_at: Option<i64>,
    /// Start of the validity interval, Unix time.
    #[serde(skip_serializing_if = "Option::is_none")]
    this_update: Option<i64>,
    /// End of the validity interval, Unix time.
    #[serde(skip_serializing_if = "Option::is_none")]
    next_update: Option<i64>,
    /// Revocation time, Unix time.
    #[serde(skip_serializing_if = "Option::is_none")]
    revocation_time: Option<i64>,
    /// RFC 5280 `CRLReason` name, when revoked with a reason.
    #[serde(skip_serializing_if = "Option::is_none")]
    revocation_reason: Option<&'static str>,
    /// Why the response is invalid.
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

/// Status and security headers of the reply to `GET /`.
#[derive(Debug, Serialize)]
struct HttpJson<'a> {
    /// HTTP status code, or `null` when the fetch failed.
    status: Option<u16>,
    /// Each security header by lowercase name, `null` when not set.
    headers: BTreeMap<String, Option<&'a str>>,
    /// Parsed `Strict-Transport-Security` policy, or `null` when the header
    /// is missing or invalid.
    hsts: Option<HstsJson>,
    /// Error message when the headers could not be fetched.
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'a str>,
}

/// Parsed `Strict-Transport-Security` policy.
#[derive(Debug, Serialize)]
struct HstsJson {
    /// `max-age` in seconds.
    max_age: u64,
    /// The `includeSubDomains` directive is present.
    include_subdomains: bool,
    /// The `preload` directive is present.
    preload: bool,
    /// The policy meets the preload list's header requirements.
    preload_eligible: bool,
}

/// Opt-in revocation check against the issuer's services.
#[derive(Debug, Serialize)]
struct RevocationJson<'a> {
    /// Each OCSP query or CRL download, in the order made.
    checks: Vec<RevocationCheckJson<'a>>,
    /// Why no check could be made, e.g. the chain could not be retrieved.
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'a str>,
}

/// One OCSP query or CRL download.
#[derive(Debug, Serialize)]
struct RevocationCheckJson<'a> {
    /// `ocsp` or `crl`.
    method: &'static str,
    /// URL that was used.
    url: &'a str,
    /// `good`, `revoked`, `unknown`, or `error`.
    status: &'static str,
    /// Start of the validity interval, Unix time.
    #[serde(skip_serializing_if = "Option::is_none")]
    this_update: Option<i64>,
    /// End of the validity interval, Unix time.
    #[serde(skip_serializing_if = "Option::is_none")]
    next_update: Option<i64>,
    /// Revocation time, Unix time.
    #[serde(skip_serializing_if = "Option::is_none")]
    revocation_time: Option<i64>,
    /// RFC 5280 `CRLReason` name, when revoked with a reason.
    #[serde(skip_serializing_if = "Option::is_none")]
    revocation_reason: Option<&'static str>,
    /// Why fetching or verification failed.
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
        key_exchange: report.key_exchange.iter().map(key_exchange).collect(),
        certificate: certificate(report.certificate),
        http: http(report.http),
        revocation: report.revocation.map(revocation),
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
            order: order(c.order),
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

/// Maps a preference order onto its JSON label.
fn order(order: CipherOrder) -> Option<&'static str> {
    match order {
        CipherOrder::Server => Some("server"),
        CipherOrder::Client => Some("client"),
        CipherOrder::NotApplicable => None,
    }
}

/// Converts one key exchange section, labelling each group with its
/// severity.
fn key_exchange(section: &KeyExchangeSection) -> KeyExchangeJson {
    let protocol = section.version.to_string();
    match &section.outcome {
        Ok(k) => KeyExchangeJson {
            protocol,
            group_order: order(k.group_order),
            groups: k
                .groups
                .iter()
                .map(|&id| GroupJson {
                    id: format!("0x{id:04x}"),
                    name: group_name(id),
                    severity: group_severity(id).0.as_str(),
                })
                .collect(),
            dh_bits: k.dh_bits,
            error: None,
        },
        Err(e) => KeyExchangeJson {
            protocol,
            group_order: None,
            groups: Vec::new(),
            dh_bits: None,
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
            ocsp: Some(ocsp(chain.ocsp.as_ref())),
            error: None,
        },
        Err(e) => CertificateJson {
            protocol: None,
            chain: Vec::new(),
            ocsp: None,
            error: Some(e),
        },
    }
}

/// Converts the stapled OCSP result.
fn ocsp(section: Option<&Result<OcspStatus, String>>) -> OcspJson<'_> {
    let mut json = OcspJson {
        stapled: section.is_some(),
        status: None,
        produced_at: None,
        this_update: None,
        next_update: None,
        revocation_time: None,
        revocation_reason: None,
        error: None,
    };
    match section {
        None => {}
        Some(Err(e)) => {
            json.status = Some("invalid");
            json.error = Some(e);
        }
        Some(Ok(status)) => {
            json.produced_at = Some(status.produced_at);
            json.this_update = Some(status.this_update);
            json.next_update = status.next_update;
            json.status = Some(match status.status {
                CertStatus::Good => "good",
                CertStatus::Revoked { time, reason } => {
                    json.revocation_time = Some(time);
                    json.revocation_reason = reason.map(revocation_reason_name);
                    "revoked"
                }
                CertStatus::Unknown => "unknown",
            });
        }
    }
    json
}

/// Converts the HTTP section; only the first HSTS header counts
/// (RFC 6797 §8.1).
fn http(section: &Result<HttpResponse, String>) -> HttpJson<'_> {
    match section {
        Ok(response) => HttpJson {
            status: Some(response.status),
            headers: SECURITY_HEADERS
                .iter()
                .map(|name| (name.to_ascii_lowercase(), response.header(name)))
                .collect(),
            hsts: response
                .header("strict-transport-security")
                .and_then(|v| parse_hsts(v).ok())
                .map(|h| HstsJson {
                    max_age: h.max_age,
                    include_subdomains: h.include_subdomains,
                    preload: h.preload,
                    preload_eligible: h.preload_eligible(),
                }),
            error: None,
        },
        Err(e) => HttpJson {
            status: None,
            headers: BTreeMap::new(),
            hsts: None,
            error: Some(e),
        },
    }
}

/// Converts the revocation checks.
fn revocation(section: &Result<Vec<RevocationCheck>, String>) -> RevocationJson<'_> {
    match section {
        Ok(checks) => RevocationJson {
            checks: checks.iter().map(revocation_check).collect(),
            error: None,
        },
        Err(e) => RevocationJson {
            checks: Vec::new(),
            error: Some(e),
        },
    }
}

/// Converts one revocation attempt.
fn revocation_check(check: &RevocationCheck) -> RevocationCheckJson<'_> {
    let mut json = RevocationCheckJson {
        method: match check.method {
            RevocationMethod::Ocsp => "ocsp",
            RevocationMethod::Crl => "crl",
        },
        url: &check.url,
        status: "error",
        this_update: None,
        next_update: None,
        revocation_time: None,
        revocation_reason: None,
        error: None,
    };
    match &check.outcome {
        Err(e) => json.error = Some(e),
        Ok(status) => {
            json.this_update = Some(status.this_update);
            json.next_update = status.next_update;
            json.status = match status.status {
                CertStatus::Good => "good",
                CertStatus::Revoked { time, reason } => {
                    json.revocation_time = Some(time);
                    json.revocation_reason = reason.map(revocation_reason_name);
                    "revoked"
                }
                CertStatus::Unknown => "unknown",
            };
        }
    }
    json
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    use testls_checks::{CertificateInfo, RevocationStatus, Severity};
    use testls_probe::{CipherResult, KeyExchangeResult};
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
            ocsp: None,
        });
        let http = Err("reset".into());
        let findings = [Finding::new("cert.untrusted", Severity::High, "untrusted")];
        let report = Report {
            target: "localhost:443",
            addr: "127.0.0.1:443".parse().unwrap(),
            sni: Some("localhost"),
            started_at: 1_700_000_000,
            protocols: &protocols,
            ciphers: &ciphers,
            key_exchange: &[],
            certificate: &certificate,
            http: &http,
            revocation: None,
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
                "key_exchange": [],
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
                    "ocsp": {"stapled": false, "status": null},
                },
                "http": {"status": null, "headers": {}, "hsts": null, "error": "reset"}, "revocation": null,
                "findings": [{"id": "cert.untrusted", "severity": "high", "message": "untrusted"}],
            })
        );
    }

    /// Key exchange sections list groups with severity, DH size, or the error.
    #[test]
    fn key_exchange_sections() {
        let sections = [
            KeyExchangeSection {
                version: ProtocolVersion::TLS13,
                outcome: Ok(KeyExchangeResult {
                    version: ProtocolVersion::TLS13,
                    groups: vec![0x11ec, 0x001d],
                    group_order: CipherOrder::Client,
                    dh_bits: None,
                }),
            },
            KeyExchangeSection {
                version: ProtocolVersion::TLS12,
                outcome: Ok(KeyExchangeResult {
                    version: ProtocolVersion::TLS12,
                    groups: vec![0x0015],
                    group_order: CipherOrder::NotApplicable,
                    dh_bits: Some(1024),
                }),
            },
            KeyExchangeSection {
                version: ProtocolVersion::TLS11,
                outcome: Err("reset".into()),
            },
        ];
        let certificate = Err("refused".into());
        let http = Err("reset".into());
        let report = Report {
            target: "127.0.0.1",
            addr: "127.0.0.1:443".parse().unwrap(),
            sni: None,
            started_at: 0,
            protocols: &[],
            ciphers: &[],
            key_exchange: &sections,
            certificate: &certificate,
            http: &http,
            revocation: None,
            findings: &[],
        };
        assert_eq!(
            value(&report)["key_exchange"],
            json!([
                {
                    "protocol": "TLSv1.3",
                    "group_order": "client",
                    "groups": [
                        {"id": "0x11ec", "name": "X25519MLKEM768", "severity": "ok"},
                        {"id": "0x001d", "name": "x25519", "severity": "ok"},
                    ],
                    "dh_bits": null,
                },
                {
                    "protocol": "TLSv1.2",
                    "group_order": null,
                    "groups": [{"id": "0x0015", "name": "secp224r1", "severity": "medium"}],
                    "dh_bits": 1024,
                },
                {"protocol": "TLSv1.1", "group_order": null, "groups": [], "dh_bits": null, "error": "reset"},
            ])
        );
    }

    /// Missing SNI is `null` and a failed certificate fetch carries the error.
    #[test]
    fn errors_and_nulls() {
        let certificate = Err("refused".into());
        let http = Err("reset".into());
        let report = Report {
            target: "127.0.0.1",
            addr: "127.0.0.1:443".parse().unwrap(),
            sni: None,
            started_at: 0,
            protocols: &[],
            ciphers: &[],
            key_exchange: &[],
            certificate: &certificate,
            http: &http,
            revocation: None,
            findings: &[],
        };
        let v = value(&report);
        assert_eq!(v["target"]["sni"], Value::Null);
        assert_eq!(
            v["certificate"],
            json!({"protocol": null, "chain": [], "ocsp": null, "error": "refused"})
        );
        assert_eq!(v["findings"], json!([]));
    }

    /// The HTTP section lists every security header and the parsed HSTS
    /// policy from the first header.
    #[test]
    fn http_section() {
        let certificate = Err("refused".into());
        let http = Ok(HttpResponse {
            status: 301,
            headers: vec![
                (
                    "strict-transport-security".into(),
                    "max-age=31536000; includeSubDomains; preload".into(),
                ),
                ("strict-transport-security".into(), "max-age=0".into()),
                ("x-frame-options".into(), "DENY".into()),
            ],
        });
        let report = Report {
            target: "127.0.0.1",
            addr: "127.0.0.1:443".parse().unwrap(),
            sni: None,
            started_at: 0,
            protocols: &[],
            ciphers: &[],
            key_exchange: &[],
            certificate: &certificate,
            http: &http,
            revocation: None,
            findings: &[],
        };
        assert_eq!(
            value(&report)["http"],
            json!({
                "status": 301,
                "headers": {
                    "content-security-policy": null,
                    "referrer-policy": null,
                    "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
                    "x-content-type-options": null,
                    "x-frame-options": "DENY",
                },
                "hsts": {
                    "max_age": 31_536_000,
                    "include_subdomains": true,
                    "preload": true,
                    "preload_eligible": true,
                },
            })
        );
    }

    /// The OCSP object carries the status, validity interval, revocation
    /// details, or the reason the response is invalid.
    #[test]
    fn ocsp_object() {
        let revoked = Ok(OcspStatus {
            status: CertStatus::Revoked {
                time: 5,
                reason: Some(1),
            },
            produced_at: 2,
            this_update: 3,
            next_update: None,
        });
        assert_eq!(
            serde_json::to_value(ocsp(Some(&revoked))).unwrap(),
            json!({
                "stapled": true,
                "status": "revoked",
                "produced_at": 2,
                "this_update": 3,
                "revocation_time": 5,
                "revocation_reason": "keyCompromise",
            })
        );
        let good = Ok(OcspStatus {
            status: CertStatus::Good,
            produced_at: 2,
            this_update: 3,
            next_update: Some(4),
        });
        assert_eq!(
            serde_json::to_value(ocsp(Some(&good))).unwrap(),
            json!({"stapled": true, "status": "good", "produced_at": 2, "this_update": 3, "next_update": 4})
        );
        let invalid = Err("bad signature".into());
        assert_eq!(
            serde_json::to_value(ocsp(Some(&invalid))).unwrap(),
            json!({"stapled": true, "status": "invalid", "error": "bad signature"})
        );
    }

    /// Revocation checks list each attempt with its status, or the reason
    /// none could be made.
    #[test]
    fn revocation_object() {
        let checks = Ok(vec![
            RevocationCheck {
                method: RevocationMethod::Ocsp,
                url: "http://ocsp.test/".into(),
                outcome: Err("HTTP status 500".into()),
            },
            RevocationCheck {
                method: RevocationMethod::Crl,
                url: "http://crl.test/ca.crl".into(),
                outcome: Ok(RevocationStatus {
                    status: CertStatus::Revoked {
                        time: 5,
                        reason: Some(1),
                    },
                    this_update: 3,
                    next_update: None,
                }),
            },
        ]);
        assert_eq!(
            serde_json::to_value(revocation(&checks)).unwrap(),
            json!({"checks": [
                {"method": "ocsp", "url": "http://ocsp.test/", "status": "error", "error": "HTTP status 500"},
                {
                    "method": "crl",
                    "url": "http://crl.test/ca.crl",
                    "status": "revoked",
                    "this_update": 3,
                    "revocation_time": 5,
                    "revocation_reason": "keyCompromise",
                },
            ]})
        );
        assert_eq!(
            serde_json::to_value(revocation(&Err("refused".into()))).unwrap(),
            json!({"checks": [], "error": "refused"})
        );
    }
}
