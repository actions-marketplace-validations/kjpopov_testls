//! Plain-text report sections.
//!
//! Each function renders one section as newline-terminated lines, so the
//! CLI can print sections as soon as their probes finish.

use std::fmt::Write as _;
use std::net::SocketAddr;

use testls_checks::{
    CertStatus, CertificateInfo, Finding, OcspStatus, RevocationCheck, Severity, cipher_name,
    cipher_severity, dh_severity, display_time, group_name, group_severity, protocol_severity,
    revocation_reason_name,
};
use testls_probe::{
    CipherOrder, CipherResult, HttpResponse, KeyExchangeResult, ProtocolResult, ProtocolSupport,
};
use testls_wire::ProtocolVersion;

use crate::Painter;

/// Cipher suites offered for one protocol version, or why they could not be
/// enumerated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CipherSection {
    /// Protocol version the suites were enumerated for.
    pub version: ProtocolVersion,
    /// Enumeration result, or the error message.
    pub outcome: Result<CipherResult, String>,
}

/// Key exchange groups and DH parameter size for one protocol version, or
/// why they could not be probed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyExchangeSection {
    /// Protocol version the key exchange was probed for.
    pub version: ProtocolVersion,
    /// Probe result, or the error message.
    pub outcome: Result<KeyExchangeResult, String>,
}

/// The certificate chain presented in a full handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateSection {
    /// Protocol version of the handshake.
    pub version: ProtocolVersion,
    /// Details of each certificate, leaf first, or why it cannot be parsed.
    pub certificates: Vec<Result<CertificateInfo, String>>,
    /// Stapled OCSP response: `None` when nothing was stapled, otherwise the
    /// verified status or why the response is invalid.
    pub ocsp: Option<Result<OcspStatus, String>>,
}

/// Renders the target, resolved address, and SNI name.
#[must_use]
pub fn header(target: &str, addr: SocketAddr, sni: Option<&str>) -> String {
    format!(
        "Target: {target} ({addr})\nSNI:    {}\n",
        sni.unwrap_or("(none)")
    )
}

/// Renders protocol support, colouring offered versions by severity.
#[must_use]
pub fn protocols(results: &[ProtocolResult], paint: Painter) -> String {
    let mut out = format!("{}\n", paint.heading("Protocols"));
    for r in results {
        let status = match &r.support {
            ProtocolSupport::Supported => paint.severity(protocol_severity(r.version).0, "offered"),
            ProtocolSupport::NotSupported => "not offered".to_owned(),
            ProtocolSupport::Error(e) => format!("error: {e}"),
        };
        let _ = writeln!(out, "  {:<8} {status}", r.version.to_string());
    }
    out
}

/// Renders the cipher suites of one protocol version, coloured by severity.
#[must_use]
pub fn ciphers(section: &CipherSection, paint: Painter) -> String {
    let version = section.version;
    let heading = paint.heading(&format!("Ciphers {version}"));
    let c = match &section.outcome {
        Ok(c) => c,
        Err(e) => return format!("{heading}: error: {e}\n"),
    };
    let mut out = match c.order {
        CipherOrder::Server => format!("{heading} server order\n"),
        CipherOrder::Client => format!("{heading} client order\n"),
        CipherOrder::NotApplicable => format!("{heading}\n"),
    };
    for &id in &c.suites {
        let (severity, _, _) = cipher_severity(version, id);
        let _ = writeln!(
            out,
            "  {}",
            paint.severity(severity, &cipher_label(version, id))
        );
    }
    out
}

/// Renders the supported groups and DH parameter size of one protocol
/// version, coloured by severity.
#[must_use]
pub fn key_exchange(section: &KeyExchangeSection, paint: Painter) -> String {
    let heading = paint.heading(&format!("Key exchange {}", section.version));
    let k = match &section.outcome {
        Ok(k) => k,
        Err(e) => return format!("{heading}: error: {e}\n"),
    };
    let mut out = match k.group_order {
        CipherOrder::Server => format!("{heading} server order\n"),
        CipherOrder::Client => format!("{heading} client order\n"),
        CipherOrder::NotApplicable => format!("{heading}\n"),
    };
    for &id in &k.groups {
        let label = format!("0x{id:04x}  {}", group_name(id));
        let _ = writeln!(out, "  {}", paint.severity(group_severity(id).0, &label));
    }
    if let Some(bits) = k.dh_bits {
        let label = format!("DH      {bits} bits");
        let _ = writeln!(out, "  {}", paint.severity(dh_severity(bits).0, &label));
    }
    if k.groups.is_empty() && k.dh_bits.is_none() {
        let _ = writeln!(out, "  no ECDHE or DHE key exchange");
    }
    out
}

/// Renders the certificate chain, or why it could not be retrieved.
#[must_use]
pub fn certificate(section: &Result<CertificateSection, String>, paint: Painter) -> String {
    let chain = match section {
        Ok(chain) => chain,
        Err(e) => return format!("{}: error: {e}\n", paint.heading("Certificate")),
    };
    let mut out = format!(
        "{}\n",
        paint.heading(&format!("Certificate ({})", chain.version))
    );
    for (position, cert) in chain.certificates.iter().enumerate() {
        match cert {
            Ok(info) => {
                let _ = writeln!(out, "  #{position} {}", info.subject);
                let _ = writeln!(out, "     issuer  {}", info.issuer);
                let _ = writeln!(
                    out,
                    "     valid   {} to {}",
                    info.not_before, info.not_after
                );
                if !info.names.is_empty() {
                    let _ = writeln!(out, "     names   {}", info.names.join(", "));
                }
                let _ = writeln!(out, "     key     {}", info.key);
            }
            Err(e) => {
                let _ = writeln!(out, "  #{position} cannot be parsed: {e}");
            }
        }
    }
    let _ = writeln!(out, "  OCSP     {}", ocsp_line(chain.ocsp.as_ref(), paint));
    out
}

/// Describes the stapled OCSP response, painted by how bad it is.
fn ocsp_line(ocsp: Option<&Result<OcspStatus, String>>, paint: Painter) -> String {
    let Some(ocsp) = ocsp else {
        return "not stapled".into();
    };
    match ocsp {
        Ok(status) => match status.status {
            CertStatus::Good => {
                let next = status
                    .next_update
                    .map_or_else(|| "none".into(), display_time);
                format!("good, next update {next}")
            }
            CertStatus::Revoked { time, reason } => paint.severity(
                Severity::Critical,
                &format!(
                    "revoked on {} ({})",
                    display_time(time),
                    reason.map_or("no reason given", revocation_reason_name)
                ),
            ),
            CertStatus::Unknown => paint.severity(Severity::Medium, "unknown to the responder"),
        },
        Err(e) => paint.severity(Severity::Medium, &format!("invalid: {e}")),
    }
}

/// Renders the opt-in revocation check: one line per OCSP query or CRL
/// download in the order they were made, or why no check was possible.
#[must_use]
pub fn revocation(section: &Result<Vec<RevocationCheck>, String>, paint: Painter) -> String {
    let checks = match section {
        Ok(checks) => checks,
        Err(e) => return format!("{}: error: {e}\n", paint.heading("Revocation")),
    };
    let mut out = format!("{}\n", paint.heading("Revocation"));
    if checks.is_empty() {
        let _ = writeln!(out, "  no HTTP OCSP responder or CRL named");
    }
    for check in checks {
        let result = match &check.outcome {
            Ok(status) => match status.status {
                CertStatus::Good => {
                    let next = status
                        .next_update
                        .map_or_else(|| "none".into(), display_time);
                    format!("good, next update {next}")
                }
                CertStatus::Revoked { time, reason } => paint.severity(
                    Severity::Critical,
                    &format!(
                        "revoked on {} ({})",
                        display_time(time),
                        reason.map_or("no reason given", revocation_reason_name)
                    ),
                ),
                CertStatus::Unknown => paint.severity(Severity::Medium, "unknown"),
            },
            Err(e) => format!("error: {e}"),
        };
        let _ = writeln!(
            out,
            "  {:<4} {}  {result}",
            check.method.as_str(),
            printable(&check.url)
        );
    }
    out
}

/// Escapes control characters (e.g. terminal escape sequences) in text
/// taken from the scanned server's certificate so it is safe to print.
fn printable(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_control() {
                c.escape_default().to_string()
            } else {
                c.to_string()
            }
        })
        .collect()
}

/// Security headers listed in the HTTP section, in display order.
pub(crate) const SECURITY_HEADERS: [&str; 5] = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
];

/// Renders the status and security headers of the reply to `GET /`, or why
/// it could not be fetched. A missing HSTS header is coloured as low.
#[must_use]
pub fn http(section: &Result<HttpResponse, String>, paint: Painter) -> String {
    let response = match section {
        Ok(r) => r,
        Err(e) => return format!("{}: error: {e}\n", paint.heading("HTTP headers")),
    };
    let mut out = format!(
        "{}\n",
        paint.heading(&format!("HTTP headers (status {})", response.status))
    );
    for name in SECURITY_HEADERS {
        let line = match response.header(name) {
            Some(value) => format!("{name:<26} {value}"),
            None if name == "Strict-Transport-Security" => {
                paint.severity(Severity::Low, &format!("{name:<26} not set"))
            }
            None => format!("{name:<26} not set"),
        };
        let _ = writeln!(out, "  {line}");
    }
    out
}

/// Renders findings in the given order with coloured severity labels and
/// their ids, which `testls explain` describes.
#[must_use]
pub fn findings(findings: &[Finding], paint: Painter) -> String {
    let mut out = format!("{}\n", paint.heading("Findings"));
    if findings.is_empty() {
        let _ = writeln!(out, "  {}", paint.severity(Severity::Ok, "none"));
    }
    for f in findings {
        let label = format!("{:<8}", f.severity.as_str());
        let _ = writeln!(
            out,
            "  {} {} [{}]",
            paint.severity(f.severity, &label),
            f.message,
            f.id
        );
    }
    out
}

/// Formats a cipher suite id and name for the cipher listing.
fn cipher_label(version: ProtocolVersion, id: u32) -> String {
    format!("{}  {}", suite_id(version, id), cipher_name(version, id))
}

/// Formats a cipher suite id as hex: six digits for SSLv2 cipher specs,
/// four otherwise.
pub(crate) fn suite_id(version: ProtocolVersion, id: u32) -> String {
    if version == ProtocolVersion::SSL2 {
        format!("0x{id:06x}")
    } else {
        format!("0x{id:04x}")
    }
}

#[cfg(test)]
mod tests {
    use testls_checks::{RevocationMethod, RevocationStatus};

    use super::*;

    /// Painter without colour, for exact text comparisons.
    const PLAIN: Painter = Painter::new(false);

    /// The header shows target, address, and SNI or a placeholder.
    #[test]
    fn header_lines() {
        let addr: SocketAddr = "127.0.0.1:443".parse().unwrap();
        assert_eq!(
            header("example.com", addr, Some("example.com")),
            "Target: example.com (127.0.0.1:443)\nSNI:    example.com\n"
        );
        assert!(header("127.0.0.1", addr, None).ends_with("SNI:    (none)\n"));
    }

    /// Each protocol gets one aligned status line.
    #[test]
    fn protocol_lines() {
        let results = [
            ProtocolResult {
                version: ProtocolVersion::TLS12,
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
        assert_eq!(
            protocols(&results, PLAIN),
            "Protocols\n  TLSv1.2  offered\n  TLSv1.0  not offered\n  SSLv3    error: timed out\n"
        );
    }

    /// Offered protocols are coloured by their severity.
    #[test]
    fn protocol_colour() {
        let results = [ProtocolResult {
            version: ProtocolVersion::TLS10,
            support: ProtocolSupport::Supported,
        }];
        assert!(protocols(&results, Painter::new(true)).contains("\x1b[33moffered\x1b[0m"));
    }

    /// Cipher listings show the preference order and one suite per line.
    #[test]
    fn cipher_lines() {
        let section = CipherSection {
            version: ProtocolVersion::TLS12,
            outcome: Ok(CipherResult {
                version: ProtocolVersion::TLS12,
                suites: vec![0xc02f, 0x000a],
                order: CipherOrder::Server,
            }),
        };
        assert_eq!(
            ciphers(&section, PLAIN),
            "Ciphers TLSv1.2 server order\n  0xc02f  TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256\n  0x000a  TLS_RSA_WITH_3DES_EDE_CBC_SHA\n"
        );
    }

    /// SSLv2 cipher specs use six hex digits and no order note.
    #[test]
    fn ssl2_cipher_lines() {
        let section = CipherSection {
            version: ProtocolVersion::SSL2,
            outcome: Ok(CipherResult {
                version: ProtocolVersion::SSL2,
                suites: vec![0x01_0080],
                order: CipherOrder::NotApplicable,
            }),
        };
        let text = ciphers(&section, PLAIN);
        assert!(text.starts_with("Ciphers SSLv2\n  0x010080  "), "{text}");
    }

    /// A failed enumeration is reported on the heading line.
    #[test]
    fn cipher_error() {
        let section = CipherSection {
            version: ProtocolVersion::TLS13,
            outcome: Err("timed out".into()),
        };
        assert_eq!(
            ciphers(&section, PLAIN),
            "Ciphers TLSv1.3: error: timed out\n"
        );
    }

    /// Key exchange listings show groups in order and the DH prime size.
    #[test]
    fn key_exchange_lines() {
        let section = KeyExchangeSection {
            version: ProtocolVersion::TLS12,
            outcome: Ok(KeyExchangeResult {
                version: ProtocolVersion::TLS12,
                groups: vec![0x001d, 0x0017],
                group_order: CipherOrder::Server,
                dh_bits: Some(2048),
            }),
        };
        assert_eq!(
            key_exchange(&section, PLAIN),
            "Key exchange TLSv1.2 server order\n  0x001d  x25519\n  0x0017  secp256r1\n  DH      2048 bits\n"
        );
    }

    /// An empty result and a failed probe are both reported.
    #[test]
    fn key_exchange_empty_and_error() {
        let section = KeyExchangeSection {
            version: ProtocolVersion::SSL3,
            outcome: Ok(KeyExchangeResult {
                version: ProtocolVersion::SSL3,
                groups: vec![],
                group_order: CipherOrder::NotApplicable,
                dh_bits: None,
            }),
        };
        assert_eq!(
            key_exchange(&section, PLAIN),
            "Key exchange SSLv3\n  no ECDHE or DHE key exchange\n"
        );
        let section = KeyExchangeSection {
            version: ProtocolVersion::TLS13,
            outcome: Err("timed out".into()),
        };
        assert_eq!(
            key_exchange(&section, PLAIN),
            "Key exchange TLSv1.3: error: timed out\n"
        );
    }

    /// Certificates list subject, issuer, validity, names, and key.
    #[test]
    fn certificate_lines() {
        let section = Ok(CertificateSection {
            version: ProtocolVersion::TLS13,
            certificates: vec![
                Ok(CertificateInfo {
                    subject: "CN=localhost".into(),
                    issuer: "CN=test CA".into(),
                    not_before: "A".into(),
                    not_after: "B".into(),
                    not_before_unix: 0,
                    not_after_unix: 0,
                    names: vec!["localhost".into(), "127.0.0.1".into()],
                    key: "EC 256 bits".into(),
                }),
                Err("bad".into()),
            ],
            ocsp: None,
        });
        assert_eq!(
            certificate(&section, PLAIN),
            "Certificate (TLSv1.3)\n  #0 CN=localhost\n     issuer  CN=test CA\n     valid   A to B\n     names   localhost, 127.0.0.1\n     key     EC 256 bits\n  #1 cannot be parsed: bad\n  OCSP     not stapled\n"
        );
        assert_eq!(
            certificate(&Err("refused".into()), PLAIN),
            "Certificate: error: refused\n"
        );
    }

    /// The OCSP line shows the stapled status, revocation, or the error.
    #[test]
    fn ocsp_lines() {
        let status = |status| OcspStatus {
            status,
            produced_at: 0,
            this_update: 0,
            next_update: Some(1_793_577_600),
        };
        let good = Ok(status(CertStatus::Good));
        assert_eq!(
            ocsp_line(Some(&good), PLAIN),
            "good, next update Nov  2 00:00:00 2026 +00:00"
        );
        let revoked = Ok(status(CertStatus::Revoked {
            time: 1_790_812_800,
            reason: Some(1),
        }));
        assert_eq!(
            ocsp_line(Some(&revoked), PLAIN),
            "revoked on Oct  1 00:00:00 2026 +00:00 (keyCompromise)"
        );
        let unknown = Ok(status(CertStatus::Unknown));
        assert_eq!(ocsp_line(Some(&unknown), PLAIN), "unknown to the responder");
        assert_eq!(
            ocsp_line(Some(&Err("bad signature".into())), PLAIN),
            "invalid: bad signature"
        );
        assert_eq!(ocsp_line(None, PLAIN), "not stapled");
    }

    /// The revocation section lists each attempt with its result.
    #[test]
    fn revocation_lines() {
        let status = |status| RevocationStatus {
            status,
            this_update: 0,
            next_update: Some(1_793_577_600),
        };
        let checks = Ok(vec![
            RevocationCheck {
                method: RevocationMethod::Ocsp,
                url: "http://ocsp.test/".into(),
                outcome: Err("HTTP status 500".into()),
            },
            RevocationCheck {
                method: RevocationMethod::Crl,
                url: "http://crl.test/ca.crl".into(),
                outcome: Ok(status(CertStatus::Good)),
            },
            RevocationCheck {
                method: RevocationMethod::Crl,
                url: "http://crl.test/b.crl".into(),
                outcome: Ok(status(CertStatus::Revoked {
                    time: 1_790_812_800,
                    reason: None,
                })),
            },
        ]);
        assert_eq!(
            revocation(&checks, PLAIN),
            "Revocation\n  OCSP http://ocsp.test/  error: HTTP status 500\n  CRL  http://crl.test/ca.crl  good, next update Nov  2 00:00:00 2026 +00:00\n  CRL  http://crl.test/b.crl  revoked on Oct  1 00:00:00 2026 +00:00 (no reason given)\n"
        );
        let hostile = Ok(vec![RevocationCheck {
            method: RevocationMethod::Ocsp,
            url: "http://a/\x1b[2J".into(),
            outcome: Err("timeout".into()),
        }]);
        assert_eq!(
            revocation(&hostile, PLAIN),
            "Revocation\n  OCSP http://a/\\u{1b}[2J  error: timeout\n"
        );
        assert_eq!(
            revocation(&Ok(vec![]), PLAIN),
            "Revocation\n  no HTTP OCSP responder or CRL named\n"
        );
        assert_eq!(
            revocation(&Err("no chain".into()), PLAIN),
            "Revocation: error: no chain\n"
        );
    }

    /// The HTTP section lists each security header or `not set`, and a
    /// failed fetch is reported on the heading line.
    #[test]
    fn http_lines() {
        let response = Ok(HttpResponse {
            status: 200,
            headers: vec![
                ("server".into(), "test".into()),
                ("x-content-type-options".into(), "nosniff".into()),
            ],
        });
        assert_eq!(
            http(&response, PLAIN),
            "HTTP headers (status 200)\n  \
             Strict-Transport-Security  not set\n  \
             Content-Security-Policy    not set\n  \
             X-Frame-Options            not set\n  \
             X-Content-Type-Options     nosniff\n  \
             Referrer-Policy            not set\n"
        );
        assert!(
            http(&response, Painter::new(true))
                .contains("\x1b[36mStrict-Transport-Security  not set\x1b[0m")
        );
        assert_eq!(
            http(&Err("refused".into()), PLAIN),
            "HTTP headers: error: refused\n"
        );
    }

    /// Findings show padded severity labels and ids, or `none`.
    #[test]
    fn finding_lines() {
        assert_eq!(findings(&[], PLAIN), "Findings\n  none\n");
        let list = [Finding::new(
            "protocol.tls10",
            Severity::Medium,
            "TLS 1.0 is offered",
        )];
        assert_eq!(
            findings(&list, PLAIN),
            "Findings\n  medium   TLS 1.0 is offered [protocol.tls10]\n"
        );
        assert!(findings(&list, Painter::new(true)).contains("\x1b[33mmedium  \x1b[0m TLS 1.0"));
    }
}
