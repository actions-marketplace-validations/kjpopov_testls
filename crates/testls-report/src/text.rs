//! Plain-text report sections.
//!
//! Each function renders one section as newline-terminated lines, so the
//! CLI can print sections as soon as their probes finish.

use std::fmt::Write as _;
use std::net::SocketAddr;

use testls_checks::{
    CertificateInfo, Finding, Severity, cipher_name, cipher_severity, protocol_severity,
};
use testls_probe::{CipherOrder, CipherResult, ProtocolResult, ProtocolSupport};
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

/// The certificate chain presented in a full handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateSection {
    /// Protocol version of the handshake.
    pub version: ProtocolVersion,
    /// Details of each certificate, leaf first, or why it cannot be parsed.
    pub certificates: Vec<Result<CertificateInfo, String>>,
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
    out
}

/// Renders findings in the given order with coloured severity labels.
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
            "  {} {}",
            paint.severity(f.severity, &label),
            f.message
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
        });
        assert_eq!(
            certificate(&section, PLAIN),
            "Certificate (TLSv1.3)\n  #0 CN=localhost\n     issuer  CN=test CA\n     valid   A to B\n     names   localhost, 127.0.0.1\n     key     EC 256 bits\n  #1 cannot be parsed: bad\n"
        );
        assert_eq!(
            certificate(&Err("refused".into()), PLAIN),
            "Certificate: error: refused\n"
        );
    }

    /// Findings show padded severity labels, or `none`.
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
            "Findings\n  medium   TLS 1.0 is offered\n"
        );
        assert!(findings(&list, Painter::new(true)).contains("\x1b[33mmedium  \x1b[0m TLS 1.0"));
    }
}
