//! Overall letter grade for a scan, derived from the findings.
//!
//! This is testls' own model and is not compatible with SSL Labs grades.
//! The worst counted finding caps the grade: `critical` gives F, `high`
//! C, `medium` B and `low` A-. With no such finding the grade is A, or A+
//! when TLSv1.3 is offered, nothing older than TLSv1.2 is, and HSTS is
//! sent with a `max-age` of at least a year. An untrusted or mismatched
//! certificate adds the T marker. `docs/grading.md` documents the model.

use std::fmt;

use testls_probe::{HttpResponse, ProtocolResult, ProtocolSupport};
use testls_wire::ProtocolVersion;

use crate::{Finding, Severity, parse_hsts};

/// HSTS `max-age` A+ needs: one year.
const A_PLUS_MIN_MAX_AGE: u64 = 365 * 24 * 60 * 60;

/// Finding ids that add the T marker.
const TRUST_IDS: [&str; 2] = ["cert.untrusted", "cert.hostname_mismatch"];

/// Letter grade, from best to worst.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Letter {
    /// Best practice: no counted findings and the A+ requirements met.
    APlus,
    /// No counted findings.
    A,
    /// Worst counted finding is `low`.
    AMinus,
    /// Worst counted finding is `medium`.
    B,
    /// Worst counted finding is `high`.
    C,
    /// Worst counted finding is `critical`.
    F,
}

impl Letter {
    /// All letters, best first.
    pub const ALL: [Self; 6] = [
        Self::APlus,
        Self::A,
        Self::AMinus,
        Self::B,
        Self::C,
        Self::F,
    ];

    /// Display form, e.g. `A+`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::APlus => "A+",
            Self::A => "A",
            Self::AMinus => "A-",
            Self::B => "B",
            Self::C => "C",
            Self::F => "F",
        }
    }

    /// Grade cap for a worst counted finding of `severity`.
    fn cap(severity: Severity) -> Self {
        match severity {
            Severity::Ok | Severity::Info => Self::A,
            Severity::Low => Self::AMinus,
            Severity::Medium => Self::B,
            Severity::High => Self::C,
            Severity::Critical => Self::F,
        }
    }
}

impl fmt::Display for Letter {
    /// Writes the display form.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Grade of one scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grade {
    /// The letter.
    pub letter: Letter,
    /// The certificate is untrusted or does not cover the host (T marker).
    pub untrusted: bool,
    /// A probe failed, so the grade may be better than the server deserves.
    pub incomplete: bool,
    /// Why the grade is not better, one line each.
    pub reasons: Vec<String>,
}

impl fmt::Display for Grade {
    /// Writes the letter, then ` T` when untrusted, e.g. `C T`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.letter.as_str())?;
        if self.untrusted {
            f.write_str(" T")?;
        }
        Ok(())
    }
}

/// Whether `finding` counts towards the grade: `low` or worse and not a
/// `policy.*` deviation.
fn counts(finding: &Finding) -> bool {
    finding.severity >= Severity::Low && !finding.id.starts_with("policy.")
}

/// Whether `finding` reports a failed probe.
fn is_error(finding: &Finding) -> bool {
    !finding.id.starts_with("policy.")
        && matches!(
            finding.id.rsplit_once('.'),
            Some((_, "error" | "incomplete"))
        )
}

/// Requirements for A+ that the scan does not meet.
///
/// The requirements are testls' own rule. They follow current guidance
/// without being mandated by it: TLS 1.3 (RFC 8446), no TLS 1.0 or 1.1
/// (deprecated by RFC 8996 §1; SSL by RFC 6176 and RFC 7568), and HSTS
/// (RFC 6797) with a `max-age` of a year, as browser preload lists ask.
fn a_plus_gaps(protocols: &[ProtocolResult], http: Option<&HttpResponse>) -> Vec<String> {
    let offered = |v| {
        protocols
            .iter()
            .any(|r| r.version == v && r.support == ProtocolSupport::Supported)
    };
    let mut gaps = Vec::new();
    if !offered(ProtocolVersion::TLS13) {
        gaps.push("A+ needs TLSv1.3".to_owned());
    }
    let legacy: Vec<String> = protocols
        .iter()
        .filter(|r| r.version < ProtocolVersion::TLS12 && r.support == ProtocolSupport::Supported)
        .map(|r| r.version.to_string())
        .collect();
    if !legacy.is_empty() {
        gaps.push(format!(
            "A+ needs no protocol older than TLSv1.2, offered: {}",
            legacy.join(", ")
        ));
    }
    let hsts = http
        .and_then(|r| r.header("strict-transport-security"))
        .and_then(|v| parse_hsts(v).ok());
    match hsts {
        Some(h) if h.max_age >= A_PLUS_MIN_MAX_AGE => {}
        Some(_) => gaps.push("A+ needs HSTS max-age of at least one year".to_owned()),
        None => gaps.push("A+ needs a valid HSTS header".to_owned()),
    }
    gaps
}

/// Grades a scan from its `findings` before suppressions and baseline,
/// the protocol detection results, and the reply to `GET /`, if any.
#[must_use]
pub fn grade(
    findings: &[Finding],
    protocols: &[ProtocolResult],
    http: Option<&HttpResponse>,
) -> Grade {
    let worst = findings
        .iter()
        .filter(|f| counts(f))
        .map(|f| f.severity)
        .max();
    let mut reasons = Vec::new();
    let letter = if let Some(worst) = worst {
        let mut ids: Vec<&str> = findings
            .iter()
            .filter(|f| counts(f) && f.severity == worst)
            .map(|f| f.id.as_str())
            .collect();
        ids.sort_unstable();
        ids.dedup();
        reasons.push(format!("{worst} findings: {}", ids.join(", ")));
        Letter::cap(worst)
    } else {
        let gaps = a_plus_gaps(protocols, http);
        if gaps.is_empty() {
            Letter::APlus
        } else {
            reasons.extend(gaps);
            Letter::A
        }
    };
    let incomplete = findings.iter().any(is_error)
        || protocols
            .iter()
            .any(|r| matches!(r.support, ProtocolSupport::Error(_)));
    if incomplete {
        reasons.push("incomplete: some probes failed".to_owned());
    }
    Grade {
        letter,
        untrusted: findings.iter().any(|f| TRUST_IDS.contains(&f.id.as_str())),
        incomplete,
        reasons,
    }
}

#[cfg(test)]
mod tests {
    //! Unit tests for the grading model.

    use super::*;

    /// Protocol results where exactly `offered` are supported.
    fn protocols(offered: &[ProtocolVersion]) -> Vec<ProtocolResult> {
        ProtocolVersion::ALL
            .into_iter()
            .map(|version| ProtocolResult {
                version,
                support: if offered.contains(&version) {
                    ProtocolSupport::Supported
                } else {
                    ProtocolSupport::NotSupported
                },
            })
            .collect()
    }

    /// A reply carrying `hsts` as its `Strict-Transport-Security` header.
    fn http(hsts: Option<&str>) -> HttpResponse {
        HttpResponse {
            status: 200,
            headers: hsts
                .map(|v| ("strict-transport-security".to_owned(), v.to_owned()))
                .into_iter()
                .collect(),
        }
    }

    /// TLSv1.2 and TLSv1.3 only.
    const MODERN: [ProtocolVersion; 2] = [ProtocolVersion::TLS12, ProtocolVersion::TLS13];

    /// One year HSTS.
    const YEAR: &str = "max-age=31536000";

    /// The worst counted severity caps the letter.
    #[test]
    fn severity_caps() {
        let p = protocols(&MODERN);
        let r = http(Some(YEAR));
        for (severity, letter) in [
            (Severity::Low, Letter::AMinus),
            (Severity::Medium, Letter::B),
            (Severity::High, Letter::C),
            (Severity::Critical, Letter::F),
        ] {
            let f = [
                Finding::new("cipher.cbc", Severity::Low, "x"),
                Finding::new("x.y", severity, "x"),
            ];
            let g = grade(&f, &p, Some(&r));
            assert_eq!(g.letter, letter, "{severity}");
            assert_eq!(g.reasons.len(), 1, "{severity}");
        }
        let f = [
            Finding::new("cipher.cbc", Severity::Low, "x"),
            Finding::new("cipher.cbc", Severity::Low, "y"),
            Finding::new("hsts.missing", Severity::Low, "x"),
        ];
        assert_eq!(
            grade(&f, &p, Some(&r)).reasons,
            ["low findings: cipher.cbc, hsts.missing"]
        );
    }

    /// Info, ok and policy findings do not count.
    #[test]
    fn ignored_findings() {
        let f = [
            Finding::new("protocol.no_tls13", Severity::Info, "x"),
            Finding::new("cert.ok", Severity::Ok, "x"),
            Finding::new("policy.protocol", Severity::Critical, "x"),
            Finding::new("policy.incomplete", Severity::Info, "x"),
        ];
        let g = grade(&f, &protocols(&MODERN), Some(&http(Some(YEAR))));
        assert_eq!(g.letter, Letter::APlus);
        assert!(!g.incomplete && !g.untrusted && g.reasons.is_empty());
        assert_eq!(g.to_string(), "A+");
    }

    /// A+ needs TLSv1.3, nothing below TLSv1.2 and a year of HSTS.
    #[test]
    fn a_plus_requirements() {
        let a = |offered: &[ProtocolVersion], hsts: Option<Option<&str>>| {
            let g = grade(&[], &protocols(offered), hsts.map(http).as_ref());
            (g.letter, g.reasons)
        };
        assert_eq!(a(&MODERN, Some(Some(YEAR))).0, Letter::APlus);
        assert_eq!(
            a(&[ProtocolVersion::TLS12], Some(Some(YEAR))),
            (Letter::A, vec!["A+ needs TLSv1.3".to_owned()])
        );
        assert_eq!(
            a(
                &[ProtocolVersion::TLS11, ProtocolVersion::TLS13],
                Some(Some(YEAR))
            )
            .1,
            ["A+ needs no protocol older than TLSv1.2, offered: TLSv1.1"]
        );
        assert_eq!(
            a(&MODERN, Some(Some("max-age=31535999"))).1,
            ["A+ needs HSTS max-age of at least one year"]
        );
        for hsts in [None, Some(None), Some(Some("bogus"))] {
            assert_eq!(a(&MODERN, hsts).1, ["A+ needs a valid HSTS header"]);
        }
    }

    /// Trust failures add T without changing how the letter is computed.
    #[test]
    fn trust_marker() {
        for id in TRUST_IDS {
            let f = [Finding::new(id, Severity::High, "x")];
            let g = grade(&f, &protocols(&MODERN), None);
            assert!(g.untrusted);
            assert_eq!(g.to_string(), "C T");
        }
    }

    /// Failed probes mark the grade incomplete.
    #[test]
    fn incomplete() {
        let p = protocols(&MODERN);
        for id in ["cipher.error", "http.error", "x.incomplete"] {
            let g = grade(&[Finding::new(id, Severity::Info, "x")], &p, None);
            assert!(g.incomplete, "{id}");
            assert_eq!(
                g.reasons.last().map(String::as_str),
                Some("incomplete: some probes failed")
            );
        }
        let mut p = protocols(&MODERN);
        p[0].support = ProtocolSupport::Error("timeout".to_owned());
        assert!(grade(&[], &p, None).incomplete);
    }

    /// Letters order best first and print as expected.
    #[test]
    fn letters() {
        let names: Vec<&str> = Letter::ALL.iter().map(|l| l.as_str()).collect();
        assert_eq!(names, ["A+", "A", "A-", "B", "C", "F"]);
        assert!(Letter::ALL.is_sorted());
        assert_eq!(Letter::AMinus.to_string(), "A-");
        for s in Severity::ALL {
            assert!(Letter::cap(s) >= Letter::A);
        }
    }
}
