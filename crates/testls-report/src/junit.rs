//! JUnit XML report for CI systems that show test results.
//!
//! Each scanned address is a `<testsuite>` and each finding a `<testcase>`
//! named by its id. Findings at or above `--fail-on` carry a `<failure>`,
//! so the report fails exactly where the exit code does; a scan that could
//! not run is a suite with one `<error>` case. The element and attribute
//! names follow the common JUnit XML format read by Jenkins, GitLab and
//! GitHub test reporters.

use std::fmt::Write as _;

use testls_checks::Severity;

use crate::sarif::Scan;

/// A target whose scan failed before producing findings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    /// Target as given on the command line.
    pub target: String,
    /// Why the scan failed.
    pub error: String,
}

/// Escapes `s` for XML text and attribute values, dropping characters XML
/// 1.0 cannot represent.
fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            '\t' | '\n' | '\r' => out.push(c),
            c if c < ' ' || matches!(c, '\u{fffe}' | '\u{ffff}') => {}
            c => out.push(c),
        }
    }
    out
}

/// Renders `scans` and `failures` as one JUnit XML document followed by a
/// newline. Findings at or above `fail_on` are failures.
#[must_use]
pub fn render(scans: &[Scan], failures: &[Failure], fail_on: Severity) -> String {
    let tests = scans.iter().map(|s| s.findings.len()).sum::<usize>() + failures.len();
    let failed = scans
        .iter()
        .flat_map(|s| &s.findings)
        .filter(|f| f.severity >= fail_on)
        .count();
    let mut out = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    let _ = writeln!(
        out,
        "<testsuites name=\"testls\" tests=\"{tests}\" failures=\"{failed}\" errors=\"{}\">",
        failures.len()
    );
    for scan in scans {
        let target = escape(&scan.target);
        let failed = scan
            .findings
            .iter()
            .filter(|f| f.severity >= fail_on)
            .count();
        let _ = writeln!(
            out,
            "  <testsuite name=\"{target} ({})\" tests=\"{}\" failures=\"{failed}\" errors=\"0\">",
            scan.addr,
            scan.findings.len()
        );
        for f in &scan.findings {
            let name = escape(&f.id);
            let message = escape(&f.message);
            let severity = f.severity.as_str();
            if f.severity >= fail_on {
                let _ = writeln!(
                    out,
                    "    <testcase name=\"{name}\" classname=\"{target}\">\n      \
                     <failure message=\"{message}\" type=\"{severity}\">{severity}: {message}</failure>\n    \
                     </testcase>"
                );
            } else {
                let _ = writeln!(
                    out,
                    "    <testcase name=\"{name}\" classname=\"{target}\">\n      \
                     <system-out>{severity}: {message}</system-out>\n    </testcase>"
                );
            }
        }
        out.push_str("  </testsuite>\n");
    }
    for failure in failures {
        let target = escape(&failure.target);
        let error = escape(&failure.error);
        let _ = writeln!(
            out,
            "  <testsuite name=\"{target}\" tests=\"1\" failures=\"0\" errors=\"1\">\n    \
             <testcase name=\"scan\" classname=\"{target}\">\n      \
             <error message=\"{error}\" type=\"scan\">{error}</error>\n    </testcase>\n  \
             </testsuite>"
        );
    }
    out.push_str("</testsuites>\n");
    out
}

#[cfg(test)]
mod tests {
    use testls_checks::Finding;

    use super::*;

    /// A scan of `target` with the given findings.
    fn scan(target: &str, findings: Vec<Finding>) -> Scan {
        Scan {
            target: target.to_owned(),
            addr: "192.0.2.1:443".parse().expect("address"),
            findings,
        }
    }

    /// Findings at or above the threshold fail, others pass with their
    /// message as output; counts add up per suite and overall.
    #[test]
    fn suites_and_failures() {
        let scans = [scan(
            "a.example:443",
            vec![
                Finding::new("protocol.tls10", Severity::Medium, "TLSv1.0 offered"),
                Finding::new("hsts.missing", Severity::Low, "no HSTS"),
            ],
        )];
        let failures = [Failure {
            target: "b.example:443".to_owned(),
            error: "cannot resolve: no such host".to_owned(),
        }];
        let xml = render(&scans, &failures, Severity::Medium);
        assert!(xml.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"));
        assert!(
            xml.contains("<testsuites name=\"testls\" tests=\"3\" failures=\"1\" errors=\"1\">")
        );
        assert!(xml.contains(
            "<testsuite name=\"a.example:443 (192.0.2.1:443)\" tests=\"2\" failures=\"1\" errors=\"0\">"
        ));
        assert!(xml.contains(
            "<failure message=\"TLSv1.0 offered\" type=\"medium\">medium: TLSv1.0 offered</failure>"
        ));
        assert!(xml.contains("<system-out>low: no HSTS</system-out>"));
        assert!(xml.contains("<error message=\"cannot resolve: no such host\" type=\"scan\">"));
        assert!(xml.ends_with("</testsuites>\n"));
        assert_eq!(xml.matches("<testcase ").count(), 3);
        assert_eq!(xml.matches("</testcase>").count(), 3);
    }

    /// An empty run is still a well-formed document.
    #[test]
    fn empty() {
        assert_eq!(
            render(&[], &[], Severity::Low),
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <testsuites name=\"testls\" tests=\"0\" failures=\"0\" errors=\"0\">\n\
             </testsuites>\n"
        );
    }

    /// Markup characters are escaped and characters XML cannot hold are
    /// dropped.
    #[test]
    fn escaping() {
        assert_eq!(
            escape("a<b>&\"c'\u{1}\td\u{ffff}"),
            "a&lt;b&gt;&amp;&quot;c&apos;\td"
        );
        let scans = [scan(
            "x",
            vec![Finding::new("id", Severity::High, "<script>")],
        )];
        let xml = render(&scans, &[], Severity::High);
        assert!(xml.contains("&lt;script&gt;"));
        assert!(!xml.contains("<script>"));
    }
}
