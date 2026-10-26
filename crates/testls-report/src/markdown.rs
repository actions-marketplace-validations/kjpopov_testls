//! Markdown report for pull request comments and CI job summaries.
//!
//! The report starts with a summary table of finding counts per scanned
//! address, followed by one section per address listing its findings from
//! most to least severe. Findings at or above `--fail-on` are marked, so the
//! report shows why the exit code failed. Targets whose scan could not run
//! are listed with their error. Output is GitHub Flavored Markdown.

use std::fmt::Write as _;

use testls_checks::Severity;

use crate::junit::Failure;
use crate::sarif::Scan;

/// Escapes `s` for inline Markdown text in a table cell: Markdown and HTML
/// punctuation is backslash-escaped and line breaks become spaces.
fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' | '`' | '*' | '_' | '[' | ']' | '<' | '>' | '|' | '#' | '!' | '~' | '&' => {
                out.push('\\');
                out.push(c);
            }
            '\r' | '\n' => out.push(' '),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

/// Renders `scans` and `failures` as one Markdown document. Findings at or
/// above `fail_on` are marked as failing.
#[must_use]
pub fn render(scans: &[Scan], failures: &[Failure], fail_on: Severity) -> String {
    let mut out = String::from("# testls report\n\n");
    let failing = scans
        .iter()
        .flat_map(|s| &s.findings)
        .filter(|f| f.severity >= fail_on)
        .count();
    let _ = writeln!(
        out,
        "{} scanned, {} failed to scan, {failing} finding(s) at or above `{}`.\n",
        scans.len(),
        failures.len(),
        fail_on.as_str()
    );
    if !scans.is_empty() {
        out.push_str("| Target | Address |");
        for severity in Severity::ALL.iter().rev() {
            let _ = write!(out, " {} |", severity.as_str());
        }
        out.push_str("\n| --- | --- |");
        out.push_str(&" ---: |".repeat(Severity::ALL.len()));
        out.push('\n');
        for scan in scans {
            let _ = write!(out, "| {} | {} |", escape(&scan.target), scan.addr);
            for severity in Severity::ALL.iter().rev() {
                let n = scan
                    .findings
                    .iter()
                    .filter(|f| f.severity == *severity)
                    .count();
                let _ = write!(out, " {n} |");
            }
            out.push('\n');
        }
    }
    for scan in scans {
        let _ = writeln!(out, "\n## {} ({})\n", escape(&scan.target), scan.addr);
        if scan.findings.is_empty() {
            out.push_str("No findings.\n");
            continue;
        }
        out.push_str("| | Severity | Finding | Message |\n| --- | --- | --- | --- |\n");
        let mut findings: Vec<_> = scan.findings.iter().collect();
        findings.sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| a.id.cmp(&b.id)));
        for f in findings {
            let mark = if f.severity >= fail_on { "❌" } else { "" };
            let _ = writeln!(
                out,
                "| {mark} | {} | `{}` | {} |",
                f.severity.as_str(),
                f.id.replace('`', ""),
                escape(&f.message)
            );
        }
    }
    if !failures.is_empty() {
        out.push_str("\n## Scan errors\n\n| Target | Error |\n| --- | --- |\n");
        for failure in failures {
            let _ = writeln!(
                out,
                "| {} | {} |",
                escape(&failure.target),
                escape(&failure.error)
            );
        }
    }
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

    /// The summary counts findings per severity, sections list findings
    /// most severe first with failing ones marked, and scan errors follow.
    #[test]
    fn report() {
        let scans = [
            scan(
                "a.example:443",
                vec![
                    Finding::new("hsts.missing", Severity::Low, "no HSTS"),
                    Finding::new("protocol.tls10", Severity::Medium, "TLSv1.0 offered"),
                ],
            ),
            scan("b.example:443", vec![]),
        ];
        let failures = [Failure {
            target: "c.example:443".to_owned(),
            error: "cannot resolve: no such host".to_owned(),
        }];
        let md = render(&scans, &failures, Severity::Medium);
        assert!(md.starts_with("# testls report\n\n"));
        assert!(md.contains("2 scanned, 1 failed to scan, 1 finding(s) at or above `medium`."));
        assert!(md.contains(
            "| Target | Address | critical | high | medium | low | info | ok |\n\
             | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |\n\
             | a.example:443 | 192.0.2.1:443 | 0 | 0 | 1 | 1 | 0 | 0 |\n\
             | b.example:443 | 192.0.2.1:443 | 0 | 0 | 0 | 0 | 0 | 0 |\n"
        ));
        let medium = md
            .find("| ❌ | medium | `protocol.tls10` | TLSv1.0 offered |")
            .expect("failing finding");
        let low = md
            .find("|  | low | `hsts.missing` | no HSTS |")
            .expect("passing finding");
        assert!(medium < low);
        assert!(md.contains("## b.example:443 (192.0.2.1:443)\n\nNo findings.\n"));
        assert!(md.contains("| c.example:443 | cannot resolve: no such host |"));
    }

    /// An empty run has a summary line and nothing else.
    #[test]
    fn empty() {
        assert_eq!(
            render(&[], &[], Severity::Low),
            "# testls report\n\n0 scanned, 0 failed to scan, 0 finding(s) at or above `low`.\n\n"
        );
    }

    /// Markdown and HTML markup cannot break out of a table cell.
    #[test]
    fn escaping() {
        assert_eq!(escape("a|b<i>*c*\n`d`\u{1}"), "a\\|b\\<i\\>\\*c\\* \\`d\\`");
        let scans = [scan(
            "x",
            vec![Finding::new("id", Severity::High, "<script>|")],
        )];
        let md = render(&scans, &[], Severity::High);
        assert!(md.contains("\\<script\\>\\|"));
        assert!(!md.contains("<script>"));
    }
}
