//! Self-contained HTML report for sharing and archiving.
//!
//! The page has the same layout as the Markdown report: a summary table of
//! finding counts per scanned address, one section per address listing its
//! findings from most to least severe, with those at or above `--fail-on`
//! marked, and a table of targets whose scan could not run. Styles are
//! inline and the page loads nothing else; a Content Security Policy
//! forbids scripts and remote resources, so scanned server text cannot run
//! in the browser even if escaping were bypassed.

use std::fmt::Write as _;

use testls_checks::Severity;

use crate::junit::Failure;
use crate::sarif::Scan;

/// Page head: metadata, the Content Security Policy and the style sheet.
const HEAD: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>testls report</title>
<style>
body { font-family: system-ui, sans-serif; margin: 2em; color: #1f2328; }
table { border-collapse: collapse; margin-bottom: 1.5em; }
th, td { border: 1px solid #d0d7de; padding: 0.3em 0.6em; text-align: left; vertical-align: top; }
th { background: #f6f8fa; }
td.n { text-align: right; }
code { font-size: 0.9em; }
tr.failing { background: #ffebe9; }
.critical, .high { color: #cf222e; font-weight: bold; }
.medium { color: #9a6700; font-weight: bold; }
.low { color: #0969da; }
.info, .ok { color: #57606a; }
</style>
</head>
<body>
<h1>testls report</h1>
"#;

/// Escapes `s` for HTML text and attribute values. Control characters other
/// than tab and line breaks are dropped.
fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            '\t' | '\r' | '\n' => out.push(c),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

/// Renders `scans` and `failures` as one HTML page. Findings at or above
/// `fail_on` are marked as failing.
#[must_use]
pub fn render(scans: &[Scan], failures: &[Failure], fail_on: Severity) -> String {
    let mut out = String::from(HEAD);
    let failing = scans
        .iter()
        .flat_map(|s| &s.findings)
        .filter(|f| f.severity >= fail_on)
        .count();
    let _ = writeln!(
        out,
        "<p>{} scanned, {} failed to scan, {failing} finding(s) at or above <code>{}</code>.</p>",
        scans.len(),
        failures.len(),
        fail_on.as_str()
    );
    if !scans.is_empty() {
        out.push_str("<table>\n<tr><th>Target</th><th>Address</th>");
        for severity in Severity::ALL.iter().rev() {
            let _ = write!(out, "<th>{}</th>", severity.as_str());
        }
        out.push_str("</tr>\n");
        for scan in scans {
            let _ = write!(
                out,
                "<tr><td>{}</td><td>{}</td>",
                escape(&scan.target),
                scan.addr
            );
            for severity in Severity::ALL.iter().rev() {
                let n = scan
                    .findings
                    .iter()
                    .filter(|f| f.severity == *severity)
                    .count();
                let _ = write!(out, "<td class=\"n\">{n}</td>");
            }
            out.push_str("</tr>\n");
        }
        out.push_str("</table>\n");
    }
    for scan in scans {
        let _ = writeln!(out, "<h2>{} ({})</h2>", escape(&scan.target), scan.addr);
        if scan.findings.is_empty() {
            out.push_str("<p>No findings.</p>\n");
            continue;
        }
        out.push_str("<table>\n<tr><th>Severity</th><th>Finding</th><th>Message</th></tr>\n");
        let mut findings: Vec<_> = scan.findings.iter().collect();
        findings.sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| a.id.cmp(&b.id)));
        for f in findings {
            let row = if f.severity >= fail_on {
                " class=\"failing\""
            } else {
                ""
            };
            let severity = f.severity.as_str();
            let _ = writeln!(
                out,
                "<tr{row}><td class=\"{severity}\">{severity}</td><td><code>{}</code></td><td>{}</td></tr>",
                escape(&f.id),
                escape(&f.message)
            );
        }
        out.push_str("</table>\n");
    }
    if !failures.is_empty() {
        out.push_str("<h2>Scan errors</h2>\n<table>\n<tr><th>Target</th><th>Error</th></tr>\n");
        for failure in failures {
            let _ = writeln!(
                out,
                "<tr class=\"failing\"><td>{}</td><td>{}</td></tr>",
                escape(&failure.target),
                escape(&failure.error)
            );
        }
        out.push_str("</table>\n");
    }
    out.push_str("</body>\n</html>\n");
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
        let html = render(&scans, &failures, Severity::Medium);
        assert!(html.starts_with("<!DOCTYPE html>\n"));
        assert!(html.ends_with("</body>\n</html>\n"));
        assert!(html.contains(
            "<p>2 scanned, 1 failed to scan, 1 finding(s) at or above <code>medium</code>.</p>"
        ));
        assert!(html.contains(
            "<tr><td>a.example:443</td><td>192.0.2.1:443</td>\
             <td class=\"n\">0</td><td class=\"n\">0</td><td class=\"n\">1</td>\
             <td class=\"n\">1</td><td class=\"n\">0</td><td class=\"n\">0</td></tr>"
        ));
        let medium = html
            .find(
                "<tr class=\"failing\"><td class=\"medium\">medium</td>\
                 <td><code>protocol.tls10</code></td><td>TLSv1.0 offered</td></tr>",
            )
            .expect("failing finding");
        let low = html
            .find("<tr><td class=\"low\">low</td><td><code>hsts.missing</code></td><td>no HSTS</td></tr>")
            .expect("passing finding");
        assert!(medium < low);
        assert!(html.contains("<h2>b.example:443 (192.0.2.1:443)</h2>\n<p>No findings.</p>\n"));
        assert!(html.contains("<td>c.example:443</td><td>cannot resolve: no such host</td>"));
    }

    /// An empty run has a summary line and no tables.
    #[test]
    fn empty() {
        let html = render(&[], &[], Severity::Low);
        assert!(html.contains(
            "<p>0 scanned, 0 failed to scan, 0 finding(s) at or above <code>low</code>.</p>"
        ));
        assert!(!html.contains("<table>"));
    }

    /// Markup in scanned text is escaped and the page forbids scripts.
    #[test]
    fn escaping() {
        assert_eq!(escape("a<b>&\"'\n\u{1}"), "a&lt;b&gt;&amp;&quot;&#39;\n");
        let scans = [scan(
            "<x>",
            vec![Finding::new(
                "id<",
                Severity::High,
                "<script>alert(1)</script>",
            )],
        )];
        let html = render(&scans, &[], Severity::High);
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(!html.contains("<script>"));
        assert!(!html.contains("<x>"));
        assert!(html.contains("default-src 'none'"));
    }
}
