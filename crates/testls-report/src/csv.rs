//! CSV report for spreadsheets and ad-hoc scripting.
//!
//! One header row, then one row per finding with the columns `target`,
//! `address`, `severity`, `id`, `message` and `failing` (`true` when the
//! finding is at or above `--fail-on`). Targets whose scan could not run
//! get one row with the id `scan.error`, an empty address and severity,
//! and the error as message. Fields are quoted as in RFC 4180 (section 2)
//! and rows end with CRLF.

use std::fmt::Write as _;

use testls_checks::Severity;

use crate::junit::Failure;
use crate::sarif::Scan;

/// Column names of the header row.
const HEADER: [&str; 6] = ["target", "address", "severity", "id", "message", "failing"];

/// Quotes `s` as one CSV field. Fields with a comma, quote or line break
/// are wrapped in double quotes with inner quotes doubled (RFC 4180,
/// section 2). Fields starting with `=`, `+`, `-`, `@`, tab, CR or LF get
/// a leading `'` so spreadsheets do not evaluate scanned server data as a
/// formula (OWASP "CSV Injection"). Other control characters, such as
/// ESC, are escaped so viewing the file cannot drive a terminal.
fn field(s: &str) -> String {
    let s: String = s
        .chars()
        .map(|c| match c {
            '\t' | '\r' | '\n' => c.to_string(),
            c if c.is_control() => c.escape_default().to_string(),
            c => c.to_string(),
        })
        .collect();
    let guard = s.starts_with(['=', '+', '-', '@', '\t', '\r', '\n']);
    let value = if guard { format!("'{s}") } else { s };
    if value.contains([',', '"', '\r', '\n']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value
    }
}

/// Appends one CRLF-terminated row of `fields` to `out`.
fn row(out: &mut String, fields: &[&str]) {
    let line: Vec<String> = fields.iter().map(|f| field(f)).collect();
    let _ = write!(out, "{}\r\n", line.join(","));
}

/// Renders `scans` and `failures` as one CSV document. Findings at or
/// above `fail_on` have `failing` set to `true`; within a scan, rows are
/// ordered from most to least severe, then by id.
#[must_use]
pub fn render(scans: &[Scan], failures: &[Failure], fail_on: Severity) -> String {
    let mut out = String::new();
    row(&mut out, &HEADER);
    for scan in scans {
        let addr = scan.addr.to_string();
        let mut findings: Vec<_> = scan.findings.iter().collect();
        findings.sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| a.id.cmp(&b.id)));
        for f in findings {
            let failing = if f.severity >= fail_on {
                "true"
            } else {
                "false"
            };
            row(
                &mut out,
                &[
                    &scan.target,
                    &addr,
                    f.severity.as_str(),
                    &f.id,
                    &f.message,
                    failing,
                ],
            );
        }
    }
    for failure in failures {
        row(
            &mut out,
            &[
                &failure.target,
                "",
                "",
                "scan.error",
                &failure.error,
                "true",
            ],
        );
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

    /// Rows follow the header, most severe first, with scan errors last.
    #[test]
    fn rows() {
        let scans = [scan(
            "a.example:443",
            vec![
                Finding::new("hsts.missing", Severity::Low, "no HSTS"),
                Finding::new("protocol.tls10", Severity::Medium, "TLSv1.0 offered"),
            ],
        )];
        let failures = [Failure {
            target: "c.example:443".to_owned(),
            error: "cannot resolve: no such host".to_owned(),
        }];
        assert_eq!(
            render(&scans, &failures, Severity::Medium),
            "target,address,severity,id,message,failing\r\n\
             a.example:443,192.0.2.1:443,medium,protocol.tls10,TLSv1.0 offered,true\r\n\
             a.example:443,192.0.2.1:443,low,hsts.missing,no HSTS,false\r\n\
             c.example:443,,,scan.error,cannot resolve: no such host,true\r\n"
        );
    }

    /// An empty run is just the header.
    #[test]
    fn empty() {
        assert_eq!(
            render(&[], &[], Severity::Low),
            "target,address,severity,id,message,failing\r\n"
        );
    }

    /// Separators and quotes are quoted, and formula prefixes are defused.
    #[test]
    fn quoting() {
        assert_eq!(field("plain"), "plain");
        assert_eq!(field("a,b"), "\"a,b\"");
        assert_eq!(field("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(field("two\nlines"), "\"two\nlines\"");
        assert_eq!(field("=1+1"), "'=1+1");
        assert_eq!(field("@SUM(A1),x"), "\"'@SUM(A1),x\"");
        assert_eq!(field("\rx"), "\"'\rx\"");
        assert_eq!(field("\n=1+1"), "\"'\n=1+1\"");
        assert_eq!(field(""), "");
        assert_eq!(field("a\x1b[2Jb"), "a\\u{1b}[2Jb");
    }
}
