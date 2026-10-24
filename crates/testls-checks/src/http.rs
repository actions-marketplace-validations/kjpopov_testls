//! HTTP checks: HSTS (RFC 6797), preload eligibility, and security headers.

use testls_probe::HttpResponse;

use crate::{Finding, Severity};

/// `max-age` below which HSTS is reported as short: 180 days.
const HSTS_MIN_MAX_AGE: u64 = 180 * 24 * 60 * 60;

/// `max-age` required for HSTS preload list submission: one year
/// (<https://hstspreload.org/#submission-requirements>).
const PRELOAD_MIN_MAX_AGE: u64 = 365 * 24 * 60 * 60;

/// Parsed `Strict-Transport-Security` policy (RFC 6797 §6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hsts {
    /// Seconds the browser should remember the policy.
    pub max_age: u64,
    /// The `includeSubDomains` directive is present.
    pub include_subdomains: bool,
    /// The non-standard `preload` directive is present.
    pub preload: bool,
}

impl Hsts {
    /// Whether the policy meets the preload list's header requirements:
    /// `max-age` of at least a year, `includeSubDomains`, and `preload`.
    #[must_use]
    pub fn preload_eligible(&self) -> bool {
        self.max_age >= PRELOAD_MIN_MAX_AGE && self.include_subdomains && self.preload
    }
}

/// Parses a `Strict-Transport-Security` value (RFC 6797 §6.1).
///
/// Directive names are case-insensitive, values may be quoted, unknown
/// directives are ignored, and a repeated directive invalidates the header.
///
/// # Errors
/// Returns a short reason when the value is not a valid policy.
pub fn parse_hsts(value: &str) -> Result<Hsts, String> {
    let mut max_age = None;
    let mut include_subdomains = false;
    let mut preload = false;
    let mut seen: Vec<String> = Vec::new();
    for directive in value.split(';') {
        let directive = directive.trim_matches([' ', '\t']);
        if directive.is_empty() {
            continue;
        }
        let (name, arg) = match directive.split_once('=') {
            Some((n, v)) => (
                n.trim_matches([' ', '\t']),
                Some(unquote(v.trim_matches([' ', '\t']))),
            ),
            None => (directive, None),
        };
        let name = name.to_ascii_lowercase();
        if seen.contains(&name) {
            return Err(format!("directive {name} repeated"));
        }
        match (name.as_str(), arg) {
            ("max-age", Some(v)) if !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()) => {
                // Values beyond u64 are clamped; they are "forever" in practice.
                max_age = Some(v.parse().unwrap_or(u64::MAX));
            }
            ("max-age", _) => return Err("max-age is not a number".to_owned()),
            ("includesubdomains", None) => include_subdomains = true,
            ("preload", None) => preload = true,
            ("includesubdomains" | "preload", Some(_)) => {
                return Err(format!("directive {name} takes no value"));
            }
            _ => {}
        }
        seen.push(name);
    }
    let max_age = max_age.ok_or("max-age is missing")?;
    Ok(Hsts {
        max_age,
        include_subdomains,
        preload,
    })
}

/// Strips one pair of surrounding double quotes (a `quoted-string` without
/// escapes, which is all `max-age` can hold).
fn unquote(v: &str) -> &str {
    v.strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .unwrap_or(v)
}

/// HSTS and security header findings for the reply to `GET /`.
#[must_use]
pub fn http_findings(response: &HttpResponse) -> Vec<Finding> {
    let mut findings = hsts_findings(response);
    findings.extend(header_findings(response));
    findings
}

/// Findings for the `Strict-Transport-Security` header. Only the first
/// header is processed (RFC 6797 §8.1).
fn hsts_findings(response: &HttpResponse) -> Vec<Finding> {
    let Some(value) = response.header("strict-transport-security") else {
        return vec![Finding::new(
            "hsts.missing",
            Severity::Low,
            "no Strict-Transport-Security header",
        )];
    };
    let hsts = match parse_hsts(value) {
        Ok(h) => h,
        Err(e) => {
            return vec![Finding::new(
                "hsts.invalid",
                Severity::Low,
                format!("invalid Strict-Transport-Security header: {e}"),
            )];
        }
    };
    let mut findings = Vec::new();
    if hsts.max_age == 0 {
        findings.push(Finding::new(
            "hsts.disabled",
            Severity::Low,
            "Strict-Transport-Security max-age=0 removes the policy",
        ));
    } else if hsts.max_age < HSTS_MIN_MAX_AGE {
        findings.push(Finding::new(
            "hsts.short",
            Severity::Low,
            format!(
                "Strict-Transport-Security max-age={} is below 180 days",
                hsts.max_age
            ),
        ));
    } else {
        findings.push(Finding::new(
            "hsts",
            Severity::Ok,
            format!("Strict-Transport-Security max-age={}", hsts.max_age),
        ));
    }
    if hsts.preload && !hsts.preload_eligible() {
        findings.push(Finding::new(
            "hsts.preload_ineligible",
            Severity::Info,
            "HSTS preload requested but max-age below one year or includeSubDomains missing",
        ));
    }
    findings
}

/// Findings for missing security headers that protect browsers against
/// MIME sniffing, framing, content injection, and referrer leaks.
fn header_findings(response: &HttpResponse) -> Vec<Finding> {
    let mut findings = Vec::new();
    let csp = response.header("content-security-policy");
    let nosniff = response
        .header("x-content-type-options")
        .is_some_and(|v| v.eq_ignore_ascii_case("nosniff"));
    if !nosniff {
        findings.push(Finding::new(
            "header.x_content_type_options",
            Severity::Info,
            "no X-Content-Type-Options: nosniff header",
        ));
    }
    let frame_ancestors = csp.is_some_and(|v| {
        v.split(';').any(|d| {
            d.trim()
                .split_ascii_whitespace()
                .next()
                .is_some_and(|n| n.eq_ignore_ascii_case("frame-ancestors"))
        })
    });
    if response.header("x-frame-options").is_none() && !frame_ancestors {
        findings.push(Finding::new(
            "header.framing",
            Severity::Info,
            "no X-Frame-Options header or CSP frame-ancestors directive",
        ));
    }
    if csp.is_none() {
        findings.push(Finding::new(
            "header.content_security_policy",
            Severity::Info,
            "no Content-Security-Policy header",
        ));
    }
    if response.header("referrer-policy").is_none() {
        findings.push(Finding::new(
            "header.referrer_policy",
            Severity::Info,
            "no Referrer-Policy header",
        ));
    }
    findings
}

#[cfg(test)]
mod tests {
    //! Unit tests for HSTS parsing and header findings.

    use super::*;

    /// Response with status 200 and the given header fields.
    fn response(headers: &[(&str, &str)]) -> HttpResponse {
        HttpResponse {
            status: 200,
            headers: headers
                .iter()
                .map(|(n, v)| (n.to_ascii_lowercase(), (*v).to_owned()))
                .collect(),
        }
    }

    /// Finding ids with their severities, for compact assertions.
    fn ids(findings: &[Finding]) -> Vec<(&str, Severity)> {
        findings
            .iter()
            .map(|f| (f.id.as_str(), f.severity))
            .collect()
    }

    /// Valid policies, including quoting, case, and unknown directives.
    #[test]
    fn parses_hsts() {
        assert_eq!(
            parse_hsts("max-age=31536000; includeSubDomains; preload"),
            Ok(Hsts {
                max_age: 31_536_000,
                include_subdomains: true,
                preload: true
            })
        );
        assert_eq!(
            parse_hsts(" MAX-AGE=\"600\" ;; future=x"),
            Ok(Hsts {
                max_age: 600,
                include_subdomains: false,
                preload: false
            })
        );
        assert_eq!(
            parse_hsts("max-age=99999999999999999999999").map(|h| h.max_age),
            Ok(u64::MAX)
        );
    }

    /// Invalid policies are rejected with a reason.
    #[test]
    fn rejects_invalid_hsts() {
        for value in [
            "",
            "includeSubDomains",
            "max-age=",
            "max-age=-1",
            "max-age=1d",
            "max-age=1; max-age=2",
            "max-age=1; preload=yes",
            "max-age=1; includesubdomains; IncludeSubDomains",
        ] {
            assert!(parse_hsts(value).is_err(), "{value}");
        }
    }

    /// Preload eligibility needs a year, includeSubDomains, and preload.
    #[test]
    fn preload_eligibility() {
        let h = |v| parse_hsts(v).unwrap().preload_eligible();
        assert!(h("max-age=31536000; includeSubDomains; preload"));
        assert!(!h("max-age=31535999; includeSubDomains; preload"));
        assert!(!h("max-age=31536000; preload"));
        assert!(!h("max-age=31536000; includeSubDomains"));
    }

    /// A well-configured site only gets the ok HSTS finding.
    #[test]
    fn good_headers() {
        let r = response(&[
            (
                "Strict-Transport-Security",
                "max-age=63072000; includeSubDomains; preload",
            ),
            ("X-Content-Type-Options", "nosniff"),
            (
                "Content-Security-Policy",
                "default-src 'self'; frame-ancestors 'none'",
            ),
            ("Referrer-Policy", "no-referrer"),
        ]);
        assert_eq!(ids(&http_findings(&r)), [("hsts", Severity::Ok)]);
    }

    /// A bare response reports every missing header.
    #[test]
    fn missing_headers() {
        assert_eq!(
            ids(&http_findings(&response(&[]))),
            [
                ("hsts.missing", Severity::Low),
                ("header.x_content_type_options", Severity::Info),
                ("header.framing", Severity::Info),
                ("header.content_security_policy", Severity::Info),
                ("header.referrer_policy", Severity::Info),
            ]
        );
    }

    /// Weak HSTS policies; only the first header counts (RFC 6797 §8.1).
    #[test]
    fn weak_hsts() {
        let hsts = |values: &[&str]| {
            let headers: Vec<_> = values
                .iter()
                .map(|v| ("Strict-Transport-Security", *v))
                .collect();
            ids(&hsts_findings(&response(&headers)))
                .into_iter()
                .map(|(id, _)| id.to_owned())
                .collect::<Vec<_>>()
        };
        assert_eq!(hsts(&["max-age=0"]), ["hsts.disabled"]);
        assert_eq!(hsts(&["max-age=86400", "max-age=63072000"]), ["hsts.short"]);
        assert_eq!(hsts(&["max-age=x"]), ["hsts.invalid"]);
        assert_eq!(
            hsts(&["max-age=15552000; preload"]),
            ["hsts", "hsts.preload_ineligible"]
        );
    }

    /// X-Frame-Options alone satisfies the framing check, and a nosniff
    /// value is required.
    #[test]
    fn framing_and_nosniff() {
        let r = response(&[
            ("X-Frame-Options", "SAMEORIGIN"),
            ("X-Content-Type-Options", "sniff"),
        ]);
        let findings = header_findings(&r);
        let found = ids(&findings);
        assert!(found.contains(&("header.x_content_type_options", Severity::Info)));
        assert!(!found.iter().any(|(id, _)| *id == "header.framing"));
    }
}
