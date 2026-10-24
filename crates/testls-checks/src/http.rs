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
/// Directive names are case-insensitive, values may be tokens or quoted
/// strings, unknown directives are ignored, and a repeated directive or any
/// value outside the grammar invalidates the header (RFC 6797 §6.1 items 2-5).
///
/// # Errors
/// Returns a short reason when the value is not a valid policy.
pub fn parse_hsts(value: &str) -> Result<Hsts, String> {
    let mut max_age = None;
    let mut include_subdomains = false;
    let mut preload = false;
    let mut seen: Vec<String> = Vec::new();
    for (name, arg) in directives(value)? {
        let name = name.to_ascii_lowercase();
        if seen.contains(&name) {
            return Err(format!("directive {name} repeated"));
        }
        match (name.as_str(), arg.as_deref()) {
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

/// Splits an STS value into `(name, value)` directives following the grammar
/// `[ directive ] *( ";" [ directive ] )` with
/// `directive = token [ "=" ( token / quoted-string ) ]` (RFC 6797 §6.1).
/// Quoted values are returned unescaped.
fn directives(value: &str) -> Result<Vec<(&str, Option<String>)>, String> {
    let invalid = || "invalid directive syntax".to_owned();
    let mut out = Vec::new();
    let mut rest = value;
    loop {
        rest = skip_ows(rest);
        if let Some(r) = rest.strip_prefix(';') {
            rest = r;
            continue;
        }
        if rest.is_empty() {
            return Ok(out);
        }
        let (name, r) = token(rest).ok_or_else(invalid)?;
        rest = skip_ows(r);
        let mut arg = None;
        if let Some(r) = rest.strip_prefix('=') {
            let r = skip_ows(r);
            let (v, r) = if r.starts_with('"') {
                quoted_string(r).ok_or_else(invalid)?
            } else {
                let (v, r) = token(r).ok_or_else(invalid)?;
                (v.to_owned(), r)
            };
            arg = Some(v);
            rest = skip_ows(r);
        }
        if !(rest.is_empty() || rest.starts_with(';')) {
            return Err(invalid());
        }
        out.push((name, arg));
    }
}

/// Skips optional whitespace (spaces and tabs).
fn skip_ows(s: &str) -> &str {
    s.trim_start_matches([' ', '\t'])
}

/// Splits a non-empty leading `token` (RFC 9110 §5.6.2) off `s`.
fn token(s: &str) -> Option<(&str, &str)> {
    let end = s
        .find(|c: char| !(c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c)))
        .unwrap_or(s.len());
    (end > 0).then(|| s.split_at(end))
}

/// Splits a leading `quoted-string` (RFC 9110 §5.6.4) off `s`, returning its
/// unescaped content and the remainder.
fn quoted_string(s: &str) -> Option<(String, &str)> {
    let mut chars = s.strip_prefix('"')?.char_indices();
    let mut content = String::new();
    while let Some((i, c)) = chars.next() {
        match c {
            '"' => return Some((content, &s[i + 2..])),
            '\\' => content.push(chars.next()?.1),
            c => content.push(c),
        }
    }
    None
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
    if !framing_protected(response) {
        findings.push(Finding::new(
            "header.framing",
            Severity::Info,
            "no restrictive X-Frame-Options header or CSP frame-ancestors directive",
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

/// Whether browsers would refuse to embed the page in a cross-origin frame.
///
/// Every `Content-Security-Policy` field is enforced, so one restrictive
/// `frame-ancestors` directive suffices; when any `frame-ancestors` is present
/// `X-Frame-Options` is ignored (CSP Level 3 §6.4.2). Otherwise the combined
/// `X-Frame-Options` values must include `DENY` or `SAMEORIGIN` (HTML
/// standard, "check a navigation response's adherence to X-Frame-Options").
fn framing_protected(response: &HttpResponse) -> bool {
    let ancestors: Vec<&str> = response
        .header_values("content-security-policy")
        .filter_map(frame_ancestors)
        .collect();
    if !ancestors.is_empty() {
        return ancestors.into_iter().any(restricts_ancestors);
    }
    response
        .header_values("x-frame-options")
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .any(|v| v.eq_ignore_ascii_case("deny") || v.eq_ignore_ascii_case("sameorigin"))
}

/// Source list of the first `frame-ancestors` directive in one policy.
fn frame_ancestors(policy: &str) -> Option<&str> {
    policy.split(';').find_map(|d| {
        let d = d.trim_matches([' ', '\t']);
        let end = d.find([' ', '\t']).unwrap_or(d.len());
        let (name, sources) = d.split_at(end);
        name.eq_ignore_ascii_case("frame-ancestors")
            .then_some(sources)
    })
}

/// Whether a `frame-ancestors` source list limits embedding: `*` and bare
/// scheme sources such as `https:` allow any site.
fn restricts_ancestors(sources: &str) -> bool {
    !sources
        .split_ascii_whitespace()
        .any(|s| s == "*" || (s.ends_with(':') && !s.starts_with('\'')))
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
        for value in [
            "max-age=1; future=\"@\"",
            "max-age=1; future = x",
            "max-age=1; future=\"a\\\"b; c\"",
            "max-age=\"1\"; future",
        ] {
            assert_eq!(parse_hsts(value).map(|h| h.max_age), Ok(1), "{value}");
        }
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
            "max-age=1; future=@",
            "max-age=1; future=a b",
            "max-age=1; future=\"open",
            "max-age=1 x",
            "@; max-age=1",
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

    /// Framing protection depends on the effective header values, and every
    /// CSP field is considered.
    #[test]
    fn effective_framing_protection() {
        let protected = |headers: &[(&str, &str)]| framing_protected(&response(headers));
        let csp = "Content-Security-Policy";
        let xfo = "X-Frame-Options";
        assert!(protected(&[(xfo, "deny")]));
        assert!(protected(&[(
            csp,
            "default-src 'self'; frame-ancestors 'none'"
        )]));
        assert!(protected(&[(csp, "frame-ancestors")]));
        assert!(protected(&[
            (csp, "default-src 'self'"),
            (csp, "frame-ancestors https://example.com"),
        ]));
        assert!(!protected(&[]));
        assert!(!protected(&[(xfo, "ALLOWALL")]));
        assert!(!protected(&[(csp, "default-src 'self'")]));
        assert!(!protected(&[(csp, "frame-ancestors *")]));
        assert!(!protected(&[(csp, "frame-ancestors 'self' https:")]));
        // frame-ancestors overrides X-Frame-Options, even when permissive.
        assert!(!protected(&[(csp, "frame-ancestors *"), (xfo, "DENY")]));
    }
}
