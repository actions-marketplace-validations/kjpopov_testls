//! HTTP extras: `Alt-Svc` (RFC 7838), software banners, and cookie
//! attributes (RFC 6265).

use testls_probe::HttpResponse;

use crate::{Finding, Severity};

/// One alternative service advertised in `Alt-Svc` (RFC 7838 §3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AltService {
    /// ALPN protocol id, percent-decoded, e.g. `h3`.
    pub protocol: String,
    /// Alternative authority, `[host]:port`, e.g. `:443`.
    pub authority: String,
    /// Freshness lifetime in seconds (`ma`), 24 hours when absent.
    pub max_age: u64,
}

/// Default `ma` of an alternative service: 24 hours (RFC 7838 §3.1).
const DEFAULT_MAX_AGE: u64 = 24 * 60 * 60;

/// Alternative services from every `Alt-Svc` header, combined into one list
/// in order (RFC 9110 §5.3). `clear` yields an empty list (RFC 7838 §3).
///
/// # Errors
///
/// Returns a message when the header does not follow the RFC 7838 grammar.
pub fn alt_services(response: &HttpResponse) -> Result<Vec<AltService>, String> {
    let value = response
        .header_values("alt-svc")
        .collect::<Vec<_>>()
        .join(",");
    if value.trim().is_empty() || value.trim().eq_ignore_ascii_case("clear") {
        return Ok(Vec::new());
    }
    let invalid = || format!("invalid Alt-Svc entry `{}`", printable(value.trim()));
    // Empty list elements are ignored (RFC 9110 §5.6.1).
    let entries: Vec<&str> = split_unquoted(&value, ',')
        .ok_or_else(invalid)?
        .into_iter()
        .filter(|e| !e.trim().is_empty())
        .collect();
    if entries.is_empty() {
        return Err(invalid());
    }
    entries.into_iter().map(alt_service).collect()
}

/// Splits `s` at `delim` outside quoted strings, honouring `\` escapes
/// inside quotes (RFC 9110 §5.6.4). `None` for an unterminated quote.
fn split_unquoted(s: &str, delim: char) -> Option<Vec<&str>> {
    let mut parts = Vec::new();
    let (mut start, mut quoted, mut escaped) = (0, false, false);
    for (i, c) in s.char_indices() {
        match c {
            _ if escaped => escaped = false,
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            c if c == delim && !quoted => {
                parts.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(&s[start..]);
    (!quoted).then_some(parts)
}

/// Parses `protocol-id "=" alt-authority *( OWS ";" OWS parameter )`.
fn alt_service(entry: &str) -> Result<AltService, String> {
    let invalid = || format!("invalid Alt-Svc entry `{}`", printable(entry.trim()));
    let mut parts = split_unquoted(entry, ';').ok_or_else(invalid)?.into_iter();
    let (protocol, authority) = parts
        .next()
        .and_then(|p| p.trim().split_once('='))
        .ok_or_else(invalid)?;
    let protocol = percent_decode(protocol)
        .filter(|p| !p.is_empty())
        .ok_or_else(invalid)?;
    let authority = authority
        .strip_prefix('"')
        .and_then(|a| a.strip_suffix('"'))
        .filter(|a| !a.contains(['"', '\\']))
        .filter(|a| {
            a.rsplit_once(':').is_some_and(|(_, port)| {
                !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit())
            })
        })
        .ok_or_else(invalid)?;
    let mut max_age = DEFAULT_MAX_AGE;
    for param in parts {
        let (name, value) = param.trim().split_once('=').ok_or_else(invalid)?;
        if name.trim().eq_ignore_ascii_case("ma") {
            max_age = value
                .trim()
                .trim_matches('"')
                .parse()
                .map_err(|_| invalid())?;
        }
    }
    Ok(AltService {
        protocol,
        authority: authority.to_owned(),
        max_age,
    })
}

/// Decodes `%XX` escapes in an ALPN protocol id (RFC 7838 §3). Returns
/// `None` for malformed escapes or non-printable results.
fn percent_decode(s: &str) -> Option<String> {
    let mut out = Vec::new();
    let mut bytes = s.bytes();
    while let Some(b) = bytes.next() {
        if b == b'%' {
            let hex = [bytes.next()?, bytes.next()?];
            out.push(u8::from_str_radix(std::str::from_utf8(&hex).ok()?, 16).ok()?);
        } else {
            out.push(b);
        }
    }
    String::from_utf8(out)
        .ok()
        .filter(|p| p.bytes().all(|b| b.is_ascii_graphic()))
}

/// Replaces characters that are not printable ASCII with `?`, so header
/// text can be shown on a terminal.
fn printable(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_graphic() || c == ' ' {
                c
            } else {
                '?'
            }
        })
        .collect()
}

/// Attributes of one `Set-Cookie` header (RFC 6265 §5.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cookie {
    /// Cookie name, with non-printable characters replaced by `?`.
    pub name: String,
    /// The `Secure` attribute is present.
    pub secure: bool,
    /// The `HttpOnly` attribute is present.
    pub http_only: bool,
    /// Value of the last `SameSite` attribute, if any.
    pub same_site: Option<String>,
}

/// Cookies set by the response, one per `Set-Cookie` header. Headers
/// without a `name=value` pair are ignored, as browsers do (RFC 6265 §5.2).
#[must_use]
pub fn cookies(response: &HttpResponse) -> Vec<Cookie> {
    response
        .header_values("set-cookie")
        .filter_map(|value| {
            let mut parts = value.split(';');
            let (name, _) = parts.next()?.split_once('=')?;
            let name = name.trim();
            if name.is_empty() {
                return None;
            }
            let mut cookie = Cookie {
                name: printable(name),
                secure: false,
                http_only: false,
                same_site: None,
            };
            for attr in parts {
                let (key, val) = attr.split_once('=').unwrap_or((attr, ""));
                match key.trim().to_ascii_lowercase().as_str() {
                    "secure" => cookie.secure = true,
                    "httponly" => cookie.http_only = true,
                    "samesite" => cookie.same_site = Some(printable(val.trim())),
                    _ => {}
                }
            }
            Some(cookie)
        })
        .collect()
}

/// Banner headers that name the server software, with a printable value.
#[must_use]
pub fn banners(response: &HttpResponse) -> Vec<(&'static str, String)> {
    [("Server", "server"), ("X-Powered-By", "x-powered-by")]
        .into_iter()
        .flat_map(|(label, name)| {
            response
                .header_values(name)
                .filter(|v| !v.is_empty())
                .map(move |v| (label, printable(v)))
        })
        .collect()
}

/// Findings for software banners, cookie attributes, and a malformed
/// `Alt-Svc` header.
#[must_use]
pub fn http_extra_findings(response: &HttpResponse) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (label, value) in banners(response) {
        if label == "X-Powered-By" || value.bytes().any(|b| b.is_ascii_digit()) {
            findings.push(Finding::new(
                "header.banner",
                Severity::Info,
                format!("{label} header discloses software details: {value}"),
            ));
        }
    }
    if let Err(e) = alt_services(response) {
        findings.push(Finding::new("header.alt_svc_invalid", Severity::Info, e));
    }
    let cookies = cookies(response);
    let names = |pred: fn(&Cookie) -> bool| {
        let names: Vec<&str> = cookies
            .iter()
            .filter(|c| pred(c))
            .map(|c| c.name.as_str())
            .collect();
        (!names.is_empty()).then(|| names.join(", "))
    };
    if let Some(n) = names(|c| !c.secure) {
        findings.push(Finding::new(
            "cookie.insecure",
            Severity::Low,
            format!("cookies without the Secure attribute: {n}"),
        ));
    }
    if let Some(n) = names(|c| !c.http_only) {
        findings.push(Finding::new(
            "cookie.no_httponly",
            Severity::Info,
            format!("cookies without the HttpOnly attribute: {n}"),
        ));
    }
    if let Some(n) = names(|c| c.same_site.is_none()) {
        findings.push(Finding::new(
            "cookie.no_samesite",
            Severity::Info,
            format!("cookies without a SameSite attribute: {n}"),
        ));
    }
    if let Some(n) = names(|c| {
        c.same_site
            .as_deref()
            .is_some_and(|s| s.eq_ignore_ascii_case("none"))
            && !c.secure
    }) {
        findings.push(Finding::new(
            "cookie.samesite_none_insecure",
            Severity::Low,
            format!("cookies with SameSite=None but no Secure attribute: {n}"),
        ));
    }
    findings
}

#[cfg(test)]
mod tests {
    //! Unit tests for `Alt-Svc` parsing, banners, and cookie findings.

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

    /// Finding ids, for compact assertions.
    fn ids(findings: &[Finding]) -> Vec<&str> {
        findings.iter().map(|f| f.id.as_str()).collect()
    }

    /// `Alt-Svc` entries, parameters, percent escapes, and `clear`.
    #[test]
    fn parses_alt_svc() {
        let alt = |v: &str| alt_services(&response(&[("Alt-Svc", v)]));
        assert_eq!(
            alt(r#"h3=":443"; ma=86400, h3-29=":8443", h2="alt.example:443"; persist=1"#).unwrap(),
            [
                AltService {
                    protocol: "h3".into(),
                    authority: ":443".into(),
                    max_age: 86400
                },
                AltService {
                    protocol: "h3-29".into(),
                    authority: ":8443".into(),
                    max_age: DEFAULT_MAX_AGE
                },
                AltService {
                    protocol: "h2".into(),
                    authority: "alt.example:443".into(),
                    max_age: DEFAULT_MAX_AGE
                },
            ]
        );
        assert_eq!(alt(r#"w%3Dx%3Ay=":443""#).unwrap()[0].protocol, "w=x:y");
        let quoted = alt(r#"h3=":443"; ext="a,b;c\"d"; ma=60, h2=":443""#).unwrap();
        assert_eq!(quoted.len(), 2);
        assert_eq!(quoted[0].max_age, 60);
        let split = alt_services(&response(&[
            ("Alt-Svc", r#"h2=":443""#),
            ("Alt-Svc", r#"h3=":443""#),
        ]))
        .unwrap();
        assert_eq!(
            split
                .iter()
                .map(|s| s.protocol.as_str())
                .collect::<Vec<_>>(),
            ["h2", "h3"]
        );
        assert_eq!(alt("clear").unwrap(), []);
        assert_eq!(alt_services(&response(&[])).unwrap(), []);
        assert_eq!(alt(r#", h3=":443", ,"#).unwrap().len(), 1);
        for bad in [
            ", ,",
            "h3",
            "h3=:443",
            r#"h3="443""#,
            r#"=":443""#,
            r#"h3=":443"; ma=x"#,
            r#"h%zz=":1""#,
            r#"h3=":notaport""#,
            r#"h3="host:""#,
            r#"h3=":443"; ext="open"#,
        ] {
            assert!(alt(bad).is_err(), "{bad}");
        }
    }

    /// Cookie attributes are case-insensitive; nameless cookies are skipped.
    #[test]
    fn parses_cookies() {
        let r = response(&[
            (
                "Set-Cookie",
                "sid=abc; Path=/; SECURE; httponly; SameSite=Lax",
            ),
            ("Set-Cookie", "theme=dark"),
            ("Set-Cookie", "novalue"),
            ("Set-Cookie", "=x; Secure"),
        ]);
        assert_eq!(
            cookies(&r),
            [
                Cookie {
                    name: "sid".into(),
                    secure: true,
                    http_only: true,
                    same_site: Some("Lax".into())
                },
                Cookie {
                    name: "theme".into(),
                    secure: false,
                    http_only: false,
                    same_site: None
                },
            ]
        );
    }

    /// Cookie findings group cookie names per missing attribute.
    #[test]
    fn cookie_findings() {
        let r = response(&[
            ("Set-Cookie", "sid=abc; Secure; HttpOnly; SameSite=Strict"),
            ("Set-Cookie", "a=1; SameSite=None"),
            ("Set-Cookie", "b=2; HttpOnly"),
        ]);
        let findings = http_extra_findings(&r);
        assert_eq!(
            ids(&findings),
            [
                "cookie.insecure",
                "cookie.no_httponly",
                "cookie.no_samesite",
                "cookie.samesite_none_insecure"
            ]
        );
        assert_eq!(
            findings[0].message,
            "cookies without the Secure attribute: a, b"
        );
        assert_eq!(
            findings[1].message,
            "cookies without the HttpOnly attribute: a"
        );
        assert_eq!(
            findings[2].message,
            "cookies without a SameSite attribute: b"
        );
        let good = response(&[("Set-Cookie", "sid=abc; Secure; HttpOnly; SameSite=Lax")]);
        assert_eq!(ids(&http_extra_findings(&good)), [] as [&str; 0]);
    }

    /// Versioned `Server` values and any `X-Powered-By` are reported.
    #[test]
    fn banner_findings() {
        let r = response(&[("Server", "nginx/1.25.3"), ("X-Powered-By", "PHP")]);
        let findings = http_extra_findings(&r);
        assert_eq!(ids(&findings), ["header.banner", "header.banner"]);
        assert_eq!(
            findings[0].message,
            "Server header discloses software details: nginx/1.25.3"
        );
        assert_eq!(
            ids(&http_extra_findings(&response(&[("Server", "nginx")]))),
            [] as [&str; 0]
        );
        assert_eq!(
            banners(&response(&[("Server", "a\u{1b}[31m")])),
            [("Server", "a?[31m".to_owned())]
        );
        let repeated = response(&[("X-Powered-By", "PHP"), ("X-Powered-By", "Express")]);
        assert_eq!(
            ids(&http_extra_findings(&repeated)),
            ["header.banner", "header.banner"]
        );
    }

    /// A malformed `Alt-Svc` header is reported.
    #[test]
    fn invalid_alt_svc_finding() {
        let findings = http_extra_findings(&response(&[("Alt-Svc", "h3")]));
        assert_eq!(ids(&findings), ["header.alt_svc_invalid"]);
        assert_eq!(findings[0].message, "invalid Alt-Svc entry `h3`");
    }
}
