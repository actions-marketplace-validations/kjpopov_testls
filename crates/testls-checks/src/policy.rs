//! Compliance policies: findings for everything a server offers or presents
//! that a published configuration profile does not allow.
//!
//! The Mozilla profiles follow the Mozilla Server Side TLS guidelines,
//! version 6.0 (<https://ssl-config.mozilla.org/guidelines/6.0.json>).
//! Suite and group code points are from the IANA TLS parameter registries.

use std::fmt;

use testls_probe::{
    CipherResult, HttpResponse, KeyExchangeResult, ProtocolResult, ProtocolSupport,
};
use testls_wire::ProtocolVersion;
use x509_parser::asn1_rs::Oid;
use x509_parser::certificate::X509Certificate;
use x509_parser::parse_x509_certificate;
use x509_parser::public_key::PublicKey;

use crate::{Finding, Severity, cipher_name, group_name, parse_hsts};

/// Seconds in a day.
const DAY: i64 = 24 * 60 * 60;

/// Severity of every policy deviation: the configuration may be safe, but
/// it is not what the chosen policy requires.
const DEVIATION: Severity = Severity::Medium;

/// A configuration profile the server can be checked against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    /// Mozilla "modern": TLSv1.3 only, ECDSA certificates.
    MozillaModern,
    /// Mozilla "intermediate": TLSv1.2 and TLSv1.3, AEAD suites with ECDHE.
    MozillaIntermediate,
}

impl Policy {
    /// All policies, in the order they are listed on the command line.
    pub const ALL: [Self; 2] = [Self::MozillaModern, Self::MozillaIntermediate];

    /// Name used on the command line and in finding messages.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MozillaModern => "mozilla-modern",
            Self::MozillaIntermediate => "mozilla-intermediate",
        }
    }

    /// What the policy allows.
    fn rules(self) -> &'static Rules {
        match self {
            Self::MozillaModern => &MOZILLA_MODERN,
            Self::MozillaIntermediate => &MOZILLA_INTERMEDIATE,
        }
    }
}

impl fmt::Display for Policy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for Policy {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|p| p.as_str().eq_ignore_ascii_case(s))
            .ok_or_else(|| format!("unknown policy {s:?}"))
    }
}

/// What one policy allows.
#[derive(Debug)]
struct Rules {
    /// Protocol versions.
    versions: &'static [ProtocolVersion],
    /// TLSv1.3 cipher suites.
    tls13_suites: &'static [u16],
    /// Cipher suites for TLSv1.2 and earlier.
    suites: &'static [u16],
    /// Named groups for (EC)DHE key exchange.
    groups: &'static [u16],
    /// Minimum RSA key size in bits, or `None` if RSA keys are not allowed.
    rsa_bits: Option<usize>,
    /// Named curves (OIDs) for ECDSA keys.
    curves: &'static [(&'static str, &'static str)],
    /// Leaf signature algorithms (OIDs).
    signatures: &'static [(&'static str, &'static str)],
    /// Longest allowed leaf validity period in days.
    lifespan_days: i64,
    /// Minimum HSTS `max-age` in seconds.
    hsts_max_age: u64,
}

/// TLSv1.3 suites of both Mozilla profiles: `TLS_AES_128_GCM_SHA256`,
/// `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`.
const MOZILLA_TLS13_SUITES: &[u16] = &[0x1301, 0x1302, 0x1303];

/// Groups of both Mozilla profiles: `X25519MLKEM768`, `x25519`,
/// `secp256r1`, `secp384r1`.
const MOZILLA_GROUPS: &[u16] = &[0x11ec, 0x001d, 0x0017, 0x0018];

/// ECDSA curves of both Mozilla profiles: P-256 (RFC 5480 §2.1.1.1) and
/// P-384.
const MOZILLA_CURVES: &[(&str, &str)] =
    &[("1.2.840.10045.3.1.7", "P-256"), ("1.3.132.0.34", "P-384")];

/// ECDSA signature algorithms (RFC 5758 §3.2).
const ECDSA_SIGNATURES: &[(&str, &str)] = &[
    ("1.2.840.10045.4.3.2", "ecdsa-with-SHA256"),
    ("1.2.840.10045.4.3.3", "ecdsa-with-SHA384"),
    ("1.2.840.10045.4.3.4", "ecdsa-with-SHA512"),
];

/// ECDSA plus `sha256WithRSAEncryption` (RFC 8017 appendix C).
const INTERMEDIATE_SIGNATURES: &[(&str, &str)] = &[
    ("1.2.840.10045.4.3.2", "ecdsa-with-SHA256"),
    ("1.2.840.10045.4.3.3", "ecdsa-with-SHA384"),
    ("1.2.840.10045.4.3.4", "ecdsa-with-SHA512"),
    ("1.2.840.113549.1.1.11", "sha256WithRSAEncryption"),
];

/// HSTS `max-age` both Mozilla profiles ask for: two years.
const MOZILLA_HSTS_MAX_AGE: u64 = 63_072_000;

/// Mozilla "modern".
static MOZILLA_MODERN: Rules = Rules {
    versions: &[ProtocolVersion::TLS13],
    tls13_suites: MOZILLA_TLS13_SUITES,
    suites: &[],
    groups: MOZILLA_GROUPS,
    rsa_bits: None,
    curves: MOZILLA_CURVES,
    signatures: ECDSA_SIGNATURES,
    lifespan_days: 90,
    hsts_max_age: MOZILLA_HSTS_MAX_AGE,
};

/// Mozilla "intermediate". The TLSv1.2 suites are the ECDHE AEAD suites
/// `0xc02b`, `0xc02f`, `0xc02c`, `0xc030`, `0xcca9` and `0xcca8`.
static MOZILLA_INTERMEDIATE: Rules = Rules {
    versions: &[ProtocolVersion::TLS12, ProtocolVersion::TLS13],
    tls13_suites: MOZILLA_TLS13_SUITES,
    suites: &[0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8],
    groups: MOZILLA_GROUPS,
    rsa_bits: Some(2048),
    curves: MOZILLA_CURVES,
    signatures: INTERMEDIATE_SIGNATURES,
    lifespan_days: 366,
    hsts_max_age: MOZILLA_HSTS_MAX_AGE,
};

/// Scan results a policy is checked against. `None` means the part was not
/// measured (skipped by the scan profile or failed); it is then reported in
/// a `policy.incomplete` finding instead of being assumed compliant.
#[derive(Debug, Clone, Copy)]
pub struct PolicyInput<'a> {
    /// Protocol detection results.
    pub protocols: &'a [ProtocolResult],
    /// Accepted cipher suites per protocol version.
    pub ciphers: Option<&'a [CipherResult]>,
    /// Key exchange groups per protocol version.
    pub key_exchange: Option<&'a [KeyExchangeResult]>,
    /// DER certificate chain, leaf first.
    pub chain: Option<&'a [Vec<u8>]>,
    /// Reply to `GET /`.
    pub http: Option<&'a HttpResponse>,
}

/// Findings for everything in `input` that `policy` does not allow.
#[must_use]
pub fn policy_findings(policy: Policy, input: &PolicyInput<'_>) -> Vec<Finding> {
    let rules = policy.rules();
    let mut findings = Vec::new();
    let mut untested = Vec::new();

    for r in input.protocols {
        if r.support == ProtocolSupport::Supported && !rules.versions.contains(&r.version) {
            findings.push(deviation(
                "policy.protocol",
                policy,
                &format!("{} is offered", r.version),
            ));
        }
    }
    match input.ciphers {
        Some(ciphers) => findings.extend(cipher_deviations(policy, ciphers)),
        None => untested.push("cipher suites"),
    }
    match input.key_exchange {
        Some(results) => findings.extend(group_deviations(policy, results)),
        None => untested.push("key exchange groups"),
    }
    match input.chain.and_then(<[_]>::first) {
        Some(leaf) => findings.extend(certificate_deviations(policy, leaf)),
        None => untested.push("certificate"),
    }
    match input.http {
        Some(response) => findings.extend(hsts_deviation(policy, response, rules.hsts_max_age)),
        None => untested.push("HSTS"),
    }
    if !untested.is_empty() {
        findings.push(Finding::new(
            "policy.incomplete",
            Severity::Info,
            format!(
                "{policy} could not be fully checked: {} not measured",
                untested.join(", ")
            ),
        ));
    }
    findings
}

/// A finding for something `policy` does not allow.
fn deviation(id: &str, policy: Policy, what: &str) -> Finding {
    Finding::new(
        id,
        DEVIATION,
        format!("{what}, which {policy} does not allow"),
    )
}

/// Accepted suites outside the policy, for the versions it allows (other
/// versions are already reported as `policy.protocol`).
fn cipher_deviations(policy: Policy, ciphers: &[CipherResult]) -> Vec<Finding> {
    let rules = policy.rules();
    let mut findings = Vec::new();
    for result in ciphers
        .iter()
        .filter(|r| rules.versions.contains(&r.version))
    {
        let allowed = if result.version == ProtocolVersion::TLS13 {
            rules.tls13_suites
        } else {
            rules.suites
        };
        for &suite in &result.suites {
            if !u16::try_from(suite).is_ok_and(|s| allowed.contains(&s)) {
                findings.push(deviation(
                    "policy.cipher",
                    policy,
                    &format!(
                        "{} accepts {}",
                        result.version,
                        cipher_name(result.version, suite)
                    ),
                ));
            }
        }
    }
    findings
}

/// Accepted groups outside the policy, each reported once.
fn group_deviations(policy: Policy, results: &[KeyExchangeResult]) -> Vec<Finding> {
    let rules = policy.rules();
    let mut seen = Vec::new();
    for result in results
        .iter()
        .filter(|r| rules.versions.contains(&r.version))
    {
        for &group in &result.groups {
            if !rules.groups.contains(&group) && !seen.contains(&group) {
                seen.push(group);
            }
        }
    }
    seen.into_iter()
        .map(|g| {
            deviation(
                "policy.group",
                policy,
                &format!(
                    "key exchange group {} (0x{g:04x}) is accepted",
                    group_name(g)
                ),
            )
        })
        .collect()
}

/// Leaf key, signature and validity period outside the policy.
fn certificate_deviations(policy: Policy, leaf: &[u8]) -> Vec<Finding> {
    let rules = policy.rules();
    let Ok(([], cert)) = parse_x509_certificate(leaf) else {
        return vec![Finding::new(
            "policy.incomplete",
            Severity::Info,
            format!("{policy} could not be fully checked: leaf certificate cannot be parsed"),
        )];
    };
    let mut findings = Vec::new();
    if let Some(what) = key_deviation(rules, &cert) {
        findings.push(deviation("policy.cert_key", policy, &what));
    }
    let signature = cert.signature_algorithm.algorithm.to_id_string();
    if !rules.signatures.iter().any(|(oid, _)| *oid == signature) {
        findings.push(deviation(
            "policy.cert_signature",
            policy,
            &format!(
                "leaf certificate is signed with {}",
                label(&signature, INTERMEDIATE_SIGNATURES)
            ),
        ));
    }
    let validity = cert.validity();
    let days = (validity.not_after.timestamp() - validity.not_before.timestamp()) / DAY;
    if days > rules.lifespan_days {
        findings.push(deviation(
            "policy.cert_lifespan",
            policy,
            &format!(
                "leaf certificate is valid for {days} days, more than {}",
                rules.lifespan_days
            ),
        ));
    }
    findings
}

/// Name of `oid` from `table`, or the dotted OID itself.
fn label(oid: &str, table: &[(&str, &'static str)]) -> String {
    table
        .iter()
        .find(|(o, _)| *o == oid)
        .map_or_else(|| oid.to_owned(), |(_, name)| (*name).to_owned())
}

/// Why the leaf's public key is outside the policy, if it is.
fn key_deviation(rules: &Rules, cert: &X509Certificate<'_>) -> Option<String> {
    let spki = cert.public_key();
    match spki.parsed() {
        Ok(PublicKey::RSA(key)) => {
            let bits = key.key_size();
            match rules.rsa_bits {
                None => Some(format!("leaf certificate has an RSA {bits}-bit key")),
                Some(min) if bits < min => Some(format!(
                    "leaf certificate has an RSA key of only {bits} bits"
                )),
                Some(_) => None,
            }
        }
        Ok(PublicKey::EC(_)) => {
            let curve = spki
                .algorithm
                .parameters
                .as_ref()
                .and_then(|p| Oid::try_from(p).ok())
                .map(|oid| oid.to_id_string());
            match curve {
                Some(c) if rules.curves.iter().any(|(oid, _)| *oid == c) => None,
                Some(c) => Some(format!("leaf certificate has an EC key on curve {c}")),
                None => Some("leaf certificate has an EC key without a named curve".to_owned()),
            }
        }
        Ok(_) | Err(_) => Some(format!(
            "leaf certificate has a key of algorithm {}",
            spki.algorithm.algorithm.to_id_string()
        )),
    }
}

/// Missing, invalid or too short HSTS policy.
fn hsts_deviation(policy: Policy, response: &HttpResponse, min_age: u64) -> Option<Finding> {
    let what = match response.header("strict-transport-security").map(parse_hsts) {
        None => "no Strict-Transport-Security header is sent".to_owned(),
        Some(Err(e)) => format!("the Strict-Transport-Security header is invalid ({e})"),
        Some(Ok(hsts)) if hsts.max_age < min_age => format!(
            "HSTS max-age is {} seconds, less than {min_age}",
            hsts.max_age
        ),
        Some(Ok(_)) => return None,
    };
    Some(deviation("policy.hsts", policy, &what))
}

#[cfg(test)]
mod tests {
    use testls_probe::CipherOrder;

    use super::*;

    /// Self-signed P-256 leaf signed with ecdsa-with-SHA256, valid 365 days.
    const EC_LOCALHOST: &[u8] = include_bytes!("testdata/ec-localhost.der");
    /// Self-signed RSA-2048 leaf signed with sha256WithRSAEncryption, 365 days.
    const RSA2048: &[u8] = include_bytes!("testdata/rsa2048-no-san.der");
    /// Self-signed RSA-1024 leaf signed with SHA-1.
    const RSA1024_SHA1: &[u8] = include_bytes!("testdata/rsa1024-sha1-wildcard.der");

    /// Protocol results with `versions` supported.
    fn protocols(versions: &[ProtocolVersion]) -> Vec<ProtocolResult> {
        ProtocolVersion::ALL
            .iter()
            .map(|&version| ProtocolResult {
                version,
                support: if versions.contains(&version) {
                    ProtocolSupport::Supported
                } else {
                    ProtocolSupport::NotSupported
                },
            })
            .collect()
    }

    /// Cipher result accepting `suites` at `version`.
    fn ciphers(version: ProtocolVersion, suites: &[u32]) -> CipherResult {
        CipherResult {
            version,
            suites: suites.to_vec(),
            order: CipherOrder::Server,
        }
    }

    /// Key exchange result accepting `groups` at `version`.
    fn groups(version: ProtocolVersion, groups: &[u16]) -> KeyExchangeResult {
        KeyExchangeResult {
            version,
            groups: groups.to_vec(),
            group_order: CipherOrder::Server,
            dh_bits: None,
            dh_prime: None,
            dh_key_reused: None,
        }
    }

    /// Reply carrying `hsts` as its HSTS header, if any.
    fn http(hsts: Option<&str>) -> HttpResponse {
        HttpResponse {
            status: 200,
            headers: hsts
                .map(|v| ("strict-transport-security".to_owned(), v.to_owned()))
                .into_iter()
                .collect(),
        }
    }

    /// Finding ids and messages.
    fn summary(findings: &[Finding]) -> Vec<(String, String)> {
        findings
            .iter()
            .map(|f| (f.id.clone(), f.message.clone()))
            .collect()
    }

    /// A server built to the intermediate profile has no deviations from it
    /// but several from modern.
    #[test]
    fn intermediate_server() {
        let protocols = protocols(&[ProtocolVersion::TLS12, ProtocolVersion::TLS13]);
        let ciphers = [
            ciphers(ProtocolVersion::TLS12, &[0xc02f, 0xc030]),
            ciphers(ProtocolVersion::TLS13, &[0x1301, 0x1302]),
        ];
        let key_exchange = [
            groups(ProtocolVersion::TLS12, &[0x001d, 0x0017]),
            groups(ProtocolVersion::TLS13, &[0x11ec, 0x001d]),
        ];
        let chain = [RSA2048.to_vec()];
        let response = http(Some("max-age=63072000"));
        let input = PolicyInput {
            protocols: &protocols,
            ciphers: Some(&ciphers),
            key_exchange: Some(&key_exchange),
            chain: Some(&chain),
            http: Some(&response),
        };
        assert_eq!(policy_findings(Policy::MozillaIntermediate, &input), []);

        let ids: Vec<_> = policy_findings(Policy::MozillaModern, &input)
            .into_iter()
            .map(|f| {
                assert_eq!(f.severity, Severity::Medium);
                f.id
            })
            .collect();
        assert_eq!(
            ids,
            [
                "policy.protocol",
                "policy.cert_key",
                "policy.cert_signature",
                "policy.cert_lifespan"
            ]
        );
    }

    /// Every kind of deviation, with its message.
    #[test]
    fn deviations() {
        let protocols = protocols(&[ProtocolVersion::TLS10, ProtocolVersion::TLS12]);
        let ciphers = [
            ciphers(ProtocolVersion::TLS10, &[0x002f]),
            ciphers(ProtocolVersion::TLS12, &[0xc02f, 0x009c]),
        ];
        let key_exchange = [groups(ProtocolVersion::TLS12, &[0x001d, 0x0019, 0x0019])];
        let chain = [RSA1024_SHA1.to_vec()];
        let response = http(Some("max-age=86400"));
        let input = PolicyInput {
            protocols: &protocols,
            ciphers: Some(&ciphers),
            key_exchange: Some(&key_exchange),
            chain: Some(&chain),
            http: Some(&response),
        };
        let tail = ", which mozilla-intermediate does not allow";
        let expected = [
            ("policy.protocol", "TLSv1.0 is offered"),
            (
                "policy.cipher",
                "TLSv1.2 accepts TLS_RSA_WITH_AES_128_GCM_SHA256",
            ),
            (
                "policy.group",
                "key exchange group secp521r1 (0x0019) is accepted",
            ),
            (
                "policy.cert_key",
                "leaf certificate has an RSA key of only 1024 bits",
            ),
            (
                "policy.cert_signature",
                "leaf certificate is signed with 1.2.840.113549.1.1.5",
            ),
            (
                "policy.hsts",
                "HSTS max-age is 86400 seconds, less than 63072000",
            ),
        ]
        .map(|(id, what)| (id.to_owned(), format!("{what}{tail}")));
        assert_eq!(
            summary(&policy_findings(Policy::MozillaIntermediate, &input)),
            expected
        );
    }

    /// Unmeasured parts are reported once, not assumed compliant.
    #[test]
    fn incomplete() {
        let protocols = protocols(&[ProtocolVersion::TLS13]);
        let input = PolicyInput {
            protocols: &protocols,
            ciphers: None,
            key_exchange: None,
            chain: None,
            http: None,
        };
        let findings = policy_findings(Policy::MozillaModern, &input);
        assert_eq!(
            summary(&findings),
            [(
                "policy.incomplete".to_owned(),
                "mozilla-modern could not be fully checked: cipher suites, key exchange \
                 groups, certificate, HSTS not measured"
                    .to_owned()
            )]
        );
        assert_eq!(findings[0].severity, Severity::Info);

        let chain = [b"junk".to_vec()];
        let input = PolicyInput {
            chain: Some(&chain),
            ..input
        };
        assert!(
            policy_findings(Policy::MozillaModern, &input)
                .iter()
                .any(|f| f.message.ends_with("leaf certificate cannot be parsed"))
        );
    }

    /// Modern accepts its own certificate type and rejects missing HSTS.
    #[test]
    fn modern_certificate_and_hsts() {
        let deviations = |der: &[u8]| -> Vec<String> {
            certificate_deviations(Policy::MozillaModern, der)
                .into_iter()
                .map(|f| f.id)
                .collect()
        };
        assert_eq!(deviations(EC_LOCALHOST), ["policy.cert_lifespan"]);
        assert_eq!(
            certificate_deviations(Policy::MozillaIntermediate, EC_LOCALHOST),
            []
        );
        assert_eq!(
            hsts_deviation(Policy::MozillaModern, &http(None), MOZILLA_HSTS_MAX_AGE)
                .map(|f| f.message),
            Some(
                "no Strict-Transport-Security header is sent, which mozilla-modern does not allow"
                    .to_owned()
            )
        );
        assert!(
            hsts_deviation(Policy::MozillaModern, &http(Some("max-age=x")), 1)
                .is_some_and(|f| f.message.contains("is invalid"))
        );
    }

    /// Names round-trip through `FromStr`.
    #[test]
    fn names() {
        for policy in Policy::ALL {
            assert_eq!(policy.as_str().parse::<Policy>(), Ok(policy));
        }
        assert_eq!("MOZILLA-MODERN".parse(), Ok(Policy::MozillaModern));
        assert!("pci".parse::<Policy>().is_err());
    }
}
