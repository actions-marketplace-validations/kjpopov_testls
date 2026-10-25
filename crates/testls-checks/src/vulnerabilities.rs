//! Named vulnerabilities derived from data the scan already collected.
//!
//! Nothing here sends attack traffic: each verdict comes from the offered
//! protocols, cipher suites, key exchange parameters and handshake features.
//! Findings are only emitted for issues no other check reports already; the
//! rest point to the existing finding id.

use testls_probe::{
    CipherResult, HandshakeFeatures, KeyExchangeResult, ProtocolResult, ProtocolSupport,
};
use testls_wire::ProtocolVersion;

use crate::ciphers::{cipher_name, has_weakness};
use crate::{Finding, Severity};

/// Verdict for one vulnerability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VulnStatus {
    /// The server shows the weakness.
    Vulnerable,
    /// The server does not show the weakness.
    NotVulnerable,
    /// The data needed for a verdict is missing.
    NotTested,
}

impl VulnStatus {
    /// Stable lower-case name used in reports.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Vulnerable => "vulnerable",
            Self::NotVulnerable => "not vulnerable",
            Self::NotTested => "not tested",
        }
    }
}

/// One named vulnerability and its verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vulnerability {
    /// Stable short id, e.g. `poodle`.
    pub id: &'static str,
    /// Display name, e.g. `POODLE`.
    pub name: &'static str,
    /// Verdict.
    pub status: VulnStatus,
    /// Short reason for the verdict.
    pub detail: String,
    /// Finding id that reports the issue when vulnerable.
    pub finding: Option<&'static str>,
}

/// Builds a [`Vulnerability`].
fn vuln(
    id: &'static str,
    name: &'static str,
    status: VulnStatus,
    detail: impl Into<String>,
    finding: &'static str,
) -> Vulnerability {
    Vulnerability {
        id,
        name,
        status,
        detail: detail.into(),
        finding: (status == VulnStatus::Vulnerable).then_some(finding),
    }
}

/// Severity of the findings this module owns.
fn severity(finding: &str) -> Option<Severity> {
    match finding {
        "vuln.crime" => Some(Severity::High),
        "vuln.renegotiation" => Some(Severity::Medium),
        "vuln.beast" | "vuln.logjam" | "vuln.fallback_scsv" | "vuln.raccoon" => Some(Severity::Low),
        _ => None,
    }
}

/// Everything the assessment looks at.
struct Inputs<'a> {
    protocols: &'a [ProtocolResult],
    ciphers: &'a [CipherResult],
    key_exchange: &'a [KeyExchangeResult],
    features: Option<&'a HandshakeFeatures>,
}

impl Inputs<'_> {
    /// Whether `version` was offered; `None` when the probe failed.
    fn offered(&self, version: ProtocolVersion) -> Option<bool> {
        match self
            .protocols
            .iter()
            .find(|p| p.version == version)?
            .support
        {
            ProtocolSupport::Supported => Some(true),
            ProtocolSupport::NotSupported => Some(false),
            ProtocolSupport::Error(_) => None,
        }
    }

    /// Names of accepted SSLv3+ suites that satisfy `pred`, deduplicated.
    fn suites(&self, pred: impl Fn(ProtocolVersion, &str) -> bool) -> Vec<&'static str> {
        let mut names: Vec<&'static str> = self
            .ciphers
            .iter()
            .filter(|c| c.version >= ProtocolVersion::SSL3)
            .flat_map(|c| {
                c.suites
                    .iter()
                    .map(|&id| (c.version, cipher_name(c.version, id)))
            })
            .filter(|&(v, name)| pred(v, name))
            .map(|(_, name)| name)
            .collect();
        names.sort_unstable();
        names.dedup();
        names
    }

    /// Key exchange results for versions before TLSv1.3.
    fn legacy_key_exchange(&self) -> impl Iterator<Item = &KeyExchangeResult> {
        self.key_exchange
            .iter()
            .filter(|k| k.version < ProtocolVersion::TLS13)
    }
}

/// Verdict from whether a protocol version is offered.
fn protocol_vuln(
    inputs: &Inputs,
    id: &'static str,
    name: &'static str,
    version: ProtocolVersion,
    finding: &'static str,
) -> Vulnerability {
    let (status, detail) = match inputs.offered(version) {
        Some(true) => (VulnStatus::Vulnerable, format!("{version} offered")),
        Some(false) => (VulnStatus::NotVulnerable, format!("{version} not offered")),
        None => (VulnStatus::NotTested, format!("{version} probe failed")),
    };
    vuln(id, name, status, detail, finding)
}

/// Verdict from the accepted suites matching `pred`.
fn suite_vuln(
    inputs: &Inputs,
    id: &'static str,
    name: &'static str,
    finding: &'static str,
    pred: impl Fn(ProtocolVersion, &str) -> bool,
) -> Vulnerability {
    if inputs.ciphers.is_empty() {
        return vuln(
            id,
            name,
            VulnStatus::NotTested,
            "no cipher suites enumerated",
            finding,
        );
    }
    let names = inputs.suites(pred);
    match names.as_slice() {
        [] => vuln(
            id,
            name,
            VulnStatus::NotVulnerable,
            "no affected suites",
            finding,
        ),
        [one] => vuln(id, name, VulnStatus::Vulnerable, *one, finding),
        [first, rest @ ..] => vuln(
            id,
            name,
            VulnStatus::Vulnerable,
            format!("{first} and {} more", rest.len()),
            finding,
        ),
    }
}

/// BEAST: CBC suites with SSLv3 or TLSv1.0, whose record IVs are predictable.
fn beast(inputs: &Inputs) -> Vulnerability {
    let (id, name, finding) = ("beast", "BEAST", "vuln.beast");
    let old = [ProtocolVersion::SSL3, ProtocolVersion::TLS10];
    if old.iter().all(|&v| inputs.offered(v) == Some(false)) {
        return vuln(
            id,
            name,
            VulnStatus::NotVulnerable,
            "no SSLv3 or TLSv1.0",
            finding,
        );
    }
    let tested = old.iter().all(|&v| {
        inputs.offered(v) == Some(false) || inputs.ciphers.iter().any(|c| c.version == v)
    });
    let verdict = suite_vuln(inputs, id, name, finding, |v, n| {
        old.contains(&v) && has_weakness("cbc", n)
    });
    if tested || verdict.status == VulnStatus::Vulnerable {
        verdict
    } else {
        vuln(
            id,
            name,
            VulnStatus::NotTested,
            "no cipher suites enumerated",
            finding,
        )
    }
}

/// Logjam: export DHE suites, small DH groups, or a widely shared 1024-bit
/// prime that is a precomputation target.
fn logjam(inputs: &Inputs) -> Vulnerability {
    let (id, name) = ("logjam", "Logjam");
    if !inputs.ciphers.is_empty() {
        let export = inputs.suites(|_, n| n.contains("DHE") && n.contains("EXPORT"));
        if let Some(suite) = export.first() {
            return vuln(id, name, VulnStatus::Vulnerable, *suite, "cipher.export");
        }
    }
    let mut detail = None;
    for k in inputs.legacy_key_exchange() {
        let Some(bits) = k.dh_bits else { continue };
        if bits < 1024 {
            let text = format!("{} uses a {bits}-bit DH group", k.version);
            return vuln(id, name, VulnStatus::Vulnerable, text, "dh.weak");
        }
        let known = k.dh_prime.as_deref().and_then(testls_data::known_dh_prime);
        if let Some(p) = known.filter(|p| !p.ffdhe && bits <= 1024) {
            let text = format!(
                "{} uses the well-known {} ({})",
                k.version, p.name, p.source
            );
            return vuln(id, name, VulnStatus::Vulnerable, text, "vuln.logjam");
        }
        detail = Some(match known {
            Some(p) => format!("{bits}-bit {}", p.name),
            None => format!("{bits}-bit custom DH group"),
        });
    }
    match detail {
        Some(text) => vuln(id, name, VulnStatus::NotVulnerable, text, ""),
        None if inputs.legacy_key_exchange().next().is_some() => vuln(
            id,
            name,
            VulnStatus::NotVulnerable,
            "no DHE key exchange",
            "",
        ),
        None => vuln(id, name, VulnStatus::NotTested, "no key exchange data", ""),
    }
}

/// Raccoon: a DHE server that reuses its public value across handshakes.
fn raccoon(inputs: &Inputs) -> Vulnerability {
    let (id, name, finding) = ("raccoon", "Raccoon", "vuln.raccoon");
    let mut measured = false;
    let mut dhe = false;
    for k in inputs.legacy_key_exchange() {
        dhe |= k.dh_bits.is_some();
        match k.dh_key_reused {
            Some(true) => {
                let text = format!("{} reuses its DH public value", k.version);
                return vuln(id, name, VulnStatus::Vulnerable, text, finding);
            }
            Some(false) => measured = true,
            None => {}
        }
    }
    let (status, detail) = if measured {
        (
            VulnStatus::NotVulnerable,
            "fresh DH public value per handshake",
        )
    } else if dhe {
        (VulnStatus::NotTested, "DH key reuse not measured")
    } else if inputs.legacy_key_exchange().next().is_some() {
        (VulnStatus::NotVulnerable, "no DHE key exchange")
    } else {
        (VulnStatus::NotTested, "no key exchange data")
    };
    vuln(id, name, status, detail, finding)
}

/// Verdict from a handshake feature probe flag.
///
/// `flag` reads the feature; `bad` is the value that means vulnerable.
fn feature_vuln(
    inputs: &Inputs,
    id: &'static str,
    name: &'static str,
    finding: &'static str,
    flag: fn(&HandshakeFeatures) -> (bool, Option<bool>),
    bad: bool,
    texts: [&'static str; 3],
) -> Vulnerability {
    let [vulnerable, safe, not_applicable] = texts;
    let Some(features) = inputs.features else {
        return vuln(
            id,
            name,
            VulnStatus::NotTested,
            "handshake probe failed",
            finding,
        );
    };
    let (applicable, value) = flag(features);
    let (status, detail) = match value {
        _ if !applicable => (VulnStatus::NotVulnerable, not_applicable),
        Some(v) if v == bad => (VulnStatus::Vulnerable, vulnerable),
        Some(_) => (VulnStatus::NotVulnerable, safe),
        None => (VulnStatus::NotTested, "handshake probe failed"),
    };
    vuln(id, name, status, detail, finding)
}

/// Assesses the named vulnerabilities from the collected scan data.
///
/// `ciphers` holds the successful cipher enumerations only; `features` is
/// `None` when the handshake feature probe failed.
#[must_use]
pub fn assess_vulnerabilities(
    protocols: &[ProtocolResult],
    ciphers: &[CipherResult],
    key_exchange: &[KeyExchangeResult],
    features: Option<&HandshakeFeatures>,
) -> Vec<Vulnerability> {
    let inputs = Inputs {
        protocols,
        ciphers,
        key_exchange,
        features,
    };
    let only_tls13 = "no TLSv1.2 or older protocol";
    vec![
        protocol_vuln(
            &inputs,
            "poodle",
            "POODLE",
            ProtocolVersion::SSL3,
            "protocol.ssl3",
        ),
        beast(&inputs),
        suite_vuln(&inputs, "sweet32", "SWEET32", "cipher.3des", |_, n| {
            ["3des", "des", "rc2"].iter().any(|k| has_weakness(k, n)) || n.contains("_IDEA_")
        }),
        suite_vuln(&inputs, "rc4", "RC4", "cipher.rc4", |_, n| {
            has_weakness("rc4", n)
        }),
        suite_vuln(&inputs, "freak", "FREAK", "cipher.export", |_, n| {
            n.starts_with("TLS_RSA_EXPORT")
        }),
        logjam(&inputs),
        protocol_vuln(
            &inputs,
            "drown",
            "DROWN",
            ProtocolVersion::SSL2,
            "protocol.ssl2",
        ),
        feature_vuln(
            &inputs,
            "crime",
            "CRIME",
            "vuln.crime",
            |f| (f.legacy_version.is_some(), f.compression),
            true,
            ["TLS compression enabled", "no TLS compression", only_tls13],
        ),
        feature_vuln(
            &inputs,
            "renegotiation",
            "Insecure renegotiation",
            "vuln.renegotiation",
            |f| (f.legacy_version.is_some(), f.secure_renegotiation),
            false,
            [
                "no secure renegotiation (RFC 5746)",
                "secure renegotiation supported",
                only_tls13,
            ],
        ),
        feature_vuln(
            &inputs,
            "fallback_scsv",
            "Downgrade (TLS_FALLBACK_SCSV)",
            "vuln.fallback_scsv",
            |f| (f.fallback_version.is_some(), f.fallback_scsv),
            false,
            [
                "TLS_FALLBACK_SCSV ignored",
                "TLS_FALLBACK_SCSV honoured",
                "only one protocol version offered",
            ],
        ),
        suite_vuln(
            &inputs,
            "no_forward_secrecy",
            "No forward secrecy",
            "cipher.no_pfs",
            |_, n| has_weakness("no_pfs", n),
        ),
        raccoon(&inputs),
    ]
}

/// Findings for vulnerable entries not already reported by another check.
#[must_use]
pub fn vulnerability_findings(vulnerabilities: &[Vulnerability]) -> Vec<Finding> {
    vulnerabilities
        .iter()
        .filter_map(|v| {
            let id = v.finding?;
            let severity = severity(id)?;
            Some(Finding::new(
                id,
                severity,
                format!("{}: {}", v.name, v.detail),
            ))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    //! Unit tests for the vulnerability assessment.

    use testls_probe::CipherOrder;

    use super::*;

    /// `TLS_RSA_WITH_3DES_EDE_CBC_SHA`.
    const RSA_3DES: u32 = 0x000a;
    /// `TLS_RSA_WITH_AES_128_CBC_SHA`.
    const RSA_AES_CBC: u32 = 0x002f;
    /// `TLS_RSA_WITH_RC4_128_SHA`.
    const RSA_RC4: u32 = 0x0005;
    /// `TLS_RSA_EXPORT_WITH_RC4_40_MD5`.
    const RSA_EXPORT: u32 = 0x0003;
    /// `TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA`.
    const DHE_EXPORT: u32 = 0x0014;
    /// `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`.
    const ECDHE_GCM: u32 = 0xc02f;
    /// `TLS_AES_128_GCM_SHA256`.
    const TLS13_AES: u32 = 0x1301;

    /// Protocol results with `offered` supported and every other version not.
    fn protocols(offered: &[ProtocolVersion]) -> Vec<ProtocolResult> {
        ProtocolVersion::ALL
            .iter()
            .map(|&version| ProtocolResult {
                version,
                support: if offered.contains(&version) {
                    ProtocolSupport::Supported
                } else {
                    ProtocolSupport::NotSupported
                },
            })
            .collect()
    }

    /// A cipher result accepting `suites` with `version`.
    fn ciphers(version: ProtocolVersion, suites: &[u32]) -> CipherResult {
        CipherResult {
            version,
            suites: suites.to_vec(),
            order: CipherOrder::Server,
        }
    }

    /// Key exchange data for `version` with optional DH parameters.
    fn kx(
        version: ProtocolVersion,
        prime: Option<Vec<u8>>,
        reused: Option<bool>,
    ) -> KeyExchangeResult {
        KeyExchangeResult {
            version,
            groups: vec![0x001d],
            group_order: CipherOrder::Server,
            dh_bits: prime.as_ref().map(|p| p.len() * 8),
            dh_prime: prime,
            dh_key_reused: reused,
        }
    }

    /// Handshake features of a well-configured TLSv1.2 + TLSv1.3 server.
    fn good_features() -> HandshakeFeatures {
        HandshakeFeatures {
            legacy_version: Some(ProtocolVersion::TLS12),
            compression: Some(false),
            secure_renegotiation: Some(true),
            fallback_version: Some(ProtocolVersion::TLS12),
            fallback_scsv: Some(true),
        }
    }

    /// Decodes upper-case hex.
    fn unhex(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Status of vulnerability `id` in `list`.
    fn status(list: &[Vulnerability], id: &str) -> VulnStatus {
        list.iter().find(|v| v.id == id).unwrap().status
    }

    /// A modern server is vulnerable to nothing and yields no findings.
    #[test]
    fn modern_server() {
        let p = protocols(&[ProtocolVersion::TLS12, ProtocolVersion::TLS13]);
        let c = [
            ciphers(ProtocolVersion::TLS12, &[ECDHE_GCM]),
            ciphers(ProtocolVersion::TLS13, &[TLS13_AES]),
        ];
        let k = [
            kx(ProtocolVersion::TLS12, None, None),
            kx(ProtocolVersion::TLS13, None, None),
        ];
        let list = assess_vulnerabilities(&p, &c, &k, Some(&good_features()));
        assert_eq!(list.len(), 12);
        for v in &list {
            assert_eq!(
                v.status,
                VulnStatus::NotVulnerable,
                "{}: {}",
                v.id,
                v.detail
            );
            assert_eq!(v.finding, None);
        }
        assert_eq!(vulnerability_findings(&list), []);
    }

    /// A legacy server trips most checks; only new issues become findings.
    #[test]
    fn legacy_server() {
        let all = [
            ProtocolVersion::SSL2,
            ProtocolVersion::SSL3,
            ProtocolVersion::TLS10,
            ProtocolVersion::TLS12,
        ];
        let p = protocols(&all);
        let c = [
            ciphers(ProtocolVersion::TLS10, &[RSA_AES_CBC, RSA_3DES, RSA_RC4]),
            ciphers(ProtocolVersion::TLS12, &[RSA_EXPORT, ECDHE_GCM]),
        ];
        let oakley2 = unhex(testls_data::known_dh_primes()[1].hex);
        let k = [kx(ProtocolVersion::TLS12, Some(oakley2), Some(true))];
        let features = HandshakeFeatures {
            legacy_version: Some(ProtocolVersion::TLS12),
            compression: Some(true),
            secure_renegotiation: Some(false),
            fallback_version: Some(ProtocolVersion::TLS10),
            fallback_scsv: Some(false),
        };
        let list = assess_vulnerabilities(&p, &c, &k, Some(&features));
        for v in &list {
            assert_eq!(v.status, VulnStatus::Vulnerable, "{}: {}", v.id, v.detail);
        }
        let by_id = |id: &str| list.iter().find(|v| v.id == id).unwrap();
        assert_eq!(by_id("poodle").finding, Some("protocol.ssl3"));
        assert_eq!(by_id("sweet32").detail, "TLS_RSA_WITH_3DES_EDE_CBC_SHA");
        assert_eq!(
            by_id("no_forward_secrecy").detail,
            "TLS_RSA_EXPORT_WITH_RC4_40_MD5 and 3 more"
        );
        assert_eq!(by_id("logjam").finding, Some("vuln.logjam"));
        assert!(by_id("logjam").detail.contains("Oakley group 2"));

        let findings = vulnerability_findings(&list);
        let ids: Vec<(&str, Severity)> = findings
            .iter()
            .map(|f| (f.id.as_str(), f.severity))
            .collect();
        assert_eq!(
            ids,
            [
                ("vuln.beast", Severity::Low),
                ("vuln.logjam", Severity::Low),
                ("vuln.crime", Severity::High),
                ("vuln.renegotiation", Severity::Medium),
                ("vuln.fallback_scsv", Severity::Low),
                ("vuln.raccoon", Severity::Low),
            ]
        );
        assert_eq!(findings[2].message, "CRIME: TLS compression enabled");
    }

    /// Logjam verdicts: export DHE, small groups, shared and safe primes.
    #[test]
    fn logjam_cases() {
        let p = protocols(&[ProtocolVersion::TLS12]);
        let assess = |c: &[CipherResult], k: &[KeyExchangeResult]| {
            let list = assess_vulnerabilities(&p, c, k, None);
            list.into_iter().find(|v| v.id == "logjam").unwrap()
        };
        let tls12 = ProtocolVersion::TLS12;

        let v = assess(&[ciphers(tls12, &[DHE_EXPORT])], &[]);
        assert_eq!(
            (v.status, v.finding),
            (VulnStatus::Vulnerable, Some("cipher.export"))
        );

        let v = assess(&[], &[kx(tls12, Some(vec![0xff; 64]), None)]);
        assert_eq!(
            (v.status, v.finding),
            (VulnStatus::Vulnerable, Some("dh.weak"))
        );
        assert_eq!(v.detail, "TLSv1.2 uses a 512-bit DH group");

        let ffdhe2048 = unhex(testls_data::known_dh_primes()[11].hex);
        let v = assess(&[], &[kx(tls12, Some(ffdhe2048), None)]);
        assert_eq!(v.status, VulnStatus::NotVulnerable);
        assert_eq!(v.detail, "2048-bit ffdhe2048");

        let v = assess(&[], &[kx(tls12, Some(vec![0xc5; 128]), None)]);
        assert_eq!(v.detail, "1024-bit custom DH group");

        let v = assess(&[], &[kx(tls12, None, None)]);
        assert_eq!(
            (v.status, v.detail.as_str()),
            (VulnStatus::NotVulnerable, "no DHE key exchange")
        );

        let v = assess(&[], &[]);
        assert_eq!(v.status, VulnStatus::NotTested);
    }

    /// Missing data leads to "not tested" rather than a guess.
    #[test]
    fn missing_data() {
        let mut p = protocols(&[ProtocolVersion::TLS12]);
        p[1].support = ProtocolSupport::Error("timeout".into());
        let k = [kx(ProtocolVersion::TLS12, Some(vec![0xc5; 256]), None)];
        let list = assess_vulnerabilities(&p, &[], &k, None);
        for id in [
            "poodle",
            "beast",
            "sweet32",
            "rc4",
            "crime",
            "renegotiation",
            "fallback_scsv",
            "raccoon",
        ] {
            assert_eq!(status(&list, id), VulnStatus::NotTested, "{id}");
        }
        assert_eq!(status(&list, "drown"), VulnStatus::NotVulnerable);
        assert_eq!(vulnerability_findings(&list), []);
    }

    /// Feature checks do not apply to TLSv1.3-only or single-version servers.
    #[test]
    fn features_not_applicable() {
        let p = protocols(&[ProtocolVersion::TLS13]);
        let c = [ciphers(ProtocolVersion::TLS13, &[TLS13_AES])];
        let features = HandshakeFeatures {
            legacy_version: None,
            compression: None,
            secure_renegotiation: None,
            fallback_version: None,
            fallback_scsv: None,
        };
        let list = assess_vulnerabilities(&p, &c, &[], Some(&features));
        let crime = list.iter().find(|v| v.id == "crime").unwrap();
        assert_eq!(crime.status, VulnStatus::NotVulnerable);
        assert_eq!(crime.detail, "no TLSv1.2 or older protocol");
        let fallback = list.iter().find(|v| v.id == "fallback_scsv").unwrap();
        assert_eq!(fallback.detail, "only one protocol version offered");
        assert_eq!(status(&list, "beast"), VulnStatus::NotVulnerable);
        assert_eq!(VulnStatus::NotTested.as_str(), "not tested");
    }
}
