//! Checks for the OCSP response a server staples to its certificate
//! (RFC 6066 §8, RFC 8446 §4.4.2.1).
//!
//! The response is parsed per RFC 6960 §4.2.1, matched to the leaf
//! certificate by `CertID`, and its signature is verified against the issuer
//! or a delegated responder certificate that the issuer authorised for OCSP
//! signing (RFC 6960 §4.2.2.2).

use ring::digest;
use x509_parser::asn1_rs::{BitString, FromDer};
use x509_parser::certificate::X509Certificate;
use x509_parser::oid_registry::{
    OID_HASH_SHA1, OID_NIST_HASH_SHA256, OID_NIST_HASH_SHA384, OID_NIST_HASH_SHA512,
};
use x509_parser::parse_x509_certificate;
use x509_parser::time::ASN1Time;
use x509_parser::verify::verify_signature;
use x509_parser::x509::AlgorithmIdentifier;

use crate::{Finding, Severity};

/// DER tag of `SEQUENCE`.
const SEQUENCE: u8 = 0x30;
/// DER tag of `INTEGER`.
const INTEGER: u8 = 0x02;
/// DER tag of `BIT STRING`.
const BIT_STRING: u8 = 0x03;
/// DER tag of `OCTET STRING`.
const OCTET_STRING: u8 = 0x04;
/// DER tag of `OBJECT IDENTIFIER`.
const OID: u8 = 0x06;
/// DER tag of `ENUMERATED`.
const ENUMERATED: u8 = 0x0a;
/// DER tag of `GeneralizedTime`.
const GENERALIZED_TIME: u8 = 0x18;

/// Context-specific constructed tag `[n]`.
const fn explicit(n: u8) -> u8 {
    0xa0 | n
}

/// Context-specific primitive tag `[n]`.
const fn implicit(n: u8) -> u8 {
    0x80 | n
}

/// Content octets of `id-pkix-ocsp-basic`, 1.3.6.1.5.5.7.48.1.1
/// (RFC 6960 §4.2.1).
const OCSP_BASIC: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01];

/// Content octets of `id-pe-tlsfeature`, 1.3.6.1.5.5.7.1.24 (RFC 7633 §6).
const TLS_FEATURE: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x18];

/// TLS extension numbers that make up "must staple" (RFC 7633 §4.2):
/// `status_request` (5) and `status_request_v2` (17).
const STATUS_REQUEST_FEATURES: [&[u8]; 2] = [&[5], &[17]];

/// Tolerated clock difference between scanner and responder, in seconds.
const CLOCK_SKEW: i64 = 5 * 60;

/// Revocation status of the leaf certificate (RFC 6960 §4.2.1 `CertStatus`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertStatus {
    /// The certificate is not revoked.
    Good,
    /// The certificate was revoked.
    Revoked {
        /// Revocation time as a Unix timestamp.
        time: i64,
        /// `CRLReason` code (RFC 5280 §5.3.1), if given.
        reason: Option<u32>,
    },
    /// The responder does not know the certificate.
    Unknown,
}

/// A stapled OCSP response that parsed and verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OcspStatus {
    /// Status of the leaf certificate.
    pub status: CertStatus,
    /// When the response was signed, as a Unix timestamp.
    pub produced_at: i64,
    /// Start of the validity interval, as a Unix timestamp.
    pub this_update: i64,
    /// End of the validity interval, as a Unix timestamp, if any.
    pub next_update: Option<i64>,
}

/// Parses a stapled OCSP response and verifies it for the leaf of `chain`.
///
/// `chain` is the server's chain, leaf first; the issuer must be the second
/// entry. `now` (Unix timestamp) is used to check a delegated responder
/// certificate's validity; freshness of the response itself is left to
/// [`ocsp_findings`].
///
/// # Errors
///
/// Returns a description if the response is malformed, not successful, does
/// not cover the leaf, or its signature does not verify.
pub fn verify_ocsp_response(
    response: &[u8],
    chain: &[Vec<u8>],
    now: i64,
) -> Result<OcspStatus, String> {
    let [leaf, issuer, ..] = chain else {
        return Err("issuer certificate missing from chain".into());
    };
    let leaf = certificate(leaf)?;
    let issuer = certificate(issuer)?;
    let basic = basic_response(response)?;
    let data = response_data(basic.tbs)?;
    let single = data
        .responses
        .iter()
        .find(|single| single.cert_id.matches(&leaf, &issuer))
        .ok_or("no response for the leaf certificate")?;
    let signer = signer(&data.responder, &basic.certs, &issuer, now)?;
    verify_signature(
        signer.public_key(),
        &basic.algorithm,
        &basic.signature,
        basic.tbs,
    )
    .map_err(|e| format!("signature does not verify: {e}"))?;
    Ok(OcspStatus {
        status: single.status,
        produced_at: data.produced_at,
        this_update: single.this_update,
        next_update: single.next_update,
    })
}

/// Name of a `CRLReason` code (RFC 5280 §5.3.1).
#[must_use]
pub fn revocation_reason_name(reason: u32) -> &'static str {
    match reason {
        0 => "unspecified",
        1 => "keyCompromise",
        2 => "cACompromise",
        3 => "affiliationChanged",
        4 => "superseded",
        5 => "cessationOfOperation",
        6 => "certificateHold",
        8 => "removeFromCRL",
        9 => "privilegeWithdrawn",
        10 => "aACompromise",
        _ => "unknown reason",
    }
}

/// Findings for OCSP stapling.
///
/// `chain` is the server's certificate chain (leaf first), `response` the
/// stapled OCSP response if one was sent, and `now` the current time as a
/// Unix timestamp.
#[must_use]
pub fn ocsp_findings(chain: &[Vec<u8>], response: Option<&[u8]>, now: i64) -> Vec<Finding> {
    let Some(response) = response else {
        let must_staple = chain
            .first()
            .and_then(|der| certificate(der).ok())
            .is_some_and(|leaf| must_staple(&leaf));
        return vec![if must_staple {
            Finding::new(
                "ocsp.must_staple_missing",
                Severity::High,
                "certificate requires OCSP stapling (RFC 7633) but no response was stapled",
            )
        } else {
            Finding::new(
                "ocsp.not_stapled",
                Severity::Info,
                "no OCSP response stapled",
            )
        }];
    };
    let status = match verify_ocsp_response(response, chain, now) {
        Ok(status) => status,
        Err(e) => {
            return vec![Finding::new(
                "ocsp.invalid",
                Severity::Medium,
                format!("stapled OCSP response is invalid: {e}"),
            )];
        }
    };
    match status.status {
        CertStatus::Revoked { time, reason } => {
            return vec![Finding::new(
                "ocsp.revoked",
                Severity::Critical,
                format!(
                    "certificate was revoked on {} ({})",
                    display_time(time),
                    reason.map_or("no reason given", revocation_reason_name)
                ),
            )];
        }
        CertStatus::Unknown => {
            return vec![Finding::new(
                "ocsp.unknown",
                Severity::Medium,
                "stapled OCSP response does not know the certificate",
            )];
        }
        CertStatus::Good => {}
    }
    if status.this_update > now + CLOCK_SKEW {
        return vec![Finding::new(
            "ocsp.not_yet_valid",
            Severity::Medium,
            format!(
                "stapled OCSP response is not valid before {}",
                display_time(status.this_update)
            ),
        )];
    }
    if let Some(next) = status.next_update
        && next + CLOCK_SKEW < now
    {
        return vec![Finding::new(
            "ocsp.expired",
            Severity::Medium,
            format!("stapled OCSP response expired {}", display_time(next)),
        )];
    }
    vec![Finding::new(
        "ocsp.stapled",
        Severity::Ok,
        "stapled OCSP response reports the certificate as good",
    )]
}

/// Formats a Unix timestamp like certificate validity dates.
fn display_time(time: i64) -> String {
    ASN1Time::from_timestamp(time).map_or_else(|_| time.to_string(), |t| t.to_string())
}

/// Whether the leaf carries the TLS feature extension with `status_request`
/// or `status_request_v2` (RFC 7633 §4.2).
fn must_staple(leaf: &X509Certificate<'_>) -> bool {
    leaf.extensions()
        .iter()
        .filter(|ext| ext.oid.as_bytes() == TLS_FEATURE)
        .any(|ext| {
            let mut outer = Der::new(ext.value);
            let Ok(features) = outer.expect(SEQUENCE, "Features") else {
                return false;
            };
            let mut features = Der::new(features);
            while let Ok(feature) = features.expect(INTEGER, "feature") {
                if STATUS_REQUEST_FEATURES.contains(&feature) {
                    return true;
                }
            }
            false
        })
}

/// Parses one DER certificate, rejecting trailing bytes.
fn certificate(der: &[u8]) -> Result<X509Certificate<'_>, String> {
    match parse_x509_certificate(der) {
        Ok(([], cert)) => Ok(cert),
        Ok(_) => Err("certificate has trailing bytes".into()),
        Err(e) => Err(format!("certificate cannot be parsed: {e}")),
    }
}

/// The signed parts of a `BasicOCSPResponse` (RFC 6960 §4.2.1).
#[derive(Debug)]
struct BasicResponse<'a> {
    /// DER of `tbsResponseData`, the signed bytes.
    tbs: &'a [u8],
    /// Signature algorithm.
    algorithm: AlgorithmIdentifier<'a>,
    /// Signature value.
    signature: BitString<'a>,
    /// Certificates included to help verify the signature.
    certs: Vec<X509Certificate<'a>>,
}

/// Unwraps `OCSPResponse` down to a `BasicOCSPResponse`.
fn basic_response(der: &[u8]) -> Result<BasicResponse<'_>, String> {
    let mut outer = Der::new(der);
    let mut response = Der::new(outer.expect(SEQUENCE, "OCSPResponse")?);
    outer.finish("OCSPResponse")?;
    let status = response.expect(ENUMERATED, "responseStatus")?;
    if status != [0] {
        return Err(format!("responder status is {}", response_status(status)));
    }
    let mut bytes = Der::new(response.expect(explicit(0), "responseBytes")?);
    response.finish("OCSPResponse")?;
    let mut bytes = Der::new(bytes.expect(SEQUENCE, "ResponseBytes")?);
    if bytes.expect(OID, "responseType")? != OCSP_BASIC {
        return Err("response type is not id-pkix-ocsp-basic".into());
    }
    let mut octets = Der::new(bytes.expect(OCTET_STRING, "response")?);
    bytes.finish("ResponseBytes")?;

    let mut basic = Der::new(octets.expect(SEQUENCE, "BasicOCSPResponse")?);
    octets.finish("BasicOCSPResponse")?;
    let tbs = basic.next("tbsResponseData")?;
    if tbs.tag != SEQUENCE {
        return Err("tbsResponseData is not a SEQUENCE".into());
    }
    let algorithm = basic.next("signatureAlgorithm")?;
    let Ok(([], algorithm)) = AlgorithmIdentifier::from_der(algorithm.raw) else {
        return Err("invalid signatureAlgorithm".into());
    };
    let signature = match basic.expect(BIT_STRING, "signature")? {
        [0, bits @ ..] => BitString::new(0, bits),
        _ => return Err("invalid signature".into()),
    };
    let mut certs = Vec::new();
    if let Some(list) = basic.optional(explicit(0), "certs")? {
        let mut list = Der::new(list);
        let mut entries = Der::new(list.expect(SEQUENCE, "certs")?);
        list.finish("certs")?;
        while !entries.is_empty() {
            let entry = entries.next("certs")?;
            certs.push(certificate(entry.raw)?);
        }
    }
    basic.finish("BasicOCSPResponse")?;
    Ok(BasicResponse {
        tbs: tbs.raw,
        algorithm,
        signature,
        certs,
    })
}

/// Name of an `OCSPResponseStatus` (RFC 6960 §4.2.1).
fn response_status(status: &[u8]) -> &'static str {
    match status {
        [1] => "malformedRequest",
        [2] => "internalError",
        [3] => "tryLater",
        [5] => "sigRequired",
        [6] => "unauthorized",
        _ => "invalid",
    }
}

/// `ResponderID` (RFC 6960 §4.2.1).
#[derive(Debug)]
enum ResponderId<'a> {
    /// DER of the responder's subject name.
    ByName(&'a [u8]),
    /// SHA-1 of the responder's public key bits.
    ByKey(&'a [u8]),
}

impl ResponderId<'_> {
    /// Whether `cert` is the responder this identifies.
    fn matches(&self, cert: &X509Certificate<'_>) -> bool {
        match self {
            Self::ByName(name) => cert.subject().as_raw() == *name,
            Self::ByKey(hash) => {
                let key = &cert.public_key().subject_public_key.data;
                digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, key).as_ref() == *hash
            }
        }
    }
}

/// The parts of `ResponseData` that are checked.
#[derive(Debug)]
struct ResponseData<'a> {
    /// Who signed the response.
    responder: ResponderId<'a>,
    /// `producedAt` as a Unix timestamp.
    produced_at: i64,
    /// One entry per certificate asked about.
    responses: Vec<SingleResponse<'a>>,
}

/// Parses `tbsResponseData` (including its SEQUENCE header).
fn response_data(der: &[u8]) -> Result<ResponseData<'_>, String> {
    let mut outer = Der::new(der);
    let mut data = Der::new(outer.expect(SEQUENCE, "tbsResponseData")?);
    if let Some(version) = data.optional(explicit(0), "version")? {
        let mut version = Der::new(version);
        if version.expect(INTEGER, "version")? != [0] {
            return Err("unsupported response version".into());
        }
        version.finish("version")?;
    }
    let responder = data.next("responderID")?;
    let mut inner = Der::new(responder.content);
    let responder = match responder.tag {
        t if t == explicit(1) => ResponderId::ByName(inner.next("byName")?.raw),
        t if t == explicit(2) => ResponderId::ByKey(inner.expect(OCTET_STRING, "byKey")?),
        _ => return Err("invalid responderID".into()),
    };
    inner.finish("responderID")?;
    let produced_at = time(&mut data, "producedAt")?;
    let mut list = Der::new(data.expect(SEQUENCE, "responses")?);
    let mut responses = Vec::new();
    while !list.is_empty() {
        responses.push(single_response(list.expect(SEQUENCE, "SingleResponse")?)?);
    }
    data.optional(explicit(1), "responseExtensions")?;
    data.finish("tbsResponseData")?;
    Ok(ResponseData {
        responder,
        produced_at,
        responses,
    })
}

/// `CertID` (RFC 6960 §4.1.1).
#[derive(Debug)]
struct CertId<'a> {
    /// Hash algorithm for the issuer name and key hashes.
    hash: AlgorithmIdentifier<'a>,
    /// Hash of the issuer's subject name DER.
    name_hash: &'a [u8],
    /// Hash of the issuer's public key bits.
    key_hash: &'a [u8],
    /// Content octets of the serial number.
    serial: &'a [u8],
}

impl CertId<'_> {
    /// Whether this identifies `leaf` as issued by `issuer`.
    fn matches(&self, leaf: &X509Certificate<'_>, issuer: &X509Certificate<'_>) -> bool {
        let oid = &self.hash.algorithm;
        let algorithm = if *oid == OID_HASH_SHA1 {
            &digest::SHA1_FOR_LEGACY_USE_ONLY
        } else if *oid == OID_NIST_HASH_SHA256 {
            &digest::SHA256
        } else if *oid == OID_NIST_HASH_SHA384 {
            &digest::SHA384
        } else if *oid == OID_NIST_HASH_SHA512 {
            &digest::SHA512
        } else {
            return false;
        };
        let key = &issuer.public_key().subject_public_key.data;
        self.serial == leaf.raw_serial()
            && digest::digest(algorithm, issuer.subject().as_raw()).as_ref() == self.name_hash
            && digest::digest(algorithm, key).as_ref() == self.key_hash
    }
}

/// The parts of a `SingleResponse` that are checked.
#[derive(Debug)]
struct SingleResponse<'a> {
    /// Which certificate this is about.
    cert_id: CertId<'a>,
    /// Its status.
    status: CertStatus,
    /// `thisUpdate` as a Unix timestamp.
    this_update: i64,
    /// `nextUpdate` as a Unix timestamp.
    next_update: Option<i64>,
}

/// Parses the content of a `SingleResponse`.
fn single_response(content: &[u8]) -> Result<SingleResponse<'_>, String> {
    let mut single = Der::new(content);
    let mut id = Der::new(single.expect(SEQUENCE, "CertID")?);
    let Ok(([], hash)) = AlgorithmIdentifier::from_der(id.next("hashAlgorithm")?.raw) else {
        return Err("invalid hashAlgorithm".into());
    };
    let cert_id = CertId {
        hash,
        name_hash: id.expect(OCTET_STRING, "issuerNameHash")?,
        key_hash: id.expect(OCTET_STRING, "issuerKeyHash")?,
        serial: id.expect(INTEGER, "serialNumber")?,
    };
    id.finish("CertID")?;

    let status = single.next("certStatus")?;
    let status = match status.tag {
        t if t == implicit(0) && status.content.is_empty() => CertStatus::Good,
        t if t == explicit(1) => revoked(status.content)?,
        t if t == implicit(2) && status.content.is_empty() => CertStatus::Unknown,
        _ => return Err("invalid certStatus".into()),
    };
    let this_update = time(&mut single, "thisUpdate")?;
    let next_update = match single.optional(explicit(0), "nextUpdate")? {
        Some(content) => {
            let mut inner = Der::new(content);
            let next = time(&mut inner, "nextUpdate")?;
            inner.finish("nextUpdate")?;
            Some(next)
        }
        None => None,
    };
    single.optional(explicit(1), "singleExtensions")?;
    single.finish("SingleResponse")?;
    Ok(SingleResponse {
        cert_id,
        status,
        this_update,
        next_update,
    })
}

/// Parses the content of `RevokedInfo`.
fn revoked(content: &[u8]) -> Result<CertStatus, String> {
    let mut info = Der::new(content);
    let time = time(&mut info, "revocationTime")?;
    let reason = match info.optional(explicit(0), "revocationReason")? {
        Some(content) => {
            let mut inner = Der::new(content);
            let code = match inner.expect(ENUMERATED, "revocationReason")? {
                [code] if *code < 0x80 => u32::from(*code),
                _ => return Err("invalid revocationReason".into()),
            };
            inner.finish("revocationReason")?;
            Some(code)
        }
        None => None,
    };
    info.finish("RevokedInfo")?;
    Ok(CertStatus::Revoked { time, reason })
}

/// Reads a `GeneralizedTime` as a Unix timestamp.
fn time(der: &mut Der<'_>, field: &str) -> Result<i64, String> {
    let element = der.next(field)?;
    if element.tag != GENERALIZED_TIME {
        return Err(format!("{field} is not a GeneralizedTime"));
    }
    match ASN1Time::from_der(element.raw) {
        Ok(([], time)) => Ok(time.timestamp()),
        _ => Err(format!("invalid {field}")),
    }
}

/// One DER element.
#[derive(Debug, Clone, Copy)]
struct Element<'a> {
    /// Identifier octet; only low tag numbers are supported.
    tag: u8,
    /// Content octets.
    content: &'a [u8],
    /// The whole encoding, header included.
    raw: &'a [u8],
}

/// Minimal reader for definite-length DER (X.690 §8.1, §10.1).
#[derive(Debug)]
struct Der<'a> {
    /// Bytes not yet read.
    input: &'a [u8],
}

impl<'a> Der<'a> {
    /// Reader over `input`.
    fn new(input: &'a [u8]) -> Self {
        Self { input }
    }

    /// Whether all input has been read.
    fn is_empty(&self) -> bool {
        self.input.is_empty()
    }

    /// Reads the next element.
    fn next(&mut self, field: &str) -> Result<Element<'a>, String> {
        let truncated = || format!("{field} is truncated");
        let input = self.input;
        let (&tag, rest) = input.split_first().ok_or_else(truncated)?;
        if tag & 0x1f == 0x1f {
            return Err(format!("{field} has an unsupported tag"));
        }
        let (&first, rest) = rest.split_first().ok_or_else(truncated)?;
        let (len, rest) = if first < 0x80 {
            (usize::from(first), rest)
        } else {
            let count = usize::from(first & 0x7f);
            if count == 0 || count > 4 || rest.len() < count {
                return Err(format!("{field} has an invalid length"));
            }
            let (bytes, rest) = rest.split_at(count);
            let len = bytes
                .iter()
                .fold(0usize, |len, &b| (len << 8) | usize::from(b));
            if bytes[0] == 0 || len < 0x80 {
                return Err(format!("{field} has a non-minimal length"));
            }
            (len, rest)
        };
        if rest.len() < len {
            return Err(truncated());
        }
        let header = input.len() - rest.len();
        let (raw, remaining) = input.split_at(header + len);
        self.input = remaining;
        Ok(Element {
            tag,
            content: &raw[header..],
            raw,
        })
    }

    /// Reads the next element, which must have `tag`, and returns its
    /// content.
    fn expect(&mut self, tag: u8, field: &str) -> Result<&'a [u8], String> {
        let element = self.next(field)?;
        if element.tag != tag {
            return Err(format!("{field} has an unexpected tag"));
        }
        Ok(element.content)
    }

    /// Reads the next element if it has `tag`, returning its content.
    fn optional(&mut self, tag: u8, field: &str) -> Result<Option<&'a [u8]>, String> {
        if self.input.first() == Some(&tag) {
            self.expect(tag, field).map(Some)
        } else {
            Ok(None)
        }
    }

    /// Fails if any input is left.
    fn finish(&self, field: &str) -> Result<(), String> {
        if self.is_empty() {
            Ok(())
        } else {
            Err(format!("{field} has trailing data"))
        }
    }
}

/// Picks the certificate whose key signed the response: the issuer itself
/// or a delegated responder it issued with the OCSP signing EKU
/// (RFC 6960 §4.2.2.2).
fn signer<'c>(
    responder: &ResponderId<'_>,
    certs: &'c [X509Certificate<'c>],
    issuer: &'c X509Certificate<'c>,
    now: i64,
) -> Result<&'c X509Certificate<'c>, String> {
    if responder.matches(issuer) {
        return Ok(issuer);
    }
    let delegate = certs
        .iter()
        .find(|cert| responder.matches(cert))
        .ok_or("responder certificate not found")?;
    delegate
        .verify_signature(Some(issuer.public_key()))
        .map_err(|_| "responder certificate is not issued by the certificate issuer")?;
    let authorised = matches!(
        delegate.extended_key_usage(),
        Ok(Some(eku)) if eku.value.ocsp_signing
    );
    if !authorised {
        return Err("responder certificate is not authorised for OCSP signing".into());
    }
    let valid = ASN1Time::from_timestamp(now).is_ok_and(|now| delegate.validity().is_valid_at(now));
    if !valid {
        return Err("responder certificate is not valid now".into());
    }
    Ok(delegate)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Self-signed test CA that issued every other fixture.
    const CA: &[u8] = include_bytes!("testdata/ocsp-ca.der");
    /// Leaf with status good.
    const LEAF: &[u8] = include_bytes!("testdata/ocsp-leaf.der");
    /// Leaf revoked for key compromise on 2026-10-01.
    const OTHER: &[u8] = include_bytes!("testdata/ocsp-other.der");
    /// Leaf the responder does not know.
    const STRAY: &[u8] = include_bytes!("testdata/ocsp-stray.der");
    /// Leaf with the TLS feature `status_request`.
    const MUST_STAPLE: &[u8] = include_bytes!("testdata/ocsp-must-staple.der");
    /// CA-signed response: `LEAF` is good.
    const GOOD: &[u8] = include_bytes!("testdata/ocsp-good.der");
    /// CA-signed response: `OTHER` is revoked.
    const REVOKED: &[u8] = include_bytes!("testdata/ocsp-revoked.der");
    /// Delegated-responder response: `LEAF` is good.
    const DELEGATED: &[u8] = include_bytes!("testdata/ocsp-delegated.der");
    /// Delegated-responder response: `STRAY` is unknown.
    const UNKNOWN: &[u8] = include_bytes!("testdata/ocsp-unknown.der");
    /// Response for `LEAF` signed by `OTHER`, which lacks the OCSP EKU.
    const UNAUTHORIZED: &[u8] = include_bytes!("testdata/ocsp-unauthorized.der");

    /// 2026-10-24, before the responses were produced.
    const BEFORE: i64 = 1_792_800_000;
    /// 2026-10-26, inside every response's validity interval.
    const NOW: i64 = 1_792_972_800;
    /// 2026-11-02, after every response's `nextUpdate`.
    const AFTER: i64 = 1_793_577_600;

    /// Chain of `leaf` and the test CA.
    fn chain(leaf: &[u8]) -> Vec<Vec<u8>> {
        vec![leaf.to_vec(), CA.to_vec()]
    }

    /// Finding ids and severities for a stapled response.
    fn findings(leaf: &[u8], response: Option<&[u8]>, now: i64) -> Vec<(String, Severity)> {
        ocsp_findings(&chain(leaf), response, now)
            .into_iter()
            .map(|f| (f.id, f.severity))
            .collect()
    }

    /// Error text of a response that fails verification.
    fn error(response: &[u8], leaf: &[u8]) -> String {
        verify_ocsp_response(response, &chain(leaf), NOW).unwrap_err()
    }

    /// A CA-signed good response verifies and is fresh.
    #[test]
    fn good_response() {
        let status = verify_ocsp_response(GOOD, &chain(LEAF), NOW).unwrap();
        assert_eq!(status.status, CertStatus::Good);
        assert!(status.produced_at > BEFORE && status.produced_at < NOW);
        assert_eq!(status.this_update, status.produced_at);
        assert_eq!(status.next_update, Some(status.this_update + 7 * 86_400));
        assert_eq!(
            findings(LEAF, Some(GOOD), NOW),
            [("ocsp.stapled".into(), Severity::Ok)]
        );
    }

    /// A delegated responder authorised by the issuer is accepted.
    #[test]
    fn delegated_responder() {
        let status = verify_ocsp_response(DELEGATED, &chain(LEAF), NOW).unwrap();
        assert_eq!(status.status, CertStatus::Good);
        assert_eq!(
            findings(LEAF, Some(DELEGATED), BEFORE),
            [("ocsp.invalid".into(), Severity::Medium)],
            "responder certificate must be valid at scan time"
        );
    }

    /// Revoked and unknown statuses are reported.
    #[test]
    fn revoked_and_unknown() {
        let status = verify_ocsp_response(REVOKED, &chain(OTHER), NOW).unwrap();
        assert_eq!(
            status.status,
            CertStatus::Revoked {
                time: 1_790_812_800,
                reason: Some(1)
            }
        );
        let revoked = ocsp_findings(&chain(OTHER), Some(REVOKED), NOW);
        assert_eq!(revoked[0].id, "ocsp.revoked");
        assert_eq!(revoked[0].severity, Severity::Critical);
        assert_eq!(
            revoked[0].message,
            "certificate was revoked on Oct  1 00:00:00 2026 +00:00 (keyCompromise)"
        );
        assert_eq!(
            findings(STRAY, Some(UNKNOWN), NOW),
            [("ocsp.unknown".into(), Severity::Medium)]
        );
    }

    /// Responses outside their validity interval are flagged.
    #[test]
    fn freshness() {
        assert_eq!(
            findings(LEAF, Some(GOOD), BEFORE),
            [("ocsp.not_yet_valid".into(), Severity::Medium)]
        );
        assert_eq!(
            findings(LEAF, Some(GOOD), AFTER),
            [("ocsp.expired".into(), Severity::Medium)]
        );
    }

    /// Missing staples are informational unless the leaf is must-staple.
    #[test]
    fn missing_staple() {
        assert_eq!(
            findings(LEAF, None, NOW),
            [("ocsp.not_stapled".into(), Severity::Info)]
        );
        assert_eq!(
            findings(MUST_STAPLE, None, NOW),
            [("ocsp.must_staple_missing".into(), Severity::High)]
        );
    }

    /// Responses that do not verify are invalid.
    #[test]
    fn invalid_responses() {
        assert_eq!(error(GOOD, OTHER), "no response for the leaf certificate");
        assert_eq!(
            error(GOOD, MUST_STAPLE),
            "no response for the leaf certificate"
        );
        assert_eq!(
            error(UNAUTHORIZED, LEAF),
            "responder certificate is not authorised for OCSP signing"
        );
        assert_eq!(
            verify_ocsp_response(GOOD, &[LEAF.to_vec()], NOW).unwrap_err(),
            "issuer certificate missing from chain"
        );
        assert_eq!(
            verify_ocsp_response(GOOD, &[LEAF.to_vec(), OTHER.to_vec()], NOW).unwrap_err(),
            "no response for the leaf certificate"
        );
        let mut tampered = GOOD.to_vec();
        let produced_at = tampered.windows(8).position(|w| w == b"20261025").unwrap();
        tampered[produced_at + 3] = b'7';
        assert!(error(&tampered, LEAF).starts_with("signature does not verify"));
        assert_eq!(
            findings(LEAF, Some(&tampered), NOW),
            [("ocsp.invalid".into(), Severity::Medium)]
        );
    }

    /// Truncated, padded and non-successful responses are rejected without
    /// panicking.
    #[test]
    fn malformed_responses() {
        for len in 0..GOOD.len() {
            assert!(!error(&GOOD[..len], LEAF).is_empty(), "prefix {len}");
        }
        let mut padded = GOOD.to_vec();
        padded.push(0);
        assert_eq!(error(&padded, LEAF), "OCSPResponse has trailing data");
        assert_eq!(
            error(&[0x30, 0x03, 0x0a, 0x01, 0x03], LEAF),
            "responder status is tryLater"
        );
        assert_eq!(
            error(&[0x30, 0x81, 0x03, 0x0a, 0x01, 0x03], LEAF),
            "OCSPResponse has a non-minimal length"
        );
    }

    /// Reason codes map to their RFC 5280 names.
    #[test]
    fn reason_names() {
        assert_eq!(revocation_reason_name(1), "keyCompromise");
        assert_eq!(revocation_reason_name(7), "unknown reason");
    }
}
