//! `ClientHello` intolerance probes.
//!
//! A baseline hello at the server's best version must complete first. Each
//! probe then sends the same hello with one twist that a conforming server
//! must ignore or accept: an unknown future version, an unknown extension,
//! GREASE values (RFC 8701), a hello filling a whole record, and a hello
//! split across many small records (RFC 8446, section 5.1).

use testls_wire::{ClientHello, Extension, KeyShareEntry, MAX_FRAGMENT_LEN, ProtocolVersion, ext};

use crate::hello::client_hello;
use crate::{CipherResult, HelloResponse, ProbeError, Transport};

/// An unassigned protocol version above TLS 1.3.
const FUTURE_VERSION: ProtocolVersion = ProtocolVersion(0x0305);
/// An extension type in an unassigned range of the IANA "TLS
/// `ExtensionType` Values" registry.
const UNKNOWN_EXTENSION: u16 = 0x0800;
/// Record fragment size of the fragmented hello.
const FRAGMENT_LEN: usize = 16;
/// GREASE values used per field (RFC 8701, section 2).
const GREASE_SUITE: u16 = 0x0a0a;
/// GREASE extension sent empty.
const GREASE_EXTENSION_EMPTY: u16 = 0x1a1a;
/// GREASE extension sent with one byte of data.
const GREASE_EXTENSION_DATA: u16 = 0x2a2a;
/// GREASE named group, also used in `key_share`.
const GREASE_GROUP: u16 = 0x3a3a;
/// GREASE signature scheme.
const GREASE_SIGNATURE: u16 = 0x4a4a;
/// GREASE version in `supported_versions`.
const GREASE_VERSION: ProtocolVersion = ProtocolVersion(0x5a5a);

/// How the server handled each unusual hello.
///
/// `Some(true)` means the handshake completed as with the baseline hello,
/// `Some(false)` that the server refused, reset, stalled or misbehaved, and
/// `None` that the probe could not run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Intolerance {
    /// Version of the baseline hello, the best the server supports.
    pub version: Option<ProtocolVersion>,
    /// Hello offering an unknown version above TLS 1.3.
    pub unknown_version: Option<bool>,
    /// Hello with an extension of an unassigned type.
    pub unknown_extension: Option<bool>,
    /// Hello with GREASE suites, extensions, groups, signature schemes and,
    /// for TLS 1.3, versions and key shares.
    pub grease: Option<bool>,
    /// Hello padded to fill a whole record (RFC 7685 padding).
    pub oversized: Option<bool>,
    /// Hello split across records of a few bytes each.
    pub fragmented: Option<bool>,
}

impl Intolerance {
    /// A result with nothing tested.
    fn untested(version: Option<ProtocolVersion>) -> Self {
        Self {
            version,
            unknown_version: None,
            unknown_extension: None,
            grease: None,
            oversized: None,
            fragmented: None,
        }
    }
}

/// Whether `response` completes a handshake at `version` with one of
/// `suites`; a `HelloRetryRequest` at `version` also counts.
fn completes(
    version: ProtocolVersion,
    suites: &[u16],
    response: &HelloResponse,
) -> Result<bool, ProbeError> {
    let HelloResponse::ServerHello { hello, .. } = response else {
        return Ok(false);
    };
    Ok(
        hello.negotiated_version().map_err(ProbeError::Decode)? == version
            && (hello.is_hello_retry_request() || suites.contains(&hello.cipher_suite)),
    )
}

/// Send encoded hello `bytes` and judge the reply.
///
/// Connect failures leave the probe untested; resets, timeouts and
/// malformed replies count as intolerance.
async fn attempt(
    transport: &Transport,
    bytes: &[u8],
    version: ProtocolVersion,
    suites: &[u16],
) -> Option<bool> {
    match transport.exchange(bytes).await {
        Ok(response) => Some(completes(version, suites, &response).unwrap_or(false)),
        Err(ProbeError::Connect(_)) => None,
        Err(_) => Some(false),
    }
}

/// `hello` offering [`FUTURE_VERSION`] as well.
fn with_unknown_version(mut hello: ClientHello) -> ClientHello {
    let mut listed = false;
    for e in &mut hello.extensions {
        if let Extension::SupportedVersions(v) = e {
            v.insert(0, FUTURE_VERSION);
            listed = true;
        }
    }
    if !listed {
        hello.version = FUTURE_VERSION;
    }
    hello
}

/// `hello` with an extension of type [`UNKNOWN_EXTENSION`].
fn with_unknown_extension(mut hello: ClientHello) -> ClientHello {
    hello.extensions.push(Extension::Raw {
        typ: UNKNOWN_EXTENSION,
        data: vec![0; 4],
    });
    hello
}

/// `hello` with GREASE values in every field that allows them
/// (RFC 8701, section 3.1).
fn with_grease(mut hello: ClientHello) -> ClientHello {
    hello.cipher_suites.insert(0, GREASE_SUITE);
    for e in &mut hello.extensions {
        match e {
            Extension::SupportedGroups(g) => g.insert(0, GREASE_GROUP),
            Extension::SignatureAlgorithms(s) => s.insert(0, GREASE_SIGNATURE),
            Extension::SupportedVersions(v) => v.insert(0, GREASE_VERSION),
            Extension::KeyShare(k) => k.insert(
                0,
                KeyShareEntry {
                    group: GREASE_GROUP,
                    key_exchange: vec![0],
                },
            ),
            _ => {}
        }
    }
    hello.extensions.insert(
        0,
        Extension::Raw {
            typ: GREASE_EXTENSION_EMPTY,
            data: Vec::new(),
        },
    );
    hello.extensions.push(Extension::Raw {
        typ: GREASE_EXTENSION_DATA,
        data: vec![0],
    });
    hello
}

/// `hello` padded so the handshake message fills a whole record.
fn padded(mut hello: ClientHello) -> Result<ClientHello, ProbeError> {
    let len = hello.encode_handshake().map_err(ProbeError::Encode)?.len();
    // Four bytes of extension type and length precede the padding.
    let pad = MAX_FRAGMENT_LEN.saturating_sub(len + 4);
    hello.extensions.push(Extension::Raw {
        typ: ext::PADDING,
        data: vec![0; pad],
    });
    Ok(hello)
}

/// Suites of `result` that fit in a TLS hello.
fn suites_of(result: &CipherResult) -> Vec<u16> {
    result
        .suites
        .iter()
        .filter_map(|&s| u16::try_from(s).ok())
        .collect()
}

/// Probe how the server copes with unusual but valid hellos.
///
/// `ciphers` are the results of
/// [`enumerate_ciphers`](crate::enumerate_ciphers) for every version the
/// server supports; the best TLS version with accepted suites is used.
/// Costs at most six connections.
///
/// # Errors
/// Returns a [`ProbeError`] if the baseline hello cannot be encoded or sent.
/// A refused baseline leaves every probe untested.
pub async fn probe_intolerance(
    transport: &Transport,
    ciphers: &[CipherResult],
    sni: Option<&str>,
) -> Result<Intolerance, ProbeError> {
    let Some(best) = ciphers
        .iter()
        .filter(|c| c.version >= ProtocolVersion::TLS10 && !c.suites.is_empty())
        .max_by_key(|c| c.version)
    else {
        return Ok(Intolerance::untested(None));
    };
    let version = best.version;
    let suites = suites_of(best);
    let base = client_hello(version, suites.clone(), sni);
    let encode = |hello: &ClientHello| hello.encode().map_err(ProbeError::Encode);

    let response = transport.exchange(&encode(&base)?).await?;
    if !completes(version, &suites, &response)? {
        return Ok(Intolerance::untested(Some(version)));
    }

    let unknown_version = encode(&with_unknown_version(base.clone()))?;
    let unknown_extension = encode(&with_unknown_extension(base.clone()))?;
    let grease = encode(&with_grease(base.clone()))?;
    let oversized = encode(&padded(base.clone())?)?;
    let fragmented = base
        .encode_fragmented(FRAGMENT_LEN)
        .map_err(ProbeError::Encode)?;
    Ok(Intolerance {
        version: Some(version),
        unknown_version: attempt(transport, &unknown_version, version, &suites).await,
        unknown_extension: attempt(transport, &unknown_extension, version, &suites).await,
        grease: attempt(transport, &grease, version, &suites).await,
        oversized: attempt(transport, &oversized, version, &suites).await,
        fragmented: attempt(transport, &fragmented, version, &suites).await,
    })
}

#[cfg(test)]
mod tests {
    //! Mock-server tests for the intolerance probes.
    use super::*;
    use crate::CipherOrder;
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// What the mock server refuses.
    #[derive(Debug, Clone, Copy)]
    enum Quirk {
        /// Refuse nothing.
        None,
        /// Refuse versions above TLS 1.3.
        FutureVersion,
        /// Refuse unknown extension types.
        UnknownExtension,
        /// Refuse GREASE values.
        Grease,
        /// Refuse handshake messages longer than this.
        MaxLen(usize),
        /// Refuse hellos spread over several records.
        Fragments,
        /// Refuse everything.
        All,
    }

    /// A decoded `ClientHello`.
    #[derive(Debug)]
    struct Hello {
        /// `legacy_version`.
        version: u16,
        /// Offered suites.
        suites: Vec<u16>,
        /// Extension types and bodies.
        extensions: Vec<(u16, Vec<u8>)>,
        /// Handshake message length.
        len: usize,
        /// Number of records carrying it.
        records: usize,
    }

    /// Whether `v` is a GREASE value (RFC 8701, section 2).
    fn is_grease(v: u16) -> bool {
        v & 0x0f0f == 0x0a0a && v >> 8 == v & 0xff
    }

    /// Read records from `s` until one whole hello has arrived.
    async fn read_hello(s: &mut tokio::net::TcpStream) -> Hello {
        let mut raw = Vec::new();
        let mut hs = Vec::new();
        let mut records = 0;
        let mut buf = [0; 4096];
        loop {
            while raw.len() >= 5 {
                let len = usize::from(u16::from_be_bytes([raw[3], raw[4]]));
                if raw.len() < 5 + len {
                    break;
                }
                hs.extend_from_slice(&raw[5..5 + len]);
                raw.drain(..5 + len);
                records += 1;
            }
            if hs.len() >= 4 {
                let len = usize::from(hs[1]) << 16 | usize::from(hs[2]) << 8 | usize::from(hs[3]);
                if hs.len() >= 4 + len {
                    return decode(&hs[4..4 + len], records);
                }
            }
            let n = s.read(&mut buf).await.unwrap();
            assert!(n > 0, "client closed early");
            raw.extend_from_slice(&buf[..n]);
        }
    }

    /// Decode a `ClientHello` body.
    fn decode(body: &[u8], records: usize) -> Hello {
        let u16_at = |i: usize| u16::from_be_bytes([body[i], body[i + 1]]);
        let mut i = 2 + 32;
        i += 1 + usize::from(body[i]);
        let n = usize::from(u16_at(i));
        let suites = body[i + 2..i + 2 + n]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&c| u16::from_be_bytes(c))
            .collect();
        i += 2 + n;
        i += 1 + usize::from(body[i]);
        let mut extensions = Vec::new();
        if i < body.len() {
            let end = i + 2 + usize::from(u16_at(i));
            i += 2;
            while i < end {
                let len = usize::from(u16_at(i + 2));
                extensions.push((u16_at(i), body[i + 4..i + 4 + len].to_vec()));
                i += 4 + len;
            }
        }
        Hello {
            version: u16_at(0),
            suites,
            extensions,
            len: body.len() + 4,
            records,
        }
    }

    /// Whether `hello` trips `quirk`.
    fn refused(hello: &Hello, quirk: Quirk) -> bool {
        let known = [0, 10, 11, 13, 21, 43, 51, 0xff01];
        let versions: Vec<u16> = hello
            .extensions
            .iter()
            .filter(|(t, _)| *t == ext::SUPPORTED_VERSIONS)
            .flat_map(|(_, d)| {
                d[1..]
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|&c| u16::from_be_bytes(c))
                    .collect::<Vec<_>>()
            })
            .collect();
        let future =
            hello.version > 0x0304 || versions.iter().any(|&v| v > 0x0304 && !is_grease(v));
        let unknown = hello
            .extensions
            .iter()
            .any(|(t, _)| !known.contains(t) && !is_grease(*t));
        let grease = hello.suites.iter().any(|&s| is_grease(s))
            || hello.extensions.iter().any(|(t, _)| is_grease(*t));
        match quirk {
            Quirk::None => false,
            Quirk::FutureVersion => future,
            Quirk::UnknownExtension => unknown,
            Quirk::Grease => grease,
            Quirk::MaxLen(m) => hello.len > m,
            Quirk::Fragments => hello.records > 1,
            Quirk::All => true,
        }
    }

    /// A `ServerHello` (plus `ServerHelloDone` below TLS 1.3) for `hello`.
    fn reply(hello: &Hello) -> Vec<u8> {
        let tls13 = hello
            .extensions
            .iter()
            .any(|(t, _)| *t == ext::SUPPORTED_VERSIONS);
        let suite = *hello.suites.iter().find(|&&s| !is_grease(s)).unwrap();
        let mut body = 0x0303u16.min(hello.version).to_be_bytes().to_vec();
        body.extend([7; 32]);
        body.push(0);
        body.extend(suite.to_be_bytes());
        body.push(0);
        let exts: Vec<u8> = if tls13 {
            vec![0, 43, 0, 2, 3, 4]
        } else {
            Vec::new()
        };
        body.extend(u16::try_from(exts.len()).unwrap().to_be_bytes());
        body.extend(&exts);
        let mut hs = vec![2, 0];
        hs.extend(u16::try_from(body.len()).unwrap().to_be_bytes());
        hs.extend(body);
        if !tls13 {
            hs.extend([14, 0, 0, 0]);
        }
        let mut rec = vec![22, 3, 3];
        rec.extend(u16::try_from(hs.len()).unwrap().to_be_bytes());
        rec.extend(hs);
        rec
    }

    /// Serve hellos forever, refusing those that trip `quirk`.
    async fn serve(quirk: Quirk) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = listener.accept().await.unwrap();
                let hello = read_hello(&mut s).await;
                let out = if refused(&hello, quirk) {
                    vec![21, 3, 3, 0, 2, 2, 40]
                } else {
                    reply(&hello)
                };
                s.write_all(&out).await.unwrap();
            }
        });
        addr
    }

    /// Cipher results for one version and suite.
    fn ciphers(version: ProtocolVersion, suite: u32) -> Vec<CipherResult> {
        vec![CipherResult {
            version,
            suites: vec![suite],
            order: CipherOrder::NotApplicable,
        }]
    }

    /// Probe a mock server with `quirk` at `version`.
    async fn probe(quirk: Quirk, version: ProtocolVersion, suite: u32) -> Intolerance {
        let addr = serve(quirk).await;
        probe_intolerance(&Transport::new(addr), &ciphers(version, suite), None)
            .await
            .unwrap()
    }

    /// A tolerant server completes every probe, at TLS 1.2 and TLS 1.3.
    #[tokio::test]
    async fn tolerant_server() {
        for (version, suite) in [
            (ProtocolVersion::TLS12, 0xc02f),
            (ProtocolVersion::TLS13, 0x1301),
        ] {
            let r = probe(Quirk::None, version, suite).await;
            assert_eq!(
                r,
                Intolerance {
                    version: Some(version),
                    unknown_version: Some(true),
                    unknown_extension: Some(true),
                    grease: Some(true),
                    oversized: Some(true),
                    fragmented: Some(true),
                },
                "{version}"
            );
        }
    }

    /// Each quirk shows up as exactly one intolerance.
    #[tokio::test]
    async fn single_quirks() {
        let tls12 = (ProtocolVersion::TLS12, 0xc02f);
        let tls13 = (ProtocolVersion::TLS13, 0x1301);
        for (quirk, (version, suite)) in [
            (Quirk::FutureVersion, tls12),
            (Quirk::FutureVersion, tls13),
            (Quirk::UnknownExtension, tls12),
            (Quirk::Grease, tls12),
            (Quirk::Grease, tls13),
            (Quirk::MaxLen(512), tls12),
            (Quirk::Fragments, tls12),
        ] {
            let r = probe(quirk, version, suite).await;
            let failed = [
                r.unknown_version,
                r.unknown_extension,
                r.grease,
                r.oversized,
                r.fragmented,
            ];
            let expected = match quirk {
                Quirk::FutureVersion => 0,
                Quirk::UnknownExtension => 1,
                Quirk::Grease => 2,
                Quirk::MaxLen(_) => 3,
                _ => 4,
            };
            for (i, result) in failed.iter().enumerate() {
                assert_eq!(*result, Some(i != expected), "{quirk:?} {version} {i}");
            }
        }
    }

    /// A refused baseline or missing ciphers leave everything untested.
    #[tokio::test]
    async fn untested() {
        let r = probe(Quirk::All, ProtocolVersion::TLS12, 0xc02f).await;
        assert_eq!(r, Intolerance::untested(Some(ProtocolVersion::TLS12)));
        let unreachable = Transport::new("127.0.0.1:9".parse().unwrap());
        let ssl3 = ciphers(ProtocolVersion::SSL3, 0x000a);
        let r = probe_intolerance(&unreachable, &ssl3, None).await.unwrap();
        assert_eq!(r, Intolerance::untested(None));
    }

    /// The padded hello fills exactly one record.
    #[test]
    fn padding_fills_a_record() {
        let hello = padded(client_hello(
            ProtocolVersion::TLS12,
            vec![0xc02f],
            Some("a.example"),
        ))
        .unwrap();
        assert_eq!(hello.encode_handshake().unwrap().len(), MAX_FRAGMENT_LEN);
        assert_eq!(hello.encode().unwrap().len(), MAX_FRAGMENT_LEN + 5);
    }
}
