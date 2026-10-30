//! Handshake feature probes behind several derived vulnerability checks.
//!
//! One hello at the highest TLS 1.2-or-earlier version offers DEFLATE
//! compression (CRIME, RFC 3749) and signals secure renegotiation
//! (RFC 5746). A second hello at a version below the server's best carries
//! `TLS_FALLBACK_SCSV`, which a protected server must refuse with an
//! `inappropriate_fallback` alert (RFC 7507, section 3). A third hello at
//! the server's best version offers only an unknown ALPN protocol, which a
//! strict server refuses with `no_application_protocol` (RFC 7301,
//! section 3.2); the ALPACA paper names strict ALPN as a countermeasure to
//! cross-protocol attacks. At TLS 1.3 the answer is encrypted, so that
//! probe is a full rustls handshake instead.

use rustls::AlertDescription;
use testls_wire::{Alert, ClientHello, Extension, ProtocolVersion, ServerHello, ext};

use crate::certificates::{connect_tls, tls13_client_config};
use crate::hello::{EMPTY_RENEGOTIATION_INFO_SCSV, FALLBACK_SCSV, client_hello};
use crate::{CipherResult, HelloResponse, ProbeError, Transport};

/// The DEFLATE compression method (RFC 3749, section 2).
const COMPRESSION_DEFLATE: u8 = 1;

/// ALPN extension body offering only `testls-unknown`, a protocol id no
/// server should know: a 15-byte list holding one 14-byte name
/// (RFC 7301, section 3.1).
const UNKNOWN_ALPN: &[u8] = b"\x00\x0f\x0etestls-unknown";

/// Handshake features found by [`probe_features`].
///
/// `None` means the feature could not be tested: the server supports no
/// suitable version, or refused the probe hello.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeFeatures {
    /// Version of the compression and renegotiation hello.
    pub legacy_version: Option<ProtocolVersion>,
    /// Whether the server agreed to DEFLATE compression.
    pub compression: Option<bool>,
    /// Whether the server answered with an empty `renegotiation_info`
    /// extension, as RFC 5746 (section 3.6) requires on an initial
    /// handshake.
    pub secure_renegotiation: Option<bool>,
    /// Version of the `TLS_FALLBACK_SCSV` hello, below the server's best.
    pub fallback_version: Option<ProtocolVersion>,
    /// Whether the server refused the fallback hello with
    /// `inappropriate_fallback`.
    pub fallback_scsv: Option<bool>,
    /// Whether the server refused a hello offering only an unknown ALPN
    /// protocol with `no_application_protocol`.
    pub strict_alpn: Option<bool>,
}

/// Send one hello and return the reply, treating a reset as a refusal.
async fn send(
    transport: &Transport,
    hello: &ClientHello,
) -> Result<Option<HelloResponse>, ProbeError> {
    let bytes = hello.encode().map_err(ProbeError::Encode)?;
    match transport.exchange(&bytes).await {
        Ok(r) => Ok(Some(r)),
        // Many servers reset instead of sending an alert.
        Err(ProbeError::Io(_)) => Ok(None),
        Err(e) => Err(e),
    }
}

/// The `ServerHello` in `response` if it completed at `version` with one of
/// `suites`.
fn accepted<'r>(
    version: ProtocolVersion,
    suites: &[u16],
    response: Option<&'r HelloResponse>,
) -> Result<Option<&'r ServerHello>, ProbeError> {
    let Some(HelloResponse::ServerHello { hello, .. }) = response else {
        return Ok(None);
    };
    if hello.is_hello_retry_request()
        || !suites.contains(&hello.cipher_suite)
        || hello.negotiated_version().map_err(ProbeError::Decode)? != version
    {
        return Ok(None);
    }
    Ok(Some(hello))
}

/// Suites of `result` that fit in a TLS hello.
fn suites_of(result: &CipherResult) -> Vec<u16> {
    result
        .suites
        .iter()
        .filter_map(|&s| u16::try_from(s).ok())
        .collect()
}

/// Probe compression, secure renegotiation, `TLS_FALLBACK_SCSV` and strict
/// ALPN.
///
/// `ciphers` are the results of
/// [`enumerate_ciphers`](crate::enumerate_ciphers) for every version the
/// server supports. Costs at most three connections.
///
/// # Errors
/// Returns a [`ProbeError`] if the compression and renegotiation probe fails
/// for reasons other than the server refusing the hello. A failed fallback
/// or ALPN probe only leaves `fallback_scsv` or `strict_alpn` unset.
pub async fn probe_features(
    transport: &Transport,
    ciphers: &[CipherResult],
    sni: Option<&str>,
) -> Result<HandshakeFeatures, ProbeError> {
    let mut supported: Vec<&CipherResult> = ciphers
        .iter()
        .filter(|c| c.version >= ProtocolVersion::SSL3 && !c.suites.is_empty())
        .collect();
    supported.sort_by_key(|c| std::cmp::Reverse(c.version));
    let mut features = HandshakeFeatures {
        legacy_version: None,
        compression: None,
        secure_renegotiation: None,
        fallback_version: None,
        fallback_scsv: None,
        strict_alpn: None,
    };

    if let Some(legacy) = supported
        .iter()
        .find(|c| c.version <= ProtocolVersion::TLS12)
    {
        let suites = suites_of(legacy);
        let mut offered = suites.clone();
        if legacy.version == ProtocolVersion::SSL3 {
            // SSLv3 hellos carry no extensions, so signal with the SCSV
            // instead (RFC 5746, section 3.3).
            offered.push(EMPTY_RENEGOTIATION_INFO_SCSV);
        }
        let mut hello = client_hello(legacy.version, offered, sni);
        hello.compression_methods = vec![COMPRESSION_DEFLATE, 0];
        let response = send(transport, &hello).await?;
        features.legacy_version = Some(legacy.version);
        if let Some(sh) = accepted(legacy.version, &suites, response.as_ref())? {
            features.compression = Some(sh.compression_method == COMPRESSION_DEFLATE);
            // An empty renegotiated_connection is a single zero length byte.
            features.secure_renegotiation =
                Some(sh.extension(ext::RENEGOTIATION_INFO) == Some(&[0][..]));
        }
    }

    if let [_, lower, ..] = supported.as_slice() {
        let mut offered = suites_of(lower);
        offered.push(FALLBACK_SCSV);
        // A failed fallback probe leaves the verdict untested without
        // discarding the compression and renegotiation results.
        let response = send(transport, &client_hello(lower.version, offered, sni))
            .await
            .ok()
            .flatten();
        features.fallback_version = Some(lower.version);
        features.fallback_scsv = match &response {
            Some(HelloResponse::Alert(a)) if a.description == Alert::INAPPROPRIATE_FALLBACK => {
                Some(true)
            }
            r => accepted(lower.version, &suites_of(lower), r.as_ref())
                .ok()
                .flatten()
                .map(|_| false),
        };
    }

    // SSLv3 hellos carry no extensions, so ALPN needs TLS.
    if let Some(best) = supported
        .first()
        .filter(|c| c.version > ProtocolVersion::SSL3)
    {
        features.strict_alpn = if best.version >= ProtocolVersion::TLS13 {
            tls13_strict_alpn(transport, sni).await
        } else {
            legacy_strict_alpn(transport, best, sni).await
        };
    }
    Ok(features)
}

/// Strict ALPN up to TLS 1.2, where the server answers ALPN in its
/// `ServerHello` (RFC 7301, section 3.1), so a raw hello at `best`'s
/// version shows the result.
async fn legacy_strict_alpn(
    transport: &Transport,
    best: &CipherResult,
    sni: Option<&str>,
) -> Option<bool> {
    let suites = suites_of(best);
    let mut hello = client_hello(best.version, suites.clone(), sni);
    hello.extensions.push(Extension::Raw {
        typ: ext::ALPN,
        data: UNKNOWN_ALPN.to_vec(),
    });
    match send(transport, &hello).await.ok().flatten() {
        Some(HelloResponse::Alert(a)) if a.description == Alert::NO_APPLICATION_PROTOCOL => {
            Some(true)
        }
        r => accepted(best.version, &suites, r.as_ref())
            .ok()
            .flatten()
            .map(|_| false),
    }
}

/// Strict ALPN over TLS 1.3, where the server's ALPN answer travels in the
/// encrypted `EncryptedExtensions` (RFC 8446, section 4.3.1) and a refusal
/// may follow the `ServerHello`, so only a full rustls handshake shows it.
///
/// `Some(true)` when the server sends `no_application_protocol`,
/// `Some(false)` when the handshake completes, `None` on any other failure.
async fn tls13_strict_alpn(transport: &Transport, sni: Option<&str>) -> Option<bool> {
    let mut config = tls13_client_config();
    config.alpn_protocols = vec![UNKNOWN_ALPN[3..].to_vec()];
    match connect_tls(transport, sni, config).await {
        Ok(_) => Some(false),
        Err(ProbeError::Io(e)) => {
            let refused = e
                .get_ref()
                .and_then(|inner| inner.downcast_ref::<rustls::Error>())
                .is_some_and(|e| {
                    *e == rustls::Error::AlertReceived(AlertDescription::NoApplicationProtocol)
                });
            refused.then_some(true)
        }
        Err(_) => None,
    }
}

#[cfg(test)]
mod tests {
    //! Mock-server tests for the feature probes.
    use super::*;
    use crate::CipherOrder;
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// How the mock server behaves.
    #[derive(Debug, Clone, Copy)]
    struct Behaviour {
        /// Accept DEFLATE when offered.
        deflate: bool,
        /// `renegotiation_info` body to send back, if any.
        renegotiation: Option<&'static [u8]>,
        /// Refuse hellos carrying `TLS_FALLBACK_SCSV`.
        fallback: bool,
        /// Refuse hellos offering an unknown ALPN protocol.
        alpn: bool,
    }

    /// Cipher suites and compression methods of a `ClientHello` record.
    fn parse_hello(record: &[u8]) -> (u16, Vec<u16>, Vec<u8>) {
        let u16_at = |i: usize| u16::from_be_bytes([record[i], record[i + 1]]);
        let version = u16_at(9);
        let mut i = 5 + 4 + 2 + 32;
        i += 1 + usize::from(record[i]);
        let len = usize::from(u16_at(i));
        let suites = record[i + 2..i + 2 + len]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&c| u16::from_be_bytes(c))
            .collect();
        i += 2 + len;
        let methods = record[i + 1..=i + usize::from(record[i])].to_vec();
        (version, suites, methods)
    }

    /// Reply to one hello as `behaviour` describes, with the first suite.
    fn reply(hello: &[u8], behaviour: Behaviour) -> Vec<u8> {
        let (version, suites, methods) = parse_hello(hello);
        if behaviour.fallback && suites.contains(&FALLBACK_SCSV) {
            return vec![21, 3, 3, 0, 2, 2, Alert::INAPPROPRIATE_FALLBACK];
        }
        if behaviour.alpn && hello.windows(UNKNOWN_ALPN.len()).any(|w| w == UNKNOWN_ALPN) {
            return vec![21, 3, 3, 0, 2, 2, Alert::NO_APPLICATION_PROTOCOL];
        }
        let mut body = version.to_be_bytes().to_vec();
        body.extend([7; 32]);
        body.push(0);
        body.extend(suites[0].to_be_bytes());
        body.push(u8::from(
            behaviour.deflate && methods.contains(&COMPRESSION_DEFLATE),
        ));
        let mut exts = Vec::new();
        // An SSLv3 hello has no extensions; only the SCSV earns a reply
        // (RFC 5746 §4.5).
        let ssl3 = version == 0x0300;
        if let Some(info) = behaviour
            .renegotiation
            .filter(|_| !ssl3 || suites.contains(&EMPTY_RENEGOTIATION_INFO_SCSV))
        {
            exts.extend([0xff, 0x01]);
            exts.extend(u16::try_from(info.len()).unwrap().to_be_bytes());
            exts.extend(info);
        }
        body.extend(u16::try_from(exts.len()).unwrap().to_be_bytes());
        body.extend(&exts);
        let mut hs = vec![2, 0];
        hs.extend(u16::try_from(body.len()).unwrap().to_be_bytes());
        hs.extend(body);
        hs.extend([14, 0, 0, 0]);
        let mut rec = vec![22, 3, 3];
        rec.extend(u16::try_from(hs.len()).unwrap().to_be_bytes());
        rec.extend(hs);
        rec
    }

    /// Serve hellos forever, replying as described in [`reply`].
    async fn serve(behaviour: Behaviour) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = listener.accept().await.unwrap();
                let mut buf = vec![0; 1 << 16];
                let mut n = 0;
                while n < 5 || n < 5 + usize::from(u16::from_be_bytes([buf[3], buf[4]])) {
                    n += s.read(&mut buf[n..]).await.unwrap();
                }
                s.write_all(&reply(&buf[..n], behaviour)).await.unwrap();
            }
        });
        addr
    }

    /// Cipher results for TLS 1.1 and TLS 1.2 with one suite each.
    fn two_versions() -> Vec<CipherResult> {
        [ProtocolVersion::TLS11, ProtocolVersion::TLS12]
            .into_iter()
            .map(|version| CipherResult {
                version,
                suites: vec![0xc013],
                order: CipherOrder::NotApplicable,
            })
            .collect()
    }

    /// A well-configured server: no compression, RFC 5746, RFC 7507.
    #[tokio::test]
    async fn protected_server() {
        let addr = serve(Behaviour {
            deflate: false,
            renegotiation: Some(&[0]),
            fallback: true,
            alpn: true,
        })
        .await;
        let f = probe_features(&Transport::new(addr), &two_versions(), None)
            .await
            .unwrap();
        assert_eq!(f.legacy_version, Some(ProtocolVersion::TLS12));
        assert_eq!(f.compression, Some(false));
        assert_eq!(f.secure_renegotiation, Some(true));
        assert_eq!(f.fallback_version, Some(ProtocolVersion::TLS11));
        assert_eq!(f.fallback_scsv, Some(true));
        assert_eq!(f.strict_alpn, Some(true));
    }

    /// A server with compression, no RFC 5746 and no fallback protection.
    #[tokio::test]
    async fn unprotected_server() {
        let addr = serve(Behaviour {
            deflate: true,
            renegotiation: None,
            fallback: false,
            alpn: false,
        })
        .await;
        let f = probe_features(&Transport::new(addr), &two_versions(), None)
            .await
            .unwrap();
        assert_eq!(f.compression, Some(true));
        assert_eq!(f.secure_renegotiation, Some(false));
        assert_eq!(f.fallback_scsv, Some(false));
        assert_eq!(f.strict_alpn, Some(false));
    }

    /// A malformed or non-empty `renegotiation_info` on an initial
    /// handshake does not count as secure renegotiation.
    #[tokio::test]
    async fn non_empty_renegotiation_info() {
        for info in [&[][..], &[1, 0xaa][..], &[0, 0][..]] {
            let addr = serve(Behaviour {
                deflate: false,
                renegotiation: Some(info),
                fallback: true,
                alpn: true,
            })
            .await;
            let f = probe_features(&Transport::new(addr), &two_versions(), None)
                .await
                .unwrap();
            assert_eq!(f.secure_renegotiation, Some(false), "{info:?}");
        }
    }

    /// A fallback probe that cannot connect keeps the compression and
    /// renegotiation results and leaves only the fallback verdict open.
    #[tokio::test]
    async fn fallback_failure_keeps_results() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = vec![0; 1 << 16];
            let mut n = 0;
            while n < 5 || n < 5 + usize::from(u16::from_be_bytes([buf[3], buf[4]])) {
                n += s.read(&mut buf[n..]).await.unwrap();
            }
            let behaviour = Behaviour {
                deflate: false,
                renegotiation: Some(&[0]),
                fallback: true,
                alpn: true,
            };
            s.write_all(&reply(&buf[..n], behaviour)).await.unwrap();
            // Dropping the listener refuses the fallback connection.
        });
        let f = probe_features(&Transport::new(addr), &two_versions(), None)
            .await
            .unwrap();
        assert_eq!(f.compression, Some(false));
        assert_eq!(f.secure_renegotiation, Some(true));
        assert_eq!(f.fallback_version, Some(ProtocolVersion::TLS11));
        assert_eq!(f.fallback_scsv, None);
        assert_eq!(f.strict_alpn, None);
    }

    /// Runs a TLS 1.3 server that accepts handshakes forever, with
    /// `alpn` as its ALPN protocols (none means ALPN is ignored).
    async fn serve_tls13(alpn: &[&[u8]]) -> SocketAddr {
        use rustls::ServerConfig;
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        use std::sync::Arc;
        use tokio_rustls::TlsAcceptor;

        let mut config =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    vec![CertificateDer::from(
                        include_bytes!("testdata/localhost.cert.der").to_vec(),
                    )],
                    PrivateKeyDer::try_from(include_bytes!("testdata/localhost.key.der").to_vec())
                        .unwrap(),
                )
                .unwrap();
        config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (s, _) = listener.accept().await.unwrap();
                let _ = acceptor.accept(s).await;
            }
        });
        addr
    }

    /// TLS 1.3 ALPN is read from a full handshake: a refusal after the
    /// `ServerHello` counts as strict, a completed handshake as not.
    #[tokio::test]
    async fn tls13_alpn() {
        let tls13 = [CipherResult {
            version: ProtocolVersion::TLS13,
            suites: vec![0x1301],
            order: CipherOrder::NotApplicable,
        }];
        for (alpn, expected) in [(&[&b"h2"[..]][..], true), (&[][..], false)] {
            let addr = serve_tls13(alpn).await;
            let f = probe_features(&Transport::new(addr), &tls13, Some("localhost"))
                .await
                .unwrap();
            assert_eq!(f.strict_alpn, Some(expected), "{alpn:?}");
        }
    }

    /// A TLS 1.3 server that drops the connection mid-handshake leaves the
    /// ALPN verdict untested.
    #[tokio::test]
    async fn tls13_alpn_failure() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut buf = [0u8; 512];
                let _ = stream.read(&mut buf).await;
            }
        });
        let tls13 = [CipherResult {
            version: ProtocolVersion::TLS13,
            suites: vec![0x1301],
            order: CipherOrder::NotApplicable,
        }];
        let f = probe_features(&Transport::new(addr), &tls13, Some("localhost"))
            .await
            .unwrap();
        assert_eq!(f.strict_alpn, None);
    }

    /// An SSLv3 hello signals secure renegotiation with the SCSV, since it
    /// carries no extensions.
    #[tokio::test]
    async fn ssl3_renegotiation_scsv() {
        let addr = serve(Behaviour {
            deflate: false,
            renegotiation: Some(&[0]),
            fallback: true,
            alpn: true,
        })
        .await;
        let ssl3 = [CipherResult {
            version: ProtocolVersion::SSL3,
            suites: vec![0x000a],
            order: CipherOrder::NotApplicable,
        }];
        let f = probe_features(&Transport::new(addr), &ssl3, None)
            .await
            .unwrap();
        assert_eq!(f.legacy_version, Some(ProtocolVersion::SSL3));
        assert_eq!(f.compression, Some(false));
        assert_eq!(f.secure_renegotiation, Some(true));
    }

    /// A connection reset counts as a refused hello, leaving the verdicts
    /// untested instead of failing the probe.
    #[tokio::test]
    async fn reset_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = listener.accept().await.unwrap();
                let mut first = [0; 1];
                let _ = s.read_exact(&mut first).await;
                // Closing with unread data makes the kernel send a reset.
                drop(s);
            }
        });
        let f = probe_features(&Transport::new(addr), &two_versions(), None)
            .await
            .unwrap();
        assert_eq!(f.legacy_version, Some(ProtocolVersion::TLS12));
        assert_eq!(f.compression, None);
        assert_eq!(f.secure_renegotiation, None);
    }

    /// A `ServerHello` with a suite or version other than offered is not
    /// an acceptance (RFC 5246 §7.4.1.3; suite IDs from the IANA TLS
    /// Cipher Suites registry).
    #[test]
    fn mismatched_server_hello() {
        let response = HelloResponse::ServerHello {
            hello: ServerHello {
                legacy_version: ProtocolVersion::TLS12,
                random: [1; 32],
                session_id: vec![],
                cipher_suite: 0xc013,
                compression_method: 0,
                extensions: vec![],
            },
            certificates: vec![],
            server_key_exchange: None,
        };
        let v = ProtocolVersion::TLS12;
        assert!(accepted(v, &[0xc013], Some(&response)).unwrap().is_some());
        assert!(accepted(v, &[0xc014], Some(&response)).unwrap().is_none());
        let v11 = ProtocolVersion::TLS11;
        assert!(accepted(v11, &[0xc013], Some(&response)).unwrap().is_none());
    }

    /// With a single version there is nothing to fall back from, and a
    /// TLS 1.3-only server has no legacy hello to send.
    #[tokio::test]
    async fn not_tested() {
        let unreachable = Transport::new("127.0.0.1:9".parse().unwrap());
        let tls13 = [CipherResult {
            version: ProtocolVersion::TLS13,
            suites: vec![0x1301],
            order: CipherOrder::NotApplicable,
        }];
        let f = probe_features(&unreachable, &tls13, None).await.unwrap();
        assert_eq!(f.legacy_version, None);
        assert_eq!(f.compression, None);
        assert_eq!(f.fallback_version, None);
        assert_eq!(f.fallback_scsv, None);
        assert_eq!(f.strict_alpn, None);
        let none = probe_features(&unreachable, &[], None).await.unwrap();
        assert_eq!(none.secure_renegotiation, None);
        assert_eq!(none.strict_alpn, None);
    }
}
