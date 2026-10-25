//! Handshake feature probes behind several derived vulnerability checks.
//!
//! One hello at the highest TLS 1.2-or-earlier version offers DEFLATE
//! compression (CRIME, RFC 3749) and signals secure renegotiation
//! (RFC 5746). A second hello at a version below the server's best carries
//! `TLS_FALLBACK_SCSV`, which a protected server must refuse with an
//! `inappropriate_fallback` alert (RFC 7507, section 3).

use testls_wire::{Alert, ClientHello, ProtocolVersion, ServerHello, ext};

use crate::hello::{EMPTY_RENEGOTIATION_INFO_SCSV, FALLBACK_SCSV, client_hello};
use crate::{CipherResult, HelloResponse, ProbeError, Transport};

/// The DEFLATE compression method (RFC 3749, section 2).
const COMPRESSION_DEFLATE: u8 = 1;

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

/// Probe compression, secure renegotiation and `TLS_FALLBACK_SCSV`.
///
/// `ciphers` are the results of
/// [`enumerate_ciphers`](crate::enumerate_ciphers) for every version the
/// server supports. Costs at most two connections.
///
/// # Errors
/// Returns a [`ProbeError`] if the compression and renegotiation probe fails
/// for reasons other than the server refusing the hello. A failed fallback
/// probe only leaves `fallback_scsv` unset.
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
    Ok(features)
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
        let mut body = version.to_be_bytes().to_vec();
        body.extend([7; 32]);
        body.push(0);
        body.extend(suites[0].to_be_bytes());
        body.push(u8::from(
            behaviour.deflate && methods.contains(&COMPRESSION_DEFLATE),
        ));
        let mut exts = Vec::new();
        if let Some(info) = behaviour.renegotiation {
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
    }

    /// A server with compression, no RFC 5746 and no fallback protection.
    #[tokio::test]
    async fn unprotected_server() {
        let addr = serve(Behaviour {
            deflate: true,
            renegotiation: None,
            fallback: false,
        })
        .await;
        let f = probe_features(&Transport::new(addr), &two_versions(), None)
            .await
            .unwrap();
        assert_eq!(f.compression, Some(true));
        assert_eq!(f.secure_renegotiation, Some(false));
        assert_eq!(f.fallback_scsv, Some(false));
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
        let none = probe_features(&unreachable, &[], None).await.unwrap();
        assert_eq!(none.secure_renegotiation, None);
    }
}
