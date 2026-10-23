//! Cipher suite enumeration and server preference detection.

use testls_wire::ProtocolVersion;

use crate::hello::{
    SSL2_CIPHER_SPECS, client_hello, legacy_suites, ssl2_client_hello, tls13_suites,
};
use crate::{HelloResponse, ProbeError, Transport};

/// Who decides which cipher suite is used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherOrder {
    /// The server picks from its own preference list.
    Server,
    /// The server follows the client's order.
    Client,
    /// Fewer than two suites are accepted, so there is nothing to order.
    NotApplicable,
}

/// Cipher suites accepted for one protocol version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CipherResult {
    /// Version the suites were offered with.
    pub version: ProtocolVersion,
    /// Accepted suites. In server preference order when `order` is
    /// [`CipherOrder::Server`]. SSLv2 cipher specs are widened to `u32`.
    pub suites: Vec<u32>,
    /// Whether the server enforces its own order.
    pub order: CipherOrder,
}

/// Outcome of one hello offering `suites`.
fn selected_suite(
    version: ProtocolVersion,
    offered: &[u16],
    response: &HelloResponse,
) -> Result<Option<u16>, ProbeError> {
    let HelloResponse::ServerHello { hello, .. } = response else {
        return Ok(None);
    };
    if hello.is_hello_retry_request() {
        // Our x25519 share was not acceptable; the suite choice in an HRR
        // is still binding for the connection.
        return Ok(offered
            .contains(&hello.cipher_suite)
            .then_some(hello.cipher_suite));
    }
    match hello.negotiated_version() {
        Ok(v) if v == version && offered.contains(&hello.cipher_suite) => {
            Ok(Some(hello.cipher_suite))
        }
        Ok(_) => Ok(None),
        Err(e) => Err(ProbeError::Decode(e)),
    }
}

async fn offer(
    transport: &Transport,
    version: ProtocolVersion,
    suites: &[u16],
    sni: Option<&str>,
) -> Result<Option<u16>, ProbeError> {
    let bytes = client_hello(version, suites.to_vec(), sni)
        .encode()
        .map_err(ProbeError::Encode)?;
    let response = match transport.exchange(&bytes).await {
        Ok(r) => r,
        // Many servers reset instead of sending handshake_failure.
        Err(ProbeError::Io(_)) => return Ok(None),
        Err(e) => return Err(e),
    };
    selected_suite(version, suites, &response)
}

/// Repeatedly offer `candidates`, removing the selected suite each time,
/// until the server refuses. Returns suites in selection order.
async fn drain(
    transport: &Transport,
    version: ProtocolVersion,
    mut candidates: Vec<u16>,
    sni: Option<&str>,
) -> Result<Vec<u16>, ProbeError> {
    let mut accepted = Vec::new();
    while !candidates.is_empty() {
        let Some(suite) = offer(transport, version, &candidates, sni).await? else {
            break;
        };
        candidates.retain(|&c| c != suite);
        accepted.push(suite);
    }
    Ok(accepted)
}

/// Enumerate every cipher suite the server accepts at `version` and
/// determine whether it enforces its own preference order.
///
/// For TLS this costs one connection per accepted suite plus two. The
/// selection order of the enumeration is the server's preference order
/// whenever the server enforces one, so no extra pass is needed.
///
/// # Errors
/// Returns a [`ProbeError`] if a probe fails for reasons other than the
/// server refusing the hello.
pub async fn enumerate_ciphers(
    transport: &Transport,
    version: ProtocolVersion,
    sni: Option<&str>,
) -> Result<CipherResult, ProbeError> {
    if version == ProtocolVersion::SSL2 {
        return enumerate_ssl2(transport).await;
    }
    let candidates = if version >= ProtocolVersion::TLS13 {
        tls13_suites()
    } else {
        legacy_suites()
    };
    let accepted = drain(transport, version, candidates, sni).await?;
    let order = match accepted.as_slice() {
        [] | [_] => CipherOrder::NotApplicable,
        [first, .., last] => {
            let mut reversed = accepted.clone();
            reversed.reverse();
            match offer(transport, version, &reversed, sni).await? {
                Some(s) if s == *first => CipherOrder::Server,
                Some(s) if s == *last => CipherOrder::Client,
                // Neither end of the list: the server does something
                // else (e.g. prefers ChaCha for non-AES clients). Its own
                // choice wins, so report server order.
                Some(_) => CipherOrder::Server,
                None => {
                    return Err(ProbeError::Unexpected(
                        "server refused a list of suites it had accepted",
                    ));
                }
            }
        }
    };
    Ok(CipherResult {
        version,
        suites: accepted.into_iter().map(u32::from).collect(),
        order,
    })
}

async fn enumerate_ssl2(transport: &Transport) -> Result<CipherResult, ProbeError> {
    let bytes = ssl2_client_hello().map_err(ProbeError::Encode)?;
    let suites = match transport.exchange(&bytes).await {
        Ok(HelloResponse::Ssl2(hello)) => hello
            .cipher_specs
            .into_iter()
            .filter(|s| SSL2_CIPHER_SPECS.contains(s))
            .collect(),
        Ok(_) | Err(ProbeError::Io(_)) => Vec::new(),
        Err(e) => return Err(e),
    };
    // SSLv2 servers return the intersection; the client chooses.
    let order = if suites.len() < 2 {
        CipherOrder::NotApplicable
    } else {
        CipherOrder::Client
    };
    Ok(CipherResult {
        version: ProtocolVersion::SSL2,
        suites,
        order,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use testls_wire::{RawExtension, ServerHello};

    fn sh(legacy: ProtocolVersion, suite: u16, exts: Vec<RawExtension>) -> HelloResponse {
        HelloResponse::ServerHello {
            hello: ServerHello {
                legacy_version: legacy,
                random: [1; 32],
                session_id: vec![],
                cipher_suite: suite,
                compression_method: 0,
                extensions: exts,
            },
            certificates: vec![],
        }
    }

    #[test]
    fn selection_requires_matching_version_and_offered_suite() {
        let v = ProtocolVersion::TLS12;
        let r = sh(v, 0xc02f, vec![]);
        assert_eq!(selected_suite(v, &[0xc02f], &r).unwrap(), Some(0xc02f));
        assert_eq!(selected_suite(v, &[0xc030], &r).unwrap(), None);
        assert_eq!(
            selected_suite(ProtocolVersion::TLS11, &[0xc02f], &r).unwrap(),
            None
        );
        assert_eq!(
            selected_suite(v, &[0xc02f], &HelloResponse::Closed).unwrap(),
            None
        );
    }

    #[test]
    fn selection_tls13() {
        let r = sh(
            ProtocolVersion::TLS12,
            0x1302,
            vec![RawExtension {
                typ: 43,
                data: vec![3, 4],
            }],
        );
        assert_eq!(
            selected_suite(ProtocolVersion::TLS13, &[0x1301, 0x1302], &r).unwrap(),
            Some(0x1302)
        );
    }
}

#[cfg(test)]
mod mock_server {
    use super::*;
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Cipher suites offered in a TLS 1.0–1.2 `ClientHello` record.
    fn offered_suites(record: &[u8]) -> Vec<u16> {
        // record header (5) + handshake header (4) + version (2) + random (32)
        let mut i = 5 + 4 + 2 + 32;
        i += 1 + usize::from(record[i]);
        let len = usize::from(u16::from_be_bytes([record[i], record[i + 1]]));
        record[i + 2..i + 2 + len]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&c| u16::from_be_bytes(c))
            .collect()
    }

    fn server_hello(suite: u16) -> Vec<u8> {
        let mut body = vec![3, 3];
        body.extend([7; 32]);
        body.push(0);
        body.extend(suite.to_be_bytes());
        body.push(0);
        let mut hs = vec![2, 0, 0, u8::try_from(body.len()).unwrap()];
        hs.extend(body);
        hs.extend([14, 0, 0, 0]);
        let mut rec = vec![22, 3, 3];
        rec.extend(u16::try_from(hs.len()).unwrap().to_be_bytes());
        rec.extend(hs);
        rec
    }

    /// Serve TLS 1.2 hellos accepting `supported`, choosing by server order
    /// (`supported` order) or client order.
    async fn serve(supported: &'static [u16], server_order: bool) -> SocketAddr {
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
                let offered = offered_suites(&buf[..n]);
                let pick = if server_order {
                    supported.iter().copied().find(|c| offered.contains(c))
                } else {
                    offered.iter().copied().find(|c| supported.contains(c))
                };
                let reply = pick.map_or_else(|| vec![21, 3, 3, 0, 2, 2, 40], server_hello);
                s.write_all(&reply).await.unwrap();
            }
        });
        addr
    }

    #[tokio::test]
    async fn server_preference() {
        let addr = serve(&[0xc030, 0x009c, 0xc02f], true).await;
        let r = enumerate_ciphers(&Transport::new(addr), ProtocolVersion::TLS12, None)
            .await
            .unwrap();
        assert_eq!(r.suites, vec![0xc030, 0x009c, 0xc02f]);
        assert_eq!(r.order, CipherOrder::Server);
    }

    #[tokio::test]
    async fn client_preference() {
        let addr = serve(&[0xc030, 0x009c, 0xc02f], false).await;
        let r = enumerate_ciphers(&Transport::new(addr), ProtocolVersion::TLS12, None)
            .await
            .unwrap();
        let mut got = r.suites.clone();
        got.sort_unstable();
        assert_eq!(got, vec![0x009c, 0xc02f, 0xc030]);
        assert_eq!(r.order, CipherOrder::Client);
    }

    #[tokio::test]
    async fn single_suite() {
        let addr = serve(&[0x009c], true).await;
        let r = enumerate_ciphers(&Transport::new(addr), ProtocolVersion::TLS12, None)
            .await
            .unwrap();
        assert_eq!(r.suites, vec![0x009c]);
        assert_eq!(r.order, CipherOrder::NotApplicable);
    }
}
