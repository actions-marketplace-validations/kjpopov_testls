//! Async TLS probes over TCP built on testls-wire.

mod certificates;
mod ciphers;
mod details;
mod features;
mod fetch;
mod groups;
pub mod hello;
mod http;
mod intolerance;
mod protocols;
mod response;

use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};
use tokio::time::timeout;

pub use certificates::{CertificateChain, fetch_certificates};
pub use ciphers::{CipherOrder, CipherResult, enumerate_ciphers};
pub use details::{HandshakeDetails, probe_details};
pub use features::{HandshakeFeatures, probe_features};
pub use fetch::{Fetcher, HttpBody};
pub use groups::{KeyExchangeResult, probe_key_exchange};
pub use http::{HttpResponse, fetch_http_headers};
pub use intolerance::{Intolerance, probe_intolerance};
pub use protocols::{ProtocolResult, ProtocolSupport, classify, detect_protocols, probe_protocol};
pub use response::HelloResponse;
use response::ResponseParser;
use testls_wire::{DecodeError, EncodeError};

/// Error from a single probe.
#[derive(Debug)]
pub enum ProbeError {
    /// TCP connect failed.
    Connect(io::Error),
    /// Reading or writing the socket failed.
    Io(io::Error),
    /// The operation did not complete within the configured timeout.
    Timeout,
    /// The hello could not be encoded.
    Encode(EncodeError),
    /// The server sent bytes that are not a valid TLS/SSL reply.
    Decode(DecodeError),
    /// The server behaved inconsistently across probes.
    Unexpected(&'static str),
}

impl fmt::Display for ProbeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connect(e) => write!(f, "connect failed: {e}"),
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::Timeout => f.write_str("timed out"),
            Self::Encode(e) => write!(f, "cannot encode hello: {e}"),
            Self::Decode(e) => write!(f, "malformed server reply: {e}"),
            Self::Unexpected(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for ProbeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Connect(e) | Self::Io(e) => Some(e),
            Self::Timeout | Self::Unexpected(_) => None,
            Self::Encode(e) => Some(e),
            Self::Decode(e) => Some(e),
        }
    }
}

/// Connection settings shared by all probes against one target.
#[derive(Debug, Clone, Copy)]
pub struct Transport {
    /// Address to connect to.
    pub addr: SocketAddr,
    /// TCP connect timeout.
    pub connect_timeout: Duration,
    /// Timeout for the server to finish answering after the hello is sent.
    pub read_timeout: Duration,
    /// Local address to connect from; the OS picks one when `None`.
    pub source: Option<IpAddr>,
}

impl Transport {
    /// Transport with 5 s connect and 10 s read timeouts and no fixed
    /// source address.
    #[must_use]
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            connect_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(10),
            source: None,
        }
    }

    /// Opens a TCP connection to [`Transport::addr`] from
    /// [`Transport::source`] within the connect timeout.
    ///
    /// # Errors
    /// As for [`connect`].
    pub(crate) async fn connect(&self) -> Result<TcpStream, ProbeError> {
        connect(self.addr, self.source, self.connect_timeout).await
    }

    /// Open a fresh connection, send an already encoded hello, and
    /// classify the server's answer.
    ///
    /// # Errors
    /// Returns a [`ProbeError`] on connect/I/O failure, timeout, or a reply
    /// that is not TLS/SSL. A connect timeout is a [`ProbeError::Connect`]
    /// with [`io::ErrorKind::TimedOut`], so callers can tell that no hello
    /// was sent.
    pub async fn exchange(&self, hello: &[u8]) -> Result<HelloResponse, ProbeError> {
        let mut stream = self.connect().await?;
        stream.set_nodelay(true).map_err(ProbeError::Io)?;
        timeout(self.read_timeout, async {
            stream.write_all(hello).await.map_err(ProbeError::Io)?;
            read_response(&mut stream).await
        })
        .await
        .map_err(|_| ProbeError::Timeout)?
    }
}

/// Connects to `addr`, binding the socket to `source` first when given.
///
/// # Errors
/// Returns [`ProbeError::Connect`] when binding or connecting fails, when
/// `source` and `addr` are from different address families, or with
/// [`io::ErrorKind::TimedOut`] when `connect_timeout` expires.
pub(crate) async fn connect(
    addr: SocketAddr,
    source: Option<IpAddr>,
    connect_timeout: Duration,
) -> Result<TcpStream, ProbeError> {
    let socket = if addr.is_ipv4() {
        TcpSocket::new_v4()
    } else {
        TcpSocket::new_v6()
    }
    .map_err(ProbeError::Connect)?;
    if let Some(ip) = source {
        if ip.is_ipv4() != addr.is_ipv4() {
            return Err(ProbeError::Connect(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("source address {ip} cannot reach {addr} (different address family)"),
            )));
        }
        socket
            .bind(SocketAddr::new(ip, 0))
            .map_err(ProbeError::Connect)?;
    }
    timeout(connect_timeout, socket.connect(addr))
        .await
        .map_err(|_| ProbeError::Connect(io::ErrorKind::TimedOut.into()))?
        .map_err(ProbeError::Connect)
}

async fn read_response(stream: &mut TcpStream) -> Result<HelloResponse, ProbeError> {
    let mut parser = ResponseParser::new();
    let mut buf = vec![0; 16 * 1024];
    loop {
        let n = match stream.read(&mut buf).await {
            Ok(n) => n,
            // A reset right after our hello is how many servers say "no".
            Err(e) if e.kind() == io::ErrorKind::ConnectionReset => 0,
            Err(e) => return Err(ProbeError::Io(e)),
        };
        if n == 0 {
            return Ok(parser.finish());
        }
        if let Some(r) = parser.push(&buf[..n]).map_err(ProbeError::Decode)? {
            return Ok(r);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    async fn serve(reply: &'static [u8]) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = [0; 512];
            let _ = s.read(&mut buf).await.unwrap();
            s.write_all(reply).await.unwrap();
        });
        addr
    }

    #[tokio::test]
    async fn alert_reply() {
        let addr = serve(&[21, 3, 3, 0, 2, 2, 70]).await;
        let r = Transport::new(addr).exchange(b"hello").await.unwrap();
        assert!(matches!(r, HelloResponse::Alert(a) if a.description == 70));
    }

    #[tokio::test]
    async fn silent_close() {
        let addr = serve(&[]).await;
        let r = Transport::new(addr).exchange(b"hello").await.unwrap();
        assert_eq!(r, HelloResponse::Closed);
    }

    #[tokio::test]
    async fn timeout_when_server_stalls() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (_s, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(5)).await;
        });
        let mut t = Transport::new(addr);
        t.read_timeout = Duration::from_millis(100);
        assert!(matches!(t.exchange(b"x").await, Err(ProbeError::Timeout)));
    }

    /// A source address is bound before connecting; one of the other
    /// address family is rejected without connecting.
    #[tokio::test]
    async fn source_address() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let peer = tokio::spawn(async move { listener.accept().await.unwrap().1 });
        let mut t = Transport::new(addr);
        t.source = Some("127.0.0.1".parse().unwrap());
        let stream = t.connect().await.unwrap();
        assert_eq!(peer.await.unwrap(), stream.local_addr().unwrap());
        assert_eq!(stream.local_addr().unwrap().ip(), t.source.unwrap());

        t.source = Some("::1".parse().unwrap());
        let Err(ProbeError::Connect(e)) = t.connect().await else {
            panic!("connected across address families");
        };
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
        assert!(e.to_string().contains("different address family"), "{e}");
    }
}
