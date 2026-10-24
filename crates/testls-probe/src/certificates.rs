//! Certificate chain retrieval over a full rustls handshake.
//!
//! The verifier used here accepts every chain and signature: the goal is to
//! record what the server presents, not to decide whether to trust it. Trust
//! is evaluated later by the checks.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, ring};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use testls_wire::ProtocolVersion;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use crate::{ProbeError, Transport};

/// Certificate chain presented by a server during a full handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateChain {
    /// Protocol version the handshake negotiated.
    pub version: ProtocolVersion,
    /// DER-encoded certificates in the order the server sent them, leaf first.
    pub certificates: Vec<Vec<u8>>,
}

/// Completes a TLS 1.2/1.3 handshake and returns the server's certificate
/// chain without validating it.
///
/// `sni` is sent as the server name; without it the target IP is used and
/// no SNI extension is sent.
///
/// # Errors
/// Returns a [`ProbeError`] on connect/I/O failure, timeout, or if the
/// handshake fails (for example, a server that only speaks TLS 1.1 or older).
pub async fn fetch_certificates(
    transport: &Transport,
    sni: Option<&str>,
) -> Result<CertificateChain, ProbeError> {
    let tls = connect_tls(transport, sni, client_config()).await?;
    let (_, conn) = tls.get_ref();
    let version = conn
        .protocol_version()
        .map(|v| ProtocolVersion(u16::from(v)))
        .ok_or(ProbeError::Unexpected(
            "handshake finished without a version",
        ))?;
    let certificates = conn
        .peer_certificates()
        .unwrap_or_default()
        .iter()
        .map(|c| c.as_ref().to_vec())
        .collect();
    Ok(CertificateChain {
        version,
        certificates,
    })
}

/// Opens a TCP connection and completes a TLS handshake with `config`.
///
/// `sni` is sent as the server name; without it the target IP is used and
/// no SNI extension is sent.
///
/// # Errors
/// Returns a [`ProbeError`] on connect/I/O failure, timeout, or a failed
/// handshake.
pub(crate) async fn connect_tls(
    transport: &Transport,
    sni: Option<&str>,
    config: ClientConfig,
) -> Result<TlsStream<TcpStream>, ProbeError> {
    let server_name = match sni {
        Some(name) => ServerName::try_from(name.to_owned())
            .map_err(|_| ProbeError::Unexpected("SNI is not a valid server name"))?,
        None => ServerName::from(transport.addr.ip()),
    };
    let stream = timeout(
        transport.connect_timeout,
        TcpStream::connect(transport.addr),
    )
    .await
    .map_err(|_| ProbeError::Timeout)?
    .map_err(ProbeError::Connect)?;
    stream.set_nodelay(true).map_err(ProbeError::Io)?;

    let connector = TlsConnector::from(Arc::new(config));
    timeout(
        transport.read_timeout,
        connector.connect(server_name, stream),
    )
    .await
    .map_err(|_| ProbeError::Timeout)?
    .map_err(ProbeError::Io)
}

/// Client config offering TLS 1.2 and 1.3 with the recording verifier.
pub(crate) fn client_config() -> ClientConfig {
    let provider = Arc::new(ring::default_provider());
    ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("ring supports the default protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAll(provider)))
        .with_no_client_auth()
}

/// Verifier that accepts any certificate and handshake signature.
#[derive(Debug)]
struct AcceptAll(Arc<CryptoProvider>);

impl ServerCertVerifier for AcceptAll {
    /// Accepts the chain unconditionally; trust is checked elsewhere.
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    /// Accepts any TLS 1.2 handshake signature.
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    /// Accepts any TLS 1.3 handshake signature.
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    /// Advertises every scheme the crypto provider knows.
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::ServerConfig;
    use rustls::pki_types::PrivateKeyDer;
    use std::net::SocketAddr;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    /// Self-signed P-256 certificate for `localhost` (valid until 2126).
    const CERT: &[u8] = include_bytes!("testdata/localhost.cert.der");
    /// PKCS#8 private key for [`CERT`].
    const KEY: &[u8] = include_bytes!("testdata/localhost.key.der");

    /// Starts a one-shot rustls server limited to `versions`.
    async fn serve(versions: &[&'static rustls::SupportedProtocolVersion]) -> SocketAddr {
        let config = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_protocol_versions(versions)
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(CERT.to_vec())],
                PrivateKeyDer::try_from(KEY.to_vec()).unwrap(),
            )
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (s, _) = listener.accept().await.unwrap();
            if let Ok(mut tls) = acceptor.accept(s).await {
                let _ = tls.shutdown().await;
            }
        });
        addr
    }

    /// TLS 1.3 handshake returns the leaf certificate and version.
    #[tokio::test]
    async fn fetches_chain_over_tls13() {
        let addr = serve(&[&rustls::version::TLS13]).await;
        let chain = fetch_certificates(&Transport::new(addr), Some("localhost"))
            .await
            .unwrap();
        assert_eq!(chain.version, ProtocolVersion::TLS13);
        assert_eq!(chain.certificates, vec![CERT.to_vec()]);
    }

    /// TLS 1.2 handshake works too, even without SNI.
    #[tokio::test]
    async fn fetches_chain_over_tls12_without_sni() {
        let addr = serve(&[&rustls::version::TLS12]).await;
        let chain = fetch_certificates(&Transport::new(addr), None)
            .await
            .unwrap();
        assert_eq!(chain.version, ProtocolVersion::TLS12);
        assert_eq!(chain.certificates, vec![CERT.to_vec()]);
    }

    /// A non-TLS peer is reported as an I/O error, not a panic.
    #[tokio::test]
    async fn non_tls_server_is_an_error() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let _ = s.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
        });
        let r = fetch_certificates(&Transport::new(addr), None).await;
        assert!(matches!(r, Err(ProbeError::Io(_))), "{r:?}");
    }
}
