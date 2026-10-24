//! HTTP response headers over a full rustls handshake.
//!
//! One `GET` request is sent and only the status line and header section of
//! the reply are read (RFC 9112 §2–§5); the body is ignored. The headers feed
//! the HSTS and security header checks.

use std::net::IpAddr;

use rustls::ClientConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

use crate::certificates::{client_config, connect_tls};
use crate::{ProbeError, Transport};

/// Upper bound on the size of the status line and header section.
const MAX_HEADER_BYTES: usize = 64 * 1024;

/// Status and headers of the server's reply to `GET /`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    /// Status code, for example `200` or `301`.
    pub status: u16,
    /// Header fields in the order received; names are lowercased and values
    /// trimmed of surrounding whitespace.
    pub headers: Vec<(String, String)>,
}

impl HttpResponse {
    /// Values of every header field called `name` (case-insensitive), in
    /// the order received.
    pub fn header_values<'a, 'n>(
        &'a self,
        name: &'n str,
    ) -> impl Iterator<Item = &'a str> + use<'a, 'n> {
        self.headers
            .iter()
            .filter(move |(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// First value of the header field called `name`, if present.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.header_values(name).next()
    }
}

/// Sends `GET /` over TLS 1.2/1.3 and returns the reply's status and
/// headers.
///
/// The `Host` header is `sni`, or the target IP without it; the port is
/// added when it is not 443. Redirects are not followed: the headers of the
/// first response are what a browser sees for this origin.
///
/// # Errors
/// Returns a [`ProbeError`] on connect/I/O failure, timeout, a failed
/// handshake, or a reply that is not an HTTP/1.x response.
pub async fn fetch_http_headers(
    transport: &Transport,
    sni: Option<&str>,
) -> Result<HttpResponse, ProbeError> {
    let mut tls = connect_tls(transport, sni, http_config()).await?;
    let request = format!(
        "GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: testls/{}\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        host_header(transport, sni),
        env!("CARGO_PKG_VERSION"),
    );
    timeout(transport.read_timeout, async {
        tls.write_all(request.as_bytes())
            .await
            .map_err(ProbeError::Io)?;
        let mut head = Vec::new();
        let mut buf = [0; 4096];
        loop {
            if let Some(end) = complete_head(&head)? {
                return parse_head(&head[..end]);
            }
            let n = match tls.read(&mut buf).await {
                Ok(n) => n,
                // Servers often close without close_notify after the reply.
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => 0,
                Err(e) => return Err(ProbeError::Io(e)),
            };
            if n == 0 {
                return Err(ProbeError::Unexpected(
                    "connection closed before the HTTP headers ended",
                ));
            }
            head.extend_from_slice(&buf[..n]);
        }
    })
    .await
    .map_err(|_| ProbeError::Timeout)?
}

/// Recording client config that also offers `http/1.1` via ALPN, so servers
/// that negotiate protocols do not pick HTTP/2.
fn http_config() -> ClientConfig {
    let mut config = client_config();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config
}

/// Value of the `Host` header (RFC 9110 §7.2): the SNI name or the IP, with
/// IPv6 in brackets, plus the port when it is not 443.
fn host_header(transport: &Transport, sni: Option<&str>) -> String {
    let host = match (sni, transport.addr.ip()) {
        (Some(name), _) => name.to_owned(),
        (None, IpAddr::V4(ip)) => ip.to_string(),
        (None, IpAddr::V6(ip)) => format!("[{ip}]"),
    };
    match transport.addr.port() {
        443 => host,
        port => format!("{host}:{port}"),
    }
}

/// Length of the header section including the terminating empty line, once
/// it has been fully received.
fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

/// Length of the received header section, `None` while it is incomplete, or
/// an error once it exceeds [`MAX_HEADER_BYTES`] (complete or not).
fn complete_head(buf: &[u8]) -> Result<Option<usize>, ProbeError> {
    let too_large = || ProbeError::Unexpected("HTTP header section too large");
    match find_header_end(buf) {
        Some(end) if end > MAX_HEADER_BYTES => Err(too_large()),
        Some(end) => Ok(Some(end)),
        None if buf.len() > MAX_HEADER_BYTES => Err(too_large()),
        None => Ok(None),
    }
}

/// Whether `name` is a non-empty `token` (RFC 9110 §5.1, §5.6.2).
fn is_token(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

/// Parses an HTTP/1.x status line and header fields (RFC 9112 §4, §5).
///
/// Obsolete line folding (RFC 9112 §5.2) is rejected, as are field lines
/// without a colon, with a name that is not a token, or with CR, LF or NUL
/// in the value. Field values may
/// carry `obs-text` (RFC 9110 §5.5); bytes that are not UTF-8 become U+FFFD.
fn parse_head(head: &[u8]) -> Result<HttpResponse, ProbeError> {
    let text = String::from_utf8_lossy(head);
    let mut lines = text.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let status = parse_status_line(status_line)
        .ok_or(ProbeError::Unexpected("reply is not an HTTP/1.x response"))?;
    let mut headers = Vec::new();
    for line in lines.take_while(|l| !l.is_empty()) {
        if line.starts_with([' ', '\t']) {
            return Err(ProbeError::Unexpected("obsolete HTTP header line folding"));
        }
        let (name, value) = line
            .split_once(':')
            .ok_or(ProbeError::Unexpected("malformed HTTP header line"))?;
        if !is_token(name) {
            return Err(ProbeError::Unexpected("malformed HTTP header name"));
        }
        // RFC 9110 §5.5: CR, LF and NUL are never valid in a field value.
        if value.contains(['\r', '\n', '\0']) {
            return Err(ProbeError::Unexpected("malformed HTTP header value"));
        }
        headers.push((
            name.to_ascii_lowercase(),
            value.trim_matches([' ', '\t']).to_owned(),
        ));
    }
    Ok(HttpResponse { status, headers })
}

/// Status code from `HTTP/1.x SP 3DIGIT SP reason` (RFC 9112 §4), limited
/// to the 100-599 range defined by RFC 9110 §15.
fn parse_status_line(line: &str) -> Option<u16> {
    let rest = line
        .strip_prefix("HTTP/1.1 ")
        .or_else(|| line.strip_prefix("HTTP/1.0 "))?;
    let code = rest.get(..3)?;
    if !code.bytes().all(|b| b.is_ascii_digit())
        || !matches!(rest.as_bytes().get(3), None | Some(b' '))
    {
        return None;
    }
    code.parse().ok().filter(|c| (100..=599).contains(c))
}

#[cfg(test)]
mod tests {
    //! Unit tests for header parsing and the HTTPS request.

    use super::*;
    use rustls::ServerConfig;
    use rustls::crypto::ring;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    /// Self-signed P-256 certificate for `localhost` (valid until 2126).
    const CERT: &[u8] = include_bytes!("testdata/localhost.cert.der");
    /// PKCS#8 private key for [`CERT`].
    const KEY: &[u8] = include_bytes!("testdata/localhost.key.der");

    /// Starts a one-shot TLS server that records the request head and
    /// answers with `reply`.
    async fn serve(reply: &'static [u8]) -> (SocketAddr, tokio::task::JoinHandle<String>) {
        let config = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_safe_default_protocol_versions()
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
        let task = tokio::spawn(async move {
            let (s, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(s).await.unwrap();
            let mut request = Vec::new();
            let mut buf = [0; 1024];
            while find_header_end(&request).is_none() {
                let n = tls.read(&mut buf).await.unwrap();
                request.extend_from_slice(&buf[..n]);
            }
            tls.write_all(reply).await.unwrap();
            let _ = tls.shutdown().await;
            String::from_utf8(request).unwrap()
        });
        (addr, task)
    }

    /// The request names the host and port; the reply headers come back.
    #[tokio::test]
    async fn fetches_headers() {
        let (addr, task) = serve(
            b"HTTP/1.1 200 OK\r\nStrict-Transport-Security: max-age=63072000\r\n\
              X-Frame-Options: DENY\r\nContent-Length: 2\r\n\r\nok",
        )
        .await;
        let r = fetch_http_headers(&Transport::new(addr), Some("localhost"))
            .await
            .unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(
            r.header("strict-transport-security"),
            Some("max-age=63072000")
        );
        assert_eq!(r.header("X-Frame-Options"), Some("DENY"));
        let request = task.await.unwrap();
        assert!(request.starts_with("GET / HTTP/1.1\r\n"), "{request}");
        assert!(
            request.contains(&format!("\r\nHost: localhost:{}\r\n", addr.port())),
            "{request}"
        );
    }

    /// A TLS server that does not speak HTTP is an error.
    #[tokio::test]
    async fn non_http_reply_is_an_error() {
        let (addr, _task) = serve(b"SSH-2.0-OpenSSH\r\n\r\n").await;
        let r = fetch_http_headers(&Transport::new(addr), None).await;
        assert!(matches!(r, Err(ProbeError::Unexpected(_))), "{r:?}");
    }

    /// Closing before the empty line ends the header section is an error.
    #[tokio::test]
    async fn truncated_headers_are_an_error() {
        let (addr, _task) = serve(b"HTTP/1.1 200 OK\r\nServer: x\r\n").await;
        let r = fetch_http_headers(&Transport::new(addr), None).await;
        assert!(matches!(r, Err(ProbeError::Unexpected(_))), "{r:?}");
    }

    /// Repeated fields are kept in order; names are lowercased and values
    /// trimmed.
    #[test]
    fn parses_repeated_fields() {
        let r = parse_head(b"HTTP/1.0 301 Moved\r\nSet-Cookie: a=1\r\nset-cookie:b=2 \r\n\r\n")
            .unwrap();
        assert_eq!(r.status, 301);
        assert_eq!(
            r.header_values("Set-Cookie").collect::<Vec<_>>(),
            ["a=1", "b=2"]
        );
        assert_eq!(r.headers[0].0, "set-cookie");
        assert_eq!(r.header("missing"), None);
    }

    /// Malformed status lines and field lines are rejected.
    #[test]
    fn rejects_malformed_heads() {
        for head in [
            &b"HTTP/2 200\r\n\r\n"[..],
            b"HTTP/1.1 20 OK\r\n\r\n",
            b"HTTP/1.1 2000\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nno-colon\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nName : v\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nA: b\r\n continued\r\n\r\n",
            b"HTTP/1.1 200 OK\r\n: v\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nBad Name: v\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nBad\"Name: v\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nX-A: a\0b\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nX-A: a\rb\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nX-A: a\nb\r\n\r\n",
        ] {
            assert!(parse_head(head).is_err(), "{head:?}");
        }
    }

    /// Status codes outside 100-599 are rejected.
    #[test]
    fn status_code_range() {
        assert_eq!(parse_status_line("HTTP/1.1 100 Continue"), Some(100));
        assert_eq!(parse_status_line("HTTP/1.1 599"), Some(599));
        assert_eq!(parse_status_line("HTTP/1.1 204"), Some(204));
        assert_eq!(parse_status_line("HTTP/1.1 000 Zero"), None);
        assert_eq!(parse_status_line("HTTP/1.1 600 Big"), None);
    }

    /// Non-UTF-8 `obs-text` in a value keeps the response and its headers.
    #[test]
    fn obs_text_values_are_kept() {
        let r = parse_head(b"HTTP/1.1 200 \xff\r\nX-A: a\xffb\r\nX-B: c\r\n\r\n").unwrap();
        assert_eq!(r.header("x-a"), Some("a\u{fffd}b"));
        assert_eq!(r.header("x-b"), Some("c"));
    }

    /// The size limit applies whether or not the terminator has arrived.
    #[test]
    fn header_size_limit() {
        let head = |len: usize| {
            let mut h = b"HTTP/1.1 200 OK\r\nX: ".to_vec();
            h.resize(len - 4, b'a');
            h.extend_from_slice(b"\r\n\r\n");
            h
        };
        assert_eq!(
            complete_head(&head(MAX_HEADER_BYTES)).unwrap(),
            Some(MAX_HEADER_BYTES)
        );
        assert!(complete_head(&head(MAX_HEADER_BYTES + 1)).is_err());
        assert_eq!(complete_head(&vec![b'a'; MAX_HEADER_BYTES]).unwrap(), None);
        assert!(complete_head(&vec![b'a'; MAX_HEADER_BYTES + 1]).is_err());
    }

    /// The `Host` header brackets IPv6 and omits the default port.
    #[test]
    fn host_header_forms() {
        let t = |addr: &str| Transport::new(addr.parse().unwrap());
        assert_eq!(host_header(&t("192.0.2.1:443"), None), "192.0.2.1");
        assert_eq!(
            host_header(&t("[2001:db8::1]:8443"), None),
            "[2001:db8::1]:8443"
        );
        assert_eq!(
            host_header(&t("192.0.2.1:443"), Some("example.com")),
            "example.com"
        );
    }
}
