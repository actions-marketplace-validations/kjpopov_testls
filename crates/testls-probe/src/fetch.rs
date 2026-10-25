//! Plain-HTTP requests to revocation endpoints.
//!
//! OCSP responders (RFC 6960 Appendix A) and CRL distribution points
//! (RFC 5280 §4.2.1.13) are published as `http://` URLs. This module sends one
//! `GET` or `POST` request to such a URL and returns the reply body, capped
//! at a caller-chosen size. Redirects are not followed.

use std::fmt::Write as _;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::ProbeError;
use crate::http::{complete_head, parse_head};

/// Settings for requests to revocation endpoints.
#[derive(Debug, Clone, Copy)]
pub struct Fetcher {
    /// TCP connect timeout, applied to each resolved address.
    pub connect_timeout: Duration,
    /// Timeout for sending the request and reading the whole reply.
    pub read_timeout: Duration,
    /// Largest accepted reply body in bytes.
    pub max_body: usize,
}

/// Reply to a [`Fetcher`] request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpBody {
    /// Status code of the final response.
    pub status: u16,
    /// `Content-Type` header, if present.
    pub content_type: Option<String>,
    /// Reply body with any chunked transfer coding removed.
    pub body: Vec<u8>,
}

/// Parts of an `http://` URL needed to send a request.
#[derive(Debug, Clone, PartialEq, Eq)]
struct HttpUrl {
    /// Host name or IP literal, without IPv6 brackets.
    host: String,
    /// TCP port, 80 unless given.
    port: u16,
    /// Path and query, at least `/`.
    target: String,
    /// Value of the `Host` header (RFC 9110 §7.2).
    authority: String,
}

impl Fetcher {
    /// Sends `GET url` and returns the reply.
    ///
    /// # Errors
    /// Returns a [`ProbeError`] for URLs that are not `http://`, resolution
    /// or connect failures, timeouts, malformed replies, and bodies larger
    /// than [`Fetcher::max_body`].
    pub async fn get(&self, url: &str) -> Result<HttpBody, ProbeError> {
        self.request(url, None).await
    }

    /// Sends `POST url` with `body` of type `content_type` and returns the
    /// reply.
    ///
    /// # Errors
    /// As for [`Fetcher::get`].
    pub async fn post(
        &self,
        url: &str,
        content_type: &str,
        body: &[u8],
    ) -> Result<HttpBody, ProbeError> {
        self.request(url, Some((content_type, body))).await
    }

    /// Sends one request and reads the reply until it is complete.
    async fn request(
        &self,
        url: &str,
        post: Option<(&str, &[u8])>,
    ) -> Result<HttpBody, ProbeError> {
        let url = HttpUrl::parse(url)?;
        let mut stream = self.connect(&url).await?;
        let request = encode_request(&url, post);
        timeout(self.read_timeout, async {
            stream.write_all(&request).await.map_err(ProbeError::Io)?;
            self.read_reply(&mut stream).await
        })
        .await
        .map_err(|_| ProbeError::Timeout)?
    }

    /// Connects to the first reachable address of the URL's host.
    async fn connect(&self, url: &HttpUrl) -> Result<TcpStream, ProbeError> {
        let addrs = timeout(
            self.connect_timeout,
            tokio::net::lookup_host((url.host.as_str(), url.port)),
        )
        .await
        .map_err(|_| ProbeError::Timeout)?
        .map_err(ProbeError::Connect)?;
        let mut last = ProbeError::Unexpected("host name did not resolve");
        for addr in addrs {
            match timeout(self.connect_timeout, TcpStream::connect(addr)).await {
                Ok(Ok(stream)) => return Ok(stream),
                Ok(Err(e)) => last = ProbeError::Connect(e),
                Err(_) => last = ProbeError::Timeout,
            }
        }
        Err(last)
    }

    /// Reads the final response head and its body (RFC 9112 §6.3).
    async fn read_reply(&self, stream: &mut TcpStream) -> Result<HttpBody, ProbeError> {
        let mut data = Vec::new();
        let mut buf = vec![0; 16 * 1024];
        let mut closed = false;
        loop {
            if let Some(end) = complete_head(&data)? {
                let head = parse_head(&data[..end])?;
                if (100..200).contains(&head.status) {
                    data.drain(..end);
                    continue;
                }
                let chunked = head
                    .header_values("transfer-encoding")
                    .any(|v| v.to_ascii_lowercase().contains("chunked"));
                let length = match head.header("content-length") {
                    Some(v) if !chunked => Some(
                        v.parse::<usize>()
                            .map_err(|_| ProbeError::Unexpected("malformed Content-Length"))?,
                    ),
                    _ => None,
                };
                if length.is_some_and(|l| l > self.max_body) {
                    return Err(too_large());
                }
                let raw = &data[end..];
                let body = if chunked {
                    match dechunk(raw, self.max_body)? {
                        Some(body) => Some(body),
                        None if closed => return Err(truncated()),
                        None => None,
                    }
                } else if let Some(length) = length {
                    match raw.get(..length) {
                        Some(body) => Some(body.to_vec()),
                        None if closed => return Err(truncated()),
                        None => None,
                    }
                } else if raw.len() > self.max_body {
                    return Err(too_large());
                } else if closed {
                    Some(raw.to_vec())
                } else {
                    None
                };
                if let Some(body) = body {
                    return Ok(HttpBody {
                        status: head.status,
                        content_type: head.header("content-type").map(str::to_owned),
                        body,
                    });
                }
            } else if closed {
                return Err(ProbeError::Unexpected(
                    "connection closed before the HTTP headers ended",
                ));
            }
            // Chunk framing adds at most a few bytes per chunk; this bound
            // only stops a server that streams forever.
            if data.len() > self.max_body.saturating_mul(2).saturating_add(64 * 1024) {
                return Err(too_large());
            }
            let n = stream.read(&mut buf).await.map_err(ProbeError::Io)?;
            closed = n == 0;
            data.extend_from_slice(&buf[..n]);
        }
    }
}

impl HttpUrl {
    /// Parses `http://host[:port][/path][?query][#fragment]`. User info is
    /// rejected and the fragment is dropped (RFC 3986 §3, RFC 9110 §4.2.1).
    fn parse(url: &str) -> Result<Self, ProbeError> {
        let invalid = |msg| Err(ProbeError::Unexpected(msg));
        let Some(rest) = url
            .get(..7)
            .filter(|s| s.eq_ignore_ascii_case("http://"))
            .map(|_| &url[7..])
        else {
            return invalid("only http:// URLs are supported");
        };
        let rest = rest.split('#').next().unwrap_or_default();
        let split = rest.find(['/', '?']).unwrap_or(rest.len());
        let (authority, target) = rest.split_at(split);
        if authority.contains('@') {
            return invalid("URLs with user info are not supported");
        }
        let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
            let Some((host, tail)) = v6.split_once(']') else {
                return invalid("malformed URL host");
            };
            (host, tail.strip_prefix(':'))
        } else {
            match authority.rsplit_once(':') {
                Some((host, port)) => (host, Some(port)),
                None => (authority, None),
            }
        };
        let port = match port {
            None | Some("") => 80,
            Some(p) if p.bytes().all(|b| b.is_ascii_digit()) => match p.parse() {
                Ok(p) if p > 0 => p,
                _ => return invalid("malformed URL port"),
            },
            Some(_) => return invalid("malformed URL port"),
        };
        if host.is_empty() || !host.bytes().all(|b| b.is_ascii_graphic()) {
            return invalid("malformed URL host");
        }
        if !target.bytes().all(|b| b.is_ascii_graphic()) {
            return invalid("malformed URL path");
        }
        let target = match target {
            "" => "/".to_owned(),
            t if t.starts_with('?') => format!("/{t}"),
            t => t.to_owned(),
        };
        let host_part = if host.contains(':') {
            format!("[{host}]")
        } else {
            host.to_owned()
        };
        let authority = match port {
            80 => host_part,
            p => format!("{host_part}:{p}"),
        };
        Ok(Self {
            host: host.to_owned(),
            port,
            target,
            authority,
        })
    }
}

/// Encodes an HTTP/1.1 request (RFC 9112 §3) that asks the server to close
/// the connection after replying.
fn encode_request(url: &HttpUrl, post: Option<(&str, &[u8])>) -> Vec<u8> {
    let method = if post.is_some() { "POST" } else { "GET" };
    let mut head = format!(
        "{method} {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: testls/{}\r\nAccept: */*\r\nConnection: close\r\n",
        url.target,
        url.authority,
        env!("CARGO_PKG_VERSION"),
    );
    if let Some((content_type, body)) = post {
        let _ = write!(
            head,
            "Content-Type: {content_type}\r\nContent-Length: {}\r\n",
            body.len()
        );
    }
    head.push_str("\r\n");
    let mut request = head.into_bytes();
    if let Some((_, body)) = post {
        request.extend_from_slice(body);
    }
    request
}

/// Removes the chunked transfer coding (RFC 9112 §7.1). Returns `None`
/// while the last chunk has not arrived; trailer fields are skipped.
fn dechunk(mut raw: &[u8], max_body: usize) -> Result<Option<Vec<u8>>, ProbeError> {
    let malformed = || ProbeError::Unexpected("malformed chunked body");
    let mut body = Vec::new();
    loop {
        let Some(eol) = raw.windows(2).position(|w| w == b"\r\n") else {
            return Ok(None);
        };
        let line = std::str::from_utf8(&raw[..eol]).map_err(|_| malformed())?;
        let size = line.split(';').next().unwrap_or_default().trim_end();
        if size.is_empty() || !size.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(malformed());
        }
        let size = usize::from_str_radix(size, 16).map_err(|_| too_large())?;
        raw = &raw[eol + 2..];
        if size == 0 {
            // Trailer section: field lines up to an empty line.
            loop {
                let Some(eol) = raw.windows(2).position(|w| w == b"\r\n") else {
                    return Ok(None);
                };
                if eol == 0 {
                    return Ok(Some(body));
                }
                raw = &raw[eol + 2..];
            }
        }
        if size > max_body.saturating_sub(body.len()) {
            return Err(too_large());
        }
        let Some(chunk) = raw.get(..size + 2) else {
            return Ok(None);
        };
        if &chunk[size..] != b"\r\n" {
            return Err(malformed());
        }
        body.extend_from_slice(&chunk[..size]);
        raw = &raw[size + 2..];
    }
}

/// Error for replies whose body exceeds the size limit.
fn too_large() -> ProbeError {
    ProbeError::Unexpected("HTTP reply body too large")
}

/// Error for replies that end before the announced body.
fn truncated() -> ProbeError {
    ProbeError::Unexpected("connection closed before the HTTP body ended")
}

#[cfg(test)]
mod tests {
    //! Unit tests for URL parsing, body framing and the request itself.

    use super::*;
    use std::net::SocketAddr;
    use tokio::net::TcpListener;

    /// Fetcher with short timeouts and a 1 KiB body limit.
    fn fetcher() -> Fetcher {
        Fetcher {
            connect_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(5),
            max_body: 1024,
        }
    }

    /// Starts a one-shot HTTP server that records the request and answers
    /// with `reply`, then closes the connection.
    async fn serve(reply: Vec<u8>) -> (SocketAddr, tokio::task::JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buf = [0; 1024];
            loop {
                let n = s.read(&mut buf).await.unwrap();
                request.extend_from_slice(&buf[..n]);
                if let Ok(Some(end)) = complete_head(&request) {
                    let length = parse_head(&request[..end])
                        .ok()
                        .and_then(|h| h.header("content-length").map(str::to_owned))
                        .map_or(0, |v| v.parse::<usize>().unwrap());
                    if request.len() >= end + length {
                        break;
                    }
                }
                if n == 0 {
                    break;
                }
            }
            s.write_all(&reply).await.unwrap();
            let _ = s.shutdown().await;
            request
        });
        (addr, task)
    }

    /// A `GET` request names the path and host; the sized body comes back.
    #[tokio::test]
    async fn get_with_content_length() {
        let (addr, task) = serve(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/pkix-crl\r\nContent-Length: 3\r\n\r\nabcEXTRA"
                .to_vec(),
        )
        .await;
        let r = fetcher()
            .get(&format!("http://{addr}/ca.crl"))
            .await
            .unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.content_type.as_deref(), Some("application/pkix-crl"));
        assert_eq!(r.body, b"abc");
        let request = String::from_utf8(task.await.unwrap()).unwrap();
        assert!(request.starts_with("GET /ca.crl HTTP/1.1\r\n"), "{request}");
        assert!(
            request.contains(&format!("\r\nHost: {addr}\r\n")),
            "{request}"
        );
    }

    /// A `POST` request carries its body, type and length.
    #[tokio::test]
    async fn post_sends_body() {
        let (addr, task) = serve(b"HTTP/1.0 200 OK\r\n\r\nreply".to_vec()).await;
        let r = fetcher()
            .post(
                &format!("http://{addr}"),
                "application/ocsp-request",
                b"\x30\x00",
            )
            .await
            .unwrap();
        assert_eq!(r.body, b"reply");
        let request = task.await.unwrap();
        let text = String::from_utf8_lossy(&request);
        assert!(text.starts_with("POST / HTTP/1.1\r\n"), "{text}");
        assert!(text.contains("\r\nContent-Type: application/ocsp-request\r\n"));
        assert!(text.contains("\r\nContent-Length: 2\r\n"));
        assert!(request.ends_with(b"\r\n\r\n\x30\x00"));
    }

    /// Chunked bodies are decoded, including extensions and trailers.
    #[tokio::test]
    async fn chunked_body() {
        let (addr, _task) = serve(
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
              3;ext=1\r\nabc\r\n2\r\nde\r\n0\r\nX-Trailer: t\r\n\r\n"
                .to_vec(),
        )
        .await;
        let r = fetcher().get(&format!("http://{addr}/")).await.unwrap();
        assert_eq!(r.body, b"abcde");
    }

    /// Error statuses are returned for the caller to judge.
    #[tokio::test]
    async fn error_status_is_returned() {
        let (addr, _task) =
            serve(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec()).await;
        let r = fetcher().get(&format!("http://{addr}/")).await.unwrap();
        assert_eq!(r.status, 404);
        assert_eq!(r.body, b"");
    }

    /// Oversized and truncated bodies are errors.
    #[tokio::test]
    async fn size_limit_and_truncation() {
        let mut big = b"HTTP/1.1 200 OK\r\n\r\n".to_vec();
        big.resize(big.len() + 1025, b'a');
        for reply in [
            big,
            b"HTTP/1.1 200 OK\r\nContent-Length: 1025\r\n\r\n".to_vec(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc".to_vec(),
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nab".to_vec(),
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n401\r\n".to_vec(),
            b"HTTP/1.1 200 OK\r\nContent-Length: x\r\n\r\n".to_vec(),
            b"HTTP/1.1 200 OK\r\n".to_vec(),
        ] {
            let (addr, _task) = serve(reply.clone()).await;
            let r = fetcher().get(&format!("http://{addr}/")).await;
            assert!(
                matches!(r, Err(ProbeError::Unexpected(_))),
                "{:?}: {r:?}",
                String::from_utf8_lossy(&reply)
            );
        }
    }

    /// Chunk framing errors are rejected.
    #[test]
    fn malformed_chunks() {
        assert!(dechunk(b"z\r\n", 10).is_err());
        assert!(dechunk(b"\r\n", 10).is_err());
        assert!(dechunk(b"2\r\nabc\r\n", 10).is_err());
        assert_eq!(dechunk(b"2\r\nab\r\n", 10).unwrap(), None);
        assert_eq!(dechunk(b"0\r\n\r\n", 10).unwrap(), Some(vec![]));
    }

    /// URLs are split into host, port, target and `Host` header.
    #[test]
    fn parses_urls() {
        let url = |s: &str| HttpUrl::parse(s).unwrap();
        let u = url("http://ocsp.example.com");
        assert_eq!(
            (u.host.as_str(), u.port, u.target.as_str()),
            ("ocsp.example.com", 80, "/")
        );
        assert_eq!(u.authority, "ocsp.example.com");
        let u = url("HTTP://crl.example.com:8080/a/b.crl?x=1#frag");
        assert_eq!((u.port, u.target.as_str()), (8080, "/a/b.crl?x=1"));
        assert_eq!(u.authority, "crl.example.com:8080");
        let u = url("http://[2001:db8::1]:81?q");
        assert_eq!((u.host.as_str(), u.target.as_str()), ("2001:db8::1", "/?q"));
        assert_eq!(u.authority, "[2001:db8::1]:81");
        assert_eq!(url("http://192.0.2.1:/").port, 80);
    }

    /// Unsupported schemes and malformed URLs are rejected.
    #[test]
    fn rejects_urls() {
        for bad in [
            "https://example.com/",
            "ldap://example.com/",
            "http:/example.com",
            "http://",
            "http://user@example.com/",
            "http://example.com:0/",
            "http://example.com:99999/",
            "http://example.com:x/",
            "http://[2001:db8::1/",
            "http://exa mple.com/",
            "http://example.com/a b",
        ] {
            assert!(HttpUrl::parse(bad).is_err(), "{bad}");
        }
    }
}
