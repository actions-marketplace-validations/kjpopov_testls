//! Parsers for server-sent messages: `ServerHello` (incl. `HelloRetryRequest`),
//! `Alert`, `Certificate`, and the SSLv2 `SERVER-HELLO`.

use crate::client_hello::ext;
use crate::codec::{DecodeError, Reader};
use crate::version::ProtocolVersion;

/// Handshake message types.
pub mod handshake_type {
    /// `server_hello`.
    pub const SERVER_HELLO: u8 = 2;
    /// `certificate`.
    pub const CERTIFICATE: u8 = 11;
    /// `server_key_exchange`.
    pub const SERVER_KEY_EXCHANGE: u8 = 12;
    /// `certificate_request`.
    pub const CERTIFICATE_REQUEST: u8 = 13;
    /// `server_hello_done`.
    pub const SERVER_HELLO_DONE: u8 = 14;
}

/// `SHA-256("HelloRetryRequest")`, the magic `ServerHello.random` of an HRR.
pub const HRR_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

/// A single handshake message borrowed from a reassembled handshake stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeMessage<'a> {
    /// Message type.
    pub typ: u8,
    /// Message body (without the 4-byte header).
    pub body: &'a [u8],
}

/// Try to split one handshake message off the front of `buf`.
///
/// Handshake messages may span several records; callers concatenate
/// handshake record fragments and call this repeatedly. Returns `Ok(None)`
/// if more bytes are needed.
///
/// # Errors
/// Never fails today; the `Result` leaves room for size limits.
pub fn parse_handshake(buf: &[u8]) -> Result<Option<(HandshakeMessage<'_>, usize)>, DecodeError> {
    if buf.len() < 4 {
        return Ok(None);
    }
    let len = usize::from(buf[1]) << 16 | usize::from(buf[2]) << 8 | usize::from(buf[3]);
    let total = 4 + len;
    if buf.len() < total {
        return Ok(None);
    }
    Ok(Some((
        HandshakeMessage {
            typ: buf[0],
            body: &buf[4..total],
        },
        total,
    )))
}

/// A raw extension as received from the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawExtension {
    /// Extension type.
    pub typ: u16,
    /// Extension body.
    pub data: Vec<u8>,
}

/// A parsed `ServerHello` or `HelloRetryRequest` body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerHello {
    /// `legacy_version` / `server_version`.
    pub legacy_version: ProtocolVersion,
    /// Server random.
    pub random: [u8; 32],
    /// Session id echo.
    pub session_id: Vec<u8>,
    /// Selected cipher suite.
    pub cipher_suite: u16,
    /// Selected compression method.
    pub compression_method: u8,
    /// Extensions, in wire order.
    pub extensions: Vec<RawExtension>,
}

impl ServerHello {
    /// Parse a `ServerHello` handshake body.
    ///
    /// # Errors
    /// Returns a [`DecodeError`] if the body is malformed.
    pub fn parse(body: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(body);
        let legacy_version = ProtocolVersion(r.u16("server_version")?);
        let mut random = [0; 32];
        random.copy_from_slice(r.take(32, "random")?);
        let session_id = r.prefixed(1, "session_id")?.rest().to_vec();
        let cipher_suite = r.u16("cipher_suite")?;
        let compression_method = r.u8("compression_method")?;
        let mut extensions = Vec::new();
        if !r.is_empty() {
            let mut exts = r.prefixed(2, "extensions")?;
            while !exts.is_empty() {
                let typ = exts.u16("extension_type")?;
                let data = exts.prefixed(2, "extension_data")?.rest().to_vec();
                extensions.push(RawExtension { typ, data });
            }
        }
        r.finish("server_hello")?;
        Ok(Self {
            legacy_version,
            random,
            session_id,
            cipher_suite,
            compression_method,
            extensions,
        })
    }

    /// Whether this is a TLS 1.3 `HelloRetryRequest`.
    #[must_use]
    pub fn is_hello_retry_request(&self) -> bool {
        self.random == HRR_RANDOM
    }

    /// Find an extension body by type.
    #[must_use]
    pub fn extension(&self, typ: u16) -> Option<&[u8]> {
        self.extensions
            .iter()
            .find(|e| e.typ == typ)
            .map(|e| e.data.as_slice())
    }

    /// The negotiated version: `supported_versions` if present, else `legacy_version`.
    ///
    /// # Errors
    /// Returns an error if `supported_versions` is malformed.
    pub fn negotiated_version(&self) -> Result<ProtocolVersion, DecodeError> {
        match self.extension(ext::SUPPORTED_VERSIONS) {
            Some(data) => {
                let mut r = Reader::new(data);
                let v = r.u16("supported_versions")?;
                r.finish("supported_versions")?;
                Ok(ProtocolVersion(v))
            }
            None => Ok(self.legacy_version),
        }
    }

    /// The group selected via `key_share` (TLS 1.3 `ServerHello` or HRR).
    ///
    /// # Errors
    /// Returns an error if `key_share` is malformed.
    pub fn key_share_group(&self) -> Result<Option<u16>, DecodeError> {
        let Some(data) = self.extension(ext::KEY_SHARE) else {
            return Ok(None);
        };
        let mut r = Reader::new(data);
        let group = r.u16("key_share")?;
        if !self.is_hello_retry_request() {
            r.prefixed(2, "key_exchange")?;
        }
        r.finish("key_share")?;
        Ok(Some(group))
    }
}

/// Alert severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AlertLevel {
    /// `warning` (1).
    Warning,
    /// `fatal` (2).
    Fatal,
    /// Any other value.
    Unknown(u8),
}

/// A TLS alert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Alert {
    /// Severity.
    pub level: AlertLevel,
    /// Alert description code (e.g. 40 = `handshake_failure`).
    pub description: u8,
}

impl Alert {
    /// `handshake_failure`.
    pub const HANDSHAKE_FAILURE: u8 = 40;
    /// `protocol_version`.
    pub const PROTOCOL_VERSION: u8 = 70;
    /// `insufficient_security`.
    pub const INSUFFICIENT_SECURITY: u8 = 71;
    /// `inappropriate_fallback`.
    pub const INAPPROPRIATE_FALLBACK: u8 = 86;
    /// `unrecognized_name`.
    pub const UNRECOGNIZED_NAME: u8 = 112;
    /// `no_application_protocol` (RFC 7301, section 3.2).
    pub const NO_APPLICATION_PROTOCOL: u8 = 120;

    /// Parse an alert record fragment.
    ///
    /// # Errors
    /// Returns an error unless the fragment is exactly two bytes.
    pub fn parse(fragment: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(fragment);
        let level = match r.u8("alert_level")? {
            1 => AlertLevel::Warning,
            2 => AlertLevel::Fatal,
            other => AlertLevel::Unknown(other),
        };
        let description = r.u8("alert_description")?;
        r.finish("alert")?;
        Ok(Self { level, description })
    }
}

/// Parse a TLS 1.2-and-earlier `Certificate` body into DER certificates,
/// leaf first.
///
/// # Errors
/// Returns a [`DecodeError`] if the body is malformed.
pub fn parse_certificate_list(body: &[u8]) -> Result<Vec<Vec<u8>>, DecodeError> {
    let mut r = Reader::new(body);
    let mut list = r.prefixed(3, "certificate_list")?;
    r.finish("certificate")?;
    let mut certs = Vec::new();
    while !list.is_empty() {
        certs.push(list.prefixed(3, "certificate")?.rest().to_vec());
    }
    Ok(certs)
}

/// A parsed SSLv2 `SERVER-HELLO`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ssl2ServerHello {
    /// Server version (normally `0x0002`).
    pub version: ProtocolVersion,
    /// DER certificate, if `certificate_type` was X.509.
    pub certificate: Vec<u8>,
    /// Supported SSLv2 cipher specs (24-bit values).
    pub cipher_specs: Vec<u32>,
}

impl Ssl2ServerHello {
    /// Parse an SSLv2 record body (starting at the message type byte).
    ///
    /// # Errors
    /// Returns a [`DecodeError`] if this is not a well-formed `SERVER-HELLO`.
    pub fn parse(body: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(body);
        if r.u8("msg_type")? != 4 {
            return Err(DecodeError::Invalid { field: "msg_type" });
        }
        let _session_id_hit = r.u8("session_id_hit")?;
        let _certificate_type = r.u8("certificate_type")?;
        let version = ProtocolVersion(r.u16("server_version")?);
        let cert_len = usize::from(r.u16("certificate_length")?);
        let specs_len = usize::from(r.u16("cipher_specs_length")?);
        let conn_id_len = usize::from(r.u16("connection_id_length")?);
        if specs_len % 3 != 0 {
            return Err(DecodeError::Invalid {
                field: "cipher_specs_length",
            });
        }
        let certificate = r.take(cert_len, "certificate")?.to_vec();
        let cipher_specs = r
            .take(specs_len, "cipher_specs")?
            .as_chunks::<3>()
            .0
            .iter()
            .map(|&[a, b, c]| u32::from(a) << 16 | u32::from(b) << 8 | u32::from(c))
            .collect();
        r.take(conn_id_len, "connection_id")?;
        r.finish("server_hello")?;
        Ok(Self {
            version,
            certificate,
            cipher_specs,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server_hello_body(random: [u8; 32], exts: &[u8]) -> Vec<u8> {
        let mut b = vec![0x03, 0x03];
        b.extend(random);
        b.extend([1, 0x42, 0x13, 0x01, 0]);
        if !exts.is_empty() {
            b.extend(u16::try_from(exts.len()).unwrap().to_be_bytes());
            b.extend(exts);
        }
        b
    }

    #[test]
    fn tls12_server_hello() {
        let sh = ServerHello::parse(&server_hello_body([7; 32], &[])).unwrap();
        assert_eq!(sh.legacy_version, ProtocolVersion::TLS12);
        assert_eq!(sh.session_id, [0x42]);
        assert_eq!(sh.cipher_suite, 0x1301);
        assert!(!sh.is_hello_retry_request());
        assert_eq!(sh.negotiated_version().unwrap(), ProtocolVersion::TLS12);
        assert_eq!(sh.key_share_group().unwrap(), None);
    }

    #[test]
    fn tls13_server_hello() {
        #[rustfmt::skip]
        let exts = [
            0, 43, 0, 2, 3, 4,
            0, 51, 0, 6, 0, 29, 0, 2, 0xaa, 0xbb,
        ];
        let sh = ServerHello::parse(&server_hello_body([7; 32], &exts)).unwrap();
        assert_eq!(sh.negotiated_version().unwrap(), ProtocolVersion::TLS13);
        assert_eq!(sh.key_share_group().unwrap(), Some(29));
    }

    #[test]
    fn hello_retry_request() {
        let exts = [0, 43, 0, 2, 3, 4, 0, 51, 0, 2, 0, 23];
        let sh = ServerHello::parse(&server_hello_body(HRR_RANDOM, &exts)).unwrap();
        assert!(sh.is_hello_retry_request());
        assert_eq!(sh.key_share_group().unwrap(), Some(23));
    }

    #[test]
    fn server_hello_trailing_data() {
        let mut body = server_hello_body([7; 32], &[0, 43, 0, 2, 3, 4]);
        body.push(0);
        assert!(ServerHello::parse(&body).is_err());
    }

    #[test]
    fn handshake_framing() {
        let buf = [2, 0, 0, 2, 9, 9, 14, 0, 0];
        let (m, used) = parse_handshake(&buf).unwrap().unwrap();
        assert_eq!((m.typ, m.body, used), (2, &[9u8, 9][..], 6));
        assert_eq!(parse_handshake(&buf[used..]).unwrap(), None);
    }

    #[test]
    fn alert() {
        let a = Alert::parse(&[2, 40]).unwrap();
        assert_eq!(a.level, AlertLevel::Fatal);
        assert_eq!(a.description, Alert::HANDSHAKE_FAILURE);
        assert!(Alert::parse(&[2]).is_err());
    }

    #[test]
    fn certificate_list() {
        let body = [0, 0, 9, 0, 0, 2, 0xaa, 0xbb, 0, 0, 1, 0xcc];
        assert_eq!(
            parse_certificate_list(&body).unwrap(),
            vec![vec![0xaa, 0xbb], vec![0xcc]]
        );
    }

    #[test]
    fn ssl2_server_hello() {
        #[rustfmt::skip]
        let body = [
            4, 0, 1, 0, 2, 0, 2, 0, 6, 0, 1,
            0x30, 0x00,
            0x07, 0x00, 0xc0, 0x01, 0x00, 0x80,
            0x55,
        ];
        let sh = Ssl2ServerHello::parse(&body).unwrap();
        assert_eq!(sh.version, ProtocolVersion::SSL2);
        assert_eq!(sh.certificate, [0x30, 0x00]);
        assert_eq!(sh.cipher_specs, [0x0007_00c0, 0x0001_0080]);
    }
}
