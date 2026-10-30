//! `ClientHello` encoders for SSLv2-compatible and SSLv3/TLS record formats.

use crate::codec::{EncodeError, Writer};
use crate::version::ProtocolVersion;

/// Record content type: handshake.
pub const CONTENT_HANDSHAKE: u8 = 22;
/// Handshake message type: `ClientHello`.
pub const HANDSHAKE_CLIENT_HELLO: u8 = 1;
/// Maximum plaintext record fragment size (2^14).
pub const MAX_FRAGMENT_LEN: usize = 1 << 14;

/// Extension type code points used by the builder.
pub mod ext {
    /// `server_name` (RFC 6066).
    pub const SERVER_NAME: u16 = 0;
    /// `supported_groups` (RFC 8422 / RFC 8446).
    pub const SUPPORTED_GROUPS: u16 = 10;
    /// `ec_point_formats` (RFC 8422).
    pub const EC_POINT_FORMATS: u16 = 11;
    /// `padding` (RFC 7685).
    pub const PADDING: u16 = 21;
    /// `extended_master_secret` (RFC 7627).
    pub const EXTENDED_MASTER_SECRET: u16 = 23;
    /// `signature_algorithms` (RFC 8446).
    pub const SIGNATURE_ALGORITHMS: u16 = 13;
    /// `application_layer_protocol_negotiation` (RFC 7301).
    pub const ALPN: u16 = 16;
    /// `supported_versions` (RFC 8446).
    pub const SUPPORTED_VERSIONS: u16 = 43;
    /// `key_share` (RFC 8446).
    pub const KEY_SHARE: u16 = 51;
    /// `renegotiation_info` (RFC 5746).
    pub const RENEGOTIATION_INFO: u16 = 0xff01;
}

/// One `key_share` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyShareEntry {
    /// Named group code point.
    pub group: u16,
    /// Public key bytes.
    pub key_exchange: Vec<u8>,
}

/// A `ClientHello` extension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Extension {
    /// `server_name` with a single DNS host name.
    ServerName(String),
    /// `supported_versions` (client form: list of versions).
    SupportedVersions(Vec<ProtocolVersion>),
    /// `supported_groups`.
    SupportedGroups(Vec<u16>),
    /// `signature_algorithms`.
    SignatureAlgorithms(Vec<u16>),
    /// `key_share` (client form: list of entries).
    KeyShare(Vec<KeyShareEntry>),
    /// `ec_point_formats`.
    EcPointFormats(Vec<u8>),
    /// `renegotiation_info` with empty `renegotiated_connection`.
    RenegotiationInfo,
    /// Any other extension, sent verbatim.
    Raw {
        /// Extension type.
        typ: u16,
        /// Extension body.
        data: Vec<u8>,
    },
}

impl Extension {
    /// The extension type code point.
    #[must_use]
    pub fn typ(&self) -> u16 {
        match self {
            Self::ServerName(_) => ext::SERVER_NAME,
            Self::SupportedVersions(_) => ext::SUPPORTED_VERSIONS,
            Self::SupportedGroups(_) => ext::SUPPORTED_GROUPS,
            Self::SignatureAlgorithms(_) => ext::SIGNATURE_ALGORITHMS,
            Self::KeyShare(_) => ext::KEY_SHARE,
            Self::EcPointFormats(_) => ext::EC_POINT_FORMATS,
            Self::RenegotiationInfo => ext::RENEGOTIATION_INFO,
            Self::Raw { typ, .. } => *typ,
        }
    }

    fn encode(&self, w: &mut Writer) -> Result<(), EncodeError> {
        w.u16(self.typ());
        w.prefixed(2, "extension_data", |w| {
            match self {
                Self::ServerName(name) => w.prefixed(2, "server_name_list", |w| {
                    w.u8(0); // host_name
                    w.prefixed(2, "host_name", |w| {
                        w.bytes(name.as_bytes());
                        Ok(())
                    })
                })?,
                Self::SupportedVersions(versions) => w.prefixed(1, "versions", |w| {
                    for v in versions {
                        w.u16(v.0);
                    }
                    Ok(())
                })?,
                Self::SupportedGroups(list) | Self::SignatureAlgorithms(list) => {
                    w.prefixed(2, "list", |w| {
                        for &v in list {
                            w.u16(v);
                        }
                        Ok(())
                    })?;
                }
                Self::KeyShare(entries) => w.prefixed(2, "client_shares", |w| {
                    for e in entries {
                        w.u16(e.group);
                        w.prefixed(2, "key_exchange", |w| {
                            w.bytes(&e.key_exchange);
                            Ok(())
                        })?;
                    }
                    Ok(())
                })?,
                Self::EcPointFormats(formats) => w.prefixed(1, "ec_point_formats", |w| {
                    w.bytes(formats);
                    Ok(())
                })?,
                Self::RenegotiationInfo => w.u8(0),
                Self::Raw { data, .. } => w.bytes(data),
            }
            Ok(())
        })
    }
}

/// An SSLv3/TLS `ClientHello`.
///
/// Fields are encoded verbatim; no validation is performed so that
/// deliberately unusual hellos can be sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHello {
    /// Version in the record header.
    pub record_version: ProtocolVersion,
    /// `legacy_version` / `client_version` field.
    pub version: ProtocolVersion,
    /// Client random.
    pub random: [u8; 32],
    /// Legacy session id (0..=32 bytes).
    pub session_id: Vec<u8>,
    /// Offered cipher suites.
    pub cipher_suites: Vec<u16>,
    /// Offered compression methods.
    pub compression_methods: Vec<u8>,
    /// Extensions. If empty, the extensions block is omitted entirely,
    /// which is required for strict SSLv3 servers.
    pub extensions: Vec<Extension>,
}

impl ClientHello {
    /// Encode the handshake message body (type + length + body), without a record header.
    ///
    /// # Errors
    /// Returns an error if a variable-length field overflows its length prefix.
    pub fn encode_handshake(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = Writer::new();
        w.u8(HANDSHAKE_CLIENT_HELLO);
        w.prefixed(3, "client_hello", |w| {
            w.u16(self.version.0);
            w.bytes(&self.random);
            w.prefixed(1, "session_id", |w| {
                w.bytes(&self.session_id);
                Ok(())
            })?;
            w.prefixed(2, "cipher_suites", |w| {
                self.cipher_suites.iter().for_each(|&c| w.u16(c));
                Ok(())
            })?;
            w.prefixed(1, "compression_methods", |w| {
                w.bytes(&self.compression_methods);
                Ok(())
            })?;
            if !self.extensions.is_empty() {
                w.prefixed(2, "extensions", |w| {
                    self.extensions.iter().try_for_each(|e| e.encode(w))
                })?;
            }
            Ok(())
        })?;
        Ok(w.into_inner())
    }

    /// Encode as a single TLS record ready to be written to a socket.
    ///
    /// # Errors
    /// Returns an error if a field overflows or the message exceeds one record.
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let hs = self.encode_handshake()?;
        if hs.len() > MAX_FRAGMENT_LEN {
            return Err(EncodeError::TooLong {
                field: "record",
                len: hs.len(),
                max: MAX_FRAGMENT_LEN,
            });
        }
        self.records(&hs, MAX_FRAGMENT_LEN)
    }

    /// Encode as consecutive records carrying at most `fragment_len` bytes
    /// of the handshake message each.
    ///
    /// Handshake messages may span several records (RFC 8446, section 5.1;
    /// RFC 5246, section 6.2.1).
    ///
    /// `fragment_len` is clamped to `1..=MAX_FRAGMENT_LEN`.
    ///
    /// # Errors
    /// Returns an error if a variable-length field overflows.
    pub fn encode_fragmented(&self, fragment_len: usize) -> Result<Vec<u8>, EncodeError> {
        let fragment_len = fragment_len.clamp(1, MAX_FRAGMENT_LEN);
        self.records(&self.encode_handshake()?, fragment_len)
    }

    /// Wrap `hs` in handshake records of at most `fragment_len` bytes.
    fn records(&self, hs: &[u8], fragment_len: usize) -> Result<Vec<u8>, EncodeError> {
        let mut w = Writer::new();
        for chunk in hs.chunks(fragment_len) {
            w.u8(CONTENT_HANDSHAKE);
            w.u16(self.record_version.0);
            w.prefixed(2, "record", |w| {
                w.bytes(chunk);
                Ok(())
            })?;
        }
        Ok(w.into_inner())
    }
}

/// An SSLv2 `CLIENT-HELLO` (two-byte record header form).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ssl2ClientHello {
    /// Version field; `0x0002` for SSLv2, or a TLS version for a
    /// SSLv2-compatible hello.
    pub version: ProtocolVersion,
    /// Three-byte cipher specs (low 24 bits used).
    pub cipher_specs: Vec<u32>,
    /// Session id (usually empty).
    pub session_id: Vec<u8>,
    /// Challenge (16..=32 bytes).
    pub challenge: Vec<u8>,
}

impl Ssl2ClientHello {
    /// Encode with the two-byte SSLv2 record header.
    ///
    /// # Errors
    /// Returns an error if the message exceeds the 15-bit SSLv2 length.
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut body = Writer::new();
        body.u8(HANDSHAKE_CLIENT_HELLO);
        body.u16(self.version.0);
        let specs_len = self.cipher_specs.len() * 3;
        for (field, len) in [
            ("cipher_specs", specs_len),
            ("session_id", self.session_id.len()),
            ("challenge", self.challenge.len()),
        ] {
            let len16 = u16::try_from(len).map_err(|_| EncodeError::TooLong {
                field,
                len,
                max: u16::MAX.into(),
            })?;
            body.u16(len16);
        }
        for spec in &self.cipher_specs {
            body.bytes(&spec.to_be_bytes()[1..]);
        }
        body.bytes(&self.session_id);
        body.bytes(&self.challenge);
        let body = body.into_inner();

        let max = 0x7fff;
        let len =
            u16::try_from(body.len())
                .ok()
                .filter(|&l| l <= max)
                .ok_or(EncodeError::TooLong {
                    field: "sslv2_record",
                    len: body.len(),
                    max: max.into(),
                })?;
        let mut w = Writer::new();
        w.u16(0x8000 | len);
        w.bytes(&body);
        Ok(w.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal() -> ClientHello {
        ClientHello {
            record_version: ProtocolVersion::TLS10,
            version: ProtocolVersion::TLS12,
            random: [0xaa; 32],
            session_id: vec![],
            cipher_suites: vec![0xc02f, 0x009c],
            compression_methods: vec![0],
            extensions: vec![],
        }
    }

    #[test]
    fn encode_without_extensions() {
        let rec = minimal().encode().unwrap();
        let mut expected = vec![22, 0x03, 0x01, 0x00, 0x2f, 1, 0x00, 0x00, 0x2b, 0x03, 0x03];
        expected.extend([0xaa; 32]);
        expected.extend([0, 0, 4, 0xc0, 0x2f, 0x00, 0x9c, 1, 0]);
        assert_eq!(rec, expected);
    }

    #[test]
    fn encode_extensions() {
        let mut ch = minimal();
        ch.extensions = vec![
            Extension::ServerName("a.b".into()),
            Extension::SupportedVersions(vec![ProtocolVersion::TLS13, ProtocolVersion::TLS12]),
            Extension::RenegotiationInfo,
            Extension::KeyShare(vec![KeyShareEntry {
                group: 29,
                key_exchange: vec![1, 2],
            }]),
        ];
        let hs = ch.encode_handshake().unwrap();
        let base = minimal().encode_handshake().unwrap();
        let exts = &hs[base.len()..];
        #[rustfmt::skip]
        let expected: &[u8] = &[
            0, 38,
            0, 0, 0, 8, 0, 6, 0, 0, 3, b'a', b'.', b'b',
            0, 43, 0, 5, 4, 3, 4, 3, 3,
            0xff, 1, 0, 1, 0,
            0, 51, 0, 8, 0, 6, 0, 29, 0, 2, 1, 2,
        ];
        assert_eq!(exts, expected);
        // Handshake length covers everything after the 4-byte header.
        let len = usize::from(hs[1]) << 16 | usize::from(hs[2]) << 8 | usize::from(hs[3]);
        assert_eq!(len, hs.len() - 4);
    }

    #[test]
    fn sslv2_hello() {
        let hello = Ssl2ClientHello {
            version: ProtocolVersion::SSL2,
            cipher_specs: vec![0x0007_00c0, 0x0001_0080],
            session_id: vec![],
            challenge: vec![0x11; 16],
        };
        let bytes = hello.encode().unwrap();
        #[rustfmt::skip]
        let mut expected = vec![
            0x80, 31, 1, 0x00, 0x02, 0, 6, 0, 0, 0, 16,
            0x07, 0x00, 0xc0, 0x01, 0x00, 0x80,
        ];
        expected.extend([0x11; 16]);
        assert_eq!(bytes, expected);
    }

    /// Fragmented encoding splits the handshake message across records
    /// whose bodies concatenate to the unfragmented message.
    #[test]
    fn fragmented_records() {
        let ch = minimal();
        let hs = ch.encode_handshake().unwrap();
        let bytes = ch.encode_fragmented(16).unwrap();
        let mut body: Vec<u8> = Vec::new();
        let mut rest = &bytes[..];
        let mut records = 0;
        while !rest.is_empty() {
            assert_eq!(&rest[..3], &[22, 3, 1]);
            let len = usize::from(u16::from_be_bytes([rest[3], rest[4]]));
            assert!(len <= 16);
            body.extend(&rest[5..5 + len]);
            rest = &rest[5 + len..];
            records += 1;
        }
        assert_eq!(body, hs);
        assert_eq!(records, hs.len().div_ceil(16));
        assert_eq!(
            ch.encode_fragmented(MAX_FRAGMENT_LEN).unwrap(),
            ch.encode().unwrap()
        );
        assert_eq!(
            ch.encode_fragmented(MAX_FRAGMENT_LEN + 1).unwrap(),
            ch.encode().unwrap()
        );
        assert_eq!(ch.encode_fragmented(0).unwrap().len(), hs.len() * 6);
    }

    #[test]
    fn oversized_record_rejected() {
        let mut ch = minimal();
        ch.cipher_suites = vec![0; 9000];
        assert!(matches!(
            ch.encode(),
            Err(EncodeError::TooLong {
                field: "record",
                ..
            })
        ));
    }
}
