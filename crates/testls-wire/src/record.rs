//! Record framing for SSLv3/TLS and SSLv2 responses.

use crate::codec::{DecodeError, Reader};
use crate::version::ProtocolVersion;

/// TLS record content type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContentType {
    /// `change_cipher_spec` (20).
    ChangeCipherSpec,
    /// `alert` (21).
    Alert,
    /// `handshake` (22).
    Handshake,
    /// `application_data` (23).
    ApplicationData,
    /// Any other value.
    Unknown(u8),
}

impl From<u8> for ContentType {
    fn from(v: u8) -> Self {
        match v {
            20 => Self::ChangeCipherSpec,
            21 => Self::Alert,
            22 => Self::Handshake,
            23 => Self::ApplicationData,
            other => Self::Unknown(other),
        }
    }
}

/// A complete SSLv3/TLS record borrowed from an input buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record<'a> {
    /// Content type.
    pub content_type: ContentType,
    /// Record-layer version.
    pub version: ProtocolVersion,
    /// Record payload.
    pub fragment: &'a [u8],
}

/// Upper bound on accepted record payloads (2^14 plus the TLS 1.2
/// ciphertext expansion allowance).
const MAX_RECORD_LEN: usize = (1 << 14) + 2048;

/// A complete SSLv2 record (two-byte header form) borrowed from an input buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ssl2Record<'a> {
    /// Record payload, starting with the message type byte.
    pub body: &'a [u8],
}

/// Either kind of record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnyRecord<'a> {
    /// SSLv3/TLS record.
    Tls(Record<'a>),
    /// SSLv2 record.
    Ssl2(Ssl2Record<'a>),
}

/// Try to split one record off the front of `buf`.
///
/// Returns `Ok(None)` if more bytes are needed, otherwise the record and the
/// number of bytes it consumed. A first byte with the high bit set is
/// treated as an SSLv2 two-byte header.
///
/// # Errors
/// Returns [`DecodeError::Invalid`] for oversized records.
pub fn parse_record(buf: &[u8]) -> Result<Option<(AnyRecord<'_>, usize)>, DecodeError> {
    let Some(&first) = buf.first() else {
        return Ok(None);
    };
    if first & 0x80 != 0 {
        if buf.len() < 2 {
            return Ok(None);
        }
        let len = usize::from(u16::from_be_bytes([first & 0x7f, buf[1]]));
        let total = 2 + len;
        if buf.len() < total {
            return Ok(None);
        }
        return Ok(Some((
            AnyRecord::Ssl2(Ssl2Record {
                body: &buf[2..total],
            }),
            total,
        )));
    }
    if buf.len() < 5 {
        return Ok(None);
    }
    let mut r = Reader::new(buf);
    let content_type = ContentType::from(r.u8("content_type")?);
    let version = ProtocolVersion(r.u16("record_version")?);
    let len = usize::from(r.u16("record_length")?);
    if len > MAX_RECORD_LEN {
        return Err(DecodeError::Invalid {
            field: "record_length",
        });
    }
    let total = 5 + len;
    if buf.len() < total {
        return Ok(None);
    }
    Ok(Some((
        AnyRecord::Tls(Record {
            content_type,
            version,
            fragment: &buf[5..total],
        }),
        total,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn needs_more() {
        assert_eq!(parse_record(&[]), Ok(None));
        assert_eq!(parse_record(&[22, 3, 3, 0]), Ok(None));
        assert_eq!(parse_record(&[22, 3, 3, 0, 2, 1]), Ok(None));
        assert_eq!(parse_record(&[0x80]), Ok(None));
    }

    #[test]
    fn tls_record() {
        let buf = [21, 3, 1, 0, 2, 2, 40, 0xff];
        let (rec, used) = parse_record(&buf).unwrap().unwrap();
        assert_eq!(used, 7);
        assert_eq!(
            rec,
            AnyRecord::Tls(Record {
                content_type: ContentType::Alert,
                version: ProtocolVersion::TLS10,
                fragment: &[2, 40],
            })
        );
    }

    #[test]
    fn ssl2_record() {
        let buf = [0x80, 3, 4, 0, 1];
        let (rec, used) = parse_record(&buf).unwrap().unwrap();
        assert_eq!(used, 5);
        assert_eq!(rec, AnyRecord::Ssl2(Ssl2Record { body: &[4, 0, 1] }));
    }

    #[test]
    fn oversized() {
        assert!(parse_record(&[22, 3, 3, 0xff, 0xff]).is_err());
    }
}
