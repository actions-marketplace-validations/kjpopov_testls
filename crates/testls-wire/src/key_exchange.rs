//! Parsers for the key exchange parameters in a TLS 1.2-and-earlier
//! `ServerKeyExchange` message.
//!
//! The layout depends on the negotiated cipher suite, so callers pick the
//! parser that matches it. Only the parameters are read; the signature that
//! follows them (absent for anonymous suites) is ignored.

use crate::codec::{DecodeError, Reader};

/// `ECCurveType.named_curve` (RFC 8422, section 5.4).
const NAMED_CURVE: u8 = 3;

/// `ServerECDHParams` of an ECDHE suite (RFC 8422, section 5.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdheParams {
    /// Named group code point of the curve.
    pub group: u16,
    /// The server's ephemeral public key.
    pub public_key: Vec<u8>,
}

impl EcdheParams {
    /// Parse the parameters at the start of a `ServerKeyExchange` body.
    ///
    /// # Errors
    /// Returns a [`DecodeError`] if the parameters are truncated or use an
    /// explicit curve, which RFC 8422 removed.
    pub fn parse(body: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(body);
        if r.u8("curve_type")? != NAMED_CURVE {
            return Err(DecodeError::Invalid {
                field: "curve_type",
            });
        }
        let group = r.u16("named_curve")?;
        let public_key = r.prefixed(1, "ecdh_public")?.rest().to_vec();
        Ok(Self { group, public_key })
    }
}

/// `ServerDHParams` of a DHE or anonymous DH suite (RFC 5246, section 7.4.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DheParams {
    /// Prime modulus, big-endian.
    pub p: Vec<u8>,
    /// Generator, big-endian.
    pub g: Vec<u8>,
    /// The server's ephemeral public value, big-endian.
    pub public_key: Vec<u8>,
}

impl DheParams {
    /// Parse the parameters at the start of a `ServerKeyExchange` body.
    ///
    /// # Errors
    /// Returns a [`DecodeError`] if the parameters are truncated or a value
    /// is empty.
    pub fn parse(body: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(body);
        let mut value = |field| {
            let v = r.prefixed(2, field)?.rest();
            if v.is_empty() {
                return Err(DecodeError::Invalid { field });
            }
            Ok(v.to_vec())
        };
        Ok(Self {
            p: value("dh_p")?,
            g: value("dh_g")?,
            public_key: value("dh_Ys")?,
        })
    }

    /// Size of the prime in bits, ignoring leading zero bytes.
    #[must_use]
    pub fn prime_bits(&self) -> usize {
        let mut bytes = self.p.iter().skip_while(|&&b| b == 0);
        bytes.next().map_or(0, |&first| {
            8 * bytes.count() + (8 - first.leading_zeros() as usize)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A named-curve x25519 key exchange followed by a signature.
    #[test]
    fn ecdhe_named_curve() {
        let body = [3, 0, 29, 2, 0xaa, 0xbb, 0x04, 0x03, 0, 1, 0xff];
        let p = EcdheParams::parse(&body).unwrap();
        assert_eq!(p.group, 29);
        assert_eq!(p.public_key, [0xaa, 0xbb]);
    }

    /// Explicit curves and truncated points are rejected.
    #[test]
    fn ecdhe_invalid() {
        assert_eq!(
            EcdheParams::parse(&[1, 0, 23, 0]),
            Err(DecodeError::Invalid {
                field: "curve_type"
            })
        );
        assert_eq!(
            EcdheParams::parse(&[3, 0, 23, 4, 1]),
            Err(DecodeError::Truncated {
                field: "ecdh_public"
            })
        );
    }

    /// DH parameters are read in order and the trailing signature ignored.
    #[test]
    fn dhe_params() {
        let body = [0, 2, 0x00, 0xb7, 0, 1, 2, 0, 1, 9, 0xde, 0xad];
        let p = DheParams::parse(&body).unwrap();
        assert_eq!(p.p, [0x00, 0xb7]);
        assert_eq!(p.g, [2]);
        assert_eq!(p.public_key, [9]);
        assert_eq!(p.prime_bits(), 8);
    }

    /// Empty or truncated values are rejected.
    #[test]
    fn dhe_invalid() {
        assert_eq!(
            DheParams::parse(&[0, 1, 7, 0, 0, 0, 1, 1]),
            Err(DecodeError::Invalid { field: "dh_g" })
        );
        assert_eq!(
            DheParams::parse(&[0, 1, 7, 0, 1, 2]),
            Err(DecodeError::Truncated { field: "dh_Ys" })
        );
    }

    /// Bit sizes count from the most significant set bit.
    #[test]
    fn prime_bits() {
        let bits = |p: &[u8]| {
            DheParams {
                p: p.to_vec(),
                g: vec![2],
                public_key: vec![1],
            }
            .prime_bits()
        };
        assert_eq!(bits(&[0x80; 256]), 2048);
        assert_eq!(bits(&[0, 0, 0x01, 0xff]), 9);
        assert_eq!(bits(&[0, 0]), 0);
    }
}
