//! Minimal DER reader and writer for the structures x509-parser does not
//! cover: OCSP requests and responses (RFC 6960) and the TLS feature
//! extension (RFC 7633).

/// DER tag of `SEQUENCE`.
pub(crate) const SEQUENCE: u8 = 0x30;
/// DER tag of `INTEGER`.
pub(crate) const INTEGER: u8 = 0x02;
/// DER tag of `BIT STRING`.
pub(crate) const BIT_STRING: u8 = 0x03;
/// DER tag of `OCTET STRING`.
pub(crate) const OCTET_STRING: u8 = 0x04;
/// DER tag of `NULL`.
pub(crate) const NULL: u8 = 0x05;
/// DER tag of `OBJECT IDENTIFIER`.
pub(crate) const OID: u8 = 0x06;
/// DER tag of `ENUMERATED`.
pub(crate) const ENUMERATED: u8 = 0x0a;
/// DER tag of `GeneralizedTime`.
pub(crate) const GENERALIZED_TIME: u8 = 0x18;

/// Context-specific constructed tag `[n]`.
pub(crate) const fn explicit(n: u8) -> u8 {
    0xa0 | n
}

/// Context-specific primitive tag `[n]`.
pub(crate) const fn implicit(n: u8) -> u8 {
    0x80 | n
}

/// Encodes one element with a low tag number and definite length.
pub(crate) fn encode(tag: u8, content: &[u8]) -> Vec<u8> {
    let len = content.len();
    let mut out = vec![tag];
    if len < 0x80 {
        out.push(u8::try_from(len).unwrap_or_default());
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|&&b| b == 0).count();
        out.push(0x80 | u8::try_from(bytes.len() - skip).unwrap_or_default());
        out.extend_from_slice(&bytes[skip..]);
    }
    out.extend_from_slice(content);
    out
}

/// One DER element.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Element<'a> {
    /// Identifier octet; only low tag numbers are supported.
    pub(crate) tag: u8,
    /// Content octets.
    pub(crate) content: &'a [u8],
    /// The whole encoding, header included.
    pub(crate) raw: &'a [u8],
}

/// Minimal reader for definite-length DER (X.690 §8.1, §10.1).
#[derive(Debug)]
pub(crate) struct Der<'a> {
    /// Bytes not yet read.
    input: &'a [u8],
}

impl<'a> Der<'a> {
    /// Reader over `input`.
    pub(crate) fn new(input: &'a [u8]) -> Self {
        Self { input }
    }

    /// Whether all input has been read.
    pub(crate) fn is_empty(&self) -> bool {
        self.input.is_empty()
    }

    /// Reads the next element.
    pub(crate) fn next(&mut self, field: &str) -> Result<Element<'a>, String> {
        let truncated = || format!("{field} is truncated");
        let input = self.input;
        let (&tag, rest) = input.split_first().ok_or_else(truncated)?;
        if tag & 0x1f == 0x1f {
            return Err(format!("{field} has an unsupported tag"));
        }
        let (&first, rest) = rest.split_first().ok_or_else(truncated)?;
        let (len, rest) = if first < 0x80 {
            (usize::from(first), rest)
        } else {
            let count = usize::from(first & 0x7f);
            if count == 0 || count > 4 || rest.len() < count {
                return Err(format!("{field} has an invalid length"));
            }
            let (bytes, rest) = rest.split_at(count);
            let len = bytes
                .iter()
                .fold(0usize, |len, &b| (len << 8) | usize::from(b));
            if bytes[0] == 0 || len < 0x80 {
                return Err(format!("{field} has a non-minimal length"));
            }
            (len, rest)
        };
        if rest.len() < len {
            return Err(truncated());
        }
        let header = input.len() - rest.len();
        let (raw, remaining) = input.split_at(header + len);
        self.input = remaining;
        Ok(Element {
            tag,
            content: &raw[header..],
            raw,
        })
    }

    /// Reads the next element, which must have `tag`, and returns its
    /// content.
    pub(crate) fn expect(&mut self, tag: u8, field: &str) -> Result<&'a [u8], String> {
        let element = self.next(field)?;
        if element.tag != tag {
            return Err(format!("{field} has an unexpected tag"));
        }
        Ok(element.content)
    }

    /// Reads the next element if it has `tag`, returning its content.
    pub(crate) fn optional(&mut self, tag: u8, field: &str) -> Result<Option<&'a [u8]>, String> {
        if self.input.first() == Some(&tag) {
            self.expect(tag, field).map(Some)
        } else {
            Ok(None)
        }
    }

    /// Fails if any input is left.
    pub(crate) fn finish(&self, field: &str) -> Result<(), String> {
        if self.is_empty() {
            Ok(())
        } else {
            Err(format!("{field} has trailing data"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encoded elements read back with the same tag and content, for short
    /// and long lengths.
    #[test]
    fn encode_round_trips() {
        for len in [0, 1, 0x7f, 0x80, 0xff, 0x100, 0x1_0000] {
            let content = vec![7u8; len];
            let encoded = encode(OCTET_STRING, &content);
            let mut der = Der::new(&encoded);
            assert_eq!(der.expect(OCTET_STRING, "x").unwrap(), content, "{len}");
            der.finish("x").unwrap();
        }
    }
}
