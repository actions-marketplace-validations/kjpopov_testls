//! Low-level big-endian reader and writer with TLS-style length prefixes.

use std::fmt;

/// Error produced while encoding a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncodeError {
    /// A variable-length field exceeded the capacity of its length prefix.
    TooLong {
        /// Name of the field that overflowed.
        field: &'static str,
        /// Actual length in bytes.
        len: usize,
        /// Maximum allowed length in bytes.
        max: usize,
    },
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong { field, len, max } => {
                write!(f, "{field} is {len} bytes, maximum is {max}")
            }
        }
    }
}

impl std::error::Error for EncodeError {}

/// Error produced while decoding a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// Input ended before the field could be read.
    Truncated {
        /// Name of the field being read.
        field: &'static str,
    },
    /// A field held a value that is not valid in this position.
    Invalid {
        /// Name of the offending field.
        field: &'static str,
    },
    /// Bytes were left over after a complete structure was parsed.
    TrailingData {
        /// Name of the enclosing structure.
        field: &'static str,
    },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { field } => write!(f, "truncated while reading {field}"),
            Self::Invalid { field } => write!(f, "invalid value in {field}"),
            Self::TrailingData { field } => write!(f, "trailing data after {field}"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Append-only big-endian writer.
#[derive(Debug, Default)]
pub(crate) struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn into_inner(self) -> Vec<u8> {
        self.buf
    }

    pub(crate) fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    pub(crate) fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub(crate) fn bytes(&mut self, v: &[u8]) {
        self.buf.extend_from_slice(v);
    }

    /// Write `f`'s output preceded by a big-endian length of `width` bytes (1..=3).
    pub(crate) fn prefixed(
        &mut self,
        width: usize,
        field: &'static str,
        f: impl FnOnce(&mut Self) -> Result<(), EncodeError>,
    ) -> Result<(), EncodeError> {
        debug_assert!((1..=3).contains(&width));
        let start = self.buf.len();
        self.buf.resize(start + width, 0);
        f(self)?;
        let len = self.buf.len() - start - width;
        let max = (1usize << (8 * width)) - 1;
        if len > max {
            return Err(EncodeError::TooLong { field, len, max });
        }
        let be = len.to_be_bytes();
        self.buf[start..start + width].copy_from_slice(&be[be.len() - width..]);
        Ok(())
    }
}

/// Zero-copy big-endian reader over a byte slice.
#[derive(Debug, Clone)]
pub(crate) struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub(crate) fn rest(&mut self) -> &'a [u8] {
        std::mem::take(&mut self.buf)
    }

    pub(crate) fn take(&mut self, n: usize, field: &'static str) -> Result<&'a [u8], DecodeError> {
        if self.buf.len() < n {
            return Err(DecodeError::Truncated { field });
        }
        let (head, tail) = self.buf.split_at(n);
        self.buf = tail;
        Ok(head)
    }

    pub(crate) fn u8(&mut self, field: &'static str) -> Result<u8, DecodeError> {
        Ok(self.take(1, field)?[0])
    }

    pub(crate) fn u16(&mut self, field: &'static str) -> Result<u16, DecodeError> {
        let b = self.take(2, field)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    pub(crate) fn u24(&mut self, field: &'static str) -> Result<usize, DecodeError> {
        let b = self.take(3, field)?;
        Ok(usize::from(b[0]) << 16 | usize::from(b[1]) << 8 | usize::from(b[2]))
    }

    /// Read a length-prefixed sub-slice with a `width`-byte length (1..=3).
    pub(crate) fn prefixed(
        &mut self,
        width: usize,
        field: &'static str,
    ) -> Result<Reader<'a>, DecodeError> {
        let len = match width {
            1 => usize::from(self.u8(field)?),
            2 => usize::from(self.u16(field)?),
            3 => self.u24(field)?,
            _ => unreachable!("invalid length prefix width"),
        };
        Ok(Reader::new(self.take(len, field)?))
    }

    pub(crate) fn finish(&self, field: &'static str) -> Result<(), DecodeError> {
        if self.buf.is_empty() {
            Ok(())
        } else {
            Err(DecodeError::TrailingData { field })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_prefixes() {
        let mut w = Writer::new();
        w.prefixed(2, "outer", |w| {
            w.u8(1);
            w.prefixed(3, "inner", |w| {
                w.bytes(b"abc");
                Ok(())
            })
        })
        .unwrap();
        assert_eq!(w.into_inner(), [0, 7, 1, 0, 0, 3, b'a', b'b', b'c']);
    }

    #[test]
    fn prefixed_overflow() {
        let mut w = Writer::new();
        let err = w
            .prefixed(1, "small", |w| {
                w.bytes(&[0; 256]);
                Ok(())
            })
            .unwrap_err();
        assert_eq!(
            err,
            EncodeError::TooLong {
                field: "small",
                len: 256,
                max: 255
            }
        );
    }

    #[test]
    fn truncated() {
        let mut r = Reader::new(&[0, 5, 1]);
        assert_eq!(
            r.prefixed(2, "vec").unwrap_err(),
            DecodeError::Truncated { field: "vec" }
        );
    }
}
