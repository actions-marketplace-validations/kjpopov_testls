//! Low-level big-endian writer with TLS-style length prefixes.

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
}
