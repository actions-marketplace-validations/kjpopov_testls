//! Protocol version code points.

use std::fmt;

/// A TLS/SSL protocol version as it appears on the wire.
///
/// Unknown values are preserved so that odd server responses can be reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProtocolVersion(pub u16);

impl ProtocolVersion {
    /// SSL 2.0.
    pub const SSL2: Self = Self(0x0002);
    /// SSL 3.0.
    pub const SSL3: Self = Self(0x0300);
    /// TLS 1.0.
    pub const TLS10: Self = Self(0x0301);
    /// TLS 1.1.
    pub const TLS11: Self = Self(0x0302);
    /// TLS 1.2.
    pub const TLS12: Self = Self(0x0303);
    /// TLS 1.3.
    pub const TLS13: Self = Self(0x0304);

    /// All versions testls knows how to probe, oldest first.
    pub const ALL: [Self; 6] = [
        Self::SSL2,
        Self::SSL3,
        Self::TLS10,
        Self::TLS11,
        Self::TLS12,
        Self::TLS13,
    ];

    /// Human-readable name, or `None` for unknown code points.
    #[must_use]
    pub fn name(self) -> Option<&'static str> {
        Some(match self {
            Self::SSL2 => "SSLv2",
            Self::SSL3 => "SSLv3",
            Self::TLS10 => "TLSv1.0",
            Self::TLS11 => "TLSv1.1",
            Self::TLS12 => "TLSv1.2",
            Self::TLS13 => "TLSv1.3",
            _ => return None,
        })
    }
}

impl fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.name() {
            Some(n) => f.write_str(n),
            None => write!(f, "0x{:04x}", self.0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ProtocolVersion;

    #[test]
    fn display() {
        assert_eq!(ProtocolVersion::TLS12.to_string(), "TLSv1.2");
        assert_eq!(ProtocolVersion(0x7f1c).to_string(), "0x7f1c");
        assert!(ProtocolVersion::SSL3 < ProtocolVersion::TLS13);
    }
}
