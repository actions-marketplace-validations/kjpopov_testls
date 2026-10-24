//! Output format choice.

use std::fmt;
use std::str::FromStr;

/// Report format, as chosen with `--format`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Format {
    /// Human-readable text, printed section by section.
    #[default]
    Text,
    /// One JSON document printed when the scan finishes.
    Json,
}

impl Format {
    /// All formats, in the order shown in `--help`.
    pub const ALL: [Self; 2] = [Self::Text, Self::Json];

    /// Lower-case name, as used on the command line.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Json => "json",
        }
    }
}

impl fmt::Display for Format {
    /// Writes the command-line name.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Error returned when parsing an unknown format name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseFormatError(String);

impl fmt::Display for ParseFormatError {
    /// Names the rejected value.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown format {:?}", self.0)
    }
}

impl std::error::Error for ParseFormatError {}

impl FromStr for Format {
    type Err = ParseFormatError;

    /// Parses `text` or `json`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|f| f.as_str() == s)
            .ok_or_else(|| ParseFormatError(s.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Names round-trip through `FromStr` and unknown names are rejected.
    #[test]
    fn parse() {
        for f in Format::ALL {
            assert_eq!(f.as_str().parse::<Format>(), Ok(f));
            assert_eq!(f.to_string(), f.as_str());
        }
        assert!("xml".parse::<Format>().is_err());
        assert_eq!(Format::default(), Format::Text);
    }
}
