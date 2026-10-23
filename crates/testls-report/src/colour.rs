//! ANSI colouring of text output.
//!
//! Escape sequences are SGR codes from ECMA-48 §8.3.117. Colour is disabled
//! when the `NO_COLOR` environment variable is set (<https://no-color.org>).

use std::fmt;
use std::str::FromStr;

use testls_checks::Severity;

/// When to colour text output, as chosen with `--color`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ColorChoice {
    /// Colour only when writing to a terminal and `NO_COLOR` is unset.
    #[default]
    Auto,
    /// Always colour, even when output is redirected.
    Always,
    /// Never colour.
    Never,
}

impl ColorChoice {
    /// All choices, in the order shown in `--help`.
    pub const ALL: [Self; 3] = [Self::Auto, Self::Always, Self::Never];

    /// Lower-case name, as used on the command line.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Always => "always",
            Self::Never => "never",
        }
    }

    /// Decides whether to colour, given whether stdout is a terminal and the
    /// value of `NO_COLOR` (only a non-empty value disables colour).
    #[must_use]
    pub fn enabled(self, is_terminal: bool, no_color: Option<&str>) -> bool {
        match self {
            Self::Always => true,
            Self::Never => false,
            Self::Auto => is_terminal && no_color.is_none_or(str::is_empty),
        }
    }
}

impl fmt::Display for ColorChoice {
    /// Writes the command-line name.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Error returned when parsing an unknown colour choice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseColorChoiceError(String);

impl fmt::Display for ParseColorChoiceError {
    /// Names the rejected value.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown color choice {:?}", self.0)
    }
}

impl std::error::Error for ParseColorChoiceError {}

impl FromStr for ColorChoice {
    type Err = ParseColorChoiceError;

    /// Parses `auto`, `always`, or `never`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|c| c.as_str() == s)
            .ok_or_else(|| ParseColorChoiceError(s.to_owned()))
    }
}

/// Wraps text in ANSI escape sequences, or passes it through unchanged when
/// colour is disabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Painter {
    /// Whether escape sequences are emitted.
    enabled: bool,
}

impl Painter {
    /// Creates a painter that colours only if `enabled`.
    #[must_use]
    pub const fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    /// Reports whether this painter emits escape sequences.
    #[must_use]
    pub fn enabled(self) -> bool {
        self.enabled
    }

    /// Section heading, in bold.
    #[must_use]
    pub fn heading(self, text: &str) -> String {
        self.paint("1", text)
    }

    /// Text coloured by severity: green for ok, red for high, bold red for
    /// critical. Informational text is left uncoloured.
    #[must_use]
    pub fn severity(self, severity: Severity, text: &str) -> String {
        let code = match severity {
            Severity::Ok => "32",
            Severity::Info => return text.to_owned(),
            Severity::Low => "36",
            Severity::Medium => "33",
            Severity::High => "31",
            Severity::Critical => "1;31",
        };
        self.paint(code, text)
    }

    /// Wraps `text` in the SGR sequence `code` and a reset.
    fn paint(self, code: &str, text: &str) -> String {
        if self.enabled {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_owned()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `auto` follows the terminal and `NO_COLOR`; the others are fixed.
    #[test]
    fn choice_enabled() {
        assert!(ColorChoice::Auto.enabled(true, None));
        assert!(ColorChoice::Auto.enabled(true, Some("")));
        assert!(!ColorChoice::Auto.enabled(true, Some("1")));
        assert!(!ColorChoice::Auto.enabled(false, None));
        assert!(ColorChoice::Always.enabled(false, Some("1")));
        assert!(!ColorChoice::Never.enabled(true, None));
    }

    /// Names round-trip through `FromStr` and `Display`.
    #[test]
    fn choice_parse() {
        for choice in ColorChoice::ALL {
            assert_eq!(choice.to_string().parse::<ColorChoice>(), Ok(choice));
        }
        assert!("yes".parse::<ColorChoice>().is_err());
        assert_eq!(ColorChoice::default(), ColorChoice::Auto);
    }

    /// A disabled painter returns text unchanged.
    #[test]
    fn disabled_is_plain() {
        let p = Painter::new(false);
        assert_eq!(p.heading("Protocols"), "Protocols");
        assert_eq!(p.severity(Severity::Critical, "bad"), "bad");
    }

    /// An enabled painter wraps text in SGR codes, except for info.
    #[test]
    fn enabled_wraps() {
        let p = Painter::new(true);
        assert_eq!(p.heading("Protocols"), "\x1b[1mProtocols\x1b[0m");
        assert_eq!(p.severity(Severity::Ok, "good"), "\x1b[32mgood\x1b[0m");
        assert_eq!(
            p.severity(Severity::Critical, "bad"),
            "\x1b[1;31mbad\x1b[0m"
        );
        assert_eq!(p.severity(Severity::Info, "note"), "note");
    }
}
