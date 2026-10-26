//! Text, JSON, SARIF, JUnit, Markdown and CSV report renderers and
//! exit-code policy.

mod colour;
pub mod csv;
mod format;
pub mod json;
pub mod junit;
pub mod markdown;
pub mod sarif;
pub mod text;

pub use colour::{ColorChoice, Painter, ParseColorChoiceError};
pub use format::{Format, ParseFormatError};
