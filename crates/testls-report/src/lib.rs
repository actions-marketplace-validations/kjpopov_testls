//! Text, JSON, SARIF, JUnit, Markdown, CSV and HTML report renderers and
//! exit-code policy.

mod colour;
pub mod csv;
mod format;
pub mod html;
pub mod json;
pub mod junit;
pub mod markdown;
pub mod sarif;
pub mod text;

pub use colour::{ColorChoice, Painter, ParseColorChoiceError};
pub use format::{Format, ParseFormatError};
