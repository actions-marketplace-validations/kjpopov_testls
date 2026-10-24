//! Text and JSON report renderers and exit-code policy.

mod colour;
mod format;
pub mod json;
pub mod text;

pub use colour::{ColorChoice, Painter, ParseColorChoiceError};
pub use format::{Format, ParseFormatError};
