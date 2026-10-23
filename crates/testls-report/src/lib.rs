//! Text and JSON report renderers and exit-code policy.

mod colour;
pub mod text;

pub use colour::{ColorChoice, Painter, ParseColorChoiceError};
