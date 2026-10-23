//! TLS record and handshake codec: `ClientHello` builders and `ServerHello`,
//! `Alert`, and `Certificate` parsers. No I/O.

mod client_hello;
mod codec;
mod version;

pub use client_hello::{
    CONTENT_HANDSHAKE, ClientHello, Extension, HANDSHAKE_CLIENT_HELLO, KeyShareEntry,
    MAX_FRAGMENT_LEN, Ssl2ClientHello, ext,
};
pub use codec::EncodeError;
pub use version::ProtocolVersion;
