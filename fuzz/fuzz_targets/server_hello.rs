//! Parses arbitrary bytes as a `ServerHello` handshake body.

#![no_main]

use libfuzzer_sys::fuzz_target;
use testls_wire::ServerHello;

fuzz_target!(|data: &[u8]| {
    let _ = ServerHello::parse(data);
});
