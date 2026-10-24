//! Parses arbitrary bytes as an SSLv2 `SERVER-HELLO` record body.

#![no_main]

use libfuzzer_sys::fuzz_target;
use testls_wire::Ssl2ServerHello;

fuzz_target!(|data: &[u8]| {
    let _ = Ssl2ServerHello::parse(data);
});
