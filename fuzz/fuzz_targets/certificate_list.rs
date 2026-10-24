//! Parses arbitrary bytes as a TLS 1.2 `Certificate` handshake body and checks
//! that the certificates fit inside the input.

#![no_main]

use libfuzzer_sys::fuzz_target;
use testls_wire::parse_certificate_list;

fuzz_target!(|data: &[u8]| {
    if let Ok(certificates) = parse_certificate_list(data) {
        let total: usize = certificates.iter().map(|c| c.len() + 3).sum();
        assert_eq!(
            total + 3,
            data.len(),
            "certificates must cover the whole list"
        );
    }
});
