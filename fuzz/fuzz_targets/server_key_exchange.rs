//! Parses arbitrary bytes as ECDHE and DHE `ServerKeyExchange` parameters.

#![no_main]

use libfuzzer_sys::fuzz_target;
use testls_wire::{DheParams, EcdheParams};

fuzz_target!(|data: &[u8]| {
    let _ = EcdheParams::parse(data);
    if let Ok(params) = DheParams::parse(data) {
        assert!(params.prime_bits() <= 8 * params.p.len());
    }
});
