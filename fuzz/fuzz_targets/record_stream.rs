//! Feeds arbitrary bytes through record framing, handshake reassembly and
//! every server message parser, the way the probes read a server response.

#![no_main]

use libfuzzer_sys::fuzz_target;
use testls_wire::{
    Alert, AnyRecord, ContentType, DheParams, EcdheParams, ServerHello, Ssl2ServerHello, handshake_type,
    parse_certificate_list, parse_handshake, parse_record,
};

fuzz_target!(|data: &[u8]| {
    let mut rest = data;
    let mut handshake = Vec::new();
    while let Ok(Some((record, used))) = parse_record(rest) {
        assert!(
            used > 0 && used <= rest.len(),
            "record consumed {used} of {}",
            rest.len()
        );
        rest = &rest[used..];
        match record {
            AnyRecord::Ssl2(record) => {
                let _ = Ssl2ServerHello::parse(record.body);
            }
            AnyRecord::Tls(record) => match record.content_type {
                ContentType::Alert => {
                    let _ = Alert::parse(record.fragment);
                }
                ContentType::Handshake => handshake.extend_from_slice(record.fragment),
                _ => {}
            },
        }
    }
    let mut stream = handshake.as_slice();
    while let Ok(Some((message, used))) = parse_handshake(stream) {
        assert!(
            used >= 4 && used <= stream.len(),
            "handshake consumed {used} of {}",
            stream.len()
        );
        stream = &stream[used..];
        match message.typ {
            handshake_type::SERVER_HELLO => {
                let _ = ServerHello::parse(message.body);
            }
            handshake_type::CERTIFICATE => {
                let _ = parse_certificate_list(message.body);
            }
            handshake_type::SERVER_KEY_EXCHANGE => {
                let _ = EcdheParams::parse(message.body);
                let _ = DheParams::parse(message.body);
            }
            _ => {}
        }
    }
});
