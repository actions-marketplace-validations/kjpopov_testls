//! Incremental interpretation of a server's reply to a `ClientHello`.

use testls_wire::{
    Alert, AnyRecord, ContentType, DecodeError, ServerHello, Ssl2ServerHello, handshake_type,
    parse_certificate_list, parse_handshake, parse_record,
};

/// How a server answered a single `ClientHello`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelloResponse {
    /// The server accepted the hello.
    ServerHello {
        /// The parsed `ServerHello` (or `HelloRetryRequest`).
        hello: ServerHello,
        /// DER certificates from a plaintext `Certificate` message (TLS 1.2
        /// and earlier), leaf first. Empty if none was seen.
        certificates: Vec<Vec<u8>>,
        /// Body of a plaintext `ServerKeyExchange` message (TLS 1.2 and
        /// earlier), if the server sent one.
        server_key_exchange: Option<Vec<u8>>,
    },
    /// The server accepted an SSLv2 `CLIENT-HELLO`.
    Ssl2(Ssl2ServerHello),
    /// The server rejected the hello with an alert.
    Alert(Alert),
    /// The server closed the connection without a usable reply.
    Closed,
}

/// Incremental parser fed with bytes read from the socket.
#[derive(Debug, Default)]
pub(crate) struct ResponseParser {
    buf: Vec<u8>,
    handshake: Vec<u8>,
    hello: Option<ServerHello>,
    certificates: Vec<Vec<u8>>,
    server_key_exchange: Option<Vec<u8>>,
}

impl ResponseParser {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Append freshly read bytes and try to reach a conclusion.
    ///
    /// Returns `Ok(None)` while more input is needed.
    pub(crate) fn push(&mut self, data: &[u8]) -> Result<Option<HelloResponse>, DecodeError> {
        let mut buf = std::mem::take(&mut self.buf);
        buf.extend_from_slice(data);
        let mut offset = 0;
        let result = loop {
            let Some((record, used)) = parse_record(&buf[offset..])? else {
                break None;
            };
            offset += used;
            if let Some(done) = self.on_record(record)? {
                break Some(done);
            }
        };
        buf.drain(..offset);
        self.buf = buf;
        Ok(result)
    }

    /// Conclude after the peer closed the connection.
    pub(crate) fn finish(self) -> HelloResponse {
        match self.hello {
            Some(hello) => HelloResponse::ServerHello {
                hello,
                certificates: self.certificates,
                server_key_exchange: self.server_key_exchange,
            },
            None => HelloResponse::Closed,
        }
    }

    fn on_record(&mut self, record: AnyRecord<'_>) -> Result<Option<HelloResponse>, DecodeError> {
        let record = match record {
            AnyRecord::Ssl2(r) => {
                if self.hello.is_some() {
                    return Err(DecodeError::Invalid {
                        field: "record_type",
                    });
                }
                return Ssl2ServerHello::parse(r.body).map(|h| Some(HelloResponse::Ssl2(h)));
            }
            AnyRecord::Tls(r) => r,
        };
        match record.content_type {
            ContentType::Handshake => {
                self.handshake.extend_from_slice(record.fragment);
                self.drain_handshake()
            }
            ContentType::Alert if self.hello.is_none() => {
                Alert::parse(record.fragment).map(|a| Some(HelloResponse::Alert(a)))
            }
            // After a ServerHello, anything that is not plaintext handshake
            // (CCS, encrypted TLS 1.3 records, a late alert) ends what we can see.
            _ if self.hello.is_some() => Ok(Some(self.take_done())),
            _ => Err(DecodeError::Invalid {
                field: "content_type",
            }),
        }
    }

    fn drain_handshake(&mut self) -> Result<Option<HelloResponse>, DecodeError> {
        let mut offset = 0;
        let mut done = false;
        while let Some((msg, used)) = parse_handshake(&self.handshake[offset..])? {
            offset += used;
            match (msg.typ, &self.hello) {
                (handshake_type::SERVER_HELLO, None) => {
                    let hello = ServerHello::parse(msg.body)?;
                    // TLS 1.3 and HRR: the rest of the flight is encrypted or absent.
                    done =
                        hello.is_hello_retry_request() || hello.negotiated_version()?.0 >= 0x0304;
                    self.hello = Some(hello);
                }
                (_, None) => {
                    return Err(DecodeError::Invalid {
                        field: "handshake_type",
                    });
                }
                (handshake_type::CERTIFICATE, Some(_)) => {
                    self.certificates = parse_certificate_list(msg.body)?;
                }
                (handshake_type::SERVER_KEY_EXCHANGE, Some(_)) => {
                    self.server_key_exchange = Some(msg.body.to_vec());
                }
                (handshake_type::SERVER_HELLO_DONE, Some(_)) => done = true,
                _ => {}
            }
            if done {
                break;
            }
        }
        self.handshake.drain(..offset);
        Ok(done.then(|| self.take_done()))
    }

    fn take_done(&mut self) -> HelloResponse {
        std::mem::take(self).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use testls_wire::{AlertLevel, ProtocolVersion};

    fn record(typ: u8, body: &[u8]) -> Vec<u8> {
        let mut v = vec![typ, 3, 3];
        v.extend_from_slice(&u16::try_from(body.len()).unwrap().to_be_bytes());
        v.extend_from_slice(body);
        v
    }

    fn handshake(typ: u8, body: &[u8]) -> Vec<u8> {
        let len = u32::try_from(body.len()).unwrap().to_be_bytes();
        let mut v = vec![typ, len[1], len[2], len[3]];
        v.extend_from_slice(body);
        v
    }

    fn server_hello(version: u16, exts: &[u8]) -> Vec<u8> {
        let mut b = version.to_be_bytes().to_vec();
        b.extend_from_slice(&[7; 32]);
        b.push(0);
        b.extend_from_slice(&[0xc0, 0x2f, 0]);
        if !exts.is_empty() {
            b.extend_from_slice(&u16::try_from(exts.len()).unwrap().to_be_bytes());
            b.extend_from_slice(exts);
        }
        handshake(2, &b)
    }

    #[test]
    fn alert() {
        let mut p = ResponseParser::new();
        let r = p.push(&record(21, &[2, 40])).unwrap();
        assert_eq!(
            r,
            Some(HelloResponse::Alert(Alert {
                level: AlertLevel::Fatal,
                description: Alert::HANDSHAKE_FAILURE
            }))
        );
    }

    #[test]
    fn tls12_flight_split_across_reads() {
        let cert = handshake(11, &[0, 0, 6, 0, 0, 3, 1, 2, 3]);
        let mut flight = server_hello(0x0303, &[]);
        flight.extend_from_slice(&cert);
        flight.extend_from_slice(&handshake(12, &[3, 0, 0x17, 1, 4]));
        flight.extend_from_slice(&handshake(14, &[]));
        let bytes = record(22, &flight);

        let mut p = ResponseParser::new();
        for chunk in bytes.chunks(7) {
            if let Some(r) = p.push(chunk).unwrap() {
                let HelloResponse::ServerHello {
                    hello,
                    certificates,
                    server_key_exchange,
                } = r
                else {
                    panic!("unexpected {r:?}");
                };
                assert_eq!(hello.cipher_suite, 0xc02f);
                assert_eq!(certificates, vec![vec![1, 2, 3]]);
                assert_eq!(server_key_exchange, Some(vec![3, 0, 0x17, 1, 4]));
                return;
            }
        }
        panic!("no conclusion");
    }

    #[test]
    fn tls13_stops_after_server_hello() {
        let sh = server_hello(0x0303, &[0, 43, 0, 2, 3, 4]);
        let mut p = ResponseParser::new();
        let r = p.push(&record(22, &sh)).unwrap().unwrap();
        let HelloResponse::ServerHello { hello, .. } = r else {
            panic!()
        };
        assert_eq!(hello.negotiated_version().unwrap(), ProtocolVersion::TLS13);
    }

    #[test]
    fn close_after_partial_flight() {
        let mut p = ResponseParser::new();
        assert_eq!(
            p.push(&record(22, &server_hello(0x0301, &[]))).unwrap(),
            None
        );
        assert!(matches!(p.finish(), HelloResponse::ServerHello { .. }));
        assert_eq!(ResponseParser::new().finish(), HelloResponse::Closed);
    }

    #[test]
    fn garbage_is_an_error() {
        let mut p = ResponseParser::new();
        assert!(p.push(b"HTTP/1.1 400 Bad Request\r\n").is_err());
    }
}
