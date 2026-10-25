//! Session and downgrade details: extended master secret, the TLS 1.3
//! downgrade sentinel, session tickets and 0-RTT.
//!
//! One raw hello at the highest TLS 1.0 to 1.2 version offers
//! `extended_master_secret` (RFC 7627). If the server also supports
//! TLS 1.3, the same reply must carry the downgrade sentinel in the last
//! eight bytes of its random (RFC 8446, section 4.1.3). A full TLS 1.3
//! handshake through rustls then records any `NewSessionTicket` and the
//! 0-RTT limit it advertises (RFC 8446, sections 4.6.1 and 4.2.10).

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use rustls::NamedGroup;
use rustls::client::{
    ClientSessionStore, Resumption, Tls12ClientSessionValue, Tls13ClientSessionValue,
};
use rustls::pki_types::ServerName;
use testls_wire::{ClientHello, Extension, ProtocolVersion, ServerHello, ext};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::time::{Instant, timeout};

use crate::certificates::{client_config, connect_tls};
use crate::hello::client_hello;
use crate::{CipherResult, HelloResponse, ProbeError, Transport};

/// Sentinel a TLS 1.3 server puts in a TLS 1.2 `ServerHello` random.
const DOWNGRADE_TLS12: [u8; 8] = *b"DOWNGRD\x01";
/// Sentinel a TLS 1.3 server puts in a TLS 1.1-or-older `ServerHello`
/// random.
const DOWNGRADE_TLS11: [u8; 8] = *b"DOWNGRD\x00";
/// Longest wait for session tickets after the handshake.
const TICKET_WAIT: Duration = Duration::from_secs(1);
/// Poll interval while waiting for session tickets.
const TICKET_POLL: Duration = Duration::from_millis(50);
/// How long to keep collecting tickets after the first one arrives.
const TICKET_GRACE: Duration = Duration::from_millis(200);

/// Details found by [`probe_details`].
///
/// `None` means the detail could not be tested: the server lacks the
/// protocol version it applies to, or refused the probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeDetails {
    /// Version of the raw extended master secret and downgrade hello.
    pub legacy_version: Option<ProtocolVersion>,
    /// Whether the server echoed `extended_master_secret`.
    pub extended_master_secret: Option<bool>,
    /// Whether a TLS 1.3 server marked the older handshake with the
    /// downgrade sentinel.
    pub downgrade_sentinel: Option<bool>,
    /// Whether the server issued a TLS 1.3 session ticket.
    pub session_tickets: Option<bool>,
    /// Largest 0-RTT data size a ticket allowed (0 means no 0-RTT).
    pub max_early_data: Option<u32>,
}

/// Probe extended master secret, the downgrade sentinel, session tickets
/// and 0-RTT.
///
/// `ciphers` are the results of
/// [`enumerate_ciphers`](crate::enumerate_ciphers) for every version the
/// server supports. Costs at most two connections.
///
/// # Errors
/// Returns a [`ProbeError`] if the raw hello fails for reasons other than
/// the server refusing it. A failed TLS 1.3 handshake only leaves the
/// ticket fields unset.
pub async fn probe_details(
    transport: &Transport,
    ciphers: &[CipherResult],
    sni: Option<&str>,
) -> Result<HandshakeDetails, ProbeError> {
    let tls13 = ciphers
        .iter()
        .any(|c| c.version == ProtocolVersion::TLS13 && !c.suites.is_empty());
    let legacy = ciphers
        .iter()
        .filter(|c| {
            (ProtocolVersion::TLS10..=ProtocolVersion::TLS12).contains(&c.version)
                && !c.suites.is_empty()
        })
        .max_by_key(|c| c.version);
    let mut details = HandshakeDetails {
        legacy_version: None,
        extended_master_secret: None,
        downgrade_sentinel: None,
        session_tickets: None,
        max_early_data: None,
    };

    if let Some(legacy) = legacy {
        let suites: Vec<u16> = legacy
            .suites
            .iter()
            .filter_map(|&s| u16::try_from(s).ok())
            .collect();
        let hello = ems_hello(legacy.version, suites.clone(), sni);
        details.legacy_version = Some(legacy.version);
        if let Some(sh) = accepted(transport, &hello, legacy.version, &suites).await? {
            details.extended_master_secret =
                Some(sh.extension(ext::EXTENDED_MASTER_SECRET) == Some(&[][..]));
            if tls13 {
                details.downgrade_sentinel = Some(has_sentinel(&sh, legacy.version));
            }
        }
    }

    if tls13 && let Some(seen) = tickets(transport, sni).await {
        details.session_tickets = Some(!seen.is_empty());
        details.max_early_data = Some(seen.into_iter().max().unwrap_or(0));
    }
    Ok(details)
}

/// A standard hello at `version` that also offers an empty
/// `extended_master_secret` extension.
fn ems_hello(version: ProtocolVersion, suites: Vec<u16>, sni: Option<&str>) -> ClientHello {
    let mut hello = client_hello(version, suites, sni);
    hello.extensions.push(Extension::Raw {
        typ: ext::EXTENDED_MASTER_SECRET,
        data: Vec::new(),
    });
    hello
}

/// Send `hello` and return the `ServerHello` if it completed at `version`
/// with one of `suites`; a reset or other reply yields `None`.
async fn accepted(
    transport: &Transport,
    hello: &ClientHello,
    version: ProtocolVersion,
    suites: &[u16],
) -> Result<Option<ServerHello>, ProbeError> {
    let bytes = hello.encode().map_err(ProbeError::Encode)?;
    let response = match transport.exchange(&bytes).await {
        Ok(r) => r,
        Err(ProbeError::Io(_)) => return Ok(None),
        Err(e) => return Err(e),
    };
    let HelloResponse::ServerHello { hello, .. } = response else {
        return Ok(None);
    };
    if hello.is_hello_retry_request()
        || !suites.contains(&hello.cipher_suite)
        || hello.negotiated_version().map_err(ProbeError::Decode)? != version
    {
        return Ok(None);
    }
    Ok(Some(hello))
}

/// Whether the `ServerHello` random ends with the sentinel RFC 8446
/// (section 4.1.3) requires for a handshake at `version`.
fn has_sentinel(hello: &ServerHello, version: ProtocolVersion) -> bool {
    let expected = if version == ProtocolVersion::TLS12 {
        DOWNGRADE_TLS12
    } else {
        DOWNGRADE_TLS11
    };
    hello.random[24..] == expected
}

/// Complete a TLS 1.3 handshake and return the 0-RTT limit of every
/// session ticket received, or `None` if no TLS 1.3 session was made.
async fn tickets(transport: &Transport, sni: Option<&str>) -> Option<Vec<u32>> {
    let recorder = Arc::new(TicketRecorder::default());
    let mut config = client_config();
    config.resumption = Resumption::store(recorder.clone());
    let mut tls = connect_tls(transport, sni, config).await.ok()?;
    if tls.get_ref().1.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3) {
        return None;
    }
    collect_tickets(&mut tls, &recorder, TICKET_WAIT.min(transport.read_timeout)).await;
    Some(recorder.take())
}

/// Read from `stream` so tickets get processed, for up to `wait`. Keeps
/// reading for [`TICKET_GRACE`] after the first ticket, since later tickets
/// may allow more 0-RTT data.
async fn collect_tickets<S: AsyncRead + Unpin>(
    stream: &mut S,
    recorder: &TicketRecorder,
    wait: Duration,
) {
    let mut deadline = Instant::now() + wait;
    let mut first_seen = false;
    let mut buf = [0u8; 1024];
    while Instant::now() < deadline {
        if !first_seen && !recorder.is_empty() {
            first_seen = true;
            deadline = deadline.min(Instant::now() + TICKET_GRACE);
        }
        match timeout(TICKET_POLL, stream.read(&mut buf)).await {
            Err(_) | Ok(Ok(1..)) => {}
            Ok(Ok(0) | Err(_)) => break,
        }
    }
}

/// Session store that keeps only the 0-RTT limit of each TLS 1.3 ticket
/// and never offers resumption.
#[derive(Debug, Default)]
struct TicketRecorder {
    /// `max_early_data_size` of every ticket received.
    early_data: Mutex<Vec<u32>>,
}

impl TicketRecorder {
    /// Whether no ticket has arrived yet.
    fn is_empty(&self) -> bool {
        self.early_data
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_empty()
    }

    /// Record one ticket's 0-RTT limit.
    fn record(&self, max_early_data: u32) {
        self.early_data
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(max_early_data);
    }

    /// The recorded 0-RTT limits.
    fn take(&self) -> Vec<u32> {
        std::mem::take(
            &mut *self
                .early_data
                .lock()
                .unwrap_or_else(PoisonError::into_inner),
        )
    }
}

impl ClientSessionStore for TicketRecorder {
    /// Ignores key exchange hints.
    fn set_kx_hint(&self, _: ServerName<'static>, _: NamedGroup) {}

    /// Never hints a key exchange group.
    fn kx_hint(&self, _: &ServerName<'_>) -> Option<NamedGroup> {
        None
    }

    /// Ignores TLS 1.2 sessions.
    fn set_tls12_session(&self, _: ServerName<'static>, _: Tls12ClientSessionValue) {}

    /// Never resumes a TLS 1.2 session.
    fn tls12_session(&self, _: &ServerName<'_>) -> Option<Tls12ClientSessionValue> {
        None
    }

    /// Nothing to remove.
    fn remove_tls12_session(&self, _: &ServerName<'static>) {}

    /// Records the ticket's 0-RTT limit.
    fn insert_tls13_ticket(&self, _: ServerName<'static>, value: Tls13ClientSessionValue) {
        self.record(value.max_early_data_size());
    }

    /// Never resumes a TLS 1.3 session.
    fn take_tls13_ticket(&self, _: &ServerName<'static>) -> Option<Tls13ClientSessionValue> {
        None
    }
}

#[cfg(test)]
mod tests {
    //! Tests against a rustls server and a raw mock server.

    use super::*;
    use crate::CipherOrder;
    use rustls::ServerConfig;
    use rustls::crypto::ring;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use std::net::SocketAddr;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    /// Self-signed P-256 certificate for `localhost`.
    const CERT: &[u8] = include_bytes!("testdata/localhost.cert.der");
    /// PKCS#8 private key for [`CERT`].
    const KEY: &[u8] = include_bytes!("testdata/localhost.key.der");

    /// Cipher results for `versions`, each with one ECDHE-ECDSA suite.
    fn results(versions: &[ProtocolVersion]) -> Vec<CipherResult> {
        versions
            .iter()
            .map(|&version| CipherResult {
                version,
                suites: vec![if version == ProtocolVersion::TLS13 {
                    0x1301
                } else {
                    0xc02b
                }],
                order: CipherOrder::NotApplicable,
            })
            .collect()
    }

    /// Starts a rustls server for TLS 1.2 and 1.3 that issues
    /// `tickets` session tickets allowing `early_data` bytes of 0-RTT.
    async fn serve_rustls(tickets: usize, early_data: u32) -> SocketAddr {
        let mut config = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS12, &rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(CERT.to_vec())],
                PrivateKeyDer::try_from(KEY.to_vec()).unwrap(),
            )
            .unwrap();
        config.send_tls13_tickets = tickets;
        config.max_early_data_size = early_data;
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (s, _) = listener.accept().await.unwrap();
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    if let Ok(mut tls) = acceptor.accept(s).await {
                        let mut buf = [0u8; 64];
                        while matches!(tls.read(&mut buf).await, Ok(1..)) {}
                    }
                });
            }
        });
        addr
    }

    /// Starts a raw server answering every hello with a TLS 1.2
    /// `ServerHello` using `random` and `extensions`.
    async fn serve_raw(random: [u8; 32], extensions: Vec<u8>) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = listener.accept().await.unwrap();
                let mut buf = vec![0u8; 4096];
                let mut n = 0;
                while n < 5 || n < 5 + usize::from(u16::from_be_bytes([buf[3], buf[4]])) {
                    match s.read(&mut buf[n..]).await {
                        Ok(0) | Err(_) => break,
                        Ok(k) => n += k,
                    }
                }
                let mut body = vec![3, 3];
                body.extend_from_slice(&random);
                body.extend_from_slice(&[0, 0xc0, 0x2b, 0]);
                body.extend_from_slice(&u16::try_from(extensions.len()).unwrap().to_be_bytes());
                body.extend_from_slice(&extensions);
                let mut hs = vec![2, 0];
                hs.extend_from_slice(&u16::try_from(body.len()).unwrap().to_be_bytes());
                hs.extend_from_slice(&body);
                hs.extend_from_slice(&[14, 0, 0, 0]);
                let mut record = vec![22, 3, 3];
                record.extend_from_slice(&u16::try_from(hs.len()).unwrap().to_be_bytes());
                record.extend_from_slice(&hs);
                let _ = s.write_all(&record).await;
            }
        });
        addr
    }

    /// rustls signals EMS and the sentinel, and issues tickets with 0-RTT.
    #[tokio::test]
    async fn rustls_server() {
        let addr = serve_rustls(2, 16384).await;
        let versions = [ProtocolVersion::TLS12, ProtocolVersion::TLS13];
        let d = probe_details(
            &Transport::new(addr),
            &results(&versions),
            Some("localhost"),
        )
        .await
        .unwrap();
        assert_eq!(
            d,
            HandshakeDetails {
                legacy_version: Some(ProtocolVersion::TLS12),
                extended_master_secret: Some(true),
                downgrade_sentinel: Some(true),
                session_tickets: Some(true),
                max_early_data: Some(16384),
            }
        );
    }

    /// Tickets without 0-RTT, and no tickets at all.
    #[tokio::test]
    async fn tickets_without_early_data() {
        let tls13 = results(&[ProtocolVersion::TLS13]);
        let addr = serve_rustls(1, 0).await;
        let d = probe_details(&Transport::new(addr), &tls13, None)
            .await
            .unwrap();
        assert_eq!(d.legacy_version, None);
        assert_eq!(d.extended_master_secret, None);
        assert_eq!(d.downgrade_sentinel, None);
        assert_eq!((d.session_tickets, d.max_early_data), (Some(true), Some(0)));

        let addr = serve_rustls(0, 0).await;
        let d = probe_details(&Transport::new(addr), &tls13, None)
            .await
            .unwrap();
        assert_eq!(
            (d.session_tickets, d.max_early_data),
            (Some(false), Some(0))
        );
    }

    /// A server without EMS that claims TLS 1.3 but omits the sentinel.
    #[tokio::test]
    async fn missing_ems_and_sentinel() {
        let addr = serve_raw([7; 32], Vec::new()).await;
        let versions = [ProtocolVersion::TLS12, ProtocolVersion::TLS13];
        let d = probe_details(&Transport::new(addr), &results(&versions), None)
            .await
            .unwrap();
        assert_eq!(d.extended_master_secret, Some(false));
        assert_eq!(d.downgrade_sentinel, Some(false));
        assert_eq!(d.session_tickets, None);
        assert_eq!(d.max_early_data, None);
    }

    /// The sentinel is only judged when TLS 1.3 is supported, and a
    /// non-empty EMS extension does not count.
    #[tokio::test]
    async fn sentinel_needs_tls13() {
        let mut random = [7; 32];
        random[24..].copy_from_slice(&DOWNGRADE_TLS12);
        let addr = serve_raw(random, vec![0, 23, 0, 1, 0]).await;
        let d = probe_details(
            &Transport::new(addr),
            &results(&[ProtocolVersion::TLS12]),
            None,
        )
        .await
        .unwrap();
        assert_eq!(d.extended_master_secret, Some(false));
        assert_eq!(d.downgrade_sentinel, None);
    }

    /// Stream that records one ticket limit per read, then stays silent.
    struct TicketStream {
        /// Recorder the "tickets" go to.
        recorder: Arc<TicketRecorder>,
        /// Limits still to deliver, in order.
        limits: Vec<u32>,
    }

    impl AsyncRead for TicketStream {
        /// Deliver the next ticket as one byte, or stay pending.
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            if self.limits.is_empty() {
                return std::task::Poll::Pending;
            }
            let limit = self.limits.remove(0);
            self.recorder.record(limit);
            buf.put_slice(&[0]);
            std::task::Poll::Ready(Ok(()))
        }
    }

    /// Tickets after the first are collected, so the largest limit wins.
    #[tokio::test]
    async fn later_tickets_are_collected() {
        let recorder = Arc::new(TicketRecorder::default());
        let mut stream = TicketStream {
            recorder: recorder.clone(),
            limits: vec![0, 1024, 16384],
        };
        collect_tickets(&mut stream, &recorder, TICKET_WAIT).await;
        assert_eq!(recorder.take(), vec![0, 1024, 16384]);
    }

    /// The TLS 1.1 sentinel differs from the TLS 1.2 one.
    #[test]
    fn sentinel_values() {
        let mut hello = ServerHello {
            legacy_version: ProtocolVersion::TLS11,
            random: [0; 32],
            session_id: Vec::new(),
            cipher_suite: 0xc013,
            compression_method: 0,
            extensions: Vec::new(),
        };
        hello.random[24..].copy_from_slice(&DOWNGRADE_TLS11);
        assert!(has_sentinel(&hello, ProtocolVersion::TLS11));
        assert!(!has_sentinel(&hello, ProtocolVersion::TLS12));
    }
}
