//! Plain-text protocol dialogues that switch a connection to TLS
//! (STARTTLS) before the first `ClientHello`.

use std::fmt;
use std::io;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::ProbeError;

/// Largest server reply accepted during the dialogue, in bytes.
const MAX_REPLY: usize = 64 * 1024;

/// Application protocol to upgrade to TLS before probing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Starttls {
    /// SMTP `STARTTLS` (RFC 3207).
    Smtp,
}

impl Starttls {
    /// All protocols, in the order they are listed on the command line.
    pub const ALL: [Self; 1] = [Self::Smtp];

    /// Name used on the command line.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Smtp => "smtp",
        }
    }

    /// Well-known port of the protocol's plain-text service.
    #[must_use]
    pub fn default_port(self) -> u16 {
        match self {
            Self::Smtp => 25,
        }
    }

    /// Runs the protocol's dialogue on `stream` until the server is ready
    /// for a `ClientHello`. `early` holds server bytes already read from
    /// `stream` (by a proxy tunnel) and is consumed first.
    ///
    /// # Errors
    /// Returns [`ProbeError::Connect`] when the server refuses, does not
    /// offer STARTTLS, sends a malformed or oversized reply, closes the
    /// connection, or sends bytes after its final reply (which would be
    /// injected into the TLS stream).
    pub(crate) async fn upgrade(
        self,
        stream: &mut TcpStream,
        early: Vec<u8>,
    ) -> Result<(), ProbeError> {
        let reader = Replies { data: early };
        match self {
            Self::Smtp => smtp(stream, reader).await,
        }
    }
}

impl fmt::Display for Starttls {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for Starttls {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|p| p.as_str().eq_ignore_ascii_case(s))
            .ok_or_else(|| format!("unknown STARTTLS protocol {s:?}"))
    }
}

/// Builds the error for a failed dialogue.
fn error(msg: String) -> ProbeError {
    ProbeError::Connect(io::Error::other(msg))
}

/// SMTP dialogue (RFC 5321 §4.2, RFC 3207 §4): greeting, `EHLO`, check
/// the `STARTTLS` keyword, `STARTTLS`, expect 220.
async fn smtp(stream: &mut TcpStream, mut reader: Replies) -> Result<(), ProbeError> {
    let greeting = reader.smtp(stream).await?;
    expect(&greeting, 220, "greeting")?;
    send(stream, b"EHLO testls.invalid\r\n").await?;
    let ehlo = reader.smtp(stream).await?;
    expect(&ehlo, 250, "EHLO")?;
    // Each line after the first is one extension keyword (RFC 5321 §4.1.1.1).
    if !ehlo.lines[1..].iter().any(|l| {
        l.split_ascii_whitespace()
            .next()
            .is_some_and(|k| k.eq_ignore_ascii_case("STARTTLS"))
    }) {
        return Err(error("SMTP server does not offer STARTTLS".into()));
    }
    send(stream, b"STARTTLS\r\n").await?;
    let ready = reader.smtp(stream).await?;
    expect(&ready, 220, "STARTTLS")?;
    reader.finish()
}

/// Writes `data` to `stream`.
async fn send(stream: &mut TcpStream, data: &[u8]) -> Result<(), ProbeError> {
    stream.write_all(data).await.map_err(ProbeError::Connect)
}

/// Fails unless `reply` has status `code`.
fn expect(reply: &Reply, code: u16, step: &str) -> Result<(), ProbeError> {
    if reply.code == code {
        return Ok(());
    }
    let text = reply.lines.first().map_or("", String::as_str);
    Err(error(format!(
        "server answered {step} with {} {text}",
        reply.code
    )))
}

/// One multi-line reply: status code and the text of each line.
#[derive(Debug, PartialEq, Eq)]
struct Reply {
    /// Three-digit status code.
    code: u16,
    /// Text after the code and separator on each line.
    lines: Vec<String>,
}

/// Buffered reader for line-based server replies.
#[derive(Debug, Default)]
struct Replies {
    /// Bytes received but not yet consumed.
    data: Vec<u8>,
}

impl Replies {
    /// Reads the next CRLF-terminated line, without the line ending.
    async fn line(&mut self, stream: &mut TcpStream) -> Result<String, ProbeError> {
        loop {
            if let Some(end) = self.data.windows(2).position(|w| w == b"\r\n") {
                let line = String::from_utf8_lossy(&self.data[..end]).into_owned();
                self.data.drain(..end + 2);
                return Ok(line);
            }
            if self.data.len() > MAX_REPLY {
                return Err(error(format!("server reply exceeds {MAX_REPLY} bytes")));
            }
            let mut buf = [0; 4096];
            let n = stream.read(&mut buf).await.map_err(ProbeError::Connect)?;
            if n == 0 {
                return Err(error("server closed the connection during STARTTLS".into()));
            }
            self.data.extend_from_slice(&buf[..n]);
        }
    }

    /// Reads an SMTP-style reply: lines of `NNN-text` ending with one
    /// `NNN text` (RFC 5321 §4.2.1).
    async fn smtp(&mut self, stream: &mut TcpStream) -> Result<Reply, ProbeError> {
        let mut lines = Vec::new();
        let mut code = None;
        let mut total = 0;
        loop {
            let line = self.line(stream).await?;
            total += line.len();
            if total > MAX_REPLY {
                return Err(error(format!("server reply exceeds {MAX_REPLY} bytes")));
            }
            let bytes = line.as_bytes();
            let malformed = || error(format!("malformed server reply {line:?}"));
            if bytes.len() < 3 || !bytes[..3].iter().all(u8::is_ascii_digit) {
                return Err(malformed());
            }
            let this: u16 = line[..3].parse().map_err(|_| malformed())?;
            if *code.get_or_insert(this) != this {
                return Err(malformed());
            }
            let last = match bytes.get(3) {
                None | Some(b' ') => true,
                Some(b'-') => false,
                Some(_) => return Err(malformed()),
            };
            lines.push(line.get(4..).unwrap_or("").to_owned());
            if last {
                return Ok(Reply { code: this, lines });
            }
        }
    }

    /// Fails when the server sent bytes past its last reply.
    fn finish(self) -> Result<(), ProbeError> {
        if self.data.is_empty() {
            Ok(())
        } else {
            Err(error("server sent data after its STARTTLS reply".into()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use tokio::net::TcpListener;

    /// Fake server that plays `script`: each entry is the client line it
    /// expects (none for the greeting) and the bytes it answers with.
    /// Returns its address and the lines it received.
    async fn server(
        script: &'static [(Option<&'static str>, &'static [u8])],
    ) -> (SocketAddr, tokio::task::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut got = Vec::new();
            let mut reader = Replies::default();
            for (expected, reply) in script {
                if let Some(expected) = expected {
                    let line = reader.line(&mut s).await.unwrap();
                    assert_eq!(&line, expected);
                    got.push(line);
                }
                s.write_all(reply).await.unwrap();
            }
            got
        });
        (addr, task)
    }

    /// Connects to `addr` and runs the SMTP upgrade.
    async fn upgrade(addr: SocketAddr) -> Result<(), ProbeError> {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        Starttls::Smtp.upgrade(&mut stream, Vec::new()).await
    }

    /// The dialogue sends EHLO and STARTTLS and accepts a multi-line
    /// greeting and EHLO reply.
    #[tokio::test]
    async fn smtp_upgrade() {
        let (addr, got) = server(&[
            (None, b"220-mx.example ESMTP\r\n220 ready\r\n"),
            (
                Some("EHLO testls.invalid"),
                b"250-mx.example\r\n250-PIPELINING\r\n250-starttls\r\n250 8BITMIME\r\n",
            ),
            (Some("STARTTLS"), b"220 2.0.0 go ahead\r\n"),
        ])
        .await;
        upgrade(addr).await.unwrap();
        assert_eq!(got.await.unwrap(), ["EHLO testls.invalid", "STARTTLS"]);
    }

    /// Refusals, missing STARTTLS, garbage and injected bytes are connect
    /// errors.
    #[tokio::test]
    async fn smtp_errors() {
        type Script = &'static [(Option<&'static str>, &'static [u8])];
        let cases: [(Script, &str); 6] = [
            (&[(None, b"554 go away\r\n")], "greeting with 554 go away"),
            (&[(None, b"SSH-2.0-x\r\n")], "malformed server reply"),
            (&[(None, b"220 hi")], "closed the connection"),
            (
                &[
                    (None, b"220 hi\r\n"),
                    (Some("EHLO testls.invalid"), b"250-mx\r\n250 SIZE 1\r\n"),
                ],
                "does not offer STARTTLS",
            ),
            (
                &[
                    (None, b"220 hi\r\n"),
                    (Some("EHLO testls.invalid"), b"250-mx\r\n250 STARTTLS\r\n"),
                    (Some("STARTTLS"), b"454 TLS not available\r\n"),
                ],
                "STARTTLS with 454",
            ),
            (
                &[
                    (None, b"220 hi\r\n"),
                    (Some("EHLO testls.invalid"), b"250-mx\r\n250 STARTTLS\r\n"),
                    (Some("STARTTLS"), b"220 go\r\n250 injected\r\n"),
                ],
                "data after its STARTTLS reply",
            ),
        ];
        for (script, expected) in cases {
            let (addr, _got) = server(script).await;
            let Err(ProbeError::Connect(e)) = upgrade(addr).await else {
                panic!("upgrade accepted {script:?}");
            };
            assert!(e.to_string().contains(expected), "{e}");
        }
    }

    /// Mixed codes within one reply are rejected.
    #[tokio::test]
    async fn smtp_mixed_codes() {
        let (addr, _got) = server(&[(None, b"220-hi\r\n250 there\r\n")]).await;
        let Err(ProbeError::Connect(e)) = upgrade(addr).await else {
            panic!("accepted mixed codes");
        };
        assert!(e.to_string().contains("malformed"), "{e}");
    }

    /// Names round-trip through `FromStr`, case-insensitively.
    #[test]
    fn names() {
        for p in Starttls::ALL {
            assert_eq!(p.as_str().to_uppercase().parse::<Starttls>(), Ok(p));
        }
        assert!("gopher".parse::<Starttls>().is_err());
        assert_eq!(Starttls::Smtp.default_port(), 25);
    }
}
