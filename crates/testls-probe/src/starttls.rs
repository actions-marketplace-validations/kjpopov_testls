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
    /// IMAP `STARTTLS` (RFC 9051 §6.2.1).
    Imap,
    /// POP3 `STLS` (RFC 2595 §4).
    Pop3,
    /// FTP `AUTH TLS` (RFC 4217 §4).
    Ftp,
}

impl Starttls {
    /// All protocols, in the order they are listed on the command line.
    pub const ALL: [Self; 4] = [Self::Smtp, Self::Imap, Self::Pop3, Self::Ftp];

    /// Name used on the command line.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Smtp => "smtp",
            Self::Imap => "imap",
            Self::Pop3 => "pop3",
            Self::Ftp => "ftp",
        }
    }

    /// Well-known port of the protocol's plain-text service.
    #[must_use]
    pub fn default_port(self) -> u16 {
        match self {
            Self::Smtp => 25,
            Self::Imap => 143,
            Self::Pop3 => 110,
            Self::Ftp => 21,
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
            Self::Imap => imap(stream, reader).await,
            Self::Pop3 => pop3(stream, reader).await,
            Self::Ftp => ftp(stream, reader).await,
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

/// IMAP dialogue (RFC 9051 §6.1.1, §6.2.1, §7.1): `* OK` greeting,
/// `CAPABILITY` must list `STARTTLS`, then `STARTTLS` must be answered `OK`.
async fn imap(stream: &mut TcpStream, mut reader: Replies) -> Result<(), ProbeError> {
    let greeting = reader.line(stream).await?;
    if !greeting
        .strip_prefix("* ")
        .is_some_and(|rest| status_is(rest, "OK"))
    {
        return Err(error(format!("server answered greeting with {greeting:?}")));
    }
    send(stream, b"a CAPABILITY\r\n").await?;
    let caps = reader.imap(stream, "a").await?;
    expect_imap(&caps, "CAPABILITY")?;
    let offered = caps.iter().any(|l| {
        let mut words = l.split_ascii_whitespace();
        words.next() == Some("*")
            && words
                .next()
                .is_some_and(|w| w.eq_ignore_ascii_case("CAPABILITY"))
            && words.any(|w| w.eq_ignore_ascii_case("STARTTLS"))
    });
    if !offered {
        return Err(error("IMAP server does not offer STARTTLS".into()));
    }
    send(stream, b"b STARTTLS\r\n").await?;
    let ready = reader.imap(stream, "b").await?;
    expect_imap(&ready, "STARTTLS")?;
    reader.finish()
}

/// Fails unless the tagged (last) line of an IMAP response is `OK`.
fn expect_imap(lines: &[String], step: &str) -> Result<(), ProbeError> {
    let last = lines.last().map_or("", String::as_str);
    match last.split_once(' ') {
        Some((_, rest)) if status_is(rest, "OK") => Ok(()),
        _ => Err(error(format!("server answered {step} with {last:?}"))),
    }
}

/// POP3 dialogue (RFC 1939 §4, RFC 2449 §5, RFC 2595 §4): `+OK`
/// greeting, `CAPA` must list `STLS`, then `STLS` must be answered `+OK`.
async fn pop3(stream: &mut TcpStream, mut reader: Replies) -> Result<(), ProbeError> {
    let greeting = reader.line(stream).await?;
    // RFC 2449 §3: `greeting = "+OK" [resp-code] *gchar`, so text such as an
    // APOP timestamp may follow `+OK` without a space.
    if !greeting
        .get(..3)
        .is_some_and(|s| s.eq_ignore_ascii_case("+OK"))
    {
        return Err(error(format!("server answered greeting with {greeting:?}")));
    }
    send(stream, b"CAPA\r\n").await?;
    let status = reader.line(stream).await?;
    expect_pop3(&status, "CAPA")?;
    let mut offered = false;
    let mut total = 0;
    loop {
        let line = reader.line(stream).await?;
        if line == "." {
            break;
        }
        total += line.len();
        if total > MAX_REPLY {
            return Err(error(format!("server reply exceeds {MAX_REPLY} bytes")));
        }
        offered |= line
            .split_ascii_whitespace()
            .next()
            .is_some_and(|k| k.eq_ignore_ascii_case("STLS"));
    }
    if !offered {
        return Err(error("POP3 server does not offer STLS".into()));
    }
    send(stream, b"STLS\r\n").await?;
    let ready = reader.line(stream).await?;
    expect_pop3(&ready, "STLS")?;
    reader.finish()
}

/// Fails unless a POP3 command status line is exactly `+OK` or starts
/// with `+OK ` (RFC 2449 §3 `single-line`).
fn expect_pop3(line: &str, step: &str) -> Result<(), ProbeError> {
    if status_is(line, "+OK") {
        Ok(())
    } else {
        Err(error(format!("server answered {step} with {line:?}")))
    }
}

/// FTP dialogue (RFC 959 §4.2, RFC 4217 §4): 220 greeting, `AUTH TLS`,
/// expect 234. A server without TLS refuses `AUTH`, so `FEAT` is not needed.
async fn ftp(stream: &mut TcpStream, mut reader: Replies) -> Result<(), ProbeError> {
    let greeting = reader.ftp(stream).await?;
    expect(&greeting, 220, "greeting")?;
    send(stream, b"AUTH TLS\r\n").await?;
    let ready = reader.ftp(stream).await?;
    expect(&ready, 234, "AUTH TLS")?;
    reader.finish()
}

/// Reports whether the first space-separated word of `s` is the status
/// `token` (ASCII case-insensitive), so `OKAY` does not pass as `OK`.
fn status_is(s: &str, token: &str) -> bool {
    s.split(' ')
        .next()
        .is_some_and(|w| w.eq_ignore_ascii_case(token))
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

    /// Reads an FTP reply (RFC 959 §4.2): one `NNN text` line, or
    /// `NNN-text`, any lines, and a closing `NNN text` with the same code.
    async fn ftp(&mut self, stream: &mut TcpStream) -> Result<Reply, ProbeError> {
        let first = self.line(stream).await?;
        let bytes = first.as_bytes();
        let malformed = || error(format!("malformed server reply {first:?}"));
        if bytes.len() < 3 || !bytes[..3].iter().all(u8::is_ascii_digit) {
            return Err(malformed());
        }
        let code: u16 = first[..3].parse().map_err(|_| malformed())?;
        let mut lines = vec![first.get(4..).unwrap_or("").to_owned()];
        match bytes.get(3) {
            None | Some(b' ') => return Ok(Reply { code, lines }),
            Some(b'-') => {}
            Some(_) => return Err(malformed()),
        }
        let prefix = first[..3].to_owned();
        let mut total = first.len();
        loop {
            let line = self.line(stream).await?;
            total += line.len();
            if total > MAX_REPLY {
                return Err(error(format!("server reply exceeds {MAX_REPLY} bytes")));
            }
            let last = line
                .strip_prefix(&prefix)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with(' '));
            lines.push(line);
            if last {
                return Ok(Reply { code, lines });
            }
        }
    }

    /// Reads IMAP response lines up to and including the one tagged
    /// `tag` (RFC 9051 §2.2.2); untagged lines come first.
    async fn imap(&mut self, stream: &mut TcpStream, tag: &str) -> Result<Vec<String>, ProbeError> {
        let mut lines = Vec::new();
        let mut total = 0;
        loop {
            let line = self.line(stream).await?;
            total += line.len();
            if total > MAX_REPLY {
                return Err(error(format!("server reply exceeds {MAX_REPLY} bytes")));
            }
            let tagged = line.split_once(' ').is_some_and(|(t, _)| t == tag);
            if !tagged && !line.starts_with("* ") {
                return Err(error(format!("malformed server reply {line:?}")));
            }
            lines.push(line);
            if tagged {
                return Ok(lines);
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

    /// Script of a fake server; see [`server`].
    type Script = &'static [(Option<&'static str>, &'static [u8])];

    /// Connects to `addr` and runs the SMTP upgrade.
    async fn upgrade(addr: SocketAddr) -> Result<(), ProbeError> {
        upgrade_with(Starttls::Smtp, addr).await
    }

    /// Connects to `addr` and runs the `protocol` upgrade.
    async fn upgrade_with(protocol: Starttls, addr: SocketAddr) -> Result<(), ProbeError> {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        protocol.upgrade(&mut stream, Vec::new()).await
    }

    /// Runs `protocol` against each script and checks the error mentions
    /// the expected text.
    async fn assert_errors(protocol: Starttls, cases: &[(Script, &str)]) {
        for &(script, expected) in cases {
            let (addr, _got) = server(script).await;
            let Err(ProbeError::Connect(e)) = upgrade_with(protocol, addr).await else {
                panic!("{protocol} upgrade accepted {script:?}");
            };
            assert!(e.to_string().contains(expected), "{e}");
        }
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
        assert_errors(Starttls::Smtp, &cases).await;
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

    /// The IMAP dialogue checks `CAPABILITY` and accepts a tagged `OK`.
    #[tokio::test]
    async fn imap_upgrade() {
        let (addr, got) = server(&[
            (None, b"* OK [CAPABILITY IMAP4rev1] ready\r\n"),
            (
                Some("a CAPABILITY"),
                b"* CAPABILITY IMAP4rev1 starttls LOGINDISABLED\r\na OK done\r\n",
            ),
            (Some("b STARTTLS"), b"b OK Begin TLS negotiation now\r\n"),
        ])
        .await;
        upgrade_with(Starttls::Imap, addr).await.unwrap();
        assert_eq!(got.await.unwrap(), ["a CAPABILITY", "b STARTTLS"]);
    }

    /// IMAP refusals, missing STARTTLS and injected bytes are connect errors.
    #[tokio::test]
    async fn imap_errors() {
        let cases: [(Script, &str); 7] = [
            (&[(None, b"* BYE busy\r\n")], "greeting with \"* BYE busy\""),
            (
                &[
                    (None, b"* OK hi\r\n"),
                    (Some("a CAPABILITY"), b"* CAPABILITY IMAP4rev1\r\na OK\r\n"),
                ],
                "does not offer STARTTLS",
            ),
            (
                &[
                    (None, b"* OK hi\r\n"),
                    (Some("a CAPABILITY"), b"garbage\r\n"),
                ],
                "malformed server reply",
            ),
            (
                &[
                    (None, b"* OK hi\r\n"),
                    (Some("a CAPABILITY"), b"* CAPABILITY STARTTLS\r\na OK\r\n"),
                    (Some("b STARTTLS"), b"b NO not now\r\n"),
                ],
                "STARTTLS with \"b NO not now\"",
            ),
            (
                &[
                    (None, b"* OK hi\r\n"),
                    (Some("a CAPABILITY"), b"* CAPABILITY STARTTLS\r\na OK\r\n"),
                    (Some("b STARTTLS"), b"b OKAY go\r\n"),
                ],
                "STARTTLS with \"b OKAY go\"",
            ),
            (&[(None, b"* OKAY hi\r\n")], "greeting with \"* OKAY hi\""),
            (
                &[
                    (None, b"* OK hi\r\n"),
                    (Some("a CAPABILITY"), b"* CAPABILITY STARTTLS\r\na OK\r\n"),
                    (Some("b STARTTLS"), b"b OK go\r\n* injected\r\n"),
                ],
                "data after its STARTTLS reply",
            ),
        ];
        assert_errors(Starttls::Imap, &cases).await;
    }

    /// The POP3 dialogue reads the multi-line `CAPA` list and sends `STLS`.
    #[tokio::test]
    async fn pop3_upgrade() {
        let (addr, got) = server(&[
            (None, b"+OK<1896.697170952@dbc.mtview.ca.us>\r\n"),
            (Some("CAPA"), b"+OK\r\nTOP\r\nstls\r\nSASL PLAIN\r\n.\r\n"),
            (Some("STLS"), b"+OK Begin TLS negotiation now\r\n"),
        ])
        .await;
        upgrade_with(Starttls::Pop3, addr).await.unwrap();
        assert_eq!(got.await.unwrap(), ["CAPA", "STLS"]);
    }

    /// POP3 refusals, missing STLS and injected bytes are connect errors.
    #[tokio::test]
    async fn pop3_errors() {
        let cases: [(Script, &str); 7] = [
            (&[(None, b"-ERR busy\r\n")], "greeting with \"-ERR busy\""),
            (&[(None, b"+O\r\n")], "greeting with \"+O\""),
            (
                &[(None, b"+OK hi\r\n"), (Some("CAPA"), b"-ERR unknown\r\n")],
                "CAPA with \"-ERR unknown\"",
            ),
            (
                &[
                    (None, b"+OK hi\r\n"),
                    (Some("CAPA"), b"+OK\r\nTOP\r\n.\r\n"),
                ],
                "does not offer STLS",
            ),
            (
                &[
                    (None, b"+OK hi\r\n"),
                    (Some("CAPA"), b"+OK\r\nSTLS\r\n.\r\n"),
                    (Some("STLS"), b"-ERR no\r\n"),
                ],
                "STLS with \"-ERR no\"",
            ),
            (
                &[
                    (None, b"+OK hi\r\n"),
                    (Some("CAPA"), b"+OK\r\nSTLS\r\n.\r\n"),
                    (Some("STLS"), b"+OKAY\r\n"),
                ],
                "STLS with \"+OKAY\"",
            ),
            (
                &[
                    (None, b"+OK hi\r\n"),
                    (Some("CAPA"), b"+OK\r\nSTLS\r\n.\r\n"),
                    (Some("STLS"), b"+OK go\r\n+OK injected\r\n"),
                ],
                "data after its STARTTLS reply",
            ),
        ];
        assert_errors(Starttls::Pop3, &cases).await;
    }

    /// The FTP dialogue accepts a multi-line greeting and sends `AUTH TLS`.
    #[tokio::test]
    async fn ftp_upgrade() {
        let (addr, got) = server(&[
            (
                None,
                b"220-Welcome\r\n  220 is not the end\r\n220 ready\r\n",
            ),
            (Some("AUTH TLS"), b"234 Proceed with negotiation.\r\n"),
        ])
        .await;
        upgrade_with(Starttls::Ftp, addr).await.unwrap();
        assert_eq!(got.await.unwrap(), ["AUTH TLS"]);
    }

    /// FTP refusals, garbage and injected bytes are connect errors.
    #[tokio::test]
    async fn ftp_errors() {
        let cases: [(Script, &str); 5] = [
            (&[(None, b"421 busy\r\n")], "greeting with 421 busy"),
            (&[(None, b"SSH-2.0-x\r\n")], "malformed server reply"),
            (&[(None, b"220-hi\r\n221 bye\r\n")], "closed the connection"),
            (
                &[
                    (None, b"220 hi\r\n"),
                    (
                        Some("AUTH TLS"),
                        b"530 Please login with USER and PASS.\r\n",
                    ),
                ],
                "AUTH TLS with 530",
            ),
            (
                &[
                    (None, b"220 hi\r\n"),
                    (Some("AUTH TLS"), b"234 go\r\n200 injected\r\n"),
                ],
                "data after its STARTTLS reply",
            ),
        ];
        assert_errors(Starttls::Ftp, &cases).await;
    }

    /// Names round-trip through `FromStr`, case-insensitively.
    #[test]
    fn names() {
        for p in Starttls::ALL {
            assert_eq!(p.as_str().to_uppercase().parse::<Starttls>(), Ok(p));
        }
        assert!("gopher".parse::<Starttls>().is_err());
        assert_eq!(Starttls::Smtp.default_port(), 25);
        assert_eq!(Starttls::Imap.default_port(), 143);
        assert_eq!(Starttls::Pop3.default_port(), 110);
        assert_eq!(Starttls::Ftp.default_port(), 21);
    }
}
