# Integration test servers

`compose.yaml` starts OpenSSL `s_server` instances, a Postfix server
with SMTP STARTTLS (`Dockerfile.postfix`, port 14425), a Dovecot
server with IMAP and POP3 STARTTLS (`Dockerfile.dovecot`, ports 14143 and
14110), a vsftpd server with FTP `AUTH TLS` (`Dockerfile.vsftpd`, port
14021) and a Prosody server with XMPP STARTTLS (`Dockerfile.prosody`,
port 15222) used by `crates/testls/tests/servers.rs`.

`server.pem` (SAN `localhost`, `127.0.0.1`; valid 2026–2126) is signed by the
test CA in `ca.pem`. The CA key was discarded after signing. `server.key` is a
test-only key; never use it anywhere else.
