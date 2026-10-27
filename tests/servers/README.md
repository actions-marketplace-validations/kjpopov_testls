# Integration test servers

`compose.yaml` starts OpenSSL `s_server` instances and a Postfix server
with SMTP STARTTLS (`Dockerfile.postfix`, port 14425) used by
`crates/testls/tests/servers.rs`.

`server.pem` (SAN `localhost`, `127.0.0.1`; valid 2026–2126) is signed by the
test CA in `ca.pem`. The CA key was discarded after signing. `server.key` is a
test-only key; never use it anywhere else.
