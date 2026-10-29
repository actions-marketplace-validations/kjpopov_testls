-- XMPP test server: client STARTTLS required, TLS 1.2+, no accounts.
pidfile = "/tmp/prosody.pid"
log = { info = "*console" }
modules_enabled = { "tls"; "saslauth"; "disco" }
c2s_require_encryption = true
authentication = "internal_hashed"
ssl = {
  certificate = "/etc/prosody/certs/server.pem";
  key = "/etc/prosody/certs/server.key";
  protocol = "tlsv1_2+";
}
VirtualHost "localhost"
