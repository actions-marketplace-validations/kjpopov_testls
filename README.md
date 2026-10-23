# testls

> `$ test ls` does nothing. `testls` protects your web servers.

TLS/SSL scanner for the web era. A Rust-native reimplementation of
[testssl.sh](https://testssl.sh) with a built-in web service and browser-based UI.
Single static binary. No bash. No subprocess.

## Why

- Rust — memory-safe, fast, and packaged as a single static binary
- Web service — built-in HTTP server with a REST API and streaming results
- Browser component — inspect TLS behavior from the browser, not only the CLI
- Drop-in parity — same checks, same output format, and similar exit codes as testssl.sh

## Quick Start

```bash
# CLI
testls https://example.com

# Web service (serves UI + API on :8443)
testls --serve --port 8443
```

## Features

| Area | Details |
| --- | --- |
| Protocol detection | TLS 1.0–1.3, DTLS, STARTTLS |
| Cipher & curve audit | Full cipher suite enumeration, weak/obsolete flags |
| Certificate checks | Expiry, chain, SAN, revocation (OCSP/CRL) |
| HSTS & headers | Strict-Transport-Security, preload, header hygiene |
| Key exchange | ECDHE, RSA, X25519, post-quantum (ML-KEM) |
| Grading | A+–M scale, compatible with testssl.sh output |
| API | JSON + SSE streaming for CI/CD integration |
| Browser | In-browser TLS inspection panel |

## Architecture

```text
┌─────────────────────────────────────────────┐
│  Browser (WebExtension)                     │
│  └─ in-page TLS inspection panel            │
└──────────────────┬──────────────────────────┘
                   │ WebSocket / SSE
┌──────────────────▼──────────────────────────┐
│  testls (Rust, single binary)               │
│  ├─ TLS engine (rustls + native TLS)        │
│  ├─ Check runner (async, parallel)          │
│  ├─ HTTP server (axum)                      │
│  └─ CLI (clap)                              │
└─────────────────────────────────────────────┘
```

## Development

```bash
git clone https://github.com/you/testls
cargo build --release
cargo test
```

## Methodology

This project was designed and architected by the maintainer.
Implementation was assisted by LLM tooling; all code paths were designed,
reviewed, and tested by a human. See [CONTRIBUTING.md](CONTRIBUTING.md)
for our AI-assistance disclosure policy.

## License

MIT OR Apache-2.0 — choose whichever you prefer.

## Credits

Inspired by [testssl.sh](https://testssl.sh) by Dirk Wetter.
`testls` is an independent reimplementation, not a fork.

---

A few notes:

- Swap `you` in the clone URL for your GitHub username.
- This project is intentionally positioned as a practical TLS scanner for modern web infrastructure.
- The methodology section is deliberately low-key for transparency without turning the project into an AI story.

