# testls

[![CI](https://github.com/kjpopov/testls/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/kjpopov/testls/actions/workflows/ci.yml)
[![Release](https://github.com/kjpopov/testls/actions/workflows/release.yml/badge.svg)](https://github.com/kjpopov/testls/actions/workflows/release.yml)
[![Latest release](https://img.shields.io/github/v/release/kjpopov/testls?include_prereleases&sort=semver)](https://github.com/kjpopov/testls/releases)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)

> `$ test ls` does nothing. `testls` protects your web servers.

TLS/SSL scanner for the web era, written in Rust and inspired by
[testssl.sh](https://testssl.sh). Single static binary. No bash. No subprocess.

> **Status: v0.3.** The command-line scanner checks protocols, cipher suites,
> key exchange, certificates, revocation, HTTP security headers, derived
> vulnerabilities, ClientHello tolerance and post-quantum readiness; the
> features marked v0.4 and later are planned. See
> [docs/PLAN.md](docs/PLAN.md) and [CHANGELOG.md](CHANGELOG.md).

## Why

- Rust — memory-safe, fast, and packaged as a single static binary
- Own handshake engine — probes legacy and modern protocols (SSLv2–TLS 1.3)
  without linking OpenSSL
- Web service (planned) — built-in HTTP server with a REST API, streaming
  results, and an embedded browser UI

## Install

Download a prebuilt binary for Linux (static musl, x86_64/aarch64), macOS
(x86_64/arm64), or Windows (x86_64) from the
[releases page](https://github.com/kjpopov/testls/releases), verify it against
`SHA256SUMS`, and put `testls` on your `PATH`:

```bash
tar xzf testls-v0.3.0-x86_64-unknown-linux-musl.tar.gz
./testls-v0.3.0-x86_64-unknown-linux-musl/testls example.com
```

On macOS the binaries are not notarized yet; clear the quarantine flag with
`xattr -d com.apple.quarantine testls` if Gatekeeper blocks them.

## Quick Start

```bash
# Scan a host (port 443 by default)
testls example.com

# JSON output for scripts; exit status 1 if any finding is medium or worse
testls --format json --fail-on medium example.com:8443

# Trust the operating system's roots or a private CA instead of Mozilla's
testls --system-roots intranet.example
testls --ca-file my-ca.pem 10.0.0.5 --sni intranet.example

# Also ask the CA's OCSP responder or CRL whether the certificate is revoked
testls --revocation example.com

# Explain a finding id shown in brackets, or list all ids
testls explain hsts.missing
```

Exit status is `0` when no finding reaches `--fail-on` (default `high`), `1`
when one does, and `2` when the scan itself fails. Run `testls --help` for all
options; the JSON format is described in
[docs/json-schema.md](docs/json-schema.md).

A web service (`testls serve`, REST API and browser UI) is planned for v0.6.

## Features

| Area | Details | Target |
| --- | --- | --- |
| Protocol detection | SSLv2, SSLv3, TLS 1.0–1.3 | v0.1 |
| Cipher audit | Per-protocol cipher suite enumeration, weak/obsolete flags | v0.1 |
| Certificate checks | Expiry, chain, SAN/hostname, key size, signature algorithm | v0.1 |
| Output | Human-readable text and JSON, CI-friendly exit codes | v0.1 |
| Key exchange | Supported groups (X25519, ECDHE curves, ML-KEM hybrids) | v0.2 |
| HTTP headers | HSTS, preload, header hygiene | v0.2 |
| Revocation | OCSP stapling, OCSP/CRL | v0.2 |
| Vulnerabilities | Derived checks: POODLE, BEAST, SWEET32, Logjam, … | v0.3 |
| Handshake | ClientHello tolerance, TLSv1.3 details, post-quantum readiness | v0.3 |
| Certificates+ | Lifetime vs CA/B Baseline Requirements, embedded SCTs | v0.3 |
| Workflow | Multiple targets, SARIF/JUnit/HTML, baselines, policies | v0.4 |
| STARTTLS | SMTP, IMAP, POP3, … | v0.5 |
| Intrusive checks | Heartbleed, CCS injection, Ticketbleed, ROBOT (`--intrusive`) | v0.5 |
| Grading | Own grading model | v0.5 |
| Web service | REST + SSE API and embedded web UI | v0.6 |

## Architecture

```text
┌─────────────────────────────────────────────┐
│  Web UI (embedded SPA)                      │
└──────────────────┬──────────────────────────┘
                   │ REST / SSE
┌──────────────────▼──────────────────────────┐
│  testls (Rust, single binary)               │
│  ├─ Probe engine (raw ClientHello codec)    │
│  ├─ Full-handshake client (rustls)          │
│  ├─ Check runner (async, parallel)          │
│  ├─ HTTP server (axum)                      │
│  └─ CLI (clap)                              │
└─────────────────────────────────────────────┘
```

## Development

```bash
git clone https://github.com/kjpopov/testls
cd testls
cargo build --release
scripts/gen-ocsp-fixtures.sh   # test fixtures, needs OpenSSL 3 or later
cargo test
```

## Responsible Use

Only scan systems you own or are authorized to test. The web service binds to
localhost by default and is intended as a local or internal tool, not a public
scanning service.

## Methodology

This project was designed and architected by the maintainer.
Implementation was assisted by LLM tooling; all code paths were designed,
reviewed, and tested by a human. See [CONTRIBUTING.md](CONTRIBUTING.md)
for our AI-assistance disclosure policy.

## License

This project is dual-licensed under the [MIT License](LICENSE-MIT) or the
[Apache License 2.0](LICENSE-APACHE), at your option.

## Credits

Inspired by [testssl.sh](https://testssl.sh) by Dirk Wetter.
`testls` is an independent, clean-room implementation, not a fork, and does
not reuse testssl.sh code or data (testssl.sh is GPLv2).
