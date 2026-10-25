# Changelog

All notable changes to `testls` are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.0] - 2026-10-25

Key exchange, HTTP security headers and revocation checks.

### Added

- Key exchange section per offered protocol: supported groups in the
  server's order (including X25519MLKEM768 and other ML-KEM hybrids for
  TLSv1.3) and the DH prime size for DHE suites.
- Findings for deprecated curves (RFC 8422), DH primes below 2048 bits, and
  TLSv1.3 without a post-quantum (ML-KEM) group.
- `key_exchange` array in the JSON report (additive; schema version stays 1).
- HTTP headers section from one `GET /` over a full handshake: HSTS
  (RFC 6797) with preload eligibility, Content-Security-Policy,
  X-Frame-Options, X-Content-Type-Options, and Referrer-Policy.
- Findings for a missing, invalid, disabled, or short (under 180 days) HSTS
  policy, a preload request that does not meet the preload list's
  requirements, and missing security headers (info).
- `http` object in the JSON report (additive).
- Stapled OCSP response check (RFC 6960): the response is verified against
  the issuer or a delegated responder and shown in the certificate section.
- Findings for a revoked, unknown, invalid, or stale OCSP response, a
  Must-Staple certificate (RFC 7633) without a staple, and no staple (info).
- `certificate.ocsp` object in the JSON report (additive).
- `--revocation`: ask the issuer's OCSP responder, falling back to its CRLs,
  whether the leaf certificate is revoked. Off by default because it
  contacts servers other than the target.
- Findings for a revoked certificate, an unknown or stale answer, and no
  usable OCSP responder or CRL (info); `revocation` object in the JSON
  report (additive).

## [0.1.0] - 2026-10-24

First stable release of the command-line scanner.

### Added

- Certificate checks: validity period, hostname/SAN match, key type and size,
  signature algorithm, and chain trust against the bundled Mozilla roots.
- `--ca-file` to trust only the roots in a PEM bundle, and `--system-roots` to
  trust the operating system's store (`SSL_CERT_FILE` / `SSL_CERT_DIR`
  override it).
- Findings with severities (`ok` to `critical`) for protocols, cipher suites
  and certificates; `--fail-on` sets the exit-status threshold (exit `0`, `1`,
  or `2` on scan errors).
- `--format json` with a versioned schema ([docs/json-schema.md](docs/json-schema.md)).
- Coloured text output with `--color auto|always|never`, honouring `NO_COLOR`.

### Changed

- Text rendering moved into the `testls-report` crate.

### Security

- Control characters in certificate details are escaped before printing.

### Project

- CI: required checks for fmt, clippy, tests on Linux/macOS/Windows, MSRV,
  static musl builds, integration tests against local OpenSSL servers,
  coverage, `cargo deny`, `zizmor` and `cargo fuzz` runs on the wire parsers.
- Dependabot updates with a 7-day cooldown; actions pinned by commit.

## [0.1.0-alpha.1] - 2026-10-23

First pre-release.

### Added

- Protocol detection for SSLv2, SSLv3 and TLS 1.0–1.3 with a hand-written
  handshake codec.
- Cipher suite enumeration per protocol and server preference detection.
- Target parsing for host, host:port, IPv4/IPv6 and URLs, plus `--sni`.
- Release binaries for Linux (static musl), macOS and Windows.

[Unreleased]: https://github.com/kjpopov/testls/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/kjpopov/testls/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/kjpopov/testls/compare/v0.1.0-alpha.1...v0.1.0
[0.1.0-alpha.1]: https://github.com/kjpopov/testls/releases/tag/v0.1.0-alpha.1
