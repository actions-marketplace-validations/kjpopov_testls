# Changelog

All notable changes to `testls` are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

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

[Unreleased]: https://github.com/kjpopov/testls/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/kjpopov/testls/compare/v0.1.0-alpha.1...v0.1.0
[0.1.0-alpha.1]: https://github.com/kjpopov/testls/releases/tag/v0.1.0-alpha.1
