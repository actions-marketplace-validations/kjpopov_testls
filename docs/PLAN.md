# testls — Project Plan

Living document. Decisions are recorded in the log at the bottom.

## Positioning

- Rust-native TLS/SSL scanner, **inspired by** testssl.sh — no output or
  exit-code compatibility promise.
- Clean-room: no code or data from testssl.sh (GPLv2). Data from IANA/RFCs.
- Single static binary, no OpenSSL, no subprocesses.
- Server mode is a **local/internal tool**, not a public scanning service.

## Architecture

```text
crates/ (Cargo workspace)
├─ testls-wire     # TLS record/handshake codec: build ClientHello, parse
│                  # ServerHello / Alert / Certificate. No I/O. Fuzzable.
├─ testls-data     # Cipher suites, groups, sig-algs (generated from IANA CSV)
├─ testls-probe    # Async probes over TCP using testls-wire
│                  # (protocol support, cipher enumeration, server preference)
├─ testls-checks   # Findings: certificate, headers, vulns; severity model
├─ testls-report   # Text + JSON renderers, exit-code policy
├─ testls-server   # axum REST + SSE, embedded UI (v0.4)
└─ testls (bin)    # clap CLI, wires everything together
```

Two connection paths:

1. **Raw probe path** (`testls-wire` + tokio TCP): sends hand-crafted
   ClientHellos and reads only up to ServerHello/Alert/Certificate. Needed
   because rustls refuses SSLv2/SSLv3/TLS1.0/1.1 and weak ciphers.
2. **Full handshake path** (rustls with a permissive verifier that records,
   not rejects): fetches cert chain for validation, performs HTTP requests for
   header checks.

## Milestones

### v0.1 — Core scanner CLI
- [x] Workspace skeleton, CI (fmt, clippy, test, MSRV), static musl build
- [x] Dependency audit in CI: `cargo deny` (RustSec advisories, licences, sources)
- [x] Dependabot: weekly grouped updates for crates, GitHub Actions and test images
- [x] Workflow audit in CI: `zizmor` (pinned actions, least-privilege tokens)
- [x] Release workflow (cross-platform binaries on tag)
- [x] `testls-data`: IANA cipher suite, group, sig-scheme registries → generated Rust tables
- [x] `testls-wire`: ClientHello builder (SSLv2-compat, SSLv3, TLS1.0–1.3),
      ServerHello/HelloRetryRequest/Alert parser, extensions (SNI,
      supported_versions, supported_groups, signature_algorithms, key_share)
- [x] Protocol detection: SSLv2, SSLv3, TLS 1.0, 1.1, 1.2, 1.3
- [x] Cipher enumeration per protocol (iterative removal) + server preference
- [x] Certificate: chain, expiry, hostname/SAN, key type/size, sig algorithm,
      trust against webpki-roots or a `--ca-file` bundle
- [ ] `--system-roots`: trust the operating system's root store
- [x] Output: coloured, TTY-aware text (`--color auto|always|never`)
- [x] Output: JSON (`--format json`, versioned schema in [json-schema.md](json-schema.md))
- [x] Exit codes: 0 ok, 1 findings ≥ `--fail-on` (default `high`), 2 scan error
- [x] Target parsing: host, host:port, URL, IPv4/IPv6, explicit `--sni`
- [x] Integration tests against local test servers (see Testing)

### v0.2 — Key exchange, headers, revocation
- Supported groups incl. X25519MLKEM768, ECDHE curve list, DH param size
- HSTS / preload / security headers via full-handshake path
- OCSP stapling, OCSP responder, CRL

### v0.3 — Protocols & vulnerabilities
- STARTTLS (SMTP, IMAP, POP3, FTP, XMPP, LDAP, PostgreSQL, MySQL)
- Vulnerability checks (Heartbleed, CCS injection, ROBOT, POODLE, BEAST,
  SWEET32, LOGJAM, FREAK, DROWN, renegotiation, compression/CRIME, …)
- Own grading model (documented, not SSL Labs-compatible)

### v0.4 — Web service
- `testls serve`: axum, binds 127.0.0.1 by default
- REST: `POST /scans`, `GET /scans/{id}`, `GET /scans/{id}/events` (SSE)
- Embedded SPA (static assets via `include_bytes!`/rust-embed)
- Safety: token auth when binding non-loopback, private/link-local target
  blocking toggle, concurrency + rate limits, scan timeouts

## Testing strategy

- Unit tests + `proptest` round-trips for the wire codec
- `cargo-fuzz` targets for all parsers (ServerHello, Certificate, Alert)
- Integration: `tests/servers/compose.yaml` runs `openssl s_server`
  containers with specific protocol/cipher sets (podman or docker);
  `crates/testls/tests/servers.rs` scans them (`--ignored`, own CI job).
  The JSON renderer is checked field by field against expected documents
- Opt-in live tests against badssl.com (not in default CI)

## Open questions

- Wire codec: hand-rolled vs. building on an existing parser crate
  (e.g. `tls-parser`) for the read side?
- Default scan profile: what runs without flags, and how long it may take
- Rate limiting / politeness defaults towards scanned servers
- STARTTLS / vulnerability prioritization for v0.3

## Decision log

| # | Decision | Rationale |
| --- | --- | --- |
| 1 | v0.1 = core scanner CLI only | Engine is the hard, valuable part |
| 2 | Custom raw handshake codec + rustls for full connections | rustls can't negotiate legacy protocols/ciphers; keeps pure-Rust static build |
| 3 | "Inspired by" testssl.sh, no compatibility promise | Avoids huge parity burden |
| 4 | Browser component = web UI embedded in binary; no WebExtension | Browser extension APIs don't expose TLS details (Chrome) |
| 5 | Server mode is local/internal, localhost by default | Avoids SSRF / open-scanner abuse |
| 6 | Clean-room, data from IANA/RFCs | testssl.sh is GPLv2; we're MIT/Apache |
| 7 | Multi-crate Cargo workspace | Isolated, fuzzable wire codec |
| 8 | tokio; bounded parallel probes (default 8 per target, configurable) | Shared runtime with axum server later |
| 9 | Edition 2024, MSRV = stable − 2 (currently 1.97) | Modern Rust, reasonable compatibility |
| 10 | Release targets: Linux x86_64/aarch64 musl, macOS x86_64/arm64, Windows x86_64 | Static Linux; self-contained elsewhere |
| 11 | Trust roots: webpki-roots default, `--system-roots` opt-in | Reproducible results across machines |
| 12 | GitHub + GitHub Actions | Existing repo host |
| 13 | Severity levels ok < info < low < medium < high < critical; `--fail-on` defaults to `high` | Weak-but-common configs (CBC, no PFS) should not fail CI by default |
| 14 | rustls with the `ring` crypto provider (no `aws-lc-rs`) | Simple cross-builds for static musl and Windows: no cmake/nasm toolchain |
| 15 | Trust is checked with `rustls-webpki` path building, at a time clamped into the leaf's validity period | Same verifier as rustls clients; expiry is reported once, by the certificate checks |
| 16 | `--ca-file` replaces the bundled roots with a PEM bundle; the leaf is matched against the SNI name, else the target IP | Lets private PKIs and the integration tests get a clean trust result |
| 17 | Colour defaults to `--color auto`: on for terminals, off when piped or `NO_COLOR` is set; hand-written ANSI codes, no colour crate; on Windows `auto` also requires enabling virtual terminal processing (via `anstyle-query`, already pulled in by clap) | Same convention as cargo/git/ripgrep; logs and files stay clean; legacy Windows consoles would print raw escape codes |
| 18 | JSON output (`--format json`) is one document printed at the end, built with serde from dedicated schema structs; `schema_version` bumps only on breaking changes; times are Unix seconds | Internal types can change without breaking consumers; additive fields stay compatible; integers avoid date-format parsing |
| 19 | `cargo deny` checks advisories daily and on every push; on pull requests only licences, bans and sources block the merge | New advisories should be fixed promptly, but must not fail unrelated PRs |
| 20 | Dependabot groups minor/patch crate bumps and all action bumps into one weekly PR each; majors and security fixes get their own PRs; version updates wait 7 days after a release | Few PRs to review, while breaking upgrades stay isolated |
| 21 | Actions are pinned to full commit SHAs with the tag in a comment; workflows default to `contents: read` and checkout does not persist credentials; `zizmor` gates workflow changes | A moved tag or compromised action cannot change what CI runs; jobs cannot push with the token they were given |
