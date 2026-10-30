# Session handoff

State left by the last agent session for the next one. Read this right
after [AGENTS.md](../AGENTS.md) (then [agent-workflow.md](agent-workflow.md)
if `gh` is allowed); update it when a session ends.

## State (2026-10-30)

- Latest release **v0.4.3** (GitHub release, container image
  `ghcr.io/kjpopov/testls:0.4.3`, Homebrew/Scoop in-repo, Marketplace action).
  v0.4.2 was deleted (web UI mistake); skip it in compare links.
- `main` has unreleased v0.5 work: `--starttls
  smtp|imap|pop3|ftp|xmpp|ldap|postgres|mysql` (PRs #108–#115, decisions
  #68–#75) and `--mx` (probe PR #119 `MxResolver` in `testls-probe/src/mx.rs`,
  CLI PR #120 `mail_hosts` in `main.rs`, decisions #76–#77), plus the
  PR #117 security hardening (PRs #122–#126, decisions #78–#81, CHANGELOG
  "Security" section), Codecov upload (PR #128, decision #82) and the
  application-layer checks: BREACH (#129, decision #83), ALPACA (#130,
  #84), Opossum (#131, #85), Codecov Test Analytics (branch
  `ci/test-analytics`, decision #86). Next decision log number: **#87**.
- Application-layer code map: BREACH reads `Content-Encoding` from the
  existing GET (`testls-probe/src/http.rs` sends `Accept-Encoding`); ALPACA
  is `HandshakeFeatures::strict_alpn` in `testls-probe/src/features.rs`
  (raw hello up to TLS 1.2, rustls handshake at TLS 1.3); Opossum is
  `testls-probe/src/upgrade.rs` (`OPTIONS *` + `Upgrade: TLS/1.0` to the
  scanned port and port 80, joined with the feature probe in
  `vulnerability_section`). Verdicts in `testls-checks/src/vulnerabilities.rs`
  (15 entries).
- PR #117 (external audit by r4d1um, Stephan
  `<dertoradium@googlemail.com>`) stays open as reference; **close it when
  v0.5 is released** (status comment 6521444559 lists the follow-ups). Its
  exit-code change (exit 2 on incomplete scans) was declined. Local branch
  `pr-117` holds its commit and can be deleted after closing.
- Hardening code map: escaping via `printable()` in
  `testls-report/src/text.rs` and `csv::field`; baseline severity in
  `testls/src/baseline.rs` (`scan_failure`); handshake signature in
  `testls-probe/src/certificates.rs` (`AcceptAll::check`, `unverifiable`,
  `UNVERIFIABLE_SCHEMES`, finding `cert.signature_unverified`); CRL scope in
  `testls-checks/src/revocation.rs` (`check_scope`, `distribution_points`);
  revocation guard in `testls-probe/src/fetch.rs` (`Fetcher::allow_private`,
  `local_host`, `ends_in_number`, `public_address`), CLI flag
  `--revocation-allow-private`.
- `--mx` has unit tests only (fake UDP DNS server in `mx.rs`, CLI parsing
  in `main.rs`); no integration test (would need a DNS server in
  `tests/servers`). Outbound port 25 is blocked on the dev machine, so live
  `--mx` scans hang until the connect timeout.
- STARTTLS lives in `testls-probe/src/starttls.rs`; `Transport::connect`
  runs it after TCP/proxy connect, failures are `ProbeError::Connect`.
  `Transport` is no longer `Copy` (has `host` for XMPP).
- CodeRabbit runs the `assertive` profile with auto-approval up to `low`
  merge risk (PLAN #46, #55, #61).

## Waiting on the maintainer

- crates.io: GitHub environment `crates-io` and the variable
  `CRATES_IO_TRUSTED_PUBLISHING` are set up. The first manual
  `cargo publish --workspace --locked` of v0.4.3 and trusted publishing on
  each `testls*` crate may still be pending; check with
  `curl -s https://crates.io/api/v1/crates/testls`. From the next tag the
  `crates-io` job publishes; if it fails halfway, rerun failed jobs.
- winget: deliberately postponed until there are more features (better odds
  with the moderators). Keep generating `packaging/winget/X.Y.Z/` in the
  packages PR, but do not remind the maintainer each release.

## Next work

v0.5 in PLAN.md, suggested order:

1. Intrusive checks behind `--intrusive` (Heartbleed, CCS injection,
   Ticketbleed, ROBOT), one PR each. Skipped by the maintainer in the
   2026-10-30 session; a remote branch `feat/intrusive-checks` exists (not
   ours, check with the maintainer before touching it).
2. Grading.
3. v0.5 release once the maintainer decides; close PR #117 then.

Open questions in PLAN.md (default profile runtime, politeness/rate limits)
still need a decision before grading.

## Habits that worked

- One topic per PR, all review fixes in one commit per round, reply to each
  thread; reviews take 10–15 minutes, poll with `sleep 290` and a 320 s tool
  timeout.
- Decline wrong suggestions with a PR comment and point the maintainer to it
  in the final message.
- Stay inside the repository directory (use `target/` or
  `CARGO_TARGET_TMPDIR` for scratch files); the maintainer declines access
  elsewhere.
- Test servers: one Debian trixie image per service (pinned digest) in
  `tests/servers`; ports 14425 smtp, 14143/14110 imap/pop3, 14021 ftp,
  15222 xmpp, 14389 ldap, 15432 postgres, 13306 mysql. Gotchas: Docker
  `COPY --chmod` gives a missing target dir that mode too (create it first);
  the Docker port proxy accepts before the service listens (`wait_for` peeks);
  vsftpd needs `init: true` under Docker. CI container logs:
  `gh run view RUN --log --job JOB | grep "<svc>-1"`.
- CodeRabbit sometimes answers in issue comments or posts empty COMMENTED
  reviews; check both before assuming nothing changed. If it never reviews
  a PR (seen on docs-only #116), comment `@coderabbitai review`.
- External PRs: review with zero trust (check CI/workflow/dependency/binary
  changes first), post a per-finding review, then redo accepted parts as
  small PRs with `Co-authored-by` and a CHANGELOG credit
  ("Reported by @user in #N.").
- CRL/OCSP test fixtures come from `scripts/gen-ocsp-fixtures.sh`
  (gitignored output; rerun after editing it).
- hickory 0.26 sources are in `~/.cargo/registry/src/*/hickory-*-0.26.3`;
  grep them for API details (docs.rs lags).
