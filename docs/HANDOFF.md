# Session handoff

State left by the last agent session for the next one. Read this right
after [AGENTS.md](../AGENTS.md) (then [agent-workflow.md](agent-workflow.md)
if `gh` is allowed); update it when a session ends.

## State (2026-10-29)

- Latest release **v0.4.3** (GitHub release, container image
  `ghcr.io/kjpopov/testls:0.4.3`, Homebrew/Scoop in-repo, Marketplace action).
  v0.4.2 was deleted (web UI mistake); skip it in compare links.
- `main` has unreleased v0.5 work: `--starttls
  smtp|imap|pop3|ftp|xmpp|ldap|postgres|mysql` (PRs #108–#115, decisions
  #68–#75). Next decision log number: **#76**.
- PLAN v0.5 has a new item (PR #116): upload coverage to Codecov; needs
  the maintainer to enable the Codecov app first.
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

1. `--mx`, probe PR #119 (`feat/mx`, `MxResolver`). Maintainer chose
   `hickory-resolver` 0.26 (workspace dep, `default-features = false`,
   features `tokio`, `system-config`; ~100 new lockfile crates, `cargo deny`
   passes). Plan: `testls-probe/src/mx.rs` with a resolver built from system
   config (`TokioResolver::builder_tokio()`, timeout from
   `--connect-timeout`) plus a test constructor pointing at a fake UDP DNS
   server (`NameServerConfig::udp(ip)`, then set `port` on each of its
   `connections`, passed to `ResolverConfig::from_name_servers`; answers built with `hickory_resolver::proto::op::Message`).
   Look up the FQDN (trailing dot, no search domains); sort by preference
   then name, lowercase, dedupe; null MX (`.`, RFC 7505) = error "accepts no
   mail"; no MX records = fall back to the domain itself (RFC 5321 §5.1);
   NXDOMAIN = error. CLI: `--mx` implies `--starttls smtp` (reject other
   `--starttls`), turns each name target into its MX hosts on port 25 (keep
   an explicit port), rejects IP/CIDR targets; lookup failures are
   per-target `Outcome::failed` (exit 2), hook in `scan_all`'s target loop.
   Decision #76 and docs go in the CLI PR, once the design is final.
2. Codecov upload (once the maintainer enabled the app).
3. Intrusive checks behind `--intrusive` (Heartbleed, CCS injection,
   Ticketbleed, ROBOT), one PR each.
4. Application-layer checks (BREACH, ALPACA, Opossum), then grading.

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
- hickory 0.26 sources are in `~/.cargo/registry/src/*/hickory-*-0.26.3`;
  grep them for API details (docs.rs lags).
