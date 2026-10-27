# Session handoff

State left by the last agent session for the next one. Read this right
after [AGENTS.md](../AGENTS.md) (then [agent-workflow.md](agent-workflow.md)
if `gh` is allowed); update it when a session ends.

## State (2026-10-27)

- `main` is clean; latest release **v0.4.3** (GitHub release, container image
  `ghcr.io/kjpopov/testls:0.4.3`, Homebrew/Scoop in-repo, Marketplace action).
  v0.4.2 was deleted (web UI mistake); skip it in compare links.
- Every v0.4 roadmap item in [PLAN.md](PLAN.md) is done. Next decision log
  number: **#68**.
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

1. STARTTLS framework in `testls-probe` (`--starttls PROTO`), SMTP first,
   then IMAP, POP3, FTP, XMPP, LDAP, PostgreSQL, MySQL. Transport is `Copy`
   and connects via `Transport::connect` (proxy/source-ip aware), so the
   STARTTLS upgrade belongs right after connect, before the ClientHello.
   Needs test servers in `tests/servers` (e.g. Postfix or `openssl s_server
   -starttls smtp`).
2. `--mx` (needs SMTP STARTTLS and an MX lookup without new heavy deps; check
   `cargo deny` before adding a resolver crate).
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
