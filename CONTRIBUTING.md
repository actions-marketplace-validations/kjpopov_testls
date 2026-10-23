# Contributing to testls

Thanks for your interest in improving `testls`.

This project is intentionally lean, but we welcome bug reports, fixes, tests, and thoughtful feature ideas.

## Project goals

`testls` aims to provide a fast, Rust-native TLS/SSL scanner with:

- a CLI experience inspired by `testssl.sh` (no output compatibility promise)
- a built-in web service and browser UI
- a single static binary deployment model
- clear, reviewable code and maintainable test coverage

## How to contribute

### 1. Report an issue

Before opening a bug report or feature request, please:

- check whether the issue already exists
- include the exact command, input, and observed output
- describe the expected behavior
- note the platform, Rust version, and environment where it fails

Please keep issue reports actionable and specific. Good reproduction steps are very helpful.

### 2. Open a pull request

When preparing a change:

- keep the scope focused
- prefer small, reviewable commits
- include tests for behavior changes
- document user-visible changes when relevant
- ensure the project still builds and tests cleanly

Scanner changes should also pass the integration tests against local servers
(podman or docker):

```sh
podman compose -f tests/servers/compose.yaml up -d --build
cargo test -p testls --test servers -- --ignored
podman compose -f tests/servers/compose.yaml down
```

### 3. Coding expectations

- Write idiomatic Rust
- Prefer clear naming and straightforward control flow
- Keep functions focused and easy to reason about
- Preserve the project’s compatibility and operational goals
- Avoid adding unnecessary dependencies or shelling out to external tools unless clearly required

### 4. Clean-room rule

`testls` is MIT/Apache-2.0 licensed; `testssl.sh` is GPLv2. Do not copy code,
cipher tables, client-simulation data, or other content from `testssl.sh`.
Derive protocol data from primary sources (IANA registries, RFCs) and cite
them in code comments or data files.

## Development setup

```bash
git clone https://github.com/kjpopov/testls
cd testls
cargo build
cargo test
```

If you are working on the web UI or server components, it may also help to run the project locally with example inputs and inspect output in the browser.

## Testing

Please run the relevant tests before opening a PR.

```bash
cargo test
```

For behavior-heavy changes, add or update regression tests where appropriate.

## AI assistance disclosure

This project is developed with human review and responsibility in the loop.

- AI tooling may be used as part of the development process
- All contributions are reviewed by a human maintainer
- Code changes are expected to be understandable, testable, and maintainable
- AI-generated code does not bypass review or responsibility

If you use AI tools while working on the project, please be transparent about it in your PR description where appropriate.

## Code of conduct

Please keep discussions constructive and respectful. We aim to maintain a welcoming, professional environment for contributors.

## License

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in `testls` shall be dual-licensed under the MIT License and the
Apache License 2.0, without any additional terms or conditions.

---

Thank you for helping make `testls` more useful, robust, and reliable.
