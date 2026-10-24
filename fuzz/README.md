# Fuzzing

[cargo-fuzz](https://rust-fuzz.github.io/book/cargo-fuzz.html) targets for the
`testls-wire` parsers, which read untrusted bytes from the network.

| Target | Input |
| --- | --- |
| `record_stream` | A raw server response: record framing, handshake reassembly, then every message parser |
| `server_hello` | A `ServerHello` / `HelloRetryRequest` body |
| `certificate_list` | A TLS 1.2 `Certificate` body |
| `server_key_exchange` | ECDHE and DHE `ServerKeyExchange` parameters |
| `ssl2_server_hello` | An SSLv2 `SERVER-HELLO` record body |

The crate is not a workspace member and needs a nightly toolchain:

```sh
cargo install cargo-fuzz        # or: brew install cargo-fuzz
cd fuzz
cargo +nightly fuzz run record_stream -- -max_total_time=60
```

Without rustup (for example Homebrew Rust), build without sanitizers:
`RUSTC_BOOTSTRAP=1 cargo fuzz run -s none record_stream`.

CI runs every target for a minute when `testls-wire`, `fuzz/` or the root
`Cargo.toml` changes and for ten minutes once a week; on other pull requests
the fuzz jobs pass without fuzzing. Crashing inputs are uploaded as artifacts; add a
regression unit test in `testls-wire` for each one you fix.
