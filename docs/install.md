# Installing testls

Every release has prebuilt binaries for Linux (static musl, x86_64 and
aarch64), macOS (x86_64 and arm64) and Windows (x86_64).

## Release archive

Download an archive from the
[releases page](https://github.com/kjpopov/testls/releases), check it
against `SHA256SUMS` and put `testls` on your `PATH`:

```bash
tar xzf testls-v0.4.3-x86_64-unknown-linux-musl.tar.gz
./testls-v0.4.3-x86_64-unknown-linux-musl/testls example.com
```

On macOS the binaries are not notarized yet; clear the quarantine flag with
`xattr -d com.apple.quarantine testls` if Gatekeeper blocks them.

## Homebrew (macOS, Linux)

This repository is also a Homebrew tap:

```bash
brew tap kjpopov/testls https://github.com/kjpopov/testls
brew install kjpopov/testls/testls
```

## Scoop (Windows)

```powershell
scoop bucket add testls https://github.com/kjpopov/testls
scoop install testls/testls
```

## winget (Windows)

Manifests are prepared in `packaging/winget/` and submitted to
`microsoft/winget-pkgs`; once accepted, `winget install Kjpopov.Testls`
works.

## Cargo

Once testls is on crates.io, `cargo binstall testls` fetches the release
archive for your platform, and `cargo install --locked testls` builds it
from source (Rust 1.97 or newer).

## Container image

Images for linux/amd64 and linux/arm64 (distroless, unprivileged, no
shell):

```bash
podman run --rm ghcr.io/kjpopov/testls:0.4 example.com
```

## GitHub Actions

See [github-action.md](github-action.md).

## Shell completions and man pages

Completions (bash, zsh, fish, PowerShell, elvish) and man pages come from
the binary itself (v0.4.0 and later):

```bash
mkdir -p ~/.local/share/bash-completion/completions ~/.local/share/man/man1
testls completions bash > ~/.local/share/bash-completion/completions/testls
testls man --dir ~/.local/share/man/man1
```

For zsh, write the script to a directory on your `fpath`:

```zsh
mkdir -p ~/.zfunc
testls completions zsh > ~/.zfunc/_testls
# in ~/.zshrc, before compinit: fpath=(~/.zfunc $fpath)
```

Homebrew installs both automatically.

## From source

```bash
git clone https://github.com/kjpopov/testls
cd testls
cargo build --release
```
