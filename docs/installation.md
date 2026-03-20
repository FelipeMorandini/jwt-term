# Installation

## Homebrew (macOS & Linux)

```bash
brew install felipemorandini/tap/jwt-term
```

## AUR (Arch Linux)

```bash
# Using an AUR helper (e.g., yay, paru)
yay -S jwt-term-bin
```

## Winget (Windows)

```powershell
winget install FelipeMorandini.jwt-term
```

## Debian/Ubuntu (.deb)

Download the `.deb` package for your architecture from [GitHub Releases](https://github.com/felipemorandini/jwt-term/releases):

```bash
# x86_64
sudo dpkg -i jwt-term_<version>-1_amd64.deb

# ARM64
sudo dpkg -i jwt-term_<version>-1_arm64.deb
```

## Cargo (crates.io)

```bash
cargo install jwt-term
```

## Pre-built Binaries

Download the latest release for your platform from [GitHub Releases](https://github.com/felipemorandini/jwt-term/releases).

=== "macOS (Apple Silicon)"

    ```bash
    curl -L https://github.com/felipemorandini/jwt-term/releases/latest/download/jwt-term-aarch64-apple-darwin.tar.gz | tar xz
    sudo mv jwt-term /usr/local/bin/
    ```

=== "macOS (Intel)"

    ```bash
    curl -L https://github.com/felipemorandini/jwt-term/releases/latest/download/jwt-term-x86_64-apple-darwin.tar.gz | tar xz
    sudo mv jwt-term /usr/local/bin/
    ```

=== "Linux (x86_64)"

    ```bash
    curl -L https://github.com/felipemorandini/jwt-term/releases/latest/download/jwt-term-x86_64-unknown-linux-musl.tar.gz | tar xz
    sudo mv jwt-term /usr/local/bin/
    ```

=== "Linux (ARM64)"

    ```bash
    curl -L https://github.com/felipemorandini/jwt-term/releases/latest/download/jwt-term-aarch64-unknown-linux-musl.tar.gz | tar xz
    sudo mv jwt-term /usr/local/bin/
    ```

=== "Windows (x86_64)"

    Download [`jwt-term-x86_64-pc-windows-msvc.zip`](https://github.com/felipemorandini/jwt-term/releases/latest/download/jwt-term-x86_64-pc-windows-msvc.zip), extract, and add `jwt-term.exe` to your PATH.

=== "Windows (ARM64)"

    Download [`jwt-term-aarch64-pc-windows-msvc.zip`](https://github.com/felipemorandini/jwt-term/releases/latest/download/jwt-term-aarch64-pc-windows-msvc.zip), extract, and add `jwt-term.exe` to your PATH.

## Building from Source

Requires Rust 1.91 or later.

```bash
git clone https://github.com/felipemorandini/jwt-term
cd jwt-term
cargo build --release
# Binary will be at: target/release/jwt-term
```

## Shell Completions

Generate tab-completion scripts for your shell:

```bash
jwt-term completions <SHELL>
```

Supported shells: `bash`, `zsh`, `fish`, `elvish`, `powershell`.

=== "Bash"

    ```bash
    jwt-term completions bash > /etc/bash_completion.d/jwt-term
    ```

=== "Zsh"

    ```bash
    jwt-term completions zsh > ~/.zfunc/_jwt-term
    ```

=== "Fish"

    ```bash
    jwt-term completions fish > ~/.config/fish/completions/jwt-term.fish
    ```
