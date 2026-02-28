# jwt-term

A blazing-fast, secure, and offline-first CLI tool built in Rust for inspecting, validating, and manipulating JSON Web Tokens (JWTs) and OAuth tokens.

Stop pasting sensitive tokens into web portals. Debug them in your terminal.

## Features

- **Instant Decoding** -- Decode base64url-encoded headers and payloads without signature verification
- **Pretty-Print Output** -- Colorized, formatted JSON for quick visual inspection
- **Offline Signature Validation** -- Validate HMAC, RSA, and ECDSA signatures with local secrets and PEM keys
- **Remote JWKS Validation** -- Fetch and validate against OIDC provider JWKS endpoints
- **Time-Travel Debugging** -- Simulate token expiry by evaluating `exp`/`nbf` against custom timestamps
- **Security First** -- No telemetry, no logging, memory-zeroed secrets, stdin/env-var support

## Installation

### From source

```bash
cargo install --path .
```

### From releases

Download the pre-built binary for your platform from [GitHub Releases](https://github.com/felipemorandini/jwt-term/releases).

| Platform | Architecture | Download |
|----------|-------------|----------|
| Linux | x86_64 | `jwt-term-vX.Y.Z-x86_64-unknown-linux-musl.tar.gz` |
| Linux | ARM64 | `jwt-term-vX.Y.Z-aarch64-unknown-linux-musl.tar.gz` |
| macOS | x86_64 (Intel) | `jwt-term-vX.Y.Z-x86_64-apple-darwin.tar.gz` |
| macOS | ARM64 (Apple Silicon) | `jwt-term-vX.Y.Z-aarch64-apple-darwin.tar.gz` |
| Windows | x86_64 | `jwt-term-vX.Y.Z-x86_64-pc-windows-msvc.zip` |
| Windows | ARM64 | `jwt-term-vX.Y.Z-aarch64-pc-windows-msvc.zip` |

## Quick Start

```bash
# Decode a JWT (no signature verification)
jwt-term decode eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U

# Pipe from stdin (keeps token out of shell history)
cat token.txt | jwt-term decode

# Read token from environment variable
jwt-term decode --token-env JWT_TOKEN
```

## Usage

### decode

Decode and inspect a JWT without verifying its signature.

```bash
jwt-term decode [OPTIONS] [TOKEN]
```

| Option | Description |
|--------|-------------|
| `--token-env <VAR>` | Read token from the named environment variable |
| `--json` | Output raw JSON without colors (machine-readable) |

### verify

Verify a JWT's signature using a local secret, key file, or remote JWKS.

```bash
jwt-term verify [OPTIONS] [TOKEN]
```

| Option | Description |
|--------|-------------|
| `--secret <SECRET>` | HMAC shared secret |
| `--secret-env <VAR>` | Read HMAC secret from environment variable |
| `--key-file <FILE>` | PEM-encoded public key file (RSA/ECDSA) |
| `--jwks-url <URL>` | JWKS endpoint URL (HTTPS only) |
| `--time-travel <EXPR>` | Evaluate expiry at a simulated time (`+7d`, `-1h`, ISO 8601) |
| `--token-env <VAR>` | Read token from environment variable |
| `--json` | Output raw JSON without colors |

## Security

jwt-term is designed with security as a first-class concern:

- **No telemetry or analytics** -- The tool never phones home. Network calls only happen when you explicitly request JWKS validation.
- **No logging** -- Token payloads and secrets are never written to disk.
- **Memory-zeroed secrets** -- HMAC keys and sensitive data are zeroed from memory after use via the `zeroize` crate.
- **Shell history safety** -- Use `--token-env` or pipe via stdin to keep tokens out of `~/.bash_history`:

```bash
# Safe: token never appears in shell history
cat token.txt | jwt-term decode
jwt-term decode --token-env MY_JWT

# Less safe: token visible in shell history
jwt-term decode eyJhbG...
```

## Development

```bash
# Build
cargo build

# Run tests
cargo test

# Lint
cargo clippy --all-targets --all-features -- -D warnings

# Format
cargo fmt
```

## License

MIT License. See [LICENSE](LICENSE) for details.
