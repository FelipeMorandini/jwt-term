# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.2] - 2026-03-18

### Added

- Automated Winget manifest updates in release workflow (`update-winget` job)
- Submitted initial manifest to microsoft/winget-pkgs
- Updated Winget manifests with real SHA256 hashes

## [1.1.1] - 2026-03-18

### Added

- Automated AUR package updates in release workflow (`update-aur` job)
- Registered `jwt-term-bin` on the AUR

### Changed

- Updated PKGBUILD version to 1.1.0
- Hardened AUR CI job: pinned host key via `ssh-keyscan`, `curl --fail` with retries

## [1.1.0] - 2026-03-18

### Added

- CHANGELOG.md following Keep a Changelog format
- AUR package (PKGBUILD) for Arch Linux installation
- Winget manifest for Windows package manager installation
- Debian package (.deb) support via cargo-deb in release workflow

## [1.0.1] - 2025-05-19

### Fixed

- Bumped `quinn-proto` to v0.11.14 to resolve security advisory
- Updated version checks in tests to use dynamic package version

### Changed

- Added cargo build workflow to CI

## [1.0.0] - 2025-05-18

### Added

- Shell completions subcommand via `clap_complete` (bash, zsh, fish, elvish, powershell)
- `cargo-audit` (rustsec) and `cargo-deny` (license/source/ban checks) in CI
- MSRV set to 1.91 (`rust-version` in Cargo.toml + `rust-toolchain.toml`)

### Fixed

- `sanitize_json_error` prevents payload content leaks in error messages
- `MAX_DEPTH=20` recursion guard in json_printer
- Display functions refactored to `&mut impl Write` for testability
- `read_token_from_stdin` returns `Zeroizing<String>` directly
- `KeyMaterial::PemKey` wraps `Zeroizing<Vec<u8>>`
- Removed stale `NotImplemented` error variant

## [0.4.0] - 2025-05-17

### Added

- Time-travel debugging via `--time-travel` flag on verify command
- Relative time expressions (`+7d`, `-1h`, `+30m`, `+1y`, `-5s`)
- ISO 8601 and Unix epoch timestamp support
- Colorized temporal claim status display
- JSON mode `time_travel` section in output

## [0.3.0] - 2025-05-16

### Added

- JWKS remote validation via `--jwks-url` (HTTPS only)
- Key matching by JWT `kid` header with single-key fallback
- Algorithm resolution preferring JWK `alg` over JWT header `alg`
- HTTPS-only URL enforcement with redirect prevention
- URL credential redaction in error messages

## [0.2.0] - 2025-05-15

### Added

- JWT signature verification with `verify` subcommand
- HMAC, RSA, RSA-PSS, ECDSA, EdDSA support
- Key input via `--secret`, `--secret-env`, `--key-file`
- Bounded key file reads (1MB limit, TOCTOU-free)
- `Zeroizing<String>` for CLI token args, secrets, env var values
- `alg:none` rejection (case-insensitive)
- `--json` mode for machine-readable output
- Exit code 1 for invalid signatures

## [0.1.2] - 2025-05-14

### Fixed

- Updated macOS runner to macos-14 in release workflow

## [0.1.1] - 2025-05-14

### Fixed

- Modified reqwest to use `rustls-tls` for Linux musl cross-compilation

## [0.1.0] - 2025-05-13

### Added

- Initial release
- JWT decoding with colorized pretty-print output
- Token input resolution (CLI arg, `--token-env`, stdin)
- 16KB token size limit and env var name validation
- Base64url decoding with JSON parsing
- Colorized JSON printer
- Token status display (exp/iat/nbf with color-coded expiry)
- `--json` mode for machine-readable output
- CI/CD with cross-platform builds (6 targets)
- Homebrew formula auto-update in release workflow
