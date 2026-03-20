# Architecture

This document describes the high-level architecture of jwt-term, a Rust CLI tool for JWT inspection, validation, and manipulation.

## Overview

jwt-term follows a **thin CLI, thick library** architecture: the CLI layer is a minimal shell that parses arguments and delegates to a core library containing all business logic. This separation keeps the core logic testable without involving CLI concerns.

## Design Principles

1. **Thin CLI, thick library** -- `main.rs` and `cli.rs` handle only argument parsing and output dispatch. All JWT logic lives in `src/core/`.
2. **Separation of concerns** -- Display formatting in `src/display/`, business logic in `src/core/`, CLI wiring in `src/commands/`.
3. **Security by default** -- Sensitive data is never logged. Secrets are zeroized after use. Unsafe code is forbidden at the compiler level.
4. **Explicit error handling** -- Domain errors are strongly typed with `thiserror`. `anyhow` is used only at the CLI boundary.
5. **Offline-first** -- Network access is only triggered by an explicit `--jwks-url` flag.

## Project Structure

```
jwt-term/
├── src/
│   ├── main.rs                 # Entry point, #![forbid(unsafe_code)]
│   ├── cli.rs                  # Clap derive definitions
│   ├── error.rs                # Domain error types (thiserror)
│   ├── commands/               # Subcommand handlers
│   │   ├── mod.rs
│   │   ├── decode.rs           # Decode subcommand
│   │   └── verify.rs           # Verify subcommand
│   ├── core/                   # Business logic (no CLI dependencies)
│   │   ├── mod.rs
│   │   ├── decoder.rs          # JWT splitting, base64url decoding
│   │   ├── validator.rs        # Signature validation
│   │   ├── jwks.rs             # JWKS fetching and key matching
│   │   └── time_travel.rs      # Time expression parsing
│   └── display/                # Terminal output formatting
│       ├── mod.rs
│       ├── json_printer.rs     # Colorized JSON output
│       └── token_status.rs     # Token expiry/validity display
└── tests/                      # Integration tests
    ├── cli_test.rs             # End-to-end CLI tests
    └── common/mod.rs           # Shared test fixtures
```

## Module Diagram

```
                    ┌──────────┐
                    │ main.rs  │
                    │  (entry) │
                    └────┬─────┘
                         │ parses args
                         v
                    ┌──────────┐
                    │  cli.rs  │
                    │  (clap)  │
                    └────┬─────┘
                         │ dispatches to
                         v
                  ┌──────────────┐
                  │  commands/   │
                  │ decode.rs    │
                  │ verify.rs    │
                  └───┬─────┬───┘
                      │     │
          calls core  │     │  calls display
                      v     v
              ┌────────┐  ┌──────────┐
              │ core/  │  │ display/ │
              └────────┘  └──────────┘
```

**Data flow:**

1. `main.rs` parses CLI arguments via `cli.rs` (clap derive)
2. The parsed command is dispatched to the appropriate handler in `commands/`
3. Command handlers call into `core/` for business logic
4. Command handlers call into `display/` for terminal output
5. Errors from `core/` (`JwtTermError`) are converted to `anyhow::Error` at the command handler boundary

## Module Responsibilities

### `main.rs` -- Entry Point

- Declares `#![forbid(unsafe_code)]` for the entire crate
- Parses CLI arguments, matches subcommand, delegates to handler
- Returns `anyhow::Result<()>` for automatic error formatting

### `cli.rs` -- CLI Argument Definitions

- Clap derive structs for `Cli`, `Commands`, `DecodeArgs`, `VerifyArgs`, `CompletionsArgs`
- Custom `fmt::Debug` on argument structs to redact sensitive fields

### `error.rs` -- Domain Errors

- `JwtTermError` enum using `thiserror::Error`
- Each variant represents a specific failure mode
- Error messages are user-facing and descriptive

### `core/decoder.rs` -- JWT Decoding

- Splits raw JWT into three dot-separated parts
- Base64url-decodes header and payload
- Parses as JSON and returns `DecodedToken`

### `core/validator.rs` -- Signature Validation

- Auto-detects algorithm from token header
- Supports HMAC, RSA, RSA-PSS, ECDSA, EdDSA
- Sensitive key material is zeroized after use

### `core/jwks.rs` -- Remote Key Fetching

- Fetches JWKS from HTTPS endpoints
- Matches keys by JWT `kid` header claim
- Enforces HTTPS-only, 10s timeout, 1MB response limit

### `core/time_travel.rs` -- Time Expression Parsing

- Parses relative expressions (`+7d`, `-1h`)
- Parses absolute ISO 8601 and Unix epoch timestamps
- Returns resolved timestamps for `exp`/`nbf` evaluation

### `display/json_printer.rs` -- JSON Output

- Colorized JSON: cyan keys, green strings, yellow numbers, magenta booleans, red null
- Plain mode (`--json`) for machine-readable output

### `display/token_status.rs` -- Token Status Display

- Human-readable temporal claim status
- Color-coded: red for expired, green for valid, yellow for not-yet-valid

## Error Handling Strategy

### Domain Layer (`thiserror`)

All business logic uses strongly typed errors:

```rust
#[derive(Debug, Error)]
pub enum JwtTermError {
    #[error("invalid token format: ...")]
    InvalidTokenFormat,
    // ...
}
```

Functions in `core/` return `Result<T, JwtTermError>`.

### CLI Boundary (`anyhow`)

Command handlers return `anyhow::Result<()>`. The `?` operator converts `JwtTermError` into `anyhow::Error`, and `main()` prints the error chain to stderr.

## Security Architecture

### Compiler-Level Safety

- `#![forbid(unsafe_code)]` prevents any `unsafe` blocks in the entire crate

### Secret Handling

- `Zeroizing<String>` and `Zeroizing<Vec<u8>>` for all sensitive data
- Custom `fmt::Debug` redacts tokens and secrets with `[REDACTED]`
- No logging of raw tokens, secrets, or key material

### Network Security

- HTTPS-only JWKS fetching
- 10-second request timeout
- 1 MB response size limit

### Privacy

- No telemetry or analytics
- No network requests beyond explicit `--jwks-url`

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Language | Rust (2024 edition, MSRV 1.91) |
| CLI Framework | Clap v4 (derive) |
| JWT Validation | jsonwebtoken crate |
| HTTP Client | reqwest (rustls-tls) |
| Error Handling | thiserror (domain) + anyhow (CLI boundary) |
| Secret Safety | zeroize crate |
| JSON Parsing | serde_json |
| Timestamps | Chrono |
| Terminal Colors | colored crate |
