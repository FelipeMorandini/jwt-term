# Architecture

This document describes the high-level architecture of jwt-term, a Rust CLI tool for JWT inspection, validation, and manipulation.

## Table of Contents

- [Overview](#overview)
- [Design Principles](#design-principles)
- [Project Structure](#project-structure)
- [Module Diagram](#module-diagram)
- [Module Responsibilities](#module-responsibilities)
- [Error Handling Strategy](#error-handling-strategy)
- [Security Architecture](#security-architecture)
- [Testing Architecture](#testing-architecture)

## Overview

jwt-term is a command-line tool that allows developers to decode, inspect, and verify JSON Web Tokens directly in the terminal. It is designed to be fast, secure, and offline-first, with optional network access only for JWKS endpoint validation.

The project follows a **thin CLI, thick library** architecture: the CLI layer is a minimal shell that parses arguments and delegates to a core library containing all business logic. This separation keeps the core logic testable without involving CLI concerns and makes it possible to reuse the core as a library in the future.

## Design Principles

1. **Thin CLI, thick library.** `main.rs` and `cli.rs` handle only argument parsing and output dispatch. All JWT logic lives in `src/core/`.

2. **Separation of concerns.** Display formatting is isolated in `src/display/`, business logic in `src/core/`, and CLI wiring in `src/commands/`. No module crosses these boundaries.

3. **Security by default.** Sensitive data is never logged. Secrets are zeroized after use. Unsafe code is forbidden at the compiler level. JWKS fetching requires HTTPS.

4. **Explicit error handling.** Domain errors are strongly typed with `thiserror`. The `anyhow` crate is used only at the CLI boundary for ergonomic error reporting to the user.

5. **Offline-first.** Network access is only triggered by an explicit `--jwks-url` flag. All other operations are fully offline.

## Project Structure

```
jwt-term/
├── Cargo.toml                  # Package manifest and dependencies
├── LICENSE                     # MIT license
├── README.md                   # User-facing documentation
├── src/
│   ├── main.rs                 # Entry point, CLI parsing delegation
│   ├── cli.rs                  # Clap derive definitions, argument structs
│   ├── error.rs                # Domain error types (thiserror)
│   ├── commands/               # Subcommand handlers
│   │   ├── mod.rs              # Module declarations
│   │   ├── decode.rs           # Decode subcommand handler
│   │   └── verify.rs           # Verify subcommand handler
│   ├── core/                   # Business logic (no CLI dependencies)
│   │   ├── mod.rs              # Module declarations
│   │   ├── decoder.rs          # JWT splitting, base64 decoding, JSON parsing
│   │   ├── validator.rs        # Signature validation (HMAC, RSA, ECDSA)
│   │   ├── jwks.rs             # JWKS fetching and key matching
│   │   └── time_travel.rs      # Time expression parsing and evaluation
│   └── display/                # Terminal output formatting
│       ├── mod.rs              # Module declarations
│       ├── json_printer.rs     # Colorized JSON pretty-printing
│       └── token_status.rs     # Token expiry/validity status display
└── tests/                      # Integration tests
    ├── cli_test.rs             # End-to-end CLI tests (assert_cmd)
    └── common/
        └── mod.rs              # Shared test fixtures and helpers
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
              │        │  │          │
              └────────┘  └──────────┘
```

**Data flow:**

1. `main.rs` parses CLI arguments via `cli.rs` (clap derive).
2. The parsed command is matched and dispatched to the appropriate handler in `commands/`.
3. Command handlers call into `core/` for business logic (decoding, validation, JWKS, time-travel).
4. Command handlers call into `display/` for terminal output formatting.
5. Errors from `core/` (typed `JwtTermError`) are converted to `anyhow::Error` at the command handler boundary.

## Module Responsibilities

### `src/main.rs` -- Entry Point

- Declares `#![forbid(unsafe_code)]` for the entire crate.
- Parses CLI arguments using `Cli::parse()`.
- Matches the subcommand and delegates to the appropriate handler in `commands/`.
- Returns `anyhow::Result<()>` so errors are automatically formatted and printed to stderr.

### `src/cli.rs` -- CLI Argument Definitions

- Defines the `Cli` struct with clap derive macros.
- Defines the `Commands` enum with one variant per subcommand (`Decode`, `Verify`).
- Defines `DecodeArgs` and `VerifyArgs` with typed fields for each flag and argument.
- Implements custom `fmt::Debug` on argument structs to redact sensitive fields (tokens and secrets), preventing accidental leakage through debug output or error chains.

### `src/error.rs` -- Domain Errors

- Defines `JwtTermError` using `thiserror::Error`.
- Each variant represents a specific failure mode (invalid format, base64 error, unsupported algorithm, JWKS fetch failure, etc.).
- Error messages are user-facing and descriptive.
- The error type is `Send + Sync` for safe use across threads.

### `src/commands/` -- Subcommand Handlers

- **`decode.rs`**: Orchestrates the decode workflow. Reads the token (from argument, env var, or stdin), calls `core::decoder` to decode it, and calls `display::json_printer` to render output.
- **`verify.rs`**: Orchestrates the verify workflow. Reads the token and key material, calls `core::validator` (or `core::jwks` for remote keys), optionally applies time-travel, and calls `display::token_status` to render results.

Command handlers are the **boundary layer** where typed domain errors are converted to `anyhow::Error` for user-facing output.

### `src/core/` -- Business Logic

This module contains all JWT logic, completely independent of CLI concerns.

- **`decoder.rs`**: Splits a raw JWT string into its three dot-separated parts, base64url-decodes the header and payload, and parses them as JSON. Returns a `DecodedToken` struct.
- **`validator.rs`**: Validates a JWT signature using provided key material. Auto-detects the algorithm from the token header. Supports HMAC (HS256/HS384/HS512), RSA (RS256/RS384/RS512), and ECDSA (ES256/ES384). Sensitive key material is zeroized after use.
- **`jwks.rs`**: Fetches a JSON Web Key Set from a remote HTTPS endpoint, finds the key matching the token's `kid` header claim, and validates the signature. Enforces HTTPS-only, request timeouts, and response size limits.
- **`time_travel.rs`**: Parses time expressions (relative like `+7d`, `-1h`; absolute ISO 8601; Unix epoch) into resolved timestamps. Used to simulate a different "current time" when evaluating `exp` and `nbf` claims.

### `src/display/` -- Terminal Output

- **`json_printer.rs`**: Renders JSON values with syntax highlighting (cyan for keys, green for strings, yellow for numbers, magenta for booleans, red for null). Supports a plain mode (`--json`) for machine-readable output.
- **`token_status.rs`**: Displays human-readable status for temporal claims (`exp`, `iat`, `nbf`). Uses color coding: red for expired, green for valid, yellow for not-yet-valid.

## Error Handling Strategy

jwt-term uses a two-tier error handling approach:

### Domain Layer (`thiserror`)

All business logic in `src/core/` and `src/error.rs` uses strongly typed errors:

```rust
#[derive(Debug, Error)]
pub enum JwtTermError {
    #[error("invalid token format: ...")]
    InvalidTokenFormat,
    // ...
}
```

Functions in `core/` return `Result<T, JwtTermError>`. This makes error handling explicit and testable. Each variant carries structured data about the failure.

### CLI Boundary (`anyhow`)

Command handlers in `src/commands/` return `anyhow::Result<()>`. The `?` operator automatically converts `JwtTermError` into `anyhow::Error`, and `main()` prints the error chain to stderr with a non-zero exit code.

This pattern keeps the core library free of presentation concerns while giving the CLI layer ergonomic error reporting.

## Security Architecture

Security is a first-class concern in jwt-term. The following measures are enforced:

### Compiler-Level Safety

- **`#![forbid(unsafe_code)]`** is declared in `main.rs`, preventing any `unsafe` blocks in the entire crate. This is enforced at compile time.

### Secret Handling

- **Zeroize.** The `zeroize` crate (with derive support) will be used to ensure that sensitive data (HMAC secrets, private keys, raw token strings) is overwritten in memory when dropped. This is planned for implementation alongside the verify command.
- **Redacted Debug.** `DecodeArgs` and `VerifyArgs` implement custom `fmt::Debug` that replaces token and secret values with `[REDACTED]`. This prevents secrets from appearing in error chains, debug output, or logs.
- **No logging of secrets.** The codebase never prints or logs raw tokens, secrets, or key material.

### Network Security

- **HTTPS-only JWKS.** The JWKS fetcher rejects any URL that does not use the `https://` scheme.
- **Request timeout.** JWKS requests enforce a 10-second timeout to prevent hanging.
- **Response size limit.** JWKS responses are limited to 1 MB to prevent resource exhaustion.

### Privacy

- **No telemetry.** jwt-term never phones home, collects usage data, or makes network requests beyond those explicitly requested by the user (JWKS fetching).
- **Offline-first.** All operations except JWKS validation work without network access.

## Testing Architecture

### Unit Tests

Unit tests will be defined in `#[cfg(test)] mod tests` blocks colocated with the implementation. They test individual functions and types in isolation.

Intended location: alongside the code in modules under `src/core/` and `src/display/`.

Example pattern: `src/error.rs` contains tests for error variant `Display` implementations. As each module is implemented, corresponding unit tests will be added inline.

### Integration Tests

Integration tests live in the `tests/` directory and test the CLI as a compiled binary.

- **`tests/cli_test.rs`**: Uses `assert_cmd` to invoke the `jwt-term` binary and `predicates` to assert on stdout, stderr, and exit codes. Tests cover argument parsing, help text, version output, subcommand routing, and error behavior.
- **`tests/common/mod.rs`**: Shared test fixtures providing pre-built JWT tokens with known claims (valid HS256, malformed, invalid, empty) for consistent test data across the suite.

### Test Dependencies

| Crate        | Purpose                                        |
|--------------|------------------------------------------------|
| `assert_cmd` | Run the compiled binary and assert on output   |
| `predicates` | Flexible matchers for stdout/stderr assertions |
| `tempfile`   | Create temporary files for key file tests      |
| `wiremock`   | Mock HTTP server for JWKS endpoint tests       |
| `tokio`      | Async runtime for wiremock-based tests         |

### Running Tests

```sh
# All tests (unit + integration)
cargo test

# Only unit tests
cargo test --lib

# Only integration tests
cargo test --test cli_test

# A specific test by name
cargo test test_decode_with_token_returns_not_implemented
```
