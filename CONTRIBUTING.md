# Contributing to jwt-term

Thank you for your interest in contributing to jwt-term. This document explains how to set up your development environment, the standards we follow, and the process for submitting changes.

## Table of Contents

- [Development Environment](#development-environment)
- [Building and Testing](#building-and-testing)
- [Branch Naming Convention](#branch-naming-convention)
- [Commit Message Format](#commit-message-format)
- [Pull Request Process](#pull-request-process)
- [Code Style](#code-style)
- [Security Considerations](#security-considerations)
- [Testing Requirements](#testing-requirements)

## Development Environment

### Prerequisites

- **Rust stable toolchain** (latest stable release). Install via [rustup](https://rustup.rs/):

  ```sh
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  ```

- **cargo** (included with the Rust toolchain).

- **clippy** and **rustfmt** components:

  ```sh
  rustup component add clippy rustfmt
  ```

### Clone the Repository

```sh
git clone https://github.com/FelipeMorandini/jwt-term.git
cd jwt-term
```

## Building and Testing

All commands are run from the project root.

| Task                  | Command                                 |
|-----------------------|-----------------------------------------|
| Build (debug)         | `cargo build`                           |
| Build (release)       | `cargo build --release`                 |
| Run all tests         | `cargo test`                            |
| Run clippy lints      | `cargo clippy -- -D warnings`           |
| Check formatting      | `cargo fmt -- --check`                  |
| Apply formatting      | `cargo fmt`                             |
| Run a specific test   | `cargo test test_name`                  |
| Run integration tests | `cargo test --test cli_test`            |

Before opening a pull request, make sure all four checks pass:

```sh
cargo fmt -- --check
cargo clippy -- -D warnings
cargo build
cargo test
```

## Branch Naming Convention

Create branches from `main` using one of the following prefixes:

| Prefix       | Purpose                                      |
|--------------|----------------------------------------------|
| `feature/*`  | New features or capabilities                 |
| `bugfix/*`   | Bug fixes                                    |
| `chore/*`    | Maintenance, dependency updates, tooling     |
| `docs/*`     | Documentation changes                        |
| `ci/*`       | CI/CD pipeline changes                       |

Examples:

- `feature/decode-command`
- `bugfix/stdin-eof-handling`
- `docs/add-architecture-guide`
- `ci/add-release-workflow`

## Commit Message Format

This project follows [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/). Every commit message must use one of the following prefixes:

| Prefix       | Purpose                                    |
|--------------|--------------------------------------------|
| `feat:`      | A new feature                              |
| `fix:`       | A bug fix                                  |
| `refactor:`  | Code restructuring without behavior change |
| `test:`      | Adding or updating tests                   |
| `docs:`      | Documentation changes                      |
| `chore:`     | Maintenance, dependencies, tooling         |
| `ci:`        | CI/CD configuration changes                |

The commit message format is:

```
<prefix>: <short summary in imperative mood>

<optional body explaining the "why" in more detail>
```

Examples:

```
feat: add JWT decode command with stdin support

fix: handle empty token input without panicking

test: add integration tests for verify subcommand

docs: update ARCHITECTURE.md with JWKS module details
```

Keep the first line under 72 characters. Use the body for additional context when needed.

## Pull Request Process

1. **Create a branch** from `main` following the naming convention above.
2. **Make your changes** in small, focused commits.
3. **Ensure all checks pass** locally:
   ```sh
   cargo fmt -- --check
   cargo clippy -- -D warnings
   cargo build
   cargo test
   ```
4. **Push your branch** and open a pull request against `main`.
5. **Fill out the PR template** with a description, related issues, and the checklist.
6. **CI must pass** before the PR can be merged. All checks (build, test, clippy, fmt) are enforced.
7. **Address review feedback** by pushing additional commits (do not force-push during review).
8. Once approved, the PR will be merged by a maintainer.

## Code Style

### General Rules

- **All public items must have doc comments.** Every public function, struct, enum, trait, and module must include a `///` or `//!` doc comment explaining its purpose.
- **Functions should be under 40 lines.** If a function grows beyond this, extract helper functions.
- **Use `thiserror` for domain errors.** All business-logic errors are defined in `src/error.rs` using `thiserror::Error`.
- **Use `anyhow` only at the CLI boundary.** Command handlers in `src/commands/` return `anyhow::Result<()>`. Core logic in `src/core/` returns typed `Result<T, JwtTermError>`.
- **Follow Rust naming conventions.** Use `snake_case` for functions and variables, `PascalCase` for types, `SCREAMING_SNAKE_CASE` for constants.
- **Run `cargo fmt` before committing.** The project uses the default rustfmt configuration.

### Module Organization

- **Thin CLI, thick library.** Keep `main.rs` and `cli.rs` minimal. Business logic belongs in `src/core/`.
- **Display logic is separate.** Terminal formatting and colorization belong in `src/display/`, not in core modules.
- **One responsibility per module.** Each file in `src/core/` and `src/display/` handles a single concern.

## Security Considerations

jwt-term handles sensitive data (tokens, secrets, private keys). All contributors must follow these rules:

- **Never log or print secrets.** Tokens, HMAC secrets, and private keys must never appear in log output, error messages, or debug formatting.
- **Use `zeroize` for sensitive data.** Any variable holding secret material must implement or use `Zeroize` so memory is cleared when the value is dropped.
- **Custom `Debug` for sensitive types.** Structs containing tokens or secrets must implement `fmt::Debug` manually to redact those fields (see `DecodeArgs` and `VerifyArgs` in `src/cli.rs` for examples).
- **No unsafe code.** The crate enforces `#![forbid(unsafe_code)]` in `main.rs`. Do not use `unsafe` blocks under any circumstance.
- **HTTPS-only for JWKS.** The JWKS fetcher must reject non-HTTPS URLs.
- **No telemetry or analytics.** This tool must never phone home, collect usage data, or make network requests beyond explicit user commands.

If you discover a security vulnerability, please follow the process described in [SECURITY.md](SECURITY.md) rather than opening a public issue.

## Testing Requirements

### Unit Tests

- All modules in `src/core/` and `src/display/` must have unit tests defined in a `#[cfg(test)] mod tests` block within the same file.
- Unit tests should cover the happy path, edge cases, and error conditions.
- Use the test fixtures defined in `tests/common/mod.rs` for consistent JWT test data.

### Integration Tests

- Integration tests live in the `tests/` directory and use [`assert_cmd`](https://docs.rs/assert_cmd) to test the CLI as a black box.
- Integration tests verify argument parsing, output formatting, exit codes, and end-to-end command behavior.
- Use [`predicates`](https://docs.rs/predicates) for flexible output assertions.
- Use [`wiremock`](https://docs.rs/wiremock) for testing JWKS endpoint interactions.
- Use [`tempfile`](https://docs.rs/tempfile) for tests that need temporary key files.

### Test Naming

- Use descriptive test names that explain the scenario: `test_decode_with_expired_token_shows_status`.
- Prefix with `test_` for consistency with the existing test suite.

---

If you have questions about contributing, feel free to open a discussion or issue on the [GitHub repository](https://github.com/FelipeMorandini/jwt-term).
