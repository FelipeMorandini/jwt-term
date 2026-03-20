# Contributing

Thank you for your interest in contributing to jwt-term. This document explains how to set up your development environment, the standards we follow, and the process for submitting changes.

## Development Environment

### Prerequisites

- **Rust stable toolchain** (latest stable release). Install via [rustup](https://rustup.rs/):

    ```sh
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    ```

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

| Task | Command |
|------|---------|
| Build (debug) | `cargo build` |
| Build (release) | `cargo build --release` |
| Run all tests | `cargo test` |
| Run clippy lints | `cargo clippy --all-targets --all-features -- -D warnings` |
| Check formatting | `cargo fmt -- --check` |
| Apply formatting | `cargo fmt` |
| Run integration tests | `cargo test --test cli_test` |

Before opening a pull request, make sure all checks pass:

```sh
cargo fmt -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo build
cargo test
```

## Branch Naming Convention

| Prefix | Purpose |
|--------|---------|
| `feature/*` | New features or capabilities |
| `bugfix/*` | Bug fixes |
| `chore/*` | Maintenance, dependency updates |
| `docs/*` | Documentation changes |
| `ci/*` | CI/CD pipeline changes |

## Commit Message Format

This project follows [Conventional Commits](https://www.conventionalcommits.org/):

| Prefix | Purpose |
|--------|---------|
| `feat:` | A new feature |
| `fix:` | A bug fix |
| `refactor:` | Code restructuring without behavior change |
| `test:` | Adding or updating tests |
| `docs:` | Documentation changes |
| `chore:` | Maintenance, dependencies |
| `ci:` | CI/CD configuration changes |

Keep the first line under 72 characters. Use the body for additional context.

## Pull Request Process

1. Create a branch from `main` following the naming convention
2. Make changes in small, focused commits
3. Ensure all checks pass locally
4. Push your branch and open a pull request against `main`
5. Fill out the PR template
6. CI must pass before merge
7. Address review feedback by pushing additional commits

## Code Style

### General Rules

- All public items must have `///` doc comments
- Functions should be under 40 lines -- extract helpers when exceeding
- Use `thiserror` for domain errors in `src/error.rs`
- Use `anyhow` only at the CLI boundary (`src/commands/`)
- Follow Rust naming conventions: `snake_case` functions, `PascalCase` types, `SCREAMING_SNAKE_CASE` constants
- Run `cargo fmt` before committing

### Module Organization

- **Thin CLI, thick library** -- Business logic belongs in `src/core/`
- **Display logic is separate** -- Terminal formatting belongs in `src/display/`
- **One responsibility per module**

## Security Considerations

jwt-term handles sensitive data. All contributors must follow these rules:

- **Never log or print secrets** -- Tokens, HMAC secrets, and private keys must never appear in output
- **Use `zeroize` for sensitive data** -- Any variable holding secret material must use `Zeroize`
- **Custom `Debug` for sensitive types** -- Redact sensitive fields
- **No unsafe code** -- `#![forbid(unsafe_code)]` is enforced
- **HTTPS-only for JWKS** -- Reject non-HTTPS URLs
- **No telemetry or analytics**

If you discover a security vulnerability, follow the process in [Security Policy](security.md).

## Testing Requirements

### Unit Tests

- All modules in `src/core/` and `src/display/` must have unit tests
- Cover happy paths, edge cases, and error conditions
- Use fixtures from `tests/common/mod.rs`

### Integration Tests

- Live in `tests/` directory using `assert_cmd`
- Verify argument parsing, output, exit codes, and end-to-end behavior
- Use `wiremock` for JWKS endpoint tests
- Use `tempfile` for temporary key file tests

### Test Naming

Use descriptive names: `test_decode_with_expired_token_shows_status`

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
