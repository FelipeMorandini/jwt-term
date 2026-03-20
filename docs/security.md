# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x.x | Yes |

## Reporting a Vulnerability

If you discover a security vulnerability in jwt-term, please report it responsibly. **Do not open a public GitHub issue.**

### How to Report

Send an email to **felipe.morandini@gmail.com** with:

1. A description of the vulnerability
2. Steps to reproduce the issue
3. The potential impact
4. Any suggested fixes (optional)

### What to Expect

- **Acknowledgment** within 48 hours of your report
- **Status update** within 7 days with an assessment and remediation timeline
- **Credit** in the release notes (unless you prefer to remain anonymous)

### Scope

The following are in scope for security reports:

- Secret or token leakage through stdout, stderr, error messages, or debug output
- Memory safety issues, including unsafe or memory-unsound behavior in dependencies
- Unintended network requests (any network call not triggered by `--jwks-url`)
- Input validation bypasses (malformed tokens causing panics or undefined behavior)
- Dependency vulnerabilities affecting jwt-term's functionality

### Out of Scope

- Tokens passed as CLI arguments being visible in shell history (this is documented behavior; use `--token-env` or stdin instead)
- Denial of service through extremely large tokens (a 16 KB size limit is enforced)

## Security Design

For details on how jwt-term handles security, see the [Security Architecture](architecture.md#security-architecture) section.

### Key Security Measures

- **`#![forbid(unsafe_code)]`** -- No unsafe Rust in the entire crate
- **`zeroize` crate** -- All secrets and keys are zeroed from memory after use
- **Redacted Debug** -- Custom `fmt::Debug` replaces sensitive values with `[REDACTED]`
- **HTTPS-only JWKS** -- Remote key fetching rejects non-HTTPS URLs
- **Request limits** -- 10-second timeout and 1 MB response limit on JWKS
- **No telemetry** -- Zero network requests beyond explicit user commands
