# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.x.x   | Yes       |

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
- Denial of service through extremely large tokens (a size limit is planned but not yet enforced)

## Security Design

For details on how jwt-term handles security, see the [Security Architecture](ARCHITECTURE.md#security-architecture) section of the architecture documentation.
