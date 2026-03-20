# jwt-term

A blazing-fast, secure, and offline-first CLI tool built in Rust for inspecting, validating, and manipulating JSON Web Tokens (JWTs) and OAuth tokens.

**Stop pasting sensitive tokens into web portals. Debug them in your terminal.**

---

## Features

- **Instant Decoding** -- Decode base64url-encoded headers and payloads without signature verification
- **Pretty-Print Output** -- Colorized, formatted JSON for quick visual inspection
- **Offline Signature Validation** -- Validate HMAC (HS256/384/512), RSA (RS256/384/512, PS256/384/512), ECDSA (ES256/384), and EdDSA signatures with local secrets and PEM keys
- **Remote JWKS Validation** -- Fetch and validate against OIDC provider JWKS endpoints over HTTPS
- **Time-Travel Debugging** -- Simulate token expiry by evaluating `exp`/`nbf` against custom timestamps
- **Security First** -- No telemetry, no logging, memory-zeroed secrets via `zeroize`, stdin/env-var support to avoid shell history exposure

## Quick Start

```bash
# Decode a JWT (no signature verification)
jwt-term decode eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U

# Pipe from stdin (keeps token out of shell history)
cat token.txt | jwt-term decode

# Read token from environment variable
jwt-term decode --token-env JWT_TOKEN

# Verify an HMAC signature
jwt-term verify <token> --secret-env HMAC_SECRET

# Verify with a PEM public key
jwt-term verify <token> --key-file public.pem

# Verify using a remote JWKS endpoint
jwt-term verify <token> --jwks-url "https://login.example.com/.well-known/jwks.json"

# Check if a token will be valid 7 days from now
jwt-term verify <token> --secret-env HMAC_SECRET --time-travel "+7d"
```

Run `jwt-term --help` to see all available commands and options.

## Supported Algorithms

| Family | Algorithms |
|--------|-----------|
| HMAC | HS256, HS384, HS512 |
| RSA | RS256, RS384, RS512 |
| RSA-PSS | PS256, PS384, PS512 |
| ECDSA | ES256, ES384 |
| EdDSA | EdDSA |

## Security Highlights

- **No telemetry or analytics** -- Never phones home
- **No logging** -- Tokens and secrets are never written to disk
- **Memory-zeroed secrets** -- Sensitive data zeroized after use via the `zeroize` crate
- **`#![forbid(unsafe_code)]`** -- No unsafe Rust anywhere in the crate
- **HTTPS-only JWKS** -- Remote key fetching requires HTTPS
- **Shell history safety** -- Use `--token-env` or stdin to keep tokens out of history

## License

MIT License. See [LICENSE](https://github.com/felipemorandini/jwt-term/blob/main/LICENSE) for details.

## Author

**Felipe Pires Morandini**

- GitHub: [@felipemorandini](https://github.com/felipemorandini)
