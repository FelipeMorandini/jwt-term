# Usage Guide

## Commands

### decode

Decode and inspect a JWT without verifying its signature.

```bash
jwt-term decode [OPTIONS] [TOKEN]
```

| Option | Description |
|--------|-------------|
| `--token-env <VAR>` | Read token from the named environment variable |
| `--json` | Output raw JSON without colors (machine-readable) |

The token can be provided as a positional argument, via `--token-env`, or piped through stdin.

**Examples:**

```bash
# Decode from argument
jwt-term decode eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.signature

# Decode from environment variable
jwt-term decode --token-env MY_JWT

# Decode from stdin
cat token.txt | jwt-term decode
echo $JWT_TOKEN | jwt-term decode

# Machine-readable output
jwt-term decode --json eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.signature
```

### verify

Verify a JWT's signature using a local secret, key file, or remote JWKS endpoint. Displays the decoded token alongside the validation result. Exits with code 1 if the signature is invalid.

```bash
jwt-term verify [OPTIONS] [TOKEN]
```

| Option | Description |
|--------|-------------|
| `--secret <SECRET>` | HMAC shared secret (see security note below) |
| `--secret-env <VAR>` | Read HMAC secret from environment variable (recommended) |
| `--key-file <FILE>` | PEM-encoded public key file (RSA/ECDSA/EdDSA) |
| `--jwks-url <URL>` | JWKS endpoint URL (HTTPS only) |
| `--time-travel <EXPR>` | Evaluate expiry at a simulated time |
| `--token-env <VAR>` | Read token from environment variable |
| `--json` | Output raw JSON without colors |

!!! warning "Security Note"
    Prefer `--secret-env` over `--secret`. Passing secrets as CLI arguments exposes them in shell history and process listings. Use environment variables or stdin for sensitive values.

**Examples:**

```bash
# Verify with HMAC secret from environment
jwt-term verify <token> --secret-env HMAC_SECRET

# Verify with RSA public key
jwt-term verify <token> --key-file public.pem

# Verify with ECDSA key
jwt-term verify <token> --key-file ec-public.pem

# Verify against a JWKS endpoint
jwt-term verify <token> --jwks-url "https://login.example.com/.well-known/jwks.json"
```

### completions

Generate shell completion scripts for tab-completion support.

```bash
jwt-term completions <SHELL>
```

Supported shells: `bash`, `zsh`, `fish`, `elvish`, `powershell`.

## Time-Travel Debugging

The `--time-travel` flag lets you simulate a different "current time" when evaluating temporal claims (`exp`, `nbf`).

### Relative Time Expressions

| Expression | Meaning |
|-----------|---------|
| `+7d` | 7 days from now |
| `-1h` | 1 hour ago |
| `+30m` | 30 minutes from now |
| `+1y` | 1 year from now |
| `-5s` | 5 seconds ago |

### Absolute Timestamps

- **ISO 8601**: `2024-06-01T00:00:00Z`
- **Unix epoch**: `1717200000`

**Examples:**

```bash
# Check if token will be valid in 7 days
jwt-term verify <token> --secret-env HMAC_SECRET --time-travel "+7d"

# Check token status at a specific date
jwt-term verify <token> --key-file public.pem --time-travel "2024-06-01T00:00:00Z"

# Check if token was valid 1 hour ago
jwt-term verify <token> --secret-env HMAC_SECRET --time-travel "-1h"
```

## Token Input Methods

jwt-term supports three ways to provide a token, listed from most secure to least:

### 1. Stdin (Recommended)

```bash
cat token.txt | jwt-term decode
```

The token never appears in shell history or process listings.

### 2. Environment Variable

```bash
export MY_JWT="eyJhbG..."
jwt-term decode --token-env MY_JWT
```

The token value is read from the environment, keeping it out of shell history.

### 3. CLI Argument

```bash
jwt-term decode eyJhbG...
```

!!! warning
    The token will be visible in shell history (`~/.bash_history`) and process listings (`ps`). Use stdin or `--token-env` for sensitive tokens.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success (decode) or valid signature (verify) |
| 1 | Invalid signature (verify) or error |

## Machine-Readable Output

Use `--json` for output suitable for piping to `jq` or other tools:

```bash
jwt-term decode --json <token> | jq '.payload.sub'
jwt-term verify --json <token> --secret-env SECRET | jq '.valid'
```
