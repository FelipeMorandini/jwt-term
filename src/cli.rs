//! CLI argument definitions for jwt-term.
//!
//! Uses `clap` derive macros to define the command-line interface.
//! Each subcommand has its own argument struct for type-safe parsing.
//!
//! # Security
//!
//! `DecodeArgs` and `VerifyArgs` implement custom `Debug` to redact
//! sensitive fields (tokens and secrets) and prevent accidental leakage
//! through debug formatting, error chains, or logging.

use std::fmt;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use zeroize::Zeroizing;

/// A blazing-fast, secure, and offline-first CLI for inspecting,
/// validating, and manipulating JSON Web Tokens (JWTs).
#[derive(Debug, Parser)]
#[command(name = "jwt-term")]
#[command(version, about, long_about = None)]
pub struct Cli {
    /// The subcommand to execute.
    #[command(subcommand)]
    pub command: Commands,
}

/// Available subcommands.
#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Decode and inspect a JWT without verifying its signature.
    Decode(DecodeArgs),

    /// Verify a JWT's signature using a secret, key file, or JWKS endpoint.
    Verify(VerifyArgs),
}

/// Arguments for the `decode` subcommand.
#[derive(clap::Args)]
pub struct DecodeArgs {
    /// The JWT token to decode. If omitted, reads from stdin.
    pub token: Option<String>,

    /// Read the token from the specified environment variable.
    #[arg(long, value_name = "VAR_NAME")]
    pub token_env: Option<String>,

    /// Output raw JSON without colors (machine-readable).
    #[arg(long)]
    pub json: bool,
}

/// Custom `Debug` that redacts the token field to prevent accidental leakage.
impl fmt::Debug for DecodeArgs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DecodeArgs")
            .field("token", &self.token.as_ref().map(|_| "[REDACTED]"))
            .field("token_env", &self.token_env)
            .field("json", &self.json)
            .finish()
    }
}

/// Arguments for the `verify` subcommand.
#[derive(clap::Args)]
pub struct VerifyArgs {
    /// The JWT token to verify. If omitted, reads from stdin.
    pub token: Option<String>,

    /// Read the token from the specified environment variable.
    #[arg(long, value_name = "VAR_NAME")]
    pub token_env: Option<String>,

    /// HMAC shared secret for signature validation.
    ///
    /// WARNING: Passing secrets via CLI arguments may expose them in shell
    /// history. Prefer using --secret-env or piping via stdin instead.
    #[arg(long, value_name = "SECRET", value_parser = parse_zeroizing_string)]
    pub secret: Option<Zeroizing<String>>,

    /// Read the HMAC secret from the specified environment variable.
    #[arg(long, value_name = "VAR_NAME")]
    pub secret_env: Option<String>,

    /// Path to a PEM-encoded public key file (RSA, ECDSA, or EdDSA).
    #[arg(long, value_name = "FILE")]
    pub key_file: Option<PathBuf>,

    /// URL of a JWKS endpoint for remote key discovery.
    ///
    /// Must be HTTPS. The tool will fetch the key set and find the
    /// matching key by the token's `kid` header claim.
    #[arg(long, value_name = "URL")]
    pub jwks_url: Option<String>,

    /// Simulate a different current time for expiry/nbf checks.
    ///
    /// Accepts relative expressions like "+7d", "-1h", "+30m" or
    /// absolute timestamps in ISO 8601 or Unix epoch format.
    #[arg(long, value_name = "EXPR")]
    pub time_travel: Option<String>,

    /// Output raw JSON without colors (machine-readable).
    #[arg(long)]
    pub json: bool,
}

/// Parse a string into a `Zeroizing<String>` for secure CLI arguments.
fn parse_zeroizing_string(s: &str) -> Result<Zeroizing<String>, std::convert::Infallible> {
    Ok(Zeroizing::new(s.to_string()))
}

/// Custom `Debug` that redacts token and secret fields to prevent
/// accidental leakage through debug formatting or error chains.
impl fmt::Debug for VerifyArgs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifyArgs")
            .field("token", &self.token.as_ref().map(|_| "[REDACTED]"))
            .field("token_env", &self.token_env)
            .field("secret", &self.secret.as_ref().map(|_| "[REDACTED]"))
            .field("secret_env", &self.secret_env)
            .field("key_file", &self.key_file)
            .field("jwks_url", &self.jwks_url)
            .field("time_travel", &self.time_travel)
            .field("json", &self.json)
            .finish()
    }
}
