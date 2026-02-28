//! Handler for the `verify` subcommand.
//!
//! Verifies a JWT's signature using a shared secret, PEM-encoded
//! public key, or a remotely fetched JWKS endpoint. Also supports
//! time-travel debugging for expiry and not-before claim evaluation.

use anyhow::Result;

use crate::cli::VerifyArgs;
use crate::error::JwtTermError;

/// Execute the `verify` subcommand with the given arguments.
pub fn execute(_args: &VerifyArgs) -> Result<()> {
    Err(JwtTermError::NotImplemented {
        command: "verify".to_string(),
    }
    .into())
}
