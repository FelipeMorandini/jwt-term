//! Handler for the `decode` subcommand.
//!
//! Decodes and pretty-prints a JWT's header and payload without
//! verifying its signature. Supports reading the token from a CLI
//! argument, environment variable, or stdin.

use anyhow::Result;

use crate::cli::DecodeArgs;
use crate::error::JwtTermError;

/// Execute the `decode` subcommand with the given arguments.
pub fn execute(_args: &DecodeArgs) -> Result<()> {
    Err(JwtTermError::NotImplemented {
        command: "decode".to_string(),
    }
    .into())
}
