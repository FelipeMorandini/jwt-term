//! Handler for the `decode` subcommand.
//!
//! Decodes and pretty-prints a JWT's header and payload without
//! verifying its signature. Supports reading the token from a CLI
//! argument, environment variable, or stdin.

use anyhow::{Context, Result};
use colored::Colorize;
use serde_json::json;

use crate::cli::DecodeArgs;
use crate::core::decoder;
use crate::display::{json_printer, token_status};

use super::resolve_token;

/// Execute the `decode` subcommand with the given arguments.
///
/// Resolves the token from the available input sources, decodes it,
/// and displays the header, payload, and token status.
pub fn execute(args: &DecodeArgs) -> Result<()> {
    let token = resolve_token(args.token.as_deref(), args.token_env.as_deref())
        .context("failed to read token")?;

    let decoded = decoder::decode_token(&token).context("failed to decode token")?;

    if args.json {
        let combined = json!({
            "header": decoded.header,
            "payload": decoded.payload,
        });
        json_printer::print_json(&combined, false);
    } else {
        println!("\n{}", "--- Header ---".bold());
        json_printer::print_json(&decoded.header, true);

        println!("\n{}", "--- Payload ---".bold());
        json_printer::print_json(&decoded.payload, true);

        println!("\n{}", "--- Token Status ---".bold());
        token_status::display_token_status(&decoded.payload);
        println!();
    }

    Ok(())
}
