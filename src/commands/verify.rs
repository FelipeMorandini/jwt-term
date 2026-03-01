//! Handler for the `verify` subcommand.
//!
//! Verifies a JWT's signature using a shared secret or PEM-encoded
//! public key. Remote JWKS endpoint validation is planned but not
//! yet implemented. Displays the decoded token contents alongside
//! the validation result.

use anyhow::{Context, Result};
use colored::Colorize;
use serde_json::json;
use zeroize::Zeroizing;

use crate::cli::VerifyArgs;
use crate::core::validator::{KeyMaterial, ValidationOutcome};
use crate::core::{decoder, validator};
use crate::display::{json_printer, token_status};
use crate::error::JwtTermError;

use super::resolve_token;

/// Execute the `verify` subcommand with the given arguments.
///
/// Resolves the token and key material, validates the signature,
/// then displays the decoded contents and validation result.
/// Returns `true` if the signature is valid, `false` if invalid.
/// The caller is responsible for mapping the boolean to an exit code.
pub fn execute(args: &VerifyArgs) -> Result<bool> {
    // Guard: features not yet implemented
    if args.jwks_url.is_some() {
        return Err(JwtTermError::NotImplemented {
            command: "JWKS validation (--jwks-url)".to_string(),
        }
        .into());
    }
    if args.time_travel.is_some() {
        return Err(JwtTermError::NotImplemented {
            command: "time-travel (--time-travel)".to_string(),
        }
        .into());
    }

    let token = resolve_token(args.token.as_deref(), args.token_env.as_deref())
        .context("failed to read token")?;

    let decoded = decoder::decode_token(&token).context("failed to decode token")?;

    let algorithm = decoded
        .header
        .get("alg")
        .and_then(|v| v.as_str())
        .ok_or(JwtTermError::InvalidTokenFormat)?;

    let key = resolve_key_material(args).context("failed to resolve key material")?;

    let outcome = validator::validate_signature(&token, algorithm, &key)
        .context("signature validation failed")?;

    if args.json {
        display_json(&decoded, &outcome, algorithm);
    } else {
        display_colored(&decoded, &outcome, algorithm);
    }

    Ok(matches!(outcome, ValidationOutcome::Valid))
}

/// Resolve key material from CLI arguments.
///
/// Checks sources in priority order:
/// 1. `--secret` (HMAC secret from CLI arg)
/// 2. `--secret-env` (HMAC secret from environment variable)
/// 3. `--key-file` (PEM-encoded public key from file)
fn resolve_key_material(args: &VerifyArgs) -> Result<KeyMaterial, JwtTermError> {
    if let Some(ref secret) = args.secret {
        return Ok(KeyMaterial::Secret(Zeroizing::new(
            secret.as_bytes().to_vec(),
        )));
    }

    if let Some(ref env_name) = args.secret_env {
        super::validate_env_var_name(env_name)?;
        let secret = Zeroizing::new(std::env::var(env_name).map_err(|e| match e {
            std::env::VarError::NotPresent => JwtTermError::EnvVarNotFound {
                name: env_name.clone(),
            },
            std::env::VarError::NotUnicode(_) => JwtTermError::EnvVarNotUnicode {
                name: env_name.clone(),
            },
        })?);
        let bytes = Zeroizing::new(secret.as_bytes().to_vec());
        drop(secret);
        return Ok(KeyMaterial::Secret(bytes));
    }

    if let Some(ref path) = args.key_file {
        let bytes = std::fs::read(path).map_err(|e| JwtTermError::KeyFileError {
            path: path.display().to_string(),
            reason: super::sanitize_io_error(&e),
        })?;
        return Ok(KeyMaterial::PemKey(bytes));
    }

    Err(JwtTermError::NoKeyProvided)
}

/// Display results in colorized terminal format.
fn display_colored(decoded: &decoder::DecodedToken, outcome: &ValidationOutcome, algorithm: &str) {
    println!("\n{}", "--- Header ---".bold());
    json_printer::print_json(&decoded.header, true);

    println!("\n{}", "--- Payload ---".bold());
    json_printer::print_json(&decoded.payload, true);

    println!("\n{}", "--- Token Status ---".bold());
    token_status::display_token_status(&decoded.payload);

    println!("\n{}", "--- Signature ---".bold());
    token_status::display_validation_result(outcome, algorithm);
    println!();
}

/// Display results in machine-readable JSON format.
fn display_json(decoded: &decoder::DecodedToken, outcome: &ValidationOutcome, algorithm: &str) {
    let signature_info = match outcome {
        ValidationOutcome::Valid => json!({
            "valid": true,
            "algorithm": algorithm,
        }),
        ValidationOutcome::Invalid { reason } => json!({
            "valid": false,
            "algorithm": algorithm,
            "reason": reason,
        }),
    };

    let combined = json!({
        "header": decoded.header,
        "payload": decoded.payload,
        "signature": signature_info,
    });
    json_printer::print_json(&combined, false);
}
