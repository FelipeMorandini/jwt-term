//! Handler for the `verify` subcommand.
//!
//! Verifies a JWT's signature using a shared secret, PEM-encoded
//! public key, or remote JWKS endpoint. Displays the decoded token
//! contents alongside the validation result.

use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result};
use colored::Colorize;
use serde_json::json;
use zeroize::Zeroizing;

use crate::cli::VerifyArgs;
use crate::core::time_travel::{self, ClaimStatus, TimeTravelResult};
use crate::core::validator::{KeyMaterial, ValidationOutcome};
use crate::core::{decoder, jwks, validator};
use crate::display::{json_printer, token_status};
use crate::error::JwtTermError;

use super::resolve_token;

/// Maximum key file size in bytes (1 MB).
const MAX_KEY_FILE_SIZE: u64 = 1_048_576;

/// Execute the `verify` subcommand with the given arguments.
///
/// Resolves the token and key material, validates the signature,
/// then displays the decoded contents and validation result.
/// When `--time-travel` is provided, also evaluates temporal claims
/// against the simulated timestamp.
/// Returns `true` if the signature is valid, `false` if invalid.
/// The caller is responsible for mapping the boolean to an exit code.
pub fn execute(args: &VerifyArgs) -> Result<bool> {
    if args.jwks_url.is_some() {
        check_jwks_conflicts(args)?;
    }

    let token = resolve_token(
        args.token.as_ref().map(|t| t.as_str()),
        args.token_env.as_deref(),
    )
    .context("failed to read token")?;

    let decoded = decoder::decode_token(&token).context("failed to decode token")?;
    // Parse time-travel before signature validation so invalid expressions
    // fail fast without triggering unnecessary JWKS network calls.
    let tt_result = resolve_time_travel(args.time_travel.as_deref(), &decoded.payload)?;
    let (outcome, display_algorithm) = validate_token(&token, &decoded, args)?;

    if args.json {
        display_json(&decoded, &outcome, &display_algorithm, tt_result.as_ref());
    } else {
        display_colored(&decoded, &outcome, &display_algorithm, tt_result.as_ref());
    }

    Ok(matches!(outcome, ValidationOutcome::Valid))
}

/// Validate the token's signature using JWKS or local key material.
///
/// Returns the validation outcome and the resolved algorithm name
/// for display purposes.
fn validate_token(
    token: &str,
    decoded: &decoder::DecodedToken,
    args: &VerifyArgs,
) -> Result<(ValidationOutcome, String)> {
    let algorithm = decoded
        .header
        .get("alg")
        .and_then(|v| v.as_str())
        .ok_or(JwtTermError::InvalidTokenFormat)?;

    if let Some(ref url) = args.jwks_url {
        let (outcome, resolved_alg) =
            jwks::validate_with_jwks(token, url).context("JWKS validation failed")?;
        Ok((outcome, resolved_alg))
    } else {
        let key = resolve_key_material(args).context("failed to resolve key material")?;
        let outcome = validator::validate_signature(token, algorithm, &key)
            .context("signature validation failed")?;
        Ok((outcome, algorithm.to_string()))
    }
}

/// Parse time-travel expression and evaluate temporal claims if requested.
fn resolve_time_travel(
    expr: Option<&str>,
    payload: &serde_json::Value,
) -> Result<Option<TimeTravelResult>> {
    expr.map(|e| -> Result<TimeTravelResult> {
        let target = time_travel::parse_time_expression(e)
            .context("failed to parse time-travel expression")?;
        Ok(time_travel::evaluate_temporal_claims(payload, &target))
    })
    .transpose()
}

/// Resolve key material from CLI arguments.
///
/// Checks sources in priority order:
/// 1. `--secret` (HMAC secret from CLI arg)
/// 2. `--secret-env` (HMAC secret from environment variable)
/// 3. `--key-file` (PEM-encoded public key from file)
fn resolve_key_material(args: &VerifyArgs) -> Result<KeyMaterial, JwtTermError> {
    if let Some(ref secret) = args.secret {
        return Ok(resolve_secret_from_arg(secret));
    }

    if let Some(ref env_name) = args.secret_env {
        return resolve_secret_from_env(env_name);
    }

    if let Some(ref path) = args.key_file {
        return resolve_key_from_file(path);
    }

    Err(JwtTermError::NoKeyProvided)
}

/// Build HMAC key material from a CLI argument value.
fn resolve_secret_from_arg(secret: &Zeroizing<String>) -> KeyMaterial {
    KeyMaterial::Secret(Zeroizing::new(secret.as_bytes().to_vec()))
}

/// Read an HMAC secret from the named environment variable.
fn resolve_secret_from_env(env_name: &str) -> Result<KeyMaterial, JwtTermError> {
    super::validate_env_var_name(env_name)?;
    let secret = Zeroizing::new(std::env::var(env_name).map_err(|e| match e {
        std::env::VarError::NotPresent => JwtTermError::EnvVarNotFound {
            name: env_name.to_string(),
        },
        std::env::VarError::NotUnicode(_) => JwtTermError::EnvVarNotUnicode {
            name: env_name.to_string(),
        },
    })?);
    let bytes = Zeroizing::new(secret.as_bytes().to_vec());
    drop(secret);
    Ok(KeyMaterial::Secret(bytes))
}

/// Read a PEM-encoded public key from a file path.
///
/// Opens the file, checks metadata on the same fd (TOCTOU-safe),
/// validates that it is a regular file within the size limit, and
/// reads the contents with a bounded read.
fn resolve_key_from_file(path: &Path) -> Result<KeyMaterial, JwtTermError> {
    let file = std::fs::File::open(path).map_err(|e| JwtTermError::KeyFileError {
        path: path.display().to_string(),
        reason: super::sanitize_io_error(&e),
    })?;
    let metadata = file.metadata().map_err(|e| JwtTermError::KeyFileError {
        path: path.display().to_string(),
        reason: super::sanitize_io_error(&e),
    })?;
    if !metadata.file_type().is_file() {
        return Err(JwtTermError::KeyFileError {
            path: path.display().to_string(),
            reason: "not a regular file".to_string(),
        });
    }
    if metadata.len() > MAX_KEY_FILE_SIZE {
        return Err(JwtTermError::KeyFileTooLarge {
            size: metadata.len(),
            max_size: MAX_KEY_FILE_SIZE,
        });
    }
    let bytes = read_bounded_file(file, path)?;
    Ok(KeyMaterial::PemKey(Zeroizing::new(bytes)))
}

/// Reject conflicting key options when `--jwks-url` is present.
///
/// Returns an error naming the first conflicting flag found.
fn check_jwks_conflicts(args: &VerifyArgs) -> Result<(), JwtTermError> {
    if args.secret.is_some() {
        return Err(JwtTermError::ConflictingKeyOptions {
            conflicting_flag: "--secret".to_string(),
        });
    }
    if args.secret_env.is_some() {
        return Err(JwtTermError::ConflictingKeyOptions {
            conflicting_flag: "--secret-env".to_string(),
        });
    }
    if args.key_file.is_some() {
        return Err(JwtTermError::ConflictingKeyOptions {
            conflicting_flag: "--key-file".to_string(),
        });
    }
    Ok(())
}

/// Read a key file with a bounded size limit.
///
/// Accepts an already-opened file handle to avoid TOCTOU races —
/// the caller opens the file and checks `file.metadata()` on the
/// same fd before passing it here. Reads up to `MAX_KEY_FILE_SIZE + 1`
/// bytes; if the read exceeds the limit, returns a `KeyFileTooLarge`
/// error.
fn read_bounded_file(file: std::fs::File, path: &Path) -> Result<Vec<u8>, JwtTermError> {
    let mut bytes = Vec::new();
    file.take(MAX_KEY_FILE_SIZE + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| JwtTermError::KeyFileError {
            path: path.display().to_string(),
            reason: super::sanitize_io_error(&e),
        })?;
    if bytes.len() as u64 > MAX_KEY_FILE_SIZE {
        return Err(JwtTermError::KeyFileTooLarge {
            size: bytes.len() as u64,
            max_size: MAX_KEY_FILE_SIZE,
        });
    }
    Ok(bytes)
}

/// Display results in colorized terminal format.
fn display_colored(
    decoded: &decoder::DecodedToken,
    outcome: &ValidationOutcome,
    algorithm: &str,
    time_travel: Option<&TimeTravelResult>,
) {
    println!("\n{}", "--- Header ---".bold());
    json_printer::print_json(&decoded.header, true);

    println!("\n{}", "--- Payload ---".bold());
    json_printer::print_json(&decoded.payload, true);

    println!("\n{}", "--- Token Status ---".bold());
    token_status::display_token_status(&decoded.payload);

    if let Some(tt_result) = time_travel {
        println!("\n{}", "--- Time Travel ---".bold());
        token_status::display_time_travel_status(tt_result);
    }

    println!("\n{}", "--- Signature ---".bold());
    token_status::display_validation_result(outcome, algorithm);
    println!();
}

/// Display results in machine-readable JSON format.
fn display_json(
    decoded: &decoder::DecodedToken,
    outcome: &ValidationOutcome,
    algorithm: &str,
    time_travel: Option<&TimeTravelResult>,
) {
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

    let mut combined = json!({
        "header": decoded.header,
        "payload": decoded.payload,
        "signature": signature_info,
    });

    if let Some(tt_result) = time_travel {
        combined["time_travel"] = build_time_travel_json(tt_result);
    }

    json_printer::print_json(&combined, false);
}

/// Build a JSON object with a status string and optional claim value.
fn claim_status_to_json(status: &str, claim_value: Option<i64>) -> serde_json::Value {
    let mut obj = json!({"status": status});
    if let Some(v) = claim_value {
        obj["claim_value"] = json!(v);
    }
    obj
}

/// Build the JSON representation of time-travel evaluation results.
fn build_time_travel_json(result: &TimeTravelResult) -> serde_json::Value {
    let exp_info = match &result.exp_status {
        ClaimStatus::Expired { .. } => claim_status_to_json("expired", result.exp_value),
        ClaimStatus::Valid => claim_status_to_json("valid", result.exp_value),
        ClaimStatus::Absent => json!({"status": "absent"}),
        ClaimStatus::Invalid => claim_status_to_json("invalid", result.exp_value),
        ClaimStatus::NotYetValid { .. } => claim_status_to_json("not_yet_valid", result.exp_value),
    };

    let nbf_info = match &result.nbf_status {
        ClaimStatus::NotYetValid { .. } => claim_status_to_json("not_yet_valid", result.nbf_value),
        ClaimStatus::Valid => claim_status_to_json("valid", result.nbf_value),
        ClaimStatus::Absent => json!({"status": "absent"}),
        ClaimStatus::Invalid => claim_status_to_json("invalid", result.nbf_value),
        ClaimStatus::Expired { .. } => claim_status_to_json("expired", result.nbf_value),
    };

    json!({
        "simulated_time": result.target.timestamp.to_rfc3339(),
        "expression": result.target.expression,
        "exp": exp_info,
        "nbf": nbf_info,
    })
}
