//! JWT signature validation logic.
//!
//! Provides functions to validate JWT signatures using HMAC shared
//! secrets or PEM-encoded public keys (RSA, ECDSA). Automatically
//! detects the algorithm from the JWT header.

use crate::error::JwtTermError;

/// The result of a signature validation attempt.
#[derive(Debug, PartialEq, Eq)]
pub enum ValidationOutcome {
    /// The signature is cryptographically valid.
    Valid,
    /// The signature does not match.
    Invalid {
        /// Human-readable reason for the failure.
        reason: String,
    },
}

/// Validate a JWT's signature using the provided secret or key material.
///
/// Auto-detects the algorithm from the token header and applies the
/// appropriate validation strategy. Sensitive key material is zeroized
/// after validation completes.
///
/// # Errors
///
/// Returns an error if the token format is invalid, the algorithm is
/// unsupported, or the key material cannot be parsed.
pub fn validate_token(
    _token: &str,
    _key_material: &[u8],
) -> Result<ValidationOutcome, JwtTermError> {
    Err(JwtTermError::NotImplemented {
        command: "validate_token".to_string(),
    })
}
