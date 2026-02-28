//! JWKS (JSON Web Key Set) fetching and key matching.
//!
//! Handles fetching a JWKS from a remote OIDC endpoint, parsing the
//! response, and finding the correct key by `kid` (Key ID) to validate
//! a JWT's signature.

use crate::core::validator::ValidationOutcome;
use crate::error::JwtTermError;

/// Fetch a JWKS from the given URL and validate a token against it.
///
/// Performs an HTTPS GET request to the JWKS endpoint, finds the key
/// matching the token's `kid` header claim, and validates the signature.
/// Returns a [`ValidationOutcome`] consistent with local validation.
///
/// # Security
///
/// - Only HTTPS URLs are accepted.
/// - Request timeout is enforced (10 seconds).
/// - Response size is limited (1 MB).
///
/// # Errors
///
/// Returns an error if the URL is not HTTPS, the request fails, no
/// matching key is found, or signature validation fails.
pub fn validate_with_jwks(
    _token: &str,
    _jwks_url: &str,
) -> Result<ValidationOutcome, JwtTermError> {
    Err(JwtTermError::NotImplemented {
        command: "validate_with_jwks".to_string(),
    })
}
