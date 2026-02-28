//! JWT decoding logic.
//!
//! Handles splitting a raw JWT string into its three parts (header,
//! payload, signature), base64url-decoding each segment, and parsing
//! the header and payload as JSON values.

use serde_json::Value;

use crate::error::JwtTermError;

/// The decoded parts of a JWT.
#[derive(Debug)]
pub struct DecodedToken {
    /// The parsed JWT header (typically contains `alg` and `typ`).
    pub header: Value,
    /// The parsed JWT payload (claims).
    pub payload: Value,
    /// The raw base64url-encoded signature segment.
    pub signature: String,
}

/// Decode a raw JWT string into its constituent parts.
///
/// Splits the token on `.` separators, base64url-decodes the header
/// and payload segments, and parses them as JSON. The signature is
/// returned as its raw base64url-encoded string.
///
/// # Errors
///
/// Returns an error if the token doesn't have exactly three parts,
/// if base64url decoding fails, or if JSON parsing fails.
pub fn decode_token(_token: &str) -> Result<DecodedToken, JwtTermError> {
    Err(JwtTermError::NotImplemented {
        command: "decode_token".to_string(),
    })
}
