//! JWT decoding logic.
//!
//! Handles splitting a raw JWT string into its three parts (header,
//! payload, signature), base64url-decoding each segment, and parsing
//! the header and payload as JSON values.

use std::fmt;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::Value;

use crate::error::JwtTermError;

/// The decoded parts of a JWT.
///
/// Implements a custom `Debug` that redacts `payload` and `signature`
/// to prevent accidental leakage of sensitive claim data.
pub struct DecodedToken {
    /// The parsed JWT header (typically contains `alg` and `typ`).
    pub header: Value,
    /// The parsed JWT payload (claims).
    pub payload: Value,
    /// The raw base64url-encoded signature segment.
    ///
    /// Used by the verify command (Phase 3) for signature validation.
    #[allow(dead_code)]
    pub signature: String,
}

/// Custom `Debug` that redacts payload and signature to prevent
/// accidental leakage through debug formatting or error chains.
impl fmt::Debug for DecodedToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DecodedToken")
            .field("header", &self.header)
            .field("payload", &"[REDACTED]")
            .field("signature", &"[REDACTED]")
            .finish()
    }
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
pub fn decode_token(token: &str) -> Result<DecodedToken, JwtTermError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(JwtTermError::InvalidTokenFormat);
    }

    let header = decode_segment(parts[0], "header")?;
    let payload = decode_segment(parts[1], "payload")?;
    let signature = parts[2].to_string();

    Ok(DecodedToken {
        header,
        payload,
        signature,
    })
}

/// Base64url-decode a segment and parse it as JSON.
fn decode_segment(encoded: &str, segment_name: &str) -> Result<Value, JwtTermError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| JwtTermError::Base64DecodeError {
            segment: segment_name.to_string(),
        })?;

    serde_json::from_slice(&bytes).map_err(|e| JwtTermError::JsonParseError {
        segment: segment_name.to_string(),
        reason: e.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decoded_token_debug_redacts_sensitive_fields() {
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
                     eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QgVXNlciIsImlhdCI6MTUxNjIzOTAyMn0.\
                     SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let decoded = decode_token(token).unwrap();
        let debug_output = format!("{:?}", decoded);

        // Header is shown (not sensitive — contains algorithm info)
        assert!(debug_output.contains("HS256"));
        // Payload and signature are redacted
        assert!(debug_output.contains("[REDACTED]"));
        assert!(!debug_output.contains("1234567890"));
        assert!(!debug_output.contains("Test User"));
        assert!(!debug_output.contains("SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"));
    }

    #[test]
    fn test_decode_valid_hs256_token() {
        // Header: {"alg":"HS256","typ":"JWT"}
        // Payload: {"sub":"1234567890","name":"Test User","iat":1516239022}
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
                     eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QgVXNlciIsImlhdCI6MTUxNjIzOTAyMn0.\
                     SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

        let decoded = decode_token(token).unwrap();

        assert_eq!(decoded.header["alg"], "HS256");
        assert_eq!(decoded.header["typ"], "JWT");
        assert_eq!(decoded.payload["sub"], "1234567890");
        assert_eq!(decoded.payload["name"], "Test User");
        assert_eq!(decoded.payload["iat"], 1516239022);
        assert_eq!(
            decoded.signature,
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        );
    }

    #[test]
    fn test_decode_token_with_two_parts_fails() {
        let token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0";
        let err = decode_token(token).unwrap_err();
        assert!(matches!(err, JwtTermError::InvalidTokenFormat));
    }

    #[test]
    fn test_decode_token_with_one_part_fails() {
        let err = decode_token("just-one-part").unwrap_err();
        assert!(matches!(err, JwtTermError::InvalidTokenFormat));
    }

    #[test]
    fn test_decode_token_with_four_parts_fails() {
        let err = decode_token("a.b.c.d").unwrap_err();
        assert!(matches!(err, JwtTermError::InvalidTokenFormat));
    }

    #[test]
    fn test_decode_token_empty_string_fails() {
        let err = decode_token("").unwrap_err();
        assert!(matches!(err, JwtTermError::InvalidTokenFormat));
    }

    #[test]
    fn test_decode_token_invalid_base64_header_fails() {
        let err = decode_token("!!!invalid!!!.eyJzdWIiOiIxMjM0In0.sig").unwrap_err();
        assert!(matches!(
            err,
            JwtTermError::Base64DecodeError { segment } if segment == "header"
        ));
    }

    #[test]
    fn test_decode_token_invalid_base64_payload_fails() {
        // Valid base64 header, invalid base64 payload
        let err = decode_token("eyJhbGciOiJIUzI1NiJ9.!!!invalid!!!.sig").unwrap_err();
        assert!(matches!(
            err,
            JwtTermError::Base64DecodeError { segment } if segment == "payload"
        ));
    }

    #[test]
    fn test_decode_token_invalid_json_header_fails() {
        // Base64url-encode "not json" → "bm90IGpzb24"
        let err = decode_token("bm90IGpzb24.eyJzdWIiOiIxMjM0In0.sig").unwrap_err();
        assert!(matches!(
            err,
            JwtTermError::JsonParseError { segment, .. } if segment == "header"
        ));
    }

    #[test]
    fn test_decode_token_invalid_json_payload_fails() {
        // Valid JSON header, base64url("not json") as payload
        let err = decode_token("eyJhbGciOiJIUzI1NiJ9.bm90IGpzb24.sig").unwrap_err();
        assert!(matches!(
            err,
            JwtTermError::JsonParseError { segment, .. } if segment == "payload"
        ));
    }

    #[test]
    fn test_decode_token_with_empty_payload_object() {
        // Header: {"alg":"none"}, Payload: {}
        // eyJhbGciOiJub25lIn0 = {"alg":"none"}
        // e30 = {}
        let token = "eyJhbGciOiJub25lIn0.e30.";
        let decoded = decode_token(token).unwrap();
        assert_eq!(decoded.header["alg"], "none");
        assert!(decoded.payload.as_object().unwrap().is_empty());
        assert_eq!(decoded.signature, "");
    }
}
