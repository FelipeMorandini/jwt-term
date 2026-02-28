//! Domain error types for jwt-term.
//!
//! All business-logic errors are defined here using `thiserror`.
//! These errors are converted to user-friendly messages at the CLI boundary.

use thiserror::Error;

/// Errors that can occur during JWT operations.
///
/// Variants are defined upfront for all planned features. Some variants
/// are not yet used and will be activated in later implementation phases.
#[derive(Debug, Error)]
#[allow(dead_code)]
pub enum JwtTermError {
    /// The provided token does not have the expected three-part structure.
    #[error("invalid token format: expected 'header.payload.signature' structure")]
    InvalidTokenFormat,

    /// Failed to decode base64url-encoded token segment.
    #[error("failed to decode {segment}: invalid base64url encoding")]
    Base64DecodeError {
        /// Which segment failed to decode (e.g., "header", "payload").
        segment: String,
    },

    /// Failed to parse decoded JSON content.
    #[error("failed to parse {segment} as JSON: {reason}")]
    JsonParseError {
        /// Which segment failed to parse (e.g., "header", "payload").
        segment: String,
        /// Description of the parsing failure.
        reason: String,
    },

    /// Signature validation failed.
    #[error("signature validation failed: {reason}")]
    SignatureInvalid {
        /// Description of why validation failed.
        reason: String,
    },

    /// The specified algorithm is not supported.
    #[error("unsupported algorithm: {algorithm}")]
    UnsupportedAlgorithm {
        /// The algorithm that was encountered.
        algorithm: String,
    },

    /// Failed to read the provided key file.
    #[error("failed to read key file '{path}': {reason}")]
    KeyFileError {
        /// Path to the key file.
        path: String,
        /// Description of the read failure.
        reason: String,
    },

    /// Failed to fetch JWKS from the remote endpoint.
    #[error("failed to fetch JWKS from '{url}': {reason}")]
    JwksFetchError {
        /// The JWKS endpoint URL.
        url: String,
        /// Description of the fetch failure.
        reason: String,
    },

    /// No matching key was found in the JWKS for the token's key ID.
    #[error("no matching key found in JWKS for kid '{kid}'")]
    JwksKeyNotFound {
        /// The key ID from the token header.
        kid: String,
    },

    /// Failed to parse a time-travel expression.
    #[error("invalid time expression '{expression}': {reason}")]
    InvalidTimeExpression {
        /// The time expression that failed to parse.
        expression: String,
        /// Description of the parsing failure.
        reason: String,
    },

    /// No token was provided via any input method.
    #[error("no token provided: pass a token as an argument, via --token-env, or through stdin")]
    NoTokenProvided,

    /// The specified environment variable is not set.
    #[error("environment variable '{name}' is not set")]
    EnvVarNotFound {
        /// Name of the missing environment variable.
        name: String,
    },

    /// The command is not yet implemented.
    #[error("{command} is not yet implemented")]
    NotImplemented {
        /// Name of the unimplemented command.
        command: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invalid_token_format_display() {
        let err = JwtTermError::InvalidTokenFormat;
        assert_eq!(
            err.to_string(),
            "invalid token format: expected 'header.payload.signature' structure"
        );
    }

    #[test]
    fn test_base64_decode_error_display_includes_segment() {
        let err = JwtTermError::Base64DecodeError {
            segment: "header".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "failed to decode header: invalid base64url encoding"
        );
    }

    #[test]
    fn test_json_parse_error_display_includes_segment_and_reason() {
        let err = JwtTermError::JsonParseError {
            segment: "payload".to_string(),
            reason: "unexpected EOF".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "failed to parse payload as JSON: unexpected EOF"
        );
    }

    #[test]
    fn test_signature_invalid_display() {
        let err = JwtTermError::SignatureInvalid {
            reason: "HMAC mismatch".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "signature validation failed: HMAC mismatch"
        );
    }

    #[test]
    fn test_unsupported_algorithm_display() {
        let err = JwtTermError::UnsupportedAlgorithm {
            algorithm: "none".to_string(),
        };
        assert_eq!(err.to_string(), "unsupported algorithm: none");
    }

    #[test]
    fn test_key_file_error_display() {
        let err = JwtTermError::KeyFileError {
            path: "/tmp/key.pem".to_string(),
            reason: "file not found".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "failed to read key file '/tmp/key.pem': file not found"
        );
    }

    #[test]
    fn test_jwks_fetch_error_display() {
        let err = JwtTermError::JwksFetchError {
            url: "https://auth.example.com/.well-known/jwks.json".to_string(),
            reason: "connection timed out".to_string(),
        };
        assert!(err.to_string().contains("auth.example.com"));
        assert!(err.to_string().contains("connection timed out"));
    }

    #[test]
    fn test_jwks_key_not_found_display() {
        let err = JwtTermError::JwksKeyNotFound {
            kid: "abc123".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "no matching key found in JWKS for kid 'abc123'"
        );
    }

    #[test]
    fn test_invalid_time_expression_display() {
        let err = JwtTermError::InvalidTimeExpression {
            expression: "+7x".to_string(),
            reason: "unknown unit 'x'".to_string(),
        };
        assert!(err.to_string().contains("+7x"));
        assert!(err.to_string().contains("unknown unit 'x'"));
    }

    #[test]
    fn test_no_token_provided_display() {
        let err = JwtTermError::NoTokenProvided;
        assert!(err.to_string().contains("no token provided"));
        assert!(err.to_string().contains("--token-env"));
        assert!(err.to_string().contains("stdin"));
    }

    #[test]
    fn test_env_var_not_found_display() {
        let err = JwtTermError::EnvVarNotFound {
            name: "JWT_TOKEN".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "environment variable 'JWT_TOKEN' is not set"
        );
    }

    #[test]
    fn test_not_implemented_display() {
        let err = JwtTermError::NotImplemented {
            command: "decode".to_string(),
        };
        assert_eq!(err.to_string(), "decode is not yet implemented");
    }

    #[test]
    fn test_error_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<JwtTermError>();
    }
}
