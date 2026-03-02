//! Core business logic for JWT operations.
//!
//! This module contains the domain logic separated from CLI concerns.
//! All types and functions here are testable without the CLI layer.

pub mod decoder;
pub mod jwks;
#[allow(dead_code)]
pub mod time_travel;
pub mod validator;

/// Sanitize a `jsonwebtoken` error kind into a user-friendly message.
///
/// Maps internal error details to generic messages so that raw library
/// internals (e.g., base64 decoding buffers, JSON fragments) are never
/// exposed to the user.
pub(crate) fn sanitize_jwt_error(kind: &jsonwebtoken::errors::ErrorKind) -> String {
    match kind {
        jsonwebtoken::errors::ErrorKind::InvalidToken => "invalid token structure".to_string(),
        jsonwebtoken::errors::ErrorKind::Base64(_) => "invalid base64 encoding".to_string(),
        jsonwebtoken::errors::ErrorKind::Json(_) => "invalid JSON in token".to_string(),
        jsonwebtoken::errors::ErrorKind::Utf8(_) => "invalid UTF-8 in token".to_string(),
        jsonwebtoken::errors::ErrorKind::InvalidAlgorithm => {
            "algorithm mismatch between header and validation".to_string()
        }
        _ => "unexpected validation error".to_string(),
    }
}
