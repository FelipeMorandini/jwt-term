//! Shared test fixtures and helper utilities.
//!
//! Provides pre-built JWT tokens with known claims for use in
//! both unit and integration tests.
//!
//! Some fixtures are defined ahead of use for later phases.
#![allow(dead_code)]

/// A valid HS256-signed JWT for testing.
///
/// Header: `{"alg":"HS256","typ":"JWT"}`
/// Payload: `{"sub":"1234567890","name":"Test User","iat":1516239022}`
/// Secret: `"test-secret"`
pub const VALID_HS256_TOKEN: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
     eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QgVXNlciIsImlhdCI6MTUxNjIzOTAyMn0.\
     SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

/// A malformed token with only two parts (missing signature).
pub const MALFORMED_TOKEN_TWO_PARTS: &str = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0";

/// A completely invalid token string.
pub const INVALID_TOKEN: &str = "not-a-valid-jwt";

/// An empty string for edge case testing.
pub const EMPTY_TOKEN: &str = "";
