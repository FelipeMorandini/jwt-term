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

/// HMAC secret used to sign test tokens for verify tests.
pub const HMAC_TEST_SECRET: &str = "verify-test-secret-key";

/// Path to the test RSA public key fixture.
pub const RSA_PUBLIC_KEY_PATH: &str = "tests/fixtures/rsa_public.pem";

/// Path to the test RSA private key fixture.
pub const RSA_PRIVATE_KEY_PATH: &str = "tests/fixtures/rsa_private.pem";

/// Path to the test EC public key fixture.
pub const EC_PUBLIC_KEY_PATH: &str = "tests/fixtures/ec_public.pem";

/// Path to the test EC private key fixture.
pub const EC_PRIVATE_KEY_PATH: &str = "tests/fixtures/ec_private.pem";

/// Create an HS256-signed token with the given claims.
pub fn create_hs256_token(secret: &str, claims: &serde_json::Value) -> String {
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    let header = Header::new(Algorithm::HS256);
    let key = EncodingKey::from_secret(secret.as_bytes());
    encode(&header, claims, &key).unwrap()
}

/// Create an RS256-signed token using the test RSA private key.
pub fn create_rs256_token(claims: &serde_json::Value) -> String {
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    let private_key = std::fs::read(RSA_PRIVATE_KEY_PATH).unwrap();
    let header = Header::new(Algorithm::RS256);
    let key = EncodingKey::from_rsa_pem(&private_key).unwrap();
    encode(&header, claims, &key).unwrap()
}

/// Create an ES256-signed token using the test EC private key.
pub fn create_es256_token(claims: &serde_json::Value) -> String {
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    let private_key = std::fs::read(EC_PRIVATE_KEY_PATH).unwrap();
    let header = Header::new(Algorithm::ES256);
    let key = EncodingKey::from_ec_pem(&private_key).unwrap();
    encode(&header, claims, &key).unwrap()
}

/// Standard test claims used across verify tests.
pub fn standard_claims() -> serde_json::Value {
    serde_json::json!({
        "sub": "1234567890",
        "name": "Test User",
        "iat": 1516239022
    })
}
