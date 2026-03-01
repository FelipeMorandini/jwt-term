//! JWT signature validation logic.
//!
//! Provides functions to validate JWT signatures using HMAC shared
//! secrets or PEM-encoded public keys (RSA, ECDSA, EdDSA). Automatically
//! detects the algorithm from the JWT header.

use std::collections::HashSet;

use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde_json::Value;
use zeroize::Zeroizing;

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

/// Key material for signature validation.
pub enum KeyMaterial {
    /// HMAC shared secret (for HS256, HS384, HS512).
    /// Wrapped in `Zeroizing` to ensure the secret is cleared from
    /// memory when no longer needed.
    Secret(Zeroizing<Vec<u8>>),
    /// PEM-encoded public key (for RSA, ECDSA, EdDSA).
    PemKey(Vec<u8>),
}

/// Validate a JWT's signature using the provided key material.
///
/// Detects the algorithm from the `algorithm` parameter (extracted from
/// the JWT header), constructs the appropriate verification key, and
/// validates the signature. Temporal claims (`exp`, `nbf`) are **not**
/// validated — this is a debugging tool that focuses on signature
/// correctness.
///
/// # Security
///
/// - Explicitly rejects `alg: "none"` as defense-in-depth.
/// - Verifies that the key material type matches the algorithm family
///   (HMAC vs. asymmetric) and returns a clear error on mismatch.
///
/// # Errors
///
/// Returns an error if:
/// - The algorithm is `"none"` or unrecognized
/// - The key material type doesn't match the algorithm family
/// - The PEM key cannot be parsed
/// - The token format is invalid
pub fn validate_signature(
    token: &str,
    algorithm: &str,
    key: &KeyMaterial,
) -> Result<ValidationOutcome, JwtTermError> {
    // Defense-in-depth: reject alg "none" before any processing
    if algorithm.eq_ignore_ascii_case("none") {
        return Err(JwtTermError::UnsupportedAlgorithm {
            algorithm: "none".to_string(),
        });
    }

    let alg = map_algorithm(algorithm)?;
    validate_key_algorithm_match(alg, key)?;

    let decoding_key = create_decoding_key(alg, key)?;

    let mut validation = Validation::new(alg);
    validation.validate_exp = false;
    validation.validate_nbf = false;
    validation.required_spec_claims = HashSet::new();

    match decode::<Value>(token, &decoding_key, &validation) {
        Ok(_) => Ok(ValidationOutcome::Valid),
        Err(e) => match e.kind() {
            jsonwebtoken::errors::ErrorKind::InvalidSignature => Ok(ValidationOutcome::Invalid {
                reason: "signature does not match the provided key".to_string(),
            }),
            _ => Err(JwtTermError::SignatureInvalid {
                reason: sanitize_jwt_error(e.kind()),
            }),
        },
    }
}

/// Map an algorithm name string to a `jsonwebtoken::Algorithm`.
fn map_algorithm(alg: &str) -> Result<Algorithm, JwtTermError> {
    match alg {
        "HS256" => Ok(Algorithm::HS256),
        "HS384" => Ok(Algorithm::HS384),
        "HS512" => Ok(Algorithm::HS512),
        "RS256" => Ok(Algorithm::RS256),
        "RS384" => Ok(Algorithm::RS384),
        "RS512" => Ok(Algorithm::RS512),
        "PS256" => Ok(Algorithm::PS256),
        "PS384" => Ok(Algorithm::PS384),
        "PS512" => Ok(Algorithm::PS512),
        "ES256" => Ok(Algorithm::ES256),
        "ES384" => Ok(Algorithm::ES384),
        "EdDSA" => Ok(Algorithm::EdDSA),
        _ => Err(JwtTermError::UnsupportedAlgorithm {
            algorithm: alg.to_string(),
        }),
    }
}

/// Verify that the key material type matches the algorithm family.
fn validate_key_algorithm_match(alg: Algorithm, key: &KeyMaterial) -> Result<(), JwtTermError> {
    let is_hmac = matches!(alg, Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512);

    match (is_hmac, key) {
        (true, KeyMaterial::Secret(_)) | (false, KeyMaterial::PemKey(_)) => Ok(()),
        (true, KeyMaterial::PemKey(_)) => Err(JwtTermError::SignatureInvalid {
            reason: format!(
                "algorithm {:?} requires a shared secret (--secret or --secret-env), not a key file",
                alg
            ),
        }),
        (false, KeyMaterial::Secret(_)) => Err(JwtTermError::SignatureInvalid {
            reason: format!(
                "algorithm {:?} requires a PEM key file (--key-file), not a shared secret",
                alg
            ),
        }),
    }
}

/// Create a `DecodingKey` from the key material and algorithm.
fn create_decoding_key(alg: Algorithm, key: &KeyMaterial) -> Result<DecodingKey, JwtTermError> {
    match key {
        KeyMaterial::Secret(secret) => Ok(DecodingKey::from_secret(secret)),
        KeyMaterial::PemKey(pem) => match alg {
            Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512 => {
                DecodingKey::from_rsa_pem(pem).map_err(|_| JwtTermError::SignatureInvalid {
                    reason: "failed to parse RSA PEM key".to_string(),
                })
            }
            Algorithm::ES256 | Algorithm::ES384 => {
                DecodingKey::from_ec_pem(pem).map_err(|_| JwtTermError::SignatureInvalid {
                    reason: "failed to parse EC PEM key".to_string(),
                })
            }
            Algorithm::EdDSA => {
                DecodingKey::from_ed_pem(pem).map_err(|_| JwtTermError::SignatureInvalid {
                    reason: "failed to parse EdDSA PEM key".to_string(),
                })
            }
            _ => Err(JwtTermError::UnsupportedAlgorithm {
                algorithm: format!("{alg:?}"),
            }),
        },
    }
}

/// Sanitize a `jsonwebtoken` error kind into a user-friendly message.
fn sanitize_jwt_error(kind: &jsonwebtoken::errors::ErrorKind) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{EncodingKey, Header, encode};
    use serde_json::json;

    /// Helper to create an HMAC-signed test token.
    fn create_hmac_token(alg: Algorithm, secret: &[u8], claims: &Value) -> String {
        let header = Header::new(alg);
        let key = EncodingKey::from_secret(secret);
        encode(&header, claims, &key).unwrap()
    }

    fn test_claims() -> Value {
        json!({"sub": "1234567890", "name": "Test User", "iat": 1516239022})
    }

    // --- Algorithm mapping ---

    #[test]
    fn test_map_algorithm_all_hmac() {
        assert_eq!(map_algorithm("HS256").unwrap(), Algorithm::HS256);
        assert_eq!(map_algorithm("HS384").unwrap(), Algorithm::HS384);
        assert_eq!(map_algorithm("HS512").unwrap(), Algorithm::HS512);
    }

    #[test]
    fn test_map_algorithm_all_rsa() {
        assert_eq!(map_algorithm("RS256").unwrap(), Algorithm::RS256);
        assert_eq!(map_algorithm("RS384").unwrap(), Algorithm::RS384);
        assert_eq!(map_algorithm("RS512").unwrap(), Algorithm::RS512);
        assert_eq!(map_algorithm("PS256").unwrap(), Algorithm::PS256);
        assert_eq!(map_algorithm("PS384").unwrap(), Algorithm::PS384);
        assert_eq!(map_algorithm("PS512").unwrap(), Algorithm::PS512);
    }

    #[test]
    fn test_map_algorithm_ec_and_eddsa() {
        assert_eq!(map_algorithm("ES256").unwrap(), Algorithm::ES256);
        assert_eq!(map_algorithm("ES384").unwrap(), Algorithm::ES384);
        assert_eq!(map_algorithm("EdDSA").unwrap(), Algorithm::EdDSA);
    }

    #[test]
    fn test_map_algorithm_unknown() {
        let err = map_algorithm("UNKNOWN").unwrap_err();
        assert!(matches!(
            err,
            JwtTermError::UnsupportedAlgorithm { algorithm } if algorithm == "UNKNOWN"
        ));
    }

    // --- Algorithm/key mismatch ---

    #[test]
    fn test_hmac_with_pem_key_mismatch() {
        let key = KeyMaterial::PemKey(vec![]);
        let err = validate_key_algorithm_match(Algorithm::HS256, &key).unwrap_err();
        assert!(
            matches!(err, JwtTermError::SignatureInvalid { reason } if reason.contains("shared secret"))
        );
    }

    #[test]
    fn test_rsa_with_secret_mismatch() {
        let key = KeyMaterial::Secret(Zeroizing::new(vec![]));
        let err = validate_key_algorithm_match(Algorithm::RS256, &key).unwrap_err();
        assert!(
            matches!(err, JwtTermError::SignatureInvalid { reason } if reason.contains("PEM key file"))
        );
    }

    #[test]
    fn test_hmac_with_secret_matches() {
        let key = KeyMaterial::Secret(Zeroizing::new(vec![1, 2, 3]));
        assert!(validate_key_algorithm_match(Algorithm::HS256, &key).is_ok());
    }

    #[test]
    fn test_rsa_with_pem_matches() {
        let key = KeyMaterial::PemKey(vec![1, 2, 3]);
        assert!(validate_key_algorithm_match(Algorithm::RS256, &key).is_ok());
    }

    // --- Signature validation (HMAC) ---

    #[test]
    fn test_validate_hs256_valid_signature() {
        let secret = b"test-secret-key";
        let token = create_hmac_token(Algorithm::HS256, secret, &test_claims());
        let key = KeyMaterial::Secret(Zeroizing::new(secret.to_vec()));

        let result = validate_signature(&token, "HS256", &key).unwrap();
        assert_eq!(result, ValidationOutcome::Valid);
    }

    #[test]
    fn test_validate_hs256_wrong_secret() {
        let token = create_hmac_token(Algorithm::HS256, b"correct-secret", &test_claims());
        let key = KeyMaterial::Secret(Zeroizing::new(b"wrong-secret".to_vec()));

        let result = validate_signature(&token, "HS256", &key).unwrap();
        assert!(matches!(result, ValidationOutcome::Invalid { .. }));
    }

    #[test]
    fn test_validate_hs384_valid_signature() {
        let secret = b"test-secret-key";
        let token = create_hmac_token(Algorithm::HS384, secret, &test_claims());
        let key = KeyMaterial::Secret(Zeroizing::new(secret.to_vec()));

        let result = validate_signature(&token, "HS384", &key).unwrap();
        assert_eq!(result, ValidationOutcome::Valid);
    }

    #[test]
    fn test_validate_hs512_valid_signature() {
        let secret = b"test-secret-key";
        let token = create_hmac_token(Algorithm::HS512, secret, &test_claims());
        let key = KeyMaterial::Secret(Zeroizing::new(secret.to_vec()));

        let result = validate_signature(&token, "HS512", &key).unwrap();
        assert_eq!(result, ValidationOutcome::Valid);
    }

    // --- Algorithm "none" rejection ---

    #[test]
    fn test_validate_rejects_alg_none() {
        let key = KeyMaterial::Secret(Zeroizing::new(b"secret".to_vec()));
        let err = validate_signature("header.payload.sig", "none", &key).unwrap_err();
        assert!(matches!(
            err,
            JwtTermError::UnsupportedAlgorithm { algorithm } if algorithm == "none"
        ));
    }

    #[test]
    fn test_validate_rejects_alg_none_case_insensitive() {
        let key = KeyMaterial::Secret(Zeroizing::new(b"secret".to_vec()));
        let err = validate_signature("header.payload.sig", "None", &key).unwrap_err();
        assert!(matches!(err, JwtTermError::UnsupportedAlgorithm { .. }));
    }

    // --- RSA validation ---

    #[test]
    fn test_validate_rs256_valid_signature() {
        let private_key = include_str!("../../tests/fixtures/rsa_private.pem");
        let public_key = include_str!("../../tests/fixtures/rsa_public.pem");

        let header = Header::new(Algorithm::RS256);
        let encoding_key = EncodingKey::from_rsa_pem(private_key.as_bytes()).unwrap();
        let token = encode(&header, &test_claims(), &encoding_key).unwrap();

        let key = KeyMaterial::PemKey(public_key.as_bytes().to_vec());
        let result = validate_signature(&token, "RS256", &key).unwrap();
        assert_eq!(result, ValidationOutcome::Valid);
    }

    #[test]
    fn test_validate_rs256_wrong_key() {
        let private_key = include_str!("../../tests/fixtures/rsa_private.pem");

        let header = Header::new(Algorithm::RS256);
        let encoding_key = EncodingKey::from_rsa_pem(private_key.as_bytes()).unwrap();
        let token = encode(&header, &test_claims(), &encoding_key).unwrap();

        // Use EC public key instead of RSA — should fail to parse
        let wrong_key = include_str!("../../tests/fixtures/ec_public.pem");
        let key = KeyMaterial::PemKey(wrong_key.as_bytes().to_vec());
        let result = validate_signature(&token, "RS256", &key);
        assert!(result.is_err());
    }

    // --- EC validation ---

    #[test]
    fn test_validate_es256_valid_signature() {
        let private_key = include_str!("../../tests/fixtures/ec_private.pem");
        let public_key = include_str!("../../tests/fixtures/ec_public.pem");

        let header = Header::new(Algorithm::ES256);
        let encoding_key = EncodingKey::from_ec_pem(private_key.as_bytes()).unwrap();
        let token = encode(&header, &test_claims(), &encoding_key).unwrap();

        let key = KeyMaterial::PemKey(public_key.as_bytes().to_vec());
        let result = validate_signature(&token, "ES256", &key).unwrap();
        assert_eq!(result, ValidationOutcome::Valid);
    }

    #[test]
    fn test_validate_es256_wrong_key() {
        let private_key = include_str!("../../tests/fixtures/ec_private.pem");

        let header = Header::new(Algorithm::ES256);
        let encoding_key = EncodingKey::from_ec_pem(private_key.as_bytes()).unwrap();
        let token = encode(&header, &test_claims(), &encoding_key).unwrap();

        // Use a different secret — signature mismatch
        let rsa_pub = include_str!("../../tests/fixtures/rsa_public.pem");
        let key = KeyMaterial::PemKey(rsa_pub.as_bytes().to_vec());
        let result = validate_signature(&token, "ES256", &key);
        assert!(result.is_err());
    }

    // --- Unsupported algorithm ---

    #[test]
    fn test_validate_unsupported_algorithm() {
        let key = KeyMaterial::Secret(Zeroizing::new(b"secret".to_vec()));
        let err = validate_signature("a.b.c", "XX999", &key).unwrap_err();
        assert!(matches!(err, JwtTermError::UnsupportedAlgorithm { .. }));
    }

    // --- Invalid PEM ---

    #[test]
    fn test_validate_rsa_invalid_pem() {
        let key = KeyMaterial::PemKey(b"not-a-valid-pem".to_vec());
        let result = create_decoding_key(Algorithm::RS256, &key);
        assert!(matches!(
            result,
            Err(JwtTermError::SignatureInvalid { reason }) if reason.contains("RSA PEM")
        ));
    }

    #[test]
    fn test_validate_ec_invalid_pem() {
        let key = KeyMaterial::PemKey(b"not-a-valid-pem".to_vec());
        let result = create_decoding_key(Algorithm::ES256, &key);
        assert!(matches!(
            result,
            Err(JwtTermError::SignatureInvalid { reason }) if reason.contains("EC PEM")
        ));
    }
}
