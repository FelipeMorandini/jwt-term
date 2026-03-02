//! JWKS (JSON Web Key Set) fetching and key matching.
//!
//! Handles fetching a JWKS from a remote OIDC endpoint, parsing the
//! response, and finding the correct key by `kid` (Key ID) to validate
//! a JWT's signature.

use std::collections::HashSet;
use std::io::Read;
use std::time::Duration;

use jsonwebtoken::jwk::{Jwk, JwkSet, KeyAlgorithm};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde_json::Value;

use crate::core::validator::ValidationOutcome;
use crate::error::JwtTermError;

/// Import the shared error sanitizer for use in this module.
use super::sanitize_jwt_error;

/// Maximum JWKS response body size in bytes (1 MB).
const JWKS_MAX_RESPONSE_SIZE: u64 = 1_048_576;

/// HTTP request timeout for JWKS endpoints in seconds.
const JWKS_TIMEOUT_SECS: u64 = 10;

/// Fetch a JWKS from the given URL and validate a token against it.
///
/// Performs an HTTPS GET request to the JWKS endpoint, finds the key
/// matching the token's `kid` header claim, and validates the signature.
/// Returns a [`ValidationOutcome`] consistent with local validation.
///
/// # Security
///
/// - Only HTTPS URLs are accepted (HTTP is rejected before any network call).
/// - Redirects are disabled to prevent HTTPS → HTTP downgrade.
/// - Request timeout is enforced (10 seconds).
/// - Response size is limited (1 MB).
/// - Error messages are sanitized to avoid leaking internal details.
///
/// # Errors
///
/// Returns an error if the URL is not HTTPS, the request fails, no
/// matching key is found, or signature validation fails.
pub fn validate_with_jwks(token: &str, jwks_url: &str) -> Result<ValidationOutcome, JwtTermError> {
    let display_url = validate_url_scheme(jwks_url)?;
    let jwks = fetch_jwks(jwks_url, &display_url)?;

    if jwks.keys.is_empty() {
        return Err(JwtTermError::JwksFetchError {
            url: display_url,
            reason: "JWKS contains no keys".to_string(),
        });
    }

    let header = extract_header(token)?;
    let jwk = find_matching_key(&jwks, header.kid.as_deref())?;
    let algorithm = resolve_algorithm(jwk, &header)?;
    validate_token_with_jwk(token, jwk, algorithm)
}

/// Reject non-HTTPS URLs before any network call.
///
/// Parses the URL properly to handle case-insensitive schemes and
/// catch malformed URLs, rather than relying on string prefix matching.
fn validate_url_scheme(url: &str) -> Result<String, JwtTermError> {
    match reqwest::Url::parse(url) {
        Ok(parsed) if parsed.scheme() == "https" => Ok(sanitize_url_for_display(&parsed)),
        Ok(parsed) => Err(JwtTermError::JwksFetchError {
            url: sanitize_url_for_display(&parsed),
            reason: format!(
                "only HTTPS URLs are accepted for JWKS endpoints (got scheme '{}')",
                parsed.scheme()
            ),
        }),
        Err(_) => Err(JwtTermError::JwksFetchError {
            url: url.to_string(),
            reason: "invalid URL for JWKS endpoint".to_string(),
        }),
    }
}

/// Fetch and parse a JWKS from a remote HTTPS endpoint.
///
/// Builds a `reqwest::blocking::Client` with an explicit timeout and
/// disabled redirects (to prevent HTTPS → HTTP downgrade), reads the
/// response body with a size limit, and parses it as a [`JwkSet`].
fn fetch_jwks(url: &str, display_url: &str) -> Result<JwkSet, JwtTermError> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(JWKS_TIMEOUT_SECS))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| JwtTermError::JwksFetchError {
            url: display_url.to_string(),
            reason: sanitize_reqwest_error(&e),
        })?;

    let response = client
        .get(url)
        .send()
        .map_err(|e| JwtTermError::JwksFetchError {
            url: display_url.to_string(),
            reason: sanitize_reqwest_error(&e),
        })?;

    if !response.status().is_success() {
        return Err(JwtTermError::JwksFetchError {
            url: display_url.to_string(),
            reason: format!("server returned HTTP {}", response.status().as_u16()),
        });
    }

    let body = read_bounded_response(response, display_url)?;

    serde_json::from_slice::<JwkSet>(&body).map_err(|_| JwtTermError::JwksFetchError {
        url: display_url.to_string(),
        reason: "response is not a valid JWKS document".to_string(),
    })
}

/// Read a response body with a size limit to prevent resource exhaustion.
///
/// Uses `std::io::Read::take` to bound the read to
/// [`JWKS_MAX_RESPONSE_SIZE`] + 1 bytes. If the read exceeds the
/// limit, returns a size error.
fn read_bounded_response(
    response: reqwest::blocking::Response,
    display_url: &str,
) -> Result<Vec<u8>, JwtTermError> {
    let mut bytes = Vec::new();
    response
        .take(JWKS_MAX_RESPONSE_SIZE + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| JwtTermError::JwksFetchError {
            url: display_url.to_string(),
            reason: "failed to read response body".to_string(),
        })?;

    if bytes.len() as u64 > JWKS_MAX_RESPONSE_SIZE {
        return Err(JwtTermError::JwksFetchError {
            url: display_url.to_string(),
            reason: format!(
                "response exceeds maximum size of {} bytes",
                JWKS_MAX_RESPONSE_SIZE
            ),
        });
    }

    Ok(bytes)
}

/// Decode only the JWT header to extract `kid` and `alg`.
fn extract_header(token: &str) -> Result<jsonwebtoken::Header, JwtTermError> {
    jsonwebtoken::decode_header(token).map_err(|_| JwtTermError::InvalidTokenFormat)
}

/// Find the matching key in the JWKS for the given `kid`.
///
/// If the token has a `kid`, finds the key with a matching `kid` in the
/// JWKS. If the token has no `kid`, uses the sole key when the JWKS
/// contains exactly one key, or returns an error when there are multiple.
///
/// Assumes the JWKS is non-empty — the caller must check for empty key
/// sets before invoking this function.
fn find_matching_key<'a>(jwks: &'a JwkSet, kid: Option<&str>) -> Result<&'a Jwk, JwtTermError> {
    match kid {
        Some(kid) => jwks.find(kid).ok_or_else(|| JwtTermError::JwksKeyNotFound {
            kid: sanitize_kid(kid),
        }),
        None if jwks.keys.len() == 1 => Ok(&jwks.keys[0]),
        None => Err(JwtTermError::JwksMissingKid),
    }
}

/// Sanitize a `kid` value for safe inclusion in error messages.
///
/// Replaces control characters (including ANSI escape sequences) with
/// the Unicode replacement character to prevent terminal injection,
/// then truncates to 128 bytes to limit error message length.
/// Uses `floor_char_boundary` to avoid panicking on multi-byte UTF-8.
fn sanitize_kid(kid: &str) -> String {
    let clean: String = kid
        .chars()
        .map(|c| if c.is_control() { '\u{FFFD}' } else { c })
        .collect();
    if clean.len() > 128 {
        let end = clean.floor_char_boundary(128);
        format!("{}...(truncated)", &clean[..end])
    } else {
        clean
    }
}

/// Determine which algorithm to use for validation.
///
/// Prefers the JWK's `alg` field when present (the server's declared
/// algorithm is authoritative). Falls back to the JWT header's `alg`
/// if the JWK does not specify one.
fn resolve_algorithm(jwk: &Jwk, header: &jsonwebtoken::Header) -> Result<Algorithm, JwtTermError> {
    match jwk.common.key_algorithm {
        Some(ka) => key_algorithm_to_algorithm(ka),
        None => Ok(header.alg),
    }
}

/// Convert a [`KeyAlgorithm`] to a [`jsonwebtoken::Algorithm`].
///
/// Rejects encryption-only algorithms (RSA1_5, RSA-OAEP, RSA-OAEP-256)
/// that are not valid for JWT signature verification.
fn key_algorithm_to_algorithm(ka: KeyAlgorithm) -> Result<Algorithm, JwtTermError> {
    match ka {
        KeyAlgorithm::HS256 => Ok(Algorithm::HS256),
        KeyAlgorithm::HS384 => Ok(Algorithm::HS384),
        KeyAlgorithm::HS512 => Ok(Algorithm::HS512),
        KeyAlgorithm::RS256 => Ok(Algorithm::RS256),
        KeyAlgorithm::RS384 => Ok(Algorithm::RS384),
        KeyAlgorithm::RS512 => Ok(Algorithm::RS512),
        KeyAlgorithm::PS256 => Ok(Algorithm::PS256),
        KeyAlgorithm::PS384 => Ok(Algorithm::PS384),
        KeyAlgorithm::PS512 => Ok(Algorithm::PS512),
        KeyAlgorithm::ES256 => Ok(Algorithm::ES256),
        KeyAlgorithm::ES384 => Ok(Algorithm::ES384),
        KeyAlgorithm::EdDSA => Ok(Algorithm::EdDSA),
        _ => Err(JwtTermError::UnsupportedAlgorithm {
            algorithm: format!("{ka:?}"),
        }),
    }
}

/// Validate a token's signature using a JWK and resolved algorithm.
///
/// Constructs a [`DecodingKey`] from the JWK and validates the token.
/// Temporal claims (`exp`, `nbf`) are not checked — this is a
/// debugging tool focused on signature correctness.
///
/// # Safety assumption — `alg:none`
///
/// This function receives a `jsonwebtoken::Algorithm` enum value which
/// has no `None` variant. The `alg:none` attack cannot reach here
/// because `resolve_algorithm` either maps from `KeyAlgorithm` (which
/// also has no `None` variant) or uses `header.alg` (which is decoded
/// by `jsonwebtoken::decode_header` into the `Algorithm` enum). If a
/// future library update introduces an `Algorithm::None` variant, add
/// an explicit rejection guard here.
fn validate_token_with_jwk(
    token: &str,
    jwk: &Jwk,
    algorithm: Algorithm,
) -> Result<ValidationOutcome, JwtTermError> {
    let decoding_key = DecodingKey::from_jwk(jwk).map_err(|_| JwtTermError::JwksInvalidKey {
        reason: "failed to construct decoding key from JWK".to_string(),
    })?;

    let mut validation = Validation::new(algorithm);
    validation.validate_exp = false;
    validation.validate_nbf = false;
    validation.required_spec_claims = HashSet::new();

    match decode::<Value>(token, &decoding_key, &validation) {
        Ok(_) => Ok(ValidationOutcome::Valid),
        Err(e) => match e.kind() {
            jsonwebtoken::errors::ErrorKind::InvalidSignature => Ok(ValidationOutcome::Invalid {
                reason: "signature does not match the JWKS key".to_string(),
            }),
            jsonwebtoken::errors::ErrorKind::InvalidAlgorithm => Ok(ValidationOutcome::Invalid {
                reason: "algorithm mismatch between token and JWKS key".to_string(),
            }),
            _ => Err(JwtTermError::SignatureInvalid {
                reason: sanitize_jwt_error(e.kind()),
            }),
        },
    }
}

/// Sanitize a `reqwest` error into a user-friendly reason string.
///
/// Maps common error types to generic messages rather than forwarding
/// raw error strings that may leak internal system details.
fn sanitize_reqwest_error(err: &reqwest::Error) -> String {
    if err.is_timeout() {
        "connection timed out".to_string()
    } else if err.is_connect() {
        "failed to connect to server".to_string()
    } else if err.is_redirect() {
        "too many redirects".to_string()
    } else {
        "request failed".to_string()
    }
}

/// Sanitize a URL for safe display in error messages.
///
/// Strips credentials (userinfo), query parameters, and fragment
/// components to prevent accidental leakage of secrets, API keys,
/// or tokens that may be embedded in the URL. Only scheme, host,
/// port, and path are preserved.
fn sanitize_url_for_display(url: &reqwest::Url) -> String {
    let mut sanitized = url.clone();
    let _ = sanitized.set_username("");
    let _ = sanitized.set_password(None);
    sanitized.set_query(None);
    sanitized.set_fragment(None);
    sanitized.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use jsonwebtoken::{EncodingKey, Header, encode};

    fn test_claims() -> Value {
        serde_json::json!({"sub": "1234567890", "name": "Test User", "iat": 1516239022})
    }

    /// Create an HS256-signed token with the given secret and optional kid.
    fn create_hmac_token_with_kid(secret: &[u8], kid: Option<&str>) -> String {
        let mut header = Header::new(Algorithm::HS256);
        header.kid = kid.map(|s| s.to_string());
        let key = EncodingKey::from_secret(secret);
        encode(&header, &test_claims(), &key).unwrap()
    }

    /// Build a JWKS JSON string containing one HMAC key.
    fn hmac_jwks_json(kid: &str, secret: &[u8], alg: &str) -> String {
        let k = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(secret);
        format!(r#"{{"keys":[{{"kty":"oct","kid":"{kid}","alg":"{alg}","k":"{k}"}}]}}"#,)
    }

    /// Parse a JWKS JSON string into a JwkSet.
    fn parse_jwks(json: &str) -> JwkSet {
        serde_json::from_str(json).unwrap()
    }

    // --- URL scheme validation ---

    #[test]
    fn test_validate_url_scheme_accepts_https() {
        assert!(validate_url_scheme("https://example.com/.well-known/jwks.json").is_ok());
    }

    #[test]
    fn test_validate_url_scheme_rejects_http() {
        let err = validate_url_scheme("http://example.com/.well-known/jwks.json").unwrap_err();
        assert!(matches!(
            err,
            JwtTermError::JwksFetchError { reason, .. } if reason.contains("HTTPS") && reason.contains("http")
        ));
    }

    #[test]
    fn test_validate_url_scheme_rejects_empty() {
        let err = validate_url_scheme("").unwrap_err();
        assert!(matches!(
            err,
            JwtTermError::JwksFetchError { reason, .. } if reason.contains("invalid URL")
        ));
    }

    #[test]
    fn test_validate_url_scheme_rejects_ftp() {
        let err = validate_url_scheme("ftp://example.com/jwks").unwrap_err();
        assert!(matches!(
            err,
            JwtTermError::JwksFetchError { reason, .. } if reason.contains("ftp")
        ));
    }

    #[test]
    fn test_validate_url_scheme_rejects_no_scheme() {
        let err = validate_url_scheme("example.com/.well-known/jwks.json").unwrap_err();
        assert!(matches!(
            err,
            JwtTermError::JwksFetchError { reason, .. } if reason.contains("invalid URL")
        ));
    }

    #[test]
    fn test_validate_url_scheme_accepts_https_case_insensitive() {
        // url::Url normalizes schemes to lowercase, so HTTPS:// is accepted
        assert!(validate_url_scheme("HTTPS://example.com/.well-known/jwks.json").is_ok());
    }

    // --- URL sanitization for display ---

    #[test]
    fn test_sanitize_url_for_display_no_sensitive_parts() {
        let url = reqwest::Url::parse("https://example.com/jwks").unwrap();
        assert_eq!(sanitize_url_for_display(&url), "https://example.com/jwks");
    }

    #[test]
    fn test_sanitize_url_for_display_strips_password() {
        let url = reqwest::Url::parse("https://user:s3cret@example.com/jwks").unwrap();
        let result = sanitize_url_for_display(&url);
        assert!(!result.contains("s3cret"));
        assert!(!result.contains("user"));
        assert!(result.contains("example.com/jwks"));
    }

    #[test]
    fn test_sanitize_url_for_display_strips_username_only() {
        let url = reqwest::Url::parse("https://admin@example.com/jwks").unwrap();
        let result = sanitize_url_for_display(&url);
        assert!(!result.contains("admin"));
        assert!(result.contains("example.com/jwks"));
    }

    #[test]
    fn test_sanitize_url_for_display_strips_query_params() {
        let url = reqwest::Url::parse("https://example.com/jwks?api_key=secret123&v=2").unwrap();
        let result = sanitize_url_for_display(&url);
        assert!(!result.contains("api_key"));
        assert!(!result.contains("secret123"));
        assert!(!result.contains('?'));
        assert_eq!(result, "https://example.com/jwks");
    }

    #[test]
    fn test_sanitize_url_for_display_strips_fragment() {
        let url = reqwest::Url::parse("https://example.com/jwks#section").unwrap();
        let result = sanitize_url_for_display(&url);
        assert!(!result.contains("section"));
        assert!(!result.contains('#'));
        assert_eq!(result, "https://example.com/jwks");
    }

    #[test]
    fn test_sanitize_url_for_display_strips_all_sensitive_parts() {
        let url =
            reqwest::Url::parse("https://user:pass@example.com/jwks?token=abc123#frag").unwrap();
        let result = sanitize_url_for_display(&url);
        assert!(!result.contains("user"));
        assert!(!result.contains("pass"));
        assert!(!result.contains("token"));
        assert!(!result.contains("abc123"));
        assert!(!result.contains("frag"));
        assert_eq!(result, "https://example.com/jwks");
    }

    #[test]
    fn test_validate_url_scheme_sanitizes_on_success() {
        let result = validate_url_scheme("https://user:pass@example.com/jwks?key=val").unwrap();
        assert!(!result.contains("user"));
        assert!(!result.contains("pass"));
        assert!(!result.contains("key=val"));
        assert!(result.contains("example.com/jwks"));
    }

    #[test]
    fn test_validate_url_scheme_sanitizes_on_http_error() {
        let err = validate_url_scheme("http://user:pass@example.com/jwks?key=val").unwrap_err();
        match err {
            JwtTermError::JwksFetchError { url, .. } => {
                assert!(!url.contains("user"));
                assert!(!url.contains("pass"));
                assert!(!url.contains("key=val"));
                assert!(url.contains("example.com/jwks"));
            }
            _ => panic!("expected JwksFetchError"),
        }
    }

    // --- Header extraction ---

    #[test]
    fn test_extract_header_with_kid() {
        let token = create_hmac_token_with_kid(b"secret", Some("my-key-id"));
        let header = extract_header(&token).unwrap();
        assert_eq!(header.kid.as_deref(), Some("my-key-id"));
        assert_eq!(header.alg, Algorithm::HS256);
    }

    #[test]
    fn test_extract_header_without_kid() {
        let token = create_hmac_token_with_kid(b"secret", None);
        let header = extract_header(&token).unwrap();
        assert!(header.kid.is_none());
    }

    #[test]
    fn test_extract_header_invalid_token() {
        let err = extract_header("not-a-valid-token").unwrap_err();
        assert!(matches!(err, JwtTermError::InvalidTokenFormat));
    }

    // --- Key matching ---

    #[test]
    fn test_find_matching_key_by_kid() {
        let jwks_json = hmac_jwks_json("key-1", b"secret", "HS256");
        let jwks = parse_jwks(&jwks_json);
        let key = find_matching_key(&jwks, Some("key-1")).unwrap();
        assert_eq!(key.common.key_id.as_deref(), Some("key-1"));
    }

    #[test]
    fn test_find_matching_key_no_match() {
        let jwks_json = hmac_jwks_json("key-1", b"secret", "HS256");
        let jwks = parse_jwks(&jwks_json);
        let err = find_matching_key(&jwks, Some("nonexistent")).unwrap_err();
        assert!(matches!(
            err,
            JwtTermError::JwksKeyNotFound { kid } if kid == "nonexistent"
        ));
    }

    #[test]
    fn test_find_matching_key_no_kid_single_key() {
        let jwks_json = hmac_jwks_json("key-1", b"secret", "HS256");
        let jwks = parse_jwks(&jwks_json);
        let key = find_matching_key(&jwks, None).unwrap();
        assert_eq!(key.common.key_id.as_deref(), Some("key-1"));
    }

    #[test]
    fn test_find_matching_key_no_kid_multiple_keys() {
        let json = r#"{"keys":[
            {"kty":"oct","kid":"k1","alg":"HS256","k":"c2VjcmV0"},
            {"kty":"oct","kid":"k2","alg":"HS256","k":"c2VjcmV0"}
        ]}"#;
        let jwks = parse_jwks(json);
        let err = find_matching_key(&jwks, None).unwrap_err();
        assert!(matches!(err, JwtTermError::JwksMissingKid));
    }

    // --- kid sanitization ---

    #[test]
    fn test_sanitize_kid_short() {
        assert_eq!(sanitize_kid("my-key-id"), "my-key-id");
    }

    #[test]
    fn test_sanitize_kid_long() {
        let long_kid = "a".repeat(200);
        let result = sanitize_kid(&long_kid);
        assert!(result.len() < 200);
        assert!(result.ends_with("...(truncated)"));
    }

    #[test]
    fn test_sanitize_kid_multibyte_utf8() {
        // Each emoji is 4 bytes; 33 emojis = 132 bytes, exceeds 128
        let emoji_kid = "\u{1F600}".repeat(33);
        assert_eq!(emoji_kid.len(), 132);
        let result = sanitize_kid(&emoji_kid);
        // Must not panic and must end with truncation marker
        assert!(result.ends_with("...(truncated)"));
        // The truncated portion must be valid UTF-8 (this assertion is
        // implicit — if it weren't, the String would not have been created)
    }

    #[test]
    fn test_sanitize_kid_replaces_ansi_escapes() {
        let kid_with_escapes = "key\x1b[31mRED\x1b[0m-id";
        let result = sanitize_kid(kid_with_escapes);
        assert!(!result.contains('\x1b'));
        assert!(result.contains('\u{FFFD}'));
        assert!(result.contains("RED"));
        assert!(result.contains("-id"));
    }

    #[test]
    fn test_sanitize_kid_replaces_null_bytes() {
        let kid_with_null = "key\0id";
        let result = sanitize_kid(kid_with_null);
        assert!(!result.contains('\0'));
        assert!(result.contains('\u{FFFD}'));
    }

    // --- Algorithm resolution ---

    #[test]
    fn test_resolve_algorithm_from_jwk() {
        let jwks_json = hmac_jwks_json("k1", b"secret", "HS256");
        let jwks = parse_jwks(&jwks_json);
        let jwk = &jwks.keys[0];

        let mut header = Header::new(Algorithm::HS384);
        header.kid = Some("k1".to_string());

        let alg = resolve_algorithm(jwk, &header).unwrap();
        // JWK's alg (HS256) takes priority over header's alg (HS384)
        assert_eq!(alg, Algorithm::HS256);
    }

    #[test]
    fn test_resolve_algorithm_from_header_when_jwk_has_no_alg() {
        // Build JWK without alg field
        let json = r#"{"keys":[{"kty":"oct","kid":"k1","k":"c2VjcmV0"}]}"#;
        let jwks = parse_jwks(json);
        let jwk = &jwks.keys[0];

        let header = Header::new(Algorithm::HS384);
        let alg = resolve_algorithm(jwk, &header).unwrap();
        assert_eq!(alg, Algorithm::HS384);
    }

    // --- KeyAlgorithm conversion ---

    #[test]
    fn test_key_algorithm_to_algorithm_all_signing() {
        let cases = [
            (KeyAlgorithm::HS256, Algorithm::HS256),
            (KeyAlgorithm::HS384, Algorithm::HS384),
            (KeyAlgorithm::HS512, Algorithm::HS512),
            (KeyAlgorithm::RS256, Algorithm::RS256),
            (KeyAlgorithm::RS384, Algorithm::RS384),
            (KeyAlgorithm::RS512, Algorithm::RS512),
            (KeyAlgorithm::PS256, Algorithm::PS256),
            (KeyAlgorithm::PS384, Algorithm::PS384),
            (KeyAlgorithm::PS512, Algorithm::PS512),
            (KeyAlgorithm::ES256, Algorithm::ES256),
            (KeyAlgorithm::ES384, Algorithm::ES384),
            (KeyAlgorithm::EdDSA, Algorithm::EdDSA),
        ];

        for (ka, expected) in cases {
            assert_eq!(key_algorithm_to_algorithm(ka).unwrap(), expected);
        }
    }

    #[test]
    fn test_key_algorithm_rejects_encryption_algorithms() {
        for ka in [
            KeyAlgorithm::RSA1_5,
            KeyAlgorithm::RSA_OAEP,
            KeyAlgorithm::RSA_OAEP_256,
        ] {
            let err = key_algorithm_to_algorithm(ka).unwrap_err();
            assert!(matches!(err, JwtTermError::UnsupportedAlgorithm { .. }));
        }
    }

    // --- Token validation with JWK ---

    #[test]
    fn test_validate_token_with_jwk_hmac_valid() {
        let secret = b"my-test-secret-key";
        let token = create_hmac_token_with_kid(secret, Some("k1"));
        let jwks_json = hmac_jwks_json("k1", secret, "HS256");
        let jwks = parse_jwks(&jwks_json);
        let jwk = &jwks.keys[0];

        let result = validate_token_with_jwk(&token, jwk, Algorithm::HS256).unwrap();
        assert_eq!(result, ValidationOutcome::Valid);
    }

    #[test]
    fn test_validate_token_with_jwk_hmac_wrong_key() {
        let token = create_hmac_token_with_kid(b"correct-secret", Some("k1"));
        let jwks_json = hmac_jwks_json("k1", b"wrong-secret", "HS256");
        let jwks = parse_jwks(&jwks_json);
        let jwk = &jwks.keys[0];

        let result = validate_token_with_jwk(&token, jwk, Algorithm::HS256).unwrap();
        assert!(matches!(result, ValidationOutcome::Invalid { .. }));
    }

    #[test]
    fn test_validate_token_with_jwk_algorithm_mismatch() {
        let secret = b"my-secret";
        let token = create_hmac_token_with_kid(secret, Some("k1"));
        let jwks_json = hmac_jwks_json("k1", secret, "HS256");
        let jwks = parse_jwks(&jwks_json);
        let jwk = &jwks.keys[0];

        // Token is HS256 but we tell validator to expect HS384
        let result = validate_token_with_jwk(&token, jwk, Algorithm::HS384).unwrap();
        assert!(
            matches!(result, ValidationOutcome::Invalid { reason } if reason.contains("algorithm mismatch"))
        );
    }

    #[test]
    fn test_rsa_token_key_compatibility() {
        let private_key = include_str!("../../tests/fixtures/rsa_private.pem");
        let public_key = include_str!("../../tests/fixtures/rsa_public.pem");

        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("rsa-key-1".to_string());
        let encoding_key = EncodingKey::from_rsa_pem(private_key.as_bytes()).unwrap();
        let token = encode(&header, &test_claims(), &encoding_key).unwrap();

        // Verify RSA token/key compatibility via DecodingKey::from_rsa_pem.
        // Building a proper RSA JWK from raw n/e components is complex and
        // not the responsibility of this module; this test confirms that
        // the token and key fixtures are compatible for RSA validation.
        let decoding_key = DecodingKey::from_rsa_pem(public_key.as_bytes()).unwrap();
        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_exp = false;
        validation.validate_nbf = false;
        validation.required_spec_claims = HashSet::new();
        let result = decode::<Value>(&token, &decoding_key, &validation);
        assert!(result.is_ok(), "RSA validation should succeed");
    }

    // --- Error sanitization ---

    #[test]
    fn test_sanitize_jwt_error_invalid_token() {
        let msg = sanitize_jwt_error(&jsonwebtoken::errors::ErrorKind::InvalidToken);
        assert_eq!(msg, "invalid token structure");
    }

    #[test]
    fn test_sanitize_jwt_error_unknown() {
        let msg = sanitize_jwt_error(&jsonwebtoken::errors::ErrorKind::InvalidIssuer);
        assert_eq!(msg, "unexpected validation error");
    }

    // --- Network behavior (wiremock) ---
    //
    // These tests use wiremock to verify security-relevant HTTP handling:
    // response size limits, redirect rejection, and error status codes.
    // They call `fetch_jwks` directly (bypassing the HTTPS scheme check)
    // since wiremock only serves HTTP. The scheme check is tested
    // separately above.
    //
    // `std::thread::spawn` is used instead of `tokio::task::spawn_blocking`
    // because `reqwest::blocking` panics inside a tokio async context.

    #[tokio::test]
    async fn test_fetch_jwks_rejects_oversized_response() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        // Respond with a body just over the 1 MB limit
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![b'x'; 1_048_577]))
            .mount(&mock_server)
            .await;

        let url = format!("{}/jwks", mock_server.uri());
        let display_url = url.clone();

        let result = std::thread::spawn(move || fetch_jwks(&url, &display_url))
            .join()
            .unwrap();

        let err = result.unwrap_err();
        assert!(matches!(
            err,
            JwtTermError::JwksFetchError { reason, .. }
                if reason.contains("maximum size")
        ));
    }

    #[tokio::test]
    async fn test_fetch_jwks_rejects_redirect() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        // Return a 301 redirect — our client uses Policy::none()
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(
                ResponseTemplate::new(301).insert_header("Location", "http://evil.com/jwks"),
            )
            .mount(&mock_server)
            .await;

        let url = format!("{}/jwks", mock_server.uri());
        let display_url = url.clone();

        let result = std::thread::spawn(move || fetch_jwks(&url, &display_url))
            .join()
            .unwrap();

        let err = result.unwrap_err();
        assert!(matches!(
            err,
            JwtTermError::JwksFetchError { reason, .. }
                if reason.contains("HTTP 301")
        ));
    }

    #[tokio::test]
    async fn test_fetch_jwks_rejects_server_error() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock_server)
            .await;

        let url = format!("{}/jwks", mock_server.uri());
        let display_url = url.clone();

        let result = std::thread::spawn(move || fetch_jwks(&url, &display_url))
            .join()
            .unwrap();

        let err = result.unwrap_err();
        assert!(matches!(
            err,
            JwtTermError::JwksFetchError { reason, .. }
                if reason.contains("HTTP 500")
        ));
    }

    #[tokio::test]
    async fn test_fetch_jwks_rejects_invalid_json() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not valid json"))
            .mount(&mock_server)
            .await;

        let url = format!("{}/jwks", mock_server.uri());
        let display_url = url.clone();

        let result = std::thread::spawn(move || fetch_jwks(&url, &display_url))
            .join()
            .unwrap();

        let err = result.unwrap_err();
        assert!(matches!(
            err,
            JwtTermError::JwksFetchError { reason, .. }
                if reason.contains("not a valid JWKS")
        ));
    }

    #[tokio::test]
    async fn test_fetch_jwks_parses_valid_jwks() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        let body = hmac_jwks_json("k1", b"test-secret", "HS256");

        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&mock_server)
            .await;

        let url = format!("{}/jwks", mock_server.uri());
        let display_url = url.clone();

        let result = std::thread::spawn(move || fetch_jwks(&url, &display_url))
            .join()
            .unwrap();

        let jwks = result.unwrap();
        assert_eq!(jwks.keys.len(), 1);
        assert_eq!(jwks.keys[0].common.key_id.as_deref(), Some("k1"));
    }
}
