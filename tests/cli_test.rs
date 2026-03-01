//! Integration tests for the jwt-term CLI.
//!
//! Tests argument parsing, help text, version output, subcommand routing,
//! decode command behavior, verify command behavior, and error handling.

mod common;

use assert_cmd::cargo::cargo_bin_cmd;
use predicates::prelude::*;

fn cmd() -> assert_cmd::Command {
    cargo_bin_cmd!("jwt-term")
}

// --- Help and Version ---

#[test]
fn test_no_args_shows_usage_hint() {
    cmd()
        .assert()
        .failure()
        .stderr(predicate::str::contains("Usage:"));
}

#[test]
fn test_help_flag_shows_description() {
    cmd()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("blazing-fast"))
        .stdout(predicate::str::contains("JWT"));
}

#[test]
fn test_short_help_flag() {
    cmd()
        .arg("-h")
        .assert()
        .success()
        .stdout(predicate::str::contains("Usage:"));
}

#[test]
fn test_version_flag() {
    cmd()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("jwt-term"))
        .stdout(predicate::str::contains("0.1.0"));
}

#[test]
fn test_short_version_flag() {
    cmd()
        .arg("-V")
        .assert()
        .success()
        .stdout(predicate::str::contains("0.1.0"));
}

// --- Subcommand Help ---

#[test]
fn test_decode_help_shows_options() {
    cmd()
        .args(["decode", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--token-env"))
        .stdout(predicate::str::contains("--json"))
        .stdout(predicate::str::contains("[TOKEN]"));
}

#[test]
fn test_verify_help_shows_options() {
    cmd()
        .args(["verify", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--secret"))
        .stdout(predicate::str::contains("--key-file"))
        .stdout(predicate::str::contains("--jwks-url"))
        .stdout(predicate::str::contains("--time-travel"))
        .stdout(predicate::str::contains("--token-env"))
        .stdout(predicate::str::contains("--secret-env"));
}

#[test]
fn test_verify_help_includes_shell_history_warning() {
    cmd()
        .args(["verify", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("shell history"));
}

// --- Unknown Commands and Invalid Args ---

#[test]
fn test_unknown_subcommand_fails() {
    cmd().arg("unknown").assert().failure().stderr(
        predicate::str::contains("invalid value 'unknown'")
            .or(predicate::str::contains("unrecognized subcommand")),
    );
}

#[test]
fn test_unknown_flag_fails() {
    cmd()
        .args(["decode", "--nonexistent"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unexpected argument"));
}

// --- Decode: Successful Decoding ---

#[test]
fn test_decode_valid_token_shows_header() {
    cmd()
        .args(["decode", common::VALID_HS256_TOKEN])
        .assert()
        .success()
        .stdout(predicate::str::contains("Header"))
        .stdout(predicate::str::contains("HS256"))
        .stdout(predicate::str::contains("JWT"));
}

#[test]
fn test_decode_valid_token_shows_payload() {
    cmd()
        .args(["decode", common::VALID_HS256_TOKEN])
        .assert()
        .success()
        .stdout(predicate::str::contains("Payload"))
        .stdout(predicate::str::contains("1234567890"))
        .stdout(predicate::str::contains("Test User"));
}

#[test]
fn test_decode_valid_token_shows_token_status() {
    cmd()
        .args(["decode", common::VALID_HS256_TOKEN])
        .assert()
        .success()
        .stdout(predicate::str::contains("Token Status"))
        .stdout(predicate::str::contains("Issued at"));
}

#[test]
fn test_decode_json_mode_outputs_valid_json() {
    let output = cmd()
        .args(["decode", "--json", common::VALID_HS256_TOKEN])
        .output()
        .expect("failed to execute");

    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("invalid JSON output");
    assert!(parsed.get("header").is_some());
    assert!(parsed.get("payload").is_some());
    assert_eq!(parsed["header"]["alg"], "HS256");
    assert_eq!(parsed["payload"]["sub"], "1234567890");
}

#[test]
fn test_decode_json_mode_no_section_headers() {
    cmd()
        .args(["decode", "--json", common::VALID_HS256_TOKEN])
        .assert()
        .success()
        .stdout(predicate::str::contains("--- Header ---").not())
        .stdout(predicate::str::contains("--- Payload ---").not())
        .stdout(predicate::str::contains("Token Status").not());
}

// --- Decode: Token from Stdin ---

#[test]
fn test_decode_from_stdin() {
    cmd()
        .arg("decode")
        .write_stdin(common::VALID_HS256_TOKEN)
        .assert()
        .success()
        .stdout(predicate::str::contains("HS256"))
        .stdout(predicate::str::contains("Test User"));
}

#[test]
fn test_decode_from_stdin_with_trailing_newline() {
    let token_with_newline = format!("{}\n", common::VALID_HS256_TOKEN);
    cmd()
        .arg("decode")
        .write_stdin(token_with_newline)
        .assert()
        .success()
        .stdout(predicate::str::contains("HS256"));
}

// --- Decode: Token from Environment Variable ---

#[test]
fn test_decode_from_env_var() {
    cmd()
        .args(["decode", "--token-env", "TEST_JWT_DECODE"])
        .env("TEST_JWT_DECODE", common::VALID_HS256_TOKEN)
        .assert()
        .success()
        .stdout(predicate::str::contains("HS256"))
        .stdout(predicate::str::contains("Test User"));
}

#[test]
fn test_decode_env_var_not_set_shows_error() {
    cmd()
        .args(["decode", "--token-env", "NONEXISTENT_JWT_VAR"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("NONEXISTENT_JWT_VAR"));
}

// --- Decode: Error Cases ---

#[test]
fn test_decode_no_token_shows_error() {
    cmd()
        .arg("decode")
        .assert()
        .failure()
        .stderr(predicate::str::contains("no token provided"));
}

#[test]
fn test_decode_malformed_two_parts_shows_error() {
    cmd()
        .args(["decode", common::MALFORMED_TOKEN_TWO_PARTS])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid token format"));
}

#[test]
fn test_decode_completely_invalid_token_shows_error() {
    cmd()
        .args(["decode", common::INVALID_TOKEN])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid token format"));
}

#[test]
fn test_decode_empty_token_arg_shows_error() {
    cmd()
        .args(["decode", ""])
        .assert()
        .failure()
        .stderr(predicate::str::contains("no token provided"));
}

#[test]
fn test_decode_invalid_base64_shows_error() {
    cmd()
        .args(["decode", "!!!.!!!.!!!"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("base64url"));
}

// --- Decode: Security Hardening ---

#[test]
fn test_decode_invalid_env_var_name_with_equals() {
    cmd()
        .args(["decode", "--token-env", "BAD=NAME"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "invalid environment variable name",
        ));
}

#[test]
fn test_decode_empty_env_var_name() {
    cmd()
        .args(["decode", "--token-env", ""])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "invalid environment variable name",
        ));
}

// --- Verify: HMAC Signature Validation ---

#[test]
fn test_verify_hs256_valid_secret() {
    let token = common::create_hs256_token(common::HMAC_TEST_SECRET, &common::standard_claims());
    cmd()
        .args(["verify", &token, "--secret", common::HMAC_TEST_SECRET])
        .assert()
        .success()
        .stdout(predicate::str::contains("VALID SIGNATURE"))
        .stdout(predicate::str::contains("HS256"));
}

#[test]
fn test_verify_hs256_wrong_secret() {
    let token = common::create_hs256_token(common::HMAC_TEST_SECRET, &common::standard_claims());
    cmd()
        .args(["verify", &token, "--secret", "wrong-secret"])
        .assert()
        .failure()
        .stdout(predicate::str::contains("INVALID SIGNATURE"));
}

#[test]
fn test_verify_hs256_displays_decoded_content() {
    let token = common::create_hs256_token(common::HMAC_TEST_SECRET, &common::standard_claims());
    cmd()
        .args(["verify", &token, "--secret", common::HMAC_TEST_SECRET])
        .assert()
        .success()
        .stdout(predicate::str::contains("--- Header ---"))
        .stdout(predicate::str::contains("--- Payload ---"))
        .stdout(predicate::str::contains("--- Token Status ---"))
        .stdout(predicate::str::contains("--- Signature ---"))
        .stdout(predicate::str::contains("Test User"))
        .stdout(predicate::str::contains("1234567890"));
}

#[test]
fn test_verify_hs256_secret_from_env() {
    let token = common::create_hs256_token(common::HMAC_TEST_SECRET, &common::standard_claims());
    cmd()
        .args(["verify", &token, "--secret-env", "JWT_TEST_SECRET"])
        .env("JWT_TEST_SECRET", common::HMAC_TEST_SECRET)
        .assert()
        .success()
        .stdout(predicate::str::contains("VALID SIGNATURE"));
}

#[test]
fn test_verify_secret_env_not_set() {
    let token = common::create_hs256_token(common::HMAC_TEST_SECRET, &common::standard_claims());
    cmd()
        .args(["verify", &token, "--secret-env", "NONEXISTENT_SECRET_VAR"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("NONEXISTENT_SECRET_VAR"));
}

// --- Verify: RSA Signature Validation ---

#[test]
fn test_verify_rs256_valid_key_file() {
    let token = common::create_rs256_token(&common::standard_claims());
    cmd()
        .args(["verify", &token, "--key-file", common::RSA_PUBLIC_KEY_PATH])
        .assert()
        .success()
        .stdout(predicate::str::contains("VALID SIGNATURE"))
        .stdout(predicate::str::contains("RS256"));
}

#[test]
fn test_verify_rs256_wrong_key_file() {
    let token = common::create_rs256_token(&common::standard_claims());
    // Use EC public key for an RSA token — key type mismatch
    cmd()
        .args(["verify", &token, "--key-file", common::EC_PUBLIC_KEY_PATH])
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("failed to parse RSA PEM key")
                .or(predicate::str::contains("signature validation failed")),
        );
}

// --- Verify: EC Signature Validation ---

#[test]
fn test_verify_es256_valid_key_file() {
    let token = common::create_es256_token(&common::standard_claims());
    cmd()
        .args(["verify", &token, "--key-file", common::EC_PUBLIC_KEY_PATH])
        .assert()
        .success()
        .stdout(predicate::str::contains("VALID SIGNATURE"))
        .stdout(predicate::str::contains("ES256"));
}

// --- Verify: EdDSA Signature Validation ---

#[test]
fn test_verify_eddsa_valid_key_file() {
    let token = common::create_eddsa_token(&common::standard_claims());
    cmd()
        .args([
            "verify",
            &token,
            "--key-file",
            common::ED25519_PUBLIC_KEY_PATH,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("VALID SIGNATURE"))
        .stdout(predicate::str::contains("EdDSA"));
}

#[test]
fn test_verify_eddsa_wrong_key_file() {
    let token = common::create_eddsa_token(&common::standard_claims());
    // Use EC public key for an EdDSA token — key type mismatch
    cmd()
        .args(["verify", &token, "--key-file", common::EC_PUBLIC_KEY_PATH])
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("failed to parse EdDSA PEM key")
                .or(predicate::str::contains("signature validation failed")),
        );
}

// --- Verify: JSON Mode ---

#[test]
fn test_verify_json_mode_valid() {
    let token = common::create_hs256_token(common::HMAC_TEST_SECRET, &common::standard_claims());
    let output = cmd()
        .args([
            "verify",
            &token,
            "--secret",
            common::HMAC_TEST_SECRET,
            "--json",
        ])
        .output()
        .expect("failed to execute");

    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("invalid JSON output");
    assert_eq!(parsed["signature"]["valid"], true);
    assert_eq!(parsed["signature"]["algorithm"], "HS256");
    assert!(parsed.get("header").is_some());
    assert!(parsed.get("payload").is_some());
}

#[test]
fn test_verify_json_mode_invalid() {
    let token = common::create_hs256_token(common::HMAC_TEST_SECRET, &common::standard_claims());
    let output = cmd()
        .args(["verify", &token, "--secret", "wrong-secret", "--json"])
        .output()
        .expect("failed to execute");

    assert!(!output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("invalid JSON output");
    assert_eq!(parsed["signature"]["valid"], false);
    assert!(parsed["signature"]["reason"].as_str().is_some());
}

// --- Verify: Token Input Sources ---

#[test]
fn test_verify_from_stdin() {
    let token = common::create_hs256_token(common::HMAC_TEST_SECRET, &common::standard_claims());
    cmd()
        .args(["verify", "--secret", common::HMAC_TEST_SECRET])
        .write_stdin(token)
        .assert()
        .success()
        .stdout(predicate::str::contains("VALID SIGNATURE"));
}

#[test]
fn test_verify_from_env_var() {
    let token = common::create_hs256_token(common::HMAC_TEST_SECRET, &common::standard_claims());
    cmd()
        .args([
            "verify",
            "--token-env",
            "TEST_JWT_VERIFY",
            "--secret",
            common::HMAC_TEST_SECRET,
        ])
        .env("TEST_JWT_VERIFY", token)
        .assert()
        .success()
        .stdout(predicate::str::contains("VALID SIGNATURE"));
}

// --- Verify: Error Cases ---

#[test]
fn test_verify_no_key_provided() {
    let token = common::create_hs256_token(common::HMAC_TEST_SECRET, &common::standard_claims());
    cmd()
        .args(["verify", &token])
        .assert()
        .failure()
        .stderr(predicate::str::contains("no key material provided"));
}

#[test]
fn test_verify_no_token_provided() {
    cmd()
        .args(["verify", "--secret", "test"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("no token provided"));
}

#[test]
fn test_verify_key_file_not_found() {
    let token = common::create_hs256_token(common::HMAC_TEST_SECRET, &common::standard_claims());
    cmd()
        .args(["verify", &token, "--key-file", "/nonexistent/path/key.pem"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("failed to read key file"));
}

#[test]
fn test_verify_alg_none_rejected() {
    // Token with alg: "none" — eyJhbGciOiJub25lIn0 = {"alg":"none"}
    let token = "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0In0.";
    cmd()
        .args(["verify", token, "--secret", "test"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unsupported algorithm"));
}

// --- Verify: Key File Size Limit ---

#[test]
fn test_verify_key_file_too_large() {
    use std::io::Write;
    let token = common::create_hs256_token(common::HMAC_TEST_SECRET, &common::standard_claims());
    let dir = tempfile::tempdir().unwrap();
    let large_file = dir.path().join("large.pem");
    // Create a file just over 1 MB
    let mut f = std::fs::File::create(&large_file).unwrap();
    f.write_all(&vec![b'A'; 1_048_577]).unwrap();
    cmd()
        .args([
            "verify",
            &token,
            "--key-file",
            large_file.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("key file too large"));
}

// --- Verify: Not Yet Implemented Features ---

#[test]
fn test_verify_jwks_url_not_implemented() {
    let token = common::create_hs256_token(common::HMAC_TEST_SECRET, &common::standard_claims());
    cmd()
        .args([
            "verify",
            &token,
            "--jwks-url",
            "https://example.com/.well-known/jwks.json",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not yet implemented"));
}

#[test]
fn test_verify_time_travel_not_implemented() {
    let token = common::create_hs256_token(common::HMAC_TEST_SECRET, &common::standard_claims());
    cmd()
        .args(["verify", &token, "--secret", "test", "--time-travel", "+7d"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not yet implemented"));
}

// --- Exit Codes ---

#[test]
fn test_help_exits_with_zero() {
    cmd().arg("--help").assert().success();
}

#[test]
fn test_no_args_exits_with_nonzero() {
    cmd().assert().failure();
}

#[test]
fn test_decode_valid_token_exits_with_zero() {
    cmd()
        .args(["decode", common::VALID_HS256_TOKEN])
        .assert()
        .success();
}

#[test]
fn test_decode_malformed_token_exits_with_nonzero() {
    cmd()
        .args(["decode", common::INVALID_TOKEN])
        .assert()
        .failure();
}

#[test]
fn test_verify_valid_exits_with_zero() {
    let token = common::create_hs256_token(common::HMAC_TEST_SECRET, &common::standard_claims());
    cmd()
        .args(["verify", &token, "--secret", common::HMAC_TEST_SECRET])
        .assert()
        .success();
}

#[test]
fn test_verify_invalid_exits_with_nonzero() {
    let token = common::create_hs256_token(common::HMAC_TEST_SECRET, &common::standard_claims());
    cmd()
        .args(["verify", &token, "--secret", "wrong-secret"])
        .assert()
        .failure();
}
