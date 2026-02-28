//! Integration tests for the jwt-term CLI.
//!
//! Tests argument parsing, help text, version output, subcommand routing,
//! decode command behavior, and error handling.

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

// --- Verify Subcommand (still stubbed) ---

#[test]
fn test_verify_with_token_returns_not_implemented() {
    cmd()
        .args([
            "verify",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.sig",
            "--secret",
            "test",
        ])
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
fn test_verify_stub_exits_with_nonzero() {
    cmd().args(["verify", "token"]).assert().failure();
}
