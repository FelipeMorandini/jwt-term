//! Integration tests for the jwt-term CLI skeleton.
//!
//! Tests argument parsing, help text, version output, subcommand routing,
//! and error behavior for the Phase 1 foundation.

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

// --- Decode Subcommand (stub behavior) ---

#[test]
fn test_decode_with_token_returns_not_implemented() {
    cmd()
        .args([
            "decode",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.signature",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not yet implemented"));
}

#[test]
fn test_decode_without_token_returns_not_implemented() {
    // Even without a token, the stub returns "not implemented"
    // before any token-reading logic runs
    cmd()
        .arg("decode")
        .assert()
        .failure()
        .stderr(predicate::str::contains("not yet implemented"));
}

// --- Verify Subcommand (stub behavior) ---

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
fn test_stub_commands_exit_with_nonzero() {
    cmd().args(["decode", "token"]).assert().failure();
    cmd().args(["verify", "token"]).assert().failure();
}
