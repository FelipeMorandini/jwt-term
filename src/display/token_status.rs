//! Token status display for temporal claims.
//!
//! Renders human-readable status information for JWT temporal claims
//! (`exp`, `iat`, `nbf`) including expiry status with color coding.

use std::io::{self, Write};

use chrono::{DateTime, TimeDelta, Utc};
use colored::Colorize;
use serde_json::Value;

use crate::core::time_travel::{ClaimStatus, TimeTravelResult};
use crate::core::validator::ValidationOutcome;

/// Write the temporal status of a JWT's claims to the given writer.
///
/// Examines `exp`, `iat`, and `nbf` claims in the payload and writes
/// human-readable status information:
/// - Expired tokens: red "EXPIRED (X ago)"
/// - Valid tokens: green "VALID (expires in X)"
/// - Not-yet-valid tokens: yellow "NOT YET VALID (valid in X)"
pub fn write_token_status(w: &mut impl Write, payload: &Value) -> io::Result<()> {
    let now = Utc::now();
    let mut has_temporal = false;

    if let Some(iat) = extract_timestamp(payload, "iat") {
        has_temporal = true;
        writeln!(w, "  {} {}", "Issued at: ".bold(), format_timestamp(iat))?;
    }

    if let Some(nbf) = extract_timestamp(payload, "nbf") {
        has_temporal = true;
        write_nbf_status(w, nbf, now)?;
    }

    if let Some(exp) = extract_timestamp(payload, "exp") {
        has_temporal = true;
        write_exp_status(w, exp, now)?;
    }

    if !has_temporal {
        writeln!(w, "  {}", "No temporal claims found".dimmed())?;
    }

    Ok(())
}

/// Display the temporal status of a JWT's claims to stdout.
///
/// Convenience wrapper around [`write_token_status`].
pub fn display_token_status(payload: &Value) {
    let _ = write_token_status(&mut io::stdout(), payload);
}

/// Write expiry (`exp`) status with color coding.
fn write_exp_status(w: &mut impl Write, exp: DateTime<Utc>, now: DateTime<Utc>) -> io::Result<()> {
    if now >= exp {
        let ago = format_duration(now.signed_duration_since(exp));
        writeln!(
            w,
            "  {} {} ({})",
            "Expires:  ".bold(),
            "EXPIRED".red().bold(),
            format!("{} ago", ago).red()
        )
    } else {
        let remaining = format_duration(exp.signed_duration_since(now));
        writeln!(
            w,
            "  {} {} ({})",
            "Expires:  ".bold(),
            "VALID".green().bold(),
            format!("expires in {}", remaining).green()
        )
    }
}

/// Write not-before (`nbf`) status with color coding.
fn write_nbf_status(w: &mut impl Write, nbf: DateTime<Utc>, now: DateTime<Utc>) -> io::Result<()> {
    if now < nbf {
        let remaining = format_duration(nbf.signed_duration_since(now));
        writeln!(
            w,
            "  {} {} ({})",
            "Not before:".bold(),
            "NOT YET VALID".yellow().bold(),
            format!("valid in {}", remaining).yellow()
        )
    } else {
        writeln!(w, "  {} {}", "Not before:".bold(), format_timestamp(nbf))
    }
}

/// Write the result of signature validation with color coding.
///
/// - Valid: green "VALID SIGNATURE (algorithm)"
/// - Invalid: red "INVALID SIGNATURE (reason)"
pub fn write_validation_result(
    w: &mut impl Write,
    outcome: &ValidationOutcome,
    algorithm: &str,
) -> io::Result<()> {
    match outcome {
        ValidationOutcome::Valid => {
            writeln!(w, "  {} ({})", "VALID SIGNATURE".green().bold(), algorithm)
        }
        ValidationOutcome::Invalid { reason } => {
            writeln!(w, "  {} ({})", "INVALID SIGNATURE".red().bold(), reason)
        }
    }
}

/// Display the result of signature validation to stdout.
///
/// Convenience wrapper around [`write_validation_result`].
pub fn display_validation_result(outcome: &ValidationOutcome, algorithm: &str) {
    let _ = write_validation_result(&mut io::stdout(), outcome, algorithm);
}

/// Extract a Unix timestamp claim from the payload as a `DateTime<Utc>`.
fn extract_timestamp(payload: &Value, claim: &str) -> Option<DateTime<Utc>> {
    payload
        .get(claim)
        .and_then(Value::as_i64)
        .and_then(|ts| DateTime::from_timestamp(ts, 0))
}

/// Format a `DateTime<Utc>` as a human-readable string.
fn format_timestamp(dt: DateTime<Utc>) -> String {
    dt.format("%Y-%m-%d %H:%M:%S UTC").to_string()
}

/// Format a `TimeDelta` as a human-readable relative duration.
fn format_duration(duration: TimeDelta) -> String {
    let secs = duration.num_seconds().unsigned_abs();

    if secs < 60 {
        format!("{} second{}", secs, pluralize(secs))
    } else if secs < 3600 {
        let mins = secs / 60;
        format!("{} minute{}", mins, pluralize(mins))
    } else if secs < 86400 {
        let hours = secs / 3600;
        format!("{} hour{}", hours, pluralize(hours))
    } else {
        let days = secs / 86400;
        format!("{} day{}", days, pluralize(days))
    }
}

/// Write time-travel evaluation results with color coding.
///
/// Shows the simulated timestamp, the original expression, and
/// the status of `exp` and `nbf` claims at that simulated time.
pub fn write_time_travel_status(w: &mut impl Write, result: &TimeTravelResult) -> io::Result<()> {
    let expression = sanitize_for_terminal(&result.target.expression);
    writeln!(
        w,
        "  {} {} ({})",
        "Simulating:".bold(),
        format_timestamp(result.target.timestamp),
        expression
    )?;

    write_tt_exp(w, &result.exp_status)?;
    write_tt_nbf(w, &result.nbf_status)
}

/// Display time-travel evaluation results to stdout.
///
/// Convenience wrapper around [`write_time_travel_status`].
pub fn display_time_travel_status(result: &TimeTravelResult) {
    let _ = write_time_travel_status(&mut io::stdout(), result);
}

/// Sanitize a string for safe terminal display by removing control characters.
///
/// Replaces control characters (including ANSI escape sequences) with the
/// Unicode replacement character while preserving printable content.
fn sanitize_for_terminal(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { '\u{FFFD}' } else { c })
        .collect()
}

/// Write the `exp` claim status at a simulated time.
fn write_tt_exp(w: &mut impl Write, status: &ClaimStatus) -> io::Result<()> {
    match status {
        ClaimStatus::Expired { elapsed } => {
            let ago = format_duration(*elapsed);
            writeln!(
                w,
                "  {} {} ({})",
                "Expires:  ".bold(),
                "EXPIRED at simulated time".red().bold(),
                format!("expired {} before simulated time", ago).red()
            )
        }
        ClaimStatus::Valid => {
            writeln!(
                w,
                "  {} {}",
                "Expires:  ".bold(),
                "VALID at simulated time".green().bold(),
            )
        }
        ClaimStatus::Absent => {
            writeln!(
                w,
                "  {} {}",
                "Expires:  ".bold(),
                "no exp claim present".dimmed()
            )
        }
        ClaimStatus::Invalid => {
            writeln!(
                w,
                "  {} {}",
                "Expires:  ".bold(),
                "INVALID exp value".red().bold()
            )
        }
        ClaimStatus::NotYetValid { remaining } => {
            let until = format_duration(*remaining);
            writeln!(
                w,
                "  {} {} ({})",
                "Expires:  ".bold(),
                "NOT YET VALID at simulated time".yellow().bold(),
                format!("expires in {}", until).yellow()
            )
        }
    }
}

/// Write the `nbf` claim status at a simulated time.
fn write_tt_nbf(w: &mut impl Write, status: &ClaimStatus) -> io::Result<()> {
    match status {
        ClaimStatus::NotYetValid { remaining } => {
            let until = format_duration(*remaining);
            writeln!(
                w,
                "  {} {} ({})",
                "Not before:".bold(),
                "NOT YET VALID at simulated time".yellow().bold(),
                format!("becomes valid in {}", until).yellow()
            )
        }
        ClaimStatus::Valid => {
            writeln!(
                w,
                "  {} {}",
                "Not before:".bold(),
                "VALID at simulated time".green().bold(),
            )
        }
        ClaimStatus::Absent => {
            writeln!(
                w,
                "  {} {}",
                "Not before:".bold(),
                "no nbf claim present".dimmed()
            )
        }
        ClaimStatus::Invalid => {
            writeln!(
                w,
                "  {} {}",
                "Not before:".bold(),
                "INVALID nbf value".red().bold()
            )
        }
        ClaimStatus::Expired { elapsed } => {
            let ago = format_duration(*elapsed);
            writeln!(
                w,
                "  {} {} ({})",
                "Not before:".bold(),
                "EXPIRED at simulated time".red().bold(),
                format!("expired {} before simulated time", ago).red()
            )
        }
    }
}

/// Return "s" for plural or "" for singular.
fn pluralize(n: u64) -> &'static str {
    if n == 1 { "" } else { "s" }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_extract_timestamp_present() {
        let payload = json!({"exp": 1700000000});
        let ts = extract_timestamp(&payload, "exp");
        assert!(ts.is_some());
        assert_eq!(ts.unwrap().timestamp(), 1700000000);
    }

    #[test]
    fn test_extract_timestamp_missing() {
        let payload = json!({"sub": "1234"});
        assert!(extract_timestamp(&payload, "exp").is_none());
    }

    #[test]
    fn test_extract_timestamp_non_numeric() {
        let payload = json!({"exp": "not-a-number"});
        assert!(extract_timestamp(&payload, "exp").is_none());
    }

    #[test]
    fn test_format_timestamp() {
        let dt = DateTime::from_timestamp(1516239022, 0).unwrap();
        let result = format_timestamp(dt);
        assert_eq!(result, "2018-01-18 01:30:22 UTC");
    }

    #[test]
    fn test_format_duration_seconds() {
        let duration = TimeDelta::seconds(45);
        assert_eq!(format_duration(duration), "45 seconds");
    }

    #[test]
    fn test_format_duration_one_second() {
        let duration = TimeDelta::seconds(1);
        assert_eq!(format_duration(duration), "1 second");
    }

    #[test]
    fn test_format_duration_minutes() {
        let duration = TimeDelta::seconds(150);
        assert_eq!(format_duration(duration), "2 minutes");
    }

    #[test]
    fn test_format_duration_one_minute() {
        let duration = TimeDelta::seconds(60);
        assert_eq!(format_duration(duration), "1 minute");
    }

    #[test]
    fn test_format_duration_hours() {
        let duration = TimeDelta::seconds(7200);
        assert_eq!(format_duration(duration), "2 hours");
    }

    #[test]
    fn test_format_duration_days() {
        let duration = TimeDelta::seconds(172800);
        assert_eq!(format_duration(duration), "2 days");
    }

    #[test]
    fn test_pluralize() {
        assert_eq!(pluralize(0), "s");
        assert_eq!(pluralize(1), "");
        assert_eq!(pluralize(2), "s");
        assert_eq!(pluralize(100), "s");
    }

    #[test]
    fn test_sanitize_for_terminal_replaces_control_chars() {
        let input = "+7d\x1b[31m\x00injected";
        let result = sanitize_for_terminal(input);
        assert!(!result.chars().any(|c| c.is_control()));
        assert!(result.contains("+7d"));
    }

    #[test]
    fn test_sanitize_for_terminal_preserves_normal_input() {
        assert_eq!(sanitize_for_terminal("+7d"), "+7d");
        assert_eq!(
            sanitize_for_terminal("2024-06-01T00:00:00Z"),
            "2024-06-01T00:00:00Z"
        );
    }

    // --- write_* function tests (Write trait) ---

    #[test]
    fn test_write_token_status_with_exp_claim() {
        let payload = json!({"exp": 1700000000});
        let mut buf = Vec::new();
        write_token_status(&mut buf, &payload).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("Expires:"));
    }

    #[test]
    fn test_write_token_status_with_iat_claim() {
        let payload = json!({"iat": 1516239022});
        let mut buf = Vec::new();
        write_token_status(&mut buf, &payload).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("Issued at:"));
    }

    #[test]
    fn test_write_token_status_no_temporal_claims() {
        let payload = json!({"sub": "user"});
        let mut buf = Vec::new();
        write_token_status(&mut buf, &payload).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("No temporal claims found"));
    }

    #[test]
    fn test_write_validation_result_valid() {
        let mut buf = Vec::new();
        write_validation_result(&mut buf, &ValidationOutcome::Valid, "HS256").unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("VALID SIGNATURE"));
        assert!(output.contains("HS256"));
    }

    #[test]
    fn test_write_validation_result_invalid() {
        let outcome = ValidationOutcome::Invalid {
            reason: "signature does not match".to_string(),
        };
        let mut buf = Vec::new();
        write_validation_result(&mut buf, &outcome, "RS256").unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("INVALID SIGNATURE"));
        assert!(output.contains("signature does not match"));
    }

    #[test]
    fn test_write_time_travel_status_with_expired() {
        use crate::core::time_travel::{TimeTarget, TimeTravelResult};

        let target = TimeTarget {
            timestamp: DateTime::from_timestamp(2000000000, 0).unwrap(),
            expression: "+7d".to_string(),
        };
        let result = TimeTravelResult {
            target,
            exp_status: ClaimStatus::Expired {
                elapsed: TimeDelta::seconds(3600),
            },
            nbf_status: ClaimStatus::Absent,
            exp_value: Some(1999996400),
            nbf_value: None,
        };
        let mut buf = Vec::new();
        write_time_travel_status(&mut buf, &result).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("Simulating"));
        assert!(output.contains("EXPIRED at simulated time"));
        assert!(output.contains("no nbf claim present"));
    }

    #[test]
    fn test_write_time_travel_status_with_valid() {
        use crate::core::time_travel::{TimeTarget, TimeTravelResult};

        let target = TimeTarget {
            timestamp: DateTime::from_timestamp(1900000000, 0).unwrap(),
            expression: "1900000000".to_string(),
        };
        let result = TimeTravelResult {
            target,
            exp_status: ClaimStatus::Valid,
            nbf_status: ClaimStatus::Valid,
            exp_value: Some(2000000000),
            nbf_value: Some(1800000000),
        };
        let mut buf = Vec::new();
        write_time_travel_status(&mut buf, &result).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("VALID at simulated time"));
    }
}
