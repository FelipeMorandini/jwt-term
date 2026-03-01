//! Token status display for temporal claims.
//!
//! Renders human-readable status information for JWT temporal claims
//! (`exp`, `iat`, `nbf`) including expiry status with color coding.

use chrono::{DateTime, TimeDelta, Utc};
use colored::Colorize;
use serde_json::Value;

use crate::core::validator::ValidationOutcome;

/// Display the temporal status of a JWT's claims.
///
/// Examines `exp`, `iat`, and `nbf` claims in the payload and prints
/// human-readable status information:
/// - Expired tokens: red "EXPIRED (X ago)"
/// - Valid tokens: green "VALID (expires in X)"
/// - Not-yet-valid tokens: yellow "NOT YET VALID (valid in X)"
pub fn display_token_status(payload: &Value) {
    let now = Utc::now();
    let mut has_temporal = false;

    if let Some(iat) = extract_timestamp(payload, "iat") {
        has_temporal = true;
        println!("  {} {}", "Issued at: ".bold(), format_timestamp(iat));
    }

    if let Some(nbf) = extract_timestamp(payload, "nbf") {
        has_temporal = true;
        display_nbf_status(nbf, now);
    }

    if let Some(exp) = extract_timestamp(payload, "exp") {
        has_temporal = true;
        display_exp_status(exp, now);
    }

    if !has_temporal {
        println!("  {}", "No temporal claims found".dimmed());
    }
}

/// Display expiry (`exp`) status with color coding.
fn display_exp_status(exp: DateTime<Utc>, now: DateTime<Utc>) {
    if now >= exp {
        let ago = format_duration(now.signed_duration_since(exp));
        println!(
            "  {} {} ({})",
            "Expires:  ".bold(),
            "EXPIRED".red().bold(),
            format!("{} ago", ago).red()
        );
    } else {
        let remaining = format_duration(exp.signed_duration_since(now));
        println!(
            "  {} {} ({})",
            "Expires:  ".bold(),
            "VALID".green().bold(),
            format!("expires in {}", remaining).green()
        );
    }
}

/// Display not-before (`nbf`) status with color coding.
fn display_nbf_status(nbf: DateTime<Utc>, now: DateTime<Utc>) {
    if now < nbf {
        let remaining = format_duration(nbf.signed_duration_since(now));
        println!(
            "  {} {} ({})",
            "Not before:".bold(),
            "NOT YET VALID".yellow().bold(),
            format!("valid in {}", remaining).yellow()
        );
    } else {
        println!("  {} {}", "Not before:".bold(), format_timestamp(nbf));
    }
}

/// Display the result of signature validation with color coding.
///
/// - Valid: green "VALID SIGNATURE (algorithm)"
/// - Invalid: red "INVALID SIGNATURE (reason)"
pub fn display_validation_result(outcome: &ValidationOutcome, algorithm: &str) {
    match outcome {
        ValidationOutcome::Valid => {
            println!("  {} ({})", "VALID SIGNATURE".green().bold(), algorithm);
        }
        ValidationOutcome::Invalid { reason } => {
            println!("  {} ({})", "INVALID SIGNATURE".red().bold(), reason);
        }
    }
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
}
