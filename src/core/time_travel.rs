//! Time-travel debugging for JWT temporal claims.
//!
//! Parses time expressions (relative like "+7d" or absolute like ISO 8601)
//! and evaluates `exp` and `nbf` claims against a simulated timestamp.

use chrono::{DateTime, TimeDelta, Utc};
use serde_json::Value;

use crate::error::JwtTermError;

/// Maximum length of a time expression in bytes.
///
/// Prevents excessive memory allocation from malformed input.
const MAX_TIME_EXPRESSION_LEN: usize = 128;

/// A parsed time target for time-travel evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeTarget {
    /// The resolved absolute timestamp.
    pub timestamp: DateTime<Utc>,
    /// The original expression provided by the user.
    pub expression: String,
}

/// The status of a single temporal claim at the simulated time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimStatus {
    /// The claim is satisfied at the simulated time.
    Valid,
    /// The token has expired at the simulated time.
    Expired {
        /// How long before the simulated time the token expired.
        elapsed: TimeDelta,
    },
    /// The token is not yet valid at the simulated time.
    NotYetValid {
        /// How long after the simulated time until the token becomes valid.
        remaining: TimeDelta,
    },
    /// The claim is not present in the token payload.
    Absent,
    /// The claim is present but its value is not usable as a timestamp.
    ///
    /// This occurs when the claim value is a non-numeric type (e.g., string,
    /// boolean) or when the numeric value is outside the representable range
    /// for `DateTime<Utc>` (e.g., extreme i64 values).
    Invalid,
}

/// Result of evaluating temporal claims against a simulated timestamp.
#[derive(Debug, Clone)]
pub struct TimeTravelResult {
    /// The target time used for evaluation.
    pub target: TimeTarget,
    /// Status of the `exp` claim at the target time.
    pub exp_status: ClaimStatus,
    /// The parsed `exp` claim value as numeric seconds since the Unix epoch.
    ///
    /// Derived from the JSON claim by [`extract_timestamp_value`], which
    /// truncates floating-point numbers to whole seconds. `None` when the
    /// `exp` claim is absent or present but not usable as a timestamp
    /// (in which case `exp_status` will be [`ClaimStatus::Invalid`]).
    pub exp_value: Option<i64>,
    /// Status of the `nbf` claim at the target time.
    pub nbf_status: ClaimStatus,
    /// The parsed `nbf` claim value as numeric seconds since the Unix epoch.
    ///
    /// Derived from the JSON claim by [`extract_timestamp_value`], which
    /// truncates floating-point numbers to whole seconds. `None` when the
    /// `nbf` claim is absent or present but not usable as a timestamp
    /// (in which case `nbf_status` will be [`ClaimStatus::Invalid`]).
    pub nbf_value: Option<i64>,
}

/// Parse a time-travel expression into an absolute timestamp.
///
/// Supports the following formats:
/// - Relative: `+7d`, `-1h`, `+30m`, `+1y`, `-5s`
/// - Absolute ISO 8601: `2024-01-15T14:30:00Z`
/// - Absolute Unix epoch: `1705312200`
///
/// # Errors
///
/// Returns an error if the expression doesn't match any known format
/// or if the resulting timestamp would overflow.
pub fn parse_time_expression(expression: &str) -> Result<TimeTarget, JwtTermError> {
    if expression.len() > MAX_TIME_EXPRESSION_LEN {
        return Err(JwtTermError::InvalidTimeExpression {
            expression: truncate_for_display(expression),
            reason: format!(
                "expression too long ({} bytes, max {})",
                expression.len(),
                MAX_TIME_EXPRESSION_LEN
            ),
        });
    }

    let trimmed = expression.trim();
    if trimmed.is_empty() {
        return Err(JwtTermError::InvalidTimeExpression {
            expression: trimmed.to_string(),
            reason: "expression cannot be empty".to_string(),
        });
    }

    // Sanitize once for use in all error paths and the stored expression.
    let sanitized = sanitize_expression(trimmed);

    if let Some(target) = try_parse_relative(trimmed, &sanitized)? {
        return Ok(target);
    }

    if let Some(target) = try_parse_iso8601(trimmed, &sanitized) {
        return Ok(target);
    }

    if let Some(target) = try_parse_unix_epoch(trimmed, &sanitized)? {
        return Ok(target);
    }

    Err(JwtTermError::InvalidTimeExpression {
        expression: sanitized,
        reason: "expected relative expression (+7d, -1h), ISO 8601 timestamp, or Unix epoch"
            .to_string(),
    })
}

/// Evaluate `exp` and `nbf` claims against a target timestamp.
///
/// Returns a [`TimeTravelResult`] with the status of each claim.
/// Claims that are absent from the payload are marked as [`ClaimStatus::Absent`].
pub fn evaluate_temporal_claims(payload: &Value, target: &TimeTarget) -> TimeTravelResult {
    let exp_value = extract_timestamp_value(payload, "exp");
    let nbf_value = extract_timestamp_value(payload, "nbf");

    let exp_status = match exp_value {
        Some(ts) => match DateTime::from_timestamp(ts, 0) {
            Some(exp_dt) => {
                if target.timestamp >= exp_dt {
                    ClaimStatus::Expired {
                        elapsed: target.timestamp.signed_duration_since(exp_dt),
                    }
                } else {
                    ClaimStatus::Valid
                }
            }
            None => ClaimStatus::Invalid,
        },
        // Claim is present but not a numeric type (e.g., string, boolean).
        None if payload.get("exp").is_some() => ClaimStatus::Invalid,
        None => ClaimStatus::Absent,
    };

    let nbf_status = match nbf_value {
        Some(ts) => match DateTime::from_timestamp(ts, 0) {
            Some(nbf_dt) => {
                if target.timestamp < nbf_dt {
                    ClaimStatus::NotYetValid {
                        remaining: nbf_dt.signed_duration_since(target.timestamp),
                    }
                } else {
                    ClaimStatus::Valid
                }
            }
            None => ClaimStatus::Invalid,
        },
        None if payload.get("nbf").is_some() => ClaimStatus::Invalid,
        None => ClaimStatus::Absent,
    };

    TimeTravelResult {
        target: target.clone(),
        exp_status,
        exp_value,
        nbf_status,
        nbf_value,
    }
}

/// Try to parse a relative time expression like `+7d` or `-1h`.
///
/// Returns `Ok(Some(target))` on success, `Ok(None)` if the expression
/// doesn't look relative, or `Err` if parsing fails (e.g., overflow).
fn try_parse_relative(expr: &str, sanitized: &str) -> Result<Option<TimeTarget>, JwtTermError> {
    let sign = expr.chars().next().unwrap_or('\0');
    if sign != '+' && sign != '-' {
        return Ok(None);
    }

    if expr.len() < 2 {
        return Err(JwtTermError::InvalidTimeExpression {
            expression: sanitized.to_string(),
            reason: "relative expression too short".to_string(),
        });
    }

    let unit = expr.chars().last().unwrap_or('\0');

    // If the last character is a digit, this isn't a relative expression
    // (e.g., "-1705312200" should fall through to the epoch parser).
    if unit.is_ascii_digit() {
        return Ok(None);
    }

    let number_str = &expr[sign.len_utf8()..expr.len() - unit.len_utf8()];

    if number_str.is_empty() {
        return Err(JwtTermError::InvalidTimeExpression {
            expression: sanitized.to_string(),
            reason: "missing numeric value".to_string(),
        });
    }

    // Reject embedded signs (e.g., "--1h" or "+-1h") — the leading sign
    // is already captured in `sign`, so the numeric part must be digits only.
    if !number_str.bytes().all(|b| b.is_ascii_digit()) {
        return Err(JwtTermError::InvalidTimeExpression {
            expression: sanitized.to_string(),
            reason: format!("'{}' is not a valid number", number_str),
        });
    }

    let value: i64 = number_str
        .parse()
        .map_err(|_| JwtTermError::InvalidTimeExpression {
            expression: sanitized.to_string(),
            reason: format!("'{}' is not a valid number", number_str),
        })?;

    let delta_seconds = unit_to_seconds(value, unit, sanitized)?;
    apply_signed_delta(sign, delta_seconds, sanitized).map(Some)
}

/// Convert a numeric value and time unit character to total seconds.
fn unit_to_seconds(value: i64, unit: char, sanitized_expr: &str) -> Result<i64, JwtTermError> {
    let seconds = match unit {
        's' => Some(value),
        'm' => value.checked_mul(60),
        'h' => value.checked_mul(3600),
        'd' => value.checked_mul(86400),
        'y' => value.checked_mul(365 * 86400),
        _ => {
            return Err(JwtTermError::InvalidTimeExpression {
                expression: sanitized_expr.to_string(),
                reason: format!(
                    "unknown unit '{}'; expected 's', 'm', 'h', 'd', or 'y'",
                    unit
                ),
            });
        }
    };

    seconds.ok_or_else(|| JwtTermError::InvalidTimeExpression {
        expression: sanitized_expr.to_string(),
        reason: "value too large, would overflow".to_string(),
    })
}

/// Apply a sign to the delta seconds and compute the target timestamp.
fn apply_signed_delta(
    sign: char,
    delta_seconds: i64,
    sanitized_expr: &str,
) -> Result<TimeTarget, JwtTermError> {
    let signed = if sign == '-' {
        delta_seconds
            .checked_neg()
            .ok_or_else(|| JwtTermError::InvalidTimeExpression {
                expression: sanitized_expr.to_string(),
                reason: "value too large, would overflow".to_string(),
            })?
    } else {
        delta_seconds
    };

    let delta =
        TimeDelta::try_seconds(signed).ok_or_else(|| JwtTermError::InvalidTimeExpression {
            expression: sanitized_expr.to_string(),
            reason: "duration out of representable range".to_string(),
        })?;

    let now = Utc::now();
    now.checked_add_signed(delta)
        .map(|timestamp| TimeTarget {
            timestamp,
            expression: sanitized_expr.to_string(),
        })
        .ok_or_else(|| JwtTermError::InvalidTimeExpression {
            expression: sanitized_expr.to_string(),
            reason: "resulting timestamp out of range".to_string(),
        })
}

/// Try to parse an ISO 8601 datetime string.
fn try_parse_iso8601(expr: &str, sanitized: &str) -> Option<TimeTarget> {
    let dt: DateTime<Utc> = expr.parse().ok()?;
    Some(TimeTarget {
        timestamp: dt,
        expression: sanitized.to_string(),
    })
}

/// Try to parse a Unix epoch timestamp (non-negative integer).
///
/// Returns `Ok(Some(target))` on success, `Ok(None)` if the expression
/// doesn't look like a Unix timestamp, or `Err` on overflow.
fn try_parse_unix_epoch(expr: &str, sanitized: &str) -> Result<Option<TimeTarget>, JwtTermError> {
    let value: i64 = match expr.parse() {
        Ok(v) => v,
        Err(_) => return Ok(None),
    };

    if value < 0 {
        return Err(JwtTermError::InvalidTimeExpression {
            expression: sanitized.to_string(),
            reason: "Unix timestamps must be non-negative".to_string(),
        });
    }

    let timestamp =
        DateTime::from_timestamp(value, 0).ok_or_else(|| JwtTermError::InvalidTimeExpression {
            expression: sanitized.to_string(),
            reason: "Unix timestamp out of representable range".to_string(),
        })?;

    Ok(Some(TimeTarget {
        timestamp,
        expression: sanitized.to_string(),
    }))
}

/// Extract a numeric timestamp claim from the payload.
///
/// Supports both integer and floating-point JSON numbers (JWT NumericDate
/// values may be encoded as floats by some implementations). Floating-point
/// values are truncated to whole seconds.
fn extract_timestamp_value(payload: &Value, claim: &str) -> Option<i64> {
    let value = payload.get(claim)?;

    if let Some(i) = value.as_i64() {
        return Some(i);
    }

    // Support NumericDate values encoded as floating-point seconds.
    if let Some(f) = value.as_f64()
        && f.is_finite()
    {
        #[allow(clippy::cast_possible_truncation)]
        let truncated = f.trunc();
        if truncated >= i64::MIN as f64 && truncated <= i64::MAX as f64 {
            return Some(truncated as i64);
        }
    }

    None
}

/// Sanitize a time expression for safe terminal display and error messages.
///
/// Replaces control characters (including ANSI escape sequences) with the
/// Unicode replacement character, consistent with `sanitize_kid` in JWKS.
fn sanitize_expression(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { '\u{FFFD}' } else { c })
        .collect()
}

/// Truncate a string for safe inclusion in error messages.
///
/// Sanitizes control characters before truncation.
fn truncate_for_display(s: &str) -> String {
    const MAX_DISPLAY: usize = 32;
    let clean = sanitize_expression(s);
    if clean.len() <= MAX_DISPLAY {
        return clean;
    }
    // Find a valid char boundary at or before MAX_DISPLAY
    let end = clean.floor_char_boundary(MAX_DISPLAY);
    format!("{}...", &clean[..end])
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeDelta as TD;
    use serde_json::json;

    // --- Relative expression parsing ---

    #[test]
    fn test_parse_relative_days() {
        let now = Utc::now();
        let result = parse_time_expression("+7d").unwrap();
        assert_eq!(result.expression, "+7d");
        // Should be approximately 7 days from the captured `now` (within 2 seconds tolerance)
        let expected = now + TD::days(7);
        let diff = (result.timestamp - expected).num_seconds().abs();
        assert!(diff < 2, "expected ~7d from now, diff was {diff}s");
    }

    #[test]
    fn test_parse_relative_negative_days() {
        let now = Utc::now();
        let result = parse_time_expression("-3d").unwrap();
        let expected = now - TD::days(3);
        let diff = (result.timestamp - expected).num_seconds().abs();
        assert!(diff < 2, "expected ~3d ago, diff was {diff}s");
    }

    #[test]
    fn test_parse_relative_hours() {
        let now = Utc::now();
        let result = parse_time_expression("+1h").unwrap();
        let expected = now + TD::hours(1);
        let diff = (result.timestamp - expected).num_seconds().abs();
        assert!(diff < 2);
    }

    #[test]
    fn test_parse_relative_minutes() {
        let now = Utc::now();
        let result = parse_time_expression("+30m").unwrap();
        let expected = now + TD::minutes(30);
        let diff = (result.timestamp - expected).num_seconds().abs();
        assert!(diff < 2);
    }

    #[test]
    fn test_parse_relative_seconds() {
        let now = Utc::now();
        let result = parse_time_expression("-5s").unwrap();
        let expected = now - TD::seconds(5);
        let diff = (result.timestamp - expected).num_seconds().abs();
        assert!(diff < 2);
    }

    #[test]
    fn test_parse_relative_years() {
        let now = Utc::now();
        let result = parse_time_expression("+1y").unwrap();
        let expected = now + TD::days(365);
        let diff = (result.timestamp - expected).num_seconds().abs();
        assert!(diff < 2);
    }

    #[test]
    fn test_parse_relative_zero() {
        let now = Utc::now();
        let result = parse_time_expression("+0d").unwrap();
        let diff = (result.timestamp - now).num_seconds().abs();
        assert!(diff < 2, "+0d should be approximately now");
    }

    #[test]
    fn test_parse_signed_digit_only_falls_through_to_epoch() {
        // "+1705312200" has a digit as last char, so try_parse_relative
        // returns Ok(None). It then falls through to try_parse_unix_epoch
        // where i64::parse accepts the leading "+".
        let result = parse_time_expression("+1705312200").unwrap();
        assert_eq!(result.timestamp.timestamp(), 1705312200);
    }

    #[test]
    fn test_parse_relative_unknown_unit() {
        let err = parse_time_expression("+7x").unwrap_err();
        assert!(matches!(
            err,
            JwtTermError::InvalidTimeExpression { reason, .. } if reason.contains("unknown unit")
        ));
    }

    #[test]
    fn test_parse_relative_missing_number() {
        let err = parse_time_expression("+d").unwrap_err();
        assert!(matches!(
            err,
            JwtTermError::InvalidTimeExpression { reason, .. } if reason.contains("missing numeric value")
        ));
    }

    #[test]
    fn test_parse_relative_invalid_number() {
        let err = parse_time_expression("+abcd").unwrap_err();
        assert!(matches!(
            err,
            JwtTermError::InvalidTimeExpression { reason, .. } if reason.contains("not a valid number")
        ));
    }

    #[test]
    fn test_parse_relative_overflow() {
        let err = parse_time_expression("+99999999999999d").unwrap_err();
        assert!(matches!(
            err,
            JwtTermError::InvalidTimeExpression { reason, .. }
                if reason.contains("overflow") || reason.contains("out of") || reason.contains("not a valid number")
        ));
    }

    // --- ISO 8601 parsing ---

    #[test]
    fn test_parse_iso8601_utc() {
        let result = parse_time_expression("2024-06-01T00:00:00Z").unwrap();
        assert_eq!(result.expression, "2024-06-01T00:00:00Z");
        assert_eq!(
            result.timestamp,
            "2024-06-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap()
        );
    }

    #[test]
    fn test_parse_iso8601_with_offset() {
        let result = parse_time_expression("2024-01-15T14:30:00+00:00").unwrap();
        assert_eq!(result.timestamp.timestamp(), 1705329000);
    }

    // --- Unix epoch parsing ---

    #[test]
    fn test_parse_unix_epoch() {
        let result = parse_time_expression("1705312200").unwrap();
        assert_eq!(result.timestamp.timestamp(), 1705312200);
        assert_eq!(result.expression, "1705312200");
    }

    #[test]
    fn test_parse_unix_epoch_zero() {
        let result = parse_time_expression("0").unwrap();
        assert_eq!(result.timestamp.timestamp(), 0);
    }

    #[test]
    fn test_parse_unix_epoch_negative_rejected() {
        let err = parse_time_expression("-1705312200").unwrap_err();
        // The digit-unit check in try_parse_relative lets this fall through
        // to try_parse_unix_epoch, which gives a clear error message.
        assert!(matches!(
            err,
            JwtTermError::InvalidTimeExpression { reason, .. }
                if reason.contains("non-negative")
        ));
    }

    // --- Error cases ---

    #[test]
    fn test_parse_empty_expression() {
        let err = parse_time_expression("").unwrap_err();
        assert!(matches!(
            err,
            JwtTermError::InvalidTimeExpression { reason, .. } if reason.contains("empty")
        ));
    }

    #[test]
    fn test_parse_whitespace_only() {
        let err = parse_time_expression("   ").unwrap_err();
        assert!(matches!(
            err,
            JwtTermError::InvalidTimeExpression { reason, .. } if reason.contains("empty")
        ));
    }

    #[test]
    fn test_parse_unrecognized_format() {
        let err = parse_time_expression("tomorrow").unwrap_err();
        assert!(matches!(
            err,
            JwtTermError::InvalidTimeExpression { reason, .. }
                if reason.contains("expected relative expression")
        ));
    }

    #[test]
    fn test_parse_expression_too_long() {
        let long_expr = "a".repeat(200);
        let err = parse_time_expression(&long_expr).unwrap_err();
        assert!(matches!(
            err,
            JwtTermError::InvalidTimeExpression { reason, .. } if reason.contains("too long")
        ));
    }

    #[test]
    fn test_parse_trims_whitespace() {
        let result = parse_time_expression("  1705312200  ").unwrap();
        assert_eq!(result.timestamp.timestamp(), 1705312200);
    }

    // --- Temporal claim evaluation ---

    #[test]
    fn test_evaluate_expired_at_target() {
        let target = TimeTarget {
            timestamp: DateTime::from_timestamp(2000000000, 0).unwrap(),
            expression: "2000000000".to_string(),
        };
        let payload = json!({"exp": 1900000000});
        let result = evaluate_temporal_claims(&payload, &target);
        assert!(matches!(result.exp_status, ClaimStatus::Expired { .. }));
    }

    #[test]
    fn test_evaluate_valid_at_target() {
        let target = TimeTarget {
            timestamp: DateTime::from_timestamp(1800000000, 0).unwrap(),
            expression: "1800000000".to_string(),
        };
        let payload = json!({"exp": 1900000000});
        let result = evaluate_temporal_claims(&payload, &target);
        assert_eq!(result.exp_status, ClaimStatus::Valid);
    }

    #[test]
    fn test_evaluate_not_yet_valid_at_target() {
        let target = TimeTarget {
            timestamp: DateTime::from_timestamp(1700000000, 0).unwrap(),
            expression: "1700000000".to_string(),
        };
        let payload = json!({"nbf": 1800000000});
        let result = evaluate_temporal_claims(&payload, &target);
        assert!(matches!(result.nbf_status, ClaimStatus::NotYetValid { .. }));
    }

    #[test]
    fn test_evaluate_nbf_valid_at_target() {
        let target = TimeTarget {
            timestamp: DateTime::from_timestamp(1900000000, 0).unwrap(),
            expression: "1900000000".to_string(),
        };
        let payload = json!({"nbf": 1800000000});
        let result = evaluate_temporal_claims(&payload, &target);
        assert_eq!(result.nbf_status, ClaimStatus::Valid);
    }

    #[test]
    fn test_evaluate_absent_claims() {
        let target = TimeTarget {
            timestamp: DateTime::from_timestamp(1700000000, 0).unwrap(),
            expression: "1700000000".to_string(),
        };
        let payload = json!({"sub": "1234"});
        let result = evaluate_temporal_claims(&payload, &target);
        assert_eq!(result.exp_status, ClaimStatus::Absent);
        assert_eq!(result.nbf_status, ClaimStatus::Absent);
    }

    #[test]
    fn test_evaluate_exp_exactly_at_boundary() {
        // When target == exp, token is considered expired (>= check)
        let target = TimeTarget {
            timestamp: DateTime::from_timestamp(1700000000, 0).unwrap(),
            expression: "1700000000".to_string(),
        };
        let payload = json!({"exp": 1700000000});
        let result = evaluate_temporal_claims(&payload, &target);
        assert!(matches!(result.exp_status, ClaimStatus::Expired { .. }));
    }

    #[test]
    fn test_evaluate_nbf_exactly_at_boundary() {
        // When target == nbf, token is considered valid (>= check)
        let target = TimeTarget {
            timestamp: DateTime::from_timestamp(1700000000, 0).unwrap(),
            expression: "1700000000".to_string(),
        };
        let payload = json!({"nbf": 1700000000});
        let result = evaluate_temporal_claims(&payload, &target);
        assert_eq!(result.nbf_status, ClaimStatus::Valid);
    }

    #[test]
    fn test_evaluate_preserves_raw_values() {
        let target = TimeTarget {
            timestamp: DateTime::from_timestamp(1700000000, 0).unwrap(),
            expression: "1700000000".to_string(),
        };
        let payload = json!({"exp": 1800000000, "nbf": 1600000000});
        let result = evaluate_temporal_claims(&payload, &target);
        assert_eq!(result.exp_value, Some(1800000000));
        assert_eq!(result.nbf_value, Some(1600000000));
    }

    #[test]
    fn test_evaluate_invalid_exp_timestamp() {
        let target = TimeTarget {
            timestamp: DateTime::from_timestamp(1700000000, 0).unwrap(),
            expression: "1700000000".to_string(),
        };
        // i64::MAX is outside the representable DateTime range
        let payload = json!({"exp": i64::MAX});
        let result = evaluate_temporal_claims(&payload, &target);
        assert_eq!(result.exp_status, ClaimStatus::Invalid);
        assert_eq!(result.exp_value, Some(i64::MAX));
    }

    #[test]
    fn test_evaluate_invalid_nbf_timestamp() {
        let target = TimeTarget {
            timestamp: DateTime::from_timestamp(1700000000, 0).unwrap(),
            expression: "1700000000".to_string(),
        };
        let payload = json!({"nbf": i64::MIN});
        let result = evaluate_temporal_claims(&payload, &target);
        assert_eq!(result.nbf_status, ClaimStatus::Invalid);
        assert_eq!(result.nbf_value, Some(i64::MIN));
    }

    #[test]
    fn test_evaluate_both_claims_present() {
        let target = TimeTarget {
            timestamp: DateTime::from_timestamp(1750000000, 0).unwrap(),
            expression: "1750000000".to_string(),
        };
        let payload = json!({"exp": 1800000000, "nbf": 1700000000});
        let result = evaluate_temporal_claims(&payload, &target);
        assert_eq!(result.exp_status, ClaimStatus::Valid);
        assert_eq!(result.nbf_status, ClaimStatus::Valid);
    }

    // --- Double-signed relative expressions ---

    #[test]
    fn test_parse_relative_double_negative_rejected() {
        let err = parse_time_expression("--1h").unwrap_err();
        assert!(matches!(
            err,
            JwtTermError::InvalidTimeExpression { reason, .. }
                if reason.contains("not a valid number")
        ));
    }

    #[test]
    fn test_parse_relative_plus_minus_rejected() {
        let err = parse_time_expression("+-1h").unwrap_err();
        assert!(matches!(
            err,
            JwtTermError::InvalidTimeExpression { reason, .. }
                if reason.contains("not a valid number")
        ));
    }

    // --- Floating-point timestamp extraction ---

    #[test]
    fn test_extract_timestamp_value_float() {
        let payload = json!({"exp": 1700000000.75});
        let value = extract_timestamp_value(&payload, "exp");
        // Float is truncated to whole seconds
        assert_eq!(value, Some(1700000000));
    }

    #[test]
    fn test_extract_timestamp_value_float_negative() {
        let payload = json!({"exp": -1.5});
        let value = extract_timestamp_value(&payload, "exp");
        assert_eq!(value, Some(-1));
    }

    // --- Non-numeric claim type detection ---

    #[test]
    fn test_evaluate_string_exp_is_invalid_not_absent() {
        let target = TimeTarget {
            timestamp: DateTime::from_timestamp(1700000000, 0).unwrap(),
            expression: "1700000000".to_string(),
        };
        let payload = json!({"exp": "not-a-number"});
        let result = evaluate_temporal_claims(&payload, &target);
        assert_eq!(result.exp_status, ClaimStatus::Invalid);
        assert_eq!(result.exp_value, None);
    }

    #[test]
    fn test_evaluate_boolean_nbf_is_invalid_not_absent() {
        let target = TimeTarget {
            timestamp: DateTime::from_timestamp(1700000000, 0).unwrap(),
            expression: "1700000000".to_string(),
        };
        let payload = json!({"nbf": true});
        let result = evaluate_temporal_claims(&payload, &target);
        assert_eq!(result.nbf_status, ClaimStatus::Invalid);
        assert_eq!(result.nbf_value, None);
    }

    #[test]
    fn test_evaluate_float_exp_is_valid() {
        let target = TimeTarget {
            timestamp: DateTime::from_timestamp(1600000000, 0).unwrap(),
            expression: "1600000000".to_string(),
        };
        // Float exp should be truncated and treated as a valid timestamp
        let payload = json!({"exp": 1700000000.5});
        let result = evaluate_temporal_claims(&payload, &target);
        assert_eq!(result.exp_status, ClaimStatus::Valid);
        assert_eq!(result.exp_value, Some(1700000000));
    }

    // --- Expression sanitization ---

    #[test]
    fn test_sanitize_expression_replaces_control_chars() {
        let input = "+7d\x1b[31m\x00injected";
        let result = sanitize_expression(input);
        // \x1b (ESC) and \x00 (NUL) are control chars → replaced with U+FFFD
        // '[', '3', '1', 'm' are printable → preserved
        assert_eq!(result, "+7d\u{FFFD}[31m\u{FFFD}injected");
        // Confirm no control characters remain
        assert!(!result.chars().any(|c| c.is_control()));
    }

    #[test]
    fn test_sanitize_expression_preserves_normal_input() {
        let input = "+7d";
        assert_eq!(sanitize_expression(input), "+7d");
    }

    #[test]
    fn test_expression_with_ansi_escape_is_sanitized_in_error() {
        let input = "+7\x1b[31mx";
        let err = parse_time_expression(input).unwrap_err();
        match err {
            JwtTermError::InvalidTimeExpression { expression, .. } => {
                // The ANSI escape should be replaced, not passed through
                assert!(!expression.chars().any(|c| c.is_control()));
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn test_whitespace_only_error_uses_trimmed_expression() {
        let err = parse_time_expression("   ").unwrap_err();
        match err {
            JwtTermError::InvalidTimeExpression { expression, .. } => {
                // Should use trimmed (empty) string, not raw whitespace
                assert_eq!(expression, "");
            }
            other => panic!("unexpected error: {other}"),
        }
    }
}
