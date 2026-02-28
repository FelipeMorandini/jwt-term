//! Time-travel debugging for JWT temporal claims.
//!
//! Parses time expressions (relative like "+7d" or absolute like ISO 8601)
//! and evaluates `exp` and `nbf` claims against a simulated timestamp.

use chrono::{DateTime, Utc};

use crate::error::JwtTermError;

/// A parsed time target for time-travel evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeTarget {
    /// The resolved absolute timestamp.
    pub timestamp: DateTime<Utc>,
    /// The original expression provided by the user.
    pub expression: String,
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
/// Returns an error if the expression doesn't match any known format.
pub fn parse_time_expression(_expression: &str) -> Result<TimeTarget, JwtTermError> {
    Err(JwtTermError::NotImplemented {
        command: "parse_time_expression".to_string(),
    })
}
