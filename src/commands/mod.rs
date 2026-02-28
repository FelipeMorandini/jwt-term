//! Command handlers for each CLI subcommand.
//!
//! Each subcommand is implemented in its own module and exposes
//! a single `execute` function that receives the parsed arguments.
//!
//! The shared [`resolve_token`] function handles token input from
//! CLI arguments, environment variables, or stdin with security
//! validation built in.

use std::io::{self, IsTerminal, Read};

use crate::error::JwtTermError;

pub mod decode;
pub mod verify;

/// Maximum token size in bytes (16 KB).
const MAX_TOKEN_SIZE: usize = 16_384;

/// Maximum environment variable name length.
const MAX_ENV_VAR_NAME_LEN: usize = 256;

/// Resolve a JWT token string from the available input sources.
///
/// Checks sources in priority order:
/// 1. Direct CLI argument (`token_arg`)
/// 2. Environment variable (`token_env` specifies the var name)
/// 3. Stdin (only if stdin is not a TTY, i.e., piped input)
///
/// Applies security validation: token size limit (16 KB) and
/// environment variable name validation.
///
/// # Errors
///
/// Returns an error if no token is available from any source,
/// if the token exceeds the size limit, or if the env var name
/// is invalid.
pub fn resolve_token(
    token_arg: Option<&str>,
    token_env: Option<&str>,
) -> Result<String, JwtTermError> {
    if let Some(token) = token_arg {
        let trimmed = token.trim();
        if trimmed.is_empty() {
            return Err(JwtTermError::NoTokenProvided);
        }
        return validate_token_size(trimmed);
    }

    if let Some(var_name) = token_env {
        validate_env_var_name(var_name)?;
        let token = std::env::var(var_name).map_err(|e| match e {
            std::env::VarError::NotPresent => JwtTermError::EnvVarNotFound {
                name: var_name.to_string(),
            },
            std::env::VarError::NotUnicode(_) => JwtTermError::EnvVarNotUnicode {
                name: var_name.to_string(),
            },
        })?;
        let trimmed = token.trim().to_string();
        if trimmed.is_empty() {
            return Err(JwtTermError::NoTokenProvided);
        }
        return validate_token_size(&trimmed);
    }

    read_token_from_stdin()
}

/// Read a token from stdin with bounded input.
///
/// Only attempts to read if stdin is not a TTY (i.e., input is piped).
/// Limits the read to `MAX_TOKEN_SIZE + 1` bytes to prevent resource
/// exhaustion from unbounded input.
fn read_token_from_stdin() -> Result<String, JwtTermError> {
    if io::stdin().is_terminal() {
        return Err(JwtTermError::NoTokenProvided);
    }

    let mut buffer = String::new();
    io::stdin()
        .take(MAX_TOKEN_SIZE as u64 + 1)
        .read_to_string(&mut buffer)
        .map_err(|e| JwtTermError::StdinReadError {
            reason: sanitize_io_error(&e),
        })?;

    let token = buffer.trim().to_string();
    if token.is_empty() {
        return Err(JwtTermError::NoTokenProvided);
    }

    validate_token_size(&token)
}

/// Validate that a token does not exceed the maximum size.
fn validate_token_size(token: &str) -> Result<String, JwtTermError> {
    if token.len() > MAX_TOKEN_SIZE {
        return Err(JwtTermError::TokenTooLarge {
            size: token.len(),
            max_size: MAX_TOKEN_SIZE,
        });
    }
    Ok(token.to_string())
}

/// Sanitize an IO error into a user-friendly reason string.
///
/// Maps common `io::ErrorKind` values to generic messages rather
/// than forwarding raw OS error strings that may leak system details.
fn sanitize_io_error(err: &io::Error) -> String {
    match err.kind() {
        io::ErrorKind::InvalidData => "stream did not contain valid UTF-8".to_string(),
        io::ErrorKind::BrokenPipe => "input stream was closed unexpectedly".to_string(),
        io::ErrorKind::TimedOut => "read timed out".to_string(),
        io::ErrorKind::UnexpectedEof => "unexpected end of input".to_string(),
        _ => format!("read failed ({})", err.kind()),
    }
}

/// Validate an environment variable name for safety.
///
/// Rejects empty names, names containing `=` (invalid on most platforms),
/// and excessively long names (> 256 characters).
fn validate_env_var_name(name: &str) -> Result<(), JwtTermError> {
    if name.is_empty() {
        return Err(JwtTermError::InvalidEnvVarName {
            name: name.to_string(),
            reason: "variable name cannot be empty".to_string(),
        });
    }

    if name.contains('=') {
        return Err(JwtTermError::InvalidEnvVarName {
            name: name.to_string(),
            reason: "variable name cannot contain '='".to_string(),
        });
    }

    if name.contains('\0') {
        return Err(JwtTermError::InvalidEnvVarName {
            name: name.to_string(),
            reason: "variable name cannot contain null bytes".to_string(),
        });
    }

    if name.len() > MAX_ENV_VAR_NAME_LEN {
        return Err(JwtTermError::InvalidEnvVarName {
            name: name.to_string(),
            reason: format!(
                "variable name too long ({} chars, max {})",
                name.len(),
                MAX_ENV_VAR_NAME_LEN
            ),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Token size validation ---

    #[test]
    fn test_validate_token_size_within_limit() {
        let token = "a".repeat(MAX_TOKEN_SIZE);
        assert!(validate_token_size(&token).is_ok());
    }

    #[test]
    fn test_validate_token_size_exceeds_limit() {
        let token = "a".repeat(MAX_TOKEN_SIZE + 1);
        let err = validate_token_size(&token).unwrap_err();
        assert!(matches!(err, JwtTermError::TokenTooLarge { .. }));
    }

    // --- Env var name validation ---

    #[test]
    fn test_validate_env_var_name_valid() {
        assert!(validate_env_var_name("JWT_TOKEN").is_ok());
    }

    #[test]
    fn test_validate_env_var_name_empty() {
        let err = validate_env_var_name("").unwrap_err();
        assert!(matches!(
            err,
            JwtTermError::InvalidEnvVarName { reason, .. } if reason.contains("empty")
        ));
    }

    #[test]
    fn test_validate_env_var_name_contains_equals() {
        let err = validate_env_var_name("BAD=VAR").unwrap_err();
        assert!(matches!(
            err,
            JwtTermError::InvalidEnvVarName { reason, .. } if reason.contains("'='")
        ));
    }

    #[test]
    fn test_validate_env_var_name_contains_null_byte() {
        let err = validate_env_var_name("VAR\0NAME").unwrap_err();
        assert!(matches!(
            err,
            JwtTermError::InvalidEnvVarName { reason, .. } if reason.contains("null")
        ));
    }

    #[test]
    fn test_validate_env_var_name_too_long() {
        let name = "A".repeat(MAX_ENV_VAR_NAME_LEN + 1);
        let err = validate_env_var_name(&name).unwrap_err();
        assert!(matches!(
            err,
            JwtTermError::InvalidEnvVarName { reason, .. } if reason.contains("too long")
        ));
    }

    // --- Token resolution ---

    #[test]
    fn test_resolve_token_from_arg() {
        let result = resolve_token(Some("my.jwt.token"), None);
        assert_eq!(result.unwrap(), "my.jwt.token");
    }

    #[test]
    fn test_resolve_token_arg_takes_priority_over_env() {
        // When a CLI arg is provided, it should be used regardless of
        // whether a token_env name is also provided.
        let result = resolve_token(Some("arg-token"), Some("SOME_VAR"));
        assert_eq!(result.unwrap(), "arg-token");
    }

    #[test]
    fn test_resolve_token_env_not_set() {
        let err = resolve_token(None, Some("NONEXISTENT_VAR_12345")).unwrap_err();
        assert!(matches!(err, JwtTermError::EnvVarNotFound { .. }));
    }

    #[test]
    fn test_resolve_token_empty_arg() {
        let err = resolve_token(Some(""), None).unwrap_err();
        assert!(matches!(err, JwtTermError::NoTokenProvided));
    }

    #[test]
    fn test_resolve_token_whitespace_arg() {
        let err = resolve_token(Some("   "), None).unwrap_err();
        assert!(matches!(err, JwtTermError::NoTokenProvided));
    }

    #[test]
    fn test_resolve_token_trims_whitespace() {
        let result = resolve_token(Some("  my.jwt.token  "), None);
        assert_eq!(result.unwrap(), "my.jwt.token");
    }

    // NOTE: test_resolve_token_no_source_in_tty was removed because it calls
    // resolve_token(None, None) which may read from the process' real stdin,
    // making it environment-dependent and potentially blocking in non-TTY CI
    // harnesses. Stdin behavior is covered by integration tests in tests/cli_test.rs.

    // --- IO error sanitization ---

    #[test]
    fn test_sanitize_io_error_invalid_data() {
        let err = io::Error::new(io::ErrorKind::InvalidData, "bad utf-8");
        assert_eq!(
            sanitize_io_error(&err),
            "stream did not contain valid UTF-8"
        );
    }

    #[test]
    fn test_sanitize_io_error_broken_pipe() {
        let err = io::Error::new(io::ErrorKind::BrokenPipe, "pipe broke");
        assert_eq!(
            sanitize_io_error(&err),
            "input stream was closed unexpectedly"
        );
    }

    #[test]
    fn test_sanitize_io_error_timed_out() {
        let err = io::Error::new(io::ErrorKind::TimedOut, "deadline exceeded");
        assert_eq!(sanitize_io_error(&err), "read timed out");
    }

    #[test]
    fn test_sanitize_io_error_unexpected_eof() {
        let err = io::Error::new(io::ErrorKind::UnexpectedEof, "eof");
        assert_eq!(sanitize_io_error(&err), "unexpected end of input");
    }

    #[test]
    fn test_sanitize_io_error_other_kind() {
        let err = io::Error::new(io::ErrorKind::PermissionDenied, "no access");
        let result = sanitize_io_error(&err);
        assert!(result.starts_with("read failed ("));
        assert!(!result.contains("no access"));
    }
}
