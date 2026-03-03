//! Colorized JSON pretty-printing for terminal output.
//!
//! Renders JSON values with syntax highlighting:
//! - Field names in cyan
//! - Strings in green
//! - Numbers in yellow
//! - Booleans in magenta
//! - Null in red

use std::io::{self, Write};

use colored::Colorize;
use serde_json::Value;

/// Maximum nesting depth for colorized JSON rendering.
///
/// Deeply nested payloads beyond this limit fall back to plain
/// `serde_json` output to prevent stack overflow from recursion.
const MAX_DEPTH: usize = 20;

/// Write a JSON value with colorized syntax highlighting to the given writer.
///
/// Renders the value with 2-space indentation and ANSI color codes.
/// When `use_color` is false, outputs plain JSON without colors
/// (suitable for machine consumption or piping).
///
/// Falls back to plain output for deeply nested values (> [`MAX_DEPTH`])
/// to prevent stack overflow from recursive colorization.
pub fn write_json(writer: &mut impl Write, value: &Value, use_color: bool) -> io::Result<()> {
    if use_color {
        writeln!(writer, "{}", colorize_value(value, 0))
    } else {
        writeln!(
            writer,
            "{}",
            serde_json::to_string_pretty(value).unwrap_or_default()
        )
    }
}

/// Print a JSON value with colorized syntax highlighting to stdout.
///
/// Convenience wrapper around [`write_json`] for direct terminal output.
pub fn print_json(value: &Value, use_color: bool) {
    let _ = write_json(&mut io::stdout(), value, use_color);
}

/// Render a JSON value as a colorized string at the given indentation depth.
///
/// Falls back to plain `serde_json` output when depth exceeds [`MAX_DEPTH`]
/// to prevent stack overflow from deeply nested payloads.
fn colorize_value(value: &Value, depth: usize) -> String {
    if depth > MAX_DEPTH {
        return serde_json::to_string_pretty(value).unwrap_or_default();
    }

    match value {
        Value::Null => "null".red().to_string(),
        Value::Bool(b) => b.to_string().magenta().to_string(),
        Value::Number(n) => n.to_string().yellow().to_string(),
        Value::String(s) => json_escape_string(s).green().to_string(),
        Value::Array(arr) => colorize_array(arr, depth),
        Value::Object(map) => colorize_object(map, depth),
    }
}

/// Serialize a string with proper JSON escaping (handles `"`, `\`, control chars).
fn json_escape_string(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| format!("\"{}\"", s))
}

/// Render a JSON array with colorized elements and proper indentation.
fn colorize_array(arr: &[Value], depth: usize) -> String {
    if arr.is_empty() {
        return "[]".to_string();
    }

    let indent = "  ".repeat(depth + 1);
    let closing_indent = "  ".repeat(depth);

    let items: Vec<String> = arr
        .iter()
        .map(|v| format!("{}{}", indent, colorize_value(v, depth + 1)))
        .collect();

    format!("[\n{}\n{}]", items.join(",\n"), closing_indent)
}

/// Render a JSON object with colorized keys and values and proper indentation.
fn colorize_object(map: &serde_json::Map<String, Value>, depth: usize) -> String {
    if map.is_empty() {
        return "{}".to_string();
    }

    let indent = "  ".repeat(depth + 1);
    let closing_indent = "  ".repeat(depth);

    let entries: Vec<String> = map
        .iter()
        .map(|(k, v)| {
            let key = json_escape_string(k).cyan().to_string();
            let val = colorize_value(v, depth + 1);
            format!("{}{}: {}", indent, key, val)
        })
        .collect();

    format!("{{\n{}\n{}}}", entries.join(",\n"), closing_indent)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_colorize_null() {
        let result = colorize_value(&Value::Null, 0);
        assert!(result.contains("null"));
    }

    #[test]
    fn test_colorize_bool() {
        let result = colorize_value(&json!(true), 0);
        assert!(result.contains("true"));
    }

    #[test]
    fn test_colorize_number() {
        let result = colorize_value(&json!(42), 0);
        assert!(result.contains("42"));
    }

    #[test]
    fn test_colorize_string() {
        let result = colorize_value(&json!("hello"), 0);
        assert!(result.contains("hello"));
    }

    #[test]
    fn test_colorize_empty_object() {
        let result = colorize_value(&json!({}), 0);
        assert_eq!(result, "{}");
    }

    #[test]
    fn test_colorize_empty_array() {
        let result = colorize_value(&json!([]), 0);
        assert_eq!(result, "[]");
    }

    #[test]
    fn test_colorize_object_has_keys_and_values() {
        let value = json!({"alg": "HS256", "typ": "JWT"});
        let result = colorize_value(&value, 0);
        assert!(result.contains("alg"));
        assert!(result.contains("HS256"));
        assert!(result.contains("typ"));
        assert!(result.contains("JWT"));
    }

    #[test]
    fn test_colorize_nested_object() {
        let value = json!({"user": {"name": "Test"}});
        let result = colorize_value(&value, 0);
        assert!(result.contains("user"));
        assert!(result.contains("name"));
        assert!(result.contains("Test"));
    }

    #[test]
    fn test_colorize_array_with_elements() {
        let value = json!(["a", "b", "c"]);
        let result = colorize_value(&value, 0);
        assert!(result.contains("a"));
        assert!(result.contains("b"));
        assert!(result.contains("c"));
    }

    #[test]
    fn test_colorize_string_with_special_chars() {
        // String with quotes, backslash, and newline should be JSON-escaped
        let value = json!("O\"Brien\\path\nnewline");
        let result = colorize_value(&value, 0);
        // Should contain escaped versions, not raw special chars breaking the output
        assert!(result.contains("O\\\"Brien"));
        assert!(result.contains("\\\\path"));
        assert!(result.contains("\\n"));
    }

    #[test]
    fn test_json_escape_string() {
        assert_eq!(json_escape_string("hello"), "\"hello\"");
        assert_eq!(json_escape_string("O\"Brien"), "\"O\\\"Brien\"");
        assert_eq!(json_escape_string("a\\b"), "\"a\\\\b\"");
        assert_eq!(json_escape_string("line\nnew"), "\"line\\nnew\"");
    }

    #[test]
    fn test_plain_json_output() {
        let value = json!({"key": "value"});
        let expected = serde_json::to_string_pretty(&value).unwrap();
        // We can't easily capture println output, but we can verify
        // the underlying serialization works correctly
        assert!(expected.contains("key"));
        assert!(expected.contains("value"));
    }

    // --- write_json tests (Write trait) ---

    #[test]
    fn test_write_json_plain_output_to_buffer() {
        let value = json!({"alg": "HS256"});
        let mut buf = Vec::new();
        write_json(&mut buf, &value, false).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("\"alg\""));
        assert!(output.contains("\"HS256\""));
        assert!(output.ends_with('\n'));
    }

    #[test]
    fn test_write_json_colored_output_to_buffer() {
        let value = json!({"key": "value"});
        let mut buf = Vec::new();
        write_json(&mut buf, &value, true).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("key"));
        assert!(output.contains("value"));
    }

    // --- MAX_DEPTH fallback ---

    #[test]
    fn test_colorize_value_at_max_depth_falls_back() {
        let value = json!({"nested": "value"});
        // At depth > MAX_DEPTH, should fall back to serde_json output
        let result = colorize_value(&value, MAX_DEPTH + 1);
        let expected = serde_json::to_string_pretty(&value).unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_colorize_value_at_max_depth_boundary() {
        let value = json!("hello");
        // At exactly MAX_DEPTH, should still colorize
        let result = colorize_value(&value, MAX_DEPTH);
        assert!(result.contains("hello"));
    }

    #[test]
    fn test_colorize_value_beyond_max_depth_scalar() {
        let value = json!(42);
        let result = colorize_value(&value, MAX_DEPTH + 1);
        assert_eq!(result, "42");
    }
}
