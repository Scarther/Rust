//! Output formatting and writing utilities

use anyhow::Result;
use serde::Serialize;
use std::fs::File;
use std::io::{self, Write};
use std::path::Path;

/// Supported output formats
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum OutputFormat {
    /// Human-readable text
    Text,
    /// JSON format
    Json,
    /// Pretty-printed JSON
    JsonPretty,
    /// CSV format
    Csv,
    /// Markdown table
    Markdown,
}

/// Write output in the specified format
pub fn write_output(
    data: &serde_json::Value,
    format: OutputFormat,
    output_path: Option<&Path>,
) -> Result<()> {
    let formatted = format_output(data, format)?;

    match output_path {
        Some(path) => {
            let mut file = File::create(path)?;
            file.write_all(formatted.as_bytes())?;
        }
        None => {
            io::stdout().write_all(formatted.as_bytes())?;
        }
    }

    Ok(())
}

/// Format data according to the specified format
pub fn format_output(data: &serde_json::Value, format: OutputFormat) -> Result<String> {
    match format {
        OutputFormat::Text => format_text(data),
        OutputFormat::Json => Ok(serde_json::to_string(data)?),
        OutputFormat::JsonPretty => Ok(serde_json::to_string_pretty(data)?),
        OutputFormat::Csv => format_csv(data),
        OutputFormat::Markdown => format_markdown(data),
    }
}

/// Format as human-readable text
fn format_text(data: &serde_json::Value) -> Result<String> {
    let mut output = String::new();

    fn format_value(value: &serde_json::Value, indent: usize) -> String {
        let prefix = "  ".repeat(indent);

        match value {
            serde_json::Value::Null => format!("{}null\n", prefix),
            serde_json::Value::Bool(b) => format!("{}{}\n", prefix, b),
            serde_json::Value::Number(n) => format!("{}{}\n", prefix, n),
            serde_json::Value::String(s) => format!("{}{}\n", prefix, s),
            serde_json::Value::Array(arr) => {
                let mut result = String::new();
                for (i, item) in arr.iter().enumerate() {
                    result.push_str(&format!("{}[{}]:\n", prefix, i));
                    result.push_str(&format_value(item, indent + 1));
                }
                result
            }
            serde_json::Value::Object(obj) => {
                let mut result = String::new();
                for (key, value) in obj {
                    result.push_str(&format!("{}{}: ", prefix, key));
                    if value.is_object() || value.is_array() {
                        result.push('\n');
                        result.push_str(&format_value(value, indent + 1));
                    } else {
                        result.push_str(&format_value(value, 0).trim_start().to_string());
                    }
                }
                result
            }
        }
    }

    output.push_str(&format_value(data, 0));
    Ok(output)
}

/// Format as CSV
fn format_csv(data: &serde_json::Value) -> Result<String> {
    let mut output = String::new();

    // Handle array of objects
    if let Some(arr) = data.as_array() {
        if let Some(first) = arr.first() {
            if let Some(obj) = first.as_object() {
                // Write header
                let headers: Vec<&str> = obj.keys().map(|s| s.as_str()).collect();
                output.push_str(&headers.join(","));
                output.push('\n');

                // Write rows
                for item in arr {
                    if let Some(item_obj) = item.as_object() {
                        let values: Vec<String> = headers
                            .iter()
                            .map(|h| {
                                item_obj
                                    .get(*h)
                                    .map(|v| csv_escape(v))
                                    .unwrap_or_default()
                            })
                            .collect();
                        output.push_str(&values.join(","));
                        output.push('\n');
                    }
                }
            }
        }
    } else if let Some(obj) = data.as_object() {
        // Single object - write as key,value pairs
        output.push_str("key,value\n");
        for (key, value) in obj {
            output.push_str(&format!("{},{}\n", key, csv_escape(value)));
        }
    }

    Ok(output)
}

/// Escape a value for CSV
fn csv_escape(value: &serde_json::Value) -> String {
    let s = match value {
        serde_json::Value::Null => "".to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => s.clone(),
        _ => serde_json::to_string(value).unwrap_or_default(),
    };

    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s
    }
}

/// Format as Markdown table
fn format_markdown(data: &serde_json::Value) -> Result<String> {
    let mut output = String::new();

    if let Some(arr) = data.as_array() {
        if let Some(first) = arr.first() {
            if let Some(obj) = first.as_object() {
                let headers: Vec<&str> = obj.keys().map(|s| s.as_str()).collect();

                // Header row
                output.push_str("| ");
                output.push_str(&headers.join(" | "));
                output.push_str(" |\n");

                // Separator
                output.push_str("|");
                for _ in &headers {
                    output.push_str("---|");
                }
                output.push('\n');

                // Data rows
                for item in arr {
                    if let Some(item_obj) = item.as_object() {
                        output.push_str("| ");
                        let values: Vec<String> = headers
                            .iter()
                            .map(|h| {
                                item_obj
                                    .get(*h)
                                    .map(|v| md_escape(v))
                                    .unwrap_or_default()
                            })
                            .collect();
                        output.push_str(&values.join(" | "));
                        output.push_str(" |\n");
                    }
                }
            }
        }
    } else if let Some(obj) = data.as_object() {
        output.push_str("| Key | Value |\n");
        output.push_str("|---|---|\n");
        for (key, value) in obj {
            output.push_str(&format!("| {} | {} |\n", key, md_escape(value)));
        }
    }

    Ok(output)
}

/// Escape a value for Markdown
fn md_escape(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => "".to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => s.replace('|', "\\|"),
        _ => serde_json::to_string(value)
            .unwrap_or_default()
            .replace('|', "\\|"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_format() {
        let data = serde_json::json!({"key": "value"});
        let output = format_output(&data, OutputFormat::Json).unwrap();
        assert!(output.contains("key"));
        assert!(output.contains("value"));
    }

    #[test]
    fn test_csv_format() {
        let data = serde_json::json!([
            {"name": "Alice", "age": 30},
            {"name": "Bob", "age": 25}
        ]);
        let output = format_output(&data, OutputFormat::Csv).unwrap();
        assert!(output.contains("name,age") || output.contains("age,name"));
        assert!(output.contains("Alice"));
    }

    #[test]
    fn test_markdown_format() {
        let data = serde_json::json!([
            {"host": "192.168.1.1", "port": 80}
        ]);
        let output = format_output(&data, OutputFormat::Markdown).unwrap();
        assert!(output.contains("|"));
        assert!(output.contains("192.168.1.1"));
    }
}
