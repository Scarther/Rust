//! # JSON Parsing Security Tool
//!
//! This module demonstrates JSON parsing and manipulation in Rust with
//! security considerations, including:
//! - Parsing JSON from files and strings
//! - Creating and modifying JSON structures
//! - Querying JSON with JSONPath
//! - Detecting sensitive data in JSON
//! - Validating JSON schemas
//!
//! ## Security Use Cases
//! - Analyzing API responses for sensitive data
//! - Parsing configuration files
//! - Extracting data from JSON logs
//! - Sanitizing JSON before transmission

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use colored::*;
use jsonpath_rust::JsonPathFinder;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::fs;
use std::io::{self, BufRead, Read};
use std::path::PathBuf;
use thiserror::Error;

// ============================================================================
// CUSTOM ERROR TYPES
// ============================================================================

/// Custom error types for JSON operations
#[derive(Error, Debug)]
pub enum JsonError {
    /// Error when JSON parsing fails
    #[error("JSON parse error: {0}")]
    ParseError(String),

    /// Error when JSONPath query fails
    #[error("JSONPath error: {0}")]
    PathError(String),

    /// Error when sensitive data is detected
    #[error("Sensitive data detected: {0}")]
    SensitiveData(String),

    /// Error when validation fails
    #[error("Validation error: {0}")]
    ValidationError(String),
}

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/// Represents analysis results for JSON content
#[derive(Debug, Serialize, Deserialize)]
pub struct JsonAnalysis {
    /// Total number of keys
    pub total_keys: usize,
    /// Maximum nesting depth
    pub max_depth: usize,
    /// Number of arrays
    pub array_count: usize,
    /// Number of objects
    pub object_count: usize,
    /// Number of strings
    pub string_count: usize,
    /// Number of numbers
    pub number_count: usize,
    /// Number of booleans
    pub boolean_count: usize,
    /// Number of null values
    pub null_count: usize,
    /// Potentially sensitive keys found
    pub sensitive_keys: Vec<String>,
    /// Size in bytes
    pub size_bytes: usize,
}

/// Represents a sensitive data finding
#[derive(Debug)]
pub struct SensitiveFinding {
    /// Path to the sensitive value
    pub path: String,
    /// Type of sensitive data
    pub data_type: String,
    /// Recommendation
    pub recommendation: String,
}

// ============================================================================
// CLI ARGUMENT STRUCTURES
// ============================================================================

/// JSON Parsing Tool - Security-focused JSON manipulation
///
/// This tool provides comprehensive JSON parsing with security analysis.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// The subcommand to execute
    #[command(subcommand)]
    command: Commands,

    /// Enable verbose output for debugging
    #[arg(short, long, global = true)]
    verbose: bool,
}

/// Available subcommands for JSON operations
#[derive(Subcommand, Debug)]
enum Commands {
    /// Parse and validate JSON
    Parse {
        /// JSON file to parse (or use stdin)
        #[arg(short, long)]
        file: Option<PathBuf>,

        /// JSON string to parse
        #[arg(short, long)]
        string: Option<String>,

        /// Pretty print output
        #[arg(short, long)]
        pretty: bool,

        /// Compact output (single line)
        #[arg(short, long)]
        compact: bool,
    },

    /// Query JSON using JSONPath
    Query {
        /// JSON file to query
        #[arg(short, long)]
        file: Option<PathBuf>,

        /// JSONPath expression (e.g., $.users[*].name)
        #[arg(short, long)]
        path: String,

        /// Output as JSON array
        #[arg(short, long)]
        json_output: bool,
    },

    /// Analyze JSON structure
    Analyze {
        /// JSON file to analyze
        #[arg(short, long)]
        file: Option<PathBuf>,

        /// Check for sensitive data
        #[arg(short, long)]
        sensitive: bool,
    },

    /// Create JSON from key-value pairs
    Create {
        /// Key-value pairs (format: key=value)
        #[arg(short, long)]
        pairs: Vec<String>,

        /// Nested key-value pairs (format: path.to.key=value)
        #[arg(short, long)]
        nested: Vec<String>,

        /// Output file (or stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Pretty print output
        #[arg(short, long)]
        pretty: bool,
    },

    /// Modify existing JSON
    Modify {
        /// JSON file to modify
        #[arg(short, long)]
        file: PathBuf,

        /// Set a value (format: path.to.key=value)
        #[arg(short, long)]
        set: Vec<String>,

        /// Delete a key (format: path.to.key)
        #[arg(short, long)]
        delete: Vec<String>,

        /// Output file (or stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Pretty print output
        #[arg(short, long)]
        pretty: bool,
    },

    /// Compare two JSON files
    Diff {
        /// First JSON file
        #[arg(short, long)]
        file1: PathBuf,

        /// Second JSON file
        #[arg(short, long)]
        file2: PathBuf,

        /// Show only differences
        #[arg(short, long)]
        only_diff: bool,
    },

    /// Sanitize JSON by removing sensitive fields
    Sanitize {
        /// JSON file to sanitize
        #[arg(short, long)]
        file: Option<PathBuf>,

        /// Additional fields to remove
        #[arg(short, long)]
        remove: Vec<String>,

        /// Mask values instead of removing
        #[arg(short, long)]
        mask: bool,

        /// Output file (or stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Merge multiple JSON files
    Merge {
        /// JSON files to merge
        #[arg(short, long, num_args = 1..)]
        files: Vec<PathBuf>,

        /// Deep merge (recursive)
        #[arg(short, long)]
        deep: bool,

        /// Output file (or stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

// ============================================================================
// SENSITIVE DATA PATTERNS
// ============================================================================

/// Patterns that indicate sensitive JSON keys
const SENSITIVE_KEY_PATTERNS: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "api-key",
    "auth",
    "authorization",
    "credential",
    "private",
    "private_key",
    "privatekey",
    "access_key",
    "accesskey",
    "secret_key",
    "secretkey",
    "session",
    "cookie",
    "jwt",
    "bearer",
    "ssn",
    "social_security",
    "credit_card",
    "creditcard",
    "card_number",
    "cvv",
    "pin",
    "bank_account",
    "routing_number",
];

/// Checks if a key name indicates sensitive data
fn is_sensitive_key(key: &str) -> bool {
    let lower = key.to_lowercase();
    SENSITIVE_KEY_PATTERNS.iter().any(|pattern| lower.contains(pattern))
}

// ============================================================================
// JSON PARSING FUNCTIONS
// ============================================================================

/// Reads JSON from a file or stdin
///
/// # Arguments
/// * `file` - Optional file path; if None, reads from stdin
///
/// # Returns
/// * `Result<Value>` - Parsed JSON value or error
fn read_json(file: Option<&PathBuf>) -> Result<Value> {
    let content = match file {
        Some(path) => {
            fs::read_to_string(path)
                .with_context(|| format!("Failed to read file: {:?}", path))?
        }
        None => {
            let mut buffer = String::new();
            io::stdin()
                .read_to_string(&mut buffer)
                .context("Failed to read from stdin")?;
            buffer
        }
    };

    serde_json::from_str(&content)
        .map_err(|e| JsonError::ParseError(e.to_string()).into())
}

/// Parses JSON from a string
///
/// # Arguments
/// * `json_str` - JSON string to parse
///
/// # Returns
/// * `Result<Value>` - Parsed JSON value or error
fn parse_json_string(json_str: &str) -> Result<Value> {
    serde_json::from_str(json_str)
        .map_err(|e| JsonError::ParseError(e.to_string()).into())
}

/// Formats JSON for output
///
/// # Arguments
/// * `value` - JSON value to format
/// * `pretty` - Whether to pretty print
///
/// # Returns
/// * `Result<String>` - Formatted JSON string
fn format_json(value: &Value, pretty: bool) -> Result<String> {
    if pretty {
        serde_json::to_string_pretty(value)
            .context("Failed to format JSON")
    } else {
        serde_json::to_string(value)
            .context("Failed to format JSON")
    }
}

// ============================================================================
// JSON ANALYSIS FUNCTIONS
// ============================================================================

/// Analyzes JSON structure recursively
///
/// # Arguments
/// * `value` - JSON value to analyze
/// * `current_depth` - Current recursion depth
/// * `path` - Current path in JSON
/// * `analysis` - Analysis results to update
/// * `sensitive_keys` - Accumulator for sensitive keys found
fn analyze_value(
    value: &Value,
    current_depth: usize,
    path: &str,
    analysis: &mut JsonAnalysis,
    sensitive_keys: &mut Vec<String>,
) {
    // Update max depth
    if current_depth > analysis.max_depth {
        analysis.max_depth = current_depth;
    }

    match value {
        Value::Object(map) => {
            analysis.object_count += 1;
            for (key, val) in map {
                analysis.total_keys += 1;

                // Check for sensitive keys
                if is_sensitive_key(key) {
                    let full_path = if path.is_empty() {
                        key.clone()
                    } else {
                        format!("{}.{}", path, key)
                    };
                    sensitive_keys.push(full_path.clone());
                }

                let new_path = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{}.{}", path, key)
                };

                analyze_value(val, current_depth + 1, &new_path, analysis, sensitive_keys);
            }
        }
        Value::Array(arr) => {
            analysis.array_count += 1;
            for (i, val) in arr.iter().enumerate() {
                let new_path = format!("{}[{}]", path, i);
                analyze_value(val, current_depth + 1, &new_path, analysis, sensitive_keys);
            }
        }
        Value::String(_) => analysis.string_count += 1,
        Value::Number(_) => analysis.number_count += 1,
        Value::Bool(_) => analysis.boolean_count += 1,
        Value::Null => analysis.null_count += 1,
    }
}

/// Performs full analysis of JSON content
///
/// # Arguments
/// * `value` - JSON value to analyze
///
/// # Returns
/// * `JsonAnalysis` - Analysis results
fn analyze_json(value: &Value) -> JsonAnalysis {
    let mut analysis = JsonAnalysis {
        total_keys: 0,
        max_depth: 0,
        array_count: 0,
        object_count: 0,
        string_count: 0,
        number_count: 0,
        boolean_count: 0,
        null_count: 0,
        sensitive_keys: Vec::new(),
        size_bytes: serde_json::to_string(value).map(|s| s.len()).unwrap_or(0),
    };

    let mut sensitive_keys = Vec::new();
    analyze_value(value, 0, "", &mut analysis, &mut sensitive_keys);
    analysis.sensitive_keys = sensitive_keys;

    analysis
}

// ============================================================================
// JSON QUERY FUNCTIONS
// ============================================================================

/// Queries JSON using JSONPath expression
///
/// # Arguments
/// * `value` - JSON value to query
/// * `path` - JSONPath expression
///
/// # Returns
/// * `Result<Vec<Value>>` - Matching values or error
fn query_jsonpath(value: &Value, path: &str) -> Result<Vec<Value>> {
    let finder = JsonPathFinder::new(Box::new(value.clone()), path)
        .map_err(|e| JsonError::PathError(e.to_string()))?;

    let results = finder.find_slice();
    Ok(results.into_iter().cloned().collect())
}

// ============================================================================
// JSON MODIFICATION FUNCTIONS
// ============================================================================

/// Sets a value at a given path in JSON
///
/// # Arguments
/// * `value` - JSON value to modify
/// * `path` - Dot-separated path (e.g., "user.name")
/// * `new_value` - Value to set
///
/// # Returns
/// * `Result<()>` - Success or error
fn set_value_at_path(value: &mut Value, path: &str, new_value: Value) -> Result<()> {
    let parts: Vec<&str> = path.split('.').collect();

    let mut current = value;
    for (i, part) in parts.iter().enumerate() {
        // Check for array index
        if let Some(idx_start) = part.find('[') {
            let key = &part[..idx_start];
            let idx_str = &part[idx_start + 1..part.len() - 1];
            let idx: usize = idx_str.parse().context("Invalid array index")?;

            // Navigate to the key first
            if !key.is_empty() {
                if !current.is_object() {
                    *current = json!({});
                }
                current = current
                    .as_object_mut()
                    .unwrap()
                    .entry(key.to_string())
                    .or_insert(json!([]));
            }

            // Navigate to array index
            if !current.is_array() {
                *current = json!([]);
            }
            let arr = current.as_array_mut().unwrap();
            while arr.len() <= idx {
                arr.push(Value::Null);
            }
            current = &mut arr[idx];
        } else {
            // Regular key navigation
            if !current.is_object() {
                *current = json!({});
            }

            // If this is the last part, set the value
            if i == parts.len() - 1 {
                current
                    .as_object_mut()
                    .unwrap()
                    .insert(part.to_string(), new_value.clone());
                return Ok(());
            }

            current = current
                .as_object_mut()
                .unwrap()
                .entry(part.to_string())
                .or_insert(json!({}));
        }
    }

    // If we reach here for a simple path, set the value
    *current = new_value;
    Ok(())
}

/// Deletes a value at a given path in JSON
///
/// # Arguments
/// * `value` - JSON value to modify
/// * `path` - Dot-separated path to delete
///
/// # Returns
/// * `Result<bool>` - Whether the key was found and deleted
fn delete_value_at_path(value: &mut Value, path: &str) -> Result<bool> {
    let parts: Vec<&str> = path.split('.').collect();

    if parts.is_empty() {
        return Ok(false);
    }

    // Navigate to parent
    let mut current = value;
    for part in &parts[..parts.len() - 1] {
        match current {
            Value::Object(map) => {
                if let Some(v) = map.get_mut(*part) {
                    current = v;
                } else {
                    return Ok(false);
                }
            }
            _ => return Ok(false),
        }
    }

    // Delete the final key
    let last_key = parts.last().unwrap();
    if let Value::Object(map) = current {
        Ok(map.remove(*last_key).is_some())
    } else {
        Ok(false)
    }
}

/// Parses a string value into appropriate JSON type
fn parse_value(value_str: &str) -> Value {
    // Try to parse as JSON first
    if let Ok(v) = serde_json::from_str(value_str) {
        return v;
    }

    // Try common types
    if value_str == "true" {
        return Value::Bool(true);
    }
    if value_str == "false" {
        return Value::Bool(false);
    }
    if value_str == "null" {
        return Value::Null;
    }
    if let Ok(n) = value_str.parse::<i64>() {
        return json!(n);
    }
    if let Ok(n) = value_str.parse::<f64>() {
        return json!(n);
    }

    // Default to string
    Value::String(value_str.to_string())
}

// ============================================================================
// JSON SANITIZATION FUNCTIONS
// ============================================================================

/// Sanitizes JSON by removing or masking sensitive fields
///
/// # Arguments
/// * `value` - JSON value to sanitize
/// * `additional_fields` - Additional field names to remove
/// * `mask_instead` - Whether to mask values instead of removing
///
/// # Returns
/// * `Value` - Sanitized JSON
fn sanitize_json(value: &Value, additional_fields: &[String], mask_instead: bool) -> Value {
    match value {
        Value::Object(map) => {
            let mut new_map = Map::new();
            for (key, val) in map {
                let is_sensitive = is_sensitive_key(key)
                    || additional_fields.iter().any(|f| key.to_lowercase() == f.to_lowercase());

                if is_sensitive {
                    if mask_instead {
                        new_map.insert(key.clone(), Value::String("***REDACTED***".to_string()));
                    }
                    // If not masking, simply don't include the key
                } else {
                    new_map.insert(key.clone(), sanitize_json(val, additional_fields, mask_instead));
                }
            }
            Value::Object(new_map)
        }
        Value::Array(arr) => {
            Value::Array(arr.iter().map(|v| sanitize_json(v, additional_fields, mask_instead)).collect())
        }
        _ => value.clone(),
    }
}

// ============================================================================
// JSON DIFF FUNCTIONS
// ============================================================================

/// Compares two JSON values and returns differences
///
/// # Arguments
/// * `value1` - First JSON value
/// * `value2` - Second JSON value
/// * `path` - Current path for reporting
///
/// # Returns
/// * `Vec<(String, String, String)>` - List of (path, value1, value2) differences
fn diff_json(value1: &Value, value2: &Value, path: &str) -> Vec<(String, String, String)> {
    let mut diffs = Vec::new();

    match (value1, value2) {
        (Value::Object(map1), Value::Object(map2)) => {
            // Check for keys in map1
            for (key, val1) in map1 {
                let new_path = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{}.{}", path, key)
                };

                if let Some(val2) = map2.get(key) {
                    diffs.extend(diff_json(val1, val2, &new_path));
                } else {
                    diffs.push((new_path, format!("{}", val1), "<missing>".to_string()));
                }
            }

            // Check for keys only in map2
            for (key, val2) in map2 {
                if !map1.contains_key(key) {
                    let new_path = if path.is_empty() {
                        key.clone()
                    } else {
                        format!("{}.{}", path, key)
                    };
                    diffs.push((new_path, "<missing>".to_string(), format!("{}", val2)));
                }
            }
        }
        (Value::Array(arr1), Value::Array(arr2)) => {
            let max_len = arr1.len().max(arr2.len());
            for i in 0..max_len {
                let new_path = format!("{}[{}]", path, i);
                match (arr1.get(i), arr2.get(i)) {
                    (Some(v1), Some(v2)) => diffs.extend(diff_json(v1, v2, &new_path)),
                    (Some(v1), None) => diffs.push((new_path, format!("{}", v1), "<missing>".to_string())),
                    (None, Some(v2)) => diffs.push((new_path, "<missing>".to_string(), format!("{}", v2))),
                    (None, None) => {}
                }
            }
        }
        _ => {
            if value1 != value2 {
                diffs.push((path.to_string(), format!("{}", value1), format!("{}", value2)));
            }
        }
    }

    diffs
}

// ============================================================================
// JSON MERGE FUNCTIONS
// ============================================================================

/// Merges two JSON values
///
/// # Arguments
/// * `base` - Base JSON value
/// * `overlay` - JSON value to merge on top
/// * `deep` - Whether to perform deep merge
///
/// # Returns
/// * `Value` - Merged JSON
fn merge_json(base: &Value, overlay: &Value, deep: bool) -> Value {
    match (base, overlay) {
        (Value::Object(base_map), Value::Object(overlay_map)) if deep => {
            let mut result = base_map.clone();
            for (key, val) in overlay_map {
                if let Some(base_val) = base_map.get(key) {
                    result.insert(key.clone(), merge_json(base_val, val, true));
                } else {
                    result.insert(key.clone(), val.clone());
                }
            }
            Value::Object(result)
        }
        _ => overlay.clone(),
    }
}

// ============================================================================
// DISPLAY FUNCTIONS
// ============================================================================

/// Displays JSON analysis results
fn display_analysis(analysis: &JsonAnalysis, check_sensitive: bool) {
    println!("\n{}", "JSON Analysis".bold().underline());
    println!("Size: {} bytes", analysis.size_bytes);
    println!("Max depth: {}", analysis.max_depth);
    println!("Total keys: {}", analysis.total_keys);
    println!();
    println!("{}", "Value Types:".yellow());
    println!("  Objects: {}", analysis.object_count);
    println!("  Arrays: {}", analysis.array_count);
    println!("  Strings: {}", analysis.string_count);
    println!("  Numbers: {}", analysis.number_count);
    println!("  Booleans: {}", analysis.boolean_count);
    println!("  Nulls: {}", analysis.null_count);

    if check_sensitive && !analysis.sensitive_keys.is_empty() {
        println!("\n{}", "Sensitive Data Found:".red().bold());
        for key in &analysis.sensitive_keys {
            println!("  {} {}", "!".red(), key);
        }
        println!();
        println!(
            "{} Found {} potentially sensitive field(s)",
            "Warning:".yellow(),
            analysis.sensitive_keys.len()
        );
    } else if check_sensitive {
        println!("\n{} No sensitive fields detected", "OK:".green());
    }
}

// ============================================================================
// MAIN FUNCTION
// ============================================================================

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Parse {
            file,
            string,
            pretty,
            compact,
        } => {
            let value = if let Some(s) = string {
                parse_json_string(&s)?
            } else {
                read_json(file.as_ref())?
            };

            let output = if compact {
                serde_json::to_string(&value)?
            } else if pretty {
                serde_json::to_string_pretty(&value)?
            } else {
                serde_json::to_string_pretty(&value)?
            };

            println!("{}", output);
            println!("\n{} JSON is valid", "OK:".green());
        }

        Commands::Query {
            file,
            path,
            json_output,
        } => {
            let value = read_json(file.as_ref())?;
            let results = query_jsonpath(&value, &path)?;

            if results.is_empty() {
                println!("{} No matches found for path: {}", "Warning:".yellow(), path);
            } else if json_output {
                println!("{}", serde_json::to_string_pretty(&results)?);
            } else {
                println!("\n{} ({} match(es))", "Results".bold().underline(), results.len());
                for (i, result) in results.iter().enumerate() {
                    println!("\n[{}]: {}", i, serde_json::to_string_pretty(result)?);
                }
            }
        }

        Commands::Analyze { file, sensitive } => {
            let value = read_json(file.as_ref())?;
            let analysis = analyze_json(&value);
            display_analysis(&analysis, sensitive);
        }

        Commands::Create {
            pairs,
            nested,
            output,
            pretty,
        } => {
            let mut result = json!({});

            // Process simple key=value pairs
            for pair in &pairs {
                let parts: Vec<&str> = pair.splitn(2, '=').collect();
                if parts.len() != 2 {
                    anyhow::bail!("Invalid pair format: '{}'. Use key=value", pair);
                }
                let key = parts[0];
                let value = parse_value(parts[1]);
                result.as_object_mut().unwrap().insert(key.to_string(), value);
            }

            // Process nested path=value pairs
            for nested_pair in &nested {
                let parts: Vec<&str> = nested_pair.splitn(2, '=').collect();
                if parts.len() != 2 {
                    anyhow::bail!("Invalid nested pair format: '{}'. Use path.to.key=value", nested_pair);
                }
                let path = parts[0];
                let value = parse_value(parts[1]);
                set_value_at_path(&mut result, path, value)?;
            }

            let json_str = format_json(&result, pretty)?;

            if let Some(path) = output {
                fs::write(&path, &json_str)?;
                println!("{} Wrote JSON to {:?}", "Success:".green(), path);
            } else {
                println!("{}", json_str);
            }
        }

        Commands::Modify {
            file,
            set,
            delete,
            output,
            pretty,
        } => {
            let mut value = read_json(Some(&file))?;

            // Apply deletions first
            for path in &delete {
                if delete_value_at_path(&mut value, path)? {
                    if cli.verbose {
                        println!("{} Deleted: {}", "Info:".blue(), path);
                    }
                } else {
                    println!("{} Key not found: {}", "Warning:".yellow(), path);
                }
            }

            // Apply sets
            for set_pair in &set {
                let parts: Vec<&str> = set_pair.splitn(2, '=').collect();
                if parts.len() != 2 {
                    anyhow::bail!("Invalid set format: '{}'. Use path.to.key=value", set_pair);
                }
                let path = parts[0];
                let new_value = parse_value(parts[1]);
                set_value_at_path(&mut value, path, new_value)?;
                if cli.verbose {
                    println!("{} Set: {}", "Info:".blue(), path);
                }
            }

            let json_str = format_json(&value, pretty)?;

            if let Some(out_path) = output {
                fs::write(&out_path, &json_str)?;
                println!("{} Wrote modified JSON to {:?}", "Success:".green(), out_path);
            } else {
                println!("{}", json_str);
            }
        }

        Commands::Diff {
            file1,
            file2,
            only_diff,
        } => {
            let value1 = read_json(Some(&file1))?;
            let value2 = read_json(Some(&file2))?;

            let diffs = diff_json(&value1, &value2, "");

            println!("\n{}", "JSON Diff".bold().underline());
            println!("File 1: {:?}", file1);
            println!("File 2: {:?}", file2);

            if diffs.is_empty() {
                println!("\n{} Files are identical", "OK:".green());
            } else {
                println!("\n{} differences found:\n", diffs.len());

                for (path, val1, val2) in &diffs {
                    println!("{}", path.cyan().bold());
                    println!("  {} {}", "-".red(), val1.red());
                    println!("  {} {}", "+".green(), val2.green());
                }
            }
        }

        Commands::Sanitize {
            file,
            remove,
            mask,
            output,
        } => {
            let value = read_json(file.as_ref())?;
            let sanitized = sanitize_json(&value, &remove, mask);

            let json_str = serde_json::to_string_pretty(&sanitized)?;

            if let Some(out_path) = output {
                fs::write(&out_path, &json_str)?;
                println!("{} Wrote sanitized JSON to {:?}", "Success:".green(), out_path);
            } else {
                println!("{}", json_str);
            }

            // Report what was sanitized
            let original_analysis = analyze_json(&value);
            if !original_analysis.sensitive_keys.is_empty() {
                println!(
                    "\n{} {} sensitive field(s)",
                    "Sanitized:".yellow(),
                    original_analysis.sensitive_keys.len()
                );
            }
        }

        Commands::Merge { files, deep, output } => {
            if files.is_empty() {
                anyhow::bail!("At least one file is required");
            }

            let mut result = read_json(Some(&files[0]))?;

            for file in &files[1..] {
                let overlay = read_json(Some(file))?;
                result = merge_json(&result, &overlay, deep);
            }

            let json_str = serde_json::to_string_pretty(&result)?;

            if let Some(out_path) = output {
                fs::write(&out_path, &json_str)?;
                println!("{} Merged {} files to {:?}", "Success:".green(), files.len(), out_path);
            } else {
                println!("{}", json_str);
            }
        }
    }

    Ok(())
}

// ============================================================================
// UNIT TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_json_string() {
        let json = r#"{"name": "test", "value": 42}"#;
        let result = parse_json_string(json);
        assert!(result.is_ok());

        let value = result.unwrap();
        assert_eq!(value["name"], "test");
        assert_eq!(value["value"], 42);
    }

    #[test]
    fn test_parse_invalid_json() {
        let json = r#"{"name": "test""#;
        let result = parse_json_string(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_is_sensitive_key() {
        assert!(is_sensitive_key("password"));
        assert!(is_sensitive_key("API_KEY"));
        assert!(is_sensitive_key("user_secret"));
        assert!(!is_sensitive_key("username"));
        assert!(!is_sensitive_key("email"));
    }

    #[test]
    fn test_analyze_json() {
        let json = json!({
            "name": "test",
            "items": [1, 2, 3],
            "nested": {
                "password": "secret"
            }
        });

        let analysis = analyze_json(&json);
        assert_eq!(analysis.total_keys, 4);
        assert_eq!(analysis.object_count, 2);
        assert_eq!(analysis.array_count, 1);
        assert!(!analysis.sensitive_keys.is_empty());
    }

    #[test]
    fn test_set_value_at_path() {
        let mut json = json!({});
        set_value_at_path(&mut json, "user.name", Value::String("John".to_string())).unwrap();

        assert_eq!(json["user"]["name"], "John");
    }

    #[test]
    fn test_delete_value_at_path() {
        let mut json = json!({
            "user": {
                "name": "John",
                "password": "secret"
            }
        });

        let deleted = delete_value_at_path(&mut json, "user.password").unwrap();
        assert!(deleted);
        assert!(json["user"].get("password").is_none());
    }

    #[test]
    fn test_sanitize_json() {
        let json = json!({
            "username": "john",
            "password": "secret123",
            "api_key": "key123"
        });

        let sanitized = sanitize_json(&json, &[], false);

        assert!(sanitized.get("username").is_some());
        assert!(sanitized.get("password").is_none());
        assert!(sanitized.get("api_key").is_none());
    }

    #[test]
    fn test_sanitize_json_mask() {
        let json = json!({
            "username": "john",
            "password": "secret123"
        });

        let sanitized = sanitize_json(&json, &[], true);

        assert_eq!(sanitized["username"], "john");
        assert_eq!(sanitized["password"], "***REDACTED***");
    }

    #[test]
    fn test_diff_json() {
        let json1 = json!({"name": "John", "age": 30});
        let json2 = json!({"name": "Jane", "age": 30});

        let diffs = diff_json(&json1, &json2, "");

        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].0, "name");
    }

    #[test]
    fn test_merge_json() {
        let base = json!({"a": 1, "b": {"c": 2}});
        let overlay = json!({"b": {"d": 3}});

        let merged = merge_json(&base, &overlay, true);

        assert_eq!(merged["a"], 1);
        assert_eq!(merged["b"]["c"], 2);
        assert_eq!(merged["b"]["d"], 3);
    }

    #[test]
    fn test_parse_value() {
        assert_eq!(parse_value("true"), Value::Bool(true));
        assert_eq!(parse_value("false"), Value::Bool(false));
        assert_eq!(parse_value("null"), Value::Null);
        assert_eq!(parse_value("42"), json!(42));
        assert_eq!(parse_value("3.14"), json!(3.14));
        assert_eq!(parse_value("hello"), Value::String("hello".to_string()));
    }

    #[test]
    fn test_query_jsonpath() {
        let json = json!({
            "users": [
                {"name": "John"},
                {"name": "Jane"}
            ]
        });

        let results = query_jsonpath(&json, "$.users[*].name").unwrap();
        assert_eq!(results.len(), 2);
    }
}
