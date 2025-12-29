//! # Environment Variable Security Tool
//!
//! This module demonstrates secure handling of environment variables in Rust,
//! including:
//! - Reading and displaying environment variables
//! - Setting and unsetting variables
//! - Detecting sensitive information in environment
//! - Exporting environment snapshots
//!
//! ## Security Considerations
//! - Environment variables often contain secrets (API keys, passwords)
//! - Child processes inherit environment variables
//! - Environment can be leaked through logs or error messages
//! - Some variables affect program behavior (PATH, LD_PRELOAD, etc.)

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use colored::*;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::PathBuf;
use thiserror::Error;

// ============================================================================
// CUSTOM ERROR TYPES
// ============================================================================

/// Custom error types for environment operations
#[derive(Error, Debug)]
pub enum EnvError {
    /// Error when variable is not found
    #[error("Environment variable not found: {0}")]
    NotFound(String),

    /// Error when variable name is invalid
    #[error("Invalid variable name: {0}")]
    InvalidName(String),

    /// Error when sensitive data is detected
    #[error("Sensitive data detected in variable: {0}")]
    SensitiveData(String),
}

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/// Represents an environment variable with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvVariable {
    /// The name of the environment variable
    pub name: String,
    /// The value of the environment variable
    pub value: String,
    /// Whether this variable appears to contain sensitive data
    pub is_sensitive: bool,
    /// Category of the variable (security, path, system, user, etc.)
    pub category: String,
}

/// Environment snapshot for export/import
#[derive(Debug, Serialize, Deserialize)]
pub struct EnvSnapshot {
    /// Timestamp of when the snapshot was taken
    pub timestamp: String,
    /// Hostname where snapshot was taken
    pub hostname: String,
    /// The environment variables
    pub variables: Vec<EnvVariable>,
}

// ============================================================================
// CLI ARGUMENT STRUCTURES
// ============================================================================

/// Environment Variable Tool - Security-focused environment inspection
///
/// This tool provides comprehensive environment variable management with
/// security analysis capabilities.
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

/// Available subcommands for environment operations
#[derive(Subcommand, Debug)]
enum Commands {
    /// List all environment variables
    List {
        /// Filter variables by pattern (regex)
        #[arg(short, long)]
        filter: Option<String>,

        /// Show only sensitive variables
        #[arg(short, long)]
        sensitive: bool,

        /// Sort output alphabetically
        #[arg(short = 'o', long)]
        sort: bool,

        /// Show values (hidden by default for sensitive vars)
        #[arg(long)]
        show_values: bool,
    },

    /// Get a specific environment variable
    Get {
        /// Name of the variable to get
        name: String,

        /// Default value if variable is not set
        #[arg(short, long)]
        default: Option<String>,
    },

    /// Set an environment variable (for current process)
    Set {
        /// Name of the variable
        name: String,

        /// Value to set
        value: String,

        /// Validate the value doesn't contain dangerous patterns
        #[arg(short = 'c', long)]
        check: bool,
    },

    /// Unset an environment variable
    Unset {
        /// Name of the variable to unset
        name: String,
    },

    /// Analyze environment for security issues
    Audit {
        /// Check for specific vulnerability types
        #[arg(short, long, value_delimiter = ',')]
        checks: Option<Vec<String>>,
    },

    /// Export environment to file
    Export {
        /// Output file path
        #[arg(short, long)]
        output: PathBuf,

        /// Export format (json, shell, env)
        #[arg(short, long, default_value = "json")]
        format: String,

        /// Include sensitive variables (DANGER!)
        #[arg(long)]
        include_sensitive: bool,
    },

    /// Compare current environment with a snapshot
    Diff {
        /// Path to snapshot file to compare against
        #[arg(short, long)]
        snapshot: PathBuf,
    },

    /// Show PATH analysis
    Path {
        /// Check for writable directories in PATH
        #[arg(short, long)]
        security_check: bool,
    },
}

// ============================================================================
// SENSITIVE DATA DETECTION
// ============================================================================

/// Patterns that indicate sensitive environment variables
/// These are common patterns for secrets and credentials
const SENSITIVE_PATTERNS: &[&str] = &[
    "PASSWORD",
    "PASSWD",
    "SECRET",
    "TOKEN",
    "API_KEY",
    "APIKEY",
    "API-KEY",
    "AUTH",
    "CREDENTIAL",
    "PRIVATE",
    "KEY",
    "CERT",
    "SSH",
    "AWS_",
    "AZURE_",
    "GCP_",
    "GOOGLE_",
    "DATABASE_URL",
    "DB_",
    "MYSQL_",
    "POSTGRES_",
    "MONGO_",
    "REDIS_",
    "ENCRYPTION",
    "DECRYPT",
    "SIGN",
    "JWT",
    "OAUTH",
    "CLIENT_SECRET",
    "ACCESS_KEY",
];

/// Security-relevant environment variables that affect program behavior
const SECURITY_RELEVANT_VARS: &[&str] = &[
    "PATH",
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "PYTHONPATH",
    "RUBYLIB",
    "NODE_PATH",
    "CLASSPATH",
    "HOME",
    "USER",
    "SHELL",
    "TERM",
    "EDITOR",
    "SUDO_USER",
    "SUDO_UID",
    "http_proxy",
    "https_proxy",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "no_proxy",
    "NO_PROXY",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "CURL_CA_BUNDLE",
    "REQUESTS_CA_BUNDLE",
];

/// Checks if a variable name indicates sensitive data
///
/// # Arguments
/// * `name` - The environment variable name to check
///
/// # Returns
/// * `bool` - True if the variable appears to be sensitive
fn is_sensitive_variable(name: &str) -> bool {
    let upper = name.to_uppercase();
    SENSITIVE_PATTERNS.iter().any(|pattern| upper.contains(pattern))
}

/// Determines the category of an environment variable
///
/// # Arguments
/// * `name` - The environment variable name
///
/// # Returns
/// * `String` - The category of the variable
fn categorize_variable(name: &str) -> String {
    let upper = name.to_uppercase();

    if is_sensitive_variable(name) {
        return "sensitive".to_string();
    }

    if SECURITY_RELEVANT_VARS
        .iter()
        .any(|v| v.to_uppercase() == upper)
    {
        return "security".to_string();
    }

    // Path-related variables
    if upper.contains("PATH") || upper.contains("DIR") || upper.contains("HOME") {
        return "path".to_string();
    }

    // Language/runtime variables
    if upper.starts_with("RUST")
        || upper.starts_with("CARGO")
        || upper.starts_with("PYTHON")
        || upper.starts_with("NODE")
        || upper.starts_with("JAVA")
        || upper.starts_with("GO")
    {
        return "language".to_string();
    }

    // System variables
    if upper.starts_with("LC_")
        || upper.starts_with("LANG")
        || upper == "TERM"
        || upper == "SHELL"
        || upper == "USER"
    {
        return "system".to_string();
    }

    "user".to_string()
}

/// Masks a sensitive value for safe display
///
/// # Arguments
/// * `value` - The value to mask
///
/// # Returns
/// * `String` - Masked value
fn mask_value(value: &str) -> String {
    if value.len() <= 4 {
        "*".repeat(value.len())
    } else {
        format!("{}...{}", &value[..2], &value[value.len() - 2..])
    }
}

// ============================================================================
// ENVIRONMENT OPERATIONS
// ============================================================================

/// Gets all environment variables as EnvVariable structs
///
/// # Returns
/// * `Vec<EnvVariable>` - List of all environment variables
fn get_all_variables() -> Vec<EnvVariable> {
    env::vars()
        .map(|(name, value)| {
            let is_sensitive = is_sensitive_variable(&name);
            let category = categorize_variable(&name);
            EnvVariable {
                name,
                value,
                is_sensitive,
                category,
            }
        })
        .collect()
}

/// Gets a specific environment variable
///
/// # Arguments
/// * `name` - The name of the variable to get
/// * `default` - Optional default value
///
/// # Returns
/// * `Result<String>` - The value or error
fn get_variable(name: &str, default: Option<String>) -> Result<String> {
    match env::var(name) {
        Ok(value) => Ok(value),
        Err(env::VarError::NotPresent) => {
            default.ok_or_else(|| EnvError::NotFound(name.to_string()).into())
        }
        Err(env::VarError::NotUnicode(_)) => {
            anyhow::bail!("Variable {} contains non-UTF8 data", name)
        }
    }
}

/// Validates a variable name according to environment variable conventions
///
/// # Arguments
/// * `name` - The variable name to validate
///
/// # Returns
/// * `Result<()>` - Ok if valid, error otherwise
fn validate_variable_name(name: &str) -> Result<()> {
    // Environment variable names should:
    // - Not be empty
    // - Start with a letter or underscore
    // - Contain only letters, numbers, and underscores

    if name.is_empty() {
        return Err(EnvError::InvalidName("Name cannot be empty".to_string()).into());
    }

    let first_char = name.chars().next().unwrap();
    if !first_char.is_alphabetic() && first_char != '_' {
        return Err(
            EnvError::InvalidName("Name must start with letter or underscore".to_string()).into(),
        );
    }

    if !name.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return Err(
            EnvError::InvalidName("Name can only contain letters, numbers, and underscores".to_string()).into(),
        );
    }

    Ok(())
}

/// Checks a value for dangerous patterns
///
/// # Arguments
/// * `value` - The value to check
///
/// # Returns
/// * `Vec<String>` - List of warnings
fn check_value_safety(value: &str) -> Vec<String> {
    let mut warnings = Vec::new();

    // Check for shell injection patterns
    let dangerous_patterns = [
        (";", "Semicolon can allow command chaining"),
        ("|", "Pipe can redirect output"),
        ("&&", "Double ampersand allows command chaining"),
        ("||", "Double pipe allows command chaining"),
        ("$(", "Command substitution detected"),
        ("`", "Backtick command substitution detected"),
        ("${", "Variable expansion detected"),
        (">", "Output redirection detected"),
        ("<", "Input redirection detected"),
    ];

    for (pattern, warning) in dangerous_patterns {
        if value.contains(pattern) {
            warnings.push(format!("{}: {}", warning, pattern));
        }
    }

    // Check for very long values (potential buffer overflow in legacy systems)
    if value.len() > 32768 {
        warnings.push("Value exceeds 32KB - may cause issues in some systems".to_string());
    }

    warnings
}

// ============================================================================
// PATH ANALYSIS
// ============================================================================

/// Analyzes the PATH environment variable for security issues
///
/// # Arguments
/// * `security_check` - Whether to perform security checks
/// * `verbose` - Whether to print verbose output
///
/// # Returns
/// * `Result<Vec<String>>` - List of issues found
fn analyze_path(security_check: bool, verbose: bool) -> Result<Vec<String>> {
    let path = env::var("PATH").unwrap_or_default();
    let mut issues = Vec::new();

    println!("\n{}", "PATH Analysis".bold().underline());

    // Split PATH by the appropriate separator
    let separator = if cfg!(windows) { ';' } else { ':' };
    let directories: Vec<&str> = path.split(separator).collect();

    println!("Number of directories: {}", directories.len());

    // Check for duplicates
    let mut seen: HashMap<&str, usize> = HashMap::new();
    for (i, dir) in directories.iter().enumerate() {
        *seen.entry(dir).or_insert(0) += 1;
        if verbose {
            println!("  {:>3}. {}", i + 1, dir);
        }
    }

    // Report duplicates
    let duplicates: Vec<_> = seen.iter().filter(|(_, &count)| count > 1).collect();
    if !duplicates.is_empty() {
        println!("\n{} Duplicate entries found:", "Warning:".yellow());
        for (dir, count) in duplicates {
            println!("  {} appears {} times", dir, count);
            issues.push(format!("Duplicate PATH entry: {}", dir));
        }
    }

    // Security checks
    if security_check {
        println!("\n{}", "Security Analysis:".yellow());

        for dir in &directories {
            // Check for empty entries (current directory)
            if dir.is_empty() {
                issues.push("Empty PATH entry (implies current directory)".to_string());
                println!(
                    "  {} Empty entry (current directory in PATH)",
                    "CRITICAL:".red().bold()
                );
                continue;
            }

            // Check for current directory explicitly
            if *dir == "." {
                issues.push("Current directory (.) in PATH".to_string());
                println!(
                    "  {} Current directory (.) in PATH",
                    "CRITICAL:".red().bold()
                );
                continue;
            }

            // Check for relative paths
            if !dir.starts_with('/') && !dir.starts_with('~') {
                #[cfg(not(windows))]
                {
                    issues.push(format!("Relative path in PATH: {}", dir));
                    println!("  {} Relative path: {}", "WARNING:".yellow(), dir);
                }
            }

            // Check directory permissions (Unix only)
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;

                if let Ok(metadata) = std::fs::metadata(dir) {
                    let mode = metadata.permissions().mode();

                    // World-writable directory in PATH is dangerous
                    if mode & 0o002 != 0 {
                        issues.push(format!("World-writable directory in PATH: {}", dir));
                        println!(
                            "  {} World-writable: {} (mode: {:o})",
                            "CRITICAL:".red().bold(),
                            dir,
                            mode & 0o777
                        );
                    }

                    // Group-writable is also concerning
                    if mode & 0o020 != 0 {
                        issues.push(format!("Group-writable directory in PATH: {}", dir));
                        println!(
                            "  {} Group-writable: {} (mode: {:o})",
                            "WARNING:".yellow(),
                            dir,
                            mode & 0o777
                        );
                    }
                } else if verbose {
                    println!("  {} Directory does not exist: {}", "Note:".blue(), dir);
                }
            }
        }

        if issues.is_empty() {
            println!("  {} No security issues found", "OK:".green());
        }
    }

    Ok(issues)
}

// ============================================================================
// SECURITY AUDIT
// ============================================================================

/// Performs a security audit of the environment
///
/// # Arguments
/// * `checks` - Optional specific checks to perform
/// * `verbose` - Whether to print verbose output
///
/// # Returns
/// * `Result<Vec<String>>` - List of issues found
fn audit_environment(checks: Option<Vec<String>>, verbose: bool) -> Result<Vec<String>> {
    let mut issues = Vec::new();
    let variables = get_all_variables();

    println!("\n{}", "Environment Security Audit".bold().underline());
    println!("Total variables: {}\n", variables.len());

    // Check for sensitive variables
    let sensitive: Vec<_> = variables.iter().filter(|v| v.is_sensitive).collect();
    if !sensitive.is_empty() {
        println!(
            "{} Found {} potentially sensitive variables:",
            "Warning:".yellow(),
            sensitive.len()
        );
        for var in &sensitive {
            println!("  - {} (value: {})", var.name.red(), mask_value(&var.value));
            issues.push(format!("Sensitive variable exposed: {}", var.name));
        }
        println!();
    }

    // Check for dangerous LD_PRELOAD
    if let Ok(ld_preload) = env::var("LD_PRELOAD") {
        println!(
            "{} LD_PRELOAD is set: {}",
            "CRITICAL:".red().bold(),
            ld_preload
        );
        issues.push(format!("LD_PRELOAD is set to: {}", ld_preload));
    }

    // Check for dangerous LD_LIBRARY_PATH
    if let Ok(ld_path) = env::var("LD_LIBRARY_PATH") {
        println!(
            "{} LD_LIBRARY_PATH is set: {}",
            "WARNING:".yellow(),
            ld_path
        );
        issues.push(format!("LD_LIBRARY_PATH is set to: {}", ld_path));
    }

    // Check for proxy settings (could redirect traffic)
    let proxy_vars = ["http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"];
    for proxy_var in proxy_vars {
        if let Ok(proxy) = env::var(proxy_var) {
            println!("{} {} is set: {}", "Note:".blue(), proxy_var, proxy);
            if verbose {
                issues.push(format!("Proxy configured: {}={}", proxy_var, proxy));
            }
        }
    }

    // Check HOME directory
    if let Ok(home) = env::var("HOME") {
        if !std::path::Path::new(&home).exists() {
            println!("{} HOME directory does not exist: {}", "WARNING:".yellow(), home);
            issues.push(format!("HOME directory missing: {}", home));
        }
    }

    // Perform PATH analysis
    let path_issues = analyze_path(true, verbose)?;
    issues.extend(path_issues);

    // Summary
    println!("\n{}", "Audit Summary".bold().underline());
    println!("Total issues found: {}", issues.len());

    if issues.is_empty() {
        println!("{} Environment appears secure", "OK:".green());
    } else {
        println!("\n{}", "Issues:".red());
        for (i, issue) in issues.iter().enumerate() {
            println!("  {}. {}", i + 1, issue);
        }
    }

    Ok(issues)
}

// ============================================================================
// EXPORT/IMPORT FUNCTIONS
// ============================================================================

/// Exports environment to a file
///
/// # Arguments
/// * `output` - Output file path
/// * `format` - Export format (json, shell, env)
/// * `include_sensitive` - Whether to include sensitive variables
///
/// # Returns
/// * `Result<()>` - Success or error
fn export_environment(output: &PathBuf, format: &str, include_sensitive: bool) -> Result<()> {
    let variables: Vec<EnvVariable> = get_all_variables()
        .into_iter()
        .filter(|v| include_sensitive || !v.is_sensitive)
        .collect();

    let content = match format {
        "json" => {
            let snapshot = EnvSnapshot {
                timestamp: chrono_like_timestamp(),
                hostname: env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string()),
                variables,
            };
            serde_json::to_string_pretty(&snapshot)?
        }
        "shell" => variables
            .iter()
            .map(|v| format!("export {}=\"{}\"", v.name, escape_shell_value(&v.value)))
            .collect::<Vec<_>>()
            .join("\n"),
        "env" => variables
            .iter()
            .map(|v| format!("{}={}", v.name, v.value))
            .collect::<Vec<_>>()
            .join("\n"),
        _ => anyhow::bail!("Unknown format: {}. Use json, shell, or env", format),
    };

    fs::write(output, content).with_context(|| format!("Failed to write to {:?}", output))?;

    println!(
        "{} Exported {} variables to {:?}",
        "Success:".green(),
        variables.len(),
        output
    );

    if !include_sensitive {
        println!(
            "{} Sensitive variables were excluded. Use --include-sensitive to include them.",
            "Note:".blue()
        );
    }

    Ok(())
}

/// Escapes a value for safe shell usage
fn escape_shell_value(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('$', "\\$")
        .replace('`', "\\`")
}

/// Generates a timestamp string (simulating chrono)
fn chrono_like_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}", duration.as_secs())
}

/// Compares current environment with a snapshot
///
/// # Arguments
/// * `snapshot_path` - Path to the snapshot file
///
/// # Returns
/// * `Result<()>` - Success or error
fn diff_environment(snapshot_path: &PathBuf) -> Result<()> {
    let content = fs::read_to_string(snapshot_path)
        .with_context(|| format!("Failed to read snapshot from {:?}", snapshot_path))?;

    let snapshot: EnvSnapshot =
        serde_json::from_str(&content).with_context(|| "Failed to parse snapshot JSON")?;

    let current = get_all_variables();
    let current_map: HashMap<_, _> = current.iter().map(|v| (&v.name, &v.value)).collect();
    let snapshot_map: HashMap<_, _> = snapshot
        .variables
        .iter()
        .map(|v| (&v.name, &v.value))
        .collect();

    println!("\n{}", "Environment Diff".bold().underline());
    println!("Snapshot timestamp: {}", snapshot.timestamp);
    println!("Snapshot host: {}\n", snapshot.hostname);

    // Find added variables
    let added: Vec<_> = current_map
        .keys()
        .filter(|k| !snapshot_map.contains_key(*k))
        .collect();

    // Find removed variables
    let removed: Vec<_> = snapshot_map
        .keys()
        .filter(|k| !current_map.contains_key(*k))
        .collect();

    // Find changed variables
    let changed: Vec<_> = current_map
        .iter()
        .filter(|(k, v)| snapshot_map.get(*k).map(|sv| sv != *v).unwrap_or(false))
        .collect();

    if !added.is_empty() {
        println!("{} Added variables:", "+++".green());
        for name in added {
            println!("  + {}", name.green());
        }
    }

    if !removed.is_empty() {
        println!("\n{} Removed variables:", "---".red());
        for name in removed {
            println!("  - {}", name.red());
        }
    }

    if !changed.is_empty() {
        println!("\n{} Changed variables:", "~~~".yellow());
        for (name, new_value) in changed {
            let old_value = snapshot_map.get(name).unwrap();
            println!("  ~ {}", name.yellow());
            println!("    old: {}", mask_value(old_value));
            println!("    new: {}", mask_value(new_value));
        }
    }

    if added.is_empty() && removed.is_empty() && changed.is_empty() {
        println!("{} No differences found", "OK:".green());
    }

    Ok(())
}

// ============================================================================
// MAIN FUNCTION
// ============================================================================

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::List {
            filter,
            sensitive,
            sort,
            show_values,
        } => {
            let mut variables = get_all_variables();

            // Apply filter if provided
            if let Some(pattern) = filter {
                let re = Regex::new(&pattern).with_context(|| "Invalid regex pattern")?;
                variables.retain(|v| re.is_match(&v.name) || re.is_match(&v.value));
            }

            // Filter sensitive only if requested
            if sensitive {
                variables.retain(|v| v.is_sensitive);
            }

            // Sort if requested
            if sort {
                variables.sort_by(|a, b| a.name.cmp(&b.name));
            }

            println!("\n{}", "Environment Variables".bold().underline());
            println!("Total: {}\n", variables.len());

            for var in &variables {
                let display_value = if var.is_sensitive && !show_values {
                    mask_value(&var.value).dimmed().to_string()
                } else {
                    var.value.clone()
                };

                let category_color = match var.category.as_str() {
                    "sensitive" => var.category.red(),
                    "security" => var.category.yellow(),
                    "path" => var.category.blue(),
                    "language" => var.category.cyan(),
                    _ => var.category.normal(),
                };

                println!(
                    "[{}] {} = {}",
                    category_color,
                    var.name.bold(),
                    display_value
                );
            }
        }

        Commands::Get { name, default } => {
            let value = get_variable(&name, default)?;
            let is_sensitive = is_sensitive_variable(&name);

            if is_sensitive {
                println!(
                    "{} This variable may contain sensitive data",
                    "Warning:".yellow()
                );
            }

            println!("{}={}", name, value);
        }

        Commands::Set { name, value, check } => {
            // Validate the variable name
            validate_variable_name(&name)?;

            // Check value safety if requested
            if check {
                let warnings = check_value_safety(&value);
                if !warnings.is_empty() {
                    println!("{} Potential security issues in value:", "Warning:".yellow());
                    for warning in &warnings {
                        println!("  - {}", warning);
                    }
                    println!();
                }
            }

            // Set the variable (only affects current process and children)
            env::set_var(&name, &value);

            println!("{} Set {}={}", "Success:".green(), name, value);
            println!(
                "{} This only affects the current process",
                "Note:".blue()
            );
        }

        Commands::Unset { name } => {
            // Check if variable exists
            if env::var(&name).is_err() {
                println!("{} Variable {} was not set", "Warning:".yellow(), name);
            } else {
                env::remove_var(&name);
                println!("{} Unset {}", "Success:".green(), name);
            }
        }

        Commands::Audit { checks } => {
            audit_environment(checks, cli.verbose)?;
        }

        Commands::Export {
            output,
            format,
            include_sensitive,
        } => {
            if include_sensitive {
                println!(
                    "{} Including sensitive variables in export!",
                    "DANGER:".red().bold()
                );
            }
            export_environment(&output, &format, include_sensitive)?;
        }

        Commands::Diff { snapshot } => {
            diff_environment(&snapshot)?;
        }

        Commands::Path { security_check } => {
            analyze_path(security_check, cli.verbose)?;
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
    fn test_is_sensitive_variable() {
        assert!(is_sensitive_variable("API_KEY"));
        assert!(is_sensitive_variable("aws_secret_key"));
        assert!(is_sensitive_variable("DATABASE_PASSWORD"));
        assert!(!is_sensitive_variable("HOME"));
        assert!(!is_sensitive_variable("PATH"));
        assert!(!is_sensitive_variable("USER"));
    }

    #[test]
    fn test_categorize_variable() {
        assert_eq!(categorize_variable("API_KEY"), "sensitive");
        assert_eq!(categorize_variable("PATH"), "security");
        assert_eq!(categorize_variable("RUST_BACKTRACE"), "language");
        assert_eq!(categorize_variable("LC_ALL"), "system");
        assert_eq!(categorize_variable("MY_CUSTOM_VAR"), "user");
    }

    #[test]
    fn test_mask_value() {
        assert_eq!(mask_value("ab"), "**");
        assert_eq!(mask_value("abcd"), "****");
        assert_eq!(mask_value("abcdef"), "ab...ef");
        assert_eq!(mask_value("secret123"), "se...23");
    }

    #[test]
    fn test_validate_variable_name() {
        assert!(validate_variable_name("VALID_NAME").is_ok());
        assert!(validate_variable_name("_ALSO_VALID").is_ok());
        assert!(validate_variable_name("valid123").is_ok());
        assert!(validate_variable_name("").is_err());
        assert!(validate_variable_name("123invalid").is_err());
        assert!(validate_variable_name("invalid-name").is_err());
    }

    #[test]
    fn test_check_value_safety() {
        let warnings = check_value_safety("safe_value");
        assert!(warnings.is_empty());

        let warnings = check_value_safety("value; rm -rf /");
        assert!(!warnings.is_empty());

        let warnings = check_value_safety("$(whoami)");
        assert!(!warnings.is_empty());

        let warnings = check_value_safety("value | cat /etc/passwd");
        assert!(!warnings.is_empty());
    }

    #[test]
    fn test_escape_shell_value() {
        assert_eq!(escape_shell_value("simple"), "simple");
        assert_eq!(escape_shell_value("with\"quotes"), "with\\\"quotes");
        assert_eq!(escape_shell_value("$variable"), "\\$variable");
        assert_eq!(escape_shell_value("`command`"), "\\`command\\`");
    }

    #[test]
    fn test_get_all_variables() {
        // Set a test variable
        env::set_var("TEST_VAR_12345", "test_value");

        let vars = get_all_variables();
        let test_var = vars.iter().find(|v| v.name == "TEST_VAR_12345");

        assert!(test_var.is_some());
        assert_eq!(test_var.unwrap().value, "test_value");

        // Cleanup
        env::remove_var("TEST_VAR_12345");
    }

    #[test]
    fn test_get_variable() {
        env::set_var("TEST_GET_VAR", "hello");

        assert_eq!(get_variable("TEST_GET_VAR", None).unwrap(), "hello");
        assert_eq!(
            get_variable("NONEXISTENT_VAR", Some("default".to_string())).unwrap(),
            "default"
        );
        assert!(get_variable("NONEXISTENT_VAR", None).is_err());

        env::remove_var("TEST_GET_VAR");
    }

    #[test]
    fn test_env_variable_struct() {
        let var = EnvVariable {
            name: "TEST".to_string(),
            value: "value".to_string(),
            is_sensitive: false,
            category: "user".to_string(),
        };

        assert_eq!(var.name, "TEST");
        assert!(!var.is_sensitive);
    }
}
