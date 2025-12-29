//! # Regex Matcher - Security Pattern Matching Tool
//!
//! A comprehensive regex matching tool for security analysis.
//! Use cases include:
//! - Extracting patterns from log files
//! - Validating input formats
//! - Finding security-relevant strings
//! - Building custom detection rules
//!
//! ## Rust Concepts Covered:
//! - Regular expressions with the regex crate
//! - Lazy static initialization
//! - Iterators and captures
//! - String manipulation
//! - Error handling
//! - Command-line subcommands
//! - Serialization

use clap::{Parser, Subcommand, ValueEnum};
use colored::*;
use lazy_static::lazy_static;
use regex::{Captures, Match, Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::{self, BufRead, BufReader};

/// Regex Matcher - Security pattern matching tool
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

/// Available subcommands
#[derive(Subcommand, Debug)]
enum Commands {
    /// Match a pattern against input text
    Match {
        /// Regular expression pattern
        pattern: String,

        /// Input text (or use --file for file input)
        #[arg(short, long)]
        text: Option<String>,

        /// Input file path
        #[arg(short, long)]
        file: Option<String>,

        /// Case-insensitive matching
        #[arg(short, long)]
        ignore_case: bool,

        /// Multi-line mode (^ and $ match line boundaries)
        #[arg(short, long)]
        multiline: bool,

        /// Dot matches newline
        #[arg(short, long)]
        dot_all: bool,

        /// Output as JSON
        #[arg(short, long)]
        json: bool,
    },

    /// Test if a pattern matches
    Test {
        /// Regular expression pattern
        pattern: String,

        /// Input text to test
        text: String,

        /// Case-insensitive matching
        #[arg(short, long)]
        ignore_case: bool,
    },

    /// Extract all matches from text
    Extract {
        /// Regular expression pattern
        pattern: String,

        /// Input text (or use --file)
        #[arg(short, long)]
        text: Option<String>,

        /// Input file path
        #[arg(short, long)]
        file: Option<String>,

        /// Case-insensitive matching
        #[arg(short, long)]
        ignore_case: bool,

        /// Only show unique matches
        #[arg(short, long)]
        unique: bool,

        /// Output as JSON
        #[arg(short, long)]
        json: bool,
    },

    /// Replace matches with a string
    Replace {
        /// Regular expression pattern
        pattern: String,

        /// Replacement string (use $1, $2 for capture groups)
        replacement: String,

        /// Input text
        text: String,

        /// Replace all occurrences (default: first only)
        #[arg(short, long)]
        all: bool,

        /// Case-insensitive matching
        #[arg(short, long)]
        ignore_case: bool,
    },

    /// Split text by pattern
    Split {
        /// Regular expression pattern
        pattern: String,

        /// Input text
        text: String,

        /// Maximum number of splits
        #[arg(short, long)]
        limit: Option<usize>,

        /// Output as JSON
        #[arg(short, long)]
        json: bool,
    },

    /// Validate regex pattern syntax
    Validate {
        /// Regular expression pattern to validate
        pattern: String,
    },

    /// Use built-in security patterns
    Security {
        /// Security pattern to use
        #[arg(short, long, value_enum)]
        pattern: SecurityPatternType,

        /// Input text (or use --file)
        #[arg(short, long)]
        text: Option<String>,

        /// Input file path
        #[arg(short, long)]
        file: Option<String>,

        /// Output as JSON
        #[arg(short, long)]
        json: bool,
    },

    /// Explain a regex pattern
    Explain {
        /// Regular expression pattern to explain
        pattern: String,
    },

    /// List all built-in security patterns
    ListPatterns,

    /// Interactive regex tester
    Interactive,
}

/// Built-in security pattern types
#[derive(Debug, Clone, Copy, ValueEnum)]
enum SecurityPatternType {
    /// Email addresses
    Email,
    /// IPv4 addresses
    Ipv4,
    /// IPv6 addresses
    Ipv6,
    /// URLs
    Url,
    /// Phone numbers
    Phone,
    /// Credit card numbers
    CreditCard,
    /// Social Security Numbers
    Ssn,
    /// AWS Access Keys
    AwsKey,
    /// Private Keys
    PrivateKey,
    /// JWT Tokens
    Jwt,
    /// Passwords in code
    Password,
    /// API Keys
    ApiKey,
    /// MAC Addresses
    MacAddress,
    /// File Paths
    FilePath,
    /// Base64 strings
    Base64,
    /// MD5 hashes
    Md5,
    /// SHA256 hashes
    Sha256,
    /// UUIDs
    Uuid,
    /// Dates
    Date,
}

/// Match result structure
#[derive(Debug, Serialize, Deserialize)]
struct MatchResult {
    /// Whether pattern matched
    matched: bool,
    /// Number of matches found
    count: usize,
    /// Individual matches
    matches: Vec<MatchInfo>,
}

/// Information about a single match
#[derive(Debug, Serialize, Deserialize)]
struct MatchInfo {
    /// Full matched text
    text: String,
    /// Start position in input
    start: usize,
    /// End position in input
    end: usize,
    /// Line number (if applicable)
    line: Option<usize>,
    /// Capture groups (if any)
    groups: Vec<CaptureGroup>,
}

/// Capture group information
#[derive(Debug, Serialize, Deserialize)]
struct CaptureGroup {
    /// Group number or name
    name: String,
    /// Captured text
    text: Option<String>,
}

lazy_static! {
    /// Map of security pattern names to their regex patterns
    static ref SECURITY_PATTERNS: HashMap<&'static str, (&'static str, &'static str)> = {
        let mut m = HashMap::new();

        // Email addresses
        m.insert("email", (
            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            "Email addresses"
        ));

        // IPv4 addresses
        m.insert("ipv4", (
            r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
            "IPv4 addresses"
        ));

        // IPv6 addresses (simplified)
        m.insert("ipv6", (
            r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}",
            "IPv6 addresses"
        ));

        // URLs
        m.insert("url", (
            r"https?://[^\s<>\"']+",
            "HTTP/HTTPS URLs"
        ));

        // Phone numbers (various formats)
        m.insert("phone", (
            r"(?:\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}",
            "Phone numbers"
        ));

        // Credit card numbers
        m.insert("credit_card", (
            r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b",
            "Credit card numbers (Visa, MC, Amex, Discover)"
        ));

        // Social Security Numbers
        m.insert("ssn", (
            r"\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b",
            "Social Security Numbers"
        ));

        // AWS Access Keys
        m.insert("aws_key", (
            r"AKIA[0-9A-Z]{16}",
            "AWS Access Key IDs"
        ));

        // Private Keys
        m.insert("private_key", (
            r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----",
            "Private key headers"
        ));

        // JWT Tokens
        m.insert("jwt", (
            r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*",
            "JWT tokens"
        ));

        // Passwords in code
        m.insert("password", (
            r#"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"]?([^'\"\s]{4,})['\"]?"#,
            "Hardcoded passwords"
        ));

        // API Keys
        m.insert("api_key", (
            r#"(?i)(?:api[_-]?key|apikey)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{20,})['\"]?"#,
            "API keys"
        ));

        // MAC Addresses
        m.insert("mac_address", (
            r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}",
            "MAC addresses"
        ));

        // File paths
        m.insert("file_path", (
            r"(?:/[a-zA-Z0-9._-]+)+|(?:[A-Za-z]:\\[^\\:*?\"<>|\r\n]+)",
            "File paths (Unix/Windows)"
        ));

        // Base64 strings
        m.insert("base64", (
            r"(?:[A-Za-z0-9+/]{4}){5,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?",
            "Base64 encoded strings"
        ));

        // MD5 hashes
        m.insert("md5", (
            r"\b[a-fA-F0-9]{32}\b",
            "MD5 hashes"
        ));

        // SHA256 hashes
        m.insert("sha256", (
            r"\b[a-fA-F0-9]{64}\b",
            "SHA256 hashes"
        ));

        // UUIDs
        m.insert("uuid", (
            r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
            "UUIDs"
        ));

        // Dates (various formats)
        m.insert("date", (
            r"\b(?:\d{4}[-/]\d{2}[-/]\d{2}|\d{2}[-/]\d{2}[-/]\d{4})\b",
            "Dates (YYYY-MM-DD or DD-MM-YYYY)"
        ));

        m
    };
}

/// Custom error type
#[derive(Debug)]
enum RegexError {
    PatternError(String),
    IoError(String),
    InvalidInput(String),
}

impl std::fmt::Display for RegexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RegexError::PatternError(msg) => write!(f, "Pattern error: {}", msg),
            RegexError::IoError(msg) => write!(f, "I/O error: {}", msg),
            RegexError::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
        }
    }
}

impl std::error::Error for RegexError {}

/// Builds a regex with options
fn build_regex(pattern: &str, ignore_case: bool, multiline: bool, dot_all: bool) -> Result<Regex, RegexError> {
    RegexBuilder::new(pattern)
        .case_insensitive(ignore_case)
        .multi_line(multiline)
        .dot_matches_new_line(dot_all)
        .build()
        .map_err(|e| RegexError::PatternError(e.to_string()))
}

/// Gets the security pattern regex string
fn get_security_pattern(pattern_type: SecurityPatternType) -> &'static str {
    let key = match pattern_type {
        SecurityPatternType::Email => "email",
        SecurityPatternType::Ipv4 => "ipv4",
        SecurityPatternType::Ipv6 => "ipv6",
        SecurityPatternType::Url => "url",
        SecurityPatternType::Phone => "phone",
        SecurityPatternType::CreditCard => "credit_card",
        SecurityPatternType::Ssn => "ssn",
        SecurityPatternType::AwsKey => "aws_key",
        SecurityPatternType::PrivateKey => "private_key",
        SecurityPatternType::Jwt => "jwt",
        SecurityPatternType::Password => "password",
        SecurityPatternType::ApiKey => "api_key",
        SecurityPatternType::MacAddress => "mac_address",
        SecurityPatternType::FilePath => "file_path",
        SecurityPatternType::Base64 => "base64",
        SecurityPatternType::Md5 => "md5",
        SecurityPatternType::Sha256 => "sha256",
        SecurityPatternType::Uuid => "uuid",
        SecurityPatternType::Date => "date",
    };

    SECURITY_PATTERNS.get(key).map(|(pattern, _)| *pattern).unwrap_or("")
}

/// Reads input from text or file
fn get_input(text: Option<&str>, file: Option<&str>) -> Result<String, RegexError> {
    if let Some(t) = text {
        Ok(t.to_string())
    } else if let Some(f) = file {
        fs::read_to_string(f)
            .map_err(|e| RegexError::IoError(e.to_string()))
    } else {
        // Read from stdin
        let stdin = io::stdin();
        let mut input = String::new();
        for line in stdin.lock().lines() {
            let line = line.map_err(|e| RegexError::IoError(e.to_string()))?;
            input.push_str(&line);
            input.push('\n');
        }
        Ok(input)
    }
}

/// Extracts capture groups from a match
fn extract_captures(captures: &Captures) -> Vec<CaptureGroup> {
    let mut groups = Vec::new();

    // Named groups aren't directly iterable in the same way,
    // so we handle numbered groups
    for (i, cap) in captures.iter().enumerate() {
        if i > 0 {  // Skip group 0 (full match)
            groups.push(CaptureGroup {
                name: format!("${}", i),
                text: cap.map(|m| m.as_str().to_string()),
            });
        }
    }

    groups
}

/// Performs pattern matching
fn perform_match(
    pattern: &str,
    input: &str,
    ignore_case: bool,
    multiline: bool,
    dot_all: bool,
) -> Result<MatchResult, RegexError> {
    let regex = build_regex(pattern, ignore_case, multiline, dot_all)?;

    let mut matches = Vec::new();
    let mut line_num = 1;
    let mut last_newline_pos = 0;

    for mat in regex.captures_iter(input) {
        // Calculate line number
        let full_match = mat.get(0).unwrap();
        let match_start = full_match.start();

        // Count newlines up to this match
        for (pos, c) in input[last_newline_pos..match_start].char_indices() {
            if c == '\n' {
                line_num += 1;
                last_newline_pos = last_newline_pos + pos + 1;
            }
        }

        let groups = extract_captures(&mat);

        matches.push(MatchInfo {
            text: full_match.as_str().to_string(),
            start: full_match.start(),
            end: full_match.end(),
            line: Some(line_num),
            groups,
        });
    }

    Ok(MatchResult {
        matched: !matches.is_empty(),
        count: matches.len(),
        matches,
    })
}

/// Extracts all unique matches
fn extract_matches(
    pattern: &str,
    input: &str,
    ignore_case: bool,
    unique: bool,
) -> Result<Vec<String>, RegexError> {
    let regex = build_regex(pattern, ignore_case, false, false)?;

    let mut matches: Vec<String> = regex
        .find_iter(input)
        .map(|m| m.as_str().to_string())
        .collect();

    if unique {
        matches.sort();
        matches.dedup();
    }

    Ok(matches)
}

/// Performs pattern replacement
fn perform_replace(
    pattern: &str,
    replacement: &str,
    input: &str,
    all: bool,
    ignore_case: bool,
) -> Result<String, RegexError> {
    let regex = build_regex(pattern, ignore_case, false, false)?;

    let result = if all {
        regex.replace_all(input, replacement).to_string()
    } else {
        regex.replace(input, replacement).to_string()
    };

    Ok(result)
}

/// Splits text by pattern
fn perform_split(
    pattern: &str,
    input: &str,
    limit: Option<usize>,
) -> Result<Vec<String>, RegexError> {
    let regex = build_regex(pattern, false, false, false)?;

    let parts: Vec<String> = if let Some(n) = limit {
        regex.splitn(input, n).map(|s| s.to_string()).collect()
    } else {
        regex.split(input).map(|s| s.to_string()).collect()
    };

    Ok(parts)
}

/// Explains a regex pattern
fn explain_pattern(pattern: &str) -> String {
    let mut explanation = String::new();

    explanation.push_str(&format!("Pattern: {}\n\n", pattern));
    explanation.push_str("Explanation:\n");

    let mut chars = pattern.chars().peekable();
    let mut pos = 0;

    while let Some(c) = chars.next() {
        let desc = match c {
            '^' => "  ^ - Start of string/line",
            '$' => "  $ - End of string/line",
            '.' => "  . - Any single character",
            '*' => "  * - Zero or more of previous",
            '+' => "  + - One or more of previous",
            '?' => "  ? - Zero or one of previous",
            '\\' => {
                if let Some(&next) = chars.peek() {
                    chars.next();
                    match next {
                        'd' => "  \\d - Any digit (0-9)",
                        'D' => "  \\D - Any non-digit",
                        'w' => "  \\w - Any word character (a-z, A-Z, 0-9, _)",
                        'W' => "  \\W - Any non-word character",
                        's' => "  \\s - Any whitespace",
                        'S' => "  \\S - Any non-whitespace",
                        'b' => "  \\b - Word boundary",
                        'n' => "  \\n - Newline",
                        't' => "  \\t - Tab",
                        _ => "  \\ - Escape sequence",
                    }
                } else {
                    "  \\ - Escape character"
                }
            }
            '[' => "  [ - Start character class",
            ']' => "  ] - End character class",
            '(' => "  ( - Start capture group",
            ')' => "  ) - End capture group",
            '{' => "  { - Start quantifier",
            '}' => "  } - End quantifier",
            '|' => "  | - Alternation (OR)",
            _ => "",
        };

        if !desc.is_empty() {
            explanation.push_str(desc);
            explanation.push('\n');
        }

        pos += 1;
    }

    explanation
}

/// Prints match results
fn print_match_results(result: &MatchResult, input: &str) {
    if !result.matched {
        println!("{}", "No matches found".yellow());
        return;
    }

    println!("{} {} found", result.count.to_string().green().bold(),
        if result.count == 1 { "match" } else { "matches" });
    println!("{}", "=".repeat(50).dimmed());

    for (i, mat) in result.matches.iter().enumerate() {
        println!("\n{}. {} ({}:{}-{})",
            (i + 1).to_string().cyan(),
            mat.text.green().bold(),
            mat.line.unwrap_or(0),
            mat.start,
            mat.end
        );

        // Show context
        let context_start = mat.start.saturating_sub(20);
        let context_end = (mat.end + 20).min(input.len());
        let context = &input[context_start..context_end];

        println!("  Context: ...{}{}{}...",
            &input[context_start..mat.start].dimmed(),
            mat.text.red().underline(),
            &input[mat.end..context_end].dimmed()
        );

        // Show capture groups if any
        if !mat.groups.is_empty() {
            println!("  Capture groups:");
            for group in &mat.groups {
                if let Some(ref text) = group.text {
                    println!("    {}: {}", group.name.cyan(), text);
                }
            }
        }
    }
}

fn main() {
    let args = Args::parse();

    let result = match args.command {
        Commands::Match { pattern, text, file, ignore_case, multiline, dot_all, json } => {
            handle_match(&pattern, text.as_deref(), file.as_deref(), ignore_case, multiline, dot_all, json)
        }
        Commands::Test { pattern, text, ignore_case } => {
            handle_test(&pattern, &text, ignore_case)
        }
        Commands::Extract { pattern, text, file, ignore_case, unique, json } => {
            handle_extract(&pattern, text.as_deref(), file.as_deref(), ignore_case, unique, json)
        }
        Commands::Replace { pattern, replacement, text, all, ignore_case } => {
            handle_replace(&pattern, &replacement, &text, all, ignore_case)
        }
        Commands::Split { pattern, text, limit, json } => {
            handle_split(&pattern, &text, limit, json)
        }
        Commands::Validate { pattern } => {
            handle_validate(&pattern)
        }
        Commands::Security { pattern, text, file, json } => {
            handle_security(pattern, text.as_deref(), file.as_deref(), json)
        }
        Commands::Explain { pattern } => {
            handle_explain(&pattern)
        }
        Commands::ListPatterns => {
            handle_list_patterns()
        }
        Commands::Interactive => {
            handle_interactive()
        }
    };

    if let Err(e) = result {
        eprintln!("{}: {}", "Error".red().bold(), e);
        std::process::exit(1);
    }
}

fn handle_match(
    pattern: &str,
    text: Option<&str>,
    file: Option<&str>,
    ignore_case: bool,
    multiline: bool,
    dot_all: bool,
    json: bool,
) -> Result<(), RegexError> {
    let input = get_input(text, file)?;
    let result = perform_match(pattern, &input, ignore_case, multiline, dot_all)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&result).unwrap());
    } else {
        print_match_results(&result, &input);
    }

    Ok(())
}

fn handle_test(pattern: &str, text: &str, ignore_case: bool) -> Result<(), RegexError> {
    let regex = build_regex(pattern, ignore_case, false, false)?;
    let matches = regex.is_match(text);

    println!("{}", "Pattern Test".bold().green());
    println!("  Pattern: {}", pattern.cyan());
    println!("  Input:   {}", text);
    println!("  Result:  {}",
        if matches {
            "MATCH".green().bold()
        } else {
            "NO MATCH".red().bold()
        }
    );

    Ok(())
}

fn handle_extract(
    pattern: &str,
    text: Option<&str>,
    file: Option<&str>,
    ignore_case: bool,
    unique: bool,
    json: bool,
) -> Result<(), RegexError> {
    let input = get_input(text, file)?;
    let matches = extract_matches(pattern, &input, ignore_case, unique)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&matches).unwrap());
    } else {
        println!("{} {} extracted", matches.len().to_string().green().bold(),
            if unique { "unique matches" } else { "matches" });
        println!("{}", "-".repeat(40).dimmed());
        for m in &matches {
            println!("  {}", m);
        }
    }

    Ok(())
}

fn handle_replace(
    pattern: &str,
    replacement: &str,
    text: &str,
    all: bool,
    ignore_case: bool,
) -> Result<(), RegexError> {
    let result = perform_replace(pattern, replacement, text, all, ignore_case)?;

    println!("{}", "Pattern Replace".bold().green());
    println!("  Pattern:     {}", pattern.cyan());
    println!("  Replacement: {}", replacement.yellow());
    println!("  Original:    {}", text);
    println!("  Result:      {}", result.green());

    Ok(())
}

fn handle_split(pattern: &str, text: &str, limit: Option<usize>, json: bool) -> Result<(), RegexError> {
    let parts = perform_split(pattern, text, limit)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&parts).unwrap());
    } else {
        println!("{}", "Pattern Split".bold().green());
        println!("  Pattern: {}", pattern.cyan());
        println!("  Parts:   {}", parts.len());
        println!("{}", "-".repeat(40).dimmed());
        for (i, part) in parts.iter().enumerate() {
            println!("  {}: {}", (i + 1).to_string().cyan(), part);
        }
    }

    Ok(())
}

fn handle_validate(pattern: &str) -> Result<(), RegexError> {
    match Regex::new(pattern) {
        Ok(_) => {
            println!("{} Pattern is valid", "OK".green().bold());
            Ok(())
        }
        Err(e) => {
            println!("{} Pattern is invalid", "ERROR".red().bold());
            println!("  {}", e);
            Err(RegexError::PatternError(e.to_string()))
        }
    }
}

fn handle_security(
    pattern_type: SecurityPatternType,
    text: Option<&str>,
    file: Option<&str>,
    json: bool,
) -> Result<(), RegexError> {
    let pattern = get_security_pattern(pattern_type);
    let input = get_input(text, file)?;

    println!("{}", format!("Security Pattern: {:?}", pattern_type).bold().yellow());
    println!("  Regex: {}", pattern.dimmed());
    println!();

    let result = perform_match(pattern, &input, false, true, false)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&result).unwrap());
    } else {
        print_match_results(&result, &input);
    }

    Ok(())
}

fn handle_explain(pattern: &str) -> Result<(), RegexError> {
    // First validate the pattern
    if let Err(e) = Regex::new(pattern) {
        return Err(RegexError::PatternError(e.to_string()));
    }

    let explanation = explain_pattern(pattern);
    println!("{}", "Pattern Explanation".bold().green());
    println!("{}", "=".repeat(50).dimmed());
    println!("{}", explanation);

    Ok(())
}

fn handle_list_patterns() -> Result<(), RegexError> {
    println!("{}", "Built-in Security Patterns".bold().green());
    println!("{}", "=".repeat(60).dimmed());

    let mut patterns: Vec<_> = SECURITY_PATTERNS.iter().collect();
    patterns.sort_by_key(|(k, _)| *k);

    for (name, (pattern, description)) in patterns {
        println!("\n{}", name.cyan().bold());
        println!("  Description: {}", description);
        println!("  Pattern:     {}", pattern.dimmed());
    }

    Ok(())
}

fn handle_interactive() -> Result<(), RegexError> {
    println!("{}", "Interactive Regex Tester".bold().green());
    println!("Enter patterns and text to test. Type 'quit' to exit.\n");

    loop {
        print!("{}", "Pattern> ".cyan());
        io::Write::flush(&mut io::stdout()).unwrap();

        let mut pattern = String::new();
        io::stdin().read_line(&mut pattern).unwrap();
        let pattern = pattern.trim();

        if pattern == "quit" || pattern == "exit" {
            break;
        }

        // Validate pattern first
        if let Err(e) = Regex::new(pattern) {
            println!("{}: {}", "Invalid pattern".red(), e);
            continue;
        }

        print!("{}", "Text> ".yellow());
        io::Write::flush(&mut io::stdout()).unwrap();

        let mut text = String::new();
        io::stdin().read_line(&mut text).unwrap();
        let text = text.trim();

        let regex = Regex::new(pattern).unwrap();
        if regex.is_match(text) {
            println!("{} Pattern matches!", "OK".green().bold());
            for mat in regex.find_iter(text) {
                println!("  Match: {} ({}:{})", mat.as_str().green(), mat.start(), mat.end());
            }
        } else {
            println!("{} No match", "X".red().bold());
        }

        println!();
    }

    Ok(())
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_match() {
        let result = perform_match(r"\d+", "abc123def456", false, false, false).unwrap();
        assert!(result.matched);
        assert_eq!(result.count, 2);
        assert_eq!(result.matches[0].text, "123");
        assert_eq!(result.matches[1].text, "456");
    }

    #[test]
    fn test_case_insensitive() {
        let result = perform_match("hello", "HELLO world", true, false, false).unwrap();
        assert!(result.matched);
        assert_eq!(result.matches[0].text, "HELLO");
    }

    #[test]
    fn test_no_match() {
        let result = perform_match("xyz", "abc123", false, false, false).unwrap();
        assert!(!result.matched);
        assert_eq!(result.count, 0);
    }

    #[test]
    fn test_extract() {
        let matches = extract_matches(r"[a-z]+", "abc 123 def", false, false).unwrap();
        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0], "abc");
        assert_eq!(matches[1], "def");
    }

    #[test]
    fn test_extract_unique() {
        let matches = extract_matches(r"\w+", "hello hello world", false, true).unwrap();
        assert_eq!(matches.len(), 2);  // "hello" only once
    }

    #[test]
    fn test_replace() {
        let result = perform_replace(r"\d+", "X", "a1b2c3", true, false).unwrap();
        assert_eq!(result, "aXbXcX");
    }

    #[test]
    fn test_replace_single() {
        let result = perform_replace(r"\d+", "X", "a1b2c3", false, false).unwrap();
        assert_eq!(result, "aXb2c3");
    }

    #[test]
    fn test_split() {
        let parts = perform_split(r"\s+", "a  b   c", None).unwrap();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts, vec!["a", "b", "c"]);
    }

    #[test]
    fn test_security_pattern_email() {
        let pattern = get_security_pattern(SecurityPatternType::Email);
        let regex = Regex::new(pattern).unwrap();
        assert!(regex.is_match("test@example.com"));
        assert!(!regex.is_match("not an email"));
    }

    #[test]
    fn test_security_pattern_ipv4() {
        let pattern = get_security_pattern(SecurityPatternType::Ipv4);
        let regex = Regex::new(pattern).unwrap();
        assert!(regex.is_match("192.168.1.1"));
        assert!(!regex.is_match("999.999.999.999"));
    }

    #[test]
    fn test_security_pattern_uuid() {
        let pattern = get_security_pattern(SecurityPatternType::Uuid);
        let regex = Regex::new(pattern).unwrap();
        assert!(regex.is_match("550e8400-e29b-41d4-a716-446655440000"));
    }

    #[test]
    fn test_capture_groups() {
        let regex = Regex::new(r"(\w+)@(\w+)\.(\w+)").unwrap();
        let captures = regex.captures("user@example.com").unwrap();
        let groups = extract_captures(&captures);

        assert_eq!(groups.len(), 3);
        assert_eq!(groups[0].text, Some("user".to_string()));
        assert_eq!(groups[1].text, Some("example".to_string()));
        assert_eq!(groups[2].text, Some("com".to_string()));
    }

    #[test]
    fn test_invalid_pattern() {
        let result = build_regex("[invalid", false, false, false);
        assert!(result.is_err());
    }
}
