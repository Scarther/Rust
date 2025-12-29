//! # String Search - Security-Focused Grep Alternative
//!
//! A powerful string/pattern search tool designed for security analysis.
//! Use cases include:
//! - Searching for hardcoded credentials in source code
//! - Finding API keys and secrets in configuration files
//! - Locating IP addresses and URLs in log files
//! - Detecting suspicious patterns in system files
//!
//! ## Rust Concepts Covered:
//! - Regular expressions with the regex crate
//! - File I/O and buffered reading
//! - Memory-mapped files for large file handling
//! - Parallel processing with rayon
//! - Error handling and propagation
//! - Enums for representing search modes
//! - Traits and trait bounds

use clap::{Parser, ValueEnum};
use colored::*;
use memmap2::Mmap;
use rayon::prelude::*;
use regex::{Regex, RegexBuilder};
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use walkdir::WalkDir;

/// String Search - Security-focused pattern matching tool
///
/// Searches files for strings or patterns, similar to grep but with
/// security-focused features like built-in patterns for secrets detection.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Pattern to search for (string or regex)
    pattern: String,

    /// Files or directories to search
    #[arg(default_value = ".")]
    paths: Vec<PathBuf>,

    /// Treat pattern as regular expression
    #[arg(short, long)]
    regex: bool,

    /// Case-insensitive search
    #[arg(short, long)]
    ignore_case: bool,

    /// Show line numbers
    #[arg(short = 'n', long)]
    line_numbers: bool,

    /// Only show matching file names
    #[arg(short = 'l', long)]
    files_only: bool,

    /// Count matches per file
    #[arg(short, long)]
    count: bool,

    /// Invert match (show non-matching lines)
    #[arg(short = 'v', long)]
    invert: bool,

    /// Show N lines before match
    #[arg(short = 'B', long, default_value = "0")]
    before: usize,

    /// Show N lines after match
    #[arg(short = 'A', long, default_value = "0")]
    after: usize,

    /// Recursive directory search
    #[arg(short = 'R', long)]
    recursive: bool,

    /// File extension filter (e.g., rs, py, js)
    #[arg(short, long)]
    extension: Option<String>,

    /// Use built-in security pattern
    #[arg(short, long, value_enum)]
    security_pattern: Option<SecurityPattern>,

    /// Maximum file size to search (in MB)
    #[arg(long, default_value = "50")]
    max_size_mb: u64,

    /// Show only unique matches
    #[arg(short, long)]
    unique: bool,

    /// Enable parallel searching
    #[arg(short, long)]
    parallel: bool,
}

/// Pre-defined security-focused search patterns
///
/// This enum demonstrates Rust's powerful enum system with
/// ValueEnum derive for CLI parsing.
#[derive(Debug, Clone, Copy, ValueEnum)]
enum SecurityPattern {
    /// AWS Access Keys
    AwsKey,
    /// API Keys and Tokens
    ApiKey,
    /// Private Keys
    PrivateKey,
    /// Passwords in code
    Password,
    /// IP Addresses
    IpAddress,
    /// Email Addresses
    Email,
    /// URLs
    Url,
    /// JWT Tokens
    Jwt,
    /// Base64 encoded strings
    Base64,
    /// Credit Card Numbers
    CreditCard,
}

impl SecurityPattern {
    /// Returns the regex pattern for each security pattern type
    ///
    /// Demonstrates match expression with enum variants
    fn to_regex(&self) -> &'static str {
        match self {
            // AWS Access Key pattern: AKIA followed by 16 alphanumeric chars
            SecurityPattern::AwsKey => r"AKIA[0-9A-Z]{16}",

            // Generic API key patterns
            SecurityPattern::ApiKey => r"(?i)(api[_-]?key|apikey|api[_-]?token)['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{20,})",

            // Private key headers
            SecurityPattern::PrivateKey => r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----",

            // Password assignments in code
            SecurityPattern::Password => r"(?i)(password|passwd|pwd|secret)['\"]?\s*[:=]\s*['\"]?[^\s'\"]{4,}",

            // IPv4 addresses
            SecurityPattern::IpAddress => r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",

            // Email addresses
            SecurityPattern::Email => r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",

            // URLs with protocol
            SecurityPattern::Url => r"https?://[^\s<>\"\\']+",

            // JWT tokens (three base64 segments)
            SecurityPattern::Jwt => r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*",

            // Base64 encoded strings (at least 20 chars)
            SecurityPattern::Base64 => r"(?:[A-Za-z0-9+/]{4}){5,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?",

            // Credit card numbers (basic pattern)
            SecurityPattern::CreditCard => r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b",
        }
    }

    /// Returns a description of what the pattern matches
    fn description(&self) -> &'static str {
        match self {
            SecurityPattern::AwsKey => "AWS Access Key IDs",
            SecurityPattern::ApiKey => "API Keys and Tokens",
            SecurityPattern::PrivateKey => "Private Key Files",
            SecurityPattern::Password => "Hardcoded Passwords",
            SecurityPattern::IpAddress => "IP Addresses",
            SecurityPattern::Email => "Email Addresses",
            SecurityPattern::Url => "URLs",
            SecurityPattern::Jwt => "JWT Tokens",
            SecurityPattern::Base64 => "Base64 Encoded Strings",
            SecurityPattern::CreditCard => "Credit Card Numbers",
        }
    }
}

/// Represents a single match result
///
/// Contains all information needed to display a match
#[derive(Debug, Clone)]
struct SearchMatch {
    /// File where match was found
    file: PathBuf,
    /// Line number (1-indexed)
    line_number: usize,
    /// The matching line content
    line: String,
    /// Start position of match in line
    match_start: usize,
    /// End position of match in line
    match_end: usize,
}

/// Represents search results for a file
#[derive(Debug)]
struct FileResults {
    file: PathBuf,
    matches: Vec<SearchMatch>,
    error: Option<String>,
}

/// Builds the search regex based on arguments
///
/// Demonstrates error handling and regex builder pattern
fn build_regex(args: &Args) -> Result<Regex, regex::Error> {
    // Determine the pattern to use
    let pattern = if let Some(ref sec_pattern) = args.security_pattern {
        sec_pattern.to_regex().to_string()
    } else if args.regex {
        args.pattern.clone()
    } else {
        // Escape special regex characters for literal search
        regex::escape(&args.pattern)
    };

    // Build regex with options
    RegexBuilder::new(&pattern)
        .case_insensitive(args.ignore_case)
        .build()
}

/// Searches a single file for matches
///
/// This function demonstrates:
/// - File I/O with BufReader for efficient line-by-line reading
/// - Iterator processing with enumerate
/// - Error handling with Result propagation
fn search_file(path: &Path, regex: &Regex, args: &Args) -> FileResults {
    let mut results = FileResults {
        file: path.to_path_buf(),
        matches: Vec::new(),
        error: None,
    };

    // Check file size
    let metadata = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) => {
            results.error = Some(format!("Cannot read metadata: {}", e));
            return results;
        }
    };

    let max_size = args.max_size_mb * 1024 * 1024;
    if metadata.len() > max_size {
        results.error = Some(format!("File too large ({}MB limit)", args.max_size_mb));
        return results;
    }

    // Open and read the file
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) => {
            results.error = Some(format!("Cannot open file: {}", e));
            return results;
        }
    };

    let reader = BufReader::new(file);

    // Process each line
    // `enumerate()` gives us (index, value) pairs
    for (line_num, line_result) in reader.lines().enumerate() {
        let line = match line_result {
            Ok(l) => l,
            Err(_) => continue,  // Skip binary/unreadable lines
        };

        // Check if line matches
        let is_match = regex.is_match(&line);

        // Handle invert flag
        let should_include = if args.invert { !is_match } else { is_match };

        if should_include {
            // Find match positions for highlighting
            if let Some(m) = regex.find(&line) {
                results.matches.push(SearchMatch {
                    file: path.to_path_buf(),
                    line_number: line_num + 1,  // 1-indexed
                    line: line.clone(),
                    match_start: m.start(),
                    match_end: m.end(),
                });
            } else if args.invert {
                // For inverted matches, we don't have a specific match position
                results.matches.push(SearchMatch {
                    file: path.to_path_buf(),
                    line_number: line_num + 1,
                    line: line.clone(),
                    match_start: 0,
                    match_end: 0,
                });
            }
        }
    }

    results
}

/// Searches a file using memory-mapping for large files
///
/// Memory mapping allows the OS to handle file buffering efficiently
fn search_file_mmap(path: &Path, regex: &Regex, args: &Args) -> FileResults {
    let mut results = FileResults {
        file: path.to_path_buf(),
        matches: Vec::new(),
        error: None,
    };

    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) => {
            results.error = Some(format!("Cannot open file: {}", e));
            return results;
        }
    };

    // Memory-map the file
    // SAFETY: We only read from the mmap, and the file won't be modified
    let mmap = match unsafe { Mmap::map(&file) } {
        Ok(m) => m,
        Err(e) => {
            results.error = Some(format!("Cannot mmap file: {}", e));
            return results;
        }
    };

    // Convert to string (may fail for binary files)
    let content = match std::str::from_utf8(&mmap) {
        Ok(s) => s,
        Err(_) => {
            // Fall back to regular search for binary files
            return search_file(path, regex, args);
        }
    };

    // Process line by line
    for (line_num, line) in content.lines().enumerate() {
        let is_match = regex.is_match(line);
        let should_include = if args.invert { !is_match } else { is_match };

        if should_include {
            if let Some(m) = regex.find(line) {
                results.matches.push(SearchMatch {
                    file: path.to_path_buf(),
                    line_number: line_num + 1,
                    line: line.to_string(),
                    match_start: m.start(),
                    match_end: m.end(),
                });
            }
        }
    }

    results
}

/// Collects all files to search based on arguments
///
/// Demonstrates walkdir usage and iterator filtering
fn collect_files(args: &Args) -> Vec<PathBuf> {
    let mut files = Vec::new();

    for path in &args.paths {
        if path.is_file() {
            files.push(path.clone());
        } else if path.is_dir() {
            // Walk directory
            let walker = if args.recursive {
                WalkDir::new(path)
            } else {
                WalkDir::new(path).max_depth(1)
            };

            for entry in walker.into_iter().filter_map(|e| e.ok()) {
                let entry_path = entry.path();

                // Skip directories
                if entry_path.is_dir() {
                    continue;
                }

                // Apply extension filter
                if let Some(ref ext) = args.extension {
                    let file_ext = entry_path.extension()
                        .and_then(|e| e.to_str())
                        .unwrap_or("");
                    if file_ext != ext {
                        continue;
                    }
                }

                files.push(entry_path.to_path_buf());
            }
        }
    }

    files
}

/// Formats and prints a single match with context
///
/// Demonstrates string manipulation and terminal coloring
fn print_match(search_match: &SearchMatch, args: &Args, show_filename: bool) {
    let mut output = String::new();

    // Add filename if searching multiple files
    if show_filename {
        output.push_str(&format!("{}:", search_match.file.display().to_string().magenta()));
    }

    // Add line number if requested
    if args.line_numbers {
        output.push_str(&format!("{}:", search_match.line_number.to_string().green()));
    }

    // Highlight the match in the line
    if search_match.match_start < search_match.match_end {
        let before = &search_match.line[..search_match.match_start];
        let matched = &search_match.line[search_match.match_start..search_match.match_end];
        let after = &search_match.line[search_match.match_end..];

        output.push_str(before);
        output.push_str(&matched.red().bold().to_string());
        output.push_str(after);
    } else {
        output.push_str(&search_match.line);
    }

    println!("{}", output);
}

/// Prints results for a file
fn print_file_results(results: &FileResults, args: &Args, show_filename: bool) {
    if let Some(ref error) = results.error {
        eprintln!("{}: {}", results.file.display().to_string().red(), error);
        return;
    }

    if results.matches.is_empty() {
        return;
    }

    // Files only mode
    if args.files_only {
        println!("{}", results.file.display().to_string().magenta());
        return;
    }

    // Count mode
    if args.count {
        println!("{}:{}",
            results.file.display().to_string().magenta(),
            results.matches.len().to_string().cyan()
        );
        return;
    }

    // Regular output
    for m in &results.matches {
        print_match(m, args, show_filename);
    }
}

fn main() {
    let args = Args::parse();

    // Build the regex
    let regex = match build_regex(&args) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{}: Invalid pattern: {}", "Error".red().bold(), e);
            std::process::exit(1);
        }
    };

    // Print security pattern info if used
    if let Some(ref pattern) = args.security_pattern {
        println!("{} Searching for: {}",
            "[Security Scan]".yellow().bold(),
            pattern.description().cyan()
        );
        println!("{}", "-".repeat(60).dimmed());
    }

    // Collect files to search
    let files = collect_files(&args);

    if files.is_empty() {
        eprintln!("{}: No files to search", "Warning".yellow());
        std::process::exit(0);
    }

    let show_filename = files.len() > 1;
    let total_matches = AtomicUsize::new(0);

    // Search files (optionally in parallel)
    if args.parallel && files.len() > 1 {
        // Parallel search using rayon
        let results: Vec<FileResults> = files
            .par_iter()  // Parallel iterator
            .map(|path| search_file_mmap(path, &regex, &args))
            .collect();

        for result in &results {
            total_matches.fetch_add(result.matches.len(), Ordering::Relaxed);
            print_file_results(result, &args, show_filename);
        }
    } else {
        // Sequential search
        for path in &files {
            let result = search_file_mmap(path, &regex, &args);
            total_matches.fetch_add(result.matches.len(), Ordering::Relaxed);
            print_file_results(&result, &args, show_filename);
        }
    }

    // Print summary
    let total = total_matches.load(Ordering::Relaxed);
    if total > 0 {
        println!("{}", "-".repeat(60).dimmed());
        println!("Total matches: {}", total.to_string().green().bold());
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use std::io::Write;

    /// Test security pattern regex compilation
    #[test]
    fn test_security_patterns_compile() {
        // All security patterns should compile without error
        for pattern in [
            SecurityPattern::AwsKey,
            SecurityPattern::ApiKey,
            SecurityPattern::PrivateKey,
            SecurityPattern::Password,
            SecurityPattern::IpAddress,
            SecurityPattern::Email,
            SecurityPattern::Url,
            SecurityPattern::Jwt,
            SecurityPattern::Base64,
            SecurityPattern::CreditCard,
        ] {
            let regex_str = pattern.to_regex();
            let result = Regex::new(regex_str);
            assert!(result.is_ok(), "Pattern {:?} failed to compile: {:?}", pattern, result);
        }
    }

    /// Test AWS key detection
    #[test]
    fn test_aws_key_pattern() {
        let regex = Regex::new(SecurityPattern::AwsKey.to_regex()).unwrap();

        assert!(regex.is_match("AKIAIOSFODNN7EXAMPLE"));
        assert!(!regex.is_match("AKIA123"));  // Too short
        assert!(!regex.is_match("NOTAKEY12345678901234"));
    }

    /// Test IP address pattern
    #[test]
    fn test_ip_address_pattern() {
        let regex = Regex::new(SecurityPattern::IpAddress.to_regex()).unwrap();

        assert!(regex.is_match("192.168.1.1"));
        assert!(regex.is_match("10.0.0.1"));
        assert!(regex.is_match("255.255.255.255"));
        assert!(!regex.is_match("256.1.1.1"));  // Invalid octet
        assert!(!regex.is_match("192.168.1"));  // Incomplete
    }

    /// Test email pattern
    #[test]
    fn test_email_pattern() {
        let regex = Regex::new(SecurityPattern::Email.to_regex()).unwrap();

        assert!(regex.is_match("user@example.com"));
        assert!(regex.is_match("test.user+tag@domain.co.uk"));
        assert!(!regex.is_match("not-an-email"));
    }

    /// Test URL pattern
    #[test]
    fn test_url_pattern() {
        let regex = Regex::new(SecurityPattern::Url.to_regex()).unwrap();

        assert!(regex.is_match("https://example.com"));
        assert!(regex.is_match("http://localhost:8080/path?query=1"));
        assert!(!regex.is_match("ftp://example.com"));  // Only http/https
    }

    /// Test file searching
    #[test]
    fn test_search_file() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.txt");

        let mut file = File::create(&test_file).unwrap();
        writeln!(file, "This is line one").unwrap();
        writeln!(file, "This line contains SECRET_KEY=abc123").unwrap();
        writeln!(file, "This is line three").unwrap();
        writeln!(file, "Another SECRET_KEY=xyz789 here").unwrap();

        let regex = Regex::new("SECRET_KEY").unwrap();
        let args = Args {
            pattern: "SECRET_KEY".to_string(),
            paths: vec![test_file.clone()],
            regex: false,
            ignore_case: false,
            line_numbers: false,
            files_only: false,
            count: false,
            invert: false,
            before: 0,
            after: 0,
            recursive: false,
            extension: None,
            security_pattern: None,
            max_size_mb: 50,
            unique: false,
            parallel: false,
        };

        let results = search_file(&test_file, &regex, &args);

        assert!(results.error.is_none());
        assert_eq!(results.matches.len(), 2);
        assert_eq!(results.matches[0].line_number, 2);
        assert_eq!(results.matches[1].line_number, 4);
    }

    /// Test case-insensitive search
    #[test]
    fn test_case_insensitive() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.txt");

        let mut file = File::create(&test_file).unwrap();
        writeln!(file, "PASSWORD=secret").unwrap();
        writeln!(file, "password=secret").unwrap();
        writeln!(file, "Password=secret").unwrap();

        let regex = RegexBuilder::new("password")
            .case_insensitive(true)
            .build()
            .unwrap();

        let args = Args {
            pattern: "password".to_string(),
            paths: vec![test_file.clone()],
            regex: false,
            ignore_case: true,
            line_numbers: false,
            files_only: false,
            count: false,
            invert: false,
            before: 0,
            after: 0,
            recursive: false,
            extension: None,
            security_pattern: None,
            max_size_mb: 50,
            unique: false,
            parallel: false,
        };

        let results = search_file(&test_file, &regex, &args);

        assert_eq!(results.matches.len(), 3);
    }

    /// Test inverted search
    #[test]
    fn test_invert_match() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.txt");

        let mut file = File::create(&test_file).unwrap();
        writeln!(file, "keep this line").unwrap();
        writeln!(file, "REMOVE this line").unwrap();
        writeln!(file, "keep this too").unwrap();

        let regex = Regex::new("REMOVE").unwrap();
        let args = Args {
            pattern: "REMOVE".to_string(),
            paths: vec![test_file.clone()],
            regex: false,
            ignore_case: false,
            line_numbers: false,
            files_only: false,
            count: false,
            invert: true,  // Invert!
            before: 0,
            after: 0,
            recursive: false,
            extension: None,
            security_pattern: None,
            max_size_mb: 50,
            unique: false,
            parallel: false,
        };

        let results = search_file(&test_file, &regex, &args);

        assert_eq!(results.matches.len(), 2);  // Two lines that don't contain REMOVE
    }

    /// Test file collection with extension filter
    #[test]
    fn test_collect_files_extension() {
        let temp_dir = TempDir::new().unwrap();

        File::create(temp_dir.path().join("file1.rs")).unwrap();
        File::create(temp_dir.path().join("file2.rs")).unwrap();
        File::create(temp_dir.path().join("file3.txt")).unwrap();

        let args = Args {
            pattern: "test".to_string(),
            paths: vec![temp_dir.path().to_path_buf()],
            regex: false,
            ignore_case: false,
            line_numbers: false,
            files_only: false,
            count: false,
            invert: false,
            before: 0,
            after: 0,
            recursive: true,
            extension: Some("rs".to_string()),
            security_pattern: None,
            max_size_mb: 50,
            unique: false,
            parallel: false,
        };

        let files = collect_files(&args);

        assert_eq!(files.len(), 2);  // Only .rs files
    }
}
