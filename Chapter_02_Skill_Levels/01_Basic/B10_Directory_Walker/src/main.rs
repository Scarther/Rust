//! # Directory Walker - Security File Discovery Tool
//!
//! This tool recursively walks directories to find files matching specific patterns.
//! Security use cases include:
//! - Finding configuration files that may contain secrets
//! - Discovering backup files (.bak, .old, .swp)
//! - Locating log files for forensic analysis
//! - Identifying potentially sensitive files by extension
//!
//! ## Rust Concepts Covered:
//! - Recursive iteration with walkdir
//! - Pattern matching with glob patterns
//! - Error handling with Result and Option
//! - Struct definitions and implementations
//! - Iterator adapters and closures
//! - File metadata access
//! - Command-line argument parsing

use clap::Parser;
use colored::*;
use chrono::{DateTime, Local};
use humansize::{format_size, BINARY};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use walkdir::{DirEntry, WalkDir};

/// Directory Walker - A security-focused file discovery tool
///
/// Recursively searches directories for files matching specified patterns.
/// Useful for finding configuration files, logs, backups, and sensitive data.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Starting directory to search from
    #[arg(short, long, default_value = ".")]
    directory: PathBuf,

    /// File pattern to match (glob syntax: *.log, *.conf, etc.)
    #[arg(short, long)]
    pattern: Option<String>,

    /// File extension to filter (without dot: txt, log, conf)
    #[arg(short, long)]
    extension: Option<String>,

    /// Maximum depth to recurse (0 = current directory only)
    #[arg(short = 'D', long)]
    max_depth: Option<usize>,

    /// Minimum file size in bytes
    #[arg(long)]
    min_size: Option<u64>,

    /// Maximum file size in bytes
    #[arg(long)]
    max_size: Option<u64>,

    /// Show hidden files (starting with .)
    #[arg(short = 'H', long)]
    hidden: bool,

    /// Show detailed file information
    #[arg(short, long)]
    verbose: bool,

    /// Only show directories
    #[arg(long)]
    dirs_only: bool,

    /// Only show files
    #[arg(long)]
    files_only: bool,

    /// Search for security-sensitive files (configs, keys, logs)
    #[arg(short, long)]
    security_scan: bool,
}

/// Represents information about a discovered file
///
/// This struct demonstrates Rust's data structuring capabilities.
/// The `derive` attribute automatically implements Debug and Clone traits.
#[derive(Debug, Clone)]
struct FileInfo {
    /// Full path to the file
    path: PathBuf,
    /// File name only
    name: String,
    /// File size in bytes
    size: u64,
    /// Last modification time
    modified: Option<SystemTime>,
    /// Whether this is a directory
    is_dir: bool,
    /// File extension if any
    extension: Option<String>,
    /// Security relevance flag
    security_relevant: bool,
}

impl FileInfo {
    /// Creates a new FileInfo from a DirEntry
    ///
    /// This demonstrates:
    /// - Method implementation for structs
    /// - Error handling with Result
    /// - Option handling for potentially missing data
    /// - Pattern matching with if-let
    fn from_entry(entry: &DirEntry) -> Result<Self, std::io::Error> {
        // Get file metadata - this can fail if we lack permissions
        let metadata = entry.metadata()?;

        // Extract the file name, handling the case where it might not be valid UTF-8
        let name = entry.file_name()
            .to_string_lossy()  // Convert OsStr to String, replacing invalid chars
            .to_string();

        // Get the file extension if present
        // `and_then` chains Option operations - only runs if Some
        let extension = entry.path()
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|s| s.to_lowercase());

        // Check if this file might be security-relevant
        let security_relevant = is_security_relevant(&name, &extension);

        Ok(FileInfo {
            path: entry.path().to_path_buf(),
            name,
            size: metadata.len(),
            modified: metadata.modified().ok(),  // Convert Result to Option
            is_dir: metadata.is_dir(),
            extension,
            security_relevant,
        })
    }

    /// Formats the file info for display
    ///
    /// Demonstrates string formatting and conditional colorization
    fn format_output(&self, verbose: bool) -> String {
        if verbose {
            // Verbose output with all details
            let size_str = format_size(self.size, BINARY);
            let modified_str = self.modified
                .map(|t| {
                    // Convert SystemTime to DateTime for formatting
                    let datetime: DateTime<Local> = t.into();
                    datetime.format("%Y-%m-%d %H:%M:%S").to_string()
                })
                .unwrap_or_else(|| "Unknown".to_string());

            let type_indicator = if self.is_dir { "DIR " } else { "FILE" };

            format!(
                "{} {:>10} {} {}",
                type_indicator,
                size_str,
                modified_str,
                self.path.display()
            )
        } else {
            // Simple output - just the path
            self.path.display().to_string()
        }
    }
}

/// Checks if a file might be security-relevant based on name and extension
///
/// This function demonstrates:
/// - Pattern matching with match expressions
/// - Slice patterns for checking prefixes/suffixes
/// - Boolean logic with iterators
fn is_security_relevant(name: &str, extension: &Option<String>) -> bool {
    // Security-sensitive file extensions
    let sensitive_extensions = [
        "pem", "key", "crt", "cer", "p12", "pfx",  // Certificates and keys
        "conf", "config", "cfg", "ini", "yaml", "yml", "toml",  // Config files
        "log", "logs",  // Log files
        "env", "secret", "secrets",  // Environment and secrets
        "sql", "db", "sqlite", "sqlite3",  // Database files
        "bak", "backup", "old", "orig", "swp", "swo",  // Backup files
        "sh", "bash", "zsh", "ps1",  // Shell scripts
        "htpasswd", "htaccess",  // Apache files
    ];

    // Security-sensitive file names
    let sensitive_names = [
        ".env", ".gitconfig", ".netrc", ".npmrc",
        "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
        "known_hosts", "authorized_keys",
        "shadow", "passwd", "sudoers",
        "credentials", "secrets", "password", "passwords",
        ".bash_history", ".zsh_history",
        "wp-config.php", "config.php",
    ];

    // Check extension
    if let Some(ext) = extension {
        if sensitive_extensions.contains(&ext.as_str()) {
            return true;
        }
    }

    // Check file name (case-insensitive)
    let lower_name = name.to_lowercase();
    sensitive_names.iter().any(|&n| lower_name.contains(n))
}

/// Checks if a file matches a glob pattern
///
/// This demonstrates pattern matching against file names
fn matches_pattern(name: &str, pattern: &str) -> bool {
    // Convert glob pattern to a simple matching algorithm
    // This is a simplified implementation - for production use glob crate
    let pattern_lower = pattern.to_lowercase();
    let name_lower = name.to_lowercase();

    if pattern_lower.starts_with('*') && pattern_lower.ends_with('*') {
        // *pattern* - contains
        let inner = &pattern_lower[1..pattern_lower.len()-1];
        name_lower.contains(inner)
    } else if pattern_lower.starts_with('*') {
        // *.ext - ends with
        let suffix = &pattern_lower[1..];
        name_lower.ends_with(suffix)
    } else if pattern_lower.ends_with('*') {
        // prefix* - starts with
        let prefix = &pattern_lower[..pattern_lower.len()-1];
        name_lower.starts_with(prefix)
    } else {
        // Exact match
        name_lower == pattern_lower
    }
}

/// Filters entries based on hidden file rules
///
/// This is a predicate function used with walkdir's filter_entry
fn is_not_hidden(entry: &DirEntry) -> bool {
    entry.file_name()
        .to_str()
        .map(|s| !s.starts_with('.'))
        .unwrap_or(false)  // If we can't read the name, skip it
}

/// Main directory walking function
///
/// This demonstrates:
/// - Iterator chaining and transformation
/// - Closure usage with filter_map
/// - Error handling in iterators
fn walk_directory(args: &Args) -> Vec<FileInfo> {
    // Build the directory walker with configuration
    let mut walker = WalkDir::new(&args.directory);

    // Apply max depth if specified
    // `if let` is a concise way to handle Option
    if let Some(depth) = args.max_depth {
        walker = walker.max_depth(depth + 1);  // +1 because depth 0 means current dir
    }

    // Convert to iterator and apply filters
    let entries: Vec<FileInfo> = walker
        .into_iter()
        // Filter hidden files unless --hidden is specified
        .filter_entry(|e| args.hidden || is_not_hidden(e))
        // Filter out errors (permission denied, etc.) and convert to FileInfo
        .filter_map(|entry| {
            // `ok()` converts Result to Option, discarding errors
            entry.ok().and_then(|e| FileInfo::from_entry(&e).ok())
        })
        // Apply pattern filter
        .filter(|info| {
            if let Some(ref pattern) = args.pattern {
                matches_pattern(&info.name, pattern)
            } else {
                true  // No pattern = match all
            }
        })
        // Apply extension filter
        .filter(|info| {
            if let Some(ref ext) = args.extension {
                info.extension.as_ref().map_or(false, |e| e == ext)
            } else {
                true
            }
        })
        // Apply size filters
        .filter(|info| {
            let min_ok = args.min_size.map_or(true, |min| info.size >= min);
            let max_ok = args.max_size.map_or(true, |max| info.size <= max);
            min_ok && max_ok
        })
        // Apply directory/file only filters
        .filter(|info| {
            if args.dirs_only {
                info.is_dir
            } else if args.files_only {
                !info.is_dir
            } else {
                true
            }
        })
        // Apply security scan filter
        .filter(|info| {
            if args.security_scan {
                info.security_relevant
            } else {
                true
            }
        })
        .collect();

    entries
}

/// Prints a summary of the scan results
fn print_summary(files: &[FileInfo]) {
    let total_files = files.iter().filter(|f| !f.is_dir).count();
    let total_dirs = files.iter().filter(|f| f.is_dir).count();
    let total_size: u64 = files.iter().filter(|f| !f.is_dir).map(|f| f.size).sum();
    let security_files = files.iter().filter(|f| f.security_relevant).count();

    println!("\n{}", "=".repeat(60).dimmed());
    println!("{}", "Scan Summary".bold());
    println!("{}", "=".repeat(60).dimmed());
    println!("  Files found:     {}", total_files.to_string().cyan());
    println!("  Directories:     {}", total_dirs.to_string().cyan());
    println!("  Total size:      {}", format_size(total_size, BINARY).cyan());
    if security_files > 0 {
        println!("  Security files:  {}", security_files.to_string().yellow().bold());
    }
}

fn main() {
    // Parse command-line arguments
    let args = Args::parse();

    // Validate that the directory exists
    if !args.directory.exists() {
        eprintln!("{}: Directory not found: {}",
            "Error".red().bold(),
            args.directory.display()
        );
        std::process::exit(1);
    }

    // Print scan header
    println!("{}", "Directory Walker - Security File Scanner".bold().green());
    println!("Scanning: {}", args.directory.display().to_string().cyan());
    if let Some(ref pattern) = args.pattern {
        println!("Pattern: {}", pattern.yellow());
    }
    if args.security_scan {
        println!("{}", "Security scan mode enabled".yellow().bold());
    }
    println!("{}", "-".repeat(60).dimmed());

    // Perform the directory walk
    let files = walk_directory(&args);

    // Display results
    for file in &files {
        let output = file.format_output(args.verbose);

        // Colorize based on security relevance
        if file.security_relevant {
            if file.is_dir {
                println!("{}", output.yellow());
            } else {
                println!("{}", output.red().bold());
            }
        } else if file.is_dir {
            println!("{}", output.blue());
        } else {
            println!("{}", output);
        }
    }

    // Print summary
    print_summary(&files);
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use std::fs::File;

    /// Test pattern matching function
    #[test]
    fn test_pattern_matching() {
        // Test wildcard suffix
        assert!(matches_pattern("config.log", "*.log"));
        assert!(!matches_pattern("config.txt", "*.log"));

        // Test wildcard prefix
        assert!(matches_pattern("config.txt", "config*"));
        assert!(!matches_pattern("settings.txt", "config*"));

        // Test contains
        assert!(matches_pattern("my_config_file.txt", "*config*"));

        // Test exact match
        assert!(matches_pattern("exact.txt", "exact.txt"));

        // Test case insensitivity
        assert!(matches_pattern("CONFIG.LOG", "*.log"));
    }

    /// Test security relevance detection
    #[test]
    fn test_security_relevance() {
        // Test sensitive extensions
        assert!(is_security_relevant("server.pem", &Some("pem".to_string())));
        assert!(is_security_relevant("app.conf", &Some("conf".to_string())));
        assert!(is_security_relevant("debug.log", &Some("log".to_string())));

        // Test sensitive file names
        assert!(is_security_relevant(".env", &None));
        assert!(is_security_relevant("id_rsa", &None));
        assert!(is_security_relevant("passwords.txt", &Some("txt".to_string())));

        // Test non-sensitive files
        assert!(!is_security_relevant("readme.md", &Some("md".to_string())));
        assert!(!is_security_relevant("main.rs", &Some("rs".to_string())));
    }

    /// Test hidden file detection
    #[test]
    fn test_hidden_detection() {
        let temp_dir = TempDir::new().unwrap();
        let hidden_path = temp_dir.path().join(".hidden_file");
        let visible_path = temp_dir.path().join("visible_file");

        File::create(&hidden_path).unwrap();
        File::create(&visible_path).unwrap();

        // Walk and check visibility
        let walker = WalkDir::new(temp_dir.path()).max_depth(1);
        let hidden_count = walker
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| !is_not_hidden(e))
            .count();

        assert!(hidden_count >= 1);  // At least our hidden file
    }

    /// Test FileInfo creation
    #[test]
    fn test_file_info_creation() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.conf");

        // Create a file with some content
        std::fs::write(&test_file, "test content").unwrap();

        // Walk and get the file info
        let entries: Vec<_> = WalkDir::new(temp_dir.path())
            .max_depth(1)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_str() == Some("test.conf"))
            .collect();

        assert_eq!(entries.len(), 1);

        let info = FileInfo::from_entry(&entries[0]).unwrap();
        assert_eq!(info.name, "test.conf");
        assert_eq!(info.extension, Some("conf".to_string()));
        assert!(info.security_relevant);  // .conf is security-relevant
        assert!(!info.is_dir);
        assert_eq!(info.size, 12);  // "test content" = 12 bytes
    }

    /// Test directory walking with arguments
    #[test]
    fn test_walk_directory() {
        let temp_dir = TempDir::new().unwrap();

        // Create test files
        std::fs::write(temp_dir.path().join("file1.log"), "log").unwrap();
        std::fs::write(temp_dir.path().join("file2.txt"), "txt").unwrap();
        std::fs::write(temp_dir.path().join("file3.log"), "log").unwrap();

        // Create args for .log files only
        let args = Args {
            directory: temp_dir.path().to_path_buf(),
            pattern: Some("*.log".to_string()),
            extension: None,
            max_depth: Some(1),
            min_size: None,
            max_size: None,
            hidden: false,
            verbose: false,
            dirs_only: false,
            files_only: true,
            security_scan: false,
        };

        let files = walk_directory(&args);

        // Should find exactly 2 .log files
        let log_files: Vec<_> = files.iter()
            .filter(|f| f.name.ends_with(".log"))
            .collect();

        assert_eq!(log_files.len(), 2);
    }
}
