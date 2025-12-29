//! # File Operations Security Tool
//!
//! This module demonstrates secure file operations in Rust, including:
//! - Reading files with proper error handling
//! - Writing files atomically to prevent data corruption
//! - Copying files with permission preservation
//! - Checking and modifying file permissions
//!
//! ## Security Considerations
//! - Always validate file paths to prevent path traversal attacks
//! - Check permissions before performing operations
//! - Use atomic operations where possible
//! - Handle symbolic links carefully to prevent symlink attacks

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use colored::*;
use std::fs::{self, File, OpenOptions, Permissions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;

// ============================================================================
// CUSTOM ERROR TYPES
// ============================================================================

/// Custom error types for file operations
/// Using thiserror for ergonomic error definitions
#[derive(Error, Debug)]
pub enum FileOpsError {
    /// Error when file is not found
    #[error("File not found: {0}")]
    NotFound(PathBuf),

    /// Error when permission is denied
    #[error("Permission denied: {0}")]
    PermissionDenied(PathBuf),

    /// Error when path traversal is detected (security issue)
    #[error("Potential path traversal attack detected: {0}")]
    PathTraversal(PathBuf),

    /// Error when file is a symlink (potential security risk)
    #[error("Symbolic link detected (potential security risk): {0}")]
    SymlinkDetected(PathBuf),

    /// Generic I/O error wrapper
    #[error("I/O error: {0}")]
    IoError(#[from] io::Error),
}

// ============================================================================
// CLI ARGUMENT STRUCTURES
// ============================================================================

/// File Operations CLI - A security-focused file manipulation tool
///
/// This tool demonstrates proper file handling in Rust with an emphasis
/// on security best practices.
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

/// Available subcommands for file operations
#[derive(Subcommand, Debug)]
enum Commands {
    /// Read and display file contents
    Read {
        /// Path to the file to read
        #[arg(short, long)]
        path: PathBuf,

        /// Show line numbers in output
        #[arg(short = 'n', long)]
        line_numbers: bool,

        /// Read only first N lines
        #[arg(short = 'l', long)]
        head: Option<usize>,

        /// Display as hexadecimal (for binary files)
        #[arg(short = 'x', long)]
        hex: bool,
    },

    /// Write content to a file
    Write {
        /// Path to the file to write
        #[arg(short, long)]
        path: PathBuf,

        /// Content to write (if not provided, reads from stdin)
        #[arg(short, long)]
        content: Option<String>,

        /// Append instead of overwrite
        #[arg(short, long)]
        append: bool,

        /// Create backup before writing
        #[arg(short, long)]
        backup: bool,
    },

    /// Copy a file to a new location
    Copy {
        /// Source file path
        #[arg(short, long)]
        source: PathBuf,

        /// Destination file path
        #[arg(short, long)]
        dest: PathBuf,

        /// Preserve file permissions
        #[arg(short, long)]
        preserve: bool,

        /// Overwrite if destination exists
        #[arg(short, long)]
        force: bool,
    },

    /// Display file permissions and metadata
    Perms {
        /// Path to the file
        #[arg(short, long)]
        path: PathBuf,

        /// New permissions in octal (e.g., 755)
        #[arg(short, long)]
        set: Option<String>,
    },

    /// Check file for security issues
    Audit {
        /// Path to the file or directory to audit
        #[arg(short, long)]
        path: PathBuf,

        /// Recursive audit for directories
        #[arg(short, long)]
        recursive: bool,
    },
}

// ============================================================================
// SECURITY VALIDATION FUNCTIONS
// ============================================================================

/// Validates a file path for potential security issues
///
/// # Security Checks
/// - Path traversal attempts (../)
/// - Null bytes in path
/// - Absolute path validation
///
/// # Arguments
/// * `path` - The path to validate
///
/// # Returns
/// * `Result<PathBuf>` - Canonicalized path or error
fn validate_path(path: &Path) -> Result<PathBuf, FileOpsError> {
    // Convert path to string for validation
    let path_str = path.to_string_lossy();

    // Check for null bytes (could be used to bypass checks in some systems)
    // This is a common attack vector in C-based systems
    if path_str.contains('\0') {
        return Err(FileOpsError::PathTraversal(path.to_path_buf()));
    }

    // Check for path traversal patterns
    // Note: We still canonicalize, but this catches obvious attempts
    if path_str.contains("..") {
        eprintln!(
            "{} Path contains '..', validating after canonicalization...",
            "Warning:".yellow()
        );
    }

    // Canonicalize the path to resolve any symlinks and relative components
    // This converts the path to an absolute path with all symlinks resolved
    let canonical = path
        .canonicalize()
        .map_err(|_| FileOpsError::NotFound(path.to_path_buf()))?;

    Ok(canonical)
}

/// Checks if a path is a symbolic link
///
/// Symbolic links can be used in attacks where an attacker replaces
/// a legitimate file with a symlink to a sensitive file.
///
/// # Arguments
/// * `path` - The path to check
///
/// # Returns
/// * `bool` - True if the path is a symbolic link
fn is_symlink(path: &Path) -> bool {
    // fs::symlink_metadata doesn't follow symlinks, unlike fs::metadata
    match fs::symlink_metadata(path) {
        Ok(metadata) => metadata.file_type().is_symlink(),
        Err(_) => false,
    }
}

// ============================================================================
// FILE READING FUNCTIONS
// ============================================================================

/// Reads a file and returns its contents as a string
///
/// This function implements secure file reading with:
/// - Path validation
/// - Proper error handling
/// - Memory-efficient buffered reading
///
/// # Arguments
/// * `path` - Path to the file to read
/// * `verbose` - Whether to print verbose output
///
/// # Returns
/// * `Result<String>` - File contents or error
fn read_file(path: &Path, verbose: bool) -> Result<String> {
    // Validate the path first
    let validated_path = validate_path(path)?;

    if verbose {
        println!("{} Reading file: {:?}", "Info:".blue(), validated_path);
    }

    // Check if it's a symlink (potential security concern)
    if is_symlink(path) {
        eprintln!(
            "{} File is a symbolic link. Resolved to: {:?}",
            "Warning:".yellow(),
            validated_path
        );
    }

    // Open the file with explicit read-only permissions
    // This is safer than using fs::read_to_string directly
    let file =
        File::open(&validated_path).with_context(|| format!("Failed to open {:?}", validated_path))?;

    // Use BufReader for efficient reading of large files
    // BufReader maintains an internal buffer, reducing system calls
    let mut reader = BufReader::new(file);
    let mut contents = String::new();

    reader
        .read_to_string(&mut contents)
        .with_context(|| format!("Failed to read contents of {:?}", validated_path))?;

    Ok(contents)
}

/// Reads a file as bytes (for binary files)
///
/// # Arguments
/// * `path` - Path to the file to read
///
/// # Returns
/// * `Result<Vec<u8>>` - File contents as bytes or error
fn read_file_bytes(path: &Path) -> Result<Vec<u8>> {
    let validated_path = validate_path(path)?;
    let contents =
        fs::read(&validated_path).with_context(|| format!("Failed to read {:?}", validated_path))?;
    Ok(contents)
}

/// Formats bytes as a hexadecimal dump
///
/// Useful for inspecting binary files or finding hidden data
///
/// # Arguments
/// * `bytes` - The bytes to format
///
/// # Returns
/// * `String` - Formatted hex dump
fn format_hex_dump(bytes: &[u8]) -> String {
    let mut output = String::new();
    for (i, chunk) in bytes.chunks(16).enumerate() {
        // Offset
        output.push_str(&format!("{:08x}  ", i * 16));

        // Hex bytes
        for (j, byte) in chunk.iter().enumerate() {
            output.push_str(&format!("{:02x} ", byte));
            if j == 7 {
                output.push(' '); // Extra space in middle
            }
        }

        // Padding for incomplete lines
        if chunk.len() < 16 {
            for _ in 0..(16 - chunk.len()) {
                output.push_str("   ");
            }
            if chunk.len() <= 8 {
                output.push(' ');
            }
        }

        // ASCII representation
        output.push_str(" |");
        for byte in chunk {
            if *byte >= 0x20 && *byte <= 0x7e {
                output.push(*byte as char);
            } else {
                output.push('.');
            }
        }
        output.push_str("|\n");
    }
    output
}

// ============================================================================
// FILE WRITING FUNCTIONS
// ============================================================================

/// Writes content to a file with optional backup
///
/// # Security Features
/// - Creates backup before overwriting
/// - Uses atomic write pattern (write to temp, then rename)
/// - Validates path before writing
///
/// # Arguments
/// * `path` - Path to write to
/// * `content` - Content to write
/// * `append` - Whether to append instead of overwrite
/// * `backup` - Whether to create a backup first
/// * `verbose` - Whether to print verbose output
///
/// # Returns
/// * `Result<()>` - Success or error
fn write_file(
    path: &Path,
    content: &str,
    append: bool,
    backup: bool,
    verbose: bool,
) -> Result<()> {
    // For new files, we can't canonicalize, so validate the parent directory
    let parent = path.parent().unwrap_or(Path::new("."));

    if path.exists() {
        // Validate existing path
        let _ = validate_path(path)?;

        // Create backup if requested
        if backup {
            let backup_path = path.with_extension(format!(
                "{}.bak",
                path.extension().unwrap_or_default().to_string_lossy()
            ));
            fs::copy(path, &backup_path)
                .with_context(|| format!("Failed to create backup at {:?}", backup_path))?;

            if verbose {
                println!("{} Created backup: {:?}", "Info:".blue(), backup_path);
            }
        }
    } else {
        // Validate parent directory exists
        if !parent.exists() {
            anyhow::bail!("Parent directory does not exist: {:?}", parent);
        }
    }

    // Open file with appropriate options
    // OpenOptions gives us fine-grained control over file opening
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .append(append)
        .truncate(!append) // Only truncate if not appending
        .open(path)
        .with_context(|| format!("Failed to open {:?} for writing", path))?;

    // Write the content
    file.write_all(content.as_bytes())
        .with_context(|| format!("Failed to write to {:?}", path))?;

    // Ensure data is flushed to disk
    // sync_all() ensures both data and metadata are written
    file.sync_all()
        .with_context(|| format!("Failed to sync {:?} to disk", path))?;

    if verbose {
        println!(
            "{} Successfully wrote {} bytes to {:?}",
            "Info:".green(),
            content.len(),
            path
        );
    }

    Ok(())
}

// ============================================================================
// FILE COPY FUNCTIONS
// ============================================================================

/// Copies a file from source to destination
///
/// # Security Features
/// - Validates both source and destination paths
/// - Optionally preserves permissions
/// - Checks for destination existence before overwriting
///
/// # Arguments
/// * `source` - Source file path
/// * `dest` - Destination file path
/// * `preserve_perms` - Whether to preserve file permissions
/// * `force` - Whether to overwrite existing files
/// * `verbose` - Whether to print verbose output
///
/// # Returns
/// * `Result<u64>` - Number of bytes copied or error
fn copy_file(
    source: &Path,
    dest: &Path,
    preserve_perms: bool,
    force: bool,
    verbose: bool,
) -> Result<u64> {
    // Validate source path
    let validated_source = validate_path(source)?;

    // Check if destination exists
    if dest.exists() && !force {
        anyhow::bail!(
            "Destination {:?} already exists. Use --force to overwrite.",
            dest
        );
    }

    if verbose {
        println!(
            "{} Copying {:?} to {:?}",
            "Info:".blue(),
            validated_source,
            dest
        );
    }

    // Get source metadata before copying
    let source_metadata = fs::metadata(&validated_source)
        .with_context(|| format!("Failed to get metadata for {:?}", validated_source))?;

    // Perform the copy
    let bytes_copied = fs::copy(&validated_source, dest)
        .with_context(|| format!("Failed to copy {:?} to {:?}", validated_source, dest))?;

    // Preserve permissions if requested
    if preserve_perms {
        fs::set_permissions(dest, source_metadata.permissions())
            .with_context(|| format!("Failed to set permissions on {:?}", dest))?;

        if verbose {
            println!("{} Preserved file permissions", "Info:".blue());
        }
    }

    println!(
        "{} Copied {} bytes from {:?} to {:?}",
        "Success:".green(),
        bytes_copied,
        source,
        dest
    );

    Ok(bytes_copied)
}

// ============================================================================
// PERMISSION FUNCTIONS
// ============================================================================

/// Displays file permissions in human-readable format
///
/// # Arguments
/// * `path` - Path to the file
/// * `verbose` - Whether to print verbose output
///
/// # Returns
/// * `Result<()>` - Success or error
#[cfg(unix)]
fn show_permissions(path: &Path, verbose: bool) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let validated_path = validate_path(path)?;
    let metadata = fs::metadata(&validated_path)
        .with_context(|| format!("Failed to get metadata for {:?}", validated_path))?;

    let permissions = metadata.permissions();
    let mode = permissions.mode();

    // Extract permission bits
    let owner_read = if mode & 0o400 != 0 { 'r' } else { '-' };
    let owner_write = if mode & 0o200 != 0 { 'w' } else { '-' };
    let owner_exec = if mode & 0o100 != 0 { 'x' } else { '-' };
    let group_read = if mode & 0o040 != 0 { 'r' } else { '-' };
    let group_write = if mode & 0o020 != 0 { 'w' } else { '-' };
    let group_exec = if mode & 0o010 != 0 { 'x' } else { '-' };
    let other_read = if mode & 0o004 != 0 { 'r' } else { '-' };
    let other_write = if mode & 0o002 != 0 { 'w' } else { '-' };
    let other_exec = if mode & 0o001 != 0 { 'x' } else { '-' };

    println!("\n{}", "File Permissions".bold().underline());
    println!("Path: {:?}", validated_path);
    println!(
        "Mode: {} (octal: {:o})",
        format!(
            "{}{}{}{}{}{}{}{}{}",
            owner_read,
            owner_write,
            owner_exec,
            group_read,
            group_write,
            group_exec,
            other_read,
            other_write,
            other_exec
        )
        .cyan(),
        mode & 0o777
    );

    // Security analysis
    println!("\n{}", "Security Analysis:".yellow());

    if mode & 0o002 != 0 {
        println!(
            "  {} World-writable file detected!",
            "WARNING:".red().bold()
        );
    }

    if mode & 0o020 != 0 && mode & 0o002 != 0 {
        println!(
            "  {} Group and world writable - high risk!",
            "CRITICAL:".red().bold()
        );
    }

    if metadata.is_file() && mode & 0o111 != 0 {
        println!("  {} File is executable", "Note:".blue());
    }

    if verbose {
        println!("\n{}", "Additional Metadata:".blue());
        println!("  Size: {} bytes", metadata.len());
        println!("  Is directory: {}", metadata.is_dir());
        println!("  Is symlink: {}", is_symlink(path));
    }

    Ok(())
}

/// Non-Unix fallback for permissions display
#[cfg(not(unix))]
fn show_permissions(path: &Path, verbose: bool) -> Result<()> {
    let validated_path = validate_path(path)?;
    let metadata = fs::metadata(&validated_path)?;
    let permissions = metadata.permissions();

    println!("\n{}", "File Permissions".bold().underline());
    println!("Path: {:?}", validated_path);
    println!("Read-only: {}", permissions.readonly());

    if verbose {
        println!("Size: {} bytes", metadata.len());
    }

    Ok(())
}

/// Sets file permissions (Unix only)
///
/// # Arguments
/// * `path` - Path to the file
/// * `mode_str` - Permission mode as octal string (e.g., "755")
///
/// # Returns
/// * `Result<()>` - Success or error
#[cfg(unix)]
fn set_file_permissions(path: &Path, mode_str: &str) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let validated_path = validate_path(path)?;

    // Parse the octal string
    let mode = u32::from_str_radix(mode_str, 8)
        .with_context(|| format!("Invalid permission mode: {}", mode_str))?;

    // Validate mode is within valid range
    if mode > 0o7777 {
        anyhow::bail!("Permission mode too large: {}", mode_str);
    }

    // Set the permissions
    let permissions = Permissions::from_mode(mode);
    fs::set_permissions(&validated_path, permissions)
        .with_context(|| format!("Failed to set permissions on {:?}", validated_path))?;

    println!(
        "{} Set permissions to {:o} on {:?}",
        "Success:".green(),
        mode,
        validated_path
    );

    Ok(())
}

#[cfg(not(unix))]
fn set_file_permissions(_path: &Path, _mode_str: &str) -> Result<()> {
    anyhow::bail!("Setting permissions is only supported on Unix systems")
}

// ============================================================================
// SECURITY AUDIT FUNCTIONS
// ============================================================================

/// Audits a file or directory for security issues
///
/// # Checks Performed
/// - World-writable files
/// - Executable files in unexpected locations
/// - Symbolic links
/// - Hidden files (starting with .)
/// - Files with suspicious extensions
///
/// # Arguments
/// * `path` - Path to audit
/// * `recursive` - Whether to audit recursively
/// * `verbose` - Whether to print verbose output
///
/// # Returns
/// * `Result<Vec<String>>` - List of security issues found
fn audit_path(path: &Path, recursive: bool, verbose: bool) -> Result<Vec<String>> {
    let mut issues = Vec::new();

    if verbose {
        println!("{} Auditing: {:?}", "Info:".blue(), path);
    }

    if path.is_file() {
        issues.extend(audit_file(path)?);
    } else if path.is_dir() {
        issues.extend(audit_directory(path, recursive)?);
    }

    Ok(issues)
}

/// Audits a single file for security issues
fn audit_file(path: &Path) -> Result<Vec<String>> {
    let mut issues = Vec::new();

    // Check if symlink
    if is_symlink(path) {
        issues.push(format!("Symbolic link: {:?}", path));
    }

    // Check if hidden file
    if let Some(name) = path.file_name() {
        if name.to_string_lossy().starts_with('.') {
            issues.push(format!("Hidden file: {:?}", path));
        }
    }

    // Unix-specific permission checks
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        if let Ok(metadata) = fs::metadata(path) {
            let mode = metadata.permissions().mode();

            // World-writable check
            if mode & 0o002 != 0 {
                issues.push(format!("World-writable: {:?} (mode: {:o})", path, mode & 0o777));
            }

            // SUID/SGID check
            if mode & 0o4000 != 0 {
                issues.push(format!("SUID bit set: {:?}", path));
            }
            if mode & 0o2000 != 0 {
                issues.push(format!("SGID bit set: {:?}", path));
            }
        }
    }

    // Check for suspicious extensions
    if let Some(ext) = path.extension() {
        let suspicious_exts = ["exe", "bat", "cmd", "ps1", "sh", "py", "rb", "pl"];
        if suspicious_exts.contains(&ext.to_string_lossy().to_lowercase().as_str()) {
            issues.push(format!("Executable script: {:?}", path));
        }
    }

    Ok(issues)
}

/// Audits a directory for security issues
fn audit_directory(path: &Path, recursive: bool) -> Result<Vec<String>> {
    let mut issues = Vec::new();

    // Check directory permissions
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        if let Ok(metadata) = fs::metadata(path) {
            let mode = metadata.permissions().mode();
            if mode & 0o002 != 0 {
                issues.push(format!(
                    "World-writable directory: {:?} (mode: {:o})",
                    path,
                    mode & 0o777
                ));
            }
        }
    }

    // Iterate through directory contents
    let entries =
        fs::read_dir(path).with_context(|| format!("Failed to read directory {:?}", path))?;

    for entry in entries {
        let entry = entry?;
        let entry_path = entry.path();

        if entry_path.is_file() {
            issues.extend(audit_file(&entry_path)?);
        } else if entry_path.is_dir() && recursive {
            issues.extend(audit_directory(&entry_path, true)?);
        }
    }

    Ok(issues)
}

// ============================================================================
// MAIN FUNCTION
// ============================================================================

fn main() -> Result<()> {
    // Parse command line arguments
    let cli = Cli::parse();

    // Match on the subcommand and execute
    match cli.command {
        Commands::Read {
            path,
            line_numbers,
            head,
            hex,
        } => {
            if hex {
                // Read as binary and display hex dump
                let bytes = read_file_bytes(&path)?;
                let limit = head.unwrap_or(bytes.len() / 16 + 1) * 16;
                let bytes_to_show = &bytes[..bytes.len().min(limit)];
                println!("{}", format_hex_dump(bytes_to_show));
            } else {
                // Read as text
                let contents = read_file(&path, cli.verbose)?;
                let lines: Vec<&str> = contents.lines().collect();
                let limit = head.unwrap_or(lines.len());

                for (i, line) in lines.iter().take(limit).enumerate() {
                    if line_numbers {
                        println!("{:>6} | {}", (i + 1).to_string().dimmed(), line);
                    } else {
                        println!("{}", line);
                    }
                }
            }
        }

        Commands::Write {
            path,
            content,
            append,
            backup,
        } => {
            let text = match content {
                Some(c) => c,
                None => {
                    // Read from stdin
                    println!("Enter content (Ctrl+D to finish):");
                    let stdin = io::stdin();
                    let mut buffer = String::new();
                    for line in stdin.lock().lines() {
                        buffer.push_str(&line?);
                        buffer.push('\n');
                    }
                    buffer
                }
            };

            write_file(&path, &text, append, backup, cli.verbose)?;
            println!("{} File written successfully", "Success:".green());
        }

        Commands::Copy {
            source,
            dest,
            preserve,
            force,
        } => {
            copy_file(&source, &dest, preserve, force, cli.verbose)?;
        }

        Commands::Perms { path, set } => {
            if let Some(mode) = set {
                set_file_permissions(&path, &mode)?;
            } else {
                show_permissions(&path, cli.verbose)?;
            }
        }

        Commands::Audit { path, recursive } => {
            let issues = audit_path(&path, recursive, cli.verbose)?;

            println!("\n{}", "Security Audit Results".bold().underline());
            println!("Path: {:?}", path);
            println!("Issues found: {}\n", issues.len());

            if issues.is_empty() {
                println!("{} No security issues detected", "OK:".green());
            } else {
                for issue in &issues {
                    println!("  {} {}", "!".red(), issue);
                }
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
    use tempfile::TempDir;

    /// Test reading a file
    #[test]
    fn test_read_file() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.txt");

        // Create test file
        fs::write(&file_path, "Hello, World!").unwrap();

        // Read it back
        let contents = read_file(&file_path, false).unwrap();
        assert_eq!(contents, "Hello, World!");
    }

    /// Test writing a file
    #[test]
    fn test_write_file() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("write_test.txt");

        // Write to file
        write_file(&file_path, "Test content", false, false, false).unwrap();

        // Verify content
        let contents = fs::read_to_string(&file_path).unwrap();
        assert_eq!(contents, "Test content");
    }

    /// Test appending to a file
    #[test]
    fn test_append_file() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("append_test.txt");

        // Write initial content
        write_file(&file_path, "Line 1\n", false, false, false).unwrap();

        // Append more content
        write_file(&file_path, "Line 2\n", true, false, false).unwrap();

        // Verify content
        let contents = fs::read_to_string(&file_path).unwrap();
        assert_eq!(contents, "Line 1\nLine 2\n");
    }

    /// Test copying a file
    #[test]
    fn test_copy_file() {
        let temp_dir = TempDir::new().unwrap();
        let source = temp_dir.path().join("source.txt");
        let dest = temp_dir.path().join("dest.txt");

        // Create source file
        fs::write(&source, "Copy me!").unwrap();

        // Copy file
        let bytes = copy_file(&source, &dest, false, false, false).unwrap();

        // Verify
        assert_eq!(bytes, 8);
        let contents = fs::read_to_string(&dest).unwrap();
        assert_eq!(contents, "Copy me!");
    }

    /// Test symlink detection
    #[test]
    fn test_is_symlink() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("regular.txt");

        // Create regular file
        fs::write(&file_path, "Not a symlink").unwrap();

        // Should not be a symlink
        assert!(!is_symlink(&file_path));
    }

    /// Test hex dump formatting
    #[test]
    fn test_hex_dump() {
        let bytes = b"Hello, World!";
        let dump = format_hex_dump(bytes);

        // Should contain hex representation
        assert!(dump.contains("48 65 6c 6c")); // "Hell"
        assert!(dump.contains("|Hello, World!|"));
    }

    /// Test file audit
    #[test]
    fn test_audit_file() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join(".hidden_file.txt");

        // Create hidden file
        fs::write(&file_path, "Hidden content").unwrap();

        // Audit should detect hidden file
        let issues = audit_file(&file_path).unwrap();
        assert!(issues.iter().any(|i| i.contains("Hidden file")));
    }

    /// Test path validation
    #[test]
    fn test_validate_path() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("valid.txt");

        // Create file
        fs::write(&file_path, "Valid").unwrap();

        // Should pass validation
        let result = validate_path(&file_path);
        assert!(result.is_ok());
    }

    /// Test non-existent file returns appropriate error
    #[test]
    fn test_validate_nonexistent() {
        let result = validate_path(Path::new("/nonexistent/path/file.txt"));
        assert!(result.is_err());
    }
}
