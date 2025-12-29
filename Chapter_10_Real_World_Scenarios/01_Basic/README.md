# Basic Level: Real World Scenarios

## Overview

Tasks that a junior SOC analyst or security intern might perform daily. These scenarios focus on practical skills with immediate applicability.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     BASIC LEVEL SCENARIOS                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   RW-B01: Log Parser               RW-B02: IOC Checker                      │
│   ─────────────────                ───────────────────                      │
│   Parse auth.log, syslog           Check files against IOC list             │
│   Extract failed logins            MD5/SHA256 hash matching                 │
│   Correlate by IP                  Report suspicious files                  │
│                                                                              │
│   RW-B03: Config Auditor           RW-B04: Password Checker                 │
│   ─────────────────────            ────────────────────                     │
│   Check SSH/Apache configs         Check password policy                    │
│   Flag insecure settings           Length, complexity, common              │
│   Generate report                  Integration with breach DBs             │
│                                                                              │
│   RW-B05: User Activity Monitor                                             │
│   ───────────────────────────                                               │
│   List logged-in users                                                       │
│   Track process execution                                                    │
│   Alert on suspicious activity                                              │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Scenarios

| ID | Name | Time | Skills |
|----|------|------|--------|
| RW-B01 | Security Log Parser | 2-3 hours | File I/O, regex |
| RW-B02 | IOC Hash Checker | 2-3 hours | Hashing, file ops |
| RW-B03 | Config Security Auditor | 3-4 hours | Parsing, validation |
| RW-B04 | Password Policy Checker | 2-3 hours | String analysis |
| RW-B05 | User Activity Monitor | 3-4 hours | Process, system info |

---

## RW-B02: IOC Hash Checker

### Scenario Background

You're a SOC analyst who received a list of Indicators of Compromise (IOCs) - specifically file hashes - from a threat intelligence feed. Your task is to scan a directory and identify any files matching these malicious hashes.

### Requirements

1. Read IOC list from file (one hash per line)
2. Recursively scan a target directory
3. Calculate MD5/SHA256 for each file
4. Report matches with file paths
5. Generate summary report

### The Code

```rust
//! RW-B02: IOC Hash Checker
//!
//! Scans directories for files matching known malicious hashes.
//!
//! # Real-World Use Case
//! - SOC analysts checking systems after breach notification
//! - Incident response during active investigations
//! - Automated scanning in security pipelines
//!
//! # Example IOC File Format
//! ```text
//! # Emotet samples
//! 5d41402abc4b2a76b9719d911017c592
//! e99a18c428cb38d5f260853678922e03
//!
//! # Wannacry
//! 84c82835a5d21bbcf75a61706d8ab549
//! ```

use clap::Parser;
use sha2::{Sha256, Digest as Sha2Digest};
use md5::{Md5, Digest as Md5Digest};
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read};
use std::path::Path;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use walkdir::WalkDir;

// ═══════════════════════════════════════════════════════════════════════════
// COMMAND LINE INTERFACE
// ═══════════════════════════════════════════════════════════════════════════

/// IOC Hash Checker - Scan files for malicious hashes
#[derive(Parser, Debug)]
#[command(name = "ioc-checker")]
#[command(about = "Check files against IOC hash list")]
struct Args {
    /// Path to IOC file containing hashes
    #[arg(short, long)]
    ioc_file: String,

    /// Directory to scan
    #[arg(short, long)]
    target: String,

    /// Hash type to use (md5, sha256, both)
    #[arg(short = 'H', long, default_value = "both")]
    hash_type: String,

    /// Output format (text, json, csv)
    #[arg(short, long, default_value = "text")]
    output: String,

    /// Skip files larger than this (MB)
    #[arg(short, long, default_value = "100")]
    max_size: u64,

    /// Show progress during scan
    #[arg(short, long)]
    progress: bool,
}

// ═══════════════════════════════════════════════════════════════════════════
// DATA STRUCTURES
// ═══════════════════════════════════════════════════════════════════════════

/// IOC database loaded from file
///
/// # Hash Storage Strategy
/// We use HashSet for O(1) lookup performance.
/// For a list of 10,000 IOCs, this makes matching nearly instant
/// compared to O(n) linear search.
#[derive(Debug)]
struct IocDatabase {
    /// MD5 hashes (32 hex chars)
    md5_hashes: HashSet<String>,

    /// SHA256 hashes (64 hex chars)
    sha256_hashes: HashSet<String>,

    /// Total IOCs loaded
    total_count: usize,

    /// Source file
    source_file: String,
}

impl IocDatabase {
    /// Loads IOCs from file
    ///
    /// # Format Support
    /// - One hash per line
    /// - Lines starting with # are comments
    /// - Empty lines are ignored
    /// - Supports mixed hash types (auto-detected by length)
    fn load(path: &str) -> Result<Self, String> {
        let file = File::open(path)
            .map_err(|e| format!("Failed to open IOC file: {}", e))?;

        let reader = BufReader::new(file);
        let mut md5_hashes = HashSet::new();
        let mut sha256_hashes = HashSet::new();

        for line in reader.lines() {
            let line = line.map_err(|e| format!("Read error: {}", e))?;
            let trimmed = line.trim();

            // Skip comments and empty lines
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            // Extract hash (first field, in case of CSV or space-separated)
            let hash = trimmed.split(|c: char| c.is_whitespace() || c == ',')
                .next()
                .unwrap_or("")
                .to_lowercase();

            // Classify by length
            match hash.len() {
                32 => { md5_hashes.insert(hash); }
                64 => { sha256_hashes.insert(hash); }
                _ => {} // Skip invalid hashes
            }
        }

        let total = md5_hashes.len() + sha256_hashes.len();

        Ok(IocDatabase {
            md5_hashes,
            sha256_hashes,
            total_count: total,
            source_file: path.to_string(),
        })
    }

    /// Checks if an MD5 hash is in the database
    fn check_md5(&self, hash: &str) -> bool {
        self.md5_hashes.contains(&hash.to_lowercase())
    }

    /// Checks if a SHA256 hash is in the database
    fn check_sha256(&self, hash: &str) -> bool {
        self.sha256_hashes.contains(&hash.to_lowercase())
    }
}

/// Result of scanning a single file
#[derive(Debug, Clone)]
struct ScanResult {
    /// File path
    path: String,

    /// File size in bytes
    size: u64,

    /// MD5 hash
    md5: Option<String>,

    /// SHA256 hash
    sha256: Option<String>,

    /// Whether file matches IOC
    is_match: bool,

    /// Which hash type matched
    match_type: Option<String>,

    /// Error if scan failed
    error: Option<String>,
}

/// Summary of scan results
#[derive(Debug)]
struct ScanSummary {
    /// Total files scanned
    files_scanned: u64,

    /// Files that matched IOCs
    matches_found: u64,

    /// Files skipped (too large, permission denied, etc.)
    files_skipped: u64,

    /// Total bytes scanned
    bytes_scanned: u64,

    /// Time taken
    duration_secs: f64,

    /// List of matching files
    matches: Vec<ScanResult>,

    /// Errors encountered
    errors: Vec<String>,
}

// ═══════════════════════════════════════════════════════════════════════════
// SCANNER IMPLEMENTATION
// ═══════════════════════════════════════════════════════════════════════════

/// File scanner that checks against IOC database
///
/// # Performance Considerations
/// - Uses buffered reading for large files
/// - Calculates hashes in single pass when possible
/// - Skips files beyond size threshold
struct IocScanner {
    /// IOC database
    ioc_db: IocDatabase,

    /// Whether to calculate MD5
    check_md5: bool,

    /// Whether to calculate SHA256
    check_sha256: bool,

    /// Maximum file size to scan (bytes)
    max_size: u64,
}

impl IocScanner {
    fn new(ioc_db: IocDatabase, hash_type: &str, max_size_mb: u64) -> Self {
        let (check_md5, check_sha256) = match hash_type.to_lowercase().as_str() {
            "md5" => (true, false),
            "sha256" => (false, true),
            _ => (true, true), // "both" or default
        };

        IocScanner {
            ioc_db,
            check_md5,
            check_sha256,
            max_size: max_size_mb * 1024 * 1024,
        }
    }

    /// Scans a directory recursively
    ///
    /// # Directory Traversal
    /// Uses `walkdir` crate which:
    /// - Handles symlinks safely (doesn't follow by default)
    /// - Skips inaccessible directories gracefully
    /// - Provides consistent cross-platform behavior
    fn scan_directory(&self, path: &str, show_progress: bool) -> ScanSummary {
        let start = Instant::now();

        let mut summary = ScanSummary {
            files_scanned: 0,
            matches_found: 0,
            files_skipped: 0,
            bytes_scanned: 0,
            duration_secs: 0.0,
            matches: Vec::new(),
            errors: Vec::new(),
        };

        // Count files first for progress
        let total_files: u64 = WalkDir::new(path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .count() as u64;

        if show_progress {
            println!("[*] Found {} files to scan", total_files);
        }

        // Scan files
        for entry in WalkDir::new(path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let file_path = entry.path();

            // Get file size
            let size = match fs::metadata(file_path) {
                Ok(meta) => meta.len(),
                Err(e) => {
                    summary.files_skipped += 1;
                    summary.errors.push(format!("{}: {}", file_path.display(), e));
                    continue;
                }
            };

            // Skip large files
            if size > self.max_size {
                summary.files_skipped += 1;
                continue;
            }

            // Scan file
            let result = self.scan_file(file_path);

            if result.error.is_some() {
                summary.files_skipped += 1;
                if let Some(err) = &result.error {
                    summary.errors.push(format!("{}: {}", file_path.display(), err));
                }
            } else {
                summary.files_scanned += 1;
                summary.bytes_scanned += size;

                if result.is_match {
                    summary.matches_found += 1;
                    summary.matches.push(result.clone());

                    if show_progress {
                        println!("[!] MATCH: {}", file_path.display());
                    }
                }
            }

            // Progress update
            if show_progress && summary.files_scanned % 100 == 0 {
                let pct = (summary.files_scanned as f64 / total_files as f64) * 100.0;
                print!("\r[*] Progress: {:.1}% ({}/{} files)", pct, summary.files_scanned, total_files);
            }
        }

        if show_progress {
            println!(); // New line after progress
        }

        summary.duration_secs = start.elapsed().as_secs_f64();
        summary
    }

    /// Scans a single file
    ///
    /// # Hash Calculation
    /// We read the file once and calculate both hashes simultaneously
    /// to avoid reading the file twice.
    fn scan_file(&self, path: &Path) -> ScanResult {
        let path_str = path.to_string_lossy().to_string();

        // Read file
        let mut file = match File::open(path) {
            Ok(f) => f,
            Err(e) => {
                return ScanResult {
                    path: path_str,
                    size: 0,
                    md5: None,
                    sha256: None,
                    is_match: false,
                    match_type: None,
                    error: Some(e.to_string()),
                };
            }
        };

        // Get size
        let size = file.metadata().map(|m| m.len()).unwrap_or(0);

        // Read content
        let mut content = Vec::new();
        if let Err(e) = file.read_to_end(&mut content) {
            return ScanResult {
                path: path_str,
                size,
                md5: None,
                sha256: None,
                is_match: false,
                match_type: None,
                error: Some(e.to_string()),
            };
        }

        // Calculate hashes
        let md5 = if self.check_md5 {
            let hash = Md5::digest(&content);
            Some(format!("{:x}", hash))
        } else {
            None
        };

        let sha256 = if self.check_sha256 {
            let hash = Sha256::digest(&content);
            Some(format!("{:x}", hash))
        } else {
            None
        };

        // Check against IOC database
        let mut is_match = false;
        let mut match_type = None;

        if let Some(ref hash) = md5 {
            if self.ioc_db.check_md5(hash) {
                is_match = true;
                match_type = Some("MD5".to_string());
            }
        }

        if let Some(ref hash) = sha256 {
            if self.ioc_db.check_sha256(hash) {
                is_match = true;
                match_type = Some(match_type.map(|t| format!("{},SHA256", t))
                    .unwrap_or_else(|| "SHA256".to_string()));
            }
        }

        ScanResult {
            path: path_str,
            size,
            md5,
            sha256,
            is_match,
            match_type,
            error: None,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// OUTPUT FORMATTING
// ═══════════════════════════════════════════════════════════════════════════

/// Formats scan results for output
fn format_results(summary: &ScanSummary, format: &str) -> String {
    match format.to_lowercase().as_str() {
        "json" => format_json(summary),
        "csv" => format_csv(summary),
        _ => format_text(summary),
    }
}

fn format_text(summary: &ScanSummary) -> String {
    let mut output = String::new();

    output.push_str("\n══════════════════════════════════════════════════════════════\n");
    output.push_str("                        SCAN SUMMARY                           \n");
    output.push_str("══════════════════════════════════════════════════════════════\n\n");

    output.push_str(&format!("Files scanned:    {}\n", summary.files_scanned));
    output.push_str(&format!("Files skipped:    {}\n", summary.files_skipped));
    output.push_str(&format!("Bytes scanned:    {}\n", format_bytes(summary.bytes_scanned)));
    output.push_str(&format!("Duration:         {:.2}s\n", summary.duration_secs));
    output.push_str(&format!("Scan rate:        {:.0} files/sec\n",
        summary.files_scanned as f64 / summary.duration_secs));

    if summary.matches_found > 0 {
        output.push_str("\n══════════════════════════════════════════════════════════════\n");
        output.push_str("                       MATCHES FOUND                           \n");
        output.push_str("══════════════════════════════════════════════════════════════\n\n");

        for m in &summary.matches {
            output.push_str(&format!("[MATCH] {}\n", m.path));
            output.push_str(&format!("        Size: {} bytes\n", m.size));
            if let Some(ref md5) = m.md5 {
                output.push_str(&format!("        MD5:  {}\n", md5));
            }
            if let Some(ref sha) = m.sha256 {
                output.push_str(&format!("        SHA256: {}\n", sha));
            }
            output.push_str(&format!("        Match Type: {}\n\n",
                m.match_type.as_deref().unwrap_or("unknown")));
        }
    } else {
        output.push_str("\n[*] No IOC matches found.\n");
    }

    output
}

fn format_json(summary: &ScanSummary) -> String {
    serde_json::json!({
        "files_scanned": summary.files_scanned,
        "files_skipped": summary.files_skipped,
        "bytes_scanned": summary.bytes_scanned,
        "duration_secs": summary.duration_secs,
        "matches_found": summary.matches_found,
        "matches": summary.matches.iter().map(|m| {
            serde_json::json!({
                "path": m.path,
                "size": m.size,
                "md5": m.md5,
                "sha256": m.sha256,
                "match_type": m.match_type
            })
        }).collect::<Vec<_>>()
    }).to_string()
}

fn format_csv(summary: &ScanSummary) -> String {
    let mut output = String::from("path,size,md5,sha256,match_type\n");

    for m in &summary.matches {
        output.push_str(&format!("{},{},{},{},{}\n",
            m.path,
            m.size,
            m.md5.as_deref().unwrap_or(""),
            m.sha256.as_deref().unwrap_or(""),
            m.match_type.as_deref().unwrap_or("")
        ));
    }

    output
}

fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} bytes", bytes)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// MAIN FUNCTION
// ═══════════════════════════════════════════════════════════════════════════

fn main() {
    let args = Args::parse();

    println!("╔════════════════════════════════════════════════════════════════╗");
    println!("║                 IOC HASH CHECKER                                ║");
    println!("╚════════════════════════════════════════════════════════════════╝\n");

    // Load IOC database
    println!("[*] Loading IOC database from: {}", args.ioc_file);
    let ioc_db = match IocDatabase::load(&args.ioc_file) {
        Ok(db) => {
            println!("[+] Loaded {} IOCs ({} MD5, {} SHA256)",
                db.total_count,
                db.md5_hashes.len(),
                db.sha256_hashes.len());
            db
        }
        Err(e) => {
            eprintln!("[-] Error: {}", e);
            std::process::exit(1);
        }
    };

    // Create scanner
    let scanner = IocScanner::new(ioc_db, &args.hash_type, args.max_size);

    // Run scan
    println!("[*] Scanning directory: {}", args.target);
    println!("[*] Max file size: {} MB", args.max_size);
    println!("[*] Hash types: {}\n", args.hash_type);

    let summary = scanner.scan_directory(&args.target, args.progress);

    // Output results
    let output = format_results(&summary, &args.output);
    println!("{}", output);

    // Exit with appropriate code
    if summary.matches_found > 0 {
        std::process::exit(1); // Exit 1 if matches found (for scripting)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn test_ioc_loading() {
        let temp = TempDir::new().unwrap();
        let ioc_path = temp.path().join("iocs.txt");

        let mut file = File::create(&ioc_path).unwrap();
        writeln!(file, "# Test IOCs").unwrap();
        writeln!(file, "5d41402abc4b2a76b9719d911017c592").unwrap(); // MD5
        writeln!(file, "").unwrap(); // Empty line
        writeln!(file, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").unwrap(); // SHA256

        let db = IocDatabase::load(ioc_path.to_str().unwrap()).unwrap();
        assert_eq!(db.md5_hashes.len(), 1);
        assert_eq!(db.sha256_hashes.len(), 1);
    }

    #[test]
    fn test_hash_checking() {
        let mut db = IocDatabase {
            md5_hashes: HashSet::new(),
            sha256_hashes: HashSet::new(),
            total_count: 0,
            source_file: String::new(),
        };

        db.md5_hashes.insert("5d41402abc4b2a76b9719d911017c592".to_string());

        assert!(db.check_md5("5d41402abc4b2a76b9719d911017c592"));
        assert!(db.check_md5("5D41402ABC4B2A76B9719D911017C592")); // Case insensitive
        assert!(!db.check_md5("0000000000000000000000000000000"));
    }
}
```

### Cargo.toml

```toml
[package]
name = "ioc-checker"
version = "0.1.0"
edition = "2021"

[dependencies]
clap = { version = "4.4", features = ["derive"] }
sha2 = "0.10"
md-5 = "0.10"
walkdir = "2.4"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
tempfile = "3.8"
```

### Usage Examples

```bash
# Basic scan
./ioc-checker --ioc-file threats.txt --target /home/user

# With progress and JSON output
./ioc-checker -i threats.txt -t /var/www -p -o json

# MD5 only, skip large files
./ioc-checker -i threats.txt -t /opt -H md5 --max-size 50

# Integration with other tools
./ioc-checker -i threats.txt -t /tmp -o csv > matches.csv
```

### Exercises

1. **Add YARA Support**: Extend to also match YARA rules
2. **Add Quarantine**: Move matching files to quarantine directory
3. **Add Network IOCs**: Check connections against malicious IPs
4. **Add Scheduling**: Run as daemon with periodic scans
5. **Add VirusTotal API**: Submit unknown hashes to VT

---

## Additional Basic Scenarios

See the following files for complete implementations:

- [RW-B01: Log Parser](./RW-B01_Log_Parser/) - Security log analysis
- [RW-B03: Config Auditor](./RW-B03_Config_Auditor/) - SSH/Apache config checking
- [RW-B04: Password Checker](./RW-B04_Password_Checker/) - Policy enforcement
- [RW-B05: Activity Monitor](./RW-B05_Activity_Monitor/) - User tracking

---

**← Previous:** [Chapter 10 Overview](../README.md) | **Next →** [Intermediate Scenarios](../02_Intermediate/README.md)
