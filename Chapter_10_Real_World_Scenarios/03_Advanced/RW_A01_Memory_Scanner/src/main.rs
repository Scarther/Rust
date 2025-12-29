//! Process Memory Scanner
//!
//! A security tool for scanning process memory for patterns, indicators of compromise,
//! and suspicious content. Essential for malware analysis and forensics.
//!
//! Features:
//! - Scan process memory for patterns (strings, regex, hex)
//! - Detect common malware indicators
//! - Memory region analysis
//! - Yara-like rule matching
//! - Dump suspicious regions
//! - Multi-process scanning

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use regex::bytes::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use tracing::{debug, error, info, warn, Level};
use tracing_subscriber::FmtSubscriber;

/// Memory Scanner CLI
#[derive(Parser)]
#[command(name = "memory-scanner")]
#[command(about = "Scan process memory for patterns and IOCs")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Enable verbose logging
    #[arg(short, long, global = true)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a process for patterns
    Scan {
        /// Target process ID
        #[arg(short, long)]
        pid: i32,

        /// Pattern to search (string)
        #[arg(short = 's', long)]
        string: Option<String>,

        /// Hex pattern to search
        #[arg(short = 'x', long)]
        hex: Option<String>,

        /// Regex pattern
        #[arg(short, long)]
        regex: Option<String>,

        /// Scan only executable regions
        #[arg(long)]
        executable_only: bool,

        /// Output results to file
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Scan for known malware indicators
    Ioc {
        /// Target process ID
        #[arg(short, long)]
        pid: i32,

        /// IOC rules file
        #[arg(short, long)]
        rules: Option<PathBuf>,

        /// Output results to file
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// List memory regions of a process
    Regions {
        /// Target process ID
        #[arg(short, long)]
        pid: i32,

        /// Show detailed information
        #[arg(short, long)]
        detailed: bool,
    },
    /// Dump memory region to file
    Dump {
        /// Target process ID
        #[arg(short, long)]
        pid: i32,

        /// Start address (hex)
        #[arg(short, long)]
        start: String,

        /// Size in bytes
        #[arg(short = 'S', long)]
        size: usize,

        /// Output file
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Scan all processes for patterns
    ScanAll {
        /// Pattern to search (string)
        #[arg(short = 's', long)]
        string: Option<String>,

        /// Hex pattern to search
        #[arg(short = 'x', long)]
        hex: Option<String>,

        /// Output results to file
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Generate IOC rules template
    GenerateRules {
        /// Output file
        #[arg(short, long, default_value = "ioc_rules.json")]
        output: PathBuf,
    },
    /// Analyze process for suspicious indicators
    Analyze {
        /// Target process ID
        #[arg(short, long)]
        pid: i32,

        /// Output report file
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

/// Memory region information
#[derive(Debug, Clone, Serialize, Deserialize)]
struct MemoryRegion {
    start_address: u64,
    end_address: u64,
    size: usize,
    permissions: String,
    offset: u64,
    device: String,
    inode: u64,
    pathname: String,
    is_readable: bool,
    is_writable: bool,
    is_executable: bool,
    is_private: bool,
}

/// Pattern match result
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PatternMatch {
    address: u64,
    region_start: u64,
    pattern_type: String,
    pattern: String,
    context: String,
    context_hex: String,
}

/// IOC rule
#[derive(Debug, Clone, Serialize, Deserialize)]
struct IocRule {
    name: String,
    description: String,
    severity: String,
    pattern_type: String,
    pattern: String,
    #[serde(default)]
    tags: Vec<String>,
}

/// IOC rules collection
#[derive(Debug, Clone, Serialize, Deserialize)]
struct IocRules {
    version: String,
    rules: Vec<IocRule>,
}

/// Scan result
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ScanResult {
    pid: i32,
    process_name: String,
    scanned_at: DateTime<Utc>,
    regions_scanned: usize,
    bytes_scanned: usize,
    matches: Vec<PatternMatch>,
    ioc_matches: Vec<IocMatch>,
}

/// IOC match
#[derive(Debug, Clone, Serialize, Deserialize)]
struct IocMatch {
    rule_name: String,
    severity: String,
    address: u64,
    description: String,
    evidence: String,
}

/// Analysis finding
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AnalysisFinding {
    category: String,
    severity: String,
    title: String,
    description: String,
    evidence: String,
}

/// Memory scanner
struct MemoryScanner;

impl MemoryScanner {
    /// Parse /proc/[pid]/maps to get memory regions
    fn get_memory_regions(pid: i32) -> Result<Vec<MemoryRegion>> {
        let maps_path = format!("/proc/{}/maps", pid);
        let file = File::open(&maps_path)
            .context(format!("Failed to open {}. Check if process exists and you have permissions.", maps_path))?;

        let reader = BufReader::new(file);
        let mut regions = Vec::new();

        for line in reader.lines() {
            let line = line?;
            let parts: Vec<&str> = line.split_whitespace().collect();

            if parts.is_empty() {
                continue;
            }

            // Parse address range
            let addr_parts: Vec<&str> = parts[0].split('-').collect();
            if addr_parts.len() != 2 {
                continue;
            }

            let start = u64::from_str_radix(addr_parts[0], 16)?;
            let end = u64::from_str_radix(addr_parts[1], 16)?;

            // Parse permissions
            let perms = parts.get(1).unwrap_or(&"----");
            let is_readable = perms.contains('r');
            let is_writable = perms.contains('w');
            let is_executable = perms.contains('x');
            let is_private = perms.contains('p');

            // Parse other fields
            let offset = parts.get(2)
                .and_then(|s| u64::from_str_radix(s, 16).ok())
                .unwrap_or(0);

            let device = parts.get(3).unwrap_or(&"00:00").to_string();
            let inode = parts.get(4)
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);

            let pathname = parts.get(5..).map(|p| p.join(" ")).unwrap_or_default();

            regions.push(MemoryRegion {
                start_address: start,
                end_address: end,
                size: (end - start) as usize,
                permissions: perms.to_string(),
                offset,
                device,
                inode,
                pathname,
                is_readable,
                is_writable,
                is_executable,
                is_private,
            });
        }

        Ok(regions)
    }

    /// Read process memory
    fn read_process_memory(pid: i32, address: u64, size: usize) -> Result<Vec<u8>> {
        let mem_path = format!("/proc/{}/mem", pid);
        let mut file = File::open(&mem_path)
            .context(format!("Failed to open process memory. Run as root or check permissions."))?;

        use std::io::Seek;
        file.seek(std::io::SeekFrom::Start(address))?;

        let mut buffer = vec![0u8; size];
        match file.read_exact(&mut buffer) {
            Ok(_) => Ok(buffer),
            Err(e) => {
                // Try to read as much as possible
                let mut partial = Vec::new();
                file.seek(std::io::SeekFrom::Start(address))?;
                file.read_to_end(&mut partial)?;
                if partial.is_empty() {
                    Err(e.into())
                } else {
                    Ok(partial)
                }
            }
        }
    }

    /// Search for pattern in memory
    fn search_pattern(
        pid: i32,
        regions: &[MemoryRegion],
        pattern: &[u8],
        pattern_str: &str,
        pattern_type: &str,
        executable_only: bool,
    ) -> Result<Vec<PatternMatch>> {
        let mut matches = Vec::new();

        for region in regions {
            if !region.is_readable {
                continue;
            }

            if executable_only && !region.is_executable {
                continue;
            }

            // Skip very large regions to avoid memory issues
            if region.size > 100 * 1024 * 1024 {
                debug!("Skipping large region: {} bytes", region.size);
                continue;
            }

            match Self::read_process_memory(pid, region.start_address, region.size) {
                Ok(memory) => {
                    // Search for pattern
                    let mut offset = 0;
                    while let Some(pos) = Self::find_pattern(&memory[offset..], pattern) {
                        let abs_pos = offset + pos;
                        let address = region.start_address + abs_pos as u64;

                        // Extract context (32 bytes around match)
                        let context_start = if abs_pos >= 16 { abs_pos - 16 } else { 0 };
                        let context_end = (abs_pos + pattern.len() + 16).min(memory.len());
                        let context_bytes = &memory[context_start..context_end];

                        // Create printable context
                        let context: String = context_bytes.iter()
                            .map(|&b| if b >= 0x20 && b < 0x7f { b as char } else { '.' })
                            .collect();

                        let context_hex = hex::encode(context_bytes);

                        matches.push(PatternMatch {
                            address,
                            region_start: region.start_address,
                            pattern_type: pattern_type.to_string(),
                            pattern: pattern_str.to_string(),
                            context,
                            context_hex,
                        });

                        offset = abs_pos + 1;
                    }
                }
                Err(e) => {
                    debug!("Failed to read region at {:x}: {}", region.start_address, e);
                }
            }
        }

        Ok(matches)
    }

    /// Find pattern in buffer
    fn find_pattern(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack.windows(needle.len())
            .position(|window| window == needle)
    }

    /// Search with regex
    fn search_regex(
        pid: i32,
        regions: &[MemoryRegion],
        pattern: &str,
        executable_only: bool,
    ) -> Result<Vec<PatternMatch>> {
        let regex = Regex::new(pattern)
            .context("Invalid regex pattern")?;

        let mut matches = Vec::new();

        for region in regions {
            if !region.is_readable {
                continue;
            }

            if executable_only && !region.is_executable {
                continue;
            }

            if region.size > 100 * 1024 * 1024 {
                continue;
            }

            match Self::read_process_memory(pid, region.start_address, region.size) {
                Ok(memory) => {
                    for mat in regex.find_iter(&memory) {
                        let address = region.start_address + mat.start() as u64;

                        let context_start = if mat.start() >= 16 { mat.start() - 16 } else { 0 };
                        let context_end = (mat.end() + 16).min(memory.len());
                        let context_bytes = &memory[context_start..context_end];

                        let context: String = context_bytes.iter()
                            .map(|&b| if b >= 0x20 && b < 0x7f { b as char } else { '.' })
                            .collect();

                        matches.push(PatternMatch {
                            address,
                            region_start: region.start_address,
                            pattern_type: "regex".to_string(),
                            pattern: pattern.to_string(),
                            context,
                            context_hex: hex::encode(context_bytes),
                        });
                    }
                }
                Err(e) => {
                    debug!("Failed to read region: {}", e);
                }
            }
        }

        Ok(matches)
    }

    /// Get process name
    fn get_process_name(pid: i32) -> String {
        let comm_path = format!("/proc/{}/comm", pid);
        fs::read_to_string(&comm_path)
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "unknown".to_string())
    }

    /// Get default IOC rules
    fn get_default_ioc_rules() -> IocRules {
        IocRules {
            version: "1.0".to_string(),
            rules: vec![
                IocRule {
                    name: "ShellCode_NOP_Sled".to_string(),
                    description: "NOP sled commonly used in shellcode".to_string(),
                    severity: "high".to_string(),
                    pattern_type: "hex".to_string(),
                    pattern: "9090909090909090".to_string(),
                    tags: vec!["shellcode".to_string(), "exploit".to_string()],
                },
                IocRule {
                    name: "Shell_Spawn".to_string(),
                    description: "Reference to /bin/sh shell".to_string(),
                    severity: "medium".to_string(),
                    pattern_type: "string".to_string(),
                    pattern: "/bin/sh".to_string(),
                    tags: vec!["shell".to_string()],
                },
                IocRule {
                    name: "Bash_Shell".to_string(),
                    description: "Reference to /bin/bash".to_string(),
                    severity: "low".to_string(),
                    pattern_type: "string".to_string(),
                    pattern: "/bin/bash".to_string(),
                    tags: vec!["shell".to_string()],
                },
                IocRule {
                    name: "ETC_Passwd".to_string(),
                    description: "Reference to /etc/passwd".to_string(),
                    severity: "medium".to_string(),
                    pattern_type: "string".to_string(),
                    pattern: "/etc/passwd".to_string(),
                    tags: vec!["credential".to_string()],
                },
                IocRule {
                    name: "ETC_Shadow".to_string(),
                    description: "Reference to /etc/shadow".to_string(),
                    severity: "high".to_string(),
                    pattern_type: "string".to_string(),
                    pattern: "/etc/shadow".to_string(),
                    tags: vec!["credential".to_string()],
                },
                IocRule {
                    name: "SSH_Private_Key".to_string(),
                    description: "SSH private key header".to_string(),
                    severity: "critical".to_string(),
                    pattern_type: "string".to_string(),
                    pattern: "-----BEGIN RSA PRIVATE KEY-----".to_string(),
                    tags: vec!["credential".to_string(), "ssh".to_string()],
                },
                IocRule {
                    name: "AWS_Access_Key".to_string(),
                    description: "Potential AWS access key".to_string(),
                    severity: "critical".to_string(),
                    pattern_type: "regex".to_string(),
                    pattern: "AKIA[0-9A-Z]{16}".to_string(),
                    tags: vec!["credential".to_string(), "aws".to_string()],
                },
                IocRule {
                    name: "Base64_Encoded_Script".to_string(),
                    description: "Base64 encoded PowerShell or bash".to_string(),
                    severity: "medium".to_string(),
                    pattern_type: "regex".to_string(),
                    pattern: "(?:powershell|bash).*-[eE](?:nc|ncodedCommand)".to_string(),
                    tags: vec!["evasion".to_string()],
                },
                IocRule {
                    name: "Metasploit_Signature".to_string(),
                    description: "Metasploit framework signature".to_string(),
                    severity: "critical".to_string(),
                    pattern_type: "string".to_string(),
                    pattern: "meterpreter".to_string(),
                    tags: vec!["malware".to_string(), "rat".to_string()],
                },
                IocRule {
                    name: "Cobalt_Strike".to_string(),
                    description: "Cobalt Strike beacon indicator".to_string(),
                    severity: "critical".to_string(),
                    pattern_type: "hex".to_string(),
                    pattern: "fc4883e4f0e8".to_string(),
                    tags: vec!["malware".to_string(), "c2".to_string()],
                },
                IocRule {
                    name: "Reverse_Shell_Netcat".to_string(),
                    description: "Netcat reverse shell pattern".to_string(),
                    severity: "high".to_string(),
                    pattern_type: "regex".to_string(),
                    pattern: "nc\\s+-[el].*\\d{1,5}".to_string(),
                    tags: vec!["backdoor".to_string()],
                },
                IocRule {
                    name: "Crypto_Mining".to_string(),
                    description: "Cryptocurrency mining indicators".to_string(),
                    severity: "high".to_string(),
                    pattern_type: "regex".to_string(),
                    pattern: "stratum\\+tcp://".to_string(),
                    tags: vec!["cryptominer".to_string()],
                },
            ],
        }
    }

    /// Scan for IOC matches
    fn scan_for_iocs(pid: i32, regions: &[MemoryRegion], rules: &IocRules) -> Result<Vec<IocMatch>> {
        let mut matches = Vec::new();

        for rule in &rules.rules {
            let pattern_matches = match rule.pattern_type.as_str() {
                "string" => {
                    Self::search_pattern(
                        pid,
                        regions,
                        rule.pattern.as_bytes(),
                        &rule.pattern,
                        "string",
                        false,
                    )?
                }
                "hex" => {
                    let bytes = hex::decode(&rule.pattern)
                        .context(format!("Invalid hex pattern in rule: {}", rule.name))?;
                    Self::search_pattern(
                        pid,
                        regions,
                        &bytes,
                        &rule.pattern,
                        "hex",
                        false,
                    )?
                }
                "regex" => {
                    Self::search_regex(pid, regions, &rule.pattern, false)?
                }
                _ => Vec::new(),
            };

            for pat_match in pattern_matches {
                matches.push(IocMatch {
                    rule_name: rule.name.clone(),
                    severity: rule.severity.clone(),
                    address: pat_match.address,
                    description: rule.description.clone(),
                    evidence: pat_match.context,
                });
            }
        }

        Ok(matches)
    }

    /// Analyze process for suspicious indicators
    fn analyze_process(pid: i32) -> Result<Vec<AnalysisFinding>> {
        let mut findings = Vec::new();
        let regions = Self::get_memory_regions(pid)?;

        // Check for RWX regions (suspicious - executable and writable)
        let rwx_regions: Vec<_> = regions.iter()
            .filter(|r| r.is_readable && r.is_writable && r.is_executable)
            .collect();

        if !rwx_regions.is_empty() {
            findings.push(AnalysisFinding {
                category: "Memory Protection".to_string(),
                severity: "high".to_string(),
                title: "RWX Memory Regions Detected".to_string(),
                description: format!("Found {} regions with Read-Write-Execute permissions", rwx_regions.len()),
                evidence: rwx_regions.iter()
                    .take(5)
                    .map(|r| format!("0x{:x}-0x{:x} {}", r.start_address, r.end_address, r.pathname))
                    .collect::<Vec<_>>()
                    .join("; "),
            });
        }

        // Check for anonymous executable regions
        let anon_exec: Vec<_> = regions.iter()
            .filter(|r| r.is_executable && r.pathname.is_empty())
            .collect();

        if !anon_exec.is_empty() {
            findings.push(AnalysisFinding {
                category: "Code Injection".to_string(),
                severity: "medium".to_string(),
                title: "Anonymous Executable Regions".to_string(),
                description: format!("Found {} anonymous executable memory regions", anon_exec.len()),
                evidence: anon_exec.iter()
                    .take(5)
                    .map(|r| format!("0x{:x} ({} bytes)", r.start_address, r.size))
                    .collect::<Vec<_>>()
                    .join("; "),
            });
        }

        // Check for deleted file mappings
        let deleted_mappings: Vec<_> = regions.iter()
            .filter(|r| r.pathname.contains("(deleted)"))
            .collect();

        if !deleted_mappings.is_empty() {
            findings.push(AnalysisFinding {
                category: "Evasion".to_string(),
                severity: "high".to_string(),
                title: "Deleted File Mappings".to_string(),
                description: "Process has mappings to deleted files".to_string(),
                evidence: deleted_mappings.iter()
                    .map(|r| r.pathname.clone())
                    .collect::<Vec<_>>()
                    .join("; "),
            });
        }

        // Check for memfd mappings (in-memory only files)
        let memfd_mappings: Vec<_> = regions.iter()
            .filter(|r| r.pathname.contains("memfd:"))
            .collect();

        if !memfd_mappings.is_empty() {
            findings.push(AnalysisFinding {
                category: "Evasion".to_string(),
                severity: "medium".to_string(),
                title: "Memory-Only File Mappings (memfd)".to_string(),
                description: "Process uses memfd for in-memory execution".to_string(),
                evidence: memfd_mappings.iter()
                    .map(|r| r.pathname.clone())
                    .collect::<Vec<_>>()
                    .join("; "),
            });
        }

        // Check total memory usage
        let total_size: usize = regions.iter().map(|r| r.size).sum();
        if total_size > 1024 * 1024 * 1024 {
            findings.push(AnalysisFinding {
                category: "Resource".to_string(),
                severity: "low".to_string(),
                title: "High Memory Usage".to_string(),
                description: format!("Process using {} MB of virtual memory", total_size / (1024 * 1024)),
                evidence: String::new(),
            });
        }

        Ok(findings)
    }
}

/// Display pattern match
fn display_match(mat: &PatternMatch) {
    println!("\n  {} Match at {}", "●".cyan(), format!("0x{:016x}", mat.address).yellow());
    println!("    Region: 0x{:x}", mat.region_start);
    println!("    Type: {}", mat.pattern_type);
    println!("    Pattern: {}", mat.pattern);
    println!("    Context: {}", mat.context);
    println!("    Hex: {}", mat.context_hex);
}

/// Display IOC match
fn display_ioc_match(mat: &IocMatch) {
    let severity_color = match mat.severity.as_str() {
        "critical" => mat.severity.to_uppercase().red().bold(),
        "high" => mat.severity.to_uppercase().red(),
        "medium" => mat.severity.to_uppercase().yellow(),
        _ => mat.severity.to_uppercase().blue(),
    };

    println!("\n  {} [{}] {}", "!".red(), severity_color, mat.rule_name.bold());
    println!("    Address: 0x{:016x}", mat.address);
    println!("    Description: {}", mat.description);
    println!("    Evidence: {}", mat.evidence);
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Setup logging
    let log_level = if cli.verbose { Level::DEBUG } else { Level::INFO };
    let subscriber = FmtSubscriber::builder()
        .with_max_level(log_level)
        .with_target(false)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    match cli.command {
        Commands::Scan { pid, string, hex, regex, executable_only, output } => {
            println!("\n{}", "=".repeat(60).cyan());
            println!("{}", "Process Memory Scanner".bold().cyan());
            println!("{}", "=".repeat(60).cyan());

            let process_name = MemoryScanner::get_process_name(pid);
            println!("Target: {} (PID: {})\n", process_name.yellow(), pid);

            let regions = MemoryScanner::get_memory_regions(pid)?;
            println!("Memory regions: {}", regions.len());

            let mut all_matches = Vec::new();

            if let Some(pattern) = string {
                println!("\nSearching for string: {}", pattern.cyan());
                let matches = MemoryScanner::search_pattern(
                    pid, &regions, pattern.as_bytes(), &pattern, "string", executable_only
                )?;
                println!("Found {} matches", matches.len().to_string().green());
                for mat in &matches {
                    display_match(mat);
                }
                all_matches.extend(matches);
            }

            if let Some(pattern) = hex {
                println!("\nSearching for hex: {}", pattern.cyan());
                let bytes = hex::decode(&pattern)?;
                let matches = MemoryScanner::search_pattern(
                    pid, &regions, &bytes, &pattern, "hex", executable_only
                )?;
                println!("Found {} matches", matches.len().to_string().green());
                for mat in &matches {
                    display_match(mat);
                }
                all_matches.extend(matches);
            }

            if let Some(pattern) = regex {
                println!("\nSearching for regex: {}", pattern.cyan());
                let matches = MemoryScanner::search_regex(pid, &regions, &pattern, executable_only)?;
                println!("Found {} matches", matches.len().to_string().green());
                for mat in &matches {
                    display_match(mat);
                }
                all_matches.extend(matches);
            }

            if let Some(output_path) = output {
                let result = ScanResult {
                    pid,
                    process_name,
                    scanned_at: Utc::now(),
                    regions_scanned: regions.len(),
                    bytes_scanned: regions.iter().filter(|r| r.is_readable).map(|r| r.size).sum(),
                    matches: all_matches,
                    ioc_matches: Vec::new(),
                };
                let content = serde_json::to_string_pretty(&result)?;
                fs::write(&output_path, content)?;
                println!("\nResults saved to: {}", output_path.display().to_string().cyan());
            }
        }
        Commands::Ioc { pid, rules, output } => {
            println!("\n{}", "=".repeat(60).cyan());
            println!("{}", "IOC Memory Scanner".bold().cyan());
            println!("{}", "=".repeat(60).cyan());

            let process_name = MemoryScanner::get_process_name(pid);
            println!("Target: {} (PID: {})\n", process_name.yellow(), pid);

            let ioc_rules = if let Some(rules_path) = rules {
                let content = fs::read_to_string(&rules_path)?;
                serde_json::from_str(&content)?
            } else {
                MemoryScanner::get_default_ioc_rules()
            };

            println!("Loaded {} IOC rules", ioc_rules.rules.len());

            let regions = MemoryScanner::get_memory_regions(pid)?;
            let matches = MemoryScanner::scan_for_iocs(pid, &regions, &ioc_rules)?;

            if matches.is_empty() {
                println!("\n{} No IOC matches found", "✓".green());
            } else {
                println!("\n{} Found {} IOC matches:", "!".red(), matches.len());
                for mat in &matches {
                    display_ioc_match(mat);
                }
            }

            if let Some(output_path) = output {
                let result = ScanResult {
                    pid,
                    process_name,
                    scanned_at: Utc::now(),
                    regions_scanned: regions.len(),
                    bytes_scanned: regions.iter().filter(|r| r.is_readable).map(|r| r.size).sum(),
                    matches: Vec::new(),
                    ioc_matches: matches,
                };
                let content = serde_json::to_string_pretty(&result)?;
                fs::write(&output_path, content)?;
                println!("\nResults saved to: {}", output_path.display().to_string().cyan());
            }
        }
        Commands::Regions { pid, detailed } => {
            println!("\n{}", "=".repeat(70).cyan());
            println!("{}", "Memory Regions".bold().cyan());
            println!("{}", "=".repeat(70).cyan());

            let process_name = MemoryScanner::get_process_name(pid);
            println!("Process: {} (PID: {})\n", process_name.yellow(), pid);

            let regions = MemoryScanner::get_memory_regions(pid)?;

            for region in &regions {
                let perm_color = if region.is_executable && region.is_writable {
                    region.permissions.red()
                } else if region.is_executable {
                    region.permissions.yellow()
                } else {
                    region.permissions.normal()
                };

                println!("  {:016x}-{:016x} {} {:>8} {}",
                    region.start_address,
                    region.end_address,
                    perm_color,
                    format_size(region.size),
                    region.pathname
                );

                if detailed {
                    println!("    Offset: {:x}, Device: {}, Inode: {}",
                        region.offset, region.device, region.inode);
                }
            }

            println!("\nTotal regions: {}", regions.len());
            println!("Total size: {}", format_size(regions.iter().map(|r| r.size).sum()));
        }
        Commands::Dump { pid, start, size, output } => {
            let address = u64::from_str_radix(start.trim_start_matches("0x"), 16)?;

            println!("\n{}", "=".repeat(50).cyan());
            println!("{}", "Memory Dump".bold().cyan());
            println!("{}", "=".repeat(50).cyan());
            println!("Dumping {} bytes from 0x{:x}", size, address);

            let memory = MemoryScanner::read_process_memory(pid, address, size)?;

            fs::write(&output, &memory)?;

            println!("{} Dumped {} bytes to {}", "✓".green(), memory.len(), output.display());
        }
        Commands::ScanAll { string, hex, output } => {
            println!("\n{}", "=".repeat(60).cyan());
            println!("{}", "Scanning All Processes".bold().cyan());
            println!("{}", "=".repeat(60).cyan());

            let mut all_results = Vec::new();

            // Read /proc for all processes
            for entry in fs::read_dir("/proc")? {
                let entry = entry?;
                let name = entry.file_name();
                let name_str = name.to_string_lossy();

                if let Ok(pid) = name_str.parse::<i32>() {
                    let process_name = MemoryScanner::get_process_name(pid);

                    if let Ok(regions) = MemoryScanner::get_memory_regions(pid) {
                        let mut matches = Vec::new();

                        if let Some(ref pattern) = string {
                            if let Ok(m) = MemoryScanner::search_pattern(
                                pid, &regions, pattern.as_bytes(), pattern, "string", false
                            ) {
                                matches.extend(m);
                            }
                        }

                        if let Some(ref pattern) = hex {
                            if let Ok(bytes) = hex::decode(pattern) {
                                if let Ok(m) = MemoryScanner::search_pattern(
                                    pid, &regions, &bytes, pattern, "hex", false
                                ) {
                                    matches.extend(m);
                                }
                            }
                        }

                        if !matches.is_empty() {
                            println!("{} {} (PID {}): {} matches",
                                "●".yellow(),
                                process_name,
                                pid,
                                matches.len()
                            );
                            all_results.push(ScanResult {
                                pid,
                                process_name,
                                scanned_at: Utc::now(),
                                regions_scanned: regions.len(),
                                bytes_scanned: 0,
                                matches,
                                ioc_matches: Vec::new(),
                            });
                        }
                    }
                }
            }

            if let Some(output_path) = output {
                let content = serde_json::to_string_pretty(&all_results)?;
                fs::write(&output_path, content)?;
                println!("\nResults saved to: {}", output_path.display().to_string().cyan());
            }
        }
        Commands::GenerateRules { output } => {
            let rules = MemoryScanner::get_default_ioc_rules();
            let content = serde_json::to_string_pretty(&rules)?;
            fs::write(&output, content)?;
            println!("{} IOC rules template saved to: {}", "✓".green(), output.display());
        }
        Commands::Analyze { pid, output } => {
            println!("\n{}", "=".repeat(60).cyan());
            println!("{}", "Process Analysis".bold().cyan());
            println!("{}", "=".repeat(60).cyan());

            let process_name = MemoryScanner::get_process_name(pid);
            println!("Target: {} (PID: {})\n", process_name.yellow(), pid);

            let findings = MemoryScanner::analyze_process(pid)?;

            if findings.is_empty() {
                println!("{} No suspicious indicators found", "✓".green());
            } else {
                println!("Found {} suspicious indicators:\n", findings.len());

                for finding in &findings {
                    let severity_color = match finding.severity.as_str() {
                        "high" => finding.severity.to_uppercase().red(),
                        "medium" => finding.severity.to_uppercase().yellow(),
                        _ => finding.severity.to_uppercase().blue(),
                    };

                    println!("  [{}] {}", severity_color, finding.title.bold());
                    println!("    Category: {}", finding.category);
                    println!("    {}", finding.description);
                    if !finding.evidence.is_empty() {
                        println!("    Evidence: {}", finding.evidence);
                    }
                    println!();
                }
            }

            if let Some(output_path) = output {
                let content = serde_json::to_string_pretty(&findings)?;
                fs::write(&output_path, content)?;
                println!("Report saved to: {}", output_path.display().to_string().cyan());
            }
        }
    }

    Ok(())
}

/// Format size in human readable format
fn format_size(size: usize) -> String {
    if size >= 1024 * 1024 * 1024 {
        format!("{:.1}GB", size as f64 / (1024.0 * 1024.0 * 1024.0))
    } else if size >= 1024 * 1024 {
        format!("{:.1}MB", size as f64 / (1024.0 * 1024.0))
    } else if size >= 1024 {
        format!("{:.1}KB", size as f64 / 1024.0)
    } else {
        format!("{}B", size)
    }
}
