//! # Memory Forensics Tool - Main Entry Point
//!
//! This is an advanced memory forensics tool for analyzing process memory
//! on Linux systems. It demonstrates sophisticated Rust techniques for
//! security analysis.
//!
//! ## Capabilities
//!
//! - Memory region enumeration and analysis
//! - String extraction from memory
//! - Pattern searching (bytes, strings, regex)
//! - Artifact detection (passwords, URLs, IPs, etc.)
//! - Memory dumping for offline analysis
//! - Heap and stack analysis
//!
//! ## Usage Examples
//!
//! ```bash
//! # Analyze process memory
//! sudo memory_forensics analyze 1234
//!
//! # Extract strings
//! sudo memory_forensics strings 1234 --min-length 8
//!
//! # Search for pattern
//! sudo memory_forensics search 1234 "password"
//!
//! # Dump memory to files
//! sudo memory_forensics dump 1234 --output ./dump/
//!
//! # Scan for artifacts
//! sudo memory_forensics artifacts 1234
//! ```

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use colored::*;
use log::{debug, error, info, warn, LevelFilter};
use memory_forensics::{
    hexdump, ArtifactType, ExtractedString, MemoryAnalyzer, MemoryArtifact,
    MemoryRegion, RegionType,
};
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

/// Memory Forensics Tool - Advanced Memory Analysis
///
/// Analyze process memory for forensic investigation, security research,
/// and incident response.
#[derive(Parser, Debug)]
#[command(name = "memory_forensics")]
#[command(author = "Security Researcher")]
#[command(version = "1.0.0")]
#[command(about = "Analyze process memory for forensic artifacts")]
#[command(long_about = None)]
struct Cli {
    /// Verbosity level (-v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Output format (text, json)
    #[arg(short, long, default_value = "text")]
    format: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Analyze process memory layout
    Analyze {
        /// Process ID to analyze
        pid: i32,

        /// Show detailed region information
        #[arg(long)]
        detailed: bool,
    },

    /// List memory regions
    Regions {
        /// Process ID
        pid: i32,

        /// Filter by type (heap, stack, code, data, lib, anonymous)
        #[arg(long)]
        filter: Option<String>,

        /// Only show readable regions
        #[arg(long)]
        readable_only: bool,

        /// Only show executable regions
        #[arg(long)]
        executable_only: bool,
    },

    /// Extract strings from memory
    Strings {
        /// Process ID
        pid: i32,

        /// Minimum string length
        #[arg(short, long, default_value = "6")]
        min_length: usize,

        /// Only show interesting strings
        #[arg(long)]
        interesting_only: bool,

        /// Maximum number of strings to show
        #[arg(long, default_value = "1000")]
        max_strings: usize,

        /// Output to file
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Search for pattern in memory
    Search {
        /// Process ID
        pid: i32,

        /// Pattern to search for
        pattern: String,

        /// Treat pattern as hex bytes
        #[arg(long)]
        hex: bool,

        /// Use regex pattern
        #[arg(long)]
        regex: bool,

        /// Show context around matches
        #[arg(short, long, default_value = "32")]
        context: usize,

        /// Maximum results
        #[arg(long, default_value = "100")]
        max_results: usize,
    },

    /// Scan for forensic artifacts
    Artifacts {
        /// Process ID
        pid: i32,

        /// Output report to file
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Filter by artifact type
        #[arg(long)]
        filter: Option<String>,
    },

    /// Dump memory regions to files
    Dump {
        /// Process ID
        pid: i32,

        /// Output directory
        #[arg(short, long)]
        output: PathBuf,

        /// Only dump specific region (by start address, hex)
        #[arg(long)]
        region: Option<String>,

        /// Only dump readable regions
        #[arg(long)]
        readable_only: bool,
    },

    /// Read memory at specific address
    Read {
        /// Process ID
        pid: i32,

        /// Memory address (hex)
        #[arg(value_parser = parse_hex)]
        address: u64,

        /// Number of bytes to read
        #[arg(default_value = "256")]
        size: usize,

        /// Output as raw bytes
        #[arg(long)]
        raw: bool,
    },

    /// Analyze heap memory
    Heap {
        /// Process ID
        pid: i32,

        /// Maximum chunks to analyze
        #[arg(long, default_value = "100")]
        max_chunks: usize,
    },

    /// Generate forensics report
    Report {
        /// Process ID
        pid: i32,

        /// Output file
        #[arg(short, long)]
        output: PathBuf,

        /// Include full artifact list
        #[arg(long)]
        full: bool,
    },

    /// Calculate hash of memory regions
    Hash {
        /// Process ID
        pid: i32,

        /// Only hash specific region (by start address, hex)
        #[arg(long)]
        region: Option<String>,
    },
}

/// Parse hexadecimal address
fn parse_hex(s: &str) -> Result<u64, String> {
    let s = s.trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(s, 16).map_err(|e| format!("Invalid hex: {}", e))
}

/// Format byte size
fn format_size(size: u64) -> String {
    if size >= 1024 * 1024 * 1024 {
        format!("{:.1} GB", size as f64 / (1024.0 * 1024.0 * 1024.0))
    } else if size >= 1024 * 1024 {
        format!("{:.1} MB", size as f64 / (1024.0 * 1024.0))
    } else if size >= 1024 {
        format!("{:.1} KB", size as f64 / 1024.0)
    } else {
        format!("{} B", size)
    }
}

/// Print memory region
fn print_region(region: &MemoryRegion, detailed: bool) {
    let type_color = match region.region_type {
        RegionType::Code => "red",
        RegionType::Heap => "yellow",
        RegionType::Stack => "green",
        RegionType::SharedLibrary => "cyan",
        RegionType::MappedFile => "blue",
        _ => "white",
    };

    let perms = format!(
        "{}{}{}{}",
        if region.readable { "r".green() } else { "-".dimmed() },
        if region.writable { "w".yellow() } else { "-".dimmed() },
        if region.executable { "x".red() } else { "-".dimmed() },
        if region.shared { "s".cyan() } else { "p".dimmed() }
    );

    let pathname = region.pathname
        .as_ref()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|| "[anonymous]".dimmed().to_string());

    println!(
        "{:016x}-{:016x} {} {:>10} {} {}",
        region.start,
        region.end,
        perms,
        format_size(region.size),
        format!("[{:?}]", region.region_type).color(type_color),
        pathname
    );

    if detailed {
        println!(
            "  {} offset={:#x} dev={} inode={}",
            "->".dimmed(),
            region.offset,
            region.device,
            region.inode
        );
    }
}

/// Print extracted string
fn print_string(s: &ExtractedString) {
    let marker = if s.is_interesting {
        "*".yellow().bold()
    } else {
        " ".normal()
    };

    let region_type = format!("[{:?}]", s.region_type).dimmed();

    // Truncate long strings
    let display_content = if s.content.len() > 80 {
        format!("{}...", &s.content[..77])
    } else {
        s.content.clone()
    };

    println!(
        "{} {:016x} {} {}",
        marker,
        s.address,
        region_type,
        if s.is_interesting {
            display_content.cyan()
        } else {
            display_content.normal()
        }
    );
}

/// Print artifact
fn print_artifact(artifact: &MemoryArtifact) {
    let type_color = match artifact.artifact_type {
        ArtifactType::Credential => "red",
        ArtifactType::CryptoMaterial => "red",
        ArtifactType::NetworkIndicator => "yellow",
        ArtifactType::IpAddress => "yellow",
        ArtifactType::EmailAddress => "cyan",
        ArtifactType::FilePath => "blue",
        ArtifactType::ExecutableHeader => "magenta",
        _ => "white",
    };

    println!(
        "{} {:016x} {}",
        format!("[{:?}]", artifact.artifact_type).color(type_color).bold(),
        artifact.address,
        artifact.description
    );

    // Show data preview
    let preview = String::from_utf8_lossy(&artifact.data[..std::cmp::min(60, artifact.data.len())]);
    println!("  {} {}", "Data:".dimmed(), preview.cyan());

    if !artifact.context.is_empty() {
        for (key, value) in &artifact.context {
            println!("  {} {}: {}", "->".dimmed(), key, value);
        }
    }
    println!();
}

/// Initialize logging
fn init_logging(verbosity: u8) {
    let level = match verbosity {
        0 => LevelFilter::Warn,
        1 => LevelFilter::Info,
        2 => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    };

    env_logger::Builder::new()
        .filter_level(level)
        .format_timestamp_secs()
        .init();
}

/// Check privileges
fn check_privileges() -> bool {
    nix::unistd::Uid::effective().is_root()
}

/// Print banner
fn print_banner() {
    println!(
        "{}",
        r#"
  __  __                                   _____                        _
 |  \/  | ___ _ __ ___   ___  _ __ _   _  |  ___|__  _ __ ___ _ __  ___(_) ___ ___
 | |\/| |/ _ \ '_ ` _ \ / _ \| '__| | | | | |_ / _ \| '__/ _ \ '_ \/ __| |/ __/ __|
 | |  | |  __/ | | | | | (_) | |  | |_| | |  _| (_) | | |  __/ | | \__ \ | (__\__ \
 |_|  |_|\___|_| |_| |_|\___/|_|   \__, | |_|  \___/|_|  \___|_| |_|___/_|\___|___/
                                   |___/
"#
        .cyan()
    );
    println!("{}", "  Advanced Memory Analysis Tool".cyan());
    println!();
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    init_logging(cli.verbose);

    print_banner();

    if !check_privileges() {
        println!(
            "{} Root privileges are recommended for full memory access.",
            "WARNING:".yellow().bold()
        );
        println!();
    }

    match cli.command {
        Commands::Analyze { pid, detailed } => {
            cmd_analyze(pid, detailed).await?;
        }

        Commands::Regions {
            pid,
            filter,
            readable_only,
            executable_only,
        } => {
            cmd_regions(pid, filter, readable_only, executable_only).await?;
        }

        Commands::Strings {
            pid,
            min_length,
            interesting_only,
            max_strings,
            output,
        } => {
            cmd_strings(pid, min_length, interesting_only, max_strings, output).await?;
        }

        Commands::Search {
            pid,
            pattern,
            hex,
            regex,
            context,
            max_results,
        } => {
            cmd_search(pid, &pattern, hex, regex, context, max_results).await?;
        }

        Commands::Artifacts { pid, output, filter } => {
            cmd_artifacts(pid, output, filter).await?;
        }

        Commands::Dump {
            pid,
            output,
            region,
            readable_only,
        } => {
            cmd_dump(pid, output, region, readable_only).await?;
        }

        Commands::Read {
            pid,
            address,
            size,
            raw,
        } => {
            cmd_read(pid, address, size, raw).await?;
        }

        Commands::Heap { pid, max_chunks } => {
            cmd_heap(pid, max_chunks).await?;
        }

        Commands::Report { pid, output, full } => {
            cmd_report(pid, output, full).await?;
        }

        Commands::Hash { pid, region } => {
            cmd_hash(pid, region).await?;
        }
    }

    Ok(())
}

async fn cmd_analyze(pid: i32, detailed: bool) -> Result<()> {
    println!("{}", "=== Memory Analysis ===".cyan().bold());
    println!("Target PID: {}", pid);
    println!();

    let analyzer = MemoryAnalyzer::new(pid)?;
    let snapshot = analyzer.create_snapshot()?;

    println!("{} {}", "Process:".yellow(), snapshot.process_name);
    println!("{} {}", "PID:".yellow(), snapshot.pid);
    println!("{} {}", "Timestamp:".yellow(), snapshot.timestamp);
    println!();

    println!("{}", "Memory Statistics:".cyan().bold());
    println!("  Total regions: {}", snapshot.regions.len());
    println!("  Total mapped: {}", format_size(snapshot.total_mapped));
    println!("  Total readable: {}", format_size(snapshot.total_readable));

    // Count by type
    let mut type_counts: std::collections::HashMap<RegionType, (usize, u64)> =
        std::collections::HashMap::new();

    for region in &snapshot.regions {
        let entry = type_counts.entry(region.region_type).or_insert((0, 0));
        entry.0 += 1;
        entry.1 += region.size;
    }

    println!();
    println!("{}", "Regions by Type:".cyan().bold());
    for (region_type, (count, size)) in type_counts {
        println!(
            "  {:15} {:>4} regions, {}",
            format!("{:?}", region_type),
            count,
            format_size(size)
        );
    }

    // Permission statistics
    let readable = snapshot.regions.iter().filter(|r| r.readable).count();
    let writable = snapshot.regions.iter().filter(|r| r.writable).count();
    let executable = snapshot.regions.iter().filter(|r| r.executable).count();

    println!();
    println!("{}", "Permission Statistics:".cyan().bold());
    println!("  Readable: {}", readable);
    println!("  Writable: {}", writable);
    println!("  Executable: {}", executable);

    if detailed {
        println!();
        println!("{}", "All Regions:".cyan().bold());
        for region in &snapshot.regions {
            print_region(region, true);
        }
    }

    Ok(())
}

async fn cmd_regions(
    pid: i32,
    filter: Option<String>,
    readable_only: bool,
    executable_only: bool,
) -> Result<()> {
    println!("{}", "=== Memory Regions ===".cyan().bold());
    println!("PID: {}", pid);
    println!();

    let analyzer = MemoryAnalyzer::new(pid)?;
    let regions = analyzer.get_regions();

    let filtered: Vec<_> = regions
        .iter()
        .filter(|r| {
            if readable_only && !r.readable {
                return false;
            }
            if executable_only && !r.executable {
                return false;
            }
            if let Some(ref f) = filter {
                let type_str = format!("{:?}", r.region_type).to_lowercase();
                if !type_str.contains(&f.to_lowercase()) {
                    return false;
                }
            }
            true
        })
        .collect();

    println!(
        "{:18} {:18} {:4} {:>10} {:15} {}",
        "START".bold(),
        "END".bold(),
        "PERM".bold(),
        "SIZE".bold(),
        "TYPE".bold(),
        "PATH".bold()
    );
    println!("{}", "-".repeat(90));

    for region in &filtered {
        print_region(region, false);
    }

    println!();
    println!("Showing {} of {} regions", filtered.len(), regions.len());

    Ok(())
}

async fn cmd_strings(
    pid: i32,
    min_length: usize,
    interesting_only: bool,
    max_strings: usize,
    output: Option<PathBuf>,
) -> Result<()> {
    println!("{}", "=== String Extraction ===".cyan().bold());
    println!("PID: {}, Min length: {}", pid, min_length);
    println!();

    let analyzer = MemoryAnalyzer::new(pid)?;
    let mut all_strings: Vec<ExtractedString> = Vec::new();

    for region in analyzer.get_regions() {
        if !region.readable {
            continue;
        }

        // Skip very large regions
        if region.size > 50 * 1024 * 1024 {
            continue;
        }

        if let Ok(data) = analyzer.read_region(region) {
            let strings = analyzer.extract_strings(&data, region.start, min_length);
            all_strings.extend(strings);
        }
    }

    // Filter if requested
    let filtered: Vec<_> = if interesting_only {
        all_strings.iter().filter(|s| s.is_interesting).collect()
    } else {
        all_strings.iter().collect()
    };

    // Output
    if let Some(path) = output {
        let mut file = File::create(&path)?;
        for s in &filtered {
            writeln!(file, "{:016x} {}", s.address, s.content)?;
        }
        println!("{} Wrote {} strings to {:?}", "OK".green(), filtered.len(), path);
    } else {
        for s in filtered.iter().take(max_strings) {
            print_string(s);
        }

        if filtered.len() > max_strings {
            println!(
                "... and {} more strings (use --max-strings to see more)",
                filtered.len() - max_strings
            );
        }
    }

    println!();
    println!("Total strings found: {}", all_strings.len());
    println!(
        "Interesting strings: {}",
        all_strings.iter().filter(|s| s.is_interesting).count()
    );

    Ok(())
}

async fn cmd_search(
    pid: i32,
    pattern: &str,
    is_hex: bool,
    is_regex: bool,
    context: usize,
    max_results: usize,
) -> Result<()> {
    println!("{}", "=== Memory Search ===".cyan().bold());
    println!("PID: {}, Pattern: {}", pid, pattern);
    println!();

    let analyzer = MemoryAnalyzer::new(pid)?;

    if is_regex {
        let matches = analyzer.search_regex(pattern)?;
        println!("Found {} matches:", matches.len());
        println!();

        for (i, (addr, matched)) in matches.iter().take(max_results).enumerate() {
            println!("{:4}. {:016x}: {}", i + 1, addr, matched.cyan());
        }
    } else {
        let search_bytes = if is_hex {
            hex::decode(pattern).context("Invalid hex pattern")?
        } else {
            pattern.as_bytes().to_vec()
        };

        let matches = analyzer.search_pattern(&search_bytes)?;
        println!("Found {} matches:", matches.len());
        println!();

        for (i, addr) in matches.iter().take(max_results).enumerate() {
            println!("{:4}. {:016x}", i + 1, addr);

            // Show context
            if context > 0 {
                let start = addr.saturating_sub(context as u64 / 2);
                if let Ok(data) = analyzer.read_memory(start, context) {
                    println!("{}", hexdump(&data, start));
                }
            }
        }
    }

    Ok(())
}

async fn cmd_artifacts(pid: i32, output: Option<PathBuf>, filter: Option<String>) -> Result<()> {
    println!("{}", "=== Artifact Scan ===".cyan().bold());
    println!("PID: {}", pid);
    println!();

    let mut analyzer = MemoryAnalyzer::new(pid)?;
    let artifacts = analyzer.scan_for_artifacts()?;

    let filtered: Vec<_> = if let Some(ref f) = filter {
        artifacts
            .iter()
            .filter(|a| format!("{:?}", a.artifact_type).to_lowercase().contains(&f.to_lowercase()))
            .collect()
    } else {
        artifacts.iter().collect()
    };

    if filtered.is_empty() {
        println!("{}", "No artifacts found.".yellow());
    } else {
        for artifact in &filtered {
            print_artifact(artifact);
        }
    }

    println!();
    println!("Total artifacts: {}", artifacts.len());

    if let Some(path) = output {
        let report = analyzer.generate_report()?;
        let mut file = File::create(&path)?;
        file.write_all(report.as_bytes())?;
        println!("{} Report written to {:?}", "OK".green(), path);
    }

    Ok(())
}

async fn cmd_dump(
    pid: i32,
    output: PathBuf,
    region: Option<String>,
    readable_only: bool,
) -> Result<()> {
    println!("{}", "=== Memory Dump ===".cyan().bold());
    println!("PID: {}, Output: {:?}", pid, output);
    println!();

    let analyzer = MemoryAnalyzer::new(pid)?;

    if let Some(region_addr) = region {
        let addr = parse_hex(&region_addr)?;
        if let Some(region) = analyzer.get_regions().iter().find(|r| r.start == addr) {
            let size = analyzer.dump_region(region, &output)?;
            println!("{} Dumped {} to {:?}", "OK".green(), format_size(size), output);
        } else {
            println!("{} Region not found at {:#x}", "ERROR".red(), addr);
        }
    } else {
        let dumped = analyzer.dump_all(&output)?;
        println!("{} Dumped {} regions to {:?}", "OK".green(), dumped.len(), output);
        for path in &dumped {
            println!("  {}", path.display());
        }
    }

    Ok(())
}

async fn cmd_read(pid: i32, address: u64, size: usize, raw: bool) -> Result<()> {
    println!("{}", "=== Memory Read ===".cyan().bold());
    println!("PID: {}, Address: {:#x}, Size: {}", pid, address, size);
    println!();

    let analyzer = MemoryAnalyzer::new(pid)?;
    let data = analyzer.read_memory(address, size)?;

    if raw {
        std::io::stdout().write_all(&data)?;
    } else {
        println!("{}", hexdump(&data, address));
    }

    Ok(())
}

async fn cmd_heap(pid: i32, max_chunks: usize) -> Result<()> {
    println!("{}", "=== Heap Analysis ===".cyan().bold());
    println!("PID: {}", pid);
    println!();

    let analyzer = MemoryAnalyzer::new(pid)?;
    let chunks = analyzer.analyze_heap()?;

    if chunks.is_empty() {
        println!("{}", "No heap region found or empty heap.".yellow());
        return Ok(());
    }

    println!(
        "{:18} {:>10} {:6} {}",
        "ADDRESS".bold(),
        "SIZE".bold(),
        "IN_USE".bold(),
        "PREVIEW".bold()
    );
    println!("{}", "-".repeat(70));

    for chunk in chunks.iter().take(max_chunks) {
        let preview: String = chunk.data_preview
            .iter()
            .map(|&b| if b >= 0x20 && b < 0x7f { b as char } else { '.' })
            .collect();

        println!(
            "{:016x} {:>10} {:6} {}",
            chunk.address,
            chunk.size,
            if chunk.in_use { "yes" } else { "no" },
            preview.dimmed()
        );
    }

    println!();
    println!("Analyzed {} chunks", std::cmp::min(chunks.len(), max_chunks));

    Ok(())
}

async fn cmd_report(pid: i32, output: PathBuf, full: bool) -> Result<()> {
    println!("{}", "=== Generating Report ===".cyan().bold());
    println!("PID: {}", pid);
    println!();

    let mut analyzer = MemoryAnalyzer::new(pid)?;

    // Run artifact scan if full report
    if full {
        analyzer.scan_for_artifacts()?;
    }

    let report = analyzer.generate_report()?;
    let mut file = File::create(&output)?;
    file.write_all(report.as_bytes())?;

    println!("{} Report written to {:?}", "OK".green(), output);

    Ok(())
}

async fn cmd_hash(pid: i32, region: Option<String>) -> Result<()> {
    println!("{}", "=== Memory Hashing ===".cyan().bold());
    println!("PID: {}", pid);
    println!();

    let analyzer = MemoryAnalyzer::new(pid)?;

    if let Some(region_addr) = region {
        let addr = parse_hex(&region_addr)?;
        if let Some(region) = analyzer.get_regions().iter().find(|r| r.start == addr) {
            let hash = analyzer.hash_region(region)?;
            println!("{:016x}-{:016x}: {}", region.start, region.end, hash);
        } else {
            println!("{} Region not found at {:#x}", "ERROR".red(), addr);
        }
    } else {
        println!(
            "{:18} {:18} {:10} {}",
            "START".bold(),
            "END".bold(),
            "SIZE".bold(),
            "SHA256".bold()
        );
        println!("{}", "-".repeat(90));

        for region in analyzer.get_regions() {
            if !region.readable {
                continue;
            }

            // Skip very large regions
            if region.size > 50 * 1024 * 1024 {
                println!(
                    "{:016x} {:016x} {:>10} {}",
                    region.start,
                    region.end,
                    format_size(region.size),
                    "[skipped - too large]".dimmed()
                );
                continue;
            }

            match analyzer.hash_region(region) {
                Ok(hash) => {
                    println!(
                        "{:016x} {:016x} {:>10} {}",
                        region.start,
                        region.end,
                        format_size(region.size),
                        hash
                    );
                }
                Err(_) => {
                    println!(
                        "{:016x} {:016x} {:>10} {}",
                        region.start,
                        region.end,
                        format_size(region.size),
                        "[error]".red()
                    );
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hex() {
        assert_eq!(parse_hex("0x1234").unwrap(), 0x1234);
        assert_eq!(parse_hex("1234").unwrap(), 0x1234);
        assert_eq!(parse_hex("0X7fff12345678").unwrap(), 0x7fff12345678);
    }

    #[test]
    fn test_format_size() {
        assert_eq!(format_size(100), "100 B");
        assert_eq!(format_size(1024), "1.0 KB");
        assert_eq!(format_size(1024 * 1024), "1.0 MB");
        assert_eq!(format_size(1024 * 1024 * 1024), "1.0 GB");
    }

    #[test]
    fn test_cli_parsing() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }
}
