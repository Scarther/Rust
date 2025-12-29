//! # Rootkit Scanner - Main Entry Point
//!
//! This is an advanced security tool for detecting rootkits on Linux systems.
//! It uses multiple detection techniques to find:
//!
//! - Hidden processes
//! - Hidden files
//! - Suspicious kernel modules
//! - Hidden network connections
//! - LD_PRELOAD attacks
//! - Modified system binaries
//!
//! ## Usage
//!
//! ```bash
//! # Run a full scan
//! sudo rootkit_scanner scan
//!
//! # Quick scan (processes only)
//! sudo rootkit_scanner quick
//!
//! # Check specific subsystem
//! sudo rootkit_scanner check --processes
//! sudo rootkit_scanner check --modules
//! sudo rootkit_scanner check --network
//!
//! # Generate report
//! sudo rootkit_scanner scan --output report.json
//! ```
//!
//! ## Security Notice
//!
//! This tool requires root privileges for comprehensive scanning.
//! It is intended for defensive security analysis only.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use colored::*;
use log::{debug, error, info, warn, LevelFilter};
use rootkit_scanner::{Finding, IndicatorType, RootkitScanner, Severity};
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

/// Rootkit Scanner - Advanced Security Analysis Tool
///
/// Detects rootkits by scanning for hidden processes, files, kernel modules,
/// and network connections using multiple detection techniques.
#[derive(Parser, Debug)]
#[command(name = "rootkit_scanner")]
#[command(author = "Security Researcher")]
#[command(version = "1.0.0")]
#[command(about = "Detect rootkits and hidden malware on Linux systems")]
#[command(long_about = None)]
struct Cli {
    /// Verbosity level (-v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Output format (text, json)
    #[arg(short, long, default_value = "text")]
    format: OutputFormat,

    /// Minimum severity to report
    #[arg(long, default_value = "info")]
    min_severity: SeverityArg,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run a full rootkit scan
    Scan {
        /// Output report to file
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Skip kernel module check
        #[arg(long)]
        skip_modules: bool,

        /// Skip network check
        #[arg(long)]
        skip_network: bool,
    },

    /// Quick scan (processes and files only)
    Quick,

    /// Check specific subsystems
    Check {
        /// Check for hidden processes
        #[arg(long)]
        processes: bool,

        /// Check for hidden files
        #[arg(long)]
        files: bool,

        /// Check kernel modules
        #[arg(long)]
        modules: bool,

        /// Check network connections
        #[arg(long)]
        network: bool,

        /// Check LD_PRELOAD
        #[arg(long)]
        preload: bool,

        /// Check system binaries
        #[arg(long)]
        binaries: bool,

        /// Check mounts
        #[arg(long)]
        mounts: bool,

        /// Check scheduled tasks
        #[arg(long)]
        tasks: bool,

        /// Check devices
        #[arg(long)]
        devices: bool,
    },

    /// List loaded kernel modules
    Modules {
        /// Show only suspicious modules
        #[arg(long)]
        suspicious_only: bool,
    },

    /// Show network connections
    Network {
        /// Show only orphaned connections
        #[arg(long)]
        orphaned_only: bool,
    },

    /// Generate a baseline for comparison
    Baseline {
        /// Output file for baseline
        output: PathBuf,
    },
}

/// Output format options
#[derive(Debug, Clone, Copy, PartialEq)]
enum OutputFormat {
    Text,
    Json,
}

impl std::str::FromStr for OutputFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "text" => Ok(OutputFormat::Text),
            "json" => Ok(OutputFormat::Json),
            _ => Err(format!("Unknown format: {}", s)),
        }
    }
}

/// Severity argument for CLI
#[derive(Debug, Clone, Copy)]
struct SeverityArg(Severity);

impl std::str::FromStr for SeverityArg {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "info" => Ok(SeverityArg(Severity::Info)),
            "low" => Ok(SeverityArg(Severity::Low)),
            "medium" => Ok(SeverityArg(Severity::Medium)),
            "high" => Ok(SeverityArg(Severity::High)),
            "critical" => Ok(SeverityArg(Severity::Critical)),
            _ => Err(format!("Unknown severity: {}", s)),
        }
    }
}

/// Application context
struct App {
    scanner: RootkitScanner,
    format: OutputFormat,
    min_severity: Severity,
}

impl App {
    fn new(format: OutputFormat, min_severity: Severity) -> Self {
        Self {
            scanner: RootkitScanner::new(),
            format,
            min_severity,
        }
    }

    /// Print a finding
    fn print_finding(&self, finding: &Finding) {
        if finding.severity < self.min_severity {
            return;
        }

        match self.format {
            OutputFormat::Text => {
                let severity_color = match finding.severity {
                    Severity::Critical => "red",
                    Severity::High => "yellow",
                    Severity::Medium => "cyan",
                    Severity::Low => "white",
                    Severity::Info => "dimmed",
                };

                println!(
                    "{} {} {}",
                    format!("[{}]", finding.severity).color(severity_color).bold(),
                    format!("[{:?}]", finding.indicator_type).dimmed(),
                    finding.title.bold()
                );
                println!("  {}", finding.description);

                if let Some(ref path) = finding.path {
                    println!("  {} {:?}", "Path:".dimmed(), path);
                }
                if let Some(pid) = finding.pid {
                    println!("  {} {}", "PID:".dimmed(), pid);
                }
                if !finding.evidence.is_empty() {
                    println!("  {}", "Evidence:".dimmed());
                    for (key, value) in &finding.evidence {
                        println!("    {}: {}", key.cyan(), value);
                    }
                }
                println!("  {} {}", "Recommendation:".yellow(), finding.recommendation);
                println!();
            }
            OutputFormat::Json => {
                if let Ok(json) = serde_json::to_string(finding) {
                    println!("{}", json);
                }
            }
        }
    }

    /// Print scan summary
    fn print_summary(&self, findings: &[Finding]) {
        let critical = findings.iter().filter(|f| f.severity == Severity::Critical).count();
        let high = findings.iter().filter(|f| f.severity == Severity::High).count();
        let medium = findings.iter().filter(|f| f.severity == Severity::Medium).count();
        let low = findings.iter().filter(|f| f.severity == Severity::Low).count();
        let info = findings.iter().filter(|f| f.severity == Severity::Info).count();

        println!();
        println!("{}", "=== Scan Summary ===".cyan().bold());
        println!();

        if critical > 0 {
            println!(
                "  {} {} CRITICAL findings",
                "!!!".red().bold(),
                critical.to_string().red().bold()
            );
        }
        if high > 0 {
            println!(
                "  {} {} HIGH findings",
                "!!".yellow().bold(),
                high.to_string().yellow().bold()
            );
        }
        if medium > 0 {
            println!(
                "  {} {} MEDIUM findings",
                "!".cyan(),
                medium.to_string().cyan()
            );
        }
        if low > 0 {
            println!("  {} LOW findings", low);
        }
        if info > 0 {
            println!("  {} INFO findings", info);
        }

        println!();

        if critical > 0 {
            println!(
                "{}",
                "CRITICAL FINDINGS DETECTED - IMMEDIATE INVESTIGATION REQUIRED".red().bold()
            );
        } else if high > 0 {
            println!(
                "{}",
                "High severity findings detected - investigation recommended".yellow()
            );
        } else if medium > 0 || low > 0 {
            println!(
                "{}",
                "Some findings detected - review recommended".cyan()
            );
        } else {
            println!("{}", "No suspicious indicators found.".green());
        }
    }

    /// Run a full scan
    async fn run_full_scan(&mut self, output: Option<PathBuf>, skip_modules: bool, skip_network: bool) -> Result<()> {
        println!("{}", "=== Rootkit Scanner - Full Scan ===".cyan().bold());
        println!();

        if skip_modules {
            println!("{}", "Skipping kernel module check (--skip-modules)".yellow());
        }
        if skip_network {
            println!("{}", "Skipping network check (--skip-network)".yellow());
        }
        println!();

        // Run scans
        println!("{}", "Scanning for hidden processes...".yellow());
        self.scanner.detect_hidden_processes().await?;

        println!("{}", "Scanning for hidden files...".yellow());
        self.scanner.detect_hidden_files().await?;

        if !skip_modules {
            println!("{}", "Analyzing kernel modules...".yellow());
            self.scanner.analyze_kernel_modules().await?;
        }

        if !skip_network {
            println!("{}", "Checking network connections...".yellow());
            self.scanner.check_network_connections().await?;
        }

        println!("{}", "Checking LD_PRELOAD...".yellow());
        self.scanner.check_ld_preload().await?;

        println!("{}", "Checking system binaries...".yellow());
        self.scanner.check_system_binaries().await?;

        println!("{}", "Checking mount points...".yellow());
        self.scanner.check_suspicious_mounts().await?;

        println!("{}", "Checking scheduled tasks...".yellow());
        self.scanner.check_scheduled_tasks().await?;

        println!("{}", "Checking device files...".yellow());
        self.scanner.check_suspicious_devices().await?;

        println!();
        println!("{}", "=== Scan Results ===".cyan().bold());
        println!();

        let findings = self.scanner.get_findings();

        if findings.is_empty() {
            println!("{}", "No suspicious indicators detected.".green());
        } else {
            for finding in findings {
                self.print_finding(finding);
            }
        }

        self.print_summary(findings);

        // Write report if requested
        if let Some(path) = output {
            let report = self.scanner.generate_report()?;
            let mut file = File::create(&path)?;
            file.write_all(report.as_bytes())?;
            println!();
            println!("{} Report written to {:?}", "OK".green(), path);
        }

        Ok(())
    }

    /// Run a quick scan
    async fn run_quick_scan(&mut self) -> Result<()> {
        println!("{}", "=== Rootkit Scanner - Quick Scan ===".cyan().bold());
        println!();

        println!("{}", "Scanning for hidden processes...".yellow());
        self.scanner.detect_hidden_processes().await?;

        println!("{}", "Scanning for hidden files...".yellow());
        self.scanner.detect_hidden_files().await?;

        println!();
        println!("{}", "=== Quick Scan Results ===".cyan().bold());
        println!();

        let findings = self.scanner.get_findings();

        if findings.is_empty() {
            println!("{}", "No hidden processes or files detected.".green());
        } else {
            for finding in findings {
                self.print_finding(finding);
            }
        }

        self.print_summary(findings);

        Ok(())
    }

    /// Run specific checks
    async fn run_checks(
        &mut self,
        processes: bool,
        files: bool,
        modules: bool,
        network: bool,
        preload: bool,
        binaries: bool,
        mounts: bool,
        tasks: bool,
        devices: bool,
    ) -> Result<()> {
        println!("{}", "=== Rootkit Scanner - Targeted Check ===".cyan().bold());
        println!();

        // If nothing specified, run all
        let run_all = !processes && !files && !modules && !network &&
                     !preload && !binaries && !mounts && !tasks && !devices;

        if processes || run_all {
            println!("{}", "Checking processes...".yellow());
            self.scanner.detect_hidden_processes().await?;
        }

        if files || run_all {
            println!("{}", "Checking files...".yellow());
            self.scanner.detect_hidden_files().await?;
        }

        if modules || run_all {
            println!("{}", "Checking kernel modules...".yellow());
            self.scanner.analyze_kernel_modules().await?;
        }

        if network || run_all {
            println!("{}", "Checking network...".yellow());
            self.scanner.check_network_connections().await?;
        }

        if preload || run_all {
            println!("{}", "Checking LD_PRELOAD...".yellow());
            self.scanner.check_ld_preload().await?;
        }

        if binaries || run_all {
            println!("{}", "Checking binaries...".yellow());
            self.scanner.check_system_binaries().await?;
        }

        if mounts || run_all {
            println!("{}", "Checking mounts...".yellow());
            self.scanner.check_suspicious_mounts().await?;
        }

        if tasks || run_all {
            println!("{}", "Checking scheduled tasks...".yellow());
            self.scanner.check_scheduled_tasks().await?;
        }

        if devices || run_all {
            println!("{}", "Checking devices...".yellow());
            self.scanner.check_suspicious_devices().await?;
        }

        println!();
        println!("{}", "=== Check Results ===".cyan().bold());
        println!();

        let findings = self.scanner.get_findings();

        if findings.is_empty() {
            println!("{}", "No suspicious indicators detected.".green());
        } else {
            for finding in findings {
                self.print_finding(finding);
            }
        }

        self.print_summary(findings);

        Ok(())
    }

    /// List kernel modules
    async fn list_modules(&self, suspicious_only: bool) -> Result<()> {
        println!("{}", "=== Loaded Kernel Modules ===".cyan().bold());
        println!();

        let content = std::fs::read_to_string("/proc/modules")?;

        let suspicious_patterns = vec!["rootkit", "hide", "stealth", "invisible", "backdoor"];

        println!(
            "{:30} {:>12} {:>6} {}",
            "NAME".bold(),
            "SIZE".bold(),
            "USED".bold(),
            "STATE".bold()
        );
        println!("{}", "-".repeat(70));

        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 4 {
                continue;
            }

            let name = parts[0];
            let size = parts[1];
            let used = parts[2];
            let state = parts.get(4).unwrap_or(&"");

            let is_suspicious = suspicious_patterns
                .iter()
                .any(|p| name.to_lowercase().contains(p));

            if suspicious_only && !is_suspicious {
                continue;
            }

            if is_suspicious {
                println!(
                    "{:30} {:>12} {:>6} {} {}",
                    name.red().bold(),
                    size,
                    used,
                    state,
                    "[SUSPICIOUS]".red().bold()
                );
            } else {
                println!("{:30} {:>12} {:>6} {}", name, size, used, state);
            }
        }

        Ok(())
    }

    /// Show network connections
    async fn show_network(&self, orphaned_only: bool) -> Result<()> {
        println!("{}", "=== Network Connections ===".cyan().bold());
        println!();

        println!(
            "{:6} {:22} {:22} {:>12} {:>8}",
            "PROTO".bold(),
            "LOCAL".bold(),
            "REMOTE".bold(),
            "STATE".bold(),
            "PID".bold()
        );
        println!("{}", "-".repeat(80));

        // Parse TCP connections
        self.show_proto_connections("tcp", orphaned_only)?;
        self.show_proto_connections("tcp6", orphaned_only)?;
        self.show_proto_connections("udp", orphaned_only)?;
        self.show_proto_connections("udp6", orphaned_only)?;

        Ok(())
    }

    fn show_proto_connections(&self, protocol: &str, orphaned_only: bool) -> Result<()> {
        let path = format!("/proc/net/{}", protocol);
        let content = std::fs::read_to_string(&path)?;

        for line in content.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 10 {
                continue;
            }

            // Parse addresses
            let local_parts: Vec<&str> = parts[1].split(':').collect();
            let remote_parts: Vec<&str> = parts[2].split(':').collect();

            if local_parts.len() != 2 || remote_parts.len() != 2 {
                continue;
            }

            let local_addr = format!(
                "{}:{}",
                hex_to_ip(local_parts[0]),
                u16::from_str_radix(local_parts[1], 16).unwrap_or(0)
            );

            let remote_addr = format!(
                "{}:{}",
                hex_to_ip(remote_parts[0]),
                u16::from_str_radix(remote_parts[1], 16).unwrap_or(0)
            );

            let state_num = u8::from_str_radix(parts[3], 16).unwrap_or(0);
            let state = tcp_state_name(state_num);

            let inode: u64 = parts.get(9).and_then(|s| s.parse().ok()).unwrap_or(0);

            // Find PID for this socket
            let pid = find_pid_for_inode(inode);

            if orphaned_only && pid.is_some() {
                continue;
            }

            let pid_str = pid.map(|p| p.to_string()).unwrap_or_else(|| "-".to_string());

            if pid.is_none() && inode != 0 && state != "LISTEN" {
                println!(
                    "{:6} {:22} {:22} {:>12} {:>8} {}",
                    protocol.red(),
                    local_addr.red(),
                    remote_addr.red(),
                    state.red(),
                    pid_str.red(),
                    "[ORPHANED]".red().bold()
                );
            } else {
                println!(
                    "{:6} {:22} {:22} {:>12} {:>8}",
                    protocol, local_addr, remote_addr, state, pid_str
                );
            }
        }

        Ok(())
    }

    /// Generate a baseline
    async fn generate_baseline(&mut self, output: PathBuf) -> Result<()> {
        println!("{}", "=== Generating System Baseline ===".cyan().bold());
        println!();

        // This would collect hashes of important files, list of processes, etc.
        // For now, we'll use the report format

        self.scanner.detect_hidden_processes().await?;
        self.scanner.analyze_kernel_modules().await?;

        let report = self.scanner.generate_report()?;
        let mut file = File::create(&output)?;
        file.write_all(report.as_bytes())?;

        println!(
            "{} Baseline written to {:?}",
            "OK".green(),
            output
        );

        Ok(())
    }
}

// Helper functions

fn hex_to_ip(hex: &str) -> String {
    if hex.len() == 8 {
        let bytes: Vec<u8> = (0..8)
            .step_by(2)
            .filter_map(|i| u8::from_str_radix(&hex[i..i+2], 16).ok())
            .collect();
        if bytes.len() == 4 {
            format!("{}.{}.{}.{}", bytes[3], bytes[2], bytes[1], bytes[0])
        } else {
            hex.to_string()
        }
    } else {
        hex.to_string()
    }
}

fn tcp_state_name(state: u8) -> &'static str {
    match state {
        0x01 => "ESTABLISHED",
        0x02 => "SYN_SENT",
        0x03 => "SYN_RECV",
        0x04 => "FIN_WAIT1",
        0x05 => "FIN_WAIT2",
        0x06 => "TIME_WAIT",
        0x07 => "CLOSE",
        0x08 => "CLOSE_WAIT",
        0x09 => "LAST_ACK",
        0x0A => "LISTEN",
        0x0B => "CLOSING",
        _ => "UNKNOWN",
    }
}

fn find_pid_for_inode(inode: u64) -> Option<i32> {
    if inode == 0 {
        return None;
    }

    let target = format!("socket:[{}]", inode);

    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.flatten() {
            if let Ok(pid) = entry.file_name().to_string_lossy().parse::<i32>() {
                let fd_path = format!("/proc/{}/fd", pid);
                if let Ok(fds) = std::fs::read_dir(&fd_path) {
                    for fd in fds.flatten() {
                        if let Ok(link) = std::fs::read_link(fd.path()) {
                            if link.to_string_lossy() == target {
                                return Some(pid);
                            }
                        }
                    }
                }
            }
        }
    }

    None
}

/// Check if running with root privileges
fn check_privileges() -> bool {
    nix::unistd::Uid::effective().is_root()
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

/// Print banner
fn print_banner() {
    println!(
        "{}",
        r#"
  ____             _   _    _ _     ____
 |  _ \ ___   ___ | |_| | _(_) |_  / ___|  ___ __ _ _ __  _ __   ___ _ __
 | |_) / _ \ / _ \| __| |/ / | __| \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
 |  _ < (_) | (_) | |_|   <| | |_   ___) | (_| (_| | | | | | | |  __/ |
 |_| \_\___/ \___/ \__|_|\_\_|\__| |____/ \___\__,_|_| |_|_| |_|\___|_|

"#
        .cyan()
    );
    println!("{}", "  Advanced Rootkit Detection for Linux".cyan());
    println!();
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    init_logging(cli.verbose);

    print_banner();

    if !check_privileges() {
        println!(
            "{} This tool requires root privileges for comprehensive scanning.",
            "WARNING:".yellow().bold()
        );
        println!(
            "{}",
            "Some checks may fail or produce incomplete results.".yellow()
        );
        println!();
    }

    let mut app = App::new(cli.format, cli.min_severity.0);

    match cli.command {
        Commands::Scan {
            output,
            skip_modules,
            skip_network,
        } => {
            app.run_full_scan(output, skip_modules, skip_network).await?;
        }

        Commands::Quick => {
            app.run_quick_scan().await?;
        }

        Commands::Check {
            processes,
            files,
            modules,
            network,
            preload,
            binaries,
            mounts,
            tasks,
            devices,
        } => {
            app.run_checks(
                processes, files, modules, network,
                preload, binaries, mounts, tasks, devices,
            ).await?;
        }

        Commands::Modules { suspicious_only } => {
            app.list_modules(suspicious_only).await?;
        }

        Commands::Network { orphaned_only } => {
            app.show_network(orphaned_only).await?;
        }

        Commands::Baseline { output } => {
            app.generate_baseline(output).await?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_to_ip() {
        assert_eq!(hex_to_ip("0100007F"), "127.0.0.1");
        assert_eq!(hex_to_ip("00000000"), "0.0.0.0");
    }

    #[test]
    fn test_tcp_state_name() {
        assert_eq!(tcp_state_name(0x01), "ESTABLISHED");
        assert_eq!(tcp_state_name(0x0A), "LISTEN");
    }

    #[test]
    fn test_cli_parsing() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }

    #[test]
    fn test_severity_parsing() {
        assert!("critical".parse::<SeverityArg>().is_ok());
        assert!("high".parse::<SeverityArg>().is_ok());
        assert!("medium".parse::<SeverityArg>().is_ok());
        assert!("low".parse::<SeverityArg>().is_ok());
        assert!("info".parse::<SeverityArg>().is_ok());
        assert!("invalid".parse::<SeverityArg>().is_err());
    }
}
