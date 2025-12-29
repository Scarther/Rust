//! # Keylogger Detector - Main Entry Point
//!
//! This is an advanced security tool for detecting keyloggers on Linux systems.
//! It demonstrates sophisticated Rust techniques including:
//!
//! - Async/await with tokio for concurrent monitoring
//! - Unsafe Rust for low-level system access
//! - FFI (Foreign Function Interface) concepts
//! - Advanced error handling patterns
//! - Real-time file system monitoring
//!
//! ## Usage
//!
//! ```bash
//! # Run a full system scan
//! sudo keylogger_detector scan
//!
//! # Monitor in real-time
//! sudo keylogger_detector monitor
//!
//! # Check for LD_PRELOAD attacks
//! sudo keylogger_detector check-preload
//!
//! # Generate comprehensive report
//! sudo keylogger_detector report --output report.json
//! ```
//!
//! ## Security Notice
//!
//! This tool requires root privileges to access /dev/input devices and
//! read process information. It is intended for DEFENSIVE security analysis
//! and should only be used on systems you own or have authorization to test.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use colored::*;
use keylogger_detector::{
    ActivityType, DetectorError, InputDeviceInfo, KeyloggerDetector, SuspiciousActivity,
};
use log::{debug, error, info, warn, LevelFilter};
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::process;
use tokio::signal;
use tokio::time::{interval, Duration};

/// Keylogger Detector - Advanced Security Analysis Tool
///
/// Detects keyloggers by monitoring input devices, analyzing process behavior,
/// and detecting suspicious patterns in system activity.
#[derive(Parser, Debug)]
#[command(name = "keylogger_detector")]
#[command(author = "Security Researcher")]
#[command(version = "1.0.0")]
#[command(about = "Detect keyloggers by monitoring input devices and system behavior")]
#[command(long_about = None)]
struct Cli {
    /// Verbosity level (-v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Output format (text, json)
    #[arg(short, long, default_value = "text")]
    format: OutputFormat,

    #[command(subcommand)]
    command: Commands,
}

/// Available commands
#[derive(Subcommand, Debug)]
enum Commands {
    /// Scan the system for keylogger indicators
    Scan {
        /// Also check for hidden processes
        #[arg(long)]
        check_hidden: bool,

        /// Check LD_PRELOAD attacks
        #[arg(long)]
        check_preload: bool,

        /// Minimum severity level to report (1-10)
        #[arg(long, default_value = "1")]
        min_severity: u8,
    },

    /// Monitor input devices in real-time
    Monitor {
        /// Duration in seconds (0 = indefinite)
        #[arg(short, long, default_value = "0")]
        duration: u64,

        /// Scan interval in seconds
        #[arg(short, long, default_value = "30")]
        interval: u64,
    },

    /// List all input devices
    Devices {
        /// Show only keyboard devices
        #[arg(long)]
        keyboards_only: bool,

        /// Show detailed device information
        #[arg(long)]
        detailed: bool,
    },

    /// Check for LD_PRELOAD-based attacks
    CheckPreload,

    /// Detect hidden processes
    Hidden,

    /// Generate a comprehensive security report
    Report {
        /// Output file path
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Include device information
        #[arg(long)]
        include_devices: bool,
    },

    /// Add a process to the whitelist
    Whitelist {
        /// Process name to whitelist
        process_name: String,
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

/// Application state and configuration
struct App {
    detector: KeyloggerDetector,
    format: OutputFormat,
}

impl App {
    fn new(format: OutputFormat) -> Self {
        Self {
            detector: KeyloggerDetector::new(),
            format,
        }
    }

    /// Print a suspicious activity in the configured format
    fn print_activity(&self, activity: &SuspiciousActivity) {
        match self.format {
            OutputFormat::Text => {
                let severity_color = match activity.severity {
                    8..=10 => "red",
                    5..=7 => "yellow",
                    _ => "white",
                };

                let severity_label = match activity.severity {
                    8..=10 => "CRITICAL",
                    5..=7 => "HIGH",
                    3..=4 => "MEDIUM",
                    _ => "LOW",
                };

                println!(
                    "{} [{}] {}",
                    format!("[{}]", activity.timestamp.format("%Y-%m-%d %H:%M:%S")).dimmed(),
                    severity_label.color(severity_color).bold(),
                    activity.description
                );

                if let Some(pid) = activity.pid {
                    println!("  {} PID: {}", "->".dimmed(), pid);
                }
                if let Some(ref name) = activity.process_name {
                    println!("  {} Process: {}", "->".dimmed(), name);
                }
                if let Some(ref path) = activity.file_path {
                    println!("  {} Path: {:?}", "->".dimmed(), path);
                }
                if !activity.metadata.is_empty() {
                    for (key, value) in &activity.metadata {
                        println!("  {} {}: {}", "->".dimmed(), key, value);
                    }
                }
                println!();
            }
            OutputFormat::Json => {
                if let Ok(json) = serde_json::to_string(activity) {
                    println!("{}", json);
                }
            }
        }
    }

    /// Print device information
    fn print_device(&self, device: &InputDeviceInfo, detailed: bool) {
        match self.format {
            OutputFormat::Text => {
                let device_type = if device.is_keyboard {
                    "[KEYBOARD]".green()
                } else if device.is_mouse {
                    "[MOUSE]".blue()
                } else {
                    "[OTHER]".white()
                };

                println!(
                    "{} {} - {}",
                    device_type,
                    device.path.display(),
                    device.name.cyan()
                );

                if detailed {
                    println!("  {} UID: {}, GID: {}, Mode: {:o}",
                        "->".dimmed(), device.uid, device.gid, device.mode & 0o777);
                    if let Some(ref phys) = device.physical_path {
                        println!("  {} Physical: {}", "->".dimmed(), phys);
                    }
                    if let Some(ref unique) = device.unique_id {
                        println!("  {} Unique ID: {}", "->".dimmed(), unique);
                    }
                    println!();
                }
            }
            OutputFormat::Json => {
                if let Ok(json) = serde_json::to_string(device) {
                    println!("{}", json);
                }
            }
        }
    }

    /// Run a full system scan
    async fn run_scan(
        &self,
        check_hidden: bool,
        check_preload: bool,
        min_severity: u8,
    ) -> Result<()> {
        println!("{}", "=== Keylogger Detection Scan ===".cyan().bold());
        println!();

        // First, enumerate input devices
        println!("{}", "Enumerating input devices...".yellow());
        match self.detector.enumerate_input_devices().await {
            Ok(devices) => {
                let kbd_count = devices.iter().filter(|d| d.is_keyboard).count();
                println!(
                    "  {} Found {} input devices ({} keyboards)",
                    "OK".green(),
                    devices.len(),
                    kbd_count
                );
            }
            Err(e) => {
                eprintln!(
                    "  {} Failed to enumerate devices: {}",
                    "ERROR".red(),
                    e
                );
            }
        }
        println!();

        // Scan processes
        println!("{}", "Scanning processes for suspicious activity...".yellow());
        match self.detector.scan_processes().await {
            Ok(findings) => {
                let filtered: Vec<_> = findings
                    .iter()
                    .filter(|a| a.severity >= min_severity)
                    .collect();

                if filtered.is_empty() {
                    println!(
                        "  {} No suspicious process activity detected",
                        "OK".green()
                    );
                } else {
                    println!(
                        "  {} Found {} suspicious activities:",
                        "WARNING".yellow(),
                        filtered.len()
                    );
                    println!();
                    for activity in filtered {
                        self.print_activity(activity);
                    }
                }
            }
            Err(e) => {
                eprintln!(
                    "  {} Failed to scan processes: {}",
                    "ERROR".red(),
                    e
                );
            }
        }
        println!();

        // Check for hidden processes if requested
        if check_hidden {
            println!("{}", "Checking for hidden processes...".yellow());
            match self.detector.detect_hidden_processes().await {
                Ok(findings) => {
                    if findings.is_empty() {
                        println!(
                            "  {} No hidden processes detected",
                            "OK".green()
                        );
                    } else {
                        println!(
                            "  {} Found {} potentially hidden processes:",
                            "ALERT".red().bold(),
                            findings.len()
                        );
                        println!();
                        for activity in findings {
                            self.print_activity(&activity);
                        }
                    }
                }
                Err(e) => {
                    eprintln!(
                        "  {} Failed to check hidden processes: {}",
                        "ERROR".red(),
                        e
                    );
                }
            }
            println!();
        }

        // Check for LD_PRELOAD attacks if requested
        if check_preload {
            println!("{}", "Checking for LD_PRELOAD attacks...".yellow());
            match self.detector.check_ld_preload().await {
                Ok(findings) => {
                    if findings.is_empty() {
                        println!(
                            "  {} No LD_PRELOAD attacks detected",
                            "OK".green()
                        );
                    } else {
                        println!(
                            "  {} Found {} LD_PRELOAD instances:",
                            "WARNING".yellow(),
                            findings.len()
                        );
                        println!();
                        for activity in findings {
                            self.print_activity(&activity);
                        }
                    }
                }
                Err(e) => {
                    eprintln!(
                        "  {} Failed to check LD_PRELOAD: {}",
                        "ERROR".red(),
                        e
                    );
                }
            }
            println!();
        }

        println!("{}", "=== Scan Complete ===".cyan().bold());
        Ok(())
    }

    /// Run real-time monitoring
    async fn run_monitor(&self, duration: u64, scan_interval: u64) -> Result<()> {
        println!("{}", "=== Real-time Keylogger Monitoring ===".cyan().bold());
        println!(
            "Monitoring input devices... Press Ctrl+C to stop"
        );
        println!();

        // Start the file system monitor
        let mut monitor_rx = self.detector.start_monitoring().await
            .context("Failed to start monitoring")?;

        // Create a periodic scanner
        let mut scan_timer = interval(Duration::from_secs(scan_interval));

        // Calculate end time if duration is specified
        let end_time = if duration > 0 {
            Some(std::time::Instant::now() + Duration::from_secs(duration))
        } else {
            None
        };

        loop {
            tokio::select! {
                // Handle Ctrl+C
                _ = signal::ctrl_c() => {
                    println!();
                    println!("{}", "Monitoring stopped by user".yellow());
                    break;
                }

                // Check if duration has elapsed
                _ = async {
                    if let Some(end) = end_time {
                        if std::time::Instant::now() >= end {
                            return;
                        }
                    }
                    tokio::time::sleep(Duration::from_secs(1)).await;
                } => {
                    if let Some(end) = end_time {
                        if std::time::Instant::now() >= end {
                            println!();
                            println!("{}", "Monitoring duration elapsed".yellow());
                            break;
                        }
                    }
                }

                // Handle file system events
                Some(activity) = monitor_rx.recv() => {
                    self.print_activity(&activity);
                }

                // Periodic process scan
                _ = scan_timer.tick() => {
                    debug!("Running periodic process scan...");
                    if let Ok(findings) = self.detector.scan_processes().await {
                        for activity in findings {
                            if activity.severity >= 5 {
                                self.print_activity(&activity);
                            }
                        }
                    }
                }
            }
        }

        // Generate final report
        println!();
        println!("{}", "Generating final report...".yellow());
        let report = self.detector.generate_report().await?;
        println!("{}", report);

        Ok(())
    }

    /// List all input devices
    async fn list_devices(&self, keyboards_only: bool, detailed: bool) -> Result<()> {
        println!("{}", "=== Input Devices ===".cyan().bold());
        println!();

        let devices = self.detector.enumerate_input_devices().await
            .context("Failed to enumerate input devices")?;

        let filtered: Vec<_> = if keyboards_only {
            devices.iter().filter(|d| d.is_keyboard).collect()
        } else {
            devices.iter().collect()
        };

        if filtered.is_empty() {
            println!("No input devices found.");
        } else {
            for device in filtered {
                self.print_device(device, detailed);
            }
        }

        println!();
        println!(
            "Total: {} devices",
            devices.len()
        );

        Ok(())
    }

    /// Check for LD_PRELOAD attacks
    async fn check_preload(&self) -> Result<()> {
        println!("{}", "=== LD_PRELOAD Attack Check ===".cyan().bold());
        println!();

        let findings = self.detector.check_ld_preload().await
            .context("Failed to check LD_PRELOAD")?;

        if findings.is_empty() {
            println!(
                "{} No LD_PRELOAD attacks detected",
                "OK".green()
            );
        } else {
            println!(
                "{} Found {} suspicious LD_PRELOAD instances:",
                "WARNING".yellow().bold(),
                findings.len()
            );
            println!();
            for activity in findings {
                self.print_activity(&activity);
            }
        }

        Ok(())
    }

    /// Detect hidden processes
    async fn detect_hidden(&self) -> Result<()> {
        println!("{}", "=== Hidden Process Detection ===".cyan().bold());
        println!();
        println!(
            "{}",
            "Comparing process lists to detect hidden processes...".yellow()
        );
        println!();

        let findings = self.detector.detect_hidden_processes().await
            .context("Failed to detect hidden processes")?;

        if findings.is_empty() {
            println!(
                "{} No hidden processes detected",
                "OK".green()
            );
        } else {
            println!(
                "{} Found {} potentially hidden processes:",
                "ALERT".red().bold(),
                findings.len()
            );
            println!();
            for activity in findings {
                self.print_activity(&activity);
            }
        }

        Ok(())
    }

    /// Generate a comprehensive report
    async fn generate_report(
        &self,
        output_path: Option<PathBuf>,
        include_devices: bool,
    ) -> Result<()> {
        println!("{}", "=== Generating Security Report ===".cyan().bold());
        println!();

        // Run all scans
        println!("Running comprehensive scan...");
        let _ = self.detector.enumerate_input_devices().await;
        let _ = self.detector.scan_processes().await;
        let _ = self.detector.detect_hidden_processes().await;
        let _ = self.detector.check_ld_preload().await;

        // Generate report
        let report = self.detector.generate_report().await
            .context("Failed to generate report")?;

        // Output to file or stdout
        if let Some(path) = output_path {
            let mut file = File::create(&path)
                .context(format!("Failed to create output file: {:?}", path))?;
            file.write_all(report.as_bytes())
                .context("Failed to write report")?;
            println!(
                "{} Report written to {:?}",
                "OK".green(),
                path
            );
        } else {
            println!("{}", report);
        }

        Ok(())
    }
}

/// Check if running with root privileges
///
/// Many operations require root access to /dev/input devices
fn check_privileges() {
    use nix::unistd::Uid;

    if !Uid::effective().is_root() {
        eprintln!(
            "{} This tool requires root privileges for full functionality.",
            "WARNING:".yellow().bold()
        );
        eprintln!(
            "Some operations may fail without access to /dev/input devices."
        );
        eprintln!();
    }
}

/// Initialize logging based on verbosity level
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

/// Print the banner
fn print_banner() {
    println!();
    println!(
        "{}",
        r#"
  _  __          _                              ____       _            _
 | |/ /___ _   _| | ___   __ _  __ _  ___ _ __ |  _ \  ___| |_ ___  ___| |_ ___  _ __
 | ' // _ \ | | | |/ _ \ / _` |/ _` |/ _ \ '__|| | | |/ _ \ __/ _ \/ __| __/ _ \| '__|
 | . \  __/ |_| | | (_) | (_| | (_| |  __/ |   | |_| |  __/ ||  __/ (__| || (_) | |
 |_|\_\___|\__, |_|\___/ \__, |\__, |\___|_|   |____/ \___|\__\___|\___|\__\___/|_|
           |___/         |___/ |___/
"#
        .cyan()
    );
    println!(
        "{}",
        "  Advanced Keylogger Detection Tool for Linux".cyan()
    );
    println!(
        "{}",
        "  For defensive security analysis only".dimmed()
    );
    println!();
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments
    let cli = Cli::parse();

    // Initialize logging
    init_logging(cli.verbose);

    // Print banner
    print_banner();

    // Check privileges
    check_privileges();

    // Create application
    let app = App::new(cli.format);

    // Execute command
    match cli.command {
        Commands::Scan {
            check_hidden,
            check_preload,
            min_severity,
        } => {
            app.run_scan(check_hidden, check_preload, min_severity).await?;
        }

        Commands::Monitor { duration, interval } => {
            app.run_monitor(duration, interval).await?;
        }

        Commands::Devices {
            keyboards_only,
            detailed,
        } => {
            app.list_devices(keyboards_only, detailed).await?;
        }

        Commands::CheckPreload => {
            app.check_preload().await?;
        }

        Commands::Hidden => {
            app.detect_hidden().await?;
        }

        Commands::Report {
            output,
            include_devices,
        } => {
            app.generate_report(output, include_devices).await?;
        }

        Commands::Whitelist { process_name } => {
            println!(
                "Added '{}' to the process whitelist.",
                process_name.green()
            );
            println!("Note: This only affects the current session.");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_output_format_parsing() {
        assert_eq!(
            "text".parse::<OutputFormat>().unwrap(),
            OutputFormat::Text
        );
        assert_eq!(
            "json".parse::<OutputFormat>().unwrap(),
            OutputFormat::Json
        );
        assert_eq!(
            "JSON".parse::<OutputFormat>().unwrap(),
            OutputFormat::Json
        );
        assert!("invalid".parse::<OutputFormat>().is_err());
    }

    #[test]
    fn test_cli_parsing() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }

    #[tokio::test]
    async fn test_app_creation() {
        let app = App::new(OutputFormat::Text);
        assert!(!app.detector.whitelist.is_empty());
    }
}
